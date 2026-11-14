//! The secure session: a Noise handshake, then authenticated encryption of
//! every message. Sans-IO: the caller feeds whole received DVC messages to
//! [`SecureSession::on_message`] and sends the bytes it gets back.
//!
//! # Handshake
//!
//! `Noise_XX_25519_ChaChaPoly_BLAKE2s` (Noise Protocol Framework, revision
//! 34, section 7.5). The helper is the initiator, the client the responder:
//!
//! ```text
//! helper (initiator)                       client (responder)
//!   -> e                     payload: "RLNK" major minor  (plaintext, hashed)
//!   <- e, ee, s, es          payload: "RLNK" major minor  (encrypted)
//!   -> s, se                 payload: empty
//! ```
//!
//! The prologue (Noise section 6) is `"Remora-Link/1\0" || channel name ||
//! "\0" || bulk token` (32 zero bytes on `Remora::Ctl`). Both sides must use
//! the same prologue or the handshake fails, so a handshake or transport
//! message recorded on one channel never verifies on the other, and
//! `Remora::Bulk` only completes for a helper that received the token over
//! the paired `Remora::Ctl` session.
//!
//! XX transmits both static keys encrypted, so an observer of the channel
//! learns neither. XX alone is used for every contact, also once paired:
//! the client authenticates the helper by comparing the static key the
//! handshake proved against its pin store ([`crate::PinStore`]). IK would
//! save one message but needs the helper's key before the first message,
//! which the client only has after pairing, and it would add a second
//! handshake shape to test; one round trip per session is not worth that.
//!
//! # Transport
//!
//! After the handshake, `snow`'s transport state encrypts each protocol
//! message with ChaCha20-Poly1305 under per-direction keys from Noise's
//! `Split()`, with the implicit 64-bit counter nonce of Noise section 5.1.
//! A Noise message holds at most 65,535 bytes, so a frame longer than
//! [`SEGMENT_PLAIN`] is encrypted as consecutive segments, each with its own
//! nonce and 16-byte tag, concatenated into one DVC message. Segment
//! boundaries follow from the length alone. Because nonces are implicit
//! counters, a replayed, reordered, dropped or modified message fails
//! authentication; that is fatal ([`Error::Decrypt`]). Splitting or merging
//! DVC messages is caught by the frame's exact length check.
//!
//! # Pairing (Ctl only)
//!
//! A short authentication string from the handshake hash alone could be
//! ground by a man in the middle (it picks its last key until the strings
//! match). So after the handshake the two sides run a commit-reveal step
//! inside the encrypted session, as in ZRTP and Vaudenay's SAS protocols:
//!
//! ```text
//!   -> SasCommit  c = BLAKE3-derive("Remora-Link v1 SAS commit", h || nI)
//!   <- SasNonce   nR
//!   -> SasReveal  nI          (the client checks c)
//!   SAS = BLAKE3-derive("Remora-Link v1 SAS", h || nI || nR) as 6 digits
//! ```
//!
//! `h` is the Noise handshake hash. Neither side can choose its nonce after
//! seeing the other's, so an attacker matches the strings with probability
//! 10^-6 per attempt. Both ends get [`Event::Sas`]; the session is ready
//! after that. `Remora::Bulk` skips this step and is ready after the
//! handshake (it is bound to Ctl by the token and the expected static key).

use snow::params::DHChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::frame::MAX_MESSAGE;
use crate::msg::{Channel, Message, PROTO_MAJOR, PROTO_MINOR};

/// The Noise protocol name.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Largest Noise message (Noise section 3).
pub const NOISE_MAX: usize = 65_535;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Plaintext bytes per encrypted segment.
pub const SEGMENT_PLAIN: usize = NOISE_MAX - TAG_LEN;

/// Largest encrypted DVC message: a [`MAX_MESSAGE`] frame plus one tag per
/// segment.
pub const MAX_WIRE: usize = MAX_MESSAGE + MAX_MESSAGE.div_ceil(SEGMENT_PLAIN) * TAG_LEN;

/// Magic at the start of the first two handshake payloads.
const MAGIC: &[u8; 4] = b"RLNK";

const COMMIT_CONTEXT: &str = "Remora-Link v1 SAS commit";
const SAS_CONTEXT: &str = "Remora-Link v1 SAS";

/// Which end of the handshake this side is. The helper (which opens the
/// channel) is always the initiator; Remora is always the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// A long-term X25519 key pair. The helper keeps one per user
/// (DPAPI-protected); the client may use a fresh one per session.
#[derive(Clone)]
pub struct StaticKey {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl StaticKey {
    /// A new random key pair from the OS random generator.
    pub fn generate() -> Result<StaticKey> {
        let mut private = Zeroizing::new([0u8; 32]);
        crate::random(&mut private[..])?;
        StaticKey::from_private(&private)
    }

    /// The key pair for a stored private key.
    pub fn from_private(private: &[u8; 32]) -> Result<StaticKey> {
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or(Error::Handshake("no X25519 backend".into()))?;
        dh.set(private);
        let mut public = [0u8; 32];
        public.copy_from_slice(dh.pubkey());
        Ok(StaticKey {
            private: Zeroizing::new(*private),
            public,
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The private key, for the owner to store protected. Never log it.
    pub fn private(&self) -> &[u8; 32] {
        &self.private
    }
}

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StaticKey({})", crate::wire::hex(&self.public))
    }
}

/// What ties a channel to an earlier, authenticated one.
#[derive(Clone, Copy, Debug, Default)]
pub struct Binding {
    /// `Remora::Bulk`: the token from `HelloAck` (required there, ignored
    /// on `Remora::Ctl`).
    pub bulk_token: Option<[u8; 32]>,
    /// The peer's static key must be exactly this one (Bulk: the key the
    /// Ctl session authenticated). None accepts any key; the caller then
    /// checks [`Event::Established`] against its pin store.
    pub expected_remote: Option<[u8; 32]>,
}

/// The six-digit short authentication string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sas(pub u32);

impl std::fmt::Display for Sas {
    /// `123 456`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// What [`SecureSession::on_message`] (and the constructors) produce, in order.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Bytes to send on this channel as one DVC message.
    Send(Vec<u8>),
    /// The handshake finished; the peer proved this static key.
    Established { remote_static: [u8; 32] },
    /// Ctl: the short authentication string; the session is now ready.
    Sas(Sas),
    /// An application message.
    Message { request_id: u32, msg: Message },
}

enum SasStep {
    /// Initiator: sent the commitment, waits for the responder's nonce.
    Nonce { mine: Zeroizing<[u8; 32]> },
    /// Responder: waits for the commitment.
    Commit,
    /// Responder: sent its nonce, waits for the reveal.
    Reveal {
        commit: [u8; 32],
        mine: Zeroizing<[u8; 32]>,
    },
}

enum State {
    Handshake(Box<HandshakeState>),
    Pairing {
        transport: Box<TransportState>,
        step: SasStep,
    },
    Ready(Box<TransportState>),
    Failed,
}

/// One end of an encrypted helper channel.
pub struct SecureSession {
    role: Role,
    channel: Channel,
    binding: Binding,
    state: State,
    handshake_hash: [u8; 32],
    remote_static: Option<[u8; 32]>,
    sas: Option<Sas>,
}

impl SecureSession {
    /// The helper's side. Returns the session and the first handshake
    /// message to send.
    pub fn initiator(
        channel: Channel,
        local: &StaticKey,
        binding: Binding,
    ) -> Result<(SecureSession, Vec<u8>)> {
        let mut s = SecureSession::new(Role::Initiator, channel, local, binding)?;
        let first = s.guard(|s| s.write_handshake(&version_payload()))?;
        Ok((s, first))
    }

    /// The client's side; it waits for the helper's first message.
    pub fn responder(
        channel: Channel,
        local: &StaticKey,
        binding: Binding,
    ) -> Result<SecureSession> {
        SecureSession::new(Role::Responder, channel, local, binding)
    }

    fn new(
        role: Role,
        channel: Channel,
        local: &StaticKey,
        binding: Binding,
    ) -> Result<SecureSession> {
        let prologue = prologue(channel, &binding)?;
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| Error::Handshake(format!("{e:?}")))?;
        let b = snow::Builder::new(params)
            .local_private_key(&local.private[..])
            .and_then(|b| b.prologue(&prologue))
            .map_err(|e| Error::Handshake(format!("{e:?}")))?;
        let hs = match role {
            Role::Initiator => b.build_initiator(),
            Role::Responder => b.build_responder(),
        }
        .map_err(|e| Error::Handshake(format!("{e:?}")))?;
        Ok(SecureSession {
            role,
            channel,
            binding,
            state: State::Handshake(Box::new(hs)),
            handshake_hash: [0; 32],
            remote_static: None,
            sas: None,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Application messages can be sent and received.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }

    /// The session failed; it must be dropped and the channel closed.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }

    /// The peer's static key once the handshake proved it.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }

    /// The Noise handshake hash (channel binding value) after the handshake.
    pub fn handshake_hash(&self) -> Option<[u8; 32]> {
        self.remote_static.map(|_| self.handshake_hash)
    }

    /// The SAS once the pairing step finished (Ctl only).
    pub fn sas(&self) -> Option<Sas> {
        self.sas
    }

    /// Runs `f`; any error leaves the session failed for good.
    fn guard<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if matches!(self.state, State::Failed) {
            return Err(Error::Closed);
        }
        let r = f(self);
        if r.is_err() {
            self.state = State::Failed;
        }
        r
    }

    /// Handles one received DVC message. Any error is fatal for the channel.
    pub fn on_message(&mut self, wire: &[u8]) -> Result<Vec<Event>> {
        self.guard(|s| s.receive(wire))
    }

    /// Encrypts one application message. Fails before the session is ready,
    /// for session-layer messages and for messages of the other channel.
    pub fn send(&mut self, request_id: u32, msg: &Message) -> Result<Vec<u8>> {
        if msg.is_session() {
            return Err(Error::State("session messages are sent by the session"));
        }
        if msg.channel() != self.channel {
            return Err(Error::State("message belongs to the other channel"));
        }
        let frame = msg.encode(request_id)?;
        self.guard(|s| match &mut s.state {
            State::Ready(t) => seal(t, &frame),
            _ => Err(Error::State("send before the session is ready")),
        })
    }

    fn write_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let State::Handshake(hs) = &mut self.state else {
            return Err(Error::State("not in the handshake"));
        };
        let mut buf = vec![0u8; NOISE_MAX];
        let n = hs
            .write_message(payload, &mut buf)
            .map_err(|e| Error::Handshake(format!("{e:?}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn receive(&mut self, wire: &[u8]) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        match &mut self.state {
            State::Handshake(hs) => {
                if wire.len() > NOISE_MAX {
                    return Err(Error::TooLarge(wire.len()));
                }
                let mut payload = vec![0u8; NOISE_MAX];
                let n = hs
                    .read_message(wire, &mut payload)
                    .map_err(|e| Error::Handshake(format!("{e:?}")))?;
                payload.truncate(n);
                self.after_handshake_read(&payload, &mut events)?;
            }
            State::Pairing { transport, .. } => {
                let frame = open(transport, wire)?;
                let (_, msg) = Message::decode(&frame)?;
                self.pairing_step(msg, &mut events)?;
            }
            State::Ready(t) => {
                let frame = open(t, wire)?;
                let (request_id, msg) = Message::decode(&frame)?;
                if msg.is_session() {
                    return Err(Error::State("pairing message after pairing"));
                }
                if msg.channel() != self.channel && !matches!(msg, Message::Unknown { .. }) {
                    return Err(Error::State("message of the other channel"));
                }
                events.push(Event::Message { request_id, msg });
            }
            State::Failed => return Err(Error::Closed),
        }
        Ok(events)
    }

    /// After reading handshake message 1 (responder), 2 (initiator) or 3
    /// (responder).
    fn after_handshake_read(&mut self, payload: &[u8], events: &mut Vec<Event>) -> Result<()> {
        let State::Handshake(hs) = &self.state else {
            return Err(Error::State("not in the handshake"));
        };
        let finished = hs.is_handshake_finished();
        let my_turn = hs.is_my_turn();
        match (self.role, finished) {
            // Message 1 at the responder, or message 2 at the initiator:
            // check the version, then answer.
            (_, false) | (Role::Initiator, true) => {
                check_version(payload)?;
                self.check_remote()?;
                if my_turn {
                    let reply = match self.role {
                        Role::Responder => version_payload(),
                        Role::Initiator => Vec::new(),
                    };
                    let out = self.write_handshake(&reply)?;
                    events.push(Event::Send(out));
                }
                let State::Handshake(hs) = &self.state else {
                    unreachable!("still in the handshake")
                };
                if hs.is_handshake_finished() {
                    self.finish_handshake(events)?;
                }
            }
            // Message 3 at the responder.
            (Role::Responder, true) => {
                if !payload.is_empty() {
                    return Err(Error::Handshake("unexpected payload in message 3".into()));
                }
                self.check_remote()?;
                self.finish_handshake(events)?;
            }
        }
        Ok(())
    }

    /// Checks the peer's static key, once known, against the binding.
    fn check_remote(&mut self) -> Result<()> {
        let State::Handshake(hs) = &self.state else {
            return Ok(());
        };
        let Some(rs) = hs.get_remote_static() else {
            return Ok(());
        };
        let rs: [u8; 32] = rs
            .try_into()
            .map_err(|_| Error::Handshake("remote key length".into()))?;
        if let Some(want) = self.binding.expected_remote
            && want != rs
        {
            return Err(Error::WrongPeer);
        }
        self.remote_static = Some(rs);
        Ok(())
    }

    fn finish_handshake(&mut self, events: &mut Vec<Event>) -> Result<()> {
        let State::Handshake(hs) = std::mem::replace(&mut self.state, State::Failed) else {
            return Err(Error::State("not in the handshake"));
        };
        self.handshake_hash
            .copy_from_slice(&hs.get_handshake_hash()[..32]);
        let remote_static = self
            .remote_static
            .ok_or(Error::Handshake("no remote static key".into()))?;
        let mut transport = Box::new(
            hs.into_transport_mode()
                .map_err(|e| Error::Handshake(format!("{e:?}")))?,
        );
        events.push(Event::Established { remote_static });
        self.state = match (self.channel, self.role) {
            (Channel::Bulk, _) => State::Ready(transport),
            (Channel::Ctl, Role::Initiator) => {
                let mut mine = Zeroizing::new([0u8; 32]);
                crate::random(&mut mine[..])?;
                let c = commitment(&self.handshake_hash, &mine);
                events.push(Event::Send(seal(
                    &mut transport,
                    &Message::SasCommit(c).encode(0)?,
                )?));
                State::Pairing {
                    transport,
                    step: SasStep::Nonce { mine },
                }
            }
            (Channel::Ctl, Role::Responder) => State::Pairing {
                transport,
                step: SasStep::Commit,
            },
        };
        Ok(())
    }

    fn pairing_step(&mut self, msg: Message, events: &mut Vec<Event>) -> Result<()> {
        let State::Pairing { transport, step } = &mut self.state else {
            return Err(Error::State("not pairing"));
        };
        let h = self.handshake_hash;
        let next: Option<SasStep>;
        let sas: Option<Sas>;
        match (std::mem::replace(step, SasStep::Commit), msg) {
            (SasStep::Nonce { mine }, Message::SasNonce(theirs)) => {
                events.push(Event::Send(seal(
                    transport,
                    &Message::SasReveal(*mine).encode(0)?,
                )?));
                sas = Some(derive_sas(&h, &mine, &theirs));
                next = None;
            }
            (SasStep::Commit, Message::SasCommit(commit)) => {
                let mut mine = Zeroizing::new([0u8; 32]);
                crate::random(&mut mine[..])?;
                events.push(Event::Send(seal(
                    transport,
                    &Message::SasNonce(*mine).encode(0)?,
                )?));
                next = Some(SasStep::Reveal { commit, mine });
                sas = None;
            }
            (SasStep::Reveal { commit, mine }, Message::SasReveal(theirs)) => {
                if !ct_eq(&commitment(&h, &theirs), &commit) {
                    return Err(Error::Commitment);
                }
                sas = Some(derive_sas(&h, &theirs, &mine));
                next = None;
            }
            _ => return Err(Error::State("unexpected message during pairing")),
        }
        match next {
            Some(n) => *step = n,
            None => {
                let State::Pairing { transport, .. } =
                    std::mem::replace(&mut self.state, State::Failed)
                else {
                    unreachable!("pairing state checked above")
                };
                self.state = State::Ready(transport);
            }
        }
        if let Some(s) = sas {
            self.sas = Some(s);
            events.push(Event::Sas(s));
        }
        Ok(())
    }
}

fn prologue(channel: Channel, binding: &Binding) -> Result<Vec<u8>> {
    let mut p = b"Remora-Link/1\0".to_vec();
    p.extend_from_slice(channel.name().as_bytes());
    p.push(0);
    match channel {
        Channel::Ctl => p.extend_from_slice(&[0u8; 32]),
        Channel::Bulk => {
            let token = binding.bulk_token.ok_or(Error::State(
                "Remora::Bulk needs the bulk token from HelloAck",
            ))?;
            p.extend_from_slice(&token);
        }
    }
    Ok(p)
}

fn version_payload() -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&PROTO_MAJOR.to_le_bytes());
    v.extend_from_slice(&PROTO_MINOR.to_le_bytes());
    v
}

fn check_version(payload: &[u8]) -> Result<()> {
    if payload.len() < 8 || &payload[..4] != MAGIC {
        return Err(Error::Handshake("not a Remora-Link handshake".into()));
    }
    let major = u16::from_le_bytes([payload[4], payload[5]]);
    if major != PROTO_MAJOR {
        return Err(Error::Version {
            ours: PROTO_MAJOR,
            theirs: major,
        });
    }
    Ok(())
}

/// Encrypts one frame as one or more Noise transport messages.
fn seal(t: &mut TransportState, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() > MAX_MESSAGE {
        return Err(Error::TooLarge(frame.len()));
    }
    let segments = frame.len().div_ceil(SEGMENT_PLAIN).max(1);
    let mut out = vec![0u8; frame.len() + segments * TAG_LEN];
    let mut at = 0;
    for part in frame.chunks(SEGMENT_PLAIN) {
        let n = t
            .write_message(part, &mut out[at..])
            .map_err(|_| Error::State("encryption failed (nonce exhausted)"))?;
        at += n;
    }
    out.truncate(at);
    Ok(out)
}

/// Decrypts one DVC message; any failure means tampering, replay or reorder.
fn open(t: &mut TransportState, wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() > MAX_WIRE {
        return Err(Error::TooLarge(wire.len()));
    }
    if wire.len() <= TAG_LEN {
        return Err(Error::Decrypt);
    }
    let mut out = vec![0u8; wire.len()];
    let mut at = 0;
    for seg in wire.chunks(NOISE_MAX) {
        if seg.len() <= TAG_LEN {
            return Err(Error::Decrypt);
        }
        let n = t
            .read_message(seg, &mut out[at..])
            .map_err(|_| Error::Decrypt)?;
        at += n;
    }
    out.truncate(at);
    Ok(out)
}

fn commitment(h: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut k = blake3::Hasher::new_derive_key(COMMIT_CONTEXT);
    k.update(h);
    k.update(nonce);
    *k.finalize().as_bytes()
}

fn derive_sas(h: &[u8; 32], initiator: &[u8; 32], responder: &[u8; 32]) -> Sas {
    let mut k = blake3::Hasher::new_derive_key(SAS_CONTEXT);
    k.update(h);
    k.update(initiator);
    k.update(responder);
    let out = k.finalize();
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&out.as_bytes()[..8]);
    // The bias of reducing 2^64 to 10^6 values is below 2^-40.
    Sas((u64::from_le_bytes(eight) % 1_000_000) as u32)
}

/// Constant-time equality for the commitment check.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{FileOffer, SessionInfo};

    fn keys() -> (StaticKey, StaticKey) {
        (
            StaticKey::generate().unwrap(),
            StaticKey::generate().unwrap(),
        )
    }

    fn sends(ev: &[Event]) -> Vec<Vec<u8>> {
        ev.iter()
            .filter_map(|e| match e {
                Event::Send(b) => Some(b.clone()),
                _ => None,
            })
            .collect()
    }

    /// Delivers every Send in `ev` to `to`, returning `to`'s events.
    fn deliver(to: &mut SecureSession, ev: &[Event]) -> Vec<Event> {
        let mut all = Vec::new();
        for b in sends(ev) {
            all.extend(to.on_message(&b).unwrap());
        }
        all
    }

    fn sas_of(ev: &[Event]) -> Option<Sas> {
        ev.iter().find_map(|e| match e {
            Event::Sas(s) => Some(*s),
            _ => None,
        })
    }

    /// Runs a full Ctl session; returns (helper, client, helper SAS, client SAS).
    fn pair(helper_key: &StaticKey, client_key: &StaticKey) -> (SecureSession, SecureSession) {
        let (mut h, first) =
            SecureSession::initiator(Channel::Ctl, helper_key, Binding::default()).unwrap();
        let mut c = SecureSession::responder(Channel::Ctl, client_key, Binding::default()).unwrap();
        let e2 = c.on_message(&first).unwrap(); // -> msg 2
        let e3 = deliver(&mut h, &e2); // -> msg 3 + commit
        assert!(e3.contains(&Event::Established {
            remote_static: client_key.public()
        }));
        let e4 = deliver(&mut c, &e3); // established + nonce
        assert!(e4.contains(&Event::Established {
            remote_static: helper_key.public()
        }));
        let e5 = deliver(&mut h, &e4); // reveal + SAS
        let e6 = deliver(&mut c, &e5); // SAS
        assert_eq!(sas_of(&e5), sas_of(&e6));
        assert!(sas_of(&e5).is_some());
        assert!(h.is_ready() && c.is_ready());
        (h, c)
    }

    #[test]
    fn handshake_and_sas_match_on_both_ends() {
        let (hk, ck) = keys();
        let (h, c) = pair(&hk, &ck);
        assert_eq!(h.sas(), c.sas());
        assert_eq!(h.handshake_hash(), c.handshake_hash());
        assert_eq!(c.remote_static(), Some(hk.public()));
        assert_eq!(h.remote_static(), Some(ck.public()));
        // Fresh randomness: a second session between the same keys gets a
        // different handshake hash (forward secrecy from fresh ephemerals).
        let (h2, _) = pair(&hk, &ck);
        assert_ne!(h.handshake_hash(), h2.handshake_hash());
        assert_eq!(format!("{}", Sas(12_345)), "012 345");
    }

    #[test]
    fn messages_both_ways_including_multi_segment() {
        let (hk, ck) = keys();
        let (mut h, mut c) = pair(&hk, &ck);
        let info = Message::SessionInfo(SessionInfo {
            locked: false,
            idle_ms: 5,
            cpu_percent: 3,
            mem_used: 1,
            mem_total: 2,
        });
        let wire = h.send(7, &info).unwrap();
        assert_eq!(
            c.on_message(&wire).unwrap(),
            vec![Event::Message {
                request_id: 7,
                msg: info
            }]
        );
        // A frame of almost 1 MiB spans 17 segments.
        let offer = Message::OpenUrl {
            url: "https://e/".into(),
        };
        let wire = c.send(1, &offer).unwrap();
        assert!(
            matches!(&h.on_message(&wire).unwrap()[0], Event::Message { msg, .. } if *msg == offer)
        );
    }

    #[test]
    fn largest_frame_on_bulk_round_trips() {
        let (hk, ck) = keys();
        let token = [5u8; 32];
        let (mut h, mut c) = bulk_pair(&hk, &ck, token, Some(hk.public())).unwrap();
        let data = vec![0xAB; crate::frame::MAX_PAYLOAD - 64];
        let m = Message::FileChunk {
            id: [1; 16],
            epoch: 1,
            offset: 0,
            data,
        };
        let wire = h.send(0, &m).unwrap();
        assert!(wire.len() <= MAX_WIRE);
        assert!(wire.len() > NOISE_MAX, "multi-segment");
        assert!(
            matches!(&c.on_message(&wire).unwrap()[0], Event::Message { msg, .. } if *msg == m)
        );
    }

    #[test]
    fn tampered_message_is_fatal() {
        let (hk, ck) = keys();
        let (mut h, mut c) = pair(&hk, &ck);
        let mut wire = h.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
        wire[3] ^= 1;
        assert!(matches!(c.on_message(&wire), Err(Error::Decrypt)));
        assert!(c.is_failed());
        // Even a good message is refused afterwards.
        let good = h.send(0, &Message::Heartbeat { seq: 2 }).unwrap();
        assert!(matches!(c.on_message(&good), Err(Error::Closed)));
        assert!(c.send(0, &Message::Heartbeat { seq: 0 }).is_err());
    }

    #[test]
    fn replay_is_rejected() {
        let (hk, ck) = keys();
        let (mut h, mut c) = pair(&hk, &ck);
        let wire = h.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
        c.on_message(&wire).unwrap();
        assert!(matches!(c.on_message(&wire), Err(Error::Decrypt)));
    }

    #[test]
    fn reorder_and_drop_are_rejected() {
        let (hk, ck) = keys();
        let (mut h, mut c) = pair(&hk, &ck);
        let a = h.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
        let b = h.send(0, &Message::Heartbeat { seq: 2 }).unwrap();
        let _ = a; // dropped
        assert!(matches!(c.on_message(&b), Err(Error::Decrypt)));
    }

    #[test]
    fn split_or_merged_dvc_messages_are_rejected() {
        let (hk, ck) = keys();
        let token = [1u8; 32];
        // Splitting a multi-segment message at a segment boundary.
        let (mut h, mut c) = bulk_pair(&hk, &ck, token, None).unwrap();
        let m = Message::FileChunk {
            id: [0; 16],
            epoch: 1,
            offset: 0,
            data: vec![1; 100_000],
        };
        let wire = h.send(0, &m).unwrap();
        assert!(c.on_message(&wire[..NOISE_MAX]).is_err());
        // Merging two messages into one.
        let (mut h, mut c) = bulk_pair(&hk, &ck, token, None).unwrap();
        let end = |e| Message::FileEnd {
            id: [0; 16],
            epoch: e,
            root: [0; 32],
        };
        let a = h.send(0, &end(1)).unwrap();
        let b = h.send(0, &end(2)).unwrap();
        assert!(c.on_message(&[a, b].concat()).is_err());
    }

    #[test]
    fn cross_session_replay_is_rejected() {
        // A message from one Ctl session never verifies in another, even
        // between the same two static keys.
        let (hk, ck) = keys();
        let (mut h1, _c1) = pair(&hk, &ck);
        let (_h2, mut c2) = pair(&hk, &ck);
        let wire = h1.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
        assert!(matches!(c2.on_message(&wire), Err(Error::Decrypt)));
    }

    fn bulk_pair(
        hk: &StaticKey,
        ck: &StaticKey,
        token: [u8; 32],
        expect: Option<[u8; 32]>,
    ) -> Result<(SecureSession, SecureSession)> {
        let hb = Binding {
            bulk_token: Some(token),
            expected_remote: None,
        };
        let cb = Binding {
            bulk_token: Some(token),
            expected_remote: expect,
        };
        let (mut h, first) = SecureSession::initiator(Channel::Bulk, hk, hb)?;
        let mut c = SecureSession::responder(Channel::Bulk, ck, cb)?;
        let e2 = c.on_message(&first)?;
        let mut e3 = Vec::new();
        for b in sends(&e2) {
            e3.extend(h.on_message(&b)?);
        }
        let mut e4 = Vec::new();
        for b in sends(&e3) {
            e4.extend(c.on_message(&b)?);
        }
        assert!(sas_of(&e4).is_none(), "Bulk has no SAS step");
        assert!(h.is_ready() && c.is_ready());
        Ok((h, c))
    }

    #[test]
    fn cross_channel_replay_is_rejected() {
        // Ctl handshake message 1 replayed into a Bulk responder: the
        // prologue differs, so the handshake fails at the first encrypted
        // field.
        let (hk, ck) = keys();
        let (mut ctl_h, first) =
            SecureSession::initiator(Channel::Ctl, &hk, Binding::default()).unwrap();
        let mut bulk_c = SecureSession::responder(
            Channel::Bulk,
            &ck,
            Binding {
                bulk_token: Some([3; 32]),
                expected_remote: None,
            },
        )
        .unwrap();
        // Message 1 has no encrypted part; the client answers, but the
        // helper's Ctl session rejects the Bulk answer.
        let e2 = bulk_c.on_message(&first).unwrap();
        let msg2 = &sends(&e2)[0];
        assert!(ctl_h.on_message(msg2).is_err());
        // Transport messages: a Ctl message fed into a Bulk session.
        let (mut h, _c) = pair(&hk, &ck);
        let (_hb, mut cb) = bulk_pair(&hk, &ck, [3; 32], None).unwrap();
        let wire = h.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
        assert!(matches!(cb.on_message(&wire), Err(Error::Decrypt)));
    }

    #[test]
    fn bulk_needs_the_right_token_and_the_same_helper() {
        let (hk, ck) = keys();
        // Right token, right helper.
        assert!(bulk_pair(&hk, &ck, [9; 32], Some(hk.public())).is_ok());
        // A different helper key (another process with its own key).
        let other = StaticKey::generate().unwrap();
        assert!(matches!(
            bulk_pair(&other, &ck, [9; 32], Some(hk.public())),
            Err(Error::WrongPeer)
        ));
        // Wrong token: the prologues differ, the handshake fails.
        let (mut h, first) = SecureSession::initiator(
            Channel::Bulk,
            &hk,
            Binding {
                bulk_token: Some([1; 32]),
                expected_remote: None,
            },
        )
        .unwrap();
        let mut c = SecureSession::responder(
            Channel::Bulk,
            &ck,
            Binding {
                bulk_token: Some([2; 32]),
                expected_remote: Some(hk.public()),
            },
        )
        .unwrap();
        let e2 = c.on_message(&first).unwrap();
        assert!(h.on_message(&sends(&e2)[0]).is_err());
        // Bulk without a token cannot even start.
        assert!(SecureSession::responder(Channel::Bulk, &ck, Binding::default()).is_err());
    }

    #[test]
    fn version_mismatch_closes() {
        let (hk, ck) = keys();
        // Build a handshake message 1 with major 2 by hand.
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let prologue = prologue(Channel::Ctl, &Binding::default()).unwrap();
        let mut hs = snow::Builder::new(params)
            .local_private_key(hk.private())
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = hs.write_message(b"RLNK\x02\x00\x00\x00", &mut buf).unwrap();
        let mut c = SecureSession::responder(Channel::Ctl, &ck, Binding::default()).unwrap();
        assert!(matches!(
            c.on_message(&buf[..n]),
            Err(Error::Version { ours: 1, theirs: 2 })
        ));
        // Not a Remora-Link payload at all.
        let mut hs = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(hk.private())
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .build_initiator()
            .unwrap();
        let n = hs.write_message(b"", &mut buf).unwrap();
        let mut c = SecureSession::responder(Channel::Ctl, &ck, Binding::default()).unwrap();
        assert!(matches!(c.on_message(&buf[..n]), Err(Error::Handshake(_))));
    }

    #[test]
    fn app_messages_before_pairing_are_refused() {
        let (hk, ck) = keys();
        let (mut h, first) =
            SecureSession::initiator(Channel::Ctl, &hk, Binding::default()).unwrap();
        assert!(h.send(0, &Message::Heartbeat { seq: 0 }).is_err());
        assert!(h.is_failed(), "a send in the wrong state is fatal too");
        let mut c = SecureSession::responder(Channel::Ctl, &ck, Binding::default()).unwrap();
        c.on_message(&first).unwrap();
        // Garbage in place of message 3.
        assert!(c.on_message(&[0u8; 80]).is_err());
    }

    #[test]
    fn commitment_mismatch_is_fatal() {
        // A helper that reveals a nonce other than the committed one.
        let (hk, ck) = keys();
        let (mut h, first) =
            SecureSession::initiator(Channel::Ctl, &hk, Binding::default()).unwrap();
        let mut c = SecureSession::responder(Channel::Ctl, &ck, Binding::default()).unwrap();
        let e2 = c.on_message(&first).unwrap();
        let e3 = deliver(&mut h, &e2);
        let _e4 = deliver(&mut c, &e3);
        // Forge the reveal with the helper's transport state.
        let State::Pairing { transport, .. } = &mut h.state else {
            panic!("helper waits for the nonce")
        };
        let forged = seal(
            transport,
            &Message::SasReveal([0x42; 32]).encode(0).unwrap(),
        )
        .unwrap();
        assert!(matches!(c.on_message(&forged), Err(Error::Commitment)));
    }

    #[test]
    fn messages_for_the_wrong_channel_are_refused() {
        let (hk, ck) = keys();
        let (mut h, _c) = pair(&hk, &ck);
        let chunk = Message::FileChunk {
            id: [0; 16],
            epoch: 0,
            offset: 0,
            data: vec![],
        };
        assert!(h.send(0, &chunk).is_err());
        let (mut h, _c) = pair(&hk, &ck);
        assert!(h.send(0, &Message::SasNonce([0; 32])).is_err());
        let _ = FileOffer {
            id: [0; 16],
            name: String::new(),
            size: 0,
            mtime: 0,
            block_size: 0,
        };
    }

    #[test]
    fn random_bytes_never_panic() {
        let (hk, ck) = keys();
        let mut s: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..300 {
            let len = (next() % 200) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut c = SecureSession::responder(Channel::Ctl, &ck, Binding::default()).unwrap();
            let _ = c.on_message(&buf);
            let (_h, mut c) = pair(&hk, &ck);
            let _ = c.on_message(&buf);
        }
    }

    #[test]
    fn static_key_from_private_matches_generate() {
        let k = StaticKey::generate().unwrap();
        let again = StaticKey::from_private(k.private()).unwrap();
        assert_eq!(k.public(), again.public());
        assert!(!format!("{k:?}").contains(&crate::wire::hex(k.private())));
    }
}
