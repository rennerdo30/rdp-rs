//! The server helper (`remora-agent`) on the client side: answers the
//! `Remora::Ctl` and `Remora::Bulk` dynamic channels with the Remora-Link
//! protocol (docs/HELPER-PROTOCOL.md) and gives the UI a [`HelperHandle`].
//!
//! Security model (RDP-41, owner decisions 2026-11-14):
//! - Fail closed: nothing is answered until the app confirmed the RDP
//!   connection is TLS-protected ([`HelperHandle::set_transport_protocol`]);
//!   a legacy (non-TLS) connection closes both channels.
//! - End-to-end encryption on top of TLS ([`remora_link::SecureSession`]);
//!   any decryption or protocol failure closes the channel.
//! - First contact needs the user to confirm the SAS; then the helper's
//!   key is pinned per server and user. A changed key asks again with a
//!   warning. An admin may set the helper's fingerprint for a connection
//!   instead: then only that key is accepted and no code is compared.
//! - Pairings that end before the user answered are counted (an attacker
//!   in the middle could otherwise retry silently until the codes match):
//!   two per connection refuse the helper for the rest of it, three per
//!   server within a day block pairing with that server until the user
//!   retries (HELPER-PROTOCOL.md 3.3).
//! - Remora's own Noise key is persistent (DPAPI-protected by the app) so
//!   the helper can pin it too; the helper sends data to the client only
//!   once it has (HELPER-PROTOCOL.md 4, 9).
//! - Every helper message is untrusted: one instance per session (a second
//!   channel open is refused), only the capabilities the user enabled
//!   (default: session info only), links and received files go to the app
//!   for confirmation, files are written only into the folder the app
//!   passes, and nothing is ever executed here.

// A few accessors (`last_seen`, `hello` before pairing) are for tests and
// later UI.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rdp::{DvcOut, DynamicChannel, LocalClose};
use remora_link::msg::{
    ErrorMsg, Hello, HelloAck, PairingStatus, SessionInfo, TransferId, UrlStatus, err,
};
use remora_link::transfer::io::{FsDir, FsSource};
use remora_link::transfer::{CHUNK_SIZE, Engine, TransferEvent, WINDOW};
use remora_link::{
    Binding, Channel, Event, Message, PinCheck, PinStore, Sas, SecureSession, StaticKey, cap,
    policy,
};

/// Messages kept while the connection's security is not yet known...
const MAX_BUFFERED: usize = 16;
/// ...and their bytes at most (a handshake is a few hundred bytes).
const MAX_BUFFERED_BYTES: usize = 2 << 20;
/// Pairings per RDP connection that may end before the user answered;
/// then `Remora::Ctl` is refused for the rest of the connection.
pub const MAX_ABORTS_PER_CONNECTION: u32 = 2;
/// The client's heartbeat interval once paired.
const HEARTBEAT: Duration = Duration::from_secs(10);
/// File bytes read per Bulk tick (client-to-server pacing on top of credit).
const BULK_BUDGET: usize = 512 << 10;
/// Reassembly cap for the helper channels: the largest encrypted message
/// plus slack (the DVC default is 16 MiB).
pub const HELPER_MAX_MESSAGE: usize = remora_link::MAX_WIRE + 4096;
/// `PROTOCOL_RDP` (MS-RDPBCGR 2.2.1.2.1): legacy security, no TLS.
const PROTOCOL_RDP: u32 = 0;
/// Events kept for the app at most; beyond it the oldest progress or
/// session info goes first (a helper must not grow the queue unbounded).
pub const MAX_EVENTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperState {
    /// No helper opened the channel (mstsc-only servers stay here).
    NotPresent,
    /// The channel is open; handshake and pairing step running.
    Handshaking,
    /// The user must compare the SAS with the one the helper shows, then
    /// call [`HelperHandle::confirm_pairing`] or `reject_pairing`.
    /// `changed`: a different key was pinned for this server before.
    AwaitingPairing {
        sas: Sas,
        changed: bool,
        /// The helper key's fingerprint, for comparing out of band.
        fingerprint: String,
    },
    /// Paired and HelloAck sent (or waiting for the helper's Hello).
    Paired,
    Failed(String),
    /// Pairing refused: too many attempts ended before the user answered
    /// (two on this connection, or three with this server within a day).
    /// [`HelperHandle::retry_pairing`] lifts it.
    PairingBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperEvent {
    State(HelperState),
    /// The helper asks to open a link; answer with
    /// [`HelperHandle::answer_url`]. Only http and https reach the app.
    OpenUrl {
        request_id: u32,
        url: String,
    },
    SessionInfo(SessionInfo),
    Transfer(TransferEvent),
    /// A second helper instance tried to open a channel; it was refused.
    SecondInstanceRefused(Channel),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Unknown,
    Secure,
    Insecure,
}

struct Link {
    session: SecureSession,
    /// Encrypted messages for this channel, sent on its next call.
    out: Vec<Vec<u8>>,
    /// Close the channel at the next opportunity.
    close: bool,
    /// Received while the transport was unknown.
    buffered: VecDeque<Vec<u8>>,
    buffered_bytes: usize,
}

type PathHook = Arc<dyn Fn(&Path) + Send + Sync>;
type SpaceHook = Arc<dyn Fn(&Path) -> Option<u64> + Send + Sync>;
type Notify = Arc<dyn Fn() + Send + Sync>;

struct Core {
    /// Bumped by [`HelperHandle::reattach`]: channel handlers of an older
    /// RDP connection are stale and do nothing.
    generation: u64,
    enabled: bool,
    user_caps: u32,
    server_id: Option<String>,
    pins_path: Option<PathBuf>,
    /// The aborted-pairing log (`helper-attempts.json`).
    attempts_path: Option<PathBuf>,
    /// An admin-set helper fingerprint: only that key, no SAS.
    expected: Option<[u8; remora_link::FINGERPRINT_LEN]>,
    transport: Transport,
    /// Remora's static key: persistent, so the helper can pin it.
    client_key: StaticKey,
    /// This PC's name, a label for the helper's list of clients.
    client_name: String,
    /// Pairings on this connection that ended before the user answered.
    aborts: u32,
    /// [`MAX_ABORTS_PER_CONNECTION`] reached: Ctl is refused.
    blocked: bool,
    /// A pairing with an unpinned key runs and the user has not answered:
    /// if Ctl ends now, it counts as aborted.
    pairing_open: bool,
    /// The SAS of this Ctl session.
    sas: Option<Sas>,
    /// The user confirmed the code in this Ctl session.
    user_confirmed: bool,
    /// The helper has (or now pinned) this client's key: `PeerPairing`
    /// Known or Confirmed, or a 1.0 helper that never says.
    peer_ok: bool,
    /// The helper asked its own user and the answer is not in yet.
    server_pending: bool,
    ctl: Option<Link>,
    bulk: Option<Link>,
    state: HelperState,
    helper_key: Option<[u8; 32]>,
    pin: Option<PinCheck>,
    paired: bool,
    hello: Option<Hello>,
    ack_sent: bool,
    accepted: u32,
    bulk_token: Option<[u8; 32]>,
    session_info: Option<SessionInfo>,
    last_seen: Option<Instant>,
    next_heartbeat: Option<Instant>,
    heartbeat_seq: u32,
    open_urls: Vec<u32>,
    engine: Engine,
    events: VecDeque<HelperEvent>,
    /// Second channel opens refused so far (one event is queued at a time).
    refusals: u32,
    notify: Option<Notify>,
    on_received: Option<PathHook>,
    free_space: Option<SpaceHook>,
}

impl Core {
    fn set_state(&mut self, s: HelperState) {
        if self.state != s {
            self.state = s.clone();
            self.push(HelperEvent::State(s));
        }
    }

    /// Queues an event for the app, bounded: repeated refusals are counted
    /// (one event waits at a time), progress and session info replace their
    /// own older entry, and a full queue drops its oldest such entry first.
    fn push(&mut self, e: HelperEvent) {
        let q = &mut self.events;
        let coalesced = match &e {
            HelperEvent::SecondInstanceRefused(_) => {
                self.refusals = self.refusals.saturating_add(1);
                q.iter()
                    .any(|x| matches!(x, HelperEvent::SecondInstanceRefused(_)))
            }
            HelperEvent::SessionInfo(_) => {
                q.retain(|x| !matches!(x, HelperEvent::SessionInfo(_)));
                false
            }
            HelperEvent::Transfer(TransferEvent::Progress { id, direction, .. }) => {
                let old = q.iter_mut().find(|x| {
                    matches!(x, HelperEvent::Transfer(TransferEvent::Progress { id: i, direction: d, .. })
                        if i == id && d == direction)
                });
                match old {
                    Some(slot) => {
                        *slot = e.clone();
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if !coalesced {
            if q.len() >= MAX_EVENTS {
                let cheap = q.iter().position(|x| {
                    matches!(
                        x,
                        HelperEvent::SessionInfo(_)
                            | HelperEvent::Transfer(TransferEvent::Progress { .. })
                    )
                });
                match cheap {
                    Some(i) => {
                        q.remove(i);
                    }
                    None => {
                        q.pop_front();
                    }
                }
            }
            q.push_back(e);
        }
        if let Some(n) = &self.notify {
            n();
        }
    }

    /// Ctl is ending (closed or failed). A pairing still open counts as
    /// aborted; returns whether pairing is now blocked.
    fn end_pairing(&mut self) -> bool {
        if !std::mem::take(&mut self.pairing_open) {
            return false;
        }
        self.aborts += 1;
        if self.aborts >= MAX_ABORTS_PER_CONNECTION {
            self.blocked = true;
        }
        let persisted = match (&self.attempts_path, &self.server_id) {
            (Some(p), Some(id)) => {
                remora_link::AttemptLog::record_abort(p, id, now_secs()).unwrap_or(false)
            }
            _ => false,
        };
        rdp::trace!(
            "helper: pairing ended before the user answered ({} on this connection)",
            self.aborts
        );
        self.blocked || persisted
    }

    /// Pairing with this server is blocked across connections.
    fn server_blocked(&self) -> bool {
        match (&self.attempts_path, &self.server_id) {
            (Some(p), Some(id)) => remora_link::AttemptLog::is_blocked(p, id),
            _ => false,
        }
    }

    fn link(&mut self, ch: Channel) -> &mut Option<Link> {
        match ch {
            Channel::Ctl => &mut self.ctl,
            Channel::Bulk => &mut self.bulk,
        }
    }

    /// Fails the channel `ch` (and Bulk with Ctl) with a reason.
    fn fail(&mut self, ch: Channel, why: String) {
        if let Some(l) = self.link(ch) {
            l.close = true;
        }
        if ch == Channel::Ctl {
            if let Some(l) = &mut self.bulk {
                l.close = true;
            }
            if self.end_pairing() {
                self.set_state(HelperState::PairingBlocked);
            } else {
                self.set_state(HelperState::Failed(why));
            }
        }
        self.update_engine_link();
    }

    /// Closes Ctl (and Bulk) because pairing is blocked.
    fn block(&mut self) {
        for ch in [Channel::Ctl, Channel::Bulk] {
            if let Some(l) = self.link(ch) {
                l.close = true;
            }
        }
        self.pairing_open = false;
        self.set_state(HelperState::PairingBlocked);
        self.update_engine_link();
    }

    /// Encrypts `msg` onto its channel. No-op when that channel is down.
    fn send(&mut self, request_id: u32, msg: &Message) {
        let ch = msg.channel();
        let Some(l) = self.link(ch) else { return };
        if l.close || !l.session.is_ready() {
            return;
        }
        match l.session.send(request_id, msg) {
            Ok(b) => l.out.push(b),
            Err(e) => self.fail(ch, format!("send failed: {e}")),
        }
    }

    fn ready(&self, ch: Channel) -> bool {
        let l = match ch {
            Channel::Ctl => &self.ctl,
            Channel::Bulk => &self.bulk,
        };
        l.as_ref().is_some_and(|l| !l.close && l.session.is_ready())
    }

    fn update_engine_link(&mut self) {
        let up = self.ack_sent && self.ready(Channel::Ctl) && self.ready(Channel::Bulk);
        self.engine.set_connected(up);
        self.flush_engine();
    }

    fn flush_engine(&mut self) {
        for m in self.engine.take_messages() {
            self.send(0, &m);
        }
        while let Some(e) = self.engine.next_event() {
            self.push(HelperEvent::Transfer(e));
        }
    }

    fn open(&mut self, ch: Channel) -> Result<(), String> {
        if !self.enabled {
            return Err("the helper is switched off".into());
        }
        if self.transport == Transport::Insecure {
            return Err("the connection is not TLS-protected".into());
        }
        if ch == Channel::Ctl && self.blocked {
            self.set_state(HelperState::PairingBlocked);
            return Err("pairing blocked: too many aborted attempts".into());
        }
        let binding = match ch {
            Channel::Ctl => Binding::default(),
            Channel::Bulk => {
                // Bulk only for the paired helper of this session.
                let (Some(token), Some(key), true) =
                    (self.bulk_token, self.helper_key, self.ack_sent)
                else {
                    return Err("Remora::Bulk opened before Remora::Ctl was paired".into());
                };
                Binding {
                    bulk_token: Some(token),
                    expected_remote: Some(key),
                }
            }
        };
        let session =
            SecureSession::responder(ch, &self.client_key, binding).map_err(|e| e.to_string())?;
        *self.link(ch) = Some(Link {
            session,
            out: Vec::new(),
            close: false,
            buffered: VecDeque::new(),
            buffered_bytes: 0,
        });
        if ch == Channel::Ctl {
            self.reset_ctl();
            self.set_state(HelperState::Handshaking);
        }
        Ok(())
    }

    fn reset_ctl(&mut self) {
        self.helper_key = None;
        self.pin = None;
        self.paired = false;
        self.hello = None;
        self.ack_sent = false;
        self.accepted = 0;
        self.bulk_token = None;
        self.session_info = None;
        self.next_heartbeat = None;
        self.open_urls.clear();
        self.pairing_open = false;
        self.sas = None;
        self.user_confirmed = false;
        self.peer_ok = false;
        self.server_pending = false;
    }

    fn closed(&mut self, ch: Channel) {
        *self.link(ch) = None;
        if ch == Channel::Ctl {
            if let Some(l) = &mut self.bulk {
                l.close = true;
            }
            let blocked = self.end_pairing();
            self.reset_ctl();
            if blocked {
                self.set_state(HelperState::PairingBlocked);
            } else if !matches!(
                self.state,
                HelperState::Failed(_) | HelperState::PairingBlocked
            ) {
                self.set_state(HelperState::NotPresent);
            }
        }
        self.update_engine_link();
    }

    fn receive(&mut self, ch: Channel, wire: &[u8]) {
        let transport = self.transport;
        let Some(l) = self.link(ch) else { return };
        if l.close {
            return;
        }
        match transport {
            Transport::Insecure => self.fail(ch, "the connection is not TLS-protected".into()),
            Transport::Unknown
                if l.buffered.len() >= MAX_BUFFERED
                    || l.buffered_bytes + wire.len() > MAX_BUFFERED_BYTES =>
            {
                self.fail(ch, "too much data before the connection was checked".into())
            }
            Transport::Unknown => {
                l.buffered_bytes += wire.len();
                l.buffered.push_back(wire.to_vec());
            }
            Transport::Secure => self.process(ch, wire),
        }
    }

    fn set_transport(&mut self, t: Transport) {
        self.transport = t;
        for ch in [Channel::Ctl, Channel::Bulk] {
            let Some(l) = self.link(ch) else { continue };
            let pending: Vec<_> = l.buffered.drain(..).collect();
            l.buffered_bytes = 0;
            if t == Transport::Insecure {
                self.fail(ch, "the connection is not TLS-protected".into());
                continue;
            }
            for w in pending {
                self.process(ch, &w);
            }
        }
    }

    fn process(&mut self, ch: Channel, wire: &[u8]) {
        let Some(l) = self.link(ch) else { return };
        let events = match l.session.on_message(wire) {
            Ok(ev) => ev,
            Err(e) => return self.fail(ch, e.to_string()),
        };
        for ev in events {
            if self.link(ch).as_ref().is_none_or(|l| l.close) {
                return;
            }
            match ev {
                Event::Send(b) => {
                    if let Some(l) = self.link(ch) {
                        l.out.push(b);
                    }
                }
                Event::Established { remote_static } => match ch {
                    Channel::Ctl => {
                        if !self.established(remote_static) {
                            return;
                        }
                    }
                    Channel::Bulk => self.update_engine_link(),
                },
                Event::Sas(sas) => self.on_sas(sas),
                Event::Message { request_id, msg } => match ch {
                    Channel::Ctl => self.on_ctl(request_id, msg),
                    Channel::Bulk => {
                        // Only file data travels on Bulk; the session
                        // already refused Ctl-only types.
                        if !self.engine.handle(&msg) {
                            self.send_unsupported(&msg);
                        }
                        self.flush_engine();
                    }
                },
            }
        }
    }

    fn check_pin(&self, key: &[u8; 32]) -> PinCheck {
        let store = match &self.pins_path {
            Some(p) => PinStore::load(p),
            None => Ok(PinStore::new()),
        };
        match (store, &self.server_id) {
            (Ok(s), Some(id)) => s.check(id, key),
            (Ok(_), None) => PinCheck::New,
            // An unreadable store must not turn a changed key into a new one.
            (Err(_), _) => PinCheck::Changed {
                previous: [0; 32],
                first_seen: 0,
            },
        }
    }

    /// The Ctl handshake proved the helper's key: check it against the pin
    /// store (or the admin-set fingerprint) and the attempt limit. False
    /// when the session was closed.
    fn established(&mut self, key: [u8; 32]) -> bool {
        self.helper_key = Some(key);
        let mut pin = self.check_pin(&key);
        if let Some(want) = self.expected {
            if remora_link::fingerprint_bytes(&key) != want {
                self.fail(
                    Channel::Ctl,
                    "the helper's fingerprint is not the one set for this connection".into(),
                );
                return false;
            }
            // The admin's pin stands for the SAS: pin exactly this key.
            if pin != PinCheck::Known
                && let (Some(p), Some(id)) = (&self.pins_path, &self.server_id)
            {
                let _ = PinStore::update(p, |s| s.pin(id, &key, now_secs()));
            }
            pin = PinCheck::Known;
        }
        if pin != PinCheck::Known {
            if self.blocked || self.server_blocked() {
                self.block();
                return false;
            }
            self.pairing_open = true;
        }
        self.pin = Some(pin);
        true
    }

    /// The fingerprint of the helper key of this Ctl session.
    fn helper_fingerprint(&self) -> String {
        self.helper_key
            .map(|k| remora_link::fingerprint(&k))
            .unwrap_or_default()
    }

    fn on_sas(&mut self, sas: Sas) {
        self.sas = Some(sas);
        if !self.client_name.is_empty() {
            let name =
                remora_link::wire::truncate(&self.client_name, remora_link::msg::MAX_CLIENT_NAME)
                    .to_string();
            self.send(0, &Message::ClientName { name });
        }
        let fingerprint = self.helper_fingerprint();
        match self.pin.clone() {
            Some(PinCheck::Known) => {
                self.send(0, &Message::Pairing(PairingStatus::Known));
                if let (Some(p), Some(id)) = (&self.pins_path, &self.server_id) {
                    let _ = PinStore::update(p, |s| s.touch(id, now_secs()));
                }
                self.paired();
            }
            Some(PinCheck::Changed { .. }) => {
                self.send(0, &Message::Pairing(PairingStatus::Confirm));
                self.set_state(HelperState::AwaitingPairing {
                    sas,
                    changed: true,
                    fingerprint,
                });
            }
            Some(PinCheck::New) | None => {
                self.send(0, &Message::Pairing(PairingStatus::Confirm));
                self.set_state(HelperState::AwaitingPairing {
                    sas,
                    changed: false,
                    fingerprint,
                });
            }
        }
    }

    /// The helper's side of pairing (1.1).
    fn on_peer_pairing(&mut self, st: PairingStatus) {
        match st {
            PairingStatus::Known | PairingStatus::Confirmed => {
                self.peer_ok = true;
                self.server_pending = false;
                if let Err(e) = self.maybe_pin() {
                    rdp::trace!("helper: {e}");
                }
            }
            PairingStatus::Confirm => {
                self.server_pending = true;
                // The helper does not know this PC and shows its code; the
                // user needs Remora's code to compare, also for a helper
                // Remora knows.
                if let (Some(sas), HelperState::Paired) = (self.sas, &self.state) {
                    if !self.ack_sent {
                        self.paired = false;
                    }
                    let fingerprint = self.helper_fingerprint();
                    self.set_state(HelperState::AwaitingPairing {
                        sas,
                        changed: false,
                        fingerprint,
                    });
                }
            }
            PairingStatus::Rejected => self.server_pending = false,
        }
    }

    /// Pins the helper key once both users confirmed: here, and on the
    /// server (or the helper already knew this PC). A 1.0 helper never
    /// says; its pairing needs Remora's confirmation only.
    fn maybe_pin(&mut self) -> Result<(), String> {
        let peer_ok = self.peer_ok || self.hello.as_ref().is_some_and(|h| h.minor == 0);
        if !self.user_confirmed || !peer_ok || self.pin == Some(PinCheck::Known) {
            return Ok(());
        }
        let Some(key) = self.helper_key else {
            return Ok(());
        };
        self.pin = Some(PinCheck::Known);
        let (Some(p), Some(id)) = (self.pins_path.clone(), self.server_id.clone()) else {
            return Ok(());
        };
        // An unreadable store is not overwritten (it may hold other
        // servers); the pairing then holds for this session only.
        PinStore::update(&p, |s| s.pin(&id, &key, now_secs()))
            .map_err(|e| format!("paired for this session only: {e}"))
    }

    fn paired(&mut self) {
        self.paired = true;
        self.set_state(HelperState::Paired);
        self.send_ack();
    }

    /// HelloAck once paired and the helper's Hello is in.
    fn send_ack(&mut self) {
        let Some(h) = &self.hello else { return };
        if !self.paired || self.ack_sent {
            return;
        }
        let mut caps = h.capabilities & self.user_caps & cap::ALL;
        if h.policy & policy::BLOCKS_FILE_TRANSFER != 0 {
            caps &= !(cap::FILE_UP | cap::FILE_DOWN);
        }
        // Received files get the Mark-of-the-Web, or none are received.
        if self.on_received.is_none() {
            caps &= !cap::FILE_DOWN;
        }
        let mut token = [0u8; 32];
        if let Err(e) = remora_link::random(&mut token) {
            return self.fail(Channel::Ctl, e.to_string());
        }
        self.accepted = caps;
        self.bulk_token = Some(token);
        self.send(
            0,
            &Message::HelloAck(HelloAck {
                major: remora_link::PROTO_MAJOR,
                minor: remora_link::PROTO_MINOR,
                capabilities: caps,
                max_message: remora_link::frame::MAX_MESSAGE as u32,
                max_chunk: CHUNK_SIZE,
                window: WINDOW as u32,
                bulk_token: token,
            }),
        );
        self.ack_sent = true;
        self.engine
            .set_permissions(caps & cap::FILE_UP != 0, caps & cap::FILE_DOWN != 0);
        self.next_heartbeat = Some(Instant::now() + HEARTBEAT);
        self.update_engine_link();
    }

    fn send_error(&mut self, code: u32, message: &str) {
        self.send(
            0,
            &Message::Error(ErrorMsg {
                code,
                message: message.into(),
            }),
        );
    }

    fn send_unsupported(&mut self, msg: &Message) {
        self.send(0, &Message::Unsupported { ty: msg.ty() });
    }

    fn on_ctl(&mut self, request_id: u32, msg: Message) {
        self.last_seen = Some(Instant::now());
        match msg {
            Message::Hello(h) => {
                if h.major != remora_link::PROTO_MAJOR {
                    self.send_error(err::VERSION, "unsupported major version");
                    return self.fail(Channel::Ctl, "the helper speaks another version".into());
                }
                if self.hello.is_some() {
                    return self.send_error(err::PROTOCOL, "second Hello");
                }
                self.hello = Some(h);
                if let Err(e) = self.maybe_pin() {
                    rdp::trace!("helper: {e}");
                }
                self.send_ack();
            }
            Message::Heartbeat { .. } => {}
            Message::PeerPairing(st) => self.on_peer_pairing(st),
            Message::Unknown { ty } => self.send(0, &Message::Unsupported { ty }),
            Message::Unsupported { .. } | Message::Error(_) => {}
            // Everything below needs a paired helper and an accepted capability.
            _ if !self.ack_sent => self.send_error(err::NOT_ALLOWED, "not paired"),
            Message::SessionInfo(info) => {
                if self.accepted & cap::SESSION_INFO == 0 {
                    return self.send_error(err::NOT_ALLOWED, "session info not enabled");
                }
                self.session_info = Some(info.clone());
                self.push(HelperEvent::SessionInfo(info));
            }
            Message::OpenUrl { url } => {
                let parsed = web_url(&url);
                if self.accepted & cap::OPEN_URL == 0 {
                    self.send(request_id, &Message::OpenUrlResult(UrlStatus::Disabled));
                } else if parsed.is_none() {
                    self.send(request_id, &Message::OpenUrlResult(UrlStatus::Invalid));
                } else if self.open_urls.len() >= 8 {
                    self.send(request_id, &Message::OpenUrlResult(UrlStatus::Declined));
                } else if let Some(u) = parsed {
                    // Only the re-serialized URL (ASCII host) leaves here.
                    self.open_urls.push(request_id);
                    self.push(HelperEvent::OpenUrl {
                        request_id,
                        url: u.to_string(),
                    });
                }
            }
            m @ (Message::FileOffer(_)
            | Message::FileAccept { .. }
            | Message::FileReject { .. }
            | Message::FileCredit { .. }
            | Message::FileCancel { .. }
            | Message::FileComplete { .. }) => {
                self.engine.handle(&m);
                self.flush_engine();
            }
            // Client-to-helper messages coming back are protocol errors.
            other => self.send_error(
                err::PROTOCOL,
                &format!("unexpected type {:#06x}", other.ty()),
            ),
        }
    }

    fn tick(&mut self, ch: Channel) {
        if self.transport != Transport::Secure {
            return;
        }
        match ch {
            Channel::Ctl => {
                if let Some(t) = self.next_heartbeat
                    && Instant::now() >= t
                {
                    self.heartbeat_seq = self.heartbeat_seq.wrapping_add(1);
                    let seq = self.heartbeat_seq;
                    self.send(0, &Message::Heartbeat { seq });
                    self.next_heartbeat = Some(Instant::now() + HEARTBEAT);
                }
            }
            Channel::Bulk => {
                self.engine.poll(BULK_BUDGET);
                self.flush_engine();
            }
        }
    }

    fn fs_dir(&self, folder: &Path) -> FsDir {
        let mut d = FsDir::new(folder);
        if let Some(f) = self.free_space.clone() {
            d = d.with_free_space(move |p| f(p));
        }
        if let Some(f) = self.on_received.clone() {
            d = d.on_finished(move |p| f(p));
        }
        d
    }
}

/// Characters a link from the helper may not contain anywhere: they have no
/// place in a plain web link and are what command lines, HTML and Windows
/// paths split on.
const URL_FORBIDDEN: [char; 9] = ['"', '<', '>', '\\', '`', '|', '{', '}', '^'];

/// The helper's link as a WHATWG URL, if it is an absolute http or https
/// URL with a host and nothing suspicious: no user info (`a@b`), no
/// spaces, control characters or [`URL_FORBIDDEN`] characters. Its
/// serialization (punycode host, percent-encoded path) is the only form
/// the app shows or opens.
pub fn web_url(raw: &str) -> Option<url::Url> {
    if raw.len() > remora_link::msg::MAX_URL
        || raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || URL_FORBIDDEN.contains(&c))
    {
        return None;
    }
    let lower = raw.get(..8).map(str::to_ascii_lowercase)?;
    let rest = if lower.starts_with("https://") {
        &raw[8..]
    } else if lower.starts_with("http://") {
        &raw[7..]
    } else {
        return None;
    };
    // The authority as written: present, and without user info.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let u = url::Url::parse(raw).ok()?;
    let ok = matches!(u.scheme(), "http" | "https")
        && u.username().is_empty()
        && u.password().is_none()
        && u.host_str().is_some_and(|h| !h.is_empty() && h.is_ascii())
        && u.as_str().len() <= remora_link::msg::MAX_URL;
    ok.then_some(u)
}

/// [`web_url`] accepts it.
pub fn is_web_url(url: &str) -> bool {
    web_url(url).is_some()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The UI's side of the helper. Cheap to clone; every method is non-blocking
/// except `accept_file` on a resume, which re-reads the partial file once.
#[derive(Clone)]
pub struct HelperHandle {
    core: Arc<Mutex<Core>>,
}

impl HelperHandle {
    /// A helper listener: enabled, session info allowed, nothing else until
    /// the user switches it on. The client's Noise key is fresh until the
    /// app sets the persistent one ([`HelperHandle::set_client`]).
    pub fn new() -> HelperHandle {
        let client_key = StaticKey::generate().expect("OS random generator");
        HelperHandle {
            core: Arc::new(Mutex::new(Core {
                generation: 0,
                enabled: true,
                user_caps: cap::SESSION_INFO,
                server_id: None,
                pins_path: None,
                attempts_path: None,
                expected: None,
                transport: Transport::Unknown,
                client_key,
                client_name: String::new(),
                aborts: 0,
                blocked: false,
                pairing_open: false,
                sas: None,
                user_confirmed: false,
                peer_ok: false,
                server_pending: false,
                ctl: None,
                bulk: None,
                state: HelperState::NotPresent,
                helper_key: None,
                pin: None,
                paired: false,
                hello: None,
                ack_sent: false,
                accepted: 0,
                bulk_token: None,
                session_info: None,
                last_seen: None,
                next_heartbeat: None,
                heartbeat_seq: 0,
                open_urls: Vec::new(),
                engine: Engine::default(),
                events: VecDeque::new(),
                refusals: 0,
                notify: None,
                on_received: None,
                free_space: None,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The two dynamic channel handlers to register with `Drdynvc`.
    pub fn channels(&self) -> Vec<Box<dyn DynamicChannel>> {
        let generation = self.lock().generation;
        [Channel::Ctl, Channel::Bulk]
            .into_iter()
            .map(|ch| {
                Box::new(HelperChannel {
                    ch,
                    generation,
                    core: self.core.clone(),
                }) as Box<dyn DynamicChannel>
            })
            .collect()
    }

    /// A new RDP connection of the same tab (an automatic or manual
    /// reconnect): drops the old connection's channels and secure sessions,
    /// forgets its transport check and pairing, and returns fresh channel
    /// handlers. File transfers are kept, paused, and resume once the helper
    /// is paired again on the new connection (docs/HELPER-PROTOCOL.md 8).
    /// Handlers of the old connection do nothing from now on, even if its
    /// session thread still runs. The per-connection attempt limit starts
    /// over; the per-server one does not.
    pub fn reattach(&self) -> Vec<Box<dyn DynamicChannel>> {
        {
            let mut c = self.lock();
            c.generation = c.generation.wrapping_add(1);
            c.ctl = None;
            c.bulk = None;
            c.reset_ctl();
            c.transport = Transport::Unknown;
            c.aborts = 0;
            c.blocked = false;
            c.set_state(HelperState::NotPresent);
            c.update_engine_link();
        }
        self.channels()
    }

    /// Off: helper channels are closed as soon as they open.
    pub fn set_enabled(&self, on: bool) {
        let mut c = self.lock();
        c.enabled = on;
        if !on {
            for ch in [Channel::Ctl, Channel::Bulk] {
                if let Some(l) = c.link(ch) {
                    l.close = true;
                }
            }
        }
    }

    /// [`cap`] bits the user allows. Takes effect at the next HelloAck;
    /// removing file-transfer bits also stops running transfers now.
    pub fn set_capabilities(&self, bits: u32) {
        let mut c = self.lock();
        c.user_caps = bits & cap::ALL;
        c.accepted &= c.user_caps;
        let a = c.accepted;
        c.engine
            .set_permissions(a & cap::FILE_UP != 0, a & cap::FILE_DOWN != 0);
        c.flush_engine();
    }

    /// The server the helper runs on (for pinning) and the pin store file.
    pub fn set_server(&self, server_id: String, pins_path: Option<PathBuf>) {
        let mut c = self.lock();
        c.server_id = Some(server_id);
        c.pins_path = pins_path;
    }

    /// Remora's persistent static key and this PC's name (the label the
    /// helper keeps for it).
    pub fn set_client(&self, key: StaticKey, name: &str) {
        let mut c = self.lock();
        c.client_key = key;
        c.client_name = name.to_string();
    }

    /// The aborted-pairing log, and an admin-set helper fingerprint for
    /// this connection (only that key is accepted, without a SAS).
    pub fn set_pairing_policy(
        &self,
        attempts_path: Option<PathBuf>,
        expected: Option<[u8; remora_link::FINGERPRINT_LEN]>,
    ) {
        let mut c = self.lock();
        c.attempts_path = attempts_path;
        c.expected = expected;
    }

    /// The user asks to pair again after [`HelperState::PairingBlocked`]:
    /// the server's aborted attempts and this connection's are forgotten,
    /// and the helper's next open is answered.
    pub fn retry_pairing(&self) -> Result<(), String> {
        let mut c = self.lock();
        c.aborts = 0;
        c.blocked = false;
        let r = match (&c.attempts_path, &c.server_id) {
            (Some(p), Some(id)) => remora_link::AttemptLog::clear(p, id).map_err(|e| e.to_string()),
            _ => Ok(()),
        };
        if c.state == HelperState::PairingBlocked {
            c.set_state(HelperState::NotPresent);
        }
        r
    }

    /// The fingerprint of the helper key seen on this connection.
    pub fn helper_fingerprint(&self) -> Option<String> {
        self.lock().helper_key.map(|k| remora_link::fingerprint(&k))
    }

    /// The helper asked its own user to confirm this PC and has no answer
    /// yet: nothing leaves the server until then.
    pub fn server_pending(&self) -> bool {
        self.lock().server_pending
    }

    /// The negotiated RDP security protocol (`ConnectionInfo::protocol`).
    /// Until this is called nothing is answered; `PROTOCOL_RDP` (no TLS)
    /// closes the helper channels for good.
    pub fn set_transport_protocol(&self, protocol: u32) {
        let t = if protocol == PROTOCOL_RDP {
            Transport::Insecure
        } else {
            Transport::Secure
        };
        self.lock().set_transport(t);
    }

    /// Called (on the session thread) whenever an event is queued.
    pub fn set_notify(&self, f: impl Fn() + Send + Sync + 'static) {
        self.lock().notify = Some(Arc::new(f));
    }

    /// Called with the full path of every received file: the app adds the
    /// Mark-of-the-Web here.
    pub fn set_received_file_hook(&self, f: impl Fn(&Path) + Send + Sync + 'static) {
        self.lock().on_received = Some(Arc::new(f));
    }

    /// Free bytes on the volume of a folder; without it the check is skipped.
    pub fn set_free_space(&self, f: impl Fn(&Path) -> Option<u64> + Send + Sync + 'static) {
        self.lock().free_space = Some(Arc::new(f));
    }

    pub fn state(&self) -> HelperState {
        self.lock().state.clone()
    }

    /// The helper's Hello (untrusted until paired).
    pub fn hello(&self) -> Option<Hello> {
        self.lock().hello.clone()
    }

    /// Capabilities in force (0 before HelloAck).
    pub fn accepted_capabilities(&self) -> u32 {
        self.lock().accepted
    }

    pub fn session_info(&self) -> Option<SessionInfo> {
        self.lock().session_info.clone()
    }

    /// How many second helper instances were refused on this connection.
    pub fn second_instance_refusals(&self) -> u32 {
        self.lock().refusals
    }

    /// When the helper last sent anything on Ctl.
    pub fn last_seen(&self) -> Option<Instant> {
        self.lock().last_seen
    }

    pub fn next_event(&self) -> Option<HelperEvent> {
        self.lock().events.pop_front()
    }

    /// The user confirmed that the code `shown` matches the helper's: pin
    /// the key and continue. Refused when the pairing waiting now is not
    /// the one the dialog showed (the helper started over meanwhile: its
    /// new code needs its own answer).
    pub fn confirm_pairing(&self, shown: Sas) -> Result<(), String> {
        let mut c = self.lock();
        match &c.state {
            HelperState::AwaitingPairing { sas, .. } if *sas == shown => {}
            HelperState::AwaitingPairing { .. } => {
                return Err("the helper started pairing again with a new code".into());
            }
            _ => return Err("no pairing to confirm".into()),
        }
        c.helper_key.ok_or("no helper key")?;
        c.pairing_open = false;
        c.user_confirmed = true;
        c.send(0, &Message::Pairing(PairingStatus::Confirmed));
        c.paired();
        // Pinned once the server's side confirmed too (or knew this PC).
        c.maybe_pin()
    }

    /// The code `shown` did not match or the user declined: close the
    /// helper. Only the pairing the dialog showed is rejected.
    pub fn reject_pairing(&self, shown: Sas) {
        let mut c = self.lock();
        if !matches!(&c.state, HelperState::AwaitingPairing { sas, .. } if *sas == shown) {
            return;
        }
        // The user's own answer: not an aborted attempt.
        c.pairing_open = false;
        c.send(0, &Message::Pairing(PairingStatus::Rejected));
        c.send_error(err::PAIRING_REJECTED, "pairing rejected");
        c.fail(Channel::Ctl, "pairing rejected".into());
    }

    /// The app's answer to [`HelperEvent::OpenUrl`].
    pub fn answer_url(&self, request_id: u32, status: UrlStatus) {
        let mut c = self.lock();
        if let Some(i) = c.open_urls.iter().position(|&r| r == request_id) {
            c.open_urls.remove(i);
            c.send(request_id, &Message::OpenUrlResult(status));
        }
    }

    /// Sends a local file to the server (needs [`cap::FILE_UP`]).
    pub fn send_file(&self, path: &Path) -> Result<TransferId, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("not a file name")?
            .to_string();
        let source = FsSource::open(path).map_err(|e| e.to_string())?;
        let mut c = self.lock();
        let id = c
            .engine
            .send(&name, Box::new(source))
            .map_err(|e| e.to_string())?;
        c.flush_engine();
        Ok(id)
    }

    /// Accepts an offered file into `folder` (the user's chosen folder).
    pub fn accept_file(&self, id: TransferId, folder: &Path) -> Result<(), String> {
        let mut c = self.lock();
        let dir = c.fs_dir(folder);
        let r = c
            .engine
            .accept(id, Box::new(dir))
            .map_err(|e| e.to_string());
        c.flush_engine();
        r
    }

    pub fn reject_file(&self, id: TransferId) {
        let mut c = self.lock();
        c.engine.reject(id);
        c.flush_engine();
    }

    pub fn cancel_file(&self, id: TransferId) {
        let mut c = self.lock();
        c.engine.cancel(id);
        c.flush_engine();
    }
}

impl Default for HelperHandle {
    fn default() -> Self {
        HelperHandle::new()
    }
}

/// `Remora::Ctl` or `Remora::Bulk` on the session thread.
struct HelperChannel {
    ch: Channel,
    /// The connection this handler belongs to ([`HelperHandle::reattach`]).
    generation: u64,
    core: Arc<Mutex<Core>>,
}

impl HelperChannel {
    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The core, unless this handler belongs to an older connection.
    fn current(&self) -> Option<MutexGuard<'_, Core>> {
        let c = self.lock();
        (c.generation == self.generation).then_some(c)
    }

    fn stale(&self) -> rdp::Error {
        rdp::Error::Protocol(format!("{}: an older connection", self.ch.name()))
    }

    /// Moves queued bytes out; an error closes the channel.
    fn drain(&self, out: &mut DvcOut) -> rdp::Result<()> {
        let Some(mut c) = self.current() else {
            return Err(self.stale());
        };
        let Some(l) = c.link(self.ch) else {
            return Ok(());
        };
        for m in l.out.drain(..) {
            out.send(m);
        }
        if l.close {
            return Err(rdp::Error::Protocol(format!("{} closed", self.ch.name())));
        }
        Ok(())
    }
}

impl DynamicChannel for HelperChannel {
    fn name(&self) -> &str {
        self.ch.name()
    }

    fn opened(&mut self, out: &mut DvcOut) -> rdp::Result<()> {
        let r = match self.current() {
            Some(mut c) => c.open(self.ch),
            None => return Err(self.stale()),
        };
        if let Err(e) = r {
            return Err(rdp::Error::Protocol(e));
        }
        self.drain(out)
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> rdp::Result<()> {
        match self.current() {
            Some(mut c) => c.receive(self.ch, msg),
            None => return Err(self.stale()),
        }
        self.drain(out)
    }

    fn tick(&mut self, out: &mut DvcOut) -> rdp::Result<()> {
        match self.current() {
            Some(mut c) => c.tick(self.ch),
            // Not open on the old connection: nothing to close.
            None => return Ok(()),
        }
        self.drain(out)
    }

    fn closed(&mut self) {
        if let Some(mut c) = self.current() {
            c.closed(self.ch);
        }
    }

    fn max_message_size(&self) -> usize {
        HELPER_MAX_MESSAGE
    }

    /// One helper instance per session: a second open is refused.
    fn allow_second_instance(&mut self) -> bool {
        if let Some(mut c) = self.current() {
            c.push(HelperEvent::SecondInstanceRefused(self.ch));
        }
        false
    }

    /// Records why the DVC layer closed Ctl. `HandlerError` is this module's
    /// own close request, whose reason is already recorded.
    fn closing(&mut self, why: LocalClose) {
        let Some(mut c) = self.current() else { return };
        if self.ch == Channel::Ctl
            && why != LocalClose::HandlerError
            && !matches!(c.state, HelperState::Failed(_))
        {
            c.set_state(HelperState::Failed(format!("channel closed: {why:?}")));
        }
    }
}

#[cfg(test)]
mod tests;
