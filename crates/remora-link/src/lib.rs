//! Remora-Link: the protocol between Remora (the RDP client) and
//! `remora-agent` (the helper in the user's session on the server).
//!
//! The helper opens two dynamic virtual channels, [`CTL_CHANNEL`]
//! (`PRI_MED`) and [`BULK_CHANNEL`] (`PRI_LOW`), both with
//! `WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS`. One DVC message is one protocol
//! message. Everything here is platform independent and sans-IO; the
//! caller moves whole messages.
//!
//! The full contract is `docs/HELPER-PROTOCOL.md`. In short:
//! - [`frame`]: the 12-byte header and the 1 MiB limit;
//! - [`msg`]: the message types (version 1.0) and capability bits;
//! - [`session`]: the Noise handshake (helper = initiator), SAS pairing and
//!   per-message ChaCha20-Poly1305; any error is fatal for the channel;
//! - [`pins`]: pinned keys (the client's helpers, the helper's clients)
//!   and the pairing attempt limit;
//! - [`store`]: lock-and-merge updates of those small JSON files;
//! - [`transfer`]: resumable, verified file transfer, both directions.
//!
//! # Driving a channel (both sides)
//!
//! ```
//! use remora_link::{Binding, Channel, Event, Message, SecureSession, StaticKey};
//!
//! // Helper: open the channel, then send the first handshake message.
//! let helper_key = StaticKey::generate().unwrap(); // stored DPAPI-protected
//! let (mut helper, first) =
//!     SecureSession::initiator(Channel::Ctl, &helper_key, Binding::default()).unwrap();
//!
//! // Client: answer the channel and feed it every received message.
//! let client_key = StaticKey::generate().unwrap();
//! let mut client =
//!     SecureSession::responder(Channel::Ctl, &client_key, Binding::default()).unwrap();
//!
//! // A tiny in-memory "transport": deliver Send events to the other side.
//! let mut to_client = vec![first];
//! let mut to_helper = Vec::new();
//! while !(to_client.is_empty() && to_helper.is_empty()) {
//!     for m in std::mem::take(&mut to_client) {
//!         for ev in client.on_message(&m).unwrap() {
//!             if let Event::Send(b) = ev { to_helper.push(b) }
//!         }
//!     }
//!     for m in std::mem::take(&mut to_helper) {
//!         for ev in helper.on_message(&m).unwrap() {
//!             if let Event::Send(b) = ev { to_client.push(b) }
//!         }
//!     }
//! }
//! // Both show the same SAS; the client checks its pin store.
//! assert_eq!(helper.sas(), client.sas());
//! let wire = helper.send(0, &Message::Heartbeat { seq: 1 }).unwrap();
//! assert!(matches!(&client.on_message(&wire).unwrap()[0], Event::Message { .. }));
//! ```
#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod msg;
pub mod pins;
pub mod session;
pub mod store;
pub mod transfer;
pub mod wire;

pub use error::{Error, Result};
pub use msg::{Channel, Message, PROTO_MAJOR, PROTO_MINOR, cap, policy};
pub use pins::{AttemptLog, ClientStore, PinCheck, PinStore, pin_id, server_id};
pub use session::{Binding, Event, Role, Sas, SecureSession, StaticKey};
pub use transfer::{Engine, TransferEvent};

/// The control channel: handshake, pairing, hello, session info, links,
/// transfer control. Opened by the helper with `PRI_MED`.
pub const CTL_CHANNEL: &str = "Remora::Ctl";

/// The bulk channel: file data. Opened by the helper with `PRI_LOW` after
/// it received `HelloAck` on [`CTL_CHANNEL`].
pub const BULK_CHANNEL: &str = "Remora::Bulk";

/// Largest message on either channel after encryption; a DVC reassembly
/// cap for these channels should allow this plus a little.
pub const MAX_WIRE: usize = session::MAX_WIRE;

/// Bytes in a key fingerprint.
pub const FINGERPRINT_LEN: usize = 20;

/// A static key's fingerprint for comparing out of band: the first 20
/// bytes of the BLAKE3 hash of the 32-byte X25519 public key.
pub fn fingerprint_bytes(public: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    let h = blake3::hash(public);
    let mut fp = [0u8; FINGERPRINT_LEN];
    fp.copy_from_slice(&h.as_bytes()[..FINGERPRINT_LEN]);
    fp
}

/// A fingerprint as people read it: ten groups of four lower-case hex
/// digits, `ab12 cd34 ...`.
pub fn format_fingerprint(fp: &[u8; FINGERPRINT_LEN]) -> String {
    let h = wire::hex(fp);
    h.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

/// [`format_fingerprint`] of a public key.
pub fn fingerprint(public: &[u8; 32]) -> String {
    format_fingerprint(&fingerprint_bytes(public))
}

/// Reads a fingerprint as typed or pasted: 40 hex digits in any case;
/// spaces, colons and dashes between them are ignored.
pub fn parse_fingerprint(text: &str) -> Option<[u8; FINGERPRINT_LEN]> {
    let digits: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '\t'))
        .collect();
    wire::unhex(&digits)
}

/// Fills `buf` from the operating system's random generator.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
}

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprints_read_and_parse_back() {
        let key = [3u8; 32];
        let fp = super::fingerprint(&key);
        assert_eq!(fp.len(), 49, "{fp}");
        assert_eq!(fp.split(' ').count(), 10);
        let h = blake3::hash(&key);
        assert!(fp.replace(' ', "") == super::wire::hex(&h.as_bytes()[..20]));
        let bytes = super::fingerprint_bytes(&key);
        assert_eq!(super::parse_fingerprint(&fp), Some(bytes));
        assert_eq!(
            super::parse_fingerprint(&fp.to_uppercase().replace(' ', ":")),
            Some(bytes)
        );
        assert_eq!(super::parse_fingerprint(&fp[..45]), None);
        assert_eq!(super::parse_fingerprint("zz"), None);
    }
}
