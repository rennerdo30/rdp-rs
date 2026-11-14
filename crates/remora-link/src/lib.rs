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
//! - [`pins`]: the client's pinned helper keys;
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
pub mod transfer;
pub mod wire;

pub use error::{Error, Result};
pub use msg::{Channel, Message, PROTO_MAJOR, PROTO_MINOR, cap, policy};
pub use pins::{PinCheck, PinStore, server_id};
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

/// Fills `buf` from the operating system's random generator.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
}
