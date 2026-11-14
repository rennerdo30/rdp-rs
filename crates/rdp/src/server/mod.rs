//! The server side of RDP, for Remora Host: enough of MS-RDPBCGR for a
//! client to log on with a password over TLS, see a desktop of uncompressed
//! 32 bpp bitmap updates and send keyboard and mouse input.
//!
//! - [`connect`]: X.224 negotiation, MCS and GCC (2.2.1.1 to 2.2.1.9)
//! - [`pdu`]: Client Info, licensing, Demand/Confirm Active, finalization
//!   and the client's share data PDUs (2.2.1.11 to 2.2.1.22, 2.2.11)
//! - [`input`]: fast-path and slow-path input events (2.2.8.1)
//! - [`output`]: fast-path bitmap updates and the system pointer (2.2.9.1.2)
//! - [`session`]: the sans-IO connection sequence and session
//! - [`transport`]: a blocking TCP and TLS (rustls) driver
//!
//! Security: TLS only (PROTOCOL_SSL). Legacy RDP security and plaintext
//! are refused at negotiation, and NLA (CredSSP) is not implemented yet,
//! so the password arrives in the Client Info PDU inside TLS.

pub mod connect;
pub mod input;
pub mod output;
pub mod pdu;
pub mod session;
pub mod transport;

pub use input::ClientInput;
pub use output::Tile;
pub use pdu::Credentials;
pub use session::{Event, ServerSession, SessionConfig};
pub use transport::{ServerTransport, TlsConfig, tls_config};

/// A desktop rectangle in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub fn new(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect { x, y, w, h }
    }

    /// The part inside a `width` x `height` desktop; None if nothing is.
    pub fn clip(&self, width: u16, height: u16) -> Option<Rect> {
        if self.x >= width || self.y >= height || self.w == 0 || self.h == 0 {
            return None;
        }
        Some(Rect {
            x: self.x,
            y: self.y,
            w: self.w.min(width - self.x),
            h: self.h.min(height - self.y),
        })
    }
}
