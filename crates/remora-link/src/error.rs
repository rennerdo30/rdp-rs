//! Errors. Every error a [`crate::SecureSession`] returns is fatal for its
//! channel: the caller closes the channel and starts again with a new one.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Malformed frame or message (bad length, truncated, bad field).
    Malformed(String),
    /// A message larger than [`crate::MAX_MESSAGE`].
    TooLarge(usize),
    /// The peer speaks a different major protocol version.
    Version { ours: u16, theirs: u16 },
    /// The Noise handshake failed (wrong prologue, bad key, bad tag).
    Handshake(String),
    /// A transport message failed authentication: tampered, replayed,
    /// reordered or dropped. The channel must be closed.
    Decrypt,
    /// The peer's static key is not the one this channel must have
    /// (for example `Remora::Bulk` bound to a different helper than `Remora::Ctl`).
    WrongPeer,
    /// The SAS commitment did not match the revealed nonce.
    Commitment,
    /// A message arrived or was sent in the wrong state.
    State(&'static str),
    /// The session failed earlier; it accepts nothing more.
    Closed,
    /// File or directory error from the transfer engine's I/O traits.
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed message: {m}"),
            Error::TooLarge(n) => write!(f, "message of {n} bytes exceeds the limit"),
            Error::Version { ours, theirs } => {
                write!(
                    f,
                    "protocol major version {theirs} (this side speaks {ours})"
                )
            }
            Error::Handshake(m) => write!(f, "handshake failed: {m}"),
            Error::Decrypt => f.write_str("message failed authentication"),
            Error::WrongPeer => f.write_str("the helper's key does not match this session"),
            Error::Commitment => f.write_str("pairing commitment mismatch"),
            Error::State(m) => write!(f, "unexpected in this state: {m}"),
            Error::Closed => f.write_str("session closed after an earlier error"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
