use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Tls(rustls::Error),
    /// Malformed or unexpected data from the peer.
    Protocol(String),
    /// Authentication was rejected or could not be completed.
    Auth(String),
    /// The server asked for a feature this prototype does not implement.
    Unsupported(String),
    Timeout,
    Disconnected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Auth(m) => write!(f, "authentication failed: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Timeout => write!(f, "timed out"),
            Error::Disconnected(m) => write!(f, "disconnected: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn proto<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(msg.into()))
}
