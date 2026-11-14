//! Connection progress: the steps of the connection sequence (MS-RDPBCGR
//! 1.3.1.1) as they start, for a caller that shows them while
//! [`crate::Client::connect_with`] blocks.

use std::sync::Arc;

/// One step of the connection sequence, reported when it starts. A step
/// ends when the next one starts (or the connection is up, or fails).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectStep {
    /// Looking up the server's address (DNS).
    Resolving,
    /// Opening the TCP connection.
    Tcp,
    /// Reaching the server through the RD Gateway (MS-TSGU): the gateway's
    /// own connection, TLS, sign-in and tunnel.
    Gateway,
    /// X.224 negotiation and the TLS handshake with the server; the
    /// certificate check runs at the end of it.
    Tls,
    /// Network Level Authentication (MS-CSSP) or an RDSTLS logon.
    SignIn,
    /// MCS connection and channels, Client Info and licensing (MS-RDPELE).
    Licensing,
    /// The capability exchange (Demand Active, 2.2.1.13.1).
    Capabilities,
    /// Connection finalization; the first picture follows.
    FirstPicture,
    /// The server redirected the connection (MS-RDPBCGR 3.2.5.13) to this
    /// target; the steps start again there.
    Redirected(String),
}

/// Called with each step as it starts, on the thread that connects. It
/// must not block for long: the connection waits for it.
#[derive(Clone)]
pub struct ConnectProgress(pub Arc<dyn Fn(&ConnectStep) + Send + Sync>);

impl ConnectProgress {
    pub fn new(f: impl Fn(&ConnectStep) + Send + Sync + 'static) -> ConnectProgress {
        ConnectProgress(Arc::new(f))
    }
}

impl std::fmt::Debug for ConnectProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectProgress")
    }
}

/// Reports `step` to `progress`, if any.
pub(crate) fn report(progress: Option<&ConnectProgress>, step: ConnectStep) {
    if let Some(p) = progress {
        (p.0)(&step);
    }
}
