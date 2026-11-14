//! A blocking server transport: TCP, the TLS upgrade after the X.224
//! negotiation (rustls as the server) and PDU framing.
//!
//! As on the client ([`crate::transport`]), a reader thread does plain
//! blocking reads on the socket and hands the bytes over a channel; the
//! session waits on that channel with its own deadline, so the socket never
//! needs a read timeout. One thread owns the TLS state and does all writes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

use crate::error::{Error, Result, proto};

/// What the reader thread sends.
enum Incoming {
    Data(Vec<u8>),
    Closed,
    Failed(io::Error),
}

/// The server's TLS settings (rustls), shared by every connection.
pub type TlsConfig = Arc<ServerConfig>;

/// rustls server settings for a certificate (DER) and its PKCS#8 private
/// key (DER), with the ring provider and TLS 1.2 and 1.3.
pub fn tls_config(certificate: Vec<u8>, private_key_pkcs8: Vec<u8>) -> Result<TlsConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_pkcs8));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate)], key)?;
    Ok(Arc::new(config))
}

/// The server's end of one connection.
pub struct ServerTransport {
    sock: TcpStream,
    rx: Receiver<Incoming>,
    /// Bytes from the socket not yet given to TLS.
    raw: Vec<u8>,
    /// Plaintext not yet framed (before TLS: the socket bytes).
    plain: Vec<u8>,
    tls: Option<Box<ServerConnection>>,
    closed: bool,
    peer: Option<SocketAddr>,
}

impl Drop for ServerTransport {
    fn drop(&mut self) {
        // Ends the reader thread's blocking read.
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

impl ServerTransport {
    /// Takes an accepted connection; starts its reader thread. Writes time
    /// out after `write_timeout` so a stalled client cannot hold the host.
    pub fn new(sock: TcpStream, write_timeout: Duration) -> Result<ServerTransport> {
        sock.set_nodelay(true)?;
        sock.set_write_timeout(Some(write_timeout))?;
        let peer = sock.peer_addr().ok();
        let mut read = sock.try_clone()?;
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("rdp-server-read".into())
            .spawn(move || {
                let mut tmp = vec![0u8; 64 * 1024];
                loop {
                    let msg = match read.read(&mut tmp) {
                        Ok(0) => Incoming::Closed,
                        Ok(n) => Incoming::Data(tmp[..n].to_vec()),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => Incoming::Failed(e),
                    };
                    let last = !matches!(msg, Incoming::Data(_));
                    if tx.send(msg).is_err() || last {
                        return;
                    }
                }
            })?;
        Ok(ServerTransport {
            sock,
            rx,
            raw: Vec::new(),
            plain: Vec::new(),
            tls: None,
            closed: false,
            peer,
        })
    }

    /// The client's address.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Waits until `deadline` for socket bytes. Ok(false): none came.
    fn receive(&mut self, deadline: Instant) -> Result<bool> {
        if self.closed {
            return Err(Error::ConnectionLost(
                "connection closed by the client".into(),
            ));
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        let msg = match self.rx.recv_timeout(wait) {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => return Ok(false),
            Err(RecvTimeoutError::Disconnected) => Incoming::Closed,
        };
        let take = |d: Vec<u8>, this: &mut Self| {
            if this.tls.is_some() {
                this.raw.extend_from_slice(&d);
            } else {
                this.plain.extend_from_slice(&d);
            }
        };
        match msg {
            Incoming::Data(d) => {
                take(d, self);
                while let Ok(Incoming::Data(more)) = self.rx.try_recv() {
                    take(more, self);
                }
                Ok(true)
            }
            Incoming::Closed => {
                self.closed = true;
                Err(Error::ConnectionLost(
                    "connection closed by the client".into(),
                ))
            }
            Incoming::Failed(e) => {
                self.closed = true;
                Err(Error::ConnectionLost(format!("connection lost: {e}")))
            }
        }
    }

    /// Moves received bytes through TLS into `plain` and sends what TLS
    /// wants to send (handshake messages, alerts).
    fn pump(&mut self) -> Result<()> {
        let Some(conn) = self.tls.as_mut() else {
            return Ok(());
        };
        loop {
            let mut tmp = [0u8; 16 * 1024];
            loop {
                match conn.reader().read(&mut tmp) {
                    Ok(0) => {
                        self.closed = true;
                        break;
                    }
                    Ok(n) => self.plain.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if self.raw.is_empty() {
                break;
            }
            let n = conn.read_tls(&mut &self.raw[..])?;
            self.raw.drain(..n);
            let state = conn.process_new_packets();
            while conn.wants_write() {
                conn.write_tls(&mut self.sock)?;
            }
            state?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Runs the TLS handshake as the server (MS-RDPBCGR 5.4.5.1) right after
    /// the X.224 Connection Confirm.
    pub fn accept_tls(&mut self, config: TlsConfig, deadline: Instant) -> Result<()> {
        if self.tls.is_some() {
            return proto("TLS already active");
        }
        let mut conn = ServerConnection::new(config)?;
        // A ClientHello that came with the X.224 request is TLS input.
        let mut pending = std::mem::take(&mut self.plain);
        loop {
            while conn.wants_write() {
                conn.write_tls(&mut self.sock)?;
            }
            if !conn.is_handshaking() {
                break;
            }
            if pending.is_empty() {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout);
                }
                // Before TLS is set, received bytes land in `plain`.
                if self.receive(deadline)? {
                    pending = std::mem::take(&mut self.plain);
                }
                continue;
            }
            let n = conn.read_tls(&mut &pending[..])?;
            pending.drain(..n);
            if let Err(e) = conn.process_new_packets() {
                // Send the alert, then fail.
                while conn.wants_write() {
                    let _ = conn.write_tls(&mut self.sock);
                }
                return Err(e.into());
            }
        }
        self.raw = pending;
        self.tls = Some(Box::new(conn));
        self.pump()
    }

    /// The next complete PDU (TPKT or fast-path), waiting until `deadline`;
    /// Ok(None) when none is complete by then.
    pub fn read_frame(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(n) = crate::transport::frame_len(&self.plain)? {
                if n == 0 {
                    return proto("zero-length frame");
                }
                if self.plain.len() >= n {
                    return Ok(Some(self.plain.drain(..n).collect()));
                }
            }
            if self.closed {
                return Err(Error::ConnectionLost(
                    "connection closed by the client".into(),
                ));
            }
            if !self.receive(deadline)? {
                return Ok(None);
            }
            self.pump()?;
        }
    }

    /// Sends bytes (through TLS once it is up).
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        match self.tls.as_mut() {
            None => self.sock.write_all(data)?,
            Some(conn) => {
                conn.writer().write_all(data)?;
                while conn.wants_write() {
                    conn.write_tls(&mut self.sock)?;
                }
            }
        }
        Ok(())
    }

    /// Sends a TLS close_notify (when TLS is up) and closes the socket.
    pub fn close(&mut self) {
        if let Some(conn) = self.tls.as_mut() {
            conn.send_close_notify();
            while conn.wants_write() {
                if conn.write_tls(&mut self.sock).is_err() {
                    break;
                }
            }
        }
        let _ = self.sock.shutdown(Shutdown::Both);
        self.closed = true;
    }
}
