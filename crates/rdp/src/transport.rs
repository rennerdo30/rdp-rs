//! TCP/TLS transport and message framing.
//!
//! A reader thread does plain blocking reads on the socket and hands the
//! bytes over a channel; the session waits on that channel with its own
//! timeout. The socket itself never gets a read timeout: on Windows an
//! expired SO_RCVTIMEO can leave an overlapped receive behind ("os error
//! 997") and the socket in an undefined state. A partial PDU stays in `buf`
//! until the rest arrives, so the session loop interleaves network reads
//! with window events on one thread.
//!
//! The bytes travel over a [`ByteStream`]: plain TCP, or an RD Gateway
//! tunnel ([`crate::gateway`]) that carries them in HTTP_DATA_PACKETs.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

use crate::error::{Error, Result, proto};

pub enum Frame {
    /// A complete TPKT packet (header included).
    X224(Vec<u8>),
    /// A complete fast-path output PDU (header included).
    FastPath(Vec<u8>),
}

fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
    )
}

/// What the reader thread sends.
enum Incoming {
    Data(Vec<u8>),
    Closed,
    Failed(io::Error),
}

/// The write side of the byte stream under the RDP connection.
pub trait ByteStream: Write + Send {
    /// Ends the connection, which also ends a blocking read on the read side.
    fn shutdown(&mut self);
}

impl ByteStream for TcpStream {
    fn shutdown(&mut self) {
        let _ = TcpStream::shutdown(self, Shutdown::Both);
    }
}

/// Bytes from the socket, read on a thread of their own.
struct Reader {
    rx: Receiver<Incoming>,
    /// Received bytes not yet consumed (by TLS, which takes them in pieces).
    pending: Vec<u8>,
    closed: bool,
}

impl Reader {
    fn spawn(sock: Box<dyn Read + Send>) -> Reader {
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("rdp-socket-read".into())
            .spawn(move || {
                let mut sock = sock;
                let mut tmp = vec![0u8; 64 * 1024];
                loop {
                    let msg = match sock.read(&mut tmp) {
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
            })
            .expect("spawn socket reader");
        Reader {
            rx,
            pending: Vec::new(),
            closed: false,
        }
    }

    /// Waits up to `wait` for bytes in `pending`. Ok(false): nothing came.
    fn fill(&mut self, wait: Duration) -> Result<bool> {
        if !self.pending.is_empty() {
            return Ok(true);
        }
        if self.closed {
            return Err(Error::ConnectionLost("connection closed by server".into()));
        }
        let msg = match self.rx.recv_timeout(wait) {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => return Ok(false),
            Err(RecvTimeoutError::Disconnected) => Incoming::Closed,
        };
        match msg {
            Incoming::Data(d) => {
                self.pending = d;
                // Take whatever else already arrived in the same go.
                while let Ok(Incoming::Data(more)) = self.rx.try_recv() {
                    self.pending.extend_from_slice(&more);
                }
                Ok(true)
            }
            Incoming::Closed => {
                self.closed = true;
                Err(Error::ConnectionLost("connection closed by server".into()))
            }
            Incoming::Failed(e) if is_reset(&e) => {
                self.closed = true;
                Err(Error::ConnectionLost("connection reset by server".into()))
            }
            Incoming::Failed(e) => {
                self.closed = true;
                Err(e.into())
            }
        }
    }

    /// Feeds pending bytes to TLS (it may take only part of them).
    fn feed(&mut self, conn: &mut ClientConnection) -> Result<()> {
        let mut rd = &self.pending[..];
        let n = conn.read_tls(&mut rd)?;
        self.pending.drain(..n);
        conn.process_new_packets()?;
        Ok(())
    }
}

pub struct Framer {
    /// The write side; the reader thread owns the read side.
    sock: Box<dyn ByteStream>,
    reader: Reader,
    tls: Option<Box<ClientConnection>>,
    /// How long one read waits for data (`set_read_timeout`).
    wait: Duration,
    buf: Vec<u8>,
}

impl Drop for Framer {
    fn drop(&mut self) {
        // Ends the reader thread's blocking read.
        self.sock.shutdown();
    }
}

impl Framer {
    pub fn new(sock: TcpStream) -> Self {
        let read = sock
            .try_clone()
            .expect("clone socket for the reader thread");
        Self::over(Box::new(sock), Box::new(read))
    }

    /// A framer over any byte stream: `read` is read on a thread of its own
    /// with blocking reads, Ok(0) meaning the peer closed the stream.
    pub fn over(stream: Box<dyn ByteStream>, read: Box<dyn Read + Send>) -> Self {
        Self {
            sock: stream,
            reader: Reader::spawn(read),
            tls: None,
            wait: Duration::from_millis(100),
            buf: Vec::new(),
        }
    }

    /// How long one read waits for data before reporting none.
    pub fn set_read_timeout(&mut self, t: Duration) -> Result<()> {
        self.wait = t;
        Ok(())
    }

    fn flush_tls(&mut self) -> Result<()> {
        if let Some(conn) = &mut self.tls {
            while conn.wants_write() {
                conn.write_tls(&mut self.sock)?;
            }
        }
        Ok(())
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.tls {
            None => self.sock.write_all(data)?,
            Some(conn) => {
                conn.writer().write_all(data)?;
                self.flush_tls()?;
            }
        }
        Ok(())
    }

    /// Appends whatever is available to `buf`; Ok(0) means nothing came in time.
    fn read_some(&mut self) -> Result<usize> {
        let Some(conn) = &mut self.tls else {
            if !self.reader.fill(self.wait)? {
                return Ok(0);
            }
            let n = self.reader.pending.len();
            self.buf.append(&mut self.reader.pending);
            return Ok(n);
        };
        let mut tmp = [0u8; 16 * 1024];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => {
                    return Err(Error::ConnectionLost("TLS session closed by server".into()));
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if !self.reader.fill(self.wait)? {
                return Ok(0);
            }
            self.reader.feed(conn)?;
            while conn.wants_write() {
                conn.write_tls(&mut self.sock)?;
            }
        }
    }

    /// Returns one message once `len_of(buf)` reports a complete one. With no
    /// deadline this makes at most one read attempt and returns `None` if the
    /// message is still incomplete; with a deadline it waits until then.
    pub fn read_with(
        &mut self,
        len_of: impl Fn(&[u8]) -> Result<Option<usize>>,
        deadline: Option<Instant>,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(n) = len_of(&self.buf)? {
                if n == 0 {
                    return proto("zero-length frame");
                }
                if self.buf.len() >= n {
                    return Ok(Some(self.buf.drain(..n).collect()));
                }
            }
            if self.read_some()? == 0 {
                match deadline {
                    None => return Ok(None),
                    Some(d) if Instant::now() >= d => return Err(Error::Timeout),
                    Some(_) => {}
                }
            }
        }
    }

    pub fn read_frame(&mut self, deadline: Option<Instant>) -> Result<Option<Frame>> {
        let raw = self.read_with(frame_len, deadline)?;
        Ok(raw.map(|r| {
            if r[0] == 0x03 {
                Frame::X224(r)
            } else {
                Frame::FastPath(r)
            }
        }))
    }

    pub fn read_exact(&mut self, n: usize, deadline: Instant) -> Result<Vec<u8>> {
        self.read_with(|_| Ok(Some(n)), Some(deadline))
            .map(|o| o.expect("deadline given"))
    }

    pub fn read_der(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        self.read_with(|b| Ok(crate::der::frame_len(b)), Some(deadline))
            .map(|o| o.expect("deadline given"))
    }

    /// Upgrades the TCP stream to TLS and returns the server's end-entity certificate (DER).
    pub fn upgrade_tls(&mut self, host: &str, deadline: Instant) -> Result<Vec<u8>> {
        if !self.buf.is_empty() || !self.reader.pending.is_empty() {
            return proto("unexpected data before TLS handshake");
        }
        if self.tls.is_some() {
            return proto("TLS already active");
        }
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| Error::Protocol(format!("invalid server name {host:?}")))?;
        let mut conn = ClientConnection::new(tls_config()?, name)?;
        while conn.is_handshaking() {
            while conn.wants_write() {
                conn.write_tls(&mut self.sock)?;
            }
            if !conn.is_handshaking() {
                break;
            }
            if conn.wants_read() {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(Error::Timeout);
                }
                if self.reader.fill(left.min(self.wait))? {
                    self.reader.feed(&mut conn)?;
                }
            }
        }
        while conn.wants_write() {
            conn.write_tls(&mut self.sock)?;
        }
        let cert = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec())
            .ok_or_else(|| Error::Protocol("server sent no certificate".into()))?;
        self.tls = Some(Box::new(conn));
        Ok(cert)
    }
}

/// Length of the TPKT or fast-path PDU at the start of `b`, once known. The
/// server uses it for fast-path input too: the same header layout.
pub(crate) fn frame_len(b: &[u8]) -> Result<Option<usize>> {
    let Some(&first) = b.first() else {
        return Ok(None);
    };
    if first == 0x03 {
        if b.len() < 4 {
            return Ok(None);
        }
        return Ok(Some(u16::from_be_bytes([b[2], b[3]]) as usize));
    }
    if first & 0x03 != 0 {
        return proto(format!("unknown PDU header byte {first:#04x}"));
    }
    let Some(&l1) = b.get(1) else { return Ok(None) };
    if l1 & 0x80 == 0 {
        return Ok(Some(l1 as usize));
    }
    let Some(&l2) = b.get(2) else { return Ok(None) };
    Ok(Some((((l1 & 0x7F) as usize) << 8) | l2 as usize))
}

/// rustls client settings shared by the RDP and the gateway TLS.
pub(crate) fn tls_config() -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Prototype only: RDP servers usually present self-signed certificates. The
/// caller prints the certificate fingerprint; CredSSP still binds the
/// authentication to this certificate's public key, so a man in the middle
/// cannot complete NLA without the password.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
