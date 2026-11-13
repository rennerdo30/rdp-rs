//! TCP/TLS transport and message framing.
//!
//! The socket keeps a short read timeout, so every read is a bounded poll. A
//! partial PDU stays in `buf` until the rest arrives, which lets the session
//! loop interleave network reads with window events on one thread.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
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

enum Stream {
    Tcp(TcpStream),
    Tls(Box<(ClientConnection, TcpStream)>),
}

fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
    )
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl Stream {
    /// Reads whatever is available; Ok(0) means the read timed out.
    fn read_some(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        let mut tmp = [0u8; 16 * 1024];
        match self {
            Stream::Tcp(s) => match s.read(&mut tmp) {
                Ok(0) => Err(Error::ConnectionLost("connection closed by server".into())),
                Ok(n) => {
                    out.extend_from_slice(&tmp[..n]);
                    Ok(n)
                }
                Err(e) if is_timeout(&e) => Ok(0),
                Err(e) => Err(e.into()),
            },
            Stream::Tls(b) => {
                let (conn, sock) = &mut **b;
                loop {
                    match conn.reader().read(&mut tmp) {
                        Ok(0) => {
                            return Err(Error::ConnectionLost(
                                "TLS session closed by server".into(),
                            ));
                        }
                        Ok(n) => {
                            out.extend_from_slice(&tmp[..n]);
                            return Ok(n);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e.into()),
                    }
                    match conn.read_tls(sock) {
                        Ok(0) => {
                            return Err(Error::ConnectionLost(
                                "connection closed by server".into(),
                            ));
                        }
                        Ok(_) => {
                            conn.process_new_packets()?;
                            while conn.wants_write() {
                                conn.write_tls(sock)?;
                            }
                        }
                        Err(e) if is_timeout(&e) => return Ok(0),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Stream::Tcp(s) => s.write_all(data)?,
            Stream::Tls(b) => {
                let (conn, sock) = &mut **b;
                conn.writer().write_all(data)?;
                while conn.wants_write() {
                    conn.write_tls(sock)?;
                }
            }
        }
        Ok(())
    }

    fn socket(&self) -> &TcpStream {
        match self {
            Stream::Tcp(s) => s,
            Stream::Tls(b) => &b.1,
        }
    }
}

pub struct Framer {
    stream: Option<Stream>,
    buf: Vec<u8>,
}

impl Framer {
    pub fn new(sock: TcpStream) -> Self {
        Self {
            stream: Some(Stream::Tcp(sock)),
            buf: Vec::new(),
        }
    }

    fn stream(&mut self) -> &mut Stream {
        self.stream.as_mut().expect("stream present")
    }

    pub fn set_read_timeout(&mut self, t: Duration) -> Result<()> {
        self.stream().socket().set_read_timeout(Some(t))?;
        Ok(())
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.stream().write_all(data)
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
            let mut tmp = std::mem::take(&mut self.buf);
            let got = self.stream().read_some(&mut tmp).map_err(|e| match e {
                Error::Io(io) if is_reset(&io) => {
                    Error::ConnectionLost("connection reset by server".into())
                }
                other => other,
            });
            self.buf = tmp;
            if got? == 0 {
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
        if !self.buf.is_empty() {
            return proto("unexpected data before TLS handshake");
        }
        let Some(Stream::Tcp(mut sock)) = self.stream.take() else {
            return proto("TLS already active");
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| Error::Protocol(format!("invalid server name {host:?}")))?;
        let mut conn = ClientConnection::new(Arc::new(config), name)?;
        while conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e) if is_timeout(&e) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        let cert = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec())
            .ok_or_else(|| Error::Protocol("server sent no certificate".into()))?;
        self.stream = Some(Stream::Tls(Box::new((conn, sock))));
        Ok(cert)
    }
}

/// Length of the TPKT or fast-path PDU at the start of `b`, once known.
fn frame_len(b: &[u8]) -> Result<Option<usize>> {
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
