//! Remote Desktop Gateway client (MS-TSGU), HTTP transport over one
//! WebSocket connection.
//!
//! Setup (MS-TSGU 3.3.5.1, 3.3.5.3.1): TLS to the gateway, then a WebSocket
//! Upgrade request (RFC 6455 4.1) to `/remoteDesktopGateway/`, authenticated
//! with `Authorization: NTLM` on the same connection. Current gateways accept
//! the upgrade, so one duplex connection replaces the RDG_OUT_DATA /
//! RDG_IN_DATA channel pair (1.3.2.1.1).
//!
//! Tunnel and channel creation (3.3.5.2): handshake, tunnel, tunnel
//! authorization and channel packets (2.2.10), each in WebSocket binary
//! frames. After that the RDP connection runs inside HTTP_DATA_PACKETs
//! (3.3.5.4); keep-alives are dropped, server pings answered, and a channel
//! close (3.3.5.5) ends the byte stream.
//!
//! The result is a [`GatewayStream`] / [`GatewayReader`] pair that
//! [`crate::transport::Framer::over`] runs the RDP connection on.

pub mod http;
pub mod packets;
pub mod ws;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::{Error, Result, proto};
use crate::ntlm::Ntlm;
use crate::trace;
use crate::transport::ByteStream;
use packets as p;

/// Where and as whom to connect through an RD Gateway.
#[derive(Clone)]
pub struct GatewayConfig {
    pub host: String,
    /// HTTPS port, normally 443.
    pub port: u16,
    /// `user`, `DOMAIN\user` or `user@domain`.
    pub username: String,
    pub domain: String,
    pub password: String,
}

impl GatewayConfig {
    pub fn new(host: &str, username: &str, password: &str) -> Self {
        Self {
            host: host.into(),
            port: 443,
            username: username.into(),
            domain: String::new(),
            password: password.into(),
        }
    }
}

/// The password never appears in debug output.
impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// An open tunnel: the write and read halves for the RDP connection, and
/// the gateway's TLS certificate (DER) for a later trust check.
pub struct Tunnel {
    pub stream: GatewayStream,
    pub reader: GatewayReader,
    /// None only over the plain-TCP test transport.
    pub certificate: Option<Vec<u8>>,
}

/// Connects to `target_host:target_port` through the gateway.
pub fn connect(
    gw: &GatewayConfig,
    target_host: &str,
    target_port: u16,
    client_name: &str,
    deadline: Instant,
    verify: Option<&crate::client::CertificateCheck>,
) -> Result<Tunnel> {
    let addr = (gw.host.as_str(), gw.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Protocol(format!("cannot resolve gateway {}", gw.host)))?;
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Timeout);
    }
    let sock = TcpStream::connect_timeout(&addr, left)?;
    sock.set_nodelay(true)?;
    open(
        sock,
        gw,
        true,
        target_host,
        target_port,
        client_name,
        deadline,
        verify,
    )
}

/// Runs the gateway setup on a connected socket; `tls` false is the plain
/// transport of the loopback tests.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open(
    sock: TcpStream,
    gw: &GatewayConfig,
    tls: bool,
    target_host: &str,
    target_port: u16,
    client_name: &str,
    deadline: Instant,
    verify: Option<&crate::client::CertificateCheck>,
) -> Result<Tunnel> {
    let mut deadline = deadline;
    let budget = deadline.saturating_duration_since(Instant::now());
    let rx = spawn_socket_reader(sock.try_clone()?);
    let link = Arc::new(Mutex::new(Link { sock, tls: None }));
    let mut inbound = Inbound {
        rx,
        plain: Vec::new(),
        stream: Vec::new(),
        eof: false,
    };
    let setup = (|| {
        let certificate = if tls {
            Some(tls_handshake(&link, &mut inbound, &gw.host, deadline)?)
        } else {
            None
        };
        // The gateway's certificate is checked before its login runs.
        if let (Some(check), Some(der)) = (verify, &certificate) {
            let server = crate::client::ServerCertificate {
                host: gw.host.clone(),
                port: gw.port,
                der: der.clone(),
                sha256: crate::crypto::sha256(der),
            };
            if !(check.0)(&server) {
                return Err(Error::Auth(
                    "the gateway certificate was not trusted".into(),
                ));
            }
            deadline = Instant::now() + budget;
        }
        upgrade(&link, &mut inbound, gw, client_name, deadline)?;
        create_tunnel(
            &link,
            &mut inbound,
            target_host,
            target_port,
            client_name,
            deadline,
        )?;
        Ok(certificate)
    })();
    match setup {
        Ok(certificate) => Ok(Tunnel {
            stream: GatewayStream {
                link: link.clone(),
                closed: false,
            },
            reader: GatewayReader {
                link,
                inbound,
                out: Vec::new(),
                pos: 0,
                done: false,
            },
            certificate,
        }),
        Err(e) => {
            // Ends the socket reader thread.
            let _ = lock(&link).sock.shutdown(Shutdown::Both);
            Err(e)
        }
    }
}

/// The gateway connection: socket plus TLS state, shared by both halves.
struct Link {
    sock: TcpStream,
    tls: Option<Box<ClientConnection>>,
}

fn lock(link: &Mutex<Link>) -> MutexGuard<'_, Link> {
    link.lock().unwrap_or_else(|e| e.into_inner())
}

impl Link {
    fn send(&mut self, plain: &[u8]) -> io::Result<()> {
        match &mut self.tls {
            None => self.sock.write_all(plain),
            Some(c) => {
                c.writer().write_all(plain)?;
                while c.wants_write() {
                    c.write_tls(&mut self.sock)?;
                }
                Ok(())
            }
        }
    }

    /// A masked WebSocket frame with a fresh mask (RFC 6455 5.3).
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        self.send(&ws::encode(opcode, payload, crate::crypto::random()))
    }

    /// Takes raw socket bytes and appends what they decrypt to into `out`.
    /// Ok(false): the peer closed the TLS session.
    fn absorb(&mut self, raw: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let Some(c) = &mut self.tls else {
            out.extend_from_slice(raw);
            return Ok(true);
        };
        let mut rd = raw;
        let mut open = true;
        while !rd.is_empty() {
            c.read_tls(&mut rd)?;
            c.process_new_packets()?;
            let mut tmp = [0u8; 16 * 1024];
            loop {
                match c.reader().read(&mut tmp) {
                    Ok(0) => {
                        open = false;
                        break;
                    }
                    Ok(n) => out.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        while c.wants_write() {
            c.write_tls(&mut self.sock)?;
        }
        Ok(open)
    }
}

type Chunk = io::Result<Vec<u8>>;

/// Blocking reads on a thread of their own, like [`crate::transport`]: no
/// socket read timeouts. An empty chunk means end of stream.
fn spawn_socket_reader(mut sock: TcpStream) -> Receiver<Chunk> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("rdp-gateway-read".into())
        .spawn(move || {
            let mut tmp = vec![0u8; 64 * 1024];
            loop {
                let msg = match sock.read(&mut tmp) {
                    Ok(n) => Ok(tmp[..n].to_vec()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => Err(e),
                };
                let last = !matches!(&msg, Ok(d) if !d.is_empty());
                if tx.send(msg).is_err() || last {
                    return;
                }
            }
        })
        .expect("spawn gateway socket reader");
    rx
}

/// The receive side: socket chunks, decrypted bytes, and the HTTP packet
/// stream carried in WebSocket frames.
pub(crate) struct Inbound {
    rx: Receiver<Chunk>,
    /// Decrypted bytes: HTTP responses during setup, then WebSocket frames.
    plain: Vec<u8>,
    /// Payload of the binary frames: a stream of HTTP transport packets.
    stream: Vec<u8>,
    /// The peer closed TLS; what came before it is still in `plain`.
    eof: bool,
}

fn closed() -> Error {
    Error::ConnectionLost("RD Gateway closed the connection".into())
}

impl Inbound {
    /// Waits for more bytes; with no deadline, as long as it takes.
    fn fill(&mut self, link: &Mutex<Link>, deadline: Option<Instant>) -> Result<()> {
        if self.eof {
            return Err(closed());
        }
        let chunk = match deadline {
            None => self.rx.recv().map_err(|_| closed())?,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                match self.rx.recv_timeout(left) {
                    Ok(c) => c,
                    Err(RecvTimeoutError::Timeout) => return Err(Error::Timeout),
                    Err(RecvTimeoutError::Disconnected) => return Err(closed()),
                }
            }
        };
        let raw = chunk.map_err(|e| match e.kind() {
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                Error::ConnectionLost("connection reset by the RD Gateway".into())
            }
            _ => e.into(),
        })?;
        if raw.is_empty() {
            return Err(closed());
        }
        self.eof = !lock(link).absorb(&raw, &mut self.plain)?;
        Ok(())
    }

    /// The next HTTP transport packet; None once the server closed the WebSocket.
    fn next_packet(
        &mut self,
        link: &Mutex<Link>,
        deadline: Option<Instant>,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(n) = p::packet_len(&self.stream)?
                && self.stream.len() >= n
            {
                return Ok(Some(self.stream.drain(..n).collect()));
            }
            let Some(f) = ws::decode(&mut self.plain)? else {
                self.fill(link, deadline)?;
                continue;
            };
            match f.opcode {
                ws::OP_BINARY | ws::OP_CONTINUATION => self.stream.extend_from_slice(&f.payload),
                ws::OP_PING => lock(link).send_frame(ws::OP_PONG, &f.payload)?,
                ws::OP_PONG => {}
                ws::OP_CLOSE => {
                    // Echo the status code (RFC 6455 5.5.1).
                    let code = &f.payload[..f.payload.len().min(2)];
                    let _ = lock(link).send_frame(ws::OP_CLOSE, code);
                    return Ok(None);
                }
                _ => return proto("text frame from the RD Gateway"),
            }
        }
    }

    /// The next setup packet of type `want`, skipping keep-alives and
    /// service messages.
    fn expect(&mut self, link: &Mutex<Link>, want: u16, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            let pkt = self.next_packet(link, Some(deadline))?.ok_or_else(closed)?;
            let (t, body) = p::split(&pkt);
            match t {
                _ if t == want => return Ok(body.to_vec()),
                p::PKT_TYPE_KEEPALIVE => {}
                p::PKT_TYPE_SERVICE_MESSAGE => {
                    trace!("gateway message: {}", p::parse_service_message(body)?)
                }
                p::PKT_TYPE_CLOSE_CHANNEL => {
                    return Err(refused("closed the tunnel", p::parse_close(body)?));
                }
                _ => return proto(format!("unexpected RD Gateway packet type {t:#x}")),
            }
        }
    }
}

/// An error for a nonzero gateway status (MS-TSGU 2.2.6).
fn refused(what: &str, code: u32) -> Error {
    let msg = format!("RD Gateway {what}: {} ({code:#010x})", p::error_name(code));
    match code {
        0x8007_59DB | 0x8007_59F8 | 0x8009_030C | 0x0000_0005 => Error::Auth(msg),
        _ => Error::Protocol(msg),
    }
}

fn tls_handshake(
    link: &Mutex<Link>,
    inbound: &mut Inbound,
    host: &str,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::Protocol(format!("invalid gateway name {host:?}")))?;
    let conn = ClientConnection::new(crate::transport::tls_config()?, name)?;
    lock(link).tls = Some(Box::new(conn));
    loop {
        {
            let mut l = lock(link);
            let Link { sock, tls } = &mut *l;
            let c = tls.as_mut().expect("set above");
            while c.wants_write() {
                c.write_tls(sock)?;
            }
            if !c.is_handshaking() {
                return c
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.as_ref().to_vec())
                    .ok_or_else(|| Error::Protocol("gateway sent no certificate".into()));
            }
        }
        inbound.fill(link, Some(deadline))?;
    }
}

/// Reads one HTTP response and its Content-Length body off `plain`.
fn read_response(
    link: &Mutex<Link>,
    inbound: &mut Inbound,
    deadline: Instant,
) -> Result<http::Response> {
    loop {
        if let Some(r) = http::parse_response(&inbound.plain)? {
            let end = r.head_len + r.content_length()?;
            while inbound.plain.len() < end {
                inbound.fill(link, Some(deadline))?;
            }
            inbound.plain.drain(..end);
            return Ok(r);
        }
        inbound.fill(link, Some(deadline))?;
    }
}

fn split_user(gw: &GatewayConfig) -> (String, String) {
    if gw.domain.is_empty()
        && let Some((d, u)) = gw.username.split_once('\\')
    {
        return (u.to_string(), d.to_string());
    }
    (gw.username.clone(), gw.domain.clone())
}

/// WebSocket Upgrade with NTLM (RFC 4559 style) on one connection:
/// NEGOTIATE, 401 with the CHALLENGE, AUTHENTICATE, 101 Switching Protocols.
fn upgrade(
    link: &Mutex<Link>,
    inbound: &mut Inbound,
    gw: &GatewayConfig,
    client_name: &str,
    deadline: Instant,
) -> Result<()> {
    let (user, domain) = split_user(gw);
    let mut ntlm = Ntlm::new(&user, &domain, &gw.password, client_name);
    let key = ws::base64_encode(&crate::crypto::random::<16>());
    let connection_id = http::random_guid();
    let request = |token: &[u8]| {
        let auth = format!("NTLM {}", ws::base64_encode(token));
        http::upgrade_request(&gw.host, gw.port, &key, &connection_id, &auth)
    };

    lock(link).send(request(&ntlm.negotiate()).as_bytes())?;
    let r = read_response(link, inbound, deadline)?;
    trace!("gateway answered NTLM negotiate with HTTP {}", r.status);
    if r.status != 401 {
        return proto(format!(
            "RD Gateway answered HTTP {} to NTLM negotiate",
            r.status
        ));
    }
    let Some(challenge) = r.auth_token("NTLM")? else {
        let offered: Vec<&str> = r.headers_named("WWW-Authenticate").collect();
        return Err(Error::Unsupported(format!(
            "RD Gateway does not offer NTLM (offers {offered:?})"
        )));
    };
    if r.header("Connection")
        .is_some_and(|v| v.eq_ignore_ascii_case("close"))
    {
        return proto("RD Gateway closed the connection during NTLM");
    }
    let authenticate = ntlm.authenticate(&challenge)?;
    lock(link).send(request(&authenticate).as_bytes())?;
    let r = read_response(link, inbound, deadline)?;
    trace!("gateway answered NTLM authenticate with HTTP {}", r.status);
    match r.status {
        101 => {}
        401 => return Err(Error::Auth("RD Gateway rejected the credentials".into())),
        s => {
            return proto(format!(
                "RD Gateway refused the WebSocket upgrade: HTTP {s}"
            ));
        }
    }
    if r.header("Sec-WebSocket-Accept") != Some(ws::accept_key(&key).as_str()) {
        return proto("RD Gateway sent a wrong Sec-WebSocket-Accept");
    }
    Ok(())
}

/// Handshake, tunnel, tunnel authorization and channel (MS-TSGU 3.3.5.2).
fn create_tunnel(
    link: &Mutex<Link>,
    inbound: &mut Inbound,
    target_host: &str,
    target_port: u16,
    client_name: &str,
    deadline: Instant,
) -> Result<()> {
    let send = |pkt: Vec<u8>| lock(link).send_frame(ws::OP_BINARY, &pkt);

    send(p::handshake_request(0))?;
    let hs = p::parse_handshake_response(&inbound.expect(
        link,
        p::PKT_TYPE_HANDSHAKE_RESPONSE,
        deadline,
    )?)?;
    if hs.error_code != 0 {
        return Err(refused("refused the handshake", hs.error_code));
    }
    if hs.ver_major != 1 {
        return Err(Error::Unsupported(format!(
            "RD Gateway protocol version {}.{}",
            hs.ver_major, hs.ver_minor
        )));
    }

    send(p::tunnel_create(
        p::HTTP_CAPABILITY_IDLE_TIMEOUT | p::HTTP_CAPABILITY_MESSAGING_SERVICE_MSG,
    ))?;
    let t =
        p::parse_tunnel_response(&inbound.expect(link, p::PKT_TYPE_TUNNEL_RESPONSE, deadline)?)?;
    if t.status_code != 0 {
        return Err(refused("refused the tunnel", t.status_code));
    }
    trace!("gateway tunnel {:?}, caps {:?}", t.tunnel_id, t.caps);

    send(p::tunnel_auth(client_name))?;
    let a = p::parse_tunnel_auth_response(&inbound.expect(
        link,
        p::PKT_TYPE_TUNNEL_AUTH_RESPONSE,
        deadline,
    )?)?;
    if a.error_code != 0 && a.error_code != p::E_PROXY_QUARANTINE_ACCESSDENIED {
        return Err(refused("denied the tunnel", a.error_code));
    }
    trace!("gateway redirection flags {:?}", a.redir_flags);

    send(p::channel_create(target_host, target_port))?;
    let c = p::parse_channel_response(&inbound.expect(
        link,
        p::PKT_TYPE_CHANNEL_RESPONSE,
        deadline,
    )?)?;
    if c.error_code != 0 {
        return Err(refused(
            &format!("refused the channel to {target_host}:{target_port}"),
            c.error_code,
        ));
    }
    trace!("gateway channel {:?} open", c.channel_id);
    Ok(())
}

/// The write half: RDP bytes go out in HTTP_DATA_PACKETs.
pub struct GatewayStream {
    link: Arc<Mutex<Link>>,
    closed: bool,
}

impl Write for GatewayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[IoSlice::new(buf)])
    }

    /// TLS writes come as several slices; they share one packet.
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut data = Vec::new();
        for b in bufs {
            let take = b.len().min(p::MAX_DATA - data.len());
            data.extend_from_slice(&b[..take]);
            if data.len() == p::MAX_DATA {
                break;
            }
        }
        if data.is_empty() {
            return Ok(0);
        }
        lock(&self.link).send_frame(ws::OP_BINARY, &p::data(&data))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ByteStream for GatewayStream {
    /// Closes the channel and the WebSocket (best effort), then the socket.
    fn shutdown(&mut self) {
        let mut l = lock(&self.link);
        if !self.closed {
            self.closed = true;
            let _ = l.send_frame(ws::OP_BINARY, &p::close(p::PKT_TYPE_CLOSE_CHANNEL, 0));
            let _ = l.send_frame(ws::OP_CLOSE, &1000u16.to_be_bytes());
        }
        let _ = l.sock.shutdown(Shutdown::Both);
    }
}

/// The read half: blocking reads return the RDP bytes of HTTP_DATA_PACKETs;
/// Ok(0) once the gateway closed the channel or the connection.
pub struct GatewayReader {
    link: Arc<Mutex<Link>>,
    inbound: Inbound,
    out: Vec<u8>,
    pos: usize,
    done: bool,
}

impl GatewayReader {
    fn handle(&mut self, pkt: &[u8]) -> Result<()> {
        let (t, body) = p::split(pkt);
        match t {
            p::PKT_TYPE_DATA => {
                self.out = p::parse_data(body)?.to_vec();
                self.pos = 0;
            }
            p::PKT_TYPE_KEEPALIVE => {}
            p::PKT_TYPE_SERVICE_MESSAGE => {
                trace!("gateway message: {}", p::parse_service_message(body)?)
            }
            p::PKT_TYPE_CLOSE_CHANNEL => {
                let code = p::parse_close(body)?;
                trace!(
                    "gateway closed the channel: {} ({code:#x})",
                    p::error_name(code)
                );
                let reply = p::close(p::PKT_TYPE_CLOSE_CHANNEL_RESPONSE, 0);
                let _ = lock(&self.link).send_frame(ws::OP_BINARY, &reply);
                self.done = true;
            }
            p::PKT_TYPE_CLOSE_CHANNEL_RESPONSE => self.done = true,
            _ => trace!("ignoring RD Gateway packet type {t:#x}"),
        }
        Ok(())
    }
}

impl Read for GatewayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.out.len() {
                let n = buf.len().min(self.out.len() - self.pos);
                buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            let step = match self.inbound.next_packet(&self.link, None) {
                Ok(Some(pkt)) => self.handle(&pkt),
                Ok(None) | Err(Error::ConnectionLost(_)) => {
                    self.done = true;
                    Ok(())
                }
                Err(e) => Err(e),
            };
            step.map_err(|e| match e {
                Error::Io(e) => e,
                e => io::Error::other(e.to_string()),
            })?;
        }
    }
}
