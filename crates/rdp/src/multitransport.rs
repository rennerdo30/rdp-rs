//! Multitransport: a UDP side channel next to the TCP connection
//! (MS-RDPBCGR 2.2.15, MS-RDPEMT) that carries the dynamic virtual
//! channels.
//!
//! The server sends an Initiate Multitransport Request PDU on the MCS
//! message channel (2.2.15.1). The client opens a reliable RDP-UDP
//! connection ([`crate::rdpeudp`]) to the server's RDP port, runs TLS over
//! it, sends the Tunnel Create Request with the request's ID and security
//! cookie (MS-RDPEMT 2.2.2.1) and waits for the Tunnel Create Response
//! (2.2.2.2). Then it tells the server with an Initiate Multitransport
//! Response PDU (S_OK, 2.2.15.2), and Soft-Sync (MS-RDPEDYC 3.1.5.3, in
//! [`crate::dvc`]) moves the dynamic channels onto the tunnel, where each
//! DVC PDU travels in one Tunnel Data PDU (MS-RDPEMT 2.2.2.3).
//!
//! The TLS setup is the main connection's ([`crate::transport`]), and the
//! server must present the very certificate the main connection presented
//! and the user's certificate check accepted; any other certificate fails
//! the tunnel. A failure before the tunnel is ready answers E_ABORT and the
//! session stays on TCP.
//!
//! Only the reliable transport (RDP-UDP-R) is offered. The lossy one
//! (RDP-UDP-L) needs DTLS (MS-RDPEMT 1.4), which rustls does not provide.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::cursor::{Put, Reader};
use crate::error::{Error, Result, proto};
use crate::rdpeudp::{Endpoint, EndpointStats, State};
use crate::trace;

/// Basic Security Header flags (MS-RDPBCGR 2.2.8.1.1.2.1).
pub const SEC_TRANSPORT_REQ: u16 = 0x0002;
pub const SEC_TRANSPORT_RSP: u16 = 0x0004;

/// requestedProtocol (2.2.15.1).
pub const PROTOCOL_UDPFECR: u16 = 0x01;
pub const PROTOCOL_UDPFECL: u16 = 0x02;

/// Multitransport Channel Data flags (2.2.1.3.8, 2.2.1.4.6).
pub const TRANSPORTTYPE_UDPFECR: u32 = 0x01;
pub const TRANSPORTTYPE_UDPFECL: u32 = 0x04;
pub const TRANSPORTTYPE_UDP_PREFERRED: u32 = 0x100;
pub const SOFTSYNC_TCP_TO_UDP: u32 = 0x200;

/// What this client advertises in its Client Multitransport Channel Data:
/// the reliable transport with Soft-Sync. No UDP-L (needs DTLS) and no
/// static channels over UDP (TRANSPORTTYPE_UDP_PREFERRED).
pub const CLIENT_FLAGS: u32 = TRANSPORTTYPE_UDPFECR | SOFTSYNC_TCP_TO_UDP;

/// hrResponse values (2.2.15.2).
pub const S_OK: u32 = 0;
pub const E_ABORT: u32 = 0x8000_4004;

/// RDP_TUNNEL_HEADER Action (MS-RDPEMT 2.2.1.1).
pub const ACTION_CREATEREQUEST: u8 = 0x0;
pub const ACTION_CREATERESPONSE: u8 = 0x1;
pub const ACTION_DATA: u8 = 0x2;

/// Bound on the whole setup: UDP handshake, TLS and the tunnel creation.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest plaintext in one TLS record on the tunnel, so that a record
/// fits in one datagram even at the smallest MTU (MS-RDPEUDP 3.1.1.3).
const MAX_RECORD_PLAINTEXT: usize = 1024;

/// Server Initiate Multitransport Request PDU (MS-RDPBCGR 2.2.15.1).
#[derive(Clone, PartialEq, Eq)]
pub struct InitiateRequest {
    pub request_id: u32,
    /// [`PROTOCOL_UDPFECR`] or [`PROTOCOL_UDPFECL`].
    pub protocol: u16,
    /// Authenticates the tunnel to the server; never logged.
    pub cookie: [u8; 16],
}

impl std::fmt::Debug for InitiateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiateRequest")
            .field("request_id", &self.request_id)
            .field("protocol", &self.protocol)
            .field("cookie", &"[redacted]")
            .finish()
    }
}

/// Parses a message channel PDU (Basic Security Header included) as an
/// Initiate Multitransport Request (2.2.15.1). Ok(None) when the header
/// does not carry SEC_TRANSPORT_REQ.
pub fn parse_initiate_request(data: &[u8]) -> Result<Option<InitiateRequest>> {
    let mut r = Reader::new(data);
    let Ok(flags) = r.u16() else { return Ok(None) };
    if flags & SEC_TRANSPORT_REQ == 0 {
        return Ok(None);
    }
    r.skip(2)?; // flagsHi
    let request_id = r.u32()?;
    let protocol = r.u16()?;
    r.skip(2)?; // reserved
    let cookie = r.array()?;
    Ok(Some(InitiateRequest {
        request_id,
        protocol,
        cookie,
    }))
}

/// Client Initiate Multitransport Response PDU (MS-RDPBCGR 2.2.15.2): the
/// message channel user data, Basic Security Header included.
pub fn initiate_response(request_id: u32, hr: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.put_u16(SEC_TRANSPORT_RSP);
    v.put_u16(0); // flagsHi
    v.put_u32(request_id);
    v.put_u32(hr);
    v
}

/// An RDP_TUNNEL_HEADER without subheaders (MS-RDPEMT 2.2.1.1).
fn tunnel_header(v: &mut Vec<u8>, action: u8, payload: usize) {
    v.put_u8(action & 0x0F); // Flags (high nibble) MUST be zero
    v.put_u16(payload as u16);
    v.put_u8(4); // HeaderLength
}

/// RDP_TUNNEL_CREATEREQUEST (MS-RDPEMT 2.2.2.1).
pub fn tunnel_create_request(req: &InitiateRequest) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    tunnel_header(&mut v, ACTION_CREATEREQUEST, 24);
    v.put_u32(req.request_id);
    v.put_u32(0); // Reserved
    v.put_bytes(&req.cookie);
    v
}

/// RDP_TUNNEL_CREATERESPONSE (MS-RDPEMT 2.2.2.2); the server side, for tests.
pub fn tunnel_create_response(hr: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    tunnel_header(&mut v, ACTION_CREATERESPONSE, 4);
    v.put_u32(hr);
    v
}

/// RDP_TUNNEL_DATA (MS-RDPEMT 2.2.2.3) carrying one higher-layer PDU.
pub fn tunnel_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return proto("tunnel data PDU over 65535 bytes");
    }
    let mut v = Vec::with_capacity(4 + data.len());
    tunnel_header(&mut v, ACTION_DATA, data.len());
    v.put_bytes(data);
    Ok(v)
}

/// One tunnel PDU (MS-RDPEMT 2.2.1.1).
#[derive(Debug, PartialEq, Eq)]
pub struct TunnelPdu<'a> {
    pub action: u8,
    /// RDP_TUNNEL_SUBHEADER structures (auto-detect, 2.2.1.1.1), unparsed.
    pub subheaders: &'a [u8],
    pub payload: &'a [u8],
}

/// The tunnel PDU at the start of `buf` and its total length, once it is
/// complete (the tunnel runs in message mode, MS-RDPEMT 3.1.5.2).
pub fn split_tunnel_pdu(buf: &[u8]) -> Result<Option<(TunnelPdu<'_>, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let action = buf[0] & 0x0F;
    let payload = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    let header = buf[3] as usize;
    if header < 4 {
        return proto(format!("tunnel HeaderLength {header}"));
    }
    let total = header + payload;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((
        TunnelPdu {
            action,
            subheaders: &buf[4..header],
            payload: &buf[header..total],
        },
        total,
    )))
}

/// The tunnel's datagram socket.
pub trait DatagramSocket: Send {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;
    /// One datagram into `buf`; Ok(None) when nothing is waiting.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
}

impl DatagramSocket for UdpSocket {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        match UdpSocket::send(self, datagram) {
            Ok(_) => Ok(()),
            // A full send buffer drops the datagram, as the network may;
            // the transport retransmits.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match UdpSocket::recv(self, buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A non-blocking UDP socket connected to `server` (MS-RDPEUDP 3.1.3: a
/// port of its own per connection).
pub fn udp_socket(server: SocketAddr) -> io::Result<UdpSocket> {
    let local: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid")
    } else {
        "[::]:0".parse().expect("valid")
    };
    let s = UdpSocket::bind(local)?;
    s.connect(server)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Where a session's UDP transport stands, for a statistics display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UdpState {
    /// Not offered (the setting is off, a gateway, or the server cannot).
    #[default]
    Off,
    /// Offered; the server has not asked for a tunnel (yet).
    Offered,
    /// The tunnel is being set up.
    Connecting,
    /// The tunnel is up; [`UdpStats::channels`] dynamic channels use it.
    Active,
    /// Setting it up failed; the session stays on TCP.
    Failed,
}

/// The UDP transport's state and counters ([`crate::ClientStats::udp`]).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct UdpStats {
    pub state: UdpState,
    /// Dynamic channels sending on the tunnel.
    pub channels: usize,
    /// The RDP-UDP smoothed round-trip time.
    pub rtt: Option<Duration>,
    /// Datagram bytes, headers included.
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retransmits: u64,
}

/// What the tunnel reports from [`Tunnel::poll`].
#[derive(Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The server accepted the tunnel (Tunnel Create Response, S_OK).
    Ready,
    /// One higher-layer PDU from a Tunnel Data PDU.
    Data(Vec<u8>),
    /// The tunnel is gone; nothing more comes from it.
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// RDP-UDP handshake.
    Udp,
    Tls,
    /// Tunnel Create Request sent.
    Create,
    Ready,
    Failed,
}

/// A multitransport tunnel: RDP-UDP-R, TLS and the tunnel PDUs.
pub struct Tunnel {
    sock: Box<dyn DatagramSocket>,
    udp: Endpoint,
    tls: Option<Box<ClientConnection>>,
    phase: Phase,
    request: InitiateRequest,
    host: String,
    /// The main connection's server certificate (DER).
    certificate: Vec<u8>,
    started: Instant,
    /// TLS records received and not yet taken by rustls.
    cipher: Vec<u8>,
    /// Decrypted bytes not yet framed into tunnel PDUs.
    plain: Vec<u8>,
}

impl Tunnel {
    /// Starts the RDP-UDP handshake for `request` over `sock`. `host` and
    /// `certificate` are the main connection's server name and certificate.
    pub fn start(
        sock: Box<dyn DatagramSocket>,
        request: InitiateRequest,
        host: &str,
        certificate: Vec<u8>,
        now: Instant,
    ) -> Tunnel {
        let isn = u32::from_le_bytes(crate::crypto::random::<4>());
        Tunnel {
            sock,
            udp: Endpoint::client(isn, now),
            tls: None,
            phase: Phase::Udp,
            request,
            host: host.to_string(),
            certificate,
            started: now,
            cipher: Vec::new(),
            plain: Vec::new(),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn request_id(&self) -> u32 {
        self.request.request_id
    }

    /// The transport's smoothed round-trip time, once measured.
    pub fn rtt(&self) -> Option<Duration> {
        self.udp.rtt()
    }

    pub fn stats(&self) -> EndpointStats {
        self.udp.stats()
    }

    fn fail(&mut self, why: String, ev: &mut Vec<TunnelEvent>) {
        if self.phase == Phase::Failed {
            return;
        }
        trace!("UDP tunnel failed: {why}");
        self.phase = Phase::Failed;
        self.udp.close(&why);
        self.tls = None;
        ev.push(TunnelEvent::Failed(why));
    }

    /// Sends one higher-layer PDU in a Tunnel Data PDU; only once ready.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != Phase::Ready {
            return proto("UDP tunnel not ready");
        }
        let pdu = tunnel_data(data)?;
        let tls = self.tls.as_mut().expect("ready has TLS");
        tls.writer().write_all(&pdu)?;
        self.flush_tls();
        Ok(())
    }

    /// Hands TLS output to the transport, one record per Source Packet.
    fn flush_tls(&mut self) {
        let Some(tls) = self.tls.as_mut() else { return };
        let mut out = Vec::new();
        while tls.wants_write() {
            if tls.write_tls(&mut out).is_err() {
                break;
            }
        }
        for record in split_records(&out) {
            self.udp.send(record);
        }
    }

    /// Exchanges datagrams, runs the timers and moves the setup forward.
    /// Errors never escape: they end the tunnel with [`TunnelEvent::Failed`].
    pub fn poll(&mut self, now: Instant) -> Vec<TunnelEvent> {
        let mut ev = Vec::new();
        if self.phase == Phase::Failed {
            return ev;
        }
        let mut buf = [0u8; 2048];
        for _ in 0..4096 {
            match self.sock.recv(&mut buf) {
                Ok(Some(n)) => self.udp.on_datagram(&buf[..n], now),
                Ok(None) => break,
                // ICMP port unreachable (Windows reports it on the next
                // receive): nothing listens on the server's UDP port.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    if self.phase == Phase::Udp {
                        self.fail("the server's UDP port is unreachable".into(), &mut ev);
                        return ev;
                    }
                }
                Err(e) => {
                    self.fail(format!("UDP receive failed: {e}"), &mut ev);
                    return ev;
                }
            }
        }
        if self.phase == Phase::Udp
            && self.udp.state() == State::Established
            && let Err(e) = self.start_tls()
        {
            self.fail(format!("TLS setup failed: {e}"), &mut ev);
            return ev;
        }
        if self.tls.is_some()
            && let Err(e) = self.receive_tls(&mut ev)
        {
            self.fail(e.to_string(), &mut ev);
            return ev;
        }
        self.flush_tls();
        for d in self.udp.poll(now) {
            if let Err(e) = self.sock.send(&d) {
                self.fail(format!("UDP send failed: {e}"), &mut ev);
                return ev;
            }
        }
        if self.udp.state() == State::Closed {
            let why = self.udp.close_reason().unwrap_or("closed").to_string();
            self.fail(why, &mut ev);
        } else if self.phase != Phase::Ready
            && now.saturating_duration_since(self.started) > SETUP_TIMEOUT
        {
            self.fail("UDP tunnel setup timed out".into(), &mut ev);
        }
        ev
    }

    fn start_tls(&mut self) -> Result<()> {
        let mut config = (*crate::transport::tls_config()?).clone();
        config.max_fragment_size = Some(MAX_RECORD_PLAINTEXT);
        let name = ServerName::try_from(self.host.clone())
            .map_err(|_| Error::Protocol(format!("invalid server name {:?}", self.host)))?;
        self.tls = Some(Box::new(ClientConnection::new(
            std::sync::Arc::new(config),
            name,
        )?));
        self.phase = Phase::Tls;
        trace!("UDP tunnel: RDP-UDP connected, TLS handshake");
        Ok(())
    }

    fn receive_tls(&mut self, ev: &mut Vec<TunnelEvent>) -> Result<()> {
        self.cipher.extend(self.udp.take_incoming());
        let tls = self.tls.as_mut().expect("checked");
        let mut tmp = [0u8; 16 * 1024];
        loop {
            let mut progressed = false;
            if !self.cipher.is_empty() {
                let mut rd = &self.cipher[..];
                let n = tls.read_tls(&mut rd)?;
                self.cipher.drain(..n);
                tls.process_new_packets()?;
                progressed = n > 0;
            }
            loop {
                match tls.reader().read(&mut tmp) {
                    Ok(0) => return proto("the server closed the UDP tunnel's TLS session"),
                    Ok(n) => {
                        self.plain.extend_from_slice(&tmp[..n]);
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
            if !progressed || self.cipher.is_empty() {
                break;
            }
        }
        if self.phase == Phase::Tls && !tls.is_handshaking() {
            let cert = tls
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec());
            if cert.as_deref() != Some(&self.certificate[..]) {
                return Err(Error::Auth(
                    "the server's certificate on UDP differs from the one on TCP".into(),
                ));
            }
            tls.writer()
                .write_all(&tunnel_create_request(&self.request))?;
            self.phase = Phase::Create;
            trace!(
                "UDP tunnel: TLS up, Tunnel Create Request {}",
                self.request.request_id
            );
        }
        let mut used = 0;
        while let Some((pdu, n)) = split_tunnel_pdu(&self.plain[used..])? {
            match (self.phase, pdu.action) {
                (Phase::Create, ACTION_CREATERESPONSE) => {
                    let hr = Reader::new(pdu.payload).u32()?;
                    if hr != S_OK {
                        return Err(Error::Protocol(format!(
                            "the server refused the UDP tunnel ({hr:#x})"
                        )));
                    }
                    trace!("UDP tunnel ready");
                    self.phase = Phase::Ready;
                    ev.push(TunnelEvent::Ready);
                }
                (Phase::Ready, ACTION_DATA) => ev.push(TunnelEvent::Data(pdu.payload.to_vec())),
                (_, a) => trace!("UDP tunnel PDU action {a} ignored"),
            }
            used += n;
        }
        self.plain.drain(..used);
        Ok(())
    }
}

/// Splits TLS output into whole records (type, version, 16-bit length);
/// trailing bytes that are not a whole record stay together.
fn split_records(mut buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while buf.len() >= 5 {
        let n = (5 + u16::from_be_bytes([buf[3], buf[4]]) as usize).min(buf.len());
        out.push(&buf[..n]);
        buf = &buf[n..];
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

#[cfg(test)]
#[path = "multitransport_tests.rs"]
pub(crate) mod tests;
