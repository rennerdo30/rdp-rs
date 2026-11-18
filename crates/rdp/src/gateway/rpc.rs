//! RD Gateway over RPC over HTTP: the RPC transport of MS-TSGU (1.3.1, 3.6)
//! on RPC over HTTP v2 (MS-RPCH 3.2.2), for gateways without the HTTP
//! transport.
//!
//! Setup:
//! 1. Two TLS connections to the gateway: the OUT channel (`RPC_OUT_DATA`,
//!    gateway to client) and the IN channel (`RPC_IN_DATA`, client to
//!    gateway), each authenticated with HTTP NTLM (MS-RPCH 2.1.2.1).
//! 2. The virtual connection: CONN/A1 on the OUT channel and CONN/B1 on the
//!    IN channel; the outbound proxy answers HTTP 200, CONN/A3 and CONN/C2
//!    (MS-RPCH 3.2.1.5.3.1, 3.2.2.5).
//! 3. A DCE/RPC bind to TsProxyRpcInterface with NTLM at packet privacy
//!    (bind, bind_ack, rpc_auth_3; MS-RPCE 3.3.1.5.2).
//! 4. TsProxyCreateTunnel, TsProxyAuthorizeTunnel, TsProxyMakeTunnelCall
//!    (for administrative messages, when offered), TsProxyCreateChannel,
//!    TsProxySetupReceivePipe (MS-TSGU 3.6.4).
//!
//! Then RDP bytes go out in TsProxySendToServer calls and come back in the
//! responses of the receive pipe; the final pipe response ends the stream.
//! Both directions keep MS-RPCH flow control (3.2.1.5.1): the client
//! acknowledges what the OUT channel delivered, and waits for the inbound
//! proxy's acknowledgments before it overruns its receive window. A Ping
//! keeps an idle IN channel open (3.2.2.6).
//!
//! Not supported: channel recycling (MS-RPCH 3.2.1.5.3.2 to .5). An IN or
//! OUT channel lasts for 1 GiB; when it runs out, the stream ends as a
//! dropped connection so the session reconnects.

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::dcerpc::{self as dce, Security};
use super::rts::{self, Cookie, Rts};
use super::tsproxy::{self as tsg, Handle};
use super::{
    GatewayConfig, GatewayReader, GatewayStream, Inbound, Link, Target, Tunnel, closed, http, lock,
    read_response, refused, spawn_socket_reader, split_user, tls_handshake, ws,
};
use crate::error::{Error, Result, proto};
use crate::ntlm::Ntlm;
use crate::trace;
use crate::transport::ByteStream;

/// Our OUT channel receive window (CONN/A1).
pub const RECEIVE_WINDOW: u32 = 0x10000;
/// The IN channel's Content-Length and lifetime (MS-RPCH 2.1.2.1.1 <8>).
pub const IN_CHANNEL_LIFETIME: u32 = 0x4000_0000;
/// The OUT channel request's Content-Length: CONN/A1 (2.1.2.1.2).
const OUT_CONTENT_LENGTH: u32 = 76;
/// The keep-alive interval asked of the inbound proxy (CONN/B1).
const CLIENT_KEEPALIVE: u32 = 300_000;
/// Capabilities offered in TsProxyCreateTunnel: the idle timeout and
/// administrative messages, as over the HTTP transport.
const CAPABILITIES: u32 = tsg::TSG_NAP_CAPABILITY_IDLE_TIMEOUT | tsg::TSG_MESSAGING_CAP_SERVICE_MSG;
/// How long a write waits for the inbound proxy to open its window.
const WINDOW_WAIT: Duration = Duration::from_secs(60);
/// Bytes of a TsProxySendToServer request around its data: call header,
/// stub header (handle, sizes), the largest auth padding, sec_trailer and
/// signature.
const SEND_OVERHEAD: usize = dce::CALL_HEADER_LEN + 32 + 15 + dce::TRAILER_LEN + dce::SIGNATURE_LEN;

/// Prefixes an error with the setup step it happened in.
fn at<T>(step: &str, r: Result<T>) -> Result<T> {
    r.map_err(|e| match e {
        Error::Protocol(m) => Error::Protocol(format!("{step}: {m}")),
        Error::Auth(m) => Error::Auth(format!("{step}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{step}: {m}")),
        Error::ConnectionLost(m) => Error::ConnectionLost(format!("{step}: {m}")),
        Error::Disconnected(m) => Error::Disconnected(format!("{step}: {m}")),
        Error::Io(e) => Error::Io(io::Error::new(e.kind(), format!("{step}: {e}"))),
        Error::Timeout => {
            trace!("RD Gateway timed out at {step}");
            Error::Timeout
        }
        e => e,
    })
}

/// A readable name for an RPC proxy error code (MS-ERREF 2.2).
fn rpc_error_name(code: u32) -> &'static str {
    match code {
        0x5 => "access denied",
        0x6BA => "the gateway's RPC server is unavailable",
        0x6BE => "the remote procedure call failed",
        0x6D9 => "the gateway's RPC endpoint is not registered",
        0x71A => "the call was cancelled",
        _ => "RPC proxy error",
    }
}

/// The error for an HTTP answer on a channel that is not the expected one.
fn channel_error(r: &http::Response) -> Error {
    match r.status {
        401 => Error::Auth("RD Gateway rejected the credentials".into()),
        403 => Error::Auth("RD Gateway denied access (HTTP 403)".into()),
        404 => Error::Unsupported(
            "RD Gateway does not offer RPC over HTTP (HTTP 404 for /rpc/rpcproxy.dll)".into(),
        ),
        s => match r.rpc_error() {
            Some(code) => Error::Protocol(format!(
                "RD Gateway RPC proxy: {} ({code:#x})",
                rpc_error_name(code)
            )),
            None => Error::Protocol(format!("RD Gateway answered HTTP {s} {}", r.reason)),
        },
    }
}

/// An RPC fault for a call, as an error.
fn fault_error(status: u32) -> Error {
    if status == 5 {
        return Error::Auth("RD Gateway rejected the credentials (RPC access denied)".into());
    }
    Error::Protocol(format!(
        "RD Gateway RPC fault: {} ({status:#x})",
        dce::status_name(status)
    ))
}

fn random_uuid() -> String {
    let b: [u8; 16] = crate::crypto::random();
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// HTTP NTLM on one channel (MS-RPCH 2.1.2.1, RFC 4559 style): the request
/// with an empty body and the NEGOTIATE, the 401 with the CHALLENGE, then
/// the real request with the AUTHENTICATE, followed by `body`.
#[allow(clippy::too_many_arguments)]
fn http_auth(
    link: &Mutex<Link>,
    inbound: &mut Inbound,
    gw: &GatewayConfig,
    client_name: &str,
    method: &str,
    content_length: u32,
    body: &[u8],
    session: &str,
    deadline: Instant,
) -> Result<()> {
    let (user, domain) = split_user(gw);
    let mut scheme = "NTLM";
    loop {
        let mut ntlm = Ntlm::new(&user, &domain, &gw.password, client_name);
        let request = |len: u32, token: &[u8]| {
            let auth = format!("{scheme} {}", ws::base64_encode(token));
            http::rpc_channel_request(method, &gw.host, gw.port, len, session, &auth)
        };
        lock(link).send(request(0, &ntlm.negotiate()).as_bytes())?;
        let r = read_response(link, inbound, deadline)?;
        trace!(
            "{method}: gateway answered NTLM negotiate with HTTP {}",
            r.status
        );
        if r.status != 401 {
            return Err(channel_error(&r));
        }
        let closing = r
            .header("Connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let Some(challenge) = r.auth_token(scheme)? else {
            if scheme == "NTLM" && r.offers("Negotiate") && !closing {
                // NTLM inside the Negotiate scheme.
                scheme = "Negotiate";
                continue;
            }
            let offered: Vec<&str> = r.headers_named("WWW-Authenticate").collect();
            return Err(Error::Unsupported(format!(
                "RD Gateway does not offer NTLM (offers {offered:?})"
            )));
        };
        if closing {
            return proto("RD Gateway closed the connection during NTLM");
        }
        let authenticate = ntlm.authenticate(&challenge)?;
        let mut msg = request(content_length, &authenticate).into_bytes();
        msg.extend_from_slice(body);
        lock(link).send(&msg)?;
        return Ok(());
    }
}

/// The IN channel side, shared by the writer, the reader (acknowledgments,
/// message calls) and the keep-alive thread.
struct Tx {
    link: Arc<Mutex<Link>>,
    call_id: u32,
    /// The largest request fragment the gateway takes.
    max_xmit: usize,
    /// RPC PDU bytes sent on the IN channel (flow control, 3.2.1.1.4).
    bytes_sent: u64,
    /// Sender AvailableWindow (3.2.1.5.1.1).
    window: u32,
    /// What is left of the IN channel's Content-Length.
    lifetime_left: u64,
    last_send: Instant,
    in_cookie: Cookie,
    /// A TsProxyMakeTunnelCall waits for a message.
    msg_pending: bool,
    closed: bool,
}

struct Shared {
    tx: Mutex<Tx>,
    /// Signalled when an acknowledgment opens the window or on close.
    window: Condvar,
    sec: Mutex<Option<Security>>,
    out_link: Arc<Mutex<Link>>,
}

impl Shared {
    /// Sends one PDU on the IN channel.
    fn send_raw(tx: &mut Tx, pdu: &[u8]) -> Result<()> {
        if tx.closed {
            return Err(closed());
        }
        if pdu.len() as u64 > tx.lifetime_left {
            return Err(Error::ConnectionLost(
                "the RD Gateway RPC IN channel is used up (channel recycling is not supported)"
                    .into(),
            ));
        }
        lock(&tx.link).send(pdu)?;
        tx.lifetime_left -= pdu.len() as u64;
        tx.last_send = Instant::now();
        Ok(())
    }

    /// Sends an RPC PDU (bind, rpc_auth_3) under flow control.
    fn send_rpc(tx: &mut Tx, pdu: &[u8]) -> Result<()> {
        tx.window = tx.window.saturating_sub(pdu.len() as u32);
        tx.bytes_sent += pdu.len() as u64;
        Self::send_raw(tx, pdu)
    }

    /// An RTS PDU (no flow control).
    fn send_rts(&self, pdu: &[u8]) -> Result<()> {
        Self::send_raw(&mut lock(&self.tx), pdu)
    }

    /// Makes a call: one sealed request fragment. With `wait`, waits for
    /// the inbound proxy's window; without, a full window is an error.
    /// Returns the call id.
    fn call(&self, opnum: u16, stub: &[u8], wait: bool) -> Result<u32> {
        let len = dce::CALL_HEADER_LEN
            + stub.len()
            + (16 - stub.len() % 16) % 16
            + dce::TRAILER_LEN
            + dce::SIGNATURE_LEN;
        let mut tx = lock(&self.tx);
        if len > tx.max_xmit {
            return proto(format!("RPC request of {len} bytes"));
        }
        let until = Instant::now() + WINDOW_WAIT;
        while (tx.window as usize) < len {
            if tx.closed {
                return Err(closed());
            }
            let left = until.saturating_duration_since(Instant::now());
            if !wait || left.is_zero() {
                return Err(Error::ConnectionLost(
                    "the RD Gateway did not open its RPC receive window".into(),
                ));
            }
            tx = self
                .window
                .wait_timeout(tx, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let call_id = tx.call_id;
        tx.call_id = tx.call_id.wrapping_add(1);
        let pdu = {
            let mut sec = lock(&self.sec);
            let sec = sec
                .as_mut()
                .ok_or_else(|| Error::Auth("RPC security not established".into()))?;
            sec.request(
                call_id,
                opnum,
                stub.len() as u32,
                dce::PFC_FIRST_FRAG | dce::PFC_LAST_FRAG,
                stub,
            )?
        };
        debug_assert_eq!(pdu.len(), len);
        Self::send_rpc(&mut tx, &pdu)?;
        Ok(call_id)
    }

    fn close(&self) {
        lock(&self.tx).closed = true;
        self.window.notify_all();
    }
}

/// The OUT channel side: PDUs from the outbound proxy, RTS handled here.
struct Rx {
    shared: Arc<Shared>,
    out: Inbound,
    /// The IN channel's receive side: only errors and TLS records arrive.
    inn: Inbound,
    in_link: Arc<Mutex<Link>>,
    /// RPC bytes received on the OUT channel (3.2.1.1.5.1.3).
    received: u64,
    /// Receiver AvailableWindow (3.2.1.1.5.1.2).
    available: u32,
    out_cookie: Cookie,
    /// Responses unsealed while waiting for another call.
    early: VecDeque<dce::Response>,
}

impl Rx {
    /// Checks the IN channel without blocking: an HTTP response there is an
    /// error, its end the end of the virtual connection.
    fn poll_in(&mut self) -> Result<()> {
        while let Ok(chunk) = self.inn.rx.try_recv() {
            self.inn.take(&self.in_link, chunk).map_err(|e| match e {
                Error::ConnectionLost(_) => {
                    Error::ConnectionLost("RD Gateway closed the RPC IN channel".into())
                }
                e => e,
            })?;
        }
        if !self.inn.plain.is_empty()
            && let Some(r) = http::parse_response(&self.inn.plain)?
        {
            return Err(channel_error(&r));
        }
        if self.inn.eof {
            return Err(Error::ConnectionLost(
                "RD Gateway closed the RPC IN channel".into(),
            ));
        }
        Ok(())
    }

    /// Waits for OUT channel bytes, watching the IN channel. With a
    /// deadline (setup) it polls the IN channel every 50 ms.
    fn fill(&mut self, deadline: Option<Instant>) -> Result<()> {
        loop {
            self.poll_in()?;
            if self.out.eof {
                return Err(closed());
            }
            let chunk = match deadline {
                None => self.out.rx.recv().map_err(|_| closed())?,
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(Error::Timeout);
                    }
                    match self
                        .out
                        .rx
                        .recv_timeout(left.min(Duration::from_millis(50)))
                    {
                        Ok(c) => c,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => return Err(closed()),
                    }
                }
            };
            return self.out.take(&self.shared.out_link, chunk);
        }
    }

    /// The OUT channel response head (2.1.2.1.4): 200, then the PDU stream.
    fn out_response(&mut self, deadline: Instant) -> Result<()> {
        loop {
            if let Some(r) = http::parse_response(&self.out.plain)? {
                self.out.plain.drain(..r.head_len);
                trace!("RPC OUT channel answered HTTP {}", r.status);
                return match r.status {
                    200 => Ok(()),
                    _ => Err(channel_error(&r)),
                };
            }
            self.fill(Some(deadline))?;
        }
    }

    /// The next PDU of the OUT channel, as is.
    fn next_raw(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>> {
        loop {
            if let Some(n) = dce::pdu_len(&self.out.plain)?
                && self.out.plain.len() >= n
            {
                return Ok(self.out.plain.drain(..n).collect());
            }
            self.fill(deadline)?;
        }
    }

    /// The next RPC PDU; RTS PDUs on the way are handled here.
    fn next_rpc(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>> {
        loop {
            let pdu = self.next_raw(deadline)?;
            if pdu[2] == dce::PTYPE_RTS {
                self.on_rts(&pdu)?;
                continue;
            }
            self.consumed(pdu.len())?;
            return Ok(pdu);
        }
    }

    /// RTS PDUs outside the connection setup: flow control
    /// acknowledgments for the IN channel (3.2.1.5.1.2), pings, and channel
    /// recycling, which ends the stream.
    fn on_rts(&mut self, pdu: &[u8]) -> Result<()> {
        let r = Rts::parse(pdu)?;
        if let Some(ack) = r.ack() {
            let mut tx = lock(&self.shared.tx);
            if ack.channel_cookie != tx.in_cookie {
                trace!("RPC flow control ack for another channel");
                return Ok(());
            }
            tx.window = rts::sender_window(&ack, tx.bytes_sent).ok_or_else(|| {
                Error::Protocol(format!(
                    "RPC flow control ack for {} of {} bytes",
                    ack.bytes_received, tx.bytes_sent
                ))
            })?;
            self.shared.window.notify_all();
        } else if r.flags & rts::FLAG_RECYCLE_CHANNEL != 0 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the RD Gateway recycles its RPC OUT channel; channel recycling is not supported",
            )));
        } else if r.flags & rts::FLAG_PING == 0 {
            trace!("ignoring RTS PDU flags {:#x} {:?}", r.flags, r.commands);
        }
        Ok(())
    }

    /// Receive window bookkeeping for an RPC PDU (3.2.1.5.1.1) and the
    /// acknowledgment once half the window is used (3.2.1.4.1.1).
    fn consumed(&mut self, n: usize) -> Result<()> {
        self.received += n as u64;
        self.available = self.available.saturating_sub(n as u32);
        if self.available < RECEIVE_WINDOW / 2 {
            let ack = rts::Ack {
                bytes_received: self.received as u32,
                available_window: RECEIVE_WINDOW,
                channel_cookie: self.out_cookie,
            };
            self.shared
                .send_rts(&rts::flow_control_ack(rts::FD_OUT_PROXY, ack))?;
            self.available = RECEIVE_WINDOW;
        }
        Ok(())
    }

    /// The next response: one kept from setup, else from the channel.
    fn next_response(&mut self, deadline: Option<Instant>) -> Result<dce::Response> {
        match self.early.pop_front() {
            Some(r) => Ok(r),
            None => self.read_response(deadline),
        }
    }

    /// Unseals the next response from the channel (or fails on a fault).
    fn read_response(&mut self, deadline: Option<Instant>) -> Result<dce::Response> {
        let mut pdu = self.next_rpc(deadline)?;
        match pdu[2] {
            dce::PTYPE_RESPONSE => {
                let mut sec = lock(&self.shared.sec);
                let sec = sec
                    .as_mut()
                    .ok_or_else(|| Error::Protocol("RPC response before the bind".into()))?;
                sec.response(&mut pdu)
            }
            dce::PTYPE_FAULT => Err(fault_error(dce::parse_fault(&pdu)?)),
            t => proto(format!("unexpected RPC PDU type {t}")),
        }
    }

    /// Makes a call during setup and collects its (fragmented) response.
    fn call(&mut self, opnum: u16, stub: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        let id = self.shared.call(opnum, stub, false)?;
        let mut stub = Vec::new();
        loop {
            let r = self.read_response(Some(deadline))?;
            if r.call_id != id {
                self.early.push_back(r);
                if self.early.len() > 64 {
                    return proto("too many RPC responses for other calls");
                }
                continue;
            }
            stub.extend_from_slice(&r.stub);
            if r.flags & dce::PFC_LAST_FRAG != 0 {
                return Ok(stub);
            }
        }
    }

    /// The DCE/RPC bind with NTLM (MS-RPCE 3.3.1.5.2): bind with the
    /// NEGOTIATE, bind_ack with the CHALLENGE, rpc_auth_3 with the
    /// AUTHENTICATE.
    fn bind(&mut self, gw: &GatewayConfig, client_name: &str, deadline: Instant) -> Result<()> {
        let (user, domain) = split_user(gw);
        let mut ntlm = Ntlm::new(&user, &domain, &gw.password, client_name);
        let level = dce::AUTHN_LEVEL_PKT_PRIVACY;
        let bind = dce::bind(1, dce::TSPROXY, level, &ntlm.negotiate());
        Shared::send_rpc(&mut lock(&self.shared.tx), &bind)?;
        let pdu = self.next_rpc(Some(deadline))?;
        let ack = match pdu[2] {
            dce::PTYPE_BIND_ACK => dce::parse_bind_ack(&pdu)?,
            dce::PTYPE_BIND_NAK => {
                return Err(Error::Auth(format!(
                    "RD Gateway refused the RPC bind (reason {})",
                    dce::parse_bind_nak(&pdu)?
                )));
            }
            dce::PTYPE_FAULT => return Err(fault_error(dce::parse_fault(&pdu)?)),
            t => return proto(format!("RPC PDU type {t} instead of bind_ack")),
        };
        match ack.results.first() {
            Some(&(dce::RESULT_ACCEPTANCE, _)) => {}
            r => {
                return Err(Error::Unsupported(format!(
                    "RD Gateway does not offer the TsProxy RPC interface ({r:?})"
                )));
            }
        }
        let authenticate = ntlm.authenticate(&ack.token)?;
        let auth3 = dce::auth3(1, level, &authenticate);
        {
            let mut tx = lock(&self.shared.tx);
            tx.max_xmit = (ack.max_recv_frag.min(dce::MAX_FRAG) as usize).max(1024);
            tx.call_id = 2;
            Shared::send_rpc(&mut tx, &auth3)?;
        }
        trace!(
            "RPC bound to TsProxy: frag {}, header signing {}",
            ack.max_recv_frag, ack.header_sign
        );
        *lock(&self.shared.sec) = Some(Security {
            ntlm,
            level,
            header_sign: ack.header_sign,
        });
        Ok(())
    }
}

/// Runs the RPC transport setup on two connected sockets (OUT channel,
/// IN channel). `tls` false is the plain transport of the loopback tests;
/// `trusted` is a certificate the caller already accepted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open(
    out_sock: TcpStream,
    in_sock: TcpStream,
    gw: &GatewayConfig,
    tls: bool,
    target: &Target,
    deadline: Instant,
    verify: Option<&crate::client::CertificateCheck>,
    trusted: Option<Vec<u8>>,
) -> Result<Tunnel> {
    let out_rx = spawn_socket_reader(out_sock.try_clone()?);
    let in_rx = spawn_socket_reader(in_sock.try_clone()?);
    let out_link = Arc::new(Mutex::new(Link {
        sock: out_sock,
        tls: None,
    }));
    let in_link = Arc::new(Mutex::new(Link {
        sock: in_sock,
        tls: None,
    }));
    let inbound = |rx| Inbound {
        rx,
        plain: Vec::new(),
        stream: Vec::new(),
        eof: false,
    };
    let r = setup(
        (out_link.clone(), inbound(out_rx)),
        (in_link.clone(), inbound(in_rx)),
        gw,
        tls,
        target,
        deadline,
        verify,
        trusted,
    );
    if r.is_err() {
        // Ends the socket reader threads.
        let _ = lock(&out_link).sock.shutdown(Shutdown::Both);
        let _ = lock(&in_link).sock.shutdown(Shutdown::Both);
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn setup(
    (out_link, mut out_in): (Arc<Mutex<Link>>, Inbound),
    (in_link, mut in_in): (Arc<Mutex<Link>>, Inbound),
    gw: &GatewayConfig,
    tls: bool,
    target: &Target,
    deadline: Instant,
    verify: Option<&crate::client::CertificateCheck>,
    trusted: Option<Vec<u8>>,
) -> Result<Tunnel> {
    let budget = deadline.saturating_duration_since(Instant::now());
    let mut deadline = deadline;
    let certificate = if tls {
        let der = at(
            "RPC OUT channel",
            tls_handshake(&out_link, &mut out_in, &gw.host, deadline),
        )?;
        if trusted.as_ref() != Some(&der)
            && let Some(check) = verify
        {
            let server = crate::client::ServerCertificate {
                host: gw.host.clone(),
                port: gw.port,
                der: der.clone(),
                sha256: crate::crypto::sha256(&der),
            };
            if !(check.0)(&server) {
                return Err(Error::Auth(
                    "the gateway certificate was not trusted".into(),
                ));
            }
            deadline = Instant::now() + budget;
        }
        let in_der = at(
            "RPC IN channel",
            tls_handshake(&in_link, &mut in_in, &gw.host, deadline),
        )?;
        if in_der != der {
            return Err(Error::Auth(
                "the gateway certificate was not trusted (it differs between the RPC channels)"
                    .into(),
            ));
        }
        Some(der)
    } else {
        None
    };

    let vc: Cookie = crate::crypto::random();
    let out_cookie: Cookie = crate::crypto::random();
    let in_cookie: Cookie = crate::crypto::random();
    let association: Cookie = crate::crypto::random();
    let session = random_uuid();
    let name = target.client_name;

    // MS-RPCH 3.2.2.4.1.2: the channel requests with CONN/A1 and CONN/B1.
    let a1 = rts::conn_a1(&vc, &out_cookie, RECEIVE_WINDOW);
    at(
        "RPC OUT channel",
        http_auth(
            &out_link,
            &mut out_in,
            gw,
            name,
            "RPC_OUT_DATA",
            OUT_CONTENT_LENGTH,
            &a1,
            &session,
            deadline,
        ),
    )?;
    let b1 = rts::conn_b1(
        &vc,
        &in_cookie,
        IN_CHANNEL_LIFETIME,
        CLIENT_KEEPALIVE,
        &association,
    );
    at(
        "RPC IN channel",
        http_auth(
            &in_link,
            &mut in_in,
            gw,
            name,
            "RPC_IN_DATA",
            IN_CHANNEL_LIFETIME,
            &b1,
            &session,
            deadline,
        ),
    )?;

    let shared = Arc::new(Shared {
        tx: Mutex::new(Tx {
            link: in_link.clone(),
            call_id: 1,
            max_xmit: dce::MAX_FRAG as usize,
            bytes_sent: 0,
            window: 0,
            lifetime_left: (IN_CHANNEL_LIFETIME as u64).saturating_sub(b1.len() as u64),
            last_send: Instant::now(),
            in_cookie,
            msg_pending: false,
            closed: false,
        }),
        window: Condvar::new(),
        sec: Mutex::new(None),
        out_link,
    });
    let mut rx = Rx {
        shared: shared.clone(),
        out: out_in,
        inn: in_in,
        in_link,
        received: 0,
        available: RECEIVE_WINDOW,
        out_cookie,
        early: VecDeque::new(),
    };

    // 3.2.2.5.2 to 3.2.2.5.4: HTTP 200, CONN/A3, CONN/C2.
    at("RPC OUT channel", rx.out_response(deadline))?;
    let a3 = at(
        "RPC virtual connection",
        rx.next_raw(Some(deadline)).and_then(|p| Rts::parse(&p)),
    )?;
    if !a3.is_conn_a3() {
        return at("RPC virtual connection", proto("expected CONN/A3"));
    }
    let c2 = at(
        "RPC virtual connection",
        rx.next_raw(Some(deadline)).and_then(|p| Rts::parse(&p)),
    )?;
    if !c2.is_conn_c2() {
        return at("RPC virtual connection", proto("expected CONN/C2"));
    }
    let timeout_ms = c2
        .connection_timeout()
        .or(a3.connection_timeout())
        .unwrap_or(120_000);
    lock(&shared.tx).window = c2.receive_window().unwrap_or(0);
    trace!(
        "RPC virtual connection open: in-proxy window {:?}, timeout {timeout_ms} ms",
        c2.receive_window()
    );

    at("RPC bind", rx.bind(gw, name, deadline))?;

    // MS-TSGU 3.6.4: tunnel, authorization, messages, channel, pipe.
    let created = at(
        "TsProxyCreateTunnel",
        rx.call(
            tsg::OP_CREATE_TUNNEL,
            &tsg::create_tunnel(CAPABILITIES),
            deadline,
        )
        .and_then(|s| tsg::parse_create_tunnel(&s)),
    )?;
    if created.hresult != 0 {
        return at(
            "TsProxyCreateTunnel",
            Err(refused("refused the tunnel", created.hresult)),
        );
    }
    trace!(
        "gateway tunnel {}, capabilities {:#x}",
        created.tunnel_id, created.capabilities
    );
    if let Some(m) = &created.consent {
        trace!("gateway consent message: {m}");
    }
    let tunnel = created.tunnel;

    let auth = at(
        "TsProxyAuthorizeTunnel",
        rx.call(
            tsg::OP_AUTHORIZE_TUNNEL,
            &tsg::authorize_tunnel(&tunnel, name),
            deadline,
        )
        .and_then(|s| tsg::parse_authorize_tunnel(&s)),
    )?;
    if auth.hresult != 0 {
        return at(
            "TsProxyAuthorizeTunnel",
            Err(refused("denied the tunnel", auth.hresult)),
        );
    }
    if created.capabilities & tsg::TSG_NAP_CAPABILITY_IDLE_TIMEOUT != 0
        && let Some(m) = auth.response_data.get(..4)
    {
        trace!(
            "gateway idle timeout {} minutes",
            u32::from_le_bytes([m[0], m[1], m[2], m[3]])
        );
    }
    trace!("gateway redirection flags {:?}", auth.redirection);

    let msg_call = if created.capabilities & tsg::TSG_MESSAGING_CAP_SERVICE_MSG != 0 {
        let stub = tsg::make_tunnel_call(&tunnel, tsg::TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST);
        let id = at(
            "TsProxyMakeTunnelCall",
            shared.call(tsg::OP_MAKE_TUNNEL_CALL, &stub, false),
        )?;
        lock(&shared.tx).msg_pending = true;
        Some(id)
    } else {
        None
    };

    let (hresult, channel, channel_id) = at(
        "TsProxyCreateChannel",
        rx.call(
            tsg::OP_CREATE_CHANNEL,
            &tsg::create_channel(&tunnel, target.host, target.port),
            deadline,
        )
        .and_then(|s| tsg::parse_create_channel(&s)),
    )?;
    if hresult != 0 {
        return at(
            "TsProxyCreateChannel",
            Err(refused(
                &format!("refused the channel to {}:{}", target.host, target.port),
                hresult,
            )),
        );
    }
    trace!("gateway channel {channel_id} open");

    let pipe_call = at(
        "TsProxySetupReceivePipe",
        shared.call(
            tsg::OP_SETUP_RECEIVE_PIPE,
            &tsg::setup_receive_pipe(&channel),
            false,
        ),
    )?;

    let period = Duration::from_millis(timeout_ms as u64 / 2)
        .clamp(Duration::from_secs(10), Duration::from_secs(150));
    let stop = keepalive(shared.clone(), period);
    let chunk = {
        let tx = lock(&shared.tx);
        tx.max_xmit.saturating_sub(SEND_OVERHEAD).min(tsg::SEND_MAX)
    };
    Ok(Tunnel {
        stream: GatewayStream::Rpc(RpcStream {
            shared: shared.clone(),
            tunnel,
            channel,
            chunk,
            stop: Some(stop),
            closed: false,
        }),
        reader: GatewayReader::Rpc(Box::new(RpcReader {
            rx,
            tunnel,
            pipe_call,
            msg_call,
            partial: HashMap::new(),
            out: Vec::new(),
            pos: 0,
            done: false,
        })),
        certificate,
    })
}

/// Sends a Ping on the IN channel when nothing else went out for `period`
/// (MS-RPCH 3.2.2.6.1). Ends when the returned sender is dropped.
fn keepalive(shared: Arc<Shared>, period: Duration) -> Sender<()> {
    let (stop, rx) = channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("rdp-gateway-keepalive".into())
        .spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(period) {
                let mut tx = lock(&shared.tx);
                if tx.closed {
                    return;
                }
                if tx.last_send.elapsed() >= period
                    && Shared::send_raw(&mut tx, &rts::ping()).is_err()
                {
                    return;
                }
            }
        });
    if spawned.is_err() {
        trace!("no keep-alive thread for the RPC IN channel");
    }
    stop
}

/// The write half: RDP bytes go out in TsProxySendToServer calls.
pub struct RpcStream {
    shared: Arc<Shared>,
    tunnel: Handle,
    channel: Handle,
    /// The most data one call carries.
    chunk: usize,
    stop: Option<Sender<()>>,
    closed: bool,
}

fn io_error(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        Error::ConnectionLost(m) => io::Error::new(io::ErrorKind::ConnectionAborted, m),
        e => io::Error::other(e.to_string()),
    }
}

impl Write for RpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[IoSlice::new(buf)])
    }

    /// TLS writes come as several slices; they share one call.
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut data = Vec::new();
        for b in bufs {
            let take = b.len().min(self.chunk - data.len());
            data.extend_from_slice(&b[..take]);
            if data.len() == self.chunk {
                break;
            }
        }
        if data.is_empty() {
            return Ok(0);
        }
        let stub = tsg::send_to_server(&self.channel, &data);
        self.shared
            .call(tsg::OP_SEND_TO_SERVER, &stub, true)
            .map_err(io_error)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ByteStream for RpcStream {
    /// Cancels the message call and closes the channel and the tunnel
    /// (MS-TSGU 3.6.4, best effort, without waiting), then both sockets.
    fn shutdown(&mut self) {
        if !self.closed {
            self.closed = true;
            self.stop = None;
            let pending = lock(&self.shared.tx).msg_pending;
            if pending {
                let stub =
                    tsg::make_tunnel_call(&self.tunnel, tsg::TSG_TUNNEL_CANCEL_ASYNC_MSG_REQUEST);
                let _ = self.shared.call(tsg::OP_MAKE_TUNNEL_CALL, &stub, false);
            }
            let _ = self
                .shared
                .call(tsg::OP_CLOSE_CHANNEL, &tsg::close(&self.channel), false);
            let _ = self
                .shared
                .call(tsg::OP_CLOSE_TUNNEL, &tsg::close(&self.tunnel), false);
        }
        self.shared.close();
        let _ = lock(&self.shared.out_link).sock.shutdown(Shutdown::Both);
        let link = lock(&self.shared.tx).link.clone();
        let _ = lock(&link).sock.shutdown(Shutdown::Both);
    }
}

/// The read half: blocking reads return the RDP bytes of the receive
/// pipe's responses; Ok(0) after its final response or when the gateway
/// closed the connection.
pub struct RpcReader {
    rx: Rx,
    tunnel: Handle,
    pipe_call: u32,
    msg_call: Option<u32>,
    /// Stubs of fragmented responses to other calls.
    partial: HashMap<u32, Vec<u8>>,
    out: Vec<u8>,
    pos: usize,
    done: bool,
}

impl RpcReader {
    fn step(&mut self) -> Result<()> {
        let r = self.rx.next_response(None)?;
        if r.call_id == self.pipe_call {
            if r.flags & dce::PFC_LAST_FRAG != 0 {
                let code = tsg::parse_return(&r.stub).unwrap_or(0);
                trace!(
                    "gateway closed the channel: {} ({code:#x})",
                    super::packets::error_name(code)
                );
                self.done = true;
            } else {
                self.out = r.stub;
                self.pos = 0;
            }
            return Ok(());
        }
        let stub = {
            let part = self.partial.entry(r.call_id).or_default();
            part.extend_from_slice(&r.stub);
            if r.flags & dce::PFC_LAST_FRAG == 0 {
                if self.partial.len() > 64 {
                    return proto("too many unfinished RPC responses");
                }
                return Ok(());
            }
            self.partial.remove(&r.call_id).unwrap_or_default()
        };
        if Some(r.call_id) == self.msg_call {
            return self.on_message(&stub);
        }
        // TsProxySendToServer (and close) results.
        let code = tsg::parse_return(&stub)?;
        if code != 0 {
            return Err(Error::Protocol(format!(
                "RD Gateway could not pass data on: {} ({code:#x})",
                super::packets::error_name(code)
            )));
        }
        Ok(())
    }

    /// An administrative message (MS-TSGU 3.6.4 data transfer step 3):
    /// logged, and the next one asked for.
    fn on_message(&mut self, stub: &[u8]) -> Result<()> {
        self.msg_call = None;
        lock(&self.rx.shared.tx).msg_pending = false;
        let (hresult, message) = tsg::parse_make_tunnel_call(stub)?;
        if hresult != 0 {
            trace!("gateway message call ended: {hresult:#x}");
            return Ok(());
        }
        match message {
            Some((tsg::TSG_ASYNC_MESSAGE_REAUTH, _)) => {
                trace!("gateway asks to reauthenticate; not supported over RPC")
            }
            Some((_, text)) => trace!("gateway message: {text}"),
            None => {}
        }
        let stub = tsg::make_tunnel_call(&self.tunnel, tsg::TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST);
        // Never waits here: this thread processes the acknowledgments.
        if let Ok(id) = self.rx.shared.call(tsg::OP_MAKE_TUNNEL_CALL, &stub, false) {
            self.msg_call = Some(id);
            lock(&self.rx.shared.tx).msg_pending = true;
        }
        Ok(())
    }
}

impl Read for RpcReader {
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
            match self.step() {
                Ok(()) => {}
                Err(Error::ConnectionLost(m)) => {
                    trace!("RD Gateway RPC stream ended: {m}");
                    self.done = true;
                }
                Err(e) => {
                    self.done = true;
                    self.rx.shared.close();
                    return Err(io_error(e));
                }
            }
        }
    }
}
