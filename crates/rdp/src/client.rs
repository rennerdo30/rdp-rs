//! Connection sequence (MS-RDPBCGR 1.3.1.1) and the session loop.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::autodetect::{AutoDetect, NetworkCharacteristics};
use crate::channel::{self, ChannelOut, Slot, StaticChannel};
use crate::codec;
use crate::compress::{Compression, Decompressor};
use crate::credssp;
use crate::crypto::sha256;
use crate::der;
use crate::error::{Error, Result, proto};
use crate::fastpath::{self, Reassembler};
use crate::framebuffer::{Damage, Framebuffer};
use crate::gateway;
use crate::gcc;
use crate::input::{InputEvent, fastpath_input};
use crate::mcs::{self, DomainPdu};
use crate::pdu::{self, AutoReconnectCookie, DemandActive, SaveSessionInfo};
use crate::pointer::{PointerCache, PointerUpdate};
use crate::redirect::{self, Redirection};
use crate::trace;
use crate::transport::{Frame, Framer};
use crate::x224;

/// The RDP server's TLS certificate, shown to the caller before any
/// credentials are sent (CredSSP runs only after the check passes).
#[derive(Debug, Clone)]
pub struct ServerCertificate {
    pub host: String,
    pub port: u16,
    /// The end-entity certificate, DER.
    pub der: Vec<u8>,
    pub sha256: [u8; 32],
}

impl ServerCertificate {
    /// "AB:CD:…" over the SHA-256 of the certificate.
    pub fn fingerprint(&self) -> String {
        self.sha256
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Decides whether a server certificate is trusted. It may block, for
/// example to ask the user; the connection's step deadline restarts after it.
#[derive(Clone)]
pub struct CertificateCheck(pub std::sync::Arc<dyn Fn(&ServerCertificate) -> bool + Send + Sync>);

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub password: String,
    pub width: u16,
    pub height: u16,
    pub client_name: String,
    pub keyboard_layout: u32,
    /// Desktop scale in percent (100..=500), like Windows' display scaling.
    pub scale: u32,
    /// Bound on every step of the connection sequence.
    pub timeout: Duration,
    /// Resume a disconnected session with this cookie (MS-RDPBCGR 5.5) instead
    /// of a new logon. Take it from [`Client::auto_reconnect_cookie`] of the
    /// session that dropped. The credentials are still sent: the server falls
    /// back to them if it rejects the cookie (3.3.5.3.11).
    pub auto_reconnect: Option<AutoReconnectCookie>,
    /// Colour depth: 15, 16, 24 or 32 bits per pixel.
    pub color_depth: u16,
    /// Connection speed hint for the server.
    pub connection_type: crate::ConnectionType,
    /// Desktop features (wallpaper, font smoothing, …); fixed at logon.
    pub experience: crate::Experience,
    /// Checks the server certificate before credentials are sent. None
    /// accepts any certificate (the fingerprint is still traced).
    pub verify_certificate: Option<CertificateCheck>,
    /// Connect through this RD Gateway (MS-TSGU); None connects directly.
    pub gateway: Option<crate::gateway::GatewayConfig>,
    /// Highest bulk compression type to advertise (MS-RDPBCGR 3.1.8).
    pub compression: Compression,
    /// Bitmap updates (default) or the graphics pipeline (MS-RDPEGFX).
    pub graphics: crate::Graphics,
    /// H.264 decoder for AVC420 with [`crate::Graphics::Gfx`]; without one
    /// (or if it returns `None`) the client advertises AVC as disabled.
    pub h264: Option<crate::H264Factory>,
    /// Several monitors (MS-RDPBCGR 2.2.1.3.6); empty is one monitor of
    /// `width` x `height`. When set, the desktop is their bounding box and
    /// `width`/`height` are not used.
    pub monitors: Vec<crate::Monitor>,
    /// Security package for NLA (MS-CSSP), for example Kerberos through the
    /// platform; None uses the crate's own NTLMv2.
    pub auth: Option<crate::AuthFactory>,
    /// Connect as told by a Server Redirection PDU (MS-RDPBCGR 3.2.5.13):
    /// its target, routing token, credentials and session id. Set by
    /// [`Client::connect_with`] between hops and by
    /// [`Client::follow_redirection`] after activation; set it yourself from
    /// [`Client::redirection`] to reconnect with an LB_NOREDIRECT routing token.
    pub redirection: Option<Redirection>,
    /// Server redirections already followed to get here, counted against
    /// [`redirect::MAX_REDIRECTS`] across connect-time and mid-session hops.
    /// 0 for a new connection; set by the redirection code.
    pub redirects: usize,
    /// RemoteApp mode (MS-RDPERP): start this program in seamless windows
    /// instead of a desktop. The client opens the `rail` channel itself;
    /// [`Client::rail`] gives its handle.
    pub remote_app: Option<crate::RemoteApp>,
    /// Advertise surface commands with RemoteFX and NSCodec (MS-RDPBCGR
    /// 2.2.9.2, MS-RDPRFX). With [`crate::Graphics::Gfx`] too, the server
    /// picks; it prefers the graphics pipeline.
    pub surface_commands: bool,
    /// Directory for client licenses and the client hardware id
    /// (MS-RDPELE 3.3.1.8, 3.3.1.9); None keeps nothing on disk.
    pub license_store: Option<std::path::PathBuf>,
    /// Advertise drawing orders, glyph, brush, offscreen and bitmap caches
    /// (MS-RDPEGDI). Off, the server sends bitmap updates only.
    pub drawing_orders: bool,
    /// Directory of the persistent bitmap cache (MS-RDPEGDI 3.2.1.4), one
    /// per server; None keeps no bitmaps between sessions.
    pub bitmap_cache_dir: Option<std::path::PathBuf>,
}

impl Config {
    pub fn new(host: &str, username: &str, password: &str) -> Self {
        Self {
            host: host.into(),
            port: 3389,
            username: username.into(),
            domain: String::new(),
            password: password.into(),
            width: 1280,
            height: 800,
            client_name: "RDP-RS".into(),
            keyboard_layout: 0x0409,
            scale: 100,
            timeout: Duration::from_secs(20),
            auto_reconnect: None,
            color_depth: 32,
            connection_type: crate::ConnectionType::Lan,
            experience: crate::Experience::default(),
            verify_certificate: None,
            gateway: None,
            compression: Compression::Off,
            graphics: crate::Graphics::Bitmap,
            h264: None,
            monitors: Vec::new(),
            auth: None,
            redirection: None,
            redirects: 0,
            remote_app: None,
            surface_commands: true,
            license_store: None,
            drawing_orders: true,
            bitmap_cache_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub protocol: u32,
    pub certificate_sha256: [u8; 32],
    /// SHA-256 of the RD Gateway's TLS certificate, when connected through one.
    pub gateway_certificate_sha256: Option<[u8; 32]>,
    pub server_rdp_version: u32,
    pub width: u16,
    pub height: u16,
    pub bpp: u16,
}

#[derive(Debug, Default)]
pub struct PollOutcome {
    /// At least one bitmap was drawn.
    pub updated: bool,
    /// Framebuffer rectangles changed during this poll.
    pub damage: Vec<Damage>,
    /// The desktop size changed (reactivation); the framebuffer was reallocated.
    pub resized: bool,
    /// The session ended.
    pub closed: Option<CloseReason>,
    /// The latest cursor change during this poll.
    pub pointer: Option<PointerUpdate>,
    /// The server's latest Monitor Layout PDU (2.2.12.1) during this poll.
    pub monitors: Option<Vec<crate::Monitor>>,
    /// RemoteApp window and channel events, in order (MS-RDPERP).
    pub rail: Vec<crate::RailEvent>,
    /// The server sent a new Network Characteristics Result (MS-RDPBCGR
    /// 2.2.14.1.5); the merged values so far.
    pub network: Option<NetworkCharacteristics>,
}

/// Why a session ended, and whether an auto-reconnect (MS-RDPBCGR 5.5) fits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReason {
    /// Human-readable cause, including the server's error info if any.
    pub text: String,
    /// True for a network drop: the transport ended (TCP reset, EOF, TLS
    /// close) and the server sent no Set Error Info code (2.2.5.1.1). False
    /// when the server ended the session itself: an MCS Disconnect Provider
    /// Ultimatum, or any nonzero error info (logoff, admin disconnect, idle
    /// timeout, another connection took the session, shutdown, licensing or
    /// protocol errors). Every defined code describes a deliberate end or a
    /// server-side failure that a reconnect cannot cure.
    pub reconnectable: bool,
    /// The last Set Error Info code (0 = none).
    pub error_info: u32,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// How the connection ended, before the error info is weighed.
enum CloseCause<'a> {
    /// Transport EOF or reset without an RDP-level goodbye.
    Transport(&'a str),
    /// MCS Disconnect Provider Ultimatum from the server.
    Ultimatum(&'a str),
}

/// How long a heartbeat-sending server may stay silent before the connection
/// counts as dropped: `reconnect` missed periods (MS-RDPBCGR 2.2.16.1).
fn silence_limit(hb: pdu::Heartbeat) -> Option<Duration> {
    if hb.period == 0 || hb.reconnect == 0 {
        return None;
    }
    Some(Duration::from_secs(hb.period as u64 * hb.reconnect as u64))
}

fn close_reason(cause: CloseCause, error_info: u32) -> CloseReason {
    let (base, transport) = match cause {
        CloseCause::Transport(m) => (m, true),
        CloseCause::Ultimatum(m) => (m, false),
    };
    let text = if error_info != 0 {
        format!(
            "{base} (error info {error_info:#x}: {})",
            pdu::error_info_name(error_info)
        )
    } else {
        base.to_string()
    };
    CloseReason {
        text,
        reconnectable: transport && error_info == 0,
        error_info,
    }
}

pub struct Client {
    f: Framer,
    user_id: u16,
    io_channel: u16,
    share_id: u32,
    keyboard_layout: u32,
    color_depth: u16,
    fb: Framebuffer,
    fastpath: Reassembler,
    /// Server-to-client bulk decompression, shared by slow-path, fast-path
    /// and virtual channel data.
    bulk: Decompressor,
    info: ConnectionInfo,
    active: bool,
    last_error_info: u32,
    /// Heartbeat settings from the server (if it sends them), and when data
    /// last arrived: a silent connection is a dropped one.
    heartbeat: Option<pdu::Heartbeat>,
    last_seen: Instant,
    channels: Vec<Slot>,
    pointers: PointerCache,
    arc_cookie: Option<AutoReconnectCookie>,
    /// Graphics pipeline output, when [`Config::graphics`] asks for it.
    gfx: Option<crate::gfx::GfxHandle>,
    /// The server's monitor layout (2.2.12.1); empty until it sends one.
    monitor_layout: Vec<crate::Monitor>,
    /// The last Server Redirection PDU that was not followed here.
    redirection: Option<Redirection>,
    /// RemoteApp window model, when [`Config::remote_app`] is set.
    rail: Option<crate::RailHandle>,
    /// The MCS message channel (2.2.1.4.5), if the server opened one.
    message_channel: Option<u16>,
    /// Network auto-detection answers and results (2.2.14).
    autodetect: AutoDetect,
    /// The server this connection reached; a redirection without a target
    /// goes back to it (1.3.8).
    host: String,
    /// The session ended for a Server Redirection PDU to follow (3.2.5.13).
    follow: bool,
    /// Surface command state, when [`Config::surface_commands`] is set.
    surface: Option<crate::surfcmd::SurfaceCommands>,
    /// Drawing orders and their caches, when [`Config::drawing_orders`] is set.
    orders: Option<Box<crate::orders::Orders>>,
}

/// Connection-sequence traffic that is not the I/O channel PDU being waited
/// for: virtual channel data kept for the session, and message channel PDUs
/// (connect-time auto-detection, 2.2.14) answered on the spot.
struct EarlyIo {
    queued: Vec<(u16, Vec<u8>)>,
    user_id: u16,
    message_channel: Option<u16>,
    autodetect: AutoDetect,
}

impl EarlyIo {
    /// Handles one PDU that is not for the I/O channel.
    fn take(&mut self, f: &mut Framer, channel: u16, data: &[u8]) -> Result<()> {
        if Some(channel) == self.message_channel {
            if let Some(rsp) = self.autodetect.on_pdu(data, Instant::now()) {
                send_io(f, self.user_id, channel, &rsp)?;
            }
            return Ok(());
        }
        trace!(
            "channel {channel}: {} bytes before activation, queued",
            data.len()
        );
        self.queued.push((channel, data.to_vec()));
        Ok(())
    }
}

/// One connection attempt's end: a session, or a redirection to follow
/// with the channel handlers, which have not seen any traffic yet.
enum Hop {
    Done(Box<Client>),
    /// The redirection, the host that sent it, and the handlers.
    Redirect(Box<Redirection>, String, Vec<Box<dyn StaticChannel>>),
}

/// Opens TCP (or the gateway tunnel) to the first reachable host: the
/// redirection's targets, else `cfg.host`. Returns the host it reached.
fn open(cfg: &Config, deadline: Instant) -> Result<(Framer, Option<[u8; 32]>, String)> {
    let mut hosts = cfg
        .redirection
        .as_ref()
        .map(Redirection::targets)
        .unwrap_or_default();
    if hosts.is_empty() {
        hosts.push(cfg.host.clone());
    }
    if let Some(gw) = &cfg.gateway {
        // The gateway resolves and reaches the host itself.
        let host = hosts.swap_remove(0);
        let verify = cfg.verify_certificate.as_ref();
        let t = gateway::connect(gw, &host, cfg.port, &cfg.client_name, deadline, verify)?;
        let cert = t.certificate.as_deref().map(sha256);
        let f = Framer::over(Box::new(t.stream), Box::new(t.reader));
        return Ok((f, cert, host));
    }
    let mut last = None;
    for host in hosts {
        let attempt = (host.as_str(), cfg.port)
            .to_socket_addrs()
            .map_err(Error::from)
            .and_then(|mut a| {
                a.next()
                    .ok_or_else(|| Error::Protocol(format!("cannot resolve {host}")))
            })
            .and_then(|addr| Ok(TcpStream::connect_timeout(&addr, cfg.timeout)?));
        match attempt {
            Ok(sock) => {
                sock.set_nodelay(true)?;
                return Ok((Framer::new(sock), None, host));
            }
            Err(e) => {
                trace!("cannot reach {host}:{}: {e}", cfg.port);
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Protocol("no host to connect to".into())))
}

/// Adds the graphics channel to the `drdynvc` handler, or adds a `drdynvc`
/// handler for it (MS-RDPEGFX 2.1).
fn add_gfx_channel(
    cfg: &Config,
    handlers: &mut Vec<Box<dyn StaticChannel>>,
) -> crate::gfx::GfxHandle {
    let decoder = cfg.h264.as_ref().and_then(|make| make());
    trace!(
        "graphics pipeline offered; H.264 decoder {}",
        if decoder.is_some() {
            "available"
        } else {
            "not available"
        }
    );
    let (channel, handle) = crate::gfx::graphics(decoder);
    let mut channel: Option<Box<dyn crate::DynamicChannel>> = Some(Box::new(channel));
    if let Some(host) = handlers.iter_mut().find_map(|h| h.as_drdynvc()) {
        host.add(channel.take().expect("not yet added"));
    }
    if let Some(channel) = channel {
        handlers.push(Box::new(crate::Drdynvc::new(vec![channel])));
    }
    handle
}

/// Sends one complete virtual channel message, chunked.
fn send_channel(f: &mut Framer, user_id: u16, slot: &Slot, msg: &[u8]) -> Result<()> {
    let show = slot.handler.options() & channel::CHANNEL_OPTION_SHOW_PROTOCOL != 0;
    for c in channel::chunk(msg, show) {
        f.write(&x224::data(&mcs::send_data_request(user_id, slot.id, &c)))?;
    }
    Ok(())
}

fn send_io(f: &mut Framer, user_id: u16, io: u16, data: &[u8]) -> Result<()> {
    if crate::log::verbose() {
        // The Client Info PDU (SEC_INFO_PKT) carries the password: never dump it.
        if data.starts_with(&[0x40, 0x00]) {
            trace!(
                "send {} bytes on channel {io}: [client info, redacted]",
                data.len()
            );
        } else if data.starts_with(&[0x80, 0x00]) {
            // Licensing PDUs (SEC_LICENSE_PKT) carry the encrypted
            // premaster secret, the license and the hardware id.
            trace!(
                "send {} bytes on channel {io}: [licensing, redacted]",
                data.len()
            );
        } else {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            trace!("send {} bytes on channel {io}: {hex}", data.len());
        }
    }
    f.write(&x224::data(&mcs::send_data_request(user_id, io, data)))
}

fn read_x224(f: &mut Framer, deadline: Instant) -> Result<Vec<u8>> {
    loop {
        match f.read_frame(Some(deadline))? {
            Some(Frame::X224(v)) => return Ok(v),
            Some(Frame::FastPath(_)) => trace!("fast-path PDU before activation ignored"),
            None => return Err(Error::Timeout),
        }
    }
}

fn read_mcs(f: &mut Framer, deadline: Instant) -> Result<Vec<u8>> {
    Ok(x224::data_payload(&read_x224(f, deadline)?)?.to_vec())
}

/// Reads the next I/O channel PDU during the connection sequence. Virtual
/// channel traffic that arrives this early (for example the device
/// redirection or clipboard handshake) is kept in `early` and delivered to
/// its channel once the session exists; auto-detect requests on the message
/// channel are answered at once (1.3.1.1, connect-time auto-detection).
fn read_io(f: &mut Framer, io: u16, deadline: Instant, early: &mut EarlyIo) -> Result<Vec<u8>> {
    loop {
        let payload = read_mcs(f, deadline)?;
        match mcs::parse_domain_pdu(&payload)? {
            DomainPdu::SendDataIndication { channel, data } if channel == io => {
                return Ok(data.to_vec());
            }
            DomainPdu::SendDataIndication { channel, data } => {
                let data = data.to_vec();
                early.take(f, channel, &data)?;
            }
            DomainPdu::DisconnectProviderUltimatum { reason } => {
                return Err(Error::Disconnected(format!(
                    "MCS disconnect, reason {reason}"
                )));
            }
            DomainPdu::Other(c) => trace!("ignoring MCS PDU choice {c}"),
        }
    }
}

/// The configuration for the next hop of a redirection chain, connect-time
/// or mid-session alike: the redirection, sent by `from`, counted against
/// [`redirect::MAX_REDIRECTS`] (3.2.5.13).
fn next_hop(cfg: &Config, to: Redirection, from: String) -> Result<Config> {
    let hop = cfg.redirects + 1;
    if hop > redirect::MAX_REDIRECTS {
        return Err(Error::Protocol(format!(
            "more than {} server redirections",
            redirect::MAX_REDIRECTS
        )));
    }
    trace!("{}", to.hop_trace(hop));
    let mut next = cfg.clone();
    // A redirection without a target goes back to its sender (1.3.8).
    next.host = from;
    next.redirection = Some(to);
    next.redirects = hop;
    Ok(next)
}

fn split_user(cfg: &Config) -> (String, String) {
    let (mut user, mut domain) = match cfg.username.split_once('\\') {
        Some((d, u)) if cfg.domain.is_empty() => (u.to_string(), d.to_string()),
        _ => (cfg.username.clone(), cfg.domain.clone()),
    };
    // A redirection's UserName and Domain replace the configured ones
    // (LB_DONTSTOREUSERNAME requires the UserName, 2.2.13.1).
    if let Some(r) = cfg.redirection.as_ref().filter(|r| !r.no_redirect()) {
        user = r.username.clone().unwrap_or(user);
        domain = r.domain.clone().unwrap_or(domain);
    }
    (user, domain)
}

impl Client {
    /// Connects without virtual channels.
    pub fn connect(cfg: &Config) -> Result<Client> {
        Self::connect_with(cfg, Vec::new())
    }

    /// Connects and opens the given static virtual channels. A Server
    /// Redirection PDU during the connection sequence (MS-RDPBCGR 3.2.5.13)
    /// is followed here, up to [`redirect::MAX_REDIRECTS`] hops, with the
    /// same handlers: they have seen no traffic before activation.
    pub fn connect_with(cfg: &Config, mut handlers: Vec<Box<dyn StaticChannel>>) -> Result<Client> {
        let gfx =
            (cfg.graphics == crate::Graphics::Gfx).then(|| add_gfx_channel(cfg, &mut handlers));
        // RemoteApp: the rail channel is opened by the client itself.
        let rail = match &cfg.remote_app {
            Some(app) => {
                let (channel, handle) = crate::rail::rail(
                    app.clone(),
                    cfg.width,
                    cfg.height,
                    crate::rail::client_status_flags(cfg.auto_reconnect.is_some()),
                )?;
                handlers.push(Box::new(channel));
                Some(handle)
            }
            None => None,
        };
        let mut cfg = cfg.clone();
        loop {
            match Self::connect_hop(&cfg, handlers, gfx.clone(), rail.clone())? {
                Hop::Done(client) => return Ok(*client),
                Hop::Redirect(to, from, back) => {
                    cfg = next_hop(&cfg, *to, from)?;
                    handlers = back;
                }
            }
        }
    }

    /// The configuration that follows the Server Redirection PDU which ended
    /// this session after activation (Enhanced Security Server Redirection,
    /// 2.2.13.3.1, 3.2.5.13): the same settings, with the redirection's
    /// target, routing token, credentials and session id, and the hop count
    /// so far. Connect it with [`Client::connect_with`] and new channel
    /// handlers (these ones have session state); that runs the same hop loop
    /// as a connect-time redirection. `cfg` is the configuration this session
    /// was connected with. None when the session did not end for a
    /// redirection; an error past [`redirect::MAX_REDIRECTS`] hops.
    pub fn follow_redirection(&self, cfg: &Config) -> Option<Result<Config>> {
        let to = self.redirection.clone().filter(|_| self.follow)?;
        Some(next_hop(cfg, to, self.host.clone()))
    }

    /// The latest network characteristics the server reported (2.2.14.1.5),
    /// with [`crate::ConnectionType::Auto`]; all None until then.
    pub fn network(&self) -> NetworkCharacteristics {
        self.autodetect.network()
    }

    fn connect_hop(
        cfg: &Config,
        handlers: Vec<Box<dyn StaticChannel>>,
        gfx: Option<crate::gfx::GfxHandle>,
        rail: Option<crate::RailHandle>,
    ) -> Result<Hop> {
        // Several monitors: the desktop is their bounding box (2.2.1.3.6).
        let desktop = match cfg.monitors.as_slice() {
            [] => None,
            m => Some(crate::monitor::VirtualDesktop::new(m)?),
        };
        let mut deadline = Instant::now() + cfg.timeout;
        let (user, domain) = split_user(cfg);
        let redirection = cfg.redirection.as_ref();

        let (mut f, gateway_certificate_sha256, host) = open(cfg, deadline)?;
        f.set_read_timeout(Duration::from_millis(100))?;

        // 1. X.224 negotiation; a routing token replaces the cookie (3.2.5.3.1)
        let cookie: String = user.chars().take(9).collect();
        let mut requested = x224::PROTOCOL_SSL | x224::PROTOCOL_HYBRID | x224::PROTOCOL_HYBRID_EX;
        let rdstls = redirection.filter(|r| !r.no_redirect() && r.wants_rdstls());
        if rdstls.is_some() {
            requested |= x224::PROTOCOL_RDSTLS;
        }
        match redirection.and_then(Redirection::routing_token) {
            Some(token) => f.write(&x224::connection_request_routed(&token, requested)?)?,
            None => f.write(&x224::connection_request(&cookie, requested))?,
        }
        let confirm = read_x224(&mut f, deadline)?;
        let protocol = x224::parse_connection_confirm(&confirm)?;
        let extended_data =
            x224::negotiation_flags(&confirm) & x224::EXTENDED_CLIENT_DATA_SUPPORTED != 0;
        trace!("negotiated protocol {protocol:#x}");
        if protocol & requested == 0 {
            return Err(Error::Unsupported(
                "server only offers legacy RDP security (no TLS)".into(),
            ));
        }

        // 2. TLS, then NLA
        let cert = f.upgrade_tls(&host, deadline)?;
        let certificate_sha256 = sha256(&cert);
        // The target must present the certificate the redirector named (5.4.5.3.1).
        let pinned = redirection.and_then(|r| r.target_certificate.as_ref());
        if pinned.is_some_and(|p| *p != cert) {
            return Err(Error::Auth(
                "the redirection target's certificate differs from the one the broker named".into(),
            ));
        }
        if let Some(check) = &cfg.verify_certificate {
            let server = ServerCertificate {
                host: host.clone(),
                port: cfg.port,
                der: cert.clone(),
                sha256: certificate_sha256,
            };
            if !(check.0)(&server) {
                return Err(Error::Auth("the server certificate was not trusted".into()));
            }
            // The check may have waited for the user.
            deadline = Instant::now() + cfg.timeout;
        }
        if let Some(r) = rdstls.filter(|_| protocol == x224::PROTOCOL_RDSTLS) {
            // RDSTLS logon with the redirected credentials (5.4.5.3.1).
            let caps = f.read_exact(redirect::RDSTLS_CAPABILITIES_LEN, deadline)?;
            redirect::parse_rdstls_capabilities(&caps)?;
            f.write(&redirect::rdstls_auth_request(r)?)?;
            let rsp = f.read_exact(redirect::RDSTLS_RESPONSE_LEN, deadline)?;
            let code = redirect::parse_rdstls_response(&rsp)?;
            if code != 0 {
                return Err(Error::Auth(format!("RDSTLS logon refused ({code:#x})")));
            }
        } else if protocol & (x224::PROTOCOL_HYBRID | x224::PROTOCOL_HYBRID_EX) != 0 {
            let public_key = der::subject_public_key(&cert)?;
            let params = credssp::AuthParams {
                host: &cfg.host,
                user: &user,
                domain: &domain,
                password: &cfg.password,
                workstation: &cfg.client_name,
            };
            credssp::authenticate(&mut f, &public_key, &params, cfg.auth.as_ref(), deadline)?;
            if protocol == x224::PROTOCOL_HYBRID_EX {
                let result = f.read_exact(4, deadline)?;
                let code = u32::from_le_bytes(result[..4].try_into().unwrap());
                if code != 0 {
                    return Err(Error::Auth(format!(
                        "early user authorization denied ({code:#x})"
                    )));
                }
            }
        }

        // 3. MCS connect with GCC conference data
        let defs: Vec<(String, u32)> = handlers
            .iter()
            .map(|h| (h.name().to_string(), h.options()))
            .collect();
        let def_refs: Vec<(&str, u32)> = defs.iter().map(|(n, o)| (n.as_str(), *o)).collect();
        if let Some(d) = &desktop {
            trace!(
                "{} monitors, desktop {}x{}{}",
                d.monitors.len(),
                d.width,
                d.height,
                if extended_data {
                    ""
                } else {
                    " (server takes no monitor data: one spanning monitor)"
                }
            );
        }
        let (width, height) = desktop.as_ref().map_or((cfg.width, cfg.height), |d| {
            (d.width as u16, d.height as u16)
        });
        let settings = gcc::ClientSettings {
            width,
            height,
            keyboard_layout: cfg.keyboard_layout,
            client_name: &cfg.client_name,
            selected_protocol: protocol,
            scale: cfg.scale,
            color_depth: cfg.color_depth,
            connection_type: cfg.connection_type,
            channels: &def_refs,
            gfx: gfx.is_some(),
            monitors: desktop.as_ref().filter(|_| extended_data),
            redirected_session_id: redirection.map(|r| r.session_id),
            redirected_smartcard: redirection.is_some_and(Redirection::smartcard_logon),
        };
        f.write(&x224::data(&mcs::connect_initial(
            &gcc::conference_create_request(&settings),
        )))?;
        let server = gcc::parse_conference_create_response(&mcs::parse_connect_response(
            &read_mcs(&mut f, deadline)?,
        )?)?;
        trace!("server data: {server:?}");

        // 4. Domain, user and channels
        f.write(&x224::data(&mcs::erect_domain_request()))?;
        f.write(&x224::data(&mcs::attach_user_request()))?;
        let user_id = mcs::parse_attach_user_confirm(&read_mcs(&mut f, deadline)?)?;
        let mut channels = vec![user_id, server.io_channel];
        // The message channel, if any, is joined too (2.2.1.4.5, 3.2.5.3.8).
        channels.extend(server.message_channel);
        channels.extend(&server.channel_ids);
        for ch in channels {
            f.write(&x224::data(&mcs::channel_join_request(user_id, ch)))?;
            let joined = mcs::parse_channel_join_confirm(&read_mcs(&mut f, deadline)?)?;
            trace!("joined channel {joined}");
        }
        let io = server.io_channel;

        // 5. Client info and licensing
        let mut early = EarlyIo {
            queued: Vec::new(),
            user_id,
            message_channel: server.message_channel,
            autodetect: AutoDetect::default(),
        };
        let info = pdu::ClientInfo {
            domain: &domain,
            user: &user,
            password: &cfg.password,
            // Enhanced RDP Security only (legacy security is refused above),
            // so the verifier uses the all-zero client random of 5.5 step 4.
            auto_reconnect: cfg
                .auto_reconnect
                .as_ref()
                .map(|c| c.client_packet(&pdu::ENHANCED_SECURITY_CLIENT_RANDOM)),
            performance_flags: cfg.experience.performance_flags(),
            compression: cfg.compression.type_code(),
            rail: rail.is_some(),
        };
        // A redirection's password blob goes to the target unchanged; after
        // an RDSTLS logon the Client Info carries no password.
        let info_pdu = match redirection.and_then(Redirection::client_info_password) {
            Some(blob) => pdu::client_info_redirected(&info, blob),
            None if rdstls.is_some() && protocol == x224::PROTOCOL_RDSTLS => {
                pdu::client_info(&pdu::ClientInfo {
                    password: "",
                    ..info
                })
            }
            None => pdu::client_info(&info),
        };
        trace!(
            "experience: {:?}, {} bpp, {:?} (performance flags {:#x})",
            cfg.experience,
            cfg.color_depth,
            cfg.connection_type,
            cfg.experience.performance_flags()
        );
        if cfg.auto_reconnect.is_some() {
            trace!("client info carries an auto-reconnect cookie");
        }
        send_io(&mut f, user_id, io, &info_pdu)?;
        // With TLS the server answers with one "valid client" licensing PDU.
        let mut pending = None;
        let data = read_io(&mut f, io, deadline, &mut early)?;
        if pdu::looks_like_share_control(&data) || redirect::is_enhanced(&data) {
            pending = Some(data); // server skipped licensing
        } else if redirect::is_standard_security(&data) {
            return Err(Error::Unsupported(
                "Standard Security Server Redirection PDU (needs Standard RDP Security)".into(),
            ));
        } else {
            // Licensing (MS-RDPELE): usually one "valid client" alert, else
            // the full exchange.
            let store = cfg.license_store.as_deref();
            let mut lic = crate::license::Licensing::new(store, &user, &cfg.client_name);
            let mut data = data;
            loop {
                let (send, step) = lic.process(&data);
                for msg in send {
                    send_io(&mut f, user_id, io, &msg)?;
                }
                if step? == crate::license::Step::Done {
                    break;
                }
                data = read_io(&mut f, io, deadline, &mut early)?;
            }
        }

        // 6. Capability exchange; a Server Redirection PDU may come instead (3.2.5.13.1)
        let mut informational = None;
        let demand = loop {
            let data = match pending.take() {
                Some(d) => d,
                None => read_io(&mut f, io, deadline, &mut early)?,
            };
            let parts = pdu::split_share_control(&data)?;
            if let Some((_, body)) = parts
                .iter()
                .find(|(t, _)| *t == redirect::PDUTYPE_SERVER_REDIR_PKT)
            {
                let to = Redirection::parse_enhanced(body)?;
                if !to.no_redirect() {
                    return Ok(Hop::Redirect(Box::new(to), host, handlers));
                }
                trace!("server redirection info (LB_NOREDIRECT), kept for a reconnect");
                informational = Some(to);
            }
            if let Some((_, body)) = parts.iter().find(|(t, _)| *t == pdu::PDUTYPE_DEMANDACTIVE) {
                break pdu::parse_demand_active(body)?;
            }
            trace!("ignoring PDU while waiting for Demand Active");
        };
        trace!("demand active: {demand:?}");
        if rail.is_some() && !demand.supports_rail() {
            // MS-RDPERP 3.2.5.1.5: the client MUST drop the connection.
            return Err(Error::Unsupported(
                "the server does not offer RemoteApp (no RAIL capability sets)".into(),
            ));
        }
        // The server assigns channel ids in the order the client listed them.
        let slots: Vec<Slot> = handlers
            .into_iter()
            .zip(server.channel_ids.iter().copied())
            .map(|(handler, id)| {
                trace!("virtual channel {} on MCS channel {id}", handler.name());
                Slot {
                    id,
                    handler,
                    defrag: Default::default(),
                    failed: false,
                }
            })
            .collect();

        let mut client = Client {
            f,
            user_id,
            io_channel: io,
            share_id: demand.share_id,
            keyboard_layout: cfg.keyboard_layout,
            color_depth: crate::experience::valid_color_depth(cfg.color_depth),
            fb: Framebuffer::new(demand.width as usize, demand.height as usize),
            fastpath: Reassembler::default(),
            bulk: Decompressor::new(cfg.compression),
            info: ConnectionInfo {
                protocol,
                certificate_sha256,
                gateway_certificate_sha256,
                server_rdp_version: server.version,
                width: demand.width,
                height: demand.height,
                bpp: demand.bpp,
            },
            active: false,
            last_error_info: 0,
            heartbeat: None,
            last_seen: Instant::now(),
            channels: slots,
            pointers: PointerCache::default(),
            // The server regenerates the cookie on every connect (5.5) and
            // sends the new one in the Save Session Info PDU.
            arc_cookie: None,
            gfx,
            monitor_layout: Vec::new(),
            redirection: informational,
            rail,
            message_channel: early.message_channel,
            autodetect: std::mem::take(&mut early.autodetect),
            host,
            follow: false,
            surface: cfg
                .surface_commands
                .then(crate::surfcmd::SurfaceCommands::default),
            orders: cfg
                .drawing_orders
                .then(|| Box::new(crate::orders::Orders::new(cfg.bitmap_cache_dir.as_deref()))),
        };
        // 7. Finalization; the Font Map reply is handled by the session loop.
        client.activate(&demand)?;
        for (channel, data) in early.queued {
            client.channel_data(channel, &data)?;
        }
        client.f.set_read_timeout(Duration::from_millis(2))?;
        Ok(Hop::Done(Box::new(client)))
    }

    /// The last Server Redirection PDU this connection did not follow: an
    /// informational one (LB_NOREDIRECT) or one that ended the session after
    /// activation (the channel handlers have state by then, so the caller
    /// reconnects with new ones). Put it in [`Config::redirection`].
    pub fn redirection(&self) -> Option<&Redirection> {
        self.redirection.as_ref()
    }

    fn send_data(&mut self, pdu_type2: u8, body: &[u8]) -> Result<()> {
        let pdu = pdu::share_data(self.share_id, self.user_id, pdu_type2, body);
        send_io(&mut self.f, self.user_id, self.io_channel, &pdu)
    }

    fn activate(&mut self, demand: &DemandActive) -> Result<()> {
        self.share_id = demand.share_id;
        let rail_caps = self
            .rail
            .as_ref()
            .map(|_| crate::rail::client_caps(demand.window_list.as_ref()));
        let confirm = pdu::confirm_active_with(
            demand.share_id,
            self.user_id,
            (demand.width, demand.height),
            self.keyboard_layout,
            self.color_depth,
            self.bulk.max() != Compression::Off,
            rail_caps.as_ref(),
        );
        let confirm = match &mut self.surface {
            Some(s) => {
                s.frame_ack = demand.frame_ack;
                let sets = crate::surfcmd::client_capability_sets();
                crate::surfcmd::append_capability_sets(confirm, &sets)
            }
            None => confirm,
        };
        let confirm = match &mut self.orders {
            Some(o) => {
                o.set_bpp(demand.bpp);
                crate::orders::caps::patch_confirm_active(&confirm, &o.client_caps())?
            }
            None => confirm,
        };
        send_io(&mut self.f, self.user_id, self.io_channel, &confirm)?;
        self.send_data(pdu::PDUTYPE2_SYNCHRONIZE, &pdu::synchronize())?;
        self.send_data(
            pdu::PDUTYPE2_CONTROL,
            &pdu::control(pdu::CTRLACTION_COOPERATE),
        )?;
        self.send_data(
            pdu::PDUTYPE2_CONTROL,
            &pdu::control(pdu::CTRLACTION_REQUEST_CONTROL),
        )?;
        // Persistent Key List PDUs (2.2.1.17), first activation only.
        let key_lists = self
            .orders
            .as_mut()
            .map(|o| o.persistent_key_lists(demand.bitmap_cache_host))
            .unwrap_or_default();
        for body in key_lists {
            let ty = crate::orders::persist::PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST;
            self.send_data(ty, &body)?;
        }
        self.send_data(pdu::PDUTYPE2_FONTLIST, &pdu::font_list())
    }

    /// The server's monitor layout (MS-RDPBCGR 2.2.12.1) in primary-relative
    /// coordinates; empty until the server sends one.
    pub fn monitor_layout(&self) -> &[crate::Monitor] {
        &self.monitor_layout
    }

    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    pub fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }

    /// True once the server has finished connection finalization (Font Map received).
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Processes server traffic for up to `budget`.
    pub fn poll(&mut self, budget: Duration) -> Result<PollOutcome> {
        let mut out = PollOutcome::default();
        let end = Instant::now() + budget;
        loop {
            match self.f.read_frame(None) {
                Ok(Some(Frame::X224(v))) => {
                    self.last_seen = Instant::now();
                    self.autodetect.received(v.len());
                    self.handle_x224(&v, &mut out)?
                }
                Ok(Some(Frame::FastPath(v))) => {
                    self.last_seen = Instant::now();
                    self.autodetect.received(v.len());
                    self.handle_fastpath(&v, &mut out)?
                }
                Ok(None) => {
                    if let Some(limit) = self.heartbeat.and_then(silence_limit)
                        && self.last_seen.elapsed() > limit
                    {
                        let text = format!(
                            "no data from the server for {} s (heartbeat missed)",
                            limit.as_secs()
                        );
                        out.closed = Some(close_reason(CloseCause::Transport(&text), 0));
                        return Ok(out);
                    }
                }
                Err(Error::ConnectionLost(m)) => {
                    out.closed = Some(close_reason(
                        CloseCause::Transport(&m),
                        self.last_error_info,
                    ));
                    return Ok(out);
                }
                Err(Error::Disconnected(m)) => {
                    out.closed = Some(close_reason(
                        CloseCause::Ultimatum(&m),
                        self.last_error_info,
                    ));
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
            self.present_gfx(&mut out);
            if let Some(rail) = &self.rail {
                out.rail.extend(rail.take_events());
            }
            if self.active {
                self.tick_channels()?;
            }
            if out.closed.is_some() || Instant::now() >= end {
                return Ok(out);
            }
        }
    }

    /// Copies finished graphics pipeline frames into the framebuffer.
    fn present_gfx(&mut self, out: &mut PollOutcome) {
        let Some(gfx) = &self.gfx else { return };
        let before = out.damage.len();
        if gfx.present(&mut self.fb, &mut out.damage) {
            out.resized = true;
            self.info.width = self.fb.width as u16;
            self.info.height = self.fb.height as u16;
        }
        out.updated |= out.damage.len() > before;
    }

    /// The latest auto-reconnect cookie from the server (MS-RDPBCGR 2.2.4.2),
    /// for [`Config::auto_reconnect`] after a network drop. The server
    /// replaces it at least hourly (5.5); always use the newest one.
    pub fn auto_reconnect_cookie(&self) -> Option<AutoReconnectCookie> {
        self.arc_cookie.clone()
    }

    /// Handles a Save Session Info PDU (2.2.10.1). A malformed one is traced
    /// and dropped; it never ends the session.
    fn save_session_info(&mut self, payload: &[u8]) {
        match pdu::parse_save_session_info(payload) {
            Ok(SaveSessionInfo::Extended { cookie, errors }) => {
                if let Some(c) = cookie {
                    // Logs the session id only, never the random bits.
                    trace!("auto-reconnect cookie for logon id {}", c.logon_id);
                    self.arc_cookie = Some(c);
                }
                if let Some(e) = errors {
                    trace!(
                        "logon notification {:#x}, data {:#x}",
                        e.notification_type, e.notification_data
                    );
                }
            }
            Ok(info) => trace!("logon notification: {info:?}"),
            Err(e) => trace!("save session info ignored: {e}"),
        }
    }

    fn handle_x224(&mut self, frame: &[u8], out: &mut PollOutcome) -> Result<()> {
        let payload = x224::data_payload(frame)?;
        match mcs::parse_domain_pdu(payload)? {
            DomainPdu::SendDataIndication { channel, data } if channel == self.io_channel => {
                if let Some(hb) = pdu::parse_heartbeat(data) {
                    if self.heartbeat != Some(hb) {
                        trace!("server heartbeat: {hb:?}");
                    }
                    self.heartbeat = Some(hb);
                    return Ok(());
                }
                let data = data.to_vec();
                self.handle_share(&data, out)
            }
            DomainPdu::SendDataIndication { channel, data }
                if Some(channel) == self.message_channel =>
            {
                let data = data.to_vec();
                self.message_channel_pdu(channel, &data, out)
            }
            DomainPdu::SendDataIndication { channel, data } => {
                let data = data.to_vec();
                self.channel_data(channel, &data)
            }
            DomainPdu::DisconnectProviderUltimatum { reason } => {
                let text = format!("server disconnected (MCS reason {reason})");
                out.closed = Some(close_reason(
                    CloseCause::Ultimatum(&text),
                    self.last_error_info,
                ));
                Ok(())
            }
            DomainPdu::Other(_) => Ok(()),
        }
    }

    /// A message channel PDU after activation (2.2.1.4.5): a heartbeat
    /// (2.2.16.1) or an auto-detect request (2.2.14.3), answered on the same
    /// channel. Anything else there is ignored.
    fn message_channel_pdu(
        &mut self,
        channel: u16,
        data: &[u8],
        out: &mut PollOutcome,
    ) -> Result<()> {
        if let Some(hb) = pdu::parse_heartbeat(data) {
            if self.heartbeat != Some(hb) {
                trace!("server heartbeat: {hb:?}");
            }
            self.heartbeat = Some(hb);
            return Ok(());
        }
        if let Some(rsp) = self.autodetect.on_pdu(data, Instant::now()) {
            send_io(&mut self.f, self.user_id, channel, &rsp)?;
        }
        if let Some(n) = self.autodetect.take_update() {
            out.network = Some(n);
        }
        Ok(())
    }

    fn handle_share(&mut self, data: &[u8], out: &mut PollOutcome) -> Result<()> {
        for (ty, body) in pdu::split_share_control(data)? {
            if !self.active {
                let ty2 = if ty == pdu::PDUTYPE_DATA {
                    body.get(8).copied()
                } else {
                    None
                };
                trace!("received share PDU type {ty} (data type {ty2:?})");
            }
            match ty {
                pdu::PDUTYPE_DEMANDACTIVE => {
                    let demand = pdu::parse_demand_active(body)?;
                    trace!("reactivation: {demand:?}");
                    if demand.width != self.info.width || demand.height != self.info.height {
                        self.fb
                            .resize(demand.width as usize, demand.height as usize);
                        out.resized = true;
                    }
                    self.info.width = demand.width;
                    self.info.height = demand.height;
                    self.info.bpp = demand.bpp;
                    self.active = false;
                    self.activate(&demand)?;
                }
                pdu::PDUTYPE_DEACTIVATEALL => {
                    trace!("deactivate all");
                    self.active = false;
                }
                pdu::PDUTYPE_DATA => self.handle_data(body, out)?,
                redirect::PDUTYPE_SERVER_REDIR_PKT => match Redirection::parse_enhanced(body) {
                    Ok(to) => {
                        let follow = !to.no_redirect();
                        trace!("{}", to.hop_trace(1));
                        self.redirection = Some(to);
                        self.follow = follow;
                        if follow {
                            let text = "the server redirected the session to another server";
                            let cause = CloseCause::Ultimatum(text);
                            out.closed = Some(close_reason(cause, self.last_error_info));
                        }
                    }
                    Err(e) => trace!("server redirection PDU ignored: {e}"),
                },
                _ => {}
            }
        }
        Ok(())
    }

    fn handle_data(&mut self, body: &[u8], out: &mut PollOutcome) -> Result<()> {
        let (ty, payload) = pdu::parse_share_data(body)?;
        let compressed_type = body.get(9).copied().unwrap_or(0);
        let payload = self.bulk.decompress(payload, compressed_type)?;
        let payload = &payload[..];
        match ty {
            pdu::PDUTYPE2_UPDATE if crate::cursor::le16(payload, 0) == Some(0) => {
                // UPDATETYPE_ORDERS (MS-RDPEGDI 2.2.2.1): drawing orders and
                // RemoteApp window orders.
                let orders = match self.orders.as_mut() {
                    Some(o) => o.slowpath(payload, &mut self.fb, &mut out.damage),
                    None => crate::rail::orders::parse_slowpath_orders(payload),
                };
                out.updated |= !out.damage.is_empty();
                self.window_orders(orders);
            }
            pdu::PDUTYPE2_UPDATE => {
                codec::draw_bitmap_update(payload, &mut self.fb, &mut out.damage)?;
                out.updated |= !out.damage.is_empty();
            }
            pdu::PDUTYPE2_POINTER => match self.pointers.slow_path(payload) {
                Ok(Some(p)) => out.pointer = Some(p),
                Ok(None) => {}
                Err(e) => trace!("pointer PDU ignored: {e}"),
            },
            pdu::PDUTYPE2_FONTMAP => {
                trace!("connection finalized");
                self.active = true;
            }
            pdu::PDUTYPE2_SET_ERROR_INFO => {
                let code = crate::cursor::le32(payload, 0).unwrap_or(0);
                if code != 0 {
                    trace!("error info {code:#x}: {}", pdu::error_info_name(code));
                    self.last_error_info = code;
                }
            }
            pdu::PDUTYPE2_SAVE_SESSION_INFO => self.save_session_info(payload),
            // 2.2.4.1.1: the server did not accept our cookie and falls back to
            // the Client Info credentials (3.3.5.3.11).
            pdu::PDUTYPE2_ARC_STATUS_PDU => trace!("server rejected the auto-reconnect cookie"),
            pdu::PDUTYPE2_SHUTDOWN_DENIED => trace!("shutdown denied"),
            // A bad layout is traced and dropped; it never ends the session.
            crate::monitor::PDUTYPE2_MONITOR_LAYOUT_PDU => {
                match crate::monitor::parse_monitor_layout(payload) {
                    Ok(m) => {
                        trace!("server monitor layout: {m:?}");
                        self.monitor_layout = m.clone();
                        out.monitors = Some(m);
                    }
                    Err(e) => trace!("monitor layout PDU ignored: {e}"),
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_fastpath(&mut self, frame: &[u8], out: &mut PollOutcome) -> Result<()> {
        for (code, data) in self.fastpath.feed(frame, &mut self.bulk)? {
            match code {
                fastpath::UPDATETYPE_BITMAP => {
                    codec::draw_bitmap_update(&data, &mut self.fb, &mut out.damage)?;
                    out.updated |= !out.damage.is_empty();
                }
                fastpath::UPDATETYPE_ORDERS => {
                    let orders = match self.orders.as_mut() {
                        Some(o) => o.fastpath(&data, &mut self.fb, &mut out.damage),
                        None => crate::rail::orders::parse_fastpath_orders(&data),
                    };
                    out.updated |= !out.damage.is_empty();
                    self.window_orders(orders)
                }
                crate::surfcmd::UPDATETYPE_SURFCMDS => self.surface_commands(&data, out)?,
                0x5..=0xC => match self.pointers.fast_path(code, &data) {
                    Ok(Some(p)) => out.pointer = Some(p),
                    Ok(None) => {}
                    // A bad cursor shape must never end the session.
                    Err(e) => trace!("pointer update {code:#x} ignored: {e}"),
                },
                _ => {} // pointer, palette, synchronize
            }
        }
        Ok(())
    }

    /// Draws a surface commands update (MS-RDPBCGR 2.2.9.1.2.1.10) and
    /// acknowledges finished frames (MS-RDPRFX 2.2.3.1). A bad update is
    /// traced and dropped; it never ends the session.
    fn surface_commands(&mut self, data: &[u8], out: &mut PollOutcome) -> Result<()> {
        let Some(s) = &mut self.surface else {
            trace!("surface commands not negotiated, update ignored");
            return Ok(());
        };
        let before = out.damage.len();
        let acks = match s.apply(data, &mut self.fb, &mut out.damage) {
            Ok(acks) => acks,
            Err(e) => {
                trace!("surface commands update ignored: {e}");
                Vec::new()
            }
        };
        out.updated |= out.damage.len() > before;
        for id in acks {
            let body = crate::surfcmd::frame_acknowledge(id);
            self.send_data(crate::surfcmd::PDUTYPE2_FRAME_ACKNOWLEDGE, &body)?;
        }
        Ok(())
    }

    /// Applies RemoteApp window orders (MS-RDPERP 2.2.1.3); other drawing
    /// orders are not negotiated and are dropped. Bad orders never end the session.
    fn window_orders(&mut self, orders: Result<Vec<crate::rail::orders::WindowOrder>>) {
        match (orders, &self.rail) {
            (Ok(o), Some(rail)) => rail.apply_orders(o),
            (Ok(o), None) => trace!("{} window orders ignored (not RemoteApp)", o.len()),
            (Err(e), _) => trace!("orders update ignored: {e}"),
        }
    }

    /// The RemoteApp window model and actions, when [`Config::remote_app`] is set.
    pub fn rail(&self) -> Option<crate::RailHandle> {
        self.rail.clone()
    }

    /// Routes one virtual channel chunk to its handler and sends the replies.
    fn channel_data(&mut self, channel: u16, chunk: &[u8]) -> Result<()> {
        let Some(i) = self.channels.iter().position(|s| s.id == channel) else {
            trace!("data on unknown channel {channel}");
            return Ok(());
        };
        let slot = &mut self.channels[i];
        if slot.failed {
            return Ok(());
        }
        let msg = match slot.defrag.feed(chunk, &mut self.bulk) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(()),
            Err(e) => {
                trace!("channel {}: {e}; channel disabled", slot.handler.name());
                slot.failed = true;
                return Ok(());
            }
        };
        // The first four bytes are each channel's message header (type and
        // flags or component and packet id); never payload data.
        let head: String = msg.iter().take(4).map(|b| format!("{b:02x}")).collect();
        trace!(
            "channel {}: message of {} bytes, header {head}",
            slot.handler.name(),
            msg.len()
        );
        let mut out = ChannelOut::default();
        if let Err(e) = slot.handler.process(&msg, &mut out) {
            // A broken channel must never end the session.
            trace!("channel {}: {e}; channel disabled", slot.handler.name());
            slot.failed = true;
        }
        self.flush_channel(i, out)
    }

    fn tick_channels(&mut self) -> Result<()> {
        for i in 0..self.channels.len() {
            let slot = &mut self.channels[i];
            if slot.failed {
                continue;
            }
            let mut out = ChannelOut::default();
            if let Err(e) = slot.handler.tick(&mut out) {
                trace!("channel {}: {e}; channel disabled", slot.handler.name());
                slot.failed = true;
            }
            self.flush_channel(i, out)?;
        }
        Ok(())
    }

    fn flush_channel(&mut self, i: usize, mut out: ChannelOut) -> Result<()> {
        for msg in out.take() {
            send_channel(&mut self.f, self.user_id, &self.channels[i], &msg)?;
        }
        Ok(())
    }

    /// Names of the virtual channels the server accepted.
    pub fn channel_names(&self) -> Vec<String> {
        self.channels
            .iter()
            .map(|s| s.handler.name().to_string())
            .collect()
    }

    /// Sends input once the session is active; before that the server rejects
    /// input as out of sequence, so events are dropped.
    pub fn send_input(&mut self, events: &[InputEvent]) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        for chunk in events.chunks(15) {
            self.f.write(&fastpath_input(chunk))?;
        }
        Ok(())
    }

    /// Asks the server to resend the whole screen.
    pub fn request_refresh(&mut self) -> Result<()> {
        if self.info.width == 0 || self.info.height == 0 {
            return proto("no desktop yet");
        }
        let body = pdu::refresh_rect(self.info.width, self.info.height);
        self.send_data(pdu::PDUTYPE2_REFRESH_RECT, &body)
    }

    /// Sends MCS Disconnect Provider Ultimatum; the session stays logged on.
    pub fn disconnect(mut self) {
        let _ = self
            .f
            .write(&x224::data(&mcs::disconnect_provider_ultimatum()));
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
