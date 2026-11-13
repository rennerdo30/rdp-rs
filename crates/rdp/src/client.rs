//! Connection sequence (MS-RDPBCGR 1.3.1.1) and the session loop.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::channel::{self, ChannelOut, Slot, StaticChannel};
use crate::codec;
use crate::credssp;
use crate::crypto::sha256;
use crate::der;
use crate::error::{Error, Result, proto};
use crate::fastpath::{self, Reassembler};
use crate::framebuffer::{Damage, Framebuffer};
use crate::gcc;
use crate::input::{InputEvent, fastpath_input};
use crate::mcs::{self, DomainPdu};
use crate::pdu::{self, DemandActive};
use crate::pointer::{PointerCache, PointerUpdate};
use crate::trace;
use crate::transport::{Frame, Framer};
use crate::x224;

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
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub protocol: u32,
    pub certificate_sha256: [u8; 32],
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
    /// The server ended the session.
    pub closed: Option<String>,
    /// The latest cursor change during this poll.
    pub pointer: Option<PointerUpdate>,
}

pub struct Client {
    f: Framer,
    user_id: u16,
    io_channel: u16,
    share_id: u32,
    keyboard_layout: u32,
    fb: Framebuffer,
    fastpath: Reassembler,
    info: ConnectionInfo,
    active: bool,
    last_error_info: u32,
    channels: Vec<Slot>,
    pointers: PointerCache,
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
/// its channel once the session exists.
fn read_io(
    f: &mut Framer,
    io: u16,
    deadline: Instant,
    early: &mut Vec<(u16, Vec<u8>)>,
) -> Result<Vec<u8>> {
    loop {
        let payload = read_mcs(f, deadline)?;
        match mcs::parse_domain_pdu(&payload)? {
            DomainPdu::SendDataIndication { channel, data } if channel == io => {
                return Ok(data.to_vec());
            }
            DomainPdu::SendDataIndication { channel, data } => {
                trace!(
                    "channel {channel}: {} bytes before activation, queued",
                    data.len()
                );
                early.push((channel, data.to_vec()));
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

fn split_user(cfg: &Config) -> (String, String) {
    if cfg.domain.is_empty()
        && let Some((d, u)) = cfg.username.split_once('\\')
    {
        return (u.to_string(), d.to_string());
    }
    (cfg.username.clone(), cfg.domain.clone())
}

impl Client {
    /// Connects without virtual channels.
    pub fn connect(cfg: &Config) -> Result<Client> {
        Self::connect_with(cfg, Vec::new())
    }

    /// Connects and opens the given static virtual channels.
    pub fn connect_with(cfg: &Config, handlers: Vec<Box<dyn StaticChannel>>) -> Result<Client> {
        let deadline = Instant::now() + cfg.timeout;
        let (user, domain) = split_user(cfg);

        let addr = (cfg.host.as_str(), cfg.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::Protocol(format!("cannot resolve {}", cfg.host)))?;
        let sock = TcpStream::connect_timeout(&addr, cfg.timeout)?;
        sock.set_nodelay(true)?;
        let mut f = Framer::new(sock);
        f.set_read_timeout(Duration::from_millis(100))?;

        // 1. X.224 negotiation
        let cookie: String = user.chars().take(9).collect();
        let requested = x224::PROTOCOL_SSL | x224::PROTOCOL_HYBRID | x224::PROTOCOL_HYBRID_EX;
        f.write(&x224::connection_request(&cookie, requested))?;
        let protocol = x224::parse_connection_confirm(&read_x224(&mut f, deadline)?)?;
        trace!("negotiated protocol {protocol:#x}");
        if protocol & requested == 0 {
            return Err(Error::Unsupported(
                "server only offers legacy RDP security (no TLS)".into(),
            ));
        }

        // 2. TLS, then NLA
        let cert = f.upgrade_tls(&cfg.host, deadline)?;
        let certificate_sha256 = sha256(&cert);
        if protocol & (x224::PROTOCOL_HYBRID | x224::PROTOCOL_HYBRID_EX) != 0 {
            let public_key = der::subject_public_key(&cert)?;
            credssp::authenticate(
                &mut f,
                &public_key,
                &user,
                &domain,
                &cfg.password,
                &cfg.client_name,
                deadline,
            )?;
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
        let settings = gcc::ClientSettings {
            width: cfg.width,
            height: cfg.height,
            keyboard_layout: cfg.keyboard_layout,
            client_name: &cfg.client_name,
            selected_protocol: protocol,
            scale: cfg.scale,
            channels: &def_refs,
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
        channels.extend(&server.channel_ids);
        for ch in channels {
            f.write(&x224::data(&mcs::channel_join_request(user_id, ch)))?;
            let joined = mcs::parse_channel_join_confirm(&read_mcs(&mut f, deadline)?)?;
            trace!("joined channel {joined}");
        }
        let io = server.io_channel;
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

        // 5. Client info and licensing
        let mut early = Vec::new();
        let info_pdu = pdu::client_info(&pdu::ClientInfo {
            domain: &domain,
            user: &user,
            password: &cfg.password,
        });
        send_io(&mut f, user_id, io, &info_pdu)?;
        // With TLS the server answers with one "valid client" licensing PDU.
        let mut pending = None;
        let data = read_io(&mut f, io, deadline, &mut early)?;
        if pdu::looks_like_share_control(&data) {
            pending = Some(data); // server skipped licensing
        } else {
            pdu::process_license(&data)?;
        }

        // 6. Capability exchange
        let demand = loop {
            let data = match pending.take() {
                Some(d) => d,
                None => read_io(&mut f, io, deadline, &mut early)?,
            };
            let parts = pdu::split_share_control(&data)?;
            if let Some((_, body)) = parts.iter().find(|(t, _)| *t == pdu::PDUTYPE_DEMANDACTIVE) {
                break pdu::parse_demand_active(body)?;
            }
            trace!("ignoring PDU while waiting for Demand Active");
        };
        trace!("demand active: {demand:?}");

        let mut client = Client {
            f,
            user_id,
            io_channel: io,
            share_id: demand.share_id,
            keyboard_layout: cfg.keyboard_layout,
            fb: Framebuffer::new(demand.width as usize, demand.height as usize),
            fastpath: Reassembler::default(),
            info: ConnectionInfo {
                protocol,
                certificate_sha256,
                server_rdp_version: server.version,
                width: demand.width,
                height: demand.height,
                bpp: demand.bpp,
            },
            active: false,
            last_error_info: 0,
            channels: slots,
            pointers: PointerCache::default(),
        };
        // 7. Finalization; the Font Map reply is handled by the session loop.
        client.activate(&demand)?;
        for (channel, data) in early {
            client.channel_data(channel, &data)?;
        }
        client.f.set_read_timeout(Duration::from_millis(2))?;
        Ok(client)
    }

    fn send_data(&mut self, pdu_type2: u8, body: &[u8]) -> Result<()> {
        let pdu = pdu::share_data(self.share_id, self.user_id, pdu_type2, body);
        send_io(&mut self.f, self.user_id, self.io_channel, &pdu)
    }

    fn activate(&mut self, demand: &DemandActive) -> Result<()> {
        self.share_id = demand.share_id;
        let confirm = pdu::confirm_active(
            demand.share_id,
            self.user_id,
            demand.width,
            demand.height,
            self.keyboard_layout,
        );
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
        self.send_data(pdu::PDUTYPE2_FONTLIST, &pdu::font_list())
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
                Ok(Some(Frame::X224(v))) => self.handle_x224(&v, &mut out)?,
                Ok(Some(Frame::FastPath(v))) => self.handle_fastpath(&v, &mut out)?,
                Ok(None) => {}
                Err(Error::Disconnected(m)) => {
                    out.closed = Some(self.close_reason(&m));
                    return Ok(out);
                }
                Err(e) => return Err(e),
            }
            if self.active {
                self.tick_channels()?;
            }
            if out.closed.is_some() || Instant::now() >= end {
                return Ok(out);
            }
        }
    }

    fn close_reason(&self, transport: &str) -> String {
        if self.last_error_info != 0 {
            format!(
                "{} (error info {:#x}: {})",
                transport,
                self.last_error_info,
                pdu::error_info_name(self.last_error_info)
            )
        } else {
            transport.to_string()
        }
    }

    fn handle_x224(&mut self, frame: &[u8], out: &mut PollOutcome) -> Result<()> {
        let payload = x224::data_payload(frame)?;
        match mcs::parse_domain_pdu(payload)? {
            DomainPdu::SendDataIndication { channel, data } if channel == self.io_channel => {
                let data = data.to_vec();
                self.handle_share(&data, out)
            }
            DomainPdu::SendDataIndication { channel, data } => {
                let data = data.to_vec();
                self.channel_data(channel, &data)
            }
            DomainPdu::DisconnectProviderUltimatum { reason } => {
                out.closed =
                    Some(self.close_reason(&format!("server disconnected (MCS reason {reason})")));
                Ok(())
            }
            DomainPdu::Other(_) => Ok(()),
        }
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
                _ => {}
            }
        }
        Ok(())
    }

    fn handle_data(&mut self, body: &[u8], out: &mut PollOutcome) -> Result<()> {
        let (ty, payload) = pdu::parse_share_data(body)?;
        match ty {
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
            pdu::PDUTYPE2_SAVE_SESSION_INFO => trace!("logon notification"),
            pdu::PDUTYPE2_SHUTDOWN_DENIED => trace!("shutdown denied"),
            _ => {}
        }
        Ok(())
    }

    fn handle_fastpath(&mut self, frame: &[u8], out: &mut PollOutcome) -> Result<()> {
        for (code, data) in self.fastpath.feed(frame)? {
            match code {
                fastpath::UPDATETYPE_BITMAP => {
                    codec::draw_bitmap_update(&data, &mut self.fb, &mut out.damage)?;
                    out.updated |= !out.damage.is_empty();
                }
                fastpath::UPDATETYPE_ORDERS => trace!("drawing orders ignored (not negotiated)"),
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
        let msg = match slot.defrag.feed(chunk) {
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
