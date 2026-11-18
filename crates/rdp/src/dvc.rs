//! Dynamic virtual channels, client side (MS-RDPEDYC).
//!
//! [`Drdynvc`] is the `drdynvc` static channel handler. It answers the
//! server's capabilities request, accepts or refuses channel creation by name,
//! reassembles fragmented data, fragments outgoing messages and handles close.
//! Each dynamic channel implements [`DynamicChannel`] and sees complete
//! messages only.
//!
//! Every PDU starts with one header byte (MS-RDPEDYC 2.2): `cbId` in bits 0-1
//! (size of the ChannelId field), `Sp` in bits 2-3 (command specific) and
//! `Cmd` in bits 4-7. Field sizes 0, 1, 2 mean 1, 2, 4 bytes.
//!
//! Not supported: compressed data (MS-RDPEDYC 2.2.3.3, 2.2.3.4) closes the
//! channel it arrives on.
//!
//! Multitransport (MS-RDPEDYC 1.3.1.2, 3.1.5.3): DVC PDUs may also travel in
//! a UDP tunnel ([`crate::multitransport`]); [`Drdynvc::process_tunnel`]
//! takes them, and what goes back on the tunnel is collected for
//! [`Drdynvc::take_tunnel_out`]. A channel the server creates over the
//! tunnel, or names in a Soft-Sync Request (2.2.5.1), sends on the tunnel
//! from then on; every other channel keeps the static channel. Tunnel data
//! that arrives before the Soft-Sync Request waits for it (3.2.5.3.1).
//!
//! Limits: a message is at most [`DynamicChannel::max_message_size`] bytes
//! ([`DEFAULT_MAX_MESSAGE`] unless the channel says otherwise); a larger
//! DYNVC_DATA_FIRST announcement or a larger unfragmented DYNVC_DATA closes
//! that channel, never the session. Messages a failing handler queued are
//! sent before the channel's DYNVC_CLOSE. A second DYNVC_CREATE_REQ for a name that is
//! already open replaces the first binding unless the channel refuses it
//! ([`DynamicChannel::allow_second_instance`]).

use crate::channel::{
    CHANNEL_OPTION_ENCRYPT_RDP, CHANNEL_OPTION_INITIALIZED, ChannelOut, StaticChannel,
};
use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};
use crate::trace;

/// Static channel name of the dynamic virtual channel transport.
pub const DRDYNVC: &str = "drdynvc";

/// DYNVC_CREATE_REQ / DYNVC_CREATE_RSP (MS-RDPEDYC 2.2.2.1, 2.2.2.2).
pub const CMD_CREATE: u8 = 0x01;
/// DYNVC_DATA_FIRST (MS-RDPEDYC 2.2.3.1).
pub const CMD_DATA_FIRST: u8 = 0x02;
/// DYNVC_DATA (MS-RDPEDYC 2.2.3.2).
pub const CMD_DATA: u8 = 0x03;
/// DYNVC_CLOSE (MS-RDPEDYC 2.2.4).
pub const CMD_CLOSE: u8 = 0x04;
/// DYNVC_CAPS_VERSION1/2/3 and DYNVC_CAPS_RSP (MS-RDPEDYC 2.2.1.1, 2.2.1.2).
pub const CMD_CAPS: u8 = 0x05;
/// DYNVC_DATA_FIRST_COMPRESSED (MS-RDPEDYC 2.2.3.3).
pub const CMD_DATA_FIRST_COMPRESSED: u8 = 0x06;
/// DYNVC_DATA_COMPRESSED (MS-RDPEDYC 2.2.3.4).
pub const CMD_DATA_COMPRESSED: u8 = 0x07;
/// DYNVC_SOFT_SYNC_REQUEST (MS-RDPEDYC 2.2.5.1).
pub const CMD_SOFT_SYNC_REQUEST: u8 = 0x08;
/// DYNVC_SOFT_SYNC_RESPONSE (MS-RDPEDYC 2.2.5.2).
pub const CMD_SOFT_SYNC_RESPONSE: u8 = 0x09;

/// Soft-Sync Request Flags (MS-RDPEDYC 2.2.5.1).
pub const SOFT_SYNC_TCP_FLUSHED: u16 = 0x01;
pub const SOFT_SYNC_CHANNEL_LIST_PRESENT: u16 = 0x02;
/// TunnelType values (MS-RDPEDYC 2.2.5.1.1, 2.2.5.2).
pub const TUNNELTYPE_UDPFECR: u32 = 0x01;
pub const TUNNELTYPE_UDPFECL: u32 = 0x03;

/// Tunnel PDUs kept while waiting for the Soft-Sync Request; more means
/// the server is not doing Soft-Sync, and they are dropped.
const MAX_HELD: usize = 4096;

/// CreationStatus for a channel name the client does not know (an NTSTATUS
/// carried as HRESULT, MS-RDPEDYC 2.2.2.2).
pub const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// CreationStatus for a create the client refuses: E_ACCESSDENIED (a
/// negative HRESULT means failure, MS-RDPEDYC 2.2.2.2).
pub const STATUS_REFUSED: u32 = 0x8007_0005;

/// Default cap on one reassembled message (the DYNVC_DATA_FIRST Length).
pub const DEFAULT_MAX_MESSAGE: usize = 16 << 20;

/// Highest DVC protocol version the client speaks (MS-RDPEDYC 2.2.1.2).
pub const MAX_VERSION: u16 = 3;

/// Largest DVC PDU the client sends, header included (MS-RDPEDYC 3.1.5.1.4:
/// data PDUs are at most 1,600 bytes).
pub const MAX_PDU: usize = 1600;

/// Complete messages a dynamic channel wants sent, in order.
#[derive(Default)]
pub struct DvcOut {
    msgs: Vec<Vec<u8>>,
}

impl DvcOut {
    pub fn send(&mut self, msg: Vec<u8>) {
        self.msgs.push(msg);
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.msgs)
    }
}

/// One dynamic virtual channel (for example
/// `Microsoft::Windows::RDS::DisplayControl`). Runs on the session worker
/// thread inside [`Drdynvc`].
pub trait DynamicChannel: Send {
    /// Channel name the server asks for in DYNVC_CREATE_REQ.
    fn name(&self) -> &str;

    /// The server opened the channel; the Create Response is already queued.
    fn opened(&mut self, _out: &mut DvcOut) -> Result<()> {
        Ok(())
    }

    /// One complete (reassembled) message from the server.
    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()>;

    /// Called on every session poll while the channel is open. Keep it cheap.
    fn tick(&mut self, _out: &mut DvcOut) -> Result<()> {
        Ok(())
    }

    /// The channel was closed by the server or after an error.
    fn closed(&mut self) {}

    /// Largest reassembled message this channel accepts. A DYNVC_DATA_FIRST
    /// announcing more closes the channel.
    fn max_message_size(&self) -> usize {
        DEFAULT_MAX_MESSAGE
    }

    /// The server asks to open this channel again while it is open (a
    /// second server-side instance). `true` (the default) closes the open
    /// binding and binds the new one; `false` refuses the new one with
    /// [`STATUS_REFUSED`] and keeps the open one.
    fn allow_second_instance(&mut self) -> bool {
        true
    }

    /// The client is about to close the channel on its own for `why`;
    /// [`Self::closed`] follows.
    fn closing(&mut self, _why: LocalClose) {}
}

/// Why the client closed a dynamic channel on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalClose {
    /// The server sent compressed data (not supported).
    Compressed,
    /// A message larger than [`DynamicChannel::max_message_size`].
    TooLarge,
    /// Fragments that do not add up to the announced length.
    Malformed,
    /// The channel handler returned an error.
    HandlerError,
}

/// Reassembly of DYNVC_DATA_FIRST + DYNVC_DATA (MS-RDPEDYC 3.1.5.2.2).
struct Reassembly {
    total: usize,
    buf: Vec<u8>,
}

struct Dvc {
    handler: Box<dyn DynamicChannel>,
    /// ChannelId while open.
    id: Option<u32>,
    reasm: Option<Reassembly>,
    /// Sends on the UDP tunnel instead of the static channel.
    udp: bool,
}

/// The `drdynvc` static channel: client side of MS-RDPEDYC.
pub struct Drdynvc {
    channels: Vec<Dvc>,
    /// Negotiated version, 0 before the capabilities exchange.
    version: u16,
    /// Reused per call so an idle tick does not allocate.
    out: DvcOut,
    /// A UDP tunnel is up and the server was told (Initiate Multitransport
    /// Response, S_OK): a Soft-Sync Request may be answered.
    tunnel_ready: bool,
    /// The Soft-Sync Request arrived and was answered.
    soft_synced: bool,
    /// The PDU being handled came from the tunnel.
    from_tunnel: bool,
    /// PDUs for the tunnel.
    tunnel_out: ChannelOut,
    /// Tunnel PDUs that came before the Soft-Sync Request.
    held: Vec<Vec<u8>>,
}

impl Drdynvc {
    pub fn new(channels: Vec<Box<dyn DynamicChannel>>) -> Drdynvc {
        Drdynvc {
            channels: channels
                .into_iter()
                .map(|handler| Dvc {
                    handler,
                    id: None,
                    reasm: None,
                    udp: false,
                })
                .collect(),
            version: 0,
            out: DvcOut::default(),
            tunnel_ready: false,
            soft_synced: false,
            from_tunnel: false,
            tunnel_out: ChannelOut::default(),
            held: Vec::new(),
        }
    }

    /// Adds a dynamic channel before the connection starts.
    pub fn add(&mut self, handler: Box<dyn DynamicChannel>) {
        self.channels.push(Dvc {
            handler,
            id: None,
            reasm: None,
            udp: false,
        });
    }

    /// The UDP tunnel is ready and the server knows it: Soft-Sync may move
    /// channels onto it (MS-RDPEDYC 3.1.5.3).
    pub fn set_tunnel_ready(&mut self) {
        self.tunnel_ready = true;
    }

    /// Open channels that send on the UDP tunnel.
    pub fn channels_on_tunnel(&self) -> usize {
        self.channels
            .iter()
            .filter(|d| d.udp && d.id.is_some())
            .count()
    }

    /// One DVC PDU from a Tunnel Data PDU (MS-RDPEMT 2.2.2.3). Replies for
    /// the static channel go to `out`, those for the tunnel to
    /// [`Self::take_tunnel_out`].
    pub fn process_tunnel(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        if !self.soft_synced {
            if self.held.len() < MAX_HELD {
                self.held.push(msg.to_vec());
            } else {
                trace!("dvc tunnel data before Soft-Sync dropped");
            }
            return Ok(());
        }
        self.from_tunnel = true;
        let r = self.handle(msg, out);
        self.from_tunnel = false;
        r
    }

    /// DVC PDUs to send in Tunnel Data PDUs, in order.
    pub fn take_tunnel_out(&mut self) -> Vec<Vec<u8>> {
        self.tunnel_out.take()
    }

    /// DYNVC_SOFT_SYNC_REQUEST (MS-RDPEDYC 2.2.5.1, 3.2.5.3): the listed
    /// channels move to the tunnel, the response goes out on the static
    /// channel (2.2.5.2), then held tunnel PDUs are handled.
    fn soft_sync(&mut self, r: &mut Reader, out: &mut ChannelOut) -> Result<()> {
        if self.from_tunnel {
            trace!("dvc soft-sync request on the tunnel ignored");
            return Ok(());
        }
        if !self.tunnel_ready {
            // No response: all channel data stays on the static channel
            // (3.2.5.3.1).
            trace!("dvc soft-sync request without a UDP tunnel ignored");
            return Ok(());
        }
        r.skip(1)?; // Pad
        let _length = r.u32()?;
        let flags = r.u16()?;
        let tunnels = r.u16()?;
        if flags & SOFT_SYNC_CHANNEL_LIST_PRESENT != 0 {
            for _ in 0..tunnels {
                let ty = r.u32()?;
                let n = r.u16()?;
                for _ in 0..n {
                    let id = r.u32()?;
                    if ty != TUNNELTYPE_UDPFECR {
                        continue;
                    }
                    if let Some(i) = self.find_open(id) {
                        trace!("dvc {} moves to UDP", self.channels[i].handler.name());
                        self.channels[i].udp = true;
                    }
                }
            }
        }
        self.soft_synced = true;
        out.send(soft_sync_response(&[TUNNELTYPE_UDPFECR]));
        for msg in std::mem::take(&mut self.held) {
            self.from_tunnel = true;
            let r = self.handle(&msg, out);
            self.from_tunnel = false;
            if let Err(e) = r {
                trace!("dvc tunnel PDU: {e}");
            }
        }
        Ok(())
    }

    /// Negotiated DVC version (0 before the capabilities request).
    pub fn version(&self) -> u16 {
        self.version
    }

    fn find_open(&self, id: u32) -> Option<usize> {
        self.channels.iter().position(|d| d.id == Some(id))
    }

    /// Closes channel `i` on the client's initiative and tells the server.
    fn close_local(&mut self, i: usize, why: LocalClose, out: &mut ChannelOut) {
        if self.channels[i].id.is_some() {
            self.channels[i].handler.closing(why);
        }
        self.close(i, true, out);
    }

    /// Closes channel `i` locally; sends a DYNVC_CLOSE when `send` is set.
    fn close(&mut self, i: usize, send: bool, out: &mut ChannelOut) {
        let d = &mut self.channels[i];
        let Some(id) = d.id.take() else { return };
        d.reasm = None;
        d.handler.closed();
        let udp = std::mem::take(&mut d.udp);
        self.out.msgs.clear();
        if send {
            // On the transport the channel used (MS-RDPEDYC 1.3.3.1).
            if udp {
                self.tunnel_out.send(close_pdu(id));
            } else {
                out.send(close_pdu(id));
            }
        }
    }

    /// Sends what channel `i` queued in `self.out`, or closes the channel if
    /// the handler failed.
    fn finish(&mut self, i: usize, res: Result<()>, out: &mut ChannelOut) {
        match res {
            Ok(()) => {
                let Some(id) = self.channels[i].id else {
                    self.out.msgs.clear();
                    return;
                };
                let sink = if self.channels[i].udp {
                    &mut self.tunnel_out
                } else {
                    &mut *out
                };
                for msg in self.out.msgs.drain(..) {
                    if let Err(e) = encode_data(id, &msg, sink) {
                        trace!("dvc {id}: {e}");
                    }
                }
            }
            Err(e) => {
                trace!(
                    "dvc {}: {e}; channel closed",
                    self.channels[i].handler.name()
                );
                // What the handler queued before failing (a last error or
                // a rejection for the peer) goes out before the close.
                if let Some(id) = self.channels[i].id {
                    let sink = if self.channels[i].udp {
                        &mut self.tunnel_out
                    } else {
                        &mut *out
                    };
                    for msg in self.out.msgs.drain(..) {
                        if let Err(e) = encode_data(id, &msg, sink) {
                            trace!("dvc {id}: {e}");
                        }
                    }
                }
                self.close_local(i, LocalClose::HandlerError, out);
            }
        }
    }

    fn deliver(&mut self, i: usize, msg: &[u8], out: &mut ChannelOut) {
        let res = self.channels[i].handler.process(msg, &mut self.out);
        self.finish(i, res, out);
    }

    /// DYNVC_CREATE_REQ (MS-RDPEDYC 2.2.2.1): answer with DYNVC_CREATE_RSP.
    /// The response goes back on the transport the request came on, and a
    /// channel created over the tunnel sends on it (MS-RDPEDYC 1.3.3.1).
    fn create(&mut self, id: u32, name: &[u8], out: &mut ChannelOut) {
        let udp = self.from_tunnel;
        let found = self
            .channels
            .iter()
            .position(|d| d.handler.name().as_bytes() == name);
        let Some(i) = found else {
            trace!(
                "dvc create {:?} ({id}): not found",
                String::from_utf8_lossy(name)
            );
            let rsp = create_response(id, STATUS_NOT_FOUND);
            if udp {
                self.tunnel_out.send(rsp);
            } else {
                out.send(rsp);
            }
            return;
        };
        // A second create for a name that is already open: the channel
        // decides whether the new instance replaces the open one.
        if let Some(open) = self.channels[i].id
            && open != id
            && !self.channels[i].handler.allow_second_instance()
        {
            trace!(
                "dvc create {} ({id}): refused, already open as {open}",
                self.channels[i].handler.name()
            );
            let rsp = create_response(id, STATUS_REFUSED);
            if udp {
                self.tunnel_out.send(rsp);
            } else {
                out.send(rsp);
            }
            return;
        }
        // A channel id reused by the server, or a second create for the same
        // name, replaces the earlier binding.
        if let Some(j) = self.find_open(id) {
            self.close(j, false, out);
        }
        self.close(i, false, out);
        trace!(
            "dvc create {} ({id}){}",
            self.channels[i].handler.name(),
            if udp { " over UDP" } else { "" }
        );
        if udp {
            self.tunnel_out.send(create_response(id, 0));
        } else {
            out.send(create_response(id, 0));
        }
        self.channels[i].id = Some(id);
        self.channels[i].udp = udp;
        let res = self.channels[i].handler.opened(&mut self.out);
        self.finish(i, res, out);
    }

    fn data_first(&mut self, id: u32, total: u32, data: &[u8], out: &mut ChannelOut) {
        let Some(i) = self.find_open(id) else {
            trace!("dvc data on unknown channel {id}");
            return;
        };
        let total = total as usize;
        if data.len() > total {
            trace!("dvc {id}: DATA_FIRST carries more than its length");
            self.close_local(i, LocalClose::Malformed, out);
            return;
        }
        let cap = self.channels[i].handler.max_message_size();
        if total > cap {
            trace!("dvc {id}: message of {total} bytes over the {cap}-byte cap; channel closed");
            self.close_local(i, LocalClose::TooLarge, out);
            return;
        }
        if data.len() == total {
            self.channels[i].reasm = None;
            self.deliver(i, data, out);
            return;
        }
        let mut buf = Vec::with_capacity(total.min(64 * 1024));
        buf.extend_from_slice(data);
        self.channels[i].reasm = Some(Reassembly { total, buf });
    }

    fn data(&mut self, id: u32, data: &[u8], out: &mut ChannelOut) {
        let Some(i) = self.find_open(id) else {
            trace!("dvc data on unknown channel {id}");
            return;
        };
        let Some(mut r) = self.channels[i].reasm.take() else {
            // Unfragmented message: the same cap as a DATA_FIRST announcement.
            let cap = self.channels[i].handler.max_message_size();
            if data.len() > cap {
                trace!(
                    "dvc {id}: message of {} bytes over the {cap}-byte cap; channel closed",
                    data.len()
                );
                self.close_local(i, LocalClose::TooLarge, out);
                return;
            }
            self.deliver(i, data, out);
            return;
        };
        if r.buf.len() + data.len() > r.total {
            trace!("dvc {id}: reassembled data exceeds DATA_FIRST length");
            self.close_local(i, LocalClose::Malformed, out);
            return;
        }
        r.buf.extend_from_slice(data);
        if r.buf.len() == r.total {
            self.deliver(i, &r.buf, out);
        } else {
            self.channels[i].reasm = Some(r);
        }
    }
}

impl Drdynvc {
    /// One DVC PDU, from the static channel or (with `from_tunnel` set) the
    /// UDP tunnel.
    fn handle(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let mut r = Reader::new(msg);
        let hdr = r.u8()?;
        let cb_id = hdr & 0x03;
        let sp = (hdr >> 2) & 0x03;
        let cmd = hdr >> 4;
        match cmd {
            CMD_CAPS => {
                // DYNVC_CAPS_VERSION1/2/3 (MS-RDPEDYC 2.2.1.1.x): Pad, Version,
                // then priority charges for versions 2 and 3 (ignored).
                r.skip(1)?;
                let v = r.u16()?;
                if v == 0 {
                    return proto("dvc capabilities version 0");
                }
                self.version = v.min(MAX_VERSION);
                trace!("dvc caps: server {v}, using {}", self.version);
                out.send(caps_response(self.version));
            }
            CMD_CREATE => {
                // Sp carries the priority class in versions 2 and 3; ignored.
                let id = read_var(&mut r, cb_id)?;
                let rest = r.rest();
                let name = rest.split(|&b| b == 0).next().unwrap_or(rest);
                self.create(id, name, out);
            }
            CMD_DATA_FIRST => {
                let id = read_var(&mut r, cb_id)?;
                let total = read_var(&mut r, sp)?;
                self.data_first(id, total, r.rest(), out);
            }
            CMD_DATA => {
                let id = read_var(&mut r, cb_id)?;
                self.data(id, r.rest(), out);
            }
            CMD_CLOSE => {
                // DYNVC_CLOSE request; the response is the same PDU
                // (MS-RDPEDYC 2.2.4, 3.2.5.4).
                let id = read_var(&mut r, cb_id)?;
                match self.find_open(id) {
                    Some(i) => {
                        trace!("dvc close {id}");
                        self.close(i, true, out);
                    }
                    None => trace!("dvc close for unknown channel {id}"),
                }
            }
            CMD_DATA_FIRST_COMPRESSED | CMD_DATA_COMPRESSED => {
                let id = read_var(&mut r, cb_id)?;
                trace!("dvc {id}: compressed data not supported; channel closed");
                if let Some(i) = self.find_open(id) {
                    self.close_local(i, LocalClose::Compressed, out);
                }
            }
            CMD_SOFT_SYNC_REQUEST => self.soft_sync(&mut r, out)?,
            _ => trace!("dvc command {cmd:#x} ignored"),
        }
        Ok(())
    }
}

impl StaticChannel for Drdynvc {
    fn name(&self) -> &str {
        DRDYNVC
    }

    fn options(&self) -> u32 {
        // mstsc: 0xC0800000.
        CHANNEL_OPTION_INITIALIZED
            | CHANNEL_OPTION_ENCRYPT_RDP
            | crate::channel::CHANNEL_OPTION_COMPRESS_RDP
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        self.handle(msg, out)
    }

    fn tick(&mut self, out: &mut ChannelOut) -> Result<()> {
        for i in 0..self.channels.len() {
            if self.channels[i].id.is_none() {
                continue;
            }
            let res = self.channels[i].handler.tick(&mut self.out);
            if res.is_ok() && self.out.is_empty() {
                continue;
            }
            self.finish(i, res, out);
        }
        Ok(())
    }

    fn as_drdynvc(&mut self) -> Option<&mut Drdynvc> {
        Some(self)
    }
}

/// Size code (cbId / Sp / Len) of the smallest field that holds `v`.
fn size_code(v: u32) -> u8 {
    if v <= 0xFF {
        0
    } else if v <= 0xFFFF {
        1
    } else {
        2
    }
}

fn field_len(code: u8) -> usize {
    1 << code
}

fn put_var(buf: &mut Vec<u8>, code: u8, v: u32) {
    match code {
        0 => buf.put_u8(v as u8),
        1 => buf.put_u16(v as u16),
        _ => buf.put_u32(v),
    }
}

fn read_var(r: &mut Reader, code: u8) -> Result<u32> {
    match code {
        0 => Ok(r.u8()? as u32),
        1 => Ok(r.u16()? as u32),
        2 => r.u32(),
        _ => proto("dvc field size code 3"),
    }
}

fn header(cmd: u8, sp: u8, cb_id: u8) -> u8 {
    (cmd << 4) | (sp << 2) | cb_id
}

/// DYNVC_CAPS_RSP (MS-RDPEDYC 2.2.1.2).
pub fn caps_response(version: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(4);
    v.put_u8(header(CMD_CAPS, 0, 0));
    v.put_u8(0);
    v.put_u16(version);
    v
}

/// DYNVC_CREATE_RSP (MS-RDPEDYC 2.2.2.2).
pub fn create_response(id: u32, status: u32) -> Vec<u8> {
    let cb = size_code(id);
    let mut v = Vec::with_capacity(9);
    v.put_u8(header(CMD_CREATE, 0, cb));
    put_var(&mut v, cb, id);
    v.put_u32(status);
    v
}

/// DYNVC_CLOSE (MS-RDPEDYC 2.2.4).
pub fn close_pdu(id: u32) -> Vec<u8> {
    let cb = size_code(id);
    let mut v = Vec::with_capacity(5);
    v.put_u8(header(CMD_CLOSE, 0, cb));
    put_var(&mut v, cb, id);
    v
}

/// DYNVC_SOFT_SYNC_RESPONSE (MS-RDPEDYC 2.2.5.2): the tunnels the client
/// will write DVC data on.
pub fn soft_sync_response(tunnels: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + 4 * tunnels.len());
    v.put_u8(header(CMD_SOFT_SYNC_RESPONSE, 0, 0));
    v.put_u8(0); // Pad
    v.put_u32(tunnels.len() as u32);
    for t in tunnels {
        v.put_u32(*t);
    }
    v
}

/// DYNVC_SOFT_SYNC_REQUEST (MS-RDPEDYC 2.2.5.1) with channel lists; the
/// server side, for tests.
pub fn soft_sync_request(lists: &[(u32, &[u32])]) -> Vec<u8> {
    let mut body = Vec::new();
    let flags = SOFT_SYNC_TCP_FLUSHED
        | if lists.is_empty() {
            0
        } else {
            SOFT_SYNC_CHANNEL_LIST_PRESENT
        };
    body.put_u16(flags);
    body.put_u16(lists.len() as u16);
    for (ty, ids) in lists {
        body.put_u32(*ty);
        body.put_u16(ids.len() as u16);
        for id in *ids {
            body.put_u32(*id);
        }
    }
    let mut v = vec![header(CMD_SOFT_SYNC_REQUEST, 0, 0), 0];
    v.put_u32(4 + body.len() as u32); // Length counts itself
    v.extend(body);
    v
}

/// Encodes one complete message as DYNVC_DATA, or as DYNVC_DATA_FIRST plus
/// DYNVC_DATA PDUs when it does not fit in one PDU (MS-RDPEDYC 2.2.3.1,
/// 2.2.3.2, 3.1.5.1.4). Each PDU is at most [`MAX_PDU`] bytes and becomes
/// one static channel message.
pub fn encode_data(id: u32, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
    let cb = size_code(id);
    let id_len = field_len(cb);
    if 1 + id_len + msg.len() <= MAX_PDU {
        let mut v = Vec::with_capacity(1 + id_len + msg.len());
        v.put_u8(header(CMD_DATA, 0, cb));
        put_var(&mut v, cb, id);
        v.put_bytes(msg);
        out.send(v);
        return Ok(());
    }
    let Ok(total) = u32::try_from(msg.len()) else {
        return proto("dvc message larger than 4 GiB");
    };
    let len_code = size_code(total);
    let first = MAX_PDU - 1 - id_len - field_len(len_code);
    let mut v = Vec::with_capacity(MAX_PDU);
    v.put_u8(header(CMD_DATA_FIRST, len_code, cb));
    put_var(&mut v, cb, id);
    put_var(&mut v, len_code, total);
    v.put_bytes(&msg[..first]);
    out.send(v);
    for part in msg[first..].chunks(MAX_PDU - 1 - id_len) {
        let mut v = Vec::with_capacity(1 + id_len + part.len());
        v.put_u8(header(CMD_DATA, 0, cb));
        put_var(&mut v, cb, id);
        v.put_bytes(part);
        out.send(v);
    }
    Ok(())
}

/// Runs a static-channel handler over a dynamic virtual channel. Some
/// extensions are carried either way with the same messages, for example
/// audio output: Windows 8 and later open `AUDIO_PLAYBACK_DVC` first and use
/// the static `rdpsnd` channel only as a fallback (MS-RDPEA 2.1).
pub struct StaticOverDvc<C: crate::channel::StaticChannel> {
    name: &'static str,
    inner: C,
}

impl<C: crate::channel::StaticChannel> StaticOverDvc<C> {
    pub fn new(name: &'static str, inner: C) -> Self {
        Self { name, inner }
    }
}

impl<C: crate::channel::StaticChannel> DynamicChannel for StaticOverDvc<C> {
    fn name(&self) -> &str {
        self.name
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let mut o = ChannelOut::default();
        let r = self.inner.process(msg, &mut o);
        for m in o.take() {
            out.send(m);
        }
        r
    }

    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        let mut o = ChannelOut::default();
        let r = self.inner.tick(&mut o);
        for m in o.take() {
            out.send(m);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records everything it sees; echoes messages back with a prefix.
    #[derive(Default)]
    struct Log {
        events: Vec<String>,
        msgs: Vec<Vec<u8>>,
    }

    struct Echo {
        name: &'static str,
        log: Arc<Mutex<Log>>,
        fail_on: Option<u8>,
        tick_msg: Option<Vec<u8>>,
        cap: Option<usize>,
        single: bool,
    }

    impl DynamicChannel for Echo {
        fn name(&self) -> &str {
            self.name
        }
        fn opened(&mut self, out: &mut DvcOut) -> Result<()> {
            self.log.lock().unwrap().events.push("opened".into());
            out.send(b"hi".to_vec());
            Ok(())
        }
        fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
            if msg.first() == self.fail_on.as_ref() {
                return proto("boom");
            }
            self.log.lock().unwrap().msgs.push(msg.to_vec());
            out.send([b"re:".as_slice(), msg].concat());
            Ok(())
        }
        fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
            if let Some(m) = self.tick_msg.take() {
                out.send(m);
            }
            Ok(())
        }
        fn closed(&mut self) {
            self.log.lock().unwrap().events.push("closed".into());
        }
        fn max_message_size(&self) -> usize {
            self.cap.unwrap_or(DEFAULT_MAX_MESSAGE)
        }
        fn allow_second_instance(&mut self) -> bool {
            self.log.lock().unwrap().events.push("second".into());
            !self.single
        }
        fn closing(&mut self, why: LocalClose) {
            self.log.lock().unwrap().events.push(format!("{why:?}"));
        }
    }

    fn echo(name: &'static str) -> (Box<dyn DynamicChannel>, Arc<Mutex<Log>>) {
        capped(name, None, false)
    }

    fn capped(
        name: &'static str,
        cap: Option<usize>,
        single: bool,
    ) -> (Box<dyn DynamicChannel>, Arc<Mutex<Log>>) {
        let log = Arc::new(Mutex::new(Log::default()));
        let ch = Echo {
            name,
            log: log.clone(),
            fail_on: None,
            tick_msg: None,
            cap,
            single,
        };
        (Box::new(ch), log)
    }

    /// DYNVC_DATA_FIRST with a 4-byte Length field (Sp = 2).
    fn data_first4(id: u8, total: u32, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x28, id];
        v.extend_from_slice(&total.to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    fn feed(d: &mut Drdynvc, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut out = ChannelOut::default();
        d.process(msg, &mut out).unwrap();
        out.take()
    }

    fn create_req(id: u8, name: &str) -> Vec<u8> {
        let mut v = vec![0x10, id];
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        v
    }

    #[test]
    fn caps_version1_spec_example() {
        // MS-RDPEDYC 4.1.1 / 4.1.2: DYNVC_CAPS_VERSION1 and DYNVC_CAPS_RSP.
        let mut d = Drdynvc::new(vec![]);
        assert_eq!(
            feed(&mut d, &[0x50, 0x00, 0x01, 0x00]),
            vec![vec![0x50, 0x00, 0x01, 0x00]]
        );
        assert_eq!(d.version(), 1);
    }

    #[test]
    fn caps_version3_and_higher_answer_min_3() {
        let mut d = Drdynvc::new(vec![]);
        let v3 = [
            0x50, 0x00, 0x03, 0x00, 0x33, 0x33, 0x11, 0x11, 0x3d, 0x0a, 0xa7, 0x04,
        ];
        assert_eq!(feed(&mut d, &v3), vec![vec![0x50, 0x00, 0x03, 0x00]]);
        let mut d = Drdynvc::new(vec![]);
        let v2 = [0x50, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(feed(&mut d, &v2), vec![vec![0x50, 0x00, 0x02, 0x00]]);
        let mut d = Drdynvc::new(vec![]);
        assert_eq!(
            feed(&mut d, &[0x50, 0x00, 0x07, 0x00]),
            vec![vec![0x50, 0x00, 0x03, 0x00]]
        );
    }

    #[test]
    fn create_known_channel() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        let out = feed(&mut d, &create_req(3, "ECHO"));
        // DYNVC_CREATE_RSP id 3 status 0, then the channel's opened() message.
        assert_eq!(
            out,
            vec![vec![0x10, 0x03, 0, 0, 0, 0], vec![0x30, 0x03, b'h', b'i']]
        );
        assert_eq!(log.lock().unwrap().events, ["opened"]);
    }

    #[test]
    fn create_unknown_channel_not_found() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        let out = feed(
            &mut d,
            &create_req(7, "Microsoft::Windows::RDS::Geometry::v08.01"),
        );
        assert_eq!(out, vec![vec![0x10, 0x07, 0x25, 0x02, 0x00, 0xC0]]);
        assert!(log.lock().unwrap().events.is_empty());
        // Data for that id goes nowhere.
        assert!(feed(&mut d, &[0x30, 0x07, 1, 2]).is_empty());
    }

    #[test]
    fn create_with_two_byte_id_and_priority() {
        let (ch, _log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        // cbId=1 (2 bytes), Sp=2 (priority), id 0x1234.
        let mut req = vec![0x19, 0x34, 0x12];
        req.extend_from_slice(b"ECHO\0");
        let out = feed(&mut d, &req);
        assert_eq!(out[0], vec![0x11, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(out[1], vec![0x31, 0x34, 0x12, b'h', b'i']);
        // Four-byte id in data from the server.
        let out = feed(&mut d, &[0x32, 0x34, 0x12, 0, 0, b'x']);
        assert_eq!(out, vec![vec![0x31, 0x34, 0x12, b'r', b'e', b':', b'x']]);
    }

    #[test]
    fn data_first_and_data_reassembly() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        // DATA_FIRST: Len=0 (1-byte length) total 6, then two DATA PDUs.
        assert!(feed(&mut d, &[0x20, 0x03, 0x06, b'a', b'b']).is_empty());
        assert!(feed(&mut d, &[0x30, 0x03, b'c', b'd']).is_empty());
        assert!(log.lock().unwrap().msgs.is_empty());
        let out = feed(&mut d, &[0x30, 0x03, b'e', b'f']);
        assert_eq!(log.lock().unwrap().msgs, vec![b"abcdef".to_vec()]);
        assert_eq!(out, vec![[&[0x30, 0x03][..], b"re:abcdef"].concat()]);
        // Two-byte length field (Sp=1): total 0x0003, complete in the first PDU.
        let out = feed(&mut d, &[0x24, 0x03, 0x03, 0x00, b'x', b'y', b'z']);
        assert_eq!(out, vec![[&[0x30, 0x03][..], b"re:xyz"].concat()]);
    }

    #[test]
    fn reassembly_overflow_closes_channel_only() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        feed(&mut d, &[0x20, 0x03, 0x03, b'a', b'b']);
        let out = feed(&mut d, &[0x30, 0x03, b'c', b'd']);
        assert_eq!(out, vec![vec![0x40, 0x03]]);
        assert_eq!(
            log.lock().unwrap().events,
            ["opened", "Malformed", "closed"]
        );
        assert!(log.lock().unwrap().msgs.is_empty());
    }

    #[test]
    fn outgoing_5000_bytes_fragmented() {
        let msg: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut out = ChannelOut::default();
        encode_data(3, &msg, &mut out).unwrap();
        let pdus = out.take();
        let lens: Vec<usize> = pdus.iter().map(|p| p.len()).collect();
        assert_eq!(lens, [1600, 1600, 1600, 210]);
        // DATA_FIRST: Cmd 2, Len code 1 (2-byte length), cbId 0.
        assert_eq!(&pdus[0][..4], &[0x24, 0x03, 0x88, 0x13]);
        assert_eq!(&pdus[0][4..], &msg[..1596]);
        for p in &pdus[1..] {
            assert_eq!(&p[..2], &[0x30, 0x03]);
        }
        assert_eq!(&pdus[1][2..], &msg[1596..3194]);
        assert_eq!(&pdus[3][2..], &msg[4792..]);
        // Our own reassembly accepts it.
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        for p in &pdus {
            feed(&mut d, p);
        }
        assert_eq!(log.lock().unwrap().msgs, vec![msg]);
    }

    #[test]
    fn exactly_one_pdu_is_not_fragmented() {
        let mut out = ChannelOut::default();
        encode_data(3, &[0u8; 1598], &mut out).unwrap();
        assert_eq!(out.take().len(), 1);
        encode_data(3, &[0u8; 1599], &mut out).unwrap();
        let pdus = out.take();
        assert_eq!(pdus.len(), 2);
        assert_eq!(pdus[0][0], 0x24);
    }

    #[test]
    fn close_request_gets_response_and_reopen_works() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        assert_eq!(feed(&mut d, &[0x40, 0x03]), vec![vec![0x40, 0x03]]);
        assert_eq!(log.lock().unwrap().events, ["opened", "closed"]);
        // Closed: data and unknown close are ignored.
        assert!(feed(&mut d, &[0x30, 0x03, b'x']).is_empty());
        assert!(feed(&mut d, &[0x40, 0x03]).is_empty());
        let out = feed(&mut d, &create_req(5, "ECHO"));
        assert_eq!(out[0], vec![0x10, 0x05, 0, 0, 0, 0]);
    }

    #[test]
    fn compressed_data_closes_channel() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        assert_eq!(
            feed(&mut d, &[0x70, 0x03, 0xE0, 0x00]),
            vec![vec![0x40, 0x03]]
        );
        assert_eq!(
            log.lock().unwrap().events,
            ["opened", "Compressed", "closed"]
        );
        feed(&mut d, &create_req(3, "ECHO"));
        assert_eq!(
            feed(&mut d, &[0x60, 0x03, 0x10, 0xE0]),
            vec![vec![0x40, 0x03]]
        );
    }

    #[test]
    fn handler_error_closes_that_channel_only() {
        let log_a = Arc::new(Mutex::new(Log::default()));
        let a = Echo {
            name: "A",
            log: log_a.clone(),
            fail_on: Some(b'!'),
            tick_msg: None,
            cap: None,
            single: false,
        };
        let (b, log_b) = echo("B");
        let mut d = Drdynvc::new(vec![Box::new(a), b]);
        feed(&mut d, &create_req(1, "A"));
        feed(&mut d, &create_req(2, "B"));
        assert_eq!(feed(&mut d, &[0x30, 0x01, b'!']), vec![vec![0x40, 0x01]]);
        assert_eq!(
            log_a.lock().unwrap().events,
            ["opened", "HandlerError", "closed"]
        );
        let out = feed(&mut d, &[0x30, 0x02, b'k']);
        assert_eq!(out, vec![vec![0x30, 0x02, b'r', b'e', b':', b'k']]);
        assert_eq!(log_b.lock().unwrap().events, ["opened"]);
    }

    #[test]
    fn tick_forwards_to_open_channels() {
        let log = Arc::new(Mutex::new(Log::default()));
        let ch = Echo {
            name: "T",
            log,
            fail_on: None,
            tick_msg: Some(b"t".to_vec()),
            cap: None,
            single: false,
        };
        let mut d = Drdynvc::new(vec![Box::new(ch)]);
        let mut out = ChannelOut::default();
        d.tick(&mut out).unwrap();
        assert!(out.is_empty(), "closed channels are not ticked");
        feed(&mut d, &create_req(9, "T"));
        d.tick(&mut out).unwrap();
        assert_eq!(out.take(), vec![vec![0x30, 0x09, b't']]);
        d.tick(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn reassembly_cap_closes_that_channel_only() {
        let (a, log_a) = capped("A", Some(100), false);
        let (b, log_b) = echo("B");
        let mut d = Drdynvc::new(vec![a, b]);
        feed(&mut d, &create_req(1, "A"));
        feed(&mut d, &create_req(2, "B"));
        // Exactly the cap is fine.
        assert!(feed(&mut d, &data_first4(1, 100, &[1; 60])).is_empty());
        feed(&mut d, &[&[0x30, 0x01][..], &[2; 40]].concat());
        assert_eq!(log_a.lock().unwrap().msgs.len(), 1);
        // One byte over: closed at DATA_FIRST, before anything is buffered.
        let out = feed(&mut d, &data_first4(1, 101, &[1; 10]));
        assert_eq!(out, vec![vec![0x40, 0x01]]);
        assert_eq!(
            log_a.lock().unwrap().events,
            ["opened", "TooLarge", "closed"]
        );
        // The other channel keeps working.
        let out = feed(&mut d, &[0x30, 0x02, b'k']);
        assert_eq!(out, vec![vec![0x30, 0x02, b'r', b'e', b':', b'k']]);
        assert_eq!(log_b.lock().unwrap().events, ["opened"]);
    }

    #[test]
    fn plain_data_over_the_cap_closes_that_channel() {
        let (a, log_a) = capped("A", Some(100), false);
        let (b, log_b) = echo("B");
        let mut d = Drdynvc::new(vec![a, b]);
        feed(&mut d, &create_req(1, "A"));
        feed(&mut d, &create_req(2, "B"));
        // A DYNVC_DATA without DATA_FIRST at the cap is delivered...
        let out = feed(&mut d, &[&[0x30, 0x01][..], &[7; 100]].concat());
        assert_eq!(out.len(), 1);
        assert_eq!(log_a.lock().unwrap().msgs.len(), 1);
        // ...one byte more closes the channel without delivering it.
        let out = feed(&mut d, &[&[0x30, 0x01][..], &[7; 101]].concat());
        assert_eq!(out, vec![vec![0x40, 0x01]]);
        assert_eq!(log_a.lock().unwrap().msgs.len(), 1);
        assert_eq!(
            log_a.lock().unwrap().events,
            ["opened", "TooLarge", "closed"]
        );
        let out = feed(&mut d, &[0x30, 0x02, b'k']);
        assert_eq!(out, vec![vec![0x30, 0x02, b'r', b'e', b':', b'k']]);
        assert_eq!(log_b.lock().unwrap().events, ["opened"]);
    }

    /// A handler that queues a last message and then fails: the message
    /// goes out before the DYNVC_CLOSE (a rejection must reach the peer).
    struct LastWords;

    impl DynamicChannel for LastWords {
        fn name(&self) -> &str {
            "L"
        }
        fn process(&mut self, _msg: &[u8], out: &mut DvcOut) -> Result<()> {
            out.send(b"bye".to_vec());
            proto("closing")
        }
    }

    #[test]
    fn queued_messages_go_out_before_the_close() {
        let mut d = Drdynvc::new(vec![Box::new(LastWords)]);
        feed(&mut d, &create_req(4, "L"));
        let out = feed(&mut d, &[0x30, 0x04, b'x']);
        assert_eq!(
            out,
            vec![vec![0x30, 0x04, b'b', b'y', b'e'], vec![0x40, 0x04]]
        );
    }

    #[test]
    fn default_cap_is_16_mib() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        let at_cap = data_first4(3, DEFAULT_MAX_MESSAGE as u32, &[0; 8]);
        assert!(feed(&mut d, &at_cap).is_empty());
        let over = data_first4(3, DEFAULT_MAX_MESSAGE as u32 + 1, &[0; 8]);
        assert_eq!(feed(&mut d, &over), vec![vec![0x40, 0x03]]);
        assert_eq!(log.lock().unwrap().events, ["opened", "TooLarge", "closed"]);
        // A 4 GiB announcement is refused the same way.
        feed(&mut d, &create_req(3, "ECHO"));
        let huge = data_first4(3, u32::MAX, &[0; 8]);
        assert_eq!(feed(&mut d, &huge), vec![vec![0x40, 0x03]]);
    }

    #[test]
    fn compressed_data_mid_message_closes_cleanly_and_reopens_fresh() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        // Half a message, then compressed data.
        feed(&mut d, &[0x20, 0x03, 0x06, b'a', b'b']);
        assert_eq!(feed(&mut d, &[0x70, 0x03, 0xE0]), vec![vec![0x40, 0x03]]);
        assert_eq!(
            log.lock().unwrap().events,
            ["opened", "Compressed", "closed"]
        );
        // Further fragments of the old message go nowhere.
        assert!(feed(&mut d, &[0x30, 0x03, b'c', b'd']).is_empty());
        // Reopened, the channel starts with no partial message.
        feed(&mut d, &create_req(4, "ECHO"));
        let out = feed(&mut d, &[0x30, 0x04, b'x']);
        assert_eq!(out, vec![vec![0x30, 0x04, b'r', b'e', b':', b'x']]);
        assert_eq!(log.lock().unwrap().msgs, vec![b"x".to_vec()]);
    }

    #[test]
    fn second_create_replaces_by_default() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        let out = feed(&mut d, &create_req(4, "ECHO"));
        assert_eq!(out[0], vec![0x10, 0x04, 0, 0, 0, 0]);
        assert_eq!(
            log.lock().unwrap().events,
            ["opened", "second", "closed", "opened"]
        );
        // Old id is gone, new id works.
        assert!(feed(&mut d, &[0x30, 0x03, b'x']).is_empty());
        assert_eq!(feed(&mut d, &[0x30, 0x04, b'y']).len(), 1);
    }

    #[test]
    fn second_create_refused_by_a_single_instance_channel() {
        let (ch, log) = capped("ONE", None, true);
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ONE"));
        let out = feed(&mut d, &create_req(4, "ONE"));
        // E_ACCESSDENIED, little-endian.
        assert_eq!(out, vec![vec![0x10, 0x04, 0x05, 0x00, 0x07, 0x80]]);
        assert_eq!(log.lock().unwrap().events, ["opened", "second"]);
        // The first instance is untouched; the refused id goes nowhere.
        assert_eq!(feed(&mut d, &[0x30, 0x03, b'x']).len(), 1);
        assert!(feed(&mut d, &[0x30, 0x04, b'y']).is_empty());
        // After the first closes, a new instance is welcome.
        feed(&mut d, &[0x40, 0x03]);
        let out = feed(&mut d, &create_req(5, "ONE"));
        assert_eq!(out[0], vec![0x10, 0x05, 0, 0, 0, 0]);
        // The same id again (the server reusing its id) is not a second
        // instance and keeps the replace behaviour.
        let out = feed(&mut d, &create_req(5, "ONE"));
        assert_eq!(out[0], vec![0x10, 0x05, 0, 0, 0, 0]);
    }

    #[test]
    fn malformed_input_never_panics() {
        let (ch, _log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        let mut out = ChannelOut::default();
        assert!(d.process(&[], &mut out).is_err());
        assert!(d.process(&[0x50], &mut out).is_err());
        assert!(d.process(&[0x13, 0x01], &mut out).is_err()); // cbId 3
        assert!(d.process(&[0x12, 0x01], &mut out).is_err()); // truncated id
        assert!(d.process(&[0x28, 0x01], &mut out).is_err()); // truncated len
        assert!(d.process(&[0x90], &mut out).is_ok()); // soft-sync ignored
        assert!(d.process(&[0xF0], &mut out).is_ok());
        // A truncated Soft-Sync Request with a tunnel up is an error.
        d.set_tunnel_ready();
        assert!(d.process(&[0x80, 0x00, 0x0A], &mut out).is_err());
    }

    fn tunnel(d: &mut Drdynvc, msg: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut out = ChannelOut::default();
        d.process_tunnel(msg, &mut out).unwrap();
        (out.take(), d.take_tunnel_out())
    }

    #[test]
    fn soft_sync_pdus() {
        // MS-RDPEDYC 2.2.5.2: Cmd 9, Pad, NumberOfTunnels, TunnelsToSwitch.
        assert_eq!(
            soft_sync_response(&[TUNNELTYPE_UDPFECR]),
            vec![0x90, 0, 1, 0, 0, 0, 1, 0, 0, 0]
        );
        // 2.2.5.1: Cmd 8, Pad, Length, Flags (TCP_FLUSHED | LIST_PRESENT),
        // NumberOfTunnels, then TunnelType, NumberOfDVCs, ids.
        assert_eq!(
            soft_sync_request(&[(TUNNELTYPE_UDPFECR, &[3])]),
            vec![
                0x80, 0, 18, 0, 0, 0, 3, 0, 1, 0, 1, 0, 0, 0, 1, 0, 3, 0, 0, 0
            ]
        );
    }

    #[test]
    fn soft_sync_without_a_tunnel_is_not_answered() {
        let (ch, _log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        feed(&mut d, &create_req(3, "ECHO"));
        assert!(feed(&mut d, &soft_sync_request(&[(TUNNELTYPE_UDPFECR, &[3])])).is_empty());
        // Data stays on the static channel.
        assert_eq!(feed(&mut d, &[0x30, 0x03, b'x']).len(), 1);
        assert!(d.take_tunnel_out().is_empty());
        assert_eq!(d.channels_on_tunnel(), 0);
    }

    #[test]
    fn soft_sync_moves_the_listed_channels_to_the_tunnel() {
        let (a, log_a) = echo("A");
        let (b, _log_b) = echo("B");
        let mut d = Drdynvc::new(vec![a, b]);
        feed(&mut d, &create_req(3, "A"));
        feed(&mut d, &create_req(4, "B"));
        // Tunnel data before the Soft-Sync Request waits (3.2.5.3.1).
        assert_eq!(tunnel(&mut d, &[0x30, 0x03, b'1']), (vec![], vec![]));
        assert!(log_a.lock().unwrap().msgs.is_empty());
        d.set_tunnel_ready();
        // Channel 3 on the reliable tunnel; channel 4 on a lossy one,
        // which this client never opened, stays on TCP.
        let req = soft_sync_request(&[(TUNNELTYPE_UDPFECR, &[3]), (TUNNELTYPE_UDPFECL, &[4])]);
        let out = feed(&mut d, &req);
        // The response on the static channel, then the held PDU is handled:
        // its reply goes to the tunnel.
        assert_eq!(out, vec![soft_sync_response(&[TUNNELTYPE_UDPFECR])]);
        assert_eq!(log_a.lock().unwrap().msgs, vec![b"1".to_vec()]);
        assert_eq!(d.take_tunnel_out(), vec![b"\x30\x03re:1".to_vec()]);
        assert_eq!(d.channels_on_tunnel(), 1);
        // Data for channel 3 from either side is answered on the tunnel...
        assert_eq!(
            tunnel(&mut d, &[0x30, 0x03, b'2']),
            (vec![], vec![b"\x30\x03re:2".to_vec()])
        );
        // ...channel 4 keeps the static channel.
        assert_eq!(
            feed(&mut d, &[0x30, 0x04, b'k']),
            vec![b"\x30\x04re:k".to_vec()]
        );
        assert!(d.take_tunnel_out().is_empty());
        // Closing channel 3 answers on the tunnel and ends its UDP binding.
        assert_eq!(
            tunnel(&mut d, &[0x40, 0x03]),
            (vec![], vec![vec![0x40, 0x03]])
        );
        assert_eq!(d.channels_on_tunnel(), 0);
        // Reopened over TCP it is a TCP channel again.
        let out = feed(&mut d, &create_req(5, "A"));
        assert_eq!(out[0], vec![0x10, 0x05, 0, 0, 0, 0]);
        assert!(d.take_tunnel_out().is_empty());
    }

    #[test]
    fn a_channel_created_over_the_tunnel_uses_it() {
        let (ch, log) = echo("ECHO");
        let mut d = Drdynvc::new(vec![ch]);
        d.set_tunnel_ready();
        feed(&mut d, &soft_sync_request(&[]));
        let (stat, udp) = tunnel(&mut d, &create_req(9, "ECHO"));
        assert!(stat.is_empty());
        assert_eq!(
            udp,
            vec![vec![0x10, 0x09, 0, 0, 0, 0], vec![0x30, 0x09, b'h', b'i']]
        );
        // An unknown name over the tunnel is refused over the tunnel.
        let (stat, udp) = tunnel(&mut d, &create_req(10, "NOPE"));
        assert!(stat.is_empty());
        assert_eq!(udp, vec![create_response(10, STATUS_NOT_FOUND)]);
        // A large reply is fragmented as on the static channel.
        let big = vec![b'z'; 5000];
        let mut msg = vec![0x30, 0x09];
        msg.extend_from_slice(&big);
        let (_, udp) = tunnel(&mut d, &msg);
        assert_eq!(udp.len(), 4);
        assert_eq!(udp[0][0], 0x24);
        assert_eq!(log.lock().unwrap().msgs, vec![big]);
    }
}
