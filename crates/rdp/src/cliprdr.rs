//! Clipboard redirection, client side (MS-RDPECLIP) on the `cliprdr` static
//! virtual channel.
//!
//! Scope: Unicode text (CF_UNICODETEXT) in both directions. Other formats
//! (file lists, images, HTML) are answered with CB_RESPONSE_FAIL; they plug in
//! through [`LOCAL_FORMATS`], [`Cliprdr::format_data`] and
//! [`Cliprdr::received_data`].
//!
//! Sharing starts off and is toggled live through [`ClipboardHandle`]: the
//! channel stays joined for the whole session and only the data exchange is
//! gated (repository rule: sharing features toggle without reconnecting).
//!
//! Flow (MS-RDPECLIP 1.3.2, 3.1.5, 3.2.5):
//! - initialization: server Clipboard Capabilities + Monitor Ready, client
//!   answers with its Clipboard Capabilities and a Format List;
//! - copy: whoever's clipboard changes sends a Format List, the peer answers
//!   with a Format List Response;
//! - paste: the side that wants the data sends a Format Data Request, the
//!   owner answers with a Format Data Response.
//!
//! Clipboard contents are never traced; only lengths and format ids.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::channel::{
    CHANNEL_OPTION_ENCRYPT_RDP, CHANNEL_OPTION_INITIALIZED, CHANNEL_OPTION_SHOW_PROTOCOL,
    ChannelOut, StaticChannel,
};
use crate::cursor::{Put, Reader, utf16le, utf16le_z};
use crate::error::{Result, proto};
use crate::trace;

// CLIPRDR_HEADER msgType values (MS-RDPECLIP 2.2.1).
pub const CB_MONITOR_READY: u16 = 0x0001;
pub const CB_FORMAT_LIST: u16 = 0x0002;
pub const CB_FORMAT_LIST_RESPONSE: u16 = 0x0003;
pub const CB_FORMAT_DATA_REQUEST: u16 = 0x0004;
pub const CB_FORMAT_DATA_RESPONSE: u16 = 0x0005;
pub const CB_TEMP_DIRECTORY: u16 = 0x0006;
pub const CB_CLIP_CAPS: u16 = 0x0007;
pub const CB_FILECONTENTS_REQUEST: u16 = 0x0008;
pub const CB_FILECONTENTS_RESPONSE: u16 = 0x0009;
pub const CB_LOCK_CLIPDATA: u16 = 0x000A;
pub const CB_UNLOCK_CLIPDATA: u16 = 0x000B;

// CLIPRDR_HEADER msgFlags values (MS-RDPECLIP 2.2.1).
pub const CB_RESPONSE_OK: u16 = 0x0001;
pub const CB_RESPONSE_FAIL: u16 = 0x0002;
pub const CB_ASCII_NAMES: u16 = 0x0004;

// General Capability Set (MS-RDPECLIP 2.2.2.1.1.1).
pub const CB_CAPSTYPE_GENERAL: u16 = 0x0001;
pub const CB_CAPS_VERSION_2: u32 = 0x0000_0002;
pub const CB_USE_LONG_FORMAT_NAMES: u32 = 0x0000_0002;

/// Standard clipboard format: UTF-16LE text with a NUL terminator.
pub const CF_UNICODETEXT: u32 = 13;

/// Formats this client can serve from the local clipboard, as (id, name).
/// Standard formats have no name. New formats are added here and in
/// [`Cliprdr::format_data`].
pub const LOCAL_FORMATS: &[(u32, &str)] = &[(CF_UNICODETEXT, "")];

/// General flags the client advertises.
const CLIENT_GENERAL_FLAGS: u32 = CB_USE_LONG_FORMAT_NAMES;

/// Size of one Short Format Name entry: formatId + 32-byte name.
const SHORT_NAME_ENTRY: usize = 36;

/// Write attempts for remote text when the local clipboard stays busy (one
/// per tick, about 2 ms apart).
const WRITE_RETRIES: u8 = 25;

/// The local system clipboard. Runs on the session worker thread, so every
/// call must return quickly (no long blocking, no message pump needed).
pub trait ClipboardBackend: Send {
    /// Changes whenever the local clipboard changes (Windows: GetClipboardSequenceNumber).
    fn sequence(&mut self) -> u32;
    fn read_text(&mut self) -> Option<String>;
    fn write_text(&mut self, text: &str) -> bool;
}

/// UI-side switch for clipboard sharing. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct ClipboardHandle {
    enabled: Arc<AtomicBool>,
}

impl ClipboardHandle {
    /// Turns sharing on or off. The session applies it on its next poll:
    /// on announces the local text, off withdraws it (empty Format List).
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Creates the `cliprdr` channel handler and its UI switch. Sharing starts off.
pub fn cliprdr(backend: Box<dyn ClipboardBackend>) -> (Cliprdr, ClipboardHandle) {
    let enabled = Arc::new(AtomicBool::new(false));
    let handle = ClipboardHandle {
        enabled: enabled.clone(),
    };
    let channel = Cliprdr {
        backend,
        enabled,
        applied: false,
        ready: false,
        server_flags: 0,
        last_seq: 0,
        requested: VecDeque::new(),
        pending_write: None,
    };
    (channel, handle)
}

/// Client side of the clipboard virtual channel.
pub struct Cliprdr {
    backend: Box<dyn ClipboardBackend>,
    enabled: Arc<AtomicBool>,
    /// Sharing state last applied by `tick` (announced to the server).
    applied: bool,
    /// Monitor Ready was handled; the client may send Format Lists.
    ready: bool,
    /// generalFlags of the server's General Capability Set (0 if absent).
    server_flags: u32,
    /// Local clipboard sequence already seen (or caused by our own write).
    last_seq: u32,
    /// Format ids of our outstanding Format Data Requests, oldest first
    /// (responses carry no format id; MS-RDPECLIP 3.1.5.2.2).
    requested: VecDeque<u32>,
    /// Remote text the busy local clipboard did not take yet, with tries left.
    pending_write: Option<(String, u8)>,
}

impl Cliprdr {
    fn sharing(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Long Format Names only if both sides set CB_USE_LONG_FORMAT_NAMES
    /// (MS-RDPECLIP 2.2.2.1.1.1).
    fn long_names(&self) -> bool {
        self.server_flags & CLIENT_GENERAL_FLAGS & CB_USE_LONG_FORMAT_NAMES != 0
    }

    fn send_format_list(&self, formats: &[(u32, &str)], out: &mut ChannelOut) {
        trace!("cliprdr: format list with {} formats", formats.len());
        out.send(format_list(formats, self.long_names()));
    }

    /// Format List with the local text if sharing is on and text is there.
    fn announce_current(&mut self, out: &mut ChannelOut, send_empty: bool) {
        if self.sharing() && self.backend.read_text().is_some() {
            self.send_format_list(LOCAL_FORMATS, out);
        } else if send_empty {
            self.send_format_list(&[], out);
        }
    }

    /// Server Monitor Ready (MS-RDPECLIP 2.2.2.2, 3.2.5.1.2): the client
    /// sends its capabilities, then its Format List.
    fn monitor_ready(&mut self, out: &mut ChannelOut) {
        out.send(capabilities(CLIENT_GENERAL_FLAGS));
        self.ready = true;
        self.applied = self.sharing();
        self.last_seq = self.backend.sequence();
        self.announce_current(out, true);
    }

    /// Server Format List (MS-RDPECLIP 2.2.3.1, 3.1.5.2.2): always
    /// acknowledged; text is fetched when sharing is on.
    fn remote_format_list(&mut self, flags: u16, body: &[u8], out: &mut ChannelOut) {
        let formats = match parse_format_list(flags, body, self.long_names()) {
            Ok(f) => f,
            Err(e) => {
                trace!("cliprdr: bad format list ({e}); answered FAIL");
                out.send(pdu(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_FAIL, &[]));
                return;
            }
        };
        trace!("cliprdr: server offers {} formats", formats.len());
        out.send(pdu(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[]));
        if self.sharing() && formats.iter().any(|(id, _)| *id == CF_UNICODETEXT) {
            out.send(format_data_request(CF_UNICODETEXT));
            self.requested.push_back(CF_UNICODETEXT);
        }
    }

    /// Answers a server Format Data Request (MS-RDPECLIP 2.2.5.1, 2.2.5.2).
    fn format_data(&mut self, format: u32) -> Vec<u8> {
        if !self.sharing() {
            return pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[]);
        }
        let data = match format {
            CF_UNICODETEXT => self.backend.read_text().map(|t| utf16le_z(&t)),
            _ => None,
        };
        match data {
            Some(d) => {
                trace!("cliprdr: sending format {format}, {} bytes", d.len());
                pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, &d)
            }
            None => {
                trace!("cliprdr: format {format} not available");
                pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[])
            }
        }
    }

    /// Server Format Data Response to our request (MS-RDPECLIP 2.2.5.2).
    fn received_data(&mut self, flags: u16, body: &[u8]) {
        let Some(format) = self.requested.pop_front() else {
            trace!("cliprdr: unsolicited format data response ignored");
            return;
        };
        if flags & CB_RESPONSE_OK == 0 {
            trace!("cliprdr: server failed format {format}");
            return;
        }
        if !self.sharing() {
            trace!("cliprdr: sharing off; format {format} data dropped");
            return;
        }
        if format == CF_UNICODETEXT {
            trace!("cliprdr: received text, {} bytes", body.len());
            let text = decode_text(body);
            self.pending_write = Some((text, WRITE_RETRIES));
            self.try_write();
        }
    }

    /// Writes pending remote text; our own write never counts as a local
    /// change (no echo back to the server).
    fn try_write(&mut self) {
        let Some((text, tries)) = self.pending_write.take() else {
            return;
        };
        let ok = self.backend.write_text(&text);
        self.last_seq = self.backend.sequence();
        if !ok && tries > 1 {
            self.pending_write = Some((text, tries - 1));
        } else if !ok {
            trace!("cliprdr: local clipboard busy; remote text dropped");
        }
    }
}

impl StaticChannel for Cliprdr {
    fn name(&self) -> &str {
        "cliprdr"
    }

    fn options(&self) -> u32 {
        // mstsc: 0xC0A00000. COMPRESS_RDP only matters when bulk compression is
        // negotiated (it is not), so channel data still arrives uncompressed.
        CHANNEL_OPTION_INITIALIZED
            | CHANNEL_OPTION_ENCRYPT_RDP
            | crate::channel::CHANNEL_OPTION_COMPRESS_RDP
            | CHANNEL_OPTION_SHOW_PROTOCOL
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let (msg_type, flags, body) = parse_header(msg)?;
        match msg_type {
            CB_CLIP_CAPS => {
                self.server_flags = parse_capabilities(body)?;
                trace!("cliprdr: server general flags {:#x}", self.server_flags);
            }
            CB_MONITOR_READY => self.monitor_ready(out),
            CB_FORMAT_LIST => self.remote_format_list(flags, body, out),
            CB_FORMAT_LIST_RESPONSE => {
                if flags & CB_RESPONSE_OK == 0 {
                    trace!("cliprdr: server rejected our format list");
                }
            }
            CB_FORMAT_DATA_REQUEST => {
                let format = Reader::new(body).u32()?;
                let reply = self.format_data(format);
                out.send(reply);
            }
            CB_FORMAT_DATA_RESPONSE => self.received_data(flags, body),
            // MS-RDPECLIP 2.2.4.1 / 2.2.4.2: only matter for file streams.
            CB_LOCK_CLIPDATA | CB_UNLOCK_CLIPDATA => {}
            other => trace!("cliprdr: message type {other} ignored"),
        }
        Ok(())
    }

    /// Cheap when idle: one atomic load and one sequence number read.
    fn tick(&mut self, out: &mut ChannelOut) -> Result<()> {
        if !self.ready {
            return Ok(());
        }
        let on = self.sharing();
        if on != self.applied {
            self.applied = on;
            self.last_seq = self.backend.sequence();
            if on {
                trace!("cliprdr: sharing on");
                self.announce_current(out, false);
            } else {
                trace!("cliprdr: sharing off");
                self.pending_write = None;
                self.send_format_list(&[], out);
            }
            return Ok(());
        }
        if !on {
            return Ok(());
        }
        let seq = self.backend.sequence();
        if seq != self.last_seq {
            // A local copy wins over remote text still waiting to be written.
            self.last_seq = seq;
            self.pending_write = None;
            self.send_format_list(LOCAL_FORMATS, out);
        } else if self.pending_write.is_some() {
            self.try_write();
        }
        Ok(())
    }
}

/// CLIPRDR_HEADER (MS-RDPECLIP 2.2.1) followed by `body`.
pub fn pdu(msg_type: u16, msg_flags: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + body.len());
    v.put_u16(msg_type);
    v.put_u16(msg_flags);
    v.put_u32(body.len() as u32);
    v.put_bytes(body);
    v
}

/// Splits a message into (msgType, msgFlags, body) (MS-RDPECLIP 2.2.1).
/// Bytes after `dataLen` are padding and ignored.
pub fn parse_header(msg: &[u8]) -> Result<(u16, u16, &[u8])> {
    let mut r = Reader::new(msg);
    let msg_type = r.u16()?;
    let flags = r.u16()?;
    let len = r.u32()? as usize;
    let body = r.bytes(len)?;
    Ok((msg_type, flags, body))
}

/// Clipboard Capabilities PDU with one General Capability Set, version 2
/// (MS-RDPECLIP 2.2.2.1, 2.2.2.1.1.1).
pub fn capabilities(general_flags: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.put_u16(1); // cCapabilitiesSets
    b.put_u16(0); // pad1
    b.put_u16(CB_CAPSTYPE_GENERAL);
    b.put_u16(12); // lengthCapability
    b.put_u32(CB_CAPS_VERSION_2);
    b.put_u32(general_flags);
    pdu(CB_CLIP_CAPS, 0, &b)
}

/// generalFlags from a Clipboard Capabilities PDU body (MS-RDPECLIP
/// 2.2.2.1); 0 when no General Capability Set is present.
pub fn parse_capabilities(body: &[u8]) -> Result<u32> {
    let mut r = Reader::new(body);
    let count = r.u16()?;
    r.skip(2)?;
    let mut flags = 0;
    for _ in 0..count {
        let set_type = r.u16()?;
        let len = r.u16()? as usize;
        if len < 4 {
            return proto(format!("cliprdr capability set length {len}"));
        }
        let data = r.bytes(len - 4)?;
        if set_type == CB_CAPSTYPE_GENERAL {
            let mut g = Reader::new(data);
            let _version = g.u32()?;
            flags = g.u32()?;
        }
    }
    Ok(flags)
}

/// Format List PDU (MS-RDPECLIP 2.2.3.1) with Long Format Names
/// (2.2.3.1.2.1) or Unicode Short Format Names (2.2.3.1.1.1).
pub fn format_list(formats: &[(u32, &str)], long_names: bool) -> Vec<u8> {
    let mut b = Vec::new();
    for &(id, name) in formats {
        b.put_u32(id);
        if long_names {
            b.put_bytes(&utf16le_z(name));
        } else {
            // 32 bytes: at most 15 UTF-16 units plus the NUL, zero padded.
            let mut n = utf16le(name);
            n.truncate(30);
            n.resize(32, 0);
            b.put_bytes(&n);
        }
    }
    pdu(CB_FORMAT_LIST, 0, &b)
}

/// (formatId, name) pairs of a Format List PDU body (MS-RDPECLIP 2.2.3.1).
pub fn parse_format_list(flags: u16, body: &[u8], long_names: bool) -> Result<Vec<(u32, String)>> {
    let mut r = Reader::new(body);
    let mut formats = Vec::new();
    if long_names {
        // MS-RDPECLIP 2.2.3.1.2.1: formatId + NUL-terminated UTF-16LE name.
        while r.remaining() > 0 {
            let id = r.u32()?;
            let mut units = Vec::new();
            loop {
                match r.u16()? {
                    0 => break,
                    u => units.push(u),
                }
            }
            formats.push((id, String::from_utf16_lossy(&units)));
        }
    } else {
        // MS-RDPECLIP 2.2.3.1.1.1: formatId + 32-byte name, ASCII if
        // CB_ASCII_NAMES is set, else UTF-16LE.
        if !body.len().is_multiple_of(SHORT_NAME_ENTRY) {
            return proto(format!("short format list of {} bytes", body.len()));
        }
        while r.remaining() > 0 {
            let id = r.u32()?;
            let raw = r.bytes(32)?;
            let name = if flags & CB_ASCII_NAMES != 0 {
                raw.iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect()
            } else {
                decode_text(raw)
            };
            formats.push((id, name));
        }
    }
    Ok(formats)
}

/// Format Data Request PDU (MS-RDPECLIP 2.2.5.1).
pub fn format_data_request(format: u32) -> Vec<u8> {
    pdu(CB_FORMAT_DATA_REQUEST, 0, &format.to_le_bytes())
}

/// CF_UNICODETEXT data: UTF-16LE up to the first NUL (MS-RDPECLIP 2.2.5.2).
pub fn decode_text(data: &[u8]) -> String {
    let (pairs, _odd) = data.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Fake system clipboard, shared with the test through an Arc.
    #[derive(Default)]
    struct Fake {
        seq: u32,
        text: Option<String>,
        writes: Vec<String>,
        /// Number of upcoming write_text calls that fail (clipboard busy).
        busy: u32,
    }

    struct Mock(Arc<Mutex<Fake>>);

    impl ClipboardBackend for Mock {
        fn sequence(&mut self) -> u32 {
            self.0.lock().unwrap().seq
        }
        fn read_text(&mut self) -> Option<String> {
            self.0.lock().unwrap().text.clone()
        }
        fn write_text(&mut self, text: &str) -> bool {
            let mut f = self.0.lock().unwrap();
            f.seq += 1; // EmptyClipboard bumps the sequence even on failure
            if f.busy > 0 {
                f.busy -= 1;
                return false;
            }
            f.seq += 1;
            f.text = Some(text.to_string());
            f.writes.push(text.to_string());
            true
        }
    }

    impl Fake {
        /// A local copy by another application.
        fn user_copies(&mut self, text: &str) {
            self.seq += 1;
            self.text = Some(text.to_string());
        }
    }

    // MS-RDPECLIP 4.1.1 Server Clipboard Capabilities PDU.
    const SERVER_CAPS: [u8; 24] = [
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
    ];
    // MS-RDPECLIP 4.1.2 Server Monitor Ready PDU.
    const MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    // MS-RDPECLIP 4.1.6 Format List Response PDU (CB_RESPONSE_OK).
    const LIST_RESPONSE_OK: [u8; 8] = [0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    // MS-RDPECLIP 4.4.1 Format Data Request PDU (CF_UNICODETEXT).
    const DATA_REQUEST_TEXT: [u8; 12] = [
        0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
    ];
    // MS-RDPECLIP 4.4.2 Format Data Response PDU ("hello world").
    const DATA_RESPONSE_HELLO: [u8; 32] = [
        0x05, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c,
        0x00, 0x6f, 0x00, 0x20, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00,
        0x00, 0x00,
    ];
    // MS-RDPECLIP 4.3.1 Lock Clipboard Data PDU.
    const LOCK: [u8; 12] = [
        0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    ];
    const DATA_RESPONSE_FAIL: [u8; 8] = [0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// Client Clipboard Capabilities: MS-RDPECLIP 4.1.3 with generalFlags
    /// 0x02 (long names only; the example also has the file-stream flags).
    const CLIENT_CAPS: [u8; 24] = [
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
    /// Long-name Format List with CF_UNICODETEXT and an empty name.
    const LIST_TEXT_LONG: [u8; 14] = [
        0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LIST_EMPTY: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// MS-RDPECLIP 4.2.1 Format List PDU (long names, includes CF_UNICODETEXT).
    fn spec_format_list_421() -> Vec<u8> {
        let hex = "            02 00 00 00 e0 00 00 00 8a c0 00 00 52 00 69 00             63 00 68 00 20 00 54 00 65 00 78 00 74 00 20 00             46 00 6f 00 72 00 6d 00 61 00 74 00 00 00 45 c1             00 00 52 00 69 00 63 00 68 00 20 00 54 00 65 00             78 00 74 00 20 00 46 00 6f 00 72 00 6d 00 61 00             74 00 20 00 57 00 69 00 74 00 68 00 6f 00 75 00             74 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00             73 00 00 00 43 c1 00 00 52 00 54 00 46 00 20 00             41 00 73 00 20 00 54 00 65 00 78 00 74 00 00 00             01 00 00 00 00 00 0d 00 00 00 00 00 04 c0 00 00             4e 00 61 00 74 00 69 00 76 00 65 00 00 00 0e c0             00 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00             44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00             6f 00 72 00 00 00 03 00 00 00 00 00 10 00 00 00             00 00 07 00 00 00 00 00";
        let hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn setup() -> (Cliprdr, ClipboardHandle, Arc<Mutex<Fake>>) {
        let fake = Arc::new(Mutex::new(Fake::default()));
        let (c, h) = cliprdr(Box::new(Mock(fake.clone())));
        (c, h, fake)
    }

    fn feed(c: &mut Cliprdr, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut out = ChannelOut::default();
        c.process(msg, &mut out).unwrap();
        out.take()
    }

    fn tick(c: &mut Cliprdr) -> Vec<Vec<u8>> {
        let mut out = ChannelOut::default();
        c.tick(&mut out).unwrap();
        out.take()
    }

    /// Session after the initialization sequence, with sharing as given.
    fn connected(on: bool) -> (Cliprdr, ClipboardHandle, Arc<Mutex<Fake>>) {
        let (mut c, h, fake) = setup();
        h.set_enabled(on);
        assert!(feed(&mut c, &SERVER_CAPS).is_empty());
        feed(&mut c, &MONITOR_READY);
        assert!(tick(&mut c).is_empty());
        (c, h, fake)
    }

    #[test]
    fn channel_definition() {
        let (c, h, _) = setup();
        assert_eq!(c.name(), "cliprdr");
        // Same as mstsc (INITIALIZED | ENCRYPT_RDP | COMPRESS_RDP | SHOW_PROTOCOL).
        assert_eq!(c.options(), 0xC0A0_0000);
        assert!(!h.enabled(), "sharing starts off");
        fn send_sync<T: Send + Sync + Clone>(_: &T) {}
        send_sync(&h);
    }

    #[test]
    fn capabilities_bytes() {
        assert_eq!(capabilities(CB_USE_LONG_FORMAT_NAMES), CLIENT_CAPS);
        let (t, f, body) = parse_header(&SERVER_CAPS).unwrap();
        assert_eq!((t, f), (CB_CLIP_CAPS, 0));
        assert_eq!(parse_capabilities(body).unwrap(), 0x0e);
        // No general set: default flags 0 (2.2.2.1.1.1).
        assert_eq!(parse_capabilities(&[0, 0, 0, 0]).unwrap(), 0);
    }

    #[test]
    fn monitor_ready_sends_caps_then_empty_list_when_off() {
        let (mut c, _h, fake) = setup();
        fake.lock().unwrap().user_copies("local");
        feed(&mut c, &SERVER_CAPS);
        let out = feed(&mut c, &MONITOR_READY);
        assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_EMPTY.to_vec()]);
    }

    #[test]
    fn monitor_ready_announces_text_when_on() {
        let (mut c, h, fake) = setup();
        h.set_enabled(true);
        fake.lock().unwrap().user_copies("local");
        feed(&mut c, &SERVER_CAPS);
        let out = feed(&mut c, &MONITOR_READY);
        assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_TEXT_LONG.to_vec()]);
        // Nothing to re-announce on the next tick.
        assert!(tick(&mut c).is_empty());
    }

    #[test]
    fn monitor_ready_on_without_text_sends_empty_list() {
        let (mut c, h, _) = setup();
        h.set_enabled(true);
        feed(&mut c, &SERVER_CAPS);
        let out = feed(&mut c, &MONITOR_READY);
        assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_EMPTY.to_vec()]);
    }

    #[test]
    fn short_names_without_server_long_name_flag() {
        let (mut c, h, fake) = setup();
        h.set_enabled(true);
        fake.lock().unwrap().user_copies("x");
        // Server capabilities without CB_USE_LONG_FORMAT_NAMES.
        let mut caps = SERVER_CAPS;
        caps[20] = 0x0c;
        feed(&mut c, &caps);
        let out = feed(&mut c, &MONITOR_READY);
        let mut want = vec![
            0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0d, 0, 0, 0,
        ];
        want.extend([0u8; 32]);
        assert_eq!(out[1], want);
    }

    #[test]
    fn format_list_encoding_long_and_short() {
        // Long: the first entries of MS-RDPECLIP 4.1.5.
        let list = format_list(&[(0xc004, "Native"), (3, ""), (8, ""), (17, "")], true);
        let spec_415: [u8; 44] = [
            0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x4e, 0x00,
            0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(list, spec_415);
        // Short: Unicode names in 32-byte blocks, truncated to 15 units + NUL.
        let short = format_list(
            &[(0xc004, "Native"), (0xc0ff, "ABCDEFGHIJKLMNOPQRS")],
            false,
        );
        assert_eq!(short.len(), 8 + 72);
        assert_eq!(&short[..8], &[0x02, 0, 0, 0, 72, 0, 0, 0]);
        assert_eq!(&short[8..12], &[0x04, 0xc0, 0, 0]);
        assert_eq!(&short[12..24], &utf16le("Native")[..]);
        assert!(short[24..44].iter().all(|&b| b == 0));
        assert_eq!(&short[48..78], &utf16le("ABCDEFGHIJKLMNO")[..]);
        assert_eq!(&short[78..80], &[0, 0]);
        let (_, f, body) = parse_header(&short).unwrap();
        assert_eq!(
            parse_format_list(f, body, false).unwrap(),
            vec![
                (0xc004, "Native".into()),
                (0xc0ff, "ABCDEFGHIJKLMNO".into())
            ]
        );
    }

    #[test]
    fn format_list_parsing() {
        let msg = spec_format_list_421();
        assert_eq!(msg.len(), 8 + 0xe0);
        let (t, f, body) = parse_header(&msg).unwrap();
        assert_eq!(t, CB_FORMAT_LIST);
        let list = parse_format_list(f, body, true).unwrap();
        let ids: Vec<u32> = list.iter().map(|(i, _)| *i).collect();
        assert_eq!(
            ids,
            [0xc08a, 0xc145, 0xc143, 1, 13, 0xc004, 0xc00e, 3, 16, 7]
        );
        assert_eq!(list[1].1, "Rich Text Format Without Objects");
        assert_eq!(list[6].1, "Object Descriptor");
        // ASCII short names (CB_ASCII_NAMES).
        let mut body = vec![0x04, 0xc0, 0, 0];
        body.extend(b"Native");
        body.resize(36, 0);
        assert_eq!(
            parse_format_list(CB_ASCII_NAMES, &body, false).unwrap(),
            vec![(0xc004, "Native".into())]
        );
        // Malformed data is an error, never a panic.
        assert!(parse_format_list(0, &body[..35], false).is_err());
        assert!(parse_format_list(0, &[13, 0, 0, 0, b'a', 0], true).is_err());
        assert!(parse_format_list(0, &[13, 0], true).is_err());
        assert!(parse_header(&[0x02, 0, 0, 0, 9, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn data_request_and_response_bytes() {
        assert_eq!(format_data_request(CF_UNICODETEXT), DATA_REQUEST_TEXT);
        assert_eq!(
            pdu(
                CB_FORMAT_DATA_RESPONSE,
                CB_RESPONSE_OK,
                &utf16le_z("hello world")
            ),
            DATA_RESPONSE_HELLO
        );
        let (_, _, body) = parse_header(&DATA_RESPONSE_HELLO).unwrap();
        assert_eq!(decode_text(body), "hello world");
        assert_eq!(decode_text(&[0x41, 0x00, 0x42]), "A");
    }

    #[test]
    fn remote_text_reaches_local_backend() {
        let (mut c, _h, fake) = connected(true);
        let out = feed(&mut c, &spec_format_list_421());
        assert_eq!(
            out,
            vec![LIST_RESPONSE_OK.to_vec(), DATA_REQUEST_TEXT.to_vec()]
        );
        assert!(feed(&mut c, &DATA_RESPONSE_HELLO).is_empty());
        assert_eq!(fake.lock().unwrap().writes, ["hello world"]);
        // No echo: our own write is not announced back.
        assert!(tick(&mut c).is_empty());
        assert!(tick(&mut c).is_empty());
    }

    #[test]
    fn remote_list_without_text_is_acknowledged_only() {
        let (mut c, _h, _) = connected(true);
        let out = feed(&mut c, &format_list(&[(0xc004, "Native")], true));
        assert_eq!(out, vec![LIST_RESPONSE_OK.to_vec()]);
    }

    #[test]
    fn local_change_is_announced_and_served() {
        let (mut c, _h, fake) = connected(true);
        fake.lock().unwrap().user_copies("hello world");
        assert_eq!(tick(&mut c), vec![LIST_TEXT_LONG.to_vec()]);
        assert!(tick(&mut c).is_empty(), "announced once");
        assert!(feed(&mut c, &LIST_RESPONSE_OK).is_empty());
        let out = feed(&mut c, &DATA_REQUEST_TEXT);
        assert_eq!(out, vec![DATA_RESPONSE_HELLO.to_vec()]);
        // Unknown formats fail.
        let out = feed(&mut c, &format_data_request(0xc004));
        assert_eq!(out, vec![DATA_RESPONSE_FAIL.to_vec()]);
    }

    #[test]
    fn sharing_off_blocks_both_directions() {
        let (mut c, h, fake) = connected(true);
        h.set_enabled(false);
        assert_eq!(
            tick(&mut c),
            vec![LIST_EMPTY.to_vec()],
            "withdrawn on switch off"
        );
        // Remote list: acknowledged, but no request and no local write.
        let out = feed(&mut c, &spec_format_list_421());
        assert_eq!(out, vec![LIST_RESPONSE_OK.to_vec()]);
        assert!(feed(&mut c, &DATA_RESPONSE_HELLO).is_empty());
        // Local copies are neither announced nor served.
        fake.lock().unwrap().user_copies("secret");
        assert!(tick(&mut c).is_empty());
        assert_eq!(
            feed(&mut c, &DATA_REQUEST_TEXT),
            vec![DATA_RESPONSE_FAIL.to_vec()]
        );
        assert!(fake.lock().unwrap().writes.is_empty());
    }

    #[test]
    fn response_after_switch_off_is_not_written() {
        let (mut c, h, fake) = connected(true);
        feed(&mut c, &spec_format_list_421());
        h.set_enabled(false);
        tick(&mut c);
        feed(&mut c, &DATA_RESPONSE_HELLO);
        assert!(fake.lock().unwrap().writes.is_empty());
    }

    #[test]
    fn switching_on_announces_local_text() {
        let (mut c, h, fake) = connected(false);
        fake.lock().unwrap().user_copies("hello world");
        assert!(tick(&mut c).is_empty());
        h.set_enabled(true);
        assert_eq!(tick(&mut c), vec![LIST_TEXT_LONG.to_vec()]);
        assert!(
            tick(&mut c).is_empty(),
            "the change made while off is not sent twice"
        );
        assert_eq!(
            feed(&mut c, &DATA_REQUEST_TEXT),
            vec![DATA_RESPONSE_HELLO.to_vec()]
        );
    }

    #[test]
    fn busy_clipboard_write_is_retried_on_tick() {
        let (mut c, _h, fake) = connected(true);
        fake.lock().unwrap().busy = 2;
        feed(&mut c, &spec_format_list_421());
        feed(&mut c, &DATA_RESPONSE_HELLO);
        assert!(fake.lock().unwrap().writes.is_empty());
        assert!(tick(&mut c).is_empty());
        assert!(tick(&mut c).is_empty());
        assert_eq!(fake.lock().unwrap().writes, ["hello world"]);
        assert!(tick(&mut c).is_empty(), "no echo after a retried write");
    }

    #[test]
    fn nothing_sent_before_monitor_ready() {
        let (mut c, h, fake) = setup();
        h.set_enabled(true);
        fake.lock().unwrap().user_copies("x");
        assert!(tick(&mut c).is_empty());
        // Lock / Unlock are accepted and ignored.
        assert!(feed(&mut c, &LOCK).is_empty());
        let mut unlock = LOCK;
        unlock[0] = 0x0b;
        assert!(feed(&mut c, &unlock).is_empty());
    }
}
