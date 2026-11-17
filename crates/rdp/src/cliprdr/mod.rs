//! Clipboard redirection, client side (MS-RDPECLIP) on the `cliprdr` static
//! virtual channel.
//!
//! Scope: Unicode text (CF_UNICODETEXT), images (CF_DIB, CF_DIBV5 and the
//! registered "PNG" format) and files (stream-based File List transfer, see
//! [`files`]) in both directions. Other formats (HTML, RTF) are answered
//! with CB_RESPONSE_FAIL.
//!
//! Server to local: a backend that can fill the local clipboard on demand
//! ([`ClipboardBackend::lazy_remote`], Windows: an OLE data object) gets a
//! [`RemoteOffer`] and fetches on paste ([`remote`]); other backends get the
//! text, and files copied into a temporary folder, right away.
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

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use crate::channel::{
    CHANNEL_OPTION_ENCRYPT_RDP, CHANNEL_OPTION_INITIALIZED, CHANNEL_OPTION_SHOW_PROTOCOL,
    ChannelOut, StaticChannel,
};
use crate::cursor::{Put, Reader, utf16le, utf16le_z};
use crate::error::{Result, proto};
use crate::trace;

pub mod files;
pub mod remote;

use files::{
    DROP_EFFECT_FORMAT, FILE_CONTENTS_FORMAT, FILE_LIST_FORMAT, Incoming, LOCAL_DROP_EFFECT_ID,
    LOCAL_FILE_CONTENTS_ID, LOCAL_FILE_LIST_ID, LocalEntry,
};
pub use files::{Direction, FileDescriptor, Transfer};
pub use remote::{Pending, RemoteFormat, RemoteOffer, RemoteSource};
use remote::{Reply, SourceRequest};

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
/// Standard clipboard format: a BITMAPINFO header, color table and bits.
pub const CF_DIB: u32 = 8;
/// Standard clipboard format: a BITMAPV5HEADER, color table and bits.
pub const CF_DIBV5: u32 = 17;
/// Registered name of PNG image data (browsers, Office, Snipping Tool).
pub const PNG_FORMAT: &str = "PNG";
/// Format id this client gives its own PNG data (a registered format, so
/// the peer maps it by name, MS-RDPECLIP 3.1.1.1).
pub const LOCAL_PNG_ID: u32 = 0xC0BD;

/// What the local clipboard holds, as far as this client shares it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalFormats {
    pub text: bool,
    /// A bitmap (Windows also counts CF_BITMAP and CF_DIBV5, which it
    /// converts to CF_DIB).
    pub dib: bool,
    pub png: bool,
    pub files: bool,
}

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

    /// True if this backend reads and writes file lists; only then does the
    /// client advertise file transfer. Read once, when the channel is made.
    fn supports_files(&self) -> bool {
        false
    }

    /// Absolute paths of the files and folders on the local clipboard
    /// (Windows: CF_HDROP), or None.
    fn read_files(&mut self) -> Option<Vec<PathBuf>> {
        None
    }

    /// Replaces the local clipboard with these files and folders, to be
    /// pasted as a copy (Windows: CF_HDROP and Preferred DropEffect).
    fn write_files(&mut self, _paths: &[PathBuf]) -> bool {
        false
    }

    /// The formats on the local clipboard. Called on every local change, so
    /// it must be cheap (Windows: IsClipboardFormatAvailable, no open).
    fn available(&mut self) -> LocalFormats {
        LocalFormats {
            text: self.read_text().is_some(),
            files: self.supports_files() && self.read_files().is_some_and(|f| !f.is_empty()),
            ..LocalFormats::default()
        }
    }

    /// The local image as CF_DIB bytes.
    fn read_dib(&mut self) -> Option<Vec<u8>> {
        None
    }

    /// The local image as PNG bytes, if the clipboard has that format.
    fn read_png(&mut self) -> Option<Vec<u8>> {
        None
    }

    /// True if this backend puts the server's clipboard on the local one on
    /// demand through [`Self::remote_offer`]; read once, when the channel is
    /// made. Otherwise the channel fetches text and files right away and
    /// writes them with [`Self::write_text`] and [`Self::write_files`].
    fn lazy_remote(&self) -> bool {
        false
    }

    /// The server's clipboard changed (`Some`), or what was offered before
    /// is no longer available (`None`: sharing off, session ended). On
    /// `None` the backend clears the local clipboard if it still holds
    /// the earlier offer.
    fn remote_offer(&mut self, _offer: Option<RemoteOffer>) {}

    /// True if the local clipboard currently holds this backend's own
    /// remote offer (so the change is not announced back to the server).
    fn owns_clipboard(&mut self) -> bool {
        false
    }
}

/// UI-side switch for clipboard sharing. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct ClipboardHandle {
    enabled: Arc<AtomicBool>,
    status: Arc<Mutex<Option<Transfer>>>,
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

    /// The file transfer in progress, if any.
    pub fn transfer(&self) -> Option<Transfer> {
        self.status.lock().ok().and_then(|s| s.clone())
    }
}

/// The default parent folder for files copied from a session:
/// `rdp-rs-clip` in the system temp folder, one subfolder per transfer.
pub fn default_file_root() -> PathBuf {
    std::env::temp_dir().join("rdp-rs-clip")
}

/// Creates the `cliprdr` channel handler and its UI switch. Sharing starts off.
pub fn cliprdr(backend: Box<dyn ClipboardBackend>) -> (Cliprdr, ClipboardHandle) {
    let enabled = Arc::new(AtomicBool::new(false));
    let status = Arc::new(Mutex::new(None));
    let handle = ClipboardHandle {
        enabled: enabled.clone(),
        status: status.clone(),
    };
    let (source_tx, source_rx) = mpsc::channel();
    let channel = Cliprdr {
        backend_files: backend.supports_files(),
        lazy: backend.lazy_remote(),
        backend,
        latest: Arc::new(AtomicU64::new(0)),
        offered: false,
        remote_ids: RemoteIds::default(),
        source_tx,
        source_rx,
        external: HashMap::new(),
        enabled,
        applied: false,
        ready: false,
        server_flags: 0,
        last_seq: 0,
        requested: VecDeque::new(),
        pending_write: None,
        file_root: default_file_root(),
        status,
        incoming: None,
        pending_files: None,
        outgoing: Vec::new(),
        served: 0,
        next_stream: 0,
    };
    (channel, handle)
}

/// Server format ids of the formats this client fetches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RemoteIds {
    text: Option<u32>,
    dib: Option<u32>,
    png: Option<u32>,
    files: Option<u32>,
}

impl RemoteIds {
    fn new(formats: &[(u32, String)], files: bool) -> Self {
        let id = |want: u32| formats.iter().any(|(id, _)| *id == want).then_some(want);
        let named = |want: &str| {
            formats
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(want))
                .map(|(id, _)| *id)
        };
        RemoteIds {
            text: id(CF_UNICODETEXT),
            dib: id(CF_DIB).or_else(|| id(CF_DIBV5)),
            png: named(PNG_FORMAT),
            files: if files { named(FILE_LIST_FORMAT) } else { None },
        }
    }

    fn get(&self, f: RemoteFormat) -> Option<u32> {
        match f {
            RemoteFormat::Text => self.text,
            RemoteFormat::Dib => self.dib,
            RemoteFormat::Png => self.png,
            RemoteFormat::FileList => self.files,
        }
    }
}

/// An outstanding Format Data Request.
enum Requested {
    /// The channel's own (text, or the File List of an eager transfer).
    Own(u32),
    /// A [`RemoteSource`] asked; the answer goes back on `Reply`.
    Source(Reply),
}

/// Client side of the clipboard virtual channel.
pub struct Cliprdr {
    backend: Box<dyn ClipboardBackend>,
    /// The backend takes [`RemoteOffer`]s.
    lazy: bool,
    /// Id of the latest offer; older [`RemoteSource`]s answer None.
    latest: Arc<AtomicU64>,
    /// An offer went to the backend and was not withdrawn.
    offered: bool,
    /// Server ids of the formats in the latest offer.
    remote_ids: RemoteIds,
    source_tx: mpsc::Sender<SourceRequest>,
    source_rx: mpsc::Receiver<SourceRequest>,
    /// File Contents Requests of sources, by streamId.
    external: HashMap<u32, Reply>,
    enabled: Arc<AtomicBool>,
    /// Sharing state last applied by `tick` (announced to the server).
    applied: bool,
    /// Monitor Ready was handled; the client may send Format Lists.
    ready: bool,
    /// generalFlags of the server's General Capability Set (0 if absent).
    server_flags: u32,
    /// Local clipboard sequence already seen (or caused by our own write).
    last_seq: u32,
    /// Our outstanding Format Data Requests, oldest first (responses carry
    /// no format id; MS-RDPECLIP 3.1.5.2.2).
    requested: VecDeque<Requested>,
    /// Remote text the busy local clipboard did not take yet, with tries left.
    pending_write: Option<(String, u8)>,
    /// The backend handles files.
    backend_files: bool,
    /// Parent of the per-transfer folders for remote files.
    file_root: PathBuf,
    /// Shared with [`ClipboardHandle::transfer`].
    status: Arc<Mutex<Option<Transfer>>>,
    /// Remote-to-local file transfer in progress.
    incoming: Option<Incoming>,
    /// Finished remote files the busy local clipboard did not take yet.
    pending_files: Option<(Vec<PathBuf>, u8)>,
    /// Local entries of the last File List sent, by lindex.
    outgoing: Vec<LocalEntry>,
    /// Bytes served from `outgoing`.
    served: u64,
    /// Last streamId used in a File Contents Request.
    next_stream: u32,
}

impl Cliprdr {
    /// Folder under which remote files are stored, one fresh subfolder per
    /// transfer (default: [`default_file_root`]).
    pub fn set_file_root(&mut self, root: PathBuf) {
        self.file_root = root;
    }

    fn sharing(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Long Format Names only if both sides set CB_USE_LONG_FORMAT_NAMES
    /// (MS-RDPECLIP 2.2.2.1.1.1).
    fn long_names(&self) -> bool {
        self.server_flags & CLIENT_GENERAL_FLAGS & CB_USE_LONG_FORMAT_NAMES != 0
    }

    fn send_format_list(&self, formats: &[(u32, &str)], out: &mut ChannelOut) {
        trace!(
            "cliprdr: format list with {} formats {}",
            formats.len(),
            describe(formats.iter().map(|&(id, n)| (id, n)))
        );
        out.send(format_list(formats, self.long_names()));
    }

    /// Formats to announce for the local clipboard: only those it holds
    /// (RDP-62: an image was announced as text before), files first.
    fn local_formats(&mut self) -> Vec<(u32, &'static str)> {
        let have = self.backend.available();
        let mut formats = Vec::new();
        if have.files && self.files_enabled() {
            // As Windows itself announces files: the list, the contents
            // format and the drop effect (a copy).
            formats.push((LOCAL_FILE_LIST_ID, FILE_LIST_FORMAT));
            formats.push((LOCAL_FILE_CONTENTS_ID, FILE_CONTENTS_FORMAT));
            formats.push((LOCAL_DROP_EFFECT_ID, DROP_EFFECT_FORMAT));
        }
        if have.text {
            formats.push((CF_UNICODETEXT, ""));
        }
        if have.dib {
            formats.push((CF_DIB, ""));
        }
        if have.png && self.long_names() {
            formats.push((LOCAL_PNG_ID, PNG_FORMAT));
        }
        formats
    }

    /// Format List with the local text or files if sharing is on and they
    /// are there.
    fn announce_current(&mut self, out: &mut ChannelOut, send_empty: bool) {
        let formats = if self.sharing() {
            self.local_formats()
        } else {
            Vec::new()
        };
        if !formats.is_empty() || send_empty {
            self.send_format_list(&formats, out);
        }
    }

    /// generalFlags of the client: long names, plus the file flags the
    /// server also set when the backend handles files (3.2.5.1.3).
    fn client_flags(&self) -> u32 {
        let mut flags = CLIENT_GENERAL_FLAGS;
        if self.backend_files {
            flags |= files::CLIENT_FILE_FLAGS & self.server_flags;
        }
        flags
    }

    /// Server Monitor Ready (MS-RDPECLIP 2.2.2.2, 3.2.5.1.2): the client
    /// sends its capabilities, then its Format List.
    fn monitor_ready(&mut self, out: &mut ChannelOut) {
        out.send(capabilities(self.client_flags()));
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
        trace!(
            "cliprdr: server offers {} formats {}",
            formats.len(),
            describe(formats.iter().map(|(id, n)| (*id, n.as_str())))
        );
        out.send(pdu(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[]));
        // A new remote copy replaces whatever was being fetched.
        self.cancel_incoming("new remote copy");
        self.pending_files = None;
        if !self.sharing() {
            return;
        }
        if self.lazy {
            self.offer_remote(&formats);
            return;
        }
        if self.files_enabled()
            && let Some((id, _)) = formats.iter().find(|(_, n)| n == FILE_LIST_FORMAT)
        {
            self.start_incoming(*id, out);
            return;
        }
        if formats.iter().any(|(id, _)| *id == CF_UNICODETEXT) {
            out.send(format_data_request(CF_UNICODETEXT));
            self.requested.push_back(Requested::Own(CF_UNICODETEXT));
        }
    }

    /// Hands the server's formats to a lazy backend as a new offer; older
    /// sources stop answering.
    fn offer_remote(&mut self, formats: &[(u32, String)]) {
        let ids = RemoteIds::new(formats, self.files_enabled());
        let id = remote::next_offer_id();
        self.latest.store(id, Ordering::Relaxed);
        self.external.clear();
        self.remote_ids = ids;
        let offer = RemoteOffer {
            id,
            text: ids.text.is_some(),
            dib: ids.dib.is_some(),
            dib_v5: ids.dib == Some(CF_DIBV5),
            png: ids.png.is_some(),
            files: ids.files.is_some(),
            source: RemoteSource {
                offer: id,
                tx: self.source_tx.clone(),
                latest: self.latest.clone(),
            },
        };
        if offer.any() {
            trace!(
                "cliprdr: offered on the local clipboard (text {}, image {}, png {}, files {})",
                offer.text, offer.dib, offer.png, offer.files
            );
            self.offered = true;
            self.backend.remote_offer(Some(offer));
        } else if self.offered {
            self.offered = false;
            self.backend.remote_offer(None);
        }
    }

    /// Ends the current offer: its sources answer None and the backend
    /// clears the local clipboard if it still holds it.
    fn withdraw_remote(&mut self) {
        self.latest
            .store(remote::next_offer_id(), Ordering::Relaxed);
        self.external.clear();
        if self.offered {
            self.offered = false;
            self.backend.remote_offer(None);
        }
    }

    /// Sends the requests sources made since the last tick.
    fn serve_sources(&mut self, out: &mut ChannelOut) {
        let latest = self.latest.load(Ordering::Relaxed);
        let on = self.sharing();
        while let Ok(req) = self.source_rx.try_recv() {
            match req {
                SourceRequest::Data {
                    offer,
                    format,
                    reply,
                } => {
                    let Some(id) = self
                        .remote_ids
                        .get(format)
                        .filter(|_| on && offer == latest)
                    else {
                        continue; // dropping `reply` answers None
                    };
                    out.send(format_data_request(id));
                    self.requested.push_back(Requested::Source(reply));
                }
                SourceRequest::Contents {
                    offer,
                    lindex,
                    position,
                    size,
                    reply,
                } => {
                    if !on || offer != latest || self.remote_ids.files.is_none() {
                        continue;
                    }
                    self.next_stream = self.next_stream.wrapping_add(1);
                    let (flags, n) = match size {
                        Some(n) => (files::FILECONTENTS_RANGE, n),
                        None => (files::FILECONTENTS_SIZE, 8),
                    };
                    out.send(files::file_contents_request(
                        self.next_stream,
                        lindex,
                        flags,
                        position,
                        n,
                    ));
                    self.external.insert(self.next_stream, reply);
                }
            }
        }
    }

    /// Answers a server Format Data Request (MS-RDPECLIP 2.2.5.1, 2.2.5.2).
    fn format_data(&mut self, format: u32) -> Vec<u8> {
        if !self.sharing() {
            return pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[]);
        }
        let data = match format {
            CF_UNICODETEXT => self.backend.read_text().map(|t| utf16le_z(&t)),
            CF_DIB => self.backend.read_dib(),
            LOCAL_PNG_ID => self.backend.read_png(),
            LOCAL_FILE_LIST_ID => self.local_file_list(),
            // DROPEFFECT_COPY: a paste copies, never moves.
            LOCAL_DROP_EFFECT_ID if !self.outgoing.is_empty() || self.files_enabled() => {
                Some(1u32.to_le_bytes().to_vec())
            }
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
        let format = match self.requested.pop_front() {
            None => {
                trace!("cliprdr: unsolicited format data response ignored");
                return;
            }
            Some(Requested::Source(reply)) => {
                let ok = flags & CB_RESPONSE_OK != 0 && self.sharing();
                trace!(
                    "cliprdr: format data for the local clipboard, {} bytes",
                    body.len()
                );
                let _ = reply.try_send(ok.then(|| body.to_vec()));
                return;
            }
            Some(Requested::Own(format)) => format,
        };
        if self
            .incoming
            .as_ref()
            .is_some_and(|i| i.format_id == format && !i.listed())
        {
            self.file_list_received(flags & CB_RESPONSE_OK != 0, body);
            return;
        }
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

    /// Clipboard data arrives as one Format Data Response: a full-screen
    /// bitmap of an 8K desktop is about 130 MB, so this channel allows
    /// more than the 16 MiB default (file contents come in 1 MiB ranges).
    fn max_message_size(&self) -> usize {
        256 << 20
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
            CB_FILECONTENTS_REQUEST => {
                let reply = self.serve_contents(body)?;
                out.send(reply);
            }
            CB_FILECONTENTS_RESPONSE => self.contents_received(flags, body)?,
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
                self.pending_files = None;
                self.cancel_incoming("sharing off");
                self.clear_outgoing();
                self.withdraw_remote();
                self.send_format_list(&[], out);
            }
            return Ok(());
        }
        self.serve_sources(out);
        if !on {
            return Ok(());
        }
        let seq = self.backend.sequence();
        if seq != self.last_seq {
            self.last_seq = seq;
            if self.backend.owns_clipboard() {
                // Our own remote offer landed on the local clipboard.
                return Ok(());
            }
            // A local copy wins over remote data still being fetched or
            // waiting to be written.
            self.pending_write = None;
            self.pending_files = None;
            self.cancel_incoming("new local copy");
            self.clear_outgoing();
            let formats = self.local_formats();
            self.send_format_list(&formats, out);
            return Ok(());
        }
        if self.pending_write.is_some() {
            self.try_write();
        }
        if self.pending_files.is_some() {
            self.try_write_files();
        }
        self.advance_incoming(out);
        Ok(())
    }
}

impl Drop for Cliprdr {
    /// The session is over: nothing offered can be fetched any more.
    fn drop(&mut self) {
        if self.offered {
            self.offered = false;
            self.backend.remote_offer(None);
        }
    }
}

/// "[13, 0xc0bc FileGroupDescriptorW]" for the log: ids and format names,
/// never contents.
fn describe<'a>(formats: impl Iterator<Item = (u32, &'a str)>) -> String {
    let parts: Vec<String> = formats
        .map(|(id, name)| {
            if name.is_empty() {
                format!("{id}")
            } else {
                format!("{id:#x} {name}")
            }
        })
        .collect();
    format!("[{}]", parts.join(", "))
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
mod tests;

#[cfg(test)]
mod files_tests;

#[cfg(test)]
mod remote_tests;
