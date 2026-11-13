//! File copy and paste over the clipboard channel with stream-based file
//! transfer (MS-RDPECLIP 1.3.2.3, 3.1.1.2, 3.1.5.4).
//!
//! - Remote to local: the server offers the File List format
//!   ("FileGroupDescriptorW"); the client fetches the Packed File List
//!   (2.2.5.2.3), then each file with File Contents Requests (2.2.5.3):
//!   FILECONTENTS_SIZE, then FILECONTENTS_RANGE in [`CHUNK`]-byte pieces,
//!   one request in flight, one per session tick. Files land in a fresh
//!   folder under the temp root, and the finished set goes to the local
//!   clipboard through [`super::ClipboardBackend::write_files`].
//! - Local to remote: local files (and directories, recursively) are
//!   announced as a File List and served from disk in bounded ranges.
//!
//! The Temporary Directory PDU (2.2.2.3) is not sent: it only serves direct
//! file access through paths (3.1.1.3), which CB_FILECLIP_NO_FILE_PATHS rules
//! out; streams need no shared folder.
//!
//! File data is never traced; names, counts and sizes may be.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    CB_FILECONTENTS_REQUEST, CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, CB_RESPONSE_OK, Cliprdr,
    pdu,
};
use crate::channel::ChannelOut;
use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Result, proto};
use crate::trace;

// General Capability Set flags for files (MS-RDPECLIP 2.2.2.1.1.1).
pub const CB_STREAM_FILECLIP_ENABLED: u32 = 0x0000_0004;
pub const CB_FILECLIP_NO_FILE_PATHS: u32 = 0x0000_0008;
pub const CB_CAN_LOCK_CLIPDATA: u32 = 0x0000_0010;
pub const CB_HUGE_FILE_SUPPORT_ENABLED: u32 = 0x0000_0020;

/// File flags the client advertises when its backend handles files; only
/// those the server also set are sent (3.2.5.1.3). Locking is not used.
pub(super) const CLIENT_FILE_FLAGS: u32 =
    CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS | CB_HUGE_FILE_SUPPORT_ENABLED;

// File Contents Request dwFlags (MS-RDPECLIP 2.2.5.3).
pub const FILECONTENTS_SIZE: u32 = 0x0000_0001;
pub const FILECONTENTS_RANGE: u32 = 0x0000_0002;

// File Descriptor flags and attributes (MS-RDPECLIP 2.2.5.2.3.1).
pub const FD_ATTRIBUTES: u32 = 0x0000_0004;
pub const FD_WRITESTIME: u32 = 0x0000_0020;
pub const FD_FILESIZE: u32 = 0x0000_0040;
pub const FD_SHOWPROGRESSUI: u32 = 0x0000_4000;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

/// Registered name of the File List format (MS-RDPECLIP 1.3.1.2, 4.5.1).
pub const FILE_LIST_FORMAT: &str = "FileGroupDescriptorW";
/// Format id this client gives its own File List (registered formats use
/// 0xC000 to 0xFFFF; the peer maps it by name, 3.1.1.1).
pub const LOCAL_FILE_LIST_ID: u32 = 0xC0BC;

/// Bytes per FILECONTENTS_RANGE request when fetching remote files.
pub const CHUNK: u32 = 1 << 20;
/// Largest total size of one remote-to-local transfer.
pub const MAX_TRANSFER_BYTES: u64 = 4 << 30;
/// Most entries in one file list, either direction.
pub const MAX_FILE_ENTRIES: usize = 65_536;
/// Largest range served to the server in one response.
const MAX_SERVED_RANGE: u32 = 8 << 20;
/// CLIPRDR_FILEDESCRIPTOR size: flags, reserved1, attributes, reserved2,
/// lastWriteTime, size high/low, 520-byte name.
const DESCRIPTOR_LEN: usize = 592;
/// fileName holds 260 UTF-16 units including the NUL.
const NAME_UNITS: usize = 260;
/// FILETIME of 1970-01-01 (100 ns intervals since 1601-01-01).
const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
/// Write attempts for a finished file set when the local clipboard is busy.
const WRITE_FILES_RETRIES: u8 = 25;

/// Which way a file transfer runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Server files being copied to this computer.
    ToLocal,
    /// Local files being read by the server.
    ToRemote,
}

/// Progress of the current file transfer, for the UI ([`super::ClipboardHandle::transfer`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub direction: Direction,
    /// Relative name of the file being transferred (backslash separated).
    pub name: String,
    pub done: u64,
    pub total: u64,
}

/// One CLIPRDR_FILEDESCRIPTOR (MS-RDPECLIP 2.2.5.2.3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDescriptor {
    pub flags: u32,
    pub attributes: u32,
    /// FILETIME: 100 ns intervals since 1601-01-01.
    pub write_time: u64,
    pub size: u64,
    /// Relative path with backslashes, at most 259 UTF-16 units.
    pub name: String,
}

impl FileDescriptor {
    pub fn is_dir(&self) -> bool {
        self.flags & FD_ATTRIBUTES != 0 && self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// Packed File List body (MS-RDPECLIP 2.2.5.2.3). Names longer than 259
/// UTF-16 units are cut (callers drop such entries before).
pub fn encode_file_list(files: &[FileDescriptor]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + files.len() * DESCRIPTOR_LEN);
    b.put_u32(files.len() as u32);
    for f in files {
        b.put_u32(f.flags);
        b.put_zeros(32);
        b.put_u32(f.attributes);
        b.put_zeros(16);
        b.put_bytes(&f.write_time.to_le_bytes());
        b.put_u32((f.size >> 32) as u32);
        b.put_u32(f.size as u32);
        let mut name = utf16le(&f.name);
        name.truncate((NAME_UNITS - 1) * 2);
        name.resize(NAME_UNITS * 2, 0);
        b.put_bytes(&name);
    }
    b
}

/// Parses a Packed File List body (MS-RDPECLIP 2.2.5.2.3).
pub fn parse_file_list(body: &[u8]) -> Result<Vec<FileDescriptor>> {
    let mut r = Reader::new(body);
    let count = r.u32()? as usize;
    if count > MAX_FILE_ENTRIES || count * DESCRIPTOR_LEN > r.remaining() {
        return proto(format!(
            "file list of {count} entries in {} bytes",
            body.len()
        ));
    }
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let flags = r.u32()?;
        r.skip(32)?;
        let attributes = r.u32()?;
        r.skip(16)?;
        let write_time = u64::from_le_bytes(r.array()?);
        let high = r.u32()? as u64;
        let low = r.u32()? as u64;
        let raw = r.bytes(NAME_UNITS * 2)?;
        files.push(FileDescriptor {
            flags,
            attributes,
            write_time,
            size: high << 32 | low,
            name: super::decode_text(raw),
        });
    }
    Ok(files)
}

/// File Contents Request PDU (MS-RDPECLIP 2.2.5.3), without clipDataId.
pub fn file_contents_request(
    stream_id: u32,
    lindex: u32,
    flags: u32,
    position: u64,
    requested: u32,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.put_u32(stream_id);
    b.put_u32(lindex);
    b.put_u32(flags);
    b.put_u32(position as u32);
    b.put_u32((position >> 32) as u32);
    b.put_u32(requested);
    pdu(CB_FILECONTENTS_REQUEST, 0, &b)
}

/// Fields of a File Contents Request PDU body (MS-RDPECLIP 2.2.5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileContentsRequest {
    pub stream_id: u32,
    pub lindex: i32,
    pub flags: u32,
    pub position: u64,
    pub requested: u32,
}

/// Parses a File Contents Request body; an optional clipDataId is ignored.
pub fn parse_file_contents_request(body: &[u8]) -> Result<FileContentsRequest> {
    let mut r = Reader::new(body);
    let stream_id = r.u32()?;
    let lindex = r.u32()? as i32;
    let flags = r.u32()?;
    let low = r.u32()? as u64;
    let high = r.u32()? as u64;
    let requested = r.u32()?;
    Ok(FileContentsRequest {
        stream_id,
        lindex,
        flags,
        position: high << 32 | low,
        requested,
    })
}

/// File Contents Response PDU (MS-RDPECLIP 2.2.5.4). A failure carries only
/// the streamId.
pub fn file_contents_response(stream_id: u32, data: Option<&[u8]>) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + data.map_or(0, <[u8]>::len));
    b.put_u32(stream_id);
    match data {
        Some(d) => {
            b.put_bytes(d);
            pdu(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, &b)
        }
        None => pdu(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, &b),
    }
}

/// A server file name as a path inside the temp folder, or None when it
/// could leave it or is not a plain Windows name: empty parts, `.`, `..`,
/// absolute or UNC paths, drive letters and streams (`:`), reserved device
/// names, characters Windows forbids, trailing dots or spaces.
pub fn safe_relative_path(name: &str) -> Option<PathBuf> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let mut path = PathBuf::new();
    for part in name.split(['\\', '/']) {
        let bad_char = |c: char| c < ' ' || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*');
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part.chars().any(bad_char)
        {
            return None;
        }
        let stem = part.split('.').next().unwrap_or(part).trim_end();
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
            return None;
        }
        path.push(part);
    }
    Some(path)
}

/// A validated entry of a remote file list.
struct RemoteEntry {
    rel: PathBuf,
    name: String,
    dir: bool,
    /// Index in the server's list (the lindex of requests).
    lindex: u32,
}

/// The file being written.
struct Current {
    file: File,
    size: u64,
    offset: u64,
}

/// What the outstanding File Contents Request asked for.
#[derive(Clone, Copy)]
enum Awaiting {
    Size,
    Range(u32),
}

/// A remote-to-local transfer.
pub(super) struct Incoming {
    /// The server's id of the File List format.
    pub(super) format_id: u32,
    /// None until the File List arrived.
    root: Option<PathBuf>,
    entries: Vec<RemoteEntry>,
    /// Next entry to fetch.
    index: usize,
    current: Option<Current>,
    awaiting: Option<(u32, Awaiting)>,
    /// Sum of the sizes the server reported with FILECONTENTS_SIZE.
    sized: u64,
    done: u64,
    total: u64,
}

impl Incoming {
    pub(super) fn new(format_id: u32) -> Self {
        Incoming {
            format_id,
            root: None,
            entries: Vec::new(),
            index: 0,
            current: None,
            awaiting: None,
            sized: 0,
            done: 0,
            total: 0,
        }
    }

    pub(super) fn listed(&self) -> bool {
        self.root.is_some()
    }

    /// Validates the list and creates the transfer folder and directories.
    fn start(
        &mut self,
        list: Vec<FileDescriptor>,
        temp_root: &Path,
    ) -> std::result::Result<(), String> {
        let mut total = 0u64;
        for (i, f) in list.into_iter().enumerate() {
            let Some(rel) = safe_relative_path(&f.name) else {
                return Err(format!("unsafe file name {:?}", f.name));
            };
            let dir = f.is_dir();
            if !dir && f.flags & FD_FILESIZE != 0 {
                total = total.saturating_add(f.size);
            }
            self.entries.push(RemoteEntry {
                rel,
                name: f.name,
                dir,
                lindex: i as u32,
            });
        }
        if total > MAX_TRANSFER_BYTES {
            return Err(format!(
                "{total} bytes over the {MAX_TRANSFER_BYTES}-byte limit"
            ));
        }
        self.total = total;
        let root = unique_dir(temp_root).map_err(|e| format!("temp folder: {e}"))?;
        self.root = Some(root.clone());
        for e in self.entries.iter().filter(|e| e.dir) {
            fs::create_dir_all(root.join(&e.rel)).map_err(|err| format!("{}: {err}", e.name))?;
        }
        Ok(())
    }

    /// The next request to send, or Ok(None) when all files are written.
    fn next_request(&mut self, stream_id: u32) -> std::result::Result<Option<Vec<u8>>, String> {
        if let Some(c) = &self.current {
            let lindex = self.entries[self.index].lindex;
            let n = (c.size - c.offset).min(CHUNK as u64) as u32;
            self.awaiting = Some((stream_id, Awaiting::Range(n)));
            return Ok(Some(file_contents_request(
                stream_id,
                lindex,
                FILECONTENTS_RANGE,
                c.offset,
                n,
            )));
        }
        while self.index < self.entries.len() && self.entries[self.index].dir {
            self.index += 1;
        }
        let Some(e) = self.entries.get(self.index) else {
            return Ok(None);
        };
        self.awaiting = Some((stream_id, Awaiting::Size));
        Ok(Some(file_contents_request(
            stream_id,
            e.lindex,
            FILECONTENTS_SIZE,
            0,
            8,
        )))
    }

    /// Handles a File Contents Response; Err aborts the transfer.
    fn response(
        &mut self,
        ok: bool,
        stream_id: u32,
        data: &[u8],
    ) -> std::result::Result<(), String> {
        let Some((want, kind)) = self.awaiting else {
            trace!("cliprdr: unsolicited file contents response ignored");
            return Ok(());
        };
        if stream_id != want {
            trace!("cliprdr: file contents response for stream {stream_id} ignored");
            return Ok(());
        }
        self.awaiting = None;
        let name = &self.entries[self.index].name;
        if !ok {
            return Err(format!("server failed {name}"));
        }
        match kind {
            Awaiting::Size => {
                let size = Reader::new(data)
                    .array::<8>()
                    .map(u64::from_le_bytes)
                    .map_err(|_| format!("size of {name}: {} bytes", data.len()))?;
                self.sized = self.sized.saturating_add(size);
                if self.sized > MAX_TRANSFER_BYTES {
                    return Err(format!("{name}: over the {MAX_TRANSFER_BYTES}-byte limit"));
                }
                let Some(root) = &self.root else {
                    return Err("no transfer folder".into());
                };
                let path = root.join(&self.entries[self.index].rel);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("{name}: {e}"))?;
                }
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|e| format!("{name}: {e}"))?;
                trace!("cliprdr: receiving {name}, {size} bytes");
                if size == 0 {
                    self.index += 1;
                } else {
                    self.current = Some(Current {
                        file,
                        size,
                        offset: 0,
                    });
                }
            }
            Awaiting::Range(n) => {
                if data.is_empty() || data.len() > n as usize {
                    return Err(format!("{name}: {} bytes for a {n}-byte range", data.len()));
                }
                let Some(c) = &mut self.current else {
                    return Err("range without a file".into());
                };
                c.file.write_all(data).map_err(|e| format!("{name}: {e}"))?;
                c.offset += data.len() as u64;
                self.done += data.len() as u64;
                if c.offset >= c.size {
                    self.current = None;
                    self.index += 1;
                }
            }
        }
        Ok(())
    }

    /// Top-level items of the finished transfer, in list order.
    fn top_level(&self) -> Vec<PathBuf> {
        let Some(root) = &self.root else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = Vec::new();
        for e in &self.entries {
            if let Some(first) = e.rel.components().next() {
                let p = root.join(first);
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        out
    }

    fn status(&self) -> Transfer {
        let name = self
            .entries
            .get(self.index)
            .map_or_else(String::new, |e| e.name.clone());
        Transfer {
            direction: Direction::ToLocal,
            name,
            done: self.done,
            total: self.total.max(self.done),
        }
    }

    /// Deletes the partial transfer folder.
    fn discard(mut self) {
        self.current = None; // close the file before deleting it
        if let Some(root) = self.root.take()
            && let Err(e) = fs::remove_dir_all(&root)
        {
            trace!("cliprdr: could not remove {}: {e}", root.display());
        }
    }
}

/// Creates `<temp_root>/<pid>-<time>-<n>`, a folder no one else uses.
fn unique_dir(temp_root: &Path) -> std::io::Result<PathBuf> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    fs::create_dir_all(temp_root)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut last = None;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = temp_root.join(format!("{}-{nanos:x}-{n}", std::process::id()));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no unique folder")))
}

/// A local file or directory offered to the server.
pub(super) struct LocalEntry {
    path: PathBuf,
    descriptor: FileDescriptor,
}

/// Lists local paths with their directory contents (directories before
/// their children, names sorted). Symbolic links to directories are not
/// followed; unreadable or vanished entries and names over 259 UTF-16
/// units are left out. Stops at [`MAX_FILE_ENTRIES`].
pub(super) fn collect_local(paths: &[PathBuf]) -> Vec<LocalEntry> {
    let mut out = Vec::new();
    for p in paths {
        let Some(name) = p.file_name() else {
            continue;
        };
        if let Ok(meta) = fs::metadata(p) {
            add_local(&mut out, p, name.to_string_lossy().into_owned(), &meta);
        }
    }
    out
}

fn add_local(out: &mut Vec<LocalEntry>, path: &Path, rel: String, meta: &fs::Metadata) {
    if out.len() >= MAX_FILE_ENTRIES {
        return;
    }
    if rel.encode_utf16().count() >= NAME_UNITS {
        trace!("cliprdr: {rel} has a name too long for a file list; left out");
        return;
    }
    let dir = meta.is_dir();
    let mut attributes = if dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    if meta.permissions().readonly() {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    let write_time = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| UNIX_EPOCH_FILETIME + (d.as_nanos() / 100) as u64);
    out.push(LocalEntry {
        path: path.to_path_buf(),
        descriptor: FileDescriptor {
            flags: FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME | FD_SHOWPROGRESSUI,
            attributes,
            write_time,
            size: if dir { 0 } else { meta.len() },
            name: rel.clone(),
        },
    });
    if !dir {
        return;
    }
    let Ok(read) = fs::read_dir(path) else {
        return;
    };
    let mut children: Vec<_> = read.filter_map(|e| e.ok()).collect();
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let Ok(link_meta) = child.metadata() else {
            continue;
        };
        let child_path = child.path();
        let meta = if link_meta.file_type().is_symlink() {
            match fs::metadata(&child_path) {
                Ok(m) if m.is_file() => m,
                _ => continue, // dangling, or a linked directory (no loops)
            }
        } else {
            link_meta
        };
        let child_rel = format!("{rel}\\{}", child.file_name().to_string_lossy());
        add_local(out, &child_path, child_rel, &meta);
    }
}

/// Reads at most `n` bytes of `path` at `position`; None if the file is
/// gone or the position lies past its end.
fn read_range(path: &Path, position: u64, n: u32) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if position > len {
        return None;
    }
    let n = (n.min(MAX_SERVED_RANGE) as u64).min(len - position);
    f.seek(SeekFrom::Start(position)).ok()?;
    let mut data = Vec::with_capacity(n as usize);
    f.take(n).read_to_end(&mut data).ok()?;
    Some(data)
}

impl Cliprdr {
    /// File transfer is possible: the backend handles files, both sides set
    /// CB_STREAM_FILECLIP_ENABLED, and long format names are in use (a
    /// short name cannot hold "FileGroupDescriptorW").
    pub(super) fn files_enabled(&self) -> bool {
        self.backend_files
            && self.long_names()
            && self.server_flags & CB_STREAM_FILECLIP_ENABLED != 0
    }

    fn set_status(&self, t: Option<Transfer>) {
        if let Ok(mut s) = self.status.lock() {
            *s = t;
        }
    }

    /// True if the local clipboard holds files the server can be offered.
    pub(super) fn local_has_files(&mut self) -> bool {
        self.files_enabled() && self.backend.read_files().is_some_and(|f| !f.is_empty())
    }

    /// Starts fetching the server's files: requests its File List.
    pub(super) fn start_incoming(&mut self, format_id: u32, out: &mut ChannelOut) {
        trace!("cliprdr: server offers files (format {format_id:#x})");
        out.send(super::format_data_request(format_id));
        self.requested.push_back(format_id);
        self.incoming = Some(Incoming::new(format_id));
    }

    /// Stops a running remote-to-local transfer and deletes its files.
    pub(super) fn cancel_incoming(&mut self, why: &str) {
        if let Some(inc) = self.incoming.take() {
            trace!("cliprdr: file transfer cancelled ({why})");
            inc.discard();
            self.set_status(None);
        }
    }

    /// The server's File List arrived (Format Data Response).
    pub(super) fn file_list_received(&mut self, ok: bool, body: &[u8]) {
        if !ok || !self.sharing() {
            self.cancel_incoming("no file list");
            return;
        }
        let list = match parse_file_list(body) {
            Ok(l) => l,
            Err(e) => {
                trace!("cliprdr: bad file list ({e})");
                self.cancel_incoming("bad file list");
                return;
            }
        };
        trace!("cliprdr: server file list with {} entries", list.len());
        let Some(inc) = &mut self.incoming else {
            return;
        };
        if let Err(e) = inc.start(list, &self.file_root) {
            trace!("cliprdr: file list rejected: {e}");
            self.cancel_incoming("rejected");
            return;
        }
        let status = inc.status();
        self.set_status(Some(status));
    }

    /// Sends the next File Contents Request of a running transfer, or
    /// hands the finished files to the local clipboard. Called per tick.
    pub(super) fn advance_incoming(&mut self, out: &mut ChannelOut) {
        let Some(inc) = &mut self.incoming else {
            return;
        };
        if !inc.listed() || inc.awaiting.is_some() {
            return;
        }
        self.next_stream = self.next_stream.wrapping_add(1);
        match inc.next_request(self.next_stream) {
            Ok(Some(req)) => out.send(req),
            Ok(None) => {
                let paths = inc.top_level();
                trace!(
                    "cliprdr: file transfer complete, {} bytes, {} items",
                    inc.done,
                    paths.len()
                );
                self.incoming = None;
                self.set_status(None);
                self.pending_files = Some((paths, WRITE_FILES_RETRIES));
                self.try_write_files();
            }
            Err(e) => {
                trace!("cliprdr: file transfer failed: {e}");
                self.cancel_incoming("failed");
            }
        }
    }

    /// Server File Contents Response (MS-RDPECLIP 2.2.5.4).
    pub(super) fn contents_received(&mut self, flags: u16, body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        let stream_id = r.u32()?;
        let Some(inc) = &mut self.incoming else {
            trace!("cliprdr: file contents response without a transfer ignored");
            return Ok(());
        };
        match inc.response(flags & CB_RESPONSE_OK != 0, stream_id, r.rest()) {
            Ok(()) => {
                let status = inc.status();
                self.set_status(Some(status));
            }
            Err(e) => {
                trace!("cliprdr: file transfer failed: {e}");
                self.cancel_incoming("failed");
            }
        }
        Ok(())
    }

    /// Puts finished remote files on the local clipboard; our own write is
    /// not announced back.
    pub(super) fn try_write_files(&mut self) {
        let Some((paths, tries)) = self.pending_files.take() else {
            return;
        };
        let ok = self.backend.write_files(&paths);
        self.last_seq = self.backend.sequence();
        if !ok && tries > 1 {
            self.pending_files = Some((paths, tries - 1));
        } else if !ok {
            trace!("cliprdr: local clipboard busy; remote files dropped");
        }
    }

    /// The local File List for a Format Data Request; remembers the entries
    /// so File Contents Requests can be served by index.
    pub(super) fn local_file_list(&mut self) -> Option<Vec<u8>> {
        if !self.files_enabled() {
            return None;
        }
        let paths = self.backend.read_files()?;
        let entries = collect_local(&paths);
        if entries.is_empty() {
            return None;
        }
        let descriptors: Vec<FileDescriptor> =
            entries.iter().map(|e| e.descriptor.clone()).collect();
        trace!("cliprdr: sending file list with {} entries", entries.len());
        self.served = 0;
        self.outgoing = entries;
        Some(encode_file_list(&descriptors))
    }

    /// Forgets the served file list (the local clipboard changed).
    pub(super) fn clear_outgoing(&mut self) {
        if !self.outgoing.is_empty() {
            self.outgoing.clear();
            if let Ok(mut s) = self.status.lock()
                && s.as_ref()
                    .is_some_and(|t| t.direction == Direction::ToRemote)
            {
                *s = None;
            }
        }
    }

    /// Answers a server File Contents Request (MS-RDPECLIP 2.2.5.3, 2.2.5.4)
    /// from the local files of the last File List sent.
    pub(super) fn serve_contents(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let req = parse_file_contents_request(body)?;
        let fail = file_contents_response(req.stream_id, None);
        if !self.sharing() || !self.files_enabled() {
            return Ok(fail);
        }
        let Some(entry) = usize::try_from(req.lindex)
            .ok()
            .and_then(|i| self.outgoing.get(i))
        else {
            trace!(
                "cliprdr: file contents request for unknown index {}",
                req.lindex
            );
            return Ok(fail);
        };
        if entry.descriptor.is_dir() {
            return Ok(fail);
        }
        let reply = match req.flags {
            FILECONTENTS_SIZE => fs::metadata(&entry.path)
                .ok()
                .filter(|m| m.is_file())
                .map(|m| m.len().to_le_bytes().to_vec()),
            FILECONTENTS_RANGE => read_range(&entry.path, req.position, req.requested),
            _ => None,
        };
        let Some(data) = reply else {
            trace!("cliprdr: {} not available", entry.descriptor.name);
            return Ok(fail);
        };
        if req.flags == FILECONTENTS_RANGE {
            let total: u64 = self.outgoing.iter().map(|e| e.descriptor.size).sum();
            self.served = self.served.saturating_add(data.len() as u64);
            let status = (self.served < total).then(|| Transfer {
                direction: Direction::ToRemote,
                name: entry.descriptor.name.clone(),
                done: self.served,
                total,
            });
            self.set_status(status);
        }
        Ok(file_contents_response(req.stream_id, Some(&data)))
    }
}
