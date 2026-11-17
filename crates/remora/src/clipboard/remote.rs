//! The server's clipboard on this PC's clipboard, fetched when something
//! pastes (RDP-62, RDP-63), like mstsc does it.
//!
//! A thread of its own ("clipboard", an OLE single-threaded apartment with a
//! message loop) puts an OLE data object on the clipboard for every server
//! copy. Pasting programs call into that object on this thread:
//!
//! - text and images are fetched whole from the server (Format Data
//!   Request) the first time, then kept;
//! - files are *virtual files*: `FileGroupDescriptorW` lists them (fetched
//!   on the first paste), and `FileContents` hands out one stream per file
//!   that reads the server's file in 1 MiB ranges, a few ranges ahead.
//!   Explorer copies from those streams with its own progress dialog, so
//!   nothing is downloaded before a paste and there is no size limit.
//!
//! Waiting for the server blocks only this thread, never the UI or the
//! session. When the offer ends (sharing off, session closed) the object
//! keeps what it already fetched: text and images stay pasteable, files
//! do not.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use rdp::cliprdr::files::{
    FD_ATTRIBUTES, FD_FILESIZE, FD_SHOWPROGRESSUI, FD_WRITESTIME, FileDescriptor, encode_file_list,
    safe_relative_path,
};
use rdp::cliprdr::remote::wait;
use rdp::cliprdr::{Pending, RemoteFormat, RemoteOffer, RemoteSource};
use windows::Win32::Foundation::{
    CLIPBRD_E_CANT_OPEN, DATA_S_SAMEFORMATETC, DV_E_DVASPECT, DV_E_FORMATETC, DV_E_LINDEX,
    DV_E_TYMED, E_FAIL, E_INVALIDARG, E_NOTIMPL, E_POINTER, FILETIME, HGLOBAL, LPARAM,
    OLE_E_ADVISENOTSUPPORTED, S_OK, STG_E_ACCESSDENIED, WPARAM,
};
use windows::Win32::System::Com::{
    CoTaskMemAlloc, DATADIR_GET, DVASPECT_CONTENT, FORMATETC, IAdviseSink, IDataObject,
    IDataObject_Impl, IEnumFORMATETC, IEnumSTATDATA, ISequentialStream_Impl, IStream, IStream_Impl,
    LOCKTYPE, STATFLAG, STATFLAG_NONAME, STATSTG, STGC, STGMEDIUM, STGMEDIUM_0, STGTY_STREAM,
    STREAM_SEEK, STREAM_SEEK_CUR, STREAM_SEEK_END, STREAM_SEEK_SET, TYMED_HGLOBAL, TYMED_ISTREAM,
};
use windows::Win32::System::DataExchange::RegisterClipboardFormatW;
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::{OleFlushClipboard, OleInitialize, OleSetClipboard};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::{
    CFSTR_FILECONTENTS, CFSTR_FILEDESCRIPTORW, CFSTR_PREFERREDDROPEFFECT, SHCreateStdEnumFmtEtc,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW,
    TranslateMessage, WM_APP, WM_USER,
};
use windows::core::{BOOL, HRESULT, PCWSTR, Ref, implement};

/// Longest wait for a whole format or the file list.
const FETCH: Duration = Duration::from_secs(60);
/// Bytes per File Contents Request of a stream.
const RANGE: u32 = 1 << 20;
/// Ranges a stream keeps in flight ahead of its reader.
const AHEAD: usize = 4;
/// Longest wait for one range.
const RANGE_WAIT: Duration = Duration::from_secs(60);
/// Attempts to take the clipboard when another program holds it open.
const SET_ATTEMPTS: u32 = 20;

const CF_UNICODETEXT: u16 = 13;
const CF_DIB: u16 = 8;
const CF_DIBV5: u16 = 17;
/// DROPEFFECT_COPY: a paste copies.
const DROPEFFECT_COPY: u32 = 1;

enum Cmd {
    Offer(RemoteOffer),
    /// The offer with this id ended.
    Withdraw(u64),
    /// Read this PC's virtual files (for the server, RDP-63).
    Local(LocalRead, mpsc::Sender<Option<Vec<u8>>>),
}

/// What the server reads of this PC's virtual files.
pub enum LocalRead {
    /// The FILEGROUPDESCRIPTORW bytes.
    List,
    Range {
        lindex: u32,
        position: u64,
        size: u32,
    },
}

/// The stream of the virtual file read last, kept for the next range.
struct LocalStream {
    seq: u32,
    lindex: u32,
    data: LocalData,
}

enum LocalData {
    Stream(IStream),
    Bytes(Vec<u8>),
}

/// Longest wait for this PC's clipboard to hand over virtual file data.
const LOCAL_WAIT: Duration = Duration::from_secs(30);

/// Reads this PC's virtual files on the clipboard thread (COM lives there,
/// never on a session's thread).
pub fn read_local(req: LocalRead) -> Option<Vec<u8>> {
    clip_thread()?;
    let (tx, rx) = mpsc::channel();
    post(Cmd::Local(req, tx));
    rx.recv_timeout(LOCAL_WAIT).ok().flatten()
}

struct ClipThread {
    tx: Mutex<mpsc::Sender<Cmd>>,
    tid: u32,
}

/// Thread id of the clipboard thread (0 before it runs).
static TID: AtomicU32 = AtomicU32::new(0);
/// Id of the offer on the clipboard (0: none).
static CURRENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn clip_thread() -> Option<&'static ClipThread> {
    static THREAD: OnceLock<Option<ClipThread>> = OnceLock::new();
    THREAD
        .get_or_init(|| {
            let (tx, rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            std::thread::Builder::new()
                .name("clipboard".into())
                .spawn(move || run(rx, ready_tx))
                .ok()?;
            let tid = ready_rx.recv_timeout(Duration::from_secs(10)).ok()??;
            Some(ClipThread {
                tx: Mutex::new(tx),
                tid,
            })
        })
        .as_ref()
}

fn post(cmd: Cmd) {
    let Some(t) = clip_thread() else {
        rdp::trace!("clipboard: no clipboard thread; server copy not offered");
        return;
    };
    if t.tx.lock().map(|tx| tx.send(cmd).is_ok()).unwrap_or(false) {
        // SAFETY: posting to a thread that has a message queue.
        let _ = unsafe { PostThreadMessageW(t.tid, WM_APP, WPARAM(0), LPARAM(0)) };
    }
}

/// Puts a server copy on this PC's clipboard.
pub fn offer(o: RemoteOffer) {
    post(Cmd::Offer(o));
}

/// The offer `id` ended; the clipboard keeps only what was fetched.
pub fn withdraw(id: u64) {
    post(Cmd::Withdraw(id));
}

/// True if the clipboard holds offer `id` (a session's own server copy: it
/// is neither announced back to that server nor read for it, since reading
/// would render through that very session).
pub fn holds(id: Option<u64>) -> bool {
    id.is_some_and(|id| id == CURRENT.load(Ordering::Relaxed)) && owns()
}

/// True if the clipboard currently holds one of our offers (its owner is
/// OLE's clipboard window, which lives on our clipboard thread).
pub fn owns() -> bool {
    let tid = TID.load(Ordering::Relaxed);
    if tid == 0 {
        return false;
    }
    use windows_sys::Win32::System::DataExchange::GetClipboardOwner;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
    // SAFETY: plain queries; a null owner gives thread id 0.
    unsafe {
        let owner = GetClipboardOwner();
        !owner.is_null() && GetWindowThreadProcessId(owner, std::ptr::null_mut()) == tid
    }
}

fn run(rx: mpsc::Receiver<Cmd>, ready: mpsc::Sender<Option<u32>>) {
    // SAFETY: OLE on this thread for its whole life; the message loop below
    // dispatches the calls other programs make into our data objects.
    unsafe {
        if let Err(e) = OleInitialize(None) {
            rdp::trace!("clipboard: OleInitialize failed: {e}");
            let _ = ready.send(None);
            return;
        }
        let mut msg = MSG::default();
        // Creates this thread's message queue before anyone posts to it.
        let _ = PeekMessageW(&mut msg, None, WM_USER, WM_USER, PM_NOREMOVE);
        let tid = GetCurrentThreadId();
        TID.store(tid, Ordering::Relaxed);
        let _ = ready.send(Some(tid));
        let mut current: Option<(u64, IDataObject, Arc<Cache>)> = None;
        let mut local: Option<LocalStream> = None;
        loop {
            let r = GetMessageW(&mut msg, None, 0, 0);
            if r.0 <= 0 {
                break;
            }
            if !(msg.message == WM_APP && msg.hwnd.is_invalid()) {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            // Thread messages can get lost in modal loops: always drain.
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    Cmd::Local(req, reply) => {
                        let _ = reply.send(local_read(req, &mut local));
                    }
                    cmd => handle(cmd, &mut current),
                }
            }
        }
    }
}

/// The bytes of an HGLOBAL medium (released here).
///
/// # Safety
/// `m` is a medium GetData returned with TYMED_HGLOBAL.
unsafe fn take_hglobal(m: &mut STGMEDIUM) -> Option<Vec<u8>> {
    use windows::Win32::System::Memory::GlobalSize;
    unsafe {
        let h = m.u.hGlobal;
        let n = GlobalSize(h);
        let p = GlobalLock(h) as *const u8;
        let v = (!p.is_null()).then(|| std::slice::from_raw_parts(p, n).to_vec());
        let _ = GlobalUnlock(h);
        windows::Win32::System::Ole::ReleaseStgMedium(m);
        v
    }
}

/// Reads this PC's clipboard as the paste of a virtual file would.
fn local_read(req: LocalRead, cache: &mut Option<LocalStream>) -> Option<Vec<u8>> {
    use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
    use windows::Win32::System::Ole::OleGetClipboard;
    // SAFETY: OLE on the clipboard thread.
    let obj = unsafe { OleGetClipboard() }.ok()?;
    // SAFETY: a plain counter read.
    let seq = unsafe { GetClipboardSequenceNumber() };
    read_virtual(&obj, seq, req, cache)
}

/// Reads virtual files of a data object; `seq` tells when a cached stream
/// belongs to older contents.
fn read_virtual(
    obj: &IDataObject,
    seq: u32,
    req: LocalRead,
    cache: &mut Option<LocalStream>,
) -> Option<Vec<u8>> {
    let cf = Formats::get();
    // SAFETY: OLE calls on this thread; every medium is released.
    unsafe {
        match req {
            LocalRead::List => {
                let mut m = obj.GetData(&etc(cf.descriptor, TYMED_HGLOBAL.0)).ok()?;
                take_hglobal(&mut m)
            }
            LocalRead::Range {
                lindex,
                position,
                size,
            } => {
                if !cache
                    .as_ref()
                    .is_some_and(|c| c.seq == seq && c.lindex == lindex)
                {
                    let mut f = etc(cf.contents, TYMED_ISTREAM.0 | TYMED_HGLOBAL.0);
                    f.lindex = lindex as i32;
                    let mut m = obj.GetData(&f).ok()?;
                    let data = if m.tymed == TYMED_ISTREAM.0 as u32 {
                        let s = (*m.u.pstm).clone();
                        windows::Win32::System::Ole::ReleaseStgMedium(&mut m);
                        LocalData::Stream(s?)
                    } else {
                        LocalData::Bytes(take_hglobal(&mut m)?)
                    };
                    *cache = Some(LocalStream { seq, lindex, data });
                }
                match &cache.as_ref()?.data {
                    LocalData::Bytes(b) => {
                        let from = (position as usize).min(b.len());
                        let to = from.saturating_add(size as usize).min(b.len());
                        Some(b[from..to].to_vec())
                    }
                    LocalData::Stream(s) => {
                        s.Seek(position as i64, STREAM_SEEK_SET, None).ok()?;
                        let mut out = vec![0u8; size as usize];
                        let mut done = 0usize;
                        while done < out.len() {
                            let mut n = 0u32;
                            let hr = s.Read(
                                out[done..].as_mut_ptr().cast(),
                                (out.len() - done) as u32,
                                Some(&mut n),
                            );
                            if hr.is_err() {
                                return None;
                            }
                            if n == 0 {
                                break;
                            }
                            done += n as usize;
                        }
                        out.truncate(done);
                        Some(out)
                    }
                }
            }
        }
    }
}

fn handle(cmd: Cmd, current: &mut Option<(u64, IDataObject, Arc<Cache>)>) {
    match cmd {
        Cmd::Local(..) => {}
        Cmd::Offer(o) => {
            let id = o.id;
            let (obj, cache) = RemoteData::create(o);
            // Set before the clipboard changes, so the session never sees
            // its own copy as a new local one (it would echo it back).
            let before = CURRENT.swap(id, Ordering::Relaxed);
            for attempt in 0..SET_ATTEMPTS {
                // SAFETY: a live data object; OLE keeps a reference.
                match unsafe { OleSetClipboard(&obj) } {
                    Ok(()) => {
                        rdp::trace!("clipboard: server copy {id} on the local clipboard");
                        *current = Some((id, obj, cache));
                        return;
                    }
                    Err(e) if e.code() == CLIPBRD_E_CANT_OPEN && attempt + 1 < SET_ATTEMPTS => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(e) => {
                        rdp::trace!("clipboard: OleSetClipboard failed: {e}");
                        CURRENT.store(before, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
        Cmd::Withdraw(id) => {
            let Some((cur, _, cache)) = current.as_ref() else {
                return;
            };
            if *cur != id {
                return;
            }
            cache.close();
            if owns() {
                // Keeps what was fetched (text, images) as plain clipboard
                // data; formats that need the server are left out.
                // SAFETY: our object is the clipboard's; OLE renders it.
                if let Err(e) = unsafe { OleFlushClipboard() } {
                    rdp::trace!("clipboard: flush failed: {e}");
                }
            }
            CURRENT.store(0, Ordering::Relaxed);
            *current = None;
        }
    }
}

/// Registered clipboard format ids.
#[derive(Clone, Copy)]
struct Formats {
    descriptor: u16,
    contents: u16,
    effect: u16,
    png: u16,
}

fn register(name: PCWSTR) -> u16 {
    // SAFETY: a NUL-terminated constant name.
    unsafe { RegisterClipboardFormatW(name) as u16 }
}

impl Formats {
    fn get() -> Self {
        static F: OnceLock<Formats> = OnceLock::new();
        *F.get_or_init(|| Formats {
            descriptor: register(CFSTR_FILEDESCRIPTORW),
            contents: register(CFSTR_FILECONTENTS),
            effect: register(CFSTR_PREFERREDDROPEFFECT),
            png: register(windows::core::w!("PNG")),
        })
    }
}

/// What a data object has fetched, shared with its thread for the flush.
#[derive(Default)]
struct Cache {
    data: Mutex<HashMap<u16, Arc<Vec<u8>>>>,
    list: Mutex<Option<Arc<Vec<FileDescriptor>>>>,
    /// The offer ended: serve only what is cached.
    closed: std::sync::atomic::AtomicBool,
}

impl Cache {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// The OLE data object of one server copy.
#[implement(IDataObject)]
struct RemoteData {
    offer: RemoteOffer,
    formats: Vec<FORMATETC>,
    cf: Formats,
    cache: Arc<Cache>,
}

fn etc(cf: u16, tymed: i32) -> FORMATETC {
    FORMATETC {
        cfFormat: cf,
        ptd: std::ptr::null_mut(),
        dwAspect: DVASPECT_CONTENT.0,
        lindex: -1,
        tymed: tymed as u32,
    }
}

impl RemoteData {
    fn create(offer: RemoteOffer) -> (IDataObject, Arc<Cache>) {
        let cf = Formats::get();
        let mut formats = Vec::new();
        if offer.files {
            formats.push(etc(cf.descriptor, TYMED_HGLOBAL.0));
            formats.push(etc(cf.contents, TYMED_ISTREAM.0));
            formats.push(etc(cf.effect, TYMED_HGLOBAL.0));
        }
        if offer.text {
            formats.push(etc(CF_UNICODETEXT, TYMED_HGLOBAL.0));
        }
        if offer.png {
            formats.push(etc(cf.png, TYMED_HGLOBAL.0));
        }
        if offer.dib {
            let dib = if offer.dib_v5 { CF_DIBV5 } else { CF_DIB };
            formats.push(etc(dib, TYMED_HGLOBAL.0));
        }
        let cache = Arc::new(Cache::default());
        let obj = RemoteData {
            offer,
            formats,
            cf,
            cache: cache.clone(),
        };
        (obj.into(), cache)
    }

    fn offers(&self, f: &FORMATETC) -> Result<(), HRESULT> {
        if f.dwAspect != DVASPECT_CONTENT.0 {
            return Err(DV_E_DVASPECT);
        }
        let Some(mine) = self.formats.iter().find(|m| m.cfFormat == f.cfFormat) else {
            return Err(DV_E_FORMATETC);
        };
        if f.tymed & mine.tymed == 0 {
            return Err(DV_E_TYMED);
        }
        if f.cfFormat != self.cf.contents && f.lindex != -1 {
            return Err(DV_E_LINDEX);
        }
        Ok(())
    }

    /// A whole format, from the cache or the server.
    fn fetch(&self, cf: u16, format: RemoteFormat) -> Option<Arc<Vec<u8>>> {
        if let Some(d) = self.cache.data.lock().ok()?.get(&cf) {
            return Some(d.clone());
        }
        if self.cache.closed() {
            return None;
        }
        let d = Arc::new(wait(&self.offer.source.data(format), FETCH)?);
        rdp::trace!(
            "clipboard: fetched format {cf} from the server, {} bytes",
            d.len()
        );
        self.cache.data.lock().ok()?.insert(cf, d.clone());
        Some(d)
    }

    /// The server's file list, checked: names must stay inside the folder
    /// they are pasted into.
    fn list(&self) -> Option<Arc<Vec<FileDescriptor>>> {
        if let Some(l) = self.cache.list.lock().ok()?.as_ref() {
            return Some(l.clone());
        }
        if self.cache.closed() {
            return None;
        }
        let list = self.offer.source.file_list(FETCH)?;
        if let Some(bad) = list.iter().find(|f| safe_relative_path(&f.name).is_none()) {
            rdp::trace!(
                "clipboard: unsafe name {:?} in the server's file list",
                bad.name
            );
            return None;
        }
        rdp::trace!("clipboard: server file list with {} entries", list.len());
        let list = Arc::new(list);
        *self.cache.list.lock().ok()? = Some(list.clone());
        Some(list)
    }

    fn stream(&self, lindex: i32) -> Result<IStream, HRESULT> {
        if self.cache.closed() {
            return Err(E_FAIL);
        }
        let list = self.list().ok_or(E_FAIL)?;
        let i = usize::try_from(lindex).map_err(|_| DV_E_LINDEX)?;
        let f = list.get(i).ok_or(DV_E_LINDEX)?;
        if f.is_dir() {
            return Err(DV_E_LINDEX);
        }
        let size = if f.flags & FD_FILESIZE != 0 {
            f.size
        } else {
            let b = wait(&self.offer.source.size(i as u32), FETCH).ok_or(E_FAIL)?;
            u64::from_le_bytes(b.get(..8).ok_or(E_FAIL)?.try_into().map_err(|_| E_FAIL)?)
        };
        rdp::trace!("clipboard: paste reads {} ({size} bytes)", f.name);
        Ok(RemoteStream::new(
            self.offer.source.clone(),
            i as u32,
            size,
            f.name.clone(),
            f.write_time,
        )
        .into())
    }
}

/// A movable global block with these bytes.
fn hglobal(bytes: &[u8]) -> Result<HGLOBAL, HRESULT> {
    // SAFETY: a fresh block of the right size, locked while copying.
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)).map_err(|e| e.code())?;
        let p = GlobalLock(mem) as *mut u8;
        if p.is_null() {
            return Err(E_FAIL);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        let _ = GlobalUnlock(mem);
        Ok(mem)
    }
}

fn hglobal_medium(bytes: &[u8]) -> Result<STGMEDIUM, HRESULT> {
    Ok(STGMEDIUM {
        tymed: TYMED_HGLOBAL.0 as u32,
        u: STGMEDIUM_0 {
            hGlobal: hglobal(bytes)?,
        },
        pUnkForRelease: std::mem::ManuallyDrop::new(None),
    })
}

/// The File List as FILEGROUPDESCRIPTORW: the same layout as MS-RDPECLIP's
/// Packed File List, with flags the shell needs (sizes, times, progress).
fn group_descriptor(list: &[FileDescriptor]) -> Vec<u8> {
    let list: Vec<FileDescriptor> = list
        .iter()
        .map(|f| FileDescriptor {
            flags: (f.flags & (FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME)) | FD_SHOWPROGRESSUI,
            ..f.clone()
        })
        .collect();
    encode_file_list(&list)
}

impl IDataObject_Impl for RemoteData_Impl {
    fn GetData(&self, pformatetcin: *const FORMATETC) -> windows::core::Result<STGMEDIUM> {
        // SAFETY: COM passes a valid FORMATETC or null.
        let f = unsafe { pformatetcin.as_ref() }.ok_or(E_POINTER)?;
        self.offers(f)?;
        let cf = f.cfFormat;
        let bytes = if cf == self.cf.contents {
            let stream = self.stream(f.lindex)?;
            return Ok(STGMEDIUM {
                tymed: TYMED_ISTREAM.0 as u32,
                u: STGMEDIUM_0 {
                    pstm: std::mem::ManuallyDrop::new(Some(stream)),
                },
                pUnkForRelease: std::mem::ManuallyDrop::new(None),
            });
        } else if cf == self.cf.descriptor {
            if self.cache.closed() {
                return Err(E_FAIL.into());
            }
            Arc::new(group_descriptor(&self.list().ok_or(E_FAIL)?))
        } else if cf == self.cf.effect {
            Arc::new(DROPEFFECT_COPY.to_le_bytes().to_vec())
        } else if cf == CF_UNICODETEXT {
            self.fetch(cf, RemoteFormat::Text).ok_or(E_FAIL)?
        } else if cf == self.cf.png {
            self.fetch(cf, RemoteFormat::Png).ok_or(E_FAIL)?
        } else if cf == CF_DIB || cf == CF_DIBV5 {
            self.fetch(cf, RemoteFormat::Dib).ok_or(E_FAIL)?
        } else {
            return Err(DV_E_FORMATETC.into());
        };
        Ok(hglobal_medium(&bytes)?)
    }

    fn GetDataHere(&self, _: *const FORMATETC, _: *mut STGMEDIUM) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn QueryGetData(&self, pformatetc: *const FORMATETC) -> HRESULT {
        // SAFETY: COM passes a valid FORMATETC or null.
        match unsafe { pformatetc.as_ref() } {
            None => E_POINTER,
            Some(f) => match self.offers(f) {
                Ok(()) => S_OK,
                Err(e) => e,
            },
        }
    }

    fn GetCanonicalFormatEtc(&self, _: *const FORMATETC, out: *mut FORMATETC) -> HRESULT {
        // SAFETY: COM passes a valid out pointer or null.
        if let Some(out) = unsafe { out.as_mut() } {
            out.ptd = std::ptr::null_mut();
        }
        DATA_S_SAMEFORMATETC
    }

    fn SetData(
        &self,
        _: *const FORMATETC,
        pmedium: *const STGMEDIUM,
        frelease: BOOL,
    ) -> windows::core::Result<()> {
        // The shell reports "Performed DropEffect" and "Paste Succeeded"
        // here; nothing to keep. A medium handed over is ours to release.
        if frelease.as_bool() && !pmedium.is_null() {
            // SAFETY: the caller transferred ownership of this medium.
            unsafe { windows::Win32::System::Ole::ReleaseStgMedium(pmedium as *mut _) };
        }
        Ok(())
    }

    fn EnumFormatEtc(&self, dwdirection: u32) -> windows::core::Result<IEnumFORMATETC> {
        if dwdirection as i32 != DATADIR_GET.0 {
            return Err(E_NOTIMPL.into());
        }
        // SAFETY: the shell copies the array.
        unsafe { SHCreateStdEnumFmtEtc(&self.formats) }
    }

    fn DAdvise(
        &self,
        _: *const FORMATETC,
        _: u32,
        _: Ref<IAdviseSink>,
    ) -> windows::core::Result<u32> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }

    fn DUnadvise(&self, _: u32) -> windows::core::Result<()> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }

    fn EnumDAdvise(&self) -> windows::core::Result<IEnumSTATDATA> {
        Err(OLE_E_ADVISENOTSUPPORTED.into())
    }
}

/// Reading position and the ranges in flight of a stream.
struct Reader {
    pos: u64,
    /// The last range received and where it starts.
    buf: Vec<u8>,
    buf_at: u64,
    /// Requested ranges, in file order: (offset, length, answer).
    inflight: VecDeque<(u64, u32, Pending)>,
    /// Where the next range request starts.
    next: u64,
}

/// One server file, read on demand.
#[implement(IStream)]
struct RemoteStream {
    source: RemoteSource,
    lindex: u32,
    size: u64,
    name: String,
    write_time: u64,
    reader: Mutex<Reader>,
}

impl RemoteStream {
    fn new(source: RemoteSource, lindex: u32, size: u64, name: String, write_time: u64) -> Self {
        RemoteStream {
            source,
            lindex,
            size,
            name,
            write_time,
            reader: Mutex::new(Reader {
                pos: 0,
                buf: Vec::new(),
                buf_at: 0,
                inflight: VecDeque::new(),
                next: 0,
            }),
        }
    }

    /// Keeps up to [`AHEAD`] ranges in flight from `r.next`.
    fn top_up(&self, r: &mut Reader) {
        while r.inflight.len() < AHEAD && r.next < self.size {
            let n = (self.size - r.next).min(RANGE as u64) as u32;
            let p = self.source.range(self.lindex, r.next, n);
            r.inflight.push_back((r.next, n, p));
            r.next += n as u64;
        }
    }

    /// Copies up to `out.len()` bytes at the reading position.
    fn read_into(&self, out: &mut [u8]) -> Result<usize, HRESULT> {
        let mut r = self.reader.lock().map_err(|_| E_FAIL)?;
        let mut done = 0;
        while done < out.len() && r.pos < self.size {
            let end = r.buf_at + r.buf.len() as u64;
            if r.pos >= r.buf_at && r.pos < end {
                let from = (r.pos - r.buf_at) as usize;
                let n = (r.buf.len() - from).min(out.len() - done);
                out[done..done + n].copy_from_slice(&r.buf[from..from + n]);
                done += n;
                r.pos += n as u64;
                continue;
            }
            // The pipeline must start at the reading position (a seek or a
            // short answer restarts it there).
            if r.inflight.front().map(|f| f.0) != Some(r.pos) {
                r.inflight.clear();
                r.next = r.pos;
            }
            self.top_up(&mut r);
            let Some((at, len, pending)) = r.inflight.pop_front() else {
                break;
            };
            match wait(&pending, RANGE_WAIT) {
                Some(d) if !d.is_empty() && d.len() <= len as usize => {
                    if d.len() < len as usize {
                        // Short answer: continue right after it.
                        r.inflight.clear();
                        r.next = at + d.len() as u64;
                    }
                    r.buf = d;
                    r.buf_at = at;
                    self.top_up(&mut r);
                }
                _ => {
                    rdp::trace!(
                        "clipboard: reading {} at {at} failed or timed out",
                        self.name
                    );
                    r.inflight.clear();
                    r.next = r.pos;
                    if done > 0 {
                        break;
                    }
                    return Err(E_FAIL);
                }
            }
        }
        Ok(done)
    }
}

impl ISequentialStream_Impl for RemoteStream_Impl {
    fn Read(&self, pv: *mut core::ffi::c_void, cb: u32, pcbread: *mut u32) -> HRESULT {
        if pv.is_null() {
            return E_POINTER;
        }
        // SAFETY: the caller's buffer of `cb` bytes.
        let out = unsafe { std::slice::from_raw_parts_mut(pv as *mut u8, cb as usize) };
        let (hr, n) = match self.read_into(out) {
            Ok(n) => (S_OK, n),
            Err(e) => (e, 0),
        };
        if !pcbread.is_null() {
            // SAFETY: the caller's out parameter.
            unsafe { *pcbread = n as u32 };
        }
        hr
    }

    fn Write(&self, _: *const core::ffi::c_void, _: u32, _: *mut u32) -> HRESULT {
        STG_E_ACCESSDENIED
    }
}

impl IStream_Impl for RemoteStream_Impl {
    fn Seek(
        &self,
        dlibmove: i64,
        dworigin: STREAM_SEEK,
        plibnewposition: *mut u64,
    ) -> windows::core::Result<()> {
        let mut r = self.reader.lock().map_err(|_| E_FAIL)?;
        let base = match dworigin {
            STREAM_SEEK_SET => 0i128,
            STREAM_SEEK_CUR => r.pos as i128,
            STREAM_SEEK_END => self.size as i128,
            _ => return Err(E_INVALIDARG.into()),
        };
        let pos = base + dlibmove as i128;
        if pos < 0 {
            return Err(E_INVALIDARG.into());
        }
        r.pos = pos.min(u64::MAX as i128) as u64;
        if !plibnewposition.is_null() {
            // SAFETY: the caller's out parameter.
            unsafe { *plibnewposition = r.pos };
        }
        Ok(())
    }

    fn SetSize(&self, _: u64) -> windows::core::Result<()> {
        Err(STG_E_ACCESSDENIED.into())
    }

    fn CopyTo(
        &self,
        _: Ref<IStream>,
        _: u64,
        _: *mut u64,
        _: *mut u64,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn Commit(&self, _: &STGC) -> windows::core::Result<()> {
        Ok(())
    }

    fn Revert(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn LockRegion(&self, _: u64, _: u64, _: &LOCKTYPE) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn UnlockRegion(&self, _: u64, _: u64, _: u32) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn Stat(&self, pstatstg: *mut STATSTG, grfstatflag: &STATFLAG) -> windows::core::Result<()> {
        // SAFETY: the caller's out structure.
        let s = unsafe { pstatstg.as_mut() }.ok_or(E_POINTER)?;
        *s = STATSTG::default();
        s.r#type = STGTY_STREAM.0 as u32;
        s.cbSize = self.size;
        let t = FILETIME {
            dwLowDateTime: self.write_time as u32,
            dwHighDateTime: (self.write_time >> 32) as u32,
        };
        s.mtime = t;
        if grfstatflag.0 & STATFLAG_NONAME.0 == 0 {
            let leaf = self.name.rsplit('\\').next().unwrap_or(&self.name);
            let w: Vec<u16> = leaf.encode_utf16().chain(Some(0)).collect();
            // SAFETY: a CoTaskMem block the caller frees, filled below.
            unsafe {
                let p = CoTaskMemAlloc(w.len() * 2) as *mut u16;
                if p.is_null() {
                    return Err(E_FAIL.into());
                }
                std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
                s.pwcsName = windows::core::PWSTR(p);
            }
        }
        Ok(())
    }

    fn Clone(&self) -> windows::core::Result<IStream> {
        Err(E_NOTIMPL.into())
    }
}

#[cfg(test)]
mod tests;
