//! The system clipboard: reading text (paste into fields) and the
//! [`WindowsClipboard`] backend for clipboard sharing in sessions.

use std::path::PathBuf;

#[cfg(windows)]
pub fn read_text() -> Option<String> {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, OpenClipboard};
    // SAFETY: the clipboard is opened by this thread and closed right after.
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let text = win::unicode_text();
        CloseClipboard();
        text
    }
}

#[cfg(not(windows))]
pub fn read_text() -> Option<String> {
    None
}

/// Clipboard backend for the `cliprdr` channel on Windows. Runs on the
/// session worker thread: a busy clipboard is retried at most 3 times
/// without sleeping, then the call gives up for this tick.
///
/// `owner` is the app's main window (HWND as an integer). Windows needs an
/// owner window to *set* clipboard data: after OpenClipboard(NULL),
/// EmptyClipboard leaves the clipboard without owner and SetClipboardData
/// fails. The owner must be a window whose thread pumps messages (the UI
/// thread does), because other programs send it WM_DESTROYCLIPBOARD.
#[derive(Default)]
pub struct WindowsClipboard {
    pub owner: isize,
}

#[cfg(windows)]
impl rdp::cliprdr::ClipboardBackend for WindowsClipboard {
    fn sequence(&mut self) -> u32 {
        // SAFETY: no arguments; reads a per-window-station counter.
        unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() }
    }

    fn read_text(&mut self) -> Option<String> {
        use windows_sys::Win32::System::DataExchange::CloseClipboard;
        if !win::open(self.owner) {
            return None;
        }
        // SAFETY: the clipboard is open on this thread until CloseClipboard.
        unsafe {
            let text = win::unicode_text();
            CloseClipboard();
            text
        }
    }

    fn write_text(&mut self, text: &str) -> bool {
        use windows_sys::Win32::System::DataExchange::CloseClipboard;
        if !win::open(self.owner) {
            return false;
        }
        // SAFETY: the clipboard is open on this thread until CloseClipboard.
        unsafe {
            let ok = win::set_unicode_text(text);
            CloseClipboard();
            ok
        }
    }

    fn supports_files(&self) -> bool {
        true
    }

    fn read_files(&mut self) -> Option<Vec<PathBuf>> {
        use windows_sys::Win32::System::DataExchange::CloseClipboard;
        if !win::open(self.owner) {
            return None;
        }
        // SAFETY: the clipboard is open on this thread until CloseClipboard.
        unsafe {
            let files = win::hdrop_files();
            CloseClipboard();
            files
        }
    }

    fn write_files(&mut self, paths: &[PathBuf]) -> bool {
        use windows_sys::Win32::System::DataExchange::CloseClipboard;
        if !win::open(self.owner) {
            return false;
        }
        // SAFETY: the clipboard is open on this thread until CloseClipboard.
        unsafe {
            let ok = win::set_hdrop_files(paths);
            CloseClipboard();
            ok
        }
    }
}

#[cfg(not(windows))]
impl rdp::cliprdr::ClipboardBackend for WindowsClipboard {
    fn sequence(&mut self) -> u32 {
        0
    }
    fn read_text(&mut self) -> Option<String> {
        None
    }
    fn write_text(&mut self, _text: &str) -> bool {
        false
    }
    fn read_files(&mut self) -> Option<Vec<PathBuf>> {
        None
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
    };
    use windows_sys::Win32::UI::Shell::{DROPFILES, DragQueryFileW};

    const CF_UNICODETEXT: u32 = 13;
    /// Standard clipboard format: a DROPFILES list of paths.
    const CF_HDROP: u32 = 15;
    /// DROPEFFECT_COPY: a paste copies the files, never moves them.
    const DROPEFFECT_COPY: u32 = 1;
    /// Most paths read from one CF_HDROP.
    const MAX_DROP_FILES: u32 = 65_536;
    const OPEN_ATTEMPTS: u32 = 3;

    /// Opens the clipboard without an owner window (the worker thread has no
    /// message pump). Another process holding it open is retried with a
    /// yield, never a sleep, so the session poll stays within its budget.
    pub fn open(owner: isize) -> bool {
        for attempt in 0..OPEN_ATTEMPTS {
            // SAFETY: `owner` is the app's live main window (or 0 = none).
            if unsafe { OpenClipboard(owner as _) } != 0 {
                return true;
            }
            if attempt + 1 < OPEN_ATTEMPTS {
                std::thread::yield_now();
            }
        }
        false
    }

    /// CF_UNICODETEXT of the open clipboard, read up to its NUL or the end
    /// of the global block, whichever comes first.
    ///
    /// # Safety
    /// The clipboard must be open on this thread.
    pub unsafe fn unicode_text() -> Option<String> {
        unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT);
            if handle.is_null() {
                return None;
            }
            let p = GlobalLock(handle) as *const u16;
            if p.is_null() {
                return None;
            }
            let max = GlobalSize(handle) / 2;
            let units = std::slice::from_raw_parts(p, max);
            let n = units.iter().position(|&u| u == 0).unwrap_or(max);
            let text = String::from_utf16_lossy(&units[..n]);
            GlobalUnlock(handle);
            Some(text)
        }
    }

    /// Replaces the open clipboard's contents with `text` as CF_UNICODETEXT.
    ///
    /// # Safety
    /// The clipboard must be open on this thread.
    pub unsafe fn set_unicode_text(text: &str) -> bool {
        let units: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        unsafe {
            if EmptyClipboard() == 0 {
                return false;
            }
            let mem = GlobalAlloc(GMEM_MOVEABLE, units.len() * 2);
            if mem.is_null() {
                return false;
            }
            let p = GlobalLock(mem) as *mut u16;
            if p.is_null() {
                GlobalFree(mem);
                return false;
            }
            std::ptr::copy_nonoverlapping(units.as_ptr(), p, units.len());
            GlobalUnlock(mem);
            // On success the system owns the block; on failure we free it.
            if SetClipboardData(CF_UNICODETEXT, mem).is_null() {
                GlobalFree(mem);
                return false;
            }
            true
        }
    }

    /// Paths of the open clipboard's CF_HDROP, if it has one.
    ///
    /// # Safety
    /// The clipboard must be open on this thread.
    pub unsafe fn hdrop_files() -> Option<Vec<PathBuf>> {
        unsafe {
            let hdrop = GetClipboardData(CF_HDROP);
            if hdrop.is_null() {
                return None;
            }
            let count = DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0);
            let mut paths = Vec::new();
            for i in 0..count.min(MAX_DROP_FILES) {
                let len = DragQueryFileW(hdrop, i, std::ptr::null_mut(), 0);
                if len == 0 {
                    continue;
                }
                let mut buf = vec![0u16; len as usize + 1];
                let got = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), len + 1) as usize;
                buf.truncate(got.min(len as usize));
                paths.push(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
            }
            (!paths.is_empty()).then_some(paths)
        }
    }

    /// Copies `bytes` into a new movable global block (null on failure).
    unsafe fn global(bytes: &[u8]) -> HANDLE {
        unsafe {
            let mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len());
            if mem.is_null() {
                return mem;
            }
            let p = GlobalLock(mem) as *mut u8;
            if p.is_null() {
                GlobalFree(mem);
                return std::ptr::null_mut();
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            GlobalUnlock(mem);
            mem
        }
    }

    /// DROPFILES header plus the wide, NUL-separated, double-NUL-terminated
    /// path list of a CF_HDROP block.
    fn hdrop_block(paths: &[PathBuf]) -> Vec<u8> {
        let header = DROPFILES {
            pFiles: size_of::<DROPFILES>() as u32,
            fWide: 1,
            ..Default::default()
        };
        // SAFETY: DROPFILES is plain packed data of exactly this size.
        let mut block = unsafe {
            std::slice::from_raw_parts((&raw const header).cast::<u8>(), size_of::<DROPFILES>())
        }
        .to_vec();
        for p in paths {
            for u in p.as_os_str().encode_wide().chain(Some(0)) {
                block.extend_from_slice(&u.to_le_bytes());
            }
        }
        block.extend_from_slice(&[0, 0]);
        block
    }

    /// Replaces the open clipboard's contents with `paths` as CF_HDROP and
    /// "Preferred DropEffect" = DROPEFFECT_COPY.
    ///
    /// # Safety
    /// The clipboard must be open on this thread.
    pub unsafe fn set_hdrop_files(paths: &[PathBuf]) -> bool {
        let block = hdrop_block(paths);
        let effect_name: Vec<u16> = "Preferred DropEffect"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        unsafe {
            if EmptyClipboard() == 0 {
                return false;
            }
            let mem = global(&block);
            if mem.is_null() {
                return false;
            }
            // On success the system owns the block; on failure we free it.
            if SetClipboardData(CF_HDROP, mem).is_null() {
                GlobalFree(mem);
                return false;
            }
            let effect_format = RegisterClipboardFormatW(effect_name.as_ptr());
            if effect_format != 0 {
                let mem = global(&DROPEFFECT_COPY.to_le_bytes());
                if !mem.is_null() && SetClipboardData(effect_format, mem).is_null() {
                    GlobalFree(mem);
                }
            }
            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hdrop_block_layout() {
            let b = hdrop_block(&[PathBuf::from("C:\\a"), PathBuf::from("D:\\b")]);
            // pFiles = 20, pt = (0, 0), fNC = 0, fWide = 1.
            assert_eq!(
                &b[..20],
                &[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
            );
            let units: Vec<u16> = b[20..]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let want: Vec<u16> = "C:\\a\0D:\\b\0\0".encode_utf16().collect();
            assert_eq!(units, want);
        }
    }
}
