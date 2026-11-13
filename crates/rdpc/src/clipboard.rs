//! The system clipboard: reading text (paste into fields) and the
//! [`WindowsClipboard`] backend for clipboard sharing in sessions.

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
#[derive(Default)]
pub struct WindowsClipboard;

#[cfg(windows)]
impl rdp::cliprdr::ClipboardBackend for WindowsClipboard {
    fn sequence(&mut self) -> u32 {
        // SAFETY: no arguments; reads a per-window-station counter.
        unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() }
    }

    fn read_text(&mut self) -> Option<String> {
        use windows_sys::Win32::System::DataExchange::CloseClipboard;
        if !win::open() {
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
        if !win::open() {
            return false;
        }
        // SAFETY: the clipboard is open on this thread until CloseClipboard.
        unsafe {
            let ok = win::set_unicode_text(text);
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
}

// wired in by RDP-3 integration
#[allow(dead_code)]
#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
    };

    const CF_UNICODETEXT: u32 = 13;
    const OPEN_ATTEMPTS: u32 = 3;

    /// Opens the clipboard without an owner window (the worker thread has no
    /// message pump). Another process holding it open is retried with a
    /// yield, never a sleep, so the session poll stays within its budget.
    pub fn open() -> bool {
        for attempt in 0..OPEN_ATTEMPTS {
            // SAFETY: no pointers passed; a null owner is allowed.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
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
}
