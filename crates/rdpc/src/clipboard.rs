//! Reading text from the system clipboard (paste into fields).

#[cfg(windows)]
pub fn read_text() -> Option<String> {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    const CF_UNICODETEXT: u32 = 13;
    // SAFETY: standard clipboard sequence; the locked pointer is only read up
    // to its NUL terminator and released before the clipboard is closed.
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        let mut text = None;
        if !handle.is_null() {
            let p = GlobalLock(handle) as *const u16;
            if !p.is_null() {
                let mut n = 0;
                while *p.add(n) != 0 {
                    n += 1;
                }
                text = Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
                GlobalUnlock(handle);
            }
        }
        CloseClipboard();
        text
    }
}

#[cfg(not(windows))]
pub fn read_text() -> Option<String> {
    None
}
