//! Windows key combinations for the remote session (as mstsc's "Apply
//! Windows key combinations").
//!
//! Keys such as Win, Alt+Tab, Alt+Esc, Ctrl+Esc and Alt+Space are taken by
//! the local shell before any window sees them. While the hook is active (the
//! session has the keyboard and the connection's setting allows it), a
//! low-level keyboard hook takes them first, hands their scancodes to Remora
//! and keeps them from the local shell. Everything else passes untouched.

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    use windows_sys::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_APPS, VK_CONTROL, VK_ESCAPE, VK_LWIN, VK_RWIN, VK_SPACE, VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, LLKHF_EXTENDED, LLKHF_INJECTED,
        SetWindowsHookExW, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    };

    type Sink = Box<dyn Fn(u8, bool, bool) + Send>;

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

    /// Installs the hook on the calling thread (it needs that thread's
    /// message loop: the window's event loop). `sink(scancode, extended, down)`.
    pub fn install(sink: impl Fn(u8, bool, bool) + Send + 'static) -> bool {
        if SINK.set(Mutex::new(Box::new(sink))).is_err() {
            return true;
        }
        // SAFETY: a valid hook procedure that lives for the whole process;
        // the module handle of this executable.
        let hook = unsafe {
            SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(hook_proc),
                GetModuleHandleW(std::ptr::null()),
                0,
            )
        };
        !hook.is_null()
    }

    pub fn set_active(on: bool) {
        ACTIVE.store(on, Ordering::Relaxed);
    }

    /// Whether the hook takes Windows key combinations now.
    pub fn is_active() -> bool {
        ACTIVE.load(Ordering::Relaxed)
    }

    /// Whether a key event belongs to the remote session.
    pub(super) fn grabs(vk: u32, alt: bool, ctrl: bool) -> bool {
        let vk = vk as u16;
        matches!(vk, VK_LWIN | VK_RWIN | VK_APPS)
            || (alt && matches!(vk, VK_TAB | VK_ESCAPE | VK_SPACE))
            || (ctrl && vk == VK_ESCAPE)
    }

    unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // SAFETY: for HC_ACTION, lparam points to a KBDLLHOOKSTRUCT owned by
        // the caller for the duration of the call.
        unsafe {
            if code == HC_ACTION as i32 && ACTIVE.load(Ordering::Relaxed) {
                let k = &*(lparam as *const KBDLLHOOKSTRUCT);
                let alt = k.flags & LLKHF_ALTDOWN != 0;
                let ctrl = GetAsyncKeyState(VK_CONTROL as i32) < 0;
                if k.flags & LLKHF_INJECTED == 0
                    && grabs(k.vkCode, alt, ctrl)
                    && let Some(sink) = SINK.get()
                    && let Ok(sink) = sink.lock()
                {
                    let down = matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
                    sink(k.scanCode as u8, k.flags & LLKHF_EXTENDED != 0, down);
                    return 1;
                }
            }
            CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam)
        }
    }
}

#[cfg(windows)]
pub use imp::{install, is_active, set_active};

#[cfg(not(windows))]
pub fn install(_sink: impl Fn(u8, bool, bool) + Send + 'static) -> bool {
    false
}

#[cfg(not(windows))]
pub fn set_active(_on: bool) {}

#[cfg(not(windows))]
pub fn is_active() -> bool {
    false
}

#[cfg(all(test, windows))]
mod tests {
    use super::imp::grabs;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_A, VK_LWIN, VK_SPACE, VK_TAB};

    #[test]
    fn only_shell_combinations_are_taken() {
        assert!(grabs(VK_LWIN as u32, false, false));
        assert!(grabs(VK_TAB as u32, true, false), "Alt+Tab");
        assert!(!grabs(VK_TAB as u32, false, false), "plain Tab stays");
        assert!(grabs(VK_SPACE as u32, true, false), "Alt+Space");
        assert!(!grabs(VK_A as u32, true, true), "letters never");
    }
}
