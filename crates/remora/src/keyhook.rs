//! Windows key combinations for the remote session (as mstsc's "Apply
//! Windows key combinations").
//!
//! Keys such as Win, Alt+Tab, Alt+Esc, Ctrl+Esc and Alt+Space are taken by
//! the local shell before any window sees them. While the hook is active (the
//! session has the keyboard and the connection's setting allows it), a
//! low-level keyboard hook takes them first, hands their scancodes to Remora
//! and keeps them from the local shell. Everything else passes untouched.
//!
//! The hook runs on its own thread with its own message loop, and like
//! mstsc it is hooked afresh each time the session takes the keyboard and
//! unhooked when it lets go. Hooked once at start, it was never called
//! while Remora's window was in front (the log showed no hook call at all
//! then), so the local shell kept the Windows key (RDP-53). A fresh hook is
//! the newest, and the newest low-level hook is called first.

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    use windows_sys::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_APPS, VK_CONTROL, VK_ESCAPE, VK_LWIN, VK_RWIN, VK_SPACE, VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetMessageW, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT,
        LLKHF_ALTDOWN, LLKHF_EXTENDED, LLKHF_INJECTED, MSG, PostThreadMessageW, SetWindowsHookExW,
        UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_APP, WM_KEYDOWN, WM_SYSKEYDOWN,
    };

    type Sink = Box<dyn Fn(u8, bool, bool) + Send>;

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();
    /// The hook thread's id, for [`reinstall`].
    static THREAD: OnceLock<u32> = OnceLock::new();
    /// Posted to the hook thread: unhook and hook again.
    const REINSTALL: u32 = WM_APP + 1;
    /// Posted to the hook thread: unhook.
    const UNHOOK: u32 = WM_APP + 2;
    /// Diagnostics (RDP-53): hook calls so far, and when the last one ran
    /// (milliseconds since the process started).
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    static START: OnceLock<std::time::Instant> = OnceLock::new();

    fn now_ms() -> u64 {
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }

    /// (hook calls so far, milliseconds since the last one).
    pub fn calls() -> (u64, u64) {
        let last = LAST_MS.load(Ordering::Relaxed);
        (CALLS.load(Ordering::Relaxed), now_ms().saturating_sub(last))
    }

    /// Keys whose virtual-key code says nothing about what is typed: logged
    /// in the diagnostics. Letters, digits, numpad and punctuation never are.
    fn loggable(vk: u32) -> bool {
        !matches!(vk, 0x30..=0x39 | 0x41..=0x5A | 0x60..=0x6F | 0xBA..=0xC0 | 0xDB..=0xDF | 0xE2)
    }

    fn hook() -> HHOOK {
        // SAFETY: a valid hook procedure that lives for the whole process;
        // the module handle of this executable.
        unsafe {
            SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(hook_proc),
                GetModuleHandleW(std::ptr::null()),
                0,
            )
        }
    }

    /// Starts the hook on its own thread. `sink(scancode, extended, down)`
    /// runs there and must return at once (it only queues an event).
    pub fn install(sink: impl Fn(u8, bool, bool) + Send + 'static) -> bool {
        if SINK.set(Mutex::new(Box::new(sink))).is_err() {
            return true;
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
        let spawned = std::thread::Builder::new()
            .name("keyhook".into())
            .spawn(move || {
                // SAFETY: plain call.
                let _ = THREAD.set(unsafe { GetCurrentThreadId() });
                // Hooked only while the session has the keyboard (set_active).
                let mut h: HHOOK = std::ptr::null_mut();
                rdp::trace!("keyhook: thread ready");
                let _ = ready_tx.send(true);
                // SAFETY: this thread's message loop; the hook procedure is
                // called from inside GetMessageW.
                unsafe {
                    let mut msg: MSG = std::mem::zeroed();
                    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                        if msg.hwnd.is_null() && msg.message == REINSTALL {
                            if !h.is_null() {
                                UnhookWindowsHookEx(h);
                            }
                            h = hook();
                            rdp::trace!("keyhook: hooked ({})", !h.is_null());
                            continue;
                        }
                        if msg.hwnd.is_null() && msg.message == UNHOOK {
                            if !h.is_null() {
                                UnhookWindowsHookEx(h);
                                h = std::ptr::null_mut();
                                rdp::trace!("keyhook: unhooked");
                            }
                            continue;
                        }
                        DispatchMessageW(&msg);
                    }
                }
            });
        spawned.is_ok()
            && ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap_or(false)
    }

    fn post(message: u32) {
        if let Some(&tid) = THREAD.get() {
            // SAFETY: posting to our hook thread's queue.
            unsafe { PostThreadMessageW(tid, message, 0, 0) };
        }
    }

    /// Hooks again (Windows may have dropped the hook without telling).
    pub fn reinstall() {
        post(REINSTALL);
    }

    /// The session takes the keyboard (hook afresh, as mstsc does on focus)
    /// or lets go (unhook).
    pub fn set_active(on: bool) {
        if ACTIVE.swap(on, Ordering::Relaxed) != on {
            rdp::trace!("keyhook: {}", if on { "takes Windows keys" } else { "off" });
            post(if on { REINSTALL } else { UNHOOK });
        }
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
            if code == HC_ACTION as i32 {
                let k = &*(lparam as *const KBDLLHOOKSTRUCT);
                CALLS.fetch_add(1, Ordering::Relaxed);
                LAST_MS.store(now_ms(), Ordering::Relaxed);
                // Diagnostics (RDP-53): never letters, digits or punctuation.
                if loggable(k.vkCode) {
                    rdp::trace!(
                        "keyhook: vk {:#04x} sc {:#04x} {} (active {}, injected {}, flags {:#x})",
                        k.vkCode,
                        k.scanCode,
                        if matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN) {
                            "down"
                        } else {
                            "up"
                        },
                        ACTIVE.load(Ordering::Relaxed),
                        k.flags & LLKHF_INJECTED != 0,
                        k.flags
                    );
                }
            }
            if code == HC_ACTION as i32 && ACTIVE.load(Ordering::Relaxed) {
                let k = &*(lparam as *const KBDLLHOOKSTRUCT);
                let alt = k.flags & LLKHF_ALTDOWN != 0;
                let ctrl = GetAsyncKeyState(VK_CONTROL as i32) < 0;
                // Injected keys too: key remappers (PowerToys, AutoHotkey,
                // vendor tools) and some IME setups inject the real keys,
                // and Remora itself never injects keys on this PC.
                if grabs(k.vkCode, alt, ctrl)
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
pub use imp::{calls, install, is_active, reinstall, set_active};

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

#[cfg(not(windows))]
pub fn reinstall() {}

#[cfg(not(windows))]
pub fn calls() -> (u64, u64) {
    (0, 0)
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
