//! A hidden window for session notifications and shutdown; it also owns
//! the notification-area icon ([`super::tray`]).
//!
//! Not a message-only (`HWND_MESSAGE`) window: those receive no broadcast
//! messages, and `WM_QUERYENDSESSION` / `WM_ENDSESSION` (logoff, shutdown)
//! are delivered only to top-level windows. So this is a top-level popup
//! that is never shown (no `WS_VISIBLE`, tool window, no taskbar button).

use std::cell::RefCell;
use std::io;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, KillTimer, MSG, PostMessageW,
    PostQuitMessage, RegisterClassExW, RegisterWindowMessageW, SetTimer, WM_CLOSE, WM_DESTROY,
    WM_ENDSESSION, WM_QUERYENDSESSION, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP,
};

use super::agent::Input;
use super::tray::{SharedFeed, Tray, WM_TRAY, WM_TRAY_STATUS};
use super::wide;
use crate::{info, warn};

const REGISTER_TIMER: usize = 1;
/// `WTSRegisterSessionNotification` fails early at logon until the Remote
/// Desktop service is ready; retry every 2 s for up to 2 min.
const REGISTER_RETRIES: u32 = 60;

thread_local! {
    static STATE: RefCell<Option<WinState>> = const { RefCell::new(None) };
}

struct WinState {
    tx: Sender<Input>,
    registered: bool,
    tries: u32,
    /// None while its menu or a question runs (the window procedure is
    /// re-entered then), or after the window closed.
    tray: Option<Tray>,
    feed: SharedFeed,
    /// Explorer's "TaskbarCreated" broadcast: the tray icon is added again.
    taskbar_created: u32,
}

/// The window's handle, usable from other threads.
#[derive(Clone, Copy)]
pub struct WindowThread {
    hwnd: isize,
}

impl WindowThread {
    pub fn close(&self) {
        // SAFETY: posting to a window owned by our thread; harmless if gone.
        unsafe { PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0) };
    }

    /// The tray's feed changed.
    pub fn status_changed(&self) {
        // SAFETY: as above.
        unsafe { PostMessageW(self.hwnd as HWND, WM_TRAY_STATUS, 0, 0) };
    }
}

pub fn spawn(tx: Sender<Input>, feed: SharedFeed, fingerprint: String) -> io::Result<WindowThread> {
    let (ready_tx, ready_rx) = mpsc::channel::<io::Result<isize>>();
    std::thread::Builder::new()
        .name("session-window".into())
        .spawn(move || thread_main(tx, feed, fingerprint, ready_tx))?;
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::other("session window did not start"))?
        .map(|hwnd| WindowThread { hwnd })
}

fn try_register(hwnd: HWND) -> bool {
    // SAFETY: our window.
    unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) != 0 }
}

fn thread_main(
    tx: Sender<Input>,
    feed: SharedFeed,
    fingerprint: String,
    ready: Sender<io::Result<isize>>,
) {
    let class = wide("RemoraAgentSessionWindow");
    // SAFETY: standard window class registration and creation; the window
    // is never shown.
    let hwnd = unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinstance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        let title = wide("Remora Agent");
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        let _ = ready.send(Err(io::Error::last_os_error()));
        return;
    }
    let registered = try_register(hwnd);
    if !registered {
        warn!("session notifications not available yet; retrying");
        // SAFETY: timer on our window.
        unsafe { SetTimer(hwnd, REGISTER_TIMER, 2000, None) };
    }
    let taskbar = wide("TaskbarCreated");
    // SAFETY: NUL-terminated name.
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar.as_ptr()) };
    let tray = Tray::new(hwnd, fingerprint);
    STATE.with(|s| {
        *s.borrow_mut() = Some(WinState {
            tx,
            registered,
            tries: 0,
            tray: Some(tray),
            feed,
            taskbar_created,
        })
    });
    let _ = ready.send(Ok(hwnd as isize));
    // SAFETY: standard message loop for this thread's window.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    }
}

fn send(input: Input) {
    STATE.with(|s| {
        if let Some(st) = s.borrow().as_ref() {
            let _ = st.tx.send(input);
        }
    });
}

/// Applies the feed's status and shows its notices.
fn apply_feed() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let Some(st) = s.as_mut() else { return };
        let Some(tray) = st.tray.as_mut() else {
            return;
        };
        let (status, notices) = match st.feed.lock() {
            Ok(mut f) => (f.status.clone(), std::mem::take(&mut f.notices)),
            Err(_) => return,
        };
        tray.set_status(status);
        for n in &notices {
            tray.notify(n);
        }
    });
}

/// Opens the tray menu. The tray leaves the state while its menu (and any
/// question it asks) runs, because those modal loops re-enter this window
/// procedure; status updates in between wait in the feed.
fn tray_menu(hwnd: HWND) {
    let taken = STATE.with(|s| {
        let mut s = s.borrow_mut();
        let st = s.as_mut()?;
        Some((st.tray.take()?, st.tx.clone()))
    });
    let Some((mut tray, tx)) = taken else {
        return;
    };
    tray.show_menu(&tx);
    STATE.with(|s| {
        if let Some(st) = s.borrow_mut().as_mut() {
            st.tray = Some(tray);
        }
    });
    // Whatever changed while the menu was open.
    // SAFETY: our window.
    unsafe { PostMessageW(hwnd, WM_TRAY_STATUS, 0, 0) };
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let taskbar_created = STATE.with(|s| s.borrow().as_ref().map(|st| st.taskbar_created));
    if taskbar_created.is_some_and(|m| m != 0 && m == msg) {
        STATE.with(|s| {
            if let Some(tray) = s.borrow_mut().as_mut().and_then(|st| st.tray.as_mut()) {
                tray.taskbar_created();
            }
        });
        return 0;
    }
    match msg {
        WM_TRAY_STATUS => {
            apply_feed();
            0
        }
        WM_TRAY => {
            // NOTIFYICON_VERSION_4: the event is LOWORD(lParam).
            if Tray::wants_menu((lparam as u32) & 0xFFFF) {
                tray_menu(hwnd);
            }
            0
        }
        WM_WTSSESSION_CHANGE => {
            send(Input::Session(wparam as u32));
            0
        }
        WM_TIMER if wparam == REGISTER_TIMER => {
            let done = STATE.with(|s| {
                let mut s = s.borrow_mut();
                let Some(st) = s.as_mut() else { return true };
                st.tries += 1;
                st.registered = try_register(hwnd);
                if st.registered {
                    info!(
                        "session notifications registered after {} retries",
                        st.tries
                    );
                } else if st.tries >= REGISTER_RETRIES {
                    warn!("session notifications unavailable; reconnects will not reopen channels");
                }
                st.registered || st.tries >= REGISTER_RETRIES
            });
            if done {
                // SAFETY: our timer.
                unsafe { KillTimer(hwnd, REGISTER_TIMER) };
            }
            0
        }
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                // The process may end as soon as this returns: let the event
                // loop shut down first (bounded).
                let (done_tx, done_rx) = mpsc::channel();
                send(Input::Shutdown {
                    done: Some(done_tx),
                });
                let _ = done_rx.recv_timeout(Duration::from_secs(5));
            }
            0
        }
        WM_DESTROY => {
            // Removes the icon (Tray's Drop).
            let tray = STATE.with(|s| s.borrow_mut().as_mut().and_then(|st| st.tray.take()));
            drop(tray);
            let registered = STATE.with(|s| s.borrow().as_ref().is_some_and(|st| st.registered));
            if registered {
                // SAFETY: our window.
                unsafe { WTSUnRegisterSessionNotification(hwnd) };
            }
            // SAFETY: plain call.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: default handling.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
