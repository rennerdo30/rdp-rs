//! The only windows the agent ever shows, both on the user's request or
//! for the user's decision:
//! - the pairing dialog: the six-digit code with Confirm and Reject, topmost,
//!   on its own thread, closed by the protocol (`PairingUi::close_sas`)
//!   through `WM_CLOSE` (no answer then), or by the user: Confirm, Reject,
//!   or closing it / five minutes without an answer (both count as Reject);
//! - a message box from `remora-agent send` when nothing could be sent.
//!
//! Tests use the protocol's test UI; nothing here runs in tests.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Once};

use remora_link::Sas;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_WINDOW, CreateFontIndirectW, DeleteObject, FW_SEMIBOLD, GetSysColorBrush, HDC, HFONT,
    SetBkMode, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, BS_PUSHBUTTON, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, GetMessageW, GetSystemMetrics, IsDialogMessageW, KillTimer,
    MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MSG, MessageBoxW, NONCLIENTMETRICSW,
    PostMessageW, PostQuitMessage, RegisterClassExW, SM_CXSCREEN, SM_CYSCREEN,
    SPI_GETNONCLIENTMETRICS, SW_SHOWNORMAL, SendMessageW, SetForegroundWindow, SetTimer,
    ShowWindow, SystemParametersInfoW, TranslateMessage, WM_CLOSE, WM_COMMAND, WM_CTLCOLORSTATIC,
    WM_DESTROY, WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_CAPTION, WS_CHILD, WS_EX_DLGMODALFRAME,
    WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

use super::agent::Input;
use super::{sys, wide};
use crate::files::Notifier;
use crate::link::PairingUi;
use crate::warn;

/// `SS_CENTER` (winuser.h; windows-sys keeps it in another feature).
const SS_CENTER: u32 = 1;
const ID_CONFIRM: usize = 101;
const ID_REJECT: usize = 102;
const TIMEOUT_TIMER: usize = 1;
/// The dialog closes by itself after five minutes (no answer).
const TIMEOUT_MS: u32 = 5 * 60 * 1000;
const CLASS: &str = "RemoraAgentPairing";
const TITLE: &str = "Remora Agent: pair with Remora";

/// The dialog's three lines.
pub fn dialog_text(client: Option<&str>, sas: Sas) -> [String; 3] {
    let who = match client {
        Some(c) => format!("Remora on \u{201C}{c}\u{201D}"),
        None => "Remora".to_string(),
    };
    [
        format!("{who} wants to pair with this helper. Does Remora show the same code?"),
        sas.to_string(),
        "Confirm only if both codes match, here and in Remora. Closing rejects.".to_string(),
    ]
}

struct Shared {
    hwnd: AtomicIsize,
    closed: AtomicBool,
}

impl Shared {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let h = self.hwnd.load(Ordering::SeqCst);
        if h != 0 {
            // SAFETY: posting to a window of another thread; harmless if gone.
            unsafe { PostMessageW(h as HWND, WM_CLOSE, 0, 0) };
        }
    }
}

/// The real [`PairingUi`]: answers come back to the event loop as
/// [`Input::PairingAnswer`].
pub struct WinPairingUi {
    tx: Sender<Input>,
    current: Option<Arc<Shared>>,
}

impl WinPairingUi {
    pub fn new(tx: Sender<Input>) -> Self {
        WinPairingUi { tx, current: None }
    }
}

impl PairingUi for WinPairingUi {
    fn show_sas(&mut self, ticket: u64, sas: Sas) {
        self.close_sas();
        let shared = Arc::new(Shared {
            hwnd: AtomicIsize::new(0),
            closed: AtomicBool::new(false),
        });
        let text = dialog_text(sys::client_name().as_deref(), sas);
        let (s, tx) = (shared.clone(), self.tx.clone());
        let spawned = std::thread::Builder::new()
            .name("pairing-dialog".into())
            .spawn(move || dialog_thread(ticket, text, s, tx));
        match spawned {
            Ok(_) => self.current = Some(shared),
            Err(e) => warn!("cannot show the pairing dialog: {e}"),
        }
    }

    fn close_sas(&mut self) {
        if let Some(s) = self.current.take() {
            s.close();
        }
    }
}

impl Drop for WinPairingUi {
    fn drop(&mut self) {
        self.close_sas();
    }
}

struct DialogState {
    ticket: u64,
    tx: Sender<Input>,
    shared: Arc<Shared>,
    answered: bool,
    fonts: Vec<HFONT>,
}

thread_local! {
    static DIALOG: RefCell<Option<DialogState>> = const { RefCell::new(None) };
}

/// Sends the user's answer once. Nothing is sent when the protocol closed
/// the dialog itself.
fn answer(confirmed: bool) {
    DIALOG.with(|d| {
        if let Some(st) = d.borrow_mut().as_mut()
            && !st.answered
            && !st.shared.closed.load(Ordering::SeqCst)
        {
            st.answered = true;
            let _ = st.tx.send(Input::PairingAnswer {
                ticket: st.ticket,
                confirmed,
            });
        }
    });
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let id = wparam & 0xFFFF;
            if id == ID_CONFIRM || id == ID_REJECT {
                answer(id == ID_CONFIRM);
                // SAFETY: our window.
                unsafe { DestroyWindow(hwnd) };
            }
            0
        }
        // The X button, Alt+F4, the timeout, or close_sas: not confirmed.
        WM_CLOSE => {
            answer(false);
            // SAFETY: our window.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_TIMER if wparam == TIMEOUT_TIMER => {
            // SAFETY: our window and timer.
            unsafe {
                KillTimer(hwnd, TIMEOUT_TIMER);
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
            0
        }
        WM_CTLCOLORSTATIC => {
            // SAFETY: the HDC of the static being painted.
            unsafe {
                SetBkMode(wparam as HDC, TRANSPARENT as i32);
                GetSysColorBrush(COLOR_WINDOW) as LRESULT
            }
        }
        WM_DESTROY => {
            DIALOG.with(|d| {
                if let Some(st) = d.borrow_mut().take() {
                    for f in st.fonts {
                        // SAFETY: fonts created by this thread, no longer selected.
                        unsafe { DeleteObject(f) };
                    }
                }
            });
            // SAFETY: plain call.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: default handling.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn fonts() -> (HFONT, HFONT) {
    // SAFETY: plain system query into a sized struct; fonts owned by caller.
    unsafe {
        let mut ncm: NONCLIENTMETRICSW = std::mem::zeroed();
        ncm.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
        SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            ncm.cbSize,
            (&mut ncm as *mut NONCLIENTMETRICSW).cast(),
            0,
        );
        let normal = CreateFontIndirectW(&ncm.lfMessageFont);
        let mut big = ncm.lfMessageFont;
        big.lfHeight = if big.lfHeight == 0 {
            -36
        } else {
            big.lfHeight * 3
        };
        big.lfWeight = FW_SEMIBOLD as i32;
        (normal, CreateFontIndirectW(&big))
    }
}

fn dialog_thread(ticket: u64, text: [String; 3], shared: Arc<Shared>, tx: Sender<Input>) {
    static REGISTER: Once = Once::new();
    let class = wide(CLASS);
    // SAFETY: window class registration and creation on this thread; all
    // handles are used only here.
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        REGISTER.call_once(|| {
            let mut wc: WNDCLASSEXW = std::mem::zeroed();
            wc.cbSize = size_of::<WNDCLASSEXW>() as u32;
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
            wc.lpszClassName = class.as_ptr();
            RegisterClassExW(&wc);
        });
        let (w, h) = (440, 210);
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
        let ex = WS_EX_TOPMOST | WS_EX_DLGMODALFRAME;
        let mut r = RECT {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
        };
        AdjustWindowRectEx(&mut r, style, 0, ex);
        let (ow, oh) = (r.right - r.left, r.bottom - r.top);
        let x = (GetSystemMetrics(SM_CXSCREEN) - ow) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - oh) / 3;
        let title = wide(TITLE);
        let hwnd = CreateWindowExW(
            ex,
            class.as_ptr(),
            title.as_ptr(),
            style,
            x,
            y,
            ow,
            oh,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            warn!("pairing dialog: {}", std::io::Error::last_os_error());
            return;
        }
        let (normal, big) = fonts();
        DIALOG.with(|d| {
            *d.borrow_mut() = Some(DialogState {
                ticket,
                tx,
                shared: shared.clone(),
                answered: false,
                fonts: vec![normal, big],
            })
        });
        let child = |class: &str, text: &str, style: u32, x, y, cw, ch, id: usize, font| {
            let (c, t) = (wide(class), wide(text));
            let h = CreateWindowExW(
                0,
                c.as_ptr(),
                t.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                cw,
                ch,
                hwnd,
                id as _,
                hinstance,
                std::ptr::null(),
            );
            SendMessageW(h, WM_SETFONT, font as WPARAM, 0);
        };
        child("STATIC", &text[0], 0, 20, 16, 400, 40, 0, normal);
        child("STATIC", &text[1], SS_CENTER, 20, 60, 400, 56, 0, big);
        child("STATIC", &text[2], 0, 20, 124, 400, 22, 0, normal);
        let button = BS_PUSHBUTTON as u32 | WS_TABSTOP;
        child(
            "BUTTON", "Reject", button, 212, 164, 100, 30, ID_REJECT, normal,
        );
        child(
            "BUTTON", "Confirm", button, 320, 164, 100, 30, ID_CONFIRM, normal,
        );
        shared.hwnd.store(hwnd as isize, Ordering::SeqCst);
        if shared.closed.load(Ordering::SeqCst) {
            DestroyWindow(hwnd);
        } else {
            SetTimer(hwnd, TIMEOUT_TIMER, TIMEOUT_MS, None);
            ShowWindow(hwnd, SW_SHOWNORMAL);
            SetForegroundWindow(hwnd);
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        shared.hwnd.store(0, Ordering::SeqCst);
    }
}

/// Message boxes for `remora-agent send` (a user-invoked command).
pub struct MessageBoxNotifier;

impl Notifier for MessageBoxNotifier {
    fn notify(&mut self, text: &str) {
        let (t, c) = (wide(text), wide("Send to my PC (Remora)"));
        // SAFETY: plain modal message box with valid strings.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                t.as_ptr(),
                c.as_ptr(),
                MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST,
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        let t = dialog_text(Some("LAPTOP"), Sas(123_456));
        assert!(t[0].contains("\u{201C}LAPTOP\u{201D}"));
        assert_eq!(t[1], "123 456");
        assert!(dialog_text(None, Sas(7)).iter().any(|l| l == "000 007"));
    }
}
