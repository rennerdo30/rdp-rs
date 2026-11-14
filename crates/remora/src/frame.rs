//! Windows 11 frame: Remora's tab strip is the title row, the way current
//! Windows apps (Explorer, Settings, Terminal) look. Adapted from ffwd's
//! `frame.rs` (https://github.com/rennerdo30/ffwd, MIT, same author).
//!
//! - The caption strip is removed in `WM_NCCALCSIZE`; side and bottom
//!   borders, the top resize edge, shadows and Aero Snap stay native.
//! - Remora draws minimise, maximise/restore and close itself.
//! - The maximise button answers `WM_NCHITTEST` with `HTMAXBUTTON`, so
//!   hovering it opens Snap Layouts exactly as on a standard window.
//! - Every other part of the title row that is not a control drags the
//!   window (and double-click maximises), handled by Windows itself.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::ScreenToClient;
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClientRect, HTCAPTION, HTCLIENT, HTMAXBUTTON, HTTOP, HTTOPLEFT, HTTOPRIGHT, IsZoomed,
    NCCALCSIZE_PARAMS, SM_CXPADDEDBORDER, SM_CYFRAME, SW_MAXIMIZE, SW_RESTORE, SWP_FRAMECHANGED,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOOWNERZORDER, SWP_NOREDRAW, SWP_NOSIZE, SWP_NOZORDER,
    SetWindowPos, ShowWindow, WM_NCCALCSIZE, WM_NCHITTEST, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN,
    WM_NCLBUTTONUP, WM_NCMOUSELEAVE, WM_NCMOUSEMOVE, WVR_VALIDRECTS,
};

/// Title-row geometry in physical client pixels, set by the UI on layout.
#[derive(Clone, Debug, Default)]
pub struct Caption {
    pub height: i32,
    /// Horizontal spans in the title row that are app controls (clicks go
    /// to Remora, not to window dragging).
    pub controls: Vec<(i32, i32)>,
    /// Left edge of the three caption buttons.
    pub buttons_left: i32,
    /// The maximise button's span.
    pub max_button: (i32, i32),
}

static CAPTION: Mutex<Option<Caption>> = Mutex::new(None);
static MAX_HOVERED: AtomicBool = AtomicBool::new(false);
static MAX_PRESSED: AtomicBool = AtomicBool::new(false);
static ZOOMED: AtomicI32 = AtomicI32::new(0);
static REPAINT: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

pub fn set_caption(c: Caption) {
    if let Ok(mut g) = CAPTION.lock() {
        *g = Some(c);
    }
}

/// Hover and press state of the maximise button. It receives non-client
/// mouse messages, so the app's own pointer events never see it.
pub fn max_button_state() -> (bool, bool) {
    (
        MAX_HOVERED.load(Ordering::Relaxed),
        MAX_PRESSED.load(Ordering::Relaxed),
    )
}

/// Removes the caption strip and installs the hit-test hook. `repaint`
/// asks the UI to redraw when the maximise button's state changes.
pub fn install(hwnd: isize, repaint: impl Fn() + Send + Sync + 'static) -> bool {
    if hwnd == 0 {
        return false;
    }
    let _ = REPAINT.set(Box::new(repaint));
    // SAFETY: hwnd is our live top-level window, owned by this (the UI)
    // thread, so subclassing it here is allowed. `subclass_proc` matches
    // SUBCLASSPROC and lives for the whole process. SetWindowPos with
    // SWP_FRAMECHANGED only makes Windows recompute the frame. The window is
    // still hidden, so no redraw or activation is needed: without
    // SWP_NOREDRAW this call took 10–97 ms at start-up, with it 1.4–2 ms
    // (FF-8, owner PC, release build).
    unsafe {
        let hwnd = hwnd as HWND;
        if SetWindowSubclass(hwnd, Some(subclass_proc), 1, 0) == 0 {
            return false;
        }
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED
                | SWP_NOMOVE
                | SWP_NOSIZE
                | SWP_NOZORDER
                | SWP_NOACTIVATE
                | SWP_NOOWNERZORDER
                | SWP_NOREDRAW,
        );
    }
    true
}

fn repaint() {
    if let Some(f) = REPAINT.get() {
        f();
    }
}

fn set_flag(flag: &AtomicBool, value: bool) {
    if flag.swap(value, Ordering::Relaxed) != value {
        repaint();
    }
}

/// Resize border thickness for this window's DPI.
///
/// # Safety
/// `hwnd` must be a live window.
unsafe fn frame_thickness(hwnd: HWND) -> i32 {
    // SAFETY: guaranteed by the caller.
    unsafe {
        let dpi = GetDpiForWindow(hwnd);
        GetSystemMetricsForDpi(SM_CYFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi)
    }
}

/// Classifies a client point in the title row.
fn caption_hit(c: &Caption, x: i32, y: i32) -> u32 {
    if y >= c.height {
        return HTCLIENT;
    }
    if x >= c.buttons_left {
        return if x >= c.max_button.0 && x < c.max_button.1 {
            HTMAXBUTTON
        } else {
            HTCLIENT
        };
    }
    if c.controls.iter().any(|&(l, r)| x >= l && x < r) {
        HTCLIENT
    } else {
        HTCAPTION
    }
}

unsafe extern "system" fn subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    // SAFETY: Windows calls this on the window's thread with valid message
    // arguments. For WM_NCCALCSIZE with wparam != 0, lparam points to a
    // NCCALCSIZE_PARAMS owned by the caller for the duration of the call.
    unsafe {
        match msg {
            WM_NCCALCSIZE if wparam != 0 => {
                let params = lparam as *mut NCCALCSIZE_PARAMS;
                let original_top = (*params).rgrc[0].top;
                let r = DefSubclassProc(hwnd, msg, wparam, lparam);
                if r != 0 {
                    return r;
                }
                // Drop the caption strip, keep the side and bottom borders.
                let rect: &mut RECT = &mut (*params).rgrc[0];
                rect.top = original_top;
                let zoomed = IsZoomed(hwnd) != 0;
                if zoomed {
                    // A maximised window hangs over the screen edge by the
                    // frame thickness; keep the content on screen.
                    rect.top += frame_thickness(hwnd);
                }
                if ZOOMED.swap(zoomed as i32, Ordering::Relaxed) != zoomed as i32 {
                    repaint();
                }
                // Keep Windows from copying the old client pixels to a new
                // spot on resize (from the top or left edge they would land
                // shifted until Remora repaints): the valid source and
                // destination are the same single pixel, so nothing moves.
                let one = RECT {
                    left: rect.left,
                    top: rect.top,
                    right: rect.left + 1,
                    bottom: rect.top + 1,
                };
                (*params).rgrc[1] = one;
                (*params).rgrc[2] = one;
                WVR_VALIDRECTS as LRESULT
            }
            WM_NCHITTEST => {
                let hit = DefSubclassProc(hwnd, msg, wparam, lparam);
                if hit != HTCLIENT as LRESULT {
                    return hit;
                }
                let mut pt = POINT {
                    x: (lparam & 0xFFFF) as i16 as i32,
                    y: ((lparam >> 16) & 0xFFFF) as i16 as i32,
                };
                ScreenToClient(hwnd, &mut pt);
                let border = frame_thickness(hwnd);
                if IsZoomed(hwnd) == 0 && pt.y < border {
                    let mut rc = RECT::default();
                    GetClientRect(hwnd, &mut rc);
                    return if pt.x < border * 2 {
                        HTTOPLEFT as LRESULT
                    } else if pt.x > rc.right - border * 2 {
                        HTTOPRIGHT as LRESULT
                    } else {
                        HTTOP as LRESULT
                    };
                }
                let hit = match CAPTION.lock() {
                    Ok(g) => g.as_ref().map_or(HTCLIENT, |c| caption_hit(c, pt.x, pt.y)),
                    Err(_) => HTCLIENT,
                };
                hit as LRESULT
            }
            WM_NCMOUSEMOVE => {
                let over = wparam == HTMAXBUTTON as WPARAM;
                if over && !MAX_HOVERED.load(Ordering::Relaxed) {
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE | TME_NONCLIENT,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    TrackMouseEvent(&mut tme);
                }
                set_flag(&MAX_HOVERED, over);
                if !over {
                    set_flag(&MAX_PRESSED, false);
                }
                DefSubclassProc(hwnd, msg, wparam, lparam)
            }
            WM_NCMOUSELEAVE => {
                set_flag(&MAX_HOVERED, false);
                set_flag(&MAX_PRESSED, false);
                DefSubclassProc(hwnd, msg, wparam, lparam)
            }
            // The maximise button is Remora's; the default handler would draw a
            // legacy button.
            WM_NCLBUTTONDOWN | WM_NCLBUTTONDBLCLK if wparam == HTMAXBUTTON as WPARAM => {
                set_flag(&MAX_PRESSED, true);
                0
            }
            WM_NCLBUTTONUP if wparam == HTMAXBUTTON as WPARAM => {
                if MAX_PRESSED.swap(false, Ordering::Relaxed) {
                    ShowWindow(
                        hwnd,
                        if IsZoomed(hwnd) != 0 {
                            SW_RESTORE
                        } else {
                            SW_MAXIMIZE
                        },
                    );
                }
                repaint();
                0
            }
            _ => DefSubclassProc(hwnd, msg, wparam, lparam),
        }
    }
}
