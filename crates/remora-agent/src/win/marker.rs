//! The latency meter's marker (RDP-67): a small square near the top-left
//! corner of the primary monitor, repainted in the colour Remora asks for.
//! Remora times how long the colour takes to reach its picture.
//!
//! The window lives on its own thread: topmost, never activated, not in the
//! taskbar, and gone with the [`Marker`] (Remora's `LatencyEnd`, or its
//! session ending). Coordinates are physical pixels (the thread is
//! per-monitor DPI aware), reported from the virtual desktop's top-left
//! corner, which is where Remora's picture starts.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, EnumDisplayMonitors, FillRect, GdiFlush,
    HDC, HMONITOR, InvalidateRect, PAINTSTRUCT, UpdateWindow,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetWindowRect, MSG,
    PM_REMOVE, PeekMessageW, RegisterClassW, SW_SHOWNOACTIVATE, ShowWindow, TranslateMessage,
    WM_PAINT, WNDCLASSW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};
use windows::core::{BOOL, w};

use super::agent::Input;

/// Side of the square, in physical pixels: large enough to keep its colour
/// through a video codec's chroma subsampling.
pub const SIZE: i32 = 32;
/// Distance from the primary monitor's top-left corner.
const MARGIN: i32 = 8;

/// The colour the window paints (0xRRGGBB).
static RGB: AtomicU32 = AtomicU32::new(0);

enum Cmd {
    Show { request_id: u32, rgb: u32 },
}

pub struct Marker {
    tx: Option<Sender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl Marker {
    /// Creates the window (on first [`Marker::show`]); every painted mark
    /// goes back to the agent loop as [`Input::MarkerShown`].
    pub fn start(out: Sender<Input>) -> Marker {
        let (tx, rx) = mpsc::channel::<Cmd>();
        let thread = std::thread::Builder::new()
            .name("latency-marker".into())
            .spawn(move || run(rx, out))
            .ok();
        Marker {
            tx: Some(tx),
            thread,
        }
    }

    pub fn show(&self, request_id: u32, rgb: u32) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Cmd::Show { request_id, rgb });
        }
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        // The thread sees the channel close, destroys the window and ends.
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

unsafe extern "system" fn wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    // SAFETY: GDI calls on our own window during WM_PAINT.
    unsafe {
        if msg == WM_PAINT {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(h, &mut ps);
            let rgb = RGB.load(Ordering::Relaxed);
            // COLORREF is 0x00BBGGRR.
            let bgr = ((rgb & 0xff) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 0xff);
            let brush = CreateSolidBrush(COLORREF(bgr));
            let rc = RECT {
                left: 0,
                top: 0,
                right: SIZE,
                bottom: SIZE,
            };
            FillRect(dc, &rc, brush);
            let _ = DeleteObject(brush.into());
            let _ = EndPaint(h, &ps);
            return LRESULT(0);
        }
        DefWindowProcW(h, msg, w, l)
    }
}

/// The virtual desktop's top-left corner (the smallest monitor origin).
fn desktop_origin() -> (i32, i32) {
    unsafe extern "system" fn each(_: HMONITOR, _: HDC, rc: *mut RECT, data: LPARAM) -> BOOL {
        // SAFETY: `data` is the `(i32, i32)` below, `rc` the monitor's rect.
        unsafe {
            let o = &mut *(data.0 as *mut (i32, i32));
            let r = &*rc;
            o.0 = o.0.min(r.left);
            o.1 = o.1.min(r.top);
        }
        true.into()
    }
    let mut o = (0i32, 0i32);
    // SAFETY: the callback only runs during this call.
    unsafe {
        let _ = EnumDisplayMonitors(
            None,
            None,
            Some(each),
            LPARAM(&mut o as *mut (i32, i32) as isize),
        );
    }
    o
}

fn run(rx: mpsc::Receiver<Cmd>, out: Sender<Input>) {
    // SAFETY: a window of this thread, destroyed before it ends.
    unsafe {
        let _ = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let Ok(inst) = GetModuleHandleW(None) else {
            return;
        };
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: inst.into(),
            lpszClassName: w!("RemoraLatencyMarker"),
            ..Default::default()
        };
        RegisterClassW(&class);
        let Ok(h) = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            w!("RemoraLatencyMarker"),
            w!("Remora latency marker"),
            WS_POPUP,
            MARGIN,
            MARGIN,
            SIZE,
            SIZE,
            None,
            None,
            Some(inst.into()),
            None,
        ) else {
            return;
        };
        let mut shown = false;
        let mut msg = MSG::default();
        loop {
            match rx.recv_timeout(Duration::from_millis(5)) {
                Ok(Cmd::Show { request_id, rgb }) => {
                    RGB.store(rgb, Ordering::Relaxed);
                    if !shown {
                        let _ = ShowWindow(h, SW_SHOWNOACTIVATE);
                        shown = true;
                    }
                    // Paint now, not when the queue gets to it.
                    let _ = InvalidateRect(Some(h), None, false);
                    let _ = UpdateWindow(h);
                    let _ = GdiFlush();
                    let mut rc = RECT::default();
                    let _ = GetWindowRect(h, &mut rc);
                    let (ox, oy) = desktop_origin();
                    let _ = out.send(Input::MarkerShown {
                        request_id,
                        x: (rc.left - ox).max(0) as u32,
                        y: (rc.top - oy).max(0) as u32,
                        size: SIZE as u32,
                    });
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let _ = DestroyWindow(h);
    }
}
