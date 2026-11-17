//! `remora-agent capture-probe [seconds]` (RDP-67, first step): can the
//! helper capture the session's picture itself, and how fast?
//!
//! - Lists the session's display adapters and outputs (a remote session
//!   has its own: the remote display adapter, or a GPU with the "hardware
//!   graphics adapter for RDS" policy).
//! - Duplicates the desktop (DXGI Desktop Duplication) while a small square
//!   in this session animates at about 60 fps, and measures: frames
//!   captured per second, the delay from the present to our capture
//!   (`LastPresentTime`), the cost of copying a frame to the CPU, and every
//!   error (lost access, a disconnected session).
//! - Lists the H.264, HEVC and AV1 encoders Media Foundation offers, and
//!   which are hardware.
//! - Benchmarks the hardware encoders on the captured picture ([`encode`],
//!   RDP-67 second step).
//!
//! Only reads and measures: nothing is sent anywhere; the square is the one
//! visible effect, and it closes when the probe ends.

mod encode;

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, InvalidateRect, PAINTSTRUCT,
};
use windows::Win32::Media::MediaFoundation::{
    MFVideoFormat_AV1, MFVideoFormat_H264, MFVideoFormat_HEVC,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetSystemMetrics, KillTimer,
    MSG, PM_REMOVE, PeekMessageW, RegisterClassW, SM_REMOTESESSION, SetTimer, TranslateMessage,
    WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows::core::{Interface, w};

fn wide_str(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

/// Runs the probe for `seconds` and returns the report.
pub fn run(seconds: u64) -> String {
    let mut r = String::new();
    // SAFETY: a plain query.
    let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    r += &format!("session: {}\n", if remote { "remote" } else { "console" });
    let adapters = adapters(&mut r);
    let anim = Animation::start();
    let captured = capture(&adapters, seconds, &mut r);
    drop(anim);
    encoders(&mut r);
    match captured {
        Some((d, Some(snapshot))) => encode::run(&d.device, &d.context, &snapshot, &mut r),
        Some((_, None)) => r += "encode: no frame was captured to encode\n",
        None => r += "encode: skipped (no capture)\n",
    }
    r
}

fn adapters(r: &mut String) -> Vec<IDXGIAdapter1> {
    let mut out = Vec::new();
    // SAFETY: DXGI enumeration; descriptors are plain data.
    unsafe {
        let factory: IDXGIFactory1 = match CreateDXGIFactory1() {
            Ok(f) => f,
            Err(e) => {
                *r += &format!("dxgi factory: {e}\n");
                return out;
            }
        };
        let mut i = 0;
        while let Ok(a) = factory.EnumAdapters1(i) {
            i += 1;
            let Ok(d) = a.GetDesc1() else { continue };
            let soft = d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0;
            *r += &format!(
                "adapter {}: {}{} (video memory {} MB, LUID {})\n",
                i - 1,
                wide_str(&d.Description),
                if soft { " [software]" } else { "" },
                d.DedicatedVideoMemory >> 20,
                encode::luid_str(encode::pack_luid(d.AdapterLuid))
            );
            let mut j = 0;
            while let Ok(o) = a.EnumOutputs(j) {
                j += 1;
                if let Ok(od) = o.GetDesc() {
                    let c = od.DesktopCoordinates;
                    *r += &format!(
                        "  output {}: {} {}x{}{}\n",
                        j - 1,
                        wide_str(&od.DeviceName),
                        c.right - c.left,
                        c.bottom - c.top,
                        if od.AttachedToDesktop.as_bool() {
                            ""
                        } else {
                            " (not attached)"
                        }
                    );
                }
            }
            out.push(a);
        }
    }
    out
}

struct Dup {
    context: ID3D11DeviceContext,
    device: ID3D11Device,
    output: IDXGIOutput1,
    dupl: IDXGIOutputDuplication,
}

/// The first adapter output that can be duplicated.
fn duplicate(adapters: &[IDXGIAdapter1], r: &mut String) -> Option<Dup> {
    for (i, a) in adapters.iter().enumerate() {
        // SAFETY: COM calls on valid interfaces; out pointers to locals.
        unsafe {
            let Ok(o) = a.EnumOutputs(0) else { continue };
            let Ok(output) = o.cast::<IDXGIOutput1>() else {
                continue;
            };
            let mut device = None;
            let mut context = None;
            // Video support for the encode benchmark's converter; not every
            // adapter has it.
            let create = |flags, device: &mut Option<_>, context: &mut Option<_>| {
                D3D11CreateDevice(
                    a,
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE::default(),
                    flags,
                    None,
                    D3D11_SDK_VERSION,
                    Some(device),
                    None,
                    Some(context),
                )
            };
            if create(
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                &mut device,
                &mut context,
            )
            .is_err()
                && let Err(e) = create(D3D11_CREATE_DEVICE_BGRA_SUPPORT, &mut device, &mut context)
            {
                *r += &format!("adapter {i}: no Direct3D 11 device: {e}\n");
                continue;
            }
            let (Some(device), Some(context)) = (device, context) else {
                continue;
            };
            match output.DuplicateOutput(&device) {
                Ok(dupl) => {
                    *r += &format!("duplication: adapter {i}, output 0\n");
                    return Some(Dup {
                        context,
                        device,
                        output,
                        dupl,
                    });
                }
                Err(e) => *r += &format!("adapter {i}: DuplicateOutput failed: {e}\n"),
            }
        }
    }
    None
}

fn qpc() -> i64 {
    let mut t = 0;
    // SAFETY: an out value.
    let _ = unsafe { QueryPerformanceCounter(&mut t) };
    t
}

/// Measures capture; returns the duplication's device and the last full
/// frame for the encode benchmark.
fn capture(
    adapters: &[IDXGIAdapter1],
    seconds: u64,
    r: &mut String,
) -> Option<(Dup, Option<ID3D11Texture2D>)> {
    let Some(mut d) = duplicate(adapters, r) else {
        *r += "capture: not possible in this session\n";
        return None;
    };
    let mut snapshot: Option<ID3D11Texture2D> = None;
    let mut freq = 0;
    // SAFETY: an out value.
    let _ = unsafe { QueryPerformanceFrequency(&mut freq) };
    let ms = |ticks: i64| ticks as f64 * 1000.0 / freq.max(1) as f64;
    let (mut frames, mut presented, mut accumulated, mut timeouts, mut lost) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut delay_sum, mut delay_max) = (0f64, 0f64);
    let (mut copy_sum, mut copies) = (0f64, 0u64);
    let mut staging: Option<ID3D11Texture2D> = None;
    let mut size = (0u32, 0u32);
    let mut errors: Vec<String> = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        // SAFETY: COM calls on the duplication; every frame is released.
        match unsafe { d.dupl.AcquireNextFrame(100, &mut info, &mut res) } {
            Ok(()) => {
                let now = qpc();
                frames += 1;
                accumulated += info.AccumulatedFrames as u64;
                if info.LastPresentTime != 0 {
                    presented += 1;
                    let delay = ms(now - info.LastPresentTime);
                    delay_sum += delay;
                    delay_max = delay_max.max(delay);
                    // What a software encoder would pay: the frame to the CPU.
                    if let Some(tex) = res.as_ref().and_then(|r| r.cast::<ID3D11Texture2D>().ok()) {
                        let t = Instant::now();
                        if copy_to_cpu(&d, &tex, &mut staging, &mut size) {
                            copy_sum += t.elapsed().as_secs_f64() * 1000.0;
                            copies += 1;
                        }
                        // The source of the encode benchmark (kept after the
                        // timing above, so it does not count there).
                        if snapshot.is_none() || presented % 60 == 0 {
                            keep_frame(&d, &tex, &mut snapshot);
                        }
                    }
                }
                // SAFETY: the frame acquired above.
                let _ = unsafe { d.dupl.ReleaseFrame() };
            }
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => timeouts += 1,
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                lost += 1;
                // SAFETY: a new duplication of the same output.
                match unsafe { d.output.DuplicateOutput(&d.device) } {
                    Ok(n) => d.dupl = n,
                    Err(e) => {
                        errors.push(format!("re-duplicating: {e}"));
                        break;
                    }
                }
            }
            Err(e) => {
                errors.push(format!("AcquireNextFrame: {e}"));
                if errors.len() > 5 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let secs = start.elapsed().as_secs_f64();
    *r += &format!(
        "capture: {frames} frames in {secs:.1} s, {presented} with a new picture ({:.1} fps), {accumulated} presents counted, {timeouts} timeouts, {lost} lost-access\n",
        presented as f64 / secs
    );
    if presented > 0 {
        *r += &format!(
            "  present -> capture delay: {:.2} ms average, {:.2} ms max\n",
            delay_sum / presented as f64,
            delay_max
        );
    }
    if copies > 0 {
        *r += &format!(
            "  frame {}x{} to the CPU: {:.2} ms average\n",
            size.0,
            size.1,
            copy_sum / copies as f64
        );
    }
    for e in errors {
        *r += &format!("  error: {e}\n");
    }
    Some((d, snapshot))
}

/// Copies a captured frame into `snapshot` (created on first use).
fn keep_frame(d: &Dup, tex: &ID3D11Texture2D, snapshot: &mut Option<ID3D11Texture2D>) {
    // SAFETY: a GPU copy between textures of the same description.
    unsafe {
        if snapshot.is_none() {
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            tex.GetDesc(&mut desc);
            let s = D3D11_TEXTURE2D_DESC {
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
                MipLevels: 1,
                ArraySize: 1,
                ..desc
            };
            let mut t = None;
            if d.device.CreateTexture2D(&s, None, Some(&mut t)).is_err() {
                return;
            }
            *snapshot = t;
        }
        if let Some(s) = snapshot.as_ref() {
            d.context.CopyResource(s, tex);
        }
    }
}

/// Copies a captured frame into a CPU-readable texture and maps it.
fn copy_to_cpu(
    d: &Dup,
    tex: &ID3D11Texture2D,
    staging: &mut Option<ID3D11Texture2D>,
    size: &mut (u32, u32),
) -> bool {
    // SAFETY: D3D11 calls on valid objects; the map is undone right away.
    unsafe {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        tex.GetDesc(&mut desc);
        if staging.is_none() || *size != (desc.Width, desc.Height) {
            let s = D3D11_TEXTURE2D_DESC {
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
                MipLevels: 1,
                ArraySize: 1,
                ..desc
            };
            let mut t = None;
            if d.device.CreateTexture2D(&s, None, Some(&mut t)).is_err() {
                return false;
            }
            *staging = t;
            *size = (desc.Width, desc.Height);
        }
        let Some(st) = staging.as_ref() else {
            return false;
        };
        d.context.CopyResource(st, tex);
        let mut m = D3D11_MAPPED_SUBRESOURCE::default();
        if d.context
            .Map(st, 0, D3D11_MAP_READ, 0, Some(&mut m))
            .is_err()
        {
            return false;
        }
        d.context.Unmap(st, 0);
        true
    }
}

fn encoders(r: &mut String) {
    for (name, subtype) in [
        ("H.264", MFVideoFormat_H264),
        ("HEVC", MFVideoFormat_HEVC),
        ("AV1", MFVideoFormat_AV1),
    ] {
        for (kind, hardware) in [("hardware", true), ("software", false)] {
            let names: Vec<String> = encode::list(subtype, hardware, false, None)
                .into_iter()
                .map(|f| f.name)
                .collect();
            *r += &format!(
                "encoder {name} {kind}: {}\n",
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            );
        }
    }
}

/// A small square that changes colour on every 15 ms timer tick, so the
/// desktop has something to present at about 60 fps.
struct Animation {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

unsafe extern "system" fn wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    use std::sync::atomic::Ordering;
    // SAFETY: GDI calls on our own window during WM_PAINT/WM_TIMER.
    unsafe {
        match msg {
            WM_TIMER => {
                TICK.fetch_add(1, Ordering::Relaxed);
                let _ = InvalidateRect(Some(h), None, false);
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let dc = BeginPaint(h, &mut ps);
                let t = TICK.load(Ordering::Relaxed);
                let colour = windows::Win32::Foundation::COLORREF(
                    (t * 7 % 256) | ((t * 13 % 256) << 8) | ((t * 29 % 256) << 16),
                );
                let brush = CreateSolidBrush(colour);
                let rc = RECT {
                    left: 0,
                    top: 0,
                    right: 160,
                    bottom: 160,
                };
                FillRect(dc, &rc, brush);
                let _ = DeleteObject(brush.into());
                let _ = EndPaint(h, &ps);
                LRESULT(0)
            }
            _ => DefWindowProcW(h, msg, w, l),
        }
    }
}

impl Animation {
    fn start() -> Animation {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::spawn(move || {
            // SAFETY: a window of this thread, destroyed before it ends.
            unsafe {
                let Ok(inst) = GetModuleHandleW(None) else {
                    return;
                };
                let class = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: inst.into(),
                    lpszClassName: w!("RemoraCaptureProbe"),
                    ..Default::default()
                };
                RegisterClassW(&class);
                let Ok(h) = CreateWindowExW(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                    w!("RemoraCaptureProbe"),
                    w!("Remora capture probe"),
                    WS_POPUP | WS_VISIBLE,
                    40,
                    40,
                    160,
                    160,
                    None,
                    None,
                    Some(inst.into()),
                    None,
                ) else {
                    return;
                };
                SetTimer(Some(h), 1, 15, None);
                let mut msg = MSG::default();
                while !s.load(std::sync::atomic::Ordering::Relaxed) {
                    while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                let _ = KillTimer(Some(h), 1);
                let _ = DestroyWindow(h);
            }
        });
        Animation {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Animation {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
