//! rdpc: prototype RDP client.
//!
//!   rdpc                                     connection manager
//!   rdpc <host[:port]> -u <[DOMAIN\]user> [-d domain] [--size WxH] [-v]
//!        [--compression off|rdp4|rdp5|rdp6|rdp61] [--gfx] [--multimon] [--kerberos]
//!                                            one session window
//!   rdpc <host> -u <user> --screenshot out.png [--wait SECONDS]
//!                                            headless: save the desktop as PNG
//!   rdpc <host> -u <user> --record out.mp4 [--wait SECONDS] [--screenshot out.png]
//!                                            headless: record the session as MP4
//!   rdpc --snapshot-ui out.png [--scale 1.5] render the manager offscreen
//!   rdpc --icon-png out.png [--icon-size N]  write the app icon as a PNG
//!   rdpc --version                           print `rdpc <version>`
//!
//! The password comes from RDP_PASSWORD or an interactive prompt.

mod app;
mod audio;
mod clipboard;
mod controls;
#[cfg(windows)]
mod frame;
#[cfg(windows)]
mod h264_mf;
mod icon;
mod keyhook;
mod known_hosts;
mod mic;
mod picker;
mod printing;
mod recorder;
mod session;
mod settings;
mod smartcard;
#[cfg(windows)]
mod sspi;
mod store;
mod text_field;
mod theme;
mod ui;
mod vault;

use std::time::{Duration, Instant};

use ffwd_render::{Canvas, TextEngine};
use rdp::{Client, Config};

#[derive(Default)]
struct Args {
    host: String,
    port: u16,
    user: String,
    domain: String,
    /// RD Gateway `host[:port]`; it takes the RDP credentials.
    gateway: Option<(String, u16)>,
    size: Option<(u16, u16)>,
    screenshot: Option<String>,
    /// `--record out.mp4`: headless recording for `--wait` seconds.
    record: Option<String>,
    snapshot_ui: Option<String>,
    icon_png: Option<String>,
    icon_size: usize,
    version: bool,
    scale: f32,
    wait: u64,
    verbose: bool,
    compression: rdp::Compression,
    /// `--microphone [index]`: Some(None) is the default device.
    microphone: Option<Option<u32>>,
    list_microphones: bool,
    gfx: bool,
    /// `--multimon`: span the session over all local monitors.
    multimon: bool,
    /// `--kerberos`: NLA through Windows SSPI Negotiate (Kerberos, NTLM fallback).
    kerberos: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: rdpc                                   (connection manager)\n\
         \x20      rdpc <host[:port]> -u <[DOMAIN\\]user> [-d domain] [--size WxH] [-v]\n\
         \x20           [--gateway gwhost[:port]]   (RD Gateway, same credentials)\n\
         \x20           [--compression off|rdp4|rdp5|rdp6|rdp61]\n\
         \x20           [--gfx]   (graphics pipeline, MS-RDPEGFX)\n\
         \x20           [--multimon]   (all local monitors, MS-RDPBCGR 2.2.1.3.6)\n\
         \x20           [--kerberos]   (Windows Negotiate: Kerberos, NTLM fallback;\n\
         \x20                           without -u: single sign-on as the logged-on user)\n\
         \x20      rdpc <host> -u <user> --screenshot out.png [--wait SECONDS]\n\
         \x20      rdpc <host> -u <user> --record out.mp4 [--wait SECONDS]\n\
         \x20      rdpc ... --microphone [INDEX]   (microphone on; see --list-microphones)\n\
         \x20      rdpc --snapshot-ui out.png [--scale 1.5]\n\
         \x20      rdpc --icon-png out.png [--icon-size N]\n\
         \x20      rdpc --version\n\
         password: RDP_PASSWORD environment variable, otherwise prompted"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        port: 3389,
        scale: 1.0,
        wait: 15,
        icon_size: 256,
        ..Default::default()
    };
    let mut it = std::env::args().skip(1).peekable();
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "-u" | "--user" => a.user = val(),
            "-d" | "--domain" => a.domain = val(),
            "--gateway" => {
                let v = val();
                a.gateway = Some(match v.rsplit_once(':') {
                    Some((h, p)) => (h.into(), p.parse().unwrap_or_else(|_| usage())),
                    None => (v, 443),
                });
            }
            "--size" => {
                let v = val();
                let (w, h) = v.split_once('x').unwrap_or_else(|| usage());
                a.size = Some((
                    w.parse().unwrap_or_else(|_| usage()),
                    h.parse().unwrap_or_else(|_| usage()),
                ));
            }
            "--screenshot" => a.screenshot = Some(val()),
            "--record" => a.record = Some(val()),
            "--snapshot-ui" => a.snapshot_ui = Some(val()),
            "--icon-png" => a.icon_png = Some(val()),
            "--icon-size" => {
                a.icon_size = val()
                    .parse()
                    .ok()
                    .filter(|n| (16..=1024).contains(n))
                    .unwrap_or_else(|| usage())
            }
            "-V" | "--version" => a.version = true,
            "--scale" => a.scale = val().parse().unwrap_or_else(|_| usage()),
            "--wait" => a.wait = val().parse().unwrap_or_else(|_| usage()),
            "-v" | "--verbose" => a.verbose = true,
            "--compression" => {
                a.compression = rdp::Compression::from_name(&val()).unwrap_or_else(|| usage())
            }
            "--microphone" => {
                let index = it.next_if(|v| v.parse::<u32>().is_ok());
                a.microphone = Some(index.and_then(|v| v.parse().ok()));
            }
            "--list-microphones" => a.list_microphones = true,
            "--gfx" => a.gfx = true,
            "--multimon" => a.multimon = true,
            "--kerberos" => a.kerberos = true,
            "-h" | "--help" => usage(),
            s if s.starts_with('-') => usage(),
            s => {
                if let Some((h, p)) = s.rsplit_once(':').filter(|(h, _)| !h.contains(':')) {
                    a.host = h.into();
                    a.port = p.parse().unwrap_or_else(|_| usage());
                } else {
                    a.host = s.into();
                }
            }
        }
    }
    // cmd.exe passes single quotes through literally: 'DOMAIN\user' keeps its quotes.
    a.user = strip_quotes(&a.user);
    a.domain = strip_quotes(&a.domain);
    // --kerberos without -u signs on as the logged-on Windows user.
    if !a.host.is_empty() && a.user.is_empty() && !a.kerberos
        || (a.screenshot.is_some() || a.record.is_some()) && a.host.is_empty()
    {
        usage();
    }
    a
}

fn strip_quotes(s: &str) -> String {
    for q in ['\'', '"'] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn main() {
    let args = parse_args();
    // -v, or Settings > Diagnostic log: trace to stderr and to the log file.
    settings::apply_logging(args.verbose || settings::AppSettings::load().diagnostic_log);

    if args.version {
        // The installer test and support reports read this line.
        println!("rdpc {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Some(path) = &args.icon_png {
        // The app icon as a PNG with transparency (packaging, README);
        // scripts/make-icon.ps1 builds assets/rdpc.ico from several sizes.
        let size = args.icon_size;
        let write = || -> Result<(), Box<dyn std::error::Error>> {
            let file = std::io::BufWriter::new(std::fs::File::create(path)?);
            let mut enc = png::Encoder::new(file, size as u32, size as u32);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            enc.write_header()?.write_image_data(&icon::rgba(size))?;
            Ok(())
        };
        if let Err(e) = write() {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        eprintln!("saved {size}x{size} icon to {path}");
        return;
    }
    if let Some(path) = &args.snapshot_ui {
        if let Err(e) = snapshot_ui(path, args.scale) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.list_microphones {
        for (i, name) in mic::input_devices().iter().enumerate() {
            println!("{i}: {name}");
        }
        return;
    }
    if let Some(device) = args.microphone {
        controls::enable_microphone_for_all(device);
    }
    if args.host.is_empty() {
        #[cfg(windows)]
        if !args.verbose {
            release_own_console();
        }
        std::process::exit(app::run(None));
    }

    let password = match std::env::var("RDP_PASSWORD") {
        Ok(p) => p,
        // Single sign-on: SSPI takes the logged-on user's credentials.
        Err(_) if args.kerberos && args.user.is_empty() => String::new(),
        Err(_) => rpassword::prompt_password(format!("Password for {}: ", args.user))
            .unwrap_or_else(|e| {
                eprintln!("cannot read password: {e}");
                std::process::exit(2)
            }),
    };
    let mut cfg = Config::new(&args.host, &args.user, &password);
    cfg.port = args.port;
    cfg.domain = args.domain.clone();
    if let Some((host, port)) = &args.gateway {
        let mut gw = rdp::GatewayConfig::new(host, &args.user, &password);
        gw.port = *port;
        gw.domain = args.domain.clone();
        cfg.gateway = Some(gw);
    }
    cfg.compression = args.compression;
    if args.kerberos {
        #[cfg(windows)]
        {
            cfg.auth = Some(sspi::factory());
        }
        #[cfg(not(windows))]
        {
            eprintln!("--kerberos needs Windows SSPI");
            std::process::exit(2);
        }
    }
    if let Some((w, h)) = args.size {
        cfg.width = w;
        cfg.height = h;
    }
    if args.multimon {
        cfg.monitors = local_monitors();
        eprintln!("{} local monitors: {:?}", cfg.monitors.len(), cfg.monitors);
    }
    if args.gfx {
        cfg.graphics = rdp::Graphics::Gfx;
        #[cfg(windows)]
        {
            cfg.h264 = Some(h264_mf::factory());
        }
    }

    if args.screenshot.is_some() || args.record.is_some() {
        let wait = Duration::from_secs(args.wait);
        let (png, mp4) = (args.screenshot.as_deref(), args.record.as_deref());
        if let Err(e) = screenshot(&cfg, png, mp4, wait) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    } else {
        std::process::exit(app::run(Some((args.host.clone(), cfg))));
    }
}

/// The connection manager started from the Start menu or Explorer gets a
/// console window of its own (rdpc is a console program for its command
/// line modes). Nobody reads it there, so the manager lets go of it. A
/// console shared with a shell (a terminal or `cargo run`) stays.
#[cfg(windows)]
fn release_own_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut pids = [0u32; 2];
    // SAFETY: the buffer is valid for its stated length.
    let attached = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    if attached == 1 {
        // SAFETY: no arguments; a failure only leaves the console open.
        unsafe { FreeConsole() };
    }
}

/// The local monitors in virtual-screen coordinates, with their effective
/// scale (EnumDisplayMonitors, GetMonitorInfoW, GetDpiForMonitor).
#[cfg(windows)]
fn local_monitors() -> Vec<rdp::Monitor> {
    use windows_sys::Win32::Foundation::{LPARAM, RECT};
    use windows_sys::Win32::Graphics::Gdi::{
        EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO,
    };
    use windows_sys::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
        SetThreadDpiAwarenessContext,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::MONITORINFOF_PRIMARY;
    use windows_sys::core::BOOL;

    unsafe extern "system" fn add(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
        // SAFETY: `data` is the Vec passed below, alive for the whole call.
        let list = unsafe { &mut *(data as *mut Vec<rdp::Monitor>) };
        let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        // SAFETY: `info` is a valid MONITORINFO with cbSize set.
        if unsafe { GetMonitorInfoW(m, &mut info) } == 0 {
            return 1;
        }
        let (mut dx, mut dy) = (96u32, 96u32);
        // SAFETY: valid monitor handle and out pointers.
        let scale = match unsafe { GetDpiForMonitor(m, MDT_EFFECTIVE_DPI, &mut dx, &mut dy) } {
            0 => dx * 100 / 96,
            _ => 0,
        };
        let r = info.rcMonitor;
        list.push(rdp::Monitor {
            left: r.left,
            top: r.top,
            right: r.right - 1,
            bottom: r.bottom - 1,
            primary: info.dwFlags & MONITORINFOF_PRIMARY != 0,
            scale,
            ..Default::default()
        });
        1
    }

    let mut list: Vec<rdp::Monitor> = Vec::new();
    // Physical pixels, not DPI-virtualized ones, for this thread only.
    // SAFETY: plain calls; the previous context is restored after.
    unsafe {
        let old = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            Some(add),
            &mut list as *mut Vec<rdp::Monitor> as LPARAM,
        );
        if !old.is_null() {
            SetThreadDpiAwarenessContext(old);
        }
    }
    list
}

#[cfg(not(windows))]
fn local_monitors() -> Vec<rdp::Monitor> {
    eprintln!("--multimon: monitor enumeration is Windows-only; using one monitor");
    Vec::new()
}

/// Headless mode: connect, wait until the screen has settled, save a PNG and
/// disconnect. With `record`, the session is recorded to that MP4 file for
/// the whole `max_wait` instead of stopping once the screen settles.
fn screenshot(
    cfg: &Config,
    path: Option<&str>,
    record: Option<&str>,
    max_wait: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("connecting to {}:{} ...", cfg.host, cfg.port);
    let mut client = Client::connect(cfg)?;
    let info = client.info().clone();
    eprintln!(
        "connected: protocol {:#x}, desktop {}x{} at {} bpp, server RDP version {:#x}",
        info.protocol, info.width, info.height, info.bpp, info.server_rdp_version
    );
    eprintln!(
        "server certificate SHA-256 {} (not verified: prototype)",
        hex(&info.certificate_sha256)
    );
    if let Some(gw) = &info.gateway_certificate_sha256 {
        eprintln!(
            "gateway certificate SHA-256 {} (not verified: prototype)",
            hex(gw)
        );
    }
    let mut recorder = match record {
        Some(p) => Some(recorder::Recorder::start(
            std::path::Path::new(p),
            info.width as u32,
            info.height as u32,
            recorder::DEFAULT_FPS,
        )?),
        None => None,
    };
    let start = Instant::now();
    let mut last_update: Option<Instant> = None;
    let mut refreshed = false;
    while start.elapsed() < max_wait {
        let out = client.poll(Duration::from_millis(50))?;
        if let Some(reason) = out.closed {
            return Err(format!("session closed: {reason}").into());
        }
        if out.updated {
            last_update = Some(Instant::now());
            if let Some(r) = recorder.as_mut() {
                r.frame(client.framebuffer());
            }
        }
        if client.is_active() && !refreshed {
            client.request_refresh()?;
            refreshed = true;
        }
        if recorder.is_none()
            && last_update.is_some_and(|t| t.elapsed() > Duration::from_millis(2500))
        {
            break;
        }
    }
    if last_update.is_none() {
        eprintln!("warning: no screen updates received within {max_wait:?}");
    }
    if let Some(r) = recorder {
        let i = r.finish()?;
        eprintln!(
            "recorded {:.1} s, {} frames, {} bytes to {}",
            i.duration.as_secs_f64(),
            i.frames,
            i.bytes,
            i.path.display()
        );
    }
    if let Some(path) = path {
        let fb = client.framebuffer();
        write_png(path, fb.width, fb.height, &fb.pixels)?;
        eprintln!("saved {}x{} screenshot to {path}", fb.width, fb.height);
    }
    client.disconnect();
    Ok(())
}

/// Renders the window with sample data offscreen, using the window's paint
/// code: `out.png` shows the Connections tab, `out-session.png` a session tab
/// with the control drawer (the remote picture area is left empty).
fn snapshot_ui(path: &str, scale: f32) -> Result<(), Box<dyn std::error::Error>> {
    let mut te = TextEngine::new();
    let fonts = ui::load_fonts(&mut te).ok_or("no usable UI font")?;
    let (w, h) = ((1320.0 * scale) as usize, (860.0 * scale) as usize);
    for (session, out) in [
        (false, path.to_string()),
        (true, path.replace(".png", "-session.png")),
    ] {
        let mut m = ui::sample(session);
        m.scale = scale;
        m.custom_frame = cfg!(windows);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        write_png(&out, w, h, &px)?;
        eprintln!("saved {w}x{h} snapshot to {out}");
    }
    // The quick panel pages, and full screen.
    for (page, full, suffix) in [
        (20, false, "-form-general"),
        (21, false, "-form-display"),
        (22, false, "-form-experience"),
        (23, false, "-form-sharing"),
        (24, false, "-form-advanced"),
        (30, false, "-settings"),
        (31, false, "-settings-vault"),
        (8, false, "-cert"),
        (9, false, "-cert-changed"),
        (1, false, "-panel-display"),
        (2, false, "-panel-quality"),
        (3, false, "-panel-session"),
        (0, true, "-fullscreen"),
    ] {
        let mut m = match page {
            8 | 9 => ui::sample_cert(page == 9),
            30.. => ui::sample_settings(page == 31),
            20.. => ui::sample_form(page - 20),
            _ => ui::sample_panel(page, full),
        };
        m.scale = scale;
        m.custom_frame = cfg!(windows);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        let out = path.replace(".png", &format!("{suffix}.png"));
        write_png(&out, w, h, &px)?;
        eprintln!("saved {w}x{h} snapshot to {out}");
    }
    // The group form.
    let mut m = ui::sample_group();
    m.scale = scale;
    m.custom_frame = cfg!(windows);
    let mut px = vec![0u32; w * h];
    m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
    let out = path.replace(".png", "-group.png");
    write_png(&out, w, h, &px)?;
    eprintln!("saved {w}x{h} snapshot to {out}");
    // The unlock screen of an encrypted vault.
    let mut m = ui::Ui::new(store::Store::locked_sample(), scale);
    m.custom_frame = cfg!(windows);
    let mut px = vec![0u32; w * h];
    m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
    let out = path.replace(".png", "-unlock.png");
    write_png(&out, w, h, &px)?;
    eprintln!("saved {w}x{h} snapshot to {out}");
    Ok(())
}

fn write_png(path: &str, w: usize, h: usize, px: &[u32]) -> Result<(), Box<dyn std::error::Error>> {
    let rgb: Vec<u8> = px
        .iter()
        .flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8])
        .collect();
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, w as u32, h as u32);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(&rgb)?;
    Ok(())
}
