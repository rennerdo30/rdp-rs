//! rdpc: prototype RDP client.
//!
//!   rdpc                                     connection manager
//!   rdpc <host[:port]> -u <[DOMAIN\]user> [-d domain] [--size WxH] [-v]
//!                                            one session window
//!   rdpc <host> -u <user> --screenshot out.png [--wait SECONDS]
//!                                            headless: save the desktop as PNG
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
mod icon;
mod printing;
mod session;
mod smartcard;
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
    size: Option<(u16, u16)>,
    screenshot: Option<String>,
    snapshot_ui: Option<String>,
    icon_png: Option<String>,
    icon_size: usize,
    version: bool,
    scale: f32,
    wait: u64,
    verbose: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: rdpc                                   (connection manager)\n\
         \x20      rdpc <host[:port]> -u <[DOMAIN\\]user> [-d domain] [--size WxH] [-v]\n\
         \x20      rdpc <host> -u <user> --screenshot out.png [--wait SECONDS]\n\
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
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "-u" | "--user" => a.user = val(),
            "-d" | "--domain" => a.domain = val(),
            "--size" => {
                let v = val();
                let (w, h) = v.split_once('x').unwrap_or_else(|| usage());
                a.size = Some((
                    w.parse().unwrap_or_else(|_| usage()),
                    h.parse().unwrap_or_else(|_| usage()),
                ));
            }
            "--screenshot" => a.screenshot = Some(val()),
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
    if !a.host.is_empty() && a.user.is_empty() || a.screenshot.is_some() && a.host.is_empty() {
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
    rdp::set_verbose(args.verbose);

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
    if args.host.is_empty() {
        #[cfg(windows)]
        if !args.verbose {
            release_own_console();
        }
        std::process::exit(app::run(None));
    }

    let password = match std::env::var("RDP_PASSWORD") {
        Ok(p) => p,
        Err(_) => rpassword::prompt_password(format!("Password for {}: ", args.user))
            .unwrap_or_else(|e| {
                eprintln!("cannot read password: {e}");
                std::process::exit(2)
            }),
    };
    let mut cfg = Config::new(&args.host, &args.user, &password);
    cfg.port = args.port;
    cfg.domain = args.domain.clone();
    if let Some((w, h)) = args.size {
        cfg.width = w;
        cfg.height = h;
    }

    match &args.screenshot {
        Some(path) => {
            if let Err(e) = screenshot(&cfg, path, Duration::from_secs(args.wait)) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        None => std::process::exit(app::run(Some((args.host.clone(), cfg)))),
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

/// Headless mode: connect, wait until the screen has settled, save a PNG and disconnect.
fn screenshot(
    cfg: &Config,
    path: &str,
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
        }
        if client.is_active() && !refreshed {
            client.request_refresh()?;
            refreshed = true;
        }
        if last_update.is_some_and(|t| t.elapsed() > Duration::from_millis(2500)) {
            break;
        }
    }
    if last_update.is_none() {
        eprintln!("warning: no screen updates received within {max_wait:?}");
    }
    let fb = client.framebuffer();
    write_png(path, fb.width, fb.height, &fb.pixels)?;
    eprintln!("saved {}x{} screenshot to {path}", fb.width, fb.height);
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
        (1, false, "-panel-display"),
        (2, false, "-panel-quality"),
        (3, false, "-panel-session"),
        (0, true, "-fullscreen"),
    ] {
        let mut m = ui::sample_panel(page, full);
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
