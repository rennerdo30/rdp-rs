//! Remora: prototype RDP client (the `remora` executable).
//!
//!   remora                                       connection manager
//!   remora <host[:port]> -u <[DOMAIN\]user> [-d domain] [--size WxH] [-v]
//!          [--compression off|rdp4|rdp5|rdp6|rdp61] [--gfx] [--multimon] [--kerberos]
//!          [--surface-commands] [--drawing-orders]
//!                                                one session window
//!   remora <host> -u <user> --screenshot out.png [--wait SECONDS]
//!                                                headless: save the desktop as PNG
//!   remora <host> -u <user> --record out.mp4 [--wait SECONDS] [--screenshot out.png]
//!                                                headless: record the session as MP4
//!   remora --snapshot-ui out.png [--scale 1.5]   render the manager offscreen
//!   remora --icon-png out.png [--icon-size N]    write the app icon as a PNG
//!   remora --version                             print `Remora <version>`
//!
//! The password comes from RDP_PASSWORD or an interactive prompt.

mod app;
mod audio;
mod audio_mf;
mod clipboard;
mod controls;
mod failure;
#[cfg(windows)]
mod frame;
mod fuzzy;
#[cfg(windows)]
mod h264_mf;
mod helper;
mod helper_app;
mod icon;
mod icons;
mod keyboard;
mod keyhook;
mod kit;
mod known_hosts;
mod link_key;
mod mic;
mod monitors;
mod picker;
mod printing;
mod recorder;
mod remoteapp;
mod session;
mod settings;
mod smartcard;
mod span;
#[cfg(windows)]
mod sspi;
mod store;
mod text_field;
mod theme;
mod thumb;
mod touch;
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
    /// `--only TEXT`: snapshot only the screens whose suffix contains it.
    snapshot_only: Option<String>,
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
    /// `--surface-commands`, `--drawing-orders`: the experimental picture
    /// paths (RemoteFX/NSCodec surface bits, MS-RDPEGDI orders), off by default.
    surface_commands: bool,
    drawing_orders: bool,
    /// `--multimon`: span the session over all local monitors.
    multimon: bool,
    /// `--kerberos`: NLA through Windows SSPI Negotiate (Kerberos, NTLM fallback).
    kerberos: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: remora                                 (connection manager)\n\
         \x20      remora <host[:port]> -u <[DOMAIN\\]user> [-d domain] [--size WxH] [-v]\n\
         \x20           [--gateway gwhost[:port]]   (RD Gateway, same credentials)\n\
         \x20           [--compression off|rdp4|rdp5|rdp6|rdp61]\n\
         \x20           [--gfx]   (graphics pipeline, MS-RDPEGFX)\n\
         \x20           [--surface-commands] [--drawing-orders]   (experimental picture paths)\n\
         \x20           [--multimon]   (all local monitors, MS-RDPBCGR 2.2.1.3.6)\n\
         \x20           [--kerberos]   (Windows Negotiate: Kerberos, NTLM fallback;\n\
         \x20                           without -u: single sign-on as the logged-on user)\n\
         \x20      remora <host> -u <user> --screenshot out.png [--wait SECONDS]\n\
         \x20      remora <host> -u <user> --record out.mp4 [--wait SECONDS]\n\
         \x20      remora ... --microphone [INDEX]   (microphone on; see --list-microphones)\n\
         \x20      remora --snapshot-ui out.png [--scale 1.5] [--only TEXT]\n\
         \x20      remora --icon-png out.png [--icon-size N]\n\
         \x20      remora --version\n\
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
            "--only" => a.snapshot_only = Some(val()),
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
            "--surface-commands" => a.surface_commands = true,
            "--drawing-orders" => a.drawing_orders = true,
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
        println!("Remora {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Some(path) = &args.icon_png {
        // The app icon as a PNG with transparency (packaging, README);
        // scripts/make-icon.ps1 builds assets/remora.ico from several sizes.
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
        if let Err(e) = snapshot_ui(path, args.scale, args.snapshot_only.as_deref()) {
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
    cfg.license_store = settings::license_dir();
    cfg.bitmap_cache_dir = settings::bitmap_cache_dir(&args.host, args.port);
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
        cfg.monitors = monitors::list().into_iter().map(|m| m.monitor).collect();
        eprintln!("{} local monitors: {:?}", cfg.monitors.len(), cfg.monitors);
    }
    cfg.surface_commands = args.surface_commands;
    cfg.drawing_orders = args.drawing_orders;
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
/// console window of its own (Remora is a console program for its command
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
fn snapshot_ui(
    path: &str,
    scale: f32,
    only: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let wanted = |suffix: &str| only.is_none_or(|o| suffix.contains(o));
    let mut te = TextEngine::new();
    let fonts = ui::load_fonts(&mut te).ok_or("no usable UI font")?;
    let (w, h) = ((1320.0 * scale) as usize, (860.0 * scale) as usize);
    // Every screen, in the dark theme and again with "-light" in the name.
    use ui::session_view as sv;
    type Screen<'a> = (&'a str, fn() -> ui::Ui);
    let names: Vec<String> = sv::FAILURES
        .iter()
        .map(|f| format!("-failed-{}", f.0))
        .collect();
    let mut screens: Vec<Screen> = vec![
        ("", || ui::sample(false)),
        ("-session", || ui::sample(true)),
        ("-form-general", || ui::sample_form(0)),
        ("-form-display", || ui::sample_form(1)),
        ("-form-experience", || ui::sample_form(2)),
        ("-form-sharing", || ui::sample_form(3)),
        ("-form-advanced", || ui::sample_form(4)),
        ("-settings", || ui::sample_settings(false)),
        ("-settings-vault", || ui::sample_settings(true)),
        ("-cert", || ui::sample_cert(false)),
        ("-cert-changed", || ui::sample_cert(true)),
        ("-panel-display", || ui::sample_panel(1, false)),
        ("-panel-quality", || ui::sample_panel(2, false)),
        ("-panel-session", || ui::sample_panel(3, false)),
        ("-fullscreen", || ui::sample_panel(0, true)),
        ("-group", ui::sample_group),
        ("-apps-form", ui::sample_apps_form),
        ("-apps-session", ui::sample_apps_tab),
        ("-desktop-apps", ui::sample_desktop_apps),
        // The sidebar folded to its rail, and dragged wider (RDP-38).
        ("-rail", || ui::sample_rail(false)),
        ("-rail-session", || ui::sample_rail(true)),
        ("-resized", ui::sample_resized),
        ("-sidebar-narrow", || {
            let mut m = ui::sample_settings(true);
            m.sidebar_w = 200.0;
            m
        }),
        ("-rail-vault", || {
            let mut m = ui::sample_settings(true);
            m.sidebar_collapsed = true;
            m
        }),
        // The session panel unpinned: its strip, floating, in full
        // screen (RDP-39).
        ("-panel-strip", || ui::sample_panel_strip(false)),
        ("-panel-strip-tip", || ui::sample_panel_strip(true)),
        ("-panel-float", || ui::sample_panel_float(0, false)),
        ("-panel-float-quality", || ui::sample_panel_float(2, false)),
        ("-panel-float-fullscreen", || {
            ui::sample_panel_float(1, true)
        }),
        ("-unlock", || {
            ui::Ui::new(store::Store::locked_sample(), 1.0)
        }),
        ("-exit", ui::sample_exit),
        ("-failed", || ui::sample_tab_state(2)),
        ("-connecting", || ui::sample_tab_state(0)),
        ("-ended", || ui::sample_tab_state(1)),
        ("-spanned", || ui::sample_tab_state(3)),
        ("-empty", ui::sample_empty),
        ("-palette", || ui::sample_palette(false, "")),
        ("-palette-query", || ui::sample_palette(false, "of")),
        ("-palette-session", || ui::sample_palette(true, "")),
        ("-palette-none", || ui::sample_palette(true, "zzq")),
        ("-home", ui::sample_home),
        ("-home-typed", || ui::sample_home_typed("off")),
        ("-home-new-host", || {
            ui::sample_home_typed("alex@10.0.0.99:3390")
        }),
        // The session screens and toolbar (RDP-31).
        ("-connecting-steps", || sv::sample_connecting(false)),
        ("-connecting-gateway", || sv::sample_connecting(true)),
        ("-reconnecting", sv::sample_reconnecting),
        ("-ended-signed-out", || {
            sv::sample_ended(failure::EndReason::SignedOut)
        }),
        ("-ended-other-user", || {
            sv::sample_ended(failure::EndReason::OtherConnection)
        }),
        ("-toolbar-shown", || sv::sample_toolbar(true, false, false)),
        ("-toolbar-hidden", || {
            sv::sample_toolbar(false, false, false)
        }),
        ("-toolbar-menu", || sv::sample_toolbar(true, true, false)),
        ("-fullscreen-toolbar", || {
            sv::sample_toolbar(true, false, true)
        }),
        // The server helper (RDP-42/43/44): pairing, a changed key, link
        // and file cards, the drop target, the panel and the editor.
        ("-helper-pairing", || ui::sample_helper_pairing(false)),
        ("-helper-pairing-changed", || {
            ui::sample_helper_pairing(true)
        }),
        ("-helper-cards", ui::sample_helper_cards),
        ("-helper-drop", || ui::sample_helper_drop(true)),
        ("-helper-drop-off", || ui::sample_helper_drop(false)),
        ("-helper-panel-session", || ui::sample_helper_panel(3, true)),
        ("-helper-panel-failed", || ui::sample_helper_panel(3, false)),
        ("-helper-panel-blocked", || ui::sample_helper_blocked(false)),
        ("-helper-panel-pending", || ui::sample_helper_blocked(true)),
        ("-helper-panel-transfers", || {
            ui::sample_helper_panel(0, true)
        }),
        ("-helper-form", || ui::sample_helper_form(false)),
        ("-helper-forget", || ui::sample_helper_form(true)),
    ];
    // The Home view and the editor at other window sizes (logical px).
    type SizedScreen = (&'static str, fn() -> ui::Ui, f32, f32);
    let sized: [SizedScreen; 5] = [
        ("-home-900", ui::sample_home, 900.0, 760.0),
        ("-home-1920", ui::sample_home, 1920.0, 1080.0),
        ("-home-2560", ui::sample_home, 2560.0, 1400.0),
        ("-empty-1920", ui::sample_empty, 1920.0, 1080.0),
        ("-editor-1920", || ui::sample_form(0), 1920.0, 1080.0),
    ];
    // The website and user guide set (scripts/screenshots.ps1): whole
    // windows with the sample remote desktop, at 1280 x 800 logical px
    // (1440 x 900 for the editor, wide enough for its Summary column).
    let site: [SizedScreen; 13] = [
        (
            "-site-session",
            || sv::sample_toolbar(true, false, false),
            1280.0,
            800.0,
        ),
        ("-site-home", ui::sample_home, 1280.0, 800.0),
        (
            "-site-quick",
            || ui::sample_home_typed("off"),
            1280.0,
            800.0,
        ),
        (
            "-site-palette",
            || ui::sample_palette(true, ""),
            1280.0,
            800.0,
        ),
        (
            "-site-connecting",
            || sv::sample_connecting(false),
            1280.0,
            800.0,
        ),
        ("-site-failed", || sv::sample_failed(3), 1280.0, 800.0),
        ("-site-monitors", || ui::sample_form(1), 1280.0, 800.0),
        ("-site-apps", ui::sample_apps_tab, 1280.0, 800.0),
        ("-site-sharing", || ui::sample(true), 1280.0, 800.0),
        (
            "-site-quality",
            || ui::sample_panel(2, false),
            1280.0,
            800.0,
        ),
        ("-site-vault", || ui::sample_settings(true), 1280.0, 800.0),
        ("-site-cert", || ui::sample_cert(false), 1280.0, 800.0),
        ("-site-editor", || ui::sample_form(0), 1440.0, 900.0),
    ];
    // One error screen per kind of failure.
    let failures: [Screen; 10] = [
        || sv::sample_failed(0),
        || sv::sample_failed(1),
        || sv::sample_failed(2),
        || sv::sample_failed(3),
        || sv::sample_failed(4),
        || sv::sample_failed(5),
        || sv::sample_failed(6),
        || sv::sample_failed(7),
        || sv::sample_failed(8),
        || sv::sample_failed(9),
    ]
    .map(|f| ("", f));
    for (i, (_, make)) in failures.into_iter().enumerate() {
        screens.push((names[i].as_str(), make));
    }
    for (light, theme) in [("", &theme::DARK), ("-light", &theme::LIGHT)] {
        theme::set(theme);
        for &(suffix, make) in screens.iter().filter(|s| wanted(s.0)) {
            let mut m = make();
            m.scale = scale;
            m.custom_frame = cfg!(windows);
            let mut px = vec![0u32; w * h];
            m.paint_snapshot(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
            let out = path.replace(".png", &format!("{suffix}{light}.png"));
            write_png(&out, w, h, &px)?;
            eprintln!("saved {w}x{h} snapshot to {out}");
        }
        for (suffix, make, lw, lh) in sized.into_iter().filter(|s| wanted(s.0)) {
            let (w, h) = ((lw * scale) as usize, (lh * scale) as usize);
            let mut m = make();
            m.scale = scale;
            m.custom_frame = cfg!(windows);
            let mut px = vec![0u32; w * h];
            m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
            let out = path.replace(".png", &format!("{suffix}{light}.png"));
            write_png(&out, w, h, &px)?;
            eprintln!("saved {w}x{h} snapshot to {out}");
        }
        for (suffix, make, lw, lh) in site.into_iter().filter(|s| wanted(s.0)) {
            let (w, h) = ((lw * scale) as usize, (lh * scale) as usize);
            let mut m = make();
            m.scale = scale;
            m.custom_frame = cfg!(windows);
            let mut px = vec![0u32; w * h];
            m.paint_snapshot(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
            let out = path.replace(".png", &format!("{suffix}{light}.png"));
            write_png(&out, w, h, &px)?;
            eprintln!("saved {w}x{h} snapshot to {out}");
        }
        if only.is_some() {
            continue;
        }
        // The component kit's reference sheet.
        let mut px = vec![0u32; w * h];
        kit::paint_sheet(&mut Canvas::new(&mut px, w, h), &mut te, &fonts, scale);
        let out = path.replace(".png", &format!("-kit{light}.png"));
        write_png(&out, w, h, &px)?;
        eprintln!("saved {w}x{h} snapshot to {out}");
        // The toolbar of a session spread across monitors (top of the
        // first monitor window): shown, and hidden to its handle.
        let sh = h / 2;
        for (suffix, shown) in [("-span-bar", true), ("-span-handle", false)] {
            let mut px = vec![0u32; w * sh];
            span::paint_sample(
                &mut px,
                w,
                sh,
                scale,
                "Office workstation",
                shown,
                &mut te,
                &fonts,
            );
            let out = path.replace(".png", &format!("{suffix}{light}.png"));
            write_png(&out, w, sh, &px)?;
            eprintln!("saved {w}x{sh} snapshot to {out}");
        }
    }
    theme::set(&theme::DARK);
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
