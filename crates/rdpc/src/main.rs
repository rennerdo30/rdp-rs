//! rdpc: prototype RDP client.
//!
//!   rdpc <host[:port]> -u <[DOMAIN\]user> [-d domain] [--size WxH] [-v]
//!        [--screenshot out.png [--wait SECONDS]]
//!
//! The password comes from RDP_PASSWORD or an interactive prompt.

mod keymap;

use std::time::{Duration, Instant};

use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window, WindowOptions};
use rdp::input::{PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3};
use rdp::{Client, Config, InputEvent};

struct Args {
    host: String,
    port: u16,
    user: String,
    domain: String,
    size: (u16, u16),
    screenshot: Option<String>,
    wait: u64,
    verbose: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: rdpc <host[:port]> -u <[DOMAIN\\]user> [-d domain] [--size WxH] [-v]\n\
         \x20           [--screenshot out.png [--wait SECONDS]]\n\
         password: RDP_PASSWORD environment variable, otherwise prompted"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        host: String::new(),
        port: 3389,
        user: String::new(),
        domain: String::new(),
        size: (1280, 800),
        screenshot: None,
        wait: 15,
        verbose: false,
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
                a.size = (
                    w.parse().unwrap_or_else(|_| usage()),
                    h.parse().unwrap_or_else(|_| usage()),
                );
            }
            "--screenshot" => a.screenshot = Some(val()),
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
    if a.host.is_empty() || a.user.is_empty() {
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
    cfg.width = args.size.0;
    cfg.height = args.size.1;

    eprintln!("connecting to {}:{} ...", args.host, args.port);
    let client = match Client::connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connection failed: {e}");
            std::process::exit(1);
        }
    };
    let info = client.info().clone();
    eprintln!(
        "connected: protocol {:#x}, desktop {}x{} at {} bpp, server RDP version {:#x}",
        info.protocol, info.width, info.height, info.bpp, info.server_rdp_version
    );
    eprintln!(
        "server certificate SHA-256 {} (not verified: prototype)",
        hex(&info.certificate_sha256)
    );

    let result = match &args.screenshot {
        Some(path) => screenshot(client, path, Duration::from_secs(args.wait)),
        None => run_window(client),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Headless mode: wait until the screen has settled, save a PNG and disconnect.
fn screenshot(
    mut client: Client,
    path: &str,
    max_wait: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, fb.width as u32, fb.height as u32);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(&fb.to_rgb())?;
    eprintln!("saved {}x{} screenshot to {path}", fb.width, fb.height);
    client.disconnect();
    Ok(())
}

fn open_window(w: usize, h: usize) -> Result<Window, minifb::Error> {
    let mut win = Window::new("rdpc", w, h, WindowOptions::default())?;
    win.set_target_fps(60);
    Ok(win)
}

/// Interactive mode: show the desktop in a window and forward keyboard and mouse.
fn run_window(mut client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let (mut w, mut h) = (client.framebuffer().width, client.framebuffer().height);
    let mut win = open_window(w, h)?;
    let mut last_mouse = (u16::MAX, u16::MAX);
    let mut buttons = [false; 3];

    while win.is_open() {
        let out = client.poll(Duration::from_millis(6))?;
        if let Some(reason) = out.closed {
            eprintln!("session closed: {reason}");
            return Ok(());
        }
        if out.resized {
            (w, h) = (client.framebuffer().width, client.framebuffer().height);
            win = open_window(w, h)?;
        }

        let mut events = Vec::new();
        for key in win.get_keys_pressed(KeyRepeat::Yes) {
            if let Some((scancode, extended)) = keymap::scancode(key) {
                events.push(InputEvent::Key {
                    scancode,
                    extended,
                    down: true,
                });
            }
        }
        for key in win.get_keys_released() {
            if let Some((scancode, extended)) = keymap::scancode(key) {
                events.push(InputEvent::Key {
                    scancode,
                    extended,
                    down: false,
                });
            }
        }
        if let Some((mx, my)) = win.get_mouse_pos(MouseMode::Discard) {
            let pos = (mx.max(0.0) as u16, my.max(0.0) as u16);
            if pos != last_mouse {
                events.push(InputEvent::mouse_move(pos.0, pos.1));
                last_mouse = pos;
            }
            for (i, (btn, flag)) in [
                (MouseButton::Left, PTRFLAGS_BUTTON1),
                (MouseButton::Right, PTRFLAGS_BUTTON2),
                (MouseButton::Middle, PTRFLAGS_BUTTON3),
            ]
            .into_iter()
            .enumerate()
            {
                let down = win.get_mouse_down(btn);
                if down != buttons[i] {
                    events.push(InputEvent::mouse_button(flag, down, pos.0, pos.1));
                    buttons[i] = down;
                }
            }
            if let Some((_, dy)) = win.get_scroll_wheel()
                && dy != 0.0
            {
                let delta = if dy > 0.0 { 120 } else { -120 };
                events.push(InputEvent::wheel(delta, pos.0, pos.1));
            }
        }
        if !events.is_empty() {
            client.send_input(&events)?;
        }

        let fb = client.framebuffer();
        win.update_with_buffer(&fb.pixels, fb.width, fb.height)?;
        if win.is_key_down(Key::F12)
            && win.is_key_down(Key::LeftCtrl)
            && win.is_key_down(Key::LeftAlt)
        {
            break; // local escape hatch: Ctrl+Alt+F12
        }
    }
    client.disconnect();
    Ok(())
}
