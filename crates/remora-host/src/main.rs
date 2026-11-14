//! `remora-host`: the command line of Remora Host (experimental).

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use remora_host::auth::{self, PasswordAuthenticator, RateLimit, RateLimiter};
use remora_host::backend::{self, demo};
use remora_host::{Desktop, Host, HostConfig, cert, info, paths};
use zeroize::Zeroizing;

const USAGE: &str = "\
Remora Host (experimental): an RDP server for Remora and other RDP clients.

Usage:
  remora-host set-password [--data-dir DIR] [--password-file FILE]
      Asks for a new host password twice (not shown) and stores its
      Argon2id hash. Clients log on with this password and any user name.
      --password-file takes the file's first line instead (scripted tests).
  remora-host run [--port 3390] [--bind 0.0.0.0] [--demo [WIDTHxHEIGHT]]
                  [--capture auto|dxgi|gdi] [--data-dir DIR] [--verbose]
      Serves this machine's desktop (Windows), or with --demo an animated
      test pattern that shows the input it receives (any platform; nothing
      is captured or typed). Needs a password (set-password).
  remora-host fingerprint [--data-dir DIR]
      Prints the SHA-256 fingerprint of the host's TLS certificate (made on
      first use), to compare with what the client shows.

The data directory defaults to %LOCALAPPDATA%\\rdp-rs\\host (Windows),
~/.local/share/rdp-rs/host (Linux) or ~/Library/Application Support/rdp-rs/host (macOS).
";

struct Options {
    command: String,
    port: u16,
    bind: Option<IpAddr>,
    demo: Option<(u16, u16)>,
    data_dir: Option<PathBuf>,
    verbose: bool,
    /// `set-password --password-file`: the password's first line, for
    /// scripted tests (the sandbox test).
    password_file: Option<PathBuf>,
    capture: backend::CaptureMode,
}

fn parse_size(s: &str) -> Option<(u16, u16)> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let (w, h) = (w.parse().ok()?, h.parse().ok()?);
    ((64..=8192).contains(&w) && (64..=8192).contains(&h)).then_some((w, h))
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter().peekable();
    let command = it.next().cloned().ok_or("no command")?;
    let mut o = Options {
        command,
        port: 3390,
        bind: None,
        demo: None,
        data_dir: None,
        verbose: false,
        password_file: None,
        capture: backend::CaptureMode::Auto,
    };
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--port" => {
                o.port = value("--port")?
                    .parse()
                    .map_err(|_| "--port needs a port number")?
            }
            "--bind" => {
                o.bind = Some(
                    value("--bind")?
                        .parse()
                        .map_err(|_| "--bind needs an IP address")?,
                )
            }
            "--data-dir" => o.data_dir = Some(PathBuf::from(value("--data-dir")?)),
            "--password-file" => o.password_file = Some(PathBuf::from(value("--password-file")?)),
            "--capture" => {
                o.capture = match value("--capture")?.as_str() {
                    "auto" => backend::CaptureMode::Auto,
                    "dxgi" => backend::CaptureMode::Dxgi,
                    "gdi" => backend::CaptureMode::Gdi,
                    other => return Err(format!("--capture {other:?}: use auto, dxgi or gdi")),
                }
            }
            "--verbose" | "-v" => o.verbose = true,
            "--demo" => {
                let size = match it.peek() {
                    Some(s) if !s.starts_with('-') => {
                        let s = it.next().expect("peeked");
                        parse_size(s).ok_or(format!("--demo size {s:?}: use WIDTHxHEIGHT"))?
                    }
                    _ => (1280, 720),
                };
                o.demo = Some(size);
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(o)
}

fn data_dir(o: &Options) -> Result<PathBuf, String> {
    o.data_dir
        .clone()
        .or_else(paths::default_data_dir)
        .ok_or_else(|| "no data directory: pass --data-dir".into())
}

fn set_password(o: &Options) -> Result<(), String> {
    let dir = data_dir(o)?;
    if let Some(file) = &o.password_file {
        let text = Zeroizing::new(
            std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?,
        );
        let line = text.lines().next().unwrap_or("");
        auth::set_password(&dir, line).map_err(|e| e.to_string())?;
        println!("Password set ({}).", auth::password_path(&dir).display());
        return Ok(());
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("New host password: ").map_err(|e| e.to_string())?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Repeat the password: ").map_err(|e| e.to_string())?,
    );
    if *first != *second {
        return Err("the passwords differ; nothing was changed".into());
    }
    auth::set_password(&dir, &first).map_err(|e| e.to_string())?;
    println!("Password set ({}).", auth::password_path(&dir).display());
    Ok(())
}

fn identity(dir: &std::path::Path) -> Result<cert::Identity, String> {
    let id = cert::load_or_create(dir, cert::platform_protector().as_ref())
        .map_err(|e| format!("TLS certificate: {e}"))?;
    match &id.origin {
        cert::Origin::Created => info!("made a new TLS certificate in {}", dir.display()),
        cert::Origin::Replaced(why) => info!(
            "WARNING: the old TLS key was unusable ({why}); made a new one. Clients will see a changed fingerprint."
        ),
        cert::Origin::Loaded => {}
    }
    Ok(id)
}

fn fingerprint(o: &Options) -> Result<(), String> {
    let dir = data_dir(o)?;
    println!("{}", identity(&dir)?.fingerprint());
    Ok(())
}

fn run(o: &Options) -> Result<(), String> {
    let dir = data_dir(o)?;
    let password = match PasswordAuthenticator::load(&dir) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("no host password yet: run `remora-host set-password` first".into());
        }
        Err(e) => return Err(format!("cannot read the password hash: {e}")),
    };
    rdp::set_verbose(o.verbose);
    let id = identity(&dir)?;
    let tls = rdp::server::tls_config(id.certificate.clone(), id.private_key.to_vec())
        .map_err(|e| format!("TLS setup: {e}"))?;

    let (capturer, input): backend::Backend = match o.demo {
        Some((w, h)) => {
            let (c, i) = demo::demo(w, h, true, true);
            (Box::new(c), Box::new(i))
        }
        None => backend::os_backend(o.capture).map_err(|e| e.to_string())?,
    };
    let (w, h) = capturer.size();

    let bind = o.bind.unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let addr = SocketAddr::new(bind, o.port);
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    info!(
        "listening on {addr} ({}, {w}x{h})",
        if o.demo.is_some() {
            "demo pattern"
        } else {
            "this desktop"
        }
    );
    info!("certificate fingerprint (SHA-256): {}", id.fingerprint());
    if !bind.is_loopback() {
        info!(
            "WARNING: reachable from the network on port {}. Anyone who reaches it can try the password; allow the port in the firewall only for networks you trust.",
            o.port
        );
    }
    info!("experimental: TLS without NLA; one client at a time; Ctrl+C stops");

    let host = Host {
        config: HostConfig::new(tls),
        auth: Arc::new(password),
        limiter: Arc::new(RateLimiter::new(RateLimit::default())),
    };
    let stop = Arc::new(AtomicBool::new(false));
    host.run(listener, Desktop::new(capturer, input), stop)
        .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let result = parse_args(&args).and_then(|o| match o.command.as_str() {
        "set-password" => set_password(&o),
        "run" => run(&o),
        "fingerprint" => fingerprint(&o),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("remora-host: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn options_parse() {
        let o = parse_args(&args("run --port 4000 --demo --bind 127.0.0.1 -v")).unwrap();
        assert_eq!(o.command, "run");
        assert_eq!(o.port, 4000);
        assert_eq!(o.demo, Some((1280, 720)));
        assert_eq!(o.bind, Some(IpAddr::from([127, 0, 0, 1])));
        assert!(o.verbose);
        let o = parse_args(&args("run --demo 800x600")).unwrap();
        assert_eq!((o.port, o.demo, o.bind), (3390, Some((800, 600)), None));
        assert!(parse_args(&args("run --demo 10x10")).is_err());
        assert!(parse_args(&args("run --port")).is_err());
        assert!(parse_args(&args("run --colour")).is_err());
    }
}
