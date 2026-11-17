//! End-to-end clipboard test client (RDP-62, RDP-63): connects to a real
//! server with clipboard sharing on and a scripted clipboard instead of the
//! system one, then follows commands on stdin, one per line, and answers
//! on stdout. `scripts/clip-vm-test.py` drives it against a throwaway
//! Windows VM.
//!
//! Environment: `E2E_HOST`, `E2E_PORT`, `E2E_USER`, `E2E_PASSWORD_FILE`
//! (the password is read from that file and never printed).
//!
//! Commands (answers start with the command's first word, or `error`):
//! - `wait-offer KIND` (text, dib, png, files): waits for a server copy
//!   that has it; `offer text=.. dib=.. png=.. files=..`
//! - `get-text`, `get-dib`: fetches that format of the server's copy
//! - `get-files`: fetches the list and every file in pipelined 1 MiB
//!   ranges, hashing as it goes (nothing is written); one `file` line per
//!   entry, then `files N BYTES SECONDS MBPS`
//! - `set-text TEXT`, `set-dib W H`, `set-files PATH|PATH|...`: a local
//!   copy (announced to the server on the next tick)
//! - `served`: bytes the server read of local files so far
//! - `quit`

use std::collections::VecDeque;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use rdp::cliprdr::remote::wait;
use rdp::cliprdr::{
    ClipboardBackend, LocalFormats, Pending, RemoteFormat, RemoteOffer, RemoteSource,
};
use rdp::{Client, Config};

const RANGE: u32 = 1 << 20;
const AHEAD: usize = 4;
const WAIT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct Local {
    seq: u32,
    text: Option<String>,
    dib: Option<Vec<u8>>,
    files: Vec<PathBuf>,
    offer: Option<RemoteOffer>,
}

struct Scripted(Arc<Mutex<Local>>);

impl ClipboardBackend for Scripted {
    fn sequence(&mut self) -> u32 {
        self.0.lock().unwrap().seq
    }
    fn read_text(&mut self) -> Option<String> {
        self.0.lock().unwrap().text.clone()
    }
    fn write_text(&mut self, _: &str) -> bool {
        false
    }
    fn supports_files(&self) -> bool {
        true
    }
    fn read_files(&mut self) -> Option<Vec<PathBuf>> {
        let f = self.0.lock().unwrap();
        (!f.files.is_empty()).then(|| f.files.clone())
    }
    fn available(&mut self) -> LocalFormats {
        let f = self.0.lock().unwrap();
        LocalFormats {
            text: f.text.is_some(),
            dib: f.dib.is_some(),
            png: false,
            files: !f.files.is_empty(),
        }
    }
    fn read_dib(&mut self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().dib.clone()
    }
    fn lazy_remote(&self) -> bool {
        true
    }
    fn remote_offer(&mut self, offer: Option<RemoteOffer>) {
        self.0.lock().unwrap().offer = offer;
    }
}

/// A 32-bpp bottom-up DIB (BITMAPINFOHEADER and bits) with a pattern.
fn make_dib(w: u32, h: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(40 + (w * h * 4) as usize);
    d.extend_from_slice(&40u32.to_le_bytes());
    d.extend_from_slice(&(w as i32).to_le_bytes());
    d.extend_from_slice(&(h as i32).to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&32u16.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    d.extend_from_slice(&(w * h * 4).to_le_bytes());
    d.extend_from_slice(&[0; 16]);
    for y in 0..h {
        for x in 0..w {
            d.extend_from_slice(&[(x * 7) as u8, (y * 5) as u8, ((x ^ y) * 3) as u8, 0xff]);
        }
    }
    d
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Reads one server file like Remora's paste stream: ranges ahead, in
/// order, hashed.
fn read_file(src: &RemoteSource, lindex: u32, size: u64) -> Result<String, String> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut inflight: VecDeque<(u64, u32, Pending)> = VecDeque::new();
    let (mut next, mut done) = (0u64, 0u64);
    while done < size {
        while inflight.len() < AHEAD && next < size {
            let n = (size - next).min(RANGE as u64) as u32;
            inflight.push_back((next, n, src.range(lindex, next, n)));
            next += n as u64;
        }
        let (at, n, p) = inflight.pop_front().ok_or("nothing in flight")?;
        let d = wait(&p, WAIT).ok_or_else(|| format!("range at {at} failed"))?;
        if d.is_empty() || d.len() > n as usize {
            return Err(format!("{} bytes for {n} at {at}", d.len()));
        }
        ctx.update(&d);
        done = at + d.len() as u64;
        if d.len() < n as usize {
            inflight.clear();
            next = done;
        }
    }
    Ok(hex(ctx.finish().as_ref()))
}

fn run_command(line: &str, local: &Arc<Mutex<Local>>, served: &rdp::ClipboardHandle) {
    let (cmd, arg) = line.split_once(' ').unwrap_or((line, ""));
    let offer = || local.lock().unwrap().offer.clone();
    match cmd {
        "wait-offer" => {
            let t = Instant::now();
            while t.elapsed() < WAIT {
                if let Some(o) = offer() {
                    let has = match arg {
                        "text" => o.text,
                        "dib" => o.dib,
                        "png" => o.png,
                        "files" => o.files,
                        _ => true,
                    };
                    if has {
                        println!(
                            "offer text={} dib={} dib_v5={} png={} files={}",
                            o.text, o.dib, o.dib_v5, o.png, o.files
                        );
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            println!("error no offer with {arg}");
        }
        "get-text" => match offer().and_then(|o| wait(&o.source.data(RemoteFormat::Text), WAIT)) {
            Some(d) => println!("text {}", rdp::cliprdr::decode_text(&d)),
            None => println!("error no text"),
        },
        "get-dib" => match offer().and_then(|o| wait(&o.source.data(RemoteFormat::Dib), WAIT)) {
            Some(d) if d.len() >= 40 => {
                let w = i32::from_le_bytes(d[4..8].try_into().unwrap());
                let h = i32::from_le_bytes(d[8..12].try_into().unwrap());
                let bpp = u16::from_le_bytes(d[14..16].try_into().unwrap());
                println!("dib {} {w} {h} {bpp}", d.len());
            }
            _ => println!("error no image"),
        },
        "get-files" => {
            let Some(o) = offer() else {
                println!("error no offer");
                return;
            };
            let Some(list) = o.source.file_list(WAIT) else {
                println!("error no file list");
                return;
            };
            let t = Instant::now();
            let mut bytes = 0u64;
            for (i, f) in list.iter().enumerate() {
                if f.is_dir() {
                    println!("file {} dir", f.name);
                    continue;
                }
                let size = match wait(&o.source.size(i as u32), WAIT) {
                    Some(b) if b.len() >= 8 => u64::from_le_bytes(b[..8].try_into().unwrap()),
                    _ => {
                        println!("error no size for {}", f.name);
                        return;
                    }
                };
                match read_file(&o.source, i as u32, size) {
                    Ok(h) => println!("file {} {size} {h}", f.name),
                    Err(e) => {
                        println!("error {}: {e}", f.name);
                        return;
                    }
                }
                bytes += size;
            }
            let s = t.elapsed().as_secs_f64();
            println!(
                "files {} {bytes} {s:.1} {:.1}",
                list.len(),
                bytes as f64 / s / 1e6
            );
        }
        "set-text" => {
            let mut l = local.lock().unwrap();
            l.text = Some(arg.to_string());
            l.dib = None;
            l.files.clear();
            l.seq += 1;
            println!("set-text ok");
        }
        "set-dib" => {
            let mut it = arg.split(' ').filter_map(|v| v.parse().ok());
            let (w, h) = (it.next().unwrap_or(64), it.next().unwrap_or(48));
            let mut l = local.lock().unwrap();
            l.dib = Some(make_dib(w, h));
            l.text = None;
            l.files.clear();
            l.seq += 1;
            println!("set-dib ok");
        }
        "set-files" => {
            let mut l = local.lock().unwrap();
            l.files = arg.split('|').map(PathBuf::from).collect();
            l.text = None;
            l.dib = None;
            l.seq += 1;
            println!("set-files ok");
        }
        "served" => match served.transfer() {
            Some(t) => println!("served {} {}", t.done, t.total),
            None => println!("served idle"),
        },
        _ => println!("error unknown command {cmd}"),
    }
}

fn main() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let password = std::fs::read_to_string(env("E2E_PASSWORD_FILE"))
        .expect("password file")
        .trim()
        .to_string();
    let mut cfg = Config::new(&env("E2E_HOST"), &env("E2E_USER"), &password);
    cfg.port = env("E2E_PORT").parse().expect("port");
    let local = Arc::new(Mutex::new(Local::default()));
    let (channel, handle) = rdp::cliprdr(Box::new(Scripted(local.clone())));
    handle.set_enabled(true);
    let mut client = match Client::connect_with(&cfg, vec![Box::new(channel)]) {
        Ok(c) => c,
        Err(e) => {
            println!("error connect: {e}");
            std::process::exit(1);
        }
    };
    println!("connected");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        match client.poll(Duration::from_millis(10)) {
            Ok(out) => {
                if let Some(reason) = out.closed {
                    println!("error closed: {reason}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                println!("error poll: {e}");
                std::process::exit(1);
            }
        }
        while let Ok(line) = rx.try_recv() {
            let line = line.trim().to_string();
            if line == "quit" {
                client.disconnect();
                println!("bye");
                return;
            }
            let (l, h) = (local.clone(), handle.clone());
            // Fetches wait for the session's own polling: never on this thread.
            std::thread::spawn(move || run_command(&line, &l, &h));
        }
    }
}
