//! End-to-end camera redirection test client (RDP-75): connects to a real
//! server and shares one synthetic camera, "Remora Test Camera", that
//! makes a moving test pattern in YUY2 or NV12. No camera of this PC is
//! listed or opened. `scripts/camera-vm-test.py` drives it against a
//! throwaway Windows VM.
//!
//! Environment: `E2E_HOST`, `E2E_PORT`, `E2E_USER`, `E2E_PASSWORD_FILE`
//! (the password is read from that file and never printed); `E2E_TRACE`
//! set: protocol trace on stderr.
//!
//! Stdout, one event per line: `connected`, `media-types`,
//! `start FORMAT WxH`, `sample N BYTES` (the first and every 30th),
//! `stop`, `error ...`. Stdin: `quit`.

use std::io::BufRead;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rdp::camera::{CameraBackend, MediaType, VideoFormat};
use rdp::{Client, Config, Drdynvc};

/// A camera that paints a moving bar, at most 30 frames a second.
struct TestPattern {
    format: Option<MediaType>,
    last: Option<Instant>,
    frames: u64,
}

impl TestPattern {
    fn frame(&self, t: &MediaType) -> Vec<u8> {
        let (w, h) = (t.width as usize, t.height as usize);
        let bar = (self.frames as usize * 8) % w;
        let luma = |x: usize, y: usize| -> u8 {
            if x.abs_diff(bar) < 16 {
                235
            } else {
                (16 + (x + y) % 200) as u8
            }
        };
        match t.format {
            VideoFormat::Yuy2 => {
                let mut v = Vec::with_capacity(w * h * 2);
                for y in 0..h {
                    for x in (0..w).step_by(2) {
                        v.extend_from_slice(&[luma(x, y), 128, luma(x + 1, y), 128]);
                    }
                }
                v
            }
            _ => {
                // NV12: the luma plane, then interleaved U/V at half height.
                let mut v = Vec::with_capacity(w * h * 3 / 2);
                for y in 0..h {
                    for x in 0..w {
                        v.push(luma(x, y));
                    }
                }
                v.resize(w * h * 3 / 2, 128);
                v
            }
        }
    }
}

impl CameraBackend for TestPattern {
    fn media_types(&mut self) -> Result<Vec<MediaType>, String> {
        println!("media-types");
        Ok(vec![
            MediaType::new(VideoFormat::Yuy2, 640, 480, 30, 1),
            MediaType::new(VideoFormat::Nv12, 640, 480, 30, 1),
            MediaType::new(VideoFormat::Nv12, 320, 240, 30, 1),
        ])
    }

    fn start(&mut self, t: &MediaType) -> Result<(), String> {
        println!("start {} {}x{}", t.format.name(), t.width, t.height);
        self.format = Some(*t);
        self.last = None;
        Ok(())
    }

    fn sample(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some(t) = self.format else {
            return Ok(None);
        };
        if self
            .last
            .is_some_and(|l| l.elapsed() < Duration::from_millis(33))
        {
            return Ok(None);
        }
        self.last = Some(Instant::now());
        let frame = self.frame(&t);
        if self.frames.is_multiple_of(30) {
            println!("sample {} {}", self.frames, frame.len());
        }
        self.frames += 1;
        Ok(Some(frame))
    }

    fn stop(&mut self) {
        if self.format.take().is_some() {
            println!("stop");
        }
    }
}

fn main() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    if std::env::var_os("E2E_TRACE").is_some() {
        rdp::log::set_verbose(true); // to stderr; credentials stay redacted
    }
    let password = std::fs::read_to_string(env("E2E_PASSWORD_FILE"))
        .expect("password file")
        .trim()
        .to_string();
    let mut cfg = Config::new(&env("E2E_HOST"), &env("E2E_USER"), &password);
    cfg.port = env("E2E_PORT").parse().expect("port");
    let camera = TestPattern {
        format: None,
        last: None,
        frames: 0,
    };
    let (channels, handle) = rdp::cameras(vec![("Remora Test Camera".into(), Box::new(camera))]);
    handle.set_enabled(0, true);
    let drdynvc = Drdynvc::new(channels);
    let mut client = match Client::connect_with(&cfg, vec![Box::new(drdynvc)]) {
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
    let mut said_version = false;
    loop {
        match client.poll(Duration::from_millis(5)) {
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
        if !said_version && handle.version() != 0 {
            said_version = true;
            println!("version {}", handle.version());
        }
        if let Ok(line) = rx.try_recv()
            && line.trim() == "quit"
        {
            client.disconnect();
            println!("bye");
            return;
        }
    }
}
