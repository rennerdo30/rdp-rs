//! Live end-to-end test of the server helper over a real Remote Desktop
//! session (RDP-64, RDP-61). Ignored by default: `scripts/helper-vm-test.py`
//! runs it against a throwaway lab clone with `remora-agent` in the
//! session, and talks to it through files in `E2E_DIR`:
//!
//! - the test writes `client.fp` (this run's Remora key), waits for
//!   `trusted` (the script ran `remora-agent trust-client` there), connects,
//!   and writes `paired` once the helper said Hello;
//! - it runs the latency meter (RDP-67) and writes `latency` (the summary,
//!   or `failed: <why>`);
//! - it sends the folder `E2E_DIR/up/<one folder>` and writes `sent`;
//! - it accepts the folder the script sends from the server (`remora-agent
//!   send`) into `E2E_DIR/down` and writes `received`;
//! - with `E2E_DIR/agent.exe` present, it sends that helper as an update and
//!   writes `updated <status>`, then `rejoined` when the helper is back.
//!
//! Environment: `E2E_HOST`, `E2E_PORT`, `E2E_USER`, `E2E_PASSWORD_FILE`,
//! `E2E_DIR`. Optional: `E2E_SIZE` (`WxH`), `E2E_GFX=1` (graphics pipeline
//! with the H.264 decoder, as the app connects), `E2E_LATENCY_ONLY=1` (end
//! after the latency meter), `E2E_STREAM=1` (then switch to the helper's
//! picture stream, save `stream.png` and measure again: `latency-stream`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use remora_link::msg::cap;
use remora_link::transfer::{Direction, TransferEvent};

use super::{HelperEvent, HelperHandle, HelperState};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

fn note(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
    eprintln!("[live] {name}: {text}");
}

fn wait_file(dir: &Path, name: &str, limit: Duration) {
    let t = Instant::now();
    while !dir.join(name).exists() {
        assert!(t.elapsed() < limit, "no {name} within {limit:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Events until `done` says stop; panics after `limit`.
fn pump(
    h: &HelperHandle,
    limit: Duration,
    mut done: impl FnMut(&HelperEvent, &HelperHandle) -> bool,
) {
    let t = Instant::now();
    loop {
        while let Some(e) = h.next_event() {
            if !matches!(e, HelperEvent::Transfer(TransferEvent::Progress { .. })) {
                eprintln!("[live] event {e:?}");
            }
            if let HelperEvent::KeyboardLayout(klid) = e
                && let Ok(dir) = std::env::var("E2E_DIR")
            {
                note(Path::new(&dir), "layout", &format!("{klid:08x}"));
            }
            if done(&e, h) {
                return;
            }
        }
        assert!(t.elapsed() < limit, "timed out after {limit:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct LiveLink<'a> {
    h: &'a HelperHandle,
    shared: &'a std::sync::Arc<std::sync::Mutex<crate::session::Shared>>,
}

impl crate::latency::Link for LiveLink<'_> {
    fn mark(&mut self, rgb: u32) -> Option<u32> {
        self.h.latency_mark(rgb)
    }
    fn end(&mut self) {
        self.h.latency_end();
    }
    fn probe(&mut self, f: &mut dyn FnMut(&mut crate::latency::Probe)) {
        f(&mut self.shared.lock().unwrap().latency);
    }
}

/// Runs the meter like the app does: poll every couple of milliseconds,
/// hand it the helper's answers.
fn measure_latency(
    h: &HelperHandle,
    shared: &std::sync::Arc<std::sync::Mutex<crate::session::Shared>>,
    dir: &Path,
) -> Result<crate::latency::Report, String> {
    let mut link = LiveLink { h, shared };
    let mut run = crate::latency::Run::start(&mut link, Instant::now())?;
    let t = Instant::now();
    loop {
        while let Some(e) = h.next_event() {
            match e {
                HelperEvent::LatencyShown { request_id, square } => {
                    run.shown(&mut link, request_id, square, Instant::now())
                }
                HelperEvent::KeyboardLayout(klid) => note(dir, "layout", &format!("{klid:08x}")),
                other => eprintln!("[live] event {other:?}"),
            }
        }
        if let Some(r) = run.poll(&mut link, Instant::now()) {
            return r;
        }
        assert!(t.elapsed() < Duration::from_secs(120), "latency meter hung");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// RDP-67: the helper's picture stream in place of RDP's, as the app's
/// switch does; a screenshot of the picture, then the latency meter.
#[cfg(windows)]
fn stream_and_measure(
    h: &HelperHandle,
    worker: &crate::session::Worker,
    dir: &Path,
) -> Result<String, String> {
    let (fw, fh) = {
        let s = worker.shared.lock().unwrap();
        (s.fb.width, s.fb.height)
    };
    let kbps = ((fw * fh) as f64 * 60.0 * 0.05 / 1000.0) as u32;
    let (tx, rx) = std::sync::mpsc::channel();
    h.stream_start(60, kbps.clamp(2_000, 50_000), tx)
        .ok_or("the helper does not offer the stream")?;
    let player = crate::stream_player::Player::start(
        rx,
        worker.shared.clone(),
        worker.notified.clone(),
        h.clone(),
        || {},
    );
    let t = Instant::now();
    let (state, w, hh, text) = loop {
        if let Some(HelperEvent::StreamState {
            state,
            width,
            height,
            text,
            ..
        }) = h.next_event()
        {
            break (state, width, height, text);
        }
        if t.elapsed() > Duration::from_secs(60) {
            return Err("no answer to StreamStart".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if state != 0 {
        return Err(text);
    }
    // Let pictures arrive, then keep what Remora shows.
    std::thread::sleep(Duration::from_secs(3));
    let owns = {
        let s = worker.shared.lock().unwrap();
        let _ = crate::write_png(
            &dir.join("stream.png").to_string_lossy(),
            s.fb.width,
            s.fb.height,
            &s.fb.pixels,
        );
        s.stream_owns
    };
    if !owns {
        return Err(format!("started at {w}x{hh}, but no picture was shown"));
    }
    let r = measure_latency(h, &worker.shared, dir)?;
    let stages = player.stage_times().summary().unwrap_or_default();
    h.stream_stop();
    drop(player);
    Ok(format!(
        "{} (helper stream {w}x{hh}; {stages})",
        r.summary()
    ))
}

#[test]
#[ignore = "live: needs a lab clone with Remote Desktop and remora-agent (scripts/helper-vm-test.py)"]
fn live_helper_folders_and_update() {
    let dir = PathBuf::from(env("E2E_DIR"));
    let password = std::fs::read_to_string(env("E2E_PASSWORD_FILE"))
        .unwrap()
        .trim()
        .to_string();
    let key = remora_link::session::StaticKey::generate().unwrap();
    note(&dir, "client.fp", &remora_link::fingerprint(&key.public()));
    wait_file(&dir, "trusted", Duration::from_secs(300));

    let mut cfg = rdp::Config::new(&env("E2E_HOST"), &env("E2E_USER"), &password);
    cfg.port = env("E2E_PORT").parse().unwrap();
    if let Some((w, h)) = std::env::var("E2E_SIZE")
        .ok()
        .and_then(|s| s.split_once('x').map(|(w, h)| (w.parse(), h.parse())))
        .and_then(|(w, h)| Some((w.ok()?, h.ok()?)))
    {
        cfg.width = w;
        cfg.height = h;
    }
    if std::env::var("E2E_GFX").is_ok_and(|v| v == "1") {
        cfg.graphics = rdp::Graphics::Gfx;
        cfg.h264 = Some(crate::h264_mf::factory());
    }
    cfg.client_name = "remora-e2e".into();
    let helper = HelperHandle::new();
    helper.set_received_file_hook(|_| Ok(()));
    let (channels, controls) = crate::controls::Controls::build(&cfg.client_name, 0, &helper);
    let h = controls.helper().clone();
    h.set_server(format!("e2e-{}", std::process::id()), None);
    h.set_client(key, &cfg.client_name);
    h.set_capabilities(cap::ALL);
    h.set_pairing_policy(None, None);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut worker = crate::session::spawn(cfg, channels, move |_, ev| {
        let _ = tx.send(ev);
    });
    // The transport (TLS) decides whether the helper may pair.
    let t = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(crate::session::Event::Connected(info)) => {
                h.set_transport_protocol(info.protocol);
                break;
            }
            Ok(crate::session::Event::Closed { why, .. }) => panic!("closed: {why}"),
            _ => assert!(t.elapsed() < Duration::from_secs(90), "no connection"),
        }
    }
    // Session events keep flowing; nobody needs them here.
    std::thread::spawn(move || while rx.recv().is_ok() {});
    note(&dir, "connected", "ok");

    // Like the user: compare the fingerprint Remora shows with the one the
    // running helper reports (`helper.fp`, written by the script), then
    // confirm. The helper trusts this key already (`trust-client`).
    pump(&h, Duration::from_secs(180), |e, h| match e {
        HelperEvent::State(HelperState::AwaitingPairing {
            sas, fingerprint, ..
        }) => {
            wait_file(&dir, "helper.fp", Duration::from_secs(120));
            let want = std::fs::read_to_string(dir.join("helper.fp")).unwrap();
            let norm = |s: &str| s.split_whitespace().collect::<String>().to_lowercase();
            assert_eq!(norm(fingerprint), norm(&want), "the helper's key");
            h.confirm_pairing(*sas).unwrap();
            false
        }
        HelperEvent::State(HelperState::Paired) => true,
        HelperEvent::State(HelperState::Failed(_) | HelperState::PairingBlocked) => {
            panic!("helper failed: {e:?}")
        }
        _ => false,
    });
    // The Hello may come just after Paired.
    let t = Instant::now();
    while h.hello().is_none() {
        assert!(t.elapsed() < Duration::from_secs(60), "no Hello");
        std::thread::sleep(Duration::from_millis(100));
    }
    let hello = h.hello().unwrap();
    note(
        &dir,
        "paired",
        &format!(
            "version {} offered {:#x} accepted {:#x}",
            hello.helper_version,
            hello.capabilities,
            h.accepted_capabilities()
        ),
    );
    assert!(
        h.accepted_capabilities() & cap::FOLDERS != 0,
        "folders agreed"
    );

    // RDP-67: the latency meter over this session's own picture.
    let result = measure_latency(&h, &worker.shared, &dir);
    note(
        &dir,
        "latency",
        &match result {
            Ok(r) => r.summary(),
            Err(e) => format!("failed: {e}"),
        },
    );
    #[cfg(windows)]
    if std::env::var("E2E_STREAM").is_ok_and(|v| v == "1") {
        let text = match stream_and_measure(&h, &worker, &dir) {
            Ok(r) => r,
            Err(e) => format!("failed: {e}"),
        };
        note(&dir, "latency-stream", &text);
        // RDP's picture must be back (its output was suppressed meanwhile).
        std::thread::sleep(Duration::from_secs(1));
        let after = measure_latency(&h, &worker.shared, &dir);
        note(
            &dir,
            "latency-after",
            &match after {
                Ok(r) => r.summary(),
                Err(e) => format!("failed: {e}"),
            },
        );
    }
    if std::env::var("E2E_LATENCY_ONLY").is_ok_and(|v| v == "1") {
        worker.close();
        return;
    }

    // PC -> server: one folder.
    let up = std::fs::read_dir(dir.join("up"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("a folder in up/");
    let id = h.send_folder(&up).expect("send_folder");
    let t = Instant::now();
    pump(&h, Duration::from_secs(3600), |e, _| match e {
        HelperEvent::Transfer(TransferEvent::Completed { id: i, .. }) if *i == id => true,
        HelperEvent::Transfer(TransferEvent::Failed { id: i, detail, .. }) if *i == id => {
            panic!("send failed: {detail}")
        }
        _ => false,
    });
    note(&dir, "sent", &format!("{:.1} s", t.elapsed().as_secs_f64()));

    // Server -> PC: the folder the script sends with `remora-agent send`.
    let down = dir.join("down");
    std::fs::create_dir_all(&down).unwrap();
    let mut offered = None;
    let t = Instant::now();
    pump(&h, Duration::from_secs(3600), |e, h| match e {
        HelperEvent::Transfer(TransferEvent::Offered {
            id, name, files, ..
        }) => {
            eprintln!("[live] offered {name} ({files} files)");
            h.accept_file(*id, &down).unwrap();
            offered = Some(*id);
            false
        }
        HelperEvent::Transfer(TransferEvent::Completed {
            id,
            direction: Direction::Receive,
            name,
        }) if Some(*id) == offered => {
            note(
                &dir,
                "received",
                &format!("{name} {:.1} s", t.elapsed().as_secs_f64()),
            );
            true
        }
        HelperEvent::Transfer(TransferEvent::Failed { id, detail, .. }) if Some(*id) == offered => {
            panic!("receive failed: {detail}")
        }
        _ => false,
    });

    // The helper replaces itself (RDP-61) and comes back.
    // The script writes `agent.exe`, then `update.go` (or `update.skip`).
    let t = Instant::now();
    while !dir.join("update.go").exists() && !dir.join("update.skip").exists() {
        assert!(t.elapsed() < Duration::from_secs(600), "no update decision");
        std::thread::sleep(Duration::from_millis(200));
    }
    let exe = std::fs::read(dir.join("agent.exe"))
        .ok()
        .filter(|_| dir.join("update.go").exists());
    if let Some(exe) = exe {
        assert!(h.send_update("9.9.9-e2e", &exe), "update sent");
        let mut status = None;
        pump(&h, Duration::from_secs(300), |e, _| match e {
            HelperEvent::UpdateResult(s) => {
                status = Some(*s);
                true
            }
            _ => false,
        });
        note(&dir, "updated", &format!("{status:?}"));
        let t = Instant::now();
        let mut gone = false;
        loop {
            while let Some(e) = h.next_event() {
                eprintln!("[live] event {e:?}");
                match e {
                    HelperEvent::State(HelperState::NotPresent | HelperState::Handshaking) => {
                        gone = true
                    }
                    // This test keeps no pin: the restarted helper is
                    // compared again; it must be the same key.
                    HelperEvent::State(HelperState::AwaitingPairing {
                        sas, fingerprint, ..
                    }) if gone => {
                        let want = std::fs::read_to_string(dir.join("helper.fp")).unwrap();
                        let norm =
                            |s: &str| s.split_whitespace().collect::<String>().to_lowercase();
                        assert_eq!(norm(&fingerprint), norm(&want), "same helper key");
                        h.confirm_pairing(sas).unwrap();
                    }
                    HelperEvent::State(HelperState::Paired) if gone => {
                        note(&dir, "rejoined", "ok");
                        worker.close();
                        return;
                    }
                    _ => {}
                }
            }
            assert!(t.elapsed() < Duration::from_secs(120), "helper not back");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    worker.close();
}
