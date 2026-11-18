//! Live end-to-end test of port redirection (RDP-74) over a real Remote
//! Desktop session. Ignored by default: `scripts/serial-vm-test.py` runs it
//! against a throwaway lab clone. No real port is used: the session gets
//! "COM9" backed by an in-process loopback (every byte written comes back
//! as received data), so the server's own serial stack (System.IO.Ports in
//! PowerShell) drives create, the settings IOCTLs, WAIT_ON_MASK, write, read
//! and close through the protocol.
//!
//! Files in `E2E_DIR`: the test writes `connected` once COM9 is announced;
//! the script writes `serial-done` (what the server saw); the test writes
//! `client` (what the loopback saw), removes the port live and writes
//! `removed`; the script writes `after-remove`.
//!
//! Environment: `E2E_HOST`, `E2E_PORT`, `E2E_USER`, `E2E_PASSWORD_FILE`,
//! `E2E_DIR`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rdp::rdpdr::serial::*;
use rdp::{SerialBackend, SerialPort};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

fn note(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
    eprintln!("[live] {name}: {text}");
}

fn wait_file(dir: &Path, name: &str, limit: Duration) -> String {
    let t = Instant::now();
    loop {
        if let Ok(s) = std::fs::read_to_string(dir.join(name)) {
            return s;
        }
        assert!(t.elapsed() < limit, "no {name} within {limit:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

struct State {
    rx: VecDeque<u8>,
    echoed: usize,
    opens: usize,
    closes: usize,
    bauds: Vec<u32>,
    controls: Vec<String>,
    baud: u32,
    line: LineControl,
    timeouts: Timeouts,
    chars: Chars,
    handflow: Handflow,
    wait_mask: u32,
    events: u32,
    read_epoch: u64,
    wait_epoch: u64,
    closed: bool,
}

/// A port whose output is its input.
struct Loopback {
    s: Mutex<State>,
    cv: Condvar,
}

impl Loopback {
    fn new() -> Arc<Loopback> {
        Arc::new(Loopback {
            s: Mutex::new(State {
                rx: VecDeque::new(),
                echoed: 0,
                opens: 0,
                closes: 0,
                bauds: Vec::new(),
                controls: Vec::new(),
                baud: 9600,
                line: LineControl {
                    stop_bits: STOP_BIT_1,
                    parity: NO_PARITY,
                    word_length: 8,
                },
                timeouts: Timeouts::default(),
                chars: Chars {
                    xon: 0x11,
                    xoff: 0x13,
                    ..Chars::default()
                },
                handflow: Handflow {
                    control_handshake: SERIAL_DTR_CONTROL,
                    flow_replace: SERIAL_RTS_CONTROL,
                    xon_limit: 2048,
                    xoff_limit: 512,
                },
                wait_mask: 0,
                events: 0,
                read_epoch: 0,
                wait_epoch: 0,
                closed: false,
            }),
            cv: Condvar::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.s.lock().unwrap_or_else(|p| p.into_inner())
    }
}

struct Open(Arc<Loopback>);

struct Backend(Arc<Loopback>);

impl SerialBackend for Backend {
    fn open(&self, port: &str) -> PortResult<Arc<dyn SerialPort>> {
        eprintln!("[live] open {port}");
        let mut s = self.0.lock();
        s.opens += 1;
        s.closed = false;
        Ok(Arc::new(Open(self.0.clone())))
    }
}

impl SerialPort for Open {
    fn read(&self, max: usize) -> PortResult<Vec<u8>> {
        let l = &self.0;
        let mut s = l.lock();
        let epoch = s.read_epoch;
        let t = s.timeouts;
        // MAXDWORD interval with no totals: return at once (Win32 rule).
        let immediate = t.read_interval == u32::MAX
            && t.read_total_multiplier == 0
            && t.read_total_constant == 0;
        let limit = (t.read_total_constant != 0)
            .then(|| Instant::now() + Duration::from_millis(t.read_total_constant.into()));
        loop {
            if s.closed || s.read_epoch != epoch {
                return Err(STATUS_CANCELLED);
            }
            if !s.rx.is_empty() || immediate || limit.is_some_and(|d| Instant::now() >= d) {
                let n = max.min(s.rx.len());
                return Ok(s.rx.drain(..n).collect());
            }
            s = l.cv.wait_timeout(s, Duration::from_millis(20)).unwrap().0;
        }
    }

    fn write(&self, data: &[u8]) -> PortResult<u32> {
        let mut s = self.0.lock();
        s.rx.extend(data);
        s.echoed += data.len();
        s.events |= SERIAL_EV_RXCHAR | SERIAL_EV_TXEMPTY;
        drop(s);
        self.0.cv.notify_all();
        Ok(data.len() as u32)
    }

    fn wait_event(&self) -> PortResult<u32> {
        let l = &self.0;
        let mut s = l.lock();
        let epoch = s.wait_epoch;
        loop {
            if s.closed {
                return Err(STATUS_CANCELLED);
            }
            if s.wait_epoch != epoch {
                return Ok(0);
            }
            let hit = s.events & s.wait_mask;
            if hit != 0 {
                s.events &= !hit;
                return Ok(hit);
            }
            s = l.cv.wait(s).unwrap();
        }
    }

    fn control(&self, c: &SerialControl) -> PortResult<ControlOut> {
        use SerialControl as C;
        let mut s = self.0.lock();
        s.controls.push(format!("{c:?}"));
        let out = match c {
            C::SetBaudRate(b) => {
                s.baud = *b;
                s.bauds.push(*b);
                ControlOut::None
            }
            C::GetBaudRate => ControlOut::U32(s.baud),
            C::SetLineControl(v) => {
                s.line = *v;
                ControlOut::None
            }
            C::GetLineControl => ControlOut::LineControl(s.line),
            C::SetTimeouts(v) => {
                s.timeouts = *v;
                ControlOut::None
            }
            C::GetTimeouts => ControlOut::Timeouts(s.timeouts),
            C::SetChars(v) => {
                s.chars = *v;
                ControlOut::None
            }
            C::GetChars => ControlOut::Chars(s.chars),
            C::SetHandflow(v) => {
                s.handflow = *v;
                ControlOut::None
            }
            C::GetHandflow => ControlOut::Handflow(s.handflow),
            C::SetWaitMask(m) => {
                s.wait_mask = *m;
                s.wait_epoch += 1;
                ControlOut::None
            }
            C::GetWaitMask => ControlOut::U32(s.wait_mask),
            C::Purge(m) => {
                if m & SERIAL_PURGE_RXABORT != 0 {
                    s.read_epoch += 1;
                }
                if m & SERIAL_PURGE_RXCLEAR != 0 {
                    s.rx.clear();
                }
                ControlOut::None
            }
            C::GetModemStatus => ControlOut::U32(0x30), // CTS, DSR
            C::GetDtrRts => ControlOut::U32(SERIAL_DTR_STATE | SERIAL_RTS_STATE),
            C::GetCommStatus => ControlOut::Status(CommStatus {
                in_queue: s.rx.len() as u32,
                ..CommStatus::default()
            }),
            C::GetProperties => ControlOut::Properties(CommProp {
                packet_length: 64,
                packet_version: 2,
                service_mask: 1, // SP_SERIALCOMM
                max_tx_queue: 0,
                max_rx_queue: 0,
                max_baud: 0x1000_0000, // BAUD_USER
                prov_sub_type: 1,      // PST_RS232
                prov_capabilities: 0xFF,
                settable_params: 0x7F,
                settable_baud: 0x1007_FFFF,
                settable_data: 0x000F,
                settable_stop_parity: 0x1F07,
                current_tx_queue: 4096,
                current_rx_queue: 4096,
                ..CommProp::default()
            }),
            C::Raw { .. } => return Err(rdp::rdpdr::fscc::STATUS_NOT_SUPPORTED),
            _ => ControlOut::None,
        };
        drop(s);
        self.0.cv.notify_all();
        Ok(out)
    }

    fn close(&self) {
        let mut s = self.0.lock();
        s.closed = true;
        s.closes += 1;
        drop(s);
        self.0.cv.notify_all();
    }
}

#[test]
#[ignore = "live: needs a lab clone with Remote Desktop (scripts/serial-vm-test.py)"]
fn live_serial_port_loopback() {
    let dir = PathBuf::from(env("E2E_DIR"));
    let password = std::fs::read_to_string(env("E2E_PASSWORD_FILE"))
        .unwrap()
        .trim()
        .to_string();
    let mut cfg = rdp::Config::new(&env("E2E_HOST"), &env("E2E_USER"), &password);
    cfg.port = env("E2E_PORT").parse().unwrap();
    cfg.client_name = "remora-e2e".into();
    let (rdpdr, devices) = rdp::rdpdr(&cfg.client_name);
    let channels: Vec<Box<dyn rdp::StaticChannel>> = vec![Box::new(rdpdr)];
    let (tx, rx) = std::sync::mpsc::channel();
    let _worker = crate::session::spawn(cfg, channels, move |_, ev| {
        let _ = tx.send(ev);
    });
    let t = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(crate::session::Event::Connected(_)) => break,
            Ok(crate::session::Event::Closed { why, .. }) => panic!("closed: {why}"),
            _ => assert!(t.elapsed() < Duration::from_secs(90), "no connection"),
        }
    }
    std::thread::spawn(move || while rx.recv().is_ok() {});

    let port = Loopback::new();
    let id = devices.add_device(rdp::port_device("COM9", Arc::new(Backend(port.clone()))).unwrap());
    // Announced after the server's User Logged On.
    std::thread::sleep(Duration::from_secs(5));
    note(&dir, "connected", "COM9");

    let server = wait_file(&dir, "serial-done", Duration::from_secs(300));
    let summary = {
        let s = port.lock();
        format!(
            "opens={} closes={} echoed={} bauds={:?} controls={}",
            s.opens,
            s.closes,
            s.echoed,
            s.bauds,
            s.controls.len()
        )
    };
    note(&dir, "client", &summary);
    devices.remove(id);
    std::thread::sleep(Duration::from_secs(3));
    note(&dir, "removed", "ok");
    wait_file(&dir, "after-remove", Duration::from_secs(300));

    let s = port.lock();
    assert!(
        server.contains("echo=ping-serial-74"),
        "server saw: {server}"
    );
    assert!(s.bauds.contains(&19200), "baud rate set: {:?}", s.bauds);
    assert!(s.opens >= 1 && s.closes >= 1, "{summary}");
}
