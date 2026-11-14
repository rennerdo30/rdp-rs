//! End to end over loopback: the host with the demo capturer (static
//! pattern) and a recording input sink, and the `rdp` crate's own client.
//! Every socket is on 127.0.0.1 and every wait has a deadline.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rdp::input::{PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2};
use rdp::{CertificateCheck, Client, Config, InputEvent};
use remora_host::auth::{PasswordAuthenticator, RateLimit, RateLimiter};
use remora_host::backend::demo;
use remora_host::{Button, Desktop, Host, HostConfig, InputSink, Toggles, cert};

const PASSWORD: &str = "correct horse battery";
const W: u16 = 320;
const H: u16 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rec {
    Key(u16, bool, bool),
    Unicode(u16, bool),
    Move(u16, u16),
    Button(Button, bool),
    Wheel(i16, bool),
    Sync(Toggles),
}

/// Records every event; also forwards it to the demo sink so the picture
/// shows the input.
struct Recorder {
    log: Arc<Mutex<Vec<Rec>>>,
    demo: demo::DemoInput,
}

impl Recorder {
    fn push(&self, r: Rec) {
        self.log.lock().unwrap().push(r);
    }
}

impl InputSink for Recorder {
    fn key(&mut self, scancode: u16, extended: bool, down: bool) {
        self.push(Rec::Key(scancode, extended, down));
        self.demo.key(scancode, extended, down);
    }
    fn unicode(&mut self, ch: u16, down: bool) {
        self.push(Rec::Unicode(ch, down));
        self.demo.unicode(ch, down);
    }
    fn mouse_move(&mut self, x: u16, y: u16) {
        self.push(Rec::Move(x, y));
        self.demo.mouse_move(x, y);
    }
    fn button(&mut self, b: Button, down: bool) {
        self.push(Rec::Button(b, down));
        self.demo.button(b, down);
    }
    fn wheel(&mut self, delta: i16, horizontal: bool) {
        self.push(Rec::Wheel(delta, horizontal));
    }
    fn sync(&mut self, toggles: Toggles) {
        self.push(Rec::Sync(toggles));
    }
}

struct TestHost {
    port: u16,
    fingerprint: String,
    log: Arc<Mutex<Vec<Rec>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    dir: PathBuf,
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start_host(name: &str) -> TestHost {
    let dir = std::env::temp_dir().join(format!("remora-host-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let id = cert::load_or_create(&dir, &cert::FileModeOnly).unwrap();
    let tls = rdp::server::tls_config(id.certificate.clone(), id.private_key.to_vec()).unwrap();
    let hash = remora_host::auth::hash_password(PASSWORD).unwrap();
    let mut config = HostConfig::new(tls);
    config.handshake_timeout = Duration::from_secs(15);
    config.write_timeout = Duration::from_secs(10);
    let host = Host {
        config,
        auth: Arc::new(PasswordAuthenticator::from_hash(&hash).unwrap()),
        limiter: Arc::new(RateLimiter::new(RateLimit {
            base_delay: Duration::from_millis(10),
            ..RateLimit::default()
        })),
    };
    let (capturer, demo_input) = demo::demo(W, H, false, false);
    let log = Arc::new(Mutex::new(Vec::new()));
    let input = Recorder {
        log: log.clone(),
        demo: demo_input,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let thread = std::thread::spawn(move || {
        host.run(
            listener,
            Desktop::new(Box::new(capturer), Box::new(input)),
            stop2,
        )
        .unwrap();
    });
    TestHost {
        port,
        fingerprint: id.fingerprint(),
        log,
        stop,
        thread: Some(thread),
        dir,
    }
}

fn client_config(h: &TestHost, password: &str) -> Config {
    let mut cfg = Config::new("127.0.0.1", "tester", password);
    cfg.port = h.port;
    cfg.width = 640;
    cfg.height = 480;
    cfg.timeout = Duration::from_secs(15);
    let fp = h.fingerprint.clone();
    cfg.verify_certificate = Some(CertificateCheck(Arc::new(move |c| c.fingerprint() == fp)));
    cfg
}

/// The demo's static pattern as the client's framebuffer holds it.
fn expected_picture() -> Vec<u32> {
    let mut v = Vec::with_capacity(usize::from(W) * usize::from(H));
    for y in 0..H {
        for x in 0..W {
            let [b, g, r, _] = demo::base_pixel(x, y, W, H);
            v.push(u32::from(b) | u32::from(g) << 8 | u32::from(r) << 16);
        }
    }
    v
}

/// Polls the client until `done` or the deadline.
fn poll_until(c: &mut Client, what: &str, mut done: impl FnMut(&Client) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done(c) {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        let out = c.poll(Duration::from_millis(20)).unwrap();
        assert!(out.closed.is_none(), "session closed: {:?}", out.closed);
    }
}

#[test]
fn client_sees_the_desktop_and_its_input_arrives() {
    let host = start_host("full");
    let mut client = Client::connect(&client_config(&host, PASSWORD)).unwrap();
    // The host's size wins over the client's 640 x 480.
    assert_eq!((client.info().width, client.info().height), (W, H));
    assert_eq!(client.info().bpp, 32);
    assert_eq!(client.info().protocol, rdp::x224::PROTOCOL_SSL);
    assert!(client.info().unicode_input());

    // The first full frame, pixel-exact.
    let want = expected_picture();
    poll_until(&mut client, "the first full frame", |c| {
        c.is_active() && c.framebuffer().pixels == want
    });

    // A second client is refused while this one is connected.
    let mut second = TcpStream::connect(("127.0.0.1", host.port)).unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let _ = second.write_all(&rdp::x224::connection_request("other", 1));
    let mut buf = [0u8; 64];
    match second.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        r => panic!("second client got {r:?}"),
    }

    client
        .send_input(&[
            InputEvent::Key {
                scancode: 0x1E,
                extended: false,
                down: true,
            },
            InputEvent::Key {
                scancode: 0x1E,
                extended: false,
                down: false,
            },
            InputEvent::Key {
                scancode: 0x48,
                extended: true,
                down: true,
            },
            InputEvent::Unicode {
                code: 0x20AC,
                down: true,
            },
            InputEvent::Unicode {
                code: 0x20AC,
                down: false,
            },
            InputEvent::mouse_move(100, 50),
            InputEvent::mouse_button(PTRFLAGS_BUTTON1, true, 100, 50),
            InputEvent::mouse_button(PTRFLAGS_BUTTON1, false, 100, 50),
            InputEvent::mouse_button(PTRFLAGS_BUTTON2, true, 120, 60),
            InputEvent::wheel(-120, 120, 60),
            // Horizontal wheel, 120 to the right (PTRFLAGS_HWHEEL).
            InputEvent::Mouse {
                flags: 0x0400 | 120,
                x: 120,
                y: 60,
            },
        ])
        .unwrap();
    let expected = vec![
        Rec::Key(0x1E, false, true),
        Rec::Key(0x1E, false, false),
        Rec::Key(0x48, true, true),
        Rec::Unicode(0x20AC, true),
        Rec::Unicode(0x20AC, false),
        Rec::Move(100, 50),
        Rec::Button(Button::Left, true),
        Rec::Button(Button::Left, false),
        Rec::Move(120, 60),
        Rec::Button(Button::Right, true),
        Rec::Wheel(-120, false),
        Rec::Wheel(120, true),
    ];
    let log = host.log.clone();
    poll_until(&mut client, "the input events", |_| {
        log.lock().unwrap().len() >= expected.len()
    });
    assert_eq!(*host.log.lock().unwrap(), expected);

    // The demo draws the input: the crosshair's white centre at the last
    // pointer position reaches the client as a picture update.
    poll_until(&mut client, "the crosshair", |c| {
        c.framebuffer().pixels[60 * usize::from(W) + 120] == 0x00FF_FFFF
    });
    client.disconnect();
}

#[test]
fn wrong_password_is_refused_without_a_picture() {
    let host = start_host("wrong");
    let err = match Client::connect(&client_config(&host, "not the password")) {
        Ok(_) => panic!("a wrong password connected"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            rdp::Error::Disconnected(_) | rdp::Error::ConnectionLost(_)
        ),
        "{err:?}"
    );
    assert!(host.log.lock().unwrap().is_empty());
    // The right password still gets in afterwards.
    let mut client = Client::connect(&client_config(&host, PASSWORD)).unwrap();
    poll_until(&mut client, "activation", Client::is_active);
    client.disconnect();
}

#[test]
fn client_without_tls_is_refused() {
    let host = start_host("notls");
    for protocols in [rdp::x224::PROTOCOL_RDP, rdp::x224::PROTOCOL_HYBRID] {
        let mut s = TcpStream::connect(("127.0.0.1", host.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(&rdp::x224::connection_request("plain", protocols))
            .unwrap();
        let mut confirm = vec![0u8; 19];
        s.read_exact(&mut confirm).unwrap();
        let err = rdp::x224::parse_connection_confirm(&confirm).unwrap_err();
        assert!(err.to_string().contains("SSL_REQUIRED_BY_SERVER"), "{err}");
        // And the host closes the connection.
        let mut rest = [0u8; 8];
        assert_eq!(s.read(&mut rest).unwrap_or(0), 0);
        // The host is free for the next client (the session thread ended).
        std::thread::sleep(Duration::from_millis(100));
    }
}
