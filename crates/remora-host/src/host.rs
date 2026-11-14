//! The host's core: accepting connections (one client at a time), the
//! connection sequence over TLS, the logon check, frame pacing and input
//! delivery.

use std::io;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rdp::server::connect;
use rdp::server::input::{
    PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3, PTRFLAGS_DOWN, PTRFLAGS_HWHEEL,
    PTRFLAGS_MOVE, PTRFLAGS_WHEEL, PTRXFLAGS_BUTTON1, PTRXFLAGS_BUTTON2, PTRXFLAGS_DOWN,
    SYNC_CAPS_LOCK, SYNC_KANA_LOCK, SYNC_NUM_LOCK, SYNC_SCROLL_LOCK, wheel_rotation,
};
use rdp::server::pdu::{ERRINFO_RPC_INITIATED_DISCONNECT, ERRINFO_SERVER_DENIED_CONNECTION};
use rdp::server::{
    ClientInput, Event, Rect, ServerSession, ServerTransport, SessionConfig, TlsConfig,
};

use crate::auth::RateLimiter;
use crate::backend::{Authenticator, Button, Capturer, InputSink, Toggles};
use crate::tiles::Shadow;

/// Prints one line of the host's log to stderr.
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => {
        eprintln!("[remora-host] {}", format_args!($($t)*))
    };
}

/// How the host runs its sessions.
#[derive(Clone)]
pub struct HostConfig {
    pub tls: TlsConfig,
    /// At most this many picture updates per second, and only when
    /// something changed.
    pub max_fps: u32,
    /// The connection sequence must reach the active session in this time.
    pub handshake_timeout: Duration,
    /// A client that takes no data for this long is dropped.
    pub write_timeout: Duration,
}

impl HostConfig {
    pub fn new(tls: TlsConfig) -> HostConfig {
        HostConfig {
            tls,
            max_fps: 30,
            handshake_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// The screen and input of the machine, and the last picture sent. It
/// outlives sessions: the next client starts from the same capturer.
pub struct Desktop {
    pub capturer: Box<dyn Capturer>,
    pub input: Box<dyn InputSink>,
    shadow: Option<Shadow>,
}

impl Desktop {
    pub fn new(capturer: Box<dyn Capturer>, input: Box<dyn InputSink>) -> Desktop {
        Desktop {
            capturer,
            input,
            shadow: None,
        }
    }
}

/// How a session ended normally.
#[derive(Debug)]
pub enum SessionEnd {
    /// The client left: Shutdown Request, Disconnect Provider Ultimatum or
    /// the connection closed after activation.
    ClientLeft(String),
    /// The host is stopping.
    Stopped,
}

/// Why a connection failed.
#[derive(Debug)]
pub enum SessionError {
    /// The client offered no TLS (answered with SSL_REQUIRED_BY_SERVER).
    NoTls,
    /// Wrong credentials (answered with Set Error Info and a disconnect).
    LogonFailed,
    /// The capturer failed.
    Capture(io::Error),
    /// Transport or protocol errors, timeouts.
    Rdp(rdp::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::NoTls => f.write_str("the client offered no TLS; refused"),
            SessionError::LogonFailed => f.write_str("wrong password; refused"),
            SessionError::Capture(e) => write!(f, "screen capture failed: {e}"),
            SessionError::Rdp(e) => write!(f, "{e}"),
        }
    }
}

impl From<rdp::Error> for SessionError {
    fn from(e: rdp::Error) -> Self {
        SessionError::Rdp(e)
    }
}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Rdp(e.into())
    }
}

fn flush(s: &mut ServerSession, t: &mut ServerTransport) -> rdp::Result<()> {
    for pdu in s.take_output() {
        t.write(&pdu)?;
    }
    Ok(())
}

/// Runs one connection to its end on the calling thread.
pub fn serve_connection(
    stream: TcpStream,
    cfg: &HostConfig,
    auth: &dyn Authenticator,
    limiter: &RateLimiter,
    desk: &mut Desktop,
    stop: &AtomicBool,
) -> Result<SessionEnd, SessionError> {
    let ip = stream.peer_addr().map(|a| a.ip()).ok();
    let mut t = ServerTransport::new(stream, cfg.write_timeout)?;
    let handshake_deadline = Instant::now() + cfg.handshake_timeout;

    // X.224 negotiation in the clear (MS-RDPBCGR 3.3.5.3.1), then TLS.
    let frame = t
        .read_frame(handshake_deadline)?
        .ok_or(rdp::Error::Timeout)?;
    let request = connect::parse_connection_request(&frame)?;
    let selected = match connect::select_protocol(request.requested_protocols) {
        Ok(p) => {
            t.write(&connect::connection_confirm(p, 0))?;
            p
        }
        Err(code) => {
            t.write(&connect::negotiation_failure(code))?;
            t.close();
            return Err(SessionError::NoTls);
        }
    };
    t.accept_tls(cfg.tls.clone(), handshake_deadline)?;

    let (width, height) = desk.capturer.size();
    let mut s = ServerSession::new(SessionConfig {
        width,
        height,
        requested_protocols: request.requested_protocols.unwrap_or(0),
        selected_protocol: selected,
    });
    let interval = Duration::from_secs(1) / cfg.max_fps.max(1);
    let mut next_tick = Instant::now();
    let mut pending = Pending::default();
    let mut mouse = Pointer {
        last: None,
        width,
        height,
    };

    loop {
        if stop.load(Ordering::Relaxed) {
            s.disconnect(ERRINFO_RPC_INITIATED_DISCONNECT);
            let _ = flush(&mut s, &mut t);
            t.close();
            return Ok(SessionEnd::Stopped);
        }
        let now = Instant::now();
        let deadline = if s.is_active() {
            next_tick
        } else {
            if now >= handshake_deadline {
                return Err(rdp::Error::Timeout.into());
            }
            handshake_deadline.min(now + Duration::from_millis(200))
        };
        let frame = match t.read_frame(deadline) {
            Ok(f) => f,
            Err(rdp::Error::ConnectionLost(m)) if s.is_active() => {
                return Ok(SessionEnd::ClientLeft(m));
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(frame) = frame {
            for event in s.handle(&frame)? {
                match event {
                    Event::Logon(c) => {
                        if auth.check(&c.user, &c.domain, &c.password) {
                            if let Some(ip) = ip {
                                limiter.success(ip);
                            }
                            info!("logon of {:?} from {} accepted", c.user, show(ip));
                            s.accept_logon()?;
                        } else {
                            let delay =
                                ip.map_or(Duration::ZERO, |ip| limiter.failure(ip, Instant::now()));
                            info!(
                                "wrong password for {:?} from {}; refused after {} ms",
                                c.user,
                                show(ip),
                                delay.as_millis()
                            );
                            std::thread::sleep(delay);
                            s.reject_logon(ERRINFO_SERVER_DENIED_CONNECTION);
                            let _ = flush(&mut s, &mut t);
                            t.close();
                            return Err(SessionError::LogonFailed);
                        }
                    }
                    Event::Active => {
                        info!("session active, {width}x{height}");
                        pending.full = true;
                        s.send_default_pointer();
                    }
                    Event::Input(input) => {
                        for e in input {
                            deliver(desk.input.as_mut(), &mut mouse, e);
                        }
                    }
                    Event::Refresh(rects) => pending.areas.extend(rects),
                    Event::Output { allowed, area } => {
                        pending.suppressed = !allowed;
                        if allowed {
                            pending
                                .areas
                                .push(area.unwrap_or(Rect::new(0, 0, width, height)));
                        }
                    }
                    Event::Closed(why) => {
                        let _ = flush(&mut s, &mut t);
                        t.close();
                        return Ok(SessionEnd::ClientLeft(why));
                    }
                }
            }
        }
        flush(&mut s, &mut t)?;
        if s.is_active() && Instant::now() >= next_tick {
            next_tick = Instant::now() + interval;
            if !pending.suppressed {
                send_picture(&mut s, desk, &mut pending).map_err(SessionError::Capture)?;
                flush(&mut s, &mut t)?;
            }
        }
    }
}

fn show(ip: Option<IpAddr>) -> String {
    ip.map_or_else(|| "an unknown address".into(), |ip| ip.to_string())
}

/// Picture work waiting for the next frame tick.
#[derive(Default)]
struct Pending {
    /// Send the whole desktop (after activation).
    full: bool,
    /// Areas the client asked for again.
    areas: Vec<Rect>,
    /// Suppress Output is in force.
    suppressed: bool,
}

/// Captures what changed and queues it, with any area the client asked for.
fn send_picture(s: &mut ServerSession, desk: &mut Desktop, p: &mut Pending) -> io::Result<()> {
    let (w, h) = desk.capturer.size();
    let first = desk.shadow.is_none();
    let shadow = desk.shadow.get_or_insert_with(|| Shadow::new(w, h));
    // The very first picture is worth waiting for a moment.
    let wait = if first {
        Duration::from_secs(1)
    } else {
        Duration::ZERO
    };
    let mut cells = match desk.capturer.next_frame(wait)? {
        Some(frame) => shadow.apply(&frame),
        None => Vec::new(),
    };
    if std::mem::take(&mut p.full) {
        cells = shadow.all_cells();
        p.areas.clear();
    } else if !p.areas.is_empty() {
        cells.extend(shadow.cells(&std::mem::take(&mut p.areas)));
        cells.sort_by_key(|c| (c.y, c.x));
        cells.dedup();
    }
    if !cells.is_empty() {
        s.send_tiles(&shadow.tiles(&cells));
    }
    Ok(())
}

/// The last pointer position given to the sink, and the desktop bounds.
struct Pointer {
    last: Option<(u16, u16)>,
    width: u16,
    height: u16,
}

impl Pointer {
    /// Moves the pointer first when a button event comes from elsewhere.
    fn move_to(&mut self, sink: &mut dyn InputSink, x: u16, y: u16, always: bool) {
        let pos = (
            x.min(self.width.saturating_sub(1)),
            y.min(self.height.saturating_sub(1)),
        );
        if always || self.last != Some(pos) {
            sink.mouse_move(pos.0, pos.1);
            self.last = Some(pos);
        }
    }
}

/// Hands one client input event to the sink (MS-RDPBCGR 2.2.8.1.1.3.1.1).
fn deliver(sink: &mut dyn InputSink, mouse: &mut Pointer, e: ClientInput) {
    match e {
        ClientInput::Key {
            scancode,
            extended,
            extended1,
            down,
        } => {
            let code = if extended1 {
                0xE100 | u16::from(scancode)
            } else {
                u16::from(scancode)
            };
            sink.key(code, extended, down);
        }
        ClientInput::Unicode { code, down } => sink.unicode(code, down),
        ClientInput::Mouse { flags, x, y } => {
            if flags & PTRFLAGS_WHEEL != 0 {
                // The position of a wheel event is not used.
                sink.wheel(wheel_rotation(flags), false);
            } else if flags & PTRFLAGS_HWHEEL != 0 {
                sink.wheel(wheel_rotation(flags), true);
            } else {
                mouse.move_to(sink, x, y, flags & PTRFLAGS_MOVE != 0);
                let down = flags & PTRFLAGS_DOWN != 0;
                for (bit, b) in [
                    (PTRFLAGS_BUTTON1, Button::Left),
                    (PTRFLAGS_BUTTON2, Button::Right),
                    (PTRFLAGS_BUTTON3, Button::Middle),
                ] {
                    if flags & bit != 0 {
                        sink.button(b, down);
                    }
                }
            }
        }
        ClientInput::MouseX { flags, x, y } => {
            mouse.move_to(sink, x, y, false);
            let down = flags & PTRXFLAGS_DOWN != 0;
            if flags & PTRXFLAGS_BUTTON1 != 0 {
                sink.button(Button::X1, down);
            }
            if flags & PTRXFLAGS_BUTTON2 != 0 {
                sink.button(Button::X2, down);
            }
        }
        // Not advertised (no TS_INPUT_FLAG_MOUSE_RELATIVE): ignored.
        ClientInput::RelativeMouse { .. } => {}
        ClientInput::Sync { toggles } => sink.sync(Toggles {
            scroll_lock: toggles & SYNC_SCROLL_LOCK != 0,
            num_lock: toggles & SYNC_NUM_LOCK != 0,
            caps_lock: toggles & SYNC_CAPS_LOCK != 0,
            kana_lock: toggles & SYNC_KANA_LOCK != 0,
        }),
    }
}

/// The accepting side: one session at a time on a worker thread; a second
/// client is refused (its connection is closed at once) while one is
/// active, and addresses over their failure limit are refused before TLS.
pub struct Host {
    pub config: HostConfig,
    pub auth: Arc<dyn Authenticator>,
    pub limiter: Arc<RateLimiter>,
}

impl Host {
    /// Accepts on `listener` until `stop` is set; then ends the running
    /// session (Set Error Info and a disconnect) and returns.
    pub fn run(
        self,
        listener: TcpListener,
        desktop: Desktop,
        stop: Arc<AtomicBool>,
    ) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        let busy = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<TcpStream>();
        let worker = {
            let busy = busy.clone();
            let stop = stop.clone();
            let Host {
                config,
                auth,
                limiter,
            } = self;
            let limiter_w = limiter.clone();
            let mut desktop = desktop;
            let handle = std::thread::Builder::new()
                .name("remora-host-session".into())
                .spawn(move || {
                    for stream in rx {
                        let peer = stream.peer_addr().ok();
                        let r = serve_connection(
                            stream,
                            &config,
                            auth.as_ref(),
                            &limiter_w,
                            &mut desktop,
                            &stop,
                        );
                        match (peer, r) {
                            (Some(p), Ok(end)) => info!("{p}: session ended: {end:?}"),
                            (Some(p), Err(e)) => info!("{p}: {e}"),
                            (None, r) => info!("session ended: {r:?}"),
                        }
                        busy.store(false, Ordering::Release);
                    }
                })?;
            (handle, limiter)
        };
        let (handle, limiter) = worker;
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    stream.set_nonblocking(false)?;
                    if !limiter.allowed(peer.ip(), Instant::now()) {
                        info!("{peer}: refused, too many wrong passwords; try again later");
                        drop(stream);
                    } else if busy.swap(true, Ordering::AcqRel) {
                        info!("{peer}: refused, another session is active");
                        drop(stream);
                    } else {
                        info!("{peer}: connected");
                        if tx.send(stream).is_err() {
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    info!("accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        drop(tx);
        let _ = handle.join();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec(Vec<String>);

    impl InputSink for Rec {
        fn key(&mut self, scancode: u16, extended: bool, down: bool) {
            self.0.push(format!("key {scancode:#x} {extended} {down}"));
        }
        fn unicode(&mut self, ch: u16, down: bool) {
            self.0.push(format!("unicode {ch:#x} {down}"));
        }
        fn mouse_move(&mut self, x: u16, y: u16) {
            self.0.push(format!("move {x} {y}"));
        }
        fn button(&mut self, b: Button, down: bool) {
            self.0.push(format!("{b:?} {down}"));
        }
        fn wheel(&mut self, delta: i16, horizontal: bool) {
            self.0.push(format!("wheel {delta} {horizontal}"));
        }
        fn sync(&mut self, t: Toggles) {
            self.0.push(format!("sync {} {}", t.num_lock, t.caps_lock));
        }
    }

    #[test]
    fn input_events_map_to_the_sink() {
        let mut rec = Rec::default();
        let mut p = Pointer {
            last: None,
            width: 800,
            height: 600,
        };
        for e in [
            ClientInput::Mouse {
                flags: PTRFLAGS_MOVE,
                x: 10,
                y: 20,
            },
            // A click at the same place: no extra move.
            ClientInput::Mouse {
                flags: PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN,
                x: 10,
                y: 20,
            },
            // A release elsewhere (clamped to the desktop): moved first.
            ClientInput::Mouse {
                flags: PTRFLAGS_BUTTON1,
                x: 900,
                y: 30,
            },
            ClientInput::Mouse {
                flags: PTRFLAGS_WHEEL | 0x0100 | 0x88,
                x: 0,
                y: 0,
            },
            ClientInput::Mouse {
                flags: PTRFLAGS_HWHEEL | 0x78,
                x: 0,
                y: 0,
            },
            ClientInput::MouseX {
                flags: PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON2,
                x: 799,
                y: 30,
            },
            ClientInput::Key {
                scancode: 0x1D,
                extended: false,
                extended1: true,
                down: true,
            },
            ClientInput::Key {
                scancode: 0x48,
                extended: true,
                extended1: false,
                down: false,
            },
            ClientInput::Unicode {
                code: 0x20AC,
                down: true,
            },
            ClientInput::Sync {
                toggles: SYNC_NUM_LOCK,
            },
            ClientInput::RelativeMouse {
                flags: PTRFLAGS_MOVE,
                dx: 1,
                dy: 1,
            },
        ] {
            deliver(&mut rec, &mut p, e);
        }
        assert_eq!(
            rec.0,
            [
                "move 10 20",
                "Left true",
                "move 799 30",
                "Left false",
                "wheel -120 false",
                "wheel 120 true",
                "X2 true",
                "key 0xe11d false true",
                "key 0x48 true false",
                "unicode 0x20ac true",
                "sync true false",
            ]
        );
    }
}
