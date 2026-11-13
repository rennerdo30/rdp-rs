//! One RDP session: the protocol runs on a worker thread; the UI thread only
//! copies damaged rectangles to the window and forwards input.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rdp::input::{PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3};
use rdp::{Client, Config, ConnectionInfo, Damage, Framebuffer, InputEvent, StaticChannel};

pub enum Event {
    Connected(ConnectionInfo),
    /// New damage is waiting in `Shared`.
    Frame,
    Closed(String),
    /// The network dropped the session; reconnecting may resume it (the
    /// cookie lets the server reattach without a new logon).
    Dropped {
        why: String,
        cookie: Option<rdp::AutoReconnectCookie>,
    },
    /// The remote cursor changed shape (or was hidden / reset).
    Pointer(rdp::PointerUpdate),
    Failed(String),
}

pub enum Cmd {
    Input(Vec<InputEvent>),
    Close,
}

/// What the worker hands to the UI thread.
pub struct Shared {
    pub fb: Framebuffer,
    pub damage: Vec<Damage>,
    /// The whole framebuffer must be presented (first frame or resize).
    pub full: bool,
}

pub struct Worker {
    pub tx: Sender<Cmd>,
    pub shared: Arc<Mutex<Shared>>,
    /// True while a Frame event is in flight, so the worker sends at most one.
    pub notified: Arc<AtomicBool>,
    pub thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn close(&mut self) {
        let _ = self.tx.send(Cmd::Close);
    }

    pub fn send(&self, events: Vec<InputEvent>) {
        if !events.is_empty() {
            let _ = self.tx.send(Cmd::Input(events));
        }
    }
}

pub fn spawn(
    cfg: Config,
    channels: Vec<Box<dyn StaticChannel>>,
    emit: impl Fn(Event) + Send + 'static,
) -> Worker {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Mutex::new(Shared {
        fb: Framebuffer::new(0, 0),
        damage: Vec::new(),
        full: true,
    }));
    let notified = Arc::new(AtomicBool::new(false));
    let (s, n) = (shared.clone(), notified.clone());
    let thread = std::thread::Builder::new()
        .name("rdp-session".into())
        .spawn(move || run(cfg, channels, rx, s, n, emit))
        .expect("spawn session thread");
    Worker {
        tx,
        shared,
        notified,
        thread: Some(thread),
    }
}

fn copy_rect(src: &Framebuffer, dst: &mut Framebuffer, d: Damage) {
    for row in d.y..d.y + d.h {
        let o = row * src.width + d.x;
        dst.pixels[o..o + d.w].copy_from_slice(&src.pixels[o..o + d.w]);
    }
}

fn run(
    cfg: Config,
    channels: Vec<Box<dyn StaticChannel>>,
    rx: Receiver<Cmd>,
    shared: Arc<Mutex<Shared>>,
    notified: Arc<AtomicBool>,
    emit: impl Fn(Event),
) {
    let mut client = match Client::connect_with(&cfg, channels) {
        Ok(c) => c,
        Err(e) => return emit(Event::Failed(e.to_string())),
    };
    {
        let fb = client.framebuffer();
        let mut s = shared.lock().unwrap();
        s.fb = Framebuffer::new(fb.width, fb.height);
        s.full = true;
    }
    emit(Event::Connected(client.info().clone()));

    loop {
        loop {
            match rx.try_recv() {
                Ok(Cmd::Input(ev)) => {
                    if let Err(e) = client.send_input(&ev) {
                        return emit(Event::Failed(e.to_string()));
                    }
                }
                Ok(Cmd::Close) | Err(TryRecvError::Disconnected) => {
                    client.disconnect();
                    return emit(Event::Closed("disconnected".into()));
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        let out = match client.poll(Duration::from_millis(4)) {
            Ok(o) => o,
            Err(e) if e.is_network_drop() => {
                return emit(Event::Dropped {
                    why: e.to_string(),
                    cookie: client.auto_reconnect_cookie(),
                });
            }
            Err(e) => return emit(Event::Failed(e.to_string())),
        };
        if out.resized || !out.damage.is_empty() {
            let fb = client.framebuffer();
            let mut s = shared.lock().unwrap();
            if out.resized || s.fb.width != fb.width || s.fb.height != fb.height {
                s.fb = Framebuffer::new(fb.width, fb.height);
                s.fb.pixels.copy_from_slice(&fb.pixels);
                s.damage.clear();
                s.full = true;
            } else {
                for &d in &out.damage {
                    copy_rect(fb, &mut s.fb, d);
                }
                s.damage.extend_from_slice(&out.damage);
            }
            drop(s);
            if !notified.swap(true, Ordering::AcqRel) {
                emit(Event::Frame);
            }
        }
        if let Some(p) = out.pointer {
            emit(Event::Pointer(p));
        }
        if let Some(reason) = out.closed {
            if reason.reconnectable {
                return emit(Event::Dropped {
                    why: reason.text,
                    cookie: client.auto_reconnect_cookie(),
                });
            }
            return emit(Event::Closed(reason.text));
        }
    }
}

pub fn key_event(ev: &winit::event::KeyEvent) -> Option<InputEvent> {
    use winit::platform::scancode::PhysicalKeyExtScancode;
    let code = ev.physical_key.to_scancode()?;
    // Windows reports extended keys with an E0 prefix in the high byte.
    let extended = code & 0xFF00 == 0xE000;
    let scancode = (code & 0xFF) as u8;
    if scancode == 0 {
        return None;
    }
    Some(InputEvent::Key {
        scancode,
        extended,
        down: ev.state.is_pressed(),
    })
}

/// Releases every modifier, so focus changes never leave a key stuck down remotely.
/// Ctrl+Alt+Del as scancodes (the local OS never sees it, so it is safe to send).
pub fn ctrl_alt_del() -> Vec<InputEvent> {
    let k = |scancode, extended, down| InputEvent::Key {
        scancode,
        extended,
        down,
    };
    vec![
        k(0x1D, false, true),
        k(0x38, false, true),
        k(0x53, true, true),
        k(0x53, true, false),
        k(0x38, false, false),
        k(0x1D, false, false),
    ]
}

pub fn release_modifiers() -> Vec<InputEvent> {
    [
        (0x1D, false),
        (0x1D, true),
        (0x38, false),
        (0x38, true),
        (0x2A, false),
        (0x36, false),
        (0x5B, true),
        (0x5C, true),
    ]
    .into_iter()
    .map(|(scancode, extended)| InputEvent::Key {
        scancode,
        extended,
        down: false,
    })
    .collect()
}

pub fn mouse_button(
    button: winit::event::MouseButton,
    down: bool,
    pos: (u16, u16),
) -> Option<InputEvent> {
    use winit::event::MouseButton as B;
    let flag = match button {
        B::Left => PTRFLAGS_BUTTON1,
        B::Right => PTRFLAGS_BUTTON2,
        B::Middle => PTRFLAGS_BUTTON3,
        _ => return None,
    };
    Some(InputEvent::mouse_button(flag, down, pos.0, pos.1))
}

pub fn wheel(delta: winit::event::MouseScrollDelta, pos: (u16, u16)) -> Option<InputEvent> {
    use winit::event::MouseScrollDelta as D;
    let notches = match delta {
        D::LineDelta(_, y) => y,
        D::PixelDelta(p) => (p.y / 120.0) as f32,
    };
    if notches == 0.0 {
        return None;
    }
    let units = (notches * 120.0).round().clamp(-255.0, 255.0) as i16;
    Some(InputEvent::wheel(units, pos.0, pos.1))
}
