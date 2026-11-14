//! One RDP session: the protocol runs on a worker thread; the UI thread only
//! copies damaged rectangles to the window and forwards input.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rdp::input::{PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3};
use rdp::{Client, Config, ConnectionInfo, Damage, Framebuffer, InputEvent, StaticChannel};

use crate::recorder::Recorder;

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
    /// RemoteApp: the window model and actions, right after `Connected`.
    RailReady(rdp::RailHandle),
    /// RemoteApp window and channel events, in order.
    Rail(Vec<rdp::RailEvent>),
    /// The server redirected the running session (MS-RDPBCGR 3.2.5.13):
    /// connect `cfg` (the next hop, from [`Client::follow_redirection`])
    /// with new channel handlers. `to` names the target for the status line.
    Redirected { cfg: Box<Config>, to: String },
    /// New network auto-detect results (MS-RDPBCGR 2.2.14.1.5).
    Network(rdp::NetworkCharacteristics),
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
    /// The session recording, while one runs; the worker hands it every update.
    recorder: Arc<Mutex<Option<Recorder>>>,
}

impl Worker {
    /// Starts recording (Some) or stops it (None); applies at the next update.
    /// The new recorder starts from the picture on screen now. Returns the
    /// recorder this replaces, for the caller to [`Recorder::finish`] (that
    /// waits for the encoder to drain, so off the UI thread if it matters);
    /// dropping it finishes the file as well.
    #[allow(dead_code, reason = "called by the session UI's record control")]
    pub fn set_recorder(&self, mut recorder: Option<Recorder>) -> Option<Recorder> {
        if let Some(r) = recorder.as_mut() {
            let s = self.shared.lock().unwrap();
            r.frame(&s.fb);
        }
        let mut slot = self.recorder.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut *slot, recorder)
    }

    /// True while a recording runs.
    #[allow(dead_code, reason = "called by the session UI's record control")]
    pub fn is_recording(&self) -> bool {
        self.recorder
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

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
    let recorder = Arc::new(Mutex::new(None));
    let (s, n, r) = (shared.clone(), notified.clone(), recorder.clone());
    let thread = std::thread::Builder::new()
        .name("rdp-session".into())
        .spawn(move || run(cfg, channels, rx, s, n, r, emit))
        .expect("spawn session thread");
    Worker {
        tx,
        shared,
        notified,
        thread: Some(thread),
        recorder,
    }
}

fn copy_rect(src: &Framebuffer, dst: &mut Framebuffer, d: Damage) {
    for row in d.y..d.y + d.h {
        let o = row * src.width + d.x;
        dst.pixels[o..o + d.w].copy_from_slice(&src.pixels[o..o + d.w]);
    }
}

fn run(
    mut cfg: Config,
    channels: Vec<Box<dyn StaticChannel>>,
    rx: Receiver<Cmd>,
    shared: Arc<Mutex<Shared>>,
    notified: Arc<AtomicBool>,
    recorder: Arc<Mutex<Option<Recorder>>>,
    emit: impl Fn(Event),
) {
    // The graphics pipeline decodes AVC420 with Media Foundation; the
    // client asks for a decoder only when cfg.graphics is Gfx.
    #[cfg(windows)]
    if cfg.h264.is_none() {
        cfg.h264 = Some(crate::h264_mf::factory());
    }
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
    if let Some(rail) = client.rail() {
        emit(Event::RailReady(rail));
    }

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
            // One copy into the recorder's mailbox; encoding is on its thread.
            if let Some(r) = recorder.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
                r.frame(fb);
            }
        }
        if let Some(p) = out.pointer {
            emit(Event::Pointer(p));
        }
        if !out.rail.is_empty() {
            emit(Event::Rail(out.rail));
        }
        if let Some(n) = out.network {
            emit(Event::Network(n));
        }
        if let Some(reason) = out.closed {
            // A Server Redirection PDU after logon: the next hop needs new
            // channel handlers, so the UI starts it (same tab, same settings).
            match client.follow_redirection(&cfg) {
                Some(Ok(next)) => {
                    let to = redirect_target(&next);
                    return emit(Event::Redirected {
                        cfg: Box::new(next),
                        to,
                    });
                }
                Some(Err(e)) => return emit(Event::Failed(e.to_string())),
                None => {}
            }
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

/// The server a redirection's next hop goes to, for the status line: its
/// first target, or the sender when it names none (MS-RDPBCGR 1.3.8).
fn redirect_target(next: &Config) -> String {
    next.redirection
        .as_ref()
        .and_then(|r| r.targets().into_iter().next())
        .unwrap_or_else(|| next.host.clone())
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
