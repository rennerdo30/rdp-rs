//! The application: one winit event loop owns the manager window and every
//! session window. No frame loop: the loop waits, and a window is redrawn only
//! when its content changed. softbuffer presents only damaged rectangles
//! (on Windows a BitBlt per rectangle), which RDP and VNC encode cheaply.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use ffwd_render::{Canvas, TextEngine};
use rdp::Config;
use softbuffer::{Context, Surface};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalSize};
use winit::event::{ElementState, MouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key as WKey, ModifiersState, NamedKey};
use winit::window::{CursorIcon, Window, WindowAttributes, WindowId};

use crate::manager::{self, Action, Fonts, Key, Manager, RowState, SessionRow};
use crate::session::{self, Worker};
use crate::store::Store;
use crate::theme;

pub enum UserEvent {
    Session(u64, session::Event),
}

struct Gfx {
    window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
}

fn make_gfx(el: &ActiveEventLoop, attrs: WindowAttributes) -> Result<Gfx, String> {
    let window = Rc::new(
        el.create_window(attrs)
            .map_err(|e| format!("cannot open a window: {e}"))?,
    );
    let ctx = Context::new(window.clone()).map_err(|e| format!("softbuffer: {e}"))?;
    let surface = Surface::new(&ctx, window.clone()).map_err(|e| format!("softbuffer: {e}"))?;
    Ok(Gfx { window, surface })
}

fn resize_surface(gfx: &mut Gfx, w: usize, h: usize) {
    if let (Some(w), Some(h)) = (NonZeroU32::new(w as u32), NonZeroU32::new(h as u32)) {
        let _ = gfx.surface.resize(w, h);
    }
}

fn to_sb(x: usize, y: usize, w: usize, h: usize) -> Option<softbuffer::Rect> {
    Some(softbuffer::Rect {
        x: x as u32,
        y: y as u32,
        width: NonZeroU32::new(w as u32)?,
        height: NonZeroU32::new(h as u32)?,
    })
}

/// Rectangles where two frames differ, as horizontal runs of 64 x 16 tiles.
fn diff_tiles(prev: &[u32], cur: &[u32], w: usize, h: usize) -> Vec<softbuffer::Rect> {
    const TW: usize = 64;
    const TH: usize = 16;
    let mut out = Vec::new();
    for ty in (0..h).step_by(TH) {
        let th = TH.min(h - ty);
        let mut run: Option<(usize, usize)> = None;
        for tx in (0..w).step_by(TW) {
            let tw = TW.min(w - tx);
            let changed = (ty..ty + th).any(|y| {
                let o = y * w + tx;
                prev[o..o + tw] != cur[o..o + tw]
            });
            match (changed, run) {
                (true, Some((x0, _))) => run = Some((x0, tx + tw)),
                (true, None) => run = Some((tx, tx + tw)),
                (false, Some((x0, x1))) => {
                    out.extend(to_sb(x0, ty, x1 - x0, th));
                    run = None;
                }
                (false, None) => {}
            }
        }
        if let Some((x0, x1)) = run {
            out.extend(to_sb(x0, ty, x1 - x0, th));
        }
    }
    out
}

struct ManagerWin {
    gfx: Gfx,
    ui: Manager,
    prev: Vec<u32>,
    cur: Vec<u32>,
    size: (usize, usize),
    cursor: (i32, i32),
    text_cursor: bool,
}

struct SessionWin {
    gfx: Gfx,
    mouse: (u16, u16),
    desktop: (usize, usize),
}

struct Session {
    worker: Worker,
    win: Option<SessionWin>,
    title: String,
}

pub struct App {
    proxy: EventLoopProxy<UserEvent>,
    te: TextEngine,
    fonts: Option<Fonts>,
    want_manager: bool,
    manager: Option<ManagerWin>,
    sessions: HashMap<u64, Session>,
    next_id: u64,
    direct: Option<(String, Config)>,
    mods: ModifiersState,
    pub exit_code: i32,
}

pub fn run(direct: Option<(String, Config)>) -> i32 {
    let event_loop = match EventLoop::<UserEvent>::with_user_event().build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("rdpc: cannot start the event loop: {e}");
            return 1;
        }
    };
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut te = TextEngine::new();
    let want_manager = direct.is_none();
    let fonts = if want_manager {
        manager::load_fonts(&mut te)
    } else {
        None
    };
    if want_manager && fonts.is_none() {
        eprintln!("rdpc: no usable UI font found");
        return 1;
    }
    let mut app = App {
        proxy: event_loop.create_proxy(),
        te,
        fonts,
        want_manager,
        manager: None,
        sessions: HashMap::new(),
        next_id: 1,
        direct,
        mods: ModifiersState::empty(),
        exit_code: 0,
    };
    if let Err(e) = event_loop.run_app(&mut app) {
        eprintln!("rdpc: event loop failed: {e}");
        return 1;
    }
    app.exit_code
}

impl App {
    fn start_session(&mut self, name: String, cfg: Config) {
        let id = self.next_id;
        self.next_id += 1;
        let proxy = self.proxy.clone();
        let title = format!("{name} — {}", cfg.host);
        if let Some(m) = &mut self.manager {
            m.ui.sessions.push(SessionRow {
                id,
                name: name.clone(),
                host: cfg.host.clone(),
                state: RowState::Connecting,
            });
            m.gfx.window.request_redraw();
        }
        let worker = session::spawn(cfg, move |ev| {
            let _ = proxy.send_event(UserEvent::Session(id, ev));
        });
        self.sessions.insert(
            id,
            Session {
                worker,
                win: None,
                title,
            },
        );
    }

    fn set_row(&mut self, id: u64, state: RowState, message: Option<(String, u32)>) {
        if let Some(m) = &mut self.manager {
            if let Some(row) = m.ui.sessions.iter_mut().find(|r| r.id == id) {
                row.state = state;
            }
            if let Some((text, color)) = message {
                m.ui.set_message(text, color);
            }
            m.gfx.window.request_redraw();
        }
    }

    fn maybe_exit(&self, el: &ActiveEventLoop) {
        if self.manager.is_none() && self.sessions.values().all(|s| s.win.is_none()) {
            el.exit();
        }
    }

    fn handle_action(&mut self, action: Action) {
        match action {
            Action::Connect { name, cfg } => self.start_session(name, *cfg),
            Action::Show(id) => {
                if let Some(w) = self.sessions.get(&id).and_then(|s| s.win.as_ref()) {
                    w.gfx.window.set_minimized(false);
                    w.gfx.window.focus_window();
                }
            }
            Action::Close(id) => {
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.worker.close();
                }
            }
        }
    }

    fn render_manager(&mut self) {
        let (Some(m), Some(fonts)) = (&mut self.manager, &self.fonts) else {
            return;
        };
        let (w, h) = m.size;
        if w == 0 || h == 0 {
            return;
        }
        m.cur.resize(w * h, 0);
        {
            let mut cv = Canvas::new(&mut m.cur, w, h);
            m.ui.paint(&mut cv, &mut self.te, fonts);
        }
        let Ok(mut buf) = m.gfx.surface.buffer_mut() else {
            return;
        };
        let full = buf.age() == 0 || m.prev.len() != m.cur.len();
        let rects = if full {
            to_sb(0, 0, w, h).into_iter().collect()
        } else {
            diff_tiles(&m.prev, &m.cur, w, h)
        };
        if rects.is_empty() {
            return;
        }
        if full {
            buf.copy_from_slice(&m.cur);
        } else {
            for r in &rects {
                for y in r.y as usize..(r.y + r.height.get()) as usize {
                    let o = y * w + r.x as usize;
                    let n = r.width.get() as usize;
                    buf[o..o + n].copy_from_slice(&m.cur[o..o + n]);
                }
            }
        }
        if let Err(e) = buf.present_with_damage(&rects) {
            eprintln!("rdpc: present failed: {e}");
        }
        std::mem::swap(&mut m.prev, &mut m.cur);
    }

    fn render_session(&mut self, id: u64) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let Some(win) = &mut s.win else { return };
        {
            let mut sh = s.worker.shared.lock().unwrap();
            s.worker.notified.store(false, Ordering::Release);
            let (dw, dh) = (sh.fb.width, sh.fb.height);
            if (dw, dh) != win.desktop {
                win.desktop = (dw, dh);
                let _ = win
                    .gfx
                    .window
                    .request_inner_size(PhysicalSize::new(dw as u32, dh as u32));
                resize_surface(&mut win.gfx, dw, dh);
                sh.full = true;
            }
            let Ok(mut buf) = win.gfx.surface.buffer_mut() else {
                return;
            };
            let full = std::mem::take(&mut sh.full) || buf.age() == 0;
            let damage = std::mem::take(&mut sh.damage);
            if buf.len() != sh.fb.pixels.len() {
                return;
            }
            if full {
                buf.copy_from_slice(&sh.fb.pixels);
            } else {
                for d in &damage {
                    for y in d.y..d.y + d.h {
                        let o = y * dw + d.x;
                        buf[o..o + d.w].copy_from_slice(&sh.fb.pixels[o..o + d.w]);
                    }
                }
            }
            let rects: Vec<softbuffer::Rect> = if full {
                to_sb(0, 0, dw, dh).into_iter().collect()
            } else {
                damage
                    .iter()
                    .filter_map(|d| to_sb(d.x, d.y, d.w, d.h))
                    .collect()
            };
            if !rects.is_empty()
                && let Err(e) = buf.present_with_damage(&rects)
            {
                eprintln!("rdpc: present failed: {e}");
            }
        }
    }

    fn manager_key(&mut self, ev: &winit::event::KeyEvent) -> Option<Key> {
        if ev.state != ElementState::Pressed {
            return None;
        }
        let ctrl = self.mods.control_key();
        Some(match &ev.logical_key {
            WKey::Named(n) => match n {
                NamedKey::Backspace => Key::Backspace,
                NamedKey::Delete => Key::Delete,
                NamedKey::ArrowLeft => Key::Left,
                NamedKey::ArrowRight => Key::Right,
                NamedKey::ArrowUp => Key::Up,
                NamedKey::ArrowDown => Key::Down,
                NamedKey::Home => Key::Home,
                NamedKey::End => Key::End,
                NamedKey::Tab if self.mods.shift_key() => Key::BackTab,
                NamedKey::Tab => Key::Tab,
                NamedKey::Enter => Key::Enter,
                NamedKey::Escape => Key::Esc,
                NamedKey::Space if !ctrl => Key::Char(' '),
                _ => return None,
            },
            WKey::Character(s) if ctrl => match s.to_lowercase().as_str() {
                "a" => Key::SelectAll,
                "v" => Key::Paste(crate::clipboard::read_text()?),
                "n" => Key::New,
                "s" => Key::Save,
                _ => return None,
            },
            WKey::Character(s) => {
                let mut chars = s.chars().filter(|c| !c.is_control());
                let c = chars.next()?;
                if chars.next().is_some() {
                    Key::Paste(s.to_string())
                } else {
                    Key::Char(c)
                }
            }
            _ => return None,
        })
    }

    fn manager_event(&mut self, el: &ActiveEventLoop, event: WindowEvent) {
        let Some(m) = &mut self.manager else { return };
        match event {
            WindowEvent::CloseRequested => {
                self.manager = None;
                self.maybe_exit(el);
            }
            WindowEvent::Resized(sz) => {
                m.size = (sz.width as usize, sz.height as usize);
                resize_surface(&mut m.gfx, m.size.0, m.size.1);
                m.prev.clear();
                m.gfx.window.request_redraw();
            }
            WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                m.ui.scale = scale_factor as f32;
                m.gfx.window.request_redraw();
            }
            WindowEvent::RedrawRequested => self.render_manager(),
            WindowEvent::CursorMoved { position, .. } => {
                m.cursor = (position.x as i32, position.y as i32);
                if m.ui.mouse_move(m.cursor.0, m.cursor.1) {
                    m.gfx.window.request_redraw();
                }
                let text = m.ui.cursor_is_text();
                if text != m.text_cursor {
                    m.gfx.window.set_cursor(if text {
                        CursorIcon::Text
                    } else {
                        CursorIcon::Default
                    });
                    m.text_cursor = text;
                }
            }
            WindowEvent::CursorLeft { .. } => {
                if m.ui.mouse_move(-1, -1) {
                    m.gfx.window.request_redraw();
                }
            }
            WindowEvent::MouseInput {
                state,
                button: MouseButton::Left,
                ..
            } => {
                let (x, y) = m.cursor;
                let action = if state == ElementState::Pressed {
                    if let Some(fonts) = &self.fonts {
                        m.ui.mouse_down(x, y, &mut self.te, fonts);
                    }
                    None
                } else {
                    m.ui.mouse_up(x, y)
                };
                m.gfx.window.request_redraw();
                if let Some(a) = action {
                    self.handle_action(a);
                }
            }
            WindowEvent::ModifiersChanged(mods) => self.mods = mods.state(),
            WindowEvent::KeyboardInput { event, .. } => {
                if let Some(k) = self.manager_key(&event) {
                    let Some(m) = &mut self.manager else { return };
                    let action = m.ui.key(k);
                    m.gfx.window.request_redraw();
                    if let Some(a) = action {
                        self.handle_action(a);
                    }
                }
            }
            _ => {}
        }
    }

    fn session_event(&mut self, el: &ActiveEventLoop, id: u64, event: WindowEvent) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let Some(win) = &mut s.win else { return };
        let mut send = Vec::new();
        match event {
            WindowEvent::CloseRequested => {
                s.worker.close();
                s.win = None;
                self.maybe_exit(el);
                return;
            }
            WindowEvent::RedrawRequested => return self.render_session(id),
            WindowEvent::KeyboardInput { event, .. } => send.extend(session::key_event(&event)),
            WindowEvent::Focused(false) => send.extend(session::release_modifiers()),
            WindowEvent::CursorMoved { position, .. } => {
                let x = position.x.clamp(0.0, (win.desktop.0.max(1) - 1) as f64) as u16;
                let y = position.y.clamp(0.0, (win.desktop.1.max(1) - 1) as f64) as u16;
                if (x, y) != win.mouse {
                    win.mouse = (x, y);
                    send.push(rdp::InputEvent::mouse_move(x, y));
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                send.extend(session::mouse_button(
                    button,
                    state == ElementState::Pressed,
                    win.mouse,
                ));
            }
            WindowEvent::MouseWheel { delta, .. } => send.extend(session::wheel(delta, win.mouse)),
            _ => {}
        }
        s.worker.send(send);
    }

    fn open_session_window(&mut self, el: &ActiveEventLoop, id: u64, info: &rdp::ConnectionInfo) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let (w, h) = (info.width as usize, info.height as usize);
        let attrs = Window::default_attributes()
            .with_title(&s.title)
            .with_inner_size(PhysicalSize::new(w as u32, h as u32))
            .with_resizable(false);
        match make_gfx(el, attrs) {
            Ok(mut gfx) => {
                resize_surface(&mut gfx, w, h);
                gfx.window.request_redraw();
                s.win = Some(SessionWin {
                    gfx,
                    mouse: (0, 0),
                    desktop: (w, h),
                });
            }
            Err(e) => {
                s.worker.close();
                eprintln!("rdpc: {e}");
            }
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.want_manager && self.manager.is_none() {
            let attrs = Window::default_attributes()
                .with_title("rdpc — Connections")
                .with_inner_size(LogicalSize::new(980.0, 640.0))
                .with_min_inner_size(LogicalSize::new(760.0, 520.0));
            match make_gfx(el, attrs) {
                Ok(gfx) => {
                    let scale = gfx.window.scale_factor() as f32;
                    let sz = gfx.window.inner_size();
                    let mut ui = Manager::new(Store::load(), scale);
                    ui.renderer = "CPU".into();
                    let mut m = ManagerWin {
                        gfx,
                        ui,
                        prev: Vec::new(),
                        cur: Vec::new(),
                        size: (sz.width as usize, sz.height as usize),
                        cursor: (-1, -1),
                        text_cursor: false,
                    };
                    resize_surface(&mut m.gfx, m.size.0, m.size.1);
                    m.gfx.window.request_redraw();
                    self.manager = Some(m);
                }
                Err(e) => {
                    eprintln!("rdpc: {e}");
                    self.exit_code = 1;
                    el.exit();
                }
            }
            self.want_manager = false;
        }
        if let Some((name, cfg)) = self.direct.take() {
            eprintln!("connecting to {}:{} ...", cfg.host, cfg.port);
            self.start_session(name, cfg);
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: UserEvent) {
        let UserEvent::Session(id, ev) = event;
        match ev {
            session::Event::Connected(info) => {
                if self.manager.is_none() {
                    eprintln!(
                        "connected: protocol {:#x}, desktop {}x{} at {} bpp",
                        info.protocol, info.width, info.height, info.bpp
                    );
                }
                self.open_session_window(el, id, &info);
                let state = RowState::Connected {
                    width: info.width,
                    height: info.height,
                    bpp: info.bpp,
                };
                let host = self
                    .sessions
                    .get(&id)
                    .map(|s| s.title.clone())
                    .unwrap_or_default();
                self.set_row(
                    id,
                    state,
                    Some((format!("Connected: {host}."), theme::TEXT_2)),
                );
            }
            session::Event::Frame => {
                if let Some(w) = self.sessions.get(&id).and_then(|s| s.win.as_ref()) {
                    w.gfx.window.request_redraw();
                }
            }
            session::Event::Closed(why) | session::Event::Failed(why) if self.manager.is_none() => {
                eprintln!("session ended: {why}");
                if let Some(mut s) = self.sessions.remove(&id)
                    && let Some(t) = s.worker.thread.take()
                {
                    let _ = t.join();
                }
                self.maybe_exit(el);
            }
            session::Event::Closed(why) => {
                if let Some(mut s) = self.sessions.remove(&id)
                    && let Some(t) = s.worker.thread.take()
                {
                    let _ = t.join();
                }
                self.set_row(id, RowState::Ended(why), None);
            }
            session::Event::Failed(why) => {
                if let Some(mut s) = self.sessions.remove(&id)
                    && let Some(t) = s.worker.thread.take()
                {
                    let _ = t.join();
                }
                self.set_row(id, RowState::Failed(why.clone()), Some((why, theme::ERR)));
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, wid: WindowId, event: WindowEvent) {
        if self
            .manager
            .as_ref()
            .is_some_and(|m| m.gfx.window.id() == wid)
        {
            return self.manager_event(el, event);
        }
        let id = self
            .sessions
            .iter()
            .find(|(_, s)| s.win.as_ref().is_some_and(|w| w.gfx.window.id() == wid))
            .map(|(id, _)| *id);
        if let Some(id) = id {
            self.session_event(el, id, event);
        }
    }
}
