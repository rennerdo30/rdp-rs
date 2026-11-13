//! The application: one window with a connections sidebar and session tabs.
//!
//! No frame loop: the event loop waits and redraws only on change. Two
//! present paths keep remote updates cheap:
//! - chrome changes (input, tabs, state) repaint the UI offscreen, blit the
//!   active session into its area, diff against the shown frame in 64 x 16
//!   tiles and present only the changed tiles;
//! - session updates copy the damaged rectangles straight into the shown
//!   frame and present just those rectangles (on Windows a BitBlt each),
//!   which is what RDP and VNC encode cheaply when rdpc itself runs remotely.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ffwd_render::{Canvas, Rect, TextEngine};
use rdp::{Config, InputEvent};
use softbuffer::{Context, Surface};
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, MouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key as WKey, ModifiersState, NamedKey};
use winit::window::{CursorIcon, CustomCursor, Window, WindowId};

use crate::controls::Controls;
use crate::session::{self, Worker};
use crate::store::Store;
use crate::theme;
use crate::ui::{self, Action, Fonts, Key, SharedDrive, TabState, Ui};

pub enum UserEvent {
    Session(u64, session::Event),
}

struct Gfx {
    window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
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

/// One session: its worker (None after it ended), what is needed to
/// reconnect, and its live controls.
struct Session {
    worker: Option<Worker>,
    cfg: Config,
    controls: Controls,
    mouse: (u16, u16),
    /// The size last requested for fit-to-window.
    fit_requested: Option<(u32, u32)>,
    /// The remote cursor to show over this session's picture.
    cursor: RemoteCursor,
    /// Native cursors made from the server's shapes, by shape identity. The
    /// Arc is kept so a freed shape's address cannot be reused for another.
    cursors: Vec<(Arc<rdp::PointerShape>, CustomCursor)>,
}

#[derive(Clone, PartialEq)]
enum RemoteCursor {
    Default,
    Hidden,
    Custom(CustomCursor),
}

/// What the window shows right now, so the cursor is only set on a change.
#[derive(Clone, PartialEq)]
enum Shown {
    Icon(CursorIcon),
    Remote(RemoteCursor),
}

struct MainWin {
    gfx: Gfx,
    ui: Ui,
    /// What is on screen.
    shown: Vec<u32>,
    /// Scratch frame for chrome repaints.
    scratch: Vec<u32>,
    size: (usize, usize),
    cursor: (i32, i32),
    shown_cursor: Shown,
    chrome_dirty: bool,
    /// The session a mouse button went down in (gets the release too).
    pressed_in: Option<u64>,
}

pub struct App {
    proxy: EventLoopProxy<UserEvent>,
    te: TextEngine,
    fonts: Fonts,
    win: Option<MainWin>,
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
    let Some(fonts) = ui::load_fonts(&mut te) else {
        eprintln!("rdpc: no usable UI font found");
        return 1;
    };
    let mut app = App {
        proxy: event_loop.create_proxy(),
        te,
        fonts,
        win: None,
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
    fn dirty(&mut self) {
        if let Some(w) = &mut self.win {
            w.chrome_dirty = true;
            w.gfx.window.request_redraw();
        }
    }

    /// The main window's native handle (Windows HWND), 0 when unavailable.
    fn hwnd(&self) -> isize {
        use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
        let Some(w) = &self.win else { return 0 };
        match w.gfx.window.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
            _ => 0,
        }
    }

    fn spawn_worker(&self, id: u64, cfg: Config) -> (Worker, Controls) {
        let proxy = self.proxy.clone();
        let (channels, controls) = Controls::build(&cfg.client_name, self.hwnd());
        let worker = session::spawn(cfg, channels, move |ev| {
            let _ = proxy.send_event(UserEvent::Session(id, ev));
        });
        (worker, controls)
    }

    fn start_session(&mut self, name: String, cfg: Config, fit: bool) {
        let id = self.next_id;
        self.next_id += 1;
        let (worker, controls) = self.spawn_worker(id, cfg.clone());
        if let Some(w) = &mut self.win {
            w.ui.open_tab(id, name, cfg.host.clone(), fit);
        }
        self.sessions.insert(
            id,
            Session {
                worker: Some(worker),
                cfg,
                controls,
                mouse: (0, 0),
                fit_requested: None,
                cursor: RemoteCursor::Default,
                cursors: Vec::new(),
            },
        );
        self.dirty();
    }

    fn reconnect(&mut self, id: u64) {
        let Some(cfg) = self.sessions.get(&id).map(|s| s.cfg.clone()) else {
            return;
        };
        if let Some(mut old) = self.sessions.get_mut(&id).and_then(|s| s.worker.take()) {
            old.close();
        }
        let (worker, controls) = self.spawn_worker(id, cfg);
        if let Some(s) = self.sessions.get_mut(&id) {
            s.worker = Some(worker);
            s.controls = controls;
            s.fit_requested = None;
            s.cursor = RemoteCursor::Default;
            s.cursors.clear();
        }
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.state = TabState::Connecting;
            t.drives.clear();
            t.clipboard = false;
            t.printers = false;
            t.smart_cards = false;
        }
        self.dirty();
    }

    fn send(&self, id: u64, events: Vec<InputEvent>) {
        if let Some(w) = self.sessions.get(&id).and_then(|s| s.worker.as_ref()) {
            w.send(events);
        }
    }

    fn message(&mut self, text: impl Into<String>, color: u32) {
        if let Some(w) = &mut self.win {
            w.ui.set_message(text, color);
        }
        self.dirty();
    }

    fn handle_action(&mut self, action: Action) {
        match action {
            Action::Connect { name, mut cfg, fit } => {
                if fit && let Some(m) = &self.win {
                    let (w, h) = m.ui.session_size_for(m.size.0 as i32, m.size.1 as i32);
                    // Desktop widths must be even; sizes between 200 and 8192.
                    cfg.width = ((w.clamp(200, 8192) as u16) & !1).max(200);
                    cfg.height = h.clamp(200, 8192) as u16;
                }
                self.start_session(name, *cfg, fit);
            }
            Action::Disconnect(id) => {
                if let Some(w) = self.sessions.get_mut(&id).and_then(|s| s.worker.as_mut()) {
                    w.close();
                }
            }
            Action::Reconnect(id) => self.reconnect(id),
            Action::CloseTab(id) => {
                if let Some(mut s) = self.sessions.remove(&id)
                    && let Some(w) = s.worker.as_mut()
                {
                    w.close();
                }
                if let Some(w) = &mut self.win {
                    w.ui.close_tab(id);
                }
                self.dirty();
            }
            Action::SetPrinters(id, on) => {
                let r = self.sessions.get(&id).map(|s| s.controls.set_printers(on));
                self.toggle_result(id, r, on, "Printers", |t| t.printers = false);
            }
            Action::SetSmartCards(id, on) => {
                let r = self
                    .sessions
                    .get(&id)
                    .map(|s| s.controls.set_smart_cards(on));
                self.toggle_result(id, r, on, "Smart cards", |t| t.smart_cards = false);
            }
            Action::SetClipboard(id, on) => {
                let r = self.sessions.get(&id).map(|s| s.controls.set_clipboard(on));
                if let Some(Err(e)) = r {
                    if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                        t.clipboard = false;
                    }
                    self.message(e, theme::WARN);
                } else {
                    self.message(
                        if on {
                            "Clipboard shared."
                        } else {
                            "Clipboard no longer shared."
                        },
                        theme::TEXT_2,
                    );
                }
            }
            Action::SetFit(id, on) => {
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.fit_requested = None;
                }
                if !on {
                    self.message(
                        "Fit to window off: the desktop keeps its size.",
                        theme::TEXT_2,
                    );
                }
                self.dirty();
            }
            Action::AddDrive(id, path) => {
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.trim_end_matches(['\\', '/', ':']).to_string());
                let r = self
                    .sessions
                    .get(&id)
                    .map(|s| s.controls.add_drive(&name, &path));
                match r {
                    Some(Ok(device_id)) => {
                        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                            t.drives.push(SharedDrive {
                                device_id,
                                name: name.clone(),
                                path,
                            });
                        }
                        self.message(format!("Sharing {name}."), theme::TEXT_2);
                    }
                    Some(Err(e)) => self.message(e, theme::WARN),
                    None => {}
                }
            }
            Action::RemoveDrive(id, i) => {
                let drive = self
                    .win
                    .as_mut()
                    .and_then(|w| w.ui.tab_mut(id))
                    .and_then(|t| (i < t.drives.len()).then(|| t.drives.remove(i)));
                if let (Some(d), Some(s)) = (drive, self.sessions.get(&id)) {
                    s.controls.remove_drive(d.device_id);
                    self.message(format!("Stopped sharing {}.", d.name), theme::TEXT_2);
                }
            }
            Action::CtrlAltDel(id) => self.send(id, session::ctrl_alt_del()),
        }
    }

    /// Repaints the chrome, blits the active session and presents the changed tiles.
    fn render_chrome(&mut self) {
        let Some(m) = &mut self.win else { return };
        let (w, h) = m.size;
        if w == 0 || h == 0 {
            return;
        }
        m.scratch.resize(w * h, 0);
        m.ui.paint(
            &mut Canvas::new(&mut m.scratch, w, h),
            &mut self.te,
            &self.fonts,
        );
        if let Some((id, area)) = m.ui.session_area
            && let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref())
        {
            let mut sh = worker.shared.lock().unwrap();
            worker.notified.store(false, Ordering::Release);
            blit(&sh.fb, &mut m.scratch, w, area, None);
            sh.damage.clear();
            sh.full = false;
        }
        let Ok(mut buf) = m.gfx.surface.buffer_mut() else {
            return;
        };
        let full = buf.age() == 0 || m.shown.len() != m.scratch.len();
        let rects: Vec<softbuffer::Rect> = if full {
            to_sb(0, 0, w, h).into_iter().collect()
        } else {
            diff_tiles(&m.shown, &m.scratch, w, h)
        };
        m.chrome_dirty = false;
        if rects.is_empty() {
            return;
        }
        if full {
            buf.copy_from_slice(&m.scratch);
        } else {
            for r in &rects {
                for y in r.y as usize..(r.y + r.height.get()) as usize {
                    let o = y * w + r.x as usize;
                    let n = r.width.get() as usize;
                    buf[o..o + n].copy_from_slice(&m.scratch[o..o + n]);
                }
            }
        }
        if let Err(e) = buf.present_with_damage(&rects) {
            eprintln!("rdpc: present failed: {e}");
        }
        std::mem::swap(&mut m.shown, &mut m.scratch);
    }

    /// Copies only the active session's damaged rectangles to the screen.
    fn render_session_damage(&mut self) {
        let Some(m) = &mut self.win else { return };
        let Some((id, area)) = m.ui.session_area else {
            return;
        };
        let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref()) else {
            return;
        };
        let (w, h) = m.size;
        if m.shown.len() != w * h {
            m.chrome_dirty = true;
            return self.render_chrome();
        }
        let mut sh = worker.shared.lock().unwrap();
        worker.notified.store(false, Ordering::Release);
        if sh.full {
            drop(sh);
            m.chrome_dirty = true;
            return self.render_chrome();
        }
        let damage = std::mem::take(&mut sh.damage);
        let mut rects = Vec::new();
        for d in &damage {
            if let Some(r) = blit(&sh.fb, &mut m.shown, w, area, Some(*d)) {
                rects.extend(to_sb(
                    r.x as usize,
                    r.y as usize,
                    r.w as usize,
                    r.h as usize,
                ));
            }
        }
        drop(sh);
        if rects.is_empty() {
            return;
        }
        let Ok(mut buf) = m.gfx.surface.buffer_mut() else {
            return;
        };
        if buf.age() == 0 {
            buf.copy_from_slice(&m.shown);
            rects = to_sb(0, 0, w, h).into_iter().collect();
        } else {
            for r in &rects {
                for y in r.y as usize..(r.y + r.height.get()) as usize {
                    let o = y * w + r.x as usize;
                    let n = r.width.get() as usize;
                    buf[o..o + n].copy_from_slice(&m.shown[o..o + n]);
                }
            }
        }
        if let Err(e) = buf.present_with_damage(&rects) {
            eprintln!("rdpc: present failed: {e}");
        }
    }

    /// Requests a server-side resize when fit-to-window is on and the tab size changed.
    fn fit_active(&mut self) {
        let Some(m) = &self.win else { return };
        let Some((id, area)) = m.ui.session_area else {
            return;
        };
        let fit = m.ui.active_tab().is_some_and(|t| t.fit);
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let want = (area.w.max(0) as u32, area.h.max(0) as u32);
        if fit && s.fit_requested != Some(want) && s.controls.request_resize(want.0, want.1) {
            s.fit_requested = Some(want);
        }
    }

    fn manager_key(&self, ev: &winit::event::KeyEvent) -> Option<Key> {
        if ev.state != ElementState::Pressed {
            return None;
        }
        let ctrl = self.mods.control_key();
        Some(match &ev.logical_key {
            WKey::Named(n) => match n {
                NamedKey::Tab if ctrl && self.mods.shift_key() => Key::PrevTab,
                NamedKey::Tab if ctrl => Key::NextTab,
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

    fn keyboard(&mut self, ev: winit::event::KeyEvent) {
        let Some(m) = &mut self.win else { return };
        let session = if m.ui.session_focus {
            m.ui.session_area.map(|(id, _)| id)
        } else {
            None
        };
        if let Some(id) = session {
            let release = ev.state.is_pressed()
                && self.mods.control_key()
                && self.mods.alt_key()
                && matches!(ev.logical_key, WKey::Named(NamedKey::Home));
            if release {
                m.ui.session_focus = false;
                self.send(id, session::release_modifiers());
                self.dirty();
            } else if let Some(e) = session::key_event(&ev) {
                self.send(id, vec![e]);
            }
            return;
        }
        if let Some(k) = self.manager_key(&ev) {
            let action = self.win.as_mut().and_then(|m| m.ui.key(k));
            self.dirty();
            if let Some(a) = action {
                self.handle_action(a);
            }
        }
    }

    /// Reports a sharing toggle; a failure switches it back off in the drawer.
    fn toggle_result(
        &mut self,
        id: u64,
        r: Option<Result<(), String>>,
        on: bool,
        what: &str,
        reset: impl FnOnce(&mut ui::Tab),
    ) {
        match r {
            Some(Err(e)) => {
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    reset(t);
                }
                self.message(e, theme::WARN);
            }
            Some(Ok(())) => {
                let text = if on {
                    format!("{what} shared.")
                } else {
                    format!("{what} no longer shared.")
                };
                self.message(text, theme::TEXT_2);
            }
            None => {}
        }
    }

    /// The worker finished: join it and show why in the tab.
    fn ended(&mut self, id: u64, state: TabState) {
        if let Some(s) = self.sessions.get_mut(&id)
            && let Some(mut w) = s.worker.take()
            && let Some(t) = w.thread.take()
        {
            let _ = t.join();
        }
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.state = state;
        }
        self.dirty();
    }

    /// Shows the remote cursor while the pointer is over a session picture,
    /// otherwise the app's own (I-beam over fields, arrow elsewhere).
    fn apply_cursor(&mut self) {
        let Some(m) = &self.win else { return };
        let (x, y) = m.cursor;
        let want = match m.ui.session_area {
            Some((id, area)) if area.contains(x, y) => {
                let c = self
                    .sessions
                    .get(&id)
                    .map_or(RemoteCursor::Default, |s| s.cursor.clone());
                Shown::Remote(c)
            }
            _ if m.ui.cursor_is_text() => Shown::Icon(CursorIcon::Text),
            _ => Shown::Icon(CursorIcon::Default),
        };
        let Some(m) = &mut self.win else { return };
        if want == m.shown_cursor {
            return;
        }
        let w = &m.gfx.window;
        match &want {
            Shown::Icon(icon) => {
                w.set_cursor_visible(true);
                w.set_cursor(*icon);
            }
            Shown::Remote(RemoteCursor::Default) => {
                w.set_cursor_visible(true);
                w.set_cursor(CursorIcon::Default);
            }
            Shown::Remote(RemoteCursor::Hidden) => w.set_cursor_visible(false),
            Shown::Remote(RemoteCursor::Custom(c)) => {
                w.set_cursor_visible(true);
                w.set_cursor(c.clone());
            }
        }
        m.shown_cursor = want;
    }

    fn mouse_to_session(&self, x: i32, y: i32) -> Option<(u64, u16, u16)> {
        let m = self.win.as_ref()?;
        let (id, area) = m.ui.session_area?;
        let s = self.sessions.get(&id)?;
        let fb = s
            .worker
            .as_ref()?
            .shared
            .lock()
            .ok()
            .map(|sh| (sh.fb.width, sh.fb.height))?;
        let in_area = area.contains(x, y) || m.pressed_in == Some(id);
        if !in_area || fb.0 == 0 {
            return None;
        }
        let fx = (x - area.x).clamp(0, fb.0 as i32 - 1) as u16;
        let fy = (y - area.y).clamp(0, fb.1 as i32 - 1) as u16;
        Some((id, fx, fy))
    }
}

/// Copies the session framebuffer (or one damaged rectangle of it) into the
/// window frame at `area`, clipped. Returns the window rectangle written.
fn blit(
    fb: &rdp::Framebuffer,
    frame: &mut [u32],
    frame_w: usize,
    area: Rect,
    only: Option<rdp::Damage>,
) -> Option<Rect> {
    let (sx, sy, sw, sh) = match only {
        Some(d) => (d.x as i32, d.y as i32, d.w as i32, d.h as i32),
        None => (0, 0, fb.width as i32, fb.height as i32),
    };
    let dst = Rect::new(area.x + sx, area.y + sy, sw, sh).intersect(area);
    if dst.is_empty() {
        return None;
    }
    for row in 0..dst.h {
        let fy = (dst.y - area.y + row) as usize;
        let fx = (dst.x - area.x) as usize;
        let src = &fb.pixels[fy * fb.width + fx..fy * fb.width + fx + dst.w as usize];
        let o = (dst.y + row) as usize * frame_w + dst.x as usize;
        frame[o..o + dst.w as usize].copy_from_slice(src);
    }
    Some(dst)
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.win.is_none() {
            let attrs = Window::default_attributes()
                .with_title("rdpc")
                .with_inner_size(LogicalSize::new(1320.0, 860.0))
                .with_min_inner_size(LogicalSize::new(900.0, 560.0))
                .with_window_icon(crate::icon::window_icon(64));
            // The taskbar (and Alt+Tab) uses the large icon; give it full resolution.
            #[cfg(windows)]
            let attrs = {
                use winit::platform::windows::WindowAttributesExtWindows;
                attrs.with_taskbar_icon(crate::icon::window_icon(256))
            };
            let made = el
                .create_window(attrs)
                .map_err(|e| e.to_string())
                .and_then(|w| {
                    let window = Rc::new(w);
                    let ctx = Context::new(window.clone()).map_err(|e| e.to_string())?;
                    let surface = Surface::new(&ctx, window.clone()).map_err(|e| e.to_string())?;
                    Ok(Gfx { window, surface })
                });
            match made {
                Ok(mut gfx) => {
                    let scale = gfx.window.scale_factor() as f32;
                    let sz = gfx.window.inner_size();
                    if let (Some(w), Some(h)) =
                        (NonZeroU32::new(sz.width), NonZeroU32::new(sz.height))
                    {
                        let _ = gfx.surface.resize(w, h);
                    }
                    gfx.window.request_redraw();
                    self.win = Some(MainWin {
                        gfx,
                        ui: Ui::new(Store::load(), scale),
                        shown: Vec::new(),
                        scratch: Vec::new(),
                        size: (sz.width as usize, sz.height as usize),
                        cursor: (-1, -1),
                        shown_cursor: Shown::Icon(CursorIcon::Default),
                        chrome_dirty: true,
                        pressed_in: None,
                    });
                }
                Err(e) => {
                    eprintln!("rdpc: cannot open a window: {e}");
                    self.exit_code = 1;
                    el.exit();
                    return;
                }
            }
        }
        if let Some((name, cfg)) = self.direct.take() {
            self.start_session(name, cfg, false);
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: UserEvent) {
        let UserEvent::Session(id, ev) = event;
        let active = self.win.as_ref().and_then(|w| w.ui.active) == Some(id);
        match ev {
            session::Event::Connected(info) => {
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.state = TabState::Connected {
                        width: info.width,
                        height: info.height,
                        bpp: info.bpp,
                    };
                }
                self.message(
                    format!(
                        "Connected: {} ({}×{}).",
                        self.sessions.get(&id).map_or("", |s| s.cfg.host.as_str()),
                        info.width,
                        info.height
                    ),
                    theme::TEXT_2,
                );
            }
            session::Event::Pointer(p) => {
                let Some(s) = self.sessions.get_mut(&id) else {
                    return;
                };
                s.cursor = match p {
                    rdp::PointerUpdate::Default => RemoteCursor::Default,
                    rdp::PointerUpdate::Hidden => RemoteCursor::Hidden,
                    rdp::PointerUpdate::Shape(shape) => {
                        if let Some((_, c)) = s.cursors.iter().find(|(k, _)| Arc::ptr_eq(k, &shape))
                        {
                            RemoteCursor::Custom(c.clone())
                        } else {
                            match CustomCursor::from_rgba(
                                shape.rgba.clone(),
                                shape.width,
                                shape.height,
                                shape.hotspot_x,
                                shape.hotspot_y,
                            ) {
                                Ok(src) => {
                                    let c = el.create_custom_cursor(src);
                                    // Bounded: the server cache has 32 slots; keep a little history.
                                    if s.cursors.len() >= 64 {
                                        s.cursors.remove(0);
                                    }
                                    s.cursors.push((shape, c.clone()));
                                    RemoteCursor::Custom(c)
                                }
                                Err(_) => RemoteCursor::Default,
                            }
                        }
                    }
                };
                self.apply_cursor();
            }
            session::Event::Frame => {
                if active {
                    if let Some(w) = &self.win {
                        w.gfx.window.request_redraw();
                    }
                } else if let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref())
                {
                    // Hidden tab: drop the damage; switching to it blits the whole picture.
                    worker.shared.lock().unwrap().damage.clear();
                    worker.notified.store(false, Ordering::Release);
                }
            }
            session::Event::Closed(why) => {
                let why = if why == "disconnected" {
                    "disconnected by you".to_string()
                } else {
                    why
                };
                self.ended(id, TabState::Ended(why));
            }
            session::Event::Failed(why) => self.ended(id, TabState::Failed(why)),
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _wid: WindowId, event: WindowEvent) {
        if self.win.is_none() {
            return;
        }
        match event {
            WindowEvent::CloseRequested => {
                for s in self.sessions.values_mut() {
                    if let Some(w) = s.worker.as_mut() {
                        w.close();
                    }
                }
                el.exit();
            }
            WindowEvent::Resized(sz) => {
                let m = self.win.as_mut().unwrap();
                m.size = (sz.width as usize, sz.height as usize);
                if let (Some(w), Some(h)) = (NonZeroU32::new(sz.width), NonZeroU32::new(sz.height))
                {
                    let _ = m.gfx.surface.resize(w, h);
                }
                m.shown.clear();
                self.dirty();
            }
            WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                self.win.as_mut().unwrap().ui.scale = scale_factor as f32;
                self.dirty();
            }
            WindowEvent::RedrawRequested => {
                if self.win.as_ref().unwrap().chrome_dirty {
                    self.render_chrome();
                    self.fit_active();
                    // Tabs and the drawer move the session area: re-pick the cursor.
                    self.apply_cursor();
                } else {
                    self.render_session_damage();
                }
            }
            WindowEvent::Focused(false) => {
                if let Some((id, _)) = self.win.as_ref().unwrap().ui.session_area {
                    self.send(id, session::release_modifiers());
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = (position.x as i32, position.y as i32);
                let m = self.win.as_mut().unwrap();
                m.cursor = (x, y);
                if m.ui.mouse_move(x, y) {
                    self.dirty();
                }
                self.apply_cursor();
                if let Some((id, fx, fy)) = self.mouse_to_session(x, y)
                    && let Some(s) = self.sessions.get_mut(&id)
                    && s.mouse != (fx, fy)
                {
                    s.mouse = (fx, fy);
                    self.send(id, vec![InputEvent::mouse_move(fx, fy)]);
                }
            }
            WindowEvent::CursorLeft { .. } => {
                if self.win.as_mut().unwrap().ui.mouse_move(-1, -1) {
                    self.dirty();
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let (x, y) = self.win.as_ref().unwrap().cursor;
                let down = state == ElementState::Pressed;
                let target = self.mouse_to_session(x, y);
                if let Some((id, fx, fy)) = target {
                    self.send(
                        id,
                        session::mouse_button(button, down, (fx, fy))
                            .into_iter()
                            .collect(),
                    );
                }
                let m = self.win.as_mut().unwrap();
                if button == MouseButton::Left {
                    let action = if down {
                        let was = m.ui.session_focus;
                        m.ui.mouse_down(x, y, &mut self.te, &self.fonts);
                        m.pressed_in = target.map(|t| t.0);
                        if was != m.ui.session_focus
                            || m.ui.session_area.is_none_or(|(_, r)| !r.contains(x, y))
                        {
                            self.dirty();
                        }
                        None
                    } else {
                        m.pressed_in = None;
                        let a = m.ui.mouse_up(x, y);
                        self.dirty();
                        a
                    };
                    if let Some(a) = action {
                        self.handle_action(a);
                    }
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let (x, y) = self.win.as_ref().unwrap().cursor;
                if let Some((id, fx, fy)) = self.mouse_to_session(x, y) {
                    self.send(id, session::wheel(delta, (fx, fy)).into_iter().collect());
                }
            }
            WindowEvent::ModifiersChanged(mods) => self.mods = mods.state(),
            WindowEvent::KeyboardInput { event, .. } => self.keyboard(event),
            _ => {}
        }
    }
}
