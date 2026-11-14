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
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{Key as WKey, ModifiersState, NamedKey};
use winit::window::{CursorIcon, CustomCursor, Window, WindowId};

use crate::controls::Controls;
use crate::session::{self, Worker};
use crate::store::{SessionOptions, Store, WinKeys};
use crate::theme::{ThemeChoice, Tone};
use crate::ui::{self, Action, Fonts, Key, SharedDrive, TabState, Ui};

mod rail;
mod touch;

pub enum UserEvent {
    Session(u64, session::Event),
    /// The frame hook saw the maximise button or window state change.
    Frame,
    /// Key derivation for the vault finished (unlock or create).
    Vault(VaultResult),
    /// Time for the next automatic reconnect attempt of a dropped session.
    Retry(u64),
    /// A Windows key combination taken by the keyboard hook: (scancode, extended, down).
    HookKey(u8, bool, bool),
    /// A recording was finished (its file, or why it failed).
    Recorded(Result<crate::recorder::RecordingInfo, String>),
    /// Export: the chosen file; Import: the chosen backup (asks its password).
    ExportTo(std::path::PathBuf),
    ImportFrom(std::path::PathBuf),
    /// The folder picker closed: (session or None for the form, folder).
    Picked(Option<u64>, Option<std::path::PathBuf>),
    /// A session waits for the user to trust its server certificate.
    Certificate(u64, ui::CertPrompt, std::sync::mpsc::Sender<bool>),
    /// The update check found a newer release.
    UpdateAvailable(rdpc_update::Candidate),
    /// "Check now" finished without an update (or failed: the reason).
    UpToDate(Result<(), String>),
    /// Installing an update: the setup started (rdpc closes), or it failed.
    UpdateStarted(Result<(), String>),
    /// Time for a throttled Home thumbnail of a session (sent once).
    Thumb(u64),
}

/// Automatic reconnect attempts after a network drop, and the wait before each.
const RETRY_DELAYS_S: [u64; 5] = [1, 2, 4, 8, 15];

pub enum VaultResult {
    Unlocked(Result<crate::vault::VaultKey, String>, bool),
    Created(Result<crate::vault::VaultKey, String>),
    /// A new master password's key (or why the change failed).
    Rekeyed(Result<crate::vault::VaultKey, String>),
    /// The contents of a backup (or why it could not be opened).
    Imported(Result<(Vec<crate::store::Group>, Vec<crate::store::Connection>), String>),
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
    /// Automatic reconnects since the last successful connection.
    retries: usize,
    /// A retry is scheduled (cleared by Disconnect or a manual reconnect).
    retry_pending: bool,
    /// The worker waits for this answer about the server certificate.
    cert_reply: Option<std::sync::mpsc::Sender<bool>>,
    /// Shown in its own windows on chosen monitors (see `span`).
    spanned: bool,
    /// RemoteApp: its apps' windows on this PC's desktop (see `remoteapp`).
    rail: Option<crate::remoteapp::RailSession>,
    /// Keyboard layout and typing translation state (see `keyboard`); a
    /// cell because every send passes through it.
    keys: std::cell::RefCell<crate::keyboard::Keys>,
    /// The last picture of a dropped session, shown dimmed while it
    /// reconnects.
    last_fb: Option<rdp::Framebuffer>,
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
    /// Until then every chrome render presents the whole window: while the
    /// window resizes or moves, Windows may change screen pixels behind our
    /// back, so presenting only changed tiles could leave stale ones.
    settle: Option<std::time::Instant>,
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
    /// Set by the drawn close button; the event loop exits after the event.
    quit: bool,
    /// Title-row geometry last given to the frame hook.
    caption_sent: Option<ui::TitleGeometry>,
    /// A newer release offered by the update check.
    update: Option<rdpc_update::Candidate>,
    /// Session windows on chosen monitors, and those still to open (the
    /// event loop creates windows), and the session whose window has focus.
    spans: Vec<crate::span::SpanWin>,
    pending_spans: Vec<crate::span::SpanSpec>,
    span_focus: Option<u64>,
    /// The RemoteApp session whose app window has the keyboard.
    app_focus: Option<u64>,
    settings: crate::settings::AppSettings,
    /// The last keyboard or mouse input (idle auto-lock).
    last_input: std::time::Instant,
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
        quit: false,
        caption_sent: None,
        update: None,
        spans: Vec::new(),
        pending_spans: Vec::new(),
        span_focus: None,
        app_focus: None,
        settings: crate::settings::AppSettings::load(),
        last_input: std::time::Instant::now(),
        exit_code: 0,
    };
    if let Err(e) = event_loop.run_app(&mut app) {
        eprintln!("rdpc: event loop failed: {e}");
        return 1;
    }
    app.exit_code
}

impl App {
    /// Starts recording a session into `Videos\rdpc`, or stops and finishes
    /// the file (off the UI thread: the encoder drains first).
    fn toggle_recording(&mut self, id: u64) {
        let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref()) else {
            return;
        };
        if worker.is_recording() {
            let old = worker.set_recorder(None);
            if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                t.recording = false;
            }
            if let Some(rec) = old {
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let _ = proxy.send_event(UserEvent::Recorded(rec.finish()));
                });
            }
            self.message("Finishing the recording…", Tone::Muted);
            return;
        }
        let (w, h) = worker
            .shared
            .lock()
            .map(|s| (s.fb.width as u32, s.fb.height as u32))
            .unwrap_or((0, 0));
        let name = self
            .win
            .as_ref()
            .and_then(|m| m.ui.tabs.iter().find(|t| t.id == id))
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "session".into());
        let path = recording_path(&name);
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match crate::recorder::Recorder::start(&path, w, h, crate::recorder::DEFAULT_FPS) {
            Ok(rec) => {
                worker.set_recorder(Some(rec));
                if let Some(t) = self.win.as_mut().and_then(|m| m.ui.tab_mut(id)) {
                    t.recording = true;
                }
                self.message(format!("Recording to {}", path.display()), Tone::Warning);
            }
            Err(e) => self.message(format!("Cannot record: {e}"), Tone::Danger),
        }
    }

    /// Quits, but asks first while sessions are open or connecting.
    fn request_quit(&mut self) {
        let open = self.win.as_ref().map_or(0, |m| {
            m.ui.tabs
                .iter()
                .filter(|t| matches!(t.state, TabState::Connected { .. } | TabState::Connecting))
                .count()
        });
        match &mut self.win {
            Some(m) if open > 0 => {
                if m.ui.fullscreen {
                    // The question must be visible: leave full screen first.
                    m.gfx.window.set_fullscreen(None);
                    m.ui.fullscreen = false;
                    m.shown.clear();
                }
                m.ui.confirm_exit = Some(open);
                m.ui.session_focus = false;
                m.gfx.window.focus_window();
                self.dirty();
            }
            _ => self.quit = true,
        }
    }

    fn set_fullscreen(&mut self, on: bool) {
        let Some(m) = &mut self.win else { return };
        if on && m.ui.active.is_none() {
            return;
        }
        m.gfx
            .window
            .set_fullscreen(on.then_some(winit::window::Fullscreen::Borderless(None)));
        m.ui.fullscreen = on;
        m.shown.clear();
        self.settle();
        self.dirty();
    }

    /// When the open vault locks itself, if auto-lock is on.
    fn auto_lock_deadline(&self) -> Option<std::time::Instant> {
        let min = self.settings.auto_lock_minutes;
        let m = self.win.as_ref()?;
        (min > 0 && m.ui.store_is_vault())
            .then(|| self.last_input + std::time::Duration::from_secs(min as u64 * 60))
    }

    /// Full presents for a moment (see `MainWin::settle`).
    fn settle(&mut self) {
        if let Some(m) = &mut self.win {
            m.settle = Some(std::time::Instant::now() + std::time::Duration::from_millis(250));
        }
    }

    /// The keyboard hook takes Windows key combinations only while the
    /// session has the keyboard and its setting asks for it.
    fn update_key_hook(&self) {
        let span = self.span_focus.is_some_and(|id| {
            self.win.as_ref().is_some_and(|m| {
                m.ui.tabs
                    .iter()
                    .any(|t| t.id == id && t.win_keys != WinKeys::Local)
            })
        });
        // App windows are never full screen: only "Remote" sends the keys.
        let app = self.app_focus.is_some_and(|id| {
            self.win.as_ref().is_some_and(|m| {
                m.ui.tabs
                    .iter()
                    .any(|t| t.id == id && t.win_keys == WinKeys::Remote)
            })
        });
        let on = span
            || app
            || self.win.as_ref().is_some_and(|m| {
                let ui = &m.ui;
                ui.window_active
                    && ui.session_focus
                    && ui.active_tab().is_some_and(|t| match t.win_keys {
                        WinKeys::Local => false,
                        WinKeys::Remote => true,
                        WinKeys::FullScreen => ui.fullscreen,
                    })
            });
        crate::keyhook::set_active(on);
    }

    fn dirty(&mut self) {
        self.update_key_hook();
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

    fn start_session(
        &mut self,
        name: String,
        mut cfg: Config,
        fit: bool,
        opts: SessionOptions,
        apps: Vec<crate::store::AppEntry>,
    ) {
        // Auto scale follows this PC's Windows scaling.
        cfg.scale = opts.scale.unwrap_or_else(|| self.auto_scale());
        cfg.verify_certificate = Some(certificate_check(self.proxy.clone(), self.next_id));
        // This PC's keyboard layout, type and IME (RDP-32).
        let (klid, keyboard) = crate::keyboard::local();
        cfg.keyboard = keyboard;
        // Picture quality is fixed at logon; reconnects keep this config.
        opts.quality.apply(&mut cfg);
        // RemoteApp: the desktop is all monitors; apps get their own windows.
        let rail = cfg
            .remote_app
            .is_some()
            .then(|| Self::rail_prepare(&mut cfg, apps));
        // Chosen monitors: the session spans them, full screen.
        let chosen = if opts.monitors.is_empty() || rail.is_some() {
            Vec::new()
        } else {
            crate::monitors::chosen(&crate::monitors::list(), &opts.monitors)
        };
        if !opts.monitors.is_empty() && chosen.is_empty() && rail.is_none() {
            self.message(
                "The chosen monitors are not connected; using this window.",
                Tone::Warning,
            );
        }
        if rail.is_none() {
            cfg.monitors = chosen.iter().map(|m| m.monitor.clone()).collect();
        }
        let fit = fit && rail.is_none();
        // One window per chosen monitor, each showing its part of the desktop.
        let span: Vec<crate::span::SpanSpec> = match crate::monitors::bounds(&chosen) {
            None => Vec::new(),
            Some((bx, by, _, _)) => chosen
                .iter()
                .enumerate()
                .map(|(i, m)| crate::span::SpanSpec {
                    session: 0,
                    rect: (m.monitor.left, m.monitor.top, m.width(), m.height()),
                    fb: (m.monitor.left - bx, m.monitor.top - by),
                    first: i == 0,
                    title: name.clone(),
                })
                .collect(),
        };
        let fit = fit && span.is_empty();
        let id = self.next_id;
        self.next_id += 1;
        let (worker, controls) = self.spawn_worker(id, cfg.clone());
        if let Some(w) = &mut self.win {
            w.ui.open_tab(id, name, cfg.host.clone(), fit);
            if let Some(t) = w.ui.tab_mut(id) {
                t.live = ui::Live::for_config(&cfg);
            }
        }
        let sent_layout = cfg.keyboard.layout;
        let remote_app = rail.is_some();
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
                retries: 0,
                retry_pending: false,
                cert_reply: None,
                spanned: false,
                rail,
                keys: std::cell::RefCell::new(crate::keyboard::Keys::new(klid, sent_layout)),
                last_fb: None,
            },
        );
        if remote_app {
            self.rail_ended(id); // the tab's view, empty until the session is up
        }
        self.apply_options(id, &opts);
        if !span.is_empty() {
            if let Some(s) = self.sessions.get_mut(&id) {
                s.spanned = true;
            }
            if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                t.spanned = true;
            }
            for mut spec in span {
                spec.session = id;
                self.pending_spans.push(spec);
            }
        }
        self.dirty();
    }

    fn apply_options(&mut self, id: u64, opts: &SessionOptions) {
        let scale = opts.scale.unwrap_or_else(|| self.auto_scale());
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        let c = &s.controls;
        c.set_scale(scale);
        c.set_speaker(crate::audio::device_index(opts.speaker.as_deref()));
        c.set_microphone_device(crate::mic::device_index(opts.mic.as_deref()));
        let mut warn = Vec::new();
        let mut on = |r: Result<(), String>, what: &str| match r {
            Ok(()) => true,
            Err(e) => {
                warn.push(format!("{what}: {e}"));
                false
            }
        };
        let clipboard = opts.clipboard && on(c.set_clipboard(true), "Clipboard");
        let sound = opts.sound && on(c.set_sound(true), "Sound");
        let printers = opts.printers && on(c.set_printers(true), "Printers");
        let smart_cards = opts.smart_cards && on(c.set_smart_cards(true), "Smart cards");
        let microphone = opts.microphone && on(c.set_microphone(true), "Microphone");
        let mut drives = Vec::new();
        for path in &opts.drives {
            let name = drive_name(path);
            match c.add_drive(&name, path) {
                Ok(device_id) => drives.push(SharedDrive {
                    device_id,
                    name,
                    path: path.clone(),
                }),
                Err(e) => warn.push(e),
            }
        }
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.quality = opts.quality;
            t.quality_live = opts.quality;
            t.win_keys = opts.win_keys;
            t.keyboard = opts.keyboard;
            t.speaker = opts.speaker.clone();
            t.microphone = microphone;
            t.mic = opts.mic.clone();
            t.scale = opts.scale;
            t.clipboard = clipboard;
            t.sound = sound;
            t.printers = printers;
            t.smart_cards = smart_cards;
            t.drives = drives;
        }
        if !warn.is_empty() {
            self.message(warn.join(" · "), Tone::Warning);
        }
    }

    /// The tab's current settings, to carry them over a reconnect.
    fn tab_options(&self, id: u64) -> SessionOptions {
        let Some(t) = self
            .win
            .as_ref()
            .and_then(|w| w.ui.tabs.iter().find(|t| t.id == id))
        else {
            return SessionOptions::default();
        };
        SessionOptions {
            scale: t.scale,
            clipboard: t.clipboard,
            sound: t.sound,
            printers: t.printers,
            smart_cards: t.smart_cards,
            drives: t.drives.iter().map(|d| d.path.clone()).collect(),
            quality: t.quality,
            win_keys: t.win_keys,
            keyboard: t.keyboard,
            speaker: t.speaker.clone(),
            microphone: t.microphone,
            mic: t.mic.clone(),
            // A reconnect keeps the session's monitors in its config.
            monitors: Vec::new(),
        }
    }

    fn reconnect(&mut self, id: u64) {
        let Some(cfg) = self.sessions.get(&id).map(|s| s.cfg.clone()) else {
            return;
        };
        self.reconnect_with(id, cfg);
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.redirected_to = None;
        }
    }

    /// The server moved the running session to another server (MS-RDPBCGR
    /// 3.2.5.13): the tab connects the next hop with its current settings.
    /// The session's saved config stays the original one, so a later
    /// reconnect goes through the broker again.
    fn redirected(&mut self, id: u64, cfg: Config, to: String) {
        rdp::trace!("ui: session {id} redirected to {to}");
        self.ended(id, TabState::Connecting);
        self.reconnect_with(id, cfg);
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.redirected_to = Some(to.clone());
        }
        self.message(format!("Redirected to {to}; connecting…"), Tone::Muted);
    }

    fn reconnect_with(&mut self, id: u64, mut cfg: Config) {
        let opts = self.tab_options(id);
        cfg.scale = self.tab_scale(id);
        // A reconnect takes this PC's layout as it is now.
        let (klid, keyboard) = crate::keyboard::local();
        cfg.keyboard = keyboard;
        let keys = crate::keyboard::Keys::new(klid, cfg.keyboard.layout);
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
            s.keys = std::cell::RefCell::new(keys);
        }
        self.rail_reset(id);
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.state = TabState::Connecting;
            t.network = None; // measured again by the new connection
            t.live.restart();
        }
        // The new session gets the settings the tab had.
        self.apply_options(id, &opts);
        self.dirty();
    }

    fn send(&self, id: u64, events: Vec<InputEvent>) {
        if let Some(s) = self.sessions.get(&id) {
            s.keys.borrow_mut().observe(&events);
            if let Some(w) = s.worker.as_ref() {
                w.send(events);
            }
        }
    }

    /// A key for session `id`: a scancode, or the typed text as Unicode when
    /// the tab's Keyboard setting translates (RDP-32).
    fn session_key(&self, id: u64, ev: &winit::event::KeyEvent) {
        let mode = self
            .win
            .as_ref()
            .and_then(|m| m.ui.tabs.iter().find(|t| t.id == id))
            .map(|t| t.keyboard)
            .unwrap_or_default();
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        let input = crate::keyboard::KeyInput::of(ev);
        let events = s
            .keys
            .borrow_mut()
            .key(&input, mode, crate::keyboard::local_klid());
        self.send(id, events);
    }

    fn message(&mut self, text: impl Into<String>, tone: Tone) {
        if let Some(w) = &mut self.win {
            w.ui.set_message(text, tone);
        }
        self.dirty();
    }

    fn handle_action(&mut self, action: Action) {
        match action {
            Action::ExecApp(id, app) => self.rail_exec(id, app),
            Action::RailFocus(id, w) => self.rail_focus(id, w),
            Action::RailClose(id, w) => self.rail_close(id, w),
            Action::Connect {
                name,
                mut cfg,
                fit,
                opts,
                apps,
            } => {
                if fit && let Some(m) = &self.win {
                    let (w, h) = m.ui.session_size_for(m.size.0 as i32, m.size.1 as i32);
                    // Desktop widths must be even; sizes between 200 and 8192.
                    cfg.width = ((w.clamp(200, 8192) as u16) & !1).max(200);
                    cfg.height = h.clamp(200, 8192) as u16;
                }
                self.start_session(name, *cfg, fit, opts, apps);
            }
            Action::SetQuality(id, q) => {
                // Used by the next logon of this session.
                if let Some(s) = self.sessions.get_mut(&id) {
                    q.apply(&mut s.cfg);
                }
                self.dirty();
            }
            Action::SetFullscreen(on) => self.set_fullscreen(on),
            Action::CopyText(text) => {
                use rdp::ClipboardBackend;
                let mut cb = crate::clipboard::WindowsClipboard { owner: self.hwnd() };
                if !cb.write_text(&text) {
                    self.message("Could not copy to the clipboard.", Tone::Warning);
                }
                self.dirty();
            }
            Action::Browse(target) => {
                let proxy = std::sync::Mutex::new(self.proxy.clone());
                crate::picker::pick_folder(self.hwnd(), move |path| {
                    if let Ok(p) = proxy.lock() {
                        let _ = p.send_event(UserEvent::Picked(target, path));
                    }
                });
            }
            Action::SetMicrophone(id, on) => {
                let r = self
                    .sessions
                    .get(&id)
                    .map(|s| s.controls.set_microphone(on));
                if let Some(Err(e)) = r {
                    self.message(format!("Microphone: {e}"), Tone::Danger);
                }
                self.dirty();
            }
            Action::SetMic(id, name) => {
                if let Some(s) = self.sessions.get(&id) {
                    s.controls
                        .set_microphone_device(crate::mic::device_index(name.as_deref()));
                }
            }
            Action::SetSpeaker(id, name) => {
                if let Some(s) = self.sessions.get(&id) {
                    s.controls
                        .set_speaker(crate::audio::device_index(name.as_deref()));
                }
            }
            Action::CertAnswer(id, trust) => {
                if let Some(tx) = self.sessions.get_mut(&id).and_then(|s| s.cert_reply.take()) {
                    let _ = tx.send(trust);
                }
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.cert = None;
                }
                self.dirty();
            }
            Action::InstallUpdate => {
                let Some(c) = self.update.clone() else {
                    return;
                };
                if let Some(m) = &mut self.win {
                    m.ui.update_busy = true;
                }
                self.message(format!("Downloading rdpc {}…", c.version), Tone::Muted);
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let r = rdpc_update::download_verified(&c)
                        .and_then(|setup| rdpc_update::launch_setup(&setup, &c.version))
                        .map(|_| ())
                        .map_err(|e| e.to_string());
                    let _ = proxy.send_event(UserEvent::UpdateStarted(r));
                });
            }
            Action::Batch(actions) => {
                for a in actions {
                    self.handle_action(a);
                }
            }
            Action::Disconnect(id) => {
                if let Some(s) = self.sessions.get_mut(&id) {
                    if let Some(tx) = s.cert_reply.take() {
                        let _ = tx.send(false);
                    }
                    if s.retry_pending {
                        s.retry_pending = false;
                        s.last_fb = None;
                        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                            t.state = TabState::Ended("reconnect cancelled".into());
                            t.live.stopped();
                            t.live.ended = Some(crate::failure::EndReason::ReconnectCancelled);
                        }
                    }
                    if let Some(w) = s.worker.as_mut() {
                        w.close();
                    }
                }
            }
            Action::Reconnect(id) => {
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.retry_pending = false;
                    s.retries = 0;
                    s.cfg.auto_reconnect = None;
                }
                self.reconnect(id)
            }
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
            Action::SetSound(id, on) => {
                let r = self.sessions.get(&id).map(|s| s.controls.set_sound(on));
                self.toggle_result(id, r, on, "Sound", |t| t.sound = false);
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
                rdp::trace!("ui: Clipboard switched {}", if on { "on" } else { "off" });
                let r = self.sessions.get(&id).map(|s| s.controls.set_clipboard(on));
                if let Some(Err(e)) = r {
                    if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                        t.clipboard = false;
                    }
                    self.message(e, Tone::Warning);
                } else {
                    self.message(
                        if on {
                            "Clipboard shared."
                        } else {
                            "Clipboard no longer shared."
                        },
                        Tone::Muted,
                    );
                }
            }
            Action::SetScale(id, choice) => {
                let pct = self.tab_scale(id);
                rdp::trace!("ui: scale for session {id}: {choice:?} -> {pct} %");
                if let Some(s) = self.sessions.get(&id) {
                    s.controls.set_scale(pct);
                }
                self.message(format!("Remote desktop scale {pct} %."), Tone::Muted);
            }
            Action::SetFit(id, on) => {
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.fit_requested = None;
                }
                if !on {
                    self.message(
                        "Fit to window off: the desktop keeps its size.",
                        Tone::Muted,
                    );
                }
                self.dirty();
            }
            Action::AddDrive(id, path) => {
                let name = drive_name(&path);
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
                        self.message(format!("Sharing {name}."), Tone::Muted);
                    }
                    Some(Err(e)) => self.message(e, Tone::Warning),
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
                    self.message(format!("Stopped sharing {}.", d.name), Tone::Muted);
                }
            }
            Action::CtrlAltDel(id) => self.send(id, session::ctrl_alt_del()),
            Action::WinMinimize => {
                if let Some(m) = &self.win {
                    m.gfx.window.set_minimized(true);
                }
            }
            Action::WinClose => self.request_quit(),
            Action::Quit => self.quit = true,
            Action::ToggleRecording(id) => self.toggle_recording(id),
            Action::Unspan(id) => self.unspan(id),
            Action::Relayout => {
                if let Some(m) = &mut self.win {
                    m.shown.clear();
                }
                self.dirty();
            }
            Action::SetAutoLock(min) => {
                self.settings.auto_lock_minutes = min;
                let _ = self.settings.save();
                if let Some(m) = &mut self.win {
                    m.ui.auto_lock = min;
                }
                self.dirty();
            }
            Action::SetTheme(choice) => {
                self.settings.theme = choice;
                let _ = self.settings.save();
                if let Some(m) = &mut self.win {
                    m.ui.theme = choice;
                    m.gfx.window.set_theme(winit_theme(choice));
                    apply_theme(choice, &m.gfx.window);
                    m.shown.clear();
                }
                for s in &self.spans {
                    s.window.request_redraw();
                }
                self.dirty();
            }
            Action::SetUpdateChannel(ch) => {
                self.settings.update_channel = ch.clone();
                let _ = self.settings.save();
                if let Some(m) = &mut self.win {
                    m.ui.update_channel = ch;
                }
                self.dirty();
            }
            Action::CheckUpdatesNow => {
                if !rdpc_update::is_installed_copy() {
                    if let Some(m) = &mut self.win {
                        m.ui.settings_done(
                            false,
                            format!(
                                "This copy was not installed by the setup; new versions are on {}",
                                rdpc_update::RELEASE_PAGE
                            ),
                        );
                    }
                    return self.dirty();
                }
                let proxy = self.proxy.clone();
                let channel = self.settings.update_channel.clone();
                std::thread::spawn(move || {
                    let ev = match run_update_check(&channel) {
                        Ok(Some(c)) => UserEvent::UpdateAvailable(c),
                        Ok(None) => UserEvent::UpToDate(Ok(())),
                        Err(e) => UserEvent::UpToDate(Err(e)),
                    };
                    let _ = proxy.send_event(ev);
                });
                if let Some(m) = &mut self.win {
                    m.ui.settings_note = Some(("Checking for updates…".into(), Tone::Muted));
                }
                self.dirty();
            }
            Action::SetDiagnosticLog(on) => {
                self.settings.diagnostic_log = on;
                let _ = self.settings.save();
                crate::settings::apply_logging(on);
                if let Some(m) = &mut self.win {
                    m.ui.diagnostic_log = on;
                }
                if on {
                    self.message(
                        "Diagnostic log on: connect, then send rdpc.log.",
                        Tone::Muted,
                    );
                }
                self.dirty();
            }
            Action::OpenLogFolder => {
                if let Some(dir) =
                    crate::settings::log_path().and_then(|p| p.parent().map(|d| d.to_path_buf()))
                {
                    let _ = std::fs::create_dir_all(&dir);
                    // Explorer shows the folder and exits on its own.
                    let _ = std::process::Command::new("explorer").arg(&dir).spawn();
                }
            }
            Action::SetCheckUpdates(on) => {
                self.settings.check_updates = on;
                let _ = self.settings.save();
                if let Some(m) = &mut self.win {
                    m.ui.check_updates = on;
                }
                self.dirty();
            }
            Action::SetRemember(on) => {
                if let Some(m) = &mut self.win {
                    let path = m.ui.store_mut().remembered_key_path();
                    let blob =
                        m.ui.store_mut()
                            .vault_key()
                            .and_then(crate::vault::protect_key);
                    let r = match (on, path) {
                        (true, Some(p)) => blob
                            .ok_or("Windows could not protect the key".to_string())
                            .and_then(|b| std::fs::write(&p, b).map_err(|e| e.to_string())),
                        (false, Some(p)) => match std::fs::remove_file(&p) {
                            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                                Err(e.to_string())
                            }
                            _ => Ok(()),
                        },
                        _ => Err("no vault".into()),
                    };
                    match r {
                        Ok(()) => m.ui.remembered = on,
                        Err(e) => m.ui.settings_done(false, e),
                    }
                }
                self.dirty();
            }
            Action::ChangeMaster { current, new } => {
                let Some(m) = &mut self.win else { return };
                let store = m.ui.store_mut();
                let (Some(old), Some(bytes)) = (store.vault_key().cloned(), store.vault_bytes())
                else {
                    return;
                };
                let proxy = self.proxy.clone();
                // Two Argon2id runs: never on the UI thread.
                std::thread::spawn(move || {
                    let r = crate::vault::read_params(&bytes)
                        .and_then(|p| crate::vault::derive(&current, p))
                        .and_then(|k| {
                            if *k.key == *old.key {
                                Ok(())
                            } else {
                                Err("The current master password is wrong.".to_string())
                            }
                        })
                        .and_then(|()| {
                            crate::vault::derive(&new, crate::vault::KdfParams::fresh())
                        });
                    let _ = proxy.send_event(UserEvent::Vault(VaultResult::Rekeyed(r)));
                });
            }
            Action::Export => {
                let proxy = std::sync::Mutex::new(self.proxy.clone());
                crate::picker::pick_with(
                    crate::picker::Pick::SaveBackup,
                    self.hwnd(),
                    move |path| {
                        if let (Some(path), Ok(p)) = (path, proxy.lock()) {
                            let _ = p.send_event(UserEvent::ExportTo(path));
                        }
                    },
                );
            }
            Action::PickImport => {
                let proxy = std::sync::Mutex::new(self.proxy.clone());
                crate::picker::pick_with(
                    crate::picker::Pick::OpenBackup,
                    self.hwnd(),
                    move |path| {
                        if let (Some(path), Ok(p)) = (path, proxy.lock()) {
                            let _ = p.send_event(UserEvent::ImportFrom(path));
                        }
                    },
                );
            }
            Action::Import { path, password } => {
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let r = std::fs::read(&path)
                        .map_err(|e| format!("Cannot read {}: {e}", path.display()))
                        .and_then(|bytes| {
                            let key = crate::vault::read_params(&bytes)
                                .and_then(|p| crate::vault::derive(&password, p))?;
                            crate::store::read_backup(&bytes, &key)
                        });
                    let _ = proxy.send_event(UserEvent::Vault(VaultResult::Imported(r)));
                });
            }
            Action::Unlock { master, remember } => {
                let params = self
                    .win
                    .as_mut()
                    .and_then(|m| m.ui.store_mut().vault_bytes())
                    .ok_or_else(|| "The vault file cannot be read.".to_string())
                    .and_then(|b| crate::vault::read_params(&b));
                let proxy = self.proxy.clone();
                // Argon2id takes about half a second: never on the UI thread.
                std::thread::spawn(move || {
                    let r = params.and_then(|p| crate::vault::derive(&master, p));
                    let _ = proxy.send_event(UserEvent::Vault(VaultResult::Unlocked(r, remember)));
                });
            }
            Action::CreateVault { master } => {
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let r = crate::vault::derive(&master, crate::vault::KdfParams::fresh());
                    let _ = proxy.send_event(UserEvent::Vault(VaultResult::Created(r)));
                });
            }
            Action::Lock => {
                if let Some(m) = &mut self.win {
                    m.ui.store_mut().lock();
                    m.ui.vault_locked();
                }
                self.dirty();
            }
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
        m.ui.paint_window(
            &mut Canvas::new(&mut m.scratch, w, h),
            &mut self.te,
            &self.fonts,
        );
        // The Home view just showed (or changed layout): pictures of the
        // sessions that ran meanwhile, then paint them.
        let need = m.ui.thumbs_needed();
        if !need.is_empty() {
            make_thumbs(&mut m.ui, &self.sessions, &need);
            m.ui.paint_window(
                &mut Canvas::new(&mut m.scratch, w, h),
                &mut self.te,
                &self.fonts,
            );
        }
        if let Some((id, area)) = m.ui.session_area
            && m.ui.session_backdrop()
            && let Some(fb) = self.sessions.get(&id).and_then(|s| s.last_fb.as_ref())
        {
            // Reconnecting: the last picture, dimmed by the overlay.
            blit(fb, &mut m.scratch, w, area, area, None);
        } else if let Some((id, area)) = m.ui.session_area
            && let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref())
        {
            let mut sh = worker.shared.lock().unwrap();
            worker.notified.store(false, Ordering::Release);
            let clip = m.ui.session_clip.unwrap_or(area);
            blit(&sh.fb, &mut m.scratch, w, area, clip, None);
            sh.damage.clear();
            sh.full = false;
        }
        // The toolbar and the reconnect card float over the picture; the
        // palette and the quit question go over that (dimming it), and
        // while they are up the session takes no updates.
        m.ui.paint_overlays(
            &mut Canvas::new(&mut m.scratch, w, h),
            &mut self.te,
            &self.fonts,
        );
        let _ = m.ui.take_overlay_damage();
        let Ok(mut buf) = m.gfx.surface.buffer_mut() else {
            return;
        };
        let settling = m.settle.is_some_and(|t| std::time::Instant::now() < t);
        let full = buf.age() == 0 || m.shown.len() != m.scratch.len() || settling;
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

    /// Repaints only what the session toolbar changed (shown, hidden,
    /// hovered): the picture under it, then the toolbar, one present.
    fn render_overlay(&mut self) {
        let Some(m) = &mut self.win else { return };
        let Some(r) = m.ui.take_overlay_damage() else {
            return;
        };
        if m.chrome_dirty {
            return; // a full repaint is coming anyway
        }
        let (w, h) = m.size;
        let area = m.ui.session_area.map(|(_, a)| a);
        let worker =
            m.ui.session_area
                .and_then(|(id, _)| self.sessions.get(&id))
                .and_then(|s| s.worker.as_ref());
        let (Some(area), Some(worker), true) = (area, worker, m.shown.len() == w * h) else {
            // No live picture under it (RemoteApp, spanned): repaint it all.
            return self.dirty();
        };
        let r = r.intersect(area);
        if r.is_empty() {
            return;
        }
        {
            let mut cv = Canvas::new(&mut m.shown, w, h);
            cv.fill(r, crate::theme::pal().bg_sidebar);
            let sh = worker.shared.lock().unwrap();
            blit(&sh.fb, &mut m.shown, w, area, r, None);
        }
        let mut cv = Canvas::new(&mut m.shown, w, h);
        cv.set_clip(r);
        m.ui.paint_overlays(&mut cv, &mut self.te, &self.fonts);
        let Ok(mut buf) = m.gfx.surface.buffer_mut() else {
            return;
        };
        let rects: Vec<softbuffer::Rect> =
            to_sb(r.x as usize, r.y as usize, r.w as usize, r.h as usize)
                .into_iter()
                .collect();
        if buf.age() == 0 {
            buf.copy_from_slice(&m.shown);
        } else {
            for y in r.y as usize..r.bottom() as usize {
                let o = y * w + r.x as usize;
                buf[o..o + r.w as usize].copy_from_slice(&m.shown[o..o + r.w as usize]);
            }
        }
        if let Err(e) = buf.present_with_damage(&rects) {
            eprintln!("rdpc: present failed: {e}");
        }
    }

    /// Copies only the active session's damaged rectangles to the screen.
    fn render_session_damage(&mut self) {
        let Some(m) = &mut self.win else { return };
        let Some((id, area)) = m.ui.session_area else {
            return;
        };
        if m.ui.session_backdrop() {
            return; // the dimmed last picture does not change
        }
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
        let clip = m.ui.session_clip.unwrap_or(area);
        let mut rects = Vec::new();
        for d in &damage {
            if let Some(r) = blit(&sh.fb, &mut m.shown, w, area, clip, Some(*d)) {
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
        // The toolbar floats over the picture: paint it again where the
        // update touched it (only there).
        if let Some(over) = m.ui.overlay_rect() {
            for r in &rects {
                let (x, y) = (r.x as i32, r.y as i32);
                let d =
                    Rect::new(x, y, r.width.get() as i32, r.height.get() as i32).intersect(over);
                if !d.is_empty() {
                    let mut cv = Canvas::new(&mut m.shown, w, h);
                    cv.set_clip(d);
                    m.ui.paint_session_overlay(&mut cv, &mut self.te, &self.fonts);
                }
            }
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
                NamedKey::PageUp => Key::PageUp,
                NamedKey::PageDown => Key::PageDown,
                NamedKey::Space if !ctrl => Key::Char(' '),
                _ => return None,
            },
            WKey::Character(s) if ctrl => match s.to_lowercase().as_str() {
                "a" => Key::SelectAll,
                "v" => Key::Paste(crate::clipboard::read_text()?),
                "n" => Key::New,
                "f" => Key::Find,
                "s" => Key::Save,
                // The command palette (and the editor-style alias).
                "k" => Key::Palette,
                "p" if self.mods.shift_key() => Key::Palette,
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
        // Ctrl+Shift+U installs an offered update (as in the other apps).
        let session_has_keys = self.win.as_ref().is_some_and(|m| m.ui.session_focus);
        if !session_has_keys
            && ev.state.is_pressed()
            && self.mods.control_key()
            && self.mods.shift_key()
            && matches!(&ev.logical_key, WKey::Character(c) if c.eq_ignore_ascii_case("u"))
            && self.update.is_some()
        {
            return self.handle_action(Action::InstallUpdate);
        }
        // Ctrl+Alt+Break switches full screen (as in mstsc), also from inside a session.
        if ev.state.is_pressed()
            && self.mods.control_key()
            && self.mods.alt_key()
            && matches!(
                ev.logical_key,
                WKey::Named(NamedKey::Pause | NamedKey::Cancel)
            )
        {
            let on = self.win.as_ref().is_some_and(|m| m.ui.fullscreen);
            return self.set_fullscreen(!on);
        }
        let Some(m) = &mut self.win else { return };
        let session = if m.ui.session_focus {
            m.ui.session_area.map(|(id, _)| id)
        } else {
            None
        };
        if let Some(id) = session {
            // Alt (the host key) shows the toolbar while it is held; the
            // key still goes to the session.
            if matches!(ev.logical_key, WKey::Named(NamedKey::Alt)) {
                m.ui.alt_key(ev.state.is_pressed());
                self.render_overlay();
            }
            let Some(m) = &mut self.win else { return };
            let release = ev.state.is_pressed()
                && self.mods.control_key()
                && self.mods.alt_key()
                && matches!(ev.logical_key, WKey::Named(NamedKey::Home));
            if release {
                m.ui.session_focus = false;
                self.send(id, session::release_modifiers());
                self.dirty();
            } else if palette_chord(&ev, self.mods) {
                // Ctrl+Alt+K: the command palette over the session, which
                // gets the keyboard back when it closes.
                m.ui.open_palette(Some(id));
                self.send(id, session::release_modifiers());
                self.dirty();
            } else {
                // Scancodes, or Unicode by the tab's Keyboard setting and for
                // keys without one (touch keyboard, emoji panel).
                self.session_key(id, &ev);
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
    /// This PC's display scaling for the window, in percent.
    fn auto_scale(&self) -> u32 {
        self.win
            .as_ref()
            .map_or(100, |m| {
                (m.gfx.window.scale_factor() * 100.0).round() as u32
            })
            .clamp(100, 500)
    }

    /// The scale a tab should use: its own choice, or Auto.
    fn tab_scale(&self, id: u64) -> u32 {
        let own = self
            .win
            .as_ref()
            .and_then(|w| w.ui.tabs.iter().find(|t| t.id == id))
            .and_then(|t| t.scale);
        own.unwrap_or_else(|| self.auto_scale())
    }

    fn toggle_result(
        &mut self,
        id: u64,
        r: Option<Result<(), String>>,
        on: bool,
        what: &str,
        reset: impl FnOnce(&mut ui::Tab),
    ) {
        rdp::trace!("ui: {what} switched {}", if on { "on" } else { "off" });
        match r {
            Some(Err(e)) => {
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    reset(t);
                }
                self.message(e, Tone::Warning);
            }
            Some(Ok(())) => {
                let text = if on {
                    format!("{what} shared.")
                } else {
                    format!("{what} no longer shared.")
                };
                self.message(text, Tone::Muted);
            }
            None => {}
        }
    }

    fn vault_result(&mut self, r: VaultResult) {
        let Some(m) = &mut self.win else { return };
        let ui = &mut m.ui;
        match r {
            VaultResult::Unlocked(Ok(key), remember) => {
                let remembered = remember.then(|| crate::vault::protect_key(&key)).flatten();
                match ui.store_mut().unlock(key) {
                    Ok(()) => {
                        if let (Some(blob), Some(path)) =
                            (remembered, ui.store_mut().remembered_key_path())
                            && let Err(e) = std::fs::write(&path, blob)
                        {
                            ui.set_message(
                                format!("Could not remember the key: {e}"),
                                Tone::Warning,
                            );
                        }
                        ui.vault_opened();
                    }
                    Err(e) => ui.vault_failed(e),
                }
            }
            VaultResult::Created(Ok(key)) => match ui.store_mut().create_vault(key) {
                Ok(()) => ui.vault_opened(),
                Err(e) => ui.vault_failed(e),
            },
            VaultResult::Unlocked(Err(e), _) | VaultResult::Created(Err(e)) => ui.vault_failed(e),
            VaultResult::Rekeyed(Ok(key)) => {
                let remember = ui.store_mut().remembered_key_path().filter(|p| p.exists());
                match ui.store_mut().rekey(key) {
                    Ok(()) => {
                        // A remembered key must follow the new password.
                        if let (Some(path), Some(blob)) = (
                            remember,
                            ui.store_mut()
                                .vault_key()
                                .and_then(crate::vault::protect_key),
                        ) {
                            let _ = std::fs::write(path, blob);
                        }
                        ui.settings_done(true, "Master password changed.".into());
                    }
                    Err(e) => ui.settings_done(false, e),
                }
            }
            VaultResult::Rekeyed(Err(e)) => ui.settings_done(false, e),
            VaultResult::Imported(Ok((groups, connections))) => {
                let added = ui.store_mut().merge(groups, connections);
                match ui.store_mut().save() {
                    Ok(()) => ui.settings_done(
                        true,
                        format!(
                            "Imported {added} connection{}.",
                            if added == 1 { "" } else { "s" }
                        ),
                    ),
                    Err(e) => ui.settings_done(false, e),
                }
                ui.refresh_selection();
            }
            VaultResult::Imported(Err(e)) => ui.settings_done(false, e),
        }
    }

    /// The worker finished: join it and show why in the tab.
    /// The network dropped a session: reconnect after a short wait, with the
    /// server's auto-reconnect cookie, a few times before giving up.
    fn dropped(&mut self, id: u64, why: String, cookie: Option<rdp::AutoReconnectCookie>) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let attempt = s.retries;
        let Some(&delay) = RETRY_DELAYS_S.get(attempt) else {
            return self.failed(
                id,
                format!(
                    "{why} (gave up after {} reconnect attempts)",
                    RETRY_DELAYS_S.len()
                ),
                crate::failure::Failure {
                    cause: crate::failure::Cause::ConnectionLost,
                    step: None,
                },
            );
        };
        s.retries += 1;
        s.retry_pending = true;
        if cookie.is_some() {
            s.cfg.auto_reconnect = cookie;
        }
        // Keep the last picture to show (dimmed) while reconnecting; a
        // failed attempt has none, so the first one's stays.
        if let Some(w) = &s.worker
            && let Ok(sh) = w.shared.lock()
            && sh.fb.width > 0
        {
            let mut fb = rdp::Framebuffer::new(sh.fb.width, sh.fb.height);
            fb.pixels.copy_from_slice(&sh.fb.pixels);
            s.last_fb = Some(fb);
        }
        let has_frame = s.last_fb.is_some();
        rdp::trace!(
            "ui: session {id} dropped ({why}); reconnect {}/{} in {delay} s",
            attempt + 1,
            RETRY_DELAYS_S.len()
        );
        self.ended(id, TabState::Connecting);
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.live.restart();
            t.live.reconnect = Some((attempt + 1, RETRY_DELAYS_S.len()));
            t.live.has_frame = has_frame;
        }
        self.message(
            format!(
                "Connection lost ({why}). Reconnecting in {delay} s, attempt {}/{}…",
                attempt + 1,
                RETRY_DELAYS_S.len()
            ),
            Tone::Warning,
        );
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(delay));
            let _ = proxy.send_event(UserEvent::Retry(id));
        });
    }

    /// The session failed: why, in technical and plain terms.
    fn failed(&mut self, id: u64, why: String, failure: crate::failure::Failure) {
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.live.stopped();
            t.live.failure = Some(failure);
        }
        if let Some(s) = self.sessions.get_mut(&id) {
            s.last_fb = None;
        }
        self.ended(id, TabState::Failed(why));
    }

    fn ended(&mut self, id: u64, state: TabState) {
        // Its monitor windows close; the tab tells what happened.
        if self.spans.iter().any(|s| s.session == id) {
            self.spans.retain(|s| s.session != id);
            if let Some(s) = self.sessions.get_mut(&id) {
                s.spanned = false;
            }
            if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                t.spanned = false;
            }
        }
        self.rail_ended(id);
        // The worker's recorder finishes its file when the worker goes.
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.recording = false;
        }
        if let Some(s) = self.sessions.get_mut(&id)
            && let Some(mut w) = s.worker.take()
            && let Some(t) = w.thread.take()
        {
            let _ = t.join();
        }
        if let Some(m) = &mut self.win
            && state != TabState::Connecting
        {
            // Its saved connection keeps when and how long it ran.
            m.ui.session_ended(id);
        }
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.state = state;
        }
        self.dirty();
    }

    /// A session reported damage: refresh its Home thumbnail now, or once
    /// after the throttle, or not at all while Home is hidden.
    fn thumb_frame(&mut self, id: u64) {
        let Some(m) = &mut self.win else { return };
        if self.sessions.get(&id).is_some_and(|s| s.rail.is_some()) {
            return;
        }
        match m.ui.thumb_due(id) {
            ui::ThumbDue::No => {}
            ui::ThumbDue::Now => {
                self.make_thumb(id);
                self.dirty();
            }
            ui::ThumbDue::After(wait) => {
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(wait);
                    let _ = proxy.send_event(UserEvent::Thumb(id));
                });
            }
        }
    }

    fn make_thumb(&mut self, id: u64) {
        let Some(m) = &mut self.win else { return };
        make_thumbs(&mut m.ui, &self.sessions, &[id]);
    }

    /// Shows the remote cursor while the pointer is over a session picture,
    /// otherwise the app's own (I-beam over fields, arrow elsewhere).
    fn apply_cursor(&mut self) {
        let Some(m) = &self.win else { return };
        let (x, y) = m.cursor;
        let want = match m.ui.session_area {
            Some((id, area))
                if area.contains(x, y) && !m.ui.over_overlay(x, y) && !m.ui.session_backdrop() =>
            {
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
        // The toolbar over the picture takes its own clicks.
        if m.ui.session_backdrop() || m.pressed_in != Some(id) && m.ui.over_overlay(x, y) {
            return None;
        }
        let s = self.sessions.get(&id)?;
        let fb = s
            .worker
            .as_ref()?
            .shared
            .lock()
            .ok()
            .map(|sh| (sh.fb.width, sh.fb.height))?;
        let visible = m.ui.session_clip.unwrap_or(area);
        let in_area = visible.contains(x, y) || m.pressed_in == Some(id);
        if !in_area || fb.0 == 0 {
            return None;
        }
        let fx = (x - area.x).clamp(0, fb.0 as i32 - 1) as u16;
        let fy = (y - area.y).clamp(0, fb.1 as i32 - 1) as u16;
        Some((id, fx, fy))
    }
}

/// Makes the Home thumbnails of these sessions from their framebuffers.
fn make_thumbs(ui: &mut Ui, sessions: &HashMap<u64, Session>, ids: &[u64]) {
    let Some((tw, th)) = ui.thumb_target() else {
        return;
    };
    for &id in ids {
        let Some(worker) = sessions.get(&id).and_then(|s| s.worker.as_ref()) else {
            continue;
        };
        let pic = {
            let sh = worker.shared.lock().unwrap();
            crate::thumb::of_framebuffer(&sh.fb, tw, th)
        };
        ui.set_thumb(id, pic);
    }
}

/// Copies the session framebuffer (or one damaged rectangle of it) into the
/// window frame at `area`, clipped. Returns the window rectangle written.
/// Copies the session picture (all of it, or one damaged rectangle) into
/// `frame` at `area`, drawing only inside `clip` (chrome may cover part of it).
fn blit(
    fb: &rdp::Framebuffer,
    frame: &mut [u32],
    frame_w: usize,
    area: Rect,
    clip: Rect,
    only: Option<rdp::Damage>,
) -> Option<Rect> {
    let (sx, sy, sw, sh) = match only {
        Some(d) => (d.x as i32, d.y as i32, d.w as i32, d.h as i32),
        None => (0, 0, fb.width as i32, fb.height as i32),
    };
    let dst = Rect::new(area.x + sx, area.y + sy, sw, sh)
        .intersect(area)
        .intersect(clip);
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
    /// After a resize or move settles, present the whole window once more.
    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        for spec in std::mem::take(&mut self.pending_spans) {
            self.open_span(el, spec);
        }
        self.sync_touch();
        // Idle auto-lock of the vault.
        let lock_at = self.auto_lock_deadline();
        if lock_at.is_some_and(|t| std::time::Instant::now() >= t) {
            if let Some(m) = &mut self.win {
                m.ui.store_mut().lock();
                m.ui.vault_locked();
                m.ui.set_message("Locked after being idle.", Tone::Muted);
            }
            self.dirty();
        }
        // RemoteApp sessions whose apps all closed end after a while.
        let rail_at = self.rail_timers();
        let lock_at = [self.auto_lock_deadline(), rail_at]
            .into_iter()
            .flatten()
            .min();
        let wait = |t: Option<std::time::Instant>| match t {
            Some(t) => ControlFlow::WaitUntil(t),
            None => ControlFlow::Wait,
        };
        let settle = self.win.as_ref().and_then(|m| m.settle);
        let Some(t) = settle else {
            el.set_control_flow(wait(lock_at));
            return;
        };
        if std::time::Instant::now() >= t {
            if let Some(m) = &mut self.win {
                m.settle = None;
                m.shown.clear();
            }
            self.dirty();
            el.set_control_flow(wait(lock_at));
        } else {
            el.set_control_flow(wait(Some(lock_at.map_or(t, |l| l.min(t)))));
        }
    }

    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.win.is_none() {
            let attrs = Window::default_attributes()
                .with_title("rdpc")
                .with_inner_size(LogicalSize::new(1320.0, 860.0))
                .with_min_inner_size(LogicalSize::new(900.0, 560.0))
                .with_window_icon(crate::icon::window_icon(64))
                .with_theme(winit_theme(self.settings.theme));
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
                    // Before reading the size: removing the caption grows the client area.
                    let framed = self.install_frame(&gfx);
                    let proxy = std::sync::Mutex::new(self.proxy.clone());
                    crate::keyhook::install(move |scancode, extended, down| {
                        if let Ok(p) = proxy.lock() {
                            let _ = p.send_event(UserEvent::HookKey(scancode, extended, down));
                        }
                    });
                    let scale = gfx.window.scale_factor() as f32;
                    let sz = gfx.window.inner_size();
                    if let (Some(w), Some(h)) =
                        (NonZeroU32::new(sz.width), NonZeroU32::new(sz.height))
                    {
                        let _ = gfx.surface.resize(w, h);
                    }
                    apply_theme(self.settings.theme, &gfx.window);
                    gfx.window.request_redraw();
                    self.win = Some(MainWin {
                        gfx,
                        ui: {
                            let mut ui = Ui::new(Store::load(), scale);
                            remembered_unlock(&mut ui);
                            ui.speakers = crate::audio::output_devices();
                            ui.mics = crate::mic::input_devices();
                            ui.local_monitors = crate::monitors::list();
                            // Loads the folder picker's shell components early.
                            crate::picker::prewarm();
                            std::thread::spawn(|| {
                                clean_clipboard_files(&std::env::temp_dir().join("rdpc-clip"))
                            });
                            ui.auto_lock = self.settings.auto_lock_minutes;
                            ui.check_updates = self.settings.check_updates;
                            ui.diagnostic_log = rdp::log::verbose();
                            ui.remembered = remembered_exists(&mut ui);
                            ui.update_channel = self.settings.update_channel.clone();
                            ui.theme = self.settings.theme;
                            if self.settings.check_updates {
                                check_for_update(
                                    self.proxy.clone(),
                                    self.settings.update_channel.clone(),
                                );
                            }
                            ui.custom_frame = framed;
                            ui
                        },
                        shown: Vec::new(),
                        scratch: Vec::new(),
                        size: (sz.width as usize, sz.height as usize),
                        cursor: (-1, -1),
                        shown_cursor: Shown::Icon(CursorIcon::Default),
                        chrome_dirty: true,
                        settle: None,
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
            self.start_session(name, cfg, false, SessionOptions::default(), Vec::new());
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: UserEvent) {
        let (id, ev) = match event {
            UserEvent::Session(id, ev) => (id, ev),
            UserEvent::Thumb(id) => {
                if self.win.as_mut().is_some_and(|m| m.ui.thumb_tick(id)) {
                    self.make_thumb(id);
                    self.dirty();
                }
                return;
            }
            UserEvent::Vault(r) => {
                self.vault_result(r);
                return self.dirty();
            }
            UserEvent::UpdateAvailable(c) => {
                rdp::trace!("ui: update {} available", c.version);
                if let Some(m) = &mut self.win {
                    m.ui.update = Some(c.version.to_string());
                    m.ui.settings_note = Some((
                        format!(
                            "rdpc {} is available: Ctrl+Shift+U or Update in the status bar.",
                            c.version
                        ),
                        Tone::Success,
                    ));
                }
                self.update = Some(c);
                return self.dirty();
            }
            UserEvent::UpToDate(r) => {
                if let Some(m) = &mut self.win {
                    match r {
                        Ok(()) => m.ui.settings_done(
                            true,
                            format!("rdpc {} is the newest version.", env!("CARGO_PKG_VERSION")),
                        ),
                        Err(e) => {
                            m.ui.settings_done(false, format!("Update check failed: {e}"))
                        }
                    }
                }
                return self.dirty();
            }
            UserEvent::UpdateStarted(Ok(())) => {
                // The setup waits for rdpc to exit, installs and starts it again.
                return self.close_all(el);
            }
            UserEvent::UpdateStarted(Err(e)) => {
                if let Some(m) = &mut self.win {
                    m.ui.update_busy = false;
                }
                return self.message(format!("Update failed: {e}"), Tone::Danger);
            }
            UserEvent::HookKey(scancode, extended, down) => {
                let main = self
                    .win
                    .as_ref()
                    .filter(|m| m.ui.session_focus)
                    .and_then(|m| m.ui.session_area.map(|(id, _)| id));
                if let Some(id) = self.app_focus.or(main) {
                    self.send(
                        id,
                        vec![InputEvent::Key {
                            scancode,
                            extended,
                            down,
                        }],
                    );
                }
                return;
            }
            UserEvent::Picked(target, Some(path)) => {
                let path = path.to_string_lossy().into_owned();
                match target {
                    Some(id) => self.handle_action(Action::AddDrive(id, path)),
                    None => {
                        if let Some(m) = &mut self.win {
                            m.ui.form_add_folder(path);
                        }
                    }
                }
                return self.dirty();
            }
            UserEvent::Picked(_, None) => return,
            UserEvent::Recorded(r) => {
                match r {
                    Ok(info) => {
                        let secs = info.duration.as_secs();
                        self.message(
                            format!(
                                "Recording saved: {} ({}:{:02}, {:.1} MB).",
                                info.path.display(),
                                secs / 60,
                                secs % 60,
                                info.bytes as f64 / 1e6
                            ),
                            Tone::Success,
                        );
                    }
                    Err(e) => self.message(format!("Recording failed: {e}"), Tone::Danger),
                }
                return;
            }
            UserEvent::ExportTo(path) => {
                if let Some(m) = &mut self.win {
                    let r =
                        m.ui.store_mut()
                            .export_backup()
                            .and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string()));
                    match r {
                        Ok(()) => {
                            m.ui.settings_done(true, format!("Exported to {}.", path.display()))
                        }
                        Err(e) => m.ui.settings_done(false, e),
                    }
                }
                return self.dirty();
            }
            UserEvent::ImportFrom(path) => {
                if let Some(m) = &mut self.win {
                    m.ui.import_file = Some(path);
                    m.ui.settings_note = None;
                    m.ui.focus_import();
                }
                return self.dirty();
            }
            UserEvent::Certificate(id, prompt, reply) => {
                match self.sessions.get_mut(&id) {
                    Some(s) => s.cert_reply = Some(reply),
                    None => {
                        let _ = reply.send(false);
                        return;
                    }
                }
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.cert = Some(prompt);
                }
                return self.dirty();
            }
            UserEvent::Retry(id) => {
                if let Some(s) = self.sessions.get_mut(&id)
                    && std::mem::take(&mut s.retry_pending)
                {
                    self.reconnect(id);
                }
                return;
            }
            UserEvent::Frame => {
                if let Some(m) = &mut self.win {
                    #[cfg(windows)]
                    {
                        m.ui.max_state = crate::frame::max_button_state();
                    }
                    m.ui.maximized = m.gfx.window.is_maximized();
                }
                return self.dirty();
            }
        };
        let active = self.win.as_ref().and_then(|w| w.ui.active) == Some(id);
        if matches!(ev, session::Event::Frame) {
            self.thumb_frame(id);
        }
        match ev {
            session::Event::Progress(step) => {
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.live.progress(step);
                }
                if active {
                    self.dirty();
                }
            }
            session::Event::Connected(info) => {
                let mut layout = None;
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.retries = 0;
                    s.last_fb = None;
                    let keys = s.keys.get_mut();
                    keys.connected(info.unicode_input());
                    layout = Some(keys.sent_layout);
                }
                if let Some(m) = &mut self.win {
                    m.ui.session_started(id);
                }
                let mut host = self
                    .sessions
                    .get(&id)
                    .map_or(String::new(), |s| s.cfg.host.clone());
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.state = TabState::Connected {
                        width: info.width,
                        height: info.height,
                        bpp: info.bpp,
                    };
                    t.keyboard_layout = layout;
                    t.live.connected();
                    // After a redirection the session runs on the target.
                    if let Some(to) = &t.redirected_to {
                        host = to.clone();
                    }
                }
                self.message(
                    format!("Connected: {host} ({}×{}).", info.width, info.height),
                    Tone::Muted,
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
                self.apply_span_cursor(id);
                self.apply_rail_cursor(id);
            }
            session::Event::RailReady(handle) => self.rail_ready(id, handle),
            session::Event::Rail(events) => self.rail_events(el, id, events),
            session::Event::Frame if self.sessions.get(&id).is_some_and(|s| s.rail.is_some()) => {
                self.render_rail(id);
            }
            session::Event::Frame if self.sessions.get(&id).is_some_and(|s| s.spanned) => {
                self.render_spans(id);
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
            session::Event::Closed { why, error_info } => {
                use crate::failure::{EndReason, Outcome};
                let (why, outcome) = if why == "disconnected" {
                    (
                        "disconnected by you".into(),
                        Outcome::Ended(EndReason::ByYou),
                    )
                } else {
                    (why, crate::failure::closed(error_info))
                };
                match outcome {
                    Outcome::Failed(cause) => {
                        let failure = crate::failure::Failure { cause, step: None };
                        self.failed(id, why, failure)
                    }
                    Outcome::Ended(reason) => {
                        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                            t.live.stopped();
                            t.live.ended = Some(reason);
                        }
                        self.ended(id, TabState::Ended(why));
                    }
                }
            }
            // A reconnect attempt that cannot reach the server yet: the
            // automatic retries go on.
            session::Event::Failed { why, failure }
                if failure.cause.is_network()
                    && self.sessions.get(&id).is_some_and(|s| s.retries > 0) =>
            {
                self.dropped(id, why, None)
            }
            session::Event::Failed { why, failure } => self.failed(id, why, failure),
            session::Event::Dropped { why, cookie } => self.dropped(id, why, cookie),
            session::Event::Redirected { cfg, to } => self.redirected(id, *cfg, to),
            session::Event::Network(n) => {
                if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                    t.network = n.summary();
                }
                self.dirty();
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, wid: WindowId, event: WindowEvent) {
        self.window_event_inner(el, wid, event);
        if std::mem::take(&mut self.quit) {
            self.close_all(el);
        }
    }
}

impl App {
    /// Disconnects every session and ends the event loop.
    fn close_all(&mut self, el: &ActiveEventLoop) {
        for s in self.sessions.values_mut() {
            if let Some(w) = s.worker.as_mut() {
                w.close();
            }
        }
        el.exit();
    }

    /// Makes the tab strip the title row (Windows 11 look). False when the
    /// hook is not available; the system caption then stays.
    fn install_frame(&self, gfx: &Gfx) -> bool {
        #[cfg(windows)]
        {
            use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
            let hwnd = match gfx.window.window_handle().map(|h| h.as_raw()) {
                Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
                _ => return false,
            };
            let proxy = std::sync::Mutex::new(self.proxy.clone());
            crate::frame::install(hwnd, move || {
                if let Ok(p) = proxy.lock() {
                    let _ = p.send_event(UserEvent::Frame);
                }
            })
        }
        #[cfg(not(windows))]
        {
            let _ = gfx;
            false
        }
    }

    /// Tells the frame hook where the title row's controls are (on change).
    fn send_caption(&mut self) {
        let Some(m) = &self.win else { return };
        if !m.ui.custom_frame {
            return;
        }
        let geo = m.ui.title_geometry();
        if self.caption_sent.as_ref() == Some(&geo) {
            return;
        }
        #[cfg(windows)]
        crate::frame::set_caption(crate::frame::Caption {
            height: geo.height,
            controls: geo.controls.clone(),
            buttons_left: geo.buttons_left,
            max_button: geo.max_button,
        });
        self.caption_sent = Some(geo);
    }

    fn window_event_inner(&mut self, _el: &ActiveEventLoop, wid: WindowId, event: WindowEvent) {
        if let Some(i) = self.spans.iter().position(|s| s.window.id() == wid) {
            return self.span_event(i, event);
        }
        if let Some((id, i)) = self.rail_window(wid) {
            return self.rail_window_event(id, i, event);
        }
        if self.win.is_none() {
            return;
        }
        match event {
            WindowEvent::CloseRequested => self.request_quit(),
            // Windows switched between light and dark apps: System follows.
            WindowEvent::ThemeChanged(_) if self.settings.theme == ThemeChoice::System => {
                if let Some(m) = &mut self.win {
                    apply_theme(ThemeChoice::System, &m.gfx.window);
                    m.shown.clear();
                }
                for s in &self.spans {
                    s.window.request_redraw();
                }
                self.dirty();
            }
            WindowEvent::Resized(sz) => {
                let m = self.win.as_mut().unwrap();
                m.size = (sz.width as usize, sz.height as usize);
                m.ui.maximized = m.gfx.window.is_maximized();
                if let (Some(w), Some(h)) = (NonZeroU32::new(sz.width), NonZeroU32::new(sz.height))
                {
                    let _ = m.gfx.surface.resize(w, h);
                }
                m.shown.clear();
                self.settle();
                self.dirty();
            }
            WindowEvent::Moved(_) => {
                self.settle();
                self.dirty();
            }
            WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                self.settle();
                self.win.as_mut().unwrap().ui.scale = scale_factor as f32;
                // Tabs on Auto follow the monitor the window moved to.
                let auto: Vec<u64> = self
                    .win
                    .as_ref()
                    .unwrap()
                    .ui
                    .tabs
                    .iter()
                    .filter(|t| t.scale.is_none())
                    .map(|t| t.id)
                    .collect();
                let pct = self.auto_scale();
                for id in auto {
                    if let Some(s) = self.sessions.get(&id) {
                        s.controls.set_scale(pct);
                    }
                }
                self.dirty();
            }
            WindowEvent::RedrawRequested => {
                if self.win.as_ref().unwrap().chrome_dirty {
                    self.render_chrome();
                    self.send_caption();
                    self.fit_active();
                    // Tabs and the drawer move the session area: re-pick the cursor.
                    self.apply_cursor();
                } else {
                    self.render_session_damage();
                }
            }
            WindowEvent::Focused(focused) => {
                self.win.as_mut().unwrap().ui.window_active = focused;
                // Alt+Tab away leaves no Alt release behind.
                self.win.as_mut().unwrap().ui.alt_key(false);
                if !focused && let Some((id, _)) = self.win.as_ref().unwrap().ui.session_area {
                    self.send(id, session::release_modifiers());
                }
                self.dirty();
            }
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = (position.x as i32, position.y as i32);
                let m = self.win.as_mut().unwrap();
                m.cursor = (x, y);
                if m.ui.mouse_move(x, y) {
                    self.dirty();
                } else {
                    // Only the toolbar over the picture changed.
                    self.render_overlay();
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
                self.last_input = std::time::Instant::now();
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
                self.last_input = std::time::Instant::now();
                let (x, y) = self.win.as_ref().unwrap().cursor;
                if let Some((id, fx, fy)) = self.mouse_to_session(x, y) {
                    self.send(id, session::wheel(delta, (fx, fy)).into_iter().collect());
                } else {
                    let lines = match delta {
                        MouseScrollDelta::LineDelta(_, l) => l,
                        MouseScrollDelta::PixelDelta(p) => p.y as f32 / 40.0,
                    };
                    if self.win.as_mut().unwrap().ui.scroll(x, y, lines) {
                        self.dirty();
                    }
                }
            }
            WindowEvent::ModifiersChanged(mods) => self.mods = mods.state(),
            WindowEvent::KeyboardInput { event, .. } => {
                self.last_input = std::time::Instant::now();
                self.keyboard(event)
            }
            _ => {}
        }
    }
}

/// Ctrl+Alt+K, the chord that opens the command palette while a session has
/// the keyboard. AltGr is Ctrl+Alt on Windows, so an AltGr+K that types a
/// character stays the session's.
fn palette_chord(ev: &winit::event::KeyEvent, mods: ModifiersState) -> bool {
    use winit::keyboard::{KeyCode, PhysicalKey};
    ev.state.is_pressed()
        && mods.control_key()
        && mods.alt_key()
        && !mods.shift_key()
        && ev.physical_key == PhysicalKey::Code(KeyCode::KeyK)
        && match &ev.logical_key {
            WKey::Character(c) => c.eq_ignore_ascii_case("k"),
            _ => true,
        }
}

/// The display name of a shared folder: its last path component.
fn drive_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.trim_end_matches(['\\', '/', ':']).to_string())
}

/// "Remember on this PC": open the vault with the DPAPI-protected key, if any.
fn remembered_unlock(ui: &mut Ui) {
    let store = ui.store_mut();
    if !store.is_locked() {
        return;
    }
    let Some(path) = store.remembered_key_path() else {
        return;
    };
    let Some(key) = std::fs::read(&path)
        .ok()
        .and_then(|b| crate::vault::unprotect_key(&b))
    else {
        return;
    };
    if store.unlock(key).is_ok() {
        ui.vault_opened();
    }
}

/// Once a day, an installed copy asks GitHub for a newer release (off the UI
/// thread). Portable copies and development builds never check.
fn check_for_update(proxy: EventLoopProxy<UserEvent>, channel: String) {
    if !rdpc_update::is_installed_copy() {
        return;
    }
    let Some(stamp) = rdpc_update::stamp_path() else {
        return;
    };
    let now = std::time::SystemTime::now();
    if !rdpc_update::due(&stamp, now) {
        return;
    }
    std::thread::spawn(move || {
        // A failed check also waits a day.
        let _ = rdpc_update::write_stamp(&stamp, now);
        match run_update_check(&channel) {
            Ok(Some(c)) => {
                let _ = proxy.send_event(UserEvent::UpdateAvailable(c));
            }
            Ok(None) => rdp::trace!("ui: no update"),
            Err(e) => rdp::trace!("ui: update check failed: {e}"),
        }
    });
}

/// Asks GitHub for a newer release on the chosen channel.
fn run_update_check(channel: &str) -> Result<Option<rdpc_update::Candidate>, String> {
    let v = rdpc_update::current_version().map_err(|e| e.to_string())?;
    let ch = rdpc_update::Channel::from_setting(Some(channel), &v);
    rdpc_update::check(&v, ch).map_err(|e| e.to_string())
}

/// Trust on first use: a known, unchanged certificate connects; a new or
/// changed one asks the user in the session tab (the worker waits).
fn certificate_check(proxy: EventLoopProxy<UserEvent>, id: u64) -> rdp::CertificateCheck {
    let proxy = std::sync::Mutex::new(proxy);
    rdp::CertificateCheck(Arc::new(move |c: &rdp::ServerCertificate| {
        let fp = crate::known_hosts::hex(&c.sha256);
        let known = crate::known_hosts::lookup(&c.host, c.port);
        if known.as_deref() == Some(fp.as_str()) {
            rdp::trace!("ui: {}:{} certificate known", c.host, c.port);
            return true;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let prompt = ui::CertPrompt {
            fingerprint: c.fingerprint(),
            changed: known.is_some(),
            host: c.host.clone(),
        };
        let sent = proxy
            .lock()
            .map(|p| p.send_event(UserEvent::Certificate(id, prompt, tx)).is_ok())
            .unwrap_or(false);
        let trusted = sent && rx.recv().unwrap_or(false);
        if trusted && let Err(e) = crate::known_hosts::remember(&c.host, c.port, &fp) {
            rdp::trace!("ui: cannot remember the certificate: {e}");
        }
        trusted
    }))
}

/// Whether a "remember on this PC" key is stored.
fn remembered_exists(ui: &mut Ui) -> bool {
    ui.store_mut()
        .remembered_key_path()
        .is_some_and(|p| p.exists())
}

/// Removes files copied from sessions more than a day ago: the clipboard
/// pointed at them, so they stay until then (one folder per transfer in
/// `rdpc-clip` in the temp folder).
fn clean_clipboard_files(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let day = std::time::Duration::from_secs(24 * 60 * 60);
    for e in entries.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > day);
        if old && e.path().is_dir() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// `Videos\rdpc\<name> <date> <time>.mp4` in the user's profile.
fn recording_path(name: &str) -> std::path::PathBuf {
    let base = std::env::var_os("USERPROFILE")
        .map(|p| std::path::PathBuf::from(p).join("Videos"))
        .unwrap_or_else(std::env::temp_dir)
        .join("rdpc");
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " -_.()".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    base.join(format!("{} {}.mp4", clean.trim(), local_stamp()))
}

/// The local date and time as "2026-11-14 09-30-05".
fn local_stamp() -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        // SAFETY: GetLocalTime fills the given structure.
        let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut t) };
        format!(
            "{:04}-{:02}-{:02} {:02}-{:02}-{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    }
    #[cfg(not(windows))]
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        secs.to_string()
    }
}

impl App {
    /// Opens one monitor window of a session spread over several monitors.
    fn open_span(&mut self, el: &ActiveEventLoop, spec: crate::span::SpanSpec) {
        let (x, y, w, h) = spec.rect;
        let attrs = Window::default_attributes()
            .with_title(format!("{} - rdpc", spec.title))
            .with_decorations(false)
            .with_position(winit::dpi::PhysicalPosition::new(x, y))
            .with_inner_size(winit::dpi::PhysicalSize::new(w as u32, h as u32))
            .with_window_icon(crate::icon::window_icon(64));
        let made = el
            .create_window(attrs)
            .map_err(|e| e.to_string())
            .and_then(|win| crate::span::SpanWin::new(Rc::new(win), spec));
        match made {
            Ok(sw) => {
                sw.window.request_redraw();
                sw.window.focus_window();
                self.spans.push(sw);
            }
            Err(e) => self.message(format!("Cannot open the monitor window: {e}"), Tone::Danger),
        }
    }

    /// Back from the monitors into the window's tab (the desktop then
    /// follows the tab's size).
    fn unspan(&mut self, id: u64) {
        self.spans.retain(|s| s.session != id);
        if self.span_focus == Some(id) {
            self.span_focus = None;
        }
        if let Some(s) = self.sessions.get_mut(&id) {
            s.spanned = false;
            s.fit_requested = None;
        }
        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
            t.spanned = false;
            t.fit = true;
        }
        if let Some(m) = &self.win {
            m.gfx.window.focus_window();
        }
        self.update_key_hook();
        self.dirty();
    }

    /// Hands new session pictures to its monitor windows.
    fn render_spans(&mut self, id: u64) {
        let Some(worker) = self.sessions.get(&id).and_then(|s| s.worker.as_ref()) else {
            return;
        };
        let mut sh = worker.shared.lock().unwrap();
        worker.notified.store(false, Ordering::Release);
        let damage = std::mem::take(&mut sh.damage);
        let full = std::mem::take(&mut sh.full);
        for sw in self.spans.iter_mut().filter(|s| s.session == id) {
            if full {
                sw.needs_full = true;
            }
            sw.present(&sh.fb, &damage, &mut self.te, &self.fonts);
        }
    }

    /// The remote cursor on a session's monitor windows.
    fn apply_span_cursor(&self, id: u64) {
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        for sw in self.spans.iter().filter(|w| w.session == id) {
            let w = &sw.window;
            match &s.cursor {
                RemoteCursor::Default => {
                    w.set_cursor_visible(true);
                    w.set_cursor(CursorIcon::Default);
                }
                RemoteCursor::Hidden => w.set_cursor_visible(false),
                RemoteCursor::Custom(c) => {
                    w.set_cursor_visible(true);
                    w.set_cursor(c.clone());
                }
            }
        }
    }

    fn span_fb_size(&self, id: u64) -> (usize, usize) {
        self.sessions
            .get(&id)
            .and_then(|s| s.worker.as_ref())
            .and_then(|w| w.shared.lock().ok().map(|s| (s.fb.width, s.fb.height)))
            .unwrap_or((0, 0))
    }

    /// Input and window events of a monitor window: everything goes to its
    /// session, except the session bar at the top of the first monitor.
    fn span_event(&mut self, i: usize, event: WindowEvent) {
        let id = self.spans[i].session;
        match event {
            WindowEvent::CloseRequested => self.unspan(id),
            WindowEvent::Resized(sz) => {
                self.spans[i].resized(sz.width, sz.height);
                self.spans[i].window.request_redraw();
            }
            WindowEvent::ScaleFactorChanged {
                mut inner_size_writer,
                ..
            } => {
                // The window keeps its monitor's size in physical pixels.
                let (w, h) = self.spans[i].size;
                let _ = inner_size_writer
                    .request_inner_size(winit::dpi::PhysicalSize::new(w as u32, h as u32));
            }
            WindowEvent::RedrawRequested => {
                self.spans[i].needs_full = true;
                self.render_spans(id);
            }
            WindowEvent::Focused(focused) => {
                if focused {
                    self.span_focus = Some(id);
                } else {
                    if self.span_focus == Some(id) {
                        self.span_focus = None;
                    }
                    self.send(id, session::release_modifiers());
                }
                self.update_key_hook();
            }
            WindowEvent::ModifiersChanged(mods) => self.mods = mods.state(),
            WindowEvent::CursorEntered { .. } => self.apply_span_cursor(id),
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = (position.x as i32, position.y as i32);
                if self.spans[i].pointer(x, y) {
                    self.render_spans(id);
                }
                if !self.spans[i].over_bar(x, y) {
                    let fb = self.span_fb_size(id);
                    let pos = self.spans[i].to_session(x, y, fb);
                    if let Some(s) = self.sessions.get_mut(&id)
                        && s.mouse != pos
                    {
                        s.mouse = pos;
                        self.send(id, vec![InputEvent::mouse_move(pos.0, pos.1)]);
                    }
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                self.last_input = std::time::Instant::now();
                let down = state == ElementState::Pressed;
                let (x, y) = self.spans[i].cursor;
                if self.spans[i].over_bar(x, y) {
                    use crate::span::BarButton as B;
                    if !down && button == MouseButton::Left {
                        match self.spans[i].button_at(x, y) {
                            Some(B::Exit) => self.unspan(id),
                            Some(B::Disconnect) => self.handle_action(Action::Disconnect(id)),
                            Some(B::CtrlAltDel) => self.send(id, session::ctrl_alt_del()),
                            Some(B::Handle) => {
                                self.spans[i].toggle_open();
                                self.render_spans(id);
                            }
                            None => {}
                        }
                    }
                    return;
                }
                if down && self.spans[i].picture_clicked() {
                    self.render_spans(id);
                }
                let fb = self.span_fb_size(id);
                let pos = self.spans[i].to_session(x, y, fb);
                self.send(
                    id,
                    session::mouse_button(button, down, pos)
                        .into_iter()
                        .collect(),
                );
            }
            WindowEvent::MouseWheel { delta, .. } => {
                self.last_input = std::time::Instant::now();
                let (x, y) = self.spans[i].cursor;
                let fb = self.span_fb_size(id);
                let pos = self.spans[i].to_session(x, y, fb);
                self.send(id, session::wheel(delta, pos).into_iter().collect());
            }
            WindowEvent::KeyboardInput { event, .. } => {
                self.last_input = std::time::Instant::now();
                // Ctrl+Alt+Break leaves the monitors, as full screen elsewhere.
                if event.state.is_pressed()
                    && self.mods.control_key()
                    && self.mods.alt_key()
                    && matches!(
                        event.logical_key,
                        WKey::Named(NamedKey::Pause | NamedKey::Cancel)
                    )
                {
                    return self.unspan(id);
                }
                self.session_key(id, &event);
            }
            _ => {}
        }
    }
}

/// The native frame's theme: a fixed choice, or None to follow Windows.
fn winit_theme(choice: ThemeChoice) -> Option<winit::window::Theme> {
    match choice {
        ThemeChoice::Dark => Some(winit::window::Theme::Dark),
        ThemeChoice::Light => Some(winit::window::Theme::Light),
        ThemeChoice::System => None,
    }
}

/// Paints with `choice`; System asks the window which theme Windows uses.
fn apply_theme(choice: ThemeChoice, window: &Window) {
    let light = window.theme() == Some(winit::window::Theme::Light);
    crate::theme::set(choice.palette(light));
}
