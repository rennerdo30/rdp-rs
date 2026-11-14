//! RemoteApp sessions in the app: launching programs, the local windows of
//! the remote ones, their input, and closing a session whose apps are gone.
//! The decisions live in `crate::remoteapp`; this is the glue.

use std::sync::atomic::Ordering;
use std::time::Instant;

use rdp::InputEvent;
use rdp::rail::{RailEvent, RailState};
use winit::event::{ElementState, WindowEvent};
use winit::event_loop::ActiveEventLoop;
use winit::window::{CursorIcon, WindowId};

use super::{App, RemoteCursor};
use crate::remoteapp::{self, RailSession, Show};
use crate::session;
use crate::store::AppEntry;
use crate::theme::Tone;
use crate::ui::{Action, AppWindowItem, RemoteAppView};

impl App {
    /// A RemoteApp connection's desktop is all of this PC's monitors, so
    /// remote windows land where they are on the server.
    pub(super) fn rail_prepare(cfg: &mut rdp::Config, apps: Vec<AppEntry>) -> RailSession {
        let all = crate::monitors::list();
        let mut rs = RailSession {
            apps,
            ..Default::default()
        };
        if let Some((bx, by, bw, bh)) = crate::monitors::bounds(&all) {
            cfg.monitors = all.iter().map(|m| m.monitor.clone()).collect();
            rs.desk = (bx, by);
            cfg.width = bw.clamp(200, 8192) as u16;
            cfg.height = bh.clamp(200, 8192) as u16;
        }
        if let Some(app) = &cfg.remote_app {
            rs.tracker.launched(&app.program, Instant::now());
        }
        rs
    }

    fn rail(&mut self, id: u64) -> Option<&mut RailSession> {
        self.sessions.get_mut(&id).and_then(|s| s.rail.as_mut())
    }

    /// Starts an app in a session: at once when it is up, else when it is.
    pub(super) fn rail_exec(&mut self, id: u64, app: AppEntry) {
        let Some(rs) = self.rail(id) else { return };
        rs.tracker.launched(&app.program, Instant::now());
        let name = app.name.clone();
        let r = match rs.launcher.launch(app) {
            Some(app) => send_exec(rs, &app),
            None => Ok(()),
        };
        match r {
            Ok(()) => self.message(format!("Starting {name}…"), Tone::Muted),
            Err(e) => self.message(e, Tone::Danger),
        }
        self.rail_refresh(id);
    }

    /// The session is up: the window model arrived, queued apps go out.
    pub(super) fn rail_ready(&mut self, id: u64, handle: rdp::RailHandle) {
        let Some(rs) = self.rail(id) else { return };
        if let Some((work, taskbar)) = remoteapp::local_work_area() {
            handle.set_work_area(work, taskbar);
        }
        rs.handle = Some(handle);
        let mut errors = Vec::new();
        for app in rs.launcher.attach() {
            if let Err(e) = send_exec(rs, &app) {
                errors.push(e);
            }
        }
        if !errors.is_empty() {
            self.message(errors.join(" "), Tone::Danger);
        }
    }

    /// Rail events from the worker: errors in plain words, focus, windows.
    pub(super) fn rail_events(&mut self, el: &ActiveEventLoop, id: u64, events: Vec<RailEvent>) {
        let foreground = self.rdpc_has_focus();
        let mut notes = Vec::new();
        let Some(rs) = self.rail(id) else { return };
        for ev in events {
            match ev {
                RailEvent::ExecResult(r) if !r.ok() => {
                    let text = remoteapp::exec_failure(&rs.apps, &r);
                    rdp::trace!(
                        "ui: {text} (Execute Result {}, raw {:#x}, {:?})",
                        r.result,
                        r.raw_result,
                        r.program
                    );
                    rs.tracker.failed(&r.program);
                    rs.linger.launch_failed();
                    notes.push((text, Tone::Danger));
                }
                RailEvent::WindowCreated(w) => {
                    if let Some(h) = &rs.handle {
                        h.request_app_id(w);
                    }
                }
                RailEvent::ActiveWindow(a) if foreground => {
                    let focused = rs
                        .windows
                        .iter()
                        .any(|w| w.id == a && w.win.window.has_focus());
                    if !focused {
                        rs.want_active = Some(a);
                    }
                }
                RailEvent::DesktopNotMonitored => notes.push((
                    "The remote session shows a secure screen (locked or signing in); its windows come back after it."
                        .into(),
                    Tone::Warning,
                )),
                _ => {}
            }
        }
        for (text, color) in notes {
            self.message(text, color);
        }
        self.rail_sync(el, id);
    }

    /// Brings the local windows in line with the server's and updates the tab.
    fn rail_sync(&mut self, el: &ActiveEventLoop, id: u64) {
        let Some(rs) = self.rail(id) else { return };
        let Some(state) = rs.handle.as_ref().map(|h| h.state()) else {
            return;
        };
        if let Some(e) = rs.sync(el, id, &state) {
            self.message(format!("Cannot open a window for the app: {e}"), Tone::Danger);
        }
        let Some(rs) = self.rail(id) else { return };
        rs.tracker.update(&state);
        rs.open = remoteapp::open_count(&state);
        self.apply_rail_cursor(id);
        self.rail_view(id, Some(&state));
    }

    /// Re-checks the empty-session timer and refreshes the tab's view.
    fn rail_refresh(&mut self, id: u64) {
        self.rail_view(id, None);
    }

    fn rail_view(&mut self, id: u64, state: Option<&RailState>) {
        let now = Instant::now();
        let host = self
            .sessions
            .get(&id)
            .map(|s| s.cfg.host.clone())
            .unwrap_or_default();
        let Some(rs) = self.rail(id) else { return };
        let mut starting = rs.tracker.starting(now);
        starting.extend(rs.launcher.queued().iter().map(|a| a.program.clone()));
        if rs.linger.update(now, rs.open, !starting.is_empty()) {
            self.message(
                format!(
                    "All apps on {host} are closed; disconnecting in {} s unless you start another.",
                    remoteapp::LINGER.as_secs()
                ),
                Tone::Muted,
            );
        }
        let Some(rs) = self.sessions.get(&id).and_then(|s| s.rail.as_ref()) else {
            return;
        };
        let running = rs.tracker.running();
        let Some(st) = state else {
            // No new window list (timers, launches): only the app states,
            // without copying the windows' icons on every wake.
            let mut changed = false;
            if let Some(v) = self
                .win
                .as_mut()
                .and_then(|m| m.ui.tab_mut(id))
                .and_then(|t| t.remote_app.as_mut())
                && (v.running != running || v.starting != starting)
            {
                v.running = running;
                v.starting = starting;
                changed = true;
            }
            if changed {
                self.dirty();
            }
            return;
        };
        let windows = {
            remoteapp::plan(st)
                .into_iter()
                .filter(|p| p.taskbar && p.show != Show::Hidden)
                .map(|p| AppWindowItem {
                    id: p.id,
                    icon: st.windows.get(&p.id).and_then(|w| {
                        w.icon
                            .as_ref()
                            .or(w.big_icon.as_ref())
                            .map(|i| (i.width, i.height, i.rgba.clone()))
                    }),
                    title: p.title,
                    minimized: p.show == Show::Minimized,
                })
                .collect()
        };
        let view = RemoteAppView {
            apps: rs.apps.clone(),
            windows,
            running,
            starting,
        };
        if let Some(t) = self.win.as_mut().and_then(|m| m.ui.tab_mut(id))
            && t.remote_app.as_ref() != Some(&view)
        {
            t.remote_app = Some(view);
            self.dirty();
        }
    }

    /// The session ended: its windows close; launches wait for a reconnect.
    pub(super) fn rail_ended(&mut self, id: u64) {
        if self.app_focus == Some(id) {
            self.app_focus = None;
        }
        let Some(rs) = self.rail(id) else { return };
        rs.windows.clear();
        rs.handle = None;
        rs.launcher.detach();
        rs.want_active = None;
        rs.open = 0;
        self.rail_view(id, Some(&RailState::default()));
    }

    /// A reconnect logs on with the first app again: start counting afresh.
    pub(super) fn rail_reset(&mut self, id: u64) {
        let program = self
            .sessions
            .get(&id)
            .and_then(|s| s.cfg.remote_app.as_ref())
            .map(|a| a.program.clone());
        let Some(rs) = self.rail(id) else { return };
        rs.tracker = Default::default();
        rs.linger = Default::default();
        if let Some(p) = program {
            rs.tracker.launched(&p, Instant::now());
        }
    }

    /// New pictures for a RemoteApp session's windows.
    pub(super) fn render_rail(&mut self, id: u64) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        let (Some(worker), Some(rs)) = (s.worker.as_ref(), s.rail.as_mut()) else {
            return;
        };
        let mut sh = worker.shared.lock().unwrap();
        worker.notified.store(false, Ordering::Release);
        let damage = std::mem::take(&mut sh.damage);
        let full = std::mem::take(&mut sh.full);
        rs.present(&sh.fb, &damage, full, &mut self.te, &self.fonts);
    }

    /// The remote cursor on a session's app windows.
    pub(super) fn apply_rail_cursor(&self, id: u64) {
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        for w in s.rail.iter().flat_map(|r| &r.windows) {
            let win = &w.win.window;
            match &s.cursor {
                RemoteCursor::Default => {
                    win.set_cursor_visible(true);
                    win.set_cursor(CursorIcon::Default);
                }
                RemoteCursor::Hidden => win.set_cursor_visible(false),
                RemoteCursor::Custom(c) => {
                    win.set_cursor_visible(true);
                    win.set_cursor(c.clone());
                }
            }
        }
    }

    /// rdpc has the keyboard (its window or one of its session windows).
    fn rdpc_has_focus(&self) -> bool {
        self.app_focus.is_some()
            || self.span_focus.is_some()
            || self.win.as_ref().is_some_and(|m| m.ui.window_active)
    }

    /// The session tab's Focus button: restore and bring the window up.
    pub(super) fn rail_focus(&mut self, id: u64, window: u32) {
        let Some(rs) = self.rail(id) else { return };
        if let Some(w) = rs.windows.iter().find(|w| w.id == window) {
            if let (Some(h), Show::Minimized) = (&rs.handle, w.plan.show) {
                h.restore(window);
            }
            w.win.window.focus_window();
        }
        if let Some(h) = &rs.handle {
            h.set_focus(window, true);
        }
    }

    /// The session tab's Close button: the app may still ask to save.
    pub(super) fn rail_close(&mut self, id: u64, window: u32) {
        if let Some(h) = self.rail(id).and_then(|rs| rs.handle.clone()) {
            h.close(window);
        }
    }

    /// Ends sessions whose last app closed a while ago; returns when to look again.
    pub(super) fn rail_timers(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let ids: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.rail.is_some() && s.worker.is_some())
            .map(|(&id, _)| id)
            .collect();
        let mut next: Option<Instant> = None;
        for id in ids {
            self.rail_refresh(id);
            let host = self
                .sessions
                .get(&id)
                .map(|s| s.cfg.host.clone())
                .unwrap_or_default();
            let Some(rs) = self.rail(id) else { continue };
            if rs.linger.due(now) {
                rdp::trace!("ui: RemoteApp session {id}: no apps open, disconnecting");
                self.handle_action(Action::CloseTab(id));
                self.message(
                    format!("Disconnected from {host}: no apps were open."),
                    Tone::Muted,
                );
                continue;
            }
            for t in [rs.linger.deadline(), rs.tracker.next_wake(now)]
                .into_iter()
                .flatten()
            {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        next
    }

    /// The app window with this id: (session, index).
    pub(super) fn rail_window(&self, wid: WindowId) -> Option<(u64, usize)> {
        self.sessions.iter().find_map(|(&id, s)| {
            let i = s
                .rail
                .as_ref()?
                .windows
                .iter()
                .position(|w| w.win.window.id() == wid)?;
            Some((id, i))
        })
    }

    /// The framebuffer position of a point in an app window.
    fn rail_point(&self, id: u64, i: usize, x: i32, y: i32) -> Option<(u16, u16)> {
        let s = self.sessions.get(&id)?;
        let rs = s.rail.as_ref()?;
        let (w, h) = s
            .worker
            .as_ref()?
            .shared
            .lock()
            .ok()
            .map(|sh| (sh.fb.width as i32, sh.fb.height as i32))?;
        if w == 0 || h == 0 {
            return None;
        }
        let (dx, dy) = rs.windows.get(i)?.to_desktop(x, y);
        let fx = (dx - rs.desk.0).clamp(0, w - 1);
        let fy = (dy - rs.desk.1).clamp(0, h - 1);
        Some((fx as u16, fy as u16))
    }

    fn rail_ids(&self, id: u64, i: usize) -> Option<(u32, rdp::RailHandle)> {
        let rs = self.sessions.get(&id)?.rail.as_ref()?;
        Some((rs.windows.get(i)?.id, rs.handle.clone()?))
    }

    /// Input and window events of an app window: everything goes to the
    /// session at desktop coordinates; taskbar actions become sys commands.
    pub(super) fn rail_window_event(&mut self, id: u64, i: usize, event: WindowEvent) {
        let ids = self.rail_ids(id, i);
        match event {
            // Alt+F4 already went to the server as keys; the taskbar's Close
            // asks the app (SC_CLOSE), which may ask to save first.
            WindowEvent::CloseRequested => {
                if let Some((w, h)) = ids
                    && !self.mods.alt_key()
                {
                    h.close(w);
                }
            }
            WindowEvent::Resized(sz) => {
                let Some(rs) = self.rail(id) else { return };
                let Some(aw) = rs.windows.get_mut(i) else {
                    return;
                };
                aw.win.resized(sz.width, sz.height);
                let minimized = aw.win.window.is_minimized() == Some(true);
                if let (Some(cmd), Some((w, h))) =
                    (remoteapp::taskbar_command(aw.plan.show, minimized), ids)
                {
                    h.sys_command(w, cmd);
                }
                aw.win.window.request_redraw();
            }
            WindowEvent::ScaleFactorChanged {
                mut inner_size_writer,
                ..
            } => {
                // The window keeps the remote window's size in pixels.
                if let Some(aw) = self.rail(id).and_then(|rs| rs.windows.get(i)) {
                    let (_, _, w, h) = aw.plan.rect;
                    let _ = inner_size_writer
                        .request_inner_size(winit::dpi::PhysicalSize::new(w.max(1), h.max(1)));
                }
            }
            WindowEvent::RedrawRequested => {
                if let Some(aw) = self.rail(id).and_then(|rs| rs.windows.get_mut(i)) {
                    aw.win.needs_full = true;
                }
                self.render_rail(id);
            }
            WindowEvent::Focused(focused) => {
                if focused {
                    self.app_focus = Some(id);
                    if let Some((w, h)) = ids {
                        h.set_focus(w, true);
                    }
                } else {
                    if self.app_focus == Some(id) {
                        self.app_focus = None;
                    }
                    self.send(id, session::release_modifiers());
                }
                self.update_key_hook();
            }
            WindowEvent::ModifiersChanged(mods) => self.mods = mods.state(),
            WindowEvent::CursorEntered { .. } => self.apply_rail_cursor(id),
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = (position.x as i32, position.y as i32);
                if let Some(aw) = self.rail(id).and_then(|rs| rs.windows.get_mut(i)) {
                    aw.win.cursor = (x, y);
                }
                if let Some(pos) = self.rail_point(id, i, x, y)
                    && let Some(s) = self.sessions.get_mut(&id)
                    && s.mouse != pos
                {
                    s.mouse = pos;
                    self.send(id, vec![InputEvent::mouse_move(pos.0, pos.1)]);
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                self.last_input = Instant::now();
                let Some((x, y)) = self
                    .rail(id)
                    .and_then(|rs| rs.windows.get(i))
                    .map(|w| w.win.cursor)
                else {
                    return;
                };
                if let Some(pos) = self.rail_point(id, i, x, y) {
                    let down = state == ElementState::Pressed;
                    let ev = session::mouse_button(button, down, pos);
                    self.send(id, ev.into_iter().collect());
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                self.last_input = Instant::now();
                let cursor = self
                    .rail(id)
                    .and_then(|rs| rs.windows.get(i))
                    .map(|w| w.win.cursor);
                if let Some((x, y)) = cursor
                    && let Some(pos) = self.rail_point(id, i, x, y)
                {
                    self.send(id, session::wheel(delta, pos).into_iter().collect());
                }
            }
            WindowEvent::KeyboardInput { event, .. } => {
                self.last_input = Instant::now();
                if let Some(e) = session::key_event(&event) {
                    self.send(id, vec![e]);
                } else {
                    let u = session::unicode_events(&event);
                    if !u.is_empty() {
                        self.send(id, u);
                    }
                }
            }
            _ => {}
        }
    }
}

fn send_exec(rs: &mut RailSession, app: &AppEntry) -> Result<(), String> {
    let r = match &rs.handle {
        Some(h) => h.exec(&app.remote_app()).map_err(|e| e.to_string()),
        None => Err("the session is not ready".into()),
    };
    r.map_err(|e| {
        rs.tracker.failed(&app.program);
        format!("{} could not start: {e}.", app.name)
    })
}
