//! RemoteApp: a connection that opens programs instead of a desktop
//! (MS-RDPERP). Every remote top-level window gets a borderless local window
//! at the same place on this PC's desktop, showing that rectangle of the
//! session picture; the session's desktop is all local monitors, so remote
//! and local desktop coordinates are the same.
//!
//! This module holds the decisions (window plan, launch queue, which
//! programs run, when an empty session ends) as plain data that tests can
//! check, and the local windows themselves (`AppWin`, built on `span`).

use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rdp::rail::{ExecResult, RailIcon, RailState, RailWindow, SysCommand};
use winit::dpi::{PhysicalPosition, PhysicalSize};
use winit::event_loop::ActiveEventLoop;
use winit::window::{Icon, Window, WindowLevel};

use crate::span::{SpanSpec, SpanWin};
use crate::store::{AppEntry, default_app_name};

// Window styles the plan reads (WinUser.h).
const WS_CHILD: u32 = 0x4000_0000;
const WS_EX_TOPMOST: u32 = 0x0000_0008;
const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
const WS_EX_APPWINDOW: u32 = 0x0004_0000;
const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

/// An empty session (no window, no notification icon) disconnects after this.
pub const LINGER: Duration = Duration::from_secs(10);
/// A launched program that shows no window within this long stops keeping
/// an empty session open.
pub const START_WAIT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    Hidden,
    Minimized,
    Shown,
}

/// How a remote window shows (ShowState, MS-RDPERP 2.2.1.3.1.2.1): hidden
/// also when cloaked or empty.
pub fn show_of(w: &RailWindow) -> Show {
    if w.cloaked || w.window_rect.width == 0 || w.window_rect.height == 0 {
        return Show::Hidden;
    }
    match w.show_state {
        0 => Show::Hidden,
        2 => Show::Minimized,
        _ => Show::Shown,
    }
}

fn top_level(w: &RailWindow) -> bool {
    w.style & WS_CHILD == 0
}

/// What the local window of one remote top-level window looks like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowPlan {
    pub id: u32,
    /// Desktop pixels: x, y, width, height.
    pub rect: (i32, i32, u32, u32),
    pub show: Show,
    /// A taskbar button (not owned, not a tool window; or WS_EX_APPWINDOW).
    pub taskbar: bool,
    /// The window whose local window owns this one (stays above it).
    pub owner: Option<u32>,
    pub topmost: bool,
    pub no_activate: bool,
    pub title: String,
    /// Visible region (x, y, width, height) relative to the window; None:
    /// all of it.
    pub region: Option<Vec<(i32, i32, i32, i32)>>,
}

/// The local windows for a window list, owners before the windows they own.
pub fn plan(state: &RailState) -> Vec<WindowPlan> {
    let mut out: Vec<(usize, WindowPlan)> = state
        .windows
        .iter()
        .filter(|(_, w)| top_level(w))
        .map(|(&id, w)| {
            let owner = Some(w.owner)
                .filter(|&o| o != 0 && o != id)
                .filter(|o| state.windows.get(o).is_some_and(top_level));
            let ex = w.ex_style;
            let r = w.window_rect;
            let p = WindowPlan {
                id,
                rect: (r.x, r.y, r.width, r.height),
                show: show_of(w),
                taskbar: ex & WS_EX_TOOLWINDOW == 0 && (w.owner == 0 || ex & WS_EX_APPWINDOW != 0),
                owner,
                topmost: ex & WS_EX_TOPMOST != 0,
                no_activate: ex & WS_EX_NOACTIVATE != 0,
                title: w.title.clone(),
                region: region(w),
            };
            (owner_depth(state, id), p)
        })
        .collect();
    out.sort_by_key(|(d, p)| (*d, p.id));
    out.into_iter().map(|(_, p)| p).collect()
}

fn owner_depth(state: &RailState, mut id: u32) -> usize {
    let mut depth = 0;
    while let Some(w) = state.windows.get(&id) {
        if w.owner == 0 || w.owner == id || depth >= 32 {
            break;
        }
        id = w.owner;
        depth += 1;
    }
    depth
}

/// The visible region in window coordinates; None when it is the whole
/// window (or unknown).
fn region(w: &RailWindow) -> Option<Vec<(i32, i32, i32, i32)>> {
    let (ox, oy) = (
        w.visible_offset.0 - w.window_rect.x,
        w.visible_offset.1 - w.window_rect.y,
    );
    let rects: Vec<(i32, i32, i32, i32)> = w
        .visible_rects
        .iter()
        .map(|r| {
            (
                ox + r.left as i32,
                oy + r.top as i32,
                r.right as i32 - r.left as i32,
                r.bottom as i32 - r.top as i32,
            )
        })
        .filter(|r| r.2 > 0 && r.3 > 0)
        .collect();
    let whole = (
        0,
        0,
        w.window_rect.width as i32,
        w.window_rect.height as i32,
    );
    match rects.as_slice() {
        [] => None,
        [r] if *r == whole => None,
        _ => Some(rects),
    }
}

/// Where a window's picture starts in the session framebuffer, which begins
/// at `desk` on the desktop.
pub fn fb_origin(rect: (i32, i32, u32, u32), desk: (i32, i32)) -> (i32, i32) {
    (rect.0 - desk.0, rect.1 - desk.1)
}

/// The system command for a minimize or restore done on this PC (taskbar
/// button, Win+D): None when the remote window is already in that state.
pub fn taskbar_command(remote: Show, local_minimized: bool) -> Option<SysCommand> {
    match (remote, local_minimized) {
        (Show::Shown, true) => Some(SysCommand::Minimize),
        (Show::Minimized, false) => Some(SysCommand::Restore),
        _ => None,
    }
}

/// A session tab as the launcher sees it.
pub struct Candidate<'a> {
    pub id: u64,
    pub name: &'a str,
    pub host: &'a str,
    pub remote_app: bool,
    pub connected: bool,
    pub connecting: bool,
}

/// Where a launch goes: a RemoteApp session of the same connection that is
/// up (or, failing that, still connecting: the launch waits for it); None
/// starts a new session.
pub fn launch_target<'a>(
    tabs: impl IntoIterator<Item = Candidate<'a>>,
    name: &str,
    host: &str,
) -> Option<u64> {
    let mut connecting = None;
    for t in tabs {
        if !(t.remote_app && t.name == name && t.host == host) {
            continue;
        }
        if t.connected {
            return Some(t.id);
        }
        if t.connecting && connecting.is_none() {
            connecting = Some(t.id);
        }
    }
    connecting
}

/// Programs to start in a session: sent at once when the session is up,
/// queued while it connects.
#[derive(Default)]
pub struct Launcher {
    attached: bool,
    queued: Vec<AppEntry>,
}

impl Launcher {
    /// The app to send now, or None when it waits for the session.
    pub fn launch(&mut self, app: AppEntry) -> Option<AppEntry> {
        if self.attached {
            Some(app)
        } else {
            self.queued.push(app);
            None
        }
    }

    /// The session is up: the queued apps to send now.
    pub fn attach(&mut self) -> Vec<AppEntry> {
        self.attached = true;
        std::mem::take(&mut self.queued)
    }

    /// The session ended; launches wait for the next one.
    pub fn detach(&mut self) {
        self.attached = false;
    }

    pub fn queued(&self) -> &[AppEntry] {
        &self.queued
    }
}

/// Whether two program strings name the same program (`||excel`,
/// `C:\...\EXCEL.EXE`).
pub fn same_program(a: &str, b: &str) -> bool {
    default_app_name(a).eq_ignore_ascii_case(&default_app_name(b))
}

struct Prog {
    program: String,
    at: Instant,
    windows: BTreeSet<u32>,
    seen: bool,
}

/// Which launched programs have windows: a new visible window belongs to
/// the program of its owner, else to a starting program whose name is in
/// its Application ID, else to the oldest starting one, else to the latest.
#[derive(Default)]
pub struct Tracker {
    progs: Vec<Prog>,
}

fn visible_windows(state: &RailState) -> impl Iterator<Item = (u32, &RailWindow)> {
    state
        .windows
        .iter()
        .filter(|(_, w)| top_level(w) && show_of(w) != Show::Hidden)
        .map(|(&id, w)| (id, w))
}

impl Tracker {
    pub fn launched(&mut self, program: &str, now: Instant) {
        self.progs.push(Prog {
            program: program.to_string(),
            at: now,
            windows: BTreeSet::new(),
            seen: false,
        });
    }

    /// The server refused a launch (its Execute Result names the program).
    pub fn failed(&mut self, program: &str) {
        let i = self
            .progs
            .iter()
            .position(|p| !p.seen && same_program(&p.program, program))
            .or_else(|| self.progs.iter().position(|p| !p.seen));
        if let Some(i) = i {
            self.progs.remove(i);
        }
    }

    pub fn update(&mut self, state: &RailState) {
        let visible: Vec<(u32, &RailWindow)> = visible_windows(state).collect();
        for p in &mut self.progs {
            p.windows.retain(|id| visible.iter().any(|(v, _)| v == id));
        }
        for (id, w) in visible {
            if self.progs.iter().any(|p| p.windows.contains(&id)) || self.progs.is_empty() {
                continue;
            }
            let by_owner = [w.owner, w.root_parent.unwrap_or(0)]
                .into_iter()
                .filter(|&o| o != 0)
                .find_map(|o| self.progs.iter().position(|p| p.windows.contains(&o)));
            let app_id = w.app_id.as_deref().map(str::to_lowercase);
            let by_id = |unseen: bool| {
                let a = app_id.as_deref()?;
                self.progs.iter().position(|p| {
                    (!unseen || !p.seen) && a.contains(&default_app_name(&p.program).to_lowercase())
                })
            };
            let i = by_owner
                .or_else(|| by_id(true))
                .or_else(|| by_id(false))
                .or_else(|| self.progs.iter().position(|p| !p.seen))
                .unwrap_or(self.progs.len() - 1);
            self.progs[i].windows.insert(id);
            self.progs[i].seen = true;
        }
        self.progs.retain(|p| !p.seen || !p.windows.is_empty());
    }

    /// Programs with windows open.
    pub fn running(&self) -> Vec<String> {
        self.progs
            .iter()
            .filter(|p| !p.windows.is_empty())
            .map(|p| p.program.clone())
            .collect()
    }

    /// Programs launched recently that show no window yet.
    pub fn starting(&self, now: Instant) -> Vec<String> {
        self.progs
            .iter()
            .filter(|p| !p.seen && now < p.at + START_WAIT)
            .map(|p| p.program.clone())
            .collect()
    }

    /// When a starting program stops counting as starting.
    pub fn next_wake(&self, now: Instant) -> Option<Instant> {
        self.progs
            .iter()
            .filter(|p| !p.seen)
            .map(|p| p.at + START_WAIT)
            .filter(|&t| t > now)
            .min()
    }
}

/// What keeps a session open: visible windows and notification icons.
pub fn open_count(state: &RailState) -> usize {
    visible_windows(state).count() + state.notify_icons.values().filter(|n| !n.hidden).count()
}

/// The auto-disconnect of a session whose last app closed: armed when the
/// session had windows and has none (and nothing is starting), disarmed by
/// a new window or launch.
#[derive(Default)]
pub struct Linger {
    had_windows: bool,
    since: Option<Instant>,
}

impl Linger {
    /// True when this armed the timer.
    pub fn update(&mut self, now: Instant, open: usize, starting: bool) -> bool {
        if open > 0 {
            self.had_windows = true;
            self.since = None;
        } else if starting {
            self.since = None;
        } else if self.had_windows && self.since.is_none() {
            self.since = Some(now);
            return true;
        }
        false
    }

    /// A launch failed: a session left without any app ends like one whose
    /// apps closed (the next `update` arms the timer).
    pub fn launch_failed(&mut self) {
        self.had_windows = true;
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.since.map(|t| t + LINGER)
    }

    pub fn due(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|t| now >= t)
    }
}

/// An Execute Result error in plain words (MS-RDPERP 2.2.2.3.2).
pub fn exec_error(result: u16) -> &'static str {
    match result {
        1 => "the server is not ready for apps (its desktop is not available)",
        2 => "the server could not read the request",
        3 => "the server does not allow this program",
        5 => "the program was not found on the server",
        6 => "the server reported an error",
        7 => "the remote session is locked",
        _ => "the server gave an unknown answer",
    }
}

/// The name of the app that runs `program`: its own name, else one made
/// from the program.
pub fn app_label(apps: &[AppEntry], program: &str) -> String {
    apps.iter()
        .find(|a| same_program(&a.program, program))
        .map(|a| a.name.clone())
        .unwrap_or_else(|| default_app_name(program))
}

pub fn exec_failure(apps: &[AppEntry], r: &ExecResult) -> String {
    format!(
        "{} could not start: {}.",
        app_label(apps, &r.program),
        exec_error(r.result)
    )
}

/// Where this PC's taskbar is: the part of the primary monitor (left, top,
/// right, bottom) outside its work area; all zero when it auto-hides.
pub fn taskbar_rect(monitor: [i32; 4], work: [i32; 4]) -> [i32; 4] {
    let [ml, mt, mr, mb] = monitor;
    let [wl, wt, wr, wb] = work;
    if wb < mb {
        [ml, wb, mr, mb]
    } else if wt > mt {
        [ml, mt, mr, wt]
    } else if wl > ml {
        [ml, mt, wl, mb]
    } else if wr < mr {
        [wr, mt, mr, mb]
    } else {
        [0; 4]
    }
}

/// The primary monitor's work area and the taskbar, for the server's
/// maximized windows (SPI_GETWORKAREA); None when unknown.
#[cfg(windows)]
pub fn local_work_area() -> Option<([u16; 4], [u16; 4])> {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN, SPI_GETWORKAREA, SystemParametersInfoW,
    };
    let mut r: RECT = unsafe { std::mem::zeroed() };
    // SAFETY: SPI_GETWORKAREA fills a RECT.
    if unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut r as *mut RECT as *mut _, 0) } == 0 {
        return None;
    }
    // SAFETY: plain metric queries.
    let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let work = [r.left, r.top, r.right, r.bottom];
    let u = |a: [i32; 4]| a.map(|v| v.clamp(0, u16::MAX as i32) as u16);
    Some((u(work), u(taskbar_rect([0, 0, w, h], work))))
}

#[cfg(not(windows))]
pub fn local_work_area() -> Option<([u16; 4], [u16; 4])> {
    None
}

/// The local window of one remote window.
pub struct AppWin {
    pub id: u32,
    pub win: SpanWin,
    pub plan: WindowPlan,
    icons: (Option<RailIcon>, Option<RailIcon>),
}

fn icon(i: &Option<RailIcon>) -> Option<Icon> {
    let i = i.as_ref()?;
    Icon::from_rgba(i.rgba.clone(), i.width as u32, i.height as u32).ok()
}

impl AppWin {
    /// The desktop position of a point in this window.
    pub fn to_desktop(&self, x: i32, y: i32) -> (i32, i32) {
        let pos = self
            .win
            .window
            .inner_position()
            .map(|p| (p.x, p.y))
            .unwrap_or((self.plan.rect.0, self.plan.rect.1));
        (pos.0 + x, pos.1 + y)
    }

    fn set_icons(&mut self, w: &RailWindow) {
        let want = (w.icon.clone(), w.big_icon.clone().or(w.icon.clone()));
        if want == self.icons {
            return;
        }
        self.win.window.set_window_icon(icon(&want.0));
        #[cfg(windows)]
        {
            use winit::platform::windows::WindowExtWindows;
            self.win.window.set_taskbar_icon(icon(&want.1));
        }
        self.icons = want;
    }

    /// Follows a changed plan; the old one is replaced first, so events the
    /// changes cause compare against the new state.
    fn update(&mut self, p: WindowPlan, desk: (i32, i32), w: &RailWindow) {
        let old = std::mem::replace(&mut self.plan, p.clone());
        let win = self.win.window.clone();
        if p.rect != old.rect {
            win.set_outer_position(PhysicalPosition::new(p.rect.0, p.rect.1));
            let _ = win.request_inner_size(PhysicalSize::new(p.rect.2.max(1), p.rect.3.max(1)));
            self.win.fb = fb_origin(p.rect, desk);
            self.win.needs_full = true;
            win.request_redraw();
        }
        if p.title != old.title {
            win.set_title(&p.title);
        }
        if p.show != old.show {
            apply_show(&win, p.show, old.show);
        }
        #[cfg(windows)]
        if p.taskbar != old.taskbar {
            use winit::platform::windows::WindowExtWindows;
            win.set_skip_taskbar(!p.taskbar);
        }
        if p.topmost != old.topmost {
            win.set_window_level(if p.topmost {
                WindowLevel::AlwaysOnTop
            } else {
                WindowLevel::Normal
            });
        }
        if p.region != old.region {
            set_region(&win, &p.region);
        }
        self.set_icons(w);
    }
}

fn apply_show(win: &Window, show: Show, old: Show) {
    match show {
        Show::Hidden => win.set_visible(false),
        Show::Minimized => {
            win.set_visible(true);
            win.set_minimized(true);
        }
        Show::Shown => {
            win.set_visible(true);
            if old == Show::Minimized {
                win.set_minimized(false);
            }
        }
    }
}

#[cfg(windows)]
fn hwnd(win: &Window) -> Option<isize> {
    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match win.window_handle().map(|h| h.as_raw()) {
        Ok(RawWindowHandle::Win32(h)) => Some(h.hwnd.get()),
        _ => None,
    }
}

/// Clips the window to the remote window's visible region (rounded corners,
/// shaped windows); None restores the full rectangle.
fn set_region(win: &Window, region: &Option<Vec<(i32, i32, i32, i32)>>) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Graphics::Gdi::{
            CombineRgn, CreateRectRgn, DeleteObject, RGN_OR, SetWindowRgn,
        };
        let Some(h) = hwnd(win) else { return };
        // SAFETY: GDI region calls on regions created here; SetWindowRgn
        // takes ownership of the combined region.
        unsafe {
            let rgn = match region {
                None => std::ptr::null_mut(),
                Some(rects) => {
                    let all = CreateRectRgn(0, 0, 0, 0);
                    for &(x, y, w, h) in rects {
                        let r = CreateRectRgn(x, y, x + w, y + h);
                        CombineRgn(all, all, r, RGN_OR);
                        DeleteObject(r);
                    }
                    all
                }
            };
            SetWindowRgn(h as _, rgn, 1);
        }
    }
    #[cfg(not(windows))]
    let _ = (win, region);
}

/// Mirrors WS_EX_NOACTIVATE: clicking the window (a menu, a tooltip) does
/// not take the focus from the window it belongs to.
fn set_no_activate(win: &Window) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GWL_EXSTYLE, GetWindowLongPtrW, SetWindowLongPtrW,
        };
        let Some(h) = hwnd(win) else { return };
        // SAFETY: reads and writes the extended style of our own window.
        unsafe {
            let ex = GetWindowLongPtrW(h as _, GWL_EXSTYLE);
            SetWindowLongPtrW(h as _, GWL_EXSTYLE, ex | WS_EX_NOACTIVATE as isize);
        }
    }
    #[cfg(not(windows))]
    let _ = win;
}

/// Everything Remora keeps for one RemoteApp session.
#[derive(Default)]
pub struct RailSession {
    pub handle: Option<rdp::RailHandle>,
    pub launcher: Launcher,
    pub tracker: Tracker,
    pub linger: Linger,
    /// The connection's apps (their names).
    pub apps: Vec<AppEntry>,
    /// Where the session framebuffer starts on this PC's desktop.
    pub desk: (i32, i32),
    pub windows: Vec<AppWin>,
    /// The window the server made active, to focus once it shows.
    pub want_active: Option<u32>,
    /// Visible windows and notification icons at the last update.
    pub open: usize,
}

impl RailSession {
    /// Creates, moves, shows and closes local windows to match the server's
    /// window list. Returns why a window could not be opened, if one failed.
    pub fn sync(
        &mut self,
        el: &ActiveEventLoop,
        session: u64,
        state: &RailState,
    ) -> Option<String> {
        let plans = plan(state);
        self.windows.retain(|w| plans.iter().any(|p| p.id == w.id));
        let mut error = None;
        for p in plans {
            let Some(rw) = state.windows.get(&p.id) else {
                continue;
            };
            match self.windows.iter().position(|w| w.id == p.id) {
                Some(i) => self.windows[i].update(p, self.desk, rw),
                None if p.show != Show::Hidden => {
                    let owner = p
                        .owner
                        .and_then(|o| self.windows.iter().find(|w| w.id == o))
                        .map(|w| w.win.window.clone());
                    match open(el, session, p, owner.as_deref(), self.desk, rw) {
                        Ok(w) => self.windows.push(w),
                        Err(e) => error = Some(e),
                    }
                }
                None => {}
            }
        }
        if let Some(a) = self.want_active
            && let Some(w) = self.windows.iter().find(|w| w.id == a)
            && w.plan.show == Show::Shown
        {
            w.win.window.focus_window();
            self.want_active = None;
        }
        error
    }

    /// Presents new session pictures in every window.
    pub fn present(
        &mut self,
        fb: &rdp::Framebuffer,
        damage: &[rdp::Damage],
        full: bool,
        te: &mut ffwd_render::TextEngine,
        fonts: &crate::ui::Fonts,
    ) {
        for w in &mut self.windows {
            if full {
                w.win.needs_full = true;
            }
            if w.plan.show == Show::Shown {
                w.win.present(fb, damage, te, fonts);
            }
        }
    }
}

fn open(
    el: &ActiveEventLoop,
    session: u64,
    p: WindowPlan,
    owner: Option<&Window>,
    desk: (i32, i32),
    rw: &RailWindow,
) -> Result<AppWin, String> {
    let (x, y, w, h) = p.rect;
    let attrs = Window::default_attributes()
        .with_title(&p.title)
        .with_decorations(false)
        .with_position(PhysicalPosition::new(x, y))
        .with_inner_size(PhysicalSize::new(w.max(1), h.max(1)))
        .with_visible(true)
        // The server says which window is active; focus follows it.
        .with_active(false)
        .with_window_level(if p.topmost {
            WindowLevel::AlwaysOnTop
        } else {
            WindowLevel::Normal
        });
    #[cfg(windows)]
    let attrs = {
        use winit::platform::windows::WindowAttributesExtWindows;
        let mut a = attrs
            .with_skip_taskbar(!p.taskbar)
            .with_undecorated_shadow(false);
        if let Some(h) = owner.and_then(hwnd) {
            a = a.with_owner_window(h);
        }
        a
    };
    #[cfg(not(windows))]
    let _ = owner;
    let window = el.create_window(attrs).map_err(|e| e.to_string())?;
    if p.no_activate {
        set_no_activate(&window);
    }
    set_region(&window, &p.region);
    if p.show == Show::Minimized {
        window.set_minimized(true);
    }
    let win = SpanWin::new(
        Rc::new(window),
        SpanSpec {
            session,
            rect: (x, y, w as i32, h as i32),
            fb: fb_origin(p.rect, desk),
            first: false,
            title: p.title.clone(),
        },
    )?;
    let mut aw = AppWin {
        id: p.id,
        win,
        plan: p,
        icons: (None, None),
    };
    aw.set_icons(rw);
    aw.win.window.request_redraw();
    Ok(aw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::rail::{NotifyIcon, WindowRect, orders::Rect16};

    fn win(owner: u32, style: u32, ex: u32, show: u8, rect: (i32, i32, u32, u32)) -> RailWindow {
        RailWindow {
            owner,
            style,
            ex_style: ex,
            show_state: show,
            title: format!("w{owner}"),
            window_rect: WindowRect {
                x: rect.0,
                y: rect.1,
                width: rect.2,
                height: rect.3,
            },
            ..Default::default()
        }
    }

    fn state(list: &[(u32, RailWindow)]) -> RailState {
        RailState {
            windows: list.iter().cloned().collect(),
            ..Default::default()
        }
    }

    #[test]
    fn plan_maps_windows_to_local_windows() {
        let s = state(&[
            // A dialog owned by the main window, listed first.
            (1, win(7, 0, 0, 5, (300, 200, 400, 300))),
            (7, win(0, 0, 0, 3, (-1920, 0, 1920, 1040))),
            (8, win(0, WS_CHILD, 0, 5, (0, 0, 10, 10))),
            (9, win(0, 0, WS_EX_TOOLWINDOW, 5, (5, 5, 20, 20))),
            (10, win(0, 0, 0, 2, (10, 10, 100, 100))),
            (11, win(0, 0, 0, 0, (10, 10, 100, 100))),
            (
                12,
                win(7, 0, WS_EX_APPWINDOW | WS_EX_TOPMOST, 5, (1, 1, 2, 2)),
            ),
        ]);
        let p = plan(&s);
        let ids: Vec<u32> = p.iter().map(|w| w.id).collect();
        // Child windows get none; owners come before what they own.
        assert_eq!(ids, [7, 9, 10, 11, 1, 12]);
        let get = |id| p.iter().find(|w| w.id == id).unwrap();
        assert_eq!(get(7).rect, (-1920, 0, 1920, 1040), "desktop pixels");
        assert!(get(7).taskbar && get(7).owner.is_none());
        assert_eq!((get(1).taskbar, get(1).owner), (false, Some(7)));
        assert!(!get(9).taskbar, "tool window");
        assert!(get(12).taskbar && get(12).topmost, "WS_EX_APPWINDOW");
        assert_eq!(get(10).show, Show::Minimized);
        assert_eq!(get(11).show, Show::Hidden);
        assert_eq!(get(7).show, Show::Shown, "maximized shows");
    }

    #[test]
    fn cloaked_or_empty_windows_hide_and_unknown_owners_are_none() {
        let mut w = win(0, 0, 0, 5, (0, 0, 10, 10));
        w.cloaked = true;
        assert_eq!(show_of(&w), Show::Hidden);
        assert_eq!(show_of(&win(0, 0, 0, 5, (0, 0, 0, 10))), Show::Hidden);
        let p = plan(&state(&[(3, win(99, 0, 0, 5, (0, 0, 5, 5)))]));
        assert_eq!((p[0].owner, p[0].taskbar), (None, false));
    }

    #[test]
    fn visible_region_relative_to_the_window() {
        let mut w = win(0, 0, 0, 5, (100, 50, 40, 30));
        w.visible_offset = (100, 50);
        let r = |l, t, r, b| Rect16 {
            left: l,
            top: t,
            right: r,
            bottom: b,
        };
        w.visible_rects = vec![r(0, 0, 40, 30)];
        assert_eq!(region(&w), None, "the whole window");
        w.visible_rects = vec![r(2, 0, 38, 1), r(0, 1, 40, 30)];
        assert_eq!(region(&w), Some(vec![(2, 0, 36, 1), (0, 1, 40, 29)]));
        w.visible_offset = (90, 50);
        w.visible_rects = vec![r(10, 0, 20, 5), r(0, 0, 0, 0)];
        assert_eq!(region(&w), Some(vec![(0, 0, 10, 5)]), "empty dropped");
    }

    #[test]
    fn framebuffer_origin_and_damage_per_window() {
        // Desktop from (-1920, 0); a window at (-100, 20) of 300 x 200.
        let desk = (-1920, 0);
        let o = fb_origin((-100, 20, 300, 200), desk);
        assert_eq!(o, (1820, 20));
        let clip = |d| crate::span::clip_damage(d, o, (300, 200));
        assert_eq!(clip((1800, 0, 100, 100)), Some((0, 0, 80, 80)));
        assert_eq!(clip((2110, 210, 50, 50)), Some((290, 190, 10, 10)));
        assert_eq!(clip((0, 0, 1820, 1000)), None, "left of the window");
    }

    #[test]
    fn taskbar_actions_become_sys_commands_once() {
        assert_eq!(
            taskbar_command(Show::Shown, true),
            Some(SysCommand::Minimize)
        );
        assert_eq!(
            taskbar_command(Show::Minimized, false),
            Some(SysCommand::Restore)
        );
        // The local window only followed the server: nothing to send.
        assert_eq!(taskbar_command(Show::Minimized, true), None);
        assert_eq!(taskbar_command(Show::Shown, false), None);
        assert_eq!(taskbar_command(Show::Hidden, true), None);
    }

    #[test]
    fn launches_reuse_a_running_session_or_wait_for_a_connecting_one() {
        let c = |id, name, remote_app, connected, connecting| Candidate {
            id,
            name,
            host: "h",
            remote_app,
            connected,
            connecting,
        };
        // A desktop session of the same connection does not count.
        assert_eq!(
            launch_target([c(1, "a", false, true, false)], "a", "h"),
            None
        );
        assert_eq!(
            launch_target(
                [
                    c(1, "a", true, false, true),
                    c(2, "b", true, true, false),
                    c(3, "a", true, true, false),
                ],
                "a",
                "h"
            ),
            Some(3),
            "a connected one first"
        );
        assert_eq!(
            launch_target([c(4, "a", true, false, true)], "a", "h"),
            Some(4)
        );
        assert_eq!(
            launch_target([c(5, "a", true, false, false)], "a", "h"),
            None,
            "ended"
        );
        assert_eq!(
            launch_target([c(6, "a", true, true, false)], "a", "x"),
            None
        );

        let app = |p: &str| AppEntry {
            program: p.into(),
            ..Default::default()
        };
        let mut l = Launcher::default();
        assert!(l.launch(app("||a")).is_none(), "queued while connecting");
        assert!(l.launch(app("||b")).is_none());
        assert_eq!(l.queued().len(), 2);
        let sent: Vec<String> = l.attach().into_iter().map(|a| a.program).collect();
        assert_eq!(sent, ["||a", "||b"]);
        assert_eq!(
            l.launch(app("||c")).map(|a| a.program).as_deref(),
            Some("||c")
        );
        l.detach();
        assert!(l.launch(app("||d")).is_none());
    }

    #[test]
    fn tracker_knows_which_programs_run() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        t.launched("||Excel", t0);
        t.launched("||notepad", t0);
        assert_eq!(t.starting(t0), ["||Excel", "||notepad"]);
        // Hidden windows count for nobody.
        let mut s = state(&[(1, win(0, 0, 0, 0, (0, 0, 9, 9)))]);
        t.update(&s);
        assert!(t.running().is_empty());
        // Notepad's window says who it is; Excel's comes unnamed.
        let mut n = win(0, 0, 0, 5, (0, 0, 9, 9));
        n.app_id = Some(r"C:\Windows\System32\NOTEPAD.EXE".into());
        s.windows.insert(2, n);
        t.update(&s);
        assert_eq!(t.running(), ["||notepad"]);
        s.windows.insert(3, win(0, 0, 0, 5, (0, 0, 9, 9)));
        // Its dialog belongs to Excel through the owner.
        s.windows.insert(4, win(3, 0, 0, 5, (0, 0, 9, 9)));
        t.update(&s);
        assert_eq!(t.running(), ["||Excel", "||notepad"]);
        assert!(t.starting(t0).is_empty());
        s.windows.remove(&3);
        t.update(&s);
        assert_eq!(t.running(), ["||Excel", "||notepad"], "the dialog is open");
        s.windows.remove(&4);
        s.windows.remove(&2);
        t.update(&s);
        assert!(t.running().is_empty());
        // A refused launch stops counting as starting.
        t.launched("||calc", t0);
        t.failed("CALC");
        assert!(t.starting(t0).is_empty());
        t.launched("||paint", t0);
        assert!(t.starting(t0 + START_WAIT).is_empty(), "gave up waiting");
        assert_eq!(t.next_wake(t0), Some(t0 + START_WAIT));
    }

    #[test]
    fn empty_session_disconnects_after_ten_seconds_unless_an_app_starts() {
        let t0 = Instant::now();
        let s = |n| t0 + Duration::from_secs(n);
        let mut l = Linger::default();
        // Connecting, first app starting: no window yet, never armed.
        assert!(!l.update(t0, 0, true));
        assert!(!l.update(s(1), 0, false));
        assert_eq!(l.deadline(), None);
        l.update(s(2), 1, false);
        // The last window closes: armed once, due ten seconds later.
        assert!(l.update(s(3), 0, false));
        assert!(!l.update(s(4), 0, false), "armed once");
        assert_eq!(l.deadline(), Some(s(13)));
        assert!(!l.due(s(12)));
        assert!(l.due(s(13)));
        // Another app starts: disarmed; its window keeps the session.
        l.update(s(5), 0, true);
        assert!(!l.due(s(20)));
        l.update(s(6), 1, false);
        assert!(l.update(s(30), 0, false));
        assert!(l.due(s(40)));
        // The only app failed to start: the session ends the same way.
        let mut l = Linger::default();
        l.update(t0, 0, true);
        l.launch_failed();
        assert!(l.update(s(1), 0, false));
        assert!(l.due(s(11)));
        // A notification icon also keeps it open.
        let mut st = state(&[]);
        st.notify_icons.insert((1, 1), NotifyIcon::default());
        assert_eq!(open_count(&st), 1);
        st.notify_icons.get_mut(&(1, 1)).unwrap().hidden = true;
        assert_eq!(open_count(&st), 0);
    }

    #[test]
    fn exec_failures_in_plain_words() {
        let apps = vec![AppEntry {
            name: "Excel".into(),
            program: "||Excel".into(),
            ..Default::default()
        }];
        let r = |result, program: &str| ExecResult {
            flags: 0,
            result,
            raw_result: 0,
            program: program.into(),
        };
        assert_eq!(
            exec_failure(&apps, &r(3, "||excel")),
            "Excel could not start: the server does not allow this program."
        );
        assert_eq!(
            exec_failure(&apps, &r(5, r"C:\tools\report.exe")),
            "Report could not start: the program was not found on the server."
        );
        assert!(exec_error(7).contains("locked"));
        assert!(exec_error(42).contains("unknown"));
    }

    #[test]
    fn taskbar_position_from_the_work_area() {
        let m = [0, 0, 1920, 1080];
        assert_eq!(taskbar_rect(m, [0, 0, 1920, 1032]), [0, 1032, 1920, 1080]);
        assert_eq!(taskbar_rect(m, [0, 48, 1920, 1080]), [0, 0, 1920, 48]);
        assert_eq!(taskbar_rect(m, [60, 0, 1920, 1080]), [0, 0, 60, 1080]);
        assert_eq!(taskbar_rect(m, [0, 0, 1860, 1080]), [1860, 0, 1920, 1080]);
        assert_eq!(taskbar_rect(m, m), [0; 4], "auto-hide");
    }
}
