//! The session tab's own screens and its floating toolbar.
//!
//! - Connecting: who and where, the connection steps as they happen (done,
//!   current, still to come), the time so far, Cancel.
//! - Reconnecting after a network drop: the last picture dimmed under a card
//!   with the attempt and Cancel.
//! - Failed: the cause in plain words with a fix, where in the sequence it
//!   broke, and Retry, Edit connection, Copy details, Open log.
//! - Ended: why and how long it ran, Reconnect and Close tab.
//! - The toolbar: a pill floating at the top centre of the picture (status
//!   and name, then icon buttons). It hides while the session has the
//!   keyboard and the pointer is elsewhere, and comes back at the top edge,
//!   on Alt, on a tap of the handle left in its place, and stays while the
//!   panel or its menu is open. The same pill sits on full screen and on
//!   the monitor windows of a spanned session (`span`).
//!
//! The pill, its handle and the reconnect card are painted over the remote
//! picture by [`Ui::paint_session_overlay`] (part of `paint_overlays`), after the app has copied the picture
//! in; showing or hiding the pill only repaints its rectangle
//! ([`Ui::take_overlay_damage`]).

use std::time::{Duration, Instant};

use rdp::ConnectStep;

use super::*;
use crate::failure::{self, Cause, EndReason, Failure};

/// Toolbar pill height (logical px) and its gap to the picture's top edge.
const PILL_H: f32 = 40.0;
const PILL_TOP: f32 = 10.0;
/// Shadow blur around the pill and its menu.
const PILL_BLUR: f32 = 14.0;
/// Height of the band above a session without a picture (RemoteApp,
/// spanned) that holds the pill.
const BAND_H: f32 = 60.0;

/// What a session tab knows about its connection beyond its state: the
/// steps reached, timings, and why it failed or ended.
#[derive(Clone, Debug, Default)]
pub struct Live {
    /// RD Gateway host, user and port of the connection (for the step
    /// labels and the fixes).
    pub gateway: Option<String>,
    pub user: String,
    pub port: u16,
    /// The last connection step reached in this attempt.
    pub step: Option<ConnectStep>,
    /// A connect-time redirection's target.
    pub redirected: Option<String>,
    /// When this attempt started, and when the session came up.
    pub started: Option<Instant>,
    pub connected_at: Option<Instant>,
    /// How long the session that ended had run.
    pub duration: Option<Duration>,
    /// Automatic reconnect: attempt (1-based) and attempts in all.
    pub reconnect: Option<(usize, usize)>,
    /// The app kept the last picture for the reconnect backdrop.
    pub has_frame: bool,
    pub failure: Option<Failure>,
    pub ended: Option<EndReason>,
}

impl Live {
    pub fn for_config(cfg: &rdp::Config) -> Live {
        Live {
            gateway: cfg.gateway.as_ref().map(|g| g.host.clone()),
            user: cfg.username.clone(),
            port: cfg.port,
            started: Some(Instant::now()),
            ..Live::default()
        }
    }

    /// A new attempt starts (reconnect, redirect, retry).
    pub fn restart(&mut self) {
        self.step = None;
        self.redirected = None;
        self.started = Some(Instant::now());
        self.failure = None;
        self.ended = None;
    }

    pub fn progress(&mut self, step: ConnectStep) {
        match step {
            ConnectStep::Redirected(to) => {
                self.redirected = Some(to);
                self.step = None;
            }
            s => self.step = Some(s),
        }
    }

    pub fn connected(&mut self) {
        self.connected_at = Some(Instant::now());
        self.reconnect = None;
        self.has_frame = false;
    }

    /// The session ended (or failed): note how long it ran.
    pub fn stopped(&mut self) {
        if let Some(t) = self.connected_at.take() {
            self.duration = Some(t.elapsed());
        }
        self.reconnect = None;
        self.has_frame = false;
    }

    /// The steps this connection goes through, in order.
    fn steps(&self) -> Vec<ConnectStep> {
        use ConnectStep as S;
        let mut v = if self.gateway.is_some() {
            vec![S::Gateway]
        } else {
            vec![S::Resolving, S::Tcp]
        };
        v.extend([
            S::Tls,
            S::SignIn,
            S::Licensing,
            S::Capabilities,
            S::FirstPicture,
        ]);
        v
    }

    /// Index of `step` in [`Live::steps`].
    fn index(&self, step: Option<&ConnectStep>) -> Option<usize> {
        let step = step?;
        let steps = self.steps();
        steps.iter().position(|s| s == step).or(match step {
            // Through a gateway these happen inside its step.
            ConnectStep::Resolving | ConnectStep::Tcp => Some(0),
            _ => None,
        })
    }

    fn label(&self, step: &ConnectStep, host: &str) -> String {
        match step {
            ConnectStep::Resolving => format!("Finding {host}"),
            ConnectStep::Tcp => format!("Connecting to port {}", self.port),
            ConnectStep::Gateway => format!(
                "Reaching RD Gateway {}",
                self.gateway.as_deref().unwrap_or("")
            ),
            ConnectStep::Tls => "Securing the connection".into(),
            ConnectStep::SignIn if self.user.is_empty() => "Signing in".into(),
            ConnectStep::SignIn => format!("Signing in as {}", self.user),
            ConnectStep::Licensing => "Checking the licence".into(),
            ConnectStep::Capabilities => "Setting up the session".into(),
            ConnectStep::FirstPicture => "Waiting for the first picture".into(),
            ConnectStep::Redirected(to) => format!("Redirected to {to}"),
        }
    }
}

/// A one-word label of a step for the trail on the error screen.
fn short(step: &ConnectStep) -> &'static str {
    match step {
        ConnectStep::Resolving => "Find",
        ConnectStep::Tcp => "Connect",
        ConnectStep::Gateway => "Gateway",
        ConnectStep::Tls => "Secure",
        ConnectStep::SignIn => "Sign in",
        ConnectStep::Licensing => "Licence",
        ConnectStep::Capabilities => "Set up",
        ConnectStep::FirstPicture => "Picture",
        ConnectStep::Redirected(_) => "Redirect",
    }
}

/// "0:07", "1:02:05".
fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

// ---- The toolbar pill (shared with the span windows) -------------------

/// A toolbar button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Panel,
    FullScreen,
    Record,
    CtrlAltDel,
    Disconnect,
    /// The command palette (Ctrl+K).
    Palette,
    /// The overflow menu.
    More,
    /// Span windows: bring the session back into the main window.
    Window,
}

/// One button of a pill: what it does and how it looks now.
#[derive(Clone, Copy, Debug)]
pub struct ToolItem {
    pub tool: Tool,
    pub icon: Icon,
    /// A toggle that is on (the panel, full screen): accent tint.
    pub on: bool,
    /// Red on hover (Disconnect), or red always (recording).
    pub danger: bool,
    pub live: bool,
}

impl ToolItem {
    pub fn new(tool: Tool, icon: Icon) -> ToolItem {
        ToolItem {
            tool,
            icon,
            on: false,
            danger: false,
            live: false,
        }
    }
    pub fn on(mut self, on: bool) -> ToolItem {
        self.on = on;
        self
    }
    pub fn danger(mut self) -> ToolItem {
        self.danger = true;
        self
    }
    pub fn live(mut self, live: bool) -> ToolItem {
        self.live = live;
        self
    }
}

/// A laid-out pill.
#[derive(Clone, Debug, Default)]
pub struct Pill {
    pub rect: Rect,
    pub name: String,
    pub dot: u32,
    /// A short red badge after the name ("REC").
    pub badge: Option<&'static str>,
    pub items: Vec<ToolItem>,
    pub buttons: Vec<Rect>,
    name_w: i32,
    divider_x: i32,
}

impl Pill {
    /// The pill with its shadow: what showing or hiding it repaints.
    pub fn bounds(&self, s: f32) -> Rect {
        let b = (PILL_BLUR * s).ceil() as i32 + 1;
        Rect::new(
            self.rect.x - b,
            self.rect.y - b,
            self.rect.w + 2 * b,
            self.rect.h + 2 * b + b / 3 + 1,
        )
    }

    pub fn tool_at(&self, x: i32, y: i32) -> Option<Tool> {
        self.buttons
            .iter()
            .zip(&self.items)
            .find(|(r, _)| r.contains(x, y))
            .map(|(_, it)| it.tool)
    }
}

/// Lays out a pill centred on `cx` with its top at `top`, at most `max_w`
/// wide (the name gives way first).
#[allow(clippy::too_many_arguments)]
pub fn pill_layout(
    te: &mut TextEngine,
    f: &Fonts,
    s: f32,
    cx: i32,
    top: i32,
    max_w: i32,
    name: &str,
    dot: u32,
    badge: Option<&'static str>,
    items: Vec<ToolItem>,
) -> Pill {
    let p = |v: f32| (v * s).round() as i32;
    let h = p(PILL_H);
    let bw = p(32.0);
    let gap = p(2.0);
    let n = items.len() as i32;
    let buttons_w = n * bw + (n - 1).max(0) * gap;
    let badge_w = badge.map_or(0, |b| {
        te.measure(f.semi, 10.0 * s, b).ceil() as i32 + p(12.0) + p(8.0)
    });
    let lead = p(16.0) + p(8.0) + p(8.0);
    let fixed = lead + badge_w + p(12.0) + 1 + p(8.0) + buttons_w + p(4.0);
    let want = te.measure(f.semi, 12.5 * s, name).ceil() as i32;
    let name_w = want.min(p(240.0)).min((max_w - fixed).max(p(40.0)));
    let w = fixed + name_w;
    let rect = Rect::new(cx - w / 2, top, w, h);
    let divider_x = rect.x + lead + name_w + badge_w + p(12.0);
    let mut x = divider_x + 1 + p(8.0);
    let mut buttons = Vec::with_capacity(items.len());
    for _ in &items {
        buttons.push(Rect::new(x, top + (h - bw) / 2, bw, bw));
        x += bw + gap;
    }
    Pill {
        rect,
        name: name.to_string(),
        dot,
        badge,
        items,
        buttons,
        name_w,
        divider_x,
    }
}

/// Paints a pill: shadow, raised round body, status dot and name, then
/// its buttons (hovered, pressed, keyboard-focused by index).
#[allow(clippy::too_many_arguments)]
pub fn paint_pill(
    cv: &mut Canvas,
    te: &mut TextEngine,
    f: &Fonts,
    s: f32,
    pill: &Pill,
    hover: Option<Tool>,
    press: Option<Tool>,
    focus: Option<usize>,
) {
    let c = pal();
    let mut k = Kit::new(cv, te, f, s);
    let r = pill.rect;
    let rad = r.h as f32 / 2.0;
    k.shadow(r, rad / s, PILL_BLUR);
    let border = if c.dark { c.border_strong } else { c.border };
    k.cv.round_border(r, rad, border, c.surface_raised);
    let cy = r.y + r.h / 2;
    k.cv.fill_circle((r.x + k.p(20.0)) as f32, cy as f32, 4.0 * s, pill.dot);
    let tx = r.x + k.p(32.0);
    let base = k.baseline(Font::Semi, 12.5, r);
    let end = k.text(Font::Semi, 12.5, tx, base, &pill.name, c.text, pill.name_w);
    if let Some(b) = pill.badge {
        let bw = k.measure(Font::Semi, 10.0, b) + k.p(12.0);
        let br = Rect::new(end.max(tx) + k.p(8.0), cy - k.p(9.0), bw, k.p(18.0));
        k.cv.fill_round(br, br.h as f32 / 2.0, c.danger);
        k.text_center(Font::Semi, 10.0, br, b, c.on_solid);
    }
    k.cv.fill(
        Rect::new(pill.divider_x, r.y + k.p(10.0), 1, r.h - k.p(20.0)),
        c.divider,
    );
    for (i, (b, it)) in pill.buttons.iter().zip(&pill.items).enumerate() {
        let hov = hover == Some(it.tool);
        let pr = hov && press == Some(it.tool);
        let brad = b.h as f32 / 2.0;
        let (fill, fg) = if it.danger && hov {
            (Some(c.danger_subtle), c.danger)
        } else if it.on {
            let fill = if hov {
                theme::mix(c.accent_subtle, c.accent, 30)
            } else {
                c.accent_subtle
            };
            (Some(fill), c.accent)
        } else if pr {
            (Some(c.surface_pressed), c.text)
        } else if hov {
            (Some(c.surface_hover), c.text)
        } else {
            (None, c.text_secondary)
        };
        if let Some(fill) = fill {
            k.cv.fill_round(*b, brad, fill);
        }
        let fg = if it.live { c.danger } else { fg };
        k.icon_in(it.icon, *b, 16.0, fg);
        if focus == Some(i) {
            k.focus_ring(*b, brad / s);
        }
    }
}

/// The handle left at the top centre while the pill hides: its visible tab
/// and the larger rectangle a tap or click hits.
pub fn handle_rects(s: f32, area: Rect) -> (Rect, Rect) {
    let p = |v: f32| (v * s).round() as i32;
    let (w, h) = (p(60.0), p(14.0));
    let tab = Rect::new(area.x + (area.w - w) / 2, area.y, w, h);
    let (hw, hh) = (p(88.0), p(26.0));
    let hit = Rect::new(area.x + (area.w - hw) / 2, area.y, hw, hh);
    (tab, hit)
}

/// Paints the handle tab: a raised tongue with a small chevron.
pub fn paint_handle(cv: &mut Canvas, s: f32, tab: Rect, hover: bool) {
    let c = pal();
    let rad = 6.0 * s;
    let r = Rect::new(tab.x, tab.y - rad as i32, tab.w, tab.h + rad as i32);
    let border = if c.dark { c.border_strong } else { c.border };
    let fill = if hover {
        c.surface_hover
    } else {
        c.surface_raised
    };
    let old = cv.set_clip(tab.intersect(cv.clip()));
    cv.round_border(r, rad, border, fill);
    cv.set_clip(old);
    let d = (10.0 * s).round();
    crate::icons::draw(
        cv,
        Icon::ChevronDown,
        tab.x as f32 + (tab.w as f32 - d) / 2.0,
        tab.y as f32 + (tab.h as f32 - d) / 2.0,
        d,
        if hover { c.accent } else { c.text_muted },
    );
}

// ---- The toolbar's state in the main window ----------------------------

/// One row of the toolbar's menu.
#[derive(Clone, Debug)]
struct MenuItem {
    icon: Icon,
    label: &'static str,
    hit: Hit,
}

#[derive(Clone, Debug)]
struct Layout {
    /// The session picture (or the screen) the pill floats over.
    area: Rect,
    pill: Pill,
    hits: Vec<Hit>,
    handle: (Rect, Rect),
    /// Always shown: no picture under it (RemoteApp, spanned).
    fixed: bool,
    menu: Vec<MenuItem>,
    menu_rect: Rect,
}

/// The toolbar's state and last layout.
#[derive(Default)]
pub struct Toolbar {
    /// Opened by its handle or the keyboard (until the session is clicked).
    open: bool,
    /// Alt is held while the session has the keyboard.
    alt: bool,
    menu: bool,
    /// Keyboard focus on a button (index).
    focus: Option<usize>,
    layout: Option<Layout>,
    /// The reconnect card is drawn over the dimmed last picture.
    dim: Option<(u64, String, String)>,
    /// What changed on the overlay since the last present.
    damage: Option<Rect>,
}

fn union(a: Rect, b: Rect) -> Rect {
    if a.is_empty() {
        return b;
    }
    if b.is_empty() {
        return a;
    }
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    Rect::new(
        x,
        y,
        a.right().max(b.right()) - x,
        a.bottom().max(b.bottom()) - y,
    )
}

impl Ui {
    /// The pill is on screen (otherwise only its handle).
    fn pill_shown(&self) -> bool {
        let tb = &self.toolbar;
        let Some(l) = &tb.layout else {
            return false;
        };
        l.fixed
            || self.bar_pinned
            || !self.session_focus
            || self.drawer
            || tb.open
            || tb.alt
            || tb.menu
            || tb.focus.is_some()
            || self.bar_revealed
    }

    /// Everything the overlay paints now (pill with its shadow and menu,
    /// or the handle), for damage.
    pub fn overlay_rect(&self) -> Option<Rect> {
        let l = self.toolbar.layout.as_ref()?;
        Some(self.overlay_rect_of(l, self.pill_shown()))
    }

    fn overlay_rect_of(&self, l: &Layout, shown: bool) -> Rect {
        if !shown {
            return l.handle.0;
        }
        let mut r = l.pill.bounds(self.scale);
        if self.toolbar.menu {
            r = union(r, inflate(l.menu_rect, self.scale));
        }
        r
    }

    /// The rectangle to repaint over the picture since the last call, when
    /// only the overlay changed.
    pub fn take_overlay_damage(&mut self) -> Option<Rect> {
        self.toolbar.damage.take()
    }

    /// The picture is the dimmed backdrop of a reconnect (the app copies in
    /// the last picture it kept, not the new connection's).
    pub fn session_backdrop(&self) -> bool {
        self.toolbar.dim.is_some()
    }

    /// The point is on the toolbar (pill, menu or handle): not the session's.
    pub fn over_overlay(&self, x: i32, y: i32) -> bool {
        self.overlay_hit(x, y).is_some()
    }

    /// Rectangles touch must leave to the toolbar.
    pub fn touch_holes(&self) -> Vec<Rect> {
        let Some(l) = &self.toolbar.layout else {
            return Vec::new();
        };
        if self.pill_shown() {
            let mut v = vec![l.pill.rect];
            if self.toolbar.menu {
                v.push(l.menu_rect);
            }
            v
        } else {
            vec![l.handle.1]
        }
    }

    /// The toolbar's hit at a point, above everything else.
    pub(super) fn overlay_hit(&self, x: i32, y: i32) -> Option<Hit> {
        let l = self.toolbar.layout.as_ref()?;
        if !self.pill_shown() {
            return l.handle.1.contains(x, y).then_some(Hit::ToolbarHandle);
        }
        if self.toolbar.menu && l.menu_rect.contains(x, y) {
            let i = menu_rows(self.scale, l.menu_rect, l.menu.len())
                .iter()
                .position(|r| r.contains(x, y))?;
            return Some(l.menu[i].hit);
        }
        if let Some(i) = l.pill.buttons.iter().position(|r| r.contains(x, y)) {
            return Some(l.hits[i]);
        }
        l.pill.rect.contains(x, y).then_some(Hit::ToolbarBody)
    }

    fn mark_overlay(&mut self, was: Option<Rect>) {
        let now = self.overlay_rect();
        let r = match (was, now) {
            (Some(a), Some(b)) => union(a, b),
            (a, b) => a.or(b).unwrap_or_default(),
        };
        if !r.is_empty() {
            self.toolbar.damage = Some(match self.toolbar.damage {
                Some(d) => union(d, r),
                None => r,
            });
        }
    }

    /// The pointer moved: the top edge (or the handle) shows the pill,
    /// leaving its neighbourhood hides it again.
    pub(super) fn toolbar_pointer(&mut self, x: i32, y: i32) {
        let Some(l) = &self.toolbar.layout else {
            self.bar_revealed = false;
            return;
        };
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let a = l.area;
        let want = if self.bar_revealed {
            let pill = l.pill.rect;
            let mut zone = Rect::new(
                pill.x - p(40.0),
                a.y,
                pill.w + p(80.0),
                pill.bottom() + p(28.0) - a.y,
            );
            if self.toolbar.menu {
                zone = union(zone, inflate(l.menu_rect, s));
            }
            zone.contains(x, y)
        } else {
            let edge = Rect::new(a.x, a.y, a.w, p(3.0).max(2));
            edge.contains(x, y) || l.handle.1.contains(x, y)
        };
        if want != self.bar_revealed {
            let was = self.overlay_rect();
            self.bar_revealed = want;
            if !want {
                self.toolbar.menu = false;
            }
            self.mark_overlay(was);
        }
    }

    /// Alt went down or up while the session has the keyboard: the pill
    /// shows while it is held.
    pub fn alt_key(&mut self, down: bool) {
        if self.toolbar.alt != down {
            let was = self.overlay_rect();
            self.toolbar.alt = down;
            self.mark_overlay(was);
        }
    }

    /// A click went into the session: the toolbar folds away.
    pub(super) fn toolbar_reset(&mut self) {
        self.toolbar.open = false;
        self.toolbar.menu = false;
        self.toolbar.focus = None;
    }

    /// Hover moved between toolbar parts and the picture only: just the
    /// overlay needs repainting.
    pub(super) fn overlay_hover(&mut self, old: Option<Hit>, new: Option<Hit>) -> bool {
        let quiet = |h: Option<Hit>| match h {
            None | Some(Hit::Session(_)) => true,
            Some(h) => self.is_overlay_hit(h),
        };
        if quiet(old) && quiet(new) && self.toolbar.layout.is_some() {
            let toolbar = |h: Option<Hit>| h.is_some_and(|h| self.is_overlay_hit(h));
            if toolbar(old) || toolbar(new) {
                self.mark_overlay(None);
            }
            true
        } else {
            false
        }
    }

    fn is_overlay_hit(&self, h: Hit) -> bool {
        let Some(l) = &self.toolbar.layout else {
            return false;
        };
        matches!(h, Hit::ToolbarHandle | Hit::ToolbarBody)
            || l.hits.contains(&h)
            || l.menu.iter().any(|m| m.hit == h)
    }

    /// Keys for the toolbar when neither the session nor a field has the
    /// keyboard: Tab and the arrows move between its buttons, Enter or
    /// Space presses one, Esc leaves it. None: not the toolbar's key.
    pub(super) fn toolbar_key(&mut self, k: &Key) -> Option<Option<Action>> {
        if self.focus.is_some() || self.session_focus || self.confirm_exit.is_some() {
            return None;
        }
        let n = self.toolbar.layout.as_ref()?.hits.len();
        if n == 0 {
            return None;
        }
        let cur = self.toolbar.focus;
        let next = |back: bool| match (cur, back) {
            (None, false) => 0,
            (None, true) => n - 1,
            (Some(i), false) => (i + 1) % n,
            (Some(i), true) => (i + n - 1) % n,
        };
        match k {
            Key::Tab | Key::Right => self.toolbar.focus = Some(next(false)),
            Key::BackTab | Key::Left => self.toolbar.focus = Some(next(true)),
            Key::Enter | Key::Char(' ') if cur.is_some() => {
                let hit = self.toolbar.layout.as_ref()?.hits[cur?];
                return Some(self.activate(hit));
            }
            Key::Esc if cur.is_some() || self.toolbar.menu => {
                self.toolbar.focus = None;
                self.toolbar.menu = false;
            }
            _ => return None,
        }
        Some(None)
    }

    /// The toolbar's and the session screens' own clicks.
    pub(super) fn activate_view(&mut self, hit: Hit) -> Option<Action> {
        match hit {
            Hit::ToolbarHandle => {
                self.toolbar.open = !self.toolbar.open;
                self.toolbar.menu = false;
            }
            Hit::ToolbarMore => self.toolbar.menu = !self.toolbar.menu,
            Hit::ToolbarBody => {}
            Hit::EditConnection(id) => {
                let t = self.tabs.iter().find(|t| t.id == id)?;
                let (name, host) = (t.name.clone(), t.host.clone());
                match self
                    .store
                    .connections
                    .iter()
                    .position(|c| c.name == name && c.host == host)
                {
                    Some(i) => {
                        self.select(i);
                        self.active = None;
                        self.settings_open = false;
                    }
                    None => self.set_message(
                        format!("{name} is no longer a saved connection."),
                        Tone::Warning,
                    ),
                }
            }
            Hit::CopyDetails(id) => {
                let text = self.failure_details(id)?;
                self.set_message("Copied the details to the clipboard.", Tone::Muted);
                return Some(Action::CopyText(text));
            }
            _ => {}
        }
        None
    }

    /// Any click but the menu button closes the toolbar's menu.
    pub(super) fn menu_done(&mut self) {
        self.toolbar.menu = false;
    }

    /// Nothing of the toolbar is shown (a dialog covers the window).
    pub(super) fn toolbar_clear(&mut self) {
        self.toolbar.layout = None;
        self.toolbar.dim = None;
    }

    /// The technical text of a failed session, for a bug report.
    fn failure_details(&self, id: u64) -> Option<String> {
        let t = self.tabs.iter().find(|t| t.id == id)?;
        let why = match &t.state {
            TabState::Failed(w) | TabState::Ended(w) => w.clone(),
            _ => String::new(),
        };
        let l = &t.live;
        let mut out = format!(
            "Remora {}\nConnection: {} ({}:{})\n",
            env!("CARGO_PKG_VERSION"),
            t.name,
            t.host,
            l.port
        );
        if let Some(g) = &l.gateway {
            out += &format!("RD Gateway: {g}\n");
        }
        if let Some(r) = &l.redirected {
            out += &format!("Redirected to: {r}\n");
        }
        if let Some(f) = &l.failure {
            out += &format!("Cause: {} ({:?})\n", f.cause.title(), f.cause);
            if let Some(s) = &f.step {
                out += &format!("Failed while: {}\n", l.label(s, &t.host));
            }
        }
        out += &format!("Error: {why}\n");
        Some(out)
    }

    // ---- Painting ------------------------------------------------------

    /// The session tab: picture area (or one of its screens), the panel
    /// beside a running session, and the toolbar's layout.
    pub(super) fn paint_session(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        content: Rect,
        id: u64,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        self.session_clip = None;
        self.toolbar.layout = None;
        self.toolbar.dim = None;
        let Some(tab) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (host, state, name) = (tab.host.clone(), tab.state.clone(), tab.name.clone());
        let (spanned, apps, live) = (tab.spanned, tab.remote_app.is_some(), tab.live.clone());
        let connected = matches!(state, TabState::Connected { .. });
        let picture = connected && !spanned && !apps;

        let mut area = content;
        // The panel sits beside a running session only.
        if self.drawer && connected {
            let dw = p(DRAWER_W).min(area.w / 2);
            let drawer = Rect::new(area.right() - dw, area.y, dw, area.h);
            area.w -= dw + 1;
            cv.fill(Rect::new(area.right(), area.y, 1, area.h), c.divider);
            self.paint_drawer(cv, te, f, drawer, id);
        }
        let mut pill_area = area;
        if connected && !picture {
            // No picture to float over: the pill gets a band of its own.
            let band = Rect::new(area.x, area.y, area.w, p(BAND_H));
            cv.fill(band, c.bg);
            pill_area = band;
            area.y += band.h;
            area.h -= band.h;
        }
        cv.fill(area, if picture { c.bg_sidebar } else { c.bg });
        if connected {
            self.layout_toolbar(te, f, pill_area, id, !picture);
        }
        match state {
            TabState::Connected { .. } if spanned => {
                let y = self.state_card(
                    cv,
                    te,
                    f,
                    area,
                    Icon::Monitors,
                    Tone::Accent,
                    "This session is on its monitors",
                    "Ctrl+Alt+Break or the toolbar at their top edge brings it back here.",
                );
                let b = Button::primary("Show it in this window").icon(Icon::Monitor);
                let bw = self.btn_w(te, f, &b);
                self.btn(
                    cv,
                    te,
                    f,
                    Rect::new(area.x + (area.w - bw) / 2, y, bw, p(36.0)),
                    &b,
                    Hit::Unspan(id),
                );
            }
            TabState::Connected { .. } if apps => self.paint_apps_tab(cv, te, f, area, id),
            TabState::Connected { .. } => {
                self.session_area = Some((id, area));
                self.hits.push((area, Hit::Session(id)));
            }
            TabState::Connecting => {
                let cert = self
                    .tabs
                    .iter()
                    .find(|t| t.id == id)
                    .and_then(|t| t.cert.clone());
                match (cert, live.reconnect) {
                    (Some(cp), _) => {
                        self.paint_cert_prompt(cv, te, f, area, id, &cp.host.clone(), &cp)
                    }
                    (None, Some((n, of))) if live.has_frame => {
                        // The last picture, dimmed, under the reconnect card.
                        self.session_area = Some((id, area));
                        let step = live
                            .step
                            .as_ref()
                            .map(|st| live.label(st, &host))
                            .unwrap_or_else(|| "Waiting to try again".into());
                        self.toolbar.dim = Some((id, format!("Attempt {n} of {of}"), step));
                        let card = reconnect_card(s, area);
                        let cancel = cancel_rect(te, f, s, card);
                        self.hits.push((area, Hit::ToolbarBody));
                        self.hits.push((cancel, Hit::Disconnect(id)));
                    }
                    _ => self.paint_connecting(cv, te, f, area, id, &name, &host, &live),
                }
            }
            TabState::Failed(why) => {
                self.paint_failed(cv, te, f, area, id, &name, &host, &live, &why)
            }
            TabState::Ended(why) => self.paint_ended(cv, te, f, area, id, &host, &live, &why),
        }
    }

    /// The pill's layout over `area`, for this session's state.
    fn layout_toolbar(&mut self, te: &mut TextEngine, f: &Fonts, area: Rect, id: u64, fixed: bool) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (name, recording, apps) = (t.name.clone(), t.recording, t.remote_app.is_some());
        let spanned = t.spanned;
        let mut items = vec![(
            ToolItem::new(Tool::Panel, Icon::PanelRight).on(self.drawer),
            Hit::Drawer,
        )];
        if !apps && !spanned {
            let icon = if self.fullscreen {
                Icon::ExitFullscreen
            } else {
                Icon::Fullscreen
            };
            items.push((
                ToolItem::new(Tool::FullScreen, icon).on(self.fullscreen),
                Hit::FullScreen,
            ));
            // Red either way: a record dot, or Stop while it records.
            let icon = if recording { Icon::Stop } else { Icon::Record };
            items.push((
                ToolItem::new(Tool::Record, icon).live(true),
                Hit::Record(id),
            ));
        }
        if !apps {
            items.push((
                ToolItem::new(Tool::CtrlAltDel, Icon::Keyboard),
                Hit::CtrlAltDel(id),
            ));
        }
        items.push((
            ToolItem::new(Tool::Disconnect, Icon::Power).danger(),
            Hit::Disconnect(id),
        ));
        items.push((ToolItem::new(Tool::Palette, Icon::Command), Hit::Palette));
        items.push((ToolItem::new(Tool::More, Icon::More), Hit::ToolbarMore));
        let (tools, hits): (Vec<ToolItem>, Vec<Hit>) = items.into_iter().unzip();
        let top = if fixed {
            area.y + (area.h - p(PILL_H)) / 2
        } else {
            area.y + p(PILL_TOP)
        };
        let pill = pill_layout(
            te,
            f,
            s,
            area.x + area.w / 2,
            top,
            area.w - p(24.0),
            &name,
            c.success,
            recording.then_some("REC"),
            tools,
        );
        let pin = if self.bar_pinned {
            "Hide toolbar automatically"
        } else {
            "Keep toolbar shown"
        };
        let menu = vec![
            MenuItem {
                icon: Icon::Pin,
                label: pin,
                hit: Hit::PinBar,
            },
            MenuItem {
                icon: Icon::Refresh,
                label: "Reconnect",
                hit: Hit::Reconnect(id),
            },
            MenuItem {
                icon: Icon::Close,
                label: "Close tab",
                hit: Hit::CloseTab(id),
            },
        ];
        let more = *pill.buttons.last().unwrap_or(&pill.rect);
        let mw = p(236.0);
        let mh = p(8.0) * 2 + menu.len() as i32 * p(34.0);
        let mx = (more.right() + p(6.0) - mw).max(area.x + p(8.0));
        let menu_rect = Rect::new(mx, pill.rect.bottom() + p(6.0), mw, mh);
        self.toolbar.layout = Some(Layout {
            area,
            handle: handle_rects(s, area),
            pill,
            hits,
            fixed,
            menu,
            menu_rect,
        });
    }

    /// Paints what floats over the session picture: the reconnect card on
    /// the dimmed picture, the pill (and its menu) or its handle. The app
    /// calls it after copying the picture in; `cv`'s clip limits it to a
    /// damaged part.
    pub fn paint_session_overlay(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let s = self.scale;
        if let (Some((_, area)), Some((id, attempt, step))) =
            (self.session_area, self.toolbar.dim.clone())
        {
            self.paint_reconnect_card(cv, te, f, area, id, &attempt, &step);
        }
        let Some(l) = self.toolbar.layout.clone() else {
            return;
        };
        let old = cv.set_clip(cv.clip().intersect(l.area));
        if self.pill_shown() {
            let tool = |h: Option<Hit>| {
                h.and_then(|h| l.hits.iter().position(|x| *x == h))
                    .map(|i| l.pill.items[i].tool)
            };
            paint_pill(
                cv,
                te,
                f,
                s,
                &l.pill,
                tool(self.hover),
                tool(self.press),
                self.toolbar.focus,
            );
            if self.toolbar.menu {
                cv.set_clip(old);
                self.paint_menu(cv, te, f, &l);
            }
        } else {
            paint_handle(cv, s, l.handle.0, self.hover == Some(Hit::ToolbarHandle));
        }
        cv.set_clip(old);
    }

    fn paint_menu(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, l: &Layout) {
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        k.shadow(l.menu_rect, radius::CARD, PILL_BLUR);
        let border = if c.dark { c.border_strong } else { c.border };
        k.cv.round_border(l.menu_rect, radius::CARD * s, border, c.surface_raised);
        for (r, item) in menu_rows(s, l.menu_rect, l.menu.len()).iter().zip(&l.menu) {
            if self.hover == Some(item.hit) {
                k.cv.fill_round(*r, radius::CONTROL * s, c.surface_hover);
            }
            let d = k.p(16.0);
            k.icon(
                item.icon,
                r.x + k.p(10.0),
                r.y + (r.h - d) / 2,
                16.0,
                c.text_secondary,
            );
            let tr = Rect::new(r.x + k.p(36.0), r.y, r.w - k.p(44.0), r.h);
            k.text_in(Font::Regular, size::BODY, tr, item.label, c.text);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_reconnect_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
        attempt: &str,
        step: &str,
    ) {
        let s = self.scale;
        let c = pal();
        let old = cv.set_clip(cv.clip().intersect(area));
        let card = reconnect_card(s, area);
        let cancel = cancel_rect(te, f, s, card);
        let mut k = Kit::new(cv, te, f, s);
        k.scrim(area);
        k.dialog(card);
        let d = k.p(44.0);
        let tile = Rect::new(card.x + k.p(24.0), card.y + k.p(24.0), d, d);
        k.cv.fill_round(tile, 12.0 * s, c.warning_subtle);
        k.icon_in(Icon::Refresh, tile, 22.0, c.warning);
        let tx = tile.right() + k.p(16.0);
        let tw = card.right() - tx - k.p(24.0);
        k.text(
            Font::Semi,
            size::HEADING + 2.0,
            tx,
            card.y + k.p(42.0),
            "Reconnecting…",
            c.text,
            tw,
        );
        k.text(
            Font::Regular,
            12.5,
            tx,
            card.y + k.p(63.0),
            &format!("{attempt} · the network dropped"),
            c.text_secondary,
            tw,
        );
        let dot_y = card.y + k.p(86.0);
        k.cv.fill_circle(
            tx as f32 + 3.0 * s,
            (dot_y - k.p(4.0)) as f32,
            3.0 * s,
            c.accent,
        );
        k.text(
            Font::Regular,
            size::SMALL,
            tx + k.p(12.0),
            dot_y,
            step,
            c.text_muted,
            tw - k.p(12.0),
        );
        cv.set_clip(old);
        let b = Button::secondary("Cancel");
        Kit::new(cv, te, f, s).button(cancel, &b, self.st(Hit::Disconnect(id)));
    }

    /// Connecting: who, where, the steps so far, the time, Cancel.
    #[allow(clippy::too_many_arguments)]
    fn paint_connecting(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
        name: &str,
        host: &str,
        live: &Live,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let steps = live.steps();
        let current = live.index(live.step.as_ref()).unwrap_or(0);
        let row_h = p(36.0);
        let list_h = steps.len() as i32 * row_h + p(16.0);
        let total = p(64.0) + p(18.0) + p(26.0) + p(22.0) + p(24.0) + list_h + p(24.0) + p(36.0);
        let mut y = area.y + ((area.h - total) / 2).max(p(16.0));
        let color = self.tab_color(name, host);
        let w = p(400.0).min(area.w - p(48.0));
        let x = area.x + (area.w - w) / 2;
        let mut k = Kit::new(cv, te, f, s);
        let d = p(64.0);
        k.avatar(
            Rect::new(area.x + (area.w - d) / 2, y, d, d),
            name,
            color,
            Some(c.warning),
            c.bg,
        );
        y += d + p(18.0);
        let title = match live.reconnect {
            Some(_) => format!("Reconnecting to {name}…"),
            None => format!("Connecting to {name}…"),
        };
        k.text_center(
            Font::Semi,
            size::HEADING + 3.0,
            Rect::new(area.x, y, area.w, p(26.0)),
            &title,
            c.text,
        );
        y += p(26.0);
        let mut sub = host.to_string();
        if let Some(g) = &live.gateway {
            sub += &format!("  ·  via {g}");
        }
        if let Some(r) = &live.redirected {
            sub += &format!("  ·  redirected to {r}");
        }
        if let Some((n, of)) = live.reconnect {
            sub += &format!("  ·  attempt {n} of {of}");
        }
        k.text_center(
            Font::Regular,
            12.5,
            Rect::new(area.x, y, area.w, p(22.0)),
            &sub,
            c.text_muted,
        );
        y += p(22.0) + p(24.0);
        let list = Rect::new(x, y, w, list_h);
        k.cv.round_border(list, radius::CARD * s, c.border, c.surface);
        let elapsed = live.started.map(|t| clock(t.elapsed()));
        let ix = list.x + p(26.0);
        for (i, step) in steps.iter().enumerate() {
            let ry = list.y + p(8.0) + i as i32 * row_h;
            let cy = ry + row_h / 2;
            // The line to the next step: accent once this one is done.
            if i + 1 < steps.len() {
                let lc = if i < current {
                    c.accent
                } else {
                    c.border_strong
                };
                k.cv.fill(
                    Rect::new(ix - p(1.0), cy + p(9.0), p(2.0).max(1), row_h - p(18.0)),
                    lc,
                );
            }
            let (fx, fy) = (ix as f32, cy as f32);
            let (font, color) = if i < current {
                k.cv.fill_circle(fx, fy, 9.0 * s, c.accent);
                let cd = k.p(12.0);
                k.icon(Icon::Check, ix - cd / 2, cy - cd / 2, 12.0, c.accent_text);
                (Font::Regular, c.text_secondary)
            } else if i == current {
                k.cv.fill_circle(fx, fy, 9.0 * s, c.accent_subtle);
                k.cv.ring(fx, fy, 9.0 * s, 2.0 * s, c.accent);
                k.cv.fill_circle(fx, fy, 3.5 * s, c.accent);
                (Font::Semi, c.text)
            } else {
                k.cv.ring(fx, fy, 8.0 * s, 1.5 * s, c.border_strong);
                (Font::Regular, c.text_faint)
            };
            let label = live.label(step, host);
            let lr = Rect::new(
                ix + p(22.0),
                ry,
                list.right() - ix - p(22.0) - p(70.0),
                row_h,
            );
            k.text_in(font, size::BODY, lr, &label, color);
            if i == current
                && let Some(e) = &elapsed
            {
                let er = Rect::new(list.right() - p(70.0), ry, p(56.0), row_h);
                k.text_right(Font::Regular, size::SMALL, er, e, c.text_muted);
            }
        }
        y = list.bottom() + p(24.0);
        let b = Button::secondary("Cancel").icon(Icon::Close);
        let bw = self.btn_w(te, f, &b);
        self.btn(
            cv,
            te,
            f,
            Rect::new(area.x + (area.w - bw) / 2, y, bw, p(36.0)),
            &b,
            Hit::Disconnect(id),
        );
    }

    /// Failed: the cause and its fix, where it broke, and what to do.
    #[allow(clippy::too_many_arguments)]
    fn paint_failed(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
        name: &str,
        host: &str,
        live: &Live,
        why: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let failure = live.failure.clone().unwrap_or(Failure {
            cause: Cause::Unknown,
            step: None,
        });
        let cause = failure.cause;
        let ctx = failure::Context {
            host,
            port: live.port,
            user: &live.user,
            gateway: live.gateway.as_deref(),
        };
        let fix = cause.fix(&ctx);
        let steps = live.steps();
        let at = live.index(failure.step.as_ref());
        let w = p(560.0).min(area.w - p(48.0));
        let x = area.x + (area.w - w) / 2;
        let mut k = Kit::new(cv, te, f, s);
        let fix_lines = k.wrap(Font::Regular, 12.5, &fix, w - p(64.0)).len().max(1) as i32;
        let fix_h = p(44.0) + fix_lines * p(19.0);
        let trail_h = if at.is_some() { p(64.0) } else { 0 };
        let total = p(56.0)
            + p(20.0)
            + p(28.0)
            + p(22.0)
            + p(22.0)
            + fix_h
            + trail_h
            + p(24.0)
            + p(36.0)
            + p(36.0);
        let mut y = area.y + ((area.h - total) / 2).max(p(16.0));
        let tone = cause.tone();
        let d = p(56.0);
        let tile = Rect::new(area.x + (area.w - d) / 2, y, d, d);
        k.cv.fill_round(tile, 16.0 * s, tone.subtle());
        k.icon_in(cause.icon(), tile, 26.0, tone.color());
        y += d + p(20.0);
        k.text_center(
            Font::Semi,
            size::HEADING + 4.0,
            Rect::new(area.x + p(16.0), y, area.w - p(32.0), p(28.0)),
            cause.title(),
            c.text,
        );
        y += p(28.0);
        let mut sub = format!("{name}  ·  {host}");
        if let Some(g) = &live.gateway {
            sub += &format!("  ·  via {g}");
        }
        k.text_center(
            Font::Regular,
            12.5,
            Rect::new(area.x + p(16.0), y, area.w - p(32.0), p(22.0)),
            &sub,
            c.text_muted,
        );
        y += p(22.0) + p(22.0);
        // What to try.
        let fr = Rect::new(x, y, w, fix_h);
        k.cv.round_border(fr, radius::CARD * s, c.border, c.surface);
        k.icon(Icon::Info, fr.x + p(18.0), fr.y + p(16.0), 16.0, c.accent);
        k.caption_text(fr.x + p(46.0), fr.y + p(28.0), "WHAT TO TRY", c.text_muted);
        k.paragraph(
            Font::Regular,
            12.5,
            fr.x + p(46.0),
            fr.y + p(49.0),
            w - p(64.0),
            &fix,
            c.text,
            false,
        );
        y = fr.bottom();
        // Where it broke.
        if let Some(at) = at {
            let n = steps.len() as i32;
            let tw = w - p(40.0);
            let step_w = tw / n.max(1);
            let ty = y + p(24.0);
            let x0 = x + p(20.0) + step_w / 2;
            for (i, st) in steps.iter().enumerate() {
                let cx = x0 + i as i32 * step_w;
                if i + 1 < steps.len() {
                    let lc = if i < at { c.accent } else { c.border };
                    k.cv.fill(
                        Rect::new(cx + p(8.0), ty - p(1.0), step_w - p(16.0), p(2.0).max(1)),
                        lc,
                    );
                }
                let (fx, fy) = (cx as f32, ty as f32);
                let label_color = if i < at {
                    k.cv.fill_circle(fx, fy, 5.0 * s, c.accent);
                    c.text_muted
                } else if i == at {
                    k.cv.fill_circle(fx, fy, 8.0 * s, tone.color());
                    let cd = k.p(10.0);
                    k.icon(Icon::Close, cx - cd / 2, ty - cd / 2, 10.0, c.on_solid);
                    tone.color()
                } else {
                    k.cv.ring(fx, fy, 5.0 * s, 1.5 * s, c.border_strong);
                    c.text_faint
                };
                let font = if i == at { Font::Semi } else { Font::Regular };
                let lr = Rect::new(cx - step_w / 2, ty + p(12.0), step_w, p(18.0));
                k.text_center(font, 11.0, lr, short(st), label_color);
            }
            y += trail_h;
        }
        y += p(24.0);
        let buttons = [
            (
                Button::primary("Retry").icon(Icon::Refresh),
                Hit::Reconnect(id),
            ),
            (
                Button::secondary("Edit connection").icon(Icon::Edit),
                Hit::EditConnection(id),
            ),
            (
                Button::ghost("Copy details").icon(Icon::Copy),
                Hit::CopyDetails(id),
            ),
            (
                Button::ghost("Open log").icon(Icon::FileText),
                Hit::OpenLogFolder,
            ),
        ];
        let widths: Vec<i32> = buttons.iter().map(|(b, _)| self.btn_w(te, f, b)).collect();
        let total_w = widths.iter().sum::<i32>() + p(8.0) * (buttons.len() as i32 - 1);
        let mut bx = area.x + (area.w - total_w) / 2;
        for ((b, hit), bw) in buttons.iter().zip(&widths) {
            self.btn(cv, te, f, Rect::new(bx, y, *bw, p(36.0)), b, *hit);
            bx += bw + p(8.0);
        }
        y += p(36.0) + p(20.0);
        let mut k = Kit::new(cv, te, f, s);
        k.text_center(
            Font::Regular,
            11.5,
            Rect::new(area.x + p(24.0), y, area.w - p(48.0), p(18.0)),
            why,
            c.text_faint,
        );
    }

    /// Ended: why, how long it ran, Reconnect and Close tab.
    #[allow(clippy::too_many_arguments)]
    fn paint_ended(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
        host: &str,
        live: &Live,
        why: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let reason = live.ended;
        let total = p(56.0) + p(20.0) + p(28.0) + p(24.0) + p(20.0) + p(20.0) + p(28.0) + p(36.0);
        let mut y = area.y + ((area.h - total) / 2).max(p(16.0));
        let mut k = Kit::new(cv, te, f, s);
        let d = p(56.0);
        let tile = Rect::new(area.x + (area.w - d) / 2, y, d, d);
        k.cv.fill_round(tile, 16.0 * s, c.surface_raised);
        k.icon_in(
            reason.map_or(Icon::Power, EndReason::icon),
            tile,
            26.0,
            c.text_secondary,
        );
        y += d + p(20.0);
        k.text_center(
            Font::Semi,
            size::HEADING + 4.0,
            Rect::new(area.x, y, area.w, p(28.0)),
            "Session ended",
            c.text,
        );
        y += p(28.0);
        let text = reason.map_or_else(|| why.to_string(), |r| r.text().to_string());
        k.text_center(
            Font::Regular,
            13.0,
            Rect::new(area.x + p(16.0), y, area.w - p(32.0), p(24.0)),
            &text,
            c.text_secondary,
        );
        y += p(24.0) + p(20.0);
        // Facts as pills: where, and how long it ran.
        let mut pills = vec![(host.to_string(), Lead::Icon(Icon::Monitor))];
        if let Some(d) = live.duration {
            pills.push((
                format!("Connected for {}", failure::duration_text(d)),
                Lead::Icon(Icon::Clock),
            ));
        }
        let widths: Vec<i32> = pills.iter().map(|(t, l)| k.pill_width(t, *l)).collect();
        let total_w = widths.iter().sum::<i32>() + p(8.0) * (pills.len() as i32 - 1);
        let mut px = area.x + (area.w - total_w) / 2;
        for ((t, l), w) in pills.iter().zip(&widths) {
            k.pill(px, y, t, Tone::Neutral, *l);
            px += w + p(8.0);
        }
        y += p(20.0) + p(28.0);
        let re = Button::primary("Reconnect").icon(Icon::Refresh);
        let close = Button::secondary("Close tab").icon(Icon::Close);
        let (rw, cw) = (self.btn_w(te, f, &re), self.btn_w(te, f, &close));
        let x0 = area.x + (area.w - rw - cw - p(8.0)) / 2;
        self.btn(
            cv,
            te,
            f,
            Rect::new(x0, y, rw, p(36.0)),
            &re,
            Hit::Reconnect(id),
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(x0 + rw + p(8.0), y, cw, p(36.0)),
            &close,
            Hit::CloseTab(id),
        );
    }

    /// Snapshots: the window as the app shows it, with a stand-in remote
    /// desktop where the session picture goes and the overlay on top.
    pub fn paint_snapshot(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.paint_window(cv, te, f);
        if let Some((_, area)) = self.session_area {
            paint_sample_picture(cv, area, SAMPLE_TINT, Some((te, f)));
        }
        self.paint_overlays(cv, te, f);
    }
}

/// The wallpaper tint of the sample remote desktop ("Office workstation").
pub const SAMPLE_TINT: u32 = 0x2ec4b6;

fn inflate(r: Rect, s: f32) -> Rect {
    let b = (PILL_BLUR * s).ceil() as i32 + 1;
    Rect::new(r.x - b, r.y - b, r.w + 2 * b, r.h + 2 * b + b / 3 + 1)
}

/// The rows of the toolbar's menu.
fn menu_rows(s: f32, menu: Rect, n: usize) -> Vec<Rect> {
    let p = |v: f32| (v * s).round() as i32;
    (0..n as i32)
        .map(|i| {
            Rect::new(
                menu.x + p(6.0),
                menu.y + p(8.0) + i * p(34.0),
                menu.w - p(12.0),
                p(34.0),
            )
        })
        .collect()
}

/// The reconnect card, centred in the picture.
fn reconnect_card(s: f32, area: Rect) -> Rect {
    let p = |v: f32| (v * s).round() as i32;
    let w = p(400.0).min(area.w - p(32.0));
    let h = p(150.0);
    Rect::new(area.x + (area.w - w) / 2, area.y + (area.h - h) / 2, w, h)
}

fn cancel_rect(te: &mut TextEngine, f: &Fonts, s: f32, card: Rect) -> Rect {
    let p = |v: f32| (v * s).round() as i32;
    let bw = kit::button_width(te, f, s, &Button::secondary("Cancel"));
    Rect::new(
        card.right() - p(24.0) - bw,
        card.bottom() - p(24.0) - p(32.0),
        bw,
        p(32.0),
    )
}

/// A stand-in remote desktop for snapshots and the Home view's sample
/// thumbnails: a wallpaper washed towards `tint`, a report window, a code
/// window in front and a taskbar. With `text` the windows get their words
/// and the taskbar its clock; without it, bars stand in for the words.
pub fn paint_sample_picture(
    cv: &mut Canvas,
    r: Rect,
    tint: u32,
    text: Option<(&mut TextEngine, &Fonts)>,
) {
    let old = cv.set_clip(r);
    let (w, h) = (r.w.max(1), r.h.max(1));
    // Sized as if the remote desktop were 1280 x 800.
    let s = (w as f32 / 1280.0).min(h as f32 / 800.0).clamp(0.3, 3.0);
    let mut pen = SamplePen { cv, text, s };
    let p = |v: f32| (v * s).round() as i32;

    // Wallpaper: night blue towards the tint, with a soft bloom low right.
    let night = 0x0a1628;
    let (bx, by) = (r.x + w * 7 / 10, r.y + h * 4 / 5);
    let bloom = w.max(h) as f32 * 0.62;
    for y in 0..h {
        let t = (y * 150 / h) as u32;
        let row = Rect::new(r.x, r.y + y, w, 1);
        pen.cv
            .fill(row, theme::mix(night, theme::mix(night, tint, 120), t));
        let dy = (r.y + y - by) as f32;
        for k in 0..24 {
            let rr = bloom * (1.0 - k as f32 * 0.038);
            if dy.abs() < rr {
                let half = (rr * rr - dy * dy).sqrt() as i32;
                pen.cv
                    .fill_alpha(Rect::new(bx - half, r.y + y, 2 * half, 1), tint, 5);
            }
        }
    }

    // Desktop folders with their names.
    for (i, name) in ["Projects", "Reports", "Shared"].iter().enumerate() {
        let x = r.x + p(26.0);
        let y = r.y + p(26.0) + i as i32 * p(86.0);
        pen.cv.fill_round(
            Rect::new(x, y - p(5.0), p(20.0), p(12.0)),
            3.0 * s,
            0xd9a83f,
        );
        pen.cv
            .fill_round(Rect::new(x, y, p(46.0), p(36.0)), 4.0 * s, 0xf5cf6b);
        pen.label(false, 11.0, x - p(4.0), y + p(44.0), name, 0xf2f5f8);
    }

    // The report window.
    let win = Rect::new(
        r.x + p(130.0),
        r.y + p(88.0),
        (w * 56 / 100).max(p(300.0)),
        (h * 64 / 100).max(p(220.0)),
    );
    sample_shadow(pen.cv, win, s);
    pen.cv.fill_round(win, 8.0 * s, 0xf7f8fa);
    pen.cv
        .fill_round(Rect::new(win.x, win.y, win.w, p(38.0)), 8.0 * s, 0xe9edf2);
    pen.cv
        .fill(Rect::new(win.x, win.y + p(30.0), win.w, p(8.0)), 0xe9edf2);
    pen.cv.fill_round(
        Rect::new(win.x + p(14.0), win.y + p(12.0), p(14.0), p(14.0)),
        3.0 * s,
        0x3d7bd9,
    );
    pen.label(
        true,
        12.0,
        win.x + p(36.0),
        win.y + p(11.0),
        "Quarterly report",
        0x2a323d,
    );
    sample_caption(pen.cv, win, s, 0x4b5563);
    // Navigation pane.
    let nav = Rect::new(win.x, win.y + p(38.0), p(156.0), win.h - p(38.0) - p(8.0));
    pen.cv.fill(nav, 0xeff2f6);
    for (i, item) in ["Overview", "Revenue", "Costs", "Regions", "Team"]
        .iter()
        .enumerate()
    {
        let row = Rect::new(
            nav.x + p(8.0),
            nav.y + p(12.0) + i as i32 * p(34.0),
            nav.w - p(16.0),
            p(28.0),
        );
        if i == 0 {
            pen.cv.fill_round(row, 5.0 * s, 0xdbe6f3);
            pen.cv.fill_round(
                Rect::new(row.x, row.y + p(7.0), p(3.0), p(14.0)),
                1.5 * s,
                0x3d7bd9,
            );
        }
        let c = if i == 0 { 0x1d3557 } else { 0x4b5563 };
        pen.label(i == 0, 12.0, row.x + p(14.0), row.y + p(6.0), item, c);
    }
    // Content: a heading, three figures and a chart.
    let cx = nav.right() + p(24.0);
    let cw = win.right() - p(24.0) - cx;
    let mut y = nav.y + p(18.0);
    pen.label(true, 20.0, cx, y, "Overview", 0x1f2937);
    pen.label(
        false,
        12.0,
        cx,
        y + p(30.0),
        "Third quarter, all regions",
        0x6b7280,
    );
    y += p(62.0);
    let gap = p(14.0);
    let fw = (cw - 2 * gap) / 3;
    let figures = [
        ("Revenue", "4.2 M", "+8 %", 0x16a34a),
        ("Orders", "18,410", "+3 %", 0x16a34a),
        ("Returns", "1.9 %", "-0.4", 0x3d7bd9),
    ];
    for (i, (label, value, delta, dc)) in figures.iter().enumerate() {
        let card = Rect::new(cx + i as i32 * (fw + gap), y, fw, p(74.0));
        pen.cv.fill_round(card, 6.0 * s, 0xdfe4ea);
        pen.cv.fill_round(card.inset(1, 1), 5.0 * s, 0xffffff);
        pen.label(
            false,
            11.0,
            card.x + p(14.0),
            card.y + p(12.0),
            label,
            0x6b7280,
        );
        pen.label(
            true,
            20.0,
            card.x + p(14.0),
            card.y + p(32.0),
            value,
            0x111827,
        );
        pen.label(
            true,
            11.0,
            card.right() - p(46.0),
            card.y + p(12.0),
            delta,
            *dc,
        );
    }
    y += p(74.0) + gap;
    let chart = Rect::new(cx, y, cw, (win.bottom() - p(20.0) - y).max(p(40.0)));
    pen.cv.fill_round(chart, 6.0 * s, 0xdfe4ea);
    pen.cv.fill_round(chart.inset(1, 1), 5.0 * s, 0xffffff);
    pen.label(
        true,
        12.0,
        chart.x + p(14.0),
        chart.y + p(12.0),
        "Revenue by month",
        0x1f2937,
    );
    let plot = Rect::new(
        chart.x + p(16.0),
        chart.y + p(40.0),
        chart.w - p(32.0),
        (chart.h - p(56.0)).max(p(10.0)),
    );
    for g in 0..4 {
        let gy = plot.y + g * plot.h / 3;
        pen.cv.fill(Rect::new(plot.x, gy, plot.w, 1), 0xeceff3);
    }
    let bars = [42, 55, 48, 63, 58, 71, 66, 78, 74, 86, 81, 92];
    let slot = plot.w / bars.len() as i32;
    let mut line = Vec::new();
    for (i, v) in bars.iter().enumerate() {
        let bh = plot.h * v / 100;
        let bx = plot.x + i as i32 * slot + slot / 5;
        let bar = Rect::new(bx, plot.bottom() - bh, slot * 3 / 5, bh);
        let c = if i == bars.len() - 1 {
            0x3d7bd9
        } else {
            0xb9d0ef
        };
        pen.cv.fill_round(bar, 2.0 * s, c);
        line.push((
            (bx + slot * 3 / 10) as f32,
            (plot.bottom() - plot.h * (v - 18) / 100) as f32,
        ));
    }
    pen.cv.stroke(&line, 2.0 * s, 0x0f9488);

    // The code window, in front.
    let code = Rect::new(
        r.x + w * 46 / 100,
        r.y + h * 36 / 100,
        (w * 46 / 100).max(p(260.0)),
        (h * 43 / 100).max(p(180.0)),
    );
    sample_shadow(pen.cv, code, s);
    pen.cv.fill_round(code, 8.0 * s, 0x1b1d23);
    pen.cv.fill_round(
        Rect::new(code.x, code.y, code.w, p(36.0)),
        8.0 * s,
        0x25272e,
    );
    pen.cv.fill(
        Rect::new(code.x, code.y + p(28.0), code.w, p(8.0)),
        0x25272e,
    );
    pen.label(
        false,
        12.0,
        code.x + p(16.0),
        code.y + p(10.0),
        "session.rs",
        0xc9ced6,
    );
    sample_caption(pen.cv, code, s, 0xaab1bb);
    let (kw, ty, fun, st, id, cm, pu, num) = (
        0xc586c0, 0x4ec9b0, 0xdcdcaa, 0xce9178, 0x9cdcfe, 0x6a9955, 0xd4d4d4, 0xb5cea8,
    );
    let lines: [(i32, &[(&str, u32)]); 12] = [
        (0, &[("// Share the clipboard, fit the picture.", cm)]),
        (
            0,
            &[
                ("pub fn ", kw),
                ("start", fun),
                ("(cfg: ", pu),
                ("Config", ty),
                (") -> ", pu),
                ("Result", ty),
                ("<", pu),
                ("Session", ty),
                ("> {", pu),
            ],
        ),
        (
            1,
            &[
                ("let ", kw),
                ("host", id),
                (" = cfg.", pu),
                ("host", fun),
                ("();", pu),
            ],
        ),
        (
            1,
            &[
                ("let mut ", kw),
                ("s", id),
                (" = ", pu),
                ("Session", ty),
                ("::", pu),
                ("connect", fun),
                ("(host)?;", pu),
            ],
        ),
        (
            1,
            &[
                ("s.", pu),
                ("share_clipboard", fun),
                ("(", pu),
                ("true", kw),
                (");", pu),
            ],
        ),
        (1, &[("s.", pu), ("fit_to_window", fun), ("();", pu)]),
        (
            1,
            &[
                ("log", fun),
                ("(", pu),
                ("\"connected to {host}\"", st),
                (");", pu),
            ],
        ),
        (1, &[("Ok", ty), ("(s)", pu)]),
        (0, &[("}", pu)]),
        (0, &[]),
        (0, &[("// Wait this long for the first picture.", cm)]),
        (
            0,
            &[
                ("const ", kw),
                ("TIMEOUT_S", id),
                (": ", pu),
                ("u64", ty),
                (" = ", pu),
                ("30", num),
                (";", pu),
            ],
        ),
    ];
    let lh = p(22.0);
    let gutter = code.x + p(16.0);
    let tx = code.x + p(48.0);
    for (i, (indent, tokens)) in lines.iter().enumerate() {
        let ly = code.y + p(50.0) + i as i32 * lh;
        if ly + lh > code.bottom() - p(8.0) {
            break;
        }
        if i == 5 {
            pen.cv
                .fill(Rect::new(code.x, ly - p(3.0), code.w, lh), 0x262a33);
        }
        pen.label(false, 11.0, gutter, ly, &(i + 1).to_string(), 0x5c6370);
        let mut x = tx + indent * p(28.0);
        for (t, c) in tokens.iter() {
            x = pen.label(false, 12.0, x, ly, t, *c);
        }
    }

    // Taskbar: the apps in the middle, a clock on the right.
    let tb = Rect::new(r.x, r.bottom() - p(46.0), w, p(46.0));
    pen.cv.fill(tb, 0x121821);
    pen.cv.fill(Rect::new(tb.x, tb.y, tb.w, 1), 0x2a3340);
    let icons = [tint, 0x4c8dff, 0xf0b230, 0xe9edf2, 0x48c774, 0x8f6cff];
    let iw = p(30.0);
    let step = p(44.0);
    let x0 = tb.x + (tb.w - icons.len() as i32 * step) / 2;
    for (i, c) in icons.iter().enumerate() {
        let ir = Rect::new(
            x0 + i as i32 * step + (step - iw) / 2,
            tb.y + p(8.0),
            iw,
            iw,
        );
        pen.cv.fill_round(ir, 6.0 * s, *c);
        if i == 1 || i == 4 {
            pen.cv.fill_round(
                Rect::new(ir.x + iw / 2 - p(4.0), tb.bottom() - p(5.0), p(8.0), p(3.0)),
                1.5 * s,
                0x9fb3c8,
            );
        }
    }
    pen.label(
        false,
        11.0,
        tb.right() - p(66.0),
        tb.y + p(6.0),
        "14:32",
        0xe9edf2,
    );
    pen.label(
        false,
        11.0,
        tb.right() - p(82.0),
        tb.y + p(24.0),
        "2026-11-14",
        0xaab4c0,
    );
    pen.cv.set_clip(old);
}

/// Draws the sample desktop's words, or bars of about their width.
struct SamplePen<'a, 'b, 'c> {
    cv: &'a mut Canvas<'b>,
    text: Option<(&'c mut TextEngine, &'c Fonts)>,
    s: f32,
}

impl SamplePen<'_, '_, '_> {
    /// `text` (`size` logical) with its top at `y`; returns the end x.
    fn label(&mut self, semi: bool, size: f32, x: i32, y: i32, text: &str, color: u32) -> i32 {
        let s = self.s;
        let font = if semi { Font::Semi } else { Font::Regular };
        match self.text.as_mut() {
            Some((te, f)) => {
                let base = y + (size * 1.05 * s).round() as i32;
                Kit::new(self.cv, te, f, s).text(font, size, x, base, text, color, i32::MAX / 4)
            }
            None => {
                let tw = (text.chars().count() as f32 * size * 0.52 * s) as i32;
                let bh = (size * 0.5 * s).max(1.0) as i32;
                if !text.trim().is_empty() {
                    let bar = Rect::new(x, y + (size * 0.4 * s) as i32, tw, bh);
                    self.cv.fill_round(bar, bh as f32 / 2.0, color);
                }
                x + tw
            }
        }
    }
}

/// Minimise, maximise and close glyphs at a sample window's top right.
fn sample_caption(cv: &mut Canvas, win: Rect, s: f32, color: u32) {
    let p = |v: f32| (v * s).round() as i32;
    let cy = win.y + p(19.0);
    let x = win.right() - p(112.0);
    cv.fill(Rect::new(x, cy, p(10.0), 1.max(p(1.0))), color);
    cv.stroke_rect(Rect::new(x + p(40.0), cy - p(5.0), p(10.0), p(10.0)), color);
    let (ax, ay) = ((x + p(80.0)) as f32, (cy - p(5.0)) as f32);
    let d = p(10.0) as f32;
    cv.stroke(&[(ax, ay), (ax + d, ay + d)], 1.2 * s, color);
    cv.stroke(&[(ax + d, ay), (ax, ay + d)], 1.2 * s, color);
}

/// A soft shadow under a sample window.
fn sample_shadow(cv: &mut Canvas, win: Rect, s: f32) {
    let b = (18.0 * s).max(2.0);
    let dy = (6.0 * s) as i32;
    let rad = 8.0 * s;
    let n = b.ceil() as i32;
    let clip = cv.clip();
    for y in (win.y - n + dy).max(clip.y)..(win.bottom() + n + dy).min(clip.bottom()) {
        for x in (win.x - n).max(clip.x)..(win.right() + n).min(clip.right()) {
            if win.contains(x, y) {
                continue;
            }
            let (px, py) = (x as f32 + 0.5, (y - dy) as f32 + 0.5);
            let qx = (px - (win.x as f32 + win.w as f32 / 2.0)).abs() - (win.w as f32 / 2.0 - rad);
            let qy = (py - (win.y as f32 + win.h as f32 / 2.0)).abs() - (win.h as f32 / 2.0 - rad);
            let d = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() - rad;
            let t = (1.0 - d.max(0.0) / b).clamp(0.0, 1.0);
            let a = (110.0 * t * t) as u32;
            if a > 0 {
                cv.fill_alpha(Rect::new(x, y, 1, 1), 0x000000, a);
            }
        }
    }
}

// ---- Samples for `--snapshot-ui` ----------------------------------------

/// A session tab state on the "Office workstation" connection.
fn sample_on(m: &mut Ui, state: TabState, live: Live) {
    m.active = Some(1);
    if let Some(t) = m.tab_mut(1) {
        t.state = state;
        t.live = live;
    }
}

fn sample_live(gateway: bool) -> Live {
    Live {
        gateway: gateway.then(|| "rdg.corp.example".to_string()),
        user: r"CORP\alex".into(),
        port: 3389,
        started: Instant::now().checked_sub(Duration::from_secs(4)),
        ..Live::default()
    }
}

/// Connecting, signing in; with an RD Gateway when `gateway`.
pub fn sample_connecting(gateway: bool) -> Ui {
    let mut m = sample(false);
    let mut live = sample_live(gateway);
    live.step = Some(ConnectStep::SignIn);
    sample_on(&mut m, TabState::Connecting, live);
    m.set_message("Connecting to 10.0.0.15…", Tone::Muted);
    m
}

/// An automatic reconnect over the dimmed last picture.
pub fn sample_reconnecting() -> Ui {
    let mut m = sample(false);
    let mut live = sample_live(false);
    live.step = Some(ConnectStep::Tcp);
    live.reconnect = Some((2, 5));
    live.has_frame = true;
    sample_on(&mut m, TabState::Connecting, live);
    m.set_message(
        "Connection lost. Reconnecting in 2 s, attempt 2/5…",
        Tone::Warning,
    );
    m
}

/// The failure samples: suffix, cause, step, technical text.
pub const FAILURES: [(&str, Cause, Option<ConnectStep>, &str); 10] = [
    (
        "host",
        Cause::HostNotFound,
        Some(ConnectStep::Resolving),
        "I/O error: No such host is known. (os error 11001)",
    ),
    (
        "refused",
        Cause::Refused,
        Some(ConnectStep::Tcp),
        "I/O error: No connection could be made because the target machine actively refused it. (os error 10061)",
    ),
    (
        "timeout",
        Cause::TimedOut,
        Some(ConnectStep::Tcp),
        "I/O error: A connection attempt failed because the connected party did not properly respond. (os error 10060)",
    ),
    (
        "password",
        Cause::WrongPassword,
        Some(ConnectStep::SignIn),
        "authentication failed: server error 0xc000006d STATUS_LOGON_FAILURE (wrong user name or password)",
    ),
    (
        "locked",
        Cause::AccountLocked,
        Some(ConnectStep::SignIn),
        "authentication failed: server error 0xc0000234 STATUS_ACCOUNT_LOCKED_OUT",
    ),
    (
        "expired",
        Cause::PasswordExpired,
        Some(ConnectStep::SignIn),
        "authentication failed: server error 0xc0000071 STATUS_PASSWORD_EXPIRED",
    ),
    (
        "cert",
        Cause::CertificateRejected,
        Some(ConnectStep::Tls),
        "authentication failed: the server certificate was not trusted",
    ),
    (
        "gateway",
        Cause::GatewayAuth,
        Some(ConnectStep::Gateway),
        "authentication failed: RD Gateway rejected the credentials",
    ),
    (
        "license",
        Cause::License,
        Some(ConnectStep::Licensing),
        "protocol error: licensing error 0x2 (ERR_NO_LICENSE)",
    ),
    (
        "protocol",
        Cause::Protocol,
        None,
        "protocol error: unexpected fast-path update code 0x0e",
    ),
];

/// One of [`FAILURES`].
pub fn sample_failed(i: usize) -> Ui {
    let (_, cause, step, why) = FAILURES[i].clone();
    let mut m = sample(false);
    let mut live = sample_live(step == Some(ConnectStep::Gateway));
    live.step = step.clone();
    live.failure = Some(Failure { cause, step });
    sample_on(&mut m, TabState::Failed(why.into()), live);
    m.set_message(cause.title(), Tone::Danger);
    m
}

/// Ended: signed out after a while, or taken over by another connection.
pub fn sample_ended(reason: EndReason) -> Ui {
    let mut m = sample(false);
    let mut live = sample_live(false);
    live.ended = Some(reason);
    live.duration = Some(Duration::from_secs(3600 + 5 * 60 + 12));
    sample_on(&mut m, TabState::Ended(reason.text().into()), live);
    m.set_message("Session ended.", Tone::Muted);
    m
}

/// A running session: the toolbar shown (as on arrival, before a click
/// into the picture) or hidden to its handle; `menu` opens its menu.
pub fn sample_toolbar(shown: bool, menu: bool, fullscreen: bool) -> Ui {
    let mut m = sample(true);
    m.drawer = false;
    m.fullscreen = fullscreen;
    m.session_focus = !shown;
    m.toolbar.menu = menu;
    if let Some(t) = m.tab_mut(1) {
        t.recording = fullscreen;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn painted(m: &mut Ui, w: usize, h: usize) -> Option<(TextEngine, Fonts)> {
        let mut te = TextEngine::new();
        let fonts = load_fonts(&mut te)?;
        let mut px = vec![0u32; w * h];
        m.paint_snapshot(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        Some((te, fonts))
    }

    /// The pill floats over the picture: the picture keeps the whole area,
    /// the pill hides when the session has the keyboard and comes back at
    /// the top edge, and only its rectangle needs repainting.
    #[test]
    fn toolbar_hides_and_shows_without_moving_the_picture() {
        let mut m = sample_toolbar(false, false, false);
        let Some(_) = painted(&mut m, 1200, 800) else {
            return; // no UI font (headless CI)
        };
        let (_, area) = m.session_area.unwrap();
        assert!(!m.pill_shown(), "the session has the keyboard");
        let pill = m.toolbar.layout.as_ref().unwrap().pill.rect;
        assert!(area.contains(pill.x, pill.y) && pill.y < area.y + 20);
        // Over the hidden pill's place the picture gets the pointer.
        assert!(!m.over_overlay(pill.x + 4, pill.y + pill.h / 2));
        assert!(!m.mouse_move(area.x + area.w / 2, area.y + 200));
        assert!(m.take_overlay_damage().is_none());
        // The top edge shows it; only the overlay is repainted.
        assert!(!m.mouse_move(area.x + area.w / 2, area.y + 1));
        assert!(m.pill_shown());
        let d = m.take_overlay_damage().expect("pill rect to repaint");
        assert!(d.contains(pill.x, pill.y) && d.h < 120, "{d:?}");
        let b = m.toolbar.layout.as_ref().unwrap().pill.buttons[0];
        assert_eq!(m.overlay_hit(b.x + 2, b.y + 2), Some(Hit::Drawer));
        assert!(m.over_overlay(b.x + 2, b.y + 2));
        // Leaving it hides it again.
        m.mouse_move(area.x + area.w / 2, area.y + 400);
        assert!(!m.pill_shown());
        assert!(m.take_overlay_damage().is_some());
        let (painted_area, after) = (area, m.session_area.unwrap().1);
        assert_eq!(painted_area, after, "the remote size does not change");
    }

    #[test]
    fn handle_tap_alt_and_panel_show_the_toolbar() {
        let mut m = sample_toolbar(false, false, true);
        let Some(_) = painted(&mut m, 1000, 700) else {
            return;
        };
        let (_, area) = m.session_area.unwrap();
        assert_eq!(area, Rect::new(0, 0, 1000, 700), "full screen: all of it");
        let (_, hit) = m.toolbar.layout.as_ref().unwrap().handle;
        assert_eq!(
            m.overlay_hit(hit.x + hit.w / 2, hit.y + hit.h / 2),
            Some(Hit::ToolbarHandle)
        );
        m.activate(Hit::ToolbarHandle);
        assert!(m.pill_shown(), "a tap on the handle opens it");
        m.toolbar_reset();
        assert!(!m.pill_shown());
        m.alt_key(true);
        assert!(m.pill_shown() && m.take_overlay_damage().is_some());
        m.alt_key(false);
        assert!(!m.pill_shown());
        m.drawer = true;
        assert!(m.pill_shown(), "stays while the panel is open");
    }

    #[test]
    fn toolbar_is_keyboard_reachable() {
        let mut m = sample_toolbar(true, false, false);
        let Some(_) = painted(&mut m, 1200, 800) else {
            return;
        };
        m.focus = None;
        assert!(m.key(Key::Tab).is_none());
        assert_eq!(m.toolbar.focus, Some(0));
        m.key(Key::Right);
        assert_eq!(m.toolbar.focus, Some(1));
        assert!(matches!(
            m.key(Key::Enter),
            Some(Action::SetFullscreen(true))
        ));
        m.key(Key::Esc);
        assert_eq!(m.toolbar.focus, None);
    }

    #[test]
    fn failed_screen_offers_retry_edit_copy_and_log() {
        let mut m = sample_failed(3);
        let Some(_) = painted(&mut m, 1200, 800) else {
            return;
        };
        for h in [
            Hit::Reconnect(1),
            Hit::EditConnection(1),
            Hit::CopyDetails(1),
            Hit::OpenLogFolder,
        ] {
            assert!(m.hits.iter().any(|(_, x)| *x == h), "{h:?}");
        }
        let Some(Action::CopyText(t)) = m.activate(Hit::CopyDetails(1)) else {
            panic!("copies the details");
        };
        assert!(
            t.contains("0xc000006d") && t.contains("Signing in as"),
            "{t}"
        );
        m.activate(Hit::EditConnection(1));
        assert_eq!((m.active, m.selected), (None, Some(0)), "opens its editor");
    }

    #[test]
    fn steps_follow_progress_and_redirection() {
        let mut l = sample_live(false);
        l.progress(ConnectStep::Tls);
        assert_eq!(l.index(l.step.as_ref()), Some(2));
        l.progress(ConnectStep::Redirected("rdsh2".into()));
        assert_eq!(
            (l.step.clone(), l.redirected.as_deref()),
            (None, Some("rdsh2"))
        );
        let g = sample_live(true);
        assert_eq!(g.steps()[0], ConnectStep::Gateway);
        assert_eq!(g.index(Some(&ConnectStep::SignIn)), Some(2));
    }
}
