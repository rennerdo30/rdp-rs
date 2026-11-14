//! The Home view: what the Connections tab shows when no connection is
//! open in the editor (at start-up, after Esc, from the Home tab or the
//! logo).
//!
//! From top to bottom: a greeting with the quick connect field (a host,
//! `user@host:port` or the name of a saved connection), the live sessions
//! with thumbnails of their pictures, the pinned favourites next to the
//! recently used connections, and every group as a coloured section of
//! compact cards. With nothing saved yet it is a first-start screen.
//!
//! Painting follows the rest of the window: immediate, hit rectangles
//! recorded per paint, nothing animated. Thumbnails are made by the app
//! (see [`crate::thumb`]) only when a session reports damage while this
//! view is visible, at most twice a second per session.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ffwd_render::{Canvas, Rect, TextEngine};

use super::{Action, Field, Fonts, Hit, Key, TabState, Ui, session_action};
use crate::icons::Icon;
use crate::kit::{Button, Font, Hint, Kit, Lead, State, Variant};
use crate::store::{Connection, Opens};
use crate::theme::{self, Tone, pal, radius, size};
use crate::thumb::Thumb;

/// The shortest time between two thumbnails of one session.
pub const THUMB_EVERY: Duration = Duration::from_millis(500);

/// Where a connection card sits (one connection can show in several).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    Favourite,
    Recent,
    Group,
}

/// The Home view's click (and keyboard) targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeHit {
    /// Show the Home view (logo, breadcrumb).
    Home,
    /// Use the quick connect choice (index into `quick_choices`).
    Choice(usize),
    /// A live session: show its tab, disconnect it, save it.
    Open(u64),
    Disconnect(u64),
    SaveSession(u64),
    /// A saved connection's card: connect, open in the editor, star.
    Connect(Zone, usize),
    Edit(Zone, usize),
    Pin(Zone, usize),
    /// A group section's header (collapses it): index into the groups,
    /// `usize::MAX` for connections outside groups.
    Section(usize),
    /// First start: import a backup, or fill in a new connection.
    Import,
    NewConnection,
}

/// Home view state kept between paints.
#[derive(Default)]
pub struct HomeState {
    /// The view is showing (instead of the editor).
    pub showing: bool,
    /// The quick connect choice picked with Up/Down.
    pick: usize,
    /// Keyboard focus on a card or button (Tab), when no field has it.
    kfocus: Option<HomeHit>,
    /// Focusable targets in paint order (the Tab order after the field).
    order: Vec<HomeHit>,
    /// Room kept at the right of the quick connect field (physical px).
    pub reserve: i32,
    thumbs: HashMap<u64, ThumbSlot>,
    /// The thumbnail size the live cards draw (physical px).
    thumb_size: (usize, usize),
    /// When each session tab connected (Unix seconds).
    since: HashMap<u64, u64>,
    /// Quick-connected sessions not saved yet (offered on their cards).
    unsaved: Vec<Connection>,
    /// Snapshots: a fixed "now" (Unix seconds, read as local time).
    clock: Option<u64>,
}

#[derive(Default)]
struct ThumbSlot {
    pic: Option<Thumb>,
    at: Option<Instant>,
    /// A delayed refresh is on its way (`Ui::thumb_tick`).
    pending: bool,
    /// Damage arrived while the view was hidden.
    stale: bool,
}

/// When to make a session's next thumbnail.
#[derive(Debug, PartialEq)]
pub enum ThumbDue {
    No,
    Now,
    /// Once, after this wait (the app sends itself one event).
    After(Duration),
}

/// What quick connect would do with the typed text.
#[derive(Clone, Debug, PartialEq)]
pub enum Choice {
    /// A saved connection (index).
    Saved(usize),
    /// A host not saved yet.
    Host(QuickTarget),
}

/// `[user@]host[:port]` typed into quick connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickTarget {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

impl QuickTarget {
    /// "host" or "host:port" (IPv6 in brackets), as typed into a form.
    pub fn address(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 3389 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Parses `host`, `host:port`, `user@host[:port]`, `[v6]:port` and a bare
/// IPv6 address; None when the text cannot be a host (spaces, an empty
/// part, a bad port).
pub fn parse_quick(text: &str) -> Option<QuickTarget> {
    let t = text.trim();
    let t = t.strip_prefix("rdp://").unwrap_or(t).trim_end_matches('/');
    if t.is_empty() || t.chars().any(char::is_whitespace) {
        return None;
    }
    let (user, rest) = match t.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
        Some(_) => return None,
        None => (None, t),
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (h, port)
    } else if rest.matches(':').count() > 1 {
        // A bare IPv6 address: no port possible.
        (rest, None)
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    let port = match port {
        None => 3389,
        Some(p) => match p.parse::<u16>() {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        },
    };
    let ok = !host.is_empty()
        && !host.starts_with(['-', '.'])
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%'));
    if !ok || (host.contains(':') && !host.contains("::") && host.matches(':').count() < 2) {
        return None;
    }
    Some(QuickTarget {
        user,
        host: host.to_string(),
        port,
    })
}

/// Text that reads as an address rather than a name.
fn looks_like_host(text: &str) -> bool {
    let t = text.trim();
    t.contains(['.', ':', '@', '[']) || (!t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
}

/// How well `query` matches a connection (higher is better); None: not
/// at all. Exact names first, then name prefixes, word starts, host
/// prefixes, anywhere in the name, and (for name-like text) the letters in
/// order.
pub fn match_score(query: &str, name: &str, host: &str) -> Option<u32> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    let n = name.to_lowercase();
    let h = host.to_lowercase();
    if n == q || h == q {
        return Some(1000);
    }
    if n.starts_with(&q) {
        return Some(800);
    }
    if n.split(|c: char| !c.is_alphanumeric())
        .any(|w| !w.is_empty() && w.starts_with(&q))
    {
        return Some(600);
    }
    if h.starts_with(&q) {
        return Some(500);
    }
    if n.contains(&q) {
        return Some(400);
    }
    if looks_like_host(&q) || q.chars().count() < 2 {
        return None;
    }
    // The letters in order ("ofws" finds "Office workstation"); a match
    // that starts words scores higher.
    let mut it = n.chars().peekable();
    let mut prev = ' ';
    let mut bonus = 0;
    for qc in q.chars().filter(|c| !c.is_whitespace()) {
        loop {
            let c = it.next()?;
            let start = !prev.is_alphanumeric();
            prev = c;
            if c == qc {
                if start {
                    bonus += 10;
                }
                break;
            }
        }
    }
    Some(200 + bonus.min(100))
}

/// Saved connections matching `query`, best first (ties: most recently
/// used, then the shorter name).
pub fn rank(query: &str, conns: &[Connection]) -> Vec<usize> {
    let mut hits: Vec<(u32, usize)> = conns
        .iter()
        .enumerate()
        .filter_map(|(i, c)| match_score(query, &c.name, &c.host).map(|s| (s, i)))
        .collect();
    hits.sort_by(|a, b| {
        let (ca, cb) = (&conns[a.1], &conns[b.1]);
        b.0.cmp(&a.0)
            .then(cb.last_used.cmp(&ca.last_used))
            .then(ca.name.len().cmp(&cb.name.len()))
            .then(a.1.cmp(&b.1))
    });
    hits.into_iter().map(|(_, i)| i).collect()
}

/// The `n` most recently used connections, newest first.
pub fn recents(conns: &[Connection], n: usize) -> Vec<usize> {
    let mut used: Vec<usize> = (0..conns.len())
        .filter(|&i| conns[i].last_used.is_some())
        .collect();
    used.sort_by(|&a, &b| {
        conns[b]
            .last_used
            .cmp(&conns[a].last_used)
            .then(conns[a].name.cmp(&conns[b].name))
    });
    used.truncate(n);
    used
}

/// "just now", "5 min ago", "2 h ago", "yesterday", "3 days ago",
/// "2 weeks ago", "4 months ago".
pub fn ago(now: u64, then: u64) -> String {
    let d = now.saturating_sub(then);
    match d {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", d / 60),
        3600..86_400 => format!("{} h ago", d / 3600),
        86_400..172_800 => "yesterday".into(),
        172_800..1_209_600 => format!("{} days ago", d / 86_400),
        1_209_600..5_184_000 => format!("{} weeks ago", d / 604_800),
        _ => format!("{} months ago", d / 2_592_000),
    }
}

/// A duration in words: "under a minute", "12 min", "1 h 12 min", "3 h",
/// "2 days 4 h".
pub fn span(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    match (d, h, m) {
        (0, 0, 0) => "under a minute".into(),
        (0, 0, m) => format!("{m} min"),
        (0, h, 0) => format!("{h} h"),
        (0, h, m) => format!("{h} h {m} min"),
        (1, 0, _) => "1 day".into(),
        (1, h, _) => format!("1 day {h} h"),
        (d, 0, _) => format!("{d} days"),
        (d, h, _) => format!("{d} days {h} h"),
    }
}

/// The greeting for a local hour.
pub fn greeting(hour: u32) -> &'static str {
    match hour {
        5..=11 => "Good morning",
        12..=17 => "Good afternoon",
        _ => "Good evening",
    }
}

/// Local wall-clock time: (hour, weekday 0 = Sunday, day, month 1..=12).
fn local_time(clock: Option<u64>) -> (u32, u32, u32, u32) {
    #[cfg(windows)]
    if clock.is_none() {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        // SAFETY: GetLocalTime fills the given structure.
        let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut t) };
        return (
            t.wHour as u32,
            t.wDayOfWeek as u32,
            t.wDay as u32,
            t.wMonth as u32,
        );
    }
    // Elsewhere (and for snapshots) the Unix time read as UTC.
    let secs = clock.unwrap_or_else(unix_now);
    let days = (secs / 86_400) as i64;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let weekday = (days + 4).rem_euclid(7) as u32;
    ((secs % 86_400 / 3600) as u32, weekday, day, month)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Columns of at least `min` (with `gap` between) that fill `w`: (count,
/// width of one).
fn grid(w: i32, min: i32, gap: i32) -> (i32, i32) {
    let n = ((w + gap) / (min + gap)).max(1);
    (n, (w - (n - 1) * gap) / n)
}

/// Like [`grid`] for `items` cards: fewer cards than columns grow to fill
/// the row, up to `max` wide each.
fn grid_fill(w: i32, min: i32, max: i32, gap: i32, items: usize) -> (i32, i32) {
    let (n, _) = grid(w, min, gap);
    let n = n.min(items.max(1) as i32);
    (n, ((w - (n - 1) * gap) / n).min(max))
}

/// Rounds the corners of a picture drawn into `r`: the pixels outside a
/// radius `rad` take `bg` (with an anti-aliased edge).
fn round_corners(cv: &mut Canvas, r: Rect, rad: f32, bg: u32) {
    let n = rad.ceil() as i32;
    for (cx, cy, x0, y0) in [
        (r.x as f32 + rad, r.y as f32 + rad, r.x, r.y),
        (r.right() as f32 - rad, r.y as f32 + rad, r.right() - n, r.y),
        (
            r.x as f32 + rad,
            r.bottom() as f32 - rad,
            r.x,
            r.bottom() - n,
        ),
        (
            r.right() as f32 - rad,
            r.bottom() as f32 - rad,
            r.right() - n,
            r.bottom() - n,
        ),
    ] {
        for y in y0..y0 + n {
            for x in x0..x0 + n {
                let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                let out = ((dx * dx + dy * dy).sqrt() - rad + 0.5).clamp(0.0, 1.0);
                if out > 0.0 {
                    cv.fill_alpha(Rect::new(x, y, 1, 1), bg, (out * 255.0) as u32);
                }
            }
        }
    }
}

/// A Home card's frame: raised on hover, a focus ring from the keyboard.
fn card_frame(k: &mut Kit, r: Rect, hover: bool, focus: bool) {
    let p = pal();
    let (border, fill) = if hover {
        (
            p.border_strong,
            if p.dark { p.surface_raised } else { p.surface },
        )
    } else {
        (p.border, p.surface)
    };
    k.cv.round_border(r, radius::CARD * k.s, border, fill);
    if focus {
        k.focus_ring(r, radius::CARD);
    }
}

/// Chips of a connection: gateway, Windows sign-in, apps, monitors.
fn chips(c: &Connection) -> Vec<(String, Tone, Lead)> {
    let mut v = Vec::new();
    if !c.gateway.is_empty() {
        v.push(("Gateway".into(), Tone::Info, Lead::Icon(Icon::Globe)));
    }
    if c.kerberos {
        v.push((
            "Windows sign-in".into(),
            Tone::Neutral,
            Lead::Icon(Icon::Shield),
        ));
    }
    if c.opens == Opens::Apps {
        let n = c.apps.len();
        v.push((
            format!("{n} app{}", if n == 1 { "" } else { "s" }),
            Tone::Accent,
            Lead::Icon(Icon::Apps),
        ));
    }
    let m = c.options.monitors.len();
    if m > 1 {
        v.push((
            format!("{m} monitors"),
            Tone::Neutral,
            Lead::Icon(Icon::Monitors),
        ));
    }
    v
}

/// One live session as a card shows it (copied out of the tab).
struct LiveCard {
    id: u64,
    name: String,
    host: String,
    connecting: bool,
    spanned: bool,
    /// RemoteApp: its window count and the titles of the first ones.
    apps: Option<(usize, Vec<String>)>,
}

impl Ui {
    /// Shows the Home view (start-up, Esc from the editor, the Home tab,
    /// the logo).
    pub(super) fn go_home(&mut self) {
        self.active = None;
        self.settings_open = false;
        self.selected = None;
        self.group_edit = None;
        self.session_focus = false;
        self.home.showing = true;
        self.home.kfocus = None;
        self.home_scroll = 0;
        self.focus = Some(Field::Quick);
    }

    /// The Home view is on screen.
    pub fn home_visible(&self) -> bool {
        self.active.is_none()
            && !self.settings_open
            && self.home.showing
            && !self.store.is_locked()
            && !self.vault_setup
            && self.confirm_exit.is_none()
    }

    fn now(&self) -> u64 {
        self.home.clock.unwrap_or_else(unix_now)
    }

    /// The snapshot clock, if one is set.
    pub(super) fn home_clock(&self) -> Option<u64> {
        self.home.clock
    }

    // ---- Quick connect -------------------------------------------------

    /// What Enter can do with the typed text: matching saved connections
    /// (at most four), and the text as a new host. Address-like text puts
    /// the new host first unless a saved connection has exactly that host.
    pub(super) fn quick_choices(&self) -> Vec<Choice> {
        let text = self.field(Field::Quick).text.trim().to_string();
        if text.is_empty() {
            return Vec::new();
        }
        let conns = &self.store.connections;
        let mut saved: Vec<Choice> = rank(&text, conns)
            .into_iter()
            .take(4)
            .map(Choice::Saved)
            .collect();
        let Some(t) = parse_quick(&text) else {
            return saved;
        };
        let exact = conns
            .iter()
            .any(|c| c.host.eq_ignore_ascii_case(&t.host) && c.port == t.port && t.user.is_none());
        if exact {
            return saved;
        }
        if looks_like_host(&text) {
            saved.insert(0, Choice::Host(t));
        } else {
            saved.push(Choice::Host(t));
        }
        saved
    }

    fn quick_enter(&mut self) -> Option<Action> {
        let n = self.quick_choices().len();
        if n == 0 {
            if self.field(Field::Quick).text.trim().is_empty() {
                self.set_message(
                    "Type a computer name or address, or the name of a saved connection.",
                    Tone::Muted,
                );
            } else {
                self.set_message(
                    "No saved connection matches, and that is not a host name.",
                    Tone::Warning,
                );
            }
            return None;
        }
        self.quick_choose(self.home.pick.min(n - 1))
    }

    fn quick_choose(&mut self, i: usize) -> Option<Action> {
        let choice = self.quick_choices().get(i)?.clone();
        self.field_mut(Field::Quick).set("");
        self.home.pick = 0;
        match choice {
            Choice::Saved(ci) => {
                // Already running: show it instead of a second session.
                let live = self
                    .store
                    .connections
                    .get(ci)
                    .and_then(|c| self.live_tab(c));
                if let Some(id) = live {
                    self.active = Some(id);
                    self.session_focus = false;
                    return None;
                }
                self.connect_saved(ci)
            }
            Choice::Host(t) => {
                // A new host: the editor asks for the sign-in; Connect
                // starts it and Save keeps it.
                self.new_connection_in("");
                self.field_mut(Field::Host).set(&t.host);
                self.field_mut(Field::Port).set(&t.port.to_string());
                let user = t.user.clone().unwrap_or_default();
                self.field_mut(Field::User).set(&user);
                self.active = None;
                self.settings_open = false;
                self.form_page = 0;
                self.home_scroll = 0;
                self.focus = Some(if user.is_empty() {
                    Field::User
                } else {
                    Field::Password
                });
                self.set_message(
                    format!(
                        "{} is new: enter the {}, then press Enter. Save keeps it.",
                        t.address(),
                        if user.is_empty() {
                            "user name and password"
                        } else {
                            "password"
                        }
                    ),
                    Tone::Muted,
                );
                None
            }
        }
    }

    /// Connects a saved connection with its settings; without a saved
    /// sign-in the editor opens on the missing field.
    pub(super) fn connect_saved(&mut self, i: usize) -> Option<Action> {
        let c = self.store.connections.get(i)?.clone();
        let r = self.store.resolve(&c);
        let first = r.apps.first().filter(|_| r.opens == Opens::Apps).cloned();
        if let Some(app) = &first
            && let Some(id) = self.launch_target(&r.name, &r.host)
        {
            self.set_message(format!("Starting {}…", app.name), Tone::Muted);
            return Some(Action::ExecApp(id, app.clone()));
        }
        if (r.user.is_empty() || r.password.is_none()) && !r.kerberos {
            self.select(i);
            self.active = None;
            self.settings_open = false;
            self.form_page = 0;
            self.home_scroll = 0;
            let need_user = r.user.is_empty();
            self.focus = Some(if need_user {
                Field::User
            } else {
                Field::Password
            });
            self.set_message(
                format!(
                    "Type the {} for {}, then press Enter.",
                    if need_user {
                        "user name and password"
                    } else {
                        "password"
                    },
                    c.name
                ),
                Tone::Warning,
            );
            return None;
        }
        self.set_message(format!("Connecting to {}…", r.host), Tone::Muted);
        let password = r.password.clone().unwrap_or_default();
        Some(session_action(&r, &password, first.as_ref()))
    }

    /// A connection started from an unsaved form: its live card offers Save.
    pub(super) fn home_note_unsaved(&mut self, c: &Connection) {
        let list = &mut self.home.unsaved;
        list.retain(|u| !(u.name == c.name && u.host == c.host));
        list.push(c.clone());
        if list.len() > 8 {
            list.remove(0);
        }
    }

    fn save_unsaved(&mut self, id: u64) {
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (name, host) = (t.name.clone(), t.host.clone());
        let Some(at) = self
            .home
            .unsaved
            .iter()
            .position(|u| u.name == name && u.host == host)
        else {
            return;
        };
        let mut c = self.home.unsaved.remove(at);
        c.last_used = self.home.since.get(&id).copied();
        if !c.group.is_empty() {
            self.store.ensure_group(&c.group);
        }
        self.store.connections.push(c);
        match self.store.save() {
            Ok(()) => self.set_message(
                format!("Saved {name}. It is in the sidebar now."),
                Tone::Muted,
            ),
            Err(e) => self.set_message(e, Tone::Danger),
        }
    }

    fn is_saved(&self, name: &str, host: &str) -> bool {
        self.store
            .connections
            .iter()
            .any(|c| c.name == name && c.host == host)
    }

    fn can_save(&self, name: &str, host: &str) -> bool {
        !self.is_saved(name, host)
            && self
                .home
                .unsaved
                .iter()
                .any(|u| u.name == name && u.host == host)
    }

    /// The live desktop tab of a saved connection, if one is connected.
    fn live_tab(&self, c: &Connection) -> Option<u64> {
        self.tabs
            .iter()
            .find(|t| {
                t.name == c.name
                    && t.host == c.host
                    && t.remote_app.is_none()
                    && matches!(t.state, TabState::Connected { .. })
            })
            .map(|t| t.id)
    }

    // ---- Stars ---------------------------------------------------------

    fn toggle_pin(&mut self, i: usize) {
        let Some(c) = self.store.connections.get_mut(i) else {
            return;
        };
        c.pinned = !c.pinned;
        let (on, name) = (c.pinned, c.name.clone());
        match self.store.save() {
            Ok(()) => self.set_message(
                if on {
                    format!("Pinned {name} to Favourites.")
                } else {
                    format!("Unpinned {name}.")
                },
                Tone::Muted,
            ),
            Err(e) => self.set_message(e, Tone::Danger),
        }
    }

    /// The editor header's star button for connection `i`.
    pub(super) fn star_button(&self, i: usize) -> (Button<'static>, Hit) {
        let on = self.store.connections.get(i).is_some_and(|c| c.pinned);
        let b = if on {
            Button::ghost("")
                .icon(Icon::StarFilled)
                .icon_color(pal().warning)
        } else {
            Button::ghost("").icon(Icon::Star)
        };
        (b, Hit::HomeView(HomeHit::Pin(Zone::Group, i)))
    }

    /// The sidebar row's star (shown on hover).
    pub(super) fn star_btn(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        i: usize,
    ) {
        let hit = Hit::HomeView(HomeHit::Pin(Zone::Group, i));
        let on = self.store.connections.get(i).is_some_and(|c| c.pinned);
        let st = self.st(hit);
        let mut k = Kit::new(cv, te, f, self.scale);
        k.icon_button(
            r,
            if on { Icon::StarFilled } else { Icon::Star },
            Variant::Ghost,
            st,
        );
        if on {
            // The kit draws ghost icons muted; a pinned star keeps its colour.
            k.icon_in(Icon::StarFilled, r, 14.0, pal().warning);
        }
        self.hits.push((r, hit));
    }

    /// "Home / Work / Office workstation" above the editor.
    pub(super) fn paint_crumbs(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let hit = Hit::HomeView(HomeHit::Home);
        let hover = self.hover == Some(hit);
        let mut parts: Vec<String> = Vec::new();
        let group = match (&self.group_edit, self.selected) {
            (Some(Some(path)), _) => super::parent_of(path).to_string(),
            (Some(None), _) | (None, None) => {
                super::normalize_path(&self.field(Field::GroupPath).text)
            }
            (None, Some(i)) => self.store.connections[i].group.clone(),
        };
        parts.extend(group.split('/').filter(|g| !g.is_empty()).map(String::from));
        let mut k = Kit::new(cv, te, f, s);
        let row = Rect::new(x - p(6.0), y - p(4.0), 0, p(24.0));
        let label = "Home";
        let lw = k.measure(Font::Regular, size::SMALL, label);
        let link = Rect::new(row.x, row.y, lw + p(30.0), row.h);
        if hover {
            k.cv.fill_round(link, radius::CONTROL * s, c.surface_hover);
        }
        let lc = if hover { c.text } else { c.text_muted };
        k.icon(
            Icon::Home,
            link.x + p(6.0),
            link.y + (link.h - p(13.0)) / 2,
            13.0,
            lc,
        );
        k.text_in(
            Font::Regular,
            size::SMALL,
            Rect::new(link.x + p(24.0), link.y, lw + 2, link.h),
            label,
            lc,
        );
        let mut cx = link.right() + p(4.0);
        for g in &parts {
            k.icon(
                Icon::ChevronRight,
                cx,
                row.y + (row.h - p(12.0)) / 2,
                12.0,
                c.text_faint,
            );
            cx += p(16.0);
            cx = k.text_in(
                Font::Regular,
                size::SMALL,
                Rect::new(cx, row.y, x + w - cx, row.h),
                g,
                c.text_muted,
            ) + p(6.0);
        }
        let tail = x + w - k.keys_width("Esc") - p(70.0);
        if tail > cx + p(16.0) {
            k.hints(
                tail,
                row.y + row.h / 2,
                p(80.0),
                &[Hint::Keys("Esc"), Hint::Text("back")],
            );
        }
        self.hits.push((link, hit));
    }

    // ---- Events --------------------------------------------------------

    pub(super) fn home_activate(&mut self, h: HomeHit) -> Option<Action> {
        match h {
            HomeHit::Home => self.go_home(),
            HomeHit::Choice(i) => return self.quick_choose(i),
            HomeHit::Open(id) => {
                self.active = Some(id);
                self.session_focus = false;
            }
            HomeHit::Disconnect(id) => return Some(Action::Disconnect(id)),
            HomeHit::SaveSession(id) => self.save_unsaved(id),
            HomeHit::Connect(_, i) => {
                let live = self.store.connections.get(i).and_then(|c| self.live_tab(c));
                if let Some(id) = live {
                    self.active = Some(id);
                    self.session_focus = false;
                    return None;
                }
                return self.connect_saved(i);
            }
            HomeHit::Edit(_, i) => {
                self.select(i);
                self.active = None;
                self.settings_open = false;
                self.form_page = 0;
                self.home_scroll = 0;
                self.focus = None;
            }
            HomeHit::Pin(_, i) => self.toggle_pin(i),
            HomeHit::Section(gi) => {
                let path = match self.store.groups.get(gi) {
                    Some(g) => g.path.clone(),
                    None => String::new(),
                };
                if !self.collapsed.remove(&path) {
                    self.collapsed.insert(path);
                }
            }
            HomeHit::Import => {
                // The backup's password is asked on the Settings page.
                self.settings_open = true;
                self.home_scroll = 0;
                self.focus = None;
                return Some(Action::PickImport);
            }
            HomeHit::NewConnection => {
                self.new_connection_in("");
                self.active = None;
                self.settings_open = false;
            }
        }
        None
    }

    /// Keys for the Home view (and Esc in the editor, which leads here).
    /// `Err` hands the key back to the usual handling.
    pub(super) fn home_key(&mut self, k: Key) -> Result<Option<Action>, Key> {
        let page = self.active.is_none() && !self.store.is_locked() && !self.vault_setup;
        if page && matches!(k, Key::Esc) {
            let editor = !self.settings_open && !self.home.showing;
            let settings = self.settings_open && !self.change_master && self.import_file.is_none();
            if editor || settings {
                self.go_home();
                return Ok(None);
            }
        }
        if !self.home_visible() {
            return Err(k);
        }
        let quick = self.focus == Some(Field::Quick);
        let kf = self.home.kfocus.filter(|_| self.focus.is_none());
        match k {
            Key::Enter => {
                if let Some(t) = kf {
                    return Ok(self.home_activate(t));
                }
                if quick {
                    return Ok(self.quick_enter());
                }
                // Nothing else here connects (the editor's form is hidden).
                Ok(None)
            }
            Key::Up | Key::Down if quick && !self.field(Field::Quick).text.trim().is_empty() => {
                let n = self.quick_choices().len();
                if n > 0 {
                    let i = self.home.pick.min(n - 1);
                    self.home.pick = if matches!(k, Key::Up) {
                        (i + n - 1) % n
                    } else {
                        (i + 1) % n
                    };
                }
                Ok(None)
            }
            Key::Tab | Key::BackTab => {
                // The field, then every card and button in paint order.
                let mut all = vec![None];
                all.extend(self.home.order.iter().map(|&h| Some(h)));
                let at = if quick {
                    Some(0)
                } else {
                    kf.and_then(|h| all.iter().position(|&x| x == Some(h)))
                };
                let n = all.len();
                let next = match (at, matches!(k, Key::BackTab)) {
                    (Some(i), false) => (i + 1) % n,
                    (Some(i), true) => (i + n - 1) % n,
                    (None, false) => 0,
                    (None, true) => n - 1,
                };
                match all[next] {
                    None => {
                        self.focus = Some(Field::Quick);
                        self.home.kfocus = None;
                    }
                    Some(h) => {
                        self.focus = None;
                        self.home.kfocus = Some(h);
                    }
                }
                Ok(None)
            }
            Key::Esc => {
                if kf.is_some() {
                    self.home.kfocus = None;
                    self.focus = Some(Field::Quick);
                } else if quick && !self.field(Field::Quick).text.is_empty() {
                    self.field_mut(Field::Quick).set("");
                    self.home.pick = 0;
                } else {
                    self.focus = None;
                }
                Ok(None)
            }
            // Ctrl+S would save the hidden editor form.
            Key::Save => Ok(None),
            Key::Char(_) | Key::Paste(_) | Key::Backspace | Key::Delete if quick => {
                self.home.pick = 0;
                Err(k)
            }
            k => Err(k),
        }
    }

    // ---- Sessions and thumbnails (called by the app) -------------------

    /// A session tab connected: its clock starts, and its saved
    /// connection counts as used now.
    pub fn session_started(&mut self, id: u64) {
        let now = self.now();
        self.home.since.entry(id).or_insert(now);
        self.mark_used(id, now, None);
    }

    /// A session ended (or its tab closed): its saved connection keeps
    /// when it was used and for how long.
    pub fn session_ended(&mut self, id: u64) {
        let Some(start) = self.home.since.remove(&id) else {
            return;
        };
        let now = self.now();
        self.mark_used(id, now, Some(now.saturating_sub(start)));
        self.home.thumbs.remove(&id);
    }

    fn mark_used(&mut self, id: u64, now: u64, duration: Option<u64>) {
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (name, host) = (t.name.clone(), t.host.clone());
        let Some(c) = self
            .store
            .connections
            .iter_mut()
            .find(|c| c.name == name && c.host == host)
        else {
            return;
        };
        c.last_used = Some(now);
        if duration.is_some() {
            c.last_duration = duration;
        }
        // A locked vault cannot be written; the next save keeps it.
        let _ = self.store.save();
    }

    /// The thumbnail size the live cards want (physical px), once painted.
    pub fn thumb_target(&self) -> Option<(usize, usize)> {
        let (w, h) = self.home.thumb_size;
        (w > 0 && h > 0).then_some((w, h))
    }

    /// A session reported damage: whether to make its thumbnail now, once
    /// later, or not (hidden view: it is made when the view shows).
    pub fn thumb_due(&mut self, id: u64) -> ThumbDue {
        let visible = self.home_visible();
        let slot = self.home.thumbs.entry(id).or_default();
        if !visible {
            slot.stale = true;
            return ThumbDue::No;
        }
        if slot.pending {
            return ThumbDue::No;
        }
        match slot.at.map(|t| t.elapsed()) {
            Some(e) if e < THUMB_EVERY => {
                slot.pending = true;
                ThumbDue::After(THUMB_EVERY - e)
            }
            _ => ThumbDue::Now,
        }
    }

    /// The delayed refresh arrived: true when it should be made now.
    pub fn thumb_tick(&mut self, id: u64) -> bool {
        if let Some(slot) = self.home.thumbs.get_mut(&id) {
            slot.pending = false;
        }
        self.home_visible() && self.tabs.iter().any(|t| t.id == id)
    }

    pub fn set_thumb(&mut self, id: u64, pic: Thumb) {
        let slot = self.home.thumbs.entry(id).or_default();
        slot.pic = Some(pic);
        slot.at = Some(Instant::now());
        slot.stale = false;
    }

    /// Sessions whose thumbnail is missing, stale or sized for another
    /// layout while the view shows (the app makes them, then repaints).
    pub fn thumbs_needed(&self) -> Vec<u64> {
        let Some((tw, th)) = self.thumb_target().filter(|_| self.home_visible()) else {
            return Vec::new();
        };
        self.tabs
            .iter()
            .filter(|t| t.remote_app.is_none() && matches!(t.state, TabState::Connected { .. }))
            .filter(|t| match self.home.thumbs.get(&t.id) {
                Some(ThumbSlot {
                    pic: Some(p),
                    stale,
                    ..
                }) => *stale || p.w > tw || p.h > th || (p.w + 2 < tw && p.h + 2 < th),
                _ => true,
            })
            .map(|t| t.id)
            .collect()
    }

    // ---- Painting ------------------------------------------------------

    pub(super) fn paint_home_view(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        self.home_area = area;
        self.home.order.clear();
        self.home.reserve = 0;
        let ids: Vec<u64> = self.tabs.iter().map(|t| t.id).collect();
        self.home.thumbs.retain(|id, _| ids.contains(id));
        self.home.since.retain(|id, _| ids.contains(id));

        let mx = if area.w < p(760.0) { p(24.0) } else { p(40.0) };
        let w = (area.w - 2 * mx).min(p(1760.0));
        let x = area.x + (area.w - w) / 2;
        let top = area.y - self.home_scroll;
        let y = if self.store.connections.is_empty() && self.store.groups.is_empty() {
            self.paint_first_start(cv, te, f, x, top, w, area)
        } else {
            let mut y = self.paint_hero(cv, te, f, x, top + p(24.0), w);
            y = self.paint_live(cv, te, f, x, y, w);
            y = self.paint_pinned_and_recent(cv, te, f, x, y, w);
            self.paint_groups(cv, te, f, x, y, w)
        };
        self.home_content = y + p(40.0) - top;
        let max = (self.home_content - area.h).max(0);
        if self.home_scroll > max {
            self.home_scroll = max;
        }
        Kit::new(cv, te, f, s).scrollbar(area, self.home_content, self.home_scroll);
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
    }

    /// The kit state of a Home target: hover, press, keyboard focus.
    fn hst(&self, h: HomeHit) -> State {
        let mut st = self.st(Hit::HomeView(h));
        st.focus = self.focus.is_none() && self.home.kfocus == Some(h);
        st
    }

    fn hovered(&self, f: impl Fn(HomeHit) -> bool) -> bool {
        matches!(self.hover, Some(Hit::HomeView(h)) if f(h))
    }

    fn kfocused(&self, h: HomeHit) -> bool {
        self.focus.is_none() && self.home.kfocus == Some(h)
    }

    /// A button for the Home view (records its hit and Tab stop).
    fn hbtn(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        b: &Button,
        h: HomeHit,
    ) {
        let st = self.hst(h);
        Kit::new(cv, te, f, self.scale).button(r, b, st);
        self.hits.push((r, Hit::HomeView(h)));
        self.home.order.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn hicon(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Icon,
        v: Variant,
        h: HomeHit,
    ) {
        let st = self.hst(h);
        Kit::new(cv, te, f, self.scale).icon_button(r, icon, v, st);
        self.hits.push((r, Hit::HomeView(h)));
    }

    /// A section caption with a count: "LIVE SESSIONS  2".
    #[allow(clippy::too_many_arguments)]
    fn caption_count(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        icon: Option<(Icon, u32)>,
        text: &str,
        count: usize,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let mut tx = x;
        if let Some((icon, color)) = icon {
            k.icon(icon, x + p(1.0), y + p(2.0), 14.0, color);
            tx += p(20.0);
        }
        let row = Rect::new(tx, y, w, p(18.0));
        let base = k.baseline(Font::Semi, size::CAPTION, row);
        let end = k.caption_text(tx, base, &text.to_uppercase(), c.text_muted);
        if count > 0 {
            let n = count.to_string();
            let nw = k.measure(Font::Semi, 10.5, &n) + p(12.0);
            let r = Rect::new(end + p(8.0), y + p(1.0), nw.max(p(18.0)), p(16.0));
            k.cv.fill_round(r, r.h as f32 / 2.0, c.surface_hover);
            k.text_center(Font::Semi, 10.5, r, &n, c.text_secondary);
        }
    }

    /// The greeting, the quick connect field and its suggestion, in a
    /// panel with "your network" at the right on wide windows.
    #[allow(clippy::too_many_arguments)]
    fn paint_hero(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let (hour, wd, day, month) = local_time(self.home.clock);
        let live = self
            .tabs
            .iter()
            .filter(|t| matches!(t.state, TabState::Connected { .. }))
            .count();
        let saved = self.store.connections.len();
        let wide = w >= p(1000.0);
        let pad = p(28.0);
        let panel = Rect::new(x, y, w, p(212.0));
        let ix = x + pad;
        let fw = if wide {
            (w - 2 * pad - p(400.0)).min(p(760.0))
        } else {
            w - 2 * pad
        };
        let top = y + pad;
        {
            let mut k = Kit::new(cv, te, f, s);
            k.cv.round_border(panel, radius::DIALOG * s, c.border, c.surface);
            let date = format!(
                "{}, {} {}",
                WEEKDAYS[wd as usize % 7],
                day,
                MONTHS[(month as usize + 11) % 12]
            );
            let row = Rect::new(ix, top, w, p(18.0));
            let base = k.baseline(Font::Semi, size::CAPTION, row);
            k.caption_text(ix + p(1.0), base, &date.to_uppercase(), c.accent);
            let end = k.text(
                Font::Semi,
                30.0,
                ix,
                top + p(54.0),
                greeting(hour),
                c.text,
                fw,
            );
            // What runs and what is saved, as pills after the greeting.
            let mut px = end + p(16.0);
            let py = top + p(34.0);
            if live > 0 {
                let t = format!("{live} live");
                px += k.pill(px, py, &t, Tone::Success, Lead::Dot) + p(6.0);
            }
            let t = format!("{saved} saved");
            if px + k.pill_width(&t, Lead::Icon(Icon::Monitor)) < ix + fw {
                k.pill(px, py, &t, Tone::Neutral, Lead::Icon(Icon::Monitor));
            }
        }
        let fr = Rect::new(ix, top + p(76.0), fw, p(50.0));
        self.paint_quick_field(cv, te, f, fr);
        if wide {
            let net = Rect::new(
                panel.right() - p(400.0),
                y + p(10.0),
                p(380.0),
                panel.h - p(20.0),
            );
            self.paint_constellation(cv, te, f, net);
        }
        panel.bottom() + p(36.0)
    }

    /// The quick connect field with the chosen suggestion inside it and
    /// the key hints under it.
    fn paint_quick_field(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, fr: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let choices = self.quick_choices();
        let pick = self.home.pick.min(choices.len().saturating_sub(1));
        let typed = !self.field(Field::Quick).text.trim().is_empty();
        // The suggestion: avatar, name and where it goes, then the Enter key.
        let chip: Option<(String, String, Option<usize>)> = choices.get(pick).map(|ch| match ch {
            Choice::Saved(i) => {
                let conn = &self.store.connections[*i];
                (conn.name.clone(), conn.host.clone(), Some(*i))
            }
            Choice::Host(t) => (
                t.address(),
                match &t.user {
                    Some(u) => format!("new · as {u}"),
                    None => "new host".into(),
                },
                None,
            ),
        });
        let mut chip_w = 0;
        if let Some((name, sub, _)) = &chip {
            let mut k = Kit::new(cv, te, f, s);
            let nw = k.measure(Font::Semi, size::BODY, name).min(p(220.0));
            let sw = k.measure(Font::Regular, size::SMALL, sub).min(p(160.0));
            chip_w = p(8.0)
                + p(26.0)
                + p(10.0)
                + nw
                + p(8.0)
                + sw
                + p(12.0)
                + k.keys_width("Enter")
                + p(8.0);
            if choices.len() > 1 {
                chip_w += p(44.0);
            }
            chip_w = chip_w.min(fr.w / 2);
        } else if typed {
            chip_w = p(110.0);
        }
        self.home.reserve = chip_w + if chip_w > 0 { p(8.0) } else { 0 };
        let placeholder = "Connect to a PC: name, address or user@host:port";
        // The field frame comes from the shared text input (caret, clicks).
        self.text_input_i(cv, te, f, fr, Some(Icon::Bolt), Field::Quick, placeholder);
        let mut k = Kit::new(cv, te, f, s);
        let right = fr.right() - p(8.0);
        let cy = fr.y + fr.h / 2;
        if let Some((name, sub, conn)) = chip {
            let r = Rect::new(right - chip_w, fr.y + p(7.0), chip_w, fr.h - p(14.0));
            k.cv.fill_round(r, radius::CONTROL * s, c.accent_subtle);
            let d = p(26.0);
            let av = Rect::new(r.x + p(6.0), cy - d / 2, d, d);
            match conn {
                Some(i) => {
                    let col = self.store.connection_color(&self.store.connections[i]);
                    let dot = self.connection_dot(&self.store.connections[i]);
                    k.avatar(av, &name, col, dot, c.accent_subtle);
                }
                None => {
                    k.cv.fill_round(av, d as f32 * 0.28, c.surface_raised);
                    k.icon_in(Icon::Plus, av, 15.0, c.accent);
                }
            }
            let mut tx = av.right() + p(10.0);
            let kw = k.keys_width("Enter");
            let count_w = if choices.len() > 1 { p(44.0) } else { 0 };
            let text_end = r.right() - p(8.0) - kw - count_w - p(8.0);
            let base = k.baseline(Font::Semi, size::BODY, r);
            tx = k.text(
                Font::Semi,
                size::BODY,
                tx,
                base,
                &name,
                c.text,
                (text_end - tx).min(p(220.0)),
            );
            if tx + p(30.0) < text_end {
                k.text(
                    Font::Regular,
                    size::SMALL,
                    tx + p(8.0),
                    base,
                    &sub,
                    c.text_muted,
                    text_end - tx - p(8.0),
                );
            }
            if choices.len() > 1 {
                let t = format!("{}/{}", pick + 1, choices.len());
                k.text_right(
                    Font::Regular,
                    size::SMALL,
                    Rect::new(
                        r.right() - p(8.0) - kw - count_w,
                        r.y,
                        count_w - p(6.0),
                        r.h,
                    ),
                    &t,
                    c.text_muted,
                );
            }
            k.keys(r.right() - p(8.0) - kw, cy - p(9.0), "Enter");
            self.hits.push((r, Hit::HomeView(HomeHit::Choice(pick))));
        } else if typed {
            k.text_right(
                Font::Regular,
                size::SMALL,
                Rect::new(right - chip_w, fr.y, chip_w - p(4.0), fr.h),
                "No match",
                c.text_faint,
            );
        }
        let hints: &[Hint] = if choices.len() > 1 {
            &[
                Hint::Keys("Enter"),
                Hint::Text("connects"),
                Hint::Keys("↑"),
                Hint::Keys("↓"),
                Hint::Text("other matches"),
                Hint::Keys("Esc"),
                Hint::Text("clears"),
            ]
        } else if self.store.connections.is_empty() {
            &[
                Hint::Keys("Enter"),
                Hint::Text("connects"),
                Hint::Keys("Ctrl+N"),
                Hint::Text("sets one up in detail"),
            ]
        } else {
            &[
                Hint::Keys("Enter"),
                Hint::Text("connects"),
                Hint::Keys("Tab"),
                Hint::Text("moves to the cards"),
                Hint::Keys("Ctrl+N"),
                Hint::Text("new connection"),
            ]
        };
        k.hints(fr.x + p(2.0), fr.bottom() + p(20.0), fr.w, hints);
    }

    /// The hero's picture of "your network": this PC on the left and the
    /// connections that matter now on an arc to its right; live ones are
    /// linked in green.
    fn paint_constellation(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, r: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        // Live sessions first, then favourites, then recent ones.
        let mut picks: Vec<(usize, bool)> = Vec::new();
        let conns = &self.store.connections;
        for t in &self.tabs {
            if let Some(i) = conns
                .iter()
                .position(|cc| cc.name == t.name && cc.host == t.host)
                && matches!(t.state, TabState::Connected { .. })
                && !picks.iter().any(|x| x.0 == i)
            {
                picks.push((i, true));
            }
        }
        let rest: Vec<usize> = (0..conns.len())
            .filter(|&i| conns[i].pinned)
            .chain(recents(conns, 6))
            .chain(0..conns.len())
            .collect();
        for i in rest {
            if picks.len() >= 4 {
                break;
            }
            if !picks.iter().any(|x| x.0 == i) {
                picks.push((i, false));
            }
        }
        let center = (r.x + p(56.0), r.y + r.h / 2);
        let n = picks.len();
        let (rx, ry) = ((r.w - p(140.0)) as f32, (r.h / 2 - p(20.0)) as f32);
        let spots: Vec<(usize, bool, f32, f32)> = picks
            .iter()
            .enumerate()
            .map(|(k, &(i, live))| {
                // Evenly over -64..64 degrees; every other one a little nearer.
                let t = if n == 1 {
                    0.5
                } else {
                    k as f32 / (n - 1) as f32
                };
                let a = (-70.0 + 140.0 * t).to_radians();
                let near = if k % 2 == 1 { 0.78 } else { 1.0 };
                (
                    i,
                    live,
                    center.0 as f32 + rx * near * a.cos(),
                    center.1 as f32 + ry * a.sin(),
                )
            })
            .collect();
        // Orbit hints behind everything.
        for f in [0.45f32, 0.78, 1.0] {
            let pts: Vec<(f32, f32)> = (0..=24)
                .map(|i| {
                    let a = (-70.0 + 140.0 * i as f32 / 24.0f32).to_radians();
                    (
                        center.0 as f32 + rx * f * a.cos(),
                        center.1 as f32 + ry * a.sin() * f.max(0.6),
                    )
                })
                .collect();
            cv.stroke(&pts, 1.0, c.divider);
        }
        for &(_, live, px, py) in &spots {
            let (color, w) = if live {
                (c.success, 2.0 * s)
            } else {
                (c.border_strong, 1.2 * s)
            };
            cv.stroke(&[(center.0 as f32, center.1 as f32), (px, py)], w, color);
        }
        let mut k = Kit::new(cv, te, f, s);
        k.cv.fill_circle(center.0 as f32, center.1 as f32, 36.0 * s, c.accent_subtle);
        k.logo(center.0 - p(22.0), center.1 - p(22.0), 44.0);
        k.text_center(
            Font::Regular,
            size::SMALL - 1.0,
            Rect::new(center.0 - p(50.0), center.1 + p(38.0), p(100.0), p(16.0)),
            "This PC",
            c.text_muted,
        );
        for &(i, live, px, py) in &spots {
            let conn = &self.store.connections[i];
            let d = if live { p(36.0) } else { p(30.0) };
            let av = Rect::new(px as i32 - d / 2, py as i32 - d / 2, d, d);
            let col = self.store.connection_color(conn);
            let halo = Rect::new(av.x - p(4.0), av.y - p(4.0), d + p(8.0), d + p(8.0));
            k.cv.fill_round(halo, halo.w as f32 * 0.3, c.surface);
            k.avatar(av, &conn.name, col, live.then_some(c.success), c.surface);
            // The name next to it, short.
            let name = conn
                .name
                .split(" (")
                .next()
                .unwrap_or(&conn.name)
                .to_string();
            let tc = if live { c.text_secondary } else { c.text_muted };
            k.text(
                if live { Font::Semi } else { Font::Regular },
                size::SMALL - 0.5,
                av.right() + p(8.0),
                av.y + d / 2 + p(4.0),
                &name,
                tc,
                r.right() - av.right() - p(8.0),
            );
        }
    }

    /// The running sessions as cards with a picture of each.
    #[allow(clippy::too_many_arguments)]
    fn paint_live(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let cards: Vec<LiveCard> = self
            .tabs
            .iter()
            .filter(|t| matches!(t.state, TabState::Connected { .. } | TabState::Connecting))
            .map(|t| LiveCard {
                id: t.id,
                name: t.name.clone(),
                host: t.redirected_to.clone().unwrap_or_else(|| t.host.clone()),
                connecting: t.state == TabState::Connecting,
                spanned: t.spanned,
                apps: t.remote_app.as_ref().map(|v| {
                    (
                        v.windows.len(),
                        v.windows.iter().take(3).map(|w| w.title.clone()).collect(),
                    )
                }),
            })
            .collect();
        if cards.is_empty() {
            return y;
        }
        self.caption_count(
            cv,
            te,
            f,
            x,
            y,
            w,
            Some((Icon::Record, c.success)),
            "Live sessions",
            cards.len(),
        );
        let y = y + p(30.0);
        let gap = p(16.0);
        let (cols, cw) = grid_fill(w, p(260.0), p(400.0), gap, cards.len());
        let thumb_h = (cw - p(12.0)) * 9 / 16;
        self.home.thumb_size = ((cw - p(12.0)).max(1) as usize, thumb_h.max(1) as usize);
        let ch = thumb_h + p(12.0) + p(92.0);
        let now = self.now();
        for (n, card) in cards.iter().enumerate() {
            let (col, row) = (n as i32 % cols, n as i32 / cols);
            let r = Rect::new(x + col * (cw + gap), y + row * (ch + gap), cw, ch);
            let open = HomeHit::Open(card.id);
            let hover = self.hovered(|h| matches!(h, HomeHit::Open(i) | HomeHit::Disconnect(i) | HomeHit::SaveSession(i) if i == card.id));
            let focus = self.kfocused(open);
            self.hits.push((r, Hit::HomeView(open)));
            self.home.order.push(open);
            let color = self.tab_color(&card.name, &card.host);
            let thumb = Rect::new(r.x + p(6.0), r.y + p(6.0), r.w - p(12.0), thumb_h);
            {
                let mut k = Kit::new(cv, te, f, s);
                card_frame(&mut k, r, hover, focus);
                let fill = if hover && c.dark {
                    c.surface_raised
                } else {
                    c.surface
                };
                let pic = self.home.thumbs.get(&card.id).and_then(|t| t.pic.as_ref());
                match (&card.apps, pic) {
                    (Some((n, titles)), _) => {
                        // RemoteApp: its windows instead of a desktop picture.
                        k.cv.fill_round(thumb, 8.0 * s, c.accent_subtle);
                        let cx = thumb.x + thumb.w / 2;
                        let tile = p(46.0);
                        let tr = Rect::new(
                            cx - tile / 2,
                            thumb.y + thumb.h / 2 - tile + p(4.0),
                            tile,
                            tile,
                        );
                        k.cv.fill_round(tr, 12.0 * s, c.surface_raised);
                        k.icon_in(Icon::Apps, tr, 22.0, c.accent);
                        let line = format!("{n} app window{}", if *n == 1 { "" } else { "s" });
                        let tw = thumb.w - p(24.0);
                        k.text_center(
                            Font::Semi,
                            size::HEADING,
                            Rect::new(thumb.x + p(12.0), tr.bottom() + p(8.0), tw, p(22.0)),
                            &line,
                            c.text,
                        );
                        let sub = titles.join(" · ");
                        k.text_center(
                            Font::Regular,
                            size::SMALL,
                            Rect::new(thumb.x + p(12.0), tr.bottom() + p(30.0), tw, p(18.0)),
                            &sub,
                            c.text_muted,
                        );
                    }
                    (None, Some(t)) if !card.connecting => {
                        // Letterboxed picture, centred.
                        k.cv.fill_round(thumb, 8.0 * s, 0x000000);
                        let (pw, ph) = if t.w * thumb.h as usize >= t.h * thumb.w as usize {
                            (thumb.w, (thumb.w as usize * t.h / t.w.max(1)) as i32)
                        } else {
                            ((thumb.h as usize * t.w / t.h.max(1)) as i32, thumb.h)
                        };
                        let pr = Rect::new(
                            thumb.x + (thumb.w - pw) / 2,
                            thumb.y + (thumb.h - ph) / 2,
                            pw,
                            ph,
                        );
                        k.cv.draw_rgba_scaled(pr, t.w, t.h, &t.rgba);
                        if card.spanned {
                            let band =
                                Rect::new(thumb.x, thumb.bottom() - p(30.0), thumb.w, p(30.0));
                            k.cv.fill_alpha(band, 0x000000, 150);
                            k.icon(
                                Icon::Monitors,
                                band.x + p(10.0),
                                band.y + p(8.0),
                                14.0,
                                0xffffff,
                            );
                            k.text_in(
                                Font::Regular,
                                size::SMALL,
                                Rect::new(band.x + p(30.0), band.y, band.w - p(40.0), band.h),
                                "Shown on its monitors",
                                0xffffff,
                            );
                        }
                        round_corners(k.cv, thumb, 8.0 * s, fill);
                    }
                    _ => {
                        k.cv.fill_round(thumb, 8.0 * s, c.surface_hover);
                        let (icon, text) = if card.connecting {
                            (Icon::Refresh, "Connecting…")
                        } else {
                            (Icon::Monitor, "Picture shows here")
                        };
                        let ir =
                            Rect::new(thumb.x, thumb.y + thumb.h / 2 - p(30.0), thumb.w, p(30.0));
                        k.icon_in(icon, ir, 22.0, c.text_faint);
                        k.text_center(
                            Font::Regular,
                            size::SMALL,
                            Rect::new(thumb.x, ir.bottom() + p(4.0), thumb.w, p(18.0)),
                            text,
                            c.text_muted,
                        );
                    }
                }
                // Name, host, state and how long it runs.
                let d = p(32.0);
                let ty = thumb.bottom() + p(14.0);
                let ring = if hover && c.dark {
                    c.surface_raised
                } else {
                    c.surface
                };
                let status = if card.connecting {
                    c.warning
                } else {
                    c.success
                };
                k.avatar(
                    Rect::new(r.x + p(14.0), ty, d, d),
                    &card.name,
                    color,
                    Some(status),
                    ring,
                );
                let tx = r.x + p(14.0) + d + p(12.0);
                let (pill, tone) = if card.connecting {
                    ("Connecting", Tone::Warning)
                } else {
                    ("Live", Tone::Success)
                };
                let pw = k.pill_width(pill, Lead::Dot);
                k.pill(r.right() - p(14.0) - pw, ty + p(1.0), pill, tone, Lead::Dot);
                let tw = r.right() - p(14.0) - pw - p(8.0) - tx;
                k.text(
                    Font::Semi,
                    size::BODY + 1.0,
                    tx,
                    ty + p(14.0),
                    &card.name,
                    c.text,
                    tw,
                );
                k.text(
                    Font::Regular,
                    size::SMALL,
                    tx,
                    ty + p(31.0),
                    &card.host,
                    c.text_muted,
                    tw,
                );
                let since = self.home.since.get(&card.id).copied();
                let line = match since {
                    Some(t) if !card.connecting => format!("for {}", span(now.saturating_sub(t))),
                    _ if card.connecting => "starting".into(),
                    _ => "running".into(),
                };
                let ly = r.bottom() - p(28.0);
                k.icon(Icon::Clock, r.x + p(14.0), ly - p(7.0), 13.0, c.text_faint);
                k.text_in(
                    Font::Regular,
                    size::SMALL,
                    Rect::new(r.x + p(33.0), ly - p(10.0), cw / 2, p(20.0)),
                    &line,
                    c.text_secondary,
                );
            }
            // Open / Disconnect (and Save for a quick-connected one).
            let bh = p(28.0);
            let by = r.bottom() - p(14.0) - bh;
            let disc = Rect::new(r.right() - p(14.0) - bh, by, bh, bh);
            self.hicon(
                cv,
                te,
                f,
                disc,
                Icon::Power,
                Variant::DangerGhost,
                HomeHit::Disconnect(card.id),
            );
            let ob = Button::secondary("Open");
            let ow = self.btn_w(te, f, &ob) - p(6.0);
            let orr = Rect::new(disc.x - p(6.0) - ow, by, ow, bh);
            let st = State {
                hover: self.hover == Some(Hit::HomeView(open)),
                ..State::default()
            };
            Kit::new(cv, te, f, s).button(orr, &ob, st);
            if self.can_save(&card.name, &card.host) {
                let sb = Button::ghost("Save")
                    .icon(Icon::StarFilled)
                    .icon_color(c.warning);
                let sw = self.btn_w(te, f, &sb) - p(6.0);
                let sr = Rect::new(orr.x - p(6.0) - sw, by, sw, bh);
                self.hbtn(cv, te, f, sr, &sb, HomeHit::SaveSession(card.id));
            }
        }
        let rows = (cards.len() as i32 + cols - 1) / cols;
        y + rows * (ch + gap) - gap + p(36.0)
    }

    /// Favourites (pinned) and, next to them on wide windows, the recent
    /// connections.
    #[allow(clippy::too_many_arguments)]
    fn paint_pinned_and_recent(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let pinned: Vec<usize> = (0..self.store.connections.len())
            .filter(|&i| self.store.connections[i].pinned)
            .collect();
        let recent = recents(&self.store.connections, 6);
        let gap = p(28.0);
        if !recent.is_empty() && w >= p(1080.0) {
            let rw = (w * 34 / 100).clamp(p(340.0), p(460.0));
            let fw = w - rw - gap;
            let a = self.paint_pinned(cv, te, f, x, y, fw, &pinned);
            let b = self.paint_recent(cv, te, f, x + fw + gap, y, rw, &recent);
            return a.max(b);
        }
        let mut y = self.paint_pinned(cv, te, f, x, y, w, &pinned);
        if !recent.is_empty() {
            y = self.paint_recent(cv, te, f, x, y, w, &recent);
        }
        y
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_pinned(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        pinned: &[usize],
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        self.caption_count(
            cv,
            te,
            f,
            x,
            y,
            w,
            Some((Icon::StarFilled, c.warning)),
            "Favourites",
            pinned.len(),
        );
        let y = y + p(30.0);
        if pinned.is_empty() {
            // One quiet line that says how to fill this.
            let r = Rect::new(x, y, w, p(52.0));
            let mut k = Kit::new(cv, te, f, s);
            k.cv.round_border(r, radius::CARD * s, c.border, c.bg);
            k.icon(
                Icon::Star,
                r.x + p(16.0),
                r.y + (r.h - p(16.0)) / 2,
                16.0,
                c.text_faint,
            );
            k.text_in(
                Font::Regular,
                size::BODY,
                Rect::new(r.x + p(42.0), r.y, r.w - p(56.0), r.h),
                "Star a connection (in its card, the sidebar or the editor) to pin it here.",
                c.text_muted,
            );
            return r.bottom() + p(36.0);
        }
        let gap = p(14.0);
        let (cols, cw) = grid_fill(w, p(250.0), p(400.0), gap, pinned.len());
        let ch = p(120.0);
        for (n, &i) in pinned.iter().enumerate() {
            let (col, row) = (n as i32 % cols, n as i32 / cols);
            let r = Rect::new(x + col * (cw + gap), y + row * (ch + gap), cw, ch);
            self.conn_card(cv, te, f, r, i, Zone::Favourite);
        }
        let rows = (pinned.len() as i32 + cols - 1) / cols;
        y + rows * (ch + gap) - gap + p(36.0)
    }

    /// A favourite's card: avatar, name, host and user, chips; Connect
    /// (or Open when it runs) on hover.
    fn conn_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        i: usize,
        zone: Zone,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let conn = self.store.resolve(&self.store.connections[i]);
        let color = self.store.connection_color(&self.store.connections[i]);
        let dot = self.connection_dot(&conn);
        let live = self.live_tab(&conn);
        let edit = HomeHit::Edit(zone, i);
        let connect = HomeHit::Connect(zone, i);
        let hover = self.hovered(|h| matches!(h, HomeHit::Edit(z, j) | HomeHit::Connect(z, j) | HomeHit::Pin(z, j) if z == zone && j == i));
        let focus = self.kfocused(connect);
        self.hits.push((r, Hit::HomeView(edit)));
        self.home.order.push(connect);
        let ring = if hover && c.dark {
            c.surface_raised
        } else {
            c.surface
        };
        {
            let mut k = Kit::new(cv, te, f, s);
            card_frame(&mut k, r, hover, focus);
            let d = p(40.0);
            k.avatar(
                Rect::new(r.x + p(16.0), r.y + p(18.0), d, d),
                &conn.name,
                color,
                dot,
                ring,
            );
            let tx = r.x + p(16.0) + d + p(12.0);
            let tw = r.right() - tx - p(44.0);
            k.text(
                Font::Semi,
                size::BODY + 1.5,
                tx,
                r.y + p(35.0),
                &conn.name,
                c.text,
                tw,
            );
            let sub = match (conn.port == 3389, conn.user.is_empty()) {
                (true, true) => conn.host.clone(),
                (true, false) => format!("{} · {}", conn.host, conn.user),
                (false, true) => format!("{}:{}", conn.host, conn.port),
                (false, false) => format!("{}:{} · {}", conn.host, conn.port, conn.user),
            };
            k.text(
                Font::Regular,
                size::SMALL,
                tx,
                r.y + p(53.0),
                &sub,
                c.text_muted,
                tw,
            );
            // Chips, or when it was last used.
            let mut cx = r.x + p(16.0);
            let cy = r.bottom() - p(34.0);
            let room = if hover || focus || live.is_some() {
                r.right() - p(110.0)
            } else {
                r.right() - p(14.0)
            };
            let list = chips(&conn);
            if list.is_empty() {
                let when = match conn.last_used {
                    Some(t) => format!("Used {}", ago(self.now(), t)),
                    None => "Not used yet".into(),
                };
                k.icon(Icon::Clock, cx, cy + p(3.0), 13.0, c.text_faint);
                k.text_in(
                    Font::Regular,
                    size::SMALL,
                    Rect::new(cx + p(19.0), cy, room - cx - p(19.0), p(20.0)),
                    &when,
                    c.text_muted,
                );
            }
            for (t, tone, lead) in &list {
                let pw = k.pill_width(t, *lead);
                if cx + pw > room {
                    break;
                }
                k.pill(cx, cy, t, *tone, *lead);
                cx += pw + p(6.0);
            }
        }
        // Star, top right.
        let star = Rect::new(r.right() - p(38.0), r.y + p(12.0), p(28.0), p(28.0));
        let pin = HomeHit::Pin(zone, i);
        let pinned = self.store.connections[i].pinned;
        let st = self.hst(pin);
        {
            let mut k = Kit::new(cv, te, f, s);
            if pinned {
                if st.hover {
                    k.cv.fill_round(star, radius::CONTROL * s, c.surface_hover);
                }
                k.icon_in(Icon::StarFilled, star, 15.0, c.warning);
            } else {
                k.icon_button(star, Icon::Star, Variant::Ghost, st);
            }
        }
        self.hits.push((star, Hit::HomeView(pin)));
        // Connect (or Open) at the bottom right.
        if hover || focus || live.is_some() {
            let b = if live.is_some() {
                Button::secondary("Open").icon(Icon::Window)
            } else {
                Button::primary("Connect").icon(Icon::Play)
            };
            let bw = self.btn_w(te, f, &b) - p(8.0);
            let br = Rect::new(
                r.right() - p(14.0) - bw,
                r.bottom() - p(14.0) - p(28.0),
                bw,
                p(28.0),
            );
            let st = State {
                hover: self.hover == Some(Hit::HomeView(connect)),
                press: self.press == Some(Hit::HomeView(connect)),
                ..State::default()
            };
            Kit::new(cv, te, f, s).button(br, &b, st);
            self.hits.push((br, Hit::HomeView(connect)));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_recent(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        recent: &[usize],
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        self.caption_count(
            cv,
            te,
            f,
            x,
            y,
            w,
            Some((Icon::Clock, c.text_muted)),
            "Recent",
            0,
        );
        let y = y + p(30.0);
        let rh = p(54.0);
        let heights = vec![rh; recent.len()];
        let rows = crate::kit::card_rows(cv, s, x, y, w, &heights);
        let now = self.now();
        for (&i, r) in recent.iter().zip(rows) {
            let conn = self.store.resolve(&self.store.connections[i]);
            let color = self.store.connection_color(&self.store.connections[i]);
            let dot = self.connection_dot(&conn);
            let edit = HomeHit::Edit(Zone::Recent, i);
            let connect = HomeHit::Connect(Zone::Recent, i);
            let hover = self.hovered(|h| matches!(h, HomeHit::Edit(Zone::Recent, j) | HomeHit::Connect(Zone::Recent, j) if j == i));
            let focus = self.kfocused(connect);
            self.hits.push((r, Hit::HomeView(edit)));
            self.home.order.push(connect);
            let mut k = Kit::new(cv, te, f, s);
            let inner = Rect::new(r.x + p(4.0), r.y + p(3.0), r.w - p(8.0), r.h - p(6.0));
            if hover {
                k.cv.fill_round(inner, 6.0 * s, c.surface_hover);
            }
            if focus {
                k.focus_ring(inner, 6.0);
            }
            let ring = if hover { c.surface_hover } else { c.surface };
            let d = p(30.0);
            k.avatar(
                Rect::new(r.x + p(14.0), r.y + (r.h - d) / 2, d, d),
                &conn.name,
                color,
                dot,
                ring,
            );
            let tx = r.x + p(14.0) + d + p(12.0);
            let when = conn.last_used.map_or_else(String::new, |t| ago(now, t));
            let ww = k.measure(Font::Regular, size::SMALL, &when);
            let right = if hover || focus {
                r.right() - p(48.0)
            } else {
                r.right() - p(16.0)
            };
            let tw = right - tx - ww - p(10.0);
            k.text(
                Font::Semi,
                size::BODY,
                tx,
                r.y + p(24.0),
                &conn.name,
                c.text,
                tw,
            );
            let sub = match conn.last_duration {
                Some(d) => format!("{} · {} session", conn.host, span(d)),
                None => conn.host.clone(),
            };
            k.text(
                Font::Regular,
                size::SMALL - 0.5,
                tx,
                r.y + p(41.0),
                &sub,
                c.text_muted,
                right - tx,
            );
            k.text_right(
                Font::Regular,
                size::SMALL,
                Rect::new(tx, r.y + p(10.0), right - tx, p(20.0)),
                &when,
                c.text_faint,
            );
            if hover || focus {
                let b = p(30.0);
                let br = Rect::new(r.right() - p(10.0) - b, r.y + (r.h - b) / 2, b, b);
                let live = self.live_tab(&conn).is_some();
                let icon = if live { Icon::Window } else { Icon::Play };
                self.hicon(cv, te, f, br, icon, Variant::Primary, connect);
            }
        }
        y + recent.len() as i32 * rh + p(36.0)
    }

    /// Every group as a coloured section of compact cards (collapsible,
    /// shared with the sidebar), then the connections outside groups.
    #[allow(clippy::too_many_arguments)]
    fn paint_groups(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let total = self.store.connections.len();
        self.caption_count(
            cv,
            te,
            f,
            x,
            y,
            w,
            Some((Icon::Folder, c.text_muted)),
            "All connections",
            total,
        );
        let nb = Button::ghost("New connection")
            .icon(Icon::Plus)
            .icon_color(c.accent);
        let nw = self.btn_w(te, f, &nb);
        self.hbtn(
            cv,
            te,
            f,
            Rect::new(x + w - nw, y - p(7.0), nw, p(30.0)),
            &nb,
            HomeHit::NewConnection,
        );
        let mut y = y + p(34.0);
        // Sections in the sidebar's order; a collapsed parent hides its
        // sub-groups too.
        let mut sections: Vec<(usize, String, usize)> = Vec::new();
        let mut order: Vec<usize> = (0..self.store.groups.len()).collect();
        order.sort_by_key(|&gi| self.store.groups[gi].path.to_lowercase());
        for gi in order {
            let path = self.store.groups[gi].path.clone();
            let hidden = self
                .collapsed
                .iter()
                .any(|cp| path.starts_with(&format!("{cp}/")));
            if hidden {
                continue;
            }
            let depth = path.matches('/').count();
            sections.push((gi, path, depth));
        }
        let loose = self.store.connections.iter().any(|c| c.group.is_empty());
        if loose {
            sections.push((usize::MAX, String::new(), 0));
        }
        let gap = p(12.0);
        let (cols, cw) = grid(w, p(230.0), gap);
        let ch = p(60.0);
        for (gi, path, depth) in sections {
            let members: Vec<usize> = (0..total)
                .filter(|&i| self.store.connections[i].group == path)
                .collect();
            let open = !self.collapsed.contains(&path);
            let hit = HomeHit::Section(gi);
            let hover = self.hover == Some(Hit::HomeView(hit));
            let focus = self.kfocused(hit);
            let hr = Rect::new(x - p(6.0), y, w + p(12.0), p(34.0));
            self.hits.push((hr, Hit::HomeView(hit)));
            self.home.order.push(hit);
            let (name, color) = if gi == usize::MAX {
                ("Not in a group".to_string(), None)
            } else {
                (
                    path.replace('/', " / "),
                    Some(theme::group_solid(self.store.group_color(&path))),
                )
            };
            {
                let mut k = Kit::new(cv, te, f, s);
                if hover {
                    k.cv.fill_round(hr, radius::CONTROL * s, c.surface_hover);
                }
                if focus {
                    k.focus_ring(hr, radius::CONTROL);
                }
                let chev = if open {
                    Icon::ChevronDown
                } else {
                    Icon::ChevronRight
                };
                let ix = x + depth as i32 * p(18.0);
                k.icon(chev, ix, y + p(10.0), 14.0, c.text_faint);
                let mut tx = ix + p(22.0);
                if let Some(col) = color {
                    // A coloured bar marks the section.
                    k.cv.fill_round(Rect::new(tx, y + p(9.0), p(4.0), p(16.0)), 2.0 * s, col);
                    tx += p(14.0);
                }
                let end = k.text(
                    Font::Semi,
                    size::HEADING - 1.0,
                    tx,
                    y + p(22.0),
                    &name,
                    c.text,
                    w / 2,
                );
                let n = members.len();
                let sub = if gi == usize::MAX || n > 0 {
                    format!("{n} connection{}", if n == 1 { "" } else { "s" })
                } else {
                    "sub-groups only".into()
                };
                k.text(
                    Font::Regular,
                    size::SMALL,
                    end + p(10.0),
                    y + p(22.0),
                    &sub,
                    c.text_muted,
                    w / 3,
                );
                // A hairline to the right edge ties the section together.
                let lx = end + p(10.0) + k.measure(Font::Regular, size::SMALL, &sub) + p(14.0);
                if lx < x + w {
                    k.cv.fill(Rect::new(lx, y + p(17.0), x + w - lx, 1), c.divider);
                }
            }
            y += p(42.0);
            if !open || members.is_empty() {
                y += p(4.0);
                continue;
            }
            for (n, &i) in members.iter().enumerate() {
                let (col, row) = (n as i32 % cols, n as i32 / cols);
                let r = Rect::new(x + col * (cw + gap), y + row * (ch + gap), cw, ch);
                self.compact_card(cv, te, f, r, i);
            }
            let rows = (members.len() as i32 + cols - 1) / cols;
            y += rows * (ch + gap) - gap + p(22.0);
        }
        y
    }

    /// A small card: avatar, name and host; Connect on hover.
    fn compact_card(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, r: Rect, i: usize) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let conn = self.store.resolve(&self.store.connections[i]);
        let color = self.store.connection_color(&self.store.connections[i]);
        let dot = self.connection_dot(&conn);
        let edit = HomeHit::Edit(Zone::Group, i);
        let connect = HomeHit::Connect(Zone::Group, i);
        let hover = self.hovered(|h| matches!(h, HomeHit::Edit(Zone::Group, j) | HomeHit::Connect(Zone::Group, j) if j == i));
        let focus = self.kfocused(connect);
        self.hits.push((r, Hit::HomeView(edit)));
        self.home.order.push(connect);
        let ring = if hover && c.dark {
            c.surface_raised
        } else {
            c.surface
        };
        {
            let mut k = Kit::new(cv, te, f, s);
            card_frame(&mut k, r, hover, focus);
            let d = p(32.0);
            k.avatar(
                Rect::new(r.x + p(12.0), r.y + (r.h - d) / 2, d, d),
                &conn.name,
                color,
                dot,
                ring,
            );
            let tx = r.x + p(12.0) + d + p(12.0);
            let right = if hover || focus {
                r.right() - p(48.0)
            } else {
                r.right() - p(12.0)
            };
            let star_w = if conn.pinned { p(18.0) } else { 0 };
            k.text(
                Font::Semi,
                size::BODY,
                tx,
                r.y + p(26.0),
                &conn.name,
                c.text,
                right - tx - star_w,
            );
            if conn.pinned && !(hover || focus) {
                k.icon(
                    Icon::StarFilled,
                    r.right() - p(26.0),
                    r.y + p(15.0),
                    12.0,
                    c.warning,
                );
            }
            let sub = if conn.opens == Opens::Apps {
                format!("{} · {} apps", conn.host, conn.apps.len())
            } else if conn.port != 3389 {
                format!("{}:{}", conn.host, conn.port)
            } else {
                conn.host.clone()
            };
            k.text(
                Font::Regular,
                size::SMALL - 0.5,
                tx,
                r.y + p(43.0),
                &sub,
                c.text_muted,
                right - tx,
            );
        }
        if hover || focus {
            let b = p(30.0);
            let br = Rect::new(r.right() - p(10.0) - b, r.y + (r.h - b) / 2, b, b);
            let icon = if self.live_tab(&conn).is_some() {
                Icon::Window
            } else {
                Icon::Play
            };
            self.hicon(cv, te, f, br, icon, Variant::Primary, connect);
        }
    }

    /// First start (nothing saved): a picture, one line of what to do, the
    /// quick connect field and the other ways in.
    #[allow(clippy::too_many_arguments)]
    fn paint_first_start(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        top: i32,
        w: i32,
        area: Rect,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let cw = w.min(p(600.0));
        let cx = x + (w - cw) / 2;
        let mut y = top + ((area.h - p(520.0)) / 2).clamp(p(40.0), p(160.0));
        {
            let mut k = Kit::new(cv, te, f, s);
            // This PC, a dashed link with a bolt, a remote PC.
            let mid = cx + cw / 2;
            let tile = p(76.0);
            let gapx = p(150.0);
            let left = Rect::new(mid - gapx / 2 - tile, y, tile, tile);
            let right = Rect::new(mid + gapx / 2, y, tile, tile);
            let ly = (y + tile / 2) as f32;
            let mut dx = left.right() + p(10.0);
            while dx < right.x - p(10.0) {
                let seg = p(8.0).min(right.x - p(10.0) - dx);
                k.cv.fill(
                    Rect::new(dx, ly as i32 - p(1.0), seg, p(2.0)),
                    c.border_strong,
                );
                dx += p(14.0);
            }
            k.cv.round_border(left, 20.0 * s, c.border, c.surface_raised);
            k.icon_in(Icon::Monitor, left, 34.0, c.text_secondary);
            k.cv.fill_round(right, 20.0 * s, c.accent);
            k.icon_in(Icon::Monitor, right, 34.0, c.accent_text);
            k.cv.fill_circle(
                right.right() as f32 - 8.0 * s,
                right.y as f32 + 8.0 * s,
                9.0 * s,
                c.bg,
            );
            k.cv.fill_circle(
                right.right() as f32 - 8.0 * s,
                right.y as f32 + 8.0 * s,
                6.0 * s,
                c.success,
            );
            let hub = Rect::new(mid - p(20.0), y + tile / 2 - p(20.0), p(40.0), p(40.0));
            k.cv.fill_circle((mid) as f32, ly, 21.0 * s, c.bg);
            k.cv.fill_circle((mid) as f32, ly, 18.0 * s, c.accent_subtle);
            k.icon_in(Icon::Bolt, hub, 18.0, c.accent);
            let lbl = |k: &mut Kit, r: Rect, t: &str| {
                k.text_center(
                    Font::Regular,
                    size::SMALL,
                    Rect::new(r.x - p(30.0), r.bottom() + p(8.0), r.w + p(60.0), p(18.0)),
                    t,
                    c.text_muted,
                );
            };
            lbl(&mut k, left, "This PC");
            lbl(&mut k, right, "Your remote PC");
            y += tile + p(64.0);
            let (hour, ..) = local_time(self.home.clock);
            let row = Rect::new(cx, y - p(14.0), cw, p(18.0));
            let gw = k.measure(Font::Semi, size::CAPTION, greeting(hour)) + p(20.0);
            let base = k.baseline(Font::Semi, size::CAPTION, row);
            k.caption_text(
                cx + (cw - gw) / 2,
                base,
                &greeting(hour).to_uppercase(),
                c.accent,
            );
            y += p(26.0);
            k.text_center(
                Font::Semi,
                26.0,
                Rect::new(cx, y - p(16.0), cw, p(34.0)),
                "Connect to your first PC",
                c.text,
            );
            y += p(30.0);
            y = k.paragraph(
                Font::Regular,
                size::BODY,
                cx + p(20.0),
                y,
                cw - p(40.0),
                "Type its name or address below. rdpc asks for the user name and password, then offers to save it for next time.",
                c.text_secondary,
                true,
            );
        }
        y += p(6.0);
        let fr = Rect::new(cx, y, cw, p(50.0));
        self.paint_quick_field(cv, te, f, fr);
        y = fr.bottom() + p(56.0);
        // The other ways in.
        let imp = Button::secondary("Import connections").icon(Icon::Download);
        let new = Button::ghost("Set up a connection").icon(Icon::Plus);
        let (iw, nw) = (self.btn_w(te, f, &imp), self.btn_w(te, f, &new));
        let total = iw + p(10.0) + nw;
        let bx = cx + (cw - total) / 2;
        self.hbtn(
            cv,
            te,
            f,
            Rect::new(bx, y, iw, p(36.0)),
            &imp,
            HomeHit::Import,
        );
        self.hbtn(
            cv,
            te,
            f,
            Rect::new(bx + iw + p(10.0), y, nw, p(36.0)),
            &new,
            HomeHit::NewConnection,
        );
        y += p(36.0) + p(14.0);
        let mut k = Kit::new(cv, te, f, s);
        k.text_center(
            Font::Regular,
            size::SMALL,
            Rect::new(cx, y, cw, p(18.0)),
            "Import reads an rdpc backup (Settings, Export).",
            c.text_faint,
        );
        y + p(18.0)
    }
}

// ---- Snapshot samples --------------------------------------------------

/// A made-up desktop picture for snapshot thumbnails: a wallpaper, two
/// windows and a taskbar, in the given accent colour.
fn sample_desktop(w: usize, h: usize, accent: u32) -> Vec<u32> {
    let mut px = vec![0u32; w * h];
    for y in 0..h {
        for x in 0..w {
            // A diagonal wallpaper wash.
            let t = ((x + y) * 255 / (w + h)) as u32;
            px[y * w + x] = theme::mix(0x10233f, accent, t / 2);
        }
    }
    let mut rect = |x0: usize, y0: usize, rw: usize, rh: usize, color: u32| {
        for y in y0..(y0 + rh).min(h) {
            for x in x0..(x0 + rw).min(w) {
                px[y * w + x] = color;
            }
        }
    };
    rect(w / 10, h / 8, w / 2, h / 2, 0xf3f3f3);
    rect(w / 10, h / 8, w / 2, h / 22, 0xdadada);
    for i in 0..6 {
        rect(
            w / 10 + w / 30,
            h / 8 + h / 12 + i * h / 20,
            w / 3 - (i % 3) * w / 20,
            h / 60,
            0xb8c0cc,
        );
    }
    rect(w * 5 / 12, h * 3 / 10, w / 2, h / 2, 0x1e1e1e);
    rect(w * 5 / 12, h * 3 / 10, w / 2, h / 22, 0x323232);
    for i in 0..7 {
        let c = [0x4ec9b0, 0x9cdcfe, 0xce9178, 0xdcdcaa][i % 4];
        rect(
            w * 5 / 12 + w / 30 + (i % 3) * w / 40,
            h * 3 / 10 + h / 12 + i * h / 22,
            w / 5 + (i * 7 % 5) * w / 40,
            h / 70,
            c,
        );
    }
    rect(0, h - h / 18, w, h / 18, 0x202020);
    for i in 0..5 {
        rect(
            w / 2 - w / 10 + i * w / 25,
            h - h / 22,
            w / 40,
            h / 30,
            [accent, 0x4c8dff, 0xf0b230, 0xe0e0e0, 0x48c774][i],
        );
    }
    px
}

impl Ui {
    /// Snapshots: a fixed clock, pins, history and live thumbnails.
    pub(super) fn home_sample(&mut self, now: u64) {
        self.home.clock = Some(now);
        let conns = &mut self.store.connections;
        for (i, c) in conns.iter_mut().enumerate() {
            match i {
                0 => {
                    c.pinned = true;
                    c.last_used = Some(now - 300);
                    c.last_duration = Some(3 * 3600 + 20 * 60);
                    c.options.monitors = vec!["A".into(), "B".into()];
                }
                1 => {
                    c.last_used = Some(now - 2 * 3600);
                    c.last_duration = Some(45 * 60);
                    c.gateway = "rdg.corp.example".into();
                }
                2 => {
                    c.pinned = true;
                    c.last_used = Some(now - 26 * 3600);
                    c.last_duration = Some(12 * 60);
                }
                3 => {
                    c.pinned = true;
                    c.last_used = Some(now - 3 * 86_400);
                    c.last_duration = Some(2 * 3600 + 5 * 60);
                }
                _ => {}
            }
        }
        let ids: Vec<u64> = self.tabs.iter().map(|t| t.id).collect();
        for id in ids {
            self.home.since.insert(id, now - 72 * 60 - id * 1500);
        }
        let (tw, th) = (320usize, 180usize);
        let accents = [0x2ec4b6, 0x8f6cff, 0xff8a3d];
        for (n, t) in self.tabs.iter().enumerate() {
            let src = sample_desktop(1280, 720, accents[n % 3]);
            let (w, h) = crate::thumb::fit(1280, 720, tw, th);
            let pic = crate::thumb::downscale(&src, 1280, 720, w, h);
            self.home.thumbs.insert(
                t.id,
                ThumbSlot {
                    pic: Some(pic),
                    at: Some(Instant::now()),
                    ..ThumbSlot::default()
                },
            );
        }
    }

    /// Snapshots: text typed into quick connect.
    pub(super) fn home_sample_typed(&mut self, text: &str) {
        self.field_mut(Field::Quick).set(text);
        self.focus = Some(Field::Quick);
        self.home.pick = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(user: Option<&str>, host: &str, port: u16) -> Option<QuickTarget> {
        Some(QuickTarget {
            user: user.map(String::from),
            host: host.into(),
            port,
        })
    }

    #[test]
    fn quick_connect_parses_hosts_ports_users_and_ipv6() {
        assert_eq!(parse_quick("10.0.0.15"), q(None, "10.0.0.15", 3389));
        assert_eq!(
            parse_quick(" build-01.lab.local "),
            q(None, "build-01.lab.local", 3389)
        );
        assert_eq!(parse_quick("pc:3390"), q(None, "pc", 3390));
        assert_eq!(
            parse_quick("alex@pc.corp:3390"),
            q(Some("alex"), "pc.corp", 3390)
        );
        assert_eq!(
            parse_quick(r"CORP\alex@pc"),
            q(Some(r"CORP\alex"), "pc", 3389)
        );
        assert_eq!(
            parse_quick("alex@corp.example@pc"),
            q(Some("alex@corp.example"), "pc", 3389),
            "a UPN user keeps its @"
        );
        assert_eq!(parse_quick("[::1]:3389"), q(None, "::1", 3389));
        assert_eq!(parse_quick("[fe80::1]:3391"), q(None, "fe80::1", 3391));
        assert_eq!(parse_quick("[::1]"), q(None, "::1", 3389));
        assert_eq!(
            parse_quick("fe80::1"),
            q(None, "fe80::1", 3389),
            "bare IPv6"
        );
        assert_eq!(parse_quick("rdp://pc:3390/"), q(None, "pc", 3390));
        for bad in [
            "", "Test VM", "pc:0", "pc:99999", "pc:abc", "@pc", "alex@", "[::1", "[::1]x", "-pc",
            "pc/share",
        ] {
            assert_eq!(parse_quick(bad), None, "{bad:?}");
        }
        assert_eq!(q(None, "::1", 3390).unwrap().address(), "[::1]:3390");
        assert_eq!(q(Some("a"), "pc", 3389).unwrap().address(), "pc");
    }

    fn conn(name: &str, host: &str, used: Option<u64>) -> Connection {
        Connection {
            name: name.into(),
            host: host.into(),
            port: 3389,
            last_used: used,
            ..Default::default()
        }
    }

    #[test]
    fn saved_names_match_best_first() {
        let conns = vec![
            conn("Office workstation", "10.0.0.15", None),
            conn("Build server", "build-01.lab.local", Some(5)),
            conn("Test VM (Windows 11)", "192.168.56.20", None),
            conn("Office apps", "apps.corp.example", Some(9)),
        ];
        // Prefix of two names: the recently used one first.
        assert_eq!(rank("off", &conns), vec![3, 0]);
        assert_eq!(rank("Build server", &conns)[0], 1, "exact name");
        assert_eq!(rank("server", &conns), vec![1], "word start");
        assert_eq!(rank("vm", &conns), vec![2]);
        assert_eq!(rank("10.0", &conns), vec![0], "host prefix");
        assert_eq!(
            rank("ofws", &conns),
            vec![0],
            "letters in order, word starts first"
        );
        assert!(
            rank("10.9", &conns).is_empty(),
            "addresses never match loosely"
        );
        assert!(rank("zz", &conns).is_empty());
        assert!(
            match_score("work", "Office workstation", "").unwrap()
                > match_score("ows", "Office workstation", "").unwrap()
        );
        assert_eq!(match_score("", "x", "y"), None);
    }

    #[test]
    fn quick_choices_put_a_typed_address_first() {
        let mut m = super::super::sample(false);
        m.home_sample_typed("10.0.0.1");
        let ch = m.quick_choices();
        assert!(
            matches!(&ch[0], Choice::Host(t) if t.host == "10.0.0.1"),
            "{ch:?}"
        );
        assert!(
            ch.contains(&Choice::Saved(0)),
            "the saved 10.0.0.15 is offered too"
        );
        m.home_sample_typed("10.0.0.15");
        assert_eq!(
            m.quick_choices(),
            vec![Choice::Saved(0)],
            "an exact saved host wins"
        );
        m.home_sample_typed("build");
        let ch = m.quick_choices();
        assert_eq!(ch[0], Choice::Saved(1));
        assert!(
            matches!(ch.last(), Some(Choice::Host(_))),
            "a one-word host stays possible"
        );
        m.home_sample_typed("Test VM");
        assert_eq!(m.quick_choices(), vec![Choice::Saved(2)]);
        // A saved connection with a live session switches to it.
        m.home_sample_typed("Office workstation");
        assert!(m.key(Key::Enter).is_none());
        assert_eq!(m.active, Some(1));
    }

    #[test]
    fn quick_connect_to_a_new_host_opens_the_form_for_its_sign_in() {
        let mut m = super::super::sample(false);
        m.home_sample_typed("alex@newbox:3390");
        assert!(m.home_visible());
        let act = m.key(Key::Enter);
        assert!(act.is_none(), "asks for the password first");
        assert!(!m.home.showing, "the editor opened");
        assert_eq!(m.field(Field::Host).text, "newbox");
        assert_eq!(m.field(Field::Port).text, "3390");
        assert_eq!(m.field(Field::User).text, "alex");
        assert_eq!(m.focus, Some(Field::Password));
        assert_eq!(m.selected, None, "not saved yet");
        m.key(Key::Esc);
        assert!(m.home_visible(), "Esc leads back Home");
    }

    #[test]
    fn tab_walks_the_cards_and_enter_uses_them() {
        let mut te = TextEngine::new();
        let Some(fonts) = super::super::load_fonts(&mut te) else {
            return; // no UI font on this machine (headless CI)
        };
        let mut m = super::super::sample_home();
        let (w, h) = (1320usize, 860usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert_eq!(m.focus, Some(Field::Quick), "Home starts in quick connect");
        m.key(Key::Tab);
        assert_eq!(
            m.home.kfocus,
            Some(HomeHit::Open(1)),
            "the first live session"
        );
        assert_eq!(m.focus, None);
        m.key(Key::BackTab);
        assert_eq!(m.focus, Some(Field::Quick), "back to the field");
        m.key(Key::Tab);
        assert!(m.key(Key::Enter).is_none());
        assert_eq!(m.active, Some(1), "Enter opens the focused session");
    }

    #[test]
    fn recents_are_newest_first_and_skip_unused() {
        let conns = vec![
            conn("a", "a", Some(10)),
            conn("b", "b", None),
            conn("c", "c", Some(30)),
            conn("d", "d", Some(20)),
            conn("e", "e", Some(30)),
        ];
        assert_eq!(recents(&conns, 6), vec![2, 4, 3, 0], "ties by name");
        assert_eq!(recents(&conns, 2), vec![2, 4]);
        assert!(recents(&[], 6).is_empty());
    }

    #[test]
    fn times_read_as_words() {
        assert_eq!(ago(1000, 1000), "just now");
        assert_eq!(ago(1000, 2000), "just now", "clock skew");
        assert_eq!(ago(10_000, 10_000 - 59), "just now");
        assert_eq!(ago(10_000, 10_000 - 300), "5 min ago");
        assert_eq!(ago(100_000, 100_000 - 2 * 3600 - 59), "2 h ago");
        assert_eq!(ago(1_000_000, 1_000_000 - 30 * 3600), "yesterday");
        assert_eq!(ago(1_000_000, 1_000_000 - 3 * 86_400), "3 days ago");
        assert_eq!(ago(10_000_000, 10_000_000 - 15 * 86_400), "2 weeks ago");
        assert_eq!(ago(100_000_000, 100_000_000 - 120 * 86_400), "4 months ago");
        assert_eq!(span(30), "under a minute");
        assert_eq!(span(12 * 60), "12 min");
        assert_eq!(span(3600 + 12 * 60 + 5), "1 h 12 min");
        assert_eq!(span(3 * 3600), "3 h");
        assert_eq!(span(86_400 + 3600), "1 day 1 h");
        assert_eq!(span(2 * 86_400 + 4 * 3600), "2 days 4 h");
        assert_eq!(greeting(7), "Good morning");
        assert_eq!(greeting(13), "Good afternoon");
        assert_eq!(greeting(21), "Good evening");
        assert_eq!(greeting(2), "Good evening");
        // 2026-11-14 18:00 UTC was a Saturday.
        assert_eq!(local_time(Some(1_794_679_200)), (18, 6, 14, 11));
    }

    #[test]
    fn history_and_pins_survive_a_round_trip_and_old_files_load() {
        let old: Connection = serde_json::from_str(
            r#"{"name":"a","host":"h","port":3389,"user":"u","width":0,"height":0}"#,
        )
        .unwrap();
        assert!(!old.pinned && old.last_used.is_none() && old.last_duration.is_none());
        let c = Connection {
            pinned: true,
            last_used: Some(7),
            last_duration: Some(60),
            ..old.clone()
        };
        let back: Connection = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        let plain = serde_json::to_string(&old).unwrap();
        assert!(
            !plain.contains("pinned") && !plain.contains("last_used"),
            "{plain}"
        );
    }

    #[test]
    fn a_session_end_records_use_and_length() {
        let mut m = super::super::sample(false);
        m.home.clock = Some(10_000);
        m.session_started(1);
        assert_eq!(m.store.connections[0].last_used, Some(10_000));
        m.home.clock = Some(10_000 + 3600 + 120);
        m.session_ended(1);
        assert_eq!(m.store.connections[0].last_used, Some(13_720));
        assert_eq!(m.store.connections[0].last_duration, Some(3720));
        m.session_ended(1);
        assert_eq!(m.store.connections[0].last_duration, Some(3720), "once");
    }

    #[test]
    fn thumbnails_wait_for_the_view_and_are_throttled() {
        let mut m = super::super::sample(false);
        m.home.thumb_size = (160, 90);
        assert!(m.home_visible());
        assert_eq!(m.thumb_due(1), ThumbDue::Now);
        m.set_thumb(
            1,
            Thumb {
                w: 160,
                h: 90,
                rgba: vec![0; 160 * 90 * 4],
            },
        );
        assert!(
            matches!(m.thumb_due(1), ThumbDue::After(_)),
            "within 500 ms"
        );
        assert_eq!(
            m.thumb_due(1),
            ThumbDue::No,
            "one delayed refresh at a time"
        );
        assert!(m.thumb_tick(1));
        assert!(m.thumbs_needed().is_empty());
        // Hidden: no work, but the picture is redone on return.
        m.active = Some(1);
        assert_eq!(m.thumb_due(1), ThumbDue::No);
        m.active = None;
        assert_eq!(m.thumbs_needed(), vec![1]);
    }
}
