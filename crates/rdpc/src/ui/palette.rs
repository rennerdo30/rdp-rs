//! The command palette (Ctrl+K): one search field over everything rdpc
//! can do right now. Open sessions, saved connections, RemoteApp apps,
//! groups, session actions and settings are ranked by a fuzzy match
//! ([`crate::fuzzy`]) and run with Enter.
//!
//! Every command maps to the [`Hit`] the window's own controls report, so a
//! command runs exactly the code its button runs. Commands that do not
//! apply right now are left out, not greyed.
//!
//! The palette is a child module of `ui` so it can reach the window's
//! handlers; it keeps its own layout and hit rectangles while open, and
//! the window's controls take no input until it closes.

use ffwd_render::{Canvas, Rect, TextEngine};

use super::{Fonts, Hit, Key, TabState, Ui};
use crate::fuzzy::fuzzy;
use crate::icons::Icon;
use crate::kit::{self, Font, Hint, Kit};
use crate::store::{KeyboardMode, Opens};
use crate::text_field::TextField;
use crate::theme::{self, ThemeChoice, Tone, pal, radius};

/// Card width, search row, result row, section header and footer heights
/// (logical px).
const CARD_W: f32 = 660.0;
const SEARCH_H: f32 = 58.0;
const ROW_H: f32 = 42.0;
const HEAD_H: f32 = 30.0;
const FOOT_H: f32 = 40.0;
/// Inner padding of the result list (top and bottom) and the row inset.
const LIST_PAD: f32 = 6.0;
const ROW_INSET: f32 = 8.0;
/// The tallest the result list grows before it scrolls.
const LIST_MAX: f32 = 432.0;
/// Results kept for a typed query.
const MAX_RESULTS: usize = 60;
/// The score per query character a keyword match needs.
const KEYWORD_MIN: i32 = 26;
/// The chord that opens the palette while a session has the keyboard.
pub const SESSION_CHORD: &str = "Ctrl+Alt+K";

/// Result groups, in their order for an empty query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    /// Actions of the active session tab.
    Session,
    Sessions,
    Connections,
    Apps,
    Groups,
    Actions,
    Settings,
}

impl Section {
    fn label(self) -> &'static str {
        match self {
            Section::Session => "This session",
            Section::Sessions => "Sessions",
            Section::Connections => "Connections",
            Section::Apps => "Apps",
            Section::Groups => "Groups",
            Section::Actions => "Actions",
            Section::Settings => "Settings",
        }
    }

    /// How many rows the section shows for an empty query.
    fn empty_cap(self) -> usize {
        match self {
            Section::Connections => 6,
            Section::Actions => 4,
            Section::Apps => 4,
            Section::Groups => 3,
            _ => usize::MAX,
        }
    }
}

/// Everything the palette can run. Indices are into the store's
/// connections and groups at the time the list was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Connect(usize),
    ConnectApp(usize, usize),
    SwitchTab(u64),
    /// The Connections tab.
    ShowConnections,
    Edit(usize),
    OpenGroup(usize),
    NewConnection,
    NewGroup,
    Disconnect(u64),
    Reconnect(u64),
    CloseTab(u64),
    CtrlAltDel(u64),
    /// The session's Keyboard setting (RDP-32).
    Keyboard(u64, KeyboardMode),
    FullScreen,
    Fit(u64),
    Unspan(u64),
    Clipboard(u64),
    Sound(u64),
    Microphone(u64),
    Printers(u64),
    SmartCards(u64),
    ShareFolder(u64),
    StopSharing(u64, usize),
    Record(u64),
    Panel,
    Theme(ThemeChoice),
    OpenSettings,
    Lock,
    CheckUpdates,
    InstallUpdate,
    OpenLogFolder,
    Quit,
}

impl Command {
    /// The control this command stands for: running it is clicking that.
    pub fn hit(self) -> Hit {
        match self {
            Command::Connect(i) => Hit::RowConnect(i),
            Command::ConnectApp(c, a) => Hit::AppRow(c, a),
            Command::SwitchTab(id) => Hit::Tab(id),
            Command::ShowConnections => Hit::Home,
            Command::Edit(i) => Hit::Row(i),
            Command::OpenGroup(g) => Hit::GroupRow(g),
            Command::NewConnection => Hit::New,
            Command::NewGroup => Hit::NewGroup,
            Command::Disconnect(id) => Hit::Disconnect(id),
            Command::Reconnect(id) => Hit::Reconnect(id),
            Command::CloseTab(id) => Hit::CloseTab(id),
            Command::CtrlAltDel(id) => Hit::CtrlAltDel(id),
            Command::Keyboard(id, k) => Hit::TabKeyboard(
                id,
                KeyboardMode::ALL
                    .iter()
                    .position(|&x| x == k)
                    .unwrap_or_default(),
            ),
            Command::FullScreen => Hit::FullScreen,
            Command::Fit(id) => Hit::Fit(id),
            Command::Unspan(id) => Hit::Unspan(id),
            Command::Clipboard(id) => Hit::Clipboard(id),
            Command::Sound(id) => Hit::Sound(id),
            Command::Microphone(id) => Hit::Microphone(id),
            Command::Printers(id) => Hit::Printers(id),
            Command::SmartCards(id) => Hit::SmartCards(id),
            Command::ShareFolder(id) => Hit::BrowseDrive(id),
            Command::StopSharing(id, i) => Hit::RemoveDrive(id, i),
            Command::Record(id) => Hit::Record(id),
            Command::Panel => Hit::Drawer,
            Command::Theme(t) => Hit::Theme(
                ThemeChoice::ALL
                    .iter()
                    .position(|&x| x == t)
                    .unwrap_or_default(),
            ),
            Command::OpenSettings => Hit::OpenSettings,
            Command::Lock => Hit::Lock,
            Command::CheckUpdates => Hit::CheckNow,
            Command::InstallUpdate => Hit::Update,
            Command::OpenLogFolder => Hit::OpenLogFolder,
            Command::Quit => Hit::WinClose,
        }
    }
}

/// What leads a row.
#[derive(Clone, Debug, PartialEq)]
enum Lead {
    /// An icon on a tile tinted by the tone.
    Icon(Icon, Tone),
    /// A monogram avatar in a group colour, with a status dot.
    Avatar(usize, Option<u32>),
    /// A group: folder on a tile in the group's colour.
    Group(usize),
}

/// What sits at a row's right edge.
#[derive(Clone, Debug, PartialEq)]
enum Chip {
    None,
    Pill(&'static str, Tone, kit::Lead),
    /// A keyboard shortcut ("Ctrl+N").
    Keys(&'static str),
}

/// One command as listed.
#[derive(Clone, Debug)]
pub struct Entry {
    pub cmd: Command,
    pub section: Section,
    pub title: String,
    sub: String,
    /// More text that finds the entry (host, group path, synonyms); it is
    /// not highlighted.
    keywords: String,
    lead: Lead,
    chip: Chip,
    /// What Enter does, shown on the selected row ("Connect").
    verb: &'static str,
    /// Ranking nudge: the active session's actions come first.
    boost: i32,
    /// Listed for an empty query.
    top: bool,
}

/// A ranked result: the entry and the title characters it matched.
#[derive(Clone, Debug)]
pub struct Item {
    pub entry: Entry,
    pub marks: Vec<usize>,
    pub score: i32,
}

/// One line of the result list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    Head(Section),
    Row(usize),
}

/// Where the mouse button went down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Press {
    Row(usize),
    Card,
    Outside,
}

/// The open palette.
pub struct Palette {
    pub query: TextField,
    /// The selected result (index into the items).
    sel: usize,
    scroll: i32,
    /// Scroll the selection into view at the next paint (keyboard moves).
    follow: bool,
    /// The session that had the keyboard when the palette opened; it gets
    /// it back when the palette closes over it.
    return_to: Option<u64>,
    press: Option<Press>,
    /// Layout of the last paint (physical px).
    card: Rect,
    field: Rect,
    list: Rect,
    rows: Vec<(Rect, usize)>,
    content: i32,
    /// Rows that fit the list (Page Up/Down).
    page: usize,
}

impl Palette {
    fn new(return_to: Option<u64>) -> Palette {
        Palette {
            query: TextField::default(),
            sel: 0,
            scroll: 0,
            follow: true,
            return_to,
            press: None,
            card: Rect::default(),
            field: Rect::default(),
            list: Rect::default(),
            rows: Vec::new(),
            content: 0,
            page: 8,
        }
    }

    /// Moves the selection by `delta` rows: arrows wrap, pages clamp.
    fn step(&mut self, n: usize, delta: isize, wrap: bool) {
        if n == 0 {
            self.sel = 0;
            return;
        }
        let cur = self.sel.min(n - 1) as isize;
        let next = cur + delta;
        self.sel = if wrap {
            next.rem_euclid(n as isize) as usize
        } else {
            next.clamp(0, n as isize - 1) as usize
        };
        self.follow = true;
    }
}

/// The lines (section headers and rows) for ranked items.
fn lines(items: &[Item]) -> Vec<Line> {
    let mut out = Vec::with_capacity(items.len() + 6);
    let mut last = None;
    for (i, it) in items.iter().enumerate() {
        if last != Some(it.entry.section) {
            out.push(Line::Head(it.entry.section));
            last = Some(it.entry.section);
        }
        out.push(Line::Row(i));
    }
    out
}

/// Ranks `entries` for `query`: an empty query keeps the curated order
/// (sections in `order`, capped); a typed one keeps the matches, best
/// sections first and best matches first within each.
pub fn rank(entries: Vec<Entry>, query: &str, order: &[Section]) -> Vec<Item> {
    let pos = |s: Section| order.iter().position(|&x| x == s).unwrap_or(order.len());
    if query.trim().is_empty() {
        let mut v: Vec<Entry> = entries.into_iter().filter(|e| e.top).collect();
        v.sort_by_key(|e| pos(e.section));
        let mut out: Vec<Item> = Vec::with_capacity(v.len());
        let mut count = 0;
        for e in v {
            if out.last().map(|i| i.entry.section) != Some(e.section) {
                count = 0;
            }
            count += 1;
            if count <= e.section.empty_cap() {
                out.push(Item {
                    entry: e,
                    marks: Vec::new(),
                    score: 0,
                });
            }
        }
        return out;
    }
    // The longer keyword text only counts for a tight match (word starts
    // and runs), so two stray letters in a description find nothing.
    let need = query.chars().filter(|c| !c.is_whitespace()).count() as i32 * KEYWORD_MIN;
    let mut items: Vec<Item> = entries
        .into_iter()
        .filter_map(|e| {
            let (score, marks) = match fuzzy(query, &e.title) {
                Some(m) => (m.score, m.positions),
                None => {
                    let m = fuzzy(query, &e.keywords).filter(|m| m.score >= need)?;
                    (m.score - 12, Vec::new())
                }
            };
            Some(Item {
                score: score + e.boost,
                entry: e,
                marks,
            })
        })
        .collect();
    // Best match first, then curated order for ties.
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(pos(a.entry.section).cmp(&pos(b.entry.section)))
    });
    items.truncate(MAX_RESULTS);
    // Group by section, sections in the order of their best match.
    let mut sections: Vec<Section> = Vec::new();
    for it in &items {
        if !sections.contains(&it.entry.section) {
            sections.push(it.entry.section);
        }
    }
    let mut out = Vec::with_capacity(items.len());
    for s in sections {
        out.extend(items.iter().filter(|i| i.entry.section == s).cloned());
    }
    out
}

/// The text of a tab state for a pill.
fn state_pill(state: &TabState) -> Chip {
    match state {
        TabState::Connected { .. } => Chip::Pill("Live", Tone::Success, kit::Lead::Dot),
        TabState::Connecting => Chip::Pill("Connecting", Tone::Warning, kit::Lead::Dot),
        TabState::Ended(_) => Chip::Pill("Ended", Tone::Muted, kit::Lead::None),
        TabState::Failed(_) => Chip::Pill("Failed", Tone::Danger, kit::Lead::Dot),
    }
}

fn on_off(on: bool) -> Chip {
    if on {
        Chip::Pill("On", Tone::Success, kit::Lead::Dot)
    } else {
        Chip::Pill("Off", Tone::Muted, kit::Lead::None)
    }
}

impl Ui {
    /// Opens the palette; `from_session` is the session that had the
    /// keyboard (it gets it back when the palette closes).
    pub fn open_palette(&mut self, from_session: Option<u64>) {
        self.palette = Some(Palette::new(from_session));
        self.session_focus = false;
        self.hover = None;
        self.press = None;
    }

    /// Closes the palette; the session it opened over gets the keyboard back.
    fn close_palette(&mut self) {
        let Some(p) = self.palette.take() else {
            return;
        };
        if let Some(id) = p.return_to
            && self.active == Some(id)
            && self
                .active_tab()
                .is_some_and(|t| matches!(t.state, TabState::Connected { .. }))
        {
            self.session_focus = true;
        }
    }

    /// Section order: inside a session its actions come first.
    fn palette_order(&self) -> Vec<Section> {
        // The top actions come before apps and groups: those are found by
        // typing.
        let mut v = vec![
            Section::Sessions,
            Section::Connections,
            Section::Actions,
            Section::Apps,
            Section::Groups,
            Section::Settings,
        ];
        if self.active.is_some() {
            v.insert(0, Section::Session);
        }
        v
    }

    /// Everything that can run right now.
    pub fn palette_entries(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut push = |cmd: Command,
                        section: Section,
                        title: String,
                        sub: String,
                        keywords: &str,
                        lead: Lead,
                        chip: Chip,
                        verb: &'static str| {
            let boost = match section {
                Section::Session => 40,
                Section::Sessions => 8,
                Section::Connections => 0,
                Section::Apps | Section::Actions => -2,
                Section::Groups | Section::Settings => -4,
            };
            out.push(Entry {
                cmd,
                section,
                keywords: format!("{title} {sub} {keywords}"),
                title,
                sub,
                lead,
                chip,
                verb,
                boost,
                top: true,
            });
        };
        let locked = self.store.is_locked();

        // The active session's actions.
        if let Some(t) = self.active_tab() {
            let id = t.id;
            let live = matches!(t.state, TabState::Connected { .. });
            let up = live || t.state == TabState::Connecting;
            let apps = t.remote_app.is_some();
            let name = t.name.clone();
            let s = Section::Session;
            if up {
                push(
                    Command::Disconnect(id),
                    s,
                    "Disconnect".into(),
                    name.clone(),
                    "end close sign out log off",
                    Lead::Icon(Icon::Power, Tone::Danger),
                    Chip::None,
                    "Disconnect",
                );
            }
            if t.state != TabState::Connecting {
                push(
                    Command::Reconnect(id),
                    s,
                    "Reconnect".into(),
                    if live {
                        "Log on again; applies quality changes".into()
                    } else {
                        name.clone()
                    },
                    "retry restart",
                    Lead::Icon(Icon::Refresh, Tone::Accent),
                    Chip::None,
                    "Reconnect",
                );
            }
            if t.spanned && live {
                push(
                    Command::Unspan(id),
                    s,
                    "Show it in this window".into(),
                    "Brings the session back from its monitors".into(),
                    "unspan monitors window",
                    Lead::Icon(Icon::Monitor, Tone::Accent),
                    Chip::None,
                    "Show",
                );
            }
            if !apps {
                let (title, icon) = if self.fullscreen {
                    ("Exit full screen", Icon::ExitFullscreen)
                } else {
                    ("Full screen", Icon::Fullscreen)
                };
                push(
                    Command::FullScreen,
                    s,
                    title.into(),
                    "Ctrl+Alt+Break from inside the session".into(),
                    "fullscreen maximize window",
                    Lead::Icon(icon, Tone::Neutral),
                    Chip::None,
                    if self.fullscreen { "Leave" } else { "Run" },
                );
            }
            if live {
                let toggles = [
                    (
                        Command::Clipboard(id),
                        "Clipboard",
                        "Copy and paste between here and the session",
                        "copy paste share",
                        Icon::Clipboard,
                        t.clipboard,
                    ),
                    (
                        Command::Sound(id),
                        "Sound",
                        "Play the session's sound on this PC",
                        "audio speaker",
                        Icon::Speaker,
                        t.sound,
                    ),
                    (
                        Command::Microphone(id),
                        "Microphone",
                        "Record from this PC's microphone",
                        "mic audio input",
                        Icon::Mic,
                        t.microphone,
                    ),
                    (
                        Command::Printers(id),
                        "Printers",
                        "Print from the session to this PC's printers",
                        "print share",
                        Icon::Printer,
                        t.printers,
                    ),
                    (
                        Command::SmartCards(id),
                        "Smart cards",
                        "Sign in with this PC's smart card readers",
                        "smartcard reader share",
                        Icon::SmartCard,
                        t.smart_cards,
                    ),
                ];
                for (cmd, title, sub, kw, icon, on) in toggles {
                    push(
                        cmd,
                        s,
                        title.into(),
                        sub.into(),
                        kw,
                        Lead::Icon(icon, Tone::Neutral),
                        on_off(on),
                        if on { "Turn off" } else { "Turn on" },
                    );
                }
                // The other Keyboard choices; they apply at once.
                for k in KeyboardMode::ALL.into_iter().filter(|k| *k != t.keyboard) {
                    let title = match k {
                        KeyboardMode::Auto => "Keyboard: automatic",
                        KeyboardMode::Remote => "Keyboard: remote layout",
                        KeyboardMode::Translate => "Keyboard: translate typing",
                    };
                    push(
                        Command::Keyboard(id, k),
                        s,
                        title.into(),
                        k.hint().into(),
                        "keyboard layout typing translate unicode scancodes language",
                        Lead::Icon(Icon::Keyboard, Tone::Neutral),
                        Chip::None,
                        "Use",
                    );
                }
                push(
                    Command::ShareFolder(id),
                    s,
                    "Share a folder…".into(),
                    "Shows a folder of this PC as a drive in the session".into(),
                    "drive drives redirect folder share",
                    Lead::Icon(Icon::Folder, Tone::Neutral),
                    Chip::None,
                    "Choose",
                );
                for (i, d) in t.drives.iter().enumerate() {
                    push(
                        Command::StopSharing(id, i),
                        s,
                        format!("Stop sharing {}", d.name),
                        d.path.clone(),
                        "drive drives folder unshare remove",
                        Lead::Icon(Icon::FolderOpen, Tone::Neutral),
                        Chip::Pill("Shared", Tone::Accent, kit::Lead::None),
                        "Stop",
                    );
                }
                if !apps && !t.spanned {
                    push(
                        Command::Fit(id),
                        s,
                        "Fit to window".into(),
                        "Resize the remote desktop with the window".into(),
                        "resize size scale",
                        Lead::Icon(Icon::Sliders, Tone::Neutral),
                        on_off(t.fit),
                        if t.fit { "Turn off" } else { "Turn on" },
                    );
                    let (title, sub, tone, chip) = if t.recording {
                        (
                            "Stop recording",
                            "Saves the video",
                            Tone::Danger,
                            Chip::Pill("Rec", Tone::Danger, kit::Lead::Dot),
                        )
                    } else {
                        (
                            "Record session",
                            "Records the session's picture to a video",
                            Tone::Danger,
                            Chip::None,
                        )
                    };
                    push(
                        Command::Record(id),
                        s,
                        title.into(),
                        sub.into(),
                        "record video capture screen",
                        Lead::Icon(
                            if t.recording {
                                Icon::Stop
                            } else {
                                Icon::Record
                            },
                            tone,
                        ),
                        chip,
                        if t.recording { "Stop" } else { "Record" },
                    );
                    push(
                        Command::CtrlAltDel(id),
                        s,
                        "Send Ctrl+Alt+Del".into(),
                        "Lock, switch user or Task Manager in the session".into(),
                        "ctrl alt delete secure attention task manager",
                        Lead::Icon(Icon::Keyboard, Tone::Neutral),
                        Chip::None,
                        "Send",
                    );
                }
            }
            push(
                Command::Panel,
                s,
                if self.drawer {
                    "Hide panel".into()
                } else {
                    "Show panel".into()
                },
                "Sharing, display, quality and session details".into(),
                "drawer sidebar settings toggle",
                Lead::Icon(Icon::PanelRight, Tone::Neutral),
                Chip::None,
                if self.drawer { "Hide" } else { "Show" },
            );
            push(
                Command::CloseTab(id),
                s,
                "Close tab".into(),
                name,
                "close tab",
                Lead::Icon(Icon::Close, Tone::Neutral),
                Chip::None,
                "Close",
            );
        }

        // Open sessions to switch to, and the Connections tab.
        for t in &self.tabs {
            if Some(t.id) == self.active {
                continue;
            }
            let status = Some(t.state.tone().color());
            // Its saved connection's group and user find it too.
            let kw = self
                .store
                .connections
                .iter()
                .find(|c| c.name == t.name && c.host == t.host)
                .map_or(String::new(), |c| format!("{} {}", c.group, c.user));
            push(
                Command::SwitchTab(t.id),
                Section::Sessions,
                t.name.clone(),
                t.host.clone(),
                &format!("switch tab session {kw}"),
                Lead::Avatar(self.tab_color(&t.name, &t.host), status),
                state_pill(&t.state),
                "Switch to",
            );
        }
        if self.active.is_some() {
            push(
                Command::ShowConnections,
                Section::Sessions,
                "Connections".into(),
                "Saved connections and the editor".into(),
                "home editor tab",
                Lead::Icon(Icon::Home, Tone::Neutral),
                Chip::None,
                "Switch to",
            );
        }

        // Saved connections. One with a session up is listed under Sessions
        // (or is the one on screen), so Enter never opens it twice.
        if !locked {
            for (i, c) in self.store.connections.iter().enumerate() {
                let open = self.tabs.iter().any(|t| {
                    t.name == c.name
                        && t.host == c.host
                        && matches!(t.state, TabState::Connected { .. } | TabState::Connecting)
                });
                let host = if c.port == 3389 {
                    c.host.clone()
                } else {
                    format!("{}:{}", c.host, c.port)
                };
                let sub = if c.group.is_empty() {
                    host
                } else {
                    format!("{host} · {}", c.group.replace('/', " / "))
                };
                let kw = format!("{} {} {} {}", c.host, c.group, c.user, c.gateway);
                let color = self.store.connection_color(c);
                let lead = Lead::Avatar(color, self.connection_dot(c));
                let (chip, verb) = if c.opens == Opens::Apps {
                    (Chip::Pill("Apps", Tone::Accent, kit::Lead::None), "Start")
                } else {
                    (Chip::None, "Connect")
                };
                if !open {
                    push(
                        Command::Connect(i),
                        Section::Connections,
                        c.name.clone(),
                        sub.clone(),
                        &kw,
                        lead,
                        chip,
                        verb,
                    );
                }
                push(
                    Command::Edit(i),
                    Section::Connections,
                    format!("Edit {}", c.name),
                    sub,
                    &kw,
                    Lead::Icon(Icon::Edit, Tone::Neutral),
                    Chip::None,
                    "Edit",
                );
            }

            // RemoteApp apps.
            for (ci, c) in self.store.connections.iter().enumerate() {
                if c.opens != Opens::Apps {
                    continue;
                }
                for (ai, a) in c.apps.iter().enumerate() {
                    let running = self.tabs.iter().any(|t| {
                        t.name == c.name
                            && t.host == c.host
                            && t.remote_app
                                .as_ref()
                                .is_some_and(|v| v.running.contains(&a.program))
                    });
                    push(
                        Command::ConnectApp(ci, ai),
                        Section::Apps,
                        a.name.clone(),
                        c.name.clone(),
                        &format!("{} {} {}", a.program, c.host, c.group),
                        Lead::Avatar(self.store.connection_color(c), None),
                        if running {
                            Chip::Pill("Running", Tone::Success, kit::Lead::Dot)
                        } else {
                            Chip::None
                        },
                        "Start",
                    );
                }
            }

            // Groups open their settings.
            for (gi, g) in self.store.groups.iter().enumerate() {
                let n = self.store.members(&g.path).count();
                let count = format!("{n} connection{}", if n == 1 { "" } else { "s" });
                let sub = if g.parent().is_empty() {
                    count
                } else {
                    format!("{} · {count}", g.parent().replace('/', " / "))
                };
                push(
                    Command::OpenGroup(gi),
                    Section::Groups,
                    g.name().to_string(),
                    sub,
                    &format!("{} folder group", g.path),
                    Lead::Group(self.store.group_color(&g.path)),
                    Chip::None,
                    "Open",
                );
            }

            push(
                Command::NewConnection,
                Section::Actions,
                "New connection".into(),
                "Add a computer to connect to".into(),
                "add create host computer",
                Lead::Icon(Icon::Plus, Tone::Accent),
                Chip::Keys("Ctrl+N"),
                "Create",
            );
            push(
                Command::NewGroup,
                Section::Actions,
                "New group".into(),
                "Share credentials and settings between connections".into(),
                "add create folder",
                Lead::Icon(Icon::Folder, Tone::Neutral),
                Chip::None,
                "Create",
            );
        }
        if let Some(v) = self.update.clone().filter(|_| !self.update_busy) {
            push(
                Command::InstallUpdate,
                Section::Actions,
                format!("Install update {v}"),
                "Downloads, verifies and restarts rdpc".into(),
                "upgrade new version",
                Lead::Icon(Icon::Download, Tone::Accent),
                Chip::Keys("Ctrl+Shift+U"),
                "Install",
            );
        }
        push(
            Command::CheckUpdates,
            Section::Actions,
            "Check for updates".into(),
            String::new(),
            "upgrade new version release",
            Lead::Icon(Icon::Refresh, Tone::Neutral),
            Chip::None,
            "Check",
        );
        push(
            Command::OpenLogFolder,
            Section::Actions,
            "Open log folder".into(),
            "Diagnostic logs for bug reports".into(),
            "logs diagnostics debug files",
            Lead::Icon(Icon::FolderOpen, Tone::Neutral),
            Chip::None,
            "Open",
        );
        push(
            Command::Quit,
            Section::Actions,
            "Quit rdpc".into(),
            String::new(),
            "exit close",
            Lead::Icon(Icon::Power, Tone::Danger),
            Chip::None,
            "Quit",
        );

        // Settings.
        for t in ThemeChoice::ALL {
            if t == self.theme {
                continue;
            }
            let (icon, sub) = match t {
                ThemeChoice::Dark => (Icon::Moon, "Dark theme"),
                ThemeChoice::Light => (Icon::Sun, "Light theme"),
                ThemeChoice::System => (Icon::Contrast, "Follow Windows"),
            };
            push(
                Command::Theme(t),
                Section::Settings,
                format!("Theme: {}", t.label()),
                sub.into(),
                "appearance colour color mode",
                Lead::Icon(icon, Tone::Neutral),
                Chip::None,
                "Apply",
            );
        }
        push(
            Command::OpenSettings,
            Section::Settings,
            "Open Settings".into(),
            "Vault, updates, theme, backups".into(),
            "preferences options",
            Lead::Icon(Icon::Gear, Tone::Neutral),
            Chip::None,
            "Open",
        );
        if self.store.is_vault() && !locked {
            push(
                Command::Lock,
                Section::Settings,
                "Lock vault".into(),
                "Saved passwords need the master password again".into(),
                "lock secure master password",
                Lead::Icon(Icon::Lock, Tone::Neutral),
                Chip::None,
                "Lock",
            );
        }
        // Editing only for a typed query, below connecting.
        for e in out.iter_mut().filter(|e| matches!(e.cmd, Command::Edit(_))) {
            e.top = false;
            e.boost -= 10;
        }
        out
    }

    /// The ranked results for the current query.
    fn palette_items(&self) -> Vec<Item> {
        let q = self
            .palette
            .as_ref()
            .map(|p| p.query.text.clone())
            .unwrap_or_default();
        rank(self.palette_entries(), &q, &self.palette_order())
    }

    /// Runs a command, closing the palette; the session it opened over gets
    /// the keyboard back when the command keeps it on screen.
    fn palette_run(&mut self, cmd: Command) -> Option<super::Action> {
        let return_to = self.palette.as_ref().and_then(|p| p.return_to);
        self.palette = None;
        let before = self.active;
        let action = self.activate(cmd.hit());
        if return_to.is_some()
            && return_to == before
            && self.active == before
            && self
                .active_tab()
                .is_some_and(|t| matches!(t.state, TabState::Connected { .. }))
        {
            self.session_focus = true;
        }
        action
    }

    /// Keys while the palette is open: it takes all of them.
    pub(super) fn palette_key(&mut self, k: Key) -> Option<super::Action> {
        match k {
            Key::Esc | Key::Palette => {
                self.close_palette();
                return None;
            }
            Key::Enter => {
                let sel = self.palette.as_ref()?.sel;
                let cmd = self.palette_items().get(sel).map(|i| i.entry.cmd)?;
                return self.palette_run(cmd);
            }
            _ => {}
        }
        let n = self.palette_items().len();
        let p = self.palette.as_mut()?;
        let edited = |p: &mut Palette| {
            p.sel = 0;
            p.scroll = 0;
            p.follow = true;
        };
        match k {
            Key::Up | Key::BackTab => p.step(n, -1, true),
            Key::Down | Key::Tab => p.step(n, 1, true),
            Key::PageUp => p.step(n, -(p.page.max(1) as isize), false),
            Key::PageDown => p.step(n, p.page.max(1) as isize, false),
            Key::Home => p.step(n, -(n as isize), false),
            Key::End => p.step(n, n as isize, false),
            Key::Char(c) => {
                p.query.insert(&c.to_string());
                edited(p);
            }
            Key::Paste(s) => {
                p.query.insert(s.lines().next().unwrap_or(""));
                edited(p);
            }
            Key::Backspace => {
                p.query.backspace();
                edited(p);
            }
            Key::Delete => {
                p.query.delete();
                edited(p);
            }
            Key::Left => p.query.left(),
            Key::Right => p.query.right(),
            Key::SelectAll => p.query.select_all(),
            _ => {}
        }
        None
    }

    /// Hover selects the row under the pointer; true when that changed.
    pub(super) fn palette_mouse_move(&mut self, x: i32, y: i32) -> bool {
        let Some(p) = self.palette.as_mut() else {
            return false;
        };
        match p.rows.iter().find(|(r, _)| r.contains(x, y)) {
            Some(&(_, i)) if i != p.sel => {
                p.sel = i;
                p.follow = false;
                true
            }
            _ => false,
        }
    }

    pub(super) fn palette_mouse_down(&mut self, x: i32, y: i32) {
        let Some(p) = self.palette.as_mut() else {
            return;
        };
        p.press = Some(match p.rows.iter().find(|(r, _)| r.contains(x, y)) {
            Some(&(_, i)) => Press::Row(i),
            None if p.card.contains(x, y) => Press::Card,
            None => Press::Outside,
        });
    }

    /// A click on a row runs it; a click on the dimmed window closes.
    pub(super) fn palette_mouse_up(&mut self, x: i32, y: i32) -> Option<super::Action> {
        let p = self.palette.as_mut()?;
        let press = p.press.take();
        let here = match p.rows.iter().find(|(r, _)| r.contains(x, y)) {
            Some(&(_, i)) => Press::Row(i),
            None if p.card.contains(x, y) => Press::Card,
            None => Press::Outside,
        };
        if press != Some(here) {
            return None;
        }
        match here {
            Press::Row(i) => {
                let cmd = self.palette_items().get(i).map(|it| it.entry.cmd)?;
                self.palette_run(cmd)
            }
            Press::Outside => {
                self.close_palette();
                None
            }
            Press::Card => None,
        }
    }

    /// The wheel scrolls the results; true when they moved.
    pub(super) fn palette_scroll(&mut self, lines: f32) -> bool {
        let s = self.scale;
        let Some(p) = self.palette.as_mut() else {
            return false;
        };
        let max = (p.content - p.list.h).max(0);
        let next = (p.scroll - (lines * ROW_H * 2.0 * s) as i32).clamp(0, max);
        let changed = next != p.scroll;
        p.scroll = next;
        p.follow = false;
        changed
    }

    /// The palette over the window: dimmed backdrop, floating card with the
    /// search field, the grouped results and the key hints.
    pub(super) fn paint_palette(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let items = self.palette_items();
        let lines = lines(&items);
        let s = self.scale;
        let px = |v: f32| (v * s).round() as i32;
        let c = pal();
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        let all = Rect::new(0, 0, w, h);
        // The window under the card takes no input; the session picture
        // (copied in before this paint) stays visible, dimmed.
        self.session_area = None;
        self.hits.clear();
        self.hits.push((all, Hit::Modal));
        self.title_controls.clear();
        let scope = self.active_tab().map(|t| {
            (
                t.name.clone(),
                theme::group_solid(self.tab_color(&t.name, &t.host)),
            )
        });
        let chord_hint =
            !self.tabs.is_empty() && self.palette.as_ref().is_some_and(|p| p.return_to.is_none());
        let Some(p) = self.palette.as_mut() else {
            return;
        };
        let n = items.len();
        if n > 0 {
            p.sel = p.sel.min(n - 1);
        }

        // Card geometry: centred, near the top; the list grows to its
        // content, up to what the window allows.
        let cw = px(CARD_W).min(w - px(32.0)).max(px(240.0));
        let top = ((h as f32 * 0.12) as i32).clamp(px(40.0), px(120.0));
        let (row_h, head_h, pad) = (px(ROW_H), px(HEAD_H), px(LIST_PAD));
        let content: i32 = 2 * pad
            + lines
                .iter()
                .enumerate()
                .map(|(i, l)| match l {
                    Line::Head(_) if i == 0 => head_h - px(4.0),
                    Line::Head(_) => head_h,
                    Line::Row(_) => row_h,
                })
                .sum::<i32>();
        let empty_h = px(132.0);
        let room = h - top - px(SEARCH_H) - px(FOOT_H) - px(24.0) - 2;
        let list_h = if n == 0 {
            empty_h
        } else {
            content.min(px(LIST_MAX)).min(room.max(row_h * 3))
        };
        let ch = px(SEARCH_H) + 1 + list_h + 1 + px(FOOT_H);
        let card = Rect::new((w - cw) / 2, top, cw, ch);
        let field = Rect::new(card.x, card.y, card.w, px(SEARCH_H));
        let list = Rect::new(card.x + 1, field.bottom() + 1, card.w - 2, list_h);
        let foot = Rect::new(card.x, list.bottom() + 1, card.w, px(FOOT_H));
        p.card = card;
        p.field = field;
        p.list = list;
        p.content = content;
        p.page = ((list_h - 2 * pad) / row_h).max(1) as usize;

        // Keep the selection in view after keyboard moves.
        let max_scroll = (content - list_h).max(0);
        if p.follow && n > 0 {
            let mut y = pad;
            for (i, l) in lines.iter().enumerate() {
                let lh = match l {
                    Line::Head(_) if i == 0 => head_h - px(4.0),
                    Line::Head(_) => head_h,
                    Line::Row(_) => row_h,
                };
                if *l == Line::Row(p.sel) {
                    // The section header above the first row comes along.
                    let first_in_section = i > 0 && matches!(lines[i - 1], Line::Head(_));
                    let want_top = if first_in_section {
                        y - lines_h(i - 1, &lines, head_h, px(4.0))
                    } else {
                        y
                    };
                    if want_top - pad < p.scroll {
                        p.scroll = (want_top - pad).max(0);
                    } else if y + lh + pad > p.scroll + list_h {
                        p.scroll = y + lh + pad - list_h;
                    }
                    break;
                }
                y += lh;
            }
        }
        p.scroll = p.scroll.clamp(0, max_scroll);
        let (sel, scroll) = (p.sel, p.scroll);
        let query = p.query.clone();
        p.rows.clear();

        let mut k = Kit::new(cv, te, f, s);
        k.scrim(all);
        k.shadow(card, radius::DIALOG, 32.0);
        let border = if c.dark { c.border_strong } else { c.border };
        k.cv.round_border(card, radius::DIALOG * s, border, c.surface_raised);

        // Search row: icon, query with caret, the session it acts on.
        let icon_d = px(20.0);
        k.icon(
            Icon::Search,
            field.x + px(20.0),
            field.y + (field.h - icon_d) / 2,
            20.0,
            c.accent,
        );
        let tx = field.x + px(54.0);
        let mut right = field.right() - px(16.0);
        if let Some((name, color)) = &scope {
            let label = format!("in {name}");
            let pw = k.pill_width(&label, kit::Lead::Swatch(*color)).min(cw / 3);
            right -= pw;
            let old = k.cv.set_clip(Rect::new(right, field.y, pw, field.h));
            k.pill(
                right,
                field.y + (field.h - px(20.0)) / 2,
                &label,
                Tone::Neutral,
                kit::Lead::Swatch(*color),
            );
            k.cv.set_clip(old);
            right -= px(12.0);
        }
        let q_size = 17.0;
        let text_r = Rect::new(tx, field.y, right - tx, field.h);
        let base = k.baseline(Font::Regular, q_size, text_r);
        let old = k.cv.set_clip(text_r.intersect(k.cv.clip()));
        let display = query.display();
        let caret_x = k.measure(
            Font::Regular,
            q_size,
            &display.chars().take(query.caret).collect::<String>(),
        );
        let shift = (caret_x - text_r.w + px(4.0)).max(0);
        let x0 = tx - shift;
        if display.is_empty() {
            k.text(
                Font::Regular,
                q_size,
                tx,
                base,
                "Search connections, sessions and commands…",
                c.text_faint,
                text_r.w,
            );
        } else {
            if query.all {
                let tw = k.measure(Font::Regular, q_size, &display);
                k.cv.fill(
                    Rect::new(x0, field.y + px(16.0), tw + 1, field.h - px(32.0)),
                    c.text_selection,
                );
            }
            k.text(
                Font::Regular,
                q_size,
                x0,
                base,
                &display,
                c.text,
                i32::MAX / 4,
            );
        }
        k.cv.fill(
            Rect::new(
                x0 + caret_x,
                field.y + px(17.0),
                px(2.0).max(1),
                field.h - px(34.0),
            ),
            c.accent,
        );
        k.cv.set_clip(old);
        k.cv.fill(
            Rect::new(card.x + 1, field.bottom(), card.w - 2, 1),
            c.divider,
        );

        // Results.
        let old = k.cv.set_clip(list.intersect(k.cv.clip()));
        if n == 0 {
            let q = query.text.trim();
            let title = format!("No matches for “{q}”");
            k.empty_state(
                list,
                list.y + px(16.0),
                Icon::Search,
                &title,
                "Try a connection, a host, a group or a command such as “full screen”.",
            );
        }
        let mut y = list.y + pad - scroll;
        let mut rows = Vec::new();
        for (li, line) in lines.iter().enumerate() {
            match *line {
                Line::Head(sec) => {
                    let hh = if li == 0 { head_h - px(4.0) } else { head_h };
                    if y + hh >= list.y && y < list.bottom() {
                        k.section(
                            list.x + px(ROW_INSET + 6.0),
                            y + hh - px(22.0),
                            list.w - px(2.0 * ROW_INSET + 12.0),
                            sec.label(),
                            None,
                        );
                    }
                    y += hh;
                }
                Line::Row(i) => {
                    let r = Rect::new(
                        list.x + px(ROW_INSET),
                        y,
                        list.w - px(2.0 * ROW_INSET),
                        row_h,
                    );
                    y += row_h;
                    if r.bottom() < list.y || r.y > list.bottom() {
                        continue;
                    }
                    paint_row(&mut k, r, &items[i], i == sel);
                    rows.push((r.intersect(list), i));
                }
            }
        }
        k.scrollbar(list, content, scroll);
        k.cv.set_clip(old);

        // Footer: key hints, and the chord for inside a session.
        k.cv.fill(Rect::new(card.x + 1, foot.y - 1, card.w - 2, 1), c.divider);
        let cy = foot.y + foot.h / 2;
        let hx = foot.x + px(16.0);
        let mut chord_w = 0;
        if chord_hint {
            let label = "inside a session";
            let lw = k.measure(Font::Regular, theme::size::SMALL, label);
            let kw = k.keys_width(SESSION_CHORD);
            chord_w = kw + px(6.0) + lw;
            let x = foot.right() - px(16.0) - chord_w;
            if x > hx + px(300.0) {
                k.hints(
                    x,
                    cy,
                    chord_w + px(4.0),
                    &[Hint::Keys(SESSION_CHORD), Hint::Text(label)],
                );
            } else {
                chord_w = 0;
            }
        }
        k.hints(
            hx,
            cy,
            foot.w - px(32.0) - chord_w - px(16.0),
            &[
                Hint::Keys("↑+↓"),
                Hint::Text("to navigate"),
                Hint::Keys("Enter"),
                Hint::Text("to run"),
                Hint::Keys("Esc"),
                Hint::Text("to close"),
            ],
        );
        if let Some(p) = self.palette.as_mut() {
            p.rows = rows;
        }
    }
}

/// Height of the header line at `i` (the first one is a little shorter).
fn lines_h(i: usize, lines: &[Line], head_h: i32, trim: i32) -> i32 {
    match lines.get(i) {
        Some(Line::Head(_)) if i == 0 => head_h - trim,
        Some(Line::Head(_)) => head_h,
        _ => 0,
    }
}

/// One result row: selection wash, lead tile or avatar, the title with
/// its matched characters marked, the secondary text and the right chip
/// (and, when selected, what Enter does).
fn paint_row(k: &mut Kit, r: Rect, it: &Item, selected: bool) {
    let c = pal();
    let s = k.s;
    let px = |v: f32| (v * s).round() as i32;
    let e = &it.entry;
    let bg = if selected {
        c.selected
    } else {
        c.surface_raised
    };
    if selected {
        k.cv.fill_round(r, radius::CONTROL * s, c.selected);
        k.cv.fill_round(
            Rect::new(r.x, r.y + px(10.0), px(3.0), r.h - px(20.0)),
            1.5 * s,
            c.accent,
        );
    }
    // Lead: 28 px tile.
    let d = px(28.0);
    let tile = Rect::new(r.x + px(10.0), r.y + (r.h - d) / 2, d, d);
    match &e.lead {
        Lead::Icon(icon, tone) => {
            let (fill, fg) = match tone {
                Tone::Neutral | Tone::Muted if selected => (c.accent_subtle, c.accent),
                Tone::Neutral | Tone::Muted => (c.surface_hover, c.text_secondary),
                t => (t.subtle(), t.color()),
            };
            k.cv.fill_round(tile, 7.0 * s, fill);
            k.icon_in(*icon, tile, 15.0, fg);
        }
        Lead::Avatar(color, status) => {
            // The monogram comes from the title ("Edit …" never has one).
            k.avatar(tile, &e.title, *color, *status, bg);
        }
        Lead::Group(color) => {
            let (fill, _) = theme::group_tile(*color);
            k.cv.fill_round(tile, 7.0 * s, fill);
            k.icon_in(Icon::Folder, tile, 15.0, theme::group_solid(*color));
        }
    }

    // Right side: chip, then the Enter hint when selected.
    let mut right = r.right() - px(12.0);
    let cap_y = r.y + (r.h - px(18.0)) / 2;
    if selected {
        let kw = k.keys_width("Enter");
        right -= kw;
        k.keys(right, cap_y, "Enter");
        let vw = k.measure(Font::Regular, theme::size::SMALL, e.verb);
        right -= vw + px(8.0);
        k.text_in(
            Font::Regular,
            theme::size::SMALL,
            Rect::new(right, r.y, vw + 1, r.h),
            e.verb,
            c.text_secondary,
        );
        right -= px(12.0);
    }
    match &e.chip {
        Chip::None => {}
        Chip::Pill(text, tone, lead) => {
            let pw = k.pill_width(text, *lead);
            right -= pw;
            k.pill(right, r.y + (r.h - px(20.0)) / 2, text, *tone, *lead);
            right -= px(10.0);
        }
        Chip::Keys(combo) if !selected => {
            let kw = k.keys_width(combo);
            right -= kw;
            k.keys(right, cap_y, combo);
            right -= px(10.0);
        }
        Chip::Keys(_) => {}
    }

    // Title with marks, then the secondary text in the room left.
    let tx = tile.right() + px(12.0);
    let size = 13.5;
    let base = k.baseline(Font::Regular, size, r);
    let end = k.text_marked(
        size,
        tx,
        base,
        &e.title,
        &it.marks,
        c.text,
        c.accent,
        right - tx,
    );
    let sx = end + px(10.0);
    if !e.sub.is_empty() && right - sx > px(48.0) {
        k.text(
            Font::Regular,
            theme::size::SMALL,
            sx,
            base,
            &e.sub,
            c.text_muted,
            right - sx,
        );
    }
}

/// The palette open over the window (snapshots): `query` typed, inside the
/// session tab or not.
pub fn sample(session: bool, query: &str) -> Ui {
    let mut m = super::sample(session);
    m.store.vault_sample();
    m.update = Some("0.2.0".into());
    m.open_palette(session.then_some(1));
    if let Some(p) = m.palette.as_mut() {
        p.query.set(query);
        if !query.is_empty() {
            p.sel = 0;
        } else {
            p.sel = 2;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(m: &Ui) -> Vec<Command> {
        m.palette_entries().into_iter().map(|e| e.cmd).collect()
    }

    fn items(m: &mut Ui, q: &str) -> Vec<Item> {
        if m.palette.is_none() {
            m.open_palette(None);
        }
        m.palette.as_mut().unwrap().query.set(q);
        m.palette_items()
    }

    #[test]
    fn keyboard_choices_other_than_the_current_one() {
        let mut live = super::super::sample(true);
        let c = cmds(&live);
        assert!(c.contains(&Command::Keyboard(1, KeyboardMode::Remote)));
        assert!(c.contains(&Command::Keyboard(1, KeyboardMode::Translate)));
        assert!(!c.contains(&Command::Keyboard(1, KeyboardMode::Auto)));
        assert_eq!(
            Command::Keyboard(1, KeyboardMode::Translate).hit(),
            Hit::TabKeyboard(1, 2)
        );
        live.tab_mut(1).unwrap().keyboard = KeyboardMode::Translate;
        let c = cmds(&live);
        assert!(c.contains(&Command::Keyboard(1, KeyboardMode::Auto)));
        assert!(!c.contains(&Command::Keyboard(1, KeyboardMode::Translate)));
    }

    #[test]
    fn session_commands_only_inside_a_live_session() {
        // Connections tab: no session actions at all.
        let home = super::super::sample(false);
        let c = cmds(&home);
        assert!(!c.iter().any(|c| matches!(c, Command::Disconnect(_))));
        assert!(!c.contains(&Command::FullScreen));
        assert!(!c.contains(&Command::Panel));
        assert!(c.contains(&Command::SwitchTab(1)), "open tabs to switch to");
        assert!(!c.contains(&Command::ShowConnections), "already there");

        // A live desktop session: its toggles, recording, full screen.
        let live = super::super::sample(true);
        let c = cmds(&live);
        for want in [
            Command::Disconnect(1),
            Command::Reconnect(1),
            Command::FullScreen,
            Command::Clipboard(1),
            Command::Sound(1),
            Command::Microphone(1),
            Command::Printers(1),
            Command::SmartCards(1),
            Command::ShareFolder(1),
            Command::StopSharing(1, 0),
            Command::Record(1),
            Command::CtrlAltDel(1),
            Command::Panel,
            Command::ShowConnections,
        ] {
            assert!(c.contains(&want), "{want:?} missing in a live session");
        }
        assert!(
            !c.contains(&Command::SwitchTab(1)),
            "no switching to itself"
        );

        // A failed session: reconnect, but nothing that needs a live one.
        let mut failed = super::super::sample(false);
        failed.active = Some(2);
        let c = cmds(&failed);
        assert!(c.contains(&Command::Reconnect(2)));
        assert!(!c.contains(&Command::Disconnect(2)));
        assert!(!c.contains(&Command::Clipboard(2)));
        assert!(!c.contains(&Command::Record(2)));
    }

    #[test]
    fn remote_app_sessions_have_no_picture_commands() {
        let m = super::super::sample_apps_tab();
        let c = cmds(&m);
        assert!(c.contains(&Command::Clipboard(3)));
        assert!(!c.contains(&Command::FullScreen));
        assert!(!c.contains(&Command::Record(3)));
        assert!(!c.contains(&Command::Fit(3)));
    }

    #[test]
    fn vault_theme_and_update_commands_follow_state() {
        let mut m = super::super::sample(false);
        assert!(
            !cmds(&m).contains(&Command::Lock),
            "no vault, nothing to lock"
        );
        assert!(!cmds(&m).contains(&Command::InstallUpdate));
        m.store.vault_sample();
        m.update = Some("9.9.9".into());
        let c = cmds(&m);
        assert!(c.contains(&Command::Lock));
        assert!(c.contains(&Command::InstallUpdate));
        // The theme in use is not offered.
        m.theme = ThemeChoice::Light;
        let c = cmds(&m);
        assert!(!c.contains(&Command::Theme(ThemeChoice::Light)));
        assert!(c.contains(&Command::Theme(ThemeChoice::Dark)));
        assert!(c.contains(&Command::Theme(ThemeChoice::System)));
        // Locked: no connections, no editing.
        let locked = Ui::new(crate::store::Store::locked_sample(), 1.0);
        let c = cmds(&locked);
        assert!(!c.iter().any(|c| matches!(c, Command::Connect(_))));
        assert!(!c.contains(&Command::NewConnection));
        assert!(c.contains(&Command::Quit));
    }

    #[test]
    fn open_connections_switch_instead_of_connecting_again() {
        let m = super::super::sample(false);
        let e = m.palette_entries();
        let ow: Vec<Command> = e
            .iter()
            .filter(|e| e.title == "Office workstation")
            .map(|e| e.cmd)
            .collect();
        assert_eq!(ow, [Command::SwitchTab(1)], "listed once, as its session");
        // A failed session's connection connects again.
        assert!(e.iter().any(|e| e.cmd == Command::Connect(1)));
        let vm = e
            .iter()
            .find(|e| e.section == Section::Connections && e.title.starts_with("Test VM"))
            .unwrap();
        assert_eq!(vm.cmd, Command::Connect(2));
    }

    #[test]
    fn empty_query_lists_sessions_first_and_session_actions_inside_one() {
        let mut home = super::super::sample(false);
        let it = items(&mut home, "");
        assert_eq!(it[0].entry.section, Section::Sessions);
        assert!(it.iter().all(|i| i.marks.is_empty()));
        // No "Edit …" rows and no duplicates of open sessions.
        assert!(!it.iter().any(|i| matches!(i.entry.cmd, Command::Edit(_))));
        let ow = it
            .iter()
            .filter(|i| i.entry.title == "Office workstation")
            .count();
        assert_eq!(ow, 1);

        let mut live = super::super::sample(true);
        let it = items(&mut live, "");
        assert_eq!(it[0].entry.section, Section::Session);
        assert_eq!(it[0].entry.cmd, Command::Disconnect(1));
    }

    #[test]
    fn typed_query_ranks_and_marks() {
        let mut m = super::super::sample(false);
        let it = items(&mut m, "bs");
        assert_eq!(it[0].entry.title, "Build server");
        assert_eq!(it[0].marks, [0, 6]);
        // Host names find connections too (no marks in the title).
        let it = items(&mut m, "192.168");
        assert_eq!(it[0].entry.cmd, Command::Connect(2));
        assert!(it[0].marks.is_empty());
        // Group paths.
        let it = items(&mut m, "lab");
        assert!(
            it.iter()
                .any(|i| matches!(i.entry.cmd, Command::OpenGroup(_)) && i.entry.title == "Lab")
        );
        // Apps.
        let it = items(&mut m, "excel");
        assert_eq!(it[0].entry.cmd, Command::ConnectApp(3, 0));
        // Two stray letters in a description find nothing.
        let it = items(&mut m, "of");
        assert!(!it.iter().any(|i| i.entry.cmd == Command::NewGroup));
        // Nothing.
        assert!(items(&mut m, "qqqq").is_empty());
    }

    #[test]
    fn inside_a_session_its_actions_win() {
        let mut m = super::super::sample(true);
        // "s" matches many things; the session's own come first.
        let it = items(&mut m, "so");
        assert_eq!(it[0].entry.section, Section::Session);
        assert_eq!(it[0].entry.cmd, Command::Sound(1));
        let it = items(&mut m, "full");
        assert_eq!(it[0].entry.cmd, Command::FullScreen);
    }

    #[test]
    fn keyboard_navigation_wraps_and_clamps() {
        let mut m = super::super::sample(true);
        m.open_palette(None);
        let n = m.palette_items().len();
        assert!(n > 10);
        let sel = |m: &Ui| m.palette.as_ref().unwrap().sel;
        m.key(Key::Up);
        assert_eq!(sel(&m), n - 1, "Up from the first wraps to the last");
        m.key(Key::Down);
        assert_eq!(sel(&m), 0, "Down from the last wraps to the first");
        m.key(Key::PageUp);
        assert_eq!(sel(&m), 0, "Page Up clamps at the top");
        m.key(Key::End);
        assert_eq!(sel(&m), n - 1);
        m.key(Key::PageDown);
        assert_eq!(sel(&m), n - 1, "Page Down clamps at the bottom");
        m.key(Key::Home);
        assert_eq!(sel(&m), 0);
        m.key(Key::PageDown);
        assert_eq!(sel(&m), 8, "a page is the default 8 rows before a paint");
        // Typing resets the selection to the best match.
        m.key(Key::Char('r'));
        assert_eq!(sel(&m), 0);
        assert_eq!(m.palette.as_ref().unwrap().query.text, "r");
        m.key(Key::Backspace);
        assert_eq!(m.palette.as_ref().unwrap().query.text, "");
    }

    #[test]
    fn enter_runs_the_command_through_its_control() {
        let mut m = super::super::sample(true);
        m.open_palette(Some(1));
        for c in "hide panel".chars() {
            m.key(Key::Char(c));
        }
        assert!(m.drawer);
        assert!(m.key(Key::Enter).is_none());
        assert!(!m.drawer, "the panel toggled like its button");
        assert!(m.palette.is_none(), "running closes the palette");
        assert!(m.session_focus, "the session gets the keyboard back");

        // Switching tabs does not hand the keyboard to the other session.
        m.session_focus = false;
        m.open_palette(Some(1));
        for c in "connections".chars() {
            m.key(Key::Char(c));
        }
        m.key(Key::Enter);
        assert_eq!(m.active, None);
        assert!(!m.session_focus);

        // Actions come back for the app to handle.
        m.open_palette(None);
        for c in "quit".chars() {
            m.key(Key::Char(c));
        }
        assert!(matches!(
            m.key(Key::Enter),
            Some(super::super::Action::WinClose)
        ));
    }

    #[test]
    fn esc_and_the_toggle_key_close_and_restore_the_session() {
        let mut m = super::super::sample(true);
        m.session_focus = true;
        m.open_palette(Some(1));
        assert!(!m.session_focus, "the palette takes the keyboard");
        m.key(Key::Esc);
        assert!(m.palette.is_none());
        assert!(m.session_focus);
        m.session_focus = false;
        m.key(Key::Palette);
        assert!(m.palette.is_some());
        m.key(Key::Palette);
        assert!(m.palette.is_none(), "the same key closes it");
    }

    #[test]
    fn clicks_run_rows_and_the_backdrop_closes() {
        let mut te = TextEngine::new();
        let Some(fonts) = super::super::load_fonts(&mut te) else {
            return; // no UI font on this machine (headless CI)
        };
        let mut m = super::super::sample(false);
        m.open_palette(None);
        let (w, h) = (1320usize, 860usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        let (r, i) = m.palette.as_ref().unwrap().rows[1];
        let cmd = m.palette_items()[i].entry.cmd;
        m.mouse_move(r.x + 4, r.y + 4);
        assert_eq!(m.palette.as_ref().unwrap().sel, i, "hover selects");
        m.mouse_down(r.x + 4, r.y + 4, &mut te, &fonts);
        let a = m.mouse_up(r.x + 4, r.y + 4);
        assert!(m.palette.is_none());
        let _ = (a, cmd);

        m.open_palette(None);
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        m.mouse_down(4, h as i32 - 4, &mut te, &fonts);
        m.mouse_up(4, h as i32 - 4);
        assert!(m.palette.is_none(), "a click on the dimmed window closes");
        assert!(m.store.connections.len() == 4, "and runs nothing");
    }
}
