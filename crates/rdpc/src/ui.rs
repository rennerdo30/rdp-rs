//! The main window: saved connections on the left, a tab strip with a
//! Connections tab (edit form) and one tab per session, a session toolbar, a
//! control drawer for live session settings and a status bar.
//!
//! Painting is immediate: every paint lays out the whole window and records
//! hit rectangles. The session picture itself is not painted here: `paint`
//! reports the session area and the app copies the remote framebuffer into
//! it, so session updates never repaint the chrome.

use ffwd_render::{Canvas, FontId, Rect, TextEngine};

use crate::store::{Connection, Group, Inherit, SessionOptions, Store, normalize_path, parent_of};
use crate::text_field::TextField;
use crate::theme::*;

pub struct Fonts {
    pub ui: FontId,
    pub semi: FontId,
}

pub fn load_fonts(te: &mut TextEngine) -> Option<Fonts> {
    type P = &'static [&'static str];
    #[cfg(windows)]
    let (ui, semi): (P, P) = (
        &[
            r"C:\Windows\Fonts\Inter-Regular.ttf",
            r"C:\Windows\Fonts\segoeui.ttf",
        ],
        &[
            r"C:\Windows\Fonts\Inter-SemiBold.ttf",
            r"C:\Windows\Fonts\seguisb.ttf",
            r"C:\Windows\Fonts\segoeuib.ttf",
        ],
    );
    #[cfg(not(windows))]
    let (ui, semi): (P, P) = (
        &[
            "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ],
        &[
            "/usr/share/fonts/truetype/inter/Inter-SemiBold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ],
    );
    // fontdue parses every outline up front, so the faces load in parallel.
    let read = |paths: P| {
        std::thread::spawn(move || {
            paths
                .iter()
                .find_map(|p| std::fs::read(p).ok())
                .and_then(TextEngine::parse)
        })
    };
    let (a, b) = (read(ui), read(semi));
    let ui = te.add(a.join().ok()??);
    let semi = b.join().ok().flatten().map_or(ui, |f| te.add(f));
    Some(Fonts { ui, semi })
}

/// Fixed starting sizes. The Display choice before them, "Fit window", is
/// stored as 0 x 0 and sizes the desktop to the session tab.
/// Fixed desktop scales offered in the drawer, besides Auto.
pub const SCALES: [u32; 4] = [100, 125, 150, 200];

pub const SIZES: [(u16, u16); 4] = [(1280, 800), (1600, 900), (1920, 1080), (2560, 1440)];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Filter = 0,
    Name,
    Host,
    Port,
    User,
    Password,
    DrivePath,
    /// Shared-folder path in the connection form.
    FormDrive,
    /// Master password (unlock or create), and its confirmation.
    Master,
    MasterConfirm,
    /// Group path of a connection, or the parent path of a group.
    GroupPath,
}

/// Fields cleared for a new connection or group.
const FORM: [Field; 6] = [
    Field::Name,
    Field::Host,
    Field::Port,
    Field::User,
    Field::Password,
    Field::GroupPath,
];

/// One sidebar row: a group or a connection, with its tree depth.
#[derive(Clone, Copy)]
enum Row {
    Group(usize, usize),
    Conn(usize, usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hit {
    Row(usize),
    /// Sidebar group row (opens the group form) and its expand arrow.
    GroupRow(usize),
    GroupToggle(usize),
    NewGroup,
    /// New connection inside the open group.
    NewInGroup,
    /// Connection/group form: inherit chip (credentials, display, sharing).
    FormInherit(u8),
    New,
    Field(Field),
    Size(usize),
    Connect,
    Save,
    Delete,
    Home,
    Tab(u64),
    CloseTab(u64),
    Drawer,
    Reconnect(u64),
    Disconnect(u64),
    Clipboard(u64),
    Printers(u64),
    Sound(u64),
    SmartCards(u64),
    Fit(u64),
    /// Scale choice: 0 = Auto, else an index into SCALES + 1.
    Scale(u64, usize),
    /// Connection form: scale choice, sharing chip, folder remove/add.
    FormScale(usize),
    FormShare(u8),
    FormRemoveDrive(usize),
    FormAddDrive,
    /// Vault: save-password chip, unlock, remember, create, cancel, lock.
    SavePassword,
    Unlock,
    Remember,
    CreateVault,
    CancelVault,
    Lock,
    AddDrive(u64),
    RemoveDrive(u64, usize),
    CtrlAltDel(u64),
    Session(u64),
    WinMinimize,
    WinClose,
}

#[derive(Clone, PartialEq)]
pub enum TabState {
    Connecting,
    Connected { width: u16, height: u16, bpp: u16 },
    Ended(String),
    Failed(String),
}

impl TabState {
    fn color(&self) -> u32 {
        match self {
            TabState::Connecting => WARN,
            TabState::Connected { .. } => OK,
            TabState::Ended(_) => TEXT_4,
            TabState::Failed(_) => ERR,
        }
    }
}

#[derive(Clone)]
pub struct SharedDrive {
    pub device_id: u32,
    pub name: String,
    pub path: String,
}

/// One session tab and its live settings.
pub struct Tab {
    pub id: u64,
    pub name: String,
    pub host: String,
    pub state: TabState,
    pub clipboard: bool,
    pub printers: bool,
    pub sound: bool,
    pub smart_cards: bool,
    pub fit: bool,
    /// Remote desktop scale in percent; None follows this PC's scaling.
    pub scale: Option<u32>,
    pub drives: Vec<SharedDrive>,
}

pub enum Action {
    /// `fit`: size the desktop to the tab (the app fills in the size) and follow resizes.
    Connect {
        name: String,
        cfg: Box<rdp::Config>,
        fit: bool,
        opts: SessionOptions,
    },
    Disconnect(u64),
    Reconnect(u64),
    CloseTab(u64),
    SetClipboard(u64, bool),
    SetPrinters(u64, bool),
    SetSound(u64, bool),
    SetSmartCards(u64, bool),
    SetFit(u64, bool),
    SetScale(u64, Option<u32>),
    AddDrive(u64, String),
    RemoveDrive(u64, usize),
    CtrlAltDel(u64),
    WinMinimize,
    WinClose,
    /// Derive the key off the UI thread, then open the vault.
    Unlock {
        master: zeroize::Zeroizing<String>,
        remember: bool,
    },
    CreateVault {
        master: zeroize::Zeroizing<String>,
    },
    Lock,
    /// Several actions at once ("Connect all" of a group).
    Batch(Vec<Action>),
}

pub enum Key {
    Char(char),
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    Tab,
    BackTab,
    Enter,
    Esc,
    SelectAll,
    Paste(String),
    New,
    Save,
    NextTab,
    PrevTab,
}

pub struct Ui {
    store: Store,
    selected: Option<usize>,
    /// Editing a group instead of a connection: Some(None) is a new group.
    group_edit: Option<Option<String>>,
    /// Inherit choices of the edited connection or group.
    inherit: Inherit,
    /// Collapsed group paths in the sidebar.
    collapsed: std::collections::HashSet<String>,
    /// Session settings of the connection being edited.
    opts: SessionOptions,
    /// The edited connection keeps (or gets) a saved password.
    save_password: bool,
    /// Showing the "set a master password" panel.
    vault_setup: bool,
    remember: bool,
    /// Key derivation running.
    pub unlocking: bool,
    vault_error: Option<String>,
    fields: [TextField; 11],
    size: usize,
    focus: Option<Field>,
    pub tabs: Vec<Tab>,
    /// None: the Connections tab.
    pub active: Option<u64>,
    pub drawer: bool,
    /// Keyboard goes to the active session (set by clicking into it).
    pub session_focus: bool,
    /// Where the active session's picture goes, set by `paint`.
    pub session_area: Option<(u64, Rect)>,
    hover: Option<Hit>,
    press: Option<Hit>,
    hits: Vec<(Rect, Hit)>,
    field_rects: Vec<(Field, Rect)>,
    message: Option<(String, u32)>,
    pub scale: f32,
    pub renderer: String,
    /// The tab strip is the window's title row (Windows 11 frame installed).
    pub custom_frame: bool,
    pub maximized: bool,
    /// Maximise button (hover, pressed); it gets non-client messages, so the
    /// frame hook reports its state.
    pub max_state: (bool, bool),
    /// The window has the focus (caption glyphs dim when it does not).
    pub window_active: bool,
    /// Title-row spans that are controls (clicks are ours, not window drags).
    title_controls: Vec<(i32, i32)>,
    caption: Rect,
    title_height: i32,
}

/// Title-row geometry in physical pixels for the frame hook.
#[derive(Clone, Debug, PartialEq)]
pub struct TitleGeometry {
    pub height: i32,
    pub controls: Vec<(i32, i32)>,
    pub buttons_left: i32,
    pub max_button: (i32, i32),
}

impl Ui {
    pub fn new(store: Store, scale: f32) -> Ui {
        let mut m = Ui {
            store,
            selected: None,
            group_edit: None,
            inherit: Inherit::default(),
            collapsed: Default::default(),
            opts: SessionOptions::default(),
            save_password: false,
            vault_setup: false,
            remember: false,
            unlocking: false,
            vault_error: None,
            fields: Default::default(),
            size: 0,
            focus: None,
            tabs: Vec::new(),
            active: None,
            drawer: true,
            session_focus: false,
            session_area: None,
            hover: None,
            press: None,
            hits: Vec::new(),
            field_rects: Vec::new(),
            message: None,
            scale,
            renderer: "CPU".into(),
            custom_frame: false,
            maximized: false,
            max_state: (false, false),
            window_active: true,
            title_controls: Vec::new(),
            caption: Rect::default(),
            title_height: 0,
        };
        m.fields[Field::Password as usize] = TextField::secret();
        m.fields[Field::Master as usize] = TextField::secret();
        m.fields[Field::MasterConfirm as usize] = TextField::secret();
        m.store.adopt_groups();
        if m.store.connections.is_empty() {
            m.new_connection();
        } else {
            m.select(0);
        }
        if m.store.is_locked() {
            m.focus = Some(Field::Master);
        }
        m
    }

    fn field(&self, f: Field) -> &TextField {
        &self.fields[f as usize]
    }

    fn field_mut(&mut self, f: Field) -> &mut TextField {
        &mut self.fields[f as usize]
    }

    pub fn set_message(&mut self, text: impl Into<String>, color: u32) {
        self.message = Some((text.into(), color));
    }

    /// The physical size the session picture gets in a window of `w` x `h`
    /// pixels: the same layout as `paint` (sidebar, tab strip, toolbar, drawer).
    pub fn session_size_for(&self, w: i32, h: i32) -> (i32, i32) {
        let p = |v: f32| (v * self.scale).round() as i32;
        let side_w = p(260.0).min(w / 3);
        let mut aw = w - side_w - 1;
        let ah = h - p(28.0) - p(38.0) - p(40.0);
        if self.drawer {
            aw -= p(290.0).min(aw / 2) + 1;
        }
        (aw.max(1), ah.max(1))
    }

    pub fn tab_mut(&mut self, id: u64) -> Option<&mut Tab> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    pub fn active_tab(&self) -> Option<&Tab> {
        self.active
            .and_then(|id| self.tabs.iter().find(|t| t.id == id))
    }

    pub fn open_tab(&mut self, id: u64, name: String, host: String, fit: bool) {
        self.tabs.push(Tab {
            id,
            name,
            host,
            state: TabState::Connecting,
            clipboard: false,
            printers: false,
            sound: false,
            smart_cards: false,
            fit,
            scale: None,
            drives: Vec::new(),
        });
        self.active = Some(id);
        self.session_focus = false;
    }

    pub fn close_tab(&mut self, id: u64) {
        let Some(i) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        self.tabs.remove(i);
        if self.active == Some(id) {
            self.active = if self.tabs.is_empty() {
                None
            } else {
                Some(self.tabs[i.min(self.tabs.len() - 1)].id)
            };
            self.session_focus = false;
        }
    }

    fn select(&mut self, i: usize) {
        let Some(c) = self.store.connections.get(i).cloned() else {
            return;
        };
        self.selected = Some(i);
        self.group_edit = None;
        self.field_mut(Field::Name).set(&c.name);
        self.field_mut(Field::Host).set(&c.host);
        self.field_mut(Field::Port).set(&c.port.to_string());
        self.field_mut(Field::User).set(&c.user);
        self.field_mut(Field::Password).set("");
        self.field_mut(Field::GroupPath).set(&c.group);
        self.size = size_index(c.width, c.height);
        self.opts = c.options.clone();
        self.save_password = c.password.is_some();
        self.inherit = c.inherit;
        self.focus = Some(Field::Password);
    }

    fn select_group(&mut self, gi: usize) {
        let Some(g) = self.store.groups.get(gi).cloned() else {
            return;
        };
        self.selected = None;
        self.group_edit = Some(Some(g.path.clone()));
        for f in FORM {
            self.field_mut(f).set("");
        }
        self.field_mut(Field::Name).set(g.name());
        self.field_mut(Field::GroupPath).set(g.parent());
        self.field_mut(Field::User).set(&g.user);
        self.size = size_index(g.width, g.height);
        self.opts = g.options.clone();
        self.save_password = g.password.is_some();
        self.inherit = g.inherit;
        self.focus = None;
    }

    /// The group a new connection or group goes into: the open group, or
    /// the group of the selected connection.
    fn context_group(&self) -> String {
        match &self.group_edit {
            Some(Some(path)) => path.clone(),
            Some(None) => normalize_path(&self.field(Field::GroupPath).text),
            None => self
                .selected
                .and_then(|i| self.store.connections.get(i))
                .map(|c| c.group.clone())
                .unwrap_or_default(),
        }
    }

    fn new_connection(&mut self) {
        self.new_connection_in("");
    }

    /// A new connection; inside a group it inherits everything to start with.
    fn new_connection_in(&mut self, group: &str) {
        self.selected = None;
        self.group_edit = None;
        for f in FORM {
            self.field_mut(f).set("");
        }
        self.field_mut(Field::Port).set("3389");
        self.field_mut(Field::GroupPath).set(group);
        self.size = 0;
        self.opts = SessionOptions::default();
        self.save_password = false;
        self.inherit = if group.is_empty() {
            Inherit::default()
        } else {
            Inherit::ALL
        };
        self.focus = Some(Field::Host);
    }

    fn new_group(&mut self) {
        let parent = self.context_group();
        self.selected = None;
        self.group_edit = Some(None);
        for f in FORM {
            self.field_mut(f).set("");
        }
        self.field_mut(Field::GroupPath).set(&parent);
        self.size = 0;
        self.opts = SessionOptions::default();
        self.save_password = false;
        self.inherit = if parent.is_empty() {
            Inherit::default()
        } else {
            Inherit::ALL
        };
        self.focus = Some(Field::Name);
    }

    /// The saved password of the edited connection or group.
    fn own_password(&self) -> Option<&String> {
        match &self.group_edit {
            Some(Some(path)) => self
                .store
                .group_index(path)
                .and_then(|i| self.store.groups[i].password.as_ref()),
            Some(None) => None,
            None => self
                .selected
                .and_then(|i| self.store.connections.get(i))
                .and_then(|c| c.password.as_ref()),
        }
    }

    /// The password to store: what was typed, else the saved one (vault only).
    fn form_password(&self, inherited: bool) -> Option<String> {
        if inherited {
            return self.own_password().cloned();
        }
        if !(self.save_password && self.store.is_vault()) {
            return None;
        }
        let typed = &self.field(Field::Password).text;
        if typed.is_empty() {
            self.own_password().cloned()
        } else {
            Some(typed.clone())
        }
    }

    /// Inherit choices for the typed group path (nothing at the top level).
    fn form_inherit(&self) -> Inherit {
        if normalize_path(&self.field(Field::GroupPath).text).is_empty() {
            Inherit::default()
        } else {
            self.inherit
        }
    }

    fn form_size(&self) -> (u16, u16) {
        if self.size == 0 {
            (0, 0)
        } else {
            SIZES[self.size - 1]
        }
    }

    fn form(&self) -> Result<Connection, String> {
        let host = self.field(Field::Host).text.trim().to_string();
        if host.is_empty() {
            return Err("Enter a host name or address.".into());
        }
        let port = match self.field(Field::Port).text.trim() {
            "" => 3389,
            p => p
                .parse::<u16>()
                .map_err(|_| format!("Port {p:?} is not a number from 1 to 65535."))?,
        };
        let inherit = self.form_inherit();
        let user = self.field(Field::User).text.trim().to_string();
        if user.is_empty() && !inherit.credentials {
            return Err("Enter a user name.".into());
        }
        let name = match self.field(Field::Name).text.trim() {
            "" => host.clone(),
            n => n.to_string(),
        };
        let (width, height) = self.form_size();
        Ok(Connection {
            name,
            host,
            port,
            user,
            width,
            height,
            options: self.opts.clone(),
            password: self.form_password(inherit.credentials),
            group: normalize_path(&self.field(Field::GroupPath).text),
            inherit,
        })
    }

    fn group_form(&self) -> Result<Group, String> {
        let name = self.field(Field::Name).text.trim().to_string();
        if name.is_empty() {
            return Err("Enter a group name.".into());
        }
        if name.contains(['/', '\\']) {
            return Err(r"A group name cannot contain / or \.".into());
        }
        let parent = normalize_path(&self.field(Field::GroupPath).text);
        let path = if parent.is_empty() {
            name
        } else {
            format!("{parent}/{name}")
        };
        if let Some(Some(old)) = &self.group_edit
            && path.starts_with(&format!("{old}/"))
        {
            return Err("A group cannot move into itself.".into());
        }
        let inherit = self.form_inherit();
        let (width, height) = self.form_size();
        Ok(Group {
            path,
            user: self.field(Field::User).text.trim().to_string(),
            password: self.form_password(inherit.credentials),
            width,
            height,
            options: self.opts.clone(),
            inherit,
        })
    }

    fn save(&mut self) {
        if self.group_edit.is_some() {
            return self.save_group();
        }
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => return self.set_message(e, ERR),
        };
        let name = c.name.clone();
        let group = c.group.clone();
        if !group.is_empty() {
            self.store.ensure_group(&group);
        }
        match self.selected {
            Some(i) => self.store.connections[i] = c,
            None => {
                self.store.connections.push(c);
                self.selected = Some(self.store.connections.len() - 1);
            }
        }
        self.field_mut(Field::Name).set(&name);
        self.field_mut(Field::GroupPath).set(&group);
        match self.store.save() {
            Ok(()) => self.set_message(format!("Saved {name}."), TEXT_2),
            Err(e) => self.set_message(e, ERR),
        }
    }

    fn save_group(&mut self) {
        let g = match self.group_form() {
            Ok(g) => g,
            Err(e) => return self.set_message(e, ERR),
        };
        let old = self.group_edit.clone().flatten();
        if old.as_deref() != Some(g.path.as_str()) && self.store.group_index(&g.path).is_some() {
            return self.set_message(format!("A group {} already exists.", g.path), ERR);
        }
        match &old {
            Some(old) => self.store.rename_group(old, &g.path),
            None => self.store.ensure_group(&g.path),
        }
        let path = g.path.clone();
        let Some(i) = self.store.group_index(&path) else {
            return;
        };
        self.store.groups[i] = g;
        self.group_edit = Some(Some(path.clone()));
        self.field_mut(Field::GroupPath).set(parent_of(&path));
        match self.store.save() {
            Ok(()) => self.set_message(format!("Saved group {path}."), TEXT_2),
            Err(e) => self.set_message(e, ERR),
        }
    }

    fn delete(&mut self) {
        match self.group_edit.clone() {
            Some(Some(path)) => {
                self.store.delete_group(&path);
                if let Err(e) = self.store.save() {
                    return self.set_message(e, ERR);
                }
                self.set_message(
                    format!("Deleted group {path}; its connections moved up."),
                    TEXT_2,
                );
                if self.store.connections.is_empty() {
                    self.new_connection();
                } else {
                    self.select(0);
                }
                return;
            }
            Some(None) => return self.new_connection(),
            None => {}
        }
        let Some(i) = self.selected else { return };
        let gone = self.store.connections.remove(i);
        if let Err(e) = self.store.save() {
            return self.set_message(e, ERR);
        }
        self.set_message(format!("Deleted {}.", gone.name), TEXT_2);
        if self.store.connections.is_empty() {
            self.new_connection();
        } else {
            self.select(i.min(self.store.connections.len() - 1));
        }
    }

    fn connect(&mut self) -> Option<Action> {
        match self.group_edit.clone() {
            Some(Some(path)) => return self.connect_all(&path),
            Some(None) => {
                self.set_message("Save the group first.", ERR);
                return None;
            }
            None => {}
        }
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => {
                self.set_message(e, ERR);
                return None;
            }
        };
        let typed = self.field(Field::Password).text.clone();
        if !c.inherit.credentials
            && self.save_password
            && self.store.is_vault()
            && !typed.is_empty()
        {
            // Connecting with "Save password" on remembers what was typed.
            if let Some(i) = self.selected {
                self.store.connections[i].password = c.password.clone();
                if let Err(e) = self.store.save() {
                    self.set_message(e, ERR);
                }
            }
        }
        let r = self.store.resolve(&c);
        if r.user.is_empty() {
            self.set_message("No user name: enter one here or in the group.", ERR);
            return None;
        }
        // A typed password wins; otherwise the saved one (vault only).
        let password = if typed.is_empty() {
            r.password.clone().unwrap_or_default()
        } else {
            typed
        };
        self.set_message(format!("Connecting to {}…", r.host), TEXT_2);
        Some(session_action(&r, &password))
    }

    /// Opens every connection in a group (and its sub-groups) that has a
    /// user and a password: saved, or typed in the group form.
    fn connect_all(&mut self, path: &str) -> Option<Action> {
        let typed = self.field(Field::Password).text.clone();
        let mut acts = Vec::new();
        let mut skipped = 0;
        for c in self.store.members(path) {
            let r = self.store.resolve(c);
            let pw = r
                .password
                .clone()
                .or_else(|| (!typed.is_empty()).then(|| typed.clone()));
            match pw {
                Some(pw) if !r.user.is_empty() => acts.push(session_action(&r, &pw)),
                _ => skipped += 1,
            }
        }
        let n = acts.len();
        let msg = match (n, skipped) {
            (0, 0) => "This group has no connections yet.".to_string(),
            (0, _) => "No member has a saved password; type one here to use it for all of them."
                .to_string(),
            (n, 0) => format!(
                "Connecting {n} connection{}…",
                if n == 1 { "" } else { "s" }
            ),
            (n, k) => format!("Connecting {n}; {k} skipped (no saved password or user)."),
        };
        self.set_message(msg, if n == 0 { ERR } else { TEXT_2 });
        (n > 0).then_some(Action::Batch(acts))
    }

    /// Sidebar rows: the group tree, or a flat list of matches while filtering.
    fn rows(&self) -> Vec<Row> {
        let q = self.field(Field::Filter).text.to_lowercase();
        if !q.is_empty() {
            return (0..self.store.connections.len())
                .filter(|&i| {
                    let c = &self.store.connections[i];
                    [&c.name, &c.host, &c.user, &c.group]
                        .iter()
                        .any(|s| s.to_lowercase().contains(&q))
                })
                .map(|i| Row::Conn(i, 0))
                .collect();
        }
        let mut out = Vec::new();
        self.tree_rows("", 0, &mut out);
        out
    }

    fn tree_rows(&self, path: &str, depth: usize, out: &mut Vec<Row>) {
        for (gi, g) in self.store.groups.iter().enumerate() {
            if g.parent() == path {
                out.push(Row::Group(gi, depth));
                if !self.collapsed.contains(&g.path) {
                    self.tree_rows(&g.path, depth + 1, out);
                }
            }
        }
        for (i, c) in self.store.connections.iter().enumerate() {
            if c.group == path {
                out.push(Row::Conn(i, depth));
            }
        }
    }

    /// Connections in sidebar order (keyboard Up/Down).
    fn visible(&self) -> Vec<usize> {
        self.rows()
            .into_iter()
            .filter_map(|r| match r {
                Row::Conn(i, _) => Some(i),
                Row::Group(..) => None,
            })
            .collect()
    }

    /// One line describing an inherited section: where it comes from and what it is.
    fn inherited_text(&self, parent: &str, section: u8) -> String {
        let pick: fn(&Inherit) -> bool = match section {
            0 => |i| i.credentials,
            1 => |i| i.display,
            _ => |i| i.sharing,
        };
        let Some(g) = self.store.source_of(parent, &Inherit::ALL, pick) else {
            return "Inherited, but no group above sets it yet.".into();
        };
        let what = match section {
            0 => {
                let user = if g.user.is_empty() {
                    "no user set"
                } else {
                    g.user.as_str()
                };
                if g.password.is_some() {
                    format!("{user} · password saved")
                } else {
                    user.to_string()
                }
            }
            1 => {
                let size = if g.width == 0 {
                    "Fit window".to_string()
                } else {
                    format!("{} × {}", g.width, g.height)
                };
                let scale = g
                    .options
                    .scale
                    .map_or("Auto scale".to_string(), |v| format!("{v} %"));
                format!("{size} · {scale}")
            }
            _ => {
                let o = &g.options;
                let on: Vec<&str> = [
                    ("Clipboard", o.clipboard),
                    ("Sound", o.sound),
                    ("Printers", o.printers),
                    ("Smart cards", o.smart_cards),
                ]
                .iter()
                .filter(|x| x.1)
                .map(|x| x.0)
                .collect();
                let mut t = if on.is_empty() {
                    "Nothing shared".to_string()
                } else {
                    on.join(", ")
                };
                let n = o.drives.len();
                if n > 0 {
                    t += &format!(" · {n} folder{}", if n == 1 { "" } else { "s" });
                }
                t
            }
        };
        format!("From {}: {what}", g.path)
    }

    /// Tab order of the visible form fields.
    fn form_order(&self) -> Vec<Field> {
        let mut v = vec![Field::Name];
        if self.group_edit.is_none() {
            v.extend([Field::Host, Field::Port]);
        }
        v.push(Field::GroupPath);
        if !self.form_inherit().credentials {
            v.push(Field::User);
        }
        v.push(Field::Password);
        v
    }

    fn hit_at(&self, x: i32, y: i32) -> Option<Hit> {
        self.hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(x, y))
            .map(|(_, h)| *h)
    }

    /// Returns true when the hover target changed (needs a repaint).
    pub fn mouse_move(&mut self, x: i32, y: i32) -> bool {
        let h = self.hit_at(x, y);
        let changed = h != self.hover
            && !matches!(
                (h, self.hover),
                (Some(Hit::Session(_)), Some(Hit::Session(_)))
            );
        self.hover = h;
        changed
    }

    pub fn cursor_is_text(&self) -> bool {
        matches!(self.hover, Some(Hit::Field(_)))
    }

    pub fn mouse_down(&mut self, x: i32, y: i32, te: &mut TextEngine, fonts: &Fonts) {
        self.press = self.hit_at(x, y);
        self.session_focus = matches!(self.press, Some(Hit::Session(_)));
        match self.press {
            Some(Hit::Field(f)) => {
                self.focus = Some(f);
                if let Some(&(_, r)) = self.field_rects.iter().find(|(ff, _)| *ff == f) {
                    let display = self.field(f).display();
                    let size = 13.5 * self.scale;
                    let rel =
                        (x - r.x) as f32 - 10.0 * self.scale + self.field_scroll(f, r, te, fonts);
                    let mut caret = 0;
                    let mut prefix = String::new();
                    for c in display.chars() {
                        let before = te.measure(fonts.ui, size, &prefix);
                        prefix.push(c);
                        let after = te.measure(fonts.ui, size, &prefix);
                        if rel < (before + after) / 2.0 {
                            break;
                        }
                        caret += 1;
                    }
                    let tf = self.field_mut(f);
                    tf.caret = caret;
                    tf.all = false;
                }
            }
            Some(Hit::Session(_)) => self.focus = None,
            Some(_) => {}
            None => self.focus = None,
        }
    }

    pub fn mouse_up(&mut self, x: i32, y: i32) -> Option<Action> {
        let pressed = self.press.take();
        let hit = self.hit_at(x, y);
        if pressed.is_some() && pressed == hit {
            self.activate(hit?)
        } else {
            None
        }
    }

    fn activate(&mut self, hit: Hit) -> Option<Action> {
        match hit {
            Hit::Row(i) => {
                self.select(i);
                self.active = None;
            }
            Hit::GroupRow(gi) => {
                self.select_group(gi);
                self.active = None;
            }
            Hit::GroupToggle(gi) => {
                if let Some(g) = self.store.groups.get(gi) {
                    let path = g.path.clone();
                    if !self.collapsed.remove(&path) {
                        self.collapsed.insert(path);
                    }
                }
            }
            Hit::NewGroup => {
                self.new_group();
                self.active = None;
            }
            Hit::NewInGroup => {
                let g = self.context_group();
                self.new_connection_in(&g);
            }
            Hit::FormInherit(i) => {
                let h = &mut self.inherit;
                let flag = match i {
                    0 => &mut h.credentials,
                    1 => &mut h.display,
                    _ => &mut h.sharing,
                };
                *flag = !*flag;
            }
            Hit::New => {
                let g = self.context_group();
                self.new_connection_in(&g);
                self.active = None;
            }
            Hit::Field(f) => self.focus = Some(f),
            Hit::Size(i) => self.size = i,
            Hit::Connect => return self.connect(),
            Hit::Save => self.save(),
            Hit::Delete => self.delete(),
            Hit::Home => self.active = None,
            Hit::Tab(id) => self.active = Some(id),
            Hit::CloseTab(id) => return Some(Action::CloseTab(id)),
            Hit::Drawer => self.drawer = !self.drawer,
            Hit::Reconnect(id) => return Some(Action::Reconnect(id)),
            Hit::Disconnect(id) => return Some(Action::Disconnect(id)),
            Hit::Sound(id) => {
                let t = self.tab_mut(id)?;
                t.sound = !t.sound;
                return Some(Action::SetSound(id, t.sound));
            }
            Hit::Printers(id) => {
                let t = self.tab_mut(id)?;
                t.printers = !t.printers;
                return Some(Action::SetPrinters(id, t.printers));
            }
            Hit::SmartCards(id) => {
                let t = self.tab_mut(id)?;
                t.smart_cards = !t.smart_cards;
                return Some(Action::SetSmartCards(id, t.smart_cards));
            }
            Hit::Clipboard(id) => {
                let t = self.tab_mut(id)?;
                t.clipboard = !t.clipboard;
                return Some(Action::SetClipboard(id, t.clipboard));
            }
            Hit::FormScale(i) => {
                self.opts.scale = if i == 0 { None } else { Some(SCALES[i - 1]) };
            }
            Hit::FormShare(i) => {
                let o = &mut self.opts;
                let flag = match i {
                    0 => &mut o.clipboard,
                    1 => &mut o.sound,
                    2 => &mut o.printers,
                    _ => &mut o.smart_cards,
                };
                *flag = !*flag;
            }
            Hit::FormRemoveDrive(i) => {
                if i < self.opts.drives.len() {
                    self.opts.drives.remove(i);
                }
            }
            Hit::FormAddDrive => self.form_add_drive(),
            Hit::SavePassword => {
                if self.store.is_vault() {
                    self.save_password = !self.save_password;
                } else {
                    // Saving passwords needs the encrypted vault first.
                    self.vault_setup = true;
                    self.vault_error = None;
                    self.focus = Some(Field::Master);
                }
            }
            Hit::Remember => self.remember = !self.remember,
            Hit::Unlock => return self.unlock(),
            Hit::CreateVault => return self.create_vault(),
            Hit::CancelVault => {
                self.vault_setup = false;
                self.field_mut(Field::Master).set("");
                self.field_mut(Field::MasterConfirm).set("");
            }
            Hit::Lock => return Some(Action::Lock),
            Hit::Scale(id, i) => {
                let t = self.tab_mut(id)?;
                t.scale = if i == 0 { None } else { Some(SCALES[i - 1]) };
                return Some(Action::SetScale(id, t.scale));
            }
            Hit::Fit(id) => {
                let t = self.tab_mut(id)?;
                t.fit = !t.fit;
                return Some(Action::SetFit(id, t.fit));
            }
            Hit::AddDrive(id) => return self.add_drive(id),
            Hit::RemoveDrive(id, i) => return Some(Action::RemoveDrive(id, i)),
            Hit::CtrlAltDel(id) => return Some(Action::CtrlAltDel(id)),
            Hit::Session(_) => {}
            Hit::WinMinimize => return Some(Action::WinMinimize),
            Hit::WinClose => return Some(Action::WinClose),
        }
        None
    }

    fn unlock(&mut self) -> Option<Action> {
        if self.unlocking {
            return None;
        }
        let master =
            zeroize::Zeroizing::new(std::mem::take(&mut self.field_mut(Field::Master).text));
        self.field_mut(Field::Master).set("");
        if master.is_empty() {
            self.vault_error = Some("Enter your master password.".into());
            return None;
        }
        self.unlocking = true;
        self.vault_error = None;
        Some(Action::Unlock {
            master,
            remember: self.remember,
        })
    }

    fn create_vault(&mut self) -> Option<Action> {
        let a = zeroize::Zeroizing::new(self.field(Field::Master).text.clone());
        let b = zeroize::Zeroizing::new(self.field(Field::MasterConfirm).text.clone());
        if a.chars().count() < 8 {
            self.vault_error = Some("Use at least 8 characters.".into());
            return None;
        }
        if a != b {
            self.vault_error = Some("The two passwords differ.".into());
            return None;
        }
        self.field_mut(Field::Master).set("");
        self.field_mut(Field::MasterConfirm).set("");
        self.unlocking = true;
        self.vault_error = None;
        Some(Action::CreateVault { master: a })
    }

    /// The app calls these with the result of key derivation.
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    pub fn vault_opened(&mut self) {
        self.store.adopt_groups();
        self.unlocking = false;
        self.vault_error = None;
        if self.vault_setup {
            self.vault_setup = false;
            self.save_password = true;
            self.set_message(
                "Master password set. Passwords you save are encrypted.",
                TEXT_2,
            );
        } else if self.store.connections.is_empty() {
            self.new_connection();
        } else {
            self.select(0);
        }
    }

    pub fn vault_failed(&mut self, e: String) {
        self.unlocking = false;
        self.vault_error = Some(e);
        self.focus = Some(Field::Master);
    }

    pub fn vault_locked(&mut self) {
        self.selected = None;
        self.new_connection();
        self.focus = Some(Field::Master);
        self.set_message("Locked.", TEXT_2);
    }

    fn form_add_drive(&mut self) {
        let path = self
            .field(Field::FormDrive)
            .text
            .trim()
            .trim_matches('"')
            .to_string();
        if path.is_empty() {
            self.focus = Some(Field::FormDrive);
            return self.set_message("Type the folder to share, then press Add.", TEXT_2);
        }
        if !std::path::Path::new(&path).is_dir() {
            return self.set_message(format!("{path} is not a folder."), ERR);
        }
        if !self.opts.drives.contains(&path) {
            self.opts.drives.push(path);
        }
        self.field_mut(Field::FormDrive).set("");
    }

    fn add_drive(&mut self, id: u64) -> Option<Action> {
        let path = self
            .field(Field::DrivePath)
            .text
            .trim()
            .trim_matches('"')
            .to_string();
        if path.is_empty() {
            self.focus = Some(Field::DrivePath);
            self.set_message("Type the folder to share, then press Add.", TEXT_2);
            return None;
        }
        if !std::path::Path::new(&path).is_dir() {
            self.set_message(format!("{path} is not a folder."), ERR);
            return None;
        }
        self.field_mut(Field::DrivePath).set("");
        Some(Action::AddDrive(id, path))
    }

    pub fn key(&mut self, k: Key) -> Option<Action> {
        match k {
            Key::Enter if self.focus == Some(Field::DrivePath) => {
                return self.active.and_then(|id| self.add_drive(id));
            }
            Key::Enter if self.focus == Some(Field::FormDrive) => self.form_add_drive(),
            Key::Enter if self.store.is_locked() => return self.unlock(),
            Key::Enter if self.vault_setup => return self.create_vault(),
            Key::Enter if self.active.is_none() => return self.connect(),
            Key::Enter => {}
            Key::Esc => self.focus = None,
            Key::New => {
                let g = self.context_group();
                self.new_connection_in(&g);
                self.active = None;
            }
            Key::Save if self.active.is_none() => self.save(),
            Key::Save => {}
            Key::NextTab | Key::PrevTab => {
                let ids: Vec<Option<u64>> = std::iter::once(None)
                    .chain(self.tabs.iter().map(|t| Some(t.id)))
                    .collect();
                let pos = ids.iter().position(|&x| x == self.active).unwrap_or(0);
                let n = ids.len();
                let next = if matches!(k, Key::NextTab) {
                    (pos + 1) % n
                } else {
                    (pos + n - 1) % n
                };
                self.active = ids[next];
                self.session_focus = false;
            }
            Key::Tab | Key::BackTab if self.active.is_none() => {
                let back = matches!(k, Key::BackTab);
                let order = self.form_order();
                let i = self.focus.and_then(|f| order.iter().position(|&x| x == f));
                let n = order.len();
                let next = match (i, back) {
                    (Some(i), false) => (i + 1) % n,
                    (Some(i), true) => (i + n - 1) % n,
                    (None, false) => 0,
                    (None, true) => n - 1,
                };
                self.focus = Some(order[next]);
                self.field_mut(order[next]).select_all();
            }
            Key::Up | Key::Down if self.focus.is_none() || self.focus == Some(Field::Filter) => {
                let vis = self.visible();
                if !vis.is_empty() {
                    let pos = self.selected.and_then(|s| vis.iter().position(|&v| v == s));
                    let next = match (pos, matches!(k, Key::Up)) {
                        (Some(p), true) => p.saturating_sub(1),
                        (Some(p), false) => (p + 1).min(vis.len() - 1),
                        (None, _) => 0,
                    };
                    let keep = self.focus;
                    self.select(vis[next]);
                    self.focus = keep;
                    self.active = None;
                }
            }
            other => {
                let f = self.focus?;
                let tf = self.field_mut(f);
                match other {
                    Key::Char(c) => tf.insert(&c.to_string()),
                    Key::Paste(s) => tf.insert(s.lines().next().unwrap_or("")),
                    Key::Backspace => tf.backspace(),
                    Key::Delete => tf.delete(),
                    Key::Left => tf.left(),
                    Key::Right => tf.right(),
                    Key::Home => tf.home(),
                    Key::End => tf.end(),
                    Key::SelectAll => tf.select_all(),
                    _ => {}
                }
            }
        }
        None
    }

    fn field_scroll(&self, f: Field, r: Rect, te: &mut TextEngine, fonts: &Fonts) -> f32 {
        let tf = self.field(f);
        let size = 13.5 * self.scale;
        let inner = r.w as f32 - 20.0 * self.scale;
        let caret_x = te.measure(
            fonts.ui,
            size,
            &tf.display().chars().take(tf.caret).collect::<String>(),
        );
        (caret_x - inner + 2.0).max(0.0)
    }

    pub fn paint(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.hits.clear();
        self.field_rects.clear();
        self.session_area = None;
        self.title_controls.clear();
        self.caption = Rect::default();
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        cv.fill(Rect::new(0, 0, w, h), BG);
        let bar_h = p(28.0);
        let body_h = h - bar_h;
        let side_w = p(260.0).min(w / 3);

        self.paint_sidebar(cv, te, f, Rect::new(0, 0, side_w, body_h));
        cv.fill(Rect::new(side_w, 0, 1, body_h), BORDER_SOFT);
        let main = Rect::new(side_w + 1, 0, w - side_w - 1, body_h);
        let strip_h = p(38.0);
        self.paint_tabs(cv, te, f, Rect::new(main.x, 0, main.w, strip_h));
        let content = Rect::new(main.x, strip_h, main.w, main.h - strip_h);
        match self.active_tab().map(|t| t.id) {
            Some(id) => self.paint_session(cv, te, f, content, id),
            None if self.store.is_locked() || self.vault_setup => {
                self.paint_vault(cv, te, f, content)
            }
            None => self.paint_home(cv, te, f, content),
        }

        let bar = Rect::new(0, body_h, w, bar_h);
        cv.fill(bar, BG_BAR);
        cv.fill(Rect::new(0, body_h, w, 1), BORDER_SOFT);
        let right = format!("{} renderer · damage-only presents", self.renderer);
        let rw = te.measure(f.ui, 12.0 * s, &right) as i32;
        te.draw_in(
            cv,
            f.ui,
            12.0 * s,
            Rect::new(w - rw - p(14.0), body_h, rw + p(14.0), bar_h),
            0.0,
            &right,
            TEXT_4,
        );
        let (msg, color) = if self.session_focus && self.active.is_some() {
            (
                "Keyboard goes to the remote session · Ctrl+Alt+Home gives it back".to_string(),
                ACCENT,
            )
        } else {
            self.message
                .clone()
                .unwrap_or_else(|| ("Ready".into(), TEXT_3))
        };
        te.draw_in(
            cv,
            f.ui,
            12.0 * s,
            Rect::new(0, body_h, w - rw - p(28.0), bar_h),
            p(14.0) as f32,
            &msg,
            color,
        );
    }

    fn paint_sidebar(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(area, BG_SIDEBAR);
        let pad = p(14.0);
        let head = Rect::new(pad, p(5.0), area.w - 2 * pad, p(28.0));
        te.draw_in(cv, f.semi, 11.5 * s, head, 0.0, "CONNECTIONS", TEXT_3);
        let nw = p(62.0);
        if !self.store.is_locked() {
            self.button(
                cv,
                te,
                f,
                Rect::new(head.right() - nw, head.y, nw, head.h),
                "+ New",
                Style::Ghost,
                Hit::New,
            );
            // "+ New" sits in the title row: a control there, not a window drag.
            self.title_controls.push((head.right() - nw, head.right()));
        }
        if self.store.is_vault() {
            let lw = p(52.0);
            let lr = Rect::new(head.right() - nw - lw - p(4.0), head.y, lw, head.h);
            self.button(cv, te, f, lr, "Lock", Style::Ghost, Hit::Lock);
            self.title_controls.push((lr.x, lr.right()));
        }
        let gw = if self.store.is_locked() { 0 } else { p(72.0) };
        self.text_input(
            cv,
            te,
            f,
            Rect::new(
                pad,
                p(44.0),
                area.w - 2 * pad - if gw > 0 { gw + p(6.0) } else { 0 },
                p(30.0),
            ),
            Field::Filter,
            "Filter",
        );
        if gw > 0 {
            self.button(
                cv,
                te,
                f,
                Rect::new(area.w - pad - gw, p(44.0), gw, p(30.0)),
                "+ Group",
                Style::Ghost,
                Hit::NewGroup,
            );
        }

        let list = Rect::new(0, p(86.0), area.w, area.h - p(86.0));
        let old = cv.set_clip(list);
        let rows = self.rows();
        if self.store.connections.is_empty() && self.store.groups.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(pad, list.y + p(8.0), list.w - 2 * pad, p(22.0)),
                0.0,
                if self.store.is_locked() {
                    "Locked."
                } else {
                    "No saved connections yet."
                },
                TEXT_3,
            );
            te.draw_in(
                cv,
                f.ui,
                12.0 * s,
                Rect::new(pad, list.y + p(30.0), list.w - 2 * pad, p(20.0)),
                0.0,
                if self.store.is_locked() {
                    "Unlock to see your connections."
                } else {
                    "Fill in the form and press Save."
                },
                TEXT_4,
            );
        } else if rows.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(pad, list.y + p(8.0), list.w - 2 * pad, p(22.0)),
                0.0,
                "No match.",
                TEXT_3,
            );
        }
        let row_h = p(52.0);
        let group_h = p(34.0);
        let home = self.active.is_none();
        let open_group = self.group_edit.clone().flatten();
        let mut y = list.y;
        for row in rows {
            if y > list.bottom() {
                break;
            }
            match row {
                Row::Group(gi, depth) => {
                    let indent = depth as i32 * p(16.0);
                    let r = Rect::new(p(8.0), y, area.w - p(16.0), group_h);
                    y += group_h + p(2.0);
                    let g = &self.store.groups[gi];
                    let (path, name) = (g.path.clone(), g.name().to_string());
                    let count = self.store.members(&path).count().to_string();
                    let hovered = matches!(self.hover, Some(Hit::GroupRow(h) | Hit::GroupToggle(h)) if h == gi);
                    if home && open_group.as_deref() == Some(path.as_str()) {
                        cv.fill_round(r, 6.0 * s, BG_SELECT);
                        cv.fill_round(
                            Rect::new(r.x, r.y + p(9.0), p(3.0), r.h - p(18.0)),
                            1.5 * s,
                            ACCENT,
                        );
                    } else if hovered {
                        cv.fill_round(r, 6.0 * s, BG_HOVER);
                    }
                    let open = !self.collapsed.contains(&path);
                    te.draw(
                        cv,
                        f.ui,
                        9.0 * s,
                        (r.x + indent + p(12.0)) as f32,
                        (r.y + p(21.0)) as f32,
                        if open { "▼" } else { "►" },
                        TEXT_3,
                        p(14.0) as f32,
                    );
                    let cw = te.measure(f.ui, 12.0 * s, &count) as i32;
                    te.draw(
                        cv,
                        f.semi,
                        13.0 * s,
                        (r.x + indent + p(28.0)) as f32,
                        (r.y + p(22.0)) as f32,
                        &name,
                        TEXT_2,
                        (r.w - indent - p(48.0) - cw) as f32,
                    );
                    te.draw(
                        cv,
                        f.ui,
                        12.0 * s,
                        (r.right() - p(14.0) - cw) as f32,
                        (r.y + p(22.0)) as f32,
                        &count,
                        TEXT_4,
                        (cw + p(2.0)) as f32,
                    );
                    self.hits.push((r.intersect(list), Hit::GroupRow(gi)));
                    self.hits.push((
                        Rect::new(r.x, r.y, indent + p(28.0), r.h).intersect(list),
                        Hit::GroupToggle(gi),
                    ));
                }
                Row::Conn(i, depth) => {
                    let indent = depth as i32 * p(16.0);
                    let r = Rect::new(p(8.0) + indent, y, area.w - p(16.0) - indent, row_h);
                    y += row_h + p(2.0);
                    self.paint_connection_row(cv, te, f, r, list, i, home);
                }
            }
        }
        cv.set_clip(old);
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_connection_row(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        list: Rect,
        i: usize,
        home: bool,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let hit = Hit::Row(i);
        if home && self.selected == Some(i) && self.group_edit.is_none() {
            cv.fill_round(r, 6.0 * s, BG_SELECT);
            cv.fill_round(
                Rect::new(r.x, r.y + p(12.0), p(3.0), r.h - p(24.0)),
                1.5 * s,
                ACCENT,
            );
        } else if self.hover == Some(hit) {
            cv.fill_round(r, 6.0 * s, BG_HOVER);
        }
        let c = self.store.resolve(&self.store.connections[i]);
        let dot = self.connection_dot(&c);
        let text_w = r.w - p(24.0) - if dot.is_some() { p(16.0) } else { 0 };
        te.draw(
            cv,
            f.semi,
            13.5 * s,
            (r.x + p(14.0)) as f32,
            (r.y + p(22.0)) as f32,
            &c.name,
            TEXT,
            text_w as f32,
        );
        let sub = if c.port == 3389 {
            format!("{} · {}", c.host, c.user)
        } else {
            format!("{}:{} · {}", c.host, c.port, c.user)
        };
        te.draw(
            cv,
            f.ui,
            12.0 * s,
            (r.x + p(14.0)) as f32,
            (r.y + p(40.0)) as f32,
            &sub,
            TEXT_3,
            text_w as f32,
        );
        if let Some(color) = dot {
            cv.fill_circle(
                (r.right() - p(16.0)) as f32,
                (r.y + r.h / 2) as f32,
                4.0 * s,
                color,
            );
        }
        self.hits.push((r.intersect(list), hit));
    }

    fn connection_dot(&self, c: &Connection) -> Option<u32> {
        let mut out = None;
        for t in self
            .tabs
            .iter()
            .filter(|t| t.name == c.name && t.host == c.host)
        {
            match t.state {
                TabState::Connected { .. } => return Some(OK),
                TabState::Connecting => out = Some(WARN),
                _ => {}
            }
        }
        out
    }

    fn paint_tabs(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, strip: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(strip, BG_SIDEBAR);
        cv.fill(
            Rect::new(strip.x, strip.bottom() - 1, strip.w, 1),
            BORDER_SOFT,
        );
        self.title_height = strip.bottom();
        let mut right = strip.right();
        if self.custom_frame {
            let cw = 3 * p(46.0);
            self.caption = Rect::new(strip.right() - cw, strip.y, cw, strip.h - 1);
            right = self.caption.x - p(8.0);
            self.paint_caption(cv);
        }
        let mut x = strip.x + p(6.0);
        let th = strip.h - p(6.0);
        let y = strip.y + p(6.0);

        // The Connections tab.
        let label = "Connections";
        let tw = te.measure(f.ui, 13.0 * s, label) as i32 + p(28.0);
        let r = Rect::new(x, y, tw, th);
        self.tab_shape(cv, r, self.active.is_none(), self.hover == Some(Hit::Home));
        let color = if self.active.is_none() { TEXT } else { TEXT_2 };
        centered(cv, te, f.ui, 13.0 * s, r, label, color);
        self.hits.push((r, Hit::Home));
        self.title_controls.push((r.x, r.right()));
        x += tw + p(2.0);

        let tabs: Vec<(u64, String, u32)> = self
            .tabs
            .iter()
            .map(|t| (t.id, t.name.clone(), t.state.color()))
            .collect();
        let avail = right - x - p(6.0);
        let each = if tabs.is_empty() {
            0
        } else {
            (avail / tabs.len() as i32).clamp(p(90.0), p(220.0))
        };
        for (id, name, color) in tabs {
            if x + p(60.0) > right {
                break;
            }
            let r = Rect::new(x, y, each.min(right - x), th);
            self.title_controls.push((r.x, r.right()));
            let active = self.active == Some(id);
            self.tab_shape(cv, r, active, self.hover == Some(Hit::Tab(id)));
            cv.fill_circle(
                (r.x + p(14.0)) as f32,
                (r.y + r.h / 2) as f32,
                3.5 * s,
                color,
            );
            let close = Rect::new(
                r.right() - p(28.0),
                r.y + (r.h - p(20.0)) / 2,
                p(20.0),
                p(20.0),
            );
            let tc = if active { TEXT } else { TEXT_2 };
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(26.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                &name,
                tc,
                (close.x - r.x - p(30.0)) as f32,
            );
            self.hits.push((r, Hit::Tab(id)));
            let ch = Hit::CloseTab(id);
            if self.hover == Some(ch) {
                cv.fill_round(close, 4.0 * s, CONTROL_HOVER);
            }
            if active || self.hover == Some(Hit::Tab(id)) || self.hover == Some(ch) {
                let (cx, cy, d) = (
                    (close.x + close.w / 2) as f32,
                    (close.y + close.h / 2) as f32,
                    4.0 * s,
                );
                cv.stroke(&[(cx - d, cy - d), (cx + d, cy + d)], 1.4 * s, TEXT_2);
                cv.stroke(&[(cx - d, cy + d), (cx + d, cy - d)], 1.4 * s, TEXT_2);
            }
            self.hits.push((close, ch));
            x += r.w + p(2.0);
        }
    }

    /// Windows 11 caption buttons (46 px each at 100 %), drawn like the
    /// system's: minimise, maximise/restore, close with a red hover.
    fn paint_caption(&mut self, cv: &mut Canvas) {
        let r = self.caption;
        let s = self.scale;
        let bw = r.w / 3;
        let line = (1.0 * s).round().max(1.0) as i32;
        let g = (5.0 * s).round() as i32;
        for i in 0..3 {
            let x = r.x + i * bw;
            let b = Rect::new(x, r.y, if i == 2 { r.right() - x } else { bw }, r.h);
            let (hover, pressed) = match i {
                1 => self.max_state,
                0 => (
                    self.hover == Some(Hit::WinMinimize),
                    self.press == Some(Hit::WinMinimize),
                ),
                _ => (
                    self.hover == Some(Hit::WinClose),
                    self.press == Some(Hit::WinClose),
                ),
            };
            let idle = if self.window_active { TEXT } else { TEXT_3 };
            let (fill, glyph) = match (i, hover, pressed && hover) {
                (2, true, true) => (CLOSE_PRESS, 0xffffff),
                (2, true, false) => (CLOSE_HOVER, 0xffffff),
                (_, true, true) => (BG_PRESS, TEXT),
                (_, true, false) => (BG_HOVER, TEXT),
                _ => (BG_SIDEBAR, idle),
            };
            cv.fill(b, fill);
            let (cx, cy) = (b.x + b.w / 2, b.y + b.h / 2);
            match i {
                0 => cv.fill(Rect::new(cx - g, cy, 2 * g, line), glyph),
                1 if self.maximized => {
                    let k = (2.0 * s).round() as i32;
                    // Back window: only its top and right edges show.
                    cv.fill(Rect::new(cx - g + k, cy - g, 2 * g - k, line), glyph);
                    cv.fill(Rect::new(cx + g - line, cy - g, line, 2 * g - k), glyph);
                    let front = Rect::new(cx - g, cy - g + k, 2 * g - k, 2 * g - k);
                    cv.fill(front, fill);
                    cv.stroke_rect(front, glyph);
                }
                1 => cv.stroke_rect(Rect::new(cx - g, cy - g, 2 * g, 2 * g), glyph),
                _ => {
                    let (fx, fy, fs) = (cx as f32, cy as f32, g as f32);
                    let w = s.max(1.0);
                    cv.stroke(&[(fx - fs, fy - fs), (fx + fs, fy + fs)], w, glyph);
                    cv.stroke(&[(fx - fs, fy + fs), (fx + fs, fy - fs)], w, glyph);
                }
            }
            match i {
                0 => self.hits.push((b, Hit::WinMinimize)),
                2 => self.hits.push((b, Hit::WinClose)),
                _ => {}
            }
        }
    }

    /// Where the title row's controls are, for the frame hook.
    pub fn title_geometry(&self) -> TitleGeometry {
        let c = self.caption;
        let bw = c.w / 3;
        TitleGeometry {
            height: self.title_height,
            controls: self.title_controls.clone(),
            buttons_left: if c.is_empty() { i32::MAX } else { c.x },
            max_button: (c.x + bw, c.x + 2 * bw),
        }
    }

    /// A selectable chip at (x, y); returns its width.
    #[allow(clippy::too_many_arguments)]
    fn chip(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        h: i32,
        text: &str,
        chosen: bool,
        hit: Hit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let w = te.measure(f.ui, 12.5 * s, text) as i32 + p(24.0);
        let r = Rect::new(x, y + p(2.0), w, h - p(4.0));
        let (border, fill, color) = if chosen {
            (ACCENT_BORDER, BG_CHOSEN, TEXT)
        } else if self.hover == Some(hit) {
            (BORDER_HOVER, CONTROL_HOVER, TEXT_2)
        } else {
            (BORDER, BG, TEXT_3)
        };
        cv.round_border(r, 6.0 * s, border, fill);
        centered(cv, te, f.ui, 12.5 * s, r, text, color);
        self.hits.push((r, hit));
        w
    }

    fn tab_shape(&self, cv: &mut Canvas, r: Rect, active: bool, hover: bool) {
        let s = self.scale;
        if active {
            cv.fill_round(
                Rect::new(r.x, r.y, r.w, r.h + (8.0 * s) as i32),
                6.0 * s,
                BG,
            );
            cv.fill(
                Rect::new(
                    r.x + (6.0 * s) as i32,
                    r.y,
                    r.w - (12.0 * s) as i32,
                    (2.0 * s).max(1.0) as i32,
                ),
                ACCENT,
            );
        } else if hover {
            cv.fill_round(
                Rect::new(r.x, r.y + (2.0 * s) as i32, r.w, r.h - (6.0 * s) as i32),
                6.0 * s,
                BG_HOVER,
            );
        }
    }

    /// The unlock screen, or the "set a master password" panel.
    fn paint_vault(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let w = p(420.0).min(area.w - p(64.0));
        let x = area.x + (area.w - w) / 2;
        let mut y = area.y + p(90.0);
        let creating = !self.store.is_locked();
        let (title, sub) = if creating {
            (
                "Set a master password",
                "Saved passwords are encrypted with it. Forget it, and they are lost.",
            )
        } else {
            (
                "Unlock your connections",
                "Your connections and saved passwords are encrypted.",
            )
        };
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x as f32,
            (y + p(20.0)) as f32,
            title,
            TEXT,
            w as f32,
        );
        y += p(34.0);
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x as f32,
            (y + p(14.0)) as f32,
            sub,
            TEXT_3,
            w as f32,
        );
        y += p(36.0);
        let fh = p(34.0);
        self.text_input(
            cv,
            te,
            f,
            Rect::new(x, y, w, fh),
            Field::Master,
            "Master password",
        );
        y += fh + p(10.0);
        if creating {
            self.text_input(
                cv,
                te,
                f,
                Rect::new(x, y, w, fh),
                Field::MasterConfirm,
                "Repeat the master password",
            );
            y += fh + p(10.0);
        } else {
            let text = if self.remember {
                "✓ Remember on this PC (Windows account)"
            } else {
                "Remember on this PC (Windows account)"
            };
            let on = self.remember;
            self.chip(cv, te, f, x, y, p(30.0), text, on, Hit::Remember);
            y += p(40.0);
        }
        if let Some(e) = self.vault_error.clone() {
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                x as f32,
                (y + p(12.0)) as f32,
                &e,
                ERR,
                w as f32,
            );
            y += p(26.0);
        }
        let bh = p(36.0);
        if self.unlocking {
            let busy = if creating {
                "Encrypting…"
            } else {
                "Unlocking…"
            };
            centered(cv, te, f.ui, 13.0 * s, Rect::new(x, y, w, bh), busy, TEXT_2);
        } else if creating {
            self.button(
                cv,
                te,
                f,
                Rect::new(x, y, p(170.0), bh),
                "Set master password",
                Style::Primary,
                Hit::CreateVault,
            );
            self.button(
                cv,
                te,
                f,
                Rect::new(x + p(178.0), y, p(96.0), bh),
                "Cancel",
                Style::Secondary,
                Hit::CancelVault,
            );
        } else {
            self.button(
                cv,
                te,
                f,
                Rect::new(x, y, p(120.0), bh),
                "Unlock",
                Style::Primary,
                Hit::Unlock,
            );
        }
        cv.set_clip(old);
    }

    fn paint_home(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let x0 = area.x + p(32.0);
        let label_w = p(96.0);
        let fx = x0 + label_w;
        let fw = p(440.0).min(area.right() - p(32.0) - fx).max(p(160.0));
        let form_w = label_w + fw;
        let group_mode = self.group_edit.is_some();
        let open_group = self.group_edit.clone().flatten();

        let title = match (&open_group, self.selected) {
            (Some(path), _) => path.rsplit('/').next().unwrap_or(path).to_string(),
            (None, _) if group_mode => "New group".into(),
            (None, Some(i)) => self.store.connections[i].name.clone(),
            (None, None) => "New connection".into(),
        };
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x0 as f32,
            (area.y + p(42.0)) as f32,
            &title,
            TEXT,
            form_w as f32,
        );
        let sub = if let Some(path) = &open_group {
            let n = self.store.members(path).count();
            format!(
                "Group with {n} connection{}. Members take the sections they inherit from here.",
                if n == 1 { "" } else { "s" }
            )
        } else if group_mode {
            "Not saved yet. Connections in a group can inherit its settings.".to_string()
        } else {
            format!(
                "{} {}",
                if self.selected.is_some() {
                    "Saved connection."
                } else {
                    "Not saved yet."
                },
                if self.store.is_vault() {
                    "Saved passwords stay in the encrypted vault."
                } else {
                    "Passwords are only saved once you set a master password."
                }
            )
        };
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x0 as f32,
            (area.y + p(64.0)) as f32,
            &sub,
            TEXT_3,
            form_w as f32,
        );

        let mut y = area.y + p(88.0);
        let row = p(44.0);
        let fh = p(32.0);
        let label = |cv: &mut Canvas, te: &mut TextEngine, y: i32, text: &str| {
            te.draw_in(
                cv,
                f.ui,
                13.0 * s,
                Rect::new(x0, y, label_w, fh),
                0.0,
                text,
                TEXT_2,
            );
        };
        let summary = |cv: &mut Canvas, te: &mut TextEngine, y: i32, text: &str| {
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                fx as f32,
                (y + p(21.0)) as f32,
                text,
                TEXT_3,
                fw as f32,
            );
        };
        label(cv, te, y, "Name");
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw, fh),
            Field::Name,
            if group_mode {
                "Group name"
            } else {
                "Defaults to the host"
            },
        );
        y += row;
        if !group_mode {
            label(cv, te, y, "Host");
            let port_w = p(96.0);
            self.text_input(
                cv,
                te,
                f,
                Rect::new(fx, y, fw - port_w - p(8.0), fh),
                Field::Host,
                "Name or IP address",
            );
            self.text_input(
                cv,
                te,
                f,
                Rect::new(fx + fw - port_w, y, port_w, fh),
                Field::Port,
                "Port",
            );
            y += row;
        }
        label(cv, te, y, if group_mode { "Parent" } else { "Group" });
        self.text_input(
            cv,
            te,
            f,
            Rect::new(fx, y, fw, fh),
            Field::GroupPath,
            if group_mode {
                "None (top level)"
            } else {
                "None (top level), e.g. Work/Servers"
            },
        );
        y += row;
        let parent = normalize_path(&self.field(Field::GroupPath).text);
        let inh = self.form_inherit();
        if !parent.is_empty() {
            label(cv, te, y, "Inherit");
            let mut cx = fx;
            for (k, (text, on)) in [
                ("Credentials", inh.credentials),
                ("Display", inh.display),
                ("Sharing", inh.sharing),
            ]
            .into_iter()
            .enumerate()
            {
                let text = if on {
                    format!("✓ {text}")
                } else {
                    text.to_string()
                };
                cx +=
                    self.chip(cv, te, f, cx, y, fh, &text, on, Hit::FormInherit(k as u8)) + p(6.0);
            }
            y += row;
        }

        // Credentials
        if inh.credentials {
            label(cv, te, y, "User");
            summary(cv, te, y, &self.inherited_text(&parent, 0));
            y += row;
            label(cv, te, y, "Password");
            let saved_in = self
                .store
                .source_of(&parent, &Inherit::ALL, |i| i.credentials)
                .filter(|g| g.password.is_some())
                .map(|g| g.path.clone());
            let hint = match saved_in {
                Some(g) => format!("Saved in {g} (type to override)"),
                None => "Asked for each connection".to_string(),
            };
            self.text_input(cv, te, f, Rect::new(fx, y, fw, fh), Field::Password, &hint);
            y += row;
        } else {
            label(cv, te, y, "User");
            self.text_input(
                cv,
                te,
                f,
                Rect::new(fx, y, fw, fh),
                Field::User,
                r"DOMAIN\user or user@domain",
            );
            y += row;
            label(cv, te, y, "Password");
            let saved = self.save_password && self.own_password().is_some();
            let chip_text = if self.save_password {
                "✓ Save password"
            } else {
                "Save password"
            };
            let chip_w = te.measure(f.ui, 12.5 * s, chip_text) as i32 + p(24.0);
            self.text_input(
                cv,
                te,
                f,
                Rect::new(fx, y, fw - chip_w - p(8.0), fh),
                Field::Password,
                if saved {
                    "Saved (type to change)"
                } else if group_mode {
                    "Used by members that inherit it"
                } else {
                    "Asked for each connection"
                },
            );
            let save_on = self.save_password;
            self.chip(
                cv,
                te,
                f,
                fx + fw - chip_w,
                y,
                fh,
                chip_text,
                save_on,
                Hit::SavePassword,
            );
            y += row;
        }

        // Display and scale
        if inh.display {
            label(cv, te, y, "Display");
            summary(cv, te, y, &self.inherited_text(&parent, 1));
            y += row;
        } else {
            label(cv, te, y, "Display");
            let mut cx = fx;
            let choices = std::iter::once("Fit window".to_string())
                .chain(SIZES.iter().map(|(sw, sh)| format!("{sw} × {sh}")));
            for (i, text) in choices.enumerate() {
                cx += self.chip(cv, te, f, cx, y, fh, &text, self.size == i, Hit::Size(i)) + p(6.0);
            }
            y += row - p(4.0);
            te.draw(
                cv,
                f.ui,
                11.5 * s,
                fx as f32,
                (y + p(12.0)) as f32,
                "Fit window matches the tab and follows resizes; a fixed size stays as chosen.",
                TEXT_4,
                fw as f32,
            );
            y += p(34.0);

            label(cv, te, y, "Scale");
            let auto = format!("Auto ({} %)", (self.scale * 100.0).round() as u32);
            let mut cx = fx;
            for (i, text) in std::iter::once(auto)
                .chain(SCALES.iter().map(|v| format!("{v} %")))
                .enumerate()
            {
                let chosen = match (i, self.opts.scale) {
                    (0, None) => true,
                    (i, Some(v)) if i > 0 => SCALES[i - 1] == v,
                    _ => false,
                };
                cx += self.chip(cv, te, f, cx, y, fh, &text, chosen, Hit::FormScale(i)) + p(6.0);
            }
            y += row;
        }

        // Sharing and shared folders
        if inh.sharing {
            label(cv, te, y, "Sharing");
            summary(cv, te, y, &self.inherited_text(&parent, 2));
            y += row + p(8.0);
        } else {
            label(cv, te, y, "Sharing");
            let o = self.opts.clone();
            let mut cx = fx;
            for (i, (text, on)) in [
                ("Clipboard", o.clipboard),
                ("Sound", o.sound),
                ("Printers", o.printers),
                ("Smart cards", o.smart_cards),
            ]
            .into_iter()
            .enumerate()
            {
                let text = if on {
                    format!("✓ {text}")
                } else {
                    text.to_string()
                };
                cx += self.chip(cv, te, f, cx, y, fh, &text, on, Hit::FormShare(i as u8)) + p(6.0);
            }
            y += row;

            label(cv, te, y, "Folders");
            let mut cx = fx;
            for (i, path) in o.drives.iter().enumerate() {
                let text = format!("{path}  ×");
                let w = self.chip(cv, te, f, cx, y, fh, &text, true, Hit::FormRemoveDrive(i));
                cx += w + p(6.0);
                if cx > fx + fw - p(120.0) {
                    cx = fx;
                    y += p(36.0);
                }
            }
            if !o.drives.is_empty() {
                y += p(38.0);
            }
            let add_w = p(64.0);
            self.text_input(
                cv,
                te,
                f,
                Rect::new(fx, y, fw - add_w - p(8.0), fh),
                Field::FormDrive,
                r"Folder to share, e.g. C:\Share",
            );
            self.button(
                cv,
                te,
                f,
                Rect::new(fx + fw - add_w, y, add_w, fh),
                "Add",
                Style::Secondary,
                Hit::FormAddDrive,
            );
            y += row + p(8.0);
        }

        let bh = p(34.0);
        let (connect, cw) = if group_mode {
            ("Connect all", p(116.0))
        } else {
            ("Connect", p(116.0))
        };
        self.button(
            cv,
            te,
            f,
            Rect::new(fx, y, cw, bh),
            connect,
            Style::Primary,
            Hit::Connect,
        );
        let mut bx = fx + cw + p(8.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(bx, y, p(84.0), bh),
            "Save",
            Style::Secondary,
            Hit::Save,
        );
        bx += p(92.0);
        if open_group.is_some() {
            self.button(
                cv,
                te,
                f,
                Rect::new(bx, y, p(120.0), bh),
                "+ Connection",
                Style::Secondary,
                Hit::NewInGroup,
            );
        }
        if self.selected.is_some() || open_group.is_some() {
            self.button(
                cv,
                te,
                f,
                Rect::new(fx + fw - p(84.0), y, p(84.0), bh),
                "Delete",
                Style::Danger,
                Hit::Delete,
            );
        }
        let hint = if group_mode {
            "Connect all opens members with a saved or typed password."
        } else {
            "Enter connects · Tab next field · Ctrl+N new · Ctrl+S save"
        };
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            fx as f32,
            (y + bh + p(22.0)) as f32,
            hint,
            TEXT_4,
            fw as f32,
        );
        cv.set_clip(old);
    }

    fn paint_session(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        content: Rect,
        id: u64,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let Some(tab) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (host, state, name) = (tab.host.clone(), tab.state.clone(), tab.name.clone());

        // Toolbar
        let tb = Rect::new(content.x, content.y, content.w, p(40.0));
        cv.fill(Rect::new(tb.x, tb.bottom() - 1, tb.w, 1), BORDER_SOFT);
        cv.fill_circle(
            (tb.x + p(18.0)) as f32,
            (tb.y + tb.h / 2) as f32,
            4.0 * s,
            state.color(),
        );
        let info = match &state {
            TabState::Connecting => format!("{host} · connecting…"),
            TabState::Connected { width, height, bpp } => {
                format!("{host} · {width} × {height} · {bpp} bpp")
            }
            TabState::Ended(why) => format!("{host} · ended: {why}"),
            TabState::Failed(why) => format!("{host} · failed: {why}"),
        };
        let mut bx = tb.right() - p(8.0);
        let mut buttons: Vec<(&str, Hit, Style)> = vec![(
            if self.drawer { "Hide panel" } else { "Panel" },
            Hit::Drawer,
            Style::Secondary,
        )];
        match state {
            TabState::Connected { .. } | TabState::Connecting => {
                buttons.insert(0, ("Disconnect", Hit::Disconnect(id), Style::Secondary))
            }
            _ => buttons.insert(0, ("Reconnect", Hit::Reconnect(id), Style::Primary)),
        }
        for (text, hit, style) in buttons.iter().rev() {
            let bw = te.measure(f.ui, 13.0 * s, text) as i32 + p(26.0);
            bx -= bw;
            self.button(
                cv,
                te,
                f,
                Rect::new(bx, tb.y + p(6.0), bw, tb.h - p(12.0)),
                text,
                *style,
                *hit,
            );
            bx -= p(6.0);
        }
        te.draw_in(
            cv,
            f.ui,
            12.5 * s,
            Rect::new(tb.x + p(30.0), tb.y, bx - tb.x - p(36.0), tb.h),
            0.0,
            &info,
            TEXT_2,
        );

        // Session area and drawer
        let mut area = Rect::new(
            content.x,
            tb.bottom(),
            content.w,
            content.bottom() - tb.bottom(),
        );
        if self.drawer {
            let dw = p(290.0).min(area.w / 2);
            let drawer = Rect::new(area.right() - dw, area.y, dw, area.h);
            area.w -= dw + 1;
            cv.fill(Rect::new(area.right(), area.y, 1, area.h), BORDER_SOFT);
            self.paint_drawer(cv, te, f, drawer, id);
        }
        cv.fill(area, BG_SIDEBAR);
        match state {
            TabState::Connected { .. } => {
                self.session_area = Some((id, area));
                self.hits.push((area, Hit::Session(id)));
            }
            TabState::Connecting => {
                centered(
                    cv,
                    te,
                    f.ui,
                    14.0 * s,
                    Rect::new(area.x, area.y, area.w, area.h - p(40.0)),
                    &format!("Connecting to {name}…"),
                    TEXT_2,
                );
            }
            TabState::Ended(why) | TabState::Failed(why) => {
                let failed = matches!(
                    self.tabs.iter().find(|t| t.id == id).map(|t| &t.state),
                    Some(TabState::Failed(_))
                );
                let mid = area.y + area.h / 2;
                centered(
                    cv,
                    te,
                    f.semi,
                    15.0 * s,
                    Rect::new(area.x, mid - p(60.0), area.w, p(24.0)),
                    if failed {
                        "Connection failed"
                    } else {
                        "Session ended"
                    },
                    TEXT,
                );
                centered(
                    cv,
                    te,
                    f.ui,
                    12.5 * s,
                    Rect::new(area.x + p(24.0), mid - p(32.0), area.w - p(48.0), p(20.0)),
                    &why,
                    if failed { ERR } else { TEXT_3 },
                );
                let bw = p(120.0);
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(area.x + area.w / 2 - bw - p(4.0), mid + p(4.0), bw, p(34.0)),
                    "Reconnect",
                    Style::Primary,
                    Hit::Reconnect(id),
                );
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(area.x + area.w / 2 + p(4.0), mid + p(4.0), bw, p(34.0)),
                    "Close tab",
                    Style::Secondary,
                    Hit::CloseTab(id),
                );
            }
        }
    }

    fn paint_drawer(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, d: Rect, id: u64) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(d, BG_SIDEBAR);
        let old = cv.set_clip(d);
        let Some(tab) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (clip_on, fit_on, drives) = (tab.clipboard, tab.fit, tab.drives.clone());
        let scale = tab.scale;
        let (printers_on, cards_on, sound_on) = (tab.printers, tab.smart_cards, tab.sound);
        let x = d.x + p(18.0);
        let w = d.w - p(36.0);
        let mut y = d.y + p(16.0);

        let section = |cv: &mut Canvas, te: &mut TextEngine, y: i32, text: &str| {
            te.draw_in(
                cv,
                f.semi,
                11.5 * s,
                Rect::new(x, y, w, p(18.0)),
                0.0,
                text,
                TEXT_3,
            );
        };
        section(cv, te, y, "SHARING");
        y += p(28.0);
        self.switch_row(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(30.0)),
            "Clipboard",
            "Text, both directions",
            clip_on,
            Hit::Clipboard(id),
        );
        y += p(48.0);
        self.switch_row(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(30.0)),
            "Sound",
            "Remote audio on this PC",
            sound_on,
            Hit::Sound(id),
        );
        y += p(48.0);
        self.switch_row(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(30.0)),
            "Printers",
            "Local printers in the session",
            printers_on,
            Hit::Printers(id),
        );
        y += p(48.0);
        self.switch_row(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(30.0)),
            "Smart cards",
            "Local readers and cards",
            cards_on,
            Hit::SmartCards(id),
        );
        y += p(48.0);

        te.draw_in(
            cv,
            f.ui,
            13.0 * s,
            Rect::new(x, y, w, p(20.0)),
            0.0,
            "Shared folders",
            TEXT,
        );
        y += p(24.0);
        if drives.is_empty() {
            te.draw_in(
                cv,
                f.ui,
                12.0 * s,
                Rect::new(x, y, w, p(18.0)),
                0.0,
                "None. They appear in the remote Explorer.",
                TEXT_4,
            );
            y += p(24.0);
        }
        for (i, drv) in drives.iter().enumerate() {
            let r = Rect::new(x, y, w, p(40.0));
            cv.round_border(r, 6.0 * s, BORDER_SOFT, BG_BAR);
            let close = Rect::new(r.right() - p(30.0), r.y + p(10.0), p(20.0), p(20.0));
            te.draw(
                cv,
                f.semi,
                12.5 * s,
                (r.x + p(10.0)) as f32,
                (r.y + p(17.0)) as f32,
                &drv.name,
                TEXT,
                (close.x - r.x - p(14.0)) as f32,
            );
            te.draw(
                cv,
                f.ui,
                11.5 * s,
                (r.x + p(10.0)) as f32,
                (r.y + p(32.0)) as f32,
                &drv.path,
                TEXT_3,
                (close.x - r.x - p(14.0)) as f32,
            );
            let hit = Hit::RemoveDrive(id, i);
            if self.hover == Some(hit) {
                cv.fill_round(close, 4.0 * s, CONTROL_HOVER);
            }
            let (cx, cy, dd) = (
                (close.x + close.w / 2) as f32,
                (close.y + close.h / 2) as f32,
                4.0 * s,
            );
            cv.stroke(&[(cx - dd, cy - dd), (cx + dd, cy + dd)], 1.4 * s, TEXT_2);
            cv.stroke(&[(cx - dd, cy + dd), (cx + dd, cy - dd)], 1.4 * s, TEXT_2);
            self.hits.push((close, hit));
            y += p(46.0);
        }
        let add_w = p(56.0);
        self.text_input(
            cv,
            te,
            f,
            Rect::new(x, y, w - add_w - p(6.0), p(30.0)),
            Field::DrivePath,
            r"Folder, e.g. C:\Share",
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(x + w - add_w, y, add_w, p(30.0)),
            "Add",
            Style::Secondary,
            Hit::AddDrive(id),
        );
        y += p(52.0);

        section(cv, te, y, "DISPLAY");
        y += p(28.0);
        self.switch_row(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(30.0)),
            "Fit to window",
            "Remote resizes with the tab",
            fit_on,
            Hit::Fit(id),
        );
        y += p(52.0);
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            x as f32,
            (y + p(13.0)) as f32,
            "Scale",
            TEXT,
            w as f32,
        );
        let auto = format!("Auto ({} %)", (self.scale * 100.0).round() as u32);
        let choices: Vec<String> = std::iter::once(auto)
            .chain(SCALES.iter().map(|v| format!("{v} %")))
            .collect();
        let mut cx = x;
        let mut cy = y + p(24.0);
        for (i, text) in choices.iter().enumerate() {
            let cw = te.measure(f.ui, 12.0 * s, text) as i32 + p(18.0);
            if cx + cw > x + w {
                cx = x;
                cy += p(32.0);
            }
            let r = Rect::new(cx, cy, cw, p(26.0));
            let hit = Hit::Scale(id, i);
            let chosen = match (i, scale) {
                (0, None) => true,
                (0, Some(_)) => false,
                (i, Some(v)) => SCALES[i - 1] == v,
                _ => false,
            };
            let (border, fill, color) = if chosen {
                (ACCENT_BORDER, BG_CHOSEN, TEXT)
            } else if self.hover == Some(hit) {
                (BORDER_HOVER, CONTROL_HOVER, TEXT_2)
            } else {
                (BORDER, BG_SIDEBAR, TEXT_3)
            };
            cv.round_border(r, 6.0 * s, border, fill);
            centered(cv, te, f.ui, 12.0 * s, r, text, color);
            self.hits.push((r, hit));
            cx += cw + p(6.0);
        }
        y = cy + p(48.0);

        section(cv, te, y, "SESSION");
        y += p(28.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(32.0)),
            "Send Ctrl+Alt+Del",
            Style::Secondary,
            Hit::CtrlAltDel(id),
        );
        y += p(46.0);
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            x as f32,
            (y + p(4.0)) as f32,
            "Changes apply live, without reconnecting.",
            TEXT_4,
            w as f32,
        );
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            x as f32,
            (y + p(22.0)) as f32,
            "Ctrl+Alt+Home gives the keyboard back.",
            TEXT_4,
            w as f32,
        );
        cv.set_clip(old);
    }

    #[allow(clippy::too_many_arguments)]
    fn switch_row(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        sub: &str,
        on: bool,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.hover == Some(hit) {
            cv.fill_round(
                Rect::new(r.x - p(8.0), r.y - p(4.0), r.w + p(16.0), r.h + p(12.0)),
                6.0 * s,
                BG_HOVER,
            );
        }
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            r.x as f32,
            (r.y + p(13.0)) as f32,
            label,
            TEXT,
            (r.w - p(50.0)) as f32,
        );
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            r.x as f32,
            (r.y + p(30.0)) as f32,
            sub,
            TEXT_3,
            (r.w - p(50.0)) as f32,
        );
        let sw = Rect::new(r.right() - p(36.0), r.y + p(6.0), p(36.0), p(20.0));
        cv.fill_round(
            sw,
            sw.h as f32 / 2.0,
            if on { ACCENT } else { BORDER_HOVER },
        );
        let knob_x = if on {
            sw.right() - sw.h / 2
        } else {
            sw.x + sw.h / 2
        };
        cv.fill_circle(
            knob_x as f32,
            (sw.y + sw.h / 2) as f32,
            sw.h as f32 / 2.0 - 2.5 * s,
            if on { ACCENT_TEXT } else { TEXT_2 },
        );
        self.hits.push((
            Rect::new(r.x - p(8.0), r.y - p(4.0), r.w + p(16.0), r.h + p(12.0)),
            hit,
        ));
    }

    fn text_input(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        field: Field,
        placeholder: &str,
    ) {
        let s = self.scale;
        let hit = Hit::Field(field);
        let focused = self.focus == Some(field);
        let border = if focused {
            ACCENT_BORDER
        } else if self.hover == Some(hit) {
            BORDER_HOVER
        } else {
            BORDER
        };
        cv.round_border(r, 6.0 * s, border, BG_INPUT);
        let pad = 10.0 * s;
        let size = 13.5 * s;
        let inner = r.inset((pad - 1.0) as i32, 2);
        let tf = self.field(field).clone();
        let display = tf.display();
        if display.is_empty() && !focused {
            te.draw_in(cv, f.ui, size, r, pad, placeholder, TEXT_4);
        } else {
            let scroll = if focused {
                self.field_scroll(field, r, te, f)
            } else {
                0.0
            };
            let old = cv.set_clip(inner.intersect(cv.clip()));
            let base = r.y as f32 + (r.h as f32 + te.ascent(f.ui, size) * 0.72) / 2.0;
            let x = r.x as f32 + pad - scroll;
            if focused && tf.all {
                let tw = te.measure(f.ui, size, &display);
                cv.fill(
                    Rect::new(
                        x as i32,
                        r.y + (6.0 * s) as i32,
                        tw.ceil() as i32 + 1,
                        r.h - (12.0 * s) as i32,
                    ),
                    BG_TEXT_SELECT,
                );
            }
            if display.is_empty() {
                te.draw(
                    cv,
                    f.ui,
                    size,
                    x + (5.0 * s).round(),
                    base.round(),
                    placeholder,
                    TEXT_4,
                    f32::MAX,
                );
            } else {
                te.draw(cv, f.ui, size, x, base.round(), &display, TEXT, f32::MAX);
            }
            if focused {
                let cx = x + te.measure(
                    f.ui,
                    size,
                    &display.chars().take(tf.caret).collect::<String>(),
                );
                cv.fill(
                    Rect::new(
                        cx.round() as i32,
                        r.y + (7.0 * s) as i32,
                        (1.5 * s).max(1.0).round() as i32,
                        r.h - (14.0 * s) as i32,
                    ),
                    ACCENT,
                );
            }
            cv.set_clip(old);
        }
        self.hits.push((r, hit));
        self.field_rects.push((field, r));
    }

    #[allow(clippy::too_many_arguments)]
    fn button(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        style: Style,
        hit: Hit,
    ) {
        let s = self.scale;
        let hover = self.hover == Some(hit);
        let press = hover && self.press == Some(hit);
        let colors = match style {
            Style::Primary => {
                let fill = if press {
                    ACCENT_PRESS
                } else if hover {
                    ACCENT_HOVER
                } else {
                    ACCENT
                };
                Some((fill, fill, ACCENT_TEXT))
            }
            Style::Secondary => Some((
                if hover { BORDER_HOVER } else { BORDER },
                if press {
                    BG_PRESS
                } else if hover {
                    CONTROL_HOVER
                } else {
                    BG_INPUT
                },
                TEXT,
            )),
            Style::Ghost => {
                hover.then_some((BORDER, if press { BG_PRESS } else { BG_HOVER }, TEXT))
            }
            Style::Danger => Some((
                if hover { ERR } else { DANGER_BORDER },
                if press {
                    BG_PRESS
                } else if hover {
                    CONTROL_HOVER
                } else {
                    BG
                },
                ERR,
            )),
        };
        let color = match colors {
            Some((border, fill, color)) => {
                cv.round_border(r, 6.0 * s, border, fill);
                color
            }
            None => TEXT_2, // ghost at rest: label only
        };
        let font = if matches!(style, Style::Primary) {
            f.semi
        } else {
            f.ui
        };
        centered(cv, te, font, 13.0 * s, r, label, color);
        self.hits.push((r, hit));
    }
}

/// Draws `text` centred in `r` without a width cap (labels are sized to fit),
/// so glyph rounding can never turn a short label into an ellipsis.
fn centered(
    cv: &mut Canvas,
    te: &mut TextEngine,
    font: FontId,
    size: f32,
    r: Rect,
    text: &str,
    color: u32,
) {
    let tw = te.measure(font, size, text);
    let x = r.x as f32 + ((r.w as f32 - tw) / 2.0).max(0.0);
    let base = r.y as f32 + (r.h as f32 + te.ascent(font, size) * 0.72) / 2.0;
    te.draw(
        cv,
        font,
        size,
        x.round(),
        base.round(),
        text,
        color,
        (r.right() as f32 - x).max(0.0),
    );
}

#[derive(Clone, Copy)]
enum Style {
    Primary,
    Secondary,
    Ghost,
    Danger,
}

fn size_index(w: u16, h: u16) -> usize {
    SIZES.iter().position(|&s| s == (w, h)).map_or(0, |i| i + 1)
}

/// The Connect action for a resolved connection.
fn session_action(r: &Connection, password: &str) -> Action {
    let mut cfg = rdp::Config::new(&r.host, &r.user, password);
    cfg.port = r.port;
    let fit = r.width == 0;
    if !fit {
        cfg.width = r.width;
        cfg.height = r.height;
    }
    Action::Connect {
        name: r.name.clone(),
        cfg: Box::new(cfg),
        fit,
        opts: r.options.clone(),
    }
}

/// The sample with the "Work" group open (snapshot of the group form).
pub fn sample_group() -> Ui {
    let mut m = sample(false);
    if let Some(i) = m.store.group_index("Work") {
        m.select_group(i);
    }
    m
}

/// Sample data for `--snapshot-ui`; never the user's saved connections.
pub fn sample(session_tab: bool) -> Ui {
    let mut store = Store::memory(vec![
        Connection {
            name: "Office workstation".into(),
            host: "10.0.0.15".into(),
            port: 3389,
            user: r"CORP\alex".into(),
            width: 0,
            height: 0,
            options: SessionOptions::default(),
            password: None,
            group: "Work".into(),
            inherit: Inherit::ALL,
        },
        Connection {
            name: "Build server".into(),
            host: "build-01.lab.local".into(),
            port: 3389,
            user: r"LAB\builder".into(),
            width: 1920,
            height: 1080,
            options: SessionOptions::default(),
            password: None,
            group: "Work/Lab".into(),
            inherit: Inherit {
                credentials: true,
                ..Default::default()
            },
        },
        Connection {
            name: "Test VM (Windows 11)".into(),
            host: "192.168.56.20".into(),
            port: 3390,
            user: "tester".into(),
            width: 1600,
            height: 900,
            options: SessionOptions::default(),
            password: None,
            group: String::new(),
            inherit: Inherit::default(),
        },
    ]);
    store.adopt_groups();
    if let Some(i) = store.group_index("Work") {
        let g = &mut store.groups[i];
        g.user = r"CORP\alex".into();
        g.options.clipboard = true;
        g.options.sound = true;
        g.options.scale = Some(125);
    }
    if let Some(i) = store.group_index("Work/Lab") {
        store.groups[i].inherit = Inherit::ALL;
    }
    let mut m = Ui::new(store, 1.0);
    m.open_tab(1, "Office workstation".into(), "10.0.0.15".into(), true);
    m.tabs[0].state = TabState::Connected {
        width: 1280,
        height: 720,
        bpp: 32,
    };
    m.tabs[0].clipboard = true;
    m.tabs[0].drives.push(SharedDrive {
        device_id: 1,
        name: "Share".into(),
        path: r"D:\Share".into(),
    });
    m.open_tab(2, "Build server".into(), "build-01.lab.local".into(), false);
    m.tabs[1].state = TabState::Failed(
        "authentication failed: server error 0xc000006d STATUS_LOGON_FAILURE".into(),
    );
    m.active = if session_tab { Some(1) } else { None };
    m.set_message("Connected to 10.0.0.15.", TEXT_2);
    m
}
