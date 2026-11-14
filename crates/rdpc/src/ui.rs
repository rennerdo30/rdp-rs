//! The main window: saved connections on the left, a tab strip with a
//! Connections tab (edit form) and one tab per session, a session toolbar, a
//! control drawer for live session settings and a status bar.
//!
//! Painting is immediate: every paint lays out the whole window and records
//! hit rectangles. The session picture itself is not painted here: `paint`
//! reports the session area and the app copies the remote framebuffer into
//! it, so session updates never repaint the chrome.

use ffwd_render::{Canvas, FontId, Rect, TextEngine};

use crate::store::{
    AppEntry, COMPRESSION, Connection, Group, Inherit, Opens, PRESETS, Quality, SessionOptions,
    Store, WinKeys, default_app_name, normalize_path, parent_of, preset_name,
};
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

/// Placeholder of a password field whose password is saved: drawn as dots.
const SAVED_MASK: &str =
    "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Colour depths offered in the form.
const DEPTHS: [u16; 4] = [32, 24, 16, 15];
/// Sub-label of the "Touch and pen" switch.
const TOUCH_HINT: &str = "Off: they act as the mouse";

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
    /// RD Gateway host[:port].
    Gateway,
    /// Settings: new master password (current one in Master, confirmation
    /// in MasterConfirm), and the password of a backup to import.
    NewMaster,
    ImportPass,
    /// Apps card: a new app's program, name, arguments and working folder.
    AppProgram,
    AppName,
    AppArgs,
    AppDir,
}

/// Fields cleared for a new connection or group.
const FORM: [Field; 11] = [
    Field::Name,
    Field::Host,
    Field::Port,
    Field::User,
    Field::Password,
    Field::GroupPath,
    Field::Gateway,
    Field::AppProgram,
    Field::AppName,
    Field::AppArgs,
    Field::AppDir,
];

/// One sidebar row: a group, a connection, or one of an Apps connection's
/// apps (connection, app), with its tree depth.
#[derive(Clone, Copy)]
enum Row {
    Group(usize, usize),
    Conn(usize, usize),
    App(usize, usize, usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hit {
    Row(usize),
    /// Sidebar group row (opens the group form) and its expand arrow.
    GroupRow(usize),
    GroupToggle(usize),
    NewGroup,
    /// Status bar: install the offered update.
    Update,
    /// New connection inside the open group.
    NewInGroup,
    /// Connection/group form: inherit switch (credentials, display, sharing).
    FormInherit(u8),
    /// Connection editor page (General, Display, Experience, Sharing, Advanced).
    FormPage(u8),
    /// Sign in with Windows (Kerberos) on or off.
    FormKerberos,
    /// Settings page and its controls.
    OpenSettings,
    AutoLock(usize),
    RememberKey,
    ChangeMasterOpen,
    ChangeMasterOk,
    ChangeMasterCancel,
    Export,
    Import,
    ImportOk,
    ImportCancel,
    CheckUpdates,
    SetupVault,
    DiagnosticLog,
    OpenLogFolder,
    /// Settings: update channel (index into CHANNELS) and Check now.
    UpdateChannel(usize),
    CheckNow,
    /// Monitor map in the editor: toggle a monitor (index into `local_monitors`).
    FormMonitor(usize),
    /// Microphone device: index into `mics` + 1 (0 = default); form and panel.
    FormMic(usize),
    TabMic(u64, usize),
    /// Microphone on/off in the panel (live).
    Microphone(u64),
    /// Quick panel: page, and the session's quality (applies on reconnect).
    DrawerPage(u8),
    TabPreset(u64, usize),
    TabDepth(u64, usize),
    TabExperience(u64, u8),
    /// Graphics: 0 bitmaps, 1 GFX (panel and form).
    TabGraphics(u64, usize),
    FormGraphics(usize),
    /// Compression: index into COMPRESSION (panel and form).
    TabCompression(u64, usize),
    FormCompression(usize),
    /// Enter or leave full screen.
    FullScreen,
    /// Full screen: keep the bar, or let it hide.
    PinBar,
    /// Start or stop recording the session to a video.
    Record(u64),
    /// Bring a session from its monitors back into the window.
    Unspan(u64),
    /// Quit confirmation: quit, stay, and the dimmed rest of the window.
    ExitConfirm,
    ExitCancel,
    Modal,
    /// Server certificate prompt: trust (and remember) or refuse.
    CertTrust(u64),
    CertRefuse(u64),
    /// Folder picker: connection form, or the session's panel.
    BrowseForm,
    BrowseDrive(u64),
    /// Sound output: index into `speakers` + 1 (0 = default); panel and form.
    TabSpeaker(u64, usize),
    FormSpeaker(usize),
    /// Windows key combinations: panel (live) and connection form.
    TabWinKeys(u64, usize),
    FormWinKeys(usize),
    /// Quality: speed preset (index into PRESETS), colour depth, experience toggle.
    FormPreset(usize),
    FormDepth(usize),
    FormExperience(u8),
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
    /// Editor: Opens Desktop (0) or Apps (1); remove an app; add the typed one.
    FormOpens(u8),
    FormRemoveApp(usize),
    FormAddApp,
    /// Sidebar: an app of a connection (connection, app): launches it.
    AppRow(usize, usize),
    /// RemoteApp tab: launch one of its apps; focus or close a remote window.
    TabLaunch(u64, usize),
    RailFocus(u64, u32),
    RailClose(u64, u32),
}

/// A RemoteApp session tab: the connection's apps and the open windows.
#[derive(Clone, Default, PartialEq)]
pub struct RemoteAppView {
    pub apps: Vec<AppEntry>,
    pub windows: Vec<AppWindowItem>,
    /// Programs with windows open, and launched ones still starting.
    pub running: Vec<String>,
    pub starting: Vec<String>,
}

/// One remote window in the session tab's list.
#[derive(Clone, PartialEq)]
pub struct AppWindowItem {
    pub id: u32,
    pub title: String,
    /// Small icon: width, height, straight RGBA.
    pub icon: Option<(u16, u16, Vec<u8>)>,
    pub minimized: bool,
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
    /// Quality chosen in the panel, and the one the session logged on with.
    pub quality: Quality,
    pub quality_live: Quality,
    /// The server certificate waits for the user's decision.
    pub cert: Option<CertPrompt>,
    /// Where Windows key combinations go (changeable live).
    pub win_keys: WinKeys,
    /// The output device its sound plays on (None: default).
    pub speaker: Option<String>,
    /// Microphone on, and the device it records from (None: default).
    pub microphone: bool,
    pub mic: Option<String>,
    /// The session's picture is being recorded to a video file.
    pub recording: bool,
    /// Shown on chosen monitors in their own windows, not in this tab.
    pub spanned: bool,
    /// A RemoteApp session: apps in their own windows, no desktop picture.
    pub remote_app: Option<RemoteAppView>,
    /// The server the session was redirected to after logon (MS-RDPBCGR
    /// 3.2.5.13), if any; `host` stays the one the user connected to.
    pub redirected_to: Option<String>,
    /// What network auto-detect measured ("RTT 12 ms · 48.0 Mbit/s").
    pub network: Option<String>,
}

/// A server certificate to trust or refuse.
#[derive(Clone, Debug)]
pub struct CertPrompt {
    /// "AB:CD:…" (SHA-256).
    pub fingerprint: String,
    /// A different certificate was trusted for this server before.
    pub changed: bool,
    /// The server it belongs to: the RDP host, or the gateway.
    pub host: String,
}

/// The tab values the panel paints (copied out to paint without borrowing).
struct TabView {
    clipboard: bool,
    sound: bool,
    printers: bool,
    smart_cards: bool,
    fit: bool,
    scale: Option<u32>,
    drives: Vec<SharedDrive>,
    quality: Quality,
    quality_live: Quality,
    state: TabState,
    host: String,
    win_keys: WinKeys,
    speaker: Option<String>,
    microphone: bool,
    mic: Option<String>,
    redirected_to: Option<String>,
    network: Option<String>,
}

pub enum Action {
    /// `fit`: size the desktop to the tab (the app fills in the size) and follow resizes.
    /// With `cfg.remote_app` set, a RemoteApp session; `apps` are the
    /// connection's apps (for names and the session tab).
    Connect {
        name: String,
        cfg: Box<rdp::Config>,
        fit: bool,
        opts: SessionOptions,
        apps: Vec<AppEntry>,
    },
    /// Start an app in a RemoteApp session that is up or connecting.
    ExecApp(u64, AppEntry),
    /// A remote window: bring it to the front, or ask it to close.
    RailFocus(u64, u32),
    RailClose(u64, u32),
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
    /// Download, verify and start the setup of the offered update.
    InstallUpdate,
    /// A session's quality for its next logon.
    SetQuality(u64, Quality),
    SetFullscreen(bool),
    /// Quit now (confirmed).
    Quit,
    /// The session area changed size (fit may resize the remote desktop).
    Relayout,
    /// Start or stop recording a session.
    ToggleRecording(u64),
    /// Bring a session from its monitors back into the window.
    Unspan(u64),
    /// Settings.
    SetAutoLock(u32),
    SetCheckUpdates(bool),
    SetDiagnosticLog(bool),
    OpenLogFolder,
    SetUpdateChannel(String),
    CheckUpdatesNow,
    SetRemember(bool),
    ChangeMaster {
        current: zeroize::Zeroizing<String>,
        new: zeroize::Zeroizing<String>,
    },
    Export,
    PickImport,
    Import {
        path: std::path::PathBuf,
        password: zeroize::Zeroizing<String>,
    },
    /// The user's answer about a server certificate.
    CertAnswer(u64, bool),
    /// Open the folder picker; None: for the connection form.
    Browse(Option<u64>),
    /// Sound of a session to this output (None: default).
    SetSpeaker(u64, Option<String>),
    /// A session's microphone on or off, and its device (None: default).
    SetMicrophone(u64, bool),
    SetMic(u64, Option<String>),
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
    /// The edited connection or group signs in with Windows (Kerberos).
    kerberos: bool,
    /// Collapsed group paths in the sidebar.
    collapsed: std::collections::HashSet<String>,
    /// Session settings of the connection being edited.
    opts: SessionOptions,
    /// What the edited connection opens, and its apps.
    opens: Opens,
    apps: Vec<AppEntry>,
    /// The edited connection keeps (or gets) a saved password.
    save_password: bool,
    /// Showing the "set a master password" panel.
    vault_setup: bool,
    remember: bool,
    /// Key derivation running.
    pub unlocking: bool,
    vault_error: Option<String>,
    fields: [TextField; 18],
    size: usize,
    focus: Option<Field>,
    pub tabs: Vec<Tab>,
    /// None: the Connections tab.
    pub active: Option<u64>,
    pub drawer: bool,
    /// Quick panel page (0 Sharing, 1 Display, 2 Quality, 3 Session) and scrolling.
    drawer_page: u8,
    drawer_scroll: i32,
    drawer_content: i32,
    drawer_area: Rect,
    /// The window is full screen (the app sets it): only the session and its bar.
    pub fullscreen: bool,
    /// Full screen: the bar stays (pinned), or hides and shows when the
    /// pointer touches the top edge.
    pub bar_pinned: bool,
    bar_revealed: bool,
    /// The part of the session area the picture may be drawn in (chrome
    /// such as the revealed full-screen bar covers the rest).
    pub session_clip: Option<Rect>,
    /// Local sound output devices (the app fills it in).
    pub speakers: Vec<String>,
    /// Local microphones (the app fills it in).
    pub mics: Vec<String>,
    /// This PC's monitors (the app fills it in).
    pub local_monitors: Vec<crate::monitors::LocalMonitor>,
    /// Connection editor page.
    form_page: u8,
    /// The Settings page is open (instead of the editor).
    pub settings_open: bool,
    /// Settings state the app fills in.
    pub auto_lock: u32,
    pub check_updates: bool,
    pub remembered: bool,
    pub diagnostic_log: bool,
    pub update_channel: String,
    /// Settings: the change-master form is open; a backup waits for its password.
    change_master: bool,
    pub import_file: Option<std::path::PathBuf>,
    pub settings_note: Option<(String, u32)>,
    /// Asking whether to quit while this many sessions are open.
    pub confirm_exit: Option<usize>,
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
    /// Version of a newer release, if the update check found one.
    pub update: Option<String>,
    /// The update is downloading or its setup is starting.
    pub update_busy: bool,
    /// Asked once to confirm an update that closes open sessions.
    update_confirm: bool,
    /// Connection form scrolling: offset, content height, visible area.
    home_scroll: i32,
    home_content: i32,
    home_area: Rect,
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
            kerberos: false,
            collapsed: Default::default(),
            opts: SessionOptions::default(),
            opens: Opens::Desktop,
            apps: Vec::new(),
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
            drawer_page: 0,
            drawer_scroll: 0,
            drawer_content: 0,
            drawer_area: Rect::default(),
            fullscreen: false,
            bar_pinned: false,
            bar_revealed: false,
            session_clip: None,
            speakers: Vec::new(),
            mics: Vec::new(),
            local_monitors: Vec::new(),
            form_page: 0,
            settings_open: false,
            auto_lock: 15,
            check_updates: true,
            remembered: false,
            diagnostic_log: false,
            update_channel: "auto".into(),
            change_master: false,
            import_file: None,
            settings_note: None,
            confirm_exit: None,
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
            update: None,
            update_busy: false,
            update_confirm: false,
            home_scroll: 0,
            home_content: 0,
            home_area: Rect::default(),
        };
        m.fields[Field::Password as usize] = TextField::secret();
        m.fields[Field::Master as usize] = TextField::secret();
        m.fields[Field::MasterConfirm as usize] = TextField::secret();
        m.fields[Field::NewMaster as usize] = TextField::secret();
        m.fields[Field::ImportPass as usize] = TextField::secret();
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
        let (mut aw, ah) = if self.fullscreen && !self.bar_pinned {
            (w, h)
        } else if self.fullscreen {
            (w, h - p(40.0))
        } else {
            let side_w = p(260.0).min(w / 3);
            (w - side_w - 1, h - p(28.0) - p(38.0) - p(40.0))
        };
        if self.drawer {
            aw -= p(320.0).min(aw / 2) + 1;
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
            quality: Quality::default(),
            quality_live: Quality::default(),
            cert: None,
            win_keys: WinKeys::default(),
            speaker: None,
            microphone: false,
            mic: None,
            recording: false,
            spanned: false,
            remote_app: None,
            redirected_to: None,
            network: None,
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
        self.field_mut(Field::Gateway).set(&c.gateway);
        self.kerberos = c.kerberos;
        self.size = size_index(c.width, c.height);
        self.opts = c.options.clone();
        self.opens = c.opens;
        self.apps = c.apps.clone();
        for f in [
            Field::AppProgram,
            Field::AppName,
            Field::AppArgs,
            Field::AppDir,
        ] {
            self.field_mut(f).set("");
        }
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
        self.field_mut(Field::Gateway).set(&g.gateway);
        self.kerberos = g.kerberos;
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
        self.opens = Opens::Desktop;
        self.apps.clear();
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
        // Windows sign-in may use the logged-on user (single sign-on).
        if user.is_empty() && !inherit.credentials && !self.kerberos {
            return Err("Enter a user name.".into());
        }
        let name = match self.field(Field::Name).text.trim() {
            "" => host.clone(),
            n => n.to_string(),
        };
        if self.opens == Opens::Apps && self.apps.is_empty() {
            return Err(
                "Add at least one app below (type its program and press Add), or choose Desktop."
                    .into(),
            );
        }
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
            gateway: self.field(Field::Gateway).text.trim().to_string(),
            kerberos: self.kerberos,
            inherit,
            opens: self.opens,
            apps: self.apps.clone(),
        })
    }

    /// Adds the app typed in the Apps card; the reason in plain words when
    /// it cannot be added.
    fn form_add_app(&mut self) -> Result<(), String> {
        let text = |f: Field| self.field(f).text.trim().to_string();
        let program = text(Field::AppProgram).trim_matches('"').to_string();
        let (args, dir, typed_name) = (
            text(Field::AppArgs),
            text(Field::AppDir),
            text(Field::AppName),
        );
        if program.is_empty() {
            self.focus = Some(Field::AppProgram);
            return Err(
                r"Type the program first: a published name like ||Excel, or a path like C:\Tools\app.exe."
                    .into(),
            );
        }
        // Client Execute PDU limits (MS-RDPERP 2.2.2.3.1), in UTF-16 units.
        let units = |s: &str| s.encode_utf16().count();
        if units(&program) > 260 {
            return Err("The program is too long: 260 characters at most.".into());
        }
        if units(&dir) > 260 {
            return Err("The working folder is too long: 260 characters at most.".into());
        }
        if units(&args) > 8000 {
            return Err("The arguments are too long: 8,000 characters at most.".into());
        }
        let name = match typed_name {
            n if n.is_empty() => default_app_name(&program),
            n => n,
        };
        if name.is_empty() {
            return Err("Give the app a name.".into());
        }
        if self.apps.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
            self.focus = Some(Field::AppName);
            return Err(format!(
                "There is already an app called {name}; give this one another name."
            ));
        }
        self.apps.push(AppEntry {
            name,
            program,
            args,
            working_dir: dir,
        });
        for f in [
            Field::AppProgram,
            Field::AppName,
            Field::AppArgs,
            Field::AppDir,
        ] {
            self.field_mut(f).set("");
        }
        self.focus = Some(Field::AppProgram);
        Ok(())
    }

    fn add_app_clicked(&mut self) {
        match self.form_add_app() {
            Ok(()) => {
                let n = self.apps.last().map(|a| a.name.clone()).unwrap_or_default();
                self.set_message(format!("Added {n}. Save keeps it."), TEXT_2);
            }
            Err(e) => self.set_message(e, ERR),
        }
    }

    /// The tabs as the launcher sees them.
    fn launch_target(&self, name: &str, host: &str) -> Option<u64> {
        crate::remoteapp::launch_target(
            self.tabs.iter().map(|t| crate::remoteapp::Candidate {
                id: t.id,
                name: &t.name,
                host: &t.host,
                remote_app: t.remote_app.is_some(),
                connected: matches!(t.state, TabState::Connected { .. }),
                connecting: t.state == TabState::Connecting,
            }),
            name,
            host,
        )
    }

    /// A click on an app in the sidebar: start it in the running session
    /// of its connection, or connect one for it.
    fn launch_app(&mut self, ci: usize, ai: usize) -> Option<Action> {
        let c = self.store.connections.get(ci)?.clone();
        let app = c.apps.get(ai)?.clone();
        if let Some(id) = self.launch_target(&c.name, &c.host) {
            self.set_message(format!("Starting {}…", app.name), TEXT_2);
            return Some(Action::ExecApp(id, app));
        }
        let r = self.store.resolve(&c);
        // A password typed into this connection's open form counts too.
        let typed = (self.selected == Some(ci) && self.group_edit.is_none())
            .then(|| self.field(Field::Password).text.clone())
            .filter(|t| !t.is_empty());
        let password = typed.or_else(|| r.password.clone());
        if (r.user.is_empty() || password.is_none()) && !r.kerberos {
            self.select(ci);
            self.active = None;
            self.settings_open = false;
            self.form_page = 0;
            self.focus = Some(if r.user.is_empty() {
                Field::User
            } else {
                Field::Password
            });
            self.set_message(
                format!(
                    "Type the {} for {}, then click {} again.",
                    if r.user.is_empty() {
                        "user name"
                    } else {
                        "password"
                    },
                    c.name,
                    app.name
                ),
                WARN,
            );
            return None;
        }
        self.set_message(
            format!("Connecting to {} for {}…", r.host, app.name),
            TEXT_2,
        );
        Some(session_action(
            &r,
            &password.unwrap_or_default(),
            Some(&app),
        ))
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
            gateway: self.field(Field::Gateway).text.trim().to_string(),
            kerberos: self.kerberos,
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
        // Apps: Connect starts the first app (in a running session if any).
        let first = r.apps.first().filter(|_| r.opens == Opens::Apps).cloned();
        if let Some(app) = &first
            && let Some(id) = self.launch_target(&r.name, &r.host)
        {
            self.set_message(format!("Starting {}…", app.name), TEXT_2);
            return Some(Action::ExecApp(id, app.clone()));
        }
        if r.user.is_empty() && !r.kerberos {
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
        Some(session_action(&r, &password, first.as_ref()))
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
                Some(pw) if !r.user.is_empty() => {
                    let first = r.apps.first().filter(|_| r.opens == Opens::Apps);
                    acts.push(session_action(&r, &pw, first))
                }
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
            let mut out = Vec::new();
            for (i, c) in self.store.connections.iter().enumerate() {
                let hit = [&c.name, &c.host, &c.user, &c.group]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&q))
                    || c.apps.iter().any(|a| a.name.to_lowercase().contains(&q));
                if hit {
                    self.push_conn(i, 0, &mut out);
                }
            }
            return out;
        }
        let mut out = Vec::new();
        self.tree_rows("", 0, &mut out);
        out
    }

    /// A connection's row, and its apps' rows under it for an Apps connection.
    fn push_conn(&self, i: usize, depth: usize, out: &mut Vec<Row>) {
        out.push(Row::Conn(i, depth));
        let c = &self.store.connections[i];
        if c.opens == Opens::Apps {
            out.extend((0..c.apps.len()).map(|a| Row::App(i, a, depth)));
        }
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
                self.push_conn(i, depth, out);
            }
        }
    }

    /// Connections in sidebar order (keyboard Up/Down).
    fn visible(&self) -> Vec<usize> {
        self.rows()
            .into_iter()
            .filter_map(|r| match r {
                Row::Conn(i, _) => Some(i),
                Row::Group(..) | Row::App(..) => None,
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
                let mut t = if g.password.is_some() {
                    format!("{user} · password saved")
                } else {
                    user.to_string()
                };
                if !g.gateway.is_empty() {
                    t += &format!(" · via {}", g.gateway);
                }
                t
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
                let q = g.options.quality;
                format!(
                    "{size} · {scale} · {} · {}-bit",
                    preset_name(q.connection),
                    q.color_depth
                )
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
        // The vault panels replace the form: only their own fields.
        if self.store.is_locked() {
            return vec![Field::Master];
        }
        if self.vault_setup {
            return vec![Field::Master, Field::MasterConfirm];
        }
        match self.form_page {
            0 => {}
            3 if !self.form_inherit().sharing => return vec![Field::FormDrive],
            _ => return Vec::new(),
        }
        let mut v = vec![Field::Name];
        if self.group_edit.is_none() {
            v.extend([Field::Host, Field::Port]);
        }
        v.push(Field::GroupPath);
        if self.group_edit.is_none() && self.opens == Opens::Apps {
            v.extend([
                Field::AppProgram,
                Field::AppName,
                Field::AppArgs,
                Field::AppDir,
            ]);
        }
        let own = !self.form_inherit().credentials;
        if own {
            v.push(Field::User);
        }
        v.push(Field::Password);
        if own {
            v.push(Field::Gateway);
        }
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
        // Full screen with a hiding bar: the top edge shows it, leaving hides it.
        if self.fullscreen && !self.bar_pinned && self.active.is_some() {
            let bar = (40.0 * self.scale) as i32;
            let want = if self.bar_revealed {
                y >= 0 && y < bar + (12.0 * self.scale) as i32
            } else {
                (0..=2).contains(&y)
            };
            if want != self.bar_revealed {
                self.bar_revealed = want;
                self.hover = self.hit_at(x, y);
                return true;
            }
        }
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
                self.settings_open = false;
            }
            Hit::GroupRow(gi) => {
                self.select_group(gi);
                self.active = None;
                self.settings_open = false;
            }
            Hit::GroupToggle(gi) => {
                if let Some(g) = self.store.groups.get(gi) {
                    let path = g.path.clone();
                    if !self.collapsed.remove(&path) {
                        self.collapsed.insert(path);
                    }
                }
            }
            Hit::Update => {
                if self.update_busy || self.update.is_none() {
                    return None;
                }
                let open = self
                    .tabs
                    .iter()
                    .filter(|t| {
                        matches!(t.state, TabState::Connected { .. } | TabState::Connecting)
                    })
                    .count();
                if open > 0 && !self.update_confirm {
                    self.update_confirm = true;
                    self.set_message(
                        format!(
                            "Installing restarts rdpc and closes {open} open session{}. Click Update again to go ahead.",
                            if open == 1 { "" } else { "s" }
                        ),
                        WARN,
                    );
                    return None;
                }
                return Some(Action::InstallUpdate);
            }
            Hit::NewGroup => {
                self.new_group();
                self.active = None;
                self.settings_open = false;
            }
            Hit::NewInGroup => {
                let g = self.context_group();
                self.new_connection_in(&g);
            }
            Hit::OpenSettings => {
                self.settings_open = true;
                self.active = None;
                self.home_scroll = 0;
                self.focus = None;
            }
            Hit::AutoLock(i) => return Some(Action::SetAutoLock(crate::settings::AUTO_LOCK[i])),
            Hit::CheckUpdates => return Some(Action::SetCheckUpdates(!self.check_updates)),
            Hit::DiagnosticLog => return Some(Action::SetDiagnosticLog(!self.diagnostic_log)),
            Hit::UpdateChannel(i) => {
                return Some(Action::SetUpdateChannel(
                    crate::settings::CHANNELS[i].0.to_string(),
                ));
            }
            Hit::CheckNow => return Some(Action::CheckUpdatesNow),
            Hit::OpenLogFolder => return Some(Action::OpenLogFolder),
            Hit::RememberKey => return Some(Action::SetRemember(!self.remembered)),
            Hit::ChangeMasterOpen => {
                self.change_master = true;
                self.settings_note = None;
                for f in [Field::Master, Field::NewMaster, Field::MasterConfirm] {
                    self.field_mut(f).set("");
                }
                self.focus = Some(Field::Master);
            }
            Hit::ChangeMasterCancel => {
                self.change_master = false;
                for f in [Field::Master, Field::NewMaster, Field::MasterConfirm] {
                    self.field_mut(f).set("");
                }
            }
            Hit::ChangeMasterOk => return self.change_master_action(),
            Hit::Export => return Some(Action::Export),
            Hit::Import => return Some(Action::PickImport),
            Hit::ImportOk => return self.import_action(),
            Hit::ImportCancel => {
                self.import_file = None;
                self.field_mut(Field::ImportPass).set("");
            }
            Hit::SetupVault => {
                self.vault_setup = true;
                self.vault_error = None;
                self.focus = Some(Field::Master);
            }
            Hit::FormKerberos => self.kerberos = !self.kerberos,
            Hit::FormPage(i) => {
                self.form_page = i;
                self.home_scroll = 0;
                self.focus = None;
            }
            Hit::FormMonitor(i) => {
                if let Some(m) = self.local_monitors.get(i) {
                    let name = m.name.clone();
                    let list = &mut self.opts.monitors;
                    if let Some(at) = list.iter().position(|n| *n == name) {
                        list.remove(at);
                    } else {
                        list.push(name);
                    }
                }
            }
            Hit::FormMic(i) => {
                self.opts.mic = i.checked_sub(1).and_then(|i| self.mics.get(i).cloned());
            }
            Hit::TabMic(id, i) => {
                let name = i.checked_sub(1).and_then(|i| self.mics.get(i).cloned());
                let t = self.tab_mut(id)?;
                t.mic = name.clone();
                return Some(Action::SetMic(id, name));
            }
            Hit::Microphone(id) => {
                let t = self.tab_mut(id)?;
                t.microphone = !t.microphone;
                return Some(Action::SetMicrophone(id, t.microphone));
            }
            Hit::DrawerPage(i) => {
                self.drawer_page = i;
                self.drawer_scroll = 0;
            }
            Hit::FullScreen => return Some(Action::SetFullscreen(!self.fullscreen)),
            Hit::Record(id) => return Some(Action::ToggleRecording(id)),
            Hit::Unspan(id) => return Some(Action::Unspan(id)),
            Hit::PinBar => {
                self.bar_pinned = !self.bar_pinned;
                self.bar_revealed = self.bar_pinned;
                return Some(Action::Relayout);
            }
            Hit::ExitConfirm => return Some(Action::Quit),
            Hit::ExitCancel => self.confirm_exit = None,
            Hit::Modal => {}
            Hit::TabWinKeys(id, i) => {
                let t = self.tab_mut(id)?;
                t.win_keys = WinKeys::ALL[i];
            }
            Hit::FormWinKeys(i) => self.opts.win_keys = WinKeys::ALL[i],
            Hit::BrowseForm => return Some(Action::Browse(None)),
            Hit::BrowseDrive(id) => return Some(Action::Browse(Some(id))),
            Hit::TabSpeaker(id, i) => {
                let name = i.checked_sub(1).and_then(|i| self.speakers.get(i).cloned());
                let t = self.tab_mut(id)?;
                t.speaker = name.clone();
                return Some(Action::SetSpeaker(id, name));
            }
            Hit::FormSpeaker(i) => {
                self.opts.speaker = i.checked_sub(1).and_then(|i| self.speakers.get(i).cloned());
            }
            Hit::CertTrust(id) => return Some(Action::CertAnswer(id, true)),
            Hit::CertRefuse(id) => return Some(Action::CertAnswer(id, false)),
            Hit::TabPreset(id, i) => {
                let t = self.tab_mut(id)?;
                let touch = t.quality.touch;
                t.quality = Quality::preset(PRESETS[i].0, t.quality.color_depth);
                t.quality.touch = touch;
                return Some(Action::SetQuality(id, t.quality));
            }
            Hit::TabDepth(id, i) => {
                let t = self.tab_mut(id)?;
                t.quality.color_depth = DEPTHS[i];
                return Some(Action::SetQuality(id, t.quality));
            }
            Hit::TabExperience(id, i) => {
                let t = self.tab_mut(id)?;
                let q = &mut t.quality;
                let flag = match i {
                    0 => &mut q.wallpaper,
                    1 => &mut q.font_smoothing,
                    2 => &mut q.composition,
                    3 => &mut q.window_drag,
                    4 => &mut q.animations,
                    5 => &mut q.visual_styles,
                    _ => &mut q.touch,
                };
                *flag = !*flag;
                return Some(Action::SetQuality(id, t.quality));
            }
            Hit::TabCompression(id, i) => {
                let t = self.tab_mut(id)?;
                t.quality.compression = COMPRESSION[i].0;
                return Some(Action::SetQuality(id, t.quality));
            }
            Hit::FormCompression(i) => self.opts.quality.compression = COMPRESSION[i].0,
            Hit::TabGraphics(id, i) => {
                let t = self.tab_mut(id)?;
                t.quality.gfx = i == 1;
                return Some(Action::SetQuality(id, t.quality));
            }
            Hit::FormGraphics(i) => self.opts.quality.gfx = i == 1,
            Hit::FormPreset(i) => {
                let depth = self.opts.quality.color_depth;
                let touch = self.opts.quality.touch;
                self.opts.quality = Quality::preset(PRESETS[i].0, depth);
                self.opts.quality.touch = touch;
            }
            Hit::FormDepth(i) => self.opts.quality.color_depth = DEPTHS[i],
            Hit::FormExperience(i) => {
                let q = &mut self.opts.quality;
                let flag = match i {
                    0 => &mut q.wallpaper,
                    1 => &mut q.font_smoothing,
                    2 => &mut q.composition,
                    3 => &mut q.window_drag,
                    4 => &mut q.animations,
                    5 => &mut q.visual_styles,
                    _ => &mut q.touch,
                };
                *flag = !*flag;
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
                self.settings_open = false;
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
                    3 => &mut o.smart_cards,
                    _ => &mut o.microphone,
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
            Hit::FormOpens(i) => {
                self.opens = if i == 1 { Opens::Apps } else { Opens::Desktop };
                if self.opens == Opens::Apps && self.apps.is_empty() {
                    self.focus = Some(Field::AppProgram);
                }
            }
            Hit::FormRemoveApp(i) => {
                if i < self.apps.len() {
                    let gone = self.apps.remove(i);
                    self.set_message(format!("Removed {}. Save keeps it.", gone.name), TEXT_2);
                }
            }
            Hit::FormAddApp => self.add_app_clicked(),
            Hit::AppRow(ci, ai) => return self.launch_app(ci, ai),
            Hit::TabLaunch(id, i) => {
                let app = self
                    .tabs
                    .iter()
                    .find(|t| t.id == id)?
                    .remote_app
                    .as_ref()?
                    .apps
                    .get(i)?
                    .clone();
                self.set_message(format!("Starting {}…", app.name), TEXT_2);
                return Some(Action::ExecApp(id, app));
            }
            Hit::RailFocus(id, w) => return Some(Action::RailFocus(id, w)),
            Hit::RailClose(id, w) => return Some(Action::RailClose(id, w)),
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

    pub fn store_is_vault(&self) -> bool {
        self.store.is_vault()
    }

    pub fn focus_import(&mut self) {
        self.focus = Some(Field::ImportPass);
    }

    /// After an import: keep the selection valid.
    pub fn refresh_selection(&mut self) {
        if self.selected.is_none()
            && !self.store.connections.is_empty()
            && self.group_edit.is_none()
        {
            self.select(0);
        }
    }

    /// A folder chosen in the picker for the connection form.
    pub fn form_add_folder(&mut self, path: String) {
        if !self.opts.drives.contains(&path) {
            self.opts.drives.push(path);
        }
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
        if self.confirm_exit.is_some() {
            match k {
                Key::Esc => self.confirm_exit = None,
                Key::Enter => return Some(Action::Quit),
                _ => {}
            }
            return None;
        }
        match k {
            Key::Enter if self.focus == Some(Field::DrivePath) => {
                return self.active.and_then(|id| self.add_drive(id));
            }
            Key::Enter if self.focus == Some(Field::FormDrive) => self.form_add_drive(),
            Key::Enter
                if matches!(
                    self.focus,
                    Some(Field::AppProgram | Field::AppName | Field::AppArgs | Field::AppDir)
                ) =>
            {
                self.add_app_clicked()
            }
            Key::Enter if self.store.is_locked() => return self.unlock(),
            Key::Enter
                if self.settings_open && self.active.is_none() && self.import_file.is_some() =>
            {
                return self.import_action();
            }
            Key::Enter if self.settings_open && self.active.is_none() && self.change_master => {
                return self.change_master_action();
            }
            Key::Enter if self.settings_open && self.active.is_none() && !self.vault_setup => {}
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
                if n == 0 {
                    return None;
                }
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
        self.paint_window(cv, te, f);
        if let Some(n) = self.confirm_exit {
            self.paint_exit_confirm(cv, te, f, n);
        }
    }

    /// "Quit rdpc?" over the dimmed window; nothing else takes clicks.
    fn paint_exit_confirm(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, n: usize) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        let all = Rect::new(0, 0, w, h);
        // The session picture is not drawn under the dialog.
        self.session_area = None;
        cv.fill_alpha(all, 0x000000, 150);
        self.hits.clear();
        self.title_controls.clear();
        self.hits.push((all, Hit::Modal));
        let cw = p(420.0).min(w - p(32.0));
        let ch = p(170.0);
        let r = Rect::new((w - cw) / 2, (h - ch) / 2, cw, ch);
        cv.round_border(r, 10.0 * s, BORDER, BG_BAR);
        let x = r.x + p(24.0);
        let tw = (r.w - p(48.0)) as f32;
        te.draw(
            cv,
            f.semi,
            16.0 * s,
            x as f32,
            (r.y + p(40.0)) as f32,
            "Quit rdpc?",
            TEXT,
            tw,
        );
        let line = if n == 1 {
            "1 session is open and will be disconnected.".to_string()
        } else {
            format!("{n} sessions are open and will be disconnected.")
        };
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            x as f32,
            (r.y + p(68.0)) as f32,
            &line,
            TEXT_2,
            tw,
        );
        let by = r.bottom() - p(24.0) - p(34.0);
        let qw = p(150.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(r.right() - p(24.0) - qw, by, qw, p(34.0)),
            "Disconnect and quit",
            Style::Danger,
            Hit::ExitConfirm,
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(
                r.right() - p(24.0) - qw - p(8.0) - p(96.0),
                by,
                p(96.0),
                p(34.0),
            ),
            "Cancel",
            Style::Secondary,
            Hit::ExitCancel,
        );
    }

    fn paint_window(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.hits.clear();
        self.field_rects.clear();
        self.session_area = None;
        self.title_controls.clear();
        self.caption = Rect::default();
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        cv.fill(Rect::new(0, 0, w, h), BG);
        // Full screen: the session with its toolbar and panel, nothing else.
        if self.fullscreen
            && let Some(id) = self.active_tab().map(|t| t.id)
        {
            self.title_height = 0;
            self.paint_session(cv, te, f, Rect::new(0, 0, w, h), id);
            return;
        }
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
            None if self.settings_open => self.paint_settings(cv, te, f, content),
            None => self.paint_home(cv, te, f, content),
        }

        let bar = Rect::new(0, body_h, w, bar_h);
        cv.fill(bar, BG_BAR);
        cv.fill(Rect::new(0, body_h, w, 1), BORDER_SOFT);
        let right = format!("{} renderer · damage-only presents", self.renderer);
        let text_w = te.measure(f.ui, 12.0 * s, &right) as i32;
        let mut rw = text_w;
        if let Some(v) = self.update.clone() {
            let text = if self.update_busy {
                format!("Updating to {v}…")
            } else {
                format!("Update to {v}")
            };
            let bw = te.measure(f.ui, 12.0 * s, &text) as i32 + p(20.0);
            let r = Rect::new(w - rw - p(28.0) - bw, body_h + p(3.0), bw, bar_h - p(6.0));
            let hover = self.hover == Some(Hit::Update) && !self.update_busy;
            cv.round_border(
                r,
                5.0 * s,
                ACCENT_BORDER,
                if hover { CONTROL_HOVER } else { BG_CHOSEN },
            );
            centered(cv, te, f.ui, 12.0 * s, r, &text, TEXT);
            self.hits.push((r, Hit::Update));
            rw += bw + p(14.0);
        }
        te.draw_in(
            cv,
            f.ui,
            12.0 * s,
            Rect::new(w - text_w - p(14.0), body_h, text_w + p(14.0), bar_h),
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

        let foot = p(52.0);
        let sr = Rect::new(
            pad,
            area.bottom() - foot + p(10.0),
            area.w - 2 * pad,
            p(32.0),
        );
        cv.fill(Rect::new(0, area.bottom() - foot, area.w, 1), BORDER_SOFT);
        let settings_style = if self.settings_open && self.active.is_none() {
            Style::Secondary
        } else {
            Style::Ghost
        };
        self.button(cv, te, f, sr, "Settings", settings_style, Hit::OpenSettings);
        let list = Rect::new(0, p(86.0), area.w, area.h - p(86.0) - foot);
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
                Row::App(ci, ai, depth) => {
                    let indent = depth as i32 * p(16.0) + p(18.0);
                    let r = Rect::new(p(8.0) + indent, y, area.w - p(16.0) - indent, p(32.0));
                    y += r.h + p(2.0);
                    self.paint_app_row(cv, te, f, r, list, ci, ai);
                }
            }
        }
        cv.set_clip(old);
    }

    /// An app under its connection: a click launches it.
    #[allow(clippy::too_many_arguments)]
    fn paint_app_row(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        list: Rect,
        ci: usize,
        ai: usize,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let hit = Hit::AppRow(ci, ai);
        if self.hover == Some(hit) {
            cv.fill_round(r, 6.0 * s, BG_HOVER);
        }
        let c = &self.store.connections[ci];
        let (name, program) = (c.apps[ai].name.clone(), c.apps[ai].program.clone());
        let dot = self.app_dot(&c.name, &c.host, &program);
        let mid = r.y + r.h / 2;
        app_glyph(cv, s, r.x + p(14.0), mid - p(7.0), TEXT_3);
        let text_w = r.w - p(44.0) - if dot.is_some() { p(16.0) } else { 0 };
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            (r.x + p(36.0)) as f32,
            (mid + p(5.0)) as f32,
            &name,
            TEXT_2,
            text_w as f32,
        );
        if let Some(color) = dot {
            cv.fill_circle((r.right() - p(16.0)) as f32, mid as f32, 4.0 * s, color);
        }
        self.hits.push((r.intersect(list), hit));
    }

    /// Green while the app has windows open, amber while it starts.
    fn app_dot(&self, name: &str, host: &str, program: &str) -> Option<u32> {
        let same = |l: &[String]| l.iter().any(|p| crate::remoteapp::same_program(p, program));
        let mut out = None;
        for t in self
            .tabs
            .iter()
            .filter(|t| t.name == name && t.host == host)
        {
            let Some(v) = &t.remote_app else { continue };
            let live = matches!(t.state, TabState::Connected { .. } | TabState::Connecting);
            if live && same(&v.running) {
                return Some(OK);
            }
            if live && same(&v.starting) {
                out = Some(WARN);
            }
        }
        out
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

    fn change_master_action(&mut self) -> Option<Action> {
        let current = zeroize::Zeroizing::new(self.field(Field::Master).text.clone());
        let new = zeroize::Zeroizing::new(self.field(Field::NewMaster).text.clone());
        let again = zeroize::Zeroizing::new(self.field(Field::MasterConfirm).text.clone());
        if current.is_empty() {
            self.settings_note = Some(("Enter your current master password.".into(), ERR));
            return None;
        }
        if new.chars().count() < 8 {
            self.settings_note = Some(("Use at least 8 characters for the new one.".into(), ERR));
            return None;
        }
        if new != again {
            self.settings_note = Some(("The two new passwords differ.".into(), ERR));
            return None;
        }
        for f in [Field::Master, Field::NewMaster, Field::MasterConfirm] {
            self.field_mut(f).set("");
        }
        self.unlocking = true;
        self.settings_note = Some(("Changing the master password…".into(), TEXT_2));
        Some(Action::ChangeMaster { current, new })
    }

    fn import_action(&mut self) -> Option<Action> {
        let path = self.import_file.clone()?;
        let password = zeroize::Zeroizing::new(self.field(Field::ImportPass).text.clone());
        if password.is_empty() {
            self.settings_note = Some(("Enter the backup's master password.".into(), ERR));
            return None;
        }
        self.field_mut(Field::ImportPass).set("");
        self.unlocking = true;
        self.settings_note = Some(("Opening the backup…".into(), TEXT_2));
        Some(Action::Import { path, password })
    }

    /// The app reports the end of a settings job (change master, export, import).
    pub fn settings_done(&mut self, ok: bool, text: String) {
        self.unlocking = false;
        if ok {
            self.change_master = false;
            self.import_file = None;
        }
        self.settings_note = Some((text, if ok { OK } else { ERR }));
    }

    /// App settings: security, backup, updates, about.
    fn paint_settings(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        self.home_area = area;
        let top = area.y - self.home_scroll;
        let x = area.x + p(40.0);
        let w = p(620.0).min(area.w - p(80.0)).max(p(300.0));
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x as f32,
            (top + p(48.0)) as f32,
            "Settings",
            TEXT,
            w as f32,
        );
        let version = format!("rdpc {}", env!("CARGO_PKG_VERSION"));
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x as f32,
            (top + p(70.0)) as f32,
            &version,
            TEXT_3,
            w as f32,
        );
        let mut y = top + p(100.0);
        if let Some((note, color)) = self.settings_note.clone() {
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                x as f32,
                (y + p(4.0)) as f32,
                &note,
                color,
                w as f32,
            );
            y += p(24.0);
        }

        // Security
        self.caption(cv, te, f, x, y, w, "SECURITY");
        y += p(24.0);
        if self.store.is_vault() {
            let cells = self.card(cv, x, y, w, &[p(58.0), p(58.0)]);
            let remembered = self.remembered;
            self.card_switch(
                cv,
                te,
                f,
                cells[0],
                "Unlock automatically on this PC",
                "Windows keeps the key for your user account (DPAPI)",
                remembered,
                Hit::RememberKey,
            );
            self.card_action(
                cv,
                te,
                f,
                cells[1],
                "Master password",
                "Encrypts saved passwords and backups",
                "Change…",
                Hit::ChangeMasterOpen,
            );
            y += p(116.0) + p(16.0);
            if self.change_master {
                let rh = p(52.0);
                let cells = self.card(cv, x, y, w, &[rh, rh, rh, p(56.0)]);
                self.field_row(
                    cv,
                    te,
                    f,
                    cells[0],
                    "Current",
                    Field::Master,
                    "Current master password",
                );
                self.field_row(
                    cv,
                    te,
                    f,
                    cells[1],
                    "New",
                    Field::NewMaster,
                    "At least 8 characters",
                );
                self.field_row(
                    cv,
                    te,
                    f,
                    cells[2],
                    "Again",
                    Field::MasterConfirm,
                    "The new one once more",
                );
                let r = cells[3];
                let label = if self.unlocking {
                    "Working…"
                } else {
                    "Change password"
                };
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(r.x + p(16.0), r.y + p(11.0), p(150.0), p(34.0)),
                    label,
                    Style::Primary,
                    Hit::ChangeMasterOk,
                );
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(r.x + p(174.0), r.y + p(11.0), p(96.0), p(34.0)),
                    "Cancel",
                    Style::Secondary,
                    Hit::ChangeMasterCancel,
                );
                y += 3 * rh + p(56.0) + p(16.0);
            }
            self.caption(cv, te, f, x, y, w, "LOCK AUTOMATICALLY WHEN IDLE");
            y += p(24.0);
            let items: Vec<(String, bool, Hit)> = crate::settings::AUTO_LOCK
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    let t = match m {
                        0 => "Never".to_string(),
                        60 => "After 1 hour".to_string(),
                        m => format!("After {m} min"),
                    };
                    (t, self.auto_lock == *m, Hit::AutoLock(i))
                })
                .collect();
            self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
            y += p(34.0) + p(24.0);
        } else {
            let cells = self.card(cv, x, y, w, &[p(58.0)]);
            self.card_action(
                cv,
                te,
                f,
                cells[0],
                "Encrypt your connections",
                "A master password lets rdpc save passwords and back up",
                "Set up…",
                Hit::SetupVault,
            );
            y += p(58.0) + p(24.0);
        }

        // Backup
        self.caption(cv, te, f, x, y, w, "BACKUP");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &[p(58.0), p(58.0)]);
        self.card_action(
            cv,
            te,
            f,
            cells[0],
            "Export connections",
            "One encrypted file, opened with your master password",
            "Export…",
            Hit::Export,
        );
        self.card_action(
            cv,
            te,
            f,
            cells[1],
            "Import connections",
            "Adds the connections and groups of a backup",
            "Import…",
            Hit::Import,
        );
        y += p(116.0) + p(16.0);
        if let Some(path) = self.import_file.clone() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cells = self.card(cv, x, y, w, &[p(44.0), p(52.0), p(56.0)]);
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                (cells[0].x + p(16.0)) as f32,
                (cells[0].y + p(27.0)) as f32,
                &format!("Import from {name}"),
                TEXT_2,
                (w - p(32.0)) as f32,
            );
            self.field_row(
                cv,
                te,
                f,
                cells[1],
                "Password",
                Field::ImportPass,
                "Master password of the backup",
            );
            let r = cells[2];
            let label = if self.unlocking {
                "Working…"
            } else {
                "Import"
            };
            self.button(
                cv,
                te,
                f,
                Rect::new(r.x + p(16.0), r.y + p(11.0), p(120.0), p(34.0)),
                label,
                Style::Primary,
                Hit::ImportOk,
            );
            self.button(
                cv,
                te,
                f,
                Rect::new(r.x + p(144.0), r.y + p(11.0), p(96.0), p(34.0)),
                "Cancel",
                Style::Secondary,
                Hit::ImportCancel,
            );
            y += p(152.0) + p(16.0);
        }
        y += p(8.0);

        // Updates
        self.caption(cv, te, f, x, y, w, "UPDATES");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &[p(58.0), p(58.0)]);
        let check = self.check_updates;
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            "Check for updates daily",
            "Ctrl+Shift+U or the status bar installs an offered update",
            check,
            Hit::CheckUpdates,
        );
        let version = format!("Installed: rdpc {}", env!("CARGO_PKG_VERSION"));
        self.card_action(
            cv,
            te,
            f,
            cells[1],
            "Check now",
            &version,
            "Check",
            Hit::CheckNow,
        );
        y += p(116.0) + p(12.0);
        let items: Vec<(String, bool, Hit)> = crate::settings::CHANNELS
            .iter()
            .enumerate()
            .map(|(i, (key, name))| {
                (
                    name.to_string(),
                    self.update_channel == *key,
                    Hit::UpdateChannel(i),
                )
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(16.0),
            w,
            "Automatic follows the installed version: beta builds get betas, stable builds stable releases.",
        );
        y += p(24.0) + p(24.0);

        // Troubleshooting
        self.caption(cv, te, f, x, y, w, "TROUBLESHOOTING");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &[p(58.0), p(58.0)]);
        let log_on = self.diagnostic_log;
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            "Diagnostic log",
            "Protocol details to rdpc.log; never passwords",
            log_on,
            Hit::DiagnosticLog,
        );
        self.card_action(
            cv,
            te,
            f,
            cells[1],
            "Log folder",
            r"%LOCALAPPDATA%\rdp-rs\logs",
            "Open",
            Hit::OpenLogFolder,
        );
        y += p(116.0);

        self.home_content = y + p(40.0) - top;
        let max = (self.home_content - area.h).max(0);
        self.home_scroll = self.home_scroll.min(max);
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
    }

    /// A card row with a label, a second line and a button on the right.
    #[allow(clippy::too_many_arguments)]
    fn card_action(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        sub: &str,
        button: &str,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let bw = te.measure(f.ui, 13.0 * s, button) as i32 + p(32.0);
        let mid = r.y + r.h / 2;
        let tw = (r.w - bw - p(44.0)) as f32;
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            (r.x + p(16.0)) as f32,
            (mid - p(2.0)) as f32,
            label,
            TEXT,
            tw,
        );
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            (r.x + p(16.0)) as f32,
            (mid + p(14.0)) as f32,
            sub,
            TEXT_3,
            tw,
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(r.right() - p(14.0) - bw, mid - p(16.0), bw, p(32.0)),
            button,
            Style::Secondary,
            hit,
        );
    }

    /// The connection (or group) editor: a header with the actions, a section
    /// switcher and one page of cards at a time. A section a connection takes
    /// from its group shows one switch and where the values come from.
    fn paint_home(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        self.home_area = area;
        let top = area.y - self.home_scroll;
        let x = area.x + p(40.0);
        let w = p(620.0).min(area.w - p(80.0)).max(p(300.0));
        let group_mode = self.group_edit.is_some();
        let open_group = self.group_edit.clone().flatten();

        // Header: title, one line about it, and the actions on the right.
        let title = match (&open_group, self.selected) {
            (Some(path), _) => path.rsplit('/').next().unwrap_or(path).to_string(),
            (None, _) if group_mode => "New group".into(),
            (None, Some(i)) => self.store.connections[i].name.clone(),
            (None, None) => "New connection".into(),
        };
        let sub = if let Some(path) = &open_group {
            let n = self.store.members(path).count();
            format!("Group · {n} connection{}", if n == 1 { "" } else { "s" })
        } else if group_mode {
            "New group · not saved yet".to_string()
        } else {
            let host = self.field(Field::Host).text.trim().to_string();
            let user = self.field(Field::User).text.trim().to_string();
            match (host.is_empty(), user.is_empty(), self.selected.is_some()) {
                (true, _, _) => "Not saved yet".to_string(),
                (false, true, _) => host,
                (false, false, _) => format!("{host} · {user}"),
            }
        };
        let bh = p(34.0);
        let connect = if group_mode { "Connect all" } else { "Connect" };
        let cw = te.measure(f.semi, 13.0 * s, connect) as i32 + p(36.0);
        let mut bx = x + w - cw;
        let by = top + p(30.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(bx, by, cw, bh),
            connect,
            Style::Primary,
            Hit::Connect,
        );
        bx -= p(84.0) + p(8.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(bx, by, p(84.0), bh),
            "Save",
            Style::Secondary,
            Hit::Save,
        );
        if open_group.is_some() {
            let nw = p(124.0);
            bx -= nw + p(8.0);
            self.button(
                cv,
                te,
                f,
                Rect::new(bx, by, nw, bh),
                "+ Connection",
                Style::Secondary,
                Hit::NewInGroup,
            );
        }
        if self.selected.is_some() || open_group.is_some() {
            bx -= p(84.0) + p(8.0);
            self.button(
                cv,
                te,
                f,
                Rect::new(bx, by, p(84.0), bh),
                "Delete",
                Style::Danger,
                Hit::Delete,
            );
        }
        let tw = (bx - x - p(16.0)) as f32;
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x as f32,
            (top + p(48.0)) as f32,
            &title,
            TEXT,
            tw,
        );
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x as f32,
            (top + p(70.0)) as f32,
            &sub,
            TEXT_3,
            tw,
        );

        // Section switcher
        let pages: Vec<(String, bool, Hit)> =
            ["General", "Display", "Experience", "Sharing", "Advanced"]
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    (
                        n.to_string(),
                        self.form_page == i as u8,
                        Hit::FormPage(i as u8),
                    )
                })
                .collect();
        self.segmented(cv, te, f, Rect::new(x, top + p(92.0), w, p(36.0)), &pages);

        let mut y = top + p(148.0);
        let parent = normalize_path(&self.field(Field::GroupPath).text);
        let inh = self.form_inherit();
        y = match self.form_page {
            0 => self.form_general(cv, te, f, x, y, w, group_mode, &parent, inh),
            1 => self.form_display(cv, te, f, x, y, w, &parent, inh),
            2 => self.form_experience(cv, te, f, x, y, w, &parent, inh),
            3 => self.form_sharing(cv, te, f, x, y, w, &parent, inh),
            _ => self.form_advanced(cv, te, f, x, y, w, &parent, inh),
        };
        let hint = if group_mode {
            "Connect all opens every member with a saved password, or the one typed here."
        } else if self.opens == Opens::Apps {
            "Connect starts the first app · click an app in the sidebar to start it · Ctrl+S saves"
        } else {
            "Enter connects · Ctrl+S saves · Ctrl+N new connection"
        };
        self.hint(cv, te, f, x, y + p(22.0), w, hint);

        // Scrolling: remember the height, keep the offset in range, show a bar.
        self.home_content = y + p(48.0) - top;
        let max = (self.home_content - area.h).max(0);
        if self.home_scroll > max {
            self.home_scroll = max;
        }
        if max > 0 {
            let track = area.h - p(8.0);
            let bar = (track * area.h / self.home_content).max(p(24.0));
            let sy = area.y + p(4.0) + (track - bar) * self.home_scroll / max;
            cv.fill_round(
                Rect::new(area.right() - p(7.0), sy, p(4.0), bar),
                2.0 * s,
                BORDER_HOVER,
            );
        }
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
    }

    /// A card row with a label on the left and a text field on the right.
    #[allow(clippy::too_many_arguments)]
    fn field_row(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        field: Field,
        placeholder: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        te.draw(
            cv,
            f.ui,
            13.0 * s,
            (r.x + p(16.0)) as f32,
            (r.y + r.h / 2 + p(5.0)) as f32,
            label,
            TEXT_2,
            p(110.0) as f32,
        );
        let input = Rect::new(
            r.x + p(132.0),
            r.y + p(9.0),
            r.w - p(132.0) - p(12.0),
            r.h - p(18.0),
        );
        self.text_input(cv, te, f, input, field, placeholder);
    }

    /// The first card of an inheritable page in a group: the switch, and
    /// where the values come from. Returns true when the page is inherited.
    #[allow(clippy::too_many_arguments)]
    fn inherit_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: &mut i32,
        w: i32,
        parent: &str,
        section: u8,
        on: bool,
        what: &str,
    ) -> bool {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if parent.is_empty() {
            return false;
        }
        let label = format!(
            "Use {}'s {what}",
            parent.rsplit('/').next().unwrap_or(parent)
        );
        let sub = if on {
            self.inherited_text(parent, section)
        } else {
            "Off: this one sets its own".to_string()
        };
        let cells = self.card(cv, x, *y, w, &[p(58.0)]);
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            &label,
            &sub,
            on,
            Hit::FormInherit(section),
        );
        *y += p(58.0) + p(20.0);
        on
    }

    #[allow(clippy::too_many_arguments)]
    fn form_general(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        group_mode: bool,
        parent: &str,
        inh: Inherit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let rh = p(52.0);
        self.caption(
            cv,
            te,
            f,
            x,
            y,
            w,
            if group_mode { "GROUP" } else { "CONNECTION" },
        );
        y += p(24.0);
        if group_mode {
            let cells = self.card(cv, x, y, w, &[rh; 2]);
            self.field_row(cv, te, f, cells[0], "Name", Field::Name, "Group name");
            self.field_row(
                cv,
                te,
                f,
                cells[1],
                "Parent",
                Field::GroupPath,
                "None (top level)",
            );
            y += 2 * rh;
        } else {
            let cells = self.card(cv, x, y, w, &[rh; 3]);
            self.field_row(
                cv,
                te,
                f,
                cells[0],
                "Name",
                Field::Name,
                "Defaults to the host",
            );
            // Host and port share a row.
            let r = cells[1];
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(16.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                "Host",
                TEXT_2,
                p(110.0) as f32,
            );
            let port_w = p(84.0);
            let hx = r.x + p(132.0);
            let hw = r.right() - p(12.0) - port_w - p(8.0) - hx;
            self.text_input(
                cv,
                te,
                f,
                Rect::new(hx, r.y + p(9.0), hw, r.h - p(18.0)),
                Field::Host,
                "Name or IP address",
            );
            self.text_input(
                cv,
                te,
                f,
                Rect::new(
                    r.right() - p(12.0) - port_w,
                    r.y + p(9.0),
                    port_w,
                    r.h - p(18.0),
                ),
                Field::Port,
                "Port",
            );
            self.field_row(
                cv,
                te,
                f,
                cells[2],
                "Group",
                Field::GroupPath,
                "None (top level), e.g. Work/Servers",
            );
            y += 3 * rh;
        }
        y += p(20.0);
        if !group_mode {
            y = self.form_opens(cv, te, f, x, y, w);
        }

        self.caption(cv, te, f, x, y, w, "SIGN-IN");
        y += p(24.0);
        let inherited = self.inherit_card(
            cv,
            te,
            f,
            x,
            &mut y,
            w,
            parent,
            0,
            inh.credentials,
            "sign-in",
        );
        if inherited {
            let cells = self.card(cv, x, y, w, &[rh]);
            let saved_in = self
                .store
                .source_of(parent, &Inherit::ALL, |i| i.credentials)
                .filter(|g| g.password.is_some())
                .map(|_| SAVED_MASK.to_string());
            let hint = saved_in.unwrap_or_else(|| "Asked for each connection".into());
            self.field_row(cv, te, f, cells[0], "Password", Field::Password, &hint);
            return y + rh;
        }
        let saved = self.save_password && self.own_password().is_some();
        let cells = self.card(cv, x, y, w, &[rh, rh, p(58.0), p(58.0), rh]);
        self.field_row(
            cv,
            te,
            f,
            cells[0],
            "User",
            Field::User,
            r"DOMAIN\user or user@domain",
        );
        let pw_hint = if saved {
            SAVED_MASK
        } else if group_mode {
            "Used by members that inherit it"
        } else {
            "Asked for each connection"
        };
        self.field_row(cv, te, f, cells[1], "Password", Field::Password, pw_hint);
        let save_sub = if self.store.is_vault() {
            "Kept in the encrypted vault"
        } else {
            "Asks for a master password first"
        };
        self.card_switch(
            cv,
            te,
            f,
            cells[2],
            "Save password",
            save_sub,
            self.save_password,
            Hit::SavePassword,
        );
        let kerberos = self.kerberos;
        self.card_switch(
            cv,
            te,
            f,
            cells[3],
            "Sign in with Windows",
            "Kerberos for domain servers, NTLM as a fallback; no user: you",
            kerberos,
            Hit::FormKerberos,
        );
        self.field_row(
            cv,
            te,
            f,
            cells[4],
            "Gateway",
            Field::Gateway,
            "None (direct), or rdg.example.com",
        );
        y + 3 * rh + 2 * p(58.0)
    }

    /// "Opens: Desktop | Apps", and in Apps mode the connection's apps with
    /// their remove buttons and the row that adds one.
    #[allow(clippy::too_many_arguments)]
    fn form_opens(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let apps_mode = self.opens == Opens::Apps;
        self.caption(cv, te, f, x, y, w, "OPENS");
        y += p(24.0);
        let items = [
            ("Desktop".to_string(), !apps_mode, Hit::FormOpens(0)),
            ("Apps".to_string(), apps_mode, Hit::FormOpens(1)),
        ];
        self.segmented(cv, te, f, Rect::new(x, y, w, p(36.0)), &items);
        y += p(36.0) + p(20.0);
        self.hint(
            cv,
            te,
            f,
            x + p(4.0),
            y - p(4.0),
            w,
            if apps_mode {
                "Each app opens in its own window on this PC, as if it ran here (RemoteApp)."
            } else {
                "The whole remote desktop, in a tab, full screen or on chosen monitors."
            },
        );
        y += p(20.0);
        if !apps_mode {
            return y;
        }
        self.caption(cv, te, f, x, y, w, "APPS");
        y += p(24.0);
        let apps = self.apps.clone();
        let mut heights = vec![p(52.0); apps.len().max(1)];
        heights.extend([p(52.0), p(52.0)]);
        let cells = self.card(cv, x, y, w, &heights);
        if apps.is_empty() {
            let r = cells[0];
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(16.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                "No apps yet: type a program below and press Add.",
                TEXT_3,
                (r.w - p(32.0)) as f32,
            );
        }
        for (i, (r, app)) in cells.iter().zip(&apps).enumerate() {
            app_glyph(cv, s, r.x + p(16.0), r.y + r.h / 2 - p(7.0), ACCENT);
            let close = Rect::new(r.right() - p(40.0), r.y + p(14.0), p(24.0), p(24.0));
            let tw = (close.x - r.x - p(56.0)) as f32;
            te.draw(
                cv,
                f.semi,
                13.5 * s,
                (r.x + p(42.0)) as f32,
                (r.y + p(22.0)) as f32,
                &app.name,
                TEXT,
                tw,
            );
            let mut sub = app.program.clone();
            if !app.args.is_empty() {
                sub = format!("{sub} {}", app.args);
            }
            if !app.working_dir.is_empty() {
                sub = format!("{sub} · in {}", app.working_dir);
            }
            te.draw(
                cv,
                f.ui,
                12.0 * s,
                (r.x + p(42.0)) as f32,
                (r.y + p(40.0)) as f32,
                &sub,
                TEXT_3,
                tw,
            );
            let hit = Hit::FormRemoveApp(i);
            if self.hover == Some(hit) {
                cv.fill_round(close, 5.0 * s, CONTROL_HOVER);
            }
            let (cx, cy, dd) = (
                (close.x + close.w / 2) as f32,
                (close.y + close.h / 2) as f32,
                4.0 * s,
            );
            cv.stroke(&[(cx - dd, cy - dd), (cx + dd, cy + dd)], 1.4 * s, TEXT_2);
            cv.stroke(&[(cx - dd, cy + dd), (cx + dd, cy - dd)], 1.4 * s, TEXT_2);
            self.hits.push((close, hit));
        }
        // The add rows: program and name; arguments, folder and Add.
        let n = heights.len();
        let (r1, r2) = (cells[n - 2], cells[n - 1]);
        let gap = p(8.0);
        let i1 = Rect::new(
            r1.x + p(12.0),
            r1.y + p(9.0),
            r1.w - p(24.0),
            r1.h - p(18.0),
        );
        let pw = (i1.w - gap) * 3 / 5;
        self.text_input(
            cv,
            te,
            f,
            Rect::new(i1.x, i1.y, pw, i1.h),
            Field::AppProgram,
            r"Program: ||Excel or C:\Tools\app.exe",
        );
        self.text_input(
            cv,
            te,
            f,
            Rect::new(i1.x + pw + gap, i1.y, i1.w - pw - gap, i1.h),
            Field::AppName,
            "Name (optional)",
        );
        let i2 = Rect::new(
            r2.x + p(12.0),
            r2.y + p(9.0),
            r2.w - p(24.0),
            r2.h - p(18.0),
        );
        let aw = p(64.0);
        let fw = (i2.w - aw - 2 * gap) / 2;
        self.text_input(
            cv,
            te,
            f,
            Rect::new(i2.x, i2.y, fw, i2.h),
            Field::AppArgs,
            "Arguments (optional)",
        );
        self.text_input(
            cv,
            te,
            f,
            Rect::new(i2.x + fw + gap, i2.y, fw, i2.h),
            Field::AppDir,
            "Working folder (optional)",
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(i2.right() - aw, i2.y, aw, i2.h),
            "Add",
            Style::Secondary,
            Hit::FormAddApp,
        );
        y + heights.iter().sum::<i32>() + p(20.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn form_display(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        parent: &str,
        inh: Inherit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.inherit_card(
            cv,
            te,
            f,
            x,
            &mut y,
            w,
            parent,
            1,
            inh.display,
            "display settings",
        ) {
            return y - p(20.0);
        }
        self.caption(cv, te, f, x, y, w, "DESKTOP SIZE");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = std::iter::once("Fit window".to_string())
            .chain(SIZES.iter().map(|(sw, sh)| format!("{sw} × {sh}")))
            .enumerate()
            .map(|(i, t)| (t, self.size == i, Hit::Size(i)))
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(16.0),
            w,
            "Fit window follows the tab's size; a fixed size stays as chosen.",
        );
        y += p(40.0);

        self.caption(cv, te, f, x, y, w, "SCALE");
        y += p(24.0);
        let auto = format!("Auto ({} %)", (self.scale * 100.0).round() as u32);
        let items: Vec<(String, bool, Hit)> = std::iter::once(auto)
            .chain(SCALES.iter().map(|v| format!("{v} %")))
            .enumerate()
            .map(|(i, t)| {
                let chosen = match (i, self.opts.scale) {
                    (0, None) => true,
                    (i, Some(v)) if i > 0 => SCALES[i - 1] == v,
                    _ => false,
                };
                (t, chosen, Hit::FormScale(i))
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "MONITORS");
        y += p(24.0);
        y = self.monitor_map(cv, te, f, x, y, w);
        let n = self.opts.monitors.len();
        let hint = match n {
            0 => "None chosen: the session runs in this window. Click monitors to span the session over them.".to_string(),
            1 => "Full screen on the chosen monitor.".to_string(),
            n => format!("Full screen across the {n} chosen monitors."),
        };
        self.hint(cv, te, f, x, y + p(16.0), w, &hint);
        y + p(24.0)
    }

    /// This PC's monitors in their real arrangement; chosen ones are lit.
    #[allow(clippy::too_many_arguments)]
    fn monitor_map(
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
        let mons = self.local_monitors.clone();
        let box_h = p(150.0);
        let frame = Rect::new(x, y, w, box_h);
        cv.round_border(frame, 8.0 * s, BORDER_SOFT, BG_BAR);
        let Some((bl, bt, bw, bh)) = crate::monitors::bounds(&mons) else {
            centered(cv, te, f.ui, 12.5 * s, frame, "No monitors found.", TEXT_3);
            return y + box_h;
        };
        let pad = p(16.0) as f32;
        let k = ((frame.w as f32 - 2.0 * pad) / bw as f32)
            .min((frame.h as f32 - 2.0 * pad) / bh as f32);
        let ox = frame.x as f32 + (frame.w as f32 - bw as f32 * k) / 2.0;
        let oy = frame.y as f32 + (frame.h as f32 - bh as f32 * k) / 2.0;
        for (i, m) in mons.iter().enumerate() {
            let r = Rect::new(
                (ox + (m.monitor.left - bl) as f32 * k) as i32 + p(3.0),
                (oy + (m.monitor.top - bt) as f32 * k) as i32 + p(3.0),
                (m.width() as f32 * k) as i32 - p(6.0),
                (m.height() as f32 * k) as i32 - p(6.0),
            );
            let on = self.opts.monitors.contains(&m.name);
            let hit = Hit::FormMonitor(i);
            let (border, fill, color) = if on {
                (ACCENT, BG_SELECT, TEXT)
            } else if self.hover == Some(hit) {
                (BORDER_HOVER, CONTROL_HOVER, TEXT_2)
            } else {
                (BORDER, BG, TEXT_3)
            };
            cv.round_border(r, 5.0 * s, border, fill);
            let num = (i + 1).to_string();
            let top = Rect::new(r.x, r.y + r.h / 2 - p(18.0), r.w, p(22.0));
            centered(cv, te, f.semi, 16.0 * s, top, &num, color);
            let size = if m.monitor.primary {
                format!("{} × {} · main", m.width(), m.height())
            } else {
                format!("{} × {}", m.width(), m.height())
            };
            let bottom = Rect::new(r.x, r.y + r.h / 2 + p(4.0), r.w, p(16.0));
            centered(cv, te, f.ui, 11.0 * s, bottom, &size, color);
            self.hits.push((r, hit));
        }
        y + box_h
    }

    #[allow(clippy::too_many_arguments)]
    fn form_experience(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        parent: &str,
        inh: Inherit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.inherit_card(
            cv,
            te,
            f,
            x,
            &mut y,
            w,
            parent,
            1,
            inh.display,
            "display settings",
        ) {
            return y - p(20.0);
        }
        let q = self.opts.quality;
        self.caption(cv, te, f, x, y, w, "CONNECTION SPEED");
        y += p(24.0);
        let subs = [
            "The server measures the link and adapts",
            "Everything on",
            "Everything on, for slower links",
            "No wallpaper or animations",
            "Visual styles only",
            "Plain desktop, least data",
        ];
        let cells = self.card(cv, x, y, w, &[p(50.0); PRESETS.len()]);
        for (i, (r, ((c, name), sub))) in cells.iter().zip(PRESETS.iter().zip(subs)).enumerate() {
            self.card_choice(
                cv,
                te,
                f,
                *r,
                name,
                sub,
                q.connection == *c,
                Hit::FormPreset(i),
            );
        }
        y += PRESETS.len() as i32 * p(50.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "COLOURS");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = DEPTHS
            .iter()
            .enumerate()
            .map(|(i, d)| (format!("{d}-bit"), q.color_depth == *d, Hit::FormDepth(i)))
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "SHOW");
        y += p(24.0);
        let rows = [
            ("Desktop background", q.wallpaper),
            ("Font smoothing", q.font_smoothing),
            ("Desktop composition", q.composition),
            ("Window contents while dragging", q.window_drag),
            ("Menu and window animations", q.animations),
            ("Visual styles", q.visual_styles),
        ];
        let cells = self.card(cv, x, y, w, &[p(44.0); 6]);
        for (i, (r, (label, on))) in cells.iter().zip(rows).enumerate() {
            self.card_switch(cv, te, f, *r, label, "", on, Hit::FormExperience(i as u8));
        }
        y += 6 * p(44.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "INPUT");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &[p(58.0)]);
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            "Touch and pen",
            TOUCH_HINT,
            q.touch,
            Hit::FormExperience(6),
        );
        y + p(58.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn form_sharing(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        parent: &str,
        inh: Inherit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.inherit_card(cv, te, f, x, &mut y, w, parent, 2, inh.sharing, "sharing") {
            return y - p(20.0);
        }
        let o = self.opts.clone();
        let rows = [
            ("Clipboard", "Text and files, both ways", o.clipboard),
            ("Sound", "Remote audio plays on this PC", o.sound),
            (
                "Microphone",
                "This PC's microphone in the session",
                o.microphone,
            ),
            ("Printers", "Local printers in the session", o.printers),
            ("Smart cards", "Local readers and cards", o.smart_cards),
        ];
        let cells = self.card(cv, x, y, w, &[p(56.0); 5]);
        for (r, (i, label, sub, on)) in cells.iter().zip([
            (0u8, rows[0].0, rows[0].1, rows[0].2),
            (1, rows[1].0, rows[1].1, rows[1].2),
            (4, rows[2].0, rows[2].1, rows[2].2),
            (2, rows[3].0, rows[3].1, rows[3].2),
            (3, rows[4].0, rows[4].1, rows[4].2),
        ]) {
            self.card_switch(cv, te, f, *r, label, sub, on, Hit::FormShare(i));
        }
        y += 5 * p(56.0) + p(20.0);

        if o.sound {
            y = self.device_card(
                cv,
                te,
                f,
                x,
                y,
                w,
                "PLAY SOUND ON",
                "Default output",
                &self.speakers.clone(),
                o.speaker.as_deref(),
                Hit::FormSpeaker,
            );
        }
        if o.microphone {
            y = self.device_card(
                cv,
                te,
                f,
                x,
                y,
                w,
                "RECORD FROM",
                "Default microphone",
                &self.mics.clone(),
                o.mic.as_deref(),
                Hit::FormMic,
            );
        }

        self.caption(cv, te, f, x, y, w, "SHARED FOLDERS");
        y += p(24.0);
        let n = o.drives.len();
        let mut heights = vec![p(46.0); n];
        heights.push(p(52.0));
        let cells = self.card(cv, x, y, w, &heights);
        for (i, (r, path)) in cells.iter().zip(&o.drives).enumerate() {
            let close = Rect::new(r.right() - p(40.0), r.y + p(11.0), p(24.0), p(24.0));
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(16.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                path,
                TEXT,
                (close.x - r.x - p(24.0)) as f32,
            );
            let hit = Hit::FormRemoveDrive(i);
            if self.hover == Some(hit) {
                cv.fill_round(close, 5.0 * s, CONTROL_HOVER);
            }
            let (cx, cy, dd) = (
                (close.x + close.w / 2) as f32,
                (close.y + close.h / 2) as f32,
                4.0 * s,
            );
            cv.stroke(&[(cx - dd, cy - dd), (cx + dd, cy + dd)], 1.4 * s, TEXT_2);
            cv.stroke(&[(cx - dd, cy + dd), (cx + dd, cy - dd)], 1.4 * s, TEXT_2);
            self.hits.push((close, hit));
        }
        let r = cells[n];
        let (bw, aw) = (p(96.0), p(64.0));
        let inner = Rect::new(r.x + p(12.0), r.y + p(9.0), r.w - p(24.0), r.h - p(18.0));
        self.button(
            cv,
            te,
            f,
            Rect::new(inner.x, inner.y, bw, inner.h),
            "Browse…",
            Style::Secondary,
            Hit::BrowseForm,
        );
        self.text_input(
            cv,
            te,
            f,
            Rect::new(
                inner.x + bw + p(8.0),
                inner.y,
                inner.w - bw - aw - p(16.0),
                inner.h,
            ),
            Field::FormDrive,
            r"or type a path, e.g. C:\Share",
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(inner.right() - aw, inner.y, aw, inner.h),
            "Add",
            Style::Secondary,
            Hit::FormAddDrive,
        );
        y + heights.iter().sum::<i32>()
    }

    /// The panel's device card (hits carry the session id).
    #[allow(clippy::too_many_arguments)]
    fn device_card_tab(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        caption: &str,
        default: &str,
        devices: &[String],
        chosen: Option<&str>,
        id: u64,
        hit: fn(u64, usize) -> Hit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        self.caption(cv, te, f, x, y, w, caption);
        y += p(24.0);
        let names: Vec<&str> = std::iter::once(default)
            .chain(devices.iter().map(String::as_str))
            .collect();
        let pick = chosen
            .and_then(|c| devices.iter().position(|d| d == c))
            .map_or(0, |i| i + 1);
        let cells = self.card(cv, x, y, w, &vec![p(40.0); names.len()]);
        for (i, (r, name)) in cells.iter().zip(&names).enumerate() {
            self.card_radio(cv, te, f, *r, name, pick == i, hit(id, i));
        }
        y + names.len() as i32 * p(40.0) + p(20.0)
    }

    /// A caption and a card choosing one local device (or the default).
    #[allow(clippy::too_many_arguments)]
    fn device_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        caption: &str,
        default: &str,
        devices: &[String],
        chosen: Option<&str>,
        hit: fn(usize) -> Hit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        self.caption(cv, te, f, x, y, w, caption);
        y += p(24.0);
        let names: Vec<&str> = std::iter::once(default)
            .chain(devices.iter().map(String::as_str))
            .collect();
        let pick = chosen
            .and_then(|c| devices.iter().position(|d| d == c))
            .map_or(0, |i| i + 1);
        let cells = self.card(cv, x, y, w, &vec![p(42.0); names.len()]);
        for (i, (r, name)) in cells.iter().zip(&names).enumerate() {
            self.card_radio(cv, te, f, *r, name, pick == i, hit(i));
        }
        y + names.len() as i32 * p(42.0) + p(20.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn form_advanced(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        parent: &str,
        inh: Inherit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.inherit_card(
            cv,
            te,
            f,
            x,
            &mut y,
            w,
            parent,
            1,
            inh.display,
            "display settings",
        ) {
            return y - p(20.0);
        }
        let q = self.opts.quality;
        self.caption(cv, te, f, x, y, w, "GRAPHICS");
        y += p(24.0);
        let subs = [
            "Classic bitmap updates. Lowest latency; the default.",
            "Graphics pipeline with H.264. Experimental.",
        ];
        let cells = self.card(cv, x, y, w, &[p(50.0); 2]);
        for (i, (r, (name, sub))) in cells
            .iter()
            .zip([("Bitmaps", subs[0]), ("GFX (H.264)", subs[1])])
            .enumerate()
        {
            self.card_choice(
                cv,
                te,
                f,
                *r,
                name,
                sub,
                q.gfx == (i == 1),
                Hit::FormGraphics(i),
            );
        }
        y += 2 * p(50.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "WINDOWS KEYS (WIN, ALT+TAB, …)");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = WinKeys::ALL
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let t = match k {
                    WinKeys::Local => "On this PC",
                    WinKeys::Remote => "On the remote",
                    WinKeys::FullScreen => "Remote in full screen",
                };
                (t.to_string(), self.opts.win_keys == *k, Hit::FormWinKeys(i))
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "COMPRESSION");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = COMPRESSION
            .iter()
            .enumerate()
            .map(|(i, (key, name))| {
                (
                    name.to_string(),
                    q.compression == *key,
                    Hit::FormCompression(i),
                )
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(16.0),
            w,
            "Less data on slow links, a little more CPU. Off is fastest on a LAN.",
        );
        y + p(24.0)
    }

    /// Mouse wheel over the quick panel or the connection form; true when
    /// something scrolled.
    pub fn scroll(&mut self, x: i32, y: i32, lines: f32) -> bool {
        if self.active.is_some() && self.drawer && self.drawer_area.contains(x, y) {
            let max = (self.drawer_content - self.drawer_area.h).max(0);
            let next = (self.drawer_scroll - (lines * 48.0 * self.scale) as i32).clamp(0, max);
            let changed = next != self.drawer_scroll;
            self.drawer_scroll = next;
            return changed;
        }
        self.scroll_home(x, y, lines)
    }

    /// Mouse wheel over the connection form; true when it scrolled.
    pub fn scroll_home(&mut self, x: i32, y: i32, lines: f32) -> bool {
        if self.active.is_some() || !self.home_area.contains(x, y) {
            return false;
        }
        let max = (self.home_content - self.home_area.h).max(0);
        let next = (self.home_scroll - (lines * 48.0 * self.scale) as i32).clamp(0, max);
        let changed = next != self.home_scroll;
        self.home_scroll = next;
        changed
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

        // Toolbar: above the session, or in full screen with a hiding bar,
        // over its top edge while revealed (drawn after the session area).
        let overlay = self.fullscreen && !self.bar_pinned;
        let tb = Rect::new(content.x, content.y, content.w, p(40.0));
        if !overlay {
            self.paint_toolbar(cv, te, f, tb, id, &host, &state, &name);
        }

        // Session area and drawer
        let area_top = if overlay { content.y } else { tb.bottom() };
        let mut area = Rect::new(content.x, area_top, content.w, content.bottom() - area_top);
        if self.drawer {
            let dw = p(320.0).min(area.w / 2);
            let drawer = Rect::new(area.right() - dw, area.y, dw, area.h);
            area.w -= dw + 1;
            cv.fill(Rect::new(area.right(), area.y, 1, area.h), BORDER_SOFT);
            self.paint_drawer(cv, te, f, drawer, id);
        }
        cv.fill(area, BG_SIDEBAR);
        self.session_clip = None;
        if overlay && self.bar_revealed {
            let bar = Rect::new(area.x, area.y, area.w, tb.h);
            self.session_clip = Some(Rect::new(area.x, bar.bottom(), area.w, area.h - bar.h));
        }
        match state.clone() {
            TabState::Connected { .. } if self.tabs.iter().any(|t| t.id == id && t.spanned) => {
                let mid = area.y + area.h / 2;
                centered(
                    cv,
                    te,
                    f.semi,
                    15.0 * s,
                    Rect::new(area.x, mid - p(48.0), area.w, p(24.0)),
                    "This session is on its monitors",
                    TEXT,
                );
                centered(
                    cv,
                    te,
                    f.ui,
                    12.5 * s,
                    Rect::new(area.x, mid - p(22.0), area.w, p(20.0)),
                    "Ctrl+Alt+Break or the bar at their top edge brings it back here.",
                    TEXT_3,
                );
                let bw = p(190.0);
                self.button(
                    cv,
                    te,
                    f,
                    Rect::new(area.x + (area.w - bw) / 2, mid + p(10.0), bw, p(34.0)),
                    "Show it in this window",
                    Style::Primary,
                    Hit::Unspan(id),
                );
            }
            TabState::Connected { .. }
                if self
                    .tabs
                    .iter()
                    .any(|t| t.id == id && t.remote_app.is_some()) =>
            {
                self.paint_apps_tab(cv, te, f, area, id);
            }
            TabState::Connected { .. } => {
                self.session_area = Some((id, area));
                self.hits
                    .push((self.session_clip.unwrap_or(area), Hit::Session(id)));
            }
            TabState::Connecting => {
                let cert = self
                    .tabs
                    .iter()
                    .find(|t| t.id == id)
                    .and_then(|t| t.cert.clone());
                match cert {
                    Some(c) => self.paint_cert_prompt(cv, te, f, area, id, &c.host.clone(), &c),
                    None => centered(
                        cv,
                        te,
                        f.ui,
                        14.0 * s,
                        Rect::new(area.x, area.y, area.w, area.h - p(40.0)),
                        &format!("Connecting to {name}…"),
                        TEXT_2,
                    ),
                }
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
        if overlay && self.bar_revealed {
            let bar = Rect::new(area.x, area.y, area.w, tb.h);
            cv.fill(bar, BG);
            self.paint_toolbar(cv, te, f, bar, id, &host, &state, &name);
        }
    }

    /// A RemoteApp session tab: its open windows (Focus, Close) and its
    /// apps to launch. The windows themselves are on this PC's desktop.
    fn paint_apps_tab(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (host, name) = (t.host.clone(), t.name.clone());
        let view = t.remote_app.clone().unwrap_or_default();
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        let x = area.x + p(40.0);
        let w = p(620.0).min(area.w - p(80.0)).max(p(300.0));
        let mut y = area.y + p(30.0);
        te.draw(
            cv,
            f.semi,
            20.0 * s,
            x as f32,
            (y + p(18.0)) as f32,
            &format!("Apps on {host}"),
            TEXT,
            w as f32,
        );
        let n = view.windows.len();
        let sub = match n {
            0 => format!("{name} · no app window open"),
            1 => format!("{name} · 1 window open on this PC"),
            n => format!("{name} · {n} windows open on this PC"),
        };
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x as f32,
            (y + p(40.0)) as f32,
            &sub,
            TEXT_3,
            w as f32,
        );
        y += p(70.0);

        self.caption(cv, te, f, x, y, w, "OPEN WINDOWS");
        y += p(24.0);
        let rh = p(52.0);
        let cells = self.card(cv, x, y, w, &vec![rh; n.max(1)]);
        if n == 0 {
            let r = cells[0];
            let text = if view.starting.is_empty() {
                "Start an app below; its windows appear on this PC's desktop."
            } else {
                "Starting…"
            };
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(16.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                text,
                TEXT_3,
                (r.w - p(32.0)) as f32,
            );
        }
        for (r, win) in cells.iter().zip(&view.windows) {
            let isz = p(20.0);
            let ir = Rect::new(r.x + p(16.0), r.y + (r.h - isz) / 2, isz, isz);
            match &win.icon {
                Some((iw, ih, rgba)) if rgba.len() == *iw as usize * *ih as usize * 4 => {
                    cv.draw_rgba_scaled(ir, *iw as usize, *ih as usize, rgba)
                }
                _ => app_glyph(cv, s, ir.x + p(3.0), ir.y + p(3.0), TEXT_3),
            }
            let (cw, fw) = (p(70.0), p(70.0));
            let close = Rect::new(r.right() - p(12.0) - cw, r.y + p(10.0), cw, r.h - p(20.0));
            let focus = Rect::new(close.x - p(8.0) - fw, close.y, fw, close.h);
            let tw = (focus.x - r.x - p(60.0)) as f32;
            let title = if win.title.is_empty() {
                "(untitled)"
            } else {
                &win.title
            };
            let ty = if win.minimized {
                p(22.0)
            } else {
                r.h / 2 + p(5.0)
            };
            te.draw(
                cv,
                f.ui,
                13.5 * s,
                (r.x + p(48.0)) as f32,
                (r.y + ty) as f32,
                title,
                TEXT,
                tw,
            );
            if win.minimized {
                te.draw(
                    cv,
                    f.ui,
                    12.0 * s,
                    (r.x + p(48.0)) as f32,
                    (r.y + p(40.0)) as f32,
                    "Minimized",
                    TEXT_3,
                    tw,
                );
            }
            self.button(
                cv,
                te,
                f,
                focus,
                "Focus",
                Style::Secondary,
                Hit::RailFocus(id, win.id),
            );
            self.button(
                cv,
                te,
                f,
                close,
                "Close",
                Style::Danger,
                Hit::RailClose(id, win.id),
            );
        }
        y += rh * n.max(1) as i32 + p(20.0);

        self.caption(cv, te, f, x, y, w, "LAUNCH");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &vec![rh; view.apps.len().max(1)]);
        if view.apps.is_empty() {
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (cells[0].x + p(16.0)) as f32,
                (cells[0].y + rh / 2 + p(5.0)) as f32,
                "This connection has no apps; add them in its editor.",
                TEXT_3,
                (w - p(32.0)) as f32,
            );
        }
        let same =
            |l: &[String], prog: &str| l.iter().any(|p| crate::remoteapp::same_program(p, prog));
        for (i, (r, app)) in cells.iter().zip(&view.apps).enumerate() {
            let hit = Hit::TabLaunch(id, i);
            if self.hover == Some(hit) {
                cv.fill_round(
                    Rect::new(r.x + p(3.0), r.y + p(3.0), r.w - p(6.0), r.h - p(6.0)),
                    6.0 * s,
                    BG_HOVER,
                );
            }
            app_glyph(cv, s, r.x + p(16.0), r.y + r.h / 2 - p(7.0), ACCENT);
            let (state, color) = if same(&view.running, &app.program) {
                ("Running · start another", OK)
            } else if same(&view.starting, &app.program) {
                ("Starting…", WARN)
            } else {
                ("Start", ACCENT)
            };
            let sw = te.measure(f.ui, 12.5 * s, state) as i32;
            te.draw(
                cv,
                f.semi,
                13.5 * s,
                (r.x + p(42.0)) as f32,
                (r.y + p(22.0)) as f32,
                &app.name,
                TEXT,
                (r.w - p(80.0) - sw) as f32,
            );
            te.draw(
                cv,
                f.ui,
                12.0 * s,
                (r.x + p(42.0)) as f32,
                (r.y + p(40.0)) as f32,
                &app.program,
                TEXT_3,
                (r.w - p(80.0) - sw) as f32,
            );
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                (r.right() - p(18.0) - sw) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                state,
                color,
                (sw + p(2.0)) as f32,
            );
            self.hits.push((*r, hit));
        }
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
    }

    /// The session toolbar: state, and Disconnect/Reconnect, full screen and panel.
    #[allow(clippy::too_many_arguments)]
    fn paint_toolbar(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        tb: Rect,
        id: u64,
        host: &str,
        state: &TabState,
        name: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(Rect::new(tb.x, tb.bottom() - 1, tb.w, 1), BORDER_SOFT);
        cv.fill_circle(
            (tb.x + p(18.0)) as f32,
            (tb.y + tb.h / 2) as f32,
            4.0 * s,
            state.color(),
        );
        // RemoteApp: no picture here, so no full screen and no recording.
        let apps = self
            .tabs
            .iter()
            .any(|t| t.id == id && t.remote_app.is_some());
        let info = match &state {
            TabState::Connecting => format!("{host} · connecting…"),
            TabState::Connected { width, height, .. } if apps => {
                format!("{host} · apps on this PC's desktop · {width} × {height}")
            }
            TabState::Connected { width, height, bpp } if self.fullscreen => {
                format!("{name} · {host} · {width} × {height} · {bpp}-bit")
            }
            TabState::Connected { width, height, bpp } => {
                format!("{host} · {width} × {height} · {bpp} bpp")
            }
            TabState::Ended(why) => format!("{host} · ended: {why}"),
            TabState::Failed(why) => format!("{host} · failed: {why}"),
        };
        let mut bx = tb.right() - p(8.0);
        let mut buttons: Vec<(&str, Hit, Style)> = vec![
            (
                if self.fullscreen {
                    "Exit full screen"
                } else {
                    "Full screen"
                },
                Hit::FullScreen,
                Style::Secondary,
            ),
            (
                if self.drawer { "Hide panel" } else { "Panel" },
                Hit::Drawer,
                Style::Secondary,
            ),
        ];
        if apps {
            buttons.remove(0);
        }
        let recording = self.tabs.iter().any(|t| t.id == id && t.recording);
        if matches!(state, TabState::Connected { .. }) && !apps {
            let (text, style) = if recording {
                ("Stop recording", Style::Danger)
            } else {
                ("Record", Style::Secondary)
            };
            buttons.insert(0, (text, Hit::Record(id), style));
        }
        if self.fullscreen {
            let pin = if self.bar_pinned {
                "Auto-hide bar"
            } else {
                "Pin bar"
            };
            buttons.insert(0, (pin, Hit::PinBar, Style::Ghost));
        }
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
    }

    /// Asks whether to trust the server certificate (first connection, or a
    /// certificate that changed since it was trusted).
    #[allow(clippy::too_many_arguments)]
    fn paint_cert_prompt(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        id: u64,
        host: &str,
        c: &CertPrompt,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let w = p(460.0).min(area.w - p(32.0));
        let h = p(250.0);
        let r = Rect::new(area.x + (area.w - w) / 2, area.y + (area.h - h) / 2, w, h);
        let (border, title, color) = if c.changed {
            (DANGER_BORDER, "The server certificate changed", ERR)
        } else {
            (BORDER, "Verify the server", TEXT)
        };
        cv.round_border(r, 10.0 * s, border, BG_BAR);
        let x = r.x + p(22.0);
        let tw = (r.w - p(44.0)) as f32;
        te.draw(
            cv,
            f.semi,
            16.0 * s,
            x as f32,
            (r.y + p(36.0)) as f32,
            title,
            color,
            tw,
        );
        let line = if c.changed {
            format!("{host} shows a different certificate than the one you trusted.")
        } else {
            format!("First connection to {host}. Check the fingerprint with its admin.")
        };
        te.draw(
            cv,
            f.ui,
            12.5 * s,
            x as f32,
            (r.y + p(62.0)) as f32,
            &line,
            TEXT_2,
            tw,
        );
        let sub = if c.changed {
            "A reinstalled server does this, but so does an attack."
        } else {
            "Your password is sent only after you trust it."
        };
        te.draw(
            cv,
            f.ui,
            12.0 * s,
            x as f32,
            (r.y + p(82.0)) as f32,
            sub,
            TEXT_3,
            tw,
        );
        // The fingerprint, 16 bytes per line.
        let fr = Rect::new(x, r.y + p(100.0), r.w - p(44.0), p(56.0));
        cv.round_border(fr, 6.0 * s, BORDER_SOFT, BG);
        te.draw(
            cv,
            f.ui,
            11.0 * s,
            (fr.x + p(12.0)) as f32,
            (fr.y + p(14.0)) as f32,
            "SHA-256",
            TEXT_4,
            tw,
        );
        let (a, b) = c.fingerprint.split_at(c.fingerprint.len().min(48));
        for (i, part) in [a.trim_end_matches(':'), b].iter().enumerate() {
            te.draw(
                cv,
                f.ui,
                12.0 * s,
                (fr.x + p(12.0)) as f32,
                (fr.y + p(30.0) + i as i32 * p(16.0)) as f32,
                part,
                TEXT,
                (fr.w - p(24.0)) as f32,
            );
        }
        let by = r.bottom() - p(22.0) - p(34.0);
        let trust = if c.changed {
            "Trust the new one"
        } else {
            "Trust and connect"
        };
        let tw2 = te.measure(f.semi, 13.0 * s, trust) as i32 + p(32.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(x, by, tw2, p(34.0)),
            trust,
            if c.changed {
                Style::Danger
            } else {
                Style::Primary
            },
            Hit::CertTrust(id),
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(x + tw2 + p(8.0), by, p(96.0), p(34.0)),
            "Cancel",
            Style::Secondary,
            Hit::CertRefuse(id),
        );
    }

    /// The quick panel: four pages (Sharing, Display, Quality, Session) of
    /// grouped cards, like Windows Settings. Its body scrolls.
    fn paint_drawer(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, d: Rect, id: u64) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(d, BG_SIDEBAR);
        let old = cv.set_clip(d);
        let Some(tab) = self.tabs.iter().find(|t| t.id == id) else {
            cv.set_clip(old);
            return;
        };
        let t = TabView {
            clipboard: tab.clipboard,
            sound: tab.sound,
            printers: tab.printers,
            smart_cards: tab.smart_cards,
            fit: tab.fit,
            scale: tab.scale,
            drives: tab.drives.clone(),
            quality: tab.quality,
            quality_live: tab.quality_live,
            state: tab.state.clone(),
            host: tab.host.clone(),
            win_keys: tab.win_keys,
            speaker: tab.speaker.clone(),
            microphone: tab.microphone,
            mic: tab.mic.clone(),
            redirected_to: tab.redirected_to.clone(),
            network: tab.network.clone(),
        };
        let x = d.x + p(16.0);
        let w = d.w - p(32.0);

        // Page switcher
        let seg = Rect::new(x, d.y + p(14.0), w, p(32.0));
        let pages: Vec<(String, bool, Hit)> = ["Sharing", "Display", "Quality", "Session"]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    n.to_string(),
                    self.drawer_page == i as u8,
                    Hit::DrawerPage(i as u8),
                )
            })
            .collect();
        self.segmented(cv, te, f, seg, &pages);

        let body = Rect::new(
            d.x,
            seg.bottom() + p(10.0),
            d.w,
            d.bottom() - seg.bottom() - p(10.0),
        );
        self.drawer_area = body;
        let inner = cv.set_clip(body);
        let first_hit = self.hits.len();
        let top = body.y + p(6.0) - self.drawer_scroll;
        let mut y = top;
        match self.drawer_page {
            0 => y = self.page_sharing(cv, te, f, x, y, w, id, &t),
            1 => y = self.page_display(cv, te, f, x, y, w, id, &t),
            2 => y = self.page_quality(cv, te, f, x, y, w, id, &t),
            _ => y = self.page_session(cv, te, f, x, y, w, id, &t),
        }
        self.drawer_content = y - top + p(16.0);
        let max = (self.drawer_content - body.h).max(0);
        self.drawer_scroll = self.drawer_scroll.min(max);
        if max > 0 {
            let track = body.h - p(8.0);
            let bar = (track * body.h / self.drawer_content).max(p(24.0));
            let by = body.y + p(4.0) + (track - bar) * self.drawer_scroll / max;
            cv.fill_round(
                Rect::new(body.right() - p(5.0), by, p(3.0), bar),
                1.5 * s,
                BORDER_HOVER,
            );
        }
        self.clip_hits(first_hit, body);
        cv.set_clip(inner);
        cv.set_clip(old);
    }

    #[allow(clippy::too_many_arguments)]
    fn page_sharing(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
        t: &TabView,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let rows = [
            (
                "Clipboard",
                "Text and files, both ways",
                t.clipboard,
                Hit::Clipboard(id),
            ),
            ("Sound", "Remote audio on this PC", t.sound, Hit::Sound(id)),
            (
                "Microphone",
                "This PC's microphone",
                t.microphone,
                Hit::Microphone(id),
            ),
            (
                "Printers",
                "Local printers in the session",
                t.printers,
                Hit::Printers(id),
            ),
            (
                "Smart cards",
                "Local readers and cards",
                t.smart_cards,
                Hit::SmartCards(id),
            ),
        ];
        let cells = self.card(cv, x, y, w, &[p(52.0); 5]);
        for (r, (label, sub, on, hit)) in cells.iter().zip(rows) {
            self.card_switch(cv, te, f, *r, label, sub, on, hit);
        }
        y += 5 * p(52.0) + p(20.0);
        if t.microphone {
            let mics = self.mics.clone();
            y = self.device_card_tab(
                cv,
                te,
                f,
                x,
                y,
                w,
                "RECORD FROM",
                "Default microphone",
                &mics,
                t.mic.as_deref(),
                id,
                Hit::TabMic,
            );
        }

        if t.sound {
            self.caption(cv, te, f, x, y, w, "PLAY SOUND ON");
            y += p(24.0);
            let names: Vec<String> = std::iter::once("Default output".to_string())
                .chain(self.speakers.iter().cloned())
                .collect();
            let chosen = t
                .speaker
                .as_ref()
                .and_then(|s| self.speakers.iter().position(|d| d == s))
                .map_or(0, |i| i + 1);
            let cells = self.card(cv, x, y, w, &vec![p(40.0); names.len()]);
            for (i, (r, name)) in cells.iter().zip(&names).enumerate() {
                self.card_radio(cv, te, f, *r, name, chosen == i, Hit::TabSpeaker(id, i));
            }
            y += names.len() as i32 * p(40.0) + p(20.0);
        }

        self.caption(cv, te, f, x, y, w, "SHARED FOLDERS");
        y += p(24.0);
        if t.drives.is_empty() {
            let cells = self.card(cv, x, y, w, &[p(44.0)]);
            te.draw_in(
                cv,
                f.ui,
                12.0 * s,
                Rect::new(
                    cells[0].x + p(14.0),
                    cells[0].y,
                    cells[0].w - p(28.0),
                    cells[0].h,
                ),
                0.0,
                "None yet. Shared folders show in the remote Explorer.",
                TEXT_3,
            );
            y += p(44.0);
        } else {
            let n = t.drives.len();
            let cells = self.card(cv, x, y, w, &vec![p(50.0); n]);
            for (i, (r, drv)) in cells.iter().zip(&t.drives).enumerate() {
                let close = Rect::new(r.right() - p(38.0), r.y + p(13.0), p(24.0), p(24.0));
                te.draw(
                    cv,
                    f.semi,
                    12.5 * s,
                    (r.x + p(14.0)) as f32,
                    (r.y + p(21.0)) as f32,
                    &drv.name,
                    TEXT,
                    (close.x - r.x - p(20.0)) as f32,
                );
                te.draw(
                    cv,
                    f.ui,
                    11.5 * s,
                    (r.x + p(14.0)) as f32,
                    (r.y + p(38.0)) as f32,
                    &drv.path,
                    TEXT_3,
                    (close.x - r.x - p(20.0)) as f32,
                );
                let hit = Hit::RemoveDrive(id, i);
                if self.hover == Some(hit) {
                    cv.fill_round(close, 5.0 * s, CONTROL_HOVER);
                }
                let (cx, cy, dd) = (
                    (close.x + close.w / 2) as f32,
                    (close.y + close.h / 2) as f32,
                    4.0 * s,
                );
                cv.stroke(&[(cx - dd, cy - dd), (cx + dd, cy + dd)], 1.4 * s, TEXT_2);
                cv.stroke(&[(cx - dd, cy + dd), (cx + dd, cy - dd)], 1.4 * s, TEXT_2);
                self.hits.push((close, hit));
            }
            y += n as i32 * p(50.0);
        }
        y += p(10.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(34.0)),
            "Browse for a folder…",
            Style::Secondary,
            Hit::BrowseDrive(id),
        );
        y += p(42.0);
        let add_w = p(60.0);
        self.text_input(
            cv,
            te,
            f,
            Rect::new(x, y, w - add_w - p(6.0), p(32.0)),
            Field::DrivePath,
            r"or type a path, e.g. C:\Share",
        );
        self.button(
            cv,
            te,
            f,
            Rect::new(x + w - add_w, y, add_w, p(32.0)),
            "Add",
            Style::Secondary,
            Hit::AddDrive(id),
        );
        y += p(32.0);
        self.hint(cv, te, f, x, y + p(10.0), w, "Sharing switches apply live.");
        y + p(30.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn page_display(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
        t: &TabView,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let full = self.fullscreen;
        let cells = self.card(cv, x, y, w, &[p(52.0); 2]);
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            "Full screen",
            "Ctrl+Alt+Break switches it",
            full,
            Hit::FullScreen,
        );
        self.card_switch(
            cv,
            te,
            f,
            cells[1],
            "Fit to window",
            "The remote desktop follows the window",
            t.fit,
            Hit::Fit(id),
        );
        y += 2 * p(52.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "SCALE");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = std::iter::once("Auto".to_string())
            .chain(SCALES.iter().map(|v| format!("{v} %")))
            .enumerate()
            .map(|(i, text)| {
                let chosen = match (i, t.scale) {
                    (0, None) => true,
                    (i, Some(v)) if i > 0 => SCALES[i - 1] == v,
                    _ => false,
                };
                (text, chosen, Hit::Scale(id, i))
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(32.0)), &items);
        y += p(32.0);
        let auto = format!(
            "Auto follows this PC's scaling ({} %). Applies live.",
            (self.scale * 100.0).round() as u32
        );
        self.hint(cv, te, f, x, y + p(10.0), w, &auto);
        y + p(30.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn page_quality(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
        t: &TabView,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let q = t.quality;
        // Touch and pen apply live; everything else waits for a logon.
        let fixed = Quality {
            touch: t.quality_live.touch,
            ..q
        };
        if fixed != t.quality_live {
            let r = Rect::new(x, y, w, p(96.0));
            cv.round_border(r, 8.0 * s, ACCENT_BORDER, BG_SELECT);
            te.draw(
                cv,
                f.semi,
                13.0 * s,
                (r.x + p(14.0)) as f32,
                (r.y + p(24.0)) as f32,
                "Reconnect to apply",
                TEXT,
                (r.w - p(28.0)) as f32,
            );
            te.draw(
                cv,
                f.ui,
                11.5 * s,
                (r.x + p(14.0)) as f32,
                (r.y + p(42.0)) as f32,
                "Quality is fixed when the session logs on.",
                TEXT_2,
                (r.w - p(28.0)) as f32,
            );
            self.button(
                cv,
                te,
                f,
                Rect::new(r.x + p(14.0), r.y + p(54.0), p(132.0), p(30.0)),
                "Reconnect now",
                Style::Primary,
                Hit::Reconnect(id),
            );
            y += p(96.0) + p(16.0);
        }

        self.caption(cv, te, f, x, y, w, "CONNECTION SPEED");
        y += p(24.0);
        let subs = [
            "The server measures the link and adapts",
            "Everything on",
            "Everything on, for slower links",
            "No wallpaper or animations",
            "Visual styles only",
            "Plain desktop, least data",
        ];
        let cells = self.card(cv, x, y, w, &[p(48.0); PRESETS.len()]);
        for (i, (r, ((c, name), sub))) in cells.iter().zip(PRESETS.iter().zip(subs)).enumerate() {
            self.card_choice(
                cv,
                te,
                f,
                *r,
                name,
                sub,
                q.connection == *c,
                Hit::TabPreset(id, i),
            );
        }
        y += PRESETS.len() as i32 * p(48.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "COLOURS");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = DEPTHS
            .iter()
            .enumerate()
            .map(|(i, d)| {
                (
                    format!("{d}-bit"),
                    q.color_depth == *d,
                    Hit::TabDepth(id, i),
                )
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(32.0)), &items);
        y += p(32.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "SHOW");
        y += p(24.0);
        let rows = [
            ("Desktop background", q.wallpaper),
            ("Font smoothing", q.font_smoothing),
            ("Desktop composition", q.composition),
            ("Window contents while dragging", q.window_drag),
            ("Menu and window animations", q.animations),
            ("Visual styles", q.visual_styles),
        ];
        let cells = self.card(cv, x, y, w, &[p(42.0); 6]);
        for (i, (r, (label, on))) in cells.iter().zip(rows).enumerate() {
            self.card_switch(
                cv,
                te,
                f,
                *r,
                label,
                "",
                on,
                Hit::TabExperience(id, i as u8),
            );
        }
        y += 6 * p(42.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "INPUT");
        y += p(24.0);
        let cells = self.card(cv, x, y, w, &[p(58.0)]);
        self.card_switch(
            cv,
            te,
            f,
            cells[0],
            "Touch and pen",
            TOUCH_HINT,
            q.touch,
            Hit::TabExperience(id, 6),
        );
        y += p(58.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "GRAPHICS");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = ["Bitmaps", "GFX (H.264)"]
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), q.gfx == (i == 1), Hit::TabGraphics(id, i)))
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(32.0)), &items);
        y += p(32.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "COMPRESSION");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = COMPRESSION
            .iter()
            .enumerate()
            .map(|(i, (key, name))| {
                (
                    name.to_string(),
                    q.compression == *key,
                    Hit::TabCompression(id, i),
                )
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(32.0)), &items);
        y += p(32.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(14.0),
            w,
            "Less data on slow links; costs a little CPU.",
        );
        y + p(30.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn page_session(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
        t: &TabView,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let (status, desktop, colours) = match &t.state {
            TabState::Connected { width, height, bpp } => (
                "Connected".to_string(),
                format!("{width} × {height}"),
                format!("{bpp}-bit"),
            ),
            TabState::Connecting => ("Connecting…".into(), "–".into(), "–".into()),
            TabState::Ended(_) => ("Ended".into(), "–".into(), "–".into()),
            TabState::Failed(_) => ("Failed".into(), "–".into(), "–".into()),
        };
        let mut rows = vec![("Host", t.host.clone())];
        // The server moved the session after logon (MS-RDPBCGR 3.2.5.13).
        if let Some(to) = &t.redirected_to {
            rows.push(("Moved to", to.clone()));
        }
        rows.extend([
            ("Status", status),
            ("Desktop", desktop),
            ("Colours", colours),
            ("Speed", preset_name(t.quality_live.connection).to_string()),
        ]);
        // Network auto-detect results, once the server sent some.
        if let Some(n) = &t.network {
            rows.push(("Network", n.clone()));
        }
        let count = rows.len();
        let cells = self.card(cv, x, y, w, &vec![p(38.0); count]);
        for (r, (label, value)) in cells.iter().zip(rows) {
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                (r.x + p(14.0)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                label,
                TEXT_3,
                p(80.0) as f32,
            );
            let vw = te.measure(f.ui, 12.5 * s, &value) as i32;
            let room = r.w - p(110.0);
            te.draw(
                cv,
                f.ui,
                12.5 * s,
                (r.right() - p(14.0) - vw.min(room)) as f32,
                (r.y + r.h / 2 + p(5.0)) as f32,
                &value,
                TEXT,
                room as f32,
            );
        }
        y += count as i32 * p(38.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "WINDOWS KEYS (WIN, ALT+TAB)");
        y += p(24.0);
        let items: Vec<(String, bool, Hit)> = WinKeys::ALL
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    k.label().to_string(),
                    t.win_keys == *k,
                    Hit::TabWinKeys(id, i),
                )
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(32.0)), &items);
        y += p(32.0) + p(20.0);

        self.caption(cv, te, f, x, y, w, "ACTIONS");
        y += p(24.0);
        self.button(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(34.0)),
            "Send Ctrl+Alt+Del",
            Style::Secondary,
            Hit::CtrlAltDel(id),
        );
        y += p(42.0);
        let half = (w - p(8.0)) / 2;
        self.button(
            cv,
            te,
            f,
            Rect::new(x, y, half, p(34.0)),
            "Reconnect",
            Style::Secondary,
            Hit::Reconnect(id),
        );
        if matches!(t.state, TabState::Connected { .. } | TabState::Connecting) {
            self.button(
                cv,
                te,
                f,
                Rect::new(x + w - half, y, half, p(34.0)),
                "Disconnect",
                Style::Danger,
                Hit::Disconnect(id),
            );
        }
        y += p(34.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(14.0),
            w,
            "Ctrl+Alt+Home gives the keyboard back.",
        );
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(32.0),
            w,
            "Ctrl+Alt+Break switches full screen.",
        );
        y + p(50.0)
    }

    /// Equal-width segments in one rounded frame; the chosen one is raised.
    fn segmented(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        items: &[(String, bool, Hit)],
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.round_border(r, 7.0 * s, BORDER, BG);
        let pad = p(3.0);
        let n = items.len().max(1) as i32;
        let inner = r.w - 2 * pad;
        for (i, (text, on, hit)) in items.iter().enumerate() {
            let i = i as i32;
            let x0 = r.x + pad + inner * i / n;
            let x1 = r.x + pad + inner * (i + 1) / n;
            let cell = Rect::new(x0, r.y + pad, x1 - x0, r.h - 2 * pad);
            if *on {
                cv.round_border(cell, 5.0 * s, ACCENT_BORDER, BG_CHOSEN);
            } else if self.hover == Some(*hit) {
                cv.fill_round(cell, 5.0 * s, BG_HOVER);
            }
            let font = if *on { f.semi } else { f.ui };
            centered(
                cv,
                te,
                font,
                12.0 * s,
                cell,
                text,
                if *on { TEXT } else { TEXT_3 },
            );
            self.hits.push((cell, *hit));
        }
    }

    /// A rounded card with rows of the given heights and dividers between them;
    /// returns the row rectangles.
    fn card(&self, cv: &mut Canvas, x: i32, y: i32, w: i32, heights: &[i32]) -> Vec<Rect> {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let total: i32 = heights.iter().sum();
        cv.round_border(Rect::new(x, y, w, total), 8.0 * s, BORDER_SOFT, BG_BAR);
        let mut out = Vec::with_capacity(heights.len());
        let mut ry = y;
        for (i, &h) in heights.iter().enumerate() {
            if i > 0 {
                cv.fill(Rect::new(x + p(14.0), ry, w - p(28.0), 1), BORDER_SOFT);
            }
            out.push(Rect::new(x, ry, w, h));
            ry += h;
        }
        out
    }

    /// A card row with a label, an optional second line and a switch.
    #[allow(clippy::too_many_arguments)]
    fn card_switch(
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
                Rect::new(r.x + p(3.0), r.y + p(3.0), r.w - p(6.0), r.h - p(6.0)),
                6.0 * s,
                BG_HOVER,
            );
        }
        let text_w = (r.w - p(78.0)) as f32;
        let mid = r.y + r.h / 2;
        if sub.is_empty() {
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(14.0)) as f32,
                (mid + p(5.0)) as f32,
                label,
                TEXT,
                text_w,
            );
        } else {
            te.draw(
                cv,
                f.ui,
                13.0 * s,
                (r.x + p(14.0)) as f32,
                (mid - p(2.0)) as f32,
                label,
                TEXT,
                text_w,
            );
            te.draw(
                cv,
                f.ui,
                11.5 * s,
                (r.x + p(14.0)) as f32,
                (mid + p(14.0)) as f32,
                sub,
                TEXT_3,
                text_w,
            );
        }
        self.draw_switch(cv, r.right() - p(50.0), mid - p(10.0), on);
        self.hits.push((r, hit));
    }

    /// A card row that is one of several choices (a radio button on the right).
    #[allow(clippy::too_many_arguments)]
    fn card_choice(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        sub: &str,
        chosen: bool,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.hover == Some(hit) {
            cv.fill_round(
                Rect::new(r.x + p(3.0), r.y + p(3.0), r.w - p(6.0), r.h - p(6.0)),
                6.0 * s,
                BG_HOVER,
            );
        }
        let text_w = (r.w - p(64.0)) as f32;
        let mid = r.y + r.h / 2;
        let font = if chosen { f.semi } else { f.ui };
        te.draw(
            cv,
            font,
            13.0 * s,
            (r.x + p(14.0)) as f32,
            (mid - p(2.0)) as f32,
            label,
            TEXT,
            text_w,
        );
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            (r.x + p(14.0)) as f32,
            (mid + p(14.0)) as f32,
            sub,
            TEXT_3,
            text_w,
        );
        let (cx, cy) = ((r.right() - p(26.0)) as f32, mid as f32);
        if chosen {
            cv.fill_circle(cx, cy, 9.0 * s, ACCENT);
            cv.stroke(
                &[
                    (cx - 4.0 * s, cy),
                    (cx - 1.2 * s, cy + 3.0 * s),
                    (cx + 4.2 * s, cy - 3.2 * s),
                ],
                1.8 * s,
                ACCENT_TEXT,
            );
        } else {
            cv.fill_circle(cx, cy, 9.0 * s, BORDER_HOVER);
            cv.fill_circle(cx, cy, 7.5 * s, BG_BAR);
        }
        self.hits.push((r, hit));
    }

    /// A one-line card row that is one of several choices.
    #[allow(clippy::too_many_arguments)]
    fn card_radio(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        chosen: bool,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        if self.hover == Some(hit) {
            cv.fill_round(
                Rect::new(r.x + p(3.0), r.y + p(3.0), r.w - p(6.0), r.h - p(6.0)),
                6.0 * s,
                BG_HOVER,
            );
        }
        let mid = r.y + r.h / 2;
        let font = if chosen { f.semi } else { f.ui };
        te.draw(
            cv,
            font,
            12.5 * s,
            (r.x + p(14.0)) as f32,
            (mid + p(5.0)) as f32,
            label,
            TEXT,
            (r.w - p(64.0)) as f32,
        );
        let (cx, cy) = ((r.right() - p(26.0)) as f32, mid as f32);
        if chosen {
            cv.fill_circle(cx, cy, 9.0 * s, ACCENT);
            cv.stroke(
                &[
                    (cx - 4.0 * s, cy),
                    (cx - 1.2 * s, cy + 3.0 * s),
                    (cx + 4.2 * s, cy - 3.2 * s),
                ],
                1.8 * s,
                ACCENT_TEXT,
            );
        } else {
            cv.fill_circle(cx, cy, 9.0 * s, BORDER_HOVER);
            cv.fill_circle(cx, cy, 7.5 * s, BG_BAR);
        }
        self.hits.push((r, hit));
    }

    fn draw_switch(&self, cv: &mut Canvas, x: i32, y: i32, on: bool) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let sw = Rect::new(x, y, p(36.0), p(20.0));
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
    }

    /// A small upper-case heading above a card.
    #[allow(clippy::too_many_arguments)]
    fn caption(
        &self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        text: &str,
    ) {
        let s = self.scale;
        te.draw_in(
            cv,
            f.semi,
            11.0 * s,
            Rect::new(x + (4.0 * s) as i32, y, w, (18.0 * s) as i32),
            0.0,
            text,
            TEXT_3,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn hint(
        &self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        text: &str,
    ) {
        let s = self.scale;
        te.draw(
            cv,
            f.ui,
            11.5 * s,
            x as f32,
            y as f32,
            text,
            TEXT_4,
            w as f32,
        );
    }

    /// Hits of rows scrolled out of `area` must not catch clicks.
    fn clip_hits(&mut self, from: usize, area: Rect) {
        let mut i = from;
        while i < self.hits.len() {
            let r = self.hits[i].0.intersect(area);
            if r.w <= 0 || r.h <= 0 {
                self.hits.remove(i);
            } else {
                self.hits[i].0 = r;
                i += 1;
            }
        }
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
        // A saved password shows as dots, like a filled field; focusing it
        // says that typing replaces it.
        let saved = placeholder == SAVED_MASK;
        let placeholder = if saved && focused {
            "Type to replace the saved password"
        } else {
            placeholder
        };
        if display.is_empty() && !focused {
            let color = if saved { TEXT_2 } else { TEXT_4 };
            te.draw_in(cv, f.ui, size, r, pad, placeholder, color);
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

/// A small app glyph: four tiles in a 14 px square (at scale 1).
fn app_glyph(cv: &mut Canvas, s: f32, x: i32, y: i32, color: u32) {
    let p = |v: f32| (v * s).round() as i32;
    for (dx, dy) in [(0.0, 0.0), (8.0, 0.0), (0.0, 8.0), (8.0, 8.0)] {
        cv.fill_round(
            Rect::new(x + p(dx), y + p(dy), p(6.0), p(6.0)),
            1.5 * s,
            color,
        );
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

/// "host" or "host:port" (443 by default); None when empty.
fn parse_gateway(text: &str) -> Option<(String, u16)> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let t = t.trim_start_matches("https://").trim_end_matches('/');
    match t.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => {
            Some((h.to_string(), p.parse().unwrap_or(443)))
        }
        _ => Some((t.to_string(), 443)),
    }
}

fn size_index(w: u16, h: u16) -> usize {
    SIZES.iter().position(|&s| s == (w, h)).map_or(0, |i| i + 1)
}

/// The Connect action for a resolved connection; with `app`, a RemoteApp
/// session that starts it (the app sizes the desktop to the monitors).
fn session_action(r: &Connection, password: &str, app: Option<&AppEntry>) -> Action {
    let mut cfg = rdp::Config::new(&r.host, &r.user, password);
    cfg.port = r.port;
    cfg.remote_app = app.map(AppEntry::remote_app);
    #[cfg(windows)]
    if r.kerberos {
        cfg.auth = Some(crate::sspi::factory());
    }
    if let Some(gw) = parse_gateway(&r.gateway) {
        // The gateway login uses the connection's credentials.
        let mut g = rdp::GatewayConfig::new(&gw.0, &r.user, password);
        g.port = gw.1;
        cfg.gateway = Some(g);
    }
    let fit = r.width == 0 && app.is_none();
    if r.width != 0 {
        cfg.width = r.width;
        cfg.height = r.height;
    }
    Action::Connect {
        name: r.name.clone(),
        cfg: Box::new(cfg),
        fit,
        opts: r.options.clone(),
        apps: if app.is_some() {
            r.apps.clone()
        } else {
            Vec::new()
        },
    }
}

/// The Settings page (with the vault open when `vault`).
pub fn sample_settings(vault: bool) -> Ui {
    let mut m = sample(false);
    m.settings_open = true;
    if vault {
        m.store.vault_sample();
        m.change_master = true;
    }
    m
}

/// The connection editor on `page` for a top-level connection.
pub fn sample_form(page: u8) -> Ui {
    let mut m = sample(false);
    m.store.connections[2].password = Some("sample".into());
    m.select(2);
    m.focus = None;
    m.form_page = page;
    m.speakers = vec![
        "Speakers (Realtek Audio)".into(),
        "Headset (USB Audio)".into(),
    ];
    m.mics = vec!["Headset microphone (USB Audio)".into()];
    let mon =
        |name: &str, left: i32, w: u32, h: u32, primary: bool| crate::monitors::LocalMonitor {
            name: name.into(),
            monitor: rdp::Monitor::new(left, 0, w, h, primary),
        };
    m.local_monitors = vec![
        mon(r"\.\DISPLAY2", -1920, 1920, 1080, false),
        mon(r"\.\DISPLAY1", 0, 2560, 1440, true),
        mon(r"\.\DISPLAY3", 2560, 1920, 1080, false),
    ];
    m.opts.monitors = vec![r"\.\DISPLAY1".into(), r"\.\DISPLAY3".into()];
    m.opts.sound = true;
    m.opts.microphone = true;
    m.opts.clipboard = true;
    m.opts.drives = vec![r"C:\Share".into()];
    m
}

/// A session tab waiting for the user to trust the server certificate.
pub fn sample_cert(changed: bool) -> Ui {
    let mut m = sample(true);
    if let Some(t) = m.tab_mut(1) {
        t.state = TabState::Connecting;
        t.cert = Some(CertPrompt {
            fingerprint: (0..32u8)
                .map(|b| format!("{:02X}", b.wrapping_mul(37)))
                .collect::<Vec<_>>()
                .join(":"),
            changed,
            host: "10.0.0.15".into(),
        });
    }
    m
}

/// A session tab with the quick panel on `page`; page 2 shows a quality
/// change waiting for a reconnect. `fullscreen` lays it out full screen.
pub fn sample_panel(page: u8, fullscreen: bool) -> Ui {
    let mut m = sample(true);
    m.drawer_page = page;
    m.fullscreen = fullscreen;
    m.speakers = vec![
        "Speakers (Realtek Audio)".into(),
        "Headset (USB Audio)".into(),
    ];
    if let Some(t) = m.tab_mut(1) {
        t.clipboard = true;
        t.sound = true;
        t.speaker = Some("Headset (USB Audio)".into());
        if page == 2 {
            t.quality.wallpaper = false;
        }
        if page == 3 {
            // Redirected after logon, with network auto-detect results.
            t.redirected_to = Some("rdsh2.corp.example".into());
            t.network = Some("RTT 14 ms · 50.0 Mbit/s".into());
        }
    }
    m
}

/// A running RemoteApp tab for the sample's "Office apps" connection: Excel
/// open with a dialog, Word starting.
fn sample_apps_session(m: &mut Ui, active: bool) {
    let apps = m.store.connections[3].apps.clone();
    let before = m.active;
    m.open_tab(3, "Office apps".into(), "apps.corp.example".into(), false);
    let icon = |rgb: u32| {
        let mut px = Vec::new();
        for y in 0..16u32 {
            for x in 0..16u32 {
                let edge = x == 0 || y == 0 || x == 15 || y == 15;
                let c = if edge { 0xFFFFFF } else { rgb };
                px.extend([(c >> 16) as u8, (c >> 8) as u8, c as u8, 255]);
            }
        }
        Some((16, 16, px))
    };
    if let Some(t) = m.tab_mut(3) {
        t.state = TabState::Connected {
            width: 4480,
            height: 1440,
            bpp: 32,
        };
        t.remote_app = Some(RemoteAppView {
            apps,
            windows: vec![
                AppWindowItem {
                    id: 0x2001,
                    title: "Budget 2027.xlsx - Excel".into(),
                    icon: icon(0x1D7044),
                    minimized: false,
                },
                AppWindowItem {
                    id: 0x2002,
                    title: "Q3 forecast.xlsx - Excel".into(),
                    icon: icon(0x1D7044),
                    minimized: true,
                },
            ],
            running: vec!["||Excel".into()],
            starting: vec!["||Word".into()],
        });
    }
    if !active {
        m.active = before;
    }
}

/// The editor of the "Office apps" connection (Opens: Apps), with its
/// session running so the sidebar shows the app dots.
pub fn sample_apps_form() -> Ui {
    let mut m = sample(false);
    sample_apps_session(&mut m, false);
    m.select(3);
    m.focus = None;
    m.field_mut(Field::AppProgram)
        .set(r"\\fs01\tools\timesheet.exe");
    m.set_message("Added Expense report. Save keeps it.", TEXT_2);
    m
}

/// The RemoteApp session tab.
pub fn sample_apps_tab() -> Ui {
    let mut m = sample(false);
    sample_apps_session(&mut m, true);
    m.set_message("Connected: apps.corp.example (4480×1440).", TEXT_2);
    m
}

/// The sample with the "Work" group open (snapshot of the group form).
pub fn sample_group() -> Ui {
    let mut m = sample(false);
    if let Some(i) = m.store.group_index("Work") {
        m.select_group(i);
    }
    // Also shows the status-bar update button.
    m.update = Some("0.2.0".into());
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
            gateway: String::new(),
            kerberos: false,
            group: "Work".into(),
            inherit: Inherit::ALL,
            ..Default::default()
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
            gateway: String::new(),
            kerberos: false,
            group: "Work/Lab".into(),
            inherit: Inherit {
                credentials: true,
                ..Default::default()
            },
            ..Default::default()
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
            gateway: String::new(),
            kerberos: false,
            group: String::new(),
            inherit: Inherit::default(),
            opens: Opens::Desktop,
            apps: Vec::new(),
        },
        Connection {
            name: "Office apps".into(),
            host: "apps.corp.example".into(),
            port: 3389,
            user: r"CORP\alex".into(),
            password: Some("sample".into()),
            opens: Opens::Apps,
            apps: vec![
                AppEntry {
                    name: "Excel".into(),
                    program: "||Excel".into(),
                    ..Default::default()
                },
                AppEntry {
                    name: "Word".into(),
                    program: "||Word".into(),
                    ..Default::default()
                },
                AppEntry {
                    name: "Expense report".into(),
                    program: r"C:\Tools\expenses.exe".into(),
                    args: "/user %USERNAME%".into(),
                    working_dir: r"C:\Tools".into(),
                },
            ],
            ..Default::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_stays_in_the_master_password_panel() {
        let mut m = sample(false);
        m.activate(Hit::SavePassword); // no vault yet: opens the set-master panel
        assert!(m.vault_setup);
        assert_eq!(m.focus, Some(Field::Master));
        m.key(Key::Tab);
        assert_eq!(m.focus, Some(Field::MasterConfirm));
        m.key(Key::Tab);
        assert_eq!(m.focus, Some(Field::Master));
        m.key(Key::BackTab);
        assert_eq!(m.focus, Some(Field::MasterConfirm));

        let mut locked = Ui::new(Store::locked_sample(), 1.0);
        locked.key(Key::Tab);
        assert_eq!(locked.focus, Some(Field::Master));
    }

    #[test]
    fn tab_skips_hidden_fields_of_a_group_form() {
        let mut m = sample_group();
        m.focus = Some(Field::Name);
        m.key(Key::Tab);
        assert_eq!(
            m.focus,
            Some(Field::GroupPath),
            "groups have no host or port"
        );
    }

    #[test]
    fn a_tall_form_scrolls_and_hidden_rows_take_no_clicks() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return; // no UI font on this machine (headless CI)
        };
        let mut m = sample(false);
        m.select(2); // top level, no inheritance: every row shown
        m.form_page = 2; // Experience: the tallest page
        let (w, h) = (1100usize, 520usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert!(
            m.home_content > m.home_area.h,
            "form taller than the window"
        );
        let inside = |m: &Ui| {
            m.hits
                .iter()
                .all(|(r, h)| !matches!(h, Hit::Connect) || r.y >= m.home_area.y)
        };
        let (cx, cy) = (m.home_area.x + 50, m.home_area.y + 50);
        assert!(m.scroll_home(cx, cy, -100.0), "scrolls down");
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert_eq!(
            m.home_scroll,
            m.home_content - m.home_area.h,
            "clamped at the end"
        );
        assert!(inside(&m));
        assert!(
            m.hits.iter().any(|(_, h)| *h == Hit::FormExperience(6)),
            "the last row is reachable"
        );
        assert!(m.scroll_home(cx, cy, 100.0));
        assert_eq!(m.home_scroll, 0);
        assert!(!m.scroll_home(cx, cy, 5.0), "already at the top");
    }

    #[test]
    fn gateway_text_parses() {
        assert_eq!(parse_gateway(""), None);
        assert_eq!(
            parse_gateway("rdg.example.com"),
            Some(("rdg.example.com".into(), 443))
        );
        assert_eq!(
            parse_gateway("https://rdg:8443/"),
            Some(("rdg".into(), 8443))
        );
    }

    #[test]
    fn quit_question_blocks_everything_else() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return;
        };
        let mut m = sample(true);
        m.confirm_exit = Some(2);
        let (w, h) = (1000usize, 700usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert!(
            m.session_area.is_none(),
            "no session picture under the dialog"
        );
        assert!(
            m.hits
                .iter()
                .all(|(_, h)| matches!(h, Hit::Modal | Hit::ExitConfirm | Hit::ExitCancel))
        );
        assert!(
            m.key(Key::Esc).is_none() && m.confirm_exit.is_none(),
            "Esc stays"
        );
    }

    #[test]
    fn full_screen_bar_hides_and_shows_at_the_top_edge() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return;
        };
        let mut m = sample_panel(0, true);
        m.drawer = false;
        let (w, h) = (1000usize, 700usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        let (_, area) = m.session_area.unwrap();
        assert_eq!(
            (area.y, area.h),
            (0, h as i32),
            "the session gets the whole screen"
        );
        assert_eq!(m.session_size_for(w as i32, h as i32), (w as i32, h as i32));
        assert!(m.session_clip.is_none());
        assert!(m.mouse_move(500, 1), "the top edge reveals the bar");
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        let clip = m.session_clip.expect("bar covers the top");
        assert!(clip.y >= 40 && m.hits.iter().any(|(_, h)| *h == Hit::FullScreen));
        assert_eq!(
            m.session_area.unwrap().1,
            area,
            "the remote size does not change"
        );
        assert!(m.mouse_move(500, 300), "leaving the bar hides it");
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert!(m.session_clip.is_none());
    }

    #[test]
    fn touch_switch_toggles_and_survives_a_speed_preset() {
        let mut m = sample(false);
        assert!(m.opts.quality.touch, "on by default");
        m.activate(Hit::FormExperience(6));
        assert!(!m.opts.quality.touch);
        assert!(m.opts.quality.visual_styles, "row 5 untouched");
        m.activate(Hit::FormPreset(PRESETS.len() - 1)); // Modem
        assert_eq!(m.opts.quality.connection, 1);
        assert!(!m.opts.quality.touch, "a speed preset keeps the choice");
        m.activate(Hit::FormExperience(6));
        assert!(m.opts.quality.touch);
    }

    #[test]
    fn touch_needs_no_reconnect() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return; // no UI font on this machine (headless CI)
        };
        let banner = |m: &mut Ui, te: &mut TextEngine| {
            let (w, h) = (1320usize, 1500usize);
            let mut px = vec![0u32; w * h];
            m.paint(&mut Canvas::new(&mut px, w, h), te, &fonts);
            m.hits.iter().any(|(_, h)| *h == Hit::Reconnect(1))
        };
        let mut m = sample_panel(2, false);
        assert!(banner(&mut m, &mut te), "wallpaper changed: reconnect");
        let t = m.tab_mut(1).unwrap();
        t.quality = t.quality_live;
        t.quality.touch = !t.quality_live.touch;
        assert!(!banner(&mut m, &mut te), "touch applies live");
    }

    /// Clicks the centre of the first hit rectangle for `hit`.
    fn click(m: &mut Ui, te: &mut TextEngine, fonts: &Fonts, hit: Hit) -> Option<Action> {
        let (w, h) = (1320usize, 860usize);
        let mut px = vec![0u32; w * h];
        m.paint(&mut Canvas::new(&mut px, w, h), te, fonts);
        let r = m
            .hits
            .iter()
            .rev()
            .find(|(_, x)| *x == hit)
            .map(|(r, _)| *r)
            .unwrap_or_else(|| panic!("{hit:?} not painted"));
        let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
        m.mouse_move(x, y);
        m.mouse_down(x, y, te, fonts);
        m.mouse_up(x, y)
    }

    #[test]
    fn a_click_on_an_app_row_launches_it() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return; // no UI font on this machine (headless CI)
        };
        let mut m = sample(false);
        // No session yet: a RemoteApp connection for Word, saved password.
        let Some(Action::Connect { cfg, apps, fit, .. }) =
            click(&mut m, &mut te, &fonts, Hit::AppRow(3, 1))
        else {
            panic!("expected Connect");
        };
        assert_eq!(cfg.remote_app.as_ref().unwrap().program, "||Word");
        assert_eq!(cfg.password, "sample");
        assert_eq!(apps.len(), 3);
        assert!(!fit);
        // With its session up (or connecting), the same click starts the
        // app in it: no new logon.
        sample_apps_session(&mut m, false);
        match click(&mut m, &mut te, &fonts, Hit::AppRow(3, 2)) {
            Some(Action::ExecApp(3, app)) => assert_eq!(app.name, "Expense report"),
            _ => panic!("expected ExecApp"),
        }
        m.tab_mut(3).unwrap().state = TabState::Connecting;
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::AppRow(3, 0)),
            Some(Action::ExecApp(3, _))
        ));
        // Ended: a new session again.
        m.tab_mut(3).unwrap().state = TabState::Ended("x".into());
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::AppRow(3, 0)),
            Some(Action::Connect { .. })
        ));
        // The connection row still opens the editor.
        assert!(click(&mut m, &mut te, &fonts, Hit::Row(3)).is_none());
        assert_eq!((m.selected, m.active), (Some(3), None));
        // The session tab launches too.
        m.tab_mut(3).unwrap().state = TabState::Connected {
            width: 1,
            height: 1,
            bpp: 32,
        };
        m.active = Some(3);
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::TabLaunch(3, 1)),
            Some(Action::ExecApp(3, a)) if a.program == "||Word"
        ));
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::RailClose(3, 0x2002)),
            Some(Action::RailClose(3, 0x2002))
        ));
    }

    #[test]
    fn an_app_without_a_password_asks_for_it() {
        let mut m = sample(false);
        m.store.connections[3].password = None;
        assert!(m.launch_app(3, 0).is_none());
        assert_eq!(m.selected, Some(3));
        assert_eq!(m.focus, Some(Field::Password));
        let msg = m.message.clone().unwrap().0;
        assert_eq!(
            msg,
            "Type the password for Office apps, then click Excel again."
        );
        // Typed into its form: the next click connects with it.
        m.field_mut(Field::Password).set("typed");
        match m.launch_app(3, 0) {
            Some(Action::Connect { cfg, .. }) => assert_eq!(cfg.password, "typed"),
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn apps_are_added_and_removed_in_the_editor() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return;
        };
        let mut m = sample(false);
        m.select(2);
        // Desktop: no apps card, no app fields in the tab order.
        assert!(!m.form_order().contains(&Field::AppProgram));
        click(&mut m, &mut te, &fonts, Hit::FormOpens(1));
        assert_eq!(m.opens, Opens::Apps);
        assert!(m.form_order().contains(&Field::AppProgram));
        // Saving Apps without an app says what to do.
        assert!(m.form().unwrap_err().contains("Add at least one app"));
        click(&mut m, &mut te, &fonts, Hit::FormAddApp);
        assert!(m.apps.is_empty());
        assert!(
            m.message
                .clone()
                .unwrap()
                .0
                .starts_with("Type the program first")
        );
        m.field_mut(Field::AppProgram)
            .set(r"C:\Windows\notepad.exe");
        click(&mut m, &mut te, &fonts, Hit::FormAddApp);
        m.field_mut(Field::AppProgram).set("||calc");
        m.field_mut(Field::AppName).set("Calculator");
        m.field_mut(Field::AppArgs).set("/x");
        assert!(m.key(Key::Enter).is_none(), "Enter in the add row adds");
        let names: Vec<&str> = m.apps.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["Notepad", "Calculator"]);
        assert_eq!(m.apps[1].args, "/x");
        assert!(m.field(Field::AppProgram).text.is_empty(), "the row clears");
        // The same name twice is refused in plain words.
        m.field_mut(Field::AppProgram).set("notepad.exe");
        click(&mut m, &mut te, &fonts, Hit::FormAddApp);
        assert_eq!(m.apps.len(), 2);
        assert!(
            m.message
                .clone()
                .unwrap()
                .0
                .contains("already an app called Notepad")
        );
        m.field_mut(Field::AppProgram).set(&"x".repeat(261));
        m.field_mut(Field::AppName).set("Long");
        assert!(m.form_add_app().unwrap_err().contains("260 characters"));
        // Remove, then save: the store keeps the change.
        click(&mut m, &mut te, &fonts, Hit::FormRemoveApp(0));
        assert_eq!(m.apps.len(), 1);
        let c = m.form().unwrap();
        assert_eq!(
            (c.opens, c.apps[0].program.as_str()),
            (Opens::Apps, "||calc")
        );
        // Back to Desktop keeps the list for later, but connects a desktop.
        click(&mut m, &mut te, &fonts, Hit::FormOpens(0));
        assert_eq!(m.opens, Opens::Desktop);
        m.field_mut(Field::Password).set("pw");
        match m.connect() {
            Some(Action::Connect { cfg, .. }) => assert!(cfg.remote_app.is_none()),
            _ => panic!("expected Connect"),
        }
    }
}
