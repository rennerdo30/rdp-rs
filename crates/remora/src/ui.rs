//! The main window: saved connections on the left, a tab strip with a
//! Connections tab (edit form) and one tab per session, a session toolbar, a
//! control drawer for live session settings and a status bar.
//!
//! Painting is immediate: every paint lays out the whole window and records
//! hit rectangles. The session picture itself is not painted here: `paint`
//! reports the session area and the app copies the remote framebuffer into
//! it, so session updates never repaint the chrome.

use ffwd_render::{Canvas, FontId, Rect, TextEngine};

use crate::icons::Icon;
use crate::kit::{self, Button, Font, Hint as KitHint, Kit, Lead, Segment, State, Variant};
use crate::store::{
    AppEntry, COMPRESSION, Connection, Group, Inherit, KeyboardMode, Opens, PRESETS, Quality,
    SessionOptions, Store, WinKeys, default_app_name, normalize_path, parent_of, preset_name,
};
use crate::text_field::TextField;
use crate::theme::{self, ThemeChoice, Tone, pal, radius, size};

mod palette;
pub use palette::{SESSION_CHORD, sample as sample_palette};
mod home;
mod sidebar;
mod summary;
pub use sidebar::{Divider, sample_rail, sample_resized};

pub use home::ThumbDue;
pub mod session_view;
pub use session_view::Live;

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

/// Main window layout in logical px; `session_size_for` uses the same.
/// The sidebar and the session panel start at these widths; the user can
/// drag both (see `sidebar`).
pub const SIDEBAR_W: f32 = 264.0;
const STRIP_H: f32 = 40.0;
const STATUS_H: f32 = 28.0;
pub const DRAWER_W: f32 = 320.0;

/// Text size of text fields (logical px); the caret maths uses it too.
const FIELD_TEXT: f32 = 13.0;

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
    /// The Home view's quick connect field.
    Quick,
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

/// One sidebar row: a group, a connection, or one of a connection's
/// RemoteApp apps (connection, app); groups and connections with their
/// tree depth.
#[derive(Clone, Copy)]
enum Row {
    Group(usize, usize),
    Conn(usize, usize),
    App(usize, usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hit {
    Row(usize),
    /// Sidebar row: Connect (shown on hover).
    RowConnect(usize),
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
    /// Group form: colour swatch (index into GROUP_COLORS; past the end: automatic).
    FormColor(usize),
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
    /// Settings: theme (index into ThemeChoice::ALL); sidebar: dark/light toggle.
    Theme(usize),
    ThemeToggle,
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
    TabKeyboard(u64, usize),
    FormKeyboard(usize),
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
    /// Opens the command palette (sidebar search, session toolbar).
    Palette,
    /// The Home view's controls (see `home`).
    HomeView(home::HomeHit),
    /// Session toolbar: its handle (shows the pill), its menu button, and
    /// the pill's body between the buttons (takes the click, does nothing).
    ToolbarHandle,
    ToolbarMore,
    ToolbarBody,
    /// Error screen: open the connection's editor; copy the technical text.
    EditConnection(u64),
    CopyDetails(u64),
    /// Folds the sidebar to its icon rail or unfolds it (the hamburger,
    /// Ctrl+B, the palette); the rail's "+N" tile unfolds it too.
    SidebarToggle,
    RailMore,
    /// The draggable edge of the sidebar or of the session panel.
    Divider(Divider),
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
    fn tone(&self) -> Tone {
        match self {
            TabState::Connecting => Tone::Warning,
            TabState::Connected { .. } => Tone::Success,
            TabState::Ended(_) => Tone::Muted,
            TabState::Failed(_) => Tone::Danger,
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
    /// How typing reaches the session (changeable live).
    pub keyboard: KeyboardMode,
    /// The keyboard layout (KLID) the session logged on with; None until
    /// it is connected.
    pub keyboard_layout: Option<u32>,
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
    /// Connection steps, timings, and why it failed or ended.
    pub live: Live,
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
    keyboard: KeyboardMode,
    keyboard_layout: Option<u32>,
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
    /// Colour theme (Settings, or the sidebar's theme button).
    SetTheme(ThemeChoice),
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
    /// Put this text on the clipboard (error details).
    CopyText(String),
    /// The sidebar folded or unfolded, or a divider was dragged: keep the
    /// layout ([`Ui::layout_settings`]) in the settings.
    SaveLayout,
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
    /// Ctrl+F: the sidebar's search.
    Find,
    NextTab,
    PrevTab,
    /// Ctrl+K or Ctrl+Shift+P: the command palette.
    Palette,
    PageUp,
    PageDown,
    /// Ctrl+B: fold or unfold the sidebar.
    ToggleSidebar,
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
    /// The edited group's chosen colour (None: automatic).
    group_color: Option<u8>,
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
    fields: [TextField; 19],
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
    /// Colour theme choice (the app applies the palette).
    pub theme: ThemeChoice,
    /// Settings: the change-master form is open; a backup waits for its password.
    change_master: bool,
    pub import_file: Option<std::path::PathBuf>,
    pub settings_note: Option<(String, Tone)>,
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
    message: Option<(String, Tone)>,
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
    /// The command palette, while it is open.
    palette: Option<palette::Palette>,
    /// The Home view: shown, quick connect, thumbnails, session clocks.
    home: home::HomeState,
    /// The session toolbar's state and layout.
    toolbar: session_view::Toolbar,
    /// The sidebar is folded to its icon rail.
    pub sidebar_collapsed: bool,
    /// The widths the sidebar and the session panel were dragged to
    /// (logical px; painting clamps them).
    pub sidebar_w: f32,
    pub panel_w: f32,
    /// Divider drags and where the dividers were painted.
    dividers: sidebar::Dividers,
    /// The tooltip of the rail item under the pointer.
    tip: Option<sidebar::Tip>,
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
            group_color: None,
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
            theme: ThemeChoice::Dark,
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
            palette: None,
            home: home::HomeState::default(),
            toolbar: Default::default(),
            sidebar_collapsed: false,
            sidebar_w: SIDEBAR_W,
            panel_w: DRAWER_W,
            dividers: Default::default(),
            tip: None,
        };
        m.fields[Field::Password as usize] = TextField::secret();
        m.fields[Field::Master as usize] = TextField::secret();
        m.fields[Field::MasterConfirm as usize] = TextField::secret();
        m.fields[Field::NewMaster as usize] = TextField::secret();
        m.fields[Field::ImportPass as usize] = TextField::secret();
        m.store.adopt_groups();
        // The Connections tab opens on the Home view.
        m.go_home();
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

    pub fn set_message(&mut self, text: impl Into<String>, tone: Tone) {
        self.message = Some((text.into(), tone));
    }

    /// The physical size the session picture gets in a window of `w` x `h`
    /// pixels: the same layout as `paint` (sidebar, tab strip, drawer; the
    /// toolbar floats over the picture).
    pub fn session_size_for(&self, w: i32, h: i32) -> (i32, i32) {
        let p = |v: f32| (v * self.scale).round() as i32;
        let (mut aw, ah) = if self.fullscreen {
            (w, h)
        } else {
            // Sidebar, the content panel's 1 px edges, tab strip and
            // status bar.
            let side_w = self.sidebar_px(w);
            (w - side_w - 1, h - p(STATUS_H) - p(STRIP_H) - 1)
        };
        if self.drawer {
            aw -= self.panel_px(aw) + 1;
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
            keyboard: KeyboardMode::default(),
            keyboard_layout: None,
            speaker: None,
            microphone: false,
            mic: None,
            recording: false,
            spanned: false,
            remote_app: None,
            redirected_to: None,
            network: None,
            live: Live::default(),
        });
        self.active = Some(id);
        self.session_focus = false;
    }

    pub fn close_tab(&mut self, id: u64) {
        let Some(i) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        self.session_ended(id);
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
        self.home.showing = false;
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
        self.home.showing = false;
        self.group_edit = Some(Some(g.path.clone()));
        for f in FORM {
            self.field_mut(f).set("");
        }
        self.field_mut(Field::Name).set(g.name());
        self.field_mut(Field::GroupPath).set(g.parent());
        self.field_mut(Field::User).set(&g.user);
        self.field_mut(Field::Gateway).set(&g.gateway);
        self.kerberos = g.kerberos;
        self.group_color = g.color;
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

    /// A new connection; inside a group it inherits everything to start with.
    fn new_connection_in(&mut self, group: &str) {
        self.selected = None;
        self.home.showing = false;
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
        self.home.showing = false;
        self.group_edit = Some(None);
        self.group_color = None;
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
        // Pin and history belong to the saved connection, not the form.
        let kept = self
            .selected
            .and_then(|i| self.store.connections.get(i))
            .map(|c| (c.pinned, c.last_used, c.last_duration))
            .unwrap_or_default();
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
            pinned: kept.0,
            last_used: kept.1,
            last_duration: kept.2,
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
                self.set_message(format!("Added {n}. Save keeps it."), Tone::Muted);
            }
            Err(e) => self.set_message(e, Tone::Danger),
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
            self.set_message(format!("Starting {}…", app.name), Tone::Muted);
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
                Tone::Warning,
            );
            return None;
        }
        self.set_message(
            format!("Connecting to {} for {}…", r.host, app.name),
            Tone::Muted,
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
            color: self.group_color,
        })
    }

    fn save(&mut self) {
        if self.group_edit.is_some() {
            return self.save_group();
        }
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => return self.set_message(e, Tone::Danger),
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
            Ok(()) => self.set_message(format!("Saved {name}."), Tone::Muted),
            Err(e) => self.set_message(e, Tone::Danger),
        }
    }

    fn save_group(&mut self) {
        let g = match self.group_form() {
            Ok(g) => g,
            Err(e) => return self.set_message(e, Tone::Danger),
        };
        let old = self.group_edit.clone().flatten();
        if old.as_deref() != Some(g.path.as_str()) && self.store.group_index(&g.path).is_some() {
            return self.set_message(format!("A group {} already exists.", g.path), Tone::Danger);
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
            Ok(()) => self.set_message(format!("Saved group {path}."), Tone::Muted),
            Err(e) => self.set_message(e, Tone::Danger),
        }
    }

    fn delete(&mut self) {
        match self.group_edit.clone() {
            Some(Some(path)) => {
                self.store.delete_group(&path);
                if let Err(e) = self.store.save() {
                    return self.set_message(e, Tone::Danger);
                }
                self.set_message(
                    format!("Deleted group {path}; its connections moved up."),
                    Tone::Muted,
                );
                return self.go_home();
            }
            Some(None) => return self.go_home(),
            None => {}
        }
        let Some(i) = self.selected else { return };
        let gone = self.store.connections.remove(i);
        if let Err(e) = self.store.save() {
            return self.set_message(e, Tone::Danger);
        }
        self.set_message(format!("Deleted {}.", gone.name), Tone::Muted);
        self.go_home();
    }

    fn connect(&mut self) -> Option<Action> {
        match self.group_edit.clone() {
            Some(Some(path)) => return self.connect_all(&path),
            Some(None) => {
                self.set_message("Save the group first.", Tone::Danger);
                return None;
            }
            None => {}
        }
        let c = match self.form() {
            Ok(c) => c,
            Err(e) => {
                self.set_message(e, Tone::Danger);
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
                    self.set_message(e, Tone::Danger);
                }
            }
        }
        let r = self.store.resolve(&c);
        // Apps: Connect starts the first app (in a running session if any).
        let first = r.apps.first().filter(|_| r.opens == Opens::Apps).cloned();
        if let Some(app) = &first
            && let Some(id) = self.launch_target(&r.name, &r.host)
        {
            self.set_message(format!("Starting {}…", app.name), Tone::Muted);
            return Some(Action::ExecApp(id, app.clone()));
        }
        if r.user.is_empty() && !r.kerberos {
            self.set_message(
                "No user name: enter one here or in the group.",
                Tone::Danger,
            );
            return None;
        }
        // A typed password wins; otherwise the saved one (vault only).
        let password = if typed.is_empty() {
            r.password.clone().unwrap_or_default()
        } else {
            typed
        };
        self.set_message(format!("Connecting to {}…", r.host), Tone::Muted);
        if self.selected.is_none() {
            // Not saved: the Home view offers to save it.
            self.home_note_unsaved(&c);
        }
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
        self.set_message(msg, if n == 0 { Tone::Danger } else { Tone::Muted });
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

    /// A connection's row, and its apps' rows under it. Apps are listed
    /// whatever the connection opens: "Opens" only decides what Connect
    /// does, each app row always starts its own RemoteApp session.
    fn push_conn(&self, i: usize, depth: usize, out: &mut Vec<Row>) {
        out.push(Row::Conn(i, depth));
        let n = self.store.connections[i].apps.len();
        out.extend((0..n).map(|a| Row::App(i, a)));
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
    /// Where an inherited section comes from (the group that sets it) and
    /// its values in one line.
    fn inherited_parts(&self, parent: &str, section: u8) -> (Option<String>, String) {
        let pick: fn(&Inherit) -> bool = match section {
            0 => |i| i.credentials,
            1 => |i| i.display,
            _ => |i| i.sharing,
        };
        let Some(g) = self.store.source_of(parent, &Inherit::ALL, pick) else {
            return (None, "Inherited, but no group above sets it yet.".into());
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
        (Some(g.path.clone()), what)
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
        if self.home_visible() {
            return vec![Field::Quick];
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
        // The Apps card is on every connection's General page.
        if self.group_edit.is_none() {
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
        if let Some(h) = self.overlay_hit(x, y) {
            return Some(h);
        }
        self.hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(x, y))
            .map(|(_, h)| *h)
    }

    /// Returns true when the hover target changed (needs a repaint).
    /// Showing, hiding or hovering the session toolbar repaints only its
    /// rectangle: see [`Ui::take_overlay_damage`].
    pub fn mouse_move(&mut self, x: i32, y: i32) -> bool {
        if self.palette.is_some() && self.confirm_exit.is_none() {
            return self.palette_mouse_move(x, y);
        }
        // A divider follows the pointer (leaving the window is not a move).
        if self.resizing() {
            return (x, y) != (-1, -1) && self.drag_to(x);
        }
        // The session toolbar: the top edge shows it, leaving hides it.
        self.toolbar_pointer(x, y);
        let h = self.hit_at(x, y);
        let changed = h != self.hover
            && !matches!(
                (h, self.hover),
                (Some(Hit::Session(_)), Some(Hit::Session(_)))
            );
        let old = std::mem::replace(&mut self.hover, h);
        changed && !self.overlay_hover(old, h)
    }

    pub fn cursor_is_text(&self) -> bool {
        matches!(self.hover, Some(Hit::Field(_)))
    }

    pub fn mouse_down(&mut self, x: i32, y: i32, te: &mut TextEngine, fonts: &Fonts) {
        if self.palette.is_some() && self.confirm_exit.is_none() {
            return self.palette_mouse_down(x, y);
        }
        self.press = self.hit_at(x, y);
        if let Some(Hit::Divider(d)) = self.press {
            // A drag or a double-click; the session keeps the keyboard.
            return self.divider_press(d, x, std::time::Instant::now());
        }
        self.session_focus = matches!(self.press, Some(Hit::Session(_)));
        match self.press {
            Some(Hit::Field(f)) => {
                self.focus = Some(f);
                if let Some(&(_, r)) = self.field_rects.iter().find(|(ff, _)| *ff == f) {
                    let display = self.field(f).display();
                    let size = field_text(f) * self.scale;
                    let rel = (x - r.x) as f32 + self.field_scroll(f, r, te, fonts);
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
            Some(Hit::Session(_)) => {
                self.focus = None;
                self.toolbar_reset();
            }
            Some(_) => {}
            None => self.focus = None,
        }
    }

    pub fn mouse_up(&mut self, x: i32, y: i32) -> Option<Action> {
        if self.palette.is_some() && self.confirm_exit.is_none() {
            return self.palette_mouse_up(x, y);
        }
        let pressed = self.press.take();
        if let Some(Hit::Divider(_)) = pressed {
            return self.divider_release();
        }
        let hit = self.hit_at(x, y);
        if pressed.is_some() && pressed == hit {
            self.activate(hit?)
        } else {
            None
        }
    }

    fn activate(&mut self, hit: Hit) -> Option<Action> {
        if hit != Hit::ToolbarMore {
            self.menu_done();
        }
        match hit {
            Hit::ToolbarHandle
            | Hit::ToolbarMore
            | Hit::ToolbarBody
            | Hit::EditConnection(_)
            | Hit::CopyDetails(_) => return self.activate_view(hit),
            Hit::Row(i) => {
                self.select(i);
                self.active = None;
                self.settings_open = false;
            }
            Hit::RowConnect(i) => {
                self.select(i);
                self.active = None;
                self.settings_open = false;
                return self.connect();
            }
            Hit::GroupRow(gi) => {
                self.select_group(gi);
                self.active = None;
                self.settings_open = false;
            }
            Hit::FormColor(i) => {
                self.group_color = (i < theme::GROUP_COLORS.len()).then_some(i as u8);
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
                            "Installing restarts Remora and closes {open} open session{}. Click Update again to go ahead.",
                            if open == 1 { "" } else { "s" }
                        ),
                        Tone::Warning,
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
            Hit::Theme(i) => {
                let choice = ThemeChoice::ALL[i.min(ThemeChoice::ALL.len() - 1)];
                return Some(Action::SetTheme(choice));
            }
            // The sidebar button flips what is on screen now (System included).
            Hit::ThemeToggle => {
                let next = if pal().dark {
                    ThemeChoice::Light
                } else {
                    ThemeChoice::Dark
                };
                return Some(Action::SetTheme(next));
            }
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
            Hit::TabKeyboard(id, i) => {
                let t = self.tab_mut(id)?;
                t.keyboard = KeyboardMode::ALL[i];
            }
            Hit::FormKeyboard(i) => self.opts.keyboard = KeyboardMode::ALL[i],
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
            Hit::Home => self.go_home(),
            Hit::Tab(id) => self.active = Some(id),
            Hit::CloseTab(id) => return Some(Action::CloseTab(id)),
            Hit::Drawer => self.drawer = !self.drawer,
            Hit::SidebarToggle | Hit::RailMore => return self.toggle_sidebar(),
            // Dividers drag (see `mouse_down`); a click does nothing.
            Hit::Divider(_) => {}
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
                    self.set_message(
                        format!("Removed {}. Save keeps it.", gone.name),
                        Tone::Muted,
                    );
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
                self.set_message(format!("Starting {}…", app.name), Tone::Muted);
                return Some(Action::ExecApp(id, app));
            }
            Hit::RailFocus(id, w) => return Some(Action::RailFocus(id, w)),
            Hit::RailClose(id, w) => return Some(Action::RailClose(id, w)),
            Hit::Palette => self.open_palette(None),
            Hit::HomeView(h) => return self.home_activate(h),
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
                Tone::Muted,
            );
        } else {
            self.go_home();
        }
    }

    pub fn vault_failed(&mut self, e: String) {
        self.unlocking = false;
        self.vault_error = Some(e);
        self.focus = Some(Field::Master);
    }

    pub fn vault_locked(&mut self) {
        self.go_home();
        self.focus = Some(Field::Master);
        self.set_message("Locked.", Tone::Muted);
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
            return self.set_message("Type the folder to share, then press Add.", Tone::Muted);
        }
        if !std::path::Path::new(&path).is_dir() {
            return self.set_message(format!("{path} is not a folder."), Tone::Danger);
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
            && !self.home.showing
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
            self.set_message("Type the folder to share, then press Add.", Tone::Muted);
            return None;
        }
        if !std::path::Path::new(&path).is_dir() {
            self.set_message(format!("{path} is not a folder."), Tone::Danger);
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
        if self.palette.is_some() {
            return self.palette_key(k);
        }
        if let Key::ToggleSidebar = k {
            return self.toggle_sidebar();
        }
        let k = match self.home_key(k) {
            Ok(done) => return done,
            Err(k) => k,
        };
        if let Some(done) = self.toolbar_key(&k) {
            return done;
        }
        match k {
            Key::Palette => self.open_palette(None),
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
            Key::Find if !self.store.is_locked() && !self.fullscreen => {
                // The rail has no filter: unfold the sidebar to show it.
                let unfold = std::mem::take(&mut self.sidebar_collapsed);
                self.focus = Some(Field::Filter);
                let tf = self.field_mut(Field::Filter);
                tf.caret = tf.text.chars().count();
                tf.all = true;
                if unfold {
                    return Some(Action::SaveLayout);
                }
            }
            Key::Find => {}
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

    /// How far a focused field's text scrolls left to keep the caret in
    /// view; `inner` is the text rectangle.
    fn field_scroll(&self, f: Field, inner: Rect, te: &mut TextEngine, fonts: &Fonts) -> f32 {
        let tf = self.field(f);
        let size = field_text(f) * self.scale;
        let inner = inner.w as f32;
        let caret_x = te.measure(
            fonts.ui,
            size,
            &tf.display().chars().take(tf.caret).collect::<String>(),
        );
        (caret_x - inner + 2.0).max(0.0)
    }

    /// The whole window with no session picture (tests; the app and the
    /// snapshots copy the picture in between, see `paint_snapshot`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn paint(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.paint_window(cv, te, f);
        self.paint_overlays(cv, te, f);
    }

    /// What floats over the window: the command palette and the quit
    /// question. The app paints the window, copies the session picture in,
    /// then calls this, so a palette over a session dims its picture.
    pub fn paint_overlays(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        // The session toolbar and reconnect card first: they float over
        // the picture, under the palette.
        self.paint_session_overlay(cv, te, f);
        if self.palette.is_some() && self.confirm_exit.is_none() {
            self.paint_palette(cv, te, f);
            self.toolbar_clear();
        }
        if let Some(n) = self.confirm_exit {
            self.paint_exit_confirm(cv, te, f, n);
        }
    }

    /// "Quit Remora?" over the dimmed window; nothing else takes clicks.
    fn paint_exit_confirm(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, n: usize) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        let all = Rect::new(0, 0, w, h);
        // The session picture and its toolbar are not drawn under the dialog.
        self.session_area = None;
        self.toolbar_clear();
        self.hits.clear();
        self.title_controls.clear();
        self.hits.push((all, Hit::Modal));
        let cw = p(440.0).min(w - p(32.0));
        let ch = p(196.0);
        let r = Rect::new((w - cw) / 2, (h - ch) / 2, cw, ch);
        let line = if n == 1 {
            "1 session is open and will be disconnected.".to_string()
        } else {
            format!("{n} sessions are open and will be disconnected.")
        };
        {
            let mut k = Kit::new(cv, te, f, s);
            k.scrim(all);
            k.dialog(r);
            let d = p(44.0);
            let tile = Rect::new(r.x + p(28.0), r.y + p(28.0), d, d);
            k.cv.fill_round(tile, 12.0 * s, c.danger_subtle);
            k.icon_in(Icon::Power, tile, 22.0, c.danger);
            let tx = tile.right() + p(16.0);
            let tw = r.right() - tx - p(28.0);
            k.text(
                Font::Semi,
                size::HEADING + 2.0,
                tx,
                r.y + p(46.0),
                "Quit Remora?",
                c.text,
                tw,
            );
            k.text(
                Font::Regular,
                12.5,
                tx,
                r.y + p(68.0),
                &line,
                c.text_secondary,
                tw,
            );
            k.hints(
                tx,
                r.y + p(98.0),
                tw,
                &[KitHint::Keys("Esc"), KitHint::Text("stays")],
            );
        }
        let by = r.bottom() - p(28.0) - p(36.0);
        let quit = Button::new("Disconnect and quit", Variant::Danger).icon(Icon::Power);
        let cancel = Button::secondary("Cancel");
        let (qw, cw2) = (self.btn_w(te, f, &quit), self.btn_w(te, f, &cancel));
        let qx = r.right() - p(28.0) - qw;
        self.btn(
            cv,
            te,
            f,
            Rect::new(qx, by, qw, p(36.0)),
            &quit,
            Hit::ExitConfirm,
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(qx - p(8.0) - cw2, by, cw2, p(36.0)),
            &cancel,
            Hit::ExitCancel,
        );
    }

    pub fn paint_window(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        self.hits.clear();
        self.field_rects.clear();
        self.session_area = None;
        self.title_controls.clear();
        self.caption = Rect::default();
        self.tip = None;
        self.dividers.panel_x = None;
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        cv.fill(Rect::new(0, 0, w, h), c.bg_sidebar);
        // Full screen: the session with its toolbar and panel, nothing else.
        if self.fullscreen
            && let Some(id) = self.active_tab().map(|t| t.id)
        {
            cv.fill(Rect::new(0, 0, w, h), c.bg);
            self.title_height = 0;
            self.paint_session(cv, te, f, Rect::new(0, 0, w, h), id);
            return;
        }
        let bar_h = p(STATUS_H);
        let body_h = h - bar_h;
        let side_w = self.sidebar_px(w);
        let strip_h = p(STRIP_H);

        // The content panel sits in the chrome with a rounded top-left
        // corner and a 1 px edge; the active tab opens into it.
        let panel = Rect::new(side_w, strip_h, w - side_w, body_h - strip_h);
        let old = cv.set_clip(panel);
        cv.round_border(
            Rect::new(panel.x, panel.y, panel.w + p(24.0), panel.h + p(24.0)),
            radius::CARD * s,
            c.border,
            c.bg,
        );
        cv.set_clip(old);
        let content = Rect::new(panel.x + 1, panel.y + 1, panel.w - 1, panel.h - 1);

        if self.sidebar_collapsed {
            self.paint_rail(cv, te, f, Rect::new(0, 0, side_w, body_h));
        } else {
            self.paint_sidebar(cv, te, f, Rect::new(0, 0, side_w, body_h));
        }
        self.paint_tabs(cv, te, f, Rect::new(side_w, 0, w - side_w, strip_h));
        match self.active_tab().map(|t| t.id) {
            Some(id) => self.paint_session(cv, te, f, content, id),
            None if self.store.is_locked() || self.vault_setup => {
                self.paint_vault(cv, te, f, content)
            }
            None if self.settings_open => self.paint_settings(cv, te, f, content),
            None if self.home.showing => self.paint_home_view(cv, te, f, content),
            None => self.paint_home(cv, te, f, content),
        }
        self.paint_status(cv, te, f, Rect::new(0, body_h, w, bar_h));
        // Last, so its grip wins over the rows and the picture beside it.
        self.paint_divider(cv, Divider::Sidebar, side_w, strip_h, body_h);
    }

    /// The status bar: the last message (with a tone dot), the update
    /// button and the renderer note.
    fn paint_status(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, bar: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let right = format!("{} renderer · damage-only presents", self.renderer);
        let text_w = k.measure(Font::Regular, 11.5, &right);
        let mut rw = text_w + p(14.0);
        k.text_in(
            Font::Regular,
            11.5,
            Rect::new(bar.right() - text_w - p(14.0), bar.y, text_w + 1, bar.h),
            &right,
            c.text_faint,
        );
        let mut update_hit = None;
        if let Some(v) = self.update.clone() {
            let text = if self.update_busy {
                format!("Updating to {v}…")
            } else {
                format!("Update to {v}")
            };
            let b = Button::secondary(&text)
                .icon(Icon::Download)
                .icon_color(c.accent);
            let bw = k.button_width(&b) - p(6.0);
            let r = Rect::new(
                bar.right() - rw - p(12.0) - bw,
                bar.y + p(3.0),
                bw,
                bar.h - p(6.0),
            );
            let hover = self.hover == Some(Hit::Update) && !self.update_busy;
            k.button(
                r,
                &b,
                State {
                    hover,
                    disabled: self.update_busy,
                    ..State::default()
                },
            );
            update_hit = Some(r);
            rw += bw + p(16.0);
        }
        let room = Rect::new(bar.x + p(14.0), bar.y, bar.w - rw - p(40.0), bar.h);
        let cy = bar.y + bar.h / 2;
        if self.session_focus && self.active.is_some() {
            let d = p(14.0);
            k.icon(Icon::Keyboard, room.x, cy - d / 2, 14.0, c.accent);
            let x = room.x + p(22.0);
            let end = k.text_in(
                Font::Regular,
                12.0,
                Rect::new(x, bar.y, room.w - p(22.0), bar.h),
                "Keyboard goes to the remote session",
                c.text_secondary,
            );
            k.hints(
                end + p(6.0),
                cy,
                room.right() - end,
                &[
                    KitHint::Keys("Ctrl+Alt+Home"),
                    KitHint::Text("gives it back"),
                    KitHint::Keys(SESSION_CHORD),
                    KitHint::Text("commands"),
                ],
            );
        } else {
            let (msg, tone) = self
                .message
                .clone()
                .unwrap_or_else(|| ("Ready".into(), Tone::Muted));
            let mut x = room.x;
            if !matches!(tone, Tone::Muted | Tone::Neutral) {
                k.cv.fill_circle((x + p(3.0)) as f32, cy as f32, 3.0 * s, tone.color());
                x += p(14.0);
            }
            let color = match tone {
                Tone::Danger | Tone::Warning => tone.color(),
                _ => c.text_muted,
            };
            k.text_in(
                Font::Regular,
                12.0,
                Rect::new(x, bar.y, room.right() - x, bar.h),
                &msg,
                color,
            );
        }
        if let Some(r) = update_hit {
            self.hits.push((r, Hit::Update));
        }
    }

    fn paint_sidebar(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let pad = p(12.0);
        let locked = self.store.is_locked();

        // Header in the title row: the hamburger (it folds the sidebar to
        // its rail, where it stays in the same place), the mark and the
        // name; Lock at the right.
        let menu = self.menu_button_rect();
        self.icon_btn(
            cv,
            te,
            f,
            menu,
            Icon::Menu,
            Variant::Ghost,
            Hit::SidebarToggle,
        );
        self.title_controls.push((menu.x, menu.right()));
        {
            let mut k = Kit::new(cv, te, f, s);
            k.logo(area.x + p(52.0), p(9.0), 22.0);
            let row = Rect::new(area.x + p(82.0), 0, p(100.0), p(40.0));
            k.text_in(Font::Semi, size::HEADING, row, "Remora", c.text);
        }
        // The mark and the name lead Home.
        let logo = Rect::new(area.x + p(48.0), p(4.0), p(96.0), p(32.0));
        self.hits.push((logo, Hit::HomeView(home::HomeHit::Home)));
        self.title_controls.push((logo.x, logo.right()));
        if self.store.is_vault() && !locked {
            // Narrow: the lock's icon only, clear of the name.
            let b = Button::ghost("Lock").icon(Icon::Lock);
            let bw = self.btn_w(te, f, &b);
            let r = if area.w - pad - bw >= logo.right() {
                let r = Rect::new(area.right() - pad - bw + p(4.0), p(6.0), bw, p(28.0));
                self.btn(cv, te, f, r, &b, Hit::Lock);
                r
            } else {
                let r = Rect::new(area.right() - pad - p(24.0), p(6.0), p(28.0), p(28.0));
                self.icon_btn(cv, te, f, r, Icon::Lock, Variant::Ghost, Hit::Lock);
                r
            };
            self.title_controls.push((r.x, r.right()));
        }

        // Search, with its shortcut while it is empty.
        let sr = Rect::new(pad, p(48.0), area.w - 2 * pad, p(32.0));
        // Empty and idle it opens the command palette; Ctrl+F filters the
        // list in place.
        let launcher = !locked
            && self.field(Field::Filter).text.is_empty()
            && self.focus != Some(Field::Filter);
        let placeholder = if locked {
            "Locked"
        } else if launcher {
            ""
        } else {
            "Filter connections"
        };
        self.text_input_i(
            cv,
            te,
            f,
            sr,
            Some(Icon::Search),
            Field::Filter,
            placeholder,
        );
        if launcher {
            let mut k = Kit::new(cv, te, f, s);
            let kw = k.keys_width("Ctrl+K");
            let kx = sr.right() - p(8.0) - kw;
            k.keys(kx, sr.y + (sr.h - p(18.0)) / 2, "Ctrl+K");
            // The placeholder ends before the key caps, whole.
            let tx = sr.x + p(33.0);
            let room = Rect::new(tx, sr.y, kx - p(6.0) - tx, sr.h);
            let text = ["Search or run a command…", "Search or run…", "Search…"]
                .into_iter()
                .find(|t| k.measure(Font::Regular, FIELD_TEXT, t) <= room.w)
                .unwrap_or("");
            k.text_in(Font::Regular, FIELD_TEXT, room, text, c.text_faint);
            self.hits.push((sr, Hit::Palette));
        }

        let mut list_top = p(96.0);
        if !locked {
            let b = Button::secondary("New connection")
                .icon(Icon::Plus)
                .icon_color(c.accent);
            self.btn(
                cv,
                te,
                f,
                Rect::new(pad, p(90.0), area.w - 2 * pad, p(34.0)),
                &b,
                Hit::New,
            );
            self.caption_action(
                cv,
                te,
                f,
                pad,
                p(140.0),
                area.w - 2 * pad,
                "Connections",
                "+ Group",
                Hit::NewGroup,
            );
            list_top = p(164.0);
        }

        // Footer: Settings and the theme switch.
        let foot = p(52.0);
        let fy = area.bottom() - foot;
        cv.fill(Rect::new(0, fy, area.w, 1), c.divider);
        let settings_on = self.settings_open && self.active.is_none();
        let b = Button::new(
            "Settings",
            if settings_on {
                Variant::Secondary
            } else {
                Variant::Ghost
            },
        )
        .icon(Icon::Gear);
        let bw = self.btn_w(te, f, &b);
        self.btn(
            cv,
            te,
            f,
            Rect::new(pad - p(4.0), fy + p(10.0), bw, p(32.0)),
            &b,
            Hit::OpenSettings,
        );
        let (icon, label) = if c.dark {
            (Icon::Sun, "Light")
        } else {
            (Icon::Moon, "Dark")
        };
        let b = Button::ghost(label).icon(icon);
        let bw = self.btn_w(te, f, &b);
        self.btn(
            cv,
            te,
            f,
            Rect::new(area.right() - pad - bw + p(4.0), fy + p(10.0), bw, p(32.0)),
            &b,
            Hit::ThemeToggle,
        );

        let list = Rect::new(0, list_top, area.w, fy - list_top);
        let old = cv.set_clip(list);
        let rows = self.rows();
        if self.store.connections.is_empty() && self.store.groups.is_empty() {
            let (title, sub) = if locked {
                ("Locked", "Unlock to see your connections.")
            } else {
                (
                    "No connections yet",
                    "New connection adds one; Save keeps it.",
                )
            };
            let mut k = Kit::new(cv, te, f, s);
            let x = pad + p(4.0);
            k.text(
                Font::Semi,
                size::BODY,
                x,
                list.y + p(18.0),
                title,
                c.text_secondary,
                list.w - 2 * pad,
            );
            k.paragraph(
                Font::Regular,
                size::SMALL,
                x,
                list.y + p(38.0),
                list.w - 2 * pad - p(8.0),
                sub,
                c.text_muted,
                false,
            );
        } else if rows.is_empty() {
            let mut k = Kit::new(cv, te, f, s);
            let x = pad + p(4.0);
            k.text(
                Font::Regular,
                size::BODY,
                x,
                list.y + p(18.0),
                "No match.",
                c.text_muted,
                list.w,
            );
        }
        let home = self.active.is_none() && !self.settings_open;
        let open_group = self.group_edit.clone().flatten();
        let mut y = list.y;
        let mut app_line: Option<(i32, i32)> = None;
        for row in rows {
            if y > list.bottom() {
                break;
            }
            match row {
                Row::Group(gi, depth) => {
                    app_line = None;
                    let indent = depth as i32 * p(14.0);
                    let r = Rect::new(p(8.0), y, area.w - p(16.0), p(32.0));
                    y += r.h + p(2.0);
                    let g = &self.store.groups[gi];
                    let (path, name) = (g.path.clone(), g.name().to_string());
                    let count = self.store.members(&path).count().to_string();
                    let color = theme::group_solid(self.store.group_color(&path));
                    let hovered = matches!(self.hover, Some(Hit::GroupRow(h) | Hit::GroupToggle(h)) if h == gi);
                    let chosen = home && open_group.as_deref() == Some(path.as_str());
                    if chosen {
                        cv.fill_round(r, radius::CONTROL * s, c.selected);
                        cv.fill_round(
                            Rect::new(r.x, r.y + p(8.0), p(3.0), r.h - p(16.0)),
                            1.5 * s,
                            c.accent,
                        );
                    } else if hovered {
                        cv.fill_round(r, radius::CONTROL * s, c.surface_hover);
                    }
                    let open = !self.collapsed.contains(&path);
                    let mut k = Kit::new(cv, te, f, s);
                    let cx = r.x + indent + p(6.0);
                    let chev = if open {
                        Icon::ChevronDown
                    } else {
                        Icon::ChevronRight
                    };
                    k.icon(chev, cx, r.y + (r.h - p(14.0)) / 2, 14.0, c.text_faint);
                    k.cv.fill_circle(
                        (cx + p(28.0)) as f32,
                        (r.y + r.h / 2) as f32,
                        4.0 * s,
                        color,
                    );
                    let cw = k.measure(Font::Regular, size::SMALL, &count);
                    let nx = cx + p(40.0);
                    let name_color = if chosen { c.text } else { c.text_secondary };
                    let base = k.baseline(Font::Semi, size::SMALL + 0.5, r);
                    k.text(
                        Font::Semi,
                        size::SMALL + 0.5,
                        nx,
                        base,
                        &name,
                        name_color,
                        r.right() - nx - cw - p(20.0),
                    );
                    k.text_right(
                        Font::Regular,
                        size::SMALL,
                        Rect::new(r.x, r.y, r.w - p(12.0), r.h),
                        &count,
                        c.text_faint,
                    );
                    self.hits.push((r.intersect(list), Hit::GroupRow(gi)));
                    self.hits.push((
                        Rect::new(r.x, r.y, indent + p(26.0), r.h).intersect(list),
                        Hit::GroupToggle(gi),
                    ));
                }
                Row::Conn(i, depth) => {
                    let indent = depth as i32 * p(14.0);
                    let r = Rect::new(p(8.0) + indent, y, area.w - p(16.0) - indent, p(48.0));
                    y += r.h + p(2.0);
                    self.paint_connection_row(cv, te, f, r, list, i, home);
                    app_line = Some((r.x + p(24.0), r.bottom()));
                }
                Row::App(ci, ai) => {
                    let (lx, top) = app_line.unwrap_or((p(32.0), y));
                    let r = Rect::new(lx + p(12.0), y, area.w - p(8.0) - lx - p(12.0), p(30.0));
                    y += r.h + p(2.0);
                    // The tree line from the connection's avatar.
                    cv.fill(Rect::new(lx, top, 1, r.y + r.h / 2 - top), c.border_strong);
                    cv.fill(Rect::new(lx, r.y + r.h / 2, p(8.0), 1), c.border_strong);
                    app_line = Some((lx, r.y + r.h / 2));
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
        let c = pal();
        let hit = Hit::AppRow(ci, ai);
        let hover = self.hover == Some(hit);
        if hover {
            cv.fill_round(r, radius::CONTROL * s, c.surface_hover);
        }
        let conn = &self.store.connections[ci];
        let (name, program) = (conn.apps[ai].name.clone(), conn.apps[ai].program.clone());
        let dot = self.app_dot(&conn.name, &conn.host, &program);
        let mut k = Kit::new(cv, te, f, s);
        let ic = if hover { c.accent } else { c.text_muted };
        k.icon(
            Icon::Apps,
            r.x + p(8.0),
            r.y + (r.h - p(14.0)) / 2,
            14.0,
            ic,
        );
        let text_w = r.w - p(40.0) - if dot.is_some() { p(16.0) } else { 0 };
        let base = k.baseline(Font::Regular, 12.5, r);
        let tc = if hover { c.text } else { c.text_secondary };
        k.text(Font::Regular, 12.5, r.x + p(30.0), base, &name, tc, text_w);
        if let Some(color) = dot {
            k.cv.fill_circle(
                (r.right() - p(14.0)) as f32,
                (r.y + r.h / 2) as f32,
                3.5 * s,
                color,
            );
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
                return Some(pal().success);
            }
            if live && same(&v.starting) {
                out = Some(pal().warning);
            }
        }
        out
    }

    /// A saved connection: avatar in its group's colour with a live dot,
    /// name, host and user; Connect and Edit appear on hover.
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
        let c = pal();
        let hit = Hit::Row(i);
        let hovered = matches!(self.hover, Some(Hit::Row(h) | Hit::RowConnect(h)) if h == i);
        let chosen = home && self.selected == Some(i) && self.group_edit.is_none();
        let row_bg = if chosen {
            cv.fill_round(r, radius::CONTROL * s, c.selected);
            cv.fill_round(
                Rect::new(r.x, r.y + p(12.0), p(3.0), r.h - p(24.0)),
                1.5 * s,
                c.accent,
            );
            c.selected
        } else if hovered {
            cv.fill_round(r, radius::CONTROL * s, c.surface_hover);
            c.surface_hover
        } else {
            c.bg_sidebar
        };
        let conn = self.store.resolve(&self.store.connections[i]);
        let color = self.store.connection_color(&self.store.connections[i]);
        let dot = self.connection_dot(&conn);
        let pinned = self.store.connections[i].pinned;
        let actions = if hovered {
            p(94.0)
        } else if pinned {
            p(18.0)
        } else {
            0
        };
        let mut k = Kit::new(cv, te, f, s);
        let d = p(32.0);
        k.avatar(
            Rect::new(r.x + p(8.0), r.y + (r.h - d) / 2, d, d),
            &conn.name,
            color,
            dot,
            row_bg,
        );
        let tx = r.x + p(50.0);
        let text_w = r.right() - tx - p(10.0) - actions;
        k.text(
            Font::Semi,
            size::BODY,
            tx,
            r.y + p(21.0),
            &conn.name,
            c.text,
            text_w,
        );
        let sub = match (conn.port == 3389, conn.user.is_empty()) {
            (true, true) => conn.host.clone(),
            (true, false) => format!("{} · {}", conn.host, conn.user),
            (false, true) => format!("{}:{}", conn.host, conn.port),
            (false, false) => format!("{}:{} · {}", conn.host, conn.port, conn.user),
        };
        k.text(
            Font::Regular,
            11.5,
            tx,
            r.y + p(37.0),
            &sub,
            c.text_muted,
            text_w,
        );
        if pinned && !hovered {
            k.icon(
                Icon::StarFilled,
                r.right() - p(24.0),
                r.y + (r.h - p(12.0)) / 2,
                12.0,
                c.warning,
            );
        }
        self.hits.push((r.intersect(list), hit));
        if hovered {
            let b = p(28.0);
            let y = r.y + (r.h - b) / 2;
            let edit = Rect::new(r.right() - p(6.0) - b, y, b, b);
            let play = Rect::new(edit.x - p(2.0) - b, y, b, b);
            let star = Rect::new(play.x - p(2.0) - b, y, b, b);
            self.star_btn(cv, te, f, star.intersect(list), i);
            self.icon_btn(
                cv,
                te,
                f,
                play.intersect(list),
                Icon::Play,
                Variant::Ghost,
                Hit::RowConnect(i),
            );
            self.icon_btn(
                cv,
                te,
                f,
                edit.intersect(list),
                Icon::Edit,
                Variant::Ghost,
                hit,
            );
        }
    }

    fn connection_dot(&self, conn: &Connection) -> Option<u32> {
        let mut out = None;
        for t in self
            .tabs
            .iter()
            .filter(|t| t.name == conn.name && t.host == conn.host)
        {
            match t.state {
                TabState::Connected { .. } => return Some(pal().success),
                TabState::Connecting => out = Some(pal().warning),
                _ => {}
            }
        }
        out
    }

    /// The colour of a session tab's avatar: its saved connection's.
    fn tab_color(&self, name: &str, host: &str) -> usize {
        self.store
            .connections
            .iter()
            .find(|c| c.name == name && c.host == host)
            .map_or_else(
                || theme::color_for_name(name),
                |c| self.store.connection_color(c),
            )
    }

    fn paint_tabs(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, strip: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        self.title_height = strip.bottom();
        let mut right = strip.right();
        if self.custom_frame {
            let cw = 3 * p(46.0);
            self.caption = Rect::new(strip.right() - cw, strip.y, cw, strip.h - 1);
            right = self.caption.x - p(8.0);
            self.paint_caption(cv);
        }
        let mut x = strip.x + p(8.0);
        let y = strip.y + p(6.0);
        let th = strip.bottom() - y;

        // The Connections tab.
        let label = "Connections";
        let tw = te.measure(f.ui, size::BODY * s, label) as i32 + p(48.0);
        let r = Rect::new(x, y, tw, th);
        let home = self.active.is_none();
        self.tab_shape(cv, r, home, self.hover == Some(Hit::Home));
        {
            let mut k = Kit::new(cv, te, f, s);
            let (ic, tc) = if home {
                (c.accent, c.text)
            } else {
                (c.text_muted, c.text_secondary)
            };
            let body = Rect::new(r.x, r.y, r.w, r.h - p(2.0));
            k.icon(
                Icon::Home,
                r.x + p(14.0),
                body.y + (body.h - p(15.0)) / 2,
                15.0,
                ic,
            );
            let font = if home { Font::Semi } else { Font::Regular };
            k.text_in(
                font,
                size::BODY,
                Rect::new(r.x + p(36.0), body.y, r.w - p(40.0), body.h),
                label,
                tc,
            );
        }
        self.hits.push((r, Hit::Home));
        self.title_controls.push((r.x, r.right()));
        x += tw + p(4.0);

        let tabs: Vec<(u64, String, String, u32)> = self
            .tabs
            .iter()
            .map(|t| (t.id, t.name.clone(), t.host.clone(), t.state.tone().color()))
            .collect();
        let avail = right - x - p(6.0);
        let each = if tabs.is_empty() {
            0
        } else {
            (avail / tabs.len() as i32 - p(4.0)).clamp(p(96.0), p(220.0))
        };
        for (id, name, host, dot) in tabs {
            if x + p(70.0) > right {
                break;
            }
            let r = Rect::new(x, y, each.min(right - x), th);
            self.title_controls.push((r.x, r.right()));
            let active = self.active == Some(id);
            let hover_tab = matches!(self.hover, Some(Hit::Tab(h) | Hit::CloseTab(h)) if h == id);
            self.tab_shape(cv, r, active, self.hover == Some(Hit::Tab(id)));
            let body = Rect::new(r.x, r.y, r.w, r.h - p(2.0));
            let color = self.tab_color(&name, &host);
            let ring = if active {
                c.bg
            } else if self.hover == Some(Hit::Tab(id)) {
                c.surface_hover
            } else {
                c.bg_sidebar
            };
            let show_close = active || hover_tab;
            let close = Rect::new(
                r.right() - p(30.0),
                body.y + (body.h - p(22.0)) / 2,
                p(22.0),
                p(22.0),
            );
            {
                let mut k = Kit::new(cv, te, f, s);
                let d = p(18.0);
                k.avatar(
                    Rect::new(r.x + p(10.0), body.y + (body.h - d) / 2, d, d),
                    &name,
                    color,
                    Some(dot),
                    ring,
                );
                let tx = r.x + p(36.0);
                let end = if show_close {
                    close.x - p(4.0)
                } else {
                    r.right() - p(12.0)
                };
                let (font, tc) = if active {
                    (Font::Semi, c.text)
                } else {
                    (Font::Regular, c.text_secondary)
                };
                k.text_in(
                    font,
                    size::BODY,
                    Rect::new(tx, body.y, end - tx, body.h),
                    &name,
                    tc,
                );
            }
            self.hits.push((r, Hit::Tab(id)));
            if show_close {
                self.icon_btn(
                    cv,
                    te,
                    f,
                    close,
                    Icon::Close,
                    Variant::Ghost,
                    Hit::CloseTab(id),
                );
            } else {
                self.hits.push((close, Hit::CloseTab(id)));
            }
            x += r.w + p(4.0);
        }
    }

    /// Windows 11 caption buttons (46 px each at 100 %), drawn like the
    /// system's: minimise, maximise/restore, close with a red hover.
    fn paint_caption(&mut self, cv: &mut Canvas) {
        let r = self.caption;
        let s = self.scale;
        let c = pal();
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
            let idle = if self.window_active {
                c.text_secondary
            } else {
                c.text_faint
            };
            let (fill, glyph) = match (i, hover, pressed && hover) {
                (2, true, true) => (c.close_pressed, c.on_solid),
                (2, true, false) => (c.close_hover, c.on_solid),
                (_, true, true) => (c.surface_pressed, c.text),
                (_, true, false) => (c.surface_hover, c.text),
                _ => (c.bg_sidebar, idle),
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

    /// A tab: the active one is a raised shape that opens into the content
    /// panel below; others show a soft chip on hover.
    fn tab_shape(&self, cv: &mut Canvas, r: Rect, active: bool, hover: bool) {
        let s = self.scale;
        let c = pal();
        let rad = 8.0 * s;
        if active {
            // Down to the panel's top edge (one row below the strip), which
            // it replaces, so tab and panel are one surface.
            let old = cv.set_clip(Rect::new(r.x, r.y, r.w, r.h + 1).intersect(cv.clip()));
            cv.round_border(
                Rect::new(r.x, r.y, r.w, r.h + (12.0 * s) as i32),
                rad,
                c.border,
                c.bg,
            );
            cv.set_clip(old);
        } else if hover {
            cv.fill_round(
                Rect::new(r.x, r.y, r.w, r.h - (5.0 * s) as i32),
                radius::CONTROL * s,
                c.surface_hover,
            );
        }
    }

    /// The unlock screen, or the "set a master password" panel: one
    /// centred card.
    fn paint_vault(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let old = cv.set_clip(area);
        let creating = !self.store.is_locked();
        let (title, sub) = if creating {
            (
                "Set a master password",
                "Saved passwords are encrypted with it. Forget it, and they are lost.",
            )
        } else {
            (
                "Unlock your connections",
                "Your connections and saved passwords are encrypted on this PC.",
            )
        };
        let w = p(400.0).min(area.w - p(48.0));
        let inner_w = w - p(64.0);
        let sub_lines = Kit::new(cv, te, f, s)
            .wrap(Font::Regular, 12.5, sub, inner_w)
            .len() as i32;
        let fh = p(36.0);
        let mut h = p(32.0) + p(52.0) + p(22.0) + p(30.0) + sub_lines * p(19.0) + p(16.0);
        h += fh + p(10.0);
        h += if creating { fh + p(10.0) } else { p(40.0) };
        if self.vault_error.is_some() {
            h += p(26.0);
        }
        h += p(38.0) + p(32.0);
        let card = Rect::new(
            area.x + (area.w - w) / 2,
            area.y + ((area.h - h) / 2).clamp(p(24.0), p(120.0)),
            w,
            h,
        );
        let x = card.x + p(32.0);
        let mut y = card.y + p(32.0);
        {
            let mut k = Kit::new(cv, te, f, s);
            k.dialog(card);
            let d = p(52.0);
            let tile = Rect::new(card.x + (card.w - d) / 2, y, d, d);
            k.cv.fill_round(tile, 16.0 * s, c.accent_subtle);
            let icon = if creating { Icon::Key } else { Icon::Lock };
            k.icon_in(icon, tile, 24.0, c.accent);
            y += d + p(22.0);
            let tr = Rect::new(card.x, y, card.w, p(28.0));
            k.text_center(Font::Semi, 19.0, tr, title, c.text);
            y += p(30.0) + p(14.0);
            y = k.paragraph(Font::Regular, 12.5, x, y, inner_w, sub, c.text_muted, true);
            y += p(2.0);
        }
        self.text_input_i(
            cv,
            te,
            f,
            Rect::new(x, y, inner_w, fh),
            Some(Icon::Key),
            Field::Master,
            "Master password",
        );
        y += fh + p(10.0);
        if creating {
            self.text_input_i(
                cv,
                te,
                f,
                Rect::new(x, y, inner_w, fh),
                Some(Icon::Key),
                Field::MasterConfirm,
                "Repeat the master password",
            );
            y += fh + p(10.0);
        } else {
            let r = Rect::new(x - p(8.0), y, inner_w + p(16.0), p(36.0));
            let on = self.remember;
            let st = self.st(Hit::Remember);
            let mut k = Kit::new(cv, te, f, s);
            if st.hover {
                k.cv.fill_round(r, radius::CONTROL * s, c.surface_hover);
            }
            k.switch(x, r.y + (r.h - p(20.0)) / 2, on, st);
            k.text_in(
                Font::Regular,
                12.5,
                Rect::new(x + p(48.0), r.y, inner_w - p(48.0), r.h),
                "Remember on this PC (Windows account)",
                c.text_secondary,
            );
            self.hits.push((r, Hit::Remember));
            y += p(40.0);
        }
        if let Some(e) = self.vault_error.clone() {
            let mut k = Kit::new(cv, te, f, s);
            k.icon(Icon::Warning, x, y + p(2.0), 14.0, c.danger);
            k.text(
                Font::Regular,
                12.5,
                x + p(22.0),
                y + p(13.0),
                &e,
                c.danger,
                inner_w - p(22.0),
            );
            y += p(26.0);
        }
        let bh = p(38.0);
        y += p(4.0);
        if self.unlocking {
            let busy = if creating {
                "Encrypting…"
            } else {
                "Unlocking…"
            };
            let b = Button::secondary(busy).icon(Icon::Refresh);
            Kit::new(cv, te, f, s).button(
                Rect::new(x, y, inner_w, bh),
                &b,
                State {
                    disabled: true,
                    ..State::default()
                },
            );
        } else if creating {
            let half = (inner_w - p(8.0)) / 2;
            self.btn(
                cv,
                te,
                f,
                Rect::new(x, y, inner_w - half - p(8.0), bh),
                &Button::secondary("Cancel"),
                Hit::CancelVault,
            );
            self.btn(
                cv,
                te,
                f,
                Rect::new(x + inner_w - half, y, half, bh),
                &Button::primary("Set password").icon(Icon::Check),
                Hit::CreateVault,
            );
        } else {
            self.btn(
                cv,
                te,
                f,
                Rect::new(x, y, inner_w, bh),
                &Button::primary("Unlock").icon(Icon::Unlock),
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
            self.settings_note = Some(("Enter your current master password.".into(), Tone::Danger));
            return None;
        }
        if new.chars().count() < 8 {
            self.settings_note = Some((
                "Use at least 8 characters for the new one.".into(),
                Tone::Danger,
            ));
            return None;
        }
        if new != again {
            self.settings_note = Some(("The two new passwords differ.".into(), Tone::Danger));
            return None;
        }
        for f in [Field::Master, Field::NewMaster, Field::MasterConfirm] {
            self.field_mut(f).set("");
        }
        self.unlocking = true;
        self.settings_note = Some(("Changing the master password…".into(), Tone::Muted));
        Some(Action::ChangeMaster { current, new })
    }

    fn import_action(&mut self) -> Option<Action> {
        let path = self.import_file.clone()?;
        let password = zeroize::Zeroizing::new(self.field(Field::ImportPass).text.clone());
        if password.is_empty() {
            self.settings_note = Some(("Enter the backup's master password.".into(), Tone::Danger));
            return None;
        }
        self.field_mut(Field::ImportPass).set("");
        self.unlocking = true;
        self.settings_note = Some(("Opening the backup…".into(), Tone::Muted));
        Some(Action::Import { path, password })
    }

    /// The app reports the end of a settings job (change master, export, import).
    pub fn settings_done(&mut self, ok: bool, text: String) {
        self.unlocking = false;
        if ok {
            self.change_master = false;
            self.import_file = None;
        }
        self.settings_note = Some((text, if ok { Tone::Success } else { Tone::Danger }));
    }

    /// App settings: appearance, security, backup, updates, troubleshooting.
    fn paint_settings(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        self.home_area = area;
        let top = area.y - self.home_scroll;
        let x = area.x + p(40.0);
        let w = p(640.0).min(area.w - p(80.0)).max(p(300.0));
        {
            let mut k = Kit::new(cv, te, f, s);
            let d = p(52.0);
            let tile = Rect::new(x, top + p(28.0), d, d);
            k.cv.round_border(tile, d as f32 * 0.28, c.border, c.surface_raised);
            k.icon_in(Icon::Gear, tile, 24.0, c.accent);
            let tx = x + d + p(16.0);
            k.text(
                Font::Semi,
                size::TITLE,
                tx,
                top + p(52.0),
                "Settings",
                c.text,
                w,
            );
            let version = format!("Remora {}", env!("CARGO_PKG_VERSION"));
            k.text(
                Font::Regular,
                12.5,
                tx,
                top + p(74.0),
                &version,
                c.text_muted,
                w,
            );
        }
        let mut y = top + p(104.0);
        if let Some((note, tone)) = self.settings_note.clone() {
            let icon = match tone {
                Tone::Danger | Tone::Warning => Icon::Warning,
                Tone::Success => Icon::Check,
                _ => Icon::Info,
            };
            let tone = if tone == Tone::Muted {
                Tone::Info
            } else {
                tone
            };
            Kit::new(cv, te, f, s).banner(Rect::new(x, y, w, p(46.0)), tone, icon, &note, "");
            y += p(46.0) + p(20.0);
        }

        // Appearance
        self.caption(cv, te, f, x, y, w, "Appearance");
        y += p(26.0);
        let items: Vec<(String, Option<Icon>, bool, Hit)> = ThemeChoice::ALL
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let icon = match t {
                    ThemeChoice::Dark => Icon::Moon,
                    ThemeChoice::Light => Icon::Sun,
                    ThemeChoice::System => Icon::Contrast,
                };
                (
                    t.label().to_string(),
                    Some(icon),
                    self.theme == *t,
                    Hit::Theme(i),
                )
            })
            .collect();
        self.segmented_i(cv, te, f, Rect::new(x, y, w, p(38.0)), &items);
        y += p(38.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(20.0),
            w,
            "System follows the Windows app theme and switches with it.",
        );
        y += p(32.0) + p(20.0);

        // Security
        self.caption(cv, te, f, x, y, w, "Security");
        y += p(26.0);
        let row = p(60.0);
        if self.store.is_vault() {
            let cells = self.card(cv, x, y, w, &[row, row]);
            let remembered = self.remembered;
            self.card_switch_i(
                cv,
                te,
                f,
                cells[0],
                Some(Icon::Key),
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
                Icon::Lock,
                "Master password",
                "Encrypts saved passwords and backups",
                "Change…",
                Hit::ChangeMasterOpen,
            );
            y += 2 * row + p(16.0);
            if self.change_master {
                let rh = p(52.0);
                let cells = self.card(cv, x, y, w, &[rh, rh, rh, p(60.0)]);
                self.field_row_i(
                    cv,
                    te,
                    f,
                    cells[0],
                    "Current",
                    Some(Icon::Key),
                    Field::Master,
                    "Current master password",
                );
                self.field_row_i(
                    cv,
                    te,
                    f,
                    cells[1],
                    "New",
                    Some(Icon::Key),
                    Field::NewMaster,
                    "At least 8 characters",
                );
                self.field_row_i(
                    cv,
                    te,
                    f,
                    cells[2],
                    "Again",
                    Some(Icon::Key),
                    Field::MasterConfirm,
                    "The new one once more",
                );
                let r = cells[3];
                let label = if self.unlocking {
                    "Working…"
                } else {
                    "Change password"
                };
                let ok = Button::primary(label).icon(Icon::Check);
                let ow = self.btn_w(te, f, &ok);
                let by = r.y + (r.h - p(34.0)) / 2;
                self.btn(
                    cv,
                    te,
                    f,
                    Rect::new(r.x + p(132.0), by, ow, p(34.0)),
                    &ok,
                    Hit::ChangeMasterOk,
                );
                let cancel = Button::secondary("Cancel");
                let cw = self.btn_w(te, f, &cancel);
                self.btn(
                    cv,
                    te,
                    f,
                    Rect::new(r.x + p(140.0) + ow, by, cw, p(34.0)),
                    &cancel,
                    Hit::ChangeMasterCancel,
                );
                y += 3 * rh + p(60.0) + p(16.0);
            }
            self.caption(cv, te, f, x, y, w, "Lock automatically when idle");
            y += p(26.0);
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
            self.segmented(cv, te, f, Rect::new(x, y, w, p(36.0)), &items);
            y += p(36.0) + p(28.0);
        } else {
            let cells = self.card(cv, x, y, w, &[row]);
            self.card_action(
                cv,
                te,
                f,
                cells[0],
                Icon::Shield,
                "Encrypt your connections",
                "A master password lets Remora save passwords and back up",
                "Set up…",
                Hit::SetupVault,
            );
            y += row + p(28.0);
        }

        // Backup
        self.caption(cv, te, f, x, y, w, "Backup");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[row, row]);
        self.card_action(
            cv,
            te,
            f,
            cells[0],
            Icon::Download,
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
            Icon::FolderOpen,
            "Import connections",
            "Adds the connections and groups of a backup",
            "Import…",
            Hit::Import,
        );
        y += 2 * row + p(16.0);
        if let Some(path) = self.import_file.clone() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cells = self.card(cv, x, y, w, &[p(46.0), p(52.0), p(60.0)]);
            {
                let mut k = Kit::new(cv, te, f, s);
                let r = cells[0];
                k.icon(
                    Icon::FolderOpen,
                    r.x + p(16.0),
                    r.y + (r.h - p(16.0)) / 2,
                    16.0,
                    c.accent,
                );
                k.text_in(
                    Font::Regular,
                    12.5,
                    Rect::new(r.x + p(46.0), r.y, r.w - p(62.0), r.h),
                    &format!("Import from {name}"),
                    c.text_secondary,
                );
            }
            self.field_row_i(
                cv,
                te,
                f,
                cells[1],
                "Password",
                Some(Icon::Key),
                Field::ImportPass,
                "Master password of the backup",
            );
            let r = cells[2];
            let label = if self.unlocking {
                "Working…"
            } else {
                "Import"
            };
            let ok = Button::primary(label).icon(Icon::Check);
            let ow = self.btn_w(te, f, &ok);
            let by = r.y + (r.h - p(34.0)) / 2;
            self.btn(
                cv,
                te,
                f,
                Rect::new(r.x + p(132.0), by, ow, p(34.0)),
                &ok,
                Hit::ImportOk,
            );
            let cancel = Button::secondary("Cancel");
            let cw = self.btn_w(te, f, &cancel);
            self.btn(
                cv,
                te,
                f,
                Rect::new(r.x + p(140.0) + ow, by, cw, p(34.0)),
                &cancel,
                Hit::ImportCancel,
            );
            y += p(158.0) + p(16.0);
        }
        y += p(12.0);

        // Updates
        self.caption(cv, te, f, x, y, w, "Updates");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[row, row]);
        let check = self.check_updates;
        self.card_switch_i(
            cv,
            te,
            f,
            cells[0],
            Some(Icon::Refresh),
            "Check for updates daily",
            "Ctrl+Shift+U or the status bar installs an offered update",
            check,
            Hit::CheckUpdates,
        );
        let version = format!("Installed: Remora {}", env!("CARGO_PKG_VERSION"));
        self.card_action(
            cv,
            te,
            f,
            cells[1],
            Icon::Download,
            "Check now",
            &version,
            "Check",
            Hit::CheckNow,
        );
        y += 2 * row + p(12.0);
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
        self.segmented(cv, te, f, Rect::new(x, y, w, p(36.0)), &items);
        y += p(36.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(20.0),
            w,
            "Automatic follows the installed version: beta builds get betas, stable builds stable releases.",
        );
        y += p(32.0) + p(24.0);

        // Troubleshooting
        self.caption(cv, te, f, x, y, w, "Troubleshooting");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[row, row]);
        let log_on = self.diagnostic_log;
        self.card_switch_i(
            cv,
            te,
            f,
            cells[0],
            Some(Icon::Info),
            "Diagnostic log",
            "Protocol details to remora.log; never passwords",
            log_on,
            Hit::DiagnosticLog,
        );
        self.card_action(
            cv,
            te,
            f,
            cells[1],
            Icon::Folder,
            "Log folder",
            r"%LOCALAPPDATA%\rdp-rs\logs",
            "Open",
            Hit::OpenLogFolder,
        );
        y += 2 * row;

        self.home_content = y + p(40.0) - top;
        let max = (self.home_content - area.h).max(0);
        self.home_scroll = self.home_scroll.min(max);
        Kit::new(cv, te, f, s).scrollbar(area, self.home_content, self.home_scroll);
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
    }

    /// A card row with an icon, a label, a second line and a button on the
    /// right.
    #[allow(clippy::too_many_arguments)]
    fn card_action(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Icon,
        label: &str,
        sub: &str,
        button: &str,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let b = Button::secondary(button);
        let bw = self.btn_w(te, f, &b);
        self.row_text(cv, te, f, r, Some(icon), label, sub, false, bw + p(28.0));
        self.btn(
            cv,
            te,
            f,
            Rect::new(
                r.right() - p(14.0) - bw,
                r.y + (r.h - p(32.0)) / 2,
                bw,
                p(32.0),
            ),
            &b,
            hit,
        );
    }

    /// The connection (or group) editor: a header with the avatar, status
    /// pills and the actions, a page switcher and one page of cards at a
    /// time. A section a connection takes from its group shows one switch
    /// and where the values come from.
    fn paint_home(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        self.home_area = area;
        // A breadcrumb row back to Home above the header.
        let crumb = p(26.0);
        let top = area.y - self.home_scroll + crumb;
        let x = area.x + p(40.0);
        let w = p(640.0).min(area.w - p(80.0)).max(p(300.0));
        let group_mode = self.group_edit.is_some();
        let open_group = self.group_edit.clone().flatten();
        self.paint_crumbs(cv, te, f, x, top - crumb + p(14.0), w);

        // Header: avatar, title, one line about it with pills, and the
        // actions on the right.
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
            match (host.is_empty(), user.is_empty()) {
                (true, _) => "Not saved yet".to_string(),
                (false, true) => host,
                (false, false) => format!("{host} · {user}"),
            }
        };
        let mut pills: Vec<(&str, Tone, Lead)> = Vec::new();
        let color = if let Some(path) = &open_group {
            self.store.group_color(path)
        } else if group_mode {
            self.group_color.map_or_else(
                || theme::color_for_name(&self.field(Field::Name).text),
                |c| c as usize,
            )
        } else if let Some(i) = self.selected {
            let conn = self.store.resolve(&self.store.connections[i]);
            match self.connection_dot(&conn) {
                Some(d) if d == c.success => pills.push(("Live", Tone::Success, Lead::Dot)),
                Some(_) => pills.push(("Connecting", Tone::Warning, Lead::Dot)),
                None => {}
            }
            if conn.opens == Opens::Apps {
                pills.push(("Apps", Tone::Accent, Lead::Icon(Icon::Apps)));
            }
            if conn.password.is_some() {
                pills.push(("Saved password", Tone::Neutral, Lead::Icon(Icon::Key)));
            }
            if !conn.gateway.is_empty() {
                pills.push(("Gateway", Tone::Info, Lead::Icon(Icon::Globe)));
            }
            if conn.kerberos {
                pills.push(("Windows sign-in", Tone::Neutral, Lead::Icon(Icon::Shield)));
            }
            self.store.connection_color(&self.store.connections[i])
        } else {
            let g = normalize_path(&self.field(Field::GroupPath).text);
            if g.is_empty() {
                theme::color_for_name(&self.field(Field::Name).text)
            } else {
                self.store.group_color(&g)
            }
        };

        // Actions, right to left.
        let bh = p(34.0);
        let by = top + p(26.0);
        let mut bx = x + w;
        let connect = if group_mode { "Connect all" } else { "Connect" };
        let mut buttons = vec![
            (Button::primary(connect).icon(Icon::Play), Hit::Connect),
            (Button::secondary("Save"), Hit::Save),
        ];
        if open_group.is_some() {
            buttons.push((
                Button::secondary("Connection").icon(Icon::Plus),
                Hit::NewInGroup,
            ));
        }
        if self.selected.is_some() || open_group.is_some() {
            buttons.push((
                Button::new("Delete", Variant::DangerGhost).icon(Icon::Trash),
                Hit::Delete,
            ));
        }
        if let (Some(i), false) = (self.selected, group_mode) {
            buttons.push(self.star_button(i));
        }
        for (b, hit) in &buttons {
            let bw = self.btn_w(te, f, b);
            bx -= bw;
            self.btn(cv, te, f, Rect::new(bx, by, bw, bh), b, *hit);
            bx -= p(8.0);
        }
        {
            let mut k = Kit::new(cv, te, f, s);
            let d = p(52.0);
            let av = Rect::new(x, top + p(28.0), d, d);
            if group_mode {
                let (fill, fg) = theme::group_tile(color);
                k.cv.fill_round(av, d as f32 * 0.28, fill);
                k.icon_in(Icon::Folder, av, 24.0, fg);
            } else {
                k.avatar(av, &title, color, None, c.bg);
            }
            let tx = x + d + p(16.0);
            let tw = bx - tx - p(8.0);
            k.text(
                Font::Semi,
                size::TITLE,
                tx,
                top + p(52.0),
                &title,
                c.text,
                tw,
            );
            let end = k.text(
                Font::Regular,
                12.5,
                tx,
                top + p(74.0),
                &sub,
                c.text_muted,
                tw,
            );
            let mut px = end + p(10.0);
            for (text, tone, lead) in pills {
                let pw = k.pill_width(text, lead);
                if px + pw > x + w {
                    break;
                }
                k.pill(px, top + p(62.0), text, tone, lead);
                px += pw + p(6.0);
            }
        }

        // Page switcher
        let pages: Vec<(String, Option<Icon>, bool, Hit)> = [
            ("General", Icon::Sliders),
            ("Display", Icon::Monitor),
            ("Experience", Icon::Star),
            ("Sharing", Icon::Folder),
            ("Advanced", Icon::Gear),
        ]
        .iter()
        .enumerate()
        .map(|(i, (n, icon))| {
            (
                n.to_string(),
                Some(*icon),
                self.form_page == i as u8,
                Hit::FormPage(i as u8),
            )
        })
        .collect();
        self.segmented_i(cv, te, f, Rect::new(x, top + p(104.0), w, p(38.0)), &pages);

        let mut y = top + p(164.0);
        let parent = normalize_path(&self.field(Field::GroupPath).text);
        let inh = self.form_inherit();
        y = match self.form_page {
            0 => self.form_general(cv, te, f, x, y, w, group_mode, &parent, inh),
            1 => self.form_display(cv, te, f, x, y, w, &parent, inh),
            2 => self.form_experience(cv, te, f, x, y, w, &parent, inh),
            3 => self.form_sharing(cv, te, f, x, y, w, &parent, inh),
            _ => self.form_advanced(cv, te, f, x, y, w, &parent, inh),
        };
        let cy = y + p(26.0);
        if group_mode {
            self.hint(
                cv,
                te,
                f,
                x,
                cy + p(4.0),
                w,
                "Connect all opens every member with a saved password, or the one typed here.",
            );
        } else if self.opens == Opens::Apps {
            self.key_hints(
                cv,
                te,
                f,
                x,
                cy,
                w,
                &[
                    KitHint::Keys("Enter"),
                    KitHint::Text("starts the first app"),
                    KitHint::Keys("Ctrl+S"),
                    KitHint::Text("saves · click an app in the sidebar to start it"),
                ],
            );
        } else if !self.apps.is_empty() {
            self.key_hints(
                cv,
                te,
                f,
                x,
                cy,
                w,
                &[
                    KitHint::Keys("Enter"),
                    KitHint::Text("connects the desktop"),
                    KitHint::Keys("Ctrl+S"),
                    KitHint::Text("saves · click an app in the sidebar to start it"),
                ],
            );
        } else {
            self.key_hints(
                cv,
                te,
                f,
                x,
                cy,
                w,
                &[
                    KitHint::Keys("Enter"),
                    KitHint::Text("connects"),
                    KitHint::Keys("Ctrl+S"),
                    KitHint::Text("saves"),
                    KitHint::Keys("Ctrl+N"),
                    KitHint::Text("new connection"),
                ],
            );
        }

        // Wide windows: what this connection will do, next to the form.
        let mut bottom = y + p(56.0);
        if !group_mode && area.w >= p(1100.0) {
            let sx = x + w + p(32.0);
            let sw = p(380.0).min(area.right() - p(40.0) - sx);
            bottom = bottom.max(self.paint_summary(cv, te, f, sx, top + p(104.0), sw) + p(40.0));
        }

        // Scrolling: remember the height, keep the offset in range, show a bar.
        self.home_content = bottom - top + crumb;
        let max = (self.home_content - area.h).max(0);
        if self.home_scroll > max {
            self.home_scroll = max;
        }
        Kit::new(cv, te, f, s).scrollbar(area, self.home_content, self.home_scroll);
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
        self.field_row_i(cv, te, f, r, label, None, field, placeholder);
    }

    /// A field row whose input has a leading icon.
    #[allow(clippy::too_many_arguments)]
    fn field_row_i(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        label: &str,
        icon: Option<Icon>,
        field: Field,
        placeholder: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        Kit::new(cv, te, f, s).text_in(
            Font::Regular,
            size::BODY,
            Rect::new(r.x + p(16.0), r.y, p(110.0), r.h),
            label,
            pal().text_secondary,
        );
        let input = Rect::new(
            r.x + p(132.0),
            r.y + (r.h - p(32.0)) / 2,
            r.w - p(132.0) - p(12.0),
            p(32.0),
        );
        self.text_input_i(cv, te, f, input, icon, field, placeholder);
    }

    /// The first card of an inheritable page in a group: the switch, a
    /// chip naming the group the values come from, and the values.
    /// Returns true when the page is inherited.
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
        let c = pal();
        let hit = Hit::FormInherit(section);
        let (source, values) = if on {
            self.inherited_parts(parent, section)
        } else {
            (None, "Off: this one sets its own".to_string())
        };
        let r = self.card(cv, x, *y, w, &[p(62.0)])[0];
        self.row_hover(cv, r, hit);
        let label = format!("Use the group's {what}");
        let st = self.st(hit);
        let mut k = Kit::new(cv, te, f, s);
        let icon_c = if on { c.accent } else { c.text_muted };
        k.icon(
            Icon::Folder,
            r.x + p(16.0),
            r.y + (r.h - p(16.0)) / 2,
            16.0,
            icon_c,
        );
        let tx = r.x + p(46.0);
        let tw = r.right() - tx - p(72.0);
        let end = k.text(
            Font::Regular,
            size::BODY,
            tx,
            r.y + p(27.0),
            &label,
            c.text,
            tw,
        );
        let from = source.unwrap_or_else(|| parent.to_string());
        let chip = format!("from {}", from.rsplit('/').next().unwrap_or(&from));
        let swatch = theme::group_solid(self.store.group_color(&from));
        if on && end + p(10.0) + k.pill_width(&chip, Lead::Dot) < tx + tw {
            k.pill(
                end + p(10.0),
                r.y + p(12.0),
                &chip,
                Tone::Neutral,
                Lead::Swatch(swatch),
            );
        }
        k.text(
            Font::Regular,
            size::SMALL - 0.5,
            tx,
            r.y + p(45.0),
            &values,
            c.text_muted,
            tw,
        );
        k.switch(r.right() - p(52.0), r.y + (r.h - p(20.0)) / 2, on, st);
        self.hits.push((r, hit));
        *y += p(62.0) + p(20.0);
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
            if group_mode { "Group" } else { "Connection" },
        );
        y += p(26.0);
        if group_mode {
            let cells = self.card(cv, x, y, w, &[rh, rh, p(56.0)]);
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
            self.color_row(cv, te, f, cells[2]);
            y += 2 * rh + p(56.0);
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
            Kit::new(cv, te, f, s).text_in(
                Font::Regular,
                size::BODY,
                Rect::new(r.x + p(16.0), r.y, p(110.0), r.h),
                "Host",
                pal().text_secondary,
            );
            let port_w = p(84.0);
            let hx = r.x + p(132.0);
            let hw = r.right() - p(12.0) - port_w - p(8.0) - hx;
            let iy = r.y + (r.h - p(32.0)) / 2;
            self.text_input_i(
                cv,
                te,
                f,
                Rect::new(hx, iy, hw, p(32.0)),
                Some(Icon::Monitor),
                Field::Host,
                "Name or IP address",
            );
            self.text_input(
                cv,
                te,
                f,
                Rect::new(r.right() - p(12.0) - port_w, iy, port_w, p(32.0)),
                Field::Port,
                "Port",
            );
            self.field_row_i(
                cv,
                te,
                f,
                cells[2],
                "Group",
                Some(Icon::Folder),
                Field::GroupPath,
                "None (top level), e.g. Work/Servers",
            );
            y += 3 * rh;
        }
        y += p(24.0);
        if !group_mode {
            y = self.form_opens(cv, te, f, x, y, w);
        }

        self.caption(cv, te, f, x, y, w, "Sign-in");
        y += p(26.0);
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
            self.field_row_i(
                cv,
                te,
                f,
                cells[0],
                "Password",
                Some(Icon::Key),
                Field::Password,
                &hint,
            );
            return y + rh;
        }
        let saved = self.save_password && self.own_password().is_some();
        let cells = self.card(cv, x, y, w, &[rh, rh, p(60.0), p(60.0), rh]);
        self.field_row_i(
            cv,
            te,
            f,
            cells[0],
            "User",
            Some(Icon::User),
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
        self.field_row_i(
            cv,
            te,
            f,
            cells[1],
            "Password",
            Some(Icon::Key),
            Field::Password,
            pw_hint,
        );
        let save_sub = if self.store.is_vault() {
            "Kept in the encrypted vault"
        } else {
            "Asks for a master password first"
        };
        self.card_switch_i(
            cv,
            te,
            f,
            cells[2],
            Some(Icon::Lock),
            "Save password",
            save_sub,
            self.save_password,
            Hit::SavePassword,
        );
        let kerberos = self.kerberos;
        self.card_switch_i(
            cv,
            te,
            f,
            cells[3],
            Some(Icon::Shield),
            "Sign in with Windows",
            "Kerberos for domain servers, NTLM as a fallback; no user: you",
            kerberos,
            Hit::FormKerberos,
        );
        self.field_row_i(
            cv,
            te,
            f,
            cells[4],
            "Gateway",
            Some(Icon::Globe),
            Field::Gateway,
            "None (direct), or rdg.example.com",
        );
        y + 3 * rh + 2 * p(60.0)
    }

    /// The group's colour: eight swatches and Auto.
    fn color_row(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, r: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let n = theme::GROUP_COLORS.len();
        let chosen = self.group_color.map(|v| v as usize);
        let auto = self.group_edit.clone().flatten().map_or_else(
            || theme::color_for_name(&self.field(Field::Name).text),
            |path| {
                // What Auto would show: the parent's colour, or the name's.
                let parent = parent_of(&path);
                if parent.is_empty() {
                    theme::color_for_name(&path)
                } else {
                    self.store.group_color(parent)
                }
            },
        );
        let mut k = Kit::new(cv, te, f, s);
        k.text_in(
            Font::Regular,
            size::BODY,
            Rect::new(r.x + p(16.0), r.y, p(110.0), r.h),
            "Colour",
            c.text_secondary,
        );
        let d = p(22.0);
        let mut x = r.x + p(132.0);
        let cy = r.y + r.h / 2;
        let mut hits = Vec::new();
        for i in 0..n {
            let hit = Hit::FormColor(i);
            let on = chosen == Some(i);
            let (cx, fy) = ((x + d / 2) as f32, cy as f32);
            if on {
                k.cv.ring(cx, fy, d as f32 / 2.0 + 3.0 * s, 2.0 * s, c.text);
            } else if self.hover == Some(hit) {
                k.cv.ring(cx, fy, d as f32 / 2.0 + 3.0 * s, 2.0 * s, c.border_strong);
            }
            k.cv.fill_circle(cx, fy, d as f32 / 2.0, theme::group_solid(i));
            if on {
                let ic = p(12.0);
                k.icon(Icon::Check, x + (d - ic) / 2, cy - ic / 2, 12.0, c.on_solid);
            }
            hits.push((
                Rect::new(x - p(3.0), cy - d / 2 - p(3.0), d + p(6.0), d + p(6.0)),
                hit,
            ));
            x += d + p(10.0);
        }
        let hit = Hit::FormColor(n);
        let label = if chosen.is_none() {
            format!("Auto · {}", theme::GROUP_COLORS[auto].0)
        } else {
            "Auto".to_string()
        };
        let b = Button::new(
            &label,
            if chosen.is_none() {
                Variant::Secondary
            } else {
                Variant::Ghost
            },
        );
        let bw = k.button_width(&b);
        let br = Rect::new(x + p(4.0), cy - p(14.0), bw, p(28.0));
        k.button(br, &b, State::hover(self.hover == Some(hit)));
        hits.push((br, hit));
        self.hits.extend(hits);
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
        let c = pal();
        let apps_mode = self.opens == Opens::Apps;
        self.caption(cv, te, f, x, y, w, "Opens");
        y += p(26.0);
        let items = [
            (
                "Desktop".to_string(),
                Some(Icon::Monitor),
                !apps_mode,
                Hit::FormOpens(0),
            ),
            (
                "Apps".to_string(),
                Some(Icon::Apps),
                apps_mode,
                Hit::FormOpens(1),
            ),
        ];
        self.segmented_i(cv, te, f, Rect::new(x, y, w, p(36.0)), &items);
        y += p(36.0) + p(20.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y - p(2.0),
            w,
            if apps_mode {
                "Connect starts the first app below in its own window on this PC (RemoteApp)."
            } else {
                "Connect opens the whole remote desktop: in a tab, full screen or on monitors."
            },
        );
        y += p(24.0);
        // The apps are the connection's whatever it opens: each one is
        // listed under it in the sidebar and starts its own RemoteApp window.
        self.caption(cv, te, f, x, y, w, "Apps");
        y += p(26.0);
        let apps = self.apps.clone();
        let mut heights = vec![p(54.0); apps.len().max(1)];
        heights.extend([p(52.0), p(52.0)]);
        let cells = self.card(cv, x, y, w, &heights);
        if apps.is_empty() {
            let r = cells[0];
            Kit::new(cv, te, f, s).text_in(
                Font::Regular,
                size::BODY,
                Rect::new(r.x + p(16.0), r.y, r.w - p(32.0), r.h),
                "No apps yet. Add a program to start it on its own from the sidebar.",
                c.text_muted,
            );
        }
        for (i, (r, app)) in cells.iter().zip(&apps).enumerate() {
            let close = Rect::new(
                r.right() - p(44.0),
                r.y + (r.h - p(28.0)) / 2,
                p(28.0),
                p(28.0),
            );
            let mut k = Kit::new(cv, te, f, s);
            let d = p(30.0);
            let tile = Rect::new(r.x + p(14.0), r.y + (r.h - d) / 2, d, d);
            k.cv.fill_round(tile, 8.0 * s, c.accent_subtle);
            k.icon_in(Icon::Apps, tile, 15.0, c.accent);
            let tx = r.x + p(56.0);
            let tw = close.x - tx - p(8.0);
            k.text(
                Font::Semi,
                size::BODY,
                tx,
                r.y + p(23.0),
                &app.name,
                c.text,
                tw,
            );
            let mut sub = app.program.clone();
            if !app.args.is_empty() {
                sub = format!("{sub} {}", app.args);
            }
            if !app.working_dir.is_empty() {
                sub = format!("{sub} · in {}", app.working_dir);
            }
            k.text(
                Font::Regular,
                11.5,
                tx,
                r.y + p(40.0),
                &sub,
                c.text_muted,
                tw,
            );
            self.icon_btn(
                cv,
                te,
                f,
                close,
                Icon::Trash,
                Variant::DangerGhost,
                Hit::FormRemoveApp(i),
            );
        }
        // The add rows: program and name; arguments, folder and Add.
        let n = heights.len();
        let (r1, r2) = (cells[n - 2], cells[n - 1]);
        let gap = p(8.0);
        let i1 = Rect::new(
            r1.x + p(12.0),
            r1.y + (r1.h - p(32.0)) / 2,
            r1.w - p(24.0),
            p(32.0),
        );
        let pw = (i1.w - gap) * 3 / 5;
        self.text_input_i(
            cv,
            te,
            f,
            Rect::new(i1.x, i1.y, pw, i1.h),
            Some(Icon::Apps),
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
            r2.y + (r2.h - p(32.0)) / 2,
            r2.w - p(24.0),
            p(32.0),
        );
        let add = Button::secondary("Add").icon(Icon::Plus);
        let aw = self.btn_w(te, f, &add);
        let fw = (i2.w - aw - 2 * gap) / 2;
        self.text_input(
            cv,
            te,
            f,
            Rect::new(i2.x, i2.y, fw, i2.h),
            Field::AppArgs,
            "Arguments (optional)",
        );
        self.text_input_i(
            cv,
            te,
            f,
            Rect::new(i2.x + fw + gap, i2.y, fw, i2.h),
            Some(Icon::Folder),
            Field::AppDir,
            "Working folder (optional)",
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(i2.right() - aw, i2.y, aw, i2.h),
            &add,
            Hit::FormAddApp,
        );
        y + heights.iter().sum::<i32>() + p(24.0)
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
        let c = pal();
        let mons = self.local_monitors.clone();
        let box_h = p(160.0);
        let frame = Rect::new(x, y, w, box_h);
        cv.round_border(frame, radius::CARD * s, c.border, c.field);
        let mut k = Kit::new(cv, te, f, s);
        let Some((bl, bt, bw, bh)) = crate::monitors::bounds(&mons) else {
            k.text_center(
                Font::Regular,
                12.5,
                frame,
                "No monitors found.",
                c.text_muted,
            );
            return y + box_h;
        };
        let pad = p(20.0) as f32;
        let sc = ((frame.w as f32 - 2.0 * pad) / bw as f32)
            .min((frame.h as f32 - 2.0 * pad) / bh as f32);
        let ox = frame.x as f32 + (frame.w as f32 - bw as f32 * sc) / 2.0;
        let oy = frame.y as f32 + (frame.h as f32 - bh as f32 * sc) / 2.0;
        let mut hits = Vec::new();
        for (i, m) in mons.iter().enumerate() {
            let r = Rect::new(
                (ox + (m.monitor.left - bl) as f32 * sc) as i32 + p(3.0),
                (oy + (m.monitor.top - bt) as f32 * sc) as i32 + p(3.0),
                (m.width() as f32 * sc) as i32 - p(6.0),
                (m.height() as f32 * sc) as i32 - p(6.0),
            );
            let on = self.opts.monitors.contains(&m.name);
            let hit = Hit::FormMonitor(i);
            let hover = self.hover == Some(hit);
            let (border, fill, color) = if on {
                (c.accent, c.accent_subtle, c.text)
            } else if hover {
                (c.border_strong, c.surface_hover, c.text_secondary)
            } else {
                (c.border, c.surface_raised, c.text_muted)
            };
            k.cv.round_border(r, 7.0 * s, border, fill);
            if on {
                // A 2 px edge for the chosen ones.
                k.round_outline(r, 7.0 * s, 2.0 * s, border);
                let d = p(16.0);
                let badge = Rect::new(r.right() - d - p(6.0), r.y + p(6.0), d, d);
                k.cv.fill_round(badge, d as f32 / 2.0, c.accent);
                k.icon_in(Icon::Check, badge, 11.0, c.accent_text);
            }
            let num = (i + 1).to_string();
            let top = Rect::new(r.x, r.y + r.h / 2 - p(20.0), r.w, p(24.0));
            k.text_center(Font::Semi, 17.0, top, &num, color);
            let size = if m.monitor.primary {
                format!("{} × {} · main", m.width(), m.height())
            } else {
                format!("{} × {}", m.width(), m.height())
            };
            let bottom = Rect::new(r.x, r.y + r.h / 2 + p(5.0), r.w, p(16.0));
            k.text_center(Font::Regular, 11.0, bottom, &size, c.text_muted);
            hits.push((r, hit));
        }
        self.hits.extend(hits);
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
        self.caption(cv, te, f, x, y, w, "Connection speed");
        y += p(26.0);
        let subs = [
            "The server measures the link and adapts",
            "Everything on",
            "Everything on, for slower links",
            "No wallpaper or animations",
            "Visual styles only",
            "Plain desktop, least data",
        ];
        let cells = self.card(cv, x, y, w, &[p(52.0); PRESETS.len()]);
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
        y += PRESETS.len() as i32 * p(52.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Colours");
        y += p(26.0);
        let items: Vec<(String, bool, Hit)> = DEPTHS
            .iter()
            .enumerate()
            .map(|(i, d)| (format!("{d}-bit"), q.color_depth == *d, Hit::FormDepth(i)))
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(36.0)), &items);
        y += p(36.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Show");
        y += p(26.0);
        let rows = [
            (Icon::Monitor, "Desktop background", q.wallpaper),
            (Icon::Edit, "Font smoothing", q.font_smoothing),
            (Icon::Window, "Desktop composition", q.composition),
            (
                Icon::Fullscreen,
                "Window contents while dragging",
                q.window_drag,
            ),
            (Icon::Star, "Menu and window animations", q.animations),
            (Icon::Sliders, "Visual styles", q.visual_styles),
        ];
        let cells = self.card(cv, x, y, w, &[p(46.0); 6]);
        for (i, (r, (icon, label, on))) in cells.iter().zip(rows).enumerate() {
            self.card_switch_i(
                cv,
                te,
                f,
                *r,
                Some(icon),
                label,
                "",
                on,
                Hit::FormExperience(i as u8),
            );
        }
        y += 6 * p(46.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Input");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[p(60.0)]);
        self.card_switch_i(
            cv,
            te,
            f,
            cells[0],
            Some(Icon::Edit),
            "Touch and pen",
            TOUCH_HINT,
            q.touch,
            Hit::FormExperience(6),
        );
        y += p(60.0) + p(24.0);
        self.keyboard_choice(
            cv,
            te,
            f,
            (x, y, w),
            self.opts.keyboard,
            true,
            Hit::FormKeyboard,
        )
    }

    /// The Keyboard choice (RDP-32): segments and one line on the chosen
    /// one. `long`: the editor's full names. Returns the y below it.
    #[allow(clippy::too_many_arguments)]
    fn keyboard_choice(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        (x, mut y, w): (i32, i32, i32),
        mode: KeyboardMode,
        long: bool,
        hit: impl Fn(usize) -> Hit,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        self.caption(cv, te, f, x, y, w, "Keyboard");
        y += p(26.0);
        let items: Vec<(String, bool, Hit)> = KeyboardMode::ALL
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let name = match (long, k) {
                    (true, KeyboardMode::Remote) => "Remote layout",
                    (true, KeyboardMode::Translate) => "Translate typing",
                    _ => k.label(),
                };
                (name.to_string(), mode == *k, hit(i))
            })
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        self.hint(cv, te, f, x, y + p(20.0), w, mode.hint());
        y + p(32.0)
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
        let c = pal();
        if self.inherit_card(cv, te, f, x, &mut y, w, parent, 2, inh.sharing, "sharing") {
            return y - p(20.0);
        }
        let o = self.opts.clone();
        let rows = [
            (
                0u8,
                Icon::Clipboard,
                "Clipboard",
                "Text and files, both ways",
                o.clipboard,
            ),
            (
                1,
                Icon::Speaker,
                "Sound",
                "Remote audio plays on this PC",
                o.sound,
            ),
            (
                4,
                Icon::Mic,
                "Microphone",
                "This PC's microphone in the session",
                o.microphone,
            ),
            (
                2,
                Icon::Printer,
                "Printers",
                "Local printers in the session",
                o.printers,
            ),
            (
                3,
                Icon::SmartCard,
                "Smart cards",
                "Local readers and cards",
                o.smart_cards,
            ),
        ];
        self.caption(cv, te, f, x, y, w, "Devices");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[p(58.0); 5]);
        for (r, (i, icon, label, sub, on)) in cells.iter().zip(rows) {
            self.card_switch_i(cv, te, f, *r, Some(icon), label, sub, on, Hit::FormShare(i));
        }
        y += 5 * p(58.0) + p(24.0);

        if o.sound {
            y = self.device_card(
                cv,
                te,
                f,
                x,
                y,
                w,
                "Play sound on",
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
                "Record from",
                "Default microphone",
                &self.mics.clone(),
                o.mic.as_deref(),
                Hit::FormMic,
            );
        }

        self.caption(cv, te, f, x, y, w, "Shared folders");
        y += p(26.0);
        let n = o.drives.len();
        let mut heights = vec![p(48.0); n];
        heights.push(p(56.0));
        let cells = self.card(cv, x, y, w, &heights);
        for (i, (r, path)) in cells.iter().zip(&o.drives).enumerate() {
            let close = Rect::new(
                r.right() - p(44.0),
                r.y + (r.h - p(28.0)) / 2,
                p(28.0),
                p(28.0),
            );
            let mut k = Kit::new(cv, te, f, s);
            k.icon(
                Icon::Folder,
                r.x + p(16.0),
                r.y + (r.h - p(16.0)) / 2,
                16.0,
                c.accent,
            );
            k.text_in(
                Font::Regular,
                size::BODY,
                Rect::new(r.x + p(46.0), r.y, close.x - r.x - p(54.0), r.h),
                path,
                c.text,
            );
            self.icon_btn(
                cv,
                te,
                f,
                close,
                Icon::Close,
                Variant::DangerGhost,
                Hit::FormRemoveDrive(i),
            );
        }
        let r = cells[n];
        let browse = Button::secondary("Browse…").icon(Icon::FolderOpen);
        let add = Button::secondary("Add").icon(Icon::Plus);
        let (bw, aw) = (self.btn_w(te, f, &browse), self.btn_w(te, f, &add));
        let inner = Rect::new(
            r.x + p(12.0),
            r.y + (r.h - p(32.0)) / 2,
            r.w - p(24.0),
            p(32.0),
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(inner.x, inner.y, bw, inner.h),
            &browse,
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
        self.btn(
            cv,
            te,
            f,
            Rect::new(inner.right() - aw, inner.y, aw, inner.h),
            &add,
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
        if self.palette.is_some() && self.confirm_exit.is_none() {
            return self.palette_scroll(lines);
        }
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

    /// A centred status: an icon tile in `tone`, a title and wrapped text.
    /// Returns the y for the buttons below it.
    #[allow(clippy::too_many_arguments)]
    fn state_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        icon: Icon,
        tone: Tone,
        title: &str,
        text: &str,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let w = p(460.0).min(area.w - p(48.0));
        let x = area.x + (area.w - w) / 2;
        let mut k = Kit::new(cv, te, f, s);
        let lines = k.wrap(Font::Regular, 12.5, text, w).len().min(4) as i32;
        let total = p(56.0) + p(20.0) + p(26.0) + lines * p(19.0) + p(20.0) + p(36.0);
        let mut y = area.y + (area.h - total) / 2;
        let d = p(56.0);
        let tile = Rect::new(area.x + (area.w - d) / 2, y, d, d);
        let (fill, fg) = match tone {
            Tone::Muted | Tone::Neutral => (c.surface_raised, c.text_secondary),
            t => (t.subtle(), t.color()),
        };
        k.cv.fill_round(tile, 16.0 * s, fill);
        k.icon_in(icon, tile, 26.0, fg);
        y += d + p(20.0);
        k.text_center(
            Font::Semi,
            size::HEADING + 1.0,
            Rect::new(area.x, y, area.w, p(24.0)),
            title,
            c.text,
        );
        y += p(26.0) + p(14.0);
        let color = if tone == Tone::Danger {
            c.danger
        } else {
            c.text_muted
        };
        let y = k.paragraph(Font::Regular, 12.5, x, y, w, text, color, true);
        y + p(8.0)
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
        let c = pal();
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let (host, name) = (t.host.clone(), t.name.clone());
        let view = t.remote_app.clone().unwrap_or_default();
        let color = self.tab_color(&name, &host);
        let old = cv.set_clip(area);
        let first_hit = self.hits.len();
        let x = area.x + p(40.0);
        let w = p(640.0).min(area.w - p(80.0)).max(p(300.0));
        let mut y = area.y + p(28.0);
        let n = view.windows.len();
        {
            let mut k = Kit::new(cv, te, f, s);
            let d = p(52.0);
            let tile = Rect::new(x, y, d, d);
            let (fill, fg) = theme::group_tile(color);
            k.cv.fill_round(tile, d as f32 * 0.28, fill);
            k.icon_in(Icon::Apps, tile, 24.0, fg);
            let tx = x + d + p(16.0);
            let title = format!("Apps on {host}");
            k.text(
                Font::Semi,
                size::TITLE,
                tx,
                y + p(24.0),
                &title,
                c.text,
                w - d - p(16.0),
            );
            let end = k.text(
                Font::Regular,
                12.5,
                tx,
                y + p(46.0),
                &name,
                c.text_muted,
                w / 2,
            );
            let pill = match n {
                0 => "No window open".to_string(),
                1 => "1 window on this PC".to_string(),
                n => format!("{n} windows on this PC"),
            };
            let tone = if n > 0 { Tone::Success } else { Tone::Muted };
            k.pill(end + p(10.0), y + p(32.0), &pill, tone, Lead::Dot);
        }
        y += p(52.0) + p(28.0);

        self.caption(cv, te, f, x, y, w, "Open windows");
        y += p(26.0);
        let rh = p(56.0);
        let cells = self.card(cv, x, y, w, &vec![rh; n.max(1)]);
        if n == 0 {
            let r = cells[0];
            let text = if view.starting.is_empty() {
                "Start an app below; its windows appear on this PC's desktop."
            } else {
                "Starting…"
            };
            Kit::new(cv, te, f, s).text_in(
                Font::Regular,
                size::BODY,
                Rect::new(r.x + p(16.0), r.y, r.w - p(32.0), r.h),
                text,
                c.text_muted,
            );
        }
        for (r, win) in cells.iter().zip(&view.windows) {
            let isz = p(20.0);
            let ir = Rect::new(r.x + p(16.0), r.y + (r.h - isz) / 2, isz, isz);
            match &win.icon {
                Some((iw, ih, rgba)) if rgba.len() == *iw as usize * *ih as usize * 4 => {
                    cv.draw_rgba_scaled(ir, *iw as usize, *ih as usize, rgba)
                }
                _ => app_glyph(cv, s, ir.x + p(3.0), ir.y + p(3.0), c.text_muted),
            }
            let focus_b = Button::secondary("Focus").icon(Icon::Window);
            let close_b = Button::new("Close", Variant::DangerGhost).icon(Icon::Close);
            let (fw, cw) = (self.btn_w(te, f, &focus_b), self.btn_w(te, f, &close_b));
            let close = Rect::new(
                r.right() - p(12.0) - cw,
                r.y + (r.h - p(32.0)) / 2,
                cw,
                p(32.0),
            );
            let focus = Rect::new(close.x - p(6.0) - fw, close.y, fw, close.h);
            let title = if win.title.is_empty() {
                "(untitled)"
            } else {
                &win.title
            };
            {
                let mut k = Kit::new(cv, te, f, s);
                let tx = r.x + p(50.0);
                let tw = focus.x - tx - p(12.0);
                if win.minimized {
                    k.text(
                        Font::Regular,
                        size::BODY,
                        tx,
                        r.y + p(24.0),
                        title,
                        c.text,
                        tw,
                    );
                    k.pill(tx, r.y + p(31.0), "Minimized", Tone::Muted, Lead::None);
                } else {
                    k.text_in(
                        Font::Regular,
                        size::BODY,
                        Rect::new(tx, r.y, tw, r.h),
                        title,
                        c.text,
                    );
                }
            }
            self.btn(cv, te, f, focus, &focus_b, Hit::RailFocus(id, win.id));
            self.btn(cv, te, f, close, &close_b, Hit::RailClose(id, win.id));
        }
        y += rh * n.max(1) as i32 + p(24.0);

        self.caption(cv, te, f, x, y, w, "Launch");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &vec![rh; view.apps.len().max(1)]);
        if view.apps.is_empty() {
            Kit::new(cv, te, f, s).text_in(
                Font::Regular,
                size::BODY,
                Rect::new(cells[0].x + p(16.0), cells[0].y, w - p(32.0), rh),
                "This connection has no apps; add them in its editor.",
                c.text_muted,
            );
        }
        let same =
            |l: &[String], prog: &str| l.iter().any(|p| crate::remoteapp::same_program(p, prog));
        for (i, (r, app)) in cells.iter().zip(&view.apps).enumerate() {
            let hit = Hit::TabLaunch(id, i);
            self.row_hover(cv, *r, hit);
            let hover = self.hover == Some(hit);
            let mut k = Kit::new(cv, te, f, s);
            let d = p(32.0);
            let tile = Rect::new(r.x + p(12.0), r.y + (r.h - d) / 2, d, d);
            k.cv.fill_round(tile, 8.0 * s, c.accent_subtle);
            k.icon_in(Icon::Apps, tile, 16.0, c.accent);
            let (state, tone) = if same(&view.running, &app.program) {
                (Some("Running"), Tone::Success)
            } else if same(&view.starting, &app.program) {
                (Some("Starting"), Tone::Warning)
            } else {
                (None, Tone::Accent)
            };
            let action = if state.is_some() {
                "Start another"
            } else {
                "Start"
            };
            let aw = k.measure(Font::Semi, size::SMALL, action) + p(20.0);
            let pw = state.map_or(0, |t| k.pill_width(t, Lead::Dot) + p(10.0));
            let tx = r.x + p(56.0);
            let tw = r.right() - tx - aw - pw - p(24.0);
            k.text(
                Font::Semi,
                size::BODY,
                tx,
                r.y + p(24.0),
                &app.name,
                c.text,
                tw,
            );
            k.text(
                Font::Regular,
                11.5,
                tx,
                r.y + p(41.0),
                &app.program,
                c.text_muted,
                tw,
            );
            let ar = Rect::new(
                r.right() - p(12.0) - aw,
                r.y + (r.h - p(28.0)) / 2,
                aw,
                p(28.0),
            );
            if hover {
                k.cv.fill_round(ar, radius::CONTROL * s, c.accent_subtle);
            }
            k.text_center(Font::Semi, size::SMALL, ar, action, c.accent);
            if let Some(t) = state {
                k.pill(ar.x - pw, r.y + (r.h - p(20.0)) / 2, t, tone, Lead::Dot);
            }
            self.hits.push((*r, hit));
        }
        self.clip_hits(first_hit, area);
        cv.set_clip(old);
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
        cp: &CertPrompt,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let w = p(480.0).min(area.w - p(32.0));
        let h = p(316.0);
        let r = Rect::new(
            area.x + (area.w - w) / 2,
            area.y + ((area.h - h) / 2).max(p(16.0)),
            w,
            h,
        );
        let (icon, tone, title) = if cp.changed {
            (
                Icon::ShieldAlert,
                Tone::Danger,
                "The server certificate changed",
            )
        } else {
            (Icon::ShieldCheck, Tone::Accent, "Verify the server")
        };
        let line = if cp.changed {
            format!("{host} shows a different certificate than the one you trusted.")
        } else {
            format!("First connection to {host}. Check the fingerprint with its admin.")
        };
        let sub = if cp.changed {
            "A reinstalled server does this, but so does an attack."
        } else {
            "Your password is sent only after you trust it."
        };
        let x = r.x + p(28.0);
        let tw = r.w - p(56.0);
        {
            let mut k = Kit::new(cv, te, f, s);
            k.dialog(r);
            let d = p(44.0);
            let tile = Rect::new(x, r.y + p(28.0), d, d);
            k.cv.fill_round(tile, 12.0 * s, tone.subtle());
            k.icon_in(icon, tile, 22.0, tone.color());
            let hx = x + d + p(14.0);
            k.text(
                Font::Semi,
                size::HEADING + 1.0,
                hx,
                r.y + p(46.0),
                title,
                c.text,
                r.right() - hx - p(28.0),
            );
            k.text(
                Font::Regular,
                12.0,
                hx,
                r.y + p(65.0),
                host,
                c.text_muted,
                r.right() - hx - p(28.0),
            );
            let mut y = r.y + p(102.0);
            y = k.paragraph(
                Font::Regular,
                12.5,
                x,
                y,
                tw,
                &line,
                c.text_secondary,
                false,
            );
            let color = if cp.changed { c.danger } else { c.text_muted };
            k.text(Font::Regular, 12.0, x, y, sub, color, tw);
            // The fingerprint, 16 bytes per line.
            let fr = Rect::new(x, r.y + p(150.0), tw, p(72.0));
            k.cv.round_border(fr, radius::CONTROL * s, c.border, c.field);
            let cap_y = fr.y + p(20.0);
            k.caption_text(fr.x + p(14.0), cap_y, "SHA-256 FINGERPRINT", c.text_faint);
            let (a, b) = cp.fingerprint.split_at(cp.fingerprint.len().min(48));
            for (i, part) in [a.trim_end_matches(':'), b].iter().enumerate() {
                k.text(
                    Font::Regular,
                    12.0,
                    fr.x + p(14.0),
                    fr.y + p(40.0) + i as i32 * p(18.0),
                    part,
                    c.text,
                    fr.w - p(28.0),
                );
            }
        }
        // Footer: the safe choice is the loud one.
        let by = r.bottom() - p(28.0) - p(36.0);
        let (left, right) = if cp.changed {
            (
                (
                    Button::new("Trust the new one", Variant::DangerGhost).icon(Icon::Unlock),
                    Hit::CertTrust(id),
                ),
                (
                    Button::primary("Don't connect").icon(Icon::Close),
                    Hit::CertRefuse(id),
                ),
            )
        } else {
            (
                (Button::secondary("Cancel"), Hit::CertRefuse(id)),
                (
                    Button::primary("Trust and connect").icon(Icon::ShieldCheck),
                    Hit::CertTrust(id),
                ),
            )
        };
        let rw = self.btn_w(te, f, &right.0);
        let lw = self.btn_w(te, f, &left.0);
        let rx = r.right() - p(28.0) - rw;
        self.btn(cv, te, f, Rect::new(rx, by, rw, p(36.0)), &right.0, right.1);
        self.btn(
            cv,
            te,
            f,
            Rect::new(rx - p(8.0) - lw, by, lw, p(36.0)),
            &left.0,
            left.1,
        );
    }

    /// The quick panel: four pages (Sharing, Display, Quality, Session) of
    /// grouped cards, like Windows Settings. Its body scrolls.
    fn paint_drawer(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, d: Rect, id: u64) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        cv.fill(d, pal().bg);
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
            keyboard: tab.keyboard,
            keyboard_layout: tab.keyboard_layout,
            speaker: tab.speaker.clone(),
            microphone: tab.microphone,
            mic: tab.mic.clone(),
            redirected_to: tab.redirected_to.clone(),
            network: tab.network.clone(),
        };
        let x = d.x + p(12.0);
        let w = d.w - p(24.0);

        // Page switcher
        let seg = Rect::new(x, d.y + p(12.0), w, p(36.0));
        let pages: Vec<(String, Option<Icon>, bool, Hit)> = [
            ("Sharing", Icon::Folder),
            ("Display", Icon::Monitor),
            ("Quality", Icon::Sliders),
            ("Session", Icon::Info),
        ]
        .iter()
        .enumerate()
        .map(|(i, (n, icon))| {
            (
                n.to_string(),
                Some(*icon),
                self.drawer_page == i as u8,
                Hit::DrawerPage(i as u8),
            )
        })
        .collect();
        self.segmented_i(cv, te, f, seg, &pages);

        let body = Rect::new(
            d.x,
            seg.bottom() + p(8.0),
            d.w,
            d.bottom() - seg.bottom() - p(8.0),
        );
        self.drawer_area = body;
        let inner = cv.set_clip(body);
        let first_hit = self.hits.len();
        let top = body.y + p(8.0) - self.drawer_scroll;
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
        let mut k = Kit::new(cv, te, f, s);
        k.scrollbar(
            Rect::new(body.x, body.y, body.w + p(4.0), body.h),
            self.drawer_content,
            self.drawer_scroll,
        );
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
        let c = pal();
        let rows = [
            (
                Icon::Clipboard,
                "Clipboard",
                "Text and files, both ways",
                t.clipboard,
                Hit::Clipboard(id),
            ),
            (
                Icon::Speaker,
                "Sound",
                "Remote audio on this PC",
                t.sound,
                Hit::Sound(id),
            ),
            (
                Icon::Mic,
                "Microphone",
                "This PC's microphone",
                t.microphone,
                Hit::Microphone(id),
            ),
            (
                Icon::Printer,
                "Printers",
                "Local printers in the session",
                t.printers,
                Hit::Printers(id),
            ),
            (
                Icon::SmartCard,
                "Smart cards",
                "Local readers and cards",
                t.smart_cards,
                Hit::SmartCards(id),
            ),
        ];
        let cells = self.card(cv, x, y, w, &[p(56.0); 5]);
        for (r, (icon, label, sub, on, hit)) in cells.iter().zip(rows) {
            self.card_switch_i(cv, te, f, *r, Some(icon), label, sub, on, hit);
        }
        y += 5 * p(56.0) + p(24.0);
        if t.microphone {
            let mics = self.mics.clone();
            y = self.device_card_tab(
                cv,
                te,
                f,
                x,
                y,
                w,
                "Record from",
                "Default microphone",
                &mics,
                t.mic.as_deref(),
                id,
                Hit::TabMic,
            );
        }
        if t.sound {
            let speakers = self.speakers.clone();
            y = self.device_card_tab(
                cv,
                te,
                f,
                x,
                y,
                w,
                "Play sound on",
                "Default output",
                &speakers,
                t.speaker.as_deref(),
                id,
                Hit::TabSpeaker,
            );
        }

        self.caption(cv, te, f, x, y, w, "Shared folders");
        y += p(26.0);
        if t.drives.is_empty() {
            let cells = self.card(cv, x, y, w, &[p(48.0)]);
            Kit::new(cv, te, f, s).text_in(
                Font::Regular,
                size::SMALL,
                Rect::new(
                    cells[0].x + p(14.0),
                    cells[0].y,
                    cells[0].w - p(28.0),
                    cells[0].h,
                ),
                "None yet; they show in the remote Explorer.",
                c.text_muted,
            );
            y += p(48.0);
        } else {
            let n = t.drives.len();
            let cells = self.card(cv, x, y, w, &vec![p(54.0); n]);
            for (i, (r, drv)) in cells.iter().zip(&t.drives).enumerate() {
                let close = Rect::new(
                    r.right() - p(40.0),
                    r.y + (r.h - p(28.0)) / 2,
                    p(28.0),
                    p(28.0),
                );
                let mut k = Kit::new(cv, te, f, s);
                k.icon(
                    Icon::Folder,
                    r.x + p(14.0),
                    r.y + (r.h - p(16.0)) / 2,
                    16.0,
                    c.accent,
                );
                let tx = r.x + p(42.0);
                let tw = close.x - tx - p(6.0);
                k.text(Font::Semi, 12.5, tx, r.y + p(23.0), &drv.name, c.text, tw);
                k.text(
                    Font::Regular,
                    11.5,
                    tx,
                    r.y + p(40.0),
                    &drv.path,
                    c.text_muted,
                    tw,
                );
                self.icon_btn(
                    cv,
                    te,
                    f,
                    close,
                    Icon::Close,
                    Variant::DangerGhost,
                    Hit::RemoveDrive(id, i),
                );
            }
            y += n as i32 * p(54.0);
        }
        y += p(12.0);
        self.btn(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(34.0)),
            &Button::secondary("Browse for a folder…").icon(Icon::FolderOpen),
            Hit::BrowseDrive(id),
        );
        y += p(42.0);
        let add = Button::secondary("Add").icon(Icon::Plus);
        let add_w = self.btn_w(te, f, &add);
        self.text_input(
            cv,
            te,
            f,
            Rect::new(x, y, w - add_w - p(6.0), p(32.0)),
            Field::DrivePath,
            r"or type a path, e.g. C:\Share",
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(x + w - add_w, y, add_w, p(32.0)),
            &add,
            Hit::AddDrive(id),
        );
        y += p(32.0);
        self.hint(cv, te, f, x, y + p(20.0), w, "Sharing switches apply live.");
        y + p(32.0)
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
        let cells = self.card(cv, x, y, w, &[p(56.0); 2]);
        self.card_switch_i(
            cv,
            te,
            f,
            cells[0],
            Some(Icon::Fullscreen),
            "Full screen",
            "Ctrl+Alt+Break switches it",
            full,
            Hit::FullScreen,
        );
        self.card_switch_i(
            cv,
            te,
            f,
            cells[1],
            Some(Icon::Monitor),
            "Fit to window",
            "The remote desktop follows the window",
            t.fit,
            Hit::Fit(id),
        );
        y += 2 * p(56.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Scale");
        y += p(26.0);
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
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        let auto = format!(
            "Auto follows this PC's scaling ({} %). Applies live.",
            (self.scale * 100.0).round() as u32
        );
        self.hint(cv, te, f, x, y + p(20.0), w, &auto);
        y + p(32.0)
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
            let r = Rect::new(x, y, w, p(108.0));
            Kit::new(cv, te, f, s).banner(
                r,
                Tone::Accent,
                Icon::Refresh,
                "Reconnect to apply",
                "Quality is fixed when the session logs on.",
            );
            self.btn(
                cv,
                te,
                f,
                Rect::new(r.x + p(42.0), r.y + p(62.0), p(150.0), p(32.0)),
                &Button::primary("Reconnect now").icon(Icon::Refresh),
                Hit::Reconnect(id),
            );
            y += p(108.0) + p(20.0);
        }

        self.caption(cv, te, f, x, y, w, "Connection speed");
        y += p(26.0);
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
                Hit::TabPreset(id, i),
            );
        }
        y += PRESETS.len() as i32 * p(50.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Colours");
        y += p(26.0);
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
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Show");
        y += p(26.0);
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
        y += 6 * p(44.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Input");
        y += p(26.0);
        let cells = self.card(cv, x, y, w, &[p(58.0)]);
        self.card_switch_i(
            cv,
            te,
            f,
            cells[0],
            Some(Icon::Edit),
            "Touch and pen",
            TOUCH_HINT,
            q.touch,
            Hit::TabExperience(id, 6),
        );
        y += p(58.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Graphics");
        y += p(26.0);
        let items: Vec<(String, bool, Hit)> = ["Bitmaps", "GFX (H.264)"]
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), q.gfx == (i == 1), Hit::TabGraphics(id, i)))
            .collect();
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Compression");
        y += p(26.0);
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
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0);
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(20.0),
            w,
            "Less data on slow links; costs a little CPU.",
        );
        y + p(32.0)
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
        let c = pal();
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
        let mut rows = vec![(Icon::Monitor, "Host", t.host.clone())];
        // The server moved the session after logon (MS-RDPBCGR 3.2.5.13).
        if let Some(to) = &t.redirected_to {
            rows.push((Icon::ChevronRight, "Moved to", to.clone()));
        }
        rows.extend([
            (Icon::Info, "Status", status),
            (Icon::Fullscreen, "Desktop", desktop),
            (Icon::Star, "Colours", colours),
            (
                Icon::Sliders,
                "Speed",
                preset_name(t.quality_live.connection).to_string(),
            ),
        ]);
        // The keyboard layout the session logged on with (RDP-32).
        if let Some(l) = t.keyboard_layout {
            rows.push((Icon::Keyboard, "Keyboard", crate::keyboard::layout_name(l)));
        }
        // Network auto-detect results, once the server sent some.
        if let Some(n) = &t.network {
            rows.push((Icon::Network, "Network", n.clone()));
        }
        let count = rows.len();
        let cells = self.card(cv, x, y, w, &vec![p(40.0); count]);
        {
            let mut k = Kit::new(cv, te, f, s);
            for (r, (icon, label, value)) in cells.iter().zip(rows) {
                k.icon(
                    icon,
                    r.x + p(14.0),
                    r.y + (r.h - p(14.0)) / 2,
                    14.0,
                    c.text_faint,
                );
                k.text_in(
                    Font::Regular,
                    12.5,
                    Rect::new(r.x + p(36.0), r.y, p(80.0), r.h),
                    label,
                    c.text_muted,
                );
                let room = r.w - p(124.0);
                k.text_right(
                    Font::Regular,
                    12.5,
                    Rect::new(r.right() - p(14.0) - room, r.y, room, r.h),
                    &value,
                    c.text,
                );
            }
        }
        y += count as i32 * p(40.0) + p(24.0);

        self.caption(cv, te, f, x, y, w, "Windows keys (Win, Alt+Tab)");
        y += p(26.0);
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
        self.segmented(cv, te, f, Rect::new(x, y, w, p(34.0)), &items);
        y += p(34.0) + p(24.0);

        y = self.keyboard_choice(cv, te, f, (x, y, w), t.keyboard, false, |i| {
            Hit::TabKeyboard(id, i)
        });
        // Remote layout keeps the session's layout: after a switch on this
        // PC only a reconnect gives it the new one.
        let local = crate::keyboard::server_layout(crate::keyboard::local_klid());
        if t.keyboard == KeyboardMode::Remote && t.keyboard_layout.is_some_and(|l| l != local) {
            y += p(4.0);
            let r = Rect::new(x, y, w, p(108.0));
            Kit::new(cv, te, f, s).banner(
                r,
                Tone::Accent,
                Icon::Refresh,
                &format!("This PC types {}", crate::keyboard::layout_name(local)),
                "Reconnect to give the session this layout.",
            );
            self.btn(
                cv,
                te,
                f,
                Rect::new(r.x + p(42.0), r.y + p(62.0), p(150.0), p(32.0)),
                &Button::primary("Reconnect now").icon(Icon::Refresh),
                Hit::Reconnect(id),
            );
            y += p(108.0);
        }
        y += p(12.0);

        self.caption(cv, te, f, x, y, w, "Actions");
        y += p(26.0);
        self.btn(
            cv,
            te,
            f,
            Rect::new(x, y, w, p(34.0)),
            &Button::secondary("Send Ctrl+Alt+Del").icon(Icon::Keyboard),
            Hit::CtrlAltDel(id),
        );
        y += p(42.0);
        let half = (w - p(8.0)) / 2;
        self.btn(
            cv,
            te,
            f,
            Rect::new(x, y, half, p(34.0)),
            &Button::secondary("Reconnect").icon(Icon::Refresh),
            Hit::Reconnect(id),
        );
        if matches!(t.state, TabState::Connected { .. } | TabState::Connecting) {
            self.btn(
                cv,
                te,
                f,
                Rect::new(x + w - half, y, half, p(34.0)),
                &Button::new("Disconnect", Variant::DangerGhost).icon(Icon::Power),
                Hit::Disconnect(id),
            );
        }
        y += p(34.0);
        self.key_hints(
            cv,
            te,
            f,
            x,
            y + p(24.0),
            w,
            &[
                KitHint::Keys("Ctrl+Alt+Home"),
                KitHint::Text("gives the keyboard back"),
            ],
        );
        self.key_hints(
            cv,
            te,
            f,
            x,
            y + p(50.0),
            w,
            &[
                KitHint::Keys("Ctrl+Alt+Break"),
                KitHint::Text("full screen"),
            ],
        );
        y + p(64.0)
    }

    /// The kit state of a hit target (hover, pressed).
    fn st(&self, hit: Hit) -> State {
        let hover = self.hover == Some(hit);
        State {
            hover,
            press: hover && self.press == Some(hit),
            ..State::default()
        }
    }

    /// Equal-width segments in one inset frame; the chosen one is raised.
    fn segmented(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        items: &[(String, bool, Hit)],
    ) {
        let items: Vec<(String, Option<Icon>, bool, Hit)> = items
            .iter()
            .map(|(t, on, h)| (t.clone(), None, *on, *h))
            .collect();
        self.segmented_i(cv, te, f, r, &items);
    }

    /// Segments with icons (page switchers).
    fn segmented_i(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        items: &[(String, Option<Icon>, bool, Hit)],
    ) {
        let segs: Vec<Segment> = items
            .iter()
            .map(|(label, icon, on, hit)| Segment {
                label,
                icon: *icon,
                on: *on,
                hover: self.hover == Some(*hit),
            })
            .collect();
        let cells = Kit::new(cv, te, f, self.scale).segmented(r, &segs);
        for (cell, item) in cells.into_iter().zip(items) {
            self.hits.push((cell, item.3));
        }
    }

    /// A card with rows of the given heights and dividers between them;
    /// returns the row rectangles.
    fn card(&self, cv: &mut Canvas, x: i32, y: i32, w: i32, heights: &[i32]) -> Vec<Rect> {
        kit::card_rows(cv, self.scale, x, y, w, heights)
    }

    /// The hover wash of a clickable card row.
    fn row_hover(&self, cv: &mut Canvas, r: Rect, hit: Hit) {
        if self.hover == Some(hit) {
            let p = |v: f32| (v * self.scale).round() as i32;
            cv.fill_round(
                Rect::new(r.x + p(4.0), r.y + p(3.0), r.w - p(8.0), r.h - p(6.0)),
                6.0 * self.scale,
                pal().surface_hover,
            );
        }
    }

    /// Label and second line of a card row, after an optional leading icon;
    /// `right` is the room kept for the control at the right.
    #[allow(clippy::too_many_arguments)]
    fn row_text(
        &self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Option<Icon>,
        label: &str,
        sub: &str,
        strong: bool,
        right: i32,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let mut k = Kit::new(cv, te, f, s);
        let mut x = r.x + p(16.0);
        if let Some(icon) = icon {
            let c = pal().text_muted;
            k.icon(icon, x, r.y + (r.h - p(16.0)) / 2, 16.0, c);
            x += p(30.0);
        }
        let w = r.right() - right - x;
        let font = if strong { Font::Semi } else { Font::Regular };
        let mid = r.y + r.h / 2;
        if sub.is_empty() {
            let base = k.baseline(font, size::BODY, r);
            k.text(font, size::BODY, x, base, label, pal().text, w);
        } else {
            k.text(font, size::BODY, x, mid - p(2.0), label, pal().text, w);
            k.text(
                Font::Regular,
                size::SMALL - 0.5,
                x,
                mid + p(14.0),
                sub,
                pal().text_muted,
                w,
            );
        }
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
        self.card_switch_i(cv, te, f, r, None, label, sub, on, hit);
    }

    /// A switch row with a leading icon.
    #[allow(clippy::too_many_arguments)]
    fn card_switch_i(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Option<Icon>,
        label: &str,
        sub: &str,
        on: bool,
        hit: Hit,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        self.row_hover(cv, r, hit);
        self.row_text(cv, te, f, r, icon, label, sub, false, p(72.0));
        let st = self.st(hit);
        Kit::new(cv, te, f, s).switch(r.right() - p(52.0), r.y + (r.h - p(20.0)) / 2, on, st);
        self.hits.push((r, hit));
    }

    /// A card row that is one of several choices (a radio mark on the right).
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
        self.row_hover(cv, r, hit);
        self.row_text(cv, te, f, r, None, label, sub, chosen, p(60.0));
        let st = self.st(hit);
        Kit::new(cv, te, f, s).radio(r.right() - p(28.0), r.y + r.h / 2, chosen, st);
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
        self.card_choice(cv, te, f, r, label, "", chosen, hit);
    }

    /// A section header above a card.
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
        Kit::new(cv, te, f, self.scale).section(x, y, w, text, None);
    }

    /// A section header with an action link at the right.
    #[allow(clippy::too_many_arguments)]
    fn caption_action(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        y: i32,
        w: i32,
        text: &str,
        action: &str,
        hit: Hit,
    ) {
        let hover = self.hover == Some(hit);
        let r = Kit::new(cv, te, f, self.scale).section(x, y, w, text, Some((action, hover)));
        if let Some(r) = r {
            self.hits.push((r, hit));
        }
    }

    /// A quiet line of help under a control.
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
        Kit::new(cv, te, f, self.scale).text(
            Font::Regular,
            size::SMALL - 0.5,
            x + (2.0 * self.scale) as i32,
            y,
            text,
            pal().text_muted,
            w,
        );
    }

    /// Key caps and words, centred on `cy`.
    #[allow(clippy::too_many_arguments)]
    fn key_hints(
        &self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        cy: i32,
        w: i32,
        items: &[KitHint],
    ) {
        Kit::new(cv, te, f, self.scale).hints(x + (2.0 * self.scale) as i32, cy, w, items);
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
        self.text_input_i(cv, te, f, r, None, field, placeholder);
    }

    /// A text field with a leading icon.
    #[allow(clippy::too_many_arguments)]
    fn text_input_i(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Option<Icon>,
        field: Field,
        placeholder: &str,
    ) {
        let s = self.scale;
        let hit = Hit::Field(field);
        let focused = self.focus == Some(field);
        let st = State {
            hover: self.hover == Some(hit),
            focus: focused,
            ..State::default()
        };
        let mut inner = Kit::new(cv, te, f, s).field_frame(r, icon, st);
        if field == Field::Quick {
            // Room for the suggestion at the right.
            inner.w -= self.home.reserve;
        }
        let size = field_text(field) * s;
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
        let base = (r.y as f32 + (r.h as f32 + te.ascent(f.ui, size) * 0.72) / 2.0).round();
        let old =
            cv.set_clip(Rect::new(inner.x - 1, r.y + 2, inner.w + 2, r.h - 4).intersect(cv.clip()));
        if display.is_empty() && !focused {
            let color = if saved {
                pal().text_secondary
            } else {
                pal().text_faint
            };
            te.draw(
                cv,
                f.ui,
                size,
                inner.x as f32,
                base,
                placeholder,
                color,
                inner.w as f32,
            );
        } else {
            let scroll = if focused {
                self.field_scroll(field, inner, te, f)
            } else {
                0.0
            };
            let x = inner.x as f32 - scroll;
            if focused && tf.all {
                let tw = te.measure(f.ui, size, &display);
                cv.fill(
                    Rect::new(
                        x as i32,
                        r.y + (6.0 * s) as i32,
                        tw.ceil() as i32 + 1,
                        r.h - (12.0 * s) as i32,
                    ),
                    pal().text_selection,
                );
            }
            if display.is_empty() {
                te.draw(
                    cv,
                    f.ui,
                    size,
                    x + (5.0 * s).round(),
                    base,
                    placeholder,
                    pal().text_faint,
                    f32::MAX,
                );
            } else {
                te.draw(cv, f.ui, size, x, base, &display, pal().text, f32::MAX);
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
                        r.y + (8.0 * s) as i32,
                        (1.5 * s).max(1.0).round() as i32,
                        r.h - (16.0 * s) as i32,
                    ),
                    pal().accent,
                );
            }
        }
        cv.set_clip(old);
        self.hits.push((r, hit));
        self.field_rects.push((field, inner));
    }

    /// A kit button that reports `hit`.
    fn btn(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        b: &Button,
        hit: Hit,
    ) {
        let st = self.st(hit);
        Kit::new(cv, te, f, self.scale).button(r, b, st);
        self.hits.push((r, hit));
    }

    /// The width a kit button needs.
    fn btn_w(&self, te: &mut TextEngine, f: &Fonts, b: &Button) -> i32 {
        kit::button_width(te, f, self.scale, b)
    }

    /// An icon-only button that reports `hit`.
    #[allow(clippy::too_many_arguments)]
    fn icon_btn(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Icon,
        variant: Variant,
        hit: Hit,
    ) {
        let st = self.st(hit);
        Kit::new(cv, te, f, self.scale).icon_button(r, icon, variant, st);
        self.hits.push((r, hit));
    }
}

/// Text size of a field (logical px): the Home view's quick connect field
/// is larger than the form's.
fn field_text(f: Field) -> f32 {
    if f == Field::Quick { 16.0 } else { FIELD_TEXT }
}

/// The app icon (14 px at 100 %) at (x, y).
fn app_glyph(cv: &mut Canvas, s: f32, x: i32, y: i32, color: u32) {
    crate::icons::draw(cv, Icon::Apps, x as f32, y as f32, 14.0 * s, color);
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
    cfg.license_store = crate::settings::license_dir();
    cfg.bitmap_cache_dir = crate::settings::bitmap_cache_dir(&r.host, r.port);
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
            t.keyboard_layout = Some(0x0407);
        }
    }
    m
}

/// A running RemoteApp tab for the sample's "Office apps" connection: Ledger
/// open with a dialog, Planner starting.
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
                    title: "Budget 2027 - Ledger".into(),
                    icon: icon(0x3D7BD9),
                    minimized: false,
                },
                AppWindowItem {
                    id: 0x2002,
                    title: "Q3 forecast - Ledger".into(),
                    icon: icon(0x3D7BD9),
                    minimized: true,
                },
            ],
            running: vec!["||Ledger".into()],
            starting: vec!["||Planner".into()],
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
    m.set_message("Added Expense report. Save keeps it.", Tone::Muted);
    m
}

/// A desktop connection ("Test VM") with an app of its own: the app is
/// listed under it in the sidebar and in its editor, Connect still opens
/// the desktop.
pub fn sample_desktop_apps() -> Ui {
    let mut m = sample(false);
    m.store.connections[2].apps.push(AppEntry {
        name: "Event viewer".into(),
        program: "eventvwr.msc".into(),
        ..Default::default()
    });
    m.select(2);
    m.focus = None;
    m
}

/// The RemoteApp session tab.
pub fn sample_apps_tab() -> Ui {
    let mut m = sample(false);
    sample_apps_session(&mut m, true);
    m.set_message("Connected: apps.corp.example (4480×1440).", Tone::Muted);
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

/// The quit question over a session tab.
pub fn sample_exit() -> Ui {
    let mut m = sample(true);
    m.confirm_exit = Some(2);
    m
}

/// The Build server tab in a given state: 0 connecting, 1 ended, 2 failed,
/// 3 shown on its monitors (spanned).
pub fn sample_tab_state(state: u8) -> Ui {
    let mut m = sample(false);
    m.active = Some(2);
    if let Some(t) = m.tab_mut(2) {
        t.state = match state {
            0 => TabState::Connecting,
            1 => TabState::Ended("The server ended the session (logged off).".into()),
            2 => t.state.clone(),
            _ => {
                t.spanned = true;
                TabState::Connected {
                    width: 4480,
                    height: 1440,
                    bpp: 32,
                }
            }
        };
    }
    m
}

/// No saved connections yet (first start).
pub fn sample_empty() -> Ui {
    let mut m = Ui::new(Store::memory(Vec::new()), 1.0);
    m.focus = None;
    m
}

/// The Home view with live sessions (one a RemoteApp), favourites,
/// history and a few more connections; a fixed clock (a Saturday evening).
pub fn sample_home() -> Ui {
    let mut m = sample(false);
    for (name, host, group, user) in [
        ("SQL server", "sql-02.lab.local", "Work/Lab", r"LABuilder"),
        ("Jump host", "jump.corp.example", "Work", r"CORPlex"),
        ("Media PC", "192.168.1.40", "", "media"),
        ("Home NAS", "nas.home.arpa", "", "admin"),
    ] {
        m.store.connections.push(Connection {
            name: name.into(),
            host: host.into(),
            port: 3389,
            user: user.into(),
            group: group.into(),
            inherit: if group.is_empty() {
                Inherit::default()
            } else {
                Inherit::ALL
            },
            ..Default::default()
        });
    }
    m.store.connections[5].kerberos = true;
    sample_apps_session(&mut m, false);
    m.home_sample(1_794_679_200 + 2 * 3600);
    m.focus = Some(Field::Quick);
    m.message = None;
    m
}

/// The Home view with text typed into quick connect.
pub fn sample_home_typed(text: &str) -> Ui {
    let mut m = sample_home();
    m.home_sample_typed(text);
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
            ..Default::default()
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
                    name: "Ledger".into(),
                    program: "||Ledger".into(),
                    ..Default::default()
                },
                AppEntry {
                    name: "Planner".into(),
                    program: "||Planner".into(),
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
    m.tabs[1].live = Live {
        user: r"LAB\builder".into(),
        port: 3389,
        failure: Some(crate::failure::Failure {
            cause: crate::failure::Cause::WrongPassword,
            step: Some(rdp::ConnectStep::SignIn),
        }),
        ..Live::default()
    };
    m.active = if session_tab { Some(1) } else { None };
    m.set_message("Connected to 10.0.0.15.", Tone::Muted);
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

    /// `session_size_for` (used to size the remote desktop before a paint)
    /// matches the area `paint` gives the picture, with and without the
    /// panel, at 100 and 150 %.
    #[test]
    fn session_size_matches_the_painted_area() {
        let mut te = TextEngine::new();
        let Some(fonts) = load_fonts(&mut te) else {
            return;
        };
        for (scale, drawer) in [(1.0, true), (1.0, false), (1.5, true), (1.5, false)] {
            let mut m = sample(true);
            m.scale = scale;
            m.drawer = drawer;
            let (w, h) = (1500usize, 940usize);
            let mut px = vec![0u32; w * h];
            m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
            let (_, area) = m.session_area.expect("connected tab shows the picture");
            assert_eq!(
                m.session_size_for(w as i32, h as i32),
                (area.w, area.h),
                "scale {scale}, panel {drawer}"
            );
        }
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
        m.session_focus = true; // the session has the keyboard: bar hidden
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
        assert!(m.overlay_hit(500, 30).is_none(), "hidden: the picture's");
        // The bar floats over the picture: showing it repaints only its
        // rectangle, never the window.
        assert!(!m.mouse_move(500, 1), "the top edge reveals the bar");
        assert!(m.take_overlay_damage().is_some());
        assert!(m.over_overlay(500, 30), "the bar takes the pointer");
        m.paint(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        assert_eq!(
            m.session_area.unwrap().1,
            area,
            "the remote size does not change"
        );
        m.mouse_move(500, 300);
        assert!(
            m.take_overlay_damage().is_some(),
            "leaving the bar hides it"
        );
        assert!(!m.over_overlay(500, 30));
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
        // No session yet: a RemoteApp connection for Planner, saved password.
        let Some(Action::Connect { cfg, apps, fit, .. }) =
            click(&mut m, &mut te, &fonts, Hit::AppRow(3, 1))
        else {
            panic!("expected Connect");
        };
        assert_eq!(cfg.remote_app.as_ref().unwrap().program, "||Planner");
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
            Some(Action::ExecApp(3, a)) if a.program == "||Planner"
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
            "Type the password for Office apps, then click Ledger again."
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
        // Desktop: the apps card is there too, its fields in the tab order
        // (apps are the connection's whatever it opens).
        assert!(m.form_order().contains(&Field::AppProgram));
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
        // Back to Desktop keeps the list, but connects a desktop.
        click(&mut m, &mut te, &fonts, Hit::FormOpens(0));
        assert_eq!(m.opens, Opens::Desktop);
        m.field_mut(Field::Password).set("pw");
        match m.connect() {
            Some(Action::Connect { cfg, .. }) => assert!(cfg.remote_app.is_none()),
            _ => panic!("expected Connect"),
        }
        // Saved that way, the app stays listed under it and starts.
        m.save();
        assert_eq!(m.store.connections[2].opens, Opens::Desktop);
        assert!(m.rows().iter().any(|r| matches!(r, Row::App(2, 0))));
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::AppRow(2, 0)),
            Some(Action::Connect { cfg, .. }) if cfg.remote_app.is_some()
        ));
    }

    /// RDP-38: "Opens" decides only what Connect does. A desktop
    /// connection with apps lists them (sidebar, palette) and each starts
    /// its own RemoteApp session; Connect still opens the desktop.
    #[test]
    fn a_desktop_connection_lists_its_apps_and_connects_the_desktop() {
        let mut m = sample(false);
        let c = &mut m.store.connections[2];
        assert_eq!(c.opens, Opens::Desktop);
        c.password = Some("pw".into());
        c.apps.push(AppEntry {
            name: "Event viewer".into(),
            program: "eventvwr.msc".into(),
            ..Default::default()
        });
        assert!(m.rows().iter().any(|r| matches!(r, Row::App(2, 0))));
        // While filtering too.
        m.field_mut(Field::Filter).set("event");
        assert!(matches!(
            m.rows().as_slice(),
            [Row::Conn(2, 0), Row::App(2, 0)]
        ));
        m.field_mut(Field::Filter).set("");
        let cmds: Vec<_> = m.palette_entries().into_iter().map(|e| e.cmd).collect();
        assert!(cmds.contains(&palette::Command::ConnectApp(2, 0)));
        // The app row starts the app in a RemoteApp session.
        match m.launch_app(2, 0) {
            Some(Action::Connect { cfg, .. }) => assert_eq!(
                cfg.remote_app.as_ref().map(|a| a.program.as_str()),
                Some("eventvwr.msc")
            ),
            _ => panic!("expected a RemoteApp Connect"),
        }
        // Connect opens the desktop.
        m.select(2);
        match m.connect() {
            Some(Action::Connect { cfg, .. }) => assert!(cfg.remote_app.is_none()),
            _ => panic!("expected Connect"),
        }
        // Opens Apps: Connect starts the first app instead.
        m.opens = Opens::Apps;
        match m.connect() {
            Some(Action::Connect { cfg, .. }) => assert!(cfg.remote_app.is_some()),
            _ => panic!("expected Connect"),
        }
    }
}
