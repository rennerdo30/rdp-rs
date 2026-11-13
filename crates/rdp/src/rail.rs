//! RemoteApp: the Remote Programs virtual channel `rail` (MS-RDPERP 2.2.2)
//! and the window model built from the Windowing Alternate Secondary Drawing
//! Orders (MS-RDPERP 2.2.1.3, parsed in [`orders`]).
//!
//! [`Config::remote_app`](crate::Config::remote_app) switches a connection to
//! RemoteApp mode: the client sets INFO_RAIL in the Client Info PDU,
//! advertises the Remote Programs and Window List capability sets, opens the
//! `rail` channel and, after the server's Handshake, sends its Handshake,
//! Client Information, System Parameters and the Client Execute PDU for the
//! program (1.3.2.1, 1.3.2.4). The window list arrives as drawing orders on the
//! I/O channel; the client applies them to the shared [`RailState`] and
//! reports [`RailEvent`]s in [`PollOutcome::rail`](crate::PollOutcome::rail).
//! The UI sends window actions through a [`RailHandle`].

pub mod orders;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Result, proto};
use crate::pdu::{RailCaps, WindowListCaps};
use crate::trace;
use orders::{CachedIcon, IconInfo, IconSlot, Rect16, WindowInfo, WindowOrder};

/// Static channel name; Windows itself uses "RAIL" (3.2.5.1.1, <30>).
pub const CHANNEL_NAME: &str = "rail";

// TS_RAIL_PDU_HEADER orderType (2.2.2.1).
pub const TS_RAIL_ORDER_EXEC: u16 = 0x0001;
pub const TS_RAIL_ORDER_ACTIVATE: u16 = 0x0002;
pub const TS_RAIL_ORDER_SYSPARAM: u16 = 0x0003;
pub const TS_RAIL_ORDER_SYSCOMMAND: u16 = 0x0004;
pub const TS_RAIL_ORDER_HANDSHAKE: u16 = 0x0005;
pub const TS_RAIL_ORDER_NOTIFY_EVENT: u16 = 0x0006;
pub const TS_RAIL_ORDER_WINDOWMOVE: u16 = 0x0008;
pub const TS_RAIL_ORDER_LOCALMOVESIZE: u16 = 0x0009;
pub const TS_RAIL_ORDER_MINMAXINFO: u16 = 0x000A;
pub const TS_RAIL_ORDER_CLIENTSTATUS: u16 = 0x000B;
pub const TS_RAIL_ORDER_SYSMENU: u16 = 0x000C;
pub const TS_RAIL_ORDER_LANGBARINFO: u16 = 0x000D;
pub const TS_RAIL_ORDER_GET_APPID_REQ: u16 = 0x000E;
pub const TS_RAIL_ORDER_GET_APPID_RESP: u16 = 0x000F;
pub const TS_RAIL_ORDER_HANDSHAKE_EX: u16 = 0x0013;
pub const TS_RAIL_ORDER_ZORDER_SYNC: u16 = 0x0014;
pub const TS_RAIL_ORDER_CLOAK: u16 = 0x0015;
pub const TS_RAIL_ORDER_POWER_DISPLAY_REQUEST: u16 = 0x0016;
pub const TS_RAIL_ORDER_SNAP_ARRANGE: u16 = 0x0017;
pub const TS_RAIL_ORDER_GET_APPID_RESP_EX: u16 = 0x0018;
pub const TS_RAIL_ORDER_EXEC_RESULT: u16 = 0x0080;

// RailSupportLevel (2.2.1.1.1).
pub const TS_RAIL_LEVEL_SUPPORTED: u32 = 0x01;
pub const TS_RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED: u32 = 0x02;
pub const TS_RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED: u32 = 0x40;
pub const TS_RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED: u32 = 0x80;
// WndSupportLevel (2.2.1.1.2).
pub const TS_WINDOW_LEVEL_SUPPORTED: u32 = 1;
pub const TS_WINDOW_LEVEL_SUPPORTED_EX: u32 = 2;

// Client Information PDU flags (2.2.2.2.2).
pub const TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE: u32 = 0x0001;
pub const TS_RAIL_CLIENTSTATUS_AUTORECONNECT: u32 = 0x0002;
pub const TS_RAIL_CLIENTSTATUS_ZORDER_SYNC: u32 = 0x0004;
pub const TS_RAIL_CLIENTSTATUS_WINDOW_RESIZE_MARGIN_SUPPORTED: u32 = 0x0010;
pub const TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED: u32 = 0x0020;
pub const TS_RAIL_CLIENTSTATUS_BIDIRECTIONAL_CLOAK_SUPPORTED: u32 = 0x0200;

/// railHandshakeFlags: the server accepts the Client Window Snap PDU (2.2.2.2.3).
pub const TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED: u32 = 0x0004;

// Client Execute flags (2.2.2.3.1).
pub const TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY: u16 = 0x0001;
pub const TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS: u16 = 0x0008;

// System parameters the client sends (2.2.2.4.1).
pub const SPI_SETDRAGFULLWINDOWS: u32 = 0x0025;
pub const SPI_SETKEYBOARDCUES: u32 = 0x100B;
pub const SPI_SETKEYBOARDPREF: u32 = 0x0045;
pub const SPI_SETWORKAREA: u32 = 0x002F;
pub const RAIL_SPI_DISPLAYCHANGE: u32 = 0xF001;
pub const SPI_SETMOUSEBUTTONSWAP: u32 = 0x0021;
pub const RAIL_SPI_TASKBARPOS: u32 = 0xF000;
pub const SPI_SETHIGHCONTRAST: u32 = 0x0043;

/// buildNumber the client sends in its Handshake PDU; servers ignore it (<32>).
pub const CLIENT_BUILD: u32 = 7601;

/// Field limits of the Client Execute PDU, in bytes (2.2.2.3.1).
const MAX_EXE_OR_DIR: usize = 520;
const MAX_ARGS: usize = 16_000;

/// The program a RemoteApp session starts (Client Execute PDU, 2.2.2.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteApp {
    /// Executable, file or published alias such as `||notepad`.
    pub program: String,
    pub args: String,
    pub working_dir: String,
}

/// Window system commands (Client System Command PDU, 2.2.2.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SysCommand {
    Size = 0xF000,
    Move = 0xF010,
    Minimize = 0xF020,
    Maximize = 0xF030,
    Close = 0xF060,
    KeyMenu = 0xF100,
    Restore = 0xF120,
    Default = 0xF160,
}

/// Server Execute Result PDU (2.2.2.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub flags: u16,
    /// RAIL_EXEC_S_OK (0) or a RAIL_EXEC_E_* code.
    pub result: u16,
    /// Operating-system specific code.
    pub raw_result: u32,
    pub program: String,
}

impl ExecResult {
    pub fn ok(&self) -> bool {
        self.result == 0
    }

    pub fn result_name(&self) -> &'static str {
        match self.result {
            0 => "launched",
            1 => "server is not monitoring the input desktop",
            2 => "request could not be decoded",
            3 => "program blocked by policy (not in the allow list)",
            5 => "file not found",
            6 => "unspecified server error",
            7 => "session is locked",
            _ => "unknown result",
        }
    }
}

/// Server Min Max Info PDU (2.2.2.7.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MinMaxInfo {
    pub window_id: u32,
    pub max_width: i16,
    pub max_height: i16,
    pub max_pos_x: i16,
    pub max_pos_y: i16,
    pub min_track_width: i16,
    pub min_track_height: i16,
    pub max_track_width: i16,
    pub max_track_height: i16,
}

/// Server Move/Size Start or End PDU (2.2.2.7.2, 2.2.2.7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalMoveSize {
    pub window_id: u32,
    /// True for Move/Size Start, false for End.
    pub start: bool,
    /// RAIL_WMSZ_* (1 = left edge ... 9 = move, 0xA keyboard move, 0xB keyboard size).
    pub kind: u16,
    /// Start: the pointer position (or offset for moves); End: the top-left corner.
    pub x: i16,
    pub y: i16,
}

/// One message the server sends on the `rail` channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPdu {
    Handshake {
        build: u32,
    },
    HandshakeEx {
        build: u32,
        flags: u32,
    },
    ExecResult(ExecResult),
    /// Server System Parameters Update (2.2.2.5.1): SPI_SETSCREENSAVEACTIVE or
    /// SPI_SETSCREENSAVESECURE with a one-byte boolean.
    SysParam {
        param: u32,
        value: u8,
    },
    MinMaxInfo(MinMaxInfo),
    LocalMoveSize(LocalMoveSize),
    /// Get Application ID Response (2.2.2.8.1) or the Extended one (2.2.2.8.2,
    /// with the process id and image name).
    AppId {
        window_id: u32,
        app_id: String,
        process: Option<(u32, String)>,
    },
    LanguageBar {
        status: u32,
    },
    ZOrderSync {
        marker_window: u32,
    },
    Cloak {
        window_id: u32,
        cloaked: bool,
    },
    PowerDisplayRequest {
        active: bool,
    },
    /// A message type this client does not act on.
    Other {
        order_type: u16,
    },
}

fn pdu(order_type: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.put_u16(order_type);
    out.put_u16((4 + body.len()) as u16);
    out.put_bytes(body);
    out
}

/// A fixed-size field of UTF-16LE text, NUL-terminated within `n` bytes.
fn fixed_text(r: &mut Reader, n: usize) -> Result<String> {
    let n = n.min(r.remaining());
    Ok(orders::utf16_text(r.bytes(n)?))
}

/// Parses one reassembled `rail` channel message (TS_RAIL_PDU_HEADER, 2.2.2.1).
pub fn parse(msg: &[u8]) -> Result<ServerPdu> {
    let mut h = Reader::new(msg);
    let order_type = h.u16()?;
    let len = h.u16()? as usize;
    if len < 4 || len > msg.len() {
        return proto(format!("rail order {order_type:#x} length {len}"));
    }
    let mut r = Reader::new(&msg[4..len]);
    Ok(match order_type {
        TS_RAIL_ORDER_HANDSHAKE => ServerPdu::Handshake { build: r.u32()? },
        TS_RAIL_ORDER_HANDSHAKE_EX => ServerPdu::HandshakeEx {
            build: r.u32()?,
            flags: r.u32()?,
        },
        TS_RAIL_ORDER_EXEC_RESULT => {
            let flags = r.u16()?;
            let result = r.u16()?;
            let raw_result = r.u32()?;
            r.u16()?; // Padding
            let n = r.u16()? as usize;
            ServerPdu::ExecResult(ExecResult {
                flags,
                result,
                raw_result,
                program: orders::utf16_text(r.bytes(n)?),
            })
        }
        TS_RAIL_ORDER_SYSPARAM => ServerPdu::SysParam {
            param: r.u32()?,
            value: r.u8()?,
        },
        TS_RAIL_ORDER_MINMAXINFO => {
            let window_id = r.u32()?;
            let mut v = [0i16; 8];
            for x in &mut v {
                *x = r.u16()? as i16;
            }
            ServerPdu::MinMaxInfo(MinMaxInfo {
                window_id,
                max_width: v[0],
                max_height: v[1],
                max_pos_x: v[2],
                max_pos_y: v[3],
                min_track_width: v[4],
                min_track_height: v[5],
                max_track_width: v[6],
                max_track_height: v[7],
            })
        }
        TS_RAIL_ORDER_LOCALMOVESIZE => ServerPdu::LocalMoveSize(LocalMoveSize {
            window_id: r.u32()?,
            start: r.u16()? != 0,
            kind: r.u16()?,
            x: r.u16()? as i16,
            y: r.u16()? as i16,
        }),
        TS_RAIL_ORDER_GET_APPID_RESP | TS_RAIL_ORDER_GET_APPID_RESP_EX => {
            let window_id = r.u32()?;
            let app_id = fixed_text(&mut r, MAX_EXE_OR_DIR)?;
            let process = if order_type == TS_RAIL_ORDER_GET_APPID_RESP_EX {
                Some((r.u32()?, fixed_text(&mut r, MAX_EXE_OR_DIR)?))
            } else {
                None
            };
            ServerPdu::AppId {
                window_id,
                app_id,
                process,
            }
        }
        TS_RAIL_ORDER_LANGBARINFO => ServerPdu::LanguageBar { status: r.u32()? },
        TS_RAIL_ORDER_ZORDER_SYNC => ServerPdu::ZOrderSync {
            marker_window: r.u32()?,
        },
        TS_RAIL_ORDER_CLOAK => ServerPdu::Cloak {
            window_id: r.u32()?,
            cloaked: r.u8()? != 0,
        },
        TS_RAIL_ORDER_POWER_DISPLAY_REQUEST => ServerPdu::PowerDisplayRequest {
            active: r.u32()? != 0,
        },
        t => ServerPdu::Other { order_type: t },
    })
}

/// Handshake PDU (2.2.2.2.1).
pub fn handshake(build: u32) -> Vec<u8> {
    pdu(TS_RAIL_ORDER_HANDSHAKE, &build.to_le_bytes())
}

/// Client Information PDU (2.2.2.2.2).
pub fn client_status(flags: u32) -> Vec<u8> {
    pdu(TS_RAIL_ORDER_CLIENTSTATUS, &flags.to_le_bytes())
}

/// Client Execute PDU (2.2.2.3.1). Environment variables are expanded on the
/// server when the working directory or arguments contain a `%`.
pub fn exec(app: &RemoteApp) -> Result<Vec<u8>> {
    let exe = utf16le(&app.program);
    let dir = utf16le(&app.working_dir);
    let args = utf16le(&app.args);
    if exe.is_empty() || exe.len() > MAX_EXE_OR_DIR {
        return proto(format!(
            "RemoteApp program is {} bytes (1..=520)",
            exe.len()
        ));
    }
    if dir.len() > MAX_EXE_OR_DIR || args.len() > MAX_ARGS {
        return proto("RemoteApp working directory or arguments too long");
    }
    let mut flags = 0;
    if app.working_dir.contains('%') {
        flags |= TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY;
    }
    if app.args.contains('%') {
        flags |= TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS;
    }
    Ok(exec_raw(flags, &exe, &dir, &args))
}

fn exec_raw(flags: u16, exe: &[u8], dir: &[u8], args: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(flags);
    b.put_u16(exe.len() as u16);
    b.put_u16(dir.len() as u16);
    b.put_u16(args.len() as u16);
    b.put_bytes(exe);
    b.put_bytes(dir);
    b.put_bytes(args);
    pdu(TS_RAIL_ORDER_EXEC, &b)
}

/// Client System Parameters Update PDU (2.2.2.4.1) with a raw body.
pub fn sysparam(param: u32, body: &[u8]) -> Vec<u8> {
    let mut b = param.to_le_bytes().to_vec();
    b.put_bytes(body);
    pdu(TS_RAIL_ORDER_SYSPARAM, &b)
}

fn rect_body(r: Rect16) -> [u8; 8] {
    let mut b = [0u8; 8];
    for (i, v) in [r.left, r.top, r.right, r.bottom].into_iter().enumerate() {
        b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// The system parameters sent after the handshake (3.2.5.2.3.1), for a
/// desktop of `width` x `height` with no client taskbar: high contrast off
/// (the 4.4.1 example), no mouse button swap, mouse preferred, full window
/// drag, access keys underlined on demand, the whole desktop as work area.
pub fn default_sysparams(width: u16, height: u16) -> Vec<Vec<u8>> {
    let screen = Rect16 {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    };
    vec![
        // TS_HIGHCONTRAST: Flags 0x7E, ColorSchemeLength 2, an empty string.
        sysparam(SPI_SETHIGHCONTRAST, &[0x7E, 0, 0, 0, 2, 0, 0, 0, 0, 0]),
        sysparam(SPI_SETMOUSEBUTTONSWAP, &[0]),
        sysparam(SPI_SETKEYBOARDPREF, &[0]),
        sysparam(SPI_SETDRAGFULLWINDOWS, &[1]),
        sysparam(SPI_SETKEYBOARDCUES, &[0]),
        sysparam(SPI_SETWORKAREA, &rect_body(screen)),
        sysparam(RAIL_SPI_DISPLAYCHANGE, &rect_body(screen)),
        sysparam(RAIL_SPI_TASKBARPOS, &rect_body(Rect16::default())),
    ]
}

/// Client Activate PDU (2.2.2.6.1).
pub fn activate(window_id: u32, enabled: bool) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    b.put_u8(enabled as u8);
    pdu(TS_RAIL_ORDER_ACTIVATE, &b)
}

/// Client System Menu PDU (2.2.2.6.2).
pub fn sysmenu(window_id: u32, left: i16, top: i16) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    b.put_u16(left as u16);
    b.put_u16(top as u16);
    pdu(TS_RAIL_ORDER_SYSMENU, &b)
}

/// Client System Command PDU (2.2.2.6.3).
pub fn syscommand(window_id: u32, command: SysCommand) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    b.put_u16(command as u16);
    pdu(TS_RAIL_ORDER_SYSCOMMAND, &b)
}

/// Client Notify Event PDU (2.2.2.6.4); `message` is a WM_* or NIN_* code.
pub fn notify_event(window_id: u32, icon_id: u32, message: u32) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    b.put_u32(icon_id);
    b.put_u32(message);
    pdu(TS_RAIL_ORDER_NOTIFY_EVENT, &b)
}

/// Client Get Application ID PDU (2.2.2.6.5).
pub fn get_app_id(window_id: u32) -> Vec<u8> {
    pdu(TS_RAIL_ORDER_GET_APPID_REQ, &window_id.to_le_bytes())
}

fn window_rect_pdu(order_type: u16, window_id: u32, r: [i16; 4]) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    for v in r {
        b.put_u16(v as u16);
    }
    pdu(order_type, &b)
}

/// Client Window Move PDU (2.2.2.7.4): left, top, right, bottom, including
/// the resize margins.
pub fn window_move(window_id: u32, rect: [i16; 4]) -> Vec<u8> {
    window_rect_pdu(TS_RAIL_ORDER_WINDOWMOVE, window_id, rect)
}

/// Client Window Snap PDU (2.2.2.7.5).
pub fn snap_arrange(window_id: u32, rect: [i16; 4]) -> Vec<u8> {
    window_rect_pdu(TS_RAIL_ORDER_SNAP_ARRANGE, window_id, rect)
}

/// Language Bar Information PDU (2.2.2.9.1).
pub fn language_bar(status: u32) -> Vec<u8> {
    pdu(TS_RAIL_ORDER_LANGBARINFO, &status.to_le_bytes())
}

/// Window Cloak State Change PDU (2.2.2.12.1).
pub fn cloak(window_id: u32, cloaked: bool) -> Vec<u8> {
    let mut b = window_id.to_le_bytes().to_vec();
    b.put_u8(cloaked as u8);
    pdu(TS_RAIL_ORDER_CLOAK, &b)
}

/// The client's Remote Programs and Window List capability sets for the
/// Confirm Active PDU (3.2.5.1.4): icon cache sizes are the minimum of ours
/// (3 caches of 12 entries) and the server's.
pub fn client_caps(server: Option<&WindowListCaps>) -> RailCaps {
    let (caches, entries) = server.map_or((3, 12), |s| {
        (s.icon_caches.min(3), s.icon_cache_entries.min(12))
    });
    RailCaps {
        rail_support_level: TS_RAIL_LEVEL_SUPPORTED
            | TS_RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED
            | TS_RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED,
        window: WindowListCaps {
            level: TS_WINDOW_LEVEL_SUPPORTED_EX,
            icon_caches: caches,
            icon_cache_entries: entries,
        },
    }
}

/// Client Information PDU flags this client sends: resize margins and large
/// icons are modelled; local move/size and Z-order sync need UI support and
/// stay off. AUTORECONNECT is set when the logon resumes a session.
pub fn client_status_flags(auto_reconnect: bool) -> u32 {
    let mut f = TS_RAIL_CLIENTSTATUS_WINDOW_RESIZE_MARGIN_SUPPORTED
        | TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED;
    if auto_reconnect {
        f |= TS_RAIL_CLIENTSTATUS_AUTORECONNECT;
    }
    f
}

/// A decoded window or notification icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailIcon {
    pub width: u16,
    pub height: u16,
    /// Top-down RGBA, 4 bytes per pixel, straight alpha.
    pub rgba: Vec<u8>,
}

/// A window rectangle in server screen coordinates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// One server window as the client knows it (2.2.1.3.1.2.1, 3.2.5.1.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RailWindow {
    pub owner: u32,
    pub style: u32,
    pub ex_style: u32,
    /// 0 hidden, 2 minimized, 3 maximized, 5 shown.
    pub show_state: u8,
    pub title: String,
    pub client_offset: (i32, i32),
    pub client_delta: (i32, i32),
    pub client_area_size: Option<(u32, u32)>,
    /// Window bounds without the resize margins.
    pub window_rect: WindowRect,
    /// Hit-testable margins: left, right, top, bottom.
    pub resize_margins: [u32; 4],
    /// Window geometry, in window coordinates.
    pub window_rects: Vec<Rect16>,
    pub visible_offset: (i32, i32),
    /// The visible region, in window coordinates relative to `visible_offset`.
    pub visible_rects: Vec<Rect16>,
    /// Small icon (title bar).
    pub icon: Option<RailIcon>,
    /// Large icon (Alt+Tab).
    pub big_icon: Option<RailIcon>,
    pub app_id: Option<String>,
    pub min_max: Option<MinMaxInfo>,
    pub cloaked: bool,
    pub root_parent: Option<u32>,
    pub taskbar_button: Option<u8>,
    pub enforce_server_zorder: bool,
    /// Registered as an application desktop toolbar, with its edge.
    pub appbar: Option<u8>,
}

/// One notification-area icon (2.2.1.3.2.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifyIcon {
    pub version: u32,
    pub tooltip: String,
    pub info_tip: Option<orders::InfoTip>,
    pub hidden: bool,
    pub icon: Option<RailIcon>,
}

/// The server's windows and notification icons.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RailState {
    pub windows: BTreeMap<u32, RailWindow>,
    /// Keyed by (owning window id, notify icon id).
    pub notify_icons: BTreeMap<(u32, u32), NotifyIcon>,
    pub active_window: Option<u32>,
    /// Top-level windows, front to back.
    pub z_order: Vec<u32>,
    /// The server monitors the input desktop (false on a secure desktop).
    pub monitored: bool,
    /// Marker window id from the Z-Order Sync Information PDU (3.2.1.2).
    pub marker_window: Option<u32>,
    /// railHandshakeFlags once the handshake completed (0 for a plain Handshake).
    pub server_flags: Option<u32>,
}

/// What changed, in the order the server said it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailEvent {
    /// The channel handshake completed and the program was requested.
    Ready {
        server_flags: u32,
    },
    ExecResult(ExecResult),
    WindowCreated(u32),
    WindowUpdated(u32),
    WindowDeleted(u32),
    NotifyIconCreated {
        window_id: u32,
        icon_id: u32,
    },
    NotifyIconUpdated {
        window_id: u32,
        icon_id: u32,
    },
    NotifyIconDeleted {
        window_id: u32,
        icon_id: u32,
    },
    ActiveWindow(u32),
    ZOrder(Vec<u32>),
    /// The server starts resending all windows (after a reconnect).
    SyncStarted,
    SyncCompleted,
    /// The server stopped monitoring the desktop; all windows were removed.
    DesktopNotMonitored,
    MinMaxInfo(MinMaxInfo),
    LocalMoveSize(LocalMoveSize),
    ServerSysParam {
        param: u32,
        value: u8,
    },
    LanguageBar {
        status: u32,
    },
    PowerDisplayRequest {
        active: bool,
    },
}

#[derive(Default)]
struct Shared {
    state: RailState,
    events: Vec<RailEvent>,
    /// Client PDUs queued by the UI, sent once the handshake is done.
    outgoing: Vec<Vec<u8>>,
    icon_cache: HashMap<(u8, u16), RailIcon>,
}

fn decode_icon(icon: &IconInfo) -> Option<RailIcon> {
    match icon.to_rgba() {
        Ok(rgba) => Some(RailIcon {
            width: icon.width,
            height: icon.height,
            rgba,
        }),
        Err(e) => {
            trace!("rail icon not decoded: {e}");
            None
        }
    }
}

impl Shared {
    /// Decodes an icon and stores it in its cache slot (CacheId 0xFF: none).
    fn icon(&mut self, icon: &IconInfo) -> Option<RailIcon> {
        let decoded = decode_icon(icon)?;
        if icon.cache_id != 0xFF {
            self.icon_cache
                .insert((icon.cache_id, icon.cache_entry), decoded.clone());
        }
        Some(decoded)
    }

    fn cached(&self, c: CachedIcon) -> Option<RailIcon> {
        let icon = self.icon_cache.get(&(c.cache_id, c.cache_entry)).cloned();
        if icon.is_none() {
            trace!("rail cached icon {}/{} unknown", c.cache_id, c.cache_entry);
        }
        icon
    }

    fn clear(&mut self) {
        for id in std::mem::take(&mut self.state.windows).into_keys() {
            self.events.push(RailEvent::WindowDeleted(id));
        }
        for (window_id, icon_id) in std::mem::take(&mut self.state.notify_icons).into_keys() {
            self.events
                .push(RailEvent::NotifyIconDeleted { window_id, icon_id });
        }
        self.state.z_order.clear();
        self.state.active_window = None;
    }

    fn set_window_icon(&mut self, id: u32, slot: IconSlot, icon: Option<RailIcon>) {
        if slot.overlay {
            return; // taskbar overlay icons are not modelled
        }
        let Some(w) = self.state.windows.get_mut(&id) else {
            return;
        };
        if slot.big {
            w.big_icon = icon;
        } else {
            w.icon = icon;
        }
        self.events.push(RailEvent::WindowUpdated(id));
    }

    /// Applies one window order (3.2.5.1.6 to 3.2.5.1.8).
    fn apply(&mut self, order: WindowOrder) {
        match order {
            WindowOrder::Window { id, new, info } => {
                let exists = self.state.windows.contains_key(&id);
                if !new && !exists {
                    trace!("rail update for unknown window {id:#x} ignored");
                    return;
                }
                apply_window_info(self.state.windows.entry(id).or_default(), info);
                self.events.push(if exists {
                    RailEvent::WindowUpdated(id)
                } else {
                    RailEvent::WindowCreated(id)
                });
            }
            WindowOrder::Icon { id, slot, icon } => {
                let icon = self.icon(&icon);
                self.set_window_icon(id, slot, icon);
            }
            WindowOrder::CachedIcon { id, slot, cached } => {
                let icon = self.cached(cached);
                self.set_window_icon(id, slot, icon);
            }
            WindowOrder::WindowDeleted { id } => {
                if self.state.windows.remove(&id).is_some() {
                    self.state.z_order.retain(|&w| w != id);
                    if self.state.active_window == Some(id) {
                        self.state.active_window = None;
                    }
                    self.events.push(RailEvent::WindowDeleted(id));
                }
            }
            WindowOrder::NotifyIcon {
                window_id,
                icon_id,
                new,
                info,
            } => {
                let key = (window_id, icon_id);
                let exists = self.state.notify_icons.contains_key(&key);
                if !new && !exists {
                    return;
                }
                let icon = match (&info.icon, info.cached_icon) {
                    (Some(i), _) => Some(self.icon(i)),
                    (None, Some(c)) => Some(self.cached(c)),
                    (None, None) => None,
                };
                let n = self.state.notify_icons.entry(key).or_default();
                if let Some(v) = info.version {
                    n.version = v;
                }
                if let Some(t) = info.tooltip {
                    n.tooltip = t;
                }
                if info.info_tip.is_some() {
                    n.info_tip = info.info_tip;
                }
                if let Some(s) = info.state {
                    n.hidden = s & 1 != 0;
                }
                if let Some(i) = icon {
                    n.icon = i;
                }
                self.events.push(if exists {
                    RailEvent::NotifyIconUpdated { window_id, icon_id }
                } else {
                    RailEvent::NotifyIconCreated { window_id, icon_id }
                });
            }
            WindowOrder::NotifyIconDeleted { window_id, icon_id } => {
                if self
                    .state
                    .notify_icons
                    .remove(&(window_id, icon_id))
                    .is_some()
                {
                    self.events
                        .push(RailEvent::NotifyIconDeleted { window_id, icon_id });
                }
            }
            WindowOrder::Desktop(d) => {
                if d.arc_began && d.hooked {
                    self.clear();
                    self.events.push(RailEvent::SyncStarted);
                }
                if d.hooked {
                    self.state.monitored = true;
                }
                if let Some(z) = d.z_order {
                    self.state.z_order = z.clone();
                    self.events.push(RailEvent::ZOrder(z));
                }
                if let Some(a) = d.active_window {
                    self.state.active_window = Some(a);
                    self.events.push(RailEvent::ActiveWindow(a));
                }
                if d.arc_completed {
                    self.events.push(RailEvent::SyncCompleted);
                }
            }
            WindowOrder::DesktopNone => {
                self.clear();
                self.state.monitored = false;
                self.events.push(RailEvent::DesktopNotMonitored);
            }
        }
    }

    /// Applies one server `rail` PDU after the handshake.
    fn server_pdu(&mut self, p: ServerPdu) {
        let ev = match p {
            ServerPdu::Handshake { .. } | ServerPdu::HandshakeEx { .. } => return,
            ServerPdu::ExecResult(r) => {
                trace!("RemoteApp exec result {}: {}", r.result, r.result_name());
                RailEvent::ExecResult(r)
            }
            ServerPdu::SysParam { param, value } => RailEvent::ServerSysParam { param, value },
            ServerPdu::MinMaxInfo(m) => {
                let Some(w) = self.state.windows.get_mut(&m.window_id) else {
                    return;
                };
                w.min_max = Some(m);
                RailEvent::MinMaxInfo(m)
            }
            ServerPdu::LocalMoveSize(m) => RailEvent::LocalMoveSize(m),
            ServerPdu::AppId {
                window_id, app_id, ..
            } => {
                let Some(w) = self.state.windows.get_mut(&window_id) else {
                    return;
                };
                w.app_id = Some(app_id);
                RailEvent::WindowUpdated(window_id)
            }
            ServerPdu::LanguageBar { status } => RailEvent::LanguageBar { status },
            ServerPdu::ZOrderSync { marker_window } => {
                self.state.marker_window = Some(marker_window);
                return;
            }
            ServerPdu::Cloak { window_id, cloaked } => {
                let Some(w) = self.state.windows.get_mut(&window_id) else {
                    return;
                };
                w.cloaked = cloaked;
                RailEvent::WindowUpdated(window_id)
            }
            ServerPdu::PowerDisplayRequest { active } => RailEvent::PowerDisplayRequest { active },
            ServerPdu::Other { order_type } => {
                trace!("rail order {order_type:#x} ignored");
                return;
            }
        };
        self.events.push(ev);
    }
}

fn apply_window_info(w: &mut RailWindow, info: WindowInfo) {
    if let Some(v) = info.owner {
        w.owner = v;
    }
    if let Some((s, ex)) = info.style {
        w.style = s;
        w.ex_style = ex;
    }
    if let Some(v) = info.show_state {
        w.show_state = v;
    }
    if let Some(v) = info.title {
        w.title = v;
    }
    if let Some(v) = info.client_offset {
        w.client_offset = v;
    }
    if let Some(v) = info.client_delta {
        w.client_delta = v;
    }
    if info.client_area_size.is_some() {
        w.client_area_size = info.client_area_size;
    }
    if let Some((x, y)) = info.window_offset {
        w.window_rect.x = x;
        w.window_rect.y = y;
    }
    if let Some((width, height)) = info.window_size {
        w.window_rect.width = width;
        w.window_rect.height = height;
    }
    if let Some((l, r)) = info.resize_margin_x {
        w.resize_margins[0] = l;
        w.resize_margins[1] = r;
    }
    if let Some((t, b)) = info.resize_margin_y {
        w.resize_margins[2] = t;
        w.resize_margins[3] = b;
    }
    if let Some(v) = info.window_rects {
        w.window_rects = v;
    }
    if let Some(v) = info.visible_offset {
        w.visible_offset = v;
    }
    if let Some(v) = info.visibility_rects {
        w.visible_rects = v;
    }
    if info.root_parent.is_some() {
        w.root_parent = info.root_parent;
    }
    if info.taskbar_button.is_some() {
        w.taskbar_button = info.taskbar_button;
    }
    if let Some(v) = info.enforce_server_zorder {
        w.enforce_server_zorder = v == 1;
    }
    match (info.appbar_state, info.appbar_edge) {
        (Some(0), _) => w.appbar = None,
        (Some(_), edge) => w.appbar = Some(edge.or(w.appbar).unwrap_or(0)),
        (None, Some(edge)) if w.appbar.is_some() => w.appbar = Some(edge),
        _ => {}
    }
}

/// Window actions for the UI, and the shared window model. Clone freely.
#[derive(Clone)]
pub struct RailHandle {
    shared: Arc<Mutex<Shared>>,
}

impl RailHandle {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn send(&self, msg: Vec<u8>) {
        self.lock().outgoing.push(msg);
    }

    /// A snapshot of all windows and notification icons.
    pub fn state(&self) -> RailState {
        self.lock().state.clone()
    }

    pub fn window(&self, id: u32) -> Option<RailWindow> {
        self.lock().state.windows.get(&id).cloned()
    }

    /// Activates (`true`) or deactivates a window, for focus changes the
    /// server cannot see as clicks, such as Alt+Tab (3.2.5.2.5.1).
    pub fn set_focus(&self, window_id: u32, focused: bool) {
        self.send(activate(window_id, focused));
    }

    pub fn sys_command(&self, window_id: u32, command: SysCommand) {
        self.send(syscommand(window_id, command));
    }

    pub fn minimize(&self, window_id: u32) {
        self.sys_command(window_id, SysCommand::Minimize);
    }

    pub fn maximize(&self, window_id: u32) {
        self.sys_command(window_id, SysCommand::Maximize);
    }

    pub fn restore(&self, window_id: u32) {
        self.sys_command(window_id, SysCommand::Restore);
    }

    pub fn close(&self, window_id: u32) {
        self.sys_command(window_id, SysCommand::Close);
    }

    /// Shows the window's system menu at a screen position.
    pub fn sys_menu(&self, window_id: u32, x: i16, y: i16) {
        self.send(sysmenu(window_id, x, y));
    }

    /// Reports a finished local move or resize: `rect` is left, top, right,
    /// bottom including the resize margins (2.2.2.7.4).
    pub fn move_window(&self, window_id: u32, rect: [i16; 4]) {
        self.send(window_move(window_id, rect));
    }

    /// Reports a snap arrangement; falls back to a Window Move PDU when the
    /// server did not offer snapping (3.2.5.2.7.5).
    pub fn snap_window(&self, window_id: u32, rect: [i16; 4]) {
        let mut s = self.lock();
        let snap = s
            .state
            .server_flags
            .is_some_and(|f| f & TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED != 0);
        s.outgoing.push(if snap {
            snap_arrange(window_id, rect)
        } else {
            window_move(window_id, rect)
        });
    }

    /// Forwards a mouse or keyboard action on a notification icon.
    pub fn notify_icon_event(&self, window_id: u32, icon_id: u32, message: u32) {
        self.send(notify_event(window_id, icon_id, message));
    }

    /// Asks for a window's Application ID; the answer updates `app_id`.
    pub fn request_app_id(&self, window_id: u32) {
        self.send(get_app_id(window_id));
    }

    pub fn set_cloaked(&self, window_id: u32, cloaked: bool) {
        self.send(cloak(window_id, cloaked));
    }

    pub(crate) fn apply_orders(&self, orders: Vec<WindowOrder>) {
        let mut s = self.lock();
        for o in orders {
            s.apply(o);
        }
    }

    pub(crate) fn take_events(&self) -> Vec<RailEvent> {
        std::mem::take(&mut self.lock().events)
    }
}

/// The `rail` static channel handler.
pub struct Rail {
    shared: Arc<Mutex<Shared>>,
    app: RemoteApp,
    width: u16,
    height: u16,
    status_flags: u32,
    ready: bool,
}

/// Creates the `rail` channel for `app` on a `width` x `height` desktop. The
/// Client Information PDU carries `status_flags` (TS_RAIL_CLIENTSTATUS_*).
pub fn rail(
    app: RemoteApp,
    width: u16,
    height: u16,
    status_flags: u32,
) -> Result<(Rail, RailHandle)> {
    exec(&app)?; // reject a program the server could not accept, before connecting
    let shared = Arc::new(Mutex::new(Shared::default()));
    let handle = RailHandle {
        shared: shared.clone(),
    };
    let channel = Rail {
        shared,
        app,
        width,
        height,
        status_flags,
        ready: false,
    };
    Ok((channel, handle))
}

impl StaticChannel for Rail {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let p = parse(msg)?;
        let server_flags = match p {
            ServerPdu::Handshake { .. } => 0,
            ServerPdu::HandshakeEx { flags, .. } => flags,
            // 3.1.5.2: nothing else counts before the handshake.
            _ if !self.ready => {
                trace!("rail PDU before the handshake ignored");
                return Ok(());
            }
            p => {
                self.shared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .server_pdu(p);
                return Ok(());
            }
        };
        if self.ready {
            return Ok(());
        }
        // 1.3.2.4: Handshake, Client Information and System Parameters right
        // after the server's handshake, then the program (Client Execute).
        out.send(handshake(CLIENT_BUILD));
        out.send(client_status(self.status_flags));
        for m in default_sysparams(self.width, self.height) {
            out.send(m);
        }
        out.send(exec(&self.app)?);
        self.ready = true;
        let mut s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        s.state.server_flags = Some(server_flags);
        s.events.push(RailEvent::Ready { server_flags });
        trace!("RemoteApp handshake done (flags {server_flags:#x}); program requested");
        Ok(())
    }

    fn tick(&mut self, out: &mut ChannelOut) -> Result<()> {
        if self.ready {
            let mut s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            for m in s.outgoing.drain(..) {
                out.send(m);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
