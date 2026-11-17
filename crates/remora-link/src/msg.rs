//! Protocol messages (version 1.0) and their payload encodings.
//!
//! Type numbers are grouped by feature; the numbers are part of the wire
//! contract (docs/HELPER-PROTOCOL.md) and never change meaning:
//!
//! | range    | group                                        | channel |
//! |----------|----------------------------------------------|---------|
//! | `0x00xx` | session (SAS exchange), inside [`crate::SecureSession`] | Ctl |
//! | `0x01xx` | control: hello, heartbeat, pairing, errors   | Ctl     |
//! | `0x02xx` | session information                          | Ctl     |
//! | `0x03xx` | open a link on the client                    | Ctl     |
//! | `0x040x` | file transfer control                        | Ctl     |
//! | `0x048x` | file transfer data                           | Bulk    |
//! | `0x05xx` | server graphics settings (1.2)               | Ctl     |
//! | `0x06xx` | helper update (1.2)                          | Ctl     |
//!
//! A type this side does not know decodes as [`Message::Unknown`]; the
//! receiver answers with [`Message::Unsupported`] and keeps the channel open.

use crate::error::{Error, Result};
use crate::frame::{self, MAX_PAYLOAD};
use crate::wire::{Put, Reader};

/// Major protocol version. A different major closes the channel.
pub const PROTO_MAJOR: u16 = 1;
/// Minor protocol version. Minors only add optional messages and fields.
/// 1.1 adds [`Message::PeerPairing`] and [`Message::ClientName`] (the
/// helper pins Remora's client key). 1.2 adds the server graphics settings:
/// [`Message::ServerSettings`], [`Message::TuneServer`] and
/// [`Message::TuneResult`] under [`cap::SERVER_TUNING`], and helper updates
/// ([`Message::UpdateBegin`] and the rest) under [`cap::HELPER_UPDATE`],
/// the latency meter ([`Message::LatencyMark`]) under [`cap::LATENCY`], and
/// the helper picture stream ([`Message::StreamStart`]) under
/// [`cap::STREAM`].
pub const PROTO_MINOR: u16 = 2;

// Session messages (handled inside SecureSession).
pub const SAS_COMMIT: u16 = 0x0001;
pub const SAS_NONCE: u16 = 0x0002;
pub const SAS_REVEAL: u16 = 0x0003;
// Control.
pub const HELLO: u16 = 0x0100;
pub const HELLO_ACK: u16 = 0x0101;
pub const HEARTBEAT: u16 = 0x0102;
pub const PAIRING: u16 = 0x0103;
pub const UNSUPPORTED: u16 = 0x0104;
pub const ERROR: u16 = 0x0105;
/// 1.1: the helper's side of pairing (helper → Remora).
pub const PEER_PAIRING: u16 = 0x0106;
/// 1.1: Remora's name for the helper's client list (Remora → helper).
pub const CLIENT_NAME: u16 = 0x0107;
// Session information.
pub const SESSION_INFO: u16 = 0x0200;
/// 1.2: the session's active keyboard layout (RDP-68).
pub const KEYBOARD_LAYOUT: u16 = 0x0201;
// Links.
pub const OPEN_URL: u16 = 0x0300;
pub const OPEN_URL_RESULT: u16 = 0x0301;
// File transfer control (Ctl).
pub const FILE_OFFER: u16 = 0x0400;
pub const FILE_ACCEPT: u16 = 0x0401;
pub const FILE_REJECT: u16 = 0x0402;
pub const FILE_CREDIT: u16 = 0x0403;
pub const FILE_CANCEL: u16 = 0x0404;
pub const FILE_COMPLETE: u16 = 0x0405;
// File transfer data (Bulk).
pub const FILE_CHUNK: u16 = 0x0480;
pub const FILE_BLOCK_HASH: u16 = 0x0481;
pub const FILE_END: u16 = 0x0482;
// Server graphics settings (Ctl, 1.2).
/// Helper → Remora: the server's graphics settings, read without admin.
pub const SERVER_SETTINGS: u16 = 0x0500;
/// Remora → helper: change them (the server's user confirms elevation).
pub const TUNE_SERVER: u16 = 0x0501;
/// Helper → Remora: how the change went; same `request_id`.
pub const TUNE_RESULT: u16 = 0x0502;
// Helper update (Ctl, 1.2): see `crate::update`.
pub const UPDATE_BEGIN: u16 = 0x0600;
pub const UPDATE_DATA: u16 = 0x0601;
pub const UPDATE_END: u16 = 0x0602;
pub const UPDATE_RESULT: u16 = 0x0603;
// Latency meter (Ctl, 1.2, RDP-67).
/// Remora → helper: show the marker square in this colour.
pub const LATENCY_MARK: u16 = 0x0700;
/// Helper → Remora: the marker is painted; where it is.
pub const LATENCY_SHOWN: u16 = 0x0701;
/// Remora → helper: remove the marker.
pub const LATENCY_END: u16 = 0x0702;
// Helper picture stream (1.2, RDP-67): control on Ctl, pictures on Bulk.
/// Remora → helper: start streaming the session's picture.
pub const STREAM_START: u16 = 0x0710;
/// Helper → Remora: the stream started, stopped or failed.
pub const STREAM_STATE: u16 = 0x0711;
/// Remora → helper: stop streaming.
pub const STREAM_STOP: u16 = 0x0712;
/// Remora → helper: a picture was shown (pacing).
pub const STREAM_ACK: u16 = 0x0713;
/// Helper → Remora (Bulk): one piece of an encoded picture.
pub const STREAM_DATA: u16 = 0x0790;
/// Largest piece of a picture in one [`Message::StreamData`].
pub const MAX_STREAM_PIECE: usize = 256 * 1024;
/// Largest encoded picture (a 4K keyframe is about 1.5 MB).
pub const MAX_STREAM_PICTURE: u32 = 16 << 20;
/// Most changed rectangles sent with a picture; more become one.
pub const MAX_STREAM_RECTS: usize = 256;
/// [`Message::StreamData`] `flags`: the picture is a keyframe.
pub const STREAM_KEYFRAME: u8 = 1;
/// [`Message::StreamStart`] `codec`: H.264 Annex B, 4:2:0.
pub const STREAM_H264: u8 = 1;

/// Capability bits (Hello offers, HelloAck accepts a subset).
pub mod cap {
    /// The helper sends [`super::SessionInfo`].
    pub const SESSION_INFO: u32 = 1 << 0;
    /// The helper may ask the client to open links.
    pub const OPEN_URL: u32 = 1 << 1;
    /// File transfer client → server (upload).
    pub const FILE_UP: u32 = 1 << 2;
    /// File transfer server → client (download).
    pub const FILE_DOWN: u32 = 1 << 3;
    /// 1.2: the helper reports the server's graphics settings and changes
    /// them when Remora asks and the server's user confirms elevation.
    pub const SERVER_TUNING: u32 = 1 << 4;
    /// 1.2: Remora may send the helper a newer version of itself.
    pub const HELPER_UPDATE: u32 = 1 << 5;
    /// 1.2: file offers may belong to a folder ([`super::FolderRef`]); a
    /// peer without it is never sent one.
    pub const FOLDERS: u32 = 1 << 6;
    /// 1.2: the helper reports the session's keyboard layout
    /// ([`super::Message::KeyboardLayout`]), so Remora can type with keys.
    pub const KEYBOARD: u32 = 1 << 7;
    /// 1.2: the latency meter: the helper paints a small square in the
    /// colour Remora asks for ([`super::Message::LatencyMark`]), so Remora
    /// can time the round trip to its own picture.
    pub const LATENCY: u32 = 1 << 8;
    /// 1.2: the helper streams the session's picture on request
    /// ([`super::Message::StreamStart`]), encoded on the server's GPU when it
    /// has one (RDP-67, experimental).
    pub const STREAM: u32 = 1 << 9;
    /// Every bit this version defines.
    pub const ALL: u32 = SESSION_INFO
        | OPEN_URL
        | FILE_UP
        | FILE_DOWN
        | SERVER_TUNING
        | HELPER_UPDATE
        | FOLDERS
        | KEYBOARD
        | LATENCY
        | STREAM;
}

/// Policy flags the helper reads from the server's configuration.
pub mod policy {
    /// Clipboard redirection is disabled by policy.
    pub const CLIPBOARD_DISABLED: u32 = 1 << 0;
    /// Drive redirection is disabled by policy.
    pub const DRIVES_DISABLED: u32 = 1 << 1;
    /// Either flag turns file transfer off in both directions.
    pub const BLOCKS_FILE_TRANSFER: u32 = CLIPBOARD_DISABLED | DRIVES_DISABLED;
}

/// [`ErrorMsg::code`] values.
pub mod err {
    /// The user rejected pairing on the client.
    pub const PAIRING_REJECTED: u32 = 1;
    /// Major version mismatch.
    pub const VERSION: u32 = 2;
    /// A second helper instance tried to open the channel.
    pub const SECOND_INSTANCE: u32 = 3;
    /// A message for a capability that was not accepted.
    pub const NOT_ALLOWED: u32 = 4;
    /// A malformed or out-of-order message.
    pub const PROTOCOL: u32 = 5;
}

/// Longest helper version string.
pub const MAX_VERSION_TEXT: usize = 64;
/// Longest client name ([`Message::ClientName`]).
pub const MAX_CLIENT_NAME: usize = 64;
/// Longest error text.
pub const MAX_TEXT: usize = 1024;
/// Longest URL.
pub const MAX_URL: usize = 8192;
/// Longest file name in bytes (UTF-8); the receiver also limits it to 255
/// UTF-16 units.
pub const MAX_NAME: usize = 1024;
/// Longest subfolder path of a folder transfer's file (UTF-8 bytes).
pub const MAX_FOLDER_PATH: usize = 4096;

/// A 128-bit random transfer id (UUID version 4 layout).
pub type TransferId = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Desktop,
    RemoteApp,
    Other(u8),
}

impl SessionKind {
    fn to_u8(self) -> u8 {
        match self {
            SessionKind::Desktop => 0,
            SessionKind::RemoteApp => 1,
            SessionKind::Other(v) => v,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            0 => SessionKind::Desktop,
            1 => SessionKind::RemoteApp,
            v => SessionKind::Other(v),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub major: u16,
    pub minor: u16,
    pub helper_version: String,
    /// Windows build number (for example 26100).
    pub os_build: u32,
    pub session_kind: SessionKind,
    /// [`cap`] bits the helper offers.
    pub capabilities: u32,
    /// [`policy`] flags.
    pub policy: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloAck {
    pub major: u16,
    pub minor: u16,
    /// [`cap`] bits the client accepts: the offered ones the user enabled.
    pub capabilities: u32,
    /// Largest frame the client accepts ([`frame::MAX_MESSAGE`]).
    pub max_message: u32,
    /// Largest file chunk payload.
    pub max_chunk: u32,
    /// Bytes a file sender may have in flight beyond the acknowledged offset.
    pub window: u32,
    /// Fresh random token; the helper puts it into the `Remora::Bulk`
    /// prologue, which binds Bulk to this Ctl session.
    pub bulk_token: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingStatus {
    /// The helper's key is pinned for this server; no SAS needed.
    Known,
    /// First contact or changed key: the client shows the SAS and waits for
    /// the user. The helper shows its SAS too.
    Confirm,
    /// The user confirmed; the client pinned the key.
    Confirmed,
    /// The user rejected; the client closes the channel.
    Rejected,
}

impl PairingStatus {
    fn to_u8(self) -> u8 {
        match self {
            PairingStatus::Known => 0,
            PairingStatus::Confirm => 1,
            PairingStatus::Confirmed => 2,
            PairingStatus::Rejected => 3,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => PairingStatus::Known,
            1 => PairingStatus::Confirm,
            2 => PairingStatus::Confirmed,
            3 => PairingStatus::Rejected,
            v => return Err(Error::Malformed(format!("pairing status {v}"))),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub locked: bool,
    /// Milliseconds since the last input in the session.
    pub idle_ms: u32,
    /// Whole-machine CPU load, 0..=100.
    pub cpu_percent: u8,
    pub mem_used: u64,
    pub mem_total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlStatus {
    Opened,
    /// The user declined, or the host is not allowed.
    Declined,
    /// Not an http or https URL, or malformed.
    Invalid,
    /// Link opening is switched off.
    Disabled,
}

impl UrlStatus {
    fn to_u8(self) -> u8 {
        match self {
            UrlStatus::Opened => 0,
            UrlStatus::Declined => 1,
            UrlStatus::Invalid => 2,
            UrlStatus::Disabled => 3,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => UrlStatus::Opened,
            1 => UrlStatus::Declined,
            2 => UrlStatus::Invalid,
            3 => UrlStatus::Disabled,
            v => return Err(Error::Malformed(format!("url status {v}"))),
        })
    }
}

/// The server's graphics settings (1.2). `None`: the value is not set
/// (Windows' default applies).
///
/// - `frame_interval`: `DWMFRAMEINTERVAL` under
///   `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations`;
///   Windows caps remote sessions at 30 fps without it, 15 allows 60.
/// - `avc444`: the policy "Prioritize H.264/AVC 444 graphics mode"
///   (`AVC444ModePreferred` under
///   `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`).
/// - `avc_hw`: the policy "Configure H.264/AVC hardware encoding"
///   (`AVCHardwareEncodePreferred`, same key).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerSettings {
    pub frame_interval: Option<u32>,
    pub avc444: Option<u32>,
    pub avc_hw: Option<u32>,
}

/// `DWMFRAMEINTERVAL` for 60 fps.
pub const FRAME_INTERVAL_60FPS: u32 = 15;

impl ServerSettings {
    /// The values [`TuneAction::Apply`] writes.
    pub const RECOMMENDED: ServerSettings = ServerSettings {
        frame_interval: Some(FRAME_INTERVAL_60FPS),
        avc444: Some(1),
        avc_hw: Some(1),
    };

    /// Every value is the recommended one.
    pub fn tuned(&self) -> bool {
        *self == Self::RECOMMENDED
    }

    /// Any value is set (by us or by an administrator).
    pub fn any_set(&self) -> bool {
        self.frame_interval.is_some() || self.avc444.is_some() || self.avc_hw.is_some()
    }
}

/// What [`Message::TuneServer`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuneAction {
    /// Write [`ServerSettings::RECOMMENDED`].
    Apply,
    /// Delete the three values: Windows' defaults again.
    Restore,
}

impl TuneAction {
    pub fn to_u8(self) -> u8 {
        match self {
            TuneAction::Apply => 0,
            TuneAction::Restore => 1,
        }
    }
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => TuneAction::Apply,
            1 => TuneAction::Restore,
            v => return Err(Error::Malformed(format!("tune action {v}"))),
        })
    }
}

/// How a [`Message::TuneServer`] went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuneStatus {
    /// The settings were written; a fresh [`Message::ServerSettings`] follows.
    Done,
    /// The server's user declined the administrator prompt.
    Declined,
    /// Writing failed (no administrator on the server, or a policy blocks it).
    Failed,
    /// Not paired, not trusted, or tuning not accepted.
    NotAllowed,
}

impl TuneStatus {
    fn to_u8(self) -> u8 {
        match self {
            TuneStatus::Done => 0,
            TuneStatus::Declined => 1,
            TuneStatus::Failed => 2,
            TuneStatus::NotAllowed => 3,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => TuneStatus::Done,
            1 => TuneStatus::Declined,
            2 => TuneStatus::Failed,
            3 => TuneStatus::NotAllowed,
            v => return Err(Error::Malformed(format!("tune status {v}"))),
        })
    }
}

/// How a helper update went ([`Message::UpdateResult`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Installed; the helper restarts as the new version now.
    Installed,
    /// Not taken: not trusted here, not accepted, the same version, or
    /// out of bounds.
    Refused,
    /// Taken but not installed (a check or writing it failed).
    Failed,
}

impl UpdateStatus {
    fn to_u8(self) -> u8 {
        match self {
            UpdateStatus::Installed => 0,
            UpdateStatus::Refused => 1,
            UpdateStatus::Failed => 2,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => UpdateStatus::Installed,
            1 => UpdateStatus::Refused,
            2 => UpdateStatus::Failed,
            v => return Err(Error::Malformed(format!("update status {v}"))),
        })
    }
}

fn put_opt(p: &mut Vec<u8>, v: Option<u32>) {
    p.put_bool(v.is_some());
    p.put_u32(v.unwrap_or(0));
}

fn opt(r: &mut Reader) -> Result<Option<u32>> {
    let present = r.bool()?;
    let v = r.u32()?;
    Ok(present.then_some(v))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMsg {
    pub code: u32,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOffer {
    pub id: TransferId,
    /// Plain file name, no folders. The receiver validates it.
    pub name: String,
    pub size: u64,
    /// Last write time, milliseconds since the Unix epoch.
    pub mtime: u64,
    /// Hash block size; 4 MiB in version 1.0.
    pub block_size: u32,
    /// 1.2 ([`cap::FOLDERS`]): the file is part of a folder transfer.
    pub folder: Option<FolderRef>,
}

/// Where a file of a folder transfer goes (protocol 1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderRef {
    /// The folder transfer's own id (not any file's).
    pub id: TransferId,
    /// The folder's name, a plain name like a file name.
    pub top: String,
    /// Subfolders below `top`, `\`-separated; empty for files directly in
    /// it. Every part is checked like a file name.
    pub path: String,
    /// Files and bytes in the whole folder.
    pub files: u32,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    SasCommit([u8; 32]),
    SasNonce([u8; 32]),
    SasReveal([u8; 32]),
    Hello(Hello),
    HelloAck(HelloAck),
    Heartbeat {
        seq: u32,
    },
    Pairing(PairingStatus),
    Unsupported {
        ty: u16,
    },
    Error(ErrorMsg),
    /// Helper → Remora (1.1), right after the SAS step and before `Hello`:
    /// `Known` — the helper has Remora's client key pinned; `Confirm` — it
    /// does not, so it shows its code and asks its user (Remora shows its
    /// code too); `Confirmed` — the user on the server confirmed and the
    /// helper pinned the client key; `Rejected` — refused there.
    PeerPairing(PairingStatus),
    /// Remora → helper (1.1), with `Pairing`: the client's name, a label for
    /// the helper's list of pinned clients (never trusted for anything).
    ClientName {
        name: String,
    },
    SessionInfo(SessionInfo),
    OpenUrl {
        url: String,
    },
    OpenUrlResult(UrlStatus),
    FileOffer(FileOffer),
    /// Start (or restart) sending at `offset`, up to `limit`. Sent again
    /// after a reconnect or a failed block, each time with a new `epoch`.
    FileAccept {
        id: TransferId,
        epoch: u32,
        offset: u64,
        limit: u64,
    },
    FileReject {
        id: TransferId,
        reason: u8,
    },
    /// The sender may send up to absolute byte offset `limit`.
    FileCredit {
        id: TransferId,
        epoch: u32,
        limit: u64,
    },
    FileCancel {
        id: TransferId,
        reason: u8,
    },
    /// The receiver verified and stored the file.
    FileComplete {
        id: TransferId,
    },
    FileChunk {
        id: TransferId,
        epoch: u32,
        offset: u64,
        data: Vec<u8>,
    },
    FileBlockHash {
        id: TransferId,
        epoch: u32,
        index: u32,
        hash: [u8; 32],
    },
    /// All data sent; `root` is BLAKE3 over the size and every block hash.
    FileEnd {
        id: TransferId,
        epoch: u32,
        root: [u8; 32],
    },
    /// Helper → Remora (1.2): after `HelloAck` and whenever they change.
    ServerSettings(ServerSettings),
    /// Helper → Remora (1.2, [`cap::KEYBOARD`]): the keyboard layout (KLID)
    /// of the session's foreground window, after `HelloAck` and on change.
    KeyboardLayout {
        klid: u32,
    },
    /// Remora → helper (1.2), `request_id` ≠ 0.
    TuneServer {
        action: TuneAction,
    },
    /// Helper → Remora (1.2), the `TuneServer`'s `request_id`.
    TuneResult {
        status: TuneStatus,
    },
    /// Remora → helper (1.2, [`cap::LATENCY`]): paint the marker square in
    /// `rgb` (0xRRGGBB); `request_id` ≠ 0 names this mark.
    LatencyMark {
        rgb: u32,
    },
    /// Helper → Remora (1.2), the mark's `request_id`: painted. The square
    /// is `size` pixels at (`x`, `y`) of Remora's picture (the session's
    /// desktop from its top-left corner).
    LatencyShown {
        x: u32,
        y: u32,
        size: u32,
    },
    /// Remora → helper (1.2): remove the marker.
    LatencyEnd,
    /// Remora → helper (1.2, [`cap::STREAM`]): stream the session's picture
    /// with `codec` ([`STREAM_H264`]), at most `max_fps` pictures a second
    /// and about `kbps`; `request_id` ≠ 0.
    StreamStart {
        codec: u8,
        max_fps: u8,
        kbps: u32,
    },
    /// Helper → Remora (1.2): `state` 0 started (the start's
    /// `request_id`; `width` x `height`), 1 stopped, 2 failed (`text` says
    /// why; the picture is RDP's again).
    StreamState {
        state: u8,
        width: u32,
        height: u32,
        text: String,
    },
    /// Remora → helper (1.2): stop streaming.
    StreamStop,
    /// Remora → helper (1.2): picture `seq` was decoded; the helper keeps at
    /// most two pictures unacknowledged and skips captures meanwhile.
    StreamAck {
        seq: u32,
    },
    /// Helper → Remora (1.2, Bulk): bytes `offset..offset + data.len()` of
    /// picture `seq` (`total` bytes, `flags` [`STREAM_KEYFRAME`]). The first
    /// piece (offset 0) carries the changed rectangles (x, y, w, h).
    StreamData {
        seq: u32,
        flags: u8,
        offset: u32,
        total: u32,
        rects: Vec<[u16; 4]>,
        data: Vec<u8>,
    },
    /// Remora → helper (1.2): a new helper follows; `request_id` ≠ 0, the
    /// same on every message of this update.
    UpdateBegin {
        version: String,
        size: u64,
        hash: [u8; 32],
    },
    UpdateData {
        offset: u64,
        data: Vec<u8>,
    },
    UpdateEnd,
    /// Helper → Remora (1.2), same `request_id`.
    UpdateResult {
        status: UpdateStatus,
    },
    /// A type this side does not know (newer minor version).
    Unknown {
        ty: u16,
    },
}

/// The channel a message travels on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    Ctl,
    Bulk,
}

impl Channel {
    /// The DVC name.
    pub fn name(self) -> &'static str {
        match self {
            Channel::Ctl => crate::CTL_CHANNEL,
            Channel::Bulk => crate::BULK_CHANNEL,
        }
    }
}

impl Message {
    pub fn ty(&self) -> u16 {
        match self {
            Message::SasCommit(_) => SAS_COMMIT,
            Message::SasNonce(_) => SAS_NONCE,
            Message::SasReveal(_) => SAS_REVEAL,
            Message::Hello(_) => HELLO,
            Message::HelloAck(_) => HELLO_ACK,
            Message::Heartbeat { .. } => HEARTBEAT,
            Message::Pairing(_) => PAIRING,
            Message::Unsupported { .. } => UNSUPPORTED,
            Message::Error(_) => ERROR,
            Message::PeerPairing(_) => PEER_PAIRING,
            Message::ClientName { .. } => CLIENT_NAME,
            Message::SessionInfo(_) => SESSION_INFO,
            Message::OpenUrl { .. } => OPEN_URL,
            Message::OpenUrlResult(_) => OPEN_URL_RESULT,
            Message::FileOffer(_) => FILE_OFFER,
            Message::FileAccept { .. } => FILE_ACCEPT,
            Message::FileReject { .. } => FILE_REJECT,
            Message::FileCredit { .. } => FILE_CREDIT,
            Message::FileCancel { .. } => FILE_CANCEL,
            Message::FileComplete { .. } => FILE_COMPLETE,
            Message::FileChunk { .. } => FILE_CHUNK,
            Message::FileBlockHash { .. } => FILE_BLOCK_HASH,
            Message::FileEnd { .. } => FILE_END,
            Message::ServerSettings(_) => SERVER_SETTINGS,
            Message::KeyboardLayout { .. } => KEYBOARD_LAYOUT,
            Message::TuneServer { .. } => TUNE_SERVER,
            Message::TuneResult { .. } => TUNE_RESULT,
            Message::UpdateBegin { .. } => UPDATE_BEGIN,
            Message::UpdateData { .. } => UPDATE_DATA,
            Message::UpdateEnd => UPDATE_END,
            Message::UpdateResult { .. } => UPDATE_RESULT,
            Message::LatencyMark { .. } => LATENCY_MARK,
            Message::LatencyShown { .. } => LATENCY_SHOWN,
            Message::LatencyEnd => LATENCY_END,
            Message::StreamStart { .. } => STREAM_START,
            Message::StreamState { .. } => STREAM_STATE,
            Message::StreamStop => STREAM_STOP,
            Message::StreamAck { .. } => STREAM_ACK,
            Message::StreamData { .. } => STREAM_DATA,
            Message::Unknown { ty } => *ty,
        }
    }

    /// The channel this message must travel on.
    pub fn channel(&self) -> Channel {
        match self {
            Message::FileChunk { .. }
            | Message::FileBlockHash { .. }
            | Message::FileEnd { .. }
            | Message::StreamData { .. } => Channel::Bulk,
            _ => Channel::Ctl,
        }
    }

    /// Session-layer messages, handled inside [`crate::SecureSession`].
    pub fn is_session(&self) -> bool {
        matches!(
            self,
            Message::SasCommit(_) | Message::SasNonce(_) | Message::SasReveal(_)
        )
    }

    /// Encodes the message as one frame.
    pub fn encode(&self, request_id: u32) -> Result<Vec<u8>> {
        let mut p = Vec::new();
        match self {
            Message::SasCommit(b) | Message::SasNonce(b) | Message::SasReveal(b) => p.put_bytes(b),
            Message::Hello(h) => {
                p.put_u16(h.major);
                p.put_u16(h.minor);
                p.put_str(&h.helper_version, MAX_VERSION_TEXT);
                p.put_u32(h.os_build);
                p.put_u8(h.session_kind.to_u8());
                p.put_u32(h.capabilities);
                p.put_u32(h.policy);
            }
            Message::HelloAck(a) => {
                p.put_u16(a.major);
                p.put_u16(a.minor);
                p.put_u32(a.capabilities);
                p.put_u32(a.max_message);
                p.put_u32(a.max_chunk);
                p.put_u32(a.window);
                p.put_bytes(&a.bulk_token);
            }
            Message::Heartbeat { seq } => p.put_u32(*seq),
            Message::Pairing(s) | Message::PeerPairing(s) => p.put_u8(s.to_u8()),
            Message::ClientName { name } => {
                if name.len() > MAX_CLIENT_NAME {
                    return Err(Error::TooLarge(name.len()));
                }
                p.put_str(name, MAX_CLIENT_NAME);
            }
            Message::Unsupported { ty } => p.put_u16(*ty),
            Message::Error(e) => {
                p.put_u32(e.code);
                p.put_str(&e.message, MAX_TEXT);
            }
            Message::SessionInfo(s) => {
                p.put_bool(s.locked);
                p.put_u32(s.idle_ms);
                p.put_u8(s.cpu_percent);
                p.put_u64(s.mem_used);
                p.put_u64(s.mem_total);
            }
            Message::OpenUrl { url } => {
                if url.len() > MAX_URL {
                    return Err(Error::TooLarge(url.len()));
                }
                p.put_str(url, MAX_URL);
            }
            Message::OpenUrlResult(s) => p.put_u8(s.to_u8()),
            Message::FileOffer(o) => {
                if o.name.len() > MAX_NAME {
                    return Err(Error::TooLarge(o.name.len()));
                }
                p.put_bytes(&o.id);
                p.put_str(&o.name, MAX_NAME);
                p.put_u64(o.size);
                p.put_u64(o.mtime);
                p.put_u32(o.block_size);
                // 1.2: only present for a folder's file (peers before 1.2
                // are never sent one: they refuse trailing bytes).
                if let Some(f) = &o.folder {
                    if f.top.len() > MAX_NAME || f.path.len() > MAX_FOLDER_PATH {
                        return Err(Error::TooLarge(f.top.len().max(f.path.len())));
                    }
                    p.put_bytes(&f.id);
                    p.put_str(&f.top, MAX_NAME);
                    p.put_str(&f.path, MAX_FOLDER_PATH);
                    p.put_u32(f.files);
                    p.put_u64(f.bytes);
                }
            }
            Message::FileAccept {
                id,
                epoch,
                offset,
                limit,
            } => {
                p.put_bytes(id);
                p.put_u32(*epoch);
                p.put_u64(*offset);
                p.put_u64(*limit);
            }
            Message::FileReject { id, reason } | Message::FileCancel { id, reason } => {
                p.put_bytes(id);
                p.put_u8(*reason);
            }
            Message::FileCredit { id, epoch, limit } => {
                p.put_bytes(id);
                p.put_u32(*epoch);
                p.put_u64(*limit);
            }
            Message::FileComplete { id } => p.put_bytes(id),
            Message::FileChunk {
                id,
                epoch,
                offset,
                data,
            } => {
                p.put_bytes(id);
                p.put_u32(*epoch);
                p.put_u64(*offset);
                p.put_blob(data);
            }
            Message::FileBlockHash {
                id,
                epoch,
                index,
                hash,
            } => {
                p.put_bytes(id);
                p.put_u32(*epoch);
                p.put_u32(*index);
                p.put_bytes(hash);
            }
            Message::FileEnd { id, epoch, root } => {
                p.put_bytes(id);
                p.put_u32(*epoch);
                p.put_bytes(root);
            }
            Message::KeyboardLayout { klid } => p.put_u32(*klid),
            Message::ServerSettings(s) => {
                put_opt(&mut p, s.frame_interval);
                put_opt(&mut p, s.avc444);
                put_opt(&mut p, s.avc_hw);
            }
            Message::TuneServer { action } => p.put_u8(action.to_u8()),
            Message::TuneResult { status } => p.put_u8(status.to_u8()),
            Message::LatencyMark { rgb } => p.put_u32(*rgb),
            Message::LatencyShown { x, y, size } => {
                p.put_u32(*x);
                p.put_u32(*y);
                p.put_u32(*size);
            }
            Message::LatencyEnd => {}
            Message::StreamStart {
                codec,
                max_fps,
                kbps,
            } => {
                p.put_u8(*codec);
                p.put_u8(*max_fps);
                p.put_u32(*kbps);
            }
            Message::StreamState {
                state,
                width,
                height,
                text,
            } => {
                p.put_u8(*state);
                p.put_u32(*width);
                p.put_u32(*height);
                p.put_str(text, MAX_TEXT);
            }
            Message::StreamStop => {}
            Message::StreamAck { seq } => p.put_u32(*seq),
            Message::StreamData {
                seq,
                flags,
                offset,
                total,
                rects,
                data,
            } => {
                p.put_u32(*seq);
                p.put_u8(*flags);
                p.put_u32(*offset);
                p.put_u32(*total);
                let n = rects.len().min(MAX_STREAM_RECTS);
                p.put_u16(n as u16);
                for r in &rects[..n] {
                    for v in r {
                        p.put_u16(*v);
                    }
                }
                p.put_blob(data);
            }
            Message::UpdateBegin {
                version,
                size,
                hash,
            } => {
                if version.len() > MAX_VERSION_TEXT {
                    return Err(Error::TooLarge(version.len()));
                }
                p.put_str(version, MAX_VERSION_TEXT);
                p.put_u64(*size);
                p.put_bytes(hash);
            }
            Message::UpdateData { offset, data } => {
                p.put_u64(*offset);
                p.put_blob(data);
            }
            Message::UpdateEnd => {}
            Message::UpdateResult { status } => p.put_u8(status.to_u8()),
            Message::Unknown { .. } => {
                return Err(Error::State("an unknown message cannot be sent"));
            }
        }
        frame::encode(self.ty(), 0, request_id, &p)
    }

    /// Decodes one frame into `(request_id, message)`. Unknown types are
    /// not an error; malformed known types are.
    pub fn decode(buf: &[u8]) -> Result<(u32, Message)> {
        let f = frame::decode(buf)?;
        let mut r = Reader::new(f.payload);
        let m = match f.ty {
            SAS_COMMIT => Message::SasCommit(r.array()?),
            SAS_NONCE => Message::SasNonce(r.array()?),
            SAS_REVEAL => Message::SasReveal(r.array()?),
            HELLO => Message::Hello(Hello {
                major: r.u16()?,
                minor: r.u16()?,
                helper_version: r.str(MAX_VERSION_TEXT)?,
                os_build: r.u32()?,
                session_kind: SessionKind::from_u8(r.u8()?),
                capabilities: r.u32()?,
                policy: r.u32()?,
            }),
            HELLO_ACK => Message::HelloAck(HelloAck {
                major: r.u16()?,
                minor: r.u16()?,
                capabilities: r.u32()?,
                max_message: r.u32()?,
                max_chunk: r.u32()?,
                window: r.u32()?,
                bulk_token: r.array()?,
            }),
            HEARTBEAT => Message::Heartbeat { seq: r.u32()? },
            PAIRING => Message::Pairing(PairingStatus::from_u8(r.u8()?)?),
            PEER_PAIRING => Message::PeerPairing(PairingStatus::from_u8(r.u8()?)?),
            CLIENT_NAME => Message::ClientName {
                name: r.str(MAX_CLIENT_NAME)?,
            },
            UNSUPPORTED => Message::Unsupported { ty: r.u16()? },
            ERROR => Message::Error(ErrorMsg {
                code: r.u32()?,
                message: r.str(MAX_TEXT)?,
            }),
            SESSION_INFO => Message::SessionInfo(SessionInfo {
                locked: r.bool()?,
                idle_ms: r.u32()?,
                cpu_percent: r.u8()?,
                mem_used: r.u64()?,
                mem_total: r.u64()?,
            }),
            OPEN_URL => Message::OpenUrl {
                url: r.str(MAX_URL)?,
            },
            OPEN_URL_RESULT => Message::OpenUrlResult(UrlStatus::from_u8(r.u8()?)?),
            FILE_OFFER => Message::FileOffer(FileOffer {
                id: r.array()?,
                name: r.str(MAX_NAME)?,
                size: r.u64()?,
                mtime: r.u64()?,
                block_size: r.u32()?,
                folder: if r.remaining() > 0 {
                    Some(FolderRef {
                        id: r.array()?,
                        top: r.str(MAX_NAME)?,
                        path: r.str(MAX_FOLDER_PATH)?,
                        files: r.u32()?,
                        bytes: r.u64()?,
                    })
                } else {
                    None
                },
            }),
            FILE_ACCEPT => Message::FileAccept {
                id: r.array()?,
                epoch: r.u32()?,
                offset: r.u64()?,
                limit: r.u64()?,
            },
            FILE_REJECT => Message::FileReject {
                id: r.array()?,
                reason: r.u8()?,
            },
            FILE_CREDIT => Message::FileCredit {
                id: r.array()?,
                epoch: r.u32()?,
                limit: r.u64()?,
            },
            FILE_CANCEL => Message::FileCancel {
                id: r.array()?,
                reason: r.u8()?,
            },
            FILE_COMPLETE => Message::FileComplete { id: r.array()? },
            FILE_CHUNK => Message::FileChunk {
                id: r.array()?,
                epoch: r.u32()?,
                offset: r.u64()?,
                data: r.blob(MAX_PAYLOAD)?.to_vec(),
            },
            FILE_BLOCK_HASH => Message::FileBlockHash {
                id: r.array()?,
                epoch: r.u32()?,
                index: r.u32()?,
                hash: r.array()?,
            },
            FILE_END => Message::FileEnd {
                id: r.array()?,
                epoch: r.u32()?,
                root: r.array()?,
            },
            KEYBOARD_LAYOUT => Message::KeyboardLayout { klid: r.u32()? },
            SERVER_SETTINGS => Message::ServerSettings(ServerSettings {
                frame_interval: opt(&mut r)?,
                avc444: opt(&mut r)?,
                avc_hw: opt(&mut r)?,
            }),
            TUNE_SERVER => Message::TuneServer {
                action: TuneAction::from_u8(r.u8()?)?,
            },
            TUNE_RESULT => Message::TuneResult {
                status: TuneStatus::from_u8(r.u8()?)?,
            },
            LATENCY_MARK => Message::LatencyMark { rgb: r.u32()? },
            LATENCY_SHOWN => Message::LatencyShown {
                x: r.u32()?,
                y: r.u32()?,
                size: r.u32()?,
            },
            LATENCY_END => Message::LatencyEnd,
            STREAM_START => Message::StreamStart {
                codec: r.u8()?,
                max_fps: r.u8()?,
                kbps: r.u32()?,
            },
            STREAM_STATE => Message::StreamState {
                state: r.u8()?,
                width: r.u32()?,
                height: r.u32()?,
                text: r.str(MAX_TEXT)?,
            },
            STREAM_STOP => Message::StreamStop,
            STREAM_ACK => Message::StreamAck { seq: r.u32()? },
            STREAM_DATA => {
                let seq = r.u32()?;
                let flags = r.u8()?;
                let offset = r.u32()?;
                let total = r.u32()?;
                let n = r.u16()? as usize;
                if n > MAX_STREAM_RECTS {
                    return Err(Error::Malformed("too many stream rectangles".into()));
                }
                let mut rects = Vec::with_capacity(n);
                for _ in 0..n {
                    rects.push([r.u16()?, r.u16()?, r.u16()?, r.u16()?]);
                }
                let data = r.blob(MAX_STREAM_PIECE)?.to_vec();
                if total > MAX_STREAM_PICTURE || offset as u64 + data.len() as u64 > total as u64 {
                    return Err(Error::Malformed("stream piece outside its picture".into()));
                }
                Message::StreamData {
                    seq,
                    flags,
                    offset,
                    total,
                    rects,
                    data,
                }
            }
            UPDATE_BEGIN => Message::UpdateBegin {
                version: r.str(MAX_VERSION_TEXT)?,
                size: r.u64()?,
                hash: r.array()?,
            },
            UPDATE_DATA => Message::UpdateData {
                offset: r.u64()?,
                data: r.blob(MAX_PAYLOAD)?.to_vec(),
            },
            UPDATE_END => Message::UpdateEnd,
            UPDATE_RESULT => Message::UpdateResult {
                status: UpdateStatus::from_u8(r.u8()?)?,
            },
            ty => return Ok((f.request_id, Message::Unknown { ty })),
        };
        r.finish()?;
        Ok((f.request_id, m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn samples() -> Vec<Message> {
        let id = [7u8; 16];
        vec![
            Message::SasCommit([1; 32]),
            Message::SasNonce([2; 32]),
            Message::SasReveal([3; 32]),
            Message::Hello(Hello {
                major: 1,
                minor: 0,
                helper_version: "0.1.0".into(),
                os_build: 26100,
                session_kind: SessionKind::RemoteApp,
                capabilities: cap::ALL,
                policy: policy::DRIVES_DISABLED,
            }),
            Message::HelloAck(HelloAck {
                major: 1,
                minor: 0,
                capabilities: cap::SESSION_INFO,
                max_message: frame::MAX_MESSAGE as u32,
                max_chunk: 256 * 1024,
                window: 2 << 20,
                bulk_token: [9; 32],
            }),
            Message::PeerPairing(PairingStatus::Confirm),
            Message::ClientName {
                name: "LAPTOP-7".into(),
            },
            Message::Heartbeat { seq: 42 },
            Message::Pairing(PairingStatus::Confirm),
            Message::Unsupported { ty: 0x7777 },
            Message::Error(ErrorMsg {
                code: err::PROTOCOL,
                message: "nope".into(),
            }),
            Message::SessionInfo(SessionInfo {
                locked: true,
                idle_ms: 1234,
                cpu_percent: 17,
                mem_used: 3 << 30,
                mem_total: 16 << 30,
            }),
            Message::OpenUrl {
                url: "https://example.org/a?b=c".into(),
            },
            Message::OpenUrlResult(UrlStatus::Declined),
            Message::FileOffer(FileOffer {
                id,
                name: "report.pdf".into(),
                size: 10 << 20,
                mtime: 1_700_000_000_000,
                block_size: 4 << 20,
                folder: None,
            }),
            Message::FileAccept {
                id,
                epoch: 2,
                offset: 4 << 20,
                limit: 6 << 20,
            },
            Message::FileReject { id, reason: 3 },
            Message::FileCredit {
                id,
                epoch: 2,
                limit: 8 << 20,
            },
            Message::FileCancel { id, reason: 1 },
            Message::FileComplete { id },
            Message::FileChunk {
                id,
                epoch: 2,
                offset: 4 << 20,
                data: vec![5; 1000],
            },
            Message::FileBlockHash {
                id,
                epoch: 2,
                index: 1,
                hash: [4; 32],
            },
            Message::FileEnd {
                id,
                epoch: 2,
                root: [6; 32],
            },
            Message::ServerSettings(ServerSettings {
                frame_interval: Some(15),
                avc444: None,
                avc_hw: Some(0),
            }),
            Message::ServerSettings(ServerSettings::default()),
            Message::KeyboardLayout { klid: 0x0000_0407 },
            Message::TuneServer {
                action: TuneAction::Restore,
            },
            Message::TuneResult {
                status: TuneStatus::Declined,
            },
            Message::LatencyMark { rgb: 0x00ff_00ff },
            Message::LatencyShown {
                x: 8,
                y: 1032,
                size: 32,
            },
            Message::LatencyEnd,
            Message::StreamStart {
                codec: STREAM_H264,
                max_fps: 60,
                kbps: 20_000,
            },
            Message::StreamState {
                state: 0,
                width: 3688,
                height: 1984,
                text: String::new(),
            },
            Message::StreamState {
                state: 2,
                width: 0,
                height: 0,
                text: "the desktop cannot be captured".into(),
            },
            Message::StreamStop,
            Message::StreamAck { seq: 7 },
            Message::StreamData {
                seq: 7,
                flags: STREAM_KEYFRAME,
                offset: 0,
                total: 300,
                rects: vec![[0, 0, 32, 32], [100, 8, 4, 4]],
                data: vec![1; 200],
            },
            Message::StreamData {
                seq: 7,
                flags: STREAM_KEYFRAME,
                offset: 200,
                total: 300,
                rects: Vec::new(),
                data: vec![2; 100],
            },
            Message::UpdateBegin {
                version: "0.1.0-beta.9".into(),
                size: 1 << 20,
                hash: [8; 32],
            },
            Message::UpdateData {
                offset: 65536,
                data: vec![3; 100],
            },
            Message::UpdateEnd,
            Message::UpdateResult {
                status: UpdateStatus::Failed,
            },
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for (i, m) in samples().into_iter().enumerate() {
            let bytes = m.encode(i as u32).unwrap();
            let (rid, back) = Message::decode(&bytes).unwrap();
            assert_eq!(rid, i as u32);
            assert_eq!(back, m);
        }
    }

    #[test]
    fn every_message_rejects_truncation_and_trailing_bytes() {
        for m in samples() {
            let bytes = m.encode(0).unwrap();
            let f = frame::decode(&bytes).unwrap();
            // Re-frame with a shortened and an extended payload.
            if !f.payload.is_empty() {
                let short = frame::encode(f.ty, 0, 0, &f.payload[..f.payload.len() - 1]).unwrap();
                assert!(Message::decode(&short).is_err(), "{m:?} short");
            }
            let mut p = f.payload.to_vec();
            p.push(0);
            let long = frame::encode(f.ty, 0, 0, &p).unwrap();
            assert!(Message::decode(&long).is_err(), "{m:?} long");
        }
    }

    #[test]
    fn recommended_settings() {
        let s = ServerSettings::RECOMMENDED;
        assert!(s.tuned() && s.any_set());
        assert!(!ServerSettings::default().tuned() && !ServerSettings::default().any_set());
        let partly = ServerSettings {
            frame_interval: Some(FRAME_INTERVAL_60FPS),
            ..Default::default()
        };
        assert!(!partly.tuned() && partly.any_set());
    }

    #[test]
    fn unknown_type_is_not_an_error() {
        let f = frame::encode(0x7FFF, 0, 9, b"anything").unwrap();
        assert_eq!(
            Message::decode(&f).unwrap(),
            (9, Message::Unknown { ty: 0x7FFF })
        );
        assert!(Message::Unknown { ty: 1 }.encode(0).is_err());
    }

    #[test]
    fn channel_assignment() {
        for m in samples() {
            let bulk = matches!(m.ty(), FILE_CHUNK | FILE_BLOCK_HASH | FILE_END | STREAM_DATA);
            assert_eq!(m.channel() == Channel::Bulk, bulk, "{m:?}");
        }
    }

    #[test]
    fn oversized_fields_rejected() {
        let url = "h".repeat(MAX_URL + 1);
        assert!(Message::OpenUrl { url }.encode(0).is_err());
        // A length prefix over the limit fails on decode.
        let mut p = Vec::new();
        p.put_u16((MAX_URL + 1) as u16);
        p.extend(std::iter::repeat_n(b'a', MAX_URL + 1));
        let f = frame::encode(OPEN_URL, 0, 0, &p).unwrap();
        assert!(Message::decode(&f).is_err());
    }

    #[test]
    fn bad_enum_values_rejected() {
        let f = frame::encode(PAIRING, 0, 0, &[9]).unwrap();
        assert!(Message::decode(&f).is_err());
        let f = frame::encode(OPEN_URL_RESULT, 0, 0, &[9]).unwrap();
        assert!(Message::decode(&f).is_err());
        let f = frame::encode(TUNE_SERVER, 0, 0, &[2]).unwrap();
        assert!(Message::decode(&f).is_err());
        let f = frame::encode(TUNE_RESULT, 0, 0, &[4]).unwrap();
        assert!(Message::decode(&f).is_err());
        let f = frame::encode(UPDATE_RESULT, 0, 0, &[3]).unwrap();
        assert!(Message::decode(&f).is_err());
        let mut si = Message::SessionInfo(SessionInfo {
            locked: false,
            idle_ms: 0,
            cpu_percent: 0,
            mem_used: 0,
            mem_total: 0,
        })
        .encode(0)
        .unwrap();
        si[frame::HEADER_LEN] = 2; // boolean 2
        assert!(Message::decode(&si).is_err());
    }

    /// Deterministic xorshift; the decoder must never panic on any input.
    #[test]
    fn fuzz_decoder_random_bytes() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let known = [
            SAS_COMMIT,
            HELLO,
            HELLO_ACK,
            ERROR,
            SESSION_INFO,
            KEYBOARD_LAYOUT,
            OPEN_URL,
            FILE_OFFER,
            FILE_CHUNK,
            FILE_END,
            SERVER_SETTINGS,
            TUNE_SERVER,
            TUNE_RESULT,
            UPDATE_BEGIN,
            UPDATE_DATA,
            UPDATE_RESULT,
        ];
        for round in 0..20_000 {
            let len = (next() % 96) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Half the rounds get a plausible header so the payload parsers run.
            if round % 2 == 0 && len >= frame::HEADER_LEN {
                let ty = known[(next() % known.len() as u64) as usize];
                buf[0..2].copy_from_slice(&ty.to_le_bytes());
                let plen = (len - frame::HEADER_LEN) as u32;
                buf[8..12].copy_from_slice(&plen.to_le_bytes());
            }
            let _ = Message::decode(&buf);
        }
        // Mutations of valid messages.
        for m in samples() {
            let good = m.encode(1).unwrap();
            for _ in 0..200 {
                let mut b = good.clone();
                let i = (next() as usize) % b.len();
                b[i] ^= (next() as u8) | 1;
                let _ = Message::decode(&b);
            }
        }
    }
}
