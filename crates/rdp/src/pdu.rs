//! Slow-path PDUs: client info, licensing, share control/data headers,
//! capability exchange and connection finalization (MS-RDPBCGR 2.2.1.11-2.2.1.22).

use crate::cursor::{Put, Reader, le16, utf16le_z};
use crate::error::{Error, Result, proto};

pub const PDUTYPE_DEMANDACTIVE: u16 = 0x1;
pub const PDUTYPE_CONFIRMACTIVE: u16 = 0x3;
pub const PDUTYPE_DEACTIVATEALL: u16 = 0x6;
pub const PDUTYPE_DATA: u16 = 0x7;

pub const PDUTYPE2_UPDATE: u8 = 2;
pub const PDUTYPE2_CONTROL: u8 = 20;
pub const PDUTYPE2_POINTER: u8 = 27;
pub const PDUTYPE2_SYNCHRONIZE: u8 = 31;
pub const PDUTYPE2_REFRESH_RECT: u8 = 33;
pub const PDUTYPE2_SHUTDOWN_DENIED: u8 = 37;
pub const PDUTYPE2_SAVE_SESSION_INFO: u8 = 38;
pub const PDUTYPE2_FONTLIST: u8 = 39;
pub const PDUTYPE2_FONTMAP: u8 = 40;
pub const PDUTYPE2_SET_ERROR_INFO: u8 = 47;
/// Server Auto-Reconnect Status PDU (MS-RDPBCGR 2.2.4.1.1): the cookie was rejected.
pub const PDUTYPE2_ARC_STATUS_PDU: u8 = 50;

pub const SERVER_CHANNEL_ID: u16 = 0x03EA;

const SEC_INFO_PKT: u16 = 0x0040;
const SEC_LICENSE_PKT: u16 = 0x0080;
const SEC_HEARTBEAT: u16 = 0x4000;

/// Server Heartbeat PDU (MS-RDPBCGR 2.2.16.1): the server sends one every
/// `period` seconds; after `warn` missed ones the client may warn, after
/// `reconnect` missed ones it should reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub period: u8,
    pub warn: u8,
    pub reconnect: u8,
}

/// Parses I/O channel data that is a heartbeat: a basic security header with
/// SEC_HEARTBEAT, then reserved, period, count1 and count2 (one byte each).
/// Anything else (share control PDUs) gives None.
pub fn parse_heartbeat(data: &[u8]) -> Option<Heartbeat> {
    if data.len() != 8 {
        return None;
    }
    let flags = u16::from_le_bytes([data[0], data[1]]);
    (flags & SEC_HEARTBEAT != 0).then_some(Heartbeat {
        period: data[5],
        warn: data[6],
        reconnect: data[7],
    })
}

pub struct ClientInfo<'a> {
    pub domain: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    /// ARC_CS_PRIVATE_PACKET (MS-RDPBCGR 2.2.4.3) for an auto-reconnect logon
    /// (3.2.5.3.11, 5.5); `None` sends cbAutoReconnectCookie = 0.
    pub auto_reconnect: Option<[u8; ARC_PACKET_LEN]>,
    /// performanceFlags (see `Experience::performance_flags`).
    pub performance_flags: u32,
    /// Highest bulk compression type (PACKET_COMPR_TYPE_*), sent as
    /// INFO_COMPRESSION plus CompressionTypeMask (2.2.1.11.1.1); `None` sends neither.
    pub compression: Option<u8>,
}

/// Client Info PDU (TS_INFO_PACKET with extended info), preceded by the basic security header.
pub fn client_info(ci: &ClientInfo) -> Vec<u8> {
    client_info_with(ci, &utf16le_z(ci.password))
}

/// Client Info PDU whose Password field is the password blob of a Server
/// Redirection Packet, passed to the target unchanged (2.2.13.1); `ci.password`
/// is ignored. cbPassword excludes the null terminator (2.2.1.11.1.1).
pub fn client_info_redirected(ci: &ClientInfo, password_blob: &[u8]) -> Vec<u8> {
    let mut password = password_blob.to_vec();
    if !password.ends_with(&[0, 0]) {
        password.extend_from_slice(&[0, 0]);
    }
    client_info_with(ci, &password)
}

/// `password`: UTF-16LE with its null terminator.
fn client_info_with(ci: &ClientInfo, password: &[u8]) -> Vec<u8> {
    const INFO_MOUSE: u32 = 0x0001;
    const INFO_DISABLECTRLALTDEL: u32 = 0x0002;
    const INFO_AUTOLOGON: u32 = 0x0008;
    const INFO_UNICODE: u32 = 0x0010;
    const INFO_MAXIMIZESHELL: u32 = 0x0020;
    const INFO_LOGONNOTIFY: u32 = 0x0040;
    const INFO_ENABLEWINDOWSKEY: u32 = 0x0100;
    const INFO_COMPRESSION: u32 = 0x0080;
    const COMPRESSION_TYPE_SHIFT: u32 = 9; // CompressionTypeMask 0x00001E00

    let mut out = Vec::new();
    out.put_u16(SEC_INFO_PKT);
    out.put_u16(0);

    out.put_u32(0); // CodePage
    out.put_u32(
        INFO_MOUSE
            | INFO_DISABLECTRLALTDEL
            | INFO_AUTOLOGON
            | INFO_UNICODE
            | INFO_MAXIMIZESHELL
            | INFO_LOGONNOTIFY
            | INFO_ENABLEWINDOWSKEY
            | ci.compression.map_or(0, |t| {
                INFO_COMPRESSION | (u32::from(t & 0x0F) << COMPRESSION_TYPE_SHIFT)
            }),
    );
    let fields = [
        utf16le_z(ci.domain),
        utf16le_z(ci.user),
        password.to_vec(),
        utf16le_z(""),
        utf16le_z(""),
    ];
    for f in &fields {
        out.put_u16(f.len().saturating_sub(2) as u16); // without the terminator
    }
    for f in &fields {
        out.put_bytes(f);
    }

    // TS_EXTENDED_INFO_PACKET
    out.put_u16(2); // AF_INET
    let addr = utf16le_z("0.0.0.0");
    out.put_u16(addr.len() as u16);
    out.put_bytes(&addr);
    let dir = utf16le_z("C:\\rdp-rs");
    out.put_u16(dir.len() as u16);
    out.put_bytes(&dir);
    out.put_zeros(172); // TS_TIME_ZONE_INFORMATION (UTC)
    out.put_u32(0); // clientSessionId
    out.put_u32(ci.performance_flags); // performanceFlags
    // cbAutoReconnectCookie is zero or 0x001C (2.2.1.11.1.1.1). The credentials
    // above stay in the PDU: if the server rejects the cookie it logs on with
    // them instead (3.3.5.3.11).
    match &ci.auto_reconnect {
        Some(arc) => {
            out.put_u16(ARC_PACKET_LEN as u16);
            out.put_bytes(arc);
        }
        None => out.put_u16(0),
    }
    out
}

/// Size of both auto-reconnect packets (cbLen, MS-RDPBCGR 2.2.4.2 and 2.2.4.3).
pub const ARC_PACKET_LEN: usize = 28;
const AUTO_RECONNECT_VERSION_1: u32 = 1;

/// The client random that MS-RDPBCGR 5.5 step 4 prescribes under Enhanced RDP
/// Security (TLS, CredSSP): no client random is generated (5.3.2), so the
/// verifier is computed over "an array of 32 zero bytes". This crate only
/// speaks Enhanced RDP Security, so this is the only client random it uses.
pub const ENHANCED_SECURITY_CLIENT_RANDOM: [u8; 32] = [0; 32];

/// The server's auto-reconnect cookie (ARC_SC_PRIVATE_PACKET, MS-RDPBCGR
/// 2.2.4.2), received in the Save Session Info PDU (2.2.10.1.1.4). Keep it in
/// memory only (5.5 step 2); `Debug` never prints the random bits.
#[derive(Clone, PartialEq, Eq)]
pub struct AutoReconnectCookie {
    /// LogonId: the session to reconnect to.
    pub logon_id: u32,
    /// ArcRandomBits: the HMAC key for the security verifier (5.5).
    pub random: [u8; 16],
}

impl std::fmt::Debug for AutoReconnectCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoReconnectCookie")
            .field("logon_id", &self.logon_id)
            .field("random", &"[redacted]")
            .finish()
    }
}

impl AutoReconnectCookie {
    /// Parses an ARC_SC_PRIVATE_PACKET (2.2.4.2): cbLen MUST be 28, Version 1.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let len = r.u32()?;
        if len as usize != ARC_PACKET_LEN {
            return proto(format!("auto-reconnect cookie length {len}"));
        }
        let version = r.u32()?;
        if version != AUTO_RECONNECT_VERSION_1 {
            return proto(format!("auto-reconnect cookie version {version}"));
        }
        Ok(Self {
            logon_id: r.u32()?,
            random: r.array()?,
        })
    }

    /// SecurityVerifier = HMAC-MD5(key = ArcRandomBits, data = client random)
    /// (MS-RDPBCGR 5.5 step 4, [RFC2104]).
    pub fn security_verifier(&self, client_random: &[u8; 32]) -> [u8; 16] {
        crate::crypto::hmac_md5(&self.random, client_random)
    }

    /// Builds the ARC_CS_PRIVATE_PACKET (2.2.4.3) for the Client Info PDU.
    pub fn client_packet(&self, client_random: &[u8; 32]) -> [u8; ARC_PACKET_LEN] {
        let mut out = Vec::with_capacity(ARC_PACKET_LEN);
        out.put_u32(ARC_PACKET_LEN as u32);
        out.put_u32(AUTO_RECONNECT_VERSION_1);
        out.put_u32(self.logon_id);
        out.put_bytes(&self.security_verifier(client_random));
        out.try_into().expect("28 bytes")
    }
}

/// TS_LOGON_ERRORS_INFO (MS-RDPBCGR 2.2.10.1.1.4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonErrors {
    /// ErrorNotificationType: an NTSTATUS or a LOGON_MSG_* value.
    pub notification_type: u32,
    /// ErrorNotificationData: a session id or a LOGON_FAILED_* value.
    pub notification_data: u32,
}

/// TS_SAVE_SESSION_INFO_PDU_DATA (MS-RDPBCGR 2.2.10.1.1), by infoType.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveSessionInfo {
    /// INFOTYPE_LOGON (0): TS_LOGON_INFO (2.2.10.1.1.1).
    Logon { session_id: u32 },
    /// INFOTYPE_LOGON_LONG (1): TS_LOGON_INFO_VERSION_2 (2.2.10.1.1.2).
    LogonLong { session_id: u32 },
    /// INFOTYPE_LOGON_PLAINNOTIFY (2): TS_PLAIN_NOTIFY (2.2.10.1.1.3).
    PlainNotify,
    /// INFOTYPE_LOGON_EXTENDED_INFO (3): TS_LOGON_INFO_EXTENDED (2.2.10.1.1.4).
    Extended {
        cookie: Option<AutoReconnectCookie>,
        errors: Option<LogonErrors>,
    },
    /// An infoType this version of the spec does not define.
    Unknown(u32),
}

/// Parses the payload of a PDUTYPE2_SAVE_SESSION_INFO share data PDU
/// (after the share data header). Bounds-checked; never panics.
pub fn parse_save_session_info(payload: &[u8]) -> Result<SaveSessionInfo> {
    const LOGON_EX_AUTORECONNECTCOOKIE: u32 = 0x1;
    const LOGON_EX_LOGONERRORS: u32 = 0x2;
    let mut r = Reader::new(payload);
    match r.u32()? {
        0 => {
            // cbDomain, Domain[52], cbUserName, UserName[512], SessionId
            r.skip(4 + 52 + 4 + 512)?;
            Ok(SaveSessionInfo::Logon {
                session_id: r.u32()?,
            })
        }
        1 => {
            let version = r.u16()?;
            if version != 1 {
                return proto(format!("logon info version {version}"));
            }
            r.u32()?; // Size
            let session_id = r.u32()?;
            let cb_domain = r.u32()? as usize;
            let cb_user = r.u32()? as usize;
            r.skip(558)?; // Pad
            r.skip(cb_domain)?;
            r.skip(cb_user)?;
            Ok(SaveSessionInfo::LogonLong { session_id })
        }
        2 => {
            r.skip(576)?; // Pad
            Ok(SaveSessionInfo::PlainNotify)
        }
        3 => {
            r.u16()?; // Length; the fields carry their own sizes
            let present = r.u32()?;
            // LogonFields are TS_LOGON_INFO_FIELDs (2.2.10.1.1.4.1) in fixed
            // order: cookie, then logon errors. The 570-byte Pad is ignored.
            fn field<'a>(r: &mut Reader<'a>, present: bool) -> Result<Option<&'a [u8]>> {
                if !present {
                    return Ok(None);
                }
                let n = r.u32()? as usize;
                r.bytes(n).map(Some)
            }
            let cookie = field(&mut r, present & LOGON_EX_AUTORECONNECTCOOKIE != 0)?
                .map(AutoReconnectCookie::parse)
                .transpose()?;
            let errors = match field(&mut r, present & LOGON_EX_LOGONERRORS != 0)? {
                Some(d) => {
                    let mut e = Reader::new(d);
                    Some(LogonErrors {
                        notification_type: e.u32()?,
                        notification_data: e.u32()?,
                    })
                }
                None => None,
            };
            Ok(SaveSessionInfo::Extended { cookie, errors })
        }
        t => Ok(SaveSessionInfo::Unknown(t)),
    }
}

/// Handles one server licensing PDU. With TLS the server normally answers the
/// client info with a single "valid client" error alert.
pub fn process_license(data: &[u8]) -> Result<()> {
    let mut r = Reader::new(data);
    let flags = r.u16()?;
    r.u16()?;
    if flags & SEC_LICENSE_PKT == 0 {
        return proto("expected a licensing PDU");
    }
    let msg_type = r.u8()?;
    r.u8()?;
    r.u16()?;
    match msg_type {
        0xFF => {
            let code = r.u32()?;
            if code == 0x7 {
                Ok(()) // STATUS_VALID_CLIENT
            } else {
                proto(format!("licensing error {code:#x}"))
            }
        }
        0x03 | 0x04 => Ok(()), // NEW_LICENSE / UPGRADE_LICENSE
        0x01 => Err(Error::Unsupported(
            "server requires RDS client licensing (LICENSE_REQUEST)".into(),
        )),
        t => proto(format!("unexpected licensing message {t:#x}")),
    }
}

/// True if the buffer starts with a share control header rather than a security header.
pub fn looks_like_share_control(data: &[u8]) -> bool {
    le16(data, 2).is_some_and(|t| t & 0xFFF0 == 0x0010)
}

pub fn share_control(pdu_type: u16, source: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.put_u16((body.len() + 6) as u16);
    out.put_u16(pdu_type | 0x10);
    out.put_u16(source);
    out.put_bytes(body);
    out
}

pub fn share_data(share_id: u32, source: u16, pdu_type2: u8, body: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(body.len() + 12);
    d.put_u32(share_id);
    d.put_u8(0);
    d.put_u8(1); // STREAM_LOW
    d.put_u16((body.len() + 4) as u16);
    d.put_u8(pdu_type2);
    d.put_u8(0);
    d.put_u16(0);
    d.put_bytes(body);
    share_control(PDUTYPE_DATA, source, &d)
}

/// Splits a buffer into share control PDUs: (pduType, body).
pub fn split_share_control(mut data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let total = u16::from_le_bytes([data[0], data[1]]) as usize;
        if total == 0x8000 {
            break; // flow control PDU
        }
        if total < 6 || total > data.len() {
            return proto(format!(
                "bad share control length {total} (have {})",
                data.len()
            ));
        }
        let ty = u16::from_le_bytes([data[2], data[3]]) & 0x0F;
        out.push((ty, &data[6..total]));
        data = &data[total..];
    }
    Ok(out)
}

/// Returns (pduType2, payload) for a share data PDU body.
pub fn parse_share_data(body: &[u8]) -> Result<(u8, &[u8])> {
    if body.len() < 12 {
        return proto("truncated share data header");
    }
    // body[9] is compressedType: the caller decompresses (crate::compress).
    Ok((body[8], &body[12..]))
}

#[derive(Debug, Clone)]
pub struct DemandActive {
    pub share_id: u32,
    pub width: u16,
    pub height: u16,
    pub bpp: u16,
}

pub fn parse_demand_active(body: &[u8]) -> Result<DemandActive> {
    let mut r = Reader::new(body);
    let share_id = r.u32()?;
    let src_len = r.u16()? as usize;
    r.u16()?;
    r.skip(src_len)?;
    let count = r.u16()?;
    r.u16()?;
    let mut da = DemandActive {
        share_id,
        width: 0,
        height: 0,
        bpp: 0,
    };
    for _ in 0..count {
        let ty = r.u16()?;
        let len = r.u16()? as usize;
        if len < 4 {
            return proto("bad capability length");
        }
        let cap = r.bytes(len - 4)?;
        if ty == CAPSTYPE_BITMAP && cap.len() >= 12 {
            da.bpp = le16(cap, 0).unwrap();
            da.width = le16(cap, 8).unwrap();
            da.height = le16(cap, 10).unwrap();
        }
    }
    if da.width == 0 || da.height == 0 {
        return proto("server sent no bitmap capability");
    }
    Ok(da)
}

const CAPSTYPE_GENERAL: u16 = 1;
const CAPSTYPE_BITMAP: u16 = 2;
const CAPSTYPE_ORDER: u16 = 3;
const CAPSTYPE_BITMAPCACHE: u16 = 4;
const CAPSTYPE_CONTROL: u16 = 5;
const CAPSTYPE_ACTIVATION: u16 = 7;
const CAPSTYPE_POINTER: u16 = 8;
const CAPSTYPE_COLORCACHE: u16 = 10;
const CAPSTYPE_SHARE: u16 = 9;
const CAPSTYPE_SOUND: u16 = 12;
const CAPSTYPE_INPUT: u16 = 13;
const CAPSTYPE_FONT: u16 = 14;
const CAPSTYPE_BRUSH: u16 = 15;
const CAPSTYPE_GLYPHCACHE: u16 = 16;
const CAPSTYPE_OFFSCREENCACHE: u16 = 17;
const CAPSTYPE_VIRTUALCHANNEL: u16 = 20;
const CAPSTYPE_MULTIFRAGMENTUPDATE: u16 = 26;
const CAPSTYPE_LARGE_POINTER: u16 = 27;

fn cap(out: &mut Vec<u8>, count: &mut u16, ty: u16, body: &[u8]) {
    out.put_u16(ty);
    out.put_u16((body.len() + 4) as u16);
    out.put_bytes(body);
    *count += 1;
}

fn capabilities(
    width: u16,
    height: u16,
    keyboard_layout: u32,
    bpp: u16,
    vc_compression: bool,
) -> (u16, Vec<u8>) {
    let mut out = Vec::new();
    let mut n = 0;

    let mut b = Vec::new();
    b.put_u16(1); // OSMAJORTYPE_WINDOWS
    b.put_u16(3); // OSMINORTYPE_WINDOWS_NT
    b.put_u16(0x0200); // protocolVersion
    b.put_u16(0);
    b.put_u16(0); // generalCompressionTypes
    // FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED | AUTORECONNECT_SUPPORTED
    // | ENC_SALTED_CHECKSUM | NO_BITMAP_COMPRESSION_HDR
    b.put_u16(0x041D);
    b.put_u16(0); // updateCapabilityFlag
    b.put_u16(0); // remoteUnshareFlag
    b.put_u16(0); // generalCompressionLevel
    b.put_u8(1); // refreshRectSupport
    b.put_u8(1); // suppressOutputSupport
    cap(&mut out, &mut n, CAPSTYPE_GENERAL, &b);

    let mut b = Vec::new();
    b.put_u16(bpp); // preferredBitsPerPixel
    b.put_u16(1);
    b.put_u16(1);
    b.put_u16(1);
    b.put_u16(width);
    b.put_u16(height);
    b.put_u16(0);
    b.put_u16(1); // desktopResizeFlag
    b.put_u16(1); // bitmapCompressionFlag
    b.put_u8(0); // highColorFlags
    b.put_u8(0x08); // drawingFlags: DRAW_ALLOW_SKIP_ALPHA (no YCoCg / subsampling)
    b.put_u16(1); // multipleRectangleSupport
    b.put_u16(0);
    cap(&mut out, &mut n, CAPSTYPE_BITMAP, &b);

    let mut b = Vec::new();
    b.put_zeros(16); // terminalDescriptor
    b.put_u32(0);
    b.put_u16(1); // desktopSaveXGranularity
    b.put_u16(20); // desktopSaveYGranularity
    b.put_u16(0);
    b.put_u16(1); // maximumOrderLevel
    b.put_u16(0); // numberFonts
    // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT (the first two are MUST)
    b.put_u16(0x002A);
    b.put_zeros(32); // orderSupport: no drawing orders, bitmaps only
    b.put_u16(0);
    b.put_u16(0);
    b.put_u32(0);
    b.put_u32(230_400); // desktopSaveSize
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(0);
    cap(&mut out, &mut n, CAPSTYPE_ORDER, &b);

    let mut b = Vec::new();
    b.put_zeros(24);
    for (entries, size) in [(200u16, 256u16), (600, 1024), (1000, 4096)] {
        b.put_u16(entries);
        b.put_u16(size);
    }
    cap(&mut out, &mut n, CAPSTYPE_BITMAPCACHE, &b);

    let mut b = Vec::new();
    b.put_u16(1); // colorPointerFlag
    b.put_u16(crate::pointer::CACHE_SIZE as u16); // colorPointerCacheSize
    b.put_u16(crate::pointer::CACHE_SIZE as u16); // pointerCacheSize (enables New Pointer, any bpp)
    cap(&mut out, &mut n, CAPSTYPE_POINTER, &b);

    let mut b = Vec::new();
    // SCANCODES | MOUSEX | FASTPATH_INPUT | UNICODE | FASTPATH_INPUT2
    b.put_u16(0x003D);
    b.put_u16(0);
    b.put_u32(keyboard_layout);
    b.put_u32(4);
    b.put_u32(0);
    b.put_u32(12);
    b.put_zeros(64);
    cap(&mut out, &mut n, CAPSTYPE_INPUT, &b);

    cap(&mut out, &mut n, CAPSTYPE_BRUSH, &[0, 0, 0, 0]);

    let mut b = Vec::new();
    // Ten TS_CACHE_DEFINITIONs; cell sizes MUST be powers of two (MS-RDPBCGR 2.2.7.1.8).
    for (entries, cell) in [
        (254u16, 4u16),
        (254, 4),
        (254, 8),
        (254, 8),
        (254, 16),
        (254, 32),
        (254, 64),
        (254, 128),
        (254, 256),
        (64, 2048),
    ] {
        b.put_u16(entries);
        b.put_u16(cell);
    }
    b.put_u32(0x0100_0100); // FragCache: 256 entries of 256 bytes
    b.put_u16(0); // GLYPH_SUPPORT_NONE
    b.put_u16(0);
    cap(&mut out, &mut n, CAPSTYPE_GLYPHCACHE, &b);

    cap(&mut out, &mut n, CAPSTYPE_OFFSCREENCACHE, &[0; 8]);

    let mut b = Vec::new();
    // VCCAPS_COMPR_SC (2.2.7.1.10): server-to-client channel data may be
    // bulk-compressed, up to the type in the Client Info PDU.
    b.put_u32(u32::from(vc_compression));
    b.put_u32(1600);
    cap(&mut out, &mut n, CAPSTYPE_VIRTUALCHANNEL, &b);

    cap(&mut out, &mut n, CAPSTYPE_SOUND, &[1, 0, 0, 0]);

    let mut b = Vec::new();
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(2);
    b.put_u16(2);
    cap(&mut out, &mut n, CAPSTYPE_CONTROL, &b);

    cap(&mut out, &mut n, CAPSTYPE_COLORCACHE, &[6, 0, 0, 0]);
    cap(&mut out, &mut n, CAPSTYPE_ACTIVATION, &[0; 8]);
    cap(&mut out, &mut n, CAPSTYPE_SHARE, &[0; 4]);
    cap(&mut out, &mut n, CAPSTYPE_FONT, &[1, 0, 0, 0]);

    // Large Pointer (2.2.7.2.7): cursors up to 384 x 384 for high-DPI sessions.
    cap(&mut out, &mut n, CAPSTYPE_LARGE_POINTER, &[0x03, 0x00]);

    let mut b = Vec::new();
    b.put_u32(8 * 1024 * 1024);
    cap(&mut out, &mut n, CAPSTYPE_MULTIFRAGMENTUPDATE, &b);

    (n, out)
}

pub fn confirm_active(
    share_id: u32,
    user_id: u16,
    width: u16,
    height: u16,
    keyboard_layout: u32,
    bpp: u16,
    vc_compression: bool,
) -> Vec<u8> {
    let (count, caps) = capabilities(width, height, keyboard_layout, bpp, vc_compression);
    let source = b"RDPRS\0";
    let mut b = Vec::new();
    b.put_u32(share_id);
    b.put_u16(SERVER_CHANNEL_ID);
    b.put_u16(source.len() as u16);
    b.put_u16((caps.len() + 4) as u16);
    b.put_bytes(source);
    b.put_u16(count);
    b.put_u16(0);
    b.put_bytes(&caps);
    share_control(PDUTYPE_CONFIRMACTIVE, user_id, &b)
}

pub fn synchronize() -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(1);
    b.put_u16(SERVER_CHANNEL_ID);
    b
}

pub const CTRLACTION_REQUEST_CONTROL: u16 = 1;
pub const CTRLACTION_COOPERATE: u16 = 4;

pub fn control(action: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(action);
    b.put_u16(0);
    b.put_u32(0);
    b
}

pub fn font_list() -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(0x0003); // FONTLIST_FIRST | FONTLIST_LAST
    b.put_u16(0x0032);
    b
}

pub fn refresh_rect(width: u16, height: u16) -> Vec<u8> {
    let mut b = vec![1, 0, 0, 0];
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(width - 1);
    b.put_u16(height - 1);
    b
}

pub fn error_info_name(code: u32) -> &'static str {
    match code {
        0x0000_0001 => "disconnected by an administrative tool",
        0x0000_0002 => "logged off by an administrative tool",
        0x0000_0003 => "idle timeout",
        0x0000_0004 => "logon timeout",
        0x0000_0005 => "another user connected to the session",
        0x0000_0006 => "server out of memory",
        0x0000_0007 => "server denied the connection",
        0x0000_0009 => "user lacks remote desktop privileges",
        0x0000_000A => "server requires fresh credentials",
        0x0000_000B => "disconnected by the user on the server",
        0x0000_000C => "logged off by the user",
        0x10C9..=0x1195 => "server rejected a client PDU (protocol error, MS-RDPBCGR 2.2.5.1.1)",
        _ => "see MS-RDPBCGR 2.2.5.1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_is_advertised() {
        let info = |compression| {
            client_info(&ClientInfo {
                domain: "",
                user: "u",
                password: "",
                auto_reconnect: None,
                performance_flags: 0,
                compression,
            })
        };
        let flags = |pdu: &[u8]| u32::from_le_bytes(pdu[8..12].try_into().unwrap());
        // INFO_COMPRESSION (0x80) with PACKET_COMPR_TYPE_RDP61 in 0x1E00.
        assert_eq!(flags(&info(Some(3))) & 0x1E80, 0x0680);
        assert_eq!(flags(&info(None)) & 0x1E80, 0);
        // TS_VIRTUALCHANNEL_CAPABILITYSET flags: VCCAPS_COMPR_SC when on.
        let vc_flags = |on| {
            let pdu = confirm_active(1, 2, 640, 480, 0x409, 32, on);
            let at = pdu.windows(4).position(|w| w == [20, 0, 12, 0]).unwrap();
            u32::from_le_bytes(pdu[at + 4..at + 8].try_into().unwrap())
        };
        assert_eq!(vc_flags(true), 1);
        assert_eq!(vc_flags(false), 0);
    }

    #[test]
    fn confirm_active_lengths_are_consistent() {
        let pdu = confirm_active(0x1234, 1007, 1280, 800, 0x409, 32, false);
        let total = u16::from_le_bytes([pdu[0], pdu[1]]) as usize;
        assert_eq!(total, pdu.len());
        let combined = u16::from_le_bytes([pdu[14], pdu[15]]) as usize;
        assert_eq!(6 + 4 + 2 + 2 + 2 + 6 + combined, pdu.len());
    }

    #[test]
    fn split_handles_multiple_pdus() {
        let mut two = share_control(PDUTYPE_DATA, 1, &[1, 2]);
        two.extend(share_control(PDUTYPE_DEACTIVATEALL, 1, &[3]));
        let parts = split_share_control(&two).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].0, PDUTYPE_DEACTIVATEALL);
    }

    #[test]
    fn heartbeat_pdu_is_recognised() {
        // Basic security header SEC_HEARTBEAT, flagsHi 0; reserved, period 5,
        // count1 3, count2 10 (MS-RDPBCGR 2.2.16.1).
        let hb = parse_heartbeat(&[0x00, 0x40, 0, 0, 0, 5, 3, 10]).unwrap();
        assert_eq!((hb.period, hb.warn, hb.reconnect), (5, 3, 10));
        assert_eq!(
            parse_heartbeat(&[0x08, 0x00, 0x17, 0x00, 0, 0, 0, 0]),
            None,
            "share control"
        );
        assert_eq!(parse_heartbeat(&[0x00, 0x40, 0, 0]), None, "too short");
    }
}
