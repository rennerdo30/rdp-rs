//! Slow-path PDUs: client info, licensing, share control/data headers,
//! capability exchange and connection finalization (MS-RDPBCGR 2.2.1.11-2.2.1.22).

use crate::cursor::{Put, Reader, le16, utf16le, utf16le_z};
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

pub const SERVER_CHANNEL_ID: u16 = 0x03EA;

const SEC_INFO_PKT: u16 = 0x0040;
const SEC_LICENSE_PKT: u16 = 0x0080;

pub struct ClientInfo<'a> {
    pub domain: &'a str,
    pub user: &'a str,
    pub password: &'a str,
}

/// Client Info PDU (TS_INFO_PACKET with extended info), preceded by the basic security header.
pub fn client_info(ci: &ClientInfo) -> Vec<u8> {
    const INFO_MOUSE: u32 = 0x0001;
    const INFO_DISABLECTRLALTDEL: u32 = 0x0002;
    const INFO_AUTOLOGON: u32 = 0x0008;
    const INFO_UNICODE: u32 = 0x0010;
    const INFO_MAXIMIZESHELL: u32 = 0x0020;
    const INFO_LOGONNOTIFY: u32 = 0x0040;
    const INFO_ENABLEWINDOWSKEY: u32 = 0x0100;

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
            | INFO_ENABLEWINDOWSKEY,
    );
    let fields = [ci.domain, ci.user, ci.password, "", ""];
    for f in fields {
        out.put_u16(utf16le(f).len() as u16);
    }
    for f in fields {
        out.put_bytes(&utf16le_z(f));
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
    out.put_u32(0x0000_0007); // no wallpaper, full-window drag or menu animations
    out.put_u16(0); // cbAutoReconnectCookie
    out
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
    if body[9] & 0x20 != 0 {
        return Err(Error::Unsupported("bulk-compressed slow-path PDU".into()));
    }
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

fn capabilities(width: u16, height: u16, keyboard_layout: u32) -> (u16, Vec<u8>) {
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
    b.put_u16(32); // preferredBitsPerPixel
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
    b.put_u32(0);
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
) -> Vec<u8> {
    let (count, caps) = capabilities(width, height, keyboard_layout);
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
    fn confirm_active_lengths_are_consistent() {
        let pdu = confirm_active(0x1234, 1007, 1280, 800, 0x409);
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
}
