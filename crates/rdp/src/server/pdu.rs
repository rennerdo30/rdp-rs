//! Server side of the slow-path PDUs: the Client Info PDU (MS-RDPBCGR
//! 2.2.1.11), the licensing "valid client" message (2.2.1.12), Demand
//! Active and Confirm Active (2.2.1.13), connection finalization (2.2.1.14
//! to 2.2.1.22) and the client's share data PDUs during the session.

use crate::cursor::{Put, Reader};
use crate::error::{Error, Result, proto};
use crate::pdu::{
    PDUTYPE_DEMANDACTIVE, PDUTYPE2_CONTROL, PDUTYPE2_FONTLIST, PDUTYPE2_FONTMAP,
    PDUTYPE2_REFRESH_RECT, PDUTYPE2_SET_ERROR_INFO, PDUTYPE2_SYNCHRONIZE, SERVER_CHANNEL_ID,
    share_control, share_data,
};

use super::Rect;
use super::input::{ClientInput, parse_slowpath_input};

const SEC_INFO_PKT: u16 = 0x0040;
const SEC_LICENSE_PKT: u16 = 0x0080;

/// PDUTYPE2 values the server handles beyond those in [`crate::pdu`].
pub const PDUTYPE2_INPUT: u8 = 28;
pub const PDUTYPE2_SUPPRESS_OUTPUT: u8 = 35;
pub const PDUTYPE2_SHUTDOWN_REQUEST: u8 = 36;
pub const PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST: u8 = 43;

/// Control PDU actions (2.2.1.15.1).
pub const CTRLACTION_REQUEST_CONTROL: u16 = 0x0001;
pub const CTRLACTION_GRANTED_CONTROL: u16 = 0x0002;
pub const CTRLACTION_COOPERATE: u16 = 0x0004;

/// Set Error Info codes (2.2.5.1.1) the host sends.
pub const ERRINFO_RPC_INITIATED_DISCONNECT: u32 = 0x0000_0001;
/// The server refused the connection; sent after wrong credentials, as no
/// code names a failed logon itself.
pub const ERRINFO_SERVER_DENIED_CONNECTION: u32 = 0x0000_0007;
pub const ERRINFO_DISCONNECTED_BY_OTHERCONNECTION: u32 = 0x0000_0005;

/// The credentials of a Client Info PDU. The password is wiped when the
/// value is dropped, and `Debug` never shows it.
pub struct Credentials {
    pub user: String,
    pub domain: String,
    pub password: String,
    /// TS_INFO_PACKET flags (2.2.1.11.1.1).
    pub flags: u32,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("password", &"[redacted]")
            .field("flags", &format_args!("{:#x}", self.flags))
            .finish()
    }
}

/// Parses the Client Info PDU (2.2.1.11): the basic security header with
/// SEC_INFO_PKT, then TS_INFO_PACKET (2.2.1.11.1.1). Only the credentials
/// are kept; the extended info is not needed.
pub fn parse_client_info(data: &[u8]) -> Result<Credentials> {
    const INFO_UNICODE: u32 = 0x0010;
    let mut r = Reader::new(data);
    let sec = r.u16()?;
    r.u16()?; // flagsHi
    if sec & SEC_INFO_PKT == 0 {
        return proto("expected the Client Info PDU");
    }
    r.u32()?; // CodePage
    let flags = r.u32()?;
    let unicode = flags & INFO_UNICODE != 0;
    let mut lens = [0usize; 5];
    for l in &mut lens {
        *l = r.u16()? as usize;
    }
    // Each field is followed by its null terminator, which cb* excludes.
    let mut field = |cb: usize| -> Result<String> {
        if unicode {
            if !cb.is_multiple_of(2) {
                return proto("odd Unicode field length in Client Info");
            }
            let b = r.bytes(cb + 2)?;
            Ok(super::connect::utf16_until_null(&b[..cb]))
        } else {
            let b = r.bytes(cb + 1)?;
            Ok(b[..cb].iter().map(|&c| c as char).collect())
        }
    };
    let domain = field(lens[0])?;
    let user = field(lens[1])?;
    let password = field(lens[2])?;
    Ok(Credentials {
        user,
        domain,
        password,
        flags,
    })
}

/// The licensing PDU a server sends when it needs no client license
/// (2.2.1.12, 3.3.5.6, MS-RDPELE 3.2.5.2): a Licensing Error Message with
/// STATUS_VALID_CLIENT and ST_NO_TRANSITION, an empty error blob, under a
/// basic security header with SEC_LICENSE_PKT. As in the spec's example
/// (4.1.12) the preamble's flags are PREAMBLE_VERSION_3_0.
pub fn license_valid_client() -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.put_u16(SEC_LICENSE_PKT);
    out.put_u16(0); // flagsHi
    out.put_u8(crate::license::ERROR_ALERT); // bMsgType
    out.put_u8(0x03); // flags: PREAMBLE_VERSION_3_0
    out.put_u16(16); // wMsgSize
    out.put_u32(crate::license::STATUS_VALID_CLIENT);
    out.put_u32(crate::license::ST_NO_TRANSITION);
    out.put_u16(crate::license::BB_ERROR_BLOB);
    out.put_u16(0);
    out
}

// Capability set types (2.2.1.13.1.1.1).
const CAPSTYPE_GENERAL: u16 = 1;
const CAPSTYPE_BITMAP: u16 = 2;
const CAPSTYPE_ORDER: u16 = 3;
const CAPSTYPE_POINTER: u16 = 8;
const CAPSTYPE_SHARE: u16 = 9;
const CAPSTYPE_INPUT: u16 = 13;
const CAPSTYPE_FONT: u16 = 14;
const CAPSTYPE_VIRTUALCHANNEL: u16 = 20;
const CAPSTYPE_MULTIFRAGMENTUPDATE: u16 = 26;

/// General Capability Set extraFlags (2.2.7.1.1).
pub const FASTPATH_OUTPUT_SUPPORTED: u16 = 0x0001;
const LONG_CREDENTIALS_SUPPORTED: u16 = 0x0004;
const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// Input Capability Set inputFlags (2.2.7.1.6).
pub const INPUT_FLAG_SCANCODES: u16 = 0x0001;
pub const INPUT_FLAG_MOUSEX: u16 = 0x0004;
pub const INPUT_FLAG_FASTPATH_INPUT: u16 = 0x0008;
pub const INPUT_FLAG_UNICODE: u16 = 0x0010;
pub const INPUT_FLAG_FASTPATH_INPUT2: u16 = 0x0020;
pub const TS_INPUT_FLAG_MOUSE_HWHEEL: u16 = 0x0100;

/// The input the host takes: scancodes, Unicode, the extended mouse
/// buttons, the horizontal wheel and fast-path input.
pub const SERVER_INPUT_FLAGS: u16 = INPUT_FLAG_SCANCODES
    | INPUT_FLAG_MOUSEX
    | INPUT_FLAG_FASTPATH_INPUT
    | INPUT_FLAG_UNICODE
    | INPUT_FLAG_FASTPATH_INPUT2
    | TS_INPUT_FLAG_MOUSE_HWHEEL;

fn cap(out: &mut Vec<u8>, count: &mut u16, ty: u16, body: &[u8]) {
    out.put_u16(ty);
    out.put_u16((body.len() + 4) as u16);
    out.put_bytes(body);
    *count += 1;
}

/// The server's capability sets: the minimal valid set for a desktop of
/// uncompressed 32 bpp bitmap updates over fast-path, with fast-path input.
fn server_capabilities(width: u16, height: u16) -> (u16, Vec<u8>) {
    let mut out = Vec::new();
    let mut n = 0;

    // General (2.2.7.1.1): fast-path output, Refresh Rect and Suppress Output.
    let mut b = Vec::new();
    b.put_u16(1); // osMajorType: OSMAJORTYPE_WINDOWS
    b.put_u16(3); // osMinorType: OSMINORTYPE_WINDOWS_NT
    b.put_u16(0x0200); // protocolVersion: TS_CAPS_PROTOCOLVERSION
    b.put_u16(0); // pad2octetsA
    b.put_u16(0); // generalCompressionTypes
    b.put_u16(FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR);
    b.put_u16(0); // updateCapabilityFlag
    b.put_u16(0); // remoteUnshareFlag
    b.put_u16(0); // generalCompressionLevel
    b.put_u8(1); // refreshRectSupport
    b.put_u8(1); // suppressOutputSupport
    cap(&mut out, &mut n, CAPSTYPE_GENERAL, &b);

    // Bitmap (2.2.7.1.2): the desktop size the client MUST use, 32 bpp.
    let mut b = Vec::new();
    b.put_u16(32); // preferredBitsPerPixel
    b.put_u16(1); // receive1BitPerPixel
    b.put_u16(1); // receive4BitsPerPixel
    b.put_u16(1); // receive8BitsPerPixel
    b.put_u16(width);
    b.put_u16(height);
    b.put_u16(0); // pad2octets
    b.put_u16(0); // desktopResizeFlag: the host does not resize
    b.put_u16(1); // bitmapCompressionFlag: MUST be TRUE
    b.put_u8(0); // highColorFlags
    b.put_u8(0); // drawingFlags
    b.put_u16(1); // multipleRectangleSupport: MUST be TRUE
    b.put_u16(0); // pad2octetsB
    cap(&mut out, &mut n, CAPSTYPE_BITMAP, &b);

    // Order (2.2.7.1.3): no drawing orders, bitmap updates only.
    let mut b = Vec::new();
    b.put_zeros(16); // terminalDescriptor
    b.put_u32(0); // pad4octetsA
    b.put_u16(1); // desktopSaveXGranularity
    b.put_u16(20); // desktopSaveYGranularity
    b.put_u16(0); // pad2octetsA
    b.put_u16(1); // maximumOrderLevel: ORD_LEVEL_1_ORDERS
    b.put_u16(0); // numberFonts
    // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT (both MUST) | COLORINDEXSUPPORT
    b.put_u16(0x002A);
    b.put_zeros(32); // orderSupport: none
    b.put_u16(0); // textFlags
    b.put_u16(0); // orderSupportExFlags
    b.put_u32(0); // pad4octetsB
    b.put_u32(480 * 480); // desktopSaveSize
    b.put_u16(0); // pad2octetsC
    b.put_u16(0); // pad2octetsD
    b.put_u16(0); // textANSICodePage
    b.put_u16(0); // pad2octetsE
    cap(&mut out, &mut n, CAPSTYPE_ORDER, &b);

    // Pointer (2.2.7.1.5): color pointers, with the New Pointer cache size.
    let mut b = Vec::new();
    b.put_u16(1); // colorPointerFlag
    b.put_u16(25); // colorPointerCacheSize
    b.put_u16(25); // pointerCacheSize
    cap(&mut out, &mut n, CAPSTYPE_POINTER, &b);

    // Input (2.2.7.1.6): the server sends no keyboard description.
    let mut b = Vec::new();
    b.put_u16(SERVER_INPUT_FLAGS);
    b.put_u16(0); // pad2octetsA
    b.put_u32(0); // keyboardLayout
    b.put_u32(0); // keyboardType
    b.put_u32(0); // keyboardSubType
    b.put_u32(0); // keyboardFunctionKey
    b.put_zeros(64); // imeFileName
    cap(&mut out, &mut n, CAPSTYPE_INPUT, &b);

    // Virtual Channel (2.2.7.1.10): no compression, the default chunk size.
    let mut b = Vec::new();
    b.put_u32(0); // flags: VCCAPS_NO_COMPR
    b.put_u32(1600); // VCChunkSize
    cap(&mut out, &mut n, CAPSTYPE_VIRTUALCHANNEL, &b);

    // Share (2.2.7.2.4): the server's MCS channel id.
    let mut b = Vec::new();
    b.put_u16(SERVER_CHANNEL_ID);
    b.put_u16(0);
    cap(&mut out, &mut n, CAPSTYPE_SHARE, &b);

    // Font (2.2.7.2.5).
    cap(&mut out, &mut n, CAPSTYPE_FONT, &[1, 0, 0, 0]);

    // Multifragment Update (2.2.7.2.6): a whole frame of tiles.
    let mut b = Vec::new();
    b.put_u32(crate::pdu::max_request_size(width, height));
    cap(&mut out, &mut n, CAPSTYPE_MULTIFRAGMENTUPDATE, &b);

    (n, out)
}

/// Demand Active PDU (2.2.1.13.1) from the server channel.
pub fn demand_active(share_id: u32, width: u16, height: u16) -> Vec<u8> {
    let (count, caps) = server_capabilities(width, height);
    let source = b"RDP\0";
    let mut b = Vec::new();
    b.put_u32(share_id);
    b.put_u16(source.len() as u16); // lengthSourceDescriptor
    b.put_u16((caps.len() + 4) as u16); // lengthCombinedCapabilities
    b.put_bytes(source);
    b.put_u16(count);
    b.put_u16(0); // pad2Octets
    b.put_bytes(&caps);
    b.put_u32(0); // sessionId
    share_control(PDUTYPE_DEMANDACTIVE, SERVER_CHANNEL_ID, &b)
}

/// What the server uses from the client's Confirm Active PDU (2.2.1.13.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfirmActive {
    pub share_id: u32,
    pub originator: u16,
    /// extraFlags of the General Capability Set (2.2.7.1.1).
    pub general_flags: u16,
    /// preferredBitsPerPixel and the desktop size of the Bitmap Capability
    /// Set (2.2.7.1.2).
    pub bpp: u16,
    pub width: u16,
    pub height: u16,
    /// inputFlags of the Input Capability Set (2.2.7.1.6).
    pub input_flags: u16,
    /// MaxRequestSize of the Multifragment Update Capability Set
    /// (2.2.7.2.6); None when the client sent none.
    pub max_request_size: Option<u32>,
}

impl ConfirmActive {
    /// The client takes fast-path output (FASTPATH_OUTPUT_SUPPORTED).
    pub fn fastpath_output(&self) -> bool {
        self.general_flags & FASTPATH_OUTPUT_SUPPORTED != 0
    }
}

/// Parses the body of a Confirm Active PDU (after the share control header).
pub fn parse_confirm_active(body: &[u8]) -> Result<ConfirmActive> {
    let mut r = Reader::new(body);
    let mut ca = ConfirmActive {
        share_id: r.u32()?,
        originator: r.u16()?,
        ..Default::default()
    };
    let src_len = r.u16()? as usize;
    r.u16()?; // lengthCombinedCapabilities
    r.skip(src_len)?;
    let count = r.u16()?;
    r.u16()?; // pad2Octets
    let mut bitmap = false;
    for _ in 0..count {
        let ty = r.u16()?;
        let len = r.u16()? as usize;
        if len < 4 {
            return proto("bad capability length");
        }
        let c = r.bytes(len - 4)?;
        let mut b = Reader::new(c);
        match ty {
            CAPSTYPE_GENERAL => {
                b.skip(10)?;
                ca.general_flags = b.u16()?;
            }
            CAPSTYPE_BITMAP => {
                ca.bpp = b.u16()?;
                b.skip(6)?;
                ca.width = b.u16()?;
                ca.height = b.u16()?;
                bitmap = true;
            }
            CAPSTYPE_INPUT => ca.input_flags = b.u16()?,
            CAPSTYPE_MULTIFRAGMENTUPDATE => ca.max_request_size = Some(b.u32()?),
            _ => {}
        }
    }
    if !bitmap {
        return proto("client sent no bitmap capability set");
    }
    Ok(ca)
}

/// Server Synchronize PDU body (2.2.1.19): messageType SYNCMSGTYPE_SYNC and
/// the target user.
pub fn synchronize(target_user: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(1);
    b.put_u16(target_user);
    b
}

/// Control PDU body (2.2.1.15.1, 2.2.1.20, 2.2.1.21).
pub fn control(action: u16, grant_id: u16, control_id: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(action);
    b.put_u16(grant_id);
    b.put_u32(control_id);
    b
}

/// Font Map PDU body (2.2.1.22.1): no entries, FONTMAP_FIRST | FONTMAP_LAST,
/// entrySize 4, as in the spec's example (4.1.22).
pub fn font_map() -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(0); // numberEntries
    b.put_u16(0); // totalNumEntries
    b.put_u16(0x0003); // mapFlags
    b.put_u16(0x0004); // entrySize
    b
}

/// Set Error Info PDU body (2.2.5.1.1).
pub fn set_error_info(code: u32) -> Vec<u8> {
    code.to_le_bytes().to_vec()
}

/// The server's finalization PDUs for one client PDU, wrapped as share
/// data from the server channel: Synchronize, Cooperate, Granted Control
/// and Font Map (2.2.1.19 to 2.2.1.22).
pub fn finalization_reply(share_id: u32, user_channel: u16, client: &ClientShareData) -> Vec<u8> {
    let data = |ty, body: &[u8]| share_data(share_id, SERVER_CHANNEL_ID, ty, body);
    match client {
        ClientShareData::Synchronize => data(PDUTYPE2_SYNCHRONIZE, &synchronize(user_channel)),
        ClientShareData::Control(CTRLACTION_COOPERATE) => {
            data(PDUTYPE2_CONTROL, &control(CTRLACTION_COOPERATE, 0, 0))
        }
        ClientShareData::Control(CTRLACTION_REQUEST_CONTROL) => data(
            PDUTYPE2_CONTROL,
            &control(
                CTRLACTION_GRANTED_CONTROL,
                user_channel,
                u32::from(SERVER_CHANNEL_ID),
            ),
        ),
        ClientShareData::FontList => data(PDUTYPE2_FONTMAP, &font_map()),
        _ => Vec::new(),
    }
}

/// A Set Error Info PDU, ready for the I/O channel.
pub fn error_info_pdu(share_id: u32, code: u32) -> Vec<u8> {
    share_data(
        share_id,
        SERVER_CHANNEL_ID,
        PDUTYPE2_SET_ERROR_INFO,
        &set_error_info(code),
    )
}

/// A share data PDU from the client (2.2.8.1.1.1.2), by pduType2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientShareData {
    /// Client Synchronize (2.2.1.14).
    Synchronize,
    /// Control Cooperate or Request Control (2.2.1.15, 2.2.1.16): the action.
    Control(u16),
    /// Persistent Key List (2.2.1.17); ignored, the host has no bitmap cache.
    PersistentKeyList,
    /// Font List (2.2.1.18).
    FontList,
    /// Refresh Rect (2.2.11.2): the areas to send again.
    RefreshRect(Vec<Rect>),
    /// Suppress Output (2.2.11.3): None stops updates; Some resumes them
    /// for the desktop rectangle.
    SuppressOutput(Option<Rect>),
    /// Slow-path input (2.2.8.1.1.3).
    Input(Vec<ClientInput>),
    /// Shutdown Request (2.2.2.2).
    ShutdownRequest,
    /// Any other pduType2.
    Other(u8),
}

/// Parses a client share data PDU body (after the share control header):
/// the share id and the PDU. A bulk-compressed PDU is refused: the host
/// never allows compression.
pub fn parse_client_share_data(body: &[u8]) -> Result<(u32, ClientShareData)> {
    const PACKET_COMPRESSED: u8 = 0x20;
    let mut r = Reader::new(body);
    let share_id = r.u32()?;
    r.u8()?; // pad1
    r.u8()?; // streamId
    r.u16()?; // uncompressedLength
    let ty = r.u8()?;
    let compressed = r.u8()?;
    r.u16()?; // compressedLength
    if compressed & PACKET_COMPRESSED != 0 {
        return proto("compressed share data PDU from the client");
    }
    let payload = r.rest();
    let mut p = Reader::new(payload);
    let pdu = match ty {
        PDUTYPE2_SYNCHRONIZE => ClientShareData::Synchronize,
        PDUTYPE2_CONTROL => ClientShareData::Control(p.u16()?),
        PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST => ClientShareData::PersistentKeyList,
        PDUTYPE2_FONTLIST => ClientShareData::FontList,
        PDUTYPE2_REFRESH_RECT => {
            let n = p.u8()?;
            p.skip(3)?; // pad3Octets
            let mut rects = Vec::with_capacity(n as usize);
            for _ in 0..n {
                rects.push(inclusive_rect(&mut p)?);
            }
            ClientShareData::RefreshRect(rects)
        }
        PDUTYPE2_SUPPRESS_OUTPUT => {
            let allow = p.u8()?;
            p.skip(3)?; // pad3Octets
            ClientShareData::SuppressOutput(match allow {
                0 => None,
                _ => Some(inclusive_rect(&mut p)?),
            })
        }
        PDUTYPE2_INPUT => ClientShareData::Input(parse_slowpath_input(payload)?),
        PDUTYPE2_SHUTDOWN_REQUEST => ClientShareData::ShutdownRequest,
        t => ClientShareData::Other(t),
    };
    Ok((share_id, pdu))
}

/// TS_RECTANGLE16 (2.2.11.1): inclusive bounds.
fn inclusive_rect(r: &mut Reader) -> Result<Rect> {
    let (left, top, right, bottom) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    if right < left || bottom < top {
        return Err(Error::Protocol(format!(
            "empty rectangle {left},{top} to {right},{bottom}"
        )));
    }
    Ok(Rect {
        x: left,
        y: top,
        w: (right - left).saturating_add(1),
        h: (bottom - top).saturating_add(1),
    })
}

#[cfg(test)]
#[path = "pdu_tests.rs"]
mod tests;
