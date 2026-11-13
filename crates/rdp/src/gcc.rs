//! T.124 GCC Conference Create Request/Response with the RDP client/server
//! data blocks (MS-RDPBCGR 2.2.1.3, 2.2.1.4).

use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Result, proto};
use crate::mcs::put_per_len;

const CS_CORE: u16 = 0xC001;
const CS_SECURITY: u16 = 0xC002;
const CS_NET: u16 = 0xC003;
const CS_CLUSTER: u16 = 0xC004;

const SC_CORE: u16 = 0x0C01;
const SC_SECURITY: u16 = 0x0C02;
const SC_NET: u16 = 0x0C03;

const RNS_UD_COLOR_8BPP: u16 = 0xCA01;
const RNS_UD_SAS_DEL: u16 = 0xAA03;
const RNS_UD_24BPP_SUPPORT: u16 = 0x0001;
const RNS_UD_16BPP_SUPPORT: u16 = 0x0002;
const RNS_UD_15BPP_SUPPORT: u16 = 0x0004;
const RNS_UD_32BPP_SUPPORT: u16 = 0x0008;
const RNS_UD_CS_SUPPORT_ERRINFO_PDU: u16 = 0x0001;
const RNS_UD_CS_WANT_32BPP_SESSION: u16 = 0x0002;
const RNS_UD_CS_STRONG_ASYMMETRIC_KEYS: u16 = 0x0008;
const RNS_UD_CS_VALID_CONNECTION_TYPE: u16 = 0x0020;
const RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL: u16 = 0x0100;
/// The client handles Server Heartbeat PDUs (MS-RDPBCGR 2.2.1.3.2, 2.2.16.1).
const RNS_UD_CS_SUPPORT_HEARTBEAT_PDU: u16 = 0x0400;

pub struct ClientSettings<'a> {
    pub width: u16,
    pub height: u16,
    pub keyboard_layout: u32,
    pub client_name: &'a str,
    pub selected_protocol: u32,
    /// Desktop scale in percent (100..=500), as Windows' display scaling.
    pub scale: u32,
    /// 15, 16, 24 or 32 bits per pixel.
    pub color_depth: u16,
    pub connection_type: crate::ConnectionType,
    /// Static virtual channels: (name, options).
    pub channels: &'a [(&'a str, u32)],
    /// Offer the graphics pipeline (MS-RDPEGFX) in earlyCapabilityFlags.
    pub gfx: bool,
    /// RedirectedSessionID from a Server Redirection PDU (2.2.1.3.5).
    pub redirected_session_id: Option<u32>,
    /// REDIRECTED_SMARTCARD: the redirection said LB_SMARTCARD_LOGON.
    pub redirected_smartcard: bool,
}

fn block(out: &mut Vec<u8>, ty: u16, body: &[u8]) {
    out.put_u16(ty);
    out.put_u16((body.len() + 4) as u16);
    out.put_bytes(body);
}

fn fixed_utf16(s: &str, bytes: usize) -> Vec<u8> {
    let mut v = utf16le(s);
    v.truncate(bytes - 2);
    v.resize(bytes, 0);
    v
}

pub fn client_data_blocks(s: &ClientSettings) -> Vec<u8> {
    let mut out = Vec::new();

    let mut core = Vec::new();
    // Announce a current client (RDP 10.12): Windows decides which in-session
    // services to start (clipboard, audio) partly from how modern the client is.
    core.put_u32(0x0008_0011); // RDP_VERSION_10_12
    core.put_u16(s.width);
    core.put_u16(s.height);
    core.put_u16(RNS_UD_COLOR_8BPP);
    core.put_u16(RNS_UD_SAS_DEL);
    core.put_u32(s.keyboard_layout);
    core.put_u32(22621); // clientBuild
    core.put_bytes(&fixed_utf16(s.client_name, 32));
    core.put_u32(4); // keyboardType: IBM enhanced (101/102)
    core.put_u32(0); // keyboardSubType
    core.put_u32(12); // keyboardFunctionKey
    core.put_zeros(64); // imeFileName
    core.put_u16(RNS_UD_COLOR_8BPP); // postBeta2ColorDepth
    core.put_u16(1); // clientProductId
    core.put_u32(0); // serialNumber
    // 32 bpp is asked for with RNS_UD_CS_WANT_32BPP_SESSION; highColorDepth
    // then says 24 (2.2.1.3.2).
    let depth = crate::experience::valid_color_depth(s.color_depth);
    core.put_u16(depth.min(24)); // highColorDepth
    core.put_u16(
        RNS_UD_24BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_15BPP_SUPPORT | RNS_UD_32BPP_SUPPORT,
    );
    let want32 = if depth == 32 {
        RNS_UD_CS_WANT_32BPP_SESSION
    } else {
        0
    };
    core.put_u16(
        RNS_UD_CS_SUPPORT_ERRINFO_PDU
            | want32
            | RNS_UD_CS_STRONG_ASYMMETRIC_KEYS
            | RNS_UD_CS_VALID_CONNECTION_TYPE
            | RNS_UD_CS_SUPPORT_HEARTBEAT_PDU
            | if s.gfx {
                RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL
            } else {
                0
            },
    );
    core.put_zeros(64); // clientDigProductId
    core.put_u8(s.connection_type as u8); // connectionType (valid per the flag above)
    core.put_u8(0); // pad1octet
    core.put_u32(s.selected_protocol);
    // Display scaling (MS-RDPBCGR 2.2.1.3.2): the physical size is derived
    // from the pixels at 96 DPI x scale, so the server's DPI math matches.
    let scale = s.scale.clamp(100, 500);
    let mm = |px: u16| (px as u32 * 2540 / (96 * scale)).clamp(10, 10_000);
    core.put_u32(mm(s.width)); // desktopPhysicalWidth (mm)
    core.put_u32(mm(s.height)); // desktopPhysicalHeight (mm)
    core.put_u16(0); // desktopOrientation: landscape
    core.put_u32(scale); // desktopScaleFactor
    core.put_u32(crate::disp::device_scale(scale)); // deviceScaleFactor
    block(&mut out, CS_CORE, &core);

    let mut sec = Vec::new();
    sec.put_u32(0); // encryptionMethods: none, TLS/CredSSP protect the session
    sec.put_u32(0); // extEncryptionMethods
    block(&mut out, CS_SECURITY, &sec);

    let mut net = Vec::new();
    net.put_u32(s.channels.len() as u32);
    for (name, options) in s.channels {
        let mut n = name.as_bytes().to_vec();
        n.resize(8, 0);
        net.put_bytes(&n);
        net.put_u32(*options);
    }
    block(&mut out, CS_NET, &net);

    block(&mut out, CS_CLUSTER, &cluster_data(s));

    out
}

/// TS_UD_CS_CLUSTER body (2.2.1.3.5): redirection version 4, plus the
/// session a Server Redirection PDU named.
fn cluster_data(s: &ClientSettings) -> Vec<u8> {
    const REDIRECTION_SUPPORTED: u32 = 0x01;
    const REDIRECTED_SESSIONID_FIELD_VALID: u32 = 0x02;
    const REDIRECTION_VERSION4: u32 = 0x03 << 2;
    const REDIRECTED_SMARTCARD: u32 = 0x40;
    let mut flags = REDIRECTION_SUPPORTED | REDIRECTION_VERSION4;
    if s.redirected_session_id.is_some() {
        flags |= REDIRECTED_SESSIONID_FIELD_VALID;
    }
    if s.redirected_smartcard {
        flags |= REDIRECTED_SMARTCARD;
    }
    let mut cluster = Vec::new();
    cluster.put_u32(flags);
    cluster.put_u32(s.redirected_session_id.unwrap_or(0));
    cluster
}

/// GCC Conference Create Request wrapped in T.124 ConnectData.
pub fn conference_create_request(s: &ClientSettings) -> Vec<u8> {
    let blocks = client_data_blocks(s);
    let mut ccr = vec![
        0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00, b'D', b'u', b'c', b'a',
    ];
    put_per_len(&mut ccr, blocks.len());
    ccr.extend(blocks);
    let mut out = vec![0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01];
    put_per_len(&mut out, ccr.len());
    out.extend(ccr);
    out
}

#[derive(Debug, Default)]
pub struct ServerData {
    pub version: u32,
    pub io_channel: u16,
    pub channel_ids: Vec<u16>,
    pub encryption_method: u32,
    pub encryption_level: u32,
}

/// Parses the GCC Conference Create Response user data.
pub fn parse_conference_create_response(data: &[u8]) -> Result<ServerData> {
    let Some(pos) = data.windows(4).position(|w| w == b"McDn") else {
        return proto("GCC response without server data key");
    };
    let (len, n) = crate::mcs::read_per_len(data, pos + 4)?;
    let start = pos + 4 + n;
    let blocks = data
        .get(start..start + len)
        .ok_or_else(|| crate::Error::Protocol("GCC server data truncated".into()))?;

    let mut sd = ServerData::default();
    let mut r = Reader::new(blocks);
    while r.remaining() >= 4 {
        let ty = r.u16()?;
        let blen = r.u16()? as usize;
        if blen < 4 {
            return proto("bad server data block length");
        }
        let body = r.bytes(blen - 4)?;
        let mut b = Reader::new(body);
        match ty {
            SC_CORE => sd.version = b.u32()?,
            SC_SECURITY => {
                sd.encryption_method = b.u32()?;
                sd.encryption_level = b.u32()?;
            }
            SC_NET => {
                sd.io_channel = b.u16()?;
                let count = b.u16()?;
                for _ in 0..count {
                    sd.channel_ids.push(b.u16()?);
                }
            }
            _ => {}
        }
    }
    if sd.io_channel == 0 {
        return proto("server did not assign an I/O channel");
    }
    Ok(sd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_block_has_spec_length() {
        let s = ClientSettings {
            width: 1024,
            height: 768,
            keyboard_layout: 0x409,
            client_name: "TEST",
            selected_protocol: 3,
            scale: 150,
            color_depth: 32,
            connection_type: crate::ConnectionType::Lan,
            channels: &[],
            gfx: false,
            redirected_session_id: None,
            redirected_smartcard: false,
        };
        let b = client_data_blocks(&s);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), CS_CORE);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 234);
        // Scale fields at the end of the core block: desktop 150, device 140.
        assert_eq!(&b[226..234], &[150, 0, 0, 0, 140, 0, 0, 0]);
        // earlyCapabilityFlags (offset 144): ERRINFO | WANT_32BPP |
        // STRONG_ASYMMETRIC_KEYS | VALID_CONNECTION_TYPE | HEARTBEAT, no GFX.
        assert_eq!(u16::from_le_bytes([b[144], b[145]]), 0x042B);
        let gfx = client_data_blocks(&ClientSettings { gfx: true, ..s });
        assert_eq!(u16::from_le_bytes([gfx[144], gfx[145]]), 0x052B);

        // Client Cluster Data is the last block (2.2.1.3.5): header, Flags,
        // RedirectedSessionID.
        let cluster = |s: &ClientSettings| {
            let b = client_data_blocks(s);
            let c = b[b.len() - 12..].to_vec();
            assert_eq!(&c[..4], &[0x04, 0xC0, 12, 0]);
            (
                u32::from_le_bytes(c[4..8].try_into().unwrap()),
                u32::from_le_bytes(c[8..12].try_into().unwrap()),
            )
        };
        // REDIRECTION_SUPPORTED | REDIRECTION_VERSION4, no session.
        assert_eq!(cluster(&s), (0x0D, 0));
        let redirected = ClientSettings {
            redirected_session_id: Some(2),
            ..s
        };
        // + REDIRECTED_SESSIONID_FIELD_VALID.
        assert_eq!(cluster(&redirected), (0x0F, 2));
        let smartcard = ClientSettings {
            redirected_smartcard: true,
            ..redirected
        };
        assert_eq!(cluster(&smartcard), (0x4F, 2));
    }
}
