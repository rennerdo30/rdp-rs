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

pub struct ClientSettings<'a> {
    pub width: u16,
    pub height: u16,
    pub keyboard_layout: u32,
    pub client_name: &'a str,
    pub selected_protocol: u32,
    /// Static virtual channels: (name, options).
    pub channels: &'a [(&'a str, u32)],
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
    core.put_u32(0x0008_0004); // RDP 5.0+
    core.put_u16(s.width);
    core.put_u16(s.height);
    core.put_u16(RNS_UD_COLOR_8BPP);
    core.put_u16(RNS_UD_SAS_DEL);
    core.put_u32(s.keyboard_layout);
    core.put_u32(2600); // clientBuild
    core.put_bytes(&fixed_utf16(s.client_name, 32));
    core.put_u32(4); // keyboardType: IBM enhanced (101/102)
    core.put_u32(0); // keyboardSubType
    core.put_u32(12); // keyboardFunctionKey
    core.put_zeros(64); // imeFileName
    core.put_u16(RNS_UD_COLOR_8BPP); // postBeta2ColorDepth
    core.put_u16(1); // clientProductId
    core.put_u32(0); // serialNumber
    core.put_u16(24); // highColorDepth
    core.put_u16(
        RNS_UD_24BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_15BPP_SUPPORT | RNS_UD_32BPP_SUPPORT,
    );
    core.put_u16(RNS_UD_CS_SUPPORT_ERRINFO_PDU | RNS_UD_CS_WANT_32BPP_SESSION);
    core.put_zeros(64); // clientDigProductId
    core.put_u8(0); // connectionType
    core.put_u8(0); // pad1octet
    core.put_u32(s.selected_protocol);
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

    let mut cluster = Vec::new();
    cluster.put_u32(0x0000_000D); // REDIRECTION_SUPPORTED | REDIRECTION_VERSION4
    cluster.put_u32(0);
    block(&mut out, CS_CLUSTER, &cluster);

    out
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
            channels: &[],
        };
        let b = client_data_blocks(&s);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), CS_CORE);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 216);
    }
}
