//! TPKT (RFC 1006) and X.224 class 0 with RDP negotiation (MS-RDPBCGR 2.2.1.1, 2.2.1.2).

use crate::cursor::{Put, le32};
use crate::error::{Error, Result, proto};

pub const PROTOCOL_RDP: u32 = 0x0;
pub const PROTOCOL_SSL: u32 = 0x1;
pub const PROTOCOL_HYBRID: u32 = 0x2;
pub const PROTOCOL_HYBRID_EX: u32 = 0x8;

pub fn tpkt(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03, 0x00];
    out.put_u16_be((payload.len() + 4) as u16);
    out.put_bytes(payload);
    out
}

/// RDSTLS (MS-RDPBCGR 5.4.5.3), for a redirected logon with an encrypted password.
pub const PROTOCOL_RDSTLS: u32 = 0x4;

/// X.224 Connection Request with routing cookie and RDP_NEG_REQ.
pub fn connection_request(cookie_user: &str, protocols: u32) -> Vec<u8> {
    let cookie = format!("Cookie: mstshash={cookie_user}\r\n");
    request(cookie.as_bytes(), protocols)
}

/// X.224 Connection Request with a routing token (from a Server Redirection
/// PDU's LoadBalanceInfo, ending in CR LF) in place of the cookie (2.2.1.1,
/// 3.2.5.3.1).
pub fn connection_request_routed(token: &[u8], protocols: u32) -> Result<Vec<u8>> {
    if !token.ends_with(b"\r\n") || 6 + token.len() + 8 > 0xFE {
        return proto("routing token too long or not terminated by CR LF");
    }
    Ok(request(token, protocols))
}

fn request(token: &[u8], protocols: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u8((6 + token.len() + 8) as u8); // length indicator
    b.put_u8(0xE0); // CR
    b.put_u16_be(0); // dst-ref
    b.put_u16_be(0); // src-ref
    b.put_u8(0); // class 0
    b.put_bytes(token);
    b.put_u8(0x01); // TYPE_RDP_NEG_REQ
    b.put_u8(0);
    b.put_u16(8);
    b.put_u32(protocols);
    tpkt(&b)
}

/// Parses the X.224 Connection Confirm and returns the selected protocol.
pub fn parse_connection_confirm(frame: &[u8]) -> Result<u32> {
    let p = frame.get(4..).unwrap_or_default();
    if p.len() < 7 || p[1] & 0xF0 != 0xD0 {
        return proto("expected X.224 Connection Confirm");
    }
    if (p[0] as usize) < 6 + 8 || p.len() < 15 {
        return Ok(PROTOCOL_RDP); // server did not negotiate: legacy RDP security
    }
    let neg = &p[7..15];
    let value = le32(neg, 4).unwrap_or(0);
    match neg[0] {
        0x02 => Ok(value),
        0x03 => Err(Error::Unsupported(format!(
            "server refused negotiation: {}",
            match value {
                1 => "SSL_REQUIRED_BY_SERVER",
                2 => "SSL_NOT_ALLOWED_BY_SERVER",
                3 => "SSL_CERT_NOT_ON_SERVER",
                4 => "INCONSISTENT_FLAGS",
                5 => "HYBRID_REQUIRED_BY_SERVER",
                6 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
                _ => "unknown failure code",
            }
        ))),
        t => proto(format!("unknown negotiation response type {t}")),
    }
}

/// Wraps MCS data in an X.224 Data TPDU inside TPKT.
pub fn data(payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x02, 0xF0, 0x80];
    b.put_bytes(payload);
    tpkt(&b)
}

pub fn data_payload(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < 7 || frame[5] != 0xF0 {
        return proto("expected X.224 Data TPDU");
    }
    Ok(&frame[7..])
}
