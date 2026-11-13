//! RD Gateway HTTP transport packets (MS-TSGU 2.2.10). All fields are
//! little-endian; every packet starts with an HTTP_PACKET_HEADER (2.2.10.9).

use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Result, proto};

// HTTP_PACKET_TYPE (MS-TSGU 2.2.5.3.3).
pub const PKT_TYPE_HANDSHAKE_REQUEST: u16 = 0x1;
pub const PKT_TYPE_HANDSHAKE_RESPONSE: u16 = 0x2;
pub const PKT_TYPE_EXTENDED_AUTH_MSG: u16 = 0x3;
pub const PKT_TYPE_TUNNEL_CREATE: u16 = 0x4;
pub const PKT_TYPE_TUNNEL_RESPONSE: u16 = 0x5;
pub const PKT_TYPE_TUNNEL_AUTH: u16 = 0x6;
pub const PKT_TYPE_TUNNEL_AUTH_RESPONSE: u16 = 0x7;
pub const PKT_TYPE_CHANNEL_CREATE: u16 = 0x8;
pub const PKT_TYPE_CHANNEL_RESPONSE: u16 = 0x9;
pub const PKT_TYPE_DATA: u16 = 0xA;
pub const PKT_TYPE_SERVICE_MESSAGE: u16 = 0xB;
pub const PKT_TYPE_REAUTH_MESSAGE: u16 = 0xC;
pub const PKT_TYPE_KEEPALIVE: u16 = 0xD;
pub const PKT_TYPE_CLOSE_CHANNEL: u16 = 0x10;
pub const PKT_TYPE_CLOSE_CHANNEL_RESPONSE: u16 = 0x11;

// HTTP_CAPABILITY_TYPE (2.2.5.3.9).
pub const HTTP_CAPABILITY_IDLE_TIMEOUT: u32 = 0x2;
pub const HTTP_CAPABILITY_MESSAGING_SERVICE_MSG: u32 = 0x8;

// HTTP_TUNNEL_RESPONSE_FIELDS_PRESENT_FLAGS (2.2.5.3.8).
pub const HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID: u16 = 0x1;

/// E_PROXY_QUARANTINE_ACCESSDENIED: tunnel authorization still continues (3.3.5.2 step 3).
pub const E_PROXY_QUARANTINE_ACCESSDENIED: u32 = 0x8007_59ED;

const HEADER_LEN: usize = 8;

/// Largest RDP payload put in one HTTP_DATA_PACKET (cbDataLen is 16 bits).
pub const MAX_DATA: usize = 0x4000;

fn packet(packet_type: u16, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(HEADER_LEN + body.len());
    p.put_u16(packet_type);
    p.put_u16(0); // reserved
    p.put_u32((HEADER_LEN + body.len()) as u32);
    p.put_bytes(body);
    p
}

/// Length of the packet at the start of `b` once its header is in (2.2.10.9).
pub fn packet_len(b: &[u8]) -> Result<Option<usize>> {
    let Some(h) = b.get(..HEADER_LEN) else {
        return Ok(None);
    };
    let len = u32::from_le_bytes(h[4..8].try_into().expect("4 bytes")) as usize;
    if !(HEADER_LEN..=0x10_0000).contains(&len) {
        return proto(format!("RD Gateway packet length {len}"));
    }
    Ok(Some(len))
}

/// A complete packet split into its type and the bytes after the header.
pub fn split(p: &[u8]) -> (u16, &[u8]) {
    (u16::from_le_bytes([p[0], p[1]]), &p[HEADER_LEN..])
}

/// UTF-16LE with a null terminator; cbLen counts the terminator, as Windows
/// and FreeRDP send it.
fn unicode_z(s: &str) -> Vec<u8> {
    let mut v = utf16le(s);
    v.extend_from_slice(&[0, 0]);
    v
}

/// HTTP_HANDSHAKE_REQUEST_PACKET (2.2.10.10), version 1.0.
pub fn handshake_request(extended_auth: u16) -> Vec<u8> {
    let mut b = vec![1, 0]; // verMajor, verMinor
    b.put_u16(0); // clientVersion, MUST be zero
    b.put_u16(extended_auth);
    packet(PKT_TYPE_HANDSHAKE_REQUEST, &b)
}

#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub error_code: u32,
    pub ver_major: u8,
    pub ver_minor: u8,
    pub extended_auth: u16,
}

/// HTTP_HANDSHAKE_RESPONSE_PACKET (2.2.10.11), body after the header.
pub fn parse_handshake_response(body: &[u8]) -> Result<HandshakeResponse> {
    let mut r = Reader::new(body);
    let error_code = r.u32()?;
    let ver_major = r.u8()?;
    let ver_minor = r.u8()?;
    r.skip(2)?; // serverVersion
    let extended_auth = r.u16()?;
    Ok(HandshakeResponse {
        error_code,
        ver_major,
        ver_minor,
        extended_auth,
    })
}

/// HTTP_TUNNEL_PACKET (2.2.10.18) without optional fields.
pub fn tunnel_create(caps: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(caps);
    b.put_u16(0); // fieldsPresent
    b.put_u16(0); // reserved
    packet(PKT_TYPE_TUNNEL_CREATE, &b)
}

#[derive(Debug, PartialEq, Eq)]
pub struct TunnelResponse {
    pub server_version: u16,
    pub status_code: u32,
    pub fields_present: u16,
    /// From HTTP_TUNNEL_RESPONSE_OPTIONAL (2.2.10.21), if present.
    pub tunnel_id: Option<u32>,
    pub caps: Option<u32>,
}

/// HTTP_TUNNEL_RESPONSE (2.2.10.20) and the start of its optional part.
pub fn parse_tunnel_response(body: &[u8]) -> Result<TunnelResponse> {
    let mut r = Reader::new(body);
    let server_version = r.u16()?;
    let status_code = r.u32()?;
    let fields_present = r.u16()?;
    r.skip(2)?; // reserved
    let tunnel_id = if fields_present & HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    let caps = if fields_present & 0x2 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    // SoH nonce/certificate and consent message follow; not used.
    Ok(TunnelResponse {
        server_version,
        status_code,
        fields_present,
        tunnel_id,
        caps,
    })
}

/// HTTP_TUNNEL_AUTH_PACKET (2.2.10.14) with the client name and no SoH.
pub fn tunnel_auth(client_name: &str) -> Vec<u8> {
    let name = unicode_z(client_name);
    let mut b = Vec::new();
    b.put_u16(0); // fieldsPresent
    b.put_u16(name.len() as u16);
    b.put_bytes(&name);
    packet(PKT_TYPE_TUNNEL_AUTH, &b)
}

#[derive(Debug, PartialEq, Eq)]
pub struct TunnelAuthResponse {
    pub error_code: u32,
    pub fields_present: u16,
    /// HTTP_TUNNEL_REDIR_FLAGS (2.2.5.3.7), if present.
    pub redir_flags: Option<u32>,
    /// Idle timeout in minutes, if present.
    pub idle_timeout: Option<u32>,
}

/// HTTP_TUNNEL_AUTH_RESPONSE (2.2.10.16) and its optional part (2.2.10.17).
pub fn parse_tunnel_auth_response(body: &[u8]) -> Result<TunnelAuthResponse> {
    let mut r = Reader::new(body);
    let error_code = r.u32()?;
    let fields_present = r.u16()?;
    r.skip(2)?; // reserved
    let redir_flags = if fields_present & 0x1 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    let idle_timeout = if fields_present & 0x2 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    Ok(TunnelAuthResponse {
        error_code,
        fields_present,
        redir_flags,
        idle_timeout,
    })
}

/// HTTP_CHANNEL_PACKET (2.2.10.2) with one resource (2.2.10.3), protocol 3.
pub fn channel_create(server: &str, port: u16) -> Vec<u8> {
    let name = unicode_z(server);
    let mut b = vec![1, 0]; // numResources, numAltResources
    b.put_u16(port);
    b.put_u16(3); // protocol, MUST be 3
    b.put_u16(name.len() as u16);
    b.put_bytes(&name);
    packet(PKT_TYPE_CHANNEL_CREATE, &b)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelResponse {
    pub error_code: u32,
    pub fields_present: u16,
    pub channel_id: Option<u32>,
}

/// HTTP_CHANNEL_RESPONSE (2.2.10.4) and the channel id of its optional part (2.2.10.5).
pub fn parse_channel_response(body: &[u8]) -> Result<ChannelResponse> {
    let mut r = Reader::new(body);
    let error_code = r.u32()?;
    let fields_present = r.u16()?;
    r.skip(2)?; // reserved
    let channel_id = if fields_present & 0x1 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    // udpPort and the UDP authnCookie follow; RDGUDP is not used.
    Ok(ChannelResponse {
        error_code,
        fields_present,
        channel_id,
    })
}

/// HTTP_DATA_PACKET (2.2.10.6). `data` is at most [`MAX_DATA`] long.
pub fn data(data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() <= 0xFFFF);
    let mut b = Vec::with_capacity(2 + data.len());
    b.put_u16(data.len() as u16);
    b.put_bytes(data);
    packet(PKT_TYPE_DATA, &b)
}

/// The data field of an HTTP_DATA_PACKET body.
pub fn parse_data(body: &[u8]) -> Result<&[u8]> {
    let mut r = Reader::new(body);
    let len = r.u16()? as usize;
    r.bytes(len)
}

/// HTTP_KEEPALIVE_PACKET (2.2.10.8).
pub fn keepalive() -> Vec<u8> {
    packet(PKT_TYPE_KEEPALIVE, &[])
}

/// HTTP_CLOSE_PACKET (2.2.10.23) of type PKT_TYPE_CLOSE_CHANNEL or
/// PKT_TYPE_CLOSE_CHANNEL_RESPONSE.
pub fn close(packet_type: u16, status: u32) -> Vec<u8> {
    packet(packet_type, &status.to_le_bytes())
}

/// The statusCode of an HTTP_CLOSE_PACKET body.
pub fn parse_close(body: &[u8]) -> Result<u32> {
    Reader::new(body).u32()
}

/// The message string of an HTTP_SERVICE_MESSAGE (2.2.10.13), as UTF-16LE.
pub fn parse_service_message(body: &[u8]) -> Result<String> {
    let mut r = Reader::new(body);
    let len = r.u16()? as usize;
    let units: Vec<u16> = r
        .bytes(len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&c| c != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// A readable name for the HRESULTs of MS-TSGU 2.2.6.1.
pub fn error_name(code: u32) -> &'static str {
    match code {
        0x8007_59D8 | 0x0000_59D8 => "gateway internal error",
        0x8007_59DA => "the gateway's resource policy (RD RAP) denies this server",
        0x8007_59DB => "the gateway's connection policy (RD CAP) denies this user",
        0x8007_59DF => "tunnel or channel already disconnected",
        0x8007_59ED => "denied by quarantine policy",
        0x8007_59E9 => "the gateway requires a capability this client lacks (consent message?)",
        0x8007_59F9 => "unsupported authentication method",
        0x0000_0005 => "access denied",
        0x0000_59DD => "the gateway could not connect to the server",
        0x0000_59E6 => "the gateway has reached its connection limit",
        0x0000_59F6 => "session timeout",
        0x0000_04CA => "graceful disconnect",
        0x0000_04D4 => "connection aborted",
        0x8009_030C => "logon denied",
        _ => "gateway error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(v: &[u8]) -> Vec<u8> {
        v.to_vec()
    }

    #[test]
    fn handshake_request_spec_example() {
        // MS-TSGU 4.2.1 step 11: verMajor 1, verMinor 0, ExtendedAuth 0.
        assert_eq!(
            handshake_request(0),
            le(&[1, 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn handshake_response_spec_example() {
        // 4.2.1 step 12: version 1.0, ExtendedAuth = PAA | SC.
        let p = [2, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x03, 0];
        assert_eq!(packet_len(&p).unwrap(), Some(18));
        let (t, body) = split(&p);
        assert_eq!(t, PKT_TYPE_HANDSHAKE_RESPONSE);
        assert_eq!(
            parse_handshake_response(body).unwrap(),
            HandshakeResponse {
                error_code: 0,
                ver_major: 1,
                ver_minor: 0,
                extended_auth: 0x3,
            }
        );
        assert!(parse_handshake_response(&body[..9]).is_err());
    }

    #[test]
    fn tunnel_create_spec_example() {
        // 4.2.1 step 13: capsFlags 0x3F, fieldsPresent 0.
        assert_eq!(
            tunnel_create(0x3F),
            le(&[4, 0, 0, 0, 16, 0, 0, 0, 0x3F, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn tunnel_response_spec_example() {
        // 4.2.1 step 14: status 0, TUNNEL_ID | CAPS, tunnelId 6, capsFlags 0x3F.
        let p = [
            5, 0, 0, 0, 26, 0, 0, 0, // hdr
            1, 0, // serverVersion
            0, 0, 0, 0, // statusCode
            3, 0, 0, 0, // fieldsPresent, reserved
            6, 0, 0, 0, 0x3F, 0, 0, 0,
        ];
        let (t, body) = split(&p);
        assert_eq!(t, PKT_TYPE_TUNNEL_RESPONSE);
        let r = parse_tunnel_response(body).unwrap();
        assert_eq!(
            r,
            TunnelResponse {
                server_version: 1,
                status_code: 0,
                fields_present: 3,
                tunnel_id: Some(6),
                caps: Some(0x3F),
            }
        );
        // A flagged optional field that is missing is an error, not a panic.
        assert!(parse_tunnel_response(&body[..14]).is_err());
    }

    #[test]
    fn tunnel_auth_spec_example() {
        // 4.2.1 step 15: client name "RDG-Client1" (22 bytes of UTF-16, plus
        // the terminator this client sends).
        let p = tunnel_auth("RDG-Client1");
        assert_eq!(&p[..8], &[6, 0, 0, 0, 36, 0, 0, 0]);
        assert_eq!(&p[8..12], &[0, 0, 24, 0]);
        assert_eq!(&p[12..34], &utf16le("RDG-Client1")[..]);
        assert_eq!(&p[34..], &[0, 0]);
    }

    #[test]
    fn tunnel_auth_response_spec_example() {
        // 4.2.1 step 16: REDIR_FLAGS | IDLE_TIMEOUT, both zero.
        let body = [0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_tunnel_auth_response(&body).unwrap(),
            TunnelAuthResponse {
                error_code: 0,
                fields_present: 3,
                redir_flags: Some(0),
                idle_timeout: Some(0),
            }
        );
        let denied = [0xDB, 0x59, 0x07, 0x80, 0, 0, 0, 0];
        assert_eq!(
            parse_tunnel_auth_response(&denied).unwrap().error_code,
            0x8007_59DB
        );
    }

    #[test]
    fn channel_create_spec_example() {
        // 4.2.1 step 17: one resource, no alternates, port 3389, protocol 3.
        let p = channel_create("srv", 3389);
        let mut want = vec![8, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0x3D, 0x0D, 3, 0, 8, 0];
        want.extend_from_slice(&utf16le("srv"));
        want.extend_from_slice(&[0, 0]);
        assert_eq!(p, want);
    }

    #[test]
    fn channel_response_spec_example() {
        // 4.2.1 step 18: CHANNELID | UDPPORT | AUTHNCOOKIE, channelId 1, udpPort 3391.
        let body = [
            0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0x3F, 0x0D, 2, 0, 0xAA, 0xBB,
        ];
        assert_eq!(
            parse_channel_response(&body).unwrap(),
            ChannelResponse {
                error_code: 0,
                fields_present: 7,
                channel_id: Some(1),
            }
        );
    }

    #[test]
    fn data_round_trip() {
        let p = data(b"\x03\x00\x00\x0b");
        assert_eq!(p, [0xA, 0, 0, 0, 14, 0, 0, 0, 4, 0, 3, 0, 0, 0x0b]);
        let (t, body) = split(&p);
        assert_eq!(t, PKT_TYPE_DATA);
        assert_eq!(parse_data(body).unwrap(), b"\x03\x00\x00\x0b");
        // cbDataLen larger than the packet is rejected.
        assert!(parse_data(&[5, 0, 1, 2]).is_err());
    }

    #[test]
    fn keepalive_and_close_packets() {
        assert_eq!(keepalive(), [0xD, 0, 0, 0, 8, 0, 0, 0]);
        let c = close(PKT_TYPE_CLOSE_CHANNEL_RESPONSE, 0);
        assert_eq!(c, [0x11, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0]);
        let c = close(PKT_TYPE_CLOSE_CHANNEL, 0x59F6);
        let (t, body) = split(&c);
        assert_eq!(t, PKT_TYPE_CLOSE_CHANNEL);
        assert_eq!(parse_close(body).unwrap(), 0x59F6);
    }

    #[test]
    fn service_message() {
        let mut body = vec![10, 0];
        body.extend_from_slice(&utf16le("Hi!"));
        body.extend_from_slice(&[0, 0, 0, 0]); // terminator and trailing slack
        assert_eq!(parse_service_message(&body).unwrap(), "Hi!");
    }

    #[test]
    fn packet_len_bounds() {
        assert_eq!(packet_len(&[0xA, 0, 0, 0, 14, 0, 0]).unwrap(), None);
        assert!(packet_len(&[0xA, 0, 0, 0, 7, 0, 0, 0]).is_err());
        assert!(packet_len(&[0xA, 0, 0, 0, 0, 0, 0, 0x10]).is_err());
    }
}
