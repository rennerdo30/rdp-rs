//! WebSocket framing (RFC 6455 section 5) and the opening-handshake key
//! (section 4.2.2), as far as the RD Gateway transport needs them: binary
//! data frames, ping/pong and close. Client frames are always masked.

use crate::error::{Result, proto};

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Largest frame payload accepted from the server; RD Gateway frames carry
/// at most one HTTP packet of up to 64 KiB of RDP data.
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;

/// One frame from the server, unmasked.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// A masked client frame with FIN set (RFC 6455 5.2, 5.3).
pub fn encode(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Takes one complete frame off the front of `buf`, if there is one.
/// Server frames are normally unmasked; a masked one is unmasked anyway.
pub fn decode(buf: &mut Vec<u8>) -> Result<Option<Frame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return proto("WebSocket frame with reserved bits set");
    }
    let opcode = b0 & 0x0F;
    if !matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return proto(format!("unknown WebSocket opcode {opcode:#x}"));
    }
    let masked = b1 & 0x80 != 0;
    let (len, mut at) = match b1 & 0x7F {
        126 => match buf.get(2..4) {
            Some(b) => (u16::from_be_bytes([b[0], b[1]]) as u64, 4),
            None => return Ok(None),
        },
        127 => match buf.get(2..10) {
            Some(b) => (u64::from_be_bytes(b.try_into().expect("8 bytes")), 10),
            None => return Ok(None),
        },
        n => (n as u64, 2),
    };
    if len > MAX_PAYLOAD {
        return proto(format!("WebSocket frame of {len} bytes"));
    }
    if opcode >= OP_CLOSE && (len > 125 || b0 & 0x80 == 0) {
        return proto("fragmented or oversized WebSocket control frame");
    }
    let mask = if masked {
        let Some(m) = buf.get(at..at + 4) else {
            return Ok(None);
        };
        at += 4;
        Some([m[0], m[1], m[2], m[3]])
    } else {
        None
    };
    let end = at + len as usize;
    if buf.len() < end {
        return Ok(None);
    }
    let mut payload: Vec<u8> = buf[at..end].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    buf.drain(..end);
    Ok(Some(Frame {
        fin: b0 & 0x80 != 0,
        opcode,
        payload,
    }))
}

/// Sec-WebSocket-Accept for a Sec-WebSocket-Key (RFC 6455 4.2.2 step 5.4).
pub fn accept_key(key: &str) -> String {
    let mut data = key.as_bytes().to_vec();
    data.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    base64_encode(digest.as_ref())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64; padding is optional, whitespace is not allowed.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let Some(v) = B64.iter().position(|&x| x == c) else {
            return proto("invalid base64");
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_rfc6455_example() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_rfc4648_vectors() {
        // RFC 4648 section 10.
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), plain.as_bytes());
        }
        assert!(base64_decode("Zm9v!").is_err());
    }

    #[test]
    fn masked_client_frame_rfc6455_example() {
        // RFC 6455 5.7: a masked text frame "Hello".
        let f = encode(OP_TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(
            f,
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        // The decoder unmasks it again.
        let mut buf = f;
        let frame = decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.payload, b"Hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn unmasked_server_frames_rfc6455_examples() {
        // RFC 6455 5.7: unmasked "Hello", then a fragmented "Hel" + "lo".
        let mut buf = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        buf.extend_from_slice(&[0x01, 0x03, 0x48, 0x65, 0x6c]);
        buf.extend_from_slice(&[0x80, 0x02, 0x6c, 0x6f]);
        let a = decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            (a.fin, a.opcode, &a.payload[..]),
            (true, OP_TEXT, &b"Hello"[..])
        );
        let b = decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            (b.fin, b.opcode, &b.payload[..]),
            (false, OP_TEXT, &b"Hel"[..])
        );
        let c = decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            (c.fin, c.opcode, &c.payload[..]),
            (true, OP_CONTINUATION, &b"lo"[..])
        );
        assert!(decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn ping_pong_and_close_frames() {
        // RFC 6455 5.7: unmasked ping "Hello"; the pong reply is masked.
        let mut buf = vec![0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let ping = decode(&mut buf).unwrap().unwrap();
        assert_eq!((ping.opcode, &ping.payload[..]), (OP_PING, &b"Hello"[..]));
        let pong = encode(OP_PONG, &ping.payload, [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(
            pong,
            [
                0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        // Close with status 1000 (normal closure).
        let close = encode(OP_CLOSE, &1000u16.to_be_bytes(), [1, 2, 3, 4]);
        assert_eq!(&close[..2], &[0x88, 0x82]);
        let mut buf = close;
        let f = decode(&mut buf).unwrap().unwrap();
        assert_eq!((f.opcode, &f.payload[..]), (OP_CLOSE, &[0x03, 0xe8][..]));
        // A control frame may not be fragmented.
        assert!(decode(&mut vec![0x09, 0x00]).is_err());
    }

    #[test]
    fn extended_lengths_and_partial_input() {
        for len in [125usize, 126, 0xFFFF, 0x10000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let f = encode(OP_BINARY, &data, [9, 8, 7, 6]);
            let header = match len {
                0..=125 => 6,
                126..=0xFFFF => 8,
                _ => 14,
            };
            assert_eq!(f.len(), header + len);
            // Any proper prefix is incomplete, never an error.
            for cut in [1, header - 1, header, f.len() - 1] {
                let mut part = f[..cut].to_vec();
                assert!(decode(&mut part).unwrap().is_none(), "len {len} cut {cut}");
                assert_eq!(part.len(), cut);
            }
            let mut whole = f;
            assert_eq!(decode(&mut whole).unwrap().unwrap().payload, data);
        }
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(decode(&mut vec![0xC2, 0x00]).is_err()); // RSV1
        assert!(decode(&mut vec![0x83, 0x00]).is_err()); // opcode 3
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode(&mut huge).is_err());
    }
}
