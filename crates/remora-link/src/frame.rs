//! Framing: one DVC message carries exactly one protocol message.
//!
//! ```text
//! offset size field
//!      0    2 type        message type (see `msg`)
//!      2    2 flags       reserved, sent as 0, ignored on receipt
//!      4    4 request_id  pairs a request with its result; 0 when unused
//!      8    4 payload_len exact length of the payload that follows
//!     12    n payload
//! ```
//!
//! All integers are little-endian. A frame is at most [`MAX_MESSAGE`] bytes
//! including the header; both [`encode`] and [`decode`] enforce it. After
//! the handshake the whole frame (header included) is encrypted, so these
//! fields are never visible on the wire.

use crate::error::{Error, Result};
use crate::wire::{Put, Reader};

/// Header length in bytes.
pub const HEADER_LEN: usize = 12;

/// Largest frame (header plus payload), 1 MiB.
pub const MAX_MESSAGE: usize = 1 << 20;

/// Largest payload of one frame.
pub const MAX_PAYLOAD: usize = MAX_MESSAGE - HEADER_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub ty: u16,
    pub flags: u16,
    pub request_id: u32,
    pub payload: &'a [u8],
}

/// Builds a frame; fails when the payload is over [`MAX_PAYLOAD`].
pub fn encode(ty: u16, flags: u16, request_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::TooLarge(HEADER_LEN + payload.len()));
    }
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
    v.put_u16(ty);
    v.put_u16(flags);
    v.put_u32(request_id);
    v.put_u32(payload.len() as u32);
    v.put_bytes(payload);
    Ok(v)
}

/// Parses one frame. The buffer must hold exactly one frame: a short or
/// long buffer (truncated, or two messages glued together) is an error.
pub fn decode(buf: &[u8]) -> Result<Frame<'_>> {
    if buf.len() > MAX_MESSAGE {
        return Err(Error::TooLarge(buf.len()));
    }
    let mut r = Reader::new(buf);
    let ty = r.u16()?;
    let flags = r.u16()?;
    let request_id = r.u32()?;
    let len = r.u32()? as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::TooLarge(HEADER_LEN.saturating_add(len)));
    }
    let payload = r.bytes(len)?;
    r.finish()?;
    Ok(Frame {
        ty,
        flags,
        request_id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_exact_bytes() {
        let f = encode(0x0102, 0, 0x0A0B_0C0D, &[9, 8]).unwrap();
        assert_eq!(
            f,
            [0x02, 0x01, 0, 0, 0x0D, 0x0C, 0x0B, 0x0A, 2, 0, 0, 0, 9, 8]
        );
        let d = decode(&f).unwrap();
        assert_eq!(
            d,
            Frame {
                ty: 0x0102,
                flags: 0,
                request_id: 0x0A0B_0C0D,
                payload: &[9, 8]
            }
        );
    }

    #[test]
    fn limit_enforced_on_encode() {
        assert!(encode(1, 0, 0, &vec![0; MAX_PAYLOAD]).is_ok());
        assert!(matches!(
            encode(1, 0, 0, &vec![0; MAX_PAYLOAD + 1]),
            Err(Error::TooLarge(_))
        ));
    }

    #[test]
    fn limit_enforced_on_decode() {
        // A header announcing more than the limit fails before any read.
        let mut f = encode(1, 0, 0, &[]).unwrap();
        f[8..12].copy_from_slice(&((MAX_PAYLOAD as u32) + 1).to_le_bytes());
        assert!(matches!(decode(&f), Err(Error::TooLarge(_))));
        f[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(decode(&f), Err(Error::TooLarge(_))));
        // A buffer over the limit fails as a whole.
        assert!(matches!(
            decode(&vec![0; MAX_MESSAGE + 1]),
            Err(Error::TooLarge(_))
        ));
        // The largest legal frame decodes.
        let big = encode(1, 0, 0, &vec![7; MAX_PAYLOAD]).unwrap();
        assert_eq!(decode(&big).unwrap().payload.len(), MAX_PAYLOAD);
    }

    #[test]
    fn truncated_and_trailing_rejected() {
        let f = encode(5, 0, 1, b"abc").unwrap();
        for n in 0..f.len() {
            assert!(decode(&f[..n]).is_err(), "truncated to {n}");
        }
        let mut long = f.clone();
        long.push(0);
        assert!(decode(&long).is_err(), "trailing byte");
        let two = [f.clone(), f].concat();
        assert!(decode(&two).is_err(), "two frames in one message");
    }

    #[test]
    fn flags_are_carried_but_not_interpreted() {
        let f = encode(5, 0xFFFF, 0, &[]).unwrap();
        assert_eq!(decode(&f).unwrap().flags, 0xFFFF);
    }
}
