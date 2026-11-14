//! Bounds-checked little-endian reading and writing, in the style of the
//! `rdp` crate's `cursor` module. Nothing here panics on malformed input.

use crate::error::{Error, Result};

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Malformed(format!(
                "truncated: need {n} bytes at offset {}, have {}",
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(Error::Malformed(format!("boolean {v}"))),
        }
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A UTF-8 string with a u16 byte-length prefix, at most `max` bytes.
    pub fn str(&mut self, max: usize) -> Result<String> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(Error::Malformed(format!("string of {n} bytes (max {max})")));
        }
        let b = self.bytes(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| Error::Malformed("string is not UTF-8".into()))
    }

    /// Byte string with a u32 length prefix, at most `max` bytes.
    pub fn blob(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(Error::Malformed(format!("blob of {n} bytes (max {max})")));
        }
        self.bytes(n)
    }

    /// Fails unless every byte was consumed: messages have exact lengths.
    pub fn finish(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(Error::Malformed(format!(
                "{} trailing bytes",
                self.remaining()
            )));
        }
        Ok(())
    }
}

pub trait Put {
    fn put_u8(&mut self, v: u8);
    fn put_bool(&mut self, v: bool);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_u64(&mut self, v: u64);
    fn put_bytes(&mut self, b: &[u8]);
    /// See [`Reader::str`]. The caller has checked the length against the
    /// message limit; longer strings are cut at a character boundary.
    fn put_str(&mut self, s: &str, max: usize);
    fn put_blob(&mut self, b: &[u8]);
}

impl Put for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_bool(&mut self, v: bool) {
        self.push(u8::from(v));
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
    fn put_str(&mut self, s: &str, max: usize) {
        let s = truncate(s, max.min(u16::MAX as usize));
        self.put_u16(s.len() as u16);
        self.extend_from_slice(s.as_bytes());
    }
    fn put_blob(&mut self, b: &[u8]) {
        self.put_u32(b.len() as u32);
        self.extend_from_slice(b);
    }
}

/// `s` cut to at most `max` bytes at a character boundary.
pub fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses lower- or upper-case hex into exactly `N` bytes.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in s.as_chunks::<2>().0.iter().enumerate() {
        let d = |c: u8| (c as char).to_digit(16);
        out[i] = (d(pair[0])? * 16 + d(pair[1])?) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(r.u16().is_err());
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.u8().is_err());
        r.finish().unwrap();
    }

    #[test]
    fn strings_round_trip_and_limits() {
        let mut v = Vec::new();
        v.put_str("grüße", 64);
        let mut r = Reader::new(&v);
        assert_eq!(r.str(64).unwrap(), "grüße");
        let mut r = Reader::new(&v);
        assert!(r.str(3).is_err(), "longer than the limit");
        // Invalid UTF-8.
        let mut r = Reader::new(&[2, 0, 0xff, 0xfe]);
        assert!(r.str(64).is_err());
        // Cut at a character boundary.
        assert_eq!(truncate("aü", 2), "a");
    }

    #[test]
    fn booleans_are_strict() {
        assert!(Reader::new(&[2]).bool().is_err());
        assert!(Reader::new(&[1]).bool().unwrap());
    }

    #[test]
    fn hex_round_trip() {
        let b = [0u8, 0xab, 0x10, 0xff];
        assert_eq!(hex(&b), "00ab10ff");
        assert_eq!(unhex::<4>("00AB10ff"), Some(b));
        assert_eq!(unhex::<4>("00ab10f"), None);
        assert_eq!(unhex::<4>("00ab10fg"), None);
    }
}
