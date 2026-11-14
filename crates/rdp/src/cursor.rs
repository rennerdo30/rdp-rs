//! Bounds-checked little/big-endian reading and writing helpers.

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

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// The buffer from offset `start` (at most the current position) on.
    pub fn buf_from(&self, start: usize) -> &'a [u8] {
        &self.buf[start.min(self.pos)..]
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Protocol(format!(
                "truncated: need {n} bytes at offset {}, have {}",
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
}

pub trait Put {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_u16_be(&mut self, v: u16);
    fn put_bytes(&mut self, b: &[u8]);
    fn put_zeros(&mut self, n: usize);
}

impl Put for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u16_be(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
    fn put_zeros(&mut self, n: usize) {
        self.resize(self.len() + n, 0);
    }
}

/// UTF-16LE without terminator.
pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// UTF-16LE with a two-byte null terminator.
pub fn utf16le_z(s: &str) -> Vec<u8> {
    let mut v = utf16le(s);
    v.extend_from_slice(&[0, 0]);
    v
}

pub fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
