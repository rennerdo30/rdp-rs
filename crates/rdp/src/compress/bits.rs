//! Bit readers for the compressed streams. MPPC (MS-RDPBCGR 3.1.8.4) writes
//! the most significant bit of each byte first; RDP 6.0 (MS-RDPEGDI
//! 3.1.8.1.4) packs codes into little-endian words, least significant bit
//! first. Reading past the end is an error, never a panic.

use crate::error::{Result, proto};

fn truncated<T>() -> Result<T> {
    proto("compressed stream truncated")
}

/// Most-significant-bit-first reader.
pub(crate) struct MsbBits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> MsbBits<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit
    }

    pub fn bit(&mut self) -> Result<u32> {
        let Some(byte) = self.data.get(self.bit / 8) else {
            return truncated();
        };
        let b = (byte >> (7 - self.bit % 8)) & 1;
        self.bit += 1;
        Ok(b as u32)
    }

    /// Reads `n` (at most 24) bits as an unsigned number, first bit highest.
    pub fn read(&mut self, n: u32) -> Result<u32> {
        if (n as usize) > self.remaining() {
            return truncated();
        }
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
}

/// Least-significant-bit-first reader.
pub(crate) struct LsbBits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> LsbBits<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit
    }

    /// The next `n` (at most 24) bits without consuming them; bits past the
    /// end read as zero.
    pub fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        let first = self.bit / 8;
        for i in 0..4 {
            if let Some(&b) = self.data.get(first + i) {
                v |= (b as u32) << (8 * i);
            }
        }
        (v >> (self.bit % 8)) & ((1u32 << n) - 1)
    }

    pub fn consume(&mut self, n: u32) -> Result<()> {
        if (n as usize) > self.remaining() {
            return truncated();
        }
        self.bit += n as usize;
        Ok(())
    }

    /// Reads `n` (at most 24) bits; the first bit read is the lowest.
    pub fn read(&mut self, n: u32) -> Result<u32> {
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }
}
