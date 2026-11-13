//! RDP 4.0 and RDP 5.0 bulk decompression (MPPC, MS-RDPBCGR 3.1.8.4).
//!
//! The stream is a most-significant-bit-first sequence of literals and
//! <copy-offset, length-of-match> tuples, padded with zero bits to a byte
//! boundary. Every token is at least 8 bits long, so fewer than 8 remaining
//! bits are padding.

use super::bits::MsbBits;
use super::history::History;
use super::{PACKET_AT_FRONT, PACKET_COMPRESSED, PACKET_FLUSHED};
use crate::error::{Result, proto};

/// Which encoding table and history size to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// 8 KB history, offsets up to 8191, lengths up to 8191 (3.1.8.4.1).
    Rdp4,
    /// 64 KB history, offsets up to 65535, lengths up to 65535 (3.1.8.4.2).
    Rdp5,
}

impl Variant {
    pub fn history_size(self) -> usize {
        match self {
            Variant::Rdp4 => 8 * 1024,
            Variant::Rdp5 => 64 * 1024,
        }
    }

    /// Longest length-of-match prefix (count of leading one bits).
    fn max_lom_prefix(self) -> u32 {
        match self {
            Variant::Rdp4 => 11,
            Variant::Rdp5 => 14,
        }
    }
}

/// One MPPC decompression context.
pub struct Mppc {
    variant: Variant,
    history: History,
}

impl Mppc {
    pub fn new(variant: Variant) -> Self {
        Self {
            variant,
            history: History::new(variant.history_size()),
        }
    }

    /// Resets the history as PACKET_FLUSHED does.
    pub fn reset(&mut self) {
        self.history.reset();
    }

    /// Applies `flags` (3.1.8.3: FLUSHED first, then AT_FRONT) and, if
    /// PACKET_COMPRESSED is set, decodes `data` into the history and returns
    /// the new bytes. `None` means the data was not compressed.
    pub fn decompress<'s>(&'s mut self, data: &[u8], flags: u8) -> Result<Option<&'s [u8]>> {
        if flags & PACKET_FLUSHED != 0 {
            self.history.reset();
        }
        if flags & PACKET_AT_FRONT != 0 {
            self.history.rewind();
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(None);
        }
        let start = self.history.pos();
        let mut r = MsbBits::new(data);
        while r.remaining() >= 8 {
            if r.bit()? == 0 {
                // 0 + 7 bits: literal below 0x80
                let lit = r.read(7)?;
                self.history.push(lit as u8)?;
                continue;
            }
            if r.bit()? == 0 {
                // 10 + lower 7 bits: literal 0x80..=0xFF
                let lit = 0x80 | r.read(7)?;
                self.history.push(lit as u8)?;
                continue;
            }
            let offset = self.copy_offset(&mut r)?;
            let length = self.length_of_match(&mut r)?;
            self.history.copy_back(offset as usize, length as usize)?;
        }
        Ok(Some(self.history.since(start)))
    }

    /// The copy-offset after its leading "11" (3.1.8.4.1.2.1, 3.1.8.4.2.2.1).
    fn copy_offset(&self, r: &mut MsbBits) -> Result<u32> {
        Ok(match self.variant {
            Variant::Rdp4 => {
                if r.bit()? == 0 {
                    320 + r.read(13)? // 110
                } else if r.bit()? == 0 {
                    64 + r.read(8)? // 1110
                } else {
                    r.read(6)? // 1111
                }
            }
            Variant::Rdp5 => {
                if r.bit()? == 0 {
                    2368 + r.read(16)? // 110
                } else if r.bit()? == 0 {
                    320 + r.read(11)? // 1110
                } else if r.bit()? == 0 {
                    64 + r.read(8)? // 11110
                } else {
                    r.read(6)? // 11111
                }
            }
        })
    }

    /// Length-of-match (3.1.8.4.1.2.2, 3.1.8.4.2.2.2): `k` one bits and a
    /// zero, then k + 1 bits added to 2^(k+1); a lone zero means 3.
    fn length_of_match(&self, r: &mut MsbBits) -> Result<u32> {
        let mut k = 0;
        while r.bit()? == 1 {
            k += 1;
            if k > self.variant.max_lom_prefix() {
                return proto("MPPC length-of-match prefix too long");
            }
        }
        if k == 0 {
            return Ok(3);
        }
        Ok((1 << (k + 1)) + r.read(k + 1)?)
    }
}
