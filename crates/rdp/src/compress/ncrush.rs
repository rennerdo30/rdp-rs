//! RDP 6.0 bulk decompression (NCRUSH, MS-RDPEGDI 3.1.8.1).
//!
//! Literals, copy-offsets, four cached offsets and the End-of-Stream marker
//! share one Huffman alphabet of 293 codes (LiteralOrEosOrCopyOffset); each
//! copy is followed by a length-of-match from a second alphabet of 32 codes.
//! Both codebooks are canonical Huffman codes built from the bit-length
//! tables (3.1.8.1.4.1, 3.1.8.1.4.2) and stored bit-reversed, because the
//! stream is read least significant bit first.

use std::sync::OnceLock;

use super::bits::LsbBits;
use super::history::History;
use super::{PACKET_AT_FRONT, PACKET_COMPRESSED, PACKET_FLUSHED};
use crate::error::{Result, proto};

pub const HISTORY_SIZE: usize = 65_536;
const EOS: u16 = 256;
const FIRST_COPY_OFFSET: u16 = 257;
const FIRST_CACHED_OFFSET: u16 = 289;

/// HuffLengthLEC (Table 1): bit lengths of the 293 LiteralOrEosOrCopyOffset codes.
#[rustfmt::skip]
pub(crate) const HUFF_LENGTH_LEC: [u8; 293] = [
    6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8,
    8, 8, 9, 8, 9, 9, 9, 9, 8, 8, 9, 9, 9, 9, 9, 9,
    8, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 10, 10,
    9, 9, 10, 9, 10, 9, 10, 9, 9, 9, 10, 10, 9, 10, 9, 9,
    8, 9, 9, 9, 9, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10,
    9, 9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10,
    8, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9,
    7, 9, 9, 10, 9, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 13, 10, 10, 10, 10,
    10, 10, 11, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 9, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10,
    8, 9, 9, 10, 9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 8, 7,
    13, 13, 7, 7, 10, 7, 7, 6, 6, 6, 6, 5, 6, 6, 6, 5,
    6, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    8, 5, 6, 7, 7,
];

/// HuffLengthL (Table 4): bit lengths of the 32 LengthOfMatch codes.
#[rustfmt::skip]
pub(crate) const HUFF_LENGTH_LOM: [u8; 32] = [
    4, 2, 3, 4, 3, 4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8,
    7, 8, 8, 9, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
];

/// CopyOffsetBitsLUT and CopyOffsetBaseLUT (Table 3).
#[rustfmt::skip]
pub(crate) const COPY_OFFSET_BITS: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
];
#[rustfmt::skip]
pub(crate) const COPY_OFFSET_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    32769, 49153,
];

/// LoMBitsLUT and LoMBaseLUT (Table 6). The table has 30 rows, so codes 30
/// and 31 of the LengthOfMatch alphabet have no meaning.
#[rustfmt::skip]
pub(crate) const LOM_BITS: [u8; 30] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 6, 6, 8, 8, 14, 14,
];
#[rustfmt::skip]
pub(crate) const LOM_BASE: [u32; 30] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 22, 26, 30,
    34, 42, 50, 58, 66, 82, 98, 114, 130, 194, 258, 514, 2, 2,
];

/// Canonical Huffman codes ([SAYOOD] 4.2.4) for `lengths`, bit-reversed so
/// the first bit on the wire is the lowest bit of the returned code.
pub(crate) fn canonical_codes(lengths: &[u8]) -> Vec<u16> {
    let mut codes = vec![0u16; lengths.len()];
    let mut code: u32 = 0;
    for len in 1..=16u8 {
        for (i, &l) in lengths.iter().enumerate() {
            if l == len {
                codes[i] = ((code as u16).reverse_bits()) >> (16 - len);
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

/// A decode table indexed by the next `bits` stream bits: each entry is
/// `symbol << 4 | length`, or 0 for a bit pattern no code starts with.
struct Table {
    bits: u32,
    entries: Vec<u16>,
}

impl Table {
    fn new(lengths: &[u8]) -> Self {
        let bits = *lengths.iter().max().unwrap_or(&1) as u32;
        let mut entries = vec![0u16; 1 << bits];
        for (sym, (&len, code)) in lengths.iter().zip(canonical_codes(lengths)).enumerate() {
            let step = 1usize << len;
            let mut i = code as usize;
            while i < entries.len() {
                entries[i] = ((sym as u16) << 4) | len as u16;
                i += step;
            }
        }
        Self { bits, entries }
    }

    fn decode(&self, r: &mut LsbBits) -> Result<u16> {
        let e = self.entries[r.peek(self.bits) as usize];
        if e == 0 {
            return proto("RDP 6.0 stream has an undefined Huffman code");
        }
        r.consume((e & 0xF) as u32)?;
        Ok(e >> 4)
    }
}

fn tables() -> &'static (Table, Table) {
    static T: OnceLock<(Table, Table)> = OnceLock::new();
    T.get_or_init(|| (Table::new(&HUFF_LENGTH_LEC), Table::new(&HUFF_LENGTH_LOM)))
}

/// One RDP 6.0 decompression context: history plus the OffsetCache (3.1.8.1.1).
pub struct Ncrush {
    history: History,
    cache: [u32; 4],
}

impl Default for Ncrush {
    fn default() -> Self {
        Self::new()
    }
}

impl Ncrush {
    pub fn new() -> Self {
        Self {
            history: History::new(HISTORY_SIZE),
            cache: [0; 4],
        }
    }

    /// Applies `flags` and decodes `data` if PACKET_COMPRESSED is set.
    /// PACKET_FLUSHED clears the history and the OffsetCache; PACKET_AT_FRONT
    /// slides the history back by half (3.1.8.1.3): the 32 KB before
    /// HistoryOffset move to the start and decoding continues at 32768.
    pub fn decompress<'s>(&'s mut self, data: &[u8], flags: u8) -> Result<Option<&'s [u8]>> {
        if flags & PACKET_FLUSHED != 0 {
            self.history.reset();
            self.cache = [0; 4];
        }
        if flags & PACKET_AT_FRONT != 0 {
            self.history.slide(HISTORY_SIZE / 2)?;
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(None);
        }
        let (lec, lom) = tables();
        let start = self.history.pos();
        let mut r = LsbBits::new(data);
        loop {
            let sym = lec.decode(&mut r)?;
            let offset = match sym {
                0..=255 => {
                    self.history.push(sym as u8)?;
                    continue;
                }
                EOS => break,
                FIRST_COPY_OFFSET..FIRST_CACHED_OFFSET => {
                    // 3.1.8.1.4.4.1, then "Store CopyOffset in OffsetCache".
                    let i = (sym - FIRST_COPY_OFFSET) as usize;
                    let extra = r.read(COPY_OFFSET_BITS[i] as u32)?;
                    let offset = COPY_OFFSET_BASE[i] + extra - 1;
                    self.cache.copy_within(0..3, 1);
                    self.cache[0] = offset;
                    offset
                }
                _ => {
                    // A cached offset moves to the head of the cache.
                    let i = (sym - FIRST_CACHED_OFFSET) as usize;
                    self.cache.swap(0, i);
                    self.cache[0]
                }
            };
            let i = lom.decode(&mut r)? as usize;
            if i >= LOM_BASE.len() {
                return proto(format!("RDP 6.0 length-of-match code {i} is undefined"));
            }
            let length = LOM_BASE[i] + r.read(LOM_BITS[i] as u32)?;
            self.history.copy_back(offset as usize, length as usize)?;
        }
        Ok(Some(self.history.since(start)))
    }
}
