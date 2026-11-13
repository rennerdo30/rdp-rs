//! RDP 6.1 bulk decompression (XCRUSH, MS-RDPEGDI 3.1.8.2 and 2.2.2.4.1).
//!
//! A packet is an RDP61_COMPRESSED_DATA structure: Level1ComprFlags,
//! Level2ComprFlags, then the level-1 payload. With L1_INNER_COMPRESSION the
//! payload first goes through an RDP 5.0 decompressor with its own 64 KB
//! history (level 2). The level-1 payload is either raw literals
//! (L1_NO_COMPRESSION) or MatchCount, RDP61_MATCH_DETAILS and literals
//! (L1_COMPRESSED); matches copy from anywhere in the 2,000,000-byte level-1
//! history.

use super::history::History;
use super::mppc::{Mppc, Variant};
use super::{PACKET_COMPRESSED, PACKET_FLUSHED};
use crate::cursor::Reader;
use crate::error::{Result, proto};

pub const HISTORY_SIZE: usize = 2_000_000;
/// Upper bound on one packet's output. A compliant compressor sends blocks
/// below 16,383 bytes (3.1.8.2.1); 64 KB leaves room without trusting it.
pub const MAX_OUTPUT: usize = 65_536;

pub const L1_COMPRESSED: u8 = 0x01;
pub const L1_NO_COMPRESSION: u8 = 0x02;
pub const L1_PACKET_AT_FRONT: u8 = 0x04;
pub const L1_INNER_COMPRESSION: u8 = 0x10;

/// One RDP 6.1 decompression context: level-1 history plus the chained
/// level-2 RDP 5.0 context.
pub struct Xcrush {
    l1: History,
    l2: Mppc,
}

impl Default for Xcrush {
    fn default() -> Self {
        Self::new()
    }
}

impl Xcrush {
    pub fn new() -> Self {
        Self {
            l1: History::new(HISTORY_SIZE),
            l2: Mppc::new(Variant::Rdp5),
        }
    }

    /// Decodes one RDP61_COMPRESSED_DATA when PACKET_COMPRESSED is set in the
    /// outer `flags`; PACKET_FLUSHED there resets both levels.
    pub fn decompress<'s>(&'s mut self, data: &'s [u8], flags: u8) -> Result<Option<&'s [u8]>> {
        let Xcrush { l1, l2 } = self;
        if flags & PACKET_FLUSHED != 0 {
            l1.reset();
            l2.reset();
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(None);
        }
        let mut r = Reader::new(data);
        let l1_flags = r.u8()?;
        let l2_flags = r.u8()?;
        let mut payload = r.rest();
        if l1_flags & L1_INNER_COMPRESSION != 0
            && let Some(inner) = l2.decompress(payload, l2_flags)?
        {
            payload = inner;
        }
        if l1_flags & L1_PACKET_AT_FRONT != 0 {
            // "MUST be reinitialized (by filling it with zeros)" (2.2.2.4.1).
            l1.reset();
        }
        let start = l1.pos();
        match l1_flags & (L1_COMPRESSED | L1_NO_COMPRESSION) {
            L1_NO_COMPRESSION => l1.extend(payload)?,
            L1_COMPRESSED => expand(l1, payload)?,
            0 => return Ok(Some(payload)),
            _ => return proto("RDP 6.1 packet is both compressed and not compressed"),
        }
        let out = l1.since(start);
        if out.len() > MAX_OUTPUT {
            return proto(format!("RDP 6.1 packet expands to {} bytes", out.len()));
        }
        Ok(Some(out))
    }
}

/// Interleaves the literals with the matches by MatchOutputOffset (3.1.8.2.3.1).
fn expand(l1: &mut History, payload: &[u8]) -> Result<()> {
    let mut r = Reader::new(payload);
    let count = r.u16()? as usize;
    let details = r.bytes(count * 8)?;
    let literals = r.rest();
    let mut lit = 0usize;
    let mut out = 0usize;
    for d in details.as_chunks::<8>().0 {
        let mut m = Reader::new(d);
        let length = m.u16()? as usize;
        let output_offset = m.u16()? as usize;
        let history_offset = m.u32()? as usize;
        let Some(gap) = output_offset.checked_sub(out) else {
            return proto("RDP 6.1 matches out of order");
        };
        let Some(raw) = literals.get(lit..lit + gap) else {
            return proto("RDP 6.1 literals truncated");
        };
        l1.extend(raw)?;
        lit += gap;
        l1.copy_from(history_offset, length)?;
        out = output_offset + length;
        if out > MAX_OUTPUT {
            return proto("RDP 6.1 output too large");
        }
    }
    l1.extend(&literals[lit..])
}
