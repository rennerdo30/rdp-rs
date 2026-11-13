//! RDP 8.0 bulk decompression ("ZGFX") for the graphics pipeline
//! (MS-RDPEGFX 2.2.5, 3.1.9.1).
//!
//! Every server-to-client message on the graphics channel is an
//! RDP_SEGMENTED_DATA structure (2.2.5.1): one segment (SINGLE, 0xE0) or a
//! segment count, the total size and an array of RDP_DATA_SEGMENT (MULTIPART,
//! 0xE1). Each segment is an RDP8_BULK_ENCODED_DATA (2.2.5.3): a header byte
//! (compression type 4 in the low nibble, PACKET_COMPRESSED 0x20) and the
//! data. Compressed data is a Huffman bit stream (3.1.9.1.2.3) of literals and
//! matches into a history of the last 2,500,000 output bytes; the history
//! lives as long as the channel. The last byte of a compressed segment counts
//! the unused bits of the byte before it (3.1.9.1.2.4).
//!
//! Every length and distance is checked: bad input is an error, never a panic.

use crate::error::{Result, proto};

/// RDP_SEGMENTED_DATA descriptor values (2.2.5.1).
pub const SEGMENTED_SINGLE: u8 = 0xE0;
pub const SEGMENTED_MULTIPART: u8 = 0xE1;
/// Compression type in the low nibble of RDP8_BULK_ENCODED_DATA.header.
const COMPRESSION_TYPE_RDP8: u8 = 0x04;
/// RDP8_BULK_ENCODED_DATA.header: the data is a Huffman bit stream.
pub const PACKET_COMPRESSED: u8 = 0x20;
/// History size: the largest match distance is 2,500,000 (3.1.9.1.2.3).
pub const HISTORY_SIZE: usize = 2_500_000;
/// A segment never expands beyond 65,535 bytes (3.1.9.1.2.3).
pub const MAX_SEGMENT_OUTPUT: usize = 65_535;
/// Upper bound on a whole message, to bound memory (graphics PDUs carry at
/// most one uncompressed 32 bpp surface update; 64 MiB covers 4096x4096).
pub const MAX_MESSAGE: usize = 64 << 20;

/// Match tokens: (prefix, prefix bits, value bits, base distance).
const MATCH_TOKENS: [(u32, u32, u32, u32); 11] = [
    (0b10001, 5, 5, 0),
    (0b10010, 5, 7, 32),
    (0b10011, 5, 9, 160),
    (0b10100, 5, 10, 672),
    (0b10101, 5, 12, 1696),
    (0b101100, 6, 14, 5792),
    (0b101101, 6, 15, 22176),
    (0b1011100, 7, 18, 54944),
    (0b1011101, 7, 20, 317088),
    (0b10111100, 8, 20, 1365664),
    (0b10111101, 8, 21, 2414240),
];

/// Short literal tokens: (prefix, prefix bits, literal).
const LITERAL_TOKENS: [(u32, u32, u8); 25] = [
    (0b11000, 5, 0x00),
    (0b11001, 5, 0x01),
    (0b110100, 6, 0x02),
    (0b110101, 6, 0x03),
    (0b110110, 6, 0xFF),
    (0b1101110, 7, 0x04),
    (0b1101111, 7, 0x05),
    (0b1110000, 7, 0x06),
    (0b1110001, 7, 0x07),
    (0b1110010, 7, 0x08),
    (0b1110011, 7, 0x09),
    (0b1110100, 7, 0x0A),
    (0b1110101, 7, 0x0B),
    (0b1110110, 7, 0x3A),
    (0b1110111, 7, 0x3B),
    (0b1111000, 7, 0x3C),
    (0b1111001, 7, 0x3D),
    (0b1111010, 7, 0x3E),
    (0b1111011, 7, 0x3F),
    (0b1111100, 7, 0x40),
    (0b1111101, 7, 0x80),
    (0b11111100, 8, 0x0C),
    (0b11111101, 8, 0x38),
    (0b11111110, 8, 0x39),
    (0b11111111, 8, 0x66),
];

/// MSB-first bit reader over a compressed segment, bounded by the bit count
/// from the trailer.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32> {
        if self.pos >= self.end {
            return proto("zgfx: bit stream overrun");
        }
        let b = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1;
        self.pos += 1;
        Ok(b as u32)
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Ok(v)
    }
}

/// Decompressor state: the history ring, kept for the life of the channel.
pub struct Zgfx {
    history: Vec<u8>,
    /// Next write offset in `history`.
    cursor: usize,
    /// Bytes ever written, capped at `HISTORY_SIZE` (valid distances).
    filled: usize,
}

impl Default for Zgfx {
    fn default() -> Self {
        Self::new()
    }
}

impl Zgfx {
    pub fn new() -> Self {
        Zgfx {
            history: Vec::new(),
            cursor: 0,
            filled: 0,
        }
    }

    fn push(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.history.is_empty() {
            self.history = vec![0; HISTORY_SIZE];
        }
        self.history[self.cursor] = b;
        self.cursor = (self.cursor + 1) % HISTORY_SIZE;
        self.filled = (self.filled + 1).min(HISTORY_SIZE);
        out.push(b);
    }

    /// Decodes one RDP_SEGMENTED_DATA structure into the original bytes.
    pub fn decompress(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let Some((&descriptor, rest)) = msg.split_first() else {
            return proto("zgfx: empty message");
        };
        let mut out = Vec::new();
        match descriptor {
            SEGMENTED_SINGLE => self.segment(rest, &mut out)?,
            SEGMENTED_MULTIPART => {
                let mut r = crate::cursor::Reader::new(rest);
                let count = r.u16()?;
                let total = r.u32()? as usize;
                if total > MAX_MESSAGE {
                    return proto(format!("zgfx: message of {total} bytes too large"));
                }
                out.reserve(total);
                for _ in 0..count {
                    let size = r.u32()? as usize;
                    let seg = r.bytes(size)?;
                    self.segment(seg, &mut out)?;
                    if out.len() > total {
                        return proto("zgfx: segments exceed uncompressedSize");
                    }
                }
                if out.len() != total {
                    return proto(format!(
                        "zgfx: {} bytes decoded, uncompressedSize {total}",
                        out.len()
                    ));
                }
            }
            d => return proto(format!("zgfx: descriptor {d:#04x}")),
        }
        Ok(out)
    }

    /// One RDP8_BULK_ENCODED_DATA segment (2.2.5.3).
    fn segment(&mut self, seg: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let Some((&header, data)) = seg.split_first() else {
            return proto("zgfx: empty segment");
        };
        if header & 0x0F != COMPRESSION_TYPE_RDP8 {
            return proto(format!("zgfx: compression type {:#x}", header & 0x0F));
        }
        if header & PACKET_COMPRESSED == 0 {
            if data.len() > MAX_SEGMENT_OUTPUT {
                return proto("zgfx: raw segment over 65535 bytes");
            }
            for &b in data {
                self.push(b, out);
            }
            return Ok(());
        }
        let Some((&trailer, stream)) = data.split_last() else {
            return proto("zgfx: compressed segment without trailer");
        };
        let unused = (trailer & 0x07) as usize;
        let Some(end) = (stream.len() * 8).checked_sub(unused) else {
            return proto("zgfx: trailer larger than the bit stream");
        };
        let start = out.len();
        let mut bits = Bits {
            data: stream,
            pos: 0,
            end,
        };
        while bits.pos < bits.end {
            self.token(&mut bits, out)?;
            if out.len() - start > MAX_SEGMENT_OUTPUT {
                return proto("zgfx: segment expands beyond 65535 bytes");
            }
        }
        Ok(())
    }

    /// Decodes one token (3.1.9.1.2.3).
    fn token(&mut self, bits: &mut Bits, out: &mut Vec<u8>) -> Result<()> {
        if bits.bit()? == 0 {
            let b = bits.bits(8)? as u8;
            self.push(b, out);
            return Ok(());
        }
        let mut code = 1u32;
        for len in 2..=8u32 {
            code = (code << 1) | bits.bit()?;
            if len < 5 {
                continue;
            }
            if let Some(&(_, _, lit)) = LITERAL_TOKENS
                .iter()
                .find(|&&(p, l, _)| l == len && p == code)
            {
                self.push(lit, out);
                return Ok(());
            }
            if let Some(&(p, _, value_bits, base)) = MATCH_TOKENS
                .iter()
                .find(|&&(p, l, _, _)| l == len && p == code)
            {
                let distance = (base + bits.bits(value_bits)?) as usize;
                if distance == 0 && p == 0b10001 {
                    return self.unencoded(bits, out);
                }
                return self.copy_match(distance, bits, out);
            }
        }
        proto(format!("zgfx: reserved token {code:#b}"))
    }

    /// Distance 0: a 15-bit count, then that many bytes on a byte boundary.
    fn unencoded(&mut self, bits: &mut Bits, out: &mut Vec<u8>) -> Result<()> {
        let count = bits.bits(15)? as usize;
        let byte = bits.pos.div_ceil(8);
        let after = (byte + count) * 8;
        if after > bits.end {
            return proto("zgfx: unencoded run past the segment end");
        }
        for i in 0..count {
            let b = bits.data[byte + i];
            self.push(b, out);
        }
        bits.pos = after;
        Ok(())
    }

    fn copy_match(&mut self, distance: usize, bits: &mut Bits, out: &mut Vec<u8>) -> Result<()> {
        let mut ones = 0u32;
        while bits.bit()? == 1 {
            ones += 1;
            if ones > 14 {
                return proto("zgfx: match length prefix too long");
            }
        }
        let length = if ones == 0 {
            3
        } else {
            (1usize << (ones + 1)) + bits.bits(ones + 1)? as usize
        };
        if distance == 0 || distance > self.filled {
            return proto(format!("zgfx: match distance {distance} outside history"));
        }
        if length > MAX_SEGMENT_OUTPUT {
            return proto("zgfx: match longer than a segment");
        }
        // Byte by byte: an overlapping match replicates (Example 3, 4.2.1.1.3).
        for _ in 0..length {
            let from = (self.cursor + HISTORY_SIZE - distance) % HISTORY_SIZE;
            let b = self.history[from];
            self.push(b, out);
        }
        Ok(())
    }
}
