//! Bulk decompression tests: spec vectors (MS-RDPBCGR 3.1.8, MS-RDPEGDI
//! 3.1.8), round trips through small test-only compressors written from the
//! same spec sections, flag handling, and random or truncated input.

use std::collections::HashMap;

use super::mppc::{Mppc, Variant};
use super::ncrush::{self, Ncrush};
use super::xcrush::{self, Xcrush};
use super::*;

// ---------------------------------------------------------------- helpers

/// Tiny deterministic PRNG (xorshift64*), so the tests need no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Text-like data with many repeats at short and long distances.
fn sample(rng: &mut Rng, len: usize) -> Vec<u8> {
    let words: [&[u8]; 8] = [
        b"the ",
        b"bell ",
        b"tolls ",
        b"for ",
        b"thee",
        b"\xff\xfe\x80",
        b"\0\0\0\0",
        b"!",
    ];
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        match rng.below(10) {
            0 => {
                let n = 1 + rng.below(6);
                v.extend(rng.bytes(n));
            }
            1 if v.len() > 40 => {
                let start = rng.below(v.len() - 20);
                let n = 3 + rng.below(17);
                v.extend_from_within(start..start + n);
            }
            _ => v.extend_from_slice(words[rng.below(words.len())]),
        }
    }
    v.truncate(len);
    v
}

/// Bits written most significant first, as text "1111 000011" (spaces ignored).
fn msb_bits(text: &str) -> Vec<u8> {
    let mut w = MsbWriter::default();
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        w.put(u32::from(c == '1'), 1);
    }
    w.finish()
}

#[derive(Default)]
struct MsbWriter {
    out: Vec<u8>,
    acc: u8,
    n: u32,
}

impl MsbWriter {
    fn put(&mut self, v: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1) as u8;
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc << (8 - self.n));
        }
        self.out
    }
}

#[derive(Default)]
struct LsbWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl LsbWriter {
    fn put(&mut self, v: u32, bits: u32) {
        self.acc |= u64::from(v & ((1u32 << bits) - 1)) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// Longest earlier match for `buf[i..end]` among recent positions with the
/// same three-byte prefix: (distance, length).
fn find_match(
    buf: &[u8],
    heads: &mut HashMap<[u8; 3], Vec<usize>>,
    i: usize,
    end: usize,
    max_dist: usize,
    max_len: usize,
) -> Option<(usize, usize)> {
    if i + 3 > end {
        return None;
    }
    let key = [buf[i], buf[i + 1], buf[i + 2]];
    let mut best: Option<(usize, usize)> = None;
    if let Some(cands) = heads.get(&key) {
        for &c in cands.iter().rev() {
            if i - c > max_dist {
                continue;
            }
            let mut n = 0;
            while i + n < end && n < max_len && buf[c + n] == buf[i + n] {
                n += 1;
            }
            if best.is_none_or(|(_, l)| n > l) {
                best = Some((i - c, n));
            }
        }
    }
    let list = heads.entry(key).or_default();
    list.push(i);
    if list.len() > 16 {
        list.remove(0);
    }
    best
}

// ------------------------------------------------- test-only compressors

/// MPPC sender (MS-RDPBCGR 3.1.8.1, 3.1.8.2, 3.1.8.4).
struct MppcEnc {
    variant: Variant,
    buf: Vec<u8>,
    pos: usize,
    first: bool,
    heads: HashMap<[u8; 3], Vec<usize>>,
}

impl MppcEnc {
    fn new(variant: Variant) -> Self {
        Self {
            variant,
            buf: vec![0; variant.history_size()],
            pos: 0,
            first: true,
            heads: HashMap::new(),
        }
    }

    fn compress(&mut self, data: &[u8]) -> (Vec<u8>, u8) {
        let ty = match self.variant {
            Variant::Rdp4 => PACKET_COMPR_TYPE_8K,
            Variant::Rdp5 => PACKET_COMPR_TYPE_64K,
        };
        let mut flags = PACKET_COMPRESSED | ty;
        if self.first {
            flags |= PACKET_FLUSHED;
            self.first = false;
        }
        if self.pos + data.len() > self.buf.len() {
            self.pos = 0;
            self.heads.clear();
            flags |= PACKET_AT_FRONT;
        }
        let start = self.pos;
        let end = start + data.len();
        self.buf[start..end].copy_from_slice(data);
        let max_len = match self.variant {
            Variant::Rdp4 => 8191,
            Variant::Rdp5 => 65535,
        };
        let mut w = MsbWriter::default();
        let mut i = start;
        while i < end {
            let buf = &self.buf;
            match find_match(buf, &mut self.heads, i, end, max_len, max_len) {
                Some((dist, len)) if len >= 3 => {
                    self.put_offset(&mut w, dist as u32);
                    put_mppc_lom(&mut w, len as u32);
                    for j in i + 1..(i + len).min(end - 2) {
                        let key = [buf[j], buf[j + 1], buf[j + 2]];
                        self.heads.entry(key).or_default().push(j);
                    }
                    i += len;
                }
                _ => {
                    let b = buf[i] as u32;
                    if b < 0x80 {
                        w.put(b, 8);
                    } else {
                        w.put(0b10, 2);
                        w.put(b & 0x7F, 7);
                    }
                    i += 1;
                }
            }
        }
        self.pos = end;
        (w.finish(), flags)
    }

    fn put_offset(&self, w: &mut MsbWriter, d: u32) {
        match self.variant {
            Variant::Rdp4 => match d {
                0..=63 => w.put((0b1111 << 6) | d, 10),
                64..=319 => w.put((0b1110 << 8) | (d - 64), 12),
                _ => w.put((0b110 << 13) | (d - 320), 16),
            },
            Variant::Rdp5 => match d {
                0..=63 => w.put((0b11111 << 6) | d, 11),
                64..=319 => w.put((0b11110 << 8) | (d - 64), 13),
                320..=2367 => w.put((0b1110 << 11) | (d - 320), 15),
                _ => w.put((0b110 << 16) | (d - 2368), 19),
            },
        }
    }
}

fn put_mppc_lom(w: &mut MsbWriter, lom: u32) {
    if lom == 3 {
        w.put(0, 1);
        return;
    }
    // 2^m <= lom < 2^(m+1): m - 1 one bits, a zero, then the lower m bits.
    let m = 31 - lom.leading_zeros();
    w.put(((1 << (m - 1)) - 1) << 1, m);
    w.put(lom & ((1 << m) - 1), m);
}

/// RDP 6.0 sender (MS-RDPEGDI 3.1.8.1.1, 3.1.8.1.4.3).
struct NcrushEnc {
    buf: Vec<u8>,
    pos: usize,
    first: bool,
    cache: [u32; 4],
    heads: HashMap<[u8; 3], Vec<usize>>,
    lec: Vec<u16>,
    lom: Vec<u16>,
}

impl NcrushEnc {
    fn new() -> Self {
        Self {
            buf: vec![0; ncrush::HISTORY_SIZE],
            pos: 0,
            first: true,
            cache: [0; 4],
            heads: HashMap::new(),
            lec: ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LEC),
            lom: ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LOM),
        }
    }

    fn sym(&self, w: &mut LsbWriter, s: usize) {
        w.put(self.lec[s] as u32, ncrush::HUFF_LENGTH_LEC[s] as u32);
    }

    fn compress(&mut self, data: &[u8]) -> (Vec<u8>, u8) {
        let mut flags = PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP6;
        if self.first {
            flags |= PACKET_FLUSHED;
            self.first = false;
        }
        if self.pos + data.len() > self.buf.len() {
            let half = self.buf.len() / 2;
            self.buf.copy_within(self.pos - half..self.pos, 0);
            self.pos = half;
            self.heads.clear();
            for j in 0..half - 2 {
                let key = [self.buf[j], self.buf[j + 1], self.buf[j + 2]];
                self.heads.entry(key).or_default().push(j);
            }
            flags |= PACKET_AT_FRONT;
        }
        let start = self.pos;
        let end = start + data.len();
        self.buf[start..end].copy_from_slice(data);
        let mut w = LsbWriter::default();
        let mut i = start;
        while i < end {
            let found = find_match(&self.buf, &mut self.heads, i, end, 65535, 16385);
            match found {
                Some((dist, len)) if len >= 2 => {
                    let d = dist as u32;
                    if let Some(c) = self.cache.iter().position(|&x| x == d) {
                        self.cache.swap(0, c);
                        self.sym(&mut w, 289 + c);
                    } else {
                        self.cache.copy_within(0..3, 1);
                        self.cache[0] = d;
                        let k = (0..32)
                            .rev()
                            .find(|&k| ncrush::COPY_OFFSET_BASE[k] <= d + 1)
                            .unwrap();
                        self.sym(&mut w, 257 + k);
                        w.put(
                            d + 1 - ncrush::COPY_OFFSET_BASE[k],
                            ncrush::COPY_OFFSET_BITS[k] as u32,
                        );
                    }
                    let l = len as u32;
                    let k = if l > 769 {
                        28
                    } else {
                        (0..28).rev().find(|&k| ncrush::LOM_BASE[k] <= l).unwrap()
                    };
                    w.put(self.lom[k] as u32, ncrush::HUFF_LENGTH_LOM[k] as u32);
                    w.put(l - ncrush::LOM_BASE[k], ncrush::LOM_BITS[k] as u32);
                    i += len;
                }
                _ => {
                    self.sym(&mut w, self.buf[i] as usize);
                    i += 1;
                }
            }
        }
        self.sym(&mut w, 256);
        self.pos = end;
        (w.finish(), flags)
    }
}

// ------------------------------------------------------------ MPPC tests

/// MS-RDPBCGR 3.1.8.2: "for.whom.the.bell.tolls,<16,15>.<40,4><19,3>e!",
/// encoded by hand with the RDP 4.0 tables of 3.1.8.4.1.
#[test]
fn rdp4_spec_example_decodes() {
    let mut bits = String::new();
    for &b in b"for.whom.the.bell.tolls," {
        bits += &format!("0{:07b} ", b);
    }
    bits += "1111 010000 110 111 "; // <16,15>
    bits += &format!("0{:07b} ", b'.');
    bits += "1111 101000 10 00 "; // <40,4>
    bits += "1111 010011 0 "; // <19,3>
    bits += &format!("0{:07b} 0{:07b}", b'e', b'!');
    let mut m = Mppc::new(Variant::Rdp4);
    let out = m
        .decompress(&msb_bits(&bits), PACKET_COMPRESSED)
        .unwrap()
        .unwrap();
    assert_eq!(out, b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!");
}

/// The same tuples with the RDP 5.0 offset prefixes (3.1.8.4.2.2.1).
#[test]
fn rdp5_spec_example_decodes() {
    let mut bits = String::new();
    for &b in b"for.whom.the.bell.tolls," {
        bits += &format!("0{:07b} ", b);
    }
    bits += "11111 010000 110 111 ";
    bits += &format!("0{:07b} ", b'.');
    bits += "11111 101000 10 00 11111 010011 0 ";
    bits += &format!("0{:07b} 0{:07b}", b'e', b'!');
    let mut m = Mppc::new(Variant::Rdp5);
    let out = m
        .decompress(&msb_bits(&bits), PACKET_COMPRESSED | 1)
        .unwrap()
        .unwrap();
    assert_eq!(out, b"for.whom.the.bell.tolls,.the.bell.tolls.for.thee!");
}

/// The encoding examples of 3.1.8.4.1: literal 0xE7, copy-offsets 3, 128 and
/// 1024, lengths 15, 120 and 4097, plus the replicating copy "Xcd<2,4>YZ".
#[test]
fn rdp4_spec_encodings() {
    let mut m = Mppc::new(Variant::Rdp4);
    let mut bits = String::new();
    let mut want = Vec::new();
    for i in 0..1100u32 {
        let b = (i * 7 % 128) as u8;
        bits += &format!("0{b:07b}");
        want.push(b);
    }
    bits += "101100111"; // 0xE7
    want.push(0xE7);
    // offset 3, L-o-M 15
    bits += "1111 000011 110 111";
    for _ in 0..15 {
        want.push(want[want.len() - 3]);
    }
    // offset 128, L-o-M 120
    bits += "1110 01000000 111110 111000";
    for _ in 0..120 {
        want.push(want[want.len() - 128]);
    }
    // offset 1024, L-o-M 4097 (overlapping, so a replicating copy)
    bits += "110 0001011000000 111111111110 000000000001";
    for _ in 0..4097 {
        want.push(want[want.len() - 1024]);
    }
    let out = m
        .decompress(&msb_bits(&bits), PACKET_COMPRESSED)
        .unwrap()
        .unwrap();
    assert_eq!(out, &want[..]);

    // 3.1.8.2: Xcd<2,4>YZ -> XcdcdcdYZ
    let bits = format!(
        "0{:07b} 0{:07b} 0{:07b} 1111 000010 10 00 0{:07b} 0{:07b}",
        b'X', b'c', b'd', b'Y', b'Z'
    );
    let out = m
        .decompress(&msb_bits(&bits), PACKET_COMPRESSED)
        .unwrap()
        .unwrap();
    assert_eq!(out, b"XcdcdcdYZ");
}

#[test]
fn mppc_round_trips_across_packets() {
    for variant in [Variant::Rdp4, Variant::Rdp5] {
        let mut rng = Rng(0x1234_5678 + variant as u64);
        let mut enc = MppcEnc::new(variant);
        let mut dec = Decompressor::new(Compression::Rdp5);
        let mut saw_front = false;
        let mut saw_copy = false;
        for _ in 0..40 {
            let n = 1 + rng.below(4000);
            let data = sample(&mut rng, n);
            let (comp, flags) = enc.compress(&data);
            saw_front |= flags & PACKET_AT_FRONT != 0;
            saw_copy |= comp.len() < data.len();
            let out = dec.decompress(&comp, flags).unwrap();
            assert_eq!(&out[..], &data[..], "{variant:?}");
        }
        assert!(saw_front && saw_copy, "{variant:?}: history never wrapped");
    }
}

#[test]
fn mppc_long_offsets_and_lengths() {
    // A 40 KB block repeated: offsets above 2368 and lengths above 8191.
    let mut rng = Rng(77);
    let block = rng.bytes(20_000);
    let mut data = block.clone();
    data.extend_from_slice(&block);
    data.extend_from_slice(&block[..9_000]);
    let mut enc = MppcEnc::new(Variant::Rdp5);
    let (comp, flags) = enc.compress(&data);
    assert!(comp.len() < 30_000);
    let mut m = Mppc::new(Variant::Rdp5);
    assert_eq!(m.decompress(&comp, flags).unwrap().unwrap(), &data[..]);
}

#[test]
fn mppc_flush_and_at_front() {
    let mut m = Mppc::new(Variant::Rdp4);
    let abc = msb_bits(&format!("0{:07b} 0{:07b} 0{:07b}", b'a', b'b', b'c'));
    m.decompress(&abc, PACKET_COMPRESSED).unwrap();
    // <3,3> after the first packet repeats "abc": the history persists.
    let copy = msb_bits("1111 000011 0");
    assert_eq!(
        m.decompress(&copy, PACKET_COMPRESSED).unwrap().unwrap(),
        b"abc"
    );
    // AT_FRONT: decoding restarts at offset 0, so offset 3 reaches nothing.
    assert!(
        m.decompress(&copy, PACKET_COMPRESSED | PACKET_AT_FRONT)
            .is_err()
    );
    m.decompress(&abc, PACKET_COMPRESSED | PACKET_AT_FRONT)
        .unwrap();
    assert_eq!(
        m.decompress(&copy, PACKET_COMPRESSED).unwrap().unwrap(),
        b"abc"
    );
    // An uncompressed packet is passed through and leaves the history alone.
    assert!(m.decompress(b"raw", 0).unwrap().is_none());
    assert_eq!(
        m.decompress(&copy, PACKET_COMPRESSED).unwrap().unwrap(),
        b"abc"
    );
    // FLUSHED alone (no data) resets HistoryOffset to 0.
    assert!(m.decompress(&[], PACKET_FLUSHED).unwrap().is_none());
    assert!(m.decompress(&copy, PACKET_COMPRESSED).is_err());
    // FLUSHED is processed before the data of the same packet.
    let both = msb_bits(&format!(
        "0{:07b} 0{:07b} 0{:07b} 1111 000011 0",
        b'x', b'y', b'z'
    ));
    let out = m
        .decompress(&both, PACKET_COMPRESSED | PACKET_FLUSHED)
        .unwrap();
    assert_eq!(out.unwrap(), b"xyzxyz");
}

#[test]
fn mppc_output_is_bounded_by_the_history() {
    let mut m = Mppc::new(Variant::Rdp4);
    // literal, then <1, 4097> twice: 8195 bytes > 8 KB.
    let bits =
        "0 1000001 1111 000001 111111111110 000000000001 1111 000001 111111111110 000000000001";
    assert!(m.decompress(&msb_bits(bits), PACKET_COMPRESSED).is_err());
    // RDP 4.0 has no 13-bit length prefix.
    let bits = "0 1000001 1111 000001 1111111111110 0000000000001";
    assert!(
        m.decompress(&msb_bits(bits), PACKET_COMPRESSED | PACKET_FLUSHED)
            .is_err()
    );
}

// ----------------------------------------------------------- NCRUSH tests

/// HuffCodeLEC (MS-RDPEGDI Table 2) and HuffCodeL (Table 5), as printed.
#[rustfmt::skip]
const SPEC_HUFF_CODE_LEC: [u16; 293] = [
    0x0004, 0x0024, 0x0014, 0x0011, 0x0051, 0x0031, 0x0071, 0x0009, 0x0049, 0x0029, 0x0069, 0x0015, 0x0095, 0x0055, 0x00d5, 0x0035,
    0x00b5, 0x0075, 0x001d, 0x00f5, 0x011d, 0x009d, 0x019d, 0x005d, 0x000d, 0x008d, 0x015d, 0x00dd, 0x01dd, 0x003d, 0x013d, 0x00bd,
    0x004d, 0x01bd, 0x007d, 0x006b, 0x017d, 0x00fd, 0x01fd, 0x0003, 0x0103, 0x0083, 0x0183, 0x026b, 0x0043, 0x016b, 0x036b, 0x00eb,
    0x0143, 0x00c3, 0x02eb, 0x01c3, 0x01eb, 0x0023, 0x03eb, 0x0123, 0x00a3, 0x01a3, 0x001b, 0x021b, 0x0063, 0x011b, 0x0163, 0x00e3,
    0x00cd, 0x01e3, 0x0013, 0x0113, 0x0093, 0x031b, 0x009b, 0x029b, 0x0193, 0x0053, 0x019b, 0x039b, 0x005b, 0x025b, 0x015b, 0x035b,
    0x0153, 0x00d3, 0x00db, 0x02db, 0x01db, 0x03db, 0x003b, 0x023b, 0x013b, 0x01d3, 0x033b, 0x00bb, 0x02bb, 0x01bb, 0x03bb, 0x007b,
    0x002d, 0x027b, 0x017b, 0x037b, 0x00fb, 0x02fb, 0x01fb, 0x03fb, 0x0007, 0x0207, 0x0107, 0x0307, 0x0087, 0x0287, 0x0187, 0x0387,
    0x0033, 0x0047, 0x0247, 0x0147, 0x0347, 0x00c7, 0x02c7, 0x01c7, 0x0133, 0x03c7, 0x0027, 0x0227, 0x0127, 0x0327, 0x00a7, 0x00b3,
    0x0019, 0x01b3, 0x0073, 0x02a7, 0x0173, 0x01a7, 0x03a7, 0x0067, 0x00f3, 0x0267, 0x0167, 0x0367, 0x00e7, 0x02e7, 0x01e7, 0x03e7,
    0x01f3, 0x0017, 0x0217, 0x0117, 0x0317, 0x0097, 0x0297, 0x0197, 0x0397, 0x0057, 0x0257, 0x0157, 0x0357, 0x00d7, 0x02d7, 0x01d7,
    0x03d7, 0x0037, 0x0237, 0x0137, 0x0337, 0x00b7, 0x02b7, 0x01b7, 0x03b7, 0x0077, 0x0277, 0x07ff, 0x0177, 0x0377, 0x00f7, 0x02f7,
    0x01f7, 0x03f7, 0x03ff, 0x000f, 0x020f, 0x010f, 0x030f, 0x008f, 0x028f, 0x018f, 0x038f, 0x004f, 0x024f, 0x014f, 0x034f, 0x00cf,
    0x000b, 0x02cf, 0x01cf, 0x03cf, 0x002f, 0x022f, 0x010b, 0x012f, 0x032f, 0x00af, 0x02af, 0x01af, 0x008b, 0x03af, 0x006f, 0x026f,
    0x018b, 0x016f, 0x036f, 0x00ef, 0x02ef, 0x01ef, 0x03ef, 0x001f, 0x021f, 0x011f, 0x031f, 0x009f, 0x029f, 0x019f, 0x039f, 0x005f,
    0x004b, 0x025f, 0x015f, 0x035f, 0x00df, 0x02df, 0x01df, 0x03df, 0x003f, 0x023f, 0x013f, 0x033f, 0x00bf, 0x02bf, 0x014b, 0x01bf,
    0x00ad, 0x00cb, 0x01cb, 0x03bf, 0x002b, 0x007f, 0x027f, 0x017f, 0x012b, 0x037f, 0x00ff, 0x02ff, 0x00ab, 0x01ab, 0x006d, 0x0059,
    0x17ff, 0x0fff, 0x0039, 0x0079, 0x01ff, 0x0005, 0x0045, 0x0034, 0x000c, 0x002c, 0x001c, 0x0000, 0x003c, 0x0002, 0x0022, 0x0010,
    0x0012, 0x0008, 0x0032, 0x000a, 0x002a, 0x001a, 0x003a, 0x0006, 0x0026, 0x0016, 0x0036, 0x000e, 0x002e, 0x001e, 0x003e, 0x0001,
    0x00ed, 0x0018, 0x0021, 0x0025, 0x0065,
];
#[rustfmt::skip]
const SPEC_HUFF_CODE_LOM: [u16; 32] = [
    0x0001, 0x0000, 0x0002, 0x0009, 0x0006, 0x0005, 0x000d, 0x000b, 0x0003, 0x001b, 0x0007, 0x0017, 0x0037, 0x000f, 0x004f, 0x006f,
    0x002f, 0x00ef, 0x001f, 0x005f, 0x015f, 0x009f, 0x00df, 0x01df, 0x003f, 0x013f, 0x00bf, 0x01bf, 0x007f, 0x017f, 0x00ff, 0x01ff,
];

#[test]
fn ncrush_codebooks_match_the_spec_tables() {
    assert_eq!(
        ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LEC),
        SPEC_HUFF_CODE_LEC
    );
    assert_eq!(
        ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LOM),
        SPEC_HUFF_CODE_LOM
    );
}

/// The decoding examples of 3.1.8.1.4.4.1.1 and 3.1.8.1.4.4.2.1: code 0x0034
/// plus 2 bits gives copy-offset 8 or 11; 0x0001 gives length 2 and 0x01df
/// plus 4 bits of 3 gives 117. Twenty literals precede the copies.
#[test]
fn ncrush_spec_decoding_examples() {
    let mut w = LsbWriter::default();
    let want_lits: Vec<u8> = (b'a'..b'a' + 20).collect();
    for &b in &want_lits {
        w.put(
            SPEC_HUFF_CODE_LEC[b as usize] as u32,
            ncrush::HUFF_LENGTH_LEC[b as usize] as u32,
        );
    }
    w.put(0x0034, 6); // copy-offset index 6
    w.put(0, 2); // -> offset 8
    w.put(0x0001, 4); // length 2
    w.put(0x0034, 6);
    w.put(3, 2); // -> offset 11
    w.put(0x01df, 9);
    w.put(3, 4); // -> length 117
    w.put(0x17ff, 13); // EOS
    let mut want = want_lits.clone();
    for (off, len) in [(8, 2), (11, 117)] {
        for _ in 0..len {
            want.push(want[want.len() - off]);
        }
    }
    let mut n = Ncrush::new();
    let out = n
        .decompress(&w.finish(), PACKET_COMPRESSED | 2)
        .unwrap()
        .unwrap();
    assert_eq!(out, &want[..]);
}

#[test]
fn ncrush_round_trips_with_cache_and_slide() {
    let mut rng = Rng(0xC0FFEE);
    let mut enc = NcrushEnc::new();
    let mut dec = Decompressor::new(Compression::Rdp6);
    let mut saw_front = false;
    for _ in 0..40 {
        let n = 1 + rng.below(6000);
        let data = sample(&mut rng, n);
        let (comp, flags) = enc.compress(&data);
        saw_front |= flags & PACKET_AT_FRONT != 0;
        let out = dec.decompress(&comp, flags).unwrap();
        assert_eq!(&out[..], &data[..]);
    }
    assert!(saw_front, "history never slid");
}

#[test]
fn ncrush_cache_hit_moves_to_front() {
    // literals "ab", explicit offset 2 len 2 (cache [2]), "c", explicit
    // offset 5 len 2 (cache [5,2]), then cached index 1 (offset 2) len 2,
    // then cached index 0 (now offset 2 again) len 2.
    let lec = ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LEC);
    let lom = ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LOM);
    let mut w = LsbWriter::default();
    let sym = |w: &mut LsbWriter, s: usize| w.put(lec[s] as u32, ncrush::HUFF_LENGTH_LEC[s] as u32);
    let len2 = |w: &mut LsbWriter| w.put(lom[0] as u32, 4);
    sym(&mut w, b'a' as usize);
    sym(&mut w, b'b' as usize);
    sym(&mut w, 257 + 2); // base 3, no bits: offset 3 - 1 = 2
    len2(&mut w);
    sym(&mut w, b'c' as usize);
    sym(&mut w, 257 + 4); // base 5, 1 bit 1: offset 5 + 1 - 1 = 5
    w.put(1, 1);
    len2(&mut w);
    sym(&mut w, 289 + 1);
    len2(&mut w);
    sym(&mut w, 289);
    len2(&mut w);
    sym(&mut w, 256);
    let mut n = Ncrush::new();
    let out = n
        .decompress(&w.finish(), PACKET_COMPRESSED | 2)
        .unwrap()
        .unwrap();
    // ab | ab | c | (5 back: "ab") | (cache[1] = 2 back) | (cache[0], now 2)
    assert_eq!(out, b"ababcababab");
}

#[test]
fn ncrush_flush_clears_cache_and_eos_is_required() {
    let lec = ncrush::canonical_codes(&ncrush::HUFF_LENGTH_LEC);
    let mut n = Ncrush::new();
    // Fill the OffsetCache: "ab" and an explicit copy-offset 2.
    let mut enc = NcrushEnc::new();
    let (c, f) = enc.compress(b"ababab");
    assert_eq!(n.decompress(&c, f).unwrap().unwrap(), b"ababab");
    // "ab" then cache[0] for 2 bytes: "abab" with the cache, but right
    // after a flush cache[0] is offset 0, which is rejected.
    let mut w = LsbWriter::default();
    for b in *b"ab" {
        w.put(
            lec[b as usize] as u32,
            ncrush::HUFF_LENGTH_LEC[b as usize] as u32,
        );
    }
    w.put(lec[289] as u32, ncrush::HUFF_LENGTH_LEC[289] as u32);
    w.put(1, 4); // length 2
    w.put(lec[256] as u32, 13);
    let stream = w.finish();
    assert_eq!(
        n.decompress(&stream, PACKET_COMPRESSED | 2)
            .unwrap()
            .unwrap(),
        b"abab"
    );
    assert!(
        n.decompress(&stream, PACKET_COMPRESSED | PACKET_FLUSHED | 2)
            .is_err()
    );
    // A stream that ends without EOS is truncated.
    let mut w = LsbWriter::default();
    w.put(
        lec[b'a' as usize] as u32,
        ncrush::HUFF_LENGTH_LEC[b'a' as usize] as u32,
    );
    assert!(
        n.decompress(&w.finish(), PACKET_COMPRESSED | PACKET_FLUSHED | 2)
            .is_err()
    );
    // The one unused 13-bit pattern (Kraft sum below 1) is rejected, not looped on.
    let free = (0..1u16 << 13).find(|p| {
        (0..293).all(|s| {
            let l = ncrush::HUFF_LENGTH_LEC[s];
            p & ((1 << l) - 1) != lec[s]
        })
    });
    let free = free.expect("one free 13-bit pattern");
    let mut w = LsbWriter::default();
    w.put(free as u32, 13);
    w.put(0, 8);
    assert!(
        n.decompress(&w.finish(), PACKET_COMPRESSED | PACKET_FLUSHED | 2)
            .is_err()
    );
}

#[test]
fn ncrush_at_front_keeps_the_last_32k() {
    let mut enc = NcrushEnc::new();
    let mut dec = Ncrush::new();
    let mut rng = Rng(5);
    let first = rng.bytes(60_000);
    let (c, f) = enc.compress(&first);
    dec.decompress(&c, f).unwrap();
    // Repeats bytes 40000..50000 of the first packet after the slide.
    let second = first[40_000..50_000].to_vec();
    let (c, f) = enc.compress(&second);
    assert_ne!(f & PACKET_AT_FRONT, 0);
    assert!(c.len() < 200, "match through the slid history: {}", c.len());
    assert_eq!(dec.decompress(&c, f).unwrap().unwrap(), &second[..]);
}

// ----------------------------------------------------------- XCRUSH tests

fn rdp61(l1: u8, l2: u8, matches: &[(u16, u16, u32)], literals: &[u8]) -> Vec<u8> {
    let mut v = vec![l1, l2];
    if l1 & xcrush::L1_COMPRESSED != 0 {
        v.extend_from_slice(&(matches.len() as u16).to_le_bytes());
        for &(len, out, hist) in matches {
            v.extend_from_slice(&len.to_le_bytes());
            v.extend_from_slice(&out.to_le_bytes());
            v.extend_from_slice(&hist.to_le_bytes());
        }
    }
    v.extend_from_slice(literals);
    v
}

/// MS-RDPEGDI 3.1.8.2.3.1: Input Data A and B (level-1 only).
#[test]
fn xcrush_spec_example() {
    let mut x = Xcrush::new();
    let a = rdp61(xcrush::L1_NO_COMPRESSION, 0, &[], b"abcdefghij");
    let flags = PACKET_COMPRESSED | 3;
    assert_eq!(x.decompress(&a, flags).unwrap().unwrap(), b"abcdefghij");
    let b = rdp61(
        xcrush::L1_COMPRESSED,
        0,
        &[(9, 5, 3), (4, 14, 0)],
        b"klmnou",
    );
    let out = x.decompress(&b, flags).unwrap().unwrap();
    assert_eq!(out, b"klmnodefghijklabcdu");
}

/// Level-1 output chained through the level-2 RDP 5.0 context.
#[test]
fn xcrush_with_level2_round_trip() {
    let mut rng = Rng(61);
    let mut l2 = MppcEnc::new(Variant::Rdp5);
    let mut dec = Decompressor::new(Compression::Rdp61);
    let mut sent: Vec<u8> = Vec::new();
    for round in 0..20 {
        let n = 200 + rng.below(3000);
        let data = sample(&mut rng, n);
        // Level 1: one 30-byte match into everything sent so far.
        let (packet, expect) = if round > 0 {
            let src = rng.below(sent.len() - 30);
            let expect = [&data[..10], &sent[src..src + 30], &data[10..]].concat();
            let flags = xcrush::L1_COMPRESSED | xcrush::L1_INNER_COMPRESSION;
            (rdp61(flags, 0, &[(30, 10, src as u32)], &data), expect)
        } else {
            let flags = xcrush::L1_NO_COMPRESSION | xcrush::L1_INNER_COMPRESSION;
            (rdp61(flags, 0, &[], &data), data.clone())
        };
        // Level 2 compresses everything after the two flag bytes.
        let (body, l2_flags) = l2.compress(&packet[2..]);
        let mut wire = vec![packet[0], l2_flags];
        wire.extend_from_slice(&body);
        let out = dec.decompress(&wire, PACKET_COMPRESSED | 3).unwrap();
        assert_eq!(&out[..], &expect[..], "round {round}");
        sent.extend_from_slice(&expect);
    }
}

#[test]
fn xcrush_rejects_bad_matches() {
    let flags = PACKET_COMPRESSED | 3;
    let mut x = Xcrush::new();
    // Match past the end of the history.
    let p = rdp61(xcrush::L1_COMPRESSED, 0, &[(10, 0, 1_999_995)], b"");
    assert!(x.decompress(&p, flags).is_err());
    // Matches out of output order.
    let p = rdp61(
        xcrush::L1_COMPRESSED,
        0,
        &[(2, 5, 0), (2, 1, 0)],
        b"abcdefg",
    );
    assert!(x.decompress(&p, flags).is_err());
    // Literals shorter than the gap before a match.
    let p = rdp61(xcrush::L1_COMPRESSED, 0, &[(2, 50, 0)], b"abc");
    assert!(x.decompress(&p, flags).is_err());
    // Both level-1 kinds at once.
    let p = rdp61(
        xcrush::L1_COMPRESSED | xcrush::L1_NO_COMPRESSION,
        0,
        &[],
        b"",
    );
    assert!(x.decompress(&p, flags).is_err());
    // MatchCount larger than the data.
    assert!(x.decompress(&[1, 0, 9, 0, 1, 2], flags).is_err());
}

#[test]
fn xcrush_at_front_resets_level1() {
    let flags = PACKET_COMPRESSED | 3;
    let mut x = Xcrush::new();
    x.decompress(&rdp61(xcrush::L1_NO_COMPRESSION, 0, &[], b"hello"), flags)
        .unwrap();
    let again = rdp61(xcrush::L1_COMPRESSED, 0, &[(5, 0, 0)], b"");
    assert_eq!(x.decompress(&again, flags).unwrap().unwrap(), b"hello");
    let front = rdp61(
        xcrush::L1_COMPRESSED | xcrush::L1_PACKET_AT_FRONT,
        0,
        &[(5, 0, 0)],
        b"",
    );
    assert_eq!(x.decompress(&front, flags).unwrap().unwrap(), &[0u8; 5]);
}

// ------------------------------------------------------ dispatch and fuzz

#[test]
fn decompressor_checks_the_advertised_type() {
    let lit = msb_bits(&format!("0{:07b}", b'a'));
    let mut off = Decompressor::default();
    assert_eq!(&off.decompress(b"plain", 0).unwrap()[..], b"plain");
    assert!(off.decompress(&lit, PACKET_COMPRESSED).is_err());
    let mut d = Decompressor::new(Compression::Rdp5);
    assert_eq!(&d.decompress(&lit, PACKET_COMPRESSED).unwrap()[..], b"a");
    assert_eq!(
        &d.decompress(&lit, PACKET_COMPRESSED | 1).unwrap()[..],
        b"a"
    );
    // Valid RDP 6.0 and 6.1 packets are refused above the advertised type.
    let (rdp6, rdp6_flags) = NcrushEnc::new().compress(b"a");
    let rdp61 = rdp61(xcrush::L1_NO_COMPRESSION, 0, &[], b"a");
    assert!(d.decompress(&rdp6, rdp6_flags).is_err());
    assert!(d.decompress(&rdp61, PACKET_COMPRESSED | 3).is_err());
    let mut d6 = Decompressor::new(Compression::Rdp6);
    assert_eq!(&d6.decompress(&rdp6, rdp6_flags).unwrap()[..], b"a");
    assert!(d6.decompress(&rdp61, PACKET_COMPRESSED | 3).is_err());
    let mut d61 = Decompressor::new(Compression::Rdp61);
    assert_eq!(
        &d61.decompress(&rdp61, PACKET_COMPRESSED | 3).unwrap()[..],
        b"a"
    );
    let mut d = Decompressor::new(Compression::Rdp61);
    assert!(d.decompress(&lit, PACKET_COMPRESSED | 4).is_err());
    assert_eq!(Compression::from_name("rdp61"), Some(Compression::Rdp61));
    assert_eq!(Compression::Rdp6.type_code(), Some(2));
    assert_eq!(Compression::Off.type_code(), None);
}

#[test]
fn random_and_truncated_input_never_panics() {
    let mut rng = Rng(0xF00D);
    let mut d = Decompressor::new(Compression::Rdp61);
    for i in 0..3000 {
        let n = rng.below(80);
        let data = rng.bytes(n);
        let ty = (rng.below(4)) as u8;
        // FLUSHED on the 2 MB RDP 6.1 history is rare, as in real traffic.
        let mut flags = PACKET_COMPRESSED | ty | (rng.next() as u8 & PACKET_AT_FRONT);
        if ty != 3 || i % 50 == 0 {
            flags |= rng.next() as u8 & PACKET_FLUSHED;
        }
        let _ = d.decompress(&data, flags);
    }
    // Valid streams cut short or with a flipped bit.
    let mut mppc = MppcEnc::new(Variant::Rdp5);
    let mut nc = NcrushEnc::new();
    let data = sample(&mut rng, 3000);
    let streams = [mppc.compress(&data), nc.compress(&data)];
    for (comp, flags) in streams {
        for cut in (0..comp.len()).step_by(7) {
            let _ = d.decompress(&comp[..cut], flags | PACKET_FLUSHED);
            let mut bad = comp.clone();
            bad[cut] ^= 1 << (cut % 8);
            let _ = d.decompress(&bad, flags | PACKET_FLUSHED);
        }
    }
}
