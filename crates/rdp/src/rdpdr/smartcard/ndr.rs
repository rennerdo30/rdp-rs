//! NDR type serialization version 1 (MS-RPCE 2.2.6), the encoding of every
//! MS-RDPESC call and return structure (MS-RDPESC 2.2, 3.1.4).
//!
//! A serialized buffer is the Common Type Header (MS-RPCE 2.2.6.1), the
//! Private Header (2.2.6.2) and the NDR body, padded to 8 bytes. In the body
//! every primitive is aligned to its size relative to the body start, and the
//! referents of embedded pointers follow the top-level structure in field
//! order (NDR deferred pointers, C706 14.3.12). Only little-endian streams
//! are accepted; every read is bounds-checked.

use crate::cursor::Put;
use crate::error::{Result, proto};

/// Common Type Header (MS-RPCE 2.2.6.1): Version 1, little endian (0x10),
/// CommonHeaderLength 8, Filler 0xCCCCCCCC.
const COMMON_HEADER: [u8; 8] = [0x01, 0x10, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC];
/// First referent id of a unique pointer, as Windows writes them.
const REFID_BASE: u32 = 0x0002_0000;

/// Reads one serialized structure.
pub struct NdrReader<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    /// Checks both headers (MS-RPCE 2.2.6.1/2.2.6.2) and returns a reader on
    /// the body (ObjectBufferLength bytes).
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 16 {
            return proto("ndr: buffer shorter than the type serialization headers");
        }
        if buf[0] != 1 || buf[1] != 0x10 || u16::from_le_bytes([buf[2], buf[3]]) != 8 {
            return proto("ndr: unsupported common type header");
        }
        let len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
        let Some(body) = buf.get(16..16 + len) else {
            return proto("ndr: ObjectBufferLength exceeds the buffer");
        };
        Ok(Self { body, pos: 0 })
    }

    fn align(&mut self, n: usize) {
        self.pos = self.pos.next_multiple_of(n).min(self.body.len());
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.body.len() - self.pos < n {
            return proto(format!("ndr: truncated at {} (need {n})", self.pos));
        }
        let s = &self.body[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.align(4);
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// An `unsigned long` with an IDL `[range(0, max)]`.
    pub fn ranged(&mut self, max: u32) -> Result<u32> {
        let v = self.u32()?;
        if v > max {
            return proto(format!("ndr: value {v} outside range 0..={max}"));
        }
        Ok(v)
    }

    /// A unique or full pointer's referent id: true when non-null.
    pub fn ptr(&mut self) -> Result<bool> {
        Ok(self.u32()? != 0)
    }

    /// The referent of a `[size_is(len)] byte *`: MaximumCount, then the
    /// bytes. MaximumCount must equal the size field.
    pub fn conformant_bytes(&mut self, len: u32) -> Result<Vec<u8>> {
        let max = self.u32()?;
        if max != len {
            return proto(format!("ndr: conformant count {max} != size {len}"));
        }
        Ok(self.bytes(len as usize)?.to_vec())
    }

    /// The referent of a `[string]` pointer (conformant varying array,
    /// C706 14.3.3.5): MaximumCount, Offset, ActualCount, then the elements.
    /// Returns the elements of `unit` bytes each.
    fn varying(&mut self, unit: usize) -> Result<&'a [u8]> {
        let max = self.u32()?;
        let offset = self.u32()?;
        let actual = self.u32()?;
        if offset != 0 || actual > max || actual > 65536 {
            return proto("ndr: bad string counts");
        }
        self.bytes(actual as usize * unit)
    }

    /// A `[string] const wchar_t *` referent, up to the first null.
    pub fn wstring(&mut self) -> Result<String> {
        let b = self.varying(2)?;
        Ok(decode_wide(b))
    }

    /// A `[string] const char *` referent, up to the first null. Bytes are
    /// taken as Latin-1.
    pub fn astring(&mut self) -> Result<String> {
        let b = self.varying(1)?;
        Ok(b.iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect())
    }

    /// One reader name: wide or ANSI.
    pub fn string(&mut self, wide: bool) -> Result<String> {
        if wide { self.wstring() } else { self.astring() }
    }
}

/// UTF-16LE up to the first null.
fn decode_wide(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Builds one serialized structure.
pub struct NdrWriter {
    body: Vec<u8>,
    next_ref: u32,
}

impl Default for NdrWriter {
    fn default() -> Self {
        Self {
            body: Vec::with_capacity(64),
            next_ref: REFID_BASE,
        }
    }
}

impl NdrWriter {
    fn align(&mut self, n: usize) {
        let len = self.body.len().next_multiple_of(n);
        self.body.resize(len, 0);
    }

    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.body.put_u32(v);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.body.put_bytes(b);
    }

    /// A unique pointer: the next referent id, or 0 for null.
    pub fn ptr(&mut self, present: bool) {
        if present {
            let id = self.next_ref;
            self.next_ref += 4;
            self.u32(id);
        } else {
            self.u32(0);
        }
    }

    /// The referent of a `[size_is] byte *`: MaximumCount and the bytes.
    pub fn conformant_bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }

    /// Both headers, the body and the padding to a multiple of 8
    /// (MS-RPCE 2.2.6.2: ObjectBufferLength is a multiple of 8).
    pub fn finish(mut self) -> Vec<u8> {
        self.align(8);
        let mut out = Vec::with_capacity(16 + self.body.len());
        out.put_bytes(&COMMON_HEADER);
        out.put_u32(self.body.len() as u32);
        out.put_u32(0); // Filler
        out.put_bytes(&self.body);
        out
    }
}

/// A multi-string (MS-RDPESC 2.2.3.4 `msz`): every name null-terminated and
/// one more null at the end; UTF-16LE when `wide`, else one byte per
/// character (non-Latin-1 characters become `?`).
pub fn multi_string(names: &[String], wide: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for n in names {
        for c in n.chars().filter(|&c| c != '\0') {
            push_char(&mut out, c, wide);
        }
        push_char(&mut out, '\0', wide);
    }
    if names.is_empty() {
        push_char(&mut out, '\0', wide);
    }
    push_char(&mut out, '\0', wide);
    out
}

fn push_char(out: &mut Vec<u8>, c: char, wide: bool) {
    if wide {
        let mut buf = [0u16; 2];
        for u in c.encode_utf16(&mut buf) {
            out.put_u16(*u);
        }
    } else {
        out.push(u8::try_from(u32::from(c)).unwrap_or(b'?'));
    }
}

/// Splits a multi-string into its names (empty names end the list).
pub fn parse_multi_string(b: &[u8], wide: bool) -> Vec<String> {
    let text = if wide {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        b.iter().map(|&c| c as char).collect()
    };
    text.split('\0')
        .take_while(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}
