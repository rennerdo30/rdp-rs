//! Field encodings shared by the drawing orders (MS-RDPEGDI 2.2.2.2.1.1.1
//! and 2.2.2.2.1.2.1).

use crate::cursor::Reader;
use crate::error::{Result, proto};

/// Most rectangles a DELTA_RECTS_FIELD may hold (MS-RDPEGDI 2.2.2.2.1.1.1.5).
pub const MAX_DELTA_RECTS: usize = 45;

/// A rectangle as (left, top, width, height).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeltaRect {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

/// The packed signed value of DELTA_RECTS_FIELD and DELTA_PTS_FIELD
/// (MS-RDPEGDI 2.2.2.2.1.1.1.4/5): one byte with a 7-bit signed value, or,
/// when the high bit is set, a 15-bit signed value over two bytes.
pub fn packed_delta(r: &mut Reader) -> Result<i32> {
    let b = r.u8()?;
    if b & 0x80 == 0 {
        // Sign-extend bit 6.
        return Ok(((b << 1) as i8 >> 1) as i32);
    }
    let v = (((b & 0x7F) as u16) << 8 | r.u8()? as u16) as i32;
    Ok(if v & 0x4000 != 0 { v - 0x8000 } else { v })
}

/// DELTA_RECTS_FIELD (MS-RDPEGDI 2.2.2.2.1.1.1.5): `count` rectangles, each
/// left/top relative to the previous one (the first to (0, 0)); a zero bit
/// keeps the previous component.
pub fn delta_rects(data: &[u8], count: usize) -> Result<Vec<DeltaRect>> {
    if count > MAX_DELTA_RECTS {
        return proto(format!("{count} delta rectangles (at most 45)"));
    }
    let mut r = Reader::new(data);
    let zero = r.bytes(count.div_ceil(2))?;
    let mut out = Vec::with_capacity(count);
    let mut prev = DeltaRect::default();
    for i in 0..count {
        let flags = zero[i / 2] << (4 * (i % 2));
        let mut rect = prev;
        if flags & 0x80 == 0 {
            rect.left = prev.left + packed_delta(&mut r)?;
        }
        if flags & 0x40 == 0 {
            rect.top = prev.top + packed_delta(&mut r)?;
        }
        if flags & 0x20 == 0 {
            rect.width = packed_delta(&mut r)?;
        }
        if flags & 0x10 == 0 {
            rect.height = packed_delta(&mut r)?;
        }
        out.push(rect);
        prev = rect;
    }
    Ok(out)
}

/// DELTA_PTS_FIELD (MS-RDPEGDI 2.2.2.2.1.1.1.4): `count` points as deltas
/// from the previous point, the first from (`x`, `y`). Returns the absolute
/// points, not including the start point.
pub fn delta_points(data: &[u8], count: usize, x: i32, y: i32) -> Result<Vec<(i32, i32)>> {
    let mut r = Reader::new(data);
    let zero = r.bytes(count.div_ceil(4))?;
    let mut out = Vec::with_capacity(count);
    let (mut px, mut py) = (x, y);
    for i in 0..count {
        let flags = zero[i / 4] << (2 * (i % 4));
        if flags & 0x80 == 0 {
            px += packed_delta(&mut r)?;
        }
        if flags & 0x40 == 0 {
            py += packed_delta(&mut r)?;
        }
        out.push((px, py));
    }
    Ok(out)
}

/// TWO_BYTE_UNSIGNED_ENCODING (MS-RDPEGDI 2.2.2.2.1.2.1.2).
pub fn two_byte_unsigned(r: &mut Reader) -> Result<u16> {
    let b = r.u8()?;
    if b & 0x80 == 0 {
        return Ok(b as u16);
    }
    Ok(((b & 0x7F) as u16) << 8 | r.u8()? as u16)
}

/// TWO_BYTE_SIGNED_ENCODING (MS-RDPEGDI 2.2.2.2.1.2.1.3).
pub fn two_byte_signed(r: &mut Reader) -> Result<i16> {
    let b = r.u8()?;
    let mut v = (b & 0x3F) as i16;
    if b & 0x80 != 0 {
        v = v << 8 | r.u8()? as i16;
    }
    Ok(if b & 0x40 != 0 { -v } else { v })
}

/// FOUR_BYTE_UNSIGNED_ENCODING (MS-RDPEGDI 2.2.2.2.1.2.1.4).
pub fn four_byte_unsigned(r: &mut Reader) -> Result<u32> {
    let b = r.u8()?;
    let mut v = (b & 0x3F) as u32;
    for _ in 0..(b >> 6) {
        v = v << 8 | r.u8()? as u32;
    }
    Ok(v)
}

/// Reads the fields of one primary order (MS-RDPEGDI 2.2.2.2.1.1.2): a
/// field is read only when its fieldFlags bit is set; otherwise the stored
/// value from the previous order of this type stays.
pub struct Fields<'r, 'a> {
    pub r: &'r mut Reader<'a>,
    pub flags: u32,
    /// TS_DELTA_COORDINATES: Coord fields are 1-byte signed deltas.
    pub delta: bool,
}

impl Fields<'_, '_> {
    /// Field `n`, counted from 1 as in the spec's tables.
    pub fn has(&self, n: u32) -> bool {
        self.flags & (1 << (n - 1)) != 0
    }

    /// COORD_FIELD (MS-RDPEGDI 2.2.2.2.1.1.1.1).
    pub fn coord(&mut self, n: u32, v: &mut i32) -> Result<()> {
        if self.has(n) {
            *v = if self.delta {
                (*v as i16).wrapping_add(self.r.u8()? as i8 as i16) as i32
            } else {
                self.r.u16()? as i16 as i32
            };
        }
        Ok(())
    }

    pub fn u8(&mut self, n: u32, v: &mut u8) -> Result<()> {
        if self.has(n) {
            *v = self.r.u8()?;
        }
        Ok(())
    }

    pub fn i8(&mut self, n: u32, v: &mut i8) -> Result<()> {
        if self.has(n) {
            *v = self.r.u8()? as i8;
        }
        Ok(())
    }

    pub fn u16(&mut self, n: u32, v: &mut u16) -> Result<()> {
        if self.has(n) {
            *v = self.r.u16()?;
        }
        Ok(())
    }

    /// A plain 2-byte signed field (not a Coord field).
    pub fn i16(&mut self, n: u32, v: &mut i32) -> Result<()> {
        if self.has(n) {
            *v = self.r.u16()? as i16 as i32;
        }
        Ok(())
    }

    /// TS_COLOR (MS-RDPEGDI 2.2.2.2.1.1.1.8) as the raw 24-bit value, first
    /// byte lowest.
    pub fn color(&mut self, n: u32, v: &mut u32) -> Result<()> {
        if self.has(n) {
            let b = self.r.bytes(3)?;
            *v = b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16;
        }
        Ok(())
    }

    /// One byte of a colour that the order sends component by component
    /// (OpaqueRect, MultiOpaqueRect): `shift` 0 = red, 8 = green, 16 = blue.
    pub fn color_byte(&mut self, n: u32, v: &mut u32, shift: u32) -> Result<()> {
        if self.has(n) {
            *v = (*v & !(0xFF << shift)) | (self.r.u8()? as u32) << shift;
        }
        Ok(())
    }

    /// The five brush fields starting at field `first`: BrushOrgX,
    /// BrushOrgY, BrushStyle, BrushHatch, BrushExtra.
    pub fn brush(&mut self, first: u32, b: &mut BrushFields) -> Result<()> {
        self.i8(first, &mut b.org_x)?;
        self.i8(first + 1, &mut b.org_y)?;
        self.u8(first + 2, &mut b.style)?;
        self.u8(first + 3, &mut b.hatch)?;
        if self.has(first + 4) {
            b.extra = self.r.array()?;
        }
        Ok(())
    }

    /// VARIABLE1_FIELD (MS-RDPEGDI 2.2.2.2.1.1.1.2).
    pub fn var1(&mut self, n: u32, v: &mut Vec<u8>) -> Result<()> {
        if self.has(n) {
            let len = self.r.u8()? as usize;
            *v = self.r.bytes(len)?.to_vec();
        }
        Ok(())
    }

    /// VARIABLE2_FIELD (MS-RDPEGDI 2.2.2.2.1.1.1.3).
    pub fn var2(&mut self, n: u32, v: &mut Vec<u8>) -> Result<()> {
        if self.has(n) {
            let len = self.r.u16()? as usize;
            *v = self.r.bytes(len)?.to_vec();
        }
        Ok(())
    }
}

/// The brush fields of PatBlt and the orders that reuse them (MS-RDPEGDI
/// 2.2.2.2.1.1.2.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrushFields {
    pub org_x: i8,
    pub org_y: i8,
    pub style: u8,
    pub hatch: u8,
    pub extra: [u8; 7],
}
