//! Secondary drawing orders (MS-RDPEGDI 2.2.2.2.1.2): they fill the client's
//! caches.

use super::draw::Glyph;
use super::fields::{four_byte_unsigned, two_byte_signed, two_byte_unsigned};
use crate::cursor::Reader;
use crate::error::{Result, proto};

pub const TS_CACHE_BITMAP_UNCOMPRESSED: u8 = 0x00;
pub const TS_CACHE_COLOR_TABLE: u8 = 0x01;
pub const TS_CACHE_BITMAP_COMPRESSED: u8 = 0x02;
pub const TS_CACHE_GLYPH: u8 = 0x03;
pub const TS_CACHE_BITMAP_UNCOMPRESSED_REV2: u8 = 0x04;
pub const TS_CACHE_BITMAP_COMPRESSED_REV2: u8 = 0x05;
pub const TS_CACHE_BRUSH: u8 = 0x07;
pub const TS_CACHE_BITMAP_COMPRESSED_REV3: u8 = 0x08;

const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;
const CBR2_HEIGHT_SAME_AS_WIDTH: u16 = 0x01;
const CBR2_PERSISTENT_KEY_PRESENT: u16 = 0x02;
const CBR2_NO_BITMAP_COMPRESSION_HDR: u16 = 0x08;
const CBR2_DO_NOT_CACHE: u16 = 0x10;
const CBR3_DO_NOT_CACHE: u16 = 0x10;
const GLYPH_ORDER_REV2: u16 = 0x20;

/// BITMAPCACHE_WAITING_LIST_INDEX: the "last entry" of a bitmap cache
/// (MS-RDPEGDI 2.2.2.2.1.2.3).
pub const WAITING_LIST_INDEX: u16 = 32767;

/// How a cached bitmap's pixels are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapCodec {
    /// Raw bottom-up rows, padded to 4 bytes.
    Raw,
    /// Interleaved RLE or (at 32 bpp) planar, as in Bitmap Updates.
    Compressed,
    /// TS_BITMAP_DATA_EX with this codecID (0 = raw, bottom-up, unpadded).
    Ex(u8),
}

/// A bitmap for one of the bitmap caches (Cache Bitmap revision 1, 2 or 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheBitmap<'a> {
    pub cache_id: u8,
    pub index: u16,
    pub width: u16,
    pub height: u16,
    pub bpp: u16,
    /// The 64-bit persistent key, when the server sent one.
    pub key: Option<u64>,
    pub codec: BitmapCodec,
    pub data: &'a [u8],
}

/// A brush for the brush cache (MS-RDPEGDI 2.2.2.2.1.2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheBrush {
    pub index: u8,
    /// BMF_* format: 1, 3 (8 bpp), 4 (16), 5 (24), 6 (32).
    pub format: u8,
    /// 64 raw pixel values, top-down (mono: 0 or 1; 8 bpp: palette index;
    /// else the pixel value at the brush's depth).
    pub px: [u32; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Secondary<'a> {
    Bitmap(CacheBitmap<'a>),
    ColorTable {
        index: u8,
        colors: Vec<u32>,
    },
    Glyphs {
        cache_id: u8,
        glyphs: Vec<(u16, Glyph)>,
    },
    Brush(Box<CacheBrush>),
    Other(u8),
}

/// Parses one secondary order body. `order` starts at controlFlags and
/// holds exactly orderLength + 13 bytes (2.2.2.2.1.2.1.1).
pub fn parse(order: &[u8]) -> Result<Secondary<'_>> {
    let mut r = Reader::new(order);
    r.u8()?;
    r.u16()?;
    let extra = r.u16()?;
    let ty = r.u8()?;
    match ty {
        TS_CACHE_BITMAP_UNCOMPRESSED | TS_CACHE_BITMAP_COMPRESSED => {
            cache_bitmap_v1(&mut r, extra, ty == TS_CACHE_BITMAP_COMPRESSED)
        }
        TS_CACHE_BITMAP_UNCOMPRESSED_REV2 | TS_CACHE_BITMAP_COMPRESSED_REV2 => {
            cache_bitmap_v2(&mut r, extra, ty == TS_CACHE_BITMAP_COMPRESSED_REV2)
        }
        TS_CACHE_BITMAP_COMPRESSED_REV3 => cache_bitmap_v3(&mut r, extra),
        TS_CACHE_COLOR_TABLE => color_table(&mut r),
        TS_CACHE_GLYPH if extra & GLYPH_ORDER_REV2 != 0 => cache_glyph_v2(&mut r, extra),
        TS_CACHE_GLYPH => cache_glyph_v1(&mut r),
        TS_CACHE_BRUSH => cache_brush(&mut r),
        t => Ok(Secondary::Other(t)),
    }
}

/// Skips the 8-byte TS_CD_HEADER (MS-RDPBCGR 2.2.9.1.1.3.1.2.3) when present.
fn strip_cd_header(data: &[u8], compressed: bool, no_header: bool) -> Result<&[u8]> {
    if compressed && !no_header {
        return data
            .get(8..)
            .ok_or_else(|| crate::Error::Protocol("short TS_CD_HEADER".into()));
    }
    Ok(data)
}

/// Cache Bitmap - Revision 1 (MS-RDPEGDI 2.2.2.2.1.2.2).
fn cache_bitmap_v1<'a>(r: &mut Reader<'a>, extra: u16, compressed: bool) -> Result<Secondary<'a>> {
    let cache_id = r.u8()?;
    r.u8()?;
    let width = r.u8()? as u16;
    let height = r.u8()? as u16;
    let bpp = r.u8()? as u16;
    let len = r.u16()? as usize;
    let index = r.u16()?;
    let data = r.bytes(len)?;
    let data = strip_cd_header(data, compressed, extra & NO_BITMAP_COMPRESSION_HDR != 0)?;
    Ok(Secondary::Bitmap(CacheBitmap {
        cache_id,
        index,
        width,
        height,
        bpp,
        key: None,
        codec: if compressed {
            BitmapCodec::Compressed
        } else {
            BitmapCodec::Raw
        },
        data,
    }))
}

/// bitsPerPixelId of the revision 2 and 3 orders (CBR2_*, CBR23_*).
fn bpp_id(id: u16) -> Result<u16> {
    Ok(match id {
        3 => 8,
        4 => 16,
        5 => 24,
        6 => 32,
        _ => return proto(format!("bitmap bitsPerPixelId {id}")),
    })
}

/// Cache Bitmap - Revision 2 (MS-RDPEGDI 2.2.2.2.1.2.3).
fn cache_bitmap_v2<'a>(r: &mut Reader<'a>, extra: u16, compressed: bool) -> Result<Secondary<'a>> {
    let cache_id = (extra & 0x7) as u8;
    let bpp = bpp_id((extra >> 3) & 0xF)?;
    let flags = extra >> 7;
    let key = if flags & CBR2_PERSISTENT_KEY_PRESENT != 0 {
        let lo = r.u32()? as u64;
        let hi = r.u32()? as u64;
        Some(hi << 32 | lo)
    } else {
        None
    };
    let width = two_byte_unsigned(r)?;
    let height = if flags & CBR2_HEIGHT_SAME_AS_WIDTH != 0 {
        width
    } else {
        two_byte_unsigned(r)?
    };
    let len = four_byte_unsigned(r)? as usize;
    let mut index = two_byte_unsigned(r)?;
    if flags & CBR2_DO_NOT_CACHE != 0 {
        index = WAITING_LIST_INDEX;
    }
    let data = r.bytes(len)?;
    let data = strip_cd_header(
        data,
        compressed,
        flags & CBR2_NO_BITMAP_COMPRESSION_HDR != 0,
    )?;
    Ok(Secondary::Bitmap(CacheBitmap {
        cache_id,
        index,
        width,
        height,
        bpp,
        key,
        codec: if compressed {
            BitmapCodec::Compressed
        } else {
            BitmapCodec::Raw
        },
        data,
    }))
}

/// Cache Bitmap - Revision 3 (MS-RDPEGDI 2.2.2.2.1.2.8) with its
/// TS_BITMAP_DATA_EX (MS-RDPBCGR 2.2.9.2.1.1).
fn cache_bitmap_v3<'a>(r: &mut Reader<'a>, extra: u16) -> Result<Secondary<'a>> {
    const EX_COMPRESSED_BITMAP_HEADER_PRESENT: u8 = 0x01;
    let cache_id = (extra & 0x7) as u8;
    let flags = extra >> 7;
    let mut index = r.u16()?;
    if flags & CBR3_DO_NOT_CACHE != 0 {
        index = WAITING_LIST_INDEX;
    }
    let lo = r.u32()? as u64;
    let hi = r.u32()? as u64;
    let bpp = r.u8()? as u16;
    let ex_flags = r.u8()?;
    r.u8()?;
    let codec = r.u8()?;
    let width = r.u16()?;
    let height = r.u16()?;
    let len = r.u32()? as usize;
    if ex_flags & EX_COMPRESSED_BITMAP_HEADER_PRESENT != 0 {
        r.skip(24)?; // TS_COMPRESSED_BITMAP_HEADER_EX
    }
    let data = r.bytes(len)?;
    Ok(Secondary::Bitmap(CacheBitmap {
        cache_id,
        index,
        width,
        height,
        bpp,
        key: Some(hi << 32 | lo),
        codec: BitmapCodec::Ex(codec),
        data,
    }))
}

/// Cache Color Table (MS-RDPEGDI 2.2.2.2.1.2.4): TS_COLOR_QUADs as 0x00RRGGBB.
fn color_table<'a>(r: &mut Reader<'a>) -> Result<Secondary<'a>> {
    let index = r.u8()?;
    let n = r.u16()? as usize;
    if n > 256 {
        return proto(format!("color table of {n} entries"));
    }
    let mut colors = Vec::with_capacity(n);
    for _ in 0..n {
        let q = r.array::<4>()?;
        colors.push((q[2] as u32) << 16 | (q[1] as u32) << 8 | q[0] as u32);
    }
    Ok(Secondary::ColorTable { index, colors })
}

/// Cache Glyph - Revision 1 (MS-RDPEGDI 2.2.2.2.1.2.5).
fn cache_glyph_v1<'a>(r: &mut Reader<'a>) -> Result<Secondary<'a>> {
    let cache_id = r.u8()?;
    let n = r.u8()?;
    let mut glyphs = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let index = r.u16()?;
        let x = r.u16()? as i16 as i32;
        let y = r.u16()? as i16 as i32;
        let cx = r.u16()? as u32;
        let cy = r.u16()? as u32;
        let aj = r.bytes(Glyph::wire_size(cx, cy))?;
        glyphs.push((index, glyph(x, y, cx, cy, aj)?));
    }
    // The unicodeCharacters that may follow are diagnostic only.
    Ok(Secondary::Glyphs { cache_id, glyphs })
}

fn glyph(x: i32, y: i32, cx: u32, cy: u32, aj: &[u8]) -> Result<Glyph> {
    Glyph::new(x, y, cx, cy, aj).ok_or_else(|| crate::Error::Protocol("short glyph bitmap".into()))
}

/// TS_CACHE_GLYPH_DATA_REV2 (MS-RDPEGDI 2.2.2.2.1.2.6.1): (cacheIndex, glyph).
pub fn glyph_v2(r: &mut Reader) -> Result<(u16, Glyph)> {
    let index = r.u8()? as u16;
    let x = two_byte_signed(r)? as i32;
    let y = two_byte_signed(r)? as i32;
    let cx = two_byte_unsigned(r)? as u32;
    let cy = two_byte_unsigned(r)? as u32;
    let aj = r.bytes(Glyph::wire_size(cx, cy))?;
    Ok((index, glyph(x, y, cx, cy, aj)?))
}

/// Cache Glyph - Revision 2 (MS-RDPEGDI 2.2.2.2.1.2.6).
fn cache_glyph_v2<'a>(r: &mut Reader<'a>, extra: u16) -> Result<Secondary<'a>> {
    let cache_id = (extra & 0x0F) as u8;
    let n = extra >> 8;
    let mut glyphs = Vec::with_capacity(n as usize);
    for _ in 0..n {
        glyphs.push(glyph_v2(r)?);
    }
    Ok(Secondary::Glyphs { cache_id, glyphs })
}

pub const BMF_1BPP: u8 = 1;
pub const BMF_8BPP: u8 = 3;
pub const BMF_16BPP: u8 = 4;
pub const BMF_24BPP: u8 = 5;
pub const BMF_32BPP: u8 = 6;

/// Cache Brush (MS-RDPEGDI 2.2.2.2.1.2.7); rows on the wire are bottom-up.
fn cache_brush<'a>(r: &mut Reader<'a>) -> Result<Secondary<'a>> {
    let index = r.u8()?;
    let format = r.u8()?;
    let cx = r.u8()?;
    let cy = r.u8()?;
    r.u8()?; // Style
    let len = r.u8()? as usize;
    let data = r.bytes(len)?;
    if cx != 8 || cy != 8 {
        return proto(format!("{cx}x{cy} brush (only 8x8)"));
    }
    let mut px = [0u32; 64];
    let bytes = match format {
        BMF_1BPP => {
            if data.len() < 8 {
                return proto("short mono brush");
            }
            for (row, &b) in data[..8].iter().enumerate() {
                for x in 0..8 {
                    px[(7 - row) * 8 + x] = (b >> (7 - x) & 1) as u32;
                }
            }
            return Ok(Secondary::Brush(Box::new(CacheBrush { index, format, px })));
        }
        BMF_8BPP => 1,
        BMF_16BPP => 2,
        BMF_24BPP => 3,
        BMF_32BPP => 4,
        _ => return proto(format!("brush format {format}")),
    };
    let value = |b: &[u8]| b.iter().rev().fold(0u32, |v, &x| v << 8 | x as u32);
    if len == 16 + 4 * bytes {
        // COMPRESSED_COLOR_BRUSH (2.2.2.2.1.2.7.1): 2-bit indices, then four colours.
        let table: Vec<u32> = data[16..].chunks(bytes).map(value).collect();
        for row in 0..8 {
            for x in 0..8 {
                let byte = data[row * 2 + x / 4];
                let i = (byte >> (6 - 2 * (x % 4))) & 3;
                px[(7 - row) * 8 + x] = table[i as usize];
            }
        }
    } else {
        let stride = 8 * bytes;
        if data.len() < 8 * stride {
            return proto("short color brush");
        }
        for row in 0..8 {
            for x in 0..8 {
                let at = row * stride + x * bytes;
                px[(7 - row) * 8 + x] = value(&data[at..at + bytes]);
            }
        }
    }
    Ok(Secondary::Brush(Box::new(CacheBrush { index, format, px })))
}
