//! Pointer (mouse cursor) updates, MS-RDPBCGR 2.2.9.1.1.4 (slow path) and
//! 2.2.9.1.2.1.5-2.2.9.1.2.1.11 (fast path).
//!
//! The server sends a shape once (Color / New / Large Pointer, stored in a
//! cache slot) and afterwards only names the slot (Cached Pointer). Shapes
//! are decoded to straight RGBA, top-down, ready for a native cursor.

use std::sync::Arc;

use crate::cursor::Reader;
use crate::error::{Result, proto};

/// Number of cache slots the client advertises (pointer capability set).
pub const CACHE_SIZE: usize = 32;

/// A decoded cursor image.
#[derive(Debug, PartialEq, Eq)]
pub struct PointerShape {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    /// Straight (non-premultiplied) RGBA, top-down, `width * height * 4` bytes.
    pub rgba: Vec<u8>,
}

/// What the session should show as its cursor.
#[derive(Clone, Debug, PartialEq)]
pub enum PointerUpdate {
    /// TS_PTRMSGTYPE_SYSTEM / SYSPTR_NULL: no cursor.
    Hidden,
    /// SYSPTR_DEFAULT: the client's default arrow.
    Default,
    Shape(Arc<PointerShape>),
}

/// The client's pointer cache.
pub struct PointerCache {
    slots: Vec<Option<Arc<PointerShape>>>,
}

impl Default for PointerCache {
    fn default() -> Self {
        Self {
            slots: vec![None; CACHE_SIZE],
        }
    }
}

impl PointerCache {
    fn store(&mut self, index: u16, shape: PointerShape) -> Result<PointerUpdate> {
        let shape = Arc::new(shape);
        let slot = self.slots.get_mut(index as usize).ok_or_else(|| {
            crate::Error::Protocol(format!("pointer cache index {index} out of range"))
        })?;
        *slot = Some(shape.clone());
        Ok(PointerUpdate::Shape(shape))
    }

    fn cached(&self, index: u16) -> Result<PointerUpdate> {
        match self.slots.get(index as usize) {
            Some(Some(s)) => Ok(PointerUpdate::Shape(s.clone())),
            _ => proto(format!("cached pointer {index} was never sent")),
        }
    }

    /// Fast-path pointer update (updateCode 5, 6, 8-12). `None`: nothing to show
    /// changes (position updates).
    pub fn fast_path(&mut self, code: u8, data: &[u8]) -> Result<Option<PointerUpdate>> {
        let mut r = Reader::new(data);
        Ok(Some(match code {
            0x5 => PointerUpdate::Hidden,  // FASTPATH_UPDATETYPE_PTR_NULL
            0x6 => PointerUpdate::Default, // FASTPATH_UPDATETYPE_PTR_DEFAULT
            0x8 => return Ok(None),        // FASTPATH_UPDATETYPE_PTR_POSITION
            0x9 => self.color(&mut r, 24)?,
            0xA => self.cached(r.u16()?)?,
            0xB => {
                let bpp = r.u16()?;
                self.color(&mut r, bpp)?
            }
            0xC => self.large(&mut r)?,
            _ => return Ok(None),
        }))
    }

    /// Slow-path Pointer Update PDU body (pduType2 = PDUTYPE2_POINTER).
    pub fn slow_path(&mut self, body: &[u8]) -> Result<Option<PointerUpdate>> {
        let mut r = Reader::new(body);
        let msg = r.u16()?;
        r.u16()?; // pad2Octets
        Ok(Some(match msg {
            0x0001 => match r.u32()? {
                0 => PointerUpdate::Hidden,  // SYSPTR_NULL
                _ => PointerUpdate::Default, // SYSPTR_DEFAULT (0x7F00)
            },
            0x0003 => return Ok(None), // TS_PTRMSGTYPE_POSITION
            0x0006 => self.color(&mut r, 24)?,
            0x0007 => self.cached(r.u16()?)?,
            0x0008 => {
                let bpp = r.u16()?;
                self.color(&mut r, bpp)?
            }
            0x0009 => self.large(&mut r)?,
            _ => return Ok(None),
        }))
    }

    /// TS_COLORPOINTERATTRIBUTE (2.2.9.1.1.4.4), preceded by xorBpp for New Pointer.
    fn color(&mut self, r: &mut Reader, bpp: u16) -> Result<PointerUpdate> {
        let index = r.u16()?;
        let hx = r.u16()?;
        let hy = r.u16()?;
        let w = r.u16()?;
        let h = r.u16()?;
        let and_len = r.u16()? as usize;
        let xor_len = r.u16()? as usize;
        let xor = r.bytes(xor_len)?;
        let and = r.bytes(and_len)?;
        let shape = decode(w, h, hx, hy, bpp, xor, and)?;
        self.store(index, shape)
    }

    /// TS_LARGEPOINTERATTRIBUTE (2.2.9.1.2.1.11): up to 384 x 384, 32-bit lengths.
    fn large(&mut self, r: &mut Reader) -> Result<PointerUpdate> {
        let bpp = r.u16()?;
        let index = r.u16()?;
        let hx = r.u16()?;
        let hy = r.u16()?;
        let w = r.u16()?;
        let h = r.u16()?;
        let and_len = r.u32()? as usize;
        let xor_len = r.u32()? as usize;
        let xor = r.bytes(xor_len)?;
        let and = r.bytes(and_len)?;
        let shape = decode(w, h, hx, hy, bpp, xor, and)?;
        self.store(index, shape)
    }
}

/// Scanline length padded to a 2-byte boundary (2.2.9.1.1.4.4).
fn stride(width: usize, bpp: usize) -> usize {
    (width * bpp).div_ceil(8).div_ceil(2) * 2
}

/// Combines the XOR (colour) and AND (transparency) masks into RGBA.
/// Both masks are bottom-up. Pixels that would invert the screen (AND = 1 with
/// a non-black XOR colour), which native RGBA cursors cannot express, are drawn
/// black with a white outline-free fill so text cursors stay visible on light
/// backgrounds, the common case.
fn decode(
    w: u16,
    h: u16,
    hx: u16,
    hy: u16,
    bpp: u16,
    xor: &[u8],
    and: &[u8],
) -> Result<PointerShape> {
    let (wu, hu, b) = (w as usize, h as usize, bpp as usize);
    if wu == 0 || hu == 0 || wu > 384 || hu > 384 {
        return proto(format!("pointer size {w}x{h}"));
    }
    if !matches!(bpp, 1 | 8 | 16 | 24 | 32) {
        return proto(format!("pointer xorBpp {bpp}"));
    }
    let xs = stride(wu, b);
    let ands = stride(wu, 1);
    if xor.len() < xs * hu {
        return proto("pointer XOR mask too short");
    }
    let has_and = and.len() >= ands * hu;
    // 32 bpp shapes normally carry real alpha; when every alpha byte is zero
    // the AND mask decides transparency instead.
    let alpha_used = bpp == 32 && (0..hu).any(|y| (0..wu).any(|x| xor[y * xs + x * 4 + 3] != 0));
    let mut rgba = vec![0u8; wu * hu * 4];
    for y in 0..hu {
        let src = hu - 1 - y; // bottom-up
        let xrow = &xor[src * xs..src * xs + xs];
        for x in 0..wu {
            let and_bit = has_and && and[src * ands + x / 8] & (0x80 >> (x % 8)) != 0;
            let (r, g, bl, a) = match bpp {
                32 => {
                    let p = &xrow[x * 4..x * 4 + 4];
                    (p[2], p[1], p[0], if alpha_used { p[3] } else { 255 })
                }
                24 => {
                    let p = &xrow[x * 3..x * 3 + 3];
                    (p[2], p[1], p[0], 255)
                }
                16 => {
                    let v = u16::from_le_bytes([xrow[x * 2], xrow[x * 2 + 1]]) as u32;
                    let c = crate::codec::rgb565(v);
                    ((c >> 16) as u8, (c >> 8) as u8, c as u8, 255)
                }
                8 => {
                    // No palette is tracked; treat as grey levels.
                    let v = xrow[x];
                    (v, v, v, 255)
                }
                _ => {
                    let on = xrow[x / 8] & (0x80 >> (x % 8)) != 0;
                    let v = if on { 255 } else { 0 };
                    (v, v, v, 255)
                }
            };
            let px = if bpp == 32 && alpha_used {
                [r, g, bl, a]
            } else if !and_bit {
                [r, g, bl, 255]
            } else if r == 0 && g == 0 && bl == 0 {
                [0, 0, 0, 0] // transparent
            } else {
                [0, 0, 0, 255] // "invert" pixel: shown black
            };
            rgba[(y * wu + x) * 4..(y * wu + x) * 4 + 4].copy_from_slice(&px);
        }
    }
    Ok(PointerShape {
        width: w,
        height: h,
        hotspot_x: hx.min(w - 1),
        hotspot_y: hy.min(h - 1),
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::Put;

    /// A 2x2 New Pointer (fast path 0xB) at 32 bpp with alpha.
    fn new_pointer_32(index: u16) -> Vec<u8> {
        let mut d = Vec::new();
        d.put_u16(32); // xorBpp
        d.put_u16(index);
        d.put_u16(1); // hotspot
        d.put_u16(0);
        d.put_u16(2); // width
        d.put_u16(2); // height
        d.put_u16(4); // AND length: 2 rows x 2 bytes
        d.put_u16(16); // XOR length: 2 rows x 8 bytes
        // bottom row first (BGRA): red opaque, transparent
        d.put_bytes(&[0, 0, 255, 255, 0, 0, 0, 0]);
        // top row: green half alpha, blue opaque
        d.put_bytes(&[0, 255, 0, 128, 255, 0, 0, 255]);
        d.put_bytes(&[0; 4]);
        d
    }

    #[test]
    fn new_pointer_32bpp_is_flipped_and_keeps_alpha() {
        let mut c = PointerCache::default();
        let Some(PointerUpdate::Shape(s)) = c.fast_path(0xB, &new_pointer_32(3)).unwrap() else {
            panic!()
        };
        assert_eq!((s.width, s.height, s.hotspot_x, s.hotspot_y), (2, 2, 1, 0));
        assert_eq!(&s.rgba[0..8], &[0, 255, 0, 128, 0, 0, 255, 255]); // top row
        assert_eq!(&s.rgba[8..16], &[255, 0, 0, 255, 0, 0, 0, 0]); // bottom row
        // Cached Pointer returns the same shape.
        assert_eq!(
            c.fast_path(0xA, &[3, 0]).unwrap(),
            Some(PointerUpdate::Shape(s))
        );
    }

    #[test]
    fn monochrome_masks_map_to_black_white_transparent_invert() {
        // 4x1 at 1 bpp: AND 0011, XOR 0101 -> black, white, transparent, invert(black).
        let mut d = Vec::new();
        d.put_u16(1);
        d.put_u16(0);
        d.put_u16(0);
        d.put_u16(0);
        d.put_u16(4);
        d.put_u16(1);
        d.put_u16(2); // AND length (1 row padded to 2 bytes)
        d.put_u16(2); // XOR length
        d.put_bytes(&[0b0101_0000, 0]); // XOR
        d.put_bytes(&[0b0011_0000, 0]); // AND
        let Some(PointerUpdate::Shape(s)) = c_new().fast_path(0xB, &d).unwrap() else {
            panic!()
        };
        assert_eq!(
            s.rgba,
            vec![0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255]
        );
    }

    fn c_new() -> PointerCache {
        PointerCache::default()
    }

    #[test]
    fn system_pointers_and_unknown_cache_slot() {
        let mut c = PointerCache::default();
        assert_eq!(c.fast_path(0x5, &[]).unwrap(), Some(PointerUpdate::Hidden));
        assert_eq!(c.fast_path(0x6, &[]).unwrap(), Some(PointerUpdate::Default));
        assert_eq!(c.fast_path(0x8, &[1, 0, 2, 0]).unwrap(), None);
        assert!(c.fast_path(0xA, &[9, 0]).is_err());
        assert_eq!(
            c.slow_path(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            Some(PointerUpdate::Hidden)
        );
        assert_eq!(
            c.slow_path(&[1, 0, 0, 0, 0, 0x7F, 0, 0]).unwrap(),
            Some(PointerUpdate::Default)
        );
    }

    #[test]
    fn truncated_shapes_are_errors_not_panics() {
        let full = new_pointer_32(0);
        for n in 0..full.len() - 4 {
            let _ = PointerCache::default().fast_path(0xB, &full[..n]);
        }
        assert!(PointerCache::default().fast_path(0xB, &full[..20]).is_err());
    }
}
