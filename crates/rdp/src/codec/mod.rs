//! Bitmap update decoding (TS_UPDATE_BITMAP_DATA) onto the framebuffer.

pub mod interleaved;
pub mod planar;

use crate::cursor::Reader;
use crate::error::{Error, Result};
use crate::framebuffer::{Damage, Framebuffer};
use crate::trace;

const BITMAP_COMPRESSION: u16 = 0x0001;
const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

pub fn rgb565(p: u32) -> u32 {
    let r = (p >> 11) & 0x1F;
    let g = (p >> 5) & 0x3F;
    let b = p & 0x1F;
    ((r << 3 | r >> 2) << 16) | ((g << 2 | g >> 4) << 8) | (b << 3 | b >> 2)
}

pub fn rgb555(p: u32) -> u32 {
    let r = (p >> 10) & 0x1F;
    let g = (p >> 5) & 0x1F;
    let b = p & 0x1F;
    ((r << 3 | r >> 2) << 16) | ((g << 3 | g >> 2) << 8) | (b << 3 | b >> 2)
}

/// Converts raw bottom-up pixel values to top-down 0x00RRGGBB.
pub fn to_rgb_top_down(raw: &[u32], w: usize, h: usize, bpp: u16) -> Vec<u32> {
    let mut out = vec![0u32; w * h];
    for y in 0..h {
        let src = &raw[(h - 1 - y) * w..(h - y) * w];
        let dst = &mut out[y * w..(y + 1) * w];
        for (d, &p) in dst.iter_mut().zip(src) {
            *d = match bpp {
                15 => rgb555(p),
                16 => rgb565(p),
                _ => p & 0x00FF_FFFF,
            };
        }
    }
    out
}

pub(crate) fn uncompressed(data: &[u8], w: usize, h: usize, bpp: u16) -> Result<Vec<u32>> {
    let bytes = match bpp {
        15 | 16 => 2,
        24 => 3,
        32 => 4,
        _ => return Err(Error::Unsupported(format!("uncompressed {bpp} bpp bitmap"))),
    };
    let stride = (w * bytes + 3) & !3;
    if data.len() < stride * h {
        return Err(Error::Protocol("uncompressed bitmap too short".into()));
    }
    let mut raw = Vec::with_capacity(w * h);
    for row in 0..h {
        let line = &data[row * stride..];
        for x in 0..w {
            let p = &line[x * bytes..x * bytes + bytes];
            let mut v = 0u32;
            for (i, b) in p.iter().enumerate().take(3) {
                v |= (*b as u32) << (8 * i);
            }
            raw.push(v);
        }
    }
    Ok(to_rgb_top_down(&raw, w, h, bpp))
}

/// Draws every rectangle of a TS_UPDATE_BITMAP_DATA and records what changed.
pub fn draw_bitmap_update(
    data: &[u8],
    fb: &mut Framebuffer,
    damage: &mut Vec<Damage>,
) -> Result<()> {
    let mut r = Reader::new(data);
    if r.u16()? != 1 {
        return Ok(());
    }
    let count = r.u16()?;
    for _ in 0..count {
        let left = r.u16()? as usize;
        let top = r.u16()? as usize;
        let right = r.u16()? as usize;
        let bottom = r.u16()? as usize;
        let w = r.u16()? as usize;
        let h = r.u16()? as usize;
        let bpp = r.u16()?;
        let flags = r.u16()?;
        let len = r.u16()? as usize;
        let mut body = r.bytes(len)?;
        let pixels = if flags & BITMAP_COMPRESSION != 0 {
            if flags & NO_BITMAP_COMPRESSION_HDR == 0 {
                body = body
                    .get(8..)
                    .ok_or_else(|| Error::Protocol("short TS_CD_HEADER".into()))?;
            }
            if bpp == 32 {
                planar::decode(body, w, h)
            } else {
                interleaved::decode(body, w, h, bpp)
            }
        } else {
            uncompressed(body, w, h, bpp)
        };
        match pixels {
            Ok(px) => {
                let dw = (right + 1).saturating_sub(left).min(w);
                let dh = (bottom + 1).saturating_sub(top).min(h);
                damage.extend(fb.blit(left, top, dw, dh, &px, w));
            }
            // One undecodable rectangle should not end the session.
            Err(e) => trace!("bitmap {w}x{h}@{bpp} flags {flags:#x} skipped: {e}"),
        }
    }
    Ok(())
}
