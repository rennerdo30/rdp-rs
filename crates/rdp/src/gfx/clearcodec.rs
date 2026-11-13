//! ClearCodec decoder (MS-RDPEGFX 2.2.4.1, 3.3.8.1), codec id 0x0008 of
//! RDPGFX_WIRE_TO_SURFACE_PDU_1.
//!
//! A CLEARCODEC_BITMAP_STREAM is either a glyph cache hit or a composite
//! payload of up to three layers, each drawn over the one before
//! (3.3.8.1.2):
//!
//! 1. residual: run-length BGR pixels in raster order (2.2.4.1.1.1);
//! 2. bands: columns of pixels ("V-Bars") per band, most of them from the
//!    V-Bar and Short V-Bar storage (2.2.4.1.1.2);
//! 3. subcodecs: rectangles, raw, NSCodec or RLEX (2.2.4.1.1.3).
//!
//! The storages, their cursors and the Decompressor Glyph Storage
//! (3.3.1.9 - 3.3.1.13) persist across PDUs; [`ClearCodec`] holds them for
//! one graphics channel. Every index, run and rectangle from the server is
//! checked: corrupt data fails the PDU with `Error::Protocol` and never
//! panics.
//!
//! Layers only write what they cover; the caller passes the destination's
//! current pixels in, so uncovered pixels keep the surface content.

use crate::cursor::Reader;
use crate::error::{Result, proto};
use crate::trace;

use super::nsc;

/// CLEARCODEC_BITMAP_STREAM flags (2.2.4.1).
pub const FLAG_GLYPH_INDEX: u8 = 0x01;
pub const FLAG_GLYPH_HIT: u8 = 0x02;
pub const FLAG_CACHE_RESET: u8 = 0x04;

/// Decompressor Glyph Storage (3.3.1.9): slots and pixels per glyph.
pub const GLYPH_SLOTS: usize = 4000;
pub const GLYPH_MAX_PIXELS: usize = 1024;
/// V-Bar Storage (3.3.1.10) and Short V-Bar Storage (3.3.1.12) sizes.
pub const VBAR_SLOTS: usize = 32768;
pub const SHORT_VBAR_SLOTS: usize = 16384;
/// Tallest band (2.2.4.1.1.2.1).
pub const MAX_BAND_HEIGHT: usize = 52;

/// CLEARCODEC_SUBCODEC subCodecId values (2.2.4.1.1.3.1).
pub const SUBCODEC_UNCOMPRESSED: u8 = 0x00;
pub const SUBCODEC_NSCODEC: u8 = 0x01;
pub const SUBCODEC_RLEX: u8 = 0x02;

/// The ClearCodec decompressor state of one graphics channel.
pub struct ClearCodec {
    /// V-Bar Storage (3.3.1.10): full band-height columns, 0x00RRGGBB.
    vbars: Vec<Option<Vec<u32>>>,
    /// V-Bar Storage Cursor (3.3.1.11).
    vbar_cursor: usize,
    /// Short V-Bar Storage (3.3.1.12).
    short_vbars: Vec<Option<Vec<u32>>>,
    /// Short V-Bar Storage Cursor (3.3.1.13).
    short_cursor: usize,
    /// Decompressor Glyph Storage (3.3.1.9): linear pixel streams.
    glyphs: Vec<Option<Vec<u32>>>,
    /// seqNumber of the last stream (2.2.4.1).
    seq: Option<u8>,
}

impl Default for ClearCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// The bitmap being decoded: `w` x `h` pixels, row-major.
struct Bitmap<'a> {
    w: usize,
    h: usize,
    px: &'a mut [u32],
}

fn bgr([b, g, r]: [u8; 3]) -> u32 {
    (r as u32) << 16 | (g as u32) << 8 | b as u32
}

/// runLengthFactor1/2/3 (2.2.4.1.1.1.1, 2.2.4.1.1.3.1.1.2): one byte, or
/// 0xFF and two bytes, or 0xFF, 0xFFFF and four bytes.
fn run_length(r: &mut Reader) -> Result<usize> {
    let f1 = r.u8()?;
    if f1 < 0xFF {
        return Ok(f1 as usize);
    }
    let f2 = r.u16()?;
    if f2 < 0xFFFF {
        return Ok(f2 as usize);
    }
    Ok(r.u32()? as usize)
}

impl ClearCodec {
    pub fn new() -> ClearCodec {
        ClearCodec {
            vbars: vec![None; VBAR_SLOTS],
            vbar_cursor: 0,
            short_vbars: vec![None; SHORT_VBAR_SLOTS],
            short_cursor: 0,
            glyphs: vec![None; GLYPH_SLOTS],
            seq: None,
        }
    }

    /// V-Bar Storage Cursor and Short V-Bar Storage Cursor.
    pub fn cursors(&self) -> (usize, usize) {
        (self.vbar_cursor, self.short_cursor)
    }

    /// One stored V-Bar, if that slot was written.
    pub fn vbar(&self, index: usize) -> Option<&[u32]> {
        self.vbars.get(index)?.as_deref()
    }

    /// One stored Short V-Bar, if that slot was written.
    pub fn short_vbar(&self, index: usize) -> Option<&[u32]> {
        self.short_vbars.get(index)?.as_deref()
    }

    /// One stored glyph, if that slot was written.
    pub fn glyph(&self, index: usize) -> Option<&[u32]> {
        self.glyphs.get(index)?.as_deref()
    }

    /// Decodes one CLEARCODEC_BITMAP_STREAM (2.2.4.1) for a `width` x
    /// `height` destination. `pixels` (0x00RRGGBB, row-major) holds the
    /// destination's current content and receives the decoded bitmap.
    pub fn decode(
        &mut self,
        data: &[u8],
        width: usize,
        height: usize,
        pixels: &mut [u32],
    ) -> Result<()> {
        if pixels.len() != width * height {
            return proto("clearcodec: output buffer size");
        }
        let mut r = Reader::new(data);
        let flags = r.u8()?;
        let seq = r.u8()?;
        if let Some(prev) = self.seq
            && seq != prev.wrapping_add(1)
        {
            trace!("clearcodec: sequence {seq} after {prev}");
        }
        self.seq = Some(seq);
        if flags & FLAG_CACHE_RESET != 0 {
            self.vbar_cursor = 0;
            self.short_cursor = 0;
        }
        let glyph = if flags & FLAG_GLYPH_INDEX != 0 {
            let i = r.u16()? as usize;
            if i >= GLYPH_SLOTS {
                return proto(format!("clearcodec: glyph index {i}"));
            }
            Some(i)
        } else if flags & FLAG_GLYPH_HIT != 0 {
            return proto("clearcodec: glyph hit without a glyph index");
        } else {
            None
        };
        if let Some(i) = glyph {
            if flags & FLAG_GLYPH_HIT != 0 {
                // The stored stream has no dimensions; any rectangle of the
                // same area takes it (4.1.1.5).
                let Some(g) = self.glyphs[i].as_deref() else {
                    return proto(format!("clearcodec: glyph {i} is empty"));
                };
                if g.len() != pixels.len() {
                    return proto(format!(
                        "clearcodec: glyph {i} has {} pixels, {width}x{height} wanted",
                        g.len()
                    ));
                }
                pixels.copy_from_slice(g);
                return Ok(());
            }
            if pixels.len() > GLYPH_MAX_PIXELS {
                return proto(format!("clearcodec: glyph of {width}x{height}"));
            }
        }

        // CLEARCODEC_COMPOSITE_PAYLOAD (2.2.4.1.1).
        let residual_len = r.u32()? as usize;
        let bands_len = r.u32()? as usize;
        let subcodec_len = r.u32()? as usize;
        let residual = r.bytes(residual_len)?;
        let bands = r.bytes(bands_len)?;
        let subcodecs = r.bytes(subcodec_len)?;
        let mut bm = Bitmap {
            w: width,
            h: height,
            px: pixels,
        };
        if !residual.is_empty() {
            decode_residual(residual, &mut bm)?;
        }
        if !bands.is_empty() {
            self.decode_bands(bands, &mut bm)?;
        }
        if !subcodecs.is_empty() {
            decode_subcodecs(subcodecs, &mut bm)?;
        }
        if let Some(i) = glyph {
            self.glyphs[i] = Some(bm.px.to_vec());
        }
        Ok(())
    }

    /// CLEARCODEC_BANDS_DATA (2.2.4.1.1.2).
    fn decode_bands(&mut self, data: &[u8], bm: &mut Bitmap) -> Result<()> {
        let mut r = Reader::new(data);
        while r.remaining() > 0 {
            // CLEARCODEC_BAND (2.2.4.1.1.2.1); the ends are inclusive.
            let x0 = r.u16()? as usize;
            let x1 = r.u16()? as usize;
            let y0 = r.u16()? as usize;
            let y1 = r.u16()? as usize;
            let bkg = bgr(r.array()?);
            if x1 < x0 || y1 < y0 || x1 >= bm.w || y1 >= bm.h {
                return proto(format!(
                    "clearcodec: band ({x0},{y0})-({x1},{y1}) outside {}x{}",
                    bm.w, bm.h
                ));
            }
            let height = y1 - y0 + 1;
            if height > MAX_BAND_HEIGHT {
                return proto(format!("clearcodec: band of height {height}"));
            }
            for x in x0..=x1 {
                let column = self.vbar_column(&mut r, height, bkg)?;
                for (y, &p) in column.iter().enumerate() {
                    bm.px[(y0 + y) * bm.w + x] = p;
                }
            }
        }
        Ok(())
    }

    /// One CLEARCODEC_VBAR (2.2.4.1.1.2.1.1): the column's pixels, after the
    /// storages and cursors are updated.
    fn vbar_column(&mut self, r: &mut Reader, height: usize, bkg: u32) -> Result<&[u32]> {
        let header = r.u16()?;
        if header & 0x8000 != 0 {
            // VBAR_CACHE_HIT (2.2.4.1.1.2.1.1.1): 15-bit index.
            let i = (header & 0x7FFF) as usize;
            return match self.vbars[i].as_deref() {
                Some(v) if v.len() == height => Ok(v),
                Some(v) => proto(format!(
                    "clearcodec: V-Bar {i} has {} pixels, band is {height}",
                    v.len()
                )),
                None => proto(format!("clearcodec: V-Bar {i} is empty")),
            };
        }
        let (short, y_on) = if header >> 14 == 1 {
            // SHORT_VBAR_CACHE_HIT (2.2.4.1.1.2.1.1.2): 14-bit index, yOn.
            let i = (header & 0x3FFF) as usize;
            let y_on = r.u8()? as usize;
            let Some(s) = self.short_vbars[i].as_deref() else {
                return proto(format!("clearcodec: Short V-Bar {i} is empty"));
            };
            (s, y_on)
        } else {
            // SHORT_VBAR_CACHE_MISS (2.2.4.1.1.2.1.1.3): yOn (8 bits),
            // yOff (6 bits), then the pixels; stored at the short cursor.
            let y_on = (header & 0xFF) as usize;
            let y_off = ((header >> 8) & 0x3F) as usize;
            if y_off < y_on {
                return proto(format!("clearcodec: Short V-Bar {y_on}..{y_off}"));
            }
            let raw = r.bytes(3 * (y_off - y_on))?;
            let s: Vec<u32> = raw.as_chunks::<3>().0.iter().map(|&p| bgr(p)).collect();
            let c = self.short_cursor;
            self.short_vbars[c] = Some(s);
            self.short_cursor = (c + 1) % SHORT_VBAR_SLOTS;
            (self.short_vbars[c].as_deref().unwrap_or(&[]), y_on)
        };
        if y_on + short.len() > height {
            return proto(format!(
                "clearcodec: Short V-Bar of {} at {y_on} in a band of {height}",
                short.len()
            ));
        }
        // Background above and below the Short V-Bar; stored as a full V-Bar
        // at the V-Bar cursor.
        let mut v = vec![bkg; height];
        v[y_on..y_on + short.len()].copy_from_slice(short);
        let c = self.vbar_cursor;
        self.vbar_cursor = (c + 1) % VBAR_SLOTS;
        Ok(self.vbars[c].insert(v).as_slice())
    }
}

/// CLEARCODEC_RESIDUAL_DATA (2.2.4.1.1.1): runs of one colour from the
/// top-left corner, at most the bitmap's pixel count.
fn decode_residual(data: &[u8], bm: &mut Bitmap) -> Result<()> {
    let mut r = Reader::new(data);
    let mut pos = 0;
    while r.remaining() > 0 {
        let color = bgr(r.array()?);
        let n = run_length(&mut r)?;
        if n > bm.px.len() - pos {
            return proto(format!(
                "clearcodec: residual runs past {} pixels",
                bm.px.len()
            ));
        }
        bm.px[pos..pos + n].fill(color);
        pos += n;
    }
    Ok(())
}

/// CLEARCODEC_SUBCODECS_DATA (2.2.4.1.1.3).
fn decode_subcodecs(data: &[u8], bm: &mut Bitmap) -> Result<()> {
    let mut r = Reader::new(data);
    while r.remaining() > 0 {
        let x = r.u16()? as usize;
        let y = r.u16()? as usize;
        let w = r.u16()? as usize;
        let h = r.u16()? as usize;
        let len = r.u32()? as usize;
        let id = r.u8()?;
        let bytes = r.bytes(len)?;
        if x + w > bm.w || y + h > bm.h {
            return proto(format!(
                "clearcodec: subcodec {w}x{h} at ({x},{y}) outside {}x{}",
                bm.w, bm.h
            ));
        }
        if len > 3 * w * h {
            return proto(format!("clearcodec: subcodec of {len} bytes for {w}x{h}"));
        }
        let pixels = match id {
            SUBCODEC_UNCOMPRESSED => {
                if len != 3 * w * h {
                    return proto(format!("clearcodec: {len} raw bytes for {w}x{h}"));
                }
                bytes.as_chunks::<3>().0.iter().map(|&p| bgr(p)).collect()
            }
            SUBCODEC_NSCODEC => nsc::decode(bytes, w, h)?,
            SUBCODEC_RLEX => rlex(bytes, w * h)?,
            _ => return proto(format!("clearcodec: subcodec id {id:#x}")),
        };
        // RLEX can end early; what it does not reach keeps the layers below.
        for (i, &p) in pixels.iter().enumerate() {
            bm.px[(y + i / w) * bm.w + x + i % w] = p;
        }
    }
    Ok(())
}

/// CLEARCODEC_SUBCODEC_RLEX (2.2.4.1.1.3.1.1): pixels in raster order, at
/// most `max`.
pub fn rlex(data: &[u8], max: usize) -> Result<Vec<u32>> {
    let mut r = Reader::new(data);
    let count = r.u8()? as usize;
    if count == 0 || count > 0x7F {
        return proto(format!("clearcodec: RLEX palette of {count}"));
    }
    let palette: Vec<u32> = (0..count)
        .map(|_| r.array().map(bgr))
        .collect::<Result<_>>()?;
    // stopIndex takes floor(log2(paletteCount - 1)) + 1 low bits; a palette
    // of one needs none. suiteDepth takes the rest of the byte.
    let bits = usize::BITS - (count - 1).leading_zeros();
    let mut out = Vec::new();
    while r.remaining() > 0 {
        // CLEARCODEC_SUBCODEC_RLEX_SEGMENT (2.2.4.1.1.3.1.1.2).
        let b = r.u8()? as usize;
        let stop = b & ((1 << bits) - 1);
        let depth = b >> bits;
        let run = run_length(&mut r)?;
        if stop >= count || depth > stop {
            return proto(format!(
                "clearcodec: RLEX suite {depth} to {stop} with {count} colours"
            ));
        }
        let start = stop - depth;
        // The start colour `run` times, then the suite start..=stop.
        if run > max - out.len() || depth + 1 > max - out.len() - run {
            return proto(format!("clearcodec: RLEX runs past {max} pixels"));
        }
        out.resize(out.len() + run, palette[start]);
        out.extend_from_slice(&palette[start..=stop]);
    }
    Ok(out)
}

#[cfg(test)]
impl ClearCodec {
    /// Seeds a V-Bar slot, as an earlier PDU would have.
    pub(crate) fn set_vbar(&mut self, index: usize, pixels: Vec<u32>) {
        self.vbars[index] = Some(pixels);
    }

    pub(crate) fn set_cursors(&mut self, vbar: usize, short: usize) {
        (self.vbar_cursor, self.short_cursor) = (vbar, short);
    }

    /// Seeds a glyph slot, as an earlier PDU would have.
    pub(crate) fn set_glyph(&mut self, index: usize, pixels: Vec<u32>) {
        self.glyphs[index] = Some(pixels);
    }
}
