//! NSCodec decoder (MS-RDPNSC), used as a ClearCodec subcodec
//! (MS-RDPEGFX 2.2.4.1.1.3.1, subCodecId 0x01).
//!
//! An NSCODEC_BITMAP_STREAM (MS-RDPNSC 2.2.2) carries four planes: luma,
//! orange chroma, green chroma and alpha, each raw or run-length encoded
//! (2.2.2.1). Decoding (3.1.8.4) recovers the chroma values from the colour
//! loss level, super-samples them when chroma subsampling is in use and
//! converts AYCoCg to RGB (MS-RDPEGDI 3.1.9.1.2 - 3.1.9.1.4). The alpha
//! plane is parsed and dropped: GFX surfaces are opaque here.

use crate::cursor::Reader;
use crate::error::{Result, proto};

/// Decodes an NSCODEC_BITMAP_STREAM of `width` x `height` pixels into
/// top-down 0x00RRGGBB pixels.
pub fn decode(data: &[u8], width: usize, height: usize) -> Result<Vec<u32>> {
    let mut r = Reader::new(data);
    let luma_len = r.u32()? as usize;
    let co_len = r.u32()? as usize;
    let cg_len = r.u32()? as usize;
    let alpha_len = r.u32()? as usize;
    let cll = r.u8()?;
    let subsampled = r.u8()? != 0;
    r.skip(2)?; // reserved
    if !(1..=7).contains(&cll) {
        return proto(format!("nscodec: colour loss level {cll}"));
    }
    // Plane sizes (2.2.2): with subsampling the luma rows are padded to a
    // multiple of 8 and the chroma planes are half size each way (3.1.8.2).
    let (luma_w, chroma_w, chroma_h) = if subsampled {
        let padded = width.div_ceil(8) * 8;
        (padded, padded / 2, height.div_ceil(2))
    } else {
        (width, width, height)
    };
    let luma = plane(r.bytes(luma_len)?, luma_w * height, "luma")?;
    let co = plane(r.bytes(co_len)?, chroma_w * chroma_h, "orange chroma")?;
    let cg = plane(r.bytes(cg_len)?, chroma_w * chroma_h, "green chroma")?;
    if alpha_len > width * height {
        return proto(format!(
            "nscodec: alpha plane of {alpha_len} bytes for {width}x{height}"
        ));
    }
    r.skip(alpha_len)?;

    let mut out = Vec::with_capacity(width * height);
    for y in 0..height {
        for x in 0..width {
            let c = if subsampled {
                (y / 2) * chroma_w + x / 2
            } else {
                y * width + x
            };
            let yy = luma[y * luma_w + x] as i32;
            out.push(ycocg_to_rgb(yy, chroma(co[c], cll), chroma(cg[c], cll)));
        }
    }
    Ok(out)
}

/// Chroma recovery (MS-RDPEGDI 3.1.9.1.4): shift the reduced value back by
/// the colour loss level, then read it as the 9-bit two's complement
/// chroma value (3.1.9.1.2).
fn chroma(v: u8, cll: u8) -> i32 {
    let nine = ((v as i32) << cll) & 0x1FF;
    if nine & 0x100 != 0 {
        nine - 0x200
    } else {
        nine
    }
}

/// Inverse AYCoCg transform (MS-RDPEGDI 3.1.9.1.2), clamped to 0..=255.
/// Recovered chroma is even (CLL >= 1), so the halves are exact.
fn ycocg_to_rgb(y: i32, co: i32, cg: i32) -> u32 {
    let clamp = |v: i32| v.clamp(0, 255) as u32;
    let r = clamp(y + co / 2 - cg / 2);
    let g = clamp(y + cg / 2);
    let b = clamp(y - co / 2 - cg / 2);
    r << 16 | g << 8 | b
}

/// One colour plane (2.2.2): raw when its byte count equals the expected
/// size, else NSCODEC_RLE_SEGMENTS (2.2.2.1): run and literal segments,
/// then the last four raw bytes of the plane (EndData).
fn plane(data: &[u8], expected: usize, what: &str) -> Result<Vec<u8>> {
    if data.len() == expected {
        return Ok(data.to_vec());
    }
    if data.len() > expected || data.len() < 4 || expected < 4 {
        return proto(format!(
            "nscodec: {what} plane of {} bytes, {expected} expected",
            data.len()
        ));
    }
    let (segments, end) = data.split_at(data.len() - 4);
    let target = expected - 4;
    let mut out = Vec::with_capacity(expected);
    let mut i = 0;
    while i < segments.len() {
        let v = segments[i];
        let n = if segments.get(i + 1) == Some(&v) {
            // NSCODEC_RLE_RUN_SEGMENT (2.2.2.2.1): value, value, factor.
            let Some(&f1) = segments.get(i + 2) else {
                return proto(format!("nscodec: {what} run truncated"));
            };
            i += 3;
            if f1 < 0xFF {
                f1 as usize + 2
            } else {
                let Some(b) = segments.get(i..i + 4) else {
                    return proto(format!("nscodec: {what} run truncated"));
                };
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
        } else {
            // NSCODEC_RLE_LITERAL_SEGMENT (2.2.2.2.2).
            i += 1;
            1
        };
        if n > target - out.len() {
            return proto(format!("nscodec: {what} plane overruns"));
        }
        out.resize(out.len() + n, v);
    }
    if out.len() != target {
        return proto(format!(
            "nscodec: {what} plane decodes to {} of {target} bytes",
            out.len()
        ));
    }
    out.extend_from_slice(end);
    Ok(out)
}

#[cfg(test)]
pub(crate) fn rle_plane(data: &[u8], expected: usize) -> Result<Vec<u8>> {
    plane(data, expected, "test")
}
