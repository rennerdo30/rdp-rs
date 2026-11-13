//! RDP 6.0 planar bitmap codec, decoder side (MS-RDPEGDI 2.2.2.5.1, 3.1.9).

use crate::cursor::Reader;
use crate::error::{Error, Result};

const FORMAT_CS: u8 = 0x08;
const FORMAT_RLE: u8 = 0x10;
const FORMAT_NA: u8 = 0x20;

/// Decodes a planar bitmap into top-down 0x00RRGGBB pixels.
pub fn decode(src: &[u8], w: usize, h: usize) -> Result<Vec<u32>> {
    let mut r = Reader::new(src);
    let header = r.u8()?;
    if header & 0x07 != 0 || header & FORMAT_CS != 0 {
        return Err(Error::Unsupported(
            "planar YCoCg / chroma subsampling".into(),
        ));
    }
    let rle = header & FORMAT_RLE != 0;
    let plane_count = if header & FORMAT_NA != 0 { 3 } else { 4 };
    let mut planes = Vec::with_capacity(plane_count);
    for _ in 0..plane_count {
        planes.push(if rle {
            rle_plane(&mut r, w, h)?
        } else {
            r.bytes(w * h)?.to_vec()
        });
    }
    let rgb = &planes[plane_count - 3..]; // alpha plane (if any) is ignored
    let mut out = vec![0u32; w * h];
    for y in 0..h {
        let sy = h - 1 - y; // planes are stored bottom-up
        for x in 0..w {
            let i = sy * w + x;
            out[y * w + x] = (rgb[0][i] as u32) << 16 | (rgb[1][i] as u32) << 8 | rgb[2][i] as u32;
        }
    }
    Ok(out)
}

/// One RLE-compressed color plane: first scanline absolute, later scanlines
/// as sign-magnitude deltas against the previous scanline.
fn rle_plane(r: &mut Reader, w: usize, h: usize) -> Result<Vec<u8>> {
    let mut plane = vec![0u8; w * h];
    for y in 0..h {
        let mut x = 0;
        let mut value: i32 = 0;
        while x < w {
            let control = r.u8()?;
            let mut run = (control & 0x0F) as usize;
            let mut raw = (control >> 4) as usize;
            if run == 1 {
                run = raw + 16;
                raw = 0;
            } else if run == 2 {
                run = raw + 32;
                raw = 0;
            }
            if x + raw + run > w {
                return Err(Error::Protocol(
                    "planar RLE segment overruns scanline".into(),
                ));
            }
            for _ in 0..raw {
                let v = r.u8()?;
                if y == 0 {
                    value = v as i32;
                } else if v & 1 != 0 {
                    value = -((v >> 1) as i32) - 1;
                } else {
                    value = (v >> 1) as i32;
                }
                put(&mut plane, w, x, y, value);
                x += 1;
            }
            for _ in 0..run {
                put(&mut plane, w, x, y, value);
                x += 1;
            }
        }
    }
    Ok(plane)
}

fn put(plane: &mut [u8], w: usize, x: usize, y: usize, value: i32) {
    plane[y * w + x] = if y == 0 {
        value as u8
    } else {
        (plane[(y - 1) * w + x] as i32 + value) as u8
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_planes_without_alpha() {
        // 2x1: R, G, B planes.
        let src = [FORMAT_NA, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        assert_eq!(decode(&src, 2, 1).unwrap(), vec![0x103050, 0x204060]);
    }

    #[test]
    fn rle_plane_with_runs_and_deltas() {
        // 4x2 plane. Row 0: raw 5 then run of 3 -> 5 5 5 5.
        // Row 1: raw delta +2 (encoded 4), run 3 -> 7 7 7 7.
        let data = [0x13, 5, 0x13, 4];
        let mut r = Reader::new(&data);
        let p = rle_plane(&mut r, 4, 2).unwrap();
        assert_eq!(p, vec![5, 5, 5, 5, 7, 7, 7, 7]);
        // Negative delta: encoded 3 => -2.
        let data = [0x13, 5, 0x13, 3];
        let mut r = Reader::new(&data);
        assert_eq!(rle_plane(&mut r, 4, 2).unwrap()[4..], [3, 3, 3, 3]);
    }

    #[test]
    fn long_run_control_codes() {
        // control 0x11: run = 1 + 16 = 17 of the current value (0).
        let data = [0x11];
        let mut r = Reader::new(&data);
        assert_eq!(rle_plane(&mut r, 17, 1).unwrap(), vec![0; 17]);
    }
}
