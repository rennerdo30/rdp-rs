//! AVC444 and AVC444v2 view combination (MS-RDPEGFX 3.3.8.3.2, 3.3.8.3.3).
//!
//! A YUV444 frame travels as two YUV420p pictures of the same size: the
//! main view (Y444 plus 2x2-filtered U and V, areas B1 - B3) and the
//! auxiliary view, which carries the chroma samples the main view lacks.
//! AVC444 and AVC444v2 differ only in how the auxiliary view is laid out.
//! Positions here are picture coordinates (origin at the destination
//! rectangle's top-left corner).

use super::h264::{Yuv420Frame, yuv_to_rgb};

/// Layout of the auxiliary (Chroma420) view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// AVC444 (3.3.8.3.2): odd chroma rows interleaved per 16x16
    /// macroblock in the luma plane (U in lines 0 - 7, V in lines 8 - 15),
    /// even rows of odd columns in the chroma planes.
    V1,
    /// AVC444v2 (3.3.8.3.3): odd chroma columns side by side in the luma
    /// plane (U left half, V right half), even columns of odd rows in the
    /// chroma planes (columns 4x in U, 4x + 2 in V; each U left, V right).
    V2,
}

/// The reverse filter is kept only when it changes the main view's value
/// by more than this (3.3.8.3.2, 3.3.8.3.3).
const CUTOFF: i32 = 30;

fn sample(plane: &[u8], stride: usize, w: usize, h: usize, x: usize, y: usize) -> Option<u8> {
    if x < w && y < h {
        plane.get(y * stride + x).copied()
    } else {
        None
    }
}

fn luma(f: &Yuv420Frame, x: usize, y: usize) -> Option<u8> {
    sample(&f.y, f.y_stride, f.width, f.height, x, y)
}

fn chroma(f: &Yuv420Frame, plane: &[u8], x: usize, y: usize) -> Option<u8> {
    let (w, h) = (f.width.div_ceil(2), f.height.div_ceil(2));
    sample(plane, f.uv_stride, w, h, x, y)
}

/// U444 (`v` false) or V444 at (x, y) with x or y odd: the sample the
/// auxiliary view carries for it. `None` outside the picture.
fn aux_sample(aux: &Yuv420Frame, layout: Layout, v: bool, x: usize, y: usize) -> Option<u8> {
    if x >= aux.width || y >= aux.height {
        return None;
    }
    match layout {
        Layout::V1 => {
            if y % 2 == 1 {
                // B4/B5: Y420(x, y) = U444(x, 2y + 1), Y420(x, 8 + y) =
                // V444(x, 2y + 1), y in 0..8 within each macroblock row.
                let k = y / 2;
                let row = 16 * (k / 8) + k % 8 + if v { 8 } else { 0 };
                luma(aux, x, row)
            } else {
                // B6/B7: U420(x, y) = U444(2x + 1, 2y), V420 likewise V444.
                chroma(aux, if v { &aux.v } else { &aux.u }, x / 2, y / 2)
            }
        }
        Layout::V2 => {
            if x % 2 == 1 {
                // B4/B5: Y420(x, y) = U444(2x + 1, y),
                // Y420(W/2 + x, y) = V444(2x + 1, y).
                let col = x / 2 + if v { aux.width / 2 } else { 0 };
                luma(aux, col, y)
            } else {
                // B6 - B9: U420(x, y) = U444(4x, 2y + 1),
                // U420(W/4 + x, y) = V444(4x, 2y + 1), and V420 the same
                // for column 4x + 2.
                let col = x / 4 + if v { aux.width / 4 } else { 0 };
                let plane = if x.is_multiple_of(4) { &aux.u } else { &aux.v };
                chroma(aux, plane, col, y / 2)
            }
        }
    }
}

/// One chroma component at (x, y). `filtered` is the main view's sample
/// for the 2x2 block; at even/even positions it is Ũ444(2x, 2y), the mean
/// of the block, and the reverse filter recovers the sample itself:
/// U444(2x, 2y) = 4 Ũ444(2x, 2y) - U444(2x + 1, 2y) - U444(2x, 2y + 1) -
/// U444(2x + 1, 2y + 1), kept only past the cutoff.
fn component(filtered: u8, aux: &Yuv420Frame, layout: Layout, v: bool, x: usize, y: usize) -> u8 {
    if x % 2 == 1 || y % 2 == 1 {
        return aux_sample(aux, layout, v, x, y).unwrap_or(filtered);
    }
    let at = |dx, dy| aux_sample(aux, layout, v, x + dx, y + dy).map(i32::from);
    let (Some(a), Some(b), Some(c)) = (at(1, 0), at(0, 1), at(1, 1)) else {
        // A block cut by the picture edge: no filter to reverse.
        return filtered;
    };
    let f = i32::from(filtered);
    let reversed = 4 * f - a - b - c;
    if (reversed - f).abs() > CUTOFF {
        reversed.clamp(0, 255) as u8
    } else {
        filtered
    }
}

/// The YUV444 sample (Y, U, V) at picture position (x, y), combined from
/// the main and auxiliary views; the caller keeps (x, y) inside `main`.
pub fn yuv444(
    main: &Yuv420Frame,
    aux: &Yuv420Frame,
    layout: Layout,
    x: usize,
    y: usize,
) -> (u8, u8, u8) {
    let c = (y / 2) * main.uv_stride + x / 2;
    (
        main.y[y * main.y_stride + x],
        component(main.u[c], aux, layout, false, x, y),
        component(main.v[c], aux, layout, true, x, y),
    )
}

/// The 0x00RRGGBB pixel at (x, y) of the combined frame (3.3.8.3.1).
pub fn rgb444(main: &Yuv420Frame, aux: &Yuv420Frame, layout: Layout, x: usize, y: usize) -> u32 {
    let (y, u, v) = yuv444(main, aux, layout, x, y);
    yuv_to_rgb(y, u, v)
}
