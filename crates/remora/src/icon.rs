//! The app icon, drawn from the same geometry as `assets/logo.svg` (a 256-unit
//! grid): a teal tile with a dark monitor and two chevrons. Drawing it at
//! runtime gives a crisp window and taskbar icon at any size without an image
//! decoder or SVG renderer.

use ffwd_render::{Canvas, Rect};

const TILE: u32 = 0x4fb8c9;
const INK: u32 = 0x0b1a1e;

fn draw(cv: &mut Canvas, size: usize) {
    let k = size as f32 / 256.0;
    let r = |x: f32, y: f32, w: f32, h: f32| {
        Rect::new(
            (x * k).round() as i32,
            (y * k).round() as i32,
            (w * k).round() as i32,
            (h * k).round() as i32,
        )
    };
    cv.fill_round(r(8.0, 8.0, 240.0, 240.0), 56.0 * k, TILE);
    cv.fill_round(r(48.0, 60.0, 160.0, 112.0), 18.0 * k, INK);
    cv.fill(r(114.0, 170.0, 28.0, 22.0), INK);
    cv.fill_round(r(80.0, 188.0, 96.0, 16.0), 8.0 * k, INK);
    for chevron in [
        [(106.0, 98.0), (124.0, 116.0), (106.0, 134.0)],
        [(134.0, 98.0), (152.0, 116.0), (134.0, 134.0)],
    ] {
        let pts: Vec<(f32, f32)> = chevron.iter().map(|&(x, y)| (x * k, y * k)).collect();
        cv.stroke(&pts, 14.0 * k, TILE);
    }
}

/// The icon as straight (non-premultiplied) RGBA bytes. The canvas only blends
/// onto opaque pixels, so it draws twice, on black and on white, and recovers
/// alpha from the difference: a = 1 - (white - black).
pub fn rgba(size: usize) -> Vec<u8> {
    let mut on_black = vec![0u32; size * size];
    let mut on_white = vec![0x00FF_FFFFu32; size * size];
    draw(&mut Canvas::new(&mut on_black, size, size), size);
    draw(&mut Canvas::new(&mut on_white, size, size), size);
    let mut out = Vec::with_capacity(size * size * 4);
    for (&b, &w) in on_black.iter().zip(&on_white) {
        let ch = |p: u32, s: u32| ((p >> s) & 0xFF) as i32;
        let a = (255 - (ch(w, 8) - ch(b, 8))).clamp(0, 255);
        for s in [16, 8, 0] {
            let c = if a == 0 {
                0
            } else {
                (ch(b, s) * 255 / a).min(255)
            };
            out.push(c as u8);
        }
        out.push(a as u8);
    }
    out
}

pub fn window_icon(size: usize) -> Option<winit::window::Icon> {
    winit::window::Icon::from_rgba(rgba(size), size as u32, size as u32).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_are_transparent_and_centre_is_opaque() {
        let px = rgba(64);
        let alpha = |x: usize, y: usize| px[(y * 64 + x) * 4 + 3];
        assert_eq!(alpha(0, 0), 0, "rounded tile corner must be transparent");
        assert_eq!(alpha(32, 32), 255);
        // The tile colour comes back exactly where it is opaque.
        let i = (8 * 64 + 32) * 4; // top edge of the tile, middle
        assert_eq!(&px[i..i + 4], &[0x4f, 0xb8, 0xc9, 255]);
    }
}
