//! The Remora mark: a teal tile with a dark remora fish whose body is a
//! screen (light glass in a dark bezel), with a forked tail, the remora's
//! suction disc on its back and an eye on its head. Drawn from the same
//! 256-unit geometry as `assets/logo.svg`.
//!
//! Every shape is a signed distance field, so each pixel gets exact
//! anti-aliased coverage at any size without an image decoder or SVG
//! renderer. Small sizes are hinted: the tile fills the whole square below
//! 48 px, the eye sits on a pixel centre, and the disc's ridges and the glass
//! highlight appear only where they have enough pixels to read.
//!
//! The same mark is the window and taskbar icon, `assets/remora.ico` and the
//! sidebar logo ([`crate::kit::Kit::logo`]), in every theme.

/// The dark theme's accent (`theme::dark::ACCENT`), the ink on it
/// (`accent_text`) and a light glass tint of the accent.
const TILE: u32 = 0x2ec4b6;
const INK: u32 = 0x03211d;
const GLASS: u32 = 0xd6f7f3;

type P = (f32, f32);

fn len(x: f32, y: f32) -> f32 {
    (x * x + y * y).sqrt()
}

/// Rounded box from `x0,y0` to `x1,y1` with corner radii
/// `[top-left, top-right, bottom-right, bottom-left]`.
fn round_box(p: P, x0: f32, y0: f32, x1: f32, y1: f32, r: [f32; 4]) -> f32 {
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    let (hx, hy) = ((x1 - x0) / 2.0, (y1 - y0) / 2.0);
    let (px, py) = (p.0 - cx, p.1 - cy);
    let r = match (px >= 0.0, py >= 0.0) {
        (false, false) => r[0],
        (true, false) => r[1],
        (true, true) => r[2],
        (false, true) => r[3],
    };
    let qx = px.abs() - hx + r;
    let qy = py.abs() - hy + r;
    qx.max(qy).min(0.0) + len(qx.max(0.0), qy.max(0.0)) - r
}

fn circle(p: P, c: P, r: f32) -> f32 {
    len(p.0 - c.0, p.1 - c.1) - r
}

/// Exact distance to a simple polygon, negative inside.
fn polygon(p: P, v: &[P]) -> f32 {
    let mut d = f32::MAX;
    let mut inside = false;
    let mut j = v.len() - 1;
    for i in 0..v.len() {
        let (a, b) = (v[i], v[j]);
        let (ex, ey) = (b.0 - a.0, b.1 - a.1);
        let (wx, wy) = (p.0 - a.0, p.1 - a.1);
        let t = ((wx * ex + wy * ey) / (ex * ex + ey * ey)).clamp(0.0, 1.0);
        d = d.min(len(wx - ex * t, wy - ey * t));
        if (a.1 > p.1) != (b.1 > p.1) && p.0 < a.0 + (p.1 - a.1) * ex / ey {
            inside = !inside;
        }
        j = i;
    }
    if inside { -d } else { d }
}

/// Smooth union: rounds the joint between two shapes over `k` units.
fn smin(a: f32, b: f32, k: f32) -> f32 {
    let h = (0.5 + 0.5 * (b - a) / k).clamp(0.0, 1.0);
    b + (a - b) * h - k * h * (1.0 - h)
}

/// The forked tail, on the left (the fish swims to the right).
/// Grown by [`TAIL_ROUND`], which rounds the lobe tips.
const TAIL: [P; 5] = [
    (82.0, 108.0),
    (34.0, 70.0),
    (50.0, 128.0),
    (34.0, 186.0),
    (82.0, 148.0),
];
const TAIL_ROUND: f32 = 6.0;

// Horizontal and vertical edges of the body and the glass sit on multiples
// of 16 units: whole pixels at 16 px, so the smallest icon stays crisp.

/// The fish in ink: body (the screen), tail and the suction disc.
fn fish(p: P) -> f32 {
    let body = round_box(p, 64.0, 80.0, 208.0, 176.0, [28.0, 52.0, 48.0, 28.0]);
    let tail = polygon(p, &TAIL) - TAIL_ROUND;
    // The remora's sucking disc, a flat oval on top of the head.
    let disc = round_box(p, 110.0, 60.0, 188.0, 88.0, [14.0; 4]);
    smin(smin(body, tail, 14.0), disc, 5.0)
}

/// The screen glass inside the body, behind the head.
fn glass(p: P) -> f32 {
    round_box(p, 80.0, 96.0, 160.0, 160.0, [10.0; 4])
}

const EYE: P = (184.0, 114.0);
const EYE_R: f32 = 10.0;

/// The ridges across the disc (tile colour), only at larger sizes.
fn ridges(p: P) -> f32 {
    let mut d = f32::MAX;
    for x in [128.0, 142.0, 156.0, 170.0] {
        d = d.min(round_box(p, x - 3.0, 67.0, x + 3.0, 81.0, [3.0; 4]));
    }
    d
}

fn mix(a: u32, b: u32, t: f32) -> u32 {
    let t = t.clamp(0.0, 1.0);
    let ch = |s: u32| {
        let (x, y) = (((a >> s) & 0xff) as f32, ((b >> s) & 0xff) as f32);
        ((x + (y - x) * t).round() as u32) << s
    };
    ch(16) | ch(8) | ch(0)
}

/// The mark at `size` x `size` as (0xRRGGBB, alpha 0..=255) per pixel, row by
/// row. The colour is straight (not premultiplied).
fn render(size: usize) -> Vec<(u32, u8)> {
    let unit = 256.0 / size.max(1) as f32; // grid units per pixel
    let cov = |d: f32| (0.5 - d / unit).clamp(0.0, 1.0);
    let large = size >= 48;
    let inset = if large { 8.0 } else { 0.0 };
    let radius = if large { 56.0 } else { 64.0 };
    let top = mix(TILE, 0xffffff, 0.10);
    let bottom = mix(TILE, 0x000000, 0.08);
    let highlight = mix(GLASS, 0xffffff, 0.6);
    // The eye snapped to the pixel grid: a dot narrower than two pixels on a
    // pixel centre (one clean pixel at 16 px), a wider one on a pixel corner.
    let snap = |v: f32| {
        if 2.0 * EYE_R / unit < 2.0 {
            ((v / unit).floor() + 0.5) * unit
        } else {
            (v / unit).round() * unit
        }
    };
    let eye = (snap(EYE.0), snap(EYE.1));
    let mut out = Vec::with_capacity(size * size);
    for y in 0..size {
        for x in 0..size {
            let p = ((x as f32 + 0.5) * unit, (y as f32 + 0.5) * unit);
            let a = cov(round_box(
                p,
                inset,
                inset,
                256.0 - inset,
                256.0 - inset,
                [radius; 4],
            ));
            if a <= 0.0 {
                out.push((0, 0));
                continue;
            }
            let mut col = mix(top, bottom, p.1 / 256.0);
            col = mix(col, INK, cov(fish(p)));
            col = mix(col, GLASS, cov(glass(p)));
            if large {
                // A soft diagonal reflection across the upper glass.
                let band = polygon(p, &[(94.0, 96.0), (126.0, 96.0), (94.0, 128.0)]);
                col = mix(col, highlight, cov(band.max(glass(p))) * 0.7);
                col = mix(col, TILE, cov(ridges(p)));
            }
            col = mix(col, GLASS, cov(circle(p, eye, EYE_R)));
            out.push((col, (a * 255.0).round() as u8));
        }
    }
    out
}

/// The app icon as straight (non-premultiplied) RGBA bytes.
pub fn rgba(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size * size * 4);
    for (col, a) in render(size) {
        out.extend_from_slice(&[(col >> 16) as u8, (col >> 8) as u8, col as u8, a]);
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
    fn corners_are_transparent_and_the_fish_reads() {
        for size in [16, 64, 256] {
            let px = rgba(size);
            let at = |gx: f32, gy: f32| {
                let (x, y) = (
                    (gx / 256.0 * size as f32) as usize,
                    (gy / 256.0 * size as f32) as usize,
                );
                let i = (y * size + x) * 4;
                [px[i], px[i + 1], px[i + 2], px[i + 3]]
            };
            assert_eq!(
                at(0.0, 0.0)[3],
                0,
                "{size}: rounded tile corner is transparent"
            );
            let tile = at(128.0, 30.0);
            assert_eq!(tile[3], 255, "{size}: tile is opaque");
            let body = at(168.0, 140.0);
            let glass = at(122.0, 136.0);
            let lum = |c: [u8; 4]| c[0] as u32 + c[1] as u32 + c[2] as u32;
            assert!(lum(body) < 120, "{size}: the head is ink: {body:?}");
            assert!(
                lum(glass) > lum(tile),
                "{size}: glass is lighter than the tile"
            );
            assert!(
                lum(tile) > lum(body) + 200,
                "{size}: tile and fish contrast"
            );
        }
    }
}
