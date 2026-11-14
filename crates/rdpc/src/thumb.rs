//! Session thumbnails for the Home view: a running session's framebuffer
//! scaled down once into a small cached RGBA picture, which the Home cards
//! draw with `draw_rgba_scaled`.
//!
//! Cost rule: a thumbnail is made only when its session reports damage
//! while the Home view is visible, at most twice a second per session, and
//! never by a timer loop (see `App::thumb_frame`). Making one reads every
//! source pixel once (an area average), so the small picture has no
//! nearest-neighbour shimmer.

/// A scaled-down picture: `w` x `h`, straight RGBA, opaque.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Thumb {
    pub w: usize,
    pub h: usize,
    pub rgba: Vec<u8>,
}

/// The largest size with the source's aspect ratio that fits `max_w` x
/// `max_h` and is no larger than the source (never 0 for a non-empty source).
pub fn fit(src_w: usize, src_h: usize, max_w: usize, max_h: usize) -> (usize, usize) {
    if src_w == 0 || src_h == 0 || max_w == 0 || max_h == 0 {
        return (0, 0);
    }
    let (mw, mh) = (max_w.min(src_w), max_h.min(src_h));
    // Width-limited, unless that makes it too tall.
    let h = (src_h * mw).div_ceil(src_w).max(1);
    if h <= mh {
        (mw, h.min(mh))
    } else {
        ((src_w * mh).div_ceil(src_h).clamp(1, mw), mh)
    }
}

/// Area-average downscale of 0RGB pixels (`src_w` x `src_h`, row stride
/// `src_w`) into `w` x `h` straight RGBA. Every source pixel lands in
/// exactly one destination box, so a flat colour stays exact.
pub fn downscale(src: &[u32], src_w: usize, src_h: usize, w: usize, h: usize) -> Thumb {
    if w == 0 || h == 0 || src_w == 0 || src_h == 0 || src.len() < src_w * src_h {
        return Thumb::default();
    }
    // Box edges: destination x covers source columns xs[x]..xs[x + 1]; a
    // box is at least one pixel wide even when upscaling.
    let edges = |n: usize, d: usize| -> Vec<(usize, usize)> {
        (0..d)
            .map(|i| {
                let a = i * n / d;
                let b = ((i + 1) * n / d).max(a + 1).min(n);
                (a.min(n - 1), b)
            })
            .collect()
    };
    let xs = edges(src_w, w);
    let ys = edges(src_h, h);
    let mut rgba = vec![0u8; w * h * 4];
    let mut sums = vec![[0u32; 3]; w];
    for (dy, &(y0, y1)) in ys.iter().enumerate() {
        sums.iter_mut().for_each(|s| *s = [0; 3]);
        for y in y0..y1 {
            let row = &src[y * src_w..(y + 1) * src_w];
            for (dx, &(x0, x1)) in xs.iter().enumerate() {
                let s = &mut sums[dx];
                for &p in &row[x0..x1] {
                    s[0] += (p >> 16) & 0xff;
                    s[1] += (p >> 8) & 0xff;
                    s[2] += p & 0xff;
                }
            }
        }
        let rows = (y1 - y0) as u32;
        for (dx, &(x0, x1)) in xs.iter().enumerate() {
            let n = rows * (x1 - x0) as u32;
            let o = (dy * w + dx) * 4;
            let s = sums[dx];
            rgba[o] = ((s[0] + n / 2) / n) as u8;
            rgba[o + 1] = ((s[1] + n / 2) / n) as u8;
            rgba[o + 2] = ((s[2] + n / 2) / n) as u8;
            rgba[o + 3] = 255;
        }
    }
    Thumb { w, h, rgba }
}

/// A thumbnail of a framebuffer that fits `max_w` x `max_h`.
pub fn of_framebuffer(fb: &rdp::Framebuffer, max_w: usize, max_h: usize) -> Thumb {
    let (w, h) = fit(fb.width, fb.height, max_w, max_h);
    downscale(&fb.pixels, fb.width, fb.height, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn px(t: &Thumb, x: usize, y: usize) -> [u8; 4] {
        let o = (y * t.w + x) * 4;
        [t.rgba[o], t.rgba[o + 1], t.rgba[o + 2], t.rgba[o + 3]]
    }

    #[test]
    fn a_four_by_four_averages_into_two_by_two() {
        // Quadrants: red, green / blue, and a black-white checker (grey).
        let mut src = vec![0u32; 16];
        for y in 0..4 {
            for x in 0..4 {
                src[y * 4 + x] = match (x < 2, y < 2) {
                    (true, true) => 0xff0000,
                    (false, true) => 0x00ff00,
                    (true, false) => 0x0000ff,
                    (false, false) if (x + y) % 2 == 0 => 0xffffff,
                    _ => 0x000000,
                };
            }
        }
        let t = downscale(&src, 4, 4, 2, 2);
        assert_eq!((t.w, t.h, t.rgba.len()), (2, 2, 16));
        assert_eq!(px(&t, 0, 0), [255, 0, 0, 255]);
        assert_eq!(px(&t, 1, 0), [0, 255, 0, 255]);
        assert_eq!(px(&t, 0, 1), [0, 0, 255, 255]);
        assert_eq!(px(&t, 1, 1), [128, 128, 128, 255], "averaged, not sampled");
    }

    #[test]
    fn uneven_boxes_cover_every_pixel_once() {
        // 5 x 3 into 2 x 1: columns 0..2 and 2..5; a bright last column
        // must reach the right half only.
        let mut src = vec![0u32; 15];
        for y in 0..3 {
            src[y * 5 + 4] = 0x0000ff;
        }
        let t = downscale(&src, 5, 3, 2, 1);
        assert_eq!(px(&t, 0, 0), [0, 0, 0, 255]);
        assert_eq!(px(&t, 1, 0), [0, 0, 85, 255], "255 / 3 columns");
    }

    #[test]
    fn fit_keeps_the_aspect_ratio() {
        assert_eq!(fit(1920, 1080, 320, 320), (320, 180));
        assert_eq!(fit(1080, 1920, 320, 180), (102, 180));
        assert_eq!(fit(100, 50, 320, 180), (100, 50), "never upscales");
        assert_eq!(fit(0, 50, 320, 180), (0, 0));
        assert_eq!(downscale(&[], 0, 0, 2, 2), Thumb::default());
    }
}
