//! Rasterisation for the drawing orders: raster operations, brushes,
//! blits, lines, polygons, ellipses and glyphs on a 0x00RRGGBB surface.

/// A drawing target: the framebuffer or an offscreen bitmap.
pub struct Surface<'a> {
    pub px: &'a mut [u32],
    pub w: usize,
    pub h: usize,
}

/// A clip rectangle, exclusive right/bottom. May be empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clip {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

impl Clip {
    pub fn new(x0: i32, y0: i32, x1: i32, y1: i32) -> Self {
        Self { x0, y0, x1, y1 }
    }

    /// From a left/top/width/height rectangle.
    pub fn rect(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self::new(x, y, x.saturating_add(w), y.saturating_add(h))
    }

    /// From an inclusive left/top/right/bottom rectangle.
    pub fn inclusive(l: i32, t: i32, r: i32, b: i32) -> Self {
        Self::new(l, t, r.saturating_add(1), b.saturating_add(1))
    }

    pub fn intersect(self, o: Clip) -> Clip {
        Clip::new(
            self.x0.max(o.x0),
            self.y0.max(o.y0),
            self.x1.min(o.x1),
            self.y1.min(o.y1),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.x1 <= self.x0 || self.y1 <= self.y0
    }

    pub fn union(self, o: Clip) -> Clip {
        if self.is_empty() {
            return o;
        }
        if o.is_empty() {
            return self;
        }
        Clip::new(
            self.x0.min(o.x0),
            self.y0.min(o.y0),
            self.x1.max(o.x1),
            self.y1.max(o.y1),
        )
    }
}

impl Surface<'_> {
    pub fn bounds(&self) -> Clip {
        Clip::new(0, 0, self.w as i32, self.h as i32)
    }

    /// `clip` limited to the surface.
    pub fn limit(&self, clip: Clip) -> Clip {
        clip.intersect(self.bounds())
    }

    fn at(&mut self, x: i32, y: i32) -> &mut u32 {
        &mut self.px[y as usize * self.w + x as usize]
    }
}

pub const ROP3_BLACKNESS: u8 = 0x00;
pub const ROP3_SRCCOPY: u8 = 0xCC;
pub const ROP3_PATCOPY: u8 = 0xF0;

/// Applies a ternary raster operation (MS-RDPEGDI 2.2.2.2.1.1.1.7) to
/// pattern, source and destination. The rop byte is the operation's truth
/// table: bit (P<<2 | S<<1 | D) gives the result, so every one of the 256
/// operations is exact; the common ones take a fast path.
#[inline]
pub fn rop3(rop: u8, p: u32, s: u32, d: u32) -> u32 {
    let v = match rop {
        0x00 => 0,                  // BLACKNESS
        0xFF => 0x00FF_FFFF,        // WHITENESS
        0xCC => s,                  // SRCCOPY
        0xF0 => p,                  // PATCOPY
        0xAA => d,                  // no-op
        0x55 => !d,                 // DSTINVERT
        0x5A => p ^ d,              // PATINVERT
        0xEE => s | d,              // SRCPAINT
        0x88 => s & d,              // SRCAND
        0x66 => s ^ d,              // SRCINVERT
        0xC0 => p & s,              // MERGECOPY
        0x33 => !s,                 // NOTSRCCOPY
        0xBB => !s | d,             // MERGEPAINT
        0x11 => !(s | d),           // NOTSRCERASE
        0x44 => s & !d,             // SRCERASE
        0xFB => p | !s | d,         // PATPAINT
        0xB8 => (s & d) | (!s & p), // PSDPxax: destination where the source is set
        0xE2 => (s & p) | (!s & d), // DSPDxax: pattern where the source is set
        _ => rop3_generic(rop, p, s, d),
    };
    v & 0x00FF_FFFF
}

fn rop3_generic(rop: u8, p: u32, s: u32, d: u32) -> u32 {
    let mut out = 0;
    for i in 0..8 {
        if rop >> i & 1 != 0 {
            let pm = if i & 4 != 0 { p } else { !p };
            let sm = if i & 2 != 0 { s } else { !s };
            let dm = if i & 1 != 0 { d } else { !d };
            out |= pm & sm & dm;
        }
    }
    out
}

/// The ROP3 equivalent of a binary raster operation R2_* (1..=16, MS-RDPEGDI
/// 2.2.2.2.1.1.1.6) over pen/pattern and destination. Out-of-range codes
/// map to R2_COPYPEN.
pub fn rop2_to_rop3(rop2: u8) -> u8 {
    let t = if (1..=16).contains(&rop2) {
        rop2 - 1
    } else {
        12
    };
    let mut rop = 0u8;
    for i in 0..8 {
        let p = (i >> 2) & 1;
        let d = i & 1;
        if t >> (p << 1 | d) & 1 != 0 {
            rop |= 1 << i;
        }
    }
    rop
}

/// True if the operation reads the source operand.
pub fn rop_uses_source(rop: u8) -> bool {
    (rop >> 2 ^ rop) & 0x33 != 0
}

/// A brush: solid, or an 8x8 pattern anchored at the brush origin.
#[derive(Clone, Debug, PartialEq)]
pub enum Pattern {
    Solid(u32),
    /// 8x8 pixels, row-major top-down, plus origin; `transparent` marks
    /// pixels a transparent background mode must leave alone.
    Bitmap {
        px: Box<[u32; 64]>,
        transparent: Option<Box<[bool; 64]>>,
        org_x: i32,
        org_y: i32,
    },
}

impl Pattern {
    /// A monochrome 8x8 brush; `rows` top-down, MSB = leftmost. Set bits
    /// take `bg`, clear bits `fg` (GDI pattern brush semantics); with
    /// `transparent_bg` the set bits are not drawn.
    pub fn mono(rows: [u8; 8], fg: u32, bg: u32, org: (i32, i32), transparent_bg: bool) -> Self {
        let mut px = Box::new([0u32; 64]);
        let mut tr = Box::new([false; 64]);
        for (y, row) in rows.iter().enumerate() {
            for x in 0..8 {
                let set = row & (0x80 >> x) != 0;
                px[y * 8 + x] = if set { bg } else { fg };
                tr[y * 8 + x] = set;
            }
        }
        Pattern::Bitmap {
            px,
            transparent: transparent_bg.then_some(tr),
            org_x: org.0,
            org_y: org.1,
        }
    }

    #[inline]
    fn at(&self, x: i32, y: i32) -> (u32, bool) {
        match self {
            Pattern::Solid(c) => (*c, false),
            Pattern::Bitmap {
                px,
                transparent,
                org_x,
                org_y,
            } => {
                let i = ((y - org_y) & 7) as usize * 8 + ((x - org_x) & 7) as usize;
                (px[i], transparent.as_ref().is_some_and(|t| t[i]))
            }
        }
    }
}

/// Source pixels for a blit: `w` x `h`, top-down.
pub struct Source<'a> {
    pub px: &'a [u32],
    pub w: usize,
    pub h: usize,
}

/// Applies `rop` over the rectangle `dst` (clipped by `clip`) with the
/// pattern and, when the rop reads it, the source at (`sx`, `sy`) mapped to
/// the rectangle's top-left. Source pixels outside the source read as 0.
/// Returns the area written.
pub fn blt(
    s: &mut Surface,
    clip: Clip,
    dst: Clip,
    rop: u8,
    pat: &Pattern,
    src: Option<(&Source, i32, i32)>,
) -> Clip {
    let area = s.limit(clip.intersect(dst));
    if area.is_empty() {
        return area;
    }
    // Fast paths for the operations nearly every order uses.
    if let (ROP3_PATCOPY, Pattern::Solid(c)) = (rop, pat) {
        let c = c & 0x00FF_FFFF;
        for y in area.y0..area.y1 {
            let row = y as usize * s.w;
            s.px[row + area.x0 as usize..row + area.x1 as usize].fill(c);
        }
        return area;
    }
    if rop == ROP3_SRCCOPY
        && let Some((src, sx, sy)) = src
    {
        for y in area.y0..area.y1 {
            let syy = sy + (y - dst.y0);
            for x in area.x0..area.x1 {
                let sxx = sx + (x - dst.x0);
                *s.at(x, y) = src_px(src, sxx, syy);
            }
        }
        return area;
    }
    for y in area.y0..area.y1 {
        for x in area.x0..area.x1 {
            let (p, skip) = pat.at(x, y);
            if skip {
                continue;
            }
            let sv = match src {
                Some((src, sx, sy)) => src_px(src, sx + (x - dst.x0), sy + (y - dst.y0)),
                None => 0,
            };
            let d = s.at(x, y);
            *d = rop3(rop, p, sv, *d);
        }
    }
    area
}

#[inline]
fn src_px(src: &Source, x: i32, y: i32) -> u32 {
    if x < 0 || y < 0 || x as usize >= src.w || y as usize >= src.h {
        return 0;
    }
    src.px[y as usize * src.w + x as usize]
}

/// Sets one pixel through a ROP3 with a solid pattern colour.
#[inline]
fn plot(s: &mut Surface, clip: Clip, x: i32, y: i32, rop: u8, c: u32) {
    if x >= clip.x0 && x < clip.x1 && y >= clip.y0 && y < clip.y1 {
        let d = s.at(x, y);
        *d = rop3(rop, c, 0, *d);
    }
}

/// A one-pixel line from (x0, y0) to (x1, y1), excluding the end point as
/// GDI's LineTo does. Returns the bounding area touched.
pub fn line(
    s: &mut Surface,
    clip: Clip,
    from: (i32, i32),
    to: (i32, i32),
    rop: u8,
    c: u32,
) -> Clip {
    let clip = s.limit(clip);
    let (mut x, mut y) = from;
    let dx = (to.0 - x).abs();
    let dy = -(to.1 - y).abs();
    let sx = if x < to.0 { 1 } else { -1 };
    let sy = if y < to.1 { 1 } else { -1 };
    let mut err = dx + dy;
    // Bounded by the clip so a far-away line cannot spin for long.
    let mut steps = dx.max(-dy) as i64;
    while (x, y) != to && steps > 0 {
        plot(s, clip, x, y, rop, c);
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
        steps -= 1;
    }
    let bbox = Clip::new(
        from.0.min(to.0),
        from.1.min(to.1),
        from.0.max(to.0) + 1,
        from.1.max(to.1) + 1,
    );
    bbox.intersect(clip)
}

/// Fills a polygon (closed implicitly) with even-odd (`winding` false,
/// ALTERNATE) or non-zero (WINDING) rule, sampling pixel centres
/// (MS-RDPEGDI 2.2.2.2.1.1.1.9).
pub fn fill_polygon(
    s: &mut Surface,
    clip: Clip,
    pts: &[(i32, i32)],
    winding: bool,
    rop: u8,
    pat: &Pattern,
) -> Clip {
    let clip = s.limit(clip);
    if pts.len() < 3 || clip.is_empty() {
        return Clip::new(0, 0, 0, 0);
    }
    let miny = pts.iter().map(|p| p.1).min().unwrap().max(clip.y0);
    let maxy = pts.iter().map(|p| p.1).max().unwrap().min(clip.y1 - 1);
    let mut touched = Clip::new(0, 0, 0, 0);
    let mut xs: Vec<(f64, i32)> = Vec::new();
    for y in miny..=maxy {
        let fy = y as f64 + 0.5;
        xs.clear();
        for i in 0..pts.len() {
            let (ax, ay) = pts[i];
            let (bx, by) = pts[(i + 1) % pts.len()];
            if ay == by {
                continue;
            }
            let (lo, hi, dir) = if ay < by { (ay, by, 1) } else { (by, ay, -1) };
            if fy < lo as f64 || fy >= hi as f64 {
                continue;
            }
            let t = (fy - ay as f64) / (by - ay) as f64;
            xs.push((ax as f64 + t * (bx - ax) as f64, dir));
        }
        xs.sort_by(|a, b| a.0.total_cmp(&b.0));
        // Between consecutive crossings the fill rule decides.
        let mut wind = 0;
        for i in 0..xs.len().saturating_sub(1) {
            wind += if winding { xs[i].1 } else { 1 };
            let inside = if winding { wind != 0 } else { wind % 2 != 0 };
            if inside {
                let x0 = (xs[i].0 - 0.5).ceil() as i32;
                let x1 = (xs[i + 1].0 - 0.5).ceil() as i32;
                let span = Clip::new(x0, y, x1, y + 1);
                touched = touched.union(blt(s, clip, span, rop, pat, None));
            }
        }
    }
    touched
}

/// An ellipse inside the inclusive rectangle; filled with `pat`, or only
/// its outline in colour `pat`'s solid colour when `fill` is false
/// (MS-RDPEGDI 2.2.2.2.1.1.2.19/20).
pub fn ellipse(
    s: &mut Surface,
    clip: Clip,
    rect: Clip,
    fill: bool,
    rop: u8,
    pat: &Pattern,
) -> Clip {
    let clip = s.limit(clip);
    let area = clip.intersect(rect);
    if area.is_empty() {
        return area;
    }
    let cx = (rect.x0 + rect.x1 - 1) as f64 / 2.0;
    let cy = (rect.y0 + rect.y1 - 1) as f64 / 2.0;
    let a = ((rect.x1 - rect.x0) as f64 / 2.0).max(0.5);
    let b = ((rect.y1 - rect.y0) as f64 / 2.0).max(0.5);
    // Horizontal extent of row y: [lo, hi) or None.
    let span = |y: i32| -> Option<(i32, i32)> {
        let dy = (y as f64 - cy) / b;
        if dy.abs() > 1.0 {
            return None;
        }
        let half = a * (1.0 - dy * dy).sqrt();
        let lo = ((cx - half).ceil() as i32).max(rect.x0);
        let hi = ((cx + half).floor() as i32 + 1).min(rect.x1);
        (hi > lo).then_some((lo, hi))
    };
    let mut touched = Clip::new(0, 0, 0, 0);
    for y in area.y0..area.y1 {
        let Some((lo, hi)) = span(y) else { continue };
        if fill {
            touched = touched.union(blt(s, clip, Clip::new(lo, y, hi, y + 1), rop, pat, None));
            continue;
        }
        // Outline: pixels of this row not covered by both neighbours' rows.
        let up = span(y - 1);
        let down = span(y + 1);
        let inner_lo = [up, down]
            .iter()
            .map(|r| r.map_or(i32::MAX, |r| r.0))
            .max()
            .unwrap();
        let inner_hi = [up, down]
            .iter()
            .map(|r| r.map_or(i32::MIN, |r| r.1))
            .min()
            .unwrap();
        for x in lo.max(clip.x0)..hi.min(clip.x1) {
            let edge = x == lo || x == hi - 1 || x < inner_lo || x >= inner_hi;
            if edge {
                touched =
                    touched.union(blt(s, clip, Clip::new(x, y, x + 1, y + 1), rop, pat, None));
            }
        }
    }
    touched
}

/// A cached glyph: a 1-bpp bitmap with its origin offset (MS-RDPEGDI
/// 2.2.2.2.1.2.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glyph {
    pub x: i32,
    pub y: i32,
    pub cx: u32,
    pub cy: u32,
    /// Rows top-down, each `(cx + 7) / 8` bytes, MSB first.
    pub bits: Vec<u8>,
}

impl Glyph {
    /// The 1-bpp data from `aj`, which must hold the unpadded rows.
    pub fn new(x: i32, y: i32, cx: u32, cy: u32, aj: &[u8]) -> Option<Self> {
        let n = cx.div_ceil(8) as usize * cy as usize;
        Some(Self {
            x,
            y,
            cx,
            cy,
            bits: aj.get(..n)?.to_vec(),
        })
    }

    /// The `aj` size on the wire: rows padded to a multiple of 4 bytes.
    pub fn wire_size(cx: u32, cy: u32) -> usize {
        (cx.div_ceil(8) as usize * cy as usize).next_multiple_of(4)
    }
}

/// Draws a glyph's set pixels in `c` with the origin at (x, y).
pub fn glyph(s: &mut Surface, clip: Clip, g: &Glyph, x: i32, y: i32, c: u32) -> Clip {
    let clip = s.limit(clip);
    let gx = x + g.x;
    let gy = y + g.y;
    let area = clip.intersect(Clip::rect(gx, gy, g.cx as i32, g.cy as i32));
    if area.is_empty() {
        return area;
    }
    let stride = g.cx.div_ceil(8) as usize;
    for py in area.y0..area.y1 {
        let row = &g.bits[(py - gy) as usize * stride..];
        for px in area.x0..area.x1 {
            let bx = (px - gx) as usize;
            if row[bx / 8] & (0x80 >> (bx % 8)) != 0 {
                *s.at(px, py) = c & 0x00FF_FFFF;
            }
        }
    }
    area
}
