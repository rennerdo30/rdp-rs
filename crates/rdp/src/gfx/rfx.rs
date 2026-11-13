//! RemoteFX codec core (MS-RDPRFX 3.1.8.2), shared by the RemoteFX
//! Progressive codec ([`super::progressive`], MS-RDPEGFX 3.3.8.2):
//!
//! - [`Bits`]: the MSB-first bit reader every RemoteFX bitstream uses.
//! - [`rlgr_decode`]: RLGR1 and RLGR3 entropy decoding (3.1.8.1.7).
//! - [`Quant`] and [`Layout`]: quantization factors and the sub-band
//!   layout of a tile, classic or Reduce-Extrapolate (MS-RDPEGFX
//!   3.2.8.1.2.2).
//! - [`Reconstructor`]: dequantization (3.1.8.2.3), inverse DWT (3.1.8.2.4,
//!   MS-RDPEGFX 3.3.8.2.2) and YCbCr to RGB (3.1.8.2.5) into reusable
//!   buffers.
//!
//! Coefficients are dequantized into 11.5 fixed point (MS-RDPRFX 4.2.4.3):
//! a factor q scales by 2^(q-6), and the 5 fraction bits make that a left
//! shift by q - 1. Every stage works on bounded integers, so corrupt data
//! gives wrong pixels, never an overflow.

/// Tile width and height (MS-RDPRFX 3.1.8.1.1).
pub const TILE: usize = 64;
/// Coefficients per tile component.
pub const COEFFS: usize = TILE * TILE;

/// MSB-first bit reader (MS-RDPRFX 3.1.8.1.7.3.1, GetBits). Reading past
/// the end yields zero bits, as an encoder's zero padding would.
pub struct Bits<'a> {
    data: &'a [u8],
    next: usize,
    /// Unread bits, left-aligned; bits below the top `n` are zero.
    acc: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            next: 0,
            acc: 0,
            n: 0,
        }
    }

    fn refill(&mut self) {
        while self.n <= 56 {
            let b = self.data.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            self.acc |= (b as u64) << (56 - self.n);
            self.n += 8;
        }
    }

    fn consume(&mut self, k: u32) {
        self.acc = self.acc.checked_shl(k).unwrap_or(0);
        self.n -= k;
    }

    /// The next `k` bits (k <= 32) as an unsigned number.
    #[inline]
    pub fn bits(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        if self.n < k {
            self.refill();
        }
        let v = (self.acc >> (64 - k)) as u32;
        self.consume(k);
        v
    }

    #[inline]
    pub fn bit(&mut self) -> u32 {
        self.bits(1)
    }

    /// Counts the one bits before the next zero bit and consumes both.
    fn ones(&mut self) -> u32 {
        let mut count = 0;
        loop {
            if self.n < 8 {
                self.refill();
            }
            let run = (!self.acc).leading_zeros();
            if run < self.n {
                self.consume(run + 1);
                return count + run;
            }
            count += self.n;
            self.consume(self.n);
        }
    }
}

/// Saturates to the coefficient range.
#[inline]
pub(crate) fn sat16(v: i64) -> i16 {
    v.clamp(i16::MIN as i64, i16::MAX as i64) as i16
}

const KPMAX: i32 = 80;
const LSGR: i32 = 3;
const UP_GR: i32 = 4;
const DN_GR: i32 = 6;
const UQ_GR: i32 = 3;
const DQ_GR: i32 = 3;

/// UpdateParam: adjusts and clamps a parameter, returns it shifted by LSGR.
#[inline]
fn update(p: &mut i32, delta: i32) -> u32 {
    *p = (*p + delta).clamp(0, KPMAX);
    (*p >> LSGR) as u32
}

/// GetGRCode: a Golomb-Rice coded value; adapts kR.
#[inline]
fn gr_code(b: &mut Bits, krp: &mut i32, kr: &mut u32) -> u32 {
    let vk = b.ones();
    // Leading ones are bounded by the input (at most 65535 * 8 for one
    // component), so the shift cannot overflow with kR <= 10.
    let mag = (vk << *kr) | b.bits(*kr);
    if vk == 0 {
        *kr = update(krp, -2);
    } else if vk != 1 {
        *kr = update(krp, vk.min(KPMAX as u32) as i32);
    }
    mag
}

/// GetIntFrom2MagSign: (2 * magnitude - sign) to a signed value.
#[inline]
fn from_2ms(v: u32) -> i64 {
    let mag = (v as i64 + 1) >> 1;
    if v & 1 != 0 { -mag } else { mag }
}

/// RLGR1 or RLGR3 decoding (MS-RDPRFX 3.1.8.1.7.3.1) of `out.len()`
/// coefficients. A stream that ends early reads as zero bits; values are
/// saturated to i16.
pub fn rlgr_decode(rlgr3: bool, data: &[u8], out: &mut [i16]) {
    let mut b = Bits::new(data);
    let (mut k, mut kp) = (1u32, 1i32 << LSGR);
    let (mut kr, mut krp) = (1u32, 1i32 << LSGR);
    let n = out.len();
    let mut i = 0;
    while i < n {
        if k != 0 {
            // Run-length mode: "0" escapes are runs of 1 << k zeros.
            while b.bit() == 0 {
                let z = (1usize << k).min(n - i);
                out[i..i + z].fill(0);
                i += z;
                k = update(&mut kp, UP_GR);
                if i == n {
                    return;
                }
            }
            let z = (b.bits(k) as usize).min(n - i);
            out[i..i + z].fill(0);
            i += z;
            if i < n {
                let sign = b.bit();
                let mag = gr_code(&mut b, &mut krp, &mut kr) as i64 + 1;
                out[i] = sat16(if sign != 0 { -mag } else { mag });
                i += 1;
                k = update(&mut kp, -DN_GR);
            }
        } else {
            // Golomb-Rice mode: values coded as 2 * magnitude - sign.
            let mag = gr_code(&mut b, &mut krp, &mut kr);
            if !rlgr3 {
                out[i] = sat16(from_2ms(mag));
                i += 1;
                k = update(&mut kp, if mag == 0 { UQ_GR } else { -DQ_GR });
            } else {
                // The sum of two values, then the first in as many bits as
                // the sum needs.
                let first = b.bits(32 - mag.leading_zeros());
                let second = mag.saturating_sub(first);
                if first != 0 && second != 0 {
                    k = update(&mut kp, -2 * DQ_GR);
                } else if first == 0 && second == 0 {
                    k = update(&mut kp, 2 * UQ_GR);
                }
                out[i] = sat16(from_2ms(first));
                i += 1;
                if i < n {
                    out[i] = sat16(from_2ms(second));
                    i += 1;
                }
            }
        }
    }
}

/// Sub-band indices in linearization order (MS-RDPRFX 3.1.8.1.6): HL1,
/// LH1, HH1, HL2, LH2, HH2, HL3, LH3, HH3, LL3.
pub const HL1: usize = 0;
pub const LH1: usize = 1;
pub const HH1: usize = 2;
pub const HL2: usize = 3;
pub const LH2: usize = 4;
pub const HH2: usize = 5;
pub const HL3: usize = 6;
pub const LH3: usize = 7;
pub const HH3: usize = 8;
pub const LL3: usize = 9;

/// One 4-bit value per sub-band, indexed by the constants above.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quant(pub [u8; 10]);

impl Quant {
    fn from_wire(b: [u8; 5], order: [usize; 10]) -> Quant {
        let mut q = [0; 10];
        for (i, band) in order.into_iter().enumerate() {
            q[band] = (b[i / 2] >> (4 * (i % 2))) & 0x0F;
        }
        Quant(q)
    }

    /// TS_RFX_CODEC_QUANT (MS-RDPRFX 2.2.2.1.5): LL3, LH3, HL3, HH3, LH2,
    /// HL2, HH2, LH1, HL1, HH1, low nibble first.
    pub fn rfx(b: [u8; 5]) -> Quant {
        Quant::from_wire(b, [LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1])
    }

    /// RFX_COMPONENT_CODEC_QUANT (MS-RDPEGFX 2.2.4.2.1.5.2): LL3, HL3, LH3,
    /// HH3, HL2, LH2, HH2, HL1, LH1, HH1, low nibble first.
    pub fn progressive(b: [u8; 5]) -> Quant {
        Quant::from_wire(b, [LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1])
    }
}

/// Where each sub-band lies in a component's 4,096 coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Offset, width and height per sub-band (raster order inside a band).
    pub bands: [(usize, usize, usize); 10],
    /// Reduce-Extrapolate (MS-RDPEGFX 3.2.8.1.2.2) or the classic DWT.
    pub extrapolate: bool,
}

const fn layout(sizes: [(usize, usize); 10], extrapolate: bool) -> Layout {
    let mut bands = [(0, 0, 0); 10];
    let mut off = 0;
    let mut i = 0;
    while i < 10 {
        bands[i] = (off, sizes[i].0, sizes[i].1);
        off += sizes[i].0 * sizes[i].1;
        i += 1;
    }
    Layout { bands, extrapolate }
}

/// The classic layout (MS-RDPRFX 4.2.4.2): 32x32, 16x16 and 8x8 bands.
pub const CLASSIC: Layout = layout(
    [
        (32, 32),
        (32, 32),
        (32, 32),
        (16, 16),
        (16, 16),
        (16, 16),
        (8, 8),
        (8, 8),
        (8, 8),
        (8, 8),
    ],
    false,
);

/// The Reduce-Extrapolate layout (MS-RDPEGFX 3.2.8.1.2.2): each level has
/// one more low than high coefficient per direction (33 + 31, 17 + 16,
/// 9 + 8); an HL band is high horizontally, so it is narrow and tall.
pub const EXTRAPOLATE: Layout = layout(
    [
        (31, 33),
        (33, 31),
        (31, 31),
        (16, 17),
        (17, 16),
        (16, 16),
        (8, 9),
        (9, 8),
        (8, 8),
        (9, 9),
    ],
    true,
);

impl Layout {
    /// The coefficient range of each sub-band.
    pub fn ranges(&self) -> [std::ops::Range<usize>; 10] {
        self.bands.map(|(o, w, h)| o..o + w * h)
    }
}

/// Dequantized values are clamped to this magnitude before the inverse DWT,
/// so three lifting levels stay far inside i32 (real data stays below
/// 2^16).
const COEFF_LIMIT: i32 = 1 << 20;
/// Line capacity: 65 samples for the extrapolating first level.
const LINE: usize = TILE + 1;

/// Scratch buffers for one tile component's reconstruction, reused across
/// tiles.
pub struct Reconstructor {
    band: Vec<i32>,
    ll: Vec<i32>,
    lo: Vec<i32>,
    hi: Vec<i32>,
    out: Vec<i32>,
}

impl Default for Reconstructor {
    fn default() -> Self {
        Self::new()
    }
}

/// One level of the inverse DWT: `nl` low and `nh` high coefficients per
/// direction, `pad` adds a zero high coefficient (the extrapolated first
/// level), and `len` outputs are kept.
#[derive(Clone, Copy)]
struct Level {
    nl: usize,
    nh: usize,
    pad: bool,
    len: usize,
}

const CLASSIC_LEVELS: [Level; 3] = [
    Level {
        nl: 8,
        nh: 8,
        pad: false,
        len: 16,
    },
    Level {
        nl: 16,
        nh: 16,
        pad: false,
        len: 32,
    },
    Level {
        nl: 32,
        nh: 32,
        pad: false,
        len: 64,
    },
];
const EXTRAPOLATE_LEVELS: [Level; 3] = [
    Level {
        nl: 9,
        nh: 8,
        pad: false,
        len: 17,
    },
    Level {
        nl: 17,
        nh: 16,
        pad: false,
        len: 33,
    },
    Level {
        nl: 33,
        nh: 31,
        pad: true,
        len: 64,
    },
];

/// The 5/3 inverse lifting of one line (MS-RDPRFX 3.1.8.2.4):
/// x[2n] = L[n] - ((H[n-1] + H[n] + 1) >> 1),
/// x[2n+1] = 2 H[n] + ((x[2n] + x[2n+2]) >> 1),
/// with mirrored boundaries (H[-1] = H[0], x past the end = x mirrored).
/// `out` receives all even samples and the odd ones below `len`.
#[inline]
pub(crate) fn lift_line(low: &[i32], high: &[i32], pad: bool, len: usize, out: &mut [i32]) {
    let (nl, nh) = (low.len(), high.len());
    // H past the end: the padded zero, else the mirror of the last one.
    let tail = if pad { 0 } else { high[nh - 1] };
    let h = |i: usize| if i < nh { high[i] } else { tail };
    out[0] = low[0] - ((high[0] + high[0] + 1) >> 1);
    for n in 1..nl.min(nh) {
        out[2 * n] = low[n] - ((high[n - 1] + high[n] + 1) >> 1);
    }
    for n in nh.max(1)..nl {
        out[2 * n] = low[n] - ((h(n - 1) + h(n) + 1) >> 1);
    }
    // Odd samples below `len`; past the last even one x mirrors back.
    let odd = len / 2;
    let inside = odd.min(nl - 1);
    for n in 0..inside {
        out[2 * n + 1] = 2 * h(n) + ((out[2 * n] + out[2 * n + 2]) >> 1);
    }
    for n in inside..odd {
        out[2 * n + 1] = 2 * h(n) + out[2 * n];
    }
}

impl Reconstructor {
    pub fn new() -> Reconstructor {
        Reconstructor {
            band: vec![0; COEFFS],
            ll: vec![0; LINE * LINE],
            lo: vec![0; LINE * LINE],
            hi: vec![0; LINE * LINE],
            out: vec![0; LINE * LINE],
        }
    }

    /// Dequantizes `coeffs` (one component, `layout` order) with `quant`
    /// and inverse transforms them into a 64x64 plane of 11.5 fixed-point
    /// samples in `plane`.
    pub fn component(&mut self, coeffs: &[i16], quant: &Quant, layout: &Layout, plane: &mut [i32]) {
        plane[..COEFFS].copy_from_slice(&self.levels(coeffs, quant, layout, 3)[..COEFFS]);
    }

    /// The first `count` inverse levels; returns the last level's output
    /// (LL2, LL1 or the plane, row stride = its width).
    pub(crate) fn levels(
        &mut self,
        coeffs: &[i16],
        quant: &Quant,
        layout: &Layout,
        count: usize,
    ) -> &[i32] {
        for (b, r) in layout.ranges().into_iter().enumerate() {
            // q in 0..=15 scales by 2^(q-6), in 11.5 fixed point a shift by
            // q - 1 (q = 0, outside the RemoteFX range, reads as 1).
            let shift = quant.0[b].saturating_sub(1) as u32;
            for (d, &c) in self.band[r.clone()].iter_mut().zip(&coeffs[r]) {
                *d = ((c as i32) << shift).clamp(-COEFF_LIMIT, COEFF_LIMIT);
            }
        }
        let levels = if layout.extrapolate {
            &EXTRAPOLATE_LEVELS
        } else {
            &CLASSIC_LEVELS
        };
        // Level 3 reads LL3 from the band buffer, later levels the previous
        // level's output (stride = its width).
        let (o, w, _) = layout.bands[LL3];
        self.ll[..w * w].copy_from_slice(&self.band[o..o + w * w]);
        let mut n = w * w;
        for (i, lv) in levels.iter().take(count).enumerate() {
            let k = 2 - i;
            let [hl, lh, hh] = [HL1 + 3 * k, LH1 + 3 * k, HH1 + 3 * k].map(|b| layout.bands[b].0);
            self.level(*lv, hl, lh, hh);
            n = lv.len * lv.len;
            std::mem::swap(&mut self.ll, &mut self.out);
        }
        &self.ll[..n]
    }

    /// One 2-D level: horizontal lifting of (LL, HL) into `lo` and (LH, HH)
    /// into `hi`, then vertical lifting of the rows into `out`
    /// (`len` x `len`, row stride `len`).
    fn level(&mut self, lv: Level, hl: usize, lh: usize, hh: usize) {
        let Level { nl, nh, pad, len } = lv;
        let band = &self.band;
        for r in 0..nl {
            let low = &self.ll[r * nl..(r + 1) * nl];
            let high = &band[hl + r * nh..hl + (r + 1) * nh];
            lift_line(low, high, pad, len, &mut self.lo[r * LINE..(r + 1) * LINE]);
        }
        for r in 0..nh {
            let low = &band[lh + r * nl..lh + (r + 1) * nl];
            let high = &band[hh + r * nh..hh + (r + 1) * nh];
            lift_line(low, high, pad, len, &mut self.hi[r * LINE..(r + 1) * LINE]);
        }
        // Vertical: the same lifting with rows for samples. Even rows first
        // (all nl of them: the extrapolated 65th is needed by the last odd
        // row, then dropped); `out` holds them at stride `len`.
        let zeros = [0i32; LINE];
        let (lo, hi, out) = (&self.lo, &self.hi, &mut self.out);
        let hrow = |r: usize| -> &[i32] { high_row(hi, &zeros, r, nh, pad, len) };
        for n in 0..nl {
            let l = &lo[n * LINE..n * LINE + len];
            let (a, b) = (hrow(n.saturating_sub(1)), hrow(n));
            let dst = &mut out[2 * n * len..(2 * n + 1) * len];
            for (((d, &l), &a), &b) in dst.iter_mut().zip(l).zip(a).zip(b) {
                *d = l - ((a + b + 1) >> 1);
            }
        }
        let last_even = 2 * (nl - 1);
        let mut n = 0;
        while 2 * n + 1 < len {
            let h = hrow(n);
            let (head, tail) = out.split_at_mut((2 * n + 1) * len);
            let prev = &head[2 * n * len..];
            let (dst, rest) = tail.split_at_mut(len);
            let next = if 2 * n + 2 <= last_even {
                &rest[..len]
            } else {
                prev
            };
            for (((d, &h), &p), &q) in dst.iter_mut().zip(h).zip(prev).zip(next) {
                *d = 2 * h + ((p + q) >> 1);
            }
            n += 1;
        }
    }
}

/// Row `r` of the high-pass rows: past the end the padded zero row or the
/// mirror of the last one.
fn high_row<'a>(
    hi: &'a [i32],
    zeros: &'a [i32],
    r: usize,
    nh: usize,
    pad: bool,
    len: usize,
) -> &'a [i32] {
    match (r < nh, pad) {
        (true, _) => &hi[r * LINE..r * LINE + len],
        (false, true) => &zeros[..len],
        (false, false) => &hi[(nh - 1) * LINE..(nh - 1) * LINE + len],
    }
}

/// YCbCr (11.5 fixed point, Y level-shifted by -128) to 0x00RRGGBB
/// (MS-RDPRFX 3.1.8.2.5):
/// R = Y + 1.402525 Cr, G = Y - 0.343730 Cb - 0.714401 Cr,
/// B = Y + 1.769905 Cb, clamped to 0..=255. Coefficients carry 14 fraction
/// bits; inputs are clamped to +-2^15 so nothing overflows.
pub fn ycbcr_to_rgb(y: &[i32], cb: &[i32], cr: &[i32], out: &mut [u32]) {
    const LIM: i32 = 1 << 15;
    const SHIFT: i32 = 14 + 5;
    const ROUND: i32 = 1 << (SHIFT - 1);
    let px = out.iter_mut().zip(y).zip(cb).zip(cr);
    for (((o, &y), &cb), &cr) in px {
        let yv = (y.clamp(-LIM, LIM) + (128 << 5)) * (1 << 14) + ROUND;
        let (cb, cr) = (cb.clamp(-LIM, LIM), cr.clamp(-LIM, LIM));
        let r = (yv + 22979 * cr) >> SHIFT;
        let g = (yv - 5632 * cb - 11705 * cr) >> SHIFT;
        let b = (yv + 28998 * cb) >> SHIFT;
        *o =
            (r.clamp(0, 255) as u32) << 16 | (g.clamp(0, 255) as u32) << 8 | b.clamp(0, 255) as u32;
    }
}
