//! RemoteFX core (MS-RDPRFX) and RemoteFX Progressive (MS-RDPEGFX 2.2.4.2,
//! 3.3.8.2, 4.1.2) tests.

use super::progressive::*;
use super::rfx::*;
use super::surface::Surface;

fn i16s(b: &[u8]) -> Vec<i16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|&c| i16::from_le_bytes(c))
        .collect()
}

// ---- MS-RDPEGFX 4.1.2: progressive entropy example (14 coefficients) ----

/// The example's bands: HL (5), LH (5), LL (4), LL last.
fn example_bands() -> [std::ops::Range<usize>; 3] {
    [0..5, 5..10, 10..14]
}

#[test]
fn rlgr1_spec_example_frame1_25() {
    // 4.1.2.1.1: RLGR1 of ProgQ-NonLL and ProgQ-LL-Deltas.
    let mut out = [0i16; 14];
    rlgr_decode(false, &[0xA8, 0x62, 0x6D, 0xFF, 0xF7, 0x00], &mut out);
    assert_eq!(out, [-2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1, -7, 6]);
}

#[test]
fn rlgr1_spec_example_frame2_25() {
    // 4.1.2.1.3.
    let mut out = [0i16; 14];
    rlgr_decode(false, &[0x88, 0x76, 0xBD, 0xFF, 0xFE, 0xF2], &mut out);
    assert_eq!(out, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, -4, 8, -9]);
}

#[test]
fn progressive_spec_example_decode() {
    // 4.1.2.2: frame 1 at 25% and 50%, frame 2 (a difference tile) at 25%,
    // 50% and 100%. Bit positions: 25% = (4, 3, 2), 50% = (0, 1, 2).
    let bands = example_bands();
    let (q25, q50, q100) = ([4u8, 3, 2], [0u8, 1, 2], [0u8, 0, 0]);
    let mut coeffs = [0i16; 14];
    let mut sign = [0i8; 14];
    let mut tmp = [0i16; 14];

    let rlgr = [0xA8, 0x62, 0x6D, 0xFF, 0xF7, 0x00];
    first_pass(
        &rlgr,
        &bands,
        &q25,
        false,
        &mut coeffs,
        Some(&mut sign),
        &mut tmp,
    );
    assert_eq!(coeffs, [-32, 0, 0, 0, 0, 0, 0, 0, 0, 8, 12, 16, -12, 12]);
    assert_eq!(&sign[..10], &[-1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let srl = [0xA0, 0x01, 0x80, 0x00, 0xC9, 0x49, 0xE0];
    upgrade(&srl, &[0x20], &bands, &q25, &q50, &mut coeffs, &mut sign).unwrap();
    assert_eq!(
        coeffs,
        [-34, -13, 15, -3, 0, 0, -6, 4, -2, 8, 12, 16, -12, 12]
    );
    assert_eq!(&sign[..10], &[-1, -1, 1, -1, 0, 0, -1, 1, -1, 1]);

    let rlgr = [0x88, 0x76, 0xBD, 0xFF, 0xFE, 0xF2];
    first_pass(
        &rlgr,
        &bands,
        &q25,
        true,
        &mut coeffs,
        Some(&mut sign),
        &mut tmp,
    );
    assert_eq!(coeffs, [-2, -13, 15, -3, 0, 0, -6, 4, -2, 8, 24, 12, 16, 4]);
    assert_eq!(&sign[..10], &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    // The spec's SRL bytes here (80 07 00 16 9C) leave out the encoding of
    // HL's last value (+1, "01" after the one-zero run "01"): its own bit
    // listing has 40 bits for nine entries that need 42. These are the
    // bytes of the full listing; see `srl_spec_erratum` for the published
    // ones.
    let srl = [0x80, 0x07, 0x00, 0x15, 0xA7, 0x00];
    upgrade(&srl, &[0x00], &bands, &q25, &q50, &mut coeffs, &mut sign).unwrap();
    assert_eq!(coeffs, [-2, -2, 3, -3, 1, 2, -6, 4, -2, 2, 24, 12, 16, 4]);
    assert_eq!(&sign[..10], &[1, 1, -1, 0, 1, 1, 0, 0, 0, -1]);

    upgrade(
        &[0xB0],
        &[0xC6, 0x40],
        &bands,
        &q50,
        &q100,
        &mut coeffs,
        &mut sign,
    )
    .unwrap();
    // DecDwtQ now equals frame #2's coefficients.
    assert_eq!(coeffs, [-2, -2, 3, -3, 1, 3, -7, 5, -2, 1, 24, 13, 18, 5]);
}

#[test]
fn upgrade_rejects_growing_bit_position() {
    let bands = example_bands();
    let (mut c, mut s) = ([0i16; 14], [0i8; 14]);
    let r = upgrade(&[], &[], &bands, &[0, 0, 0], &[1, 0, 0], &mut c, &mut s);
    assert!(matches!(r, Err(crate::error::Error::Protocol(_))));
}

// ---- MS-RDPRFX 4.2.4: sample tile (RLGR3, classic DWT) ----

const TILESET: &[u8] = include_bytes!("testdata/rfx_tileset.bin");
const Y_COEFFS: &[u8] = include_bytes!("testdata/rfx_y_coeffs.bin");
const CB_RECON: &[u8] = include_bytes!("testdata/rfx_cb_recon.bin");
const XRGB: &[u8] = include_bytes!("testdata/rfx_xrgb.bin");

/// The sample tile's quant table and its Y, Cb and Cr data (4.2.4.1).
fn sample_tile() -> (Quant, [&'static [u8]; 3]) {
    let quant = Quant::rfx(TILESET[0x16..0x1B].try_into().unwrap());
    let len = |at: usize| u16::from_le_bytes([TILESET[at], TILESET[at + 1]]) as usize;
    let (y, cb, cr) = (len(0x28), len(0x2A), len(0x2C));
    let d = &TILESET[0x2E..];
    (quant, [&d[..y], &d[y..y + cb], &d[y + cb..y + cb + cr]])
}

/// Entropy decoded, LL3 differences summed (3.1.8.2.2).
fn sample_coeffs(data: &[u8]) -> Vec<i16> {
    let mut c = vec![0i16; COEFFS];
    rlgr_decode(true, data, &mut c);
    let mut acc = 0;
    for v in &mut c[CLASSIC.ranges()[LL3].clone()] {
        acc += *v;
        *v = acc;
    }
    c
}

#[test]
fn rfx_sample_quant_table() {
    let (q, _) = sample_tile();
    // 4.2.4.1: LL3 6, LH3 6, HL3 6, HH3 6, LH2 7, HL2 7, HH2 8, LH1 8,
    // HL1 8, HH1 9 (stored in linearization order).
    assert_eq!(q.0, [8, 8, 9, 7, 7, 8, 6, 6, 6, 6]);
}

#[test]
fn rlgr3_spec_sample_y_component() {
    let (_, [y, ..]) = sample_tile();
    let mut out = vec![0i16; COEFFS];
    rlgr_decode(true, y, &mut out);
    assert_eq!(out, i16s(Y_COEFFS));
}

#[test]
fn classic_idwt_spec_sample_level3_is_exact() {
    // 4.2.4.3.1: dequantized level-3 bands, inverse DWT-X then DWT-Y, give
    // the 16x16 LL2 of the Y component exactly.
    let (q, [y, ..]) = sample_tile();
    let mut rec = Reconstructor::new();
    let ll2 = rec.levels(&sample_coeffs(y), &q, &CLASSIC, 1);
    let want: Vec<i32> = i16s(include_bytes!("testdata/rfx_y_ll2.bin"))
        .into_iter()
        .map(i32::from)
        .collect();
    assert_eq!(ll2, want);
}

#[test]
fn classic_idwt_spec_sample_cb_component() {
    // 4.2.4.3.5: the reconstructed Cb plane in 11.5 fixed point. The
    // level-3 output (LL2) of this sample matches the spec exactly; the
    // spec's last two levels round some odd samples differently (its own
    // dumps are not consistent with one integer rounding rule), so later
    // samples may differ by 2/32 of a step at most.
    let (q, [_, cb, _]) = sample_tile();
    let mut plane = vec![0i32; COEFFS];
    Reconstructor::new().component(&sample_coeffs(cb), &q, &CLASSIC, &mut plane);
    let want: Vec<i32> = i16s(CB_RECON).into_iter().map(i32::from).collect();
    let mut exact = 0;
    for (i, (&g, &w)) in plane.iter().zip(&want).enumerate() {
        assert!(g.abs_diff(w) <= 2, "sample {i}: {g} vs {w}");
        exact += (g == w) as usize;
    }
    assert!(exact > COEFFS * 3 / 4, "{exact} exact samples");
}

#[test]
fn spec_sample_tile_to_xrgb() {
    // 4.2.4.4: the decoded XRGB image (the spec converts in floating point;
    // with the plane rounding above, about 83% of the pixels match exactly
    // and none is off by more than one step).
    let (q, data) = sample_tile();
    let mut rec = Reconstructor::new();
    let mut planes = vec![vec![0i32; COEFFS]; 3];
    for (p, d) in planes.iter_mut().zip(data) {
        rec.component(&sample_coeffs(d), &q, &CLASSIC, p);
    }
    let mut px = vec![0u32; COEFFS];
    ycbcr_to_rgb(&planes[0], &planes[1], &planes[2], &mut px);
    let want: Vec<u32> = XRGB
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u32::from_le_bytes(c) & 0xFF_FFFF)
        .collect();
    let mut exact = 0;
    for (i, (&g, &w)) in px.iter().zip(&want).enumerate() {
        for s in [0, 8, 16] {
            let (a, b) = ((g >> s) & 0xFF, (w >> s) & 0xFF);
            assert!(a.abs_diff(b) <= 1, "pixel {i}: {g:06x} vs {w:06x}");
        }
        exact += (g == w) as usize;
    }
    assert!(exact > COEFFS * 4 / 5, "{exact} exact pixels");
}

#[test]
fn srl_spec_erratum() {
    // The published 4.1.2.1.4 bytes, read by the coding rules of 3.1.8.1.5,
    // give HL 11 -12 0 -2 and LH 0 0 0 -3 0: the "01" value of HL's +1 is
    // missing, so later entries shift. Pinning this documents the erratum.
    let bands = example_bands();
    let mut coeffs = [-2i16, -13, 15, -3, 0, 0, -6, 4, -2, 8, 24, 12, 16, 4];
    let mut sign = [1i8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let srl = [0x80, 0x07, 0x00, 0x16, 0x9C];
    upgrade(
        &srl,
        &[0x00],
        &bands,
        &[4, 3, 2],
        &[0, 1, 2],
        &mut coeffs,
        &mut sign,
    )
    .unwrap();
    assert_eq!(coeffs, [-2, -2, 3, -3, -2, 0, -6, 4, -8, 8, 24, 12, 16, 4]);
}

// ---- Hand-computed DWT, dequantization and quant tables ----

#[test]
fn lift_line_hand_computed() {
    let mut out = [0i32; 6];
    // Classic: x0 = 10 - ((4 + 4 + 1) >> 1) = 6, x2 = 20 - ((4 - 2 + 1) >> 1)
    // = 19, x1 = 8 + ((6 + 19) >> 1) = 20, x3 = -4 + ((19 + 19) >> 1) = 15
    // (x4 mirrors x2).
    lift_line(&[10, 20], &[4, -2], false, 4, &mut out);
    assert_eq!(out[..4], [6, 20, 19, 15]);
    // The +1 before the shift matters: x2 = 20 - ((4 - 1 + 1) >> 1) = 18,
    // x1 = 8 + ((6 + 18) >> 1) = 20, x3 = -2 + 18 = 16.
    lift_line(&[10, 20], &[4, -1], false, 4, &mut out);
    assert_eq!(out[..4], [6, 20, 18, 16]);
    // Reduce-Extrapolate: three low, two high, five out. x4 = 30 -
    // ((-2 + -2 + 1) >> 1) = 32 (H[2] mirrors H[1]); x3 = -4 + ((19 + 32)
    // >> 1) = 21.
    lift_line(&[10, 20, 30], &[4, -2], false, 5, &mut out);
    assert_eq!(out[..5], [6, 20, 19, 21, 32]);
    // The padded first level: the missing high value is zero, so x4 = 30 -
    // ((-2 + 0 + 1) >> 1) = 31 and x3 = -4 + ((19 + 31) >> 1) = 21.
    lift_line(&[10, 20, 30], &[4, -2], true, 5, &mut out);
    assert_eq!(out[..5], [6, 20, 19, 21, 31]);
}

#[test]
fn flat_ll3_dequantizes_to_a_flat_plane() {
    // Only LL3 set: every inverse level interpolates a constant, so the
    // plane is LL3 << (q - 1) everywhere (11.5 fixed point, 2^(q-6) scale).
    for (layout, q) in [(CLASSIC, 6u8), (EXTRAPOLATE, 6), (EXTRAPOLATE, 9)] {
        let mut c = vec![0i16; COEFFS];
        c[layout.ranges()[LL3].clone()].fill(3);
        let mut quant = Quant([7; 10]);
        quant.0[LL3] = q;
        let mut plane = vec![0i32; COEFFS];
        Reconstructor::new().component(&c, &quant, &layout, &mut plane);
        assert!(plane.iter().all(|&v| v == 3 << (q - 1)), "{layout:?} q {q}");
    }
}

#[test]
fn single_high_coefficient_spreads_by_the_lifting() {
    // HH1 (0, 0) = 1 with q 6 is 32 in 11.5 fixed point.
    // Horizontal (row 0 of the high rows, LH1 = 0): x0 = -((32 + 32 + 1)
    // >> 1) = -32, x2 = -((32 + 0 + 1) >> 1) = -16, x1 = 64 + ((-32 - 16)
    // >> 1) = 40, x3 = (-16 + 0) >> 1 = -8.
    // Vertical (low rows all 0): row 0 = -((2h + 1) >> 1) = -h, row 2 =
    // -((h + 1) >> 1), row 1 = 2h + ((row 0 + row 2) >> 1), row 3 =
    // (row 2 + 0) >> 1.
    let mut c = vec![0i16; COEFFS];
    c[CLASSIC.ranges()[HH1].start] = 1;
    let mut plane = vec![0i32; COEFFS];
    Reconstructor::new().component(&c, &Quant([6; 10]), &CLASSIC, &mut plane);
    let rows: Vec<&[i32]> = (0..5).map(|r| &plane[r * 64..r * 64 + 5]).collect();
    assert_eq!(rows[0], [32, -40, 16, 8, 0]);
    assert_eq!(rows[1], [-40, 50, -20, -10, 0]);
    assert_eq!(rows[2], [16, -20, 8, 4, 0]);
    assert_eq!(rows[3], [8, -10, 4, 2, 0]);
    assert_eq!(rows[4], [0; 5]);
    assert_eq!(plane.iter().filter(|&&v| v != 0).count(), 16);
}

#[test]
fn unit_coefficient_shows_the_rounding() {
    // Quant 1 (no shift), HH1 (0, 0) = 1: odd sums make the "+ 1" of the
    // even step and the floor of the odd step visible.
    // High rows, horizontal: x0 = -((1 + 1 + 1) >> 1) = -1, x2 = -((1 + 0 +
    // 1) >> 1) = -1, x1 = 2 + ((-1 - 1) >> 1) = 1, x3 = (-1 + 0) >> 1 = -1.
    // Vertical: row 0 = -((2h + 1) >> 1), row 2 = -((h + 1) >> 1),
    // row 1 = 2h + ((row 0 + row 2) >> 1), row 3 = row 2 >> 1.
    let mut c = vec![0i16; COEFFS];
    c[CLASSIC.ranges()[HH1].start] = 1;
    let mut plane = vec![0i32; COEFFS];
    Reconstructor::new().component(&c, &Quant([1; 10]), &CLASSIC, &mut plane);
    let rows: Vec<&[i32]> = (0..5).map(|r| &plane[r * 64..r * 64 + 5]).collect();
    assert_eq!(rows[0], [1, -1, 1, 1, 0]);
    assert_eq!(rows[1], [-2, 1, -2, -2, 0]);
    assert_eq!(rows[2], [0, -1, 0, 0, 0]);
    assert_eq!(rows[3], [0, -1, 0, 0, 0]);
    assert_eq!(rows[4], [0; 5]);
}

#[test]
fn quant_nibble_orders() {
    // Wire fields in order, low nibble first: 1, 2, ..., 10.
    let wire = [0x21, 0x43, 0x65, 0x87, 0xA9];
    // MS-RDPRFX: LL3 LH3 HL3 HH3 LH2 HL2 HH2 LH1 HL1 HH1.
    let q = Quant::rfx(wire).0;
    assert_eq!([q[LL3], q[LH3], q[HL3], q[HH3], q[LH2]], [1, 2, 3, 4, 5]);
    assert_eq!([q[HL2], q[HH2], q[LH1], q[HL1], q[HH1]], [6, 7, 8, 9, 10]);
    // MS-RDPEGFX: LL3 HL3 LH3 HH3 HL2 LH2 HH2 HL1 LH1 HH1.
    let q = Quant::progressive(wire).0;
    assert_eq!([q[LL3], q[HL3], q[LH3], q[HH3], q[HL2]], [1, 2, 3, 4, 5]);
    assert_eq!([q[LH2], q[HH2], q[HL1], q[LH1], q[HH1]], [6, 7, 8, 9, 10]);
}

#[test]
fn layouts_cover_4096_coefficients() {
    for l in [CLASSIC, EXTRAPOLATE] {
        let r = l.ranges();
        assert_eq!(r[0].start, 0);
        assert_eq!(r[LL3].end, COEFFS);
        assert!(r.windows(2).all(|w| w[0].end == w[1].start));
    }
    assert_eq!(EXTRAPOLATE.bands[HL1], (0, 31, 33));
    assert_eq!(EXTRAPOLATE.bands[LH1], (1023, 33, 31));
    assert_eq!(EXTRAPOLATE.bands[LL3], (4015, 9, 9));
}

#[test]
fn ycbcr_hand_computed() {
    // Y = 0 (128 after the level shift), Cr = +10, Cb = -10 (11.5 fixed
    // point): R = 128 + 14.03 = 142, G = 128 + 3.44 - 7.14 = 124,
    // B = 128 - 17.7 = 110; clamping at both ends.
    let mut out = [0u32; 3];
    let y = [0, 200 << 5, -200 << 5];
    let cb = [-10 << 5, 0, 0];
    let cr = [10 << 5, 0, 0];
    ycbcr_to_rgb(&y, &cb, &cr, &mut out);
    assert_eq!(out, [0x8E7C6E, 0xFFFFFF, 0x000000]);
}

// ---- A small test-only encoder (MS-RDPRFX 3.1.8.1, MS-RDPEGFX 3.2.8.1) ----

#[derive(Default)]
struct BitW {
    out: Vec<u8>,
    n: usize,
}

impl BitW {
    fn bit(&mut self, b: bool) {
        if self.n.is_multiple_of(8) {
            self.out.push(0);
        }
        if b {
            *self.out.last_mut().unwrap() |= 0x80 >> (self.n % 8);
        }
        self.n += 1;
    }
    fn bits(&mut self, k: u32, v: u32) {
        for i in (0..k).rev() {
            self.bit(v >> i & 1 != 0);
        }
    }
}

/// CodeGR (MS-RDPRFX 3.1.8.1.7.3.2).
fn code_gr(w: &mut BitW, krp: &mut i32, val: u32) {
    let kr = (*krp >> 3) as u32;
    let vk = val >> kr;
    for _ in 0..vk {
        w.bit(true);
    }
    w.bit(false);
    w.bits(kr, val & ((1 << kr) - 1));
    if vk == 0 {
        *krp = (*krp - 2).max(0);
    } else if vk > 1 {
        *krp = (*krp + vk as i32).min(80);
    }
}

/// RLGR1 encoder (MS-RDPRFX 3.1.8.1.7.3.2).
fn rlgr1_encode(vals: &[i16]) -> Vec<u8> {
    let mut w = BitW::default();
    let (mut kp, mut krp) = (8i32, 8i32);
    let mut i = 0;
    while i < vals.len() {
        let k = (kp >> 3) as u32;
        if k != 0 {
            let mut nz = 0u32;
            while i < vals.len() && vals[i] == 0 {
                nz += 1;
                i += 1;
            }
            let mut k = k;
            while nz >= 1 << k {
                w.bit(false);
                nz -= 1 << k;
                kp = (kp + 4).min(80);
                k = (kp >> 3) as u32;
            }
            w.bit(true);
            w.bits(k, nz);
            if i < vals.len() {
                let v = vals[i] as i32;
                i += 1;
                w.bit(v < 0);
                code_gr(&mut w, &mut krp, v.unsigned_abs() - 1);
                kp = (kp - 6).max(0);
            }
        } else {
            let v = vals[i] as i32;
            i += 1;
            let two_ms = if v < 0 {
                2 * (-v) as u32 - 1
            } else {
                2 * v as u32
            };
            code_gr(&mut w, &mut krp, two_ms);
            kp = if two_ms == 0 {
                (kp + 3).min(80)
            } else {
                (kp - 3).max(0)
            };
        }
    }
    w.out
}

/// SRL encoder (MS-RDPEGFX 3.1.8.1.5).
struct SrlW {
    w: BitW,
    kp: u32,
    nz: u32,
}

impl SrlW {
    fn new() -> SrlW {
        SrlW {
            w: BitW::default(),
            kp: 8,
            nz: 0,
        }
    }
    fn run(&mut self) {
        let mut k = self.kp / 8;
        while self.nz >= 1 << k {
            self.w.bit(false);
            self.nz -= 1 << k;
            self.kp = (self.kp + 4).min(80);
            k = self.kp / 8;
        }
        self.w.bit(true);
        self.w.bits(k, self.nz);
        self.kp = self.kp.saturating_sub(6);
        self.nz = 0;
    }
    fn push(&mut self, v: i32, nbits: u8) {
        if v == 0 {
            self.nz += 1;
            return;
        }
        self.run();
        self.w.bit(v < 0);
        let mag = v.unsigned_abs();
        for _ in 1..mag {
            self.w.bit(false);
        }
        if mag < (1 << nbits) - 1 {
            self.w.bit(true);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nz > 0 {
            self.run();
        }
        self.w.out.push(0);
        self.w.out
    }
}

/// Forward 5/3 lifting of one line, the exact counterpart of `lift_line`:
/// classic for even lengths, Reduce-Extrapolate for odd ones.
fn fwd_line(x: &[i32]) -> (Vec<i32>, Vec<i32>) {
    let m = x.len();
    let xm = |j: usize| if j < m { x[j] } else { x[2 * m - 2 - j] };
    let nh = m / 2;
    let h: Vec<i32> = (0..nh)
        .map(|i| (x[2 * i + 1] - ((x[2 * i] + xm(2 * i + 2)) >> 1)) >> 1)
        .collect();
    let hm = |i: isize| h[i.clamp(0, nh as isize - 1) as usize];
    let l = (0..m.div_ceil(2))
        .map(|i| x[2 * i] + ((hm(i as isize - 1) + hm(i as isize) + 1) >> 1))
        .collect();
    (l, h)
}

/// Forward DWT of a 64x64 plane into `layout` order.
fn fwd_dwt(plane: &[i32], layout: &Layout) -> Vec<i32> {
    let mut out = vec![0; COEFFS];
    let mut ll: Vec<i32> = plane.to_vec();
    let mut n = TILE;
    for level in 0..3 {
        // The extrapolated 65th sample of the first level.
        let ext = layout.extrapolate && level == 0;
        let m = n + ext as usize;
        let col = |c: usize| -> Vec<i32> {
            let mut v: Vec<i32> = (0..n).map(|r| ll[r * n + c]).collect();
            if ext {
                v.push(2 * v[n - 1] - v[n - 2]);
            }
            v
        };
        let (nl, nh) = (m.div_ceil(2), m / 2 - ext as usize);
        // Vertical, then horizontal on each output row.
        let mut lo = vec![vec![0; n]; nl];
        let mut hi = vec![vec![0; n]; nh];
        for c in 0..n {
            let (l, h) = fwd_line(&col(c));
            for r in 0..nl {
                lo[r][c] = l[r];
            }
            for r in 0..nh {
                hi[r][c] = h[r];
            }
        }
        let row = |v: &[i32]| {
            let mut v = v.to_vec();
            if ext {
                v.push(2 * v[n - 1] - v[n - 2]);
            }
            let (l, mut h) = fwd_line(&v);
            h.truncate(nh);
            (l, h)
        };
        let k = level;
        let put = |out: &mut Vec<i32>, band: usize, r: usize, vals: &[i32]| {
            let (o, w, _) = layout.bands[band];
            out[o + r * w..o + (r + 1) * w].copy_from_slice(vals);
        };
        let mut next = vec![0; nl * nl];
        for (r, v) in lo.iter().enumerate() {
            let (l, h) = row(v);
            next[r * nl..(r + 1) * nl].copy_from_slice(&l);
            put(&mut out, HL1 + 3 * k, r, &h);
        }
        for (r, v) in hi.iter().enumerate() {
            let (l, h) = row(v);
            put(&mut out, LH1 + 3 * k, r, &l);
            put(&mut out, HH1 + 3 * k, r, &h);
        }
        ll = next;
        n = nl;
    }
    let (o, w, h) = layout.bands[LL3];
    out[o..o + w * h].copy_from_slice(&ll);
    out
}

/// RGB to YCbCr (MS-RDPRFX 3.1.8.1.3), Y level-shifted.
fn rgb_to_ycbcr(px: &[u32]) -> [Vec<i32>; 3] {
    let mut out = [vec![0; COEFFS], vec![0; COEFFS], vec![0; COEFFS]];
    for (i, &p) in px.iter().enumerate() {
        let (r, g, b) = (
            (p >> 16 & 255) as f64,
            (p >> 8 & 255) as f64,
            (p & 255) as f64,
        );
        out[0][i] = (0.299 * r + 0.587 * g + 0.114 * b - 128.0).round() as i32;
        out[1][i] = (-0.168935 * r - 0.331665 * g + 0.50059 * b).round() as i32;
        out[2][i] = (0.499813 * r - 0.418531 * g - 0.081282 * b).round() as i32;
    }
    out
}

/// A tile's quantized DWT coefficients (all factors 6: scale 1).
fn dwtq(px: &[u32], layout: &Layout) -> [Vec<i32>; 3] {
    rgb_to_ycbcr(px).map(|p| fwd_dwt(&p, layout))
}

/// LL3 deltas and the RLGR1 stream of one component's coefficients.
fn rlgr_with_deltas(c: &[i32], layout: &Layout) -> Vec<u8> {
    let mut v: Vec<i16> = c.iter().map(|&x| x as i16).collect();
    for i in layout.ranges()[LL3].clone().skip(1) {
        v[i] = (c[i] - c[i - 1]) as i16;
    }
    rlgr1_encode(&v)
}

/// The progressive encoder state of one component (3.2.8.1.5).
struct ProgEnc {
    dwtq: Vec<i32>,
    das: Vec<i32>,
    ranges: [std::ops::Range<usize>; 10],
}

impl ProgEnc {
    fn new(dwtq: &[i32], layout: &Layout) -> ProgEnc {
        ProgEnc {
            dwtq: dwtq.to_vec(),
            das: vec![0; COEFFS],
            ranges: layout.ranges(),
        }
    }
    /// The first pass at `bitpos` (ProgQ, LL3 toward minus infinity).
    fn first(&mut self, bitpos: &[u8; 10]) -> Vec<u8> {
        let mut q = vec![0i32; COEFFS];
        for (b, r) in self.ranges.clone().into_iter().enumerate() {
            let s = bitpos[b];
            for i in r {
                let v = self.dwtq[i];
                q[i] = if b == LL3 || v >= 0 {
                    v >> s
                } else {
                    -((-v) >> s)
                };
                self.das[i] = q[i] << s;
            }
        }
        let ll = self.ranges[LL3].clone();
        let mut v: Vec<i16> = q.iter().map(|&x| x as i16).collect();
        for i in ll.clone().skip(1) {
            v[i] = (q[i] - q[i - 1]) as i16;
        }
        rlgr1_encode(&v)
    }
    /// An upgrade pass from `prev` to `cur`: (SRL, raw) streams.
    fn upgrade(&mut self, prev: &[u8; 10], cur: &[u8; 10]) -> (Vec<u8>, Vec<u8>) {
        let mut srl = SrlW::new();
        let mut raw = BitW::default();
        for (b, r) in self.ranges.clone().into_iter().enumerate() {
            let (nbits, s) = (prev[b] - cur[b], cur[b]);
            if nbits == 0 {
                continue;
            }
            for i in r {
                let drs = self.dwtq[i] - self.das[i];
                let uq = if b == LL3 || drs >= 0 {
                    drs >> s
                } else {
                    -((-drs) >> s)
                };
                if b == LL3 {
                    raw.bits(nbits as u32, uq as u32);
                } else if self.das[i] != 0 {
                    raw.bits(nbits as u32, uq.unsigned_abs());
                } else {
                    srl.push(uq, nbits);
                }
                self.das[i] += uq << s;
            }
        }
        (srl.finish(), raw.out)
    }
}

// ---- Block builders (MS-RDPEGFX 2.2.4.2.1) ----

fn block(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut v = kind.to_le_bytes().to_vec();
    v.extend((6 + body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// RFX_COMPONENT_CODEC_QUANT bytes for per-band values.
fn quant_bytes(q: &[u8; 10]) -> [u8; 5] {
    let order = [LL3, HL3, LH3, HH3, HL2, LH2, HH2, HL1, LH1, HH1];
    let mut b = [0u8; 5];
    for (i, band) in order.into_iter().enumerate() {
        b[i / 2] |= q[band] << (4 * (i % 2));
    }
    b
}

/// A region with one quant table (all 6) and the given progressive
/// tables (same bit positions for the three components).
fn region(
    rects: &[(u16, u16, u16, u16)],
    prog: &[[u8; 10]],
    flags: u8,
    tiles: &[Vec<u8>],
) -> Vec<u8> {
    let tiles: Vec<u8> = tiles.concat();
    let mut b = vec![64];
    b.extend((rects.len() as u16).to_le_bytes());
    b.extend([1, prog.len() as u8, flags]);
    b.extend(1u16.to_le_bytes());
    b.extend((tiles.len() as u32).to_le_bytes());
    for &(x, y, w, h) in rects {
        for v in [x, y, w, h] {
            b.extend(v.to_le_bytes());
        }
    }
    b.extend(quant_bytes(&[6; 10]));
    for p in prog {
        b.push(50);
        for _ in 0..3 {
            b.extend(quant_bytes(p));
        }
    }
    b.extend(tiles);
    block(WBT_REGION, &b)
}

fn lens_and_data(parts: &[&[u8]]) -> Vec<u8> {
    let mut b: Vec<u8> = parts
        .iter()
        .flat_map(|p| (p.len() as u16).to_le_bytes())
        .collect();
    for p in parts {
        b.extend_from_slice(p);
    }
    b
}

fn tile_simple(x: u16, y: u16, flags: u8, data: &[Vec<u8>; 3]) -> Vec<u8> {
    let mut b = vec![0, 0, 0];
    b.extend(x.to_le_bytes());
    b.extend(y.to_le_bytes());
    b.push(flags);
    b.extend(lens_and_data(&[&data[0], &data[1], &data[2], &[]]));
    block(WBT_TILE_SIMPLE, &b)
}

fn tile_first(x: u16, y: u16, flags: u8, quality: u8, data: &[Vec<u8>; 3]) -> Vec<u8> {
    let mut b = vec![0, 0, 0];
    b.extend(x.to_le_bytes());
    b.extend(y.to_le_bytes());
    b.extend([flags, quality]);
    b.extend(lens_and_data(&[&data[0], &data[1], &data[2], &[]]));
    block(WBT_TILE_FIRST, &b)
}

fn tile_upgrade(x: u16, y: u16, quality: u8, data: &[(Vec<u8>, Vec<u8>); 3]) -> Vec<u8> {
    let mut b = vec![0, 0, 0];
    b.extend(x.to_le_bytes());
    b.extend(y.to_le_bytes());
    b.push(quality);
    let parts: Vec<&[u8]> = data.iter().flat_map(|(s, r)| [&s[..], &r[..]]).collect();
    b.extend(lens_and_data(&parts));
    block(WBT_TILE_UPGRADE, &b)
}

/// SYNC, CONTEXT, FRAME_BEGIN, the regions, FRAME_END.
fn stream(regions: &[Vec<u8>]) -> Vec<u8> {
    let mut v = block(WBT_SYNC, &[0xCA, 0xAC, 0xCC, 0xCA, 0x00, 0x01]);
    v.extend(block(WBT_CONTEXT, &[0, 64, 0, 1]));
    let mut fb = 0u32.to_le_bytes().to_vec();
    fb.extend((regions.len() as u16).to_le_bytes());
    v.extend(block(WBT_FRAME_BEGIN, &fb));
    for r in regions {
        v.extend_from_slice(r);
    }
    v.extend(block(WBT_FRAME_END, &[]));
    v
}

fn surface(w: usize, h: usize, fill: u32) -> Surface {
    Surface {
        width: w,
        height: h,
        pixels: vec![fill; w * h],
        origin: None,
    }
}

/// A test image: gradients with a hard edge.
fn image(seed: u32) -> Vec<u32> {
    (0..COEFFS as u32)
        .map(|i| {
            let (x, y) = (i % 64, i / 64);
            let r = (x * 3 + y + seed) & 255;
            let g = if x > 40 { 220 } else { 30 + y * 2 };
            let b = (x + y * 2 + seed * 7) & 255;
            r << 16 | g << 8 | b
        })
        .collect()
}

fn max_channel_diff(a: &[u32], b: &[u32]) -> u32 {
    a.iter()
        .zip(b)
        .flat_map(|(&p, &q)| [0, 8, 16].map(|s| ((p >> s) & 255).abs_diff((q >> s) & 255)))
        .max()
        .unwrap()
}

/// Decoded pixels match the source within the test encoder's rounding: at
/// most 8 steps per channel, under one step on average.
fn close(got: &[u32], want: &[u32]) -> bool {
    let sum: u32 = got
        .iter()
        .zip(want)
        .flat_map(|(&p, &q)| [0, 8, 16].map(|s| ((p >> s) & 255).abs_diff((q >> s) & 255)))
        .sum();
    max_channel_diff(got, want) <= 8 && sum < 3 * got.len() as u32
}

/// Pixels of tile (tx, ty) in a surface.
fn tile_px(s: &Surface, tx: usize, ty: usize) -> Vec<u32> {
    (0..TILE)
        .flat_map(|r| {
            let o = (ty * TILE + r) * s.width + tx * TILE;
            s.pixels[o..o + TILE].to_vec()
        })
        .collect()
}

fn simple_tile_bytes(px: &[u32], x: u16, y: u16) -> Vec<u8> {
    let c = dwtq(px, &EXTRAPOLATE);
    tile_simple(x, y, 0, &c.map(|c| rlgr_with_deltas(&c, &EXTRAPOLATE)))
}

#[test]
fn rlgr1_encoder_round_trip() {
    let mut seed = 0x1234_5678u32;
    for len in [1usize, 2, 14, 300, COEFFS] {
        let vals: Vec<i16> = (0..len)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                // Long zero runs with bursts of large values.
                if (i / 40) % 3 == 0 {
                    (seed % 2001) as i16 - 1000
                } else {
                    0
                }
            })
            .collect();
        let mut out = vec![0i16; len];
        rlgr_decode(false, &rlgr1_encode(&vals), &mut out);
        assert_eq!(out, vals, "length {len}");
    }
}

#[test]
fn fwd_dwt_round_trips_through_the_inverse() {
    // The test encoder is only useful if `Reconstructor` inverts it: with
    // quant 6 the planes come back within the forward lifting's rounding.
    for layout in [CLASSIC, EXTRAPOLATE] {
        let planes = rgb_to_ycbcr(&image(3));
        let mut rec = Reconstructor::new();
        for p in &planes {
            let c: Vec<i16> = fwd_dwt(p, &layout).iter().map(|&v| v as i16).collect();
            let mut out = vec![0; COEFFS];
            rec.component(&c, &Quant([6; 10]), &layout, &mut out);
            let worst = out.iter().zip(p).map(|(&o, &w)| (o - (w << 5)).abs()).max();
            let mean = out
                .iter()
                .zip(p)
                .map(|(&o, &w)| (o - (w << 5)).abs())
                .sum::<i32>()
                / COEFFS as i32;
            // The lifting halves each high value, so every level can drop a
            // low bit: a few steps at worst, half a step on average.
            assert!(
                worst.unwrap() <= 5 << 5 && mean <= 16,
                "{layout:?}: {worst:?} {mean}"
            );
        }
    }
}

#[test]
fn simple_tile_round_trip() {
    let px = image(1);
    let mut s = surface(128, 64, 0xDEAD);
    let data = stream(&[region(
        &[(64, 0, 64, 64)],
        &[],
        1,
        &[simple_tile_bytes(&px, 1, 0)],
    )]);
    let mut painted = Vec::new();
    let mut dec = Progressive::new();
    dec.decode(1, 7, &data, &mut s, &mut painted).unwrap();
    assert!(close(&tile_px(&s, 1, 0), &px));
    // The tile left of it was not touched.
    assert!(tile_px(&s, 0, 0).iter().all(|&p| p == 0xDEAD));
    assert_eq!(painted, vec![super::surface::Area::new(64, 0, 64, 64)]);
    assert_eq!(dec.counts(), (1, 1));
}

#[test]
fn progressive_passes_upgrade_the_tile_to_the_simple_result() {
    let px = image(2);
    let c = dwtq(&px, &EXTRAPOLATE);
    let coarse = [6, 6, 6, 5, 5, 5, 4, 4, 4, 3];
    let mid = [3, 3, 3, 2, 2, 2, 1, 1, 1, 1];
    let rect = [(0u16, 0u16, 64u16, 64u16)];

    let mut want = surface(64, 64, 0);
    let simple = stream(&[region(&rect, &[], 1, &[simple_tile_bytes(&px, 0, 0)])]);
    Progressive::new()
        .decode(1, 1, &simple, &mut want, &mut Vec::new())
        .unwrap();

    let mut enc: Vec<ProgEnc> = c.iter().map(|c| ProgEnc::new(c, &EXTRAPOLATE)).collect();
    let mut dec = Progressive::new();
    let mut s = surface(64, 64, 0);
    let first = [0, 1, 2].map(|i| enc[i].first(&coarse));
    let tiles = [tile_first(0, 0, 0, 0, &first)];
    dec.decode(
        1,
        9,
        &stream(&[region(&rect, &[coarse, mid], 1, &tiles)]),
        &mut s,
        &mut Vec::new(),
    )
    .unwrap();
    let pass1 = s.pixels.clone();
    assert!(
        max_channel_diff(&pass1, &want.pixels) > 8,
        "coarse pass is coarse"
    );

    let up = [0, 1, 2].map(|i| enc[i].upgrade(&coarse, &mid));
    let tiles = [tile_upgrade(0, 0, 1, &up)];
    dec.decode(
        1,
        9,
        &stream(&[region(&rect, &[coarse, mid], 1, &tiles)]),
        &mut s,
        &mut Vec::new(),
    )
    .unwrap();
    let pass2 = s.pixels.clone();
    assert_ne!(pass2, pass1, "an upgrade changes the tile");
    assert!(max_channel_diff(&pass2, &want.pixels) < max_channel_diff(&pass1, &want.pixels));

    // To full quality (progressiveQuality 0xFF: every bit position 0).
    let up = [0, 1, 2].map(|i| enc[i].upgrade(&mid, &[0; 10]));
    let tiles = [tile_upgrade(0, 0, FULL_QUALITY, &up)];
    dec.decode(
        1,
        9,
        &stream(&[region(&rect, &[coarse, mid], 1, &tiles)]),
        &mut s,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(s.pixels, want.pixels, "all passes add up to the whole tile");
}

#[test]
fn difference_tile_adds_to_the_current_coefficients() {
    let (a, b) = (image(4), image(40));
    let (ca, cb) = (dwtq(&a, &EXTRAPOLATE), dwtq(&b, &EXTRAPOLATE));
    let rect = [(0u16, 0u16, 64u16, 64u16)];
    let mut dec = Progressive::new();
    let mut s = surface(64, 64, 0);
    let first = stream(&[region(&rect, &[], 1, &[simple_tile_bytes(&a, 0, 0)])]);
    dec.decode(1, 1, &first, &mut s, &mut Vec::new()).unwrap();
    let diff: [Vec<u8>; 3] = [0, 1, 2].map(|i| {
        let d: Vec<i32> = cb[i].iter().zip(&ca[i]).map(|(b, a)| b - a).collect();
        rlgr_with_deltas(&d, &EXTRAPOLATE)
    });
    let tiles = [tile_simple(0, 0, RFX_TILE_DIFFERENCE, &diff)];
    dec.decode(
        1,
        1,
        &stream(&[region(&rect, &[], 1, &tiles)]),
        &mut s,
        &mut Vec::new(),
    )
    .unwrap();
    let mut want = surface(64, 64, 0);
    let whole = stream(&[region(&rect, &[], 1, &[simple_tile_bytes(&b, 0, 0)])]);
    Progressive::new()
        .decode(1, 1, &whole, &mut want, &mut Vec::new())
        .unwrap();
    assert_eq!(s.pixels, want.pixels);
}

#[test]
fn regions_clip_tiles_and_reuse_earlier_tiles_of_the_frame() {
    let px = image(5);
    let mut s = surface(100, 70, 0xABCDEF);
    let mut dec = Progressive::new();
    // Region 1 carries the tile but asks for a 10x10 square only; region 2
    // asks for another square of the same tile without resending it.
    let r1 = region(&[(5, 5, 10, 10)], &[], 1, &[simple_tile_bytes(&px, 0, 0)]);
    let r2 = region(&[(40, 50, 8, 4)], &[], 1, &[]);
    let mut painted = Vec::new();
    dec.decode(1, 1, &stream(&[r1, r2]), &mut s, &mut painted)
        .unwrap();
    let mut full = surface(64, 64, 0);
    let whole = stream(&[region(
        &[(0, 0, 64, 64)],
        &[],
        1,
        &[simple_tile_bytes(&px, 0, 0)],
    )]);
    Progressive::new()
        .decode(1, 1, &whole, &mut full, &mut Vec::new())
        .unwrap();
    for y in 0..70 {
        for x in 0..100 {
            let inside = (5..15).contains(&x) && (5..15).contains(&y)
                || (40..48).contains(&x) && (50..54).contains(&y);
            let want = if inside {
                full.pixels[y * 64 + x]
            } else {
                0xABCDEF
            };
            assert_eq!(s.pixels[y * 100 + x], want, "({x}, {y})");
        }
    }
    assert_eq!(painted.len(), 2);
}

#[test]
fn regions_outside_a_frame_are_ignored() {
    let px = image(6);
    let mut s = surface(64, 64, 7);
    let r = region(&[(0, 0, 64, 64)], &[], 1, &[simple_tile_bytes(&px, 0, 0)]);
    Progressive::new()
        .decode(1, 1, &r, &mut s, &mut Vec::new())
        .unwrap();
    assert!(s.pixels.iter().all(|&p| p == 7));
}

#[test]
fn delete_context_frees_progressive_state() {
    let px = image(7);
    let c = dwtq(&px, &EXTRAPOLATE);
    let coarse = [5; 10];
    let rect = [(0u16, 0u16, 64u16, 64u16)];
    let mut enc: Vec<ProgEnc> = c.iter().map(|c| ProgEnc::new(c, &EXTRAPOLATE)).collect();
    let first = [0, 1, 2].map(|i| enc[i].first(&coarse));
    let up = [0, 1, 2].map(|i| enc[i].upgrade(&coarse, &[0; 10]));
    let mut dec = Progressive::new();
    let mut s = surface(64, 64, 0);
    let r = region(&rect, &[coarse], 1, &[tile_first(0, 0, 0, 0, &first)]);
    dec.decode(3, 21, &stream(&[r]), &mut s, &mut Vec::new())
        .unwrap();
    dec.delete_context(3, 21);
    assert_eq!(dec.counts(), (0, 1), "the tile's coefficients stay");
    let upgrade = stream(&[region(
        &rect,
        &[coarse],
        1,
        &[tile_upgrade(0, 0, 0xFF, &up)],
    )]);
    let r = dec.decode(3, 21, &upgrade, &mut s, &mut Vec::new());
    assert!(matches!(r, Err(crate::error::Error::Protocol(_))), "{r:?}");
    dec.delete_surface(3);
    assert_eq!(dec.counts(), (0, 0));
}

#[test]
fn bad_tiles_are_protocol_errors() {
    let px = image(8);
    let rect = [(0u16, 0u16, 64u16, 64u16)];
    let up = [
        (vec![0u8], vec![0u8]),
        (vec![0], vec![0]),
        (vec![0], vec![0]),
    ];
    let mut bad_quant = simple_tile_bytes(&px, 0, 0);
    bad_quant[6] = 1; // quantIdxY 1 of one table
    let cases = [
        // An upgrade with no first pass.
        region(&rect, &[[1; 10]], 1, &[tile_upgrade(0, 0, 0, &up)]),
        // progressiveQuality past the tables.
        region(
            &rect,
            &[],
            1,
            &[tile_first(0, 0, 0, 0, &[vec![], vec![], vec![]])],
        ),
        region(&rect, &[], 1, &[bad_quant]),
        // A non-tile block among the tiles.
        region(&rect, &[], 1, &[block(WBT_SYNC, &[0; 6])]),
    ];
    for (i, r) in cases.into_iter().enumerate() {
        let mut s = surface(64, 64, 0);
        let res = Progressive::new().decode(1, 1, &stream(&[r]), &mut s, &mut Vec::new());
        assert!(
            matches!(res, Err(crate::error::Error::Protocol(_))),
            "case {i}: {res:?}"
        );
    }
    // A tile outside the surface is read and dropped.
    let mut s = surface(64, 64, 5);
    let r = region(&rect, &[], 1, &[simple_tile_bytes(&px, 3, 0)]);
    let mut dec = Progressive::new();
    dec.decode(1, 1, &stream(&[r]), &mut s, &mut Vec::new())
        .unwrap();
    assert!(s.pixels.iter().all(|&p| p == 5));
    assert_eq!(dec.counts().1, 0);
}

fn xorshift(seed: &mut u32) -> u32 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 17;
    *seed ^= *seed << 5;
    *seed
}

#[test]
fn random_truncated_and_mutated_streams_never_panic() {
    let px = image(9);
    let c = dwtq(&px, &EXTRAPOLATE);
    let mut enc: Vec<ProgEnc> = c.iter().map(|c| ProgEnc::new(c, &EXTRAPOLATE)).collect();
    let coarse = [4; 10];
    let first = [0, 1, 2].map(|i| enc[i].first(&coarse));
    let up = [0, 1, 2].map(|i| enc[i].upgrade(&coarse, &[0; 10]));
    let rect = [(0u16, 0u16, 100u16, 70u16)];
    let valid = [
        stream(&[region(
            &rect,
            &[coarse],
            1,
            &[tile_first(0, 0, 0, 0, &first)],
        )]),
        stream(&[region(
            &rect,
            &[coarse],
            1,
            &[tile_upgrade(0, 0, 0xFF, &up)],
        )]),
        stream(&[region(&rect, &[], 0, &[simple_tile_bytes(&px, 1, 1)])]),
    ];
    let mut dec = Progressive::new();
    let mut s = surface(100, 70, 0);
    let mut seed = 0x9E37_79B9u32;
    for v in &valid {
        for n in 0..v.len() {
            let _ = dec.decode(1, 1, &v[..n], &mut s, &mut Vec::new());
        }
        for _ in 0..200 {
            let mut m = v.clone();
            for _ in 0..1 + xorshift(&mut seed) % 4 {
                let i = xorshift(&mut seed) as usize % m.len();
                m[i] = xorshift(&mut seed) as u8;
            }
            let _ = dec.decode(1, 1 + seed % 3, &m, &mut s, &mut Vec::new());
        }
    }
    for _ in 0..300 {
        let n = xorshift(&mut seed) as usize % 400;
        let mut m: Vec<u8> = (0..n).map(|_| xorshift(&mut seed) as u8).collect();
        // Half of them start with a plausible block header.
        if n > 6 && seed & 1 == 0 {
            m[..2].copy_from_slice(&WBT_REGION.to_le_bytes());
            m[2..6].copy_from_slice(&(n as u32).to_le_bytes());
        }
        let _ = dec.decode(1, 1, &m, &mut s, &mut Vec::new());
    }
    // Raw entropy decoders on noise, including all-ones runs.
    let mut out = vec![0i16; COEFFS];
    for fill in [0x00u8, 0xFF, 0xAA] {
        rlgr_decode(false, &[fill; 3000], &mut out);
        rlgr_decode(true, &[fill; 3000], &mut out);
        let mut sign = vec![0i8; COEFFS];
        let bands = EXTRAPOLATE.ranges();
        upgrade(
            &[fill; 500],
            &[fill; 500],
            &bands,
            &[15; 10],
            &[0; 10],
            &mut out,
            &mut sign,
        )
        .unwrap();
    }
}

// ---- The graphics channel (MS-RDPEGFX 2.2.2.2, 2.2.2.3, 3.3.5.2) ----

fn gfx_pdu(cmd: u16, body: &[u8]) -> Vec<u8> {
    let mut v = cmd.to_le_bytes().to_vec();
    v.extend(0u16.to_le_bytes());
    v.extend((8 + body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn wire2(id: u16, ctx: u32, data: &[u8]) -> Vec<u8> {
    let mut b = id.to_le_bytes().to_vec();
    b.extend(super::pdu::CODECID_CAPROGRESSIVE.to_le_bytes());
    b.extend(ctx.to_le_bytes());
    b.push(super::pdu::PIXEL_FORMAT_XRGB_8888);
    b.extend((data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    gfx_pdu(super::pdu::CMDID_WIRETOSURFACE_2, &b)
}

#[test]
fn parse_wire_to_surface_2_and_delete_context() {
    use super::pdu::{ServerPdu, parse_pdus};
    let mut buf = wire2(5, 0x0102_0304, &[9, 8, 7]);
    buf.extend(gfx_pdu(
        super::pdu::CMDID_DELETEENCODINGCONTEXT,
        &[5, 0, 4, 3, 2, 1],
    ));
    let pdus = parse_pdus(&buf).unwrap();
    assert_eq!(
        pdus[0].0,
        ServerPdu::WireToSurface2 {
            surface_id: 5,
            codec_id: 9,
            context_id: 0x0102_0304,
            pixel_format: 0x20,
            data: &[9, 8, 7],
        }
    );
    assert_eq!(
        pdus[1].0,
        ServerPdu::DeleteEncodingContext {
            surface_id: 5,
            context_id: 0x0102_0304,
        }
    );
}

#[test]
fn channel_paints_progressive_tiles_and_still_acknowledges() {
    use super::pdu::*;
    use crate::dvc::{DvcOut, DynamicChannel};
    let (mut ch, handle) = super::graphics(None);
    let px = image(10);
    let tile = stream(&[region(
        &[(0, 0, 64, 32)],
        &[],
        1,
        &[simple_tile_bytes(&px, 0, 0)],
    )]);
    let mut msg = vec![0xE0, 0x04];
    let reset = [64u32, 32, 0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    for p in [
        gfx_pdu(CMDID_RESETGRAPHICS, &reset),
        gfx_pdu(CMDID_CREATESURFACE, &[1, 0, 64, 0, 32, 0, 0x20]),
        gfx_pdu(
            CMDID_MAPSURFACETOOUTPUT,
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        gfx_pdu(CMDID_STARTFRAME, &[0; 8]),
        wire2(1, 3, &tile),
        // A corrupt one in the same message is skipped.
        wire2(1, 3, &[0xC4, 0xCC, 0xFF, 0, 0, 0]),
        gfx_pdu(CMDID_DELETEENCODINGCONTEXT, &[1, 0, 3, 0, 0, 0]),
        gfx_pdu(CMDID_ENDFRAME, &[4, 0, 0, 0]),
    ] {
        msg.extend(p);
    }
    let mut out = DvcOut::default();
    ch.process(&msg, &mut out).unwrap();
    assert_eq!(out.take(), vec![frame_acknowledge(0, 4, 1)]);
    let mut fb = crate::Framebuffer::new(64, 32);
    handle.present(&mut fb, &mut Vec::new());
    assert!(close(&fb.pixels, &px[..64 * 32]));
}

#[test]
fn per_tile_decode_cost() {
    // A rough figure, not a gate: 16 full-quality tiles, three times.
    let tiles: Vec<Vec<u8>> = (0..16u16)
        .map(|i| simple_tile_bytes(&image(i as u32), i % 4, i / 4))
        .collect();
    let data = stream(&[region(&[(0, 0, 256, 256)], &[], 1, &tiles)]);
    let mut dec = Progressive::new();
    let mut s = surface(256, 256, 0);
    let t = std::time::Instant::now();
    for _ in 0..3 {
        dec.decode(1, 1, &data, &mut s, &mut Vec::new()).unwrap();
    }
    let per = t.elapsed() / 48;
    // The reconstruction alone (dequantize, inverse DWT, colour).
    let c = dwtq(&image(1), &EXTRAPOLATE).map(|c| c.iter().map(|&v| v as i16).collect::<Vec<_>>());
    let mut rec = Reconstructor::new();
    let mut planes = vec![vec![0i32; COEFFS]; 3];
    let mut px = vec![0u32; COEFFS];
    let t = std::time::Instant::now();
    for _ in 0..48 {
        for (p, c) in planes.iter_mut().zip(&c) {
            rec.component(c, &Quant([6; 10]), &EXTRAPOLATE, p);
        }
        ycbcr_to_rgb(&planes[0], &planes[1], &planes[2], &mut px);
    }
    let recon = t.elapsed() / 48;
    let t = std::time::Instant::now();
    let streams = c.map(|c| rlgr1_encode(&c));
    let mut out = vec![0i16; COEFFS];
    for _ in 0..48 {
        for s in &streams {
            rlgr_decode(false, s, &mut out);
        }
    }
    let entropy = t.elapsed() / 48;
    eprintln!(
        "progressive: {per:?} per 64x64 tile; reconstruction {recon:?}, RLGR1 {entropy:?} \
         ({} bytes)",
        streams.iter().map(Vec::len).sum::<usize>()
    );
}
