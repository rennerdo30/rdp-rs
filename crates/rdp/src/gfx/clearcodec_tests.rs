//! ClearCodec (MS-RDPEGFX 2.2.4.1, 4.1.1) and NSCodec (MS-RDPNSC) tests.

use super::clearcodec::*;
use super::nsc;
use crate::error::Error;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

fn is_protocol<T: std::fmt::Debug>(r: crate::error::Result<T>) -> bool {
    matches!(r, Err(Error::Protocol(_)))
}

/// A CLEARCODEC_BITMAP_STREAM with a composite payload.
fn stream(flags: u8, glyph: Option<u16>, residual: &[u8], bands: &[u8], sub: &[u8]) -> Vec<u8> {
    let mut v = vec![flags, 0];
    if let Some(g) = glyph {
        v.extend(g.to_le_bytes());
    }
    for part in [residual, bands, sub] {
        v.extend((part.len() as u32).to_le_bytes());
    }
    for part in [residual, bands, sub] {
        v.extend_from_slice(part);
    }
    v
}

/// A CLEARCODEC_BAND header (inclusive ends, background B G R) and V-Bars.
fn band(x0: u16, x1: u16, y0: u16, y1: u16, bkg: [u8; 3], vbars: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [x0, x1, y0, y1] {
        v.extend(n.to_le_bytes());
    }
    v.extend(bkg);
    v.extend_from_slice(vbars);
    v
}

/// SHORT_VBAR_CACHE_MISS header and pixels (B G R each).
fn short_miss(y_on: u8, pixels: &[[u8; 3]]) -> Vec<u8> {
    let y_off = y_on as usize + pixels.len();
    let mut v = vec![y_on, y_off as u8];
    for p in pixels {
        v.extend(p);
    }
    v
}

fn short_hit(index: u16, y_on: u8) -> Vec<u8> {
    let mut v = (0x4000 | index).to_le_bytes().to_vec();
    v.push(y_on);
    v
}

fn vbar_hit(index: u16) -> Vec<u8> {
    (0x8000 | index).to_le_bytes().to_vec()
}

fn subcodec(x: u16, y: u16, w: u16, h: u16, id: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [x, y, w, h] {
        v.extend(n.to_le_bytes());
    }
    v.extend((data.len() as u32).to_le_bytes());
    v.push(id);
    v.extend_from_slice(data);
    v
}

fn decode(cc: &mut ClearCodec, data: &[u8], w: usize, h: usize) -> crate::error::Result<Vec<u32>> {
    let mut px = vec![0x0012_3456; w * h];
    cc.decode(data, w, h, &mut px).map(|_| px)
}

// ---- Spec examples (MS-RDPEGFX 4.1.1) ----

#[test]
fn example1_glyph_hit() {
    let data = hex("03 c3 11 00");
    let mut cc = ClearCodec::new();
    // Slot 17 is empty: the hit fails.
    assert!(is_protocol(decode(&mut cc, &data, 8, 9)));
    let glyph: Vec<u32> = (0..72).collect();
    cc.set_glyph(17, glyph.clone());
    assert_eq!(decode(&mut cc, &data, 8, 9).unwrap(), glyph);
    // Any shape of the same area takes the stream (4.1.1.5); another
    // area does not.
    assert_eq!(decode(&mut cc, &data, 24, 3).unwrap(), glyph);
    assert!(is_protocol(decode(&mut cc, &data, 8, 8)));
}

const EXAMPLE2: &str = "00 0d 00 00 00 00 00 00 00 00 82 00 00 00 00 00 \
    00 00 4e 00 11 00 75 00 00 00 02 0e ff ff ff 00 \
    00 00 db ff ff 00 3a 90 ff b6 66 66 b6 ff b6 66 \
    00 90 db ff 00 00 3a db 90 3a 3a 90 db 66 00 00 \
    ff ff b6 64 64 64 11 04 11 4c 11 4c 11 4c 11 4c \
    11 4c 00 47 13 00 01 01 04 00 01 00 00 47 16 00 \
    11 02 00 47 29 00 11 01 00 49 0a 00 01 00 04 00 \
    01 00 00 4a 0a 00 09 00 01 00 00 47 05 00 01 01 \
    1c 00 01 00 11 4c 11 4c 11 4c 00 47 0d 4d 00 4d";

#[test]
fn example2_rlex_subcodec() {
    let data = hex(EXAMPLE2);
    assert_eq!(data.len(), 144);
    // The RLEX payload alone decodes to exactly 78 x 17 pixels.
    let rlex_data = &data[2 + 12 + 13..];
    assert_eq!(rlex_data.len(), 117);
    let px = rlex(rlex_data, 78 * 17).unwrap();
    assert_eq!(px.len(), 78 * 17);
    // First segment: index 0 four times, then the suite 0, 1.
    let (white, black) = (0x00FF_FFFF, 0);
    assert_eq!(&px[..6], &[white, white, white, white, white, black]);
    // Second segment: 76 more of index 0, then 0, 1.
    assert!(px[6..83].iter().all(|&p| p == white));
    assert_eq!(px[83], black);
    // The suite 7, 8, 9 of the sixteenth segment, in RGB.
    let at = px
        .windows(3)
        .position(|w| w == [0xFF_DB90, 0x3A_0000, 0x3A_90DB])
        .expect("suite 7..=9 decoded");
    assert!(at > 83);

    let mut cc = ClearCodec::new();
    assert_eq!(decode(&mut cc, &data, 78, 17).unwrap(), px);
    // One pixel less does not fit.
    assert!(is_protocol(rlex(rlex_data, 78 * 17 - 1)));
}

const EXAMPLE3: &str = "00 df 0e 00 00 00 8b 00 00 00 00 00 00 00 fe fe \
    fe ff 80 05 ff ff ff 40 fe fe fe 40 00 00 3f 00 \
    03 00 0b 00 fe fe fe c5 d0 c6 d0 c7 d0 68 d4 69 \
    d4 6a d4 6b d4 6c d4 6d d4 1a d4 1a d4 a6 d0 6e \
    d4 6f d4 70 d4 71 d4 72 d4 73 d4 74 d4 21 d4 22 \
    d4 23 d4 24 d4 25 d4 d9 d0 da d0 db d0 c5 d0 c5 \
    d0 dc d0 c2 d0 21 d4 22 d4 23 d4 24 d4 25 d4 c9 \
    d0 ca d0 5a d4 2b d1 28 d1 2c d1 75 d4 27 d4 28 \
    d4 29 d4 2a d4 1a d4 1a d4 1a d4 b7 d0 b8 d0 b9 \
    d0 ba d0 bb d0 bc d0 bd d0 be d0 bf d0 c0 d0 c1 \
    d0 c2 d0 c3 d0 c4 d0";

#[test]
fn example3_residual_and_vbar_hits() {
    let data = hex(EXAMPLE3);
    assert_eq!(data.len(), 167);
    let headers: Vec<usize> = data[14 + 14 + 11..]
        .chunks(2)
        .map(|c| (u16::from_le_bytes([c[0], c[1]]) & 0x7FFF) as usize)
        .collect();
    assert_eq!(headers.len(), 64);
    assert_eq!(headers[0], 0x50c5);
    let mut cc = ClearCodec::new();
    // Without the V-Bars an earlier PDU stored, the stream fails.
    assert!(is_protocol(decode(&mut cc, &data, 64, 24)));
    // Each stored V-Bar is 9 pixels; pixel y of V-Bar i is i * 16 + y.
    for &i in &headers {
        cc.set_vbar(i, (0..9).map(|y| (i * 16 + y) as u32).collect());
    }
    let px = decode(&mut cc, &data, 64, 24).unwrap();
    let (fe, ff) = (0x00FE_FEFE, 0x00FF_FFFF);
    for y in 0..24 {
        for x in 0..64 {
            let want = match y {
                3..=11 => (headers[x] * 16 + y - 3) as u32,
                22 => ff, // pixels 1408..1472 of the residual layer
                _ => fe,
            };
            assert_eq!(px[y * 64 + x], want, "pixel ({x},{y})");
        }
    }
    // Hits leave the cursors alone.
    assert_eq!(cc.cursors(), (0, 0));
}

const EXAMPLE4: &str = "01 0b 78 00 00 00 00 00 46 00 00 00 00 00 00 00 \
    00 00 06 00 00 00 0e 00 00 00 00 00 0f ff ff ff \
    ff ff ff ff ff ff b6 ff ff ff ff ff ff ff ff ff \
    b6 66 ff ff ff ff ff ff ff b6 66 db 90 3a ff ff \
    b6 ff ff ff ff ff ff ff ff ff 46 91 47 91 48 91 \
    49 91 4a 91 1b 91";

#[test]
fn example4_short_vbar_miss_and_glyph_store() {
    let data = hex(EXAMPLE4);
    assert_eq!(data.len(), 86);
    let mut cc = ClearCodec::new();
    let hits = [0x1146, 0x1147, 0x1148, 0x1149, 0x114a, 0x111b];
    for (n, &i) in hits.iter().enumerate() {
        cc.set_vbar(i, vec![n as u32 + 1; 15]);
    }
    let px = decode(&mut cc, &data, 7, 15).unwrap();
    // Column 0: the 15 pixels of the Short V-Bar miss.
    let column: Vec<u32> = data[29..29 + 45]
        .chunks(3)
        .map(|p| (p[2] as u32) << 16 | (p[1] as u32) << 8 | p[0] as u32)
        .collect();
    assert_eq!(column[0], 0x00FF_FFFF);
    assert_eq!(column[10], 0x003A_90DB); // 11th pixel: db 90 3a
    for y in 0..15 {
        assert_eq!(px[y * 7], column[y]);
        for x in 1..7 {
            assert_eq!(px[y * 7 + x], x as u32);
        }
    }
    // The miss went to both storages at their cursors, which advanced.
    assert_eq!(cc.short_vbar(0), Some(&column[..]));
    assert_eq!(cc.vbar(0), Some(&column[..]));
    assert_eq!(cc.cursors(), (1, 1));
    // Glyph 120 holds the decoded bitmap; a later hit draws it.
    assert_eq!(cc.glyph(120), Some(&px[..]));
    assert_eq!(decode(&mut cc, &hex("03 0c 78 00"), 15, 7).unwrap(), px);
}

// ---- Hand-built streams ----

#[test]
fn residual_runs_and_coverage() {
    let mut cc = ClearCodec::new();
    // 4 x 2: two of red (one-byte run), then five of blue through the
    // two-byte form; the last pixel keeps the destination.
    let residual = hex("00 00 ff 02 ff 00 00 ff 05 00");
    let px = decode(&mut cc, &stream(0, None, &residual, &[], &[]), 4, 2).unwrap();
    let (red, blue, old) = (0x00FF_0000, 0x0000_00FF, 0x0012_3456);
    assert_eq!(px, vec![red, red, blue, blue, blue, blue, blue, old]);
    // The four-byte form.
    let residual = hex("01 02 03 ff ff ff 08 00 00 00");
    let px = decode(&mut cc, &stream(0, None, &residual, &[], &[]), 4, 2).unwrap();
    assert_eq!(px, vec![0x0003_0201; 8]);
    // One pixel too many.
    let residual = hex("01 02 03 09");
    assert!(is_protocol(decode(
        &mut cc,
        &stream(0, None, &residual, &[], &[]),
        4,
        2
    )));
    // A run cut short.
    let residual = hex("01 02 03 ff 05");
    assert!(is_protocol(decode(
        &mut cc,
        &stream(0, None, &residual, &[], &[]),
        4,
        2
    )));
}

#[test]
fn bands_short_vbars_and_storage() {
    let mut cc = ClearCodec::new();
    let (b, g, r) = ([0xff, 0, 0], [0, 0xff, 0], [0, 0, 0xff]);
    let bkg = [0x10, 0x20, 0x30];
    let bk = 0x0030_2010;
    let (blue, green, red) = (0x0000_00FF, 0x0000_FF00, 0x00FF_0000);
    // A 3 x 4 band at (1,1) in a 5 x 6 bitmap: a miss with yOn 1 and two
    // pixels, a miss with yOn 0 and one pixel, then a hit on short 0 at
    // yOn 2.
    let mut vbars = short_miss(1, &[b, g]);
    vbars.extend(short_miss(0, &[r]));
    vbars.extend(short_hit(0, 2));
    let bands = band(1, 3, 1, 4, bkg, &vbars);
    let px = decode(&mut cc, &stream(0, None, &[], &bands, &[]), 5, 6).unwrap();
    let old = 0x0012_3456;
    let col = |x: usize| -> Vec<u32> { (0..6).map(|y| px[y * 5 + x]).collect() };
    assert_eq!(col(0), vec![old; 6]);
    assert_eq!(col(1), vec![old, bk, blue, green, bk, old]);
    assert_eq!(col(2), vec![old, red, bk, bk, bk, old]);
    assert_eq!(col(3), vec![old, bk, bk, blue, green, old]);
    assert_eq!(col(4), vec![old; 6]);
    assert_eq!(cc.short_vbar(0), Some(&[blue, green][..]));
    assert_eq!(cc.short_vbar(1), Some(&[red][..]));
    assert_eq!(cc.vbar(2), Some(&[bk, bk, blue, green][..]));
    assert_eq!(cc.cursors(), (3, 2));

    // The next PDU reuses all three V-Bars by index, in another band.
    let mut vbars = vbar_hit(2);
    vbars.extend(vbar_hit(0));
    vbars.extend(vbar_hit(1));
    let bands = band(0, 2, 2, 5, [0; 3], &vbars);
    let px = decode(&mut cc, &stream(0, None, &[], &bands, &[]), 5, 6).unwrap();
    assert_eq!(px[2 * 5], bk);
    assert_eq!(px[5 * 5], green);
    assert_eq!(px[2 * 5 + 1], bk);
    assert_eq!(px[3 * 5 + 1], blue);
    assert_eq!(px[2 * 5 + 2], red);
    assert_eq!(cc.cursors(), (3, 2));

    // A zero-length Short V-Bar is legal: the column is background.
    let bands = band(0, 0, 0, 1, bkg, &short_miss(1, &[]));
    let px = decode(&mut cc, &stream(0, None, &[], &bands, &[]), 1, 2).unwrap();
    assert_eq!(px, vec![bk, bk]);
    assert_eq!(cc.short_vbar(2), Some(&[][..]));
    assert_eq!(cc.cursors(), (4, 3));
}

#[test]
fn cursors_wrap_and_reset() {
    let mut cc = ClearCodec::new();
    cc.set_cursors(VBAR_SLOTS - 1, SHORT_VBAR_SLOTS - 1);
    let bands = band(0, 0, 0, 0, [0; 3], &short_miss(0, &[[1, 2, 3]]));
    decode(&mut cc, &stream(0, None, &[], &bands, &[]), 1, 1).unwrap();
    assert_eq!(cc.cursors(), (0, 0));
    assert_eq!(cc.vbar(VBAR_SLOTS - 1), Some(&[0x0003_0201][..]));
    assert_eq!(
        cc.short_vbar(SHORT_VBAR_SLOTS - 1),
        Some(&[0x0003_0201][..])
    );
    decode(&mut cc, &stream(0, None, &[], &bands, &[]), 1, 1).unwrap();
    assert_eq!(cc.cursors(), (1, 1));
    // CLEARCODEC_FLAG_CACHE_RESET zeroes both cursors before decoding.
    cc.set_cursors(70, 50);
    decode(
        &mut cc,
        &stream(FLAG_CACHE_RESET, None, &[], &bands, &[]),
        1,
        1,
    )
    .unwrap();
    assert_eq!(cc.cursors(), (1, 1));
}

#[test]
fn bad_bands_are_errors() {
    let px = |cc: &mut ClearCodec, bands: Vec<u8>| {
        is_protocol(decode(cc, &stream(0, None, &[], &bands, &[]), 4, 60))
    };
    let mut cc = ClearCodec::new();
    let one = short_miss(0, &[[0; 3]]);
    // Outside the bitmap, reversed, taller than 52.
    assert!(px(&mut cc, band(4, 4, 0, 0, [0; 3], &one)));
    assert!(px(&mut cc, band(0, 0, 60, 60, [0; 3], &one)));
    assert!(px(&mut cc, band(1, 0, 0, 0, [0; 3], &one)));
    assert!(px(&mut cc, band(0, 0, 0, 52, [0; 3], &one)));
    // Fewer V-Bars than columns.
    assert!(px(&mut cc, band(0, 1, 0, 0, [0; 3], &one)));
    // Empty slots.
    assert!(px(&mut cc, band(0, 0, 0, 0, [0; 3], &vbar_hit(9))));
    assert!(px(&mut cc, band(0, 0, 0, 0, [0; 3], &short_hit(9, 0))));
    // A V-Bar of another height.
    cc.set_vbar(5, vec![0; 3]);
    assert!(px(&mut cc, band(0, 0, 0, 1, [0; 3], &vbar_hit(5))));
    // yOff before yOn.
    assert!(px(&mut cc, band(0, 0, 0, 3, [0; 3], &[2, 1])));
    // A Short V-Bar that ends below the band, by miss and by hit.
    assert!(px(
        &mut cc,
        band(0, 0, 0, 1, [0; 3], &short_miss(1, &[[0; 3]; 2]))
    ));
    let before = cc.cursors().1;
    decode(
        &mut cc,
        &stream(
            0,
            None,
            &[],
            &band(0, 0, 0, 2, [0; 3], &short_miss(0, &[[0; 3]; 3])),
            &[],
        ),
        4,
        60,
    )
    .unwrap();
    assert!(px(
        &mut cc,
        band(0, 0, 0, 2, [0; 3], &short_hit(before as u16, 1))
    ));
    // Pixels cut short.
    assert!(px(&mut cc, band(0, 0, 0, 3, [0; 3], &[0, 3, 1, 2, 3])));
}

#[test]
fn subcodecs_raw_rlex_nscodec() {
    let mut cc = ClearCodec::new();
    let old = 0x0012_3456;
    // Raw 2 x 1 at (1,0), then RLEX 2 x 2 at (0,1) with a palette of 3
    // (2 index bits): byte 0x05 is stop 1, depth 1; a run of 1 of colour 0,
    // then the suite 0, 1. Three pixels; the fourth keeps the destination.
    let palette = "03 10 00 00 20 00 00 30 00 00";
    let raw = subcodec(1, 0, 2, 1, SUBCODEC_UNCOMPRESSED, &hex("01 02 03 04 05 06"));
    let mut sub = raw.clone();
    sub.extend(subcodec(
        0,
        1,
        2,
        2,
        SUBCODEC_RLEX,
        &hex(&format!("{palette} 05 01")),
    ));
    let px = decode(&mut cc, &stream(0, None, &[], &[], &sub), 3, 3).unwrap();
    let (c0, c1) = (0x10, 0x20);
    assert_eq!(
        px,
        vec![old, 0x0003_0201, 0x0006_0504, c0, c0, old, c1, old, old]
    );
    // A run of 3 and the suite overflow the four pixels.
    let mut sub = raw.clone();
    sub.extend(subcodec(
        0,
        1,
        2,
        2,
        SUBCODEC_RLEX,
        &hex(&format!("{palette} 05 03")),
    ));
    assert!(is_protocol(decode(
        &mut cc,
        &stream(0, None, &[], &[], &sub),
        3,
        3
    )));

    // NSCodec 4 x 4 at (1,1) of 5 x 5: RLE planes (a raw NSCodec stream
    // is larger than 3 * width * height), CLL 1, no subsampling.
    let sub = subcodec(1, 1, 4, 4, SUBCODEC_NSCODEC, &nsc_flat_4x4(100, 0x10, 0xF8));
    let px = decode(&mut cc, &stream(0, None, &[], &[], &sub), 5, 5).unwrap();
    for y in 0..5 {
        for x in 0..5 {
            let want = if x > 0 && y > 0 { 0x007C_5C5C } else { old };
            assert_eq!(px[y * 5 + x], want);
        }
    }

    // Errors: outside the bitmap, too many bytes, raw size, unknown id.
    for bad in [
        subcodec(2, 0, 2, 1, SUBCODEC_UNCOMPRESSED, &[0; 6]),
        subcodec(0, 0, 1, 1, SUBCODEC_RLEX, &[1, 0, 0, 0, 0]),
        subcodec(0, 0, 2, 1, SUBCODEC_UNCOMPRESSED, &[0; 5]),
        subcodec(0, 0, 1, 1, 3, &[0; 3]),
        subcodec(0, 0, 1, 1, SUBCODEC_RLEX, &[0, 0]),
    ] {
        assert!(is_protocol(decode(
            &mut cc,
            &stream(0, None, &[], &[], &bad),
            3,
            3
        )));
    }
}

#[test]
fn rlex_bad_indexes() {
    // Palette of 1: no index bits; byte 0 is the only valid segment.
    assert_eq!(
        rlex(&hex("01 0a 0b 0c 00 02"), 9).unwrap(),
        vec![0x000C_0B0A; 3]
    );
    assert!(is_protocol(rlex(&hex("01 0a 0b 0c 01 00"), 9)));
    // Palette of 2, stop index 1 with depth 2 starts below zero.
    assert!(is_protocol(rlex(&hex("02 00 00 00 00 00 00 05 00"), 9)));
    // Palette of 3 (2 bits), stop index 3 does not exist.
    assert!(is_protocol(rlex(
        &hex("03 00 00 00 00 00 00 00 00 00 03 00"),
        9
    )));
    // paletteCount 0 and 0x80.
    assert!(is_protocol(rlex(&[0], 9)));
    assert!(is_protocol(rlex(&[0x80], 9)));
}

#[test]
fn glyph_index_and_hit_rules() {
    let mut cc = ClearCodec::new();
    let residual = hex("01 02 03 06");
    let s = stream(FLAG_GLYPH_INDEX, Some(3999), &residual, &[], &[]);
    let px = decode(&mut cc, &s, 3, 2).unwrap();
    assert_eq!(cc.glyph(3999), Some(&px[..]));
    // Index 4000 is outside the storage.
    let s = stream(FLAG_GLYPH_INDEX, Some(4000), &residual, &[], &[]);
    assert!(is_protocol(decode(&mut cc, &s, 3, 2)));
    // A hit without an index.
    assert!(is_protocol(decode(&mut cc, &[FLAG_GLYPH_HIT, 0], 3, 2)));
    // Glyphs hold at most 1,024 pixels.
    let s = stream(
        FLAG_GLYPH_INDEX,
        Some(1),
        &hex("01 02 03 ff 01 04"),
        &[],
        &[],
    );
    assert!(is_protocol(decode(&mut cc, &s, 1025, 1)));
    assert!(
        decode(
            &mut cc,
            &stream(FLAG_GLYPH_INDEX, Some(1), &[], &[], &[]),
            1024,
            1
        )
        .is_ok()
    );
    // Without the flag nothing is stored.
    decode(&mut cc, &stream(0, None, &residual, &[], &[]), 3, 2).unwrap();
    assert_eq!(cc.glyph(0), None);
}

#[test]
fn truncated_and_random_streams_never_panic() {
    let examples = [
        hex(EXAMPLE2),
        hex(EXAMPLE3),
        hex(EXAMPLE4),
        hex(NSC_EXAMPLE),
    ];
    let mut cc = ClearCodec::new();
    for ex in &examples[..3] {
        for n in 0..ex.len() {
            let _ = decode(&mut cc, &ex[..n], 78, 24);
        }
    }
    for n in 0..examples[3].len() {
        assert!(nsc::decode(&examples[3][..n], 15, 10).is_err());
    }
    let mut seed = 0x9E37_79B9u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for round in 0..3000 {
        // Mutate a few bytes of an example, or make random bytes behind a
        // plausible header.
        let mut msg = if round % 2 == 0 {
            let mut m = examples[(next() % 4) as usize].clone();
            for _ in 0..1 + next() % 4 {
                let i = next() as usize % m.len();
                m[i] = next() as u8;
            }
            m
        } else {
            let len = (next() % 64) as usize;
            (0..len).map(|_| next() as u8).collect()
        };
        if round % 4 == 1 && msg.len() > 14 {
            msg[0] &= 0x07;
            for (i, b) in msg.iter_mut().enumerate().take(14).skip(2) {
                *b = (next() % 24) as u8 * u8::from(i % 4 == 2);
            }
        }
        let (w, h) = (1 + next() as usize % 80, 1 + next() as usize % 30);
        let _ = decode(&mut cc, &msg, w, h);
        let _ = nsc::decode(&msg, w, h);
        let _ = rlex(&msg, w * h);
    }
}

// ---- NSCodec (MS-RDPNSC) ----

/// NSCodec stream of 4 x 4 pixels of one colour: each plane a run of 12
/// and four bytes of EndData, CLL 1, no subsampling.
fn nsc_flat_4x4(y: u8, co: u8, cg: u8) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [7u32, 7, 7, 0] {
        v.extend(n.to_le_bytes());
    }
    v.extend([1, 0, 0, 0]);
    for b in [y, co, cg] {
        v.extend([b, b, 10, b, b, b, b]);
    }
    v
}

/// NSCodec stream of one pixel: raw planes, CLL 1, no subsampling.
fn nsc_raw_1x1(y: u8, co: u8, cg: u8) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [1u32, 1, 1, 0] {
        v.extend(n.to_le_bytes());
    }
    v.extend([1, 0, 0, 0, y, co, cg]);
    v
}

const NSC_EXAMPLE: &str = "71 00 00 00 07 00 00 00 0b 00 00 00 07 00 00 00 \
    03 01 00 00 63 63 01 64 64 00 63 63 02 64 64 00 \
    63 63 00 64 64 01 63 63 01 64 64 01 63 63 01 64 \
    64 00 63 63 00 64 64 01 63 63 00 64 64 0c 63 63 \
    00 64 64 0c 63 63 00 64 64 0c 63 63 00 64 64 0c \
    63 64 64 04 63 64 63 63 00 64 64 03 63 64 64 03 \
    63 63 00 64 63 63 00 64 64 03 65 63 64 64 01 63 \
    64 64 00 65 64 64 06 63 64 64 00 63 63 00 64 64 \
    04 64 65 65 65 22 22 22 22 22 22 22 37 37 19 36 \
    37 37 06 37 37 37 37 ff ff 90 ff ff ff ff";

#[test]
fn nsc_spec_example() {
    // MS-RDPNSC 4: 15 x 10, CLL 3, chroma subsampling, every plane RLE.
    let data = hex(NSC_EXAMPLE);
    assert_eq!(data.len(), 158);
    let want = hex("ff 3f 0f ff ff 3f 0f ff ff 3f 0f ff ff 40 10 ff \
        ff 40 10 ff ff 3f 0f ff ff 3f 0f ff ff 3f 0f ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 3f 0f ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 3f 0f ff \
        ff 3f 0f ff ff 3f 0f ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 3f 0f ff ff 3f 0f ff ff 3f 0f ff \
        ff 40 10 ff ff 40 10 ff ff 3f 0f ff ff 3f 0f ff \
        ff 40 10 ff ff 40 10 ff ff 3f 0f ff ff 3f 0f ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 3f 0f ff ff 3f 0f ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 3f 0f ff ff 3f 0f ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 3f 0f ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 3f 0f ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 3c 14 ff ff 3b 13 ff ff 40 10 ff ff 3f 0f ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 3f 0f ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 3b 13 ff \
        ff 3b 13 ff ff 40 10 ff ff 3f 0f ff ff 3f 0f ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 41 11 ff ff 3f 0f ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 3f 0f ff ff 40 10 ff ff 40 10 ff \
        ff 41 11 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 3f 0f ff \
        ff 3f 0f ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 40 10 ff ff 40 10 ff ff 40 10 ff ff 40 10 ff \
        ff 41 11 ff ff 41 11 ff");
    assert_eq!(want.len(), 600);
    // B G R A per pixel; alpha is not kept.
    let want: Vec<u32> = want
        .chunks(4)
        .map(|p| (p[2] as u32) << 16 | (p[1] as u32) << 8 | p[0] as u32)
        .collect();
    assert_eq!(nsc::decode(&data, 15, 10).unwrap(), want);
}

#[test]
fn nsc_raw_planes_hand_computed() {
    // Y 100, Co 0x10 << 1 = 32, Cg 0xF8 << 1 = 0x1F0 = -16:
    // R = 100 + 16 + 8, G = 100 - 8, B = 100 - 16 + 8.
    assert_eq!(
        nsc::decode(&nsc_raw_1x1(100, 0x10, 0xF8), 1, 1).unwrap(),
        vec![0x007C_5C5C]
    );
    // Clamping: Y 250, Co 0x7F << 1 = 254 -> R = 250 + 127 > 255, B < 0.
    assert_eq!(
        nsc::decode(&nsc_raw_1x1(250, 0x7F, 0), 1, 1).unwrap(),
        vec![0x00FF_FA7B]
    );
    // CLL 7 takes only the low bits that stay inside 9 bits: 0x03 << 7 =
    // 0x180 = -128.
    let mut s = nsc_raw_1x1(128, 0x03, 0);
    s[16] = 7;
    assert_eq!(nsc::decode(&s, 1, 1).unwrap(), vec![0x0040_80C0]);
    // CLL 0 and 8 are invalid.
    for cll in [0, 8] {
        s[16] = cll;
        assert!(is_protocol(nsc::decode(&s, 1, 1)));
    }
}

#[test]
fn nsc_chroma_super_sampling() {
    // 3 x 3 with subsampling: luma rows padded to 8, chroma 4 x 2. Every
    // chroma sample is distinct; each covers a 2 x 2 block.
    let luma: Vec<u8> = vec![100; 8 * 3];
    let co: Vec<u8> = (0..8).map(|i| i * 2).collect();
    let cg = vec![0u8; 8];
    let mut s = Vec::new();
    for n in [luma.len(), co.len(), cg.len(), 0] {
        s.extend((n as u32).to_le_bytes());
    }
    s.extend([1, 1, 0, 0]);
    s.extend(&luma);
    s.extend(&co);
    s.extend(&cg);
    let px = nsc::decode(&s, 3, 3).unwrap();
    // Co = 2 * byte, so R = 100 + byte and B = 100 - byte.
    let at = |x: usize, y: usize| co[(y / 2) * 4 + x / 2] as u32;
    for y in 0..3 {
        for x in 0..3 {
            let c = at(x, y);
            assert_eq!(
                px[y * 3 + x],
                (100 + c) << 16 | 100 << 8 | (100 - c),
                "({x},{y})"
            );
        }
    }
    assert_eq!(px[8], (100 + 10) << 16 | 100 << 8 | 90);
}

#[test]
fn nsc_rle_planes() {
    // Run (short form), literal, run (long form), EndData.
    let data = hex("07 07 01 08 09 09 ff 05 01 00 00 01 02 03 04");
    let mut want = vec![7, 7, 7, 8];
    want.extend([9; 261]);
    want.extend([1, 2, 3, 4]);
    assert_eq!(nsc::rle_plane(&data, want.len()).unwrap(), want);
    // One byte short, one byte over, a run cut short, no EndData.
    assert!(is_protocol(nsc::rle_plane(&data, want.len() + 1)));
    assert!(is_protocol(nsc::rle_plane(&data, want.len() - 1)));
    assert!(is_protocol(nsc::rle_plane(
        &hex("05 07 07 ff 00 01 02 03 04"),
        300
    )));
    assert!(is_protocol(nsc::rle_plane(&hex("01 02 03"), 9)));
    // A plane larger than expected.
    assert!(is_protocol(nsc::rle_plane(&[0; 10], 9)));
}
