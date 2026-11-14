//! Drawing order tests: the annotated examples of MS-RDPEGDI section 4,
//! rendering of every primary order on a small framebuffer, the caches, the
//! persistent bitmap cache and the capability sets.

use super::draw::{self, Clip, Pattern, Source, Surface};
use super::fields::{self, DeltaRect};
use super::primary::{self, History};
use super::secondary::{self, BitmapCodec, Secondary};
use super::*;
use crate::cursor::Reader;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// Decodes one primary order into `h`; the order must be consumed exactly.
fn read(h: &mut History, bytes: &[u8]) -> primary::Header {
    let mut r = Reader::new(bytes);
    let control = r.u8().unwrap();
    let header = h.read(control, &mut r).unwrap();
    assert_eq!(r.remaining(), 0, "order not consumed exactly");
    header
}

fn dr(left: i32, top: i32, width: i32, height: i32) -> DeltaRect {
    DeltaRect {
        left,
        top,
        width,
        height,
    }
}

// ---- MS-RDPEGDI 4.1: annotated primary drawing orders ----

#[test]
fn spec_dstblt() {
    let mut h = History::default();
    let hd = read(&mut h, &hex("09 00 0c 48 00 37 01"));
    assert_eq!(hd.order_type, primary::DSTBLT);
    assert_eq!(hd.bounds, None);
    assert_eq!((h.dstblt.rect.w, h.dstblt.rect.h), (72, 311));
}

#[test]
fn spec_multi_dstblt() {
    let mut h = History::default();
    read(
        &mut h,
        &hex("09 0f 7f 12 01 2d 01 a0 00 0c 00 55 02 0d 00 04 81 12 81 2d 80 58 0c 80 60 80 40 0c"),
    );
    let o = &h.multi_dstblt;
    assert_eq!(
        (o.rect.x, o.rect.y, o.rect.w, o.rect.h),
        (274, 301, 160, 12)
    );
    assert_eq!(o.rop, 0x55);
    let rects = fields::delta_rects(&o.deltas, o.n as usize).unwrap();
    assert_eq!(rects, vec![dr(274, 301, 88, 12), dr(370, 301, 64, 12)]);
}

#[test]
fn spec_patblt() {
    let mut h = History::default();
    read(
        &mut h,
        &hex("09 01 7f 02 1a 00 c3 01 0d 00 0d 00 f0 ff ff 00 5b ef 00 81"),
    );
    let o = &h.patblt;
    assert_eq!((o.rect.x, o.rect.y, o.rect.w, o.rect.h), (26, 451, 13, 13));
    assert_eq!(o.rop, 0xF0);
    assert_eq!((o.back, o.fore), (0x00FFFF, 0x00EF5B));
    assert_eq!(o.brush.style, 0x81);
}

#[test]
fn spec_multi_patblt() {
    let mut h = History::default();
    read(
        &mut h,
        &hex(
            "09 10 df 31 e4 00 b7 00 0e 02 c5 01 5a ff ff 00 ae b2 04 19 00 08 40 80 e4 80 b7 82 0e 1b \
             1b 81 07 32 81 39 80 d5 32 fe c7 32 82 0e 81 78",
        ),
    );
    let o = &h.multi_patblt;
    assert_eq!(
        (o.rect.x, o.rect.y, o.rect.w, o.rect.h),
        (228, 183, 526, 453)
    );
    assert_eq!((o.rop, o.fore), (0x5A, 0x00FFFF));
    assert_eq!((o.brush.org_x, o.brush.org_y), (-82, -78));
    let rects = fields::delta_rects(&o.deltas, o.n as usize).unwrap();
    assert_eq!(
        rects,
        vec![
            dr(228, 183, 526, 27),
            dr(228, 210, 263, 50),
            dr(541, 210, 213, 50),
            dr(228, 260, 526, 376)
        ]
    );
}

#[test]
fn spec_opaque_rect() {
    // The dump in 4.1.5 has fieldFlags 0x3c (fields 3-6) but also lists a
    // Blue byte (field 7): with the flags as sent, that byte is left over.
    let mut h = History::default();
    let bytes = hex("09 0a 3c 00 04 00 03 73 02 06");
    let mut r = Reader::new(&bytes);
    let control = r.u8().unwrap();
    h.read(control, &mut r).unwrap();
    assert_eq!(r.rest(), &[0x06]);
    let o = &h.opaque_rect;
    assert_eq!((o.rect.w, o.rect.h), (1024, 768));
    let orders = Orders::new(None);
    assert_eq!(orders.color(o.color), 0x730200);
    // With field 7 flagged the colour is complete.
    read(&mut h, &hex("09 0a 7c 00 04 00 03 73 02 06"));
    assert_eq!(orders.color(h.opaque_rect.color), 0x730206);
}

#[test]
fn spec_multi_opaque_rect() {
    let mut h = History::default();
    read(
        &mut h,
        &hex(
            "09 12 bf 01 87 01 1c 01 f1 00 12 00 5c ef 04 16 00 08 40 81 87 81 1c 80 f1 01 01 01 10 \
             80 f0 01 10 ff 10 10 80 f1 01",
        ),
    );
    let o = &h.multi_opaque_rect;
    assert_eq!(
        (o.rect.x, o.rect.y, o.rect.w, o.rect.h),
        (391, 284, 241, 18)
    );
    assert_eq!(o.color, 0x00EF5C);
    let rects = fields::delta_rects(&o.deltas, o.n as usize).unwrap();
    assert_eq!(
        rects,
        vec![
            dr(391, 284, 241, 1),
            dr(391, 285, 1, 16),
            dr(631, 285, 1, 16),
            dr(391, 301, 241, 1)
        ]
    );
}

#[test]
fn spec_scrblt() {
    // The dump in 4.1.7 lists nYSrc as "8e 00" but prints only "8e".
    let mut h = History::default();
    read(&mut h, &hex("09 02 7d 07 00 a1 01 f1 00 cc 2f 01 8e 00"));
    let o = &h.scrblt;
    assert_eq!((o.rect.x, o.rect.w, o.rect.h), (7, 417, 241));
    assert_eq!((o.rop, o.x_src, o.y_src), (0xCC, 303, 142));
}

#[test]
fn spec_memblt() {
    let mut h = History::default();
    read(&mut h, &hex("49 0d 97 ff 00 02 00 06 01 15 00 15 00"));
    let o = &h.memblt;
    assert_eq!(o.cache_id, 0x00FF);
    assert_eq!((o.rect.x, o.rect.y, o.rect.h), (2, 262, 21));
    assert_eq!(o.y_src, 21);
}

#[test]
fn spec_mem3blt() {
    let mut h = History::default();
    read(
        &mut h,
        &hex("49 0e 3f 8e 01 00 3c 01 1f 01 40 00 0c 00 b8 ff ff 00 3b 1e ff 7f"),
    );
    let o = &h.mem3blt;
    assert_eq!(o.cache_id, 1);
    assert_eq!((o.rect.x, o.rect.y, o.rect.w, o.rect.h), (316, 287, 64, 12));
    assert_eq!((o.rop, o.fore), (0xB8, 0x00FFFF));
    assert_eq!((o.brush.org_x, o.brush.org_y), (59, 30));
    assert_eq!(o.cache_index, 32767);
}

#[test]
fn spec_lineto_with_delta_bounds_and_coordinates() {
    let mut h = History::default();
    // The previous values the annotation refers to.
    h.bounds.top = 0xE7;
    h.bounds.bottom = 0xF3;
    h.lineto.x0 = 0x33A;
    h.lineto.y0 = 0x15E;
    h.lineto.x1 = 0x33D;
    h.lineto.y1 = 0x15B;
    let hd = read(
        &mut h,
        &hex("1d 09 1e 02 a5 3d 03 1a 4a 03 1b 03 b1 0e a6 5b ef 00"),
    );
    let b = hd.bounds.unwrap();
    assert_eq!((b.left, b.top, b.right, b.bottom), (829, 257, 842, 270));
    let o = &h.lineto;
    assert_eq!((o.x0, o.y0, o.x1, o.y1), (829, 271, 843, 257));
    assert_eq!(o.pen, 0x00EF5B);
}

#[test]
fn spec_glyph_index_examples() {
    let mut h = History::default();
    read(
        &mut h,
        &hex(
            "19 1b 00 01 20 6a 02 27 38 00 39 07 3a 06 3b 07 3c 06 3d 06 18 04 1f 06 17 02 14 04 1b \
             06 19 06 45 05 18 06 1f 06 1f 02 14 02 46 06 ff 15 24",
        ),
    );
    assert_eq!(h.glyph_index.bk.right, 618);
    assert_eq!(h.glyph_index.data.len(), 39);
    assert_eq!(&h.glyph_index.data[36..], &[0xFF, 0x15, 0x24]);

    read(
        &mut h,
        &hex(
            "19 1b e8 3f 38 00 ff ff ff 0c 02 6e 01 4d 02 7b 01 09 02 6e 01 f6 02 7b 01 0c 02 79 01 03 fe 04 00",
        ),
    );
    let o = &h.glyph_index;
    assert_eq!(o.op_redundant, 0);
    assert_eq!(o.fore, 0xFFFFFF);
    assert_eq!(
        (o.bk.left, o.bk.top, o.bk.right, o.bk.bottom),
        (524, 366, 589, 379)
    );
    assert_eq!(
        (o.op.left, o.op.top, o.op.right, o.op.bottom),
        (521, 366, 758, 379)
    );
    assert_eq!((o.x, o.y), (524, 377));
    assert_eq!(o.data, vec![0xFE, 0x04, 0x00]);
}

#[test]
fn spec_glyph_index_add_fragment_stores_the_preceding_bytes() {
    let mut o = Orders::new(None);
    let data = hex(
        "38 00 39 07 3a 06 3b 07 3c 06 3d 06 18 04 1f 06 17 02 14 04 1b 06 19 06 45 05 18 06 1f 06 1f 02 \
         14 02 46 06 ff 15 24",
    );
    let run = TextRun {
        cache_id: 7,
        fl_accel: 0x03,
        char_inc: 0,
        x: 10,
        y: 20,
    };
    let placed = o.layout_glyphs(&run, &data).unwrap();
    assert_eq!(placed.len(), 18);
    assert_eq!(placed[0], (0x38, 10, 20));
    assert_eq!(placed[1], (0x39, 17, 20));
    assert_eq!(o.caches.fragments[0x15].as_deref(), Some(&data[..36]));
    // USE with a delta replays the fragment from the moved pen.
    let again = o.layout_glyphs(&run, &[0xFE, 0x15, 0x05]).unwrap();
    assert_eq!(again.len(), 18);
    assert_eq!(again[0], (0x38, 15, 20));
    assert_eq!(again[1], (0x39, 22, 20));
}

#[test]
fn spec_fast_index_examples() {
    let mut h = History::default();
    read(
        &mut h,
        &hex(
            "09 13 ff 70 07 00 03 ff ff 00 74 3b 00 0e 00 71 00 42 00 7e 00 00 80 7c 00 15 00 00 01 \
             06 02 04 03 08 05 09 06 06 06 06 07 06 08 02 ff 00 12",
        ),
    );
    let o = &h.fast_index;
    assert_eq!((o.cache_id, o.ul_char_inc, o.fl_accel), (7, 0, 3));
    assert_eq!((o.back, o.fore), (0x00FFFF, 0x003B74));
    assert_eq!(
        (o.bk.left, o.bk.top, o.bk.right, o.bk.bottom),
        (14, 113, 66, 126)
    );
    assert_eq!((o.x, o.y), (-32768, 124));
    assert_eq!(o.data.len(), 21);

    // Example 2 uses delta coordinates from the previous values.
    h.fast_index.bk.top = 0x159;
    h.fast_index.bk.right = 0x161;
    h.fast_index.bk.bottom = 0x166;
    h.fast_index.y = 0x164;
    read(&mut h, &hex("19 13 e0 60 e2 d5 e2 e2 03 fe 1c 00"));
    let o = &h.fast_index;
    assert_eq!(
        (o.bk.top, o.bk.right, o.bk.bottom, o.y),
        (315, 310, 328, 326)
    );
    assert_eq!(o.data, vec![0xFE, 0x1C, 0x00]);
}

const FAST_GLYPH: &str = "0d 18 fb 7e 0f 8b 00 b1 00 2c 04 bd 00 06 00 03 ff ff 00 8b 00 b1 00 93 00 be 00 \
                          0d 00 fe 7f 00 80 00 80 bb 00 13 00 01 4a 06 0a 80 80 80 b8 c4 84 84 84 84 84 00 00 68 00";

#[test]
fn spec_fast_glyph_parses_and_draws() {
    let mut h = History::default();
    let hd = read(&mut h, &hex(FAST_GLYPH));
    let b = hd.bounds.unwrap();
    assert_eq!((b.left, b.top, b.right, b.bottom), (139, 177, 1068, 189));
    let o = &h.fast_glyph;
    assert_eq!((o.cache_id, o.fl_accel, o.fore), (6, 3, 0x00FFFF));
    assert_eq!(
        (o.bk.left, o.bk.top, o.bk.right, o.bk.bottom),
        (139, 177, 147, 190)
    );
    assert_eq!((o.op.top, o.op.right, o.op.bottom), (13, 32766, -32768));
    assert_eq!((o.x, o.y), (-32768, 187));

    // Drawn: the "h" glyph at (BkLeft + 1, 187 - 10) in BackColor (black,
    // never sent), over an opaque rectangle in ForeColor that runs to the
    // right edge, all inside the bounds.
    let mut fb = Framebuffer::new(160, 200);
    fb.pixels.fill(0x123456);
    let mut orders = Orders::new(None);
    let mut damage = Vec::new();
    orders.process(1, &hex(FAST_GLYPH), &mut fb, &mut damage);
    let px = |x: usize, y: usize| fb.pixels[y * 160 + x];
    assert_eq!(px(140, 177), 0, "glyph pixel");
    assert_eq!(px(141, 177), 0xFFFF00, "opaque rectangle");
    assert_eq!(px(140, 180), 0);
    assert_eq!(px(141, 180), 0xFFFF00);
    assert_eq!(px(142, 180), 0);
    assert_eq!(px(159, 189), 0xFFFF00, "opaque runs to the right edge");
    assert_eq!(px(150, 190), 0x123456, "bounds bottom is inclusive 189");
    assert_eq!(px(138, 180), 0x123456);
    assert!(!damage.is_empty());
    // The glyph went to the cache.
    assert_eq!(orders.caches.glyph(6, 0).unwrap().cx, 6);
}

#[test]
fn spec_polygon_cb() {
    let mut h = History::default();
    read(
        &mut h,
        &hex("09 15 ef 1b ea 00 46 01 0d 01 08 00 00 04 03 81 08 03 05 88 09 26 09 77"),
    );
    let o = &h.polygon_cb;
    assert_eq!((o.x, o.y, o.rop2, o.fill_mode), (234, 326, 0x0D, 1));
    assert_eq!((o.brush.style, o.brush.hatch), (0x81, 8));
    let pts = fields::delta_points(&o.deltas, o.n as usize, o.x, o.y).unwrap();
    assert_eq!(pts, vec![(234, 335), (272, 344), (272, 335)]);
}

#[test]
fn spec_polyline() {
    let mut h = History::default();
    let hd = read(
        &mut h,
        &hex(
            "2d 16 73 f8 01 b8 02 00 c0 00 20 6c 00 00 00 00 00 04 00 00 ff 7e 76 ff 41 6c ff 24 62 ff \
             2b 59 ff 55 51 ff 9c 49 73 43 80 4d ff be 80 99 ff ba 80 cd ff b7 80 de ff b6 80 ca ff b6 \
             80 96 ff b7 80 48 ff ba 6f ff be ff 97 43 ff 52 4a ff 2b 51 ff 24 59 ff 44 63 ff 81 6c 56 \
             76 2f 80 82 0a 80 bf 14 80 dd 1e 80 d4 27 80 ab 2f 80 64 37 0d 3d ff b3 80 42 ff 67 80 46",
        ),
    );
    assert!(
        hd.bounds.is_some(),
        "TS_ZERO_BOUNDS_DELTAS keeps the last bounds"
    );
    let o = &h.polyline;
    assert_eq!((o.x, o.y, o.pen, o.n), (504, 696, 0x00C000, 32));
    let pts = fields::delta_points(&o.deltas, o.n as usize, o.x, o.y).unwrap();
    assert_eq!(pts.len(), 32);
    assert_eq!(pts[0], (374, 686));
    assert_eq!(pts[6], (-534, 434));
    assert_eq!(pts[22], (-492, -392));
    assert_eq!(pts[31], (316, 6));
}

#[test]
fn spec_ellipse_sc_and_cb() {
    let mut h = History::default();
    h.bounds.top = 0x14C;
    let hd = read(
        &mut h,
        &hex("0d 19 7f 29 ca 00 fb 3c 02 ca 00 47 01 eb 03 3c 02 0d 02 c0 21 00"),
    );
    let b = hd.bounds.unwrap();
    assert_eq!((b.left, b.top, b.bottom), (202, 327, 572));
    let o = &h.ellipse_sc;
    assert_eq!((o.left, o.top, o.right, o.bottom), (202, 327, 1003, 572));
    assert_eq!((o.rop2, o.fill_mode, o.color), (0x0D, 2, 0x0021C0));

    let mut h = History {
        bounds: primary::Bounds {
            left: 0x2E,
            top: 0x89,
            right: 0,
            bottom: 0xAD,
        },
        ..History::default()
    };
    let hd = read(
        &mut h,
        &hex("0d 1a ff 0c b0 03 b9 c9 09 00 8e fe 10 01 5e 02 0d 01 ff ff 00 60 30 00 02 05"),
    );
    let b = hd.bounds.unwrap();
    assert_eq!((b.left, b.top, b.bottom), (49, 66, 118));
    let o = &h.ellipse_cb;
    assert_eq!((o.left, o.top, o.right, o.bottom), (9, -370, 272, 606));
    assert_eq!((o.fill_mode, o.back, o.fore), (1, 0x00FFFF, 0x003060));
    assert_eq!((o.brush.style, o.brush.hatch), (2, 5));
}

// ---- MS-RDPEGDI 4.2 / 4.3: secondary and alternate secondary orders ----

#[test]
fn spec_cache_bitmap_v1() {
    let bytes = hex("03 03 00 00 04 02 00 00 10 01 08 01 00 00 00 10");
    let Secondary::Bitmap(b) = secondary::parse(&bytes).unwrap() else {
        panic!("not a bitmap")
    };
    assert_eq!(
        (b.cache_id, b.index, b.width, b.height, b.bpp),
        (0, 0, 16, 1, 8)
    );
    assert_eq!(b.codec, BitmapCodec::Compressed);
    assert_eq!(b.data, &[0x10]);
}

#[test]
fn spec_cache_bitmap_v2_decodes_to_the_annotated_pixels() {
    let order = include_bytes!("testdata/cache_bitmap_rev2.bin");
    let raw = include_bytes!("testdata/cache_bitmap_rev2_raw.bin");
    let Secondary::Bitmap(b) = secondary::parse(order).unwrap() else {
        panic!("not a bitmap")
    };
    assert_eq!((b.cache_id, b.bpp, b.width, b.height), (1, 16, 32, 32));
    assert_eq!(b.index, secondary::WAITING_LIST_INDEX);
    assert_eq!(
        (b.key, b.codec, b.data.len()),
        (None, BitmapCodec::Compressed, 220)
    );

    let mut o = Orders::new(None);
    o.set_bpp(16);
    o.secondary(order).unwrap();
    let got = o.caches.bitmap(1, secondary::WAITING_LIST_INDEX).unwrap();
    let raw16: Vec<u32> = raw
        .chunks(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]) as u32)
        .collect();
    assert_eq!(got.px, codec::to_rgb_top_down(&raw16, 32, 32, 16));
}

#[test]
fn spec_cache_glyph_v1_and_v2() {
    let v1 = hex(
        "03 37 00 10 00 03 07 03 31 00 00 00 f8 ff 05 00 08 00 c0 c0 c0 c0 c0 c0 c0 f8 32 00 00 00 fa ff \
         06 00 08 00 7c cc cc cc cc 7c 0c 78 33 00 00 00 f8 ff 07 00 08 00 7c c6 c6 c6 c6 c6 c6 7c 4c 00 \
         67 00 4f 00",
    );
    let Secondary::Glyphs { cache_id, glyphs } = secondary::parse(&v1).unwrap() else {
        panic!("not glyphs")
    };
    assert_eq!(cache_id, 7);
    assert_eq!(glyphs.len(), 3);
    assert_eq!(glyphs[0].0, 49);
    assert_eq!(
        (glyphs[0].1.x, glyphs[0].1.y, glyphs[0].1.cx, glyphs[0].1.cy),
        (0, -8, 5, 8)
    );
    assert_eq!(glyphs[1].1.bits, hex("7c cc cc cc cc 7c 0c 78"));
    assert_eq!((glyphs[2].0, glyphs[2].1.cx), (51, 7));

    let v2 = hex("03 04 00 37 01 03 34 00 49 03 03 a0 a0 a0 00 22 00");
    let Secondary::Glyphs { cache_id, glyphs } = secondary::parse(&v2).unwrap() else {
        panic!("not glyphs")
    };
    assert_eq!(cache_id, 7);
    assert_eq!(glyphs.len(), 1);
    let (i, g) = &glyphs[0];
    assert_eq!((*i, g.x, g.y, g.cx, g.cy), (52, 0, -9, 3, 3));
    assert_eq!(g.bits, vec![0xA0, 0xA0, 0xA0]);
}

#[test]
fn spec_cache_brush_rows_are_bottom_up() {
    let bytes = hex("03 07 00 00 00 07 00 01 08 08 81 08 aa 55 aa 55 aa 55 aa 55");
    let Secondary::Brush(b) = secondary::parse(&bytes).unwrap() else {
        panic!("not a brush")
    };
    assert_eq!((b.index, b.format), (0, secondary::BMF_1BPP));
    // The last byte (0x55) is the top row.
    assert_eq!(&b.px[..8], &[0, 1, 0, 1, 0, 1, 0, 1]);
    assert_eq!(&b.px[56..], &[1, 0, 1, 0, 1, 0, 1, 0]);
}

#[test]
fn spec_cache_bitmap_v3() {
    let mut bytes =
        hex("03 37 00 30 0c 08 ff 7f 35 50 ec bc 74 52 65 b7 20 00 00 00 05 00 02 00 28 00 00 00");
    for _ in 0..5 {
        bytes.extend(hex("5b 4f 45 ff"));
    }
    for _ in 0..5 {
        bytes.extend(hex("5b 50 45 ff"));
    }
    let Secondary::Bitmap(b) = secondary::parse(&bytes).unwrap() else {
        panic!("not a bitmap")
    };
    assert_eq!((b.cache_id, b.bpp, b.width, b.height), (0, 32, 5, 2));
    assert_eq!(b.key, Some(0xB765_5274_BCEC_5035));
    assert_eq!(b.index, secondary::WAITING_LIST_INDEX);
    assert_eq!(b.codec, BitmapCodec::Ex(0));
    let mut o = Orders::new(None);
    o.secondary(&bytes).unwrap();
    let got = o.caches.bitmap(0, secondary::WAITING_LIST_INDEX).unwrap();
    // Bottom-up: the first row on the wire is the bottom one.
    assert_eq!(got.px[..5], [0x45505B; 5]);
    assert_eq!(got.px[5..], [0x454F5B; 5]);
}

#[test]
fn spec_create_offscreen_and_switch_surface() {
    let mut o = Orders::new(None);
    let mut fb = Framebuffer::new(8, 8);
    let mut damage = Vec::new();
    o.offscreen[2] = Some(Bitmap {
        w: 1,
        h: 1,
        px: vec![0],
    });
    let mut data = hex("06 00 80 60 01 10 00 01 00 02 00");
    data.extend(hex("02 00 00")); // switch to offscreen 0
    o.process(2, &data, &mut fb, &mut damage);
    let b = o.offscreen[0].as_ref().unwrap();
    assert_eq!((b.w, b.h), (352, 16));
    assert!(o.offscreen[2].is_none(), "the delete list removed entry 2");
    assert_eq!(o.target, Some(0));
    o.process(1, &hex("02 ff ff"), &mut fb, &mut damage);
    assert_eq!(o.target, None);
}

// ---- field encodings ----

#[test]
fn two_and_four_byte_encodings() {
    let rd = |b: &[u8], f: fn(&mut Reader) -> crate::Result<u32>| f(&mut Reader::new(b)).unwrap();
    assert_eq!(
        rd(&[0x9A, 0x1B], |r| fields::two_byte_unsigned(r)
            .map(u32::from)),
        0x1A1B
    );
    assert_eq!(
        rd(&[0x9A, 0x1B, 0x1C], fields::four_byte_unsigned),
        0x1A_1B1C
    );
    assert_eq!(rd(&[0x05], fields::four_byte_unsigned), 5);
    let s = |b: &[u8]| fields::two_byte_signed(&mut Reader::new(b)).unwrap();
    assert_eq!(s(&[0xDA, 0x1B]), -0x1A1B);
    assert_eq!(s(&[0x42]), -2);
    assert_eq!(s(&[0x05]), 5);
}

#[test]
fn delta_rects_reject_more_than_45() {
    assert!(fields::delta_rects(&[0; 200], 46).is_err());
    assert!(fields::delta_rects(&[], 1).is_err(), "truncated");
}

// ---- raster operations ----

#[test]
fn rop3_fast_paths_match_the_truth_table() {
    let (p, s, d) = (0x00F0_F0F0u32, 0x00CC_CCCC, 0x00AA_AAAA);
    for rop in 0..=255u8 {
        // With the classic operand patterns the result is the rop byte.
        let v = draw::rop3(rop, p, s, d);
        assert_eq!(v & 0xFF, rop as u32, "rop {rop:#04x}");
        let (p2, s2, d2) = (0x0012_3456, 0x0065_4321, 0x00A5_5A0F);
        let generic = {
            let mut out = 0u32;
            for i in 0..8 {
                if rop >> i & 1 != 0 {
                    let pm = if i & 4 != 0 { p2 } else { !p2 };
                    let sm = if i & 2 != 0 { s2 } else { !s2 };
                    let dm = if i & 1 != 0 { d2 } else { !d2 };
                    out |= pm & sm & dm;
                }
            }
            out & 0x00FF_FFFF
        };
        assert_eq!(draw::rop3(rop, p2, s2, d2), generic, "rop {rop:#04x}");
    }
}

#[test]
fn rop2_maps_to_rop3() {
    assert_eq!(draw::rop2_to_rop3(1), 0x00); // R2_BLACK
    assert_eq!(draw::rop2_to_rop3(6), 0x55); // R2_NOT
    assert_eq!(draw::rop2_to_rop3(7), 0x5A); // R2_XORPEN
    assert_eq!(draw::rop2_to_rop3(11), 0xAA); // R2_NOP
    assert_eq!(draw::rop2_to_rop3(13), 0xF0); // R2_COPYPEN
    assert_eq!(draw::rop2_to_rop3(16), 0xFF); // R2_WHITE
    assert!(draw::rop_uses_source(0xCC));
    assert!(!draw::rop_uses_source(0xF0));
}

// ---- rendering of every primary order ----

/// A primary order with TS_STANDARD | TS_TYPE_CHANGE.
fn prim(ty: u8, field_bytes: usize, flags: u32, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x09, ty];
    for i in 0..field_bytes {
        v.push((flags >> (8 * i)) as u8);
    }
    v.extend_from_slice(body);
    v
}

/// The same, with absolute bounds.
fn prim_bounded(ty: u8, field_bytes: usize, flags: u32, b: [i16; 4], body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x0D, ty];
    for i in 0..field_bytes {
        v.push((flags >> (8 * i)) as u8);
    }
    v.push(0x0F);
    for c in b {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v.extend_from_slice(body);
    v
}

/// A secondary order with the given type, extraFlags and body.
fn sec(ty: u8, extra: u16, body: &[u8]) -> Vec<u8> {
    let total = 6 + body.len();
    let mut v = vec![0x03];
    v.extend_from_slice(&((total as i32 - 13) as i16).to_le_bytes());
    v.extend_from_slice(&extra.to_le_bytes());
    v.push(ty);
    v.extend_from_slice(body);
    v
}

fn coords(v: &[i16]) -> Vec<u8> {
    v.iter().flat_map(|c| c.to_le_bytes()).collect()
}

struct Canvas {
    fb: Framebuffer,
    o: Orders,
    damage: Vec<Damage>,
}

impl Canvas {
    fn new(w: usize, h: usize, fill: u32) -> Self {
        let mut fb = Framebuffer::new(w, h);
        fb.pixels.fill(fill);
        Self {
            fb,
            o: Orders::new(None),
            damage: Vec::new(),
        }
    }

    fn run(&mut self, orders: &[Vec<u8>]) {
        let data: Vec<u8> = orders.concat();
        self.o
            .process(orders.len() as u16, &data, &mut self.fb, &mut self.damage);
    }

    fn px(&self, x: usize, y: usize) -> u32 {
        self.fb.pixels[y * self.fb.width + x]
    }

    /// Pixels equal to `c` inside the framebuffer.
    fn count(&self, c: u32) -> usize {
        self.fb.pixels.iter().filter(|&&p| p == c).count()
    }
}

#[test]
fn draws_opaque_rect_with_damage() {
    let mut c = Canvas::new(16, 16, 0);
    c.run(&[prim(
        0x0A,
        1,
        0x7F,
        &[&coords(&[2, 3, 4, 5])[..], &[0x11, 0x22, 0x33]].concat(),
    )]);
    assert_eq!(c.px(2, 3), 0x112233);
    assert_eq!(c.px(5, 7), 0x112233);
    assert_eq!(c.px(6, 7), 0);
    assert_eq!(c.px(5, 8), 0);
    assert_eq!(c.count(0x112233), 20);
    assert_eq!(
        c.damage,
        vec![Damage {
            x: 2,
            y: 3,
            w: 4,
            h: 5
        }]
    );
}

#[test]
fn bounds_clip_the_order() {
    let mut c = Canvas::new(16, 16, 0);
    let body = [&coords(&[0, 0, 16, 16])[..], &[0xFF, 0, 0]].concat();
    c.run(&[prim_bounded(0x0A, 1, 0x7F, [4, 5, 6, 7], &body)]);
    assert_eq!(c.count(0xFF0000), 9, "inclusive 3 x 3 bounds");
    assert_eq!(c.px(4, 5), 0xFF0000);
    assert_eq!(c.px(7, 5), 0);
}

#[test]
fn draws_dstblt() {
    let mut c = Canvas::new(8, 8, 0x00F0_0F0F);
    c.run(&[prim(
        0x00,
        1,
        0x1F,
        &[&coords(&[1, 1, 2, 2])[..], &[0x55]].concat(),
    )]);
    assert_eq!(c.px(1, 1), 0x000F_F0F0, "DSTINVERT");
    assert_eq!(c.px(3, 3), 0x00F0_0F0F);
    c.run(&[prim(0x00, 1, 0x10, &[0x00])]); // BLACKNESS, same rectangle
    assert_eq!(c.px(2, 2), 0);
    assert_eq!(c.count(0), 4);
}

#[test]
fn draws_patblt_solid_hatched_and_pattern() {
    let mut c = Canvas::new(8, 8, 0);
    // Solid brush, PATCOPY: ForeColor.
    let solid = [
        &coords(&[0, 0, 8, 8])[..],
        &[0xF0],
        &[1, 2, 3],
        &[4, 5, 6],
        &[0, 0, 0, 0],
    ]
    .concat();
    c.run(&[prim(0x01, 2, 0x3FF, &solid)]);
    assert_eq!(c.count(0x040506), 64);
    // Horizontal hatch: the bottom row of each 8x8 cell in ForeColor.
    let hatch = [&[0xF0][..], &[0xAA, 0, 0], &[0, 0, 0xBB], &[2, 0]].concat();
    c.run(&[prim(0x01, 2, 0x0670, &hatch)]);
    assert_eq!(c.px(3, 7), 0xBB);
    assert_eq!(c.px(3, 6), 0xAA0000);
    assert_eq!(c.count(0xBB), 8);
    // BS_PATTERN: BrushHatch is the bottom row, BrushExtra the rows above.
    let pattern = [&[3u8, 0x80][..], &[0x01, 0, 0, 0, 0, 0, 0xFF]].concat();
    c.run(&[prim(0x01, 2, 0x0E00, &pattern)]);
    // Set bits take BackColor, clear bits ForeColor.
    assert_eq!(c.px(0, 7), 0xAA0000);
    assert_eq!(c.px(1, 7), 0xBB);
    assert_eq!(c.px(7, 6), 0xAA0000);
    assert_eq!(c.px(0, 6), 0xBB);
    assert_eq!(c.count(0xAA0000), 1 + 1 + 8);
    // PATINVERT with a solid brush XORs.
    let inv = [&[0x5A][..], &[0xFF, 0xFF, 0xFF], &[0]].concat();
    c.run(&[prim(0x01, 2, 0x0250, &inv)]);
    assert_eq!(c.px(1, 7), 0xFFFF44);
}

#[test]
fn draws_scrblt_with_overlap() {
    let mut c = Canvas::new(8, 1, 0);
    c.fb.pixels = (0..8).collect();
    // Copy x 0..6 to x 2..8: overlapping, must read the old pixels.
    c.run(&[prim(
        0x02,
        1,
        0x7F,
        &[&coords(&[2, 0, 6, 1])[..], &[0xCC], &coords(&[0, 0])].concat(),
    )]);
    assert_eq!(c.fb.pixels, vec![0, 1, 0, 1, 2, 3, 4, 5]);
}

#[test]
fn draws_multi_orders() {
    // Two rectangles: (1,1,2,2) and (5,1,2,2).
    // zeroBits 0x07: the second rectangle keeps top, width and height.
    let deltas = |n: u8| vec![n, 6, 0, 0x07, 1, 1, 2, 2, 4];
    let mut c = Canvas::new(8, 4, 0);
    let body = [&coords(&[0, 0, 8, 4])[..], &[9, 9, 9], &deltas(2)].concat();
    c.run(&[prim(0x12, 2, 0x1FF, &body)]);
    assert_eq!(c.count(0x090909), 8);
    assert_eq!(c.px(5, 2), 0x090909);
    assert_eq!(c.px(4, 2), 0);

    // MultiDstBlt WHITENESS over the same rectangles.
    let mut c = Canvas::new(8, 4, 0);
    let body = [&coords(&[0, 0, 8, 4])[..], &[0xFF], &deltas(2)].concat();
    c.run(&[prim(0x0F, 1, 0x7F, &body)]);
    assert_eq!(c.count(0xFFFFFF), 8);

    // MultiPatBlt with a solid brush.
    let mut c = Canvas::new(8, 4, 0);
    let body = [
        &coords(&[0, 0, 8, 4])[..],
        &[0xF0],
        &[0, 0, 0],
        &[7, 7, 7],
        &[0, 0, 0, 0],
        &deltas(2),
    ]
    .concat();
    c.run(&[prim(0x10, 2, 0x37FF, &body)]);
    assert_eq!(c.count(0x070707), 8);

    // MultiScrBlt: each rectangle copies from its offset in the source.
    let mut c = Canvas::new(8, 4, 0);
    c.fb.pixels[0] = 0xABCDEF; // (0, 0)
    let body = [
        &coords(&[1, 1, 6, 2])[..],
        &[0xCC],
        &coords(&[0, 0]),
        &deltas(2),
    ]
    .concat();
    c.run(&[prim(0x11, 2, 0x1FF, &body)]);
    assert_eq!(
        c.px(1, 1),
        0xABCDEF,
        "first rectangle starts at the source origin"
    );
    assert_eq!(c.px(5, 1), 0, "second reads (4, 0)");
}

/// Cache Bitmap Rev. 2, uncompressed 32 bpp, `w` x `h` top-down pixels.
fn cache_bitmap_v2(cache: u8, index: u8, w: u8, h: u8, px: &[u32], key: Option<u64>) -> Vec<u8> {
    let mut data = Vec::new();
    for row in (0..h as usize).rev() {
        for x in 0..w as usize {
            data.extend_from_slice(&px[row * w as usize + x].to_le_bytes());
        }
    }
    let flags: u16 = if key.is_some() { 0x02 } else { 0 };
    let extra = cache as u16 | 6 << 3 | flags << 7;
    let mut body = Vec::new();
    if let Some(k) = key {
        body.extend_from_slice(&(k as u32).to_le_bytes());
        body.extend_from_slice(&((k >> 32) as u32).to_le_bytes());
    }
    assert!(data.len() < 0x40 && index < 0x80);
    body.extend([w, h, data.len() as u8, index]);
    body.extend(data);
    sec(secondary::TS_CACHE_BITMAP_UNCOMPRESSED_REV2, extra, &body)
}

fn memblt(cache: u8, index: u16, rect: [i16; 4], src: [i16; 2], rop: u8) -> Vec<u8> {
    let body = [
        &(cache as u16).to_le_bytes()[..],
        &coords(&rect),
        &[rop],
        &coords(&src),
        &index.to_le_bytes(),
    ]
    .concat();
    prim(0x0D, 2, 0x1FF, &body)
}

#[test]
fn draws_memblt_from_the_bitmap_cache() {
    let mut c = Canvas::new(8, 8, 0x00FF_FFFF);
    let px = [0x110000, 0x220000, 0x330000, 0x440000];
    c.run(&[cache_bitmap_v2(0, 3, 2, 2, &px, None)]);
    c.run(&[memblt(0, 3, [5, 6, 2, 2], [0, 0], 0xCC)]);
    assert_eq!(
        (c.px(5, 6), c.px(6, 6), c.px(5, 7), c.px(6, 7)),
        (0x110000, 0x220000, 0x330000, 0x440000)
    );
    // Source offset and SRCAND.
    c.run(&[memblt(0, 3, [0, 0, 1, 1], [1, 1], 0x88)]);
    assert_eq!(c.px(0, 0), 0x440000);
    // A missing entry skips the order but not the batch.
    let before = c.fb.pixels.clone();
    c.run(&[
        memblt(0, 9, [0, 0, 2, 2], [0, 0], 0xCC),
        memblt(0, 3, [2, 2, 1, 1], [0, 0], 0xCC),
    ]);
    assert_eq!(c.px(0, 1), before[8]);
    assert_eq!(c.px(2, 2), 0x110000);
}

#[test]
fn draws_mem3blt_with_a_brush() {
    let mut c = Canvas::new(4, 4, 0x0000_00FF);
    let px = [0xFFFFFF, 0, 0, 0xFFFFFF];
    c.run(&[cache_bitmap_v2(1, 0, 2, 2, &px, None)]);
    // 0xB8 (PSDPxax): the destination where the source is set, else ForeColor.
    let body = [
        &1u16.to_le_bytes()[..],
        &coords(&[0, 0, 2, 2]),
        &[0xB8],
        &coords(&[0, 0]),
        &[0, 0, 0],
        &[0x00, 0xFF, 0x00],
        &[0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 0, 0],
        &0u16.to_le_bytes(),
    ]
    .concat();
    c.run(&[prim(0x0E, 3, 0xFFFF, &body)]);
    assert_eq!(c.px(0, 0), 0x0000FF);
    assert_eq!(c.px(1, 0), 0x00FF00);
    assert_eq!(c.px(1, 1), 0x0000FF);
}

#[test]
fn offscreen_bitmaps_draw_without_damage_and_blit_back() {
    let mut c = Canvas::new(8, 8, 0);
    let create = hex("06 03 00 04 00 04 00"); // offscreen 3, 4 x 4
    let switch_to = hex("02 03 00");
    let fill = prim(
        0x0A,
        1,
        0x7F,
        &[&coords(&[0, 0, 4, 4])[..], &[0x12, 0x34, 0x56]].concat(),
    );
    c.run(&[create, switch_to, fill]);
    assert_eq!(c.count(0), 64, "nothing on screen");
    assert!(c.damage.is_empty());
    c.run(&[hex("02 ff ff"), memblt(0xFF, 3, [2, 2, 2, 2], [1, 1], 0xCC)]);
    assert_eq!(c.px(2, 2), 0x123456);
    assert_eq!(c.count(0x123456), 4);
    assert_eq!(
        c.damage,
        vec![Damage {
            x: 2,
            y: 2,
            w: 2,
            h: 2
        }]
    );
    // Drawing to a surface that was never created is skipped.
    c.run(&[
        hex("02 07 00"),
        prim(
            0x0A,
            1,
            0x7F,
            &[&coords(&[0, 0, 8, 8])[..], &[1, 1, 1]].concat(),
        ),
    ]);
    assert_eq!(c.count(0x010101), 0);
}

#[test]
fn draws_lineto_and_polyline() {
    let mut c = Canvas::new(8, 8, 0);
    // R2_COPYPEN from (1, 2) to (5, 2); the end point is not drawn.
    let body = [&coords(&[1, 2, 5, 2])[..], &[13], &[0xFF, 0, 0]].concat();
    c.run(&[prim(0x09, 2, 0x025E, &body)]);
    assert_eq!(c.count(0xFF0000), 4);
    assert_eq!(c.px(1, 2), 0xFF0000);
    assert_eq!(c.px(5, 2), 0);
    // Polyline (0,0) -> (3,0) -> (3,3): R2_COPYPEN, green.
    let deltas = [0x40u8, 0x03, 0x03]; // point 1: dx 3, dy 0 (zero); point 2: dx 0 (zero), dy 3
    let deltas = [&[0x60u8][..], &deltas[1..]].concat();
    let body = [
        &coords(&[0, 0])[..],
        &[13],
        &[0, 0],
        &[0, 0xFF, 0],
        &[2],
        &[deltas.len() as u8],
        &deltas,
    ]
    .concat();
    c.run(&[prim(0x16, 1, 0x7F, &body)]);
    assert_eq!(c.px(0, 0), 0x00FF00);
    assert_eq!(c.px(2, 0), 0x00FF00);
    assert_eq!(c.px(3, 0), 0x00FF00);
    assert_eq!(c.px(3, 2), 0x00FF00);
    assert_eq!(c.px(3, 3), 0, "the last point is excluded");
}

#[test]
fn draws_polygons() {
    let mut c = Canvas::new(10, 10, 0);
    // Square (2,2) (6,2) (6,6) (2,6).
    let deltas = [
        0x64u8, /* p1 dy=0, p2 dx=0, p3 dy=0 */
        0x04, 0x04, 0x7C,
    ];
    let body = [
        &coords(&[2, 2])[..],
        &[13, 1],
        &[0xFF, 0xFF, 0],
        &[3],
        &[deltas.len() as u8],
        &deltas,
    ]
    .concat();
    c.run(&[prim(0x14, 1, 0x7F, &body)]);
    assert_eq!(c.count(0xFFFF00), 16);
    assert_eq!(c.px(2, 2), 0xFFFF00);
    assert_eq!(c.px(5, 5), 0xFFFF00);
    assert_eq!(c.px(6, 6), 0);

    // PolygonCB with a vertical hatch brush, opaque background.
    let mut c = Canvas::new(10, 10, 0);
    let body = [
        &coords(&[0, 0])[..],
        &[13, 1],
        &[0, 0, 0xFF],
        &[0xFF, 0, 0],
        &[0, 0, 2, 1],
        &[3],
        &[4u8, 0x64, 0x08, 0x08, 0x78],
    ]
    .concat();
    c.run(&[prim(0x15, 2, 0x1BFF, &body)]);
    // HS_VERTICAL: column 4 of each cell is ForeColor.
    assert_eq!(c.px(4, 3), 0xFF0000);
    assert_eq!(c.px(3, 3), 0x0000FF);
    assert_eq!(c.count(0xFF0000), 8);
    assert_eq!(c.count(0x0000FF), 56);
}

#[test]
fn draws_ellipses() {
    let mut c = Canvas::new(12, 12, 0);
    let body = [&coords(&[1, 1, 9, 9])[..], &[13, 1], &[0, 0x80, 0]].concat();
    c.run(&[prim(0x19, 1, 0x7F, &body)]);
    let filled = c.count(0x008000);
    // A 9 x 9 disc covers about pi * 4.5^2 = 64 pixels.
    assert!((55..=75).contains(&filled), "{filled}");
    assert_eq!(c.px(5, 5), 0x008000);
    assert_eq!(c.px(1, 1), 0, "corner outside");
    assert_eq!(c.px(5, 1), 0x008000, "top centre");
    assert_eq!(c.px(10, 5), 0);

    // Outline only (FillMode 0): the centre stays.
    let mut c = Canvas::new(12, 12, 0);
    let body = [&coords(&[1, 1, 9, 9])[..], &[13, 0], &[0, 0x80, 0]].concat();
    c.run(&[prim(0x19, 1, 0x7F, &body)]);
    assert_eq!(c.px(5, 5), 0);
    assert_eq!(c.px(1, 5), 0x008000);
    assert!(c.count(0x008000) < filled);

    // EllipseCB with a solid brush.
    let mut c = Canvas::new(12, 12, 0);
    let body = [
        &coords(&[1, 1, 9, 9])[..],
        &[13, 1],
        &[0, 0, 0],
        &[0, 0, 0x40],
        &[0, 0, 0, 0],
    ]
    .concat();
    c.run(&[prim(0x1A, 2, 0x0FFF, &body)]);
    assert_eq!(c.count(0x000040), filled);
}

/// Cache Glyph Rev. 2 with one 2 x 2 glyph, all pixels set.
fn cache_glyph(cache: u8, index: u8) -> Vec<u8> {
    let extra = cache as u16 | 0x20 | 1 << 8;
    sec(
        secondary::TS_CACHE_GLYPH,
        extra,
        &[index, 0, 0, 2, 2, 0xC0, 0xC0, 0, 0],
    )
}

#[test]
fn draws_glyph_index_with_fragments() {
    let mut c = Canvas::new(16, 16, 0);
    // Fields 1-10, 20-22: cache 0, flAccel 3, no char inc, opaque rect absent.
    let body = [
        &[0u8, 0x03, 0, 0][..],
        &[0x11, 0x22, 0x33],
        &[0xAA, 0xBB, 0xCC],
        &coords(&[0, 0, 15, 15]),
        &coords(&[2, 4]),
        &[7, 1, 0, 1, 5, 0xFF, 0x05, 0x04],
    ]
    .concat();
    let flags = 0x3FF | 1 << 19 | 1 << 20 | 1 << 21;
    c.run(&[cache_glyph(0, 1), prim(0x1B, 3, flags, &body)]);
    assert_eq!(c.count(0x112233), 8, "two 2 x 2 glyphs in BackColor");
    assert_eq!(c.px(2, 4), 0x112233);
    assert_eq!(c.px(7, 5), 0x112233);
    assert_eq!(c.px(4, 4), 0);
    // Replay fragment 5 with Y = 10 (fields 21 and 22 only).
    let body = [&coords(&[10])[..], &[3, 0xFE, 0x05, 0x00]].concat();
    c.run(&[prim(0x1B, 3, 1 << 20 | 1 << 21, &body)]);
    assert_eq!(c.px(2, 10), 0x112233);
    assert_eq!(c.px(8, 11), 0x112233);
    assert_eq!(c.count(0x112233), 16);
    // fOpRedundant with an empty opaque rectangle fills the background one.
    let body = [&[1u8][..], &coords(&[0, 0, 3, 3])].concat();
    c.run(&[prim(0x1B, 3, 1 << 3 | 0x3C0, &body)]);
    assert_eq!(c.px(3, 3), 0xAABBCC, "ForeColor, inclusive rectangle");
    assert_eq!(c.px(4, 3), 0);
}

#[test]
fn draws_fast_index() {
    let mut c = Canvas::new(16, 16, 0);
    // cacheId 0, fDrawing (ulCharInc 4, flAccel 3), colours, Bk (0,0)-(16,16),
    // X 1, Y 1, glyphs 1 1 at a fixed pitch of 4.
    let body = [
        &[0u8][..],
        &[4, 3],
        &[0xFF, 0, 0],
        &[0, 0, 0xFF],
        &coords(&[0, 0, 16, 16]),
        &coords(&[1, 1]),
        &[2, 1, 1],
    ]
    .concat();
    c.run(&[cache_glyph(0, 1), prim(0x13, 2, 0x70FF, &body)]);
    // Op rectangle defaults to Bk's left/right; top and bottom stay 0, so
    // no opaque fill.
    assert_eq!(c.count(0xFF0000), 8);
    assert_eq!(c.px(1, 1), 0xFF0000);
    assert_eq!(c.px(5, 2), 0xFF0000);
    assert_eq!(c.px(3, 1), 0);
}

// ---- robustness ----

#[test]
fn truncated_and_random_orders_never_panic() {
    let samples = [
        hex(FAST_GLYPH),
        hex("09 15 ef 1b ea 00 46 01 0d 01 08 00 00 04 03 81 08 03 05 88 09 26 09 77"),
        hex(
            "09 12 bf 01 87 01 1c 01 f1 00 12 00 5c ef 04 16 00 08 40 81 87 81 1c 80 f1 01 01 01 10",
        ),
        hex("06 00 80 60 01 10 00 01 00 02 00"),
        include_bytes!("testdata/cache_bitmap_rev2.bin").to_vec(),
        hex(
            "19 1b e8 3f 38 00 ff ff ff 0c 02 6e 01 4d 02 7b 01 09 02 6e 01 f6 02 7b 01 0c 02 79 01 03 fe 04 00",
        ),
    ];
    for s in &samples {
        for n in 0..=s.len() {
            let mut fb = Framebuffer::new(32, 32);
            let mut o = Orders::new(None);
            o.process(3, &s[..n], &mut fb, &mut Vec::new());
        }
    }
    let mut seed = 0x1234_5678u32;
    let mut next = move || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (seed >> 24) as u8
    };
    let mut fb = Framebuffer::new(64, 64);
    let mut o = Orders::new(None);
    for _ in 0..2000 {
        let len = next() as usize;
        let data: Vec<u8> = (0..len).map(|_| next()).collect();
        o.process(next() as u16, &data, &mut fb, &mut Vec::new());
    }
}

#[test]
fn window_orders_in_a_mixed_batch_reach_the_caller() {
    // OpaqueRect, then a window order deleting window 7, then another OpaqueRect.
    let mut win = vec![0x2E, 0, 0];
    win.extend_from_slice(&(0x0100_0000u32 | 0x2000_0000).to_le_bytes()); // TYPE_WINDOW | DELETED
    win.extend_from_slice(&7u32.to_le_bytes());
    let size = win.len() as u16;
    win[1..3].copy_from_slice(&size.to_le_bytes());
    let mut c = Canvas::new(4, 4, 0);
    let a = prim(
        0x0A,
        1,
        0x7F,
        &[&coords(&[0, 0, 1, 1])[..], &[1, 0, 0]].concat(),
    );
    let b = prim(0x0A, 1, 0x0F, &coords(&[1, 1, 1, 1]));
    let data = [a, win, b].concat();
    let windows = c.o.process(3, &data, &mut c.fb, &mut c.damage);
    assert_eq!(windows, vec![WindowOrder::WindowDeleted { id: 7 }]);
    assert_eq!(c.px(0, 0), 0x010000);
    assert_eq!(c.px(1, 1), 0x010000, "the order after the window order ran");
}

#[test]
fn slow_and_fast_path_framing() {
    let order = prim(
        0x0A,
        1,
        0x7F,
        &[&coords(&[0, 0, 2, 2])[..], &[0, 0, 9]].concat(),
    );
    let mut slow = vec![0, 0, 0, 0, 1, 0, 0, 0];
    slow.extend(&order);
    let mut fast = vec![1, 0];
    fast.extend(&order);
    for (slow_path, data) in [(true, slow), (false, fast)] {
        let mut fb = Framebuffer::new(4, 4);
        let mut o = Orders::new(None);
        let mut damage = Vec::new();
        if slow_path {
            o.slowpath(&data, &mut fb, &mut damage).unwrap();
        } else {
            o.fastpath(&data, &mut fb, &mut damage).unwrap();
        }
        assert_eq!(fb.pixels.iter().filter(|&&p| p == 9).count(), 4);
        assert_eq!(damage.len(), 1);
    }
}

#[test]
fn many_small_damages_merge() {
    let mut c = Canvas::new(100, 2, 0);
    let mut orders = Vec::new();
    for x in 0..80i16 {
        orders.push(prim(
            0x0A,
            1,
            0x7F,
            &[&coords(&[x, 0, 1, 1])[..], &[1, 1, 1]].concat(),
        ));
    }
    c.run(&orders);
    assert_eq!(
        c.damage,
        vec![Damage {
            x: 0,
            y: 0,
            w: 80,
            h: 1
        }]
    );
}

// ---- persistent bitmap cache ----

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rdp-orders-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn persistent_bitmaps_survive_a_reconnect() {
    let dir = temp_dir("persist");
    let key = 0x0123_4567_89AB_CDEFu64;
    let px = [0x010203, 0x040506, 0x070809, 0x0A0B0C];
    {
        let mut c = Canvas::new(4, 4, 0);
        c.o = Orders::new(Some(&dir));
        assert!(
            c.o.persistent_key_lists(true).is_empty(),
            "nothing stored yet"
        );
        c.run(&[cache_bitmap_v2(2, 5, 2, 2, &px, Some(key))]);
        // Non-persistent caches are not stored.
        c.run(&[cache_bitmap_v2(0, 1, 2, 2, &px, Some(key + 1))]);
    }
    let mut c = Canvas::new(4, 4, 0);
    c.o = Orders::new(Some(&dir));
    assert_eq!(c.o.persisted_keys[2], vec![key]);
    assert!(c.o.persisted_keys[0].is_empty());
    // The server addresses loaded keys by their position in the key list.
    c.run(&[memblt(2, 0, [0, 0, 2, 2], [0, 0], 0xCC)]);
    assert_eq!(c.px(1, 1), 0x0A0B0C);
    let pdus = c.o.persistent_key_lists(true);
    assert_eq!(pdus.len(), 1);
    let p = &pdus[0];
    assert_eq!(u16::from_le_bytes([p[4], p[5]]), 1, "numEntriesCache2");
    assert_eq!(u16::from_le_bytes([p[14], p[15]]), 1, "totalEntriesCache2");
    assert_eq!(p[20], 0x03, "PERSIST_PDU_FIRST | PERSIST_PDU_LAST");
    assert_eq!(&p[24..32], &key.to_le_bytes());
    assert!(c.o.persistent_key_lists(true).is_empty(), "sent once");
    let mut o = Orders::new(Some(&dir));
    assert!(
        o.persistent_key_lists(false).is_empty(),
        "server without rev. 2 caches"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn key_lists_split_at_169_keys() {
    let keys = vec![vec![1u64], vec![], (0..200u64).collect()];
    let pdus = persist::key_list_pdus(&keys);
    assert_eq!(pdus.len(), 2);
    let n = |p: &Vec<u8>, i: usize| u16::from_le_bytes([p[i * 2], p[i * 2 + 1]]);
    assert_eq!((n(&pdus[0], 0), n(&pdus[0], 2)), (1, 168));
    assert_eq!((n(&pdus[1], 0), n(&pdus[1], 2)), (0, 32));
    assert_eq!((n(&pdus[0], 5), n(&pdus[0], 7)), (1, 200), "totals");
    assert_eq!((n(&pdus[1], 5), n(&pdus[1], 7)), (1, 200));
    assert_eq!((pdus[0][20], pdus[1][20]), (0x01, 0x02));
    assert_eq!(pdus[0].len(), 24 + 169 * 8);
    // Keys in cache order: cache 0's key first.
    assert_eq!(&pdus[0][24..32], &1u64.to_le_bytes());
    assert!(persist::key_list_pdus(&[vec![], vec![], vec![]]).is_empty());
}

#[test]
fn persistent_store_evicts_the_oldest_to_the_cap() {
    let dir = temp_dir("evict");
    let bmp = Bitmap {
        w: 16,
        h: 16,
        px: vec![7; 256],
    };
    let size = 9 + 256 * 3;
    {
        let mut s = persist::Store::open(&dir, 1 << 30).unwrap();
        for k in 0..10u64 {
            s.save(2, k, &bmp);
            let f = std::fs::File::options()
                .write(true)
                .open(dir.join("c2").join(format!("{k:016x}.bmp")))
                .unwrap();
            let t =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000 + k);
            f.set_modified(t).unwrap();
        }
    }
    // Reopen with room for four files: the six oldest go.
    let mut s = persist::Store::open(&dir, 4 * size as u64).unwrap();
    let loaded = s.load(2, 100);
    let keys: Vec<u64> = loaded.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![9, 8, 7, 6]);
    assert_eq!(loaded[0].1, bmp);
    // A corrupt file is dropped.
    std::fs::write(dir.join("c2").join(format!("{:016x}.bmp", 99)), b"junk").unwrap();
    assert_eq!(s.load(2, 100).len(), 4);
    assert!(!dir.join("c2").join(format!("{:016x}.bmp", 99)).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- capability sets ----

fn capsets(pdu: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut r = Reader::new(pdu);
    let total = r.u16().unwrap() as usize;
    assert_eq!(total, pdu.len());
    r.skip(4 + 4 + 2).unwrap();
    let src = r.u16().unwrap() as usize;
    let combined = r.u16().unwrap() as usize;
    r.skip(src).unwrap();
    assert_eq!(combined, r.remaining());
    let n = r.u16().unwrap();
    r.u16().unwrap();
    let mut out = Vec::new();
    for _ in 0..n {
        let ty = r.u16().unwrap();
        let len = r.u16().unwrap() as usize;
        out.push((ty, r.bytes(len - 4).unwrap().to_vec()));
    }
    assert_eq!(r.remaining(), 0);
    out
}

#[test]
fn confirm_active_gets_the_order_and_cache_sets() {
    let plain = crate::pdu::confirm_active(0x1234, 1007, 1024, 768, 0x409, 32, false);
    let before = capsets(&plain);
    let o = Orders::new(None);
    let patched = caps::patch_confirm_active(&plain, &o.client_caps()).unwrap();
    let after = capsets(&patched);
    assert_eq!(after.len(), before.len());
    let get = |ty: u16| after.iter().find(|(t, _)| *t == ty).map(|(_, b)| b.clone());
    assert!(
        get(caps::CAPSTYPE_BITMAPCACHE).is_none(),
        "revision 1 replaced"
    );
    let rev2 = get(caps::CAPSTYPE_BITMAPCACHE_REV2).unwrap();
    assert_eq!(rev2.len(), 36);
    assert_eq!(rev2[3], 3, "NumCellCaches");
    assert_eq!(
        u16::from_le_bytes([rev2[0], rev2[1]]),
        0,
        "no persistent keys without a directory"
    );
    let order = get(caps::CAPSTYPE_ORDER).unwrap();
    assert_eq!(order.len(), 84);
    let support = &order[32..64];
    for i in [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x0F, 0x12, 0x13, 0x16, 0x18, 0x1B,
    ] {
        assert_eq!(support[i], 1, "orderSupport[{i:#x}]");
    }
    assert_eq!(support[0x0B], 0, "SaveBitmap not negotiated");
    let glyph = get(caps::CAPSTYPE_GLYPHCACHE).unwrap();
    assert_eq!(
        u16::from_le_bytes([glyph[44], glyph[45]]),
        3,
        "GLYPH_SUPPORT_ENCODE"
    );
    assert_eq!(get(caps::CAPSTYPE_BRUSH).unwrap(), vec![2, 0, 0, 0]);
    assert_eq!(
        get(caps::CAPSTYPE_OFFSCREENCACHE).unwrap()[..4],
        [1, 0, 0, 0]
    );
    // Other sets are untouched and in place.
    assert_eq!(before[0], after[0]);

    // With a persistent directory, cache 2 is persistent and keys are expected.
    let dir = temp_dir("caps");
    let o = Orders::new(Some(&dir));
    let rev2 = caps::client_caps(o.store.is_some())[1].1.clone();
    assert_eq!(u16::from_le_bytes([rev2[0], rev2[1]]), 1);
    assert_eq!(
        u32::from_le_bytes(rev2[12..16].try_into().unwrap()),
        2560 | 0x8000_0000
    );
    assert_eq!(u32::from_le_bytes(rev2[4..8].try_into().unwrap()), 600);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- drawing primitives ----

#[test]
fn blt_reads_outside_source_as_zero_and_clips() {
    let mut px = vec![5u32; 16];
    let mut s = Surface {
        px: &mut px,
        w: 4,
        h: 4,
    };
    let src = Source {
        px: &[1, 2, 3, 4],
        w: 2,
        h: 2,
    };
    let area = draw::blt(
        &mut s,
        Clip::new(-10, -10, 100, 100),
        Clip::rect(2, 2, 3, 3),
        0xCC,
        &Pattern::Solid(0),
        Some((&src, 0, 0)),
    );
    assert_eq!(area, Clip::new(2, 2, 4, 4));
    assert_eq!(&px[8..], &[5, 5, 1, 2, 5, 5, 3, 4]);
}
