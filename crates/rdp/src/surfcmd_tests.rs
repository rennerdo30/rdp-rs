use super::*;
use crate::gfx::rfx::COEFFS;

/// MS-RDPRFX 4.2.2 (encode header messages) followed by 4.2.3 (one frame:
/// FRAME_BEGIN, a 64x64 REGION, a one-tile TILESET, FRAME_END).
const MESSAGES: &[u8] = include_bytes!("gfx/testdata/rfx_message.bin");
const HEADERS_LEN: usize = 0x2f;
/// MS-RDPRFX 4.2.4.1: a TS_RFX_TILESET with one tile, and 4.2.4.5 its
/// decoded XRGB image.
const TILESET: &[u8] = include_bytes!("gfx/testdata/rfx_tileset.bin");
const XRGB: &[u8] = include_bytes!("gfx/testdata/rfx_xrgb.bin");

/// MS-RDPRFX 4.2.1: TS_RFX_CLNT_CAPS_CONTAINER.
const RFX_CLIENT_CAPS: [u8; 0x31] = [
    0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0xc0, 0xcb, 0x08, 0x00,
    0x00, 0x00, 0x01, 0x00, 0xc1, 0xcb, 0x1d, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xcf, 0x02, 0x00, 0x08,
    0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x40, 0x00, 0x00, 0x01, 0x01,
    0x04,
];

#[test]
fn rfx_client_caps_match_the_spec_example() {
    assert_eq!(rfx_client_caps_container(), RFX_CLIENT_CAPS);
}

#[test]
fn codec_guids_in_wire_order() {
    assert_eq!(
        CODEC_GUID_REMOTEFX,
        [
            0x12, 0x2F, 0x77, 0x76, 0x72, 0xBD, 0x63, 0x44, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F,
            0x78, 0x86
        ]
    );
    assert_eq!(CODEC_GUID_NSCODEC[..4], [0xB9, 0x1B, 0x8D, 0xCA]);
    assert_eq!(CODEC_GUID_NSCODEC[4..8], [0x0F, 0x00, 0x4F, 0x15]);
}

#[test]
fn capability_sets() {
    let sets = client_capability_sets();
    let ty: Vec<u16> = sets.iter().map(|s| s.0).collect();
    assert_eq!(ty, [0x1C, 0x1D, 0x1E]);
    // cmdFlags: SETSURFACEBITS | FRAMEMARKER | STREAMSURFACEBITS, reserved.
    assert_eq!(sets[0].1, [0x52, 0, 0, 0, 0, 0, 0, 0]);
    let codecs = &sets[1].1;
    assert_eq!(codecs[0], 2);
    // NSCodec first, with codec id 1 (it MUST be 1) and its 3-byte caps.
    assert_eq!(codecs[1..17], CODEC_GUID_NSCODEC);
    assert_eq!(codecs[17..20], [CODEC_ID_NSCODEC, 3, 0]);
    assert_eq!(codecs[20..23], nscodec_caps());
    assert_eq!(codecs[23..39], CODEC_GUID_REMOTEFX);
    assert_eq!(codecs[39..42], [CODEC_ID_REMOTEFX, 0x31, 0]);
    assert_eq!(codecs[42..], RFX_CLIENT_CAPS);
}

#[test]
fn appends_capability_sets_to_confirm_active() {
    let base = crate::pdu::confirm_active(0x1234, 1007, 800, 600, 0x409, 32, false);
    let sets = client_capability_sets();
    let pdu = append_capability_sets(base.clone(), &sets);
    let le16 = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]) as usize;
    assert_eq!(le16(&pdu, 0), pdu.len());
    let added: usize = sets.iter().map(|s| s.1.len() + 4).sum();
    assert_eq!(pdu.len(), base.len() + added);
    assert_eq!(le16(&pdu, 14), le16(&base, 14) + added);
    let count_at = 16 + le16(&pdu, 12);
    assert_eq!(le16(&pdu, count_at), le16(&base, count_at) + 3);
    // The combined length still covers the count, pad and every set.
    assert_eq!(count_at + le16(&pdu, 14), pdu.len());
    // Walk the sets: the last three are ours.
    let mut at = count_at + 4;
    let mut types = Vec::new();
    while at < pdu.len() {
        types.push(le16(&pdu, at));
        at += le16(&pdu, at + 2);
    }
    assert_eq!(at, pdu.len());
    assert_eq!(types[types.len() - 3..], [0x1C, 0x1D, 0x1E]);
}

#[test]
fn rfx_spec_stream_parses() {
    let mut dec = RfxDecoder::new();
    // Headers alone end no frame.
    assert!(dec.decode(&MESSAGES[..HEADERS_LEN]).unwrap().is_empty());
    let frames = dec.decode(&MESSAGES[HEADERS_LEN..]).unwrap();
    assert_eq!(frames.len(), 1);
    let f = &frames[0];
    assert_eq!(
        f.rects,
        [crate::gfx::rfx_msg::RfxRect {
            x: 0,
            y: 0,
            w: 64,
            h: 64
        }]
    );
    assert_eq!(f.tiles.len(), 1);
    assert_eq!((f.tiles[0].x, f.tiles[0].y), (0, 0));
}

#[test]
fn rfx_rejects_a_bad_sync() {
    let mut bad = MESSAGES[..HEADERS_LEN].to_vec();
    bad[6] ^= 1; // magic
    assert!(RfxDecoder::new().decode(&bad).is_err());
}

/// The 4.2.3 frame with the 4.2.4.1 tileset in place of its own, at tile
/// index (tx, ty), and the given region rectangles.
fn spec_frame(tx: u16, ty: u16, rects: &[(u16, u16, u16, u16)]) -> Vec<u8> {
    let mut m = MESSAGES[..HEADERS_LEN].to_vec();
    m.extend_from_slice(&MESSAGES[HEADERS_LEN..HEADERS_LEN + 14]); // FRAME_BEGIN
    let mut region = Vec::new();
    region.put_u16(0xCCC6);
    region.put_u32((15 + 8 * rects.len()) as u32);
    region.put_bytes(&[1, 0, 1]);
    region.put_u16(rects.len() as u16);
    for &(x, y, w, h) in rects {
        for v in [x, y, w, h] {
            region.put_u16(v);
        }
    }
    region.put_u16(0xCAC1);
    region.put_u16(1);
    m.extend_from_slice(&region);
    let mut ts = TILESET.to_vec();
    // The tile's xIdx and yIdx (4.2.4.1: CBT_TILE at 0x1B).
    ts[0x1B + 9..0x1B + 11].copy_from_slice(&tx.to_le_bytes());
    ts[0x1B + 11..0x1B + 13].copy_from_slice(&ty.to_le_bytes());
    m.extend_from_slice(&ts);
    m.extend_from_slice(&MESSAGES[MESSAGES.len() - 8..]); // FRAME_END
    m
}

fn want_pixels() -> Vec<u32> {
    XRGB.as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u32::from_le_bytes(c) & 0xFF_FFFF)
        .collect()
}

/// Within one step per channel of the spec's floating-point result
/// (see `spec_sample_tile_to_xrgb` in the progressive tests).
fn close(a: u32, b: u32) -> bool {
    [0, 8, 16]
        .iter()
        .all(|s| ((a >> s) & 0xFF).abs_diff((b >> s) & 0xFF) <= 1)
}

fn surface_bits(codec: u8, left: u16, top: u16, w: u16, h: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(CMDTYPE_STREAM_SURFACE_BITS);
    for v in [left, top, left + w, top + h] {
        b.put_u16(v);
    }
    b.put_bytes(&[32, 0, 0, codec]);
    b.put_u16(w);
    b.put_u16(h);
    b.put_u32(data.len() as u32);
    b.put_bytes(data);
    b
}

fn frame_marker(action: u16, id: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(CMDTYPE_FRAME_MARKER);
    b.put_u16(action);
    b.put_u32(id);
    b
}

#[test]
fn remotefx_surface_bits_draw_the_spec_tile() {
    let mut fb = Framebuffer::new(200, 150);
    let mut s = SurfaceCommands {
        frame_ack: true,
        ..Default::default()
    };
    let mut upd = frame_marker(SURFACECMD_FRAMEACTION_BEGIN, 7);
    upd.extend(surface_bits(
        CODEC_ID_REMOTEFX,
        10,
        20,
        64,
        64,
        &spec_frame(0, 0, &[(0, 0, 64, 64)]),
    ));
    upd.extend(frame_marker(SURFACECMD_FRAMEACTION_END, 7));
    let mut damage = Vec::new();
    let acks = s.apply(&upd, &mut fb, &mut damage).unwrap();
    assert_eq!(acks, [7]);
    assert_eq!(
        damage,
        [Damage {
            x: 10,
            y: 20,
            w: 64,
            h: 64
        }]
    );
    let want = want_pixels();
    for y in 0..64 {
        for x in 0..64 {
            let got = fb.pixels[(20 + y) * 200 + 10 + x];
            assert!(close(got, want[y * 64 + x]), "pixel {x},{y}");
        }
    }
    // Outside the destination nothing was drawn.
    assert_eq!(fb.pixels[19 * 200 + 10], 0);
    assert_eq!(fb.pixels[20 * 200 + 9], 0);
}

#[test]
fn remotefx_region_clips_the_tile() {
    let mut fb = Framebuffer::new(256, 256);
    let mut s = SurfaceCommands::default();
    // Tile (1, 1) covers 64..128; the region keeps 80..96 x 70..74.
    let msg = spec_frame(1, 1, &[(80, 70, 16, 4)]);
    let upd = surface_bits(CODEC_ID_REMOTEFX, 0, 0, 256, 256, &msg);
    let mut damage = Vec::new();
    let acks = s.apply(&upd, &mut fb, &mut damage).unwrap();
    assert!(acks.is_empty(), "no frame marker, no acknowledgement");
    assert_eq!(
        damage,
        [Damage {
            x: 80,
            y: 70,
            w: 16,
            h: 4
        }]
    );
    let want = want_pixels();
    let drawn = fb.pixels.iter().filter(|&&p| p != 0).count();
    assert!(drawn <= 16 * 4);
    for y in 70..74 {
        for x in 80..96 {
            let w = want[(y - 64) * 64 + (x - 64)];
            assert!(close(fb.pixels[y * 256 + x], w), "pixel {x},{y}");
        }
    }
    assert_eq!(fb.pixels[69 * 256 + 80], 0);
    assert_eq!(fb.pixels[70 * 256 + 96], 0);
}

#[test]
fn frame_end_is_acknowledged_only_when_negotiated() {
    let mut fb = Framebuffer::new(8, 8);
    let mut s = SurfaceCommands::default();
    let upd = frame_marker(SURFACECMD_FRAMEACTION_END, 3);
    assert!(s.apply(&upd, &mut fb, &mut Vec::new()).unwrap().is_empty());
    s.frame_ack = true;
    assert_eq!(s.apply(&upd, &mut fb, &mut Vec::new()).unwrap(), [3]);
    assert_eq!(frame_acknowledge(3), [3, 0, 0, 0]);
}

#[test]
fn nscodec_and_uncompressed_surface_bits() {
    let mut fb = Framebuffer::new(16, 16);
    let mut s = SurfaceCommands::default();
    // NSCodec, 2x1, raw planes, colour loss level 1: luma 100 and 200,
    // no chroma, opaque alpha.
    let mut ns = Vec::new();
    for len in [2u32, 2, 2, 2] {
        ns.put_u32(len);
    }
    ns.put_bytes(&[1, 0, 0, 0]);
    ns.put_bytes(&[100, 200, 0, 0, 0, 0, 255, 255]);
    let mut upd = surface_bits(CODEC_ID_NSCODEC, 3, 4, 2, 1, &ns);
    // Uncompressed: one BGRX pixel.
    upd.extend(surface_bits(
        CODEC_ID_NONE,
        0,
        0,
        1,
        1,
        &[0x11, 0x22, 0x33, 0xFF],
    ));
    upd[8] = 32; // bpp of the first command
    let mut damage = Vec::new();
    s.apply(&upd, &mut fb, &mut damage).unwrap();
    assert_eq!(fb.pixels[4 * 16 + 3], 0x64_6464);
    assert_eq!(fb.pixels[4 * 16 + 4], 0xC8_C8C8);
    assert_eq!(fb.pixels[0], 0x33_2211);
    assert_eq!(damage.len(), 2);
}

#[test]
fn bad_updates_are_errors_not_panics() {
    let mut fb = Framebuffer::new(8, 8);
    let mut s = SurfaceCommands::default();
    for upd in [
        vec![0x01, 0x00, 0x00],
        vec![0x99, 0x00],
        surface_bits(9, 0, 0, 4, 4, &[0; 4]),
        surface_bits(CODEC_ID_REMOTEFX, 0, 0, 4, 4, &[0xC0, 0xCC, 2, 0, 0, 0]),
        surface_bits(CODEC_ID_NONE, 0, 0, 4, 4, &[0; 4]),
    ] {
        assert!(s.apply(&upd, &mut fb, &mut Vec::new()).is_err());
    }
    // A truncated tileset inside a well-formed frame.
    let mut msg = spec_frame(0, 0, &[(0, 0, 64, 64)]);
    msg.truncate(msg.len() - 100);
    let upd = surface_bits(CODEC_ID_REMOTEFX, 0, 0, 64, 64, &msg);
    assert!(s.apply(&upd, &mut fb, &mut Vec::new()).is_err());
    let _ = COEFFS;
}
