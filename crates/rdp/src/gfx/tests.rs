use super::h264::{H264Decoder, Yuv420Frame, yuv_to_rgb};
use super::pdu::*;
use super::surface::{Area, GfxState};
use super::zgfx::Zgfx;
use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::Put;
use crate::dvc::Drdynvc;
use crate::error::Error;

pub(super) fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

// ---- ZGFX (MS-RDPEGFX 4.2.1.1) ----

#[test]
fn zgfx_example1_literals_and_match() {
    let out = Zgfx::new()
        .decompress(&hex("E0 24 CE 9B 19 62 18 00"))
        .unwrap();
    assert_eq!(out, hex("01 02 FF 65 65 65 65 65"));
}

#[test]
fn zgfx_example2_unencoded_segment() {
    let text = b"The quick brown fox jumps over the lazy dog";
    let mut msg = hex("E0 04");
    msg.extend_from_slice(text);
    assert_eq!(Zgfx::new().decompress(&msg).unwrap(), text);
}

#[test]
fn zgfx_example3_overlapping_match() {
    let out = Zgfx::new()
        .decompress(&hex("E0 24 20 90 88 71 1F B2 01"))
        .unwrap();
    assert_eq!(out, b"ABC".repeat(20));
}

#[test]
fn zgfx_example4_multipart_shares_history() {
    let msg = hex("E1 03 00 2B 00 00 00 11 00 00 00 04 54 68 65 20 \
         71 75 69 63 6B 20 62 72 6F 77 6E 20 0E 00 00 00 \
         04 66 6F 78 20 6A 75 6D 70 73 20 6F 76 65 10 00 \
         00 00 24 39 08 0E 91 F8 D8 61 3D 1E 44 06 43 79 \
         9C 02");
    let out = Zgfx::new().decompress(&msg).unwrap();
    assert_eq!(out, b"The quick brown fox jumps over the lazy dog");
}

#[test]
fn zgfx_example5_unencoded_run_in_compressed_segment() {
    // Same layout as 4.2.1.1.5: match distance 0, a 15-bit count of 1,000,
    // padding to the byte boundary, the raw bytes, trailer 0.
    let raw: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut msg = hex("E0 24 88 01 F4 00");
    msg.extend_from_slice(&raw);
    msg.push(0);
    assert_eq!(Zgfx::new().decompress(&msg).unwrap(), raw);
}

#[test]
fn zgfx_longer_distances_and_lengths() {
    let mut z = Zgfx::new();
    let raw: Vec<u8> = (1..=200u8).collect();
    let mut msg = vec![0xE0, 0x04];
    msg.extend_from_slice(&raw);
    z.decompress(&msg).unwrap();
    // 10010 0001000 = distance 32 + 8 = 40; "0" = length 3; 3 unused bits.
    assert_eq!(
        z.decompress(&hex("E0 24 90 80 03")).unwrap(),
        [161, 162, 163]
    );
    // That copy is history too. 10011 000000010 = distance 160 + 2 = 162
    // (back to value 42); "110 101" = length 8 + 5 = 13;
    // 4 unused bits.
    let out = z.decompress(&hex("E0 24 98 0B 50 04")).unwrap();
    assert_eq!(out, (42..55).collect::<Vec<u8>>());
}

#[test]
fn zgfx_history_persists_across_messages() {
    let mut z = Zgfx::new();
    z.decompress(&hex("E0 04 41 42 43")).unwrap();
    // 10001 00011 0 = match distance 3, length 3, then 5 unused bits:
    // 0x88 0xC0, trailer 0x05.
    assert_eq!(z.decompress(&hex("E0 24 88 C0 05")).unwrap(), b"ABC");
    // A fresh decoder has no history for that distance.
    assert!(Zgfx::new().decompress(&hex("E0 24 88 C0 05")).is_err());
}

#[test]
fn zgfx_rejects_bad_input() {
    let bad: &[&[u8]] = &[
        &[],
        &[0xE2, 0x04],                   // unknown descriptor
        &[0xE0],                         // no segment header
        &[0xE0, 0x03, 1, 2],             // compression type 3
        &[0xE0, 0x24],                   // compressed without trailer
        &[0xE0, 0x24, 0x00, 0x09],       // 7 bits left: a literal overruns
        &[0xE0, 0x24, 0x80, 0x00],       // "10000" reserved token
        &[0xE0, 0x24, 0x88, 0x40, 0x00], // distance 1 with empty history
        &[0xE1, 0x01, 0x00, 0x05, 0, 0, 0, 0x02, 0, 0, 0, 0x04, 0x41], // size mismatch
        &[0xE1, 0x01, 0x00],             // truncated header
    ];
    for b in bad {
        assert!(Zgfx::new().decompress(b).is_err(), "{b:02x?}");
    }
    // An unencoded run longer than the segment.
    assert!(
        Zgfx::new()
            .decompress(&hex("E0 24 88 01 F4 00 41 00"))
            .is_err()
    );
}

#[test]
fn zgfx_random_input_never_panics() {
    let mut seed = 0x1234_5678u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    let mut z = Zgfx::new();
    for _ in 0..3000 {
        let len = (next() % 40) as usize;
        let mut msg: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if msg.len() > 2 {
            msg[0] = 0xE0 | (next() & 1) as u8;
            msg[1] = 0x24;
        }
        let _ = z.decompress(&msg);
    }
}

// ---- PDUs (MS-RDPEGFX 2.2.2) ----

pub(super) fn pdu(cmd: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(cmd);
    v.put_u16(0);
    v.put_u32(8 + body.len() as u32);
    v.extend_from_slice(body);
    v
}

pub(super) fn rect(l: u16, t: u16, r: u16, b: u16) -> Vec<u8> {
    [l, t, r, b].iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn one(buf: &[u8]) -> ServerPdu<'_> {
    let mut v = parse_pdus(buf).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].1, buf.len());
    v.remove(0).0
}

#[test]
fn caps_advertise_layout() {
    let v = caps_advertise(&advertised_caps(false));
    let mut want = hex("12 00 00 00 2E 00 00 00 03 00");
    want.extend(hex("01 07 0A 00 04 00 00 00 A2 00 00 00")); // 10.7
    want.extend(hex("02 00 0A 00 04 00 00 00 22 00 00 00")); // 10.0
    want.extend(hex("05 01 08 00 04 00 00 00 02 00 00 00")); // 8.1
    assert_eq!(v, want);
    // With a decoder: 10.x without AVC_DISABLED (AVC444 obliged), then 8.1
    // with AVC420.
    let v = caps_advertise(&advertised_caps(true));
    let mut want = hex("12 00 00 00 5E 00 00 00 07 00");
    want.extend(hex("01 07 0A 00 04 00 00 00 82 00 00 00")); // 10.7
    want.extend(hex("00 06 0A 00 04 00 00 00 02 00 00 00")); // 10.6
    want.extend(hex("02 05 0A 00 04 00 00 00 02 00 00 00")); // 10.5
    want.extend(hex("00 04 0A 00 04 00 00 00 02 00 00 00")); // 10.4
    want.extend(hex("00 02 0A 00 04 00 00 00 02 00 00 00")); // 10.2
    want.extend(hex("02 00 0A 00 04 00 00 00 02 00 00 00")); // 10.0
    want.extend(hex("05 01 08 00 04 00 00 00 12 00 00 00")); // 8.1
    assert_eq!(v, want);
}

#[test]
fn frame_acknowledge_layout() {
    assert_eq!(
        frame_acknowledge(0, 0x0102_0304, 7),
        hex("0D 00 00 00 14 00 00 00 00 00 00 00 04 03 02 01 07 00 00 00")
    );
}

#[test]
fn parse_caps_confirm_and_surface_commands() {
    let b = pdu(
        CMDID_CAPSCONFIRM,
        &hex("05 01 08 00 04 00 00 00 12 00 00 00"),
    );
    assert_eq!(
        one(&b),
        ServerPdu::CapsConfirm(CapSet {
            version: CAPVERSION_81,
            flags: 0x12
        })
    );
    let b = pdu(CMDID_CREATESURFACE, &hex("07 00 80 02 E0 01 20"));
    assert_eq!(
        one(&b),
        ServerPdu::CreateSurface {
            surface_id: 7,
            width: 640,
            height: 480,
            pixel_format: PIXEL_FORMAT_XRGB_8888
        }
    );
    let b = pdu(CMDID_DELETESURFACE, &hex("07 00"));
    assert_eq!(one(&b), ServerPdu::DeleteSurface { surface_id: 7 });
    let b = pdu(
        CMDID_MAPSURFACETOOUTPUT,
        &hex("07 00 00 00 0A 00 00 00 14 00 00 00"),
    );
    assert_eq!(
        one(&b),
        ServerPdu::MapSurfaceToOutput {
            surface_id: 7,
            x: 10,
            y: 20
        }
    );
    let b = pdu(CMDID_STARTFRAME, &hex("01 00 00 00 05 00 00 00"));
    assert_eq!(
        one(&b),
        ServerPdu::StartFrame {
            timestamp: 1,
            frame_id: 5
        }
    );
    let b = pdu(CMDID_ENDFRAME, &hex("05 00 00 00"));
    assert_eq!(one(&b), ServerPdu::EndFrame { frame_id: 5 });
    let b = pdu(CMDID_EVICTCACHEENTRY, &hex("09 00"));
    assert_eq!(one(&b), ServerPdu::EvictCacheEntry { cache_slot: 9 });
}

#[test]
fn parse_fill_copy_cache_commands() {
    // Colour B, G, R, XA = 0x11 0x22 0x33 0xFF -> 0x00332211.
    let mut body = hex("02 00 11 22 33 FF 02 00");
    body.extend(rect(0, 0, 4, 4));
    body.extend(rect(8, 8, 9, 10));
    assert_eq!(
        one(&pdu(CMDID_SOLIDFILL, &body)),
        ServerPdu::SolidFill {
            surface_id: 2,
            color: 0x0033_2211,
            rects: vec![
                Rect16 {
                    left: 0,
                    top: 0,
                    right: 4,
                    bottom: 4
                },
                Rect16 {
                    left: 8,
                    top: 8,
                    right: 9,
                    bottom: 10
                }
            ],
        }
    );
    let mut body = hex("01 00 02 00");
    body.extend(rect(1, 2, 3, 4));
    body.extend(hex("01 00 05 00 06 00"));
    assert_eq!(
        one(&pdu(CMDID_SURFACETOSURFACE, &body)),
        ServerPdu::SurfaceToSurface {
            src: 1,
            dst: 2,
            rect: Rect16 {
                left: 1,
                top: 2,
                right: 3,
                bottom: 4
            },
            points: vec![Point16 { x: 5, y: 6 }],
        }
    );
    let mut body = hex("01 00 88 77 66 55 44 33 22 11 03 00");
    body.extend(rect(0, 0, 2, 2));
    assert!(matches!(
        one(&pdu(CMDID_SURFACETOCACHE, &body)),
        ServerPdu::SurfaceToCache {
            surface_id: 1,
            cache_key: 0x1122_3344_5566_7788,
            cache_slot: 3,
            ..
        }
    ));
    let body = hex("03 00 01 00 02 00 00 00 00 00 0A 00 0A 00");
    assert_eq!(
        one(&pdu(CMDID_CACHETOSURFACE, &body)),
        ServerPdu::CacheToSurface {
            cache_slot: 3,
            surface_id: 1,
            points: vec![Point16 { x: 0, y: 0 }, Point16 { x: 10, y: 10 }],
        }
    );
    let body = hex("02 00 06 00 09 00");
    assert_eq!(
        one(&pdu(CMDID_CACHEIMPORTREPLY, &body)),
        ServerPdu::CacheImportReply { slots: vec![6, 9] }
    );
}

fn reset_pdu(w: u32, h: u32) -> Vec<u8> {
    // 340 bytes in all (2.2.2.14): one monitor, then padding.
    let mut body = Vec::new();
    body.put_u32(w);
    body.put_u32(h);
    body.put_u32(1);
    body.extend(hex("00 00 00 00 00 00 00 00"));
    body.put_u32(w - 1);
    body.put_u32(h - 1);
    body.put_u32(1);
    body.resize(332, 0);
    pdu(CMDID_RESETGRAPHICS, &body)
}

#[test]
fn parse_reset_graphics_and_wire_to_surface() {
    let b = reset_pdu(1024, 768);
    assert_eq!(b.len(), 340);
    assert_eq!(
        one(&b),
        ServerPdu::ResetGraphics {
            width: 1024,
            height: 768,
            monitor_count: 1
        }
    );
    let mut bad = b.clone();
    bad[16] = 17; // monitorCount over 16
    assert!(
        parse_pdus(&bad).unwrap().is_empty(),
        "the bad PDU is skipped"
    );
    // 17 monitors refused even when the PDU is long enough to hold them.
    let mut body = Vec::new();
    body.put_u32(1024);
    body.put_u32(768);
    body.put_u32(17);
    body.resize(12 + 17 * 20, 0);
    assert!(
        parse_pdus(&pdu(CMDID_RESETGRAPHICS, &body))
            .unwrap()
            .is_empty()
    );
    body[8] = 16;
    assert!(parse_pdus(&pdu(CMDID_RESETGRAPHICS, &body)).is_ok());
    let mut body = hex("01 00 0A 00 20");
    body.extend(rect(1, 1, 3, 2));
    body.extend(hex("03 00 00 00 AA BB CC"));
    assert_eq!(
        one(&pdu(CMDID_WIRETOSURFACE_1, &body)),
        ServerPdu::WireToSurface1 {
            surface_id: 1,
            codec_id: CODECID_PLANAR,
            pixel_format: PIXEL_FORMAT_XRGB_8888,
            dest: Rect16 {
                left: 1,
                top: 1,
                right: 3,
                bottom: 2
            },
            data: &[0xAA, 0xBB, 0xCC],
        }
    );
}

#[test]
fn parse_rejects_malformed_pdus() {
    let cases = [
        hex("04 00 00 00 07 00 00 00"),    // pduLength below the header
        hex("04 00 00 00 20 00 00 00 00"), // pduLength past the buffer
        pdu(CMDID_SOLIDFILL, &hex("01 00 00 00 00 00 05 00")), // rects missing
        pdu(
            CMDID_WIRETOSURFACE_1,
            &hex("01 00 00 00 20 05 00 05 00 00 00 00 00 10 00 00 00"),
        ), // inverted rect
        pdu(CMDID_CACHETOSURFACE, &hex("01 00 01 00 FF FF")), // points missing
        pdu(
            CMDID_RESETGRAPHICS,
            &hex("00 00 00 00 10 00 00 00 00 00 00 00"),
        ), // width 0
    ];
    // A broken header fails the message; a broken body skips that PDU.
    for c in &cases {
        assert!(parse_pdus(c).map_or(true, |v| v.is_empty()), "{c:02x?}");
    }
    // Unknown commands are reported, not refused.
    assert_eq!(one(&pdu(0x0016, &[1, 2, 3])), ServerPdu::Other(0x0016));
}

#[test]
fn several_pdus_in_one_message_report_offsets() {
    let mut buf = pdu(CMDID_STARTFRAME, &hex("00 00 00 00 01 00 00 00"));
    buf.extend(pdu(CMDID_ENDFRAME, &hex("01 00 00 00")));
    let v = parse_pdus(&buf).unwrap();
    assert_eq!(v.iter().map(|p| p.1).collect::<Vec<_>>(), [16, 28]);
}

#[test]
fn avc420_metablock() {
    let mut data = hex("02 00 00 00");
    data.extend(rect(0, 0, 16, 16));
    data.extend(rect(16, 0, 32, 8));
    // qp 22 q 100 with the reserved bit set; qp 26 progressive q 50.
    data.extend(hex("56 64 9A 32"));
    data.extend(hex("00 00 00 01 67"));
    let m = parse_avc420(&data).unwrap();
    assert_eq!(m.regions.len(), 2);
    assert_eq!(m.regions[1].left, 16);
    assert_eq!(
        m.quality,
        vec![
            QuantQuality {
                qp: 22,
                progressive: false,
                quality: 100
            },
            QuantQuality {
                qp: 26,
                progressive: true,
                quality: 50
            }
        ]
    );
    assert_eq!(m.bitstream, &[0, 0, 0, 1, 0x67]);
    // Region count larger than the data.
    assert!(parse_avc420(&hex("03 00 00 00 00 00 00 00 10 00 10 00 16 64")).is_err());
    assert!(parse_avc420(&hex("FF FF FF FF")).is_err());
    assert!(parse_avc420(&[1, 0]).is_err());
}

// ---- YUV to RGB (3.3.8.3.1) ----

#[test]
fn yuv_to_rgb_hand_computed() {
    assert_eq!(yuv_to_rgb(128, 128, 128), 0x0080_8080);
    assert_eq!(yuv_to_rgb(0, 128, 128), 0x0000_0000);
    assert_eq!(yuv_to_rgb(255, 128, 128), 0x00FF_FFFF);
    // R = (65280 + 403*127) >> 8 = 454 -> 255; G = (65280 - 15240) >> 8 = 195.
    assert_eq!(yuv_to_rgb(255, 128, 255), 0x00FF_C3FF);
    // y=25600, U-128=72, V-128=-78: R = -5834>>8 -> 0, G = 31504>>8 = 123,
    // B = 59800>>8 = 233.
    assert_eq!(yuv_to_rgb(100, 200, 50), 0x0000_7BE9);
    // G = (12800 - 48*(-28) - 120*92) >> 8 = (12800 + 1344 - 11040) >> 8 = 12.
    // R = (12800 + 37076) >> 8 = 194; B = (12800 - 13300) >> 8 -> 0.
    assert_eq!(yuv_to_rgb(50, 100, 220), 0x00C2_0C00);
    // One value per coefficient where a coefficient off by one shows:
    // B = 475*127 >> 8 = 235; G = (32768 + 48*128) >> 8 = 152;
    // G = (32768 + 120*128) >> 8 = 188; R = 403*127 >> 8 = 199.
    assert_eq!(yuv_to_rgb(0, 255, 128), 0x0000_00EB);
    assert_eq!(yuv_to_rgb(128, 0, 128), 0x0080_9800);
    assert_eq!(yuv_to_rgb(128, 128, 0), 0x0000_BC80);
    assert_eq!(yuv_to_rgb(0, 128, 255), 0x00C7_0000);
}

#[test]
fn yuv_frame_validate_and_sample() {
    let f = Yuv420Frame {
        width: 3,
        height: 3,
        y: vec![128; 9],
        u: vec![128, 255, 128, 128],
        v: vec![128; 4],
        y_stride: 3,
        uv_stride: 2,
    };
    f.validate().unwrap();
    assert_eq!(f.rgb(0, 0), 0x0080_8080);
    // (2, 0) uses chroma sample (1, 0): U = 255.
    assert_eq!(f.rgb(2, 0), yuv_to_rgb(128, 255, 128));
    let short = Yuv420Frame {
        u: vec![0; 3],
        ..f.clone()
    };
    assert!(short.validate().is_err());
    // Chroma is shared by 2x2 pixels: x 4 and 5 use chroma column 2.
    let wide = Yuv420Frame {
        width: 6,
        height: 2,
        y: vec![128; 12],
        u: vec![128, 128, 0],
        v: vec![128; 3],
        y_stride: 6,
        uv_stride: 3,
    };
    assert_eq!(wide.rgb(4, 1), yuv_to_rgb(128, 0, 128));
    assert_eq!(wide.rgb(3, 1), 0x0080_8080);
}

// ---- Surfaces, cache, output (3.3.1) ----

fn state_with_surface(w: usize, h: usize) -> GfxState {
    let mut s = GfxState::new();
    s.reset(w, h);
    s.create(1, w, h).unwrap();
    assert!(s.map(1, 0, 0));
    s
}

#[test]
fn fill_compose_present() {
    let mut s = state_with_surface(8, 4);
    s.compose();
    let mut fb = crate::Framebuffer::new(8, 4);
    let mut dmg = Vec::new();
    s.present(&mut fb, &mut dmg);
    dmg.clear();
    // Second rectangle is clipped to the surface.
    assert!(s.fill(
        1,
        0x00FF_0000,
        &[Area::new(1, 1, 2, 2), Area::new(6, 3, 10, 10)]
    ));
    assert_eq!(fb.pixels[9], 0, "nothing is shown before the end of frame");
    s.compose();
    assert!(!s.present(&mut fb, &mut dmg));
    assert_eq!(dmg.len(), 2);
    assert_eq!(
        dmg[1],
        crate::Damage {
            x: 6,
            y: 3,
            w: 2,
            h: 1
        }
    );
    let red: Vec<usize> = (0..32).filter(|&i| fb.pixels[i] == 0x00FF_0000).collect();
    assert_eq!(red, [9, 10, 17, 18, 30, 31]);
    assert!(!s.fill(9, 0, &[Area::new(0, 0, 1, 1)]), "unknown surface");
}

#[test]
fn mapping_shows_what_the_surface_already_holds() {
    let mut s = GfxState::new();
    s.reset(4, 4);
    s.create(1, 2, 2).unwrap();
    s.fill(1, 9, &[Area::new(0, 0, 2, 2)]);
    s.compose();
    assert!(s.output().pixels.iter().all(|&p| p == 0), "not mapped yet");
    s.map(1, 2, 2);
    s.compose();
    assert_eq!(s.output().pixels.iter().filter(|&&p| p == 9).count(), 4);
}

#[test]
fn mapped_origin_offsets_output() {
    let mut s = GfxState::new();
    s.reset(10, 10);
    s.create(4, 2, 2).unwrap();
    s.map(4, 7, 8);
    s.fill(4, 0x0012_3456, &[Area::new(0, 0, 2, 2)]);
    s.compose();
    let o = s.output();
    assert_eq!(o.pixels[8 * 10 + 7], 0x0012_3456);
    assert_eq!(o.pixels[9 * 10 + 8], 0x0012_3456);
    assert_eq!(o.pixels.iter().filter(|&&p| p != 0).count(), 4);
    // An unmapped surface never reaches the output.
    s.create(5, 2, 2).unwrap();
    s.fill(5, 0x00FF_FFFF, &[Area::new(0, 0, 2, 2)]);
    s.compose();
    assert_eq!(s.output().pixels.iter().filter(|&&p| p != 0).count(), 4);
}

#[test]
fn reset_resizes_framebuffer_once() {
    let mut s = state_with_surface(4, 2);
    s.fill(1, 7, &[Area::new(0, 0, 4, 2)]);
    s.compose();
    let mut fb = crate::Framebuffer::new(2, 2);
    let mut dmg = Vec::new();
    assert!(s.present(&mut fb, &mut dmg));
    assert_eq!((fb.width, fb.height), (4, 2));
    assert!(fb.pixels.iter().all(|&p| p == 7));
    assert_eq!(
        dmg,
        [crate::Damage {
            x: 0,
            y: 0,
            w: 4,
            h: 2
        }]
    );
    dmg.clear();
    assert!(!s.present(&mut fb, &mut dmg));
    assert!(dmg.is_empty());
}

#[test]
fn surface_to_surface_overlapping_copy() {
    let mut s = state_with_surface(4, 1);
    let px = [1, 2, 3, 4];
    s.blit(1, Area::new(0, 0, 4, 1), &px, 4);
    // Copy pixels 0..3 one to the right on the same surface.
    assert!(s.copy(1, Area::new(0, 0, 3, 1), 1, &[(1, 0)]));
    assert_eq!(s.surface(1).unwrap().pixels, [1, 1, 2, 3]);
    // To another surface at two points, clipped at its edge.
    s.create(2, 3, 1).unwrap();
    assert!(s.copy(1, Area::new(2, 0, 2, 1), 2, &[(0, 0), (2, 0)]));
    assert_eq!(s.surface(2).unwrap().pixels, [2, 3, 2]);
    assert!(!s.copy(1, Area::new(0, 0, 1, 1), 9, &[(0, 0)]));
    // Several points: every copy uses the source as it was before the
    // first one (the first write overlaps the source).
    let mut s = state_with_surface(4, 1);
    s.blit(1, Area::new(0, 0, 4, 1), &[1, 2, 3, 4], 4);
    assert!(s.copy(1, Area::new(0, 0, 2, 1), 1, &[(1, 0), (2, 0)]));
    assert_eq!(s.surface(1).unwrap().pixels, [1, 1, 1, 2]);
}

#[test]
fn cache_round_trip_evict_and_limits() {
    let mut s = state_with_surface(4, 2);
    s.blit(1, Area::new(0, 0, 4, 2), &[1, 2, 3, 4, 5, 6, 7, 8], 4);
    assert!(s.to_cache(1, Area::new(1, 0, 2, 2), 1).unwrap());
    assert_eq!(s.cached(1), Some((2, 2, &[2, 3, 6, 7][..])));
    assert!(s.from_cache(1, 1, &[(2, 0), (3, 1)]).unwrap());
    assert_eq!(s.surface(1).unwrap().pixels, [1, 2, 2, 3, 5, 6, 6, 2]);
    s.evict(1);
    assert!(s.cached(1).is_none());
    assert!(s.from_cache(1, 1, &[(0, 0)]).is_err());
    // Slots are one-based, at most 4,096 with the small cache.
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 0).is_err());
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 4096).unwrap());
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 4097).is_err());
    s.set_small_cache(false);
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 25600).unwrap());
}

#[test]
fn cache_byte_limit_is_enforced() {
    let mut s = GfxState::new();
    s.create(1, 2048, 2048).unwrap(); // 16 MiB of pixels
    assert!(s.to_cache(1, Area::new(0, 0, 2048, 2048), 1).unwrap());
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 2).is_err());
    // Replacing the same slot frees the old entry first.
    assert!(s.to_cache(1, Area::new(0, 0, 2048, 2048), 1).unwrap());
    s.evict(1);
    assert!(s.to_cache(1, Area::new(0, 0, 1, 1), 2).unwrap());
}

#[test]
fn oversized_surface_is_refused() {
    let mut s = GfxState::new();
    assert!(s.create(1, 65535, 65535).is_err());
}

// ---- The channel, scripted (3.3.5) ----

/// Returns a fixed picture: Y = 128, U = 128 and V from `v`.
struct FakeH264 {
    calls: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    v: u8,
}

impl H264Decoder for FakeH264 {
    fn decode(&mut self, nal: &[u8]) -> crate::Result<Option<Yuv420Frame>> {
        self.calls.lock().unwrap().push(nal.to_vec());
        Ok(Some(Yuv420Frame {
            width: 16,
            height: 16,
            y: vec![128; 256],
            u: vec![128; 64],
            v: vec![self.v; 64],
            y_stride: 16,
            uv_stride: 8,
        }))
    }
}

/// Wraps graphics PDUs as an unencoded ZGFX SINGLE message.
fn zgfx_raw(pdus: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0xE0, 0x04];
    for p in pdus {
        v.extend_from_slice(p);
    }
    v
}

fn feed(d: &mut Drdynvc, msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = ChannelOut::default();
    d.process(msg, &mut out).unwrap();
    out.take()
}

/// DYNVC_DATA on channel 5 (MS-RDPEDYC 2.2.3.2); short enough for one PDU.
fn dvc_data(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30, 0x05];
    v.extend_from_slice(payload);
    v
}

fn fill_pdu(id: u16, bgr: [u8; 3], r: (u16, u16, u16, u16)) -> Vec<u8> {
    let mut body = id.to_le_bytes().to_vec();
    body.extend([bgr[0], bgr[1], bgr[2], 0xFF, 1, 0]);
    body.extend(rect(r.0, r.1, r.2, r.3));
    pdu(CMDID_SOLIDFILL, &body)
}

#[test]
fn scripted_session_caps_reset_surface_frame_ack() {
    let (channel, handle) = graphics(None);
    let mut d = Drdynvc::new(vec![Box::new(channel)]);
    feed(&mut d, &[0x50, 0x00, 0x03, 0x00]);
    // Create request: the response, then the caps advertise (3.3.5.18).
    let mut req = vec![0x10, 0x05];
    req.extend_from_slice(CHANNEL_NAME.as_bytes());
    req.push(0);
    let out = feed(&mut d, &req);
    assert_eq!(out[0], [0x10, 0x05, 0, 0, 0, 0]);
    assert_eq!(out[1], dvc_data(&caps_advertise(&advertised_caps(false))));

    let confirm = pdu(
        CMDID_CAPSCONFIRM,
        &hex("01 07 0A 00 04 00 00 00 A2 00 00 00"),
    );
    assert!(feed(&mut d, &dvc_data(&zgfx_raw(&[confirm]))).is_empty());
    let reset = zgfx_raw(&[reset_pdu(64, 32)]);
    // 340 bytes: larger than one DVC PDU only with headers; send as DATA_FIRST.
    let mut first = vec![0x24, 0x05];
    first.extend((reset.len() as u16).to_le_bytes());
    first.extend_from_slice(&reset);
    assert!(feed(&mut d, &first).is_empty());
    let create = pdu(CMDID_CREATESURFACE, &hex("01 00 40 00 20 00 20"));
    let map = pdu(
        CMDID_MAPSURFACETOOUTPUT,
        &hex("01 00 00 00 00 00 00 00 00 00 00 00"),
    );
    assert!(feed(&mut d, &dvc_data(&zgfx_raw(&[create, map]))).is_empty());

    let frame = zgfx_raw(&[
        pdu(CMDID_STARTFRAME, &hex("00 00 00 00 2A 00 00 00")),
        fill_pdu(1, [0x30, 0x20, 0x10], (2, 3, 6, 5)),
        pdu(CMDID_ENDFRAME, &hex("2A 00 00 00")),
    ]);
    let out = feed(&mut d, &dvc_data(&frame));
    // RDPGFX_FRAME_ACKNOWLEDGE_PDU: queue depth 0, frame 42, 1 decoded.
    assert_eq!(out, vec![dvc_data(&frame_acknowledge(0, 42, 1))]);

    let mut fb = crate::Framebuffer::new(64, 32);
    let mut dmg = Vec::new();
    assert!(!handle.present(&mut fb, &mut dmg));
    // The first present after the reset covers the whole output.
    assert_eq!(
        dmg,
        [crate::Damage {
            x: 0,
            y: 0,
            w: 64,
            h: 32
        }]
    );
    assert_eq!(fb.pixels[3 * 64 + 2], 0x0010_2030);
    assert_eq!(fb.pixels[4 * 64 + 5], 0x0010_2030);
    assert_eq!(fb.pixels[5 * 64 + 5], 0);

    // A frame followed by more PDUs in the same message reports them as
    // queued bytes; frames keep counting.
    let start = pdu(CMDID_STARTFRAME, &hex("00 00 00 00 2B 00 00 00"));
    let frame = zgfx_raw(&[pdu(CMDID_ENDFRAME, &hex("2A 00 00 00")), start.clone()]);
    let out = feed(&mut d, &dvc_data(&frame));
    assert_eq!(
        out,
        vec![dvc_data(&frame_acknowledge(start.len() as u32, 42, 2))]
    );
}

#[test]
fn channel_error_closes_only_graphics() {
    let (channel, _handle) = graphics(None);
    let mut d = Drdynvc::new(vec![Box::new(channel)]);
    let mut req = vec![0x10, 0x05];
    req.extend_from_slice(CHANNEL_NAME.as_bytes());
    req.push(0);
    feed(&mut d, &req);
    // A broken ZGFX stream is dropped; the channel stays open (no
    // DYNVC_CLOSE), or the session would never draw again.
    assert!(feed(&mut d, &dvc_data(&[0xE5, 0x04])).is_empty());
}

#[test]
fn a_bad_pdu_does_not_cost_the_frame_acknowledgement() {
    let (mut ch, _handle) = graphics(None);
    setup(&mut ch);
    let bad = pdu(CMDID_SOLIDFILL, &hex("00 00 00 00 00 00 05 00")); // rects missing
    let end = pdu(CMDID_ENDFRAME, &7u32.to_le_bytes());
    let sent = run(&mut ch, &[bad, end]);
    assert_eq!(sent.len(), 1, "one FrameAcknowledge");
    assert_eq!(u16::from_le_bytes([sent[0][0], sent[0][1]]), 0x000D);
    assert_eq!(
        u32::from_le_bytes(sent[0][12..16].try_into().unwrap()),
        7,
        "frameId"
    );
}

pub(super) fn wire(id: u16, codec: u16, dest: (u16, u16, u16, u16), data: &[u8]) -> Vec<u8> {
    let mut body = id.to_le_bytes().to_vec();
    body.extend(codec.to_le_bytes());
    body.push(PIXEL_FORMAT_XRGB_8888);
    body.extend(rect(dest.0, dest.1, dest.2, dest.3));
    body.extend((data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    pdu(CMDID_WIRETOSURFACE_1, &body)
}

pub(super) fn run(ch: &mut GraphicsChannel, pdus: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    ch.process(&zgfx_raw(pdus), &mut out).unwrap();
    out.take()
}

pub(super) fn setup(ch: &mut GraphicsChannel) {
    run(
        ch,
        &[
            reset_pdu(32, 16),
            pdu(CMDID_CREATESURFACE, &hex("01 00 20 00 10 00 20")),
            pdu(
                CMDID_MAPSURFACETOOUTPUT,
                &hex("01 00 00 00 00 00 00 00 00 00 00 00"),
            ),
        ],
    );
}

#[test]
fn wire_to_surface_uncompressed_and_planar() {
    let (mut ch, h) = graphics(None);
    setup(&mut ch);
    // Uncompressed 2x1 XRGB: B G R X.
    let raw = hex("01 02 03 00 0A 0B 0C FF");
    // Planar raw (no RLE, no alpha plane): R, G, B planes, rows bottom-up.
    let planar = hex("20 AA BB 11 22 99 88");
    let wrong = hex("01 02 03");
    let acks = run(
        &mut ch,
        &[
            wire(1, CODECID_UNCOMPRESSED, (4, 4, 6, 5), &raw),
            wire(1, CODECID_PLANAR, (0, 0, 2, 1), &planar),
            wire(1, CODECID_UNCOMPRESSED, (8, 8, 10, 9), &wrong),
            wire(1, CODECID_CAVIDEO, (10, 10, 12, 12), &[0; 8]),
            pdu(CMDID_ENDFRAME, &hex("01 00 00 00")),
        ],
    );
    assert_eq!(acks, vec![frame_acknowledge(0, 1, 1)]);
    let mut fb = crate::Framebuffer::new(32, 16);
    let mut dmg = Vec::new();
    h.present(&mut fb, &mut dmg);
    assert_eq!(fb.pixels[4 * 32 + 4], 0x0003_0201);
    assert_eq!(fb.pixels[4 * 32 + 5], 0x000C_0B0A);
    assert_eq!(fb.pixels[0], 0x00AA_1199);
    assert_eq!(fb.pixels[1], 0x00BB_2288);
    // The bad and the unsupported updates changed nothing.
    assert_eq!(fb.pixels[8 * 32 + 8], 0);
    assert_eq!(fb.pixels[10 * 32 + 10], 0);
}

/// A ClearCodec stream (MS-RDPEGFX 2.2.4.1) with residual and bands layers.
fn clear(residual: &[u8], bands: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0];
    v.extend((residual.len() as u32).to_le_bytes());
    v.extend((bands.len() as u32).to_le_bytes());
    v.extend(0u32.to_le_bytes());
    v.extend_from_slice(residual);
    v.extend_from_slice(bands);
    v
}

/// One-column band at (x, 0) down to `y_end`, black background.
fn clear_band(x: u16, y_end: u16, vbar: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [x, x, 0, y_end] {
        v.extend(n.to_le_bytes());
    }
    v.extend([0, 0, 0]);
    v.extend(hex(vbar));
    v
}

#[test]
fn wire_to_surface_clearcodec_caches_live_per_channel() {
    let (mut ch, h) = graphics(None);
    setup(&mut ch);
    let acks = run(
        &mut ch,
        &[
            wire(1, CODECID_UNCOMPRESSED, (7, 7, 8, 8), &hex("11 22 33 00")),
            // 4 x 4 at (4,4): two residual pixels, a Short V-Bar miss of one
            // pixel in a two-high band at column 2. (7,7) is not covered.
            wire(
                1,
                CODECID_CLEARCODEC,
                (4, 4, 8, 8),
                &clear(&hex("01 02 03 02"), &clear_band(2, 1, "00 01 0a 0b 0c")),
            ),
            // The next PDU hits Short V-Bar 0.
            wire(
                1,
                CODECID_CLEARCODEC,
                (0, 0, 2, 2),
                &clear(&[], &clear_band(0, 0, "00 40 00")),
            ),
            // An unknown surface still feeds the storages: V-Bar 2 ...
            wire(
                9,
                CODECID_CLEARCODEC,
                (0, 0, 1, 1),
                &clear(&[], &clear_band(0, 0, "00 01 04 05 06")),
            ),
            // ... which this PDU draws.
            wire(
                1,
                CODECID_CLEARCODEC,
                (1, 0, 2, 1),
                &clear(&[], &clear_band(0, 0, "02 80")),
            ),
            // Corrupt data fails this PDU only.
            wire(1, CODECID_CLEARCODEC, (0, 8, 4, 12), &hex("00 00 ff")),
            pdu(CMDID_ENDFRAME, &hex("01 00 00 00")),
        ],
    );
    assert_eq!(acks, vec![frame_acknowledge(0, 1, 1)]);
    let mut fb = crate::Framebuffer::new(32, 16);
    h.present(&mut fb, &mut Vec::new());
    let at = |x: usize, y: usize| fb.pixels[y * 32 + x];
    assert_eq!(at(4, 4), 0x0003_0201);
    assert_eq!(at(5, 4), 0x0003_0201);
    assert_eq!(at(6, 4), 0x000C_0B0A);
    assert_eq!(at(6, 5), 0);
    assert_eq!(at(7, 7), 0x0033_2211);
    assert_eq!(at(0, 0), 0x000C_0B0A);
    assert_eq!(at(1, 0), 0x0006_0504);
    // The channel keeps working after the corrupt PDU.
    run(
        &mut ch,
        &[
            wire(
                1,
                CODECID_CLEARCODEC,
                (2, 0, 3, 1),
                &clear(&[], &clear_band(0, 0, "01 80")),
            ),
            pdu(CMDID_ENDFRAME, &hex("02 00 00 00")),
        ],
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[2], 0x000C_0B0A);
}

#[test]
fn clearcodec_storage_resets_when_the_channel_closes() {
    let (mut ch, h) = graphics(None);
    setup(&mut ch);
    let miss = clear(&[], &clear_band(0, 0, "00 01 0a 0b 0c"));
    let hit = clear(&[], &clear_band(0, 0, "00 80"));
    let frame = |id: u32| pdu(CMDID_ENDFRAME, &(id).to_le_bytes());
    run(
        &mut ch,
        &[
            wire(1, CODECID_CLEARCODEC, (0, 0, 1, 1), &miss),
            wire(1, CODECID_CLEARCODEC, (1, 0, 2, 1), &hit),
            frame(1),
        ],
    );
    let mut fb = crate::Framebuffer::new(32, 16);
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[1], 0x000C_0B0A);
    // A new channel starts with empty storages: the same hit draws nothing.
    ch.closed();
    setup(&mut ch);
    run(
        &mut ch,
        &[wire(1, CODECID_CLEARCODEC, (1, 0, 2, 1), &hit), frame(2)],
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[1], 0);
}

#[test]
fn wire_to_surface_avc420_copies_regions_only() {
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let dec = FakeH264 {
        calls: calls.clone(),
        v: 200,
    };
    let (mut ch, h) = graphics(Some(Box::new(dec)));
    let mut out = DvcOut::default();
    ch.opened(&mut out).unwrap();
    assert_eq!(out.take(), vec![caps_advertise(&advertised_caps(true))]);
    setup(&mut ch);
    // destRect (8,0)-(24,16); one region (10,2)-(12,4) inside it and one
    // partly outside the decoded picture's right edge.
    let mut data = hex("02 00 00 00");
    data.extend(rect(10, 2, 12, 4));
    data.extend(rect(22, 14, 30, 20));
    data.extend(hex("16 64 16 64"));
    data.extend(hex("00 00 00 01 65 88"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC420, (8, 0, 24, 16), &data),
            pdu(CMDID_ENDFRAME, &hex("02 00 00 00")),
        ],
    );
    assert_eq!(*calls.lock().unwrap(), vec![hex("00 00 00 01 65 88")]);
    let mut fb = crate::Framebuffer::new(32, 16);
    let mut dmg = Vec::new();
    h.present(&mut fb, &mut dmg);
    let px = yuv_to_rgb(128, 128, 200);
    let set: Vec<usize> = (0..fb.pixels.len())
        .filter(|&i| fb.pixels[i] == px)
        .collect();
    assert_eq!(
        set,
        [
            2 * 32 + 10,
            2 * 32 + 11,
            3 * 32 + 10,
            3 * 32 + 11,
            14 * 32 + 22,
            14 * 32 + 23,
            15 * 32 + 22,
            15 * 32 + 23
        ]
    );
}

#[test]
fn avc420_regions_clip_to_dest_and_picture() {
    let dec = FakeH264 {
        calls: Default::default(),
        v: 60,
    };
    let (mut ch, h) = graphics(Some(Box::new(dec)));
    setup(&mut ch);
    // destRect (4,0)-(32,16) is wider than the 16x16 picture: the region
    // (16,1)-(26,2) keeps x 16..20 (picture columns 12..16).
    let mut wide = hex("01 00 00 00");
    wide.extend(rect(16, 1, 26, 2));
    wide.extend(hex("16 64 00 00 00 01"));
    // destRect (0,8)-(2,10): the region (1,9)-(8,16) keeps (1,9) only.
    let mut small = hex("01 00 00 00");
    small.extend(rect(1, 9, 8, 16));
    small.extend(hex("16 64 00 00 00 01"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC420, (4, 0, 32, 16), &wide),
            wire(1, CODECID_AVC420, (0, 8, 2, 10), &small),
            pdu(CMDID_ENDFRAME, &hex("04 00 00 00")),
        ],
    );
    let mut fb = crate::Framebuffer::new(32, 16);
    h.present(&mut fb, &mut Vec::new());
    let px = yuv_to_rgb(128, 128, 60);
    let set: Vec<usize> = (0..fb.pixels.len())
        .filter(|&i| fb.pixels[i] == px)
        .collect();
    assert_eq!(set, [32 + 16, 32 + 17, 32 + 18, 32 + 19, 9 * 32 + 1]);
}

#[test]
fn avc420_without_decoder_is_dropped_and_acked() {
    let (mut ch, _h) = graphics(None);
    setup(&mut ch);
    let mut data = hex("01 00 00 00");
    data.extend(rect(0, 0, 16, 16));
    data.extend(hex("16 64 00 00 00 01"));
    let acks = run(
        &mut ch,
        &[
            wire(1, CODECID_AVC420, (0, 0, 16, 16), &data),
            pdu(CMDID_ENDFRAME, &hex("03 00 00 00")),
        ],
    );
    assert_eq!(acks, vec![frame_acknowledge(0, 3, 1)]);
}

#[test]
fn caps_confirm_sets_cache_size() {
    let (mut ch, _h) = graphics(None);
    run(
        &mut ch,
        &[pdu(
            CMDID_CAPSCONFIRM,
            &hex("02 00 0A 00 04 00 00 00 20 00 00 00"),
        )],
    );
    assert_eq!(
        ch.confirmed(),
        Some(CapSet {
            version: CAPVERSION_10,
            flags: CAPS_FLAG_AVC_DISABLED
        })
    );
    setup(&mut ch);
    // Without SMALL_CACHE the 100 MB cache allows slot 25,600.
    let mut body = hex("01 00 00 00 00 00 00 00 00 00 00 64");
    body.extend(rect(0, 0, 1, 1));
    run(&mut ch, &[pdu(CMDID_SURFACETOCACHE, &body)]);
    assert!(ch.state().cached(25600).is_some());
}

#[test]
fn errors_are_protocol_errors() {
    match Zgfx::new().decompress(&[0xE7]) {
        Err(Error::Protocol(_)) => {}
        other => panic!("{other:?}"),
    }
}
