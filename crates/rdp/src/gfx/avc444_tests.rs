//! AVC444 / AVC444v2 tests (MS-RDPEGFX 2.2.4.5, 2.2.4.6, 3.3.8.3.2,
//! 3.3.8.3.3). Expected values are worked out by hand from the area
//! formulas B1 - B9 and the reverse filter.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::avc444::{Layout, yuv444};
use super::h264::{H264Decoder, Yuv420Frame, yuv_to_rgb};
use super::pdu::*;
use super::tests::{hex, pdu, rect, run, setup, wire};
use super::*;

/// A w x h picture with constant planes.
fn frame(w: usize, h: usize, y: u8, u: u8, v: u8) -> Yuv420Frame {
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    Yuv420Frame {
        width: w,
        height: h,
        y: vec![y; w * h],
        u: vec![u; cw * ch],
        v: vec![v; cw * ch],
        y_stride: w,
        uv_stride: cw,
    }
}

/// RFX_AVC420_METABLOCK plus bitstream (2.2.4.4).
fn avc420(regions: &[(u16, u16, u16, u16)], bitstream: &[u8]) -> Vec<u8> {
    let mut v = (regions.len() as u32).to_le_bytes().to_vec();
    for r in regions {
        v.extend(rect(r.0, r.1, r.2, r.3));
    }
    for _ in regions {
        v.extend([22, 100]);
    }
    v.extend_from_slice(bitstream);
    v
}

/// avc420EncodedBitstreamInfo, then the subframes.
fn avc444(lc: u32, first: &[u8], second: &[u8]) -> Vec<u8> {
    let cb = if lc == 2 { 0 } else { first.len() as u32 };
    let mut v = (cb | lc << 30).to_le_bytes().to_vec();
    v.extend_from_slice(first);
    v.extend_from_slice(second);
    v
}

// ---- Parsing (2.2.4.5, 2.2.4.6) ----

#[test]
fn parse_avc444_lc_and_subframes() {
    let luma = avc420(&[(0, 0, 16, 16)], &hex("00 00 00 01 65"));
    let chroma = avc420(&[(0, 0, 8, 8)], &hex("00 00 00 01 41"));
    assert_eq!(luma.len(), 0x13);
    // LC 0: cbAvc420EncodedBitstream1 = 0x13 in the low 30 bits.
    let mut both = hex("13 00 00 00");
    both.extend(&luma);
    both.extend(&chroma);
    match parse_avc444(&both).unwrap() {
        Avc444::Both { luma: l, chroma: c } => {
            assert_eq!(
                l.regions,
                [Rect16 {
                    left: 0,
                    top: 0,
                    right: 16,
                    bottom: 16
                }]
            );
            assert_eq!(l.bitstream, hex("00 00 00 01 65"));
            assert_eq!(
                c.regions,
                [Rect16 {
                    left: 0,
                    top: 0,
                    right: 8,
                    bottom: 8
                }]
            );
            assert_eq!(c.bitstream, hex("00 00 00 01 41"));
        }
        other => panic!("{other:?}"),
    }
    // LC 1 is bit 30.
    let mut one = hex("13 00 00 40");
    one.extend(&luma);
    match parse_avc444(&one).unwrap() {
        Avc444::Luma(l) => assert_eq!(l.bitstream, hex("00 00 00 01 65")),
        other => panic!("{other:?}"),
    }
    // LC 2 is bit 31, with cbAvc420EncodedBitstream1 zero.
    let mut two = hex("00 00 00 80");
    two.extend(&chroma);
    match parse_avc444(&two).unwrap() {
        Avc444::Chroma(c) => assert_eq!(c.bitstream, hex("00 00 00 01 41")),
        other => panic!("{other:?}"),
    }
    assert_eq!(two, avc444(2, &chroma, &[]));
    // LC 3 and a first subframe longer than the data are errors.
    let mut three = hex("13 00 00 C0");
    three.extend(&luma);
    assert!(parse_avc444(&three).is_err());
    let mut long = hex("14 00 00 00");
    long.extend(&luma);
    assert!(parse_avc444(&long).is_err());
    assert!(parse_avc444(&hex("13 00")).is_err());
}

// ---- View combination (3.3.8.3.2, 3.3.8.3.3) ----

#[test]
fn avc444_v1_combination() {
    let mut main = frame(16, 32, 50, 100, 100);
    let mut aux = frame(16, 32, 0, 0, 0);
    // B4/B5: odd rows. U444(3, 5) is aux Y row 2, V444(3, 5) row 10.
    aux.y[2 * 16 + 3] = 77;
    aux.y[10 * 16 + 3] = 88;
    // Second macroblock row: U444(7, 17) is aux Y row 16, V444 row 24.
    aux.y[16 * 16 + 7] = 55;
    aux.y[24 * 16 + 7] = 44;
    // B6/B7: U444(5, 4) = auxU(2, 2), V444(5, 4) = auxV(2, 2).
    aux.u[2 * 8 + 2] = 99;
    aux.v[2 * 8 + 2] = 66;
    assert_eq!(yuv444(&main, &aux, Layout::V1, 3, 5), (50, 77, 88));
    assert_eq!(yuv444(&main, &aux, Layout::V1, 7, 17), (50, 55, 44));
    assert_eq!(yuv444(&main, &aux, Layout::V1, 5, 4), (50, 99, 66));
    // U444(4, 4): 4 * 60 - U(5,4) 99 - U(4,5) 10 - U(5,5) 20 = 111,
    // 51 away from 60, so the reversed value is used.
    main.u[2 * 8 + 2] = 60;
    aux.y[2 * 16 + 4] = 10;
    aux.y[2 * 16 + 5] = 20;
    assert_eq!(yuv444(&main, &aux, Layout::V1, 4, 4).1, 111);
    // U444(0, 0): 400 - auxU(0,0) 100 - Y(0,0) 100 - Y(1,0) 90 = 110, only
    // 10 away: the main view's 100 stays.
    aux.u[0] = 100;
    aux.y[0] = 100;
    aux.y[1] = 90;
    assert_eq!(yuv444(&main, &aux, Layout::V1, 0, 0).1, 100);
    // V444(0, 0): 400 - auxV(0,0) 90 - Y(0,8) 90 - Y(1,8) 89 = 131, 31
    // away: used. V444(2, 0): 400 - 90 - 90 - 90 = 130, exactly 30: not.
    aux.v[0] = 90;
    aux.y[8 * 16] = 90;
    aux.y[8 * 16 + 1] = 89;
    aux.v[1] = 90;
    aux.y[8 * 16 + 2] = 90;
    aux.y[8 * 16 + 3] = 90;
    assert_eq!(yuv444(&main, &aux, Layout::V1, 0, 0).2, 131);
    assert_eq!(yuv444(&main, &aux, Layout::V1, 2, 0).2, 100);
}

#[test]
fn avc444_v2_combination() {
    let mut main = frame(16, 16, 50, 100, 100);
    let mut aux = frame(16, 16, 0, 0, 0);
    // B4/B5: odd columns. U444(3, 5) = auxY(1, 5), V444 = auxY(8 + 1, 5).
    aux.y[5 * 16 + 1] = 77;
    aux.y[5 * 16 + 9] = 88;
    // B6/B7: column 4x of odd rows. U444(4, 5) = auxU(1, 2),
    // V444(4, 5) = auxU(4 + 1, 2).
    aux.u[2 * 8 + 1] = 99;
    aux.u[2 * 8 + 5] = 66;
    // B8/B9: column 4x + 2. U444(6, 5) = auxV(1, 2), V444 = auxV(5, 2).
    aux.v[2 * 8 + 1] = 55;
    aux.v[2 * 8 + 5] = 44;
    assert_eq!(yuv444(&main, &aux, Layout::V2, 3, 5), (50, 77, 88));
    assert_eq!(yuv444(&main, &aux, Layout::V2, 4, 5), (50, 99, 66));
    assert_eq!(yuv444(&main, &aux, Layout::V2, 6, 5), (50, 55, 44));
    // U444(4, 4): 4 * 60 - U(5,4) auxY(2,4) 10 - U(4,5) 99 - U(5,5)
    // auxY(2,5) 20 = 111.
    main.u[2 * 8 + 2] = 60;
    aux.y[4 * 16 + 2] = 10;
    aux.y[5 * 16 + 2] = 20;
    assert_eq!(yuv444(&main, &aux, Layout::V2, 4, 4).1, 111);
    // V444(4, 4): 400 - auxY(10,4) 0 - auxU(5,2) 66 - auxY(10,5) 0 = 334,
    // clamped to 255.
    assert_eq!(yuv444(&main, &aux, Layout::V2, 4, 4).2, 255);
    // The same planes read as AVC444 give other samples.
    assert_ne!(yuv444(&main, &aux, Layout::V1, 3, 5), (50, 77, 88));
}

// ---- The channel with a scripted decoder ----

/// Returns queued pictures in order and records each access unit.
struct Scripted {
    frames: Arc<Mutex<VecDeque<Yuv420Frame>>>,
    calls: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl H264Decoder for Scripted {
    fn decode(&mut self, nal: &[u8]) -> crate::Result<Option<Yuv420Frame>> {
        self.calls.lock().unwrap().push(nal.to_vec());
        Ok(self.frames.lock().unwrap().pop_front())
    }
}

type Script = (
    Arc<Mutex<VecDeque<Yuv420Frame>>>,
    Arc<Mutex<Vec<Vec<u8>>>>,
    GraphicsChannel,
    GfxHandle,
);

fn scripted() -> Script {
    let frames = Arc::new(Mutex::new(VecDeque::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (mut ch, h) = graphics(Some(Box::new(Scripted {
        frames: frames.clone(),
        calls: calls.clone(),
    })));
    setup(&mut ch);
    (frames, calls, ch, h)
}

fn confirm(ch: &mut GraphicsChannel, version: u32, flags: u32) {
    let mut body = version.to_le_bytes().to_vec();
    body.extend(4u32.to_le_bytes());
    body.extend(flags.to_le_bytes());
    run(ch, &[pdu(CMDID_CAPSCONFIRM, &body)]);
}

fn end(id: u32) -> Vec<u8> {
    pdu(CMDID_ENDFRAME, &id.to_le_bytes())
}

#[test]
fn avc444_channel_combines_and_keeps_views() {
    let (frames, calls, mut ch, h) = scripted();
    confirm(&mut ch, CAPVERSION_107, CAPS_FLAG_SMALL_CACHE);
    let mut fb = crate::Framebuffer::new(32, 16);
    let dest = (0, 0, 16, 16);
    // LC 0: the main view paints (0,0)-(16,16) as 4:2:0, the chroma view
    // repaints (0,0)-(2,2) as 4:4:4. (1, 0) takes U, V from auxU/auxV(0, 0).
    frames
        .lock()
        .unwrap()
        .extend([frame(16, 16, 90, 128, 128), frame(16, 16, 128, 200, 60)]);
    let luma = avc420(&[(0, 0, 16, 16)], &hex("00 00 00 01 65"));
    let chroma = avc420(&[(0, 0, 2, 2)], &hex("00 00 00 01 41"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, dest, &avc444(0, &luma, &chroma)),
            end(1),
        ],
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [hex("00 00 00 01 65"), hex("00 00 00 01 41")]
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[1], yuv_to_rgb(90, 200, 60));
    assert_eq!(fb.pixels[5 * 32 + 5], yuv_to_rgb(90, 128, 128));
    assert_eq!(fb.pixels[20], 0, "outside destRect");

    // LC 2: a new chroma view, combined with the kept main view (Y 90).
    frames
        .lock()
        .unwrap()
        .push_back(frame(16, 16, 128, 30, 220));
    let chroma = avc420(&[(4, 0, 6, 2)], &hex("00 00 00 01 42"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, dest, &avc444(2, &chroma, &[])),
            end(2),
        ],
    );
    assert_eq!(calls.lock().unwrap().len(), 3);
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[5], yuv_to_rgb(90, 30, 220));
    assert_eq!(fb.pixels[1], yuv_to_rgb(90, 200, 60), "outside the region");

    // LC 1: a new main view (Y 200), painted as 4:2:0 and kept.
    frames
        .lock()
        .unwrap()
        .push_back(frame(16, 16, 200, 128, 128));
    let luma = avc420(&[(8, 0, 10, 2)], &hex("00 00 00 01 25"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, dest, &avc444(1, &luma, &[])),
            end(3),
        ],
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[9], yuv_to_rgb(200, 128, 128));
    assert_eq!(fb.pixels[5], yuv_to_rgb(90, 30, 220));

    // LC 2 again combines with the newest main view.
    frames
        .lock()
        .unwrap()
        .push_back(frame(16, 16, 128, 30, 220));
    let chroma = avc420(&[(12, 0, 14, 2)], &hex("00 00 00 01 43"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, dest, &avc444(2, &chroma, &[])),
            end(4),
        ],
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[13], yuv_to_rgb(200, 30, 220));

    // AVC444v2: (15, 0) has an odd column, so U and V come from the aux
    // luma plane's halves (40 left, 230 right), not from auxU/auxV.
    let mut aux = frame(16, 16, 40, 128, 128);
    for row in aux.y.chunks_mut(16) {
        row[8..].fill(230);
    }
    frames.lock().unwrap().push_back(aux);
    let chroma = avc420(&[(15, 0, 16, 1)], &hex("00 00 00 01 44"));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444V2, dest, &avc444(2, &chroma, &[])),
            end(5),
        ],
    );
    h.present(&mut fb, &mut Vec::new());
    assert_eq!(fb.pixels[15], yuv_to_rgb(200, 40, 230));
    assert_eq!(calls.lock().unwrap().len(), 6);
}

#[test]
fn avc444_chroma_without_matching_main_view_is_dropped() {
    let (frames, calls, mut ch, h) = scripted();
    let chroma = avc420(&[(0, 0, 16, 16)], &hex("00 00 00 01 41"));
    frames
        .lock()
        .unwrap()
        .push_back(frame(16, 16, 128, 30, 220));
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, (0, 0, 16, 16), &avc444(2, &chroma, &[])),
            end(1),
        ],
    );
    // A main view at another origin does not match either.
    let luma = avc420(&[(16, 0, 17, 1)], &hex("00 00 00 01 65"));
    frames
        .lock()
        .unwrap()
        .extend([frame(16, 16, 90, 128, 128), frame(16, 16, 128, 30, 220)]);
    run(
        &mut ch,
        &[
            wire(1, CODECID_AVC444, (16, 0, 32, 16), &avc444(1, &luma, &[])),
            wire(1, CODECID_AVC444, (0, 0, 16, 16), &avc444(2, &chroma, &[])),
            end(2),
        ],
    );
    assert_eq!(calls.lock().unwrap().len(), 3);
    let mut fb = crate::Framebuffer::new(32, 16);
    h.present(&mut fb, &mut Vec::new());
    let painted: Vec<usize> = (0..fb.pixels.len())
        .filter(|&i| fb.pixels[i] != 0)
        .collect();
    assert_eq!(painted, [16], "only the luma pixel");
}

#[test]
fn caps_confirm_routes_avc_codecs() {
    let a420 = avc420(&[(0, 0, 1, 1)], &hex("00 00 00 01 65"));
    let a444 = avc444(1, &a420, &[]);
    // (version, flags, AVC420 decoded, AVC444 decoded)
    let cases = [
        (CAPVERSION_81, CAPS_FLAG_AVC420_ENABLED, true, false),
        (CAPVERSION_81, 0, false, false),
        (CAPVERSION_8, CAPS_FLAG_AVC420_ENABLED, false, false),
        (CAPVERSION_10, CAPS_FLAG_AVC_DISABLED, false, false),
        (CAPVERSION_10, 0, true, true),
        (CAPVERSION_107, CAPS_FLAG_SCALEDMAP_DISABLE, true, true),
    ];
    for (version, flags, want420, want444) in cases {
        let (frames, calls, mut ch, _h) = scripted();
        confirm(&mut ch, version, flags);
        frames
            .lock()
            .unwrap()
            .extend([frame(16, 16, 1, 128, 128), frame(16, 16, 1, 128, 128)]);
        run(&mut ch, &[wire(1, CODECID_AVC420, (0, 0, 16, 16), &a420)]);
        assert_eq!(
            calls.lock().unwrap().len(),
            want420 as usize,
            "{version:#x} AVC420"
        );
        calls.lock().unwrap().clear();
        for codec in [CODECID_AVC444, CODECID_AVC444V2] {
            run(&mut ch, &[wire(1, codec, (0, 0, 16, 16), &a444)]);
        }
        assert_eq!(
            calls.lock().unwrap().len(),
            2 * want444 as usize,
            "{version:#x} AVC444"
        );
    }
}
