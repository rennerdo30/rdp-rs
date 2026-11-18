use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::geometry::{self, Area, GeometryPacket, MappedGeometry, Rect32};
use super::pdu::{self, Notification, PresentationRequest, StartPresentation, VideoData};
use super::*;
use crate::dvc::{DvcOut, DynamicChannel};
use crate::framebuffer::{Damage, Framebuffer};
use crate::gfx::h264::{H264Decoder, Yuv420Frame};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- MS-RDPEVOR 4.1 - 4.4 ----

/// MS-RDPEVOR 4.1: TSMM_PRESENTATION_REQUEST (START), with the trailing
/// reserved byte Windows sends after cbSize.
const START_EXAMPLE: &[u8] = include_bytes!("testdata/rdpevor_4_1.bin");

/// MS-RDPEVOR 4.3: TSMM_VIDEO_DATA with one 779-byte keyframe sample.
const DATA_EXAMPLE: &[u8] = include_bytes!("testdata/rdpevor_4_3.bin");

/// MS-RDPEVOR 4.4: TSMM_PRESENTATION_REQUEST (STOP).
const STOP_EXAMPLE: &str = "44000000 01000000 03010200 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00";

/// The spec's sample (MS-RDPEVOR 4.3): a 480 x 244 H.264 keyframe.
fn spec_sample() -> Vec<u8> {
    let (_, body) = pdu::split_header(DATA_EXAMPLE).unwrap();
    VideoData::parse(body).unwrap().sample.to_vec()
}

#[test]
fn vor_start_presentation_example() {
    let msg = START_EXAMPLE.to_vec();
    assert_eq!(msg.len(), 106, "105 bytes and the reserved byte");
    let (kind, body) = pdu::split_header(&msg).unwrap();
    assert_eq!(kind, pdu::PACKET_TYPE_PRESENTATION_REQUEST);
    assert_eq!(body.len(), 105 - 8);
    let PresentationRequest::Start(s) = pdu::parse_presentation_request(body).unwrap() else {
        panic!("not a start");
    };
    assert_eq!(s.presentation_id, 3);
    assert_eq!(s.version, 1);
    assert_eq!((s.source_width, s.source_height), (480, 244));
    assert_eq!((s.scaled_width, s.scaled_height), (480, 244));
    assert_eq!(s.timestamp_offset, 66_609_445_540);
    assert_eq!(s.geometry_mapping_id, 0x8000_7ABA_0004_0222);
    assert_eq!(s.video_subtype, pdu::MFVIDEOFORMAT_H264);
    assert_eq!(s.extra.len(), 37);
    assert!(s.extra.starts_with(&[0, 0, 0, 1, 0x67, 0x42]), "SPS first");
    // FrameRate and AverageBitrateKbps are reserved: written as zero.
    let mut expected = msg[..105].to_vec();
    expected[11] = 0;
    expected[12..14].copy_from_slice(&[0, 0]);
    assert_eq!(s.encode(), expected);
}

#[test]
fn vor_presentation_response_example() {
    assert_eq!(
        pdu::presentation_response(3),
        hex("0C000000 02000000 03000000")
    );
}

#[test]
fn vor_video_data_example() {
    let msg = DATA_EXAMPLE.to_vec();
    assert_eq!(msg.len(), 820, "819 bytes and the reserved byte");
    let (kind, body) = pdu::split_header(&msg).unwrap();
    assert_eq!(kind, pdu::PACKET_TYPE_VIDEO_DATA);
    let d = VideoData::parse(body).unwrap();
    assert_eq!(d.presentation_id, 3);
    assert_eq!(
        d.flags,
        pdu::DATA_FLAG_HAS_TIMESTAMPS | pdu::DATA_FLAG_KEYFRAME
    );
    assert!(d.keyframe() && d.has_timestamp());
    assert_eq!(d.timestamp, 444_103);
    assert_eq!(d.duration, 0);
    assert_eq!((d.packet_index, d.packets_in_sample), (1, 1));
    assert_eq!(d.sample_number, 1);
    assert_eq!(d.sample.len(), 779);
    assert_eq!(d.encode(), msg[..819].to_vec());
}

#[test]
fn vor_stop_presentation_example() {
    let msg = hex(STOP_EXAMPLE);
    let (kind, body) = pdu::split_header(&msg).unwrap();
    assert_eq!(kind, pdu::PACKET_TYPE_PRESENTATION_REQUEST);
    assert_eq!(
        pdu::parse_presentation_request(body).unwrap(),
        PresentationRequest::Stop { presentation_id: 3 }
    );
    // The short form (only the valid fields) parses the same.
    let short = pdu::stop_presentation(3);
    let (_, body) = pdu::split_header(&short).unwrap();
    assert_eq!(
        pdu::parse_presentation_request(body).unwrap(),
        PresentationRequest::Stop { presentation_id: 3 }
    );
}

#[test]
fn vor_malformed_lengths_are_errors() {
    // cbSize past the message.
    let mut msg = START_EXAMPLE.to_vec();
    msg[0] = 0x70;
    assert!(pdu::split_header(&msg).is_err());
    // cbSize shorter than the header.
    assert!(pdu::split_header(&hex("04000000 01000000")).is_err());
    // cbExtra past the message.
    let msg = START_EXAMPLE.to_vec();
    let (_, body) = pdu::split_header(&msg).unwrap();
    let mut cut = body.to_vec();
    cut.truncate(body.len() - 1);
    assert!(pdu::parse_presentation_request(&cut).is_err());
    // A packet index of 0, or past PacketsInSample.
    for (index, count) in [(0u16, 1u16), (3, 2)] {
        let d = VideoData {
            presentation_id: 1,
            version: 1,
            flags: 0,
            timestamp: 0,
            duration: 0,
            packet_index: index,
            packets_in_sample: count,
            sample_number: 1,
            sample: b"x",
        }
        .encode();
        let (_, body) = pdu::split_header(&d).unwrap();
        assert!(VideoData::parse(body).is_err(), "{index}/{count}");
    }
}

#[test]
fn vor_client_notifications_round_trip() {
    let net = pdu::client_notification(7, Notification::NetworkError);
    assert_eq!(net, hex("10000000 03000000 07010000 00000000"));
    for (n, want) in [
        (Notification::NetworkError, Notification::NetworkError),
        (Notification::Unrestricted, Notification::Unrestricted),
        (Notification::FrameRate(12), Notification::FrameRate(12)),
        (Notification::FrameRate(0), Notification::FrameRate(1)),
        (Notification::FrameRate(60), Notification::FrameRate(30)),
    ] {
        let m = pdu::client_notification(7, n);
        let (kind, body) = pdu::split_header(&m).unwrap();
        assert_eq!(kind, pdu::PACKET_TYPE_CLIENT_NOTIFICATION);
        assert_eq!(pdu::parse_client_notification(body).unwrap(), (7, want));
    }
    // Frame rate override: cbData 16 and the structure of 2.2.1.5.
    assert_eq!(
        pdu::client_notification(2, Notification::FrameRate(15)),
        hex("20000000 03000000 02020000 10000000 02000000 0F000000 00000000 00000000")
    );
}

// ---- MS-RDPEGT 4.1, 4.2 ----

/// MS-RDPEGT 4.1 (raw bytes; the annotated TopLevelTop and TopLevelBottom
/// differ from them, the raw bytes are used).
const GEOMETRY_EXAMPLE: &str =
    "78000000 01000000 22020400 BA7A0080 01000000 00000000 E2010300 00000000
    10000000 8A000000 F0010000 7E010000 23010000 72000000 78040000 CA020000
    02000000 30000000 20000000 01000000 01000000 00000000 00000000 00000000
    E0010000 F4000000 00000000 00000000 E0010000 F4000000 00";

const GEOMETRY_CLEAR_EXAMPLE: &str =
    "48000000 01000000 22020400 BA7A0080 02000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00";

#[test]
fn egt_update_example() {
    let msg = hex(GEOMETRY_EXAMPLE);
    assert_eq!(msg.len(), 121);
    let GeometryPacket::Update(g) = geometry::parse(&msg).unwrap() else {
        panic!("not an update");
    };
    assert_eq!(g.mapping_id, 0x8000_7ABA_0004_0222);
    assert_eq!(g.top_level_id, 0x301E2);
    assert_eq!(g.tracked, Rect32::new(16, 138, 496, 382));
    assert_eq!(g.top_level, Rect32::new(291, 114, 1144, 714));
    assert_eq!(g.bound, Rect32::new(0, 0, 480, 244));
    assert_eq!(g.rects, vec![Rect32::new(0, 0, 480, 244)]);
    // 480 x 244 at (291 + 16, 114 + 138) on the desktop.
    assert_eq!(g.placement(), Rect32::new(307, 252, 787, 496));
    assert_eq!(
        g.visible(1920, 1080),
        vec![Area {
            x: 307,
            y: 252,
            w: 480,
            h: 244
        }]
    );
    assert_eq!(geometry::encode_update(&g), msg[..120].to_vec());
}

#[test]
fn egt_clear_example() {
    let msg = hex(GEOMETRY_CLEAR_EXAMPLE);
    assert_eq!(
        geometry::parse(&msg).unwrap(),
        GeometryPacket::Clear {
            mapping_id: 0x8000_7ABA_0004_0222
        }
    );
    assert_eq!(
        geometry::parse(&geometry::encode_clear(7)).unwrap(),
        GeometryPacket::Clear { mapping_id: 7 }
    );
}

fn mapping(tracked: Rect32, top_level: Rect32, rects: Vec<Rect32>) -> MappedGeometry {
    MappedGeometry {
        mapping_id: 1,
        top_level_id: 0,
        tracked,
        top_level,
        bound: Rect32::default(),
        rects,
    }
}

#[test]
fn egt_visible_parts_are_clipped_to_the_video_and_the_desktop() {
    // A 200 x 100 video at (50, 40) in a window at (-30, 10): desktop
    // (20, 50) - (220, 150). Two visible parts: the left half, and a strip
    // reaching past the video's right edge (clipped to it).
    let g = mapping(
        Rect32::new(50, 40, 250, 140),
        Rect32::new(-30, 10, 800, 600),
        vec![Rect32::new(0, 0, 100, 100), Rect32::new(150, 0, 400, 20)],
    );
    assert_eq!(g.placement(), Rect32::new(20, 50, 220, 150));
    let a = |x, y, w, h| Area { x, y, w, h };
    assert_eq!(
        g.visible(1000, 1000),
        vec![a(20, 50, 100, 100), a(170, 50, 50, 20)]
    );
    // A desktop of 150 x 120 cuts both.
    assert_eq!(g.visible(150, 120), vec![a(20, 50, 100, 70)]);
    // Off the desktop to the left: x stays at 0.
    let g = mapping(
        Rect32::new(0, 0, 100, 50),
        Rect32::new(-60, 0, 100, 50),
        vec![Rect32::new(0, 0, 100, 50)],
    );
    assert_eq!(g.visible(800, 600), vec![a(0, 0, 40, 50)]);
    // Nothing visible: no rectangles.
    let g = mapping(Rect32::new(0, 0, 100, 50), Rect32::default(), vec![]);
    assert!(g.visible(800, 600).is_empty());
}

#[test]
fn egt_region_outside_rcbound_is_ignored_in_window_tracking_mode() {
    let mut g = mapping(
        Rect32::new(0, 0, 100, 100),
        Rect32::new(0, 0, 500, 500),
        vec![Rect32::new(200, 200, 300, 300)],
    );
    g.bound = Rect32::new(0, 0, 100, 100);
    g.top_level_id = 5;
    let GeometryPacket::Update(p) = geometry::parse(&geometry::encode_update(&g)).unwrap() else {
        panic!()
    };
    assert!(p.rects.is_empty(), "region ignored");
    // Outside window tracking mode rcBound is ignored.
    g.top_level_id = 0;
    let GeometryPacket::Update(p) = geometry::parse(&geometry::encode_update(&g)).unwrap() else {
        panic!()
    };
    assert_eq!(p.rects.len(), 1);
}

#[test]
fn egt_malformed_regions_are_errors() {
    let g = mapping(
        Rect32::new(0, 0, 10, 10),
        Rect32::default(),
        vec![Rect32::new(0, 0, 10, 10)],
    );
    let msg = geometry::encode_update(&g);
    // nCount larger than the buffer holds.
    let mut m = msg.clone();
    m[72 + 8] = 2;
    assert!(geometry::parse(&m).is_err());
    // dwSize other than 32.
    let mut m = msg.clone();
    m[72] = 31;
    assert!(geometry::parse(&m).is_err());
    // cbGeometryData past the message, or below the clear form.
    let mut m = msg.clone();
    m[0] += 1;
    assert!(geometry::parse(&m).is_err());
    assert!(geometry::parse(&hex("10000000 01000000 01000000 00000000")).is_err());
    // A huge tracked rectangle.
    let huge = mapping(Rect32::new(0, 0, 100_000, 10), Rect32::default(), vec![]);
    assert!(geometry::parse(&geometry::encode_update(&huge)).is_err());
}

// ---- H.264 helpers ----

#[test]
fn access_unit_adds_the_sequence_header_and_a_closing_delimiter() {
    let sample = [0, 0, 0, 1, 0x65, 1, 2, 3];
    assert_eq!(
        access_unit(&[0, 0, 0, 1, 0x67, 9], &sample),
        [&[0, 0, 0, 1, 0x67, 9][..], &sample, &AUD].concat()
    );
    // A leading delimiter is dropped; one later in the sample stays.
    let led = [0, 0, 0, 1, 9, 0x10, 0, 0, 1, 0x65, 7, 0, 0, 0, 1, 9, 0x10];
    assert_eq!(
        access_unit(&[], &led),
        [&led[6..], &AUD[..]].concat(),
        "leading AUD stripped"
    );
    // The spec's sample has its delimiter after the SEI: kept.
    let s = spec_sample();
    assert_eq!(access_unit(&[], &s), [&s[..], &AUD[..]].concat());
    // A sample of only a delimiter decodes nothing but the closing one.
    assert_eq!(access_unit(&[], &[0, 0, 1, 9, 0xf0]), AUD.to_vec());
}

#[test]
fn bt601_limited_range_colours() {
    assert_eq!(rgb601(16, 128, 128), 0x000000);
    assert_eq!(rgb601(235, 128, 128), 0xFFFFFF);
    assert_eq!(rgb601(126, 128, 128), 0x808080);
    // BT.601 red, green and blue (studio range; the 8-bit codes round, so
    // within 2 per channel).
    let near =
        |a: u32, b: u32| (0..3).all(|i| ((a >> (8 * i)) as u8).abs_diff((b >> (8 * i)) as u8) <= 2);
    for (yuv, rgb) in [
        ((81, 90, 240), 0xFF0000),
        ((145, 54, 34), 0x00FF00),
        ((41, 240, 110), 0x0000FF),
    ] {
        let got = rgb601(yuv.0, yuv.1, yuv.2);
        assert!(near(got, rgb), "{yuv:?}: {got:06x}");
    }
    // Not the full-range BT.709 formula of the graphics pipeline.
    assert_ne!(
        rgb601(16, 128, 128),
        crate::gfx::h264::yuv_to_rgb(16, 128, 128)
    );
}

// ---- Presentation lifecycle with a mock decoder ----

/// Returns a `w` x `h` NV12 picture per access unit, its luma the number of
/// pictures decoded so far times 20 (grey levels), and logs the input.
#[derive(Clone)]
struct Mock {
    inputs: Arc<Mutex<Vec<Vec<u8>>>>,
    size: (usize, usize),
    fail: Arc<Mutex<bool>>,
}

impl Mock {
    fn new(w: usize, h: usize) -> Mock {
        Mock {
            inputs: Arc::default(),
            size: (w, h),
            fail: Arc::default(),
        }
    }

    fn luma(n: usize) -> u8 {
        (16 + 20 * n) as u8
    }
}

impl H264Decoder for Mock {
    fn decode(&mut self, au: &[u8]) -> crate::Result<Option<Yuv420Frame>> {
        if *self.fail.lock().unwrap() {
            return Err(crate::Error::Protocol("mock decode error".into()));
        }
        let mut inputs = self.inputs.lock().unwrap();
        inputs.push(au.to_vec());
        let (w, h) = self.size;
        let cw = w.div_ceil(2);
        Ok(Some(Yuv420Frame {
            width: w,
            height: h,
            y: vec![Mock::luma(inputs.len()); w * h],
            uv: vec![128; 2 * cw * h.div_ceil(2)],
            y_stride: w,
            uv_stride: 2 * cw,
            ..Default::default()
        }))
    }
}

struct Rig {
    control: Box<dyn DynamicChannel>,
    data: Box<dyn DynamicChannel>,
    geometry: Box<dyn DynamicChannel>,
    handle: VideoHandle,
    mock: Mock,
    made: Arc<Mutex<usize>>,
}

fn rig(w: usize, h: usize) -> Rig {
    let mock = Mock::new(w, h);
    let made = Arc::new(Mutex::new(0));
    let (m, n) = (mock.clone(), made.clone());
    let factory: crate::H264Factory = Arc::new(move || {
        *n.lock().unwrap() += 1;
        Some(Box::new(m.clone()) as Box<dyn H264Decoder>)
    });
    let (mut channels, handle) = video(factory);
    let geometry = channels.pop().unwrap();
    let data = channels.pop().unwrap();
    let control = channels.pop().unwrap();
    assert_eq!(control.name(), CONTROL_CHANNEL);
    assert_eq!(data.name(), DATA_CHANNEL);
    assert_eq!(geometry.name(), geometry::CHANNEL_NAME);
    let mut r = Rig {
        control,
        data,
        geometry,
        handle,
        mock,
        made,
    };
    r.control.opened(&mut DvcOut::default()).unwrap();
    r
}

fn start(id: u8, w: u32, h: u32, mapping: u64, extra: &[u8]) -> Vec<u8> {
    StartPresentation {
        presentation_id: id,
        version: 1,
        source_width: w,
        source_height: h,
        scaled_width: w,
        scaled_height: h,
        timestamp_offset: 0,
        geometry_mapping_id: mapping,
        video_subtype: pdu::MFVIDEOFORMAT_H264,
        extra: extra.to_vec(),
    }
    .encode()
}

fn packet(id: u8, sample: u32, index: u16, count: u16, ts_ms: Option<u64>, data: &[u8]) -> Vec<u8> {
    VideoData {
        presentation_id: id,
        version: 1,
        flags: if ts_ms.is_some() {
            pdu::DATA_FLAG_HAS_TIMESTAMPS
        } else {
            0
        },
        timestamp: ts_ms.unwrap_or(0) * 10_000,
        duration: 0,
        packet_index: index,
        packets_in_sample: count,
        sample_number: sample,
        sample: data,
    }
    .encode()
}

fn control(r: &mut Rig, msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    r.control.process(msg, &mut out).unwrap();
    out.take()
}

fn tick(r: &mut Rig) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    r.control.tick(&mut out).unwrap();
    out.take()
}

fn data_at(r: &Rig, msg: &[u8], now: Instant) {
    lock(&r.handle.0).data(msg, now).unwrap();
}

#[test]
fn start_answers_once_and_stop_ends_the_presentation() {
    let mut r = rig(16, 16);
    assert_eq!(
        control(&mut r, &start(3, 16, 16, 9, &[])),
        vec![pdu::presentation_response(3)]
    );
    assert_eq!(*r.made.lock().unwrap(), 1, "decoder made at start");
    assert_eq!(r.handle.active(), 1);
    // A second start for the running id is ignored (3.2.5.1).
    assert!(control(&mut r, &start(3, 16, 16, 9, &[])).is_empty());
    assert_eq!(*r.made.lock().unwrap(), 1);
    // Stop ends it; a second stop is ignored.
    assert!(control(&mut r, &pdu::stop_presentation(3)).is_empty());
    assert_eq!(r.handle.active(), 0);
    assert!(control(&mut r, &pdu::stop_presentation(3)).is_empty());
    // The id can start again.
    assert_eq!(control(&mut r, &start(3, 16, 16, 9, &[])).len(), 1);
    assert_eq!(r.handle.stats().presentations, 2);
}

#[test]
fn start_without_h264_decoder_or_size_is_not_answered() {
    let mut r = rig(16, 16);
    let mut wrong = start(1, 16, 16, 9, &[]);
    wrong[48] ^= 0xff; // VideoSubtypeId
    assert!(control(&mut r, &wrong).is_empty());
    assert!(control(&mut r, &start(2, 0, 16, 9, &[])).is_empty());
    assert!(control(&mut r, &start(3, 16, 9000, 9, &[])).is_empty());
    assert_eq!(r.handle.active(), 0);
    // No decoder on this machine: no response (3.3.3).
    let (mut channels, handle) = video(Arc::new(|| None));
    let mut out = DvcOut::default();
    channels[0]
        .process(&start(4, 16, 16, 9, &[]), &mut out)
        .unwrap();
    assert!(out.is_empty());
    assert_eq!(handle.active(), 0);
}

#[test]
fn malformed_control_message_is_an_error() {
    let mut r = rig(16, 16);
    let mut msg = start(1, 16, 16, 9, &[]);
    msg[0] = 0xff;
    assert!(r.control.process(&msg, &mut DvcOut::default()).is_err());
    // Another packet type with a valid header is ignored.
    assert!(control(&mut r, &pdu::presentation_response(1)).is_empty());
}

#[test]
fn packets_are_reassembled_and_decoded_with_the_sequence_header() {
    let mut r = rig(16, 16);
    let sps = [0, 0, 0, 1, 0x67, 0xAA];
    control(&mut r, &start(1, 16, 16, 9, &sps));
    let t = Instant::now();
    data_at(&r, &packet(1, 1, 1, 3, Some(0), &[0, 0, 0, 1, 0x65, 1]), t);
    data_at(&r, &packet(1, 1, 2, 3, Some(0), &[2, 3]), t);
    assert!(r.mock.inputs.lock().unwrap().is_empty(), "not complete yet");
    data_at(&r, &packet(1, 1, 3, 3, Some(0), &[4]), t);
    data_at(&r, &packet(1, 2, 1, 1, Some(33), &[0, 0, 1, 0x41, 9]), t);
    let inputs = r.mock.inputs.lock().unwrap().clone();
    assert_eq!(
        inputs,
        vec![
            [&sps[..], &[0, 0, 0, 1, 0x65, 1, 2, 3, 4], &AUD].concat(),
            [&[0, 0, 1, 0x41, 9][..], &AUD].concat(),
        ]
    );
    assert_eq!(r.handle.stats().decoded, 2);
    assert!(tick(&mut r).is_empty(), "nothing lost");
}

#[test]
fn lost_packets_drop_the_sample_and_ask_for_a_keyframe() {
    let mut r = rig(16, 16);
    control(&mut r, &start(1, 16, 16, 9, &[]));
    let t = Instant::now();
    data_at(&r, &packet(1, 1, 1, 2, None, &[1]), t);
    // Packet 2 of sample 1 never comes; sample 2 starts.
    data_at(&r, &packet(1, 2, 1, 1, None, &[2]), t);
    assert_eq!(r.mock.inputs.lock().unwrap().len(), 1, "only sample 2");
    let notes = tick(&mut r);
    assert_eq!(
        notes,
        vec![pdu::client_notification(1, Notification::NetworkError)]
    );
    // Within a second, no second notification.
    data_at(
        &r,
        &packet(1, 5, 2, 2, None, &[3]),
        t + Duration::from_millis(500),
    );
    assert!(tick(&mut r).is_empty());
    // A gap in sample numbers after that second.
    data_at(
        &r,
        &packet(1, 9, 1, 1, None, &[4]),
        t + Duration::from_millis(1500),
    );
    assert_eq!(tick(&mut r).len(), 1);
    assert_eq!(
        r.mock.inputs.lock().unwrap().len(),
        2,
        "the gap's sample still decodes"
    );
    // A decode error asks again.
    *r.mock.fail.lock().unwrap() = true;
    data_at(
        &r,
        &packet(1, 10, 1, 1, None, &[5]),
        t + Duration::from_secs(3),
    );
    assert_eq!(
        tick(&mut r),
        vec![pdu::client_notification(1, Notification::NetworkError)]
    );
}

#[test]
fn data_for_unknown_presentations_is_dropped() {
    let r = rig(16, 16);
    data_at(&r, &packet(4, 1, 1, 1, None, &[1]), Instant::now());
    assert!(r.mock.inputs.lock().unwrap().is_empty());
    // A malformed data message is an error (it closes the data channel).
    let mut msg = packet(4, 1, 1, 1, None, &[1]);
    msg[0] = 0xff;
    assert!(lock(&r.handle.0).data(&msg, Instant::now()).is_err());
}

/// A 640 x 480 desktop filled with `fill`.
fn desktop(fill: u32) -> Framebuffer {
    let mut fb = Framebuffer::new(640, 480);
    fb.pixels.fill(fill);
    fb
}

fn geometry_at(r: &mut Rig, mapping: u64, x: i32, y: i32, w: i32, h: i32, rects: Vec<Rect32>) {
    let g = MappedGeometry {
        mapping_id: mapping,
        top_level_id: 0,
        tracked: Rect32::new(0, 0, w, h),
        top_level: Rect32::new(x, y, x + w, y + h),
        bound: Rect32::default(),
        rects,
    };
    r.geometry
        .process(&geometry::encode_update(&g), &mut DvcOut::default())
        .unwrap();
}

fn grey(n: usize) -> u32 {
    rgb601(Mock::luma(n), 128, 128)
}

#[test]
fn frames_are_painted_at_their_time_into_the_visible_parts() {
    let mut r = rig(8, 4);
    control(&mut r, &start(1, 8, 4, 9, &[]));
    // Shown 16 x 8 (scaled x2) at (100, 50); the right half is covered.
    geometry_at(&mut r, 9, 100, 50, 16, 8, vec![Rect32::new(0, 0, 8, 8)]);
    let t0 = Instant::now();
    for (n, ms) in [(1, 0), (2, 500), (3, 1000)] {
        data_at(&r, &packet(1, n, 1, 1, Some(ms), &[n as u8]), t0);
    }
    let mut fb = desktop(0x123456);
    let mut damage = Vec::new();
    r.handle.present(&mut fb, &mut damage, 0, t0);
    assert_eq!(
        damage,
        vec![Damage {
            x: 100,
            y: 50,
            w: 8,
            h: 8
        }]
    );
    assert_eq!(fb.pixels[50 * 640 + 100], grey(1));
    assert_eq!(fb.pixels[57 * 640 + 107], grey(1));
    assert_eq!(
        fb.pixels[50 * 640 + 108],
        0x123456,
        "covered part untouched"
    );
    assert_eq!(fb.pixels[49 * 640 + 100], 0x123456);
    // Not due yet: nothing painted.
    damage.clear();
    r.handle
        .present(&mut fb, &mut damage, 0, t0 + Duration::from_millis(400));
    assert!(damage.is_empty());
    // Both later frames due: the newest is shown, the other skipped.
    r.handle
        .present(&mut fb, &mut damage, 0, t0 + Duration::from_millis(1000));
    assert_eq!(fb.pixels[50 * 640 + 100], grey(3));
    let s = r.handle.stats();
    assert_eq!((s.decoded, s.presented, s.skipped), (3, 2, 1));
}

#[test]
fn frames_are_scaled_to_the_tracked_rectangle() {
    let mut r = rig(4, 2);
    control(&mut r, &start(1, 4, 2, 9, &[]));
    geometry_at(&mut r, 9, 0, 0, 8, 4, vec![Rect32::new(0, 0, 8, 4)]);
    // A picture whose luma rises left to right: the mock's luma is
    // replaced after decoding.
    let t = Instant::now();
    data_at(&r, &packet(1, 1, 1, 1, None, &[1]), t);
    {
        let mut st = lock(&r.handle.0);
        let q = &mut st.presentations[0].queue[0].frame;
        q.y = vec![20, 60, 100, 140, 20, 60, 100, 140];
    }
    let mut fb = desktop(0);
    r.handle.present(&mut fb, &mut Vec::new(), 0, t);
    let row: Vec<u32> = fb.pixels[640..648].to_vec();
    let want: Vec<u32> = [20, 20, 60, 60, 100, 100, 140, 140]
        .iter()
        .map(|&y| rgb601(y, 128, 128))
        .collect();
    assert_eq!(row, want);
}

#[test]
fn graphics_repaints_under_the_video_are_painted_over_again() {
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    geometry_at(&mut r, 9, 10, 10, 8, 8, vec![Rect32::new(0, 0, 8, 8)]);
    let t = Instant::now();
    data_at(&r, &packet(1, 1, 1, 1, None, &[1]), t);
    let mut fb = desktop(0);
    r.handle.present(&mut fb, &mut Vec::new(), 0, t);
    // The graphics pipeline paints (0, 0) - (14, 14) black.
    for y in 0..14 {
        fb.pixels[y * 640..y * 640 + 14].fill(0);
    }
    let mut damage = vec![Damage {
        x: 0,
        y: 0,
        w: 14,
        h: 14,
    }];
    r.handle.present(&mut fb, &mut damage, 0, t);
    assert_eq!(
        damage[1..],
        [Damage {
            x: 10,
            y: 10,
            w: 4,
            h: 4
        }],
        "only the overlap"
    );
    assert_eq!(fb.pixels[10 * 640 + 10], grey(1));
    assert_eq!(fb.pixels[13 * 640 + 13], grey(1));
    // Damage before `from` is not the graphics': not repainted.
    let mut damage = vec![Damage {
        x: 0,
        y: 0,
        w: 14,
        h: 14,
    }];
    r.handle.present(&mut fb, &mut damage, 1, t);
    assert_eq!(damage.len(), 1);
}

#[test]
fn stop_clear_and_moves_restore_the_picture_underneath() {
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    geometry_at(&mut r, 9, 10, 10, 8, 8, vec![Rect32::new(0, 0, 8, 8)]);
    let t = Instant::now();
    data_at(&r, &packet(1, 1, 1, 1, None, &[1]), t);
    let mut fb = desktop(0);
    r.handle.present(&mut fb, &mut Vec::new(), 0, t);
    assert!(r.handle.take_restore().is_empty());
    // Moved: the old place is restored, the new one painted in full.
    geometry_at(&mut r, 9, 30, 10, 8, 8, vec![Rect32::new(0, 0, 8, 8)]);
    assert_eq!(
        r.handle.take_restore(),
        vec![Damage {
            x: 10,
            y: 10,
            w: 8,
            h: 8
        }]
    );
    let mut damage = Vec::new();
    r.handle.present(&mut fb, &mut damage, 0, t);
    assert_eq!(
        damage,
        vec![Damage {
            x: 30,
            y: 10,
            w: 8,
            h: 8
        }]
    );
    // The same geometry again changes nothing.
    geometry_at(&mut r, 9, 30, 10, 8, 8, vec![Rect32::new(0, 0, 8, 8)]);
    assert!(r.handle.take_restore().is_empty());
    // Stop: the video's place is restored.
    control(&mut r, &pdu::stop_presentation(1));
    assert_eq!(
        r.handle.take_restore(),
        vec![Damage {
            x: 30,
            y: 10,
            w: 8,
            h: 8
        }]
    );
    // Clear: restored again (the presentation is gone, harmless), then
    // a clear for an unknown mapping is ignored.
    r.geometry
        .process(&geometry::encode_clear(9), &mut DvcOut::default())
        .unwrap();
    assert_eq!(r.handle.take_restore().len(), 1);
    r.geometry
        .process(&geometry::encode_clear(9), &mut DvcOut::default())
        .unwrap();
    assert!(r.handle.take_restore().is_empty());
}

#[test]
fn closing_the_control_channel_ends_presentations() {
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    control(&mut r, &start(2, 8, 8, 10, &[]));
    assert_eq!(r.handle.active(), 2);
    r.control.closed();
    assert_eq!(r.handle.active(), 0);
    // Closing the geometry channel forgets the mappings.
    geometry_at(&mut r, 9, 0, 0, 8, 8, vec![Rect32::new(0, 0, 8, 8)]);
    r.handle
        .present(&mut desktop(0), &mut Vec::new(), 0, Instant::now());
    r.geometry.closed();
    assert_eq!(r.handle.take_restore().len(), 1);
    assert!(lock(&r.handle.0).geometries.is_empty());
}

#[test]
fn at_most_max_presentations_run() {
    let mut r = rig(8, 8);
    for id in 0..MAX_PRESENTATIONS as u8 + 2 {
        control(&mut r, &start(id, 8, 8, 9, &[]));
    }
    assert_eq!(r.handle.active(), MAX_PRESENTATIONS);
}

#[test]
fn the_queue_drops_the_oldest_frames() {
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    let t = Instant::now();
    // Frames 200 ms apart, all arriving at once: only MAX_QUEUED wait.
    for n in 1..=MAX_QUEUED as u32 + 3 {
        data_at(
            &r,
            &packet(1, n, 1, 1, Some(200 * u64::from(n - 1)), &[1]),
            t,
        );
    }
    let st = lock(&r.handle.0);
    assert_eq!(st.presentations[0].queue.len(), MAX_QUEUED);
    assert_eq!(st.stats.skipped, 3);
}

#[test]
fn late_and_jumping_timestamps_reanchor_the_clock() {
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    let t0 = Instant::now();
    data_at(&r, &packet(1, 1, 1, 1, Some(1000), &[1]), t0);
    // 100 ms of stream arriving 1 s later: re-anchored, due at arrival.
    let t1 = t0 + Duration::from_secs(1);
    data_at(&r, &packet(1, 2, 1, 1, Some(1100), &[1]), t1);
    // A jump of 10 s ahead: re-anchored too.
    data_at(&r, &packet(1, 3, 1, 1, Some(11_100), &[1]), t1);
    // On time: due 50 ms after the anchor.
    data_at(&r, &packet(1, 4, 1, 1, Some(11_150), &[1]), t1);
    let st = lock(&r.handle.0);
    let due: Vec<Instant> = st.presentations[0].queue.iter().map(|q| q.due).collect();
    assert_eq!(due, vec![t0, t1, t1, t1 + Duration::from_millis(50)]);
}

#[test]
fn rate_governor_asks_for_fewer_frames_then_lifts_the_limit() {
    let mut g = RateGovernor::default();
    let t = Instant::now();
    let interval = Some(Duration::from_millis(33));
    let slow = Duration::from_millis(80);
    let mut sent = Vec::new();
    for i in 0..60 {
        if let Some(n) = g.observe(slow, interval, t + Duration::from_millis(33 * i)) {
            sent.push(n);
        }
    }
    assert_eq!(
        sent,
        vec![Notification::FrameRate(12)],
        "once, after warm-up"
    );
    // The decoder becomes fast; the server sends 12 fps.
    let fast = Duration::from_millis(5);
    let later = t + Duration::from_secs(10);
    let mut sent = Vec::new();
    for i in 0..60 {
        if let Some(n) = g.observe(
            fast,
            Some(Duration::from_millis(83)),
            later + Duration::from_millis(83 * i),
        ) {
            sent.push(n);
        }
    }
    assert_eq!(sent, vec![Notification::Unrestricted]);
    // A decoder that keeps up never asks.
    let mut g = RateGovernor::default();
    assert!((0..100).all(|i| {
        g.observe(fast, interval, t + Duration::from_millis(33 * i))
            .is_none()
    }));
}

#[test]
fn slow_decoding_sends_a_frame_rate_override() {
    // Through the channels: a decoder that takes longer than the frame
    // interval. The mock is instant, so the governor is fed directly.
    let mut r = rig(8, 8);
    control(&mut r, &start(1, 8, 8, 9, &[]));
    let t = Instant::now();
    let n = {
        let mut st = lock(&r.handle.0);
        let p = &mut st.presentations[0];
        (0..40)
            .filter_map(|i| {
                p.rate.observe(
                    Duration::from_millis(100),
                    Some(Duration::from_millis(33)),
                    t + Duration::from_millis(33 * i),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(n, vec![Notification::FrameRate(10)]);
    lock(&r.handle.0).queue_notification(1, n[0]);
    assert_eq!(
        tick(&mut r),
        vec![pdu::client_notification(1, Notification::FrameRate(10))]
    );
}

#[test]
fn channels_open_through_drdynvc_by_name() {
    use crate::channel::{ChannelOut, StaticChannel};
    let r = rig(8, 8);
    let mut dvc = crate::dvc::Drdynvc::new(vec![r.control, r.data, r.geometry]);
    let mut out = ChannelOut::default();
    // Capabilities, then a create for each name (MS-RDPEDYC 2.2.2.1).
    dvc.process(&[0x50, 0x00, 0x01, 0x00], &mut out).unwrap();
    for (id, name) in [
        (3u8, CONTROL_CHANNEL),
        (4, DATA_CHANNEL),
        (5, geometry::CHANNEL_NAME),
    ] {
        let mut msg = vec![0x10, id];
        msg.extend_from_slice(name.as_bytes());
        msg.push(0);
        let mut out = ChannelOut::default();
        dvc.process(&msg, &mut out).unwrap();
        let sent = out.take();
        // DYNVC_CREATE_RSP with CreationStatus 0.
        assert_eq!(sent.len(), 1, "{name}");
        assert_eq!(&sent[0][2..], &[0, 0, 0, 0], "{name} accepted");
    }
}

#[test]
fn restored_areas_come_back_from_the_graphics_output() {
    use crate::gfx::surface::{Area as GArea, GfxState};
    let mut st = GfxState::new();
    st.reset(64, 32);
    st.create(1, 64, 32).unwrap();
    st.map(1, 0, 0);
    st.fill(1, 0x00AB_CDEF, &[GArea::new(0, 0, 64, 32)]);
    st.compose();
    let mut fb = Framebuffer::new(0, 0);
    st.present(&mut fb, &mut Vec::new());
    // Video painted over part of it; then restored.
    fb.pixels[5 * 64 + 5] = 0x111111;
    st.restore(Damage {
        x: 4,
        y: 4,
        w: 4,
        h: 4,
    });
    let mut damage = Vec::new();
    st.present(&mut fb, &mut damage);
    assert_eq!(
        damage,
        vec![Damage {
            x: 4,
            y: 4,
            w: 4,
            h: 4
        }]
    );
    assert_eq!(fb.pixels[5 * 64 + 5], 0x00AB_CDEF);
}
