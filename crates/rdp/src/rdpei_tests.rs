//! Tests for the touch and pen input channel (MS-RDPEI). Section 4 of the
//! spec has only geometry pictures, no PDU bytes; the byte vectors here are
//! the inline examples of section 2.2.2 plus PDUs built by hand from the
//! field tables of 2.2.3.

use std::time::Duration;

use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::dvc::Drdynvc;

fn enc<T: Copy>(f: fn(&mut Vec<u8>, T), v: T) -> Vec<u8> {
    let mut out = Vec::new();
    f(&mut out, v);
    out
}

fn dec<T>(f: fn(&mut Reader) -> Result<T>, b: &[u8]) -> T {
    let mut r = Reader::new(b);
    let v = f(&mut r).unwrap();
    assert_eq!(r.remaining(), 0, "{b:02x?} fully consumed");
    v
}

#[test]
fn spec_examples_of_section_2_2_2() {
    // MS-RDPEI 2.2.2.1 to 2.2.2.5, the "For example" sentences.
    assert_eq!(enc(put_two_byte_unsigned, 0x1A1B), [0x9A, 0x1B]);
    assert_eq!(enc(put_two_byte_signed, -0x1A1B), [0xDA, 0x1B]);
    assert_eq!(enc(put_two_byte_signed, -0x0002), [0x42]);
    assert_eq!(enc(put_four_byte_unsigned, 0x001A_1B1C), [0x9A, 0x1B, 0x1C]);
    assert_eq!(enc(put_four_byte_signed, -0x001A_1B1C), [0xBA, 0x1B, 0x1C]);
    assert_eq!(enc(put_four_byte_signed, -0x0000_0002), [0x22]);
    assert_eq!(
        enc(put_eight_byte_unsigned, 0x001A_1B1C_1D1E_1F2A),
        [0xDA, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x2A]
    );
    assert_eq!(dec(read_two_byte_unsigned, &[0x9A, 0x1B]), 0x1A1B);
    assert_eq!(dec(read_two_byte_signed, &[0xDA, 0x1B]), -0x1A1B);
    assert_eq!(dec(read_two_byte_signed, &[0x42]), -2);
    assert_eq!(dec(read_four_byte_unsigned, &[0x9A, 0x1B, 0x1C]), 0x1A_1B1C);
    assert_eq!(dec(read_four_byte_signed, &[0xBA, 0x1B, 0x1C]), -0x1A_1B1C);
    assert_eq!(dec(read_four_byte_signed, &[0x22]), -2);
    assert_eq!(
        dec(
            read_eight_byte_unsigned,
            &[0xDA, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x2A]
        ),
        0x001A_1B1C_1D1E_1F2A
    );
}

#[test]
fn two_byte_unsigned_boundaries() {
    for (v, bytes) in [
        (0u16, &[0x00][..]),
        (0x7F, &[0x7F]),
        (0x80, &[0x80, 0x80]),
        (0x7FFF, &[0xFF, 0xFF]),
    ] {
        assert_eq!(enc(put_two_byte_unsigned, v), bytes, "{v:#x}");
        assert_eq!(dec(read_two_byte_unsigned, bytes), v);
    }
    // Out of range clamps to the maximum.
    assert_eq!(enc(put_two_byte_unsigned, 0x8000), [0xFF, 0xFF]);
    assert_eq!(enc(put_two_byte_unsigned, u16::MAX), [0xFF, 0xFF]);
}

#[test]
fn two_byte_signed_boundaries() {
    for (v, bytes) in [
        (0i16, &[0x00][..]),
        (0x3F, &[0x3F]),
        (-0x3F, &[0x7F]),
        (0x40, &[0x80, 0x40]),
        (-0x40, &[0xC0, 0x40]),
        (0x3FFF, &[0xBF, 0xFF]),
        (-0x3FFF, &[0xFF, 0xFF]),
        (-90, &[0xC0, 0x5A]),
    ] {
        assert_eq!(enc(put_two_byte_signed, v), bytes, "{v}");
        assert_eq!(dec(read_two_byte_signed, bytes), v);
    }
    assert_eq!(enc(put_two_byte_signed, i16::MIN), [0xFF, 0xFF]);
    assert_eq!(enc(put_two_byte_signed, i16::MAX), [0xBF, 0xFF]);
    // Negative zero decodes as zero.
    assert_eq!(dec(read_two_byte_signed, &[0x40]), 0);
}

#[test]
fn four_byte_unsigned_boundaries() {
    for (v, bytes) in [
        (0u32, &[0x00][..]),
        (0x3F, &[0x3F]),
        (0x40, &[0x40, 0x40]),
        (0x3FFF, &[0x7F, 0xFF]),
        (0x4000, &[0x80, 0x40, 0x00]),
        (0x3F_FFFF, &[0xBF, 0xFF, 0xFF]),
        (0x40_0000, &[0xC0, 0x40, 0x00, 0x00]),
        (0x3FFF_FFFF, &[0xFF, 0xFF, 0xFF, 0xFF]),
    ] {
        assert_eq!(enc(put_four_byte_unsigned, v), bytes, "{v:#x}");
        assert_eq!(dec(read_four_byte_unsigned, bytes), v);
    }
    assert_eq!(enc(put_four_byte_unsigned, u32::MAX), [0xFF; 4]);
}

#[test]
fn four_byte_signed_boundaries() {
    for (v, bytes) in [
        (0i32, &[0x00][..]),
        (0x1F, &[0x1F]),
        (-0x1F, &[0x3F]),
        (0x20, &[0x40, 0x20]),
        (-0x20, &[0x60, 0x20]),
        (0x1FFF, &[0x5F, 0xFF]),
        (-0x1FFF, &[0x7F, 0xFF]),
        (0x2000, &[0x80, 0x20, 0x00]),
        (0x1F_FFFF, &[0x9F, 0xFF, 0xFF]),
        (-0x1F_FFFF, &[0xBF, 0xFF, 0xFF]),
        (0x20_0000, &[0xC0, 0x20, 0x00, 0x00]),
        (0x1FFF_FFFF, &[0xDF, 0xFF, 0xFF, 0xFF]),
        (-0x1FFF_FFFF, &[0xFF, 0xFF, 0xFF, 0xFF]),
    ] {
        assert_eq!(enc(put_four_byte_signed, v), bytes, "{v:#x}");
        assert_eq!(dec(read_four_byte_signed, bytes), v);
    }
    assert_eq!(enc(put_four_byte_signed, i32::MIN), [0xFF; 4]);
    assert_eq!(
        enc(put_four_byte_signed, i32::MAX),
        [0xDF, 0xFF, 0xFF, 0xFF]
    );
}

#[test]
fn eight_byte_unsigned_boundaries() {
    // Each length n holds 5 + 8 (n - 1) bits; check the last value of every
    // length and the first of the next.
    for n in 1..=8u32 {
        let max = (1u64 << (5 + 8 * (n - 1))) - 1;
        let b = enc(put_eight_byte_unsigned, max);
        assert_eq!(b.len(), n as usize, "{max:#x}");
        assert_eq!(b[0] >> 5, (n - 1) as u8, "length code of {max:#x}");
        assert_eq!(b[0] & 0x1F, 0x1F);
        assert!(b[1..].iter().all(|&x| x == 0xFF));
        assert_eq!(dec(read_eight_byte_unsigned, &b), max);
        if n < 8 {
            let b = enc(put_eight_byte_unsigned, max + 1);
            assert_eq!(b.len(), n as usize + 1, "{:#x}", max + 1);
            assert_eq!(dec(read_eight_byte_unsigned, &b), max + 1);
        }
    }
    assert_eq!(enc(put_eight_byte_unsigned, 0), [0x00]);
    assert_eq!(enc(put_eight_byte_unsigned, 0x20), [0x20, 0x20]);
    assert_eq!(enc(put_eight_byte_unsigned, 1000), [0x23, 0xE8]);
    assert_eq!(enc(put_eight_byte_unsigned, u64::MAX), [0xFF; 8]);
}

#[test]
fn truncated_integers_are_errors() {
    assert!(read_two_byte_unsigned(&mut Reader::new(&[0x80])).is_err());
    assert!(read_two_byte_signed(&mut Reader::new(&[0xC0])).is_err());
    assert!(read_four_byte_unsigned(&mut Reader::new(&[0xC0, 0, 0])).is_err());
    assert!(read_four_byte_signed(&mut Reader::new(&[0x80, 0])).is_err());
    assert!(read_eight_byte_unsigned(&mut Reader::new(&[0xE0, 0, 0, 0, 0, 0, 0])).is_err());
    assert!(read_eight_byte_unsigned(&mut Reader::new(&[])).is_err());
}

#[test]
fn cs_ready_bytes() {
    // RDPINPUT_CS_READY_PDU (MS-RDPEI 2.2.3.2): 16 bytes.
    assert_eq!(
        cs_ready_pdu(0, PROTOCOL_V300, 10),
        [
            0x02, 0x00, 0x10, 0x00, 0x00, 0x00, // header: CS_READY, 16
            0x00, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x03, 0x00, // protocolVersion 3.0.0
            0x0A, 0x00, // maxTouchContacts
        ]
    );
}

fn down(id: u8, x: i32, y: i32) -> TouchContact {
    TouchContact {
        contact_id: id,
        x,
        y,
        flags: CONTACT_FLAG_DOWN | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT,
        ..Default::default()
    }
}

#[test]
fn touch_event_bytes() {
    let frame = TouchFrame {
        contacts: vec![down(0, 100, 200)],
    };
    assert_eq!(
        touch_event_pdu(0, &[(0, &frame)]),
        [
            0x03, 0x00, 0x11, 0x00, 0x00, 0x00, // header: TOUCH, 17
            0x00, // encodeTime 0
            0x01, // frameCount 1
            0x01, // contactCount 1
            0x00, // frameOffset 0
            0x00, // contactId
            0x00, // fieldsPresent
            0x40, 0x64, // x 100
            0x40, 0xC8, // y 200
            0x19, // DOWN | INRANGE | INCONTACT
        ]
    );
}

#[test]
fn pen_event_bytes() {
    let frame = PenFrame {
        contacts: vec![PenContact {
            device_id: 0,
            x: -5,
            y: 0x3000,
            flags: CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT,
            pen_flags: Some(PEN_FLAG_ERASER_PRESSED),
            pressure: Some(1024),
            rotation: Some(359),
            tilt_x: Some(-45),
            tilt_y: Some(90),
        }],
    };
    assert_eq!(
        pen_event_pdu(5, &[(1000, &frame)]),
        [
            0x08, 0x00, 0x1A, 0x00, 0x00, 0x00, // header: PEN, 26
            0x05, // encodeTime 5 ms
            0x01, // frameCount
            0x01, // contactCount
            0x23, 0xE8, // frameOffset 1000 us
            0x00, // deviceId
            0x1F, // fieldsPresent: all five
            0x25, // x -5
            0x80, 0x30, 0x00, // y 0x3000
            0x1A, // UPDATE | INRANGE | INCONTACT
            0x02, // penFlags: eraser
            0x44, 0x00, // pressure 1024
            0x81, 0x67, // rotation 359
            0x6D, // tiltX -45
            0x80, 0x5A, // tiltY 90
        ]
    );
}

#[test]
fn touch_round_trip_with_all_fields() {
    let a = TouchFrame {
        contacts: vec![
            TouchContact {
                contact_id: 7,
                x: -0x1FFF_FFFF,
                y: 0x1FFF_FFFF,
                flags: CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT,
                rect: Some((-0x3FFF, -1, 0x40, 0x3FFF)),
                orientation: Some(359),
                pressure: Some(512),
            },
            down(255, 0, 0),
        ],
    };
    let b = TouchFrame {
        contacts: vec![TouchContact {
            flags: CONTACT_FLAG_UP,
            ..down(7, 3, 4)
        }],
    };
    let pdu = touch_event_pdu(0x3FFF_FFFF, &[(0, &a), (u32::MAX as u64 + 1, &b)]);
    let p = parse_touch_event(&pdu).unwrap();
    assert_eq!(p.encode_time, 0x3FFF_FFFF);
    assert_eq!(
        p.frames,
        vec![
            (0, a.contacts.clone()),
            (u32::MAX as u64 + 1, b.contacts.clone())
        ]
    );
    // Every prefix is an error, never a panic.
    for n in 0..pdu.len() {
        assert!(parse_touch_event(&pdu[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn pen_round_trip_and_optional_fields() {
    let all_absent = PenContact {
        x: 10,
        y: 20,
        flags: CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE,
        ..Default::default()
    };
    let some = PenContact {
        pen_flags: Some(PEN_FLAG_BARREL_PRESSED | PEN_FLAG_INVERTED),
        tilt_y: Some(-90),
        ..all_absent.clone()
    };
    let f = PenFrame {
        contacts: vec![all_absent, some],
    };
    let pdu = pen_event_pdu(0, &[(42, &f)]);
    let p = parse_pen_event(&pdu).unwrap();
    assert_eq!(p.frames, vec![(42, f.contacts.clone())]);
    for n in 0..pdu.len() {
        assert!(parse_pen_event(&pdu[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn out_of_range_contact_values_are_clamped() {
    let c = PenContact {
        flags: CONTACT_FLAG_UP,
        pressure: Some(5000),
        rotation: Some(400),
        tilt_x: Some(120),
        tilt_y: Some(-300),
        ..Default::default()
    };
    let p = parse_pen_event(&pen_event_pdu(0, &[(0, &PenFrame { contacts: vec![c] })])).unwrap();
    let c = &p.frames[0].1[0];
    assert_eq!(
        (c.pressure, c.rotation, c.tilt_x, c.tilt_y),
        (Some(1024), Some(40), Some(90), Some(-90))
    );
    let t = TouchContact {
        orientation: Some(360),
        pressure: Some(2000),
        ..down(1, 0, 0)
    };
    let p = parse_touch_event(&touch_event_pdu(
        0,
        &[(0, &TouchFrame { contacts: vec![t] })],
    ))
    .unwrap();
    assert_eq!(
        (p.frames[0].1[0].orientation, p.frames[0].1[0].pressure),
        (Some(0), Some(1024))
    );
}

#[test]
fn contact_flag_combinations() {
    assert_eq!(
        VALID_CONTACT_FLAGS,
        [0x04, 0x24, 0x02, 0x22, 0x19, 0x1A, 0x0C, 0x0A]
    );
    assert!(valid_contact_flags(0x19));
    assert!(!valid_contact_flags(CONTACT_FLAG_DOWN));
    assert!(!valid_contact_flags(
        CONTACT_FLAG_DOWN | CONTACT_FLAG_INRANGE
    ));
    assert!(!valid_contact_flags(0));
}

#[test]
fn dismiss_hovering_bytes() {
    assert_eq!(
        dismiss_hovering_pdu(0xFF),
        [0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0xFF]
    );
}

fn sc_ready(version: u32, features: Option<u32>) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(EVENTID_SC_READY);
    v.put_u32(if features.is_some() { 14 } else { 10 });
    v.put_u32(version);
    if let Some(f) = features {
        v.put_u32(f);
    }
    v
}

fn header(event: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(event);
    v.put_u32(6);
    v
}

fn test_clock() -> (Clock, Arc<Mutex<Instant>>) {
    let t = Arc::new(Mutex::new(Instant::now()));
    let t2 = t.clone();
    (Box::new(move || *t2.lock().unwrap()), t)
}

fn process(ch: &mut TouchInput, msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    ch.process(msg, &mut out).unwrap();
    out.take()
}

fn tick(ch: &mut TouchInput) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    ch.tick(&mut out).unwrap();
    out.take()
}

#[test]
fn version_negotiation() {
    for (server, features, answer, pen) in [
        (PROTOCOL_V100, None, PROTOCOL_V100, false),
        (PROTOCOL_V101, None, PROTOCOL_V101, false),
        (PROTOCOL_V200, None, PROTOCOL_V200, true),
        (
            PROTOCOL_V300,
            Some(SC_READY_MULTIPEN_INJECTION_SUPPORTED),
            PROTOCOL_V300,
            true,
        ),
        (PROTOCOL_V300, None, PROTOCOL_V300, true),
        (0x0004_0000, Some(0), PROTOCOL_V300, true),
        (0, None, PROTOCOL_V100, false),
    ] {
        let (mut ch, h) = touch_input(TouchOptions::default());
        assert!(!h.is_ready());
        let sent = process(&mut ch, &sc_ready(server, features));
        assert_eq!(
            sent,
            vec![cs_ready_pdu(0, answer, 10)],
            "server {server:#x}"
        );
        assert!(h.is_ready());
        assert_eq!(h.pen_ready(), pen, "server {server:#x}");
        assert_eq!(h.version(), answer);
    }
}

#[test]
fn show_touch_visuals_flag_and_contacts() {
    let (mut ch, _h) = touch_input(TouchOptions {
        show_touch_visuals: true,
        max_touch_contacts: 5,
    });
    let sent = process(&mut ch, &sc_ready(PROTOCOL_V200, None));
    assert_eq!(
        sent,
        vec![cs_ready_pdu(
            CS_READY_FLAGS_SHOW_TOUCH_VISUALS,
            PROTOCOL_V200,
            5
        )]
    );
    assert!(
        !TouchOptions::default().show_touch_visuals,
        "off by default"
    );
}

#[test]
fn sc_ready_parse() {
    assert_eq!(
        parse_sc_ready(&sc_ready(PROTOCOL_V300, Some(1))).unwrap(),
        ScReady {
            protocol_version: PROTOCOL_V300,
            supported_features: Some(1)
        }
    );
    let short = header(EVENTID_SC_READY);
    assert!(parse_sc_ready(&short).is_err());
    assert!(parse_sc_ready(&header(EVENTID_TOUCH)).is_err());
}

#[test]
fn frames_wait_for_ready_and_carry_timing() {
    let (clock, t) = test_clock();
    let (mut ch, h) = touch_input_with_clock(TouchOptions::default(), clock);
    let t0 = *t.lock().unwrap();
    let f = |x| TouchFrame {
        contacts: vec![down(1, x, 0)],
    };
    assert!(!h.send_touch_at(f(1), t0), "dropped before SC_READY");
    process(&mut ch, &sc_ready(PROTOCOL_V200, None));
    assert!(tick(&mut ch).is_empty());
    assert!(h.send_touch_at(f(1), t0));
    assert!(h.send_touch_at(f(2), t0 + Duration::from_micros(8000)));
    *t.lock().unwrap() = t0 + Duration::from_millis(12);
    let sent = tick(&mut ch);
    assert_eq!(sent.len(), 1);
    let p = parse_touch_event(&sent[0]).unwrap();
    assert_eq!(p.encode_time, 12, "from the oldest frame");
    assert_eq!(
        p.frames.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![0, 8000],
        "first frame 0, then microseconds since the previous one"
    );
    // The offset continues across PDUs.
    assert!(h.send_touch_at(f(3), t0 + Duration::from_micros(10_500)));
    let p = parse_touch_event(&tick(&mut ch)[0]).unwrap();
    assert_eq!(p.frames[0].0, 2500);
    assert!(tick(&mut ch).is_empty());
}

#[test]
fn pen_needs_version_2() {
    let (mut ch, h) = touch_input(TouchOptions::default());
    process(&mut ch, &sc_ready(PROTOCOL_V101, None));
    let pen = PenFrame {
        contacts: vec![PenContact {
            flags: CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE,
            ..Default::default()
        }],
    };
    assert!(!h.send_pen(pen.clone()));
    assert!(tick(&mut ch).is_empty());
    process(&mut ch, &sc_ready(PROTOCOL_V200, None));
    assert!(h.send_pen(pen.clone()));
    let sent = tick(&mut ch);
    assert_eq!(sent.len(), 1);
    assert_eq!(parse_pen_event(&sent[0]).unwrap().frames[0].1, pen.contacts);
}

#[test]
fn suspend_and_resume() {
    let (mut ch, h) = touch_input(TouchOptions::default());
    process(&mut ch, &sc_ready(PROTOCOL_V300, Some(0)));
    let f = TouchFrame {
        contacts: vec![down(0, 0, 0)],
    };
    assert!(h.send_touch(f.clone()));
    assert!(process(&mut ch, &header(EVENTID_SUSPEND_INPUT)).is_empty());
    assert!(!h.is_ready());
    assert!(!h.pen_ready());
    assert!(!h.send_touch(f.clone()));
    assert!(!h.dismiss_hovering(0));
    assert!(
        tick(&mut ch).is_empty(),
        "frames queued before suspend dropped"
    );
    process(&mut ch, &header(EVENTID_SUSPEND_INPUT));
    process(&mut ch, &header(EVENTID_RESUME_INPUT));
    assert!(h.is_ready());
    assert!(h.dismiss_hovering(3));
    assert_eq!(tick(&mut ch), vec![dismiss_hovering_pdu(3)]);
}

#[test]
fn malformed_server_messages() {
    let (mut ch, h) = touch_input(TouchOptions::default());
    // pduLength not matching the data: ignored (MS-RDPEI 3.1.5.1).
    let mut bad = sc_ready(PROTOCOL_V200, None);
    bad[2] = 11;
    assert!(process(&mut ch, &bad).is_empty());
    assert!(!h.is_ready());
    // Unknown event: ignored.
    assert!(process(&mut ch, &header(0x7777)).is_empty());
    // Client-to-server events from the server: ignored.
    assert!(process(&mut ch, &dismiss_hovering_pdu(1)).is_empty());
    // Too short for a header: an error (closes only this channel).
    let mut out = DvcOut::default();
    assert!(ch.process(&[0x01, 0x00, 0x06], &mut out).is_err());
    // SC_READY without a protocolVersion: an error.
    assert!(ch.process(&header(EVENTID_SC_READY), &mut out).is_err());
    assert!(out.is_empty());
    assert!(!h.is_ready());
}

#[test]
fn queue_is_bounded() {
    let (mut ch, h) = touch_input(TouchOptions::default());
    process(&mut ch, &sc_ready(PROTOCOL_V200, None));
    let f = TouchFrame {
        contacts: vec![down(0, 0, 0)],
    };
    for _ in 0..MAX_QUEUED_FRAMES {
        assert!(h.send_touch(f.clone()));
    }
    assert!(!h.send_touch(f.clone()));
    assert!(!h.send_touch(TouchFrame::default()), "empty frames dropped");
    let sent = tick(&mut ch);
    assert_eq!(sent.len(), MAX_QUEUED_FRAMES.div_ceil(MAX_FRAMES_PER_PDU));
    let total: usize = sent
        .iter()
        .map(|p| parse_touch_event(p).unwrap().frames.len())
        .sum();
    assert_eq!(total, MAX_QUEUED_FRAMES);
}

#[test]
fn end_to_end_through_drdynvc() {
    let (ch, h) = touch_input(TouchOptions::default());
    let mut d = Drdynvc::new(vec![Box::new(ch)]);
    let mut out = ChannelOut::default();
    d.process(&[0x50, 0x00, 0x01, 0x00], &mut out).unwrap();
    let mut req = vec![0x10, 0x07];
    req.extend_from_slice(CHANNEL_NAME.as_bytes());
    req.push(0);
    d.process(&req, &mut out).unwrap();
    let mut data = vec![0x30, 0x07];
    data.extend_from_slice(&sc_ready(PROTOCOL_V300, Some(0)));
    d.process(&data, &mut out).unwrap();
    let mut cs = vec![0x30, 0x07];
    cs.extend_from_slice(&cs_ready_pdu(0, PROTOCOL_V300, 10));
    assert_eq!(
        out.take(),
        vec![
            vec![0x50, 0x00, 0x01, 0x00],
            vec![0x10, 0x07, 0, 0, 0, 0],
            cs
        ]
    );
    assert!(h.send_touch(TouchFrame {
        contacts: vec![down(0, 100, 200)],
    }));
    d.tick(&mut out).unwrap();
    let sent = out.take();
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][..2], &[0x30, 0x07]);
    assert_eq!(parse_touch_event(&sent[0][2..]).unwrap().frames.len(), 1);
    // A broken message closes the channel, and the handle stops accepting.
    let mut broken = vec![0x30, 0x07];
    broken.extend_from_slice(&header(EVENTID_SC_READY));
    d.process(&broken, &mut out).unwrap();
    assert_eq!(out.take(), vec![vec![0x40, 0x07]], "DYNVC_CLOSE");
    assert!(!h.is_ready());
}

#[test]
fn dropping_the_channel_ends_ready() {
    let (mut ch, h) = touch_input(TouchOptions::default());
    process(&mut ch, &sc_ready(PROTOCOL_V200, None));
    assert!(h.is_ready());
    drop(ch);
    assert!(!h.is_ready());
    assert!(!h.send_touch(TouchFrame {
        contacts: vec![down(0, 0, 0)],
    }));
}

#[test]
fn handle_is_clone_send_sync() {
    fn check<T: Clone + Send + Sync>() {}
    check::<TouchHandle>();
}
