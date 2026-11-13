//! Multi-monitor tests: GCC monitor blocks (MS-RDPBCGR 2.2.1.3.6,
//! 2.2.1.3.10), the server's Monitor Layout PDU (2.2.12.1), the Display
//! Control layout with several monitors (MS-RDPEDISP 2.2.2.2) and GFX output
//! composition (MS-RDPEGFX 3.3.5.15).

use super::*;
use crate::disp::{self, DisplayCaps};
use crate::dvc::{DvcOut, DynamicChannel};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// Primary 1920 x 1080 at (0,0) and a 1280 x 1024 monitor to its left.
fn two_monitors() -> Vec<Monitor> {
    vec![
        Monitor {
            physical_mm: (600, 340),
            scale: 150,
            ..Monitor::new(0, 0, 1920, 1080, true)
        },
        Monitor {
            orientation: Orientation::Portrait,
            ..Monitor::new(-1280, 0, 1280, 1024, false)
        },
    ]
}

#[test]
fn monitor_block_field_layout() {
    let d = VirtualDesktop::new(&two_monitors()).unwrap();
    let expect = hex("05 c0 34 00  00 00 00 00  02 00 00 00
         00 00 00 00  00 00 00 00  7f 07 00 00  37 04 00 00  01 00 00 00
         00 fb ff ff  00 00 00 00  ff ff ff ff  ff 03 00 00  00 00 00 00");
    assert_eq!(client_monitor_data(&d), expect);
}

#[test]
fn monitor_ex_block_field_layout() {
    let d = VirtualDesktop::new(&two_monitors()).unwrap();
    let expect = hex("08 c0 38 00  00 00 00 00  14 00 00 00  02 00 00 00
         58 02 00 00  54 01 00 00  00 00 00 00  96 00 00 00  8c 00 00 00
         00 00 00 00  00 00 00 00  5a 00 00 00  64 00 00 00  64 00 00 00");
    assert_eq!(client_monitor_ex_data(&d, 100), expect);
    // A monitor without its own scale takes the session's (clamped).
    let ex = client_monitor_ex_data(&d, 900);
    assert_eq!(&ex[ex.len() - 8..], &[0xf4, 1, 0, 0, 180, 0, 0, 0]);
}

#[test]
fn gcc_client_data_carries_the_monitor_blocks() {
    let d = VirtualDesktop::new(&two_monitors()).unwrap();
    let mut s = crate::gcc::ClientSettings {
        width: d.width as u16,
        height: d.height as u16,
        keyboard_layout: 0x409,
        client_name: "TEST",
        selected_protocol: 3,
        scale: 100,
        color_depth: 32,
        connection_type: crate::ConnectionType::Lan,
        channels: &[],
        gfx: false,
        monitors: Some(&d),
        redirected_session_id: None,
        redirected_smartcard: false,
    };
    let b = crate::gcc::client_data_blocks(&s);
    // desktopWidth/Height (offsets 8, 10) are the bounding box 3200 x 1080.
    assert_eq!(&b[8..12], &[0x80, 0x0c, 0x38, 0x04]);
    // earlyCapabilityFlags: RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU added.
    assert_eq!(u16::from_le_bytes([b[144], b[145]]), 0x046B);
    let tail = [client_monitor_data(&d), client_monitor_ex_data(&d, 100)].concat();
    assert!(b.ends_with(&tail));
    s.monitors = None;
    let one = crate::gcc::client_data_blocks(&s);
    assert_eq!(one.len(), b.len() - tail.len());
    assert_eq!(u16::from_le_bytes([one[144], one[145]]), 0x042B);
}

#[test]
fn primary_moves_to_the_origin() {
    // Windows-style coordinates with the primary right of a second monitor:
    // the primary's corner becomes (0,0) and the other one goes negative.
    let d = VirtualDesktop::new(&[
        Monitor::new(0, 0, 1280, 1024, false),
        Monitor::new(1280, 0, 1920, 1080, true),
    ])
    .unwrap();
    assert_eq!(d.monitors[0], Monitor::new(0, 0, 1920, 1080, true));
    assert_eq!(d.monitors[1], Monitor::new(-1280, 0, 1280, 1024, false));
    assert_eq!((d.left, d.top, d.width, d.height), (-1280, 0, 3200, 1080));
    assert_eq!(d.to_framebuffer(&d.monitors[1]), Some((0, 0, 1280, 1024)));
    assert_eq!(
        d.to_framebuffer(&d.monitors[0]),
        Some((1280, 0, 1920, 1080))
    );
    assert_eq!(
        d.to_framebuffer(&Monitor::new(-1281, 0, 10, 10, false)),
        None
    );
}

#[test]
fn bounding_box_of_offset_monitors() {
    let d = VirtualDesktop::new(&[
        Monitor::new(0, 0, 1920, 1080, true),
        Monitor::new(1920, -420, 1080, 1920, false),
        Monitor::new(0, 1080, 1920, 1080, false),
    ])
    .unwrap();
    assert_eq!((d.left, d.top, d.width, d.height), (0, -420, 3000, 2580));
    assert_eq!(d.to_framebuffer(&d.monitors[0]), Some((0, 420, 1920, 1080)));
    assert_eq!(
        d.to_framebuffer(&d.monitors[1]),
        Some((1920, 0, 1080, 1920))
    );
}

#[test]
fn primary_choice_and_limits() {
    // No primary flag: the monitor holding (0,0) becomes primary.
    let d = VirtualDesktop::new(&[
        Monitor::new(-800, 0, 800, 600, false),
        Monitor::new(0, 0, 800, 600, false),
    ])
    .unwrap();
    assert_eq!(d.monitors[0], Monitor::new(0, 0, 800, 600, true));
    assert!(!d.monitors[1].primary);
    // Two flagged: the first wins; exactly one stays flagged.
    let d = VirtualDesktop::new(&[
        Monitor::new(500, 500, 800, 600, true),
        Monitor::new(0, 0, 400, 600, true),
    ])
    .unwrap();
    assert_eq!(d.monitors.iter().filter(|m| m.primary).count(), 1);
    assert_eq!(d.monitors[1], Monitor::new(-500, -500, 400, 600, false));
    // Limits of 2.2.1.3.6.
    assert!(VirtualDesktop::new(&[]).is_err());
    let many: Vec<Monitor> = (0..17)
        .map(|i| Monitor::new(i * 200, 0, 200, 200, i == 0))
        .collect();
    assert!(VirtualDesktop::new(&many).is_err());
    assert!(VirtualDesktop::new(&many[..16]).is_ok());
    assert!(VirtualDesktop::new(&[Monitor::new(0, 0, 199, 600, true)]).is_err());
    assert!(VirtualDesktop::new(&[Monitor::new(0, 0, 200, 200, true)]).is_ok());
    let wide = [
        Monitor::new(0, 0, 16383, 600, true),
        Monitor::new(16383, 0, 16383, 600, false),
    ];
    assert_eq!(VirtualDesktop::new(&wide).unwrap().width, 32766);
    let wider = [
        Monitor::new(0, 0, 16384, 600, true),
        Monitor::new(16383, 0, 16384, 600, false),
    ];
    assert!(VirtualDesktop::new(&wider).is_err());
    let inverted = Monitor {
        right: -1,
        ..Monitor::new(0, 0, 800, 600, true)
    };
    assert!(VirtualDesktop::new(&[inverted]).is_err());
    // Extreme coordinates never overflow.
    let far = [
        Monitor::new(i32::MIN, 0, 800, 600, true),
        Monitor::new(i32::MAX - 799, 0, 800, 600, false),
    ];
    assert!(VirtualDesktop::new(&far).is_err());
}

#[test]
fn parses_server_monitor_layout() {
    let body = hex("02 00 00 00
         00 00 00 00  00 00 00 00  7f 07 00 00  37 04 00 00  01 00 00 00
         00 fb ff ff  00 00 00 00  ff ff ff ff  ff 03 00 00  00 00 00 00");
    let m = parse_monitor_layout(&body).unwrap();
    assert_eq!(
        m,
        vec![
            Monitor::new(0, 0, 1920, 1080, true),
            Monitor::new(-1280, 0, 1280, 1024, false)
        ]
    );
    assert!(parse_monitor_layout(&body[..body.len() - 1]).is_err());
    let mut many = body.clone();
    many[0] = 17;
    many.resize(4 + 17 * 20, 0);
    assert!(parse_monitor_layout(&many).is_err());
    assert_eq!(parse_monitor_layout(&[0, 0, 0, 0]).unwrap(), vec![]);
    let mut huge = body;
    huge[3] = 0x80;
    assert!(parse_monitor_layout(&huge).is_err());
}

#[test]
fn display_control_multi_monitor_pdu_bytes() {
    let d = VirtualDesktop::new(&[
        Monitor::new(0, 0, 1920, 1080, true),
        Monitor::new(-1280, 0, 1280, 1024, false),
    ])
    .unwrap();
    let expect = hex("02 00 00 00  60 00 00 00  28 00 00 00  02 00 00 00
         01 00 00 00  00 00 00 00  00 00 00 00  80 07 00 00  38 04 00 00
         00 00 00 00  00 00 00 00  00 00 00 00  64 00 00 00  64 00 00 00
         00 00 00 00  00 fb ff ff  00 00 00 00  00 05 00 00  00 04 00 00
         00 00 00 00  00 00 00 00  00 00 00 00  64 00 00 00  64 00 00 00");
    assert_eq!(disp::monitors_layout_pdu(&d, 100), expect);
    // One monitor gives the same bytes as the single-monitor PDU.
    let one = VirtualDesktop::new(&[Monitor::new(0, 0, 1920, 1080, true)]).unwrap();
    assert_eq!(
        disp::monitors_layout_pdu(&one, 150),
        disp::monitor_layout_pdu(1920, 1080, 150)
    );
}

fn caps(n: u32, a: u32, b: u32) -> DisplayCaps {
    DisplayCaps {
        max_num_monitors: n,
        max_monitor_area_factor_a: a,
        max_monitor_area_factor_b: b,
    }
}

#[test]
fn fit_layout_clamps_truncates_and_limits_area() {
    let m = [
        Monitor::new(-1281, 0, 1281, 100, false),
        Monitor::new(0, 0, 9000, 1080, true),
    ];
    let d = disp::fit_layout(&m, None).unwrap();
    assert_eq!(d.monitors[0], Monitor::new(0, 0, 8192, 1080, true));
    assert_eq!(d.monitors[1], Monitor::new(-1281, 0, 1280, 200, false));
    // MaxNumMonitors 1 keeps the primary only, and the box shrinks with it.
    let d = disp::fit_layout(&m, Some(&caps(1, 8192, 8192))).unwrap();
    assert_eq!(d.monitors.len(), 1);
    assert_eq!((d.left, d.width), (0, 8192));
    // Area: 1920x1080 + 1280x1024 fits 2 x (1920 x 1080), not 2 x (1600 x 1000).
    let two = two_monitors();
    assert!(disp::fit_layout(&two, Some(&caps(2, 1920, 1080))).is_some());
    assert!(disp::fit_layout(&two, Some(&caps(2, 1600, 1000))).is_none());
}

fn tick(ch: &mut disp::DisplayControl) -> Vec<Vec<u8>> {
    let mut out = DvcOut::default();
    ch.tick(&mut out).unwrap();
    out.take()
}

#[test]
fn display_handle_sends_layouts_and_latest_request_wins() {
    let t = std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let t2 = t.clone();
    let (mut ch, handle) = disp::display_control_with_clock(Box::new(move || *t2.lock().unwrap()));
    let caps_pdu = hex("05 00 00 00 14 00 00 00 10 00 00 00 00 20 00 00 00 20 00 00");
    ch.process(&caps_pdu, &mut DvcOut::default()).unwrap();
    let advance = || *t.lock().unwrap() += std::time::Duration::from_millis(300);
    let two = two_monitors();
    let d = VirtualDesktop::new(&two).unwrap();

    handle.request_layout(&two);
    assert_eq!(tick(&mut ch), vec![disp::monitors_layout_pdu(&d, 100)]);
    assert!(tick(&mut ch).is_empty());

    // A resize after a layout wins, and the other way round.
    advance();
    handle.request_layout(&two);
    handle.request_resize(1280, 720);
    assert_eq!(
        tick(&mut ch),
        vec![disp::monitor_layout_pdu(1280, 720, 100)]
    );
    advance();
    handle.request_resize(1280, 720);
    handle.request_layout(&two);
    assert_eq!(tick(&mut ch), vec![disp::monitors_layout_pdu(&d, 100)]);

    // A scale change re-sends the layout; monitors without their own scale take it.
    advance();
    handle.set_scale(200);
    let sent = tick(&mut ch);
    assert_eq!(sent, vec![disp::monitors_layout_pdu(&d, 200)]);
    assert_eq!(&sent[0][sent[0].len() - 8..], &[200, 0, 0, 0, 180, 0, 0, 0]);

    // A layout that cannot be sent is dropped, not retried forever.
    advance();
    handle.request_layout(&[]);
    assert!(tick(&mut ch).is_empty());
    advance();
    assert!(tick(&mut ch).is_empty());
}

#[test]
fn gfx_outputs_compose_into_one_virtual_desktop() {
    use crate::gfx::surface::{Area, GfxState};
    // Two monitors side by side: the left one 6 x 4, the primary 8 x 5 at
    // x = 6 of the 14 x 5 output buffer (RDPGFX_RESET_GRAPHICS covers the
    // bounding box; MapSurfaceToOutput places each monitor's surface).
    let mut s = GfxState::new();
    s.reset(14, 5);
    s.create(1, 6, 4).unwrap();
    s.create(2, 8, 5).unwrap();
    assert!(s.map(1, 0, 0));
    assert!(s.map(2, 6, 0));
    s.fill(1, 0x0011_1111, &[Area::new(0, 0, 6, 4)]);
    s.fill(2, 0x0022_2222, &[Area::new(0, 0, 8, 5)]);
    s.compose();
    let mut fb = crate::Framebuffer::new(1, 1);
    let mut damage = Vec::new();
    assert!(
        s.present(&mut fb, &mut damage),
        "takes the bounding box size"
    );
    assert_eq!((fb.width, fb.height), (14, 5));
    for y in 0..5 {
        for x in 0..14 {
            let want = match (x, y) {
                (6.., _) => 0x0022_2222,
                (_, 0..4) => 0x0011_1111,
                _ => 0,
            };
            assert_eq!(fb.pixels[y * 14 + x], want, "pixel {x},{y}");
        }
    }
    // Later damage on the primary's surface lands at its output offset.
    damage.clear();
    s.fill(2, 0x0033_3333, &[Area::new(1, 2, 2, 2)]);
    s.compose();
    assert!(!s.present(&mut fb, &mut damage));
    assert_eq!(
        damage,
        [crate::Damage {
            x: 7,
            y: 2,
            w: 2,
            h: 2
        }]
    );
    assert_eq!(fb.pixels[2 * 14 + 7], 0x0033_3333);
}
