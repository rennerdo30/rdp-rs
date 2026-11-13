//! MS-RDPERP tests: every PDU against the section 4 example bytes where the
//! spec has them, round trips otherwise, the drawing order framing, the
//! window model and a scripted channel session.

use super::orders::*;
use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

// ---- rail channel PDUs (MS-RDPERP 4.2 to 4.8) ----

#[test]
fn handshake_4_2_1() {
    let bytes = hex("05 00 08 00 71 17 00 00");
    assert_eq!(
        parse(&bytes).unwrap(),
        ServerPdu::Handshake { build: 0x1771 }
    );
    assert_eq!(handshake(0x1771), bytes);
}

#[test]
fn handshake_ex() {
    let msg = hex("13 00 0c 00 71 17 00 00 04 00 00 00");
    assert_eq!(
        parse(&msg).unwrap(),
        ServerPdu::HandshakeEx {
            build: 0x1771,
            flags: TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED
        }
    );
}

#[test]
fn client_status_4_2_2() {
    assert_eq!(
        client_status(TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE),
        hex("0b 00 08 00 01 00 00 00")
    );
}

const EXEC_4_3_1: &str = "01 00 5e 00 08 00 14 00 26 00 18 00 7c 00 7c 00
    69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00
    66 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00
    77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00
    6d 00 33 00 32 00 77 00 77 00 77 00 2e 00 62 00
    69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00";

#[test]
fn exec_4_3_1() {
    let pdu = exec_raw(
        TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS,
        &utf16le("||iexplore"),
        &utf16le("f:\\windows\\system32"),
        &utf16le("www.bing.com"),
    );
    assert_eq!(pdu, hex(EXEC_4_3_1));
    // exec() builds the same layout; expansion flags only for '%'.
    let app = RemoteApp {
        program: "||iexplore".into(),
        args: "www.bing.com".into(),
        working_dir: "f:\\windows\\system32".into(),
    };
    let mut expected = hex(EXEC_4_3_1);
    expected[4] = 0;
    assert_eq!(exec(&app).unwrap(), expected);
    let pct = RemoteApp {
        working_dir: "%USERPROFILE%".into(),
        args: "%TEMP%".into(),
        ..app.clone()
    };
    assert_eq!(exec(&pct).unwrap()[4], 0x09);
}

#[test]
fn exec_limits() {
    let empty = RemoteApp::default();
    assert!(exec(&empty).is_err());
    let long = RemoteApp {
        program: "a".repeat(261),
        ..Default::default()
    };
    assert!(exec(&long).is_err(), "522 bytes > 520");
    let ok = RemoteApp {
        program: "a".repeat(260),
        ..Default::default()
    };
    assert!(exec(&ok).is_ok());
    let args = RemoteApp {
        program: "x".into(),
        args: "a".repeat(8001),
        ..Default::default()
    };
    assert!(exec(&args).is_err());
    assert!(rail(empty, 800, 600, 0).is_err());
}

#[test]
fn exec_result_4_3_2() {
    let bytes = hex("80 00 24 00 08 00 03 00 15 00 00 00 00 00 14 00
         7c 00 7c 00 57 00 72 00 6f 00 6e 00 67 00 41 00 70 00 70 00");
    let ServerPdu::ExecResult(r) = parse(&bytes).unwrap() else {
        panic!()
    };
    assert_eq!(
        r,
        ExecResult {
            flags: 8,
            result: 3,
            raw_result: 0x15,
            program: "||WrongApp".into()
        }
    );
    assert!(!r.ok());
    assert!(r.result_name().contains("policy"));
}

#[test]
fn sysparam_4_4_1() {
    let p = default_sysparams(1024, 768);
    assert_eq!(
        p[0],
        hex("03 00 12 00 43 00 00 00 7e 00 00 00 02 00 00 00 00 00")
    );
    // Work area: TS_RECTANGLE_16 of the desktop.
    assert_eq!(p[5], hex("03 00 10 00 2f 00 00 00 00 00 00 00 00 04 00 03"));
    assert!(p.iter().all(|m| le16(m, 2) as usize == m.len()));
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[test]
fn server_sysparam() {
    let msg = hex("03 00 09 00 11 00 00 00 01");
    assert_eq!(
        parse(&msg).unwrap(),
        ServerPdu::SysParam {
            param: 0x11,
            value: 1
        }
    );
}

#[test]
fn client_event_pdus_4_5() {
    assert_eq!(activate(0x1014e, true), hex("02 00 09 00 4e 01 01 00 01"));
    assert_eq!(
        sysmenu(0x90122, -92, 0x24a),
        hex("0c 00 0c 00 22 01 09 00 a4 ff 4a 02")
    );
    assert_eq!(
        syscommand(0x20052, SysCommand::Minimize),
        hex("04 00 0a 00 52 00 02 00 20 f0")
    );
    assert_eq!(
        notify_event(0x201aa, 2, 0x204),
        hex("06 00 10 00 aa 01 02 00 02 00 00 00 04 02 00 00")
    );
    assert_eq!(language_bar(1), hex("0D 00 08 00 01 00 00 00"));
    assert_eq!(get_app_id(0x20052), hex("0E 00 08 00 52 00 02 00"));
    assert_eq!(
        parse(&hex("0D 00 08 00 01 00 00 00")).unwrap(),
        ServerPdu::LanguageBar { status: 1 }
    );
}

#[test]
fn app_id_response_4_5_7() {
    // The example's orderLength is 0x208 (520): a 512-byte ApplicationId.
    let mut msg = hex("0F 00 08 02 52 00 02 00");
    msg.extend(utf16le("microsoft.windows.notepad"));
    msg.resize(520, 0);
    assert_eq!(
        parse(&msg).unwrap(),
        ServerPdu::AppId {
            window_id: 0x20052,
            app_id: "microsoft.windows.notepad".into(),
            process: None
        }
    );
    // Extended response (2.2.2.8.2): 520-byte id, process id, 520-byte image name.
    let mut ex = Vec::new();
    ex.put_u16(TS_RAIL_ORDER_GET_APPID_RESP_EX);
    ex.put_u16(4 + 4 + 520 + 4 + 520);
    ex.put_u32(7);
    let mut id = utf16le("app");
    id.resize(520, 0);
    ex.extend(id);
    ex.put_u32(1234);
    let mut img = utf16le("notepad.exe");
    img.resize(520, 0);
    ex.extend(img);
    assert_eq!(
        parse(&ex).unwrap(),
        ServerPdu::AppId {
            window_id: 7,
            app_id: "app".into(),
            process: Some((1234, "notepad.exe".into()))
        }
    );
}

#[test]
fn window_move_4_6_1_and_snap() {
    let m = window_move(0x20020, [0x309, 0x100, 0x5db, 0x188]);
    assert_eq!(m, hex("08 00 10 00 20 00 02 00 09 03 00 01 db 05 88 01"));
    let s = snap_arrange(0x20020, [0x309, 0x100, 0x5db, 0x188]);
    assert_eq!(&s[..2], &[0x17, 0]);
    assert_eq!(&s[2..], &m[2..]);
}

#[test]
fn local_move_size_4_6_2() {
    let msg = hex("09 00 10 00 94 00 01 00 01 00 08 00 2c 05 e9 03");
    assert_eq!(
        parse(&msg).unwrap(),
        ServerPdu::LocalMoveSize(LocalMoveSize {
            window_id: 0x10094,
            start: true,
            kind: 8,
            x: 0x52c,
            y: 0x3e9
        })
    );
    let end = hex("09 00 10 00 94 00 01 00 00 00 09 00 f6 ff 20 00");
    let ServerPdu::LocalMoveSize(e) = parse(&end).unwrap() else {
        panic!()
    };
    assert!(!e.start);
    assert_eq!((e.x, e.y), (-10, 32));
}

#[test]
fn min_max_info_4_6_3() {
    let msg = hex("0a 00 18 00 94 00 01 00 48 06 b8 04 00 00 00 00 70 00 1b 00 4c 06 bc 04");
    assert_eq!(
        parse(&msg).unwrap(),
        ServerPdu::MinMaxInfo(MinMaxInfo {
            window_id: 0x10094,
            max_width: 0x648,
            max_height: 0x4b8,
            max_pos_x: 0,
            max_pos_y: 0,
            min_track_width: 0x70,
            min_track_height: 0x1b,
            max_track_width: 0x64c,
            max_track_height: 0x4bc
        })
    );
}

#[test]
fn zorder_power_cloak_4_7_4_8() {
    assert_eq!(
        parse(&hex("14 00 08 00 10 05 40 00")).unwrap(),
        ServerPdu::ZOrderSync {
            marker_window: 0x400510
        }
    );
    assert_eq!(
        parse(&hex("16 00 08 00 01 00 00 00")).unwrap(),
        ServerPdu::PowerDisplayRequest { active: true }
    );
    let c = cloak(9, true);
    assert_eq!(c, hex("15 00 09 00 09 00 00 00 01"));
    assert_eq!(
        parse(&c).unwrap(),
        ServerPdu::Cloak {
            window_id: 9,
            cloaked: true
        }
    );
}

#[test]
fn bad_rail_headers_are_errors() {
    assert!(parse(&[5, 0]).is_err());
    assert!(parse(&hex("05 00 03 00 00")).is_err(), "length below 4");
    assert!(
        parse(&hex("05 00 09 00 71 17 00 00")).is_err(),
        "length past end"
    );
    assert!(
        parse(&hex("80 00 0c 00 08 00 03 00 15 00 00 00")).is_err(),
        "truncated body"
    );
    assert_eq!(
        parse(&hex("12 00 04 00")).unwrap(),
        ServerPdu::Other { order_type: 0x12 }
    );
}

// ---- window orders (MS-RDPERP 4.1.1) ----

/// 4.1.1.1. The capture prints 128 bytes of the 129 in OrderSize; the last
/// byte is EnforceServerZOrder (WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER is set).
fn new_window_order() -> Vec<u8> {
    let mut v = hex("2e 81 00 9e df 08 19 58 01 12 00 00 00 00 00 00
         00 cf 14 00 01 00 00 05 1a 00 46 00 69 00 6c 00
         65 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00
         65 00 72 00 1b 01 00 00 34 01 00 00 07 00 00 00
         07 00 00 00 00 00 00 00 07 00 00 00 8d 00 00 00
         9a 00 00 00 8e 00 00 00 9a 00 00 00 e6 05 00 00
         42 03 00 00 01 00 00 00 00 00 e6 05 42 03 8d 00
         00 00 9a 00 00 00 01 00 00 00 00 00 e6 05 42 03");
    v.push(0);
    assert_eq!(v.len(), 0x81);
    v
}

#[test]
fn new_window_4_1_1_1() {
    let WindowOrder::Window { id, new, info } = parse_window_order(&new_window_order()).unwrap()
    else {
        panic!()
    };
    assert_eq!((id, new), (0x120158, true));
    let full = Rect16 {
        left: 0,
        top: 0,
        right: 1510,
        bottom: 834,
    };
    assert_eq!(
        info,
        WindowInfo {
            owner: Some(0),
            style: Some((0x14cf_0000, 0x100)),
            show_state: Some(5),
            title: Some("File Explorer".into()),
            client_offset: Some((283, 308)),
            resize_margin_x: Some((7, 7)),
            resize_margin_y: Some((0, 7)),
            window_offset: Some((141, 154)),
            client_delta: Some((142, 154)),
            window_size: Some((1510, 834)),
            window_rects: Some(vec![full]),
            visible_offset: Some((141, 154)),
            visibility_rects: Some(vec![full]),
            enforce_server_zorder: Some(0),
            ..Default::default()
        }
    );
}

#[test]
fn deleted_window_4_1_1_2() {
    let o = hex("2e 0b 00 00 00 00 21 24 00 03 00");
    assert_eq!(
        parse_window_order(&o).unwrap(),
        WindowOrder::WindowDeleted { id: 0x30024 }
    );
}

/// 4.1.1.3, with the truncated icon bits of the capture zero-filled to OrderSize.
fn notify_icon_order() -> Vec<u8> {
    let mut v = hex("2e 9d 04 01 00 00 52 8e 00 01 00 d2 9c 00 00 40
         00 2a 20 0e 20 43 00 6f 00 6d 00 6d 00 75 00 6e
         00 69 00 63 00 61 00 74 00 6f 00 72 00 20 00 2d
         00 20 00 4e 00 6f 00 74 00 20 00 73 00 69 00 67
         00 6e 00 65 00 64 00 20 00 69 00 6e 00 0e 20 2c
         20 00 00 02 20 10 00 10 00 40 00 00 04 fe 03 00");
    v.resize(0x49d, 0);
    v
}

#[test]
fn new_notify_icon_4_1_1_3() {
    let WindowOrder::NotifyIcon {
        window_id,
        icon_id,
        new,
        info,
    } = parse_window_order(&notify_icon_order()).unwrap()
    else {
        panic!()
    };
    assert_eq!((window_id, icon_id, new), (0x1008e, 0x9cd2, true));
    assert_eq!(
        info.tooltip.as_deref(),
        Some("\u{202a}\u{200e}Communicator - Not signed in\u{200e}\u{202c}")
    );
    let icon = info.icon.unwrap();
    assert_eq!(
        (
            icon.cache_entry,
            icon.cache_id,
            icon.bpp,
            icon.width,
            icon.height
        ),
        (0, 2, 32, 16, 16)
    );
    assert_eq!((icon.bits_mask.len(), icon.bits_color.len()), (64, 1024));
    assert_eq!(&icon.bits_mask[..2], &[0xfe, 0x03]);
    assert!(icon.color_table.is_empty());
    assert_eq!(icon.to_rgba().unwrap().len(), 16 * 16 * 4);
}

#[test]
fn deleted_notify_icon_4_1_1_4() {
    let o = hex("2e 0f 00 01 00 00 62 f4 01 03 00 00 00 00 00");
    assert_eq!(
        parse_window_order(&o).unwrap(),
        WindowOrder::NotifyIconDeleted {
            window_id: 0x301f4,
            icon_id: 0
        }
    );
}

#[test]
fn desktop_orders_4_1_1_5_and_6() {
    // The capture prints 16 of the 20 bytes; the second id is from its legend.
    let mut o = hex("2e 14 00 30 00 00 04 a0 00 01 00 02 a0 00 01 00");
    o.extend(hex("66 00 02 00"));
    assert_eq!(
        parse_window_order(&o).unwrap(),
        WindowOrder::Desktop(DesktopInfo {
            active_window: Some(0x100a0),
            z_order: Some(vec![0x100a0, 0x20066]),
            ..Default::default()
        })
    );
    assert_eq!(
        parse_window_order(&hex("2e 07 00 01 00 00 04")).unwrap(),
        WindowOrder::DesktopNone
    );
}

#[test]
fn icon_and_cached_icon_orders() {
    // Window icon: 2x2, 24 bpp, big icon, cached at 1/5.
    let mut o = vec![0x2e, 0, 0];
    o.put_u32(WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_ICON | WINDOW_ORDER_FIELD_ICON_BIG);
    o.put_u32(77);
    o.extend(icon_2x2_24bpp());
    let n = o.len() as u16;
    o[1..3].copy_from_slice(&n.to_le_bytes());
    let WindowOrder::Icon { id, slot, icon } = parse_window_order(&o).unwrap() else {
        panic!()
    };
    assert_eq!((id, slot.big, slot.overlay), (77, true, false));
    assert_eq!((icon.cache_id, icon.cache_entry), (1, 5));
    let mut c = hex("2e 0e 00");
    c.put_u32(WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_CACHEDICON);
    c.put_u32(77);
    c.extend([5, 0, 1]);
    assert_eq!(
        parse_window_order(&c).unwrap(),
        WindowOrder::CachedIcon {
            id: 77,
            slot: IconSlot::default(),
            cached: CachedIcon {
                cache_entry: 5,
                cache_id: 1
            }
        }
    );
}

/// TS_ICON_INFO: 2x2 at 24 bpp, rows padded to 8 bytes, stored bottom-up:
/// top row red, blue; bottom row green, white. Mask: top-right transparent.
fn icon_2x2_24bpp() -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(5); // CacheEntry
    v.put_u8(1); // CacheId
    v.put_u8(24);
    v.put_u16(2);
    v.put_u16(2);
    v.put_u16(8); // CbBitsMask: 2 rows of 4
    v.put_u16(16); // CbBitsColor: 2 rows of 8
    v.extend([0x00, 0, 0, 0, 0x40, 0, 0, 0]); // mask, bottom row first
    v.extend([0, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0, 0]); // bottom: green, white
    v.extend([0, 0, 0xFF, 0xFF, 0, 0, 0, 0]); // top: red, blue (BGR)
    v
}

#[test]
fn icon_decodes_bottom_up_with_mask() {
    let mut order = vec![0x2e, 0, 0];
    order.put_u32(WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_ICON);
    order.put_u32(1);
    order.extend(icon_2x2_24bpp());
    let WindowOrder::Icon { icon, .. } = parse_window_order(&order).unwrap() else {
        panic!()
    };
    assert_eq!(
        icon.to_rgba().unwrap(),
        vec![
            0xFF, 0, 0, 0xFF, 0, 0, 0xFF, 0, // red, blue (masked out)
            0, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // green, white
        ]
    );
}

#[test]
fn icon_palette_and_alpha_depths() {
    // 1 bpp with a two-entry table: black, yellow; rows of 4 bytes.
    let icon = IconInfo {
        bpp: 1,
        width: 2,
        height: 1,
        color_table: vec![0, 0, 0, 0, 0, 0xFF, 0xFF, 0],
        bits_color: vec![0x40, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(
        icon.to_rgba().unwrap(),
        vec![0, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0xFF]
    );
    // 4 bpp: high nibble first.
    let icon = IconInfo {
        bpp: 4,
        width: 2,
        height: 1,
        color_table: vec![0, 0, 0, 0, 0xFF, 0, 0, 0],
        bits_color: vec![0x10, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(
        icon.to_rgba().unwrap(),
        vec![0, 0, 0xFF, 0xFF, 0, 0, 0, 0xFF]
    );
    // 32 bpp with alpha ignores the mask; 16 bpp is 5-5-5.
    let icon = IconInfo {
        bpp: 32,
        width: 1,
        height: 1,
        bits_color: vec![1, 2, 3, 0x80],
        bits_mask: vec![0x80, 0, 0, 0],
        ..Default::default()
    };
    assert_eq!(icon.to_rgba().unwrap(), vec![3, 2, 1, 0x80]);
    let icon = IconInfo {
        bpp: 16,
        width: 1,
        height: 1,
        bits_color: vec![0x00, 0x7C, 0, 0],
        ..Default::default()
    };
    assert_eq!(icon.to_rgba().unwrap(), vec![0xFF, 0, 0, 0xFF]);
    // Short bitmaps and silly sizes are errors, not panics.
    for bad in [
        IconInfo {
            bpp: 24,
            width: 4,
            height: 1,
            bits_color: vec![0; 8],
            ..Default::default()
        },
        IconInfo {
            bpp: 7,
            width: 1,
            height: 1,
            bits_color: vec![0; 4],
            ..Default::default()
        },
        IconInfo {
            bpp: 32,
            width: 0,
            height: 1,
            ..Default::default()
        },
        IconInfo {
            bpp: 32,
            width: 300,
            height: 1,
            bits_color: vec![0; 1200],
            ..Default::default()
        },
        IconInfo {
            bpp: 1,
            width: 16,
            height: 1,
            bits_color: vec![0; 4],
            bits_mask: vec![0],
            ..Default::default()
        },
    ] {
        assert!(bad.to_rgba().is_err(), "{bad:?}");
    }
}

#[test]
fn truncated_orders_are_errors() {
    let full = new_window_order();
    for n in [1, 7, 11, 40, 128] {
        assert!(parse_window_order(&full[..n]).is_err(), "cut at {n}");
    }
    assert!(
        parse_window_order(&hex("2f 07 00 01 00 00 04")).is_err(),
        "not altsec window"
    );
    assert!(
        parse_window_order(&hex("2e 07 00 00 00 00 00")).is_err(),
        "no type flag"
    );
}

// ---- order framing (MS-RDPEGDI 2.2.2.1, 2.2.2.2) ----

#[test]
fn fastpath_orders_skip_secondary_and_bad_window_orders() {
    let mut u = Vec::new();
    u.put_u16(4); // numberOrders
    // Secondary order (TS_STANDARD | TS_SECONDARY): orderLength = 20 - 13.
    u.extend([0x03, 7, 0, 0, 0, 0x07]);
    u.extend([0xAA; 14]);
    // A window order whose body is cut short, sized by its OrderSize.
    u.extend(hex("2e 09 00 00 00 00 01 24 00"));
    u.extend(hex("2e 0b 00 00 00 00 21 24 00 03 00"));
    u.extend(hex("2e 07 00 01 00 00 04"));
    let orders = parse_fastpath_orders(&u).unwrap();
    assert_eq!(
        orders,
        vec![
            WindowOrder::WindowDeleted { id: 0x30024 },
            WindowOrder::DesktopNone
        ]
    );
}

#[test]
fn unknown_orders_end_the_batch() {
    // A primary order has no length: everything after it is dropped.
    let mut u = Vec::new();
    u.put_u16(3);
    u.extend(hex("2e 07 00 01 00 00 04"));
    u.extend([0x09]); // a primary order's controlFlags; its fields follow unsized
    u.extend(hex("2e 07 00 01 00 00 04"));
    assert_eq!(
        parse_fastpath_orders(&u).unwrap(),
        vec![WindowOrder::DesktopNone]
    );
    // So does another alternate secondary order (frame marker, type 0x0D).
    let mut u = Vec::new();
    u.put_u16(2);
    u.extend([0x36, 0, 0, 0, 0]);
    u.extend(hex("2e 07 00 01 00 00 04"));
    assert!(parse_fastpath_orders(&u).unwrap().is_empty());
    // An OrderSize past the end stops without reading out of bounds.
    let mut u = Vec::new();
    u.put_u16(1);
    u.extend(hex("2e ff 00 01 00 00 04"));
    assert!(parse_fastpath_orders(&u).unwrap().is_empty());
    // A count larger than the data is fine.
    let mut u = Vec::new();
    u.put_u16(9);
    u.extend(hex("2e 07 00 01 00 00 04"));
    assert_eq!(parse_fastpath_orders(&u).unwrap().len(), 1);
}

#[test]
fn slowpath_orders_header() {
    let mut u = Vec::new();
    u.put_u16(UPDATETYPE_ORDERS);
    u.put_u16(0xBEEF);
    u.put_u16(1);
    u.put_u16(0xBEEF);
    u.extend(hex("2e 07 00 01 00 00 04"));
    assert_eq!(
        parse_slowpath_orders(&u).unwrap(),
        vec![WindowOrder::DesktopNone]
    );
    u[0] = 1; // a bitmap update
    assert!(parse_slowpath_orders(&u).is_err());
}

// ---- window model ----

fn model() -> RailHandle {
    let (_, h) = rail(
        RemoteApp {
            program: "notepad".into(),
            ..Default::default()
        },
        800,
        600,
        0,
    )
    .unwrap();
    h
}

fn update_title(id: u32, title: &str) -> WindowOrder {
    WindowOrder::Window {
        id,
        new: false,
        info: WindowInfo {
            title: Some(title.into()),
            window_offset: Some((-5, 6)),
            ..Default::default()
        },
    }
}

#[test]
fn model_create_update_delete() {
    let h = model();
    let created = parse_window_order(&new_window_order()).unwrap();
    h.apply_orders(vec![created.clone()]);
    assert_eq!(h.take_events(), vec![RailEvent::WindowCreated(0x120158)]);
    let w = h.window(0x120158).unwrap();
    assert_eq!(w.title, "File Explorer");
    assert_eq!(
        w.window_rect,
        WindowRect {
            x: 141,
            y: 154,
            width: 1510,
            height: 834
        }
    );
    assert_eq!(w.resize_margins, [7, 7, 0, 7]);
    assert_eq!(w.visible_rects.len(), 1);
    assert_eq!((w.style, w.ex_style, w.show_state), (0x14cf_0000, 0x100, 5));

    // An update changes only the fields it carries.
    h.apply_orders(vec![update_title(0x120158, "Docs")]);
    assert_eq!(h.take_events(), vec![RailEvent::WindowUpdated(0x120158)]);
    let w = h.window(0x120158).unwrap();
    assert_eq!(w.title, "Docs");
    assert_eq!(
        (w.window_rect.x, w.window_rect.y, w.window_rect.width),
        (-5, 6, 1510)
    );
    assert_eq!(w.show_state, 5);

    // Updates and deletes for unknown windows are ignored (3.2.5.1.6).
    h.apply_orders(vec![
        update_title(9, "x"),
        WindowOrder::WindowDeleted { id: 9 },
    ]);
    assert!(h.take_events().is_empty());
    assert!(h.window(9).is_none());

    h.apply_orders(vec![WindowOrder::WindowDeleted { id: 0x120158 }]);
    assert_eq!(h.take_events(), vec![RailEvent::WindowDeleted(0x120158)]);
    assert!(h.state().windows.is_empty());
}

#[test]
fn model_icons_and_cache() {
    let h = model();
    h.apply_orders(vec![
        parse_window_order(&new_window_order()).unwrap(),
        WindowOrder::Icon {
            id: 0x120158,
            slot: IconSlot {
                big: true,
                overlay: false,
            },
            icon: {
                let mut o = vec![0x2e, 0, 0];
                o.put_u32(WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_ICON);
                o.put_u32(1);
                o.extend(icon_2x2_24bpp());
                match parse_window_order(&o).unwrap() {
                    WindowOrder::Icon { icon, .. } => icon,
                    _ => unreachable!(),
                }
            },
        },
        // The small icon comes from the cache slot 1/5 the big one filled.
        WindowOrder::CachedIcon {
            id: 0x120158,
            slot: IconSlot::default(),
            cached: CachedIcon {
                cache_entry: 5,
                cache_id: 1,
            },
        },
    ]);
    let w = h.window(0x120158).unwrap();
    let big = w.big_icon.unwrap();
    assert_eq!((big.width, big.height, big.rgba.len()), (2, 2, 16));
    assert_eq!(w.icon.unwrap(), big);
    assert_eq!(
        h.take_events(),
        vec![
            RailEvent::WindowCreated(0x120158),
            RailEvent::WindowUpdated(0x120158),
            RailEvent::WindowUpdated(0x120158)
        ]
    );
}

#[test]
fn model_notify_icons_and_desktop() {
    let h = model();
    h.apply_orders(vec![
        parse_window_order(&notify_icon_order()).unwrap(),
        parse_window_order(&new_window_order()).unwrap(),
    ]);
    let s = h.state();
    let n = &s.notify_icons[&(0x1008e, 0x9cd2)];
    assert!(n.tooltip.contains("Communicator"));
    assert!(n.icon.is_some());
    h.take_events();

    // Z-order and active window.
    let mut o = hex("2e 14 00 30 00 00 04 58 01 12 00 02 58 01 12 00");
    o.extend(hex("66 00 02 00"));
    h.apply_orders(vec![parse_window_order(&o).unwrap()]);
    assert_eq!(h.state().active_window, Some(0x120158));
    assert_eq!(h.state().z_order, vec![0x120158, 0x20066]);

    // ARC began + hooked: everything is discarded and resent (3.2.5.1.8).
    h.take_events();
    h.apply_orders(vec![WindowOrder::Desktop(DesktopInfo {
        hooked: true,
        arc_began: true,
        ..Default::default()
    })]);
    let ev = h.take_events();
    assert!(ev.contains(&RailEvent::WindowDeleted(0x120158)));
    assert!(ev.contains(&RailEvent::NotifyIconDeleted {
        window_id: 0x1008e,
        icon_id: 0x9cd2
    }));
    assert_eq!(ev.last(), Some(&RailEvent::SyncStarted));
    let s = h.state();
    assert!(s.windows.is_empty() && s.notify_icons.is_empty() && s.monitored);
    assert_eq!(s.active_window, None);

    // A hooked-only order (no ARC) keeps the windows.
    h.apply_orders(vec![
        parse_window_order(&new_window_order()).unwrap(),
        WindowOrder::Desktop(DesktopInfo {
            hooked: true,
            ..Default::default()
        }),
    ]);
    assert_eq!(h.state().windows.len(), 1);
    h.apply_orders(vec![WindowOrder::DesktopNone]);
    assert!(h.state().windows.is_empty());
    assert!(!h.state().monitored);
}

// ---- scripted channel session ----

#[test]
fn channel_session_handshake_exec_result() {
    let (mut ch, h) = rail(
        RemoteApp {
            program: "||notepad".into(),
            args: "a.txt".into(),
            working_dir: String::new(),
        },
        1024,
        768,
        client_status_flags(false),
    )
    .unwrap();
    assert_eq!(ch.name(), "rail");
    let mut out = ChannelOut::default();

    // Before the handshake: nothing is processed or sent (3.1.5.2).
    ch.process(&hex("14 00 08 00 10 05 40 00"), &mut out)
        .unwrap();
    h.minimize(5);
    ch.tick(&mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!(h.state().marker_window, None);

    // Server Handshake -> Handshake, Client Information, System Parameters, Execute.
    ch.process(&handshake(0x1771), &mut out).unwrap();
    let msgs = out.take();
    assert_eq!(msgs[0], handshake(CLIENT_BUILD));
    assert_eq!(msgs[1], client_status(0x30));
    let n = default_sysparams(1024, 768).len();
    assert_eq!(&msgs[2..2 + n], &default_sysparams(1024, 768)[..]);
    let exec_pdu = &msgs[2 + n];
    assert_eq!(le16(exec_pdu, 0), TS_RAIL_ORDER_EXEC);
    assert_eq!(&exec_pdu[12..30], &utf16le("||notepad")[..]);
    assert_eq!(msgs.len(), 3 + n);
    assert_eq!(h.take_events(), vec![RailEvent::Ready { server_flags: 0 }]);

    // The UI's queued command goes out on the next tick.
    ch.tick(&mut out).unwrap();
    assert_eq!(out.take(), vec![syscommand(5, SysCommand::Minimize)]);

    // A second handshake does not relaunch the program.
    ch.process(&handshake(0x1771), &mut out).unwrap();
    assert!(out.is_empty());

    // Exec result.
    let mut res = hex("80 00 22 00 00 00 00 00 00 00 00 00 00 00 12 00");
    res.extend(utf16le("||notepad"));
    ch.process(&res, &mut out).unwrap();
    let ev = h.take_events();
    let [RailEvent::ExecResult(r)] = &ev[..] else {
        panic!("{ev:?}")
    };
    assert!(r.ok());
    assert_eq!(r.program, "||notepad");

    // Server PDUs after the handshake update the model.
    h.apply_orders(vec![parse_window_order(&new_window_order()).unwrap()]);
    h.take_events();
    let mut mm = hex("0a 00 18 00 58 01 12 00 48 06 b8 04 00 00 00 00 70 00 1b 00 4c 06 bc 04");
    ch.process(&mm, &mut out).unwrap();
    assert_eq!(
        h.window(0x120158).unwrap().min_max.unwrap().max_width,
        0x648
    );
    mm[4] = 0x99; // unknown window: ignored
    ch.process(&mm, &mut out).unwrap();
    let mut appid = hex("0F 00 08 02 58 01 12 00");
    appid.extend(utf16le("notepad"));
    appid.resize(520, 0);
    ch.process(&appid, &mut out).unwrap();
    assert_eq!(
        h.window(0x120158).unwrap().app_id.as_deref(),
        Some("notepad")
    );
    ch.process(&hex("15 00 09 00 58 01 12 00 01"), &mut out)
        .unwrap();
    assert!(h.window(0x120158).unwrap().cloaked);
    assert_eq!(h.take_events().len(), 3);
    assert!(out.is_empty());
}

#[test]
fn handshake_ex_enables_snap() {
    let (mut ch, h) = rail(
        RemoteApp {
            program: "x".into(),
            ..Default::default()
        },
        640,
        480,
        0,
    )
    .unwrap();
    let mut out = ChannelOut::default();
    h.snap_window(3, [0, 0, 10, 10]);
    ch.process(&hex("13 00 0c 00 71 17 00 00 04 00 00 00"), &mut out)
        .unwrap();
    out.take();
    h.snap_window(3, [0, 0, 10, 10]);
    ch.tick(&mut out).unwrap();
    let msgs = out.take();
    // Queued before the handshake: a plain move; after: a snap.
    assert_eq!(le16(&msgs[0], 0), TS_RAIL_ORDER_WINDOWMOVE);
    assert_eq!(le16(&msgs[1], 0), TS_RAIL_ORDER_SNAP_ARRANGE);
    assert_eq!(h.state().server_flags, Some(4));
}

#[test]
fn handle_actions_encode() {
    let h = model();
    h.set_focus(1, true);
    h.maximize(1);
    h.restore(1);
    h.close(1);
    h.sys_menu(1, 2, 3);
    h.move_window(1, [1, 2, 3, 4]);
    h.notify_icon_event(1, 2, 0x205);
    h.request_app_id(1);
    h.set_cloaked(1, false);
    let out = std::mem::take(&mut h.lock().outgoing);
    assert_eq!(
        out,
        vec![
            activate(1, true),
            syscommand(1, SysCommand::Maximize),
            syscommand(1, SysCommand::Restore),
            syscommand(1, SysCommand::Close),
            sysmenu(1, 2, 3),
            window_move(1, [1, 2, 3, 4]),
            notify_event(1, 2, 0x205),
            get_app_id(1),
            cloak(1, false),
        ]
    );
    assert_eq!(&syscommand(1, SysCommand::Close)[8..], &[0x60, 0xf0]);
}

#[test]
fn handle_exec_queues_another_program() {
    let h = model();
    let app = RemoteApp {
        program: "||calc".into(),
        ..Default::default()
    };
    h.exec(&app).unwrap();
    // A program the server could not accept is refused before sending.
    assert!(h.exec(&RemoteApp::default()).is_err());
    h.set_work_area([0, 0, 1920, 1040], [0, 1040, 1920, 1080]);
    let out = std::mem::take(&mut h.lock().outgoing);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0], exec(&app).unwrap());
    assert_eq!(le16(&out[1], 0), TS_RAIL_ORDER_SYSPARAM);
    assert_eq!(&out[1][4..8], &SPI_SETWORKAREA.to_le_bytes());
    assert_eq!(le16(&out[1], 12), 1920);
    assert_eq!(le16(&out[1], 14), 1040);
    assert_eq!(&out[2][4..8], &RAIL_SPI_TASKBARPOS.to_le_bytes());
    assert_eq!(le16(&out[2], 10), 1040);
}

// ---- connection setup (MS-RDPERP 3.2.5.1) ----

#[test]
fn client_info_sets_info_rail() {
    let flags = |rail| {
        let pdu = crate::pdu::client_info(&crate::pdu::ClientInfo {
            domain: "",
            user: "u",
            password: "",
            auto_reconnect: None,
            performance_flags: 0,
            compression: None,
            rail,
        });
        u32::from_le_bytes(pdu[8..12].try_into().unwrap())
    };
    assert_eq!(
        flags(true) & 0x8020,
        0x8000,
        "INFO_RAIL, no INFO_MAXIMIZESHELL"
    );
    assert_eq!(flags(false) & 0x8020, 0x0020);
}

#[test]
fn confirm_active_carries_rail_caps() {
    let server = WindowListCaps {
        level: TS_WINDOW_LEVEL_SUPPORTED_EX,
        icon_caches: 2,
        icon_cache_entries: 40,
    };
    let caps = client_caps(Some(&server));
    assert_eq!(
        (caps.window.icon_caches, caps.window.icon_cache_entries),
        (2, 12)
    );
    let pdu = crate::pdu::confirm_active_with(1, 2, (640, 480), 0x409, 32, false, Some(&caps));
    let rail_at = pdu.windows(4).position(|w| w == [0x17, 0, 8, 0]).unwrap();
    assert_eq!(&pdu[rail_at + 4..rail_at + 8], &[0xC1, 0, 0, 0]);
    let win_at = pdu.windows(4).position(|w| w == [0x18, 0, 11, 0]).unwrap();
    assert_eq!(&pdu[win_at + 4..win_at + 11], &[2, 0, 0, 0, 2, 12, 0]);
    // Lengths stay consistent and the plain PDU has neither set.
    assert_eq!(le16(&pdu, 0) as usize, pdu.len());
    let plain = crate::pdu::confirm_active(1, 2, 640, 480, 0x409, 32, false);
    assert_eq!(pdu.len(), plain.len() + 8 + 11);
    assert!(!plain.windows(4).any(|w| w == [0x17, 0, 8, 0]));
}

#[test]
fn demand_active_rail_caps() {
    let demand = |extra: &[u8], count: u16| {
        let mut b = Vec::new();
        b.put_u32(0x1234); // shareId
        b.put_u16(4);
        b.put_u16(0);
        b.extend(b"RDP\0");
        b.put_u16(count);
        b.put_u16(0);
        // Bitmap capability: 32 bpp, 800 x 600.
        b.put_u16(2);
        b.put_u16(28);
        let mut bm = vec![0u8; 24];
        bm[0] = 32;
        bm[8..10].copy_from_slice(&800u16.to_le_bytes());
        bm[10..12].copy_from_slice(&600u16.to_le_bytes());
        b.extend(bm);
        b.extend(extra);
        crate::pdu::parse_demand_active(&b).unwrap()
    };
    let plain = demand(&[], 1);
    assert!(!plain.supports_rail());
    let caps = hex("17 00 08 00 01 00 00 00 18 00 0b 00 02 00 00 00 03 0c 00");
    let d = demand(&caps, 3);
    assert_eq!(d.rail_support_level, Some(1));
    assert_eq!(
        d.window_list,
        Some(WindowListCaps {
            level: 2,
            icon_caches: 3,
            icon_cache_entries: 12
        })
    );
    assert!(d.supports_rail());
    let no_level = hex("17 00 08 00 00 00 00 00 18 00 0b 00 02 00 00 00 03 0c 00");
    assert!(!demand(&no_level, 3).supports_rail());
    let no_window = hex("17 00 08 00 01 00 00 00 18 00 0b 00 00 00 00 00 03 0c 00");
    assert!(!demand(&no_window, 3).supports_rail());
}
