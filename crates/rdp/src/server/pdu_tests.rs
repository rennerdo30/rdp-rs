use super::*;
use crate::pdu::{ClientInfo, PDUTYPE_DATA, split_share_control};

fn only_pdu(data: &[u8]) -> (u16, Vec<u8>) {
    let parts = split_share_control(data).unwrap();
    assert_eq!(parts.len(), 1);
    (parts[0].0, parts[0].1.to_vec())
}

#[test]
fn client_info_credentials_are_read() {
    let pdu = crate::pdu::client_info(&ClientInfo {
        domain: "WORK",
        user: "alice",
        password: "s3cret \u{dc}ber",
        auto_reconnect: None,
        performance_flags: 0,
        compression: None,
        rail: false,
    });
    let c = parse_client_info(&pdu).unwrap();
    assert_eq!(
        (c.user.as_str(), c.domain.as_str(), c.password.as_str()),
        ("alice", "WORK", "s3cret \u{dc}ber")
    );
    assert_ne!(c.flags & 0x0008, 0, "INFO_AUTOLOGON");
    let shown = format!("{c:?}");
    assert!(
        shown.contains("alice") && !shown.contains("s3cret"),
        "{shown}"
    );

    // An ANSI Client Info (no INFO_UNICODE): one-byte terminators.
    let mut a = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0x08, 0, 0, 0];
    for cb in [0u16, 3, 2, 0, 0] {
        a.extend(cb.to_le_bytes());
    }
    a.extend(b"\0bob\0pw\0\0\0");
    let c = parse_client_info(&a).unwrap();
    assert_eq!((c.user.as_str(), c.password.as_str()), ("bob", "pw"));

    // Truncated, or not a Client Info PDU: errors.
    assert!(parse_client_info(&pdu[..30]).is_err());
    assert!(parse_client_info(&[0x80, 0, 0, 0]).is_err());
}

#[test]
fn valid_client_licensing_ends_licensing() {
    let pdu = license_valid_client();
    // MS-RDPBCGR 4.1.12 (without its MCS and X.224 headers).
    assert_eq!(
        pdu,
        [
            0x80, 0x00, 0x00, 0x00, 0xFF, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00
        ]
    );
    let mut lic = crate::license::Licensing::new(None, "alice", "PC");
    let (send, step) = lic.process(&pdu);
    assert!(send.is_empty());
    assert_eq!(step.unwrap(), crate::license::Step::Done);
    crate::pdu::process_license(&pdu).unwrap();
}

#[test]
fn demand_active_is_read_by_the_client() {
    let pdu = demand_active(0x0001_03EA, 1920, 1080);
    assert_eq!(
        u16::from_le_bytes([pdu[0], pdu[1]]) as usize,
        pdu.len(),
        "totalLength"
    );
    let (ty, body) = only_pdu(&pdu);
    assert_eq!(ty, PDUTYPE_DEMANDACTIVE);
    let da = crate::pdu::parse_demand_active(&body).unwrap();
    assert_eq!(
        (da.share_id, da.width, da.height, da.bpp),
        (0x0001_03EA, 1920, 1080, 32)
    );
    assert_eq!(da.input_flags, Some(SERVER_INPUT_FLAGS));
    assert!(!da.frame_ack && !da.bitmap_cache_host && !da.supports_rail());
    // lengthCombinedCapabilities covers numberCapabilities, pad and the
    // sets: the body is shareId, two lengths, "RDP\0", the sets, sessionId.
    let combined = u16::from_le_bytes([body[6], body[7]]) as usize;
    assert_eq!(4 + 2 + 2 + 4 + combined + 4, body.len());
    assert_eq!(
        u16::from_le_bytes([body[12], body[13]]),
        9,
        "capability sets"
    );
}

#[test]
fn confirm_active_from_the_client_is_read() {
    let kb = crate::KeyboardInfo::default();
    let pdu = crate::pdu::confirm_active_with(0x0001_03EA, 1007, (1280, 800), &kb, 32, false, None);
    let (ty, body) = only_pdu(&pdu);
    assert_eq!(ty, crate::pdu::PDUTYPE_CONFIRMACTIVE);
    let ca = parse_confirm_active(&body).unwrap();
    assert_eq!(ca.share_id, 0x0001_03EA);
    assert_eq!(ca.originator, crate::pdu::SERVER_CHANNEL_ID);
    assert_eq!((ca.width, ca.height, ca.bpp), (1280, 800, 32));
    assert!(ca.fastpath_output());
    assert_eq!(ca.input_flags, 0x003D);
    assert_eq!(
        ca.max_request_size,
        Some(crate::pdu::max_request_size(1280, 800))
    );
    assert!(parse_confirm_active(&body[..body.len() - 5]).is_err());
}

#[test]
fn client_finalization_pdus_are_read() {
    let share = 0x0001_03EA;
    let parse = |ty, body: &[u8]| {
        let (pty, b) = only_pdu(&crate::pdu::share_data(share, 1007, ty, body));
        assert_eq!(pty, PDUTYPE_DATA);
        let (id, pdu) = parse_client_share_data(&b).unwrap();
        assert_eq!(id, share);
        pdu
    };
    assert_eq!(
        parse(PDUTYPE2_SYNCHRONIZE, &crate::pdu::synchronize()),
        ClientShareData::Synchronize
    );
    assert_eq!(
        parse(
            PDUTYPE2_CONTROL,
            &crate::pdu::control(crate::pdu::CTRLACTION_COOPERATE)
        ),
        ClientShareData::Control(CTRLACTION_COOPERATE)
    );
    assert_eq!(
        parse(
            PDUTYPE2_CONTROL,
            &crate::pdu::control(crate::pdu::CTRLACTION_REQUEST_CONTROL)
        ),
        ClientShareData::Control(CTRLACTION_REQUEST_CONTROL)
    );
    assert_eq!(
        parse(PDUTYPE2_FONTLIST, &crate::pdu::font_list()),
        ClientShareData::FontList
    );
    assert_eq!(
        parse(PDUTYPE2_REFRESH_RECT, &crate::pdu::refresh_rect(800, 600)),
        ClientShareData::RefreshRect(vec![Rect::new(0, 0, 800, 600)])
    );
    // Suppress Output (2.2.11.3.1): suppress, then allow for a rectangle.
    assert_eq!(
        parse(PDUTYPE2_SUPPRESS_OUTPUT, &[0, 0, 0, 0]),
        ClientShareData::SuppressOutput(None)
    );
    assert_eq!(
        parse(
            PDUTYPE2_SUPPRESS_OUTPUT,
            &[1, 0, 0, 0, 0, 0, 0, 0, 0x1F, 0x03, 0x57, 0x02]
        ),
        ClientShareData::SuppressOutput(Some(Rect::new(0, 0, 800, 600)))
    );
    assert_eq!(
        parse(PDUTYPE2_SHUTDOWN_REQUEST, &[]),
        ClientShareData::ShutdownRequest
    );
    assert_eq!(
        parse(PDUTYPE2_INPUT, &[0, 0, 0, 0]),
        ClientShareData::Input(Vec::new())
    );
    assert_eq!(parse(99, &[1, 2]), ClientShareData::Other(99));
    // An empty rectangle and truncated bodies are errors.
    let bad = crate::pdu::share_data(share, 1007, PDUTYPE2_REFRESH_RECT, &[1, 0, 0, 0, 5, 0]);
    assert!(parse_client_share_data(&only_pdu(&bad).1).is_err());
    let bad = crate::pdu::share_data(
        share,
        1007,
        PDUTYPE2_REFRESH_RECT,
        &[1, 0, 0, 0, 5, 0, 0, 0, 4, 0, 9, 0],
    );
    assert!(parse_client_share_data(&only_pdu(&bad).1).is_err());
    // Compressed share data (compressedType PACKET_COMPRESSED) is refused.
    let (_, mut body) = only_pdu(&crate::pdu::share_data(share, 1007, 31, &[1, 0, 0, 0]));
    body[9] = 0x20;
    assert!(parse_client_share_data(&body).is_err());
}

#[test]
fn server_finalization_pdus_match_the_spec() {
    // 4.1.19 to 4.1.22 (bodies after the share data header).
    assert_eq!(synchronize(1007), [0x01, 0x00, 0xEF, 0x03]);
    assert_eq!(
        control(CTRLACTION_COOPERATE, 0, 0),
        [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        control(CTRLACTION_GRANTED_CONTROL, 1007, 0x03EA),
        [0x02, 0x00, 0xEF, 0x03, 0xEA, 0x03, 0x00, 0x00]
    );
    assert_eq!(font_map(), [0, 0, 0, 0, 0x03, 0, 0x04, 0]);
    let reply = |pdu| {
        let (_, body) = only_pdu(&finalization_reply(0x103EA, 1007, &pdu));
        let (ty, payload) = crate::pdu::parse_share_data(&body).unwrap();
        (ty, payload.to_vec())
    };
    assert_eq!(
        reply(ClientShareData::Synchronize),
        (PDUTYPE2_SYNCHRONIZE, synchronize(1007))
    );
    assert_eq!(
        reply(ClientShareData::Control(CTRLACTION_REQUEST_CONTROL)),
        (
            PDUTYPE2_CONTROL,
            control(CTRLACTION_GRANTED_CONTROL, 1007, 0x03EA)
        )
    );
    assert_eq!(
        reply(ClientShareData::FontList),
        (PDUTYPE2_FONTMAP, font_map())
    );
    assert!(finalization_reply(1, 1007, &ClientShareData::PersistentKeyList).is_empty());
    let (_, body) = only_pdu(&error_info_pdu(0x103EA, ERRINFO_SERVER_DENIED_CONNECTION));
    let (ty, payload) = crate::pdu::parse_share_data(&body).unwrap();
    assert_eq!((ty, payload), (PDUTYPE2_SET_ERROR_INFO, &[7, 0, 0, 0][..]));
}
