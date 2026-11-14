use super::*;
use crate::mcs::{self, DomainPdu};
use crate::x224::{PROTOCOL_HYBRID, PROTOCOL_SSL};

const USER: u16 = 1005;

fn session() -> ServerSession {
    ServerSession::new(SessionConfig {
        width: 800,
        height: 600,
        requested_protocols: PROTOCOL_SSL | PROTOCOL_HYBRID,
        selected_protocol: PROTOCOL_SSL,
    })
}

fn io(data: &[u8]) -> Vec<u8> {
    x224::data(&mcs::send_data_request(USER, connect::IO_CHANNEL, data))
}

/// The I/O channel payloads among the server's output.
fn io_out(s: &mut ServerSession) -> Vec<Vec<u8>> {
    s.take_output()
        .iter()
        .filter_map(
            |f| match mcs::parse_domain_pdu(x224::data_payload(f).ok()?).ok()? {
                DomainPdu::SendDataIndication { channel, data } => {
                    assert_eq!(channel, connect::IO_CHANNEL);
                    Some(data.to_vec())
                }
                _ => None,
            },
        )
        .collect()
}

/// Runs the client side up to the Logon event, with one static channel.
fn up_to_logon(s: &mut ServerSession) -> Credentials {
    let kb = crate::KeyboardInfo::default();
    let channels = [("cliprdr", 0xC0A0_0000)];
    let settings = crate::gcc::ClientSettings {
        width: 1024,
        height: 768,
        keyboard: &kb,
        client_name: "T",
        selected_protocol: PROTOCOL_SSL,
        scale: 100,
        color_depth: 32,
        connection_type: crate::ConnectionType::Lan,
        channels: &channels,
        gfx: false,
        monitors: None,
        redirected_session_id: None,
        redirected_smartcard: false,
    };
    let initial = mcs::connect_initial(&crate::gcc::conference_create_request(&settings));
    assert!(s.handle(&x224::data(&initial)).unwrap().is_empty());
    let out = s.take_output();
    let gcc = mcs::parse_connect_response(x224::data_payload(&out[0]).unwrap()).unwrap();
    let sd = crate::gcc::parse_conference_create_response(&gcc).unwrap();
    assert_eq!(sd.channel_ids, vec![1004]);

    s.handle(&x224::data(&mcs::erect_domain_request())).unwrap();
    s.handle(&x224::data(&mcs::attach_user_request())).unwrap();
    let out = s.take_output();
    let user = mcs::parse_attach_user_confirm(x224::data_payload(&out[0]).unwrap()).unwrap();
    assert_eq!(user, USER);
    for ch in [USER, connect::IO_CHANNEL, 1004] {
        s.handle(&x224::data(&mcs::channel_join_request(USER, ch)))
            .unwrap();
        let out = s.take_output();
        let joined = mcs::parse_channel_join_confirm(x224::data_payload(&out[0]).unwrap());
        assert_eq!(joined.unwrap(), ch);
    }
    // An unknown channel is refused, not fatal.
    s.handle(&x224::data(&mcs::channel_join_request(USER, 1200)))
        .unwrap();
    let out = s.take_output();
    assert!(mcs::parse_channel_join_confirm(x224::data_payload(&out[0]).unwrap()).is_err());

    let info = crate::pdu::client_info(&crate::pdu::ClientInfo {
        domain: "",
        user: "alice",
        password: "pw",
        auto_reconnect: None,
        performance_flags: 0,
        compression: None,
        rail: false,
    });
    let mut events = s.handle(&io(&info)).unwrap();
    assert_eq!(events.len(), 1);
    match events.remove(0) {
        Event::Logon(c) => c,
        e => panic!("expected logon, got {e:?}"),
    }
}

#[test]
fn full_sequence_reaches_active_and_reports_input() {
    let mut s = session();
    let creds = up_to_logon(&mut s);
    assert_eq!(
        (creds.user.as_str(), creds.password.as_str()),
        ("alice", "pw")
    );
    // Nothing is sent before the decision; bitmaps are not sent before activation.
    assert!(s.take_output().is_empty());
    s.accept_logon().unwrap();
    let out = io_out(&mut s);
    assert_eq!(out.len(), 2);
    crate::pdu::process_license(&out[0]).unwrap();
    let (_, body) = crate::pdu::split_share_control(&out[1]).unwrap()[0];
    let demand = crate::pdu::parse_demand_active(body).unwrap();
    assert_eq!((demand.width, demand.height), (800, 600));

    // The client's Confirm Active and finalization, as our client sends them.
    let kb = crate::KeyboardInfo::default();
    let confirm =
        crate::pdu::confirm_active_with(demand.share_id, USER, (800, 600), &kb, 32, false, None);
    assert!(s.handle(&io(&confirm)).unwrap().is_empty());
    assert!(!s.is_active());
    let data = |ty, body: &[u8]| io(&crate::pdu::share_data(demand.share_id, USER, ty, body));
    s.handle(&data(31, &crate::pdu::synchronize())).unwrap();
    s.handle(&data(
        20,
        &crate::pdu::control(crate::pdu::CTRLACTION_COOPERATE),
    ))
    .unwrap();
    s.handle(&data(
        20,
        &crate::pdu::control(crate::pdu::CTRLACTION_REQUEST_CONTROL),
    ))
    .unwrap();
    let events = s.handle(&data(39, &crate::pdu::font_list())).unwrap();
    assert!(matches!(events[..], [Event::Active]));
    assert!(s.is_active());
    // Synchronize, Cooperate, Granted Control, Font Map, in that order.
    let types: Vec<u8> = io_out(&mut s)
        .iter()
        .map(|d| {
            let (_, body) = crate::pdu::split_share_control(d).unwrap()[0];
            crate::pdu::parse_share_data(body).unwrap().0
        })
        .collect();
    assert_eq!(types, [31, 20, 20, 40]);

    // Fast-path input after activation.
    let input = crate::input::fastpath_input(&[crate::InputEvent::mouse_move(5, 6)]);
    match &s.handle(&input).unwrap()[..] {
        [Event::Input(i)] => assert_eq!(
            i[..],
            [ClientInput::Mouse {
                flags: crate::input::PTRFLAGS_MOVE,
                x: 5,
                y: 6
            }]
        ),
        e => panic!("{e:?}"),
    }
    // Refresh Rect beyond the desktop is clipped.
    let refresh = data(33, &crate::pdu::refresh_rect(1000, 700));
    match &s.handle(&refresh).unwrap()[..] {
        [Event::Refresh(r)] => assert_eq!(r[..], [Rect::new(0, 0, 800, 600)]),
        e => panic!("{e:?}"),
    }
    // Suppress Output off and on.
    match &s.handle(&data(35, &[0, 0, 0, 0])).unwrap()[..] {
        [Event::Output { allowed: false, .. }] => {}
        e => panic!("{e:?}"),
    }
    // Bitmaps go out as fast-path PDUs now.
    let px = vec![0u8; 64 * 64 * 4];
    s.send_tiles(&[Tile {
        pixels: &px,
        stride: 64 * 4,
        image_width: 64,
        image_height: 64,
        x: 0,
        y: 0,
        w: 64,
        h: 64,
    }]);
    let out = s.take_output();
    assert!(!out.is_empty() && out.iter().all(|p| p[0] == 0x00));

    // The client's ultimatum ends the session.
    let bye = x224::data(&mcs::disconnect_provider_ultimatum());
    assert!(matches!(&s.handle(&bye).unwrap()[..], [Event::Closed(_)]));
    assert!(s.is_closed());
}

#[test]
fn rejected_logon_sends_error_info_and_disconnects() {
    let mut s = session();
    let _ = up_to_logon(&mut s);
    s.reject_logon(spdu::ERRINFO_SERVER_DENIED_CONNECTION);
    let out = s.take_output();
    assert_eq!(out.len(), 2);
    let payload = x224::data_payload(&out[0]).unwrap();
    let DomainPdu::SendDataIndication { data, .. } = mcs::parse_domain_pdu(payload).unwrap() else {
        panic!("expected Set Error Info");
    };
    let (_, body) = crate::pdu::split_share_control(data).unwrap()[0];
    let (ty, code) = crate::pdu::parse_share_data(body).unwrap();
    assert_eq!((ty, code), (47, &[7, 0, 0, 0][..]));
    assert!(matches!(
        mcs::parse_domain_pdu(x224::data_payload(&out[1]).unwrap()).unwrap(),
        DomainPdu::DisconnectProviderUltimatum { .. }
    ));
    assert!(s.is_closed());
    // No Demand Active can follow, and later input is dropped.
    assert!(s.accept_logon().is_err());
    let input = crate::input::fastpath_input(&[crate::InputEvent::mouse_move(1, 1)]);
    assert!(s.handle(&input).unwrap().is_empty());
}

#[test]
fn out_of_order_pdus_are_errors() {
    let mut s = session();
    // Attach User before Connect Initial.
    assert!(s.handle(&x224::data(&mcs::attach_user_request())).is_err());
    // Input before logon.
    let mut s = session();
    let _ = up_to_logon(&mut s);
    let input = crate::input::fastpath_input(&[crate::InputEvent::mouse_move(1, 1)]);
    assert!(s.handle(&input).is_err());
    // A client whose core data names another protocol (3.3.5.3.3).
    let mut s = ServerSession::new(SessionConfig {
        width: 800,
        height: 600,
        requested_protocols: PROTOCOL_SSL,
        selected_protocol: PROTOCOL_HYBRID,
    });
    let kb = crate::KeyboardInfo::default();
    let settings = crate::gcc::ClientSettings {
        width: 800,
        height: 600,
        keyboard: &kb,
        client_name: "T",
        selected_protocol: PROTOCOL_SSL,
        scale: 100,
        color_depth: 32,
        connection_type: crate::ConnectionType::Lan,
        channels: &[],
        gfx: false,
        monitors: None,
        redirected_session_id: None,
        redirected_smartcard: false,
    };
    let initial = mcs::connect_initial(&crate::gcc::conference_create_request(&settings));
    assert!(s.handle(&x224::data(&initial)).is_err());
}
