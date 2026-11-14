use super::*;
use crate::mcs::{self, DomainPdu};
use crate::x224::{self, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX, PROTOCOL_RDP};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn spec_connection_request_and_confirm() {
    // MS-RDPBCGR 4.1.1: cookie "mstshash=eltons", requestedProtocols 0.
    let req = hex(
        "03 00 00 2c 27 e0 00 00 00 00 00 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 \
         3d 65 6c 74 6f 6e 73 0d 0a 01 00 08 00 00 00 00 00",
    );
    let cr = parse_connection_request(&req).unwrap();
    assert_eq!(cr.cookie.as_deref(), Some("Cookie: mstshash=eltons"));
    assert_eq!(cr.requested_protocols, Some(PROTOCOL_RDP));
    // 4.1.2: the confirm selecting PROTOCOL_RDP, no flags.
    assert_eq!(
        connection_confirm(PROTOCOL_RDP, 0),
        hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00")
    );
}

#[test]
fn negotiation_selects_tls_only() {
    let offer = |protocols| {
        let req = x224::connection_request("user", protocols);
        let cr = parse_connection_request(&req).unwrap();
        assert_eq!(cr.cookie.as_deref(), Some("Cookie: mstshash=user"));
        assert_eq!(cr.requested_protocols, Some(protocols));
        select_protocol(cr.requested_protocols)
    };
    // What our client and mstsc offer: TLS is chosen, NLA is not.
    let all = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX;
    assert_eq!(offer(all), Ok(PROTOCOL_SSL));
    assert_eq!(offer(PROTOCOL_SSL), Ok(PROTOCOL_SSL));
    // No TLS on offer: refused, never plaintext.
    assert_eq!(offer(PROTOCOL_RDP), Err(SSL_REQUIRED_BY_SERVER));
    assert_eq!(offer(PROTOCOL_HYBRID), Err(SSL_REQUIRED_BY_SERVER));
    assert_eq!(select_protocol(None), Err(SSL_REQUIRED_BY_SERVER));

    // The client reads the answers.
    let confirm = connection_confirm(PROTOCOL_SSL, 0);
    assert_eq!(
        x224::parse_connection_confirm(&confirm).unwrap(),
        PROTOCOL_SSL
    );
    let failure = negotiation_failure(SSL_REQUIRED_BY_SERVER);
    let err = x224::parse_connection_confirm(&failure).unwrap_err();
    assert!(err.to_string().contains("SSL_REQUIRED_BY_SERVER"), "{err}");
}

#[test]
fn connection_request_without_negotiation_or_cookie() {
    // A legacy request: cookie only.
    let mut b = vec![0, 0xE0, 0, 0, 0, 0, 0];
    b.extend(b"Cookie: mstshash=a\r\n");
    b[0] = (b.len() - 1) as u8;
    let cr = parse_connection_request(&x224::tpkt(&b)).unwrap();
    assert_eq!(cr.requested_protocols, None);
    // Negotiation request only, followed by correlation info (ignored).
    let mut b = vec![0, 0xE0, 0, 0, 0, 0, 0, 0x01, 0x08, 8, 0, 3, 0, 0, 0];
    b.push(0x06);
    b.extend([0u8; 35]);
    b[0] = (b.len() - 1) as u8;
    let cr = parse_connection_request(&x224::tpkt(&b)).unwrap();
    assert_eq!((cr.cookie, cr.requested_protocols), (None, Some(3)));
    // Malformed: errors, never panics.
    for bad in [
        vec![],
        vec![3, 0, 0, 4],
        hex("03 00 00 0b 06 d0 00 00 00 00 00"),
        hex("03 00 00 0f 0a e0 00 00 00 00 00 41 42 43 44"),
        hex("03 00 00 0b 30 e0 00 00 00 00 00"),
        hex("03 00 00 0f 0a e0 00 00 00 00 00 01 00 08 00"),
    ] {
        assert!(parse_connection_request(&bad).is_err(), "{bad:02x?}");
    }
}

fn client_settings<'a>(
    keyboard: &'a crate::KeyboardInfo,
    channels: &'a [(&'a str, u32)],
) -> crate::gcc::ClientSettings<'a> {
    crate::gcc::ClientSettings {
        width: 1600,
        height: 900,
        keyboard,
        client_name: "REMORA-PC",
        selected_protocol: PROTOCOL_SSL,
        scale: 100,
        color_depth: 32,
        connection_type: crate::ConnectionType::Lan,
        channels,
        gfx: false,
        monitors: None,
        redirected_session_id: None,
        redirected_smartcard: false,
    }
}

#[test]
fn client_conference_data_is_parsed() {
    let kb = crate::KeyboardInfo {
        layout: 0x0807,
        ..Default::default()
    };
    let channels = [("cliprdr", 0xC0A0_0000), ("rdpdr", 0x8080_0000)];
    let gcc = crate::gcc::conference_create_request(&client_settings(&kb, &channels));
    let initial = mcs::connect_initial(&gcc);
    let user_data = parse_connect_initial(&initial).unwrap();
    assert_eq!(user_data, gcc);
    let cd = parse_conference_create_request(&user_data).unwrap();
    assert_eq!((cd.width, cd.height), (1600, 900));
    assert_eq!(cd.client_name, "REMORA-PC");
    assert_eq!(cd.keyboard_layout, 0x0807);
    assert_eq!(cd.server_selected_protocol, Some(PROTOCOL_SSL));
    assert_eq!(cd.high_color_depth, Some(24));
    assert_eq!(cd.early_capability_flags & 0x0002, 0x0002, "WANT_32BPP");
    assert_eq!(
        cd.channels,
        vec![
            ("cliprdr".to_string(), 0xC0A0_0000),
            ("rdpdr".to_string(), 0x8080_0000)
        ]
    );
    assert!(!cd.message_channel);
    // Truncated data: an error.
    assert!(parse_conference_create_request(&user_data[..user_data.len() - 3]).is_err());
    assert!(parse_connect_initial(&initial[..initial.len() - 1]).is_err());
}

#[test]
fn connect_response_reaches_the_client() {
    let plan = ChannelPlan::new(3);
    assert_eq!(plan.static_channels, vec![1004, 1005, 1006]);
    assert_eq!(plan.user_channel, 1007);
    let requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX;
    let blocks = server_data_blocks(requested, &plan);
    let response = connect_response(&conference_create_response(&blocks));
    let gcc = mcs::parse_connect_response(&response).unwrap();
    let sd = crate::gcc::parse_conference_create_response(&gcc).unwrap();
    assert_eq!(sd.io_channel, IO_CHANNEL);
    assert_eq!(sd.channel_ids, vec![1004, 1005, 1006]);
    assert_eq!((sd.encryption_method, sd.encryption_level), (0, 0));
    assert_eq!(sd.version, RDP_VERSION_5_PLUS);
    assert_eq!(sd.message_channel, None);
    // Server Core Data: version, clientRequestedProtocols, flags.
    assert_eq!(&blocks[..4], &[0x01, 0x0C, 16, 0]);
    assert_eq!(le32(&blocks, 8), Some(requested));
    // An odd channel count is padded to a multiple of four bytes (2.2.1.4.4).
    let net = &blocks[blocks.len() - 16..];
    assert_eq!(&net[..4], &[0x03, 0x0C, 16, 0]);
    assert_eq!(&net[14..], &[0, 0]);
}

#[test]
fn domain_pdus_round_trip_with_the_client() {
    assert_eq!(
        parse_client_domain_pdu(&mcs::erect_domain_request()).unwrap(),
        ClientDomainPdu::ErectDomain
    );
    assert_eq!(
        parse_client_domain_pdu(&mcs::attach_user_request()).unwrap(),
        ClientDomainPdu::AttachUser
    );
    // 4.1.7: Attach User Confirm, initiator 6 (user 1007).
    assert_eq!(attach_user_confirm(1007), hex("2e 00 00 06"));
    assert_eq!(
        mcs::parse_attach_user_confirm(&attach_user_confirm(1007)).unwrap(),
        1007
    );
    let join = mcs::channel_join_request(1007, 1003);
    assert_eq!(
        parse_client_domain_pdu(&join).unwrap(),
        ClientDomainPdu::ChannelJoin {
            user_channel: 1007,
            channel: 1003
        }
    );
    // 4.1.9: Channel Join Confirm for the I/O channel.
    assert_eq!(
        channel_join_confirm(1007, 1003),
        hex("3e 00 00 06 03 eb 03 eb")
    );
    assert_eq!(
        mcs::parse_channel_join_confirm(&channel_join_confirm(1007, 1003)).unwrap(),
        1003
    );
    assert!(mcs::parse_channel_join_confirm(&channel_join_refused(1007, 1010)).is_err());

    let payload = vec![0x5A; 300];
    let send = mcs::send_data_request(1007, 1003, &payload);
    assert_eq!(
        parse_client_domain_pdu(&send).unwrap(),
        ClientDomainPdu::SendData {
            user_channel: 1007,
            channel: 1003,
            data: &payload
        }
    );
    match mcs::parse_domain_pdu(&send_data_indication(1003, &payload)).unwrap() {
        DomainPdu::SendDataIndication { channel, data } => {
            assert_eq!((channel, data), (1003, &payload[..]))
        }
        _ => panic!("expected a Send Data Indication"),
    }
    // The client's ultimatum (rn-user-requested) and the server's
    // (rn-provider-initiated).
    assert_eq!(
        parse_client_domain_pdu(&mcs::disconnect_provider_ultimatum()).unwrap(),
        ClientDomainPdu::Disconnect { reason: 3 }
    );
    assert!(matches!(
        mcs::parse_domain_pdu(&disconnect_provider_ultimatum()).unwrap(),
        DomainPdu::DisconnectProviderUltimatum { reason: 1 }
    ));
    // Truncated PDUs are errors.
    assert!(parse_client_domain_pdu(&[]).is_err());
    assert!(parse_client_domain_pdu(&join[..3]).is_err());
    assert!(parse_client_domain_pdu(&send[..send.len() - 1]).is_err());
}
