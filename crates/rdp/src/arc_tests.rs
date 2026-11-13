//! Tests for auto-reconnect (MS-RDPBCGR 5.5): Save Session Info parsing with
//! the section 4.3 example bytes, the ARC_SC / ARC_CS packets and the Client
//! Info PDU with and without the cookie.

use super::*;

/// The 18-byte share control + share data header of a 4.3.x example.
fn share_header(total: u16) -> Vec<u8> {
    let [lo, hi] = total.to_le_bytes();
    vec![
        lo, hi, 0x17, 0x00, 0xea, 0x03, // share control: length, PDUTYPE_DATAPDU, source 1002
        0xea, 0x03, 0x02, 0x00, 0x00, 0x01, lo, hi, // shareId, pad1, STREAM_LOW, length
        0x26, 0x00, 0x00, 0x00, // PDUTYPE2_SAVE_SESSION_INFO, no compression
    ]
}

/// Splits a share control PDU the way the session loop does and returns the
/// Save Session Info payload.
fn payload_of(pdu: &[u8]) -> Vec<u8> {
    let parts = split_share_control(pdu).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].0, PDUTYPE_DATA);
    let (ty, payload) = parse_share_data(parts[0].1).unwrap();
    assert_eq!(ty, PDUTYPE2_SAVE_SESSION_INFO);
    payload.to_vec()
}

const SPEC_RANDOM: [u8; 16] = [
    0xa8, 0x02, 0xe7, 0x25, 0xe2, 0x4c, 0x82, 0xb7, 0x52, 0xa5, 0x53, 0x50, 0x34, 0x98, 0xa1, 0xa8,
];

/// 4.3.1: Logon Info Version 2 (decrypted, 624 bytes).
fn spec_logon_long() -> Vec<u8> {
    let mut p = share_header(0x0270);
    p.extend([0x01, 0x00, 0x00, 0x00]); // INFOTYPE_LOGON_LONG
    p.extend([0x01, 0x00]); // Version
    p.extend([0x12, 0x00, 0x00, 0x00]); // Size
    p.extend([0x02, 0x00, 0x00, 0x00]); // SessionId
    p.extend([0x0c, 0x00, 0x00, 0x00]); // cbDomain
    p.extend([0x0e, 0x00, 0x00, 0x00]); // cbUserName
    p.extend([0u8; 558]); // Pad
    p.extend([
        0x4e, 0x00, 0x54, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x00, 0x00,
    ]);
    p.extend([
        0x65, 0x00, 0x6c, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x73, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(p.len(), 0x0270);
    p
}

/// 4.3.2: Plain Notify (decrypted, 598 bytes).
fn spec_plain_notify() -> Vec<u8> {
    let mut p = share_header(0x0256);
    p.extend([0x02, 0x00, 0x00, 0x00]); // INFOTYPE_LOGON_PLAINNOTIFY
    p.extend([0u8; 576]);
    assert_eq!(p.len(), 0x0256);
    p
}

/// 4.3.3: Logon Info Extended with an auto-reconnect cookie (decrypted, 630 bytes).
fn spec_logon_extended() -> Vec<u8> {
    let mut p = share_header(0x0276);
    p.extend([0x03, 0x00, 0x00, 0x00]); // INFOTYPE_LOGON_EXTENDED_INFO
    p.extend([0x26, 0x00]); // Length = 38
    p.extend([0x01, 0x00, 0x00, 0x00]); // LOGON_EX_AUTORECONNECTCOOKIE
    p.extend([0x1c, 0x00, 0x00, 0x00]); // cbFieldData
    p.extend([0x1c, 0x00, 0x00, 0x00]); // cbLen
    p.extend([0x01, 0x00, 0x00, 0x00]); // Version
    p.extend([0x02, 0x00, 0x00, 0x00]); // LogonId
    p.extend(SPEC_RANDOM);
    p.extend([0u8; 570]); // Pad
    assert_eq!(p.len(), 0x0276);
    p
}

#[test]
fn save_session_info_logon_long_spec_4_3_1() {
    let info = parse_save_session_info(&payload_of(&spec_logon_long())).unwrap();
    assert_eq!(info, SaveSessionInfo::LogonLong { session_id: 2 });
}

#[test]
fn save_session_info_plain_notify_spec_4_3_2() {
    let info = parse_save_session_info(&payload_of(&spec_plain_notify())).unwrap();
    assert_eq!(info, SaveSessionInfo::PlainNotify);
}

#[test]
fn save_session_info_extended_cookie_spec_4_3_3() {
    let info = parse_save_session_info(&payload_of(&spec_logon_extended())).unwrap();
    assert_eq!(
        info,
        SaveSessionInfo::Extended {
            cookie: Some(AutoReconnectCookie {
                logon_id: 2,
                random: SPEC_RANDOM,
            }),
            errors: None,
        }
    );
}

#[test]
fn save_session_info_logon_v1() {
    // 2.2.10.1.1.1 (no spec example): cbDomain, Domain[52], cbUserName,
    // UserName[512], SessionId = 576 bytes.
    let mut p = vec![0x00, 0x00, 0x00, 0x00]; // INFOTYPE_LOGON
    p.extend([0x0c, 0x00, 0x00, 0x00]);
    let mut domain = [0u8; 52];
    domain[..12].copy_from_slice(&utf16le_z("NTDEV"));
    p.extend(domain);
    p.extend([0x0e, 0x00, 0x00, 0x00]);
    let mut user = [0u8; 512];
    user[..14].copy_from_slice(&utf16le_z("eltons"));
    p.extend(user);
    p.extend([0x07, 0x00, 0x00, 0x00]); // SessionId
    assert_eq!(p.len(), 4 + 576);
    assert_eq!(
        parse_save_session_info(&p).unwrap(),
        SaveSessionInfo::Logon { session_id: 7 }
    );
}

#[test]
fn save_session_info_extended_errors_and_cookie() {
    // 2.2.10.1.1.4: both fields, cookie first, then TS_LOGON_ERRORS_INFO.
    let mut p = vec![0x03, 0x00, 0x00, 0x00];
    p.extend([0x32, 0x00]); // Length = 2 + 4 + 32 + 12 = 50
    p.extend([0x03, 0x00, 0x00, 0x00]); // cookie | logon errors
    p.extend([
        0x1c, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ]);
    p.extend([0x05, 0x00, 0x00, 0x00]); // LogonId 5
    p.extend(SPEC_RANDOM);
    p.extend([0x08, 0x00, 0x00, 0x00]); // cbFieldData
    p.extend([0xfe, 0xff, 0xff, 0xff]); // LOGON_MSG_SESSION_CONTINUE
    p.extend([0x05, 0x00, 0x00, 0x00]); // session id
    p.extend([0u8; 570]);
    assert_eq!(
        parse_save_session_info(&p).unwrap(),
        SaveSessionInfo::Extended {
            cookie: Some(AutoReconnectCookie {
                logon_id: 5,
                random: SPEC_RANDOM,
            }),
            errors: Some(LogonErrors {
                notification_type: 0xFFFF_FFFE,
                notification_data: 5,
            }),
        }
    );

    // Logon errors alone: the field after the (absent) cookie is read.
    let mut p = vec![0x03, 0x00, 0x00, 0x00, 0x12, 0x00, 0x02, 0x00, 0x00, 0x00];
    p.extend([
        0x08, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(
        parse_save_session_info(&p).unwrap(),
        SaveSessionInfo::Extended {
            cookie: None,
            errors: Some(LogonErrors {
                notification_type: 0xFFFF_FFFF,
                notification_data: 0,
            }),
        }
    );
}

#[test]
fn save_session_info_unknown_type_and_truncation() {
    assert_eq!(
        parse_save_session_info(&[0x09, 0, 0, 0]).unwrap(),
        SaveSessionInfo::Unknown(9)
    );
    // Every truncation of every sample is an error, never a panic.
    for pdu in [
        spec_logon_long(),
        spec_plain_notify(),
        spec_logon_extended(),
    ] {
        let payload = payload_of(&pdu);
        let needed = match payload[0] {
            3 => 4 + 2 + 4 + 4 + 28, // the 570-byte Pad is not required
            _ => payload.len(),
        };
        for n in 0..needed {
            assert!(parse_save_session_info(&payload[..n]).is_err(), "len {n}");
        }
    }
    // A cookie field whose cbFieldData overruns the PDU.
    let p = [
        3, 0, 0, 0, 0x26, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x1c, 0, 0, 0,
    ];
    assert!(parse_save_session_info(&p).is_err());
}

#[test]
fn arc_sc_packet_rejects_bad_length_and_version() {
    let mut good = vec![0x1c, 0, 0, 0, 0x01, 0, 0, 0, 0x02, 0, 0, 0];
    good.extend(SPEC_RANDOM);
    assert_eq!(
        AutoReconnectCookie::parse(&good).unwrap(),
        AutoReconnectCookie {
            logon_id: 2,
            random: SPEC_RANDOM
        }
    );
    let mut bad_len = good.clone();
    bad_len[0] = 0x1d;
    assert!(AutoReconnectCookie::parse(&bad_len).is_err());
    let mut bad_version = good.clone();
    bad_version[4] = 0x02;
    assert!(AutoReconnectCookie::parse(&bad_version).is_err());
    assert!(AutoReconnectCookie::parse(&good[..27]).is_err());
}

#[test]
fn arc_cs_packet_with_enhanced_security_client_random() {
    // 5.5: HMAC-MD5(ArcRandomBits, 32 zero bytes). Expected verifier from an
    // independent implementation (.NET HMACMD5) over the 4.3.3 cookie.
    let cookie = AutoReconnectCookie {
        logon_id: 2,
        random: SPEC_RANDOM,
    };
    let packet = cookie.client_packet(&ENHANCED_SECURITY_CLIENT_RANDOM);
    assert_eq!(
        packet,
        [
            0x1c, 0x00, 0x00, 0x00, // cbLen
            0x01, 0x00, 0x00, 0x00, // Version
            0x02, 0x00, 0x00, 0x00, // LogonId
            0x42, 0xb7, 0x9a, 0x48, 0x16, 0xea, 0xda, 0xd6, // SecurityVerifier
            0x34, 0xd6, 0x8c, 0x5e, 0xdc, 0xe8, 0x64, 0xb9,
        ]
    );
    // The client random is the HMAC data, not ignored.
    let mut random = [0u8; 32];
    for (i, b) in random.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    assert_eq!(
        cookie.security_verifier(&random),
        [
            0x5e, 0xa5, 0x55, 0x88, 0xea, 0x6d, 0x64, 0x4a, 0x4d, 0x1b, 0x5c, 0x9a, 0x3f, 0x98,
            0x44, 0x4a,
        ]
    );
}

#[test]
fn cookie_debug_hides_the_random_bits() {
    let cookie = AutoReconnectCookie {
        logon_id: 2,
        random: SPEC_RANDOM,
    };
    let text = format!("{cookie:?}");
    assert!(text.contains("logon_id: 2"), "{text}");
    assert!(text.contains("redacted"), "{text}");
    for b in SPEC_RANDOM {
        assert!(!text.contains(&b.to_string()) || b == 2, "{text}");
    }
    assert!(!text.contains("168"), "{text}"); // 0xa8, the first random byte
}

/// Client Info PDU for domain "D", user "u", password "p".
fn info(auto_reconnect: Option<[u8; ARC_PACKET_LEN]>) -> Vec<u8> {
    client_info(&ClientInfo {
        domain: "D",
        user: "u",
        password: "p",
        auto_reconnect,
    })
}

// Security header 4, CodePage 4, flags 4, five cb fields 10, strings 4+4+4+2+2,
// extended info: family 2, cbClientAddress 2, "0.0.0.0\0" 16, cbClientDir 2,
// "C:\rdp-rs\0" 20, time zone 172, clientSessionId 4, performanceFlags 4,
// cbAutoReconnectCookie 2.
const INFO_LEN: usize = 4 + 4 + 4 + 10 + 16 + 2 + 2 + 16 + 2 + 20 + 172 + 4 + 4 + 2;

#[test]
fn client_info_without_cookie() {
    let pdu = info(None);
    assert_eq!(INFO_LEN, 262);
    assert_eq!(pdu.len(), INFO_LEN);
    assert_eq!(&pdu[..4], &[0x40, 0x00, 0x00, 0x00]);
    // INFO_AUTOLOGON stays set: the server falls back to these credentials.
    let flags = u32::from_le_bytes(pdu[8..12].try_into().unwrap());
    assert_eq!(flags & 0x0008, 0x0008);
    // performanceFlags, then cbAutoReconnectCookie = 0 ends the PDU.
    assert_eq!(&pdu[INFO_LEN - 6..], &[0x07, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn client_info_with_cookie() {
    let cookie = AutoReconnectCookie {
        logon_id: 2,
        random: SPEC_RANDOM,
    };
    let arc = cookie.client_packet(&ENHANCED_SECURITY_CLIENT_RANDOM);
    let pdu = info(Some(arc));
    assert_eq!(pdu.len(), INFO_LEN + ARC_PACKET_LEN);
    // Everything before cbAutoReconnectCookie is unchanged.
    assert_eq!(&pdu[..INFO_LEN - 2], &info(None)[..INFO_LEN - 2]);
    // cbAutoReconnectCookie = 0x001C at offset 260, ARC_CS_PRIVATE_PACKET at 262.
    assert_eq!(&pdu[INFO_LEN - 2..INFO_LEN], &[0x1c, 0x00]);
    assert_eq!(&pdu[INFO_LEN..], &arc);
    assert_eq!(
        &pdu[INFO_LEN..INFO_LEN + 12],
        &[0x1c, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]
    );
}
