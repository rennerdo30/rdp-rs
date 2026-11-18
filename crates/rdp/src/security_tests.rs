//! Standard RDP Security (MS-RDPBCGR 5.3): key derivation, MAC and key
//! update against reference vectors, the spec's certificate (4.1.4) and
//! Security Exchange PDU (4.1.9), and header round trips through a
//! simulated server (the client's keys with encryption and decryption
//! swapped, 5.3.5.1).

use super::*;
use crate::fastpath::Reassembler;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const CLIENT_RANDOM: [u8; 32] = {
    let mut r = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        r[i] = i as u8;
        i += 1;
    }
    r
};
const SERVER_RANDOM: [u8; 32] = {
    let mut r = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        r[i] = 0xA0 + i as u8;
        i += 1;
    }
    r
};

const STRENGTHS: [KeyStrength; 3] = [
    KeyStrength::Bits40,
    KeyStrength::Bits56,
    KeyStrength::Bits128,
];

/// The reference values below come from an independent Python
/// implementation of 5.3.5.1, 5.3.6.1, 5.3.6.1.1 and 5.3.7.1 (hashlib MD5
/// and SHA-1, a textbook RC4), for client random 00..1f and server random
/// a0..bf. The spec's own traces (4.1.9-4.1.11) do not publish their
/// client random, so they cannot pin the keys.
#[test]
fn session_keys_match_the_reference() {
    let want = [
        ("d1269e255f0b4401", "d1269efca4772bce", "d1269e05fdc6f505"),
        ("d1cbab255f0b4401", "d154fffca4772bce", "d1047705fdc6f505"),
        (
            "d3cbab255f0b440131261fea5b917b0e",
            "9854fffca4772bce1de4814e332130d1",
            "ad047705fdc6f5058d7a221b5ccf984c",
        ),
    ];
    for (s, (mac, enc, dec)) in STRENGTHS.into_iter().zip(want) {
        let k = session_keys(&CLIENT_RANDOM, &SERVER_RANDOM, s);
        assert_eq!(
            (hx(&k.mac), hx(&k.encrypt), hx(&k.decrypt)),
            (mac.into(), enc.into(), dec.into()),
            "{s:?}"
        );
    }
}

#[test]
fn key_update_matches_the_reference() {
    let want = [
        "d1269e88fa17ff30",
        "d1cfaf4225935eba",
        "97d9d889b527b7e6ffc0538f1765b746",
    ];
    for (s, want) in STRENGTHS.into_iter().zip(want) {
        let k = session_keys(&CLIENT_RANDOM, &SERVER_RANDOM, s);
        assert_eq!(hx(&update_key(&k.encrypt, &k.encrypt, s)), want, "{s:?}");
    }
}

#[test]
fn unsalted_mac_matches_the_reference() {
    let k = session_keys(&CLIENT_RANDOM, &SERVER_RANDOM, KeyStrength::Bits128);
    assert_eq!(hx(&mac_signature(&k.mac, b"abc", None)), "ded7ffaf0434e9f9");
}

/// 4,098 packets "packet" + n: the salted MAC counts packets (5.3.6.1.1)
/// and the RC4 key changes before packet 4,096 (5.3.7.1).
#[test]
fn encrypted_stream_with_salted_mac_and_key_update_matches_the_reference() {
    let want: [[(&str, &str); 4]; 3] = [
        [
            ("bbb127ce2fc30117", "27becc58de44a198f1ec"),
            ("ede249cca0124c76", "91fe6abbbf3a6bd5f3a0"),
            ("7b9d714e8bd9160e", "bc5269f30ccb44e536bb"),
            ("5b3728287c1c995b", "1d43e129d14f1a060124"),
        ],
        [
            ("706a7aea32e99e64", "69f884a12f7b1aa47e70"),
            ("8f3a69d4c86fdedd", "69fe2eacc94e7cd33153"),
            ("2db519b4d682844e", "ec2ae699b71105b07d20"),
            ("130f2ae8ae2eb595", "7c506154202ef95ed3ee"),
        ],
        [
            ("a4b429f75c9f5eb8", "0f8ab7a5062d34b0db47"),
            ("f3ea964f6eb8887c", "cfd424c6ebb13438ae1a"),
            ("c930070b2a6cf4cb", "727459cead12e7976d90"),
            ("69056b81769644db", "61cee4c384bd68eb6350"),
        ],
    ];
    for (s, want) in STRENGTHS.into_iter().zip(want) {
        let k = session_keys(&CLIENT_RANDOM, &SERVER_RANDOM, s);
        let mut sec = StandardSecurity::from_keys(s, ENCRYPTION_LEVEL_HIGH, &k);
        sec.set_salted_mac(true);
        let mut got = Vec::new();
        for n in 0u32..4098 {
            let data = [&b"packet"[..], &n.to_le_bytes()].concat();
            let pdu = sec.wrap(0, &data);
            assert_eq!(
                &pdu[..4],
                &[0x08, 0x08, 0, 0],
                "SEC_ENCRYPT | SEC_SECURE_CHECKSUM"
            );
            if [0, 4095, 4096, 4097].contains(&n) {
                got.push((hx(&pdu[4..12]), hx(&pdu[12..])));
            }
        }
        let want: Vec<_> = want
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        assert_eq!(got, want, "{s:?}");
    }
}

/// MS-RDPBCGR 4.1.4: the MCS Connect Response with the server's random
/// and a proprietary certificate signed with the Terminal Services key.
const CONNECT_RESPONSE: &str = "
03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02 01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01
02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82 01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00
01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08 00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed
03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00 00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a
12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96 e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00
00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00 00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe
ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5 cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55
ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f 55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00
00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef
9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5 69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a
e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00 00";

fn spec_server_data() -> crate::gcc::ServerData {
    let frame = hex(CONNECT_RESPONSE);
    assert_eq!(frame.len(), 337);
    let user_data =
        crate::mcs::parse_connect_response(crate::x224::data_payload(&frame).unwrap()).unwrap();
    crate::gcc::parse_conference_create_response(&user_data).unwrap()
}

#[test]
fn spec_server_security_data_and_certificate() {
    let sd = spec_server_data();
    assert_eq!(sd.encryption_method, ENCRYPTION_METHOD_128BIT);
    assert_eq!(sd.encryption_level, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE);
    assert_eq!(
        sd.server_random.map(|r| hx(&r)).as_deref(),
        Some("1011772030610a12e434a11ef2c39f317da45f01893496e0ff1108697f1ac3d2")
    );
    assert_eq!(sd.server_certificate.len(), 184);
    let key = server_key(&sd.server_certificate).unwrap();
    assert_eq!(key.exponent, 0x0001_0001);
    assert_eq!(key.modulus.len(), 64);
    assert_eq!(&key.modulus[..4], &[0xcb, 0x81, 0xfe, 0xba]);
    assert_eq!(&key.modulus[60..], &[0x26, 0x56, 0x12, 0xbc]);
    // 5.3.4.1: the encrypted random is the modulus length plus 8 zeros.
    let enc = encrypt_client_random(&key, &CLIENT_RANDOM).unwrap();
    assert_eq!(enc.len(), 72);
    assert!(enc[64..].iter().all(|&b| b == 0));
}

#[test]
fn a_changed_proprietary_certificate_fails_its_signature() {
    let cert = spec_server_data().server_certificate;
    // One bit of the modulus (the signed data), then of the signature.
    for at in [40, 120] {
        let mut bad = cert.clone();
        bad[at] ^= 0x01;
        assert!(
            matches!(server_key(&bad), Err(Error::Auth(_))),
            "byte {at} changed but the signature still verified"
        );
    }
    // Truncated: an error, not a panic.
    for n in [0, 3, 20, 100, 183] {
        assert!(server_key(&cert[..n]).is_err());
    }
}

/// MS-RDPBCGR 4.1.9: header flags SEC_EXCHANGE_PKT | SEC_LICENSE_ENCRYPT_SC,
/// length 72, the encrypted random with its 8 zero bytes.
#[test]
fn security_exchange_pdu_matches_the_spec() {
    let spec = hex(
        "01 02 00 00 48 00 00 00 91 ac 0c 8f 64 8c 39 f4 e7 ff 0a 3b 79 11 5c 13
         51 2a cb 72 8f 9d b7 42 2e f7 08 4c 8e ae 55 99 62 d2 81 81 e4 66 c8 05 ea d4
         73 06 3f c8 5f af 2a fd fc f1 64 b3 3f 0a 15 1d db 2c 10 9d 30 11 00 00 00 00
         00 00 00 00",
    );
    assert_eq!(security_exchange_pdu(&spec[8..]), spec);
}

/// A client and a server state over the same randoms.
fn pair(s: KeyStrength, level: u32) -> (StandardSecurity, StandardSecurity) {
    let k = session_keys(&CLIENT_RANDOM, &SERVER_RANDOM, s);
    let server = SessionKeys {
        mac: k.mac.clone(),
        encrypt: k.decrypt.clone(),
        decrypt: k.encrypt.clone(),
    };
    (
        StandardSecurity::from_keys(s, level, &k),
        StandardSecurity::from_keys(s, level, &server),
    )
}

#[test]
fn slow_path_round_trips_in_both_directions() {
    for s in STRENGTHS {
        let (mut client, mut server) = pair(s, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE);
        for n in 0..5000u32 {
            client.set_salted_mac(n % 3 == 0);
            server.set_salted_mac(n % 2 == 0);
            let share = [&b"share control "[..], &n.to_le_bytes()].concat();
            let up = client.wrap(0, &share);
            assert_ne!(&up[12..], &share[..], "encrypted");
            // The server gets the plaintext back; share data has no header.
            assert_eq!(server.unwrap(&up).unwrap(), share);
            let down = server.wrap(0, &share);
            assert_eq!(client.unwrap(&down).unwrap(), share, "{s:?} packet {n}");
        }
    }
}

#[test]
fn typed_pdus_keep_a_basic_header() {
    let (mut client, mut server) = pair(KeyStrength::Bits128, ENCRYPTION_LEVEL_HIGH);
    // Client Info: SEC_INFO_PKT | SEC_ENCRYPT (4.1.10).
    let info = client.wrap(0x0040, b"info");
    assert_eq!(&info[..4], &[0x48, 0x00, 0, 0]);
    assert_eq!(
        server.unwrap(&info).unwrap(),
        [&[0x40, 0, 0, 0][..], b"info"].concat()
    );
    // Licensing goes in the clear until the server says it takes it
    // encrypted (SEC_LICENSE_ENCRYPT_CS, 4.1.11).
    assert_eq!(
        client.wrap(0x0080, b"lic"),
        [&[0x80, 0, 0, 0][..], b"lic"].concat()
    );
    // (The client's Security Exchange PDU offered SEC_LICENSE_ENCRYPT_SC.)
    server.license_encrypt = true;
    let alert = server.wrap(0x0080 | 0x0200, b"alert");
    assert_eq!(&alert[..2], &[0x88, 0x02]);
    assert_eq!(
        client.unwrap(&alert).unwrap(),
        [&[0x80, 0, 0, 0][..], b"alert"].concat()
    );
    assert_eq!(&client.wrap(0x0080, b"lic")[..2], &[0x88, 0x00]);
    // A heartbeat comes unencrypted with a basic header (2.2.16.1).
    let hb = [0x00, 0x40, 0, 0, 0, 5, 3, 10];
    assert_eq!(client.unwrap(&hb).unwrap(), hb);
}

#[test]
fn tampered_or_plaintext_data_is_refused() {
    let (mut client, mut server) = pair(KeyStrength::Bits56, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE);
    let mut down = server.wrap(0, b"bitmap update");
    *down.last_mut().unwrap() ^= 1;
    assert!(client.unwrap(&down).is_err(), "MAC mismatch");
    // Above level Low, share data in the clear is refused...
    assert!(client.unwrap(&[0, 0, 0, 0, 1, 2]).is_err());
    // ...at level Low the server sends it in the clear (5.3.1).
    let (mut low, _) = pair(KeyStrength::Bits56, ENCRYPTION_LEVEL_LOW);
    assert_eq!(low.unwrap(&[0, 0, 0, 0, 1, 2]).unwrap(), [1, 2]);
    // Truncated headers: errors, not panics.
    for n in 0..12 {
        assert!(client.unwrap(&down[..n]).is_err(), "{n} bytes");
    }
}

/// MS-RDPBCGR 4.7: one encrypted mouse event with a salted MAC has the
/// header 0xc4 and length 17.
#[test]
fn fastpath_input_layout_matches_the_spec() {
    let (mut client, mut server) = pair(KeyStrength::Bits128, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE);
    client.set_salted_mac(true);
    let event = [0x20, 0x00, 0x08, 0xab, 0x02, 0x6f, 0x01];
    let plain = [&[0x04, 9][..], &event].concat();
    let pdu = client.fastpath_input(&plain);
    assert_eq!(&pdu[..2], &[0xc4, 0x11]);
    assert_eq!(pdu.len(), 17);
    // The server reads it back (same layout as fast-path output).
    assert_eq!(server.fastpath_output(&pdu).unwrap(), plain);
}

#[test]
fn fastpath_output_decrypts_into_reassembler_frames() {
    let (mut client, mut server) = pair(KeyStrength::Bits40, ENCRYPTION_LEVEL_HIGH);
    // A bitmap update of 200 bytes: the two-byte length form.
    let mut plain = vec![0x00, 0x80, 0x00, 0x01, 200, 0];
    plain.extend((0..200).map(|i| i as u8));
    let n = plain.len() as u16;
    plain[1..3].copy_from_slice(&(0x8000 | n).to_be_bytes());
    let enc = server.fastpath_input(&plain);
    assert_eq!(enc[0] >> 6, FASTPATH_ENCRYPTED, "unsalted");
    let frame = client.fastpath_output(&enc).unwrap();
    let mut bulk = crate::compress::Decompressor::default();
    let ups = Reassembler::default().feed(&frame, &mut bulk).unwrap();
    assert_eq!(
        ups,
        vec![(crate::fastpath::UPDATETYPE_BITMAP, plain[6..].to_vec())]
    );
    // Unencrypted fast-path output above level Low is refused.
    assert!(client.fastpath_output(&plain).is_err());
    // A wrong length: an error, not a panic.
    assert!(client.fastpath_output(&enc[..enc.len() - 1]).is_err());
}

#[test]
fn methods_and_levels() {
    assert_eq!(CLIENT_ENCRYPTION_METHODS, 0x0B);
    let r = (&CLIENT_RANDOM, &SERVER_RANDOM);
    assert!(StandardSecurity::new(ENCRYPTION_METHOD_128BIT, 2, r.0, r.1).is_ok());
    for (method, level) in [
        (0, 0),
        (ENCRYPTION_METHOD_FIPS, 4),
        (2, 4),
        (2, 0),
        (2, 5),
        (4, 2),
    ] {
        assert!(
            StandardSecurity::new(method, level, r.0, r.1).is_err(),
            "{method:#x}/{level}"
        );
    }
    assert!(legacy_refused().to_string().contains(LEGACY_REFUSED));
}
