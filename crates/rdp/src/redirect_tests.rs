//! Server redirection: the spec's annotated PDUs (MS-RDPBCGR 4.5, 4.6), the
//! X.224 routing token, redaction, RDSTLS PDUs, and loopback reconnects
//! through fake TLS servers.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::cursor::utf16le;
use crate::der::{ctx, integer, seq, tlv};
use crate::{ChannelOut, Client, Config, StaticChannel, mcs, pdu, x224};

fn hex(lines: &[&str]) -> Vec<u8> {
    let s: String = lines.concat();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// MS-RDPBCGR 4.6: Enhanced Security Server Redirection PDU, whole frame.
fn spec_enhanced_frame() -> Vec<u8> {
    hex(&[
        "0300021c02f08068000103eb70820d0d020a00ea035f5900040402020000001d0b00004600000032003000300031003a",
        "0034003800390038003a00320062003a0032003a0039006400650037003a0034003500360039003a0066006200330039",
        "003a00650066003200390000001c000000610064006d0069006e006900730074007200610074006f0072000000160000",
        "00540053002d005300540052004500530053003100000078000000020000804453484c0210f3e3bfb137952880b756f3",
        "7c274a43cc50985905b56b509762f8cfc01b6a0616dbb9b1ba2101f4ea82dc3717657dbe58ec34e9330712c1768df5bc",
        "a29f2cef32a7a480a905f70294968d95b82cdb554a7808eb8710c78ba90ae644abec6bee42bb32e7b0ef3cae4573a669",
        "6900005a0000006a00690061007a006f0075002d00740065007300740032002e00740073002d00730074007200650073",
        "00730031002e006e00740074006500730074002e006d006900630072006f0073006f00660074002e0063006f006d0000",
        "001a0000004a00490041005a004f0055002d005400450053005400320000007000000002000000460000003200300030",
        "0031003a0034003800390038003a00320062003a0032003a0039006400650037003a0034003500360039003a00660062",
        "00330039003a00650066003200390000001e0000003100350037002e00350039002e003200340030002e003100340034",
        "000000c0c0c0c0c0c0c0c000",
    ])
}

/// MS-RDPBCGR 4.5: the decrypted RDP_SERVER_REDIRECTION_PACKET of the
/// Standard Security variant.
fn spec_standard_packet() -> Vec<u8> {
    hex(&[
        "00040402020000001d0b00004600000032003000300031003a0034003800390038003a00320062003a0032003a003900",
        "6400650037003a0034003500360039003a0066006200330039003a00650066003200390000001c000000610064006d00",
        "69006e006900730074007200610074006f007200000016000000540053002d0053005400520045005300530031000000",
        "78000000020000804453484c066f271b2910f9d958fb467df9e10214a215aa00345c76a45276fd04d62d858d64698880",
        "1b8d0eb0b79bd3d884c610a2e9b6e006995d85162dbfd8f19977752dbee277a63f5efb86caed04813111d3b9fc32ad45",
        "dfadcab78d026f9265c6d7b468cdf649bcb888876e01ced095fd00005a0000006a00690061007a006f0075002d007400",
        "65007300740032002e00740073002d0073007400720065007300730031002e006e00740074006500730074002e006d00",
        "6900630072006f0073006f00660074002e0063006f006d0000001a0000004a00490041005a004f0055002d0054004500",
        "530054003200000070000000020000004600000032003000300031003a0034003800390038003a00320062003a003200",
        "3a0039006400650037003a0034003500360039003a0066006200330039003a00650066003200390000001e0000003100",
        "350037002e00350039002e003200340030002e003100340034000000c0c0c0c0c0c0c0c0",
    ])
}

const V6: &str = "2001:4898:2b:2:9de7:4569:fb39:ef29";
const FQDN: &str = "jiazou-test2.ts-stress1.nttest.microsoft.com";

/// The I/O channel payload of the 4.6 frame.
fn spec_enhanced_payload() -> Vec<u8> {
    let frame = spec_enhanced_frame();
    assert_eq!(frame.len(), 540);
    let mcs = x224::data_payload(&frame).unwrap();
    match mcs::parse_domain_pdu(mcs).unwrap() {
        mcs::DomainPdu::SendDataIndication { channel, data } => {
            assert_eq!(channel, 1003);
            data.to_vec()
        }
        _ => panic!("expected Send Data Indication"),
    }
}

fn parse_spec_enhanced() -> Redirection {
    let data = spec_enhanced_payload();
    assert!(is_enhanced(&data));
    assert!(!pdu::looks_like_share_control(&data), "PDUVersion is zero");
    let parts = pdu::split_share_control(&data).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].0, PDUTYPE_SERVER_REDIR_PKT);
    Redirection::parse_enhanced(parts[0].1).unwrap()
}

#[test]
fn parses_the_spec_enhanced_security_example() {
    let r = parse_spec_enhanced();
    assert_eq!(r.session_id, 2);
    assert_eq!(r.flags, 0x0b1d);
    assert_eq!(r.target_net_address.as_deref(), Some(V6));
    assert_eq!(r.username.as_deref(), Some("administrator"));
    assert_eq!(r.domain.as_deref(), Some("TS-STRESS1"));
    let pw = r.password.as_ref().unwrap().bytes();
    assert_eq!(pw.len(), 0x78);
    assert_eq!(&pw[..8], &[0x02, 0x00, 0x00, 0x80, b'D', b'S', b'H', b'L']);
    assert_eq!(&pw[0x76..], &[0, 0]);
    assert_eq!(r.target_fqdn.as_deref(), Some(FQDN));
    assert_eq!(r.target_netbios_name.as_deref(), Some("JIAZOU-TEST2"));
    assert_eq!(r.target_net_addresses, [V6, "157.59.240.144"]);
    assert_eq!(r.load_balance_info, None);
    assert!(!r.no_redirect() && !r.wants_rdstls() && !r.smartcard_logon());
    // Duplicates collapse; IP addresses first, then the names.
    assert_eq!(r.targets(), [V6, "157.59.240.144", FQDN, "JIAZOU-TEST2"]);
    assert_eq!(r.routing_token(), None);
    assert_eq!(r.client_info_password(), Some(pw));
}

#[test]
fn parses_the_spec_standard_security_packet() {
    // The 4.5 frame's security header: SEC_SECURE_CHECKSUM | SEC_REDIRECTION_PKT.
    assert!(is_standard_security(&[0x00, 0x0c, 0x00, 0x00]));
    assert!(
        !is_standard_security(&[0x80, 0x00, 0x00, 0x00]),
        "licensing"
    );
    assert!(!is_enhanced(&[0x00, 0x0c, 0x00, 0x00]));
    let packet = spec_standard_packet();
    assert_eq!(packet.len(), 516);
    let r = Redirection::parse(&packet).unwrap();
    let e = parse_spec_enhanced();
    // Same packet as 4.6 except for the encrypted password blob.
    assert_eq!(r.password.as_ref().unwrap().bytes().len(), 0x78);
    assert_ne!(r.password, e.password);
    assert_eq!(
        Redirection {
            password: None,
            ..r
        },
        Redirection {
            password: None,
            ..e
        }
    );
}

#[test]
fn rejects_malformed_packets() {
    let packet = spec_standard_packet();
    assert!(Redirection::parse(&packet[..300]).is_err(), "truncated");
    let mut bad = packet.clone();
    bad[1] = 0;
    assert!(Redirection::parse(&bad).is_err(), "no SEC_REDIRECTION_PKT");
    let mut long = packet.clone();
    long[0x0c] = 0xff; // TargetNetAddressLength past the end
    assert!(Redirection::parse(&long).is_err());
}

#[test]
fn password_blob_never_reaches_debug_or_trace() {
    let r = parse_spec_enhanced();
    let blob = r.password.as_ref().unwrap().bytes().to_vec();
    for text in [format!("{r:?}"), format!("{r:#?}"), r.hop_trace(1)] {
        assert!(!text.contains("DSHL"), "{text}");
        for window in [&blob[8..12], &blob[40..44]] {
            let as_list = format!("{}, {}", window[0], window[1]);
            assert!(!text.contains(&as_list), "{text}");
            let as_hex: String = window.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!text.contains(&as_hex), "{text}");
        }
    }
    assert!(format!("{r:?}").contains("<redacted>"));
    let trace = r.hop_trace(2);
    assert!(trace.contains("session 2") && trace.contains("157.59.240.144"));
    assert!(!trace.contains("administrator") && !trace.contains("TS-STRESS1"));
    let with_token = Redirection {
        load_balance_info: Some(b"Cookie: msts=3640205228.15629.0000".to_vec()),
        ..r
    };
    let trace = with_token.hop_trace(1);
    assert!(trace.contains("routing token 34 bytes"), "{trace}");
    assert!(!trace.contains("3640205228"), "{trace}");
}

#[test]
fn routing_token_replaces_the_cookie() {
    let r = Redirection {
        flags: LB_LOAD_BALANCE_INFO,
        load_balance_info: Some(b"Cookie: msts=3640205228.15629.0000".to_vec()),
        ..Default::default()
    };
    let token = r.routing_token().unwrap();
    assert_eq!(token, b"Cookie: msts=3640205228.15629.0000\r\n");
    let cr = x224::connection_request_routed(&token, x224::PROTOCOL_SSL).unwrap();
    // TPKT, then length indicator = 6 + token + RDP_NEG_REQ (2.2.1.1).
    assert_eq!(&cr[..4], &[3, 0, 0, (4 + 1 + 6 + token.len() + 8) as u8]);
    assert_eq!(cr[4] as usize, 6 + token.len() + 8);
    assert_eq!(&cr[5..11], &[0xE0, 0, 0, 0, 0, 0]);
    assert_eq!(&cr[11..11 + token.len()], &token[..]);
    assert_eq!(&cr[11 + token.len()..], &[1, 0, 8, 0, 1, 0, 0, 0]);
    // Already terminated: not doubled.
    let r2 = Redirection {
        load_balance_info: Some(token.clone()),
        ..r
    };
    assert_eq!(r2.routing_token().unwrap(), token);
    assert!(x224::connection_request_routed(b"no crlf", 0).is_err());
    assert!(x224::connection_request_routed(&[b'a'; 300], 0).is_err());
}

#[test]
fn noredirect_keeps_only_the_routing_information() {
    let r = Redirection {
        flags: LB_NOREDIRECT | LB_TARGET_NET_ADDRESS | LB_PASSWORD | LB_LOAD_BALANCE_INFO,
        target_net_address: Some("10.0.0.9".into()),
        password: Some(PasswordBlob(vec![1, 2, 0, 0])),
        load_balance_info: Some(b"tok".to_vec()),
        ..Default::default()
    };
    assert!(r.no_redirect());
    assert!(r.targets().is_empty());
    assert_eq!(r.client_info_password(), None);
    assert_eq!(r.routing_token().unwrap(), b"tok\r\n");
}

#[test]
fn redirected_client_info_carries_the_blob() {
    let info = pdu::ClientInfo {
        domain: "D",
        user: "u",
        password: "ignored",
        auto_reconnect: None,
        performance_flags: 0,
        compression: None,
    };
    let blob = [0x02, 0x00, 0x00, 0x80, 0x44, 0x53, 0x48, 0x4c, 0x00, 0x00];
    let pdu = pdu::client_info_redirected(&info, &blob);
    // cbDomain, cbUserName, cbPassword exclude the terminator (2.2.1.11.1.1).
    assert_eq!(&pdu[12..18], &[2, 0, 2, 0, 8, 0]);
    // Domain "D\0", user "u\0", then the blob as is.
    assert_eq!(&pdu[22..26], &[b'D', 0, 0, 0]);
    assert_eq!(&pdu[26..30], &[b'u', 0, 0, 0]);
    assert_eq!(&pdu[30..40], &blob);
    // The plain path is unchanged.
    let plain = pdu::client_info(&info);
    assert_eq!(&plain[16..18], &[14, 0]);
    assert_eq!(plain.len() + 10 - (14 + 2), pdu.len());
}

#[test]
fn rdstls_pdus() {
    let guid = utf16le_z("Zm9vYmFy");
    let r = Redirection {
        flags: LB_PASSWORD_IS_PK_ENCRYPTED | LB_PASSWORD | LB_REDIRECTION_GUID | LB_USERNAME,
        username: Some("bob".into()),
        password: Some(PasswordBlob(vec![9; 5])),
        redirection_guid: Some(guid.clone()),
        ..Default::default()
    };
    assert!(r.wants_rdstls());
    assert_eq!(r.client_info_password(), None, "the blob goes to RDSTLS");
    let req = rdstls_auth_request(&r).unwrap();
    let mut want = vec![1, 0, 2, 0, 1, 0];
    want.extend((guid.len() as u16).to_le_bytes());
    want.extend(&guid);
    want.extend([8, 0]);
    want.extend(utf16le_z("bob"));
    want.extend([2, 0, 0, 0]); // empty domain, terminator only
    want.extend([5, 0, 9, 9, 9, 9, 9]);
    assert_eq!(req, want);
    parse_rdstls_capabilities(&[1, 0, 1, 0, 1, 0, 1, 0]).unwrap();
    assert!(parse_rdstls_capabilities(&[1, 0, 4, 0, 1, 0, 1, 0]).is_err());
    assert_eq!(
        parse_rdstls_response(&[1, 0, 4, 0, 1, 0, 5, 0, 0, 0]).unwrap(),
        5
    );
    assert!(parse_rdstls_response(&[1, 0, 1, 0, 1, 0, 0, 0, 0, 0]).is_err());
    let no_guid = Redirection {
        redirection_guid: None,
        ..r
    };
    assert!(!no_guid.wants_rdstls());
    assert!(rdstls_auth_request(&no_guid).is_err());
}

/// A Server Redirection Packet with the given fields, in spec order.
struct Packet {
    session_id: u32,
    flags: u32,
    fields: Vec<Vec<u8>>,
}

impl Packet {
    fn new(session_id: u32) -> Self {
        Packet {
            session_id,
            flags: 0,
            fields: Vec::new(),
        }
    }

    fn field(mut self, flag: u32, data: Vec<u8>) -> Self {
        self.flags |= flag;
        self.fields.push(data);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.put_u32(self.session_id);
        body.put_u32(self.flags);
        for f in &self.fields {
            body.put_u32(f.len() as u32);
            body.put_bytes(f);
        }
        let mut out = Vec::new();
        out.put_u16(SEC_REDIRECTION_PKT);
        out.put_u16((body.len() + 4) as u16);
        out.put_bytes(&body);
        out
    }

    /// The Enhanced Security Server Redirection PDU on the I/O channel.
    fn enhanced(&self) -> Vec<u8> {
        let mut body = vec![0, 0]; // pad2Octets
        body.extend(self.bytes());
        let mut out = Vec::new();
        out.put_u16((body.len() + 6) as u16);
        out.put_u16(PDUTYPE_SERVER_REDIR_PKT);
        out.put_u16(1002);
        out.extend(body);
        out
    }
}

fn addresses(list: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u32(list.len() as u32);
    for a in list {
        let w = utf16le_z(a);
        out.put_u32(w.len() as u32);
        out.put_bytes(&w);
    }
    out
}

#[test]
fn target_certificate_and_address_list() {
    let mut container = Vec::new();
    for (ty, enc, data) in [(1u32, 1u32, &b"skip"[..]), (32, 1, &b"DER!"[..])] {
        container.put_u32(ty);
        container.put_u32(enc);
        container.put_u32(data.len() as u32);
        container.put_bytes(data);
    }
    let b64 = crate::gateway::ws::base64_encode(&container);
    let r = Redirection::parse(
        &Packet::new(4)
            .field(LB_TARGET_CERTIFICATE, utf16le_z(&b64))
            .field(
                LB_TARGET_NET_ADDRESSES,
                addresses(&["10.0.0.1", "10.0.0.2"]),
            )
            .bytes(),
    )
    .unwrap();
    assert_eq!(r.target_certificate.as_deref(), Some(&b"DER!"[..]));
    assert_eq!(r.targets(), ["10.0.0.1", "10.0.0.2"]);
}

// ---- loopback: fake TLS servers -------------------------------------------

/// A self-signed P-256 certificate and its PKCS#8 key, built here so the
/// tests need no fixture files.
fn test_identity() -> (Vec<u8>, Vec<u8>) {
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let oid = |b: &[u8]| tlv(0x06, b);
    let ecdsa_sha256 = seq(&oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]));
    let name = seq(&tlv(
        0x31,
        &seq(&[oid(&[0x55, 0x04, 0x03]), tlv(0x0C, b"rdp-rs test")].concat()),
    ));
    let validity = seq(&[tlv(0x17, b"250101000000Z"), tlv(0x17, b"491231000000Z")].concat());
    let mut point = vec![0];
    point.extend_from_slice(key.public_key().as_ref());
    let spki = seq(&[
        seq(&[
            oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
            oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        ]
        .concat()),
        tlv(0x03, &point),
    ]
    .concat());
    let tbs = seq(&[
        ctx(0, &integer(2)),
        integer(1),
        ecdsa_sha256.clone(),
        name.clone(),
        validity,
        name,
        spki,
    ]
    .concat());
    let sig = key.sign(&rng, &tbs).unwrap();
    let mut bits = vec![0];
    bits.extend_from_slice(sig.as_ref());
    let cert = seq(&[tbs, ecdsa_sha256, tlv(0x03, &bits)].concat());
    (cert, pkcs8.as_ref().to_vec())
}

fn server_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert, key) = test_identity();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
    Arc::new(config)
}

fn read_tpkt(s: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    let mut frame = head.to_vec();
    frame.resize(len.max(4), 0);
    s.read_exact(&mut frame[4..])?;
    Ok(frame)
}

fn accept(listener: &TcpListener, wait: Duration) -> Option<TcpStream> {
    listener.set_nonblocking(true).unwrap();
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if let Ok((s, _)) = listener.accept() {
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// What the client sent to one fake server.
#[derive(Default)]
struct Seen {
    connection_request: Vec<u8>,
    connect_initial: Vec<u8>,
    client_info: Vec<u8>,
}

/// Plays a TLS-only RDP server up to the Client Info PDU, then sends `reply`
/// on the I/O channel (if any) and closes.
fn fake_server(sock: TcpStream, tls: Arc<rustls::ServerConfig>, reply: Option<&[u8]>) -> Seen {
    let mut seen = Seen::default();
    let mut sock = sock;
    seen.connection_request = read_tpkt(&mut sock).unwrap();
    // Connection Confirm selecting PROTOCOL_SSL (2.2.1.2).
    sock.write_all(&x224::tpkt(&[
        14, 0xD0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 1, 0, 0, 0,
    ]))
    .unwrap();
    let conn = rustls::ServerConnection::new(tls).unwrap();
    let mut s = rustls::StreamOwned::new(conn, sock);
    seen.connect_initial = read_tpkt(&mut s).unwrap();
    // MCS Connect Response: result, calledConnectId, domainParameters, GCC
    // data with SC_CORE and SC_NET (I/O channel 1003, channels 1004..).
    let mut blocks = Vec::new();
    blocks.extend([0x01, 0x0C, 8, 0, 4, 0, 8, 0]);
    blocks.extend([0x03, 0x0C, 12, 0, 0xEB, 0x03, 2, 0, 0xEC, 0x03, 0xED, 0x03]);
    let mut gcc = b"McDn".to_vec();
    mcs::put_per_len(&mut gcc, blocks.len());
    gcc.extend(blocks);
    let body = [
        tlv(0x0A, &[0]),
        integer(0),
        seq(&integer(1)),
        tlv(0x04, &gcc),
    ]
    .concat();
    let mut response = vec![0x7F];
    response.extend(tlv(0x66, &body));
    s.write_all(&x224::data(&response)).unwrap();
    read_tpkt(&mut s).unwrap(); // Erect Domain Request
    read_tpkt(&mut s).unwrap(); // Attach User Request
    s.write_all(&x224::data(&[0x2E, 0, 0, 6])).unwrap(); // user 1007
    loop {
        let frame = read_tpkt(&mut s).unwrap();
        let m = &frame[7..];
        match m[0] >> 2 {
            14 => {
                // Channel Join Confirm for the requested channel.
                let c = [0x3E, 0, m[1], m[2], m[3], m[4], m[3], m[4]];
                s.write_all(&x224::data(&c)).unwrap();
            }
            25 => {
                let (len, n) = mcs::read_per_len(m, 6).unwrap();
                seen.client_info = m[6 + n..6 + n + len].to_vec();
                break;
            }
            other => panic!("unexpected MCS PDU {other}"),
        }
    }
    if let Some(data) = reply {
        let mut ind = vec![0x68, 0x00, 0x01, 0x03, 0xEB, 0x70];
        mcs::put_per_len(&mut ind, data.len());
        ind.extend_from_slice(data);
        s.write_all(&x224::data(&ind)).unwrap();
    }
    s.conn.send_close_notify();
    let _ = s.flush();
    seen
}

struct Named(&'static str);

impl StaticChannel for Named {
    fn name(&self) -> &str {
        self.0
    }

    fn process(&mut self, _msg: &[u8], _out: &mut ChannelOut) -> crate::Result<()> {
        Ok(())
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn client_config(port: u16, checked: Arc<Mutex<Vec<String>>>) -> Config {
    let mut cfg = Config::new("127.0.0.1", "user", "configured-secret");
    cfg.port = port;
    cfg.timeout = Duration::from_secs(10);
    cfg.verify_certificate = Some(crate::CertificateCheck(Arc::new(move |c| {
        checked.lock().unwrap().push(c.host.clone());
        true
    })));
    cfg
}

#[test]
fn follows_a_redirection_to_the_first_reachable_target() {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = first.local_addr().unwrap().port();
    // The target listens on another loopback address with the same port,
    // since the redirection carries no port.
    let Ok(target) = TcpListener::bind(("127.0.0.2", port)) else {
        eprintln!("127.0.0.2 is not usable here; test skipped");
        return;
    };
    let token = b"Cookie: msts=3640205228.15629.0000\r\n".to_vec();
    let blob = vec![0x02, 0x00, 0x00, 0x80, 0x5A, 0xA5, 0x3C, 0xC3, 0x99];
    let redirect = Packet::new(7)
        .field(LB_LOAD_BALANCE_INFO, token.clone())
        .field(LB_USERNAME, utf16le_z("bob"))
        .field(LB_DOMAIN, utf16le_z("CORP"))
        .field(LB_PASSWORD, blob.clone())
        // Nothing listens on 127.0.0.3: the client must move on.
        .field(
            LB_TARGET_NET_ADDRESSES,
            addresses(&["127.0.0.3", "127.0.0.2"]),
        )
        .enhanced();
    let tls = server_config();
    let (t1, t2) = (tls.clone(), tls);
    let s1 = std::thread::spawn(move || {
        let sock = accept(&first, Duration::from_secs(20)).expect("first connection");
        fake_server(sock, t1, Some(&redirect))
    });
    let s2 = std::thread::spawn(move || {
        let sock = accept(&target, Duration::from_secs(30)).expect("redirected connection");
        fake_server(sock, t2, None)
    });

    let checked = Arc::new(Mutex::new(Vec::new()));
    let cfg = client_config(port, checked.clone());
    let channels: Vec<Box<dyn StaticChannel>> =
        vec![Box::new(Named("chan1")), Box::new(Named("chan2"))];
    let err = Client::connect_with(&cfg, channels)
        .err()
        .expect("the target hangs up");
    let (seen1, seen2) = (s1.join().unwrap(), s2.join().unwrap());
    assert!(!err.to_string().contains("redirection"), "{err}");

    // First hop: the configured user's cookie, no session id.
    assert!(contains(
        &seen1.connection_request,
        b"Cookie: mstshash=user\r\n"
    ));
    assert!(contains(
        &seen1.connect_initial,
        &[0x04, 0xC0, 12, 0, 0x0D, 0, 0, 0, 0, 0, 0, 0]
    ));
    // Second hop: the routing token instead of the cookie (3.2.5.3.1) ...
    assert!(contains(&seen2.connection_request, &token));
    assert!(!contains(&seen2.connection_request, b"mstshash"));
    // ... the session id in the cluster data (2.2.1.3.5) ...
    assert!(contains(
        &seen2.connect_initial,
        &[0x04, 0xC0, 12, 0, 0x0F, 0, 0, 0, 7, 0, 0, 0]
    ));
    // ... the same channel handlers ...
    assert!(contains(&seen2.connect_initial, b"chan1\0\0\0"));
    assert!(contains(&seen2.connect_initial, b"chan2\0\0\0"));
    // ... and the redirected credentials, with the blob as the password.
    let info = &seen2.client_info;
    assert!(contains(info, &utf16le("bob")) && contains(info, &utf16le("CORP")));
    assert!(contains(info, &blob));
    assert_eq!(&info[16..18], &(blob.len() as u16).to_le_bytes());
    assert!(!contains(info, &utf16le("configured-secret")));
    // The certificate check ran for the target too.
    assert_eq!(*checked.lock().unwrap(), ["127.0.0.1", "127.0.0.2"]);
}

#[test]
fn target_must_present_the_certificate_the_broker_named() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut container = Vec::new();
    for v in [32u32, 1, 4] {
        container.put_u32(v);
    }
    container.put_bytes(b"other");
    let b64 = crate::gateway::ws::base64_encode(&container[..16]);
    let redirect = Packet::new(1)
        .field(LB_TARGET_NET_ADDRESS, utf16le_z("127.0.0.1"))
        .field(LB_TARGET_CERTIFICATE, utf16le_z(&b64))
        .enhanced();
    let server = std::thread::spawn(move || {
        let tls = server_config();
        let sock = accept(&listener, Duration::from_secs(20)).unwrap();
        fake_server(sock, tls.clone(), Some(&redirect));
        let sock = accept(&listener, Duration::from_secs(20)).unwrap();
        // The client hangs up after the TLS handshake: no MCS traffic.
        let run = std::panic::AssertUnwindSafe(move || fake_server(sock, tls, None));
        let _ = std::panic::catch_unwind(run);
    });
    let checked = Arc::new(Mutex::new(Vec::new()));
    let cfg = client_config(port, checked.clone());
    let err = Client::connect(&cfg)
        .err()
        .expect("pinned certificate differs");
    server.join().unwrap();
    assert!(err.to_string().contains("certificate differs"), "{err}");
    // Refused before the caller's check is asked.
    assert_eq!(*checked.lock().unwrap(), ["127.0.0.1"]);
}

/// Serves `pdu` to every connection on `listener` until none comes for 2 s;
/// returns how many connections there were.
fn serve_repeatedly(listener: TcpListener, pdu: Vec<u8>) -> std::thread::JoinHandle<usize> {
    std::thread::spawn(move || {
        let tls = server_config();
        let mut wait = Duration::from_secs(20);
        let mut count = 0;
        while let Some(sock) = accept(&listener, wait) {
            count += 1;
            fake_server(sock, tls.clone(), Some(&pdu));
            wait = Duration::from_secs(2);
        }
        count
    })
}

#[test]
fn noredirect_is_not_followed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let info = Packet::new(3)
        .field(LB_LOAD_BALANCE_INFO, b"Cookie: msts=1.2.3\r\n".to_vec())
        .enhanced();
    let mut info = info;
    info[16] |= LB_NOREDIRECT as u8; // RedirFlags, low byte
    let server = serve_repeatedly(listener, info);
    let cfg = client_config(port, Arc::new(Mutex::new(Vec::new())));
    // The client stays and waits for Demand Active; the server hangs up.
    let err = Client::connect(&cfg).err().expect("server hangs up");
    assert!(!err.to_string().contains("redirection"), "{err}");
    assert_eq!(server.join().unwrap(), 1);
}

#[test]
fn redirect_loops_stop_after_the_hop_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // No target: every hop comes back here with the routing token (1.3.8).
    let redirect = Packet::new(3)
        .field(LB_LOAD_BALANCE_INFO, b"Cookie: msts=1.2.3\r\n".to_vec())
        .enhanced();
    let server = serve_repeatedly(listener, redirect);
    let cfg = client_config(port, Arc::new(Mutex::new(Vec::new())));
    let err = Client::connect(&cfg).err().expect("loop refused");
    assert_eq!(server.join().unwrap(), 1 + MAX_REDIRECTS);
    assert!(
        err.to_string().contains("more than 3 server redirections"),
        "{err}"
    );
}
