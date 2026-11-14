//! Licensing tests on the MS-RDPELE section 4 example messages.
//!
//! The section 4 examples do not come from one protocol run (4 says so),
//! so no example pairs a premaster secret with its keys. Key derivation,
//! MAC and RSA results below were computed independently from the
//! formulas of 5.1.2 and 5.1.5 (Python hashlib and pow) over the example
//! randoms, premaster secret and certificate key.

use super::*;
use crate::crypto::rc4_once;

/// Each file is one example message, preamble first (no security header).
const REQUEST: &[u8] = include_bytes!("testdata/rdpele_4_1.bin");
const NEW_REQUEST: &[u8] = include_bytes!("testdata/rdpele_4_2.bin");
const INFO: &[u8] = include_bytes!("testdata/rdpele_4_3.bin");
const RESPONSE: &[u8] = include_bytes!("testdata/rdpele_4_5.bin");
const NEW_LICENSE_MSG: &[u8] = include_bytes!("testdata/rdpele_4_6.bin");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The decrypted premaster secret of the 4.2 example.
fn premaster() -> [u8; 48] {
    unhex(
        "cf7adbcbfb0e1523871c8481ba9d4e15bbd256bdd8f7f316cc353be1934278dd\
         929ae47ae299d473b1aa6f55943bc9bc",
    )
    .try_into()
    .unwrap()
}

fn server_random() -> [u8; 32] {
    REQUEST[4..36].try_into().unwrap()
}

fn client_random() -> [u8; 32] {
    NEW_REQUEST[12..44].try_into().unwrap()
}

#[test]
fn parses_the_server_license_request() {
    assert_eq!(REQUEST[0], LICENSE_REQUEST);
    let req = parse_license_request(&REQUEST[4..]).unwrap();
    assert_eq!(req.server_random[..4], [0x84, 0xef, 0xae, 0x20]);
    assert_eq!(req.product.version, 0x0006_0000);
    assert_eq!(
        req.product.company,
        crate::cursor::utf16le_z("Microsoft Corporation")
    );
    assert_eq!(req.product.product_id, crate::cursor::utf16le_z("A02"));
    assert_eq!(req.key_exchange, [KEY_EXCHANGE_ALG_RSA]);
    assert_eq!(req.certificate.len(), 0x812);
    assert_eq!(req.scopes, [b"microsoft.com\0".to_vec()]);
}

#[test]
fn takes_the_terminal_server_key_from_the_x509_chain() {
    let req = parse_license_request(&REQUEST[4..]).unwrap();
    let key = server_public_key(&req.certificate).unwrap();
    assert_eq!(key.exponent, 65537);
    assert_eq!(key.modulus.len(), 256);
    // The last certificate of the chain (the terminal server's) has the
    // modulus c8 90 6b ... 6f 5b; the first (license server) 88 ad 7c ....
    assert_eq!(key.modulus[255], 0xc8);
    assert_eq!(key.modulus[254], 0x90);
    assert_eq!(key.modulus[0], 0x5b);
}

#[test]
fn proprietary_certificate_key() {
    // PROPRIETARYSERVERCERTIFICATE with a 512-bit RSA1 key blob.
    let mut c = Vec::new();
    c.put_u32(1);
    c.put_u32(1);
    c.put_u32(1);
    let mut key = Vec::new();
    key.put_u32(0x3141_5352);
    key.put_u32(72);
    key.put_u32(512);
    key.put_u32(63);
    key.put_u32(65537);
    let modulus: Vec<u8> = (1..=64).collect();
    key.put_bytes(&modulus);
    key.put_zeros(8);
    c.put_u16(6);
    c.put_u16(key.len() as u16);
    c.put_bytes(&key);
    c.put_u16(8);
    c.put_u16(72);
    c.put_zeros(72);
    let k = server_public_key(&c).unwrap();
    assert_eq!(k.exponent, 65537);
    assert_eq!(k.modulus, modulus);
}

#[test]
fn encrypts_the_premaster_secret_little_endian() {
    let req = parse_license_request(&REQUEST[4..]).unwrap();
    let key = server_public_key(&req.certificate).unwrap();
    let c = key.encrypt(&premaster()).unwrap();
    assert_eq!(c.len(), 256 + 8);
    assert_eq!(c[256..], [0; 8]);
    let want = unhex(
        "f3c4da993c1ea02665e0fc5ca8765ad82f4c7d63711575b8d1ec684bf5d37ee5\
         9d763597e92c60fd3dde53fd62547b44f594966f0b74d54dc637545dcd711bce\
         c6d22ad2139f7987bd919768dcdf626854c5fe59fe63f681798677d1a0909378\
         ae90cf4a8c7db8e76e13d4db1ceb9076aaf78631318195ae7945b946c5e13ff1\
         b67780be46fe4f97baf97803bfdcbba09d9aba833acc11d8dd9fb190b0e7b8ee\
         a0b20d310e5e93d5ed9c4271a3d2f9e0874eea85ae02194f1df7066a6822ae27\
         093b4ddbd83240f5b1ce63a7954448582c3ba694fbe5b54557b35baab9f73f2e\
         17483cd4410956ba5f9c12a6009f2f81f554a26d3c314a34b9cc545683aedf50",
    );
    assert_eq!(c[..256], want[..]);
}

#[test]
fn derives_mac_salt_and_licensing_key() {
    let k = derive_keys(&premaster(), &client_random(), &server_random());
    assert_eq!(k.mac_salt[..], unhex("74cca2098e38f01d3eddf0b495c56968"));
    assert_eq!(k.encryption[..], unhex("6e1891432db6e14ce25985fba5c6f36d"));
    // Swapping the randoms (the two stages use opposite orders) changes both.
    let swapped = derive_keys(&premaster(), &server_random(), &client_random());
    assert_ne!(swapped.mac_salt, k.mac_salt);
}

#[test]
fn mac_over_the_example_challenge() {
    let k = derive_keys(&premaster(), &client_random(), &server_random());
    // "TEST" as the 4.4 example's decrypted platform challenge.
    let challenge = unhex("54004500530054000000");
    assert_eq!(
        mac(&k.mac_salt, &challenge)[..],
        unhex("e452a73830b396466bda2a6dcada4558")
    );
}

#[test]
fn builds_the_new_license_request_of_4_2() {
    let encrypted = &NEW_REQUEST[0x30..0x30 + 0x108];
    let msg = new_license_request(&client_random(), encrypted, "Administrator", "RODENT");
    assert_eq!(msg, NEW_REQUEST);
}

#[test]
fn builds_the_license_info_of_4_3() {
    let cr: [u8; 32] = INFO[12..44].try_into().unwrap();
    let encrypted = &INFO[0x30..0x30 + 0x108];
    let license = &INFO[0x13c..0x13c + 0x799];
    let hwid = &INFO[0x8d9..0x8d9 + 0x14];
    let m: [u8; 16] = INFO[0x8ed..0x8fd].try_into().unwrap();
    assert_eq!(license_info(&cr, encrypted, license, hwid, &m), INFO);
}

#[test]
fn builds_the_platform_challenge_response_of_4_5() {
    let enc_data = &RESPONSE[8..8 + 0x12];
    let enc_hwid = &RESPONSE[0x1e..0x1e + 0x14];
    let m: [u8; 16] = RESPONSE[0x32..0x42].try_into().unwrap();
    let mut want = RESPONSE.to_vec();
    // The example marks both blob types "(ignored)" and sends BB_DATA_BLOB;
    // 2.2.2.5 says BB_ENCRYPTED_DATA_BLOB, which is what is sent here.
    want[4] = 0x09;
    want[0x1a] = 0x09;
    assert_eq!(platform_challenge_response(enc_data, enc_hwid, &m), want);
}

#[test]
fn response_fields_use_fresh_rc4_states() {
    // In 4.5 the response data and the hardware id are each encrypted from
    // the start of the RC4 key stream: their key streams are equal.
    let data = challenge_response_data(&unhex("54004500530054000000"));
    assert_eq!(data[..8], [0x00, 0x01, 0x00, 0x01, 0x03, 0x00, 0x0a, 0x00]);
    let ks = |enc: &[u8], plain: &[u8]| -> Vec<u8> {
        enc.iter().zip(plain).map(|(a, b)| a ^ b).collect()
    };
    let hwid = unhex("02000000f159873ec9d898af2402f8f3293af026");
    let a = ks(&RESPONSE[8..8 + 0x12], &data);
    let b = ks(&RESPONSE[0x1e..0x1e + 0x14], &hwid);
    assert_eq!(a[..], b[..0x12]);
}

/// A server for one licensing run with a known RSA key: decrypting the
/// premaster secret is not possible without the private key, so the test
/// server recomputes the keys from what it records instead.
struct Recorder {
    keys: Keys,
}

fn exchange_with_store(store: Option<&Path>) -> (Licensing, Recorder) {
    let mut lic = Licensing::new(store, "user", "HOST");
    let (send, step) = lic.process(&with_security_header(REQUEST));
    assert_eq!(step.unwrap(), Step::Continue);
    assert_eq!(send.len(), 1);
    let keys = lic.session.as_ref().unwrap().keys.clone();
    (lic, Recorder { keys })
}

fn server_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    with_security_header(&message(msg_type, body))
}

fn challenge(keys: &Keys, plain: &[u8], mac_ok: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(0);
    put_blob(
        &mut b,
        BB_ENCRYPTED_DATA_BLOB,
        &rc4_once(&keys.encryption, plain),
    );
    let mut m = mac(&keys.mac_salt, plain);
    if !mac_ok {
        m[0] ^= 1;
    }
    b.put_bytes(&m);
    server_message(PLATFORM_CHALLENGE, &b)
}

fn new_license(keys: &Keys, info: &NewLicenseInfo) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.put_u32(info.version);
    for f in [&info.scope, &info.company, &info.product_id, &info.license] {
        plain.put_u32(f.len() as u32);
        plain.put_bytes(f);
    }
    let mut b = Vec::new();
    put_blob(
        &mut b,
        BB_ENCRYPTED_DATA_BLOB,
        &rc4_once(&keys.encryption, &plain),
    );
    b.put_bytes(&mac(&keys.mac_salt, &plain));
    server_message(NEW_LICENSE, &b)
}

fn example_license() -> NewLicenseInfo {
    NewLicenseInfo {
        version: 0x0006_0000,
        scope: b"microsoft.com\0".to_vec(),
        company: crate::cursor::utf16le_z("Microsoft Corporation"),
        product_id: crate::cursor::utf16le_z("A02"),
        license: vec![0x30, 0x82, 1, 2, 3],
    }
}

#[test]
fn full_exchange_stores_the_license_and_presents_it_next_time() {
    let dir = std::env::temp_dir().join(format!("rdp-rs-license-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // First connection: no license, so a New License Request.
    let (mut lic, srv) = exchange_with_store(Some(&dir));
    assert_eq!(lic.last.as_ref().unwrap()[4], NEW_LICENSE_REQUEST);
    let plain = b"T\0E\0S\0T\0\0\0";
    let (send, step) = lic.process(&challenge(&srv.keys, plain, true));
    assert_eq!(step.unwrap(), Step::Continue);
    let rsp = &send[0];
    assert_eq!(rsp[..5], [0x80, 0, 0, 0, PLATFORM_CHALLENGE_RESPONSE]);
    // The server side of 3.2.5.5: decrypt both fields, check the MAC.
    let mut r = Reader::new(&rsp[8..]);
    let (_, enc_data) = read_blob(&mut r).unwrap();
    let (_, enc_hwid) = read_blob(&mut r).unwrap();
    let their_mac = r.array::<16>().unwrap();
    let data = rc4_once(&srv.keys.encryption, enc_data);
    let hwid = rc4_once(&srv.keys.encryption, enc_hwid);
    assert_eq!(data, challenge_response_data(plain));
    assert_eq!(hwid[..4], PLATFORM_ID.to_le_bytes());
    assert_eq!(
        mac(&srv.keys.mac_salt, &[data, hwid.clone()].concat()),
        their_mac
    );
    let (send, step) = lic.process(&new_license(&srv.keys, &example_license()));
    assert_eq!(step.unwrap(), Step::Done);
    assert!(send.is_empty());

    // Second connection: the stored license goes back in License Info, with
    // the same hardware id.
    let (lic, srv) = exchange_with_store(Some(&dir));
    let info = lic.last.as_ref().unwrap();
    assert_eq!(info[4], LICENSE_INFO);
    let mut r = Reader::new(&info[8..]);
    r.skip(40).unwrap();
    read_blob(&mut r).unwrap(); // premaster
    let (_, license) = read_blob(&mut r).unwrap();
    assert_eq!(license, example_license().license);
    let (_, enc_hwid) = read_blob(&mut r).unwrap();
    let hwid2 = rc4_once(&srv.keys.encryption, enc_hwid);
    assert_eq!(hwid2, hwid);
    assert_eq!(r.array::<16>().unwrap(), mac(&srv.keys.mac_salt, &hwid2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_mac_aborts_with_an_error_alert() {
    let (mut lic, srv) = exchange_with_store(None);
    let (send, step) = lic.process(&challenge(&srv.keys, b"x", false));
    assert!(step.is_err());
    assert_eq!(send.len(), 1);
    let alert = &send[0];
    assert_eq!(alert[4], ERROR_ALERT);
    assert_eq!(alert[8..12], ERR_INVALID_MAC.to_le_bytes());
    assert_eq!(alert[12..16], ST_TOTAL_ABORT.to_le_bytes());
}

#[test]
fn error_alerts_and_transitions() {
    let alert = |code: u32, st: u32| {
        let mut b = Vec::new();
        b.put_u32(code);
        b.put_u32(st);
        put_blob(&mut b, BB_ERROR_BLOB, &[]);
        server_message(ERROR_ALERT, &b)
    };
    let mut lic = Licensing::new(None, "u", "m");
    let (_, step) = lic.process(&alert(STATUS_VALID_CLIENT, ST_NO_TRANSITION));
    assert_eq!(step.unwrap(), Step::Done);
    let (_, step) = lic.process(&alert(0x06, ST_TOTAL_ABORT));
    let e = step.unwrap_err().to_string();
    assert!(e.contains("ERR_NO_LICENSE_SERVER"), "{e}");
    // Resend: the last client message goes out again.
    let (mut lic, _) = exchange_with_store(None);
    let last = lic.last.clone().unwrap();
    let (send, step) = lic.process(&alert(0x0C, ST_RESEND_LAST_MESSAGE));
    assert_eq!(step.unwrap(), Step::Continue);
    assert_eq!(send, [last]);
    // A platform challenge before any license request is out of sequence.
    let mut lic = Licensing::new(None, "u", "m");
    let (_, step) = lic.process(&server_message(PLATFORM_CHALLENGE, &[0; 24]));
    assert!(step.is_err());
}

#[test]
fn parses_the_new_license_of_4_6() {
    assert_eq!(NEW_LICENSE_MSG[0], NEW_LICENSE);
    let mut r = Reader::new(&NEW_LICENSE_MSG[4..]);
    let (ty, enc) = read_blob(&mut r).unwrap();
    assert_eq!((ty, enc.len()), (BB_ENCRYPTED_DATA_BLOB, 0x7ef));
    // MACData at 0x7f7 (4 + 2 + 2 + 0x7ef) ends the message.
    assert_eq!(r.array::<16>().unwrap()[..], NEW_LICENSE_MSG[0x7f7..]);
    assert_eq!(r.remaining(), 0);
}
