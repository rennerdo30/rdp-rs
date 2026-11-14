//! Client licensing (MS-RDPELE), run between the Client Info PDU and the
//! capability exchange (MS-RDPBCGR 1.3.1.1).
//!
//! The server either ends licensing at once with a "valid client" error
//! alert (STATUS_VALID_CLIENT, 2.2.2.8), or runs the exchange of 1.3.3:
//!
//! 1. Server License Request (2.2.2.1): server random, product, scopes and
//!    the server certificate (proprietary or an X.509 chain, 2.2.1.4).
//! 2. The client answers with Client License Information (2.2.2.3) when
//!    its store holds a license for that product and scope, else with a
//!    Client New License Request (2.2.2.2). Both carry a client random and
//!    a 48-byte premaster secret encrypted with the server's RSA key
//!    (5.1.1.1); both sides derive the MAC salt and RC4 licensing key from
//!    the three values (5.1.2).
//! 3. Server Platform Challenge (2.2.2.4) -> Client Platform Challenge
//!    Response (2.2.2.5): the decrypted challenge and the client hardware
//!    id, each RC4-encrypted, and a MAC over both (5.1.3, 5.1.5).
//! 4. Server New License or Upgrade License (2.2.2.6, 2.2.2.7): the
//!    decrypted license is stored for the next connection.
//!
//! Keys, the premaster secret, the hardware id and license blobs are never
//! logged; traces name message types and error codes only.

use std::path::{Path, PathBuf};

use crate::crypto::{md5, random, rc4_once, rsa_encrypt_le, sha1, sha256};
use crate::cursor::{Put, Reader};
use crate::error::{Error, Result, proto};
use crate::trace;

/// bMsgType of the licensing preamble (MS-RDPBCGR 2.2.1.12.1.1).
pub const LICENSE_REQUEST: u8 = 0x01;
pub const PLATFORM_CHALLENGE: u8 = 0x02;
pub const NEW_LICENSE: u8 = 0x03;
pub const UPGRADE_LICENSE: u8 = 0x04;
pub const LICENSE_INFO: u8 = 0x12;
pub const NEW_LICENSE_REQUEST: u8 = 0x13;
pub const PLATFORM_CHALLENGE_RESPONSE: u8 = 0x15;
pub const ERROR_ALERT: u8 = 0xFF;
/// PREAMBLE_VERSION_3_0 | EXTENDED_ERROR_MSG_SUPPORTED.
const PREAMBLE_FLAGS: u8 = 0x83;
const SEC_LICENSE_PKT: u16 = 0x0080;

/// wBlobType (MS-RDPBCGR 2.2.1.12.1.2).
pub const BB_DATA_BLOB: u16 = 0x0001;
pub const BB_RANDOM_BLOB: u16 = 0x0002;
pub const BB_CERTIFICATE_BLOB: u16 = 0x0003;
pub const BB_ERROR_BLOB: u16 = 0x0004;
pub const BB_ENCRYPTED_DATA_BLOB: u16 = 0x0009;
pub const BB_KEY_EXCHG_ALG_BLOB: u16 = 0x000D;
pub const BB_SCOPE_BLOB: u16 = 0x000E;
pub const BB_CLIENT_USER_NAME_BLOB: u16 = 0x000F;
pub const BB_CLIENT_MACHINE_NAME_BLOB: u16 = 0x0010;

pub const KEY_EXCHANGE_ALG_RSA: u32 = 1;
/// CLIENT_OS_ID_WINNT_POST_52 | CLIENT_IMAGE_ID_MICROSOFT, as in the
/// MS-RDPELE 4.2 example.
pub const PLATFORM_ID: u32 = 0x0401_0000;

/// dwErrorCode (MS-RDPBCGR 2.2.1.12.1.3).
pub const ERR_INVALID_SERVER_CERTIFICATE: u32 = 0x01;
pub const ERR_NO_LICENSE: u32 = 0x02;
pub const ERR_INVALID_MAC: u32 = 0x03;
pub const STATUS_VALID_CLIENT: u32 = 0x07;
/// dwStateTransition.
pub const ST_TOTAL_ABORT: u32 = 1;
pub const ST_NO_TRANSITION: u32 = 2;
pub const ST_RESET_PHASE_TO_START: u32 = 3;
pub const ST_RESEND_LAST_MESSAGE: u32 = 4;

/// The name of a licensing error code, for messages.
pub fn error_name(code: u32) -> &'static str {
    match code {
        0x01 => "ERR_INVALID_SERVER_CERTIFICATE",
        0x02 => "ERR_NO_LICENSE",
        0x03 => "ERR_INVALID_MAC",
        0x04 => "ERR_INVALID_SCOPE",
        0x06 => "ERR_NO_LICENSE_SERVER",
        0x07 => "STATUS_VALID_CLIENT",
        0x08 => "ERR_INVALID_CLIENT",
        0x0B => "ERR_INVALID_PRODUCTID",
        0x0C => "ERR_INVALID_MESSAGE_LEN",
        _ => "unknown",
    }
}

fn read_blob<'a>(r: &mut Reader<'a>) -> Result<(u16, &'a [u8])> {
    let ty = r.u16()?;
    let len = r.u16()? as usize;
    Ok((ty, r.bytes(len)?))
}

fn put_blob(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.put_u16(ty);
    out.put_u16(data.len() as u16);
    out.put_bytes(data);
}

/// A licensing message with its preamble (MS-RDPBCGR 2.2.1.12.1.1), without
/// the security header.
pub fn message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.put_u8(msg_type);
    out.put_u8(PREAMBLE_FLAGS);
    out.put_u16((body.len() + 4) as u16);
    out.put_bytes(body);
    out
}

/// The licensing PDU as sent on the I/O channel: a basic security header
/// with SEC_LICENSE_PKT (MS-RDPELE 2.2.2), then the message.
pub fn with_security_header(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 4);
    out.put_u16(SEC_LICENSE_PKT);
    out.put_u16(0);
    out.put_bytes(msg);
    out
}

/// PRODUCT_INFO (2.2.2.1.1); the strings stay in their wire form
/// (null-terminated UTF-16), as the license store indexes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductInfo {
    pub version: u32,
    pub company: Vec<u8>,
    pub product_id: Vec<u8>,
}

/// SERVER_LICENSE_REQUEST (2.2.2.1).
#[derive(Debug, Clone)]
pub struct LicenseRequest {
    pub server_random: [u8; 32],
    pub product: ProductInfo,
    pub key_exchange: Vec<u32>,
    /// SERVER_CERTIFICATE (2.2.1.4); empty if the server sent none.
    pub certificate: Vec<u8>,
    /// Scope names (null-terminated ANSI, as sent).
    pub scopes: Vec<Vec<u8>>,
}

pub fn parse_license_request(msg: &[u8]) -> Result<LicenseRequest> {
    let mut r = Reader::new(msg);
    let server_random = r.array::<32>()?;
    let version = r.u32()?;
    let n = r.u32()? as usize;
    let company = r.bytes(n)?.to_vec();
    let n = r.u32()? as usize;
    let product_id = r.bytes(n)?.to_vec();
    let (_, kx) = read_blob(&mut r)?;
    let key_exchange = kx
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u32::from_le_bytes(c))
        .collect();
    let (_, cert) = read_blob(&mut r)?;
    let count = r.u32()?;
    let mut scopes = Vec::new();
    for _ in 0..count {
        let (ty, s) = read_blob(&mut r)?;
        if ty == BB_SCOPE_BLOB {
            scopes.push(s.to_vec());
        }
    }
    Ok(LicenseRequest {
        server_random,
        product: ProductInfo {
            version,
            company,
            product_id,
        },
        key_exchange,
        certificate: cert.to_vec(),
        scopes,
    })
}

/// An RSA public key: the modulus little-endian, as RDP encrypts with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub modulus: Vec<u8>,
    pub exponent: u32,
}

impl PublicKey {
    /// Encrypts the premaster secret (MS-RDPELE 5.1.1.1, MS-RDPBCGR
    /// 5.3.4.1): modulus length plus 8 zero bytes.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        rsa_encrypt_le(data, &self.modulus, self.exponent)
            .ok_or_else(|| Error::Protocol("licensing: unusable server RSA key".into()))
    }
}

/// The server's public key from a SERVER_CERTIFICATE (MS-RDPBCGR
/// 2.2.1.4.3.1): a proprietary certificate, or an X.509 chain whose last
/// certificate is the terminal server's (MS-RDPELE 2.2.1.4.2, 5.1.1.1).
pub fn server_public_key(cert: &[u8]) -> Result<PublicKey> {
    let mut r = Reader::new(cert);
    let version = r.u32()? & 0x7FFF_FFFF;
    match version {
        1 => {
            // PROPRIETARYSERVERCERTIFICATE: dwSigAlgId, dwKeyAlgId, then
            // the RSA_PUBLIC_KEY blob (2.2.1.4.3.1.1.1).
            r.skip(8)?;
            let (_, key) = read_blob(&mut r)?;
            let mut k = Reader::new(key);
            if k.u32()? != 0x3141_5352 {
                return proto("licensing: bad RSA1 magic");
            }
            let keylen = k.u32()? as usize;
            let bitlen = k.u32()? as usize;
            k.u32()?; // datalen
            let exponent = k.u32()?;
            let modulus = k.bytes(keylen)?;
            Ok(PublicKey {
                modulus: modulus[..(bitlen / 8).min(keylen)].to_vec(),
                exponent,
            })
        }
        2 => {
            let count = r.u32()?;
            if !(1..=200).contains(&count) {
                return proto(format!("licensing: {count} certificates in the chain"));
            }
            let mut last = &[][..];
            for _ in 0..count {
                let n = r.u32()? as usize;
                last = r.bytes(n)?;
            }
            x509_rsa_key(last)
        }
        v => proto(format!("licensing: server certificate version {v}")),
    }
}

/// The RSA key of an X.509 certificate: SubjectPublicKeyInfo holds
/// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
fn x509_rsa_key(cert: &[u8]) -> Result<PublicKey> {
    use crate::der::DerReader;
    let spk = crate::der::subject_public_key(cert)?;
    let seq = DerReader::new(&spk).expect(0x30)?;
    let mut r = DerReader::new(seq);
    let n = r.expect(0x02)?;
    let e = r.expect(0x02)?;
    let e = e.iter().skip_while(|&&b| b == 0).collect::<Vec<_>>();
    if e.is_empty() || e.len() > 4 {
        return proto("licensing: unsupported RSA public exponent");
    }
    let exponent = e.iter().fold(0u32, |a, &&b| a << 8 | b as u32);
    let mut modulus: Vec<u8> = n.iter().rev().copied().collect();
    while modulus.last() == Some(&0) {
        modulus.pop();
    }
    Ok(PublicKey { modulus, exponent })
}

/// The licensing keys (MS-RDPELE 5.1.2).
#[derive(Clone)]
pub struct Keys {
    pub mac_salt: [u8; 16],
    pub encryption: [u8; 16],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.mac_salt.fill(0);
        self.encryption.fill(0);
        std::hint::black_box(&self.mac_salt);
        std::hint::black_box(&self.encryption);
    }
}

/// SaltedHash(S, I) = MD5(S + SHA-1(I + S + A + B)).
fn salted_hash(s: &[u8], i: &[u8], a: &[u8], b: &[u8]) -> [u8; 16] {
    let inner = sha1(&[i, s, a, b].concat());
    md5(&[s, &inner[..]].concat())
}

/// The 48-byte value 'A' + 'BB' + 'CCC' hashes of `s` give.
fn triple(s: &[u8], a: &[u8], b: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (k, i) in [&b"A"[..], b"BB", b"CCC"].into_iter().enumerate() {
        out[k * 16..k * 16 + 16].copy_from_slice(&salted_hash(s, i, a, b));
    }
    out
}

/// MasterSecret, SessionKeyBlob, MAC salt and licensing key (5.1.2).
pub fn derive_keys(
    premaster: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Keys {
    let mut master = triple(premaster, client_random, server_random);
    let mut blob = triple(&master, server_random, client_random);
    let mut mac_salt = [0u8; 16];
    mac_salt.copy_from_slice(&blob[..16]);
    let encryption = md5(&[&blob[16..32], client_random, server_random].concat());
    master.fill(0);
    blob.fill(0);
    std::hint::black_box((&master, &blob));
    Keys {
        mac_salt,
        encryption,
    }
}

/// MACData (5.1.5): MD5(salt + pad2 + SHA-1(salt + pad1 + length + data)).
pub fn mac(salt: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let inner = sha1(
        &[
            salt,
            &[0x36; 40][..],
            &(data.len() as u32).to_le_bytes(),
            data,
        ]
        .concat(),
    );
    md5(&[salt, &[0x5C; 48][..], &inner[..]].concat())
}

/// CLIENT_NEW_LICENSE_REQUEST (2.2.2.2), with its preamble.
pub fn new_license_request(
    client_random: &[u8; 32],
    encrypted_premaster: &[u8],
    user: &str,
    machine: &str,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(KEY_EXCHANGE_ALG_RSA);
    b.put_u32(PLATFORM_ID);
    b.put_bytes(client_random);
    put_blob(&mut b, BB_RANDOM_BLOB, encrypted_premaster);
    put_blob(&mut b, BB_CLIENT_USER_NAME_BLOB, &ansi_z(user));
    put_blob(&mut b, BB_CLIENT_MACHINE_NAME_BLOB, &ansi_z(machine));
    message(NEW_LICENSE_REQUEST, &b)
}

/// CLIENT_LICENSE_INFO (2.2.2.3), with its preamble. The hardware id blob
/// uses BB_DATA_BLOB, as in the MS-RDPELE 4.3 example.
pub fn license_info(
    client_random: &[u8; 32],
    encrypted_premaster: &[u8],
    license: &[u8],
    encrypted_hwid: &[u8],
    mac: &[u8; 16],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(KEY_EXCHANGE_ALG_RSA);
    b.put_u32(PLATFORM_ID);
    b.put_bytes(client_random);
    put_blob(&mut b, BB_RANDOM_BLOB, encrypted_premaster);
    put_blob(&mut b, BB_DATA_BLOB, license);
    put_blob(&mut b, BB_DATA_BLOB, encrypted_hwid);
    b.put_bytes(mac);
    message(LICENSE_INFO, &b)
}

/// CLIENT_PLATFORM_CHALLENGE_RESPONSE (2.2.2.5), with its preamble.
pub fn platform_challenge_response(
    encrypted_response: &[u8],
    encrypted_hwid: &[u8],
    mac: &[u8; 16],
) -> Vec<u8> {
    let mut b = Vec::new();
    put_blob(&mut b, BB_ENCRYPTED_DATA_BLOB, encrypted_response);
    put_blob(&mut b, BB_ENCRYPTED_DATA_BLOB, encrypted_hwid);
    b.put_bytes(mac);
    message(PLATFORM_CHALLENGE_RESPONSE, &b)
}

/// PLATFORM_CHALLENGE_RESPONSE_DATA (2.2.2.5.1): version 0x0100, a Win32
/// client, LICENSE_DETAIL_DETAIL, then the decrypted challenge.
pub fn challenge_response_data(challenge: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(0x0100);
    b.put_u16(0x0100); // WIN32_PLATFORMCHALLENGE_TYPE
    b.put_u16(0x0003); // LICENSE_DETAIL_DETAIL
    b.put_u16(challenge.len() as u16);
    b.put_bytes(challenge);
    b
}

/// LICENSE_ERROR_MESSAGE (MS-RDPBCGR 2.2.1.12.1.3) with an empty error blob.
pub fn error_alert(code: u32, transition: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(code);
    b.put_u32(transition);
    put_blob(&mut b, BB_ERROR_BLOB, &[]);
    message(ERROR_ALERT, &b)
}

/// NEW_LICENSE_INFO (2.2.2.6.1), decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLicenseInfo {
    pub version: u32,
    pub scope: Vec<u8>,
    pub company: Vec<u8>,
    pub product_id: Vec<u8>,
    pub license: Vec<u8>,
}

pub fn parse_new_license_info(data: &[u8]) -> Result<NewLicenseInfo> {
    let mut r = Reader::new(data);
    let version = r.u32()?;
    let field = |r: &mut Reader| -> Result<Vec<u8>> {
        let n = r.u32()? as usize;
        Ok(r.bytes(n)?.to_vec())
    };
    let scope = field(&mut r)?;
    let company = field(&mut r)?;
    let product_id = field(&mut r)?;
    let license = field(&mut r)?;
    Ok(NewLicenseInfo {
        version,
        scope,
        company,
        product_id,
        license,
    })
}

/// Null-terminated 8-bit text; characters outside Latin-1 become '?'.
fn ansi_z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s
        .chars()
        .map(|c| u8::try_from(c as u32).unwrap_or(b'?'))
        .collect();
    v.push(0);
    v
}

/// The client license store (3.3.1.8): one file per license, named by a
/// hash of its index (dwVersion, scope, company, product id), and the
/// client's hardware id (3.3.1.9), random once per store.
#[derive(Debug, Clone)]
pub struct LicenseStore {
    dir: PathBuf,
}

const HWID_FILE: &str = "hardware-id";

impl LicenseStore {
    pub fn new(dir: impl Into<PathBuf>) -> LicenseStore {
        LicenseStore { dir: dir.into() }
    }

    fn path(&self, version: u32, scope: &[u8], company: &[u8], product: &[u8]) -> PathBuf {
        let mut key = Vec::new();
        key.put_u32(version);
        for f in [scope, company, product] {
            key.put_u32(f.len() as u32);
            key.put_bytes(f);
        }
        let h: String = sha256(&key)[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.dir.join(format!("{h}.lic"))
    }

    /// The stored license for the product under any of the scopes.
    pub fn find(&self, product: &ProductInfo, scopes: &[Vec<u8>]) -> Option<Vec<u8>> {
        scopes.iter().find_map(|s| {
            let p = self.path(product.version, s, &product.company, &product.product_id);
            std::fs::read(p).ok().filter(|l| !l.is_empty())
        })
    }

    /// Stores (or replaces) a license; a failure is traced, not fatal.
    pub fn save(&self, info: &NewLicenseInfo) {
        let p = self.path(info.version, &info.scope, &info.company, &info.product_id);
        if let Err(e) = write_file(&p, &info.license) {
            trace!("licensing: cannot store the license: {e}");
        }
    }

    /// The 16 hardware-specific bytes of CLIENT_HARDWARE_ID, created on
    /// first use.
    pub fn hardware_id(&self) -> [u8; 16] {
        let p = self.dir.join(HWID_FILE);
        if let Some(id) = std::fs::read(&p).ok().and_then(|b| b.try_into().ok()) {
            return id;
        }
        let id = random::<16>();
        if let Err(e) = write_file(&p, &id) {
            trace!("licensing: cannot store the hardware id: {e}");
        }
        id
    }
}

fn write_file(p: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, p)
}

/// One licensing exchange's secrets.
struct Session {
    keys: Keys,
}

/// What the caller does after [`Licensing::process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Send the replies and read the next licensing PDU.
    Continue,
    /// Licensing is over; the capability exchange follows.
    Done,
}

/// The client side of the licensing exchange.
pub struct Licensing {
    store: Option<LicenseStore>,
    user: String,
    machine: String,
    hwid: [u8; 20],
    session: Option<Session>,
    /// The last message sent, for ST_RESEND_LAST_MESSAGE.
    last: Option<Vec<u8>>,
    /// An error alert to send before the connection ends.
    alert: Option<Vec<u8>>,
}

impl Licensing {
    /// `store` keeps licenses and the hardware id across connections;
    /// without one, nothing is written and the hardware id is random per
    /// connection.
    pub fn new(store: Option<&Path>, user: &str, machine: &str) -> Licensing {
        let store = store.map(LicenseStore::new);
        let data = store
            .as_ref()
            .map_or_else(random::<16>, LicenseStore::hardware_id);
        let mut hwid = [0u8; 20];
        hwid[..4].copy_from_slice(&PLATFORM_ID.to_le_bytes());
        hwid[4..].copy_from_slice(&data);
        Licensing {
            store,
            user: user.into(),
            machine: machine.into(),
            hwid,
            session: None,
            last: None,
            alert: None,
        }
    }

    /// Handles one licensing PDU from the I/O channel (security header,
    /// preamble, message). Returns the PDUs to send, ready for the I/O
    /// channel, and then the outcome: on an error they hold the client's
    /// error alert (ST_TOTAL_ABORT, 3.3.5.1, 3.3.5.9), and the connection
    /// ends after sending it.
    pub fn process(&mut self, pdu: &[u8]) -> (Vec<Vec<u8>>, Result<Step>) {
        match self.handle(pdu) {
            Ok((send, step)) => (send, Ok(step)),
            Err(e) => (self.alert.take().into_iter().collect(), Err(e)),
        }
    }

    fn handle(&mut self, pdu: &[u8]) -> Result<(Vec<Vec<u8>>, Step)> {
        let mut r = Reader::new(pdu);
        let flags = r.u16()?;
        r.u16()?; // flagsHi
        if flags & SEC_LICENSE_PKT == 0 {
            return proto("expected a licensing PDU");
        }
        let msg_type = r.u8()?;
        r.u8()?; // flags
        let size = r.u16()? as usize;
        let rest = r.rest();
        let msg = &rest[..size.saturating_sub(4).min(rest.len())];
        let reply = match msg_type {
            ERROR_ALERT => return self.error_alert(msg),
            LICENSE_REQUEST => {
                trace!("licensing: server license request");
                self.license_request(msg)?
            }
            PLATFORM_CHALLENGE => {
                trace!("licensing: platform challenge");
                self.platform_challenge(msg)?
            }
            NEW_LICENSE | UPGRADE_LICENSE => {
                trace!(
                    "licensing: {} license received",
                    if msg_type == NEW_LICENSE {
                        "new"
                    } else {
                        "upgraded"
                    }
                );
                self.new_license(msg)?;
                return Ok((Vec::new(), Step::Done));
            }
            t => return proto(format!("unexpected licensing message {t:#x}")),
        };
        let pdu = with_security_header(&reply);
        self.last = Some(pdu.clone());
        Ok((vec![pdu], Step::Continue))
    }

    fn error_alert(&mut self, msg: &[u8]) -> Result<(Vec<Vec<u8>>, Step)> {
        let mut r = Reader::new(msg);
        let code = r.u32()?;
        let transition = r.u32()?;
        let name = error_name(code);
        if code == STATUS_VALID_CLIENT {
            trace!("licensing: valid client");
            return Ok((Vec::new(), Step::Done));
        }
        match transition {
            // The server is done with licensing (3.1.5.3); it decides
            // whether the session goes on.
            ST_NO_TRANSITION => {
                trace!("licensing: server error {name} ({code:#x}), no transition");
                Ok((Vec::new(), Step::Done))
            }
            ST_RESEND_LAST_MESSAGE => {
                trace!("licensing: server asks to resend ({name})");
                Ok((self.last.clone().into_iter().collect(), Step::Continue))
            }
            ST_RESET_PHASE_TO_START => {
                trace!("licensing: server restarts licensing ({name})");
                self.session = None;
                self.last = None;
                Ok((Vec::new(), Step::Continue))
            }
            _ => proto(format!("licensing error {code:#x} ({name})")),
        }
    }

    fn abort(&mut self, code: u32, why: &str) -> Error {
        trace!("licensing: aborting: {why}");
        self.alert = Some(with_security_header(&error_alert(code, ST_TOTAL_ABORT)));
        Error::Protocol(format!("licensing: {why}"))
    }

    fn license_request(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let req = parse_license_request(msg)?;
        if req.certificate.is_empty() {
            return Err(Error::Unsupported(
                "licensing without a server certificate (needs Standard RDP Security)".into(),
            ));
        }
        let key = match server_public_key(&req.certificate) {
            Ok(k) => k,
            Err(e) => {
                return Err(self.abort(ERR_INVALID_SERVER_CERTIFICATE, &e.to_string()));
            }
        };
        let client_random = random::<32>();
        let mut premaster = random::<48>();
        let encrypted = key.encrypt(&premaster)?;
        let keys = derive_keys(&premaster, &client_random, &req.server_random);
        premaster.fill(0);
        std::hint::black_box(&premaster);
        let stored = self
            .store
            .as_ref()
            .and_then(|s| s.find(&req.product, &req.scopes));
        let reply = match stored {
            Some(license) => {
                trace!("licensing: presenting the stored license");
                let enc_hwid = rc4_once(&keys.encryption, &self.hwid);
                let m = mac(&keys.mac_salt, &self.hwid);
                license_info(&client_random, &encrypted, &license, &enc_hwid, &m)
            }
            None => {
                trace!("licensing: requesting a new license");
                new_license_request(&client_random, &encrypted, &self.user, &self.machine)
            }
        };
        self.session = Some(Session { keys });
        Ok(reply)
    }

    fn platform_challenge(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let Some(s) = &self.session else {
            return proto("licensing: platform challenge before a license request");
        };
        let keys = s.keys.clone();
        let mut r = Reader::new(msg);
        r.u32()?; // ConnectFlags
        let (_, encrypted) = read_blob(&mut r)?;
        let their_mac = r.array::<16>()?;
        let challenge = rc4_once(&keys.encryption, encrypted);
        if mac(&keys.mac_salt, &challenge) != their_mac {
            return Err(self.abort(ERR_INVALID_MAC, "platform challenge MAC mismatch"));
        }
        let data = challenge_response_data(&challenge);
        let m = mac(&keys.mac_salt, &[&data[..], &self.hwid].concat());
        // Each field is encrypted with a fresh RC4 state (MS-RDPELE 4.5).
        let enc_data = rc4_once(&keys.encryption, &data);
        let enc_hwid = rc4_once(&keys.encryption, &self.hwid);
        Ok(platform_challenge_response(&enc_data, &enc_hwid, &m))
    }

    fn new_license(&mut self, msg: &[u8]) -> Result<()> {
        let Some(s) = &self.session else {
            return proto("licensing: license before a license request");
        };
        let keys = s.keys.clone();
        let mut r = Reader::new(msg);
        let (_, encrypted) = read_blob(&mut r)?;
        let their_mac = r.array::<16>()?;
        let info = rc4_once(&keys.encryption, encrypted);
        if mac(&keys.mac_salt, &info) != their_mac {
            return Err(self.abort(ERR_INVALID_MAC, "new license MAC mismatch"));
        }
        let info = parse_new_license_info(&info)?;
        if let Some(store) = &self.store {
            store.save(&info);
        }
        self.session = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "license_tests.rs"]
mod tests;
