//! Standard RDP Security (MS-RDPBCGR 5.3): the legacy security layer of
//! servers without TLS. Only used when a connection explicitly allows it
//! ([`crate::Config::legacy_security`]); it is never chosen on its own.
//!
//! - The server sends a 32-byte random and its RSA key in a proprietary
//!   certificate (signed with the published Terminal Services key,
//!   5.3.3.1) or an X.509 chain (5.3.3.2) in the Server Security Data
//!   (2.2.1.4.3).
//! - The client sends its own random, RSA-encrypted with that key, in the
//!   Security Exchange PDU (2.2.1.10, 5.3.4.1).
//! - Both derive a MAC key and one RC4 key per direction (5.3.5.1), 40, 56
//!   or 128 bits; every PDU carries an 8-byte MAC over its plaintext
//!   (5.3.6.1, salted with the packet count when SEC_SECURE_CHECKSUM is
//!   set, 5.3.6.1.1) and each RC4 key is replaced after 4,096 packets
//!   (5.3.7.1).
//!
//! At the FIPS level (5.3.5.2) the same exchange gives Triple DES keys
//! instead: one EDE3 CBC stream per direction, chained across packets,
//! data padded to whole blocks, and an HMAC-SHA-1 over the plaintext and
//! the packet count as the MAC (5.3.6.2). There are no key updates; the
//! security headers carry a version and the pad length (2.2.8.1.1.2.3,
//! fipsInformation in fast-path PDUs).
//!
//! None of this resists an active attacker the way TLS does: the server's
//! identity rests on trust on first use of its key, RC4 is broken, and
//! 40- and 56-bit keys are brute-forceable. Keys are never logged.

use crate::crypto::{Rc4, md5, rc4_once, rsa_encrypt_le, sha1};
use crate::cursor::{Put, Reader};
use crate::des::TripleDesCbc;
use crate::error::{Error, Result, proto};
use crate::license::{self, PublicKey, salted_hash};

/// Encryption methods (2.2.1.3.3, 2.2.1.4.3).
pub const ENCRYPTION_METHOD_40BIT: u32 = 0x01;
pub const ENCRYPTION_METHOD_128BIT: u32 = 0x02;
pub const ENCRYPTION_METHOD_56BIT: u32 = 0x08;
pub const ENCRYPTION_METHOD_FIPS: u32 = 0x10;
/// What the client offers in its Client Security Data (2.2.1.3.3) under
/// Standard RDP Security: 40, 56 and 128-bit RC4 and FIPS.
pub const CLIENT_ENCRYPTION_METHODS: u32 = ENCRYPTION_METHOD_40BIT
    | ENCRYPTION_METHOD_56BIT
    | ENCRYPTION_METHOD_128BIT
    | ENCRYPTION_METHOD_FIPS;

/// Encryption levels (2.2.1.4.3, 5.3.1).
pub const ENCRYPTION_LEVEL_LOW: u32 = 1;
pub const ENCRYPTION_LEVEL_CLIENT_COMPATIBLE: u32 = 2;
pub const ENCRYPTION_LEVEL_HIGH: u32 = 3;
pub const ENCRYPTION_LEVEL_FIPS: u32 = 4;

/// Security header flags (2.2.8.1.1.2.1).
pub const SEC_EXCHANGE_PKT: u16 = 0x0001;
pub const SEC_ENCRYPT: u16 = 0x0008;
const SEC_RESET_SEQNO: u16 = 0x0010;
const SEC_IGNORE_SEQNO: u16 = 0x0020;
pub const SEC_LICENSE_PKT: u16 = 0x0080;
/// SEC_LICENSE_ENCRYPT_CS from the server, SEC_LICENSE_ENCRYPT_SC from
/// the client: the sender takes encrypted licensing PDUs.
pub const SEC_LICENSE_ENCRYPT: u16 = 0x0200;
pub const SEC_REDIRECTION_PKT: u16 = 0x0400;
pub const SEC_SECURE_CHECKSUM: u16 = 0x0800;
const SEC_FLAGSHI_VALID: u16 = 0x8000;

/// Fast-path header flags, the top two bits of fpInputHeader and
/// fpOutputHeader (2.2.8.1.2, 2.2.9.1.2).
const FASTPATH_SECURE_CHECKSUM: u8 = 0x1;
const FASTPATH_ENCRYPTED: u8 = 0x2;

/// Packets per RC4 key before it is updated (5.3.7.1).
const KEY_UPDATE_INTERVAL: u32 = 4096;

/// The FIPS level's 3DES CBC initialization vector (5.3.5.2).
const FIPS_IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
/// TS_SECURITY_HEADER2 (2.2.8.1.1.2.3) and fipsInformation: the header
/// length and TSFIPS_VERSION1.
const FIPS_HEADER_LENGTH: u16 = 0x10;
const TSFIPS_VERSION1: u8 = 1;

/// The Terminal Services signing key (5.3.3.1.1): modulus, little-endian.
const TS_SIGNING_MODULUS: [u8; 64] = [
    0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9, 0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
    0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2, 0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
    0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef, 0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
    0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb, 0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87,
];
/// Its public exponent (bytes 5b 7b 88 c0, little-endian).
const TS_SIGNING_EXPONENT: u32 = 0xC088_7B5B;

/// The start of the error when a server offers only Standard RDP Security
/// and the connection does not allow it; the app matches it to name its
/// own setting.
pub const LEGACY_REFUSED: &str = "the server offers only legacy RDP security";

/// The refusal for a server that offers only Standard RDP Security while
/// [`crate::Config::legacy_security`] is off.
pub fn legacy_refused() -> Error {
    Error::Unsupported(format!(
        "{LEGACY_REFUSED} (Standard RDP Security: RC4, no TLS, no server \
         authentication); allow legacy RDP security for this connection to \
         connect anyway (Config::legacy_security, remora --legacy-security)"
    ))
}

/// Negotiated key strength (5.3.5.1, Table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStrength {
    Bits40,
    Bits56,
    Bits128,
}

impl KeyStrength {
    /// The RC4 strength of a server-selected encryptionMethod (2.2.1.4.3).
    /// No encryption at all is never accepted; FIPS has no RC4 strength
    /// (see [`check_method`]).
    pub fn from_method(method: u32) -> Result<KeyStrength> {
        match method {
            ENCRYPTION_METHOD_40BIT => Ok(KeyStrength::Bits40),
            ENCRYPTION_METHOD_56BIT => Ok(KeyStrength::Bits56),
            ENCRYPTION_METHOD_128BIT => Ok(KeyStrength::Bits128),
            ENCRYPTION_METHOD_FIPS => proto("FIPS encryption uses Triple DES, not RC4"),
            0 => Err(Error::Unsupported(
                "the server offers no encryption at all; refused".into(),
            )),
            m => proto(format!("unknown encryption method {m:#x}")),
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            KeyStrength::Bits40 => 40,
            KeyStrength::Bits56 => 56,
            KeyStrength::Bits128 => 128,
        }
    }

    /// The RC4 key from a 128-bit one: salted down to 64 bits for 40 and
    /// 56 bits (5.3.5.1), else unchanged. `key` has at least 16 bytes.
    fn reduce(self, key: &[u8]) -> Vec<u8> {
        match self {
            KeyStrength::Bits40 => [&[0xD1, 0x26, 0x9E][..], &key[3..8]].concat(),
            KeyStrength::Bits56 => [&[0xD1][..], &key[1..8]].concat(),
            KeyStrength::Bits128 => key[..16].to_vec(),
        }
    }
}

/// The client's initial keys (5.3.5.1). `Debug` is not derived: these are secrets.
pub struct SessionKeys {
    pub mac: Vec<u8>,
    pub encrypt: Vec<u8>,
    pub decrypt: Vec<u8>,
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        for k in [&mut self.mac, &mut self.encrypt, &mut self.decrypt] {
            k.fill(0);
            std::hint::black_box(&k);
        }
    }
}

/// The client's MAC, encryption and decryption keys from the two randoms
/// (5.3.5.1): PreMasterSecret, MasterSecret, SessionKeyBlob, FinalHash,
/// then salted to the negotiated strength.
pub fn session_keys(client: &[u8; 32], server: &[u8; 32], strength: KeyStrength) -> SessionKeys {
    let hash3 = |s: &[u8], labels: [&[u8]; 3]| -> Vec<u8> {
        labels
            .iter()
            .flat_map(|i| salted_hash(s, i, client, server))
            .collect()
    };
    let mut pre = [&client[..24], &server[..24]].concat();
    let mut master = hash3(&pre, [b"A", b"BB", b"CCC"]);
    let mut blob = hash3(&master, [b"X", b"YY", b"ZZZ"]);
    let final_hash = |k: &[u8]| md5(&[k, client, server].concat());
    let keys = SessionKeys {
        mac: strength.reduce(&blob[..16]),
        // The client decrypts with the key the server encrypts with.
        decrypt: strength.reduce(&final_hash(&blob[16..32])),
        encrypt: strength.reduce(&final_hash(&blob[32..48])),
    };
    for v in [&mut pre, &mut master, &mut blob] {
        v.fill(0);
        std::hint::black_box(&v);
    }
    keys
}

/// The 8-byte MAC (5.3.6.1): First64Bits(MD5(MACKeyN + Pad2 +
/// SHA(MACKeyN + Pad1 + DataLength + Data))); with `count`, the salted
/// variant appends the encryption count to the SHA input (5.3.6.1.1).
pub fn mac_signature(key: &[u8], data: &[u8], count: Option<u32>) -> [u8; 8] {
    let count = count.map(u32::to_le_bytes);
    let inner = sha1(
        &[
            key,
            &[0x36; 40][..],
            &(data.len() as u32).to_le_bytes(),
            data,
            count.as_ref().map_or(&[][..], |c| &c[..]),
        ]
        .concat(),
    );
    let outer = md5(&[key, &[0x5C; 48][..], &inner[..]].concat());
    outer[..8].try_into().expect("8 bytes")
}

/// The next RC4 key after 4,096 packets (5.3.7.1).
pub fn update_key(initial: &[u8], current: &[u8], strength: KeyStrength) -> Vec<u8> {
    let inner = sha1(&[initial, &[0x36; 40][..], current].concat());
    let temp = md5(&[initial, &[0x5C; 48][..], &inner[..]].concat());
    match strength {
        KeyStrength::Bits128 => rc4_once(&temp, &temp),
        _ => {
            let t64 = &temp[..8];
            // NewEncryptKey40/56: the salt over Last40/56Bits(PreSaltKey).
            strength.reduce(&rc4_once(t64, t64))
        }
    }
}

/// A server-selected encryptionMethod Remora can use: 40, 56 or 128-bit
/// RC4, or FIPS (2.2.1.4.3).
pub fn check_method(method: u32) -> Result<()> {
    if method == ENCRYPTION_METHOD_FIPS {
        return Ok(());
    }
    KeyStrength::from_method(method).map(|_| ())
}

/// The client's FIPS keys (5.3.5.2). `Debug` is not derived: these are secrets.
pub struct FipsKeys {
    pub hmac: [u8; 20],
    pub encrypt: [u8; 24],
    pub decrypt: [u8; 24],
}

impl Drop for FipsKeys {
    fn drop(&mut self) {
        self.hmac.fill(0);
        self.encrypt.fill(0);
        self.decrypt.fill(0);
        std::hint::black_box((&self.hmac, &self.encrypt, &self.decrypt));
    }
}

/// A 168-bit 3DES key (the SHA-1 hash and its first byte again) spread
/// to 24 bytes with odd parity, as Windows does it (5.3.5.2): seven bits
/// per byte, the bits of each byte taken least significant first.
fn fips_expand(key: &[u8; 21]) -> [u8; 24] {
    let bits: Vec<u8> = key
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1))
        .collect();
    std::array::from_fn(|i| {
        // Bits 0 to 6 of byte i are stream bits 7i..7i+6; bit 7 is zero.
        let b = (0..7).fold(0u8, |acc, j| acc | (bits[7 * i + j] << j));
        // Then the least significant bit makes the parity odd. DES never
        // reads that bit, so overwriting stream bit 7i is harmless here
        // and matches what the server derives.
        let high = b & 0xFE;
        high | u8::from(high.count_ones().is_multiple_of(2))
    })
}

/// The client's FIPS keys from the two randoms (5.3.5.2):
/// ClientEncryptKeyT = SHA1(Last128Bits(ClientRandom) +
/// Last128Bits(ServerRandom)), ClientDecryptKeyT from the first 128
/// bits, HMACKey = SHA1(ClientDecryptKeyT + ClientEncryptKeyT).
pub fn fips_keys(client: &[u8; 32], server: &[u8; 32]) -> FipsKeys {
    let mut encrypt_t = sha1(&[&client[16..], &server[16..]].concat());
    let mut decrypt_t = sha1(&[&client[..16], &server[..16]].concat());
    let hmac = sha1(&[&decrypt_t[..], &encrypt_t[..]].concat());
    let widen = |t: &[u8; 20]| -> [u8; 24] {
        let mut k = [0u8; 21];
        k[..20].copy_from_slice(t);
        k[20] = t[0];
        let out = fips_expand(&k);
        k.fill(0);
        std::hint::black_box(&k);
        out
    };
    let keys = FipsKeys {
        hmac,
        encrypt: widen(&encrypt_t),
        decrypt: widen(&decrypt_t),
    };
    encrypt_t.fill(0);
    decrypt_t.fill(0);
    std::hint::black_box((&encrypt_t, &decrypt_t));
    keys
}

/// The FIPS MAC (5.3.6.2): the first 8 bytes of HMAC-SHA-1(HMACKey,
/// Data + EncryptionCount).
pub fn fips_mac(key: &[u8; 20], data: &[u8], count: u32) -> [u8; 8] {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let mut ctx = ring::hmac::Context::with_key(&k);
    ctx.update(data);
    ctx.update(&count.to_le_bytes());
    ctx.sign().as_ref()[..8].try_into().expect("8 bytes")
}

/// One direction's RC4 stream with its key updates.
struct Cipher {
    strength: KeyStrength,
    initial: Vec<u8>,
    key: Vec<u8>,
    rc4: Rc4,
    /// Packets since the last key update.
    used: u32,
    /// Packets so far: the salted MAC's EncryptionCount (5.3.6.1.1).
    count: u32,
}

impl Cipher {
    fn new(key: &[u8], strength: KeyStrength) -> Cipher {
        Cipher {
            strength,
            initial: key.to_vec(),
            key: key.to_vec(),
            rc4: Rc4::new(key),
            used: 0,
            count: 0,
        }
    }

    /// Encrypts or decrypts one packet in place, updating the key first
    /// when the current one has done 4,096 packets.
    fn apply(&mut self, data: &mut [u8]) {
        if self.used == KEY_UPDATE_INTERVAL {
            self.key = update_key(&self.initial, &self.key, self.strength);
            self.rc4 = Rc4::new(&self.key);
            self.used = 0;
            crate::trace!(
                "legacy RDP security: RC4 key updated after {} packets",
                self.count
            );
        }
        self.rc4.process(data);
        self.used += 1;
        self.count = self.count.wrapping_add(1);
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.initial.fill(0);
        self.key.fill(0);
        std::hint::black_box((&self.initial, &self.key));
    }
}

/// The ciphers and MAC key of one connection: RC4 at 40, 56 or 128 bits,
/// or the FIPS level's Triple DES.
enum Keys {
    Rc4 {
        strength: KeyStrength,
        mac_key: Vec<u8>,
        encrypt: Cipher,
        decrypt: Cipher,
    },
    Fips {
        hmac: [u8; 20],
        encrypt: TripleDesCbc,
        decrypt: TripleDesCbc,
        /// Packets sent and received: the MAC's EncryptionCount (5.3.6.2).
        sent: u32,
        received: u32,
    },
}

impl Drop for Keys {
    fn drop(&mut self) {
        match self {
            Keys::Rc4 { mac_key, .. } => {
                mac_key.fill(0);
                std::hint::black_box(mac_key);
            }
            Keys::Fips { hmac, .. } => {
                hmac.fill(0);
                std::hint::black_box(hmac);
            }
        }
    }
}

/// The negotiated Standard RDP Security state of one connection.
pub struct StandardSecurity {
    keys: Keys,
    level: u32,
    /// Sign outgoing PDUs with the salted MAC: both General Capability
    /// Sets carry ENC_SALTED_CHECKSUM (5.3.6.1.1). RC4 only.
    salted: bool,
    /// The server takes encrypted licensing PDUs (SEC_LICENSE_ENCRYPT_CS).
    pub(crate) license_encrypt: bool,
}

/// The FIPS fields of a security header or fast-path PDU: the length
/// 0x10, TSFIPS_VERSION1 and the pad length (2.2.8.1.1.2.3).
fn fips_information(pad: u8) -> [u8; 4] {
    let [lo, hi] = FIPS_HEADER_LENGTH.to_le_bytes();
    [lo, hi, TSFIPS_VERSION1, pad]
}

/// Reads [`fips_information`] and returns the pad length.
fn read_fips_information(r: &mut Reader) -> Result<u8> {
    let length = r.u16()?;
    let version = r.u8()?;
    let pad = r.u8()?;
    if length != FIPS_HEADER_LENGTH || version != TSFIPS_VERSION1 {
        return proto(format!(
            "FIPS security header of length {length:#x}, version {version}"
        ));
    }
    Ok(pad)
}

impl StandardSecurity {
    /// The state for the server's encryptionMethod and encryptionLevel
    /// (2.2.1.4.3) and the two randoms. Level 0 is refused.
    pub fn new(
        method: u32,
        level: u32,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<StandardSecurity> {
        if method == ENCRYPTION_METHOD_FIPS {
            if !(ENCRYPTION_LEVEL_LOW..=ENCRYPTION_LEVEL_FIPS).contains(&level) {
                return proto(format!("encryption level {level} with FIPS encryption"));
            }
            let keys = fips_keys(client_random, server_random);
            return Ok(StandardSecurity::from_fips_keys(level, &keys));
        }
        let strength = KeyStrength::from_method(method)?;
        if !(ENCRYPTION_LEVEL_LOW..=ENCRYPTION_LEVEL_HIGH).contains(&level) {
            return proto(format!(
                "encryption level {level} with encryption method {method:#x}"
            ));
        }
        let keys = session_keys(client_random, server_random, strength);
        Ok(StandardSecurity::from_keys(strength, level, &keys))
    }

    /// The RC4 state from given keys; a test plays the server by swapping
    /// the encryption and decryption keys.
    pub(crate) fn from_keys(strength: KeyStrength, level: u32, k: &SessionKeys) -> Self {
        StandardSecurity {
            keys: Keys::Rc4 {
                strength,
                mac_key: k.mac.clone(),
                encrypt: Cipher::new(&k.encrypt, strength),
                decrypt: Cipher::new(&k.decrypt, strength),
            },
            level,
            salted: false,
            license_encrypt: false,
        }
    }

    /// The FIPS state from given keys; a test plays the server by swapping
    /// the encryption and decryption keys.
    pub(crate) fn from_fips_keys(level: u32, k: &FipsKeys) -> Self {
        StandardSecurity {
            keys: Keys::Fips {
                hmac: k.hmac,
                encrypt: TripleDesCbc::new(&k.encrypt, FIPS_IV, false),
                decrypt: TripleDesCbc::new(&k.decrypt, FIPS_IV, true),
                sent: 0,
                received: 0,
            },
            level,
            salted: false,
            license_encrypt: false,
        }
    }

    fn fips(&self) -> bool {
        matches!(self.keys, Keys::Fips { .. })
    }

    /// For traces: "128-bit RC4, encryption level 2".
    pub fn describe(&self) -> String {
        match &self.keys {
            Keys::Rc4 { strength, .. } => format!(
                "{}-bit RC4, encryption level {}",
                strength.bits(),
                self.level
            ),
            Keys::Fips { .. } => format!("FIPS Triple DES, encryption level {}", self.level),
        }
    }

    /// Sign outgoing PDUs with the salted MAC (5.3.6.1.1), once the
    /// server's General Capability Set carries ENC_SALTED_CHECKSUM. The
    /// FIPS MAC always includes the packet count.
    pub fn set_salted_mac(&mut self, on: bool) {
        self.salted = on && !self.fips();
    }

    /// Signs and encrypts `data` in place; returns its MAC and, at the
    /// FIPS level, the pad length (the data is padded to whole blocks).
    fn seal(&mut self, data: &mut Vec<u8>) -> ([u8; 8], Option<u8>) {
        match &mut self.keys {
            Keys::Rc4 {
                mac_key, encrypt, ..
            } => {
                let count = self.salted.then_some(encrypt.count);
                let sig = mac_signature(mac_key, data, count);
                encrypt.apply(data);
                (sig, None)
            }
            Keys::Fips {
                hmac,
                encrypt,
                sent,
                ..
            } => {
                let sig = fips_mac(hmac, data, *sent);
                let pad = (8 - data.len() % 8) % 8;
                data.resize(data.len() + pad, 0);
                encrypt.process(data);
                *sent = sent.wrapping_add(1);
                (sig, Some(pad as u8))
            }
        }
    }

    /// Decrypts `data` in place and checks its MAC (5.3.6.1, 5.3.6.2): a
    /// mismatch ends the connection. `pad` is the FIPS pad length.
    fn open(
        &mut self,
        data: &mut Vec<u8>,
        sig: &[u8; 8],
        salted: bool,
        pad: Option<u8>,
    ) -> Result<()> {
        let ok = match (&mut self.keys, pad) {
            (
                Keys::Rc4 {
                    mac_key, decrypt, ..
                },
                None,
            ) => {
                let count = decrypt.count;
                decrypt.apply(data);
                mac_signature(mac_key, data, salted.then_some(count)) == *sig
            }
            (
                Keys::Fips {
                    hmac,
                    decrypt,
                    received,
                    ..
                },
                Some(pad),
            ) => {
                // Windows pads whole blocks with 8 bytes, never more.
                if !data.len().is_multiple_of(8) || pad > 8 || pad as usize > data.len() {
                    return proto(format!(
                        "FIPS data of {} bytes with {pad} bytes of padding",
                        data.len()
                    ));
                }
                decrypt.process(data);
                data.truncate(data.len() - pad as usize);
                let count = *received;
                *received = received.wrapping_add(1);
                fips_mac(hmac, data, count) == *sig
            }
            _ => return proto("Standard RDP Security: security header of the wrong kind"),
        };
        if !ok {
            return proto(
                "Standard RDP Security: MAC mismatch (data altered, or keys out of step)",
            );
        }
        Ok(())
    }

    /// An outgoing slow-path PDU (MCS user data): `flags` are its basic
    /// security header flags (0 for share control and channel data,
    /// SEC_INFO_PKT, SEC_LICENSE_PKT, ...), `body` what follows the header.
    /// Everything is encrypted (every level encrypts client-to-server
    /// traffic, 5.3.6) except licensing PDUs the server did not ask to get
    /// encrypted (2.2.1.12) and the Security Exchange PDU.
    pub fn wrap(&mut self, flags: u16, body: &[u8]) -> Vec<u8> {
        let plain = flags & SEC_EXCHANGE_PKT != 0
            || (flags & SEC_LICENSE_PKT != 0 && !self.license_encrypt);
        let mut out = Vec::with_capacity(body.len() + 24);
        if plain {
            out.put_u16(flags);
            out.put_u16(0);
            out.put_bytes(body);
            return out;
        }
        let checksum = if self.salted { SEC_SECURE_CHECKSUM } else { 0 };
        let mut data = body.to_vec();
        let (sig, pad) = self.seal(&mut data);
        out.put_u16(flags | SEC_ENCRYPT | checksum);
        out.put_u16(0);
        if let Some(pad) = pad {
            // TS_SECURITY_HEADER2 (2.2.8.1.1.2.3).
            out.put_bytes(&fips_information(pad));
        }
        out.put_bytes(&sig);
        out.put_bytes(&data);
        out
    }

    /// An incoming slow-path PDU (MCS user data), decrypted and checked,
    /// in the form Enhanced RDP Security delivers it: share control and
    /// channel data without a security header, typed PDUs (licensing,
    /// heartbeat, auto-detect, redirection) with a basic one.
    ///
    /// Above ENCRYPTION_LEVEL_LOW the server encrypts everything, so an
    /// unencrypted PDU without a type flag is refused (an attacker could
    /// otherwise inject plaintext share data).
    pub fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut r = Reader::new(data);
        let flags = r.u16()?;
        r.u16()?; // flagsHi
        // A Standard Security Server Redirection PDU is encrypted without
        // SEC_ENCRYPT (2.2.8.1.1.2.1, 4.5).
        let encrypted = flags & (SEC_ENCRYPT | SEC_REDIRECTION_PKT) != 0;
        let mut body;
        if encrypted {
            let pad = if self.fips() {
                Some(read_fips_information(&mut r)?)
            } else {
                None
            };
            let sig = r.array::<8>()?;
            body = r.rest().to_vec();
            self.open(&mut body, &sig, flags & SEC_SECURE_CHECKSUM != 0, pad)?;
        } else {
            body = r.rest().to_vec();
        }
        if flags & SEC_LICENSE_PKT != 0 && flags & SEC_LICENSE_ENCRYPT != 0 {
            self.license_encrypt = true;
        }
        let kept = flags
            & !(SEC_ENCRYPT
                | SEC_SECURE_CHECKSUM
                | SEC_RESET_SEQNO
                | SEC_IGNORE_SEQNO
                | SEC_FLAGSHI_VALID
                | SEC_LICENSE_ENCRYPT);
        if kept == 0 {
            if !encrypted && self.level > ENCRYPTION_LEVEL_LOW {
                return proto("Standard RDP Security: unencrypted share data from the server");
            }
            return Ok(body);
        }
        let mut out = Vec::with_capacity(body.len() + 4);
        out.put_u16(kept);
        out.put_u16(0);
        out.put_bytes(&body);
        Ok(out)
    }

    /// An incoming fast-path output PDU (2.2.9.1.2), decrypted and checked,
    /// without its security flags, fipsInformation and dataSignature: what
    /// [`crate::fastpath::Reassembler`] reads.
    pub fn fastpath_output(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let (header, mut data, sig) = split_fastpath(frame, self.fips())?;
        let flags = header >> 6;
        match sig {
            Some((sig, pad)) => {
                self.open(&mut data, &sig, flags & FASTPATH_SECURE_CHECKSUM != 0, pad)?
            }
            None if self.level > ENCRYPTION_LEVEL_LOW => {
                return proto(
                    "Standard RDP Security: unencrypted fast-path update from the server",
                );
            }
            None => {}
        }
        Ok(fastpath_frame(header & 0x3F, &[], &data))
    }

    /// An outgoing fast-path input PDU (2.2.8.1.2) from
    /// [`crate::input::fastpath_input`], signed and encrypted.
    pub fn fastpath_input(&mut self, pdu: &[u8]) -> Vec<u8> {
        let (header, mut data, _) =
            split_fastpath(pdu, false).expect("our own fast-path input PDU");
        let checksum = if self.salted {
            FASTPATH_SECURE_CHECKSUM
        } else {
            0
        };
        let (sig, pad) = self.seal(&mut data);
        let header = header & 0x3F | (FASTPATH_ENCRYPTED | checksum) << 6;
        let prefix = match pad {
            Some(pad) => [&fips_information(pad)[..], &sig[..]].concat(),
            None => sig.to_vec(),
        };
        fastpath_frame(header, &prefix, &data)
    }
}

/// A fast-path PDU's header byte, its data, and, when the encrypted flag
/// is set, its dataSignature with the pad length from its fipsInformation
/// when `fips` (2.2.8.1.2, 2.2.9.1.2).
#[allow(clippy::type_complexity)]
fn split_fastpath(
    frame: &[u8],
    fips: bool,
) -> Result<(u8, Vec<u8>, Option<([u8; 8], Option<u8>)>)> {
    let mut r = Reader::new(frame);
    let header = r.u8()?;
    let len1 = r.u8()?;
    let len = if len1 & 0x80 != 0 {
        ((len1 as usize & 0x7F) << 8) | r.u8()? as usize
    } else {
        len1 as usize
    };
    if len != frame.len() {
        return proto(format!("fast-path length {len}, frame of {}", frame.len()));
    }
    let sig = if (header >> 6) & FASTPATH_ENCRYPTED != 0 {
        let pad = if fips {
            Some(read_fips_information(&mut r)?)
        } else {
            None
        };
        Some((r.array::<8>()?, pad))
    } else {
        None
    };
    Ok((header, r.rest().to_vec(), sig))
}

/// A fast-path PDU: header, length (one byte when it fits), `prefix`
/// (fipsInformation and dataSignature), `data`.
fn fastpath_frame(header: u8, prefix: &[u8], data: &[u8]) -> Vec<u8> {
    let short = 2 + prefix.len() + data.len();
    let mut out = vec![header];
    if short < 0x80 {
        out.put_u8(short as u8);
    } else {
        out.put_u16_be(0x8000 | (short + 1) as u16);
    }
    out.put_bytes(prefix);
    out.put_bytes(data);
    out
}

/// The Security Exchange PDU's user data (2.2.1.10): a basic security
/// header with SEC_EXCHANGE_PKT and SEC_LICENSE_ENCRYPT_SC (the client
/// takes encrypted licensing PDUs, 3.2.5.3.10), the length, and the
/// encrypted client random with its 8 zero bytes.
pub fn security_exchange_pdu(encrypted_random: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encrypted_random.len() + 8);
    out.put_u16(SEC_EXCHANGE_PKT | SEC_LICENSE_ENCRYPT);
    out.put_u16(0);
    out.put_u32(encrypted_random.len() as u32);
    out.put_bytes(encrypted_random);
    out
}

/// The client random encrypted with the server's key (5.3.4.1): the
/// modulus length plus 8 zero bytes.
pub fn encrypt_client_random(key: &PublicKey, random: &[u8; 32]) -> Result<Vec<u8>> {
    rsa_encrypt_le(random, &key.modulus, key.exponent).ok_or_else(|| {
        Error::Protocol("the server's RSA key cannot encrypt the client random".into())
    })
}

/// The server's public key from the Server Security Data certificate
/// (2.2.1.4.3.1). A proprietary certificate must carry a valid signature
/// by the Terminal Services key (5.3.3.1.3); an X.509 chain (issued by a
/// license server) cannot be checked against anything the client trusts,
/// so it is taken as is (the caller pins the certificate).
pub fn server_key(cert: &[u8]) -> Result<PublicKey> {
    let mut r = Reader::new(cert);
    if r.u32()? & 0x7FFF_FFFF != 1 {
        return license::server_public_key(cert)
            .map_err(|e| Error::Protocol(format!("server certificate: {e}")));
    }
    // PROPRIETARYSERVERCERTIFICATE (2.2.1.4.3.1.1).
    let sig_alg = r.u32()?;
    let key_alg = r.u32()?;
    if sig_alg != 1 || key_alg != 1 {
        return proto(format!(
            "proprietary certificate algorithms {sig_alg}/{key_alg}"
        ));
    }
    if r.u16()? != 0x0006 {
        return proto("proprietary certificate without BB_RSA_KEY_BLOB");
    }
    let key_len = r.u16()? as usize;
    let key = r.bytes(key_len)?;
    let signed = &cert[..16 + key_len];
    if r.u16()? != 0x0008 {
        return proto("proprietary certificate without BB_RSA_SIGNATURE_BLOB");
    }
    let sig_len = r.u16()? as usize;
    let sig = r.bytes(sig_len)?;
    // RSA_PUBLIC_KEY (2.2.1.4.3.1.1.1).
    let mut k = Reader::new(key);
    if k.u32()? != 0x3141_5352 {
        return proto("server RSA key without the RSA1 magic");
    }
    let keylen = k.u32()? as usize;
    let bitlen = k.u32()? as usize;
    k.u32()?; // datalen
    let exponent = k.u32()?;
    let modulus = k.bytes(keylen)?;
    if !bitlen.is_multiple_of(8) || bitlen / 8 > keylen {
        return proto(format!("server RSA key of {bitlen} bits in {keylen} bytes"));
    }
    // 5.3.3.1.3: s^e mod n is the MD5 hash, 0x00, 0xFF up to byte 62, 0x01.
    let m = rsa_encrypt_le(sig, &TS_SIGNING_MODULUS, TS_SIGNING_EXPONENT)
        .ok_or_else(|| Error::Auth("the server's certificate signature is malformed".into()))?;
    let mut want = [0xFFu8; 63];
    want[..16].copy_from_slice(&md5(signed));
    want[16] = 0;
    want[62] = 1;
    if m[..63] != want || m[63..].iter().any(|&b| b != 0) {
        return Err(Error::Auth(
            "the server's proprietary certificate has an invalid signature".into(),
        ));
    }
    Ok(PublicKey {
        modulus: modulus[..bitlen / 8].to_vec(),
        exponent,
    })
}

#[cfg(test)]
#[path = "security_tests.rs"]
pub(crate) mod tests;
