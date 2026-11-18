//! NTLMv2 client (MS-NLMP), connection-oriented with extended session security,
//! key exchange, MIC and sealing as CredSSP requires.

use crate::crypto::{Rc4, hmac_md5, md4, md5, random, rc4_once};
use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Error, Result, proto};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const REQUEST_TARGET: u32 = 0x0000_0004;
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const NEGOTIATE_128: u32 = 0x2000_0000;
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub const NEGOTIATE_56: u32 = 0x8000_0000;

const CLIENT_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// Windows 10.0 build 19041, NTLMSSP revision 15.
const VERSION: [u8; 8] = [10, 0, 0x61, 0x4A, 0, 0, 0, 0x0F];

const AV_EOL: u16 = 0;
const AV_FLAGS: u16 = 6;
const AV_TIMESTAMP: u16 = 7;
const AV_CHANNEL_BINDINGS: u16 = 10;
const AV_FLAG_MIC_PRESENT: u32 = 0x2;

pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt_hash = md4(&utf16le(password));
    hmac_md5(&nt_hash, &utf16le(&(user.to_uppercase() + domain)))
}

pub struct V2Responses {
    pub nt_proof: [u8; 16],
    pub nt_response: Vec<u8>,
    pub lm_response: Vec<u8>,
    pub session_base_key: [u8; 16],
}

/// NTLMv2 response computation (MS-NLMP 3.3.2).
pub fn compute_v2(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
    zero_lm: bool,
) -> V2Responses {
    let mut temp = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
    temp.put_bytes(timestamp);
    temp.put_bytes(client_challenge);
    temp.put_zeros(4);
    temp.put_bytes(target_info);
    temp.put_zeros(4);

    let nt_proof = hmac_md5(response_key, &[&server_challenge[..], &temp].concat());
    let nt_response = [&nt_proof[..], &temp].concat();
    let lm_response = if zero_lm {
        vec![0u8; 24]
    } else {
        let lm = hmac_md5(
            response_key,
            &[&server_challenge[..], &client_challenge[..]].concat(),
        );
        [&lm[..], &client_challenge[..]].concat()
    };
    let session_base_key = hmac_md5(response_key, &nt_proof);
    V2Responses {
        nt_proof,
        nt_response,
        lm_response,
        session_base_key,
    }
}

fn filetime_now() -> [u8; 8] {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = (d.as_secs() + 11_644_473_600) * 10_000_000 + d.subsec_nanos() as u64 / 100;
    ticks.to_le_bytes()
}

fn parse_av_pairs(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    loop {
        if r.remaining() < 4 {
            break; // tolerate a missing MsvAvEOL
        }
        let id = r.u16()?;
        let len = r.u16()? as usize;
        let value = r.bytes(len)?;
        if id == AV_EOL {
            break;
        }
        out.push((id, value.to_vec()));
    }
    Ok(out)
}

fn write_av_pairs(pairs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, v) in pairs {
        out.put_u16(*id);
        out.put_u16(v.len() as u16);
        out.put_bytes(v);
    }
    out.put_u16(AV_EOL);
    out.put_u16(0);
    out
}

struct Session {
    key_exch: bool,
    client_sign: [u8; 16],
    server_sign: [u8; 16],
    client_seal: Rc4,
    server_seal: Rc4,
    client_seq: u32,
    server_seq: u32,
}

pub struct Ntlm {
    user: String,
    domain: String,
    password: String,
    workstation: String,
    negotiate_msg: Vec<u8>,
    session: Option<Session>,
}

impl Ntlm {
    pub fn new(user: &str, domain: &str, password: &str, workstation: &str) -> Self {
        Self {
            user: user.into(),
            domain: domain.into(),
            password: password.into(),
            workstation: workstation.into(),
            negotiate_msg: Vec::new(),
            session: None,
        }
    }

    /// NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1).
    pub fn negotiate(&mut self) -> Vec<u8> {
        let mut m = Vec::new();
        m.put_bytes(SIGNATURE);
        m.put_u32(1);
        m.put_u32(CLIENT_FLAGS);
        m.put_zeros(8); // DomainNameFields
        m.put_zeros(8); // WorkstationFields
        m.put_bytes(&VERSION);
        self.negotiate_msg = m.clone();
        m
    }

    /// Consumes the CHALLENGE_MESSAGE and produces the AUTHENTICATE_MESSAGE.
    pub fn authenticate(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        let mut r = Reader::new(challenge);
        if r.bytes(8)? != SIGNATURE || r.u32()? != 2 {
            return proto("not an NTLM CHALLENGE_MESSAGE");
        }
        r.skip(8)?; // TargetNameFields
        let flags = r.u32()?;
        let server_challenge: [u8; 8] = r.array()?;
        r.skip(8)?;
        let ti_len = r.u16()? as usize;
        r.skip(2)?;
        let ti_off = r.u32()? as usize;
        let target_info = challenge
            .get(ti_off..ti_off + ti_len)
            .ok_or_else(|| Error::Protocol("NTLM target info out of range".into()))?;

        if flags & NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 {
            return Err(Error::Unsupported(
                "NTLM without extended session security".into(),
            ));
        }

        let mut pairs = parse_av_pairs(target_info)?;
        let timestamp: Option<[u8; 8]> = pairs
            .iter()
            .find(|(id, v)| *id == AV_TIMESTAMP && v.len() == 8)
            .map(|(_, v)| v[..8].try_into().unwrap());
        match pairs.iter_mut().find(|(id, _)| *id == AV_FLAGS) {
            Some((_, v)) if v.len() == 4 => {
                let f = u32::from_le_bytes(v[..4].try_into().unwrap()) | AV_FLAG_MIC_PRESENT;
                *v = f.to_le_bytes().to_vec();
            }
            _ => pairs.push((AV_FLAGS, AV_FLAG_MIC_PRESENT.to_le_bytes().to_vec())),
        }
        if !pairs.iter().any(|(id, _)| *id == AV_CHANNEL_BINDINGS) {
            pairs.push((AV_CHANNEL_BINDINGS, vec![0u8; 16]));
        }
        let target_info = write_av_pairs(&pairs);

        let key = ntowf_v2(&self.password, &self.user, &self.domain);
        let client_challenge: [u8; 8] = random();
        let v2 = compute_v2(
            &key,
            &server_challenge,
            &client_challenge,
            &timestamp.unwrap_or_else(filetime_now),
            &target_info,
            timestamp.is_some(),
        );

        let key_exchange_key = v2.session_base_key;
        let key_exch = flags & NEGOTIATE_KEY_EXCH != 0;
        let (exported, encrypted_key) = if key_exch {
            let exported: [u8; 16] = random();
            (exported, rc4_once(&key_exchange_key, &exported))
        } else {
            (key_exchange_key, Vec::new())
        };

        let domain = utf16le(&self.domain);
        let user = utf16le(&self.user);
        let ws = utf16le(&self.workstation);
        let fields: [&[u8]; 6] = [
            &v2.lm_response,
            &v2.nt_response,
            &domain,
            &user,
            &ws,
            &encrypted_key,
        ];
        let mut msg = Vec::new();
        msg.put_bytes(SIGNATURE);
        msg.put_u32(3);
        let mut offset = 88u32;
        for f in fields {
            msg.put_u16(f.len() as u16);
            msg.put_u16(f.len() as u16);
            msg.put_u32(offset);
            offset += f.len() as u32;
        }
        msg.put_u32(flags);
        msg.put_bytes(&VERSION);
        msg.put_zeros(16); // MIC, filled below
        debug_assert_eq!(msg.len(), 88);
        for f in fields {
            msg.put_bytes(f);
        }
        let mic = hmac_md5(
            &exported,
            &[&self.negotiate_msg[..], challenge, &msg].concat(),
        );
        msg[72..88].copy_from_slice(&mic);

        let derive = |magic: &[u8]| md5(&[&exported[..], magic].concat());
        self.session = Some(Session {
            key_exch,
            client_sign: derive(b"session key to client-to-server signing key magic constant\0"),
            server_sign: derive(b"session key to server-to-client signing key magic constant\0"),
            client_seal: Rc4::new(&derive(
                b"session key to client-to-server sealing key magic constant\0",
            )),
            server_seal: Rc4::new(&derive(
                b"session key to server-to-client sealing key magic constant\0",
            )),
            client_seq: 0,
            server_seq: 0,
        });
        Ok(msg)
    }

    /// Seals a message the way SSPI EncryptMessage does for CredSSP:
    /// 16-byte signature followed by the RC4-encrypted payload.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| Error::Auth("NTLM not established".into()))?;
        let seq = s.client_seq.to_le_bytes();
        let mut sealed = data.to_vec();
        s.client_seal.process(&mut sealed);
        let mut checksum: [u8; 8] = hmac_md5(&s.client_sign, &[&seq[..], data].concat())[..8]
            .try_into()
            .unwrap();
        if s.key_exch {
            s.client_seal.process(&mut checksum);
        }
        s.client_seq += 1;
        let mut out = Vec::with_capacity(16 + data.len());
        out.put_u32(1);
        out.put_bytes(&checksum);
        out.put_bytes(&seq);
        out.put_bytes(&sealed);
        Ok(out)
    }

    /// GSS_WrapEx (sealed) or GSS_GetMICEx (signed only) for one DCE/RPC
    /// PDU (MS-NLMP 3.4.3, 3.4.4; MS-RPCE 3.3.1.5.2.2): the signature covers
    /// the plaintext of `sign` (the body, or header, body and sec_trailer
    /// with header signing), then `seal`, if given, is encrypted in place.
    /// Returns the 16-byte NTLMSSP_MESSAGE_SIGNATURE.
    pub fn wrap_pdu(
        &mut self,
        pdu: &mut [u8],
        seal: Option<std::ops::Range<usize>>,
        sign: std::ops::Range<usize>,
    ) -> Result<[u8; 16]> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| Error::Auth("NTLM not established".into()))?;
        let signed = pdu
            .get(sign)
            .ok_or_else(|| Error::Protocol("NTLM signed range out of bounds".into()))?;
        let seq = s.client_seq.to_le_bytes();
        let mut checksum: [u8; 8] = hmac_md5(&s.client_sign, &[&seq[..], signed].concat())[..8]
            .try_into()
            .expect("8 of 16 bytes");
        if let Some(r) = seal {
            let body = pdu
                .get_mut(r)
                .ok_or_else(|| Error::Protocol("NTLM sealed range out of bounds".into()))?;
            s.client_seal.process(body);
        }
        if s.key_exch {
            s.client_seal.process(&mut checksum);
        }
        s.client_seq = s.client_seq.wrapping_add(1);
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&1u32.to_le_bytes());
        out[4..12].copy_from_slice(&checksum);
        out[12..].copy_from_slice(&seq);
        Ok(out)
    }

    /// The receive side of [`Self::wrap_pdu`] (GSS_UnwrapEx / GSS_VerifyMICEx):
    /// decrypts `seal` in place, then checks `signature` over `sign`.
    pub fn unwrap_pdu(
        &mut self,
        pdu: &mut [u8],
        seal: Option<std::ops::Range<usize>>,
        sign: std::ops::Range<usize>,
        signature: &[u8],
    ) -> Result<()> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| Error::Auth("NTLM not established".into()))?;
        if signature.len() < 16 || pdu.get(sign.clone()).is_none() {
            return proto("NTLM signature or signed range out of bounds");
        }
        if let Some(r) = seal {
            let body = pdu
                .get_mut(r)
                .ok_or_else(|| Error::Protocol("NTLM sealed range out of bounds".into()))?;
            s.server_seal.process(body);
        }
        let mut checksum: [u8; 8] = signature[4..12].try_into().expect("checked length");
        if s.key_exch {
            s.server_seal.process(&mut checksum);
        }
        let seq = s.server_seq.to_le_bytes();
        let expected = hmac_md5(&s.server_sign, &[&seq[..], &pdu[sign]].concat());
        if checksum != expected[..8] || signature[12..16] != seq {
            return Err(Error::Auth("RPC message signature mismatch".into()));
        }
        s.server_seq = s.server_seq.wrapping_add(1);
        Ok(())
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| Error::Auth("NTLM not established".into()))?;
        if data.len() < 16 {
            return proto("sealed NTLM message too short");
        }
        let mut plain = data[16..].to_vec();
        s.server_seal.process(&mut plain);
        let mut checksum: [u8; 8] = data[4..12].try_into().unwrap();
        if s.key_exch {
            s.server_seal.process(&mut checksum);
        }
        let seq = s.server_seq.to_le_bytes();
        let expected = hmac_md5(&s.server_sign, &[&seq[..], &plain].concat());
        if checksum != expected[..8] || data[12..16] != seq {
            return Err(Error::Auth("server message signature mismatch".into()));
        }
        s.server_seq += 1;
        Ok(plain)
    }
}

/// The server's side of a session, for loopback tests that play a peer.
#[cfg(test)]
impl Ntlm {
    /// A session from an exported session key, seen from the client, or
    /// (with `server`) from the server, whose send keys are the client's
    /// receive keys (MS-NLMP 3.4.5).
    pub(crate) fn with_session_key(exported: [u8; 16], server: bool) -> Ntlm {
        let derive = |magic: &[u8]| md5(&[&exported[..], magic].concat());
        let c_sign = derive(b"session key to client-to-server signing key magic constant\0");
        let s_sign = derive(b"session key to server-to-client signing key magic constant\0");
        let c_seal = derive(b"session key to client-to-server sealing key magic constant\0");
        let s_seal = derive(b"session key to server-to-client sealing key magic constant\0");
        let (cs, ss, ce, se) = if server {
            (s_sign, c_sign, s_seal, c_seal)
        } else {
            (c_sign, s_sign, c_seal, s_seal)
        };
        let mut n = Ntlm::new("", "", "", "");
        n.session = Some(Session {
            key_exch: true,
            client_sign: cs,
            server_sign: ss,
            client_seal: Rc4::new(&ce),
            server_seal: Rc4::new(&se),
            client_seq: 0,
            server_seq: 0,
        });
        n
    }

    /// What a server learns from an AUTHENTICATE_MESSAGE (MS-NLMP 3.2.5.1.2)
    /// when it knows the password: the exported session key.
    pub(crate) fn exported_key(
        authenticate: &[u8],
        password: &str,
        user: &str,
        domain: &str,
    ) -> [u8; 16] {
        let field = |at: usize| {
            let len = u16::from_le_bytes([authenticate[at], authenticate[at + 1]]) as usize;
            let off = u32::from_le_bytes(authenticate[at + 4..at + 8].try_into().unwrap()) as usize;
            &authenticate[off..off + len]
        };
        let nt_proof = &field(20)[..16];
        let base = hmac_md5(&ntowf_v2(password, user, domain), nt_proof);
        rc4_once(&base, field(52)).try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn nt_hash_of_password() {
        // MS-NLMP 4.2.2.1.2 NTOWFv1("Password")
        assert_eq!(
            hex(&md4(&utf16le("Password"))),
            "a4f49c406510bdcab6824ee7c30fd852"
        );
    }

    /// MS-NLMP 4.2.4 NTLMv2 authentication test vectors.
    #[test]
    fn ntlmv2_spec_vectors() {
        let key = ntowf_v2("Password", "User", "Domain");
        assert_eq!(hex(&key), "0c868a403bfd7a93a3001ef22ef02e3f");

        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge = [0xaa; 8];
        let target_info = write_av_pairs(&[(2, utf16le("Domain")), (1, utf16le("Server"))]);
        let v2 = compute_v2(
            &key,
            &server_challenge,
            &client_challenge,
            &[0; 8],
            &target_info,
            false,
        );
        assert_eq!(
            hex(&v2.lm_response),
            "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
        );
        assert_eq!(hex(&v2.nt_proof), "68cd0ab851e51c96aabc927bebef6a1c");
        assert_eq!(
            hex(&v2.session_base_key),
            "8de40ccadbc14a82f15cb0ad0de95ca3"
        );
        let encrypted = rc4_once(&v2.session_base_key, &[0x55; 16]);
        assert_eq!(hex(&encrypted), "c5dad2544fc9799094ce1ce90bc9d03e");
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn session_with(sign: &[u8], seal: &[u8]) -> Session {
        let sign: [u8; 16] = sign.try_into().unwrap();
        let seal: [u8; 16] = seal.try_into().unwrap();
        Session {
            key_exch: true,
            client_sign: sign,
            server_sign: sign,
            client_seal: Rc4::new(&seal),
            server_seal: Rc4::new(&seal),
            client_seq: 0,
            server_seq: 0,
        }
    }

    /// MS-NLMP 4.2.4.4 GSS_WrapEx example (NTLMv2, key exchange): the sealed
    /// data and the signature of "Plaintext".
    #[test]
    fn wrap_pdu_matches_the_spec_example() {
        let sealkey = unhex("59 f6 00 97 3c c4 96 0a 25 48 0a 7c 19 6e 4c 58");
        let signkey = unhex("47 88 dc 86 1b 47 82 f3 5d 43 fd 98 fe 1a 2d 39");
        let mut a = Ntlm::new("u", "", "p", "w");
        a.session = Some(session_with(&signkey, &sealkey));
        let mut msg = utf16le("Plaintext");
        let n = msg.len();
        let sig = a.wrap_pdu(&mut msg, Some(0..n), 0..n).unwrap();
        assert_eq!(
            hex(&msg),
            "54e50165bf1936dc996020c1811b0f06fb5f",
            "sealed data"
        );
        assert_eq!(hex(&sig), "010000007fb38ec5c55d497600000000");
    }

    /// The DCE/RPC case: header and trailer are signed but stay clear, only
    /// the body is sealed; the peer with the same keys unwraps it, and a
    /// changed header byte fails the signature.
    #[test]
    fn wrap_pdu_signs_more_than_it_seals() {
        let key = [9u8; 16];
        let pdu0: Vec<u8> = (0..64u8).collect();
        let mut a = Ntlm::new("u", "", "p", "w");
        a.session = Some(session_with(&key, &key));
        let mut pdu = pdu0.clone();
        let sig = a.wrap_pdu(&mut pdu, Some(24..48), 0..56).unwrap();
        assert_eq!(&pdu[..24], &pdu0[..24], "header stays clear");
        assert_ne!(&pdu[24..48], &pdu0[24..48], "body sealed");
        assert_eq!(&pdu[48..], &pdu0[48..]);

        let mut b = Ntlm::new("u", "", "p", "w");
        b.session = Some(session_with(&key, &key));
        let mut got = pdu.clone();
        b.unwrap_pdu(&mut got, Some(24..48), 0..56, &sig).unwrap();
        assert_eq!(got, pdu0);

        let mut c = Ntlm::new("u", "", "p", "w");
        c.session = Some(session_with(&key, &key));
        let mut bad = pdu.clone();
        bad[3] ^= 1;
        assert!(matches!(
            c.unwrap_pdu(&mut bad, Some(24..48), 0..56, &sig),
            Err(Error::Auth(_))
        ));
        assert!(c.unwrap_pdu(&mut bad, Some(24..99), 0..56, &sig).is_err());
    }

    #[test]
    fn seal_round_trip_with_mirrored_keys() {
        // A sealed client message decrypts with the same key schedule on the other side.
        let mut a = Ntlm::new("u", "", "p", "w");
        let key = [7u8; 16];
        a.session = Some(Session {
            key_exch: true,
            client_sign: key,
            server_sign: key,
            client_seal: Rc4::new(&key),
            server_seal: Rc4::new(&key),
            client_seq: 0,
            server_seq: 0,
        });
        let sealed = a.encrypt(b"hello credssp").unwrap();
        assert_eq!(sealed.len(), 16 + 13);
        let mut b = Ntlm::new("u", "", "p", "w");
        b.session = Some(Session {
            key_exch: true,
            client_sign: key,
            server_sign: key,
            client_seal: Rc4::new(&key),
            server_seal: Rc4::new(&key),
            client_seq: 0,
            server_seq: 0,
        });
        assert_eq!(b.decrypt(&sealed).unwrap(), b"hello credssp");
    }
}
