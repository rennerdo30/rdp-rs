//! Connection-oriented DCE/RPC PDUs ([C706] 12.6, MS-RPCE 2.2.2) for the
//! TsProxy calls of the RD Gateway RPC transport: bind, bind_ack, bind_nak,
//! rpc_auth_3, request, response and fault, with an NTLM sec_trailer at
//! packet integrity or packet privacy (MS-RPCE 2.2.2.11, 3.3.1.5.2.2).

use std::ops::Range;

use crate::cursor::{Put, Reader};
use crate::error::{Error, Result, proto};
use crate::ntlm::Ntlm;

pub const PTYPE_REQUEST: u8 = 0;
pub const PTYPE_RESPONSE: u8 = 2;
pub const PTYPE_FAULT: u8 = 3;
pub const PTYPE_BIND: u8 = 11;
pub const PTYPE_BIND_ACK: u8 = 12;
pub const PTYPE_BIND_NAK: u8 = 13;
pub const PTYPE_AUTH3: u8 = 16;
pub const PTYPE_RTS: u8 = 20;

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
/// In bind, bind_ack and rpc_auth_3 (MS-RPCE 2.2.2.3).
pub const PFC_SUPPORT_HEADER_SIGN: u8 = 0x04;

/// RPC_C_AUTHN_WINNT: NTLM (MS-RPCE 2.2.1.1.7).
pub const AUTHN_WINNT: u8 = 10;
/// RPC_C_AUTHN_LEVEL_PKT_INTEGRITY and _PKT_PRIVACY (MS-RPCE 2.2.1.1.8).
pub const AUTHN_LEVEL_PKT_INTEGRITY: u8 = 5;
pub const AUTHN_LEVEL_PKT_PRIVACY: u8 = 6;

/// The common header ([C706] 12.6.1).
pub const HEADER_LEN: usize = 16;
/// Request and response headers: common header, alloc_hint, p_cont_id,
/// opnum or cancel_count ([C706] 12.6.4.9, 12.6.4.10).
pub const CALL_HEADER_LEN: usize = 24;
/// The sec_trailer (MS-RPCE 2.2.2.11).
pub const TRAILER_LEN: usize = 8;
/// An NTLMSSP_MESSAGE_SIGNATURE (MS-NLMP 2.2.2.9.1).
pub const SIGNATURE_LEN: usize = 16;
/// Our max_xmit_frag and max_recv_frag in the bind.
pub const MAX_FRAG: u16 = 0x0FF8;

/// The interface and transfer syntax of a presentation context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxId {
    /// The UUID in its wire form (first three fields little-endian).
    pub uuid: [u8; 16],
    /// Major version in the low 16 bits, minor in the high 16 bits.
    pub version: u32,
}

/// UUID text to its NDR wire form (MS-DTYP 2.3.4.2).
pub const fn uuid(s: &str) -> [u8; 16] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit in UUID"),
        }
    }
    let b = s.as_bytes();
    let mut raw = [0u8; 16];
    let (mut i, mut n) = (0, 0);
    while i < b.len() {
        if b[i] == b'-' {
            i += 1;
            continue;
        }
        raw[n] = nib(b[i]) << 4 | nib(b[i + 1]);
        n += 1;
        i += 2;
    }
    assert!(n == 16, "UUID needs 16 bytes");
    // Data1 (4), Data2 (2) and Data3 (2) are little-endian on the wire.
    [
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ]
}

/// TsProxyRpcInterface 44e265dd-7daf-42cd-8560-3cdb6e7a2729, version 1.3
/// (MS-TSGU 2.1.1, 6).
pub const TSPROXY: SyntaxId = SyntaxId {
    uuid: uuid("44e265dd-7daf-42cd-8560-3cdb6e7a2729"),
    version: 1 | 3 << 16,
};

/// NDR 2.0 transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 ([C706] 14).
pub const NDR20: SyntaxId = SyntaxId {
    uuid: uuid("8a885d04-1ceb-11c9-9fe8-08002b104860"),
    version: 2,
};

/// The common header of every PDU ([C706] 12.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub ptype: u8,
    pub flags: u8,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl Header {
    /// rpc_vers 5.0, little-endian/ASCII/IEEE data representation.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.put_bytes(&[5, 0, self.ptype, self.flags, 0x10, 0, 0, 0]);
        out.put_u16(self.frag_length);
        out.put_u16(self.auth_length);
        out.put_u32(self.call_id);
    }

    pub fn parse(pdu: &[u8]) -> Result<Header> {
        let mut r = Reader::new(pdu);
        let (vers, minor) = (r.u8()?, r.u8()?);
        if vers != 5 || minor > 1 {
            return proto(format!("RPC version {vers}.{minor}"));
        }
        let ptype = r.u8()?;
        let flags = r.u8()?;
        let drep = r.array::<4>()?;
        if drep[0] & 0xF0 != 0x10 {
            return proto("big-endian RPC data representation");
        }
        let h = Header {
            ptype,
            flags,
            frag_length: r.u16()?,
            auth_length: r.u16()?,
            call_id: r.u32()?,
        };
        if (h.frag_length as usize) < HEADER_LEN || h.frag_length as usize != pdu.len() {
            return proto(format!("RPC frag_length {}", h.frag_length));
        }
        Ok(h)
    }
}

/// The length of the PDU at the start of `buf` once its header is there
/// (RTS PDUs too: they share the common header, MS-RPCH 2.2.3.6.1).
pub fn pdu_len(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 10 {
        return Ok(None);
    }
    let n = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    if n < HEADER_LEN {
        return proto(format!("RPC frag_length {n}"));
    }
    Ok(Some(n))
}

/// Pads `out` with zeros so its length is a multiple of `n`.
fn align(out: &mut Vec<u8>, n: usize) -> u8 {
    let pad = (n - out.len() % n) % n;
    out.put_zeros(pad);
    pad as u8
}

/// Appends the sec_trailer and token and fixes frag_length and auth_length.
fn finish_auth(mut pdu: Vec<u8>, level: u8, pad: u8, token: &[u8]) -> Vec<u8> {
    pdu.put_bytes(&[AUTHN_WINNT, level, pad, 0]);
    pdu.put_u32(0); // auth_context_id
    pdu.put_bytes(token);
    let n = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&n.to_le_bytes());
    pdu[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
    pdu
}

/// bind with one presentation context and the first NTLM token
/// ([C706] 12.6.4.3, MS-RPCE 3.3.1.5.2.2).
pub fn bind(call_id: u32, iface: SyntaxId, level: u8, token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    Header {
        ptype: PTYPE_BIND,
        flags: PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_SUPPORT_HEADER_SIGN,
        frag_length: 0,
        auth_length: 0,
        call_id,
    }
    .write(&mut b);
    b.put_u16(MAX_FRAG); // max_xmit_frag
    b.put_u16(MAX_FRAG); // max_recv_frag
    b.put_u32(0); // assoc_group_id: a new association
    b.put_bytes(&[1, 0, 0, 0]); // n_context_elem, reserved
    b.put_u16(0); // p_cont_id
    b.put_bytes(&[1, 0]); // n_transfer_syn, reserved
    b.put_bytes(&iface.uuid);
    b.put_u32(iface.version);
    b.put_bytes(&NDR20.uuid);
    b.put_u32(NDR20.version);
    let pad = align(&mut b, 4);
    finish_auth(b, level, pad, token)
}

/// rpc_auth_3 with the last NTLM token (MS-RPCE 2.2.2.10).
pub fn auth3(call_id: u32, level: u8, token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    Header {
        ptype: PTYPE_AUTH3,
        flags: PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_SUPPORT_HEADER_SIGN,
        frag_length: 0,
        auth_length: 0,
        call_id,
    }
    .write(&mut b);
    b.put_u32(0); // pad
    finish_auth(b, level, 0, token)
}

/// The sec_trailer and token of a PDU (MS-RPCE 2.2.2.11): the trailer
/// starts at frag_length - auth_length - 8.
#[derive(Debug)]
pub struct Auth {
    pub auth_type: u8,
    pub level: u8,
    pub pad: u8,
    /// Offset of the sec_trailer in the PDU.
    pub trailer_at: usize,
}

pub fn auth_of(pdu: &[u8], h: &Header) -> Result<Option<Auth>> {
    if h.auth_length == 0 {
        return Ok(None);
    }
    let at = (h.frag_length as usize)
        .checked_sub(h.auth_length as usize + TRAILER_LEN)
        .filter(|&a| a >= HEADER_LEN)
        .ok_or_else(|| Error::Protocol(format!("RPC auth_length {}", h.auth_length)))?;
    let t = &pdu[at..at + TRAILER_LEN];
    Ok(Some(Auth {
        auth_type: t[0],
        level: t[1],
        pad: t[2],
        trailer_at: at,
    }))
}

/// p_result_t of a bind_ack ([C706] 12.6.3.1).
pub const RESULT_ACCEPTANCE: u16 = 0;

#[derive(Debug)]
pub struct BindAck {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    /// (result, reason) of each presentation context.
    pub results: Vec<(u16, u16)>,
    pub header_sign: bool,
    /// The NTLM CHALLENGE_MESSAGE.
    pub token: Vec<u8>,
}

/// bind_ack ([C706] 12.6.4.4).
pub fn parse_bind_ack(pdu: &[u8]) -> Result<BindAck> {
    let h = Header::parse(pdu)?;
    if h.ptype != PTYPE_BIND_ACK {
        return proto(format!("RPC PDU type {} instead of bind_ack", h.ptype));
    }
    let mut r = Reader::new(pdu);
    r.skip(HEADER_LEN)?;
    let max_xmit_frag = r.u16()?;
    let max_recv_frag = r.u16()?;
    let assoc_group_id = r.u32()?;
    let addr_len = r.u16()? as usize;
    r.skip(addr_len)?; // sec_addr: the server's port_spec
    r.skip((4 - r.pos() % 4) % 4)?;
    let n = r.u8()? as usize;
    r.skip(3)?;
    let mut results = Vec::with_capacity(n);
    for _ in 0..n {
        let result = r.u16()?;
        let reason = r.u16()?;
        r.skip(20)?; // transfer_syntax
        results.push((result, reason));
    }
    let auth = auth_of(pdu, &h)?
        .ok_or_else(|| Error::Auth("the RPC bind_ack carries no NTLM challenge".into()))?;
    if auth.auth_type != AUTHN_WINNT {
        return Err(Error::Unsupported(format!(
            "RPC authentication type {}",
            auth.auth_type
        )));
    }
    Ok(BindAck {
        max_xmit_frag,
        max_recv_frag,
        assoc_group_id,
        results,
        header_sign: h.flags & PFC_SUPPORT_HEADER_SIGN != 0,
        token: pdu[auth.trailer_at + TRAILER_LEN..].to_vec(),
    })
}

/// provider_reject_reason of a bind_nak ([C706] 12.6.4.5).
pub fn parse_bind_nak(pdu: &[u8]) -> Result<u16> {
    let mut r = Reader::new(pdu);
    r.skip(HEADER_LEN)?;
    r.u16()
}

/// The status of a fault PDU ([C706] 12.6.4.7): after alloc_hint,
/// p_cont_id, cancel_count and a reserved byte.
pub fn parse_fault(pdu: &[u8]) -> Result<u32> {
    let mut r = Reader::new(pdu);
    r.skip(CALL_HEADER_LEN)?;
    r.u32()
}

/// A readable name for common fault and reject codes (MS-RPCE 3.3.3.5.1,
/// MS-ERREF 2.2).
pub fn status_name(code: u32) -> &'static str {
    match code {
        0x0000_0005 => "access denied",
        0x1C01_0002 => "operation number out of range",
        0x1C01_0003 => "unknown interface",
        0x1C00_001A => "protocol error",
        0x1C00_0011 => "bad stub data",
        0x0000_06F7 => "bad stub data",
        0x0000_06D1 => "procedure number out of range",
        0x0000_06C6 => "invalid argument",
        _ => "error",
    }
}

/// A response PDU after its sec_trailer was checked and its body unsealed.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub call_id: u32,
    pub flags: u8,
    /// Stub data, without the authentication padding.
    pub stub: Vec<u8>,
}

/// The negotiated security of the RPC connection: NTLM at packet integrity
/// or packet privacy, with or without header signing.
pub struct Security {
    pub ntlm: Ntlm,
    pub level: u8,
    pub header_sign: bool,
}

impl Security {
    /// The ranges that are sealed and signed for a call PDU whose
    /// sec_trailer is at `trailer_at` (MS-RPCE 3.3.1.5.2.2).
    fn ranges(&self, trailer_at: usize) -> (Option<Range<usize>>, Range<usize>) {
        let body = CALL_HEADER_LEN..trailer_at;
        let seal = (self.level == AUTHN_LEVEL_PKT_PRIVACY).then(|| body.clone());
        let sign = if self.header_sign {
            0..trailer_at + TRAILER_LEN
        } else {
            body
        };
        (seal, sign)
    }

    /// One request fragment ([C706] 12.6.4.9) with the stub sealed or
    /// signed. `flags` carries PFC_FIRST_FRAG / PFC_LAST_FRAG.
    pub fn request(
        &mut self,
        call_id: u32,
        opnum: u16,
        alloc_hint: u32,
        flags: u8,
        stub: &[u8],
    ) -> Result<Vec<u8>> {
        self.call_pdu(PTYPE_REQUEST, call_id, opnum, alloc_hint, flags, stub)
    }

    /// A request, or (for the loopback tests' gateway) a response: the
    /// last header word is the opnum, or cancel_count and a reserved byte.
    pub fn call_pdu(
        &mut self,
        ptype: u8,
        call_id: u32,
        opnum: u16,
        alloc_hint: u32,
        flags: u8,
        stub: &[u8],
    ) -> Result<Vec<u8>> {
        let mut b = Vec::with_capacity(CALL_HEADER_LEN + stub.len() + 40);
        Header {
            ptype,
            flags,
            frag_length: 0,
            auth_length: SIGNATURE_LEN as u16,
            call_id,
        }
        .write(&mut b);
        b.put_u32(alloc_hint);
        b.put_u16(0); // p_cont_id
        b.put_u16(opnum);
        b.put_bytes(stub);
        // The sec_trailer is 16-byte aligned from the body (MS-RPCE 2.2.2.11).
        let pad = ((16 - stub.len() % 16) % 16) as u8;
        b.put_zeros(pad as usize);
        let trailer_at = b.len();
        b.put_bytes(&[AUTHN_WINNT, self.level, pad, 0]);
        b.put_u32(0);
        let total = b.len() + SIGNATURE_LEN;
        if total > u16::MAX as usize {
            return proto("RPC request fragment too long");
        }
        b[8..10].copy_from_slice(&(total as u16).to_le_bytes());
        let (seal, sign) = self.ranges(trailer_at);
        let sig = self.ntlm.wrap_pdu(&mut b, seal, sign)?;
        b.put_bytes(&sig);
        Ok(b)
    }

    /// Checks and unseals a response PDU ([C706] 12.6.4.10).
    pub fn response(&mut self, pdu: &mut [u8]) -> Result<Response> {
        self.open_call(PTYPE_RESPONSE, pdu)
    }

    /// Checks and unseals a request or response PDU of type `ptype`.
    pub fn open_call(&mut self, ptype: u8, pdu: &mut [u8]) -> Result<Response> {
        let h = Header::parse(pdu)?;
        if h.ptype != ptype {
            return proto(format!("RPC PDU type {} instead of {ptype}", h.ptype));
        }
        let auth = auth_of(pdu, &h)?
            .ok_or_else(|| Error::Auth("unsigned RPC call on a secured connection".into()))?;
        if auth.trailer_at < CALL_HEADER_LEN
            || auth.auth_type != AUTHN_WINNT
            || auth.level != self.level
            || (h.auth_length as usize) < SIGNATURE_LEN
        {
            return Err(Error::Auth(format!(
                "RPC protection {}/{} does not match the bind",
                auth.auth_type, auth.level
            )));
        }
        let stub_end = auth
            .trailer_at
            .checked_sub(auth.pad as usize)
            .filter(|&e| e >= CALL_HEADER_LEN)
            .ok_or_else(|| Error::Protocol(format!("RPC auth_pad_length {}", auth.pad)))?;
        let (seal, sign) = self.ranges(auth.trailer_at);
        let sig_at = auth.trailer_at + TRAILER_LEN;
        let signature = pdu[sig_at..sig_at + SIGNATURE_LEN].to_vec();
        self.ntlm.unwrap_pdu(pdu, seal, sign, &signature)?;
        Ok(Response {
            call_id: h.call_id,
            flags: h.flags,
            stub: pdu[CALL_HEADER_LEN..stub_end].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_wire_form() {
        // [C706] A.2: the first three fields little-endian.
        assert_eq!(
            TSPROXY.uuid,
            [
                0xdd, 0x65, 0xe2, 0x44, 0xaf, 0x7d, 0xcd, 0x42, 0x85, 0x60, 0x3c, 0xdb, 0x6e, 0x7a,
                0x27, 0x29
            ]
        );
        assert_eq!(TSPROXY.version, 0x0003_0001);
        assert_eq!(&NDR20.uuid[..4], &[0x04, 0x5d, 0x88, 0x8a]);
    }

    #[test]
    fn bind_layout() {
        let b = bind(7, TSPROXY, AUTHN_LEVEL_PKT_PRIVACY, b"NTLMSSP-token");
        let h = Header::parse(&b).unwrap();
        assert_eq!(h.ptype, PTYPE_BIND);
        assert_eq!(h.flags, 0x07);
        assert_eq!(h.call_id, 7);
        assert_eq!(h.auth_length, 13);
        assert_eq!(b.len(), 72 + 8 + 13);
        assert_eq!(&b[16..20], &[0xF8, 0x0F, 0xF8, 0x0F]);
        assert_eq!(b[24], 1, "one context");
        assert_eq!(&b[32..48], &TSPROXY.uuid);
        assert_eq!(&b[52..68], &NDR20.uuid);
        let a = auth_of(&b, &h).unwrap().unwrap();
        assert_eq!((a.auth_type, a.level, a.pad, a.trailer_at), (10, 6, 0, 72));
        assert_eq!(&b[80..], b"NTLMSSP-token");
    }

    fn bind_ack_bytes(flags: u8, results: &[(u16, u16)], token: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        Header {
            ptype: PTYPE_BIND_ACK,
            flags,
            frag_length: 0,
            auth_length: 0,
            call_id: 1,
        }
        .write(&mut b);
        b.put_u16(5840);
        b.put_u16(5840);
        b.put_u32(0x1234);
        b.put_u16(5);
        b.put_bytes(b"3388\0");
        align(&mut b, 4);
        b.put_bytes(&[results.len() as u8, 0, 0, 0]);
        for &(res, reason) in results {
            b.put_u16(res);
            b.put_u16(reason);
            b.put_bytes(&NDR20.uuid);
            b.put_u32(NDR20.version);
        }
        let pad = align(&mut b, 4);
        finish_auth(b, AUTHN_LEVEL_PKT_PRIVACY, pad, token)
    }

    #[test]
    fn parses_bind_ack() {
        let b = bind_ack_bytes(0x07, &[(0, 0)], b"challenge");
        let a = parse_bind_ack(&b).unwrap();
        assert_eq!((a.max_xmit_frag, a.max_recv_frag), (5840, 5840));
        assert_eq!(a.assoc_group_id, 0x1234);
        assert_eq!(a.results, vec![(0, 0)]);
        assert!(a.header_sign);
        assert_eq!(a.token, b"challenge");
        let b = bind_ack_bytes(0x03, &[(2, 1)], b"c");
        let a = parse_bind_ack(&b).unwrap();
        assert!(!a.header_sign);
        assert_eq!(a.results, vec![(2, 1)]);
    }

    #[test]
    fn bad_headers_are_errors() {
        let mut b = bind_ack_bytes(0x03, &[(0, 0)], b"c");
        assert!(parse_bind_ack(&b[..b.len() - 1]).is_err(), "frag_length");
        b[0] = 4;
        assert!(parse_bind_ack(&b).is_err(), "version");
        assert!(pdu_len(&[5, 0, 2, 3, 0x10, 0, 0, 0, 4, 0]).is_err());
        assert_eq!(pdu_len(&[5, 0, 2, 3]).unwrap(), None);
        // auth_length larger than the PDU.
        let mut b = bind_ack_bytes(0x03, &[(0, 0)], b"c");
        b[10] = 0xFF;
        assert!(parse_bind_ack(&b).is_err());
    }

    /// The client's and the gateway's view of one NTLM session.
    fn pair(level: u8, header_sign: bool) -> (Security, Security) {
        let mk = |server| Security {
            ntlm: Ntlm::with_session_key([3; 16], server),
            level,
            header_sign,
        };
        (mk(false), mk(true))
    }

    /// Requests from the client and responses from the gateway open on the
    /// other side: padding, sealing and signing at both levels.
    #[test]
    fn sealed_call_round_trip() {
        for level in [AUTHN_LEVEL_PKT_INTEGRITY, AUTHN_LEVEL_PKT_PRIVACY] {
            for header_sign in [false, true] {
                let (mut client, mut gw) = pair(level, header_sign);
                for (i, stub) in [&b"x"[..], &[7u8; 32][..], &b"seventeen bytes!!"[..]]
                    .into_iter()
                    .enumerate()
                {
                    let call_id = 9 + i as u32;
                    let mut pdu = client.request(call_id, 8, 0, 3, stub).unwrap();
                    assert_eq!(
                        (pdu.len() - CALL_HEADER_LEN - TRAILER_LEN - SIGNATURE_LEN) % 16,
                        0
                    );
                    let sealed = pdu[CALL_HEADER_LEN..CALL_HEADER_LEN + stub.len()] != *stub;
                    assert_eq!(sealed, level == AUTHN_LEVEL_PKT_PRIVACY);
                    assert_eq!(&pdu[22..24], &[8, 0], "opnum");
                    let got = gw.open_call(PTYPE_REQUEST, &mut pdu).unwrap();
                    assert_eq!((got.call_id, got.stub.as_slice()), (call_id, stub));

                    let mut reply = gw.call_pdu(PTYPE_RESPONSE, call_id, 0, 0, 3, stub).unwrap();
                    let r = client.response(&mut reply).unwrap();
                    assert_eq!((r.call_id, r.flags), (call_id, 3));
                    assert_eq!(r.stub, stub);
                }
                // A changed call_id passes only when the header is not signed.
                let mut reply = gw.call_pdu(PTYPE_RESPONSE, 1, 0, 0, 3, b"z").unwrap();
                reply[12] = 2;
                assert_eq!(client.response(&mut reply).is_ok(), !header_sign);
            }
        }
    }

    #[test]
    fn tampered_response_fails() {
        let (mut client, mut gw) = pair(AUTHN_LEVEL_PKT_PRIVACY, true);
        let mut pdu = gw
            .call_pdu(PTYPE_RESPONSE, 1, 0, 0, 3, b"secret data")
            .unwrap();
        pdu[CALL_HEADER_LEN] ^= 0x40;
        assert!(matches!(client.response(&mut pdu), Err(Error::Auth(_))));
        // A pad longer than the body.
        let (mut client, mut gw) = pair(AUTHN_LEVEL_PKT_PRIVACY, true);
        let mut pdu = gw.call_pdu(PTYPE_RESPONSE, 1, 0, 0, 3, b"x").unwrap();
        let at = pdu.len() - SIGNATURE_LEN - TRAILER_LEN;
        pdu[at + 2] = 200;
        assert!(matches!(client.response(&mut pdu), Err(Error::Protocol(_))));
        // A response at a lower protection level than the bind.
        let (mut client, _) = pair(AUTHN_LEVEL_PKT_PRIVACY, true);
        let (_, mut gw) = pair(AUTHN_LEVEL_PKT_INTEGRITY, true);
        let mut pdu = gw.call_pdu(PTYPE_RESPONSE, 1, 0, 0, 3, b"x").unwrap();
        assert!(matches!(client.response(&mut pdu), Err(Error::Auth(_))));
    }
}
