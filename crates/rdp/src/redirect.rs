//! Server redirection for session brokers and load balancers (MS-RDPBCGR
//! 1.3.8, 2.2.13, 3.2.5.13) and the RDSTLS logon a redirected connection may
//! use (2.2.17, 5.4.5.3).
//!
//! [`crate::Client::connect_with`] follows a redirection that arrives during
//! the connection sequence by itself: it connects to the target, presents the
//! routing token and the redirected credentials, and asks for the session id.
//! At most [`MAX_REDIRECTS`] hops are followed.

use std::fmt;

use crate::cursor::{Put, Reader, le16, utf16le_z};
use crate::error::{Error, Result, proto};

/// Hops [`crate::Client::connect_with`] follows before it gives up, so two
/// brokers that point at each other cannot loop forever.
pub const MAX_REDIRECTS: usize = 3;

/// RDP_SERVER_REDIRECTION_PACKET::Flags (2.2.13.1), also the security header
/// flag of the Standard Security variant (2.2.13.2.1).
pub const SEC_REDIRECTION_PKT: u16 = 0x0400;
/// Share Control Header type of the Enhanced Security variant (2.2.13.3.1).
pub const PDUTYPE_SERVER_REDIR_PKT: u16 = 0x000A;

pub const LB_TARGET_NET_ADDRESS: u32 = 0x0000_0001;
pub const LB_LOAD_BALANCE_INFO: u32 = 0x0000_0002;
pub const LB_USERNAME: u32 = 0x0000_0004;
pub const LB_DOMAIN: u32 = 0x0000_0008;
pub const LB_PASSWORD: u32 = 0x0000_0010;
pub const LB_DONTSTOREUSERNAME: u32 = 0x0000_0020;
pub const LB_SMARTCARD_LOGON: u32 = 0x0000_0040;
pub const LB_NOREDIRECT: u32 = 0x0000_0080;
pub const LB_TARGET_FQDN: u32 = 0x0000_0100;
pub const LB_TARGET_NETBIOS_NAME: u32 = 0x0000_0200;
pub const LB_TARGET_NET_ADDRESSES: u32 = 0x0000_0800;
pub const LB_CLIENT_TSV_URL: u32 = 0x0000_1000;
pub const LB_SERVER_TSV_CAPABLE: u32 = 0x0000_2000;
pub const LB_PASSWORD_IS_PK_ENCRYPTED: u32 = 0x0000_4000;
pub const LB_REDIRECTION_GUID: u32 = 0x0000_8000;
pub const LB_TARGET_CERTIFICATE: u32 = 0x0001_0000;

/// The redirected password: a cleartext password or a logon cookie the
/// target decrypts, or (LB_PASSWORD_IS_PK_ENCRYPTED) a blob for RDSTLS. It
/// is passed on unchanged and never printed: `Debug` shows only that it exists.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordBlob(Vec<u8>);

impl PasswordBlob {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PasswordBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordBlob(<redacted>)")
    }
}

/// A parsed Server Redirection Packet (RDP_SERVER_REDIRECTION_PACKET, 2.2.13.1).
/// Strings are decoded from UTF-16 without their terminator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Redirection {
    /// The session to reconnect to; sent as RedirectedSessionID in the
    /// Client Cluster Data (2.2.1.3.5).
    pub session_id: u32,
    /// RedirFlags (`LB_*`).
    pub flags: u32,
    pub target_net_address: Option<String>,
    /// Opaque; becomes the X.224 routing token (3.2.5.3.1).
    pub load_balance_info: Option<Vec<u8>>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub password: Option<PasswordBlob>,
    pub target_fqdn: Option<String>,
    pub target_netbios_name: Option<String>,
    pub tsv_url: Option<Vec<u8>>,
    /// RedirectionGuid as sent (Base64 GUID in UTF-16), for RDSTLS.
    pub redirection_guid: Option<Vec<u8>>,
    /// The target's X.509 certificate (DER) from the Target Certificate
    /// Container (2.2.13.1.2); the target must present exactly this one.
    pub target_certificate: Option<Vec<u8>>,
    pub target_net_addresses: Vec<String>,
}

fn wide(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn field<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let n = r.u32()? as usize;
    r.bytes(n)
}

/// TARGET_CERTIFICATE_CONTAINER (2.2.13.1.2): the element of type
/// ELEMENT_TYPE_CERTIFICATE (32) with encoding ENCODING_TYPE_ASN1_DER (1).
fn target_certificate(container: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut r = Reader::new(container);
    while r.remaining() >= 12 {
        let (ty, encoding, size) = (r.u32()?, r.u32()?, r.u32()? as usize);
        let data = r.bytes(size)?;
        if ty == 32 && encoding == 1 {
            return Ok(Some(data.to_vec()));
        }
    }
    Ok(None)
}

impl Redirection {
    /// Parses RDP_SERVER_REDIRECTION_PACKET (2.2.13.1).
    pub fn parse(data: &[u8]) -> Result<Redirection> {
        let mut r = Reader::new(data);
        if r.u16()? != SEC_REDIRECTION_PKT {
            return proto("server redirection packet without SEC_REDIRECTION_PKT");
        }
        let len = r.u16()? as usize;
        // Length covers the whole packet, including the optional padding.
        let packet = data
            .get(..len.max(12))
            .ok_or_else(|| Error::Protocol("server redirection packet truncated".into()))?;
        let mut r = Reader::new(&packet[4..]);
        let mut out = Redirection {
            session_id: r.u32()?,
            flags: r.u32()?,
            ..Default::default()
        };
        let flags = out.flags;
        let has = move |flag: u32| flags & flag != 0;
        let text = |r: &mut Reader, flag| -> Result<Option<String>> {
            Ok(if has(flag) {
                Some(wide(field(r)?))
            } else {
                None
            })
        };
        out.target_net_address = text(&mut r, LB_TARGET_NET_ADDRESS)?;
        if has(LB_LOAD_BALANCE_INFO) {
            out.load_balance_info = Some(field(&mut r)?.to_vec());
        }
        out.username = text(&mut r, LB_USERNAME)?;
        out.domain = text(&mut r, LB_DOMAIN)?;
        if has(LB_PASSWORD) {
            out.password = Some(PasswordBlob(field(&mut r)?.to_vec()));
        }
        out.target_fqdn = text(&mut r, LB_TARGET_FQDN)?;
        out.target_netbios_name = text(&mut r, LB_TARGET_NETBIOS_NAME)?;
        if has(LB_CLIENT_TSV_URL) {
            out.tsv_url = Some(field(&mut r)?.to_vec());
        }
        if has(LB_REDIRECTION_GUID) {
            out.redirection_guid = Some(field(&mut r)?.to_vec());
        }
        if has(LB_TARGET_CERTIFICATE) {
            let b64 = wide(field(&mut r)?);
            let container = crate::gateway::ws::base64_decode(b64.trim())?;
            out.target_certificate = target_certificate(&container)?;
        }
        if has(LB_TARGET_NET_ADDRESSES) {
            let mut list = Reader::new(field(&mut r)?);
            let count = list.u32()?;
            for _ in 0..count {
                out.target_net_addresses.push(wide(field(&mut list)?));
            }
        }
        Ok(out)
    }

    /// Parses the Enhanced Security Server Redirection PDU (2.2.13.3.1) from
    /// the body after its Share Control Header: pad2Octets, then the packet.
    pub fn parse_enhanced(body: &[u8]) -> Result<Redirection> {
        Self::parse(
            body.get(2..)
                .ok_or_else(|| Error::Protocol("server redirection PDU truncated".into()))?,
        )
    }

    /// LB_NOREDIRECT: informational only (2.2.13.1). The client stays on this
    /// server; only the routing token and session id serve a later reconnect.
    pub fn no_redirect(&self) -> bool {
        self.flags & LB_NOREDIRECT != 0
    }

    pub fn smartcard_logon(&self) -> bool {
        self.flags & LB_SMARTCARD_LOGON != 0
    }

    pub fn server_tsv_capable(&self) -> bool {
        self.flags & LB_SERVER_TSV_CAPABLE != 0
    }

    /// LB_PASSWORD_IS_PK_ENCRYPTED with a password and a redirection GUID:
    /// the target expects an RDSTLS logon (2.2.17.2, 5.4.5.3).
    pub fn wants_rdstls(&self) -> bool {
        self.flags & LB_PASSWORD_IS_PK_ENCRYPTED != 0
            && self.password.is_some()
            && self.redirection_guid.is_some()
    }

    /// Hosts to try, in order: the target address, the address list, the
    /// FQDN, the NetBIOS name. Empty for LB_NOREDIRECT, or when the packet
    /// names no target: the client then goes back to the server it came from
    /// with the routing token (1.3.8).
    pub fn targets(&self) -> Vec<String> {
        if self.no_redirect() {
            return Vec::new();
        }
        let mut out: Vec<String> = Vec::new();
        let all = self
            .target_net_address
            .iter()
            .chain(&self.target_net_addresses)
            .chain(&self.target_fqdn)
            .chain(&self.target_netbios_name);
        for host in all {
            if !host.is_empty() && !out.contains(host) {
                out.push(host.clone());
            }
        }
        out
    }

    /// The X.224 routing token (2.2.1.1, 3.2.5.3.1): LoadBalanceInfo,
    /// terminated by CR LF.
    pub fn routing_token(&self) -> Option<Vec<u8>> {
        let mut t = self.load_balance_info.clone().filter(|t| !t.is_empty())?;
        if !t.ends_with(b"\r\n") {
            t.extend_from_slice(b"\r\n");
        }
        Some(t)
    }

    /// The Client Info password (2.2.1.11.1.1) on the target: the blob as
    /// received, unless it is for RDSTLS. Includes the null terminator.
    pub fn client_info_password(&self) -> Option<&[u8]> {
        if self.no_redirect() || self.flags & LB_PASSWORD_IS_PK_ENCRYPTED != 0 {
            return None;
        }
        self.password.as_ref().map(PasswordBlob::bytes)
    }

    /// One trace line for a hop: never the credentials, the password blob or
    /// the routing token's contents.
    pub fn hop_trace(&self, hop: usize) -> String {
        let targets = self.targets();
        format!(
            "server redirection {hop}/{MAX_REDIRECTS}: session {}, flags {:#x}, target {}, routing token {} bytes{}",
            self.session_id,
            self.flags,
            if targets.is_empty() {
                "the same server".to_string()
            } else {
                targets.join(", ")
            },
            self.load_balance_info.as_ref().map_or(0, Vec::len),
            if self.password.is_some() {
                ", with redirected credentials"
            } else {
                ""
            }
        )
    }
}

/// True for a Standard Security Server Redirection PDU (2.2.13.2.1): its
/// security header carries SEC_REDIRECTION_PKT. That form only exists under
/// Standard RDP Security, which this client never negotiates.
pub fn is_standard_security(data: &[u8]) -> bool {
    le16(data, 0).is_some_and(|f| f & SEC_REDIRECTION_PKT != 0)
}

/// True for an Enhanced Security Server Redirection PDU (2.2.13.3.1): a Share
/// Control Header of type PDUTYPE_SERVER_REDIR_PKT. Its PDUVersion is zero,
/// so it does not look like other share control PDUs.
pub fn is_enhanced(data: &[u8]) -> bool {
    le16(data, 2).is_some_and(|t| t & 0x0F == PDUTYPE_SERVER_REDIR_PKT)
        && le16(data, 0).is_some_and(|n| n as usize >= 8 && n as usize <= data.len())
}

const RDSTLS_VERSION_1: u16 = 0x0001;
const RDSTLS_TYPE_CAPABILITIES: u16 = 0x0001;
const RDSTLS_TYPE_AUTHREQ: u16 = 0x0002;
const RDSTLS_TYPE_AUTHRSP: u16 = 0x0004;
const RDSTLS_DATA_CAPABILITIES: u16 = 0x0001;
const RDSTLS_DATA_PASSWORD_CREDS: u16 = 0x0001;
const RDSTLS_DATA_RESULT_CODE: u16 = 0x0001;

/// Size of the RDSTLS Capabilities PDU (2.2.17.1).
pub const RDSTLS_CAPABILITIES_LEN: usize = 8;
/// Size of the RDSTLS Authentication Response PDU (2.2.17.4).
pub const RDSTLS_RESPONSE_LEN: usize = 10;

/// Checks the RDSTLS Capabilities PDU (2.2.17.1) for version 1.
pub fn parse_rdstls_capabilities(b: &[u8]) -> Result<()> {
    let mut r = Reader::new(b);
    let head = (r.u16()?, r.u16()?, r.u16()?);
    if head
        != (
            RDSTLS_VERSION_1,
            RDSTLS_TYPE_CAPABILITIES,
            RDSTLS_DATA_CAPABILITIES,
        )
    {
        return proto(format!("unexpected RDSTLS capabilities header {head:?}"));
    }
    if r.u16()? & RDSTLS_VERSION_1 == 0 {
        return Err(Error::Unsupported(
            "server does not offer RDSTLS version 1".into(),
        ));
    }
    Ok(())
}

/// RDSTLS Authentication Request PDU with Password Credentials (2.2.17.2),
/// filled from the redirection packet. Contains the password blob: never
/// trace it.
pub fn rdstls_auth_request(r: &Redirection) -> Result<Vec<u8>> {
    let (Some(guid), Some(password)) = (&r.redirection_guid, &r.password) else {
        return proto("RDSTLS needs a redirection GUID and a password");
    };
    let mut out = Vec::new();
    out.put_u16(RDSTLS_VERSION_1);
    out.put_u16(RDSTLS_TYPE_AUTHREQ);
    out.put_u16(RDSTLS_DATA_PASSWORD_CREDS);
    let user = utf16le_z(r.username.as_deref().unwrap_or_default());
    let domain = utf16le_z(r.domain.as_deref().unwrap_or_default());
    for f in [&guid[..], &user, &domain, password.bytes()] {
        let n = u16::try_from(f.len())
            .map_err(|_| Error::Protocol("RDSTLS field longer than 65535 bytes".into()))?;
        out.put_u16(n);
        out.put_bytes(f);
    }
    Ok(out)
}

/// Parses the RDSTLS Authentication Response PDU (2.2.17.4); returns the
/// result code (0 = success).
pub fn parse_rdstls_response(b: &[u8]) -> Result<u32> {
    let mut r = Reader::new(b);
    let head = (r.u16()?, r.u16()?, r.u16()?);
    if head
        != (
            RDSTLS_VERSION_1,
            RDSTLS_TYPE_AUTHRSP,
            RDSTLS_DATA_RESULT_CODE,
        )
    {
        return proto(format!("unexpected RDSTLS response header {head:?}"));
    }
    r.u32()
}

#[cfg(test)]
#[path = "redirect_tests.rs"]
mod tests;
