//! Joining a shared desktop from an invitation: Windows Desktop Sharing,
//! Remote Assistance and session shadowing (MS-TSTS RpcShadow2) all hand the
//! viewer a Remote Assistance Connection String 2 (MS-RAI 2.2.2):
//!
//! ```text
//! <E><A KH="..." KH2="sha256:..." ID="auth string"/>
//!    <C><T ID="1" SID="1440550163"><L P="49749" N="172.31.250.64"/></T></C></E>
//! ```
//!
//! The viewer connects to a listed address and port (MS-RA 3.1.5), then runs
//! the normal RDP connection with the Remote Assistance Client Info fields
//! ([`AssistanceLogon`], MS-RA 2.2.7.2). The picture comes as usual; who may
//! control the desktop travels on the `encomsp` channel ([`crate::encomsp`]).

use crate::error::{Error, Result};

/// Invitations are short (RpcShadow2 caps them at 8192 characters).
const MAX_INVITATION: usize = 64 * 1024;

/// One listener of the sharer (`<L>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// `N`: host name or IP address (IPv6 possibly with a `%zone`).
    pub host: String,
    pub port: u16,
}

/// One transport (`<T>`): its listeners and the session id `SID`, which is
/// also the Preconnection PDU Id (MS-RDPEPS 6 <1>).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    pub id: u32,
    pub session_id: u32,
    pub listeners: Vec<Listener>,
}

/// A parsed Remote Assistance Connection String 2 (MS-RAI 2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// `<A ID>`: the authorization string, sent as the Client Info
    /// WorkingDir (MS-RA 2.2.7.2).
    pub auth_id: String,
    /// `<A KH>`: base64 SHA-1 of the sharer's RDP public key blob.
    pub key_hash: Option<String>,
    /// `<A KH2>`: `algorithm:base64` of the same key.
    pub key_hash2: Option<String>,
    pub transports: Vec<Transport>,
}

/// The Client Info replacements of a Remote Assistance connection (MS-RA
/// 2.2.7.2) and the optional Preconnection PDU (MS-RDPEPS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistanceLogon {
    /// WorkingDir: the invitation's `<A ID>`.
    pub auth_id: String,
    /// AlternateShell: the invitation password, or None for "*".
    pub password: Option<String>,
    /// Send RDP_PRECONNECTION_PDU_V1 with this Id (the transport's `SID`)
    /// before the X.224 request. Windows Remote Assistance experts do; a
    /// listener that does not expect it fails the connection, so it is
    /// opt-in (FreeRDP connects to shadow invitations without it).
    pub preconnection_id: Option<u32>,
    /// The invitation's `KH` and `KH2` ([`Invitation::key_hash`]): a TLS
    /// certificate whose RSA key hashes to one of them is the sharer's own
    /// and needs no trust prompt ([`AssistanceLogon::certificate_matches`]).
    pub key_hash: Option<String>,
    pub key_hash2: Option<String>,
}

impl AssistanceLogon {
    /// The Client Info and key pins of `inv`.
    pub fn from_invitation(inv: &Invitation, preconnection_id: Option<u32>) -> Self {
        Self {
            auth_id: inv.auth_id.clone(),
            password: None,
            preconnection_id,
            key_hash: inv.key_hash.clone(),
            key_hash2: inv.key_hash2.clone(),
        }
    }

    /// Whether the TLS certificate `cert` (DER) carries the key the
    /// invitation names. KH is the base64 SHA-1 of the server's RSA public
    /// key blob (MS-RAI 2.2.2, MS-RDPBCGR 2.2.1.4.3.1.1.1); KH2 is
    /// `sha256:`, `sha384:` or `sha512:` and the base64 hash. The spec
    /// defines them on the Standard RDP Security certificate; here the same
    /// blob is built from the TLS certificate's RSA key. No match (or no
    /// hash) leaves the decision to the normal certificate check.
    pub fn certificate_matches(&self, cert: &[u8]) -> bool {
        let Ok(blob) = crate::der::subject_public_key(cert).and_then(|k| rsa_key_blob(&k)) else {
            return false;
        };
        let b64 = crate::gateway::ws::base64_encode;
        let kh = self
            .key_hash
            .as_deref()
            .is_some_and(|kh| kh == b64(&crate::crypto::sha1(&blob)));
        let kh2 = self
            .key_hash2
            .as_deref()
            .and_then(|v| v.split_once(':'))
            .is_some_and(|(alg, hash)| {
                alg.eq_ignore_ascii_case("sha256") && hash == b64(&crate::crypto::sha256(&blob))
            });
        kh || kh2
    }
}

/// RSA_PUBLIC_KEY (MS-RDPBCGR 2.2.1.4.3.1.1.1) of an X.509 RSAPublicKey:
/// magic "RSA1", keylen (modulus bytes plus 8 zero bytes of padding),
/// bitlen, datalen (bitlen / 8 - 1), pubExp, then the modulus little-endian.
pub fn rsa_key_blob(rsa_public_key: &[u8]) -> Result<Vec<u8>> {
    use crate::cursor::Put;
    use crate::der::DerReader;
    let seq = DerReader::new(rsa_public_key).expect(0x30)?;
    let mut r = DerReader::new(seq);
    let n = r.expect(0x02)?;
    let e = r.expect(0x02)?;
    let n: Vec<u8> = n.iter().copied().skip_while(|&b| b == 0).collect();
    let e: Vec<u8> = e.iter().copied().skip_while(|&b| b == 0).collect();
    if n.is_empty() || e.is_empty() || e.len() > 4 {
        return proto("invitation: certificate key is not a usable RSA key");
    }
    let exponent = e.iter().fold(0u32, |a, &b| a << 8 | u32::from(b));
    let bits = n.len() as u32 * 8;
    let mut out = Vec::with_capacity(20 + n.len() + 8);
    out.put_u32(0x3141_5352); // "RSA1"
    out.put_u32(n.len() as u32 + 8);
    out.put_u32(bits);
    out.put_u32(bits / 8 - 1);
    out.put_u32(exponent);
    out.extend(n.iter().rev());
    out.put_zeros(8);
    Ok(out)
}

impl Invitation {
    /// Parses the `<E>` element of an invitation (a bare connection string,
    /// or a file that contains one). Unknown elements and attributes are
    /// skipped; `<L>` with a websocket `U` instead of a port is not usable
    /// here and left out.
    pub fn parse(text: &str) -> Result<Invitation> {
        if text.len() > MAX_INVITATION {
            return proto("invitation is too long");
        }
        if text.contains("<UPLOADINFO") && !text.contains("<E") {
            return Err(Error::Unsupported(
                "Remote Assistance invitation files (.msrcIncident with an encrypted ticket) \
                 need the Remote Assistance channel; use a Desktop Sharing or shadow \
                 connection string"
                    .into(),
            ));
        }
        let mut auth: Option<(String, Option<String>, Option<String>)> = None;
        let mut transports: Vec<Transport> = Vec::new();
        let mut in_e = false;
        for tag in Tags::new(text) {
            let tag = tag?;
            match (tag.name, tag.closing) {
                ("E", false) => in_e = true,
                ("E", true) => break,
                _ if !in_e => {}
                ("A", false) => {
                    let id = tag.attr("ID")?.ok_or_else(|| missing("A", "ID"))?;
                    auth = Some((id, tag.attr("KH")?, tag.attr("KH2")?));
                }
                ("T", false) => transports.push(Transport {
                    id: number(&tag, "T", "ID")?,
                    session_id: number(&tag, "T", "SID")?,
                    listeners: Vec::new(),
                }),
                ("L", false) => {
                    let Some(t) = transports.last_mut() else {
                        return proto("invitation: <L> outside <T>");
                    };
                    let host = tag.attr("N")?.ok_or_else(|| missing("L", "N"))?;
                    if let Some(port) = tag.attr("P")? {
                        let port = port.parse().map_err(|_| bad("L", "P", &port))?;
                        t.listeners.push(Listener { host, port });
                    }
                }
                _ => {}
            }
        }
        let Some((auth_id, key_hash, key_hash2)) = auth else {
            return proto("invitation: no <E><A ID=...> element");
        };
        Ok(Invitation {
            auth_id,
            key_hash,
            key_hash2,
            transports,
        })
    }

    /// Every (listener, SID) pair, in the invitation's order: the expert
    /// tries them all and keeps the first that connects (MS-RA 3.1.5).
    pub fn targets(&self) -> Vec<(Listener, u32)> {
        self.transports
            .iter()
            .flat_map(|t| t.listeners.iter().map(|l| (l.clone(), t.session_id)))
            .collect()
    }
}

fn proto<T>(m: &str) -> Result<T> {
    Err(Error::Protocol(m.into()))
}

fn missing(element: &str, attr: &str) -> Error {
    Error::Protocol(format!("invitation: <{element}> without {attr}"))
}

fn bad(element: &str, attr: &str, value: &str) -> Error {
    Error::Protocol(format!(
        "invitation: <{element} {attr}=\"{value}\"> is not a number"
    ))
}

fn number<T: std::str::FromStr>(tag: &Tag, element: &str, attr: &str) -> Result<T> {
    let v = tag.attr(attr)?.ok_or_else(|| missing(element, attr))?;
    v.parse().map_err(|_| bad(element, attr, &v))
}

/// One XML start or end tag.
struct Tag<'a> {
    name: &'a str,
    closing: bool,
    attrs: &'a str,
}

impl Tag<'_> {
    /// The value of attribute `name`, entity-decoded.
    fn attr(&self, name: &str) -> Result<Option<String>> {
        let mut rest = self.attrs;
        loop {
            rest = rest.trim_start();
            if rest.is_empty() || rest.starts_with('/') {
                return Ok(None);
            }
            let eq = rest.find('=').ok_or_else(|| attr_error(self.name))?;
            let key = rest[..eq].trim();
            let after = rest[eq + 1..].trim_start();
            let quote = after.chars().next().ok_or_else(|| attr_error(self.name))?;
            if quote != '"' && quote != '\'' {
                return Err(attr_error(self.name));
            }
            let end = after[1..]
                .find(quote)
                .ok_or_else(|| attr_error(self.name))?;
            let value = &after[1..1 + end];
            if key == name {
                return unescape(value).map(Some);
            }
            rest = &after[end + 2..];
        }
    }
}

fn attr_error(element: &str) -> Error {
    Error::Protocol(format!("invitation: malformed attributes in <{element}>"))
}

fn unescape(v: &str) -> Result<String> {
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let semi = rest[i..]
            .find(';')
            .ok_or_else(|| Error::Protocol("invitation: unterminated entity".into()))?;
        out.push_str(match &rest[i + 1..i + semi] {
            "amp" => "&",
            "lt" => "<",
            "gt" => ">",
            "quot" => "\"",
            "apos" => "'",
            e => return Err(Error::Protocol(format!("invitation: entity &{e};"))),
        });
        rest = &rest[i + semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The tags of a document, skipping text, `<?..?>` and `<!..>`.
struct Tags<'a> {
    rest: &'a str,
}

impl<'a> Tags<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text }
    }
}

impl<'a> Iterator for Tags<'a> {
    type Item = Result<Tag<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = self.rest.find('<')?;
            let after = &self.rest[start + 1..];
            let Some(end) = after.find('>') else {
                self.rest = "";
                return Some(proto("invitation: unterminated tag"));
            };
            let inner = &after[..end];
            self.rest = &after[end + 1..];
            if inner.starts_with('?') || inner.starts_with('!') {
                continue;
            }
            let (closing, inner) = match inner.strip_prefix('/') {
                Some(i) => (true, i),
                None => (false, inner),
            };
            let split = inner
                .find(|c: char| c.is_whitespace() || c == '/')
                .unwrap_or(inner.len());
            return Some(Ok(Tag {
                name: &inner[..split],
                closing,
                attrs: &inner[split..],
            }));
        }
    }
}

#[cfg(test)]
#[path = "assistance_tests.rs"]
mod tests;
