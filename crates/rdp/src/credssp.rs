//! CredSSP (MS-CSSP) client: a security package's tokens inside TSRequest,
//! public key binding, then delegation of the password credentials.
//!
//! The package is the crate's own NTLMv2 ([`crate::ntlm`]) unless the caller
//! supplies another through [`AuthFactory`] (rdpc: Windows SSPI "Negotiate",
//! which is Kerberos with NTLM fallback). MS-CSSP 3.1.5 treats the package's
//! tokens and its encryption as opaque; CredSSP only needs [`AuthPackage`].

use std::sync::Arc;
use std::time::Instant;

use crate::crypto::{random, sha256};
use crate::cursor::utf16le;
use crate::der::{self, DerReader, ctx, integer, octet, seq};
use crate::error::{Error, Result, proto};
use crate::ntlm::Ntlm;
use crate::trace;
use crate::transport::Framer;

const CLIENT_VERSION: u32 = 6;
const CLIENT_SERVER_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
const SERVER_CLIENT_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

#[derive(Default, Debug)]
pub struct TsRequest {
    pub version: u32,
    pub nego_token: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<Vec<u8>>,
}

impl TsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut c = ctx(0, &integer(self.version));
        if let Some(t) = &self.nego_token {
            c.extend(ctx(1, &seq(&seq(&ctx(0, &octet(t))))));
        }
        if let Some(a) = &self.auth_info {
            c.extend(ctx(2, &octet(a)));
        }
        if let Some(p) = &self.pub_key_auth {
            c.extend(ctx(3, &octet(p)));
        }
        if let Some(n) = &self.client_nonce {
            c.extend(ctx(5, &octet(n)));
        }
        seq(&c)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let body = DerReader::new(data).expect(0x30)?;
        let mut r = DerReader::new(body);
        let mut req = TsRequest::default();
        while !r.is_empty() {
            let (tag, c) = r.read()?;
            let mut inner = DerReader::new(c);
            match tag {
                0xA0 => req.version = der::parse_integer(inner.expect(0x02)?)? as u32,
                0xA1 => {
                    // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
                    let list = inner.expect(0x30)?;
                    let item = DerReader::new(list).expect(0x30)?;
                    let tok = DerReader::new(item).expect(0xA0)?;
                    req.nego_token = Some(DerReader::new(tok).expect(0x04)?.to_vec());
                }
                0xA2 => req.auth_info = Some(inner.expect(0x04)?.to_vec()),
                0xA3 => req.pub_key_auth = Some(inner.expect(0x04)?.to_vec()),
                0xA4 => req.error_code = Some(der::parse_integer(inner.expect(0x02)?)? as u32),
                0xA5 => req.client_nonce = Some(inner.expect(0x04)?.to_vec()),
                _ => {}
            }
        }
        Ok(req)
    }
}

fn ntstatus_name(code: u32) -> &'static str {
    match code {
        0xC000_006D => "STATUS_LOGON_FAILURE (wrong user name or password)",
        0xC000_006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000_0070 => "STATUS_INVALID_WORKSTATION",
        0xC000_0071 => "STATUS_PASSWORD_EXPIRED",
        0xC000_0072 => "STATUS_ACCOUNT_DISABLED",
        0xC000_0193 => "STATUS_ACCOUNT_EXPIRED",
        0xC000_0224 => "STATUS_PASSWORD_MUST_CHANGE",
        0xC000_0234 => "STATUS_ACCOUNT_LOCKED_OUT",
        0xC000_015B => "STATUS_LOGON_TYPE_NOT_GRANTED",
        0x8009_0308 => "SEC_E_INVALID_TOKEN",
        0x8009_030C => "SEC_E_LOGON_DENIED",
        _ => "unknown status",
    }
}

fn read_request(f: &mut Framer, deadline: Instant) -> Result<TsRequest> {
    let raw = f.read_der(deadline).map_err(|e| match e {
        Error::Disconnected(_) | Error::ConnectionLost(_) => {
            Error::Auth("server closed the connection during NLA (wrong credentials?)".into())
        }
        other => other,
    })?;
    let req = TsRequest::decode(&raw)?;
    if let Some(code) = req.error_code {
        return Err(Error::Auth(format!(
            "server error {code:#010x} {}",
            ntstatus_name(code)
        )));
    }
    Ok(req)
}

fn ts_credentials(domain: &str, user: &str, password: &str) -> Vec<u8> {
    let mut pw = ctx(0, &octet(&utf16le(domain)));
    pw.extend(ctx(1, &octet(&utf16le(user))));
    pw.extend(ctx(2, &octet(&utf16le(password))));
    let mut c = ctx(0, &integer(1)); // credType 1 = password
    c.extend(ctx(1, &octet(&seq(&pw))));
    seq(&c)
}

/// The result of one [`AuthPackage::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Token for the server; may be empty only when `done`.
    pub token: Vec<u8>,
    /// The security context is established: wrap and unwrap are usable.
    pub done: bool,
}

/// A security package that CredSSP runs inside TSRequest negoTokens
/// (MS-CSSP 3.1.5 step 2): SPNEGO, Kerberos or NTLM, opaque to CredSSP.
pub trait AuthPackage: Send {
    /// The next token: `None` on the first call, then the server's last
    /// negoToken.
    fn step(&mut self, input: Option<&[u8]>) -> Result<Step>;
    /// Encrypts with the package's confidentiality service into one blob
    /// (SSPI EncryptMessage: the token buffer followed by the data buffer).
    fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts a blob made by the server's wrap.
    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

/// What a package factory gets to build the package for one connection.
#[derive(Debug, Clone, Copy)]
pub struct AuthParams<'a> {
    /// The server host name (the Kerberos service is `TERMSRV/<host>`).
    pub host: &'a str,
    pub user: &'a str,
    pub domain: &'a str,
    pub password: &'a str,
    pub workstation: &'a str,
}

/// Builds the security package for a connection; see [`crate::Config::auth`].
pub type AuthFactory = Arc<dyn Fn(&AuthParams<'_>) -> Result<Box<dyn AuthPackage>> + Send + Sync>;

/// The crate's own NTLMv2 as an [`AuthPackage`]: NEGOTIATE, then
/// AUTHENTICATE in answer to the CHALLENGE, then sealing (MS-NLMP 3.4.3).
pub struct NtlmPackage {
    ntlm: Ntlm,
    round: u8,
}

impl NtlmPackage {
    pub fn new(p: &AuthParams<'_>) -> Self {
        Self {
            ntlm: Ntlm::new(p.user, p.domain, p.password, p.workstation),
            round: 0,
        }
    }
}

impl AuthPackage for NtlmPackage {
    fn step(&mut self, input: Option<&[u8]>) -> Result<Step> {
        self.round = self.round.saturating_add(1);
        match (self.round, input) {
            (1, None) => Ok(Step {
                token: self.ntlm.negotiate(),
                done: false,
            }),
            (2, Some(challenge)) => Ok(Step {
                token: self.ntlm.authenticate(challenge)?,
                done: true,
            }),
            _ => proto("NTLM: unexpected CredSSP round"),
        }
    }

    fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.ntlm.encrypt(data)
    }

    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.ntlm.decrypt(data)
    }
}

/// Bound on negoToken round trips (Kerberos needs one or two, NTLM one).
const MAX_ROUNDS: usize = 16;

/// Runs NLA over the established TLS session with the package `factory`
/// builds, or with the crate's NTLM when it is `None`.
pub fn authenticate(
    f: &mut Framer,
    server_public_key: &[u8],
    params: &AuthParams<'_>,
    factory: Option<&AuthFactory>,
    deadline: Instant,
) -> Result<()> {
    let mut pkg: Box<dyn AuthPackage> = match factory {
        Some(make) => make(params)?,
        None => Box::new(NtlmPackage::new(params)),
    };
    authenticate_with(f, server_public_key, pkg.as_mut(), params, deadline)
}

/// MS-CSSP 3.1.5 steps 2 to 5 with any security package.
pub fn authenticate_with(
    f: &mut Framer,
    server_public_key: &[u8],
    pkg: &mut dyn AuthPackage,
    params: &AuthParams<'_>,
    deadline: Instant,
) -> Result<()> {
    // Step 2: negoTokens until the package's context is established. Until
    // the server has answered, assume it speaks our version: a package that
    // is done in one step (no mutual authentication) sends pubKeyAuth at once.
    let mut version = CLIENT_VERSION;
    let mut step = pkg.step(None)?;
    let mut rounds = 0;
    while !step.done {
        rounds += 1;
        if step.token.is_empty() || rounds > MAX_ROUNDS {
            return proto("CredSSP: the security package made no progress");
        }
        let msg = TsRequest {
            version: CLIENT_VERSION,
            nego_token: Some(std::mem::take(&mut step.token)),
            ..Default::default()
        };
        f.write(&msg.encode())?;
        let reply = read_request(f, deadline)?;
        version = reply.version.min(CLIENT_VERSION);
        if rounds == 1 {
            trace!("CredSSP: server version {}, using {version}", reply.version);
        }
        let token = reply
            .nego_token
            .ok_or_else(|| Error::Protocol("CredSSP challenge without negoToken".into()))?;
        step = pkg.step(Some(&token))?;
    }

    // Step 3: the last token, if the package has one, together with the
    // encrypted public key binding. Versions 5 and 6 hash a client nonce in;
    // the nonce travels in the clear and the package (NTLM or Kerberos alike)
    // only encrypts the hash, so nothing here depends on the package.
    let nonce: [u8; 32] = random();
    let binding = if version >= 5 {
        sha256(&[CLIENT_SERVER_MAGIC, &nonce, server_public_key].concat()).to_vec()
    } else {
        server_public_key.to_vec()
    };
    let msg = TsRequest {
        version: CLIENT_VERSION,
        nego_token: (!step.token.is_empty()).then_some(step.token),
        pub_key_auth: Some(pkg.wrap(&binding)?),
        client_nonce: (version >= 5).then(|| nonce.to_vec()),
        ..Default::default()
    };
    f.write(&msg.encode())?;

    // Steps 4 and 5: the server's binding, encrypted by its side of the package.
    let reply = read_request(f, deadline)?;
    if reply.nego_token.is_some() {
        // Step 4 omits negoTokens; our context is already complete.
        trace!("CredSSP: ignoring a negoToken next to the server's pubKeyAuth");
    }
    let sealed = reply
        .pub_key_auth
        .ok_or_else(|| Error::Auth("server did not confirm the public key".into()))?;
    let plain = pkg.unwrap(&sealed)?;
    let expected = if version >= 5 {
        sha256(&[SERVER_CLIENT_MAGIC, &nonce, server_public_key].concat()).to_vec()
    } else {
        let mut k = server_public_key.to_vec();
        k[0] = k[0].wrapping_add(1);
        k
    };
    if plain != expected {
        return proto("CredSSP server public key binding mismatch (possible man in the middle)");
    }

    let creds = TsRequest {
        version: CLIENT_VERSION,
        auth_info: Some(pkg.wrap(&ts_credentials(params.domain, params.user, params.password))?),
        ..Default::default()
    };
    f.write(&creds.encode())?;
    trace!("CredSSP: credentials delegated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_request_round_trip() {
        let req = TsRequest {
            version: 6,
            nego_token: Some(vec![1, 2, 3]),
            pub_key_auth: Some(vec![9; 200]),
            client_nonce: Some(vec![5; 32]),
            ..Default::default()
        };
        let back = TsRequest::decode(&req.encode()).unwrap();
        assert_eq!(back.version, 6);
        assert_eq!(back.nego_token.unwrap(), vec![1, 2, 3]);
        assert_eq!(back.pub_key_auth.unwrap(), vec![9; 200]);
        assert_eq!(back.client_nonce.unwrap(), vec![5; 32]);
    }

    #[test]
    fn error_code_decodes_as_ntstatus() {
        let mut c = ctx(0, &integer(6));
        c.extend(ctx(4, &der::tlv(0x02, &[0xC0, 0x00, 0x00, 0x6D])));
        let req = TsRequest::decode(&seq(&c)).unwrap();
        assert_eq!(req.error_code, Some(0xC000_006D));
    }
}

#[cfg(test)]
#[path = "credssp_tests.rs"]
mod package_tests;
