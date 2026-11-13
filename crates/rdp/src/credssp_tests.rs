//! CredSSP end to end over a loopback fake server (MS-CSSP 3.1.5): a scripted
//! [`AuthPackage`] checks the TSRequest fields of every round and that
//! pubKeyAuth and authInfo go through the package's wrap and unwrap; the
//! default NTLM package keeps its message shapes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::*;

const PUBLIC_KEY: &[u8] = b"\x30\x0a fake subject public key";

fn params() -> AuthParams<'static> {
    AuthParams {
        host: "server.example",
        user: "alice",
        domain: "EXAMPLE",
        password: "secret",
        workstation: "WS",
    }
}

/// A package that answers each server token from a script and marks what it
/// wraps (`C>`) and expects the server's wraps to be marked (`S>`).
/// (expected server token, token out, done) per step.
type Script = Vec<(Option<&'static [u8]>, &'static [u8], bool)>;

struct Scripted {
    script: Script,
    log: Arc<Mutex<Vec<String>>>,
}

impl AuthPackage for Scripted {
    fn step(&mut self, input: Option<&[u8]>) -> Result<Step> {
        let (want, out, done) = self.script.remove(0);
        assert_eq!(input, want, "the package got the server's token");
        self.log.lock().unwrap().push(format!("step {}", out.len()));
        Ok(Step {
            token: out.to_vec(),
            done,
        })
    }
    fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.log.lock().unwrap().push("wrap".into());
        Ok([b"C>", data].concat())
    }
    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.log.lock().unwrap().push("unwrap".into());
        match data.strip_prefix(b"S>") {
            Some(d) => Ok(d.to_vec()),
            None => Err(Error::Auth("not wrapped by the server".into())),
        }
    }
}

fn read_req(s: &mut TcpStream) -> Option<TsRequest> {
    let mut buf = Vec::new();
    let mut b = [0u8];
    loop {
        if let Some(n) = der::frame_len(&buf)
            && buf.len() >= n
        {
            return Some(TsRequest::decode(&buf).unwrap());
        }
        if s.read(&mut b).ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
    }
}

fn reply(s: &mut TcpStream, r: TsRequest) {
    s.write_all(&r.encode()).unwrap();
}

/// Runs the client against `server` on a loopback pair.
fn run(
    factory: Option<AuthFactory>,
    server: impl FnOnce(&mut TcpStream) + Send + 'static,
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut srv, _) = listener.accept().unwrap();
    let handle: JoinHandle<()> = std::thread::spawn(move || server(&mut srv));
    let mut f = Framer::new(sock);
    f.set_read_timeout(Duration::from_millis(20)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = authenticate(&mut f, PUBLIC_KEY, &params(), factory.as_ref(), deadline);
    drop(f);
    handle.join().expect("fake server assertions");
    result
}

fn scripted(script: Script) -> (AuthFactory, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    let script = Mutex::new(Some(script));
    let factory: AuthFactory = Arc::new(move |p: &AuthParams<'_>| {
        assert_eq!(p.host, "server.example");
        let script = script
            .lock()
            .unwrap()
            .take()
            .expect("one package per connection");
        Ok(Box::new(Scripted {
            script,
            log: l.clone(),
        }) as Box<dyn AuthPackage>)
    });
    (factory, log)
}

fn hash(magic: &[u8], nonce: &[u8]) -> Vec<u8> {
    sha256(&[magic, nonce, PUBLIC_KEY].concat()).to_vec()
}

#[test]
fn package_drives_three_rounds_with_v6_binding() {
    let (factory, log) = scripted(vec![
        (None, b"T1", false),
        (Some(b"S1"), b"T2", false),
        (Some(b"S2"), b"T3", true),
    ]);
    let result = run(Some(factory), |s| {
        for (out, back) in [(&b"T1"[..], &b"S1"[..]), (b"T2", b"S2")] {
            let r = read_req(s).unwrap();
            assert_eq!(r.version, 6);
            assert_eq!(r.nego_token.as_deref(), Some(out));
            assert!(r.pub_key_auth.is_none() && r.auth_info.is_none());
            assert!(r.client_nonce.is_none());
            reply(
                s,
                TsRequest {
                    version: 6,
                    nego_token: Some(back.to_vec()),
                    ..Default::default()
                },
            );
        }
        // Step 3: the last token together with the wrapped binding hash.
        let r = read_req(s).unwrap();
        assert_eq!(r.nego_token.as_deref(), Some(&b"T3"[..]));
        let nonce = r.client_nonce.expect("v6 sends a nonce");
        assert_eq!(nonce.len(), 32);
        let want = [&b"C>"[..], &hash(CLIENT_SERVER_MAGIC, &nonce)].concat();
        assert_eq!(r.pub_key_auth.unwrap(), want);
        assert!(r.auth_info.is_none());
        reply(
            s,
            TsRequest {
                version: 6,
                pub_key_auth: Some([&b"S>"[..], &hash(SERVER_CLIENT_MAGIC, &nonce)].concat()),
                ..Default::default()
            },
        );
        // Step 5: TSCredentials with TSPasswordCreds, wrapped.
        let r = read_req(s).unwrap();
        let creds = ts_credentials("EXAMPLE", "alice", "secret");
        assert_eq!(r.auth_info.unwrap(), [&b"C>"[..], &creds].concat());
        assert!(r.nego_token.is_none() && r.pub_key_auth.is_none());
    });
    result.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        ["step 2", "step 2", "step 2", "wrap", "unwrap", "wrap"]
    );
}

#[test]
fn version_4_server_gets_the_bare_key_and_no_empty_token() {
    let (factory, log) = scripted(vec![(None, b"K1", false), (Some(b"R1"), b"", true)]);
    let result = run(Some(factory), |s| {
        read_req(s).unwrap();
        reply(
            s,
            TsRequest {
                version: 4,
                nego_token: Some(b"R1".to_vec()),
                ..Default::default()
            },
        );
        let r = read_req(s).unwrap();
        assert!(r.nego_token.is_none(), "an empty last token is omitted");
        assert!(r.client_nonce.is_none(), "no nonce below version 5");
        assert_eq!(r.pub_key_auth.unwrap(), [&b"C>"[..], PUBLIC_KEY].concat());
        let mut plus_one = PUBLIC_KEY.to_vec();
        plus_one[0] += 1;
        reply(
            s,
            TsRequest {
                version: 4,
                pub_key_auth: Some([&b"S>"[..], &plus_one].concat()),
                ..Default::default()
            },
        );
        assert!(read_req(s).unwrap().auth_info.is_some());
    });
    result.unwrap();
    assert_eq!(log.lock().unwrap().len(), 5);
}

#[test]
fn package_done_at_once_sends_token_and_binding_together() {
    let (factory, _) = scripted(vec![(None, b"AP", true)]);
    let result = run(Some(factory), |s| {
        let r = read_req(s).unwrap();
        assert_eq!(r.nego_token.as_deref(), Some(&b"AP"[..]));
        let nonce = r.client_nonce.expect("our own version is assumed");
        reply(
            s,
            TsRequest {
                version: 6,
                pub_key_auth: Some([&b"S>"[..], &hash(SERVER_CLIENT_MAGIC, &nonce)].concat()),
                ..Default::default()
            },
        );
        read_req(s).unwrap();
    });
    result.unwrap();
}

#[test]
fn wrong_server_binding_is_refused_before_credentials() {
    for answer in [&b"S>wrong"[..], b"plain, not unwrapped"] {
        let (factory, _) = scripted(vec![(None, b"T", false), (Some(b"R"), b"F", true)]);
        let result = run(Some(factory), move |s| {
            read_req(s).unwrap();
            reply(
                s,
                TsRequest {
                    version: 6,
                    nego_token: Some(b"R".to_vec()),
                    ..Default::default()
                },
            );
            read_req(s).unwrap();
            reply(
                s,
                TsRequest {
                    version: 6,
                    pub_key_auth: Some(answer.to_vec()),
                    ..Default::default()
                },
            );
            assert!(read_req(s).is_none(), "no authInfo after a bad binding");
        });
        assert!(result.is_err());
    }
}

#[test]
fn stalled_package_is_an_error() {
    let (factory, _) = scripted(vec![(None, b"", false)]);
    assert!(run(Some(factory), |s| assert!(read_req(s).is_none())).is_err());
}

/// A minimal NTLM CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) with extended session
/// security and an empty target info list.
fn ntlm_challenge() -> Vec<u8> {
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend(2u32.to_le_bytes());
    m.extend([0u8; 8]); // TargetNameFields
    m.extend(
        (crate::ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY | crate::ntlm::NEGOTIATE_SEAL)
            .to_le_bytes(),
    );
    m.extend([0x11; 8]); // ServerChallenge
    m.extend([0u8; 8]);
    m.extend(4u16.to_le_bytes());
    m.extend(4u16.to_le_bytes());
    m.extend(48u32.to_le_bytes());
    m.extend([0u8; 4]); // MsvAvEOL
    m
}

#[test]
fn default_package_is_the_crates_ntlm() {
    let result = run(None, |s| {
        let r = read_req(s).unwrap();
        let p = params();
        let negotiate = Ntlm::new(p.user, p.domain, p.password, p.workstation).negotiate();
        let want = TsRequest {
            version: 6,
            nego_token: Some(negotiate),
            ..Default::default()
        };
        assert_eq!(r.encode(), want.encode());
        reply(
            s,
            TsRequest {
                version: 6,
                nego_token: Some(ntlm_challenge()),
                ..Default::default()
            },
        );
        let r = read_req(s).unwrap();
        assert_eq!(&r.nego_token.unwrap()[..12], b"NTLMSSP\0\x03\0\0\0");
        // 16-byte NTLM signature in front of the sealed 32-byte hash.
        assert_eq!(r.pub_key_auth.unwrap().len(), 48);
        assert_eq!(r.client_nonce.unwrap().len(), 32);
        assert!(r.auth_info.is_none());
        reply(
            s,
            TsRequest {
                version: 6,
                pub_key_auth: Some(vec![0; 48]),
                ..Default::default()
            },
        );
    });
    match result {
        Err(Error::Auth(m)) => assert!(m.contains("signature"), "{m}"),
        other => panic!("forged server binding accepted: {other:?}"),
    }
}

#[test]
fn ntlm_package_rejects_out_of_order_rounds() {
    let mut p = NtlmPackage::new(&params());
    assert!(p.step(Some(b"early")).is_err());
    let mut p = NtlmPackage::new(&params());
    assert!(!p.step(None).unwrap().done);
    assert!(p.step(Some(&ntlm_challenge())).unwrap().done);
    // A second CHALLENGE, even a valid one, is not answered.
    assert!(p.step(Some(&ntlm_challenge())).is_err());
}
