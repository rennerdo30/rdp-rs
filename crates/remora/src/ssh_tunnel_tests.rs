//! The jump host connector against an in-process russh server on loopback:
//! host key trust, key file sign-in and the forwarded byte stream.

use super::*;

use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg};

#[test]
fn parses_jump_hosts() {
    let j = |t| parse(t, "me");
    assert_eq!(
        j("bastion"),
        Some(JumpHost {
            host: "bastion".into(),
            port: 22,
            user: "me".into(),
            key_file: None
        })
    );
    let full = j("ops@bastion.corp:2222").unwrap();
    assert_eq!(
        (full.user.as_str(), full.host.as_str(), full.port),
        ("ops", "bastion.corp", 2222)
    );
    assert_eq!(full.label(), "ops@bastion.corp:2222");
    let v6 = j("ops@[fd00::1]:2200").unwrap();
    assert_eq!((v6.host.as_str(), v6.port), ("fd00::1", 2200));
    assert_eq!(v6.label(), "ops@[fd00::1]:2200");
    assert_eq!(j("fd00::1").unwrap().host, "fd00::1", "a bare IPv6 address");
    assert_eq!(j("ssh://ops@bastion/").unwrap().label(), "ops@bastion");
    for bad in [
        "",
        "  ",
        "-oProxyCommand=x",
        "ops@-x",
        "-u@host",
        "a b",
        "host:0",
        "host:x",
        "[::1",
    ] {
        assert_eq!(j(bad), None, "{bad:?}");
    }
}

#[test]
fn known_keys_decide_whether_to_ask() {
    let fp = "SHA256:aaa";
    assert_eq!(known(Some(fp), None, fp), Known::Trusted);
    assert_eq!(known(None, Some(true), fp), Known::Trusted);
    assert_eq!(
        known(Some("SHA256:old"), Some(true), fp),
        Known::Trusted,
        "OpenSSH trusts it"
    );
    assert_eq!(
        known(Some(fp), Some(false), fp),
        Known::Trusted,
        "trusted in Remora after a change"
    );
    assert_eq!(known(None, None, fp), Known::New);
    assert_eq!(known(Some("SHA256:old"), None, fp), Known::Changed);
    assert_eq!(known(None, Some(false), fp), Known::Changed);
}

/// A jump host that accepts one client key and forwards direct-tcpip
/// channels to loopback ports.
#[derive(Clone)]
struct Jump {
    allowed: PublicKey,
    opened: Arc<AtomicUsize>,
}

impl server::Handler for Jump {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if key.public_key == &self.allowed {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Ok(out) = tokio::net::TcpStream::connect((host, port as u16)).await else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        self.opened.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut out = out;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut out).await;
        });
        Ok(())
    }
}

struct Lab {
    jump: JumpHost,
    host_key: PublicKey,
    opened: Arc<AtomicUsize>,
    dir: PathBuf,
    /// An echo server the tunnel can reach.
    echo_port: u16,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rng() -> impl rand::CryptoRng {
    rand::rng()
}

/// Starts the jump host and an echo server on loopback threads.
fn lab(name: &str) -> Lab {
    let dir = std::env::temp_dir().join(format!("remora-ssh-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let client_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let key_file = dir.join("id_ed25519");
    std::fs::write(
        &key_file,
        client_key
            .to_openssh(keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let host_public = host_key.public_key().clone();
    let opened = Arc::new(AtomicUsize::new(0));
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in echo.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let mut w = s;
                let _ = io::copy(&mut r, &mut w);
            });
        }
    });
    let ssh = TcpListener::bind("127.0.0.1:0").unwrap();
    let ssh_port = ssh.local_addr().unwrap().port();
    ssh.set_nonblocking(true).unwrap();
    let handler = Jump {
        allowed: client_key.public_key().clone(),
        opened: opened.clone(),
    };
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Arc::new(server::Config {
                keys: vec![host_key],
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..server::Config::default()
            });
            let listener = tokio::net::TcpListener::from_std(ssh).unwrap();
            while let Ok((sock, _)) = listener.accept().await {
                let config = config.clone();
                let h = handler.clone();
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(config, sock, h).await {
                        let _ = s.await;
                    }
                });
            }
        });
    });
    Lab {
        jump: JumpHost {
            host: "127.0.0.1".into(),
            port: ssh_port,
            user: "ops".into(),
            key_file: Some(key_file),
        },
        host_key: host_public,
        opened,
        dir,
        echo_port,
    }
}

impl Lab {
    fn options(&self) -> Options {
        Options {
            pins: Some(self.dir.join("known_hosts.json")),
            openssh: Some(self.dir.join("openssh_known_hosts")),
            agents: false,
        }
    }

    fn fingerprint(&self) -> String {
        self.host_key.fingerprint(HashAlg::Sha256).to_string()
    }
}

/// A host key check that answers `trust` and records the prompts.
fn answering(trust: bool) -> (HostKeyCheck, Arc<Mutex<Vec<HostKeyPrompt>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    let check: HostKeyCheck = Arc::new(move |p: &HostKeyPrompt| {
        log.lock().unwrap().push(p.clone());
        trust
    });
    (check, asked)
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn echo_through(c: &rdp::Connector, port: u16) -> rdp::Result<()> {
    let mut s = c.open("127.0.0.1", port, soon())?;
    s.write.write_all(b"RDP bytes").unwrap();
    let mut got = [0u8; 9];
    s.read.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"RDP bytes", "the stream goes through the jump host");
    s.write.shutdown();
    let mut rest = Vec::new();
    s.read.read_to_end(&mut rest).unwrap();
    assert!(
        rest.is_empty(),
        "shutting the write side down ends the stream"
    );
    Ok(())
}

#[test]
fn trusts_a_new_key_once_and_carries_the_stream() {
    let lab = lab("trust");
    let (check, asked) = answering(true);
    let c = connector_with(lab.jump.clone(), check, lab.options());
    echo_through(&c, lab.echo_port).unwrap();
    assert_eq!(
        *asked.lock().unwrap(),
        [HostKeyPrompt {
            host: "127.0.0.1".into(),
            port: lab.jump.port,
            fingerprint: lab.fingerprint(),
            changed: false,
        }]
    );
    // The trusted key connects without asking again.
    echo_through(&c, lab.echo_port).unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(lab.opened.load(Ordering::SeqCst), 2);
}

#[test]
fn a_refused_key_sends_nothing_and_says_why() {
    let lab = lab("refuse");
    let (check, asked) = answering(false);
    let c = connector_with(lab.jump.clone(), check, lab.options());
    let e = c.open("127.0.0.1", lab.echo_port, soon()).err().unwrap();
    assert!(e.to_string().contains("SSH key was not trusted"), "{e}");
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(lab.opened.load(Ordering::SeqCst), 0);
}

#[test]
fn a_changed_key_asks_with_a_warning() {
    let lab = lab("changed");
    let opts = lab.options();
    crate::known_hosts::remember_ssh_in(
        opts.pins.as_ref().unwrap(),
        "127.0.0.1",
        lab.jump.port,
        "SHA256:someoldkey",
    )
    .unwrap();
    let (check, asked) = answering(false);
    let c = connector_with(lab.jump.clone(), check, opts);
    assert!(c.open("127.0.0.1", lab.echo_port, soon()).is_err());
    assert!(asked.lock().unwrap()[0].changed);
}

#[test]
fn a_key_in_openssh_known_hosts_connects_without_asking() {
    let lab = lab("openssh");
    let opts = lab.options();
    let line = format!(
        "[127.0.0.1]:{} {}\n",
        lab.jump.port,
        lab.host_key.to_openssh().unwrap()
    );
    std::fs::write(opts.openssh.as_ref().unwrap(), line).unwrap();
    let (check, asked) = answering(false);
    let c = connector_with(lab.jump.clone(), check, opts);
    echo_through(&c, lab.echo_port).unwrap();
    assert!(asked.lock().unwrap().is_empty());
}

#[test]
fn another_key_type_in_openssh_known_hosts_is_a_change() {
    let lab = lab("keytype");
    let opts = lab.options();
    let other = PrivateKey::random(
        &mut rng(),
        Algorithm::Ecdsa {
            curve: keys::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let line = format!(
        "[127.0.0.1]:{} {}
",
        lab.jump.port,
        other.public_key().to_openssh().unwrap()
    );
    std::fs::write(opts.openssh.as_ref().unwrap(), line).unwrap();
    let (check, asked) = answering(false);
    let c = connector_with(lab.jump.clone(), check, opts);
    assert!(c.open("127.0.0.1", lab.echo_port, soon()).is_err());
    assert!(asked.lock().unwrap()[0].changed, "not a first connection");
}

#[test]
fn a_wrong_key_file_is_a_sign_in_error() {
    let lab = lab("auth");
    let other = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let file = lab.dir.join("other");
    std::fs::write(
        &file,
        other
            .to_openssh(keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut jump = lab.jump.clone();
    jump.key_file = Some(file);
    let (check, _) = answering(true);
    let c = connector_with(jump, check, lab.options());
    match c.open("127.0.0.1", lab.echo_port, soon()) {
        Err(Error::Auth(m)) => assert!(m.contains("refused the sign-in as ops"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
    let mut none = lab.jump.clone();
    none.key_file = None;
    let (check, _) = answering(true);
    let c = connector_with(none, check, lab.options());
    match c.open("127.0.0.1", lab.echo_port, soon()) {
        Err(Error::Auth(m)) => assert!(m.contains("no SSH key"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn a_target_the_jump_host_cannot_reach_names_it() {
    let lab = lab("forward");
    let (check, _) = answering(true);
    let c = connector_with(lab.jump.clone(), check, lab.options());
    // A closed port: bind and drop.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let e = c.open("127.0.0.1", closed, soon()).err().unwrap();
    assert!(e.to_string().contains("could not open 127.0.0.1"), "{e}");
}

#[test]
fn an_unreachable_jump_host_is_an_io_error() {
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let jump = JumpHost {
        host: "127.0.0.1".into(),
        port: closed,
        user: "ops".into(),
        key_file: None,
    };
    let (check, _) = answering(true);
    let c = connector_with(
        jump,
        check,
        Options {
            pins: None,
            openssh: None,
            agents: false,
        },
    );
    match c.open("127.0.0.1", 3389, soon()) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
        other => panic!("{:?}", other.err()),
    }
}
