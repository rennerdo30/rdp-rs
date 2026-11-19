//! RDP through an SSH jump host (RDP-88): an [`rdp::Connector`] that signs
//! in to the jump host with `russh` and carries the RDP byte stream in a
//! `direct-tcpip` channel (RFC 4254 7.2), like `ssh -J`.
//!
//! - The RDP connection runs on top unchanged: X.224, TLS and NLA go end
//!   to end, so the server certificate is still checked as usual.
//! - The jump host's key is trusted on first use like a server certificate:
//!   a key in `%USERPROFILE%\.ssh\known_hosts` (OpenSSH's file) or one the
//!   user trusted in Remora connects silently; a new or changed key asks.
//!   Nothing is sent to the jump host before its key is trusted.
//! - Sign-in: the connection's key file (unencrypted), then the keys of the
//!   OpenSSH agent and Pageant. No passwords: the RDP password is never
//!   sent to the jump host.
//! - One SSH connection per RDP connection, on a thread of its own with a
//!   small tokio runtime; it ends with the RDP connection.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use russh::client;
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rdp::Error;

/// Default SSH port.
pub const PORT: u16 = 22;

/// Agent keys tried at most (servers allow 6 attempts by default).
const MAX_AGENT_KEYS: usize = 4;

/// Where to jump through: `user@host:port`, and an optional key file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpHost {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_file: Option<PathBuf>,
}

impl JumpHost {
    /// `user@host:port` for messages (the port only when not 22).
    pub fn label(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            PORT => format!("{}@{host}", self.user),
            p => format!("{}@{host}:{p}", self.user),
        }
    }
}

/// Parses `host`, `user@host`, `host:port`, `user@host:port` or
/// `user@[v6]:port`. Without a user, `default_user` (the Windows user
/// name, as OpenSSH does). None when empty or malformed: a user or host
/// that starts with `-`, or has spaces or control characters.
pub fn parse(text: &str, default_user: &str) -> Option<JumpHost> {
    let t = text
        .trim()
        .trim_start_matches("ssh://")
        .trim_end_matches('/');
    if t.is_empty() {
        return None;
    }
    let (user, rest) = match t.rsplit_once('@') {
        Some((u, r)) => (u.to_string(), r),
        None => (default_user.to_string(), t),
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        let port = match tail {
            "" => PORT,
            p => p.strip_prefix(':')?.parse().ok()?,
        };
        (h.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            // One colon: host:port. More: a bare IPv6 address.
            Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().ok()?),
            _ => (rest.to_string(), PORT),
        }
    };
    let bad = |s: &str| {
        s.is_empty() || s.starts_with('-') || s.chars().any(|c| c.is_whitespace() || c.is_control())
    };
    if bad(&host) || bad(&user) || port == 0 {
        return None;
    }
    Some(JumpHost {
        host,
        port,
        user,
        key_file: None,
    })
}

/// A jump host key to trust or refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    /// OpenSSH's form: `SHA256:` and unpadded base64.
    pub fingerprint: String,
    /// A different key was trusted for this host before (in Remora or in
    /// OpenSSH's known_hosts).
    pub changed: bool,
}

/// Asks the user about a key (may block until they answer); true trusts.
pub type HostKeyCheck = Arc<dyn Fn(&HostKeyPrompt) -> bool + Send + Sync>;

/// What a host key's records say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    /// Remora or OpenSSH trusts this key.
    Trusted,
    /// No record: first use.
    New,
    /// A record of another key.
    Changed,
}

/// `pinned`: Remora's fingerprint for the host; `openssh`: what OpenSSH's
/// known_hosts says (Some(true) a match, Some(false) another key, None no
/// entry or no file).
fn known(pinned: Option<&str>, openssh: Option<bool>, fingerprint: &str) -> Known {
    if pinned == Some(fingerprint) || openssh == Some(true) {
        Known::Trusted
    } else if pinned.is_some() || openssh == Some(false) {
        Known::Changed
    } else {
        Known::New
    }
}

/// OpenSSH's verdict on `key` for host:port in `file`.
/// Any recorded key for the host that is not this one (another type
/// included) counts as a change.
fn openssh_known(file: &Path, host: &str, port: u16, key: &PublicKey) -> Option<bool> {
    match keys::known_hosts::known_host_keys_path(host, port, file) {
        Ok(recorded) if recorded.is_empty() => None,
        Ok(recorded) => Some(recorded.iter().any(|(_, k)| k == key)),
        Err(e) => {
            rdp::trace!("ssh: cannot read {}: {e}", file.display());
            None
        }
    }
}

fn openssh_known_hosts() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|h| PathBuf::from(h).join(".ssh").join("known_hosts"))
}

/// Time the user spent on a host key prompt: it does not count against
/// the connection's deadline.
#[derive(Default)]
struct Paused {
    asking: AtomicBool,
    millis: AtomicU64,
}

/// The SSH client handler: checks the jump host's key.
struct Handler {
    host: String,
    port: u16,
    check: HostKeyCheck,
    paused: Arc<Paused>,
    /// Set when the user (or the records) refused the key, for the error.
    refused: Arc<Mutex<Option<String>>>,
    /// Where Remora keeps trusted fingerprints; None: the default file.
    pins: Option<PathBuf>,
    openssh: Option<PathBuf>,
    pinned: Option<String>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            // A host certificate: its key is checked like a plain key.
            PublicKeyOrCertificate::Certificate(c) => PublicKey::from(c.public_key().clone()),
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if let Some(want) = &self.pinned {
            if *want == fingerprint {
                return Ok(true);
            }
            rdp::trace!("ssh: the jump host's key is {fingerprint}, not the pinned one");
            *self.refused.lock().unwrap_or_else(|e| e.into_inner()) = Some(fingerprint);
            return Ok(false);
        }
        let pinned = match &self.pins {
            Some(p) => crate::known_hosts::lookup_ssh_in(p, &self.host, self.port),
            None => crate::known_hosts::lookup_ssh(&self.host, self.port),
        };
        let openssh = self
            .openssh
            .as_deref()
            .and_then(|f| openssh_known(f, &self.host, self.port, &key));
        let changed = match known(pinned.as_deref(), openssh, &fingerprint) {
            Known::Trusted => {
                rdp::trace!("ssh: {}:{} host key known", self.host, self.port);
                return Ok(true);
            }
            Known::New => false,
            Known::Changed => true,
        };
        let prompt = HostKeyPrompt {
            host: self.host.clone(),
            port: self.port,
            fingerprint: fingerprint.clone(),
            changed,
        };
        let check = self.check.clone();
        self.paused.asking.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        let trusted = tokio::task::spawn_blocking(move || check(&prompt))
            .await
            .unwrap_or(false);
        self.paused
            .millis
            .fetch_add(t0.elapsed().as_millis() as u64, Ordering::SeqCst);
        self.paused.asking.store(false, Ordering::SeqCst);
        if !trusted {
            *self.refused.lock().unwrap_or_else(|e| e.into_inner()) = Some(fingerprint);
            return Ok(false);
        }
        let saved = match &self.pins {
            Some(p) => crate::known_hosts::remember_ssh_in(p, &self.host, self.port, &fingerprint),
            None => crate::known_hosts::remember_ssh(&self.host, self.port, &fingerprint),
        };
        if let Err(e) = saved {
            rdp::trace!("ssh: cannot remember the host key: {e}");
        }
        Ok(true)
    }
}

/// The tunnel's settings beyond the jump host (tests point them at
/// temporary files and disable the agents).
#[derive(Clone)]
struct Options {
    pins: Option<PathBuf>,
    openssh: Option<PathBuf>,
    agents: bool,
    /// Only this fingerprint (`SHA256:...`) is trusted; nothing is asked or
    /// remembered (the command line's `--expect-jump-fingerprint`).
    pinned: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            pins: None,
            openssh: openssh_known_hosts(),
            agents: true,
            pinned: None,
        }
    }
}

/// A connector that reaches each RDP host through `jump`.
pub fn connector(jump: JumpHost, check: HostKeyCheck) -> rdp::Connector {
    connector_with(jump, check, Options::default())
}

/// A connector that trusts only the jump host key with this fingerprint
/// (`SHA256:...`), for scripts: no prompt, nothing remembered.
pub fn connector_pinned(jump: JumpHost, fingerprint: &str) -> rdp::Connector {
    let opts = Options {
        pinned: Some(fingerprint.trim().to_string()),
        ..Options::default()
    };
    connector_with(jump, Arc::new(|_: &HostKeyPrompt| false), opts)
}

fn connector_with(jump: JumpHost, check: HostKeyCheck, opts: Options) -> rdp::Connector {
    rdp::Connector::new(jump.label(), move |host, port, deadline| {
        open(&jump, check.clone(), &opts, host, port, deadline)
    })
}

/// Opens host:port through the jump host; blocks until the channel is open
/// or the setup failed.
fn open(
    jump: &JumpHost,
    check: HostKeyCheck,
    opts: &Options,
    host: &str,
    port: u16,
    deadline: Instant,
) -> rdp::Result<rdp::ConnectorStream> {
    let (ready_tx, ready_rx) = mpsc::channel::<rdp::Result<()>>();
    let (up_tx, up_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // Bounded: a slow reader holds the SSH window back instead of growing
    // a queue.
    let (down_tx, down_rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(64);
    // Fired (or dropped) when the RDP side shuts the stream down.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let jump = jump.clone();
    let opts = opts.clone();
    let target = (host.to_string(), port);
    std::thread::Builder::new()
        .name("ssh-tunnel".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(Error::Io(e)));
                    return;
                }
            };
            rt.block_on(run(
                jump,
                check,
                opts,
                target,
                deadline,
                ready_tx,
                Pipes {
                    up: up_rx,
                    down: down_tx,
                    stop: stop_rx,
                },
            ));
        })
        .map_err(Error::Io)?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(rdp::ConnectorStream {
            write: Box::new(TunnelWriter {
                tx: Some(up_tx),
                stop: Some(stop_tx),
            }),
            read: Box::new(TunnelReader {
                rx: down_rx,
                buf: Vec::new(),
                at: 0,
            }),
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Protocol("the SSH tunnel stopped".into())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    jump: JumpHost,
    check: HostKeyCheck,
    opts: Options,
    target: (String, u16),
    deadline: Instant,
    ready: mpsc::Sender<rdp::Result<()>>,
    pipes: Pipes,
) {
    let paused = Arc::new(Paused::default());
    let setup = setup(&jump, check, &opts, &target, paused.clone());
    let (session, channel) = match within(setup, deadline, &paused).await {
        Ok(v) => v,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    rdp::trace!(
        "ssh: tunnel to {}:{} through {} open",
        target.0,
        target.1,
        jump.label()
    );
    if ready.send(Ok(())).is_err() {
        return;
    }
    pump(channel, pipes).await;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    rdp::trace!("ssh: tunnel through {} closed", jump.label());
}

/// Runs `fut` until `deadline`, plus the time a host key prompt took.
async fn within<T>(
    fut: impl Future<Output = rdp::Result<T>>,
    deadline: Instant,
    paused: &Paused,
) -> rdp::Result<T> {
    tokio::pin!(fut);
    loop {
        let extra = Duration::from_millis(paused.millis.load(Ordering::SeqCst));
        let until = tokio::time::Instant::from_std(deadline + extra);
        tokio::select! {
            r = &mut fut => return r,
            _ = tokio::time::sleep_until(until) => {
                if !paused.asking.load(Ordering::SeqCst)
                    && Duration::from_millis(paused.millis.load(Ordering::SeqCst)) == extra
                {
                    return Err(Error::Timeout);
                }
                // The user is deciding, or just did: wait on.
                if paused.asking.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

type Session = client::Handle<Handler>;
type Channel = russh::Channel<client::Msg>;

/// Connects, checks the key, signs in and opens the channel.
async fn setup(
    jump: &JumpHost,
    check: HostKeyCheck,
    opts: &Options,
    target: &(String, u16),
    paused: Arc<Paused>,
) -> rdp::Result<(Session, Channel)> {
    let addrs: Vec<_> = tokio::net::lookup_host((jump.host.as_str(), jump.port))
        .await
        .map(Iterator::collect)
        .unwrap_or_default();
    if addrs.is_empty() {
        return Err(Error::Protocol(format!(
            "cannot resolve the jump host {}",
            jump.host
        )));
    }
    // Each address in turn (an unreachable IPv6 one may come first).
    let mut last = None;
    let mut sock = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => {
                rdp::trace!("ssh: cannot reach {addr}: {e}");
                last = Some(e);
            }
        }
    }
    let sock = match sock {
        Some(s) => s,
        None => {
            return Err(Error::Io(
                last.unwrap_or_else(|| io::ErrorKind::NotConnected.into()),
            ));
        }
    };
    let _ = sock.set_nodelay(true);
    let refused = Arc::new(Mutex::new(None));
    let handler = Handler {
        host: jump.host.clone(),
        port: jump.port,
        check,
        paused,
        refused: refused.clone(),
        pins: opts.pins.clone(),
        openssh: opts.openssh.clone(),
        pinned: opts.pinned.clone(),
    };
    let config = Arc::new(client::Config {
        // A long RDP session: keep the tunnel alive, never time it out.
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 4,
        inactivity_timeout: None,
        nodelay: true,
        ..client::Config::default()
    });
    let mut session = match client::connect_stream(config, sock, handler).await {
        Ok(s) => s,
        Err(e) => {
            if let Some(fp) = refused.lock().unwrap_or_else(|e| e.into_inner()).take() {
                return Err(Error::Protocol(format!(
                    "the jump host's SSH key was not trusted ({fp})"
                )));
            }
            return Err(ssh_error(e));
        }
    };
    sign_in(&mut session, jump, opts.agents).await?;
    let channel = session
        .channel_open_direct_tcpip(target.0.clone(), u32::from(target.1), "127.0.0.1", 0)
        .await
        .map_err(|e| {
            Error::Protocol(format!(
                "the jump host could not open {}:{}: {}",
                target.0,
                target.1,
                match e {
                    russh::Error::ChannelOpenFailure(f) => format!("{f:?}"),
                    e => e.to_string(),
                }
            ))
        })?;
    Ok((session, channel))
}

fn ssh_error(e: russh::Error) -> Error {
    match e {
        russh::Error::IO(io) => Error::Io(io),
        russh::Error::ConnectionTimeout | russh::Error::KeepaliveTimeout => Error::Timeout,
        e => Error::Protocol(format!("SSH: {e}")),
    }
}

/// The key file, then the agents' keys. Error::Auth when none is accepted.
async fn sign_in(session: &mut Session, jump: &JumpHost, agents: bool) -> rdp::Result<()> {
    let user = jump.user.as_str();
    // RSA keys sign with SHA-2 when the server says it takes it.
    let rsa = session
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    let mut tried = Vec::new();
    if let Some(path) = &jump.key_file {
        let key = keys::load_secret_key(path, None).map_err(|e| match e {
            keys::Error::KeyIsEncrypted => Error::Auth(format!(
                "the key file {} has a passphrase: add it to the OpenSSH agent (ssh-add) and leave the key file empty",
                path.display()
            )),
            e => Error::Auth(format!("cannot read the key file {}: {e}", path.display())),
        })?;
        tried.push("the key file".to_string());
        let r = session
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), rsa))
            .await
            .map_err(ssh_error)?;
        if r.success() {
            return Ok(());
        }
    }
    if agents {
        let n = agent_sign_in(session, user, rsa).await?;
        if n.0 {
            return Ok(());
        }
        if n.1 > 0 {
            tried.push(format!(
                "{} agent key{}",
                n.1,
                if n.1 == 1 { "" } else { "s" }
            ));
        }
    }
    Err(Error::Auth(if tried.is_empty() {
        format!(
            "no SSH key to sign in to the jump host as {user}: set a key file, or add a key to the OpenSSH agent (ssh-add)"
        )
    } else {
        format!(
            "the jump host refused the sign-in as {user} (tried {})",
            tried.join(" and ")
        )
    }))
}

/// Tries each key of the OpenSSH agent, then of Pageant: (signed in, keys
/// tried).
async fn agent_sign_in(
    session: &mut Session,
    user: &str,
    rsa: Option<HashAlg>,
) -> rdp::Result<(bool, usize)> {
    let mut tried = 0;
    #[cfg(windows)]
    {
        use russh::keys::agent::client::AgentClient;
        if let Ok(a) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
            && try_agent(session, user, rsa, a, &mut tried).await?
        {
            return Ok((true, tried));
        }
        if let Ok(a) = AgentClient::connect_pageant().await
            && try_agent(session, user, rsa, a, &mut tried).await?
        {
            return Ok((true, tried));
        }
    }
    #[cfg(unix)]
    {
        use russh::keys::agent::client::AgentClient;
        if let Ok(a) = AgentClient::connect_env().await
            && try_agent(session, user, rsa, a, &mut tried).await?
        {
            return Ok((true, tried));
        }
    }
    let _ = (session, user, rsa);
    Ok((false, tried))
}

#[cfg(any(windows, unix))]
async fn try_agent<S>(
    session: &mut Session,
    user: &str,
    rsa: Option<HashAlg>,
    mut agent: russh::keys::agent::client::AgentClient<S>,
    tried: &mut usize,
) -> rdp::Result<bool>
where
    S: russh::keys::agent::client::AgentStream + Unpin + Send + 'static,
{
    use russh::keys::agent::AgentIdentity;
    let Ok(ids) = agent.request_identities().await else {
        return Ok(false);
    };
    for id in ids {
        let AgentIdentity::PublicKey { key, .. } = id else {
            continue;
        };
        // OpenSSH servers drop the connection after MaxAuthTries (6).
        if *tried >= MAX_AGENT_KEYS {
            rdp::trace!("ssh: more agent keys than tried; set a key file");
            break;
        }
        *tried += 1;
        let hash = key.algorithm().is_rsa().then_some(rsa).flatten();
        match session
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(r) if r.success() => return Ok(true),
            Ok(_) => {}
            Err(e) => rdp::trace!("ssh: agent key not used: {e:?}"),
        }
    }
    Ok(false)
}

/// Moves bytes between the channel and the blocking RDP side until either
/// end closes.
/// The tunnel thread's ends of the RDP side's stream.
struct Pipes {
    up: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    down: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
    stop: tokio::sync::oneshot::Receiver<()>,
}

async fn pump(channel: Channel, pipes: Pipes) {
    let Pipes {
        mut up,
        down,
        mut stop,
    } = pipes;
    let (mut rd, mut wr) = tokio::io::split(channel.into_stream());
    let to_server = async {
        while let Some(buf) = up.recv().await {
            if wr.write_all(&buf).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };
    let from_server = async {
        let mut b = vec![0u8; 64 * 1024];
        loop {
            match rd.read(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if down.send(Ok(b[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = down.send(Err(e)).await;
                    break;
                }
            }
        }
    };
    // The RDP side's shutdown ends it even while a write is stuck on a
    // full SSH window.
    tokio::select! {
        _ = to_server => {}
        _ = from_server => {}
        _ = &mut stop => {}
    }
}

/// The RDP side's write half: hands bytes to the tunnel thread.
struct TunnelWriter {
    tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// Dropping it (shutdown, or the writer dropped) stops the pump.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Write for TunnelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "the SSH tunnel closed");
        let tx = self.tx.as_ref().ok_or_else(closed)?;
        tx.send(buf.to_vec()).map_err(|_| closed())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl rdp::transport::ByteStream for TunnelWriter {
    fn shutdown(&mut self) {
        // Ends the tunnel thread, which closes the channel and the SSH
        // connection; the read side then sees the end of the stream.
        self.tx = None;
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// The RDP side's read half.
struct TunnelReader {
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    buf: Vec<u8>,
    at: usize,
}

impl Read for TunnelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at >= self.buf.len() {
            // A plain thread (the framer's reader), never a runtime's.
            match self.rx.blocking_recv() {
                Some(Ok(b)) => {
                    self.buf = b;
                    self.at = 0;
                }
                Some(Err(e)) => return Err(e),
                // The tunnel ended.
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[cfg(test)]
#[path = "ssh_tunnel_tests.rs"]
mod tests;
