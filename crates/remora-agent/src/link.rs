//! [`LinkProtocol`]: the helper side of Remora-Link (docs/HELPER-PROTOCOL.md)
//! on top of the agent's [`Protocol`] seam. Platform independent; the
//! Windows parts (SAS dialog, folders, files) come in through
//! [`PairingUi`] and [`Files`], so the whole flow runs in tests against a
//! Remora-side `SecureSession` and `Engine`.
//!
//! Per `Remora::Ctl` open (section 5):
//! 1. Noise XX as initiator, then the SAS commit-reveal (inside
//!    `SecureSession`); Remora's static key is kept for the Bulk binding.
//! 2. `Hello` right after the SAS (capabilities, policy, OS build, session
//!    kind, version). File bits are not offered when policy disables
//!    clipboard or drive redirection.
//! 3. `PeerPairing` (1.1) right after the SAS, before `Hello`: `Known` when
//!    Remora's client key is pinned here ([`ClientPins`]), else `Confirm`
//!    and the SAS dialog at once. `Pairing` from Remora: `Known` → nothing
//!    more to show; `Confirm` → the SAS dialog (if not up already) until
//!    the user answers it here, Remora rejects, or the channel closes.
//!    Reject here (or closing the dialog) closes the channel. While the
//!    answer is pending no file data moves. Once both users confirmed, the
//!    client key is pinned here and `PeerPairing{Confirmed}` tells Remora.
//! 4. `HelloAck`: the accepted capabilities, the bulk token. A usable file
//!    capability opens `Remora::Bulk` ([`Action::OpenChannel`]), bound to
//!    the token and to Remora's Ctl key.
//! 5. Heartbeats every 10 s, `SessionInfo` on every tick if accepted,
//!    `OpenUrl` for links, file transfer through `remora_link::Engine`.
//!
//! # Server-to-client data goes only to a pinned client
//!
//! Remora has a persistent client key (DPAPI-protected on the client). The
//! helper pins it per user ([`ClientPins`], `agent-clients.json`) after the
//! user confirmed the code on the server and Remora's user confirmed too;
//! an admin can pre-seed it with `remora-agent trust-client`. Data that
//! leaves the server (file offers, `FILE_DOWN`, and links, `OPEN_URL`) goes
//! only to a client key pinned here
//! ([`LinkProtocol::server_to_client_allowed`], the single gate), never on
//! `Pairing{Known}` alone: a TLS-terminating proxy playing the client has
//! another key and gets the dialog. Session info needs only Remora's
//! pairing.
//!
//! # Nothing touches the receive folder before the server user confirmed
//!
//! Files from Remora (`FILE_UP`) need the client confirmed here too: its
//! key pinned, or the dialog answered in this session
//! ([`LinkProtocol::client_trusted`]). File messages that arrive earlier
//! are held (at most [`MAX_HELD`]) and handed to the engine only then; a
//! session that ends unconfirmed drops them, so an unknown client never
//! creates a part file or holds a transfer slot. File data on Bulk before
//! that closes Bulk. One client holds at most [`MAX_PER_CLIENT`] incoming
//! transfers (running or paused), so it cannot take every slot.
//!
//! # Pinned clients only
//!
//! With [`ClientPins::strict`] (an admin trusted a client by fingerprint,
//! the `PinnedClientsOnly` policy, or `remora-agent strict on`), an
//! unknown client key is refused without a dialog: a man in the middle
//! that ends TLS can then not get a click on the server either. After
//! [`MAX_UNANSWERED`] pairings with unknown keys that ended unanswered
//! within [`UNANSWERED_WINDOW`], unknown keys are refused the same way for
//! a back-off that doubles each time (from [`BACKOFF_MIN`] to
//! [`BACKOFF_MAX`]).
//!
//! Any session error closes that channel (and Bulk with Ctl); the next
//! open starts from scratch. The engine lives across channel sessions, so
//! uploads pause on a drop and resume after the next pairing.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use remora_link::msg::{
    ErrorMsg, Hello, HelloAck, PairingStatus, SessionInfo as WireInfo, SessionKind as WireKind,
    UrlStatus, err,
};
use remora_link::transfer::io::{Source, TargetDir};
use remora_link::transfer::worker::{EngineWorker, Posted};
use remora_link::transfer::{Direction, TransferEvent};
use remora_link::{Binding, Event, Message, Sas, SecureSession, StaticKey, cap, policy};

use crate::info::{SessionInfo, SessionKind};
use crate::seam::{Action, AgentEvent, Channel, Protocol, SendOutcome, UrlOutcome};
use crate::{debug, info, warn};

/// The helper's heartbeat interval once paired (Remora uses the same).
pub const HEARTBEAT: Duration = Duration::from_secs(10);
/// How long a link waits for Remora's `OpenUrlResult`. Remora answers only
/// after its user decided, so no answer in time means "Remora is asking":
/// the link counts as forwarded and is not opened locally as well. Below
/// the pipe's 3 s answer timeout.
pub const URL_ANSWER_WAIT: Duration = Duration::from_secs(2);
/// How often transfers are pumped without a message from Remora (the
/// worker also wakes the loop through [`LinkProtocol::set_transfer_notify`]).
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Links waiting for Remora's answer at a time (Remora queues 8 too).
const MAX_PENDING_URLS: usize = 8;
/// File messages held while the server user has not confirmed the client.
pub const MAX_HELD: usize = 64;
/// Incoming transfers (running or paused) one client key may hold.
pub const MAX_PER_CLIENT: usize = remora_link::transfer::MAX_ACTIVE / 2;
/// Unknown-key pairings that may end unanswered within
/// [`UNANSWERED_WINDOW`] before unknown keys are refused for a while.
pub const MAX_UNANSWERED: usize = 3;
pub const UNANSWERED_WINDOW: Duration = Duration::from_secs(10 * 60);
pub const BACKOFF_MIN: Duration = Duration::from_secs(60);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);

/// Shows the pairing code in the user's session and asks the user there.
pub trait PairingUi {
    /// Remora asks the user to compare codes: show this one with Confirm
    /// and Reject until [`PairingUi::close_sas`]. The answer comes back as
    /// [`AgentEvent::PairingAnswer`] with this `ticket`; closing the dialog
    /// any other way by the user (or its timeout) answers "rejected".
    fn show_sas(&mut self, ticket: u64, sas: Sas);
    /// Pairing ended (rejected, channel gone, answered). Idempotent.
    fn close_sas(&mut self);
}

/// The Remora clients the user confirmed on this server.
pub trait ClientPins {
    /// This client key is pinned (confirmed here before, or pre-seeded).
    fn is_pinned(&self, key: &[u8; 32]) -> bool;
    /// Pins it, with the client's name as a label.
    fn pin(&mut self, key: &[u8; 32], label: &str) -> io::Result<()>;
    /// Pinned clients only: why, or None when unknown clients may pair
    /// through the dialog.
    fn strict(&self) -> Option<&'static str> {
        None
    }
}

/// [`ClientPins`] in `agent-clients.json` (read fresh each time, so a
/// `trust-client` or `forget-client` takes effect on the next session),
/// with the pinned-clients-only switches ([`crate::clients::strict_mode`]).
pub struct FileClients {
    pub clients: Option<PathBuf>,
    /// The per-user setting (`remora-agent strict on|off`).
    pub setting: Option<PathBuf>,
    /// The `PinnedClientsOnly` policy (HKLM), read each time.
    pub policy: fn() -> Option<u32>,
}

impl ClientPins for FileClients {
    fn is_pinned(&self, key: &[u8; 32]) -> bool {
        // An unreadable store pins nobody (fail closed: the dialog shows).
        self.clients
            .as_deref()
            .is_some_and(|p| remora_link::ClientStore::load(p).is_ok_and(|s| s.is_pinned(key)))
    }
    fn strict(&self) -> Option<&'static str> {
        crate::clients::strict_mode(
            (self.policy)(),
            self.setting.as_deref(),
            self.clients.as_deref(),
        )
    }
    fn pin(&mut self, key: &[u8; 32], label: &str) -> io::Result<()> {
        let Some(p) = &self.clients else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no settings folder",
            ));
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        remora_link::ClientStore::update(p, |s| s.pin(key, label, now))
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// The file system as the transfers see it.
pub trait Files {
    /// The folder received files go into (created if missing).
    fn receive_dir(&mut self) -> io::Result<Box<dyn TargetDir>>;
    /// Opens a file to send: its plain name and a reader. Refuses anything
    /// that is not a regular file (folders, links, devices).
    fn open_source(&mut self, path: &Path) -> io::Result<(String, Box<dyn Source>)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pairing {
    /// Waiting for Remora's `Pairing`.
    Waiting,
    /// The SAS dialog is up.
    Confirming,
    Paired,
}

struct Ctl {
    session: SecureSession,
    remora_key: Option<[u8; 32]>,
    sas: Option<Sas>,
    /// Capabilities offered in our Hello (None: not sent yet).
    offered: Option<u32>,
    pairing: Pairing,
    /// The dialog shown for this session, if any.
    ticket: Option<u64>,
    /// The user confirmed the code on the server in this session.
    local_confirmed: bool,
    /// Remora's client key is pinned here (before, or now by both users).
    client_known: bool,
    /// Remora paired on its side (`Pairing` Known or Confirmed).
    remora_ok: bool,
    /// Remora's name for itself (`ClientName`), the pin's label.
    client_name: String,
    /// Accepted capabilities and the bulk token, after `HelloAck`.
    ack: Option<(u32, [u8; 32])>,
    next_heartbeat: Option<Instant>,
    heartbeat_seq: u32,
    /// The user here answered the dialog (either way).
    answered: bool,
    /// Refused without a dialog (pinned clients only, or back-off).
    refused: bool,
    /// File messages waiting for the client to be confirmed here.
    held: Vec<Message>,
    /// Incoming transfers this session started.
    created: Vec<[u8; 16]>,
}

struct PendingUrl {
    id: u64,
    deadline: Instant,
}

pub struct LinkProtocol {
    key: StaticKey,
    ui: Box<dyn PairingUi>,
    files: Box<dyn Files>,
    clients: Box<dyn ClientPins>,
    /// The transfer engine on its own thread: reads, writes and re-hashes
    /// never hold up this loop (heartbeats, links, pairing).
    engine: EngineWorker,
    ctl: Option<Ctl>,
    bulk: Option<SecureSession>,
    /// Bulk was asked for and not closed since.
    bulk_wanted: bool,
    info: Option<SessionInfo>,
    urls: BTreeMap<u32, PendingUrl>,
    next_request_id: u32,
    sas_shown: bool,
    next_ticket: u64,
    next_poll: Option<Instant>,
    /// The time of the event being handled.
    now: Instant,
    /// Incoming transfers by the client key that started them.
    owners: BTreeMap<[u8; 16], [u8; 32]>,
    /// When unknown-key pairings ended unanswered (recent ones).
    unanswered: Vec<Instant>,
    /// Unknown keys are refused until then.
    backoff_until: Option<Instant>,
    /// The next back-off.
    backoff: Duration,
}

/// Short transfer id for the log.
fn tid(id: &[u8; 16]) -> String {
    remora_link::wire::hex(&id[..4])
}

fn dir_name(d: Direction) -> &'static str {
    match d {
        Direction::Send => "to Remora",
        Direction::Receive => "from Remora",
    }
}

/// The `Hello` for this session.
pub fn hello(info: &SessionInfo) -> Hello {
    let mut pol = 0;
    if info.policy.clipboard_disabled {
        pol |= policy::CLIPBOARD_DISABLED;
    }
    if info.policy.drives_disabled {
        pol |= policy::DRIVES_DISABLED;
    }
    let mut caps = cap::ALL;
    if info.policy.file_transfer_disabled() {
        caps &= !(cap::FILE_UP | cap::FILE_DOWN);
    }
    let version =
        remora_link::wire::truncate(info.agent_version, remora_link::msg::MAX_VERSION_TEXT);
    Hello {
        major: remora_link::PROTO_MAJOR,
        minor: remora_link::PROTO_MINOR,
        helper_version: version.to_string(),
        os_build: info.os.build,
        // The wire knows desktop and RemoteApp; the console never has a
        // channel, and an unclassified remote session is a desktop.
        session_kind: match info.kind {
            SessionKind::RemoteApp => WireKind::RemoteApp,
            SessionKind::Desktop | SessionKind::Console | SessionKind::Unknown => WireKind::Desktop,
        },
        capabilities: caps,
        policy: pol,
    }
}

/// The `SessionInfo` message for a snapshot; unknown values are 0.
pub fn wire_info(i: &SessionInfo) -> WireInfo {
    let (used, total) = i.memory.map_or((0, 0), |m| {
        (
            m.total_bytes.saturating_sub(m.available_bytes),
            m.total_bytes,
        )
    });
    WireInfo {
        locked: i.locked.unwrap_or(false),
        idle_ms: i.idle_ms.map_or(0, |v| v.min(u64::from(u32::MAX)) as u32),
        cpu_percent: i
            .cpu_percent
            .filter(|c| c.is_finite())
            .map_or(0, |c| c.clamp(0.0, 100.0).round() as u8),
        mem_used: used,
        mem_total: total,
    }
}

impl LinkProtocol {
    pub fn new(
        key: StaticKey,
        ui: Box<dyn PairingUi>,
        files: Box<dyn Files>,
        clients: Box<dyn ClientPins>,
    ) -> LinkProtocol {
        LinkProtocol {
            key,
            ui,
            files,
            clients,
            engine: EngineWorker::default(),
            ctl: None,
            bulk: None,
            bulk_wanted: false,
            info: None,
            urls: BTreeMap::new(),
            next_request_id: 1,
            sas_shown: false,
            next_ticket: 1,
            next_poll: None,
            now: Instant::now(),
            owners: BTreeMap::new(),
            unanswered: Vec::new(),
            backoff_until: None,
            backoff: BACKOFF_MIN,
        }
    }

    /// Called on the transfer worker's thread when it has messages or
    /// events: the event loop should feed a `Timer` soon.
    pub fn set_transfer_notify(&self, f: impl Fn() + Send + Sync + 'static) {
        self.engine.set_notify(std::sync::Arc::new(f));
    }

    /// [`Protocol::on_event`] with an explicit clock (tests).
    pub fn on_event_at(&mut self, ev: AgentEvent, now: Instant) -> Vec<Action> {
        self.now = now;
        let mut out = Vec::new();
        match ev {
            AgentEvent::ChannelOpened(Channel::Ctl) => self.open_ctl(&mut out),
            AgentEvent::ChannelOpened(Channel::Bulk) => self.open_bulk(&mut out),
            AgentEvent::ChannelClosed(Channel::Ctl) => {
                if self.ctl.is_some() {
                    info!("Remora::Ctl session ended");
                }
                self.drop_ctl(&mut out);
            }
            AgentEvent::ChannelClosed(Channel::Bulk) => self.drop_bulk(),
            AgentEvent::Message(Channel::Ctl, wire) => self.on_ctl_wire(&wire, now, &mut out),
            AgentEvent::Message(Channel::Bulk, wire) => self.on_bulk_wire(&wire, &mut out),
            AgentEvent::SessionInfoTick(i) => self.on_info(i, &mut out),
            AgentEvent::OpenUrl { id, url } => self.open_url(id, url, now, &mut out),
            AgentEvent::SendFiles { id, paths } => self.send_files(id, paths, &mut out),
            AgentEvent::PairingAnswer { ticket, confirmed } => {
                self.on_local_answer(ticket, confirmed, &mut out)
            }
            AgentEvent::Timer => {}
            AgentEvent::Shutdown => self.close_ui(),
        }
        self.housekeeping(now, &mut out);
        out
    }

    // ------------------------------------------------------------ state

    fn acked(&self) -> Option<u32> {
        self.ctl
            .as_ref()
            .filter(|c| c.session.is_ready())
            .and_then(|c| c.ack.map(|(caps, _)| caps))
    }

    fn bulk_ready(&self) -> bool {
        self.bulk.as_ref().is_some_and(|b| b.is_ready())
    }

    /// Whether data may go from the server to the client (file offers,
    /// links) in this Ctl session: only to a client key pinned here, and
    /// not while the pairing dialog waits for an answer. The single gate
    /// for every server-to-client feature.
    pub fn server_to_client_allowed(&self) -> bool {
        self.ctl
            .as_ref()
            .is_some_and(|c| c.client_known && c.ticket.is_none() && c.session.is_ready())
    }

    /// The client is confirmed here: its key is pinned, or the user here
    /// confirmed the code in this session, and no dialog waits. Until then
    /// nothing from it reaches the transfer engine or the receive folder.
    pub fn client_trusted(&self) -> bool {
        self.ctl.as_ref().is_some_and(|c| {
            (c.client_known || c.local_confirmed) && c.ticket.is_none() && c.session.is_ready()
        })
    }

    /// (send, receive) file rights in force.
    fn file_rights(&self) -> (bool, bool) {
        let caps = self.acked().unwrap_or(0);
        (
            caps & cap::FILE_DOWN != 0 && self.server_to_client_allowed(),
            caps & cap::FILE_UP != 0 && self.client_trusted(),
        )
    }

    /// The pairing dialog is up and unanswered: the transfer link stays down
    /// and the engine's rights untouched (a paused download must not be
    /// cancelled just because the answer has not come yet).
    fn answer_pending(&self) -> bool {
        self.ctl.as_ref().is_some_and(|c| c.ticket.is_some())
    }

    /// Applies the file rights to the engine and opens Bulk when one is
    /// usable. Taking a right away cancels that direction's transfers; until
    /// the client is confirmed here the engine's rights are left as they
    /// are (a paused transfer of a confirmed client must not be cancelled
    /// because another session waits for its answer). Once confirmed, the
    /// file messages held meanwhile go to the engine.
    fn apply_rights(&mut self, out: &mut Vec<Action>) {
        let Some(caps) = self.acked() else {
            // Rights come with HelloAck; until then nothing changes.
            return;
        };
        let (send, receive) = self.file_rights();
        if self.client_trusted() {
            self.engine.set_permissions(send, receive);
        }
        // Bulk may open before the answer (it is bound to this session and
        // carries nothing until then).
        let usable = send || caps & cap::FILE_UP != 0;
        if usable && !self.bulk_wanted && self.ctl.is_some() {
            self.bulk_wanted = true;
            out.push(Action::OpenChannel(Channel::Bulk));
        }
        if self.client_trusted() {
            let held = self
                .ctl
                .as_mut()
                .map(|c| std::mem::take(&mut c.held))
                .unwrap_or_default();
            for m in held {
                self.post_ctl(&m, out);
            }
        }
        self.update_link();
    }

    /// Hands a file message from Ctl to the engine; a flood closes Ctl.
    fn post_ctl(&mut self, m: &Message, out: &mut Vec<Action>) {
        match self.engine.post(m) {
            Posted::Queued | Posted::NotFile => {}
            Posted::Overflow | Posted::Invalid => {
                self.fail(Channel::Ctl, "file messages beyond every limit", out)
            }
        }
    }

    /// Brings the engine's link up or down. Offers accepted while it was
    /// down ask for their data on link-up (the engine re-sends its
    /// `FileAccept`), so no grace or holding of offers is needed.
    fn update_link(&mut self) {
        let (send, receive) = self.file_rights();
        let want = (send || receive) && self.bulk_ready() && !self.answer_pending();
        if want == self.engine.is_connected() {
            return;
        }
        info!("file transfer link {}", if want { "up" } else { "down" });
        self.engine.set_connected(want);
    }

    fn close_ui(&mut self) {
        if self.sas_shown {
            self.sas_shown = false;
            self.ui.close_sas();
        }
    }

    /// Forgets the Ctl session: closes the dialog, answers waiting links,
    /// pauses transfers and closes Bulk. Does not close Ctl itself. A
    /// session that ends with its client unconfirmed leaves nothing: its
    /// held messages are dropped and any transfer it started is cancelled
    /// (with its part files). An unknown key's pairing that ended without
    /// an answer here counts towards the back-off.
    fn drop_ctl(&mut self, out: &mut Vec<Action>) {
        if let Some(c) = self.ctl.take() {
            let trusted = c.client_known || c.local_confirmed;
            if !trusted {
                for id in &c.created {
                    self.engine.cancel(*id);
                    self.owners.remove(id);
                }
                if !c.held.is_empty() {
                    info!(
                        "{} file messages of an unconfirmed client dropped",
                        c.held.len()
                    );
                }
            }
            if !trusted && !c.answered && !c.refused && c.sas.is_some() {
                self.note_unanswered();
            }
        }
        self.close_ui();
        for (_, u) in std::mem::take(&mut self.urls) {
            out.push(Action::OpenUrlResult {
                id: u.id,
                outcome: UrlOutcome::NoClient,
            });
        }
        if self.bulk.is_some() || self.bulk_wanted {
            out.push(Action::Close(Channel::Bulk));
        }
        self.bulk = None;
        self.bulk_wanted = false;
        self.update_link();
    }

    fn drop_bulk(&mut self) {
        if self.bulk.take().is_some() {
            info!("Remora::Bulk session ended");
        }
        self.update_link();
    }

    /// A fatal error on `ch`: close it (and Bulk with Ctl).
    fn fail(&mut self, ch: Channel, why: &str, out: &mut Vec<Action>) {
        warn!("{}: {why}; closing", ch.dvc_name());
        match ch {
            Channel::Ctl => {
                let had = self.ctl.is_some();
                self.drop_ctl(out);
                if had {
                    out.push(Action::Close(Channel::Ctl));
                }
            }
            Channel::Bulk => {
                self.bulk = None;
                self.bulk_wanted = false;
                self.update_link();
                out.push(Action::Close(Channel::Bulk));
            }
        }
    }

    /// Encrypts `msg` onto its channel. False if the channel is not ready
    /// or the message could not be sent (a session failure closes it).
    fn send(&mut self, request_id: u32, msg: &Message, out: &mut Vec<Action>) -> bool {
        let ch = Channel::from_link(msg.channel());
        let session = match ch {
            Channel::Ctl => self.ctl.as_mut().map(|c| &mut c.session),
            Channel::Bulk => self.bulk.as_mut(),
        };
        let Some(s) = session.filter(|s| s.is_ready()) else {
            return false;
        };
        match s.send(request_id, msg) {
            Ok(b) => {
                out.push(Action::Send(ch, b));
                true
            }
            Err(e) => {
                if s.is_failed() {
                    self.fail(ch, &format!("send failed: {e}"), out);
                } else {
                    warn!("message type {:#06x} not sent: {e}", msg.ty());
                }
                false
            }
        }
    }

    fn send_error(&mut self, code: u32, message: &str, out: &mut Vec<Action>) {
        let m = Message::Error(ErrorMsg {
            code,
            message: message.into(),
        });
        self.send(0, &m, out);
    }

    /// An unknown key's pairing ended unanswered: too many in a while start
    /// a back-off in which unknown keys are refused without a dialog.
    fn note_unanswered(&mut self) {
        let now = self.now;
        self.unanswered
            .retain(|&t| now.saturating_duration_since(t) < UNANSWERED_WINDOW);
        self.unanswered.push(now);
        if self.unanswered.len() >= MAX_UNANSWERED {
            self.unanswered.clear();
            self.backoff_until = Some(now + self.backoff);
            warn!(
                "{MAX_UNANSWERED} pairings ended unanswered; unknown Remora clients refused for {} s",
                self.backoff.as_secs()
            );
            self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// Why an unknown client key is refused without a dialog now, if it is.
    fn refuse_unknown(&self) -> Option<&'static str> {
        if let Some(why) = self.clients.strict() {
            return Some(why);
        }
        self.backoff_until
            .is_some_and(|t| self.now < t)
            .then_some("too many pairings ended unanswered; try again later")
    }

    // -------------------------------------------------------------- Ctl

    fn open_ctl(&mut self, out: &mut Vec<Action>) {
        if self.ctl.is_some() {
            info!("Remora::Ctl opened again; starting over");
            self.drop_ctl(out);
        }
        match remora_link::SecureSession::initiator(
            remora_link::Channel::Ctl,
            &self.key,
            Binding::default(),
        ) {
            Ok((session, first)) => {
                self.ctl = Some(Ctl {
                    session,
                    remora_key: None,
                    sas: None,
                    offered: None,
                    pairing: Pairing::Waiting,
                    ticket: None,
                    local_confirmed: false,
                    client_known: false,
                    remora_ok: false,
                    client_name: String::new(),
                    ack: None,
                    next_heartbeat: None,
                    heartbeat_seq: 0,
                    answered: false,
                    refused: false,
                    held: Vec::new(),
                    created: Vec::new(),
                });
                out.push(Action::Send(Channel::Ctl, first));
            }
            Err(e) => {
                warn!("Remora::Ctl: cannot start the handshake: {e}");
                out.push(Action::Close(Channel::Ctl));
            }
        }
    }

    fn on_ctl_wire(&mut self, wire: &[u8], now: Instant, out: &mut Vec<Action>) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        let events = match ctl.session.on_message(wire) {
            Ok(ev) => ev,
            Err(e) => return self.fail(Channel::Ctl, &e.to_string(), out),
        };
        for ev in events {
            let Some(ctl) = self.ctl.as_mut() else {
                return;
            };
            match ev {
                Event::Send(b) => out.push(Action::Send(Channel::Ctl, b)),
                Event::Established { remote_static } => {
                    ctl.remora_key = Some(remote_static);
                    ctl.client_known = self.clients.is_pinned(&remote_static);
                    info!(
                        "Remora::Ctl handshake done (client {})",
                        if ctl.client_known {
                            "known"
                        } else {
                            "not known here"
                        }
                    );
                }
                Event::Sas(sas) => {
                    ctl.sas = Some(sas);
                    let known = ctl.client_known;
                    if !known && let Some(why) = self.refuse_unknown() {
                        return self.refuse_client(why, out);
                    }
                    let st = if known {
                        PairingStatus::Known
                    } else {
                        PairingStatus::Confirm
                    };
                    self.send(0, &Message::PeerPairing(st), out);
                    if !known {
                        // This client needs the user here, whatever Remora says.
                        self.show_dialog();
                    }
                    self.maybe_hello(out);
                }
                Event::Message { request_id, msg } => self.on_ctl_msg(request_id, msg, now, out),
            }
        }
    }

    /// Refuses an unknown client key without asking anyone here: Remora
    /// hears why, and Ctl closes (its queued messages go out first).
    fn refuse_client(&mut self, why: &'static str, out: &mut Vec<Action>) {
        let fp = self
            .ctl
            .as_mut()
            .and_then(|c| {
                c.refused = true;
                c.remora_key
            })
            .map(|k| remora_link::fingerprint(&k))
            .unwrap_or_default();
        warn!("unknown Remora client {fp} refused: {why}");
        self.send(0, &Message::PeerPairing(PairingStatus::Rejected), out);
        self.send_error(
            err::PAIRING_REJECTED,
            "this helper accepts paired Remora clients only",
            out,
        );
        self.fail(Channel::Ctl, "client not paired here", out);
    }

    /// Sends `Hello` once the session is ready and a snapshot is known.
    fn maybe_hello(&mut self, out: &mut Vec<Action>) {
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let Some(ctl) = self.ctl.as_ref() else {
            return;
        };
        if !ctl.session.is_ready() || ctl.offered.is_some() {
            return;
        }
        let h = hello(info);
        let caps = h.capabilities;
        if self.send(0, &Message::Hello(h), out)
            && let Some(ctl) = self.ctl.as_mut()
        {
            ctl.offered = Some(caps);
            info!("Hello sent (capabilities {caps:#x})");
        }
    }

    fn on_ctl_msg(&mut self, request_id: u32, msg: Message, now: Instant, out: &mut Vec<Action>) {
        match msg {
            Message::Pairing(st) => self.on_pairing(st, out),
            Message::HelloAck(a) => self.on_ack(a, now, out),
            Message::Heartbeat { .. } => {}
            Message::ClientName { name } => {
                if let Some(ctl) = self.ctl.as_mut() {
                    // Untrusted text for the log and the client list.
                    ctl.client_name = remora_link::pins::clean_label(&name);
                }
            }
            Message::OpenUrlResult(status) => self.on_url_result(request_id, status, out),
            Message::Error(e) => {
                warn!("Remora reported error {}", e.code);
                if e.code == err::PAIRING_REJECTED || e.code == err::VERSION {
                    self.fail(Channel::Ctl, "Remora ended the session", out);
                }
            }
            Message::Unsupported { ty } => info!("Remora does not support type {ty:#06x}"),
            // A newer minor version: answer, never close.
            Message::Unknown { ty } => {
                self.send(0, &Message::Unsupported { ty }, out);
            }
            m @ (Message::FileOffer(_)
            | Message::FileAccept { .. }
            | Message::FileReject { .. }
            | Message::FileCredit { .. }
            | Message::FileCancel { .. }
            | Message::FileComplete { .. }) => {
                if self.acked().is_none() {
                    self.send_error(err::NOT_ALLOWED, "not paired", out);
                } else if self.client_trusted() {
                    self.post_ctl(&m, out);
                } else if let Some(ctl) = self.ctl.as_mut() {
                    // Held until the user here confirms this client.
                    if ctl.held.len() >= MAX_HELD {
                        return self.fail(
                            Channel::Ctl,
                            "too many file messages before the server user answered",
                            out,
                        );
                    }
                    ctl.held.push(m);
                }
            }
            // Helper-to-Remora types coming back.
            other => self.send_error(
                err::PROTOCOL,
                &format!("unexpected type {:#06x}", other.ty()),
                out,
            ),
        }
    }

    /// Shows the SAS dialog for this Ctl session (once).
    fn show_dialog(&mut self) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        let Some(sas) = ctl.sas else {
            return;
        };
        if ctl.ticket.is_some() || ctl.local_confirmed {
            return;
        }
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        ctl.ticket = Some(ticket);
        self.close_ui();
        self.ui.show_sas(ticket, sas);
        self.sas_shown = true;
    }

    /// Pins Remora's client key once both users confirmed (the dialog here
    /// and Remora's `Pairing` Known or Confirmed).
    fn maybe_pin_client(&mut self) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        if ctl.client_known || !ctl.local_confirmed || !ctl.remora_ok {
            return;
        }
        let Some(key) = ctl.remora_key else {
            return;
        };
        ctl.client_known = true;
        let label = ctl.client_name.clone();
        match self.clients.pin(&key, &label) {
            Ok(()) => info!("Remora client pinned"),
            // It still counts for this session; the next one asks again.
            Err(e) => warn!("Remora client not saved ({e}); pinned for this session"),
        }
    }

    fn on_pairing(&mut self, st: PairingStatus, out: &mut Vec<Action>) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        match st {
            PairingStatus::Known => {
                ctl.pairing = Pairing::Paired;
                ctl.remora_ok = true;
                info!("pairing: known to Remora");
                self.maybe_pin_client();
            }
            PairingStatus::Confirm => {
                if ctl.pairing != Pairing::Waiting {
                    return self.send_error(err::PROTOCOL, "unexpected Pairing", out);
                }
                ctl.pairing = Pairing::Confirming;
                info!("pairing: Remora asks the user to compare codes");
                self.show_dialog();
            }
            PairingStatus::Confirmed => {
                // Remora's user confirmed; the dialog here stays until the
                // user answers it too.
                ctl.pairing = Pairing::Paired;
                ctl.remora_ok = true;
                info!("pairing: confirmed in Remora");
                self.maybe_pin_client();
            }
            PairingStatus::Rejected => {
                info!("pairing: rejected in Remora");
                self.close_ui();
                self.fail(Channel::Ctl, "pairing rejected", out);
            }
        }
    }

    /// The user answered the dialog on the server.
    fn on_local_answer(&mut self, ticket: u64, confirmed: bool, out: &mut Vec<Action>) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        if ctl.ticket != Some(ticket) {
            return; // a dialog of an earlier session
        }
        ctl.ticket = None;
        ctl.local_confirmed = confirmed;
        ctl.answered = true;
        self.close_ui();
        if confirmed {
            info!("pairing: confirmed on the server");
            self.send(0, &Message::PeerPairing(PairingStatus::Confirmed), out);
            self.maybe_pin_client();
            self.apply_rights(out);
        } else {
            info!("pairing: rejected on the server");
            self.send(0, &Message::PeerPairing(PairingStatus::Rejected), out);
            self.send_error(err::PAIRING_REJECTED, "rejected on the server", out);
            self.fail(Channel::Ctl, "pairing rejected on the server", out);
        }
    }

    fn on_ack(&mut self, a: HelloAck, now: Instant, out: &mut Vec<Action>) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        if ctl.ack.is_some() {
            return self.send_error(err::PROTOCOL, "second HelloAck", out);
        }
        if a.major != remora_link::PROTO_MAJOR {
            self.send_error(err::VERSION, "unsupported major version", out);
            return self.fail(Channel::Ctl, "Remora speaks another major version", out);
        }
        let Some(offered) = ctl.offered else {
            return self.send_error(err::PROTOCOL, "HelloAck before Hello", out);
        };
        // Remora answers only once paired on its side.
        ctl.pairing = Pairing::Paired;
        ctl.remora_ok = true;
        let caps = a.capabilities & offered;
        ctl.ack = Some((caps, a.bulk_token));
        ctl.next_heartbeat = Some(now + HEARTBEAT);
        info!("paired; Remora accepted capabilities {caps:#x}");
        self.maybe_pin_client();
        if a.max_chunk < remora_link::transfer::CHUNK_SIZE {
            // The engine's chunk is fixed for its lifetime (transfers resume
            // across sessions). Remora 1.0 always accepts 256 KiB.
            warn!("Remora limits chunks to {} bytes", a.max_chunk);
        }
        self.apply_rights(out);
        self.send_info(out);
    }

    fn on_info(&mut self, i: SessionInfo, out: &mut Vec<Action>) {
        // Policy can change while connected: switch file transfer off at
        // once (the next Hello will not offer it).
        if i.policy.file_transfer_disabled()
            && let Some(ctl) = self.ctl.as_mut()
            && let Some((caps, _)) = ctl.ack.as_mut()
            && *caps & (cap::FILE_UP | cap::FILE_DOWN) != 0
        {
            info!("file transfer switched off by policy");
            *caps &= !(cap::FILE_UP | cap::FILE_DOWN);
            if self.bulk.is_some() || self.bulk_wanted {
                self.bulk = None;
                self.bulk_wanted = false;
                out.push(Action::Close(Channel::Bulk));
            }
            self.apply_rights(out);
        }
        self.info = Some(i);
        self.maybe_hello(out);
        self.send_info(out);
    }

    fn send_info(&mut self, out: &mut Vec<Action>) {
        if self.acked().is_some_and(|c| c & cap::SESSION_INFO != 0)
            && let Some(i) = self.info.as_ref()
        {
            let m = Message::SessionInfo(wire_info(i));
            self.send(0, &m, out);
        }
    }

    // ------------------------------------------------------------- Bulk

    fn open_bulk(&mut self, out: &mut Vec<Action>) {
        let binding = self.ctl.as_ref().and_then(|c| match (c.ack, c.remora_key) {
            (Some((_, token)), Some(key)) if c.session.is_ready() => Some(Binding {
                bulk_token: Some(token),
                expected_remote: Some(key),
            }),
            _ => None,
        });
        let Some(binding) = binding.filter(|_| self.bulk_wanted) else {
            info!("Remora::Bulk opened without a paired Remora::Ctl; closing");
            self.bulk = None;
            out.push(Action::Close(Channel::Bulk));
            return;
        };
        match SecureSession::initiator(remora_link::Channel::Bulk, &self.key, binding) {
            Ok((s, first)) => {
                self.bulk = Some(s);
                out.push(Action::Send(Channel::Bulk, first));
            }
            Err(e) => self.fail(Channel::Bulk, &format!("cannot start: {e}"), out),
        }
    }

    fn on_bulk_wire(&mut self, wire: &[u8], out: &mut Vec<Action>) {
        let Some(b) = self.bulk.as_mut() else {
            return;
        };
        let events = match b.on_message(wire) {
            Ok(ev) => ev,
            Err(e) => return self.fail(Channel::Bulk, &e.to_string(), out),
        };
        for ev in events {
            match ev {
                Event::Send(b) => out.push(Action::Send(Channel::Bulk, b)),
                Event::Established { .. } => {
                    info!("Remora::Bulk handshake done");
                    self.update_link();
                }
                Event::Sas(_) => {}
                // Nothing was asked for before the client is confirmed.
                Event::Message { .. } if !self.client_trusted() => {
                    return self.fail(
                        Channel::Bulk,
                        "file data before the server user confirmed the client",
                        out,
                    );
                }
                Event::Message { msg, .. } => match self.engine.post(&msg) {
                    Posted::Queued => {}
                    // Unknown types only: the session refuses Ctl types.
                    Posted::NotFile => {
                        self.send(0, &Message::Unsupported { ty: msg.ty() }, out);
                    }
                    Posted::Overflow | Posted::Invalid => {
                        return self.fail(Channel::Bulk, "file data beyond every credit", out);
                    }
                },
            }
        }
    }

    // ------------------------------------------------------------ links

    fn open_url(&mut self, id: u64, url: String, now: Instant, out: &mut Vec<Action>) {
        let allowed =
            self.acked().is_some_and(|c| c & cap::OPEN_URL != 0) && self.server_to_client_allowed();
        if !allowed || self.urls.len() >= MAX_PENDING_URLS {
            out.push(Action::OpenUrlResult {
                id,
                outcome: UrlOutcome::NoClient,
            });
            return;
        }
        let mut rid = self.next_request_id;
        while rid == 0 || self.urls.contains_key(&rid) {
            rid = rid.wrapping_add(1);
        }
        self.next_request_id = rid.wrapping_add(1);
        self.urls.insert(
            rid,
            PendingUrl {
                id,
                deadline: now + URL_ANSWER_WAIT,
            },
        );
        if !self.send(rid, &Message::OpenUrl { url }, out)
            && let Some(u) = self.urls.remove(&rid)
        {
            // Not sent, and the session is still up (a failure answered it).
            out.push(Action::OpenUrlResult {
                id: u.id,
                outcome: UrlOutcome::NoClient,
            });
        }
    }

    fn on_url_result(&mut self, request_id: u32, status: UrlStatus, out: &mut Vec<Action>) {
        let Some(u) = self.urls.remove(&request_id) else {
            info!("link answer after the timeout ({status:?})");
            return;
        };
        let outcome = match status {
            // Opened, or the user said no there: either way not locally.
            UrlStatus::Opened | UrlStatus::Declined => UrlOutcome::Forwarded,
            UrlStatus::Invalid | UrlStatus::Disabled => UrlOutcome::NoClient,
        };
        info!("link answered by Remora: {status:?}");
        out.push(Action::OpenUrlResult { id: u.id, outcome });
    }

    // ------------------------------------------------------------ files

    fn send_files(&mut self, id: u64, paths: Vec<PathBuf>, out: &mut Vec<Action>) {
        if !self.file_rights().0 {
            out.push(Action::SendFilesResult {
                id,
                outcome: SendOutcome::NoClient,
            });
            return;
        }
        let (mut offered, mut failed) = (0u16, 0u16);
        for p in paths {
            let r = self.files.open_source(&p).and_then(|(name, src)| {
                if crate::files::reserved_name(&name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "transfer working files are not sent",
                    ));
                }
                debug!("offering {name}");
                self.engine
                    .send(&name, src)
                    .map_err(|e| io::Error::other(e.to_string()))
            });
            match r {
                Ok(t) => {
                    offered = offered.saturating_add(1);
                    info!("transfer {} offered to Remora", tid(&t));
                }
                Err(e) => {
                    failed = failed.saturating_add(1);
                    warn!("a file could not be offered: {e}");
                    debug!("not offered: {}", p.display());
                }
            }
        }
        out.push(Action::SendFilesResult {
            id,
            outcome: SendOutcome::Offered { offered, failed },
        });
    }

    fn on_transfer(&mut self, e: TransferEvent) {
        match e {
            TransferEvent::Offered { id, name, size, .. } => {
                info!("transfer {} from Remora: {size} bytes", tid(&id));
                debug!("transfer {} name {name}", tid(&id));
                // Only a confirmed client's offers reach the engine; the
                // check stays here so nothing else can start a transfer.
                let owner = self
                    .ctl
                    .as_ref()
                    .filter(|_| self.client_trusted())
                    .and_then(|c| c.remora_key);
                let Some(owner) = owner else {
                    warn!("transfer {}: no confirmed client; refused", tid(&id));
                    self.engine
                        .refuse(id, remora_link::transfer::reason::DISABLED);
                    return;
                };
                if self.owners.values().filter(|k| **k == owner).count() >= MAX_PER_CLIENT {
                    warn!(
                        "transfer {}: this client holds {MAX_PER_CLIENT} transfers; refused",
                        tid(&id)
                    );
                    self.engine.refuse(id, remora_link::transfer::reason::BUSY);
                    return;
                }
                self.owners.insert(id, owner);
                if let Some(c) = self.ctl.as_mut() {
                    c.created.push(id);
                }
                match self.files.receive_dir() {
                    Ok(dir) => {
                        self.engine.accept(id, dir);
                    }
                    Err(e) => {
                        warn!("transfer {}: no receive folder: {e}", tid(&id));
                        self.engine.reject(id);
                    }
                }
            }
            TransferEvent::Progress { .. } => {}
            TransferEvent::Paused { id, direction } => {
                info!("transfer {} {} paused", tid(&id), dir_name(direction));
            }
            TransferEvent::Completed {
                id,
                direction,
                name,
            } => {
                self.owners.remove(&id);
                info!("transfer {} {} completed", tid(&id), dir_name(direction));
                debug!("transfer {} stored as {name}", tid(&id));
            }
            TransferEvent::Failed {
                id,
                direction,
                reason,
                by_peer,
                detail,
            } => {
                self.owners.remove(&id);
                warn!(
                    "transfer {} {} failed: reason {reason}{}",
                    tid(&id),
                    dir_name(direction),
                    if by_peer { " (by Remora)" } else { "" }
                );
                debug!("transfer {} detail: {detail}", tid(&id));
            }
        }
    }

    /// Sends the worker's messages and handles its events.
    fn pump(&mut self, out: &mut Vec<Action>) {
        for _ in 0..64 {
            // Tests drive the protocol step by step: let the worker catch up.
            #[cfg(test)]
            self.engine.sync(Duration::from_secs(10));
            let mut busy = false;
            while let Some(e) = self.engine.next_event() {
                busy = true;
                self.on_transfer(e);
            }
            for m in self.engine.take_messages() {
                busy = true;
                self.send(0, &m, out);
            }
            if !busy {
                break;
            }
        }
    }

    // ------------------------------------------------------------ clock

    fn housekeeping(&mut self, now: Instant, out: &mut Vec<Action>) {
        if let Some(ctl) = self.ctl.as_mut()
            && let Some(t) = ctl.next_heartbeat
            && now >= t
        {
            ctl.heartbeat_seq = ctl.heartbeat_seq.wrapping_add(1);
            ctl.next_heartbeat = Some(now + HEARTBEAT);
            let seq = ctl.heartbeat_seq;
            self.send(0, &Message::Heartbeat { seq }, out);
        }
        let due: Vec<u32> = self
            .urls
            .iter()
            .filter(|(_, u)| u.deadline <= now)
            .map(|(&r, _)| r)
            .collect();
        for r in due {
            if let Some(u) = self.urls.remove(&r) {
                info!("link: no answer yet; Remora is asking the user");
                out.push(Action::OpenUrlResult {
                    id: u.id,
                    outcome: UrlOutcome::Forwarded,
                });
            }
        }
        self.pump(out);
        self.next_poll =
            (self.engine.active() > 0 && self.engine.is_connected()).then(|| now + POLL_INTERVAL);
    }

    fn deadline(&self) -> Option<Instant> {
        let hb = self.ctl.as_ref().and_then(|c| c.next_heartbeat);
        let url = self.urls.values().map(|u| u.deadline).min();
        [hb, url, self.next_poll].into_iter().flatten().min()
    }
}

impl Protocol for LinkProtocol {
    fn on_event(&mut self, ev: AgentEvent) -> Vec<Action> {
        self.on_event_at(ev, Instant::now())
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.deadline()
    }
}

#[cfg(test)]
mod tests;
