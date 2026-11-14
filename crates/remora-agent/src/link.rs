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
//! 3. `Pairing`: `Known` → nothing to show; `Confirm` → the SAS dialog
//!    with Confirm and Reject until the user answers it here, Remora
//!    rejects, or the channel closes. Reject here (or closing the dialog)
//!    closes the channel. While the answer is pending no file data moves.
//! 4. `HelloAck`: the accepted capabilities, the bulk token. A usable file
//!    capability opens `Remora::Bulk` ([`Action::OpenChannel`]), bound to
//!    the token and to Remora's Ctl key.
//! 5. Heartbeats every 10 s, `SessionInfo` on every tick if accepted,
//!    `OpenUrl` for links, file transfer through `remora_link::Engine`.
//!
//! # Server-to-client data needs a local confirmation
//!
//! Remora's Noise key is fresh per connection, so the helper cannot tell
//! the real client from a TLS-terminating proxy playing it, and
//! `Pairing{Known}` proves nothing to the helper (HELPER-PROTOCOL.md 9).
//! Until Remora has a persistent client key the helper pins, data that
//! leaves the server (file offers, `FILE_DOWN`, and links, `OPEN_URL`) is
//! sent only after the user confirmed the code **on the server** in this
//! Ctl session ([`LinkProtocol::server_to_client_allowed`]). Session info
//! and files coming from Remora (`FILE_UP`) need only Remora's pairing.
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
use remora_link::transfer::{Direction, Engine, TransferEvent};
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
/// File bytes read per engine poll.
pub const POLL_BUDGET: usize = 4 << 20;
/// How often transfers are pumped without a message from Remora.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Links waiting for Remora's answer at a time (Remora queues 8 too).
const MAX_PENDING_URLS: usize = 8;
/// Wait between our Bulk handshake finishing and the first file message on
/// Ctl. The initiator finishes first (it writes handshake message 3), and
/// Ctl (PRI_MED) can overtake Bulk (PRI_LOW): a `FileOffer` that reaches
/// Remora before message 3 would be accepted while Remora's link is still
/// down, and Remora's engine then waits for a new offer that never comes.
/// The grace makes that ordering practically certain; the contract gap is
/// reported on RDP-43.
pub const LINK_GRACE: Duration = Duration::from_secs(1);

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
    /// Accepted capabilities and the bulk token, after `HelloAck`.
    ack: Option<(u32, [u8; 32])>,
    next_heartbeat: Option<Instant>,
    heartbeat_seq: u32,
}

struct PendingUrl {
    id: u64,
    deadline: Instant,
}

pub struct LinkProtocol {
    key: StaticKey,
    ui: Box<dyn PairingUi>,
    files: Box<dyn Files>,
    engine: Engine,
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
    /// When the engine's link goes up ([`LINK_GRACE`]).
    link_up_at: Option<Instant>,
    /// Remora's offers that arrived while our link was still down: an
    /// engine accepts those into a paused state that only a new offer
    /// resumes, so they wait here until the link is up.
    held_offers: Vec<Message>,
    /// The time of the event being handled.
    now: Instant,
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
    pub fn new(key: StaticKey, ui: Box<dyn PairingUi>, files: Box<dyn Files>) -> LinkProtocol {
        LinkProtocol {
            key,
            ui,
            files,
            engine: Engine::default(),
            ctl: None,
            bulk: None,
            bulk_wanted: false,
            info: None,
            urls: BTreeMap::new(),
            next_request_id: 1,
            sas_shown: false,
            next_ticket: 1,
            next_poll: None,
            link_up_at: None,
            held_offers: Vec::new(),
            now: Instant::now(),
        }
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
    /// links) in this Ctl session: only after the user confirmed the code
    /// on the server. The single gate for every server-to-client feature;
    /// a later client key pinned by the helper can widen it.
    pub fn server_to_client_allowed(&self) -> bool {
        self.ctl
            .as_ref()
            .is_some_and(|c| c.local_confirmed && c.session.is_ready())
    }

    /// (send, receive) file rights in force.
    fn file_rights(&self) -> (bool, bool) {
        let caps = self.acked().unwrap_or(0);
        (
            caps & cap::FILE_DOWN != 0 && self.server_to_client_allowed(),
            caps & cap::FILE_UP != 0,
        )
    }

    /// The pairing dialog is up and unanswered: the transfer link stays down
    /// and the engine's rights untouched (a paused download must not be
    /// cancelled just because the answer has not come yet).
    fn answer_pending(&self) -> bool {
        self.ctl.as_ref().is_some_and(|c| c.ticket.is_some())
    }

    /// Applies the file rights to the engine and opens Bulk when one is
    /// usable. Taking the send right away cancels outgoing transfers.
    fn apply_rights(&mut self, out: &mut Vec<Action>) {
        let (send, receive) = self.file_rights();
        if !self.answer_pending() {
            self.engine.set_permissions(send, receive);
        }
        if (send || receive) && !self.bulk_wanted && self.ctl.is_some() {
            self.bulk_wanted = true;
            out.push(Action::OpenChannel(Channel::Bulk));
        }
        self.update_link();
    }

    /// Brings the engine's link up (after [`LINK_GRACE`]) or down (at once).
    fn update_link(&mut self) {
        let (send, receive) = self.file_rights();
        let want = (send || receive) && self.bulk_ready() && !self.answer_pending();
        if !want {
            self.link_up_at = None;
            if self.engine.is_connected() {
                info!("file transfer link down");
            }
            self.engine.set_connected(false);
            return;
        }
        if self.engine.is_connected() {
            return;
        }
        let at = *self.link_up_at.get_or_insert(self.now + LINK_GRACE);
        if self.now >= at {
            self.link_up_at = None;
            info!("file transfer link up");
            self.engine.set_connected(true);
            for m in std::mem::take(&mut self.held_offers) {
                self.engine.handle(&m);
            }
        }
    }

    fn close_ui(&mut self) {
        if self.sas_shown {
            self.sas_shown = false;
            self.ui.close_sas();
        }
    }

    /// Forgets the Ctl session: closes the dialog, answers waiting links,
    /// pauses transfers and closes Bulk. Does not close Ctl itself.
    fn drop_ctl(&mut self, out: &mut Vec<Action>) {
        self.ctl = None;
        self.held_offers.clear();
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
                    ack: None,
                    next_heartbeat: None,
                    heartbeat_seq: 0,
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
                    info!("Remora::Ctl handshake done");
                }
                Event::Sas(sas) => {
                    ctl.sas = Some(sas);
                    self.maybe_hello(out);
                }
                Event::Message { request_id, msg } => self.on_ctl_msg(request_id, msg, now, out),
            }
        }
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
                if self.acked().is_some() {
                    match &m {
                        Message::FileOffer(o) if !self.engine.is_connected() => {
                            if self.held_offers.len() < remora_link::transfer::MAX_ACTIVE {
                                self.held_offers.push(m);
                            } else {
                                let busy = Message::FileReject {
                                    id: o.id,
                                    reason: remora_link::transfer::reason::BUSY,
                                };
                                self.send(0, &busy, out);
                            }
                        }
                        _ => {
                            self.engine.handle(&m);
                        }
                    }
                } else {
                    self.send_error(err::NOT_ALLOWED, "not paired", out);
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

    fn on_pairing(&mut self, st: PairingStatus, out: &mut Vec<Action>) {
        let Some(ctl) = self.ctl.as_mut() else {
            return;
        };
        match st {
            PairingStatus::Known => {
                ctl.pairing = Pairing::Paired;
                info!("pairing: known to Remora");
            }
            PairingStatus::Confirm => {
                if ctl.pairing != Pairing::Waiting {
                    return self.send_error(err::PROTOCOL, "unexpected Pairing", out);
                }
                ctl.pairing = Pairing::Confirming;
                if let Some(sas) = ctl.sas {
                    info!("pairing: Remora asks the user to compare codes");
                    let ticket = self.next_ticket;
                    self.next_ticket += 1;
                    ctl.ticket = Some(ticket);
                    self.close_ui();
                    self.ui.show_sas(ticket, sas);
                    self.sas_shown = true;
                }
            }
            PairingStatus::Confirmed => {
                // Remora's user confirmed; the dialog here stays until the
                // user answers it too (server-to-client data needs that).
                ctl.pairing = Pairing::Paired;
                info!("pairing: confirmed in Remora");
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
        self.close_ui();
        if confirmed {
            info!("pairing: confirmed on the server");
            self.apply_rights(out);
        } else {
            info!("pairing: rejected on the server");
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
        let caps = a.capabilities & offered;
        ctl.ack = Some((caps, a.bulk_token));
        ctl.next_heartbeat = Some(now + HEARTBEAT);
        info!("paired; Remora accepted capabilities {caps:#x}");
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
                Event::Message { msg, .. } => {
                    if !self.engine.handle(&msg) {
                        // Unknown types only: the session refuses Ctl types.
                        self.send(0, &Message::Unsupported { ty: msg.ty() }, out);
                    }
                }
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
                match self.files.receive_dir() {
                    Ok(dir) => {
                        if let Err(e) = self.engine.accept(id, dir) {
                            warn!("transfer {}: {e}", tid(&id));
                        }
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

    /// Moves file data and the engine's messages, handles its events.
    fn pump(&mut self, out: &mut Vec<Action>) {
        self.engine.poll(POLL_BUDGET);
        for _ in 0..64 {
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
        if self.link_up_at.is_some() {
            self.update_link();
        }
        self.pump(out);
        self.next_poll =
            (self.engine.active() > 0 && self.engine.is_connected()).then(|| now + POLL_INTERVAL);
    }

    fn deadline(&self) -> Option<Instant> {
        let hb = self.ctl.as_ref().and_then(|c| c.next_heartbeat);
        let url = self.urls.values().map(|u| u.deadline).min();
        [hb, url, self.next_poll, self.link_up_at]
            .into_iter()
            .flatten()
            .min()
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
