//! End to end: [`LinkProtocol`] against a Remora built from remora-link
//! (responder `SecureSession`s, pin decision, `HelloAck`, an `Engine`),
//! over in-memory channels. Not `crates/remora`: this checks the agent
//! against the contract, with a Remora small enough to read.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use remora_link::msg::{HelloAck, PairingStatus, UrlStatus};
use remora_link::transfer::io::{MemDir, MemSource};
use remora_link::transfer::{BLOCK_SIZE, CHUNK_SIZE, WINDOW};

use super::*;
use crate::info::{Memory, OsVersion, PolicyFlags};

// ------------------------------------------------------------ the agent side

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ui {
    Show(u64, Sas),
    Close,
}

#[derive(Clone, Default)]
struct UiLog(Rc<RefCell<Vec<Ui>>>);

impl PairingUi for UiLog {
    fn show_sas(&mut self, ticket: u64, sas: Sas) {
        self.0.borrow_mut().push(Ui::Show(ticket, sas));
    }
    fn close_sas(&mut self) {
        self.0.borrow_mut().push(Ui::Close);
    }
}

impl UiLog {
    fn take(&self) -> Vec<Ui> {
        std::mem::take(&mut self.0.borrow_mut())
    }
    fn last_ticket(&self) -> Option<u64> {
        self.0.borrow().iter().rev().find_map(|u| match u {
            Ui::Show(t, _) => Some(*t),
            Ui::Close => None,
        })
    }
}

struct MemFiles {
    dir: MemDir,
    sources: BTreeMap<PathBuf, (Vec<u8>, u64)>,
}

impl Files for MemFiles {
    fn receive_dir(&mut self) -> io::Result<Box<dyn TargetDir>> {
        Ok(Box::new(self.dir.clone()))
    }
    fn open_source(&mut self, path: &Path) -> io::Result<(String, Box<dyn Source>)> {
        let (data, mtime) = self
            .sources
            .get(path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        Ok((name, Box::new(MemSource::new(data.clone(), *mtime))))
    }
}

fn snapshot(policy: PolicyFlags) -> SessionInfo {
    SessionInfo {
        agent_version: "9.9.9-test",
        os: OsVersion {
            build: 26100,
            ..OsVersion::default()
        },
        kind: SessionKind::RemoteApp,
        policy,
        locked: Some(true),
        idle_ms: Some(1234),
        cpu_percent: Some(42.4),
        memory: Some(Memory {
            total_bytes: 8 << 30,
            available_bytes: 3 << 30,
            load_percent: 62,
        }),
    }
}

// ------------------------------------------------------------ Remora's side

struct Remora {
    key: StaticKey,
    /// The helper key pinned for this server.
    pinned: Option<[u8; 32]>,
    user_caps: u32,
    /// Answer `Confirm` with this once the SAS is known (None: wait).
    auto_confirm: Option<bool>,
    /// Answer every `OpenUrl` with this (None: keep it pending).
    url_answer: Option<UrlStatus>,
    ctl: Option<SecureSession>,
    bulk: Option<SecureSession>,
    helper_key: Option<[u8; 32]>,
    sas: Option<Sas>,
    awaiting_user: bool,
    hello: Option<Hello>,
    paired: bool,
    ack_sent: bool,
    token: Option<[u8; 32]>,
    engine: Engine,
    dir: MemDir,
    out: VecDeque<(Channel, Vec<u8>)>,
    /// Application messages received on Ctl.
    got: Vec<(u32, Message)>,
    /// Channels Remora closed.
    closes: Vec<Channel>,
}

impl Remora {
    fn new() -> Remora {
        Remora {
            key: StaticKey::generate().unwrap(),
            pinned: None,
            user_caps: cap::ALL,
            auto_confirm: Some(true),
            url_answer: Some(UrlStatus::Opened),
            ctl: None,
            bulk: None,
            helper_key: None,
            sas: None,
            awaiting_user: false,
            hello: None,
            paired: false,
            ack_sent: false,
            token: None,
            engine: Engine::default(),
            dir: MemDir::new(),
            out: VecDeque::new(),
            got: Vec::new(),
            closes: Vec::new(),
        }
    }

    fn open(&mut self, ch: Channel) {
        match ch {
            Channel::Ctl => {
                self.ctl = Some(
                    SecureSession::responder(
                        remora_link::Channel::Ctl,
                        &self.key,
                        Binding::default(),
                    )
                    .unwrap(),
                );
                self.helper_key = None;
                self.sas = None;
                self.hello = None;
                self.paired = false;
                self.ack_sent = false;
                self.token = None;
                self.awaiting_user = false;
            }
            Channel::Bulk => {
                // Remora closes a Bulk that opens before HelloAck.
                let (Some(token), Some(key), true) = (self.token, self.helper_key, self.ack_sent)
                else {
                    self.closes.push(Channel::Bulk);
                    return;
                };
                self.bulk = Some(
                    SecureSession::responder(
                        remora_link::Channel::Bulk,
                        &self.key,
                        Binding {
                            bulk_token: Some(token),
                            expected_remote: Some(key),
                        },
                    )
                    .unwrap(),
                );
            }
        }
    }

    fn closed(&mut self, ch: Channel) {
        match ch {
            Channel::Ctl => {
                self.ctl = None;
                self.bulk = None;
                self.ack_sent = false;
            }
            Channel::Bulk => self.bulk = None,
        }
        self.link();
    }

    fn link(&mut self) {
        let up = self.ack_sent
            && self.ctl.as_ref().is_some_and(|s| s.is_ready())
            && self.bulk.as_ref().is_some_and(|s| s.is_ready());
        self.engine.set_connected(up);
    }

    fn send(&mut self, rid: u32, m: &Message) {
        let ch = Channel::from_link(m.channel());
        let s = match ch {
            Channel::Ctl => self.ctl.as_mut(),
            Channel::Bulk => self.bulk.as_mut(),
        };
        if let Some(s) = s.filter(|s| s.is_ready()) {
            let b = s.send(rid, m).unwrap();
            self.out.push_back((ch, b));
        }
    }

    fn fail(&mut self, ch: Channel) {
        self.closes.push(ch);
        self.closed(ch);
    }

    fn receive(&mut self, ch: Channel, wire: &[u8]) {
        let s = match ch {
            Channel::Ctl => self.ctl.as_mut(),
            Channel::Bulk => self.bulk.as_mut(),
        };
        let Some(s) = s else { return };
        let evs = match s.on_message(wire) {
            Ok(e) => e,
            Err(_) => return self.fail(ch),
        };
        for ev in evs {
            match ev {
                Event::Send(b) => self.out.push_back((ch, b)),
                Event::Established { remote_static } => {
                    if ch == Channel::Ctl {
                        self.helper_key = Some(remote_static);
                    } else {
                        self.link();
                    }
                }
                Event::Sas(sas) => {
                    self.sas = Some(sas);
                    if self.pinned == self.helper_key {
                        self.send(0, &Message::Pairing(PairingStatus::Known));
                        self.paired = true;
                        self.ack();
                    } else {
                        self.send(0, &Message::Pairing(PairingStatus::Confirm));
                        self.awaiting_user = true;
                        if let Some(yes) = self.auto_confirm {
                            self.user_answer(yes);
                        }
                    }
                }
                Event::Message { request_id, msg } => match ch {
                    Channel::Ctl => self.on_ctl(request_id, msg),
                    Channel::Bulk => {
                        assert!(self.engine.handle(&msg));
                    }
                },
            }
        }
    }

    fn user_answer(&mut self, yes: bool) {
        assert!(self.awaiting_user);
        self.awaiting_user = false;
        if yes {
            self.pinned = self.helper_key;
            self.send(0, &Message::Pairing(PairingStatus::Confirmed));
            self.paired = true;
            self.ack();
        } else {
            self.send(0, &Message::Pairing(PairingStatus::Rejected));
            self.send(
                0,
                &Message::Error(ErrorMsg {
                    code: err::PAIRING_REJECTED,
                    message: "rejected".into(),
                }),
            );
            self.fail(Channel::Ctl);
        }
    }

    fn ack(&mut self) {
        let Some(h) = &self.hello else { return };
        if !self.paired || self.ack_sent {
            return;
        }
        let mut caps = h.capabilities & self.user_caps;
        if h.policy & policy::BLOCKS_FILE_TRANSFER != 0 {
            caps &= !(cap::FILE_UP | cap::FILE_DOWN);
        }
        let mut token = [0u8; 32];
        remora_link::random(&mut token).unwrap();
        self.token = Some(token);
        self.send(
            0,
            &Message::HelloAck(HelloAck {
                major: remora_link::PROTO_MAJOR,
                minor: remora_link::PROTO_MINOR,
                capabilities: caps,
                max_message: remora_link::frame::MAX_MESSAGE as u32,
                max_chunk: CHUNK_SIZE,
                window: WINDOW as u32,
                bulk_token: token,
            }),
        );
        self.ack_sent = true;
        self.engine
            .set_permissions(caps & cap::FILE_UP != 0, caps & cap::FILE_DOWN != 0);
        self.link();
    }

    fn on_ctl(&mut self, rid: u32, msg: Message) {
        self.got.push((rid, msg.clone()));
        match msg {
            Message::Hello(h) => {
                self.hello = Some(h);
                self.ack();
            }
            Message::OpenUrl { .. } => {
                if let Some(st) = self.url_answer {
                    self.send(rid, &Message::OpenUrlResult(st));
                }
            }
            m @ (Message::FileOffer(_)
            | Message::FileAccept { .. }
            | Message::FileReject { .. }
            | Message::FileCredit { .. }
            | Message::FileCancel { .. }
            | Message::FileComplete { .. }) => {
                self.engine.handle(&m);
            }
            _ => {}
        }
    }

    /// Engine traffic; accepts every offered file into `dir`.
    fn pump(&mut self) {
        self.engine.poll(1 << 20);
        while let Some(e) = self.engine.next_event() {
            if let TransferEvent::Offered { id, .. } = e {
                self.engine.accept(id, Box::new(self.dir.clone())).unwrap();
            }
        }
        for m in self.engine.take_messages() {
            self.send(0, &m);
        }
    }

    fn got_types(&self) -> Vec<u16> {
        self.got.iter().map(|(_, m)| m.ty()).collect()
    }
}

// ------------------------------------------------------------ the wire

struct Net {
    agent: LinkProtocol,
    ui: UiLog,
    files_dir: MemDir,
    remora: Remora,
    now: Instant,
    open: [bool; 2],
    pending: VecDeque<AgentEvent>,
    url_results: Vec<(u64, UrlOutcome)>,
    send_results: Vec<(u64, SendOutcome)>,
    /// Channels the agent closed.
    agent_closes: Vec<Channel>,
    opens_requested: Vec<Channel>,
    /// Count of Bulk messages delivered; past `cut_after` the wire drops all.
    bulk_seen: usize,
    cut_after: Option<usize>,
}

impl Net {
    fn new(remora: Remora, sources: BTreeMap<PathBuf, (Vec<u8>, u64)>) -> Net {
        let ui = UiLog::default();
        let files_dir = MemDir::new();
        let files = MemFiles {
            dir: files_dir.clone(),
            sources,
        };
        let agent = LinkProtocol::new(
            StaticKey::generate().unwrap(),
            Box::new(ui.clone()),
            Box::new(files),
        );
        Net {
            agent,
            ui,
            files_dir,
            remora,
            now: Instant::now(),
            open: [false; 2],
            pending: VecDeque::new(),
            url_results: Vec::new(),
            send_results: Vec::new(),
            agent_closes: Vec::new(),
            opens_requested: Vec::new(),
            bulk_seen: 0,
            cut_after: None,
        }
    }

    fn cut(&self) -> bool {
        self.cut_after.is_some_and(|n| self.bulk_seen >= n)
    }

    fn agent_event(&mut self, ev: AgentEvent) {
        self.pending.push_back(ev);
        self.settle();
    }

    fn apply(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(ch, b) => {
                    if !self.open[ch.index()] || self.cut() {
                        continue;
                    }
                    if ch == Channel::Bulk {
                        self.bulk_seen += 1;
                    }
                    self.remora.receive(ch, &b);
                }
                Action::Close(ch) => {
                    self.agent_closes.push(ch);
                    if self.open[ch.index()] {
                        self.open[ch.index()] = false;
                        self.remora.closed(ch);
                    }
                }
                Action::OpenChannel(ch) => {
                    self.opens_requested.push(ch);
                    self.open[ch.index()] = true;
                    self.remora.open(ch);
                    if self.remora.closes.last() == Some(&ch) && self.remora.bulk.is_none() {
                        self.open[ch.index()] = false;
                        self.pending.push_back(AgentEvent::ChannelClosed(ch));
                    } else {
                        self.pending.push_back(AgentEvent::ChannelOpened(ch));
                    }
                }
                Action::OpenUrlResult { id, outcome } => self.url_results.push((id, outcome)),
                Action::SendFilesResult { id, outcome } => self.send_results.push((id, outcome)),
            }
        }
    }

    fn settle(&mut self) {
        for _ in 0..200_000 {
            if let Some(ev) = self.pending.pop_front() {
                let a = self.agent.on_event_at(ev, self.now);
                self.apply(a);
                continue;
            }
            // What Remora sent before closing arrives before the close.
            if let Some((ch, b)) = self.remora.out.pop_front() {
                if self.open[ch.index()] && !self.cut() {
                    if ch == Channel::Bulk {
                        self.bulk_seen += 1;
                    }
                    self.pending.push_back(AgentEvent::Message(ch, b));
                }
                continue;
            }
            // Remora closed a channel: the agent sees it close.
            let closes: Vec<Channel> = std::mem::take(&mut self.remora.closes);
            let mut any = false;
            for ch in closes {
                if self.open[ch.index()] {
                    self.open[ch.index()] = false;
                    self.pending.push_back(AgentEvent::ChannelClosed(ch));
                    any = true;
                }
            }
            if any {
                continue;
            }
            self.remora.pump();
            if !self.remora.out.is_empty() {
                continue;
            }
            return;
        }
        panic!("the conversation did not settle");
    }

    /// Time passes; the agent's timer fires.
    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.agent_event(AgentEvent::Timer);
    }

    fn connect(&mut self, info: SessionInfo) {
        self.open[Channel::Ctl.index()] = true;
        self.remora.open(Channel::Ctl);
        self.pending
            .push_back(AgentEvent::ChannelOpened(Channel::Ctl));
        self.pending.push_back(AgentEvent::SessionInfoTick(info));
        self.settle();
    }

    /// The local user answers the dialog on the server.
    fn answer_locally(&mut self, yes: bool) {
        let ticket = self
            .agent
            .ctl
            .as_ref()
            .and_then(|c| c.ticket)
            .expect("a dialog is shown");
        assert_eq!(self.ui.last_ticket().or(Some(ticket)), Some(ticket));
        self.agent_event(AgentEvent::PairingAnswer {
            ticket,
            confirmed: yes,
        });
    }

    /// The whole link drops (client disconnect): both sides see it.
    fn drop_link(&mut self) {
        self.cut_after = None;
        self.remora.out.clear();
        for ch in [Channel::Bulk, Channel::Ctl] {
            if self.open[ch.index()] {
                self.open[ch.index()] = false;
                self.remora.closed(ch);
                self.pending.push_back(AgentEvent::ChannelClosed(ch));
            }
        }
        self.settle();
    }

    /// Lets the Bulk link come up past the agent's grace.
    fn grace(&mut self) {
        self.advance(LINK_GRACE);
    }
}

fn paired_net(remora: Remora) -> Net {
    let mut n = Net::new(remora, BTreeMap::new());
    n.connect(snapshot(PolicyFlags::default()));
    n
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

// ------------------------------------------------------------ tests

#[test]
fn first_contact_shows_the_same_code_and_needs_both_confirmations() {
    let mut n = paired_net(Remora::new());
    let ui = n.ui.take();
    let remora_sas = n.remora.sas.expect("Remora has a SAS");
    assert_eq!(n.agent.ctl.as_ref().unwrap().sas, Some(remora_sas));
    assert!(
        matches!(ui.as_slice(), [Ui::Show(_, s)] if *s == remora_sas),
        "{ui:?}"
    );
    // Remora confirmed and sent HelloAck; the dialog here stays open.
    assert!(n.remora.ack_sent);
    assert!(n.agent.acked().is_some());
    assert!(!n.agent.server_to_client_allowed());
    // Hello carried the session facts.
    let hello = n.remora.hello.clone().unwrap();
    assert_eq!(hello.capabilities, cap::ALL);
    assert_eq!(hello.policy, 0);
    assert_eq!(hello.os_build, 26100);
    assert_eq!(hello.session_kind, WireKind::RemoteApp);
    assert_eq!(hello.helper_version, "9.9.9-test");
    // Bulk opened and is bound, but no file data moves before the answer.
    assert_eq!(n.opens_requested, vec![Channel::Bulk]);
    assert!(n.agent.bulk_ready());
    assert!(n.remora.bulk.as_ref().unwrap().is_ready());
    n.grace();
    assert!(!n.agent.engine.is_connected());
    // Now the user confirms on the server too.
    n.answer_locally(true);
    assert_eq!(n.ui.take(), vec![Ui::Close]);
    assert!(n.agent.server_to_client_allowed());
    n.grace();
    assert!(n.agent.engine.is_connected());
}

#[test]
fn transfer_link_waits_for_the_grace() {
    let mut r = Remora::new();
    r.auto_confirm = Some(true);
    let mut n = paired_net(r);
    n.answer_locally(true);
    assert!(n.agent.bulk_ready());
    assert!(!n.agent.engine.is_connected(), "not before the grace");
    assert!(n.agent.next_deadline().unwrap() <= n.now + LINK_GRACE);
    n.advance(LINK_GRACE / 2);
    assert!(!n.agent.engine.is_connected());
    n.advance(LINK_GRACE / 2);
    assert!(n.agent.engine.is_connected());
}

#[test]
fn known_key_shows_nothing_and_blocks_server_to_client_data() {
    let mut r = Remora::new();
    r.auto_confirm = Some(true);
    let mut n = paired_net(r);
    n.answer_locally(true);
    n.drop_link();
    n.ui.take();
    // Reconnect: Remora knows the key now.
    n.connect(snapshot(PolicyFlags::default()));
    assert!(n.ui.take().is_empty(), "no dialog for a known key");
    assert!(n.agent.acked().is_some());
    assert!(!n.agent.server_to_client_allowed());
    // Links and downloads are refused locally; nothing goes to Remora.
    let before = n.remora.got.len();
    n.agent_event(AgentEvent::OpenUrl {
        id: 7,
        url: "https://e.example/".into(),
    });
    n.agent_event(AgentEvent::SendFiles {
        id: 8,
        paths: vec![PathBuf::from(r"C:\x.bin")],
    });
    assert_eq!(n.url_results, vec![(7, UrlOutcome::NoClient)]);
    assert_eq!(n.send_results, vec![(8, SendOutcome::NoClient)]);
    assert!(
        !n.remora.got[before..]
            .iter()
            .any(|(_, m)| matches!(m, Message::OpenUrl { .. } | Message::FileOffer(_)))
    );
    // Session info still flows.
    n.agent_event(AgentEvent::SessionInfoTick(
        snapshot(PolicyFlags::default()),
    ));
    assert!(matches!(
        n.remora.got.last(),
        Some((_, Message::SessionInfo(_)))
    ));
}

#[test]
fn rejection_on_either_side_closes() {
    // Remora's user rejects.
    let mut r = Remora::new();
    r.auto_confirm = Some(false);
    let n = paired_net(r);
    assert!(n.agent.ctl.is_none());
    assert_eq!(n.ui.take().last(), Some(&Ui::Close));
    assert!(!n.open[Channel::Ctl.index()]);
    assert!(n.opens_requested.is_empty(), "no Bulk");

    // The user on the server rejects.
    let mut r = Remora::new();
    r.auto_confirm = None;
    let mut n = paired_net(r);
    assert!(matches!(n.ui.take().as_slice(), [Ui::Show(..)]));
    n.answer_locally(false);
    assert_eq!(n.ui.take(), vec![Ui::Close]);
    assert!(n.agent_closes.contains(&Channel::Ctl));
    assert!(n.agent.ctl.is_none());
    assert!(
        n.remora
            .got
            .iter()
            .any(|(_, m)| matches!(m, Message::Error(e) if e.code == err::PAIRING_REJECTED))
    );
    // A stale answer for the old dialog changes nothing.
    n.connect(snapshot(PolicyFlags::default()));
    n.agent_event(AgentEvent::PairingAnswer {
        ticket: 1,
        confirmed: true,
    });
    assert!(!n.agent.server_to_client_allowed());
}

#[test]
fn policy_turns_file_capabilities_off() {
    let mut n = Net::new(Remora::new(), BTreeMap::new());
    n.connect(snapshot(PolicyFlags {
        clipboard_disabled: true,
        drives_disabled: false,
    }));
    n.answer_locally(true);
    let hello = n.remora.hello.clone().unwrap();
    assert_eq!(hello.capabilities, cap::SESSION_INFO | cap::OPEN_URL);
    assert_eq!(hello.policy, policy::CLIPBOARD_DISABLED);
    assert!(n.opens_requested.is_empty(), "no Bulk without file caps");
    n.agent_event(AgentEvent::SendFiles {
        id: 1,
        paths: vec![PathBuf::from(r"C:\x")],
    });
    assert_eq!(n.send_results, vec![(1, SendOutcome::NoClient)]);

    // Policy switched on mid-session: Bulk closes, rights go.
    let mut n = paired_net(Remora::new());
    n.answer_locally(true);
    assert!(n.agent.bulk_ready());
    n.agent_event(AgentEvent::SessionInfoTick(snapshot(PolicyFlags {
        clipboard_disabled: false,
        drives_disabled: true,
    })));
    assert!(n.agent_closes.contains(&Channel::Bulk));
    assert_eq!(n.agent.file_rights(), (false, false));
}

#[test]
fn session_info_and_heartbeats_flow_once_accepted() {
    let mut r = Remora::new();
    r.user_caps = cap::SESSION_INFO;
    let mut n = paired_net(r);
    n.agent_event(AgentEvent::SessionInfoTick(
        snapshot(PolicyFlags::default()),
    ));
    let info = n
        .remora
        .got
        .iter()
        .rev()
        .find_map(|(_, m)| match m {
            Message::SessionInfo(i) => Some(i.clone()),
            _ => None,
        })
        .expect("SessionInfo sent");
    assert_eq!(
        info,
        WireInfo {
            locked: true,
            idle_ms: 1234,
            cpu_percent: 42,
            mem_used: 5 << 30,
            mem_total: 8 << 30,
        }
    );
    let beats = |n: &Net| {
        n.remora
            .got_types()
            .iter()
            .filter(|&&t| t == 0x0102)
            .count()
    };
    assert_eq!(beats(&n), 0);
    n.advance(HEARTBEAT);
    assert_eq!(beats(&n), 1);
    n.advance(HEARTBEAT / 2);
    assert_eq!(beats(&n), 1);
    n.advance(HEARTBEAT / 2);
    assert_eq!(beats(&n), 2);
    // Not accepted: no SessionInfo.
    let mut r = Remora::new();
    r.user_caps = cap::OPEN_URL;
    let mut n = paired_net(r);
    n.agent_event(AgentEvent::SessionInfoTick(
        snapshot(PolicyFlags::default()),
    ));
    assert!(!n.remora.got_types().contains(&0x0200));
}

#[test]
fn open_url_round_trip_timeout_and_refusals() {
    // Before pairing or without the capability: NoClient, nothing sent.
    let mut n = Net::new(Remora::new(), BTreeMap::new());
    n.agent_event(AgentEvent::OpenUrl {
        id: 1,
        url: "https://e.example/".into(),
    });
    assert_eq!(n.url_results, vec![(1, UrlOutcome::NoClient)]);

    let mut n = paired_net(Remora::new());
    n.answer_locally(true);
    n.agent_event(AgentEvent::OpenUrl {
        id: 2,
        url: "https://e.example/a".into(),
    });
    assert_eq!(n.url_results, vec![(2, UrlOutcome::Forwarded)]);
    let (rid, m) = n
        .remora
        .got
        .iter()
        .rev()
        .find(|(_, m)| m.ty() == 0x0300)
        .unwrap();
    assert_ne!(*rid, 0);
    assert_eq!(
        *m,
        Message::OpenUrl {
            url: "https://e.example/a".into()
        }
    );

    // Remora asks its user (no answer yet): forwarded after the wait.
    n.remora.url_answer = None;
    n.url_results.clear();
    n.agent_event(AgentEvent::OpenUrl {
        id: 3,
        url: "https://e.example/b".into(),
    });
    assert!(n.url_results.is_empty());
    assert!(n.agent.next_deadline().unwrap() <= n.now + URL_ANSWER_WAIT);
    n.advance(URL_ANSWER_WAIT);
    assert_eq!(n.url_results, vec![(3, UrlOutcome::Forwarded)]);

    // Disabled in Remora: the local fallback runs.
    n.remora.url_answer = Some(UrlStatus::Disabled);
    n.url_results.clear();
    n.agent_event(AgentEvent::OpenUrl {
        id: 4,
        url: "https://e.example/c".into(),
    });
    assert_eq!(n.url_results, vec![(4, UrlOutcome::NoClient)]);

    // A pending link is answered when the channel goes.
    n.remora.url_answer = None;
    n.url_results.clear();
    n.agent_event(AgentEvent::OpenUrl {
        id: 5,
        url: "https://e.example/d".into(),
    });
    n.drop_link();
    assert_eq!(n.url_results, vec![(5, UrlOutcome::NoClient)]);

    // Not accepted by Remora.
    let mut r = Remora::new();
    r.user_caps = cap::SESSION_INFO;
    let mut n = paired_net(r);
    n.answer_locally(true);
    n.agent_event(AgentEvent::OpenUrl {
        id: 6,
        url: "https://e.example/".into(),
    });
    assert_eq!(n.url_results, vec![(6, UrlOutcome::NoClient)]);
}

#[test]
fn upload_survives_a_drop_and_resumes() {
    let mut n = paired_net(Remora::new());
    n.answer_locally(true);
    n.grace();
    let file = data(BLOCK_SIZE as usize + 700_000, 3);
    // Remora sends a file to the server.
    n.remora
        .engine
        .send(
            "report.pdf",
            Box::new(MemSource::new(file.clone(), 1_700_000_000_000)),
        )
        .unwrap();
    // The wire dies after the first block and some of the second.
    n.cut_after = Some(20);
    n.settle();
    assert!(n.files_dir.get("report.pdf").is_none());
    assert!(n.files_dir.get("report.pdf.remora-part").is_some());
    n.drop_link();
    // Reconnect: known key, the transfer resumes at the verified block.
    n.connect(snapshot(PolicyFlags::default()));
    n.grace();
    for _ in 0..10 {
        n.advance(POLL_INTERVAL);
    }
    assert!(
        n.files_dir.get("report.pdf") == Some(file),
        "stored file differs; folder has {:?}",
        n.files_dir.names()
    );
    assert!(n.files_dir.get("report.pdf.remora-part").is_none());
    assert_eq!(n.files_dir.finished_names(), vec!["report.pdf".to_string()]);
    // The agent restarted the second session at 4 MiB, not at 0.
    assert!(n.remora.got.iter().any(|(_, m)| matches!(
        m,
        Message::FileAccept { offset, .. } if *offset == u64::from(BLOCK_SIZE)
    )));
}

#[test]
fn upload_offered_before_the_link_is_up_waits_and_completes() {
    // Remora's link is up as soon as its Bulk is; ours waits for the
    // answer on the server and the grace. A new offer in that window must
    // not end up accepted-but-paused.
    let mut n = paired_net(Remora::new());
    assert!(n.remora.engine.is_connected());
    assert!(!n.agent.engine.is_connected());
    let file = data(700_000, 5);
    n.remora
        .engine
        .send("early.txt", Box::new(MemSource::new(file.clone(), 9)))
        .unwrap();
    n.settle();
    assert_eq!(n.agent.held_offers.len(), 1);
    assert!(n.files_dir.names().is_empty(), "nothing written yet");
    n.answer_locally(true);
    n.grace();
    for _ in 0..5 {
        n.advance(POLL_INTERVAL);
    }
    assert!(n.agent.held_offers.is_empty());
    assert!(
        n.files_dir.get("early.txt") == Some(file),
        "folder has {:?}",
        n.files_dir.names()
    );
}

#[test]
fn download_survives_a_drop_and_resumes() {
    let file = data(BLOCK_SIZE as usize + 300_000, 9);
    let mut sources = BTreeMap::new();
    sources.insert(PathBuf::from(r"C:\Users\u\big.iso"), (file.clone(), 42));
    sources.insert(PathBuf::from(r"C:\Users\u\x.remora-part"), (vec![1], 1));
    let mut n = Net::new(Remora::new(), sources);
    n.connect(snapshot(PolicyFlags::default()));
    n.answer_locally(true);
    n.grace();
    n.cut_after = Some(20);
    n.agent_event(AgentEvent::SendFiles {
        id: 11,
        paths: vec![
            PathBuf::from(r"C:\Users\u\big.iso"),
            PathBuf::from(r"C:\Users\u\missing.txt"),
            PathBuf::from(r"C:\Users\u\x.remora-part"),
        ],
    });
    assert_eq!(
        n.send_results,
        vec![(
            11,
            SendOutcome::Offered {
                offered: 1,
                failed: 2
            }
        )]
    );
    assert!(n.remora.dir.get("big.iso.remora-part").is_some());
    n.drop_link();
    // A new Ctl session must be confirmed on the server again before the
    // download continues (Known is not enough for server-to-client data).
    n.remora.pinned = None;
    n.connect(snapshot(PolicyFlags::default()));
    n.answer_locally(true);
    n.grace();
    for _ in 0..10 {
        n.advance(POLL_INTERVAL);
    }
    assert!(
        n.remora.dir.get("big.iso") == Some(file),
        "stored file differs; folder has {:?}",
        n.remora.dir.names()
    );
    assert!(n.remora.dir.get("big.iso.remora-part").is_none());
}

#[test]
fn known_reconnect_cancels_pending_downloads() {
    let file = data(300_000, 1);
    let mut sources = BTreeMap::new();
    sources.insert(PathBuf::from(r"C:\a.bin"), (file, 5));
    let mut n = Net::new(Remora::new(), sources);
    n.connect(snapshot(PolicyFlags::default()));
    n.answer_locally(true);
    n.cut_after = Some(0);
    n.agent_event(AgentEvent::SendFiles {
        id: 1,
        paths: vec![PathBuf::from(r"C:\a.bin")],
    });
    assert_eq!(n.agent.engine.active(), 1);
    n.drop_link();
    n.connect(snapshot(PolicyFlags::default()));
    n.grace();
    // Known pairing: the queued download is dropped, never re-offered.
    assert_eq!(n.agent.engine.active(), 0);
    assert!(n.remora.dir.get("a.bin").is_none());
}

#[test]
fn unknown_and_misdirected_messages() {
    let mut n = paired_net(Remora::new());
    let mut out = Vec::new();
    n.agent
        .on_ctl_msg(0, Message::Unknown { ty: 0x0777 }, n.now, &mut out);
    n.apply(out);
    n.settle();
    assert!(matches!(
        n.remora.got.last(),
        Some((_, Message::Unsupported { ty: 0x0777 }))
    ));
    assert!(n.agent.ctl.is_some(), "an unknown type never closes");
    // A helper-to-Remora type coming back: an error, the channel stays.
    let mut out = Vec::new();
    n.agent.on_ctl_msg(
        0,
        Message::OpenUrl {
            url: "https://x.example/".into(),
        },
        n.now,
        &mut out,
    );
    n.apply(out);
    assert!(matches!(
        n.remora.got.last(),
        Some((_, Message::Error(e))) if e.code == err::PROTOCOL
    ));
    assert!(n.agent.ctl.is_some());
}

#[test]
fn garbage_closes_ctl_and_bulk() {
    let mut n = paired_net(Remora::new());
    assert!(n.agent.bulk_ready());
    n.agent_event(AgentEvent::Message(Channel::Ctl, vec![0u8; 64]));
    assert!(n.agent_closes.contains(&Channel::Ctl));
    assert!(n.agent_closes.contains(&Channel::Bulk));
    assert!(n.agent.ctl.is_none() && n.agent.bulk.is_none());
    assert_eq!(n.ui.take().last(), Some(&Ui::Close));
}

#[test]
fn bulk_open_without_pairing_is_closed() {
    let mut n = Net::new(Remora::new(), BTreeMap::new());
    let a = n
        .agent
        .on_event_at(AgentEvent::ChannelOpened(Channel::Bulk), n.now);
    assert_eq!(a, vec![Action::Close(Channel::Bulk)]);
}

#[test]
fn second_ctl_open_restarts_cleanly() {
    let mut n = paired_net(Remora::new());
    n.answer_locally(true);
    assert!(n.agent.bulk_ready());
    let first_key = n.agent.ctl.as_ref().unwrap().remora_key;
    // The client's Ctl reopens (a new client) without a close first.
    n.remora.key = StaticKey::generate().unwrap();
    n.agent_closes.clear();
    n.opens_requested.clear();
    n.open[Channel::Bulk.index()] = false;
    n.remora.closed(Channel::Bulk);
    n.connect(snapshot(PolicyFlags::default()));
    assert!(n.agent_closes.contains(&Channel::Bulk), "old Bulk closed");
    let ctl = n.agent.ctl.as_ref().unwrap();
    assert_ne!(ctl.remora_key, first_key);
    assert!(ctl.ack.is_some(), "paired again");
    assert!(!ctl.local_confirmed, "confirmation is per session");
    assert_eq!(n.opens_requested, vec![Channel::Bulk]);
    assert!(n.agent.bulk_ready());
}

#[test]
fn bulk_binding_refuses_another_remora_key() {
    let mut n = paired_net(Remora::new());
    n.answer_locally(true);
    // Bulk reopened by someone with a different key and the right token.
    n.open[Channel::Bulk.index()] = false;
    n.remora.closed(Channel::Bulk);
    n.agent_event(AgentEvent::ChannelClosed(Channel::Bulk));
    let real = n.remora.key.clone();
    n.remora.key = StaticKey::generate().unwrap();
    n.agent_closes.clear();
    n.open[Channel::Bulk.index()] = true;
    n.remora.open(Channel::Bulk);
    n.agent_event(AgentEvent::ChannelOpened(Channel::Bulk));
    assert!(n.agent_closes.contains(&Channel::Bulk));
    assert!(!n.agent.bulk_ready());
    n.remora.key = real;
}

#[test]
fn hello_waits_for_the_first_snapshot() {
    let mut n = Net::new(Remora::new(), BTreeMap::new());
    n.open[Channel::Ctl.index()] = true;
    n.remora.open(Channel::Ctl);
    n.agent_event(AgentEvent::ChannelOpened(Channel::Ctl));
    assert!(n.remora.sas.is_some());
    assert!(n.remora.hello.is_none());
    n.agent_event(AgentEvent::SessionInfoTick(
        snapshot(PolicyFlags::default()),
    ));
    assert!(n.remora.hello.is_some());
    assert!(n.remora.ack_sent);
}

#[test]
fn wire_info_bounds() {
    let mut i = snapshot(PolicyFlags::default());
    i.cpu_percent = Some(f32::NAN);
    i.idle_ms = Some(u64::MAX);
    i.locked = None;
    i.memory = None;
    let w = wire_info(&i);
    assert_eq!(
        (w.cpu_percent, w.idle_ms, w.locked, w.mem_total),
        (0, u32::MAX, false, 0)
    );
    i.cpu_percent = Some(250.0);
    assert_eq!(wire_info(&i).cpu_percent, 100);
}
