//! The client adapter against a simulated helper built from remora-link.

use super::*;
use remora_link::msg::SessionKind;
use remora_link::transfer::Engine;
use remora_link::transfer::io::MemSource;

/// The helper side of one channel, driven by hand.
struct FakeHelper {
    ctl: SecureSession,
    bulk: Option<SecureSession>,
    key: StaticKey,
    /// Decoded messages the client sent on Ctl / Bulk.
    got: Vec<Message>,
    sas: Option<Sas>,
}

struct Rig {
    handle: HelperHandle,
    ctl: Box<dyn DynamicChannel>,
    bulk: Box<dyn DynamicChannel>,
    dir: PathBuf,
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "remora-helper-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

impl Rig {
    fn new(tag: &str) -> Rig {
        let handle = HelperHandle::new();
        let dir = temp_dir(tag);
        handle.set_server("server:3389".into(), Some(dir.join("helpers.json")));
        let mut ch = handle.channels();
        let bulk = ch.pop().unwrap();
        let ctl = ch.pop().unwrap();
        Rig {
            handle,
            ctl,
            bulk,
            dir,
        }
    }

    /// Opens Ctl and runs the handshake with `key`. Returns the helper.
    fn connect(&mut self, key: StaticKey) -> FakeHelper {
        let mut out = DvcOut::default();
        self.ctl.opened(&mut out).unwrap();
        assert!(out.is_empty());
        let (ctl, first) =
            SecureSession::initiator(Channel::Ctl, &key, Binding::default()).unwrap();
        let mut h = FakeHelper {
            ctl,
            bulk: None,
            key,
            got: Vec::new(),
            sas: None,
        };
        self.exchange(&mut h, Channel::Ctl, vec![first]);
        h
    }

    /// Delivers helper messages to the client and the answers back, until quiet.
    fn exchange(&mut self, h: &mut FakeHelper, ch: Channel, mut msgs: Vec<Vec<u8>>) {
        for _ in 0..50 {
            let mut out = DvcOut::default();
            let chan = match ch {
                Channel::Ctl => &mut self.ctl,
                Channel::Bulk => &mut self.bulk,
            };
            for m in msgs.drain(..) {
                chan.process(&m, &mut out).unwrap();
            }
            chan.tick(&mut out).unwrap();
            let answers = out.take();
            if answers.is_empty() {
                return;
            }
            for a in answers {
                let sess = match ch {
                    Channel::Ctl => &mut h.ctl,
                    Channel::Bulk => h.bulk.as_mut().unwrap(),
                };
                for ev in sess.on_message(&a).unwrap() {
                    match ev {
                        Event::Send(b) => msgs.push(b),
                        Event::Sas(s) => h.sas = Some(s),
                        Event::Message { msg, .. } => h.got.push(msg),
                        Event::Established { .. } => {}
                    }
                }
            }
        }
        panic!("no quiet point");
    }

    /// Runs Ctl and Bulk ticks and moves everything until quiet.
    fn pump(&mut self, h: &mut FakeHelper) {
        self.exchange(h, Channel::Ctl, vec![]);
        if h.bulk.is_some() {
            self.exchange(h, Channel::Bulk, vec![]);
        }
        self.exchange(h, Channel::Ctl, vec![]);
    }

    fn send(&mut self, h: &mut FakeHelper, msg: Message) {
        let ch = msg.channel();
        let wire = match ch {
            Channel::Ctl => h.ctl.send(1, &msg).unwrap(),
            Channel::Bulk => h.bulk.as_mut().unwrap().send(1, &msg).unwrap(),
        };
        self.exchange(h, ch, vec![wire]);
    }

    fn events(&self) -> Vec<HelperEvent> {
        std::iter::from_fn(|| self.handle.next_event()).collect()
    }

    /// Ctl paired and HelloAck received; returns the HelloAck.
    fn pair_and_hello(&mut self, h: &mut FakeHelper, offer: u32, policy_bits: u32) -> HelloAck {
        if matches!(self.handle.state(), HelperState::AwaitingPairing { .. }) {
            self.handle.confirm_pairing(shown(&self.handle)).unwrap();
            self.pump(h);
        }
        self.send(h, hello(offer, policy_bits));
        h.got
            .iter()
            .find_map(|m| match m {
                Message::HelloAck(a) => Some(a.clone()),
                _ => None,
            })
            .expect("HelloAck")
    }

    fn open_bulk(&mut self, h: &mut FakeHelper, token: [u8; 32]) {
        let mut out = DvcOut::default();
        self.bulk.opened(&mut out).unwrap();
        let (bulk, first) = SecureSession::initiator(
            Channel::Bulk,
            &h.key,
            Binding {
                bulk_token: Some(token),
                expected_remote: None,
            },
        )
        .unwrap();
        h.bulk = Some(bulk);
        self.exchange(h, Channel::Bulk, vec![first]);
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The code the pairing dialog shows now.
fn shown(h: &HelperHandle) -> Sas {
    match h.state() {
        HelperState::AwaitingPairing { sas, .. } => sas,
        s => panic!("no pairing: {s:?}"),
    }
}

fn hello(caps: u32, policy_bits: u32) -> Message {
    Message::Hello(Hello {
        major: 1,
        minor: 0,
        helper_version: "0.1.0".into(),
        os_build: 26100,
        session_kind: SessionKind::Desktop,
        capabilities: caps,
        policy: policy_bits,
    })
}

#[test]
fn nothing_is_answered_before_the_connection_is_known_to_be_tls() {
    let mut r = Rig::new("tls-wait");
    let key = StaticKey::generate().unwrap();
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out).unwrap();
    let (_s, first) = SecureSession::initiator(Channel::Ctl, &key, Binding::default()).unwrap();
    r.ctl.process(&first, &mut out).unwrap();
    r.ctl.tick(&mut out).unwrap();
    assert!(out.is_empty(), "no answer while the transport is unknown");
    // TLS confirmed: the buffered handshake is answered.
    r.handle.set_transport_protocol(1);
    r.ctl.tick(&mut out).unwrap();
    assert_eq!(out.take().len(), 1, "handshake message 2");
}

#[test]
fn a_connection_without_tls_closes_the_helper_channels() {
    let mut r = Rig::new("no-tls");
    let key = StaticKey::generate().unwrap();
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out).unwrap();
    let (_s, first) = SecureSession::initiator(Channel::Ctl, &key, Binding::default()).unwrap();
    r.ctl.process(&first, &mut out).unwrap();
    r.handle.set_transport_protocol(0); // PROTOCOL_RDP
    assert!(r.ctl.tick(&mut out).is_err(), "closed");
    assert!(out.is_empty(), "never answered");
    // A later open is refused at once.
    assert!(r.ctl.opened(&mut out).is_err());
}

#[test]
fn switched_off_refuses_the_channel() {
    let mut r = Rig::new("off");
    r.handle.set_enabled(false);
    let mut out = DvcOut::default();
    assert!(r.ctl.opened(&mut out).is_err());
}

#[test]
fn first_contact_needs_the_sas_then_pins_the_key() {
    let mut r = Rig::new("pair");
    r.handle.set_transport_protocol(1);
    let key = StaticKey::generate().unwrap();
    let mut h = r.connect(key.clone());
    let state = r.handle.state();
    let HelperState::AwaitingPairing {
        sas,
        changed,
        fingerprint,
    } = state
    else {
        panic!("{state:?}")
    };
    assert!(!changed);
    assert_eq!(fingerprint, remora_link::fingerprint(&key.public()));
    assert_eq!(Some(sas), h.sas, "both ends show the same SAS");
    assert!(h.got.contains(&Message::Pairing(PairingStatus::Confirm)));
    // The helper's Hello waits for the user; no HelloAck yet.
    r.send(&mut h, hello(cap::ALL, 0));
    assert!(!h.got.iter().any(|m| matches!(m, Message::HelloAck(_))));
    r.handle.confirm_pairing(shown(&r.handle)).unwrap();
    r.pump(&mut h);
    assert!(h.got.contains(&Message::Pairing(PairingStatus::Confirmed)));
    let ack = h
        .got
        .iter()
        .find_map(|m| match m {
            Message::HelloAck(a) => Some(a.clone()),
            _ => None,
        })
        .unwrap();
    // Default user setting: session info only.
    assert_eq!(ack.capabilities, cap::SESSION_INFO);
    assert_eq!(r.handle.state(), HelperState::Paired);
    let pins = PinStore::load(&r.dir.join("helpers.json")).unwrap();
    assert_eq!(pins.check("server:3389", &key.public()), PinCheck::Known);

    // A second session with the same helper key pairs silently.
    let mut r2 = Rig::new("pair-2");
    std::fs::copy(r.dir.join("helpers.json"), r2.dir.join("helpers.json")).unwrap();
    r2.handle.set_transport_protocol(1);
    let mut h2 = r2.connect(key);
    assert!(h2.got.contains(&Message::Pairing(PairingStatus::Known)));
    assert_eq!(r2.handle.state(), HelperState::Paired);
    r2.send(&mut h2, hello(cap::ALL, 0));
    assert!(h2.got.iter().any(|m| matches!(m, Message::HelloAck(_))));
}

#[test]
fn a_reconnect_keeps_transfers_and_retires_the_old_channels() {
    let mut r = Rig::new("reattach");
    r.handle.set_transport_protocol(1);
    r.handle.set_capabilities(cap::ALL);
    let key = StaticKey::generate().unwrap();
    let mut h = r.connect(key.clone());
    let ack = r.pair_and_hello(&mut h, cap::ALL, 0);
    r.open_bulk(&mut h, ack.bulk_token);
    let src = r.dir.join("upload.bin");
    std::fs::write(&src, vec![7u8; 1000]).unwrap();
    let id = r.handle.send_file(&src).unwrap();
    r.pump(&mut h);
    assert!(
        h.got
            .iter()
            .any(|m| matches!(m, Message::FileOffer(o) if o.id == id))
    );
    r.events();

    // The RDP connection drops and the tab reconnects.
    let mut fresh = r.handle.reattach();
    let new_bulk = fresh.pop().unwrap();
    let new_ctl = fresh.pop().unwrap();
    let mut old_ctl = std::mem::replace(&mut r.ctl, new_ctl);
    let mut old_bulk = std::mem::replace(&mut r.bulk, new_bulk);
    let ev = r.events();
    assert!(ev.contains(&HelperEvent::State(HelperState::NotPresent)));
    assert_eq!(r.handle.accepted_capabilities(), 0);
    // The old connection's handlers are retired: whatever its thread still
    // does cannot touch the new connection.
    let mut out = DvcOut::default();
    assert!(old_ctl.process(&[0; 8], &mut out).is_err());
    assert!(old_ctl.opened(&mut out).is_err());
    old_ctl.closed();
    old_bulk.closed();
    assert!(out.is_empty());

    // Nothing is answered on the new connection before its TLS check.
    r.handle.set_transport_protocol(1);
    let mut h2 = r.connect(key);
    assert!(h2.got.contains(&Message::Pairing(PairingStatus::Known)));
    let ack2 = r.pair_and_hello(&mut h2, cap::ALL, 0);
    assert_ne!(ack2.bulk_token, ack.bulk_token);
    r.open_bulk(&mut h2, ack2.bulk_token);
    r.pump(&mut h2);
    // The same transfer is offered again (same id): the receiver resumes it.
    assert!(
        h2.got
            .iter()
            .any(|m| matches!(m, Message::FileOffer(o) if o.id == id)),
        "{:?}",
        h2.got
    );
}

#[test]
fn a_changed_key_warns_and_reject_closes() {
    let mut r = Rig::new("changed");
    let mut pins = PinStore::new();
    pins.pin("server:3389", &[7; 32], 1);
    pins.save(&r.dir.join("helpers.json")).unwrap();
    r.handle.set_transport_protocol(1);
    let mut h = r.connect(StaticKey::generate().unwrap());
    assert!(matches!(
        r.handle.state(),
        HelperState::AwaitingPairing { changed: true, .. }
    ));
    r.handle.reject_pairing(Sas(0));
    assert!(
        matches!(r.handle.state(), HelperState::AwaitingPairing { .. }),
        "another code's answer does nothing"
    );
    r.handle.reject_pairing(shown(&r.handle));
    let mut out = DvcOut::default();
    assert!(r.ctl.tick(&mut out).is_err(), "channel closes");
    for m in out.take() {
        for ev in h.ctl.on_message(&m).unwrap() {
            if let Event::Message { msg, .. } = ev {
                h.got.push(msg);
            }
        }
    }
    assert!(h.got.contains(&Message::Pairing(PairingStatus::Rejected)));
    assert!(matches!(r.handle.state(), HelperState::Failed(_)));
    // The old pin is untouched.
    let pins = PinStore::load(&r.dir.join("helpers.json")).unwrap();
    assert_eq!(pins.check("server:3389", &[7; 32]), PinCheck::Known);
}

#[test]
fn an_unreadable_pin_store_is_treated_as_changed() {
    let mut r = Rig::new("bad-store");
    std::fs::write(r.dir.join("helpers.json"), b"garbage").unwrap();
    r.handle.set_transport_protocol(1);
    let mut h = r.connect(StaticKey::generate().unwrap());
    assert!(matches!(
        r.handle.state(),
        HelperState::AwaitingPairing { changed: true, .. }
    ));
    // The helper knows this PC; confirming here would pin...
    r.send(&mut h, Message::PeerPairing(PairingStatus::Known));
    // ...but does not overwrite the unreadable file.
    assert!(r.handle.confirm_pairing(shown(&r.handle)).is_err());
    assert_eq!(
        std::fs::read(r.dir.join("helpers.json")).unwrap(),
        b"garbage"
    );
    assert_eq!(r.handle.state(), HelperState::Paired);
}

#[test]
fn capabilities_follow_user_setting_and_policy() {
    let mut r = Rig::new("caps");
    r.handle.set_transport_protocol(1);
    r.handle.set_capabilities(cap::ALL);
    r.handle.set_received_file_hook(|_| {});
    let mut h = r.connect(StaticKey::generate().unwrap());
    // Drive clipboard disabled by policy: no file transfer at all.
    let ack = r.pair_and_hello(&mut h, cap::ALL, policy::CLIPBOARD_DISABLED);
    assert_eq!(ack.capabilities, cap::SESSION_INFO | cap::OPEN_URL);
    assert_eq!(r.handle.accepted_capabilities(), ack.capabilities);
}

#[test]
fn messages_before_pairing_are_refused() {
    let mut r = Rig::new("early");
    r.handle.set_transport_protocol(1);
    let mut h = r.connect(StaticKey::generate().unwrap());
    r.send(
        &mut h,
        Message::OpenUrl {
            url: "https://example.org".into(),
        },
    );
    assert!(
        h.got
            .iter()
            .any(|m| matches!(m, Message::Error(e) if e.code == err::NOT_ALLOWED))
    );
    assert!(
        !r.events()
            .iter()
            .any(|e| matches!(e, HelperEvent::OpenUrl { .. }))
    );
}

#[test]
fn session_info_unknown_types_and_links() {
    let mut r = Rig::new("msgs");
    r.handle.set_transport_protocol(1);
    r.handle.set_capabilities(cap::SESSION_INFO | cap::OPEN_URL);
    let mut h = r.connect(StaticKey::generate().unwrap());
    r.pair_and_hello(&mut h, cap::ALL, 0);
    let info = SessionInfo {
        locked: true,
        idle_ms: 10,
        cpu_percent: 5,
        mem_used: 1,
        mem_total: 2,
    };
    r.send(&mut h, Message::SessionInfo(info.clone()));
    assert_eq!(r.handle.session_info(), Some(info));
    // A type from a newer helper: answered with Unsupported, the channel
    // stays open. (SecureSession::send cannot encode an unknown type, so the
    // decoded message is handed to the Ctl handler directly.)
    r.handle.lock().on_ctl(0, Message::Unknown { ty: 0x7ABC });
    r.pump(&mut h);
    assert!(h.got.contains(&Message::Unsupported { ty: 0x7ABC }));
    // Links: only http(s) reach the app, the app answers.
    r.send(
        &mut h,
        Message::OpenUrl {
            url: "file:///C:/Windows/System32/calc.exe".into(),
        },
    );
    assert!(h.got.contains(&Message::OpenUrlResult(UrlStatus::Invalid)));
    r.send(
        &mut h,
        Message::OpenUrl {
            url: "https://example.org/a".into(),
        },
    );
    let ev = r.events();
    let (rid, url) = ev
        .iter()
        .find_map(|e| match e {
            HelperEvent::OpenUrl { request_id, url } => Some((*request_id, url.clone())),
            _ => None,
        })
        .unwrap();
    assert_eq!(url, "https://example.org/a");
    r.handle.answer_url(rid, UrlStatus::Opened);
    r.pump(&mut h);
    assert!(h.got.contains(&Message::OpenUrlResult(UrlStatus::Opened)));
}

#[test]
fn bulk_requires_the_paired_helper() {
    // Before pairing: Bulk is refused.
    let mut r = Rig::new("bulk-early");
    r.handle.set_transport_protocol(1);
    let _h = r.connect(StaticKey::generate().unwrap());
    let mut out = DvcOut::default();
    assert!(r.bulk.opened(&mut out).is_err());

    // After pairing, a different helper key on Bulk fails the handshake.
    let mut r = Rig::new("bulk-other");
    r.handle.set_transport_protocol(1);
    let mut h = r.connect(StaticKey::generate().unwrap());
    let ack = r.pair_and_hello(&mut h, cap::ALL, 0);
    let mut out = DvcOut::default();
    r.bulk.opened(&mut out).unwrap();
    let other = StaticKey::generate().unwrap();
    let (mut s, first) = SecureSession::initiator(
        Channel::Bulk,
        &other,
        Binding {
            bulk_token: Some(ack.bulk_token),
            expected_remote: None,
        },
    )
    .unwrap();
    r.bulk.process(&first, &mut out).unwrap();
    let msg2 = out.take();
    let ev = s.on_message(&msg2[0]).unwrap();
    let Some(Event::Send(msg3)) = ev.into_iter().find(|e| matches!(e, Event::Send(_))) else {
        panic!("message 3")
    };
    assert!(r.bulk.process(&msg3, &mut out).is_err(), "wrong helper key");
}

#[test]
fn download_end_to_end_into_the_chosen_folder() {
    let mut r = Rig::new("download");
    r.handle.set_transport_protocol(1);
    r.handle.set_capabilities(cap::ALL);
    let marked = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let m2 = marked.clone();
    let threads = Arc::new(Mutex::new(Vec::<String>::new()));
    let t2 = threads.clone();
    r.handle.set_received_file_hook(move |p| {
        m2.lock().unwrap().push(p.to_path_buf());
        let name = std::thread::current().name().unwrap_or("").to_string();
        t2.lock().unwrap().push(name);
    });
    let mut h = r.connect(StaticKey::generate().unwrap());
    let ack = r.pair_and_hello(&mut h, cap::ALL, 0);
    assert_ne!(ack.capabilities & cap::FILE_DOWN, 0);
    r.open_bulk(&mut h, ack.bulk_token);

    // The helper's own engine sends a 5 MiB file.
    let data: Vec<u8> = (0..5u32 << 20).map(|i| (i * 7) as u8).collect();
    let mut tx = Engine::default();
    tx.set_permissions(true, false);
    tx.set_connected(true);
    let id = tx
        .send("report.bin", Box::new(MemSource::new(data.clone(), 1)))
        .unwrap();
    let downloads = r.dir.join("Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    for _ in 0..200 {
        tx.poll(1 << 20);
        for m in tx.take_messages() {
            r.send(&mut h, m);
        }
        for e in r.events() {
            if let HelperEvent::Transfer(TransferEvent::Offered { id: o, .. }) = e {
                assert_eq!(o, id);
                r.handle.accept_file(o, &downloads).unwrap();
            }
        }
        r.pump(&mut h);
        for m in std::mem::take(&mut h.got) {
            tx.handle(&m);
        }
        if tx.active() == 0 {
            break;
        }
    }
    assert_eq!(std::fs::read(downloads.join("report.bin")).unwrap(), data);
    // The Mark-of-the-Web goes on the part before its rename, and on the
    // stored file after it.
    let marked = marked.lock().unwrap();
    assert_eq!(marked.len(), 2, "MotW hook called twice: {marked:?}");
    assert!(
        marked[0]
            .to_string_lossy()
            .ends_with("report.bin.remora-part")
    );
    assert!(marked[1].ends_with("report.bin"));
    // Review 8: the file work ran on the transfer worker, never on the
    // thread that moves the channel's bytes (here: the test thread).
    assert!(
        threads
            .lock()
            .unwrap()
            .iter()
            .all(|t| t == "remora-transfer"),
        "{:?}",
        threads.lock().unwrap()
    );
    let left: Vec<_> = std::fs::read_dir(&downloads).unwrap().collect();
    assert_eq!(left.len(), 1, "no part or sidecar left");
}

#[test]
fn a_second_helper_instance_is_refused() {
    let mut r = Rig::new("second");
    assert!(!r.ctl.allow_second_instance());
    assert!(
        r.events()
            .contains(&HelperEvent::SecondInstanceRefused(Channel::Ctl))
    );
    assert_eq!(r.ctl.max_message_size(), HELPER_MAX_MESSAGE);
}

#[test]
fn web_url_check() {
    for ok in ["https://example.org", "HTTP://a/b?c#d", "https://a:8080/x"] {
        assert!(is_web_url(ok), "{ok}");
    }
    for bad in [
        "file:///C:/x",
        "javascript:alert(1)",
        "ms-settings:",
        "https://",
        "https:///path",
        "https://a b",
        "https://a\nb",
        "\\\\server\\share",
        "ftp://x",
        "",
        // User info hides the real host.
        "https://good.example@evil.example/",
        "https://@evil.example/",
        "https://user:pw@evil.example/",
        // Characters that split command lines, HTML or paths.
        "https://evil\\@good.example/",
        "https://a.example/\"onload",
        "https://a.example/<x>",
        "https://a.example/`cmd`",
        "https://a.example/a|b",
        "https://a.example/{x}",
        "https://a.example/^",
        "https:\\\\evil.example",
    ] {
        assert!(!is_web_url(bad), "{bad:?}");
    }
    // What leaves is the WHATWG serialization: an ASCII (punycode) host.
    let u = web_url("https://b\u{fc}cher.example/\u{e4}?q=1").unwrap();
    assert_eq!(u.host_str(), Some("xn--bcher-kva.example"));
    assert!(u.as_str().is_ascii(), "{u}");
    assert_eq!(
        web_url("HTTPS://Example.ORG:443/a").unwrap().as_str(),
        "https://example.org/a"
    );
}

#[test]
fn a_new_pairing_attempt_needs_its_own_answer() {
    let mut r = Rig::new("pair-again");
    r.handle.set_transport_protocol(1);
    let _h = r.connect(StaticKey::generate().unwrap());
    let first = shown(&r.handle);
    // The helper closes Ctl and starts over while the dialog is up.
    r.ctl.closed();
    let mut fresh = r.handle.channels();
    r.bulk = fresh.pop().unwrap();
    r.ctl = fresh.pop().unwrap();
    let _h2 = r.connect(StaticKey::generate().unwrap());
    let second = shown(&r.handle);
    if second != first {
        assert!(r.handle.confirm_pairing(first).is_err(), "old code");
        assert!(matches!(
            r.handle.state(),
            HelperState::AwaitingPairing { .. }
        ));
        assert!(
            PinStore::load(&r.dir.join("helpers.json"))
                .unwrap()
                .get("server:3389")
                .is_none(),
            "nothing pinned"
        );
    }
    r.handle.confirm_pairing(second).unwrap();
    assert_eq!(r.handle.state(), HelperState::Paired);
}

#[test]
fn no_file_down_without_the_mark_of_the_web_hook() {
    let mut r = Rig::new("motw-gate");
    r.handle.set_transport_protocol(1);
    r.handle.set_capabilities(cap::ALL);
    let mut h = r.connect(StaticKey::generate().unwrap());
    let ack = r.pair_and_hello(&mut h, cap::ALL, 0);
    assert_eq!(ack.capabilities & cap::FILE_DOWN, 0);
    assert_ne!(ack.capabilities & cap::FILE_UP, 0);
}

#[test]
fn the_event_queue_stays_bounded() {
    let mut r = Rig::new("flood");
    for _ in 0..10_000 {
        assert!(!r.ctl.allow_second_instance());
    }
    assert_eq!(r.handle.second_instance_refusals(), 10_000);
    let ev = r.events();
    assert_eq!(
        ev.iter()
            .filter(|e| matches!(e, HelperEvent::SecondInstanceRefused(_)))
            .count(),
        1
    );
    // Session info keeps only the newest.
    r.handle.set_transport_protocol(1);
    let mut h = r.connect(StaticKey::generate().unwrap());
    r.pair_and_hello(&mut h, cap::ALL, 0);
    r.events();
    for i in 0..(MAX_EVENTS as u32 + 50) {
        r.send(
            &mut h,
            Message::SessionInfo(SessionInfo {
                locked: false,
                idle_ms: i,
                cpu_percent: 1,
                mem_used: 1,
                mem_total: 2,
            }),
        );
    }
    let ev = r.events();
    assert!(ev.len() <= MAX_EVENTS);
    let infos: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            HelperEvent::SessionInfo(i) => Some(i.idle_ms),
            _ => None,
        })
        .collect();
    assert_eq!(infos, vec![MAX_EVENTS as u32 + 49]);
}

/// A man in the middle's try: the handshake and the SAS commitment run,
/// Remora answers with its nonce, and the attacker (who now knows the
/// code) drops the channel instead of revealing.
fn grind_once(r: &mut Rig, key: &StaticKey) -> rdp::Result<()> {
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out)?;
    let (mut s, first) = SecureSession::initiator(Channel::Ctl, key, Binding::default()).unwrap();
    r.ctl.process(&first, &mut out)?;
    let msg2 = out.take();
    let mut to_client = Vec::new();
    for ev in s.on_message(&msg2[0]).unwrap() {
        if let Event::Send(b) = ev {
            to_client.push(b);
        }
    }
    for m in to_client {
        r.ctl.process(&m, &mut out)?;
    }
    // Remora sent its nonce; the attacker learns the code and aborts.
    assert_eq!(out.take().len(), 1, "SasNonce");
    r.ctl.closed();
    Ok(())
}

#[test]
fn two_aborted_pairings_refuse_the_helper_for_the_connection() {
    let mut r = Rig::new("grind");
    r.handle.set_transport_protocol(1);
    let mitm = StaticKey::generate().unwrap();
    grind_once(&mut r, &mitm).unwrap();
    assert_eq!(r.handle.state(), HelperState::NotPresent);
    grind_once(&mut r, &mitm).unwrap();
    assert_eq!(r.handle.state(), HelperState::PairingBlocked);
    // Remora::Ctl is refused for the rest of this connection...
    let mut out = DvcOut::default();
    assert!(r.ctl.opened(&mut out).is_err());
    assert_eq!(r.handle.state(), HelperState::PairingBlocked);
    // ...also for a helper it knows.
    let known = StaticKey::generate().unwrap();
    let mut s = PinStore::new();
    s.pin("server:3389", &known.public(), 1);
    s.save(&r.dir.join("helpers.json")).unwrap();
    assert!(r.ctl.opened(&mut out).is_err());
    // A new connection starts the per-connection count over.
    let mut fresh = r.handle.reattach();
    r.bulk = fresh.pop().unwrap();
    r.ctl = fresh.pop().unwrap();
    r.handle.set_transport_protocol(1);
    let _h = r.connect(known);
    assert_eq!(r.handle.state(), HelperState::Paired);
}

#[test]
fn a_known_helper_or_the_users_own_answer_is_not_an_abort() {
    let mut r = Rig::new("not-abort");
    r.handle.set_transport_protocol(1);
    let key = StaticKey::generate().unwrap();
    // The user rejects twice: two answers, no block.
    for _ in 0..2 {
        let _h = r.connect(key.clone());
        r.handle.reject_pairing(shown(&r.handle));
        r.ctl.closed();
    }
    assert_ne!(r.handle.state(), HelperState::PairingBlocked);
    // A pinned helper that closes early is not counted either.
    let mut s = PinStore::new();
    s.pin("server:3389", &key.public(), 1);
    s.save(&r.dir.join("helpers.json")).unwrap();
    for _ in 0..3 {
        grind_once(&mut r, &key).unwrap();
    }
    assert_eq!(r.handle.state(), HelperState::NotPresent);
}

#[test]
fn three_aborts_in_a_day_block_pairing_with_the_server_until_retried() {
    let mut r = Rig::new("grind-server");
    let attempts = r.dir.join("helper-attempts.json");
    r.handle.set_pairing_policy(Some(attempts.clone()), None);
    let mitm = StaticKey::generate().unwrap();
    // One abort per connection, three connections.
    for _ in 0..3 {
        r.handle.set_transport_protocol(1);
        grind_once(&mut r, &mitm).unwrap();
        let mut fresh = r.handle.reattach();
        r.bulk = fresh.pop().unwrap();
        r.ctl = fresh.pop().unwrap();
    }
    assert!(remora_link::AttemptLog::is_blocked(
        &attempts,
        "server:3389"
    ));
    // A new connection: an unpinned key is refused right after the
    // handshake, before any code exists.
    r.handle.set_transport_protocol(1);
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out).unwrap();
    let (mut s, first) = SecureSession::initiator(Channel::Ctl, &mitm, Binding::default()).unwrap();
    r.ctl.process(&first, &mut out).unwrap();
    let msg2 = out.take();
    let mut sends = Vec::new();
    for ev in s.on_message(&msg2[0]).unwrap() {
        if let Event::Send(b) = ev {
            sends.push(b);
        }
    }
    assert!(r.ctl.process(&sends[0], &mut out).is_err(), "closed");
    assert!(out.is_empty(), "no SAS nonce was sent");
    assert_eq!(r.handle.state(), HelperState::PairingBlocked);
    // The user retries from the helper card: pairing works again.
    r.ctl.closed();
    r.handle.retry_pairing().unwrap();
    assert!(!remora_link::AttemptLog::is_blocked(
        &attempts,
        "server:3389"
    ));
    assert_eq!(r.handle.state(), HelperState::NotPresent);
    let _h = r.connect(StaticKey::generate().unwrap());
    assert!(matches!(
        r.handle.state(),
        HelperState::AwaitingPairing { .. }
    ));
}

#[test]
fn an_admin_set_fingerprint_pins_only_that_key_without_a_code() {
    let mut r = Rig::new("admin-pin");
    let key = StaticKey::generate().unwrap();
    r.handle
        .set_pairing_policy(None, Some(remora_link::fingerprint_bytes(&key.public())));
    r.handle.set_transport_protocol(1);
    let h = r.connect(key.clone());
    assert!(h.got.contains(&Message::Pairing(PairingStatus::Known)));
    assert_eq!(r.handle.state(), HelperState::Paired);
    let pins = PinStore::load(&r.dir.join("helpers.json")).unwrap();
    assert_eq!(pins.check("server:3389", &key.public()), PinCheck::Known);
    // Any other key is refused outright: no code to compare, no question.
    let mut r = Rig::new("admin-pin-2");
    r.handle
        .set_pairing_policy(None, Some(remora_link::fingerprint_bytes(&key.public())));
    r.handle.set_transport_protocol(1);
    let other = StaticKey::generate().unwrap();
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out).unwrap();
    let (mut s, first) =
        SecureSession::initiator(Channel::Ctl, &other, Binding::default()).unwrap();
    r.ctl.process(&first, &mut out).unwrap();
    let msg2 = out.take();
    let sends: Vec<_> = s
        .on_message(&msg2[0])
        .unwrap()
        .into_iter()
        .filter_map(|e| match e {
            Event::Send(b) => Some(b),
            _ => None,
        })
        .collect();
    assert!(r.ctl.process(&sends[0], &mut out).is_err());
    assert!(matches!(r.handle.state(), HelperState::Failed(_)));
}

/// The helper does not know this PC (1.1 `PeerPairing{Confirm}`): Remora
/// shows its code even for a pinned helper, and a new helper is pinned only
/// once the server's user confirmed too.
#[test]
fn the_helpers_own_confirmation_shows_the_code_and_gates_the_pin() {
    let mut r = Rig::new("peer-pair");
    r.handle
        .set_client(StaticKey::generate().unwrap(), "LAPTOP-7");
    r.handle.set_transport_protocol(1);
    let key = StaticKey::generate().unwrap();
    let mut h = r.connect(key.clone());
    assert!(h.got.contains(&Message::ClientName {
        name: "LAPTOP-7".into()
    }));
    r.send(&mut h, Message::PeerPairing(PairingStatus::Confirm));
    assert!(r.handle.server_pending());
    r.handle.confirm_pairing(shown(&r.handle)).unwrap();
    let mut hello11 = hello(cap::ALL, 0);
    if let Message::Hello(x) = &mut hello11 {
        x.minor = 1;
    }
    r.send(&mut h, hello11);
    let pins = r.dir.join("helpers.json");
    assert!(
        PinStore::load(&pins).unwrap().iter().next().is_none(),
        "not pinned before the server's user confirmed"
    );
    r.send(&mut h, Message::PeerPairing(PairingStatus::Confirmed));
    assert!(!r.handle.server_pending());
    assert_eq!(
        PinStore::load(&pins)
            .unwrap()
            .check("server:3389", &key.public()),
        PinCheck::Known
    );

    // Next session: the helper is pinned here, but the server forgot this
    // PC; Remora still shows the code for the server's user to compare.
    let mut r2 = Rig::new("peer-pair-2");
    std::fs::copy(&pins, r2.dir.join("helpers.json")).unwrap();
    r2.handle.set_transport_protocol(1);
    let mut h2 = r2.connect(key);
    assert_eq!(r2.handle.state(), HelperState::Paired);
    r2.send(&mut h2, Message::PeerPairing(PairingStatus::Confirm));
    assert!(matches!(
        r2.handle.state(),
        HelperState::AwaitingPairing { changed: false, .. }
    ));
    r2.handle.confirm_pairing(shown(&r2.handle)).unwrap();
    r2.pump(&mut h2);
    assert!(h2.got.contains(&Message::Pairing(PairingStatus::Confirmed)));
}

#[test]
fn the_pre_tls_buffer_is_capped_in_bytes() {
    let mut r = Rig::new("pre-tls-bytes");
    let mut out = DvcOut::default();
    r.ctl.opened(&mut out).unwrap();
    let big = vec![0u8; 1 << 20];
    r.ctl.process(&big, &mut out).unwrap();
    r.ctl.process(&big, &mut out).unwrap();
    // Two messages, 2 MiB: the third byte over closes the channel.
    r.ctl.process(&[0], &mut out).unwrap_err();
    assert!(matches!(r.handle.state(), HelperState::Failed(_)));
}

/// Dropping the whole RDP connection mid-pairing is no free retry: each
/// such attempt counts for the server like a closed channel.
#[test]
fn a_pairing_cut_off_by_a_reconnect_counts_for_the_server() {
    let mut r = Rig::new("grind-reconnect");
    let attempts = r.dir.join("helper-attempts.json");
    r.handle.set_pairing_policy(Some(attempts.clone()), None);
    let mitm = StaticKey::generate().unwrap();
    for _ in 0..3 {
        r.handle.set_transport_protocol(1);
        let _h = r.connect(mitm.clone());
        assert!(matches!(
            r.handle.state(),
            HelperState::AwaitingPairing { .. }
        ));
        // The connection drops; the tab reconnects (no channel close seen).
        let mut fresh = r.handle.reattach();
        r.bulk = fresh.pop().unwrap();
        r.ctl = fresh.pop().unwrap();
    }
    assert!(remora_link::AttemptLog::is_blocked(
        &attempts,
        "server:3389"
    ));
}
