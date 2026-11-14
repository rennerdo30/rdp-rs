//! Transfer engine tests: two engines in memory, every message passed
//! through the wire encoding.

use super::io::{MemDir, MemSource};
use super::*;
use crate::msg::Message;

/// Deterministic test data.
fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

fn wire(m: &Message) -> Message {
    let bytes = m.encode(0).unwrap();
    Message::decode(&bytes).unwrap().1
}

struct Pair {
    tx: Engine,
    rx: Engine,
    dir: MemDir,
    /// Chunk bytes delivered to the receiver.
    delivered: u64,
    /// Receiver events seen while running (offers are accepted).
    rx_events: Vec<TransferEvent>,
}

impl Pair {
    fn new() -> Pair {
        let mut tx = Engine::default();
        let mut rx = Engine::default();
        tx.set_permissions(true, false);
        rx.set_permissions(false, true);
        tx.set_connected(true);
        rx.set_connected(true);
        Pair {
            tx,
            rx,
            dir: MemDir::new(),
            delivered: 0,
            rx_events: Vec::new(),
        }
    }

    /// Moves messages until both sides are quiet or `stop` says so. The
    /// receiver accepts every offer into `dir`. `tamper` may edit or drop
    /// a sender message (return None to drop).
    fn run(
        &mut self,
        stop: &mut dyn FnMut(&Pair) -> bool,
        tamper: &mut dyn FnMut(Message) -> Option<Message>,
    ) {
        for _ in 0..100_000 {
            if stop(self) {
                return;
            }
            self.tx.poll(1 << 20);
            let a = self.tx.take_messages();
            for m in a.iter() {
                if let Some(m) = tamper(wire(m)) {
                    if let Message::FileChunk { data, .. } = &m {
                        self.delivered += data.len() as u64;
                    }
                    self.rx.handle(&m);
                }
            }
            while let Some(e) = self.rx.next_event() {
                if let TransferEvent::Offered { id, .. } = e {
                    self.rx.accept(id, Box::new(self.dir.clone())).unwrap();
                }
                self.rx_events.push(e);
            }
            let b = self.rx.take_messages();
            for m in b.iter() {
                self.tx.handle(&wire(m));
            }
            if a.is_empty() && b.is_empty() && self.tx.active() + self.rx.active() == 0 {
                return;
            }
            if a.is_empty() && b.is_empty() && !self.tx.is_connected() {
                return;
            }
        }
        panic!("transfer did not settle");
    }

    fn run_all(&mut self) {
        self.run(&mut |_| false, &mut Some);
    }
}

fn rx_events(p: &mut Pair) -> Vec<TransferEvent> {
    let mut v = std::mem::take(&mut p.rx_events);
    v.extend(events(&mut p.rx));
    v
}

fn events(e: &mut Engine) -> Vec<TransferEvent> {
    std::iter::from_fn(|| e.next_event()).collect()
}

fn completed(ev: &[TransferEvent]) -> Option<String> {
    ev.iter().find_map(|e| match e {
        TransferEvent::Completed { name, .. } => Some(name.clone()),
        _ => None,
    })
}

fn failed(ev: &[TransferEvent]) -> Option<(u8, bool)> {
    ev.iter().find_map(|e| match e {
        TransferEvent::Failed {
            reason, by_peer, ..
        } => Some((*reason, *by_peer)),
        _ => None,
    })
}

const MIB: usize = 1 << 20;

#[test]
fn happy_path_two_and_a_half_blocks() {
    let mut p = Pair::new();
    let file = data(10 * MIB + 123, 1);
    p.tx.send("report.pdf", Box::new(MemSource::new(file.clone(), 77)))
        .unwrap();
    p.run_all();
    assert_eq!(p.dir.get("report.pdf").as_deref(), Some(&file[..]));
    assert_eq!(p.dir.names(), ["report.pdf"], "part and sidecar removed");
    assert_eq!(p.dir.finished_names(), ["report.pdf"], "MotW hook called");
    assert_eq!(completed(&events(&mut p.tx)).as_deref(), Some("report.pdf"));
    assert_eq!(completed(&rx_events(&mut p)).as_deref(), Some("report.pdf"));
    assert_eq!(p.delivered, file.len() as u64, "every byte sent once");
}

#[test]
fn empty_and_exact_block_files() {
    for len in [0, BLOCK_SIZE as usize, 1] {
        let mut p = Pair::new();
        let file = data(len, 2);
        p.tx.send("f.bin", Box::new(MemSource::new(file.clone(), 1)))
            .unwrap();
        p.run_all();
        assert_eq!(p.dir.get("f.bin"), Some(file), "len {len}");
    }
}

#[test]
fn existing_file_is_never_overwritten() {
    let mut p = Pair::new();
    p.dir.put("a.txt", b"keep".to_vec());
    p.dir
        .put("a (2).txt.remora-part", b"other transfer".to_vec());
    p.tx.send("a.txt", Box::new(MemSource::new(b"new".to_vec(), 1)))
        .unwrap();
    p.run_all();
    assert_eq!(p.dir.get("a.txt").unwrap(), b"keep");
    assert_eq!(p.dir.get("a (3).txt").unwrap(), b"new");
    assert_eq!(completed(&rx_events(&mut p)).as_deref(), Some("a (3).txt"));
}

#[test]
fn a_file_appearing_during_the_transfer_is_not_replaced() {
    let mut p = Pair::new();
    let file = data(3 * MIB, 3);
    p.tx.send("late.bin", Box::new(MemSource::new(file.clone(), 1)))
        .unwrap();
    let dir = p.dir.clone();
    let mut planted = false;
    p.run(&mut |_| false, &mut |m| {
        if !planted && matches!(m, Message::FileChunk { .. }) {
            dir.put("late.bin", b"user file".to_vec());
            planted = true;
        }
        Some(m)
    });
    assert_eq!(p.dir.get("late.bin").unwrap(), b"user file");
    assert_eq!(p.dir.get("late (2).bin"), Some(file));
}

#[test]
fn user_reject_reaches_the_sender() {
    let mut tx = Engine::default();
    let mut rx = Engine::default();
    tx.set_permissions(true, false);
    rx.set_permissions(false, true);
    tx.set_connected(true);
    rx.set_connected(true);
    let id = tx
        .send("x.txt", Box::new(MemSource::new(vec![1, 2, 3], 1)))
        .unwrap();
    for m in tx.take_messages() {
        rx.handle(&m);
    }
    assert!(matches!(rx.next_event(), Some(TransferEvent::Offered { id: i, .. }) if i == id));
    rx.reject(id);
    for m in rx.take_messages() {
        tx.handle(&m);
    }
    assert_eq!(failed(&events(&mut tx)), Some((reason::USER, true)));
    assert_eq!(tx.active() + rx.active(), 0);
}

#[test]
fn disabled_direction_rejects_and_send_refuses() {
    let mut rx = Engine::default();
    rx.set_connected(true);
    let offer = FileOffer {
        id: [1; 16],
        name: "x".into(),
        size: 1,
        mtime: 0,
        block_size: BLOCK_SIZE,
    };
    rx.handle(&Message::FileOffer(offer));
    assert_eq!(
        rx.take_messages(),
        [Message::FileReject {
            id: [1; 16],
            reason: reason::DISABLED
        }]
    );
    assert!(rx.next_event().is_none());
    let mut tx = Engine::default();
    assert!(tx.send("x", Box::new(MemSource::new(vec![], 0))).is_err());
}

#[test]
fn unsafe_names_are_rejected_before_the_user_sees_them() {
    for bad in [
        "../evil.exe",
        "C:\\x",
        "a.txt:Zone.Identifier",
        "CON",
        "x. ",
    ] {
        let mut rx = Engine::default();
        rx.set_permissions(false, true);
        rx.set_connected(true);
        rx.handle(&Message::FileOffer(FileOffer {
            id: [2; 16],
            name: bad.into(),
            size: 10,
            mtime: 0,
            block_size: BLOCK_SIZE,
        }));
        assert_eq!(
            rx.take_messages(),
            [Message::FileReject {
                id: [2; 16],
                reason: reason::BAD_NAME
            }],
            "{bad:?}"
        );
        let ev = events(&mut rx);
        assert!(
            !ev.iter()
                .any(|e| matches!(e, TransferEvent::Offered { .. }))
        );
        assert_eq!(failed(&ev), Some((reason::BAD_NAME, false)));
    }
    // The sender refuses them too.
    let mut tx = Engine::default();
    tx.set_permissions(true, false);
    assert!(
        tx.send("../x", Box::new(MemSource::new(vec![], 0)))
            .is_err()
    );
}

#[test]
fn not_enough_space_is_refused() {
    let mut p = Pair::new();
    p.dir = MemDir::new().with_free_space(100);
    p.tx.send("big.bin", Box::new(MemSource::new(vec![0; 101], 1)))
        .unwrap();
    p.run_all();
    assert_eq!(failed(&events(&mut p.tx)), Some((reason::NO_SPACE, true)));
    assert!(p.dir.names().is_empty(), "nothing written");
}

#[test]
fn flow_control_never_exceeds_credit() {
    let mut tx = Engine::default();
    tx.set_permissions(true, false);
    tx.set_connected(true);
    let id = tx
        .send("f", Box::new(MemSource::new(data(9 * MIB, 4), 1)))
        .unwrap();
    tx.take_messages();
    let sent = |tx: &mut Engine| -> (u64, u64) {
        let mut bytes = 0;
        let mut end = 0;
        for m in tx.take_messages() {
            if let Message::FileChunk { offset, data, .. } = m {
                bytes += data.len() as u64;
                end = end.max(offset + data.len() as u64);
            }
        }
        (bytes, end)
    };
    tx.handle(&Message::FileAccept {
        id,
        epoch: 1,
        offset: 0,
        limit: 600 * 1024,
    });
    tx.poll(usize::MAX);
    assert_eq!(sent(&mut tx), (600 * 1024, 600 * 1024));
    tx.poll(usize::MAX);
    assert_eq!(sent(&mut tx), (0, 0), "nothing without more credit");
    // A stale epoch's credit is ignored; a lower limit never shrinks it.
    tx.handle(&Message::FileCredit {
        id,
        epoch: 0,
        limit: 5 * MIB as u64,
    });
    tx.handle(&Message::FileCredit {
        id,
        epoch: 1,
        limit: 1,
    });
    tx.poll(usize::MAX);
    assert_eq!(sent(&mut tx), (0, 0));
    tx.handle(&Message::FileCredit {
        id,
        epoch: 1,
        limit: MIB as u64,
    });
    tx.poll(usize::MAX);
    assert_eq!(sent(&mut tx), (MIB as u64 - 600 * 1024, MIB as u64));
    // Budget limits bytes read per poll.
    tx.handle(&Message::FileCredit {
        id,
        epoch: 1,
        limit: 4 * MIB as u64,
    });
    tx.poll(1);
    assert_eq!(
        sent(&mut tx).0,
        CHUNK_SIZE as u64,
        "one chunk per small budget"
    );
}

#[test]
fn in_flight_data_stays_within_the_window() {
    // Every chunk the receiver sees ends at or below the highest limit it
    // granted; with the default window that is at most 2 MiB ahead.
    let mut p = Pair::new();
    let file = data(9 * MIB, 5);
    p.tx.send("w.bin", Box::new(MemSource::new(file.clone(), 1)))
        .unwrap();
    let mut max_end = 0u64;
    p.run(&mut |_| false, &mut |m| {
        if let Message::FileChunk { offset, data, .. } = &m {
            max_end = max_end.max(offset + data.len() as u64);
            assert!(data.len() <= CHUNK_SIZE as usize);
            assert_eq!(
                offset / BLOCK_SIZE as u64,
                (offset + data.len() as u64 - 1) / BLOCK_SIZE as u64,
                "chunks never cross a block"
            );
        }
        Some(m)
    });
    assert_eq!(p.dir.get("w.bin"), Some(file));
    assert_eq!(max_end, 9 * MIB as u64);
}

#[test]
fn receiver_fails_a_chunk_beyond_credit() {
    let mut rx = Engine::default();
    rx.set_permissions(false, true);
    rx.set_connected(true);
    let id = [3; 16];
    rx.handle(&Message::FileOffer(FileOffer {
        id,
        name: "f".into(),
        size: 8 * MIB as u64,
        mtime: 0,
        block_size: BLOCK_SIZE,
    }));
    events(&mut rx);
    let dir = MemDir::new();
    rx.accept(id, Box::new(dir.clone())).unwrap();
    let accept = rx.take_messages();
    let Message::FileAccept { epoch, limit, .. } = accept[0] else {
        panic!("{accept:?}")
    };
    assert_eq!(limit, WINDOW);
    rx.handle(&Message::FileChunk {
        id,
        epoch,
        offset: 0,
        data: vec![0; CHUNK_SIZE as usize + 1],
    });
    assert_eq!(failed(&events(&mut rx)), Some((reason::PROTOCOL, false)));
    assert!(dir.names().is_empty(), "part removed");
}

/// Runs a 10 MiB transfer, cuts the link after `cut_at` bytes reached the
/// receiver, and returns the pair, the file and the bytes sent before the cut.
fn cut_after(cut_at: u64) -> (Pair, Vec<u8>, u64) {
    let mut p = Pair::new();
    let file = data(10 * MIB, 6);
    p.tx.send("big.iso", Box::new(MemSource::new(file.clone(), 5)))
        .unwrap();
    p.run(&mut |p| p.delivered >= cut_at, &mut Some);
    let before = p.delivered;
    p.tx.set_connected(false);
    p.rx.set_connected(false);
    // Whatever was in flight is lost with the channel.
    p.tx.take_messages();
    p.rx.take_messages();
    assert!(p.dir.exists("big.iso.remora-part"));
    assert!(p.dir.exists("big.iso.remora-part.meta"));
    (p, file, before)
}

#[test]
fn resume_after_reconnect_continues_from_the_verified_block() {
    let (mut p, file, before) = cut_after(6 * MIB as u64);
    assert!(before >= 6 * MIB as u64 && before < 10 * MIB as u64);
    let paused: Vec<_> = events(&mut p.tx)
        .into_iter()
        .filter(|e| matches!(e, TransferEvent::Paused { .. }))
        .collect();
    assert_eq!(paused.len(), 1);
    p.delivered = 0;
    p.tx.set_connected(true);
    p.rx.set_connected(true);
    p.run_all();
    assert_eq!(p.dir.get("big.iso"), Some(file));
    // Only the unverified tail is sent again: from block 1 (4 MiB) on.
    assert_eq!(p.delivered, 6 * MIB as u64);
}

#[test]
fn resume_after_receiver_restart_uses_the_sidecar() {
    let (mut p, file, _) = cut_after(9 * MIB as u64);
    // The receiving process restarts: a fresh engine, same folder.
    p.rx = Engine::default();
    p.rx.set_permissions(false, true);
    p.delivered = 0;
    p.tx.set_connected(true);
    p.rx.set_connected(true);
    p.run_all();
    assert_eq!(p.dir.get("big.iso"), Some(file));
    assert_eq!(p.delivered, 2 * MIB as u64, "two verified blocks kept");
    assert_eq!(p.dir.names(), ["big.iso"]);
}

#[test]
fn resume_rechecks_the_part_file() {
    let (mut p, file, _) = cut_after(9 * MIB as u64);
    p.dir.corrupt("big.iso.remora-part", 4 * MIB + 10); // inside block 1
    p.rx = Engine::default();
    p.rx.set_permissions(false, true);
    p.delivered = 0;
    p.tx.set_connected(true);
    p.rx.set_connected(true);
    p.run_all();
    assert_eq!(p.dir.get("big.iso"), Some(file));
    assert_eq!(
        p.delivered,
        6 * MIB as u64,
        "block 0 kept, 1 and later resent"
    );
}

#[test]
fn resume_with_a_changed_source_fails() {
    let (mut p, _file, _) = cut_after(5 * MIB as u64);
    // The sender's file is modified while disconnected (new mtime).
    let s = p.tx.sending.values_mut().next().unwrap();
    s.source = Box::new(MemSource::new(data(10 * MIB, 6), 999));
    p.tx.set_connected(true);
    p.rx.set_connected(true);
    p.run_all();
    assert_eq!(
        failed(&events(&mut p.tx)),
        Some((reason::SOURCE_CHANGED, false))
    );
    assert_eq!(
        failed(&rx_events(&mut p)),
        Some((reason::SOURCE_CHANGED, true))
    );
    assert!(p.dir.names().is_empty(), "receiver cleaned up");
}

#[test]
fn a_corrupted_block_is_detected_and_resent() {
    let mut p = Pair::new();
    let file = data(9 * MIB, 7);
    p.tx.send("c.bin", Box::new(MemSource::new(file.clone(), 1)))
        .unwrap();
    let mut flipped = false;
    p.run(&mut |_| false, &mut |mut m| {
        if let Message::FileChunk { offset, data, .. } = &mut m
            && !flipped
            && *offset >= 4 * MIB as u64
        {
            data[0] ^= 1;
            flipped = true;
        }
        Some(m)
    });
    assert!(flipped);
    assert_eq!(p.dir.get("c.bin"), Some(file));
    // Block 1 (4 MiB) was sent twice; chunks already in flight when the
    // rewind went out (at most one window) arrive and are ignored.
    let d = p.delivered;
    assert!((13 * MIB as u64..=15 * MIB as u64).contains(&d), "{d}");
}

#[test]
fn persistent_corruption_fails_with_integrity() {
    let mut p = Pair::new();
    p.tx.send("d.bin", Box::new(MemSource::new(data(5 * MIB, 8), 1)))
        .unwrap();
    p.run(&mut |_| false, &mut |mut m| {
        if let Message::FileChunk {
            offset: 0, data, ..
        } = &mut m
        {
            data[0] ^= 1;
        }
        Some(m)
    });
    assert_eq!(failed(&rx_events(&mut p)), Some((reason::INTEGRITY, false)));
    assert_eq!(failed(&events(&mut p.tx)), Some((reason::INTEGRITY, true)));
    assert!(p.dir.names().is_empty(), "part and sidecar removed");
}

#[test]
fn a_wrong_root_hash_fails() {
    let mut p = Pair::new();
    p.tx.send("r.bin", Box::new(MemSource::new(data(1000, 9), 1)))
        .unwrap();
    p.run(&mut |_| false, &mut |mut m| {
        if let Message::FileEnd { root, .. } = &mut m {
            root[0] ^= 1;
        }
        Some(m)
    });
    assert_eq!(failed(&rx_events(&mut p)), Some((reason::INTEGRITY, false)));
    assert!(p.dir.names().is_empty());
}

#[test]
fn sender_cancel_cleans_up_the_receiver() {
    let mut p = Pair::new();
    let id =
        p.tx.send("e.bin", Box::new(MemSource::new(data(6 * MIB, 10), 1)))
            .unwrap();
    p.run(&mut |p| p.delivered > MIB as u64, &mut Some);
    p.tx.cancel(id);
    p.run_all();
    assert_eq!(failed(&events(&mut p.tx)), Some((reason::USER, false)));
    assert_eq!(failed(&rx_events(&mut p)), Some((reason::USER, true)));
    assert!(p.dir.names().is_empty());
}

#[test]
fn receiver_cancel_stops_the_sender() {
    let mut p = Pair::new();
    let id =
        p.tx.send("e.bin", Box::new(MemSource::new(data(6 * MIB, 10), 1)))
            .unwrap();
    p.run(&mut |p| p.delivered > MIB as u64, &mut Some);
    p.rx.cancel(id);
    p.run_all();
    assert_eq!(failed(&events(&mut p.tx)), Some((reason::USER, true)));
    assert!(p.dir.names().is_empty());
    assert_eq!(p.tx.active(), 0);
}

#[test]
fn a_repeated_offer_after_completion_completes_again() {
    // The sender lost the link before FileComplete arrived.
    let mut p = Pair::new();
    let file = data(1000, 11);
    p.tx.send("g.bin", Box::new(MemSource::new(file.clone(), 1)))
        .unwrap();
    let mut drop_complete = true;
    // Run until the receiver completed, swallowing its FileComplete.
    for _ in 0..100 {
        p.tx.poll(1 << 20);
        for m in p.tx.take_messages() {
            p.rx.handle(&m);
        }
        while let Some(e) = p.rx.next_event() {
            if let TransferEvent::Offered { id, .. } = e {
                p.rx.accept(id, Box::new(p.dir.clone())).unwrap();
            }
        }
        for m in p.rx.take_messages() {
            if drop_complete && matches!(m, Message::FileComplete { .. }) {
                drop_complete = false;
                continue;
            }
            p.tx.handle(&m);
        }
        if !drop_complete {
            break;
        }
    }
    assert_eq!(p.dir.get("g.bin"), Some(file.clone()));
    p.tx.set_connected(false);
    p.rx.set_connected(false);
    p.tx.set_connected(true);
    p.rx.set_connected(true);
    p.run_all();
    assert_eq!(completed(&events(&mut p.tx)).as_deref(), Some("g.bin"));
    assert_eq!(p.dir.names(), ["g.bin"], "stored once");
}

#[test]
fn switching_a_direction_off_cancels_its_transfers() {
    let mut p = Pair::new();
    p.tx.send("h.bin", Box::new(MemSource::new(data(6 * MIB, 12), 1)))
        .unwrap();
    p.run(&mut |p| p.delivered > MIB as u64, &mut Some);
    p.rx.set_permissions(false, false);
    p.run_all();
    assert_eq!(failed(&events(&mut p.tx)), Some((reason::DISABLED, true)));
    assert!(p.dir.names().is_empty());
}

#[test]
fn ids_are_uuid_v4() {
    let a = new_id().unwrap();
    let b = new_id().unwrap();
    assert_ne!(a, b);
    assert_eq!(a[6] >> 4, 4);
    assert_eq!(a[8] >> 6, 2);
}

fn offer(id: u8, name: &str, size: u64) -> FileOffer {
    FileOffer {
        id: [id; 16],
        name: name.into(),
        size,
        mtime: 1,
        block_size: BLOCK_SIZE,
    }
}

fn receiver() -> Engine {
    let mut rx = Engine::default();
    rx.set_permissions(false, true);
    rx.set_connected(true);
    rx
}

/// A sidecar as the engine writes it (version 2 log).
fn sidecar(id: u8, name: &str, size: u64, blocks: &[[u8; 32]]) -> Vec<u8> {
    let mut v = format!(
        r#"{{"v":2,"id":"{}","name":"{name}","size":{size},"mtime":1,"block":{BLOCK_SIZE}}}"#,
        hex(&[id; 16])
    )
    .into_bytes();
    v.push(b'\n');
    for b in blocks {
        v.extend_from_slice(hex(b).as_bytes());
        v.push(b'\n');
    }
    v
}

/// Review 6: an accept that fails (no space) must not delete the part and
/// sidecar of another transfer that happens to use the same name.
#[test]
fn a_failed_accept_leaves_other_transfers_files_alone() {
    let mut rx = receiver();
    let dir = MemDir::new();
    rx.handle(&Message::FileOffer(offer(1, "r.pdf", 10)));
    rx.accept([1; 16], Box::new(dir.clone())).unwrap();
    assert!(dir.exists("r.pdf.remora-part") && dir.exists("r.pdf.remora-part.meta"));
    rx.handle(&Message::FileOffer(offer(2, "r.pdf", u64::MAX)));
    rx.accept([2; 16], Box::new(dir.clone().with_free_space(1000)))
        .unwrap();
    assert!(events(&mut rx).iter().any(|e| matches!(
        e,
        TransferEvent::Failed {
            reason: reason::NO_SPACE,
            ..
        }
    )));
    assert!(dir.exists("r.pdf.remora-part"), "transfer 1's part kept");
    assert!(dir.exists("r.pdf.remora-part.meta"), "and its sidecar");
}

/// Review 7: a sidecar planted under another name (delivered earlier as an
/// ordinary file) must not make a resume store the data under that name.
#[test]
fn a_planted_sidecar_cannot_rename_the_stored_file() {
    let content = b"MZ-payload".to_vec();
    let dir = MemDir::new();
    let h = *blake3::hash(&content).as_bytes();
    dir.put(
        "evil.exe.remora-part.meta",
        sidecar(9, "evil.exe", content.len() as u64, &[h]),
    );
    dir.put("evil.exe.remora-part", content.clone());
    let mut rx = receiver();
    rx.handle(&Message::FileOffer(offer(
        9,
        "report.pdf",
        content.len() as u64,
    )));
    events(&mut rx);
    rx.accept([9; 16], Box::new(dir.clone())).unwrap();
    // Not resumed: the receiver asks for everything from offset 0.
    assert!(matches!(
        rx.take_messages()[..],
        [Message::FileAccept { offset: 0, .. }]
    ));
    let root = root_hash(content.len() as u64, &[h]);
    rx.handle(&Message::FileEnd {
        id: [9; 16],
        epoch: 1,
        root,
    });
    assert!(!dir.exists("evil.exe"));
    // And such names never arrive as files in the first place.
    for planted in ["evil.exe.remora-part.meta", "evil.exe.remora-part", "x.TMP"] {
        let mut rx = receiver();
        rx.handle(&Message::FileOffer(offer(3, planted, 10)));
        assert_eq!(
            rx.take_messages(),
            [Message::FileReject {
                id: [3; 16],
                reason: reason::BAD_NAME
            }],
            "{planted}"
        );
    }
}

/// A sidecar of the offered name's numbered variant still resumes.
#[test]
fn a_numbered_variant_resumes() {
    let content = data(10, 3);
    let dir = MemDir::new();
    let h = *blake3::hash(&content).as_bytes();
    dir.put(
        "r (2).pdf.remora-part.meta",
        sidecar(4, "r (2).pdf", 10, &[h]),
    );
    dir.put("r (2).pdf.remora-part", content.clone());
    let mut rx = receiver();
    rx.handle(&Message::FileOffer(offer(4, "r.pdf", 10)));
    rx.accept([4; 16], Box::new(dir.clone())).unwrap();
    assert!(matches!(
        rx.take_messages()[..],
        [Message::FileAccept { offset: 10, .. }]
    ));
    rx.handle(&Message::FileEnd {
        id: [4; 16],
        epoch: 1,
        root: root_hash(10, &[h]),
    });
    assert_eq!(dir.get("r (2).pdf"), Some(content));
}

/// Review 12: more recorded hashes than the size has blocks must not
/// underflow (a panic in debug builds) and the extra ones are ignored.
#[test]
fn a_sidecar_with_too_many_blocks_does_not_underflow() {
    let content = b"0123456789".to_vec();
    let dir = MemDir::new();
    let h = *blake3::hash(&content).as_bytes();
    dir.put("x.remora-part.meta", sidecar(7, "x", 10, &[h, h, h]));
    dir.put("x.remora-part", content);
    let mut rx = receiver();
    rx.handle(&Message::FileOffer(offer(7, "x", 10)));
    rx.accept([7; 16], Box::new(dir.clone())).unwrap();
    assert!(matches!(
        rx.take_messages()[..],
        [Message::FileAccept { offset: 10, .. }]
    ));
}

/// The sidecar is a log: one appended line per verified block, and a torn
/// last line (a crash mid-append) only loses that block.
#[test]
fn the_sidecar_is_appended_and_a_torn_line_is_ignored() {
    let (p, file, _) = cut_after(9 * MIB as u64);
    let meta = p.dir.get("big.iso.remora-part.meta").unwrap();
    let lines: Vec<_> = meta.split(|&b| b == b'\n').collect();
    // Header, two block lines, and nothing after the last newline.
    assert_eq!(lines.len(), 4, "{}", String::from_utf8_lossy(&meta));
    assert!(lines[3].is_empty());
    assert_eq!(
        lines[1],
        hex(blake3::hash(&file[..4 * MIB]).as_bytes()).as_bytes()
    );
    // Tear the last record: only block 0 survives.
    let torn = meta[..meta.len() - 10].to_vec();
    let (_, hashes) = parse_meta(&torn).unwrap();
    assert_eq!(hashes.len(), 1);
    assert!(
        parse_meta(b"{\"v\":1}\n").is_none(),
        "old format is not read"
    );
}

/// RDP-43 gap: an offer accepted while the receiver's link is down asks for
/// its data when the link comes up (the sender does not offer it again).
#[test]
fn an_offer_accepted_while_the_link_is_down_starts_on_link_up() {
    let mut rx = Engine::default();
    rx.set_permissions(false, true);
    let dir = MemDir::new();
    rx.handle(&Message::FileOffer(offer(5, "late.bin", 10)));
    rx.accept([5; 16], Box::new(dir.clone())).unwrap();
    assert!(rx.take_messages().is_empty(), "link down: nothing sent");
    rx.set_connected(true);
    assert!(matches!(
        rx.take_messages()[..],
        [Message::FileAccept {
            offset: 0,
            epoch: 1,
            ..
        }]
    ));
    // The sender's re-offer before any data gets the same accept, not a
    // new epoch (nothing in flight is thrown away).
    rx.handle(&Message::FileOffer(offer(5, "late.bin", 10)));
    assert!(matches!(
        rx.take_messages()[..],
        [Message::FileAccept { epoch: 1, .. }]
    ));
}

/// Shell-active types are stored with ".download"; the part is marked
/// before the rename and the stored file after it.
#[test]
fn shell_active_files_are_stored_neutral_and_marked_twice() {
    let mut p = Pair::new();
    let file = data(100, 13);
    p.tx.send("intranet.url", Box::new(MemSource::new(file.clone(), 1)))
        .unwrap();
    p.run_all();
    assert_eq!(p.dir.names(), ["intranet.url.download"]);
    assert_eq!(p.dir.get("intranet.url.download"), Some(file));
    assert_eq!(p.dir.marked_names(), ["intranet.url.download.remora-part"]);
    assert_eq!(p.dir.finished_names(), ["intranet.url.download"]);
}
