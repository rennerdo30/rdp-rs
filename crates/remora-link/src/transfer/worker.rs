//! [`EngineWorker`]: an [`Engine`] on its own thread, so file I/O (reads,
//! writes, `fsync`, the re-hash of a resumed part) never runs on the thread
//! that moves the channel's bytes. Remora's RDP session thread uses it: it
//! posts received file messages and commands, and takes the messages to
//! send; it never waits for the disk.
//!
//! Bounded both ways:
//! - **In:** every posted message is charged until the worker handled it:
//!   [`MSG_COST`] plus its payload (chunk data, an offered name). A peer
//!   sending past its credit, or flooding small messages while the disk is
//!   busy, would exceed [`IN_CAP`] (every transfer's window plus slack),
//!   and [`EngineWorker::post`] says so: the caller closes the channel. An
//!   empty `FileChunk` is refused outright (it carries nothing but cost).
//! - **Out:** the worker reads ahead at most [`OUT_HIGH`] bytes of chunks
//!   that the channel has not taken yet.
//!
//! Commands are applied in the order posted; [`EngineWorker::sync`] waits
//! until everything posted before it is done (tests, shutdown).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use super::io::{Source, TargetDir};
use super::{Engine, Limits, MAX_ACTIVE, TransferEvent, WINDOW, new_id, path};
use crate::msg::{Message, TransferId};

/// Incoming chunk bytes queued at most: every transfer's full window and
/// 4 MiB of slack. A well-behaved peer never gets near it.
pub const IN_CAP: usize = MAX_ACTIVE * WINDOW as usize + (4 << 20);
/// What every queued inbound message costs on top of its payload: the
/// queue node and the message itself, so a flood of small messages is
/// bounded like chunk data.
pub const MSG_COST: usize = 128;
/// Outgoing chunk bytes the worker reads ahead of the channel.
pub const OUT_HIGH: usize = 4 << 20;
/// File bytes read per worker round.
const BUDGET: usize = 1 << 20;
/// How often the worker pumps while sending.
const PUMP: Duration = Duration::from_millis(4);

type Notify = Arc<dyn Fn() + Send + Sync>;

enum Cmd {
    Handle(Message),
    Connected(bool),
    Permissions(bool, bool),
    Send(TransferId, String, Box<dyn Source>),
    Accept(TransferId, Box<dyn TargetDir>),
    Reject(TransferId, u8),
    Cancel(TransferId),
    Sync(Sender<()>),
}

#[derive(Default)]
struct Shared {
    out: Mutex<VecDeque<Message>>,
    events: Mutex<VecDeque<TransferEvent>>,
    out_bytes: AtomicUsize,
    in_bytes: AtomicUsize,
    notify: Mutex<Option<Notify>>,
    /// Transfers in the engine (either direction).
    active: AtomicUsize,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn chunk_len(m: &Message) -> usize {
    match m {
        Message::FileChunk { data, .. } => data.len(),
        _ => 0,
    }
}

/// What a posted message is charged against [`IN_CAP`] until handled.
fn in_cost(m: &Message) -> usize {
    MSG_COST
        + match m {
            Message::FileChunk { data, .. } => data.len(),
            Message::FileOffer(o) => o.name.len(),
            _ => 0,
        }
}

/// What [`EngineWorker::post`] did with a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted {
    Queued,
    /// Not a file-transfer message (answer `Unsupported`).
    NotFile,
    /// The peer sent more than every credit together allows (or more
    /// messages than the worker can queue): close the channel.
    Overflow,
    /// A message no well-behaved peer sends (an empty `FileChunk`): close
    /// the channel.
    Invalid,
}

/// An [`Engine`] on a worker thread. Every method returns at once.
pub struct EngineWorker {
    tx: Sender<Cmd>,
    shared: Arc<Shared>,
    connected: AtomicBool,
    permissions: Mutex<(bool, bool)>,
}

impl Default for EngineWorker {
    fn default() -> Self {
        EngineWorker::new(Limits::default())
    }
}

impl EngineWorker {
    /// Starts the worker (both directions off, link down).
    pub fn new(limits: Limits) -> EngineWorker {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Shared::default());
        let s2 = shared.clone();
        let spawned = std::thread::Builder::new()
            .name("remora-transfer".into())
            .spawn(move || run(Engine::new(limits), rx, s2));
        if spawned.is_err() {
            // No thread: every command is dropped and sync() returns at
            // once; transfers simply never start.
        }
        EngineWorker {
            tx,
            shared,
            connected: AtomicBool::new(false),
            permissions: Mutex::new((false, false)),
        }
    }

    fn cmd(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }

    /// Called (on the worker thread) whenever messages or events wait.
    pub fn set_notify(&self, f: Notify) {
        *lock(&self.shared.notify) = Some(f);
    }

    pub fn set_permissions(&self, send: bool, receive: bool) {
        let mut p = lock(&self.permissions);
        if *p != (send, receive) {
            *p = (send, receive);
            self.cmd(Cmd::Permissions(send, receive));
        }
    }

    pub fn permissions(&self) -> (bool, bool) {
        *lock(&self.permissions)
    }

    /// The link (both channels) is up or down. Going down also drops what
    /// the worker queued for the old link.
    pub fn set_connected(&self, up: bool) {
        if self.connected.swap(up, Ordering::AcqRel) == up {
            return;
        }
        if !up {
            let mut out = lock(&self.shared.out);
            out.clear();
            self.shared.out_bytes.store(0, Ordering::Release);
        }
        self.cmd(Cmd::Connected(up));
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Hands a received message to the engine.
    pub fn post(&self, m: &Message) -> Posted {
        let file = matches!(
            m,
            Message::FileOffer(_)
                | Message::FileAccept { .. }
                | Message::FileReject { .. }
                | Message::FileCredit { .. }
                | Message::FileCancel { .. }
                | Message::FileComplete { .. }
                | Message::FileChunk { .. }
                | Message::FileBlockHash { .. }
                | Message::FileEnd { .. }
        );
        if !file {
            return Posted::NotFile;
        }
        if matches!(m, Message::FileChunk { data, .. } if data.is_empty()) {
            return Posted::Invalid;
        }
        let n = in_cost(m);
        let queued = self.shared.in_bytes.fetch_add(n, Ordering::AcqRel) + n;
        if queued > IN_CAP {
            self.shared.in_bytes.fetch_sub(n, Ordering::AcqRel);
            return Posted::Overflow;
        }
        self.cmd(Cmd::Handle(m.clone()));
        Posted::Queued
    }

    /// Offers a file. The name and the direction are checked here; the
    /// rest (size, too many transfers) comes back as a `Failed` event.
    pub fn send(&self, name: &str, source: Box<dyn Source>) -> crate::Result<TransferId> {
        if !self.permissions().0 {
            return Err(crate::Error::State("sending files is switched off"));
        }
        path::check_name(name).map_err(|e| crate::Error::Malformed(e.to_string()))?;
        let id = new_id()?;
        self.cmd(Cmd::Send(id, name.to_string(), source));
        Ok(id)
    }

    /// Accepts an offered file into `dir` (a resume re-reads the part file
    /// on the worker, never on the caller's thread).
    pub fn accept(&self, id: TransferId, dir: Box<dyn TargetDir>) {
        self.cmd(Cmd::Accept(id, dir));
    }

    pub fn reject(&self, id: TransferId) {
        self.cmd(Cmd::Reject(id, super::reason::USER));
    }

    /// Rejects an offered file with a [`super::reason`] code (`BUSY`, ...).
    pub fn refuse(&self, id: TransferId, reason: u8) {
        self.cmd(Cmd::Reject(id, reason));
    }

    pub fn cancel(&self, id: TransferId) {
        self.cmd(Cmd::Cancel(id));
    }

    /// Messages to send, in order.
    pub fn take_messages(&self) -> Vec<Message> {
        // The byte count changes only under the queue's lock.
        let mut out = lock(&self.shared.out);
        let v: Vec<Message> = out.drain(..).collect();
        let n: usize = v.iter().map(chunk_len).sum();
        self.shared.out_bytes.fetch_sub(n, Ordering::AcqRel);
        v
    }

    pub fn next_event(&self) -> Option<TransferEvent> {
        lock(&self.shared.events).pop_front()
    }

    /// Transfers in progress (either direction), as of the last round.
    pub fn active(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    /// Waits (at most `timeout`) until every command posted before is
    /// done and one more round ran. False on timeout.
    pub fn sync(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        self.cmd(Cmd::Sync(tx));
        rx.recv_timeout(timeout).is_ok()
    }
}

/// The worker thread: apply commands in order, pump outgoing transfers
/// while the channel keeps up, publish messages and events.
fn run(mut engine: Engine, rx: Receiver<Cmd>, shared: Arc<Shared>) {
    loop {
        let sending = engine.is_connected() && engine.sending_active();
        let first = if sending {
            rx.recv_timeout(PUMP)
        } else {
            rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
        };
        let mut syncs = Vec::new();
        let mut next = match first {
            Ok(c) => Some(c),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // A batch of commands, then one pump.
        let mut n = 0;
        while let Some(c) = next.take() {
            match c {
                Cmd::Handle(m) => {
                    let cost = in_cost(&m);
                    engine.handle(&m);
                    shared.in_bytes.fetch_sub(cost, Ordering::AcqRel);
                }
                Cmd::Connected(up) => engine.set_connected(up),
                Cmd::Permissions(s, r) => engine.set_permissions(s, r),
                Cmd::Send(id, name, source) => {
                    if let Err(e) = engine.send_with_id(id, &name, source) {
                        engine.events.push_back(TransferEvent::Failed {
                            id,
                            direction: super::Direction::Send,
                            reason: super::reason::IO,
                            by_peer: false,
                            detail: e.to_string(),
                        });
                    }
                }
                Cmd::Accept(id, dir) => {
                    let _ = engine.accept(id, dir);
                }
                Cmd::Reject(id, reason) => engine.reject_with(id, reason),
                Cmd::Cancel(id) => engine.cancel(id),
                Cmd::Sync(done) => syncs.push(done),
            }
            n += 1;
            if n < 256 {
                next = rx.try_recv().ok();
            }
        }
        if engine.is_connected() && shared.out_bytes.load(Ordering::Acquire) < OUT_HIGH {
            engine.poll(BUDGET);
        }
        let msgs = engine.take_messages();
        let mut events = Vec::new();
        while let Some(e) = engine.next_event() {
            events.push(e);
        }
        shared.active.store(engine.active(), Ordering::Release);
        let any = !msgs.is_empty() || !events.is_empty();
        if !msgs.is_empty() {
            let bytes: usize = msgs.iter().map(chunk_len).sum();
            let mut out = lock(&shared.out);
            shared.out_bytes.fetch_add(bytes, Ordering::AcqRel);
            out.extend(msgs);
        }
        if !events.is_empty() {
            lock(&shared.events).extend(events);
        }
        if any && let Some(f) = lock(&shared.notify).clone() {
            f();
        }
        for s in syncs {
            let _ = s.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::io::{MemDir, MemSource};
    use super::*;

    const T: Duration = Duration::from_secs(10);

    /// Two workers move a file; the callers only post and take.
    #[test]
    fn a_transfer_runs_on_the_workers() {
        let tx = EngineWorker::default();
        let rx = EngineWorker::default();
        tx.set_permissions(true, false);
        rx.set_permissions(false, true);
        tx.set_connected(true);
        rx.set_connected(true);
        let dir = MemDir::new();
        let data: Vec<u8> = (0..(9u32 << 20)).map(|i| (i * 13) as u8).collect();
        let id = tx
            .send("w.bin", Box::new(MemSource::new(data.clone(), 1)))
            .unwrap();
        let mut done = false;
        for _ in 0..20_000 {
            tx.sync(T);
            for m in tx.take_messages() {
                assert_eq!(rx.post(&m), Posted::Queued);
            }
            rx.sync(T);
            while let Some(e) = rx.next_event() {
                if let TransferEvent::Offered { id: o, .. } = e {
                    rx.accept(o, Box::new(dir.clone()));
                }
            }
            for m in rx.take_messages() {
                tx.post(&m);
            }
            while let Some(e) = tx.next_event() {
                if let TransferEvent::Completed { id: c, .. } = e {
                    assert_eq!(c, id);
                    done = true;
                }
            }
            if done {
                break;
            }
        }
        assert!(done, "completed");
        assert_eq!(dir.get("w.bin"), Some(data));
        assert_eq!(tx.active(), 0);
    }

    /// A folder whose listing waits until released: keeps the worker busy.
    struct Gate {
        dir: MemDir,
        open: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl TargetDir for Gate {
        fn exists(&self, n: &str) -> bool {
            self.dir.exists(n)
        }
        fn create_new(&mut self, n: &str) -> std::io::Result<Box<dyn super::super::io::PartFile>> {
            self.dir.create_new(n)
        }
        fn open(&mut self, n: &str) -> std::io::Result<Box<dyn super::super::io::PartFile>> {
            self.dir.open(n)
        }
        fn read_small(&self, n: &str) -> std::io::Result<Vec<u8>> {
            self.dir.read_small(n)
        }
        fn write_small(&mut self, n: &str, d: &[u8]) -> std::io::Result<()> {
            self.dir.write_small(n, d)
        }
        fn append(&mut self, n: &str, d: &[u8]) -> std::io::Result<()> {
            self.dir.append(n, d)
        }
        fn remove(&mut self, n: &str) -> std::io::Result<()> {
            self.dir.remove(n)
        }
        fn rename_new(&mut self, a: &str, b: &str) -> std::io::Result<()> {
            self.dir.rename_new(a, b)
        }
        fn list(&self) -> std::io::Result<Vec<String>> {
            let (m, cv) = &*self.open;
            let mut open = m.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            self.dir.list()
        }
    }

    /// A peer that ignores its credit while the disk is busy fills the
    /// inbound bound and is told so, instead of growing memory without end.
    #[test]
    fn chunks_past_every_credit_overflow() {
        let rx = EngineWorker::default();
        rx.set_permissions(false, true);
        rx.set_connected(true);
        rx.post(&Message::FileOffer(crate::msg::FileOffer {
            id: [1; 16],
            name: "x".into(),
            size: 1 << 40,
            mtime: 1,
            block_size: super::super::BLOCK_SIZE,
        }));
        assert!(rx.sync(T));
        // The accept blocks the worker in the folder listing.
        let open = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        rx.accept(
            [1; 16],
            Box::new(Gate {
                dir: MemDir::new(),
                open: open.clone(),
            }),
        );
        let chunk = Message::FileChunk {
            id: [1; 16],
            epoch: 1,
            offset: 0,
            data: vec![0; super::super::CHUNK_SIZE as usize],
        };
        // The offer is handled already; each chunk costs its data and MSG_COST.
        let fits = IN_CAP / (super::super::CHUNK_SIZE as usize + MSG_COST);
        for i in 0..fits {
            assert_eq!(rx.post(&chunk), Posted::Queued, "chunk {i}");
        }
        assert_eq!(rx.post(&chunk), Posted::Overflow);
        assert_eq!(rx.post(&Message::Heartbeat { seq: 1 }), Posted::NotFile);
        *open.0.lock().unwrap() = true;
        open.1.notify_all();
        assert!(rx.sync(T));
        assert_eq!(
            rx.shared.in_bytes.load(Ordering::Acquire),
            0,
            "all processed"
        );
    }

    /// Going down drops what was read ahead for the old link.
    #[test]
    fn going_down_drops_read_ahead() {
        let tx = EngineWorker::default();
        tx.set_permissions(true, false);
        tx.set_connected(true);
        let id = tx
            .send("a", Box::new(MemSource::new(vec![1; 1000], 1)))
            .unwrap();
        tx.sync(T);
        assert!(!tx.take_messages().is_empty(), "the offer");
        tx.post(&Message::FileAccept {
            id,
            epoch: 1,
            offset: 0,
            limit: 1000,
        });
        tx.sync(T);
        assert!(
            tx.shared.out_bytes.load(Ordering::Acquire) > 0,
            "read ahead"
        );
        tx.set_connected(false);
        assert!(tx.take_messages().is_empty());
        assert_eq!(tx.shared.out_bytes.load(Ordering::Acquire), 0);
    }

    /// Review 2 item 3: small messages (and empty chunks) are charged too.
    /// While the worker is busy, a peer flooding offers and block hashes
    /// hits the bound instead of growing the queue without end, and an
    /// empty chunk is refused outright.
    #[test]
    fn small_messages_are_bounded_while_the_worker_is_busy() {
        let rx = EngineWorker::default();
        rx.set_permissions(false, true);
        rx.set_connected(true);
        rx.post(&Message::FileOffer(crate::msg::FileOffer {
            id: [1; 16],
            name: "x".into(),
            size: 1 << 30,
            mtime: 1,
            block_size: super::super::BLOCK_SIZE,
        }));
        assert!(rx.sync(T));
        let open = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        rx.accept(
            [1; 16],
            Box::new(Gate {
                dir: MemDir::new(),
                open: open.clone(),
            }),
        );
        let empty = Message::FileChunk {
            id: [2; 16],
            epoch: 1,
            offset: 0,
            data: Vec::new(),
        };
        assert_eq!(rx.post(&empty), Posted::Invalid);
        let name = "n".repeat(1024);
        let (mut queued, mut overflow) = (0usize, false);
        for i in 0..2_000_000u32 {
            let m = if i % 2 == 0 {
                Message::FileBlockHash {
                    id: [2; 16],
                    epoch: 1,
                    index: i,
                    hash: [0; 32],
                }
            } else {
                Message::FileOffer(crate::msg::FileOffer {
                    id: [3; 16],
                    name: name.clone(),
                    size: 1,
                    mtime: 1,
                    block_size: super::super::BLOCK_SIZE,
                })
            };
            match rx.post(&m) {
                Posted::Queued => queued += 1,
                Posted::Overflow => {
                    overflow = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(overflow, "the flood hit the bound ({queued} queued)");
        assert!(queued <= IN_CAP / MSG_COST, "{queued} queued");
        *open.0.lock().unwrap() = true;
        open.1.notify_all();
        assert!(rx.sync(Duration::from_secs(60)));
        assert_eq!(rx.shared.in_bytes.load(Ordering::Acquire), 0, "all handled");
    }
}
