//! Reliable file transfer with resume (RDP-43): pure logic, I/O through
//! [`io::Source`] and [`io::TargetDir`], so the client and the helper run
//! the same engine in both directions.
//!
//! # Flow
//!
//! ```text
//! sender                                   receiver
//!   FileOffer{id,name,size,mtime}  --Ctl-->   validate name; app accepts
//!                                  <--Ctl--   FileAccept{epoch,offset,limit}
//!   FileChunk{epoch,offset,data}   --Bulk->   write to "<name>.remora-part"
//!   FileBlockHash{epoch,i,hash}    --Bulk->   compare, record in sidecar
//!                                  <--Ctl--   FileCredit{epoch,limit}
//!   ...
//!   FileEnd{epoch,root}            --Bulk->   compare root, rename
//!                                  <--Ctl--   FileComplete
//! ```
//!
//! - **Chunks** are at most [`CHUNK_SIZE`] (256 KiB) and never cross a
//!   [`BLOCK_SIZE`] (4 MiB) boundary.
//! - **Flow control:** the receiver grants an absolute byte `limit`; the
//!   sender never sends past it. The receiver moves it to `written +
//!   window` (2 MiB) once less than half a window is left.
//! - **Integrity:** BLAKE3 per 4 MiB block, compared as each block ends;
//!   the root is BLAKE3 over the size and every block hash. A bad block
//!   rewinds to its start (new epoch, at most [`MAX_BLOCK_RETRIES`] times).
//! - **Resume:** the receiver keeps `<name>.remora-part.meta`, a JSON
//!   sidecar with the verified block hashes. After a reconnect the sender
//!   offers the same id again; the receiver re-checks the part file against
//!   the sidecar and accepts at the verified offset. The sender continues
//!   only if the source's size and mtime are unchanged.
//! - **Epochs:** every FileAccept starts a new epoch; data and credits of
//!   older epochs are ignored, so nothing in flight before a rewind counts.
//! - **Names:** checked by [`path::check_name`]; an existing file is never
//!   replaced: the receiver picks `name (2).ext` and so on.

pub mod io;
pub mod path;

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::msg::{FileOffer, Message, TransferId};
use crate::wire::{hex, unhex};
use io::{PartFile, Source, TargetDir};

/// Hash block size (version 1.0 fixes it).
pub const BLOCK_SIZE: u32 = 4 << 20;
/// Largest chunk payload.
pub const CHUNK_SIZE: u32 = 256 << 10;
/// Default flow-control window.
pub const WINDOW: u64 = 2 << 20;
/// Re-sends of one bad block before the transfer fails.
pub const MAX_BLOCK_RETRIES: u32 = 3;
/// Transfers per direction at a time.
pub const MAX_ACTIVE: usize = 32;
/// Suffix of the partial file.
pub const PART_SUFFIX: &str = ".remora-part";
/// Suffix of the sidecar.
pub const META_SUFFIX: &str = ".remora-part.meta";

/// [`Message::FileReject`] and [`Message::FileCancel`] reasons.
pub mod reason {
    pub const USER: u8 = 1;
    /// The direction is switched off (user setting or server policy).
    pub const DISABLED: u8 = 2;
    pub const BAD_NAME: u8 = 3;
    pub const NO_SPACE: u8 = 4;
    pub const IO: u8 = 5;
    pub const INTEGRITY: u8 = 6;
    pub const SOURCE_CHANGED: u8 = 7;
    pub const PROTOCOL: u8 = 8;
    pub const BUSY: u8 = 9;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferEvent {
    /// The peer offers a file; call [`Engine::accept`] or [`Engine::reject`].
    /// `name` passed [`path::check_name`].
    Offered {
        id: TransferId,
        name: String,
        size: u64,
        mtime: u64,
    },
    Progress {
        id: TransferId,
        direction: Direction,
        done: u64,
        total: u64,
    },
    /// The connection dropped; the transfer resumes after a reconnect.
    Paused {
        id: TransferId,
        direction: Direction,
    },
    /// Stored (receiving: under `name`) or confirmed by the receiver.
    Completed {
        id: TransferId,
        direction: Direction,
        name: String,
    },
    /// Rejected, cancelled or failed; see [`reason`].
    Failed {
        id: TransferId,
        direction: Direction,
        reason: u8,
        by_peer: bool,
        detail: String,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub chunk: u32,
    pub window: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            chunk: CHUNK_SIZE,
            window: WINDOW,
        }
    }
}

/// BLAKE3 root over the size and the block hashes.
pub fn root_hash(size: u64, blocks: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("Remora-Link v1 file root");
    h.update(&size.to_le_bytes());
    for b in blocks {
        h.update(b);
    }
    *h.finalize().as_bytes()
}

fn block_count(size: u64) -> u64 {
    size.div_ceil(BLOCK_SIZE as u64)
}

/// End offset of the block that contains `offset`, capped at `size`.
fn block_end(offset: u64, size: u64) -> u64 {
    ((offset / BLOCK_SIZE as u64 + 1) * BLOCK_SIZE as u64).min(size)
}

/// A random transfer id with UUID version 4 bits.
pub fn new_id() -> crate::Result<TransferId> {
    let mut id = [0u8; 16];
    crate::random(&mut id)?;
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    Ok(id)
}

#[derive(Serialize, Deserialize)]
struct Meta {
    v: u32,
    id: String,
    name: String,
    size: u64,
    mtime: u64,
    block: u32,
    blocks: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendState {
    /// Offer sent (or queued while disconnected), waiting for FileAccept.
    Offered,
    Sending,
    /// FileEnd sent, waiting for FileComplete.
    Ended,
}

struct Sending {
    offer: FileOffer,
    source: Box<dyn Source>,
    state: SendState,
    epoch: u32,
    next: u64,
    limit: u64,
    /// Bytes fed into `hashes` + `hasher`, from the start of the file.
    hashed: u64,
    hasher: blake3::Hasher,
    hashes: Vec<[u8; 32]>,
    /// FileEnd went out at least once (FileComplete may follow a reconnect).
    ended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvState {
    /// Waiting for the app to accept or reject.
    Offered,
    Receiving,
    /// Disconnected; waiting for the sender's new offer.
    Paused,
}

struct Receiving {
    offer: FileOffer,
    state: RecvState,
    dir: Option<Box<dyn TargetDir>>,
    /// Target file name; the part file is `name + PART_SUFFIX`.
    name: String,
    part: Option<Box<dyn PartFile>>,
    epoch: u32,
    written: u64,
    limit: u64,
    hasher: blake3::Hasher,
    hashes: Vec<[u8; 32]>,
    retries: u32,
}

impl Receiving {
    fn verified(&self) -> u64 {
        (self.hashes.len() as u64 * BLOCK_SIZE as u64).min(self.offer.size)
    }

    fn meta(&self) -> Meta {
        Meta {
            v: 1,
            id: hex(&self.offer.id),
            name: self.name.clone(),
            size: self.offer.size,
            mtime: self.offer.mtime,
            block: self.offer.block_size,
            blocks: self.hashes.iter().map(|h| hex(h)).collect(),
        }
    }

    fn save_meta(&mut self) -> std::io::Result<()> {
        let json = serde_json::to_vec(&self.meta()).map_err(std::io::Error::other)?;
        let name = format!("{}{META_SUFFIX}", self.name);
        match self.dir.as_mut() {
            Some(d) => d.write_small(&name, &json),
            None => Ok(()),
        }
    }

    /// Back to the last verified block, ready for a new epoch.
    fn rewind(&mut self, window: u64) -> std::io::Result<Message> {
        let v = self.verified();
        if let Some(p) = self.part.as_mut() {
            p.set_len(v)?;
        }
        self.written = v;
        self.hasher = blake3::Hasher::new();
        self.epoch = self.epoch.wrapping_add(1);
        self.limit = (v + window).min(self.offer.size);
        self.state = RecvState::Receiving;
        Ok(Message::FileAccept {
            id: self.offer.id,
            epoch: self.epoch,
            offset: v,
            limit: self.limit,
        })
    }

    fn remove_files(&mut self) {
        self.part = None;
        if let Some(d) = self.dir.as_mut() {
            let _ = d.remove(&format!("{}{PART_SUFFIX}", self.name));
            let _ = d.remove(&format!("{}{META_SUFFIX}", self.name));
        }
    }
}

/// One side's transfers, both directions.
pub struct Engine {
    limits: Limits,
    connected: bool,
    allow_send: bool,
    allow_receive: bool,
    sending: BTreeMap<TransferId, Sending>,
    receiving: BTreeMap<TransferId, Receiving>,
    /// Recently completed incoming ids: a repeated offer (the sender missed
    /// FileComplete in a disconnect) is answered with FileComplete again.
    completed: VecDeque<TransferId>,
    out: Vec<Message>,
    events: VecDeque<TransferEvent>,
    buf: Vec<u8>,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new(Limits::default())
    }
}

impl Engine {
    /// Both directions start off and the link down.
    pub fn new(limits: Limits) -> Engine {
        Engine {
            limits: Limits {
                chunk: limits.chunk.clamp(1, CHUNK_SIZE),
                window: limits.window.max(limits.chunk as u64),
            },
            connected: false,
            allow_send: false,
            allow_receive: false,
            sending: BTreeMap::new(),
            receiving: BTreeMap::new(),
            completed: VecDeque::new(),
            out: Vec::new(),
            events: VecDeque::new(),
            buf: Vec::new(),
        }
    }

    /// Which directions are allowed (capabilities accepted, user setting,
    /// server policy). Switching one off cancels its transfers.
    pub fn set_permissions(&mut self, send: bool, receive: bool) {
        self.allow_send = send;
        self.allow_receive = receive;
        if !send {
            let ids: Vec<_> = self.sending.keys().copied().collect();
            for id in ids {
                self.fail_send(id, reason::DISABLED, "file transfer switched off", true);
            }
        }
        if !receive {
            let ids: Vec<_> = self.receiving.keys().copied().collect();
            for id in ids {
                self.fail_receive(id, reason::DISABLED, "file transfer switched off", true);
            }
        }
    }

    /// Both channels (Ctl and Bulk) are ready (`true`) or one was lost.
    /// Losing the link pauses every transfer; regaining it re-offers the
    /// outgoing ones, which the receiver resumes.
    pub fn set_connected(&mut self, up: bool) {
        if up == self.connected {
            return;
        }
        self.connected = up;
        if !up {
            for (id, s) in &mut self.sending {
                if s.state != SendState::Offered {
                    self.events.push_back(TransferEvent::Paused {
                        id: *id,
                        direction: Direction::Send,
                    });
                }
                s.state = SendState::Offered;
            }
            for (id, r) in &mut self.receiving {
                if r.state == RecvState::Receiving {
                    r.state = RecvState::Paused;
                    self.events.push_back(TransferEvent::Paused {
                        id: *id,
                        direction: Direction::Receive,
                    });
                }
            }
            return;
        }
        for s in self.sending.values_mut() {
            s.state = SendState::Offered;
            // A new connection: any epoch the receiver starts is accepted.
            s.epoch = 0;
            self.out.push(Message::FileOffer(s.offer.clone()));
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Offers a file. `name` is the plain name the receiver will see.
    pub fn send(&mut self, name: &str, mut source: Box<dyn Source>) -> crate::Result<TransferId> {
        if !self.allow_send {
            return Err(crate::Error::State("sending files is switched off"));
        }
        if self.sending.len() >= MAX_ACTIVE {
            return Err(crate::Error::State("too many transfers"));
        }
        path::check_name(name).map_err(|e| crate::Error::Malformed(e.to_string()))?;
        let (size, mtime) = source.stat()?;
        let offer = FileOffer {
            id: new_id()?,
            name: name.to_string(),
            size,
            mtime,
            block_size: BLOCK_SIZE,
        };
        let id = offer.id;
        if self.connected {
            self.out.push(Message::FileOffer(offer.clone()));
        }
        self.sending.insert(
            id,
            Sending {
                offer,
                source,
                state: SendState::Offered,
                epoch: 0,
                next: 0,
                limit: 0,
                hashed: 0,
                hasher: blake3::Hasher::new(),
                hashes: Vec::new(),
                ended: false,
            },
        );
        Ok(id)
    }

    /// Accepts an offered file into `dir`. Resumes from a sidecar there when
    /// one matches the offer.
    pub fn accept(&mut self, id: TransferId, dir: Box<dyn TargetDir>) -> crate::Result<()> {
        let Some(r) = self.receiving.get_mut(&id) else {
            return Err(crate::Error::State("no such offer"));
        };
        if r.state != RecvState::Offered {
            return Err(crate::Error::State("already accepted"));
        }
        r.dir = Some(dir);
        let taken: Vec<String> = self
            .receiving
            .values()
            .filter(|o| o.state != RecvState::Offered)
            .map(|o| o.name.clone())
            .collect();
        let r = self.receiving.get_mut(&id).expect("checked above");
        let res = open_target(r, &taken);
        match res {
            Ok(()) => {}
            Err((code, detail)) => {
                self.fail_receive(id, code, &detail, true);
                return Ok(());
            }
        }
        let window = self.limits.window;
        let r = self.receiving.get_mut(&id).expect("checked above");
        if self.connected {
            match r.rewind(window) {
                Ok(m) => self.out.push(m),
                Err(e) => self.fail_receive(id, reason::IO, &e.to_string(), true),
            }
        } else {
            r.state = RecvState::Paused;
        }
        Ok(())
    }

    pub fn reject(&mut self, id: TransferId) {
        if self.receiving.contains_key(&id) {
            self.fail_receive(id, reason::USER, "rejected", true);
        }
    }

    /// Cancels a transfer in either direction; a received part is deleted.
    pub fn cancel(&mut self, id: TransferId) {
        if self.sending.contains_key(&id) {
            self.fail_send(id, reason::USER, "cancelled", true);
        }
        if self.receiving.contains_key(&id) {
            self.fail_receive(id, reason::USER, "cancelled", true);
        }
    }

    /// Messages to send, in order; route each by [`Message::channel`].
    pub fn take_messages(&mut self) -> Vec<Message> {
        std::mem::take(&mut self.out)
    }

    pub fn next_event(&mut self) -> Option<TransferEvent> {
        self.events.pop_front()
    }

    /// Ids of transfers in progress (either direction).
    pub fn active(&self) -> usize {
        self.sending.len() + self.receiving.len()
    }

    fn progress(&mut self, id: TransferId, direction: Direction, done: u64, total: u64) {
        // Coalesce with a progress event for the same transfer at the back.
        if let Some(TransferEvent::Progress {
            id: last,
            direction: d,
            done: dn,
            ..
        }) = self.events.back_mut()
            && *last == id
            && *d == direction
        {
            *dn = done;
            return;
        }
        self.events.push_back(TransferEvent::Progress {
            id,
            direction,
            done,
            total,
        });
    }

    fn fail_send(&mut self, id: TransferId, code: u8, detail: &str, tell_peer: bool) {
        if self.sending.remove(&id).is_none() {
            return;
        }
        if tell_peer && self.connected {
            self.out.push(Message::FileCancel { id, reason: code });
        }
        self.events.push_back(TransferEvent::Failed {
            id,
            direction: Direction::Send,
            reason: code,
            by_peer: !tell_peer,
            detail: detail.to_string(),
        });
    }

    fn fail_receive(&mut self, id: TransferId, code: u8, detail: &str, tell_peer: bool) {
        let Some(mut r) = self.receiving.remove(&id) else {
            return;
        };
        r.remove_files();
        if tell_peer && self.connected {
            let m = if r.state == RecvState::Offered {
                Message::FileReject { id, reason: code }
            } else {
                Message::FileCancel { id, reason: code }
            };
            self.out.push(m);
        }
        self.events.push_back(TransferEvent::Failed {
            id,
            direction: Direction::Receive,
            reason: code,
            by_peer: !tell_peer,
            detail: detail.to_string(),
        });
    }

    /// Handles a file-transfer message from the peer. Returns false for
    /// messages that are not file-transfer messages. Peer mistakes fail the
    /// transfer, never the channel.
    pub fn handle(&mut self, msg: &Message) -> bool {
        match msg {
            Message::FileOffer(o) => self.on_offer(o),
            Message::FileAccept {
                id,
                epoch,
                offset,
                limit,
            } => self.on_accept(*id, *epoch, *offset, *limit),
            Message::FileReject { id, reason } => {
                self.fail_send(*id, *reason, "rejected by the receiver", false)
            }
            Message::FileCredit { id, epoch, limit } => {
                if let Some(s) = self.sending.get_mut(id)
                    && s.epoch == *epoch
                    && s.state != SendState::Offered
                {
                    s.limit = s.limit.max((*limit).min(s.offer.size));
                }
            }
            Message::FileCancel { id, reason } => {
                self.fail_send(*id, *reason, "cancelled by the peer", false);
                self.fail_receive(*id, *reason, "cancelled by the peer", false);
            }
            Message::FileComplete { id } => match self
                .sending
                .get(id)
                .map(|s| s.state == SendState::Ended || s.ended)
            {
                Some(true) => {
                    let s = self.sending.remove(id).expect("checked above");
                    self.events.push_back(TransferEvent::Completed {
                        id: *id,
                        direction: Direction::Send,
                        name: s.offer.name,
                    });
                }
                Some(false) => {
                    self.fail_send(*id, reason::PROTOCOL, "completed before the end", true)
                }
                None => {}
            },
            Message::FileChunk {
                id,
                epoch,
                offset,
                data,
            } => self.on_chunk(*id, *epoch, *offset, data),
            Message::FileBlockHash {
                id,
                epoch,
                index,
                hash,
            } => self.on_block_hash(*id, *epoch, *index, hash),
            Message::FileEnd { id, epoch, root } => self.on_end(*id, *epoch, root),
            _ => return false,
        }
        true
    }

    fn on_offer(&mut self, o: &FileOffer) {
        if self.completed.contains(&o.id) {
            self.out.push(Message::FileComplete { id: o.id });
            return;
        }
        if let Some(r) = self.receiving.get_mut(&o.id) {
            if r.state == RecvState::Offered {
                return; // still with the user
            }
            if r.offer != *o {
                self.fail_receive(o.id, reason::SOURCE_CHANGED, "the offer changed", true);
                return;
            }
            // Resume after a reconnect.
            let window = self.limits.window;
            match r.rewind(window) {
                Ok(m) => self.out.push(m),
                Err(e) => self.fail_receive(o.id, reason::IO, &e.to_string(), true),
            }
            return;
        }
        let reject = |code| Message::FileReject {
            id: o.id,
            reason: code,
        };
        if !self.allow_receive {
            self.out.push(reject(reason::DISABLED));
            return;
        }
        if o.block_size != BLOCK_SIZE {
            self.out.push(reject(reason::PROTOCOL));
            return;
        }
        if self.receiving.len() >= MAX_ACTIVE {
            self.out.push(reject(reason::BUSY));
            return;
        }
        if let Err(e) = path::check_name(&o.name) {
            self.out.push(reject(reason::BAD_NAME));
            self.events.push_back(TransferEvent::Failed {
                id: o.id,
                direction: Direction::Receive,
                reason: reason::BAD_NAME,
                by_peer: false,
                detail: e.to_string(),
            });
            return;
        }
        self.receiving.insert(
            o.id,
            Receiving {
                offer: o.clone(),
                state: RecvState::Offered,
                dir: None,
                name: o.name.clone(),
                part: None,
                epoch: 0,
                written: 0,
                limit: 0,
                hasher: blake3::Hasher::new(),
                hashes: Vec::new(),
                retries: 0,
            },
        );
        self.events.push_back(TransferEvent::Offered {
            id: o.id,
            name: o.name.clone(),
            size: o.size,
            mtime: o.mtime,
        });
    }

    fn on_accept(&mut self, id: TransferId, epoch: u32, offset: u64, limit: u64) {
        let Some(s) = self.sending.get_mut(&id) else {
            return;
        };
        if epoch <= s.epoch {
            return; // stale or repeated
        }
        let size = s.offer.size;
        let aligned = offset.is_multiple_of(BLOCK_SIZE as u64) || offset == size;
        if offset > size || !aligned || limit < offset {
            self.fail_send(id, reason::PROTOCOL, "bad resume offset", true);
            return;
        }
        match s.source.stat() {
            Ok((len, mtime)) if len == size && mtime == s.offer.mtime => {}
            Ok(_) => {
                self.fail_send(id, reason::SOURCE_CHANGED, "the file changed", true);
                return;
            }
            Err(e) => {
                self.fail_send(id, reason::IO, &e.to_string(), true);
                return;
            }
        }
        s.epoch = epoch;
        s.next = offset;
        s.limit = limit.min(size);
        s.state = SendState::Sending;
        if s.hashed > offset {
            s.hashes.truncate((offset / BLOCK_SIZE as u64) as usize);
            s.hasher = blake3::Hasher::new();
            s.hashed = s.hashes.len() as u64 * BLOCK_SIZE as u64;
        }
    }

    /// Produces chunk, block-hash and end messages for outgoing transfers,
    /// reading at most about `budget` bytes from the sources. Never sends
    /// past a receiver's credit.
    pub fn poll(&mut self, budget: usize) {
        if !self.connected {
            return;
        }
        let mut budget = budget;
        let ids: Vec<_> = self.sending.keys().copied().collect();
        for id in ids {
            if budget == 0 {
                break;
            }
            if let Err((code, detail)) = self.pump(id, &mut budget) {
                self.fail_send(id, code, &detail, true);
            }
        }
    }

    fn pump(&mut self, id: TransferId, budget: &mut usize) -> Result<(), (u8, String)> {
        let chunk = self.limits.chunk as u64;
        let Engine {
            sending, out, buf, ..
        } = self;
        let s = sending.get_mut(&id).expect("listed above");
        if s.state != SendState::Sending {
            return Ok(());
        }
        let size = s.offer.size;
        let before = s.next;
        let io = |e: std::io::Error| (reason::IO, e.to_string());
        // Catch up hashing up to `next` (a resume in a new process).
        while s.hashed < s.next && *budget > 0 {
            let n = chunk
                .min(s.next - s.hashed)
                .min(block_end(s.hashed, size) - s.hashed) as usize;
            buf.resize(n, 0);
            if s.source.read_at(s.hashed, buf).map_err(io)? != n {
                return Err((reason::SOURCE_CHANGED, "the file got shorter".into()));
            }
            feed(s, &buf[..n]);
            *budget = budget.saturating_sub(n);
        }
        if s.hashed < s.next {
            return Ok(());
        }
        while s.next < size && s.next < s.limit && *budget > 0 {
            let n = chunk
                .min(s.limit - s.next)
                .min(block_end(s.next, size) - s.next) as usize;
            buf.resize(n, 0);
            if s.source.read_at(s.next, buf).map_err(io)? != n {
                return Err((reason::SOURCE_CHANGED, "the file got shorter".into()));
            }
            let blocks = s.hashes.len();
            feed(s, &buf[..n]);
            out.push(Message::FileChunk {
                id,
                epoch: s.epoch,
                offset: s.next,
                data: buf[..n].to_vec(),
            });
            s.next += n as u64;
            *budget = budget.saturating_sub(n);
            if s.hashes.len() > blocks {
                out.push(Message::FileBlockHash {
                    id,
                    epoch: s.epoch,
                    index: blocks as u32,
                    hash: s.hashes[blocks],
                });
            }
        }
        let done = s.next;
        if s.next == size && s.hashed == size {
            out.push(Message::FileEnd {
                id,
                epoch: s.epoch,
                root: root_hash(size, &s.hashes),
            });
            s.state = SendState::Ended;
            s.ended = true;
        }
        if done != before {
            self.progress(id, Direction::Send, done, size);
        }
        Ok(())
    }

    fn on_chunk(&mut self, id: TransferId, epoch: u32, offset: u64, data: &[u8]) {
        // The protocol limit, not this side's own (smaller) sending chunk.
        let max_chunk = CHUNK_SIZE as u64;
        let window = self.limits.window;
        let Some(r) = self.receiving.get_mut(&id) else {
            return;
        };
        if r.state != RecvState::Receiving || epoch != r.epoch {
            return; // stale: sent before a rewind or a reconnect
        }
        let size = r.offer.size;
        let len = data.len() as u64;
        let ok = offset == r.written
            && len > 0
            && len <= max_chunk
            && offset + len <= r.limit
            && offset + len <= block_end(offset, size);
        if !ok {
            self.fail_receive(
                id,
                reason::PROTOCOL,
                "chunk outside the credit or order",
                true,
            );
            return;
        }
        let written = r
            .part
            .as_mut()
            .map_or(Err(std::io::ErrorKind::NotFound.into()), |p| {
                p.write_at(offset, data)
            });
        if let Err(e) = written {
            self.fail_receive(id, reason::IO, &e.to_string(), true);
            return;
        }
        r.hasher.update(data);
        r.written += len;
        let done = r.written;
        if r.limit < size && r.limit - r.written <= window / 2 {
            r.limit = (r.written + window).min(size);
            self.out.push(Message::FileCredit {
                id,
                epoch: r.epoch,
                limit: r.limit,
            });
        }
        self.progress(id, Direction::Receive, done, size);
    }

    fn on_block_hash(&mut self, id: TransferId, epoch: u32, index: u32, hash: &[u8; 32]) {
        let window = self.limits.window;
        let Some(r) = self.receiving.get_mut(&id) else {
            return;
        };
        if r.state != RecvState::Receiving || epoch != r.epoch {
            return;
        }
        let size = r.offer.size;
        let start = index as u64 * BLOCK_SIZE as u64;
        if index as usize != r.hashes.len() || start >= size || r.written != block_end(start, size)
        {
            self.fail_receive(id, reason::PROTOCOL, "block hash out of order", true);
            return;
        }
        let mine = *std::mem::replace(&mut r.hasher, blake3::Hasher::new())
            .finalize()
            .as_bytes();
        if mine != *hash {
            r.retries += 1;
            if r.retries > MAX_BLOCK_RETRIES {
                self.fail_receive(id, reason::INTEGRITY, "a block failed verification", true);
                return;
            }
            match r.rewind(window) {
                Ok(m) => self.out.push(m),
                Err(e) => self.fail_receive(id, reason::IO, &e.to_string(), true),
            }
            return;
        }
        r.hashes.push(mine);
        let saved = r
            .part
            .as_mut()
            .map_or(Ok(()), |p| p.sync())
            .and_then(|()| r.save_meta());
        if let Err(e) = saved {
            self.fail_receive(id, reason::IO, &e.to_string(), true);
        }
    }

    fn on_end(&mut self, id: TransferId, epoch: u32, root: &[u8; 32]) {
        let Some(r) = self.receiving.get_mut(&id) else {
            return;
        };
        if r.state != RecvState::Receiving || epoch != r.epoch {
            return;
        }
        let size = r.offer.size;
        if r.written != size || r.hashes.len() as u64 != block_count(size) {
            self.fail_receive(id, reason::PROTOCOL, "end before all data", true);
            return;
        }
        if root_hash(size, &r.hashes) != *root {
            self.fail_receive(id, reason::INTEGRITY, "the file hash does not match", true);
            return;
        }
        match finish(r) {
            Ok(name) => {
                self.receiving.remove(&id);
                if self.completed.len() >= 256 {
                    self.completed.pop_front();
                }
                self.completed.push_back(id);
                self.out.push(Message::FileComplete { id });
                self.events.push_back(TransferEvent::Completed {
                    id,
                    direction: Direction::Receive,
                    name,
                });
            }
            Err(e) => self.fail_receive(id, reason::IO, &e.to_string(), true),
        }
    }
}

/// Feeds sent bytes into the sender's block hashes.
fn feed(s: &mut Sending, data: &[u8]) {
    s.hasher.update(data);
    s.hashed += data.len() as u64;
    if s.hashed.is_multiple_of(BLOCK_SIZE as u64) || s.hashed == s.offer.size {
        let h = std::mem::replace(&mut s.hasher, blake3::Hasher::new());
        s.hashes.push(*h.finalize().as_bytes());
    }
}

/// Picks the target name, or finds a resumable part, and opens it. Errors
/// carry a [`reason`] code.
fn open_target(r: &mut Receiving, taken: &[String]) -> Result<(), (u8, String)> {
    let dir = r.dir.as_mut().expect("set by accept");
    let io = |e: std::io::Error| (reason::IO, e.to_string());
    // A sidecar for this id: resume.
    let id_hex = hex(&r.offer.id);
    for name in dir.list().map_err(io)? {
        let Some(target) = name.strip_suffix(META_SUFFIX) else {
            continue;
        };
        let Ok(bytes) = dir.read_small(&name) else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<Meta>(&bytes) else {
            continue;
        };
        if meta.v != 1
            || meta.id != id_hex
            || meta.size != r.offer.size
            || meta.mtime != r.offer.mtime
            || meta.block != r.offer.block_size
            || meta.name != target
            || path::check_name(target).is_err()
        {
            continue;
        }
        let Ok(mut part) = dir.open(&format!("{target}{PART_SUFFIX}")) else {
            continue;
        };
        // Re-verify the recorded blocks against the part file.
        let mut hashes = Vec::new();
        let mut block = vec![0u8; BLOCK_SIZE as usize];
        for (i, h) in meta.blocks.iter().enumerate() {
            let Some(want) = unhex::<32>(h) else { break };
            let start = i as u64 * BLOCK_SIZE as u64;
            let len = (block_end(start, r.offer.size) - start) as usize;
            if start >= r.offer.size || part.read_at(start, &mut block[..len]).map_err(io)? != len {
                break;
            }
            if *blake3::hash(&block[..len]).as_bytes() != want {
                break;
            }
            hashes.push(want);
        }
        let verified = (hashes.len() as u64 * BLOCK_SIZE as u64).min(r.offer.size);
        if dir
            .free_space()
            .is_some_and(|free| free < r.offer.size - verified)
        {
            return Err((reason::NO_SPACE, "not enough free space".into()));
        }
        r.name = target.to_string();
        r.hashes = hashes;
        r.part = Some(part);
        r.save_meta().map_err(io)?;
        return Ok(());
    }
    if dir.free_space().is_some_and(|free| free < r.offer.size) {
        return Err((reason::NO_SPACE, "not enough free space".into()));
    }
    for n in 1..=1000u32 {
        let cand = if n == 1 {
            r.offer.name.clone()
        } else {
            path::numbered(&r.offer.name, n)
        };
        if path::check_name(&cand).is_err() {
            break;
        }
        let part_name = format!("{cand}{PART_SUFFIX}");
        let meta_name = format!("{cand}{META_SUFFIX}");
        if dir.exists(&cand)
            || dir.exists(&part_name)
            || dir.exists(&meta_name)
            || taken.contains(&cand)
        {
            continue;
        }
        let part = match dir.create_new(&part_name) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        };
        r.name = cand;
        r.part = Some(part);
        r.save_meta().map_err(io)?;
        return Ok(());
    }
    Err((reason::IO, "no free file name".into()))
}

/// Renames the verified part to its final name, never replacing a file.
fn finish(r: &mut Receiving) -> std::io::Result<String> {
    if let Some(mut p) = r.part.take() {
        p.sync()?;
    }
    let dir = r.dir.as_mut().expect("receiving has a folder");
    let part_name = format!("{}{PART_SUFFIX}", r.name);
    let mut last = None;
    for n in 1..=1000u32 {
        let cand = if n == 1 {
            r.name.clone()
        } else {
            path::numbered(&r.offer.name, n)
        };
        match dir.rename_new(&part_name, &cand) {
            Ok(()) => {
                let _ = dir.remove(&format!("{}{META_SUFFIX}", r.name));
                dir.finished(&cand);
                return Ok(cand);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no free file name")))
}

#[cfg(test)]
mod tests;
