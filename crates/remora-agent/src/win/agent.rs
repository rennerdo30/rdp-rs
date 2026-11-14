//! The agent's event loop: one thread runs the [`Lifecycle`] and the
//! [`Protocol`] ([`LinkProtocol`]); IO threads (channel open, reader,
//! writer, session window, local pipe, pairing dialog) feed it through one
//! mpsc channel.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::System::Threading::CreateMutexW;

use super::dpapi::Dpapi;
use super::files::WinFiles;
use super::ui::WinPairingUi;
use super::wts::{self, WtsChunkIo};
use super::{OwnedHandle, pipe, sys, wide, window};
use crate::closing;
use crate::framing::{DvcPipe, MessagePipe};
use crate::info::CpuTimes;
use crate::keystore::{self, KeyOrigin};
use crate::lifecycle::{LifeAction, Lifecycle, SessionChange};
use crate::link::{FileClients, LinkProtocol};
use crate::links;
use crate::seam::{Action, AgentEvent, Channel, Protocol, SendOutcome, UrlOutcome};
use crate::{info, warn};
use remora_link::StaticKey;

/// How often a session snapshot goes to the protocol while Ctl is open.
const TICK: Duration = Duration::from_secs(5);
/// Messages queued per channel writer before `Send` waits.
const WRITE_QUEUE: usize = 64;
/// How often a blocked reader checks whether its channel was closed.
const READ_POLL: Duration = Duration::from_secs(1);

/// Everything the event loop reacts to.
pub enum Input {
    /// `WM_WTSSESSION_CHANGE` code.
    Session(u32),
    Opened {
        ch: Channel,
        generation: u64,
        result: io::Result<OwnedHandle>,
    },
    Message {
        ch: Channel,
        generation: u64,
        data: Vec<u8>,
    },
    Closed {
        ch: Channel,
        generation: u64,
        reason: String,
    },
    OpenUrl {
        url: String,
        reply: Sender<UrlOutcome>,
    },
    /// `remora-agent send` over the pipe.
    SendFiles {
        paths: Vec<PathBuf>,
        reply: Sender<SendOutcome>,
    },
    /// The user answered the pairing dialog.
    PairingAnswer { ticket: u64, confirmed: bool },
    /// The transfer worker has messages or events for the protocol.
    TransferWake,
    /// Exit; `done` is signalled once the loop has finished.
    Shutdown { done: Option<Sender<()>> },
}

struct OpenChannel {
    file: Arc<OwnedHandle>,
    writer: SyncSender<Vec<u8>>,
    /// Fires (disconnects) when the writer has sent everything and ended.
    writer_done: Receiver<()>,
    stop: Arc<AtomicBool>,
}

impl OpenChannel {
    /// Stops the channel: the writer first sends what was queued (the last
    /// `PeerPairing` or `Error` of a refused session), at most
    /// [`closing::FLUSH_WAIT`], then its I/O is cancelled. Returns the
    /// thread that waits for that (shutdown joins it).
    fn close(self) -> Option<std::thread::JoinHandle<()>> {
        self.stop.store(true, Ordering::SeqCst);
        drop(self.writer);
        let file = self.file;
        closing::close_after_flush(self.writer_done, closing::FLUSH_WAIT, move || {
            wts::cancel_all(&file)
        })
    }
}

/// `agent run`. Returns the exit code.
pub fn run() -> i32 {
    // One agent per session: `Local\` is the session's namespace.
    let name = wide(r"Local\RemoraAgent.Run");
    // SAFETY: named mutex, held (never released) for the process lifetime.
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    // SAFETY: plain call.
    if mutex.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        info!("another agent runs in this session; exiting");
        return 0;
    }
    let _mutex = OwnedHandle(mutex);
    crate::logging::set_debug(std::env::var_os("REMORA_AGENT_DEBUG").is_some_and(|v| v == "1"));
    info!(
        "agent {} started in session {}",
        env!("CARGO_PKG_VERSION"),
        sys::current_session_id()
    );
    let Some(key) = load_key() else {
        return 1;
    };
    let code = event_loop(key);
    info!("agent exiting");
    code
}

/// The user's agent key, DPAPI-protected in `%LOCALAPPDATA%`. Without a
/// usable location the key lives for this process only (Remora then sees a
/// changed key each start and asks to compare codes).
fn load_key() -> Option<StaticKey> {
    let generate = || StaticKey::generate().map_err(|e| io::Error::other(e.to_string()));
    let Some(path) = keystore::default_key_path() else {
        warn!("LOCALAPPDATA is not set; the agent key is not kept");
        return generate()
            .inspect_err(|e| warn!("cannot make a key: {e}"))
            .ok();
    };
    match keystore::load_or_create(&path, &Dpapi, &generate) {
        Ok(k) => {
            match &k.origin {
                KeyOrigin::Loaded => info!("agent key loaded"),
                KeyOrigin::Created => info!("agent key created"),
                KeyOrigin::Replaced(why) => {
                    warn!("agent key replaced ({why}); Remora will ask to compare codes again")
                }
            }
            if let Some(e) = &k.save_error {
                warn!("agent key not saved ({e}); it lasts for this run only");
            }
            Some(k.key)
        }
        Err(e) => {
            warn!("cannot make a key: {e}");
            None
        }
    }
}

struct Loop {
    tx: Sender<Input>,
    life: Lifecycle,
    protocol: Box<dyn Protocol>,
    open: [Option<OpenChannel>; 2],
    next_request: u64,
    pending_urls: BTreeMap<u64, Sender<UrlOutcome>>,
    pending_sends: BTreeMap<u64, Sender<SendOutcome>>,
    static_info: Option<sys::StaticInfo>,
    cpu_prev: Option<CpuTimes>,
    shutting_down: bool,
    /// A `TransferWake` is in the queue.
    wake_queued: Arc<AtomicBool>,
}

/// Pipe requests waiting for the protocol's answer at a time; an older one
/// is dropped (its pipe client then sees "no client").
const MAX_PENDING_REQUESTS: usize = 8;

fn event_loop(key: StaticKey) -> i32 {
    let (tx, rx) = mpsc::channel::<Input>();
    let protocol = Box::new(LinkProtocol::new(
        key,
        Box::new(WinPairingUi::new(tx.clone())),
        Box::new(WinFiles),
        Box::new(FileClients {
            clients: keystore::default_clients_path(),
            setting: keystore::default_strict_path(),
            policy: sys::pinned_clients_policy,
        }),
    ));
    // The transfer worker wakes the loop; a wake already queued is enough.
    let wake_tx = std::sync::Mutex::new(tx.clone());
    let queued = Arc::new(AtomicBool::new(false));
    let q2 = queued.clone();
    protocol.set_transfer_notify(move || {
        if !q2.swap(true, Ordering::AcqRel)
            && let Ok(t) = wake_tx.lock()
        {
            let _ = t.send(Input::TransferWake);
        }
    });
    let window = match window::spawn(tx.clone()) {
        Ok(w) => Some(w),
        Err(e) => {
            warn!("no session window ({e}); reconnects will not reopen channels");
            None
        }
    };
    match sys::current_user() {
        Ok((sid, _)) => {
            let name = links::pipe_name(sys::current_session_id(), &sid);
            if let Err(e) = pipe::spawn_server(&name, &sid, tx.clone()) {
                warn!("open-url pipe unavailable: {e}");
            }
        }
        Err(e) => warn!("cannot read the current user ({e}); open-url pipe off"),
    }
    let mut lp = Loop {
        tx,
        life: Lifecycle::new(),
        protocol,
        open: [None, None],
        next_request: 1,
        pending_urls: BTreeMap::new(),
        pending_sends: BTreeMap::new(),
        static_info: None,
        cpu_prev: None,
        shutting_down: false,
        wake_queued: queued,
    };
    let remote = sys::remote_connected();
    info!(
        "session is {}",
        if remote {
            "remote-connected"
        } else {
            "not remote-connected; idle"
        }
    );
    let actions = lp.life.start(remote);
    lp.run_life(actions);
    lp.run(&rx);
    if let Some(w) = window {
        w.close();
    }
    0
}

impl Loop {
    fn run(&mut self, rx: &Receiver<Input>) {
        let mut next_tick = Instant::now() + TICK;
        while !self.shutting_down {
            let now = Instant::now();
            let deadline = [
                Some(next_tick),
                self.life.next_deadline(),
                self.protocol.next_deadline(),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(next_tick);
            match rx.recv_timeout(deadline.saturating_duration_since(now)) {
                Ok(input) => self.handle(input),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let now = Instant::now();
            let due = self.life.poll(now);
            self.run_life(due);
            if now >= next_tick {
                next_tick = now + TICK;
                self.tick();
            }
            if self.protocol.next_deadline().is_some_and(|d| d <= now) {
                self.feed(AgentEvent::Timer);
            }
        }
    }

    fn request_id(&mut self) -> u64 {
        let id = self.next_request;
        self.next_request += 1;
        id
    }

    fn handle(&mut self, input: Input) {
        let now = Instant::now();
        match input {
            Input::Session(code) => {
                let ev = SessionChange::from_code(code);
                info!("session event {ev:?}");
                let actions = self.life.on_session(ev);
                self.run_life(actions);
                if matches!(ev, SessionChange::Lock | SessionChange::Unlock) {
                    self.tick();
                }
            }
            Input::Opened {
                ch,
                generation,
                result,
            } => {
                let ok = result.is_ok();
                let keep = self.life.on_open_result(ch, generation, ok, now);
                match result {
                    Ok(file) if keep => self.attach(ch, generation, file),
                    Ok(_) => info!("{} opened late; dropped", ch.dvc_name()),
                    // Expected under mstsc or without the Remora listener.
                    Err(e) => info!("{} not opened: {e}", ch.dvc_name()),
                }
            }
            Input::Message {
                ch,
                generation,
                data,
            } => {
                if self.life.open_generation(ch) == Some(generation) {
                    self.feed(AgentEvent::Message(ch, data));
                }
            }
            Input::Closed {
                ch,
                generation,
                reason,
            } => {
                if self.life.on_closed(ch, generation, now, true) {
                    info!("{} closed: {reason}", ch.dvc_name());
                    self.detach(ch);
                }
            }
            Input::OpenUrl { url, reply } => {
                info!("open-url request ({} bytes)", url.len());
                let id = self.request_id();
                self.pending_urls.insert(id, reply);
                // Bound the map: a dropped sender reads as "no client".
                while self.pending_urls.len() > MAX_PENDING_REQUESTS {
                    self.pending_urls.pop_first();
                }
                self.feed(AgentEvent::OpenUrl { id, url });
            }
            Input::SendFiles { paths, reply } => {
                info!("send request ({} files)", paths.len());
                let id = self.request_id();
                self.pending_sends.insert(id, reply);
                while self.pending_sends.len() > MAX_PENDING_REQUESTS {
                    self.pending_sends.pop_first();
                }
                self.feed(AgentEvent::SendFiles { id, paths });
            }
            Input::PairingAnswer { ticket, confirmed } => {
                self.feed(AgentEvent::PairingAnswer { ticket, confirmed });
            }
            Input::TransferWake => {
                self.wake_queued.store(false, Ordering::Release);
                self.feed(AgentEvent::Timer);
            }
            Input::Shutdown { done } => {
                self.shutdown();
                if let Some(d) = done {
                    let _ = d.send(());
                }
            }
        }
    }

    fn shutdown(&mut self) {
        if self.shutting_down {
            return;
        }
        info!("shutting down");
        self.feed(AgentEvent::Shutdown);
        // The last messages go out before the process ends (bounded).
        let mut flushing = Vec::new();
        for ch in Channel::ALL {
            if let Some(oc) = self.open[ch.index()].take() {
                flushing.extend(oc.close());
            }
        }
        for t in flushing {
            let _ = t.join();
        }
        self.shutting_down = true;
    }

    fn run_life(&mut self, actions: Vec<LifeAction>) {
        for a in actions {
            match a {
                LifeAction::Open(ch, generation) => self.start_open(ch, generation),
                LifeAction::Close(ch) => self.detach(ch),
                LifeAction::Shutdown => self.shutdown(),
            }
        }
    }

    fn start_open(&self, ch: Channel, generation: u64) {
        let tx = self.tx.clone();
        // The open may block until the client answers; a stale result is
        // ignored by generation.
        let spawned = std::thread::Builder::new()
            .name(format!("open-{}", ch.dvc_name()))
            .spawn(move || {
                let result = wts::open_channel(ch);
                let _ = tx.send(Input::Opened {
                    ch,
                    generation,
                    result,
                });
            });
        if let Err(e) = spawned {
            warn!("cannot start opener thread: {e}");
        }
    }

    fn attach(&mut self, ch: Channel, generation: u64, file: OwnedHandle) {
        let file = Arc::new(file);
        let stop = Arc::new(AtomicBool::new(false));
        let (wtx, wrx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let started = spawn_reader(ch, generation, file.clone(), stop.clone(), self.tx.clone())
            .and_then(|()| {
                spawn_writer(ch, generation, file.clone(), wrx, done_tx, self.tx.clone())
            });
        let oc = OpenChannel {
            file,
            writer: wtx,
            writer_done: done_rx,
            stop,
        };
        if let Err(e) = started {
            warn!("{}: cannot start IO threads: {e}", ch.dvc_name());
            oc.close();
            self.life.on_closed(ch, generation, Instant::now(), true);
            return;
        }
        info!("{} open", ch.dvc_name());
        self.open[ch.index()] = Some(oc);
        if ch == Channel::Ctl {
            self.static_info = Some(sys::static_info());
        }
        self.feed(AgentEvent::ChannelOpened(ch));
        if ch == Channel::Ctl {
            // The protocol's Hello needs a snapshot; do not wait a tick.
            self.tick();
        }
    }

    fn detach(&mut self, ch: Channel) {
        if let Some(oc) = self.open[ch.index()].take() {
            oc.close();
            self.feed(AgentEvent::ChannelClosed(ch));
        }
    }

    fn tick(&mut self) {
        if !self.life.is_open(Channel::Ctl) {
            return;
        }
        let s = self.static_info.get_or_insert_with(sys::static_info);
        let snapshot = sys::collect(s, &mut self.cpu_prev);
        self.feed(AgentEvent::SessionInfoTick(snapshot));
    }

    fn feed(&mut self, ev: AgentEvent) {
        let actions = self.protocol.on_event(ev);
        for a in actions {
            match a {
                Action::Send(ch, msg) => match &self.open[ch.index()] {
                    // Blocks only while the writer's queue is full; the
                    // writer never waits on this loop.
                    Some(oc) => {
                        if oc.writer.send(msg).is_err() {
                            warn!("{}: writer gone; message dropped", ch.dvc_name());
                        }
                    }
                    None => warn!(
                        "{}: send of {} bytes on a closed channel dropped",
                        ch.dvc_name(),
                        msg.len()
                    ),
                },
                Action::Close(ch) => {
                    // Also cancels a pending open (its result is dropped).
                    self.life.close(ch);
                    if let Some(oc) = self.open[ch.index()].take() {
                        info!("{} closed by the protocol", ch.dvc_name());
                        oc.close();
                    }
                }
                Action::OpenChannel(ch) => {
                    let opens = self.life.request_open(ch);
                    self.run_life(opens);
                }
                Action::OpenUrlResult { id, outcome } => {
                    if let Some(reply) = self.pending_urls.remove(&id) {
                        let _ = reply.send(outcome);
                    }
                }
                Action::SendFilesResult { id, outcome } => {
                    if let Some(reply) = self.pending_sends.remove(&id) {
                        let _ = reply.send(outcome);
                    }
                }
            }
        }
    }
}

fn spawn_reader(
    ch: Channel,
    generation: u64,
    file: Arc<OwnedHandle>,
    stop: Arc<AtomicBool>,
    tx: Sender<Input>,
) -> io::Result<()> {
    let io = WtsChunkIo::new(file)?;
    std::thread::Builder::new()
        .name(format!("read-{}", ch.dvc_name()))
        .spawn(move || {
            let mut pipe = DvcPipe::new(io);
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                match pipe.recv(READ_POLL) {
                    Ok(Some(data)) => {
                        let msg = Input::Message {
                            ch,
                            generation,
                            data,
                        };
                        if tx.send(msg).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        if !stop.load(Ordering::SeqCst) {
                            let _ = tx.send(Input::Closed {
                                ch,
                                generation,
                                reason: e.to_string(),
                            });
                        }
                        return;
                    }
                }
            }
        })?;
    Ok(())
}

/// The channel's writer: sends queued messages in order until the queue's
/// sender is dropped and the queue is empty, then drops `done` (the close
/// waits for that before cancelling the channel's I/O).
fn spawn_writer(
    ch: Channel,
    generation: u64,
    file: Arc<OwnedHandle>,
    rx: Receiver<Vec<u8>>,
    done: Sender<()>,
    tx: Sender<Input>,
) -> io::Result<()> {
    let io = WtsChunkIo::new(file)?;
    std::thread::Builder::new()
        .name(format!("write-{}", ch.dvc_name()))
        .spawn(move || {
            let _done = done;
            let mut pipe = DvcPipe::new(io);
            for msg in rx {
                if let Err(e) = pipe.send(&msg) {
                    let _ = tx.send(Input::Closed {
                        ch,
                        generation,
                        reason: format!("write failed: {e}"),
                    });
                    return;
                }
            }
        })?;
    Ok(())
}
