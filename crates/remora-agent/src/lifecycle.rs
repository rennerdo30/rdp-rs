//! When to open and close the channels (RDP-42, HELPER-PROTOCOL.md 1): a
//! pure state machine fed with session events and open results, so the
//! policy is tested without Windows.
//!
//! - A DVC exists only while an RDP client is attached, so `Remora::Ctl` is
//!   opened when the session is remote-connected (at start and on every
//!   `WTS_REMOTE_CONNECT`); both channels close on `WTS_REMOTE_DISCONNECT`
//!   or when the session moves to the console.
//! - `Remora::Bulk` opens only on request ([`Lifecycle::request_open`],
//!   after `HelloAck`): Remora closes a Bulk channel that opens earlier. A
//!   new connect or [`Lifecycle::close`] cancels the request.
//! - An open that fails (mstsc or another client without a Remora listener)
//!   is retried with a slow backoff while the session stays connected (and,
//!   for Bulk, while it is wanted): 30 s, doubling, capped at 10 min. A new
//!   connect resets it.
//! - Every open attempt carries a generation; results of an older attempt
//!   (the open can block for a long time) are ignored.

use std::time::{Duration, Instant};

use crate::seam::Channel;

pub const BACKOFF_FIRST: Duration = Duration::from_secs(30);
pub const BACKOFF_CAP: Duration = Duration::from_secs(600);

/// `WM_WTSSESSION_CHANGE` codes the agent reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionChange {
    ConsoleConnect,
    ConsoleDisconnect,
    RemoteConnect,
    RemoteDisconnect,
    Logoff,
    Lock,
    Unlock,
    Other(u32),
}

impl SessionChange {
    /// From `wParam` of `WM_WTSSESSION_CHANGE` (`winuser.h` `WTS_*`).
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::ConsoleConnect,
            2 => Self::ConsoleDisconnect,
            3 => Self::RemoteConnect,
            4 => Self::RemoteDisconnect,
            6 => Self::Logoff,
            7 => Self::Lock,
            8 => Self::Unlock,
            c => Self::Other(c),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifeAction {
    /// Start opening the channel; report the result with this generation.
    Open(Channel, u64),
    /// Close the channel if it is open.
    Close(Channel),
    /// Exit the agent.
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Opening(u64),
    Open(u64),
}

#[derive(Debug, Clone, Copy)]
struct Chan {
    state: State,
    backoff: Duration,
    retry_at: Option<Instant>,
    /// Opened on connect (Ctl) or only while requested (Bulk).
    on_demand: bool,
    /// Bulk: requested and not closed since.
    wanted: bool,
}

impl Chan {
    fn should_run(&self, remote: bool) -> bool {
        remote && (!self.on_demand || self.wanted)
    }
}

#[derive(Debug)]
pub struct Lifecycle {
    remote: bool,
    next_gen: u64,
    chans: [Chan; 2],
}

impl Lifecycle {
    pub fn new() -> Self {
        let c = Chan {
            state: State::Closed,
            backoff: BACKOFF_FIRST,
            retry_at: None,
            on_demand: false,
            wanted: false,
        };
        let mut chans = [c; 2];
        chans[Channel::Bulk.index()].on_demand = true;
        Self {
            remote: false,
            next_gen: 1,
            chans,
        }
    }

    /// At start: open at once if the session is remote-connected; on the
    /// console, stay idle until a client connects.
    pub fn start(&mut self, remote_connected: bool) -> Vec<LifeAction> {
        if remote_connected {
            self.on_session(SessionChange::RemoteConnect)
        } else {
            Vec::new()
        }
    }

    fn begin_open(&mut self, ch: Channel) -> LifeAction {
        let g = self.next_gen;
        self.next_gen += 1;
        let c = &mut self.chans[ch.index()];
        c.retry_at = None;
        c.state = State::Opening(g);
        LifeAction::Open(ch, g)
    }

    pub fn on_session(&mut self, ev: SessionChange) -> Vec<LifeAction> {
        let mut out = Vec::new();
        match ev {
            SessionChange::RemoteConnect => {
                self.remote = true;
                for ch in Channel::ALL {
                    let c = &mut self.chans[ch.index()];
                    // A reconnect gives a new client; the old channel is dead.
                    if matches!(c.state, State::Open(_)) {
                        out.push(LifeAction::Close(ch));
                    }
                    c.state = State::Closed;
                    c.backoff = BACKOFF_FIRST;
                    c.retry_at = None;
                    c.wanted = false;
                    if !c.on_demand {
                        out.push(self.begin_open(ch));
                    }
                }
            }
            SessionChange::RemoteDisconnect | SessionChange::ConsoleConnect => {
                self.remote = false;
                for ch in Channel::ALL {
                    let c = &mut self.chans[ch.index()];
                    if matches!(c.state, State::Open(_)) {
                        out.push(LifeAction::Close(ch));
                    }
                    // A pending open is now stale; its result is dropped.
                    c.state = State::Closed;
                    c.retry_at = None;
                    c.wanted = false;
                }
            }
            SessionChange::Logoff => out.push(LifeAction::Shutdown),
            SessionChange::ConsoleDisconnect
            | SessionChange::Lock
            | SessionChange::Unlock
            | SessionChange::Other(_) => {}
        }
        out
    }

    /// The protocol asks for an on-demand channel (Bulk after `HelloAck`).
    pub fn request_open(&mut self, ch: Channel) -> Vec<LifeAction> {
        let c = &mut self.chans[ch.index()];
        c.wanted = true;
        if !self.remote || c.state != State::Closed {
            return Vec::new();
        }
        c.backoff = BACKOFF_FIRST;
        vec![self.begin_open(ch)]
    }

    /// The protocol closes a channel (failed authentication, rejected
    /// pairing, Bulk after Ctl). No retry before the next connect or
    /// request; a pending open's result is dropped. Returns whether the
    /// channel was open.
    pub fn close(&mut self, ch: Channel) -> bool {
        let c = &mut self.chans[ch.index()];
        let was_open = matches!(c.state, State::Open(_));
        c.state = State::Closed;
        c.retry_at = None;
        c.wanted = false;
        was_open
    }

    /// The result of an `Open`. Returns whether the channel should be kept:
    /// `false` for a stale success, which the caller closes again.
    pub fn on_open_result(&mut self, ch: Channel, generation: u64, ok: bool, now: Instant) -> bool {
        let remote = self.remote;
        let c = &mut self.chans[ch.index()];
        if c.state != State::Opening(generation) {
            return false;
        }
        if ok {
            c.state = State::Open(generation);
            c.backoff = BACKOFF_FIRST;
            c.retry_at = None;
            true
        } else {
            c.state = State::Closed;
            let run = c.should_run(remote);
            Self::schedule_retry(c, run, now);
            false
        }
    }

    /// The channel closed by itself (client closed it, read error): retried
    /// with backoff while the session is connected. With `retry` false it
    /// stays closed until the next client connect. Returns whether the
    /// event was for the current channel.
    pub fn on_closed(&mut self, ch: Channel, generation: u64, now: Instant, retry: bool) -> bool {
        let remote = self.remote;
        let c = &mut self.chans[ch.index()];
        if c.state != State::Open(generation) {
            return false;
        }
        c.state = State::Closed;
        let run = c.should_run(remote) && retry;
        Self::schedule_retry(c, run, now);
        true
    }

    fn schedule_retry(c: &mut Chan, run: bool, now: Instant) {
        if !run {
            c.retry_at = None;
            return;
        }
        c.retry_at = Some(now + c.backoff);
        c.backoff = (c.backoff * 2).min(BACKOFF_CAP);
    }

    /// Retries that are due.
    pub fn poll(&mut self, now: Instant) -> Vec<LifeAction> {
        let mut out = Vec::new();
        for ch in Channel::ALL {
            let c = &self.chans[ch.index()];
            let due = c.retry_at.is_some_and(|t| t <= now) && c.should_run(self.remote);
            if due {
                out.push(self.begin_open(ch));
            }
        }
        out
    }

    /// The earliest pending retry, for the event loop's wait.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.chans.iter().filter_map(|c| c.retry_at).min()
    }

    pub fn is_open(&self, ch: Channel) -> bool {
        matches!(self.chans[ch.index()].state, State::Open(_))
    }

    /// The generation of the open channel, if any.
    pub fn open_generation(&self, ch: Channel) -> Option<u64> {
        match self.chans[ch.index()].state {
            State::Open(g) => Some(g),
            _ => None,
        }
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gens(actions: &[LifeAction]) -> Vec<(Channel, u64)> {
        actions
            .iter()
            .filter_map(|a| match a {
                LifeAction::Open(c, g) => Some((*c, *g)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn console_start_stays_idle() {
        let mut l = Lifecycle::new();
        assert!(l.start(false).is_empty());
        assert!(l.poll(Instant::now() + BACKOFF_CAP * 10).is_empty());
        assert_eq!(l.next_deadline(), None);
        // Locks and console events open nothing either.
        assert!(l.on_session(SessionChange::Lock).is_empty());
        assert!(l.on_session(SessionChange::ConsoleConnect).is_empty());
        // Bulk is not opened off a remote connection.
        assert!(l.request_open(Channel::Bulk).is_empty());
    }

    #[test]
    fn connect_opens_ctl_only_and_reconnect_reopens() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        let g = gens(&l.start(true));
        assert_eq!(g, vec![(Channel::Ctl, 1)], "Bulk waits for HelloAck");
        assert!(l.on_open_result(Channel::Ctl, 1, true, t));
        let b = gens(&l.request_open(Channel::Bulk));
        assert_eq!(b, vec![(Channel::Bulk, 2)]);
        // Asking again while opening does nothing.
        assert!(l.request_open(Channel::Bulk).is_empty());
        assert!(l.on_open_result(Channel::Bulk, 2, true, t));
        assert!(l.is_open(Channel::Ctl) && l.is_open(Channel::Bulk));
        let a = l.on_session(SessionChange::RemoteConnect);
        assert_eq!(
            a,
            vec![
                LifeAction::Close(Channel::Ctl),
                LifeAction::Open(Channel::Ctl, 3),
                LifeAction::Close(Channel::Bulk),
            ]
        );
        assert!(!l.is_open(Channel::Bulk));
    }

    #[test]
    fn bulk_retries_only_while_wanted() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        let g = gens(&l.start(true));
        l.on_open_result(Channel::Ctl, g[0].1, true, t);
        let b = gens(&l.request_open(Channel::Bulk))[0].1;
        assert!(!l.on_open_result(Channel::Bulk, b, false, t));
        assert_eq!(l.next_deadline(), Some(t + BACKOFF_FIRST));
        let b2 = gens(&l.poll(t + BACKOFF_FIRST));
        assert_eq!(b2.len(), 1);
        assert!(l.on_open_result(Channel::Bulk, b2[0].1, true, t));
        // Closed by the client: retried while wanted.
        assert!(l.on_closed(Channel::Bulk, b2[0].1, t, true));
        assert!(l.next_deadline().is_some());
        // The protocol drops it (Ctl went away): no retry, late result dropped.
        let b3 = gens(&l.poll(t + BACKOFF_CAP));
        assert!(!l.close(Channel::Bulk));
        assert_eq!(l.next_deadline(), None);
        assert!(!l.on_open_result(Channel::Bulk, b3[0].1, true, t));
        assert!(l.poll(t + BACKOFF_CAP * 10).is_empty());
        // Closing an open channel reports it.
        let b4 = gens(&l.request_open(Channel::Bulk))[0].1;
        l.on_open_result(Channel::Bulk, b4, true, t);
        assert!(l.close(Channel::Bulk));
    }

    #[test]
    fn failed_open_backs_off_and_caps() {
        let mut t = Instant::now();
        let mut l = Lifecycle::new();
        let mut g = gens(&l.start(true));
        let mut waits = Vec::new();
        for _ in 0..8 {
            let (ch, gen_) = g[0];
            assert_eq!(ch, Channel::Ctl);
            assert!(!l.on_open_result(ch, gen_, false, t));
            let d = l.next_deadline().unwrap();
            waits.push(d - t);
            assert!(l.poll(d - Duration::from_millis(1)).is_empty());
            t = d;
            g = gens(&l.poll(t));
        }
        let secs: Vec<u64> = waits.iter().map(|d| d.as_secs()).collect();
        assert_eq!(secs, [30, 60, 120, 240, 480, 600, 600, 600]);
    }

    #[test]
    fn connect_resets_backoff_and_disconnect_stops_retries() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        for (ch, g) in gens(&l.start(true)) {
            l.on_open_result(ch, g, false, t);
        }
        for (ch, g) in gens(&l.poll(t + BACKOFF_FIRST)) {
            l.on_open_result(ch, g, false, t + BACKOFF_FIRST);
        }
        assert_eq!(l.next_deadline(), Some(t + BACKOFF_FIRST * 3));
        l.on_session(SessionChange::RemoteDisconnect);
        assert_eq!(l.next_deadline(), None);
        assert!(l.poll(t + BACKOFF_CAP * 10).is_empty());
        let t2 = t + Duration::from_secs(1000);
        for (ch, g) in gens(&l.on_session(SessionChange::RemoteConnect)) {
            l.on_open_result(ch, g, false, t2);
        }
        assert_eq!(l.next_deadline(), Some(t2 + BACKOFF_FIRST));
    }

    #[test]
    fn stale_results_are_ignored() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        let first = gens(&l.start(true));
        // The client reconnects before the first open returned.
        let second = gens(&l.on_session(SessionChange::RemoteConnect));
        assert!(!l.on_open_result(Channel::Ctl, first[0].1, true, t));
        assert!(!l.is_open(Channel::Ctl));
        assert!(l.on_open_result(Channel::Ctl, second[0].1, true, t));
        // A close from an older channel does not touch the new one.
        assert!(!l.on_closed(Channel::Ctl, first[0].1, t, true));
        assert!(l.is_open(Channel::Ctl));
        // Disconnect while Bulk is opening: the late success is stale.
        let b = gens(&l.request_open(Channel::Bulk));
        l.on_session(SessionChange::RemoteDisconnect);
        assert!(!l.on_open_result(Channel::Bulk, b[0].1, true, t));
    }

    #[test]
    fn closed_by_client_retries_while_connected() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        let g = gens(&l.start(true));
        l.on_open_result(Channel::Ctl, g[0].1, true, t);
        assert!(l.on_closed(Channel::Ctl, g[0].1, t, true));
        assert_eq!(l.next_deadline(), Some(t + BACKOFF_FIRST));
        // A protocol close waits for the next connect.
        let g = gens(&l.poll(t + BACKOFF_FIRST));
        l.on_open_result(Channel::Ctl, g[0].1, true, t);
        assert!(l.close(Channel::Ctl));
        assert_eq!(l.next_deadline(), None);
        assert!(l.poll(t + BACKOFF_CAP * 10).is_empty());
        assert_eq!(
            l.on_session(SessionChange::Logoff),
            vec![LifeAction::Shutdown]
        );
    }

    #[test]
    fn session_codes() {
        assert_eq!(SessionChange::from_code(3), SessionChange::RemoteConnect);
        assert_eq!(SessionChange::from_code(4), SessionChange::RemoteDisconnect);
        assert_eq!(SessionChange::from_code(6), SessionChange::Logoff);
        assert_eq!(SessionChange::from_code(99), SessionChange::Other(99));
    }
}
