//! When to open and close the channels (RDP-42): a pure state machine fed
//! with session events and open results, so the policy is tested without
//! Windows.
//!
//! - A DVC exists only while an RDP client is attached, so the channels are
//!   opened when the session is remote-connected (at start and on every
//!   `WTS_REMOTE_CONNECT`) and closed on `WTS_REMOTE_DISCONNECT` or when the
//!   session moves to the console.
//! - An open that fails (mstsc or another client without a Remora listener)
//!   is retried with a slow backoff while the session stays connected:
//!   30 s, doubling, capped at 10 min. A new connect resets it.
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
        };
        Self {
            remote: false,
            next_gen: 1,
            chans: [c; 2],
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

    pub fn on_session(&mut self, ev: SessionChange) -> Vec<LifeAction> {
        let mut out = Vec::new();
        match ev {
            SessionChange::RemoteConnect => {
                self.remote = true;
                for ch in Channel::ALL {
                    // A reconnect gives a new client; the old channel is dead.
                    if matches!(self.chans[ch.index()].state, State::Open(_)) {
                        out.push(LifeAction::Close(ch));
                    }
                    let c = &mut self.chans[ch.index()];
                    c.backoff = BACKOFF_FIRST;
                    c.retry_at = None;
                    let g = self.next_gen;
                    self.next_gen += 1;
                    self.chans[ch.index()].state = State::Opening(g);
                    out.push(LifeAction::Open(ch, g));
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

    /// The result of an `Open`. Returns whether the channel should be kept:
    /// `false` for a stale success, which the caller closes again.
    pub fn on_open_result(&mut self, ch: Channel, generation: u64, ok: bool, now: Instant) -> bool {
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
            Self::schedule_retry(c, self.remote, now);
            false
        }
    }

    /// The channel closed by itself (client closed it, read error): retried
    /// with backoff while the session is connected. With `retry` false (the
    /// protocol closed it, for example after failed authentication) it
    /// stays closed until the next client connect. Returns whether the event
    /// was for the current channel.
    pub fn on_closed(&mut self, ch: Channel, generation: u64, now: Instant, retry: bool) -> bool {
        let c = &mut self.chans[ch.index()];
        if c.state != State::Open(generation) {
            return false;
        }
        c.state = State::Closed;
        Self::schedule_retry(c, self.remote && retry, now);
        true
    }

    fn schedule_retry(c: &mut Chan, remote: bool, now: Instant) {
        if !remote {
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
            let due = self.chans[ch.index()]
                .retry_at
                .is_some_and(|t| t <= now && self.remote);
            if due {
                let g = self.next_gen;
                self.next_gen += 1;
                let c = &mut self.chans[ch.index()];
                c.retry_at = None;
                c.state = State::Opening(g);
                out.push(LifeAction::Open(ch, g));
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
    }

    #[test]
    fn remote_start_opens_both_and_reconnect_reopens() {
        let t = Instant::now();
        let mut l = Lifecycle::new();
        let a = l.start(true);
        let g = gens(&a);
        assert_eq!(g.len(), 2);
        assert!(l.on_open_result(Channel::Ctl, g[0].1, true, t));
        assert!(l.on_open_result(Channel::Bulk, g[1].1, true, t));
        assert!(l.is_open(Channel::Ctl));
        let a = l.on_session(SessionChange::RemoteConnect);
        assert_eq!(
            &a[..2],
            &[
                LifeAction::Close(Channel::Ctl),
                LifeAction::Open(Channel::Ctl, 3)
            ]
        );
        assert_eq!(gens(&a).len(), 2);
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
            // Bulk keeps failing too; only follow Ctl's deadline.
            if let Some(&(Channel::Bulk, bg)) = g.get(1) {
                l.on_open_result(Channel::Bulk, bg, false, t);
            }
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
        // Disconnect while opening: the late success is stale.
        l.on_session(SessionChange::RemoteDisconnect);
        assert!(!l.on_open_result(Channel::Bulk, second[1].1, true, t));
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
        assert!(l.on_closed(Channel::Ctl, g[0].1, t, false));
        assert_eq!(l.next_deadline(), None);
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
