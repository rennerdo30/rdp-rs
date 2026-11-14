//! The server helper in a session tab (RDP-42/43/44): what the tab knows
//! about its helper, the questions the helper raises (pairing, links,
//! files) and how they are painted.
//!
//! - The helper is invisible until one connects: no card, no command, no
//!   drop hint while none is there.
//! - **Pairing** is a modal card over the session with the six-digit code;
//!   a changed key is a warning whose safe answer (Don't pair) is the
//!   default. The keyboard does not reach the session while it is up.
//! - **Links** and **offered files** are small cards at the picture's
//!   bottom right, oldest at the bottom; nothing opens or is written before
//!   the user says so (or chose "Always" for links of this server).
//! - **Transfers** are listed on the panel's Sharing page; the helper's
//!   state and the server's session info on its Session page.
//!
//! The model ([`HelperView`]) turns adapter events into what the tab shows
//! and into [`Effect`]s the app carries out; everything that decides is a
//! plain function, tested here.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ffwd_render::{Canvas, Rect, TextEngine};
use remora_link::msg::{SessionInfo, TransferId, UrlStatus};
use remora_link::transfer::{Direction, TransferEvent, reason};
use remora_link::{Sas, cap, policy};

use super::*;
use crate::helper::{HelperEvent, HelperState};
use crate::store::HelperOptions;

/// Cards over the picture at most; more wait behind "+N".
const MAX_CARDS: usize = 3;
/// Progress repaints at most this often.
pub const PROGRESS_REDRAW: Duration = Duration::from_millis(250);

/// Where the tab's helper is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Status {
    /// No helper on this server (or not yet): nothing shows.
    #[default]
    Absent,
    Handshaking,
    /// Waiting for the user to compare `sas` with the server's.
    Pairing {
        sas: Sas,
        changed: bool,
    },
    Paired,
    Failed(String),
    /// Too many pairing attempts ended before the user answered.
    Blocked,
}

/// The helper's own description (its `Hello`, shown once paired).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HelloView {
    pub version: String,
    pub os_build: u32,
    /// Capabilities it offers and its server policy flags.
    pub offered: u32,
    pub policy: u32,
}

/// A link waiting for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkAsk {
    pub request_id: u32,
    /// The adapter's re-serialized URL and its ASCII host.
    pub url: String,
    pub host: String,
}

/// A file the server offers, waiting for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub id: TransferId,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowState {
    /// Offered, not accepted yet by the other side.
    Waiting,
    Running,
    /// The connection dropped; it resumes after a reconnect.
    Paused,
    Done,
    Failed(String),
}

/// One transfer in the panel's list.
#[derive(Clone, Debug)]
pub struct Row {
    pub id: TransferId,
    pub name: String,
    pub dir: Direction,
    pub total: u64,
    pub done: u64,
    pub state: RowState,
    /// Downloads: the folder it is saved in.
    pub folder: Option<PathBuf>,
    /// Smoothed bytes per second, and the last sample (time, bytes).
    pub(super) rate: f64,
    sample: Option<(Instant, u64)>,
}

impl Row {
    fn new(id: TransferId, name: String, dir: Direction, total: u64) -> Row {
        Row {
            id,
            name,
            dir,
            total,
            done: 0,
            state: RowState::Waiting,
            folder: None,
            rate: 0.0,
            sample: None,
        }
    }

    pub fn active(&self) -> bool {
        matches!(
            self.state,
            RowState::Waiting | RowState::Running | RowState::Paused
        )
    }

    /// The received file (downloads that finished).
    pub fn path(&self) -> Option<PathBuf> {
        (self.dir == Direction::Receive && self.state == RowState::Done)
            .then(|| self.folder.as_ref().map(|f| f.join(&self.name)))
            .flatten()
    }

    pub fn eta(&self) -> Option<Duration> {
        (self.rate >= 1.0 && self.state == RowState::Running).then(|| {
            Duration::from_secs_f64(self.total.saturating_sub(self.done) as f64 / self.rate)
        })
    }

    fn progress(&mut self, done: u64, total: u64, now: Instant) {
        self.total = total;
        match self.sample {
            None => self.sample = Some((now, done)),
            Some((t, d)) => {
                let dt = now.saturating_duration_since(t).as_secs_f64();
                if dt >= 0.5 {
                    let inst = done.saturating_sub(d) as f64 / dt;
                    self.rate = if self.rate == 0.0 {
                        inst
                    } else {
                        0.6 * self.rate + 0.4 * inst
                    };
                    self.sample = Some((now, done));
                }
            }
        }
        self.done = done;
        self.state = RowState::Running;
    }
}

/// What the app does for the tab after an event.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// Answer a link request without asking (refused, or switched off).
    Answer(u32, UrlStatus),
    /// Open a link at once ("Always" was chosen for this server).
    Open(u32, String),
    /// One line in the status bar.
    Notice(String, Tone),
    /// The helper asks to pair: take the keyboard from the session.
    PairingAsked,
    /// A download has this many bytes still to come; or it is over.
    Reserve(TransferId, PathBuf, u64),
    Release(TransferId),
}

/// What happens to a link the helper asks to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkDecision {
    Ask,
    Open,
    Refuse(UrlStatus),
}

/// What dropping files on the session would do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropHint {
    /// Send this many files.
    Send(usize),
    /// Not possible; why and how to change it.
    Off(&'static str, &'static str),
}

/// Links of a connection: refused unless switched on and a plain web link;
/// opened at once when "Always" was chosen; otherwise asked.
pub fn link_decision(opts: &HelperOptions, url: &str) -> LinkDecision {
    if !crate::helper::is_web_url(url) {
        LinkDecision::Refuse(UrlStatus::Invalid)
    } else if !opts.open_links {
        LinkDecision::Refuse(UrlStatus::Disabled)
    } else if opts.links_unasked {
        LinkDecision::Open
    } else {
        LinkDecision::Ask
    }
}

/// Why a transfer stopped, in words.
pub fn reason_text(code: u8, by_peer: bool) -> String {
    match code {
        reason::USER if by_peer => "Cancelled on the server",
        reason::USER => "Cancelled",
        reason::DISABLED => "File transfer is switched off",
        reason::BAD_NAME => "The file name is not safe",
        reason::NO_SPACE => "Not enough free space",
        reason::IO => "Could not read or write the file",
        reason::INTEGRITY => "The data did not check out",
        reason::SOURCE_CHANGED => "The file changed while it was sent",
        reason::BUSY => "Too many transfers at once",
        _ => "Protocol error",
    }
    .into()
}

/// The server helper as one session tab sees it.
#[derive(Clone, Debug, Default)]
pub struct HelperView {
    pub status: Status,
    pub hello: Option<HelloView>,
    /// Capabilities in force (0 until paired).
    pub accepted: u32,
    pub info: Option<SessionInfo>,
    pub links: Vec<LinkAsk>,
    pub offers: Vec<Offer>,
    pub transfers: Vec<Row>,
    /// The connection's helper settings in force for this tab.
    pub opts: HelperOptions,
    /// Pairing attempts that ended before the user answered.
    pub aborted: u32,
    /// Second helper instances refused.
    pub refusals: u32,
    /// The helper key's fingerprint (`ab12 cd34 …`), once its handshake ran.
    pub fingerprint: Option<String>,
    /// The helper asked its own user to confirm this PC; nothing leaves the
    /// server before that answer.
    pub server_pending: bool,
    /// A server offer was refused unseen because receiving is off: said
    /// once per tab, quietly.
    pub refused_said: bool,
}

impl HelperView {
    /// The pairing question to show: its code and whether the key changed.
    pub fn pairing(&self) -> Option<(Sas, bool)> {
        match self.status {
            Status::Pairing { sas, changed } => Some((sas, changed)),
            _ => None,
        }
    }

    /// Anything of the helper shows in the panel.
    pub fn present(&self) -> bool {
        self.status != Status::Absent || self.aborted > 0
    }

    pub fn paired(&self) -> bool {
        self.status == Status::Paired
    }

    /// Files can be sent now.
    pub fn can_send(&self) -> bool {
        self.paired() && self.accepted & cap::FILE_UP != 0
    }

    /// What a drop of `n` files would do (None: say nothing).
    pub fn drop_hint(&self, n: usize) -> Option<DropHint> {
        if n == 0 || !self.paired() {
            return None;
        }
        if self.can_send() {
            return Some(DropHint::Send(n));
        }
        let policy_blocks = self
            .hello
            .as_ref()
            .is_some_and(|h| h.policy & policy::BLOCKS_FILE_TRANSFER != 0);
        Some(if !self.opts.send_files {
            DropHint::Off(
                "Sending files is off for this connection",
                "Switch on \"Send files to the server\" in its Sharing settings.",
            )
        } else if policy_blocks {
            DropHint::Off(
                "The server does not allow file transfer",
                "Its policy turns off clipboard or drive redirection.",
            )
        } else {
            DropHint::Off(
                "This helper cannot receive files",
                "Update remora-agent on the server.",
            )
        })
    }

    /// The tab's rows of `dir` still running.
    pub fn running(&self) -> usize {
        self.transfers.iter().filter(|r| r.active()).count()
    }

    fn set_status(&mut self, s: HelperState) -> Vec<Effect> {
        let was_pairing = matches!(self.status, Status::Pairing { .. });
        let next = match s {
            HelperState::NotPresent => Status::Absent,
            HelperState::Handshaking => Status::Handshaking,
            HelperState::AwaitingPairing {
                sas,
                changed,
                fingerprint,
            } => {
                self.fingerprint = Some(fingerprint);
                Status::Pairing { sas, changed }
            }
            HelperState::Paired => Status::Paired,
            HelperState::Failed(why) => Status::Failed(why),
            HelperState::PairingBlocked => Status::Blocked,
        };
        let mut fx = Vec::new();
        if was_pairing && !matches!(next, Status::Paired | Status::Pairing { .. }) {
            // The helper went away while the code was shown: say so where
            // the helper is described (not as a nag).
            self.aborted += 1;
        }
        if matches!(next, Status::Pairing { .. }) {
            fx.push(Effect::PairingAsked);
        }
        if next != Status::Paired {
            // Request ids belong to the session that is gone.
            self.links.clear();
            self.accepted = 0;
            self.info = None;
        }
        self.status = next;
        fx
    }

    /// Takes in one adapter event; returns what the app must do.
    pub fn apply(&mut self, ev: HelperEvent, now: Instant) -> Vec<Effect> {
        match ev {
            HelperEvent::State(s) => self.set_status(s),
            HelperEvent::SessionInfo(i) => {
                self.info = Some(i);
                Vec::new()
            }
            HelperEvent::OpenUrl { request_id, url } => match link_decision(&self.opts, &url) {
                LinkDecision::Refuse(st) => vec![Effect::Answer(request_id, st)],
                LinkDecision::Open => vec![Effect::Open(request_id, url)],
                LinkDecision::Ask => {
                    let host = crate::helper_app::link_host(&url).unwrap_or_default();
                    self.links.push(LinkAsk {
                        request_id,
                        url,
                        host,
                    });
                    Vec::new()
                }
            },
            HelperEvent::SecondInstanceRefused(_) => {
                self.refusals += 1;
                if self.refusals == 1 {
                    vec![Effect::Notice(
                        "A second server helper tried to connect and was refused.".into(),
                        Tone::Warning,
                    )]
                } else {
                    Vec::new()
                }
            }
            HelperEvent::Transfer(t) => self.transfer(t, now),
        }
    }

    fn row(&mut self, id: TransferId, dir: Direction) -> Option<&mut Row> {
        self.transfers
            .iter_mut()
            .find(|r| r.id == id && r.dir == dir)
    }

    fn transfer(&mut self, ev: TransferEvent, now: Instant) -> Vec<Effect> {
        match ev {
            TransferEvent::Offered { id, name, size, .. } => {
                if !self.offers.iter().any(|o| o.id == id) {
                    self.offers.push(Offer { id, name, size });
                }
                Vec::new()
            }
            TransferEvent::Progress {
                id,
                direction,
                done,
                total,
            } => {
                let Some(r) = self.row(id, direction) else {
                    return Vec::new();
                };
                r.progress(done, total, now);
                match (&r.folder, direction) {
                    (Some(f), Direction::Receive) => {
                        vec![Effect::Reserve(id, f.clone(), total.saturating_sub(done))]
                    }
                    _ => Vec::new(),
                }
            }
            TransferEvent::Paused { id, direction } => {
                if let Some(r) = self.row(id, direction) {
                    r.state = RowState::Paused;
                    r.sample = None;
                }
                Vec::new()
            }
            TransferEvent::Completed {
                id,
                direction,
                name,
            } => {
                let mut fx = vec![Effect::Release(id)];
                if let Some(r) = self.row(id, direction) {
                    r.state = RowState::Done;
                    r.done = r.total;
                    r.name = name.clone();
                    let text = match (&r.folder, direction) {
                        (Some(f), Direction::Receive) => {
                            format!("Saved {name} in {}.", crate::helper_app::short_dir(f))
                        }
                        _ => format!("Sent {name} to the server."),
                    };
                    fx.push(Effect::Notice(text, Tone::Success));
                }
                fx
            }
            TransferEvent::Failed {
                id,
                direction,
                reason: code,
                by_peer,
                detail,
            } => {
                let offered = self.offers.iter().position(|o| o.id == id);
                if let Some(i) = offered {
                    // Withdrawn by the server before the user answered.
                    self.offers.remove(i);
                }
                let mut fx = vec![Effect::Release(id)];
                let said = self.refused_said;
                let mut say = false;
                match self.row(id, direction) {
                    Some(r) => {
                        let mut why = reason_text(code, by_peer);
                        if code == reason::IO && !detail.is_empty() {
                            why = format!("{why}: {detail}");
                        }
                        r.state = RowState::Failed(why);
                    }
                    None if code == reason::BAD_NAME && direction == Direction::Receive => {
                        fx.push(Effect::Notice(
                            "The server offered a file with an unsafe name; it was refused.".into(),
                            Tone::Warning,
                        ));
                    }
                    // Refused before anyone saw it: receiving is off here.
                    None if code == reason::DISABLED
                        && direction == Direction::Receive
                        && !by_peer
                        && !said =>
                    {
                        say = true;
                        fx.push(Effect::Notice(
                            "The server offered a file; receiving files is off for this connection."
                                .into(),
                            Tone::Muted,
                        ));
                    }
                    None if code == reason::BUSY && direction == Direction::Receive && !by_peer => {
                        fx.push(Effect::Notice(
                            "The server offered another file while 32 were waiting; it was refused."
                                .into(),
                            Tone::Warning,
                        ));
                    }
                    None => {}
                }
                if say {
                    self.refused_said = true;
                }
                fx
            }
        }
    }

    /// The user saves offer `i`: it becomes a row saving into the
    /// connection's folder. Returns its id and that folder.
    pub fn accept(&mut self, i: usize) -> Option<(TransferId, PathBuf)> {
        if i >= self.offers.len() {
            return None;
        }
        let o = self.offers.remove(i);
        let folder = crate::helper_app::download_dir(&self.opts);
        let mut r = Row::new(o.id, o.name, Direction::Receive, o.size);
        r.folder = Some(folder.clone());
        self.transfers.push(r);
        Some((o.id, folder))
    }

    /// A file the user sends (after the adapter took it).
    pub fn sending(&mut self, id: TransferId, name: String, size: u64) {
        self.transfers
            .push(Row::new(id, name, Direction::Send, size));
    }

    /// A transfer the app could not start or the user cancelled.
    pub fn fail(&mut self, id: TransferId, why: String) {
        if let Some(r) = self.transfers.iter_mut().find(|r| r.id == id) {
            r.state = RowState::Failed(why);
        }
    }

    /// Drops finished and failed rows.
    pub fn clear_finished(&mut self) {
        self.transfers.retain(Row::active);
    }
}

/// Bytes as Windows shows them (1 KB = 1024 bytes).
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} bytes");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[u])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// A short duration: "45 s", "3 min", "2 h 5 min".
pub fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min", s / 60)
    } else {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    }
}

/// The second line of a transfer row.
fn row_line(r: &Row) -> (String, Tone) {
    let pct = if r.total > 0 {
        (r.done as f64 * 100.0 / r.total as f64).floor() as u64
    } else {
        0
    };
    match &r.state {
        RowState::Waiting => (format!("{} · waiting", fmt_bytes(r.total)), Tone::Muted),
        RowState::Running => {
            let mut s = format!("{pct} %");
            if r.rate >= 1.0 {
                s += &format!(" · {}/s", fmt_bytes(r.rate as u64));
            }
            if let Some(eta) = r.eta() {
                s += &format!(" · {} left", fmt_dur(eta));
            }
            (s, Tone::Muted)
        }
        RowState::Paused => (format!("Paused at {pct} %, resumes later"), Tone::Warning),
        RowState::Done => match (&r.folder, r.dir) {
            (Some(f), Direction::Receive) => (
                format!(
                    "{} · in {}",
                    fmt_bytes(r.total),
                    crate::helper_app::short_dir(f)
                ),
                Tone::Success,
            ),
            _ => (format!("{} · sent", fmt_bytes(r.total)), Tone::Success),
        },
        RowState::Failed(why) => (why.clone(), Tone::Danger),
    }
}

// ---- Layout over the session ---------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardKind {
    Link(usize),
    Offer(usize),
}

/// Where the helper's cards were laid out over the session (physical px).
#[derive(Clone, Debug, Default)]
pub(super) struct Overlay {
    id: u64,
    /// The visible part of the session area.
    area: Rect,
    /// The pairing question (its dialog).
    modal: Option<Rect>,
    cards: Vec<(Rect, CardKind)>,
    /// Cards not shown ("+N").
    more: usize,
    /// The drop target is up.
    drop: Option<DropHint>,
    buttons: Vec<(Rect, Hit)>,
}

impl Overlay {
    fn bounds(&self) -> Option<Rect> {
        if self.modal.is_some() || self.drop.is_some() {
            return Some(self.area);
        }
        self.cards
            .iter()
            .map(|(r, _)| {
                // The card's shadow too.
                Rect::new(r.x - 30, r.y - 30, r.w + 60, r.h + 60)
            })
            .reduce(|a, b| {
                let x = a.x.min(b.x);
                let y = a.y.min(b.y);
                Rect::new(
                    x,
                    y,
                    a.right().max(b.right()) - x,
                    a.bottom().max(b.bottom()) - y,
                )
            })
    }
}

fn link_h(s: f32) -> i32 {
    (132.0 * s).round() as i32
}

fn offer_h(s: f32) -> i32 {
    (108.0 * s).round() as i32
}

/// Right-aligned buttons ending at `right`, at `y`, height `h`.
fn button_row(
    te: &mut TextEngine,
    f: &Fonts,
    s: f32,
    right: i32,
    y: i32,
    h: i32,
    items: &[(Button, Hit)],
) -> Vec<(Rect, Hit)> {
    let gap = (8.0 * s).round() as i32;
    let mut x = right;
    let mut out = Vec::new();
    for (b, hit) in items.iter().rev() {
        let w = kit::button_width(te, f, s, b);
        x -= w;
        out.push((Rect::new(x, y, w, h), *hit));
        x -= gap;
    }
    out.reverse();
    out
}

fn pairing_buttons(id: u64, changed: bool) -> [(Button<'static>, Hit); 2] {
    if changed {
        [
            (
                Button::new("Pair anyway", Variant::DangerGhost),
                Hit::HelperPair(id),
            ),
            (
                Button::primary("Don't pair").icon(Icon::Close),
                Hit::HelperNoPair(id),
            ),
        ]
    } else {
        [
            (Button::secondary("Don't pair"), Hit::HelperNoPair(id)),
            (
                Button::primary("Pair").icon(Icon::ShieldCheck),
                Hit::HelperPair(id),
            ),
        ]
    }
}

fn link_buttons(id: u64) -> [(Button<'static>, Hit); 3] {
    [
        (Button::ghost("Ignore"), Hit::LinkIgnore(id)),
        (
            Button::secondary("Always for this server"),
            Hit::LinkAlways(id),
        ),
        (Button::primary("Open").icon(Icon::Globe), Hit::LinkOpen(id)),
    ]
}

fn offer_buttons(id: u64, i: usize) -> [(Button<'static>, Hit); 2] {
    [
        (Button::secondary("Decline"), Hit::OfferDecline(id, i)),
        (
            Button::primary("Save").icon(Icon::Download),
            Hit::OfferSave(id, i),
        ),
    ]
}

const MODAL_W: f32 = 460.0;
const MODAL_H: f32 = 364.0;

impl Ui {
    /// The active tab's helper asks to pair: its card is up and takes the
    /// keyboard and the pointer over the session.
    pub fn helper_modal_open(&self) -> bool {
        self.active_tab().is_some_and(|t| {
            matches!(t.state, TabState::Connected { .. }) && t.helper.pairing().is_some()
        })
    }

    /// Keyboard input goes to the session (it has the focus and no helper
    /// question covers it).
    pub fn keys_to_session(&self) -> bool {
        self.session_focus && !self.helper_modal_open()
    }

    /// The drop target over the active session for `n` hovered files.
    pub fn drop_hint(&self, n: usize) -> Option<DropHint> {
        let t = self.active_tab()?;
        if !matches!(t.state, TabState::Connected { .. }) {
            return None;
        }
        t.helper.drop_hint(n)
    }

    /// Lays out the helper's cards over a running session's `area` (the
    /// part of it not under the floating panel).
    pub(super) fn helper_layout(&mut self, te: &mut TextEngine, f: &Fonts, id: u64, area: Rect) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return;
        };
        let mut ov = Overlay {
            id,
            area,
            ..Overlay::default()
        };
        if let Some((_, changed)) = t.helper.pairing() {
            let w = p(MODAL_W).min(area.w - p(32.0));
            let h = p(MODAL_H);
            let r = Rect::new(
                area.x + (area.w - w) / 2,
                area.y + ((area.h - h) / 2).max(p(16.0)),
                w,
                h,
            );
            ov.modal = Some(r);
            ov.buttons = button_row(
                te,
                f,
                s,
                r.right() - p(28.0),
                r.bottom() - p(28.0) - p(36.0),
                p(36.0),
                &pairing_buttons(id, changed),
            );
            self.helper_ov = ov;
            return;
        }
        if let Some(hint) = self
            .drop_hint(self.dropping)
            .filter(|_| self.active == Some(id))
        {
            ov.drop = Some(hint);
            self.helper_ov = ov;
            return;
        }
        let kinds: Vec<CardKind> = (0..t.helper.links.len())
            .map(CardKind::Link)
            .chain((0..t.helper.offers.len()).map(CardKind::Offer))
            .collect();
        let w = p(380.0).min(area.w - p(32.0));
        let mut bottom = area.bottom() - p(16.0);
        let right = area.right() - p(16.0);
        for kind in kinds.iter().take(MAX_CARDS) {
            let h = match kind {
                CardKind::Link(_) => link_h(s),
                CardKind::Offer(_) => offer_h(s),
            };
            if bottom - h < area.y + p(72.0) {
                break;
            }
            let r = Rect::new(right - w, bottom - h, w, h);
            let by = r.bottom() - p(16.0) - p(30.0);
            let br = r.right() - p(16.0);
            let b = match kind {
                CardKind::Link(_) => button_row(te, f, s, br, by, p(30.0), &link_buttons(id)),
                CardKind::Offer(i) => button_row(te, f, s, br, by, p(30.0), &offer_buttons(id, *i)),
            };
            ov.buttons.extend(b);
            ov.cards.push((r, *kind));
            bottom = r.y - p(10.0);
        }
        ov.more = kinds.len() - ov.cards.len();
        self.helper_ov = ov;
    }

    /// The helper's part of the overlay's damage rectangle.
    pub(super) fn helper_overlay_rect(&self) -> Option<Rect> {
        self.helper_ov.bounds()
    }

    /// The helper's cards take the pointer over the session: their buttons,
    /// and the rest of a card (or all of the session under the pairing
    /// question) does nothing.
    pub(super) fn helper_overlay_hit(&self, x: i32, y: i32) -> Option<Hit> {
        let ov = &self.helper_ov;
        if let Some((_, h)) = ov.buttons.iter().find(|(r, _)| r.contains(x, y)) {
            return Some(*h);
        }
        if ov.modal.is_some() || ov.drop.is_some() {
            return ov.area.contains(x, y).then_some(Hit::Modal);
        }
        ov.cards
            .iter()
            .any(|(r, _)| r.contains(x, y))
            .then_some(Hit::Modal)
    }

    pub(super) fn helper_overlay_clear(&mut self) {
        self.helper_ov = Overlay::default();
    }

    /// Enter and Esc answer the pairing question (Esc and, for a changed
    /// key, Enter mean Don't pair); other keys go nowhere while it is up.
    pub(super) fn helper_key(&mut self, k: &Key) -> Option<Option<Action>> {
        if !self.helper_modal_open() {
            return None;
        }
        let t = self.active_tab()?;
        let (sas, changed) = t.helper.pairing()?;
        let id = t.id;
        Some(match k {
            Key::Enter => Some(Action::HelperPairing(id, sas, !changed)),
            Key::Esc => Some(Action::HelperPairing(id, sas, false)),
            _ => None,
        })
    }

    /// The helper's clicks (cards, panel rows, editor rows).
    pub(super) fn activate_helper(&mut self, hit: Hit) -> Option<Action> {
        match hit {
            Hit::HelperPair(id) | Hit::HelperNoPair(id) => {
                let (sas, _) = self.tab_mut(id)?.helper.pairing()?;
                Some(Action::HelperPairing(
                    id,
                    sas,
                    matches!(hit, Hit::HelperPair(_)),
                ))
            }
            Hit::LinkOpen(id) | Hit::LinkAlways(id) | Hit::LinkIgnore(id) => {
                let t = self.tab_mut(id)?;
                if t.helper.links.is_empty() {
                    return None;
                }
                let l = t.helper.links.remove(0);
                let open = !matches!(hit, Hit::LinkIgnore(_));
                if matches!(hit, Hit::LinkAlways(_)) {
                    t.helper.opts.links_unasked = true;
                    let (name, host) = (t.name.clone(), t.host.clone());
                    self.trust_links(&name, &host);
                }
                Some(Action::AnswerLink {
                    id,
                    request_id: l.request_id,
                    url: l.url,
                    open,
                })
            }
            Hit::OfferSave(id, i) => {
                let (tid, folder) = self.tab_mut(id)?.helper.accept(i)?;
                Some(Action::AcceptFile(id, tid, folder))
            }
            Hit::OfferDecline(id, i) => {
                let t = self.tab_mut(id)?;
                if i >= t.helper.offers.len() {
                    return None;
                }
                let o = t.helper.offers.remove(i);
                Some(Action::DeclineFile(id, o.id))
            }
            Hit::TransferCancel(id, i) => {
                let r = self.tab_mut(id)?.helper.transfers.get(i)?;
                r.active().then_some(Action::CancelTransfer(id, r.id))
            }
            Hit::TransferShow(id, i) => {
                let path = self.tab_mut(id)?.helper.transfers.get(i)?.path()?;
                Some(Action::ShowInFolder(path))
            }
            Hit::TransfersClear(id) => {
                self.tab_mut(id)?.helper.clear_finished();
                None
            }
            Hit::SendFiles(id) => Some(Action::PickSendFiles(id)),
            Hit::ShowTransfers(_) => {
                self.drawer_page = 0;
                self.drawer_scroll = 0;
                if self.panel_pinned {
                    self.drawer = true;
                } else {
                    self.panel.open = self.active;
                }
                None
            }
            Hit::ForgetHelper(id) => {
                let t = self.tabs.iter().find(|t| t.id == id)?;
                let server = remora_link::server_id(&t.host, t.live.port);
                self.forget = Some((server, t.host.clone()));
                None
            }
            Hit::RetryHelperPairing(id) => {
                let t = self.tab_mut(id)?;
                (t.helper.status == Status::Blocked).then_some(Action::RetryHelperPairing(id))
            }
            Hit::FormHelper(i) => {
                let h = &mut self.opts.helper;
                match i {
                    0 => h.open_links = !h.open_links,
                    1 => h.receive_files = !h.receive_files,
                    2 => h.send_files = !h.send_files,
                    _ => h.links_unasked = !h.links_unasked,
                }
                None
            }
            Hit::FormDownloads => Some(Action::BrowseDownloads),
            Hit::FormForgetHelper => {
                let host = self.field(Field::Host).text.trim().to_string();
                let port = self.field(Field::Port).text.trim().parse().unwrap_or(3389);
                self.forget = Some((remora_link::server_id(&host, port), host));
                None
            }
            Hit::ForgetOk => {
                let (server, host) = self.forget.take()?;
                self.helper_pins.remove(&server);
                self.set_message(
                    format!("Forgot the helper of {host}; its next session asks to pair."),
                    Tone::Muted,
                );
                Some(Action::ForgetHelper(server))
            }
            Hit::ForgetCancel => {
                self.forget = None;
                None
            }
            _ => None,
        }
    }

    /// "Always for this server": the saved connection opens its links
    /// without asking from now on.
    fn trust_links(&mut self, name: &str, host: &str) {
        let Some(c) = self
            .store
            .connections
            .iter_mut()
            .find(|c| c.name == name && c.host == host)
        else {
            return;
        };
        c.options.helper.links_unasked = true;
        if let Err(e) = self.store.save() {
            self.set_message(format!("Could not save the connection: {e}"), Tone::Warning);
        }
    }

    /// The editor's download folder was picked.
    pub fn form_set_download_dir(&mut self, dir: String) {
        self.opts.helper.download_dir = Some(dir);
    }

    // ---- Painting over the session ---------------------------------------

    /// The pairing question, the drop target or the cards (overlay pass).
    pub(super) fn paint_helper_overlay(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let ov = self.helper_ov.clone();
        let Some(t) = self.tabs.iter().find(|t| t.id == ov.id) else {
            return;
        };
        let (host, view) = (t.host.clone(), t.helper.clone());
        let old = cv.set_clip(cv.clip().intersect(ov.area));
        if cv.clip().is_empty() {
            cv.set_clip(old);
            return;
        }
        if let (Some(r), Some((sas, changed))) = (ov.modal, view.pairing()) {
            Kit::new(cv, te, f, self.scale).scrim(ov.area);
            let fp = view.fingerprint.clone().unwrap_or_default();
            self.paint_pairing(cv, te, f, r, &host, sas, changed, &fp);
        } else if let Some(hint) = &ov.drop {
            self.paint_drop(cv, te, f, ov.area, &host, hint);
        } else {
            for (i, (r, kind)) in ov.cards.iter().enumerate() {
                match kind {
                    CardKind::Link(n) => {
                        if let Some(l) = view.links.get(*n) {
                            self.paint_link_card(cv, te, f, *r, l);
                        }
                    }
                    CardKind::Offer(n) => {
                        if let Some(o) = view.offers.get(*n) {
                            self.paint_offer_card(cv, te, f, *r, o, &t_folder(&view));
                        }
                    }
                }
                // "+N" on the top card.
                if ov.more > 0 && i + 1 == ov.cards.len() {
                    let mut k = Kit::new(cv, te, f, self.scale);
                    let text = format!("+{} more", ov.more);
                    let pw = k.pill_width(&text, kit::Lead::None);
                    k.pill(
                        r.right() - k.p(14.0) - pw,
                        r.y + k.p(14.0),
                        &text,
                        Tone::Accent,
                        kit::Lead::None,
                    );
                }
            }
        }
        for (r, hit) in &ov.buttons {
            let b = self.helper_button(*hit, ov.id, changed_of(&view));
            if let Some(b) = b {
                let st = self.st(*hit);
                Kit::new(cv, te, f, self.scale).button(*r, &b, st);
            }
        }
        cv.set_clip(old);
    }

    /// The button a laid-out hit stands for.
    fn helper_button(&self, hit: Hit, id: u64, changed: bool) -> Option<Button<'static>> {
        let all = pairing_buttons(id, changed)
            .into_iter()
            .chain(link_buttons(id))
            .collect::<Vec<_>>();
        if let Some((b, _)) = all.into_iter().find(|(_, h)| *h == hit) {
            return Some(b);
        }
        match hit {
            Hit::OfferSave(_, i) | Hit::OfferDecline(_, i) => offer_buttons(id, i)
                .into_iter()
                .find(|(_, h)| *h == hit)
                .map(|(b, _)| b),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_pairing(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        host: &str,
        sas: Sas,
        changed: bool,
        fingerprint: &str,
    ) {
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let p = |v: f32| (v * s).round() as i32;
        k.dialog(r);
        let (icon, tone, title) = if changed {
            (
                Icon::ShieldAlert,
                Tone::Danger,
                "The server helper's key changed",
            )
        } else {
            (Icon::ShieldCheck, Tone::Accent, "Pair the server helper?")
        };
        let x = r.x + p(28.0);
        let tw = r.w - p(56.0);
        let d = p(44.0);
        let tile = Rect::new(x, r.y + p(28.0), d, d);
        k.cv.fill_round(tile, 12.0 * s, tone.subtle());
        k.icon_in(icon, tile, 22.0, tone.color());
        let hx = tile.right() + p(14.0);
        let hw = r.right() - hx - p(28.0);
        k.text(
            Font::Semi,
            size::HEADING + 1.0,
            hx,
            r.y + p(46.0),
            title,
            c.text,
            hw,
        );
        k.text(
            Font::Regular,
            12.0,
            hx,
            r.y + p(65.0),
            &format!("remora-agent on {host}"),
            c.text_muted,
            hw,
        );
        let text = if changed {
            format!(
                "The helper on {host} has a different key than last time. A reinstalled helper does this, but so does an attack. Pair only if the server shows this code."
            )
        } else {
            format!(
                "Check that {host} shows the same code. Pairing lets the helper show the session's state, and links and files if you allow them."
            )
        };
        let color = if changed { c.danger } else { c.text_secondary };
        k.paragraph(
            Font::Regular,
            12.5,
            x,
            r.y + p(104.0),
            tw,
            &text,
            color,
            false,
        );
        // The code: big, in two groups, in a well.
        let well = Rect::new(x, r.y + p(170.0), tw, p(68.0));
        k.cv.round_border(well, radius::CONTROL * s, c.border, c.field);
        let code = sas.to_string();
        let (a, b) = code.split_once(' ').unwrap_or((&code, ""));
        let big = 30.0;
        let gw = k.measure(Font::Semi, big, a);
        let gap = p(18.0);
        let total = gw + gap + k.measure(Font::Semi, big, b);
        let base = k.baseline(Font::Semi, big, well);
        let cx = well.x + (well.w - total) / 2;
        let digits = if changed { c.danger } else { c.text };
        k.text(Font::Semi, big, cx, base, a, digits, gw + p(4.0));
        k.text(Font::Semi, big, cx + gw + gap, base, b, digits, well.w);
        // The key's fingerprint, to compare out of band (remora-agent
        // fingerprint on the server): small, under the code.
        if !fingerprint.is_empty() {
            let line = format!("Helper fingerprint  {fingerprint}");
            let fw = k.measure(Font::Regular, 11.0, &line).min(tw);
            k.text(
                Font::Regular,
                11.0,
                x + (tw - fw) / 2,
                well.bottom() + p(20.0),
                &line,
                c.text_muted,
                tw,
            );
        }
        let hints: [kit::Hint; 4] = if changed {
            [
                kit::Hint::Keys("Enter"),
                kit::Hint::Text("or"),
                kit::Hint::Keys("Esc"),
                kit::Hint::Text("don't pair"),
            ]
        } else {
            [
                kit::Hint::Keys("Enter"),
                kit::Hint::Text("pairs"),
                kit::Hint::Keys("Esc"),
                kit::Hint::Text("doesn't"),
            ]
        };
        k.hints(x, r.y + p(282.0), tw, &hints);
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_drop(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        host: &str,
        hint: &DropHint,
    ) {
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let p = |v: f32| (v * s).round() as i32;
        k.scrim(area);
        let send = matches!(hint, DropHint::Send(_));
        let inner = Rect::new(
            area.x + p(16.0),
            area.y + p(16.0),
            area.w - p(32.0),
            area.h - p(32.0),
        );
        let edge = if send { c.accent } else { c.border_strong };
        k.round_outline(inner, radius::DIALOG, 2.0 * s, edge);
        let w = p(400.0).min(area.w - p(64.0));
        let h = p(152.0);
        let r = Rect::new(area.x + (area.w - w) / 2, area.y + (area.h - h) / 2, w, h);
        k.dialog(r);
        let d = p(52.0);
        let tile = Rect::new(r.x + (r.w - d) / 2, r.y + p(26.0), d, d);
        let (tone, title, sub) = match hint {
            DropHint::Send(n) => (
                Tone::Accent,
                format!("Drop to send to {host}"),
                if *n == 1 {
                    "1 file · copied by the server helper".to_string()
                } else {
                    format!("{n} files · copied by the server helper")
                },
            ),
            DropHint::Off(t, s) => (Tone::Muted, t.to_string(), s.to_string()),
        };
        let (fill, fg) = if send {
            (tone.subtle(), tone.color())
        } else {
            (c.surface_hover, c.text_muted)
        };
        k.cv.fill_round(tile, 14.0 * s, fill);
        k.icon_in(Icon::Upload, tile, 26.0, fg);
        k.text_center(
            Font::Semi,
            size::HEADING + 1.0,
            Rect::new(
                r.x + p(16.0),
                tile.bottom() + p(14.0),
                r.w - p(32.0),
                p(24.0),
            ),
            &title,
            c.text,
        );
        k.paragraph(
            Font::Regular,
            12.5,
            r.x + p(24.0),
            tile.bottom() + p(58.0),
            r.w - p(48.0),
            &sub,
            c.text_muted,
            true,
        );
    }

    fn paint_link_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        l: &LinkAsk,
    ) {
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let p = |v: f32| (v * s).round() as i32;
        k.dialog(r);
        let d = p(32.0);
        let tile = Rect::new(r.x + p(16.0), r.y + p(16.0), d, d);
        k.cv.fill_round(tile, 9.0 * s, c.accent_subtle);
        k.icon_in(Icon::Link, tile, 16.0, c.accent);
        let tx = tile.right() + p(12.0);
        let tw = r.right() - tx - p(16.0);
        // Where it goes first: the host, as the browser will see it.
        let host = if l.host.is_empty() { &l.url } else { &l.host };
        k.text(Font::Semi, 14.0, tx, r.y + p(29.0), host, c.text, tw);
        k.text(
            Font::Regular,
            12.0,
            tx,
            r.y + p(47.0),
            "The server wants to open this link here",
            c.text_muted,
            tw,
        );
        k.text(
            Font::Regular,
            11.5,
            r.x + p(16.0),
            r.y + p(72.0),
            &l.url,
            c.text_secondary,
            r.w - p(32.0),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn paint_offer_card(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        o: &Offer,
        folder: &str,
    ) {
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        let p = |v: f32| (v * s).round() as i32;
        k.dialog(r);
        let d = p(32.0);
        let tile = Rect::new(r.x + p(16.0), r.y + p(16.0), d, d);
        k.cv.fill_round(tile, 9.0 * s, c.accent_subtle);
        k.icon_in(Icon::Download, tile, 16.0, c.accent);
        let tx = tile.right() + p(12.0);
        let tw = r.right() - tx - p(16.0);
        k.text(Font::Semi, 14.0, tx, r.y + p(29.0), &o.name, c.text, tw);
        k.text(
            Font::Regular,
            12.0,
            tx,
            r.y + p(47.0),
            &format!("{} from the server · to {folder}", fmt_bytes(o.size)),
            c.text_muted,
            tw,
        );
    }

    // ---- The panel -------------------------------------------------------

    /// The Session page's helper card (nothing without a helper).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn page_session_helper(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return y;
        };
        let v = t.helper.clone();
        if !v.present() {
            return y;
        }
        self.caption(cv, te, f, x, y, w, "Server helper");
        y += p(26.0);
        let (icon, tone, title, sub) = match &v.status {
            // Paired here; the helper still waits for its own user.
            Status::Paired if v.server_pending => (
                Icon::Shield,
                Tone::Warning,
                "Paired here".to_string(),
                "Now confirm the code on the server".into(),
            ),
            Status::Paired => (
                Icon::ShieldCheck,
                Tone::Success,
                "Paired".to_string(),
                v.hello
                    .as_ref()
                    .map(|h| format!("remora-agent {} · build {}", h.version, h.os_build))
                    .unwrap_or_else(|| "Waiting for its details".into()),
            ),
            Status::Handshaking => (
                Icon::Refresh,
                Tone::Warning,
                "Connecting…".into(),
                "Encrypted handshake with the helper".into(),
            ),
            Status::Pairing { .. } => (
                Icon::Shield,
                Tone::Accent,
                "Waiting for you".into(),
                "Compare the code on the server, then pair".into(),
            ),
            Status::Failed(why) => (
                Icon::ShieldAlert,
                Tone::Danger,
                "Not connected".into(),
                why.clone(),
            ),
            Status::Blocked => (
                Icon::ShieldAlert,
                Tone::Danger,
                "Pairing blocked".into(),
                "Too many unanswered tries".into(),
            ),
            Status::Absent => (
                Icon::Shield,
                Tone::Muted,
                "Gone".into(),
                "The helper closed its channel".into(),
            ),
        };
        // Label, value and an optional meter (fill, tone).
        type InfoRow<'a> = (&'a str, String, Option<(f32, Tone)>);
        let mut rows: Vec<InfoRow> = Vec::new();
        if let (Status::Paired, Some(i)) = (&v.status, &v.info) {
            rows.push((
                "Screen",
                if i.locked { "Locked" } else { "Unlocked" }.into(),
                None,
            ));
            rows.push((
                "Idle",
                fmt_dur(Duration::from_millis(i.idle_ms as u64)),
                None,
            ));
            let cpu = i.cpu_percent.min(100);
            let tone = if cpu >= 90 {
                Tone::Danger
            } else {
                Tone::Accent
            };
            rows.push(("CPU", format!("{cpu} %"), Some((cpu as f32 / 100.0, tone))));
            let frac = if i.mem_total > 0 {
                (i.mem_used as f64 / i.mem_total as f64).clamp(0.0, 1.0) as f32
            } else {
                0.0
            };
            let tone = if frac >= 0.9 {
                Tone::Danger
            } else {
                Tone::Accent
            };
            rows.push((
                "Memory",
                format!("{} of {}", fmt_bytes(i.mem_used), fmt_bytes(i.mem_total)),
                Some((frac, tone)),
            ));
        }
        let mut notes: Vec<(String, Tone)> = Vec::new();
        if v.aborted > 0 {
            let n = v.aborted;
            notes.push((
                if n == 1 {
                    "A pairing attempt ended unanswered".into()
                } else {
                    format!("{n} pairing attempts ended unanswered")
                },
                Tone::Warning,
            ));
        }
        if v.refusals > 0 {
            notes.push(("A second helper was refused".into(), Tone::Warning));
        }
        // The key's fingerprint in two lines of five groups (never cut).
        let fp_lines = v
            .fingerprint
            .as_ref()
            .filter(|_| !matches!(v.status, Status::Absent | Status::Blocked))
            .map(|fp| {
                let g: Vec<&str> = fp.split(' ').collect();
                let half = g.len().div_ceil(2);
                (g[..half].join(" "), g[half..].join(" "))
            });
        let blocked = v.status == Status::Blocked;
        if blocked {
            notes.push(("Retry only if you expect this helper".into(), Tone::Danger));
        }
        let allowed = (v.status == Status::Paired).then(|| {
            let mut a = Vec::new();
            if v.accepted & cap::OPEN_URL != 0 {
                a.push("links");
            }
            if v.accepted & cap::FILE_DOWN != 0 {
                a.push("files in");
            }
            if v.accepted & cap::FILE_UP != 0 {
                a.push("files out");
            }
            if a.is_empty() {
                "session info only".to_string()
            } else {
                a.join(", ")
            }
        });
        let mut heights = vec![p(58.0)];
        heights.extend(std::iter::repeat_n(p(38.0), rows.len()));
        heights.extend(std::iter::repeat_n(p(38.0), notes.len()));
        if fp_lines.is_some() {
            heights.push(p(52.0));
        }
        if allowed.is_some() {
            heights.push(p(52.0));
        }
        if blocked {
            heights.push(p(56.0));
        }
        let cells = self.card(cv, x, y, w, &heights);
        let mut k = Kit::new(cv, te, f, s);
        let head = cells[0];
        let d = p(32.0);
        let tile = Rect::new(head.x + p(12.0), head.y + (head.h - d) / 2, d, d);
        k.cv.fill_round(tile, 9.0 * s, tone.subtle());
        k.icon_in(icon, tile, 16.0, tone.color());
        let tx = tile.right() + p(12.0);
        let tw = head.right() - tx - p(12.0);
        k.text(
            Font::Semi,
            size::BODY,
            tx,
            head.y + p(25.0),
            &title,
            c.text,
            tw,
        );
        let sub_c = if tone == Tone::Danger {
            c.danger
        } else {
            c.text_muted
        };
        k.text(
            Font::Regular,
            size::SMALL - 0.5,
            tx,
            head.y + p(43.0),
            &sub,
            sub_c,
            tw,
        );
        let mut i = 1;
        for (label, value, bar) in &rows {
            let r = cells[i];
            i += 1;
            k.text_in(
                Font::Regular,
                12.5,
                Rect::new(r.x + p(14.0), r.y, p(80.0), r.h),
                label,
                c.text_muted,
            );
            let vw = k.measure(Font::Regular, 12.5, value).min(r.w - p(110.0));
            k.text_right(
                Font::Regular,
                12.5,
                Rect::new(r.right() - p(14.0) - vw, r.y, vw, r.h),
                value,
                c.text,
            );
            if let Some((frac, tone)) = bar {
                // A meter between the label and the value.
                let bx = r.x + p(96.0);
                let bw = (r.right() - p(14.0) - vw - p(12.0) - bx).max(0);
                if bw > p(24.0) {
                    let track = Rect::new(bx, r.y + (r.h - p(4.0)) / 2, bw, p(4.0));
                    k.cv.fill_round(track, 2.0 * s, c.surface_hover);
                    let fw = ((bw as f32) * frac).round() as i32;
                    if fw > 0 {
                        k.cv.fill_round(
                            Rect::new(track.x, track.y, fw.max(p(4.0)), track.h),
                            2.0 * s,
                            tone.color(),
                        );
                    }
                }
            }
        }
        for (text, tone) in &notes {
            let r = cells[i];
            i += 1;
            k.cv.fill_circle(
                (r.x + p(18.0)) as f32,
                (r.y + r.h / 2) as f32,
                3.0 * s,
                tone.color(),
            );
            k.text_in(
                Font::Regular,
                12.0,
                Rect::new(r.x + p(30.0), r.y, r.w - p(44.0), r.h),
                text,
                c.text_secondary,
            );
        }
        if let Some((l1, l2)) = &fp_lines {
            let r = cells[i];
            i += 1;
            k.text(
                Font::Regular,
                12.5,
                r.x + p(14.0),
                r.y + p(22.0),
                "Fingerprint",
                c.text_muted,
                p(90.0),
            );
            for (n, line) in [l1, l2].into_iter().enumerate() {
                let lw = k.measure(Font::Regular, 11.5, line).min(r.w - p(120.0));
                k.text(
                    Font::Regular,
                    11.5,
                    r.right() - p(14.0) - lw,
                    r.y + p(21.0) + n as i32 * p(16.0),
                    line,
                    c.text_secondary,
                    lw + 1,
                );
            }
        }
        if let Some(a) = &allowed {
            let r = cells[i];
            i += 1;
            k.text(
                Font::Regular,
                12.5,
                r.x + p(14.0),
                r.y + p(21.0),
                "Allowed",
                c.text_muted,
                p(80.0),
            );
            let vw = k.measure(Font::Regular, 12.5, a).min(r.w - p(110.0));
            k.text(
                Font::Regular,
                12.5,
                r.right() - p(14.0) - vw,
                r.y + p(21.0),
                a,
                c.text,
                vw + 1,
            );
            k.text(
                Font::Regular,
                11.5,
                r.x + p(14.0),
                r.y + p(39.0),
                "Change it in the connection's Sharing settings",
                c.text_muted,
                r.w - p(28.0),
            );
        }
        if blocked {
            let r = cells[i];
            drop(k);
            let b = Button::secondary("Retry pairing").icon(Icon::Refresh);
            self.btn(
                cv,
                te,
                f,
                Rect::new(
                    r.x + p(12.0),
                    r.y + (r.h - p(34.0)) / 2,
                    r.w - p(24.0),
                    p(34.0),
                ),
                &b,
                Hit::RetryHelperPairing(id),
            );
        }
        y + heights.iter().sum::<i32>() + p(24.0)
    }

    /// The Sharing page's transfers and Send files (nothing without them).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn page_sharing_transfers(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
        id: u64,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let Some(t) = self.tabs.iter().find(|t| t.id == id) else {
            return y;
        };
        let (host, v) = (t.host.clone(), t.helper.clone());
        if v.transfers.is_empty() && !v.can_send() {
            return y;
        }
        if v.transfers.iter().any(|r| !r.active()) {
            self.caption_action(
                cv,
                te,
                f,
                x,
                y,
                w,
                "Files with the server",
                "Clear finished",
                Hit::TransfersClear(id),
            );
        } else {
            self.caption(cv, te, f, x, y, w, "Files with the server");
        }
        y += p(26.0);
        let n = v.transfers.len();
        if n > 0 {
            let cells = self.card(cv, x, y, w, &vec![p(60.0); n]);
            for (i, (r, row)) in cells.iter().zip(&v.transfers).enumerate() {
                let (line, tone) = row_line(row);
                let act = if row.active() {
                    Some((
                        Icon::Close,
                        Variant::DangerGhost,
                        Hit::TransferCancel(id, i),
                    ))
                } else if row.path().is_some() {
                    Some((Icon::FolderOpen, Variant::Ghost, Hit::TransferShow(id, i)))
                } else {
                    None
                };
                let btn = Rect::new(
                    r.right() - p(40.0),
                    r.y + (r.h - p(28.0)) / 2,
                    p(28.0),
                    p(28.0),
                );
                {
                    let mut k = Kit::new(cv, te, f, s);
                    let d = p(30.0);
                    let tile = Rect::new(r.x + p(12.0), r.y + (r.h - d) / 2, d, d);
                    let (fill, fg) = match row.state {
                        RowState::Done => (c.success_subtle, c.success),
                        RowState::Failed(_) => (c.danger_subtle, c.danger),
                        _ => (c.accent_subtle, c.accent),
                    };
                    k.cv.fill_round(tile, 8.0 * s, fill);
                    let icon = match row.dir {
                        Direction::Send => Icon::Upload,
                        Direction::Receive => Icon::Download,
                    };
                    k.icon_in(icon, tile, 15.0, fg);
                    let tx = tile.right() + p(10.0);
                    let tw = btn.x - tx - p(8.0);
                    k.text(Font::Semi, 12.5, tx, r.y + p(25.0), &row.name, c.text, tw);
                    let lc = match tone {
                        Tone::Danger => c.danger,
                        Tone::Warning => c.warning,
                        _ => c.text_muted,
                    };
                    k.text(Font::Regular, 11.5, tx, r.y + p(42.0), &line, lc, tw);
                    if matches!(row.state, RowState::Running | RowState::Paused) {
                        let track = Rect::new(tx, r.bottom() - p(9.0), tw, p(3.0));
                        k.cv.fill_round(track, 1.5 * s, c.surface_hover);
                        let frac = if row.total > 0 {
                            (row.done as f64 / row.total as f64).clamp(0.0, 1.0)
                        } else {
                            0.0
                        };
                        let fw = (tw as f64 * frac).round() as i32;
                        let color = if row.state == RowState::Paused {
                            c.warning
                        } else {
                            c.accent
                        };
                        if fw > 0 {
                            k.cv.fill_round(Rect::new(tx, track.y, fw, track.h), 1.5 * s, color);
                        }
                    }
                }
                if let Some((icon, variant, hit)) = act {
                    self.icon_btn(cv, te, f, btn, icon, variant, hit);
                }
            }
            y += n as i32 * p(60.0) + p(12.0);
        }
        if v.can_send() {
            let label = format!("Send files to {host}…");
            self.btn(
                cv,
                te,
                f,
                Rect::new(x, y, w, p(34.0)),
                &Button::secondary(&label).icon(Icon::Upload),
                Hit::SendFiles(id),
            );
            y += p(34.0);
            self.hint(
                cv,
                te,
                f,
                x,
                y + p(20.0),
                w,
                "Or drop them onto the session.",
            );
            y += p(32.0);
        }
        y + p(16.0)
    }

    // ---- The connection editor -----------------------------------------

    /// The editor's "Server helper" section (Sharing page).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn form_helper(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        x: i32,
        mut y: i32,
        w: i32,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let h = self.opts.helper.clone();
        y += p(24.0);
        self.caption(cv, te, f, x, y, w, "Server helper");
        y += p(26.0);
        enum R {
            Switch(Icon, &'static str, &'static str, bool, Hit),
            Folder,
        }
        let mut rows = vec![R::Switch(
            Icon::Link,
            "Open links on this PC",
            "Asks first; only http and https links",
            h.open_links,
            Hit::FormHelper(0),
        )];
        if h.open_links {
            rows.push(R::Switch(
                Icon::Bolt,
                "Open them without asking",
                "Links from this server open at once",
                h.links_unasked,
                Hit::FormHelper(3),
            ));
        }
        rows.push(R::Switch(
            Icon::Download,
            "Receive files from the server",
            "Asks for each file",
            h.receive_files,
            Hit::FormHelper(1),
        ));
        if h.receive_files {
            rows.push(R::Folder);
        }
        rows.push(R::Switch(
            Icon::Upload,
            "Send files to the server",
            "Drop them onto the session",
            h.send_files,
            Hit::FormHelper(2),
        ));
        let cells = self.card(cv, x, y, w, &vec![p(58.0); rows.len()]);
        for (r, row) in cells.iter().zip(rows) {
            match row {
                R::Switch(icon, label, sub, on, hit) => {
                    self.card_switch_i(cv, te, f, *r, Some(icon), label, sub, on, hit)
                }
                R::Folder => {
                    let b = Button::secondary("Change…").icon(Icon::FolderOpen);
                    let bw = self.btn_w(te, f, &b);
                    let br = Rect::new(
                        r.right() - p(12.0) - bw,
                        r.y + (r.h - p(32.0)) / 2,
                        bw,
                        p(32.0),
                    );
                    let dir = crate::helper_app::download_dir(&h);
                    let shown = crate::helper_app::short_dir(&dir);
                    self.row_text(
                        cv,
                        te,
                        f,
                        *r,
                        Some(Icon::FolderOpen),
                        "Save received files in",
                        &shown,
                        false,
                        bw + p(24.0),
                    );
                    self.btn(cv, te, f, br, &b, Hit::FormDownloads);
                }
            }
        }
        y += cells.len() as i32 * p(58.0);
        // An admin's pin: the helper key this connection accepts (no code).
        if self.group_edit.is_none() {
            y += p(12.0);
            let cells = self.card(cv, x, y, w, &[p(52.0)]);
            self.field_row_i(
                cv,
                te,
                f,
                cells[0],
                "Fingerprint",
                Some(Icon::ShieldCheck),
                Field::HelperFingerprint,
                "Optional: from remora-agent fingerprint",
            );
            y += p(52.0);
            self.hint(
                cv,
                te,
                f,
                x,
                y + p(20.0),
                w,
                "Set it and only that helper is accepted, without comparing codes.",
            );
            y += p(28.0);
        }
        let host = self.field(Field::Host).text.trim().to_string();
        let port = self.field(Field::Port).text.trim().parse().unwrap_or(3389);
        if !host.is_empty()
            && self
                .helper_pins
                .contains(&remora_link::server_id(&host, port))
        {
            y += p(12.0);
            let cells = self.card(cv, x, y, w, &[p(58.0)]);
            let r = cells[0];
            let b = Button::new("Forget…", Variant::DangerGhost);
            let bw = self.btn_w(te, f, &b);
            self.row_text(
                cv,
                te,
                f,
                r,
                Some(Icon::ShieldCheck),
                "A helper is paired with this server",
                "Forget it: its next session asks to pair again",
                false,
                bw + p(24.0),
            );
            self.btn(
                cv,
                te,
                f,
                Rect::new(
                    r.right() - p(12.0) - bw,
                    r.y + (r.h - p(32.0)) / 2,
                    bw,
                    p(32.0),
                ),
                &b,
                Hit::FormForgetHelper,
            );
            y += p(58.0);
        }
        let _ = c;
        self.hint(
            cv,
            te,
            f,
            x,
            y + p(20.0),
            w,
            "Once paired, a helper shows the server's state in the session panel. It never runs anything here.",
        );
        y + p(28.0)
    }

    /// "Forget the paired helper?" over the dimmed window.
    pub(super) fn paint_forget_confirm(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        host: &str,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let (w, h) = (cv.width() as i32, cv.height() as i32);
        let all = Rect::new(0, 0, w, h);
        self.session_area = None;
        self.toolbar_clear();
        self.hits.clear();
        self.title_controls.clear();
        self.hits.push((all, Hit::Modal));
        let cw = p(440.0).min(w - p(32.0));
        let ch = p(196.0);
        let r = Rect::new((w - cw) / 2, (h - ch) / 2, cw, ch);
        {
            let mut k = Kit::new(cv, te, f, s);
            k.scrim(all);
            k.dialog(r);
            let d = p(44.0);
            let tile = Rect::new(r.x + p(28.0), r.y + p(28.0), d, d);
            k.cv.fill_round(tile, 12.0 * s, c.danger_subtle);
            k.icon_in(Icon::ShieldAlert, tile, 22.0, c.danger);
            let tx = tile.right() + p(16.0);
            let tw = r.right() - tx - p(28.0);
            k.text(
                Font::Semi,
                size::HEADING + 2.0,
                tx,
                r.y + p(46.0),
                "Forget the paired helper?",
                c.text,
                tw,
            );
            k.text(
                Font::Regular,
                12.5,
                tx,
                r.y + p(68.0),
                &format!("The next session on {host} asks to pair again."),
                c.text_secondary,
                tw,
            );
            k.hints(
                tx,
                r.y + p(98.0),
                tw,
                &[kit::Hint::Keys("Esc"), kit::Hint::Text("keeps it")],
            );
        }
        let by = r.bottom() - p(28.0) - p(36.0);
        let ok = Button::new("Forget", Variant::Danger);
        let cancel = Button::secondary("Cancel");
        let (ow, cw2) = (self.btn_w(te, f, &ok), self.btn_w(te, f, &cancel));
        let ox = r.right() - p(28.0) - ow;
        self.btn(
            cv,
            te,
            f,
            Rect::new(ox, by, ow, p(36.0)),
            &ok,
            Hit::ForgetOk,
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(ox - p(8.0) - cw2, by, cw2, p(36.0)),
            &cancel,
            Hit::ForgetCancel,
        );
    }
}

fn t_folder(v: &HelperView) -> String {
    crate::helper_app::short_dir(&crate::helper_app::download_dir(&v.opts))
}

fn changed_of(v: &HelperView) -> bool {
    v.pairing().is_some_and(|(_, c)| c)
}

// ---- Samples for `--snapshot-ui` ----------------------------------------

fn sample_hello() -> HelloView {
    HelloView {
        version: "0.1.0".into(),
        os_build: 26100,
        offered: cap::ALL,
        policy: 0,
    }
}

fn sample_rows() -> Vec<Row> {
    let mut a = Row::new(
        [1; 16],
        "Q3 report.pdf".into(),
        Direction::Receive,
        48 << 20,
    );
    a.folder = Some(crate::helper_app::default_download_dir());
    a.done = 31 << 20;
    a.rate = 6.2 * (1u64 << 20) as f64;
    a.state = RowState::Running;
    let mut b = Row::new(
        [2; 16],
        "setup-tools.zip".into(),
        Direction::Send,
        220 << 20,
    );
    b.done = 96 << 20;
    b.state = RowState::Paused;
    let mut c = Row::new([3; 16], "notes.txt".into(), Direction::Receive, 12 << 10);
    c.folder = Some(crate::helper_app::default_download_dir());
    c.done = c.total;
    c.state = RowState::Done;
    let mut d = Row::new([4; 16], "dump.bin".into(), Direction::Receive, 9 << 30);
    d.state = RowState::Failed(reason_text(reason::NO_SPACE, false));
    vec![a, b, c, d]
}

/// The sample session with its helper in `status` (paired: with session
/// info and every switch on).
fn sample_with(status: Status) -> Ui {
    let mut m = super::sample(true);
    if let Some(t) = m.tab_mut(1) {
        t.helper.opts = HelperOptions {
            open_links: true,
            receive_files: true,
            send_files: true,
            ..Default::default()
        };
        if status == Status::Paired {
            t.helper.hello = Some(sample_hello());
            t.helper.accepted = cap::ALL;
            t.helper.info = Some(SessionInfo {
                locked: false,
                idle_ms: 4 * 60_000,
                cpu_percent: 37,
                mem_used: 11_400 << 20,
                mem_total: 16 << 30,
            });
        }
        t.helper.status = status;
    }
    m.session_focus = true;
    m
}

/// A sample helper fingerprint.
const SAMPLE_FP: &str = "3f9a 07c2 b18e 5d40 9e6b a2f1 0c77 e43d 1b25 86f9";

/// The pairing question over the session; `changed`: the key changed.
pub fn sample_pairing(changed: bool) -> Ui {
    let mut m = sample_with(Status::Pairing {
        sas: Sas(482_913),
        changed,
    });
    if let Some(t) = m.tab_mut(1) {
        t.helper.fingerprint = Some(SAMPLE_FP.into());
    }
    m
}

/// A link and a file offer waiting over the running session.
pub fn sample_cards() -> Ui {
    let mut m = sample_with(Status::Paired);
    if let Some(t) = m.tab_mut(1) {
        t.helper.links.push(LinkAsk {
            request_id: 7,
            url: "https://intranet.corp.example/wiki/Deploy_checklist?section=rollback".into(),
            host: "intranet.corp.example".into(),
        });
        t.helper.offers.push(Offer {
            id: [9; 16],
            name: "Q3 report.pdf".into(),
            size: 3_350_000,
        });
    }
    m
}

/// Files dragged over the session: sending possible, or switched off.
pub fn sample_drop(on: bool) -> Ui {
    let mut m = sample_with(Status::Paired);
    if !on && let Some(t) = m.tab_mut(1) {
        t.helper.opts.send_files = false;
        t.helper.accepted &= !cap::FILE_UP;
    }
    m.dropping = 3;
    m
}

/// The panel's Session page with the helper `paired` (or failed), or its
/// Sharing page with transfers.
pub fn sample_helper_panel(page: u8, paired: bool) -> Ui {
    let mut m = if paired {
        let mut m = sample_with(Status::Paired);
        if let Some(t) = m.tab_mut(1) {
            t.helper.fingerprint = Some(SAMPLE_FP.into());
        }
        m
    } else {
        let mut m = sample_with(Status::Failed("pairing rejected".into()));
        if let Some(t) = m.tab_mut(1) {
            t.helper.aborted = 1;
        }
        m
    };
    m.drawer_page = page;
    m.session_focus = false;
    if page == 0
        && let Some(t) = m.tab_mut(1)
    {
        t.helper.transfers = sample_rows();
    }
    m
}

/// The Session page with pairing blocked after aborted attempts, or a
/// helper still waiting for its own user's answer (`pending`).
pub fn sample_helper_blocked(pending: bool) -> Ui {
    let mut m = if pending {
        let mut m = sample_with(Status::Paired);
        if let Some(t) = m.tab_mut(1) {
            t.helper.fingerprint = Some(SAMPLE_FP.into());
            t.helper.server_pending = true;
        }
        m
    } else {
        let mut m = sample_with(Status::Blocked);
        if let Some(t) = m.tab_mut(1) {
            t.helper.aborted = 2;
        }
        m
    };
    m.drawer_page = 3;
    m.session_focus = false;
    m
}

/// The editor's Sharing page with the helper switches on and a paired
/// helper to forget; with `confirm`, the forget question over it.
pub fn sample_helper_form(confirm: bool) -> Ui {
    let mut m = super::sample_form(3);
    m.opts.helper = HelperOptions {
        open_links: true,
        links_unasked: false,
        receive_files: true,
        send_files: false,
        download_dir: None,
        fingerprint: None,
    };
    m.field_mut(Field::HelperFingerprint).set(SAMPLE_FP);
    let host = m.field(Field::Host).text.trim().to_string();
    let port = m.field(Field::Port).text.trim().parse().unwrap_or(3389);
    m.helper_pins.insert(remora_link::server_id(&host, port));
    // The helper section sits below the shared folders.
    m.home_scroll = 900;
    if confirm {
        m.forget = Some((remora_link::server_id(&host, port), host));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::HelperState as H;

    fn now() -> Instant {
        Instant::now()
    }

    fn painted(m: &mut Ui, w: usize, h: usize) -> Option<(TextEngine, Fonts)> {
        let mut te = TextEngine::new();
        let fonts = load_fonts(&mut te)?;
        let mut px = vec![0u32; w * h];
        m.paint_snapshot(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        Some((te, fonts))
    }

    fn rect_of(m: &Ui, hit: Hit) -> Option<Rect> {
        m.helper_ov
            .buttons
            .iter()
            .chain(m.hits.iter())
            .find(|(_, h)| *h == hit)
            .map(|(r, _)| *r)
    }

    fn click(m: &mut Ui, te: &mut TextEngine, fonts: &Fonts, hit: Hit) -> Option<Action> {
        let r = rect_of(m, hit).unwrap_or_else(|| panic!("{hit:?} not painted"));
        let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
        m.mouse_move(x, y);
        m.mouse_down(x, y, te, fonts);
        m.mouse_up(x, y)
    }

    fn is_helper_hit(h: &Hit) -> bool {
        matches!(
            h,
            Hit::HelperPair(_)
                | Hit::HelperNoPair(_)
                | Hit::LinkOpen(_)
                | Hit::LinkAlways(_)
                | Hit::LinkIgnore(_)
                | Hit::OfferSave(..)
                | Hit::OfferDecline(..)
                | Hit::TransferCancel(..)
                | Hit::TransferShow(..)
                | Hit::TransfersClear(_)
                | Hit::SendFiles(_)
                | Hit::ForgetHelper(_)
        )
    }

    #[test]
    fn links_are_refused_unless_allowed_and_web() {
        let mut o = HelperOptions::default();
        let web = "https://example.org/a";
        assert_eq!(
            link_decision(&o, web),
            LinkDecision::Refuse(UrlStatus::Disabled)
        );
        o.open_links = true;
        assert_eq!(link_decision(&o, web), LinkDecision::Ask);
        assert_eq!(link_decision(&o, "HTTP://example.org"), LinkDecision::Ask);
        for bad in [
            "file:///C:/Windows/notepad.exe",
            "javascript:alert(1)",
            "ms-settings:privacy",
            "mailto:a@b.example",
            r"\\host\share\run.exe",
            "https://good.example@evil.example/",
        ] {
            assert_eq!(
                link_decision(&o, bad),
                LinkDecision::Refuse(UrlStatus::Invalid),
                "{bad}"
            );
        }
        o.links_unasked = true;
        assert_eq!(link_decision(&o, web), LinkDecision::Open);
        // Even "Always" never opens a non-web link.
        assert_eq!(
            link_decision(&o, "file:///C:/x"),
            LinkDecision::Refuse(UrlStatus::Invalid)
        );
    }

    #[test]
    fn link_events_ask_open_or_answer() {
        let mut v = HelperView::default();
        v.set_status(H::Paired);
        let ev = |id| HelperEvent::OpenUrl {
            request_id: id,
            url: "https://example.org/x".into(),
        };
        assert_eq!(
            v.apply(ev(1), now()),
            vec![Effect::Answer(1, UrlStatus::Disabled)]
        );
        v.opts.open_links = true;
        assert!(v.apply(ev(2), now()).is_empty());
        assert_eq!(v.links.len(), 1);
        assert_eq!(v.links[0].host, "example.org");
        v.opts.links_unasked = true;
        assert_eq!(
            v.apply(ev(3), now()),
            vec![Effect::Open(3, "https://example.org/x".into())]
        );
        // The helper going away drops the questions of its session.
        v.apply(HelperEvent::State(H::NotPresent), now());
        assert!(v.links.is_empty());
    }

    #[test]
    fn pairing_modal_confirms_rejects_and_a_changed_key_defaults_to_no() {
        let Some((mut te, fonts)) = ({
            let mut m = sample_pairing(false);
            painted(&mut m, 1320, 860).map(|tf| (tf.0, tf.1))
        }) else {
            return;
        };
        let mut m = sample_pairing(false);
        let mut px = vec![0u32; 1320 * 860];
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert!(m.helper_modal_open());
        assert!(!m.keys_to_session(), "the session gets no keys");
        assert!(m.session_input_blocked(), "nor the mouse");
        // No toolbar under the question.
        assert!(m.overlay_rect().is_some());
        let sas = Sas(482_913);
        assert!(matches!(
            m.key(Key::Enter),
            Some(Action::HelperPairing(1, s, true)) if s == sas
        ));
        assert!(matches!(
            m.key(Key::Esc),
            Some(Action::HelperPairing(1, s, false)) if s == sas
        ));
        assert!(m.key(Key::Char('a')).is_none(), "typing goes nowhere");
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::HelperPair(1)),
            Some(Action::HelperPairing(1, _, true))
        ));
        // A click on the picture under it is not the session's.
        let ov = m.helper_ov.area;
        assert_eq!(m.helper_overlay_hit(ov.x + 4, ov.y + 4), Some(Hit::Modal));

        let mut m = sample_pairing(true);
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert!(
            matches!(m.key(Key::Enter), Some(Action::HelperPairing(1, _, false))),
            "Enter on a changed key does not pair"
        );
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::HelperNoPair(1)),
            Some(Action::HelperPairing(1, _, false))
        ));
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::HelperPair(1)),
            Some(Action::HelperPairing(1, _, true))
        ));
    }

    #[test]
    fn a_pairing_that_ends_unanswered_is_counted_and_shown() {
        let mut v = HelperView::default();
        let fx = v.apply(
            HelperEvent::State(H::AwaitingPairing {
                sas: Sas(1),
                changed: false,
                fingerprint: "ab12 cd34".into(),
            }),
            now(),
        );
        assert_eq!(fx, vec![Effect::PairingAsked]);
        assert!(v.pairing().is_some());
        v.apply(HelperEvent::State(H::NotPresent), now());
        assert_eq!(v.aborted, 1);
        assert!(v.present(), "the card says so");
        // A new attempt replaces the question with its own code.
        v.apply(
            HelperEvent::State(H::AwaitingPairing {
                sas: Sas(2),
                changed: false,
                fingerprint: "ab12 cd34".into(),
            }),
            now(),
        );
        assert_eq!(v.pairing(), Some((Sas(2), false)));
        v.apply(HelperEvent::State(H::Paired), now());
        assert_eq!(v.aborted, 1, "an answered one is not counted");
        v.apply(HelperEvent::State(H::PairingBlocked), now());
        assert_eq!(v.status, Status::Blocked);
    }

    #[test]
    fn drop_overlay_shows_only_for_a_paired_helper() {
        let mut v = HelperView::default();
        assert_eq!(v.drop_hint(2), None, "no helper: nothing");
        v.set_status(H::Handshaking);
        assert_eq!(v.drop_hint(2), None);
        v.set_status(H::Paired);
        v.hello = Some(sample_hello());
        assert!(matches!(v.drop_hint(2), Some(DropHint::Off(..))));
        v.opts.send_files = true;
        v.accepted = cap::SESSION_INFO | cap::FILE_UP;
        assert_eq!(v.drop_hint(2), Some(DropHint::Send(2)));
        assert_eq!(v.drop_hint(0), None, "nothing hovering");
        v.accepted = cap::SESSION_INFO;
        v.hello.as_mut().unwrap().policy = policy::DRIVES_DISABLED;
        assert_eq!(
            v.drop_hint(1),
            Some(DropHint::Off(
                "The server does not allow file transfer",
                "Its policy turns off clipboard or drive redirection."
            ))
        );
    }

    #[test]
    fn transfer_rows_follow_progress_pause_completion_and_failure() {
        let mut v = HelperView::default();
        v.set_status(H::Paired);
        let t0 = Instant::now();
        let id = [5; 16];
        v.apply(
            HelperEvent::Transfer(TransferEvent::Offered {
                id,
                name: "a.bin".into(),
                size: 4000,
                mtime: 0,
            }),
            t0,
        );
        assert_eq!(v.offers.len(), 1);
        let (got, folder) = v.accept(0).unwrap();
        assert_eq!(got, id);
        assert!(v.offers.is_empty());
        assert_eq!(v.transfers[0].state, RowState::Waiting);
        let prog = |done| {
            HelperEvent::Transfer(TransferEvent::Progress {
                id,
                direction: Direction::Receive,
                done,
                total: 4000,
            })
        };
        assert_eq!(
            v.apply(prog(1000), t0),
            vec![Effect::Reserve(id, folder.clone(), 3000)]
        );
        v.apply(prog(3000), t0 + Duration::from_secs(1));
        let r = &v.transfers[0];
        assert_eq!((r.state.clone(), r.done), (RowState::Running, 3000));
        assert!((r.rate - 2000.0).abs() < 1.0, "{}", r.rate);
        assert_eq!(r.eta(), Some(Duration::from_millis(500)));
        v.apply(
            HelperEvent::Transfer(TransferEvent::Paused {
                id,
                direction: Direction::Receive,
            }),
            t0,
        );
        assert_eq!(v.transfers[0].state, RowState::Paused);
        let fx = v.apply(
            HelperEvent::Transfer(TransferEvent::Completed {
                id,
                direction: Direction::Receive,
                name: "a (2).bin".into(),
            }),
            t0,
        );
        assert_eq!(fx[0], Effect::Release(id));
        let r = &v.transfers[0];
        assert_eq!(r.state, RowState::Done);
        assert_eq!(r.path(), Some(folder.join("a (2).bin")), "the final name");
        // An upload the server rejects.
        v.sending([6; 16], "b.txt".into(), 10);
        v.apply(
            HelperEvent::Transfer(TransferEvent::Failed {
                id: [6; 16],
                direction: Direction::Send,
                reason: reason::NO_SPACE,
                by_peer: true,
                detail: String::new(),
            }),
            t0,
        );
        assert_eq!(
            v.transfers[1].state,
            RowState::Failed("Not enough free space".into())
        );
        v.clear_finished();
        assert!(v.transfers.is_empty());
        // An offer withdrawn before the user answered goes away.
        v.apply(
            HelperEvent::Transfer(TransferEvent::Offered {
                id: [7; 16],
                name: "c".into(),
                size: 1,
                mtime: 0,
            }),
            t0,
        );
        v.apply(
            HelperEvent::Transfer(TransferEvent::Failed {
                id: [7; 16],
                direction: Direction::Receive,
                reason: reason::USER,
                by_peer: true,
                detail: String::new(),
            }),
            t0,
        );
        assert!(v.offers.is_empty());
    }

    #[test]
    fn cards_answer_links_and_offers() {
        let Some((mut te, fonts)) = painted(&mut sample_cards(), 1320, 860) else {
            return;
        };
        let mut m = sample_cards();
        let mut px = vec![0u32; 1320 * 860];
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert_eq!(m.helper_ov.cards.len(), 2);
        // The cards are not the session's.
        let card = m.helper_ov.cards[0].0;
        assert!(m.over_overlay(card.x + 3, card.y + 3));
        match click(&mut m, &mut te, &fonts, Hit::LinkIgnore(1)) {
            Some(Action::AnswerLink {
                id: 1,
                request_id: 7,
                open: false,
                ..
            }) => {}
            _ => panic!("ignore"),
        }
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        match click(&mut m, &mut te, &fonts, Hit::OfferSave(1, 0)) {
            Some(Action::AcceptFile(1, id, folder)) => {
                assert_eq!(id, [9; 16]);
                assert!(folder.ends_with(std::path::Path::new("Downloads").join("Remora")));
            }
            _ => panic!("save"),
        }
        let t = m.tab_mut(1).unwrap();
        assert!(t.helper.offers.is_empty() && t.helper.links.is_empty());
        assert_eq!(t.helper.transfers.len(), 1);
    }

    #[test]
    fn always_for_this_server_trusts_its_links() {
        let mut m = sample_cards();
        let _ = m.activate_helper(Hit::LinkAlways(1));
        assert!(m.tab_mut(1).unwrap().helper.opts.links_unasked);
        assert!(
            m.store.connections[0].options.helper.links_unasked,
            "kept for the saved connection"
        );
    }

    #[test]
    fn nothing_of_the_helper_shows_without_one() {
        let Some((mut te, fonts)) = painted(&mut super::super::sample(true), 1320, 860) else {
            return;
        };
        for page in [0u8, 3] {
            let mut m = super::super::sample_panel(page, false);
            m.dropping = 2;
            let mut px = vec![0u32; 1320 * 860];
            m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
            assert!(!m.hits.iter().any(|(_, h)| is_helper_hit(h)), "page {page}");
            assert!(m.helper_ov.buttons.is_empty() && m.helper_ov.drop.is_none());
            assert!(!m.helper_modal_open());
            assert_eq!(m.drop_hint(2), None);
            let cmds: Vec<_> = m.palette_entries().into_iter().map(|e| e.cmd).collect();
            assert!(!cmds.iter().any(|c| matches!(
                c,
                super::super::palette::Command::SendFiles(_)
                    | super::super::palette::Command::ShowTransfers(_)
                    | super::super::palette::Command::ForgetHelper(_)
            )));
        }
    }

    #[test]
    fn the_panel_lists_transfers_and_session_info() {
        let Some((mut te, fonts)) = painted(&mut super::super::sample(true), 1320, 860) else {
            return;
        };
        let mut m = sample_helper_panel(0, true);
        let mut px = vec![0u32; 1320 * 860];
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert!(rect_of(&m, Hit::SendFiles(1)).is_some());
        assert!(rect_of(&m, Hit::TransferCancel(1, 0)).is_some(), "running");
        assert!(rect_of(&m, Hit::TransferShow(1, 2)).is_some(), "done");
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::TransferShow(1, 2)),
            Some(Action::ShowInFolder(_))
        ));
        let _ = m.activate_helper(Hit::TransfersClear(1));
        assert_eq!(m.tab_mut(1).unwrap().helper.transfers.len(), 2);
    }

    #[test]
    fn forget_asks_first() {
        let Some((mut te, fonts)) = painted(&mut super::super::sample(true), 1320, 860) else {
            return;
        };
        let mut m = sample_helper_form(true);
        let mut px = vec![0u32; 1320 * 860];
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert!(m.key(Key::Esc).is_none());
        assert!(m.forget.is_none(), "Esc keeps it");
        let mut m = sample_helper_form(true);
        m.paint_snapshot(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        match m.key(Key::Enter) {
            Some(Action::ForgetHelper(s)) => assert_eq!(s, "192.168.56.20:3390"),
            _ => panic!("forget"),
        }
        assert!(m.helper_pins.is_empty());
    }

    #[test]
    fn a_blocked_pairing_offers_retry_on_the_card_and_in_the_palette() {
        let mut m = sample_helper_blocked(false);
        let Some((mut te, fonts)) = painted(&mut m, 1320, 860) else {
            return;
        };
        assert!(matches!(
            click(&mut m, &mut te, &fonts, Hit::RetryHelperPairing(1)),
            Some(Action::RetryHelperPairing(1))
        ));
        // Only while blocked.
        let mut m = sample_helper_panel(3, true);
        assert!(m.activate_helper(Hit::RetryHelperPairing(1)).is_none());
        let m = sample_helper_blocked(false);
        assert!(
            m.palette_entries()
                .into_iter()
                .map(|e| e.cmd)
                .any(|c| matches!(c, super::super::palette::Command::RetryHelperPairing(1)))
        );
    }

    #[test]
    fn an_offer_refused_unseen_is_said_once_quietly() {
        let mut v = HelperView::default();
        let refused = |id: u8| {
            HelperEvent::Transfer(TransferEvent::Failed {
                id: [id; 16],
                direction: Direction::Receive,
                reason: reason::DISABLED,
                by_peer: false,
                detail: String::new(),
            })
        };
        let fx = v.apply(refused(1), now());
        assert!(
            fx.iter()
                .any(|e| matches!(e, Effect::Notice(_, Tone::Muted))),
            "{fx:?}"
        );
        let fx = v.apply(refused(2), now());
        assert!(!fx.iter().any(|e| matches!(e, Effect::Notice(..))), "once");
    }

    #[test]
    fn the_editor_keeps_a_valid_helper_fingerprint_only() {
        let mut m = super::super::sample_form(3);
        m.field_mut(Field::HelperFingerprint).set("not hex");
        assert!(m.form().is_err());
        m.field_mut(Field::HelperFingerprint).set(SAMPLE_FP);
        let c = m.form().unwrap();
        assert_eq!(c.options.helper.fingerprint.as_deref(), Some(SAMPLE_FP));
        m.field_mut(Field::HelperFingerprint).set("  ");
        assert_eq!(m.form().unwrap().options.helper.fingerprint, None);
    }

    #[test]
    fn sizes_and_durations_read_well() {
        assert_eq!(fmt_bytes(512), "512 bytes");
        assert_eq!(fmt_bytes(3_350_000), "3.2 MB");
        assert_eq!(fmt_bytes(9 << 30), "9.0 GB");
        assert_eq!(fmt_bytes(220 << 20), "220 MB");
        assert_eq!(fmt_dur(Duration::from_secs(45)), "45 s");
        assert_eq!(fmt_dur(Duration::from_secs(240)), "4 min");
        assert_eq!(fmt_dur(Duration::from_secs(7500)), "2 h 5 min");
    }
}
