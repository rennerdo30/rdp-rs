//! The server helper in the app (RDP-42/43/44): one helper adapter per
//! tab, kept across the tab's reconnects so transfers resume; its events
//! turned into the tab's view; the user's answers carried out.
//!
//! The adapter wakes the event loop at most once per batch of events
//! (`pending`); progress repaints at most every [`PROGRESS_REDRAW`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use remora_link::msg::UrlStatus;
use remora_link::transfer::TransferEvent;

use super::{App, UserEvent};
use crate::helper::{HelperEvent, HelperHandle};
use crate::helper_app;
use crate::session;
use crate::theme::Tone;
use crate::ui::helper::{Effect, HelloView, PROGRESS_REDRAW};
use crate::ui::{Action, TabState};

/// A tab's server helper and its wake-up flag.
pub(super) struct TabHelper {
    pub(super) handle: HelperHandle,
    /// An event is queued and the event loop was told; cleared when the
    /// app drains the queue.
    pending: Arc<AtomicBool>,
}

impl App {
    /// The helper adapter of a new tab, with the app's hooks: wake-up,
    /// Mark-of-the-Web on received files, and free space net of the other
    /// downloads.
    pub(super) fn new_helper(&self, id: u64) -> TabHelper {
        let handle = HelperHandle::new();
        let pending = Arc::new(AtomicBool::new(false));
        let proxy = Mutex::new(self.proxy.clone());
        let flag = pending.clone();
        handle.set_notify(move || {
            if !flag.swap(true, Ordering::AcqRel)
                && let Ok(p) = proxy.lock()
            {
                let _ = p.send_event(UserEvent::Helper(id));
            }
        });
        handle.set_received_file_hook(|path| {
            if let Err(e) = helper_app::mark_of_the_web(path) {
                rdp::trace!("ui: no Mark-of-the-Web on {}: {e}", path.display());
            }
        });
        handle.set_free_space(helper_app::free_for_downloads);
        TabHelper { handle, pending }
    }

    fn helper_of(&self, id: u64) -> Option<HelperHandle> {
        self.sessions.get(&id).map(|s| s.helper.handle.clone())
    }

    /// Drains a tab's helper events into its view and acts on them.
    pub(super) fn helper_events(&mut self, id: u64) {
        let Some(s) = self.sessions.get(&id) else {
            return;
        };
        s.helper.pending.store(false, Ordering::Release);
        let h = s.helper.handle.clone();
        let now = Instant::now();
        let active = self.win.as_ref().and_then(|w| w.ui.active) == Some(id);
        let (mut changed, mut ticked) = (false, false);
        let mut effects = Vec::new();
        let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) else {
            while h.next_event().is_some() {}
            return;
        };
        while let Some(ev) = h.next_event() {
            let quiet = matches!(
                ev,
                HelperEvent::SessionInfo(_) | HelperEvent::Transfer(TransferEvent::Progress { .. })
            );
            if quiet {
                ticked = true;
            } else {
                changed = true;
            }
            effects.extend(t.helper.apply(ev, now));
        }
        t.helper.refusals = h.second_instance_refusals();
        if t.helper.paired() {
            t.helper.accepted = h.accepted_capabilities();
            t.helper.hello = h.hello().map(|x| HelloView {
                version: x.helper_version,
                os_build: x.os_build,
                offered: x.capabilities,
                policy: x.policy,
            });
        }
        let host = t.host.clone();
        for e in effects {
            self.helper_effect(id, &h, e, active, &host);
        }
        if changed {
            self.helper_drawn = now;
            self.dirty();
        } else if ticked && active {
            let due = self.helper_drawn + PROGRESS_REDRAW;
            if now >= due {
                self.helper_drawn = now;
                self.dirty();
            } else {
                self.helper_redraw = Some(due);
            }
        }
    }

    fn helper_effect(&mut self, id: u64, h: &HelperHandle, e: Effect, active: bool, host: &str) {
        match e {
            Effect::Answer(rid, st) => h.answer_url(rid, st),
            Effect::Open(rid, url) => self.open_link(h, rid, &url),
            Effect::Notice(text, tone) => self.message(text, tone),
            Effect::PairingAsked => {
                if active {
                    // The question takes the keyboard from the session.
                    if let Some(m) = &mut self.win {
                        m.ui.session_focus = false;
                    }
                    self.send(id, session::release_modifiers());
                } else {
                    self.message(
                        format!(
                            "The server helper on {host} asks to pair; open its tab to answer."
                        ),
                        Tone::Accent,
                    );
                }
            }
            Effect::Reserve(tid, dir, left) => helper_app::reserve(tid, &dir, left),
            Effect::Release(tid) => helper_app::release(tid),
        }
    }

    /// Opens a link the user (or "Always") allowed; the helper hears how
    /// it went.
    fn open_link(&mut self, h: &HelperHandle, rid: u32, url: &str) {
        match helper_app::open_web_url(url) {
            Ok(()) => h.answer_url(rid, UrlStatus::Opened),
            Err(e) => {
                h.answer_url(rid, UrlStatus::Declined);
                self.message(format!("Could not open the link: {e}"), Tone::Warning);
            }
        }
    }

    /// A progress repaint that waited for its turn (from `about_to_wait`).
    pub(super) fn helper_tick(&mut self) {
        if self.helper_redraw.is_some_and(|t| Instant::now() >= t) {
            self.helper_redraw = None;
            self.helper_drawn = Instant::now();
            self.dirty();
        }
    }

    /// Re-reads which servers have a paired helper.
    pub(super) fn refresh_pins(&mut self) {
        if let Some(m) = &mut self.win {
            m.ui.helper_pins = helper_app::pinned_servers();
        }
    }

    /// Sends files to the tab's server, one transfer each.
    pub(super) fn send_files(&mut self, id: u64, paths: Vec<PathBuf>) {
        let Some(h) = self.helper_of(id) else {
            return;
        };
        for path in paths {
            if path.is_dir() {
                self.message(
                    "Folders cannot be sent yet; send the files in them.",
                    Tone::Warning,
                );
                continue;
            }
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match h.send_file(&path) {
                Ok(tid) => {
                    if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                        t.helper.sending(tid, name, size);
                    }
                }
                Err(e) => self.message(format!("Cannot send {name}: {e}"), Tone::Warning),
            }
        }
        self.dirty();
    }

    /// Files dropped on the window: sent when the active session's helper
    /// takes them, otherwise nothing (the drop target said why).
    pub(super) fn dropped_file(&mut self, path: PathBuf) {
        let target = self.win.as_mut().and_then(|m| {
            m.ui.dropping = 0;
            let send = matches!(
                m.ui.drop_hint(1),
                Some(crate::ui::helper::DropHint::Send(_))
            );
            m.ui.active.filter(|_| send)
        });
        match target {
            Some(id) => self.send_files(id, vec![path]),
            None => self.dirty(),
        }
    }

    /// Releases what a closing tab still reserved for its downloads.
    pub(super) fn helper_closed(&mut self, id: u64) {
        if let Some(t) = self
            .win
            .as_ref()
            .and_then(|w| w.ui.tabs.iter().find(|t| t.id == id))
        {
            for r in &t.helper.transfers {
                helper_app::release(r.id);
            }
        }
    }

    /// The helper's actions; any other action is handed back.
    pub(super) fn helper_action(&mut self, a: Action) -> Option<Action> {
        match a {
            Action::HelperPairing(id, sas, pair) => {
                // Handled: nothing to do for a closed tab.
                let h = self.helper_of(id)?;
                if pair {
                    if let Err(e) = h.confirm_pairing(sas) {
                        self.message(format!("Server helper: {e}."), Tone::Warning);
                    }
                    self.refresh_pins();
                } else {
                    h.reject_pairing(sas);
                }
                // The session gets the keyboard back.
                if let Some(m) = &mut self.win
                    && m.ui.active == Some(id)
                    && m.ui
                        .active_tab()
                        .is_some_and(|t| matches!(t.state, TabState::Connected { .. }))
                {
                    m.ui.session_focus = true;
                }
                self.helper_events(id);
                self.dirty();
            }
            Action::AnswerLink {
                id,
                request_id,
                url,
                open,
            } => {
                if let Some(h) = self.helper_of(id) {
                    if open {
                        self.open_link(&h, request_id, &url);
                    } else {
                        h.answer_url(request_id, UrlStatus::Declined);
                    }
                }
                self.dirty();
            }
            Action::AcceptFile(id, tid, folder) => {
                // Handled: nothing to do for a closed tab.
                let h = self.helper_of(id)?;
                let r = std::fs::create_dir_all(&folder)
                    .map_err(|e| format!("Cannot create {}: {e}", folder.display()))
                    .and_then(|()| h.accept_file(tid, &folder));
                let size = self
                    .win
                    .as_ref()
                    .and_then(|w| w.ui.tabs.iter().find(|t| t.id == id))
                    .and_then(|t| t.helper.transfers.iter().find(|r| r.id == tid))
                    .map_or(0, |r| r.total);
                match r {
                    Ok(()) => helper_app::reserve(tid, &folder, size),
                    Err(e) => {
                        h.reject_file(tid);
                        if let Some(t) = self.win.as_mut().and_then(|w| w.ui.tab_mut(id)) {
                            t.helper.fail(tid, e);
                        }
                    }
                }
                self.helper_events(id);
                self.dirty();
            }
            Action::DeclineFile(id, tid) => {
                if let Some(h) = self.helper_of(id) {
                    h.reject_file(tid);
                }
                self.dirty();
            }
            Action::CancelTransfer(id, tid) => {
                if let Some(h) = self.helper_of(id) {
                    h.cancel_file(tid);
                }
                helper_app::release(tid);
                self.helper_events(id);
                self.dirty();
            }
            Action::ShowInFolder(path) => super::show_in_explorer(&path),
            Action::PickSendFiles(id) => {
                let proxy = Mutex::new(self.proxy.clone());
                crate::picker::pick_files(self.hwnd(), move |files| {
                    if !files.is_empty()
                        && let Ok(p) = proxy.lock()
                    {
                        let _ = p.send_event(UserEvent::PickedFiles(id, files));
                    }
                });
            }
            Action::BrowseDownloads => {
                let proxy = Mutex::new(self.proxy.clone());
                crate::picker::pick_with(
                    crate::picker::Pick::DownloadFolder,
                    self.hwnd(),
                    move |dir| {
                        if let (Some(dir), Ok(p)) = (dir, proxy.lock()) {
                            let _ = p.send_event(UserEvent::PickedDownloads(dir));
                        }
                    },
                );
            }
            Action::ForgetHelper(server) => {
                let r = helper_app::pins_path()
                    .ok_or_else(|| "no settings folder".to_string())
                    .and_then(|p| helper_app::forget_pin(&p, &server));
                if let Err(e) = r {
                    self.message(format!("Could not forget the helper: {e}"), Tone::Danger);
                }
                self.refresh_pins();
                self.dirty();
            }
            other => return Some(other),
        }
        None
    }
}
