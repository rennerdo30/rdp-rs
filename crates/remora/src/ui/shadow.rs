//! Shadowing from the app (RDP-85): the "Sessions on <server>" dialog
//! lists a server's sessions and watches or controls one, like
//! `remora <host> --list-sessions` and `--shadow ID [--control]`; the
//! command palette also opens Desktop Sharing invitation files. The app
//! does the work off the UI thread ([`crate::shadow`]) and reports back
//! with [`Ui::shadow_sessions`] and [`Ui::shadow_failed`].

use ffwd_render::{Canvas, Rect, TextEngine};

use super::{Action, Field, Fonts, Hit, Ui};
use crate::icons::Icon;
use crate::kit::{Button, Font, Kit, State};
use crate::shadow::RemoteSession;
use crate::theme::{pal, size};

/// Session rows shown; a server with more lists them on the command line.
const MAX_ROWS: usize = 7;

/// The dialog's state.
#[derive(Clone, Debug)]
pub enum ShadowState {
    /// Reading the server's sessions.
    Loading,
    /// The list could not be read, or a shadow request failed.
    Failed(String),
    /// The sessions with a signed-in user.
    Sessions(Vec<RemoteSession>),
    /// Asking the server for session `id` (and its user, with consent).
    Asking(u32),
}

#[derive(Clone, Debug)]
pub struct ShadowDialog {
    /// The connection's name and host.
    pub name: String,
    pub host: String,
    pub state: ShadowState,
    /// Ask the session's user first (mstsc without /noConsentPrompt).
    pub consent: bool,
    /// The last list, kept while asking or after a failed request.
    sessions: Vec<RemoteSession>,
}

impl Ui {
    /// Opens the dialog for the connection in the editor (its Host as
    /// typed) and asks the app to read its sessions.
    pub(super) fn open_shadow(&mut self) -> Option<Action> {
        let host = self.field(Field::Host).text.trim().to_string();
        if host.is_empty() {
            self.set_message(
                "Enter the server's name first.",
                crate::theme::Tone::Warning,
            );
            return None;
        }
        let name = Some(self.field(Field::Name).text.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| host.clone());
        self.shadow = Some(ShadowDialog {
            name,
            host: host.clone(),
            state: ShadowState::Loading,
            consent: true,
            sessions: Vec::new(),
        });
        Some(Action::ListSessions(host))
    }

    /// The app read `host`'s sessions (or failed to).
    pub fn shadow_sessions(&mut self, host: &str, r: Result<Vec<RemoteSession>, String>) {
        let Some(d) = self.shadow.as_mut().filter(|d| d.host == host) else {
            return;
        };
        d.state = match r {
            Ok(list) => {
                // Only sessions with a signed-in user can be shadowed.
                d.sessions = list.into_iter().filter(|s| !s.user.is_empty()).collect();
                ShadowState::Sessions(d.sessions.clone())
            }
            Err(e) => ShadowState::Failed(e),
        };
    }

    /// A shadow request failed: shown in the dialog when it is still open.
    /// Returns false when it is not (the app shows a message instead).
    pub fn shadow_failed(&mut self, e: &str) -> bool {
        match self.shadow.as_mut() {
            Some(d) => {
                d.state = ShadowState::Failed(e.to_string());
                true
            }
            None => false,
        }
    }

    /// The dialog is open for `host` and waits for a shadow request.
    pub fn shadow_waiting(&self, host: &str) -> bool {
        self.shadow
            .as_ref()
            .is_some_and(|d| d.host == host && matches!(d.state, ShadowState::Asking(_)))
    }

    /// The shared desktop is connecting: the dialog has done its job.
    pub fn shadow_done(&mut self) {
        self.shadow = None;
    }

    pub(super) fn activate_shadow(&mut self, hit: Hit) -> Option<Action> {
        let d = self.shadow.as_mut()?;
        match hit {
            Hit::ShadowClose => self.shadow = None,
            Hit::ShadowConsent => d.consent = !d.consent,
            Hit::ShadowRefresh => {
                d.state = ShadowState::Loading;
                return Some(Action::ListSessions(d.host.clone()));
            }
            Hit::ShadowWatch(i) | Hit::ShadowControl(i) => {
                let s = d.sessions.get(i)?;
                let id = s.id;
                let req = crate::shadow::ShadowRequest {
                    session_id: id,
                    control: matches!(hit, Hit::ShadowControl(_)),
                    consent: d.consent,
                };
                d.state = ShadowState::Asking(id);
                return Some(Action::Shadow {
                    name: d.name.clone(),
                    host: d.host.clone(),
                    req,
                });
            }
            _ => {}
        }
        None
    }

    pub(super) fn shadow_key(&mut self, k: &super::Key) -> Option<Action> {
        match k {
            super::Key::Esc => self.activate_shadow(Hit::ShadowClose),
            super::Key::Enter if matches!(self.shadow.as_ref()?.state, ShadowState::Failed(_)) => {
                self.activate_shadow(Hit::ShadowRefresh)
            }
            _ => None,
        }
    }

    /// "Sessions on <server>" over the dimmed window.
    pub(super) fn paint_shadow(&mut self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let Some(d) = self.shadow.clone() else {
            return;
        };
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

        let rows = match &d.state {
            ShadowState::Sessions(list) => list.len().clamp(1, MAX_ROWS),
            _ => 1,
        };
        let row_h = p(48.0);
        let pad = p(28.0);
        let cw = p(560.0).min(w - p(32.0));
        let ch = p(130.0) + rows as i32 * row_h + p(14.0) + p(36.0) + pad;
        let r = Rect::new((w - cw) / 2, ((h - ch) / 2).max(p(16.0)), cw, ch);
        let tx;
        {
            let mut k = Kit::new(cv, te, f, s);
            k.scrim(all);
            k.dialog(r);
            let t = p(44.0);
            let tile = Rect::new(r.x + pad, r.y + pad, t, t);
            k.cv.fill_round(tile, 12.0 * s, c.accent_subtle);
            k.icon_in(Icon::Monitors, tile, 22.0, c.accent);
            tx = tile.right() + p(16.0);
            let tw = r.right() - tx - pad;
            k.text(
                Font::Semi,
                size::HEADING + 2.0,
                tx,
                r.y + p(46.0),
                &format!("Sessions on {}", d.name),
                c.text,
                tw,
            );
            k.text(
                Font::Regular,
                12.5,
                tx,
                r.y + p(68.0),
                &format!("Shadow a signed-in user's session on {}.", d.host),
                c.text_secondary,
                tw,
            );
        }

        // Ask the user first.
        let sy = r.y + p(92.0);
        let sw = Rect::new(tx, sy, p(36.0), p(20.0));
        let row = Rect::new(tx, sy - p(4.0), r.right() - pad - tx, p(28.0));
        let hover = self.hover == Some(Hit::ShadowConsent);
        {
            let mut k = Kit::new(cv, te, f, s);
            k.switch(sw.x, sw.y, d.consent, State::hover(hover));
            k.text(
                Font::Semi,
                size::BODY,
                sw.right() + p(10.0),
                sy + p(14.0),
                "Ask the user first",
                c.text,
                row.w,
            );
            let note = if d.consent {
                "they see a prompt and can decline"
            } else {
                "no prompt: the server's policy must allow it"
            };
            let nx = sw.right()
                + p(10.0)
                + k.measure(Font::Semi, size::BODY, "Ask the user first")
                + p(10.0);
            k.text(
                Font::Regular,
                size::SMALL,
                nx,
                sy + p(14.0),
                note,
                c.text_muted,
                row.right() - nx,
            );
        }
        self.hits.push((row, Hit::ShadowConsent));

        // The list, or what is going on.
        let lx = r.x + pad;
        let lw = r.w - 2 * pad;
        let mut y = r.y + p(130.0);
        let status =
            |cv: &mut Canvas, te: &mut TextEngine, y: i32, icon: Icon, text: &str, tone: u32| {
                let mut k = Kit::new(cv, te, f, s);
                let box_ = Rect::new(lx, y, lw, row_h - p(6.0));
                k.cv.fill_round(box_, 10.0 * s, c.surface_hover);
                k.icon_in(
                    icon,
                    Rect::new(lx + p(12.0), y, p(20.0), box_.h),
                    16.0,
                    tone,
                );
                k.text(
                    Font::Regular,
                    size::BODY,
                    lx + p(40.0),
                    y + box_.h / 2 + p(5.0),
                    text,
                    tone,
                    lw - p(52.0),
                );
            };
        match &d.state {
            ShadowState::Loading => status(
                cv,
                te,
                y,
                Icon::Refresh,
                "Reading the server's sessions…",
                c.text_secondary,
            ),
            ShadowState::Asking(id) => status(
                cv,
                te,
                y,
                Icon::Refresh,
                &if d.consent {
                    format!(
                        "Asking the user of session {id}; they have about 30 seconds to answer…"
                    )
                } else {
                    format!("Asking the server for session {id}…")
                },
                c.text_secondary,
            ),
            ShadowState::Failed(e) => status(cv, te, y, Icon::Warning, e, c.danger),
            ShadowState::Sessions(list) if list.is_empty() => status(
                cv,
                te,
                y,
                Icon::User,
                "Nobody is signed in on this server.",
                c.text_secondary,
            ),
            ShadowState::Sessions(list) => {
                for (i, sess) in list.iter().take(MAX_ROWS).enumerate() {
                    let rr = Rect::new(lx, y, lw, row_h - p(6.0));
                    let watch = Button::secondary("Watch");
                    let control = Button::secondary("Control");
                    let (ww, cw2) = (self.btn_w(te, f, &watch), self.btn_w(te, f, &control));
                    let bh = p(30.0);
                    let by = rr.y + (rr.h - bh) / 2;
                    let cx = rr.right() - p(8.0) - cw2;
                    let wx = cx - p(6.0) - ww;
                    {
                        let mut k = Kit::new(cv, te, f, s);
                        k.cv.fill_round(rr, 10.0 * s, c.surface_hover);
                        let id = format!("{}", sess.id);
                        k.text(
                            Font::Semi,
                            size::SMALL,
                            rr.x + p(14.0),
                            rr.y + rr.h / 2 + p(5.0),
                            &id,
                            c.text_muted,
                            p(36.0),
                        );
                        let ux = rr.x + p(52.0);
                        k.text(
                            Font::Semi,
                            size::BODY,
                            ux,
                            rr.y + p(19.0),
                            &sess.user,
                            c.text,
                            wx - ux - p(8.0),
                        );
                        let state = if sess.station.is_empty() {
                            sess.state.to_string()
                        } else {
                            format!("{} · {}", sess.state, sess.station)
                        };
                        k.text(
                            Font::Regular,
                            size::SMALL,
                            ux,
                            rr.y + p(36.0),
                            &state,
                            c.text_muted,
                            wx - ux - p(8.0),
                        );
                    }
                    self.btn(
                        cv,
                        te,
                        f,
                        Rect::new(wx, by, ww, bh),
                        &watch,
                        Hit::ShadowWatch(i),
                    );
                    self.btn(
                        cv,
                        te,
                        f,
                        Rect::new(cx, by, cw2, bh),
                        &control,
                        Hit::ShadowControl(i),
                    );
                    y += row_h;
                }
                y -= row_h;
            }
        }
        let _ = y;

        // Footer: what it needs, Refresh and Close.
        let by = r.bottom() - pad - p(36.0);
        let close = Button::secondary("Close");
        let refresh = Button::secondary("Refresh").icon(Icon::Refresh);
        let (cw2, rw) = (self.btn_w(te, f, &close), self.btn_w(te, f, &refresh));
        let cx = r.right() - pad - cw2;
        let rx = cx - p(8.0) - rw;
        {
            let mut k = Kit::new(cv, te, f, s);
            let more = match &d.state {
                ShadowState::Sessions(l) if l.len() > MAX_ROWS => {
                    format!(
                        "{} more: remora {} --list-sessions. ",
                        l.len() - MAX_ROWS,
                        d.host
                    )
                }
                _ => String::new(),
            };
            k.text(
                Font::Regular,
                size::SMALL,
                lx,
                by + p(14.0),
                &format!("{more}Runs as your Windows account,"),
                c.text_muted,
                rx - lx - p(12.0),
            );
            k.text(
                Font::Regular,
                size::SMALL,
                lx,
                by + p(30.0),
                "which needs rights to shadow on the server.",
                c.text_muted,
                rx - lx - p(12.0),
            );
        }
        self.btn(
            cv,
            te,
            f,
            Rect::new(rx, by, rw, p(36.0)),
            &refresh,
            Hit::ShadowRefresh,
        );
        self.btn(
            cv,
            te,
            f,
            Rect::new(cx, by, cw2, p(36.0)),
            &close,
            Hit::ShadowClose,
        );
    }
}

/// The sample for `--snapshot-ui`: the dialog over the editor.
pub fn sample_shadow(state: u8) -> Ui {
    let mut m = super::sample_form(0);
    let sessions = vec![
        RemoteSession {
            id: 2,
            station: "RDP-Tcp#3".into(),
            state: "Active",
            user: "CONTOSO\\maria".into(),
        },
        RemoteSession {
            id: 3,
            station: "Console".into(),
            state: "Active",
            user: "CONTOSO\\admin".into(),
        },
        RemoteSession {
            id: 5,
            station: String::new(),
            state: "Disconnected",
            user: "CONTOSO\\build".into(),
        },
    ];
    m.shadow = Some(ShadowDialog {
        name: "Build server".into(),
        host: "build01.contoso.local".into(),
        state: match state {
            0 => ShadowState::Sessions(sessions.clone()),
            1 => ShadowState::Loading,
            2 => ShadowState::Asking(2),
            _ => ShadowState::Failed("the user declined the request".into()),
        },
        consent: true,
        sessions,
    });
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u32, user: &str) -> RemoteSession {
        RemoteSession {
            id,
            station: String::new(),
            state: "Active",
            user: user.into(),
        }
    }

    #[test]
    fn the_dialog_lists_and_shadows_a_session() {
        let mut m = crate::ui::sample_form(4);
        let Some(Action::ListSessions(host)) = m.activate(Hit::ShadowOpen) else {
            panic!("the Sessions button reads the server's sessions");
        };
        assert_eq!(host, "192.168.56.20");
        // A late answer for another server is ignored.
        m.shadow_sessions("other", Ok(vec![session(9, "x")]));
        assert!(matches!(
            m.shadow.as_ref().unwrap().state,
            ShadowState::Loading
        ));
        // Services and listeners (no user) are left out.
        m.shadow_sessions(
            &host,
            Ok(vec![
                session(0, ""),
                session(2, r"LAB\maria"),
                session(65536, ""),
            ]),
        );
        let ShadowState::Sessions(list) = &m.shadow.as_ref().unwrap().state else {
            panic!("listed");
        };
        assert_eq!(list.len(), 1);
        // Control without asking: the switch, then the row's Control.
        m.activate(Hit::ShadowConsent);
        let Some(Action::Shadow { name, host: h, req }) = m.activate(Hit::ShadowControl(0)) else {
            panic!("Control asks the server");
        };
        assert_eq!(
            (name.as_str(), h.as_str()),
            ("Test VM (Windows 11)", "192.168.56.20")
        );
        assert_eq!((req.session_id, req.control, req.consent), (2, true, false));
        assert!(m.shadow_waiting(&h));
        // A refusal shows in the dialog; Enter reads the list again.
        assert!(m.shadow_failed("the user declined the request"));
        assert!(!m.shadow_waiting(&h));
        assert!(matches!(
            m.key(crate::ui::Key::Enter),
            Some(Action::ListSessions(_))
        ));
        // Esc closes it; a late answer then finds no dialog.
        assert!(m.key(crate::ui::Key::Esc).is_none());
        assert!(m.shadow.is_none());
        assert!(!m.shadow_waiting(&h));
        assert!(!m.shadow_failed("late"));
    }

    #[test]
    fn watch_asks_the_user_by_default() {
        let mut m = crate::ui::sample_form(4);
        m.activate(Hit::ShadowOpen);
        m.shadow_sessions("192.168.56.20", Ok(vec![session(3, r"LAB\admin")]));
        let Some(Action::Shadow { req, .. }) = m.activate(Hit::ShadowWatch(0)) else {
            panic!("Watch asks the server");
        };
        assert_eq!((req.session_id, req.control, req.consent), (3, false, true));
        // A row index past the list does nothing.
        m.shadow_sessions("192.168.56.20", Ok(vec![]));
        assert!(m.activate(Hit::ShadowWatch(5)).is_none());
    }

    #[test]
    fn an_empty_host_does_not_open_the_dialog() {
        let mut m = crate::ui::sample_form(4);
        m.field_mut(Field::Host).set("  ");
        assert!(m.activate(Hit::ShadowOpen).is_none());
        assert!(m.shadow.is_none());
    }
}
