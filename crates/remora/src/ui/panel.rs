//! The session panel's two shapes (RDP-39).
//!
//! - **Pinned**: the panel docks beside the picture (`paint_drawer`), the
//!   picture gets narrower, its left edge drags (RDP-38). The toolbar's
//!   panel button hides it; then the strip below stands in for it, and a
//!   page icon docks it again on that page.
//! - **Unpinned** (the default): a slim strip of the four page icons stays
//!   at the picture's right edge. A page icon, the toolbar's panel button,
//!   Ctrl+Alt+P or the palette opens the panel floating over the picture's
//!   right part. The picture keeps its size (no Display Control resize):
//!   the app copies it only left of the panel (`session_clip`), and the
//!   panel's shadow is painted over the picture with the toolbar
//!   (`paint_session_overlay`). While it floats, the session gets no mouse
//!   input; a click on the picture closes it and is not sent, Esc closes it
//!   (and gives the keyboard back to the session it was taken from).
//!
//! Full screen has no strip: the toolbar's panel button opens the floating
//! panel there. The pin in the panel's header switches between the two and
//! is kept in the settings ([`Action::SaveLayout`]).

use ffwd_render::{Canvas, Rect, TextEngine};

use super::sidebar::{TipSide, TipSpec};
use super::*;

/// The strip's width (logical px).
pub const STRIP_W: f32 = 44.0;
/// Its icon buttons: side and step.
const ITEM: f32 = 36.0;
const STEP: f32 = 40.0;
/// The floating panel's header height (logical px).
const HEAD_H: f32 = 52.0;
/// The floating panel's shadow over the picture (logical px).
const SHADOW: f32 = 16.0;

/// The panel's pages: name, icon, and what is on it (the strip's tooltip).
pub(super) const PAGES: [(&str, Icon, &str); 4] = [
    (
        "Sharing",
        Icon::Folder,
        "Clipboard, sound, printers and folders",
    ),
    (
        "Display",
        Icon::Monitor,
        "Fit to window, scale and full screen",
    ),
    (
        "Quality",
        Icon::Sliders,
        "Graphics, visual effects and speed",
    ),
    ("Session", Icon::Info, "Keyboard, network and status"),
];

/// How the panel is painted: docked beside the picture (page switcher and
/// pin), or floating over it (a header with the page's name, pin and
/// close; the page switcher too when there is no strip, in full screen).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shape {
    Docked,
    Float { pages: bool },
}

/// The floating panel's state.
#[derive(Default)]
pub(super) struct PanelState {
    /// The panel floats over this session's picture.
    pub(super) open: Option<u64>,
    /// The session the panel took the keyboard from (Ctrl+Alt+P, the
    /// palette): Esc gives it back.
    pub(super) return_to: Option<u64>,
    /// A press on the picture closed the panel: that press and its release
    /// are not the session's.
    swallow: bool,
    /// Where the last paint put the floating panel (physical px).
    pub(super) float_rect: Option<Rect>,
}

impl Ui {
    /// The panel is on screen for the active session: docked, or floating.
    pub(super) fn panel_visible(&self) -> bool {
        if self.panel_pinned {
            self.drawer
        } else {
            self.panel.open.is_some() && self.panel.open == self.active
        }
    }

    /// The strip shows beside a running session while the panel is not
    /// docked (never in full screen).
    pub(super) fn strip_shown(&self) -> bool {
        !self.fullscreen && !(self.panel_pinned && self.drawer)
    }

    /// The strip's width, with its 1 px edge (physical px; 0 without it).
    pub(super) fn strip_px(&self) -> i32 {
        if self.strip_shown() {
            (STRIP_W * self.scale).round() as i32 + 1
        } else {
            0
        }
    }

    /// The panel floats over the picture now (painted that way): the
    /// session gets no mouse input, a click on the picture closes it.
    pub fn panel_floating(&self) -> bool {
        self.panel.float_rect.is_some()
    }

    /// Mouse input is not the session's: the panel floats over it, or the
    /// press that closed it is still down.
    pub fn session_input_blocked(&self) -> bool {
        self.panel_floating() || self.panel.swallow
    }

    /// The toolbar's panel button (and the palette's "Show/Hide session
    /// panel"): pinned, it shows or hides the docked panel; unpinned, it
    /// opens or closes the floating one.
    pub(super) fn toggle_panel(&mut self) {
        if self.panel_pinned {
            self.drawer = !self.drawer;
        } else if self.panel.open.is_some() {
            self.close_panel();
        } else {
            self.panel.open = self.active;
            self.panel.return_to = None;
        }
    }

    /// Ctrl+Alt+P, also while the session has the keyboard (`from`): the
    /// panel button's toggle. A floating panel takes the keyboard from the
    /// session; Esc gives it back. False: no running session to show it on.
    pub fn panel_shortcut(&mut self, from: Option<u64>) -> bool {
        let running = self
            .active_tab()
            .is_some_and(|t| matches!(t.state, TabState::Connected { .. }));
        if !running || self.palette.is_some() || self.confirm_exit.is_some() {
            return false;
        }
        self.toggle_panel();
        if self.panel.open.is_some() {
            self.panel.return_to = from;
            self.session_focus = false;
        }
        true
    }

    /// A page icon in the strip: the panel opens on that page (docked when
    /// pinned); the page it is open on closes it again.
    pub(super) fn panel_page(&mut self, page: u8) {
        if self.drawer_page != page {
            self.drawer_page = page;
            self.drawer_scroll = 0;
        } else if self.panel.open.is_some() && !self.panel_pinned {
            return self.close_panel();
        }
        if self.panel_pinned {
            self.drawer = true;
        } else {
            self.panel.open = self.active;
        }
    }

    /// The pin: docks the floating panel beside the picture, or floats the
    /// docked one (it stays open). Kept in the settings.
    pub(super) fn pin_panel(&mut self) -> Option<Action> {
        if self.panel_pinned {
            self.panel_pinned = false;
            self.panel.open = self.active;
        } else {
            self.panel_pinned = true;
            self.drawer = true;
            self.panel.open = None;
        }
        self.panel.return_to = None;
        Some(Action::SaveLayout)
    }

    /// Closes the floating panel; the session it took the keyboard from
    /// gets it back.
    pub(super) fn close_panel(&mut self) {
        self.panel.open = None;
        if let Some(id) = self.panel.return_to.take()
            && self.active == Some(id)
            && self
                .active_tab()
                .is_some_and(|t| matches!(t.state, TabState::Connected { .. }))
        {
            self.session_focus = true;
        }
    }

    /// Esc with the floating panel open (no field has the keyboard): it
    /// closes. False: not the panel's key.
    pub(super) fn panel_esc(&mut self) -> bool {
        if self.focus.is_some() || self.panel.open.is_none() {
            return false;
        }
        self.close_panel();
        true
    }

    /// A press at (x, y) while the panel floats: outside it, the panel
    /// closes. On the picture the press only closes it (true: nothing else
    /// happens, the session gets the keyboard but not the click); on the
    /// panel's own controls (strip, toolbar button) it goes on as usual.
    pub(super) fn panel_press(&mut self, x: i32, y: i32) -> bool {
        let Some(r) = self.panel.float_rect else {
            return false;
        };
        if r.contains(x, y) {
            return false;
        }
        let hit = self.hit_at(x, y);
        if matches!(
            hit,
            Some(Hit::PanelPage(_) | Hit::PanelPin | Hit::Drawer | Hit::Divider(_))
        ) {
            return false;
        }
        self.panel.open = None;
        self.panel.return_to = None;
        if let Some(Hit::Session(_)) = hit {
            self.panel.swallow = true;
            self.press = None;
            self.focus = None;
            self.toolbar_reset();
            self.session_focus = true;
            return true;
        }
        false
    }

    /// The button lifted: a press that closed the panel is over. True when
    /// it was one (nothing to activate).
    pub(super) fn panel_release(&mut self) -> bool {
        std::mem::take(&mut self.panel.swallow)
    }

    /// The band left of the floating panel its shadow falls on (physical
    /// px), repainted over the picture with the toolbar.
    pub(super) fn panel_shadow_rect(&self) -> Option<Rect> {
        let r = self.panel.float_rect?;
        let b = (SHADOW * self.scale).ceil() as i32 + 1;
        Some(Rect::new(r.x - b, r.y, b, r.h))
    }

    /// Paints the floating panel's shadow over the picture (overlay pass).
    pub(super) fn paint_panel_shadow(&self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let (Some(r), Some(band)) = (self.panel.float_rect, self.panel_shadow_rect()) else {
            return;
        };
        let old = cv.set_clip(cv.clip().intersect(band));
        if !cv.clip().is_empty() {
            Kit::new(cv, te, f, self.scale).shadow(r, 0.0, SHADOW);
        }
        cv.set_clip(old);
    }

    /// The strip at the session's right edge: the four page icons (the open
    /// page lit), the pin at the bottom, and the tooltip of the one under
    /// the pointer (left of the strip, while the panel is closed).
    pub(super) fn paint_strip(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        id: u64,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        cv.fill(r, c.bg);
        cv.fill(Rect::new(r.x - 1, r.y, 1, r.h), c.divider);
        let item = |y: i32| Rect::new(r.x + (r.w - p(ITEM)) / 2, y, p(ITEM), p(ITEM));
        let open = self.panel.open == Some(id) && !self.panel_pinned;
        let mut specs = Vec::new();
        for (i, (name, icon, sub)) in PAGES.iter().enumerate() {
            let b = item(r.y + p(8.0) + i as i32 * p(STEP));
            let hit = Hit::PanelPage(i as u8);
            let on = open && self.drawer_page == i as u8;
            self.strip_button(cv, te, f, b, *icon, hit, on);
            if on {
                // The accent mark at the strip's outer edge, as in the rail.
                cv.fill_round(
                    Rect::new(r.right() - p(3.0), b.y + p(9.0), p(3.0), b.h - p(18.0)),
                    1.5 * s,
                    c.accent,
                );
            }
            specs.push(TipSpec {
                hit,
                anchor: b,
                title: (*name).into(),
                sub: vec![(*sub).into()],
                keys: None,
            });
        }
        // The pin at the bottom, while unpinned (the open panel has its own
        // in its header; pinned, a page icon docks the panel again).
        let pin = item(r.bottom() - p(8.0) - p(ITEM));
        if !open && !self.panel_pinned && pin.y > r.y + p(8.0) + 4 * p(STEP) {
            self.strip_button(cv, te, f, pin, Icon::Pin, Hit::PanelPin, false);
            specs.push(TipSpec {
                hit: Hit::PanelPin,
                anchor: pin,
                title: "Pin the panel".into(),
                sub: vec!["Beside the picture, which gets narrower".into()],
                keys: None,
            });
        }
        if !open
            && self.palette.is_none()
            && self.confirm_exit.is_none()
            && let Some(spec) = specs.into_iter().find(|t| Some(t.hit) == self.hover)
        {
            self.set_tip(cv, te, f, TipSide::Left(r), spec);
        }
    }

    /// One icon button of the strip: chosen (the open page), pressed or
    /// hovered.
    #[allow(clippy::too_many_arguments)]
    fn strip_button(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Icon,
        hit: Hit,
        on: bool,
    ) {
        let c = pal();
        let st = self.st(hit);
        let fill = if on {
            Some(c.selected)
        } else if st.press {
            Some(c.surface_pressed)
        } else if st.hover {
            Some(c.surface_hover)
        } else {
            None
        };
        if let Some(fill) = fill {
            cv.fill_round(r, radius::CONTROL * self.scale, fill);
        }
        let color = if on {
            c.accent
        } else if st.hover {
            c.text
        } else {
            c.text_muted
        };
        Kit::new(cv, te, f, self.scale).icon_in(icon, r, 18.0, color);
        self.hits.push((r, hit));
    }

    /// The floating panel's header: the page's icon and name, the pin and
    /// the close button. Returns its bottom.
    pub(super) fn paint_panel_head(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        d: Rect,
    ) -> i32 {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let head = Rect::new(d.x, d.y, d.w, p(HEAD_H));
        let (name, icon, _) = PAGES[(self.drawer_page as usize).min(PAGES.len() - 1)];
        let side = p(32.0);
        let by = head.y + (head.h - side) / 2;
        let close = Rect::new(head.right() - p(10.0) - side, by, side, side);
        let pin = Rect::new(close.x - p(4.0) - side, by, side, side);
        {
            let mut k = Kit::new(cv, te, f, s);
            let ir = Rect::new(head.x + p(16.0), head.y, p(18.0), head.h);
            k.icon_in(icon, ir, 18.0, c.accent);
            let tr = Rect::new(
                ir.right() + p(10.0),
                head.y,
                pin.x - ir.right() - p(18.0),
                head.h,
            );
            k.text_in(Font::Semi, size::HEADING, tr, name, c.text);
        }
        self.icon_btn(cv, te, f, pin, Icon::Pin, Variant::Ghost, Hit::PanelPin);
        self.icon_btn(
            cv,
            te,
            f,
            close,
            Icon::Close,
            Variant::Ghost,
            Hit::PanelClose,
        );
        cv.fill(Rect::new(head.x, head.bottom() - 1, head.w, 1), c.divider);
        let tip = match self.hover {
            Some(Hit::PanelPin) => Some(TipSpec {
                hit: Hit::PanelPin,
                anchor: pin,
                title: "Pin beside the picture".into(),
                sub: vec!["The picture gets narrower to make room".into()],
                keys: None,
            }),
            Some(Hit::PanelClose) => Some(TipSpec {
                hit: Hit::PanelClose,
                anchor: close,
                title: "Close".into(),
                sub: Vec::new(),
                keys: Some("Esc"),
            }),
            _ => None,
        };
        if let Some(spec) = tip
            && self.palette.is_none()
        {
            self.set_tip(cv, te, f, TipSide::Below, spec);
        }
        head.bottom()
    }

    /// The docked panel's pin (lit: pinned), right of the page switcher.
    pub(super) fn paint_docked_pin(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
    ) {
        let c = pal();
        let st = self.st(Hit::PanelPin);
        let fill = if st.hover {
            theme::mix(c.accent_subtle, c.accent, 30)
        } else {
            c.accent_subtle
        };
        cv.fill_round(r, radius::CONTROL * self.scale, fill);
        Kit::new(cv, te, f, self.scale).icon_in(Icon::Pin, r, 16.0, c.accent);
        self.hits.push((r, Hit::PanelPin));
        if self.hover == Some(Hit::PanelPin) && self.palette.is_none() {
            let spec = TipSpec {
                hit: Hit::PanelPin,
                anchor: r,
                title: "Unpin".into(),
                sub: vec!["Fold to a strip; the panel floats over the picture".into()],
                keys: None,
            };
            self.set_tip(cv, te, f, TipSide::Below, spec);
        }
    }
}

/// A session with the panel unpinned: the strip at the picture's right
/// edge, with the pointer on a page icon (its tooltip) when `hover`.
pub fn sample_panel_strip(hover: bool) -> Ui {
    let mut m = sample(true);
    m.panel_pinned = false;
    m.session_focus = true;
    if hover {
        m.hover = Some(Hit::PanelPage(1));
    }
    m
}

/// A session with the panel floating over the picture on `page`; in full
/// screen too (no strip there: the page switcher is in the panel).
pub fn sample_panel_float(page: u8, fullscreen: bool) -> Ui {
    let mut m = super::sample_panel(page, fullscreen);
    m.panel_pinned = false;
    m.panel.open = m.active;
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn painted(m: &mut Ui, w: usize, h: usize) -> Option<(TextEngine, Fonts)> {
        let mut te = TextEngine::new();
        let fonts = load_fonts(&mut te)?;
        let mut px = vec![0u32; w * h];
        m.paint_snapshot(&mut Canvas::new(&mut px, w, h), &mut te, &fonts);
        Some((te, fonts))
    }

    fn repaint(m: &mut Ui, te: &mut TextEngine, fonts: &Fonts, w: usize, h: usize) {
        let mut px = vec![0u32; w * h];
        m.paint_snapshot(&mut Canvas::new(&mut px, w, h), te, fonts);
    }

    fn rect_of(m: &Ui, hit: Hit) -> Rect {
        m.hits
            .iter()
            .rev()
            .find(|(_, h)| *h == hit)
            .map(|(r, _)| *r)
            .unwrap_or_else(|| panic!("{hit:?} not painted"))
    }

    fn click(m: &mut Ui, te: &mut TextEngine, fonts: &Fonts, x: i32, y: i32) -> Option<Action> {
        m.mouse_move(x, y);
        m.mouse_down(x, y, te, fonts);
        m.mouse_up(x, y)
    }

    /// RDP-39: opening the floating panel changes neither the session
    /// area nor the size the session is asked to have (no Display Control
    /// resize); the picture is only copied left of the panel.
    #[test]
    fn the_floating_panel_keeps_the_session_size() {
        let mut m = sample_panel_strip(false);
        let Some((mut te, fonts)) = painted(&mut m, 1320, 860) else {
            return; // no UI font on this machine
        };
        let (id, area) = m.session_area.unwrap();
        let size = m.session_size_for(1320, 860);
        assert_eq!((area.w, area.h), size, "the strip is part of the layout");
        assert!(m.session_clip.is_none());
        // The strip sits right of the picture.
        let icon = rect_of(&m, Hit::PanelPage(2));
        assert!(icon.x >= area.right());
        let (x, y) = (icon.x + 4, icon.y + 4);
        assert!(click(&mut m, &mut te, &fonts, x, y).is_none());
        assert_eq!(m.panel.open, Some(id));
        assert_eq!(m.drawer_page, 2);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        assert!(m.panel_floating());
        assert_eq!(
            m.session_area,
            Some((id, area)),
            "the picture keeps its size"
        );
        assert_eq!(m.session_size_for(1320, 860), size, "no resize");
        let float = m.panel.float_rect.unwrap();
        assert_eq!(float.right(), area.right());
        let clip = m.session_clip.expect("the picture is clipped");
        assert_eq!(clip.right(), float.x, "copied only left of the panel");
        // The shadow over the picture is repainted with the toolbar.
        let over = m.overlay_rect().unwrap();
        assert!(over.contains(float.x - 2, float.y + float.h / 2));
        // The toolbar centres over what is left of the picture.
        let pill = m.pill_rect().unwrap();
        assert!(pill.right() < float.x);
        // The pointer over the panel is the panel's.
        assert!(m.session_input_blocked());
        // Its header, between the title and the buttons.
        let mid = (float.x + float.w / 2, float.y + 26);
        m.mouse_move(mid.0, mid.1);
        assert_eq!(m.hover, Some(Hit::PanelBody));
        // Its pages switch from the strip, the open page's icon closes it.
        let icon = rect_of(&m, Hit::PanelPage(0));
        click(&mut m, &mut te, &fonts, icon.x + 4, icon.y + 4);
        assert_eq!((m.panel.open, m.drawer_page), (Some(id), 0));
        click(&mut m, &mut te, &fonts, icon.x + 4, icon.y + 4);
        assert_eq!(m.panel.open, None);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        assert_eq!(m.session_area, Some((id, area)));
        assert!(m.session_clip.is_none() && !m.session_input_blocked());
    }

    /// A click on the picture closes the floating panel and is not the
    /// session's: neither the press nor its release.
    #[test]
    fn a_click_outside_closes_the_panel_and_is_not_sent() {
        let mut m = sample_panel_float(0, false);
        m.session_focus = false;
        let Some((mut te, fonts)) = painted(&mut m, 1320, 860) else {
            return;
        };
        let (id, area) = m.session_area.unwrap();
        assert!(m.panel_floating());
        let (x, y) = (area.x + 200, area.y + 300);
        m.mouse_move(x, y);
        assert!(m.session_input_blocked(), "no input while it floats");
        m.mouse_down(x, y, &mut te, &fonts);
        assert_eq!(m.panel.open, None, "the press closed it");
        // The window repaints before the button lifts: the release is not
        // the session's either.
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        assert!(!m.panel_floating());
        assert!(m.session_input_blocked(), "the press is not the session's");
        assert!(m.mouse_up(x, y).is_none());
        assert!(!m.session_input_blocked(), "the next click is");
        assert!(m.session_focus, "the session has the keyboard again");
        assert_eq!(m.session_area, Some((id, area)));
        // A click on the panel itself leaves it open.
        m.panel.open = Some(id);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        let float = m.panel.float_rect.unwrap();
        click(&mut m, &mut te, &fonts, float.x + 20, float.bottom() - 10);
        assert_eq!(m.panel.open, Some(id));
        // So does the toolbar's panel button, which closes it.
        assert!(m.activate(Hit::Drawer).is_none());
        assert_eq!(m.panel.open, None);
        // A click elsewhere in the window (a tab) closes it and goes on.
        m.panel.open = Some(id);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        let tab = rect_of(&m, Hit::Tab(2));
        click(&mut m, &mut te, &fonts, tab.x + 10, tab.y + 10);
        assert_eq!((m.panel.open, m.active), (None, Some(2)));
    }

    /// Esc closes the floating panel and gives the keyboard back to the
    /// session Ctrl+Alt+P took it from; it is not sent to the session.
    #[test]
    fn the_shortcut_opens_it_and_esc_closes_it() {
        let mut m = sample_panel_strip(false);
        let Some((mut te, fonts)) = painted(&mut m, 1320, 860) else {
            return;
        };
        assert!(m.session_focus);
        assert!(m.panel_shortcut(Some(1)));
        assert_eq!(m.panel.open, Some(1));
        assert!(!m.session_focus, "Remora has the keyboard: Esc is ours");
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        // A field in the panel has the keyboard: Esc leaves it first.
        m.focus = Some(Field::DrivePath);
        assert!(m.key(Key::Esc).is_none());
        assert_eq!((m.focus, m.panel.open), (None, Some(1)));
        assert!(m.key(Key::Esc).is_none());
        assert_eq!(m.panel.open, None);
        assert!(m.session_focus, "back to the session");
        // Ctrl+Alt+P again closes it too; nothing without a running session.
        m.panel_shortcut(Some(1));
        assert!(m.panel_shortcut(None));
        assert_eq!(m.panel.open, None);
        m.active = None;
        assert!(!m.panel_shortcut(None));
        // The palette's command opens it and keeps the keyboard.
        m.active = Some(1);
        m.session_focus = true;
        m.open_palette(Some(1));
        for c in "show session panel".chars() {
            m.key(Key::Char(c));
        }
        assert!(m.key(Key::Enter).is_none());
        assert_eq!(m.panel.open, Some(1));
        assert!(!m.session_focus);
        assert!(m.key(Key::Esc).is_none());
        assert!(m.session_focus);
    }

    /// The pin docks the floating panel (the session area shrinks and is
    /// saved), unpinning floats it again over the full-size picture.
    #[test]
    fn pin_and_unpin_round_trip() {
        let mut m = sample_panel_float(1, false);
        let Some((mut te, fonts)) = painted(&mut m, 1320, 860) else {
            return;
        };
        let (_, floating) = m.session_area.unwrap();
        let pin = rect_of(&m, Hit::PanelPin);
        assert!(m.panel.float_rect.unwrap().contains(pin.x, pin.y));
        assert!(matches!(
            click(&mut m, &mut te, &fonts, pin.x + 4, pin.y + 4),
            Some(Action::SaveLayout)
        ));
        assert!(m.panel_pinned && m.drawer && m.panel.open.is_none());
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        let (_, docked) = m.session_area.unwrap();
        assert!(!m.panel_floating() && m.session_clip.is_none());
        assert!(docked.w < floating.w, "docked: the picture makes room");
        assert_eq!(m.session_size_for(1320, 860), (docked.w, docked.h));
        assert!(m.hits.iter().all(|(_, h)| !matches!(h, Hit::PanelPage(_))));
        // The docked panel's pin floats it again, still open.
        let pin = rect_of(&m, Hit::PanelPin);
        assert!(matches!(
            click(&mut m, &mut te, &fonts, pin.x + 4, pin.y + 4),
            Some(Action::SaveLayout)
        ));
        assert!(!m.panel_pinned && m.panel.open == m.active);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        assert_eq!(m.session_area.unwrap().1, floating);
        assert!(m.panel_floating());
        // Pinned and hidden by the toolbar button: the strip docks it again.
        m.pin_panel();
        m.activate(Hit::Drawer);
        assert!(m.panel_pinned && !m.drawer);
        repaint(&mut m, &mut te, &fonts, 1320, 860);
        let icon = rect_of(&m, Hit::PanelPage(3));
        click(&mut m, &mut te, &fonts, icon.x + 4, icon.y + 4);
        assert!(m.drawer && m.panel_pinned);
        assert_eq!(m.drawer_page, 3);
    }

    /// Full screen has no strip; the toolbar's panel button floats the
    /// panel over the whole picture, with the page switcher in it.
    #[test]
    fn full_screen_has_no_strip() {
        let mut m = sample_panel_strip(false);
        m.fullscreen = true;
        let Some((mut te, fonts)) = painted(&mut m, 1000, 700) else {
            return;
        };
        let (_, area) = m.session_area.unwrap();
        assert_eq!(area, Rect::new(0, 0, 1000, 700));
        assert!(m.hits.iter().all(|(_, h)| !matches!(h, Hit::PanelPage(_))));
        m.activate(Hit::Drawer);
        repaint(&mut m, &mut te, &fonts, 1000, 700);
        assert_eq!(m.session_area.unwrap().1, area);
        assert_eq!(m.panel.float_rect.unwrap().right(), 1000);
        assert!(m.hits.iter().any(|(_, h)| matches!(h, Hit::DrawerPage(_))));
    }

    /// The strip's tooltip names the page, left of the strip.
    #[test]
    fn strip_icons_have_tooltips() {
        let mut m = sample_panel_strip(true);
        let Some(_) = painted(&mut m, 1320, 860) else {
            return;
        };
        let tip = m.tip.as_ref().expect("a tooltip");
        assert_eq!(tip.title, "Display");
        let icon = rect_of(&m, Hit::PanelPage(1));
        assert!(tip.rect.right() < icon.x, "left of the strip");
        assert!(m.overlay_rect().unwrap().contains(tip.rect.x, tip.rect.y));
    }
}
