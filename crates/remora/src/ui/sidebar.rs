//! The sidebar's two shapes and the window's draggable dividers.
//!
//! The connections sidebar folds to an icon rail (the hamburger, Ctrl+B or
//! the palette's "Collapse sidebar"): the same controls as icons, one
//! avatar per connection with its live dot, and a tooltip naming whatever
//! the pointer is on. The sidebar's right edge and the session panel's left
//! edge drag to resize them; a double-click puts one back to its default
//! width, and dragging the sidebar narrower than [`SNAP_W`] folds it to the
//! rail. The fold and the widths are kept in the settings
//! ([`Action::SaveLayout`] when a toggle or a drag ends).
//!
//! While a divider drags, the session area changes on every move; the app
//! holds the Display Control resize back until the drag ends
//! ([`Ui::resizing`]), so the server gets one resize, not one per move.

use std::time::{Duration, Instant};

use ffwd_render::{Canvas, Rect, TextEngine};

use super::*;

/// The rail's width (logical px).
pub const RAIL_W: f32 = 56.0;
/// How narrow and wide the sidebar drags (logical px).
pub const SIDEBAR_MIN: f32 = 200.0;
pub const SIDEBAR_MAX: f32 = 480.0;
/// Dragging the sidebar narrower than this folds it to the rail.
const SNAP_W: f32 = 140.0;
/// How narrow and wide the session panel drags (logical px).
pub const PANEL_MIN: f32 = 280.0;
pub const PANEL_MAX: f32 = 560.0;
/// A wide sidebar leaves the content at least this much (logical px);
/// in a small window it may still take a third of it.
const CONTENT_MIN: f32 = 640.0;
/// Half the width of a divider's grip (logical px).
const GRIP: f32 = 3.0;
/// Two presses on a divider this close together are a double-click.
const DOUBLE_CLICK: Duration = Duration::from_millis(500);
/// Rail buttons and avatars: their side, and the step between avatars.
const ITEM: f32 = 40.0;
const STEP: f32 = 44.0;

/// A draggable edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Divider {
    /// The sidebar's right edge.
    Sidebar,
    /// The session panel's left edge.
    Panel,
}

/// A divider being dragged: which, and where on it the pointer took it
/// (pointer x minus the divider's x), so it does not jump to the pointer.
#[derive(Clone, Copy, Debug)]
struct Drag {
    which: Divider,
    grab: i32,
}

/// Divider state: the drag, the last press (double-click), and where the
/// last paint put the dividers (physical px).
#[derive(Default)]
pub(super) struct Dividers {
    drag: Option<Drag>,
    last_press: Option<(Divider, Instant)>,
    /// The layout changed since the press: save it when the button lifts.
    changed: bool,
    sidebar_x: i32,
    pub(super) panel_x: Option<i32>,
    /// The session panel's right edge (its width is measured from there).
    pub(super) panel_right: i32,
}

/// A tooltip (rail, panel strip): where it goes (physical px) and what it
/// says.
pub(super) struct Tip {
    pub(super) rect: Rect,
    pub(super) title: String,
    sub: Vec<String>,
    keys: Option<&'static str>,
}

/// One control that may show a tooltip (the rail, the session panel's
/// strip and header).
pub(super) struct TipSpec {
    pub(super) hit: Hit,
    pub(super) anchor: Rect,
    pub(super) title: String,
    pub(super) sub: Vec<String>,
    pub(super) keys: Option<&'static str>,
}

/// Where a tooltip goes: right of an area (the rail), left of one (the
/// session panel's strip), or under its control.
#[derive(Clone, Copy)]
pub(super) enum TipSide {
    Right(Rect),
    Left(Rect),
    Below,
}

impl Ui {
    /// The layout the settings kept (widths in logical px, clamped).
    pub fn set_layout(&mut self, collapsed: bool, sidebar_w: u32, panel_w: u32) {
        self.sidebar_collapsed = collapsed;
        self.sidebar_w = (sidebar_w as f32).clamp(SIDEBAR_MIN, SIDEBAR_MAX);
        self.panel_w = (panel_w as f32).clamp(PANEL_MIN, PANEL_MAX);
    }

    /// The layout to keep: folded, sidebar width, panel width (logical px).
    pub fn layout_settings(&self) -> (bool, u32, u32) {
        (
            self.sidebar_collapsed,
            self.sidebar_w.round() as u32,
            self.panel_w.round() as u32,
        )
    }

    /// The sidebar's width in a window `w` px wide (physical px).
    pub(super) fn sidebar_px(&self, w: i32) -> i32 {
        let p = |v: f32| (v * self.scale).round() as i32;
        if self.sidebar_collapsed {
            return p(RAIL_W);
        }
        let room = (w / 3).max(w - p(CONTENT_MIN));
        p(self.sidebar_w.clamp(SIDEBAR_MIN, SIDEBAR_MAX)).min(room)
    }

    /// The session panel's width beside a session area `avail` px wide.
    pub(super) fn panel_px(&self, avail: i32) -> i32 {
        let w = (self.panel_w.clamp(PANEL_MIN, PANEL_MAX) * self.scale).round() as i32;
        w.min(avail / 2)
    }

    /// A divider is being dragged: the session area is not final yet.
    pub fn resizing(&self) -> bool {
        self.dividers.drag.is_some()
    }

    /// The pointer is on a divider (or dragging one): the resize cursor.
    pub fn cursor_is_resize(&self) -> bool {
        self.resizing() || matches!(self.hover, Some(Hit::Divider(_)))
    }

    /// The point is on a divider's grip: not the session's.
    pub fn over_divider(&self, x: i32, y: i32) -> bool {
        self.hits
            .iter()
            .any(|(r, h)| matches!(h, Hit::Divider(_)) && r.contains(x, y))
    }

    /// Folds the sidebar to the rail or unfolds it.
    pub(super) fn toggle_sidebar(&mut self) -> Option<Action> {
        if self.fullscreen {
            return None;
        }
        self.sidebar_collapsed = !self.sidebar_collapsed;
        if self.sidebar_collapsed && self.focus == Some(Field::Filter) {
            self.focus = None;
        }
        Some(Action::SaveLayout)
    }

    /// The hamburger: the same place in the sidebar and in the rail.
    pub(super) fn menu_button_rect(&self) -> Rect {
        let p = |v: f32| (v * self.scale).round() as i32;
        let side = p(32.0);
        Rect::new((p(RAIL_W) - side) / 2, p(4.0), side, side)
    }

    /// The button went down on a divider at `x`: a drag starts, or a
    /// double-click puts the divider back to its default width.
    pub(super) fn divider_press(&mut self, d: Divider, x: i32, now: Instant) {
        let double = matches!(self.dividers.last_press,
            Some((was, at)) if was == d && now.duration_since(at) < DOUBLE_CLICK);
        if double {
            self.dividers.last_press = None;
            self.dividers.drag = None;
            match d {
                Divider::Sidebar => {
                    self.sidebar_collapsed = false;
                    self.sidebar_w = SIDEBAR_W;
                }
                Divider::Panel => self.panel_w = DRAWER_W,
            }
            self.dividers.changed = true;
            return;
        }
        self.dividers.last_press = Some((d, now));
        let line = match d {
            Divider::Sidebar => self.dividers.sidebar_x,
            Divider::Panel => self.dividers.panel_x.unwrap_or(x),
        };
        self.dividers.drag = Some(Drag {
            which: d,
            grab: x - line,
        });
    }

    /// The pointer moved to `x` while a divider drags; true when the
    /// layout changed (repaint).
    pub(super) fn drag_to(&mut self, x: i32) -> bool {
        let Some(drag) = self.dividers.drag else {
            return false;
        };
        let line = x - drag.grab;
        let before = (self.sidebar_collapsed, self.sidebar_w, self.panel_w);
        match drag.which {
            Divider::Sidebar => {
                let want = line as f32 / self.scale;
                if want < SNAP_W {
                    self.sidebar_collapsed = true;
                } else {
                    self.sidebar_collapsed = false;
                    self.sidebar_w = want.clamp(SIDEBAR_MIN, SIDEBAR_MAX).round();
                }
            }
            Divider::Panel => {
                // The panel starts one pixel right of its divider line.
                let want = (self.dividers.panel_right - line - 1) as f32 / self.scale;
                self.panel_w = want.clamp(PANEL_MIN, PANEL_MAX).round();
            }
        }
        let changed = before != (self.sidebar_collapsed, self.sidebar_w, self.panel_w);
        self.dividers.changed |= changed;
        changed
    }

    /// The button lifted after a press on a divider: the drag ends; a
    /// changed layout is saved (and the session gets its final size).
    pub(super) fn divider_release(&mut self) -> Option<Action> {
        self.dividers.drag = None;
        std::mem::take(&mut self.dividers.changed).then_some(Action::SaveLayout)
    }

    /// Records a divider at `x` from `top` to `bottom`: its grip, and a
    /// line while it is hovered (quiet) or dragged (accent).
    pub(super) fn paint_divider(
        &mut self,
        cv: &mut Canvas,
        d: Divider,
        x: i32,
        top: i32,
        bottom: i32,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        // The sidebar's edge is the content panel's rounded corner at the
        // top: its line starts below the curve.
        let inset = match d {
            Divider::Sidebar => {
                self.dividers.sidebar_x = x;
                p(radius::CARD)
            }
            Divider::Panel => {
                self.dividers.panel_x = Some(x);
                0
            }
        };
        let dragging = self.dividers.drag.is_some_and(|g| g.which == d);
        if dragging || self.hover == Some(Hit::Divider(d)) {
            let lw = p(2.0).max(2);
            let line = Rect::new(x - lw / 2, top + inset, lw, bottom - top - inset);
            cv.fill(line, if dragging { c.accent } else { c.border_strong });
        }
        let g = p(GRIP).max(2);
        self.hits.push((
            Rect::new(x - g, top, 2 * g + 1, bottom - top),
            Hit::Divider(d),
        ));
    }

    /// Connections in the rail's order: the group tree, depth first, its
    /// folded groups included (the rail lists every connection).
    pub(super) fn rail_order(&self) -> Vec<usize> {
        fn walk(m: &Ui, path: &str, out: &mut Vec<usize>) {
            for g in &m.store.groups {
                if g.parent() == path {
                    walk(m, &g.path, out);
                }
            }
            for (i, c) in m.store.connections.iter().enumerate() {
                if c.group == path {
                    out.push(i);
                }
            }
        }
        let mut out = Vec::new();
        walk(self, "", &mut out);
        out
    }

    /// The folded sidebar: the hamburger, Home, search and New, one
    /// avatar per connection, and Settings and the theme at the bottom.
    pub(super) fn paint_rail(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let locked = self.store.is_locked();
        let item = |y: i32| Rect::new(area.x + (area.w - p(ITEM)) / 2, y, p(ITEM), p(ITEM));
        let mut specs: Vec<TipSpec> = Vec::new();

        // The hamburger, in the title row as in the full sidebar.
        let menu = self.menu_button_rect();
        self.icon_btn(
            cv,
            te,
            f,
            menu,
            Icon::Menu,
            Variant::Ghost,
            Hit::SidebarToggle,
        );
        self.title_controls.push((menu.x, menu.right()));
        specs.push(TipSpec {
            hit: Hit::SidebarToggle,
            anchor: menu,
            title: "Expand sidebar".into(),
            sub: Vec::new(),
            keys: Some("Ctrl+B"),
        });

        // The mark leads Home.
        let home = item(p(46.0));
        let home_hit = Hit::HomeView(home::HomeHit::Home);
        self.rail_back(cv, home, home_hit, false);
        let d = p(24.0);
        Kit::new(cv, te, f, s).logo(home.x + (home.w - d) / 2, home.y + (home.h - d) / 2, 24.0);
        self.hits.push((home, home_hit));
        specs.push(TipSpec {
            hit: home_hit,
            anchor: home,
            title: "Home".into(),
            sub: vec!["Recent sessions and quick connect".into()],
            keys: None,
        });

        let mut sep = p(96.0);
        if !locked {
            let search = item(p(92.0));
            self.rail_icon(cv, te, f, search, Icon::Search, Hit::Palette, false, None);
            specs.push(TipSpec {
                hit: Hit::Palette,
                anchor: search,
                title: "Search or run a command".into(),
                sub: Vec::new(),
                keys: Some("Ctrl+K"),
            });
            let new = item(p(136.0));
            self.rail_icon(cv, te, f, new, Icon::Plus, Hit::New, false, Some(c.accent));
            specs.push(TipSpec {
                hit: Hit::New,
                anchor: new,
                title: "New connection".into(),
                sub: Vec::new(),
                keys: Some("Ctrl+N"),
            });
            sep = p(184.0);
        }
        cv.fill(
            Rect::new(area.x + p(14.0), sep, area.w - p(28.0), 1),
            c.divider,
        );

        // Footer: Lock (an open vault), Settings, the theme.
        let mut foot: Vec<(Icon, Hit, bool, String, Vec<String>)> = Vec::new();
        if self.store.is_vault() && !locked {
            foot.push((
                Icon::Lock,
                Hit::Lock,
                false,
                "Lock".into(),
                vec!["The master password opens it again".into()],
            ));
        }
        foot.push((
            Icon::Gear,
            Hit::OpenSettings,
            self.settings_open && self.active.is_none(),
            "Settings".into(),
            Vec::new(),
        ));
        let (theme_icon, theme_title) = if c.dark {
            (Icon::Sun, "Light theme")
        } else {
            (Icon::Moon, "Dark theme")
        };
        foot.push((
            theme_icon,
            Hit::ThemeToggle,
            false,
            theme_title.into(),
            Vec::new(),
        ));
        let fy = area.bottom() - p(12.0) - foot.len() as i32 * p(STEP);
        cv.fill(
            Rect::new(area.x + p(14.0), fy, area.w - p(28.0), 1),
            c.divider,
        );
        for (n, (icon, hit, on, title, sub)) in foot.into_iter().enumerate() {
            let r = item(fy + p(8.0) + n as i32 * p(STEP));
            self.rail_icon(cv, te, f, r, icon, hit, on, None);
            specs.push(TipSpec {
                hit,
                anchor: r,
                title,
                sub,
                keys: None,
            });
        }

        // One avatar per connection; a short line between groups. What
        // does not fit folds into a "+N" tile that unfolds the sidebar.
        if !locked {
            let top = sep + p(10.0);
            let bottom = fy - p(6.0);
            let order = self.rail_order();
            let mut slots: Vec<(usize, i32, bool)> = Vec::new();
            let mut y = top;
            let mut last_group: Option<&str> = None;
            for &i in &order {
                let g = self.store.connections[i].group.as_str();
                let split = last_group.is_some_and(|l| l != g);
                if split {
                    y += p(9.0);
                }
                slots.push((i, y, split));
                y += p(STEP);
                last_group = Some(g);
            }
            let fits = slots
                .iter()
                .take_while(|(_, y, _)| *y + p(ITEM) <= bottom)
                .count();
            let (shown, more) = if fits < slots.len() {
                let n = fits.saturating_sub(1);
                (n, slots.len() - n)
            } else {
                (slots.len(), 0)
            };
            let list = Rect::new(area.x, top, area.w, bottom - top);
            let old = cv.set_clip(cv.clip().intersect(list));
            let home_on = self.active.is_none() && !self.settings_open;
            for &(i, y, split) in &slots[..shown] {
                if split {
                    cv.fill(
                        Rect::new(area.x + p(20.0), y - p(7.0), area.w - p(40.0), 1),
                        c.border_strong,
                    );
                }
                let r = item(y);
                let spec = self.paint_rail_conn(cv, te, f, area, r, i, home_on);
                specs.push(spec);
            }
            if more > 0 {
                let y = slots.get(shown).map_or(top, |s| s.1);
                let r = item(y);
                let st = self.st(Hit::RailMore);
                let mut k = Kit::new(cv, te, f, s);
                k.cv.round_border(
                    r.inset(p(4.0), p(4.0)),
                    radius::CONTROL * s,
                    if st.hover { c.border_strong } else { c.border },
                    if st.hover {
                        c.surface_hover
                    } else {
                        c.bg_sidebar
                    },
                );
                k.text_center(
                    Font::Semi,
                    size::SMALL,
                    r,
                    &format!("+{more}"),
                    if st.hover { c.text } else { c.text_muted },
                );
                self.hits.push((r, Hit::RailMore));
                specs.push(TipSpec {
                    hit: Hit::RailMore,
                    anchor: r,
                    title: format!("{more} more connection{}", if more == 1 { "" } else { "s" }),
                    sub: vec!["Expand the sidebar to see them all".into()],
                    keys: Some("Ctrl+B"),
                });
            }
            cv.set_clip(old);
        }

        // The tooltip of the control under the pointer.
        if self.palette.is_none()
            && self.confirm_exit.is_none()
            && let Some(spec) = specs.into_iter().find(|t| Some(t.hit) == self.hover)
        {
            self.set_tip(cv, te, f, TipSide::Right(area), spec);
        }
    }

    /// One connection in the rail: its avatar with the live dot, chosen
    /// and hover states. Returns its tooltip.
    #[allow(clippy::too_many_arguments)]
    fn paint_rail_conn(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        area: Rect,
        r: Rect,
        i: usize,
        home: bool,
    ) -> TipSpec {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let c = pal();
        let hit = Hit::Row(i);
        let chosen = home && self.selected == Some(i) && self.group_edit.is_none();
        let bg = self.rail_back(cv, r, hit, chosen);
        if chosen {
            // The accent mark at the rail's edge, as on a chosen row.
            cv.fill_round(
                Rect::new(area.x, r.y + p(10.0), p(3.0), r.h - p(20.0)),
                1.5 * s,
                c.accent,
            );
        }
        let conn = self.store.resolve(&self.store.connections[i]);
        let color = self.store.connection_color(&self.store.connections[i]);
        let dot = self.connection_dot(&conn);
        let d = p(32.0);
        Kit::new(cv, te, f, s).avatar(
            Rect::new(r.x + (r.w - d) / 2, r.y + (r.h - d) / 2, d, d),
            &conn.name,
            color,
            dot,
            bg,
        );
        self.hits.push((r, hit));
        let mut where_ = if conn.port == 3389 {
            conn.host.clone()
        } else {
            format!("{}:{}", conn.host, conn.port)
        };
        if !conn.user.is_empty() {
            where_ = format!("{where_} · {}", conn.user);
        }
        let mut sub = vec![where_];
        if !conn.apps.is_empty() {
            let names: Vec<&str> = conn.apps.iter().map(|a| a.name.as_str()).collect();
            let n = names.len();
            sub.push(format!(
                "{n} app{}: {}",
                if n == 1 { "" } else { "s" },
                names.join(", ")
            ));
        }
        TipSpec {
            hit,
            anchor: r,
            title: conn.name.clone(),
            sub,
            keys: None,
        }
    }

    /// A rail control's background: chosen, pressed or hovered. Returns
    /// the colour under it (for an avatar's dot ring).
    fn rail_back(&self, cv: &mut Canvas, r: Rect, hit: Hit, on: bool) -> u32 {
        let c = pal();
        let st = self.st(hit);
        let fill = if on {
            c.selected
        } else if st.press {
            c.surface_pressed
        } else if st.hover {
            c.surface_hover
        } else {
            return c.bg_sidebar;
        };
        cv.fill_round(r, radius::CONTROL * self.scale, fill);
        fill
    }

    /// An icon control in the rail; `tint` colours its glyph (New).
    #[allow(clippy::too_many_arguments)]
    fn rail_icon(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        r: Rect,
        icon: Icon,
        hit: Hit,
        on: bool,
        tint: Option<u32>,
    ) {
        let c = pal();
        self.rail_back(cv, r, hit, on);
        let lit = on || self.hover == Some(hit);
        let color = tint.unwrap_or(if lit { c.text } else { c.text_muted });
        Kit::new(cv, te, f, self.scale).icon_in(icon, r, 18.0, color);
        self.hits.push((r, hit));
    }

    /// Lays out the tooltip of `spec` beside an area (level with its
    /// control) or under its control, inside the window.
    pub(super) fn set_tip(
        &mut self,
        cv: &mut Canvas,
        te: &mut TextEngine,
        f: &Fonts,
        side: TipSide,
        spec: TipSpec,
    ) {
        let s = self.scale;
        let p = |v: f32| (v * s).round() as i32;
        let win_w = cv.width() as i32;
        let mut k = Kit::new(cv, te, f, s);
        let mut top_w = k.measure(Font::Semi, 12.5, &spec.title);
        if let Some(keys) = spec.keys {
            top_w += p(12.0) + k.keys_width(keys);
        }
        let sub_w = spec
            .sub
            .iter()
            .map(|l| k.measure(Font::Regular, 11.5, l))
            .max()
            .unwrap_or(0);
        let w = (top_w.max(sub_w) + 2 * p(10.0)).min(p(320.0));
        let h = p(32.0) + spec.sub.len() as i32 * p(17.0);
        let level = |area: Rect| {
            let mid = spec.anchor.y + spec.anchor.h / 2;
            (mid - h / 2).clamp(p(4.0), (area.bottom() - h - p(4.0)).max(p(4.0)))
        };
        let (x, y) = match side {
            TipSide::Right(area) => (area.right() + p(6.0), level(area)),
            TipSide::Left(area) => (area.x - p(6.0) - w, level(area)),
            TipSide::Below => (
                (spec.anchor.right() - w).clamp(p(4.0), (win_w - w - p(4.0)).max(p(4.0))),
                spec.anchor.bottom() + p(6.0),
            ),
        };
        self.tip = Some(Tip {
            rect: Rect::new(x, y, w, h),
            title: spec.title,
            sub: spec.sub,
            keys: spec.keys,
        });
    }

    /// The tooltip's rectangle with its shadow (to repaint it over the
    /// picture).
    pub(super) fn tip_bounds(&self) -> Option<Rect> {
        let t = self.tip.as_ref()?;
        let b = (14.0 * self.scale).ceil() as i32 + 1;
        Some(Rect::new(
            t.rect.x - b,
            t.rect.y - b,
            t.rect.w + 2 * b,
            t.rect.h + 2 * b + b / 2,
        ))
    }

    /// Paints the tooltip (over the picture: see `paint_session_overlay`).
    pub(super) fn paint_tip(&self, cv: &mut Canvas, te: &mut TextEngine, f: &Fonts) {
        let Some(t) = &self.tip else {
            return;
        };
        let s = self.scale;
        let c = pal();
        let mut k = Kit::new(cv, te, f, s);
        k.shadow(t.rect, radius::CONTROL, 12.0);
        let border = if c.dark { c.border_strong } else { c.border };
        k.cv.round_border(t.rect, radius::CONTROL * s, border, c.surface_raised);
        let pad = k.p(10.0);
        let row = Rect::new(
            t.rect.x + pad,
            t.rect.y + k.p(6.0),
            t.rect.w - 2 * pad,
            k.p(20.0),
        );
        let mut title_w = row.w;
        if let Some(keys) = t.keys {
            let kw = k.keys_width(keys);
            k.keys(row.right() - kw, row.y + (row.h - k.p(18.0)) / 2, keys);
            title_w -= kw + k.p(12.0);
        }
        k.text_in(
            Font::Semi,
            12.5,
            Rect::new(row.x, row.y, title_w, row.h),
            &t.title,
            c.text,
        );
        for (n, line) in t.sub.iter().enumerate() {
            let r = Rect::new(row.x, row.bottom() + n as i32 * k.p(17.0), row.w, k.p(17.0));
            k.text_in(Font::Regular, 11.5, r, line, c.text_muted);
        }
    }
}

/// The main window with the sidebar folded to its rail; with a session
/// on screen, and with the pointer on the first connection (its tooltip).
pub fn sample_rail(session: bool) -> Ui {
    let mut m = sample(session);
    m.sidebar_collapsed = true;
    m.hover = Some(Hit::Row(0));
    m
}

/// A session with the sidebar and the panel dragged wider, the panel's
/// divider mid-drag.
pub fn sample_resized() -> Ui {
    let mut m = sample(true);
    m.sidebar_w = 340.0;
    m.panel_w = 400.0;
    m.dividers.drag = Some(Drag {
        which: Divider::Panel,
        grab: 0,
    });
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn painted(m: &mut Ui, w: usize, h: usize) -> (TextEngine, Option<Fonts>) {
        let mut te = TextEngine::new();
        let fonts = load_fonts(&mut te);
        if let Some(f) = &fonts {
            let mut px = vec![0u32; w * h];
            m.paint(&mut Canvas::new(&mut px, w, h), &mut te, f);
        }
        (te, fonts)
    }

    fn rect_of(m: &Ui, hit: Hit) -> Rect {
        m.hits
            .iter()
            .rev()
            .find(|(_, h)| *h == hit)
            .map(|(r, _)| *r)
            .unwrap_or_else(|| panic!("{hit:?} not painted"))
    }

    #[test]
    fn the_hamburger_ctrl_b_and_the_palette_fold_the_sidebar() {
        let mut m = sample(false);
        assert!(!m.sidebar_collapsed);
        assert!(matches!(
            m.activate(Hit::SidebarToggle),
            Some(Action::SaveLayout)
        ));
        assert!(m.sidebar_collapsed);
        assert!(matches!(
            m.key(Key::ToggleSidebar),
            Some(Action::SaveLayout)
        ));
        assert!(!m.sidebar_collapsed);
        // The palette's command is the same control.
        let cmds: Vec<_> = m.palette_entries().into_iter().map(|e| e.cmd).collect();
        assert!(cmds.contains(&palette::Command::Sidebar));
        assert_eq!(palette::Command::Sidebar.hit(), Hit::SidebarToggle);
        // Ctrl+F on the rail unfolds it to reach the filter.
        m.sidebar_collapsed = true;
        assert!(matches!(m.key(Key::Find), Some(Action::SaveLayout)));
        assert!(!m.sidebar_collapsed);
        assert_eq!(m.focus, Some(Field::Filter));
        // Full screen has no sidebar to fold.
        m.fullscreen = true;
        assert!(m.key(Key::ToggleSidebar).is_none());
        assert!(!m.sidebar_collapsed);
    }

    #[test]
    fn the_rail_lists_every_connection_and_a_click_is_the_rows_click() {
        let mut m = sample(false);
        m.sidebar_collapsed = true;
        m.collapsed.insert("Work".into()); // a folded group still shows
        let (mut te, Some(fonts)) = painted(&mut m, 1320, 860) else {
            return; // no UI font on this machine
        };
        assert_eq!(m.rail_order().len(), m.store.connections.len());
        for i in 0..m.store.connections.len() {
            let r = rect_of(&m, Hit::Row(i));
            assert!(r.right() <= (RAIL_W * m.scale) as i32, "inside the rail");
        }
        // The rail is narrow: the session area is wide.
        let (w, _) = m.session_size_for(1320, 860);
        assert_eq!(w, 1320 - 56 - 1 - (DRAWER_W as i32) - 1);
        // A click on an avatar opens the connection, like its row.
        let r = rect_of(&m, Hit::Row(2));
        let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
        m.mouse_move(x, y);
        m.mouse_down(x, y, &mut te, &fonts);
        assert!(m.mouse_up(x, y).is_none());
        assert_eq!((m.selected, m.active), (Some(2), None));
        // Hovering it shows its name and the apps it can start.
        let mut px = vec![0u32; 1320 * 860];
        m.hover = Some(Hit::Row(3));
        m.paint(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        let tip = m.tip.as_ref().expect("a tooltip");
        assert_eq!(tip.title, "Office apps");
        assert!(tip.sub.iter().any(|l| l.contains("Ledger, Planner")));
        assert!(tip.rect.x >= (RAIL_W * m.scale) as i32, "right of the rail");
        assert!(
            m.overlay_rect()
                .is_some_and(|o| o.contains(tip.rect.x, tip.rect.y))
        );
        // Nothing hovered: no tooltip.
        m.hover = None;
        m.paint(&mut Canvas::new(&mut px, 1320, 860), &mut te, &fonts);
        assert!(m.tip.is_none());
    }

    #[test]
    fn too_many_connections_fold_into_a_more_tile() {
        let mut m = sample(false);
        let base = m.store.connections[2].clone();
        for n in 0..30 {
            let mut c = base.clone();
            c.name = format!("Extra {n}");
            m.store.connections.push(c);
        }
        m.sidebar_collapsed = true;
        let (_te, Some(_)) = painted(&mut m, 1320, 860) else {
            return;
        };
        let more = rect_of(&m, Hit::RailMore);
        let shown = m
            .hits
            .iter()
            .filter(|(_, h)| matches!(h, Hit::Row(_)))
            .count();
        assert!(shown > 5 && shown < m.store.connections.len());
        assert!(more.bottom() <= rect_of(&m, Hit::OpenSettings).y);
        assert!(matches!(
            m.activate(Hit::RailMore),
            Some(Action::SaveLayout)
        ));
        assert!(!m.sidebar_collapsed);
    }

    #[test]
    fn dragging_the_sidebar_resizes_snaps_to_the_rail_and_resets() {
        let mut m = sample(false);
        let (_te, Some(fonts)) = painted(&mut m, 1320, 860) else {
            return;
        };
        let _ = fonts;
        let grip = rect_of(&m, Hit::Divider(Divider::Sidebar));
        let x0 = grip.x + grip.w / 2;
        assert_eq!(x0, 264, "the grip sits on the edge");
        let t0 = Instant::now();
        m.divider_press(Divider::Sidebar, x0, t0);
        assert!(m.resizing() && m.cursor_is_resize());
        assert!(m.drag_to(x0 + 100));
        assert_eq!(m.sidebar_w, 364.0);
        // Clamped at both ends.
        m.drag_to(5000);
        assert_eq!(m.sidebar_w, SIDEBAR_MAX);
        m.drag_to(170);
        assert_eq!((m.sidebar_collapsed, m.sidebar_w), (false, SIDEBAR_MIN));
        // Narrower than the snap point: the rail.
        m.drag_to(100);
        assert!(m.sidebar_collapsed);
        assert!(matches!(m.divider_release(), Some(Action::SaveLayout)));
        assert!(!m.resizing());
        assert_eq!(m.layout_settings(), (true, 200, 320));
        // A press without a move saves nothing.
        m.divider_press(Divider::Sidebar, 56, t0 + Duration::from_secs(5));
        assert!(m.divider_release().is_none());
        // A double-click: the default width, unfolded.
        m.divider_press(Divider::Sidebar, 56, t0 + Duration::from_millis(5300));
        assert!(!m.resizing());
        assert!(matches!(m.divider_release(), Some(Action::SaveLayout)));
        assert_eq!(m.layout_settings(), (false, 264, 320));
    }

    #[test]
    fn dragging_the_panel_resizes_the_session_area() {
        let mut m = sample(true);
        let (mut te, Some(fonts)) = painted(&mut m, 1500, 940) else {
            return;
        };
        let (_, before) = m.session_area.unwrap();
        let grip = rect_of(&m, Hit::Divider(Divider::Panel));
        let x0 = grip.x + grip.w / 2;
        assert_eq!(x0, before.right(), "the grip sits on the panel's edge");
        // Through the mouse: down on the grip, move left, up.
        m.mouse_move(x0, grip.y + 200);
        assert!(m.cursor_is_resize());
        m.mouse_down(x0, grip.y + 200, &mut te, &fonts);
        assert!(m.resizing());
        assert!(m.mouse_move(x0 - 80, grip.y + 300));
        assert_eq!(m.panel_w, DRAWER_W + 80.0);
        // While it drags the picture follows the panel.
        let mut px = vec![0u32; 1500 * 940];
        m.paint(&mut Canvas::new(&mut px, 1500, 940), &mut te, &fonts);
        let (_, during) = m.session_area.unwrap();
        assert_eq!(during.w, before.w - 80);
        assert_eq!(m.session_size_for(1500, 940), (during.w, during.h));
        assert!(matches!(
            m.mouse_up(x0 - 80, grip.y + 300),
            Some(Action::SaveLayout)
        ));
        assert!(!m.resizing());
        assert_eq!(m.layout_settings(), (false, 264, 400));
        // Clamped.
        m.panel_w = 9000.0;
        assert_eq!(m.panel_px(4000), (PANEL_MAX * m.scale) as i32);
        assert_eq!(m.panel_px(400), 200, "never more than half the area");
    }

    #[test]
    fn widths_scale_with_the_display() {
        let mut m = sample(false);
        m.scale = 1.5;
        m.sidebar_w = 300.0;
        assert_eq!(m.sidebar_px(3000), 450);
        m.sidebar_collapsed = true;
        assert_eq!(m.sidebar_px(3000), 84);
        m.sidebar_collapsed = false;
        // A small window keeps a third of itself for the sidebar at most.
        assert_eq!(m.sidebar_px(900), 300);
        // A drag works in logical px.
        m.dividers.sidebar_x = 450;
        m.divider_press(Divider::Sidebar, 450, Instant::now());
        m.drag_to(450 + 150);
        assert_eq!(m.sidebar_w, 400.0);
        // Settings out of range come back clamped.
        m.set_layout(false, 5, 99999);
        assert_eq!(m.layout_settings(), (false, 200, 560));
    }
}
