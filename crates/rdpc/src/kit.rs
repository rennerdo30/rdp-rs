//! The component kit: every control rdpc draws, styled from the theme
//! tokens ([`crate::theme`]) and the icon set ([`crate::icons`]).
//!
//! Components only paint. They take a rectangle (or a position) in
//! physical pixels and a [`State`]; the caller owns layout, hit testing
//! and focus, so the kit works for the main window, the span bar and
//! anything built later.
//!
//! ```ignore
//! let mut k = Kit::new(cv, te, fonts, scale);
//! k.button(r, &Button::primary("Connect").icon(Icon::Play), state);
//! let w = k.pill(x, y, "Live", Tone::Success, Lead::Dot);
//! ```
//!
//! Sizes passed as `f32` are logical pixels (scaled by `s` inside);
//! rectangles and positions are physical pixels.

use ffwd_render::{Canvas, FontId, Rect, TextEngine};

use crate::icons::{self, Icon};
use crate::theme::{self, Tone, pal, radius, size};
use crate::ui::Fonts;

/// Interaction state of one control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub hover: bool,
    pub press: bool,
    /// Keyboard focus: draws the focus ring.
    pub focus: bool,
    pub disabled: bool,
}

impl State {
    pub fn hover(hover: bool) -> State {
        State {
            hover,
            ..State::default()
        }
    }
}

/// Button look, from loudest to quietest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The one main action of a view (accent fill).
    Primary,
    /// Neutral bordered button.
    Secondary,
    /// No frame until hovered (toolbars, sidebars).
    Ghost,
    /// A confirmed destructive action (red fill).
    Danger,
    /// A destructive action offered next to others (red text, no fill).
    DangerGhost,
}

/// What a button shows.
#[derive(Clone, Copy, Debug)]
pub struct Button<'t> {
    pub label: &'t str,
    pub icon: Option<Icon>,
    pub variant: Variant,
    /// Icon colour instead of the label's (the red dot of Record).
    pub icon_color: Option<u32>,
}

impl<'t> Button<'t> {
    pub fn new(label: &'t str, variant: Variant) -> Button<'t> {
        Button {
            label,
            icon: None,
            variant,
            icon_color: None,
        }
    }
    pub fn primary(label: &'t str) -> Button<'t> {
        Button::new(label, Variant::Primary)
    }
    pub fn secondary(label: &'t str) -> Button<'t> {
        Button::new(label, Variant::Secondary)
    }
    pub fn ghost(label: &'t str) -> Button<'t> {
        Button::new(label, Variant::Ghost)
    }
    pub fn icon(mut self, icon: Icon) -> Button<'t> {
        self.icon = Some(icon);
        self
    }
    pub fn icon_color(mut self, color: u32) -> Button<'t> {
        self.icon_color = Some(color);
        self
    }
}

/// What leads a pill's text.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lead {
    None,
    /// A status dot in the tone's colour.
    Dot,
    /// A dot in a given colour (a group colour).
    Swatch(u32),
    Icon(Icon),
}

/// One segment of a segmented control.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'t> {
    pub label: &'t str,
    pub icon: Option<Icon>,
    pub on: bool,
    pub hover: bool,
}

/// A piece of a keyboard hint line.
#[derive(Clone, Copy, Debug)]
pub enum Hint<'t> {
    /// Key caps: "Ctrl+S" draws two caps.
    Keys(&'t str),
    Text(&'t str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Font {
    Regular,
    Semi,
}

/// Paints components onto one canvas.
pub struct Kit<'a, 'b> {
    pub cv: &'a mut Canvas<'b>,
    pub te: &'a mut TextEngine,
    pub f: &'a Fonts,
    /// UI scale (1.0 = 96 dpi).
    pub s: f32,
}

impl<'a, 'b> Kit<'a, 'b> {
    pub fn new(cv: &'a mut Canvas<'b>, te: &'a mut TextEngine, f: &'a Fonts, s: f32) -> Self {
        Kit { cv, te, f, s }
    }

    /// Logical to physical pixels.
    pub fn p(&self, v: f32) -> i32 {
        (v * self.s).round() as i32
    }

    fn font(&self, font: Font) -> FontId {
        match font {
            Font::Regular => self.f.ui,
            Font::Semi => self.f.semi,
        }
    }

    // ---- Text ----------------------------------------------------------

    /// Width of `text` in physical pixels (`size` logical).
    pub fn measure(&mut self, font: Font, size: f32, text: &str) -> i32 {
        let id = self.font(font);
        self.te.measure(id, size * self.s, text).ceil() as i32
    }

    /// Text with its baseline at `y`, cut with an ellipsis at `max_w`.
    /// Returns the end x.
    #[allow(clippy::too_many_arguments)]
    pub fn text(
        &mut self,
        font: Font,
        size: f32,
        x: i32,
        y: i32,
        text: &str,
        color: u32,
        max_w: i32,
    ) -> i32 {
        let id = self.font(font);
        self.te.draw(
            self.cv,
            id,
            size * self.s,
            x as f32,
            y as f32,
            text,
            color,
            max_w.max(0) as f32,
        ) as i32
    }

    /// Text with some characters marked (search matches): marked runs are
    /// semibold in `mark`, the rest regular in `color`. `marks` are char
    /// indices, ascending. Cut with an ellipsis at `max_w`; returns the end x.
    #[allow(clippy::too_many_arguments)]
    pub fn text_marked(
        &mut self,
        size: f32,
        x: i32,
        y: i32,
        text: &str,
        marks: &[usize],
        color: u32,
        mark: u32,
        max_w: i32,
    ) -> i32 {
        let end = x + max_w;
        let mut pen = x;
        let mut run = String::new();
        let mut run_marked = false;
        let mut chars = text.chars().enumerate().peekable();
        while let Some((i, ch)) = chars.next() {
            let marked = marks.binary_search(&i).is_ok();
            if marked != run_marked && !run.is_empty() {
                let (font, c) = if run_marked {
                    (Font::Semi, mark)
                } else {
                    (Font::Regular, color)
                };
                pen = self.text(font, size, pen, y, &run, c, end - pen);
                run.clear();
                if pen >= end {
                    return pen;
                }
            }
            run_marked = marked;
            run.push(ch);
            if chars.peek().is_none() {
                let (font, c) = if run_marked {
                    (Font::Semi, mark)
                } else {
                    (Font::Regular, color)
                };
                pen = self.text(font, size, pen, y, &run, c, end - pen);
            }
        }
        pen
    }

    /// Text vertically centred in `r`, left aligned (ellipsis at the right).
    pub fn text_in(&mut self, font: Font, size: f32, r: Rect, text: &str, color: u32) -> i32 {
        let id = self.font(font);
        let base = self.baseline(font, size, r);
        self.te.draw(
            self.cv,
            id,
            size * self.s,
            r.x as f32,
            base as f32,
            text,
            color,
            r.w.max(0) as f32,
        ) as i32
    }

    /// Text centred in `r` both ways.
    pub fn text_center(&mut self, font: Font, size: f32, r: Rect, text: &str, color: u32) {
        let id = self.font(font);
        let tw = self.te.measure(id, size * self.s, text);
        let x = r.x as f32 + ((r.w as f32 - tw) / 2.0).max(0.0);
        let base = self.baseline(font, size, r);
        self.te.draw(
            self.cv,
            id,
            size * self.s,
            x.round(),
            base as f32,
            text,
            color,
            (r.right() as f32 - x).max(0.0) + 1.0,
        );
    }

    /// Text ending at `right`, vertically centred in `r`'s rows.
    pub fn text_right(&mut self, font: Font, size: f32, r: Rect, text: &str, color: u32) {
        let w = self.measure(font, size, text).min(r.w);
        let rr = Rect::new(r.right() - w, r.y, w + 1, r.h);
        self.text_in(font, size, rr, text, color);
    }

    /// The baseline that centres a line of `size` in `r`.
    pub fn baseline(&self, font: Font, size: f32, r: Rect) -> i32 {
        let asc = self.te.ascent(self.font(font), size * self.s);
        (r.y as f32 + (r.h as f32 + asc * 0.72) / 2.0).round() as i32
    }

    /// Splits `text` into lines no wider than `max_w`.
    pub fn wrap(&mut self, font: Font, size: f32, text: &str, max_w: i32) -> Vec<String> {
        let mut lines = Vec::new();
        let mut line = String::new();
        for word in text.split(' ') {
            let next = if line.is_empty() {
                word.to_string()
            } else {
                format!("{line} {word}")
            };
            if !line.is_empty() && self.measure(font, size, &next) > max_w {
                lines.push(std::mem::replace(&mut line, word.to_string()));
            } else {
                line = next;
            }
        }
        if !line.is_empty() {
            lines.push(line);
        }
        lines
    }

    /// Wrapped text from baseline `y`; returns the y below the last line.
    #[allow(clippy::too_many_arguments)]
    pub fn paragraph(
        &mut self,
        font: Font,
        size: f32,
        x: i32,
        y: i32,
        w: i32,
        text: &str,
        color: u32,
        center: bool,
    ) -> i32 {
        let lh = self.p(size * 1.5);
        let mut y = y;
        for line in self.wrap(font, size, text, w) {
            if center {
                let lw = self.measure(font, size, &line);
                self.text(font, size, x + (w - lw).max(0) / 2, y, &line, color, w);
            } else {
                self.text(font, size, x, y, &line, color, w);
            }
            y += lh;
        }
        y
    }

    /// Upper-case section label with a little tracking.
    pub fn caption_text(&mut self, x: i32, y: i32, text: &str, color: u32) -> i32 {
        let id = self.f.semi;
        let sz = size::CAPTION * self.s;
        let track = 0.6 * self.s;
        let mut pen = x as f32;
        let mut buf = [0u8; 4];
        for c in text.chars() {
            let ch = c.encode_utf8(&mut buf);
            self.te
                .draw(self.cv, id, sz, pen.round(), y as f32, ch, color, f32::MAX);
            pen += self.te.measure(id, sz, ch) + track;
        }
        pen as i32
    }

    // ---- Icons ---------------------------------------------------------

    /// An icon of `size` logical px with its top-left at (x, y).
    pub fn icon(&mut self, icon: Icon, x: i32, y: i32, size: f32, color: u32) {
        icons::draw(self.cv, icon, x as f32, y as f32, size * self.s, color);
    }

    /// An icon centred in `r`.
    pub fn icon_in(&mut self, icon: Icon, r: Rect, size: f32, color: u32) {
        let d = self.p(size);
        self.icon(icon, r.x + (r.w - d) / 2, r.y + (r.h - d) / 2, size, color);
    }

    /// The rdpc mark: an accent tile with a monitor and a live dot.
    pub fn logo(&mut self, x: i32, y: i32, size: f32) {
        let p = pal();
        let d = self.p(size);
        let r = Rect::new(x, y, d, d);
        self.cv.fill_round(r, d as f32 * 0.3, p.accent);
        let m = (d as f32 * 0.62).round() as i32;
        icons::draw(
            self.cv,
            Icon::Monitor,
            (x + (d - m) / 2) as f32,
            (y + (d - m) / 2) as f32 - d as f32 * 0.02,
            m as f32,
            p.accent_text,
        );
    }

    // ---- Surfaces ------------------------------------------------------

    /// A soft drop shadow around `r` (dialogs and popovers only).
    pub fn shadow(&mut self, r: Rect, rad: f32, blur: f32) {
        let (color, peak) = pal().shadow;
        let b = blur * self.s;
        let dy = (b / 3.0).round() as i32;
        let rad = rad * self.s;
        let outer = Rect::new(
            r.x - b.ceil() as i32,
            r.y - b.ceil() as i32 + dy,
            r.w + 2 * b.ceil() as i32,
            r.h + 2 * b.ceil() as i32,
        );
        let clip = self.cv.clip();
        for y in outer.y.max(clip.y)..outer.bottom().min(clip.bottom()) {
            for x in outer.x.max(clip.x)..outer.right().min(clip.right()) {
                // Distance to the rounded rectangle (shifted down by dy).
                let px = x as f32 + 0.5;
                let py = (y - dy) as f32 + 0.5;
                let qx = (px - (r.x as f32 + r.w as f32 / 2.0)).abs() - (r.w as f32 / 2.0 - rad);
                let qy = (py - (r.y as f32 + r.h as f32 / 2.0)).abs() - (r.h as f32 / 2.0 - rad);
                let d = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() - rad;
                if d <= 0.0 && r.contains(x, y) {
                    continue;
                }
                let t = (1.0 - d.max(0.0) / b).clamp(0.0, 1.0);
                let a = (peak as f32 * t * t) as u32;
                if a > 0 {
                    self.cv.fill_alpha(Rect::new(x, y, 1, 1), color, a);
                }
            }
        }
    }

    /// Dims `r` behind a dialog.
    pub fn scrim(&mut self, r: Rect) {
        let (color, a) = pal().scrim;
        self.cv.fill_alpha(r, color, a);
    }

    /// A dialog card: shadow, raised fill, border, dialog radius.
    pub fn dialog(&mut self, r: Rect) {
        let p = pal();
        self.shadow(r, radius::DIALOG, 24.0);
        let border = if p.dark { p.border_strong } else { p.border };
        self.cv
            .round_border(r, radius::DIALOG * self.s, border, p.surface_raised);
    }

    /// A scroll bar thumb at the right edge of `track` for content of
    /// `content` px scrolled by `offset`.
    pub fn scrollbar(&mut self, track: Rect, content: i32, offset: i32) {
        let max = (content - track.h).max(0);
        if max == 0 {
            return;
        }
        let pad = self.p(4.0);
        let len = track.h - 2 * pad;
        let bar = (len * track.h / content).max(self.p(28.0));
        let y = track.y + pad + (len - bar) * offset / max;
        let w = self.p(4.0);
        self.cv.fill_round(
            Rect::new(track.right() - w - self.p(3.0), y, w, bar),
            w as f32 / 2.0,
            pal().scrollbar,
        );
    }

    /// The focus ring around a control (2 px, outside it).
    pub fn focus_ring(&mut self, r: Rect, rad: f32) {
        let g = self.p(2.0).max(1);
        let outer = Rect::new(r.x - g - 1, r.y - g - 1, r.w + 2 * g + 2, r.h + 2 * g + 2);
        let ring = pal().focus_ring;
        let o = rad * self.s + g as f32 + 1.0;
        self.round_outline(outer, o, g as f32, ring);
    }

    /// A rounded rectangle outline of width `w` (no fill inside).
    pub fn round_outline(&mut self, r: Rect, rad: f32, w: f32, color: u32) {
        let rad = rad.min(r.w as f32 / 2.0).min(r.h as f32 / 2.0);
        let (x0, y0) = (r.x as f32 + w / 2.0, r.y as f32 + w / 2.0);
        let (x1, y1) = (r.right() as f32 - w / 2.0, r.bottom() as f32 - w / 2.0);
        let rr = (rad - w / 2.0).max(0.0);
        let mut pts = Vec::new();
        let arc = |pts: &mut Vec<(f32, f32)>, cx: f32, cy: f32, a0: f32| {
            for i in 0..=6 {
                let a = (a0 + 90.0 * i as f32 / 6.0).to_radians();
                pts.push((cx + rr * a.cos(), cy + rr * a.sin()));
            }
        };
        arc(&mut pts, x1 - rr, y0 + rr, -90.0);
        arc(&mut pts, x1 - rr, y1 - rr, 0.0);
        arc(&mut pts, x0 + rr, y1 - rr, 90.0);
        arc(&mut pts, x0 + rr, y0 + rr, 180.0);
        if let Some(&first) = pts.first() {
            pts.push(first);
        }
        self.cv.stroke(&pts, w, color);
    }

    // ---- Buttons -------------------------------------------------------

    /// The width a button needs for its label and icon.
    pub fn button_width(&mut self, b: &Button) -> i32 {
        button_width(self.te, self.f, self.s, b)
    }

    /// A button: fill and border by variant and state, icon then label,
    /// centred in `r`.
    pub fn button(&mut self, r: Rect, b: &Button, st: State) {
        let p = pal();
        let rad = radius::CONTROL * self.s;
        let (fill, border, color) = match (b.variant, st.disabled) {
            (_, true) => (Some(p.surface_hover), Some(p.border), p.text_faint),
            (Variant::Primary, _) => {
                let f = if st.press {
                    p.accent_pressed
                } else if st.hover {
                    p.accent_hover
                } else {
                    p.accent
                };
                (Some(f), None, p.accent_text)
            }
            (Variant::Secondary, _) => (
                Some(if st.press {
                    p.surface_pressed
                } else if st.hover {
                    p.surface_hover
                } else {
                    p.surface_raised
                }),
                Some(if st.hover { p.border_strong } else { p.border }),
                p.text,
            ),
            (Variant::Ghost, _) => (
                if st.press {
                    Some(p.surface_pressed)
                } else if st.hover {
                    Some(p.surface_hover)
                } else {
                    None
                },
                None,
                if st.hover { p.text } else { p.text_secondary },
            ),
            (Variant::Danger, _) => {
                let base = p.danger;
                let f = if st.press {
                    theme::mix(base, 0x000000, 40)
                } else if st.hover {
                    theme::mix(base, 0xffffff, 26)
                } else {
                    base
                };
                (Some(f), None, p.on_solid)
            }
            (Variant::DangerGhost, _) => (
                if st.press {
                    Some(theme::mix(p.danger_subtle, p.danger, 30))
                } else if st.hover {
                    Some(p.danger_subtle)
                } else {
                    None
                },
                None,
                p.danger,
            ),
        };
        match (fill, border) {
            (Some(f), Some(b)) => self.cv.round_border(r, rad, b, f),
            (Some(f), None) => self.cv.fill_round(r, rad, f),
            _ => {}
        }
        if st.focus {
            self.focus_ring(r, radius::CONTROL);
        }
        let font = if b.variant == Variant::Primary {
            Font::Semi
        } else {
            Font::Regular
        };
        let tw = if b.label.is_empty() {
            0
        } else {
            self.measure(font, size::BODY, b.label)
        };
        let iw = if b.icon.is_some() { self.p(16.0) } else { 0 };
        let gap = if iw > 0 && tw > 0 { self.p(7.0) } else { 0 };
        let total = iw + gap + tw;
        let mut x = r.x + ((r.w - total) / 2).max(if iw > 0 { self.p(10.0) } else { 0 });
        if let Some(icon) = b.icon {
            let ic = b.icon_color.filter(|_| !st.disabled).unwrap_or(color);
            self.icon(icon, x, r.y + (r.h - iw) / 2, 16.0, ic);
            x += iw + gap;
        }
        if tw > 0 {
            let base = self.baseline(font, size::BODY, r);
            self.text(font, size::BODY, x, base, b.label, color, r.right() - x + 1);
        }
    }

    /// A square icon-only button (ghost unless `variant` says otherwise).
    pub fn icon_button(&mut self, r: Rect, icon: Icon, variant: Variant, st: State) {
        let p = pal();
        let rad = radius::CONTROL * self.s;
        let color = match variant {
            Variant::Primary => {
                self.cv
                    .fill_round(r, rad, if st.hover { p.accent_hover } else { p.accent });
                p.accent_text
            }
            Variant::Secondary => {
                self.cv.round_border(
                    r,
                    rad,
                    if st.hover { p.border_strong } else { p.border },
                    if st.press {
                        p.surface_pressed
                    } else if st.hover {
                        p.surface_hover
                    } else {
                        p.surface_raised
                    },
                );
                p.text_secondary
            }
            Variant::Danger | Variant::DangerGhost => {
                if st.hover {
                    self.cv.fill_round(r, rad, p.danger_subtle);
                }
                if st.hover { p.danger } else { p.text_muted }
            }
            Variant::Ghost => {
                if st.press {
                    self.cv.fill_round(r, rad, p.surface_pressed);
                } else if st.hover {
                    self.cv.fill_round(r, rad, p.surface_hover);
                }
                if st.hover { p.text } else { p.text_muted }
            }
        };
        if st.focus {
            self.focus_ring(r, radius::CONTROL);
        }
        let sz = if r.h < self.p(26.0) { 14.0 } else { 16.0 };
        self.icon_in(icon, r, sz, color);
    }

    // ---- Pills, avatars, keycaps --------------------------------------

    /// Width of a pill with `text` and `lead`.
    pub fn pill_width(&mut self, text: &str, lead: Lead) -> i32 {
        let tw = self.measure(Font::Semi, 11.5, text);
        let lead_w = match lead {
            Lead::None => 0,
            Lead::Dot | Lead::Swatch(_) => self.p(12.0),
            Lead::Icon(_) => self.p(17.0),
        };
        tw + lead_w + self.p(18.0)
    }

    /// A rounded status pill (20 px tall) at (x, y); returns its width.
    pub fn pill(&mut self, x: i32, y: i32, text: &str, tone: Tone, lead: Lead) -> i32 {
        let w = self.pill_width(text, lead);
        let h = self.p(20.0);
        let r = Rect::new(x, y, w, h);
        self.cv.fill_round(r, h as f32 / 2.0, tone.subtle());
        let fg = match tone {
            Tone::Neutral | Tone::Muted => pal().text_secondary,
            t => t.color(),
        };
        let mut tx = x + self.p(9.0);
        match lead {
            Lead::None => {}
            Lead::Dot | Lead::Swatch(_) => {
                let dot = match lead {
                    Lead::Swatch(c) => c,
                    _ => tone.color(),
                };
                self.cv.fill_circle(
                    (tx + self.p(3.0)) as f32,
                    (y + h / 2) as f32,
                    3.0 * self.s,
                    dot,
                );
                tx += self.p(12.0);
            }
            Lead::Icon(icon) => {
                self.icon(icon, tx - self.p(1.0), y + (h - self.p(13.0)) / 2, 13.0, fg);
                tx += self.p(17.0);
            }
        }
        let base = self.baseline(Font::Semi, 11.5, r);
        self.text(Font::Semi, 11.5, tx, base, text, fg, w);
        w
    }

    /// A rounded avatar tile with a monogram in group colour `color`
    /// (index into the group palette) and an optional status dot whose
    /// ring takes `ring_bg` (the colour around the avatar).
    pub fn avatar(&mut self, r: Rect, name: &str, color: usize, status: Option<u32>, ring_bg: u32) {
        let (fill, fg) = theme::group_tile(color);
        self.cv.fill_round(r, r.w as f32 * 0.28, fill);
        let mono = monogram(name);
        let sz = (r.h as f32 / self.s) * 0.4;
        self.text_center(Font::Semi, sz, r, &mono, fg);
        if let Some(c) = status {
            let d = (r.w as f32 * 0.17).max(3.0 * self.s);
            let (cx, cy) = (r.right() as f32 - d * 0.6, r.bottom() as f32 - d * 0.6);
            self.cv.fill_circle(cx, cy, d + 1.6 * self.s, ring_bg);
            self.cv.fill_circle(cx, cy, d, c);
        }
    }

    /// One key cap ("Ctrl", "K"); returns its width.
    pub fn keycap(&mut self, x: i32, y: i32, key: &str) -> i32 {
        let p = pal();
        let h = self.p(18.0);
        let tw = self.measure(Font::Semi, 10.5, key);
        let w = (tw + self.p(10.0)).max(h);
        let r = Rect::new(x, y, w, h);
        let rad = 4.0 * self.s;
        // Bottom edge a little heavier: reads as a key.
        self.cv.fill_round(r, rad, p.border_strong);
        self.cv.fill_round(
            Rect::new(r.x + 1, r.y + 1, r.w - 2, r.h - 1 - self.p(1.5).max(1)),
            rad - 1.0,
            p.surface_raised,
        );
        let inner = Rect::new(r.x, r.y, r.w, r.h - self.p(1.0));
        self.text_center(Font::Semi, 10.5, inner, key, p.text_secondary);
        w
    }

    /// The width of `keys(combo)`.
    pub fn keys_width(&mut self, combo: &str) -> i32 {
        let h = self.p(18.0);
        let mut w = 0;
        for (i, key) in combo.split('+').enumerate() {
            if i > 0 {
                w += self.p(3.0);
            }
            w += (self.measure(Font::Semi, 10.5, key) + self.p(10.0)).max(h);
        }
        w
    }

    /// Key caps for a combination ("Ctrl+Shift+U"); returns the width.
    pub fn keys(&mut self, x: i32, y: i32, combo: &str) -> i32 {
        let mut cx = x;
        for (i, key) in combo.split('+').enumerate() {
            if i > 0 {
                cx += self.p(3.0);
            }
            cx += self.keycap(cx, y, key);
        }
        cx - x
    }

    /// A line of hints ("[Enter] connects  [Ctrl][S] saves") with its
    /// vertical centre at `cy`, cut at `max_w`.
    pub fn hints(&mut self, x: i32, cy: i32, max_w: i32, items: &[Hint]) {
        let p = pal();
        let cap_y = cy - self.p(9.0);
        let mut cx = x;
        for (i, item) in items.iter().enumerate() {
            match item {
                Hint::Keys(k) => {
                    if i > 0 {
                        cx += self.p(14.0);
                    }
                    if cx + self.p(18.0) > x + max_w {
                        return;
                    }
                    cx += self.keys(cx, cap_y, k);
                }
                Hint::Text(t) => {
                    cx += self.p(6.0);
                    let r = Rect::new(cx, cy - self.p(9.0), x + max_w - cx, self.p(18.0));
                    if r.w <= 0 {
                        return;
                    }
                    cx = self.text_in(Font::Regular, size::SMALL, r, t, p.text_muted);
                }
            }
        }
    }

    // ---- Form controls -------------------------------------------------

    /// A switch (36 x 20) with its top-left at (x, y).
    pub fn switch(&mut self, x: i32, y: i32, on: bool, st: State) {
        let p = pal();
        let r = Rect::new(x, y, self.p(36.0), self.p(20.0));
        let track = match (on, st.hover) {
            (true, true) => p.accent_hover,
            (true, false) => p.accent,
            (false, true) => theme::mix(p.border_strong, p.text_faint, 90),
            (false, false) => p.border_strong,
        };
        self.cv.fill_round(r, r.h as f32 / 2.0, track);
        let knob_x = if on {
            r.right() - r.h / 2
        } else {
            r.x + r.h / 2
        };
        let knob = if on || !p.dark {
            p.on_solid
        } else {
            p.text_secondary
        };
        self.cv.fill_circle(
            knob_x as f32,
            (r.y + r.h / 2) as f32,
            r.h as f32 / 2.0 - 3.0 * self.s,
            knob,
        );
        if st.focus {
            self.focus_ring(r, 10.0);
        }
    }

    /// A radio mark centred at (cx, cy).
    pub fn radio(&mut self, cx: i32, cy: i32, on: bool, st: State) {
        let p = pal();
        let (x, y) = (cx as f32, cy as f32);
        let r = 9.0 * self.s;
        if on {
            self.cv.fill_circle(x, y, r, p.accent);
            let d = self.p(12.0);
            self.icon(Icon::Check, cx - d / 2, cy - d / 2, 12.0, p.accent_text);
        } else {
            let c = if st.hover {
                p.text_muted
            } else {
                p.border_strong
            };
            self.cv.ring(x, y, r, 1.5 * self.s, c);
        }
    }

    /// Frame of a text field: inset fill, border, focus ring. Returns the
    /// inner text rectangle (after the leading icon, if any).
    pub fn field_frame(&mut self, r: Rect, icon: Option<Icon>, st: State) -> Rect {
        let p = pal();
        let rad = radius::CONTROL * self.s;
        let border = if st.focus {
            p.accent
        } else if st.hover {
            p.border_strong
        } else {
            p.border
        };
        self.cv.round_border(r, rad, border, p.field);
        if st.focus {
            self.focus_ring(r, radius::CONTROL);
        }
        let mut inner = Rect::new(r.x + self.p(10.0), r.y, r.w - self.p(20.0), r.h);
        if let Some(icon) = icon {
            let d = self.p(15.0);
            let c = if st.focus { p.accent } else { p.text_faint };
            self.icon(icon, r.x + self.p(10.0), r.y + (r.h - d) / 2, 15.0, c);
            inner.x += self.p(23.0);
            inner.w -= self.p(23.0);
        }
        inner
    }

    /// A segmented control: equal segments in an inset frame, the chosen
    /// one raised. Returns the segment rectangles (for hits).
    pub fn segmented(&mut self, r: Rect, items: &[Segment]) -> Vec<Rect> {
        let p = pal();
        let rad = (radius::CONTROL + 1.0) * self.s;
        self.cv.round_border(r, rad, p.border, p.field);
        let pad = self.p(3.0);
        let n = items.len().max(1) as i32;
        let inner = r.w - 2 * pad;
        let mut out = Vec::with_capacity(items.len());
        // Icons only when every segment has room for its icon and label
        // (semibold, as when chosen), so the row stays consistent.
        let cell_w = inner / n;
        let icons = items.iter().all(|it| {
            it.icon.is_some()
                && self.p(15.0)
                    + self.p(6.0)
                    + self.measure(Font::Semi, size::SMALL, it.label)
                    + self.p(8.0)
                    <= cell_w
        });
        for (i, it) in items.iter().enumerate() {
            let i = i as i32;
            let x0 = r.x + pad + inner * i / n;
            let x1 = r.x + pad + inner * (i + 1) / n;
            let cell = Rect::new(x0, r.y + pad, x1 - x0, r.h - 2 * pad);
            let crad = (radius::CONTROL - 1.0) * self.s;
            if it.on {
                let b = if p.dark { p.border_strong } else { p.border };
                self.cv.round_border(cell, crad, b, p.surface_raised);
            } else if it.hover {
                self.cv.fill_round(cell, crad, p.surface_hover);
            }
            let (font, color) = if it.on {
                (Font::Semi, p.text)
            } else if it.hover {
                (Font::Regular, p.text)
            } else {
                (Font::Regular, p.text_muted)
            };
            let tw = self.measure(font, size::SMALL, it.label);
            let iw = if it.icon.is_some() { self.p(15.0) } else { 0 };
            let gap = if iw > 0 { self.p(6.0) } else { 0 };
            let (iw, gap) = if icons { (iw, gap) } else { (0, 0) };
            let x = cell.x + (cell.w - iw - gap - tw).max(0) / 2;
            if let (Some(icon), true) = (it.icon, iw > 0) {
                let ic = if it.on { p.accent } else { color };
                self.icon(icon, x, cell.y + (cell.h - iw) / 2, 15.0, ic);
            }
            let base = self.baseline(font, size::SMALL, cell);
            self.text(
                font,
                size::SMALL,
                x + iw + gap,
                base,
                it.label,
                color,
                cell.right() - x - iw - gap,
            );
            out.push(cell);
        }
        out
    }

    /// A section header: tracked upper-case caption at (x, y) in an 18 px
    /// row, with an optional action link at the right. Returns the action's
    /// rectangle.
    pub fn section(
        &mut self,
        x: i32,
        y: i32,
        w: i32,
        caption: &str,
        action: Option<(&str, bool)>,
    ) -> Option<Rect> {
        let p = pal();
        let row = Rect::new(x, y, w, self.p(18.0));
        let base = self.baseline(Font::Semi, size::CAPTION, row);
        self.caption_text(x + self.p(2.0), base, &caption.to_uppercase(), p.text_muted);
        let (label, hover) = action?;
        let aw = self.measure(Font::Regular, size::SMALL, label);
        let r = Rect::new(
            x + w - aw - self.p(2.0),
            y - self.p(2.0),
            aw + self.p(4.0),
            row.h + self.p(4.0),
        );
        let c = if hover { p.accent_hover } else { p.accent };
        self.text_center(Font::Regular, size::SMALL, r, label, c);
        Some(r)
    }

    // ---- Feedback -------------------------------------------------------

    /// A banner: tinted card with an icon, a title and a line of text.
    pub fn banner(&mut self, r: Rect, tone: Tone, icon: Icon, title: &str, text: &str) {
        let p = pal();
        let border = theme::mix(tone.subtle(), tone.color(), if p.dark { 70 } else { 60 });
        self.cv
            .round_border(r, radius::CARD * self.s, border, tone.subtle());
        let x = r.x + self.p(14.0);
        self.icon(icon, x, r.y + self.p(14.0), 18.0, tone.color());
        let tx = x + self.p(28.0);
        let tw = r.right() - tx - self.p(14.0);
        self.text(
            Font::Semi,
            size::BODY,
            tx,
            r.y + self.p(28.0),
            title,
            p.text,
            tw,
        );
        if !text.is_empty() {
            self.text(
                Font::Regular,
                size::SMALL,
                tx,
                r.y + self.p(47.0),
                text,
                p.text_secondary,
                tw,
            );
        }
    }

    /// An empty state centred in `r` from `y`: a tile with an icon, a
    /// title and wrapped text. Returns the y below it (for an action).
    pub fn empty_state(&mut self, r: Rect, y: i32, icon: Icon, title: &str, text: &str) -> i32 {
        let p = pal();
        let d = self.p(52.0);
        let tile = Rect::new(r.x + (r.w - d) / 2, y, d, d);
        self.cv
            .round_border(tile, 14.0 * self.s, p.border, p.surface_raised);
        self.icon_in(icon, tile, 24.0, p.accent);
        let mut y = tile.bottom() + self.p(30.0);
        let tw = r.w - self.p(32.0);
        let title_r = Rect::new(r.x + self.p(16.0), y - self.p(18.0), tw, self.p(24.0));
        self.text_center(Font::Semi, size::HEADING, title_r, title, p.text);
        y += self.p(22.0);
        y = self.paragraph(
            Font::Regular,
            size::SMALL + 0.5,
            r.x + self.p(16.0),
            y,
            tw,
            text,
            p.text_muted,
            true,
        );
        y
    }
}

/// A card: surface fill, 1 px border, card radius (no text engine needed).
pub fn card(cv: &mut Canvas, s: f32, r: Rect) {
    let p = pal();
    cv.round_border(r, radius::CARD * s, p.border, p.surface);
}

/// A card with rows of the given heights and dividers between them;
/// returns the row rectangles.
pub fn card_rows(cv: &mut Canvas, s: f32, x: i32, y: i32, w: i32, heights: &[i32]) -> Vec<Rect> {
    let total: i32 = heights.iter().sum();
    card(cv, s, Rect::new(x, y, w, total));
    let inset = (16.0 * s).round() as i32;
    let mut out = Vec::with_capacity(heights.len());
    let mut ry = y;
    for (i, &h) in heights.iter().enumerate() {
        if i > 0 {
            cv.fill(Rect::new(x + inset, ry, w - 2 * inset, 1), pal().divider);
        }
        out.push(Rect::new(x, ry, w, h));
        ry += h;
    }
    out
}

/// The width a button needs for its label and icon (physical px).
pub fn button_width(te: &mut TextEngine, f: &Fonts, s: f32, b: &Button) -> i32 {
    let p = |v: f32| (v * s).round() as i32;
    let font = if b.variant == Variant::Primary {
        f.semi
    } else {
        f.ui
    };
    let text = if b.label.is_empty() {
        0
    } else {
        te.measure(font, size::BODY * s, b.label).ceil() as i32
    };
    let icon = if b.icon.is_some() {
        p(16.0) + if text > 0 { p(7.0) } else { 0 }
    } else {
        0
    };
    let pad = if b.icon.is_some() && text > 0 {
        p(12.0) + p(14.0)
    } else if text == 0 {
        p(16.0)
    } else {
        2 * p(14.0)
    };
    text + icon + pad
}

/// One or two letters for an avatar: the initials of the first two words,
/// or the first two letters of a single word ("Office apps" -> "OA",
/// "Excel" -> "Ex").
pub fn monogram(name: &str) -> String {
    let all: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    // Words that start with a letter; a name of digits only (an IP
    // address) falls back to its first word.
    let lettered: Vec<&str> = all
        .iter()
        .copied()
        .filter(|w| w.starts_with(char::is_alphabetic))
        .collect();
    let words = if lettered.is_empty() {
        all.into_iter().take(1).collect()
    } else {
        lettered
    };
    match words.as_slice() {
        [] => "?".into(),
        [one] => {
            let mut c = one.chars();
            let first: String = c
                .next()
                .map(|c| c.to_uppercase().collect())
                .unwrap_or_default();
            let second: String = c
                .next()
                .map(|c| c.to_lowercase().collect())
                .unwrap_or_default();
            first + &second
        }
        [a, b, ..] => {
            let up = |w: &str| -> String {
                w.chars()
                    .next()
                    .map(|c| c.to_uppercase().collect())
                    .unwrap_or_default()
            };
            up(a) + &up(b)
        }
    }
}

/// A reference sheet of the kit (for `--snapshot-ui` look review): every
/// icon, button variant and state, pills, avatars, key caps, form controls
/// and a banner.
pub fn paint_sheet(cv: &mut Canvas, te: &mut TextEngine, f: &Fonts, s: f32) {
    let p = pal();
    let b = cv.bounds();
    cv.fill(b, p.bg);
    let mut k = Kit::new(cv, te, f, s);
    let x0 = k.p(32.0);
    let mut y = k.p(28.0);
    k.section(x0, y, k.p(600.0), "Icons", None);
    y += k.p(28.0);
    for (i, icon) in Icon::ALL.iter().enumerate() {
        let (col, row) = (i as i32 % 17, i as i32 / 17);
        let cell = Rect::new(
            x0 + col * k.p(40.0),
            y + row * k.p(40.0),
            k.p(34.0),
            k.p(34.0),
        );
        k.cv.round_border(cell, 6.0 * s, p.border, p.surface);
        k.icon_in(*icon, cell, 16.0, p.text);
    }
    y += 3 * k.p(40.0) + k.p(20.0);
    k.section(x0, y, k.p(600.0), "Buttons", None);
    y += k.p(28.0);
    let variants = [
        Button::primary("Connect").icon(Icon::Play),
        Button::secondary("Save"),
        Button::ghost("Settings").icon(Icon::Gear),
        Button::new("Disconnect and quit", Variant::Danger),
        Button::new("Delete", Variant::DangerGhost).icon(Icon::Trash),
        Button::secondary("Record")
            .icon(Icon::Record)
            .icon_color(p.danger),
    ];
    let states = [
        State::default(),
        State::hover(true),
        State {
            focus: true,
            ..State::default()
        },
        State {
            disabled: true,
            ..State::default()
        },
    ];
    for (row, st) in states.iter().enumerate() {
        let mut x = x0;
        for v in &variants {
            let w = k.button_width(v);
            let r = Rect::new(x, y + row as i32 * k.p(44.0), w, k.p(32.0));
            k.button(r, v, *st);
            x += w + k.p(12.0);
        }
        let r = Rect::new(x, y + row as i32 * k.p(44.0), k.p(32.0), k.p(32.0));
        k.icon_button(r, Icon::More, Variant::Ghost, *st);
        k.icon_button(
            Rect::new(r.right() + k.p(8.0), r.y, r.w, r.h),
            Icon::PanelRight,
            Variant::Secondary,
            *st,
        );
    }
    y += 4 * k.p(44.0) + k.p(12.0);
    k.section(
        x0,
        y,
        k.p(600.0),
        "Pills, avatars, keys",
        Some(("Action", false)),
    );
    y += k.p(28.0);
    let mut x = x0;
    for (text, tone, lead) in [
        ("Live", Tone::Success, Lead::Dot),
        ("Connecting", Tone::Warning, Lead::Dot),
        ("Failed", Tone::Danger, Lead::Dot),
        ("Saved password", Tone::Neutral, Lead::Icon(Icon::Key)),
        ("Gateway", Tone::Info, Lead::Icon(Icon::Globe)),
        ("Kerberos", Tone::Neutral, Lead::Icon(Icon::Shield)),
        ("Apps", Tone::Accent, Lead::Icon(Icon::Apps)),
    ] {
        x += k.pill(x, y, text, tone, lead) + k.p(8.0);
    }
    y += k.p(34.0);
    let mut x = x0;
    for (i, name) in ["Office workstation", "Build server", "Test VM", "Excel"]
        .iter()
        .enumerate()
    {
        let d = k.p(36.0);
        let status = [Some(p.success), Some(p.warning), None, Some(p.danger)][i];
        k.avatar(Rect::new(x, y, d, d), name, i * 2, status, p.bg);
        x += d + k.p(12.0);
    }
    for (i, c) in theme::GROUP_COLORS.iter().enumerate() {
        let d = k.p(22.0);
        k.avatar(Rect::new(x, y + k.p(7.0), d, d), c.0, i, None, p.bg);
        x += d + k.p(6.0);
    }
    k.hints(
        x + k.p(16.0),
        y + k.p(18.0),
        k.p(400.0),
        &[
            Hint::Keys("Enter"),
            Hint::Text("connects"),
            Hint::Keys("Ctrl+K"),
            Hint::Text("commands"),
        ],
    );
    y += k.p(56.0);
    k.section(x0, y, k.p(600.0), "Controls", None);
    y += k.p(28.0);
    let field = Rect::new(x0, y, k.p(260.0), k.p(32.0));
    let inner = k.field_frame(field, Some(Icon::Search), State::default());
    k.text_in(
        Font::Regular,
        13.0,
        inner,
        "Search connections",
        p.text_faint,
    );
    let field = Rect::new(field.right() + k.p(12.0), y, k.p(200.0), k.p(32.0));
    let inner = k.field_frame(
        field,
        None,
        State {
            focus: true,
            ..State::default()
        },
    );
    k.text_in(Font::Regular, 13.0, inner, "10.0.0.15", p.text);
    let sx = field.right() + k.p(20.0);
    k.switch(sx, y + k.p(6.0), true, State::default());
    k.switch(sx + k.p(48.0), y + k.p(6.0), false, State::default());
    k.radio(sx + k.p(110.0), y + k.p(16.0), true, State::default());
    k.radio(sx + k.p(140.0), y + k.p(16.0), false, State::default());
    y += k.p(48.0);
    let segs = [
        Segment {
            label: "General",
            icon: Some(Icon::Sliders),
            on: true,
            hover: false,
        },
        Segment {
            label: "Display",
            icon: Some(Icon::Monitor),
            on: false,
            hover: true,
        },
        Segment {
            label: "Sharing",
            icon: Some(Icon::Folder),
            on: false,
            hover: false,
        },
    ];
    k.segmented(Rect::new(x0, y, k.p(420.0), k.p(36.0)), &segs);
    y += k.p(52.0);
    k.banner(
        Rect::new(x0, y, k.p(420.0), k.p(62.0)),
        Tone::Warning,
        Icon::Warning,
        "Reconnect to apply",
        "Quality is fixed when the session logs on.",
    );
    let card = Rect::new(x0 + k.p(800.0), y - k.p(100.0), k.p(300.0), k.p(162.0));
    k.dialog(card);
    k.empty_state(
        card,
        card.y + k.p(16.0),
        Icon::Monitor,
        "No connections yet",
        "Add one with New connection.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monograms() {
        assert_eq!(monogram("Office workstation"), "OW");
        assert_eq!(monogram("Test VM (Windows 11)"), "TV");
        assert_eq!(monogram("build-01.lab.local"), "BL");
        assert_eq!(monogram("Excel"), "Ex");
        assert_eq!(monogram("10.0.0.15"), "10");
        assert_eq!(monogram(""), "?");
    }
}
