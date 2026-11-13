//! A session spread over several monitors: one borderless window per chosen
//! monitor, each showing its own part of the remote desktop. Monitors that
//! were not chosen stay free, even when they sit between chosen ones.
//!
//! The session's framebuffer is the bounding box of the chosen monitors; a
//! window shows the rectangle at its monitor's offset in it and maps its
//! pointer back into it. The first window carries the session bar, which
//! hides and shows at the top edge.

use std::num::NonZeroU32;
use std::rc::Rc;

use ffwd_render::{Canvas, Rect, TextEngine};
use softbuffer::{Context, Surface};
use winit::window::Window;

use crate::theme::*;
use crate::ui::Fonts;

/// A monitor window to open (the event loop creates it).
pub struct SpanSpec {
    pub session: u64,
    /// The monitor on this PC's desktop: x, y, width, height (physical pixels).
    pub rect: (i32, i32, i32, i32),
    /// Where that monitor's picture starts in the session framebuffer.
    pub fb: (usize, usize),
    /// The first window shows the session bar.
    pub first: bool,
    pub title: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BarButton {
    Exit,
    Disconnect,
}

pub struct SpanWin {
    pub window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
    pub session: u64,
    pub fb: (usize, usize),
    pub size: (usize, usize),
    first: bool,
    title: String,
    revealed: bool,
    pub cursor: (i32, i32),
    hover: Option<BarButton>,
    buttons: Vec<(Rect, BarButton)>,
    /// The next present copies the whole picture.
    pub needs_full: bool,
}

fn sb(x: usize, y: usize, w: usize, h: usize) -> Option<softbuffer::Rect> {
    Some(softbuffer::Rect {
        x: x as u32,
        y: y as u32,
        width: NonZeroU32::new(w as u32)?,
        height: NonZeroU32::new(h as u32)?,
    })
}

/// The part of a damaged rectangle `d` (framebuffer coordinates) that falls
/// on a monitor at `fb` of size `size`, in that monitor's coordinates.
pub fn clip_damage(
    d: (usize, usize, usize, usize),
    fb: (usize, usize),
    size: (usize, usize),
) -> Option<(usize, usize, usize, usize)> {
    let x0 = d.0.max(fb.0);
    let y0 = d.1.max(fb.1);
    let x1 = (d.0 + d.2).min(fb.0 + size.0);
    let y1 = (d.1 + d.3).min(fb.1 + size.1);
    (x0 < x1 && y0 < y1).then(|| (x0 - fb.0, y0 - fb.1, x1 - x0, y1 - y0))
}

impl SpanWin {
    pub fn new(window: Rc<Window>, spec: SpanSpec) -> Result<SpanWin, String> {
        let ctx = Context::new(window.clone()).map_err(|e| e.to_string())?;
        let mut surface = Surface::new(&ctx, window.clone()).map_err(|e| e.to_string())?;
        let size = window.inner_size();
        if let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) {
            let _ = surface.resize(w, h);
        }
        Ok(SpanWin {
            window,
            surface,
            session: spec.session,
            fb: spec.fb,
            size: (size.width as usize, size.height as usize),
            first: spec.first,
            title: spec.title,
            revealed: false,
            cursor: (0, 0),
            hover: None,
            buttons: Vec::new(),
            needs_full: true,
        })
    }

    pub fn resized(&mut self, w: u32, h: u32) {
        if let (Some(nw), Some(nh)) = (NonZeroU32::new(w), NonZeroU32::new(h)) {
            let _ = self.surface.resize(nw, nh);
        }
        self.size = (w as usize, h as usize);
        self.needs_full = true;
    }

    fn scale(&self) -> f32 {
        self.window.scale_factor() as f32
    }

    fn bar_h(&self) -> i32 {
        (40.0 * self.scale()).round() as i32
    }

    /// The pointer moved: the top edge shows the bar, leaving it hides it.
    /// True when the window must be redrawn.
    pub fn pointer(&mut self, x: i32, y: i32) -> bool {
        self.cursor = (x, y);
        if !self.first {
            return false;
        }
        let bh = self.bar_h();
        let want = if self.revealed {
            y >= 0 && y < bh + (12.0 * self.scale()) as i32
        } else {
            (0..=2).contains(&y)
        };
        let hover = if want { self.button_at(x, y) } else { None };
        let changed = want != self.revealed || hover != self.hover;
        if changed {
            self.revealed = want;
            self.hover = hover;
            self.needs_full = true;
        }
        changed
    }

    /// The pointer is over the revealed bar (it does not reach the session).
    pub fn over_bar(&self, y: i32) -> bool {
        self.first && self.revealed && y < self.bar_h()
    }

    pub fn button_at(&self, x: i32, y: i32) -> Option<BarButton> {
        self.buttons
            .iter()
            .find(|(r, _)| r.contains(x, y))
            .map(|(_, b)| *b)
    }

    /// The framebuffer position of a point in this window.
    pub fn to_session(&self, x: i32, y: i32, fb_size: (usize, usize)) -> (u16, u16) {
        let fx = (self.fb.0 as i32 + x).clamp(0, fb_size.0.saturating_sub(1) as i32);
        let fy = (self.fb.1 as i32 + y).clamp(0, fb_size.1.saturating_sub(1) as i32);
        (fx as u16, fy as u16)
    }

    /// Copies this monitor's part of the session picture (all of it, or
    /// what `damage` touched) and presents it.
    pub fn present(
        &mut self,
        fb: &rdp::Framebuffer,
        damage: &[rdp::Damage],
        te: &mut TextEngine,
        fonts: &Fonts,
    ) {
        let (w, h) = self.size;
        if w == 0 || h == 0 {
            return;
        }
        let full = std::mem::take(&mut self.needs_full);
        let (fx, fy) = self.fb;
        let bar = self.first && self.revealed;
        let bar_h = self.bar_h().max(0) as usize;
        let scale = self.scale();
        let title = self.title.clone();
        let hover = self.hover;
        let Ok(mut buf) = self.surface.buffer_mut() else {
            return;
        };
        let full = full || buf.age() == 0;
        let copy = |px: &mut [u32], x0: usize, y0: usize, cw: usize, ch: usize| {
            for row in 0..ch {
                let dst = (y0 + row) * w + x0;
                let (sy, sx) = (fy + y0 + row, fx + x0);
                if sy < fb.height && sx < fb.width {
                    let n = cw.min(fb.width - sx);
                    let s = sy * fb.width + sx;
                    px[dst..dst + n].copy_from_slice(&fb.pixels[s..s + n]);
                    px[dst + n..dst + cw].fill(0);
                } else {
                    px[dst..dst + cw].fill(0);
                }
            }
        };
        let mut rects = Vec::new();
        if full {
            copy(&mut buf, 0, 0, w, h);
            rects.extend(sb(0, 0, w, h));
        } else {
            for d in damage {
                if let Some((x, y, cw, ch)) = clip_damage((d.x, d.y, d.w, d.h), (fx, fy), (w, h)) {
                    copy(&mut buf, x, y, cw, ch);
                    rects.extend(sb(x, y, cw, ch));
                }
            }
        }
        let mut buttons = Vec::new();
        if bar && !rects.is_empty() || bar && full {
            buttons = paint_bar(&mut buf, w, h, scale, &title, hover, te, fonts);
            rects.extend(sb(0, 0, w, bar_h.min(h)));
        }
        if rects.is_empty() {
            return;
        }
        let _ = buf.present_with_damage(&rects);
        if bar {
            self.buttons = buttons;
        }
    }
}

/// The session bar over the top of the first monitor: the connection's name,
/// Exit full screen and Disconnect. Returns the buttons' rectangles.
#[allow(clippy::too_many_arguments)]
fn paint_bar(
    px: &mut [u32],
    w: usize,
    h: usize,
    s: f32,
    title: &str,
    hover: Option<BarButton>,
    te: &mut TextEngine,
    f: &Fonts,
) -> Vec<(Rect, BarButton)> {
    let p = |v: f32| (v * s).round() as i32;
    let mut cv = Canvas::new(px, w, h);
    let bh = p(40.0);
    cv.fill(Rect::new(0, 0, w as i32, bh), BG_BAR);
    cv.fill(Rect::new(0, bh - 1, w as i32, 1), BORDER_SOFT);
    te.draw_in(
        &mut cv,
        f.ui,
        12.5 * s,
        Rect::new(p(14.0), 0, w as i32 / 2, bh),
        0.0,
        title,
        TEXT_2,
    );
    let mut out = Vec::new();
    let mut x = w as i32 - p(8.0);
    for (text, button) in [
        ("Disconnect", BarButton::Disconnect),
        ("Exit full screen", BarButton::Exit),
    ] {
        let tw = te.measure(f.ui, 13.0 * s, text) as i32;
        let bw = tw + p(26.0);
        x -= bw;
        let r = Rect::new(x, p(6.0), bw, bh - p(12.0));
        let fill = if hover == Some(button) {
            CONTROL_HOVER
        } else {
            BG_INPUT
        };
        let border = if button == BarButton::Disconnect {
            DANGER_BORDER
        } else {
            BORDER
        };
        cv.round_border(r, 6.0 * s, border, fill);
        let color = if button == BarButton::Disconnect {
            ERR
        } else {
            TEXT
        };
        te.draw_in(
            &mut cv,
            f.ui,
            13.0 * s,
            r,
            ((r.w - tw) / 2) as f32,
            text,
            color,
        );
        out.push((r, button));
        x -= p(6.0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::clip_damage;

    #[test]
    fn damage_lands_on_the_right_monitor() {
        // Two monitors side by side in the framebuffer: 0..1920 and 1920..4480.
        let left = ((0, 0), (1920, 1080));
        let right = ((1920, 0), (2560, 1440));
        // A rectangle across the seam is split between them.
        let d = (1900, 100, 40, 10);
        assert_eq!(clip_damage(d, left.0, left.1), Some((1900, 100, 20, 10)));
        assert_eq!(clip_damage(d, right.0, right.1), Some((0, 100, 20, 10)));
        // Below the shorter monitor: only the taller one gets it.
        assert_eq!(clip_damage((10, 1200, 5, 5), left.0, left.1), None);
        assert_eq!(
            clip_damage((2000, 1200, 5, 5), right.0, right.1),
            Some((80, 1200, 5, 5))
        );
    }
}
