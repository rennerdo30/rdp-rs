//! A session spread over several monitors: one borderless window per chosen
//! monitor, each showing its own part of the remote desktop. Monitors that
//! were not chosen stay free, even when they sit between chosen ones.
//!
//! The session's framebuffer is the bounding box of the chosen monitors; a
//! window shows the rectangle at its monitor's offset in it and maps its
//! pointer back into it. The first window carries the session toolbar: the
//! same floating pill as the main window (see `ui::session_view`), hidden to
//! a small handle at the top centre until the pointer touches the top edge
//! or a tap on the handle opens it.
//!
//! RemoteApp windows (see `remoteapp`) are the same kind of window without
//! the bar: each shows its remote window's rectangle, which may start left
//! of or above the framebuffer (a window partly off the desktop).

use std::num::NonZeroU32;
use std::rc::Rc;

use ffwd_render::{Canvas, Rect, TextEngine};
use softbuffer::{Context, Surface};
use winit::window::Window;

use crate::icons::Icon;
use crate::theme::pal;
use crate::ui::Fonts;
use crate::ui::session_view::{self, Pill, Tool, ToolItem};

/// A monitor window to open (the event loop creates it).
pub struct SpanSpec {
    pub session: u64,
    /// The monitor on this PC's desktop: x, y, width, height (physical pixels).
    pub rect: (i32, i32, i32, i32),
    /// Where that monitor's picture starts in the session framebuffer.
    pub fb: (i32, i32),
    /// The first window shows the session bar.
    pub first: bool,
    pub title: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BarButton {
    /// Back into the main window.
    Exit,
    CtrlAltDel,
    Disconnect,
    /// The handle the hidden toolbar leaves (a tap opens it).
    Handle,
}

pub struct SpanWin {
    pub window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
    pub session: u64,
    pub fb: (i32, i32),
    pub size: (usize, usize),
    first: bool,
    title: String,
    /// The pointer is at the top: the toolbar shows.
    revealed: bool,
    /// Opened by a tap on its handle (until a tap on the picture).
    open: bool,
    pub cursor: (i32, i32),
    hover: Option<BarButton>,
    /// The toolbar's layout from the last present.
    pill: Option<Pill>,
    /// Part of the window to repaint for the toolbar alone.
    bar_dirty: Option<Rect>,
    /// The next present copies the whole picture.
    pub needs_full: bool,
}

fn union(a: Rect, b: Rect) -> Rect {
    if a.is_empty() {
        return b;
    }
    if b.is_empty() {
        return a;
    }
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    Rect::new(
        x,
        y,
        a.right().max(b.right()) - x,
        a.bottom().max(b.bottom()) - y,
    )
}

fn tool_button(t: Tool) -> Option<BarButton> {
    match t {
        Tool::Window => Some(BarButton::Exit),
        Tool::CtrlAltDel => Some(BarButton::CtrlAltDel),
        Tool::Disconnect => Some(BarButton::Disconnect),
        _ => None,
    }
}

fn button_tool(b: BarButton) -> Option<Tool> {
    match b {
        BarButton::Exit => Some(Tool::Window),
        BarButton::CtrlAltDel => Some(Tool::CtrlAltDel),
        BarButton::Disconnect => Some(Tool::Disconnect),
        BarButton::Handle => None,
    }
}

/// The toolbar of a spanned session's first window.
fn layout(te: &mut TextEngine, f: &Fonts, s: f32, w: usize, title: &str) -> Pill {
    let p = |v: f32| (v * s).round() as i32;
    let items = vec![
        ToolItem::new(Tool::Window, Icon::Monitor),
        ToolItem::new(Tool::CtrlAltDel, Icon::Keyboard),
        ToolItem::new(Tool::Disconnect, Icon::Power).danger(),
    ];
    session_view::pill_layout(
        te,
        f,
        s,
        w as i32 / 2,
        p(10.0),
        w as i32 - p(24.0),
        title,
        pal().success,
        None,
        items,
    )
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
/// on a window showing the framebuffer from `fb` (may be negative) at size
/// `size`, in that window's coordinates.
pub fn clip_damage(
    d: (usize, usize, usize, usize),
    fb: (i32, i32),
    size: (usize, usize),
) -> Option<(usize, usize, usize, usize)> {
    let (ox, oy) = (fb.0 as i64, fb.1 as i64);
    let x0 = (d.0 as i64).max(ox);
    let y0 = (d.1 as i64).max(oy);
    let x1 = (d.0 as i64 + d.2 as i64).min(ox + size.0 as i64);
    let y1 = (d.1 as i64 + d.3 as i64).min(oy + size.1 as i64);
    (x0 < x1 && y0 < y1).then(|| {
        (
            (x0 - ox) as usize,
            (y0 - oy) as usize,
            (x1 - x0) as usize,
            (y1 - y0) as usize,
        )
    })
}

/// Copies the framebuffer rectangle at `origin + (x0, y0)` of `cw` x `ch`
/// into `px` (a `w` pixels wide window picture) at (x0, y0); parts outside
/// the framebuffer become black.
#[allow(clippy::too_many_arguments)]
pub fn copy_from_fb(
    px: &mut [u32],
    w: usize,
    fb: &rdp::Framebuffer,
    origin: (i32, i32),
    x0: usize,
    y0: usize,
    cw: usize,
    ch: usize,
) {
    for row in 0..ch {
        let dst = (y0 + row) * w + x0;
        let line = &mut px[dst..dst + cw];
        let sy = origin.1 as i64 + (y0 + row) as i64;
        let sx = origin.0 as i64 + x0 as i64;
        // Source columns that exist: [a, b) of the line.
        let a = (-sx).clamp(0, cw as i64) as usize;
        let b = (fb.width as i64 - sx).clamp(0, cw as i64) as usize;
        if sy < 0 || sy >= fb.height as i64 || a >= b {
            line.fill(0);
            continue;
        }
        let s = sy as usize * fb.width + (sx + a as i64) as usize;
        line[..a].fill(0);
        line[a..b].copy_from_slice(&fb.pixels[s..s + (b - a)]);
        line[b..].fill(0);
    }
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
            open: false,
            cursor: (0, 0),
            hover: None,
            pill: None,
            bar_dirty: None,
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

    fn area(&self) -> Rect {
        Rect::new(0, 0, self.size.0 as i32, self.size.1 as i32)
    }

    /// The toolbar shows (otherwise only its handle).
    fn shown(&self) -> bool {
        self.revealed || self.open
    }

    /// What the toolbar covers now: the pill with its shadow, or the handle.
    fn bar_rect(&self) -> Option<Rect> {
        if !self.first {
            return None;
        }
        let s = self.scale();
        match &self.pill {
            Some(p) if self.shown() => Some(p.bounds(s)),
            _ => Some(session_view::handle_rects(s, self.area()).0),
        }
    }

    fn mark(&mut self, was: Option<Rect>) {
        let r = match (was, self.bar_rect()) {
            (Some(a), Some(b)) => union(a, b),
            (a, b) => a.or(b).unwrap_or_default(),
        };
        self.bar_dirty = Some(self.bar_dirty.map_or(r, |d| union(d, r)));
    }

    /// The pointer moved: the top edge (or the handle) shows the toolbar,
    /// leaving its neighbourhood hides it. True when the window must be
    /// redrawn (only the toolbar's part of it).
    pub fn pointer(&mut self, x: i32, y: i32) -> bool {
        self.cursor = (x, y);
        if !self.first {
            return false;
        }
        let s = self.scale();
        let p = |v: f32| (v * s).round() as i32;
        let handle = session_view::handle_rects(s, self.area()).1;
        let want = match (&self.pill, self.revealed) {
            (Some(pl), true) => {
                let r = pl.rect;
                Rect::new(r.x - p(40.0), 0, r.w + p(80.0), r.bottom() + p(28.0)).contains(x, y)
            }
            _ => (0..p(3.0).max(2)).contains(&y) || handle.contains(x, y),
        };
        let was = self.bar_rect();
        let changed_shown = want != self.revealed;
        self.revealed = want;
        let hover = self.button_at(x, y);
        if changed_shown || hover != self.hover {
            self.hover = hover;
            self.mark(was);
            return true;
        }
        false
    }

    /// A tap or click on the picture: a toolbar opened by its handle folds.
    pub fn picture_clicked(&mut self) -> bool {
        if self.open {
            let was = self.bar_rect();
            self.open = false;
            self.mark(was);
            return true;
        }
        false
    }

    /// The handle was tapped: the toolbar opens (or folds again).
    pub fn toggle_open(&mut self) {
        let was = self.bar_rect();
        self.open = !self.open;
        self.mark(was);
    }

    /// The point is on the toolbar or its handle (not the session's).
    pub fn over_bar(&self, x: i32, y: i32) -> bool {
        self.button_at(x, y).is_some()
            || self.shown() && self.pill.as_ref().is_some_and(|p| p.rect.contains(x, y))
    }

    /// The client rectangle (x, y, w, h) where touch reaches the session:
    /// the whole window, minus [`SpanWin::touch_holes`].
    pub fn touch_area(&self) -> (i32, i32, i32, i32) {
        (0, 0, self.size.0 as i32, self.size.1 as i32)
    }

    /// Where touch is left to the toolbar (a tap on the handle opens it).
    pub fn touch_holes(&self) -> Vec<(i32, i32, i32, i32)> {
        if !self.first {
            return Vec::new();
        }
        let r = match &self.pill {
            Some(p) if self.shown() => p.rect,
            _ => session_view::handle_rects(self.scale(), self.area()).1,
        };
        vec![(r.x, r.y, r.w, r.h)]
    }

    pub fn button_at(&self, x: i32, y: i32) -> Option<BarButton> {
        if !self.first {
            return None;
        }
        if self.shown() {
            let p = self.pill.as_ref()?;
            return p.tool_at(x, y).and_then(tool_button);
        }
        let handle = session_view::handle_rects(self.scale(), self.area()).1;
        handle.contains(x, y).then_some(BarButton::Handle)
    }

    /// The framebuffer position of a point in this window.
    pub fn to_session(&self, x: i32, y: i32, fb_size: (usize, usize)) -> (u16, u16) {
        let fx = (self.fb.0 + x).clamp(0, fb_size.0.saturating_sub(1) as i32);
        let fy = (self.fb.1 + y).clamp(0, fb_size.1.saturating_sub(1) as i32);
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
        let scale = self.scale();
        if self.first {
            self.pill = Some(layout(te, fonts, scale, w, &self.title));
        }
        let bar = self.bar_rect();
        let dirty = self.bar_dirty.take();
        let shown = self.shown();
        let pill = self.pill.clone();
        let hover = self.hover;
        let Ok(mut buf) = self.surface.buffer_mut() else {
            return;
        };
        let full = full || buf.age() == 0;
        let copy = |px: &mut [u32], x0: usize, y0: usize, cw: usize, ch: usize| {
            copy_from_fb(px, w, fb, (fx, fy), x0, y0, cw, ch)
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
        // The toolbar alone changed: the picture under it, then the toolbar.
        if let Some(d) = dirty.filter(|_| !full) {
            let d = d.intersect(Rect::new(0, 0, w as i32, h as i32));
            if !d.is_empty() {
                copy(
                    &mut buf,
                    d.x as usize,
                    d.y as usize,
                    d.w as usize,
                    d.h as usize,
                );
                rects.extend(sb(d.x as usize, d.y as usize, d.w as usize, d.h as usize));
            }
        }
        // The toolbar floats over the picture: paint it again where the
        // picture changed under it.
        if let (Some(bar), Some(pill)) = (bar, &pill) {
            for r in rects.clone() {
                let r = Rect::new(
                    r.x as i32,
                    r.y as i32,
                    r.width.get() as i32,
                    r.height.get() as i32,
                );
                let d = r.intersect(bar);
                if !d.is_empty() {
                    let mut cv = Canvas::new(&mut buf, w, h);
                    cv.set_clip(d);
                    paint_bar(&mut cv, scale, pill, shown, hover, te, fonts);
                }
            }
        }
        if rects.is_empty() {
            return;
        }
        let _ = buf.present_with_damage(&rects);
    }
}

/// The toolbar of the first monitor window: the pill, or its handle.
fn paint_bar(
    cv: &mut Canvas,
    s: f32,
    pill: &Pill,
    shown: bool,
    hover: Option<BarButton>,
    te: &mut TextEngine,
    f: &Fonts,
) {
    if shown {
        let tool = hover.and_then(button_tool);
        session_view::paint_pill(cv, te, f, s, pill, tool, None, None);
    } else {
        let area = Rect::new(0, 0, cv.width() as i32, cv.height() as i32);
        let tab = session_view::handle_rects(s, area).0;
        session_view::paint_handle(cv, s, tab, hover == Some(BarButton::Handle));
    }
}

/// For `--snapshot-ui`: a monitor window of a spanned session, a stand-in
/// picture with the toolbar shown or hidden to its handle.
#[allow(clippy::too_many_arguments)]
pub fn paint_sample(
    px: &mut [u32],
    w: usize,
    h: usize,
    s: f32,
    title: &str,
    shown: bool,
    te: &mut TextEngine,
    f: &Fonts,
) {
    let mut cv = Canvas::new(px, w, h);
    session_view::paint_sample_picture(
        &mut cv,
        Rect::new(0, 0, w as i32, h as i32),
        session_view::SAMPLE_TINT,
        Some((&mut *te, f)),
    );
    let pill = layout(te, f, s, w, title);
    paint_bar(&mut cv, s, &pill, shown, None, te, f);
}

#[cfg(test)]
mod tests {
    use super::{clip_damage, copy_from_fb};

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

    #[test]
    fn damage_on_a_window_partly_off_the_desktop() {
        // A RemoteApp window 100 x 50 whose picture starts at (-30, -10).
        let (o, size) = ((-30, -10), (100, 50));
        assert_eq!(clip_damage((0, 0, 10, 10), o, size), Some((30, 10, 10, 10)));
        assert_eq!(
            clip_damage((60, 30, 50, 50), o, size),
            Some((90, 40, 10, 10))
        );
        assert_eq!(clip_damage((70, 0, 5, 5), o, size), None, "right of it");
        assert_eq!(clip_damage((0, 40, 5, 5), o, size), None, "below it");
    }

    #[test]
    fn copy_fills_what_the_framebuffer_lacks_with_black() {
        let mut fb = rdp::Framebuffer::new(4, 2);
        for (i, p) in fb.pixels.iter_mut().enumerate() {
            *p = i as u32 + 1;
        }
        // A 3 x 2 window starting one pixel left of and above the framebuffer.
        let mut px = vec![9u32; 6];
        copy_from_fb(&mut px, 3, &fb, (-1, -1), 0, 0, 3, 2);
        assert_eq!(px, [0, 0, 0, 0, 1, 2]);
        // Off the right edge.
        let mut px = vec![9u32; 6];
        copy_from_fb(&mut px, 3, &fb, (2, 0), 0, 0, 3, 2);
        assert_eq!(px, [3, 4, 0, 7, 8, 0]);
        // Only a damaged part is written.
        let mut px = vec![9u32; 6];
        copy_from_fb(&mut px, 3, &fb, (0, 0), 1, 1, 1, 1);
        assert_eq!(px, [9, 9, 9, 9, 6, 9]);
    }
}
