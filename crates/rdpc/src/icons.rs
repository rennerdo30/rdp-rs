//! rdpc's icon set: vector glyphs drawn with the canvas' anti-aliased
//! strokes and fills, so they stay crisp at every scale.
//!
//! Every icon is designed on a 16 x 16 grid with a 1.5 unit stroke and
//! round ends, kept inside the grid's 1..15 band so the stroke never leaves
//! the box. [`draw`] maps the grid onto any square: `size` is the side in
//! physical pixels (16 x the UI scale for the regular size).

use ffwd_render::Canvas;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Plus,
    Search,
    Gear,
    /// Connect, start.
    Play,
    Stop,
    /// Disconnect.
    Power,
    Edit,
    Trash,
    Folder,
    FolderOpen,
    Monitor,
    Monitors,
    Fullscreen,
    ExitFullscreen,
    /// RemoteApp programs.
    Apps,
    Window,
    Clipboard,
    Speaker,
    Mic,
    Printer,
    SmartCard,
    Lock,
    Unlock,
    Key,
    Shield,
    ShieldCheck,
    ShieldAlert,
    /// RD Gateway.
    Globe,
    /// Link quality bars.
    Network,
    Record,
    ChevronDown,
    ChevronRight,
    Close,
    More,
    Pin,
    Star,
    Refresh,
    Warning,
    Info,
    Check,
    Sun,
    Moon,
    /// Theme follows Windows: half sun, half moon.
    Contrast,
    Keyboard,
    User,
    Home,
    /// Quality settings.
    Sliders,
    /// The side panel.
    PanelRight,
    Download,
}

impl Icon {
    pub const ALL: [Icon; 49] = [
        Icon::Plus,
        Icon::Search,
        Icon::Gear,
        Icon::Play,
        Icon::Stop,
        Icon::Power,
        Icon::Edit,
        Icon::Trash,
        Icon::Folder,
        Icon::FolderOpen,
        Icon::Monitor,
        Icon::Monitors,
        Icon::Fullscreen,
        Icon::ExitFullscreen,
        Icon::Apps,
        Icon::Window,
        Icon::Clipboard,
        Icon::Speaker,
        Icon::Mic,
        Icon::Printer,
        Icon::SmartCard,
        Icon::Lock,
        Icon::Unlock,
        Icon::Key,
        Icon::Shield,
        Icon::ShieldCheck,
        Icon::ShieldAlert,
        Icon::Globe,
        Icon::Network,
        Icon::Record,
        Icon::ChevronDown,
        Icon::ChevronRight,
        Icon::Close,
        Icon::More,
        Icon::Pin,
        Icon::Star,
        Icon::Refresh,
        Icon::Warning,
        Icon::Info,
        Icon::Check,
        Icon::Sun,
        Icon::Moon,
        Icon::Contrast,
        Icon::Keyboard,
        Icon::User,
        Icon::Home,
        Icon::Sliders,
        Icon::PanelRight,
        Icon::Download,
    ];
}

/// Maps the 16-unit grid onto the target square.
struct Pen<'a, 'b> {
    cv: &'a mut Canvas<'b>,
    x: f32,
    y: f32,
    k: f32,
    w: f32,
    color: u32,
}

impl Pen<'_, '_> {
    fn pt(&self, (x, y): (f32, f32)) -> (f32, f32) {
        (self.x + x * self.k, self.y + y * self.k)
    }

    /// An open polyline.
    fn line(&mut self, pts: &[(f32, f32)]) {
        let pts: Vec<(f32, f32)> = pts.iter().map(|&p| self.pt(p)).collect();
        self.cv.stroke(&pts, self.w, self.color);
    }

    /// A closed outline.
    fn shape(&mut self, pts: &[(f32, f32)]) {
        let mut v: Vec<(f32, f32)> = pts.iter().map(|&p| self.pt(p)).collect();
        if let Some(&first) = v.first() {
            v.push(first);
        }
        self.cv.stroke(&v, self.w, self.color);
    }

    fn fill_tri(&mut self, a: (f32, f32), b: (f32, f32), c: (f32, f32)) {
        let (a, b, c) = (self.pt(a), self.pt(b), self.pt(c));
        self.cv.fill_triangle(a, b, c, self.color);
    }

    fn dot(&mut self, c: (f32, f32), r: f32) {
        let (x, y) = self.pt(c);
        self.cv.fill_circle(x, y, r * self.k, self.color);
    }

    fn circle(&mut self, c: (f32, f32), r: f32) {
        let (x, y) = self.pt(c);
        // `ring` takes the outer radius.
        self.cv.ring(x, y, r * self.k + self.w / 2.0, self.w, self.color);
    }

    /// Arc points from `a0` to `a1` degrees (0 = right, 90 = down).
    fn arc_pts(c: (f32, f32), rx: f32, ry: f32, a0: f32, a1: f32) -> Vec<(f32, f32)> {
        let n = (((a1 - a0).abs() / 10.0).ceil() as usize).max(4);
        (0..=n)
            .map(|i| {
                let a = (a0 + (a1 - a0) * i as f32 / n as f32).to_radians();
                (c.0 + rx * a.cos(), c.1 + ry * a.sin())
            })
            .collect()
    }

    fn arc(&mut self, c: (f32, f32), r: f32, a0: f32, a1: f32) {
        self.line(&Self::arc_pts(c, r, r, a0, a1));
    }

    /// Rounded rectangle outline (grid units).
    fn rrect(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32) {
        let mut v = Vec::new();
        v.extend(Self::arc_pts((x + w - r, y + r), r, r, -90.0, 0.0));
        v.extend(Self::arc_pts((x + w - r, y + h - r), r, r, 0.0, 90.0));
        v.extend(Self::arc_pts((x + r, y + h - r), r, r, 90.0, 180.0));
        v.extend(Self::arc_pts((x + r, y + r), r, r, 180.0, 270.0));
        self.shape(&v);
    }

    fn fill_rrect(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32) {
        let (px, py) = self.pt((x, y));
        let rect = ffwd_render::Rect::new(
            px.round() as i32,
            py.round() as i32,
            (w * self.k).round() as i32,
            (h * self.k).round() as i32,
        );
        self.cv.fill_round(rect, r * self.k, self.color);
    }
}

/// Draws `icon` in the square at (`x`, `y`) with side `size` (physical px).
pub fn draw(cv: &mut Canvas, icon: Icon, x: f32, y: f32, size: f32, color: u32) {
    let k = size / 16.0;
    let mut p = Pen {
        cv,
        x,
        y,
        k,
        w: (1.5 * k).max(1.0),
        color,
    };
    match icon {
        Icon::Plus => {
            p.line(&[(8.0, 3.0), (8.0, 13.0)]);
            p.line(&[(3.0, 8.0), (13.0, 8.0)]);
        }
        Icon::Close => {
            p.line(&[(4.0, 4.0), (12.0, 12.0)]);
            p.line(&[(4.0, 12.0), (12.0, 4.0)]);
        }
        Icon::Check => p.line(&[(3.5, 8.5), (6.5, 11.5), (12.5, 4.5)]),
        Icon::ChevronDown => p.line(&[(4.0, 6.0), (8.0, 10.0), (12.0, 6.0)]),
        Icon::ChevronRight => p.line(&[(6.0, 4.0), (10.0, 8.0), (6.0, 12.0)]),
        Icon::Search => {
            p.circle((7.0, 7.0), 4.3);
            p.line(&[(10.3, 10.3), (13.5, 13.5)]);
        }
        Icon::Gear => {
            p.circle((8.0, 8.0), 2.0);
            p.circle((8.0, 8.0), 4.6);
            let w = p.w;
            p.w = w * 1.7;
            for i in 0..8 {
                let a = (i as f32 * 45.0).to_radians();
                let (c, s) = (a.cos(), a.sin());
                p.line(&[(8.0 + 5.2 * c, 8.0 + 5.2 * s), (8.0 + 6.1 * c, 8.0 + 6.1 * s)]);
            }
            p.w = w;
        }
        Icon::Play => p.fill_tri((4.5, 2.8), (13.2, 8.0), (4.5, 13.2)),
        Icon::Stop => p.fill_rrect(3.5, 3.5, 9.0, 9.0, 1.8),
        Icon::Power => {
            p.arc((8.0, 8.6), 5.2, -55.0, 235.0);
            p.line(&[(8.0, 2.0), (8.0, 7.5)]);
        }
        Icon::Edit => {
            p.shape(&[
                (10.6, 2.6),
                (13.4, 5.4),
                (6.2, 12.6),
                (2.6, 13.4),
                (3.4, 9.8),
            ]);
            p.line(&[(9.0, 4.2), (11.8, 7.0)]);
        }
        Icon::Trash => {
            p.line(&[(2.8, 4.5), (13.2, 4.5)]);
            p.line(&[(6.2, 4.5), (6.2, 2.6), (9.8, 2.6), (9.8, 4.5)]);
            p.line(&[(4.3, 4.5), (5.0, 13.4), (11.0, 13.4), (11.7, 4.5)]);
            p.line(&[(6.9, 7.2), (6.9, 10.8)]);
            p.line(&[(9.1, 7.2), (9.1, 10.8)]);
        }
        Icon::Folder => p.shape(&[
            (2.0, 4.0),
            (6.0, 4.0),
            (7.6, 5.8),
            (14.0, 5.8),
            (14.0, 12.8),
            (2.0, 12.8),
        ]),
        Icon::FolderOpen => {
            p.line(&[
                (2.0, 12.6),
                (2.0, 4.0),
                (6.0, 4.0),
                (7.6, 5.8),
                (12.2, 5.8),
                (12.2, 7.6),
            ]);
            p.shape(&[(2.0, 12.6), (4.2, 7.6), (14.4, 7.6), (12.4, 12.6)]);
        }
        Icon::Monitor => {
            p.rrect(1.8, 2.6, 12.4, 8.6, 1.5);
            p.line(&[(8.0, 11.2), (8.0, 13.4)]);
            p.line(&[(5.0, 13.4), (11.0, 13.4)]);
        }
        Icon::Monitors => {
            p.rrect(1.2, 3.4, 6.4, 5.4, 1.2);
            p.rrect(8.4, 3.4, 6.4, 5.4, 1.2);
            p.line(&[(4.4, 8.8), (4.4, 11.0)]);
            p.line(&[(11.6, 8.8), (11.6, 11.0)]);
            p.line(&[(2.6, 12.4), (13.4, 12.4)]);
        }
        Icon::Fullscreen => {
            p.line(&[(2.5, 6.0), (2.5, 2.5), (6.0, 2.5)]);
            p.line(&[(10.0, 2.5), (13.5, 2.5), (13.5, 6.0)]);
            p.line(&[(13.5, 10.0), (13.5, 13.5), (10.0, 13.5)]);
            p.line(&[(6.0, 13.5), (2.5, 13.5), (2.5, 10.0)]);
        }
        Icon::ExitFullscreen => {
            p.line(&[(6.0, 2.5), (6.0, 6.0), (2.5, 6.0)]);
            p.line(&[(10.0, 2.5), (10.0, 6.0), (13.5, 6.0)]);
            p.line(&[(13.5, 10.0), (10.0, 10.0), (10.0, 13.5)]);
            p.line(&[(2.5, 10.0), (6.0, 10.0), (6.0, 13.5)]);
        }
        Icon::Apps => {
            for (x, y) in [(2.2, 2.2), (9.0, 2.2), (2.2, 9.0), (9.0, 9.0)] {
                p.rrect(x, y, 4.8, 4.8, 1.3);
            }
        }
        Icon::Window => {
            p.rrect(1.8, 2.6, 12.4, 10.8, 1.6);
            p.line(&[(1.8, 5.9), (14.2, 5.9)]);
        }
        Icon::Clipboard => {
            p.rrect(3.2, 3.2, 9.6, 10.8, 1.6);
            p.rrect(5.8, 1.6, 4.4, 3.0, 1.0);
            p.line(&[(5.8, 8.6), (10.2, 8.6)]);
            p.line(&[(5.8, 11.0), (8.6, 11.0)]);
        }
        Icon::Speaker => {
            p.shape(&[
                (2.2, 6.0),
                (4.8, 6.0),
                (8.2, 3.0),
                (8.2, 13.0),
                (4.8, 10.0),
                (2.2, 10.0),
            ]);
            p.arc((8.2, 8.0), 2.6, -50.0, 50.0);
            p.arc((8.2, 8.0), 5.2, -52.0, 52.0);
        }
        Icon::Mic => {
            p.rrect(5.8, 1.6, 4.4, 7.6, 2.2);
            p.arc((8.0, 7.0), 4.4, 0.0, 180.0);
            p.line(&[(8.0, 11.4), (8.0, 14.0)]);
            p.line(&[(5.6, 14.0), (10.4, 14.0)]);
        }
        Icon::Printer => {
            p.line(&[(4.6, 5.8), (4.6, 2.2), (11.4, 2.2), (11.4, 5.8)]);
            p.line(&[
                (4.6, 11.4),
                (2.0, 11.4),
                (2.0, 5.8),
                (14.0, 5.8),
                (14.0, 11.4),
                (11.4, 11.4),
            ]);
            p.shape(&[(4.6, 9.2), (11.4, 9.2), (11.4, 14.0), (4.6, 14.0)]);
        }
        Icon::SmartCard => {
            p.rrect(1.6, 3.4, 12.8, 9.2, 1.6);
            p.rrect(3.8, 5.8, 3.6, 3.0, 0.8);
            p.line(&[(9.6, 10.4), (12.2, 10.4)]);
        }
        Icon::Lock => {
            p.rrect(3.2, 7.0, 9.6, 7.0, 1.6);
            p.line(&[(5.2, 7.0), (5.2, 5.0)]);
            p.arc((8.0, 5.0), 2.8, 180.0, 360.0);
            p.line(&[(10.8, 5.0), (10.8, 7.0)]);
            p.dot((8.0, 10.5), 1.1);
        }
        Icon::Unlock => {
            p.rrect(3.2, 7.0, 9.6, 7.0, 1.6);
            p.line(&[(5.2, 7.0), (5.2, 4.6)]);
            p.arc((8.0, 4.6), 2.8, 180.0, 330.0);
            p.dot((8.0, 10.5), 1.1);
        }
        Icon::Key => {
            p.circle((5.4, 10.6), 2.9);
            p.line(&[(7.5, 8.5), (13.4, 2.6)]);
            p.line(&[(11.2, 4.8), (12.9, 6.5)]);
            p.line(&[(9.5, 6.5), (10.8, 7.8)]);
        }
        Icon::Shield | Icon::ShieldCheck | Icon::ShieldAlert => {
            p.shape(&[
                (8.0, 1.8),
                (13.2, 3.8),
                (13.2, 7.8),
                (12.0, 10.8),
                (8.0, 14.2),
                (4.0, 10.8),
                (2.8, 7.8),
                (2.8, 3.8),
            ]);
            if icon == Icon::ShieldCheck {
                p.line(&[(5.6, 8.0), (7.3, 9.7), (10.6, 6.2)]);
            } else if icon == Icon::ShieldAlert {
                p.line(&[(8.0, 5.0), (8.0, 8.4)]);
                p.dot((8.0, 10.8), 1.0);
            }
        }
        Icon::Globe => {
            p.circle((8.0, 8.0), 6.0);
            p.line(&[(2.2, 8.0), (13.8, 8.0)]);
            let e = Pen::arc_pts((8.0, 8.0), 2.6, 6.0, 0.0, 360.0);
            p.line(&e);
        }
        Icon::Network => {
            p.fill_rrect(2.0, 9.6, 2.6, 4.0, 0.8);
            p.fill_rrect(6.7, 6.4, 2.6, 7.2, 0.8);
            p.fill_rrect(11.4, 2.6, 2.6, 11.0, 0.8);
        }
        Icon::Record => {
            p.circle((8.0, 8.0), 6.0);
            p.dot((8.0, 8.0), 3.4);
        }
        Icon::More => {
            for x in [3.6, 8.0, 12.4] {
                p.dot((x, 8.0), 1.35);
            }
        }
        Icon::Pin => {
            p.shape(&[
                (5.6, 2.2),
                (10.4, 2.2),
                (9.6, 6.2),
                (12.2, 9.4),
                (3.8, 9.4),
                (6.4, 6.2),
            ]);
            p.line(&[(8.0, 9.4), (8.0, 14.2)]);
        }
        Icon::Star => {
            let pts: Vec<(f32, f32)> = (0..10)
                .map(|i| {
                    let r = if i % 2 == 0 { 6.2 } else { 2.7 };
                    let a = (-90.0 + i as f32 * 36.0f32).to_radians();
                    (8.0 + r * a.cos(), 8.6 + r * a.sin())
                })
                .collect();
            p.shape(&pts);
        }
        Icon::Refresh => {
            p.arc((8.0, 8.0), 5.2, -40.0, 250.0);
            // Arrow head at the start of the arc (upper right).
            let a = (-40.0f32).to_radians();
            let (ex, ey) = (8.0 + 5.2 * a.cos(), 8.0 + 5.2 * a.sin());
            p.line(&[(ex - 3.2, ey - 0.6), (ex, ey), (ex + 0.4, ey - 3.2)]);
        }
        Icon::Warning => {
            p.shape(&[(8.0, 2.2), (14.2, 13.2), (1.8, 13.2)]);
            p.line(&[(8.0, 6.4), (8.0, 9.2)]);
            p.dot((8.0, 11.2), 0.95);
        }
        Icon::Info => {
            p.circle((8.0, 8.0), 6.0);
            p.line(&[(8.0, 7.4), (8.0, 11.2)]);
            p.dot((8.0, 5.0), 0.95);
        }
        Icon::Sun => {
            p.circle((8.0, 8.0), 2.8);
            for i in 0..8 {
                let a = (i as f32 * 45.0).to_radians();
                let (c, s) = (a.cos(), a.sin());
                p.line(&[(8.0 + 4.8 * c, 8.0 + 4.8 * s), (8.0 + 6.2 * c, 8.0 + 6.2 * s)]);
            }
        }
        Icon::Moon => {
            let mut v = Pen::arc_pts((8.0, 8.0), 5.8, 5.8, 45.0, 315.0);
            // Inner edge: a smaller circle to the right, back to the start.
            let (cx, cy) = (13.4, 8.0);
            let r = ((12.1f32 - cx).powi(2) + (3.9f32 - cy).powi(2)).sqrt();
            let a0 = (3.9f32 - cy).atan2(12.1 - cx).to_degrees();
            let a1 = (12.1f32 - cy).atan2(12.1 - cx).to_degrees();
            v.extend(Pen::arc_pts((cx, cy), r, r, a0 + 360.0, a1).into_iter().skip(1));
            p.shape(&v);
        }
        Icon::Contrast => {
            p.circle((8.0, 8.0), 6.0);
            // The right half filled with strokes (no polygon fill).
            for i in 0..12 {
                let y = 2.5 + i as f32;
                let dx = (36.0f32 - (y - 8.0).powi(2)).max(0.0).sqrt();
                p.line(&[(8.0, y), (8.0 + dx, y)]);
            }
        }
        Icon::Keyboard => {
            p.rrect(1.4, 3.6, 13.2, 8.8, 1.6);
            for x in [4.2, 6.6, 9.0, 11.4] {
                p.dot((x, 6.6), 0.75);
            }
            p.dot((4.2, 9.4), 0.75);
            p.dot((11.4, 9.4), 0.75);
            p.line(&[(6.4, 9.4), (9.6, 9.4)]);
        }
        Icon::User => {
            p.circle((8.0, 5.4), 2.8);
            p.arc((8.0, 14.6), 5.6, 200.0, 340.0);
        }
        Icon::Home => {
            p.line(&[(2.2, 8.0), (8.0, 2.6), (13.8, 8.0)]);
            p.line(&[(3.8, 6.6), (3.8, 13.6), (12.2, 13.6), (12.2, 6.6)]);
            p.line(&[(6.8, 13.6), (6.8, 10.0), (9.2, 10.0), (9.2, 13.6)]);
        }
        Icon::Sliders => {
            for (y, knob) in [(4.0, 10.4), (8.0, 5.4), (12.0, 9.0)] {
                p.line(&[(2.2, y), (13.8, y)]);
                p.dot((knob, y), 1.9);
            }
        }
        Icon::PanelRight => {
            p.rrect(1.8, 2.6, 12.4, 10.8, 1.6);
            p.line(&[(9.8, 2.6), (9.8, 13.4)]);
        }
        Icon::Download => {
            p.line(&[(8.0, 2.2), (8.0, 10.2)]);
            p.line(&[(4.6, 6.8), (8.0, 10.2), (11.4, 6.8)]);
            p.line(&[(2.8, 13.4), (13.2, 13.4)]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every icon puts ink inside its box and none outside (one pixel of
    /// anti-aliasing slack), at the regular size and at 200 %.
    #[test]
    fn every_icon_draws_inside_its_box() {
        for size in [16usize, 32] {
            let (w, off) = (size + 40, 20usize);
            for icon in Icon::ALL {
                let mut px = vec![0u32; w * w];
                let mut cv = Canvas::new(&mut px, w, w);
                draw(&mut cv, icon, off as f32, off as f32, size as f32, 0xffffff);
                let mut inside = 0;
                for y in 0..w {
                    for x in 0..w {
                        if px[y * w + x] == 0 {
                            continue;
                        }
                        let near = |v: usize| v + 1 >= off && v <= off + size;
                        assert!(
                            near(x) && near(y),
                            "{icon:?} at {size} px leaves its box at ({x}, {y})"
                        );
                        inside += 1;
                    }
                }
                assert!(inside > size, "{icon:?} at {size} px draws almost nothing");
            }
        }
    }
}
