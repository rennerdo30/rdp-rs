//! The demo backend: a test pattern instead of a screen, and an input sink
//! that only records and logs. It never touches the real desktop, so it is
//! safe to run anywhere, and the end-to-end tests use it.
//!
//! The picture: a gradient with a checkerboard (the static pattern, see
//! [`base_pixel`]); when animated, a moving bar pair and a seconds counter.
//! Input shows up in the picture as soon as it arrives: a crosshair at the
//! mouse position, the last scancode (green while down, red after release,
//! "E0" in front for extended keys), the last Unicode character as hex, and
//! one square per mouse button that lights while it is held.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Button, Capturer, Frame, InputSink, Rect, Toggles};

/// What the demo input sink received; drawn into the picture.
#[derive(Debug, Default, Clone)]
struct DemoState {
    cursor: Option<(u16, u16)>,
    /// Scancode (0xE0xx for extended keys) and whether it is down.
    key: Option<(u16, bool)>,
    unicode: Option<u16>,
    /// Pressed buttons: bit 0 left, 1 right, 2 middle, 3 X1, 4 X2.
    buttons: u8,
    /// Changes with every event, so the capturer knows to redraw.
    version: u64,
}

/// A demo capturer and its input sink, sharing what the sink received.
/// `animated` false gives a static picture (the tests compare it).
pub fn demo(width: u16, height: u16, animated: bool, log: bool) -> (DemoCapturer, DemoInput) {
    let state = Arc::new(Mutex::new(DemoState::default()));
    let capturer = DemoCapturer {
        width: width.max(1),
        height: height.max(1),
        animated,
        start: Instant::now(),
        state: state.clone(),
        drawn: None,
        buf: vec![0; usize::from(width.max(1)) * usize::from(height.max(1)) * 4],
    };
    (capturer, DemoInput { state, log })
}

/// The static pattern at (x, y) of a `w` x `h` picture, as B, G, R, unused:
/// blue grows to the right, green downwards, red alternates in a 32-pixel
/// checkerboard.
pub fn base_pixel(x: u16, y: u16, w: u16, h: u16) -> [u8; 4] {
    let (x, y) = (u32::from(x), u32::from(y));
    let b = x * 255 / u32::from(w.max(2) - 1);
    let g = y * 255 / u32::from(h.max(2) - 1);
    let r = if (x / 32 + y / 32) % 2 == 0 {
        0x30
    } else {
        0xC0
    };
    [b as u8, g as u8, r, 0xFF]
}

pub struct DemoCapturer {
    width: u16,
    height: u16,
    animated: bool,
    start: Instant,
    state: Arc<Mutex<DemoState>>,
    /// The animation step and input version last drawn.
    drawn: Option<(u64, u64)>,
    buf: Vec<u8>,
}

impl Capturer for DemoCapturer {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn next_frame(&mut self, _timeout: Duration) -> io::Result<Option<Frame<'_>>> {
        let step = if self.animated {
            (self.start.elapsed().as_millis() / 33) as u64
        } else {
            0
        };
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if self.drawn == Some((step, state.version)) {
            return Ok(None);
        }
        self.drawn = Some((step, state.version));
        self.render(step, &state);
        Ok(Some(Frame {
            width: self.width,
            height: self.height,
            stride: usize::from(self.width) * 4,
            pixels: &self.buf,
            damage: vec![Rect::new(0, 0, self.width, self.height)],
        }))
    }
}

impl DemoCapturer {
    fn render(&mut self, step: u64, state: &DemoState) {
        let (w, h) = (self.width, self.height);
        for y in 0..h {
            for x in 0..w {
                let i = (usize::from(y) * usize::from(w) + usize::from(x)) * 4;
                self.buf[i..i + 4].copy_from_slice(&base_pixel(x, y, w, h));
            }
        }
        let mut c = Canvas {
            buf: &mut self.buf,
            w,
            h,
        };
        if self.animated {
            // A vertical and a horizontal bar sweeping across.
            let bx = ((step * 12) % u64::from(w)) as u16;
            let by = ((step * 6) % u64::from(h)) as u16;
            c.fill(bx, 0, 48, h, [0xF0, 0xF0, 0xF0]);
            c.fill(0, by, w, 24, [0xD0, 0xD0, 0x20]);
            // The seconds since start, five digits.
            let secs = self.start.elapsed().as_secs() % 100_000;
            c.fill(10, 10, 5 * 24 + 12, 46, [0, 0, 0]);
            c.text(16, 16, &format!("{secs:05}"), 6, [0xFF, 0xFF, 0xFF]);
        }
        if let Some((sc, down)) = state.key {
            let color = if down {
                [0x40, 0xE0, 0x40]
            } else {
                [0x40, 0x40, 0xE0]
            };
            c.fill(10, 64, 4 * 24 + 12, 46, [0, 0, 0]);
            c.text(16, 70, &format!("{sc:04X}"), 6, color);
        }
        if let Some(u) = state.unicode {
            c.fill(10, 118, 4 * 24 + 12, 46, [0, 0, 0]);
            c.text(16, 124, &format!("{u:04X}"), 6, [0xF0, 0xA0, 0x40]);
        }
        if state.cursor.is_some() || state.buttons != 0 {
            for i in 0..5u16 {
                let on = state.buttons & (1 << i) != 0;
                let color = if on {
                    [0x20, 0xE0, 0xF0]
                } else {
                    [0x30, 0x30, 0x30]
                };
                c.fill(10 + i * 22, 172, 18, 18, color);
            }
        }
        if let Some((x, y)) = state.cursor {
            // A crosshair, black with a white centre.
            c.fill(x.saturating_sub(12), y.saturating_sub(1), 25, 3, [0, 0, 0]);
            c.fill(x.saturating_sub(1), y.saturating_sub(12), 3, 25, [0, 0, 0]);
            c.fill(x, y, 1, 1, [0xFF, 0xFF, 0xFF]);
        }
    }
}

/// Clipped drawing on a BGRA buffer.
struct Canvas<'a> {
    buf: &'a mut [u8],
    w: u16,
    h: u16,
}

/// 3 x 5 glyphs for hex digits, one row per entry, bit 2 is the left column.
const GLYPHS: [[u8; 5]; 16] = [
    [7, 5, 5, 5, 7], // 0
    [2, 6, 2, 2, 7], // 1
    [7, 1, 7, 4, 7], // 2
    [7, 1, 7, 1, 7], // 3
    [5, 5, 7, 1, 1], // 4
    [7, 4, 7, 1, 7], // 5
    [7, 4, 7, 5, 7], // 6
    [7, 1, 2, 2, 2], // 7
    [7, 5, 7, 5, 7], // 8
    [7, 5, 7, 1, 7], // 9
    [2, 5, 7, 5, 5], // A
    [6, 5, 6, 5, 6], // B
    [7, 4, 4, 4, 7], // C
    [6, 5, 5, 5, 6], // D
    [7, 4, 6, 4, 7], // E
    [7, 4, 6, 4, 4], // F
];

impl Canvas<'_> {
    /// Fills a rectangle with an RGB colour, clipped to the picture.
    fn fill(&mut self, x: u16, y: u16, w: u16, h: u16, rgb: [u8; 3]) {
        let x_end = x.saturating_add(w).min(self.w);
        let y_end = y.saturating_add(h).min(self.h);
        for yy in y..y_end {
            for xx in x..x_end {
                let i = (usize::from(yy) * usize::from(self.w) + usize::from(xx)) * 4;
                self.buf[i..i + 4].copy_from_slice(&[rgb[2], rgb[1], rgb[0], 0xFF]);
            }
        }
    }

    /// Draws hex digits at `scale` pixels per glyph dot.
    fn text(&mut self, x: u16, y: u16, s: &str, scale: u16, rgb: [u8; 3]) {
        for (n, ch) in s.chars().enumerate() {
            let Some(d) = ch.to_digit(16) else { continue };
            let gx = x + n as u16 * 4 * scale;
            for (row, bits) in GLYPHS[d as usize].iter().enumerate() {
                for col in 0..3u16 {
                    if bits & (4 >> col) != 0 {
                        self.fill(gx + col * scale, y + row as u16 * scale, scale, scale, rgb);
                    }
                }
            }
        }
    }
}

/// The demo's input sink: draws into the demo picture and logs.
pub struct DemoInput {
    state: Arc<Mutex<DemoState>>,
    log: bool,
}

impl DemoInput {
    fn update(&self, what: std::fmt::Arguments, f: impl FnOnce(&mut DemoState)) {
        if self.log {
            eprintln!("[remora-host] demo input: {what}");
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
        s.version += 1;
    }
}

fn button_bit(b: Button) -> u8 {
    match b {
        Button::Left => 1,
        Button::Right => 2,
        Button::Middle => 4,
        Button::X1 => 8,
        Button::X2 => 16,
    }
}

impl InputSink for DemoInput {
    fn key(&mut self, scancode: u16, extended: bool, down: bool) {
        let code = if extended {
            0xE000 | scancode
        } else {
            scancode
        };
        let updown = if down { "down" } else { "up" };
        self.update(format_args!("key {code:#06x} {updown}"), |s| {
            s.key = Some((code, down))
        });
    }

    fn unicode(&mut self, ch: u16, down: bool) {
        let updown = if down { "down" } else { "up" };
        self.update(format_args!("unicode U+{ch:04X} {updown}"), |s| {
            s.unicode = Some(ch)
        });
    }

    fn mouse_move(&mut self, x: u16, y: u16) {
        // Moves are drawn, not logged: they come by the hundred.
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.cursor = Some((x, y));
        s.version += 1;
    }

    fn button(&mut self, b: Button, down: bool) {
        let updown = if down { "down" } else { "up" };
        self.update(format_args!("{b:?} button {updown}"), |s| {
            if down {
                s.buttons |= button_bit(b);
            } else {
                s.buttons &= !button_bit(b);
            }
        });
    }

    fn wheel(&mut self, delta: i16, horizontal: bool) {
        let axis = if horizontal { "horizontal" } else { "vertical" };
        self.update(format_args!("{axis} wheel {delta}"), |_| {});
    }

    fn sync(&mut self, toggles: Toggles) {
        self.update(format_args!("toggles {toggles:?}"), |_| {});
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_pattern_then_input_redraws() {
        let (mut cap, mut input) = demo(100, 60, false, false);
        let f = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!((f.width, f.height, f.stride), (100, 60, 400));
        assert_eq!(f.damage, vec![Rect::new(0, 0, 100, 60)]);
        // The static picture is the base pattern, pixel for pixel.
        for (y, x) in [(0u16, 0u16), (59, 99), (33, 40)] {
            let i = (usize::from(y) * 100 + usize::from(x)) * 4;
            assert_eq!(f.pixels[i..i + 4], base_pixel(x, y, 100, 60));
        }
        let before = f.pixels.to_vec();
        // Nothing changed: no frame.
        assert!(cap.next_frame(Duration::ZERO).unwrap().is_none());
        // Input changes the picture.
        input.mouse_move(50, 30);
        input.key(0x1E, false, true);
        let f = cap.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_ne!(f.pixels, &before[..]);
        let centre = (30 * 100 + 50) * 4;
        assert_eq!(f.pixels[centre..centre + 4], [0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
