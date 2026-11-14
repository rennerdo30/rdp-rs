//! The host's platform seams: what it shows ([`Capturer`]), where input
//! goes ([`InputSink`]) and who may log on ([`Authenticator`]).
//!
//! - [`demo`]: an animated test pattern that draws the input it receives;
//!   cross-platform, used by the tests and safe to run anywhere.
//! - `windows`: DXGI Desktop Duplication and SendInput (Windows only).
//! - [`unsupported`]: Linux and macOS, which have no backend yet.

use std::io;
use std::time::Duration;

pub use rdp::server::Rect;

pub mod demo;
pub mod unsupported;
#[cfg(windows)]
pub mod windows;

/// One captured picture: BGRA pixels (B, G, R, unused), rows top-down, and
/// the rectangles that changed since the previous frame.
pub struct Frame<'a> {
    pub width: u16,
    pub height: u16,
    /// Bytes per row (at least `width * 4`).
    pub stride: usize,
    pub pixels: &'a [u8],
    /// Changed areas. The first frame a capturer returns covers the whole
    /// picture.
    pub damage: Vec<Rect>,
}

/// A screen source.
pub trait Capturer: Send {
    /// The desktop size in pixels; the session's Demand Active uses it.
    fn size(&self) -> (u16, u16);

    /// The next changed frame, waiting at most `timeout`; None when nothing
    /// changed in that time.
    fn next_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame<'_>>>;
}

/// Mouse buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
    /// The first extended button (back).
    X1,
    /// The second extended button (forward).
    X2,
}

/// Toggle key states from a synchronize event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Toggles {
    pub scroll_lock: bool,
    pub num_lock: bool,
    pub caps_lock: bool,
    pub kana_lock: bool,
}

/// Where the client's input goes. Positions are desktop pixels of the
/// captured screen.
pub trait InputSink: Send {
    /// A set-1 scancode; `extended` is the E0 prefix. A key with the E1
    /// prefix (Pause) arrives as `0xE100 | scancode`.
    fn key(&mut self, scancode: u16, extended: bool, down: bool);
    /// A UTF-16 code unit.
    fn unicode(&mut self, ch: u16, down: bool);
    fn mouse_move(&mut self, x: u16, y: u16);
    fn button(&mut self, b: Button, down: bool);
    /// Wheel rotation, 120 per notch; positive is away from the user
    /// (vertical) or to the right (horizontal).
    fn wheel(&mut self, delta: i16, horizontal: bool);
    /// The client's toggle key states (sent on focus and at connect).
    fn sync(&mut self, toggles: Toggles);
}

/// Decides who may log on.
pub trait Authenticator: Send + Sync {
    /// True when the credentials of a Client Info PDU are accepted.
    fn check(&self, user: &str, domain: &str, password: &str) -> bool;
}

/// The capturer and input sink of the platform's real desktop.
pub type Backend = (Box<dyn Capturer>, Box<dyn InputSink>);

/// The platform's backend: the Windows desktop, or an error that says this
/// platform is not supported yet.
pub fn os_backend() -> io::Result<Backend> {
    #[cfg(windows)]
    {
        windows::backend()
    }
    #[cfg(not(windows))]
    {
        unsupported::backend()
    }
}
