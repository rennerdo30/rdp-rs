//! Keyboard and mouse input through SendInput.
//!
//! Positions arrive in pixels of the captured output and are mapped to the
//! absolute 0..65535 coordinates of the whole virtual desktop
//! (MOUSEEVENTF_VIRTUALDESK), so a capture of a secondary monitor would map
//! right too. Keys go as scancodes (KEYEVENTF_SCANCODE), so the host's own
//! keyboard layout interprets them, as on a local keyboard; Unicode events
//! use KEYEVENTF_UNICODE. Input to elevated windows or the secure desktop is
//! blocked by Windows (UIPI) for a host that runs unelevated.
//!
//! The mapping is pure functions with tests; SendInput itself is only
//! called at run time, never by the tests.

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
    SendInput, VK_CAPITAL, VK_NUMLOCK, VK_PAUSE, VK_SCROLL,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    XBUTTON1, XBUTTON2,
};

use crate::backend::{Button, InputSink, Toggles};

/// The virtual desktop: left, top, width, height.
type VirtualScreen = (i32, i32, i32, i32);

/// Maps a pixel of the captured output (whose top left is `origin` in
/// virtual desktop coordinates) to SendInput's absolute coordinates.
pub(crate) fn absolute(x: u16, y: u16, origin: (i32, i32), vs: VirtualScreen) -> (i32, i32) {
    let norm = |p: i32, start: i32, len: i32| -> i32 {
        let span = i64::from((len - 1).max(1));
        let v = i64::from(p - start) * 65535 / span;
        v.clamp(0, 65535) as i32
    };
    (
        norm(origin.0 + i32::from(x), vs.0, vs.2),
        norm(origin.1 + i32::from(y), vs.1, vs.3),
    )
}

/// The KEYBDINPUT fields (wVk, wScan, dwFlags) for a key event. The E1
/// key (Pause, 0xE11D) has no scancode form in SendInput: it goes as
/// VK_PAUSE.
pub(crate) fn key_fields(scancode: u16, extended: bool, down: bool) -> (u16, u16, u32) {
    let up = if down { 0 } else { KEYEVENTF_KEYUP };
    if scancode & 0xFF00 == 0xE100 {
        return (VK_PAUSE, 0, up);
    }
    let ext = if extended { KEYEVENTF_EXTENDEDKEY } else { 0 };
    (0, scancode & 0xFF, KEYEVENTF_SCANCODE | ext | up)
}

/// The mouse flags and mouseData for a button event.
pub(crate) fn button_fields(b: Button, down: bool) -> (u32, i32) {
    let pick = |d, u| if down { d } else { u };
    match b {
        Button::Left => (pick(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP), 0),
        Button::Right => (pick(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP), 0),
        Button::Middle => (pick(MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP), 0),
        Button::X1 => (
            pick(MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP),
            i32::from(XBUTTON1),
        ),
        Button::X2 => (
            pick(MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP),
            i32::from(XBUTTON2),
        ),
    }
}

/// The toggle keys to press (down and up) so that the current states
/// (Scroll, Num, Caps Lock) become the wanted ones. Kana is left alone.
pub(crate) fn toggles_to_press(current: [bool; 3], wanted: Toggles) -> Vec<u16> {
    [
        (VK_SCROLL, current[0], wanted.scroll_lock),
        (VK_NUMLOCK, current[1], wanted.num_lock),
        (VK_CAPITAL, current[2], wanted.caps_lock),
    ]
    .into_iter()
    .filter(|&(_, now, want)| now != want)
    .map(|(vk, _, _)| vk)
    .collect()
}

fn keyboard(vk: u16, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn mouse(dx: i32, dy: i32, data: i32, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as _,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Injects input into the desktop of the session the host runs in.
pub struct SendInputSink {
    origin: (i32, i32),
}

impl SendInputSink {
    /// `origin`: the captured output's top left in virtual desktop pixels.
    pub fn new(origin: (i32, i32)) -> SendInputSink {
        SendInputSink { origin }
    }

    fn send(&self, inputs: &[INPUT]) {
        // SAFETY: a valid array of initialized INPUT structures.
        let sent = unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            )
        };
        if sent as usize != inputs.len() {
            crate::info!(
                "SendInput refused input ({}); an elevated window or the secure desktop may have the focus",
                std::io::Error::last_os_error()
            );
        }
    }
}

impl InputSink for SendInputSink {
    fn key(&mut self, scancode: u16, extended: bool, down: bool) {
        let (vk, scan, flags) = key_fields(scancode, extended, down);
        self.send(&[keyboard(vk, scan, flags)]);
    }

    fn unicode(&mut self, ch: u16, down: bool) {
        let up = if down { 0 } else { KEYEVENTF_KEYUP };
        self.send(&[keyboard(0, ch, KEYEVENTF_UNICODE | up)]);
    }

    fn mouse_move(&mut self, x: u16, y: u16) {
        // SAFETY: GetSystemMetrics has no preconditions.
        let vs = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        let (dx, dy) = absolute(x, y, self.origin, vs);
        let flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        self.send(&[mouse(dx, dy, 0, flags)]);
    }

    fn button(&mut self, b: Button, down: bool) {
        let (flags, data) = button_fields(b, down);
        self.send(&[mouse(0, 0, data, flags)]);
    }

    fn wheel(&mut self, delta: i16, horizontal: bool) {
        let flags = if horizontal {
            MOUSEEVENTF_HWHEEL
        } else {
            MOUSEEVENTF_WHEEL
        };
        self.send(&[mouse(0, 0, i32::from(delta), flags)]);
    }

    fn sync(&mut self, toggles: Toggles) {
        // SAFETY: GetKeyState has no preconditions; bit 0 is the toggle.
        let on = |vk: u16| unsafe { GetKeyState(i32::from(vk)) } & 1 != 0;
        let current = [on(VK_SCROLL), on(VK_NUMLOCK), on(VK_CAPITAL)];
        for vk in toggles_to_press(current, toggles) {
            self.send(&[keyboard(vk, 0, 0), keyboard(vk, 0, KEYEVENTF_KEYUP)]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_map_to_the_virtual_desktop() {
        // One 1920 x 1080 monitor.
        let vs = (0, 0, 1920, 1080);
        assert_eq!(absolute(0, 0, (0, 0), vs), (0, 0));
        assert_eq!(absolute(1919, 1079, (0, 0), vs), (65535, 65535));
        assert_eq!(absolute(960, 540, (0, 0), vs), (32784, 32797));
        // The captured monitor right of a 1280-wide one that starts at
        // -1280: the virtual desktop is 3200 wide from -1280.
        let vs = (-1280, 0, 3200, 1080);
        assert_eq!(absolute(0, 0, (0, 0), vs).0, 1280 * 65535 / 3199);
        assert_eq!(absolute(1919, 0, (0, 0), vs).0, 65535);
        // Out of range clamps.
        assert_eq!(
            absolute(5000, 5000, (0, 0), (0, 0, 1920, 1080)),
            (65535, 65535)
        );
    }

    #[test]
    fn keys_go_as_scancodes() {
        assert_eq!(key_fields(0x1E, false, true), (0, 0x1E, KEYEVENTF_SCANCODE));
        assert_eq!(
            key_fields(0x48, true, false),
            (
                0,
                0x48,
                KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP
            )
        );
        // Pause (E1 1D) as the virtual key.
        assert_eq!(key_fields(0xE11D, false, true), (VK_PAUSE, 0, 0));
        assert_eq!(
            key_fields(0xE11D, false, false),
            (VK_PAUSE, 0, KEYEVENTF_KEYUP)
        );
    }

    #[test]
    fn buttons_and_toggles() {
        assert_eq!(button_fields(Button::Left, true), (MOUSEEVENTF_LEFTDOWN, 0));
        assert_eq!(
            button_fields(Button::Middle, false),
            (MOUSEEVENTF_MIDDLEUP, 0)
        );
        assert_eq!(
            button_fields(Button::X2, true),
            (MOUSEEVENTF_XDOWN, i32::from(XBUTTON2))
        );
        let want = Toggles {
            num_lock: true,
            ..Default::default()
        };
        assert_eq!(
            toggles_to_press([false, false, true], want),
            vec![VK_NUMLOCK, VK_CAPITAL]
        );
        assert!(toggles_to_press([false, true, false], want).is_empty());
    }
}
