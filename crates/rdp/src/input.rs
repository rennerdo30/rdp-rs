//! Fast-path input events (MS-RDPBCGR 2.2.8.1.2).

use crate::cursor::Put;

pub const PTRFLAGS_WHEEL_NEGATIVE: u16 = 0x0100;
pub const PTRFLAGS_WHEEL: u16 = 0x0200;
pub const PTRFLAGS_MOVE: u16 = 0x0800;
pub const PTRFLAGS_BUTTON1: u16 = 0x1000;
pub const PTRFLAGS_BUTTON2: u16 = 0x2000;
pub const PTRFLAGS_BUTTON3: u16 = 0x4000;
pub const PTRFLAGS_DOWN: u16 = 0x8000;

#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    /// Set-1 scancode; `extended` adds the E0 prefix.
    Key { scancode: u8, extended: bool, down: bool },
    Unicode { code: u16, down: bool },
    Mouse { flags: u16, x: u16, y: u16 },
}

impl InputEvent {
    pub fn mouse_move(x: u16, y: u16) -> Self {
        InputEvent::Mouse { flags: PTRFLAGS_MOVE, x, y }
    }

    /// `button`: PTRFLAGS_BUTTON1 (left), BUTTON2 (right) or BUTTON3 (middle).
    pub fn mouse_button(button: u16, down: bool, x: u16, y: u16) -> Self {
        InputEvent::Mouse { flags: button | if down { PTRFLAGS_DOWN } else { 0 }, x, y }
    }

    /// Vertical wheel; positive is away from the user. One notch is 120.
    pub fn wheel(delta: i16, x: u16, y: u16) -> Self {
        let d = delta.clamp(-255, 255);
        let flags = if d < 0 {
            PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | ((d as i32 & 0xFF) as u16)
        } else {
            PTRFLAGS_WHEEL | d as u16
        };
        InputEvent::Mouse { flags, x, y }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            InputEvent::Key { scancode, extended, down } => {
                let flags = (!down as u8) | if extended { 0x02 } else { 0 };
                out.put_u8(flags);
                out.put_u8(scancode);
            }
            InputEvent::Unicode { code, down } => {
                out.put_u8((4 << 5) | (!down as u8));
                out.put_u16(code);
            }
            InputEvent::Mouse { flags, x, y } => {
                out.put_u8(1 << 5);
                out.put_u16(flags);
                out.put_u16(x);
                out.put_u16(y);
            }
        }
    }
}

/// One fast-path input PDU carrying up to 15 events.
pub fn fastpath_input(events: &[InputEvent]) -> Vec<u8> {
    debug_assert!(!events.is_empty() && events.len() <= 15);
    let mut body = Vec::new();
    for e in events {
        e.encode(&mut body);
    }
    let header = (events.len() as u8) << 2;
    let mut out = vec![header];
    let short = 2 + body.len();
    if short < 0x80 {
        out.put_u8(short as u8);
    } else {
        out.put_u16_be(0x8000 | (3 + body.len()) as u16);
    }
    out.put_bytes(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_down_up() {
        let pdu = fastpath_input(&[
            InputEvent::Key { scancode: 0x1E, extended: false, down: true },
            InputEvent::Key { scancode: 0x48, extended: true, down: false },
        ]);
        assert_eq!(pdu, vec![2 << 2, 6, 0x00, 0x1E, 0x03, 0x48]);
    }

    #[test]
    fn full_pdu_length_is_header_plus_events() {
        // 15 mouse events (the most one header can count) still fit the 1-byte length.
        let events = vec![InputEvent::mouse_move(1, 2); 15];
        let pdu = fastpath_input(&events);
        assert_eq!(pdu[0], 15 << 2);
        assert_eq!(pdu.len(), 2 + 15 * 7);
        assert_eq!(pdu[1] as usize, pdu.len());
    }

    #[test]
    fn wheel_down_uses_nine_bit_negative() {
        let InputEvent::Mouse { flags, .. } = InputEvent::wheel(-120, 0, 0) else { unreachable!() };
        assert_eq!(flags, PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 0x88);
    }
}
