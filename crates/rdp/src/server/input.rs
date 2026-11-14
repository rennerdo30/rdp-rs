//! Client input as the server receives it: fast-path input events
//! (MS-RDPBCGR 2.2.8.1.2) and the slow-path Input Event PDU (2.2.8.1.1.3).

use crate::cursor::Reader;
use crate::error::{Error, Result, proto};

/// Pointer flags (2.2.8.1.1.3.1.1.3); the client's are in [`crate::input`].
pub use crate::input::{
    PTRFLAGS_BUTTON1, PTRFLAGS_BUTTON2, PTRFLAGS_BUTTON3, PTRFLAGS_DOWN, PTRFLAGS_MOVE,
    PTRFLAGS_WHEEL, PTRFLAGS_WHEEL_NEGATIVE,
};
pub const PTRFLAGS_HWHEEL: u16 = 0x0400;
/// The 9-bit wheel rotation, sign included (WheelRotationMask).
const WHEEL_ROTATION_MASK: u16 = 0x01FF;

/// Extended mouse flags (2.2.8.1.1.3.1.1.4).
pub const PTRXFLAGS_DOWN: u16 = 0x8000;
pub const PTRXFLAGS_BUTTON1: u16 = 0x0001;
pub const PTRXFLAGS_BUTTON2: u16 = 0x0002;

/// Toggle key states of a synchronize event (2.2.8.1.1.3.1.1.5,
/// 2.2.8.1.2.2.5); the same bits in both paths.
pub const SYNC_SCROLL_LOCK: u32 = 0x01;
pub const SYNC_NUM_LOCK: u32 = 0x02;
pub const SYNC_CAPS_LOCK: u32 = 0x04;
pub const SYNC_KANA_LOCK: u32 = 0x08;

/// One input event from the client, in either path's encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientInput {
    /// A set-1 scancode; `extended` is the E0 prefix, `extended1` the E1
    /// prefix (Pause).
    Key {
        scancode: u8,
        extended: bool,
        extended1: bool,
        down: bool,
    },
    /// A UTF-16 code unit.
    Unicode { code: u16, down: bool },
    /// Pointer flags with a position in desktop pixels.
    Mouse { flags: u16, x: u16, y: u16 },
    /// Extended buttons (PTRXFLAGS_*).
    MouseX { flags: u16, x: u16, y: u16 },
    /// Relative motion (2.2.8.1.2.2.7); not advertised by the host.
    RelativeMouse { flags: u16, dx: i16, dy: i16 },
    /// Toggle key states (SYNC_* bits).
    Sync { toggles: u32 },
}

/// The signed wheel rotation of a PTRFLAGS_WHEEL or PTRFLAGS_HWHEEL event:
/// a 9-bit two's complement value, 120 per notch.
pub fn wheel_rotation(flags: u16) -> i16 {
    let v = (flags & WHEEL_ROTATION_MASK) as i16;
    if flags & PTRFLAGS_WHEEL_NEGATIVE != 0 {
        v - 0x200
    } else {
        v
    }
}

/// Parses a fast-path input PDU (2.2.8.1.2) with its header. TLS carries
/// it, so the encryption flags MUST be clear (no FIPS info, no signature).
pub fn parse_fastpath_input(frame: &[u8]) -> Result<Vec<ClientInput>> {
    const FASTPATH_INPUT_ENCRYPTED: u8 = 0x2;
    let mut r = Reader::new(frame);
    let header = r.u8()?;
    if header & 0x03 != 0 {
        return proto("not a fast-path input PDU");
    }
    if (header >> 6) & FASTPATH_INPUT_ENCRYPTED != 0 {
        return Err(Error::Unsupported("encrypted fast-path input".into()));
    }
    let l1 = r.u8()?;
    if l1 & 0x80 != 0 {
        r.u8()?;
    }
    let mut count = ((header >> 2) & 0x0F) as usize;
    if count == 0 {
        count = r.u8()? as usize; // numEvents after the length (> 15 events)
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let h = r.u8()?;
        let flags = h & 0x1F;
        let event = match h >> 5 {
            0 => ClientInput::Key {
                down: flags & 0x01 == 0, // FASTPATH_INPUT_KBDFLAGS_RELEASE
                extended: flags & 0x02 != 0,
                extended1: flags & 0x04 != 0,
                scancode: r.u8()?,
            },
            1 => ClientInput::Mouse {
                flags: r.u16()?,
                x: r.u16()?,
                y: r.u16()?,
            },
            2 => ClientInput::MouseX {
                flags: r.u16()?,
                x: r.u16()?,
                y: r.u16()?,
            },
            3 => ClientInput::Sync {
                toggles: u32::from(flags),
            },
            4 => ClientInput::Unicode {
                down: flags & 0x01 == 0,
                code: r.u16()?,
            },
            5 => ClientInput::RelativeMouse {
                flags: r.u16()?,
                dx: r.u16()? as i16,
                dy: r.u16()? as i16,
            },
            6 => {
                r.u32()?; // TS_FP_QOETIMESTAMP_EVENT: not input
                continue;
            }
            c => return proto(format!("unknown fast-path input event code {c}")),
        };
        out.push(event);
    }
    Ok(out)
}

/// Parses the payload of a slow-path Input Event PDU (TS_INPUT_PDU_DATA,
/// 2.2.8.1.1.3.1): numEvents, pad, then TS_INPUT_EVENTs of 12 bytes.
pub fn parse_slowpath_input(payload: &[u8]) -> Result<Vec<ClientInput>> {
    const KBDFLAGS_EXTENDED: u16 = 0x0100;
    const KBDFLAGS_EXTENDED1: u16 = 0x0200;
    const KBDFLAGS_RELEASE: u16 = 0x8000;
    let mut r = Reader::new(payload);
    let count = r.u16()?;
    r.u16()?; // pad2Octets
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        r.u32()?; // eventTime
        let ty = r.u16()?;
        let a = r.u16()?;
        let b = r.u16()?;
        let c = r.u16()?;
        out.push(match ty {
            // INPUT_EVENT_SYNC: pad2Octets, toggleFlags
            0x0000 => ClientInput::Sync {
                toggles: u32::from(b) | (u32::from(c) << 16),
            },
            // INPUT_EVENT_SCANCODE: keyboardFlags, keyCode, pad
            0x0004 => ClientInput::Key {
                scancode: b as u8,
                extended: a & KBDFLAGS_EXTENDED != 0,
                extended1: a & KBDFLAGS_EXTENDED1 != 0,
                down: a & KBDFLAGS_RELEASE == 0,
            },
            // INPUT_EVENT_UNICODE: keyboardFlags, unicodeCode, pad
            0x0005 => ClientInput::Unicode {
                code: b,
                down: a & KBDFLAGS_RELEASE == 0,
            },
            0x8001 => ClientInput::Mouse {
                flags: a,
                x: b,
                y: c,
            },
            0x8002 => ClientInput::MouseX {
                flags: a,
                x: b,
                y: c,
            },
            0x8004 => ClientInput::RelativeMouse {
                flags: a,
                dx: b as i16,
                dy: c as i16,
            },
            // INPUT_EVENT_UNUSED and anything unknown: skipped.
            _ => continue,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputEvent, fastpath_input};

    #[test]
    fn client_fastpath_input_round_trips() {
        let sent = [
            InputEvent::Key {
                scancode: 0x1E,
                extended: false,
                down: true,
            },
            InputEvent::Key {
                scancode: 0x48,
                extended: true,
                down: false,
            },
            InputEvent::Unicode {
                code: 0x20AC,
                down: true,
            },
            InputEvent::mouse_move(640, 400),
            InputEvent::mouse_button(PTRFLAGS_BUTTON2, true, 1, 2),
            InputEvent::wheel(-120, 3, 4),
        ];
        let got = parse_fastpath_input(&fastpath_input(&sent)).unwrap();
        assert_eq!(
            got,
            vec![
                ClientInput::Key {
                    scancode: 0x1E,
                    extended: false,
                    extended1: false,
                    down: true
                },
                ClientInput::Key {
                    scancode: 0x48,
                    extended: true,
                    extended1: false,
                    down: false
                },
                ClientInput::Unicode {
                    code: 0x20AC,
                    down: true
                },
                ClientInput::Mouse {
                    flags: PTRFLAGS_MOVE,
                    x: 640,
                    y: 400
                },
                ClientInput::Mouse {
                    flags: PTRFLAGS_BUTTON2 | PTRFLAGS_DOWN,
                    x: 1,
                    y: 2
                },
                ClientInput::Mouse {
                    flags: PTRFLAGS_WHEEL | PTRFLAGS_WHEEL_NEGATIVE | 0x88,
                    x: 3,
                    y: 4
                },
            ]
        );
        let ClientInput::Mouse { flags, .. } = got[5] else {
            unreachable!()
        };
        assert_eq!(wheel_rotation(flags), -120);
        assert_eq!(wheel_rotation(PTRFLAGS_WHEEL | 120), 120);
    }

    #[test]
    fn long_length_and_counted_events() {
        // 15 mouse events use the two-byte length form.
        let sent = vec![InputEvent::mouse_move(7, 9); 15];
        let pdu = fastpath_input(&sent);
        assert_eq!(parse_fastpath_input(&pdu).unwrap().len(), 15);
        // numEvents 0 in the header: the count follows the length
        // (2.2.8.1.2): one sync event with Num Lock and Caps Lock, one
        // horizontal wheel event and one X button.
        let mut pdu = vec![0x00, 0, 3];
        pdu.push((3 << 5) | 0x06); // TS_FP_SYNC_EVENT
        pdu.push(1 << 5); // TS_FP_POINTER_EVENT
        pdu.extend((PTRFLAGS_HWHEEL | 0x78).to_le_bytes());
        pdu.extend([10, 0, 20, 0]);
        pdu.push(2 << 5); // TS_FP_POINTERX_EVENT
        pdu.extend((PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON2).to_le_bytes());
        pdu.extend([1, 0, 2, 0]);
        pdu[1] = pdu.len() as u8;
        assert_eq!(
            parse_fastpath_input(&pdu).unwrap(),
            vec![
                ClientInput::Sync {
                    toggles: SYNC_NUM_LOCK | SYNC_CAPS_LOCK
                },
                ClientInput::Mouse {
                    flags: PTRFLAGS_HWHEEL | 0x78,
                    x: 10,
                    y: 20
                },
                ClientInput::MouseX {
                    flags: PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON2,
                    x: 1,
                    y: 2
                },
            ]
        );
    }

    #[test]
    fn malformed_fastpath_input_is_an_error() {
        assert!(parse_fastpath_input(&[]).is_err());
        // Two events announced, one present.
        assert!(parse_fastpath_input(&[2 << 2, 4, 0x00, 0x1E]).is_err());
        // Encrypted.
        assert!(parse_fastpath_input(&[0x80 | (1 << 2), 4, 0x00, 0x1E]).is_err());
        // Unknown event code 7.
        assert!(parse_fastpath_input(&[1 << 2, 3, 7 << 5]).is_err());
    }

    #[test]
    fn slowpath_input_events() {
        // TS_INPUT_PDU_DATA with scancode (extended, release), Unicode,
        // mouse and sync events (2.2.8.1.1.3.1.1).
        let mut p = vec![4, 0, 0, 0];
        let ev = |p: &mut Vec<u8>, ty: u16, a: u16, b: u16, c: u16| {
            p.extend([0, 0, 0, 0]);
            for v in [ty, a, b, c] {
                p.extend(v.to_le_bytes());
            }
        };
        ev(&mut p, 0x0004, 0x8100, 0x4B, 0);
        ev(&mut p, 0x0005, 0x0000, 0x00E9, 0);
        ev(&mut p, 0x8001, PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN, 5, 6);
        ev(&mut p, 0x0000, 0, SYNC_SCROLL_LOCK as u16, 0);
        assert_eq!(
            parse_slowpath_input(&p).unwrap(),
            vec![
                ClientInput::Key {
                    scancode: 0x4B,
                    extended: true,
                    extended1: false,
                    down: false
                },
                ClientInput::Unicode {
                    code: 0xE9,
                    down: true
                },
                ClientInput::Mouse {
                    flags: PTRFLAGS_BUTTON1 | PTRFLAGS_DOWN,
                    x: 5,
                    y: 6
                },
                ClientInput::Sync {
                    toggles: SYNC_SCROLL_LOCK
                },
            ]
        );
        p.truncate(p.len() - 1);
        assert!(parse_slowpath_input(&p).is_err());
    }
}
