//! Touch and pen input for the session windows, sent over the remote
//! session's input channel (MS-RDPEI, [`rdp::TouchHandle`]).
//!
//! winit gives no raw pointer data, so each session window gets a window
//! subclass that sees `WM_POINTERDOWN/UPDATE/UP` before winit does. For a
//! touch or pen pointer over the session picture, while the server's input
//! channel is ready (and, for pens, allows pen input), the subclass reads
//! the frame with `GetPointerFrameTouchInfo` / `GetPointerPenInfo`, maps it
//! to session coordinates exactly as the mouse is mapped, queues it on the
//! handle and swallows the message. Otherwise the message goes to
//! `DefWindowProc`, which turns it into mouse input (mouse promotion); so
//! the session bar, the tabs and the sidebar keep working by touch, and a
//! server without the channel still gets a mouse.
//!
//! Mouse input stays on the classic `WM_MOUSE*` path: `EnableMouseInPointer`
//! is pinned to FALSE (its default) so the mouse never arrives as pointer
//! messages.
//!
//! Which windows take touch, and how their pixels map, is set by the app
//! after every event batch with [`set_targets`]; the subclass only reads it.
//! Everything runs on the UI thread.

use rdp::rdpei::{
    CONTACT_FLAG_CANCELED, CONTACT_FLAG_DOWN, CONTACT_FLAG_INCONTACT, CONTACT_FLAG_INRANGE,
    CONTACT_FLAG_UP, CONTACT_FLAG_UPDATE, PEN_FLAG_BARREL_PRESSED, PEN_FLAG_ERASER_PRESSED,
    PEN_FLAG_INVERTED,
};

/// Where touch on one window goes.
#[derive(Clone)]
pub struct Target {
    pub handle: rdp::TouchHandle,
    /// Client-area rectangle (x, y, w, h) in which a contact may start.
    pub accept: (i32, i32, i32, i32),
    /// Added to a point to get session framebuffer coordinates: to the
    /// client-area point, or to the screen point when `screen` is set.
    pub offset: (i32, i32),
    pub screen: bool,
    /// Session framebuffer size; positions are clamped into it.
    pub fb: (i32, i32),
}

impl Target {
    pub fn accepts(&self, client: (i32, i32)) -> bool {
        let (x, y, w, h) = self.accept;
        client.0 >= x && client.1 >= y && client.0 < x + w && client.1 < y + h
    }

    /// Session framebuffer position of a point, clamped like mouse input.
    pub fn map(&self, client: (i32, i32), screen: (i32, i32)) -> (i32, i32) {
        let (px, py) = if self.screen { screen } else { client };
        let x = (px + self.offset.0).clamp(0, (self.fb.0 - 1).max(0));
        let y = (py + self.offset.1).clamp(0, (self.fb.1 - 1).max(0));
        (x, y)
    }
}

// POINTER_FLAG_* (winuser.h), kept here so the mapping is testable anywhere.
pub const PF_INRANGE: u32 = 0x0000_0002;
pub const PF_INCONTACT: u32 = 0x0000_0004;
pub const PF_CANCELED: u32 = 0x0000_8000;
pub const PF_DOWN: u32 = 0x0001_0000;
pub const PF_UP: u32 = 0x0004_0000;

/// RDPEI contactFlags for a pointer event (MS-RDPEI 2.2.3.3.1.1, 3.1.1.1).
/// Always one of the combinations the spec allows.
pub fn contact_flags(pointer_flags: u32) -> u32 {
    let in_range = pointer_flags & PF_INRANGE != 0;
    let canceled = pointer_flags & PF_CANCELED != 0;
    if pointer_flags & PF_DOWN != 0 {
        CONTACT_FLAG_DOWN | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT
    } else if pointer_flags & PF_UP != 0 {
        if canceled {
            CONTACT_FLAG_UP | CONTACT_FLAG_CANCELED
        } else if in_range {
            CONTACT_FLAG_UP | CONTACT_FLAG_INRANGE
        } else {
            CONTACT_FLAG_UP
        }
    } else if canceled {
        CONTACT_FLAG_UPDATE | CONTACT_FLAG_CANCELED
    } else if pointer_flags & PF_INCONTACT != 0 {
        CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT
    } else if in_range {
        CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE
    } else {
        CONTACT_FLAG_UPDATE
    }
}

/// True when a contact with these flags has left the digitizer's range (or
/// was cancelled), so the contact id is free again.
pub fn ends(flags: u32) -> bool {
    flags & CONTACT_FLAG_CANCELED != 0 || flags & CONTACT_FLAG_INRANGE == 0
}

/// True when a contact with these flags is hovering (in range, not touching).
pub fn hovering(flags: u32) -> bool {
    flags & CONTACT_FLAG_INRANGE != 0 && flags & CONTACT_FLAG_INCONTACT == 0
}

// PEN_FLAG_* (winuser.h); the RDPEI bits are in a different order.
pub const WIN_PEN_BARREL: u32 = 0x1;
pub const WIN_PEN_INVERTED: u32 = 0x2;
pub const WIN_PEN_ERASER: u32 = 0x4;

/// RDPEI penFlags for Windows pen flags (MS-RDPEI 2.2.3.7.1.1).
pub fn pen_flags(win: u32) -> u32 {
    let mut f = 0;
    if win & WIN_PEN_BARREL != 0 {
        f |= PEN_FLAG_BARREL_PRESSED;
    }
    if win & WIN_PEN_ERASER != 0 {
        f |= PEN_FLAG_ERASER_PRESSED;
    }
    if win & WIN_PEN_INVERTED != 0 {
        f |= PEN_FLAG_INVERTED;
    }
    f
}

/// True when a contact the session has not seen may start with these flags:
/// touching down, or coming into hover range (MS-RDPEI 3.1.1.1).
pub fn starts(flags: u32) -> bool {
    flags == CONTACT_FLAG_DOWN | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT
        || flags == CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE
}

/// The smallest contact id (0..=255) not in `used`.
pub fn free_id(used: impl Iterator<Item = u8> + Clone) -> Option<u8> {
    (0..=255u8).find(|id| !used.clone().any(|u| u == *id))
}

#[cfg(windows)]
mod imp {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use rdp::rdpei::{CONTACT_FLAG_UPDATE, PenContact, PenFrame, TouchContact, TouchFrame};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::ScreenToClient;
    use windows_sys::Win32::UI::Input::Pointer::{
        EnableMouseInPointer, GetPointerFrameTouchInfo, GetPointerPenInfo, GetPointerType,
        POINTER_PEN_INFO, POINTER_TOUCH_INFO, SkipPointerFrameMessages,
    };
    use windows_sys::Win32::UI::Input::Touch::UnregisterTouchWindow;
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, GetSystemMetrics, NID_READY, PEN_MASK_PRESSURE, PEN_MASK_ROTATION,
        PEN_MASK_TILT_X, PEN_MASK_TILT_Y, PT_PEN, PT_TOUCH, SM_DIGITIZER, SM_MAXIMUMTOUCHES,
        TOUCH_MASK_CONTACTAREA, TOUCH_MASK_ORIENTATION, TOUCH_MASK_PRESSURE, WM_NCDESTROY,
        WM_POINTERCAPTURECHANGED, WM_POINTERDOWN, WM_POINTERLEAVE, WM_POINTERUP, WM_POINTERUPDATE,
    };

    use super::{Target, contact_flags, ends, free_id, hovering, pen_flags, starts};

    const SUBCLASS_ID: usize = 0x5445; // "TE"

    /// A contact the session owns, from its first event to leaving range.
    #[derive(Clone, Copy)]
    struct Active {
        hwnd: isize,
        contact_id: u8,
        pen: bool,
        /// The last flags and position sent, for synthesised endings.
        flags: u32,
        pos: (i32, i32),
    }

    #[derive(Default)]
    struct State {
        attached: Vec<isize>,
        targets: HashMap<isize, Target>,
        /// By Windows pointer id.
        active: HashMap<u32, Active>,
        mouse_pinned: bool,
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    /// True if a touch or pen digitizer is attached (MS-RDPEI 3.3.3: the
    /// client should not open the channel otherwise).
    pub fn digitizer_present() -> bool {
        // SAFETY: plain system metric query.
        let d = unsafe { GetSystemMetrics(SM_DIGITIZER) } as u32;
        d & NID_READY != 0
    }

    /// Simultaneous touch contacts this PC supports, for maxTouchContacts.
    pub fn max_contacts() -> u16 {
        // SAFETY: plain system metric query.
        let n = unsafe { GetSystemMetrics(SM_MAXIMUMTOUCHES) };
        if n > 0 {
            n.min(256) as u16
        } else {
            rdp::rdpei::DEFAULT_MAX_TOUCH_CONTACTS
        }
    }

    /// Subclasses a session window once. Call on the UI thread.
    pub fn attach(hwnd: isize) {
        if hwnd == 0 {
            return;
        }
        STATE.with_borrow_mut(|s| {
            if !s.mouse_pinned {
                s.mouse_pinned = true;
                // SAFETY: plain call; FALSE keeps the default (mouse as WM_MOUSE*).
                unsafe { EnableMouseInPointer(0) };
            }
            if s.attached.contains(&hwnd) {
                return;
            }
            // SAFETY: hwnd is a live window of this (the UI) thread;
            // `subclass_proc` matches SUBCLASSPROC and lives for the process.
            // UnregisterTouchWindow undoes winit's WM_TOUCH registration so an
            // unhandled pointer message becomes mouse input, not WM_TOUCH.
            unsafe {
                if SetWindowSubclass(hwnd as HWND, Some(subclass_proc), SUBCLASS_ID, 0) != 0 {
                    UnregisterTouchWindow(hwnd as HWND);
                    s.attached.push(hwnd);
                }
            }
        });
    }

    /// Replaces the touch targets: windows not listed take no touch.
    pub fn set_targets(targets: Vec<(isize, Target)>) {
        STATE.with_borrow_mut(|s| {
            s.targets = targets.into_iter().collect();
            // Contacts on windows that lost their target end without a frame;
            // the server cancels them when the channel goes.
            let State {
                targets, active, ..
            } = s;
            active.retain(|_, a| targets.contains_key(&a.hwnd));
        });
    }

    enum Outcome {
        /// Sent to the session; swallow the message.
        Sent,
        /// Let DefWindowProc turn it into mouse input.
        Mouse,
        /// Not touch or pen: the normal window procedure.
        Pass,
    }

    fn client_point(hwnd: isize, screen: POINT) -> (i32, i32) {
        let mut p = screen;
        // SAFETY: hwnd is the window whose message is being handled.
        unsafe { ScreenToClient(hwnd as HWND, &mut p) };
        (p.x, p.y)
    }

    fn pointer(hwnd: isize, id: u32) -> Outcome {
        let mut ty = 0;
        // SAFETY: id comes from the pointer message being handled.
        if unsafe { GetPointerType(id, &mut ty) } == 0 {
            return Outcome::Pass;
        }
        match ty {
            PT_TOUCH => touch(hwnd, id),
            PT_PEN => pen(hwnd, id),
            _ => Outcome::Pass,
        }
    }

    fn target(hwnd: isize) -> Option<Target> {
        STATE.with_borrow(|s| s.targets.get(&hwnd).cloned())
    }

    fn touch(hwnd: isize, id: u32) -> Outcome {
        let Some(t) = target(hwnd) else {
            return Outcome::Mouse;
        };
        if !t.handle.is_ready() {
            STATE.with_borrow_mut(|s| s.active.retain(|_, a| a.hwnd != hwnd || a.pen));
            return Outcome::Mouse;
        }
        let mut count = 0u32;
        // SAFETY: a null buffer asks for the count only.
        if unsafe { GetPointerFrameTouchInfo(id, &mut count, std::ptr::null_mut()) } == 0
            || count == 0
        {
            return Outcome::Mouse;
        }
        let mut infos = vec![POINTER_TOUCH_INFO::default(); count.min(256) as usize];
        let mut n = infos.len() as u32;
        // SAFETY: the buffer holds `n` entries.
        if unsafe { GetPointerFrameTouchInfo(id, &mut n, infos.as_mut_ptr()) } == 0 {
            return Outcome::Mouse;
        }
        infos.truncate(n as usize);
        // Only the session's own contacts, or contacts starting over it.
        let mine = |s: &State, info: &POINTER_TOUCH_INFO| {
            let p = &info.pointerInfo;
            s.active.contains_key(&p.pointerId)
                || (starts(contact_flags(p.pointerFlags))
                    && t.accepts(client_point(hwnd, p.ptPixelLocation)))
        };
        let ours = STATE.with_borrow(|s| {
            infos
                .iter()
                .any(|i| i.pointerInfo.pointerId == id && mine(s, i))
        });
        if !ours {
            return Outcome::Mouse;
        }
        let mut frame = TouchFrame::default();
        STATE.with_borrow_mut(|s| {
            for info in &infos {
                if !mine(s, info) {
                    continue;
                }
                let p = &info.pointerInfo;
                let flags = contact_flags(p.pointerFlags);
                let screen = (p.ptPixelLocation.x, p.ptPixelLocation.y);
                let (x, y) = t.map(client_point(hwnd, p.ptPixelLocation), screen);
                let contact_id = match s.active.get(&p.pointerId) {
                    Some(a) => a.contact_id,
                    None => {
                        let used = s.active.values().filter(|a| !a.pen).map(|a| a.contact_id);
                        let Some(cid) = free_id(used) else { continue };
                        cid
                    }
                };
                let mut c = TouchContact {
                    contact_id,
                    x,
                    y,
                    flags,
                    ..Default::default()
                };
                if info.touchMask & TOUCH_MASK_CONTACTAREA != 0 {
                    let r = &info.rcContact;
                    let rel = |v: i32, o: i32| (v - o).clamp(-0x3FFF, 0x3FFF) as i16;
                    c.rect = Some((
                        rel(r.left, screen.0),
                        rel(r.top, screen.1),
                        rel(r.right, screen.0),
                        rel(r.bottom, screen.1),
                    ));
                }
                if info.touchMask & TOUCH_MASK_ORIENTATION != 0 {
                    c.orientation = Some(info.orientation);
                }
                if info.touchMask & TOUCH_MASK_PRESSURE != 0 {
                    c.pressure = Some(info.pressure);
                }
                if ends(flags) {
                    s.active.remove(&p.pointerId);
                } else {
                    s.active.insert(
                        p.pointerId,
                        Active {
                            hwnd,
                            contact_id,
                            pen: false,
                            flags,
                            pos: (x, y),
                        },
                    );
                }
                frame.contacts.push(c);
            }
        });
        t.handle.send_touch(frame);
        // The frame's other pointer messages carry nothing new.
        // SAFETY: id comes from the message being handled.
        unsafe { SkipPointerFrameMessages(id) };
        Outcome::Sent
    }

    fn pen(hwnd: isize, id: u32) -> Outcome {
        let Some(t) = target(hwnd) else {
            return Outcome::Mouse;
        };
        let active = STATE.with_borrow(|s| s.active.get(&id).copied());
        if !t.handle.pen_ready() {
            STATE.with_borrow_mut(|s| s.active.remove(&id));
            return Outcome::Mouse;
        }
        let mut info = POINTER_PEN_INFO::default();
        // SAFETY: id comes from the message being handled.
        if unsafe { GetPointerPenInfo(id, &mut info) } == 0 {
            return Outcome::Mouse;
        }
        let p = &info.pointerInfo;
        let flags = contact_flags(p.pointerFlags);
        let client = client_point(hwnd, p.ptPixelLocation);
        let screen = (p.ptPixelLocation.x, p.ptPixelLocation.y);
        let inside = t.accepts(client);
        match active {
            // A hovering pen that moves off the picture leaves range there,
            // so the window's own controls get it as a mouse.
            Some(a)
                if hovering(a.flags) && !inside && flags & rdp::rdpei::CONTACT_FLAG_DOWN == 0 =>
            {
                end_hover(&t, a);
                STATE.with_borrow_mut(|s| s.active.remove(&id));
                return Outcome::Mouse;
            }
            Some(_) => {}
            None if inside && starts(flags) => {}
            None => return Outcome::Mouse,
        }
        let (x, y) = t.map(client, screen);
        let c = PenContact {
            device_id: 0,
            x,
            y,
            flags,
            pen_flags: Some(pen_flags(info.penFlags)),
            pressure: (info.penMask & PEN_MASK_PRESSURE != 0).then_some(info.pressure),
            rotation: (info.penMask & PEN_MASK_ROTATION != 0).then_some(info.rotation as u16),
            tilt_x: (info.penMask & PEN_MASK_TILT_X != 0).then_some(info.tiltX as i16),
            tilt_y: (info.penMask & PEN_MASK_TILT_Y != 0).then_some(info.tiltY as i16),
        };
        STATE.with_borrow_mut(|s| {
            if ends(flags) {
                s.active.remove(&id);
            } else {
                s.active.insert(
                    id,
                    Active {
                        hwnd,
                        contact_id: 0,
                        pen: true,
                        flags,
                        pos: (x, y),
                    },
                );
            }
        });
        t.handle.send_pen(PenFrame { contacts: vec![c] });
        Outcome::Sent
    }

    /// Hovering -> out of range at the last position (UPDATE alone).
    fn end_hover(t: &Target, a: Active) {
        if a.pen {
            t.handle.send_pen(PenFrame {
                contacts: vec![PenContact {
                    x: a.pos.0,
                    y: a.pos.1,
                    flags: CONTACT_FLAG_UPDATE,
                    ..Default::default()
                }],
            });
        } else {
            t.handle.send_touch(TouchFrame {
                contacts: vec![TouchContact {
                    contact_id: a.contact_id,
                    x: a.pos.0,
                    y: a.pos.1,
                    flags: CONTACT_FLAG_UPDATE,
                    ..Default::default()
                }],
            });
        }
    }

    /// The pointer left the window or lost capture: a hovering contact
    /// leaves range, an engaged one is cancelled.
    fn leave(hwnd: isize, id: u32) {
        let Some(a) = STATE.with_borrow_mut(|s| s.active.remove(&id)) else {
            return;
        };
        let Some(t) = target(hwnd) else { return };
        if hovering(a.flags) {
            end_hover(&t, a);
            return;
        }
        let flags = rdp::rdpei::CONTACT_FLAG_UP | rdp::rdpei::CONTACT_FLAG_CANCELED;
        if a.pen {
            t.handle.send_pen(PenFrame {
                contacts: vec![PenContact {
                    x: a.pos.0,
                    y: a.pos.1,
                    flags,
                    ..Default::default()
                }],
            });
        } else {
            t.handle.send_touch(TouchFrame {
                contacts: vec![TouchContact {
                    contact_id: a.contact_id,
                    x: a.pos.0,
                    y: a.pos.1,
                    flags,
                    ..Default::default()
                }],
            });
        }
    }

    unsafe extern "system" fn subclass_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        _id: usize,
        _data: usize,
    ) -> LRESULT {
        let h = hwnd as isize;
        let pointer_id = (wparam & 0xFFFF) as u32;
        // SAFETY (all arms): forwarding the message being handled to the
        // next window procedure in the chain or to the default one.
        unsafe {
            match msg {
                WM_POINTERDOWN | WM_POINTERUPDATE | WM_POINTERUP => match pointer(h, pointer_id) {
                    Outcome::Sent => 0,
                    Outcome::Mouse => DefWindowProcW(hwnd, msg, wparam, lparam),
                    Outcome::Pass => DefSubclassProc(hwnd, msg, wparam, lparam),
                },
                WM_POINTERLEAVE | WM_POINTERCAPTURECHANGED => {
                    leave(h, pointer_id);
                    DefSubclassProc(hwnd, msg, wparam, lparam)
                }
                WM_NCDESTROY => {
                    STATE.with_borrow_mut(|s| {
                        s.attached.retain(|&w| w != h);
                        s.targets.remove(&h);
                        s.active.retain(|_, a| a.hwnd != h);
                    });
                    RemoveWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID);
                    DefSubclassProc(hwnd, msg, wparam, lparam)
                }
                _ => DefSubclassProc(hwnd, msg, wparam, lparam),
            }
        }
    }
}

#[cfg(windows)]
pub use imp::{attach, digitizer_present, max_contacts, set_targets};

#[cfg(not(windows))]
pub fn digitizer_present() -> bool {
    false
}

#[cfg(not(windows))]
pub fn max_contacts() -> u16 {
    rdp::rdpei::DEFAULT_MAX_TOUCH_CONTACTS
}

#[cfg(not(windows))]
pub fn attach(_hwnd: isize) {}

#[cfg(not(windows))]
pub fn set_targets(_targets: Vec<(isize, Target)>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::rdpei::valid_contact_flags;

    /// POINTER_FLAG_UPDATE; `contact_flags` treats every event that is not a
    /// down or an up as an update.
    const PF_UPDATE: u32 = 0x0002_0000;

    #[test]
    fn every_pointer_state_maps_to_a_valid_combination() {
        // All combinations of the flags that matter, including ones Windows
        // never sends: the result must still be valid on the wire.
        let bits = [
            PF_INRANGE,
            PF_INCONTACT,
            PF_CANCELED,
            PF_DOWN,
            PF_UPDATE,
            PF_UP,
        ];
        for m in 0..(1u32 << bits.len()) {
            let f = bits
                .iter()
                .enumerate()
                .filter(|(i, _)| m & (1 << i) != 0)
                .fold(0, |a, (_, b)| a | b);
            assert!(valid_contact_flags(contact_flags(f)), "{f:#x}");
        }
    }

    #[test]
    fn contact_lifecycle() {
        // Touch: down, move, up (leaves range at once).
        assert_eq!(contact_flags(PF_DOWN | PF_INRANGE | PF_INCONTACT), 0x19);
        assert_eq!(contact_flags(PF_UPDATE | PF_INRANGE | PF_INCONTACT), 0x1A);
        assert_eq!(contact_flags(PF_UP), CONTACT_FLAG_UP);
        assert!(ends(contact_flags(PF_UP)));
        // Pen: hover, touch down, lift (still hovering), leave range.
        let hover = contact_flags(PF_UPDATE | PF_INRANGE);
        assert_eq!(hover, CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE);
        assert!(hovering(hover) && !ends(hover));
        let lift = contact_flags(PF_UP | PF_INRANGE);
        assert_eq!(lift, CONTACT_FLAG_UP | CONTACT_FLAG_INRANGE);
        assert!(hovering(lift) && !ends(lift));
        assert_eq!(contact_flags(PF_UPDATE), CONTACT_FLAG_UPDATE);
        assert!(ends(contact_flags(PF_UPDATE)));
        // Cancelled.
        assert_eq!(
            contact_flags(PF_UP | PF_INRANGE | PF_CANCELED),
            CONTACT_FLAG_UP | CONTACT_FLAG_CANCELED
        );
        assert!(ends(contact_flags(PF_UPDATE | PF_INCONTACT | PF_CANCELED)));
        assert!(!ends(contact_flags(PF_DOWN | PF_INRANGE | PF_INCONTACT)));
        // Only a touch-down or a hover may start a contact.
        assert!(starts(contact_flags(PF_DOWN | PF_INRANGE | PF_INCONTACT)));
        assert!(starts(hover));
        assert!(!starts(contact_flags(
            PF_UPDATE | PF_INRANGE | PF_INCONTACT
        )));
        assert!(!starts(contact_flags(PF_UP)));
    }

    #[test]
    fn pen_flags_reorder_bits() {
        assert_eq!(pen_flags(0), 0);
        assert_eq!(pen_flags(WIN_PEN_BARREL), PEN_FLAG_BARREL_PRESSED);
        assert_eq!(pen_flags(WIN_PEN_ERASER), PEN_FLAG_ERASER_PRESSED);
        assert_eq!(pen_flags(WIN_PEN_INVERTED), PEN_FLAG_INVERTED);
        assert_eq!(
            pen_flags(WIN_PEN_INVERTED | WIN_PEN_ERASER),
            PEN_FLAG_INVERTED | PEN_FLAG_ERASER_PRESSED
        );
    }

    #[test]
    fn mapping_matches_the_mouse() {
        let (_ch, handle) = rdp::touch_input(rdp::TouchOptions::default());
        // Main window: session picture at (200, 80), 1000 x 600 visible.
        let t = Target {
            handle: handle.clone(),
            accept: (200, 80, 1000, 600),
            offset: (-200, -80),
            screen: false,
            fb: (1920, 1080),
        };
        assert!(t.accepts((200, 80)));
        assert!(!t.accepts((199, 80)), "sidebar");
        assert!(!t.accepts((1200, 80)), "right of the picture");
        assert_eq!(t.map((250, 100), (0, 0)), (50, 20));
        assert_eq!(t.map((100, 50), (0, 0)), (0, 0), "clamped like the mouse");
        assert_eq!(t.map((5000, 5000), (0, 0)), (1919, 1079));
        // Span window showing the framebuffer from (1920, 0).
        let s = Target {
            offset: (1920, 0),
            accept: (0, 0, 1920, 1080),
            fb: (3840, 1080),
            ..t.clone()
        };
        assert_eq!(s.map((10, 20), (0, 0)), (1930, 20));
        // RemoteApp: screen point minus the desktop origin.
        let r = Target {
            offset: (1280, 0),
            screen: true,
            fb: (3840, 1080),
            ..t
        };
        assert_eq!(r.map((5, 5), (-1000, 300)), (280, 300));
    }

    #[test]
    fn contact_ids_reuse_the_smallest_free() {
        assert_eq!(free_id([].into_iter()), Some(0));
        assert_eq!(free_id([0u8, 1, 3].into_iter()), Some(2));
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(free_id(all.iter().copied()), None);
    }
}
