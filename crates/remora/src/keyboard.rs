//! Keyboard layout and typing translation (RDP-32).
//!
//! At connect the session gets this PC's active keyboard layout (KLID),
//! keyboard type and IME (MS-RDPBCGR 2.2.1.3.2), so the remote desktop types
//! like this PC. Keys normally go as scancodes and the remote layout decides
//! the characters. When the layouts differ (the user switched layouts with
//! Win+Space after connecting, or chose "Translate typing"), keys that type
//! text go as Unicode keyboard events (2.2.8.1.2.2.2) carrying the character
//! this PC's layout produced, including dead-key compositions and AltGr
//! characters. Shortcuts, navigation and function keys and the modifiers
//! themselves stay scancodes.

use rdp::{InputEvent, KeyboardInfo};

use crate::store::KeyboardMode;

/// Left and right Ctrl, left and right Alt (set-1 scancode, extended).
const CTRL: [(u8, bool); 2] = [(0x1D, false), (0x1D, true)];
const ALT: [(u8, bool); 2] = [(0x38, false), (0x38, true)];
const WIN: [(u8, bool); 2] = [(0x5B, true), (0x5C, true)];
const SHIFT: [(u8, bool); 2] = [(0x2A, false), (0x36, false)];
const RIGHT_ALT: (u8, bool) = (0x38, true);

fn is_modifier(k: (u8, bool)) -> bool {
    CTRL.contains(&k) || ALT.contains(&k) || WIN.contains(&k) || SHIFT.contains(&k)
}

/// One key press or release, as the decision needs it (no Win32 types).
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyInput<'a> {
    /// Set-1 scancode and E0 prefix; None for keys without one (touch
    /// keyboard, emoji panel, injected text).
    pub scancode: Option<(u8, bool)>,
    pub down: bool,
    /// The character(s) the key typed with this PC's layout and every
    /// modifier, dead-key compositions included (presses only).
    pub text: Option<&'a str>,
    /// A dead key: it types nothing yet, the next key composes.
    pub dead: bool,
    /// The AltGr key of a layout that has one.
    pub altgr: bool,
}

impl<'a> KeyInput<'a> {
    pub fn of(ev: &'a winit::event::KeyEvent) -> Self {
        use winit::keyboard::{Key, NamedKey};
        #[cfg(windows)]
        let text = {
            use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;
            ev.text_with_all_modifiers()
        };
        #[cfg(not(windows))]
        let text = ev.text.as_deref();
        let scancode = crate::session::key_event(ev).and_then(|e| match e {
            InputEvent::Key {
                scancode, extended, ..
            } => Some((scancode, extended)),
            _ => None,
        });
        KeyInput {
            scancode,
            down: ev.state.is_pressed(),
            text: text.filter(|_| ev.state.is_pressed()),
            dead: matches!(ev.logical_key, Key::Dead(_)),
            altgr: matches!(ev.logical_key, Key::Named(NamedKey::AltGraph)),
        }
    }
}

/// How the remote sees a press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The key itself, as a scancode.
    Scancode,
    /// The typed text as Unicode events; `wrap`: the remote holds Ctrl/Alt
    /// for AltGr, release them around the text so it is no shortcut.
    Unicode { wrap: bool },
    /// Nothing now (a dead key; its composition follows as text).
    Swallow,
}

/// Modifiers the remote holds, as this client sent them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub ctrl: bool,
    pub alt: bool,
    pub win: bool,
    /// The held right Alt is this PC's AltGr.
    pub altgr: bool,
}

/// Text worth translating: printable and not a plain space (the same key
/// on every layout; a space as a key keeps holding and games working).
fn types_text(text: Option<&str>) -> bool {
    text.is_some_and(|t| !t.is_empty() && t != " " && !t.chars().any(char::is_control))
}

/// Scancode or Unicode for a press while typing is translated. Shortcuts
/// (Ctrl or Alt alone, Win), modifiers and keys that type no text stay
/// scancodes; AltGr (or Ctrl+Alt) text is wrapped.
pub fn decide(k: &KeyInput, translate: bool, m: Mods) -> Decision {
    if !translate || k.scancode.is_some_and(is_modifier) || k.altgr {
        return Decision::Scancode;
    }
    let altgr = m.altgr || (m.ctrl && m.alt);
    let shortcut = m.win || (!altgr && (m.ctrl || m.alt));
    if shortcut {
        return Decision::Scancode;
    }
    if k.dead {
        return Decision::Swallow;
    }
    if types_text(k.text) {
        return Decision::Unicode { wrap: altgr };
    }
    Decision::Scancode
}

/// Whether typing is translated: by the setting, and for Automatic when
/// this PC's layout is not the one the session got at connect.
pub fn translating(mode: KeyboardMode, connect_klid: u32, local_klid: u32) -> bool {
    match mode {
        KeyboardMode::Remote => false,
        KeyboardMode::Translate => true,
        // A custom layout went as its language's standard layout.
        KeyboardMode::Auto => local_klid != connect_klid || is_custom(connect_klid),
    }
}

fn unicode_pairs(text: &str, out: &mut Vec<InputEvent>) {
    for code in text.encode_utf16() {
        out.push(InputEvent::Unicode { code, down: true });
        out.push(InputEvent::Unicode { code, down: false });
    }
}

fn key(k: (u8, bool), down: bool) -> InputEvent {
    InputEvent::Key {
        scancode: k.0,
        extended: k.1,
        down,
    }
}

/// One session's keyboard state.
#[derive(Debug)]
pub struct Keys {
    /// This PC's layout (KLID) when the session connected.
    connect_klid: u32,
    /// The layout the session got (keyboardLayout).
    pub sent_layout: u32,
    /// The server takes Unicode keyboard events (INPUT_FLAG_UNICODE).
    unicode: bool,
    /// "No Unicode input" was logged.
    warned: bool,
    /// Modifier keys the remote holds, in press order.
    held: Vec<(u8, bool)>,
    /// The held right Alt is this PC's AltGr.
    altgr: bool,
    /// Keys whose last press went as text or was swallowed: their release
    /// is not sent.
    translated: Vec<(u8, bool)>,
}

impl Keys {
    pub fn new(connect_klid: u32, sent_layout: u32) -> Self {
        Keys {
            connect_klid,
            sent_layout,
            unicode: false,
            warned: false,
            held: Vec::new(),
            altgr: false,
            translated: Vec::new(),
        }
    }

    /// The session is up; `unicode`: the server announced INPUT_FLAG_UNICODE.
    pub fn connected(&mut self, unicode: bool) {
        self.unicode = unicode;
    }

    /// Notes what is sent to the remote (every key event goes through here,
    /// also hook keys and modifier releases), to know what it holds.
    pub fn observe(&mut self, events: &[InputEvent]) {
        for e in events {
            if let InputEvent::Key {
                scancode,
                extended,
                down,
            } = *e
            {
                let k = (scancode, extended);
                if !is_modifier(k) {
                    continue;
                }
                self.held.retain(|h| *h != k);
                if down {
                    self.held.push(k);
                }
            }
        }
    }

    pub fn mods(&self) -> Mods {
        let held = |set: &[(u8, bool)]| self.held.iter().any(|k| set.contains(k));
        Mods {
            ctrl: held(&CTRL),
            alt: held(&ALT),
            win: held(&WIN),
            altgr: self.altgr && self.held.contains(&RIGHT_ALT),
        }
    }

    /// Whether typing is translated now, for the tab's setting and this PC's
    /// current layout.
    pub fn translating(&self, mode: KeyboardMode, local_klid: u32) -> bool {
        translating(mode, self.connect_klid, local_klid)
    }

    /// The events for one key press or release.
    pub fn key(&mut self, k: &KeyInput, mode: KeyboardMode, local_klid: u32) -> Vec<InputEvent> {
        let mut out = Vec::new();
        let Some(sc) = k.scancode else {
            // No scancode: only the text can go, and only as Unicode.
            if k.down
                && self.unicode
                && let Some(text) = k.text.filter(|t| !t.chars().any(char::is_control))
            {
                unicode_pairs(text, &mut out);
            }
            return out;
        };
        if !k.down {
            if sc == RIGHT_ALT {
                self.altgr = false;
            }
            if let Some(i) = self.translated.iter().position(|t| *t == sc) {
                self.translated.swap_remove(i);
            } else {
                out.push(key(sc, false));
            }
            return out;
        }
        let mut translate = self.translating(mode, local_klid);
        if translate && !self.unicode {
            if !self.warned {
                self.warned = true;
                rdp::trace!("keyboard: the server takes no Unicode input; keys go as scancodes");
            }
            translate = false;
        }
        if sc == RIGHT_ALT {
            // Its releases around AltGr text are ours; the press says what it is.
            self.altgr = k.altgr;
        }
        self.translated.retain(|t| *t != sc);
        match decide(k, translate, self.mods()) {
            Decision::Scancode => out.push(key(sc, true)),
            Decision::Swallow => self.translated.push(sc),
            Decision::Unicode { wrap } => {
                self.translated.push(sc);
                let lift: Vec<(u8, bool)> = if wrap {
                    self.held
                        .iter()
                        .copied()
                        .filter(|h| CTRL.contains(h) || ALT.contains(h))
                        .collect()
                } else {
                    Vec::new()
                };
                out.extend(lift.iter().map(|&h| key(h, false)));
                unicode_pairs(k.text.unwrap_or_default(), &mut out);
                out.extend(lift.iter().map(|&h| key(h, true)));
            }
        }
        out
    }
}

/// A layout id from a third-party or self-made layout ("a0000407"): the
/// server has none of those, so it gets the language's standard layout.
pub fn is_custom(klid: u32) -> bool {
    !matches!(klid >> 28, 0x0 | 0xE)
}

/// The keyboardLayout to send for this PC's layout.
pub fn server_layout(klid: u32) -> u32 {
    if is_custom(klid) { klid & 0xFFFF } else { klid }
}

/// A layout id from a keyboard layout handle, when Windows gives no name:
/// the high word is the layout's language, a device handle (0xFxxx, the
/// layout itself is then unknown), or for an IME the whole handle.
pub fn klid_from_hkl(hkl: usize) -> u32 {
    let lang = (hkl & 0xFFFF) as u32;
    let device = ((hkl >> 16) & 0xFFFF) as u32;
    match device & 0xF000 {
        0xE000 => (device << 16) | lang,
        0xF000 => lang,
        _ if device == 0 => lang,
        _ => device,
    }
}

/// This PC's keyboard as the session should get it: its current layout
/// (raw KLID) and what is sent for it.
pub fn local() -> (u32, KeyboardInfo) {
    let klid = local_klid();
    let mut info = KeyboardInfo {
        layout: server_layout(klid),
        ..KeyboardInfo::default()
    };
    #[cfg(windows)]
    {
        let kind = win::keyboard_type(0);
        if kind != 0 {
            info.kind = kind;
            info.subtype = win::keyboard_type(1);
            info.function_keys = match win::keyboard_type(2) {
                0 => 12,
                n => n,
            };
        }
        info.ime_file_name = win::ime_file_name(win::hkl());
    }
    (klid, info)
}

/// The active layout of the calling (UI) thread, as a KLID.
pub fn local_klid() -> u32 {
    #[cfg(windows)]
    {
        use std::cell::Cell;
        thread_local! {
            static LAST: Cell<(usize, u32)> = const { Cell::new((0, 0)) };
        }
        let hkl = win::hkl();
        let (h, k) = LAST.get();
        if h == hkl && hkl != 0 {
            return k;
        }
        let klid = win::layout_name().unwrap_or_else(|| match klid_from_hkl(hkl) {
            0 => 0x0409,
            k => k,
        });
        LAST.set((hkl, klid));
        klid
    }
    #[cfg(not(windows))]
    0x0409
}

/// A short readable layout name, in English like the rest of the app:
/// "German (Germany)", "English (US), Dvorak".
pub fn layout_name(layout: u32) -> String {
    let lang = (layout & 0xFFFF) as u16;
    let short = |s: String| {
        s.replace(" (United States)", " (US)")
            .replace(" (United Kingdom)", " (UK)")
    };
    #[cfg(windows)]
    let found = win::language_name(lang);
    #[cfg(not(windows))]
    let found: Option<String> = None;
    let base = found
        .or_else(|| builtin_language(lang).map(str::to_string))
        .map(short)
        .unwrap_or_else(|| format!("Layout {layout:08X}"));
    match layout >> 16 {
        0 => base,
        v if v & 0xF000 == 0xE000 => format!("{base}, IME"),
        v => match variant(layout) {
            Some(n) => format!("{base}, {n}"),
            None => format!("{base}, variant {v}"),
        },
    }
}

fn builtin_language(lang: u16) -> Option<&'static str> {
    Some(match lang {
        0x0409 => "English (United States)",
        0x0809 => "English (United Kingdom)",
        0x0407 => "German (Germany)",
        0x0807 => "German (Switzerland)",
        0x0C07 => "German (Austria)",
        0x040C => "French (France)",
        0x080C => "French (Belgium)",
        0x100C => "French (Switzerland)",
        0x0C0C => "French (Canada)",
        0x0410 => "Italian (Italy)",
        0x040A | 0x0C0A => "Spanish (Spain)",
        0x0413 => "Dutch (Netherlands)",
        0x0813 => "Dutch (Belgium)",
        0x0816 => "Portuguese (Portugal)",
        0x0416 => "Portuguese (Brazil)",
        0x0406 => "Danish (Denmark)",
        0x0414 => "Norwegian (Norway)",
        0x041D => "Swedish (Sweden)",
        0x040B => "Finnish (Finland)",
        0x0415 => "Polish (Poland)",
        0x0405 => "Czech (Czechia)",
        0x040E => "Hungarian (Hungary)",
        0x0419 => "Russian (Russia)",
        0x0422 => "Ukrainian (Ukraine)",
        0x0408 => "Greek (Greece)",
        0x0411 => "Japanese (Japan)",
        0x0412 => "Korean (Korea)",
        0x0804 => "Chinese (China)",
        0x0404 => "Chinese (Taiwan)",
        _ => return None,
    })
}

fn variant(layout: u32) -> Option<&'static str> {
    Some(match layout {
        0x0001_0409 => "Dvorak",
        0x0002_0409 => "International",
        0x0003_0409 => "Dvorak for left hand",
        0x0004_0409 => "Dvorak for right hand",
        0x0001_0407 => "IBM",
        _ => return None,
    })
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Globalization::{
        GetLocaleInfoEx, LCIDToLocaleName, LOCALE_ALLOW_NEUTRAL_NAMES, LOCALE_SENGLISHDISPLAYNAME,
    };
    use windows_sys::Win32::UI::Input::Ime::ImmGetIMEFileNameW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetKeyboardLayout, GetKeyboardLayoutNameW, GetKeyboardType,
    };

    fn until_nul(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    /// The calling thread's keyboard layout handle.
    pub fn hkl() -> usize {
        // SAFETY: plain query for the calling thread.
        unsafe { GetKeyboardLayout(0) as usize }
    }

    /// The calling thread's active layout by name (KLID): right also where
    /// the handle's high word is a device handle ("Layout Id" layouts such
    /// as Dvorak, 0xF002xxxx).
    pub fn layout_name() -> Option<u32> {
        let mut buf = [0u16; 9]; // KL_NAMELENGTH
        // SAFETY: the buffer holds KL_NAMELENGTH units, as required.
        if unsafe { GetKeyboardLayoutNameW(buf.as_mut_ptr()) } == 0 {
            return None;
        }
        rdp::input::parse_klid(&until_nul(&buf))
    }

    /// GetKeyboardType: 0 type, 1 subtype, 2 function keys; 0 on failure.
    pub fn keyboard_type(flag: i32) -> u32 {
        // SAFETY: plain query.
        unsafe { GetKeyboardType(flag) }.max(0) as u32
    }

    /// The IME file name of an IME layout; empty for others.
    pub fn ime_file_name(hkl: usize) -> String {
        let mut buf = [0u16; 128];
        // SAFETY: the length passed is at most the buffer's, whether read
        // as bytes or as characters.
        let n = unsafe { ImmGetIMEFileNameW(hkl as _, buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            String::new()
        } else {
            until_nul(&buf)
        }
    }

    /// The English display name of a language id ("German (Germany)").
    pub fn language_name(lang: u16) -> Option<String> {
        let mut name = [0u16; 85]; // LOCALE_NAME_MAX_LENGTH
        // SAFETY: the buffer and its length in characters.
        let n = unsafe {
            LCIDToLocaleName(
                lang as u32,
                name.as_mut_ptr(),
                name.len() as i32,
                LOCALE_ALLOW_NEUTRAL_NAMES,
            )
        };
        if n <= 0 {
            return None;
        }
        let mut out = [0u16; 128];
        // SAFETY: a null-terminated locale name; the buffer and its length.
        let m = unsafe {
            GetLocaleInfoEx(
                name.as_ptr(),
                LOCALE_SENGLISHDISPLAYNAME,
                out.as_mut_ptr(),
                out.len() as i32,
            )
        };
        (m > 1).then(|| until_nul(&out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: (u8, bool) = (0x1E, false); // A key (Q on AZERTY)
    const Q: (u8, bool) = (0x10, false);
    const DEL: (u8, bool) = (0x53, true);
    const F5: (u8, bool) = (0x3F, false);
    const SPACE: (u8, bool) = (0x39, false);
    const ENTER: (u8, bool) = (0x1C, false);
    const CARET: (u8, bool) = (0x29, false);
    const GERMAN: u32 = 0x0407;
    const US: u32 = 0x0409;

    /// Compact form: "k1E+" key down, "k38e-" extended key up, "u0040+".
    fn show(events: &[InputEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match *e {
                InputEvent::Key {
                    scancode,
                    extended,
                    down,
                } => format!(
                    "k{scancode:02X}{}{}",
                    if extended { "e" } else { "" },
                    if down { "+" } else { "-" }
                ),
                InputEvent::Unicode { code, down } => {
                    format!("u{code:04X}{}", if down { "+" } else { "-" })
                }
                InputEvent::Mouse { .. } => "mouse".into(),
            })
            .collect()
    }

    /// A connected session (German layout at connect, Unicode supported);
    /// `send` passes through `observe` as the app's send does.
    struct S {
        keys: Keys,
        mode: KeyboardMode,
        local: u32,
    }

    impl S {
        fn new(mode: KeyboardMode, local: u32) -> S {
            let mut keys = Keys::new(GERMAN, GERMAN);
            keys.connected(true);
            S { keys, mode, local }
        }
        fn send(&mut self, k: KeyInput) -> Vec<String> {
            let ev = self.keys.key(&k, self.mode, self.local);
            self.keys.observe(&ev);
            show(&ev)
        }
        fn press(&mut self, sc: (u8, bool), text: Option<&str>) -> Vec<String> {
            self.send(KeyInput {
                scancode: Some(sc),
                down: true,
                text,
                ..Default::default()
            })
        }
        fn release(&mut self, sc: (u8, bool)) -> Vec<String> {
            self.send(KeyInput {
                scancode: Some(sc),
                down: false,
                ..Default::default()
            })
        }
    }

    #[test]
    fn automatic_follows_the_layout_switch() {
        // Same layout as at connect: keys stay keys, as before.
        let mut s = S::new(KeyboardMode::Auto, GERMAN);
        assert_eq!(s.press(A, Some("a")), ["k1E+"]);
        assert_eq!(s.release(A), ["k1E-"]);
        // Switched to US English locally: text goes as typed here.
        s.local = US;
        assert_eq!(s.press(A, Some("a")), ["u0061+", "u0061-"]);
        assert_eq!(s.release(A), Vec::<String>::new());
        // Remote layout: always the key.
        s.mode = KeyboardMode::Remote;
        assert_eq!(s.press(A, Some("a")), ["k1E+"]);
        assert_eq!(s.release(A), ["k1E-"]);
    }

    #[test]
    fn shortcuts_and_special_keys_stay_keys() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        let keys = |s: &mut S, sc, text| {
            let d = s.press(sc, text);
            let u = s.release(sc);
            (d, u)
        };
        // Plain and shifted text is translated.
        assert_eq!(keys(&mut s, A, Some("a")).0, ["u0061+", "u0061-"]);
        assert_eq!(s.press((0x2A, false), None), ["k2A+"]);
        assert_eq!(keys(&mut s, A, Some("A")).0, ["u0041+", "u0041-"]);
        assert_eq!(s.release((0x2A, false)), ["k2A-"]);
        // Control characters, space, and keys without text are keys.
        assert_eq!(
            keys(&mut s, ENTER, Some("\r")),
            (vec!["k1C+".into()], vec!["k1C-".into()])
        );
        assert_eq!(keys(&mut s, SPACE, Some(" ")).0, ["k39+"]);
        assert_eq!(keys(&mut s, F5, None).0, ["k3F+"]);
        // Ctrl+C, Alt+F (WM_SYSCHAR text), Win+E (hook-sent Win).
        for (m, name) in [
            ((0x1D, false), "ctrl"),
            ((0x38, false), "alt"),
            ((0x5B, true), "win"),
        ] {
            s.press(m, None);
            assert_eq!(
                keys(&mut s, A, Some("a")),
                (vec!["k1E+".into()], vec!["k1E-".into()]),
                "{name}"
            );
            s.release(m);
        }
        // Ctrl+Alt+Del and a Ctrl+Alt shortcut without text are keys.
        s.press((0x1D, false), None);
        s.press((0x38, false), None);
        assert_eq!(keys(&mut s, DEL, None).0, ["k53e+"]);
        assert_eq!(keys(&mut s, A, None).0, ["k1E+"]);
        assert_eq!(s.release((0x38, false)), ["k38-"]);
        assert_eq!(s.release((0x1D, false)), ["k1D-"]);
        // Modifiers themselves are always keys.
        assert_eq!(s.press((0x36, false), Some("x")), ["k36+"]);
    }

    #[test]
    fn altgr_text_lifts_the_remote_modifiers() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        // AltGr (winit drops the fake left Ctrl): the right Alt goes.
        let altgr = KeyInput {
            scancode: Some(RIGHT_ALT),
            down: true,
            altgr: true,
            ..Default::default()
        };
        assert_eq!(s.send(altgr), ["k38e+"]);
        assert_eq!(
            s.press(Q, Some("@")),
            ["k38e-", "u0040+", "u0040-", "k38e+"]
        );
        assert_eq!(s.release(Q), Vec::<String>::new());
        // Held AltGr: repeats and the next character work the same.
        assert_eq!(s.press(Q, Some("@")).len(), 4);
        assert_eq!(s.release(RIGHT_ALT), ["k38e-"]);
        assert_eq!(s.keys.mods(), Mods::default());
        // Right Alt of a layout without AltGr is Alt: a shortcut.
        assert_eq!(s.press(RIGHT_ALT, None), ["k38e+"]);
        assert_eq!(s.press(A, Some("a")), ["k1E+"]);
        s.release(A);
        s.release(RIGHT_ALT);
        // Left Ctrl + left Alt typing a character: both lifted, in order.
        s.press((0x1D, false), None);
        s.press((0x38, false), None);
        assert_eq!(
            s.press(Q, Some("@")),
            ["k1D-", "k38-", "u0040+", "u0040-", "k1D+", "k38+"]
        );
        assert!(s.keys.mods().ctrl && s.keys.mods().alt, "restored");
    }

    #[test]
    fn dead_keys_compose_locally() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        let dead = KeyInput {
            scancode: Some(CARET),
            down: true,
            dead: true,
            ..Default::default()
        };
        assert_eq!(s.send(dead), Vec::<String>::new());
        assert_eq!(s.release(CARET), Vec::<String>::new());
        assert_eq!(s.press((0x12, false), Some("ê")), ["u00EA+", "u00EA-"]);
        // Dead key then space types the accent itself.
        s.send(dead);
        assert_eq!(s.press(SPACE, Some("^")), ["u005E+", "u005E-"]);
        // Remote layout: the dead key goes, the remote composes.
        s.mode = KeyboardMode::Remote;
        assert_eq!(s.send(dead), ["k29+"]);
    }

    #[test]
    fn repeat_and_stale_releases() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        // Auto-repeat: every press types again; one release.
        assert_eq!(s.press(A, Some("a")).len(), 2);
        assert_eq!(s.press(A, Some("a")).len(), 2);
        assert_eq!(s.release(A), Vec::<String>::new());
        // A translated press whose release was lost (focus change) must not
        // eat the release of the next press as a key.
        s.press(A, Some("a"));
        s.mode = KeyboardMode::Remote;
        assert_eq!(s.press(A, Some("a")), ["k1E+"]);
        assert_eq!(s.release(A), ["k1E-"]);
    }

    #[test]
    fn no_unicode_from_the_server_means_keys() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        s.keys.connected(false);
        assert_eq!(s.press(A, Some("a")), ["k1E+"]);
        assert_eq!(s.release(A), ["k1E-"]);
        // Text without a scancode cannot go at all.
        let emoji = KeyInput {
            down: true,
            text: Some("😀"),
            ..Default::default()
        };
        assert_eq!(s.send(emoji), Vec::<String>::new());
        s.keys.connected(true);
        assert_eq!(s.send(emoji), ["uD83D+", "uD83D-", "uDE00+", "uDE00-"]);
    }

    #[test]
    fn modifier_releases_clear_the_held_state() {
        let mut s = S::new(KeyboardMode::Translate, GERMAN);
        s.send(KeyInput {
            scancode: Some(RIGHT_ALT),
            down: true,
            altgr: true,
            ..Default::default()
        });
        s.press((0x1D, false), None);
        s.keys.observe(&crate::session::release_modifiers());
        assert_eq!(s.keys.mods(), Mods::default());
        assert_eq!(s.press(A, Some("a")), ["u0061+", "u0061-"]);
    }

    #[test]
    fn automatic_translates_from_a_custom_layout() {
        assert!(!translating(KeyboardMode::Auto, GERMAN, GERMAN));
        assert!(translating(KeyboardMode::Auto, GERMAN, 0x0807));
        assert!(translating(KeyboardMode::Auto, 0xA000_0407, 0xA000_0407));
        assert!(!translating(KeyboardMode::Remote, GERMAN, US));
        assert!(translating(KeyboardMode::Translate, GERMAN, GERMAN));
    }

    #[test]
    fn layout_ids() {
        assert_eq!(server_layout(0x0001_0409), 0x0001_0409);
        assert_eq!(server_layout(0xE001_0411), 0xE001_0411, "IME");
        assert_eq!(server_layout(0xA000_0407), 0x0407, "custom");
        // Handles: language + layout, device handle, IME, plain.
        assert_eq!(klid_from_hkl(0x0407_0409), 0x0407);
        assert_eq!(klid_from_hkl(0xF002_0409), 0x0409);
        assert_eq!(klid_from_hkl(0xE001_0411), 0xE001_0411);
        assert_eq!(klid_from_hkl(0x0000_0807), 0x0807);
    }

    #[test]
    fn layout_names() {
        let n = layout_name(0x0407);
        assert!(n.starts_with("German"), "{n}");
        assert!(layout_name(0x0001_0409).ends_with(" (US), Dvorak"));
        assert!(layout_name(0x0005_0408).ends_with(", variant 5"));
        assert_eq!(builtin_language(0x0807), Some("German (Switzerland)"));
    }
}
