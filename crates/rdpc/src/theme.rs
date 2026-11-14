//! Design tokens: the colours, spacing, radii and type sizes every screen
//! draws with. Nothing in the UI code names a raw colour; it asks the
//! current [`Palette`] for a semantic role (`pal().surface`, `pal().danger`).
//!
//! Three themes: Dark (the default, a deep blue-black with a teal accent
//! that reads as "connected"), Light (near-white with white cards), and
//! System, which follows Windows' "apps use light theme" choice.
//!
//! Remote rule (ffwd decision 0001): solid fills first. Alpha is kept for
//! the dialog scrim and its shadow; everything else is a flat colour, which
//! codecs compress well when rdpc itself runs inside a remote session.

use std::cell::Cell;

/// Every colour role of one theme (0xRRGGBB).
#[derive(Debug)]
pub struct Palette {
    pub dark: bool,
    /// Content area (editor, settings, session background).
    pub bg: u32,
    /// Window chrome: sidebar, tab strip, status bar.
    pub bg_sidebar: u32,
    /// Cards and bars on the content area.
    pub surface: u32,
    /// Controls, popovers and dialogs above a surface.
    pub surface_raised: u32,
    pub surface_hover: u32,
    pub surface_pressed: u32,
    /// Text fields: an inset well.
    pub field: u32,
    /// The selected sidebar row.
    pub selected: u32,
    /// Selected text in a field.
    pub text_selection: u32,
    pub border: u32,
    pub border_strong: u32,
    /// Lines between rows inside a card.
    pub divider: u32,
    pub text: u32,
    /// Labels next to controls.
    pub text_secondary: u32,
    /// Second lines, captions.
    pub text_muted: u32,
    /// Placeholders, hints, disabled.
    pub text_faint: u32,
    pub accent: u32,
    pub accent_hover: u32,
    pub accent_pressed: u32,
    /// Text and glyphs on an accent fill.
    pub accent_text: u32,
    /// Tinted background of accent pills, chosen segments, banners.
    pub accent_subtle: u32,
    pub focus_ring: u32,
    pub success: u32,
    pub success_subtle: u32,
    pub warning: u32,
    pub warning_subtle: u32,
    pub danger: u32,
    pub danger_subtle: u32,
    pub info: u32,
    pub info_subtle: u32,
    /// Dims the window behind a dialog: colour and alpha (0..=255).
    pub scrim: (u32, u32),
    /// Dialog shadow: colour and peak alpha.
    pub shadow: (u32, u32),
    /// Text and glyphs on a saturated fill (danger button, caption close,
    /// colour swatch, switch knob).
    pub on_solid: u32,
    /// Windows' own close-button red (caption).
    pub close_hover: u32,
    pub close_pressed: u32,
    /// Scroll bar thumb.
    pub scrollbar: u32,
}

/// Mixes `a` towards `b` by `t`/255 (const, for the palettes below).
pub const fn mix(a: u32, b: u32, t: u32) -> u32 {
    const fn ch(a: u32, b: u32, t: u32, s: u32) -> u32 {
        let x = (a >> s) & 0xff;
        let y = (b >> s) & 0xff;
        ((x * (255 - t) + y * t + 127) / 255) & 0xff
    }
    (ch(a, b, t, 16) << 16) | (ch(a, b, t, 8) << 8) | ch(a, b, t, 0)
}

const fn pct(p: u32) -> u32 {
    p * 255 / 100
}

mod dark {
    pub const BG: u32 = 0x0f1217;
    pub const SIDEBAR: u32 = 0x0a0c10;
    pub const SURFACE: u32 = 0x151920;
    pub const RAISED: u32 = 0x1b2029;
    pub const ACCENT: u32 = 0x2ec4b6;
    pub const SUCCESS: u32 = 0x3dd68c;
    pub const WARNING: u32 = 0xf5b942;
    pub const DANGER: u32 = 0xf2585d;
    pub const INFO: u32 = 0x5aa9ff;
}

pub static DARK: Palette = Palette {
    dark: true,
    bg: dark::BG,
    bg_sidebar: dark::SIDEBAR,
    surface: dark::SURFACE,
    surface_raised: dark::RAISED,
    surface_hover: 0x232933,
    surface_pressed: 0x2b323e,
    field: 0x0c0f13,
    selected: mix(0x161b22, dark::ACCENT, pct(7)),
    text_selection: mix(dark::RAISED, dark::ACCENT, pct(38)),
    border: 0x252b35,
    border_strong: 0x37404d,
    divider: 0x1e232b,
    text: 0xe9edf2,
    text_secondary: 0xbcc4ce,
    text_muted: 0x8a94a1,
    text_faint: 0x5f6976,
    accent: dark::ACCENT,
    accent_hover: 0x55d9cc,
    accent_pressed: 0x22a99c,
    accent_text: 0x03211d,
    accent_subtle: mix(dark::SURFACE, dark::ACCENT, pct(14)),
    focus_ring: mix(dark::BG, dark::ACCENT, pct(60)),
    success: dark::SUCCESS,
    success_subtle: mix(dark::SURFACE, dark::SUCCESS, pct(15)),
    warning: dark::WARNING,
    warning_subtle: mix(dark::SURFACE, dark::WARNING, pct(14)),
    danger: dark::DANGER,
    danger_subtle: mix(dark::SURFACE, dark::DANGER, pct(14)),
    info: dark::INFO,
    info_subtle: mix(dark::SURFACE, dark::INFO, pct(14)),
    scrim: (0x030406, 165),
    on_solid: 0xffffff,
    shadow: (0x000000, 110),
    close_hover: 0xc42b1c,
    close_pressed: 0x9e2a1f,
    scrollbar: 0x343c48,
};

mod light {
    pub const BG: u32 = 0xf7f8fa;
    pub const SIDEBAR: u32 = 0xeceff3;
    pub const SURFACE: u32 = 0xffffff;
    pub const ACCENT: u32 = 0x0d9e91;
    pub const SUCCESS: u32 = 0x18975a;
    pub const WARNING: u32 = 0xb7761a;
    pub const DANGER: u32 = 0xd6383f;
    pub const INFO: u32 = 0x2b74db;
}

pub static LIGHT: Palette = Palette {
    dark: false,
    bg: light::BG,
    bg_sidebar: light::SIDEBAR,
    surface: light::SURFACE,
    surface_raised: 0xffffff,
    surface_hover: 0xeef1f4,
    surface_pressed: 0xe3e7ec,
    field: 0xf6f7f9,
    selected: mix(0xffffff, light::ACCENT, pct(10)),
    text_selection: mix(0xffffff, light::ACCENT, pct(28)),
    border: 0xdfe3e8,
    border_strong: 0xc5cbd3,
    divider: 0xebedf0,
    text: 0x14181d,
    text_secondary: 0x3b434d,
    text_muted: 0x636d79,
    text_faint: 0x959da7,
    accent: light::ACCENT,
    accent_hover: 0x0b897e,
    accent_pressed: 0x08756b,
    accent_text: 0xffffff,
    accent_subtle: mix(light::SURFACE, light::ACCENT, pct(11)),
    focus_ring: mix(light::BG, light::ACCENT, pct(55)),
    success: light::SUCCESS,
    success_subtle: mix(light::SURFACE, light::SUCCESS, pct(11)),
    warning: light::WARNING,
    warning_subtle: mix(light::SURFACE, light::WARNING, pct(12)),
    danger: light::DANGER,
    danger_subtle: mix(light::SURFACE, light::DANGER, pct(9)),
    info: light::INFO,
    info_subtle: mix(light::SURFACE, light::INFO, pct(10)),
    scrim: (0x0e1116, 95),
    on_solid: 0xffffff,
    shadow: (0x1a2230, 46),
    close_hover: 0xc42b1c,
    close_pressed: 0x9e2a1f,
    scrollbar: 0xc5cbd3,
};

thread_local! {
    static CURRENT: Cell<&'static Palette> = const { Cell::new(&DARK) };
}

/// The palette the UI paints with now (per UI thread).
pub fn pal() -> &'static Palette {
    CURRENT.with(Cell::get)
}

/// Switches the palette; the caller repaints.
pub fn set(p: &'static Palette) {
    CURRENT.with(|c| c.set(p));
}

/// The user's theme choice (saved in settings.json).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeChoice {
    #[default]
    Dark,
    Light,
    /// Follows Windows' app theme (light or dark).
    System,
}

impl ThemeChoice {
    pub const ALL: [ThemeChoice; 3] = [ThemeChoice::Dark, ThemeChoice::Light, ThemeChoice::System];

    pub fn label(self) -> &'static str {
        match self {
            ThemeChoice::Dark => "Dark",
            ThemeChoice::Light => "Light",
            ThemeChoice::System => "System",
        }
    }

    /// The palette for this choice; `system_light` is Windows' setting.
    pub fn palette(self, system_light: bool) -> &'static Palette {
        match self {
            ThemeChoice::Dark => &DARK,
            ThemeChoice::Light => &LIGHT,
            ThemeChoice::System if system_light => &LIGHT,
            ThemeChoice::System => &DARK,
        }
    }
}

/// What a status message, note or pill means; its colour comes from the
/// current palette, so a theme switch recolours text already on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Muted,
    Accent,
    Success,
    Warning,
    Danger,
    Info,
}

impl Tone {
    /// Foreground: text, icon, dot.
    pub fn color(self) -> u32 {
        let p = pal();
        match self {
            Tone::Neutral => p.text_secondary,
            Tone::Muted => p.text_muted,
            Tone::Accent => p.accent,
            Tone::Success => p.success,
            Tone::Warning => p.warning,
            Tone::Danger => p.danger,
            Tone::Info => p.info,
        }
    }

    /// Tinted background for pills and banners.
    pub fn subtle(self) -> u32 {
        let p = pal();
        match self {
            Tone::Neutral | Tone::Muted => p.surface_hover,
            Tone::Accent => p.accent_subtle,
            Tone::Success => p.success_subtle,
            Tone::Warning => p.warning_subtle,
            Tone::Danger => p.danger_subtle,
            Tone::Info => p.info_subtle,
        }
    }
}

/// Spacing scale in logical pixels (multiply by the UI scale). The whole
/// scale is offered; screens pick their steps from it.
#[allow(dead_code)]
pub mod space {
    pub const XS: f32 = 4.0;
    pub const S: f32 = 8.0;
    pub const M: f32 = 12.0;
    pub const L: f32 = 16.0;
    pub const XL: f32 = 24.0;
    pub const XXL: f32 = 32.0;
}

/// Corner radii in logical pixels; a pill uses half its height.
pub mod radius {
    pub const CONTROL: f32 = 6.0;
    pub const CARD: f32 = 10.0;
    pub const DIALOG: f32 = 14.0;
}

/// Type scale in logical pixels: size and whether it is semibold.
pub mod size {
    /// Page titles (semibold).
    pub const TITLE: f32 = 22.0;
    /// Card and dialog headings (semibold).
    pub const HEADING: f32 = 15.0;
    pub const BODY: f32 = 13.0;
    pub const SMALL: f32 = 12.0;
    /// Upper-case section labels (semibold).
    pub const CAPTION: f32 = 11.0;
}

/// Control heights in logical pixels.
#[allow(dead_code)]
pub mod height {
    pub const SMALL: f32 = 28.0;
    pub const CONTROL: f32 = 32.0;
    pub const LARGE: f32 = 36.0;
}

/// The group colours: name and base colour. Groups pick one (or get one
/// from their name); connections show their group's colour.
pub const GROUP_COLORS: [(&str, u32); 8] = [
    ("Teal", 0x2ec4b6),
    ("Blue", 0x4c8dff),
    ("Violet", 0x8f6cff),
    ("Pink", 0xec5fa6),
    ("Orange", 0xff8a3d),
    ("Amber", 0xf0b230),
    ("Green", 0x48c774),
    ("Slate", 0x8391a7),
];

/// A stable colour index for a name (groups without a chosen colour,
/// connections outside groups).
pub fn color_for_name(name: &str) -> usize {
    // FNV-1a over the lower-case name: stable across runs and versions.
    let mut h: u32 = 0x811c9dc5;
    for b in name.to_lowercase().bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    (h % GROUP_COLORS.len() as u32) as usize
}

/// A group colour as a solid dot or bar in the current theme.
pub fn group_solid(i: usize) -> u32 {
    let c = GROUP_COLORS[i % GROUP_COLORS.len()].1;
    if pal().dark {
        c
    } else {
        mix(c, 0x000000, pct(12))
    }
}

/// An avatar tile in group colour `i`: (fill, monogram colour).
pub fn group_tile(i: usize) -> (u32, u32) {
    let c = GROUP_COLORS[i % GROUP_COLORS.len()].1;
    let p = pal();
    if p.dark {
        (mix(p.surface, c, pct(24)), mix(c, 0xffffff, pct(28)))
    } else {
        (mix(0xffffff, c, pct(17)), mix(c, 0x000000, pct(38)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_ends_and_middle() {
        assert_eq!(mix(0x000000, 0xffffff, 0), 0x000000);
        assert_eq!(mix(0x000000, 0xffffff, 255), 0xffffff);
        assert_eq!(mix(0x000000, 0xff00ff, 128), 0x800080);
    }

    #[test]
    fn theme_choice_reads_old_and_new_settings() {
        let c: ThemeChoice = serde_json::from_str("\"system\"").unwrap();
        assert_eq!(c, ThemeChoice::System);
        assert!(std::ptr::eq(ThemeChoice::System.palette(true), &LIGHT));
        assert!(std::ptr::eq(ThemeChoice::System.palette(false), &DARK));
    }

    #[test]
    fn group_colours_are_stable() {
        assert_eq!(color_for_name("Work"), color_for_name("work"));
        assert!(color_for_name("anything") < GROUP_COLORS.len());
    }
}
