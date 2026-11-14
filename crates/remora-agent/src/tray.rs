//! What the tray icon shows: its status dot, tooltip, menu and
//! notifications. Plain data, so it is tested without a shell; the Windows
//! side (`win::tray`) only draws and runs it.

use crate::seam::{AgentStatus, Notice, Phase};

/// The status dot drawn on the icon's lower right corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot {
    /// Waiting for Remora (or connecting).
    Grey,
    /// Paired and connected.
    Green,
    /// The pairing dialog waits for the user.
    Amber,
}

impl Dot {
    pub const ALL: [Dot; 3] = [Dot::Grey, Dot::Green, Dot::Amber];

    pub fn index(self) -> usize {
        match self {
            Dot::Grey => 0,
            Dot::Green => 1,
            Dot::Amber => 2,
        }
    }

    /// Opaque ARGB.
    pub fn argb(self) -> u32 {
        match self {
            Dot::Grey => 0xFF9A_A0A6,
            Dot::Green => 0xFF22_C55E,
            Dot::Amber => 0xFFF5_A524,
        }
    }
}

pub fn dot(phase: Phase) -> Dot {
    match phase {
        Phase::Waiting | Phase::Connecting => Dot::Grey,
        Phase::Pairing => Dot::Amber,
        Phase::Connected => Dot::Green,
    }
}

/// One line on what the helper is doing.
pub fn status_line(s: &AgentStatus) -> String {
    let mut line = match s.phase {
        Phase::Waiting => "Waiting for Remora".to_string(),
        Phase::Connecting => "Remora is connecting…".to_string(),
        Phase::Pairing => "Pairing: compare the code in the window".to_string(),
        Phase::Connected if s.client.is_empty() => "Connected to Remora".to_string(),
        Phase::Connected => format!("Connected to {}", s.client),
    };
    match s.transfers {
        0 => {}
        1 => line.push_str(" · 1 transfer"),
        n => line.push_str(&format!(" · {n} transfers")),
    }
    line
}

/// The icon's tooltip; Windows takes at most 127 UTF-16 units.
pub fn tooltip(s: &AgentStatus) -> String {
    clip_utf16(&format!("Remora helper\n{}", status_line(s)), 127)
}

/// A Remora PC this helper is paired with, for the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPc {
    pub label: String,
    /// As `remora-agent clients` prints it (`3f9a 07c2 …`).
    pub fingerprint: String,
}

/// The user's choices around "pinned PCs only".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Strict {
    /// The per-user switch (`remora-agent strict on`).
    pub user_on: bool,
    /// On for another reason the user cannot switch off here (policy, or a
    /// PC trusted by fingerprint): the reason.
    pub forced: Option<String>,
}

/// What the menu is built from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuModel {
    pub status: AgentStatus,
    pub strict: Strict,
    pub paired: Vec<PairedPc>,
    /// This helper's fingerprint; empty when it has no key.
    pub fingerprint: String,
}

/// What a menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    OpenReceived,
    CopyFingerprint,
    /// Forget the paired PC at this index of [`MenuModel::paired`].
    Forget(usize),
    ToggleStrict,
    OpenLog,
    Quit,
}

impl Cmd {
    /// Menu ids: 0 means "no choice" to `TrackPopupMenu`, so ids start at 1.
    pub fn id(self) -> u32 {
        match self {
            Cmd::OpenReceived => 1,
            Cmd::CopyFingerprint => 2,
            Cmd::ToggleStrict => 3,
            Cmd::OpenLog => 4,
            Cmd::Quit => 5,
            Cmd::Forget(i) => 100 + i as u32,
        }
    }

    pub fn from_id(id: u32, paired: usize) -> Option<Cmd> {
        Some(match id {
            1 => Cmd::OpenReceived,
            2 => Cmd::CopyFingerprint,
            3 => Cmd::ToggleStrict,
            4 => Cmd::OpenLog,
            5 => Cmd::Quit,
            n if n >= 100 && ((n - 100) as usize) < paired => Cmd::Forget((n - 100) as usize),
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Shown but not clickable (status, explanations).
    Label(String),
    Item {
        label: String,
        cmd: Cmd,
        checked: bool,
        enabled: bool,
    },
    Separator,
    Submenu {
        label: String,
        entries: Vec<Entry>,
    },
}

fn item(label: &str, cmd: Cmd) -> Entry {
    Entry::Item {
        label: label.into(),
        cmd,
        checked: false,
        enabled: true,
    }
}

/// Paired PCs listed in the menu; more are left to `remora-agent clients`.
pub const MAX_LISTED: usize = 20;

/// The tray menu, top to bottom.
pub fn menu(m: &MenuModel) -> Vec<Entry> {
    let mut out = vec![
        Entry::Label(status_line(&m.status)),
        Entry::Separator,
        item("Open received files", Cmd::OpenReceived),
    ];
    if !m.fingerprint.is_empty() {
        out.push(item(
            &format!("Copy this helper's fingerprint ({})", short(&m.fingerprint)),
            Cmd::CopyFingerprint,
        ));
    }
    let mut pcs: Vec<Entry> = m
        .paired
        .iter()
        .take(MAX_LISTED)
        .enumerate()
        .map(|(i, pc)| {
            let name = if pc.label.is_empty() {
                "(no name)"
            } else {
                &pc.label
            };
            item(
                &format!("Forget {name} ({})…", short(&pc.fingerprint)),
                Cmd::Forget(i),
            )
        })
        .collect();
    if pcs.is_empty() {
        pcs.push(Entry::Label("No Remora PC paired yet".into()));
    } else if m.paired.len() > MAX_LISTED {
        pcs.push(Entry::Label(format!(
            "{} more: remora-agent clients",
            m.paired.len() - MAX_LISTED
        )));
    }
    out.push(Entry::Submenu {
        label: format!("Paired PCs ({})", m.paired.len()),
        entries: pcs,
    });
    out.push(match &m.strict.forced {
        Some(why) => Entry::Item {
            label: format!("Only paired PCs may connect ({why})"),
            cmd: Cmd::ToggleStrict,
            checked: true,
            enabled: false,
        },
        None => Entry::Item {
            label: "Only paired PCs may connect".into(),
            cmd: Cmd::ToggleStrict,
            checked: m.strict.user_on,
            enabled: true,
        },
    });
    out.extend([
        Entry::Separator,
        item("Open log folder", Cmd::OpenLog),
        item("Quit helper", Cmd::Quit),
    ]);
    out
}

/// The first two groups of a fingerprint, enough to tell PCs apart.
fn short(fp: &str) -> String {
    let groups: Vec<&str> = fp.split_whitespace().take(2).collect();
    if groups.is_empty() {
        return String::new();
    }
    format!("{} …", groups.join(" "))
}

/// A notification's (title, text), within the shell's limits (63 and 255
/// UTF-16 units).
pub fn notice_text(n: &Notice) -> (String, String) {
    let (title, text) = match n {
        Notice::PairingWaiting => (
            "Remora wants to pair".to_string(),
            "Compare the code in the Remora helper window with the one Remora shows, \
             then confirm or reject."
                .to_string(),
        ),
        Notice::FileReceived(name) => (
            "File received from Remora".to_string(),
            format!("{name} is in Downloads\\From Remora."),
        ),
    };
    (clip_utf16(&title, 63), clip_utf16(&text, 255))
}

/// `s` cut to at most `max` UTF-16 units, at a character boundary, with an
/// ellipsis when cut.
pub fn clip_utf16(s: &str, max: usize) -> String {
    if s.encode_utf16().count() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in s.chars() {
        if units + c.len_utf16() > max - 1 {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

/// Paints the status dot into a square ARGB icon image (`size` x `size`,
/// rows top to bottom): a filled circle in the lower right corner with a
/// thin dark ring, so it reads on light and dark taskbars. Edges are
/// smoothed by coverage.
pub fn paint_dot(px: &mut [u32], size: usize, color: u32) {
    if size < 8 || px.len() < size * size {
        return;
    }
    let r = (size as f32 * 0.22).max(3.0);
    let ring = (size as f32 / 16.0).max(1.0);
    let c = size as f32 - r - 0.5;
    let outer = r + ring;
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 + 0.5 - c).powi(2) + (y as f32 + 0.5 - c).powi(2)).sqrt();
            if d > outer + 0.5 {
                continue;
            }
            let i = y * size + x;
            let ring_cov = (outer + 0.5 - d).clamp(0.0, 1.0);
            let fill_cov = (r + 0.5 - d).clamp(0.0, 1.0);
            let ringed = blend(px[i], 0xFF1E_1E1E, ring_cov);
            px[i] = blend(ringed, color, fill_cov);
        }
    }
}

/// `top` over `bottom` (straight ARGB) with `t` coverage.
fn blend(bottom: u32, top: u32, t: f32) -> u32 {
    if t <= 0.0 {
        return bottom;
    }
    if t >= 1.0 {
        return top;
    }
    let ch = |v: u32, s: u32| (v >> s) & 0xFF;
    let mix = |b: u32, t2: u32| (b as f32 + (t2 as f32 - b as f32) * t).round() as u32;
    let a = mix(ch(bottom, 24), ch(top, 24));
    let r = mix(ch(bottom, 16), ch(top, 16));
    let g = mix(ch(bottom, 8), ch(top, 8));
    let b = mix(ch(bottom, 0), ch(top, 0));
    (a << 24) | (r << 16) | (g << 8) | b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(phase: Phase, client: &str, transfers: usize) -> AgentStatus {
        AgentStatus {
            phase,
            client: client.into(),
            transfers,
        }
    }

    #[test]
    fn the_dot_follows_the_phase() {
        assert_eq!(dot(Phase::Waiting), Dot::Grey);
        assert_eq!(dot(Phase::Connecting), Dot::Grey);
        assert_eq!(dot(Phase::Pairing), Dot::Amber);
        assert_eq!(dot(Phase::Connected), Dot::Green);
        for (i, d) in Dot::ALL.into_iter().enumerate() {
            assert_eq!(d.index(), i);
            assert_eq!(d.argb() >> 24, 0xFF, "opaque");
        }
    }

    #[test]
    fn status_lines_and_tooltip() {
        assert_eq!(
            status_line(&st(Phase::Waiting, "", 0)),
            "Waiting for Remora"
        );
        assert_eq!(
            status_line(&st(Phase::Connected, "WORKPC", 2)),
            "Connected to WORKPC · 2 transfers"
        );
        assert_eq!(
            status_line(&st(Phase::Connected, "", 1)),
            "Connected to Remora · 1 transfer"
        );
        let t = tooltip(&st(Phase::Connected, &"x".repeat(300), 0));
        assert!(t.starts_with("Remora helper\nConnected to x"));
        assert_eq!(t.encode_utf16().count(), 127);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn clipping_keeps_whole_characters() {
        // 😀 is two UTF-16 units: never split.
        let s = "ab😀😀😀";
        let c = clip_utf16(s, 5);
        assert!(c.encode_utf16().count() <= 5, "{c}");
        assert_eq!(c, "ab😀…");
        assert_eq!(clip_utf16("short", 10), "short");
    }

    fn model() -> MenuModel {
        MenuModel {
            status: st(Phase::Connected, "WORKPC", 0),
            strict: Strict::default(),
            paired: vec![
                PairedPc {
                    label: "WORKPC".into(),
                    fingerprint: "3f9a 07c2 11aa 22bb".into(),
                },
                PairedPc {
                    label: String::new(),
                    fingerprint: "0000 1111 2222".into(),
                },
            ],
            fingerprint: "abcd ef01 2345".into(),
        }
    }

    fn items(entries: &[Entry]) -> Vec<(String, Cmd, bool, bool)> {
        let mut out = Vec::new();
        for e in entries {
            match e {
                Entry::Item {
                    label,
                    cmd,
                    checked,
                    enabled,
                } => out.push((label.clone(), *cmd, *checked, *enabled)),
                Entry::Submenu { entries, .. } => out.extend(items(entries)),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn the_menu_lists_status_actions_and_paired_pcs() {
        let m = menu(&model());
        assert_eq!(m[0], Entry::Label("Connected to WORKPC".into()));
        let it = items(&m);
        let labels: Vec<&str> = it.iter().map(|i| i.0.as_str()).collect();
        assert!(labels.contains(&"Open received files"));
        assert!(labels.contains(&"Copy this helper's fingerprint (abcd ef01 …)"));
        assert!(labels.contains(&"Forget WORKPC (3f9a 07c2 …)…"));
        assert!(labels.contains(&"Forget (no name) (0000 1111 …)…"));
        assert_eq!(it.last().unwrap().1, Cmd::Quit);
        // Every command's id maps back to it.
        for (_, cmd, _, _) in &it {
            assert_eq!(Cmd::from_id(cmd.id(), 2), Some(*cmd));
        }
        assert_eq!(Cmd::from_id(0, 2), None, "no choice");
        assert_eq!(Cmd::from_id(102, 2), None, "past the list");
    }

    #[test]
    fn strict_mode_shows_who_set_it() {
        let mut m = model();
        let find = |m: &MenuModel| {
            items(&menu(m))
                .into_iter()
                .find(|i| i.1 == Cmd::ToggleStrict)
                .unwrap()
        };
        assert!(!find(&m).2);
        m.strict.user_on = true;
        let (_, _, checked, enabled) = find(&m);
        assert!(checked && enabled, "the user's own switch");
        m.strict.forced = Some("policy".into());
        let (label, _, checked, enabled) = find(&m);
        assert!(checked && !enabled, "cannot be switched off here");
        assert!(label.contains("policy"));
    }

    #[test]
    fn no_key_no_fingerprint_item_and_an_empty_pc_list_says_so() {
        let mut m = model();
        m.fingerprint.clear();
        m.paired.clear();
        let menu = menu(&m);
        assert!(!items(&menu).iter().any(|i| i.1 == Cmd::CopyFingerprint));
        let sub = menu
            .iter()
            .find_map(|e| match e {
                Entry::Submenu { label, entries } => Some((label.clone(), entries.clone())),
                _ => None,
            })
            .unwrap();
        assert_eq!(sub.0, "Paired PCs (0)");
        assert_eq!(sub.1, [Entry::Label("No Remora PC paired yet".into())]);
    }

    #[test]
    fn long_pc_lists_are_capped() {
        let mut m = model();
        m.paired = (0..25)
            .map(|i| PairedPc {
                label: format!("PC{i}"),
                fingerprint: "aaaa bbbb".into(),
            })
            .collect();
        let it = items(&menu(&m));
        assert_eq!(
            it.iter().filter(|i| matches!(i.1, Cmd::Forget(_))).count(),
            MAX_LISTED
        );
    }

    #[test]
    fn notices_fit_the_shell() {
        let (title, text) = notice_text(&Notice::FileReceived("a".repeat(400)));
        assert_eq!(title, "File received from Remora");
        assert!(text.encode_utf16().count() <= 255);
        let (title, _) = notice_text(&Notice::PairingWaiting);
        assert!(title.encode_utf16().count() <= 63);
    }

    #[test]
    fn the_dot_sits_in_the_lower_right_corner() {
        let size = 16;
        let mut px = vec![0u32; size * size];
        paint_dot(&mut px, size, Dot::Green.argb());
        // Top left untouched, the dot's centre is the colour, opaque.
        assert_eq!(px[0], 0);
        assert_eq!(px[size + 1], 0);
        let r = (size as f32 * 0.22).max(3.0);
        let c = (size as f32 - r - 0.5) as usize;
        assert_eq!(px[c * size + c], Dot::Green.argb());
        // Just outside the fill the dark ring shows (smoothed, so partly
        // covered at its outer edge): visible, and darker than the dot.
        let ring = px[c * size + (c - r as usize - 1)];
        let green = |p: u32| (p >> 8) & 0xFF;
        assert!(ring >> 24 >= 0x80, "visible ring {ring:#010x}");
        assert!(
            green(ring) < green(Dot::Green.argb()),
            "dark ring {ring:#010x}"
        );
        // Too small or short buffers are left alone.
        let mut tiny = vec![0u32; 4];
        paint_dot(&mut tiny, 2, Dot::Green.argb());
        assert_eq!(tiny, [0; 4]);
    }
}
