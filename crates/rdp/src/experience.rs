//! Picture quality and desktop experience, as on mstsc's Experience tab.
//!
//! Three things, all fixed at logon:
//! - the connection type in the client core data (MS-RDPBCGR 2.2.1.3.2,
//!   `connectionType`), a hint for how much the server may send;
//! - the colour depth (core data `highColorDepth` / `supportedColorDepths` /
//!   `RNS_UD_CS_WANT_32BPP_SESSION`, and the bitmap capability's
//!   `preferredBitsPerPixel`, 2.2.7.1.2);
//! - the performance flags in the extended Client Info (2.2.1.11.1.1.1,
//!   `performanceFlags`): which desktop features the server turns off.

/// The connection speed the client reports (2.2.1.3.2 `connectionType`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectionType {
    /// 56 Kbps.
    Modem = 1,
    /// 256 Kbps to 2 Mbps.
    BroadbandLow = 2,
    /// 2 to 16 Mbps, high latency.
    Satellite = 3,
    /// 2 to 10 Mbps.
    BroadbandHigh = 4,
    /// 10 Mbps or more, high latency.
    Wan = 5,
    /// 10 Mbps or more.
    #[default]
    Lan = 6,
    /// CONNECTION_TYPE_AUTODETECT: the server measures the link and picks
    /// the desktop features itself (2.2.1.3.2). The client then advertises
    /// RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT and the message channel, and
    /// answers the server's measurements (2.2.14, [`crate::autodetect`]).
    Auto = 7,
}

impl ConnectionType {
    pub fn from_u8(v: u8) -> Option<ConnectionType> {
        Some(match v {
            1 => ConnectionType::Modem,
            2 => ConnectionType::BroadbandLow,
            3 => ConnectionType::Satellite,
            4 => ConnectionType::BroadbandHigh,
            5 => ConnectionType::Wan,
            6 => ConnectionType::Lan,
            7 => ConnectionType::Auto,
            _ => return None,
        })
    }
}

const PERF_DISABLE_WALLPAPER: u32 = 0x0000_0001;
const PERF_DISABLE_FULLWINDOWDRAG: u32 = 0x0000_0002;
const PERF_DISABLE_MENUANIMATIONS: u32 = 0x0000_0004;
const PERF_DISABLE_THEMING: u32 = 0x0000_0008;
const PERF_DISABLE_CURSOR_SHADOW: u32 = 0x0000_0020;
const PERF_ENABLE_FONT_SMOOTHING: u32 = 0x0000_0080;
const PERF_ENABLE_DESKTOP_COMPOSITION: u32 = 0x0000_0100;

/// Desktop features the remote session shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Experience {
    pub wallpaper: bool,
    pub font_smoothing: bool,
    /// Desktop composition (transparency, shadows; DWM effects).
    pub desktop_composition: bool,
    /// Window contents while dragging.
    pub window_drag: bool,
    /// Menu and window animations.
    pub animations: bool,
    pub visual_styles: bool,
    pub cursor_shadow: bool,
}

impl Default for Experience {
    fn default() -> Self {
        Experience::for_connection(ConnectionType::Lan)
    }
}

impl Experience {
    /// What mstsc enables for each connection speed.
    pub fn for_connection(c: ConnectionType) -> Experience {
        let all = Experience {
            wallpaper: true,
            font_smoothing: true,
            desktop_composition: true,
            window_drag: true,
            animations: true,
            visual_styles: true,
            cursor_shadow: true,
        };
        let none = Experience {
            wallpaper: false,
            font_smoothing: false,
            desktop_composition: false,
            window_drag: false,
            animations: false,
            visual_styles: false,
            cursor_shadow: false,
        };
        match c {
            // Auto: the server overrides the flags once it has measured the
            // link (2.2.1.3.2); until then, and if it cannot, everything is on.
            ConnectionType::Lan | ConnectionType::Wan | ConnectionType::Auto => all,
            ConnectionType::BroadbandHigh => Experience {
                wallpaper: false,
                animations: false,
                ..all
            },
            ConnectionType::Satellite => Experience {
                desktop_composition: true,
                visual_styles: true,
                ..none
            },
            ConnectionType::BroadbandLow => Experience {
                visual_styles: true,
                ..none
            },
            ConnectionType::Modem => none,
        }
    }

    /// The Client Info `performanceFlags` value.
    pub fn performance_flags(&self) -> u32 {
        let mut f = 0;
        let mut off = |on: bool, flag: u32| {
            if !on {
                f |= flag;
            }
        };
        off(self.wallpaper, PERF_DISABLE_WALLPAPER);
        off(self.window_drag, PERF_DISABLE_FULLWINDOWDRAG);
        off(self.animations, PERF_DISABLE_MENUANIMATIONS);
        off(self.visual_styles, PERF_DISABLE_THEMING);
        off(self.cursor_shadow, PERF_DISABLE_CURSOR_SHADOW);
        if self.font_smoothing {
            f |= PERF_ENABLE_FONT_SMOOTHING;
        }
        if self.desktop_composition {
            f |= PERF_ENABLE_DESKTOP_COMPOSITION;
        }
        f
    }
}

/// A colour depth the client can decode: 15, 16, 24 or 32 bits per pixel.
pub fn valid_color_depth(bpp: u16) -> u16 {
    match bpp {
        15 | 16 | 24 | 32 => bpp,
        _ => 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn performance_flags_match_the_spec_bits() {
        assert_eq!(
            Experience::for_connection(ConnectionType::Lan).performance_flags(),
            0x180
        );
        assert_eq!(
            Experience::for_connection(ConnectionType::Modem).performance_flags(),
            0x2F,
            "everything off: wallpaper, drag, animations, theming, cursor shadow"
        );
        let e = Experience {
            wallpaper: false,
            ..Experience::default()
        };
        assert_eq!(e.performance_flags(), 0x181);
    }

    #[test]
    fn presets_get_poorer_with_the_line() {
        let count = |c| {
            let e = Experience::for_connection(c);
            [
                e.wallpaper,
                e.font_smoothing,
                e.desktop_composition,
                e.window_drag,
                e.animations,
                e.visual_styles,
                e.cursor_shadow,
            ]
            .iter()
            .filter(|b| **b)
            .count()
        };
        assert!(count(ConnectionType::Lan) > count(ConnectionType::BroadbandHigh));
        assert!(count(ConnectionType::BroadbandHigh) > count(ConnectionType::BroadbandLow));
        assert_eq!(count(ConnectionType::Modem), 0);
        assert_eq!(ConnectionType::from_u8(7), Some(ConnectionType::Auto));
        assert_eq!(ConnectionType::from_u8(8), None);
        assert_eq!(
            ConnectionType::from_u8(4),
            Some(ConnectionType::BroadbandHigh)
        );
        assert_eq!(valid_color_depth(8), 32);
    }
}
