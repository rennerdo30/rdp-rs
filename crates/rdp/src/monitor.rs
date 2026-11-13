//! Multi-monitor layouts: the client's monitors in the GCC client data
//! (TS_UD_CS_MONITOR, MS-RDPBCGR 2.2.1.3.6, and TS_UD_CS_MONITOR_EX,
//! 2.2.1.3.10) and the server's Monitor Layout PDU (2.2.12.1).
//!
//! The session's framebuffer covers the virtual desktop: the bounding box of
//! all monitors. Framebuffer pixel (0, 0) is the box's top-left corner, so a
//! monitor at `left`/`top` (primary-relative) sits at `left - desktop.left`,
//! `top - desktop.top` in the framebuffer ([`VirtualDesktop::to_framebuffer`]).

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};

/// CS_MONITOR user data block type (MS-RDPBCGR 2.2.1.3.6).
pub const CS_MONITOR: u16 = 0xC005;
/// CS_MONITOR_EX user data block type (MS-RDPBCGR 2.2.1.3.10).
pub const CS_MONITOR_EX: u16 = 0xC008;
/// TS_MONITOR_PRIMARY (MS-RDPBCGR 2.2.1.3.6.1).
pub const TS_MONITOR_PRIMARY: u32 = 0x0000_0001;
/// Most monitors in a TS_UD_CS_MONITOR block (2.2.1.3.6).
pub const MAX_MONITORS: usize = 16;
/// Largest virtual desktop side (2.2.1.3.6).
pub const MAX_DESKTOP: u32 = 32766;
/// Smallest virtual desktop side (2.2.1.3.6).
pub const MIN_DESKTOP: u32 = 200;
/// PDUTYPE2_MONITOR_LAYOUT_PDU (MS-RDPBCGR 2.2.12.1).
pub const PDUTYPE2_MONITOR_LAYOUT_PDU: u8 = 55;

/// Monitor orientation (MS-RDPBCGR 2.2.1.3.10.1, MS-RDPEDISP 2.2.2.2.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Orientation {
    #[default]
    Landscape,
    Portrait,
    LandscapeFlipped,
    PortraitFlipped,
}

impl Orientation {
    /// The wire value in degrees.
    pub fn degrees(self) -> u32 {
        match self {
            Orientation::Landscape => 0,
            Orientation::Portrait => 90,
            Orientation::LandscapeFlipped => 180,
            Orientation::PortraitFlipped => 270,
        }
    }
}

/// One monitor. `left`, `top`, `right` and `bottom` are inclusive virtual
/// desktop coordinates, as Windows reports them (any origin; the layout is
/// moved so the primary monitor starts at (0, 0)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Monitor {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub primary: bool,
    /// Physical size in millimetres; (0, 0) when unknown (the server ignores
    /// values outside 10..=10,000).
    pub physical_mm: (u32, u32),
    /// Desktop scale in percent (100..=500); 0 uses the session's scale.
    pub scale: u32,
    pub orientation: Orientation,
}

impl Monitor {
    /// A landscape monitor at (left, top) of `width` x `height` pixels.
    pub fn new(left: i32, top: i32, width: u32, height: u32, primary: bool) -> Monitor {
        Monitor {
            left,
            top,
            right: left.saturating_add(width as i32).saturating_sub(1),
            bottom: top.saturating_add(height as i32).saturating_sub(1),
            primary,
            ..Monitor::default()
        }
    }

    pub fn width(&self) -> u32 {
        (self.right as i64 - self.left as i64 + 1).max(0) as u32
    }

    pub fn height(&self) -> u32 {
        (self.bottom as i64 - self.top as i64 + 1).max(0) as u32
    }
}

/// A checked layout: exactly one primary monitor, at (0, 0) and listed
/// first, and the bounding box of all monitors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualDesktop {
    /// The monitors in primary-relative coordinates, primary first.
    pub monitors: Vec<Monitor>,
    /// Top-left corner of the bounding box (primary-relative; <= 0).
    pub left: i32,
    pub top: i32,
    /// Size of the bounding box: the session's desktop size.
    pub width: u32,
    pub height: u32,
}

impl VirtualDesktop {
    /// Checks a client layout (MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.6.1): 1 to 16
    /// monitors, each at least one pixel, and a bounding box from 200 x 200
    /// to 32,766 x 32,766. The primary is the first monitor marked so, else
    /// the one holding (0, 0), else the first; the layout is moved so its
    /// top-left corner is (0, 0) and it comes first.
    pub fn new(monitors: &[Monitor]) -> Result<VirtualDesktop> {
        if monitors.is_empty() || monitors.len() > MAX_MONITORS {
            return proto(format!("{} monitors (1 to 16 allowed)", monitors.len()));
        }
        if let Some(m) = monitors
            .iter()
            .find(|m| m.right < m.left || m.bottom < m.top)
        {
            return proto(format!("empty monitor rectangle {m:?}"));
        }
        let p = monitors
            .iter()
            .position(|m| m.primary)
            .or_else(|| {
                monitors.iter().position(|m| {
                    (m.left..=m.right).contains(&0) && (m.top..=m.bottom).contains(&0)
                })
            })
            .unwrap_or(0);
        let (dx, dy) = (monitors[p].left as i64, monitors[p].top as i64);
        let (mut l, mut t, mut r, mut b) = (i64::MAX, i64::MAX, i64::MIN, i64::MIN);
        for m in monitors {
            l = l.min(m.left as i64 - dx);
            t = t.min(m.top as i64 - dy);
            r = r.max(m.right as i64 - dx);
            b = b.max(m.bottom as i64 - dy);
        }
        let (w, h) = (r - l + 1, b - t + 1);
        let range = MIN_DESKTOP as i64..=MAX_DESKTOP as i64;
        if !range.contains(&w) || !range.contains(&h) {
            return proto(format!("virtual desktop {w}x{h} (200 to 32766 per side)"));
        }
        // All coordinates now fit: |x| < 32766 after the move.
        let shift = |m: &Monitor, primary: bool| Monitor {
            left: (m.left as i64 - dx) as i32,
            top: (m.top as i64 - dy) as i32,
            right: (m.right as i64 - dx) as i32,
            bottom: (m.bottom as i64 - dy) as i32,
            primary,
            ..m.clone()
        };
        let mut out = vec![shift(&monitors[p], true)];
        out.extend(
            monitors
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != p)
                .map(|(_, m)| shift(m, false)),
        );
        Ok(VirtualDesktop {
            monitors: out,
            left: l as i32,
            top: t as i32,
            width: w as u32,
            height: h as u32,
        })
    }

    /// A monitor's rectangle in framebuffer pixels: (x, y, width, height).
    /// None if it lies outside the bounding box (a server layout that does
    /// not match the session size).
    pub fn to_framebuffer(&self, m: &Monitor) -> Option<(usize, usize, usize, usize)> {
        let x = m.left as i64 - self.left as i64;
        let y = m.top as i64 - self.top as i64;
        let (w, h) = (m.width() as i64, m.height() as i64);
        if x < 0 || y < 0 || x + w > self.width as i64 || y + h > self.height as i64 {
            return None;
        }
        Some((x as usize, y as usize, w as usize, h as usize))
    }
}

/// TS_MONITOR_DEF (MS-RDPBCGR 2.2.1.3.6.1).
fn put_monitor_def(v: &mut Vec<u8>, m: &Monitor) {
    v.put_u32(m.left as u32);
    v.put_u32(m.top as u32);
    v.put_u32(m.right as u32);
    v.put_u32(m.bottom as u32);
    v.put_u32(if m.primary { TS_MONITOR_PRIMARY } else { 0 });
}

/// The TS_UD_CS_MONITOR block (MS-RDPBCGR 2.2.1.3.6), header included.
pub fn client_monitor_data(d: &VirtualDesktop) -> Vec<u8> {
    let n = d.monitors.len();
    let mut v = Vec::with_capacity(12 + 20 * n);
    v.put_u16(CS_MONITOR);
    v.put_u16((12 + 20 * n) as u16);
    v.put_u32(0); // flags
    v.put_u32(n as u32); // monitorCount
    for m in &d.monitors {
        put_monitor_def(&mut v, m);
    }
    v
}

/// Desktop scale for a monitor: its own, else the session's; 100..=500.
pub fn monitor_scale(m: &Monitor, session_scale: u32) -> u32 {
    match m.scale {
        0 => session_scale,
        s => s,
    }
    .clamp(100, 500)
}

/// The TS_UD_CS_MONITOR_EX block (MS-RDPBCGR 2.2.1.3.10), header included.
pub fn client_monitor_ex_data(d: &VirtualDesktop, session_scale: u32) -> Vec<u8> {
    let n = d.monitors.len();
    let mut v = Vec::with_capacity(16 + 20 * n);
    v.put_u16(CS_MONITOR_EX);
    v.put_u16((16 + 20 * n) as u16);
    v.put_u32(0); // flags
    v.put_u32(20); // monitorAttributeSize
    v.put_u32(n as u32); // monitorCount, as in TS_UD_CS_MONITOR
    for m in &d.monitors {
        // TS_MONITOR_ATTRIBUTES (2.2.1.3.10.1)
        let scale = monitor_scale(m, session_scale);
        v.put_u32(m.physical_mm.0);
        v.put_u32(m.physical_mm.1);
        v.put_u32(m.orientation.degrees());
        v.put_u32(scale);
        v.put_u32(crate::disp::device_scale(scale));
    }
    v
}

/// Parses the body of a Monitor Layout PDU (MS-RDPBCGR 2.2.12.1) after the
/// share data header: monitorCount and the TS_MONITOR_DEF array, in the
/// server's primary-relative coordinates.
pub fn parse_monitor_layout(payload: &[u8]) -> Result<Vec<Monitor>> {
    let mut r = Reader::new(payload);
    let count = r.u32()? as usize;
    // Truncated arrays fail in the reader below.
    if count > MAX_MONITORS {
        return proto(format!("monitor layout PDU with {count} monitors"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (left, top) = (r.u32()? as i32, r.u32()? as i32);
        let (right, bottom) = (r.u32()? as i32, r.u32()? as i32);
        let flags = r.u32()?;
        out.push(Monitor {
            left,
            top,
            right,
            bottom,
            primary: flags & TS_MONITOR_PRIMARY != 0,
            ..Monitor::default()
        });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "monitor_tests.rs"]
mod tests;
