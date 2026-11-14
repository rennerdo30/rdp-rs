//! This PC's monitors, for sessions that use several of them.
//!
//! A connection saves its chosen monitors by Windows device name
//! (`\\.\DISPLAY1`), so the choice survives reboots and other monitors
//! being plugged in.

/// One local monitor: its device name and its place on the desktop, in
/// physical pixels (the library's [`rdp::Monitor`], absolute coordinates).
#[derive(Clone, Debug, PartialEq)]
pub struct LocalMonitor {
    pub name: String,
    pub monitor: rdp::Monitor,
}

impl LocalMonitor {
    pub fn width(&self) -> i32 {
        self.monitor.right - self.monitor.left + 1
    }

    pub fn height(&self) -> i32 {
        self.monitor.bottom - self.monitor.top + 1
    }
}

/// The monitors chosen by name, in this PC's order; names no longer
/// present are left out.
pub fn chosen(all: &[LocalMonitor], names: &[String]) -> Vec<LocalMonitor> {
    all.iter()
        .filter(|m| names.contains(&m.name))
        .cloned()
        .collect()
}

/// The bounding box (left, top, width, height) of some monitors.
pub fn bounds(list: &[LocalMonitor]) -> Option<(i32, i32, i32, i32)> {
    let left = list.iter().map(|m| m.monitor.left).min()?;
    let top = list.iter().map(|m| m.monitor.top).min()?;
    let right = list.iter().map(|m| m.monitor.right).max()?;
    let bottom = list.iter().map(|m| m.monitor.bottom).max()?;
    Some((left, top, right - left + 1, bottom - top + 1))
}

/// Lists the monitors with their scale (EnumDisplayMonitors,
/// GetMonitorInfoW, GetDpiForMonitor), in physical pixels.
#[cfg(windows)]
pub fn list() -> Vec<LocalMonitor> {
    use windows_sys::Win32::Foundation::{LPARAM, RECT};
    use windows_sys::Win32::Graphics::Gdi::{
        EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW,
    };
    use windows_sys::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
        SetThreadDpiAwarenessContext,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::MONITORINFOF_PRIMARY;
    use windows_sys::core::BOOL;

    unsafe extern "system" fn add(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
        // SAFETY: `data` is the Vec passed below, alive for the whole call.
        let list = unsafe { &mut *(data as *mut Vec<LocalMonitor>) };
        let mut info: MONITORINFOEXW = unsafe { std::mem::zeroed() };
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        // SAFETY: `info` is a valid MONITORINFOEXW with cbSize set.
        if unsafe { GetMonitorInfoW(m, &mut info as *mut MONITORINFOEXW as *mut _) } == 0 {
            return 1;
        }
        let (mut dx, mut dy) = (96u32, 96u32);
        // SAFETY: valid monitor handle and out pointers.
        let scale = match unsafe { GetDpiForMonitor(m, MDT_EFFECTIVE_DPI, &mut dx, &mut dy) } {
            0 => dx * 100 / 96,
            _ => 0,
        };
        let r = info.monitorInfo.rcMonitor;
        let len = info.szDevice.iter().position(|&c| c == 0).unwrap_or(32);
        list.push(LocalMonitor {
            name: String::from_utf16_lossy(&info.szDevice[..len]),
            monitor: rdp::Monitor {
                left: r.left,
                top: r.top,
                right: r.right - 1,
                bottom: r.bottom - 1,
                primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
                scale,
                ..Default::default()
            },
        });
        1
    }

    let mut list: Vec<LocalMonitor> = Vec::new();
    // Physical pixels, not DPI-virtualized ones, for this thread only.
    // SAFETY: plain calls; the previous context is restored after.
    unsafe {
        let old = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            Some(add),
            &mut list as *mut Vec<LocalMonitor> as LPARAM,
        );
        if !old.is_null() {
            SetThreadDpiAwarenessContext(old);
        }
    }
    list
}

#[cfg(not(windows))]
pub fn list() -> Vec<LocalMonitor> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mon(name: &str, left: i32, w: i32) -> LocalMonitor {
        LocalMonitor {
            name: name.into(),
            monitor: rdp::Monitor::new(left, 0, w as u32, 1080, left == 0),
        }
    }

    #[test]
    fn choose_two_of_three_by_name() {
        let all = [
            mon("A", -1920, 1920),
            mon("B", 0, 1920),
            mon("C", 1920, 2560),
        ];
        let pick = chosen(&all, &["C".into(), "B".into(), "gone".into()]);
        assert_eq!(
            pick.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["B", "C"]
        );
        assert_eq!(bounds(&pick), Some((0, 0, 1920 + 2560, 1080)));
        assert_eq!(bounds(&[]), None);
    }
}
