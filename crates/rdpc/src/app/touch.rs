//! Touch and pen in the app: which windows send touch to which session, and
//! how their pixels map (see `crate::touch`). Refreshed after every event
//! batch, from the same state the mouse mapping uses.

use winit::window::Window;

use super::App;
use crate::touch::Target;

fn hwnd_of(win: &Window) -> isize {
    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match win.window_handle().map(|h| h.as_raw()) {
        Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
        _ => 0,
    }
}

impl App {
    /// The touch handle and framebuffer size of a session whose connection
    /// has "Touch and pen" on, when the server's input channel is there.
    fn touch_session(&self, id: u64) -> Option<(rdp::TouchHandle, (i32, i32))> {
        let on = self
            .win
            .as_ref()?
            .ui
            .tabs
            .iter()
            .find(|t| t.id == id)
            .is_none_or(|t| t.quality.touch);
        if !on {
            return None;
        }
        let s = self.sessions.get(&id)?;
        let handle = s.controls.touch()?.clone();
        let fb = s
            .worker
            .as_ref()?
            .shared
            .lock()
            .ok()
            .map(|sh| (sh.fb.width as i32, sh.fb.height as i32))?;
        (fb.0 > 0 && fb.1 > 0).then_some((handle, fb))
    }

    /// Hands the current touch targets to the window subclasses.
    pub(super) fn sync_touch(&self) {
        if !self.sessions.values().any(|s| s.controls.touch().is_some()) {
            crate::touch::set_targets(Vec::new());
            return;
        }
        let mut targets = Vec::new();
        // The main window: the visible part of the session picture, mapped
        // like `mouse_to_session`.
        if let Some(m) = &self.win
            && let Some((id, area)) = m.ui.session_area
            && let Some((handle, fb)) = self.touch_session(id)
        {
            let visible = m.ui.session_clip.unwrap_or(area);
            targets.push((
                hwnd_of(&m.gfx.window),
                Target {
                    handle,
                    accept: (visible.x, visible.y, visible.w, visible.h),
                    // The toolbar floats over the picture: a tap on it (or
                    // its handle) is the window's.
                    holes: m
                        .ui
                        .touch_holes()
                        .iter()
                        .map(|r| (r.x, r.y, r.w, r.h))
                        .collect(),
                    offset: (-area.x, -area.y),
                    screen: false,
                    fb,
                },
            ));
        }
        // Monitor windows: their part of the framebuffer, minus the bar.
        for sw in &self.spans {
            if let Some((handle, fb)) = self.touch_session(sw.session) {
                targets.push((
                    hwnd_of(&sw.window),
                    Target {
                        handle,
                        accept: sw.touch_area(),
                        holes: sw.touch_holes(),
                        offset: sw.fb,
                        screen: false,
                        fb,
                    },
                ));
            }
        }
        // RemoteApp windows: desktop position minus the framebuffer origin,
        // like `rail_point`.
        for (&id, s) in &self.sessions {
            let Some(rs) = &s.rail else { continue };
            let Some((handle, fb)) = self.touch_session(id) else {
                continue;
            };
            for aw in &rs.windows {
                let (w, h) = aw.win.size;
                targets.push((
                    hwnd_of(&aw.win.window),
                    Target {
                        handle: handle.clone(),
                        accept: (0, 0, w as i32, h as i32),
                        holes: Vec::new(),
                        offset: (-rs.desk.0, -rs.desk.1),
                        screen: true,
                        fb,
                    },
                ));
            }
        }
        for (hwnd, _) in &targets {
            crate::touch::attach(*hwnd);
        }
        crate::touch::set_targets(targets);
    }
}
