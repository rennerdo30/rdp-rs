//! The Windows backend: DXGI Desktop Duplication for the picture and
//! SendInput for keyboard and mouse.
//!
//! Limits of this first version: the primary output (the first output of
//! the first adapter) only; the host runs in the user's session, so the
//! secure desktop (UAC prompts, Ctrl+Alt+Del, the lock screen) is not
//! captured and takes no input; nothing here runs as a service.

mod capture;
mod gdi;
mod input;

pub use capture::DuplicationCapturer;
pub use gdi::GdiCapturer;
pub use input::SendInputSink;

use std::io;

use super::{Backend, CaptureMode};
use crate::info;

/// The capturer for the primary output and an input sink mapped to it.
/// Automatic takes DXGI Desktop Duplication and falls back to GDI where it
/// is not available (remote sessions such as Windows Sandbox's desktop).
pub fn backend(mode: CaptureMode) -> io::Result<Backend> {
    let dxgi = match mode {
        CaptureMode::Gdi => None,
        CaptureMode::Dxgi => Some(DuplicationCapturer::new()?),
        CaptureMode::Auto => match DuplicationCapturer::new() {
            Ok(c) => Some(c),
            Err(e) => {
                info!("Desktop Duplication not available ({e}); capturing with GDI");
                None
            }
        },
    };
    match dxgi {
        Some(c) => {
            let origin = c.origin();
            Ok((Box::new(c), Box::new(SendInputSink::new(origin))))
        }
        // GDI captures the primary screen at (0, 0).
        None => Ok((
            Box::new(GdiCapturer::new()?),
            Box::new(SendInputSink::new((0, 0))),
        )),
    }
}
