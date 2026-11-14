//! The Windows backend: DXGI Desktop Duplication for the picture and
//! SendInput for keyboard and mouse.
//!
//! Limits of this first version: the primary output (the first output of
//! the first adapter) only; the host runs in the user's session, so the
//! secure desktop (UAC prompts, Ctrl+Alt+Del, the lock screen) is not
//! captured and takes no input; nothing here runs as a service.

mod capture;
mod input;

pub use capture::DuplicationCapturer;
pub use input::SendInputSink;

use std::io;

use super::Backend;

/// The capturer for the primary output and an input sink mapped to it.
pub fn backend() -> io::Result<Backend> {
    let capturer = DuplicationCapturer::new()?;
    let origin = capturer.origin();
    Ok((Box::new(capturer), Box::new(SendInputSink::new(origin))))
}
