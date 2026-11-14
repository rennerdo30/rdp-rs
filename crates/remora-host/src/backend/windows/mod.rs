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
use std::time::Duration;

use super::{Backend, CaptureMode, Capturer, Frame};
use crate::info;

/// True when every pixel of the frame has the same colour (alpha ignored).
pub fn uniform(f: &Frame<'_>) -> bool {
    let row = f.width as usize * 4;
    let Some(first) = f.pixels.get(..3) else {
        return true;
    };
    (0..f.height as usize).all(|y| {
        f.pixels[y * f.stride..y * f.stride + row]
            .as_chunks::<4>()
            .0
            .iter()
            .all(|p| &p[..3] == first)
    })
}

/// Whether a capturer's first frame (the whole screen) is one colour; None
/// when no frame came within a few tries.
fn first_frame_uniform(c: &mut dyn Capturer) -> Option<bool> {
    for _ in 0..5 {
        if let Ok(Some(f)) = c.next_frame(Duration::from_millis(400)) {
            return Some(uniform(&f));
        }
    }
    None
}

/// Some display drivers give Desktop Duplication no usable picture while
/// GDI sees the desktop (the Venera virtio-gpu driver in QEMU guests: black
/// frames, or AcquireNextFrame failing over and over with
/// DXGI_ERROR_KEYED_MUTEX_ABANDONED): true when a probe duplication's first
/// frame is one colour or never comes, and GDI's first frame is a picture.
/// A working duplication delivers the whole screen as its first frame at
/// once, also on a still desktop.
fn duplication_is_blank() -> bool {
    let Ok(mut probe) = DuplicationCapturer::new() else {
        return false;
    };
    if first_frame_uniform(&mut probe) == Some(false) {
        return false;
    }
    drop(probe);
    GdiCapturer::new()
        .ok()
        .and_then(|mut g| first_frame_uniform(&mut g))
        == Some(false)
}

/// The capturer for the primary output and an input sink mapped to it.
/// Automatic takes DXGI Desktop Duplication and falls back to GDI where it
/// is not available (remote sessions such as Windows Sandbox's desktop) or
/// delivers only a black picture where GDI sees the desktop.
pub fn backend(mode: CaptureMode) -> io::Result<Backend> {
    let dxgi = match mode {
        CaptureMode::Gdi => None,
        CaptureMode::Dxgi => Some(DuplicationCapturer::new()?),
        CaptureMode::Auto if duplication_is_blank() => {
            info!(
                "Desktop Duplication gives no picture on this display driver (black or no frames) while GDI sees the desktop; capturing with GDI"
            );
            None
        }
        // A fresh duplication: its first frame is the whole screen.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(px: &[u8], w: u16, h: u16, stride: usize) -> Frame<'_> {
        Frame {
            width: w,
            height: h,
            stride,
            pixels: px,
            damage: Vec::new(),
        }
    }

    #[test]
    fn uniform_ignores_alpha_and_row_padding() {
        // 2 x 2, stride 12 (4 bytes of padding per row).
        let mut px = vec![0u8; 24];
        assert!(uniform(&frame(&px, 2, 2, 12)), "all black");
        px[3] = 0xFF; // alpha only
        px[8..12].copy_from_slice(&[9, 9, 9, 9]); // padding only
        assert!(uniform(&frame(&px, 2, 2, 12)));
        px[16] = 1; // a real pixel in the second row
        assert!(!uniform(&frame(&px, 2, 2, 12)));
    }
}
