//! A GDI screen capturer: `BitBlt` of the primary screen into a DIB, with
//! damage found by comparing 64 x 64 tiles to the previous picture.
//!
//! The fallback when DXGI Desktop Duplication is not available: in remote
//! sessions (the host itself run inside an RDP session, or Windows Sandbox,
//! whose desktop is one), without a hardware adapter, or when another
//! duplication already holds the output. Slower than duplication (a full
//! copy per frame), so the frame rate is capped.

use std::io;
use std::time::{Duration, Instant};

use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, HBITMAP, HDC, HGDIOBJ, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

use crate::backend::{Capturer, Frame, Rect};

/// Tile size for change detection.
const TILE: usize = 64;
/// At most this many captures per second.
const MAX_FPS: u32 = 20;

pub struct GdiCapturer {
    width: u16,
    height: u16,
    screen: HDC,
    mem: HDC,
    bitmap: HBITMAP,
    old: HGDIOBJ,
    /// The DIB's pixels (BGRA, top-down), owned by `bitmap`.
    bits: *mut u8,
    /// The previous picture, for change detection; also what a frame lends.
    prev: Vec<u8>,
    first: bool,
    last: Option<Instant>,
}

// SAFETY: the GDI handles and the DIB pointer are used only through
// `&mut self`, from whichever single thread owns the capturer.
unsafe impl Send for GdiCapturer {}

impl GdiCapturer {
    pub fn new() -> io::Result<GdiCapturer> {
        // SAFETY: plain GDI calls; every object made here is freed in Drop
        // (or right here on failure).
        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN).clamp(1, 0xFFFF);
            let h = GetSystemMetrics(SM_CYSCREEN).clamp(1, 0xFFFF);
            let screen = GetDC(None);
            if screen.is_invalid() {
                return Err(io::Error::other("GetDC(screen) failed"));
            }
            let mem = CreateCompatibleDC(Some(screen));
            if mem.is_invalid() {
                ReleaseDC(None, screen);
                return Err(io::Error::other("CreateCompatibleDC failed"));
            }
            let mut bmi = BITMAPINFO::default();
            bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = w;
            bmi.bmiHeader.biHeight = -h; // top-down
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB.0;
            let mut bits = std::ptr::null_mut();
            let bitmap = match CreateDIBSection(Some(mem), &bmi, DIB_RGB_COLORS, &mut bits, None, 0)
            {
                Ok(b) if !bits.is_null() => b,
                _ => {
                    let _ = DeleteDC(mem);
                    ReleaseDC(None, screen);
                    return Err(io::Error::other("CreateDIBSection failed"));
                }
            };
            let old = SelectObject(mem, bitmap.into());
            Ok(GdiCapturer {
                width: w as u16,
                height: h as u16,
                screen,
                mem,
                bitmap,
                old,
                bits: bits.cast(),
                prev: vec![0; w as usize * h as usize * 4],
                first: true,
                last: None,
            })
        }
    }

    fn len(&self) -> usize {
        self.width as usize * self.height as usize * 4
    }
}

impl Drop for GdiCapturer {
    fn drop(&mut self) {
        // SAFETY: the objects this capturer made, freed once.
        unsafe {
            SelectObject(self.mem, self.old);
            let _ = DeleteObject(self.bitmap.into());
            let _ = DeleteDC(self.mem);
            ReleaseDC(None, self.screen);
        }
    }
}

/// The 64 x 64 tiles of `cur` that differ from `prev` (both BGRA rows of
/// `w * 4` bytes), merged per tile row into runs.
pub fn changed_tiles(prev: &[u8], cur: &[u8], w: usize, h: usize) -> Vec<Rect> {
    let mut out = Vec::new();
    let stride = w * 4;
    for ty in (0..h).step_by(TILE) {
        let th = TILE.min(h - ty);
        let mut run: Option<(usize, usize)> = None;
        for tx in (0..w).step_by(TILE) {
            let tw = TILE.min(w - tx);
            let differs = (ty..ty + th).any(|y| {
                let a = y * stride + tx * 4;
                prev[a..a + tw * 4] != cur[a..a + tw * 4]
            });
            match (differs, run) {
                (true, Some((x0, _))) => run = Some((x0, tx + tw)),
                (true, None) => run = Some((tx, tx + tw)),
                (false, Some((x0, x1))) => {
                    out.push(rect(x0, ty, x1 - x0, th));
                    run = None;
                }
                (false, None) => {}
            }
        }
        if let Some((x0, x1)) = run {
            out.push(rect(x0, ty, x1 - x0, th));
        }
    }
    out
}

fn rect(x: usize, y: usize, w: usize, h: usize) -> Rect {
    Rect {
        x: x as u16,
        y: y as u16,
        w: w as u16,
        h: h as u16,
    }
}

impl Capturer for GdiCapturer {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn next_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame<'_>>> {
        // Pace: wait for the next slot, but never past the caller's timeout.
        let slot = Duration::from_secs(1) / MAX_FPS;
        if let Some(last) = self.last {
            let wait = slot.saturating_sub(last.elapsed());
            if wait > timeout {
                std::thread::sleep(timeout);
                return Ok(None);
            }
            std::thread::sleep(wait);
        }
        self.last = Some(Instant::now());
        let (w, h) = (self.width as i32, self.height as i32);
        // SAFETY: both DCs and the selected DIB are this capturer's.
        unsafe {
            BitBlt(
                self.mem,
                0,
                0,
                w,
                h,
                Some(self.screen),
                0,
                0,
                SRCCOPY | CAPTUREBLT,
            )
        }
        .map_err(|e| io::Error::other(format!("BitBlt: {e}")))?;
        let len = self.len();
        // SAFETY: the DIB holds width * height 32-bit pixels.
        let cur = unsafe { std::slice::from_raw_parts(self.bits, len) };
        let (wu, hu) = (self.width as usize, self.height as usize);
        let damage = if self.first {
            vec![rect(0, 0, wu, hu)]
        } else {
            changed_tiles(&self.prev, cur, wu, hu)
        };
        if damage.is_empty() {
            return Ok(None);
        }
        self.first = false;
        self.prev.copy_from_slice(cur);
        Ok(Some(Frame {
            width: self.width,
            height: self.height,
            stride: wu * 4,
            pixels: &self.prev,
            damage,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_pictures_have_no_damage_and_changes_are_tiled() {
        let (w, h) = (200, 130);
        let a = vec![0u8; w * h * 4];
        assert!(changed_tiles(&a, &a, w, h).is_empty());
        let mut b = a.clone();
        // One pixel in the second tile of the first row, one in the last
        // (partial) tile of the third row.
        b[(10 * w + 70) * 4] = 1;
        b[(129 * w + 199) * 4 + 2] = 9;
        let d = changed_tiles(&a, &b, w, h);
        assert_eq!(
            d,
            [rect(64, 0, 64, 64), rect(192, 128, 8, 2)],
            "partial edge tiles keep their real size"
        );
        // Neighbouring changed tiles merge into one run.
        b[(5 * w + 130) * 4] = 3;
        let d = changed_tiles(&a, &b, w, h);
        assert_eq!(d[0], rect(64, 0, 128, 64));
    }
}
