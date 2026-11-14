//! Screen capture with DXGI Desktop Duplication (IDXGIOutputDuplication).
//!
//! Each frame's move and dirty rectangles become the damage; the desktop
//! texture is copied into a CPU-readable staging texture and the damaged
//! rows are copied out. After DXGI_ERROR_ACCESS_LOST (a mode change, a
//! desktop switch such as UAC or the lock screen) the duplication is made
//! again and the next frame is a full one.
//!
//! The rectangle and format logic are pure functions with tests; the
//! capture itself only runs when the host runs, never in the tests.

use std::io;
use std::time::Duration;

use windows::Win32::Foundation::{HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    DXGI_OUTDUPL_MOVE_RECT, IDXGIAdapter, IDXGIDevice, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource,
};
use windows::core::Interface;

use crate::backend::{Capturer, Frame, Rect};

/// A RECT (exclusive right and bottom) as a Rect clipped to the output.
pub(crate) fn clip_rect(r: &RECT, width: u16, height: u16) -> Option<Rect> {
    let left = r.left.clamp(0, i32::from(width));
    let top = r.top.clamp(0, i32::from(height));
    let right = r.right.clamp(0, i32::from(width));
    let bottom = r.bottom.clamp(0, i32::from(height));
    (right > left && bottom > top).then(|| {
        Rect::new(
            left as u16,
            top as u16,
            (right - left) as u16,
            (bottom - top) as u16,
        )
    })
}

/// Copies the rows of `rects` from a mapped texture (`row_pitch` bytes per
/// row) into `dst` (`dst_stride` bytes per row), BGRA.
pub(crate) fn copy_rects(
    src: &[u8],
    row_pitch: usize,
    dst: &mut [u8],
    dst_stride: usize,
    rects: &[Rect],
) {
    for r in rects {
        let start = usize::from(r.x) * 4;
        let len = usize::from(r.w) * 4;
        for y in usize::from(r.y)..usize::from(r.y) + usize::from(r.h) {
            let (Some(s), Some(d)) = (
                src.get(y * row_pitch + start..y * row_pitch + start + len),
                dst.get_mut(y * dst_stride + start..y * dst_stride + start + len),
            ) else {
                continue;
            };
            d.copy_from_slice(s);
        }
    }
}

fn win_err(what: &str, e: windows::core::Error) -> io::Error {
    io::Error::other(format!("{what}: {e}"))
}

/// The primary output of the default adapter, duplicated.
pub struct DuplicationCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    dupl: Option<IDXGIOutputDuplication>,
    staging: Option<ID3D11Texture2D>,
    width: u16,
    height: u16,
    origin: (i32, i32),
    buf: Vec<u8>,
    /// The next frame is sent whole (start, after access was lost).
    full: bool,
    meta: Vec<u8>,
}

// SAFETY: the capturer is created on one thread and then used only by the
// session thread it is moved to, one call at a time. The D3D11 device is
// created without D3D11_CREATE_DEVICE_SINGLETHREADED, so it and its
// immediate context may be used from another thread than their creator's;
// DXGI duplication objects have no thread affinity.
unsafe impl Send for DuplicationCapturer {}

impl DuplicationCapturer {
    pub fn new() -> io::Result<DuplicationCapturer> {
        let mut device = None;
        let mut context = None;
        // SAFETY: out pointers to locals; no adapter (the default one).
        unsafe {
            D3D11CreateDevice(
                None::<&IDXGIAdapter>,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .map_err(|e| win_err("cannot create a Direct3D 11 device", e))?;
        let device: ID3D11Device = device.ok_or_else(|| io::Error::other("no D3D11 device"))?;
        let context = context.ok_or_else(|| io::Error::other("no D3D11 context"))?;
        // SAFETY: COM calls on valid interfaces.
        let (output, desc) = unsafe {
            let dxgi: IDXGIDevice = device.cast().map_err(|e| win_err("IDXGIDevice", e))?;
            let adapter = dxgi.GetAdapter().map_err(|e| win_err("GetAdapter", e))?;
            let output = adapter
                .EnumOutputs(0)
                .map_err(|e| win_err("this adapter has no display output", e))?;
            let desc = output
                .GetDesc()
                .map_err(|e| win_err("output description", e))?;
            let output: IDXGIOutput1 = output.cast().map_err(|e| win_err("IDXGIOutput1", e))?;
            (output, desc)
        };
        let r = desc.DesktopCoordinates;
        let mut c = DuplicationCapturer {
            device,
            context,
            output,
            dupl: None,
            staging: None,
            width: (r.right - r.left).clamp(1, 0xFFFF) as u16,
            height: (r.bottom - r.top).clamp(1, 0xFFFF) as u16,
            origin: (r.left, r.top),
            buf: Vec::new(),
            full: true,
            meta: Vec::new(),
        };
        c.duplicate()?;
        Ok(c)
    }

    /// The output's top left in virtual desktop pixels.
    pub fn origin(&self) -> (i32, i32) {
        self.origin
    }

    /// (Re)creates the duplication; sizes the buffer to the mode.
    fn duplicate(&mut self) -> io::Result<()> {
        // SAFETY: COM calls on valid interfaces.
        let dupl = unsafe { self.output.DuplicateOutput(&self.device) }.map_err(|e| {
            win_err(
                "Desktop Duplication is not available (another program may use it, or the secure desktop is shown)",
                e,
            )
        })?;
        // SAFETY: as above.
        let desc = unsafe { dupl.GetDesc() };
        self.width = desc.ModeDesc.Width.clamp(1, 0xFFFF) as u16;
        self.height = desc.ModeDesc.Height.clamp(1, 0xFFFF) as u16;
        self.buf = vec![0; usize::from(self.width) * usize::from(self.height) * 4];
        self.staging = None;
        self.dupl = Some(dupl);
        self.full = true;
        Ok(())
    }

    /// A CPU-readable copy target in the desktop texture's size and format.
    fn staging_for(&mut self, tex: &ID3D11Texture2D) -> io::Result<ID3D11Texture2D> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: valid texture, out pointer to a local.
        unsafe { tex.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "desktop format {:?} is not supported (HDR or a high colour mode is on)",
                    desc.Format
                ),
            ));
        }
        if let Some(s) = &self.staging {
            return Ok(s.clone());
        }
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width: desc.Width,
            Height: desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: desc.Format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging = None;
        // SAFETY: valid description, out pointer to a local.
        unsafe {
            self.device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
        }
        .map_err(|e| win_err("staging texture", e))?;
        let staging = staging.ok_or_else(|| io::Error::other("no staging texture"))?;
        self.staging = Some(staging.clone());
        Ok(staging)
    }

    /// The move and dirty rectangles of the acquired frame.
    fn damage(
        &mut self,
        dupl: &IDXGIOutputDuplication,
        info: &DXGI_OUTDUPL_FRAME_INFO,
    ) -> Vec<Rect> {
        let size = info.TotalMetadataBufferSize as usize;
        if size == 0 {
            return Vec::new();
        }
        self.meta.resize(size, 0);
        let mut out = Vec::new();
        let mut used = 0u32;
        // SAFETY: the buffer holds `size` bytes; DXGI writes at most that.
        let moved = unsafe {
            dupl.GetFrameMoveRects(
                size as u32,
                self.meta.as_mut_ptr().cast::<DXGI_OUTDUPL_MOVE_RECT>(),
                &mut used,
            )
        };
        if moved.is_ok() {
            let n = used as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
            for i in 0..n {
                // SAFETY: DXGI wrote `n` move rects; read unaligned from bytes.
                let m: DXGI_OUTDUPL_MOVE_RECT = unsafe {
                    std::ptr::read_unaligned(
                        self.meta.as_ptr().cast::<DXGI_OUTDUPL_MOVE_RECT>().add(i),
                    )
                };
                out.extend(clip_rect(&m.DestinationRect, self.width, self.height));
            }
        }
        let mut used = 0u32;
        // SAFETY: as above, for RECTs.
        let dirty = unsafe {
            dupl.GetFrameDirtyRects(
                size as u32,
                self.meta.as_mut_ptr().cast::<RECT>(),
                &mut used,
            )
        };
        if dirty.is_ok() {
            let n = used as usize / std::mem::size_of::<RECT>();
            for i in 0..n {
                // SAFETY: DXGI wrote `n` rects.
                let r: RECT =
                    unsafe { std::ptr::read_unaligned(self.meta.as_ptr().cast::<RECT>().add(i)) };
                out.extend(clip_rect(&r, self.width, self.height));
            }
        }
        if moved.is_err() || dirty.is_err() {
            // Unknown damage: everything.
            return vec![Rect::new(0, 0, self.width, self.height)];
        }
        out
    }

    /// Copies the damaged rows of the acquired desktop texture.
    fn read(&mut self, resource: &IDXGIResource, rects: &[Rect]) -> io::Result<()> {
        let tex: ID3D11Texture2D = resource.cast().map_err(|e| win_err("desktop texture", e))?;
        let staging = self.staging_for(&tex)?;
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: valid resources of the same size and format; Map's out
        // pointer is a local; the mapped memory is read only between Map and
        // Unmap, within RowPitch x height bytes.
        unsafe {
            self.context.CopyResource(&staging, &tex);
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| win_err("map the staging texture", e))?;
            let pitch = mapped.RowPitch as usize;
            let src = std::slice::from_raw_parts(
                mapped.pData.cast::<u8>(),
                pitch * usize::from(self.height),
            );
            let stride = usize::from(self.width) * 4;
            copy_rects(src, pitch, &mut self.buf, stride, rects);
            self.context.Unmap(&staging, 0);
        }
        Ok(())
    }
}

impl Capturer for DuplicationCapturer {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn next_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame<'_>>> {
        if self.dupl.is_none() {
            // After access was lost: try again; the secure desktop may
            // still be up, which is not an error of the session.
            if self.duplicate().is_err() {
                std::thread::sleep(timeout.min(Duration::from_millis(100)));
                return Ok(None);
            }
        }
        let dupl = self.dupl.clone().expect("duplication exists");
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        let ms = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
        // SAFETY: out pointers to locals.
        match unsafe { dupl.AcquireNextFrame(ms, &mut info, &mut resource) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                crate::info!("desktop duplication lost ({e}); starting again");
                self.dupl = None;
                return Ok(None);
            }
            Err(e) => return Err(win_err("AcquireNextFrame", e)),
        }
        // Only the pointer changed: no new picture.
        let picture = info.LastPresentTime != 0 || self.full;
        let result = match (&resource, picture) {
            (Some(res), true) => {
                let rects = if self.full {
                    vec![Rect::new(0, 0, self.width, self.height)]
                } else {
                    self.damage(&dupl, &info)
                };
                self.read(res, &rects).map(|()| Some(rects))
            }
            _ => Ok(None),
        };
        drop(resource);
        // SAFETY: a frame was acquired above.
        let _ = unsafe { dupl.ReleaseFrame() };
        match result? {
            Some(damage) => {
                self.full = false;
                Ok(Some(Frame {
                    width: self.width,
                    height: self.height,
                    stride: usize::from(self.width) * 4,
                    pixels: &self.buf,
                    damage,
                }))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rects_are_clipped_to_the_output() {
        let r = |left, top, right, bottom| RECT {
            left,
            top,
            right,
            bottom,
        };
        assert_eq!(
            clip_rect(&r(10, 20, 110, 70), 1920, 1080),
            Some(Rect::new(10, 20, 100, 50))
        );
        assert_eq!(
            clip_rect(&r(-5, 1000, 30, 2000), 1920, 1080),
            Some(Rect::new(0, 1000, 30, 80))
        );
        assert_eq!(clip_rect(&r(5, 5, 5, 9), 1920, 1080), None);
        assert_eq!(clip_rect(&r(1920, 0, 2000, 10), 1920, 1080), None);
    }

    #[test]
    fn only_damaged_rows_are_copied_across_pitches() {
        // A 4 x 3 source with a 24-byte pitch (padding), into a 16-byte stride.
        let src: Vec<u8> = (0..72).collect();
        let mut dst = vec![0xEE; 48];
        copy_rects(&src, 24, &mut dst, 16, &[Rect::new(1, 1, 2, 2)]);
        assert_eq!(&dst[16..20], &[0xEE; 4]);
        assert_eq!(&dst[20..28], &src[28..36]);
        assert_eq!(&dst[36..44], &src[52..60]);
        assert_eq!(&dst[..16], &[0xEE; 16]);
    }
}
