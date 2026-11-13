//! H.264 decoding for the AVC420 codec (MS-RDPEGFX 2.2.4.4, 3.3.8.3).
//!
//! The library defines the decoder interface and the colour conversion; the
//! decoder itself is platform code supplied through [`H264Factory`] (rdpc
//! uses the Windows Media Foundation H.264 decoder).

use std::sync::Arc;

use crate::error::{Result, proto};

/// One decoded picture in planar YUV 4:2:0 (I420): a full-size luma plane and
/// two chroma planes of half width and half height (rounded up).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Yuv420Frame {
    pub width: usize,
    pub height: usize,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    /// Bytes per row of `y`.
    pub y_stride: usize,
    /// Bytes per row of `u` and `v`.
    pub uv_stride: usize,
}

impl Yuv420Frame {
    /// Checks that the planes hold `width` x `height` pixels.
    pub fn validate(&self) -> Result<()> {
        let (cw, ch) = (self.width.div_ceil(2), self.height.div_ceil(2));
        let fits = |len: usize, stride: usize, w: usize, h: usize| {
            h == 0 || stride >= w && len >= stride * (h - 1) + w
        };
        if !fits(self.y.len(), self.y_stride, self.width, self.height)
            || !fits(self.u.len(), self.uv_stride, cw, ch)
            || !fits(self.v.len(), self.uv_stride, cw, ch)
        {
            return proto("h264: decoded frame planes too small");
        }
        Ok(())
    }

    /// The 0x00RRGGBB pixel at (x, y); the caller keeps (x, y) in range.
    pub fn rgb(&self, x: usize, y: usize) -> u32 {
        let c = (y / 2) * self.uv_stride + x / 2;
        yuv_to_rgb(self.y[y * self.y_stride + x], self.u[c], self.v[c])
    }
}

/// An H.264 decoder for one graphics channel. `decode` gets one complete
/// access unit in Annex B byte-stream format (2.2.4.4: each AVC420 bitmap
/// stream is a single frame) and returns the decoded picture, or `None` if
/// the decoder produced no picture for it.
pub trait H264Decoder: Send {
    fn decode(&mut self, annex_b: &[u8]) -> Result<Option<Yuv420Frame>>;
}

/// Creates a decoder for a new session, or `None` when no decoder is
/// available on this machine (the client then advertises AVC as disabled).
pub type H264Factory = Arc<dyn Fn() -> Option<Box<dyn H264Decoder>> + Send + Sync>;

fn clamp(v: i32) -> u32 {
    v.clamp(0, 255) as u32
}

/// YUV to RGB as MS-RDPEGFX 3.3.8.3.1 defines it (full-range BT.709 in
/// 8.8 fixed point):
///
/// R = (256 Y + 403 (V - 128)) >> 8
/// G = (256 Y - 48 (U - 128) - 120 (V - 128)) >> 8
/// B = (256 Y + 475 (U - 128)) >> 8
///
/// each clamped to 0..=255. Returns 0x00RRGGBB.
pub fn yuv_to_rgb(y: u8, u: u8, v: u8) -> u32 {
    let y = 256 * y as i32;
    let d = u as i32 - 128;
    let e = v as i32 - 128;
    let r = clamp((y + 403 * e) >> 8);
    let g = clamp((y - 48 * d - 120 * e) >> 8);
    let b = clamp((y + 475 * d) >> 8);
    r << 16 | g << 8 | b
}
