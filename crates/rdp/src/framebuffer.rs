/// Client-side copy of the remote desktop, 0x00RRGGBB per pixel, top-down.
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
}

impl Framebuffer {
    pub fn new(width: usize, height: usize) -> Self {
        Self { width, height, pixels: vec![0; width * height] }
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        *self = Self::new(width, height);
    }

    /// Copies a `w` x `h` block from `src` (row stride `src_stride`) to (x, y), clipped.
    pub fn blit(&mut self, x: usize, y: usize, w: usize, h: usize, src: &[u32], src_stride: usize) {
        if x >= self.width || y >= self.height {
            return;
        }
        let w = w.min(self.width - x);
        let h = h.min(self.height - y);
        for row in 0..h {
            let s = &src[row * src_stride..row * src_stride + w];
            let d = (y + row) * self.width + x;
            self.pixels[d..d + w].copy_from_slice(s);
        }
    }

    /// Packed RGB bytes, for image export.
    pub fn to_rgb(&self) -> Vec<u8> {
        self.pixels
            .iter()
            .flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8])
            .collect()
    }
}
