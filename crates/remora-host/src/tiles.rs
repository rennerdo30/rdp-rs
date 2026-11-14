//! The host's copy of the screen and its damage tracking: captured frames
//! are copied in by 64 x 64 grid cell, and only the cells whose pixels
//! really changed are sent (a capturer's damage is often coarse).

use rdp::server::{Rect, Tile};

use crate::backend::Frame;

/// The cell size: bitmap updates carry at most 64 x 64 per rectangle.
pub const CELL: u16 = 64;

/// The last picture sent, BGRA, rows top-down.
pub struct Shadow {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl Shadow {
    /// A black picture of the given size.
    pub fn new(width: u16, height: u16) -> Shadow {
        Shadow {
            width,
            height,
            pixels: vec![0; usize::from(width) * usize::from(height) * 4],
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn stride(&self) -> usize {
        usize::from(self.width) * 4
    }

    /// The grid cells that cover `rects` (clipped to the picture).
    pub fn cells(&self, rects: &[Rect]) -> Vec<Rect> {
        let cols = self.width.div_ceil(CELL);
        let rows = self.height.div_ceil(CELL);
        let mut marked = vec![false; usize::from(cols) * usize::from(rows)];
        for r in rects {
            let Some(r) = r.clip(self.width, self.height) else {
                continue;
            };
            for cy in r.y / CELL..=(r.y + r.h - 1) / CELL {
                for cx in r.x / CELL..=(r.x + r.w - 1) / CELL {
                    marked[usize::from(cy) * usize::from(cols) + usize::from(cx)] = true;
                }
            }
        }
        let mut out = Vec::new();
        for cy in 0..rows {
            for cx in 0..cols {
                if marked[usize::from(cy) * usize::from(cols) + usize::from(cx)] {
                    out.push(self.cell(cx, cy));
                }
            }
        }
        out
    }

    fn cell(&self, cx: u16, cy: u16) -> Rect {
        let (x, y) = (cx * CELL, cy * CELL);
        Rect::new(x, y, CELL.min(self.width - x), CELL.min(self.height - y))
    }

    /// Every cell of the picture.
    pub fn all_cells(&self) -> Vec<Rect> {
        self.cells(&[Rect::new(0, 0, self.width, self.height)])
    }

    /// Copies the frame's damaged cells in and returns those whose pixels
    /// changed. A frame of another size replaces the picture (all cells).
    pub fn apply(&mut self, frame: &Frame) -> Vec<Rect> {
        let same_size = (frame.width, frame.height) == (self.width, self.height);
        let cells = if same_size {
            self.cells(&frame.damage)
        } else {
            *self = Shadow::new(frame.width, frame.height);
            self.all_cells()
        };
        let stride = self.stride();
        let mut changed = Vec::new();
        for c in cells {
            let row_bytes = usize::from(c.w) * 4;
            let mut differs = !same_size;
            for row in 0..usize::from(c.h) {
                let y = usize::from(c.y) + row;
                let src = y * frame.stride + usize::from(c.x) * 4;
                let dst = y * stride + usize::from(c.x) * 4;
                let (Some(s), Some(d)) = (
                    frame.pixels.get(src..src + row_bytes),
                    self.pixels.get_mut(dst..dst + row_bytes),
                ) else {
                    continue; // a frame shorter than it claims: keep the old
                };
                if s != d {
                    d.copy_from_slice(s);
                    differs = true;
                }
            }
            if differs {
                changed.push(c);
            }
        }
        changed
    }

    /// The cells as bitmap tiles from this picture.
    pub fn tiles<'a>(&'a self, cells: &[Rect]) -> Vec<Tile<'a>> {
        cells
            .iter()
            .map(|c| Tile {
                pixels: &self.pixels,
                stride: self.stride(),
                image_width: self.width,
                image_height: self.height,
                x: c.x,
                y: c.y,
                w: c.w,
                h: c.h,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(px: &[u8], w: u16, h: u16, damage: Vec<Rect>) -> Frame<'_> {
        Frame {
            width: w,
            height: h,
            stride: usize::from(w) * 4,
            pixels: px,
            damage,
        }
    }

    #[test]
    fn cells_cover_damage_once() {
        let s = Shadow::new(150, 70);
        // Two overlapping rectangles across the first two columns.
        let cells = s.cells(&[Rect::new(10, 10, 60, 5), Rect::new(63, 0, 2, 2)]);
        assert_eq!(
            cells,
            vec![Rect::new(0, 0, 64, 64), Rect::new(64, 0, 64, 64)]
        );
        // The edge cells are clipped to the picture.
        let all = s.all_cells();
        assert_eq!(all.len(), 6);
        assert_eq!(all[5], Rect::new(128, 64, 22, 6));
        // Damage outside the picture is ignored.
        assert!(s.cells(&[Rect::new(150, 0, 5, 5)]).is_empty());
    }

    #[test]
    fn only_really_changed_cells_are_reported() {
        let (w, h) = (130u16, 64u16);
        let mut px = vec![0u8; usize::from(w) * usize::from(h) * 4];
        let mut s = Shadow::new(w, h);
        // Full damage but nothing differs from the black start: nothing.
        let full = vec![Rect::new(0, 0, w, h)];
        assert!(s.apply(&frame(&px, w, h, full.clone())).is_empty());
        // One pixel in the third column changes.
        px[(10 * usize::from(w) + 129) * 4] = 9;
        assert_eq!(
            s.apply(&frame(&px, w, h, full.clone())),
            vec![Rect::new(128, 0, 2, 64)]
        );
        // A change outside the reported damage is not picked up.
        px[0] = 1;
        assert!(
            s.apply(&frame(&px, w, h, vec![Rect::new(70, 0, 4, 4)]))
                .is_empty()
        );
        // A frame of another size replaces everything.
        let small = vec![0u8; 64 * 64 * 4];
        assert_eq!(s.apply(&frame(&small, 64, 64, Vec::new())).len(), 1);
        assert_eq!(s.size(), (64, 64));
    }
}
