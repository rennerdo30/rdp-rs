//! Client graphics state (MS-RDPEGFX 3.3.1): offscreen surfaces (3.3.1.6),
//! the bitmap cache (3.3.1.4), the surface-to-output mapping (3.3.1.8) and
//! the Graphics Output Buffer (3.3.1.7) that finished frames are composed
//! into. Pixels are 0x00RRGGBB, as in the session framebuffer.
//!
//! Server rectangles that reach outside a surface are clipped, never trusted.

use std::collections::HashMap;

use crate::error::{Result, proto};
use crate::framebuffer::{Damage, Framebuffer};

/// Largest surface the client allocates, in pixels (an 8K desktop fits).
pub const MAX_SURFACE_PIXELS: usize = 64 << 20;
/// Dirty rectangles kept per frame before they collapse into bounding boxes.
const MAX_DIRTY: usize = 512;

/// A rectangle in pixels: x, y, width, height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl Area {
    pub fn new(x: usize, y: usize, w: usize, h: usize) -> Area {
        Area { x, y, w, h }
    }

    /// The part inside a `width` x `height` bound, if any.
    pub fn clip(self, width: usize, height: usize) -> Option<Area> {
        if self.x >= width || self.y >= height {
            return None;
        }
        let w = self.w.min(width - self.x);
        let h = self.h.min(height - self.y);
        (w > 0 && h > 0).then_some(Area { w, h, ..self })
    }

    fn union(self, o: Area) -> Area {
        let x = self.x.min(o.x);
        let y = self.y.min(o.y);
        let r = (self.x + self.w).max(o.x + o.w);
        let b = (self.y + self.h).max(o.y + o.h);
        Area::new(x, y, r - x, b - y)
    }
}

/// An offscreen surface (3.3.1.6).
pub struct Surface {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
    /// Top-left corner in the Graphics Output Buffer, once mapped (3.3.1.8).
    pub origin: Option<(usize, usize)>,
}

impl Surface {
    /// Copies `area` of `src` (row stride `stride`, origin at `src`'s first
    /// pixel) to (area.x, area.y), clipped. Returns the area written.
    pub fn blit(&mut self, area: Area, src: &[u32], stride: usize) -> Option<Area> {
        let a = area.clip(self.width, self.height)?;
        for row in 0..a.h {
            let s = &src[row * stride..row * stride + a.w];
            let d = (a.y + row) * self.width + a.x;
            self.pixels[d..d + a.w].copy_from_slice(s);
        }
        Some(a)
    }

    /// The pixels of `area` (already clipped to this surface), row by row.
    pub fn read(&self, a: Area) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.w * a.h);
        for row in a.y..a.y + a.h {
            let o = row * self.width + a.x;
            out.extend_from_slice(&self.pixels[o..o + a.w]);
        }
        out
    }

    /// The pixels of `area`, row by row, `area.w` x `area.h` of them; the
    /// part outside the surface reads as 0.
    pub fn read_padded(&self, area: Area) -> Vec<u32> {
        let mut out = vec![0; area.w * area.h];
        if let Some(a) = area.clip(self.width, self.height) {
            for row in 0..a.h {
                let s = (a.y + row) * self.width + a.x;
                let d = row * area.w;
                out[d..d + a.w].copy_from_slice(&self.pixels[s..s + a.w]);
            }
        }
        out
    }

    pub fn fill(&mut self, area: Area, color: u32) -> Option<Area> {
        let a = area.clip(self.width, self.height)?;
        for row in a.y..a.y + a.h {
            let o = row * self.width + a.x;
            self.pixels[o..o + a.w].fill(color);
        }
        Some(a)
    }
}

/// One bitmap cache entry (3.3.1.4).
struct CacheEntry {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

/// Surfaces, cache and output of one graphics channel.
pub struct GfxState {
    surfaces: HashMap<u16, Surface>,
    cache: HashMap<u16, CacheEntry>,
    cache_bytes: usize,
    /// Highest cache slot (slots are one-based) and the cache size limit.
    max_slots: u16,
    cache_limit: usize,
    /// The Graphics Output Buffer (3.3.1.7).
    output: Framebuffer,
    /// The output was resized and not presented since.
    resized: bool,
    /// Surface areas changed since the last end of frame.
    dirty: Vec<(u16, Area)>,
    /// Output areas composed and not presented yet.
    pending: Vec<Damage>,
}

impl Default for GfxState {
    fn default() -> Self {
        Self::new()
    }
}

impl GfxState {
    pub fn new() -> GfxState {
        let mut s = GfxState {
            surfaces: HashMap::new(),
            cache: HashMap::new(),
            cache_bytes: 0,
            max_slots: 0,
            cache_limit: 0,
            output: Framebuffer::new(0, 0),
            resized: false,
            dirty: Vec::new(),
            pending: Vec::new(),
        };
        s.set_small_cache(true);
        s
    }

    /// Cache limits from the confirmed capabilities (3.3.1.4): 16 MB and
    /// 4,096 slots with SMALL_CACHE or THINCLIENT, else 100 MB and 25,600.
    pub fn set_small_cache(&mut self, small: bool) {
        (self.max_slots, self.cache_limit) = if small {
            (4096, 16 << 20)
        } else {
            (25600, 100 << 20)
        };
    }

    pub fn surface(&self, id: u16) -> Option<&Surface> {
        self.surfaces.get(&id)
    }

    /// Writable surface; the caller marks what it changes with [`Self::mark`].
    pub fn surface_mut(&mut self, id: u16) -> Option<&mut Surface> {
        self.surfaces.get_mut(&id)
    }

    pub fn output(&self) -> &Framebuffer {
        &self.output
    }

    /// RDPGFX_RESET_GRAPHICS_PDU (3.3.5.14): resize the output buffer.
    pub fn reset(&mut self, width: usize, height: usize) {
        if (width, height) != (self.output.width, self.output.height) {
            self.output.resize(width, height);
            self.resized = true;
            self.pending.clear();
        }
    }

    /// RDPGFX_CREATE_SURFACE_PDU (3.3.5.9). A second create for the same id
    /// replaces the surface.
    pub fn create(&mut self, id: u16, width: usize, height: usize) -> Result<()> {
        if width * height > MAX_SURFACE_PIXELS {
            return proto(format!("gfx: surface {width}x{height} too large"));
        }
        self.surfaces.insert(
            id,
            Surface {
                width,
                height,
                pixels: vec![0; width * height],
                origin: None,
            },
        );
        Ok(())
    }

    /// RDPGFX_DELETE_SURFACE_PDU (3.3.5.10); also removes the mapping.
    pub fn delete(&mut self, id: u16) {
        self.surfaces.remove(&id);
        self.dirty.retain(|(s, _)| *s != id);
    }

    /// RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU (3.3.5.15). The whole surface is
    /// composed at the next end of frame.
    pub fn map(&mut self, id: u16, x: usize, y: usize) -> bool {
        let Some(s) = self.surfaces.get_mut(&id) else {
            return false;
        };
        s.origin = Some((x, y));
        let all = Area::new(0, 0, s.width, s.height);
        self.mark(id, all);
        true
    }

    /// Records a changed surface area for the next composition.
    pub fn mark(&mut self, id: u16, a: Area) {
        if a.w == 0 || a.h == 0 {
            return;
        }
        if self.dirty.len() >= MAX_DIRTY {
            // Collapse into one bounding box per surface.
            let mut boxes: Vec<(u16, Area)> = Vec::new();
            for (s, d) in self.dirty.drain(..) {
                match boxes.iter_mut().find(|(b, _)| *b == s) {
                    Some((_, b)) => *b = b.union(d),
                    None => boxes.push((s, d)),
                }
            }
            self.dirty = boxes;
        }
        self.dirty.push((id, a));
    }

    /// Writes pixels to a surface and marks them; false if no such surface.
    pub fn blit(&mut self, id: u16, area: Area, src: &[u32], stride: usize) -> bool {
        let Some(s) = self.surfaces.get_mut(&id) else {
            return false;
        };
        if let Some(a) = s.blit(area, src, stride) {
            self.mark(id, a);
        }
        true
    }

    /// RDPGFX_SOLIDFILL_PDU (3.3.5.4).
    pub fn fill(&mut self, id: u16, color: u32, areas: &[Area]) -> bool {
        let Some(s) = self.surfaces.get_mut(&id) else {
            return false;
        };
        let done: Vec<Area> = areas.iter().filter_map(|&a| s.fill(a, color)).collect();
        for a in done {
            self.mark(id, a);
        }
        true
    }

    /// RDPGFX_SURFACE_TO_SURFACE_PDU (3.3.5.5): SRCCOPY of `src_area` to each
    /// point. The source is read first, so overlapping copies on one
    /// surface are exact.
    pub fn copy(&mut self, src: u16, src_area: Area, dst: u16, points: &[(usize, usize)]) -> bool {
        let Some(s) = self.surfaces.get(&src) else {
            return false;
        };
        let Some(a) = src_area.clip(s.width, s.height) else {
            return self.surfaces.contains_key(&dst);
        };
        let pixels = s.read(a);
        if !self.surfaces.contains_key(&dst) {
            return false;
        }
        for &(x, y) in points {
            self.blit(dst, Area::new(x, y, a.w, a.h), &pixels, a.w);
        }
        true
    }

    /// RDPGFX_SURFACE_TO_CACHE_PDU (3.3.5.6).
    pub fn to_cache(&mut self, id: u16, area: Area, slot: u16) -> Result<bool> {
        if slot == 0 || slot > self.max_slots {
            return proto(format!("gfx: cache slot {slot} out of range"));
        }
        let Some(s) = self.surfaces.get(&id) else {
            return Ok(false);
        };
        let a = area
            .clip(s.width, s.height)
            .unwrap_or(Area::new(0, 0, 0, 0));
        let pixels = s.read(a);
        self.evict(slot);
        let bytes = pixels.len() * 4;
        if self.cache_bytes + bytes > self.cache_limit {
            return proto("gfx: bitmap cache over its size limit");
        }
        self.cache_bytes += bytes;
        self.cache.insert(
            slot,
            CacheEntry {
                width: a.w,
                height: a.h,
                pixels,
            },
        );
        Ok(true)
    }

    /// RDPGFX_CACHE_TO_SURFACE_PDU (3.3.5.7).
    pub fn from_cache(&mut self, slot: u16, id: u16, points: &[(usize, usize)]) -> Result<bool> {
        let Some(e) = self.cache.remove(&slot) else {
            return proto(format!("gfx: cache slot {slot} is empty"));
        };
        let ok = self.surfaces.contains_key(&id);
        for &(x, y) in points {
            self.blit(id, Area::new(x, y, e.width, e.height), &e.pixels, e.width);
        }
        self.cache.insert(slot, e);
        Ok(ok)
    }

    /// RDPGFX_EVICT_CACHE_ENTRY_PDU (3.3.5.8).
    pub fn evict(&mut self, slot: u16) {
        if let Some(e) = self.cache.remove(&slot) {
            self.cache_bytes -= e.pixels.len() * 4;
        }
    }

    pub fn cached(&self, slot: u16) -> Option<(usize, usize, &[u32])> {
        self.cache
            .get(&slot)
            .map(|e| (e.width, e.height, e.pixels.as_slice()))
    }

    /// End of frame: composes every changed area of a mapped surface into
    /// the output buffer and queues it for presentation.
    pub fn compose(&mut self) {
        for (id, a) in std::mem::take(&mut self.dirty) {
            let Some(s) = self.surfaces.get(&id) else {
                continue;
            };
            let Some((ox, oy)) = s.origin else { continue };
            let Some(a) = a.clip(s.width, s.height) else {
                continue;
            };
            let out = Area::new(ox + a.x, oy + a.y, a.w, a.h);
            let Some(o) = out.clip(self.output.width, self.output.height) else {
                continue;
            };
            for row in 0..o.h {
                let src = (a.y + row) * s.width + a.x;
                let dst = (o.y + row) * self.output.width + o.x;
                self.output.pixels[dst..dst + o.w].copy_from_slice(&s.pixels[src..src + o.w]);
            }
            self.pending.push(Damage {
                x: o.x,
                y: o.y,
                w: o.w,
                h: o.h,
            });
        }
    }

    /// Copies composed areas to `fb` and appends them to `damage`. After a
    /// reset to a new size `fb` takes the output's size and is copied whole;
    /// returns true when `fb` was resized.
    pub fn present(&mut self, fb: &mut Framebuffer, damage: &mut Vec<Damage>) -> bool {
        let (ow, oh) = (self.output.width, self.output.height);
        let mut resized = false;
        if std::mem::take(&mut self.resized) && ow > 0 && oh > 0 {
            if (fb.width, fb.height) != (ow, oh) {
                fb.resize(ow, oh);
                resized = true;
            }
            self.pending.clear();
            self.pending.push(Damage {
                x: 0,
                y: 0,
                w: ow,
                h: oh,
            });
        }
        // Until a reset says otherwise the session size wins: areas outside
        // `fb` are dropped.
        for d in self.pending.drain(..) {
            let Some(a) = Area::new(d.x, d.y, d.w, d.h).clip(fb.width.min(ow), fb.height.min(oh))
            else {
                continue;
            };
            for row in a.y..a.y + a.h {
                let s = row * ow + a.x;
                let t = row * fb.width + a.x;
                fb.pixels[t..t + a.w].copy_from_slice(&self.output.pixels[s..s + a.w]);
            }
            damage.push(Damage {
                x: a.x,
                y: a.y,
                w: a.w,
                h: a.h,
            });
        }
        resized
    }
}
