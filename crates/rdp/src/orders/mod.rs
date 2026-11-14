//! Drawing orders (MS-RDPEGDI 2.2.2): primary orders drawn onto the
//! framebuffer or an offscreen bitmap, secondary orders filling the bitmap,
//! glyph, brush and colour table caches, alternate secondary orders for
//! offscreen bitmaps, and the persistent bitmap cache. RemoteApp window
//! orders in the same stream are handed back to the caller.
//!
//! Errors follow MS-RDPEGDI 3.2.5.1.1.1: an order that cannot be parsed
//! ends the batch (primary and alternate secondary orders carry no length,
//! so nothing after it can be found); an order that refers to a missing
//! cache entry is skipped. Neither ends the session.

pub mod caps;
pub mod draw;
pub mod fields;
pub mod persist;
pub mod primary;
pub mod secondary;

#[cfg(test)]
mod tests;

use std::path::Path;

use crate::codec;
use crate::cursor::Reader;
use crate::error::{Error, Result, proto};
use crate::framebuffer::{Damage, Framebuffer};
use crate::rail::orders::WindowOrder;
use crate::trace;
use draw::{Clip, Glyph, Pattern, Source, Surface};
use fields::{BrushFields, DeltaRect};
use primary::{Bounds, History};
use secondary::{BitmapCodec, CacheBitmap, CacheBrush, Secondary, WAITING_LIST_INDEX};

/// Cap on the persistent bitmap cache directory.
pub const PERSISTENT_CACHE_BYTES: u64 = 100 * 1024 * 1024;
/// Cap on the pixels of all offscreen bitmaps together (16 MB at 32 bpp).
const OFFSCREEN_MAX_PIXELS: usize = 4 * 1024 * 1024;
/// Largest bitmap a bitmap cache entry may hold.
const CACHE_MAX_PIXELS: usize = 256 * 256;
/// After this many damage rectangles in one batch they are merged into one.
const MAX_DAMAGE_PER_BATCH: usize = 64;

const SCREEN_BITMAP_SURFACE: u16 = 0xFFFF;
const TS_BITMAPCACHE_SCREEN_ID: u8 = 0xFF;

/// A decoded bitmap, 0x00RRGGBB, top-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    pub w: usize,
    pub h: usize,
    pub px: Vec<u32>,
}

impl Bitmap {
    fn source(&self) -> Source<'_> {
        Source {
            px: &self.px,
            w: self.w,
            h: self.h,
        }
    }
}

struct BitmapCache {
    entries: Vec<Option<Bitmap>>,
    /// The "last entry" (BITMAPCACHE_WAITING_LIST_INDEX).
    waiting: Option<Bitmap>,
    persistent: bool,
}

/// The client caches of MS-RDPEGDI 3.1.1.1.
struct Caches {
    bitmaps: Vec<BitmapCache>,
    glyphs: Vec<Vec<Option<Glyph>>>,
    fragments: Vec<Option<Vec<u8>>>,
    brushes: Vec<Option<CacheBrush>>,
    color_tables: Vec<Vec<u32>>,
}

impl Caches {
    fn new() -> Self {
        Self {
            bitmaps: caps::BITMAP_CACHES
                .iter()
                .map(|&(n, persistent)| BitmapCache {
                    entries: vec![None; n],
                    waiting: None,
                    persistent,
                })
                .collect(),
            glyphs: vec![vec![None; caps::GLYPH_CACHE_ENTRIES]; caps::GLYPH_CACHES],
            fragments: vec![None; 256],
            brushes: vec![None; caps::BRUSH_CACHE_ENTRIES],
            color_tables: vec![Vec::new(); 6],
        }
    }

    fn bitmap(&self, cache: u8, index: u16) -> Result<&Bitmap> {
        let c = self
            .bitmaps
            .get(cache as usize)
            .ok_or_else(|| Error::Protocol(format!("bitmap cache {cache}")))?;
        let b = if index == WAITING_LIST_INDEX {
            c.waiting.as_ref()
        } else {
            c.entries.get(index as usize).and_then(Option::as_ref)
        };
        b.ok_or_else(|| Error::Protocol(format!("bitmap cache {cache} entry {index} is empty")))
    }

    fn glyph(&self, cache: u8, index: u8) -> Result<&Glyph> {
        self.glyphs
            .get(cache as usize)
            .and_then(|c| c.get(index as usize))
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::Protocol(format!("glyph cache {cache} entry {index} is empty")))
    }
}

/// Drawing order state for one connection.
pub struct Orders {
    /// Session colour depth: how TS_COLOR values and bitmaps are encoded.
    bpp: u16,
    history: History,
    caches: Caches,
    offscreen: Vec<Option<Bitmap>>,
    /// Current drawing surface: None is the screen (Switch Surface).
    target: Option<u16>,
    store: Option<persist::Store>,
    /// Keys loaded from disk, per bitmap cache in index order.
    persisted_keys: Vec<Vec<u64>>,
    keys_sent: bool,
}

/// Bitmap Cache Host Support capability set type (MS-RDPBCGR 2.2.7.2.1).
pub const CAPSTYPE_BITMAPCACHE_HOSTSUPPORT: u16 = 18;

impl Orders {
    /// A fresh decoder. With `persistent_dir`, bitmaps the server marks as
    /// persistent are stored there and the stored ones are loaded into the
    /// caches now, to be announced with [`Orders::persistent_key_lists`].
    pub fn new(persistent_dir: Option<&Path>) -> Self {
        let mut o = Orders {
            bpp: 32,
            history: History::default(),
            caches: Caches::new(),
            offscreen: vec![None; caps::OFFSCREEN_CACHE_ENTRIES as usize],
            target: None,
            store: None,
            persisted_keys: vec![Vec::new(); caps::BITMAP_CACHES.len()],
            keys_sent: false,
        };
        if let Some(dir) = persistent_dir {
            match persist::Store::open(dir, PERSISTENT_CACHE_BYTES) {
                Ok(mut store) => {
                    for (id, cache) in o.caches.bitmaps.iter_mut().enumerate() {
                        if !cache.persistent {
                            continue;
                        }
                        let loaded = store.load(id as u8, cache.entries.len());
                        for (i, (key, bmp)) in loaded.into_iter().enumerate() {
                            cache.entries[i] = Some(bmp);
                            o.persisted_keys[id].push(key);
                        }
                    }
                    trace!(
                        "persistent bitmap cache {}: {} bitmaps",
                        dir.display(),
                        o.persisted_keys.iter().map(Vec::len).sum::<usize>()
                    );
                    o.store = Some(store);
                }
                Err(e) => trace!("persistent bitmap cache {} unusable: {e}", dir.display()),
            }
        }
        o
    }

    /// Starts a (re)activation: sets the session colour depth from the
    /// Demand Active PDU, draws on the screen again and clears the primary
    /// order history, which both sides start afresh. The caches stay.
    pub fn set_bpp(&mut self, bpp: u16) {
        self.bpp = bpp;
        self.target = None;
        self.history = History::default();
    }

    /// The client capability sets for drawing orders.
    pub fn client_caps(&self) -> Vec<(u16, Vec<u8>)> {
        // PERSISTENT_KEYS_EXPECTED_FLAG promises a Persistent Key List PDU
        // (2.2.7.1.4.2); set it only when one will follow.
        let keys = !self.keys_sent && self.persisted_keys.iter().any(|k| !k.is_empty());
        caps::client_caps(self.store.is_some(), keys)
    }

    /// Persistent Key List PDU bodies (MS-RDPBCGR 2.2.1.17) to send once,
    /// during the first connection finalization, if the server supports
    /// Revision 2 bitmap caches (3.2.5.3.17). Empty afterwards.
    pub fn persistent_key_lists(&mut self, server_supports: bool) -> Vec<Vec<u8>> {
        if self.keys_sent || !server_supports || self.store.is_none() {
            return Vec::new();
        }
        self.keys_sent = true;
        persist::key_list_pdus(&self.persisted_keys)
    }

    /// TS_UPDATE_ORDERS_PDU_DATA after the share data header (MS-RDPEGDI
    /// 2.2.2.1): updateType, pad, numberOrders, pad, orderData.
    pub fn slowpath(
        &mut self,
        update: &[u8],
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Result<Vec<WindowOrder>> {
        let mut r = Reader::new(update);
        r.u16()?;
        r.u16()?;
        let count = r.u16()?;
        r.u16()?;
        Ok(self.process(count, r.rest(), fb, damage))
    }

    /// TS_FP_UPDATE_ORDERS body (MS-RDPEGDI 2.2.2.2): numberOrders, orderData.
    pub fn fastpath(
        &mut self,
        update: &[u8],
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Result<Vec<WindowOrder>> {
        let mut r = Reader::new(update);
        let count = r.u16()?;
        Ok(self.process(count, r.rest(), fb, damage))
    }

    /// Runs `count` DRAWING_ORDERs (MS-RDPEGDI 2.2.2.2.1). Returns the
    /// window orders among them; screen changes go to `damage`.
    pub fn process(
        &mut self,
        count: u16,
        data: &[u8],
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Vec<WindowOrder> {
        let mut windows = Vec::new();
        let mut r = Reader::new(data);
        let first_damage = damage.len();
        for i in 0..count {
            let result = match r.u8() {
                Ok(control) => self.order(control, &mut r, fb, damage, &mut windows),
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                trace!("orders update: stopped at order {i} of {count}: {e}");
                break;
            }
        }
        if damage.len() - first_damage > MAX_DAMAGE_PER_BATCH {
            let merged = damage[first_damage..]
                .iter()
                .map(|d| Clip::rect(d.x as i32, d.y as i32, d.w as i32, d.h as i32))
                .fold(Clip::new(0, 0, 0, 0), Clip::union);
            damage.truncate(first_damage);
            damage.extend(to_damage(merged));
        }
        windows
    }

    /// One order; Err ends the batch.
    fn order(
        &mut self,
        control: u8,
        r: &mut Reader,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        windows: &mut Vec<WindowOrder>,
    ) -> Result<()> {
        match control & 0x03 {
            0x01 => {
                let header = self.history.read(control, r)?;
                if let Err(e) = self.draw_primary(header, fb, damage) {
                    trace!("primary order {:#04x} skipped: {e}", header.order_type);
                }
                Ok(())
            }
            0x03 => {
                // 2.2.2.2.1.2.1.1: orderLength is the length minus 13,
                // counted from controlFlags (one byte already read).
                let start = r.pos() - 1;
                let raw = r.u16()? as i16 as i32;
                let total = raw + 13;
                if total < 6 {
                    return proto(format!("secondary order length {total}"));
                }
                r.skip(total as usize - 3)?;
                let order = &r.buf_from(start)[..total as usize];
                if let Err(e) = self.secondary(order) {
                    trace!("secondary order {:?} skipped: {e}", order.get(5));
                }
                Ok(())
            }
            0x02 => self.alternate(control, r, windows),
            _ => proto(format!("drawing order class {control:#04x}")),
        }
    }

    /// TS_COLOR (MS-RDPEGDI 2.2.2.2.1.1.1.8) to 0x00RRGGBB: red, green,
    /// blue bytes at 24/32 bpp; a 15/16-bit pixel value at high colour.
    fn color(&self, raw: u32) -> u32 {
        match self.bpp {
            15 => codec::rgb555(raw & 0xFFFF),
            16 => codec::rgb565(raw & 0xFFFF),
            8 => {
                let t = &self.caches.color_tables[0];
                t.get((raw & 0xFF) as usize).copied().unwrap_or(0)
            }
            _ => (raw & 0xFF) << 16 | (raw & 0xFF00) | (raw >> 16 & 0xFF),
        }
    }

    /// A pixel value at a bitmap or brush depth to 0x00RRGGBB.
    fn pixel(&self, v: u32, bpp: u16) -> u32 {
        match bpp {
            15 => codec::rgb555(v),
            16 if self.bpp == 15 => codec::rgb555(v),
            16 => codec::rgb565(v),
            8 => self.caches.color_tables[0]
                .get(v as usize)
                .copied()
                .unwrap_or(0),
            _ => v & 0x00FF_FFFF,
        }
    }

    /// The brush of a PatBlt-style order (MS-RDPEGDI 2.2.2.2.1.1.2.3); None
    /// for BS_NULL. `transparent` is the TRANSPARENT background mode.
    fn pattern(
        &self,
        b: &BrushFields,
        back: u32,
        fore: u32,
        transparent: bool,
    ) -> Result<Option<Pattern>> {
        const TS_CACHED_BRUSH: u8 = 0x80;
        // HS_* hatch bitmaps; clear bits are the hatch lines.
        const HATCH: [[u8; 8]; 6] = [
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            [0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7],
            [0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F],
            [0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE],
            [0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0x00],
            [0x7E, 0xBD, 0xDB, 0xE7, 0xE7, 0xDB, 0xBD, 0x7E],
        ];
        let fg = self.color(fore);
        let bg = self.color(back);
        let org = (b.org_x as i32, b.org_y as i32);
        if b.style & TS_CACHED_BRUSH != 0 {
            let brush = self
                .caches
                .brushes
                .get(b.hatch as usize)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    Error::Protocol(format!("brush cache entry {} is empty", b.hatch))
                })?;
            if brush.format == secondary::BMF_1BPP {
                let mut rows = [0u8; 8];
                for (y, row) in rows.iter_mut().enumerate() {
                    for x in 0..8 {
                        *row |= (brush.px[y * 8 + x] as u8) << (7 - x);
                    }
                }
                return Ok(Some(Pattern::mono(rows, fg, bg, org, transparent)));
            }
            let bpp = match brush.format {
                secondary::BMF_8BPP => 8,
                secondary::BMF_16BPP => 16,
                secondary::BMF_24BPP => 24,
                _ => 32,
            };
            let mut px = Box::new([0u32; 64]);
            for (d, &v) in px.iter_mut().zip(brush.px.iter()) {
                *d = self.pixel(v, bpp);
            }
            return Ok(Some(Pattern::Bitmap {
                px,
                transparent: None,
                org_x: org.0,
                org_y: org.1,
            }));
        }
        Ok(match b.style {
            0 => Some(Pattern::Solid(fg)),
            1 => None,
            2 => {
                let rows = *HATCH
                    .get(b.hatch as usize)
                    .ok_or_else(|| Error::Protocol(format!("hatch style {}", b.hatch)))?;
                Some(Pattern::mono(rows, fg, bg, org, transparent))
            }
            3 => {
                // BrushHatch is the bottom row, BrushExtra rows 6..0.
                let mut rows = [0u8; 8];
                rows[7] = b.hatch;
                for (i, &e) in b.extra.iter().enumerate() {
                    rows[6 - i] = e;
                }
                Some(Pattern::mono(rows, fg, bg, org, transparent))
            }
            s => return proto(format!("brush style {s:#04x}")),
        })
    }

    /// Runs `f` on the current drawing surface; damage is recorded only for
    /// the screen.
    fn on_target(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        f: impl FnOnce(&mut Surface, &Caches) -> Result<Clip>,
    ) -> Result<()> {
        match self.target {
            None => {
                let mut s = Surface {
                    px: &mut fb.pixels,
                    w: fb.width,
                    h: fb.height,
                };
                let area = f(&mut s, &self.caches)?;
                damage.extend(to_damage(area));
            }
            Some(id) => {
                let bmp = self
                    .offscreen
                    .get_mut(id as usize)
                    .and_then(Option::as_mut)
                    .ok_or_else(|| {
                        Error::Protocol(format!("offscreen bitmap {id} does not exist"))
                    })?;
                let mut s = Surface {
                    px: &mut bmp.px,
                    w: bmp.w,
                    h: bmp.h,
                };
                f(&mut s, &self.caches)?;
            }
        }
        Ok(())
    }

    /// The current surface as a clip rectangle.
    fn target_bounds(&self, fb: &Framebuffer) -> Result<Clip> {
        let (w, h) = match self.target {
            None => (fb.width, fb.height),
            Some(id) => {
                let b = self
                    .offscreen
                    .get(id as usize)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| {
                        Error::Protocol(format!("offscreen bitmap {id} does not exist"))
                    })?;
                (b.w, b.h)
            }
        };
        Ok(Clip::new(0, 0, w as i32, h as i32))
    }

    /// A copy of a region of the current surface (ScrBlt's source).
    fn target_copy(&self, fb: &Framebuffer, x: i32, y: i32, w: i32, h: i32) -> Result<Bitmap> {
        let (px, sw, sh) = match self.target {
            None => (&fb.pixels[..], fb.width, fb.height),
            Some(id) => {
                let b = self
                    .offscreen
                    .get(id as usize)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| {
                        Error::Protocol(format!("offscreen bitmap {id} does not exist"))
                    })?;
                (&b.px[..], b.w, b.h)
            }
        };
        copy_region(px, sw, sh, x, y, w, h)
    }

    fn draw_primary(
        &mut self,
        h: primary::Header,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Result<()> {
        use primary::*;
        let clip = match h.bounds {
            Some(b) => Clip::inclusive(b.left, b.top, b.right, b.bottom),
            None => Clip::new(i32::MIN / 2, i32::MIN / 2, i32::MAX / 2, i32::MAX / 2),
        };
        match h.order_type {
            DSTBLT => {
                let o = self.history.dstblt.clone();
                let dst = to_clip(o.rect);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::blt(s, clip, dst, o.rop, &Pattern::Solid(0), None))
                })
            }
            PATBLT => {
                let o = self.history.patblt.clone();
                let Some(pat) = self.pattern(&o.brush, o.back, o.fore, false)? else {
                    return Ok(());
                };
                let dst = to_clip(o.rect);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::blt(s, clip, dst, o.rop, &pat, None))
                })
            }
            SCRBLT => {
                let o = self.history.scrblt.clone();
                self.scr_blt(fb, damage, clip, o.rect, o.rop, o.x_src, o.y_src)
            }
            OPAQUERECT => {
                let o = self.history.opaque_rect.clone();
                let pat = Pattern::Solid(self.color(o.color));
                let dst = to_clip(o.rect);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::blt(s, clip, dst, draw::ROP3_PATCOPY, &pat, None))
                })
            }
            MULTIDSTBLT => {
                let o = self.history.multi_dstblt.clone();
                let dst = to_clip(o.rect);
                for d in fields::delta_rects(&o.deltas, o.n as usize)? {
                    let c = clip.intersect(delta_clip(d));
                    self.on_target(fb, damage, |s, _| {
                        Ok(draw::blt(s, c, dst, o.rop, &Pattern::Solid(0), None))
                    })?;
                }
                Ok(())
            }
            MULTIPATBLT => {
                let o = self.history.multi_patblt.clone();
                let Some(pat) = self.pattern(&o.brush, o.back, o.fore, false)? else {
                    return Ok(());
                };
                let dst = to_clip(o.rect);
                for d in fields::delta_rects(&o.deltas, o.n as usize)? {
                    let c = clip.intersect(delta_clip(d));
                    self.on_target(fb, damage, |s, _| {
                        Ok(draw::blt(s, c, dst, o.rop, &pat, None))
                    })?;
                }
                Ok(())
            }
            MULTISCRBLT => {
                let o = self.history.multi_scrblt.clone();
                for d in fields::delta_rects(&o.deltas, o.n as usize)? {
                    let rect = Rect {
                        x: d.left,
                        y: d.top,
                        w: d.width,
                        h: d.height,
                    };
                    let sx = o.x_src + (d.left - o.rect.x);
                    let sy = o.y_src + (d.top - o.rect.y);
                    self.scr_blt(fb, damage, clip, rect, o.rop, sx, sy)?;
                }
                Ok(())
            }
            MULTIOPAQUERECT => {
                let o = self.history.multi_opaque_rect.clone();
                let pat = Pattern::Solid(self.color(o.color));
                for d in fields::delta_rects(&o.deltas, o.n as usize)? {
                    let dst = delta_clip(d);
                    self.on_target(fb, damage, |s, _| {
                        Ok(draw::blt(s, clip, dst, draw::ROP3_PATCOPY, &pat, None))
                    })?;
                }
                Ok(())
            }
            MEMBLT => {
                let o = self.history.memblt.clone();
                self.mem_blt(
                    fb,
                    damage,
                    clip,
                    o.cache_id,
                    o.cache_index,
                    o.rect,
                    o.x_src,
                    o.y_src,
                    o.rop,
                    &Pattern::Solid(0),
                )
            }
            MEM3BLT => {
                let o = self.history.mem3blt.clone();
                let Some(pat) = self.pattern(&o.brush, o.back, o.fore, false)? else {
                    return Ok(());
                };
                self.mem_blt(
                    fb,
                    damage,
                    clip,
                    o.cache_id,
                    o.cache_index,
                    o.rect,
                    o.x_src,
                    o.y_src,
                    o.rop,
                    &pat,
                )
            }
            LINETO => {
                let o = self.history.lineto.clone();
                let rop = draw::rop2_to_rop3(o.rop2);
                let c = self.color(o.pen);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::line(s, clip, (o.x0, o.y0), (o.x1, o.y1), rop, c))
                })
            }
            POLYLINE => {
                let o = self.history.polyline.clone();
                let rop = draw::rop2_to_rop3(o.rop2);
                let c = self.color(o.pen);
                let pts = fields::delta_points(&o.deltas, o.n as usize, o.x, o.y)?;
                self.on_target(fb, damage, |s, _| {
                    let mut area = Clip::new(0, 0, 0, 0);
                    let mut from = (o.x, o.y);
                    for &p in &pts {
                        area = area.union(draw::line(s, clip, from, p, rop, c));
                        from = p;
                    }
                    Ok(area)
                })
            }
            POLYGON_SC => {
                let o = self.history.polygon_sc.clone();
                let pat = Pattern::Solid(self.color(o.color));
                self.polygon(
                    fb,
                    damage,
                    clip,
                    o.x,
                    o.y,
                    &o.deltas,
                    o.n,
                    o.rop2,
                    o.fill_mode,
                    &pat,
                )
            }
            POLYGON_CB => {
                let o = self.history.polygon_cb.clone();
                // bRop2 bit 0x80: TRANSPARENT background mode (2.2.2.2.1.1.2.17).
                let Some(pat) = self.pattern(&o.brush, o.back, o.fore, o.rop2 & 0x80 != 0)? else {
                    return Ok(());
                };
                self.polygon(
                    fb,
                    damage,
                    clip,
                    o.x,
                    o.y,
                    &o.deltas,
                    o.n,
                    o.rop2 & 0x1F,
                    o.fill_mode,
                    &pat,
                )
            }
            ELLIPSE_SC => {
                let o = self.history.ellipse_sc.clone();
                let pat = Pattern::Solid(self.color(o.color));
                let rect = Clip::inclusive(o.left, o.top, o.right, o.bottom);
                let rop = draw::rop2_to_rop3(o.rop2);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::ellipse(s, clip, rect, o.fill_mode != 0, rop, &pat))
                })
            }
            ELLIPSE_CB => {
                let o = self.history.ellipse_cb.clone();
                let Some(pat) = self.pattern(&o.brush, o.back, o.fore, o.rop2 & 0x80 != 0)? else {
                    return Ok(());
                };
                let rect = Clip::inclusive(o.left, o.top, o.right, o.bottom);
                let rop = draw::rop2_to_rop3(o.rop2 & 0x1F);
                self.on_target(fb, damage, |s, _| {
                    Ok(draw::ellipse(s, clip, rect, o.fill_mode != 0, rop, &pat))
                })
            }
            GLYPH_INDEX => {
                let o = self.history.glyph_index.clone();
                self.glyph_index(fb, damage, clip, &o)
            }
            FAST_INDEX => {
                let o = self.history.fast_index.clone();
                self.fast_text(fb, damage, clip, &o, false)
            }
            FAST_GLYPH => {
                let o = self.history.fast_glyph.clone();
                self.fast_text(fb, damage, clip, &o, true)
            }
            t => proto(format!("primary order {t:#04x} not drawn")),
        }
    }

    /// ScrBlt (MS-RDPEGDI 2.2.2.2.1.1.2.7): from the current surface to itself.
    #[allow(clippy::too_many_arguments)]
    fn scr_blt(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        rect: primary::Rect,
        rop: u8,
        sx: i32,
        sy: i32,
    ) -> Result<()> {
        // Copy only the source of the visible part: source and destination
        // may overlap, and an off-screen rectangle may be huge.
        let area = clip
            .intersect(to_clip(rect))
            .intersect(self.target_bounds(fb)?);
        if area.is_empty() {
            return Ok(());
        }
        let (dx, dy) = (area.x0 - rect.x, area.y0 - rect.y);
        let src = self.target_copy(fb, sx + dx, sy + dy, area.x1 - area.x0, area.y1 - area.y0)?;
        self.on_target(fb, damage, |s, _| {
            Ok(draw::blt(
                s,
                area,
                area,
                rop,
                &Pattern::Solid(0),
                Some((&src.source(), 0, 0)),
            ))
        })
    }

    /// MemBlt / Mem3Blt (MS-RDPEGDI 2.2.2.2.1.1.2.9/10): from a bitmap cache
    /// entry or, with cache id 0xFF, an offscreen bitmap.
    #[allow(clippy::too_many_arguments)]
    fn mem_blt(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        cache_id: u16,
        index: u16,
        rect: primary::Rect,
        sx: i32,
        sy: i32,
        rop: u8,
        pat: &Pattern,
    ) -> Result<()> {
        // The high byte selects a colour table, used only at 8 bpp.
        let cache = cache_id as u8;
        let dst = to_clip(rect);
        if cache == TS_BITMAPCACHE_SCREEN_ID {
            let b = self
                .offscreen
                .get(index as usize)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    Error::Protocol(format!("offscreen bitmap {index} does not exist"))
                })?;
            // A copy, as the source may be the current surface itself.
            let area = clip.intersect(dst).intersect(self.target_bounds(fb)?);
            if area.is_empty() {
                return Ok(());
            }
            let (dx, dy) = (area.x0 - rect.x, area.y0 - rect.y);
            let src = copy_region(
                &b.px,
                b.w,
                b.h,
                sx + dx,
                sy + dy,
                area.x1 - area.x0,
                area.y1 - area.y0,
            )?;
            return self.on_target(fb, damage, |s, _| {
                Ok(draw::blt(
                    s,
                    area,
                    area,
                    rop,
                    pat,
                    Some((&src.source(), 0, 0)),
                ))
            });
        }
        self.caches.bitmap(cache, index)?;
        self.on_target(fb, damage, |s, c| {
            let b = c.bitmap(cache, index)?;
            Ok(draw::blt(
                s,
                clip,
                dst,
                rop,
                pat,
                Some((&b.source(), sx, sy)),
            ))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn polygon(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        x: i32,
        y: i32,
        deltas: &[u8],
        n: u8,
        rop2: u8,
        fill_mode: u8,
        pat: &Pattern,
    ) -> Result<()> {
        let mut pts = vec![(x, y)];
        pts.extend(fields::delta_points(deltas, n as usize, x, y)?);
        let rop = draw::rop2_to_rop3(rop2);
        // FillMode WINDING = 2, ALTERNATE = 1 (2.2.2.2.1.1.1.9).
        let winding = fill_mode == 2;
        self.on_target(fb, damage, |s, _| {
            Ok(draw::fill_polygon(s, clip, &pts, winding, rop, pat))
        })
    }

    /// GlyphIndex (MS-RDPEGDI 2.2.2.2.1.1.2.13): the opaque rectangle in
    /// ForeColor, then the glyphs in BackColor clipped to the background
    /// rectangle (both rectangles inclusive).
    fn glyph_index(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        o: &primary::GlyphIndex,
    ) -> Result<()> {
        let fore = Pattern::Solid(self.color(o.fore));
        let opaque = if o.op.right > o.op.left {
            Some(bounds_inclusive(o.op))
        } else if o.op_redundant != 0 && o.bk.right > o.bk.left {
            // The opaque rectangle equals the background one.
            Some(bounds_inclusive(o.bk))
        } else {
            None
        };
        let text_clip = if o.bk.right > o.bk.left {
            clip.intersect(bounds_inclusive(o.bk))
        } else {
            clip
        };
        let color = self.color(o.back);
        let run = TextRun {
            cache_id: o.cache_id,
            fl_accel: o.fl_accel,
            char_inc: o.ul_char_inc,
            x: o.x,
            y: o.y,
        };
        self.text(
            fb, damage, clip, opaque, &fore, text_clip, run, &o.data, color,
        )
    }

    /// FastIndex (2.2.2.2.1.1.2.14) and FastGlyph (2.2.2.2.1.1.2.15), with
    /// the opaque rectangle encoding of FastIndex's OpTop/OpBottom.
    fn fast_text(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        o: &primary::FastText,
        single: bool,
    ) -> Result<()> {
        let mut op = o.op;
        if op.bottom == -32768 {
            let flags = op.top & 0x0F;
            if flags & 0x01 != 0 {
                op.bottom = o.bk.bottom;
            }
            if flags & 0x02 != 0 {
                op.right = o.bk.right;
            }
            if flags & 0x04 != 0 {
                op.top = o.bk.top;
            }
            if flags & 0x08 != 0 {
                op.left = o.bk.left;
            }
        }
        if op.left == 0 {
            op.left = o.bk.left;
        }
        if op.right == 0 {
            op.right = o.bk.right;
        }
        let x = if o.x == -32768 { o.bk.left } else { o.x };
        let y = if o.y == -32768 { o.bk.top } else { o.y };
        let fore = Pattern::Solid(self.color(o.fore));
        // Fast orders give right/bottom as exclusive edges.
        let op_clip = Clip::new(op.left, op.top, op.right, op.bottom);
        let opaque = (!op_clip.is_empty()).then_some(op_clip);
        let bk = Clip::new(o.bk.left, o.bk.top, o.bk.right, o.bk.bottom);
        let text_clip = if bk.is_empty() {
            clip
        } else {
            clip.intersect(bk)
        };
        let color = self.color(o.back);
        let run = TextRun {
            cache_id: o.cache_id,
            fl_accel: o.fl_accel,
            char_inc: o.ul_char_inc,
            x,
            y,
        };
        if !single {
            return self.text(
                fb, damage, clip, opaque, &fore, text_clip, run, &o.data, color,
            );
        }
        // FastGlyph: one cached glyph index, or the glyph itself
        // (TS_CACHE_GLYPH_DATA_REV2), which is cached too.
        let index = match o.data.as_slice() {
            [] => return proto("empty FastGlyph data"),
            [i] => *i,
            data => {
                let (index, g) = secondary::glyph_v2(&mut Reader::new(data))?;
                self.put_glyph(o.cache_id, index, g)?;
                index as u8
            }
        };
        self.caches.glyph(o.cache_id, index)?;
        self.on_target(fb, damage, |s, c| {
            let mut area = Clip::new(0, 0, 0, 0);
            if let Some(op) = opaque {
                area = draw::blt(s, clip, op, draw::ROP3_PATCOPY, &fore, None);
            }
            let g = c.glyph(o.cache_id, index)?;
            Ok(area.union(draw::glyph(s, text_clip, g, x, y, color)))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn text(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        clip: Clip,
        opaque: Option<Clip>,
        fore: &Pattern,
        text_clip: Clip,
        run: TextRun,
        data: &[u8],
        color: u32,
    ) -> Result<()> {
        let placed = self.layout_glyphs(&run, data)?;
        self.on_target(fb, damage, |s, c| {
            let mut area = Clip::new(0, 0, 0, 0);
            if let Some(op) = opaque {
                area = draw::blt(s, clip, op, draw::ROP3_PATCOPY, fore, None);
            }
            for (index, x, y) in placed {
                if let Ok(g) = c.glyph(run.cache_id, index) {
                    area = area.union(draw::glyph(s, text_clip, g, x, y, color));
                }
            }
            Ok(area)
        })
    }

    /// Walks GlyphIndex/FastIndex glyph data (MS-RDPEGDI 2.2.2.2.1.1.2.13):
    /// glyph indices with optional deltas, USE (0xFE) and ADD (0xFF)
    /// fragment operations. Returns (glyph index, x, y) to draw.
    fn layout_glyphs(&mut self, run: &TextRun, data: &[u8]) -> Result<Vec<(u8, i32, i32)>> {
        let mut pen = (run.x, run.y);
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let op = data[i];
            i += 1;
            match op {
                0xFE => {
                    let id = *data
                        .get(i)
                        .ok_or_else(|| Error::Protocol("truncated USE".into()))?;
                    i += 1;
                    if run.explicit_deltas() && i < data.len() {
                        let d = read_delta(data, &mut i)?;
                        run.advance(&mut pen, d);
                    }
                    let frag = self.caches.fragments[id as usize]
                        .clone()
                        .ok_or_else(|| Error::Protocol(format!("glyph fragment {id} is empty")))?;
                    self.layout_run(run, &frag, &mut pen, &mut out)?;
                }
                0xFF => {
                    let (Some(&id), Some(&size)) = (data.get(i), data.get(i + 1)) else {
                        return proto("truncated ADD");
                    };
                    let end = i - 1;
                    let start = end.checked_sub(size as usize).ok_or_else(|| {
                        Error::Protocol("glyph fragment larger than the data".into())
                    })?;
                    self.caches.fragments[id as usize] = Some(data[start..end].to_vec());
                    i += 2;
                }
                index => {
                    let d = if run.explicit_deltas() {
                        read_delta(data, &mut i)?
                    } else {
                        0
                    };
                    self.place(run, index, d, &mut pen, &mut out);
                }
            }
        }
        Ok(out)
    }

    /// A fragment's glyph entries (no USE/ADD inside).
    fn layout_run(
        &self,
        run: &TextRun,
        data: &[u8],
        pen: &mut (i32, i32),
        out: &mut Vec<(u8, i32, i32)>,
    ) -> Result<()> {
        let mut i = 0;
        while i < data.len() {
            let index = data[i];
            i += 1;
            let d = if run.explicit_deltas() {
                read_delta(data, &mut i)?
            } else {
                0
            };
            self.place(run, index, d, pen, out);
        }
        Ok(())
    }

    fn place(
        &self,
        run: &TextRun,
        index: u8,
        delta: i32,
        pen: &mut (i32, i32),
        out: &mut Vec<(u8, i32, i32)>,
    ) {
        const SO_CHAR_INC_EQUAL_BM_BASE: u8 = 0x20;
        run.advance(pen, delta);
        out.push((index, pen.0, pen.1));
        let step = if run.char_inc != 0 {
            run.char_inc as i32
        } else if run.fl_accel & SO_CHAR_INC_EQUAL_BM_BASE != 0 {
            self.caches
                .glyph(run.cache_id, index)
                .map_or(0, |g| g.cx as i32)
        } else {
            0
        };
        run.advance(pen, step);
    }

    fn put_glyph(&mut self, cache: u8, index: u16, g: Glyph) -> Result<()> {
        let slot = self
            .caches
            .glyphs
            .get_mut(cache as usize)
            .and_then(|c| c.get_mut(index as usize))
            .ok_or_else(|| Error::Protocol(format!("glyph cache {cache} entry {index}")))?;
        *slot = Some(g);
        Ok(())
    }

    /// Applies one secondary order (MS-RDPEGDI 3.2.5.1.2.1).
    fn secondary(&mut self, order: &[u8]) -> Result<()> {
        match secondary::parse(order)? {
            Secondary::Bitmap(b) => self.cache_bitmap(&b),
            Secondary::ColorTable { index, colors } => {
                let slot = self
                    .caches
                    .color_tables
                    .get_mut(index as usize)
                    .ok_or_else(|| Error::Protocol(format!("color table {index}")))?;
                *slot = colors;
                Ok(())
            }
            Secondary::Glyphs { cache_id, glyphs } => {
                for (index, g) in glyphs {
                    self.put_glyph(cache_id, index, g)?;
                }
                Ok(())
            }
            Secondary::Brush(b) => {
                let slot = self
                    .caches
                    .brushes
                    .get_mut(b.index as usize)
                    .ok_or_else(|| Error::Protocol(format!("brush cache entry {}", b.index)))?;
                *slot = Some(*b);
                Ok(())
            }
            Secondary::Other(t) => proto(format!("secondary order type {t}")),
        }
    }

    fn cache_bitmap(&mut self, b: &CacheBitmap) -> Result<()> {
        let (w, h) = (b.width as usize, b.height as usize);
        if w == 0 || h == 0 || w * h > CACHE_MAX_PIXELS {
            return proto(format!("{w}x{h} cache bitmap"));
        }
        let bpp = if b.bpp == 16 && self.bpp == 15 {
            15
        } else {
            b.bpp
        };
        let px = match b.codec {
            BitmapCodec::Raw => codec::uncompressed(b.data, w, h, bpp)?,
            BitmapCodec::Compressed if bpp == 32 => codec::planar::decode(b.data, w, h)?,
            BitmapCodec::Compressed => codec::interleaved::decode(b.data, w, h, bpp)?,
            BitmapCodec::Ex(0) => raw_ex(b.data, w, h, bpp)?,
            BitmapCodec::Ex(c) => {
                return Err(Error::Unsupported(format!("cache bitmap codec {c}")));
            }
        };
        let px = if bpp == 8 {
            px.iter().map(|&v| self.pixel(v, 8)).collect()
        } else {
            px
        };
        let bmp = Bitmap { w, h, px };
        let cache = self
            .caches
            .bitmaps
            .get_mut(b.cache_id as usize)
            .ok_or_else(|| Error::Protocol(format!("bitmap cache {}", b.cache_id)))?;
        if let (Some(key), true, Some(store)) = (b.key, cache.persistent, self.store.as_mut()) {
            store.save(b.cache_id, key, &bmp);
        }
        if b.index == WAITING_LIST_INDEX {
            cache.waiting = Some(bmp);
        } else {
            *cache.entries.get_mut(b.index as usize).ok_or_else(|| {
                Error::Protocol(format!("bitmap cache {} entry {}", b.cache_id, b.index))
            })? = Some(bmp);
        }
        Ok(())
    }

    /// One alternate secondary order (MS-RDPEGDI 2.2.2.2.1.3). Those this
    /// client does not negotiate are skipped by their own length fields.
    fn alternate(
        &mut self,
        control: u8,
        r: &mut Reader,
        windows: &mut Vec<WindowOrder>,
    ) -> Result<()> {
        let ty = control >> 2;
        match ty {
            // Switch Surface (2.2.2.2.1.3.3).
            0x00 => {
                let id = r.u16()?;
                self.target = (id != SCREEN_BITMAP_SURFACE).then_some(id);
                if id != SCREEN_BITMAP_SURFACE && id >= caps::OFFSCREEN_CACHE_ENTRIES {
                    return proto(format!("switch surface to {id}"));
                }
            }
            // Create Offscreen Bitmap (2.2.2.2.1.3.2).
            0x01 => {
                let flags = r.u16()?;
                let cx = r.u16()? as usize;
                let cy = r.u16()? as usize;
                if flags & 0x8000 != 0 {
                    let n = r.u16()?;
                    for _ in 0..n {
                        let i = r.u16()? as usize;
                        if let Some(slot) = self.offscreen.get_mut(i) {
                            *slot = None;
                        }
                    }
                }
                let id = (flags & 0x7FFF) as usize;
                let used: usize = self
                    .offscreen
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != id)
                    .filter_map(|(_, b)| b.as_ref().map(|b| b.px.len()))
                    .sum();
                if id >= self.offscreen.len() || used + cx * cy > OFFSCREEN_MAX_PIXELS {
                    trace!("offscreen bitmap {id} ({cx}x{cy}) refused");
                    if let Some(slot) = self.offscreen.get_mut(id) {
                        *slot = None;
                    }
                } else {
                    self.offscreen[id] = Some(Bitmap {
                        w: cx,
                        h: cy,
                        px: vec![0; cx * cy],
                    });
                }
            }
            // Stream Bitmap First / Next (2.2.2.2.1.3.5).
            0x02 => {
                let flags = r.u8()?;
                r.skip(7)?; // BitmapBpp, BitmapType, BitmapWidth, BitmapHeight
                if flags & 0x04 != 0 {
                    r.u32()?;
                } else {
                    r.u16()?;
                }
                let n = r.u16()? as usize;
                r.skip(n)?;
            }
            0x03 => {
                r.skip(3)?;
                let n = r.u16()? as usize;
                r.skip(n)?;
            }
            // Create NineGrid Bitmap (2.2.2.2.1.3.4).
            0x04 => r.skip(1 + 2 + 2 + 2 + 16)?,
            // Draw GDI+ First / Next / End (2.2.2.2.1.3.6.5-7).
            0x05 | 0x07 => {
                r.u8()?;
                let n = r.u16()? as usize;
                r.skip(8 + n)?;
            }
            0x06 => {
                r.u8()?;
                let n = r.u16()? as usize;
                r.skip(n)?;
            }
            // Draw GDI+ Cache First / Next / End (2.2.2.2.1.3.6.2-4).
            0x08 | 0x0A => {
                r.skip(5)?;
                let n = r.u16()? as usize;
                r.skip(4 + n)?;
            }
            0x09 => {
                r.skip(5)?;
                let n = r.u16()? as usize;
                r.skip(n)?;
            }
            // Windowing orders (MS-RDPERP 2.2.1.3) carry their own size.
            crate::rail::orders::TS_ALTSEC_WINDOW => {
                let start = r.pos() - 1;
                let size = r.u16()? as usize;
                if size < 3 {
                    return proto(format!("window order size {size}"));
                }
                r.skip(size - 3)?;
                match crate::rail::orders::parse_window_order(&r.buf_from(start)[..size]) {
                    Ok(o) => windows.push(o),
                    Err(e) => trace!("window order skipped: {e}"),
                }
            }
            // Frame Marker (2.2.2.2.1.3.7).
            0x0D => {
                r.u32()?;
            }
            t => return proto(format!("alternate secondary order {t:#04x}")),
        }
        Ok(())
    }
}

/// Position and spacing of a glyph run.
struct TextRun {
    cache_id: u8,
    fl_accel: u8,
    char_inc: u8,
    x: i32,
    y: i32,
}

impl TextRun {
    /// Glyph indices are followed by deltas unless the font is fixed pitch
    /// or SO_CHAR_INC_EQUAL_BM_BASE is set.
    fn explicit_deltas(&self) -> bool {
        self.char_inc == 0 && self.fl_accel & 0x20 == 0
    }

    fn advance(&self, pen: &mut (i32, i32), d: i32) {
        const SO_VERTICAL: u8 = 0x04;
        const SO_REVERSED: u8 = 0x08;
        let d = if self.fl_accel & SO_REVERSED != 0 {
            -d
        } else {
            d
        };
        if self.fl_accel & SO_VERTICAL != 0 {
            pen.1 += d;
        } else {
            pen.0 += d;
        }
    }
}

/// A glyph delta: one byte, or 0x80 and a 2-byte little-endian value.
fn read_delta(data: &[u8], i: &mut usize) -> Result<i32> {
    let b = *data
        .get(*i)
        .ok_or_else(|| Error::Protocol("truncated glyph delta".into()))?;
    *i += 1;
    if b != 0x80 {
        return Ok(b as i32);
    }
    let v = crate::cursor::le16(data, *i)
        .ok_or_else(|| Error::Protocol("truncated glyph delta".into()))?;
    *i += 2;
    Ok(v as i32)
}

fn to_clip(r: primary::Rect) -> Clip {
    Clip::rect(r.x, r.y, r.w, r.h)
}

fn delta_clip(d: DeltaRect) -> Clip {
    Clip::rect(d.left, d.top, d.width, d.height)
}

fn bounds_inclusive(b: Bounds) -> Clip {
    Clip::inclusive(b.left, b.top, b.right, b.bottom)
}

fn to_damage(c: Clip) -> Option<Damage> {
    (!c.is_empty() && c.x0 >= 0 && c.y0 >= 0).then(|| Damage {
        x: c.x0 as usize,
        y: c.y0 as usize,
        w: (c.x1 - c.x0) as usize,
        h: (c.y1 - c.y0) as usize,
    })
}

/// `w` x `h` pixels at (x, y) of a surface; outside pixels are 0.
fn copy_region(px: &[u32], sw: usize, sh: usize, x: i32, y: i32, w: i32, h: i32) -> Result<Bitmap> {
    let (w, h) = (w.max(0) as usize, h.max(0) as usize);
    if w * h > 64 * 1024 * 1024 {
        return proto(format!("{w}x{h} source region"));
    }
    let mut out = vec![0u32; w * h];
    for row in 0..h {
        let syy = y + row as i32;
        if syy < 0 || syy as usize >= sh {
            continue;
        }
        for col in 0..w {
            let sxx = x + col as i32;
            if sxx >= 0 && (sxx as usize) < sw {
                out[row * w + col] = px[syy as usize * sw + sxx as usize];
            }
        }
    }
    Ok(Bitmap { w, h, px: out })
}

/// Uncompressed TS_BITMAP_DATA_EX pixels (codecID 0): bottom-up rows.
fn raw_ex(data: &[u8], w: usize, h: usize, bpp: u16) -> Result<Vec<u32>> {
    let bytes = match bpp {
        15 | 16 => 2,
        24 => 3,
        32 => 4,
        _ => return Err(Error::Unsupported(format!("{bpp} bpp cache bitmap"))),
    };
    if data.len() < w * h * bytes {
        return proto("uncompressed bitmap too short");
    }
    let raw: Vec<u32> = data[..w * h * bytes]
        .chunks_exact(bytes)
        .map(|p| p.iter().take(3).rev().fold(0u32, |v, &b| v << 8 | b as u32))
        .collect();
    Ok(codec::to_rgb_top_down(&raw, w, h, bpp))
}
