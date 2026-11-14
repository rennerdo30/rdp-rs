//! Primary drawing orders (MS-RDPEGDI 2.2.2.2.1.1.2): field decoding into
//! the Primary Drawing Order History (3.2.5.1.1.1). Every field keeps its
//! last value per order type; an order only carries the fields that changed.

use super::fields::{BrushFields, Fields};
use crate::cursor::Reader;
use crate::error::{Result, proto};

pub const TS_STANDARD: u8 = 0x01;
pub const TS_SECONDARY: u8 = 0x02;
pub const TS_BOUNDS: u8 = 0x04;
pub const TS_TYPE_CHANGE: u8 = 0x08;
pub const TS_DELTA_COORDINATES: u8 = 0x10;
pub const TS_ZERO_BOUNDS_DELTAS: u8 = 0x20;

pub const DSTBLT: u8 = 0x00;
pub const PATBLT: u8 = 0x01;
pub const SCRBLT: u8 = 0x02;
pub const LINETO: u8 = 0x09;
pub const OPAQUERECT: u8 = 0x0A;
pub const MEMBLT: u8 = 0x0D;
pub const MEM3BLT: u8 = 0x0E;
pub const MULTIDSTBLT: u8 = 0x0F;
pub const MULTIPATBLT: u8 = 0x10;
pub const MULTISCRBLT: u8 = 0x11;
pub const MULTIOPAQUERECT: u8 = 0x12;
pub const FAST_INDEX: u8 = 0x13;
pub const POLYGON_SC: u8 = 0x14;
pub const POLYGON_CB: u8 = 0x15;
pub const POLYLINE: u8 = 0x16;
pub const FAST_GLYPH: u8 = 0x18;
pub const ELLIPSE_SC: u8 = 0x19;
pub const ELLIPSE_CB: u8 = 0x1A;
pub const GLYPH_INDEX: u8 = 0x1B;

/// Number of fields of each supported order (from its section's
/// "Number of fields"); None for orders this client does not negotiate.
fn field_count(ty: u8) -> Option<u32> {
    Some(match ty {
        DSTBLT => 5,
        PATBLT => 12,
        SCRBLT => 7,
        LINETO => 10,
        OPAQUERECT => 7,
        MEMBLT => 9,
        MEM3BLT => 16,
        MULTIDSTBLT => 7,
        MULTIPATBLT => 14,
        MULTISCRBLT => 9,
        MULTIOPAQUERECT => 9,
        FAST_INDEX => 15,
        POLYGON_SC => 7,
        POLYGON_CB => 13,
        POLYLINE => 7,
        FAST_GLYPH => 15,
        ELLIPSE_SC => 7,
        ELLIPSE_CB => 13,
        GLYPH_INDEX => 22,
        _ => return None,
    })
}

/// Inclusive bounding rectangle (TS_BOUNDS, 2.2.2.2.1.1.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bounds {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// A rectangle given as left/top/width/height Coord fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DstBlt {
    pub rect: Rect,
    pub rop: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PatBlt {
    pub rect: Rect,
    pub rop: u8,
    pub back: u32,
    pub fore: u32,
    pub brush: BrushFields,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScrBlt {
    pub rect: Rect,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpaqueRect {
    pub rect: Rect,
    pub color: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultiDstBlt {
    pub rect: Rect,
    pub rop: u8,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultiPatBlt {
    pub rect: Rect,
    pub rop: u8,
    pub back: u32,
    pub fore: u32,
    pub brush: BrushFields,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultiScrBlt {
    pub rect: Rect,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultiOpaqueRect {
    pub rect: Rect,
    pub color: u32,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemBlt {
    pub cache_id: u16,
    pub rect: Rect,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
    pub cache_index: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mem3Blt {
    pub cache_id: u16,
    pub rect: Rect,
    pub rop: u8,
    pub x_src: i32,
    pub y_src: i32,
    pub back: u32,
    pub fore: u32,
    pub brush: BrushFields,
    pub cache_index: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineTo {
    pub back_mode: u16,
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
    pub back: u32,
    pub rop2: u8,
    pub pen_style: u8,
    pub pen_width: u8,
    pub pen: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolygonSc {
    pub x: i32,
    pub y: i32,
    pub rop2: u8,
    pub fill_mode: u8,
    pub color: u32,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolygonCb {
    pub x: i32,
    pub y: i32,
    pub rop2: u8,
    pub fill_mode: u8,
    pub back: u32,
    pub fore: u32,
    pub brush: BrushFields,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Polyline {
    pub x: i32,
    pub y: i32,
    pub rop2: u8,
    pub brush_cache_entry: u16,
    pub pen: u32,
    pub n: u8,
    pub deltas: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EllipseSc {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub rop2: u8,
    pub fill_mode: u8,
    pub color: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EllipseCb {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub rop2: u8,
    pub fill_mode: u8,
    pub back: u32,
    pub fore: u32,
    pub brush: BrushFields,
}

/// GlyphIndex, and FastIndex/FastGlyph once decoded (they share the glyph
/// fields; FastIndex/FastGlyph pack flAccel and ulCharInc into fDrawing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GlyphIndex {
    pub cache_id: u8,
    pub fl_accel: u8,
    pub ul_char_inc: u8,
    pub op_redundant: u8,
    /// Text colour.
    pub back: u32,
    /// Opaque rectangle colour.
    pub fore: u32,
    pub bk: Bounds,
    pub op: Bounds,
    pub brush: BrushFields,
    pub x: i32,
    pub y: i32,
    pub data: Vec<u8>,
}

/// FastIndex (2.2.2.2.1.1.2.14) and FastGlyph (2.2.2.2.1.1.2.15) fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FastText {
    pub cache_id: u8,
    pub fl_accel: u8,
    pub ul_char_inc: u8,
    pub back: u32,
    pub fore: u32,
    pub bk: Bounds,
    pub op: Bounds,
    pub x: i32,
    pub y: i32,
    pub data: Vec<u8>,
}

/// The Primary Drawing Order History (MS-RDPEGDI 3.2.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct History {
    pub order_type: u8,
    pub bounds: Bounds,
    pub dstblt: DstBlt,
    pub patblt: PatBlt,
    pub scrblt: ScrBlt,
    pub opaque_rect: OpaqueRect,
    pub multi_dstblt: MultiDstBlt,
    pub multi_patblt: MultiPatBlt,
    pub multi_scrblt: MultiScrBlt,
    pub multi_opaque_rect: MultiOpaqueRect,
    pub memblt: MemBlt,
    pub mem3blt: Mem3Blt,
    pub lineto: LineTo,
    pub polygon_sc: PolygonSc,
    pub polygon_cb: PolygonCb,
    pub polyline: Polyline,
    pub ellipse_sc: EllipseSc,
    pub ellipse_cb: EllipseCb,
    pub glyph_index: GlyphIndex,
    pub fast_index: FastText,
    pub fast_glyph: FastText,
}

impl Default for History {
    fn default() -> Self {
        Self {
            // The initial order type is PatBlt (2.2.2.2.1.1.2).
            order_type: PATBLT,
            bounds: Bounds::default(),
            dstblt: Default::default(),
            patblt: Default::default(),
            scrblt: Default::default(),
            opaque_rect: Default::default(),
            multi_dstblt: Default::default(),
            multi_patblt: Default::default(),
            multi_scrblt: Default::default(),
            multi_opaque_rect: Default::default(),
            memblt: Default::default(),
            mem3blt: Default::default(),
            lineto: Default::default(),
            polygon_sc: Default::default(),
            polygon_cb: Default::default(),
            polyline: Default::default(),
            ellipse_sc: Default::default(),
            ellipse_cb: Default::default(),
            glyph_index: Default::default(),
            fast_index: Default::default(),
            fast_glyph: Default::default(),
        }
    }
}

/// The decoded header of one primary order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub order_type: u8,
    /// The bounds to clip to, when TS_BOUNDS is set.
    pub bounds: Option<Bounds>,
}

fn rect(f: &mut Fields, first: u32, r: &mut Rect) -> Result<()> {
    f.coord(first, &mut r.x)?;
    f.coord(first + 1, &mut r.y)?;
    f.coord(first + 2, &mut r.w)?;
    f.coord(first + 3, &mut r.h)
}

impl History {
    /// Decodes one primary order after its controlFlags byte, updating the
    /// history. Fails on truncated data or an order type this client did
    /// not negotiate; the rest of the batch cannot be parsed then.
    pub fn read(&mut self, control: u8, r: &mut Reader) -> Result<Header> {
        if control & TS_TYPE_CHANGE != 0 {
            self.order_type = r.u8()?;
        }
        let ty = self.order_type;
        let Some(fields) = field_count(ty) else {
            return proto(format!("primary order type {ty:#04x} not supported"));
        };
        // ceil((fields + 1) / 8) bytes, minus the zero bytes counted by
        // TS_ZERO_FIELD_BYTE_BIT0/1.
        let n = (fields as usize + 1).div_ceil(8);
        let n = n.saturating_sub((control >> 6) as usize);
        let mut flags = 0u32;
        for i in 0..n {
            flags |= (r.u8()? as u32) << (8 * i);
        }
        let bounds = if control & TS_BOUNDS != 0 {
            if control & TS_ZERO_BOUNDS_DELTAS == 0 {
                self.read_bounds(r)?;
            }
            Some(self.bounds)
        } else {
            None
        };
        let mut f = Fields {
            r,
            flags,
            delta: control & TS_DELTA_COORDINATES != 0,
        };
        self.read_fields(ty, &mut f)?;
        Ok(Header {
            order_type: ty,
            bounds,
        })
    }

    fn read_bounds(&mut self, r: &mut Reader) -> Result<()> {
        let flags = r.u8()?;
        let b = &mut self.bounds;
        for (i, v) in [&mut b.left, &mut b.top, &mut b.right, &mut b.bottom]
            .into_iter()
            .enumerate()
        {
            if flags & (0x10 << i) != 0 {
                *v = (*v as i16).wrapping_add(r.u8()? as i8 as i16) as i32;
            } else if flags & (1 << i) != 0 {
                *v = r.u16()? as i16 as i32;
            }
        }
        Ok(())
    }

    fn read_fields(&mut self, ty: u8, f: &mut Fields) -> Result<()> {
        match ty {
            // 2.2.2.2.1.1.2.1
            DSTBLT => {
                let o = &mut self.dstblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)
            }
            // 2.2.2.2.1.1.2.3
            PATBLT => {
                let o = &mut self.patblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)?;
                f.color(6, &mut o.back)?;
                f.color(7, &mut o.fore)?;
                f.brush(8, &mut o.brush)
            }
            // 2.2.2.2.1.1.2.7
            SCRBLT => {
                let o = &mut self.scrblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)?;
                f.coord(6, &mut o.x_src)?;
                f.coord(7, &mut o.y_src)
            }
            // 2.2.2.2.1.1.2.5
            OPAQUERECT => {
                let o = &mut self.opaque_rect;
                rect(f, 1, &mut o.rect)?;
                f.color_byte(5, &mut o.color, 0)?;
                f.color_byte(6, &mut o.color, 8)?;
                f.color_byte(7, &mut o.color, 16)
            }
            // 2.2.2.2.1.1.2.2
            MULTIDSTBLT => {
                let o = &mut self.multi_dstblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)?;
                f.u8(6, &mut o.n)?;
                f.var2(7, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.4
            MULTIPATBLT => {
                let o = &mut self.multi_patblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)?;
                f.color(6, &mut o.back)?;
                f.color(7, &mut o.fore)?;
                f.brush(8, &mut o.brush)?;
                f.u8(13, &mut o.n)?;
                f.var2(14, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.8
            MULTISCRBLT => {
                let o = &mut self.multi_scrblt;
                rect(f, 1, &mut o.rect)?;
                f.u8(5, &mut o.rop)?;
                f.coord(6, &mut o.x_src)?;
                f.coord(7, &mut o.y_src)?;
                f.u8(8, &mut o.n)?;
                f.var2(9, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.6
            MULTIOPAQUERECT => {
                let o = &mut self.multi_opaque_rect;
                rect(f, 1, &mut o.rect)?;
                f.color_byte(5, &mut o.color, 0)?;
                f.color_byte(6, &mut o.color, 8)?;
                f.color_byte(7, &mut o.color, 16)?;
                f.u8(8, &mut o.n)?;
                f.var2(9, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.9
            MEMBLT => {
                let o = &mut self.memblt;
                f.u16(1, &mut o.cache_id)?;
                rect(f, 2, &mut o.rect)?;
                f.u8(6, &mut o.rop)?;
                f.coord(7, &mut o.x_src)?;
                f.coord(8, &mut o.y_src)?;
                f.u16(9, &mut o.cache_index)
            }
            // 2.2.2.2.1.1.2.10
            MEM3BLT => {
                let o = &mut self.mem3blt;
                f.u16(1, &mut o.cache_id)?;
                rect(f, 2, &mut o.rect)?;
                f.u8(6, &mut o.rop)?;
                f.coord(7, &mut o.x_src)?;
                f.coord(8, &mut o.y_src)?;
                f.color(9, &mut o.back)?;
                f.color(10, &mut o.fore)?;
                f.brush(11, &mut o.brush)?;
                f.u16(16, &mut o.cache_index)
            }
            // 2.2.2.2.1.1.2.11
            LINETO => {
                let o = &mut self.lineto;
                f.u16(1, &mut o.back_mode)?;
                f.coord(2, &mut o.x0)?;
                f.coord(3, &mut o.y0)?;
                f.coord(4, &mut o.x1)?;
                f.coord(5, &mut o.y1)?;
                f.color(6, &mut o.back)?;
                f.u8(7, &mut o.rop2)?;
                f.u8(8, &mut o.pen_style)?;
                f.u8(9, &mut o.pen_width)?;
                f.color(10, &mut o.pen)
            }
            // 2.2.2.2.1.1.2.16
            POLYGON_SC => {
                let o = &mut self.polygon_sc;
                f.coord(1, &mut o.x)?;
                f.coord(2, &mut o.y)?;
                f.u8(3, &mut o.rop2)?;
                f.u8(4, &mut o.fill_mode)?;
                f.color(5, &mut o.color)?;
                f.u8(6, &mut o.n)?;
                f.var1(7, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.17
            POLYGON_CB => {
                let o = &mut self.polygon_cb;
                f.coord(1, &mut o.x)?;
                f.coord(2, &mut o.y)?;
                f.u8(3, &mut o.rop2)?;
                f.u8(4, &mut o.fill_mode)?;
                f.color(5, &mut o.back)?;
                f.color(6, &mut o.fore)?;
                f.brush(7, &mut o.brush)?;
                f.u8(12, &mut o.n)?;
                f.var1(13, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.18
            POLYLINE => {
                let o = &mut self.polyline;
                f.coord(1, &mut o.x)?;
                f.coord(2, &mut o.y)?;
                f.u8(3, &mut o.rop2)?;
                f.u16(4, &mut o.brush_cache_entry)?;
                f.color(5, &mut o.pen)?;
                f.u8(6, &mut o.n)?;
                f.var1(7, &mut o.deltas)
            }
            // 2.2.2.2.1.1.2.19
            ELLIPSE_SC => {
                let o = &mut self.ellipse_sc;
                f.coord(1, &mut o.left)?;
                f.coord(2, &mut o.top)?;
                f.coord(3, &mut o.right)?;
                f.coord(4, &mut o.bottom)?;
                f.u8(5, &mut o.rop2)?;
                f.u8(6, &mut o.fill_mode)?;
                f.color(7, &mut o.color)
            }
            // 2.2.2.2.1.1.2.20
            ELLIPSE_CB => {
                let o = &mut self.ellipse_cb;
                f.coord(1, &mut o.left)?;
                f.coord(2, &mut o.top)?;
                f.coord(3, &mut o.right)?;
                f.coord(4, &mut o.bottom)?;
                f.u8(5, &mut o.rop2)?;
                f.u8(6, &mut o.fill_mode)?;
                f.color(7, &mut o.back)?;
                f.color(8, &mut o.fore)?;
                f.brush(9, &mut o.brush)
            }
            // 2.2.2.2.1.1.2.13: Bk/Op/X/Y are plain 2-byte fields here.
            GLYPH_INDEX => {
                let o = &mut self.glyph_index;
                f.u8(1, &mut o.cache_id)?;
                f.u8(2, &mut o.fl_accel)?;
                f.u8(3, &mut o.ul_char_inc)?;
                f.u8(4, &mut o.op_redundant)?;
                f.color(5, &mut o.back)?;
                f.color(6, &mut o.fore)?;
                f.i16(7, &mut o.bk.left)?;
                f.i16(8, &mut o.bk.top)?;
                f.i16(9, &mut o.bk.right)?;
                f.i16(10, &mut o.bk.bottom)?;
                f.i16(11, &mut o.op.left)?;
                f.i16(12, &mut o.op.top)?;
                f.i16(13, &mut o.op.right)?;
                f.i16(14, &mut o.op.bottom)?;
                f.brush(15, &mut o.brush)?;
                f.i16(20, &mut o.x)?;
                f.i16(21, &mut o.y)?;
                f.var1(22, &mut o.data)
            }
            // 2.2.2.2.1.1.2.14 / 2.2.2.2.1.1.2.15
            FAST_INDEX | FAST_GLYPH => {
                let o = if ty == FAST_INDEX {
                    &mut self.fast_index
                } else {
                    &mut self.fast_glyph
                };
                f.u8(1, &mut o.cache_id)?;
                if f.has(2) {
                    o.ul_char_inc = f.r.u8()?;
                    o.fl_accel = f.r.u8()?;
                }
                f.color(3, &mut o.back)?;
                f.color(4, &mut o.fore)?;
                f.coord(5, &mut o.bk.left)?;
                f.coord(6, &mut o.bk.top)?;
                f.coord(7, &mut o.bk.right)?;
                f.coord(8, &mut o.bk.bottom)?;
                f.coord(9, &mut o.op.left)?;
                f.coord(10, &mut o.op.top)?;
                f.coord(11, &mut o.op.right)?;
                f.coord(12, &mut o.op.bottom)?;
                f.coord(13, &mut o.x)?;
                f.coord(14, &mut o.y)?;
                f.var1(15, &mut o.data)
            }
            _ => unreachable!("field_count checked the type"),
        }
    }
}
