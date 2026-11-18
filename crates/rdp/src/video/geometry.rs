//! Geometry tracking (MS-RDPEGT): where a redirected video sits on the
//! desktop and which parts of it are visible.
//!
//! The server sends one message, MAPPED_GEOMETRY_PACKET (2.2.1.1), on the
//! `Microsoft::Windows::RDS::Geometry::v08.01` channel: an update creates or
//! replaces the geometry of a mapping id, a clear deletes it (3.1.3). The
//! tracked rectangle is relative to its top-level window, whose rectangle
//! is in desktop coordinates; the visible region (an RGNDATA) is relative
//! to the tracked rectangle. Like the other MS-RDPEVOR and MS-RDPEGT
//! messages, Windows appends one reserved byte after `cbGeometryData`
//! (example 4.1), which is ignored.

use crate::cursor::Reader;
use crate::error::{Result, proto};

/// Dynamic virtual channel name (MS-RDPEGT 2.1).
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Geometry::v08.01";

/// UpdateType GEOMETRY_UPDATE (2.2.1.1).
pub const UPDATE: u32 = 0x01;
/// UpdateType GEOMETRY_CLEAR (2.2.1.1).
pub const CLEAR: u32 = 0x02;
/// GeometryType GEOMETRY_TYPE_REGION, the only one in RDP 8 (2.2.1.1).
pub const GEOMETRY_TYPE_REGION: u32 = 0x02;
/// RGNDATAHEADER iType RDH_RECTANGLES (Windows GDI).
pub const RDH_RECTANGLES: u32 = 1;
/// RGNDATAHEADER dwSize.
pub const RGNDATAHEADER_SIZE: u32 = 32;

/// Rectangles accepted in one region; more is treated as malformed.
pub const MAX_RECTS: usize = 4096;
/// Largest tracked or top-level rectangle side accepted, in pixels.
pub const MAX_SIDE: i64 = 32768;

/// A rectangle with exclusive right and bottom edges (a Windows RECT).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect32 {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect32 {
    pub const fn new(left: i32, top: i32, right: i32, bottom: i32) -> Rect32 {
        Rect32 {
            left,
            top,
            right,
            bottom,
        }
    }

    pub fn width(&self) -> i64 {
        (i64::from(self.right) - i64::from(self.left)).max(0)
    }

    pub fn height(&self) -> i64 {
        (i64::from(self.bottom) - i64::from(self.top)).max(0)
    }

    pub fn is_empty(&self) -> bool {
        self.width() == 0 || self.height() == 0
    }

    /// The overlap of two rectangles (empty when they do not meet).
    pub fn intersect(&self, o: &Rect32) -> Rect32 {
        Rect32 {
            left: self.left.max(o.left),
            top: self.top.max(o.top),
            right: self.right.min(o.right),
            bottom: self.bottom.min(o.bottom),
        }
    }

    /// Moved by (dx, dy), saturating at the i32 range.
    pub fn offset(&self, dx: i32, dy: i32) -> Rect32 {
        Rect32 {
            left: self.left.saturating_add(dx),
            top: self.top.saturating_add(dy),
            right: self.right.saturating_add(dx),
            bottom: self.bottom.saturating_add(dy),
        }
    }

    fn read(r: &mut Reader) -> Result<Rect32> {
        Ok(Rect32 {
            left: r.u32()? as i32,
            top: r.u32()? as i32,
            right: r.u32()? as i32,
            bottom: r.u32()? as i32,
        })
    }
}

/// A desktop area in framebuffer pixels: x, y, width, height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl Area {
    /// `r` clipped to a `width` x `height` desktop; `None` when nothing is
    /// left.
    pub fn clipped(r: &Rect32, width: usize, height: usize) -> Option<Area> {
        let c = r.intersect(&Rect32::new(
            0,
            0,
            width.min(i32::MAX as usize) as i32,
            height.min(i32::MAX as usize) as i32,
        ));
        if c.is_empty() {
            return None;
        }
        Some(Area {
            x: c.left as usize,
            y: c.top as usize,
            w: c.width() as usize,
            h: c.height() as usize,
        })
    }

    /// The overlap with another area, if any.
    pub fn intersect(&self, o: &Area) -> Option<Area> {
        let x = self.x.max(o.x);
        let y = self.y.max(o.y);
        let r = (self.x + self.w).min(o.x + o.w);
        let b = (self.y + self.h).min(o.y + o.h);
        (r > x && b > y).then_some(Area {
            x,
            y,
            w: r - x,
            h: b - y,
        })
    }
}

/// The geometry of one mapping (GEOMETRY_UPDATE, 2.2.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedGeometry {
    pub mapping_id: u64,
    /// The top-level window in window tracking mode (3.1.1), else 0.
    pub top_level_id: u64,
    /// The tracked rectangle, relative to the top-level rectangle.
    pub tracked: Rect32,
    /// The top-level rectangle in desktop coordinates.
    pub top_level: Rect32,
    /// The RGNDATA rcBound (ignored outside window tracking mode).
    pub bound: Rect32,
    /// The visible parts, relative to the tracked rectangle. Empty when the
    /// region is to be ignored (no rectangles, none meeting rcBound, or a
    /// geometry type other than a region): then nothing is shown.
    pub rects: Vec<Rect32>,
}

impl MappedGeometry {
    /// The tracked rectangle in desktop coordinates: where the video's
    /// picture goes, scaled to this size.
    pub fn placement(&self) -> Rect32 {
        self.tracked.offset(self.top_level.left, self.top_level.top)
    }

    /// The visible parts in desktop coordinates, each inside the placement
    /// and inside a `width` x `height` desktop. Empty areas are left out;
    /// the server sends non-overlapping regions (1.5).
    pub fn visible(&self, width: usize, height: usize) -> Vec<Area> {
        let place = self.placement();
        self.rects
            .iter()
            .map(|r| r.offset(place.left, place.top).intersect(&place))
            .filter_map(|r| Area::clipped(&r, width, height))
            .collect()
    }
}

/// A MAPPED_GEOMETRY_PACKET (2.2.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeometryPacket {
    Update(MappedGeometry),
    /// GEOMETRY_CLEAR: delete the mapping's geometry (3.1.3).
    Clear {
        mapping_id: u64,
    },
    /// An UpdateType this client does not know; ignored.
    Other {
        mapping_id: u64,
        update_type: u32,
    },
}

fn u64le(r: &mut Reader) -> Result<u64> {
    Ok(u64::from_le_bytes(r.array()?))
}

/// Parses a MAPPED_GEOMETRY_PACKET. Lengths that do not add up are
/// malformed (3.1.8.1); bytes after `cbGeometryData` are ignored.
pub fn parse(msg: &[u8]) -> Result<GeometryPacket> {
    let mut r = Reader::new(msg);
    let size = r.u32()? as usize;
    if !(20..=msg.len()).contains(&size) {
        return proto(format!(
            "geometry: cbGeometryData {size} for a message of {} bytes",
            msg.len()
        ));
    }
    let mut r = Reader::new(&msg[..size]);
    r.skip(4)?;
    let _version = r.u32()?;
    let mapping_id = u64le(&mut r)?;
    let update_type = r.u32()?;
    match update_type {
        CLEAR => return Ok(GeometryPacket::Clear { mapping_id }),
        UPDATE => {}
        _ => {
            return Ok(GeometryPacket::Other {
                mapping_id,
                update_type,
            });
        }
    }
    let _flags = r.u32()?;
    let top_level_id = u64le(&mut r)?;
    let tracked = Rect32::read(&mut r)?;
    let top_level = Rect32::read(&mut r)?;
    let geometry_type = r.u32()?;
    let cb = r.u32()? as usize;
    let buf = r.bytes(cb)?;
    for rect in [tracked, top_level] {
        if rect.width() > MAX_SIDE || rect.height() > MAX_SIDE {
            return proto(format!("geometry: rectangle {rect:?} too large"));
        }
    }
    let (bound, mut rects) = if geometry_type == GEOMETRY_TYPE_REGION {
        parse_rgndata(buf)?
    } else {
        crate::trace!("geometry: type {geometry_type} ignored");
        (Rect32::default(), Vec::new())
    };
    // The region is ignored when it has no rectangles, or, in window
    // tracking mode, when none meets rcBound (2.2.1.1).
    if top_level_id != 0 && !rects.iter().any(|r| !r.intersect(&bound).is_empty()) {
        rects.clear();
    }
    Ok(GeometryPacket::Update(MappedGeometry {
        mapping_id,
        top_level_id,
        tracked,
        top_level,
        bound,
        rects,
    }))
}

/// RGNDATA (Windows GDI): RGNDATAHEADER (dwSize, iType, nCount, nRgnSize,
/// rcBound) and nCount RECTs. Returns rcBound and the rectangles; a type
/// other than RDH_RECTANGLES yields none.
pub fn parse_rgndata(buf: &[u8]) -> Result<(Rect32, Vec<Rect32>)> {
    let mut r = Reader::new(buf);
    let size = r.u32()?;
    let kind = r.u32()?;
    let count = r.u32()? as usize;
    let _rgn_size = r.u32()?;
    let bound = Rect32::read(&mut r)?;
    if size != RGNDATAHEADER_SIZE {
        return proto(format!("geometry: RGNDATAHEADER dwSize {size}"));
    }
    if count > MAX_RECTS || r.remaining() < count * 16 {
        return proto(format!(
            "geometry: {count} rectangles in {} bytes",
            r.remaining()
        ));
    }
    if kind != RDH_RECTANGLES {
        crate::trace!("geometry: region type {kind} ignored");
        return Ok((bound, Vec::new()));
    }
    let rects = (0..count)
        .map(|_| Rect32::read(&mut r))
        .collect::<Result<Vec<_>>>()?;
    Ok((bound, rects))
}

/// Encodes a MAPPED_GEOMETRY_PACKET for an update (tests and tools).
pub fn encode_update(g: &MappedGeometry) -> Vec<u8> {
    use crate::cursor::Put;
    let rect = |out: &mut Vec<u8>, r: &Rect32| {
        for v in [r.left, r.top, r.right, r.bottom] {
            out.put_u32(v as u32);
        }
    };
    let mut out = Vec::new();
    out.put_u32(0);
    out.put_u32(1);
    out.put_bytes(&g.mapping_id.to_le_bytes());
    out.put_u32(UPDATE);
    out.put_u32(0);
    out.put_bytes(&g.top_level_id.to_le_bytes());
    rect(&mut out, &g.tracked);
    rect(&mut out, &g.top_level);
    out.put_u32(GEOMETRY_TYPE_REGION);
    out.put_u32(32 + 16 * g.rects.len() as u32);
    out.put_u32(RGNDATAHEADER_SIZE);
    out.put_u32(RDH_RECTANGLES);
    out.put_u32(g.rects.len() as u32);
    out.put_u32(0);
    rect(&mut out, &g.bound);
    for r in &g.rects {
        rect(&mut out, r);
    }
    let n = out.len() as u32;
    out[..4].copy_from_slice(&n.to_le_bytes());
    out
}

/// Encodes a GEOMETRY_CLEAR MAPPED_GEOMETRY_PACKET (tests and tools).
pub fn encode_clear(mapping_id: u64) -> Vec<u8> {
    use crate::cursor::Put;
    let mut out = Vec::new();
    out.put_u32(20);
    out.put_u32(1);
    out.put_bytes(&mapping_id.to_le_bytes());
    out.put_u32(CLEAR);
    out
}
