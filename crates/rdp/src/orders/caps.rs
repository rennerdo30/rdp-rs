//! The client capability sets that turn drawing orders on (MS-RDPBCGR
//! 2.2.7.1.3, 2.2.7.1.4.2, 2.2.7.1.7, 2.2.7.1.8, 2.2.7.1.9), applied to a
//! Confirm Active PDU built for bitmap updates only.

use crate::cursor::{Put, Reader};
use crate::error::Result;

pub const CAPSTYPE_ORDER: u16 = 3;
pub const CAPSTYPE_BITMAPCACHE: u16 = 4;
pub const CAPSTYPE_BRUSH: u16 = 15;
pub const CAPSTYPE_GLYPHCACHE: u16 = 16;
pub const CAPSTYPE_OFFSCREENCACHE: u16 = 17;
pub const CAPSTYPE_BITMAPCACHE_REV2: u16 = 19;

/// Revision 2 bitmap caches: (entries, persistent). Cache 2 holds the
/// 64 x 64 tiles and is the persistent one, as in MS-RDPEGDI 3.1.1.1.1.
pub const BITMAP_CACHES: [(usize, bool); 3] = [(600, false), (600, false), (2560, true)];
pub const GLYPH_CACHES: usize = 10;
pub const GLYPH_CACHE_ENTRIES: usize = 254;
pub const BRUSH_CACHE_ENTRIES: usize = 64;
pub const OFFSCREEN_CACHE_KB: u16 = 7680;
pub const OFFSCREEN_CACHE_ENTRIES: u16 = 500;

/// orderSupport negotiation indices (2.2.7.1.3) of the orders drawn here.
const ORDER_SUPPORT: [usize; 18] = [
    0x00, // DstBlt
    0x01, // PatBlt and OpaqueRect
    0x02, // ScrBlt
    0x03, // MemBlt
    0x04, // Mem3Blt
    0x08, // LineTo
    0x0F, // MultiDstBlt
    0x10, // MultiPatBlt
    0x11, // MultiScrBlt
    0x12, // MultiOpaqueRect
    0x13, // FastIndex
    0x14, // PolygonSC
    0x15, // PolygonCB
    0x16, // Polyline
    0x18, // FastGlyph
    0x19, // EllipseSC
    0x1A, // EllipseCB
    0x1B, // GlyphIndex
];

/// Order Capability Set body (2.2.7.1.3).
fn order_caps() -> Vec<u8> {
    const NEGOTIATEORDERSUPPORT: u16 = 0x0002;
    const ZEROBOUNDSDELTASSUPPORT: u16 = 0x0008;
    const COLORINDEXSUPPORT: u16 = 0x0020;
    const ORDERFLAGS_EXTRA_FLAGS: u16 = 0x0080;
    let mut b = Vec::new();
    b.put_zeros(16); // terminalDescriptor
    b.put_u32(0);
    b.put_u16(1); // desktopSaveXGranularity
    b.put_u16(20); // desktopSaveYGranularity
    b.put_u16(0);
    b.put_u16(1); // maximumOrderLevel
    b.put_u16(0); // numberFonts
    b.put_u16(
        NEGOTIATEORDERSUPPORT
            | ZEROBOUNDSDELTASSUPPORT
            | COLORINDEXSUPPORT
            | ORDERFLAGS_EXTRA_FLAGS,
    );
    let mut support = [0u8; 32];
    for i in ORDER_SUPPORT {
        support[i] = 1;
    }
    b.put_bytes(&support);
    b.put_u16(0); // textFlags
    // orderSupportExFlags: Cache Bitmap Rev. 3 is not advertised. Its
    // bitmaps may use the codecs of the Bitmap Codecs capability set, which
    // this cache does not decode; Rev. 2 carries the same persistent keys.
    b.put_u16(0);
    b.put_u32(0);
    b.put_u32(230_400); // desktopSaveSize
    b.put_u16(0);
    b.put_u16(0);
    b.put_u16(0); // textANSICodePage
    b.put_u16(0);
    b
}

/// Revision 2 Bitmap Cache Capability Set body (2.2.7.1.4.2).
fn bitmap_cache_rev2(persistent: bool) -> Vec<u8> {
    const PERSISTENT_KEYS_EXPECTED_FLAG: u16 = 0x0001;
    let mut b = Vec::new();
    b.put_u16(if persistent {
        PERSISTENT_KEYS_EXPECTED_FLAG
    } else {
        0
    });
    b.put_u8(0);
    b.put_u8(BITMAP_CACHES.len() as u8);
    for i in 0..5 {
        let cell = BITMAP_CACHES.get(i).map_or(0, |&(n, p)| {
            n as u32 | if p && persistent { 0x8000_0000 } else { 0 }
        });
        b.put_u32(cell);
    }
    b.put_zeros(12);
    b
}

/// Glyph Cache Capability Set body (2.2.7.1.8) with GLYPH_SUPPORT_ENCODE.
fn glyph_caps() -> Vec<u8> {
    const GLYPH_SUPPORT_ENCODE: u16 = 3;
    let mut b = Vec::new();
    // Cell sizes MUST be powers of two (2.2.7.1.8.1).
    for cell in [4u16, 4, 8, 8, 16, 32, 64, 128, 256, 2048] {
        b.put_u16(GLYPH_CACHE_ENTRIES as u16);
        b.put_u16(cell);
    }
    b.put_u16(256); // FragCache entries
    b.put_u16(256); // FragCache maximum cell size
    b.put_u16(GLYPH_SUPPORT_ENCODE);
    b.put_u16(0);
    b
}

/// The capability sets replacing the bitmap-only ones: (type, body).
pub fn client_caps(persistent: bool) -> Vec<(u16, Vec<u8>)> {
    const BRUSH_COLOR_FULL: u32 = 2;
    let mut offscreen = Vec::new();
    offscreen.put_u32(1);
    offscreen.put_u16(OFFSCREEN_CACHE_KB);
    offscreen.put_u16(OFFSCREEN_CACHE_ENTRIES);
    vec![
        (CAPSTYPE_ORDER, order_caps()),
        (CAPSTYPE_BITMAPCACHE_REV2, bitmap_cache_rev2(persistent)),
        (CAPSTYPE_BRUSH, BRUSH_COLOR_FULL.to_le_bytes().to_vec()),
        (CAPSTYPE_GLYPHCACHE, glyph_caps()),
        (CAPSTYPE_OFFSCREENCACHE, offscreen),
    ]
}

/// Rewrites a Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2, with its Share
/// Control Header) so its order and cache capability sets are `caps`: a set
/// of the same type is replaced, the Revision 1 Bitmap Cache set gives way
/// to Revision 2, and the rest is kept in order.
pub fn patch_confirm_active(pdu: &[u8], caps: &[(u16, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut r = Reader::new(pdu);
    r.u16()?; // totalLength
    let pdu_type = r.u16()?;
    let source = r.u16()?;
    let share_id = r.u32()?;
    let originator = r.u16()?;
    let src_len = r.u16()? as usize;
    r.u16()?; // lengthCombinedCapabilities
    let descriptor = r.bytes(src_len)?;
    let count = r.u16()?;
    r.u16()?;
    let mut sets: Vec<(u16, Vec<u8>)> = Vec::new();
    for _ in 0..count {
        let ty = r.u16()?;
        let len = r.u16()? as usize;
        let body = r.bytes(len.saturating_sub(4))?;
        sets.push((ty, body.to_vec()));
    }
    let mut out_sets: Vec<(u16, Vec<u8>)> = Vec::new();
    for (ty, body) in sets {
        let ty = if ty == CAPSTYPE_BITMAPCACHE {
            CAPSTYPE_BITMAPCACHE_REV2
        } else {
            ty
        };
        match caps.iter().find(|(t, _)| *t == ty) {
            Some(c) => out_sets.push(c.clone()),
            None => out_sets.push((ty, body)),
        }
    }
    for c in caps {
        if !out_sets.iter().any(|(t, _)| *t == c.0) {
            out_sets.push(c.clone());
        }
    }
    let mut combined = Vec::new();
    for (ty, body) in &out_sets {
        combined.put_u16(*ty);
        combined.put_u16((body.len() + 4) as u16);
        combined.put_bytes(body);
    }
    let mut b = Vec::new();
    b.put_u32(share_id);
    b.put_u16(originator);
    b.put_u16(src_len as u16);
    b.put_u16((combined.len() + 4) as u16);
    b.put_bytes(descriptor);
    b.put_u16(out_sets.len() as u16);
    b.put_u16(0);
    b.put_bytes(&combined);
    let mut out = Vec::with_capacity(b.len() + 6);
    out.put_u16((b.len() + 6) as u16);
    out.put_u16(pdu_type);
    out.put_u16(source);
    out.put_bytes(&b);
    Ok(out)
}
