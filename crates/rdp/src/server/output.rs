//! Server output: fast-path updates (MS-RDPBCGR 2.2.9.1.2) with the
//! fragmentation rules of 2.2.9.1.2.1, uncompressed 32 bpp bitmap updates
//! (TS_FP_UPDATE_BITMAP, 2.2.9.1.2.1.2) and the system pointer.

use crate::cursor::Put;
use crate::fastpath::UPDATETYPE_BITMAP;

/// FASTPATH_UPDATETYPE_PTR_DEFAULT (2.2.9.1.2.1): the system default pointer.
pub const UPDATETYPE_PTR_DEFAULT: u8 = 0x6;

const FRAGMENT_SINGLE: u8 = 0;
const FRAGMENT_LAST: u8 = 1;
const FRAGMENT_FIRST: u8 = 2;
const FRAGMENT_NEXT: u8 = 3;

/// The largest fast-path PDU: its length field has 15 bits (2.2.9.1.2).
pub const MAX_FASTPATH_PDU: usize = 0x7FFF;
/// The update data in one fast-path PDU: the PDU less its header (1),
/// length (2), update header (1) and size (2).
pub const MAX_FRAGMENT: usize = MAX_FASTPATH_PDU - 6;

/// One fast-path output PDU (2.2.9.1.2) carrying one update or fragment,
/// uncompressed: fpOutputHeader (action FASTPATH_OUTPUT_ACTION_FASTPATH,
/// no encryption), length, updateHeader, size, data.
fn fastpath_pdu(code: u8, fragmentation: u8, data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() <= MAX_FRAGMENT);
    let total = 1 + 2 + 1 + 2 + data.len();
    let mut out = Vec::with_capacity(total);
    out.put_u8(0x00);
    out.put_u16_be(0x8000 | total as u16);
    out.put_u8((code & 0x0F) | (fragmentation << 4));
    out.put_u16(data.len() as u16);
    out.put_bytes(data);
    out
}

/// Fast-path output PDUs for one update: a single PDU, or FIRST, NEXT...
/// and LAST fragments of at most `max_fragment` bytes each (2.2.9.1.2.1).
/// The caller keeps `data` within the client's MaxRequestSize (2.2.7.2.6).
pub fn fastpath_update(code: u8, data: &[u8], max_fragment: usize) -> Vec<Vec<u8>> {
    let max = max_fragment.clamp(1, MAX_FRAGMENT);
    if data.len() <= max {
        return vec![fastpath_pdu(code, FRAGMENT_SINGLE, data)];
    }
    let chunks: Vec<&[u8]> = data.chunks(max).collect();
    let last = chunks.len() - 1;
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let frag = match i {
                0 => FRAGMENT_FIRST,
                i if i == last => FRAGMENT_LAST,
                _ => FRAGMENT_NEXT,
            };
            fastpath_pdu(code, frag, c)
        })
        .collect()
}

/// The fast-path update that shows the system default pointer
/// (TS_FP_SYSTEMPOINTERDEFAULTATTRIBUTE, 2.2.9.1.2.1.6); it has no data.
pub fn pointer_default() -> Vec<u8> {
    fastpath_pdu(UPDATETYPE_PTR_DEFAULT, FRAGMENT_SINGLE, &[])
}

/// A rectangle of a 32 bpp source image to send.
#[derive(Debug, Clone, Copy)]
pub struct Tile<'a> {
    /// The whole source image: BGRA (B, G, R, unused), rows top-down.
    pub pixels: &'a [u8],
    /// Bytes per source row.
    pub stride: usize,
    /// Source image size; the tile is clipped to it.
    pub image_width: u16,
    pub image_height: u16,
    /// The tile, in desktop pixels (the source maps 1:1 onto the desktop).
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// The encoded size of one tile's TS_BITMAP_DATA.
pub fn bitmap_data_len(w: u16, h: u16) -> usize {
    18 + usize::from(w.next_multiple_of(4)) * usize::from(h) * 4
}

/// Appends one uncompressed 32 bpp TS_BITMAP_DATA (2.2.9.1.1.3.1.2.2): the
/// destination rectangle (inclusive), then the bitmap with its rows
/// bottom-up. The bitmap width is rounded up to a multiple of four, as
/// common servers do; the extra columns are black and fall outside the
/// destination rectangle, which clips them.
pub fn put_bitmap_data(out: &mut Vec<u8>, t: &Tile) {
    let w = t.w.min(t.image_width.saturating_sub(t.x));
    let h = t.h.min(t.image_height.saturating_sub(t.y));
    if w == 0 || h == 0 {
        return;
    }
    let bw = w.next_multiple_of(4);
    out.put_u16(t.x); // destLeft
    out.put_u16(t.y); // destTop
    out.put_u16(t.x + w - 1); // destRight
    out.put_u16(t.y + h - 1); // destBottom
    out.put_u16(bw); // width
    out.put_u16(h); // height
    out.put_u16(32); // bitsPerPixel
    out.put_u16(0); // flags: uncompressed
    out.put_u16((usize::from(bw) * usize::from(h) * 4) as u16); // bitmapLength
    let row_bytes = usize::from(w) * 4;
    let pad = usize::from(bw - w) * 4;
    for row in (0..usize::from(h)).rev() {
        let start = (usize::from(t.y) + row) * t.stride + usize::from(t.x) * 4;
        out.put_bytes(&t.pixels[start..start + row_bytes]);
        out.put_zeros(pad);
    }
}

/// Groups tiles into bitmap updates (TS_UPDATE_BITMAP_DATA, 2.2.9.1.1.3.1.2)
/// of at most `max_update` bytes each and returns the fast-path PDUs for
/// them, fragmented. Tiles are sent as pieces of at most 64 x 64 (16 KiB at
/// 32 bpp), so one piece always fits `max_update` (at least 16 KiB + 22).
pub fn bitmap_updates(tiles: &[Tile], max_update: usize) -> Vec<Vec<u8>> {
    let mut pdus = Vec::new();
    let mut update = Vec::new();
    let mut count = 0u16;
    let flush = |update: &mut Vec<u8>, count: &mut u16, pdus: &mut Vec<Vec<u8>>| {
        if *count == 0 {
            return;
        }
        update[2..4].copy_from_slice(&count.to_le_bytes());
        pdus.extend(fastpath_update(UPDATETYPE_BITMAP, update, MAX_FRAGMENT));
        update.clear();
        *count = 0;
    };
    // bitmapLength has 16 bits: larger tiles go out as 64 x 64 pieces.
    let pieces = tiles.iter().flat_map(|t| {
        let w = t.w.min(t.image_width.saturating_sub(t.x));
        let h = t.h.min(t.image_height.saturating_sub(t.y));
        (0..h).step_by(64).flat_map(move |dy| {
            (0..w).step_by(64).map(move |dx| Tile {
                x: t.x + dx,
                y: t.y + dy,
                w: (w - dx).min(64),
                h: (h - dy).min(64),
                ..*t
            })
        })
    });
    for t in pieces {
        let t = &t;
        let len = bitmap_data_len(t.w, t.h);
        if count > 0 && (update.len() + len > max_update || count == u16::MAX) {
            flush(&mut update, &mut count, &mut pdus);
        }
        if count == 0 {
            update.put_u16(1); // updateType: UPDATETYPE_BITMAP
            update.put_u16(0); // numberRectangles, set on flush
        }
        put_bitmap_data(&mut update, t);
        count += 1;
    }
    flush(&mut update, &mut count, &mut pdus);
    pdus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::Decompressor;
    use crate::fastpath::Reassembler;
    use crate::framebuffer::Framebuffer;

    /// A deterministic BGRA image.
    fn image(w: usize, h: usize) -> Vec<u8> {
        let mut px = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                px.extend([(x * 7) as u8, (y * 5) as u8, (x ^ y) as u8, 0xFF]);
            }
        }
        px
    }

    /// Feeds PDUs through the client's reassembler and bitmap decoder.
    fn draw(pdus: &[Vec<u8>], fb: &mut Framebuffer) -> usize {
        let mut ra = Reassembler::default();
        let mut bulk = Decompressor::default();
        let mut damage = Vec::new();
        let mut updates = 0;
        for p in pdus {
            for (code, data) in ra.feed(p, &mut bulk).unwrap() {
                assert_eq!(code, UPDATETYPE_BITMAP);
                crate::codec::draw_bitmap_update(&data, fb, &mut damage).unwrap();
                updates += 1;
            }
        }
        updates
    }

    #[test]
    fn tiles_reach_the_client_framebuffer_pixel_exact() {
        // 150 x 70: the right column of tiles is 22 wide (not a multiple of
        // four), the bottom row 6 high.
        let (w, h) = (150u16, 70u16);
        let px = image(w.into(), h.into());
        let mut tiles = Vec::new();
        for ty in (0..h).step_by(64) {
            for tx in (0..w).step_by(64) {
                tiles.push(Tile {
                    pixels: &px,
                    stride: usize::from(w) * 4,
                    image_width: w,
                    image_height: h,
                    x: tx,
                    y: ty,
                    w: 64,
                    h: 64,
                });
            }
        }
        // Updates of up to 40 KiB: several rectangles each, fragmented.
        let pdus = bitmap_updates(&tiles, 40 * 1024);
        assert!(pdus.iter().all(|p| p.len() <= MAX_FASTPATH_PDU));
        let mut fb = Framebuffer::new(w.into(), h.into());
        let updates = draw(&pdus, &mut fb);
        assert!(updates >= 2, "split into several updates");
        for y in 0..usize::from(h) {
            for x in 0..usize::from(w) {
                let i = (y * usize::from(w) + x) * 4;
                let want =
                    u32::from(px[i]) | u32::from(px[i + 1]) << 8 | u32::from(px[i + 2]) << 16;
                assert_eq!(fb.pixels[y * usize::from(w) + x], want, "pixel {x},{y}");
            }
        }
    }

    #[test]
    fn a_large_tile_goes_out_in_pieces() {
        // One 150 x 70 tile: bitmapLength has 16 bits, so it is split into
        // 64 x 64 pieces (six rectangles in one update here).
        let (w, h) = (150u16, 70u16);
        let px = image(w.into(), h.into());
        let tile = Tile {
            pixels: &px,
            stride: usize::from(w) * 4,
            image_width: w,
            image_height: h,
            x: 0,
            y: 0,
            w,
            h,
        };
        let pdus = bitmap_updates(&[tile], 1 << 20);
        let mut fb = Framebuffer::new(w.into(), h.into());
        assert_eq!(draw(&pdus, &mut fb), 1);
        let i = (69 * usize::from(w) + 149) * 4;
        let want = u32::from(px[i]) | u32::from(px[i + 1]) << 8 | u32::from(px[i + 2]) << 16;
        assert_eq!(fb.pixels[69 * usize::from(w) + 149], want);
        let mut ra = Reassembler::default();
        let mut data = Vec::new();
        for p in &pdus {
            data.extend(ra.feed(p, &mut Decompressor::default()).unwrap());
        }
        assert_eq!(u16::from_le_bytes([data[0].1[2], data[0].1[3]]), 6);
    }

    #[test]
    fn large_updates_are_fragmented() {
        let data = vec![0xAB; MAX_FRAGMENT * 2 + 5];
        let pdus = fastpath_update(UPDATETYPE_BITMAP, &data, MAX_FRAGMENT);
        assert_eq!(pdus.len(), 3);
        // updateHeader: FIRST, NEXT, LAST.
        assert_eq!(
            pdus.iter().map(|p| p[3] >> 4).collect::<Vec<_>>(),
            [FRAGMENT_FIRST, FRAGMENT_NEXT, FRAGMENT_LAST]
        );
        let mut ra = Reassembler::default();
        let mut bulk = Decompressor::default();
        let mut got = Vec::new();
        for p in &pdus {
            assert_eq!(
                p.len(),
                usize::from(u16::from_be_bytes([p[1], p[2]]) & 0x7FFF)
            );
            got.extend(ra.feed(p, &mut bulk).unwrap());
        }
        assert_eq!(got, vec![(UPDATETYPE_BITMAP, data)]);
    }

    #[test]
    fn default_pointer_reaches_the_client() {
        let mut ra = Reassembler::default();
        let ups = ra
            .feed(&pointer_default(), &mut Decompressor::default())
            .unwrap();
        assert_eq!(ups, vec![(UPDATETYPE_PTR_DEFAULT, Vec::new())]);
        let mut cache = crate::pointer::PointerCache::default();
        assert_eq!(
            cache.fast_path(ups[0].0, &ups[0].1).unwrap(),
            Some(crate::PointerUpdate::Default)
        );
    }
}
