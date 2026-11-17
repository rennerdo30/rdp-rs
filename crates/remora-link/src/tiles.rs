//! Lossless tiles for the helper's picture stream (RDP-67): small changed
//! regions (typing, menus, a cursor in text) travel as LZ4-compressed BGRA
//! instead of through the video encoder, which needs ~14 ms for a whole 4K
//! picture however little changed. Text stays exact.
//!
//! A tiles picture is [`crate::msg::Message::StreamData`] with
//! [`crate::msg::STREAM_TILES`]: its rectangles name the tiles, its data holds
//! one entry per rectangle, in order: `u32 length` (little-endian) and an LZ4
//! block of the rectangle's `w * h * 4` bytes (BGRA, rows top-down, no
//! padding).

use crate::error::{Error, Result};

/// Most pixels of all tiles of one picture; larger changes go through the
/// video encoder (and decoding is bounded by it).
pub const MAX_TILE_PIXELS: usize = 1 << 20;

/// Encodes the tiles' pixels (each `w * h * 4` BGRA bytes) for a tiles
/// picture.
pub fn encode(tiles: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in tiles {
        let c = lz4_flex::block::compress(t);
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
        out.extend_from_slice(&c);
    }
    out
}

/// Decodes a tiles picture: the pixels of each rectangle (x, y, w, h), in
/// order. Rejects data that does not match the rectangles.
pub fn decode(rects: &[[u16; 4]], data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let total: usize = rects.iter().map(|r| r[2] as usize * r[3] as usize).sum();
    if total > MAX_TILE_PIXELS {
        return Err(Error::Malformed(format!("{total} tile pixels")));
    }
    let mut at = 0usize;
    let mut out = Vec::with_capacity(rects.len());
    for r in rects {
        let want = r[2] as usize * r[3] as usize * 4;
        let len = data
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| Error::Malformed("tile data truncated".into()))?;
        at += 4;
        let block = data
            .get(at..at + len)
            .ok_or_else(|| Error::Malformed("tile data truncated".into()))?;
        at += len;
        let px = lz4_flex::block::decompress(block, want)
            .map_err(|e| Error::Malformed(format!("tile: {e}")))?;
        if px.len() != want {
            return Err(Error::Malformed("tile size".into()));
        }
        out.push(px);
    }
    if at != data.len() {
        return Err(Error::Malformed("trailing tile data".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiles_round_trip_and_reject_bad_data() {
        let a: Vec<u8> = (0..2 * 3 * 4).map(|i| i as u8).collect();
        let b = vec![7u8; 4 * 4 * 4];
        let rects = [[0, 0, 2, 3], [10, 10, 4, 4]];
        let data = encode(&[&a, &b]);
        assert_eq!(decode(&rects, &data).unwrap(), vec![a.clone(), b.clone()]);
        // Other sizes, truncation, extra bytes, too many pixels.
        assert!(decode(&[[0, 0, 3, 3], [10, 10, 4, 4]], &data).is_err());
        assert!(decode(&rects, &data[..data.len() - 1]).is_err());
        let mut more = data.clone();
        more.push(0);
        assert!(decode(&rects, &more).is_err());
        assert!(decode(&[[0, 0, 2048, 1024]], &data).is_err());
    }
}
