//! Fast-path output (MS-RDPBCGR 2.2.9.1.2) with update fragment reassembly.

use crate::compress::Decompressor;
use crate::cursor::Reader;
use crate::error::{Error, Result};

pub const UPDATETYPE_ORDERS: u8 = 0x0;
pub const UPDATETYPE_BITMAP: u8 = 0x1;
pub const UPDATETYPE_PALETTE: u8 = 0x2;
pub const UPDATETYPE_SYNCHRONIZE: u8 = 0x3;

const FRAGMENT_SINGLE: u8 = 0;
const FRAGMENT_LAST: u8 = 1;
const FRAGMENT_FIRST: u8 = 2;
const FRAGMENT_NEXT: u8 = 3;

#[derive(Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    code: u8,
}

impl Reassembler {
    /// Parses one fast-path output PDU and returns its complete updates as
    /// (updateCode, data). Each update (or fragment) is bulk-decompressed by
    /// `bulk` when FASTPATH_OUTPUT_COMPRESSION_USED is set (2.2.9.1.2.1).
    pub fn feed(&mut self, frame: &[u8], bulk: &mut Decompressor) -> Result<Vec<(u8, Vec<u8>)>> {
        let mut r = Reader::new(frame);
        let header = r.u8()?;
        if (header >> 6) & 0x2 != 0 {
            return Err(Error::Unsupported("encrypted fast-path output".into()));
        }
        if r.u8()? & 0x80 != 0 {
            r.u8()?;
        }
        let mut out = Vec::new();
        while r.remaining() > 0 {
            let h = r.u8()?;
            let code = h & 0x0F;
            let fragmentation = (h >> 4) & 0x3;
            let compression = if (h >> 6) & 0x2 != 0 { r.u8()? } else { 0 };
            let size = r.u16()? as usize;
            let data = bulk.decompress(r.bytes(size)?, compression)?;
            match fragmentation {
                FRAGMENT_SINGLE => out.push((code, data.into_owned())),
                FRAGMENT_FIRST => {
                    self.buf = data.into_owned();
                    self.code = code;
                }
                FRAGMENT_NEXT => self.buf.extend_from_slice(&data),
                FRAGMENT_LAST => {
                    self.buf.extend_from_slice(&data);
                    out.push((self.code, std::mem::take(&mut self.buf)));
                }
                _ => unreachable!(),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_fragments() {
        let mut ra = Reassembler::default();
        // FIRST fragment of a bitmap update, then LAST.
        let first = [0x00, 7, 0x21, 2, 0, 0xAA, 0xBB];
        let mut bulk = Decompressor::default();
        assert!(ra.feed(&first, &mut bulk).unwrap().is_empty());
        let last = [0x00, 6, 0x11, 1, 0, 0xCC];
        let ups = ra.feed(&last, &mut bulk).unwrap();
        assert_eq!(ups, vec![(UPDATETYPE_BITMAP, vec![0xAA, 0xBB, 0xCC])]);
    }

    #[test]
    fn decompresses_compressed_updates() {
        use crate::compress::Compression;
        // Bitmap update with FASTPATH_OUTPUT_COMPRESSION_USED and
        // compressionFlags PACKET_COMPRESSED | 8K: MPPC "A", "B", <2,3>.
        let frame = [0x00, 10, 0x81, 0x20, 4, 0, 0x41, 0x42, 0xF0, 0x80];
        let mut ra = Reassembler::default();
        let mut bulk = Decompressor::new(Compression::Rdp4);
        let ups = ra.feed(&frame, &mut bulk).unwrap();
        assert_eq!(ups, vec![(UPDATETYPE_BITMAP, b"ABABA".to_vec())]);
        // Not advertised: refused instead of misread.
        assert!(ra.feed(&frame, &mut Decompressor::default()).is_err());
    }
}
