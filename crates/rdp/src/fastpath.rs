//! Fast-path output (MS-RDPBCGR 2.2.9.1.2) with update fragment reassembly.

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
    /// Parses one fast-path output PDU and returns its complete updates as (updateCode, data).
    pub fn feed(&mut self, frame: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
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
            if (h >> 6) & 0x2 != 0 {
                let flags = r.u8()?;
                if flags & 0x20 != 0 {
                    return Err(Error::Unsupported("bulk-compressed fast-path update".into()));
                }
            }
            let size = r.u16()? as usize;
            let data = r.bytes(size)?;
            match fragmentation {
                FRAGMENT_SINGLE => out.push((code, data.to_vec())),
                FRAGMENT_FIRST => {
                    self.buf = data.to_vec();
                    self.code = code;
                }
                FRAGMENT_NEXT => self.buf.extend_from_slice(data),
                FRAGMENT_LAST => {
                    self.buf.extend_from_slice(data);
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
        assert!(ra.feed(&first).unwrap().is_empty());
        let last = [0x00, 6, 0x11, 1, 0, 0xCC];
        let ups = ra.feed(&last).unwrap();
        assert_eq!(ups, vec![(UPDATETYPE_BITMAP, vec![0xAA, 0xBB, 0xCC])]);
    }
}
