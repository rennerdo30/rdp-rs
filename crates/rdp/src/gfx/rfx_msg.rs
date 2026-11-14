//! The RemoteFX encode message stream (MS-RDPRFX 2.2.2, 3.1.8.3), as the
//! bitmap data of Set/Stream Surface Bits commands (MS-RDPBCGR 2.2.9.2)
//! carries it outside the graphics pipeline.
//!
//! A stream starts with the header messages (TS_RFX_SYNC, then
//! TS_RFX_CODEC_VERSIONS, TS_RFX_CHANNELS and TS_RFX_CONTEXT in any order);
//! each frame is TS_RFX_FRAME_BEGIN, one TS_RFX_REGION, one TS_RFX_TILESET
//! and TS_RFX_FRAME_END. In video mode the headers come once per stream, so
//! the decoder keeps them across calls. Tiles are decoded with the codec
//! core in [`super::rfx`]: RLGR1/RLGR3, LL3 differences (3.1.8.2.2),
//! dequantization, inverse DWT and YCbCr to RGB.

use super::rfx::{CLASSIC, COEFFS, LL3, Quant, Reconstructor, TILE, rlgr_decode, ycbcr_to_rgb};
use crate::cursor::Reader;
use crate::error::{Result, proto};

pub const WBT_SYNC: u16 = 0xCCC0;
pub const WBT_CODEC_VERSIONS: u16 = 0xCCC1;
pub const WBT_CHANNELS: u16 = 0xCCC2;
pub const WBT_CONTEXT: u16 = 0xCCC3;
pub const WBT_FRAME_BEGIN: u16 = 0xCCC4;
pub const WBT_FRAME_END: u16 = 0xCCC5;
pub const WBT_REGION: u16 = 0xCCC6;
pub const WBT_EXTENSION: u16 = 0xCCC7;
pub const CBT_TILESET: u16 = 0xCAC2;
pub const CBT_TILE: u16 = 0xCAC3;
/// TS_RFX_SYNC.magic (2.2.2.2.1).
pub const WF_MAGIC: u32 = 0xCACC_ACCA;
pub const WF_VERSION_1_0: u16 = 0x0100;
/// TS_RFX_TILESET properties.et (2.2.2.3.4).
pub const CLW_ENTROPY_RLGR1: u16 = 0x01;
pub const CLW_ENTROPY_RLGR3: u16 = 0x04;

/// A TS_RFX_RECT (2.2.2.1.6), relative to the destination of the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RfxRect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// One decoded 64x64 tile: its top-left pixel and 0x00RRGGBB pixels.
pub struct RfxTile {
    pub x: usize,
    pub y: usize,
    pub pixels: Vec<u32>,
}

/// One decoded frame: the region (the tiles are clipped to its rectangles,
/// 3.1.8.2.6) and the tiles.
#[derive(Default)]
pub struct RfxFrame {
    pub rects: Vec<RfxRect>,
    pub tiles: Vec<RfxTile>,
}

/// RemoteFX decoder state for one connection.
pub struct RfxDecoder {
    /// Channel 0's frame size from TS_RFX_CHANNELS, for regions without
    /// rectangles (2.2.2.3.3).
    channel: (u16, u16),
    frame: Option<RfxFrame>,
    rec: Reconstructor,
    coeffs: Vec<i16>,
    planes: [Vec<i32>; 3],
}

impl Default for RfxDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RfxDecoder {
    pub fn new() -> RfxDecoder {
        RfxDecoder {
            channel: (0, 0),
            frame: None,
            rec: Reconstructor::new(),
            coeffs: vec![0; COEFFS],
            planes: std::array::from_fn(|_| vec![0; COEFFS]),
        }
    }

    /// Decodes a run of encode messages and returns the frames that ended
    /// in it. Header messages update the stream state; a frame may span
    /// calls.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<RfxFrame>> {
        let mut out = Vec::new();
        let mut r = Reader::new(data);
        while r.remaining() > 0 {
            let ty = r.u16()?;
            let len = r.u32()? as usize;
            if len < 6 {
                return proto(format!("rfx: block {ty:#06x} of {len} bytes"));
            }
            let body = r.bytes(len - 6)?;
            match ty {
                WBT_SYNC => {
                    let mut b = Reader::new(body);
                    let (magic, version) = (b.u32()?, b.u16()?);
                    if magic != WF_MAGIC || version != WF_VERSION_1_0 {
                        return proto(format!("rfx: sync {magic:#x} version {version:#x}"));
                    }
                }
                // The decoder SHOULD ignore the version (2.2.2.1.4).
                WBT_CODEC_VERSIONS => {}
                WBT_CHANNELS => self.channels(body)?,
                WBT_CONTEXT => {
                    // codecId, channelId, ctxId, then tileSize (2.2.2.2.4).
                    let mut b = Reader::new(body);
                    b.skip(3)?;
                    let tile = b.u16()?;
                    if tile as usize != TILE {
                        return proto(format!("rfx: tile size {tile}"));
                    }
                }
                WBT_FRAME_BEGIN => self.frame = Some(RfxFrame::default()),
                WBT_REGION => {
                    let rects = self.region(body)?;
                    self.frame.get_or_insert_with(Default::default).rects = rects;
                }
                WBT_EXTENSION => {
                    let tiles = self.tileset(body)?;
                    self.frame
                        .get_or_insert_with(Default::default)
                        .tiles
                        .extend(tiles);
                }
                WBT_FRAME_END => out.extend(self.frame.take()),
                // Unknown blocks are skipped by their length (3.1.8.3.1).
                _ => {}
            }
        }
        Ok(out)
    }

    /// TS_RFX_CHANNELS (2.2.2.2.3).
    fn channels(&mut self, body: &[u8]) -> Result<()> {
        let mut b = Reader::new(body);
        let n = b.u8()?;
        for _ in 0..n {
            let id = b.u8()?;
            let (w, h) = (b.u16()?, b.u16()?);
            if id == 0 {
                self.channel = (w, h);
            }
        }
        Ok(())
    }

    /// TS_RFX_REGION (2.2.2.3.3), after the codec and channel ids.
    fn region(&self, body: &[u8]) -> Result<Vec<RfxRect>> {
        let mut b = Reader::new(body);
        b.skip(2)?; // codecId, channelId
        b.u8()?; // regionFlags
        let n = b.u16()?;
        let mut rects = Vec::with_capacity(n as usize);
        for _ in 0..n {
            rects.push(RfxRect {
                x: b.u16()?,
                y: b.u16()?,
                w: b.u16()?,
                h: b.u16()?,
            });
        }
        if rects.is_empty() {
            // No rectangles: the whole channel frame.
            let (w, h) = self.channel;
            rects.push(RfxRect { x: 0, y: 0, w, h });
        }
        Ok(rects)
    }

    /// TS_RFX_TILESET (2.2.2.3.4) with its tiles (2.2.2.3.4.1).
    fn tileset(&mut self, body: &[u8]) -> Result<Vec<RfxTile>> {
        let mut b = Reader::new(body);
        b.skip(2)?; // codecId, channelId
        let subtype = b.u16()?;
        if subtype != CBT_TILESET {
            return proto(format!("rfx: extension subtype {subtype:#06x}"));
        }
        b.u16()?; // idx
        let props = b.u16()?;
        let rlgr3 = match (props >> 10) & 0xF {
            CLW_ENTROPY_RLGR1 => false,
            CLW_ENTROPY_RLGR3 => true,
            et => return proto(format!("rfx: entropy algorithm {et}")),
        };
        let num_quant = b.u8()? as usize;
        b.u8()?; // tileSize
        let num_tiles = b.u16()?;
        let size = b.u32()? as usize;
        let quants: Vec<Quant> = (0..num_quant)
            .map(|_| b.array::<5>().map(Quant::rfx))
            .collect::<Result<_>>()?;
        let mut t = Reader::new(b.bytes(size)?);
        let mut tiles = Vec::with_capacity(num_tiles as usize);
        for _ in 0..num_tiles {
            let ty = t.u16()?;
            let len = t.u32()? as usize;
            if ty != CBT_TILE || len < 19 {
                return proto(format!("rfx: tile block {ty:#06x} of {len} bytes"));
            }
            let mut tb = Reader::new(t.bytes(len - 6)?);
            let q = [tb.u8()?, tb.u8()?, tb.u8()?].map(|i| quants.get(i as usize).copied());
            let (x, y) = (tb.u16()? as usize, tb.u16()? as usize);
            let lens = [tb.u16()?, tb.u16()?, tb.u16()?];
            for (c, (len, quant)) in lens.into_iter().zip(q).enumerate() {
                let Some(quant) = quant else {
                    return proto("rfx: tile quantizer index out of range");
                };
                self.component(rlgr3, tb.bytes(len as usize)?, &quant, c);
            }
            let mut pixels = vec![0u32; COEFFS];
            let [py, pcb, pcr] = &self.planes;
            ycbcr_to_rgb(py, pcb, pcr, &mut pixels);
            tiles.push(RfxTile {
                x: x * TILE,
                y: y * TILE,
                pixels,
            });
        }
        Ok(tiles)
    }

    /// One tile component into plane `c`: entropy decoding, LL3
    /// differences (3.1.8.2.2), then dequantization and inverse DWT.
    fn component(&mut self, rlgr3: bool, data: &[u8], quant: &Quant, c: usize) {
        rlgr_decode(rlgr3, data, &mut self.coeffs);
        let mut acc = 0i16;
        for v in &mut self.coeffs[CLASSIC.ranges()[LL3].clone()] {
            acc = acc.wrapping_add(*v);
            *v = acc;
        }
        self.rec
            .component(&self.coeffs, quant, &CLASSIC, &mut self.planes[c]);
    }
}
