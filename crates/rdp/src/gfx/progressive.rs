//! RemoteFX Progressive codec, client side (MS-RDPEGFX 2.2.4.2, 3.3.8.2),
//! carried by RDPGFX_WIRE_TO_SURFACE_PDU_2 (2.2.2.2).
//!
//! State (3.3.1.1 - 3.3.1.3): every surface keeps the DWT coefficients of
//! the tiles it received ("current frame", DecDwtQ), which sub-band diffing
//! and upgrades add to. A tile sent progressively also keeps its sign
//! state and bit positions; that state belongs to the codec context of its
//! first pass and is freed by RDPGFX_DELETE_ENCODING_CONTEXT_PDU (2.2.2.3).
//! Deleting the surface frees everything.
//!
//! Decoding is bounds-checked; a corrupt block fails its PDU with
//! [`Error::Protocol`](crate::error::Error::Protocol). Tiles already
//! painted by earlier regions of that PDU stay.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use super::rfx::{self, Bits, COEFFS, Layout, Quant, Reconstructor, TILE, sat16};
use super::surface::{Area, Surface};
use crate::cursor::Reader;
use crate::error::{Result, proto};

/// RFX_PROGRESSIVE_DATABLOCK.blockType values (2.2.4.2.1).
pub const WBT_SYNC: u16 = 0xCCC0;
pub const WBT_FRAME_BEGIN: u16 = 0xCCC1;
pub const WBT_FRAME_END: u16 = 0xCCC2;
pub const WBT_CONTEXT: u16 = 0xCCC3;
pub const WBT_REGION: u16 = 0xCCC4;
pub const WBT_TILE_SIMPLE: u16 = 0xCCC5;
pub const WBT_TILE_FIRST: u16 = 0xCCC6;
pub const WBT_TILE_UPGRADE: u16 = 0xCCC7;

/// RFX_PROGRESSIVE_REGION.flags: Reduce-Extrapolate DWT (2.2.4.2.1.5).
pub const RFX_DWT_REDUCE_EXTRAPOLATE: u8 = 0x01;
/// Tile flags: the tile is a difference tile (2.2.4.2.1.5.3).
pub const RFX_TILE_DIFFERENCE: u8 = 0x01;
/// progressiveQuality: full quality, every bit position zero (2.2.4.2.1.5.4).
pub const FULL_QUALITY: u8 = 0xFF;

const BLOCK_HEADER: usize = 6;

/// BitPos per sub-band of the three components.
type BitPos = [[u8; 10]; 3];

/// Persistent progressive state of one tile (3.3.1.2).
struct ProgState {
    /// Codec context of the first pass.
    ctx: u32,
    /// Sign of what each non-LL3 coefficient received (3.3.8.2.1.1).
    sign: Box<[i8]>,
    /// Bit positions of the last pass.
    bitpos: BitPos,
}

/// A tile of a surface (3.3.1.3) and its progressive state.
struct Tile {
    /// DecDwtQ of Y, Cb and Cr, `COEFFS` each, in layout order.
    coeffs: Box<[i16]>,
    quant: [Quant; 3],
    layout: Layout,
    prog: Option<ProgState>,
}

impl Tile {
    fn new() -> Tile {
        Tile {
            coeffs: vec![0; 3 * COEFFS].into_boxed_slice(),
            quant: [Quant::default(); 3],
            layout: rfx::EXTRAPOLATE,
            prog: None,
        }
    }
}

/// The tables of one RFX_PROGRESSIVE_REGION.
struct Region {
    layout: Layout,
    quants: Vec<Quant>,
    prog: Vec<BitPos>,
}

impl Region {
    fn quant(&self, idx: [u8; 3]) -> Result<[Quant; 3]> {
        let mut q = [Quant::default(); 3];
        for (q, i) in q.iter_mut().zip(idx) {
            *q = *self.quants.get(i as usize).ok_or_else(|| {
                crate::error::Error::Protocol(format!("progressive: quant index {i}"))
            })?;
        }
        Ok(q)
    }

    fn bitpos(&self, quality: u8) -> Result<BitPos> {
        if quality == FULL_QUALITY {
            return Ok([[0; 10]; 3]);
        }
        match self.prog.get(quality as usize) {
            Some(b) => Ok(*b),
            None => proto(format!("progressive: quality index {quality}")),
        }
    }
}

/// The common head of the three tile blocks (2.2.4.2.1.5.3 - 5).
struct TileHead {
    quant: [u8; 3],
    x: u16,
    y: u16,
}

fn tile_head(r: &mut Reader) -> Result<TileHead> {
    Ok(TileHead {
        quant: r.array()?,
        x: r.u16()?,
        y: r.u16()?,
    })
}

/// Splits `r` into component fields of the given lengths.
fn fields<'a, const N: usize>(r: &mut Reader<'a>, lens: [u16; N]) -> Result<[&'a [u8]; N]> {
    let mut out = [&[][..]; N];
    for (o, n) in out.iter_mut().zip(lens) {
        *o = r.bytes(n as usize)?;
    }
    Ok(out)
}

/// First progressive pass of one component, or a whole tile with zero bit
/// positions (3.3.8.2.1.1). `bands` are in linearization order with LL3
/// last; `tmp` holds `coeffs.len()` values. A difference tile adds to
/// `coeffs`, an original tile replaces them. `sign` receives the sign of
/// each non-LL3 value.
pub(crate) fn first_pass(
    data: &[u8],
    bands: &[Range<usize>],
    bitpos: &[u8],
    diff: bool,
    coeffs: &mut [i16],
    sign: Option<&mut [i8]>,
    tmp: &mut [i16],
) {
    let tmp = &mut tmp[..coeffs.len()];
    rfx::rlgr_decode(false, data, tmp);
    let ll = bands.len() - 1;
    // LL3 arrives as deltas (3.1.8.1.2).
    let mut acc = 0i64;
    for v in &mut tmp[bands[ll].clone()] {
        acc += *v as i64;
        *v = sat16(acc);
    }
    for (b, r) in bands.iter().enumerate() {
        let s = bitpos[b].min(15);
        for (c, &q) in coeffs[r.clone()].iter_mut().zip(&tmp[r.clone()]) {
            let base = if diff { *c as i64 } else { 0 };
            *c = sat16(base + ((q as i64) << s));
        }
    }
    if let Some(sign) = sign {
        sign.fill(0);
        for r in &bands[..ll] {
            for (s, &q) in sign[r.clone()].iter_mut().zip(&tmp[r.clone()]) {
                *s = q.signum() as i8;
            }
        }
    }
}

/// Simplified run-length decoder (3.1.8.1.5): zero runs as in RLGR with
/// KP starting at 8, nonzero values unary coded with a magnitude bound.
struct Srl<'a> {
    bits: Bits<'a>,
    kp: u32,
    zeros: usize,
    pending: bool,
}

impl<'a> Srl<'a> {
    fn new(data: &'a [u8]) -> Srl<'a> {
        Srl {
            bits: Bits::new(data),
            kp: 8,
            zeros: 0,
            pending: false,
        }
    }

    /// The next element, whose magnitude has `nbits` bits (1..=15).
    fn next(&mut self, nbits: u8) -> i32 {
        if self.zeros > 0 {
            self.zeros -= 1;
            return 0;
        }
        if !self.pending {
            let nz = self.run();
            if nz > 0 {
                self.zeros = nz - 1;
                self.pending = true;
                return 0;
            }
        }
        self.pending = false;
        self.unary(nbits)
    }

    /// One zero run (3.1.8.1.5.1). Runs past a tile's size end early: the
    /// stream is exhausted or corrupt.
    fn run(&mut self) -> usize {
        let mut nz = 0usize;
        loop {
            let k = self.kp / 8;
            if self.bits.bit() == 0 {
                nz += 1 << k;
                self.kp = (self.kp + 4).min(80);
                if nz > COEFFS {
                    return nz;
                }
            } else {
                nz += self.bits.bits(k) as usize;
                self.kp = self.kp.saturating_sub(6);
                return nz;
            }
        }
    }

    /// A nonzero value (3.1.8.1.5.2): sign, then magnitude - 1 zeros ended
    /// by a one unless the magnitude is the largest `nbits` allow.
    fn unary(&mut self, nbits: u8) -> i32 {
        let negative = self.bits.bit() != 0;
        let max = (1i32 << nbits) - 1;
        let mut mag = 1;
        while mag < max && self.bits.bit() == 0 {
            mag += 1;
        }
        if negative { -mag } else { mag }
    }
}

/// An upgrade pass of one component (3.3.8.2.1.2): for each band with
/// prev - cur bits to send, LL3 values and values whose sign is known come
/// from the raw stream, the others from the SRL stream.
pub(crate) fn upgrade(
    srl: &[u8],
    raw: &[u8],
    bands: &[Range<usize>],
    prev: &[u8],
    cur: &[u8],
    coeffs: &mut [i16],
    sign: &mut [i8],
) -> Result<()> {
    let mut srl = Srl::new(srl);
    let mut raw = Bits::new(raw);
    let ll = bands.len() - 1;
    for (b, r) in bands.iter().enumerate() {
        let (p, s) = (prev[b].min(15), cur[b].min(15));
        if s > p {
            return proto(format!("progressive: band {b} bit position {p} -> {s}"));
        }
        let nbits = p - s;
        if nbits == 0 {
            continue;
        }
        let coeffs = &mut coeffs[r.clone()];
        if b == ll {
            for c in coeffs {
                let v = raw.bits(nbits as u32) as i64;
                *c = sat16(*c as i64 + (v << s));
            }
            continue;
        }
        for (c, sg) in coeffs.iter_mut().zip(&mut sign[r.clone()]) {
            let v = match *sg {
                0 => {
                    let v = srl.next(nbits);
                    *sg = v.signum() as i8;
                    v as i64
                }
                1 => raw.bits(nbits as u32) as i64,
                _ => -(raw.bits(nbits as u32) as i64),
            };
            *c = sat16(*c as i64 + (v << s));
        }
    }
    Ok(())
}

/// The RemoteFX Progressive decoder of one graphics channel.
pub struct Progressive {
    surfaces: HashMap<u16, HashMap<(u16, u16), Tile>>,
    /// Codec contexts (3.3.1.1), by surface and codecContextId.
    contexts: HashSet<(u16, u32)>,
    /// Between RFX_PROGRESSIVE_FRAME_BEGIN and _END.
    in_frame: bool,
    // Reusable buffers.
    recon: Reconstructor,
    tmp: Vec<i16>,
    planes: Vec<i32>,
    pixels: Vec<u32>,
    rects: Vec<Area>,
    candidates: Vec<(u16, u16)>,
}

impl Default for Progressive {
    fn default() -> Self {
        Self::new()
    }
}

impl Progressive {
    pub fn new() -> Progressive {
        Progressive {
            surfaces: HashMap::new(),
            contexts: HashSet::new(),
            in_frame: false,
            recon: Reconstructor::new(),
            tmp: vec![0; COEFFS],
            planes: vec![0; 3 * COEFFS],
            pixels: vec![0; COEFFS],
            rects: Vec::new(),
            candidates: Vec::new(),
        }
    }

    /// RDPGFX_DELETE_ENCODING_CONTEXT_PDU (3.3.5.3): the context goes, and
    /// with it the progressive state of the tiles it started.
    pub fn delete_context(&mut self, surface: u16, ctx: u32) {
        self.contexts.remove(&(surface, ctx));
        for t in self
            .surfaces
            .get_mut(&surface)
            .into_iter()
            .flat_map(|s| s.values_mut())
        {
            if t.prog.as_ref().is_some_and(|p| p.ctx == ctx) {
                t.prog = None;
            }
        }
    }

    /// The surface was deleted or replaced: all its state goes.
    pub fn delete_surface(&mut self, surface: u16) {
        self.surfaces.remove(&surface);
        self.contexts.retain(|&(s, _)| s != surface);
    }

    /// Number of contexts and tiles kept (for tests and traces).
    pub fn counts(&self) -> (usize, usize) {
        let tiles = self.surfaces.values().map(|s| s.len()).sum();
        (self.contexts.len(), tiles)
    }

    /// Decodes one RFX_PROGRESSIVE_BITMAP_STREAM (2.2.4.2) for `surface_id`
    /// and paints the regions into `surface`. The areas painted are
    /// appended to `painted`.
    pub fn decode(
        &mut self,
        surface_id: u16,
        ctx: u32,
        data: &[u8],
        surface: &mut Surface,
        painted: &mut Vec<Area>,
    ) -> Result<()> {
        self.contexts.insert((surface_id, ctx));
        let mut r = Reader::new(data);
        while r.remaining() > 0 {
            let kind = r.u16()?;
            let len = r.u32()? as usize;
            if len < BLOCK_HEADER {
                return proto(format!("progressive: block {kind:#x} of {len} bytes"));
            }
            let mut body = Reader::new(r.bytes(len - BLOCK_HEADER)?);
            match kind {
                WBT_FRAME_BEGIN => self.in_frame = true,
                WBT_FRAME_END => self.in_frame = false,
                WBT_CONTEXT => {
                    let _ctx_id = body.u8()?;
                    let tile_size = body.u16()?;
                    if tile_size as usize != TILE {
                        return proto(format!("progressive: tile size {tile_size}"));
                    }
                }
                // Regions outside a frame are ignored (2.2.4.2.1.5).
                WBT_REGION if self.in_frame => {
                    self.region(surface_id, ctx, &mut body, surface, painted)?
                }
                // SYNC carries nothing the decoder needs; unknown blocks
                // are skipped by their length.
                _ => {}
            }
        }
        Ok(())
    }

    /// RFX_PROGRESSIVE_REGION (2.2.4.2.1.5): decode the tiles, then paint
    /// every tile under the region's rectangles.
    fn region(
        &mut self,
        sid: u16,
        ctx: u32,
        r: &mut Reader,
        surface: &mut Surface,
        painted: &mut Vec<Area>,
    ) -> Result<()> {
        let tile_size = r.u8()?;
        let num_rects = r.u16()? as usize;
        let num_quant = r.u8()? as usize;
        let num_prog = r.u8()? as usize;
        let flags = r.u8()?;
        let _num_tiles = r.u16()?;
        let tile_data = r.u32()? as usize;
        if tile_size as usize != TILE || num_quant > 7 {
            return proto(format!(
                "progressive: region tile size {tile_size}, {num_quant} quant tables"
            ));
        }
        if r.remaining() < num_rects * 8 + num_quant * 5 + num_prog * 16 {
            return proto("progressive: region tables truncated");
        }
        self.rects.clear();
        for _ in 0..num_rects {
            let [x, y, w, h] = [r.u16()?, r.u16()?, r.u16()?, r.u16()?].map(|v| v as usize);
            if let Some(a) = Area::new(x, y, w, h).clip(surface.width, surface.height) {
                self.rects.push(a);
            }
        }
        let region = Region {
            layout: if flags & RFX_DWT_REDUCE_EXTRAPOLATE != 0 {
                rfx::EXTRAPOLATE
            } else {
                rfx::CLASSIC
            },
            quants: (0..num_quant)
                .map(|_| Ok(Quant::progressive(r.array()?)))
                .collect::<Result<_>>()?,
            prog: (0..num_prog)
                .map(|_| {
                    let _quality = r.u8()?;
                    let q = [r.array()?, r.array()?, r.array()?];
                    Ok(q.map(|b| Quant::progressive(b).0))
                })
                .collect::<Result<_>>()?,
        };
        let mut tiles = Reader::new(r.bytes(tile_data)?);
        let grid = (surface.width.div_ceil(TILE), surface.height.div_ceil(TILE));
        while tiles.remaining() > 0 {
            let kind = tiles.u16()?;
            let len = tiles.u32()? as usize;
            if len < BLOCK_HEADER {
                return proto(format!("progressive: tile block {kind:#x} of {len} bytes"));
            }
            let mut body = Reader::new(tiles.bytes(len - BLOCK_HEADER)?);
            self.tile(sid, ctx, kind, &mut body, &region, grid)?;
        }
        self.paint(sid, surface);
        painted.extend_from_slice(&self.rects);
        Ok(())
    }

    /// One tile block (2.2.4.2.1.5.3 - 5). Tiles outside the surface are
    /// read and dropped.
    fn tile(
        &mut self,
        sid: u16,
        ctx: u32,
        kind: u16,
        r: &mut Reader,
        region: &Region,
        grid: (usize, usize),
    ) -> Result<()> {
        let head = tile_head(r)?;
        let quant = region.quant(head.quant)?;
        let inside = (head.x as usize) < grid.0 && (head.y as usize) < grid.1;
        let tiles = self.surfaces.entry(sid).or_default();
        let bands = region.layout.ranges();
        match kind {
            WBT_TILE_SIMPLE | WBT_TILE_FIRST => {
                let flags = r.u8()?;
                let bitpos = if kind == WBT_TILE_FIRST {
                    Some(region.bitpos(r.u8()?)?)
                } else {
                    None
                };
                let lens = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
                let [y, cb, cr, _tail] = fields(r, lens)?;
                if !inside {
                    return Ok(());
                }
                let t = tiles.entry((head.x, head.y)).or_insert_with(Tile::new);
                t.quant = quant;
                t.layout = region.layout;
                let diff = flags & RFX_TILE_DIFFERENCE != 0;
                // A first pass or a whole tile clears the progressive state
                // (3.3.8.2.1).
                let mut prog = bitpos.map(|bitpos| {
                    let mut sign = t.prog.take().map(|p| p.sign).unwrap_or_default();
                    if sign.len() != 3 * COEFFS {
                        sign = vec![0; 3 * COEFFS].into_boxed_slice();
                    }
                    ProgState { ctx, sign, bitpos }
                });
                t.prog = None;
                let zero = [0u8; 10];
                for (c, data) in [y, cb, cr].into_iter().enumerate() {
                    let range = c * COEFFS..(c + 1) * COEFFS;
                    let (bp, sign) = match prog.as_mut() {
                        Some(p) => (&p.bitpos[c], Some(&mut p.sign[range.clone()])),
                        None => (&zero, None),
                    };
                    first_pass(
                        data,
                        &bands,
                        bp,
                        diff,
                        &mut t.coeffs[range],
                        sign,
                        &mut self.tmp,
                    );
                }
                t.prog = prog;
            }
            WBT_TILE_UPGRADE => {
                let quality = r.u8()?;
                let lens = [r.u16()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?];
                let [ys, yr, cbs, cbr, crs, crr] = fields(r, lens)?;
                let bitpos = region.bitpos(quality)?;
                if !inside {
                    return Ok(());
                }
                if !self.contexts.contains(&(sid, ctx)) {
                    return proto(format!("progressive: upgrade in unknown context {ctx}"));
                }
                let Some(t) = tiles.get_mut(&(head.x, head.y)) else {
                    return proto("progressive: upgrade of an unknown tile");
                };
                let Some(p) = t.prog.as_mut() else {
                    return proto("progressive: upgrade without a first pass");
                };
                t.quant = quant;
                for (c, (s, w)) in [(ys, yr), (cbs, cbr), (crs, crr)].into_iter().enumerate() {
                    let range = c * COEFFS..(c + 1) * COEFFS;
                    let coeffs = &mut t.coeffs[range.clone()];
                    let sign = &mut p.sign[range];
                    upgrade(s, w, &bands, &p.bitpos[c], &bitpos[c], coeffs, sign)?;
                    p.bitpos[c] = bitpos[c];
                }
            }
            _ => return proto(format!("progressive: block {kind:#x} among the tiles")),
        }
        Ok(())
    }

    /// Paints every known tile under the region's rectangles, each
    /// reconstructed once and clipped to the rectangles (MS-RDPRFX
    /// 3.1.8.2.6). Tiles from earlier regions of the frame count too
    /// (2.2.4.2.1.5).
    fn paint(&mut self, sid: u16, surface: &mut Surface) {
        let Some(tiles) = self.surfaces.get(&sid) else {
            return;
        };
        self.candidates.clear();
        for a in &self.rects {
            for ty in a.y / TILE..(a.y + a.h).div_ceil(TILE) {
                for tx in a.x / TILE..(a.x + a.w).div_ceil(TILE) {
                    let key = (tx as u16, ty as u16);
                    if tiles.contains_key(&key) {
                        self.candidates.push(key);
                    }
                }
            }
        }
        self.candidates.sort_unstable();
        self.candidates.dedup();
        for &(tx, ty) in &self.candidates {
            let t = &tiles[&(tx, ty)];
            let (y, rest) = self.planes.split_at_mut(COEFFS);
            let (cb, cr) = rest.split_at_mut(COEFFS);
            for (c, plane) in [y, cb, cr].into_iter().enumerate() {
                let coeffs = &t.coeffs[c * COEFFS..(c + 1) * COEFFS];
                self.recon.component(coeffs, &t.quant[c], &t.layout, plane);
            }
            let (y, rest) = self.planes.split_at(COEFFS);
            let (cb, cr) = rest.split_at(COEFFS);
            rfx::ycbcr_to_rgb(y, cb, cr, &mut self.pixels);
            let (x0, y0) = (tx as usize * TILE, ty as usize * TILE);
            for a in &self.rects {
                let (l, t) = (a.x.max(x0), a.y.max(y0));
                let (r, b) = ((a.x + a.w).min(x0 + TILE), (a.y + a.h).min(y0 + TILE));
                if r <= l || b <= t {
                    continue;
                }
                let src = &self.pixels[(t - y0) * TILE + (l - x0)..];
                surface.blit(Area::new(l, t, r - l, b - t), src, TILE);
            }
        }
    }
}
