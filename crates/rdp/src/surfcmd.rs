//! Surface commands (MS-RDPBCGR 2.2.9.2): Set Surface Bits, Stream Surface
//! Bits and Frame Marker in fast-path updates (2.2.9.1.2.1.10), with the
//! capability sets that enable them:
//!
//! - Surface Commands (2.2.7.2.9),
//! - Bitmap Codecs (2.2.7.2.10) with RemoteFX (MS-RDPRFX 2.2.1.1) and
//!   NSCodec (MS-RDPNSC 2.2.1),
//! - Frame Acknowledge (MS-RDPRFX 2.2.1.3); finished frames are
//!   acknowledged with TS_FRAME_ACKNOWLEDGE_PDU (MS-RDPRFX 2.2.3.1).
//!
//! The bitmap data is decoded by [`crate::gfx::rfx_msg`] (RemoteFX) and
//! [`crate::gfx::nsc`] (NSCodec) and drawn into the framebuffer like bitmap
//! updates.

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};
use crate::framebuffer::{Damage, Framebuffer};
use crate::gfx::rfx::TILE;
use crate::gfx::rfx_msg::{RfxDecoder, RfxFrame};

/// FASTPATH_UPDATETYPE_SURFCMDS (2.2.9.1.2.1).
pub const UPDATETYPE_SURFCMDS: u8 = 0x4;
pub const CAPSETTYPE_SURFACE_COMMANDS: u16 = 0x001C;
pub const CAPSETTYPE_BITMAP_CODECS: u16 = 0x001D;
pub const CAPSETTYPE_FRAME_ACKNOWLEDGE: u16 = 0x001E;
pub const SURFCMDS_SETSURFACEBITS: u32 = 0x02;
pub const SURFCMDS_FRAMEMARKER: u32 = 0x10;
pub const SURFCMDS_STREAMSURFACEBITS: u32 = 0x40;
pub const CMDTYPE_SET_SURFACE_BITS: u16 = 0x0001;
pub const CMDTYPE_FRAME_MARKER: u16 = 0x0004;
pub const CMDTYPE_STREAM_SURFACE_BITS: u16 = 0x0006;
pub const SURFACECMD_FRAMEACTION_BEGIN: u16 = 0x0000;
pub const SURFACECMD_FRAMEACTION_END: u16 = 0x0001;
/// TS_BITMAP_DATA_EX.flags (2.2.9.2.1.1).
const EX_COMPRESSED_BITMAP_HEADER_PRESENT: u8 = 0x01;
/// MS-RDPRFX 2.2.3.1.
pub const PDUTYPE2_FRAME_ACKNOWLEDGE: u8 = 0x38;

/// Bitmap codec ids the client assigns (2.2.7.2.10.1.1); NSCodec MUST be 1.
pub const CODEC_ID_NONE: u8 = 0;
pub const CODEC_ID_NSCODEC: u8 = 1;
pub const CODEC_ID_REMOTEFX: u8 = 3;

/// CODEC_GUID_NSCODEC {CA8D1BB9-000F-154F-589F-AE2D1A87E2D6}, wire order.
pub const CODEC_GUID_NSCODEC: [u8; 16] = guid(
    0xCA8D_1BB9,
    0x000F,
    0x154F,
    [0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xD6],
);
/// CODEC_GUID_REMOTEFX {76772F12-BD72-4463-AFB3-B73C9C6F7886}, wire order.
pub const CODEC_GUID_REMOTEFX: [u8; 16] = guid(
    0x7677_2F12,
    0xBD72,
    0x4463,
    [0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86],
);

/// A GUID as the TS_BITMAPCODEC encodes it (2.2.7.2.10.1.1.1): the first
/// three parts little-endian, then the eight bytes in order.
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// Frames the client may have in flight, as the Frame Acknowledge hint.
const MAX_UNACKNOWLEDGED_FRAMES: u32 = 2;

/// TS_RFX_CLNT_CAPS_CONTAINER (MS-RDPRFX 2.2.1.1): mixing with other codecs
/// allowed (CARDP_CAPS_CAPTURE_NON_CAC), one capset with two video-mode
/// icaps, RLGR1 and RLGR3 (the layout of the MS-RDPRFX 4.2.1 example).
pub fn rfx_client_caps_container() -> Vec<u8> {
    let mut icaps = Vec::new();
    for entropy in [1u8, 4] {
        icaps.put_u16(0x0100); // CLW_VERSION_1_0
        icaps.put_u16(TILE as u16); // CT_TILE_64x64
        icaps.put_u8(0); // flags: video mode allowed
        icaps.put_u8(1); // CLW_COL_CONV_ICT
        icaps.put_u8(1); // CLW_XFORM_DWT_53_A
        icaps.put_u8(entropy); // CLW_ENTROPY_RLGR1 / RLGR3
    }
    let mut capset = Vec::new();
    capset.put_u16(0xCBC1); // CBY_CAPSET
    capset.put_u32(13 + icaps.len() as u32);
    capset.put_u8(1); // codecId
    capset.put_u16(0xCFC0); // CLY_CAPSET
    capset.put_u16(2); // numIcaps
    capset.put_u16(8); // icapLen
    capset.put_bytes(&icaps);
    let mut caps = Vec::new();
    caps.put_u16(0xCBC0); // CBY_CAPS
    caps.put_u32(8);
    caps.put_u16(1); // numCapsets
    caps.put_bytes(&capset);
    let mut out = Vec::new();
    out.put_u32(12 + caps.len() as u32);
    out.put_u32(1); // CARDP_CAPS_CAPTURE_NON_CAC
    out.put_u32(caps.len() as u32);
    out.put_bytes(&caps);
    out
}

/// TS_NSCODEC_CAPABILITYSET (MS-RDPNSC 2.2.1): dynamic fidelity and chroma
/// subsampling allowed, colour loss level up to 3 (what the decoder takes:
/// 1 to 7).
pub fn nscodec_caps() -> [u8; 3] {
    [1, 1, 3]
}

/// The client's capability sets for surface commands, as (type, body) for
/// the Confirm Active PDU: Surface Commands, Bitmap Codecs and Frame
/// Acknowledge.
pub fn client_capability_sets() -> Vec<(u16, Vec<u8>)> {
    let mut surf = Vec::new();
    surf.put_u32(SURFCMDS_SETSURFACEBITS | SURFCMDS_FRAMEMARKER | SURFCMDS_STREAMSURFACEBITS);
    surf.put_u32(0);
    let mut codecs = Vec::new();
    codecs.put_u8(2);
    for (guid, id, props) in [
        (
            CODEC_GUID_NSCODEC,
            CODEC_ID_NSCODEC,
            nscodec_caps().to_vec(),
        ),
        (
            CODEC_GUID_REMOTEFX,
            CODEC_ID_REMOTEFX,
            rfx_client_caps_container(),
        ),
    ] {
        codecs.put_bytes(&guid);
        codecs.put_u8(id);
        codecs.put_u16(props.len() as u16);
        codecs.put_bytes(&props);
    }
    vec![
        (CAPSETTYPE_SURFACE_COMMANDS, surf),
        (CAPSETTYPE_BITMAP_CODECS, codecs),
        (
            CAPSETTYPE_FRAME_ACKNOWLEDGE,
            MAX_UNACKNOWLEDGED_FRAMES.to_le_bytes().to_vec(),
        ),
    ]
}

/// Appends capability sets to a Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2)
/// built by [`crate::pdu::confirm_active_with`]: the sets go at the end and
/// the share control length, lengthCombinedCapabilities and
/// numberCapabilities grow with them.
pub fn append_capability_sets(mut pdu: Vec<u8>, sets: &[(u16, Vec<u8>)]) -> Vec<u8> {
    // Share control header (6), shareId (4), originatorId (2).
    const SRC_LEN: usize = 12;
    const CAPS_LEN: usize = 14;
    let le16 = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let src_len = le16(&pdu, SRC_LEN) as usize;
    let count_at = 16 + src_len;
    let mut add = Vec::new();
    for (ty, body) in sets {
        add.put_u16(*ty);
        add.put_u16((body.len() + 4) as u16);
        add.put_bytes(body);
    }
    let total = le16(&pdu, 0) as usize + add.len();
    let caps = le16(&pdu, CAPS_LEN) as usize + add.len();
    let count = le16(&pdu, count_at) + sets.len() as u16;
    pdu[0..2].copy_from_slice(&(total as u16).to_le_bytes());
    pdu[CAPS_LEN..CAPS_LEN + 2].copy_from_slice(&(caps as u16).to_le_bytes());
    pdu[count_at..count_at + 2].copy_from_slice(&count.to_le_bytes());
    pdu.extend_from_slice(&add);
    pdu
}

/// The body of a TS_FRAME_ACKNOWLEDGE_PDU (MS-RDPRFX 2.2.3.1) after the
/// share data header.
pub fn frame_acknowledge(frame_id: u32) -> [u8; 4] {
    frame_id.to_le_bytes()
}

/// TS_BITMAP_DATA_EX (2.2.9.2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapDataEx<'a> {
    pub bpp: u8,
    pub codec_id: u8,
    pub width: u16,
    pub height: u16,
    pub data: &'a [u8],
}

/// One surface command (2.2.9.1.2.1.10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceCommand<'a> {
    /// Set or Stream Surface Bits (2.2.9.2.1, 2.2.9.2.2): the destination
    /// top-left corner and the bitmap.
    Bits {
        left: u16,
        top: u16,
        bitmap: BitmapDataEx<'a>,
    },
    /// Frame Marker (2.2.9.2.3).
    FrameMarker { action: u16, frame_id: u32 },
}

/// Parses the surfaceCommands of a TS_FP_SURFCMDS update.
pub fn parse(data: &[u8]) -> Result<Vec<SurfaceCommand<'_>>> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        match r.u16()? {
            CMDTYPE_SET_SURFACE_BITS | CMDTYPE_STREAM_SURFACE_BITS => {
                let (left, top) = (r.u16()?, r.u16()?);
                r.skip(4)?; // destRight, destBottom: the bitmap gives the size
                let bpp = r.u8()?;
                let flags = r.u8()?;
                r.u8()?; // reserved
                let codec_id = r.u8()?;
                let (width, height) = (r.u16()?, r.u16()?);
                let len = r.u32()? as usize;
                if flags & EX_COMPRESSED_BITMAP_HEADER_PRESENT != 0 {
                    r.skip(24)?; // TS_COMPRESSED_BITMAP_HEADER_EX
                }
                let bitmap = BitmapDataEx {
                    bpp,
                    codec_id,
                    width,
                    height,
                    data: r.bytes(len)?,
                };
                out.push(SurfaceCommand::Bits { left, top, bitmap });
            }
            CMDTYPE_FRAME_MARKER => out.push(SurfaceCommand::FrameMarker {
                action: r.u16()?,
                frame_id: r.u32()?,
            }),
            // The length of an unknown command is not known.
            t => return proto(format!("unknown surface command {t:#06x}")),
        }
    }
    Ok(out)
}

/// Surface command state of one connection: the RemoteFX stream and
/// whether the server takes frame acknowledgements.
#[derive(Default)]
pub struct SurfaceCommands {
    rfx: RfxDecoder,
    /// Both sides sent the Frame Acknowledge capability set.
    pub frame_ack: bool,
}

impl SurfaceCommands {
    /// Draws one TS_FP_SURFCMDS update into `fb`, adds the changed
    /// rectangles to `damage` and returns the frame ids to acknowledge.
    pub fn apply(
        &mut self,
        data: &[u8],
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Result<Vec<u32>> {
        let mut acks = Vec::new();
        for cmd in parse(data)? {
            match cmd {
                SurfaceCommand::Bits { left, top, bitmap } => {
                    self.bits(left as usize, top as usize, &bitmap, fb, damage)?
                }
                SurfaceCommand::FrameMarker { action, frame_id } => {
                    if action == SURFACECMD_FRAMEACTION_END && self.frame_ack {
                        acks.push(frame_id);
                    }
                }
            }
        }
        Ok(acks)
    }

    fn bits(
        &mut self,
        left: usize,
        top: usize,
        bm: &BitmapDataEx,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
    ) -> Result<()> {
        let (w, h) = (bm.width as usize, bm.height as usize);
        match bm.codec_id {
            CODEC_ID_REMOTEFX => {
                for frame in self.rfx.decode(bm.data)? {
                    draw_rfx(&frame, left, top, fb, damage);
                }
            }
            CODEC_ID_NSCODEC => {
                let px = crate::gfx::nsc::decode(bm.data, w, h)?;
                damage.extend(fb.blit(left, top, w, h, &px, w));
            }
            CODEC_ID_NONE => {
                // Not encoded: top-down rows of 32-bpp BGRX pixels.
                if bm.bpp != 32 || bm.data.len() < w * h * 4 {
                    return proto(format!(
                        "uncompressed surface bits: {} bpp, {} bytes for {w}x{h}",
                        bm.bpp,
                        bm.data.len()
                    ));
                }
                let px: Vec<u32> = bm.data[..w * h * 4]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|&[b, g, r, _]| u32::from_le_bytes([b, g, r, 0]))
                    .collect();
                damage.extend(fb.blit(left, top, w, h, &px, w));
            }
            id => return proto(format!("surface bits with unknown codec id {id}")),
        }
        Ok(())
    }
}

/// Draws a RemoteFX frame at (left, top): each tile clipped to each region
/// rectangle (MS-RDPRFX 3.1.8.2.6). The rectangles are the damage.
fn draw_rfx(
    frame: &RfxFrame,
    left: usize,
    top: usize,
    fb: &mut Framebuffer,
    damage: &mut Vec<Damage>,
) {
    for rect in &frame.rects {
        let (rx, ry) = (rect.x as usize, rect.y as usize);
        let (rx2, ry2) = (rx + rect.w as usize, ry + rect.h as usize);
        for tile in &frame.tiles {
            let x0 = rx.max(tile.x);
            let y0 = ry.max(tile.y);
            let x1 = rx2.min(tile.x + TILE);
            let y1 = ry2.min(tile.y + TILE);
            if x0 >= x1 || y0 >= y1 {
                continue;
            }
            let src = &tile.pixels[(y0 - tile.y) * TILE + (x0 - tile.x)..];
            fb.blit(left + x0, top + y0, x1 - x0, y1 - y0, src, TILE);
        }
        let (x, y) = (left + rx, top + ry);
        if x < fb.width && y < fb.height && rect.w > 0 && rect.h > 0 {
            damage.push(Damage {
                x,
                y,
                w: (rect.w as usize).min(fb.width - x),
                h: (rect.h as usize).min(fb.height - y),
            });
        }
    }
}

#[cfg(test)]
#[path = "surfcmd_tests.rs"]
mod tests;
