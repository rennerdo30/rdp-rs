//! Graphics pipeline messages (MS-RDPEGFX 2.2.1 - 2.2.3): parsing of the
//! server PDUs this client handles and encoding of the client PDUs.

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};

/// RDPGFX_HEADER.cmdId values (2.2.1.5).
pub const CMDID_WIRETOSURFACE_1: u16 = 0x0001;
pub const CMDID_WIRETOSURFACE_2: u16 = 0x0002;
pub const CMDID_DELETEENCODINGCONTEXT: u16 = 0x0003;
pub const CMDID_SOLIDFILL: u16 = 0x0004;
pub const CMDID_SURFACETOSURFACE: u16 = 0x0005;
pub const CMDID_SURFACETOCACHE: u16 = 0x0006;
pub const CMDID_CACHETOSURFACE: u16 = 0x0007;
pub const CMDID_EVICTCACHEENTRY: u16 = 0x0008;
pub const CMDID_CREATESURFACE: u16 = 0x0009;
pub const CMDID_DELETESURFACE: u16 = 0x000A;
pub const CMDID_STARTFRAME: u16 = 0x000B;
pub const CMDID_ENDFRAME: u16 = 0x000C;
pub const CMDID_FRAMEACKNOWLEDGE: u16 = 0x000D;
pub const CMDID_RESETGRAPHICS: u16 = 0x000E;
pub const CMDID_MAPSURFACETOOUTPUT: u16 = 0x000F;
pub const CMDID_CACHEIMPORTOFFER: u16 = 0x0010;
pub const CMDID_CACHEIMPORTREPLY: u16 = 0x0011;
pub const CMDID_CAPSADVERTISE: u16 = 0x0012;
pub const CMDID_CAPSCONFIRM: u16 = 0x0013;

/// RDPGFX_WIRE_TO_SURFACE_PDU_1.codecId values (2.2.2.1).
pub const CODECID_UNCOMPRESSED: u16 = 0x0000;
pub const CODECID_CAVIDEO: u16 = 0x0003;
/// RDPGFX_WIRE_TO_SURFACE_PDU_2.codecId: RemoteFX Progressive (2.2.2.2).
pub const CODECID_CAPROGRESSIVE: u16 = 0x0009;
pub const CODECID_CLEARCODEC: u16 = 0x0008;
pub const CODECID_PLANAR: u16 = 0x000A;
pub const CODECID_AVC420: u16 = 0x000B;
pub const CODECID_ALPHA: u16 = 0x000C;
pub const CODECID_AVC444: u16 = 0x000E;
pub const CODECID_AVC444V2: u16 = 0x000F;

/// RDPGFX_PIXELFORMAT (2.2.1.4).
pub const PIXEL_FORMAT_XRGB_8888: u8 = 0x20;
pub const PIXEL_FORMAT_ARGB_8888: u8 = 0x21;

/// RDPGFX_CAPSET.version values (2.2.1.6).
pub const CAPVERSION_8: u32 = 0x0008_0004;
pub const CAPVERSION_81: u32 = 0x0008_0105;
pub const CAPVERSION_10: u32 = 0x000A_0002;
pub const CAPVERSION_107: u32 = 0x000A_0701;

/// Capability flags (2.2.3.1 - 2.2.3.10).
pub const CAPS_FLAG_THINCLIENT: u32 = 0x0000_0001;
pub const CAPS_FLAG_SMALL_CACHE: u32 = 0x0000_0002;
pub const CAPS_FLAG_AVC420_ENABLED: u32 = 0x0000_0010;
pub const CAPS_FLAG_AVC_DISABLED: u32 = 0x0000_0020;
pub const CAPS_FLAG_SCALEDMAP_DISABLE: u32 = 0x0000_0080;

/// RDPGFX_FRAME_ACKNOWLEDGE_PDU.queueDepth: no information (2.2.2.13).
pub const QUEUE_DEPTH_UNAVAILABLE: u32 = 0;
/// RDPGFX_FRAME_ACKNOWLEDGE_PDU.queueDepth: acknowledgements suspended.
pub const SUSPEND_FRAME_ACKNOWLEDGEMENT: u32 = 0xFFFF_FFFF;

/// Largest Graphics Output Buffer dimension (2.2.2.14).
pub const MAX_OUTPUT_DIM: u32 = 32766;
const HEADER_LEN: usize = 8;

/// RDPGFX_RECT16 (2.2.1.2): right and bottom are exclusive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect16 {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Rect16 {
    pub fn width(&self) -> usize {
        self.right.saturating_sub(self.left) as usize
    }
    pub fn height(&self) -> usize {
        self.bottom.saturating_sub(self.top) as usize
    }
    fn read(r: &mut Reader) -> Result<Rect16> {
        let rect = Rect16 {
            left: r.u16()?,
            top: r.u16()?,
            right: r.u16()?,
            bottom: r.u16()?,
        };
        if rect.right < rect.left || rect.bottom < rect.top {
            return proto(format!("gfx: inverted rectangle {rect:?}"));
        }
        Ok(rect)
    }
}

/// RDPGFX_POINT16 (2.2.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point16 {
    pub x: u16,
    pub y: u16,
}

/// RDPGFX_CAPSET (2.2.1.6) with the 4-byte flags data every defined set has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapSet {
    pub version: u32,
    pub flags: u32,
}

/// A server PDU this client acts on; the rest are reported as `Other`.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerPdu<'a> {
    /// RDPGFX_WIRE_TO_SURFACE_PDU_1 (2.2.2.1).
    WireToSurface1 {
        surface_id: u16,
        codec_id: u16,
        pixel_format: u8,
        dest: Rect16,
        data: &'a [u8],
    },
    /// RDPGFX_WIRE_TO_SURFACE_PDU_2 (2.2.2.2).
    WireToSurface2 {
        surface_id: u16,
        codec_id: u16,
        context_id: u32,
        pixel_format: u8,
        data: &'a [u8],
    },
    /// RDPGFX_DELETE_ENCODING_CONTEXT_PDU (2.2.2.3).
    DeleteEncodingContext { surface_id: u16, context_id: u32 },
    /// RDPGFX_SOLIDFILL_PDU (2.2.2.4); `color` is 0x00RRGGBB.
    SolidFill {
        surface_id: u16,
        color: u32,
        rects: Vec<Rect16>,
    },
    /// RDPGFX_SURFACE_TO_SURFACE_PDU (2.2.2.5).
    SurfaceToSurface {
        src: u16,
        dst: u16,
        rect: Rect16,
        points: Vec<Point16>,
    },
    /// RDPGFX_SURFACE_TO_CACHE_PDU (2.2.2.6).
    SurfaceToCache {
        surface_id: u16,
        cache_key: u64,
        cache_slot: u16,
        rect: Rect16,
    },
    /// RDPGFX_CACHE_TO_SURFACE_PDU (2.2.2.7).
    CacheToSurface {
        cache_slot: u16,
        surface_id: u16,
        points: Vec<Point16>,
    },
    /// RDPGFX_EVICT_CACHE_ENTRY_PDU (2.2.2.8).
    EvictCacheEntry { cache_slot: u16 },
    /// RDPGFX_CREATE_SURFACE_PDU (2.2.2.9).
    CreateSurface {
        surface_id: u16,
        width: u16,
        height: u16,
        pixel_format: u8,
    },
    /// RDPGFX_DELETE_SURFACE_PDU (2.2.2.10).
    DeleteSurface { surface_id: u16 },
    /// RDPGFX_START_FRAME_PDU (2.2.2.11).
    StartFrame { timestamp: u32, frame_id: u32 },
    /// RDPGFX_END_FRAME_PDU (2.2.2.12).
    EndFrame { frame_id: u32 },
    /// RDPGFX_RESET_GRAPHICS_PDU (2.2.2.14); the monitor layout is not kept.
    ResetGraphics {
        width: u32,
        height: u32,
        monitor_count: u32,
    },
    /// RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU (2.2.2.15).
    MapSurfaceToOutput { surface_id: u16, x: u32, y: u32 },
    /// RDPGFX_CACHE_IMPORT_REPLY_PDU (2.2.2.17).
    CacheImportReply { slots: Vec<u16> },
    /// RDPGFX_CAPS_CONFIRM_PDU (2.2.2.19).
    CapsConfirm(CapSet),
    /// Any other command, by cmdId.
    Other(u16),
}

fn points(r: &mut Reader) -> Result<Vec<Point16>> {
    let n = r.u16()? as usize;
    if r.remaining() < n * 4 {
        return proto("gfx: point array truncated");
    }
    (0..n)
        .map(|_| {
            Ok(Point16 {
                x: r.u16()?,
                y: r.u16()?,
            })
        })
        .collect()
}

/// RDPGFX_CAPSET (2.2.1.6); capsData shorter than 4 bytes reads as flags 0.
fn capset(r: &mut Reader) -> Result<CapSet> {
    let version = r.u32()?;
    let len = r.u32()? as usize;
    let data = r.bytes(len)?;
    let flags = crate::cursor::le32(data, 0).unwrap_or(0);
    Ok(CapSet { version, flags })
}

/// Parses one decompressed graphics message into its PDUs (2.1: one
/// RDP_SEGMENTED_DATA yields one or more PDUs). Each PDU comes with the
/// offset just past it.
pub fn parse_pdus(buf: &[u8]) -> Result<Vec<(ServerPdu<'_>, usize)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let mut h = Reader::new(&buf[at..]);
        let cmd = h.u16()?;
        let _flags = h.u16()?;
        let len = h.u32()? as usize;
        if len < HEADER_LEN || len > buf.len() - at {
            return proto(format!("gfx: pduLength {len} for command {cmd:#x}"));
        }
        let body = &buf[at + HEADER_LEN..at + len];
        at += len;
        // One PDU that cannot be read is skipped by its length: the rest of
        // the message (an EndFrame and its acknowledgement) still counts.
        match parse_body(cmd, body) {
            Ok(pdu) => out.push((pdu, at)),
            Err(e) => crate::trace!("gfx: command {cmd:#x} of {len} bytes skipped: {e}"),
        }
    }
    Ok(out)
}

fn parse_body(cmd: u16, body: &[u8]) -> Result<ServerPdu<'_>> {
    let mut r = Reader::new(body);
    let pdu = match cmd {
        CMDID_WIRETOSURFACE_1 => {
            let surface_id = r.u16()?;
            let codec_id = r.u16()?;
            let pixel_format = r.u8()?;
            let dest = Rect16::read(&mut r)?;
            let n = r.u32()? as usize;
            ServerPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest,
                data: r.bytes(n)?,
            }
        }
        CMDID_WIRETOSURFACE_2 => {
            let surface_id = r.u16()?;
            let codec_id = r.u16()?;
            let context_id = r.u32()?;
            let pixel_format = r.u8()?;
            let n = r.u32()? as usize;
            ServerPdu::WireToSurface2 {
                surface_id,
                codec_id,
                context_id,
                pixel_format,
                data: r.bytes(n)?,
            }
        }
        CMDID_DELETEENCODINGCONTEXT => ServerPdu::DeleteEncodingContext {
            surface_id: r.u16()?,
            context_id: r.u32()?,
        },
        CMDID_SOLIDFILL => {
            let surface_id = r.u16()?;
            let [b, g, red, _xa] = r.array()?;
            let n = r.u16()? as usize;
            if r.remaining() < n * 8 {
                return proto("gfx: solid fill rectangles truncated");
            }
            let rects = (0..n)
                .map(|_| Rect16::read(&mut r))
                .collect::<Result<_>>()?;
            ServerPdu::SolidFill {
                surface_id,
                color: (red as u32) << 16 | (g as u32) << 8 | b as u32,
                rects,
            }
        }
        CMDID_SURFACETOSURFACE => ServerPdu::SurfaceToSurface {
            src: r.u16()?,
            dst: r.u16()?,
            rect: Rect16::read(&mut r)?,
            points: points(&mut r)?,
        },
        CMDID_SURFACETOCACHE => ServerPdu::SurfaceToCache {
            surface_id: r.u16()?,
            cache_key: u64::from_le_bytes(r.array()?),
            cache_slot: r.u16()?,
            rect: Rect16::read(&mut r)?,
        },
        CMDID_CACHETOSURFACE => ServerPdu::CacheToSurface {
            cache_slot: r.u16()?,
            surface_id: r.u16()?,
            points: points(&mut r)?,
        },
        CMDID_EVICTCACHEENTRY => ServerPdu::EvictCacheEntry {
            cache_slot: r.u16()?,
        },
        CMDID_CREATESURFACE => ServerPdu::CreateSurface {
            surface_id: r.u16()?,
            width: r.u16()?,
            height: r.u16()?,
            pixel_format: r.u8()?,
        },
        CMDID_DELETESURFACE => ServerPdu::DeleteSurface {
            surface_id: r.u16()?,
        },
        CMDID_STARTFRAME => ServerPdu::StartFrame {
            timestamp: r.u32()?,
            frame_id: r.u32()?,
        },
        CMDID_ENDFRAME => ServerPdu::EndFrame { frame_id: r.u32()? },
        CMDID_RESETGRAPHICS => {
            let width = r.u32()?;
            let height = r.u32()?;
            let monitor_count = r.u32()?;
            if width == 0 || height == 0 || width > MAX_OUTPUT_DIM || height > MAX_OUTPUT_DIM {
                return proto(format!("gfx: reset graphics to {width}x{height}"));
            }
            if monitor_count > 16 {
                return proto(format!("gfx: {monitor_count} monitors"));
            }
            // TS_MONITOR_DEF (MS-RDPBCGR 2.2.1.3.6.1) is 20 bytes; the
            // remaining pad bytes are ignored.
            r.skip(monitor_count as usize * 20)?;
            ServerPdu::ResetGraphics {
                width,
                height,
                monitor_count,
            }
        }
        CMDID_MAPSURFACETOOUTPUT => {
            let surface_id = r.u16()?;
            r.skip(2)?;
            ServerPdu::MapSurfaceToOutput {
                surface_id,
                x: r.u32()?,
                y: r.u32()?,
            }
        }
        CMDID_CACHEIMPORTREPLY => {
            let n = r.u16()? as usize;
            if n > 5462 {
                // 2.2.2.16: at most 5462 entries are offered.
                return proto(format!("gfx: cache import reply with {n} entries"));
            }
            if r.remaining() < n * 2 {
                return proto("gfx: cache import reply truncated");
            }
            ServerPdu::CacheImportReply {
                slots: (0..n).map(|_| r.u16()).collect::<Result<_>>()?,
            }
        }
        CMDID_CAPSCONFIRM => ServerPdu::CapsConfirm(capset(&mut r)?),
        other => ServerPdu::Other(other),
    };
    Ok(pdu)
}

fn header(cmd: u16, body_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + body_len);
    v.put_u16(cmd);
    v.put_u16(0);
    v.put_u32((HEADER_LEN + body_len) as u32);
    v
}

/// RDPGFX_CAPS_ADVERTISE_PDU (2.2.2.18).
pub fn caps_advertise(sets: &[CapSet]) -> Vec<u8> {
    let mut v = header(CMDID_CAPSADVERTISE, 2 + sets.len() * 12);
    v.put_u16(sets.len() as u16);
    for s in sets {
        v.put_u32(s.version);
        v.put_u32(4);
        v.put_u32(s.flags);
    }
    v
}

/// RDPGFX_FRAME_ACKNOWLEDGE_PDU (2.2.2.13).
pub fn frame_acknowledge(queue_depth: u32, frame_id: u32, total_frames: u32) -> Vec<u8> {
    let mut v = header(CMDID_FRAMEACKNOWLEDGE, 12);
    v.put_u32(queue_depth);
    v.put_u32(frame_id);
    v.put_u32(total_frames);
    v
}

/// RDPGFX_AVC420_QUANT_QUALITY (2.2.4.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantQuality {
    /// Quantization parameter (6 bits).
    pub qp: u8,
    /// The region is progressively encoded.
    pub progressive: bool,
    /// Quality level 0..=100.
    pub quality: u8,
}

/// RFX_AVC420_BITMAP_STREAM (2.2.4.4): the RFX_AVC420_METABLOCK (2.2.4.4.1)
/// and the H.264 Annex B bitstream that follows it.
#[derive(Debug, PartialEq, Eq)]
pub struct Avc420<'a> {
    pub regions: Vec<Rect16>,
    pub quality: Vec<QuantQuality>,
    pub bitstream: &'a [u8],
}

/// Parses an RFX_AVC420_BITMAP_STREAM.
pub fn parse_avc420(data: &[u8]) -> Result<Avc420<'_>> {
    let mut r = Reader::new(data);
    let n = r.u32()? as usize;
    // Each region costs 10 bytes (rectangle and quant/quality).
    if n > r.remaining() / 10 {
        return proto(format!("gfx: AVC420 metablock with {n} regions truncated"));
    }
    let regions = (0..n)
        .map(|_| Rect16::read(&mut r))
        .collect::<Result<Vec<_>>>()?;
    let quality = (0..n)
        .map(|_| {
            let qp = r.u8()?;
            let quality = r.u8()?;
            Ok(QuantQuality {
                qp: qp & 0x3F,
                progressive: qp & 0x80 != 0,
                quality,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Avc420 {
        regions,
        quality,
        bitstream: r.rest(),
    })
}
