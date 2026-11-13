//! Graphics Pipeline Extension, client side (MS-RDPEGFX), on the
//! `Microsoft::Windows::RDS::Graphics` dynamic virtual channel.
//!
//! Opt-in ([`crate::Graphics::Gfx`]): the client sets
//! RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL in its core data (MS-RDPBCGR
//! 2.2.1.3.2) and offers this channel. The server then sends the desktop as
//! surface commands instead of bitmap updates.
//!
//! - [`zgfx`]: RDP 8.0 bulk decompression of every server message (2.2.5).
//! - [`pdu`]: the graphics PDUs (2.2.1 - 2.2.4).
//! - [`surface`]: surfaces, bitmap cache and the output buffer (3.3.1).
//! - [`h264`]: the H.264 decoder interface and colour conversion (3.3.8.3).
//! - [`clearcodec`]: ClearCodec and its caches (2.2.4.1, 3.3.8.1), with the
//!   NSCodec subcodec in [`nsc`] (MS-RDPNSC).
//!
//! Codecs: uncompressed, planar (MS-RDPEGDI 2.2.2.5.1), ClearCodec and
//! AVC420 (2.2.4.4) when an H.264 decoder is supplied. Not implemented: AVC444,
//! RemoteFX and RemoteFX Progressive (WireToSurface2) and Alpha; their
//! updates are dropped and traced. The persistent bitmap cache is not
//! offered (no RDPGFX_CACHE_IMPORT_OFFER_PDU, 3.3.5.16).
//!
//! Frames are composed into the output buffer at RDPGFX_END_FRAME_PDU and
//! acknowledged at once (3.3.5.12, 3.3.5.13); the session loop copies the
//! composed areas into its framebuffer through [`GfxHandle::present`].

pub mod clearcodec;
pub mod h264;
pub mod nsc;
pub mod pdu;
pub mod surface;
pub mod zgfx;

#[cfg(test)]
mod clearcodec_tests;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex, MutexGuard};

use crate::codec::planar;
use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::Result;
use crate::framebuffer::{Damage, Framebuffer};
use crate::trace;

use clearcodec::ClearCodec;
use h264::H264Decoder;
use pdu::{CapSet, Rect16, ServerPdu};
use surface::{Area, GfxState};

/// Dynamic virtual channel name (2.1).
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// How the server sends the desktop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Graphics {
    /// Classic bitmap updates (MS-RDPBCGR 2.2.9.1.1.3.1.2): lowest latency.
    #[default]
    Bitmap,
    /// The graphics pipeline (MS-RDPEGFX), with H.264 when a decoder exists.
    Gfx,
}

/// The capability sets the client advertises (2.2.2.18), best first.
///
/// Without an H.264 decoder: versions 10.7 and 10.0 with AVC disabled and
/// 8.1 without AVC420. With a decoder: 8.1 with AVC420 only. A 10.x set
/// without RDPGFX_CAPS_FLAG_AVC_DISABLED obliges the client to decode
/// AVC444 (2.2.3.3), which is not implemented, and a server picks the
/// highest version it shares; so AVC420 is offered through 8.1 alone.
/// Every set asks for the 16 MB bitmap cache.
pub fn advertised_caps(avc420: bool) -> Vec<CapSet> {
    use pdu::*;
    if avc420 {
        return vec![CapSet {
            version: CAPVERSION_81,
            flags: CAPS_FLAG_SMALL_CACHE | CAPS_FLAG_AVC420_ENABLED,
        }];
    }
    vec![
        CapSet {
            version: CAPVERSION_107,
            flags: CAPS_FLAG_SMALL_CACHE | CAPS_FLAG_AVC_DISABLED | CAPS_FLAG_SCALEDMAP_DISABLE,
        },
        CapSet {
            version: CAPVERSION_10,
            flags: CAPS_FLAG_SMALL_CACHE | CAPS_FLAG_AVC_DISABLED,
        },
        CapSet {
            version: CAPVERSION_81,
            flags: CAPS_FLAG_SMALL_CACHE,
        },
    ]
}

/// The session side of the graphics channel: composed output to present.
#[derive(Clone)]
pub struct GfxHandle(Arc<Mutex<GfxState>>);

impl GfxHandle {
    fn lock(&self) -> MutexGuard<'_, GfxState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Copies what finished frames changed into `fb` and appends the areas
    /// to `damage`. Returns true if `fb` was resized (RDPGFX_RESET_GRAPHICS).
    pub fn present(&self, fb: &mut Framebuffer, damage: &mut Vec<Damage>) -> bool {
        self.lock().present(fb, damage)
    }
}

/// Graphics channel handler (client side of MS-RDPEGFX).
pub struct GraphicsChannel {
    state: Arc<Mutex<GfxState>>,
    zgfx: zgfx::Zgfx,
    h264: Option<Box<dyn H264Decoder>>,
    /// ClearCodec storages and cursors; they belong to the channel, not to
    /// a surface (3.3.1.9 - 3.3.1.13).
    clear: ClearCodec,
    /// The capability set the server confirmed (3.3.1.14).
    confirmed: Option<CapSet>,
    /// Frames decoded since the channel opened (2.2.2.13).
    frames: u32,
}

/// Creates the graphics channel and the handle the session presents from.
/// With `h264` the client offers AVC420.
pub fn graphics(h264: Option<Box<dyn H264Decoder>>) -> (GraphicsChannel, GfxHandle) {
    let state = Arc::new(Mutex::new(GfxState::new()));
    (
        GraphicsChannel {
            state: state.clone(),
            zgfx: zgfx::Zgfx::new(),
            h264,
            clear: ClearCodec::new(),
            confirmed: None,
            frames: 0,
        },
        GfxHandle(state),
    )
}

fn area(r: &Rect16) -> Area {
    Area::new(r.left as usize, r.top as usize, r.width(), r.height())
}

impl GraphicsChannel {
    fn state(&self) -> MutexGuard<'_, GfxState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The capability set the server confirmed, once it has.
    pub fn confirmed(&self) -> Option<CapSet> {
        self.confirmed
    }

    /// Handles one decompressed graphics message (one or more PDUs).
    pub fn handle(&mut self, buf: &[u8], out: &mut DvcOut) -> Result<()> {
        for (pdu, end) in pdu::parse_pdus(buf)? {
            self.pdu(pdu, buf.len() - end, out);
        }
        Ok(())
    }

    /// One PDU. Commands that name unknown surfaces or slots are traced and
    /// skipped, so one bad command does not end the graphics stream.
    /// `unprocessed` counts the bytes of this message after the PDU.
    fn pdu(&mut self, pdu: ServerPdu, unprocessed: usize, out: &mut DvcOut) {
        let missing = |what: &str, id: u16| trace!("gfx: {what} for unknown surface {id}");
        match pdu {
            ServerPdu::CapsConfirm(caps) => {
                trace!(
                    "gfx: caps confirm {:#010x} flags {:#x}",
                    caps.version, caps.flags
                );
                let small = caps.flags & (pdu::CAPS_FLAG_SMALL_CACHE | pdu::CAPS_FLAG_THINCLIENT);
                self.state().set_small_cache(small != 0);
                self.confirmed = Some(caps);
            }
            ServerPdu::ResetGraphics {
                width,
                height,
                monitor_count,
            } => {
                trace!("gfx: reset graphics {width}x{height}, {monitor_count} monitors");
                self.state().reset(width as usize, height as usize);
            }
            ServerPdu::CreateSurface {
                surface_id,
                width,
                height,
                pixel_format,
            } => {
                trace!(
                    "gfx: create surface {surface_id} {width}x{height} format {pixel_format:#x}"
                );
                if let Err(e) = self
                    .state()
                    .create(surface_id, width as usize, height as usize)
                {
                    trace!("{e}");
                }
            }
            ServerPdu::DeleteSurface { surface_id } => self.state().delete(surface_id),
            ServerPdu::MapSurfaceToOutput { surface_id, x, y } => {
                if !self.state().map(surface_id, x as usize, y as usize) {
                    missing("map to output", surface_id);
                }
            }
            ServerPdu::StartFrame { .. } => {}
            ServerPdu::EndFrame { frame_id } => {
                self.state().compose();
                self.frames = self.frames.wrapping_add(1);
                // queueDepth counts graphics bytes received and not yet
                // processed: what follows this PDU in the same message.
                // Zero there reads as QUEUE_DEPTH_UNAVAILABLE (2.2.2.13).
                let depth = (unprocessed as u32).min(pdu::SUSPEND_FRAME_ACKNOWLEDGEMENT - 1);
                out.send(pdu::frame_acknowledge(depth, frame_id, self.frames));
                if self.frames <= 3 || self.frames.is_multiple_of(200) {
                    trace!(
                        "gfx: frame {frame_id} acknowledged ({} decoded)",
                        self.frames
                    );
                }
            }
            ServerPdu::SolidFill {
                surface_id,
                color,
                rects,
            } => {
                let areas: Vec<Area> = rects.iter().map(area).collect();
                if !self.state().fill(surface_id, color, &areas) {
                    missing("solid fill", surface_id);
                }
            }
            ServerPdu::SurfaceToSurface {
                src,
                dst,
                rect,
                points,
            } => {
                let pts: Vec<_> = points
                    .iter()
                    .map(|p| (p.x as usize, p.y as usize))
                    .collect();
                if !self.state().copy(src, area(&rect), dst, &pts) {
                    trace!("gfx: surface to surface {src} -> {dst}: unknown surface");
                }
            }
            ServerPdu::SurfaceToCache {
                surface_id,
                cache_slot,
                rect,
                ..
            } => match self.state().to_cache(surface_id, area(&rect), cache_slot) {
                Ok(true) => {}
                Ok(false) => missing("surface to cache", surface_id),
                Err(e) => trace!("{e}"),
            },
            ServerPdu::CacheToSurface {
                cache_slot,
                surface_id,
                points,
            } => {
                let pts: Vec<_> = points
                    .iter()
                    .map(|p| (p.x as usize, p.y as usize))
                    .collect();
                match self.state().from_cache(cache_slot, surface_id, &pts) {
                    Ok(true) => {}
                    Ok(false) => missing("cache to surface", surface_id),
                    Err(e) => trace!("{e}"),
                }
            }
            ServerPdu::EvictCacheEntry { cache_slot } => self.state().evict(cache_slot),
            ServerPdu::CacheImportReply { slots } => {
                // No offer is sent, so nothing was imported.
                trace!(
                    "gfx: cache import reply with {} entries ignored",
                    slots.len()
                );
            }
            ServerPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest,
                data,
            } => {
                if let Err(e) = self.wire_to_surface(surface_id, codec_id, pixel_format, dest, data)
                {
                    trace!("gfx: wire to surface {surface_id} codec {codec_id:#x}: {e}");
                }
            }
            ServerPdu::Other(cmd) => {
                trace!("gfx: command {cmd:#x} not supported, ignored");
            }
        }
    }

    /// RDPGFX_WIRE_TO_SURFACE_PDU_1 (3.3.5.1): decode and copy to a surface.
    fn wire_to_surface(
        &mut self,
        id: u16,
        codec: u16,
        pixel_format: u8,
        dest: Rect16,
        data: &[u8],
    ) -> Result<()> {
        let (w, h) = (dest.width(), dest.height());
        let target = area(&dest);
        let pixels = match codec {
            pdu::CODECID_UNCOMPRESSED => {
                if pixel_format != pdu::PIXEL_FORMAT_XRGB_8888
                    && pixel_format != pdu::PIXEL_FORMAT_ARGB_8888
                {
                    return crate::error::proto(format!("pixel format {pixel_format:#x}"));
                }
                if data.len() != w * h * 4 {
                    return crate::error::proto(format!(
                        "{} bytes for {w}x{h} uncompressed",
                        data.len()
                    ));
                }
                // Little-endian XRGB/ARGB: B, G, R, X/A per pixel; alpha is
                // not copied (3.3.5.1).
                data.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|[b, g, r, _]| (*r as u32) << 16 | (*g as u32) << 8 | *b as u32)
                    .collect()
            }
            pdu::CODECID_PLANAR => planar::decode(data, w, h)?,
            pdu::CODECID_CLEARCODEC => {
                if w * h > surface::MAX_SURFACE_PIXELS {
                    return crate::error::proto(format!("{w}x{h} ClearCodec bitmap"));
                }
                // Layers draw over what the surface shows; the stream is
                // decoded even for an unknown surface so the caches stay in
                // step with the server.
                let mut px = self
                    .state()
                    .surface(id)
                    .map_or_else(|| vec![0; w * h], |s| s.read_padded(target));
                self.clear.decode(data, w, h, &mut px)?;
                px
            }
            pdu::CODECID_AVC420 => return self.avc420(id, dest, data),
            _ => {
                trace!("gfx: codec {codec:#x} not implemented; {w}x{h} update dropped");
                return Ok(());
            }
        };
        if !self.state().blit(id, target, &pixels, w) {
            trace!("gfx: wire to surface for unknown surface {id}");
        }
        Ok(())
    }

    /// AVC420 (2.2.4.4): decode the frame, then copy the region rectangles
    /// (surface coordinates inside `dest`) from the picture, whose origin is
    /// the top-left corner of `dest`.
    fn avc420(&mut self, id: u16, dest: Rect16, data: &[u8]) -> Result<()> {
        let avc = pdu::parse_avc420(data)?;
        let Some(decoder) = self.h264.as_mut() else {
            trace!("gfx: AVC420 update without a decoder dropped");
            return Ok(());
        };
        let Some(frame) = decoder.decode(avc.bitstream)? else {
            return Ok(());
        };
        frame.validate()?;
        let mut st = self.state();
        if st.surface(id).is_none() {
            trace!("gfx: AVC420 for unknown surface {id}");
            return Ok(());
        }
        let (dx, dy) = (dest.left as usize, dest.top as usize);
        for r in &avc.regions {
            // Region ∩ destRect ∩ decoded picture.
            let left = r.left.max(dest.left) as usize;
            let top = r.top.max(dest.top) as usize;
            let right = (r.right.min(dest.right) as usize).min(dx + frame.width);
            let bottom = (r.bottom.min(dest.bottom) as usize).min(dy + frame.height);
            if right <= left || bottom <= top {
                continue;
            }
            let (w, h) = (right - left, bottom - top);
            let mut px = Vec::with_capacity(w * h);
            for y in top - dy..bottom - dy {
                for x in left - dx..right - dx {
                    px.push(frame.rgb(x, y));
                }
            }
            st.blit(id, Area::new(left, top, w, h), &px, w);
        }
        Ok(())
    }
}

impl DynamicChannel for GraphicsChannel {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    /// Sends RDPGFX_CAPS_ADVERTISE_PDU first (3.3.5.18).
    fn opened(&mut self, out: &mut DvcOut) -> Result<()> {
        let caps = advertised_caps(self.h264.is_some());
        trace!("gfx: channel open, advertising {caps:x?}");
        out.send(pdu::caps_advertise(&caps));
        Ok(())
    }

    /// One RDP_SEGMENTED_DATA message (2.1). A decompression or framing
    /// error closes the channel: the history is lost and later messages
    /// cannot be decoded.
    /// A message that cannot be decompressed or parsed is traced and
    /// dropped: an error here would close the channel, and with it every
    /// screen update for the rest of the session.
    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let buf = match self.zgfx.decompress(msg) {
            Ok(b) => b,
            Err(e) => {
                trace!("gfx: message of {} bytes dropped: {e}", msg.len());
                return Ok(());
            }
        };
        if let Err(e) = self.handle(&buf, out) {
            trace!("gfx: message of {} bytes dropped: {e}", buf.len());
        }
        Ok(())
    }

    fn closed(&mut self) {
        trace!("gfx: channel closed");
        self.zgfx = zgfx::Zgfx::new();
        self.clear = ClearCodec::new();
        self.confirmed = None;
    }
}
