//! Video redirection: Video Optimized Remoting (MS-RDPEVOR) placed with
//! geometry tracking (MS-RDPEGT), client side.
//!
//! A server that classifies a part of the screen as video can send it as
//! an H.264 stream on two dynamic channels instead of painting it into the
//! graphics pipeline: the control channel
//! (`Microsoft::Windows::RDS::Video::Control::v08.01`) starts and stops a
//! presentation, the data channel (`...::Video::Data::v08.01`) carries the
//! samples with their timestamps. The presentation names a geometry
//! mapping; the geometry channel (`Microsoft::Windows::RDS::Geometry::v08.01`)
//! says where on the desktop that mapping is and which parts are visible.
//!
//! The protocol depends on the graphics pipeline (MS-RDPEVOR 1.5), so the
//! client offers these channels only with [`crate::Graphics::Gfx`], an H.264
//! decoder and [`crate::Config::video`]; [`crate::gfx::GfxHandle`] paints the
//! frames over the composed picture.
//!
//! - [`pdu`]: the MS-RDPEVOR messages (2.2.1).
//! - [`geometry`]: MAPPED_GEOMETRY_PACKET and the placement maths (MS-RDPEGT).
//!
//! Each presentation gets its own decoder from the session's
//! [`H264Factory`] when it starts (3.2.5.1); the response is sent once the
//! decoder is there, and not at all when there is none, a subtype other
//! than H.264, or an odd size (3.3.3). Samples are reassembled from their
//! packets, decoded at once and shown at their timestamps: the first frame
//! anchors the server's clock to this one, later frames wait for their
//! time, late frames are shown at once, a frame more than
//! [`RESYNC_LATE`] late or [`RESYNC_EARLY`] early re-anchors, and frames
//! overtaken by a newer due one are skipped. The picture is scaled
//! (nearest neighbour) from the encoded size to the tracked rectangle,
//! converted with BT.601 limited range (2.2.1.6), and painted into the
//! visible parts only, as damage: no frame loop. Where the graphics
//! pipeline repaints a visible part, the current frame is painted again;
//! where the video goes away (stop, clear, a moved or shrunk geometry) the
//! composed graphics output is copied back.
//!
//! Missing or out-of-order packets and decode errors ask the server for a
//! keyframe (Network Error notification, at most once per
//! [`NETWORK_ERROR_GAP`]); a decoder slower than the stream asks for a
//! lower frame rate (2.2.1.5), see [`RateGovernor`].

pub mod geometry;
pub mod pdu;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::Result;
use crate::framebuffer::{Damage, Framebuffer};
use crate::gfx::h264::{H264Decoder, H264Factory, Yuv420Frame};
use crate::trace;

use geometry::{Area, GeometryPacket, MappedGeometry};
use pdu::{Notification, PresentationRequest, StartPresentation, VideoData};

/// Control channel name (MS-RDPEVOR 2.1).
pub const CONTROL_CHANNEL: &str = "Microsoft::Windows::RDS::Video::Control::v08.01";
/// Data channel name (MS-RDPEVOR 2.1).
pub const DATA_CHANNEL: &str = "Microsoft::Windows::RDS::Video::Data::v08.01";

/// Presentations at once. The spec allows one (3.1); a few more cost
/// nothing and survive a server that starts the next before stopping the
/// last.
pub const MAX_PRESENTATIONS: usize = 4;
/// Geometry mappings kept; an update for a new id past this is dropped.
pub const MAX_GEOMETRIES: usize = 64;
/// Largest reassembled sample.
pub const MAX_SAMPLE: usize = 8 << 20;
/// Largest encoded picture side accepted (the spec caps the scaled size at
/// 1920 x 1080; this leaves room for padding).
pub const MAX_SIDE: u32 = 4096;
/// Decoded frames waiting for their time; past this the oldest is dropped.
pub const MAX_QUEUED: usize = 8;
/// A frame due this much before now re-anchors the clock (after a stall).
pub const RESYNC_LATE: Duration = Duration::from_millis(250);
/// A frame due this much after now re-anchors the clock (a timestamp jump).
pub const RESYNC_EARLY: Duration = Duration::from_secs(2);
/// Smallest gap between two Network Error notifications.
pub const NETWORK_ERROR_GAP: Duration = Duration::from_secs(1);

/// An access unit delimiter (H.264 NAL type 9, any slice types), appended
/// to every sample so the Media Foundation decoder knows the picture is
/// complete and returns it at once instead of with the next sample.
pub const AUD: [u8; 6] = [0, 0, 0, 1, 9, 0xf0];

/// What video redirection did since the session started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VideoStats {
    /// Presentations started (answered with a response).
    pub presentations: u64,
    /// Samples decoded into a picture.
    pub decoded: u64,
    /// Frames painted.
    pub presented: u64,
    /// Frames skipped: overtaken by a newer one or dropped from a full queue.
    pub skipped: u64,
    /// Time spent decoding.
    pub decode: Duration,
}

/// BT.601 limited range (16-235 luma, 16-240 chroma) YCbCr to 0x00RRGGBB,
/// the colour space of MS-RDPEVOR samples (2.2.1.6), in 8.8 fixed point:
///
/// R = 1.164 (Y - 16) + 1.596 (V - 128)
/// G = 1.164 (Y - 16) - 0.392 (U - 128) - 0.813 (V - 128)
/// B = 1.164 (Y - 16) + 2.017 (U - 128)
pub fn rgb601(y: u8, u: u8, v: u8) -> u32 {
    let c = 298 * (i32::from(y) - 16);
    let d = i32::from(u) - 128;
    let e = i32::from(v) - 128;
    let clamp = |x: i32| ((x + 128) >> 8).clamp(0, 255) as u32;
    clamp(c + 409 * e) << 16 | clamp(c - 100 * d - 208 * e) << 8 | clamp(c + 516 * d)
}

/// True when `b` starts with an Annex B start code (00 00 01 or
/// 00 00 00 01).
fn start_code(b: &[u8]) -> Option<usize> {
    if b.starts_with(&[0, 0, 1]) {
        Some(3)
    } else if b.starts_with(&[0, 0, 0, 1]) {
        Some(4)
    } else {
        None
    }
}

/// `sample` without a leading access unit delimiter: [`AUD`] already ends
/// the previous sample, and two in a row would be an empty access unit.
fn strip_leading_aud(sample: &[u8]) -> &[u8] {
    let Some(n) = start_code(sample) else {
        return sample;
    };
    if sample.get(n).map(|b| b & 0x1f) != Some(9) {
        return sample;
    }
    let next = (n + 1..sample.len()).find(|&i| start_code(&sample[i..]).is_some());
    next.map_or(&[], |i| &sample[i..])
}

/// The bytes handed to the decoder for one sample: the sequence header
/// (SPS and PPS, first sample only), the sample without a leading access
/// unit delimiter, and a closing [`AUD`].
pub fn access_unit(sequence_header: &[u8], sample: &[u8]) -> Vec<u8> {
    let body = strip_leading_aud(sample);
    let mut au = Vec::with_capacity(sequence_header.len() + body.len() + AUD.len());
    au.extend_from_slice(sequence_header);
    au.extend_from_slice(body);
    au.extend_from_slice(&AUD);
    au
}

/// Paints `frame` (its top-left `src` pixels) scaled to `placement` into
/// `fb`, inside `area` only (desktop coordinates; the caller keeps it
/// inside both `placement` and `fb`). Nearest neighbour.
pub fn paint_frame(
    fb: &mut Framebuffer,
    frame: &Yuv420Frame,
    src: (usize, usize),
    placement: &geometry::Rect32,
    area: Area,
) {
    let (pw, ph) = (placement.width() as usize, placement.height() as usize);
    let (sw, sh) = (src.0.min(frame.width), src.1.min(frame.height));
    if pw == 0 || ph == 0 || sw == 0 || sh == 0 {
        return;
    }
    let (px, py) = (i64::from(placement.left), i64::from(placement.top));
    // Source column of each painted column: the centre of the destination
    // pixel, mapped back.
    let cols: Vec<usize> = (area.x..area.x + area.w)
        .map(|x| {
            let dx = (x as i64 - px).clamp(0, pw as i64 - 1) as usize;
            ((2 * dx + 1) * sw / (2 * pw)).min(sw - 1)
        })
        .collect();
    for y in area.y..area.y + area.h {
        let dy = (y as i64 - py).clamp(0, ph as i64 - 1) as usize;
        let sy = ((2 * dy + 1) * sh / (2 * ph)).min(sh - 1);
        let row = &mut fb.pixels[y * fb.width + area.x..y * fb.width + area.x + area.w];
        let luma = &frame.y[sy * frame.y_stride..];
        let cy = sy / 2;
        for (px, &sx) in row.iter_mut().zip(&cols) {
            let cx = sx / 2;
            *px = rgb601(
                luma[sx],
                frame.chroma(false, cx, cy),
                frame.chroma(true, cx, cy),
            );
        }
    }
}

/// Decides when to ask the server for another frame rate (2.2.1.5): when
/// decoding a frame takes longer than the time between frames, ask for as
/// many frames per second as the decoder manages (1 - 30; lower only);
/// once it manages twice the rate asked for, lift the limit. At most one change
/// per [`RateGovernor::HOLD`], and none before [`RateGovernor::WARMUP`]
/// samples.
#[derive(Debug, Default)]
pub struct RateGovernor {
    samples: u32,
    /// Smoothed decoding time and time between frames, seconds.
    decode: f64,
    interval: f64,
    requested: Option<u32>,
    last_change: Option<Instant>,
}

impl RateGovernor {
    pub const WARMUP: u32 = 30;
    pub const HOLD: Duration = Duration::from_secs(5);
    const ALPHA: f64 = 0.1;

    /// One decoded sample: how long decoding took and the time since the
    /// previous sample (if known). Returns a notification to send.
    pub fn observe(
        &mut self,
        decode: Duration,
        interval: Option<Duration>,
        now: Instant,
    ) -> Option<Notification> {
        let ewma = |avg: f64, v: f64, first: bool| {
            if first {
                v
            } else {
                avg + Self::ALPHA * (v - avg)
            }
        };
        self.decode = ewma(self.decode, decode.as_secs_f64(), self.samples == 0);
        if let Some(i) = interval.filter(|i| !i.is_zero() && *i < Duration::from_secs(2)) {
            self.interval = ewma(self.interval, i.as_secs_f64(), self.interval == 0.0);
        }
        self.samples = self.samples.saturating_add(1);
        if self.samples < Self::WARMUP || self.decode <= 0.0 || self.interval <= 0.0 {
            return None;
        }
        if self
            .last_change
            .is_some_and(|t| now.saturating_duration_since(t) < Self::HOLD)
        {
            return None;
        }
        let capacity = (1.0 / self.decode).floor().min(1000.0) as u32;
        let incoming = 1.0 / self.interval;
        // Only ever lowered by an override (while one is in effect the
        // server sends at most that rate); raised by lifting it.
        let change = match self.requested {
            _ if f64::from(capacity) < incoming && self.requested.is_none_or(|r| capacity < r) => {
                let fps = capacity.clamp(pdu::MIN_FRAMERATE, pdu::MAX_FRAMERATE);
                (self.requested != Some(fps)).then_some(Notification::FrameRate(fps))
            }
            Some(r) if capacity >= 2 * r => Some(Notification::Unrestricted),
            _ => None,
        };
        if let Some(n) = change {
            self.requested = match n {
                Notification::FrameRate(fps) => Some(fps),
                _ => None,
            };
            self.last_change = Some(now);
        }
        change
    }
}

/// A sample being reassembled from its packets.
struct Partial {
    sample_number: u32,
    next: u16,
    total: u16,
    flags: u8,
    timestamp: u64,
    duration: u64,
    data: Vec<u8>,
}

/// A decoded frame waiting for its time.
struct Queued {
    due: Instant,
    frame: Yuv420Frame,
}

struct Presentation {
    id: u8,
    mapping_id: u64,
    /// The encoded picture size (ScaledWidth x ScaledHeight).
    scaled: (usize, usize),
    decoder: Box<dyn H264Decoder>,
    /// The sequence header, sent with the first sample, then cleared.
    sequence_header: Vec<u8>,
    partial: Option<Partial>,
    /// The last complete sample's number and timestamp.
    last_sample: Option<(u32, Option<u64>)>,
    /// Local time and server timestamp that match.
    anchor: Option<(Instant, u64)>,
    queue: VecDeque<Queued>,
    current: Option<Yuv420Frame>,
    /// The current frame is new, or its geometry changed: paint all of it.
    repaint: bool,
    last_network_error: Option<Instant>,
    rate: RateGovernor,
}

impl Presentation {
    fn recycle(&mut self, frame: Yuv420Frame) {
        self.decoder.recycle(frame);
    }
}

/// State the three channels and the session's [`VideoHandle`] share. All
/// of them run on the session worker thread.
struct VideoState {
    factory: H264Factory,
    presentations: Vec<Presentation>,
    geometries: HashMap<u64, MappedGeometry>,
    /// Desktop areas the video no longer covers: the graphics output is
    /// copied back there.
    restore: Vec<Damage>,
    /// Notifications for the control channel, in order.
    notify: Vec<Vec<u8>>,
    control_open: bool,
    /// The desktop size of the last present.
    desktop: (usize, usize),
    stats: VideoStats,
}

impl VideoState {
    fn find(&mut self, id: u8) -> Option<usize> {
        self.presentations.iter().position(|p| p.id == id)
    }

    /// Queues the visible parts of `mapping` for restoring.
    fn restore_mapping(&mut self, mapping: u64) {
        let Some(g) = self.geometries.get(&mapping) else {
            return;
        };
        let (w, h) = self.desktop;
        self.restore
            .extend(g.visible(w, h).into_iter().map(|a| Damage {
                x: a.x,
                y: a.y,
                w: a.w,
                h: a.h,
            }));
    }

    fn queue_notification(&mut self, id: u8, n: Notification) {
        if self.control_open {
            trace!("video {id}: notifying {n:?}");
            self.notify.push(pdu::client_notification(id, n));
        }
    }

    /// Network Error notification for presentation `i`, rate limited.
    fn network_error(&mut self, i: usize, now: Instant) {
        let p = &mut self.presentations[i];
        if p.last_network_error
            .is_some_and(|t| now.saturating_duration_since(t) < NETWORK_ERROR_GAP)
        {
            return;
        }
        p.last_network_error = Some(now);
        let id = p.id;
        self.queue_notification(id, Notification::NetworkError);
    }

    /// TSMM_PRESENTATION_REQUEST Start (3.2.5.1).
    fn start(&mut self, s: StartPresentation, out: &mut DvcOut) {
        let id = s.presentation_id;
        if self.find(id).is_some() {
            trace!("video {id}: start for a running presentation ignored");
            return;
        }
        if s.video_subtype != pdu::MFVIDEOFORMAT_H264 {
            trace!("video {id}: subtype {:02x?} not supported", s.video_subtype);
            return;
        }
        let (w, h) = (s.scaled_width, s.scaled_height);
        if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
            trace!("video {id}: picture size {w}x{h} refused");
            return;
        }
        if self.presentations.len() >= MAX_PRESENTATIONS {
            trace!("video {id}: {MAX_PRESENTATIONS} presentations running; start ignored");
            return;
        }
        let Some(decoder) = (self.factory)() else {
            trace!("video {id}: no H.264 decoder; start ignored");
            return;
        };
        let sequence_header = if s.extra.is_empty() || start_code(&s.extra).is_some() {
            s.extra
        } else {
            trace!("video {id}: sequence header not in Annex B form; ignored");
            Vec::new()
        };
        trace!(
            "video {id}: start {w}x{h} (source {}x{}), mapping {:#x}",
            s.source_width, s.source_height, s.geometry_mapping_id
        );
        self.presentations.push(Presentation {
            id,
            mapping_id: s.geometry_mapping_id,
            scaled: (w as usize, h as usize),
            decoder,
            sequence_header,
            partial: None,
            last_sample: None,
            anchor: None,
            queue: VecDeque::new(),
            current: None,
            repaint: false,
            last_network_error: None,
            rate: RateGovernor::default(),
        });
        self.stats.presentations += 1;
        out.send(pdu::presentation_response(id));
    }

    /// TSMM_PRESENTATION_REQUEST Stop (3.2.5.1).
    fn stop(&mut self, id: u8) {
        let Some(i) = self.find(id) else {
            trace!("video {id}: stop for an unknown presentation ignored");
            return;
        };
        let p = self.presentations.remove(i);
        trace!("video {id}: stopped");
        if p.current.is_some() {
            self.restore_mapping(p.mapping_id);
        }
    }

    /// Ends every presentation (the control channel closed).
    fn stop_all(&mut self) {
        let ids: Vec<u8> = self.presentations.iter().map(|p| p.id).collect();
        for id in ids {
            self.stop(id);
        }
    }

    /// One TSMM_VIDEO_DATA message (2.2.1.6).
    fn data(&mut self, msg: &[u8], now: Instant) -> Result<()> {
        let (kind, body) = pdu::split_header(msg)?;
        if kind != pdu::PACKET_TYPE_VIDEO_DATA {
            trace!("video data: packet type {kind} ignored");
            return Ok(());
        }
        let d = VideoData::parse(body)?;
        let Some(i) = self.find(d.presentation_id) else {
            trace!(
                "video {}: data for an unknown presentation dropped",
                d.presentation_id
            );
            return Ok(());
        };
        let Some(sample) = self.reassemble(i, &d, now) else {
            return Ok(());
        };
        self.decode(i, sample, now);
        Ok(())
    }

    /// Adds a packet to its sample; returns the sample once complete.
    fn reassemble(&mut self, i: usize, d: &VideoData, now: Instant) -> Option<Partial> {
        let p = &mut self.presentations[i];
        let mut lost = false;
        if d.packet_index == 1 {
            lost |= p.partial.take().is_some();
            p.partial = Some(Partial {
                sample_number: d.sample_number,
                next: 1,
                total: d.packets_in_sample,
                flags: d.flags,
                timestamp: d.timestamp,
                duration: d.duration,
                data: Vec::with_capacity(d.sample.len() * usize::from(d.packets_in_sample)),
            });
        }
        let fits = p.partial.as_ref().is_some_and(|s| {
            s.sample_number == d.sample_number
                && s.next == d.packet_index
                && s.total == d.packets_in_sample
                && s.data.len() + d.sample.len() <= MAX_SAMPLE
        });
        let mut done = None;
        if fits {
            let s = p.partial.as_mut().expect("checked");
            s.data.extend_from_slice(d.sample);
            s.next += 1;
            if s.next > s.total {
                done = p.partial.take();
            }
        } else {
            lost = true;
            p.partial = None;
            trace!(
                "video {}: packet {}/{} of sample {} out of order; sample dropped",
                p.id, d.packet_index, d.packets_in_sample, d.sample_number
            );
        }
        if let Some(s) = &done
            && let Some((last, _)) = p.last_sample
            && s.sample_number != last.wrapping_add(1)
        {
            trace!("video {}: sample {} after {last}", p.id, s.sample_number);
            lost = true;
        }
        if lost {
            self.network_error(i, now);
        }
        done
    }

    /// Decodes a complete sample and queues the picture for its time.
    fn decode(&mut self, i: usize, s: Partial, now: Instant) {
        let p = &mut self.presentations[i];
        let has_ts = s.flags & pdu::DATA_FLAG_HAS_TIMESTAMPS != 0;
        let ts = has_ts.then_some(s.timestamp);
        // The time since the previous sample, for the frame rate.
        let interval = match (s.duration, p.last_sample) {
            (d, _) if d > 0 => Some(d),
            (_, Some((_, Some(prev)))) => ts.and_then(|t| t.checked_sub(prev)),
            _ => None,
        }
        .map(|d| Duration::from_nanos(d.saturating_mul(100)));
        p.last_sample = Some((s.sample_number, ts));
        let au = access_unit(&p.sequence_header, &s.data);
        let started = Instant::now();
        let result = p.decoder.decode(&au);
        let took = started.elapsed();
        self.stats.decode += took;
        let frame = match result.and_then(|f| {
            if let Some(f) = &f {
                f.validate()?;
            }
            Ok(f)
        }) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(e) => {
                trace!(
                    "video {}: sample {} not decoded: {e}",
                    p.id, s.sample_number
                );
                self.network_error(i, now);
                return;
            }
        };
        let p = &mut self.presentations[i];
        p.sequence_header.clear();
        self.stats.decoded += 1;
        if let Some(n) = p.rate.observe(took, interval, now) {
            let id = p.id;
            self.queue_notification(id, n);
        }
        let p = &mut self.presentations[i];
        let due = match ts {
            None => now,
            Some(t) => {
                let anchored = p
                    .anchor
                    .filter(|(_, base)| t >= *base)
                    .and_then(|(at, base)| {
                        let due = at + Duration::from_nanos((t - base).saturating_mul(100));
                        (due + RESYNC_LATE >= now && due <= now + RESYNC_EARLY).then_some(due)
                    });
                anchored.unwrap_or_else(|| {
                    p.anchor = Some((now, t));
                    now
                })
            }
        };
        p.queue.push_back(Queued { due, frame });
        if p.queue.len() > MAX_QUEUED
            && let Some(old) = p.queue.pop_front()
        {
            p.recycle(old.frame);
            self.stats.skipped += 1;
        }
    }

    /// One MAPPED_GEOMETRY_PACKET (MS-RDPEGT 2.2.1.1).
    fn geometry(&mut self, msg: &[u8]) -> Result<()> {
        match geometry::parse(msg)? {
            GeometryPacket::Update(g) => {
                let id = g.mapping_id;
                if self.geometries.get(&id) == Some(&g) {
                    return Ok(());
                }
                if !self.geometries.contains_key(&id) && self.geometries.len() >= MAX_GEOMETRIES {
                    trace!("geometry {id:#x}: {MAX_GEOMETRIES} mappings kept; update dropped");
                    return Ok(());
                }
                trace!(
                    "geometry {id:#x}: at {:?}, {} visible rectangles",
                    g.placement(),
                    g.rects.len()
                );
                self.restore_mapping(id);
                self.geometries.insert(id, g);
                for p in self.presentations.iter_mut().filter(|p| p.mapping_id == id) {
                    p.repaint = true;
                }
            }
            GeometryPacket::Clear { mapping_id } => {
                // Unknown mappings are ignored (3.1.3).
                if self.geometries.contains_key(&mapping_id) {
                    trace!("geometry {mapping_id:#x}: cleared");
                    self.restore_mapping(mapping_id);
                    self.geometries.remove(&mapping_id);
                }
            }
            GeometryPacket::Other {
                mapping_id,
                update_type,
            } => trace!("geometry {mapping_id:#x}: update type {update_type} ignored"),
        }
        Ok(())
    }

    /// Forgets every mapping (the geometry channel closed).
    fn clear_geometries(&mut self) {
        let ids: Vec<u64> = self.geometries.keys().copied().collect();
        for id in ids {
            self.restore_mapping(id);
        }
        self.geometries.clear();
    }

    /// Shows the frames that are due and repaints the current frames where
    /// `damage[from..]` (what the graphics pipeline just painted) meets
    /// them; appends what it painted to `damage`.
    fn present(
        &mut self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        from: usize,
        now: Instant,
    ) {
        if (fb.width, fb.height) != self.desktop {
            self.desktop = (fb.width, fb.height);
            self.presentations.iter_mut().for_each(|p| p.repaint = true);
        }
        let painted_by_gfx: Vec<Area> = damage[from.min(damage.len())..]
            .iter()
            .map(|d| Area {
                x: d.x,
                y: d.y,
                w: d.w,
                h: d.h,
            })
            .collect();
        for i in 0..self.presentations.len() {
            let p = &mut self.presentations[i];
            let mut newest: Option<Yuv420Frame> = None;
            while p.queue.front().is_some_and(|q| q.due <= now) {
                let q = p.queue.pop_front().expect("checked");
                if let Some(old) = newest.replace(q.frame) {
                    p.recycle(old);
                    self.stats.skipped += 1;
                }
            }
            if let Some(f) = newest {
                if let Some(old) = p.current.replace(f) {
                    p.recycle(old);
                }
                p.repaint = true;
                self.stats.presented += 1;
            }
            let (Some(frame), Some(g)) = (&p.current, self.geometries.get(&p.mapping_id)) else {
                continue;
            };
            let place = g.placement();
            let visible = g.visible(fb.width, fb.height);
            let areas: Vec<Area> = if std::mem::take(&mut p.repaint) {
                visible
            } else {
                visible
                    .iter()
                    .flat_map(|v| painted_by_gfx.iter().filter_map(|d| v.intersect(d)))
                    .collect()
            };
            for a in areas {
                paint_frame(fb, frame, p.scaled, &place, a);
                damage.push(Damage {
                    x: a.x,
                    y: a.y,
                    w: a.w,
                    h: a.h,
                });
            }
        }
    }
}

/// The session side of video redirection: paints the frames into the
/// framebuffer. Shared with the three channels.
#[derive(Clone)]
pub struct VideoHandle(Arc<Mutex<VideoState>>);

impl VideoHandle {
    fn lock(&self) -> MutexGuard<'_, VideoState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Desktop areas the video stopped covering since the last call; the
    /// graphics pipeline copies its output back there.
    pub fn take_restore(&self) -> Vec<Damage> {
        std::mem::take(&mut self.lock().restore)
    }

    /// Paints due frames, and the current frames where `damage[from..]`
    /// overlaps them, into `fb`; appends the painted areas to `damage`.
    pub fn present(
        &self,
        fb: &mut Framebuffer,
        damage: &mut Vec<Damage>,
        from: usize,
        now: Instant,
    ) {
        self.lock().present(fb, damage, from, now);
    }

    /// What video redirection did so far.
    pub fn stats(&self) -> VideoStats {
        self.lock().stats
    }

    /// Presentations running now.
    pub fn active(&self) -> usize {
        self.lock().presentations.len()
    }
}

/// The control channel: presentation requests in, responses and
/// notifications out (MS-RDPEVOR 2.1).
pub struct ControlChannel(Arc<Mutex<VideoState>>);
/// The data channel: TSMM_VIDEO_DATA in (MS-RDPEVOR 2.1).
pub struct DataChannel(Arc<Mutex<VideoState>>);
/// The geometry channel: MAPPED_GEOMETRY_PACKET in (MS-RDPEGT 2.1).
pub struct GeometryChannel(Arc<Mutex<VideoState>>);

fn lock(s: &Arc<Mutex<VideoState>>) -> MutexGuard<'_, VideoState> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

/// Creates the three channels (control, data, geometry) and the handle the
/// session paints from. Each presentation gets a decoder from `factory`.
pub fn video(factory: H264Factory) -> (Vec<Box<dyn DynamicChannel>>, VideoHandle) {
    let state = Arc::new(Mutex::new(VideoState {
        factory,
        presentations: Vec::new(),
        geometries: HashMap::new(),
        restore: Vec::new(),
        notify: Vec::new(),
        control_open: false,
        desktop: (0, 0),
        stats: VideoStats::default(),
    }));
    let channels: Vec<Box<dyn DynamicChannel>> = vec![
        Box::new(ControlChannel(state.clone())),
        Box::new(DataChannel(state.clone())),
        Box::new(GeometryChannel(state.clone())),
    ];
    (channels, VideoHandle(state))
}

impl ControlChannel {
    fn flush(&self, out: &mut DvcOut) {
        for m in std::mem::take(&mut lock(&self.0).notify) {
            out.send(m);
        }
    }
}

impl DynamicChannel for ControlChannel {
    fn name(&self) -> &str {
        CONTROL_CHANNEL
    }

    fn opened(&mut self, _out: &mut DvcOut) -> Result<()> {
        trace!("video: control channel open");
        lock(&self.0).control_open = true;
        Ok(())
    }

    /// A malformed message closes the channel (3.1.5.1); a valid one with
    /// unexpected content is ignored.
    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let (kind, body) = pdu::split_header(msg)?;
        if kind != pdu::PACKET_TYPE_PRESENTATION_REQUEST {
            trace!("video control: packet type {kind} ignored");
            return Ok(());
        }
        let request = pdu::parse_presentation_request(body)?;
        let mut st = lock(&self.0);
        match request {
            PresentationRequest::Start(s) => st.start(s, out),
            PresentationRequest::Stop { presentation_id } => st.stop(presentation_id),
            PresentationRequest::Other {
                presentation_id,
                command,
            } => trace!("video {presentation_id}: command {command} ignored"),
        }
        drop(st);
        self.flush(out);
        Ok(())
    }

    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        self.flush(out);
        Ok(())
    }

    fn closed(&mut self) {
        trace!("video: control channel closed");
        let mut st = lock(&self.0);
        st.control_open = false;
        st.notify.clear();
        st.stop_all();
    }
}

impl DynamicChannel for DataChannel {
    fn name(&self) -> &str {
        DATA_CHANNEL
    }

    fn process(&mut self, msg: &[u8], _out: &mut DvcOut) -> Result<()> {
        lock(&self.0).data(msg, Instant::now())
    }

    fn closed(&mut self) {
        trace!("video: data channel closed");
        for p in &mut lock(&self.0).presentations {
            p.partial = None;
        }
    }
}

impl DynamicChannel for GeometryChannel {
    fn name(&self) -> &str {
        geometry::CHANNEL_NAME
    }

    fn process(&mut self, msg: &[u8], _out: &mut DvcOut) -> Result<()> {
        lock(&self.0).geometry(msg)
    }

    fn closed(&mut self) {
        trace!("video: geometry channel closed");
        lock(&self.0).clear_geometries();
    }
}
