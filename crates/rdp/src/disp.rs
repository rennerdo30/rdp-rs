//! Display Control virtual channel, client side (MS-RDPEDISP).
//!
//! Lets the client change the remote desktop size without reconnecting. The
//! UI calls [`DisplayHandle::request_resize`]; the channel sends one
//! DISPLAYCONTROL_MONITOR_LAYOUT_PDU once the server's capabilities arrived,
//! at most one per [`RATE_LIMIT`]. The server answers with a Deactivate All
//! and a new Demand Active at the new size (MS-RDPEDISP 3.2.5.1.1), which the
//! session loop already handles.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::cursor::{Put, Reader};
use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::{Result, proto};
use crate::trace;

/// Dynamic virtual channel name (MS-RDPEDISP 2.1).
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::DisplayControl";

/// DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT (MS-RDPEDISP 2.2.1.1).
pub const PDU_TYPE_MONITOR_LAYOUT: u32 = 0x0000_0002;
/// DISPLAYCONTROL_PDU_TYPE_CAPS (MS-RDPEDISP 2.2.1.1).
pub const PDU_TYPE_CAPS: u32 = 0x0000_0005;
/// DISPLAYCONTROL_MONITOR_PRIMARY (MS-RDPEDISP 2.2.2.2.1).
pub const MONITOR_PRIMARY: u32 = 0x0000_0001;
/// Size of one DISPLAYCONTROL_MONITOR_LAYOUT entry (MS-RDPEDISP 2.2.2.2).
pub const MONITOR_LAYOUT_SIZE: u32 = 40;

/// Monitor width and height bounds (MS-RDPEDISP 2.2.2.2.1).
pub const MIN_SIZE: u32 = 200;
pub const MAX_SIZE: u32 = 8192;

/// Minimum gap between two layout PDUs.
pub const RATE_LIMIT: Duration = Duration::from_millis(250);

/// Time source; injectable for tests.
pub type Clock = Box<dyn Fn() -> Instant + Send>;

/// DISPLAYCONTROL_CAPS_PDU contents (MS-RDPEDISP 2.2.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayCaps {
    pub max_num_monitors: u32,
    pub max_monitor_area_factor_a: u32,
    pub max_monitor_area_factor_b: u32,
}

/// Parses a DISPLAYCONTROL_CAPS_PDU (MS-RDPEDISP 2.2.2.1), header included.
pub fn parse_caps(msg: &[u8]) -> Result<DisplayCaps> {
    let mut r = Reader::new(msg);
    let ty = r.u32()?;
    let len = r.u32()?;
    if ty != PDU_TYPE_CAPS {
        return proto(format!("display control: type {ty} is not caps"));
    }
    if len < 20 {
        return proto(format!("display control caps length {len}"));
    }
    Ok(DisplayCaps {
        max_num_monitors: r.u32()?,
        max_monitor_area_factor_a: r.u32()?,
        max_monitor_area_factor_b: r.u32()?,
    })
}

/// Clamps a requested size to what the protocol and the server allow:
/// width and height within 200..=8192, width even (MS-RDPEDISP 2.2.2.2.1),
/// and the area within MaxMonitorAreaFactorA × MaxMonitorAreaFactorB ×
/// MaxNumMonitors (MS-RDPEDISP 2.2.2.1), keeping the aspect ratio when it
/// shrinks. The minimum size wins over an area limit below 200 × 200.
pub fn clamp_size(width: u32, height: u32, caps: Option<&DisplayCaps>) -> (u32, u32) {
    let mut w = width.clamp(MIN_SIZE, MAX_SIZE);
    let mut h = height.clamp(MIN_SIZE, MAX_SIZE);
    if let Some(c) = caps {
        let (a, b) = (c.max_monitor_area_factor_a, c.max_monitor_area_factor_b);
        if a > 0 && b > 0 {
            let limit = a as u64 * b as u64 * c.max_num_monitors.max(1) as u64;
            let area = w as u64 * h as u64;
            if area > limit {
                let s = (limit as f64 / area as f64).sqrt();
                w = ((w as f64 * s) as u32).max(MIN_SIZE);
                h = ((h as f64 * s) as u32).max(MIN_SIZE);
                // Float rounding fix-up; bounded by the 8192 range.
                while (w as u64 * h as u64) > limit && (w > MIN_SIZE || h > MIN_SIZE) {
                    if (w >= h && w > MIN_SIZE) || h <= MIN_SIZE {
                        w -= 1;
                    } else {
                        h -= 1;
                    }
                }
            }
        }
    }
    (w & !1, h)
}

/// DISPLAYCONTROL_MONITOR_LAYOUT_PDU (MS-RDPEDISP 2.2.2.2) with one primary
/// monitor at (0,0): no physical size, landscape, 100 % scale.
/// DeviceScaleFactor for a desktop scale: the spec allows only 100, 140 and
/// 180 (MS-RDPEDISP 2.2.2.2.1). Thresholds as Windows clients use them, so
/// 125 % stays at 100.
pub fn device_scale(desktop_scale: u32) -> u32 {
    match desktop_scale {
        0..140 => 100,
        140..180 => 140,
        _ => 180,
    }
}

/// One-monitor layout. `scale` is the desktop scale in percent (100..=500,
/// like Windows' "Scale" setting); the remote session renders its UI that much
/// larger so it looks the same size as on a local high-DPI screen.
pub fn monitor_layout_pdu(width: u32, height: u32, scale: u32) -> Vec<u8> {
    let scale = scale.clamp(100, 500);
    let len = 8 + 8 + MONITOR_LAYOUT_SIZE;
    let mut v = Vec::with_capacity(len as usize);
    v.put_u32(PDU_TYPE_MONITOR_LAYOUT);
    v.put_u32(len);
    v.put_u32(MONITOR_LAYOUT_SIZE);
    v.put_u32(1); // NumMonitors
    // DISPLAYCONTROL_MONITOR_LAYOUT (MS-RDPEDISP 2.2.2.2.1)
    v.put_u32(MONITOR_PRIMARY);
    v.put_u32(0); // Left
    v.put_u32(0); // Top
    v.put_u32(width);
    v.put_u32(height);
    v.put_u32(0); // PhysicalWidth
    v.put_u32(0); // PhysicalHeight
    v.put_u32(0); // Orientation: ORIENTATION_LANDSCAPE
    v.put_u32(scale); // DesktopScaleFactor
    v.put_u32(device_scale(scale)); // DeviceScaleFactor
    v
}

const PENDING: u64 = 1 << 63;

struct Shared {
    /// `PENDING | width << 32 | height`, or 0 when nothing is pending.
    request: AtomicU64,
    ready: AtomicBool,
    /// Desktop scale in percent for the next layout.
    scale: std::sync::atomic::AtomicU32,
    /// The last requested size (same packing, without PENDING), for re-sends.
    last_size: AtomicU64,
}

/// UI side of the Display Control channel.
#[derive(Clone)]
pub struct DisplayHandle {
    shared: Arc<Shared>,
}

impl DisplayHandle {
    /// Asks for a new remote size. Only the latest request is kept.
    pub fn request_resize(&self, width: u32, height: u32) {
        let size = ((width.min(0x7FFF_FFFF) as u64) << 32) | height as u64;
        self.shared.last_size.store(size, Ordering::Release);
        self.shared.request.store(PENDING | size, Ordering::Release);
    }

    /// Sets the desktop scale in percent (100..=500) and re-sends the current
    /// size with it, so the session re-renders at once (no reconnect).
    pub fn set_scale(&self, percent: u32) {
        let percent = percent.clamp(100, 500);
        if self.shared.scale.swap(percent, Ordering::AcqRel) != percent {
            let size = self.shared.last_size.load(Ordering::Acquire);
            if size != 0 {
                self.shared.request.store(PENDING | size, Ordering::Release);
            }
        }
    }

    /// True once the server sent its capabilities, so resizes take effect.
    pub fn ready(&self) -> bool {
        self.shared.ready.load(Ordering::Acquire)
    }
}

/// The Display Control dynamic channel handler.
pub struct DisplayControl {
    shared: Arc<Shared>,
    caps: Option<DisplayCaps>,
    last_sent: Option<Instant>,
    clock: Clock,
}

/// Creates the channel and the handle the UI keeps.
pub fn display_control() -> (DisplayControl, DisplayHandle) {
    display_control_with_clock(Box::new(Instant::now))
}

/// Like [`display_control`] with an injected time source.
pub fn display_control_with_clock(clock: Clock) -> (DisplayControl, DisplayHandle) {
    let shared = Arc::new(Shared {
        request: AtomicU64::new(0),
        ready: AtomicBool::new(false),
        scale: std::sync::atomic::AtomicU32::new(100),
        last_size: AtomicU64::new(0),
    });
    let ch = DisplayControl {
        shared: shared.clone(),
        caps: None,
        last_sent: None,
        clock,
    };
    (ch, DisplayHandle { shared })
}

impl DisplayControl {
    pub fn caps(&self) -> Option<DisplayCaps> {
        self.caps
    }
}

impl DynamicChannel for DisplayControl {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    fn process(&mut self, msg: &[u8], _out: &mut DvcOut) -> Result<()> {
        // DISPLAYCONTROL_HEADER (MS-RDPEDISP 2.2.1.1).
        let mut r = Reader::new(msg);
        let ty = r.u32()?;
        let len = r.u32()?;
        if (len as usize) < 8 || len as usize > msg.len() {
            return proto(format!("display control PDU length {len}"));
        }
        match ty {
            PDU_TYPE_CAPS => {
                let caps = parse_caps(&msg[..len as usize])?;
                trace!("display control caps: {caps:?}");
                self.caps = Some(caps);
                self.shared.ready.store(true, Ordering::Release);
            }
            _ => trace!("display control PDU type {ty} ignored"),
        }
        Ok(())
    }

    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        if self.caps.is_none() || self.shared.request.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        let now = (self.clock)();
        if let Some(t) = self.last_sent
            && now.saturating_duration_since(t) < RATE_LIMIT
        {
            return Ok(());
        }
        let v = self.shared.request.swap(0, Ordering::AcqRel);
        if v == 0 {
            return Ok(());
        }
        let (w, h) = (((v >> 32) & 0x7FFF_FFFF) as u32, v as u32);
        let (w, h) = clamp_size(w, h, self.caps.as_ref());
        let scale = self.shared.scale.load(Ordering::Acquire);
        trace!("display control layout {w}x{h} at {scale} %");
        out.send(monitor_layout_pdu(w, h, scale));
        self.last_sent = Some(now);
        Ok(())
    }

    fn closed(&mut self) {
        self.caps = None;
        self.shared.ready.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{ChannelOut, StaticChannel};
    use crate::dvc::Drdynvc;
    use std::sync::Mutex;

    /// DISPLAYCONTROL_CAPS_PDU: 16 monitors, factors 8192 x 8192.
    const CAPS: [u8; 20] = [
        0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00,
    ];

    fn caps(n: u32, a: u32, b: u32) -> DisplayCaps {
        DisplayCaps {
            max_num_monitors: n,
            max_monitor_area_factor_a: a,
            max_monitor_area_factor_b: b,
        }
    }

    fn test_clock() -> (Clock, Arc<Mutex<Instant>>) {
        let t = Arc::new(Mutex::new(Instant::now()));
        let t2 = t.clone();
        (Box::new(move || *t2.lock().unwrap()), t)
    }

    fn advance(t: &Mutex<Instant>, ms: u64) {
        *t.lock().unwrap() += Duration::from_millis(ms);
    }

    fn tick(ch: &mut DisplayControl) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        ch.tick(&mut out).unwrap();
        out.take()
    }

    fn size_of(pdu: &[u8]) -> (u32, u32) {
        let w = u32::from_le_bytes(pdu[28..32].try_into().unwrap());
        let h = u32::from_le_bytes(pdu[32..36].try_into().unwrap());
        (w, h)
    }

    #[test]
    fn parses_caps() {
        assert_eq!(parse_caps(&CAPS).unwrap(), caps(16, 8192, 8192));
        assert!(parse_caps(&CAPS[..19]).is_err());
        let mut short = CAPS;
        short[4] = 0x10;
        assert!(parse_caps(&short).is_err());
    }

    #[test]
    fn layout_pdu_bytes() {
        let expect: [u8; 56] = [
            0x02, 0, 0, 0, 0x38, 0, 0, 0, // header: MONITOR_LAYOUT, 56 bytes
            0x28, 0, 0, 0, 0x01, 0, 0, 0, // MonitorLayoutSize 40, NumMonitors 1
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // primary at (0,0)
            0x80, 0x07, 0, 0, 0x38, 0x04, 0, 0, // 1920 x 1080
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // physical size, orientation
            0x64, 0, 0, 0, 0x64, 0, 0, 0, // scale factors 100
        ];
        assert_eq!(monitor_layout_pdu(1920, 1080, 100), expect);
    }

    #[test]
    fn clamping() {
        assert_eq!(clamp_size(1001, 701, None), (1000, 701));
        assert_eq!(clamp_size(100, 50, None), (200, 200));
        assert_eq!(clamp_size(10000, 9000, None), (8192, 8192));
        assert_eq!(clamp_size(8193, 8191, None), (8192, 8191));
        // Area limit 1920 x 1080 x 1: 3840 x 2160 halves exactly.
        let c = caps(1, 1920, 1080);
        assert_eq!(clamp_size(3840, 2160, Some(&c)), (1920, 1080));
        assert_eq!(clamp_size(1920, 1080, Some(&c)), (1920, 1080));
        // Odd result after scaling is made even and stays within the area.
        // Scale sqrt(2073600 / 6002000) = 0.5878: 1763 x 1175, then even.
        let (w, h) = clamp_size(3001, 2000, Some(&c));
        assert_eq!((w, h), (1762, 1175));
        assert!(w as u64 * h as u64 <= 1920 * 1080);
        // The area scales with MaxNumMonitors.
        assert_eq!(
            clamp_size(3840, 2160, Some(&caps(4, 1920, 1080))),
            (3840, 2160)
        );
        // Zero factors mean no area limit; the minimum wins over a tiny area.
        assert_eq!(clamp_size(3840, 2160, Some(&caps(1, 0, 0))), (3840, 2160));
        assert_eq!(clamp_size(1000, 1000, Some(&caps(1, 10, 10))), (200, 200));
    }

    #[test]
    fn waits_for_caps_then_sends_layout() {
        let (clock, _t) = test_clock();
        let (mut ch, handle) = display_control_with_clock(clock);
        handle.request_resize(1921, 1080);
        assert!(!handle.ready());
        assert!(tick(&mut ch).is_empty());
        ch.process(&CAPS, &mut DvcOut::default()).unwrap();
        assert!(handle.ready());
        let sent = tick(&mut ch);
        assert_eq!(sent, vec![monitor_layout_pdu(1920, 1080, 100)]);
        assert!(tick(&mut ch).is_empty());
        ch.closed();
        assert!(!handle.ready());
    }

    #[test]
    fn rate_limit_and_latest_request_wins() {
        let (clock, t) = test_clock();
        let (mut ch, handle) = display_control_with_clock(clock);
        ch.process(&CAPS, &mut DvcOut::default()).unwrap();
        handle.request_resize(1000, 800);
        assert_eq!(size_of(&tick(&mut ch)[0]), (1000, 800));
        handle.request_resize(1200, 900);
        advance(&t, 100);
        assert!(tick(&mut ch).is_empty());
        handle.request_resize(1300, 900);
        advance(&t, 149);
        assert!(tick(&mut ch).is_empty(), "249 ms after the last layout");
        advance(&t, 1);
        let sent = tick(&mut ch);
        assert_eq!(sent.len(), 1);
        assert_eq!(size_of(&sent[0]), (1300, 900));
        advance(&t, 1000);
        assert!(tick(&mut ch).is_empty());
    }

    #[test]
    fn handle_is_clone_send_sync() {
        fn check<T: Clone + Send + Sync>() {}
        check::<DisplayHandle>();
    }

    #[test]
    fn end_to_end_through_drdynvc() {
        let (clock, _t) = test_clock();
        let (ch, handle) = display_control_with_clock(clock);
        let mut d = Drdynvc::new(vec![Box::new(ch)]);
        let mut out = ChannelOut::default();
        d.process(&[0x50, 0x00, 0x01, 0x00], &mut out).unwrap();
        let mut req = vec![0x10, 0x04];
        req.extend_from_slice(CHANNEL_NAME.as_bytes());
        req.push(0);
        d.process(&req, &mut out).unwrap();
        let mut data = vec![0x30, 0x04];
        data.extend_from_slice(&CAPS);
        d.process(&data, &mut out).unwrap();
        assert_eq!(
            out.take(),
            vec![vec![0x50, 0x00, 0x01, 0x00], vec![0x10, 0x04, 0, 0, 0, 0]]
        );
        handle.request_resize(1280, 720);
        d.tick(&mut out).unwrap();
        let mut expect = vec![0x30, 0x04];
        expect.extend_from_slice(&monitor_layout_pdu(1280, 720, 100));
        assert_eq!(out.take(), vec![expect]);
    }

    #[test]
    fn scale_goes_into_the_layout_and_resends_the_size() {
        let pdu = monitor_layout_pdu(1920, 1080, 150);
        // DesktopScaleFactor and DeviceScaleFactor are the last two fields.
        assert_eq!(&pdu[pdu.len() - 8..], &[150, 0, 0, 0, 140, 0, 0, 0]);
        assert_eq!(
            &monitor_layout_pdu(800, 600, 50)[48..52],
            &[100, 0, 0, 0],
            "clamped to 100"
        );
        assert_eq!(
            (
                device_scale(100),
                device_scale(125),
                device_scale(150),
                device_scale(200)
            ),
            (100, 100, 140, 180)
        );
        let (_ch, h) = display_control();
        h.request_resize(1000, 800);
        h.shared.request.store(0, Ordering::Release); // pretend it was sent
        h.set_scale(150);
        assert_ne!(
            h.shared.request.load(Ordering::Acquire),
            0,
            "scale change re-sends the size"
        );
        h.shared.request.store(0, Ordering::Release);
        h.set_scale(150);
        assert_eq!(
            h.shared.request.load(Ordering::Acquire),
            0,
            "same scale: no re-send"
        );
    }
}
