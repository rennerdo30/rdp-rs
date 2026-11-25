//! What the statistics overlay shows (RDP-56): measured on the session
//! thread and sent to the UI once a second as [`Stats`].
//!
//! - Traffic: bytes in and out of the connection (TLS records included)
//!   per second.
//! - Round trip: a ping (ICMP echo) to the server once a second, on a
//!   thread of its own ([`Pinger`]). Where the server does not answer pings,
//!   Windows' smoothed TCP round-trip time on the connection's socket
//!   (`SIO_TCP_INFO`) instead, marked as such: it runs from sending until
//!   the server's TCP acknowledges, and a server delays acknowledging small
//!   packets such as keystrokes, so it reads far above the network's round
//!   trip (30 ms TCP on a 1 ms LAN). A gateway session has neither.
//! - Input to picture: from a key or mouse button press to the next change
//!   of the picture. It includes the round trip, the server's reaction and
//!   encoding, and Remora's decoding. A press that changes nothing on
//!   screen within two seconds is not counted.
//! - Picture: updates the session delivered per second; with the graphics
//!   pipeline also its frames per second, decoding time per frame and the
//!   last codec.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rdp::input::PTRFLAGS_DOWN;
use rdp::{ClientStats, InputEvent};

/// How often a [`Stats`] goes to the UI.
pub const INTERVAL: Duration = Duration::from_secs(1);
/// A press older than this without a picture change is not measured.
const INPUT_TIMEOUT: Duration = Duration::from_secs(2);
/// Input-to-picture samples kept for the average and the worst.
const SAMPLES: usize = 20;

/// One reading for the overlay.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    /// Kilobits per second received and sent since the last reading.
    pub in_kbps: f64,
    pub out_kbps: f64,
    /// The latest ping to the server, milliseconds.
    pub ping_ms: Option<f64>,
    /// Windows' smoothed TCP round-trip time, milliseconds (includes the
    /// server's delayed acknowledgements).
    pub tcp_rtt_ms: Option<f64>,
    /// Picture updates delivered per second.
    pub updates_per_s: f64,
    /// Graphics pipeline only.
    pub gfx: Option<GfxRate>,
    /// Input to picture over the last samples: average and worst, ms.
    pub input_ms: Option<(f64, f64)>,
    /// Window repaints of this session per second (the UI fills it in).
    pub repaints_per_s: f64,
    /// From a decoded update to the window showing it: average and worst
    /// since the last reading, ms (the UI fills it in).
    pub screen_ms: Option<(f64, f64)>,
    /// Whether the session runs over UDP (MS-RDPEMT) or TCP only.
    pub udp: rdp::multitransport::UdpStats,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GfxRate {
    pub fps: f64,
    /// Average decoding time per frame, milliseconds.
    pub decode_ms: f64,
    pub codec: Option<&'static str>,
}

/// Collects what one session does between readings.
pub struct Meter {
    since: Instant,
    prev: ClientStats,
    updates: u32,
    pressed: Option<Instant>,
    samples: VecDeque<Duration>,
}

impl Meter {
    pub fn new(now: Instant, stats: ClientStats) -> Meter {
        Meter {
            since: now,
            prev: stats,
            updates: 0,
            pressed: None,
            samples: VecDeque::with_capacity(SAMPLES),
        }
    }

    /// Input went to the server: a press starts a measurement unless one
    /// is running.
    pub fn input(&mut self, events: &[InputEvent], now: Instant) {
        if self.pressed.is_some_and(|t| now - t > INPUT_TIMEOUT) {
            self.pressed = None;
        }
        if self.pressed.is_none() && events.iter().any(is_press) {
            self.pressed = Some(now);
        }
    }

    /// The picture changed.
    pub fn picture(&mut self, now: Instant) {
        self.updates += 1;
        if let Some(t) = self.pressed.take() {
            let took = now - t;
            if took <= INPUT_TIMEOUT {
                if self.samples.len() == SAMPLES {
                    self.samples.pop_front();
                }
                self.samples.push_back(took);
            }
        }
    }

    /// Time for the next reading.
    pub fn due(&self, now: Instant) -> bool {
        now - self.since >= INTERVAL
    }

    /// The reading since the last one; starts the next interval.
    pub fn take(
        &mut self,
        now: Instant,
        cur: ClientStats,
        tcp_rtt: Option<Duration>,
        ping: Option<Duration>,
    ) -> Stats {
        let secs = (now - self.since).as_secs_f64().max(1e-3);
        let kbps = |a: u64, b: u64| a.saturating_sub(b) as f64 * 8.0 / 1000.0 / secs;
        let gfx = cur.gfx.map(|g| {
            let prev = self.prev.gfx.unwrap_or_default();
            let frames = g.frames.saturating_sub(prev.frames);
            let decode = g.decode.saturating_sub(prev.decode);
            GfxRate {
                fps: frames as f64 / secs,
                decode_ms: if frames == 0 {
                    0.0
                } else {
                    decode.as_secs_f64() * 1000.0 / frames as f64
                },
                codec: g.codec,
            }
        });
        let input_ms = (!self.samples.is_empty()).then(|| {
            let ms = |d: &Duration| d.as_secs_f64() * 1000.0;
            let sum: f64 = self.samples.iter().map(ms).sum();
            let worst = self.samples.iter().map(ms).fold(0.0, f64::max);
            (sum / self.samples.len() as f64, worst)
        });
        let stats = Stats {
            in_kbps: kbps(cur.bytes_in, self.prev.bytes_in),
            out_kbps: kbps(cur.bytes_out, self.prev.bytes_out),
            ping_ms: ping.map(|d| d.as_secs_f64() * 1000.0),
            tcp_rtt_ms: tcp_rtt.map(|d| d.as_secs_f64() * 1000.0),
            updates_per_s: self.updates as f64 / secs,
            gfx,
            input_ms,
            repaints_per_s: 0.0,
            screen_ms: None,
            udp: cur.udp,
        };
        self.since = now;
        self.prev = cur;
        self.updates = 0;
        stats
    }
}

/// The overlay's rows: (label, value). `server` is what the server's
/// network auto-detect measured, `desktop` the session's size.
pub fn rows(
    st: &Stats,
    server: Option<&str>,
    desktop: Option<(u16, u16)>,
) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    v.push((
        "Round trip",
        match (st.ping_ms, st.tcp_rtt_ms) {
            (Some(ms), _) => format!("{} (ping)", fmt_ms(ms)),
            (None, Some(ms)) => format!("TCP {} · no ping reply", fmt_ms(ms)),
            (None, None) => "not measured".into(),
        },
    ));
    v.push(("Transport", transport(&st.udp)));
    if let Some(s) = server {
        v.push(("Server measured", s.to_string()));
    }
    v.push((
        "Input → picture",
        st.input_ms.map_or_else(
            || "press a key to measure".into(),
            |(avg, worst)| format!("{} avg · {} worst", fmt_ms(avg), fmt_ms(worst)),
        ),
    ));
    match &st.gfx {
        Some(g) => {
            let codec = g.codec.map(|c| format!(" · {c}")).unwrap_or_default();
            v.push(("Graphics", format!("GFX{codec} · {:.0} fps", g.fps)));
            v.push(("Decoding", format!("{} per frame", fmt_ms(g.decode_ms))));
        }
        None => v.push(("Graphics", "Bitmap".into())),
    }
    if let Some((avg, worst)) = st.screen_ms {
        v.push((
            "Update → screen",
            format!("{} avg · {} worst", fmt_ms(avg), fmt_ms(worst)),
        ));
    }
    v.push((
        "Updates",
        format!(
            "{:.0}/s · repaints {:.0}/s",
            st.updates_per_s, st.repaints_per_s
        ),
    ));
    v.push(("Received", fmt_rate(st.in_kbps)));
    v.push(("Sent", fmt_rate(st.out_kbps)));
    if let Some((w, h)) = desktop {
        v.push(("Desktop", format!("{w} × {h}")));
    }
    v
}

/// The Transport row: UDP with its channels and round trip once the tunnel
/// is up, else TCP and what became of UDP.
fn transport(u: &rdp::multitransport::UdpStats) -> String {
    use rdp::multitransport::UdpState;
    match u.state {
        UdpState::Off => "TCP".into(),
        UdpState::Offered => "TCP · UDP offered, not used".into(),
        UdpState::Connecting => "TCP · UDP connecting".into(),
        UdpState::Failed => "TCP · UDP failed".into(),
        UdpState::Active => {
            let rtt = u
                .rtt
                .map(|d| format!(" · {}", fmt_ms(d.as_secs_f64() * 1000.0)))
                .unwrap_or_default();
            let ch = if u.channels == 1 {
                "channel"
            } else {
                "channels"
            };
            format!("UDP · {} {ch}{rtt}", u.channels)
        }
    }
}

fn fmt_ms(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1} ms")
    } else {
        format!("{ms:.0} ms")
    }
}

fn fmt_rate(kbps: f64) -> String {
    if kbps >= 1000.0 {
        format!("{:.1} Mbit/s", kbps / 1000.0)
    } else {
        format!("{kbps:.0} kbit/s")
    }
}

/// Pings a server once a second on a thread of its own, while it lives.
pub struct Pinger {
    /// The latest round trip in microseconds; `u32::MAX` for none.
    rtt: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
}

impl Pinger {
    /// IPv4 servers only; others get no ping.
    pub fn start(addr: IpAddr) -> Pinger {
        let rtt = Arc::new(AtomicU32::new(u32::MAX));
        let stop = Arc::new(AtomicBool::new(false));
        if let IpAddr::V4(v4) = addr {
            let (rtt, stop) = (rtt.clone(), stop.clone());
            let _ = std::thread::Builder::new()
                .name("rdp-ping".into())
                .spawn(move || ping_loop(v4, &rtt, &stop));
        }
        Pinger { rtt, stop }
    }

    pub fn rtt(&self) -> Option<Duration> {
        match self.rtt.load(Ordering::Relaxed) {
            u32::MAX => None,
            us => Some(Duration::from_micros(us as u64)),
        }
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// One echo a second (1 s timeout). The last reply stays shown through two
/// lost pings; a third clears it.
#[cfg(windows)]
fn ping_loop(addr: std::net::Ipv4Addr, rtt: &AtomicU32, stop: &AtomicBool) {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };
    // SAFETY: an ICMP handle this thread owns and closes.
    let h = unsafe { IcmpCreateFile() };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return;
    }
    let dest = u32::from_ne_bytes(addr.octets());
    let data = [0x52u8; 32];
    // Room for one reply with its data, and an ICMP error.
    let mut reply = vec![0u8; size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + 64];
    let mut lost = 0;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        // SAFETY: valid handle, request and reply buffers of the sizes given.
        let n = unsafe {
            IcmpSendEcho(
                h,
                dest,
                data.as_ptr().cast(),
                data.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                1000,
            )
        };
        let took = started.elapsed();
        // SAFETY: with n > 0 the buffer starts with an ICMP_ECHO_REPLY;
        // read unaligned from the byte buffer.
        let ok = n > 0
            && unsafe { std::ptr::read_unaligned(reply.as_ptr().cast::<ICMP_ECHO_REPLY>()) }.Status
                == 0;
        if ok {
            lost = 0;
            let us = took.as_micros().min(u32::MAX as u128 - 1) as u32;
            rtt.store(us, Ordering::Relaxed);
        } else {
            lost += 1;
            if lost >= 3 {
                rtt.store(u32::MAX, Ordering::Relaxed);
            }
        }
        // The rest of the second, waking up for the stop flag.
        let next = started + INTERVAL;
        while !stop.load(Ordering::Relaxed) && Instant::now() < next {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // SAFETY: closing the handle opened above.
    unsafe { IcmpCloseHandle(h) };
}

#[cfg(not(windows))]
fn ping_loop(_addr: std::net::Ipv4Addr, _rtt: &AtomicU32, _stop: &AtomicBool) {}

/// A key or mouse button going down (not a release, move or wheel turn).
fn is_press(ev: &InputEvent) -> bool {
    match *ev {
        InputEvent::Key { down, .. } | InputEvent::Unicode { down, .. } => down,
        InputEvent::Mouse { flags, .. } => flags & PTRFLAGS_DOWN != 0,
        InputEvent::Sync { .. } => false,
    }
}

/// Windows' smoothed round-trip time of a TCP connection (`SIO_TCP_INFO`,
/// Windows 10 1703 and later).
#[cfg(windows)]
pub fn tcp_rtt(sock: &std::net::TcpStream) -> Option<Duration> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_TCP_INFO, TCP_INFO_v0, WSAIoctl};
    let version: u32 = 0;
    let mut info = TCP_INFO_v0::default();
    let mut got = 0u32;
    // SAFETY: a synchronous WSAIoctl on a socket this stream owns, with
    // input and output buffers of the sizes given.
    let r = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_TCP_INFO,
            (&raw const version).cast(),
            size_of::<u32>() as u32,
            (&raw mut info).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut got,
            std::ptr::null_mut(),
            None,
        )
    };
    (r == 0 && got as usize >= size_of::<TCP_INFO_v0>())
        .then(|| Duration::from_micros(info.RttUs as u64))
}

#[cfg(not(windows))]
pub fn tcp_rtt(_sock: &std::net::TcpStream) -> Option<Duration> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::GfxStats;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn key(down: bool) -> InputEvent {
        InputEvent::Key {
            scancode: 0x1E,
            extended: false,
            down,
        }
    }

    #[test]
    fn rates_come_from_the_difference_of_two_readings() {
        let t0 = Instant::now();
        let mut m = Meter::new(
            t0,
            ClientStats {
                bytes_in: 1_000,
                bytes_out: 100,
                gfx: Some(GfxStats {
                    frames: 10,
                    decode: ms(20),
                    codec: Some("AVC420"),
                }),
                ..ClientStats::default()
            },
        );
        m.picture(t0 + ms(100));
        m.picture(t0 + ms(200));
        assert!(!m.due(t0 + ms(999)));
        assert!(m.due(t0 + ms(1000)));
        let s = m.take(
            t0 + ms(1000),
            ClientStats {
                bytes_in: 126_000,
                bytes_out: 1_100,
                gfx: Some(GfxStats {
                    frames: 70,
                    decode: ms(140),
                    codec: Some("AVC444"),
                }),
                ..ClientStats::default()
            },
            Some(Duration::from_micros(3_500)),
            Some(Duration::from_micros(1_250)),
        );
        assert_eq!(s.in_kbps, 1000.0);
        assert_eq!(s.out_kbps, 8.0);
        assert_eq!(s.tcp_rtt_ms, Some(3.5));
        assert_eq!(s.ping_ms, Some(1.25));
        assert_eq!(s.updates_per_s, 2.0);
        let g = s.gfx.expect("gfx");
        assert_eq!(g.fps, 60.0);
        assert_eq!(g.decode_ms, 2.0);
        assert_eq!(g.codec, Some("AVC444"));
        assert_eq!(s.input_ms, None);
    }

    #[cfg(windows)]
    #[test]
    fn pinger_measures_loopback() {
        let p = Pinger::start(IpAddr::from([127, 0, 0, 1]));
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.rtt().is_none() && Instant::now() < deadline {
            std::thread::sleep(ms(20));
        }
        let rtt = p.rtt().expect("a reply from 127.0.0.1");
        assert!(rtt < ms(100), "{rtt:?}");
        assert!(
            Pinger::start(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]))
                .rtt()
                .is_none()
        );
    }

    #[test]
    fn rows_name_what_was_measured() {
        let st = Stats {
            in_kbps: 12_345.0,
            out_kbps: 41.2,
            ping_ms: Some(1.04),
            tcp_rtt_ms: Some(31.0),
            updates_per_s: 58.0,
            gfx: Some(GfxRate {
                fps: 60.0,
                decode_ms: 2.06,
                codec: Some("AVC420"),
            }),
            input_ms: Some((28.4, 41.0)),
            repaints_per_s: 57.6,
            screen_ms: Some((2.4, 7.0)),
            udp: Default::default(),
        };
        let r = rows(&st, Some("RTT 4 ms"), Some((1828, 1232)));
        let get = |k: &str| r.iter().find(|(l, _)| *l == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Round trip"), Some("1.0 ms (ping)"));
        assert_eq!(get("Server measured"), Some("RTT 4 ms"));
        assert_eq!(get("Input → picture"), Some("28 ms avg · 41 ms worst"));
        assert_eq!(get("Graphics"), Some("GFX · AVC420 · 60 fps"));
        assert_eq!(get("Decoding"), Some("2.1 ms per frame"));
        assert_eq!(get("Update → screen"), Some("2.4 ms avg · 7.0 ms worst"));
        assert_eq!(get("Updates"), Some("58/s · repaints 58/s"));
        assert_eq!(get("Received"), Some("12.3 Mbit/s"));
        assert_eq!(get("Sent"), Some("41 kbit/s"));
        assert_eq!(get("Desktop"), Some("1828 × 1232"));
        let plain = rows(&Stats::default(), None, None);
        let get = |k: &str| plain.iter().find(|(l, _)| *l == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Round trip"), Some("not measured"));
        let tcp_only = Stats {
            tcp_rtt_ms: Some(31.0),
            ..Stats::default()
        };
        assert_eq!(
            rows(&tcp_only, None, None)[0].1,
            "TCP 31 ms · no ping reply"
        );
        assert_eq!(get("Graphics"), Some("Bitmap"));
        assert_eq!(get("Input → picture"), Some("press a key to measure"));
        assert_eq!(get("Server measured"), None);
        assert_eq!(get("Transport"), Some("TCP"));
    }

    #[test]
    fn transport_row_says_whether_udp_is_in_use() {
        use rdp::multitransport::{UdpState, UdpStats};
        let row = |udp: UdpStats| {
            let st = Stats {
                udp,
                ..Stats::default()
            };
            rows(&st, None, None)
                .into_iter()
                .find(|(l, _)| *l == "Transport")
                .unwrap()
                .1
        };
        let s = |state| UdpStats {
            state,
            ..UdpStats::default()
        };
        assert_eq!(row(s(UdpState::Off)), "TCP");
        assert_eq!(row(s(UdpState::Connecting)), "TCP · UDP connecting");
        assert_eq!(row(s(UdpState::Failed)), "TCP · UDP failed");
        let active = UdpStats {
            state: UdpState::Active,
            channels: 3,
            rtt: Some(ms(12)),
            ..UdpStats::default()
        };
        assert_eq!(row(active), "UDP · 3 channels · 12 ms");
        // The reading carries the client's UDP state through.
        let t0 = Instant::now();
        let mut m = Meter::new(t0, ClientStats::default());
        let cur = ClientStats {
            udp: active,
            ..ClientStats::default()
        };
        assert_eq!(m.take(t0 + ms(1000), cur, None, None).udp, active);
    }

    #[test]
    fn input_to_picture_counts_presses_that_change_the_picture() {
        let t0 = Instant::now();
        let mut m = Meter::new(t0, ClientStats::default());
        // A release or a move starts nothing.
        m.input(&[key(false), InputEvent::mouse_move(1, 1)], t0);
        m.picture(t0 + ms(5));
        // A press, then a second press before the picture changed: timed
        // from the first.
        m.input(&[key(true)], t0 + ms(10));
        m.input(&[key(true)], t0 + ms(20));
        m.picture(t0 + ms(40));
        // A click.
        m.input(
            &[InputEvent::Mouse {
                flags: PTRFLAGS_DOWN | rdp::input::PTRFLAGS_BUTTON1,
                x: 1,
                y: 1,
            }],
            t0 + ms(100),
        );
        m.picture(t0 + ms(150));
        // A press that changed nothing for too long is dropped.
        m.input(&[key(true)], t0 + ms(200));
        m.input(&[key(true)], t0 + ms(200) + INPUT_TIMEOUT + ms(1));
        m.picture(t0 + ms(200) + INPUT_TIMEOUT + ms(11));
        let s = m.take(t0 + ms(3000), ClientStats::default(), None, None);
        assert_eq!(s.input_ms, Some(((30.0 + 50.0 + 10.0) / 3.0, 50.0)));
        // Samples carry over to the next reading.
        let s = m.take(t0 + ms(4000), ClientStats::default(), None, None);
        assert!(s.input_ms.is_some());
        assert_eq!(s.gfx, None);
    }
}
