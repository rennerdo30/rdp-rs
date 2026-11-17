//! The latency meter (RDP-67): how long a change on the server takes to
//! reach Remora's picture.
//!
//! The server helper paints a small square in a colour Remora names
//! (`LatencyMark`). Remora notes the time it asked, and the session worker
//! notes when a decoded frame first shows that colour at the square
//! ([`Probe`]). The difference is the full round trip on one clock: the
//! request to the server, the helper painting, the server's capture and
//! encoder, the network, and Remora's decoder. The helper's answer
//! (`LatencyShown`) gives the channel's own round trip for comparison.
//!
//! The same meter can time any picture path, so the server's RDP picture
//! today and a helper stream later are measured the same way.

use std::time::{Duration, Instant};

use rdp::Framebuffer;

/// Marks per measurement.
pub const ROUNDS: usize = 20;
/// The colours the marker cycles through: each differs strongly from the
/// one before, in every channel a codec keeps.
const COLOURS: [u32; 4] = [0x00ff_00ff, 0x0000_ff00, 0x0000_00ff, 0x00ff_ff00];
/// Per channel, how far a decoded pixel may be from the colour asked for
/// (codecs round, and 4:2:0 chroma bleeds into small areas).
const TOLERANCE: i32 = 56;
/// How long one mark may take before it counts as lost.
const ROUND_LIMIT: Duration = Duration::from_secs(2);
/// How long the first mark may take to show (the helper starts its window,
/// the picture settles).
const SETUP_LIMIT: Duration = Duration::from_secs(6);

/// Where the helper painted its square, in picture pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Square {
    pub x: usize,
    pub y: usize,
    pub size: usize,
}

/// Whether the decoded picture shows `rgb` at the square: five points well
/// inside it (the edges blur under a codec) must all match.
pub fn shows(fb: &Framebuffer, sq: Square, rgb: u32) -> bool {
    if sq.size < 8 || sq.x + sq.size > fb.width || sq.y + sq.size > fb.height {
        return false;
    }
    let q = sq.size / 4;
    let points = [
        (sq.size / 2, sq.size / 2),
        (q, q),
        (sq.size - q, q),
        (q, sq.size - q),
        (sq.size - q, sq.size - q),
    ];
    let want = [(rgb >> 16) & 0xff, (rgb >> 8) & 0xff, rgb & 0xff];
    points.iter().all(|&(dx, dy)| {
        let p = fb.pixels[(sq.y + dy) * fb.width + sq.x + dx];
        let got = [(p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff];
        got.iter()
            .zip(want)
            .all(|(&g, w)| (g as i32 - w as i32).abs() <= TOLERANCE)
    })
}

/// Watches the decoded picture for one colour at one square. It lives in
/// the session's shared state; the worker calls [`Probe::check`] after
/// every update, so the time is when the frame was decoded, not when the
/// window drew it.
#[derive(Default)]
pub struct Probe {
    watch: Option<(u32, Square, u32)>,
    hit: Option<(u32, Instant)>,
}

impl Probe {
    pub fn arm(&mut self, generation: u32, sq: Square, rgb: u32) {
        self.watch = Some((generation, sq, rgb));
        self.hit = None;
    }

    pub fn disarm(&mut self) {
        self.watch = None;
        self.hit = None;
    }

    pub fn check(&mut self, fb: &Framebuffer, now: Instant) {
        if let Some((generation, sq, rgb)) = self.watch
            && shows(fb, sq, rgb)
        {
            self.hit = Some((generation, now));
            self.watch = None;
        }
    }

    /// When the colour armed under `generation` was first decoded.
    pub fn take_hit(&mut self, generation: u32) -> Option<Instant> {
        match self.hit {
            Some((g, t)) if g == generation => {
                self.hit = None;
                Some(t)
            }
            _ => None,
        }
    }
}

/// What the meter needs from the connection.
pub trait Link {
    /// Asks the helper to paint `rgb`; the mark's id, or None when the
    /// helper cannot be asked.
    fn mark(&mut self, rgb: u32) -> Option<u32>;
    /// Asks the helper to remove the marker.
    fn end(&mut self);
    /// The session's probe, under its lock.
    fn probe(&mut self, f: &mut dyn FnMut(&mut Probe));
}

/// One measurement's result.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// Request to decoded picture, per mark, sorted.
    pub picture: Vec<Duration>,
    /// Request to the helper's answer, per mark, sorted.
    pub channel: Vec<Duration>,
    pub lost: usize,
}

fn pct(v: &[Duration], p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

impl Report {
    pub fn median(&self) -> Duration {
        pct(&self.picture, 0.5)
    }

    /// One line for the panel and the log.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{:.0} ms to the picture (median of {}, {:.0}–{:.0} ms, 95% under {:.0} ms); helper channel {:.0} ms",
            ms(self.median()),
            self.picture.len(),
            ms(pct(&self.picture, 0.0)),
            ms(pct(&self.picture, 1.0)),
            ms(pct(&self.picture, 0.95)),
            ms(pct(&self.channel, 0.5)),
        );
        if self.lost > 0 {
            s += &format!("; {} marks never showed", self.lost);
        }
        s
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    /// The first mark is out; waiting for the helper to say where it is.
    Setup {
        rid: u32,
        since: Instant,
    },
    /// The square is known; waiting for its first colour in the picture.
    Settle {
        since: Instant,
    },
    /// A pause before the next mark (random, so marks do not lock onto the
    /// server's frame clock).
    Gap {
        until: Instant,
    },
    /// A mark is out.
    Round {
        rid: u32,
        sent: Instant,
        answered: Option<Duration>,
    },
    Done,
}

/// One measurement: drive it with [`Run::poll`] (often: every few ms) and
/// [`Run::shown`] for every `LatencyShown`.
pub struct Run {
    state: State,
    square: Option<Square>,
    generation: u32,
    colour: usize,
    rounds: usize,
    picture: Vec<Duration>,
    channel: Vec<Duration>,
    lost: usize,
    seed: u64,
}

impl Run {
    /// Starts: the first mark goes out now. Err when the helper cannot be
    /// asked (not paired, or the meter not accepted).
    pub fn start(link: &mut dyn Link, now: Instant) -> Result<Run, String> {
        let rid = link
            .mark(COLOURS[0])
            .ok_or("the server helper is not connected, or too old for the latency meter")?;
        Ok(Run {
            state: State::Setup { rid, since: now },
            square: None,
            generation: 0,
            colour: 0,
            rounds: ROUNDS,
            picture: Vec::new(),
            channel: Vec::new(),
            lost: 0,
            seed: now.elapsed().as_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15,
        })
    }

    pub fn done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// How many marks are measured so far, of how many.
    pub fn progress(&self) -> (usize, usize) {
        (self.picture.len() + self.lost, self.rounds)
    }

    fn gap(&mut self) -> Duration {
        // xorshift: 60 to 160 ms.
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        Duration::from_millis(60 + self.seed % 100)
    }

    /// The helper's `LatencyShown` for mark `rid`.
    pub fn shown(&mut self, link: &mut dyn Link, rid: u32, sq: Square, now: Instant) {
        match self.state {
            State::Setup { rid: r, .. } if r == rid => {
                self.square = Some(sq);
                self.generation += 1;
                let g = self.generation;
                link.probe(&mut |p| p.arm(g, sq, COLOURS[0]));
                self.state = State::Settle { since: now };
            }
            State::Round {
                rid: r,
                sent,
                answered: None,
            } if r == rid => {
                self.state = State::Round {
                    rid,
                    sent,
                    answered: Some(now.saturating_duration_since(sent)),
                };
            }
            _ => {}
        }
    }

    /// Advances; returns the result once, when the measurement ends.
    pub fn poll(&mut self, link: &mut dyn Link, now: Instant) -> Option<Result<Report, String>> {
        let g = self.generation;
        let mut hit = None;
        link.probe(&mut |p| hit = p.take_hit(g));
        match self.state {
            State::Done => None,
            State::Setup { since, .. } => (now.duration_since(since) > SETUP_LIMIT).then(|| {
                self.finish(link);
                Err("the server helper did not show its marker".into())
            }),
            State::Settle { since } => {
                if hit.is_some() {
                    let until = now + self.gap();
                    self.state = State::Gap { until };
                    None
                } else if now.duration_since(since) > SETUP_LIMIT {
                    self.finish(link);
                    Some(Err("the marker never appeared in the picture (is the top-left corner of the session covered?)".into()))
                } else {
                    None
                }
            }
            State::Gap { until } => {
                if now < until {
                    return None;
                }
                let sq = self.square?;
                self.colour = (self.colour + 1) % COLOURS.len();
                let rgb = COLOURS[self.colour];
                self.generation += 1;
                let g = self.generation;
                link.probe(&mut |p| p.arm(g, sq, rgb));
                let sent = Instant::now();
                match link.mark(rgb) {
                    Some(rid) => {
                        self.state = State::Round {
                            rid,
                            sent,
                            answered: None,
                        };
                        None
                    }
                    None => {
                        self.finish(link);
                        Some(Err("the server helper went away".into()))
                    }
                }
            }
            State::Round { sent, answered, .. } => {
                if let Some(t) = hit {
                    self.picture.push(t.saturating_duration_since(sent));
                    if let Some(a) = answered {
                        self.channel.push(a);
                    }
                } else if now.duration_since(sent) > ROUND_LIMIT {
                    self.lost += 1;
                    link.probe(&mut |p| p.disarm());
                } else {
                    return None;
                }
                if self.picture.len() + self.lost < self.rounds {
                    let until = now + self.gap();
                    self.state = State::Gap { until };
                    return None;
                }
                self.finish(link);
                if self.picture.len() < self.rounds / 2 {
                    return Some(Err(format!(
                        "{} of {} marks never reached the picture",
                        self.lost, self.rounds
                    )));
                }
                let mut picture = std::mem::take(&mut self.picture);
                let mut channel = std::mem::take(&mut self.channel);
                picture.sort();
                channel.sort();
                Some(Ok(Report {
                    picture,
                    channel,
                    lost: self.lost,
                }))
            }
        }
    }

    /// Stops early (the user closed the session or asked again).
    pub fn cancel(&mut self, link: &mut dyn Link) {
        if !self.done() {
            self.finish(link);
        }
    }

    fn finish(&mut self, link: &mut dyn Link) {
        link.probe(&mut |p| p.disarm());
        link.end();
        self.state = State::Done;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb_with(sq: Square, rgb: u32) -> Framebuffer {
        let mut fb = Framebuffer::new(100, 80);
        for y in sq.y..sq.y + sq.size {
            for x in sq.x..sq.x + sq.size {
                fb.pixels[y * fb.width + x] = rgb;
            }
        }
        fb
    }

    const SQ: Square = Square {
        x: 8,
        y: 8,
        size: 32,
    };

    #[test]
    fn a_square_shows_its_colour_within_tolerance() {
        assert!(shows(&fb_with(SQ, 0x00f0_10e8), SQ, 0x00ff_00ff));
        assert!(!shows(&fb_with(SQ, 0x0080_0080), SQ, 0x00ff_00ff));
        // Outside the picture: never.
        let off = Square {
            x: 90,
            y: 8,
            size: 32,
        };
        assert!(!shows(&fb_with(SQ, 0x00ff_00ff), off, 0x00ff_00ff));
    }

    /// A fake helper and session: marks are numbered, the probe is checked
    /// against a picture the test paints.
    #[derive(Default)]
    struct Fake {
        marks: Vec<u32>,
        ended: bool,
        probe: Probe,
        refuse: bool,
    }

    impl Link for Fake {
        fn mark(&mut self, rgb: u32) -> Option<u32> {
            if self.refuse {
                return None;
            }
            self.marks.push(rgb);
            Some(self.marks.len() as u32)
        }
        fn end(&mut self) {
            self.ended = true;
        }
        fn probe(&mut self, f: &mut dyn FnMut(&mut Probe)) {
            f(&mut self.probe)
        }
    }

    #[test]
    fn a_measurement_times_every_mark_to_the_picture() {
        let mut link = Fake::default();
        let t0 = Instant::now();
        let mut run = Run::start(&mut link, t0).unwrap();
        run.rounds = 3;
        // The helper answers the setup mark; the picture shows it.
        run.shown(&mut link, 1, SQ, t0);
        link.probe.check(&fb_with(SQ, COLOURS[0]), t0);
        let mut now = t0;
        let mut result = None;
        for _ in 0..10_000 {
            now += Duration::from_millis(1);
            if let Some(r) = run.poll(&mut link, now) {
                result = Some(r);
                break;
            }
            // Each mark: answered at once, in the picture 30 ms later.
            if let State::Round { rid, sent, .. } = run.state {
                run.shown(&mut link, rid, SQ, now);
                if now.duration_since(sent) >= Duration::from_millis(30) {
                    let rgb = *link.marks.last().unwrap();
                    link.probe
                        .check(&fb_with(SQ, rgb), sent + Duration::from_millis(30));
                }
            }
        }
        let report = result.expect("finished").expect("measured");
        assert_eq!(report.picture.len(), 3);
        assert!(
            report
                .picture
                .iter()
                .all(|d| *d == Duration::from_millis(30))
        );
        assert_eq!(report.lost, 0);
        assert!(link.ended);
        assert_eq!(link.marks.len(), 4);
        // Consecutive colours differ.
        assert!(link.marks.windows(2).all(|w| w[0] != w[1]));
        assert!(report.summary().starts_with("30 ms to the picture"));
    }

    #[test]
    fn a_marker_that_never_shows_ends_with_a_reason() {
        let mut link = Fake::default();
        let t0 = Instant::now();
        let mut run = Run::start(&mut link, t0).unwrap();
        run.shown(&mut link, 1, SQ, t0);
        let r = run.poll(&mut link, t0 + SETUP_LIMIT + Duration::from_millis(1));
        assert!(matches!(r, Some(Err(e)) if e.contains("never appeared")));
        assert!(link.ended);
        assert!(run.done());
        // A helper that cannot be asked: no run at all.
        let mut link = Fake {
            refuse: true,
            ..Fake::default()
        };
        assert!(Run::start(&mut link, t0).is_err());
    }
}
