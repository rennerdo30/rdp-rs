//! Shows the server helper's picture stream (RDP-67, experimental) in a
//! session's picture, in place of RDP's.
//!
//! The helper sends each encoded picture (H.264) in pieces on its Bulk
//! channel, with the regions that changed. This thread puts the pieces
//! together, decodes the picture with its own Media Foundation decoder,
//! converts only the changed regions into the session's picture, notes the
//! time for the latency meter, and acknowledges the picture so the helper
//! sends the next one. While it shows pictures, the session worker leaves
//! the picture alone ([`crate::session::Shared::stream_owns`]); when it ends,
//! the worker copies RDP's whole picture back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rdp::{Damage, H264Decoder, Yuv420Frame};

use crate::helper::{HelperHandle, StreamPiece};
use crate::session::Shared;

/// A picture being put together from its pieces.
struct Assembly {
    seq: u32,
    total: u32,
    rects: Vec<[u16; 4]>,
    data: Vec<u8>,
}

/// Puts pictures together; returns a complete one. A piece that does not
/// continue the current picture drops it (the next keyframe or full
/// picture repairs the view).
#[derive(Default)]
pub struct Assembler {
    cur: Option<Assembly>,
}

impl Assembler {
    pub fn add(&mut self, p: StreamPiece) -> Option<(u32, Vec<[u16; 4]>, Vec<u8>)> {
        if p.offset == 0 {
            self.cur = Some(Assembly {
                seq: p.seq,
                total: p.total,
                rects: p.rects,
                data: Vec::with_capacity(p.total as usize),
            });
        }
        let a = self.cur.as_mut()?;
        if a.seq != p.seq || a.data.len() != p.offset as usize || a.total != p.total {
            self.cur = None;
            return None;
        }
        a.data.extend_from_slice(&p.data);
        if a.data.len() < a.total as usize {
            return None;
        }
        let a = self.cur.take()?;
        Some((a.seq, a.rects, a.data))
    }
}

/// An access unit delimiter (H.264 NAL type 9): appended to every picture
/// so Windows' decoder knows it is complete. Without it the decoder waits
/// for the next picture's start, so a quiet screen never showed its last
/// change (RDP-71: one picture held back, shown with the AMD encoder).
pub const AUD: [u8; 6] = [0, 0, 0, 1, 9, 0xf0];

/// YCbCr in BT.709 limited range (16-235) to 0x00RRGGBB: the stream's
/// colours, as the helper converts them (not RDP's full-range formula).
pub fn rgb709(y: u8, u: u8, v: u8) -> u32 {
    let c = 298 * (i32::from(y) - 16);
    let d = i32::from(u) - 128;
    let e = i32::from(v) - 128;
    let clamp = |x: i32| ((x + 128) >> 8).clamp(0, 255) as u32;
    let r = clamp(c + 459 * e);
    let g = clamp(c - 55 * d - 136 * e);
    let b = clamp(c + 541 * d);
    r << 16 | g << 8 | b
}

/// Copies the changed rectangles of a decoded picture into `fb` (clipped
/// to both) and returns them as damage.
pub fn paint(frame: &Yuv420Frame, rects: &[[u16; 4]], fb: &mut rdp::Framebuffer) -> Vec<Damage> {
    let (w, h) = (frame.width.min(fb.width), frame.height.min(fb.height));
    let mut damage = Vec::new();
    for r in rects {
        let (x0, y0) = (r[0] as usize, r[1] as usize);
        let (x1, y1) = ((x0 + r[2] as usize).min(w), (y0 + r[3] as usize).min(h));
        if x1 <= x0 || y1 <= y0 {
            continue;
        }
        for y in y0..y1 {
            let row = &mut fb.pixels[y * fb.width..y * fb.width + fb.width];
            for (x, px) in row.iter_mut().enumerate().take(x1).skip(x0) {
                let (cx, cy) = (x / 2, y / 2);
                *px = rgb709(
                    frame.y[y * frame.y_stride + x],
                    frame.chroma(false, cx, cy),
                    frame.chroma(true, cx, cy),
                );
            }
        }
        damage.push(Damage {
            x: x0,
            y: y0,
            w: x1 - x0,
            h: y1 - y0,
        });
    }
    damage
}

/// The running player; dropping it stops the thread (the session worker
/// then copies RDP's picture back).
pub struct Player {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Player {
    /// Plays the pieces from `rx` into `shared`; `wake` asks the window to
    /// present (the session's usual frame notice, sent at most once until
    /// the window took the damage, like the worker does with `notified`).
    pub fn start(
        rx: Receiver<StreamPiece>,
        shared: Arc<Mutex<Shared>>,
        notified: Arc<AtomicBool>,
        helper: HelperHandle,
        wake: impl Fn() + Send + 'static,
    ) -> Player {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::Builder::new()
            .name("stream-player".into())
            .spawn(move || run(&rx, &shared, &notified, &helper, &wake, &s))
            .ok();
        Player { stop, thread }
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(
    rx: &Receiver<StreamPiece>,
    shared: &Arc<Mutex<Shared>>,
    notified: &Arc<AtomicBool>,
    helper: &HelperHandle,
    wake: &dyn Fn(),
    stop: &AtomicBool,
) {
    let mut decoder = match crate::h264_mf::MfH264::new() {
        Ok(d) => d,
        Err(e) => {
            rdp::trace!("stream: no H.264 decoder: {e}");
            return;
        }
    };
    let mut asm = Assembler::default();
    let mut shown = 0u64;
    let started = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let piece = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(p) => p,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let Some((seq, rects, mut data)) = asm.add(piece) else {
            continue;
        };
        data.extend_from_slice(&AUD);
        match decoder.decode(&data) {
            Ok(Some(frame)) => {
                let now = Instant::now();
                {
                    let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                    s.stream_owns = true;
                    let s = &mut *s;
                    let damage = paint(&frame, &rects, &mut s.fb);
                    s.damage.extend_from_slice(&damage);
                    s.ready.get_or_insert(now);
                    s.latency.check(&s.fb, now);
                }
                decoder.recycle(frame);
                if !notified.swap(true, Ordering::AcqRel) {
                    wake();
                }
                shown += 1;
                if shown == 1 || shown.is_multiple_of(600) {
                    rdp::trace!(
                        "stream: picture {seq} shown ({shown} in {:.0} s)",
                        started.elapsed().as_secs_f64()
                    );
                }
            }
            Ok(None) => {}
            Err(e) => rdp::trace!("stream: picture {seq} not decoded: {e}"),
        }
        // Decoded or not, the helper may send the next one.
        helper.stream_ack(seq);
    }
    // RDP's picture again, all of it.
    let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
    if s.stream_owns {
        s.stream_owns = false;
        s.resync = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(seq: u32, offset: u32, total: u32, data: &[u8]) -> StreamPiece {
        StreamPiece {
            seq,
            flags: 0,
            offset,
            total,
            rects: if offset == 0 {
                vec![[0, 0, 4, 4]]
            } else {
                Vec::new()
            },
            data: data.to_vec(),
        }
    }

    #[test]
    fn pieces_make_a_picture_and_gaps_drop_it() {
        let mut a = Assembler::default();
        assert!(a.add(piece(1, 0, 6, &[1, 2, 3])).is_none());
        let (seq, rects, data) = a.add(piece(1, 3, 6, &[4, 5, 6])).unwrap();
        assert_eq!(
            (seq, rects, data),
            (1, vec![[0, 0, 4, 4]], vec![1, 2, 3, 4, 5, 6])
        );
        // A piece out of order drops the picture; the next one starts clean.
        assert!(a.add(piece(2, 0, 6, &[1, 2, 3])).is_none());
        assert!(a.add(piece(2, 4, 6, &[5, 6])).is_none());
        assert!(a.add(piece(2, 3, 6, &[4, 5, 6])).is_none());
        assert_eq!(a.add(piece(3, 0, 2, &[9, 9])).map(|p| p.0), Some(3));
        // A piece of another picture without its start is ignored.
        assert!(a.add(piece(4, 2, 4, &[1, 2])).is_none());
    }

    /// BT.709 limited range: the standard values of pure colours come back
    /// within a step or two.
    #[test]
    fn stream_colours_are_bt709_limited_range() {
        let near = |got: u32, want: [u32; 3]| {
            let g = [got >> 16 & 0xff, got >> 8 & 0xff, got & 0xff];
            g.iter().zip(want).all(|(a, b)| a.abs_diff(b) <= 2)
        };
        assert!(near(rgb709(235, 128, 128), [255, 255, 255]));
        assert!(near(rgb709(16, 128, 128), [0, 0, 0]));
        assert!(
            near(rgb709(63, 102, 240), [255, 0, 0]),
            "{:06x}",
            rgb709(63, 102, 240)
        );
        assert!(
            near(rgb709(173, 42, 26), [0, 255, 0]),
            "{:06x}",
            rgb709(173, 42, 26)
        );
        assert!(
            near(rgb709(32, 240, 118), [0, 0, 255]),
            "{:06x}",
            rgb709(32, 240, 118)
        );
    }

    #[test]
    fn painting_copies_only_the_changed_rectangles() {
        let frame = Yuv420Frame {
            width: 8,
            height: 4,
            y: vec![200; 32],
            uv: vec![128; 16],
            y_stride: 8,
            uv_stride: 8,
            ..Default::default()
        };
        let mut fb = rdp::Framebuffer::new(6, 3);
        // One inside, one cut by the picture's edge, one outside.
        let d = paint(&frame, &[[1, 1, 2, 1], [4, 0, 9, 9], [7, 3, 1, 1]], &mut fb);
        let grey = rgb709(200, 128, 128);
        assert_eq!(fb.pixels[6 + 1], grey);
        assert_eq!(fb.pixels[6 + 2], grey);
        assert_eq!(fb.pixels[0], 0);
        assert_eq!(fb.pixels[5], grey);
        assert_eq!(fb.pixels[2 * 6 + 5], grey);
        assert_eq!(d.len(), 2);
        assert_eq!((d[1].x, d[1].y, d[1].w, d[1].h), (4, 0, 2, 3));
    }
}
