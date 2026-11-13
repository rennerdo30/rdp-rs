//! Session recording: the session's picture as an MP4 file (H.264 video),
//! written with Media Foundation's sink writer, the H.264 encoder that ships
//! with Windows and its MP4 container.
//!
//! The session worker only hands pictures over ([`Recorder::frame`]: one copy
//! into a two-buffer mailbox, newest wins, never a wait on the encoder). The
//! recorder's own thread converts to NV12 and encodes at a fixed rate,
//! repeating the last picture while nothing changes, so the video's timeline
//! follows real time on the monotonic clock. A desktop resize mid-recording
//! is letterboxed (and scaled down when larger) into the size the file
//! started with.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Frame rate when the caller has no preference.
pub const DEFAULT_FPS: u32 = 15;

/// What a finished recording holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingInfo {
    pub path: PathBuf,
    /// Length of the video timeline.
    pub duration: Duration,
    /// Encoded frames (a catch-up after a stall is one longer frame).
    pub frames: u64,
    /// File size after finalisation.
    pub bytes: u64,
}

/// A picture handed from the session to the encoder thread.
#[derive(Default)]
struct Picture {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

/// Hand-off between the session and the encoder thread. Two picture buffers
/// circulate: the encoder's current one, and one that is either `pending`
/// (newest, not yet taken) or `spare` (free for the next copy).
#[derive(Default)]
struct Mailbox {
    pending: Option<Picture>,
    spare: Option<Picture>,
    /// Pictures overwritten before the encoder took them.
    dropped: u64,
}

fn lock(m: &Mutex<Mailbox>) -> std::sync::MutexGuard<'_, Mailbox> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A running recording. Dropping it finishes the file too (and waits for
/// that); [`Recorder::finish`] also reports what was written.
pub struct Recorder {
    mailbox: Arc<Mutex<Mailbox>>,
    /// Dropped to tell the encoder thread to finish.
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<Result<RecordingInfo, String>>>,
}

impl Recorder {
    /// Creates `path` (replacing a file there) and starts encoding
    /// `width`x`height` at `fps` frames per second. Fails when Media
    /// Foundation, the H.264 encoder or the file cannot be set up.
    pub fn start(path: &Path, width: u32, height: u32, fps: u32) -> Result<Recorder, String> {
        if width == 0 || height == 0 || width > 8192 || height > 8192 {
            return Err(format!("cannot record a {width}x{height} picture"));
        }
        let fps = fps.clamp(1, 60);
        // H.264 4:2:0 needs even sizes; an odd edge gets one black line.
        let (w, h) = ((width as usize + 1) & !1, (height as usize + 1) & !1);
        let mailbox = Arc::new(Mutex::new(Mailbox::default()));
        let (stop, stopped) = mpsc::channel();
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let (mb, path) = (mailbox.clone(), path.to_path_buf());
        let thread = std::thread::Builder::new()
            .name("rdp-recorder".into())
            .spawn(move || {
                let sink = match sink::Sink::create(&path, w, h, fps) {
                    Ok(s) => {
                        let _ = ready_tx.send(Ok(()));
                        s
                    }
                    Err(e) => {
                        // The sink writer creates the file before it fails
                        // on the encoder; leave no empty file behind.
                        if std::fs::metadata(&path).is_ok_and(|m| m.len() == 0) {
                            let _ = std::fs::remove_file(&path);
                        }
                        let _ = ready_tx.send(Err(e.clone()));
                        return Err(e);
                    }
                };
                encode(sink, &mb, &stopped, fps, w, h, path)
            })
            .map_err(|e| format!("cannot start the recorder thread: {e}"))?;
        match ready.recv() {
            Ok(Ok(())) => Ok(Recorder {
                mailbox,
                stop: Some(stop),
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("the recorder thread ended during setup".into())
            }
        }
    }

    /// Hands the session's current picture to the encoder: one copy into a
    /// free buffer, replacing a picture the encoder has not taken yet. Never
    /// waits for the encoder; a picture of another size is letterboxed there.
    pub fn frame(&mut self, fb: &rdp::Framebuffer) {
        let n = fb.width * fb.height;
        if n == 0 || fb.pixels.len() < n {
            return;
        }
        let mut pic = {
            let mut m = lock(&self.mailbox);
            match m.pending.take() {
                Some(p) => {
                    m.dropped += 1;
                    p
                }
                None => m.spare.take().unwrap_or_default(),
            }
        };
        pic.width = fb.width;
        pic.height = fb.height;
        pic.pixels.clear();
        pic.pixels.extend_from_slice(&fb.pixels[..n]);
        lock(&self.mailbox).pending = Some(pic);
    }

    /// Stops recording, writes the file's index and reports the result.
    pub fn finish(mut self) -> Result<RecordingInfo, String> {
        self.stop_thread()
            .unwrap_or_else(|| Err("recorder already finished".into()))
    }

    fn stop_thread(&mut self) -> Option<Result<RecordingInfo, String>> {
        drop(self.stop.take());
        let t = self.thread.take()?;
        Some(
            t.join()
                .unwrap_or_else(|_| Err("the recorder thread panicked".into())),
        )
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if let Some(Err(e)) = self.stop_thread() {
            rdp::trace!("recording failed: {e}");
        }
    }
}

/// The encoder thread: one frame per slot of the fixed-rate timeline, from
/// the newest picture, until the recorder is stopped.
fn encode(
    mut sink: sink::Sink,
    mailbox: &Mutex<Mailbox>,
    stop: &Receiver<()>,
    fps: u32,
    w: usize,
    h: usize,
    path: PathBuf,
) -> Result<RecordingInfo, String> {
    let mut pacer = Pacer::new(fps);
    let mut current: Option<Picture> = None;
    let mut nv12 = vec![16u8; w * h];
    nv12.resize(w * h * 3 / 2, 128); // black until the first picture
    let mut canvas = Vec::new();
    let mut frames = 0u64;
    let mut result = Ok(());
    let start = Instant::now();
    loop {
        let stopping = !matches!(
            stop.recv_timeout(pacer.wait(start.elapsed())),
            Err(RecvTimeoutError::Timeout)
        );
        if let Some((time, duration)) = pacer.due(start.elapsed()) {
            let fresh = take_newest(mailbox, &mut current);
            if let Some(p) = current.as_ref().filter(|_| fresh) {
                if (p.width, p.height) == (w, h) {
                    bgrx_to_nv12(&p.pixels, w, w, h, &mut nv12);
                } else {
                    letterbox(p, w, h, &mut canvas);
                    bgrx_to_nv12(&canvas, w, w, h, &mut nv12);
                }
            }
            if let Err(e) = sink.write(&nv12, time, duration) {
                result = Err(e);
                break;
            }
            frames += 1;
        }
        if stopping {
            break;
        }
    }
    let finalized = sink.finish();
    result?;
    finalized?;
    let dropped = lock(mailbox).dropped;
    rdp::trace!("recording: {frames} frames, {dropped} pictures replaced before encoding");
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(RecordingInfo {
        path,
        duration: Duration::from_nanos(pacer.end() as u64 * 100),
        frames,
        bytes,
    })
}

/// Encoder side of the mailbox: makes a waiting picture `current` and gives
/// the old buffer back as the spare. False when nothing new arrived.
fn take_newest(mailbox: &Mutex<Mailbox>, current: &mut Option<Picture>) -> bool {
    let mut m = lock(mailbox);
    match m.pending.take() {
        Some(p) => {
            m.spare = current.replace(p);
            true
        }
        None => false,
    }
}

/// Fixed-rate timeline: slot `n` covers `[n, n + 1) / fps` seconds after the
/// start. The frame for a slot is due once its start has passed; slots
/// missed during a stall fold into one longer frame, so the timeline stays
/// real time without encoding a burst of repeats.
struct Pacer {
    fps: u64,
    next: u64,
}

impl Pacer {
    fn new(fps: u32) -> Pacer {
        Pacer {
            fps: fps.max(1) as u64,
            next: 0,
        }
    }

    /// Start of `slot` in Media Foundation time (100 ns units).
    fn time(&self, slot: u64) -> i64 {
        (slot as u128 * 10_000_000 / self.fps as u128) as i64
    }

    /// The frame due at `elapsed`, as (start, duration) in 100 ns units.
    fn due(&mut self, elapsed: Duration) -> Option<(i64, i64)> {
        let slot = (elapsed.as_nanos() * self.fps as u128 / 1_000_000_000) as u64;
        if slot < self.next {
            return None;
        }
        let start = self.time(self.next);
        self.next = slot + 1;
        Some((start, self.time(self.next) - start))
    }

    /// How long until the next frame is due (rounded up: no early wake).
    fn wait(&self, elapsed: Duration) -> Duration {
        let at = (self.next as u128 * 1_000_000_000).div_ceil(self.fps as u128);
        Duration::from_nanos(at.saturating_sub(elapsed.as_nanos()) as u64)
    }

    /// End of the last frame handed out (100 ns units).
    fn end(&self) -> i64 {
        self.time(self.next)
    }
}

/// Target bitrate: 4 Mbit/s at 1920x1080, by area, within 0.5..20 Mbit/s.
fn bitrate(w: usize, h: usize) -> u32 {
    let b = 4_000_000u64 * (w * h) as u64 / (1920 * 1080);
    b.clamp(500_000, 20_000_000) as u32
}

/// Where a `sw`x`sh` picture goes in a `dw`x`dh` frame: centred, aspect
/// kept, scaled down when it does not fit, never scaled up.
/// Returns (x, y, width, height).
fn fit(sw: usize, sh: usize, dw: usize, dh: usize) -> (usize, usize, usize, usize) {
    let (rw, rh) = if sw <= dw && sh <= dh {
        (sw, sh)
    } else if sw * dh <= dw * sh {
        ((sw * dh / sh).max(1), dh)
    } else {
        (dw, (sh * dw / sw).max(1))
    };
    ((dw - rw) / 2, (dh - rh) / 2, rw, rh)
}

/// Draws `p` into a black `dw`x`dh` canvas at [`fit`]'s place
/// (nearest-neighbour when scaled).
fn letterbox(p: &Picture, dw: usize, dh: usize, out: &mut Vec<u32>) {
    out.clear();
    out.resize(dw * dh, 0);
    let (x0, y0, rw, rh) = fit(p.width, p.height, dw, dh);
    let cols: Vec<usize> = (0..rw).map(|x| x * p.width / rw).collect();
    for y in 0..rh {
        let src = &p.pixels[(y * p.height / rh) * p.width..][..p.width];
        let dst = &mut out[(y0 + y) * dw + x0..][..rw];
        for (d, &sx) in dst.iter_mut().zip(&cols) {
            *d = src[sx];
        }
    }
}

/// 0x00RRGGBB pixels (`stride` pixels per row) to NV12 in `out`: a `w`x`h`
/// luma plane, then interleaved Cb/Cr at half resolution, both with pitch
/// `w`. BT.709, limited range (16..235 luma), 8-bit fixed point; chroma from
/// the 2x2 block's average. `w` and `h` are even.
fn bgrx_to_nv12(px: &[u32], stride: usize, w: usize, h: usize, out: &mut [u8]) {
    let rgb = |p: u32| {
        (
            (p >> 16 & 0xFF) as i32,
            (p >> 8 & 0xFF) as i32,
            (p & 0xFF) as i32,
        )
    };
    let (luma, chroma) = out[..w * h * 3 / 2].split_at_mut(w * h);
    for y in 0..h {
        for (x, d) in luma[y * w..][..w].iter_mut().enumerate() {
            let (r, g, b) = rgb(px[y * stride + x]);
            *d = (((47 * r + 157 * g + 16 * b + 128) >> 8) + 16) as u8;
        }
    }
    for cy in 0..h / 2 {
        let (top, bottom) = (&px[2 * cy * stride..], &px[(2 * cy + 1) * stride..]);
        for cx in 0..w / 2 {
            let (mut r, mut g, mut b) = (0, 0, 0);
            for p in [
                top[2 * cx],
                top[2 * cx + 1],
                bottom[2 * cx],
                bottom[2 * cx + 1],
            ] {
                let (pr, pg, pb) = rgb(p);
                (r, g, b) = (r + pr, g + pg, b + pb);
            }
            let u = ((-26 * r - 86 * g + 112 * b + 512) >> 10) + 128;
            let v = ((112 * r - 102 * g - 10 * b + 512) >> 10) + 128;
            chroma[cy * w + 2 * cx] = u.clamp(16, 240) as u8;
            chroma[cy * w + 2 * cx + 1] = v.clamp(16, 240) as u8;
        }
    }
}

#[cfg(windows)]
mod sink {
    use std::path::Path;

    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
    use windows::core::HSTRING;

    fn err(what: &str) -> impl Fn(windows::core::Error) -> String + '_ {
        move |e| format!("recording: Media Foundation {what}: {e}")
    }

    /// The sink writer with its one H.264 stream; lives on the encoder thread.
    pub struct Sink {
        writer: Option<IMFSinkWriter>,
        stream: u32,
        mf_started: bool,
        com_init: bool,
    }

    impl Sink {
        /// Prefers a hardware encoder; falls back to the software one when
        /// the hardware path cannot be set up for this size.
        pub fn create(path: &Path, w: usize, h: usize, fps: u32) -> Result<Sink, String> {
            let mut s = Sink {
                writer: None,
                stream: 0,
                mf_started: false,
                com_init: false,
            };
            // SAFETY: COM / Media Foundation start-up on this thread,
            // balanced in Drop.
            unsafe {
                s.com_init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
                MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(err("startup"))?;
            }
            s.mf_started = true;
            let (writer, stream) = match open(path, w, h, fps, true) {
                Ok(o) => o,
                Err(e) => {
                    rdp::trace!("{e}; trying the software encoder");
                    open(path, w, h, fps, false)?
                }
            };
            s.writer = Some(writer);
            s.stream = stream;
            Ok(s)
        }

        /// Encodes one NV12 picture shown from `time` for `duration` (100 ns).
        pub fn write(&mut self, nv12: &[u8], time: i64, duration: i64) -> Result<(), String> {
            let writer = self.writer.as_ref().ok_or("recording: no writer")?;
            // SAFETY: the buffer is locked for exactly its allocated length.
            unsafe {
                let len = nv12.len() as u32;
                let buffer = MFCreateMemoryBuffer(len).map_err(err("buffer"))?;
                let mut p = std::ptr::null_mut();
                buffer.Lock(&mut p, None, None).map_err(err("lock"))?;
                std::ptr::copy_nonoverlapping(nv12.as_ptr(), p, nv12.len());
                buffer.Unlock().map_err(err("unlock"))?;
                buffer.SetCurrentLength(len).map_err(err("buffer"))?;
                let sample = MFCreateSample().map_err(err("sample"))?;
                sample.AddBuffer(&buffer).map_err(err("sample"))?;
                sample.SetSampleTime(time).map_err(err("sample"))?;
                sample.SetSampleDuration(duration).map_err(err("sample"))?;
                writer
                    .WriteSample(self.stream, &sample)
                    .map_err(err("encode"))
            }
        }

        /// Drains the encoder and writes the MP4 index (moov).
        pub fn finish(&mut self) -> Result<(), String> {
            let writer = self.writer.take().ok_or("recording: no writer")?;
            // SAFETY: a call on an owned interface.
            unsafe { writer.Finalize().map_err(err("finalize")) }
        }
    }

    /// Sink writer for an MP4 file with one H.264 stream fed NV12. NV12 is
    /// what the in-box encoder takes directly: with converters disabled
    /// (MF_READWRITE_DISABLE_CONVERTERS) NV12 input works and RGB32 input
    /// is refused (MF_E_INVALIDMEDIATYPE), so the colour conversion is ours
    /// and the writer inserts no video processor.
    fn open(
        path: &Path,
        w: usize,
        h: usize,
        fps: u32,
        hardware: bool,
    ) -> Result<(IMFSinkWriter, u32), String> {
        let size = (w as u64) << 32 | h as u64;
        let rate = (fps as u64) << 32 | 1;
        // SAFETY: Media Foundation calls with valid arguments on interfaces
        // created here.
        unsafe {
            let mut attrs = None;
            MFCreateAttributes(&mut attrs, 2).map_err(err("attributes"))?;
            let attrs = attrs.ok_or("recording: no attributes")?;
            attrs
                .SetGUID(&MF_TRANSCODE_CONTAINERTYPE, &MFTranscodeContainerType_MPEG4)
                .and_then(|_| {
                    attrs.SetUINT32(&MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, hardware as u32)
                })
                .map_err(err("attributes"))?;
            let url = HSTRING::from(path.as_os_str());
            let writer = MFCreateSinkWriterFromURL(&url, None, &attrs).map_err(err("file"))?;
            let video = |subtype: &windows::core::GUID| -> windows::core::Result<IMFMediaType> {
                let t = MFCreateMediaType()?;
                t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
                t.SetGUID(&MF_MT_SUBTYPE, subtype)?;
                t.SetUINT64(&MF_MT_FRAME_SIZE, size)?;
                t.SetUINT64(&MF_MT_FRAME_RATE, rate)?;
                t.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, 1 << 32 | 1)?;
                t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
                // BT.709 limited range, as bgrx_to_nv12 produces it.
                t.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32)?;
                t.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
                t.SetUINT32(&MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709.0 as u32)?;
                t.SetUINT32(&MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709.0 as u32)?;
                Ok(t)
            };
            let output = video(&MFVideoFormat_H264)
                .and_then(|t| {
                    t.SetUINT32(&MF_MT_AVG_BITRATE, super::bitrate(w, h))?;
                    t.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main.0 as u32)?;
                    Ok(t)
                })
                .map_err(err("H.264 type"))?;
            let stream = writer.AddStream(&output).map_err(err("H.264 encoder"))?;
            let input = video(&MFVideoFormat_NV12)
                .and_then(|t| {
                    t.SetUINT32(&MF_MT_DEFAULT_STRIDE, w as u32)?;
                    Ok(t)
                })
                .map_err(err("NV12 type"))?;
            writer
                .SetInputMediaType(stream, &input, None)
                .map_err(err("NV12 input"))?;
            writer.BeginWriting().map_err(err("start"))?;
            Ok((writer, stream))
        }
    }

    impl Drop for Sink {
        fn drop(&mut self) {
            self.writer = None;
            // SAFETY: balances the successful start-up calls in create.
            unsafe {
                if self.mf_started {
                    let _ = MFShutdown();
                }
                if self.com_init {
                    CoUninitialize();
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod sink {
    use std::path::Path;

    pub struct Sink;

    impl Sink {
        pub fn create(_: &Path, _: usize, _: usize, _: u32) -> Result<Sink, String> {
            Err("recording needs Windows (Media Foundation)".into())
        }
        pub fn write(&mut self, _: &[u8], _: i64, _: i64) -> Result<(), String> {
            Ok(())
        }
        pub fn finish(&mut self) -> Result<(), String> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHITE: u32 = 0xFF_FFFF;
    const RED: u32 = 0xFF_0000;
    const GREEN: u32 = 0x00_FF00;
    const BLUE: u32 = 0x00_00FF;

    /// Y, Cb, Cr of a picture filled with one colour (2x2, one chroma block).
    fn solid(c: u32) -> [u8; 3] {
        let mut out = [0u8; 6];
        bgrx_to_nv12(&[c; 4], 2, 2, 2, &mut out);
        assert!(out[..4].iter().all(|&y| y == out[0]));
        [out[0], out[4], out[5]]
    }

    #[test]
    fn bt709_limited_range_colours() {
        // Hand-computed from BT.709 (Kr 0.2126, Kb 0.0722), 219/224 levels:
        // the fixed-point results match the exact values within one level
        // (green's exact luma is 172.6).
        assert_eq!(solid(0), [16, 128, 128]);
        assert_eq!(solid(WHITE), [235, 128, 128]);
        assert_eq!(solid(0x80_8080), [126, 128, 128]);
        assert_eq!(solid(RED), [63, 102, 240]);
        assert_eq!(solid(GREEN), [172, 42, 26]);
        assert_eq!(solid(BLUE), [32, 240, 118]);
    }

    #[test]
    fn nv12_layout_stride_and_block_average() {
        // 4x2 picture in rows of 5 pixels (the fifth is padding): a red
        // block, then a block half white, half black.
        let px = [
            RED, RED, WHITE, 0, 0x12_3456, //
            RED, RED, WHITE, 0, 0x12_3456,
        ];
        let mut out = [0u8; 12];
        bgrx_to_nv12(&px, 5, 4, 2, &mut out);
        assert_eq!(out[..8], [63, 63, 235, 16, 63, 63, 235, 16]);
        // Interleaved Cb, Cr per block; grey averages to neutral chroma.
        assert_eq!(out[8..], [102, 240, 128, 128]);
    }

    #[test]
    fn pacer_follows_the_clock() {
        let ms = Duration::from_millis;
        let mut p = Pacer::new(10); // 100 ms slots = 1,000,000 units
        assert_eq!(p.wait(ms(0)), ms(0));
        assert_eq!(p.due(ms(0)), Some((0, 1_000_000)));
        assert_eq!(p.due(ms(50)), None, "slot 0 already out");
        assert_eq!(p.wait(ms(50)), ms(50));
        assert_eq!(p.due(ms(100)), Some((1_000_000, 1_000_000)));
        // A stall over slots 2..=4: one frame covers them all.
        assert_eq!(p.due(ms(470)), Some((2_000_000, 3_000_000)));
        assert_eq!(p.end(), 5_000_000);
        assert_eq!(p.wait(ms(470)), ms(30));
        assert_eq!(p.due(ms(499)), None);
    }

    #[test]
    fn pacer_odd_rates_tile_the_timeline() {
        // 15 fps: 666,666.67 units per slot; frames must neither overlap
        // nor leave gaps, and 15 slots end at exactly one second.
        let mut p = Pacer::new(15);
        let (mut end, mut now) = (0, Duration::ZERO);
        for i in 0..15u64 {
            // Waking after `wait` finds the frame due (no early wake-up).
            now += p.wait(now);
            assert_eq!(now.as_nanos(), (i as u128 * 1_000_000_000).div_ceil(15));
            let (t, d) = p.due(now).expect("frame due at the wake-up");
            assert_eq!(t, end);
            end = t + d;
        }
        assert_eq!(end, 10_000_000);
        // Just before slot 15 starts nothing is due, and the wait reaches it.
        let before = Duration::from_nanos(999_999_999);
        assert_eq!(p.due(before), None);
        assert_eq!(p.wait(before), Duration::from_nanos(1));
    }

    #[test]
    fn fit_letterboxes_and_scales_down_only() {
        assert_eq!(fit(1280, 720, 1280, 720), (0, 0, 1280, 720));
        assert_eq!(fit(800, 600, 1280, 720), (240, 60, 800, 600));
        assert_eq!(fit(1920, 1080, 1280, 720), (0, 0, 1280, 720));
        assert_eq!(fit(1920, 1200, 1280, 720), (64, 0, 1152, 720));
        assert_eq!(fit(2560, 720, 1280, 720), (0, 180, 1280, 360));
    }

    #[test]
    fn letterbox_draws_centred_and_scaled() {
        // 2x1 into 4x4: unscaled, centred at (1, 1).
        let p = Picture {
            width: 2,
            height: 1,
            pixels: vec![RED, BLUE],
        };
        let mut out = Vec::new();
        letterbox(&p, 4, 4, &mut out);
        let mut want = vec![0; 16];
        want[5] = RED;
        want[6] = BLUE;
        assert_eq!(out, want);
        // 4x2 into 2x2: halved to 2x1 (every other column and row), with
        // the leftover row black.
        let p = Picture {
            width: 4,
            height: 2,
            pixels: vec![RED, GREEN, BLUE, WHITE, 1, 2, 3, 4],
        };
        letterbox(&p, 2, 2, &mut out);
        assert_eq!(out, [RED, BLUE, 0, 0]);
    }

    #[test]
    fn mailbox_keeps_the_newest_picture_in_two_buffers() {
        let mut rec = Recorder {
            mailbox: Arc::new(Mutex::new(Mailbox::default())),
            stop: None,
            thread: None,
        };
        let fb = |v: u32| rdp::Framebuffer {
            width: 2,
            height: 1,
            pixels: vec![v, v],
        };
        let mut current = None;
        assert!(!take_newest(&rec.mailbox, &mut current), "nothing yet");
        rec.frame(&fb(1));
        rec.frame(&fb(2)); // the encoder is behind: 1 is replaced, not 2
        rec.frame(&rdp::Framebuffer::new(0, 0)); // ignored
        assert!(take_newest(&rec.mailbox, &mut current));
        assert_eq!(current.as_ref().unwrap().pixels, [2, 2]);
        assert!(!take_newest(&rec.mailbox, &mut current), "repeat the last");
        rec.frame(&fb(3));
        assert!(take_newest(&rec.mailbox, &mut current));
        assert_eq!(current.as_ref().unwrap().pixels, [3, 3]);
        let m = lock(&rec.mailbox);
        // Buffer 2 came back as the spare: two buffers circulate.
        assert_eq!(m.spare.as_ref().unwrap().pixels, [2, 2]);
        assert!(m.pending.is_none());
        assert_eq!(m.dropped, 1);
    }

    #[test]
    fn bitrate_scales_with_area() {
        assert_eq!(bitrate(1920, 1080), 4_000_000);
        assert_eq!(bitrate(3840, 2160), 16_000_000);
        assert_eq!(bitrate(320, 240), 500_000);
        assert_eq!(bitrate(7680, 4320), 20_000_000);
    }

    /// Top-level MP4 boxes as (type, body).
    fn boxes(data: &[u8]) -> Vec<([u8; 4], &[u8])> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 8 <= data.len() {
            let size = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            let kind: [u8; 4] = data[i + 4..i + 8].try_into().unwrap();
            let (head, size) = match size {
                1 => (
                    16,
                    u64::from_be_bytes(data[i + 8..i + 16].try_into().unwrap()) as usize,
                ),
                0 => (8, data.len() - i),
                s => (8, s),
            };
            assert!(size >= head && i + size <= data.len(), "box overruns file");
            out.push((kind, &data[i + head..i + size]));
            i += size;
        }
        out
    }

    /// Encodes 2 s of 320x240 with Media Foundation and checks the file.
    /// Ignored by default: it needs Media Foundation and takes 2 s of real
    /// time (`cargo test -p rdpc recorder -- --ignored`).
    #[test]
    #[ignore]
    fn media_foundation_writes_a_valid_mp4() {
        let path = std::env::temp_dir().join(format!("rdpc-rec-{}.mp4", std::process::id()));
        let mut rec = Recorder::start(&path, 320, 240, 15).expect("recorder");
        let mut fb = rdp::Framebuffer::new(320, 240);
        let start = Instant::now();
        let mut i = 0u32;
        while start.elapsed() < Duration::from_secs(2) {
            for (n, p) in fb.pixels.iter_mut().enumerate() {
                *p = ((n as u32 + i * 4) & 0xFF) | ((i * 8) & 0xFF) << 16;
            }
            rec.frame(&fb);
            if i == 20 {
                // A resize mid-recording is letterboxed into 320x240.
                fb = rdp::Framebuffer::new(400, 200);
            }
            i += 1;
            std::thread::sleep(Duration::from_millis(40));
        }
        let info = rec.finish().expect("finished recording");
        let data = std::fs::read(&path).expect("file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(info.bytes, data.len() as u64);
        assert!(
            (Duration::from_millis(1950)..Duration::from_millis(2250)).contains(&info.duration),
            "{info:?}"
        );
        assert!((29..=34).contains(&info.frames), "{info:?}");
        let top = boxes(&data);
        assert_eq!(&top[0].0, b"ftyp", "file starts with ftyp");
        let moov = top.iter().find(|b| &b.0 == b"moov").expect("moov box").1;
        let mvhd = boxes(moov)
            .into_iter()
            .find(|b| &b.0 == b"mvhd")
            .expect("mvhd box")
            .1;
        let (timescale, duration) = if mvhd[0] == 1 {
            (
                u32::from_be_bytes(mvhd[20..24].try_into().unwrap()) as f64,
                u64::from_be_bytes(mvhd[24..32].try_into().unwrap()) as f64,
            )
        } else {
            (
                u32::from_be_bytes(mvhd[12..16].try_into().unwrap()) as f64,
                u32::from_be_bytes(mvhd[16..20].try_into().unwrap()) as f64,
            )
        };
        let secs = duration / timescale;
        assert!(
            (secs - info.duration.as_secs_f64()).abs() < 0.1,
            "mvhd {secs} s, recorder {info:?}"
        );
        assert!(top.iter().any(|b| &b.0 == b"mdat"), "media data");
    }
}
