//! This PC's cameras for camera redirection (MS-RDPECAM, `rdp::camera`):
//! [`list`] names the video capture devices without opening them, and
//! [`MfCamera`] captures from one with a Media Foundation source reader.
//!
//! Privacy: a camera is opened only when the server asks for it and the
//! user shares it. [`MfCamera::media_types`] creates the device's media
//! source briefly to read its formats (no capture), when the server has
//! activated the device; [`MfCamera::start`] opens it for capture and
//! [`MfCamera::stop`] (also on drop) shuts the source down at once, which
//! releases the device.
//!
//! All Media Foundation work runs on threads of its own, in the
//! multithreaded apartment: the session worker only hands over commands
//! and picks up finished samples, so a slow driver never stalls a session.
//! Formats are offered as the camera produces them (no conversion): H.264,
//! MJPG, YUY2, NV12, I420, RGB24 and RGB32, the ones MS-RDPECAM carries.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rdp::camera::{MEDIA_FLAG_BOTTOM_UP_IMAGE, MediaType, VideoFormat};

/// A local camera: its display name and the device path that opens it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCamera {
    pub name: String,
    /// MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK.
    pub link: String,
}

/// The video capture devices, in Windows' order. Nothing is opened: this
/// reads the device list only.
pub fn list() -> Vec<LocalCamera> {
    #[cfg(windows)]
    {
        win::list()
    }
    #[cfg(not(windows))]
    Vec::new()
}

/// The cameras' display names (the settings' choices).
pub fn names() -> Vec<String> {
    list().into_iter().map(|c| c.name).collect()
}

/// Which of `cameras` a connection shares: every one for None, else the
/// ones with that name. Empty when sharing is off or the named camera is
/// not connected.
pub fn chosen(cameras: &[String], on: bool, name: Option<&str>) -> Vec<usize> {
    if !on {
        return Vec::new();
    }
    cameras
        .iter()
        .enumerate()
        .filter(|(_, c)| name.is_none_or(|n| n == c.as_str()))
        .map(|(i, _)| i)
        .collect()
}

/// Width and height, or numerator and denominator, from a packed
/// MF_MT_FRAME_SIZE / MF_MT_FRAME_RATE / MF_MT_PIXEL_ASPECT_RATIO value.
fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

/// One native camera format as MS-RDPECAM describes it; None for formats
/// the protocol cannot carry or that make no sense. `stride` is
/// MF_MT_DEFAULT_STRIDE when the type has it (negative: bottom-up rows).
fn describe(
    format: VideoFormat,
    size: u64,
    rate: Option<u64>,
    aspect: Option<u64>,
    stride: Option<i32>,
) -> Option<MediaType> {
    let (width, height) = unpack(size);
    if width == 0 || height == 0 {
        return None;
    }
    // A camera without a frame rate is treated as 30 fps.
    let (num, den) = rate
        .map(unpack)
        .filter(|&(n, d)| n > 0 && d > 0)
        .unwrap_or((30, 1));
    let mut t = MediaType::new(format, width, height, num, den);
    if let Some((n, d)) = aspect.map(unpack).filter(|&(n, d)| n > 0 && d > 0) {
        t.pixel_aspect_ratio_numerator = n;
        t.pixel_aspect_ratio_denominator = d;
    }
    if matches!(format, VideoFormat::Rgb24 | VideoFormat::Rgb32) && stride.is_some_and(|s| s < 0) {
        t.flags |= MEDIA_FLAG_BOTTOM_UP_IMAGE;
    }
    Some(t)
}

/// Adds `t` unless an equal format is already listed.
fn push_unique(list: &mut Vec<MediaType>, t: MediaType) {
    if !list.iter().any(|o| o.same_format(&t)) {
        list.push(t);
    }
}

/// H.264 samples kept while the session does not ask for them; beyond this
/// the queue is dropped and refilled from the next key frame.
const H264_BACKLOG: usize = 30;

/// Captured samples waiting for the session. Uncompressed and MJPG
/// samples stand alone, so only the newest is kept; an H.264 stream must
/// stay decodable, so its samples queue, and an overflow drops to the next
/// key frame.
#[derive(Default)]
struct Samples {
    queue: VecDeque<Vec<u8>>,
    /// H.264: waiting for a key frame after dropping samples.
    need_key: bool,
    /// Capture failed; reported once to the session.
    failed: Option<String>,
}

impl Samples {
    fn push(&mut self, h264: bool, sample: Vec<u8>, key: bool) {
        if !h264 {
            self.queue.clear();
            self.queue.push_back(sample);
            return;
        }
        if self.need_key && !key {
            return;
        }
        self.need_key = false;
        if self.queue.len() >= H264_BACKLOG {
            self.queue.clear();
            if !key {
                self.need_key = true;
                return;
            }
        }
        self.queue.push_back(sample);
    }
}

type SharedSamples = Arc<Mutex<Samples>>;

fn lock(s: &SharedSamples) -> std::sync::MutexGuard<'_, Samples> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

/// Camera backend for one local camera through Media Foundation.
pub struct MfCamera {
    link: String,
    samples: SharedSamples,
    #[cfg(windows)]
    capture: Option<win::Capture>,
}

impl MfCamera {
    pub fn new(link: &str) -> Self {
        MfCamera {
            link: link.to_string(),
            samples: SharedSamples::default(),
            #[cfg(windows)]
            capture: None,
        }
    }
}

impl rdp::CameraBackend for MfCamera {
    #[cfg(windows)]
    fn media_types(&mut self) -> Result<Vec<MediaType>, String> {
        win::media_types(&self.link)
    }

    #[cfg(not(windows))]
    fn media_types(&mut self) -> Result<Vec<MediaType>, String> {
        let _ = &self.link;
        Err("no camera capture on this platform".into())
    }

    #[cfg(windows)]
    fn start(&mut self, media_type: &MediaType) -> Result<(), String> {
        self.stop();
        *lock(&self.samples) = Samples::default();
        self.capture = Some(win::Capture::open(
            &self.link,
            *media_type,
            self.samples.clone(),
        )?);
        Ok(())
    }

    #[cfg(not(windows))]
    fn start(&mut self, _media_type: &MediaType) -> Result<(), String> {
        Err("no camera capture on this platform".into())
    }

    fn sample(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut s = lock(&self.samples);
        if let Some(e) = s.failed.take() {
            return Err(e);
        }
        Ok(s.queue.pop_front())
    }

    fn stop(&mut self) {
        // Capture::drop shuts the media source down, releasing the camera.
        #[cfg(windows)]
        {
            self.capture = None;
        }
        *lock(&self.samples) = Samples::default();
    }
}

#[cfg(windows)]
mod win {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use rdp::camera::{MediaType, VideoFormat};
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
    };
    use windows::core::{GUID, Interface, PWSTR};

    use super::{LocalCamera, SharedSamples, describe, lock, push_unique};

    /// How long the session waits for Media Foundation to list or open a
    /// camera before it gives up (a hung driver must not stall it).
    const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

    /// How long [`Capture::drop`] waits for the capture thread to finish
    /// after the source was shut down.
    const STOP_WAIT: Duration = Duration::from_millis(300);

    fn err(what: &str, e: windows::core::Error) -> String {
        format!("Media Foundation {what}: {e}")
    }

    /// COM (multithreaded apartment) and Media Foundation, started for as
    /// long as this lives on the current thread.
    struct Started {
        com_init: bool,
    }

    impl Started {
        fn new() -> Result<Self, String> {
            // SAFETY: plain initialisation calls, balanced in drop.
            unsafe {
                let com_init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
                if let Err(e) = MFStartup(MF_VERSION, MFSTARTUP_LITE) {
                    if com_init {
                        CoUninitialize();
                    }
                    return Err(err("startup", e));
                }
                Ok(Started { com_init })
            }
        }
    }

    impl Drop for Started {
        fn drop(&mut self) {
            // SAFETY: balances the MFStartup and CoInitializeEx in new.
            unsafe {
                let _ = MFShutdown();
                if self.com_init {
                    CoUninitialize();
                }
            }
        }
    }

    /// Runs `f` on a thread with Media Foundation started and waits up to
    /// [`OPEN_TIMEOUT`] for its answer.
    fn on_mf_thread<T: Send + 'static>(
        what: &str,
        f: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name(format!("camera {what}"))
            .spawn(move || {
                let r = Started::new().and_then(|_mf| f());
                let _ = tx.send(r);
            })
            .map_err(|e| format!("camera {what}: {e}"))?;
        rx.recv_timeout(OPEN_TIMEOUT)
            .map_err(|_| format!("camera {what}: no answer from Media Foundation"))?
    }

    /// A string attribute of an activation object.
    fn string(a: &IMFActivate, key: &GUID) -> Option<String> {
        let mut p = PWSTR::null();
        let mut len = 0u32;
        // SAFETY: GetAllocatedString hands back a CoTaskMemAlloc'd,
        // NUL-terminated string of `len` characters, freed here.
        unsafe {
            a.GetAllocatedString(key, &mut p, &mut len).ok()?;
            let s = p.to_string().ok();
            CoTaskMemFree(Some(p.0 as *const _));
            s
        }
    }

    /// Attributes selecting video capture devices.
    fn video_attributes(link: Option<&str>) -> Result<IMFAttributes, String> {
        let mut attrs = None;
        // SAFETY: plain attribute store calls on a new store.
        unsafe {
            MFCreateAttributes(&mut attrs, 2).map_err(|e| err("attributes", e))?;
            let attrs = attrs.ok_or("Media Foundation attributes: none")?;
            attrs
                .SetGUID(
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
                )
                .map_err(|e| err("attributes", e))?;
            if let Some(link) = link {
                attrs
                    .SetString(
                        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                        &windows::core::HSTRING::from(link),
                    )
                    .map_err(|e| err("attributes", e))?;
            }
            Ok(attrs)
        }
    }

    pub fn list() -> Vec<LocalCamera> {
        on_mf_thread("list", || {
            let attrs = video_attributes(None)?;
            let mut array: *mut Option<IMFActivate> = std::ptr::null_mut();
            let mut count = 0u32;
            // SAFETY: MFEnumDeviceSources fills an array of `count`
            // activation objects allocated with CoTaskMemAlloc; each is
            // moved out once, then the array is freed. No object is
            // activated, so no device is opened.
            unsafe {
                MFEnumDeviceSources(&attrs, &mut array, &mut count)
                    .map_err(|e| err("device list", e))?;
                if array.is_null() {
                    return Ok(Vec::new());
                }
                let activates: Vec<IMFActivate> = (0..count as usize)
                    .filter_map(|i| std::ptr::read(array.add(i)))
                    .collect();
                CoTaskMemFree(Some(array as *const _));
                Ok(activates
                    .iter()
                    .filter_map(|a| {
                        let link =
                            string(a, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK)?;
                        let name = string(a, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME)
                            .unwrap_or_else(|| "Camera".into());
                        Some(LocalCamera { name, link })
                    })
                    .collect())
            }
        })
        .unwrap_or_default()
    }

    /// The camera's media source and a source reader on it, without
    /// format converters (samples come as the camera makes them).
    fn open(link: &str) -> Result<(IMFMediaSource, IMFSourceReader), String> {
        // SAFETY: Media Foundation calls with valid attribute stores.
        unsafe {
            let source = MFCreateDeviceSource(&video_attributes(Some(link))?)
                .map_err(|e| err("open camera", e))?;
            let mut attrs = None;
            MFCreateAttributes(&mut attrs, 1).map_err(|e| err("attributes", e))?;
            let attrs = attrs.ok_or("Media Foundation attributes: none")?;
            attrs
                .SetUINT32(&MF_READWRITE_DISABLE_CONVERTERS, 1)
                .map_err(|e| err("attributes", e))?;
            match MFCreateSourceReaderFromMediaSource(&source, &attrs) {
                Ok(reader) => Ok((source, reader)),
                Err(e) => {
                    let _ = source.Shutdown();
                    Err(err("source reader", e))
                }
            }
        }
    }

    fn format_of(subtype: &GUID) -> Option<VideoFormat> {
        Some(match *subtype {
            s if s == MFVideoFormat_H264 => VideoFormat::H264,
            s if s == MFVideoFormat_MJPG => VideoFormat::Mjpg,
            s if s == MFVideoFormat_YUY2 => VideoFormat::Yuy2,
            s if s == MFVideoFormat_NV12 => VideoFormat::Nv12,
            s if s == MFVideoFormat_I420 || s == MFVideoFormat_IYUV => VideoFormat::I420,
            s if s == MFVideoFormat_RGB24 => VideoFormat::Rgb24,
            s if s == MFVideoFormat_RGB32 => VideoFormat::Rgb32,
            _ => return None,
        })
    }

    /// A native media type as MS-RDPECAM describes it.
    fn describe_native(t: &IMFMediaType) -> Option<MediaType> {
        // SAFETY: attribute reads on a valid media type.
        unsafe {
            let format = format_of(&t.GetGUID(&MF_MT_SUBTYPE).ok()?)?;
            let size = t.GetUINT64(&MF_MT_FRAME_SIZE).ok()?;
            let rate = t.GetUINT64(&MF_MT_FRAME_RATE).ok();
            let aspect = t.GetUINT64(&MF_MT_PIXEL_ASPECT_RATIO).ok();
            let stride = t.GetUINT32(&MF_MT_DEFAULT_STRIDE).ok().map(|s| s as i32);
            describe(format, size, rate, aspect, stride)
        }
    }

    /// The camera's native types with their index, in the camera's order.
    fn native_types(reader: &IMFSourceReader) -> Vec<(u32, IMFMediaType)> {
        let stream = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
        (0..1024)
            // SAFETY: indexes until MF_E_NO_MORE_TYPES.
            .map_while(|i| {
                unsafe { reader.GetNativeMediaType(stream, i) }
                    .ok()
                    .map(|t| (i, t))
            })
            .collect()
    }

    pub fn media_types(link: &str) -> Result<Vec<MediaType>, String> {
        let link = link.to_string();
        on_mf_thread("formats", move || {
            let (source, reader) = open(&link)?;
            let mut list = Vec::new();
            for (_, t) in native_types(&reader) {
                if let Some(d) = describe_native(&t) {
                    push_unique(&mut list, d);
                }
            }
            drop(reader);
            // SAFETY: releases the device; the reader is gone.
            unsafe {
                let _ = source.Shutdown();
            }
            Ok(list)
        })
    }

    /// The media source, handed to the session thread so it can shut the
    /// camera down while the capture thread waits for a frame.
    struct SourceHandle(IMFMediaSource);

    // SAFETY: Media Foundation media sources are free-threaded; the
    // session thread only calls Shutdown, which may be called from any
    // thread and makes a pending ReadSample return.
    unsafe impl Send for SourceHandle {}

    /// A running capture: a thread reading samples into the shared queue.
    pub struct Capture {
        source: SourceHandle,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Capture {
        /// Opens the camera in `wanted` (one of [`media_types`]) and starts
        /// reading; returns once the first read is under way.
        pub fn open(link: &str, wanted: MediaType, samples: SharedSamples) -> Result<Self, String> {
            let (tx, rx) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let link = link.to_string();
            let flag = stop.clone();
            let thread = std::thread::Builder::new()
                .name("camera capture".into())
                .spawn(move || run(&link, wanted, &samples, &flag, &tx))
                .map_err(|e| format!("camera capture: {e}"))?;
            match rx.recv_timeout(OPEN_TIMEOUT) {
                Ok(Ok(source)) => Ok(Capture {
                    source,
                    stop,
                    thread: Some(thread),
                }),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    stop.store(true, Ordering::Relaxed);
                    Err("camera capture: no answer from Media Foundation".into())
                }
            }
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // SAFETY: Shutdown releases the device at once and ends a
            // ReadSample that waits for a frame.
            unsafe {
                let _ = self.source.0.Shutdown();
            }
            if let Some(t) = self.thread.take() {
                let until = Instant::now() + STOP_WAIT;
                while !t.is_finished() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(2));
                }
                if t.is_finished() {
                    let _ = t.join();
                }
            }
        }
    }

    /// The capture thread: opens the camera, then reads samples until
    /// stopped or the camera fails.
    fn run(
        link: &str,
        wanted: MediaType,
        samples: &SharedSamples,
        stop: &AtomicBool,
        ready: &mpsc::Sender<Result<SourceHandle, String>>,
    ) {
        let _mf = match Started::new() {
            Ok(s) => s,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let (source, reader) = match open(link) {
            Ok(v) => v,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let stream = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
        let native = native_types(&reader)
            .into_iter()
            .find(|(_, t)| describe_native(t).is_some_and(|d| d.same_format(&wanted)));
        // SAFETY: Media Foundation calls on the reader this thread owns.
        let set = unsafe {
            match native {
                Some((_, t)) => reader
                    .SetStreamSelection(MF_SOURCE_READER_ALL_STREAMS.0 as u32, false)
                    .and_then(|_| reader.SetStreamSelection(stream, true))
                    .and_then(|_| reader.SetCurrentMediaType(stream, None, &t))
                    .map_err(|e| err("set format", e)),
                None => Err("camera: the format is no longer offered".into()),
            }
        };
        if let Err(e) = set {
            drop(reader);
            // SAFETY: releases the device.
            unsafe {
                let _ = source.Shutdown();
            }
            let _ = ready.send(Err(e));
            return;
        }
        if ready.send(Ok(SourceHandle(source.clone()))).is_err() {
            // The session gave up waiting.
            // SAFETY: releases the device.
            unsafe {
                let _ = source.Shutdown();
            }
            return;
        }
        let h264 = wanted.format == VideoFormat::H264;
        while !stop.load(Ordering::Relaxed) {
            let mut flags = 0u32;
            let mut sample = None;
            // SAFETY: a synchronous read on this thread's reader.
            let read = unsafe {
                reader.ReadSample(stream, 0, None, Some(&mut flags), None, Some(&mut sample))
            };
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let failed = match read {
                Err(e) => Some(err("read", e)),
                Ok(()) if flags & MF_SOURCE_READERF_ERROR.0 as u32 != 0 => {
                    Some("camera: stream error".to_string())
                }
                Ok(()) if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 => {
                    Some("camera: stream ended".to_string())
                }
                Ok(()) => None,
            };
            if let Some(e) = failed {
                lock(samples).failed = Some(e);
                break;
            }
            let Some(sample) = sample else { continue };
            match bytes(&sample) {
                Ok(data) => {
                    // SAFETY: attribute read on a valid sample.
                    let key = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }
                        .is_ok_and(|v| v != 0);
                    lock(samples).push(h264, data, key);
                }
                Err(e) => {
                    lock(samples).failed = Some(e);
                    break;
                }
            }
        }
        drop(reader);
        // SAFETY: releases the device (a second Shutdown is harmless).
        unsafe {
            let _ = source.Shutdown();
        }
    }

    /// A sample's bytes in their contiguous form: rows without padding for
    /// uncompressed formats, in the format's own row order.
    fn bytes(sample: &IMFSample) -> Result<Vec<u8>, String> {
        // SAFETY: each buffer stays locked while it is read, and the
        // lengths Media Foundation reports bound every access.
        unsafe {
            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(|e| err("buffer", e))?;
            if let Ok(b2) = buffer.cast::<IMF2DBuffer>() {
                let len = b2.GetContiguousLength().map_err(|e| err("buffer", e))?;
                let mut data = vec![0u8; len as usize];
                b2.ContiguousCopyTo(&mut data)
                    .map_err(|e| err("buffer", e))?;
                return Ok(data);
            }
            let mut p = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut p, None, Some(&mut len))
                .map_err(|e| err("lock", e))?;
            let data = std::slice::from_raw_parts(p, len as usize).to_vec();
            let _ = buffer.Unlock();
            Ok(data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn subtypes_map_to_the_spec_formats() {
            assert_eq!(format_of(&MFVideoFormat_H264), Some(VideoFormat::H264));
            assert_eq!(format_of(&MFVideoFormat_MJPG), Some(VideoFormat::Mjpg));
            assert_eq!(format_of(&MFVideoFormat_YUY2), Some(VideoFormat::Yuy2));
            assert_eq!(format_of(&MFVideoFormat_NV12), Some(VideoFormat::Nv12));
            assert_eq!(format_of(&MFVideoFormat_I420), Some(VideoFormat::I420));
            assert_eq!(format_of(&MFVideoFormat_IYUV), Some(VideoFormat::I420));
            assert_eq!(format_of(&MFVideoFormat_RGB24), Some(VideoFormat::Rgb24));
            assert_eq!(format_of(&MFVideoFormat_RGB32), Some(VideoFormat::Rgb32));
            // Formats MS-RDPECAM cannot carry are not offered.
            assert_eq!(format_of(&MFVideoFormat_HEVC), None);
            assert_eq!(format_of(&MFVideoFormat_YV12), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::CameraBackend;
    use rdp::camera::MEDIA_FLAG_DECODING_REQUIRED;

    // No camera is opened or listed here except in the ignored live test.

    fn pack(a: u32, b: u32) -> u64 {
        (u64::from(a) << 32) | u64::from(b)
    }

    #[test]
    fn native_types_are_described_for_the_spec() {
        let t = describe(
            VideoFormat::Mjpg,
            pack(1280, 720),
            Some(pack(30, 1)),
            None,
            None,
        )
        .unwrap();
        assert_eq!(t, MediaType::new(VideoFormat::Mjpg, 1280, 720, 30, 1));
        assert_eq!(t.flags, MEDIA_FLAG_DECODING_REQUIRED);
        let t = describe(
            VideoFormat::Yuy2,
            pack(640, 480),
            Some(pack(30_000, 1001)),
            Some(pack(4, 3)),
            Some(1280),
        )
        .unwrap();
        assert_eq!(
            (t.frame_rate_numerator, t.frame_rate_denominator),
            (30_000, 1001)
        );
        assert_eq!(
            (
                t.pixel_aspect_ratio_numerator,
                t.pixel_aspect_ratio_denominator
            ),
            (4, 3)
        );
        assert_eq!(t.flags, 0);
        // Negative stride: bottom-up RGB.
        let t = describe(VideoFormat::Rgb32, pack(320, 240), None, None, Some(-1280)).unwrap();
        assert_eq!(t.flags, MEDIA_FLAG_BOTTOM_UP_IMAGE);
        assert_eq!((t.frame_rate_numerator, t.frame_rate_denominator), (30, 1));
        // Zero sizes are no format; zero rates fall back to 30 fps.
        assert!(describe(VideoFormat::Nv12, pack(0, 480), None, None, None).is_none());
        let t = describe(
            VideoFormat::Nv12,
            pack(640, 480),
            Some(pack(0, 0)),
            None,
            None,
        )
        .unwrap();
        assert_eq!(t.frame_rate_numerator, 30);
    }

    #[test]
    fn duplicate_formats_are_listed_once() {
        let mut list = Vec::new();
        let a = MediaType::new(VideoFormat::Nv12, 640, 480, 30, 1);
        push_unique(&mut list, a);
        push_unique(&mut list, MediaType { flags: 2, ..a });
        push_unique(
            &mut list,
            MediaType::new(VideoFormat::Nv12, 640, 480, 15, 1),
        );
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn uncompressed_samples_keep_only_the_newest() {
        let mut s = Samples::default();
        s.push(false, vec![1], false);
        s.push(false, vec![2], false);
        assert_eq!(s.queue, [vec![2]]);
    }

    #[test]
    fn h264_samples_queue_and_overflow_to_the_next_key_frame() {
        let mut s = Samples::default();
        s.push(true, vec![0], true);
        for i in 1..H264_BACKLOG {
            s.push(true, vec![i as u8], false);
        }
        assert_eq!(s.queue.len(), H264_BACKLOG);
        // Full: a delta frame drops the backlog and everything up to the
        // next key frame.
        s.push(true, vec![100], false);
        assert!(s.queue.is_empty());
        s.push(true, vec![101], false);
        assert!(s.queue.is_empty());
        s.push(true, vec![102], true);
        s.push(true, vec![103], false);
        assert_eq!(s.queue, [vec![102], vec![103]]);
    }

    #[test]
    fn chosen_cameras_follow_the_setting() {
        let cams = vec!["Front".to_string(), "USB".to_string()];
        assert!(chosen(&cams, false, None).is_empty());
        assert_eq!(chosen(&cams, true, None), [0, 1]);
        assert_eq!(chosen(&cams, true, Some("USB")), [1]);
        assert!(chosen(&cams, true, Some("Gone")).is_empty());
    }

    #[test]
    fn closed_backend_has_nothing_and_reports_a_failure_once() {
        let mut cam = MfCamera::new(r"\\?\no-such-camera");
        assert_eq!(cam.sample(), Ok(None));
        lock(&cam.samples).failed = Some("lost".into());
        assert_eq!(cam.sample(), Err("lost".into()));
        assert_eq!(cam.sample(), Ok(None));
        cam.stop();
    }

    /// Opens this PC's first camera, reads its formats and captures one
    /// sample in the first format. Never run automatically: it turns the
    /// owner's camera on. The owner runs it with
    /// `cargo test -p remora live_camera -- --ignored --nocapture`.
    #[test]
    #[ignore = "opens the real camera"]
    fn live_camera_first_device() {
        let cams = list();
        println!("cameras: {cams:?}");
        let cam = cams.first().expect("no camera on this PC");
        let mut backend = MfCamera::new(&cam.link);
        let types = backend.media_types().unwrap();
        for t in &types {
            println!(
                "  {} {}x{} {}/{} fps flags {:#x}",
                t.format.name(),
                t.width,
                t.height,
                t.frame_rate_numerator,
                t.frame_rate_denominator,
                t.flags
            );
        }
        backend.start(&types[0]).unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = None;
        while got.is_none() && std::time::Instant::now() < until {
            got = backend.sample().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        backend.stop();
        let sample = got.expect("no sample within 5 seconds");
        println!("sample of {} bytes", sample.len());
        assert!(!sample.is_empty());
    }
}
