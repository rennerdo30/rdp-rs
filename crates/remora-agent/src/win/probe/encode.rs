//! Encode benchmark for `capture-probe` (RDP-67, second step): how fast and
//! how small can this server's encoders make the session's picture?
//!
//! The source is the desktop the probe just captured, scrolled by 12 rows
//! per frame, so every frame changes everywhere (the hard case, like
//! scrolling a page) while the content is real. Frames are fed at 60 fps:
//!
//! - GPU path (hardware encoders): the Direct3D 11 video processor turns
//!   the BGRA frame into NV12 on the GPU and the encoder reads the texture
//!   through Media Foundation's DXGI device manager; nothing goes through
//!   the CPU.
//! - CPU path (software encoders, or no video processor): the frame is read
//!   back and converted to NV12 on the CPU.
//!
//! Each encoder runs in low-latency mode at a fixed bitrate. Measured per
//! encoder: frames out of frames in, latency from starting the frame to its
//! bitstream (conversion included), frame sizes, keyframes, bitrate, and
//! frames the encoder was too slow to take. Nothing is sent anywhere; the
//! bitstream is dropped.

use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{LUID, RECT};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_BIND_VIDEO_ENCODER, D3D11_BOX,
    D3D11_CPU_ACCESS_READ, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_TEX2D_VPIV,
    D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
    D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
    ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice, ID3D11VideoProcessor,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncMPVDefaultBPictureCount, CODECAPI_AVEncMPVGOPSize, CODECAPI_AVLowLatencyMode,
    ICodecAPI, IMF2DBuffer, IMFActivate, IMFDXGIDeviceManager, IMFMediaBuffer,
    IMFMediaEventGenerator, IMFSample, IMFTransform, METransformDrainComplete,
    METransformHaveOutput, METransformNeedInput, MF_E_NO_EVENTS_AVAILABLE,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT,
    MF_LOW_LATENCY, MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE,
    MF_MT_MAJOR_TYPE, MF_MT_MPEG2_PROFILE, MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MF_TRANSFORM_ASYNC,
    MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION, MFCreateDXGIDeviceManager, MFCreateDXGISurfaceBuffer,
    MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFSTARTUP_NOSOCKET,
    MFSampleExtension_CleanPoint, MFShutdown, MFStartup, MFT_CATEGORY_VIDEO_ENCODER,
    MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_COMMAND_DRAIN,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_END_STREAMING, MFT_MESSAGE_NOTIFY_START_OF_STREAM,
    MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_AV1,
    MFVideoFormat_H264, MFVideoFormat_HEVC, MFVideoFormat_NV12, MFVideoInterlace_Progressive,
};
use windows::Win32::Media::MediaFoundation::{MFCreateAttributes, MFTEnum2};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};
use windows::core::{GUID, Interface};

/// Seconds each encoder runs.
const SECONDS: u64 = 5;
const FPS: u32 = 60;
/// Rows the source scrolls per frame.
const SCROLL: u32 = 12;
/// 100-ns units per frame.
const FRAME_TICKS: i64 = 10_000_000 / FPS as i64;
/// NV12 textures the GPU path rotates through, so the converter never
/// overwrites a frame an asynchronous encoder may still be reading.
const RING: usize = 4;

/// One encoder MF offers.
pub(super) struct Found {
    pub name: String,
    pub activate: IMFActivate,
    /// The adapter it was enumerated for (`MFTEnum2` with
    /// `MFT_ENUM_ADAPTER_LUID`); `None` from the adapter-blind `MFTEnumEx`.
    pub luid: Option<u64>,
}

/// An adapter LUID as the probe prints it.
pub(super) fn luid_str(luid: u64) -> String {
    format!("{:x}:{:08x}", luid >> 32, luid as u32)
}

/// Packs a LUID like its memory layout, the form MF stores it in.
pub(super) fn pack_luid(l: LUID) -> u64 {
    ((l.HighPart as u32 as u64) << 32) | l.LowPart as u64
}

/// The encoders MF offers for `subtype`; with `adapter`, only the hardware
/// encoders of that adapter (a GPU's encoder needs the textures of its own
/// GPU; a server can list one encoder per adapter, or one for another GPU).
pub(super) fn list(
    subtype: GUID,
    hardware: bool,
    nv12_input: bool,
    adapter: Option<u64>,
) -> Vec<Found> {
    let flags = if hardware {
        MFT_ENUM_FLAG_HARDWARE.0 | MFT_ENUM_FLAG_SORTANDFILTER.0
    } else {
        MFT_ENUM_FLAG_SYNCMFT.0 | MFT_ENUM_FLAG_SORTANDFILTER.0
    };
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: subtype,
    };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut n = 0u32;
    let mut out = Vec::new();
    // SAFETY: MF fills the array; every entry is moved out once and the
    // array freed.
    unsafe {
        let input = nv12_input.then_some(&input as *const _);
        let found = match adapter {
            Some(luid) => {
                let mut attrs = None;
                if MFCreateAttributes(&mut attrs, 1).is_err() {
                    return out;
                }
                let Some(attrs) = attrs else { return out };
                if attrs
                    .SetBlob(&MFT_ENUM_ADAPTER_LUID, &luid.to_le_bytes())
                    .is_err()
                {
                    return out;
                }
                MFTEnum2(
                    MFT_CATEGORY_VIDEO_ENCODER,
                    MFT_ENUM_FLAG(flags),
                    input,
                    Some(&output),
                    &attrs,
                    &mut list,
                    &mut n,
                )
            }
            None => MFTEnumEx(
                MFT_CATEGORY_VIDEO_ENCODER,
                MFT_ENUM_FLAG(flags),
                input,
                Some(&output),
                &mut list,
                &mut n,
            ),
        };
        if found.is_err() {
            return out;
        }
        for i in 0..n as usize {
            if let Some(a) = std::ptr::read(list.add(i)) {
                let mut buf = [0u16; 256];
                let mut len = 0u32;
                let name = if a
                    .GetString(&MFT_FRIENDLY_NAME_Attribute, &mut buf, Some(&mut len))
                    .is_ok()
                {
                    String::from_utf16_lossy(&buf[..len as usize])
                } else {
                    "(unnamed)".into()
                };
                out.push(Found {
                    name,
                    activate: a,
                    luid: adapter,
                });
            }
        }
        CoTaskMemFree(Some(list as *const _));
    }
    out
}

/// Runs the benchmark on the captured frame `snapshot` and appends the
/// report.
pub(super) fn run(
    device: &ID3D11Device,
    context: &ID3D11DeviceContext,
    snapshot: &ID3D11Texture2D,
    r: &mut String,
) {
    // SAFETY: COM and MF start-up for this thread; MF is shut down below.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        if let Err(e) = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) {
            *r += &format!("encode: Media Foundation did not start: {e}\n");
            return;
        }
    }
    match Bench::new(device, context, snapshot) {
        Ok(b) => b.all(r),
        Err(e) => *r += &format!("encode: {e}\n"),
    }
    // SAFETY: matches the MFStartup above; every MF object is gone by now.
    let _ = unsafe { MFShutdown() };
}

struct Bench {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    snapshot: ID3D11Texture2D,
    /// The scrolled frame the converters read.
    source: ID3D11Texture2D,
    size: (u32, u32),
    /// The encoded size: even width and height.
    even: (u32, u32),
    gpu: Result<Gpu, String>,
    cpu: Option<Cpu>,
    manager: Option<IMFDXGIDeviceManager>,
    bitrate: u32,
    /// The adapter the captured picture is on.
    luid: Option<u64>,
}

fn err(what: &str, e: windows::core::Error) -> String {
    format!("{what}: {e}")
}

impl Bench {
    fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        snapshot: &ID3D11Texture2D,
    ) -> Result<Bench, String> {
        // SAFETY: D3D11 and MF calls on valid objects; out pointers to locals.
        unsafe {
            // The encoder uses the device from its own threads.
            if let Ok(mt) = device.cast::<ID3D11Multithread>() {
                let _ = mt.SetMultithreadProtected(true);
            }
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            snapshot.GetDesc(&mut desc);
            let size = (desc.Width, desc.Height);
            let even = (desc.Width & !1, desc.Height & !1);
            let s = D3D11_TEXTURE2D_DESC {
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
                MipLevels: 1,
                ArraySize: 1,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                ..desc
            };
            let mut source = None;
            device
                .CreateTexture2D(&s, None, Some(&mut source))
                .map_err(|e| err("source texture", e))?;
            let source = source.ok_or("source texture: none")?;
            let gpu = Gpu::new(device, context, &source, size, even);
            let mut token = 0u32;
            let mut manager = None;
            if MFCreateDXGIDeviceManager(&mut token, &mut manager).is_ok()
                && let Some(m) = &manager
                && m.ResetDevice(device, token).is_err()
            {
                manager = None;
            }
            // About 0.05 bit per pixel at 60 fps: 22 Mbit/s for 3688x1984,
            // 3 Mbit/s for 1280x800.
            let bitrate = ((even.0 as f64 * even.1 as f64 * FPS as f64 * 0.05) as u32)
                .clamp(2_000_000, 50_000_000);
            let luid = device
                .cast::<IDXGIDevice>()
                .and_then(|d| d.GetAdapter())
                .and_then(|a| a.GetDesc())
                .ok()
                .map(|d| pack_luid(d.AdapterLuid));
            Ok(Bench {
                device: device.clone(),
                context: context.clone(),
                snapshot: snapshot.clone(),
                source,
                size,
                even,
                gpu,
                cpu: None,
                manager,
                bitrate,
                luid,
            })
        }
    }

    fn all(mut self, r: &mut String) {
        *r += &format!(
            "encode: {}x{} scrolling {SCROLL} rows per frame at {FPS} fps, {:.1} Mbit/s, low-latency mode, {SECONDS} s each\n",
            self.even.0,
            self.even.1,
            self.bitrate as f64 / 1e6
        );
        match &self.gpu {
            Ok(_) => *r += "  conversion to NV12: GPU (Direct3D 11 video processor)\n",
            Err(e) => *r += &format!("  conversion to NV12: CPU (no GPU video processor: {e})\n"),
        }
        if let Some(l) = self.luid {
            *r += &format!("  captured on adapter {}\n", luid_str(l));
        }
        let mut any_hw = false;
        for (codec, subtype) in [
            ("H.264", MFVideoFormat_H264),
            ("HEVC", MFVideoFormat_HEVC),
            ("AV1", MFVideoFormat_AV1),
        ] {
            // The encoders of the capture's adapter; only when it has none
            // (or Windows cannot tell), every hardware encoder.
            let mut hw = match self.luid {
                Some(l) => list(subtype, true, true, Some(l)),
                None => Vec::new(),
            };
            if hw.is_empty() {
                hw = list(subtype, true, true, None);
            }
            if hw.is_empty() {
                continue;
            }
            any_hw = true;
            // A failure on the GPU path is retried with frames from the CPU,
            // so the report tells an encoder that cannot share our textures
            // from one that cannot run at all.
            let mut lines = Vec::new();
            for f in &hw {
                let label = match f.luid {
                    Some(_) => format!("{} [capture adapter]", f.name),
                    None => format!("{} [any adapter]", f.name),
                };
                let gpu = self.one(codec, subtype, &f.activate, true);
                // SAFETY: releases what ActivateObject created; the activation
                // can create a fresh object afterwards.
                let _ = unsafe { f.activate.ShutdownObject() };
                match gpu {
                    Ok(line) => {
                        lines = vec![format!("  {codec} hardware {label}: {line}\n")];
                        break;
                    }
                    Err(e) => {
                        lines.push(format!("  {codec} hardware {label} failed: {e}\n"));
                        let cpu = self.one(codec, subtype, &f.activate, false);
                        // SAFETY: as above.
                        let _ = unsafe { f.activate.ShutdownObject() };
                        match cpu {
                            Ok(line) => {
                                lines.push(format!(
                                    "  {codec} hardware {label} with CPU input: {line}\n"
                                ));
                                break;
                            }
                            Err(e) => lines.push(format!(
                                "  {codec} hardware {label} with CPU input failed: {e}\n"
                            )),
                        }
                    }
                }
            }
            for l in lines {
                *r += &l;
            }
        }
        if !any_hw {
            // Without hardware, measure the software H.264 encoder: the CPU
            // path a server without a GPU would have.
            match list(MFVideoFormat_H264, false, true, None).first() {
                Some(f) => {
                    let res = self.one("H.264", MFVideoFormat_H264, &f.activate, false);
                    // SAFETY: releases what ActivateObject created.
                    let _ = unsafe { f.activate.ShutdownObject() };
                    match res {
                        Ok(line) => *r += &format!("  H.264 software {}: {line}\n", f.name),
                        Err(e) => *r += &format!("  H.264 software {} failed: {e}\n", f.name),
                    }
                }
                None => *r += "  no H.264 encoder\n",
            }
        }
    }

    /// Copies the snapshot into `source`, scrolled by `i * SCROLL` rows.
    fn scroll(&self, i: u64) {
        let (w, h) = self.size;
        let s = ((i * SCROLL as u64) % h as u64) as u32;
        // SAFETY: copies between two textures of the same size and format.
        unsafe {
            if s == 0 {
                self.context.CopyResource(&self.source, &self.snapshot);
                return;
            }
            let lower = D3D11_BOX {
                left: 0,
                top: s,
                front: 0,
                right: w,
                bottom: h,
                back: 1,
            };
            self.context.CopySubresourceRegion(
                &self.source,
                0,
                0,
                0,
                0,
                &self.snapshot,
                0,
                Some(&lower),
            );
            let upper = D3D11_BOX {
                left: 0,
                top: 0,
                front: 0,
                right: w,
                bottom: s,
                back: 1,
            };
            self.context.CopySubresourceRegion(
                &self.source,
                0,
                0,
                h - s,
                0,
                &self.snapshot,
                0,
                Some(&upper),
            );
        }
    }

    /// The NV12 sample for frame `i` on the GPU or CPU path.
    fn frame(&mut self, i: u64, on_gpu: bool) -> Result<IMFSample, String> {
        self.scroll(i);
        // SAFETY: MF and D3D11 calls on valid objects.
        unsafe {
            let buffer: IMFMediaBuffer = if on_gpu {
                let Ok(gpu) = &self.gpu else {
                    return Err("no GPU converter".into());
                };
                let tex = gpu.convert(i as usize % RING)?;
                let b = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, tex, 0, false)
                    .map_err(|e| err("DXGI surface buffer", e))?;
                if let Ok(b2) = b.cast::<IMF2DBuffer>()
                    && let Ok(len) = b2.GetContiguousLength()
                {
                    let _ = b.SetCurrentLength(len);
                }
                b
            } else {
                if self.cpu.is_none() {
                    self.cpu = Some(Cpu::new(&self.device, &self.source)?);
                }
                let Some(cpu) = &self.cpu else {
                    return Err("no CPU converter".into());
                };
                cpu.convert(&self.context, &self.source, self.even)?
            };
            let sample = MFCreateSample().map_err(|e| err("sample", e))?;
            sample
                .AddBuffer(&buffer)
                .map_err(|e| err("sample buffer", e))?;
            let t = i as i64 * FRAME_TICKS;
            let _ = sample.SetSampleTime(t);
            let _ = sample.SetSampleDuration(FRAME_TICKS);
            Ok(sample)
        }
    }

    /// Sets up the encoder behind `a` and measures it; returns the report
    /// line.
    fn one(
        &mut self,
        codec: &str,
        subtype: GUID,
        a: &IMFActivate,
        use_gpu: bool,
    ) -> Result<String, String> {
        // SAFETY: MF calls on the transform this function owns.
        let enc = unsafe { Encoder::new(a, codec, subtype, self, use_gpu)? };
        let on_gpu = enc.d3d;
        let mut stats = Stats::default();
        let result = self.drive(&enc, on_gpu, &mut stats);
        // SAFETY: ends streaming on our transform.
        unsafe {
            let _ = enc.t.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        result?;
        Ok(stats.line(on_gpu, &enc.refused))
    }

    fn drive(&mut self, enc: &Encoder, on_gpu: bool, st: &mut Stats) -> Result<(), String> {
        let frame = Duration::from_nanos(1_000_000_000 / FPS as u64);
        let start = Instant::now();
        let end = start + Duration::from_secs(SECONDS);
        let mut due = start;
        let mut need = 0u32;
        let mut i = 0u64;
        let mut sent: HashMap<i64, Instant> = HashMap::new();
        loop {
            let now = Instant::now();
            if now >= end {
                break;
            }
            if let Some(ev) = &enc.events {
                // SAFETY: event queue of our asynchronous transform.
                unsafe {
                    loop {
                        match ev.GetEvent(MF_EVENT_FLAG_NO_WAIT) {
                            Ok(e) => {
                                let ty = e.GetType().unwrap_or(0);
                                if ty == METransformNeedInput.0 as u32 {
                                    need += 1;
                                } else if ty == METransformHaveOutput.0 as u32 {
                                    enc.output(&mut sent, st)?;
                                }
                            }
                            Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => break,
                            Err(e) => return Err(err("encoder event", e)),
                        }
                    }
                }
            }
            if now >= due && (enc.events.is_none() || need > 0) {
                // Frames the encoder was too slow to take are skipped, as a
                // live stream would.
                while due + frame <= now {
                    due += frame;
                    st.missed += 1;
                }
                let t0 = Instant::now();
                let sample = self.frame(i, on_gpu)?;
                st.prepare += t0.elapsed().as_secs_f64() * 1000.0;
                sent.insert(i as i64 * FRAME_TICKS, t0);
                // SAFETY: input for our transform.
                unsafe { enc.t.ProcessInput(0, &sample, 0) }.map_err(|e| err("ProcessInput", e))?;
                st.input += 1;
                need = need.saturating_sub(1);
                i += 1;
                due += frame;
                if enc.events.is_none() {
                    enc.output(&mut sent, st)?;
                }
            }
            std::thread::sleep(Duration::from_micros(300));
        }
        // Drain what is still inside the encoder.
        // SAFETY: messages and events of our transform.
        unsafe {
            let _ = enc.t.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = enc.t.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
            match &enc.events {
                None => enc.output(&mut sent, st)?,
                Some(ev) => {
                    let stop = Instant::now() + Duration::from_secs(1);
                    while Instant::now() < stop {
                        match ev.GetEvent(MF_EVENT_FLAG_NO_WAIT) {
                            Ok(e) => {
                                let ty = e.GetType().unwrap_or(0);
                                if ty == METransformHaveOutput.0 as u32 {
                                    enc.output(&mut sent, st)?;
                                } else if ty == METransformDrainComplete.0 as u32 {
                                    break;
                                }
                            }
                            Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        st.seconds = start.elapsed().as_secs_f64();
        Ok(())
    }
}

/// One activated encoder, set up for low-latency streaming.
struct Encoder {
    t: IMFTransform,
    events: Option<IMFMediaEventGenerator>,
    /// Reads Direct3D 11 textures (the GPU path).
    d3d: bool,
    provides_samples: bool,
    out_size: u32,
    /// Settings the encoder refused (it runs with its defaults there).
    refused: Vec<String>,
}

fn variant_u32(v: u32) -> VARIANT {
    let mut x = VARIANT::default();
    // SAFETY: writes the tag and the matching union member.
    unsafe {
        let inner = &mut *x.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = v;
    }
    x
}

fn variant_bool(v: bool) -> VARIANT {
    let mut x = VARIANT::default();
    // SAFETY: writes the tag and the matching union member.
    unsafe {
        let inner = &mut *x.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = windows::Win32::Foundation::VARIANT_BOOL(if v { -1 } else { 0 });
    }
    x
}

impl Encoder {
    /// # Safety
    /// MF must be started on this thread.
    unsafe fn new(
        a: &IMFActivate,
        codec: &str,
        subtype: GUID,
        b: &Bench,
        use_gpu: bool,
    ) -> Result<Encoder, String> {
        unsafe {
            let t: IMFTransform = a.ActivateObject().map_err(|e| err("activate", e))?;
            let attrs = t.GetAttributes().ok();
            let is_async = attrs
                .as_ref()
                .and_then(|a| a.GetUINT32(&MF_TRANSFORM_ASYNC).ok())
                .unwrap_or(0)
                != 0;
            if let Some(at) = &attrs {
                if is_async {
                    at.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)
                        .map_err(|e| err("unlock", e))?;
                }
                let _ = at.SetUINT32(&MF_LOW_LATENCY, 1);
            }
            let aware = attrs
                .as_ref()
                .and_then(|a| a.GetUINT32(&MF_SA_D3D11_AWARE).ok())
                .unwrap_or(0)
                != 0;
            let mut d3d = false;
            if use_gpu
                && aware
                && b.gpu.is_ok()
                && let Some(m) = &b.manager
            {
                t.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, m.as_raw() as usize)
                    .map_err(|e| err("Direct3D device for the encoder", e))?;
                d3d = true;
            }
            let mut refused = Vec::new();
            if let Ok(api) = t.cast::<ICodecAPI>() {
                for (name, key, v) in [
                    ("low latency", CODECAPI_AVLowLatencyMode, variant_bool(true)),
                    ("CBR", CODECAPI_AVEncCommonRateControlMode, variant_u32(0)),
                    (
                        "bitrate",
                        CODECAPI_AVEncCommonMeanBitRate,
                        variant_u32(b.bitrate),
                    ),
                    (
                        "no B-frames",
                        CODECAPI_AVEncMPVDefaultBPictureCount,
                        variant_u32(0),
                    ),
                    ("GOP 3600", CODECAPI_AVEncMPVGOPSize, variant_u32(3600)),
                ] {
                    if api.SetValue(&key, &v).is_err() {
                        refused.push(name.to_string());
                    }
                }
            } else {
                refused.push("ICodecAPI".into());
            }
            let frame_size = ((b.even.0 as u64) << 32) | b.even.1 as u64;
            let rate = ((FPS as u64) << 32) | 1;
            let out = MFCreateMediaType().map_err(|e| err("media type", e))?;
            let _ = out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video);
            let _ = out.SetGUID(&MF_MT_SUBTYPE, &subtype);
            let _ = out.SetUINT32(&MF_MT_AVG_BITRATE, b.bitrate);
            let _ = out.SetUINT64(&MF_MT_FRAME_SIZE, frame_size);
            let _ = out.SetUINT64(&MF_MT_FRAME_RATE, rate);
            let _ = out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32);
            match codec {
                "H.264" => {
                    let _ = out.SetUINT32(&MF_MT_MPEG2_PROFILE, 100); // High
                }
                "HEVC" => {
                    let _ = out.SetUINT32(&MF_MT_MPEG2_PROFILE, 1); // Main
                }
                _ => {}
            }
            t.SetOutputType(0, &out, 0)
                .map_err(|e| err(&format!("output type {}x{}", b.even.0, b.even.1), e))?;
            let mut set = false;
            for k in 0..64 {
                let Ok(inp) = t.GetInputAvailableType(0, k) else {
                    break;
                };
                if inp.GetGUID(&MF_MT_SUBTYPE).ok() != Some(MFVideoFormat_NV12) {
                    continue;
                }
                let _ = inp.SetUINT64(&MF_MT_FRAME_SIZE, frame_size);
                let _ = inp.SetUINT64(&MF_MT_FRAME_RATE, rate);
                let _ = inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32);
                t.SetInputType(0, &inp, 0)
                    .map_err(|e| err("NV12 input type", e))?;
                set = true;
                break;
            }
            if !set {
                return Err("no NV12 input".into());
            }
            let info = t
                .GetOutputStreamInfo(0)
                .map_err(|e| err("output info", e))?;
            let provides_samples = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0)
                    as u32
                != 0;
            t.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| err("begin streaming", e))?;
            t.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| err("start of stream", e))?;
            let events = if is_async {
                Some(
                    t.cast::<IMFMediaEventGenerator>()
                        .map_err(|e| err("events", e))?,
                )
            } else {
                None
            };
            Ok(Encoder {
                t,
                events,
                d3d,
                provides_samples,
                out_size: info.cbSize.max(4 << 20),
                refused,
            })
        }
    }

    /// Takes every output the encoder has ready and records it.
    fn output(&self, sent: &mut HashMap<i64, Instant>, st: &mut Stats) -> Result<(), String> {
        for _ in 0..64 {
            // SAFETY: ProcessOutput on our transform; the buffer's sample and
            // events are taken back out of the ManuallyDrop fields.
            unsafe {
                let mine = if self.provides_samples {
                    None
                } else {
                    let s = MFCreateSample().map_err(|e| err("output sample", e))?;
                    let b =
                        MFCreateMemoryBuffer(self.out_size).map_err(|e| err("output buffer", e))?;
                    s.AddBuffer(&b).map_err(|e| err("output buffer", e))?;
                    Some(s)
                };
                let mut db = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: ManuallyDrop::new(mine),
                    dwStatus: 0,
                    pEvents: ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                let res = self.t.ProcessOutput(0, &mut db, &mut status);
                let sample = ManuallyDrop::take(&mut db[0].pSample);
                drop(ManuallyDrop::take(&mut db[0].pEvents));
                match res {
                    Ok(()) => {
                        if let Some(s) = sample {
                            st.record(&s, sent);
                        }
                        if self.events.is_some() {
                            // One HaveOutput event, one output.
                            return Ok(());
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        let t = self
                            .t
                            .GetOutputAvailableType(0, 0)
                            .map_err(|e| err("new output type", e))?;
                        self.t
                            .SetOutputType(0, &t, 0)
                            .map_err(|e| err("new output type", e))?;
                    }
                    Err(e) => return Err(err("ProcessOutput", e)),
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Stats {
    input: u64,
    missed: u64,
    seconds: f64,
    /// Milliseconds spent preparing frames on the CPU side (scroll,
    /// conversion submit or readback, ProcessInput not included).
    prepare: f64,
    latencies: Vec<f64>,
    sizes: Vec<u32>,
    keyframes: Vec<u32>,
}

impl Stats {
    fn record(&mut self, s: &IMFSample, sent: &mut HashMap<i64, Instant>) {
        // SAFETY: plain getters on an output sample.
        unsafe {
            let bytes = s.GetTotalLength().unwrap_or(0);
            if let Ok(t) = s.GetSampleTime()
                && let Some(t0) = sent.remove(&t)
            {
                self.latencies.push(t0.elapsed().as_secs_f64() * 1000.0);
            }
            self.sizes.push(bytes);
            if s.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0 {
                self.keyframes.push(bytes);
            }
        }
    }

    fn line(&self, on_gpu: bool, refused: &[String]) -> String {
        let out = self.sizes.len();
        let mut lat = self.latencies.clone();
        lat.sort_by(|a, b| a.total_cmp(b));
        let pct = |p: f64| {
            if lat.is_empty() {
                0.0
            } else {
                lat[((lat.len() - 1) as f64 * p).round() as usize]
            }
        };
        let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len().max(1) as f64;
        let total: u64 = self.sizes.iter().map(|&b| b as u64).sum();
        let kb = |b: f64| b / 1024.0;
        let mut s = format!(
            "{out}/{} frames out ({:.1} fps), {} too late; latency {:.2} ms average, {:.2} ms p95, {:.2} ms max; frame {:.1} KB average, {:.1} KB max; {} keyframes ({:.1} KB average); {:.1} Mbit/s; input {} ({:.2} ms per frame on the CPU side)",
            self.input,
            out as f64 / self.seconds.max(0.001),
            self.missed,
            avg(&lat),
            pct(0.95),
            lat.last().copied().unwrap_or(0.0),
            kb(total as f64 / out.max(1) as f64),
            kb(self.sizes.iter().copied().max().unwrap_or(0) as f64),
            self.keyframes.len(),
            kb(self.keyframes.iter().map(|&b| b as f64).sum::<f64>()
                / self.keyframes.len().max(1) as f64),
            total as f64 * 8.0 / self.seconds.max(0.001) / 1e6,
            if on_gpu { "GPU" } else { "CPU" },
            self.prepare / self.input.max(1) as f64,
        );
        if !refused.is_empty() {
            s += &format!("; refused: {}", refused.join(", "));
        }
        s
    }
}

/// BGRA to NV12 on the GPU with the Direct3D 11 video processor.
struct Gpu {
    video: ID3D11VideoContext,
    processor: ID3D11VideoProcessor,
    input: ID3D11VideoProcessorInputView,
    outputs: Vec<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)>,
}

impl Gpu {
    fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        source: &ID3D11Texture2D,
        size: (u32, u32),
        even: (u32, u32),
    ) -> Result<Gpu, String> {
        // SAFETY: D3D11 video calls on valid objects; out pointers to locals.
        unsafe {
            let vdev = device
                .cast::<ID3D11VideoDevice>()
                .map_err(|e| err("video device", e))?;
            let video = context
                .cast::<ID3D11VideoContext>()
                .map_err(|e| err("video context", e))?;
            let rate = DXGI_RATIONAL {
                Numerator: FPS,
                Denominator: 1,
            };
            let desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputFrameRate: rate,
                InputWidth: size.0,
                InputHeight: size.1,
                OutputFrameRate: rate,
                OutputWidth: even.0,
                OutputHeight: even.1,
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
            };
            let en = vdev
                .CreateVideoProcessorEnumerator(&desc)
                .map_err(|e| err("video processor enumerator", e))?;
            let processor = vdev
                .CreateVideoProcessor(&en, 0)
                .map_err(|e| err("video processor", e))?;
            let iv = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                FourCC: 0,
                ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPIV {
                        MipSlice: 0,
                        ArraySlice: 0,
                    },
                },
            };
            let mut input = None;
            vdev.CreateVideoProcessorInputView(source, &en, &iv, Some(&mut input))
                .map_err(|e| err("video processor input", e))?;
            let input = input.ok_or("video processor input: none")?;
            let ov = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
                },
            };
            let mut outputs = Vec::new();
            for _ in 0..RING {
                let mut tex = None;
                let mut d = D3D11_TEXTURE2D_DESC {
                    Width: even.0,
                    Height: even.1,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_NV12,
                    SampleDesc: DXGI_SAMPLE_DESC {
                        Count: 1,
                        Quality: 0,
                    },
                    Usage: D3D11_USAGE_DEFAULT,
                    BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_VIDEO_ENCODER.0) as u32,
                    CPUAccessFlags: 0,
                    MiscFlags: 0,
                };
                if device.CreateTexture2D(&d, None, Some(&mut tex)).is_err() {
                    d.BindFlags = D3D11_BIND_RENDER_TARGET.0 as u32;
                    device
                        .CreateTexture2D(&d, None, Some(&mut tex))
                        .map_err(|e| err("NV12 texture", e))?;
                }
                let tex = tex.ok_or("NV12 texture: none")?;
                let mut view = None;
                vdev.CreateVideoProcessorOutputView(&tex, &en, &ov, Some(&mut view))
                    .map_err(|e| err("video processor output", e))?;
                outputs.push((tex, view.ok_or("video processor output: none")?));
            }
            // Crop the odd row or column instead of scaling.
            let crop = RECT {
                left: 0,
                top: 0,
                right: even.0 as i32,
                bottom: even.1 as i32,
            };
            video.VideoProcessorSetStreamSourceRect(&processor, 0, true, Some(&crop));
            video.VideoProcessorSetStreamDestRect(&processor, 0, true, Some(&crop));
            Ok(Gpu {
                video,
                processor,
                input,
                outputs,
            })
        }
    }

    fn convert(&self, k: usize) -> Result<&ID3D11Texture2D, String> {
        let (tex, view) = &self.outputs[k % self.outputs.len()];
        let mut stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(Some(self.input.clone())),
            ..Default::default()
        };
        // SAFETY: one stream from our input view into our output view; the
        // cloned view reference is released right after.
        let res = unsafe {
            self.video
                .VideoProcessorBlt(&self.processor, view, 0, std::slice::from_ref(&stream))
        };
        // SAFETY: drops the clone stored above, exactly once.
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        res.map_err(|e| err("VideoProcessorBlt", e))?;
        Ok(tex)
    }
}

/// BGRA to NV12 on the CPU: read the frame back, convert, fill a memory
/// buffer.
struct Cpu {
    staging: ID3D11Texture2D,
}

impl Cpu {
    fn new(device: &ID3D11Device, source: &ID3D11Texture2D) -> Result<Cpu, String> {
        // SAFETY: a staging copy of the source's description.
        unsafe {
            let mut d = D3D11_TEXTURE2D_DESC::default();
            source.GetDesc(&mut d);
            let s = D3D11_TEXTURE2D_DESC {
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
                ..d
            };
            let mut t = None;
            device
                .CreateTexture2D(&s, None, Some(&mut t))
                .map_err(|e| err("staging texture", e))?;
            Ok(Cpu {
                staging: t.ok_or("staging texture: none")?,
            })
        }
    }

    fn convert(
        &self,
        context: &ID3D11DeviceContext,
        source: &ID3D11Texture2D,
        (w, h): (u32, u32),
    ) -> Result<IMFMediaBuffer, String> {
        let (w, h) = (w as usize, h as usize);
        let len = w * h * 3 / 2;
        // SAFETY: the mapped staging texture is read within its pitch and
        // size; the MF buffer is written within its locked length.
        unsafe {
            context.CopyResource(&self.staging, source);
            let mut m = D3D11_MAPPED_SUBRESOURCE::default();
            context
                .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut m))
                .map_err(|e| err("map", e))?;
            let buf = MFCreateMemoryBuffer(len as u32).map_err(|e| err("buffer", e));
            let result = buf.and_then(|buf| {
                let mut p: *mut u8 = std::ptr::null_mut();
                let mut max = 0u32;
                buf.Lock(&mut p, Some(&mut max), None)
                    .map_err(|e| err("lock", e))?;
                if (max as usize) < len {
                    let _ = buf.Unlock();
                    return Err("buffer too small".into());
                }
                let dst = std::slice::from_raw_parts_mut(p, len);
                let pitch = m.RowPitch as usize;
                let src = std::slice::from_raw_parts(m.pData as *const u8, pitch * h);
                bgra_to_nv12(src, pitch, w, h, dst);
                let _ = buf.Unlock();
                let _ = buf.SetCurrentLength(len as u32);
                Ok(buf)
            });
            context.Unmap(&self.staging, 0);
            result
        }
    }
}

/// BT.601 limited-range BGRA to NV12; chroma from the top-left pixel of
/// each 2x2 block (enough for a speed and size measurement).
pub(super) fn bgra_to_nv12(src: &[u8], pitch: usize, w: usize, h: usize, dst: &mut [u8]) {
    let (y_plane, uv_plane) = dst.split_at_mut(w * h);
    for row in 0..h {
        let s = &src[row * pitch..row * pitch + w * 4];
        let d = &mut y_plane[row * w..row * w + w];
        for (px, y) in s.as_chunks::<4>().0.iter().zip(d.iter_mut()) {
            let (b, g, r) = (px[0] as i32, px[1] as i32, px[2] as i32);
            *y = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
        }
    }
    for row in 0..h / 2 {
        let s = &src[row * 2 * pitch..];
        let d = &mut uv_plane[row * w..row * w + w];
        for col in 0..w / 2 {
            let px = &s[col * 8..col * 8 + 4];
            let (b, g, r) = (px[0] as i32, px[1] as i32, px[2] as i32);
            d[col * 2] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8;
            d[col * 2 + 1] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::bgra_to_nv12;

    #[test]
    fn nv12_of_white_black_and_red() {
        // 2x2 white, then a 2x2 block: black top-left, the rest red.
        let w = 4;
        let h = 2;
        let mut src = vec![0u8; w * 4 * h];
        for row in 0..h {
            for col in 0..w {
                let p = &mut src[(row * w + col) * 4..][..4];
                let colour = if col < 2 {
                    [255, 255, 255, 255]
                } else if row == 0 && col == 2 {
                    [0, 0, 0, 255]
                } else {
                    [0, 0, 255, 255]
                };
                p.copy_from_slice(&colour);
            }
        }
        let mut dst = vec![0u8; w * h * 3 / 2];
        bgra_to_nv12(&src, w * 4, w, h, &mut dst);
        assert_eq!(&dst[..2], &[235, 235]);
        assert_eq!(dst[2], 16);
        assert_eq!(dst[3], 82);
        // White block: neutral chroma; black block: neutral too.
        assert_eq!(&dst[8..12], &[128, 128, 128, 128]);
    }

    /// The benchmark on this PC's default GPU with a generated picture: no
    /// desktop capture, no window. It exercises the GPU converter and the
    /// asynchronous hardware encoders that the lab VM lacks:
    /// `cargo test -p remora-agent encode_on_this_gpu -- --ignored --nocapture`.
    #[test]
    #[ignore = "uses this PC's GPU encoders for about 15 s"]
    fn encode_on_this_gpu() {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
        use windows::Win32::Graphics::Direct3D11::{
            D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION, D3D11_SUBRESOURCE_DATA,
            D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11CreateDevice,
        };
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
        };

        let (w, h) = std::env::var("ENCODE_TEST_SIZE")
            .ok()
            .and_then(|s| {
                s.split_once('x')
                    .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)))
            })
            .unwrap_or((2560u32, 1440u32));
        // Text-like content: a gradient with thin lines, so frames do not
        // compress to nothing.
        let mut px = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                let line = (y % 18 < 2 && x % 300 < 240) || (x * 7 + y * 3) % 97 == 0;
                let v = if line { 20 } else { 200 + ((x + y) % 50) as u8 };
                px[i..i + 4].copy_from_slice(&[v, v.wrapping_sub((x % 40) as u8), v, 255]);
            }
        }
        // SAFETY: device and texture creation with valid descriptions and
        // initial data that outlives the call.
        unsafe {
            let mut device = None;
            let mut context = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .expect("hardware Direct3D 11 device");
            let (device, context) = (device.unwrap(), context.unwrap());
            let desc = D3D11_TEXTURE2D_DESC {
                Width: w,
                Height: h,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
            };
            let init = D3D11_SUBRESOURCE_DATA {
                pSysMem: px.as_ptr() as *const _,
                SysMemPitch: w * 4,
                SysMemSlicePitch: 0,
            };
            let mut tex = None;
            device
                .CreateTexture2D(&desc, Some(&init), Some(&mut tex))
                .expect("picture");
            let mut r = String::new();
            let tex = tex.unwrap();
            super::run(&device, &context, &tex, &mut r);
            println!("{r}");
            assert!(r.contains("frames out"), "{r}");
            assert!(!r.contains("failed"), "{r}");
            assert!(r.contains("[capture adapter]"), "{r}");

            // The fallback a failed GPU path takes: the same hardware
            // encoder fed from the CPU.
            use windows::Win32::Media::MediaFoundation::{
                MF_VERSION, MFSTARTUP_NOSOCKET, MFShutdown, MFStartup, MFVideoFormat_H264,
            };
            MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET).unwrap();
            {
                let mut b = super::Bench::new(&device, &context, &tex).unwrap();
                let f = super::list(MFVideoFormat_H264, true, true, b.luid)
                    .into_iter()
                    .next()
                    .expect("a hardware H.264 encoder on this adapter");
                let line = b.one("H.264", MFVideoFormat_H264, &f.activate, false);
                let _ = f.activate.ShutdownObject();
                let line = line.unwrap();
                println!("H.264 hardware with CPU input: {line}");
                assert!(line.contains("input CPU"), "{line}");
            }
            let _ = MFShutdown();
        }
    }
}
