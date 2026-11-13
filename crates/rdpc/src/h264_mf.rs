//! H.264 decoding for the graphics pipeline's AVC420 codec (MS-RDPEGFX
//! 2.2.4.4) with the H.264 decoder that ships with Windows: the Media
//! Foundation transform `CLSID_MSH264DecoderMFT`, software mode, low-latency
//! (one picture out per access unit in), NV12 output.
//!
//! Where Media Foundation or the decoder is missing (Windows N editions
//! without the Media Feature Pack, Server Core) [`factory`] yields `None`
//! and the client advertises AVC as disabled.

use std::sync::Arc;

use rdp::{H264Decoder, H264Factory, Yuv420Frame};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::core::Interface;

/// Creates a decoder per session; `None` when Media Foundation's H.264
/// decoder cannot be started on this machine.
pub fn factory() -> H264Factory {
    Arc::new(|| match MfH264::new() {
        Ok(d) => Some(Box::new(d) as Box<dyn H264Decoder>),
        Err(e) => {
            rdp::trace!("Media Foundation H.264 decoder unavailable: {e}");
            None
        }
    })
}

fn err(what: &str, e: windows::core::Error) -> rdp::Error {
    rdp::Error::Unsupported(format!("Media Foundation {what}: {e}"))
}

/// The MFT and what it was configured with.
pub struct MfH264 {
    mft: Option<IMFTransform>,
    /// NV12 output: picture size and row pitch of the luma plane.
    width: usize,
    height: usize,
    stride: usize,
    /// MFStartup / CoInitializeEx succeeded and need their counterpart.
    mf_started: bool,
    com_init: bool,
}

// SAFETY: the Microsoft H.264 decoder MFT is free-threaded (registered with
// ThreadingModel "Both") and is created in the multithreaded apartment; the
// session uses it from one thread at a time (the worker owns the channel).
unsafe impl Send for MfH264 {}

impl MfH264 {
    pub fn new() -> rdp::Result<MfH264> {
        let mut d = MfH264 {
            mft: None,
            width: 0,
            height: 0,
            stride: 0,
            mf_started: false,
            com_init: false,
        };
        // SAFETY: plain COM / Media Foundation initialisation and calls on
        // interfaces this struct owns; every pointer passed is valid.
        unsafe {
            // S_OK or S_FALSE (already initialised) must be balanced; a thread
            // in another apartment (RPC_E_CHANGED_MODE) keeps its own.
            d.com_init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
            MFStartup(MF_VERSION, MFSTARTUP_LITE).map_err(|e| err("startup", e))?;
            d.mf_started = true;
            let mft: IMFTransform =
                CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)
                    .map_err(|e| err("H.264 decoder", e))?;
            // Low latency: no frame reordering delay; RDP sends no B-frames.
            if let Ok(attrs) = mft.GetAttributes() {
                let _ = attrs.SetUINT32(&CODECAPI_AVLowLatencyMode, 1);
            }
            let input = MFCreateMediaType().map_err(|e| err("media type", e))?;
            input
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .and_then(|_| input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264))
                .and_then(|_| mft.SetInputType(0, &input, 0))
                .map_err(|e| err("input type", e))?;
            d.mft = Some(mft);
            d.select_output()?;
            let mft = d.mft.as_ref().expect("set above");
            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        }
        Ok(d)
    }

    /// Picks the NV12 output type (again after a stream change) and reads
    /// the picture size and pitch from it.
    unsafe fn select_output(&mut self) -> rdp::Result<()> {
        let mft = self
            .mft
            .as_ref()
            .ok_or_else(|| rdp::Error::Protocol("no decoder".into()))?;
        // SAFETY: calls on an owned interface with valid arguments.
        unsafe {
            let mut i = 0;
            loop {
                let t = mft
                    .GetOutputAvailableType(0, i)
                    .map_err(|e| err("NV12 output", e))?;
                i += 1;
                if t.GetGUID(&MF_MT_SUBTYPE).ok() != Some(MFVideoFormat_NV12) {
                    continue;
                }
                mft.SetOutputType(0, &t, 0)
                    .map_err(|e| err("output type", e))?;
                let size = t.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
                self.width = (size >> 32) as usize;
                self.height = (size & 0xFFFF_FFFF) as usize;
                // MF_MT_DEFAULT_STRIDE is a signed pitch; NV12 is top-down.
                self.stride = match t.GetUINT32(&MF_MT_DEFAULT_STRIDE).map(|s| s as i32) {
                    Ok(s) if s > 0 => s as usize,
                    _ => self.width,
                };
                return Ok(());
            }
        }
    }

    /// Feeds one access unit.
    unsafe fn input(&self, mft: &IMFTransform, nal: &[u8]) -> windows::core::Result<()> {
        // SAFETY: the buffer is locked for exactly its allocated length.
        unsafe {
            let len = nal.len() as u32;
            let buffer = MFCreateMemoryBuffer(len)?;
            let mut p = std::ptr::null_mut();
            buffer.Lock(&mut p, None, None)?;
            std::ptr::copy_nonoverlapping(nal.as_ptr(), p, nal.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(len)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            mft.ProcessInput(0, &sample, 0)
        }
    }

    /// Pulls one picture, if the decoder has one.
    unsafe fn output(&mut self) -> rdp::Result<Option<Yuv420Frame>> {
        loop {
            let mft = self
                .mft
                .clone()
                .ok_or_else(|| rdp::Error::Protocol("no decoder".into()))?;
            // SAFETY: the output buffer struct owns the sample it carries; both
            // ManuallyDrop fields are taken or dropped below.
            unsafe {
                let info = mft
                    .GetOutputStreamInfo(0)
                    .map_err(|e| err("stream info", e))?;
                let provides = info.dwFlags
                    & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0
                        | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0) as u32
                    != 0;
                let sample = if provides {
                    None
                } else {
                    let s = MFCreateSample().map_err(|e| err("sample", e))?;
                    let b =
                        MFCreateMemoryBuffer(info.cbSize.max(1)).map_err(|e| err("buffer", e))?;
                    s.AddBuffer(&b).map_err(|e| err("buffer", e))?;
                    Some(s)
                };
                let mut buf = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: std::mem::ManuallyDrop::new(sample),
                    dwStatus: 0,
                    pEvents: std::mem::ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                let r = mft.ProcessOutput(0, &mut buf, &mut status);
                let sample = std::mem::ManuallyDrop::take(&mut buf[0].pSample);
                drop(std::mem::ManuallyDrop::take(&mut buf[0].pEvents));
                match r {
                    Ok(()) => {
                        let Some(sample) = sample else {
                            return Ok(None);
                        };
                        return self.read(&sample).map(Some);
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => self.select_output()?,
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                    Err(e) => return Err(err("decode", e)),
                }
            }
        }
    }

    /// Copies an NV12 picture into planar I420. The row pitch comes from
    /// IMF2DBuffer2 where the buffer has one, else from the media type.
    unsafe fn read(&self, sample: &IMFSample) -> rdp::Result<Yuv420Frame> {
        let (w, h) = (self.width, self.height);
        // SAFETY: each buffer stays locked while its bytes are read, and the
        // length Media Foundation reports bounds every access.
        unsafe {
            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(|e| err("buffer", e))?;
            if let Ok(b2) = buffer.cast::<IMF2DBuffer2>() {
                let (mut scan0, mut start) = (std::ptr::null_mut(), std::ptr::null_mut());
                let (mut pitch, mut len) = (0i32, 0u32);
                b2.Lock2DSize(
                    MF2DBuffer_LockFlags_Read,
                    &mut scan0,
                    &mut pitch,
                    &mut start,
                    &mut len,
                )
                .map_err(|e| err("lock", e))?;
                let offset = scan0.offset_from(start);
                let frame = if pitch > 0 && offset >= 0 && (offset as usize) <= len as usize {
                    let data = std::slice::from_raw_parts(scan0, len as usize - offset as usize);
                    nv12_to_i420(data, w, h, pitch as usize)
                } else {
                    Err(rdp::Error::Protocol("h264: bottom-up NV12 buffer".into()))
                };
                let _ = b2.Unlock2D();
                return frame;
            }
            let mut p = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut p, None, Some(&mut len))
                .map_err(|e| err("lock", e))?;
            let frame = nv12_to_i420(
                std::slice::from_raw_parts(p, len as usize),
                w,
                h,
                self.stride,
            );
            let _ = buffer.Unlock();
            frame
        }
    }
}

/// NV12 (a luma plane, then interleaved U/V rows at half height, both with
/// pitch `pitch`) to planar YUV 4:2:0.
fn nv12_to_i420(data: &[u8], w: usize, h: usize, pitch: usize) -> rdp::Result<Yuv420Frame> {
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    if w == 0 || h == 0 || pitch < w || data.len() < pitch * h + pitch * (ch - 1) + cw * 2 {
        return Err(rdp::Error::Protocol(format!(
            "h264: NV12 picture {w}x{h} pitch {pitch} in {} bytes",
            data.len()
        )));
    }
    let mut y = Vec::with_capacity(w * h);
    for row in 0..h {
        y.extend_from_slice(&data[row * pitch..row * pitch + w]);
    }
    let (mut u, mut v) = (Vec::with_capacity(cw * ch), Vec::with_capacity(cw * ch));
    for row in 0..ch {
        let line = &data[pitch * h + row * pitch..][..cw * 2];
        for pair in line.chunks(2) {
            u.push(pair[0]);
            v.push(pair[1]);
        }
    }
    Ok(Yuv420Frame {
        width: w,
        height: h,
        y,
        u,
        v,
        y_stride: w,
        uv_stride: cw,
    })
}

impl H264Decoder for MfH264 {
    fn decode(&mut self, nal: &[u8]) -> rdp::Result<Option<Yuv420Frame>> {
        let mft = self
            .mft
            .clone()
            .ok_or_else(|| rdp::Error::Protocol("no decoder".into()))?;
        // SAFETY: calls on owned interfaces; see `input` and `output`.
        unsafe {
            match self.input(&mft, nal) {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_NOTACCEPTING => {
                    // A picture is still waiting: take it, then retry.
                    let pending = self.output()?;
                    self.input(&mft, nal).map_err(|e| err("decode", e))?;
                    let next = self.output()?;
                    return Ok(next.or(pending));
                }
                Err(e) => return Err(err("decode", e)),
            }
            self.output()
        }
    }
}

impl Drop for MfH264 {
    fn drop(&mut self) {
        self.mft = None;
        // SAFETY: balances the successful MFStartup / CoInitializeEx in new.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nv12_split_and_bounds() {
        // 4x2 picture, pitch 6: Y rows then one UV row.
        let data = [
            1, 2, 3, 4, 0, 0, //
            5, 6, 7, 8, 0, 0, //
            10, 20, 11, 21, 0, 0,
        ];
        let f = nv12_to_i420(&data, 4, 2, 6).unwrap();
        assert_eq!(f.y, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(f.u, [10, 11]);
        assert_eq!(f.v, [20, 21]);
        f.validate().unwrap();
        assert!(nv12_to_i420(&data[..15], 4, 2, 6).is_err());
        assert!(nv12_to_i420(&data, 4, 2, 3).is_err());
    }

    /// Bit writer for an H.264 RBSP (ITU-T H.264 7.2: u(n), ue(v), se(v)).
    #[derive(Default)]
    struct Bits {
        bytes: Vec<u8>,
        acc: u8,
        n: u8,
    }

    impl Bits {
        fn u(&mut self, bits: u32, v: u32) {
            for i in (0..bits).rev() {
                self.acc = self.acc << 1 | ((v >> i) & 1) as u8;
                self.n += 1;
                if self.n == 8 {
                    self.bytes.push(self.acc);
                    (self.acc, self.n) = (0, 0);
                }
            }
        }
        fn ue(&mut self, v: u32) {
            let len = 32 - (v + 1).leading_zeros();
            self.u(len - 1, 0);
            self.u(len, v + 1);
        }
        fn align_zero(&mut self) {
            while self.n != 0 {
                self.u(1, 0);
            }
        }
        /// rbsp_trailing_bits, then a NAL unit with start code and
        /// emulation prevention (7.4.1).
        fn nal(mut self, header: u8) -> Vec<u8> {
            self.u(1, 1);
            self.align_zero();
            let mut out = vec![0, 0, 0, 1, header];
            let mut zeros = 0;
            for b in self.bytes {
                if zeros == 2 && b <= 3 {
                    out.push(3);
                    zeros = 0;
                }
                zeros = if b == 0 { zeros + 1 } else { 0 };
                out.push(b);
            }
            out
        }
    }

    /// A 48x48 baseline IDR picture of I_PCM macroblocks (H.264 7.3), so the
    /// decoded samples are known exactly: macroblock i has luma 40 + 16 i,
    /// Cb 100 + i and Cr 150 + i. Deblocking is off.
    fn pcm_picture() -> Vec<u8> {
        let mut sps = Bits::default();
        sps.u(8, 66); // profile_idc: Baseline
        sps.u(8, 0xC0); // constraint_set0/1
        sps.u(8, 30); // level_idc 3.0
        sps.ue(0); // seq_parameter_set_id
        sps.ue(0); // log2_max_frame_num_minus4
        sps.ue(2); // pic_order_cnt_type
        sps.ue(1); // max_num_ref_frames
        sps.u(1, 0); // gaps_in_frame_num_value_allowed_flag
        sps.ue(2); // pic_width_in_mbs_minus1
        sps.ue(2); // pic_height_in_map_units_minus1
        sps.u(1, 1); // frame_mbs_only_flag
        sps.u(1, 1); // direct_8x8_inference_flag
        sps.u(1, 0); // frame_cropping_flag
        sps.u(1, 0); // vui_parameters_present_flag
        let mut pps = Bits::default();
        pps.ue(0); // pic_parameter_set_id
        pps.ue(0); // seq_parameter_set_id
        pps.u(1, 0); // entropy_coding_mode_flag: CAVLC
        pps.u(1, 0); // bottom_field_pic_order_in_frame_present_flag
        pps.ue(0); // num_slice_groups_minus1
        pps.ue(0); // num_ref_idx_l0_default_active_minus1
        pps.ue(0); // num_ref_idx_l1_default_active_minus1
        pps.u(1, 0); // weighted_pred_flag
        pps.u(2, 0); // weighted_bipred_idc
        pps.ue(0); // pic_init_qp_minus26 (se 0)
        pps.ue(0); // pic_init_qs_minus26 (se 0)
        pps.ue(0); // chroma_qp_index_offset (se 0)
        pps.u(1, 1); // deblocking_filter_control_present_flag
        pps.u(1, 0); // constrained_intra_pred_flag
        pps.u(1, 0); // redundant_pic_cnt_present_flag
        let mut slice = Bits::default();
        slice.ue(0); // first_mb_in_slice
        slice.ue(7); // slice_type: I (all slices)
        slice.ue(0); // pic_parameter_set_id
        slice.u(4, 0); // frame_num
        slice.ue(0); // idr_pic_id
        slice.u(1, 0); // no_output_of_prior_pics_flag
        slice.u(1, 0); // long_term_reference_flag
        slice.ue(0); // slice_qp_delta (se 0)
        slice.ue(1); // disable_deblocking_filter_idc: off
        for mb in 0..9u32 {
            slice.ue(25); // mb_type I_PCM
            slice.align_zero(); // pcm_alignment_zero_bit
            for _ in 0..256 {
                slice.u(8, 40 + 16 * mb);
            }
            for _ in 0..64 {
                slice.u(8, 100 + mb);
            }
            for _ in 0..64 {
                slice.u(8, 150 + mb);
            }
        }
        [sps.nal(0x67), pps.nal(0x68), slice.nal(0x65)].concat()
    }

    /// Decodes a generated picture with the Windows decoder. Ignored by
    /// default: it needs Media Foundation (`cargo test -- --ignored`).
    #[test]
    #[ignore]
    fn media_foundation_decodes_pcm_picture() {
        let mut d = MfH264::new().expect("Media Foundation H.264 decoder");
        let au = pcm_picture();
        // Low latency: every access unit yields its picture at once, as
        // each AVC420 update must be drawn before its frame is acknowledged.
        let first = d
            .decode(&au)
            .unwrap()
            .expect("picture for the first access unit");
        let f = d
            .decode(&au)
            .unwrap()
            .expect("picture for the second access unit");
        assert_eq!(first, f);
        f.validate().unwrap();
        assert_eq!((f.width, f.height), (48, 48));
        for mb in 0..9 {
            let (mx, my) = ((mb % 3) * 16, (mb / 3) * 16);
            assert_eq!(f.y[(my + 5) * f.y_stride + mx + 7], 40 + 16 * mb as u8);
            let c = (my / 2 + 3) * f.uv_stride + mx / 2 + 2;
            assert_eq!((f.u[c], f.v[c]), (100 + mb as u8, 150 + mb as u8));
        }
    }

    /// The whole AVC420 path: a graphics channel with this decoder gets a
    /// WireToSurface1 (MS-RDPEGFX 2.2.2.1, 2.2.4.4) and the session
    /// framebuffer shows the picture's colours in the region only.
    #[test]
    #[ignore]
    fn media_foundation_avc420_through_the_graphics_channel() {
        use rdp::DynamicChannel;
        let pdu = |cmd: u16, body: &[u8]| {
            let mut v = cmd.to_le_bytes().to_vec();
            v.extend([0, 0]);
            v.extend((8 + body.len() as u32).to_le_bytes());
            v.extend_from_slice(body);
            v
        };
        let rect = |l: u16, t: u16, r: u16, b: u16| -> Vec<u8> {
            [l, t, r, b].iter().flat_map(|v| v.to_le_bytes()).collect()
        };
        let mut reset = vec![48, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0];
        reset.resize(332, 0);
        // Region: macroblock 4 (16..32, 16..32) only.
        let mut avc = vec![1, 0, 0, 0];
        avc.extend(rect(16, 16, 32, 32));
        avc.extend([22, 100]);
        avc.extend(pcm_picture());
        let mut w2s = vec![1, 0, 0x0B, 0, 0x20];
        w2s.extend(rect(0, 0, 48, 48));
        w2s.extend((avc.len() as u32).to_le_bytes());
        w2s.extend(avc);
        let mut msg = vec![0xE1, 1, 0];
        let body = [
            pdu(0x000E, &reset),
            pdu(0x0009, &[1, 0, 48, 0, 48, 0, 0x20]),
            pdu(0x000F, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            pdu(0x0001, &w2s),
            pdu(0x000C, &[1, 0, 0, 0]),
        ]
        .concat();
        // MULTIPART: one raw segment may hold up to 65,535 bytes.
        msg.extend((body.len() as u32).to_le_bytes());
        msg.extend((body.len() as u32 + 1).to_le_bytes());
        msg.push(0x04);
        msg.extend(body);
        let decoder = MfH264::new().expect("Media Foundation H.264 decoder");
        let (mut ch, handle) = rdp::gfx::graphics(Some(Box::new(decoder)));
        let mut out = rdp::DvcOut::default();
        ch.process(&msg, &mut out).unwrap();
        assert_eq!(out.take().len(), 1, "one frame acknowledgement");
        let mut fb = rdp::Framebuffer::new(48, 48);
        handle.present(&mut fb, &mut Vec::new());
        let inside = rdp::gfx::h264::yuv_to_rgb(40 + 16 * 4, 104, 154);
        assert_eq!(fb.pixels[20 * 48 + 20], inside);
        assert_eq!(fb.pixels[31 * 48 + 31], inside);
        assert_eq!(fb.pixels[5 * 48 + 5], 0, "outside the region");
    }
}
