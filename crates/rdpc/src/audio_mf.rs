//! AAC and MP3 audio for the sound channel (MS-RDPEA note <4> format tags
//! 0xA106, 0x1610 and 0x0055) with the decoders that ship with Windows:
//! the Media Foundation transforms for AAC and MP3, found through
//! `MFTEnumEx` and set to 16-bit PCM output.
//!
//! Where Media Foundation or a decoder is missing (Windows N editions
//! without the Media Feature Pack, Server Core) [`decoder`] offers only
//! what is there, or yields `None`, and those formats are not advertised.

use rdp::rdpsnd::codec::{WAVE_FORMAT_AAC_MS, WAVE_FORMAT_MPEG_HEAAC};
use rdp::rdpsnd::{AudioDecoder, AudioFormat, PcmFormat};

/// The AAC and MP3 decoder for one sound channel; None when this machine
/// has neither (or is not Windows).
pub fn decoder() -> Option<Box<dyn AudioDecoder>> {
    #[cfg(windows)]
    {
        win::MfAudio::probe().map(|d| Box::new(d) as Box<dyn AudioDecoder>)
    }
    #[cfg(not(windows))]
    None
}

/// AAC sampling frequencies by samplingFrequencyIndex (ISO/IEC 14496-3
/// 1.6.3.4).
const AAC_RATES: [u32; 12] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
];

/// MPEG-1, MPEG-2 and MPEG-2.5 Layer III sampling rates.
const MP3_RATES: [u32; 9] = [
    48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
];

fn is_aac(tag: u16) -> bool {
    matches!(tag, WAVE_FORMAT_AAC_MS | WAVE_FORMAT_MPEG_HEAAC)
}

/// Mono or stereo at a rate the codec defines.
fn playable(f: &AudioFormat, rates: &[u32]) -> bool {
    (1..=2).contains(&f.channels) && rates.contains(&f.samples_per_sec)
}

/// The 16-bit PCM a format decodes to.
fn pcm_of(f: &AudioFormat) -> PcmFormat {
    PcmFormat {
        channels: f.channels,
        sample_rate: f.samples_per_sec,
        bits: 16,
    }
}

/// AudioSpecificConfig for AAC-LC (ISO/IEC 14496-3 1.6.2.1):
/// audioObjectType 2, samplingFrequencyIndex, channelConfiguration, and
/// the three GASpecificConfig flags at 0.
fn aac_lc_config(f: &AudioFormat) -> Option<[u8; 2]> {
    let index = AAC_RATES.iter().position(|&r| r == f.samples_per_sec)? as u8;
    let channels = u8::try_from(f.channels)
        .ok()
        .filter(|c| (1..=7).contains(c))?;
    Some([2 << 3 | index >> 1, (index & 1) << 7 | channels << 3])
}

/// MF_MT_AAC_PAYLOAD_TYPE and MF_MT_USER_DATA for an AAC format: the
/// HEAACWAVEINFO fields after WAVEFORMATEX (wPayloadType,
/// wAudioProfileLevelIndication, wStructType, wReserved1, dwReserved2)
/// followed, for raw payloads, by the AudioSpecificConfig.
///
/// A format whose extra data already holds those fields (0x1610 always,
/// 0xA106 if the server sends them) is used as is. Otherwise the first
/// wave decides: an ADTS stream starts with the 12-bit syncword
/// (ISO/IEC 13818-7 6.2), else raw AAC-LC frames are assumed with the
/// configuration from the format.
fn aac_user_data(f: &AudioFormat, first: &[u8]) -> Option<(u32, Vec<u8>)> {
    if f.extra.len() >= 12 {
        let payload = u16::from_le_bytes([f.extra[0], f.extra[1]]);
        return Some((u32::from(payload), f.extra.clone()));
    }
    // 0xFE: no audio profile and level specified.
    let tail = |payload: u8| vec![payload, 0, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if first.len() >= 2 && first[0] == 0xFF && first[1] & 0xF0 == 0xF0 {
        return Some((1, tail(1)));
    }
    let mut data = tail(0);
    match f.extra.len() {
        2.. => data.extend_from_slice(&f.extra),
        _ => data.extend_from_slice(&aac_lc_config(f)?),
    }
    Some((0, data))
}

#[cfg(windows)]
mod win {
    use std::sync::OnceLock;

    use rdp::rdpsnd::{AudioDecoder, AudioFormat, PcmFormat};
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
    };
    use windows::core::GUID;

    use super::{AAC_RATES, MP3_RATES, aac_user_data, is_aac, pcm_of, playable};
    use rdp::rdpsnd::codec::WAVE_FORMAT_MPEGLAYER3;

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
            // SAFETY: plain initialisation calls; S_OK or S_FALSE must be
            // balanced, a thread in another apartment keeps its own.
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

    /// Audio decoder MFTs taking `subtype` and producing PCM, best first.
    fn decoders(subtype: GUID) -> Vec<IMFActivate> {
        let input = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Audio,
            guidSubtype: subtype,
        };
        let output = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Audio,
            guidSubtype: MFAudioFormat_PCM,
        };
        let flags = MFT_ENUM_FLAG(
            MFT_ENUM_FLAG_SYNCMFT.0 | MFT_ENUM_FLAG_LOCALMFT.0 | MFT_ENUM_FLAG_SORTANDFILTER.0,
        );
        let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: MFTEnumEx fills an array of `count` activation objects
        // allocated with CoTaskMemAlloc; each is moved out once, then the
        // array itself is freed.
        unsafe {
            let found = MFTEnumEx(
                MFT_CATEGORY_AUDIO_DECODER,
                flags,
                Some(&input),
                Some(&output),
                &mut list,
                &mut count,
            );
            if found.is_err() || list.is_null() {
                return Vec::new();
            }
            let v = (0..count as usize)
                .filter_map(|i| std::ptr::read(list.add(i)))
                .collect();
            CoTaskMemFree(Some(list as *const _));
            v
        }
    }

    /// AAC and MP3 decoding on Media Foundation; one per sound channel.
    pub struct MfAudio {
        aac: bool,
        mp3: bool,
        /// The open format, and its decoder once configured (AAC waits for
        /// the first wave to tell ADTS from raw frames).
        format: Option<AudioFormat>,
        mft: Option<IMFTransform>,
        /// Started on the session worker at the first open; kept until drop.
        started: Option<Started>,
    }

    // SAFETY: the Microsoft audio decoder MFTs are free-threaded and are
    // created in the multithreaded apartment on the session worker, which
    // then owns the channel and uses them from one thread at a time.
    unsafe impl Send for MfAudio {}

    impl MfAudio {
        /// Which decoders this machine has (checked once per process), as
        /// a decoder; None when it has neither.
        pub fn probe() -> Option<MfAudio> {
            static FOUND: OnceLock<(bool, bool)> = OnceLock::new();
            let &(aac, mp3) = FOUND.get_or_init(|| match Started::new() {
                Ok(_mf) => (
                    !decoders(MFAudioFormat_AAC).is_empty(),
                    !decoders(MFAudioFormat_MP3).is_empty(),
                ),
                Err(e) => {
                    rdp::trace!("{e}; no AAC or MP3 audio");
                    (false, false)
                }
            });
            (aac || mp3).then_some(MfAudio {
                aac,
                mp3,
                format: None,
                mft: None,
                started: None,
            })
        }

        /// Creates and configures the decoder for the open format; `first`
        /// is the first wave's data (see `aac_user_data`).
        fn configure(&self, first: &[u8]) -> Result<IMFTransform, String> {
            let f = self.format.as_ref().ok_or("no format open")?;
            let aac = is_aac(f.tag);
            let subtype = if aac {
                MFAudioFormat_AAC
            } else {
                MFAudioFormat_MP3
            };
            // SAFETY: calls on interfaces created here with valid arguments.
            unsafe {
                let input = MFCreateMediaType().map_err(|e| err("media type", e))?;
                input
                    .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)
                    .and_then(|_| input.SetGUID(&MF_MT_SUBTYPE, &subtype))
                    .and_then(|_| input.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, f.channels.into()))
                    .and_then(|_| {
                        input.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, f.samples_per_sec)
                    })
                    .map_err(|e| err("input type", e))?;
                if aac {
                    let (payload, user) =
                        aac_user_data(f, first).ok_or("AAC format without a configuration")?;
                    input
                        .SetUINT32(&MF_MT_AAC_PAYLOAD_TYPE, payload)
                        .and_then(|_| input.SetBlob(&MF_MT_USER_DATA, &user))
                        .map_err(|e| err("AAC input type", e))?;
                }
                let pcm = pcm_of(f);
                let output = MFCreateMediaType().map_err(|e| err("media type", e))?;
                output
                    .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)
                    .and_then(|_| output.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM))
                    .and_then(|_| output.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, pcm.channels.into()))
                    .and_then(|_| {
                        output.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, pcm.sample_rate)
                    })
                    .and_then(|_| output.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16))
                    .and_then(|_| {
                        output.SetUINT32(&MF_MT_AUDIO_BLOCK_ALIGNMENT, pcm.block_align().into())
                    })
                    .and_then(|_| {
                        output.SetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, pcm.avg_bytes_per_sec())
                    })
                    .map_err(|e| err("output type", e))?;
                let mut last = String::from("no decoder");
                for activate in decoders(subtype) {
                    let mft: IMFTransform = match activate.ActivateObject() {
                        Ok(m) => m,
                        Err(e) => {
                            last = err("activate", e);
                            continue;
                        }
                    };
                    match mft
                        .SetInputType(0, &input, 0)
                        .and_then(|_| mft.SetOutputType(0, &output, 0))
                    {
                        Ok(()) => {
                            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
                            let _ = mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
                            return Ok(mft);
                        }
                        Err(e) => last = err("media types", e),
                    }
                }
                Err(last)
            }
        }

        /// Feeds one compressed frame (or several).
        unsafe fn input(mft: &IMFTransform, data: &[u8]) -> windows::core::Result<()> {
            // SAFETY: the buffer is locked for exactly its allocated length.
            unsafe {
                let len = data.len() as u32;
                let buffer = MFCreateMemoryBuffer(len)?;
                let mut p = std::ptr::null_mut();
                buffer.Lock(&mut p, None, None)?;
                std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
                buffer.Unlock()?;
                buffer.SetCurrentLength(len)?;
                let sample = MFCreateSample()?;
                sample.AddBuffer(&buffer)?;
                mft.ProcessInput(0, &sample, 0)
            }
        }

        /// Appends all PCM the decoder has ready.
        unsafe fn drain(mft: &IMFTransform, pcm: &mut Vec<u8>) -> Result<(), String> {
            // SAFETY: the output struct owns the sample it carries; both
            // ManuallyDrop fields are taken below; buffers stay locked only
            // while their bytes are copied.
            unsafe {
                loop {
                    let info = mft
                        .GetOutputStreamInfo(0)
                        .map_err(|e| err("stream info", e))?;
                    let sample = MFCreateSample().map_err(|e| err("sample", e))?;
                    let buffer = MFCreateMemoryBuffer(info.cbSize.max(1 << 16))
                        .map_err(|e| err("buffer", e))?;
                    sample.AddBuffer(&buffer).map_err(|e| err("buffer", e))?;
                    let mut out = [MFT_OUTPUT_DATA_BUFFER {
                        dwStreamID: 0,
                        pSample: std::mem::ManuallyDrop::new(Some(sample)),
                        dwStatus: 0,
                        pEvents: std::mem::ManuallyDrop::new(None),
                    }];
                    let mut status = 0u32;
                    let r = mft.ProcessOutput(0, &mut out, &mut status);
                    let sample = std::mem::ManuallyDrop::take(&mut out[0].pSample);
                    drop(std::mem::ManuallyDrop::take(&mut out[0].pEvents));
                    match r {
                        Ok(()) => {
                            let Some(sample) = sample else { continue };
                            let b = sample
                                .ConvertToContiguousBuffer()
                                .map_err(|e| err("buffer", e))?;
                            let mut p = std::ptr::null_mut();
                            let mut len = 0u32;
                            b.Lock(&mut p, None, Some(&mut len))
                                .map_err(|e| err("lock", e))?;
                            pcm.extend_from_slice(std::slice::from_raw_parts(p, len as usize));
                            let _ = b.Unlock();
                        }
                        Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                        Err(e) => return Err(err("decode", e)),
                    }
                }
            }
        }
    }

    impl AudioDecoder for MfAudio {
        fn accepts(&self, f: &AudioFormat) -> bool {
            if is_aac(f.tag) {
                self.aac && playable(f, &AAC_RATES)
            } else {
                f.tag == WAVE_FORMAT_MPEGLAYER3 && self.mp3 && playable(f, &MP3_RATES)
            }
        }

        fn open(&mut self, f: &AudioFormat) -> Result<PcmFormat, String> {
            self.close();
            if !self.accepts(f) {
                return Err(format!("format {:#06x} not decodable", f.tag));
            }
            if self.started.is_none() {
                self.started = Some(Started::new()?);
            }
            self.format = Some(f.clone());
            // AAC configuration may depend on the first wave.
            if !is_aac(f.tag) || f.extra.len() >= 12 {
                self.mft = Some(self.configure(&[])?);
            }
            Ok(pcm_of(f))
        }

        fn decode(&mut self, data: &[u8], pcm: &mut Vec<u8>) -> Result<(), String> {
            if data.is_empty() {
                return Ok(());
            }
            let mft = match &self.mft {
                Some(m) => m.clone(),
                None => {
                    let m = self.configure(data)?;
                    self.mft = Some(m.clone());
                    m
                }
            };
            // SAFETY: calls on the owned decoder; see `input` and `drain`.
            unsafe {
                match Self::input(&mft, data) {
                    Ok(()) => {}
                    Err(e) if e.code() == MF_E_NOTACCEPTING => {
                        Self::drain(&mft, pcm)?;
                        Self::input(&mft, data).map_err(|e| err("decode", e))?;
                    }
                    Err(e) => return Err(err("decode", e)),
                }
                Self::drain(&mft, pcm)
            }
        }

        fn close(&mut self) {
            self.mft = None;
            self.format = None;
        }
    }

    impl Drop for MfAudio {
        fn drop(&mut self) {
            // The decoder goes before Media Foundation shuts down.
            self.mft = None;
            self.started = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aac(channels: u16, rate: u32, extra: Vec<u8>) -> AudioFormat {
        AudioFormat {
            tag: WAVE_FORMAT_AAC_MS,
            channels,
            samples_per_sec: rate,
            avg_bytes_per_sec: 12_000,
            block_align: 4,
            bits_per_sample: 16,
            extra,
        }
    }

    /// 44.1 kHz stereo AAC-LC is 0x12 0x10; 48 kHz mono is 0x11 0x88
    /// (00010 0011 0001 000).
    #[test]
    fn audio_specific_config() {
        assert_eq!(aac_lc_config(&aac(2, 44_100, vec![])), Some([0x12, 0x10]));
        assert_eq!(aac_lc_config(&aac(1, 48_000, vec![])), Some([0x11, 0x88]));
        assert_eq!(aac_lc_config(&aac(2, 8_000, vec![])), Some([0x15, 0x90]));
        assert_eq!(aac_lc_config(&aac(2, 44_000, vec![])), None);
    }

    #[test]
    fn aac_user_data_choices() {
        // HEAACWAVEINFO tail in the format: used as is.
        let tail = vec![1, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x10];
        assert_eq!(
            aac_user_data(&aac(2, 44_100, tail.clone()), &[0; 4]),
            Some((1, tail))
        );
        // ADTS syncword in the first wave.
        let (payload, data) = aac_user_data(&aac(2, 44_100, vec![]), &[0xFF, 0xF1, 0x50]).unwrap();
        assert_eq!((payload, data.len()), (1, 12));
        // Raw frames: the configuration from the format, or from the
        // server's 2-byte AudioSpecificConfig.
        let (payload, data) = aac_user_data(&aac(2, 44_100, vec![]), &[0x21, 0x00]).unwrap();
        assert_eq!(
            (payload, &data[..2], &data[12..]),
            (0, &[0, 0][..], &[0x12, 0x10][..])
        );
        let (_, data) = aac_user_data(&aac(2, 44_100, vec![0x13, 0x08]), &[0x21]).unwrap();
        assert_eq!(data[12..], [0x13, 0x08]);
    }

    /// One silent MPEG-1 Layer III frame: 128 kbit/s, 44.1 kHz, stereo,
    /// no CRC (header FF FB 90 00, ISO/IEC 11172-3 2.4.1.3), all-zero side
    /// information and main data: 417 bytes, 1152 samples per channel.
    #[cfg(windows)]
    fn silent_mp3_frame() -> Vec<u8> {
        let mut f = vec![0xFF, 0xFB, 0x90, 0x00];
        f.resize(144 * 128_000 / 44_100, 0);
        f
    }

    /// Decodes generated MP3 and AAC frames with the Windows decoders; no
    /// audio device is opened. Ignored by default: it needs Media
    /// Foundation (`cargo test -p rdpc -- --ignored media_foundation_audio`).
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn media_foundation_audio_decodes_silence() {
        use rdp::rdpsnd::codec::WAVE_FORMAT_MPEGLAYER3;
        let mut d = win::MfAudio::probe().expect("Media Foundation audio decoders");
        let mp3 = AudioFormat {
            tag: WAVE_FORMAT_MPEGLAYER3,
            channels: 2,
            samples_per_sec: 44_100,
            avg_bytes_per_sec: 16_000,
            block_align: 1,
            bits_per_sample: 0,
            extra: vec![],
        };
        assert!(d.accepts(&mp3));
        let pcm = d.open(&mp3).unwrap();
        assert_eq!((pcm.channels, pcm.sample_rate, pcm.bits), (2, 44_100, 16));
        let mut out = Vec::new();
        for _ in 0..4 {
            d.decode(&silent_mp3_frame(), &mut out).unwrap();
        }
        assert!(out.len() >= 3 * 1152 * 4, "{} bytes", out.len());
        assert_eq!(out.len() % 4, 0);
        assert!(out.iter().all(|&b| b == 0), "silence decodes to zeros");

        // Raw AAC-LC, mono 44.1 kHz: a single channel element with
        // global_gain 0, max_sfb 0 and no tools, then ID_END
        // (ISO/IEC 14496-3 4.4.2): 32 bits, 0x00 0x00 0x00 0x07.
        let aac = aac(1, 44_100, vec![]);
        assert!(d.accepts(&aac));
        d.open(&aac).unwrap();
        let mut out = Vec::new();
        for _ in 0..4 {
            d.decode(&[0x00, 0x00, 0x00, 0x07], &mut out).unwrap();
        }
        assert!(out.len() >= 2 * 1024 * 2, "{} bytes", out.len());
        assert!(out.iter().all(|&b| b == 0), "silence decodes to zeros");
        d.close();
    }
}
