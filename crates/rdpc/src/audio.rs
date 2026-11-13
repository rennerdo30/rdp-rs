//! Local audio output for the `rdpsnd` channel: [`WaveOut`] plays PCM
//! through the Windows waveOut API (winmm).
//!
//! The backend runs on the session worker thread and never blocks it: each
//! wave is copied into one of [`SLOTS`] buffers and queued; finished buffers
//! are recycled on the next write; when all are still playing the wave is
//! dropped. The queue therefore holds at most [`SLOTS`] waves of latency.

use rdp::rdpsnd::{AudioBackend, PcmFormat};

/// Queued buffers (one wave each). Windows servers send waves of about 20 to
/// 50 ms, so this bounds the local latency to a few hundred milliseconds
/// while riding out network jitter.
pub const SLOTS: usize = 12;

/// Audio backend on the default waveOut device (WAVE_MAPPER).
#[derive(Default)]
pub struct WaveOut {
    #[cfg(windows)]
    device: Option<win::Device>,
    /// Waves dropped because every buffer was still queued.
    dropped: u64,
}

#[cfg(windows)]
impl AudioBackend for WaveOut {
    fn open(&mut self, format: &PcmFormat) -> Result<(), String> {
        self.close();
        self.device = Some(win::Device::open(format)?);
        Ok(())
    }

    fn write(&mut self, samples: &[u8]) -> Result<(), String> {
        let Some(device) = self.device.as_mut() else {
            return Err("audio device not open".into());
        };
        if !device.write(samples)? {
            self.dropped += 1;
        }
        Ok(())
    }

    fn close(&mut self) {
        // Device::drop stops playback and releases the buffers.
        self.device = None;
    }
}

#[cfg(not(windows))]
impl AudioBackend for WaveOut {
    fn open(&mut self, _format: &PcmFormat) -> Result<(), String> {
        Err("no audio output on this platform".into())
    }

    fn write(&mut self, _samples: &[u8]) -> Result<(), String> {
        Err("no audio output on this platform".into())
    }

    fn close(&mut self) {}
}

/// WAVEFORMATEX fields for a PCM format, as
/// (wFormatTag, nChannels, nSamplesPerSec, nAvgBytesPerSec, nBlockAlign, wBitsPerSample).
fn wave_format(f: &PcmFormat) -> (u16, u16, u32, u32, u16, u16) {
    (
        1, // WAVE_FORMAT_PCM
        f.channels,
        f.sample_rate,
        f.avg_bytes_per_sec(),
        f.block_align(),
        f.bits,
    )
}

#[cfg(windows)]
mod win {
    use std::ptr::{addr_of, null_mut};

    use rdp::rdpsnd::PcmFormat;
    use windows_sys::Win32::Media::Audio::{
        CALLBACK_NULL, HWAVEOUT, WAVE_MAPPER, WAVEFORMATEX, WAVEHDR, WHDR_DONE, waveOutClose,
        waveOutOpen, waveOutPrepareHeader, waveOutReset, waveOutUnprepareHeader, waveOutWrite,
    };
    use windows_sys::Win32::Media::MMSYSERR_NOERROR;

    use super::{SLOTS, wave_format};

    const HDR_SIZE: u32 = std::mem::size_of::<WAVEHDR>() as u32;

    /// One queue buffer. The header is boxed so its address stays fixed
    /// while the driver owns it; `data` is not resized while queued.
    struct Slot {
        hdr: Box<WAVEHDR>,
        data: Vec<u8>,
        queued: bool,
    }

    /// An open waveOut handle with its buffer ring.
    pub struct Device {
        handle: HWAVEOUT,
        slots: Vec<Slot>,
    }

    // SAFETY: a waveOut handle and its headers may be used from any thread;
    // the Device is owned by one thread at a time (the session worker) and
    // the driver touches only the queued headers and buffers, which stay
    // alive and unmoved until they are unprepared.
    unsafe impl Send for Device {}

    impl Device {
        pub fn open(format: &PcmFormat) -> Result<Self, String> {
            let (tag, channels, rate, avg, align, bits) = wave_format(format);
            let wfx = WAVEFORMATEX {
                wFormatTag: tag,
                nChannels: channels,
                nSamplesPerSec: rate,
                nAvgBytesPerSec: avg,
                nBlockAlign: align,
                wBitsPerSample: bits,
                cbSize: 0,
            };
            let mut handle: HWAVEOUT = null_mut();
            // SAFETY: valid out pointer and format; no callback (CALLBACK_NULL),
            // so finished buffers are found by polling WHDR_DONE.
            let rc = unsafe { waveOutOpen(&mut handle, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) };
            if rc != MMSYSERR_NOERROR {
                return Err(format!("waveOutOpen failed ({rc})"));
            }
            let slots = (0..SLOTS)
                .map(|_| Slot {
                    hdr: Box::default(),
                    data: Vec::new(),
                    queued: false,
                })
                .collect();
            Ok(Self { handle, slots })
        }

        /// Queues one wave. Returns Ok(false) when it was dropped because
        /// every buffer is still playing.
        pub fn write(&mut self, samples: &[u8]) -> Result<bool, String> {
            if samples.is_empty() {
                return Ok(true);
            }
            let handle = self.handle;
            let Some(slot) = self
                .slots
                .iter_mut()
                .find_map(|s| reclaim(handle, s).then_some(s))
            else {
                return Ok(false);
            };
            slot.data.clear();
            slot.data.extend_from_slice(samples);
            *slot.hdr = WAVEHDR {
                lpData: slot.data.as_mut_ptr(),
                dwBufferLength: slot.data.len() as u32,
                ..Default::default()
            };
            let hdr: *mut WAVEHDR = &mut *slot.hdr;
            // SAFETY: the header and its buffer live in the slot, which is
            // neither moved nor modified until reclaimed or the device drops.
            unsafe {
                let rc = waveOutPrepareHeader(handle, hdr, HDR_SIZE);
                if rc != MMSYSERR_NOERROR {
                    return Err(format!("waveOutPrepareHeader failed ({rc})"));
                }
                let rc = waveOutWrite(handle, hdr, HDR_SIZE);
                if rc != MMSYSERR_NOERROR {
                    waveOutUnprepareHeader(handle, hdr, HDR_SIZE);
                    return Err(format!("waveOutWrite failed ({rc})"));
                }
            }
            slot.queued = true;
            Ok(true)
        }
    }

    /// True if the slot is free, unpreparing it first when the driver is
    /// done with it.
    fn reclaim(handle: HWAVEOUT, slot: &mut Slot) -> bool {
        if !slot.queued {
            return true;
        }
        let hdr: *mut WAVEHDR = &mut *slot.hdr;
        // SAFETY: the driver sets dwFlags of a queued header; WAVEHDR is
        // packed, so the field is read unaligned through the raw pointer.
        let flags = unsafe { addr_of!((*hdr).dwFlags).read_unaligned() };
        if flags & WHDR_DONE == 0 {
            return false;
        }
        // SAFETY: the header was prepared on this handle and is done.
        unsafe { waveOutUnprepareHeader(handle, hdr, HDR_SIZE) };
        slot.queued = false;
        true
    }

    impl Drop for Device {
        fn drop(&mut self) {
            // SAFETY: waveOutReset returns every queued buffer marked done,
            // so each can be unprepared before the handle closes and the
            // slots are freed.
            unsafe {
                waveOutReset(self.handle);
                for slot in &mut self.slots {
                    if slot.queued {
                        waveOutUnprepareHeader(self.handle, &mut *slot.hdr, HDR_SIZE);
                        slot.queued = false;
                    }
                }
                waveOutClose(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No device is opened here: only the format mapping and the closed state.

    #[test]
    fn wave_format_for_48k_stereo() {
        let f = PcmFormat {
            channels: 2,
            sample_rate: 48_000,
            bits: 16,
        };
        assert_eq!(wave_format(&f), (1, 2, 48_000, 192_000, 4, 16));
    }

    #[test]
    fn write_before_open_is_an_error() {
        let mut w = WaveOut::default();
        assert!(w.write(&[0; 4]).is_err());
        w.close();
        assert_eq!(w.dropped, 0);
    }
}
