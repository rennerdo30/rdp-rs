//! Local microphone for the `AUDIO_INPUT` channel: [`WaveIn`] captures PCM
//! through the Windows waveIn API (winmm), and [`input_devices`] lists the
//! capture devices by name.
//!
//! The backend runs on the session worker thread and never blocks it:
//! [`SLOTS`] buffers are queued with the driver; each session tick collects
//! the filled ones in order and queues them again. Nothing is opened until
//! the server starts recording and the user has switched the microphone on.

use std::sync::{Arc, Mutex};

use rdp::audin::CaptureBackend;
use rdp::rdpsnd::{CLIENT_FORMATS, PcmFormat};

/// Capture buffers queued with the driver.
pub const SLOTS: usize = 8;

/// The capture device a session uses: a waveIn device index, or None for
/// the system default (WAVE_MAPPER). Read when capture starts, so a change
/// applies from the next start.
pub type DeviceChoice = Arc<Mutex<Option<u32>>>;

/// Names of the waveIn capture devices; the position is the device index.
#[cfg(windows)]
pub fn input_devices() -> Vec<String> {
    win::devices()
}

#[cfg(not(windows))]
pub fn input_devices() -> Vec<String> {
    Vec::new()
}

/// Capture backend on a waveIn device.
pub struct WaveIn {
    device: DeviceChoice,
    #[cfg(windows)]
    capture: Option<win::Capture>,
}

impl WaveIn {
    pub fn new(device: DeviceChoice) -> Self {
        Self {
            device,
            #[cfg(windows)]
            capture: None,
        }
    }

    fn chosen_device(&self) -> Option<u32> {
        *self.device.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Bytes per capture buffer: one server packet, kept between 10 and 200 ms
/// so tiny packets do not flood the driver and huge ones do not add latency.
fn buffer_bytes(format: &PcmFormat, frames_per_packet: u32) -> usize {
    let min = format.sample_rate / 100;
    let max = format.sample_rate / 5;
    frames_per_packet.clamp(min, max) as usize * usize::from(format.block_align())
}

/// A device name from a fixed-size, NUL-terminated UTF-16 field.
fn wide_name(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

impl CaptureBackend for WaveIn {
    fn formats(&self) -> Vec<PcmFormat> {
        // The wave mapper converts from the device's native format, so every
        // PCM format the client knows can be captured.
        CLIENT_FORMATS.to_vec()
    }

    #[cfg(windows)]
    fn start(&mut self, format: &PcmFormat, frames_per_packet: u32) -> Result<(), String> {
        self.stop();
        let bytes = buffer_bytes(format, frames_per_packet);
        self.capture = Some(win::Capture::open(self.chosen_device(), format, bytes)?);
        Ok(())
    }

    #[cfg(not(windows))]
    fn start(&mut self, _format: &PcmFormat, _frames_per_packet: u32) -> Result<(), String> {
        let _ = self.chosen_device();
        Err("no audio capture on this platform".into())
    }

    #[cfg(windows)]
    fn read(&mut self) -> Option<Vec<u8>> {
        self.capture.as_mut()?.read()
    }

    #[cfg(not(windows))]
    fn read(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn stop(&mut self) {
        // Capture::drop stops recording and releases the buffers.
        #[cfg(windows)]
        {
            self.capture = None;
        }
    }
}

#[cfg(windows)]
mod win {
    use std::ptr::{addr_of, null_mut};

    use rdp::rdpsnd::PcmFormat;
    use windows_sys::Win32::Media::Audio::{
        CALLBACK_NULL, HWAVEIN, WAVE_MAPPED, WAVE_MAPPER, WAVEFORMATEX, WAVEHDR, WAVEINCAPSW,
        WHDR_DONE, waveInAddBuffer, waveInClose, waveInGetDevCapsW, waveInGetNumDevs, waveInOpen,
        waveInPrepareHeader, waveInReset, waveInStart, waveInUnprepareHeader,
    };
    use windows_sys::Win32::Media::MMSYSERR_NOERROR;

    use super::{SLOTS, wide_name};

    const HDR_SIZE: u32 = std::mem::size_of::<WAVEHDR>() as u32;

    pub fn devices() -> Vec<String> {
        // SAFETY: plain query calls with a correctly sized out structure.
        let count = unsafe { waveInGetNumDevs() };
        (0..count)
            .map(|i| {
                let mut caps = WAVEINCAPSW::default();
                let size = std::mem::size_of::<WAVEINCAPSW>() as u32;
                let rc = unsafe { waveInGetDevCapsW(i as usize, &mut caps, size) };
                if rc == MMSYSERR_NOERROR {
                    let name = caps.szPname;
                    wide_name(&name)
                } else {
                    format!("Microphone {}", i + 1)
                }
            })
            .collect()
    }

    /// One capture buffer. The header is boxed so its address stays fixed
    /// while the driver owns it; `data` is never resized while queued.
    struct Slot {
        hdr: Box<WAVEHDR>,
        data: Vec<u8>,
        queued: bool,
    }

    /// An open, recording waveIn handle with its buffer ring.
    pub struct Capture {
        handle: HWAVEIN,
        slots: Vec<Slot>,
        /// The slot the driver fills next (buffers complete in queue order).
        next: usize,
    }

    // SAFETY: a waveIn handle and its headers may be used from any thread;
    // the Capture is owned by one thread at a time (the session worker) and
    // the driver touches only the queued headers and buffers, which stay
    // alive and unmoved until they are unprepared.
    unsafe impl Send for Capture {}

    impl Capture {
        pub fn open(device: Option<u32>, format: &PcmFormat, bytes: usize) -> Result<Self, String> {
            let wfx = WAVEFORMATEX {
                wFormatTag: 1, // WAVE_FORMAT_PCM
                nChannels: format.channels,
                nSamplesPerSec: format.sample_rate,
                nAvgBytesPerSec: format.avg_bytes_per_sec(),
                nBlockAlign: format.block_align(),
                wBitsPerSample: format.bits,
                cbSize: 0,
            };
            // A chosen device goes through the mapper too (WAVE_MAPPED), so
            // it records in any PCM format.
            let (id, flags) = match device {
                Some(i) => (i, CALLBACK_NULL | WAVE_MAPPED),
                None => (WAVE_MAPPER, CALLBACK_NULL),
            };
            let mut handle: HWAVEIN = null_mut();
            // SAFETY: valid out pointer and format; no callback, so filled
            // buffers are found by polling WHDR_DONE.
            let rc = unsafe { waveInOpen(&mut handle, id, &wfx, 0, 0, flags) };
            if rc != MMSYSERR_NOERROR {
                return Err(format!("waveInOpen failed ({rc})"));
            }
            let mut capture = Self {
                handle,
                slots: (0..SLOTS)
                    .map(|_| Slot {
                        hdr: Box::default(),
                        data: vec![0; bytes],
                        queued: false,
                    })
                    .collect(),
                next: 0,
            };
            for i in 0..SLOTS {
                capture.queue(i)?;
            }
            // SAFETY: open handle with buffers queued.
            let rc = unsafe { waveInStart(handle) };
            if rc != MMSYSERR_NOERROR {
                return Err(format!("waveInStart failed ({rc})"));
            }
            Ok(capture)
        }

        /// Hands slot `i` to the driver.
        fn queue(&mut self, i: usize) -> Result<(), String> {
            let handle = self.handle;
            let slot = &mut self.slots[i];
            *slot.hdr = WAVEHDR {
                lpData: slot.data.as_mut_ptr(),
                dwBufferLength: slot.data.len() as u32,
                ..Default::default()
            };
            let hdr: *mut WAVEHDR = &mut *slot.hdr;
            // SAFETY: the header and its buffer live in the slot, which is
            // neither moved nor modified until reclaimed or the capture drops.
            unsafe {
                let rc = waveInPrepareHeader(handle, hdr, HDR_SIZE);
                if rc != MMSYSERR_NOERROR {
                    return Err(format!("waveInPrepareHeader failed ({rc})"));
                }
                let rc = waveInAddBuffer(handle, hdr, HDR_SIZE);
                if rc != MMSYSERR_NOERROR {
                    waveInUnprepareHeader(handle, hdr, HDR_SIZE);
                    return Err(format!("waveInAddBuffer failed ({rc})"));
                }
            }
            slot.queued = true;
            Ok(())
        }

        /// The next filled buffer's audio, or None if the driver is still
        /// filling it. The buffer goes straight back to the driver.
        pub fn read(&mut self) -> Option<Vec<u8>> {
            // Skip slots that could not be queued again; the rest keep going.
            for _ in 0..SLOTS {
                if self.slots[self.next].queued {
                    break;
                }
                self.next = (self.next + 1) % SLOTS;
            }
            let i = self.next;
            let slot = &mut self.slots[i];
            if !slot.queued {
                return None;
            }
            let hdr: *mut WAVEHDR = &mut *slot.hdr;
            // SAFETY: the driver writes these fields of a queued header;
            // WAVEHDR is packed, so they are read unaligned.
            let (flags, recorded) = unsafe {
                (
                    addr_of!((*hdr).dwFlags).read_unaligned(),
                    addr_of!((*hdr).dwBytesRecorded).read_unaligned(),
                )
            };
            if flags & WHDR_DONE == 0 {
                return None;
            }
            // SAFETY: the header was prepared on this handle and is done.
            unsafe { waveInUnprepareHeader(self.handle, hdr, HDR_SIZE) };
            slot.queued = false;
            let n = (recorded as usize).min(slot.data.len());
            let audio = slot.data[..n].to_vec();
            self.next = (i + 1) % SLOTS;
            // On failure the ring shrinks by one; the others keep recording.
            let _ = self.queue(i);
            Some(audio)
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            // SAFETY: waveInReset stops recording and returns every queued
            // buffer marked done, so each can be unprepared before the
            // handle closes and the slots are freed.
            unsafe {
                waveInReset(self.handle);
                for slot in &mut self.slots {
                    if slot.queued {
                        waveInUnprepareHeader(self.handle, &mut *slot.hdr, HDR_SIZE);
                        slot.queued = false;
                    }
                }
                waveInClose(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No device is opened or enumerated here: only the pure helpers and the
    // closed state. Live capture is never tested automatically.

    const STEREO_48: PcmFormat = PcmFormat {
        channels: 2,
        sample_rate: 48_000,
        bits: 16,
    };

    #[test]
    fn buffer_is_one_packet_within_10_to_200_ms() {
        assert_eq!(buffer_bytes(&STEREO_48, 960), 960 * 4);
        assert_eq!(buffer_bytes(&STEREO_48, 1), 480 * 4);
        assert_eq!(buffer_bytes(&STEREO_48, 100_000), 9600 * 4);
    }

    #[test]
    fn wide_name_stops_at_nul() {
        let mut w = [0u16; 32];
        for (i, c) in "Mic (USB)".encode_utf16().enumerate() {
            w[i] = c;
        }
        w[10] = u16::from(b'x');
        assert_eq!(wide_name(&w), "Mic (USB)");
        let full = [u16::from(b'a'); 32];
        assert_eq!(wide_name(&full).len(), 32);
    }

    #[test]
    fn closed_backend_reads_nothing() {
        let mut w = WaveIn::new(Arc::new(Mutex::new(Some(3))));
        assert_eq!(w.chosen_device(), Some(3));
        assert!(w.read().is_none());
        w.stop();
        assert_eq!(w.formats(), CLIENT_FORMATS);
    }

    /// Records one second from the default microphone. Never run
    /// automatically: it opens the owner's real capture device.
    #[test]
    #[ignore = "records from the real microphone"]
    fn live_capture_default_device() {
        let mut w = WaveIn::new(Arc::new(Mutex::new(None)));
        w.start(&STEREO_48, 960).unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut total = 0;
        while std::time::Instant::now() < until {
            while let Some(b) = w.read() {
                total += b.len();
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        w.stop();
        assert!(total > 0);
    }
}
