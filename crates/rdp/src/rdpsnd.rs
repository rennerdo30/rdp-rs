//! Audio output redirection, client side (MS-RDPEA) on the `rdpsnd` static
//! virtual channel.
//!
//! Scope: uncompressed PCM, 16-bit, mono or stereo, 44.1 or 48 kHz
//! ([`CLIENT_FORMATS`]). The client advertises no UDP port, so all audio
//! arrives over the virtual channel as WaveInfo + Wave PDUs (versions below
//! 8) or Wave2 PDUs (both sides at version 8).
//!
//! Windows servers only talk on `rdpsnd` when the client also advertises the
//! `rdpdr` channel (MS-RDPEA 2.1, product note <1>), and Windows 8 and later
//! first try the `AUDIO_PLAYBACK_DVC` dynamic channel; the client refuses
//! unknown dynamic channels, which makes the server fall back to this static
//! channel (MS-RDPEA 3.1.3, note <11>).
//!
//! Sharing starts off and is toggled live through [`AudioHandle`]. The
//! format negotiation happens once, whatever the switch says; "off" means
//! every wave is still confirmed to the server but its samples are dropped
//! and the local device is closed (repository rule: sharing features toggle
//! without reconnecting). Turning sharing on takes effect on the next wave.
//!
//! Flow (MS-RDPEA 1.3.2):
//! - initialization: Server Audio Formats and Version PDU, client answers
//!   with its Client Audio Formats and Version PDU and, when both versions
//!   are at least 6, a Quality Mode PDU; Training PDUs are echoed at any time;
//! - data: WaveInfo + Wave (or Wave2) carry one audio sample, the client
//!   answers each with a Wave Confirm PDU; a Close PDU ends the stream.
//!
//! Audio data is never traced; only sizes, block numbers and format indexes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};
use crate::trace;

// RDPSND PDU Header msgType values (MS-RDPEA 2.2.1).
pub const SNDC_CLOSE: u8 = 0x01;
pub const SNDC_WAVE: u8 = 0x02;
pub const SNDC_SETVOLUME: u8 = 0x03;
pub const SNDC_SETPITCH: u8 = 0x04;
pub const SNDC_WAVECONFIRM: u8 = 0x05;
pub const SNDC_TRAINING: u8 = 0x06;
pub const SNDC_FORMATS: u8 = 0x07;
pub const SNDC_CRYPTKEY: u8 = 0x08;
pub const SNDC_WAVEENCRYPT: u8 = 0x09;
pub const SNDC_UDPWAVE: u8 = 0x0A;
pub const SNDC_UDPWAVELAST: u8 = 0x0B;
pub const SNDC_QUALITYMODE: u8 = 0x0C;
pub const SNDC_WAVE2: u8 = 0x0D;

// Client Audio Formats and Version dwFlags (MS-RDPEA 2.2.2.2).
pub const TSSNDCAPS_ALIVE: u32 = 0x0000_0001;
pub const TSSNDCAPS_VOLUME: u32 = 0x0000_0002;
pub const TSSNDCAPS_PITCH: u32 = 0x0000_0004;

// Quality Mode PDU wQualityMode (MS-RDPEA 2.2.2.3).
pub const DYNAMIC_QUALITY: u16 = 0x0000;
pub const MEDIUM_QUALITY: u16 = 0x0001;
pub const HIGH_QUALITY: u16 = 0x0002;

/// WAVE_FORMAT_PCM, the format tag every client and server supports
/// (MS-RDPEA 2.2.2.1.1).
pub const WAVE_FORMAT_PCM: u16 = 0x0001;

/// Protocol version the client advertises: 8, the version of Windows 8 and
/// later, which enables Wave2 PDUs (MS-RDPEA 2.2.2.2 note <6>, 1.3.2.2).
pub const CLIENT_VERSION: u16 = 8;

/// Size of the RDPSND PDU Header (MS-RDPEA 2.2.1).
const HEADER: usize = 4;
/// Body of a WaveInfo PDU without its header: wTimeStamp, wFormatNo,
/// cBlockNo, bPad and the first four data bytes (MS-RDPEA 2.2.3.3).
const WAVE_INFO_BODY: usize = 12;
/// Wave2 fields before the audio data (MS-RDPEA 2.2.3.10).
const WAVE2_FIXED: usize = 12;

/// An uncompressed PCM format the local device plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmFormat {
    pub channels: u16,
    pub sample_rate: u32,
    pub bits: u16,
}

impl PcmFormat {
    /// Bytes per sample frame (all channels).
    pub fn block_align(&self) -> u16 {
        self.channels * self.bits.div_ceil(8)
    }

    pub fn avg_bytes_per_sec(&self) -> u32 {
        self.sample_rate * u32::from(self.block_align())
    }
}

/// PCM formats this client accepts, 16-bit at 44.1 and 48 kHz, stereo and
/// mono. The client offers each server format that matches one exactly.
pub const CLIENT_FORMATS: &[PcmFormat] = &[
    PcmFormat {
        channels: 2,
        sample_rate: 48_000,
        bits: 16,
    },
    PcmFormat {
        channels: 2,
        sample_rate: 44_100,
        bits: 16,
    },
    PcmFormat {
        channels: 1,
        sample_rate: 48_000,
        bits: 16,
    },
    PcmFormat {
        channels: 1,
        sample_rate: 44_100,
        bits: 16,
    },
];

/// The local audio output. Runs on the session worker thread, so every call
/// must return quickly: queue the samples and drop audio rather than block.
pub trait AudioBackend: Send {
    /// Opens the device for `format`. Called before the first samples and
    /// whenever the format changes (after [`AudioBackend::close`]).
    fn open(&mut self, format: &PcmFormat) -> std::result::Result<(), String>;
    /// Queues one audio sample (whole frames in the open format).
    fn write(&mut self, samples: &[u8]) -> std::result::Result<(), String>;
    /// Stops playback and releases the device.
    fn close(&mut self);
}

/// UI-side switch for audio playback. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct AudioHandle {
    enabled: Arc<AtomicBool>,
}

impl AudioHandle {
    /// Turns playback on or off. On takes effect with the next wave; off
    /// drops the next wave and closes the device on the next session poll.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Creates the `rdpsnd` channel handler and its UI switch. Playback starts off.
pub fn rdpsnd(backend: Box<dyn AudioBackend>) -> (Rdpsnd, AudioHandle) {
    let enabled = Arc::new(AtomicBool::new(false));
    let handle = AudioHandle {
        enabled: enabled.clone(),
    };
    let channel = Rdpsnd {
        backend,
        enabled,
        server_version: 0,
        formats: Vec::new(),
        pending: None,
        open: None,
        clock: Arc::new(Instant::now),
    };
    (channel, handle)
}

/// One AUDIO_FORMAT structure (MS-RDPEA 2.2.2.1.1), kept byte-exact so the
/// client can echo the server's entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioFormat {
    pub tag: u16,
    pub channels: u16,
    pub samples_per_sec: u32,
    pub avg_bytes_per_sec: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    /// Format-specific extra data (cbSize bytes).
    pub extra: Vec<u8>,
}

impl AudioFormat {
    fn parse(r: &mut Reader) -> Result<Self> {
        let tag = r.u16()?;
        let channels = r.u16()?;
        let samples_per_sec = r.u32()?;
        let avg_bytes_per_sec = r.u32()?;
        let block_align = r.u16()?;
        let bits_per_sample = r.u16()?;
        let cb_size = r.u16()? as usize;
        let extra = r.bytes(cb_size)?.to_vec();
        Ok(Self {
            tag,
            channels,
            samples_per_sec,
            avg_bytes_per_sec,
            block_align,
            bits_per_sample,
            extra,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.tag);
        out.put_u16(self.channels);
        out.put_u32(self.samples_per_sec);
        out.put_u32(self.avg_bytes_per_sec);
        out.put_u16(self.block_align);
        out.put_u16(self.bits_per_sample);
        out.put_u16(self.extra.len() as u16);
        out.put_bytes(&self.extra);
    }

    /// The matching entry of [`CLIENT_FORMATS`], if this is one of them with
    /// consistent PCM fields.
    fn client_pcm(&self) -> Option<PcmFormat> {
        if self.tag != WAVE_FORMAT_PCM {
            return None;
        }
        CLIENT_FORMATS.iter().copied().find(|f| {
            f.channels == self.channels
                && f.sample_rate == self.samples_per_sec
                && f.bits == self.bits_per_sample
                && f.block_align() == self.block_align
                && f.avg_bytes_per_sec() == self.avg_bytes_per_sec
        })
    }
}

/// Fields of a Server Audio Formats and Version PDU the client uses
/// (MS-RDPEA 2.2.2.1).
#[derive(Debug, PartialEq, Eq)]
pub struct ServerFormats {
    pub last_block_confirmed: u8,
    pub version: u16,
    pub formats: Vec<AudioFormat>,
}

/// Parses the body (after the header) of a Server Audio Formats and Version
/// PDU (MS-RDPEA 2.2.2.1). dwFlags, dwVolume, dwPitch, wDGramPort and bPad
/// are ignored on receipt.
pub fn parse_server_formats(body: &[u8]) -> Result<ServerFormats> {
    let mut r = Reader::new(body);
    r.skip(4 + 4 + 4 + 2)?;
    let count = r.u16()?;
    let last_block_confirmed = r.u8()?;
    let version = r.u16()?;
    r.skip(1)?;
    // Each AUDIO_FORMAT is at least 18 bytes: bound the count by the data
    // before allocating.
    if usize::from(count) * 18 > r.remaining() {
        return proto(format!(
            "rdpsnd: {count} formats announced, {} bytes left",
            r.remaining()
        ));
    }
    let mut formats = Vec::with_capacity(count.into());
    for _ in 0..count {
        formats.push(AudioFormat::parse(&mut r)?);
    }
    Ok(ServerFormats {
        last_block_confirmed,
        version,
        formats,
    })
}

/// RDPSND PDU Header + body (MS-RDPEA 2.2.1). bPad is sent as 0.
fn pdu(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER + body.len());
    v.put_u8(msg_type);
    v.put_u8(0);
    v.put_u16(body.len() as u16);
    v.put_bytes(body);
    v
}

/// Client Audio Formats and Version PDU (MS-RDPEA 2.2.2.2). wDGramPort is
/// always 0 (no UDP; MS-RDPEA 3.2.5.1.1.2) and bPad is 0.
pub fn client_formats(
    flags: u32,
    volume: u32,
    pitch: u32,
    last_block_confirmed: u8,
    version: u16,
    formats: &[AudioFormat],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u32(flags);
    b.put_u32(volume);
    b.put_u32(pitch);
    b.put_u16_be(0);
    b.put_u16(formats.len() as u16);
    b.put_u8(last_block_confirmed);
    b.put_u16(version);
    b.put_u8(0);
    for f in formats {
        f.write(&mut b);
    }
    pdu(SNDC_FORMATS, &b)
}

/// Quality Mode PDU (MS-RDPEA 2.2.2.3).
pub fn quality_mode(mode: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.put_u16(mode);
    b.put_u16(0);
    pdu(SNDC_QUALITYMODE, &b)
}

/// Training Confirm PDU echoing the Training PDU's fields (MS-RDPEA 2.2.3.2).
pub fn training_confirm(timestamp: u16, pack_size: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.put_u16(timestamp);
    b.put_u16(pack_size);
    pdu(SNDC_TRAINING, &b)
}

/// Wave Confirm PDU (MS-RDPEA 2.2.3.8).
pub fn wave_confirm(timestamp: u16, block_no: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.put_u16(timestamp);
    b.put_u8(block_no);
    b.put_u8(0);
    pdu(SNDC_WAVECONFIRM, &b)
}

/// A WaveInfo PDU waiting for its Wave PDU (MS-RDPEA 2.2.3.3).
struct WaveInfo {
    timestamp: u16,
    format_no: u16,
    block_no: u8,
    first: [u8; 4],
    /// Total audio bytes: the four in `first` plus the Wave PDU's data.
    total: usize,
}

/// Client side of the audio output virtual channel.
pub struct Rdpsnd {
    backend: Box<dyn AudioBackend>,
    enabled: Arc<AtomicBool>,
    /// wVersion of the last Server Audio Formats and Version PDU.
    server_version: u16,
    /// The client's format list; wFormatNo indexes it (MS-RDPEA 3.1.1.2).
    formats: Vec<PcmFormat>,
    /// WaveInfo PDU whose Wave PDU is the next message.
    pending: Option<WaveInfo>,
    /// Format the backend is open with; None while closed.
    open: Option<PcmFormat>,
    /// Time source for the Wave Confirm timestamp (replaced in tests).
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Rdpsnd {
    fn playing(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn close_backend(&mut self) {
        if self.open.take().is_some() {
            self.backend.close();
        }
    }

    /// Server Audio Formats and Version PDU (MS-RDPEA 3.2.5.1.1.1): answers
    /// with the supported subset of the server's formats, in the server's
    /// order (3.2.5.1.1.2), then a Quality Mode PDU if both versions are at
    /// least 6 (3.2.5.1.1.3). A repeated PDU restarts the protocol (3.2.5.2.1.7).
    fn server_formats(&mut self, body: &[u8], out: &mut ChannelOut) -> Result<()> {
        let server = parse_server_formats(body)?;
        self.close_backend();
        self.pending = None;
        self.server_version = server.version;
        let mut offered = Vec::new();
        self.formats.clear();
        for f in &server.formats {
            if let Some(pcm) = f.client_pcm() {
                offered.push(f.clone());
                self.formats.push(pcm);
            }
        }
        trace!(
            "rdpsnd: server version {} offers {} formats, client takes {}",
            server.version,
            server.formats.len(),
            offered.len()
        );
        out.send(client_formats(
            TSSNDCAPS_ALIVE,
            0,
            0,
            0,
            CLIENT_VERSION,
            &offered,
        ));
        if server.version >= 6 && CLIENT_VERSION >= 6 {
            out.send(quality_mode(HIGH_QUALITY));
        }
        Ok(())
    }

    /// WaveInfo PDU (MS-RDPEA 3.2.5.2.1.1): BodySize covers the WaveInfo
    /// body and the Wave PDU's data, so the audio is BodySize - 8 bytes.
    fn wave_info(&mut self, body_size: usize, body: &[u8]) -> Result<()> {
        if body_size < WAVE_INFO_BODY {
            return proto(format!("rdpsnd: WaveInfo BodySize {body_size} below 12"));
        }
        let mut r = Reader::new(body);
        let timestamp = r.u16()?;
        let format_no = r.u16()?;
        let block_no = r.u8()?;
        r.skip(3)?;
        let first = r.array::<4>()?;
        if self.pending.is_some() {
            trace!("rdpsnd: WaveInfo without its Wave PDU abandoned");
        }
        self.pending = Some(WaveInfo {
            timestamp,
            format_no,
            block_no,
            first,
            total: body_size - (WAVE_INFO_BODY - 4),
        });
        Ok(())
    }

    /// Wave PDU (MS-RDPEA 3.2.5.2.1.2): bPad (4 bytes) then the rest of the
    /// audio; the WaveInfo's four data bytes replace the padding.
    fn wave(&mut self, info: WaveInfo, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let received = (self.clock)();
        let rest = info.total - 4;
        let Some(data) = msg.get(4..4 + rest) else {
            return proto(format!(
                "rdpsnd: Wave PDU {} bytes, WaveInfo announced {}",
                msg.len(),
                info.total
            ));
        };
        let mut sample = Vec::with_capacity(info.total);
        sample.extend_from_slice(&info.first);
        sample.extend_from_slice(data);
        self.consume(
            info.timestamp,
            info.format_no,
            info.block_no,
            &sample,
            received,
            out,
        )
    }

    /// Wave2 PDU (MS-RDPEA 2.2.3.10): one PDU per audio sample.
    fn wave2(&mut self, body: &[u8], out: &mut ChannelOut) -> Result<()> {
        let received = (self.clock)();
        if body.len() < WAVE2_FIXED {
            return proto(format!("rdpsnd: Wave2 body {} bytes", body.len()));
        }
        let mut r = Reader::new(body);
        let timestamp = r.u16()?;
        let format_no = r.u16()?;
        let block_no = r.u8()?;
        r.skip(3)?;
        let _audio_timestamp = r.u32()?;
        self.consume(timestamp, format_no, block_no, r.rest(), received, out)
    }

    /// Plays (or, while off, drops) one audio sample and confirms it at once
    /// (MS-RDPEA 3.2.5.2.1.6). wTimeStamp is the wave's plus the
    /// milliseconds between receiving it and sending the confirm.
    fn consume(
        &mut self,
        timestamp: u16,
        format_no: u16,
        block_no: u8,
        sample: &[u8],
        received: Instant,
        out: &mut ChannelOut,
    ) -> Result<()> {
        let Some(&format) = self.formats.get(usize::from(format_no)) else {
            return proto(format!(
                "rdpsnd: wave format {format_no} of {} negotiated",
                self.formats.len()
            ));
        };
        if self.playing() {
            if self.open != Some(format) {
                self.close_backend();
                match self.backend.open(&format) {
                    Ok(()) => self.open = Some(format),
                    Err(e) => trace!("rdpsnd: audio device open failed: {e}"),
                }
            }
            if self.open.is_some()
                && let Err(e) = self.backend.write(sample)
            {
                trace!("rdpsnd: audio write failed: {e}");
            }
            trace!(
                "rdpsnd: block {block_no} format {format_no}, {} bytes played",
                sample.len()
            );
        } else {
            self.close_backend();
            trace!(
                "rdpsnd: block {block_no}, {} bytes dropped (off)",
                sample.len()
            );
        }
        let elapsed = (self.clock)()
            .saturating_duration_since(received)
            .as_millis();
        let delay = u16::try_from(elapsed).unwrap_or(u16::MAX);
        out.send(wave_confirm(timestamp.wrapping_add(delay), block_no));
        Ok(())
    }
}

impl StaticChannel for Rdpsnd {
    fn name(&self) -> &str {
        "rdpsnd"
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        // A Wave PDU has no RDPSND header; it is whatever follows a WaveInfo.
        if let Some(info) = self.pending.take() {
            return self.wave(info, msg, out);
        }
        let mut r = Reader::new(msg);
        let msg_type = r.u8()?;
        r.skip(1)?;
        let body_size = r.u16()? as usize;
        if msg_type == SNDC_WAVE {
            return self.wave_info(body_size, r.rest());
        }
        let body = r.bytes(body_size)?;
        match msg_type {
            SNDC_FORMATS => self.server_formats(body, out)?,
            SNDC_TRAINING => {
                // Training PDU (MS-RDPEA 2.2.3.1, 3.2.5.1.1.4): echo the
                // timestamp and pack size at once.
                let mut b = Reader::new(body);
                let timestamp = b.u16()?;
                let pack_size = b.u16()?;
                trace!("rdpsnd: training, pack size {pack_size}");
                out.send(training_confirm(timestamp, pack_size));
            }
            SNDC_WAVE2 => self.wave2(body, out)?,
            SNDC_CLOSE => {
                // Close PDU (MS-RDPEA 3.2.5.2.1.7): the stream ends.
                trace!("rdpsnd: close");
                self.close_backend();
            }
            SNDC_SETVOLUME | SNDC_SETPITCH => {
                // Volume and Pitch PDUs (MS-RDPEA 2.2.4.1, 2.2.4.2). The
                // client does not set TSSNDCAPS_VOLUME or TSSNDCAPS_PITCH, so
                // both are ignored (pitch is always ignored, 3.2.5.3.1.2).
                Reader::new(body).u32()?;
                trace!("rdpsnd: volume/pitch PDU {msg_type:#x} ignored");
            }
            _ => {
                // Crypt Key, Wave Encrypt and the UDP PDUs only follow a UDP
                // port the client never advertises (MS-RDPEA 3.1.1.5).
                trace!(
                    "rdpsnd: msgType {msg_type:#x} ({} bytes) ignored",
                    body.len()
                );
            }
        }
        Ok(())
    }

    /// Releases the device as soon as playback is switched off.
    fn tick(&mut self, _out: &mut ChannelOut) -> Result<()> {
        if self.open.is_some() && !self.playing() {
            trace!("rdpsnd: playback off, device closed");
            self.close_backend();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "rdpsnd_tests.rs"]
mod tests;
