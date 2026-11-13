//! Audio input redirection (microphone), client side (MS-RDPEAI) on the
//! `AUDIO_INPUT` dynamic virtual channel (MS-RDPEAI 2.1).
//!
//! Scope: uncompressed PCM in the formats the [`CaptureBackend`] reports
//! (16-bit, mono or stereo, 44.1 or 48 kHz on Windows). The client answers
//! the server's format list with the subset it can capture, and the server
//! picks one of those.
//!
//! Flow (MS-RDPEAI 1.3, 3.2.5):
//! - initialization: server Version PDU, client Version PDU; server Sound
//!   Formats PDU, client Incoming Data PDU + Sound Formats PDU; server Open
//!   PDU, client Format Change PDU (confirming initialFormat) + Open Reply PDU;
//! - data: per captured packet of exactly FramesPerPacket frames, an
//!   Incoming Data PDU and a Data PDU;
//! - format change: server Format Change PDU, the client confirms it with
//!   the same PDU and encodes all later data in the new format;
//! - termination: the dynamic channel closes (3.1.5.2); capture stops.
//!
//! Sharing starts off and is toggled live through [`AudioInputHandle`]. The
//! negotiation always runs, so the channel stays open; "off" means the
//! capture device is closed and no Data PDU is sent. An Open PDU that
//! arrives while off is answered with success, and capture starts as soon as
//! sharing is switched on (on the next channel tick).
//!
//! Malformed, unknown and out-of-sequence PDUs are ignored, as MS-RDPEAI
//! 3.1.5 requires; they never close the channel. Audio data is never traced.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cursor::{Put, Reader};
use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::{Result, proto};
use crate::rdpsnd::{AudioFormat, PcmFormat};
use crate::trace;

/// Dynamic virtual channel name (MS-RDPEAI 2.1).
pub const AUDIO_INPUT: &str = "AUDIO_INPUT";

// SNDIN_PDU header MessageId values (MS-RDPEAI 2.2.1).
pub const MSG_SNDIN_VERSION: u8 = 0x01;
pub const MSG_SNDIN_FORMATS: u8 = 0x02;
pub const MSG_SNDIN_OPEN: u8 = 0x03;
pub const MSG_SNDIN_OPEN_REPLY: u8 = 0x04;
pub const MSG_SNDIN_DATA_INCOMING: u8 = 0x05;
pub const MSG_SNDIN_DATA: u8 = 0x06;
pub const MSG_SNDIN_FORMATCHANGE: u8 = 0x07;

/// Version the client advertises (MS-RDPEAI 2.2.2.1). Version 2 only changes
/// how the server uses Format Change PDUs with AAC formats (3.3.5.3.1),
/// which this client never offers.
pub const CLIENT_VERSION: u32 = 1;

/// HRESULT S_OK for the Open Reply PDU (MS-ERREF 2.1).
pub const S_OK: u32 = 0;
/// HRESULT E_FAIL: the capture device could not be opened (MS-ERREF 2.1).
pub const E_FAIL: u32 = 0x8000_4005;

/// Upper bound for FramesPerPacket: ten seconds at 48 kHz. A larger value
/// is treated as malformed so a bogus Open PDU cannot make the client
/// buffer without limit.
pub const MAX_FRAMES_PER_PACKET: u32 = 480_000;

/// Captured audio the client keeps while the session is slow to tick, in
/// packets. Older audio is dropped beyond this.
const MAX_BACKLOG_PACKETS: usize = 8;

/// The local microphone. Runs on the session worker thread, so every call
/// must return quickly: [`CaptureBackend::read`] returns what is already
/// captured and never waits for more.
pub trait CaptureBackend: Send {
    /// PCM formats the device can capture.
    fn formats(&self) -> Vec<PcmFormat>;
    /// Opens the device and starts capturing in `format`. `frames_per_packet`
    /// is the packet size the server asked for, a hint for buffer sizes.
    fn start(
        &mut self,
        format: &PcmFormat,
        frames_per_packet: u32,
    ) -> std::result::Result<(), String>;
    /// The next block of captured audio (whole frames, any length), or None
    /// when nothing new is available.
    fn read(&mut self) -> Option<Vec<u8>>;
    /// Stops capturing and releases the device.
    fn stop(&mut self);
}

/// UI-side switch for microphone redirection. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct AudioInputHandle {
    enabled: Arc<AtomicBool>,
}

impl AudioInputHandle {
    /// Turns the microphone on or off; applies on the next channel tick.
    /// Off closes the capture device and sends no more audio; the channel
    /// and the server's recording session stay open.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Creates the `AUDIO_INPUT` channel handler and its UI switch. The
/// microphone starts off.
pub fn audin(backend: Box<dyn CaptureBackend>) -> (AudioInput, AudioInputHandle) {
    let enabled = Arc::new(AtomicBool::new(false));
    let handle = AudioInputHandle {
        enabled: enabled.clone(),
    };
    let channel = AudioInput {
        backend,
        enabled,
        formats: Vec::new(),
        current: None,
        frames_per_packet: 0,
        open: false,
        capturing: None,
        start_failed: false,
        pending: Vec::new(),
    };
    (channel, handle)
}

/// Version PDU (MS-RDPEAI 2.2.2.1).
pub fn version_pdu(version: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.put_u8(MSG_SNDIN_VERSION);
    v.put_u32(version);
    v
}

/// Sound Formats PDU (MS-RDPEAI 2.2.2.2) as the client sends it: no
/// ExtraData, so cbSizeFormatsPacket is the size of the whole PDU.
pub fn formats_pdu(formats: &[AudioFormat]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u8(MSG_SNDIN_FORMATS);
    v.put_u32(formats.len() as u32);
    v.put_u32(0);
    for f in formats {
        f.write(&mut v);
    }
    let size = v.len() as u32;
    v[5..9].copy_from_slice(&size.to_le_bytes());
    v
}

/// Open Reply PDU (MS-RDPEAI 2.2.2.4).
pub fn open_reply(result: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.put_u8(MSG_SNDIN_OPEN_REPLY);
    v.put_u32(result);
    v
}

/// Format Change PDU (MS-RDPEAI 2.2.4.1).
pub fn format_change(new_format: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.put_u8(MSG_SNDIN_FORMATCHANGE);
    v.put_u32(new_format);
    v
}

/// Incoming Data PDU (MS-RDPEAI 2.2.3.1).
pub fn incoming_data() -> Vec<u8> {
    vec![MSG_SNDIN_DATA_INCOMING]
}

/// Data PDU (MS-RDPEAI 2.2.3.2).
pub fn data_pdu(audio: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + audio.len());
    v.put_u8(MSG_SNDIN_DATA);
    v.put_bytes(audio);
    v
}

/// Parses the body (after the header) of a Sound Formats PDU (MS-RDPEAI
/// 2.2.2.2). cbSizeFormatsPacket and any ExtraData are ignored on receipt.
pub fn parse_formats(body: &[u8]) -> Result<Vec<AudioFormat>> {
    let mut r = Reader::new(body);
    let count = r.u32()?;
    let _cb_size_formats_packet = r.u32()?;
    // A count beyond the data fails in the loop; the preallocation is capped.
    let mut formats = Vec::with_capacity((count as usize).min(32));
    for _ in 0..count {
        formats.push(AudioFormat::parse(&mut r)?);
    }
    Ok(formats)
}

/// Fields of an Open PDU (MS-RDPEAI 2.2.2.3).
#[derive(Debug, PartialEq, Eq)]
pub struct Open {
    pub frames_per_packet: u32,
    pub initial_format: u32,
    /// The format the server suggests for the capture device (wFormatTag
    /// to ExtraFormatData). Data is always encoded in `initial_format`;
    /// this client captures in that format directly.
    pub capture: AudioFormat,
}

/// Parses the body (after the header) of an Open PDU (MS-RDPEAI 2.2.2.3).
/// The trailing fields form a WAVEFORMATEX, laid out like AUDIO_FORMAT.
pub fn parse_open(body: &[u8]) -> Result<Open> {
    let mut r = Reader::new(body);
    let frames_per_packet = r.u32()?;
    let initial_format = r.u32()?;
    let capture = AudioFormat::parse(&mut r)?;
    Ok(Open {
        frames_per_packet,
        initial_format,
        capture,
    })
}

/// Client side of the audio input dynamic channel.
pub struct AudioInput {
    backend: Box<dyn CaptureBackend>,
    enabled: Arc<AtomicBool>,
    /// The negotiated format list, as the client sent it; initialFormat and
    /// NewFormat index it (MS-RDPEAI 3.1.1).
    formats: Vec<PcmFormat>,
    /// Current audio format, an index into `formats`.
    current: Option<usize>,
    /// FramesPerPacket of the last Open PDU.
    frames_per_packet: u32,
    /// The server opened recording and the Open Reply was a success.
    open: bool,
    /// Format the backend is capturing in; None while stopped.
    capturing: Option<PcmFormat>,
    /// The last start failed; not retried until the switch, the format or
    /// the Open PDU changes.
    start_failed: bool,
    /// Captured audio not yet sent (less than one packet, or a backlog).
    pending: Vec<u8>,
}

impl AudioInput {
    fn sharing(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn stop_capture(&mut self) {
        if self.capturing.take().is_some() {
            self.backend.stop();
        }
        self.pending.clear();
    }

    /// Bytes of one Data PDU's audio: FramesPerPacket frames of the current
    /// format (MS-RDPEAI 2.2.2.3).
    fn packet_size(&self, format: &PcmFormat) -> usize {
        self.frames_per_packet as usize * usize::from(format.block_align())
    }

    fn current_format(&self) -> Option<PcmFormat> {
        self.current.and_then(|i| self.formats.get(i).copied())
    }

    /// Starts the backend in `format`; on failure the reason is traced.
    fn start_capture(&mut self, format: PcmFormat) -> bool {
        match self.backend.start(&format, self.frames_per_packet) {
            Ok(()) => {
                trace!(
                    "audin: capture started, {} Hz, {} channels, {} frames per packet",
                    format.sample_rate, format.channels, self.frames_per_packet
                );
                self.capturing = Some(format);
                self.start_failed = false;
                true
            }
            Err(e) => {
                trace!("audin: capture device open failed: {e}");
                self.start_failed = true;
                false
            }
        }
    }

    /// Sound Formats PDU (MS-RDPEAI 3.2.5.1.3 to 3.2.5.1.5): an Incoming
    /// Data PDU, then the server's formats the backend captures, in the
    /// server's order. A repeated PDU restarts the negotiation.
    fn server_formats(&mut self, body: &[u8], out: &mut DvcOut) -> Result<()> {
        let server = parse_formats(body)?;
        self.stop_capture();
        self.open = false;
        self.current = None;
        let local = self.backend.formats();
        let mut offered = Vec::new();
        self.formats.clear();
        for f in &server {
            if let Some(pcm) = f.pcm_in(&local)
                && !self.formats.contains(&pcm)
            {
                offered.push(f.clone());
                self.formats.push(pcm);
            }
        }
        trace!(
            "audin: server offers {} formats, client takes {}",
            server.len(),
            offered.len()
        );
        out.send(incoming_data());
        out.send(formats_pdu(&offered));
        Ok(())
    }

    /// Open PDU (MS-RDPEAI 3.2.5.1.6 to 3.2.5.1.8): a Format Change PDU
    /// confirming initialFormat, then the Open Reply. While sharing is off
    /// the reply is a success and capture waits for the switch.
    fn open(&mut self, body: &[u8], out: &mut DvcOut) -> Result<()> {
        let open = parse_open(body)?;
        let index = open.initial_format as usize;
        let Some(&format) = self.formats.get(index) else {
            return proto(format!(
                "audin: Open initialFormat {index} of {} negotiated",
                self.formats.len()
            ));
        };
        if open.frames_per_packet == 0 || open.frames_per_packet > MAX_FRAMES_PER_PACKET {
            return proto(format!(
                "audin: Open FramesPerPacket {}",
                open.frames_per_packet
            ));
        }
        self.stop_capture();
        self.current = Some(index);
        self.frames_per_packet = open.frames_per_packet;
        self.start_failed = false;
        let ok = !self.sharing() || self.start_capture(format);
        self.open = ok;
        out.send(format_change(open.initial_format));
        out.send(open_reply(if ok { S_OK } else { E_FAIL }));
        Ok(())
    }

    /// Format Change PDU (MS-RDPEAI 3.2.5.3): confirm and switch; capture
    /// restarts in the new format on the next tick.
    fn format_change(&mut self, body: &[u8], out: &mut DvcOut) -> Result<()> {
        let new = Reader::new(body).u32()?;
        let index = new as usize;
        if index >= self.formats.len() {
            return proto(format!(
                "audin: Format Change to {index} of {} negotiated",
                self.formats.len()
            ));
        }
        trace!("audin: format change to {index}");
        self.stop_capture();
        self.current = Some(index);
        self.start_failed = false;
        out.send(format_change(new));
        Ok(())
    }

    /// Sends every complete packet in `pending` (MS-RDPEAI 3.2.5.2).
    fn send_packets(&mut self, size: usize, out: &mut DvcOut) {
        let mut sent = 0;
        while self.pending.len() - sent >= size {
            out.send(incoming_data());
            out.send(data_pdu(&self.pending[sent..sent + size]));
            sent += size;
        }
        self.pending.drain(..sent);
    }
}

impl DynamicChannel for AudioInput {
    fn name(&self) -> &str {
        AUDIO_INPUT
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let Some((&id, body)) = msg.split_first() else {
            trace!("audin: empty PDU ignored");
            return Ok(());
        };
        let res = match id {
            MSG_SNDIN_VERSION => Reader::new(body).u32().map(|v| {
                // MS-RDPEAI 3.2.5.1.1, 3.2.5.1.2.
                trace!("audin: server version {v}");
                out.send(version_pdu(CLIENT_VERSION));
            }),
            MSG_SNDIN_FORMATS => self.server_formats(body, out),
            MSG_SNDIN_OPEN => self.open(body, out),
            MSG_SNDIN_FORMATCHANGE => self.format_change(body, out),
            _ => {
                trace!("audin: MessageId {id:#x} ({} bytes) ignored", body.len());
                Ok(())
            }
        };
        // MS-RDPEAI 3.1.5: malformed and out-of-sequence PDUs are ignored.
        if let Err(e) = res {
            trace!("audin: {e}; PDU ignored");
        }
        Ok(())
    }

    /// Follows the switch and sends what the device captured.
    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        if !self.sharing() {
            if self.capturing.is_some() {
                trace!("audin: microphone off, capture stopped");
                self.stop_capture();
            }
            self.start_failed = false;
            return Ok(());
        }
        if !self.open {
            return Ok(());
        }
        let Some(format) = self.current_format() else {
            return Ok(());
        };
        if self.capturing != Some(format) {
            self.stop_capture();
            if self.start_failed || !self.start_capture(format) {
                return Ok(());
            }
        }
        let size = self.packet_size(&format);
        while let Some(block) = self.backend.read() {
            self.pending.extend_from_slice(&block);
        }
        // A session that ticks too rarely drops the oldest whole packets
        // rather than buffering without limit.
        let limit = size * MAX_BACKLOG_PACKETS;
        if self.pending.len() > limit {
            let excess = (self.pending.len() - limit).div_ceil(size) * size;
            trace!("audin: {excess} bytes of backlog dropped");
            self.pending.drain(..excess.min(self.pending.len()));
        }
        self.send_packets(size, out);
        Ok(())
    }

    /// The channel closed (MS-RDPEAI 3.1.5.2): stop capturing and forget
    /// the negotiation; a new channel starts over with a Version PDU.
    fn closed(&mut self) {
        self.stop_capture();
        self.open = false;
        self.current = None;
        self.formats.clear();
        self.frames_per_packet = 0;
        self.start_failed = false;
    }
}

#[cfg(test)]
#[path = "audin_tests.rs"]
mod tests;
