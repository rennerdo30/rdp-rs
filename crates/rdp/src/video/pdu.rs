//! Video Optimized Remoting messages (MS-RDPEVOR 2.2.1).
//!
//! Every message starts with a TSMM_VIDEO_PACKET_HEADER (2.2.1.1) whose
//! `cbSize` counts the whole message. Windows appends one reserved byte
//! after `cbSize` (the examples in 4.1, 4.3 and 4.4 carry it), so bytes
//! after `cbSize` are ignored rather than refused.

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};

/// Size of TSMM_VIDEO_PACKET_HEADER (2.2.1.1).
pub const HEADER_SIZE: usize = 8;

/// TSMM_PACKET_TYPE_PRESENTATION_REQUEST (2.2.1.1).
pub const PACKET_TYPE_PRESENTATION_REQUEST: u32 = 1;
/// TSMM_PACKET_TYPE_PRESENTATION_RESPONSE (2.2.1.1).
pub const PACKET_TYPE_PRESENTATION_RESPONSE: u32 = 2;
/// TSMM_PACKET_TYPE_CLIENT_NOTIFICATION (2.2.1.1).
pub const PACKET_TYPE_CLIENT_NOTIFICATION: u32 = 3;
/// TSMM_PACKET_TYPE_VIDEO_DATA (2.2.1.1).
pub const PACKET_TYPE_VIDEO_DATA: u32 = 4;

/// TSMM_PRESENTATION_REQUEST Command: Start Presentation (2.2.1.2).
pub const COMMAND_START: u8 = 0x01;
/// TSMM_PRESENTATION_REQUEST Command: Stop Presentation (2.2.1.2).
pub const COMMAND_STOP: u8 = 0x02;

/// TSMM_CLIENT_NOTIFICATION NotificationType: Network Error (2.2.1.4).
pub const NOTIFICATION_NETWORK_ERROR: u8 = 0x01;
/// TSMM_CLIENT_NOTIFICATION NotificationType: Frame Rate Override (2.2.1.4).
pub const NOTIFICATION_FRAMERATE_OVERRIDE: u8 = 0x02;

/// TSMM_CLIENT_NOTIFICATION_FRAMERATE_OVERRIDE Flags: unrestricted (2.2.1.5).
pub const FRAMERATE_UNRESTRICTED: u32 = 0x1;
/// TSMM_CLIENT_NOTIFICATION_FRAMERATE_OVERRIDE Flags: override (2.2.1.5).
pub const FRAMERATE_OVERRIDE: u32 = 0x2;
/// DesiredFrameRate range (2.2.1.5).
pub const MIN_FRAMERATE: u32 = 1;
pub const MAX_FRAMERATE: u32 = 30;

/// TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS (2.2.1.6).
pub const DATA_FLAG_HAS_TIMESTAMPS: u8 = 0x01;
/// TSMM_VIDEO_DATA_FLAG_KEYFRAME (2.2.1.6).
pub const DATA_FLAG_KEYFRAME: u8 = 0x02;
/// TSMM_VIDEO_DATA_FLAG_NEW_FRAMERATE (2.2.1.6).
pub const DATA_FLAG_NEW_FRAMERATE: u8 = 0x04;

/// MFVideoFormat_H264, {34363248-0000-0010-8000-00AA00389B71}, as the GUID
/// is laid out on the wire (2.2.1.2 VideoSubtypeId).
pub const MFVIDEOFORMAT_H264: [u8; 16] = [
    0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// Largest ScaledWidth and ScaledHeight the spec allows (2.2.1.2).
pub const MAX_SCALED_WIDTH: u32 = 1920;
pub const MAX_SCALED_HEIGHT: u32 = 1080;

fn u64le(r: &mut Reader) -> Result<u64> {
    Ok(u64::from_le_bytes(r.array()?))
}

fn header(out: &mut Vec<u8>, packet_type: u32) {
    out.put_u32(0); // cbSize, set by `finish`
    out.put_u32(packet_type);
}

fn finish(mut out: Vec<u8>) -> Vec<u8> {
    let n = out.len() as u32;
    out[..4].copy_from_slice(&n.to_le_bytes());
    out
}

/// TSMM_VIDEO_PACKET_HEADER (2.2.1.1): the packet type and the message
/// after the header, `cbSize` bytes in all. A `cbSize` shorter than the
/// header or longer than the message is malformed (3.1.5.1).
pub fn split_header(msg: &[u8]) -> Result<(u32, &[u8])> {
    let mut r = Reader::new(msg);
    let size = r.u32()? as usize;
    let packet_type = r.u32()?;
    if size < HEADER_SIZE || size > msg.len() {
        return proto(format!(
            "video: cbSize {size} for a message of {} bytes",
            msg.len()
        ));
    }
    Ok((packet_type, &msg[HEADER_SIZE..size]))
}

/// TSMM_PRESENTATION_REQUEST with Command Start Presentation (2.2.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartPresentation {
    pub presentation_id: u8,
    pub version: u8,
    /// Width and height after scaling back to the original resolution.
    pub source_width: u32,
    pub source_height: u32,
    /// Width and height of the encoded stream.
    pub scaled_width: u32,
    pub scaled_height: u32,
    /// Server time (100 ns since boot) when the presentation started.
    pub timestamp_offset: u64,
    /// The MS-RDPEGT mapping that places this video.
    pub geometry_mapping_id: u64,
    pub video_subtype: [u8; 16],
    /// For H.264, the sequence header: SPS and PPS.
    pub extra: Vec<u8>,
}

impl StartPresentation {
    /// The whole TSMM_PRESENTATION_REQUEST, header included.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68 + self.extra.len());
        header(&mut out, PACKET_TYPE_PRESENTATION_REQUEST);
        out.put_u8(self.presentation_id);
        out.put_u8(self.version);
        out.put_u8(COMMAND_START);
        out.put_u8(0); // FrameRate, reserved
        out.put_u16(0); // AverageBitrateKbps, reserved
        out.put_u16(0); // Reserved
        out.put_u32(self.source_width);
        out.put_u32(self.source_height);
        out.put_u32(self.scaled_width);
        out.put_u32(self.scaled_height);
        out.put_bytes(&self.timestamp_offset.to_le_bytes());
        out.put_bytes(&self.geometry_mapping_id.to_le_bytes());
        out.put_bytes(&self.video_subtype);
        out.put_u32(self.extra.len() as u32);
        out.put_bytes(&self.extra);
        finish(out)
    }
}

/// A TSMM_PRESENTATION_REQUEST (2.2.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentationRequest {
    Start(StartPresentation),
    /// Stop Presentation: only the id, version and command are valid.
    Stop {
        presentation_id: u8,
    },
    /// A command this client does not know; ignored (3.1.5.1).
    Other {
        presentation_id: u8,
        command: u8,
    },
}

/// Encodes a Stop Presentation request (header and the three valid fields).
pub fn stop_presentation(presentation_id: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    header(&mut out, PACKET_TYPE_PRESENTATION_REQUEST);
    out.put_u8(presentation_id);
    out.put_u8(1);
    out.put_u8(COMMAND_STOP);
    out.put_u8(0);
    finish(out)
}

/// Parses a TSMM_PRESENTATION_REQUEST body (after the header).
pub fn parse_presentation_request(body: &[u8]) -> Result<PresentationRequest> {
    let mut r = Reader::new(body);
    let presentation_id = r.u8()?;
    let version = r.u8()?;
    let command = r.u8()?;
    match command {
        COMMAND_START => {}
        COMMAND_STOP => return Ok(PresentationRequest::Stop { presentation_id }),
        _ => {
            return Ok(PresentationRequest::Other {
                presentation_id,
                command,
            });
        }
    }
    r.skip(1 + 2 + 2)?; // FrameRate, AverageBitrateKbps, Reserved
    let source_width = r.u32()?;
    let source_height = r.u32()?;
    let scaled_width = r.u32()?;
    let scaled_height = r.u32()?;
    let timestamp_offset = u64le(&mut r)?;
    let geometry_mapping_id = u64le(&mut r)?;
    let video_subtype = r.array::<16>()?;
    let cb_extra = r.u32()? as usize;
    let extra = r.bytes(cb_extra)?.to_vec();
    Ok(PresentationRequest::Start(StartPresentation {
        presentation_id,
        version,
        source_width,
        source_height,
        scaled_width,
        scaled_height,
        timestamp_offset,
        geometry_mapping_id,
        video_subtype,
        extra,
    }))
}

/// TSMM_PRESENTATION_RESPONSE (2.2.1.3): the client is ready to render.
/// ResponseFlags and ResultFlags are reserved and zero.
pub fn presentation_response(presentation_id: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    header(&mut out, PACKET_TYPE_PRESENTATION_RESPONSE);
    out.put_u8(presentation_id);
    out.put_u8(0);
    out.put_u16(0);
    finish(out)
}

/// The notification a TSMM_CLIENT_NOTIFICATION carries (2.2.1.4, 2.2.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    /// Missing or out-of-order packets; the server answers with a keyframe.
    NetworkError,
    /// The client decodes all frames and has room for more.
    Unrestricted,
    /// The client decodes at most this many frames per second (1 - 30).
    FrameRate(u32),
}

/// TSMM_CLIENT_NOTIFICATION (2.2.1.4), with a
/// TSMM_CLIENT_NOTIFICATION_FRAMERATE_OVERRIDE (2.2.1.5) for a frame rate.
pub fn client_notification(presentation_id: u8, n: Notification) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    header(&mut out, PACKET_TYPE_CLIENT_NOTIFICATION);
    out.put_u8(presentation_id);
    let (kind, data) = match n {
        Notification::NetworkError => (NOTIFICATION_NETWORK_ERROR, None),
        Notification::Unrestricted => (
            NOTIFICATION_FRAMERATE_OVERRIDE,
            Some((FRAMERATE_UNRESTRICTED, 0)),
        ),
        Notification::FrameRate(fps) => (
            NOTIFICATION_FRAMERATE_OVERRIDE,
            Some((FRAMERATE_OVERRIDE, fps.clamp(MIN_FRAMERATE, MAX_FRAMERATE))),
        ),
    };
    out.put_u8(kind);
    out.put_u16(0); // Reserved
    match data {
        None => out.put_u32(0),
        Some((flags, fps)) => {
            out.put_u32(16);
            out.put_u32(flags);
            out.put_u32(fps);
            out.put_u32(0); // Reserved1
            out.put_u32(0); // Reserved2
        }
    }
    finish(out)
}

/// Parses a TSMM_CLIENT_NOTIFICATION body (after the header): the
/// presentation id and the notification.
pub fn parse_client_notification(body: &[u8]) -> Result<(u8, Notification)> {
    let mut r = Reader::new(body);
    let id = r.u8()?;
    let kind = r.u8()?;
    r.skip(2)?;
    let cb = r.u32()? as usize;
    let mut d = Reader::new(r.bytes(cb)?);
    let n = match kind {
        NOTIFICATION_NETWORK_ERROR => Notification::NetworkError,
        NOTIFICATION_FRAMERATE_OVERRIDE => {
            let flags = d.u32()?;
            let fps = d.u32()?;
            if flags & FRAMERATE_UNRESTRICTED != 0 {
                Notification::Unrestricted
            } else {
                Notification::FrameRate(fps)
            }
        }
        _ => return proto(format!("video: notification type {kind}")),
    };
    Ok((id, n))
}

/// TSMM_VIDEO_DATA (2.2.1.6): one packet of a video sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoData<'a> {
    pub presentation_id: u8,
    pub version: u8,
    pub flags: u8,
    /// 100 ns since the presentation started; valid with
    /// [`DATA_FLAG_HAS_TIMESTAMPS`].
    pub timestamp: u64,
    /// 100 ns between the last sample and this one.
    pub duration: u64,
    /// One-based index of this packet within the sample.
    pub packet_index: u16,
    pub packets_in_sample: u16,
    /// One-based sample number.
    pub sample_number: u32,
    pub sample: &'a [u8],
}

impl VideoData<'_> {
    /// Parses a TSMM_VIDEO_DATA body (after the header). A packet index
    /// outside 1..=PacketsInSample is malformed.
    pub fn parse(body: &[u8]) -> Result<VideoData<'_>> {
        let mut r = Reader::new(body);
        let presentation_id = r.u8()?;
        let version = r.u8()?;
        let flags = r.u8()?;
        r.skip(1)?;
        let timestamp = u64le(&mut r)?;
        let duration = u64le(&mut r)?;
        let packet_index = r.u16()?;
        let packets_in_sample = r.u16()?;
        let sample_number = r.u32()?;
        let cb = r.u32()? as usize;
        let sample = r.bytes(cb)?;
        if packet_index == 0 || packet_index > packets_in_sample {
            return proto(format!(
                "video: packet {packet_index} of {packets_in_sample}"
            ));
        }
        Ok(VideoData {
            presentation_id,
            version,
            flags,
            timestamp,
            duration,
            packet_index,
            packets_in_sample,
            sample_number,
            sample,
        })
    }

    /// The whole TSMM_VIDEO_DATA message, header included.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.sample.len());
        header(&mut out, PACKET_TYPE_VIDEO_DATA);
        out.put_u8(self.presentation_id);
        out.put_u8(self.version);
        out.put_u8(self.flags);
        out.put_u8(0);
        out.put_bytes(&self.timestamp.to_le_bytes());
        out.put_bytes(&self.duration.to_le_bytes());
        out.put_u16(self.packet_index);
        out.put_u16(self.packets_in_sample);
        out.put_u32(self.sample_number);
        out.put_u32(self.sample.len() as u32);
        out.put_bytes(self.sample);
        finish(out)
    }

    pub fn keyframe(&self) -> bool {
        self.flags & DATA_FLAG_KEYFRAME != 0
    }

    pub fn has_timestamp(&self) -> bool {
        self.flags & DATA_FLAG_HAS_TIMESTAMPS != 0
    }
}
