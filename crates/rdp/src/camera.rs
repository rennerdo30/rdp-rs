//! Camera redirection, client side (MS-RDPECAM): this PC's video capture
//! devices in the session, over dynamic virtual channels (MS-RDPECAM 2.1).
//!
//! Channels:
//! - the device enumeration channel [`ENUMERATOR`] negotiates the protocol
//!   version and announces cameras with Device Added and Device Removed
//!   notifications (MS-RDPECAM 1.3.1 to 1.3.3);
//! - one device channel per camera, named by the client in its Device
//!   Added notification ([`device_channel_name`]), carries activation, the
//!   stream and media type lists, Start and Stop Streams and the samples
//!   (MS-RDPECAM 1.3.4 to 1.3.7).
//!
//! Every camera has its own [`CameraBackend`]; the protocol state machine
//! here never touches a device directly. Sharing starts off: a camera is
//! announced only after [`CameraHandle::set_enabled`] switches it on, and
//! switching it off announces its removal, stops any capture at once and
//! fails every later request on its channel. The backend is asked to
//! capture only between a successful Start Streams Request and the Stop
//! Streams or Deactivate Device Request (or the channel closing).
//!
//! Scope: one stream per camera (Color, Capture category). Samples are
//! answered one per Sample Request, as MS-RDPECAM 2.2.3.13 requires: a
//! request waits until the backend has a new sample. Version 2 device
//! properties (MS-RDPECAM 2.2.3.16 to 2.2.3.20) are passed to the backend,
//! whose default reports none.
//!
//! Malformed and out-of-sequence requests are answered with an Error
//! Response (or a Sample Error Response for a Sample Request), as
//! MS-RDPECAM 3.2.5 requires; they never close the channel. Sample data is
//! never traced.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::cursor::{Put, Reader};
use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::{Result, proto};
use crate::trace;

/// Name of the device enumeration channel (MS-RDPECAM 2.1).
pub const ENUMERATOR: &str = "RDCamera_Device_Enumerator";

/// Highest protocol version the client speaks (MS-RDPECAM 2.2.1; version 2
/// adds the device property messages).
pub const MAX_VERSION: u8 = 2;

/// Longest device channel name, without the terminator (MS-RDPECAM 2.1).
pub const MAX_CHANNEL_NAME: usize = 256;

// SHARED_MSG_HEADER MessageId values (MS-RDPECAM 2.2.1).
pub const MSG_SUCCESS_RESPONSE: u8 = 0x01;
pub const MSG_ERROR_RESPONSE: u8 = 0x02;
pub const MSG_SELECT_VERSION_REQUEST: u8 = 0x03;
pub const MSG_SELECT_VERSION_RESPONSE: u8 = 0x04;
pub const MSG_DEVICE_ADDED: u8 = 0x05;
pub const MSG_DEVICE_REMOVED: u8 = 0x06;
pub const MSG_ACTIVATE_DEVICE_REQUEST: u8 = 0x07;
pub const MSG_DEACTIVATE_DEVICE_REQUEST: u8 = 0x08;
pub const MSG_STREAM_LIST_REQUEST: u8 = 0x09;
pub const MSG_STREAM_LIST_RESPONSE: u8 = 0x0A;
pub const MSG_MEDIA_TYPE_LIST_REQUEST: u8 = 0x0B;
pub const MSG_MEDIA_TYPE_LIST_RESPONSE: u8 = 0x0C;
pub const MSG_CURRENT_MEDIA_TYPE_REQUEST: u8 = 0x0D;
pub const MSG_CURRENT_MEDIA_TYPE_RESPONSE: u8 = 0x0E;
pub const MSG_START_STREAMS_REQUEST: u8 = 0x0F;
pub const MSG_STOP_STREAMS_REQUEST: u8 = 0x10;
pub const MSG_SAMPLE_REQUEST: u8 = 0x11;
pub const MSG_SAMPLE_RESPONSE: u8 = 0x12;
pub const MSG_SAMPLE_ERROR_RESPONSE: u8 = 0x13;
pub const MSG_PROPERTY_LIST_REQUEST: u8 = 0x14;
pub const MSG_PROPERTY_LIST_RESPONSE: u8 = 0x15;
pub const MSG_PROPERTY_VALUE_REQUEST: u8 = 0x16;
pub const MSG_PROPERTY_VALUE_RESPONSE: u8 = 0x17;
pub const MSG_SET_PROPERTY_VALUE_REQUEST: u8 = 0x18;

// Error Response ErrorCode values (MS-RDPECAM 2.2.3.2). The last three are
// generated only by version 2 of the protocol.
pub const ERR_UNEXPECTED_ERROR: u32 = 0x01;
pub const ERR_INVALID_MESSAGE: u32 = 0x02;
pub const ERR_NOT_INITIALIZED: u32 = 0x03;
pub const ERR_INVALID_REQUEST: u32 = 0x04;
pub const ERR_INVALID_STREAM_NUMBER: u32 = 0x05;
pub const ERR_INVALID_MEDIA_TYPE: u32 = 0x06;
pub const ERR_OUT_OF_MEMORY: u32 = 0x07;
pub const ERR_ITEM_NOT_FOUND: u32 = 0x08;
pub const ERR_SET_NOT_FOUND: u32 = 0x09;
pub const ERR_OPERATION_NOT_SUPPORTED: u32 = 0x0A;

// STREAM_DESCRIPTION fields (MS-RDPECAM 2.2.3.6.1).
pub const FRAME_SOURCE_COLOR: u16 = 0x0001;
pub const FRAME_SOURCE_INFRARED: u16 = 0x0002;
pub const FRAME_SOURCE_CUSTOM: u16 = 0x0008;
pub const STREAM_CATEGORY_CAPTURE: u8 = 0x01;

// MEDIA_TYPE_DESCRIPTION Flags (MS-RDPECAM 2.2.3.8.1).
pub const MEDIA_FLAG_DECODING_REQUIRED: u8 = 0x01;
pub const MEDIA_FLAG_BOTTOM_UP_IMAGE: u8 = 0x02;

// PROPERTY_DESCRIPTION PropertySet values (MS-RDPECAM 2.2.3.17.1).
pub const PROPERTY_SET_CAMERA_CONTROL: u8 = 0x01;
pub const PROPERTY_SET_VIDEO_PROC_AMP: u8 = 0x02;

// Capabilities flags and PROPERTY_VALUE Mode (MS-RDPECAM 2.2.3.17.1,
// 2.2.3.19.1).
pub const PROPERTY_MANUAL: u8 = 0x01;
pub const PROPERTY_AUTO: u8 = 0x02;

/// Size of a MEDIA_TYPE_DESCRIPTION (MS-RDPECAM 2.2.3.8.1).
pub const MEDIA_TYPE_SIZE: usize = 26;
/// Size of a STREAM_DESCRIPTION (MS-RDPECAM 2.2.3.6.1).
pub const STREAM_DESCRIPTION_SIZE: usize = 5;
/// Size of a START_STREAM_INFO (MS-RDPECAM 2.2.3.11.1).
pub const START_STREAM_INFO_SIZE: usize = 1 + MEDIA_TYPE_SIZE;
/// Size of a PROPERTY_DESCRIPTION (MS-RDPECAM 2.2.3.17.1).
pub const PROPERTY_DESCRIPTION_SIZE: usize = 19;

/// Sample Requests the client holds for one stream before answering more
/// with a Sample Error Response. The server sends one at a time (each
/// waits for its sample), so this only bounds a misbehaving server.
pub const MAX_PENDING_SAMPLES: u32 = 8;

/// The device channel name the client gives camera `index` (MS-RDPECAM 2.1,
/// 4.2.1: the spec's example uses "RDCamera_Device_0").
pub fn device_channel_name(index: usize) -> String {
    format!("RDCamera_Device_{index}")
}

/// MEDIA_TYPE_DESCRIPTION Format (MS-RDPECAM 2.2.3.8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VideoFormat {
    /// H.264 with start codes and in-band SPS/PPS; one picture per sample.
    H264 = 0x01,
    /// Motion JPEG: each sample is one JPEG image.
    Mjpg = 0x02,
    Yuy2 = 0x03,
    Nv12 = 0x04,
    /// Planar Y, U, V (YV12 with the chroma planes swapped).
    I420 = 0x05,
    Rgb24 = 0x06,
    Rgb32 = 0x07,
}

impl VideoFormat {
    pub fn from_u8(v: u8) -> Option<VideoFormat> {
        Some(match v {
            0x01 => VideoFormat::H264,
            0x02 => VideoFormat::Mjpg,
            0x03 => VideoFormat::Yuy2,
            0x04 => VideoFormat::Nv12,
            0x05 => VideoFormat::I420,
            0x06 => VideoFormat::Rgb24,
            0x07 => VideoFormat::Rgb32,
            _ => return None,
        })
    }

    /// Compressed formats the server decodes (DecodingRequired).
    pub fn compressed(self) -> bool {
        matches!(self, VideoFormat::H264 | VideoFormat::Mjpg)
    }

    /// Short name for logs and the UI.
    pub fn name(self) -> &'static str {
        match self {
            VideoFormat::H264 => "H.264",
            VideoFormat::Mjpg => "MJPG",
            VideoFormat::Yuy2 => "YUY2",
            VideoFormat::Nv12 => "NV12",
            VideoFormat::I420 => "I420",
            VideoFormat::Rgb24 => "RGB24",
            VideoFormat::Rgb32 => "RGB32",
        }
    }
}

/// MEDIA_TYPE_DESCRIPTION (MS-RDPECAM 2.2.3.8.1): one stream format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MediaType {
    pub format: VideoFormat,
    pub width: u32,
    pub height: u32,
    pub frame_rate_numerator: u32,
    pub frame_rate_denominator: u32,
    pub pixel_aspect_ratio_numerator: u32,
    pub pixel_aspect_ratio_denominator: u32,
    /// [`MEDIA_FLAG_DECODING_REQUIRED`], [`MEDIA_FLAG_BOTTOM_UP_IMAGE`].
    pub flags: u8,
}

impl MediaType {
    /// A format with square pixels; DecodingRequired is set for H.264 and
    /// MJPG.
    pub fn new(format: VideoFormat, width: u32, height: u32, fps_num: u32, fps_den: u32) -> Self {
        MediaType {
            format,
            width,
            height,
            frame_rate_numerator: fps_num,
            frame_rate_denominator: fps_den,
            pixel_aspect_ratio_numerator: 1,
            pixel_aspect_ratio_denominator: 1,
            flags: if format.compressed() {
                MEDIA_FLAG_DECODING_REQUIRED
            } else {
                0
            },
        }
    }

    pub fn write(&self, v: &mut Vec<u8>) {
        v.put_u8(self.format as u8);
        v.put_u32(self.width);
        v.put_u32(self.height);
        v.put_u32(self.frame_rate_numerator);
        v.put_u32(self.frame_rate_denominator);
        v.put_u32(self.pixel_aspect_ratio_numerator);
        v.put_u32(self.pixel_aspect_ratio_denominator);
        v.put_u8(self.flags);
    }

    pub fn parse(r: &mut Reader) -> Result<MediaType> {
        let raw = r.u8()?;
        let Some(format) = VideoFormat::from_u8(raw) else {
            return proto(format!("camera: media type format {raw:#x}"));
        };
        Ok(MediaType {
            format,
            width: r.u32()?,
            height: r.u32()?,
            frame_rate_numerator: r.u32()?,
            frame_rate_denominator: r.u32()?,
            pixel_aspect_ratio_numerator: r.u32()?,
            pixel_aspect_ratio_denominator: r.u32()?,
            flags: r.u8()?,
        })
    }

    /// The same stream format: everything but the flags, which only
    /// describe how the samples look and some servers echo differently.
    pub fn same_format(&self, other: &MediaType) -> bool {
        MediaType { flags: 0, ..*self } == MediaType { flags: 0, ..*other }
    }
}

/// STREAM_DESCRIPTION (MS-RDPECAM 2.2.3.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamDescription {
    pub frame_source_types: u16,
    pub category: u8,
    pub selected: bool,
    pub can_be_shared: bool,
}

impl StreamDescription {
    /// The one stream this client offers per camera: colour video,
    /// selected, not shared between server applications (it runs in one
    /// format at a time).
    pub const COLOR: StreamDescription = StreamDescription {
        frame_source_types: FRAME_SOURCE_COLOR,
        category: STREAM_CATEGORY_CAPTURE,
        selected: true,
        can_be_shared: false,
    };

    pub fn write(&self, v: &mut Vec<u8>) {
        v.put_u16(self.frame_source_types);
        v.put_u8(self.category);
        v.put_u8(u8::from(self.selected));
        v.put_u8(u8::from(self.can_be_shared));
    }

    pub fn parse(r: &mut Reader) -> Result<StreamDescription> {
        Ok(StreamDescription {
            frame_source_types: r.u16()?,
            category: r.u8()?,
            selected: r.u8()? != 0,
            can_be_shared: r.u8()? != 0,
        })
    }
}

/// PROPERTY_DESCRIPTION (MS-RDPECAM 2.2.3.17.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyDescription {
    pub set: u8,
    pub id: u8,
    /// [`PROPERTY_MANUAL`], [`PROPERTY_AUTO`].
    pub capabilities: u8,
    pub min: i32,
    pub max: i32,
    pub step: i32,
    pub default: i32,
}

impl PropertyDescription {
    pub fn write(&self, v: &mut Vec<u8>) {
        v.put_u8(self.set);
        v.put_u8(self.id);
        v.put_u8(self.capabilities);
        v.put_u32(self.min as u32);
        v.put_u32(self.max as u32);
        v.put_u32(self.step as u32);
        v.put_u32(self.default as u32);
    }

    pub fn parse(r: &mut Reader) -> Result<PropertyDescription> {
        Ok(PropertyDescription {
            set: r.u8()?,
            id: r.u8()?,
            capabilities: r.u8()?,
            min: r.u32()? as i32,
            max: r.u32()? as i32,
            step: r.u32()? as i32,
            default: r.u32()? as i32,
        })
    }
}

/// PROPERTY_VALUE (MS-RDPECAM 2.2.3.19.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyValue {
    /// [`PROPERTY_MANUAL`] or [`PROPERTY_AUTO`].
    pub mode: u8,
    pub value: i32,
}

impl PropertyValue {
    pub fn write(&self, v: &mut Vec<u8>) {
        v.put_u8(self.mode);
        v.put_u32(self.value as u32);
    }

    pub fn parse(r: &mut Reader) -> Result<PropertyValue> {
        Ok(PropertyValue {
            mode: r.u8()?,
            value: r.u32()? as i32,
        })
    }
}

/// SHARED_MSG_HEADER (MS-RDPECAM 2.2.1).
fn header(version: u8, id: u8) -> Vec<u8> {
    vec![version, id]
}

/// Select Version Request (MS-RDPECAM 2.2.2.1): the client's highest
/// version in the header.
pub fn select_version_request(version: u8) -> Vec<u8> {
    header(version, MSG_SELECT_VERSION_REQUEST)
}

/// Device Added Notification (MS-RDPECAM 2.2.2.3): the display name as
/// null-terminated UTF-16, the channel name as null-terminated ANSI.
/// Characters a channel name cannot carry become `_`; it is cut to
/// [`MAX_CHANNEL_NAME`].
pub fn device_added(version: u8, device_name: &str, channel: &str) -> Vec<u8> {
    let mut v = header(version, MSG_DEVICE_ADDED);
    for c in device_name.encode_utf16().filter(|&c| c != 0) {
        v.put_u16(c);
    }
    v.put_u16(0);
    put_ansi_z(&mut v, channel);
    v
}

/// Device Removed Notification (MS-RDPECAM 2.2.2.4).
pub fn device_removed(version: u8, channel: &str) -> Vec<u8> {
    let mut v = header(version, MSG_DEVICE_REMOVED);
    put_ansi_z(&mut v, channel);
    v
}

fn put_ansi_z(v: &mut Vec<u8>, s: &str) {
    for b in s
        .bytes()
        .take(MAX_CHANNEL_NAME)
        .map(|b| if b.is_ascii_graphic() { b } else { b'_' })
    {
        v.put_u8(b);
    }
    v.put_u8(0);
}

/// Success Response (MS-RDPECAM 2.2.3.1).
pub fn success_response(version: u8) -> Vec<u8> {
    header(version, MSG_SUCCESS_RESPONSE)
}

/// Error Response (MS-RDPECAM 2.2.3.2).
pub fn error_response(version: u8, code: u32) -> Vec<u8> {
    let mut v = header(version, MSG_ERROR_RESPONSE);
    v.put_u32(code);
    v
}

/// Stream List Response (MS-RDPECAM 2.2.3.6).
pub fn stream_list_response(version: u8, streams: &[StreamDescription]) -> Vec<u8> {
    let mut v = header(version, MSG_STREAM_LIST_RESPONSE);
    for s in streams {
        s.write(&mut v);
    }
    v
}

/// Media Type List Response (MS-RDPECAM 2.2.3.8).
pub fn media_type_list_response(version: u8, types: &[MediaType]) -> Vec<u8> {
    let mut v = header(version, MSG_MEDIA_TYPE_LIST_RESPONSE);
    for t in types {
        t.write(&mut v);
    }
    v
}

/// Current Media Type Response (MS-RDPECAM 2.2.3.10).
pub fn current_media_type_response(version: u8, media_type: &MediaType) -> Vec<u8> {
    let mut v = header(version, MSG_CURRENT_MEDIA_TYPE_RESPONSE);
    media_type.write(&mut v);
    v
}

/// Sample Response (MS-RDPECAM 2.2.3.14).
pub fn sample_response(version: u8, stream: u8, sample: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + sample.len());
    v.put_u8(version);
    v.put_u8(MSG_SAMPLE_RESPONSE);
    v.put_u8(stream);
    v.put_bytes(sample);
    v
}

/// Sample Error Response (MS-RDPECAM 2.2.3.15).
pub fn sample_error_response(version: u8, stream: u8, code: u32) -> Vec<u8> {
    let mut v = header(version, MSG_SAMPLE_ERROR_RESPONSE);
    v.put_u8(stream);
    v.put_u32(code);
    v
}

/// Property List Response (MS-RDPECAM 2.2.3.17).
pub fn property_list_response(version: u8, properties: &[PropertyDescription]) -> Vec<u8> {
    let mut v = header(version, MSG_PROPERTY_LIST_RESPONSE);
    for p in properties {
        p.write(&mut v);
    }
    v
}

/// Property Value Response (MS-RDPECAM 2.2.3.19).
pub fn property_value_response(version: u8, value: &PropertyValue) -> Vec<u8> {
    let mut v = header(version, MSG_PROPERTY_VALUE_RESPONSE);
    value.write(&mut v);
    v
}

/// A request the server sends on a device channel (MS-RDPECAM 2.2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceRequest {
    /// Activate Device Request (2.2.3.3).
    Activate,
    /// Deactivate Device Request (2.2.3.4).
    Deactivate,
    /// Stream List Request (2.2.3.5).
    StreamList,
    /// Media Type List Request (2.2.3.7): StreamIndex.
    MediaTypeList(u8),
    /// Current Media Type Request (2.2.3.9): StreamIndex.
    CurrentMediaType(u8),
    /// Start Streams Request (2.2.3.11): 1 to 255 START_STREAM_INFO.
    StartStreams(Vec<(u8, MediaType)>),
    /// Stop Streams Request (2.2.3.12).
    StopStreams,
    /// Sample Request (2.2.3.13): StreamIndex.
    Sample(u8),
    /// Property List Request (2.2.3.16), version 2.
    PropertyList,
    /// Property Value Request (2.2.3.18), version 2: PropertySet, PropertyId.
    PropertyValue(u8, u8),
    /// Set Property Value Request (2.2.3.20), version 2.
    SetPropertyValue(u8, u8, PropertyValue),
}

impl DeviceRequest {
    /// Requests that exist only in version 2 of the protocol.
    pub fn version2_only(&self) -> bool {
        matches!(
            self,
            DeviceRequest::PropertyList
                | DeviceRequest::PropertyValue(..)
                | DeviceRequest::SetPropertyValue(..)
        )
    }
}

/// Parses the body (after SHARED_MSG_HEADER) of request `id` on a device
/// channel. A request with trailing bytes is malformed, except the Start
/// Streams Request, whose length gives its count (MS-RDPECAM 3.2.5.12)
/// and must be a whole number of START_STREAM_INFO.
pub fn parse_device_request(id: u8, body: &[u8]) -> Result<DeviceRequest> {
    let mut r = Reader::new(body);
    let req = match id {
        MSG_ACTIVATE_DEVICE_REQUEST => DeviceRequest::Activate,
        MSG_DEACTIVATE_DEVICE_REQUEST => DeviceRequest::Deactivate,
        MSG_STREAM_LIST_REQUEST => DeviceRequest::StreamList,
        MSG_MEDIA_TYPE_LIST_REQUEST => DeviceRequest::MediaTypeList(r.u8()?),
        MSG_CURRENT_MEDIA_TYPE_REQUEST => DeviceRequest::CurrentMediaType(r.u8()?),
        MSG_START_STREAMS_REQUEST => {
            let n = body.len() / START_STREAM_INFO_SIZE;
            if n == 0 || n > 255 || !body.len().is_multiple_of(START_STREAM_INFO_SIZE) {
                return proto(format!(
                    "camera: Start Streams Request of {} bytes",
                    body.len()
                ));
            }
            let mut infos = Vec::with_capacity(n);
            for _ in 0..n {
                let stream = r.u8()?;
                infos.push((stream, MediaType::parse(&mut r)?));
            }
            DeviceRequest::StartStreams(infos)
        }
        MSG_STOP_STREAMS_REQUEST => DeviceRequest::StopStreams,
        MSG_SAMPLE_REQUEST => DeviceRequest::Sample(r.u8()?),
        MSG_PROPERTY_LIST_REQUEST => DeviceRequest::PropertyList,
        MSG_PROPERTY_VALUE_REQUEST => DeviceRequest::PropertyValue(r.u8()?, r.u8()?),
        MSG_SET_PROPERTY_VALUE_REQUEST => {
            let set = r.u8()?;
            let pid = r.u8()?;
            DeviceRequest::SetPropertyValue(set, pid, PropertyValue::parse(&mut r)?)
        }
        _ => return proto(format!("camera: MessageId {id:#x} is not a device request")),
    };
    if r.remaining() != 0 {
        return proto(format!(
            "camera: MessageId {id:#x} with {} trailing bytes",
            r.remaining()
        ));
    }
    Ok(req)
}

/// One local camera. Runs on the session worker thread, so every call
/// must return quickly: [`CameraBackend::sample`] returns what is already
/// captured and never waits for the next frame.
pub trait CameraBackend: Send {
    /// The stream formats the camera produces, restricted to the formats
    /// MS-RDPECAM carries, in the camera's order of preference. Called only
    /// while the server has the device activated; it may look at the
    /// device but must not start capturing.
    fn media_types(&mut self) -> std::result::Result<Vec<MediaType>, String>;

    /// Opens the camera and starts capturing in `media_type`, one of
    /// [`CameraBackend::media_types`].
    fn start(&mut self, media_type: &MediaType) -> std::result::Result<(), String>;

    /// The next captured sample, Ok(None) while none is ready, or an error
    /// when capture failed (the camera was unplugged, for example).
    /// Samples the session does not ask for may be dropped, except that
    /// an H.264 stream must stay decodable.
    fn sample(&mut self) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Stops capturing and releases the camera at once.
    fn stop(&mut self);

    /// Device properties (version 2): none unless the backend has some.
    fn properties(&mut self) -> Vec<PropertyDescription> {
        Vec::new()
    }

    /// The current value of a property, or an MS-RDPECAM ErrorCode.
    fn property(&mut self, _set: u8, _id: u8) -> std::result::Result<PropertyValue, u32> {
        Err(ERR_ITEM_NOT_FOUND)
    }

    /// Sets a property, or returns an MS-RDPECAM ErrorCode.
    fn set_property(
        &mut self,
        _set: u8,
        _id: u8,
        _value: PropertyValue,
    ) -> std::result::Result<(), u32> {
        Err(ERR_ITEM_NOT_FOUND)
    }
}

/// One camera as the session sees it.
struct Device {
    /// Display name for the Device Added notification.
    display: String,
    /// Device channel name.
    channel: String,
    /// The user shares this camera.
    enabled: AtomicBool,
    /// Capture failed for good (the camera is gone); not announced again.
    gone: AtomicBool,
}

impl Device {
    fn wanted(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) && !self.gone.load(Ordering::Relaxed)
    }
}

/// State shared by the enumeration channel, the device channels and the
/// UI handle.
struct Shared {
    devices: Vec<Device>,
    /// Negotiated version; 0 before the Select Version Response.
    version: AtomicU8,
    /// Bumped whenever a device's `wanted` may have changed.
    generation: AtomicU64,
}

impl Shared {
    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

/// UI-side switches for camera redirection. Cheap to clone; Send + Sync.
#[derive(Clone)]
pub struct CameraHandle {
    shared: Arc<Shared>,
}

impl CameraHandle {
    /// The cameras the session can share, by display name, in channel
    /// order.
    pub fn names(&self) -> Vec<String> {
        self.shared
            .devices
            .iter()
            .map(|d| d.display.clone())
            .collect()
    }

    /// Shares camera `index` or stops sharing it; applies on the next
    /// channel tick. Off announces the removal to the server and closes the
    /// camera if it was capturing. On also retries a camera whose capture
    /// failed (unplugged and plugged in again).
    pub fn set_enabled(&self, index: usize, on: bool) {
        if let Some(d) = self.shared.devices.get(index) {
            d.enabled.store(on, Ordering::Relaxed);
            if on {
                d.gone.store(false, Ordering::Relaxed);
            }
            self.shared.bump();
        }
    }

    pub fn enabled(&self, index: usize) -> bool {
        self.shared
            .devices
            .get(index)
            .is_some_and(|d| d.enabled.load(Ordering::Relaxed))
    }

    /// Negotiated protocol version, 0 until the server answered.
    pub fn version(&self) -> u8 {
        self.shared.version.load(Ordering::Relaxed)
    }
}

/// Creates the enumeration channel, one device channel per camera (in
/// order, named [`device_channel_name`]) and their UI handle. Every camera
/// starts off. The caller registers all channels with [`crate::Drdynvc`].
pub fn cameras(
    devices: Vec<(String, Box<dyn CameraBackend>)>,
) -> (Vec<Box<dyn DynamicChannel>>, CameraHandle) {
    let mut backends = Vec::with_capacity(devices.len());
    let mut list = Vec::with_capacity(devices.len());
    for (i, (name, backend)) in devices.into_iter().enumerate() {
        list.push(Device {
            display: name,
            channel: device_channel_name(i),
            enabled: AtomicBool::new(false),
            gone: AtomicBool::new(false),
        });
        backends.push(backend);
    }
    let shared = Arc::new(Shared {
        devices: list,
        version: AtomicU8::new(0),
        generation: AtomicU64::new(0),
    });
    let mut channels: Vec<Box<dyn DynamicChannel>> = vec![Box::new(Enumerator {
        shared: shared.clone(),
        announced: vec![false; backends.len()],
        seen: u64::MAX,
    })];
    for (index, backend) in backends.into_iter().enumerate() {
        channels.push(Box::new(DeviceChannel::new(shared.clone(), index, backend)));
    }
    (channels, CameraHandle { shared })
}

/// The device enumeration channel (MS-RDPECAM 1.3.1 to 1.3.3).
pub struct Enumerator {
    shared: Arc<Shared>,
    /// Which cameras the server was told about.
    announced: Vec<bool>,
    /// The `generation` the announcements match.
    seen: u64,
}

impl Enumerator {
    /// Sends Device Added or Device Removed for every camera whose sharing
    /// changed since the last announcement (MS-RDPECAM 3.2.5.3, 3.2.5.4).
    fn announce(&mut self, out: &mut DvcOut) {
        let version = self.shared.version.load(Ordering::Relaxed);
        if version == 0 {
            return;
        }
        let generation = self.shared.generation.load(Ordering::Relaxed);
        if generation == self.seen {
            return;
        }
        self.seen = generation;
        for (d, announced) in self.shared.devices.iter().zip(&mut self.announced) {
            let wanted = d.wanted();
            if wanted == *announced {
                continue;
            }
            *announced = wanted;
            if wanted {
                trace!("camera: device added: {} on {}", d.display, d.channel);
                out.send(device_added(version, &d.display, &d.channel));
            } else {
                trace!("camera: device removed: {}", d.channel);
                out.send(device_removed(version, &d.channel));
            }
        }
    }
}

impl DynamicChannel for Enumerator {
    fn name(&self) -> &str {
        ENUMERATOR
    }

    /// The client starts the Version Negotiation sequence (MS-RDPECAM
    /// 3.2.5.1).
    fn opened(&mut self, out: &mut DvcOut) -> Result<()> {
        self.shared.version.store(0, Ordering::Relaxed);
        self.announced.iter_mut().for_each(|a| *a = false);
        out.send(select_version_request(MAX_VERSION));
        Ok(())
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let [version, id, ..] = *msg else {
            trace!("camera: enumerator message of {} bytes ignored", msg.len());
            return Ok(());
        };
        // MS-RDPECAM 3.2.5.2: a version the client does not speak ends the
        // protocol; a repeated response is out of sequence. Both, and every
        // other message, are discarded (3.1.5).
        if id != MSG_SELECT_VERSION_RESPONSE || msg.len() != 2 {
            trace!("camera: enumerator MessageId {id:#x} ignored");
            return Ok(());
        }
        if self.shared.version.load(Ordering::Relaxed) != 0 {
            trace!("camera: repeated Select Version Response ignored");
            return Ok(());
        }
        if !(1..=MAX_VERSION).contains(&version) {
            trace!("camera: server selected version {version}; camera redirection off");
            return Ok(());
        }
        trace!("camera: protocol version {version}");
        self.shared.version.store(version, Ordering::Relaxed);
        self.seen = u64::MAX;
        self.announce(out);
        Ok(())
    }

    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        self.announce(out);
        Ok(())
    }

    fn closed(&mut self) {
        self.shared.version.store(0, Ordering::Relaxed);
        self.announced.iter_mut().for_each(|a| *a = false);
        // Device channels see the version gone and stop capturing.
        self.shared.bump();
    }

    fn max_message_size(&self) -> usize {
        4096
    }

    fn allow_second_instance(&mut self) -> bool {
        false
    }
}

/// One device channel (MS-RDPECAM 1.3.4 to 1.3.7).
///
/// Windows opens a device channel once per capture client and keeps the
/// instances open together: it may start the stream on one and send the
/// Sample Requests on another (RDP-83). So the device's state lives in
/// [`DevState`], shared by all instances; each instance only keeps its own
/// waiting Sample Requests, since a response goes back on the channel the
/// request came on.
///
/// States (MS-RDPECAM 3.1.1): Deactivated while `activations` is 0,
/// Activated after an Activate Device Request, Streaming while `streaming`
/// is set.
pub struct DeviceChannel {
    shared: Arc<Shared>,
    index: usize,
    dev: Arc<Mutex<DevState>>,
    /// Sample Requests on this instance waiting for a sample.
    pending: u32,
}

/// The camera and its protocol state, common to a device channel's
/// instances.
struct DevState {
    backend: Box<dyn CameraBackend>,
    /// Activate Device Requests not yet matched by a Deactivate.
    activations: u32,
    /// The camera's formats, fetched once while activated.
    media_types: Option<Vec<MediaType>>,
    /// The format last started (the Current Media Type).
    current: Option<MediaType>,
    /// The format the backend captures in; None while not streaming.
    streaming: Option<MediaType>,
    /// Instances open now.
    open: u32,
}

impl DevState {
    /// Stops capture (MS-RDPECAM 3.2.5.24); waiting Sample Requests of
    /// every instance are answered with an error on their next turn.
    fn stop(&mut self, index: usize) {
        if self.streaming.take().is_some() {
            self.backend.stop();
            trace!("camera {index}: capture stopped");
        }
    }

    /// Back to the Deactivated state with the camera closed.
    fn reset(&mut self, index: usize) {
        self.stop(index);
        self.activations = 0;
    }

    /// The camera's formats, asked from the backend the first time.
    fn media_types(&mut self, index: usize) -> std::result::Result<&[MediaType], u32> {
        if self.media_types.is_none() {
            match self.backend.media_types() {
                Ok(list) if !list.is_empty() => {
                    trace!("camera {index}: {} media types", list.len());
                    self.media_types = Some(list);
                }
                Ok(_) => {
                    trace!("camera {index}: no usable media types");
                    return Err(ERR_UNEXPECTED_ERROR);
                }
                Err(e) => {
                    trace!("camera {index}: media types failed: {e}");
                    return Err(ERR_UNEXPECTED_ERROR);
                }
            }
        }
        Ok(self.media_types.as_deref().unwrap_or_default())
    }
}

/// The only stream index this client offers.
const STREAM: u8 = 0;

impl DeviceChannel {
    fn new(shared: Arc<Shared>, index: usize, backend: Box<dyn CameraBackend>) -> DeviceChannel {
        DeviceChannel {
            shared,
            index,
            dev: Arc::new(Mutex::new(DevState {
                backend,
                activations: 0,
                media_types: None,
                current: None,
                streaming: None,
                open: 0,
            })),
            pending: 0,
        }
    }

    fn device(&self) -> &Device {
        &self.shared.devices[self.index]
    }

    fn dev(&self) -> std::sync::MutexGuard<'_, DevState> {
        self.dev.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn version(&self, request_version: u8) -> u8 {
        match self.shared.version.load(Ordering::Relaxed) {
            0 => request_version,
            v => v,
        }
    }

    /// Answers this instance's waiting Sample Requests with `code`.
    fn fail_pending(&mut self, version: u8, code: u32, out: &mut DvcOut) {
        for _ in 0..std::mem::take(&mut self.pending) {
            out.send(sample_error_response(version, STREAM, code));
        }
    }

    /// Stops capture and fails the waiting Sample Requests.
    fn stop_streaming(&mut self, d: &mut DevState, version: u8, code: u32, out: &mut DvcOut) {
        d.stop(self.index);
        self.fail_pending(version, code, out);
    }

    /// Answers one request (MS-RDPECAM 3.2.5.5 to 3.2.5.21); Err is the
    /// ErrorCode of the Error Response to send.
    fn handle(
        &mut self,
        version: u8,
        req: DeviceRequest,
        out: &mut DvcOut,
    ) -> std::result::Result<(), u32> {
        if req.version2_only() && version < 2 {
            return Err(ERR_INVALID_MESSAGE);
        }
        let dev = self.dev.clone();
        let mut d = dev.lock().unwrap_or_else(|p| p.into_inner());
        if req != DeviceRequest::Activate && d.activations == 0 {
            // MS-RDPECAM 3.1.1: in the Deactivated state every request but
            // Activate fails with NotInitialized.
            return Err(ERR_NOT_INITIALIZED);
        }
        let index = self.index;
        match req {
            DeviceRequest::Activate => {
                d.activations = d.activations.saturating_add(1);
                out.send(success_response(version));
            }
            DeviceRequest::Deactivate => {
                d.activations -= 1;
                if d.activations == 0 {
                    self.stop_streaming(&mut d, version, ERR_NOT_INITIALIZED, out);
                }
                out.send(success_response(version));
            }
            DeviceRequest::StreamList => {
                out.send(stream_list_response(version, &[StreamDescription::COLOR]));
            }
            DeviceRequest::MediaTypeList(stream) => {
                check_stream(stream)?;
                let list = d.media_types(index)?;
                out.send(media_type_list_response(version, list));
            }
            DeviceRequest::CurrentMediaType(stream) => {
                check_stream(stream)?;
                let current = match d.current {
                    Some(t) => t,
                    None => d.media_types(index)?[0],
                };
                out.send(current_media_type_response(version, &current));
            }
            DeviceRequest::StartStreams(infos) => {
                // One stream: the last entry for it wins; any other index
                // is invalid.
                let mut wanted = None;
                for (stream, t) in infos {
                    check_stream(stream)?;
                    wanted = Some(t);
                }
                let wanted = wanted.ok_or(ERR_INVALID_MESSAGE)?;
                let Some(&format) = d
                    .media_types(index)?
                    .iter()
                    .find(|t| t.same_format(&wanted))
                else {
                    return Err(ERR_INVALID_MEDIA_TYPE);
                };
                self.stop_streaming(&mut d, version, ERR_NOT_INITIALIZED, out);
                if let Err(e) = d.backend.start(&format) {
                    trace!("camera {index}: capture start failed: {e}");
                    return Err(ERR_UNEXPECTED_ERROR);
                }
                trace!(
                    "camera {index}: capture started, {} {}x{} at {}/{} fps",
                    format.format.name(),
                    format.width,
                    format.height,
                    format.frame_rate_numerator,
                    format.frame_rate_denominator
                );
                d.current = Some(format);
                d.streaming = Some(format);
                out.send(success_response(version));
            }
            DeviceRequest::StopStreams => {
                self.stop_streaming(&mut d, version, ERR_NOT_INITIALIZED, out);
                out.send(success_response(version));
            }
            // Answered by `sample_request`, never through here.
            DeviceRequest::Sample(_) => return Err(ERR_INVALID_REQUEST),
            DeviceRequest::PropertyList => {
                let list = d.backend.properties();
                out.send(property_list_response(version, &list));
            }
            DeviceRequest::PropertyValue(set, id) => {
                let value = d.backend.property(set, id)?;
                out.send(property_value_response(version, &value));
            }
            DeviceRequest::SetPropertyValue(set, id, value) => {
                d.backend.set_property(set, id, value)?;
                out.send(success_response(version));
            }
        }
        Ok(())
    }

    /// A Sample Request (MS-RDPECAM 3.2.5.13): queued while streaming,
    /// else answered with a Sample Error Response.
    fn sample_request(&mut self, version: u8, stream: u8, out: &mut DvcOut) {
        let streaming = self.dev().streaming.is_some();
        let code = if stream != STREAM {
            Some(ERR_INVALID_STREAM_NUMBER)
        } else if !streaming {
            Some(ERR_NOT_INITIALIZED)
        } else if self.pending >= MAX_PENDING_SAMPLES {
            Some(ERR_INVALID_REQUEST)
        } else {
            None
        };
        match code {
            Some(code) => out.send(sample_error_response(version, stream, code)),
            None => {
                self.pending += 1;
                self.deliver(version, out);
            }
        }
    }

    /// Answers waiting Sample Requests with what the backend captured; once
    /// capture stopped (on any instance) they get an error.
    fn deliver(&mut self, version: u8, out: &mut DvcOut) {
        let dev = self.dev.clone();
        let mut d = dev.lock().unwrap_or_else(|p| p.into_inner());
        while self.pending > 0 {
            if d.streaming.is_none() {
                self.fail_pending(version, ERR_NOT_INITIALIZED, out);
                break;
            }
            match d.backend.sample() {
                Ok(Some(sample)) => {
                    self.pending -= 1;
                    out.send(sample_response(version, STREAM, &sample));
                }
                Ok(None) => break,
                Err(e) => {
                    // The camera is gone: fail the waiting requests, stop
                    // capture and tell the server it was removed.
                    trace!("camera {}: capture failed: {e}", self.index);
                    self.stop_streaming(&mut d, version, ERR_UNEXPECTED_ERROR, out);
                    self.device().gone.store(true, Ordering::Relaxed);
                    self.shared.bump();
                }
            }
        }
    }

    /// Back to the Deactivated state with the camera closed; waiting
    /// Sample Requests get an error when `out` is given.
    fn reset(&mut self, out: Option<&mut DvcOut>) {
        self.dev().reset(self.index);
        match out {
            Some(out) => {
                let version = self.version(MAX_VERSION);
                self.fail_pending(version, ERR_NOT_INITIALIZED, out);
            }
            None => self.pending = 0,
        }
    }
}

fn check_stream(stream: u8) -> std::result::Result<(), u32> {
    if stream == STREAM {
        Ok(())
    } else {
        Err(ERR_INVALID_STREAM_NUMBER)
    }
}

impl DynamicChannel for DeviceChannel {
    fn name(&self) -> &str {
        &self.shared.devices[self.index].channel
    }

    /// The first instance starts from the Deactivated state; a further one
    /// joins the device as it is.
    fn opened(&mut self, _out: &mut DvcOut) -> Result<()> {
        self.pending = 0;
        let mut d = self.dev();
        if d.open == 0 {
            d.reset(self.index);
            d.current = None;
        }
        d.open += 1;
        Ok(())
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        let [request_version, id, ref body @ ..] = *msg else {
            // Too short to answer with the right header; discarded (3.1.5).
            trace!(
                "camera {}: message of {} bytes ignored",
                self.index,
                msg.len()
            );
            return Ok(());
        };
        let version = self.version(request_version);
        if !self.device().wanted() {
            // Not shared (any more): nothing reaches the camera, and one
            // still capturing closes now rather than on the next tick.
            let busy = {
                let d = self.dev();
                d.streaming.is_some() || d.activations > 0
            };
            if busy {
                self.reset(Some(out));
            }
            let code = ERR_NOT_INITIALIZED;
            if id == MSG_SAMPLE_REQUEST {
                out.send(sample_error_response(
                    version,
                    body.first().copied().unwrap_or(0),
                    code,
                ));
            } else {
                out.send(error_response(version, code));
            }
            return Ok(());
        }
        let req = match parse_device_request(id, body) {
            Ok(req) => req,
            Err(e) => {
                // MS-RDPECAM 3.2.5: a malformed request gets InvalidMessage.
                trace!("camera {}: {e}", self.index);
                out.send(error_response(version, ERR_INVALID_MESSAGE));
                return Ok(());
            }
        };
        if let DeviceRequest::Sample(stream) = req {
            if self.dev().activations == 0 {
                out.send(sample_error_response(version, stream, ERR_NOT_INITIALIZED));
            } else {
                self.sample_request(version, stream, out);
            }
            return Ok(());
        }
        if let Err(code) = self.handle(version, req, out) {
            trace!(
                "camera {}: MessageId {id:#x} failed with {code}",
                self.index
            );
            out.send(error_response(version, code));
        }
        Ok(())
    }

    /// Follows the switch, and answers waiting Sample Requests.
    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        let version = self.version(MAX_VERSION);
        if self.dev().streaming.is_some() && !self.device().wanted() {
            trace!("camera {}: sharing off, capture stopped", self.index);
            self.reset(Some(out));
            return Ok(());
        }
        if self.pending > 0 {
            self.deliver(version, out);
        }
        Ok(())
    }

    /// The last instance closed: the camera closes at once.
    fn closed(&mut self) {
        self.pending = 0;
        let mut d = self.dev();
        d.open = d.open.saturating_sub(1);
        if d.open == 0 {
            d.reset(self.index);
            d.current = None;
        }
    }

    fn max_message_size(&self) -> usize {
        4096
    }

    /// Another instance of this device channel, over the same device state.
    fn new_instance(&mut self) -> Option<Box<dyn DynamicChannel>> {
        Some(Box::new(DeviceChannel {
            shared: self.shared.clone(),
            index: self.index,
            dev: self.dev.clone(),
            pending: 0,
        }))
    }
}

impl Drop for DeviceChannel {
    /// The session ended: the camera closes at once. An extra instance
    /// dropped after it closed leaves the others' capture running; the
    /// last handle on the device closes the camera.
    fn drop(&mut self) {
        if Arc::strong_count(&self.dev) == 1 {
            self.dev().stop(self.index);
        }
    }
}

#[cfg(test)]
#[path = "camera_tests.rs"]
mod tests;
