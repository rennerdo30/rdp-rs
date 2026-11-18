//! Tests for camera redirection, with MS-RDPECAM section 4 example bytes
//! where the spec has them. No camera is opened: a scripted backend hands
//! out queued samples and records every call.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::dvc::Drdynvc;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// MS-RDPECAM 4.4.6: Media Type List Response, four H.264 formats.
const SPEC_MEDIA_TYPE_LIST: &str = "02 0c 01 80 02 00 00 e0 01 00 00 1e 00 00 00 01
    00 00 00 01 00 00 00 01 00 00 00 01 01 20 03 00
    00 58 02 00 00 1e 00 00 00 01 00 00 00 01 00 00
    00 01 00 00 00 01 01 00 05 00 00 d0 02 00 00 1e
    00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01
    01 80 07 00 00 38 04 00 00 1e 00 00 00 01 00 00
    00 01 00 00 00 01 00 00 00 01";

/// MS-RDPECAM 4.4.8: Current Media Type Response, H.264 1920x1080 at 30.
const SPEC_CURRENT_MEDIA_TYPE: &str = "02 0e 01 80 07 00 00 38 04 00 00 1e 00 00 00 01
    00 00 00 01 00 00 00 01 00 00 00 01";

/// MS-RDPECAM 4.5.1: Start Streams Request for that format on stream 0.
const SPEC_START_STREAMS: &str = "02 0f 00 01 80 07 00 00 38 04 00 00 1e 00 00 00
    01 00 00 00 01 00 00 00 01 00 00 00 01";

/// MS-RDPECAM 4.6.2: Property List Response, Focus and Brightness.
const SPEC_PROPERTY_LIST: &str = "02 15 01 02 03 00 00 00 00 fa 00 00 00 05 00 00
    00 00 00 00 00 02 02 01 00 00 00 00 ff 00 00 00
    01 00 00 00 80 00 00 00";

fn h264(width: u32, height: u32) -> MediaType {
    MediaType::new(VideoFormat::H264, width, height, 30, 1)
}

/// The four formats of the spec's Media Type List Response.
fn spec_types() -> Vec<MediaType> {
    vec![
        h264(640, 480),
        h264(800, 600),
        h264(1280, 720),
        h264(1920, 1080),
    ]
}

fn spec_properties() -> Vec<PropertyDescription> {
    vec![
        PropertyDescription {
            set: PROPERTY_SET_CAMERA_CONTROL,
            id: 2, // Focus
            capabilities: PROPERTY_MANUAL | PROPERTY_AUTO,
            min: 0,
            max: 250,
            step: 5,
            default: 0,
        },
        PropertyDescription {
            set: PROPERTY_SET_VIDEO_PROC_AMP,
            id: 2, // Brightness
            capabilities: PROPERTY_MANUAL,
            min: 0,
            max: 255,
            step: 1,
            default: 128,
        },
    ]
}

// ---------------------------------------------------------------- PDUs

#[test]
fn select_version_spec_example() {
    // MS-RDPECAM 4.1.1.
    assert_eq!(select_version_request(2), hex("02 03"));
}

#[test]
fn device_added_spec_example() {
    // MS-RDPECAM 4.2.1 (the annotation says "Camera_Device_0"; the bytes
    // carry "RDCamera_Device_0", the name this client uses).
    let want = hex("02 05 4d 00 6f 00 63 00 6b 00 20 00 43 00 61 00
         6d 00 65 00 72 00 61 00 20 00 31 00 00 00 52 44
         43 61 6d 65 72 61 5f 44 65 76 69 63 65 5f 30 00");
    assert_eq!(
        device_added(2, "Mock Camera 1", &device_channel_name(0)),
        want
    );
}

#[test]
fn device_removed_spec_example() {
    // MS-RDPECAM 4.3.1.
    let want = hex("02 06 52 44 43 61 6d 65 72 61 5f 44 65 76 69 63 65 5f 31 00");
    assert_eq!(device_removed(2, "RDCamera_Device_1"), want);
}

#[test]
fn channel_names_are_ansi_and_bounded() {
    let v = device_removed(1, "Cam é\u{1}x");
    assert_eq!(v, b"\x01\x06Cam____x\0");
    let long = "a".repeat(300);
    assert_eq!(device_removed(1, &long).len(), 2 + MAX_CHANNEL_NAME + 1);
    // A NUL inside a display name would end it early on the server.
    let v = device_added(1, "A\0B", "c");
    assert_eq!(v, hex("01 05 41 00 42 00 00 00 63 00"));
}

#[test]
fn simple_responses_spec_examples() {
    // MS-RDPECAM 4.4.2 Success Response, 4.8 Error Response.
    assert_eq!(success_response(2), hex("02 01"));
    assert_eq!(
        error_response(2, ERR_NOT_INITIALIZED),
        hex("02 02 03 00 00 00")
    );
}

#[test]
fn stream_list_response_spec_example() {
    // MS-RDPECAM 4.4.4: two shareable colour streams, the first selected.
    let shared = StreamDescription {
        can_be_shared: true,
        ..StreamDescription::COLOR
    };
    let second = StreamDescription {
        selected: false,
        ..shared
    };
    let want = hex("02 0a 01 00 01 01 01 01 00 01 00 01");
    assert_eq!(stream_list_response(2, &[shared, second]), want);
    let mut r = Reader::new(&want[2..]);
    assert_eq!(StreamDescription::parse(&mut r).unwrap(), shared);
    assert_eq!(StreamDescription::parse(&mut r).unwrap(), second);
}

#[test]
fn media_type_list_response_spec_example() {
    // MS-RDPECAM 4.4.6.
    let want = hex(SPEC_MEDIA_TYPE_LIST);
    assert_eq!(want.len(), 2 + 4 * MEDIA_TYPE_SIZE);
    assert_eq!(media_type_list_response(2, &spec_types()), want);
    let mut r = Reader::new(&want[2..]);
    for t in spec_types() {
        assert_eq!(MediaType::parse(&mut r).unwrap(), t);
    }
    assert_eq!(r.remaining(), 0);
}

#[test]
fn current_media_type_response_spec_example() {
    // MS-RDPECAM 4.4.8.
    assert_eq!(
        current_media_type_response(2, &h264(1920, 1080)),
        hex(SPEC_CURRENT_MEDIA_TYPE)
    );
}

#[test]
fn device_requests_spec_examples() {
    // MS-RDPECAM 4.4.1, 4.4.3, 4.4.5, 4.4.7, 4.4.9, 4.5.1, 4.5.2, 4.5.4,
    // 4.6.1, 4.6.3, 4.7.1.
    let parse = |s: &str| {
        let b = hex(s);
        parse_device_request(b[1], &b[2..]).unwrap()
    };
    assert_eq!(parse("02 07"), DeviceRequest::Activate);
    assert_eq!(parse("02 09"), DeviceRequest::StreamList);
    assert_eq!(parse("02 0b 00"), DeviceRequest::MediaTypeList(0));
    assert_eq!(parse("02 0d 00"), DeviceRequest::CurrentMediaType(0));
    assert_eq!(parse("02 08"), DeviceRequest::Deactivate);
    assert_eq!(
        parse(SPEC_START_STREAMS),
        DeviceRequest::StartStreams(vec![(0, h264(1920, 1080))])
    );
    assert_eq!(parse("02 11 00"), DeviceRequest::Sample(0));
    assert_eq!(parse("02 10"), DeviceRequest::StopStreams);
    assert_eq!(parse("02 14"), DeviceRequest::PropertyList);
    assert_eq!(parse("02 16 02 02"), DeviceRequest::PropertyValue(2, 2));
    assert_eq!(
        parse("02 18 02 02 01 64 00 00 00"),
        DeviceRequest::SetPropertyValue(
            2,
            2,
            PropertyValue {
                mode: PROPERTY_MANUAL,
                value: 100
            }
        )
    );
}

#[test]
fn sample_response_spec_example_header() {
    // MS-RDPECAM 4.5.3: header, stream 0, then the sample bytes as is.
    let sample = hex("00 00 00 01 09 30 00 00 00 01 61 e0 42");
    let v = sample_response(2, 0, &sample);
    assert_eq!(&v[..3], &[0x02, 0x12, 0x00]);
    assert_eq!(&v[3..], &sample[..]);
    assert_eq!(
        sample_error_response(2, 0, ERR_UNEXPECTED_ERROR),
        hex("02 13 00 01 00 00 00")
    );
}

#[test]
fn property_messages_spec_examples() {
    // MS-RDPECAM 4.6.2, 4.6.4.
    assert_eq!(
        property_list_response(2, &spec_properties()),
        hex(SPEC_PROPERTY_LIST)
    );
    let list = hex(SPEC_PROPERTY_LIST);
    let mut r = Reader::new(&list[2..]);
    for p in spec_properties() {
        assert_eq!(PropertyDescription::parse(&mut r).unwrap(), p);
    }
    let value = PropertyValue {
        mode: PROPERTY_MANUAL,
        value: 100,
    };
    assert_eq!(
        property_value_response(2, &value),
        hex("02 17 01 64 00 00 00")
    );
    // Negative values survive the signed fields.
    let neg = PropertyDescription {
        min: -10,
        ..spec_properties()[0]
    };
    let mut v = Vec::new();
    neg.write(&mut v);
    assert_eq!(
        PropertyDescription::parse(&mut Reader::new(&v)).unwrap(),
        neg
    );
}

#[test]
fn malformed_requests_are_errors_not_panics() {
    assert!(parse_device_request(MSG_MEDIA_TYPE_LIST_REQUEST, &[]).is_err());
    assert!(parse_device_request(MSG_ACTIVATE_DEVICE_REQUEST, &[0]).is_err());
    assert!(parse_device_request(MSG_SAMPLE_REQUEST, &[0, 0]).is_err());
    let start = hex(SPEC_START_STREAMS);
    // One byte short, one byte over, none at all.
    assert!(parse_device_request(MSG_START_STREAMS_REQUEST, &start[2..start.len() - 1]).is_err());
    assert!(
        parse_device_request(MSG_START_STREAMS_REQUEST, &[&start[2..], &[0]].concat()).is_err()
    );
    assert!(parse_device_request(MSG_START_STREAMS_REQUEST, &[]).is_err());
    // An unknown format.
    let mut bad = start[2..].to_vec();
    bad[1] = 0x09;
    assert!(parse_device_request(MSG_START_STREAMS_REQUEST, &bad).is_err());
    assert!(parse_device_request(MSG_SUCCESS_RESPONSE, &[]).is_err());
    assert!(parse_device_request(0xFF, &[]).is_err());
    // 256 START_STREAM_INFO is one more than the spec allows.
    let many = start[2..].repeat(256);
    assert!(parse_device_request(MSG_START_STREAMS_REQUEST, &many).is_err());
    let max = start[2..].repeat(255);
    assert!(parse_device_request(MSG_START_STREAMS_REQUEST, &max).is_ok());
}

// ------------------------------------------------------- state machine

#[derive(Debug, PartialEq, Eq, Clone)]
enum Ev {
    MediaTypes,
    Start(MediaType),
    Stop,
    SetProperty(u8, u8, PropertyValue),
}

#[derive(Default)]
struct Script {
    events: Vec<Ev>,
    types: Vec<MediaType>,
    samples: VecDeque<Vec<u8>>,
    fail_start: bool,
    fail_capture: bool,
    capturing: bool,
}

struct Mock(Arc<Mutex<Script>>);

impl CameraBackend for Mock {
    fn media_types(&mut self) -> std::result::Result<Vec<MediaType>, String> {
        let mut s = self.0.lock().unwrap();
        s.events.push(Ev::MediaTypes);
        Ok(s.types.clone())
    }

    fn start(&mut self, media_type: &MediaType) -> std::result::Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.events.push(Ev::Start(*media_type));
        if s.fail_start {
            return Err("busy".into());
        }
        s.capturing = true;
        Ok(())
    }

    fn sample(&mut self) -> std::result::Result<Option<Vec<u8>>, String> {
        let mut s = self.0.lock().unwrap();
        assert!(s.capturing, "sample asked while not capturing");
        if s.fail_capture {
            return Err("device lost".into());
        }
        Ok(s.samples.pop_front())
    }

    fn stop(&mut self) {
        let mut s = self.0.lock().unwrap();
        s.events.push(Ev::Stop);
        s.capturing = false;
    }

    fn properties(&mut self) -> Vec<PropertyDescription> {
        spec_properties()
    }

    fn property(&mut self, set: u8, id: u8) -> std::result::Result<PropertyValue, u32> {
        match (set, id) {
            (PROPERTY_SET_VIDEO_PROC_AMP, 2) => Ok(PropertyValue {
                mode: PROPERTY_MANUAL,
                value: 100,
            }),
            (1 | 2, _) => Err(ERR_ITEM_NOT_FOUND),
            _ => Err(ERR_SET_NOT_FOUND),
        }
    }

    fn set_property(
        &mut self,
        set: u8,
        id: u8,
        value: PropertyValue,
    ) -> std::result::Result<(), u32> {
        self.0
            .lock()
            .unwrap()
            .events
            .push(Ev::SetProperty(set, id, value));
        Ok(())
    }
}

/// The enumerator and `n` mock cameras, with their scripts.
struct Rig {
    channels: Vec<Box<dyn DynamicChannel>>,
    handle: CameraHandle,
    scripts: Vec<Arc<Mutex<Script>>>,
}

fn rig(n: usize) -> Rig {
    let scripts: Vec<_> = (0..n)
        .map(|_| {
            Arc::new(Mutex::new(Script {
                types: spec_types(),
                ..Default::default()
            }))
        })
        .collect();
    let devices = scripts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                format!("Mock Camera {}", i + 1),
                Box::new(Mock(s.clone())) as Box<dyn CameraBackend>,
            )
        })
        .collect();
    let (channels, handle) = cameras(devices);
    Rig {
        channels,
        handle,
        scripts,
    }
}

impl Rig {
    fn send(&mut self, channel: usize, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        self.channels[channel].process(msg, &mut out).unwrap();
        out.take()
    }

    fn tick(&mut self, channel: usize) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        self.channels[channel].tick(&mut out).unwrap();
        out.take()
    }

    fn open(&mut self, channel: usize) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        self.channels[channel].opened(&mut out).unwrap();
        out.take()
    }

    fn events(&self, camera: usize) -> Vec<Ev> {
        self.scripts[camera].lock().unwrap().events.clone()
    }

    fn push_sample(&self, camera: usize, sample: &[u8]) {
        self.scripts[camera]
            .lock()
            .unwrap()
            .samples
            .push_back(sample.to_vec());
    }

    /// Version 2 negotiated, camera 0 shared and its channel open.
    fn negotiated(n: usize) -> Rig {
        let mut r = rig(n);
        r.handle.set_enabled(0, true);
        assert_eq!(r.open(0), vec![hex("02 03")]);
        r.send(0, &hex("02 04"));
        r.open(1);
        r
    }

    /// ... and activated, streaming 1080p H.264.
    fn streaming() -> Rig {
        let mut r = Rig::negotiated(1);
        assert_eq!(r.send(1, &hex("02 07")), vec![hex("02 01")]);
        assert_eq!(r.send(1, &hex(SPEC_START_STREAMS)), vec![hex("02 01")]);
        r
    }
}

#[test]
fn enumerator_negotiates_and_announces_shared_cameras_only() {
    let mut r = rig(2);
    assert_eq!(r.channels[0].name(), ENUMERATOR);
    assert_eq!(r.channels[1].name(), "RDCamera_Device_0");
    assert_eq!(r.channels[2].name(), "RDCamera_Device_1");
    assert_eq!(r.handle.names(), ["Mock Camera 1", "Mock Camera 2"]);
    // MS-RDPECAM 4.1: the client asks first, with its highest version.
    assert_eq!(r.open(0), vec![hex("02 03")]);
    // Nothing is shared yet: the response announces nothing.
    assert!(r.send(0, &hex("02 04")).is_empty());
    assert_eq!(r.handle.version(), 2);
    assert!(r.tick(0).is_empty());
    r.handle.set_enabled(1, true);
    assert_eq!(
        r.tick(0),
        vec![device_added(2, "Mock Camera 2", "RDCamera_Device_1")]
    );
    assert!(r.tick(0).is_empty(), "announced once");
    r.handle.set_enabled(1, false);
    assert_eq!(r.tick(0), vec![device_removed(2, "RDCamera_Device_1")]);
    assert!(r.tick(0).is_empty());
    // Listing and announcing never touches a camera.
    assert!(r.events(0).is_empty() && r.events(1).is_empty());
}

#[test]
fn cameras_shared_before_negotiation_are_announced_with_the_response() {
    let mut r = rig(2);
    r.handle.set_enabled(0, true);
    r.handle.set_enabled(1, true);
    r.open(0);
    assert!(r.tick(0).is_empty(), "nothing before the version is known");
    // The server picks version 1: every later header carries 1.
    assert_eq!(
        r.send(0, &hex("01 04")),
        vec![
            device_added(1, "Mock Camera 1", "RDCamera_Device_0"),
            device_added(1, "Mock Camera 2", "RDCamera_Device_1"),
        ]
    );
    assert_eq!(r.handle.version(), 1);
}

#[test]
fn enumerator_discards_bad_and_repeated_responses() {
    let mut r = rig(1);
    r.handle.set_enabled(0, true);
    r.open(0);
    // A version the client does not speak: the protocol does not go on.
    assert!(r.send(0, &hex("03 04")).is_empty());
    assert!(r.send(0, &hex("00 04")).is_empty());
    assert_eq!(r.handle.version(), 0);
    assert!(r.tick(0).is_empty());
    // Malformed and other messages are discarded too.
    assert!(r.send(0, &[]).is_empty());
    assert!(r.send(0, &hex("02")).is_empty());
    assert!(r.send(0, &hex("02 04 00")).is_empty());
    assert!(r.send(0, &hex("02 05")).is_empty());
    assert_eq!(r.send(0, &hex("02 04")).len(), 1);
    // A repeated response does not announce again or change the version.
    assert!(r.send(0, &hex("01 04")).is_empty());
    assert_eq!(r.handle.version(), 2);
}

#[test]
fn enumerator_reopened_starts_over() {
    let mut r = Rig::negotiated(1);
    r.channels[0].closed();
    assert_eq!(r.handle.version(), 0);
    assert_eq!(r.open(0), vec![hex("02 03")]);
    assert_eq!(
        r.send(0, &hex("02 04")),
        vec![device_added(2, "Mock Camera 1", "RDCamera_Device_0")]
    );
}

#[test]
fn deactivated_device_answers_not_initialized() {
    let mut r = Rig::negotiated(1);
    let not_init = vec![hex("02 02 03 00 00 00")];
    for req in ["02 09", "02 0b 00", "02 0d 00", "02 10", "02 08", "02 14"] {
        assert_eq!(r.send(1, &hex(req)), not_init, "{req}");
    }
    assert_eq!(r.send(1, &hex(SPEC_START_STREAMS)), not_init);
    // A Sample Request gets a Sample Error Response.
    assert_eq!(
        r.send(1, &hex("02 11 00")),
        vec![hex("02 13 00 03 00 00 00")]
    );
    assert!(r.events(0).is_empty(), "the camera is never touched");
}

#[test]
fn device_initialization_sequence() {
    // MS-RDPECAM 1.3.4 with the bytes of 4.4.
    let mut r = Rig::negotiated(1);
    assert_eq!(r.send(1, &hex("02 07")), vec![hex("02 01")]);
    assert!(r.events(0).is_empty(), "activation alone opens nothing");
    assert_eq!(
        r.send(1, &hex("02 09")),
        vec![stream_list_response(2, &[StreamDescription::COLOR])]
    );
    assert_eq!(r.send(1, &hex("02 0b 00")), vec![hex(SPEC_MEDIA_TYPE_LIST)]);
    // Nothing started yet: the current type is the camera's first.
    assert_eq!(
        r.send(1, &hex("02 0d 00")),
        vec![current_media_type_response(2, &h264(640, 480))]
    );
    assert_eq!(r.send(1, &hex("02 08")), vec![hex("02 01")]);
    // The formats were asked once and capture never started.
    assert_eq!(r.events(0), vec![Ev::MediaTypes]);
}

#[test]
fn video_capture_sequence_one_sample_per_request() {
    // MS-RDPECAM 1.3.5 with the bytes of 4.5.
    let mut r = Rig::streaming();
    assert_eq!(
        r.events(0),
        vec![Ev::MediaTypes, Ev::Start(h264(1920, 1080))]
    );
    // The current type is now the started one (4.4.8).
    assert_eq!(
        r.send(1, &hex("02 0d 00")),
        vec![hex(SPEC_CURRENT_MEDIA_TYPE)]
    );
    // A request waits until the camera has a sample.
    assert!(r.send(1, &hex("02 11 00")).is_empty());
    assert!(r.tick(1).is_empty());
    r.push_sample(0, b"frame1");
    r.push_sample(0, b"frame2");
    assert_eq!(r.tick(1), vec![sample_response(2, 0, b"frame1")]);
    // One request, one sample: frame2 waits for the next request.
    assert!(r.tick(1).is_empty());
    assert_eq!(
        r.send(1, &hex("02 11 00")),
        vec![sample_response(2, 0, b"frame2")]
    );
    // Stop Streams closes the camera; a waiting request is failed.
    assert!(r.send(1, &hex("02 11 00")).is_empty());
    assert_eq!(
        r.send(1, &hex("02 10")),
        vec![hex("02 13 00 03 00 00 00"), hex("02 01")]
    );
    assert_eq!(r.events(0).last(), Some(&Ev::Stop));
    assert!(!r.scripts[0].lock().unwrap().capturing);
    // Activated but not streaming: Sample Requests fail.
    assert_eq!(
        r.send(1, &hex("02 11 00")),
        vec![hex("02 13 00 03 00 00 00")]
    );
    assert_eq!(r.send(1, &hex("02 08")), vec![hex("02 01")]);
}

#[test]
fn start_streams_checks_stream_and_format() {
    let mut r = Rig::negotiated(1);
    r.send(1, &hex("02 07"));
    // A format the camera does not have.
    let mut req = hex(SPEC_START_STREAMS);
    req[4] = 0x99; // width 1920 -> 0x799 = 1945
    assert_eq!(r.send(1, &req), vec![hex("02 02 06 00 00 00")]);
    // Stream 1 does not exist.
    let mut req = hex(SPEC_START_STREAMS);
    req[2] = 1;
    assert_eq!(r.send(1, &req), vec![hex("02 02 05 00 00 00")]);
    assert_eq!(r.send(1, &hex("02 0b 01")), vec![hex("02 02 05 00 00 00")]);
    assert_eq!(
        r.send(1, &hex("02 11 01")),
        vec![hex("02 13 01 05 00 00 00")]
    );
    // Flags are not part of the format: a server echoing other flags is fine.
    let mut req = hex(SPEC_START_STREAMS);
    *req.last_mut().unwrap() = 0;
    assert_eq!(r.send(1, &req), vec![hex("02 01")]);
    assert_eq!(
        r.events(0),
        vec![Ev::MediaTypes, Ev::Start(h264(1920, 1080))],
        "the camera's own description is started"
    );
}

#[test]
fn start_failure_is_an_error_and_not_streaming() {
    let mut r = Rig::negotiated(1);
    r.scripts[0].lock().unwrap().fail_start = true;
    r.send(1, &hex("02 07"));
    assert_eq!(
        r.send(1, &hex(SPEC_START_STREAMS)),
        vec![hex("02 02 01 00 00 00")]
    );
    assert_eq!(
        r.send(1, &hex("02 11 00")),
        vec![hex("02 13 00 03 00 00 00")]
    );
}

#[test]
fn restart_with_another_format_stops_first() {
    let mut r = Rig::streaming();
    let mut req = vec![0x02, 0x0f, 0x00];
    h264(640, 480).write(&mut req);
    assert_eq!(r.send(1, &req), vec![hex("02 01")]);
    assert_eq!(
        r.events(0),
        vec![
            Ev::MediaTypes,
            Ev::Start(h264(1920, 1080)),
            Ev::Stop,
            Ev::Start(h264(640, 480))
        ]
    );
}

#[test]
fn activations_are_counted() {
    // MS-RDPECAM 3.1.1: as many Deactivates as Activates.
    let mut r = Rig::streaming();
    assert_eq!(r.send(1, &hex("02 07")), vec![hex("02 01")]);
    assert_eq!(r.send(1, &hex("02 08")), vec![hex("02 01")]);
    assert!(
        r.scripts[0].lock().unwrap().capturing,
        "still activated once"
    );
    assert_eq!(r.send(1, &hex("02 08")), vec![hex("02 01")]);
    assert!(
        !r.scripts[0].lock().unwrap().capturing,
        "deactivated: closed"
    );
    assert_eq!(r.send(1, &hex("02 08")), vec![hex("02 02 03 00 00 00")]);
}

#[test]
fn deactivate_while_streaming_closes_the_camera() {
    let mut r = Rig::streaming();
    assert!(r.send(1, &hex("02 11 00")).is_empty());
    assert_eq!(
        r.send(1, &hex("02 08")),
        vec![hex("02 13 00 03 00 00 00"), hex("02 01")]
    );
    assert_eq!(r.events(0).last(), Some(&Ev::Stop));
}

#[test]
fn sharing_off_closes_the_camera_at_once_and_removes_it() {
    let mut r = Rig::streaming();
    assert!(r.send(1, &hex("02 11 00")).is_empty());
    r.handle.set_enabled(0, false);
    // The device channel's next tick closes the camera.
    assert_eq!(r.tick(1), vec![hex("02 13 00 03 00 00 00")]);
    assert!(!r.scripts[0].lock().unwrap().capturing);
    assert_eq!(r.tick(0), vec![device_removed(2, "RDCamera_Device_0")]);
    // Requests on the old channel reach nothing.
    assert_eq!(r.send(1, &hex("02 07")), vec![hex("02 02 03 00 00 00")]);
    assert_eq!(
        r.send(1, &hex(SPEC_START_STREAMS)),
        vec![hex("02 02 03 00 00 00")]
    );
    assert_eq!(
        r.events(0)
            .iter()
            .filter(|e| matches!(e, Ev::Start(_)))
            .count(),
        1
    );
    // Shared again: announced again, and works from Activate on.
    r.handle.set_enabled(0, true);
    assert_eq!(
        r.tick(0),
        vec![device_added(2, "Mock Camera 1", "RDCamera_Device_0")]
    );
    r.open(1);
    assert_eq!(r.send(1, &hex("02 0b 00")), vec![hex("02 02 03 00 00 00")]);
    assert_eq!(r.send(1, &hex("02 07")), vec![hex("02 01")]);
}

#[test]
fn channel_close_and_drop_close_the_camera() {
    let mut r = Rig::streaming();
    r.channels[1].closed();
    assert_eq!(r.events(0).last(), Some(&Ev::Stop));
    assert!(!r.scripts[0].lock().unwrap().capturing);
    // Reopened: Deactivated again.
    r.open(1);
    assert_eq!(r.send(1, &hex("02 09")), vec![hex("02 02 03 00 00 00")]);

    // The session ending (the channel dropped while streaming).
    let r = Rig::streaming();
    let script = r.scripts[0].clone();
    assert!(script.lock().unwrap().capturing);
    drop(r);
    assert!(!script.lock().unwrap().capturing);
    assert_eq!(script.lock().unwrap().events.last(), Some(&Ev::Stop));
}

#[test]
fn capture_failure_fails_requests_and_removes_the_device() {
    let mut r = Rig::streaming();
    assert!(r.send(1, &hex("02 11 00")).is_empty());
    r.scripts[0].lock().unwrap().fail_capture = true;
    assert_eq!(r.tick(1), vec![hex("02 13 00 01 00 00 00")]);
    assert!(!r.scripts[0].lock().unwrap().capturing);
    // MS-RDPECAM 3.2.7: the client starts the Device Removal sequence.
    assert_eq!(r.tick(0), vec![device_removed(2, "RDCamera_Device_0")]);
    assert!(r.handle.enabled(0), "the user's choice stays");
}

#[test]
fn pending_sample_requests_are_bounded() {
    let mut r = Rig::streaming();
    for _ in 0..MAX_PENDING_SAMPLES {
        assert!(r.send(1, &hex("02 11 00")).is_empty());
    }
    assert_eq!(
        r.send(1, &hex("02 11 00")),
        vec![hex("02 13 00 04 00 00 00")]
    );
    for i in 0..MAX_PENDING_SAMPLES {
        r.push_sample(0, &[i as u8]);
    }
    assert_eq!(r.tick(1).len(), MAX_PENDING_SAMPLES as usize);
}

#[test]
fn version2_properties_reach_the_backend() {
    // MS-RDPECAM 1.3.6 and 1.3.7 with the bytes of 4.6 and 4.7.
    let mut r = Rig::negotiated(1);
    r.send(1, &hex("02 07"));
    assert_eq!(r.send(1, &hex("02 14")), vec![hex(SPEC_PROPERTY_LIST)]);
    assert_eq!(
        r.send(1, &hex("02 16 02 02")),
        vec![hex("02 17 01 64 00 00 00")]
    );
    assert_eq!(
        r.send(1, &hex("02 16 02 09")),
        vec![hex("02 02 08 00 00 00")]
    );
    assert_eq!(
        r.send(1, &hex("02 16 07 01")),
        vec![hex("02 02 09 00 00 00")]
    );
    assert_eq!(
        r.send(1, &hex("02 18 02 02 01 64 00 00 00")),
        vec![hex("02 01")]
    );
    assert_eq!(
        r.events(0),
        vec![Ev::SetProperty(
            2,
            2,
            PropertyValue {
                mode: PROPERTY_MANUAL,
                value: 100
            }
        )]
    );
}

#[test]
fn version1_rejects_property_requests() {
    let mut r = rig(1);
    r.handle.set_enabled(0, true);
    r.open(0);
    r.send(0, &hex("01 04"));
    r.open(1);
    assert_eq!(r.send(1, &hex("01 07")), vec![hex("01 01")]);
    assert_eq!(r.send(1, &hex("01 14")), vec![hex("01 02 02 00 00 00")]);
    assert!(r.events(0).is_empty());
}

#[test]
fn malformed_device_messages_get_invalid_message() {
    let mut r = Rig::negotiated(1);
    r.send(1, &hex("02 07"));
    let invalid = vec![hex("02 02 02 00 00 00")];
    assert_eq!(r.send(1, &hex("02 0b")), invalid);
    assert_eq!(r.send(1, &hex("02 07 00")), invalid);
    assert_eq!(r.send(1, &hex("02 0f 00 01")), invalid);
    assert_eq!(
        r.send(1, &hex("02 01")),
        invalid,
        "a response is no request"
    );
    assert_eq!(r.send(1, &hex("02 ee")), invalid);
    // Too short to carry a header: discarded.
    assert!(r.send(1, &[]).is_empty());
    assert!(r.send(1, &[2]).is_empty());
}

#[test]
fn random_input_never_panics() {
    // Every MessageId with every short body length, in every state.
    let mut r = Rig::streaming();
    r.push_sample(0, b"x");
    let mut seed = 0x1234_5678u32;
    for id in 0..=0x1Fu8 {
        for len in 0..40usize {
            let mut msg = vec![2, id];
            for _ in 0..len {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                msg.push((seed >> 16) as u8);
            }
            for ch in 0..r.channels.len() {
                r.send(ch, &msg);
                r.tick(ch);
            }
        }
    }
}

#[test]
fn device_channel_routes_through_drdynvc() {
    // The channel names the client announces are the ones Drdynvc binds.
    let r = Rig::negotiated(1);
    let script = r.scripts[0].clone();
    let mut d = Drdynvc::new(r.channels);
    let feed = |d: &mut Drdynvc, msg: &[u8]| {
        let mut out = ChannelOut::default();
        d.process(msg, &mut out).unwrap();
        out.take()
    };
    let mut create = vec![0x10, 0x07];
    create.extend_from_slice(b"RDCamera_Device_0\0");
    assert_eq!(feed(&mut d, &create)[0], vec![0x10, 0x07, 0, 0, 0, 0]);
    // Activate Device Request as DYNVC_DATA on channel 7.
    assert_eq!(
        feed(&mut d, &[0x30, 0x07, 0x02, 0x07]),
        vec![vec![0x30, 0x07, 0x02, 0x01]]
    );
    assert!(script.lock().unwrap().events.is_empty());
}
