//! Tests for the `AUDIO_INPUT` channel, with MS-RDPEAI section 4 example
//! bytes where the spec has them. No device is opened: a scripted backend
//! hands out queued blocks and records every call.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::dvc::Drdynvc;
use crate::rdpsnd::CLIENT_FORMATS;

/// MS-RDPEAI 4.1.3: Server Sound Formats PDU, 21 formats, 667 bytes.
const SPEC_SERVER_FORMATS: &[&str] = &[
    "0215000000000000800100020044ac000010b102000400100000000200020044",
    "ac000047ad0000000804002000f407070000010000000200ff00000000c00040",
    "00f0000000cc0130ff880118ff1100020044ac0000dbac0000000804000200f9",
    "07020002002256000027570000000404002000f403070000010000000200ff00",
    "000000c0004000f0000000cc0130ff880118ff1100020022560000b956000000",
    "0404000200f9030200010044ac0000a3560000000404002000f4070700000100",
    "00000200ff00000000c0004000f0000000cc0130ff880118ff1100010044ac00",
    "006d560000000404000200f90702000200112b0000192c0000000204002000f4",
    "01070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11",
    "000200112b0000a92b0000000204000200f9010200010022560000932b000000",
    "0204002000f403070000010000000200ff00000000c0004000f0000000cc0130",
    "ff880118ff11000100225600005c2b0000000204000200f9033100010044ac00",
    "00fd220000410000000200400102000200401f000000200000000204002000f4",
    "01070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11",
    "000200401f0000ae1f0000000204000200f90102000100112b00000c16000000",
    "0104002000f401070000010000000200ff00000000c0004000f0000000cc0130",
    "ff880118ff11000100112b0000d4150000000104000200f90131000100225600",
    "007e110000410000000200400102000100401f000000100000000104002000f4",
    "01070000010000000200ff00000000c0004000f0000000cc0130ff880118ff11",
    "000100401f0000d70f0000000104000200f90131000100112b0000bf08000041",
    "0000000200400131000100401f0000590600004100000002004001",
];

/// MS-RDPEAI 4.1.6: Open PDU, FramesPerPacket 2205, initialFormat 11,
/// WAVE_FORMAT_EXTENSIBLE 44.1 kHz stereo 16-bit.
const SPEC_OPEN: &str = "039d0800000b000000feff020044ac000010b10200040010001600\
                         1000030000000100000000001000800000aa00389b71";

fn hex(parts: &[&str]) -> Vec<u8> {
    let s: String = parts.concat();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const STEREO_44: PcmFormat = PcmFormat {
    channels: 2,
    sample_rate: 44_100,
    bits: 16,
};
const MONO_48: PcmFormat = PcmFormat {
    channels: 1,
    sample_rate: 48_000,
    bits: 16,
};

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Start(PcmFormat, u32),
    Stop,
}

#[derive(Default)]
struct Script {
    events: Vec<Ev>,
    blocks: VecDeque<Vec<u8>>,
    reads: usize,
    fail_start: bool,
}

struct Mock(Arc<Mutex<Script>>);

impl CaptureBackend for Mock {
    fn formats(&self) -> Vec<PcmFormat> {
        CLIENT_FORMATS.to_vec()
    }
    fn start(&mut self, format: &PcmFormat, fpp: u32) -> std::result::Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.events.push(Ev::Start(*format, fpp));
        if s.fail_start {
            Err("no microphone".into())
        } else {
            Ok(())
        }
    }
    fn read(&mut self) -> Option<Vec<u8>> {
        let mut s = self.0.lock().unwrap();
        s.reads += 1;
        s.blocks.pop_front()
    }
    fn stop(&mut self) {
        self.0.lock().unwrap().events.push(Ev::Stop);
    }
}

struct Rig {
    ch: AudioInput,
    handle: AudioInputHandle,
    script: Arc<Mutex<Script>>,
}

impl Rig {
    fn new() -> Rig {
        let script = Arc::new(Mutex::new(Script::default()));
        let (ch, handle) = audin(Box::new(Mock(script.clone())));
        Rig { ch, handle, script }
    }

    fn feed(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        self.ch.process(msg, &mut out).unwrap();
        out.take()
    }

    fn tick(&mut self) -> Vec<Vec<u8>> {
        let mut out = DvcOut::default();
        self.ch.tick(&mut out).unwrap();
        out.take()
    }

    fn events(&self) -> Vec<Ev> {
        std::mem::take(&mut self.script.lock().unwrap().events)
    }

    fn queue(&self, block: Vec<u8>) {
        self.script.lock().unwrap().blocks.push_back(block);
    }

    /// Version and the spec's server formats: the client keeps one format,
    /// 44.1 kHz stereo, at index 0.
    fn negotiate(&mut self) {
        self.feed(&[1, 1, 0, 0, 0]);
        self.feed(&hex(SPEC_SERVER_FORMATS));
    }

    /// Open PDU with the spec's capture format and the given values.
    fn open(&mut self, fpp: u32, initial: u32) -> Vec<Vec<u8>> {
        let mut msg = hex(&[SPEC_OPEN]);
        msg[1..5].copy_from_slice(&fpp.to_le_bytes());
        msg[5..9].copy_from_slice(&initial.to_le_bytes());
        self.feed(&msg)
    }
}

fn data(audio: &[u8]) -> Vec<Vec<u8>> {
    vec![vec![MSG_SNDIN_DATA_INCOMING], data_pdu(audio)]
}

#[test]
fn version_spec_example() {
    // MS-RDPEAI 4.1.1 server Version PDU, 4.1.2 client Version PDU.
    let mut rig = Rig::new();
    assert_eq!(rig.feed(&[1, 1, 0, 0, 0]), vec![vec![1, 1, 0, 0, 0]]);
    assert_eq!(rig.feed(&[1, 2, 0, 0, 0]), vec![vec![1, 1, 0, 0, 0]]);
}

#[test]
fn spec_server_formats_parse_exactly() {
    let msg = hex(SPEC_SERVER_FORMATS);
    assert_eq!(msg.len(), 0x29b);
    let formats = parse_formats(&msg[1..]).unwrap();
    assert_eq!(formats.len(), 21);
    let tags: Vec<u16> = formats.iter().map(|f| f.tag).collect();
    assert_eq!(&tags[..4], &[1, 2, 0x11, 2]);
    assert_eq!(tags[20], 0x31);
    // The 21 AUDIO_FORMATs use every byte: 9 header bytes plus their sizes.
    let size: usize = formats.iter().map(|f| 18 + f.extra.len()).sum();
    assert_eq!(9 + size, msg.len());
}

#[test]
fn server_formats_answered_with_capturable_subset() {
    // MS-RDPEAI 4.1.3 to 4.1.5: Incoming Data PDU, then the client's
    // formats. Of the spec's list only PCM 44.1 kHz stereo 16-bit is one the
    // backend captures; cbSizeFormatsPacket is the whole PDU (27 bytes).
    let mut rig = Rig::new();
    let out = rig.feed(&hex(SPEC_SERVER_FORMATS));
    let spec = hex(SPEC_SERVER_FORMATS);
    let mut formats = vec![2, 1, 0, 0, 0, 27, 0, 0, 0];
    formats.extend_from_slice(&spec[9..27]);
    assert_eq!(out, vec![vec![5], formats]);
    assert_eq!(rig.ch.formats, vec![STEREO_44]);
}

#[test]
fn server_formats_skip_mismatched_and_duplicate_pcm() {
    let mut rig = Rig::new();
    let pcm = |ch: u16, rate: u32, avg: u32, align: u16| AudioFormat {
        tag: 1,
        channels: ch,
        samples_per_sec: rate,
        avg_bytes_per_sec: avg,
        block_align: align,
        bits_per_sample: 16,
        extra: vec![],
    };
    let list = [
        pcm(1, 48_000, 96_000, 2),
        pcm(2, 48_000, 96_000, 4), // inconsistent nAvgBytesPerSec
        pcm(1, 22_050, 44_100, 2), // not captured
        pcm(1, 48_000, 96_000, 2), // duplicate
    ];
    let mut msg = formats_pdu(&list);
    msg[5..9].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let out = rig.feed(&msg);
    assert_eq!(out[1], formats_pdu(&list[..1]));
    assert_eq!(rig.ch.formats, vec![MONO_48]);
}

#[test]
fn spec_open_parses() {
    let msg = hex(&[SPEC_OPEN]);
    let open = parse_open(&msg[1..]).unwrap();
    assert_eq!(open.frames_per_packet, 2205);
    assert_eq!(open.initial_format, 11);
    assert_eq!(open.capture.tag, 0xFFFE);
    assert_eq!(open.capture.channels, 2);
    assert_eq!(open.capture.samples_per_sec, 44_100);
    assert_eq!(open.capture.extra.len(), 22);
}

#[test]
fn spec_reply_pdus() {
    // MS-RDPEAI 4.1.7 Format Change, 4.1.8 Open Reply, 4.2.1 Incoming Data.
    assert_eq!(format_change(11), [7, 0x0b, 0, 0, 0]);
    assert_eq!(open_reply(S_OK), [4, 0, 0, 0, 0]);
    assert_eq!(incoming_data(), [5]);
    assert_eq!(data_pdu(&[0xd6, 0x38]), [6, 0xd6, 0x38]);
}

#[test]
fn open_confirms_format_then_replies_and_starts() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    rig.negotiate();
    // The spec's initialFormat 11 is beyond the one negotiated format: the
    // out-of-sequence Open is ignored (MS-RDPEAI 3.1.5).
    assert!(rig.feed(&hex(&[SPEC_OPEN])).is_empty());
    assert!(rig.events().is_empty());
    assert_eq!(
        rig.open(2205, 0),
        vec![vec![7, 0, 0, 0, 0], vec![4, 0, 0, 0, 0]]
    );
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2205)]);
}

#[test]
fn data_is_sent_in_packets_of_frames_per_packet() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    rig.negotiate();
    rig.open(4, 0); // 4 stereo 16-bit frames: 16 bytes per Data PDU.
    let audio: Vec<u8> = (0..48).collect();
    rig.queue(audio[..10].to_vec());
    rig.queue(audio[10..20].to_vec());
    rig.queue(audio[20..40].to_vec());
    let out = rig.tick();
    assert_eq!(out, [data(&audio[..16]), data(&audio[16..32])].concat());
    // 8 bytes wait for the rest of their packet.
    assert!(rig.tick().is_empty());
    rig.queue(audio[40..48].to_vec());
    assert_eq!(rig.tick(), data(&audio[32..48]));
}

#[test]
fn off_sends_nothing_and_keeps_the_channel() {
    let mut rig = Rig::new();
    rig.negotiate();
    // Open while off: success, but no device.
    assert_eq!(
        rig.open(2, 0),
        vec![vec![7, 0, 0, 0, 0], vec![4, 0, 0, 0, 0]]
    );
    rig.queue(vec![1; 8]);
    assert!(rig.tick().is_empty());
    assert!(rig.events().is_empty());
    assert_eq!(rig.script.lock().unwrap().reads, 0);
    // On: capture starts on the next tick and data flows.
    rig.handle.set_enabled(true);
    assert_eq!(rig.tick(), data(&[1; 8]));
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2)]);
    // Off again: the device closes, captured audio is not sent.
    rig.handle.set_enabled(false);
    rig.queue(vec![2; 8]);
    assert!(rig.tick().is_empty());
    assert_eq!(rig.events(), [Ev::Stop]);
    // The channel still answers the server.
    assert_eq!(rig.feed(&[7, 0, 0, 0, 0]), vec![vec![7, 0, 0, 0, 0]]);
}

#[test]
fn device_failure_replies_error_and_does_not_retry() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    rig.script.lock().unwrap().fail_start = true;
    rig.negotiate();
    let out = rig.open(2, 0);
    assert_eq!(out[1], open_reply(E_FAIL));
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2)]);
    rig.tick();
    rig.tick();
    assert!(rig.events().is_empty());
    // The server may send another Open PDU; it is tried again.
    rig.script.lock().unwrap().fail_start = false;
    assert_eq!(rig.open(2, 0)[1], open_reply(S_OK));
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2)]);
}

#[test]
fn failed_start_in_tick_waits_for_the_switch() {
    let mut rig = Rig::new();
    rig.negotiate();
    rig.open(2, 0);
    rig.script.lock().unwrap().fail_start = true;
    rig.handle.set_enabled(true);
    rig.tick();
    rig.tick();
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2)]);
    rig.handle.set_enabled(false);
    rig.tick();
    rig.handle.set_enabled(true);
    rig.tick();
    assert_eq!(rig.events(), [Ev::Start(STEREO_44, 2)]);
}

#[test]
fn format_change_confirms_and_restarts_capture() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    let list: Vec<AudioFormat> = [STEREO_44, MONO_48]
        .iter()
        .map(|f| AudioFormat {
            tag: 1,
            channels: f.channels,
            samples_per_sec: f.sample_rate,
            avg_bytes_per_sec: f.avg_bytes_per_sec(),
            block_align: f.block_align(),
            bits_per_sample: 16,
            extra: vec![],
        })
        .collect();
    rig.feed(&formats_pdu(&list));
    rig.open(4, 0);
    rig.queue(vec![9; 20]);
    assert_eq!(rig.tick(), data(&[9; 16]));
    rig.events();
    // MS-RDPEAI 4.3: the client confirms with the same PDU.
    assert_eq!(rig.feed(&[7, 1, 0, 0, 0]), vec![vec![7, 1, 0, 0, 0]]);
    assert_eq!(rig.events(), [Ev::Stop]);
    // Leftover audio of the old format is dropped; packets are now
    // 4 mono frames = 8 bytes.
    rig.queue(vec![3; 8]);
    assert_eq!(rig.tick(), data(&[3; 8]));
    assert_eq!(rig.events(), [Ev::Start(MONO_48, 4)]);
    // An index beyond the list is ignored.
    assert!(rig.feed(&[7, 2, 0, 0, 0]).is_empty());
}

#[test]
fn backlog_keeps_the_newest_packets() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    rig.negotiate();
    rig.open(1, 0); // 4 bytes per packet.
    let audio: Vec<u8> = (0..80).collect();
    rig.queue(audio.clone());
    let out = rig.tick();
    let want: Vec<Vec<u8>> = audio[48..].chunks(4).flat_map(data).collect();
    assert_eq!(out, want);
}

#[test]
fn close_stops_capture_and_forgets_the_negotiation() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    rig.negotiate();
    rig.open(2, 0);
    rig.events();
    rig.ch.closed();
    assert_eq!(rig.events(), [Ev::Stop]);
    rig.queue(vec![1; 8]);
    assert!(rig.tick().is_empty());
    assert!(rig.open(2, 0).is_empty());
}

#[test]
fn malformed_pdus_are_ignored() {
    let mut rig = Rig::new();
    rig.handle.set_enabled(true);
    for msg in [
        &[][..],
        &[1, 1, 0],
        &[2, 5, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        &[3, 1, 0, 0, 0],
        &[7],
        &[0x42, 1, 2, 3],
        &[MSG_SNDIN_DATA, 1, 2],
    ] {
        assert!(rig.feed(msg).is_empty(), "{msg:?}");
    }
    rig.negotiate();
    assert!(rig.open(0, 0).is_empty(), "FramesPerPacket 0");
    assert!(rig.open(MAX_FRAMES_PER_PACKET + 1, 0).is_empty());
    assert!(rig.events().is_empty());
}

#[test]
fn scripted_session_over_drdynvc() {
    let script = Arc::new(Mutex::new(Script::default()));
    let (ch, handle) = audin(Box::new(Mock(script.clone())));
    handle.set_enabled(true);
    let mut d = Drdynvc::new(vec![Box::new(ch)]);
    let mut out = ChannelOut::default();
    let mut feed = |d: &mut Drdynvc, msg: &[u8]| {
        d.process(msg, &mut out).unwrap();
        out.take()
    };
    let wrap = |msg: &[u8]| [&[0x30, 0x05][..], msg].concat();
    let mut create = vec![0x10, 0x05];
    create.extend_from_slice(b"AUDIO_INPUT\0");
    assert_eq!(feed(&mut d, &create), vec![vec![0x10, 0x05, 0, 0, 0, 0]]);
    assert_eq!(
        feed(&mut d, &wrap(&[1, 1, 0, 0, 0])),
        vec![wrap(&[1, 1, 0, 0, 0])]
    );
    let formats = hex(SPEC_SERVER_FORMATS);
    let out1 = feed(&mut d, &wrap(&formats));
    assert_eq!(out1.len(), 2);
    assert_eq!(out1[0], wrap(&[5]));
    let mut open = hex(&[SPEC_OPEN]);
    open[5] = 0; // initialFormat 0
    assert_eq!(
        feed(&mut d, &wrap(&open)),
        vec![wrap(&[7, 0, 0, 0, 0]), wrap(&[4, 0, 0, 0, 0])]
    );
    // One packet of 2205 stereo frames: 8820 bytes, fragmented by the DVC
    // layer into DATA_FIRST + DATA PDUs after the Incoming Data PDU.
    script.lock().unwrap().blocks.push_back(vec![0x11; 8820]);
    let mut tick_out = ChannelOut::default();
    d.tick(&mut tick_out).unwrap();
    let pdus = tick_out.take();
    assert_eq!(pdus[0], wrap(&[5]));
    assert_eq!(&pdus[1][..5], &[0x24, 0x05, 0x75, 0x22, MSG_SNDIN_DATA]);
    let body: usize = pdus[1..].iter().map(|p| p.len()).sum();
    // 8821 Data PDU bytes, plus headers: 4 for DATA_FIRST, 2 per DATA PDU.
    assert_eq!(body, 8821 + 4 + 2 * (pdus.len() - 2));
    assert_eq!(script.lock().unwrap().events, [Ev::Start(STEREO_44, 2205)]);
    // Server closes the channel: capture stops.
    assert_eq!(feed(&mut d, &[0x40, 0x05]), vec![vec![0x40, 0x05]]);
    assert_eq!(
        script.lock().unwrap().events,
        [Ev::Start(STEREO_44, 2205), Ev::Stop]
    );
}
