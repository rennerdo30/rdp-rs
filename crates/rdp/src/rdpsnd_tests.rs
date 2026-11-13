//! Tests for the `rdpsnd` channel, with MS-RDPEA section 4 example bytes
//! where the spec has them. No audio device is opened: a mock backend
//! records every call.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Open(PcmFormat),
    Write(Vec<u8>),
    Close,
}

/// Records calls; each write advances the shared fake clock by `write_ms`.
struct Mock {
    log: Arc<Mutex<Vec<Ev>>>,
    now_ms: Arc<AtomicU64>,
    write_ms: u64,
    fail_open: bool,
}

impl AudioBackend for Mock {
    fn open(&mut self, format: &PcmFormat) -> std::result::Result<(), String> {
        self.log.lock().unwrap().push(Ev::Open(*format));
        if self.fail_open {
            Err("no device".into())
        } else {
            Ok(())
        }
    }
    fn write(&mut self, samples: &[u8]) -> std::result::Result<(), String> {
        self.log.lock().unwrap().push(Ev::Write(samples.to_vec()));
        self.now_ms.fetch_add(self.write_ms, Ordering::Relaxed);
        Ok(())
    }
    fn close(&mut self) {
        self.log.lock().unwrap().push(Ev::Close);
    }
}

struct Rig {
    ch: Rdpsnd,
    handle: AudioHandle,
    log: Arc<Mutex<Vec<Ev>>>,
}

impl Rig {
    fn events(&self) -> Vec<Ev> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    fn feed(&mut self, msg: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = ChannelOut::default();
        self.ch.process(msg, &mut out)?;
        Ok(out.take())
    }

    fn tick(&mut self) {
        let mut out = ChannelOut::default();
        self.ch.tick(&mut out).unwrap();
        assert!(out.is_empty());
    }
}

fn rig_with(write_ms: u64, fail_open: bool) -> Rig {
    let log = Arc::new(Mutex::new(Vec::new()));
    let now_ms = Arc::new(AtomicU64::new(0));
    let (mut ch, handle) = rdpsnd(Box::new(Mock {
        log: log.clone(),
        now_ms: now_ms.clone(),
        write_ms,
        fail_open,
    }));
    let base = Instant::now();
    ch.clock = Arc::new(move || base + Duration::from_millis(now_ms.load(Ordering::Relaxed)));
    Rig { ch, handle, log }
}

fn rig() -> Rig {
    rig_with(0, false)
}

const STEREO_48K: PcmFormat = PcmFormat {
    channels: 2,
    sample_rate: 48_000,
    bits: 16,
};

/// MS-RDPEA 4.1.1: Server Audio Formats and Version PDU (version 5; PCM
/// 22.05 kHz, A-law, mu-law, MS ADPCM with 32 extra bytes, IMA ADPCM).
const SPEC_SERVER_FORMATS: &[u8] = &[
    0x07, 0x2b, 0x90, 0x00, 0x08, 0xfb, 0x8b, 0x00, 0xe0, 0xf1, 0x09, 0x00, 0x70, 0x27, 0x1f, 0x77,
    0x00, 0x00, 0x05, 0x00, 0xff, 0x05, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x22, 0x56, 0x00, 0x00,
    0x88, 0x58, 0x01, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x22, 0x56,
    0x00, 0x00, 0x44, 0xac, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00,
    0x22, 0x56, 0x00, 0x00, 0x44, 0xac, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x22, 0x56, 0x00, 0x00, 0x27, 0x57, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x20, 0x00,
    0xf4, 0x03, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x40, 0x00, 0xf0, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x30, 0xff, 0x88, 0x01, 0x18, 0xff,
    0x11, 0x00, 0x02, 0x00, 0x22, 0x56, 0x00, 0x00, 0xb9, 0x56, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00,
    0x02, 0x00, 0xf9, 0x03,
];

/// AUDIO_FORMAT bytes for a PCM format (MS-RDPEA 2.2.2.1.1).
fn pcm_entry(f: PcmFormat) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(WAVE_FORMAT_PCM);
    v.put_u16(f.channels);
    v.put_u32(f.sample_rate);
    v.put_u32(f.avg_bytes_per_sec());
    v.put_u16(f.block_align());
    v.put_u16(f.bits);
    v.put_u16(0);
    v
}

/// A Server Audio Formats and Version PDU with raw AUDIO_FORMAT entries.
fn server_formats_pdu(version: u16, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_zeros(14);
    b.put_u16(entries.len() as u16);
    b.put_u8(0);
    b.put_u16(version);
    b.put_u8(0);
    for e in entries {
        b.put_bytes(e);
    }
    pdu(SNDC_FORMATS, &b)
}

/// Negotiates version 8 with 48 kHz stereo as format 0 and 44.1 kHz mono as 1.
fn negotiated(r: &mut Rig) {
    let mono_44 = PcmFormat {
        channels: 1,
        sample_rate: 44_100,
        bits: 16,
    };
    r.feed(&server_formats_pdu(
        8,
        &[pcm_entry(STEREO_48K), pcm_entry(mono_44)],
    ))
    .unwrap();
}

fn wave2_pdu(timestamp: u16, format_no: u16, block_no: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(timestamp);
    b.put_u16(format_no);
    b.put_u8(block_no);
    b.put_zeros(3);
    b.put_u32(0x1234_5678);
    b.put_bytes(data);
    pdu(SNDC_WAVE2, &b)
}

#[test]
fn starts_off() {
    let r = rig();
    assert!(!r.handle.enabled());
    assert_eq!(r.ch.name(), "rdpsnd");
}

#[test]
fn spec_server_formats_parse() {
    let s = parse_server_formats(&SPEC_SERVER_FORMATS[4..]).unwrap();
    assert_eq!(s.version, 5);
    assert_eq!(s.last_block_confirmed, 0xff);
    let tags: Vec<u16> = s.formats.iter().map(|f| f.tag).collect();
    assert_eq!(tags, [1, 6, 7, 2, 0x11]);
    assert_eq!(s.formats[0].samples_per_sec, 22_050);
    assert_eq!(s.formats[0].avg_bytes_per_sec, 88_200);
    assert_eq!(s.formats[3].extra.len(), 32);
    assert_eq!(s.formats[4].extra, [0xf9, 0x03]);
}

/// MS-RDPEA 4.1.2 with the trailing bPad (0x7c in the example, arbitrary by
/// 2.2.2.2) sent as 0: the writer reproduces the example's format list.
#[test]
fn spec_client_formats_bytes() {
    let s = parse_server_formats(&SPEC_SERVER_FORMATS[4..]).unwrap();
    let got = client_formats(0x3, 0xffff_ffff, 0x00f9_f700, 0x28, 5, &s.formats);
    let mut want = SPEC_SERVER_FORMATS.to_vec();
    want[..24].copy_from_slice(&[
        0x07, 0x00, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0xf7, 0xf9,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x28, 0x05, 0x00, 0x00,
    ]);
    assert_eq!(got, want);
}

/// The spec's server offers only 22.05 kHz PCM and codecs: the client
/// answers version 8, ALIVE, no formats, and no Quality Mode (server v5).
#[test]
fn spec_server_formats_get_empty_client_list() {
    let mut r = rig();
    let out = r.feed(SPEC_SERVER_FORMATS).unwrap();
    assert_eq!(
        out,
        vec![vec![
            0x07, 0x00, 0x14, 0x00, // header, BodySize 20
            0x01, 0x00, 0x00, 0x00, // dwFlags TSSNDCAPS_ALIVE
            0, 0, 0, 0, 0, 0, 0, 0, // dwVolume, dwPitch
            0x00, 0x00, // wDGramPort
            0x00, 0x00, // wNumberOfFormats
            0x00, // cLastBlockConfirmed
            0x08, 0x00, // wVersion 8
            0x00, // bPad
        ]]
    );
}

#[test]
fn negotiation_keeps_supported_pcm_in_server_order_and_sends_quality_mode() {
    let mut r = rig();
    let pcm_22k = &SPEC_SERVER_FORMATS[24..42];
    let mono_44 = PcmFormat {
        channels: 1,
        sample_rate: 44_100,
        bits: 16,
    };
    // 8-bit, inconsistent-avg and non-PCM (same layout, A-law tag)
    // variants must be refused.
    let pcm8 = pcm_entry(PcmFormat {
        channels: 2,
        sample_rate: 48_000,
        bits: 8,
    });
    let mut bad_avg = pcm_entry(STEREO_48K);
    bad_avg[8] ^= 1;
    let mut alaw = pcm_entry(STEREO_48K);
    alaw[0] = 0x06;
    let entries = vec![
        pcm_22k.to_vec(),
        pcm_entry(mono_44),
        pcm8,
        bad_avg,
        alaw,
        pcm_entry(STEREO_48K),
    ];
    let out = r.feed(&server_formats_pdu(8, &entries)).unwrap();
    assert_eq!(out.len(), 2);
    let mut want = client_formats(TSSNDCAPS_ALIVE, 0, 0, 0, 8, &[]);
    want[2] = 20 + 36;
    want[18] = 2;
    want.extend_from_slice(&pcm_entry(mono_44));
    want.extend_from_slice(&pcm_entry(STEREO_48K));
    assert_eq!(out[0], want);
    // Quality Mode PDU, HIGH_QUALITY (MS-RDPEA 2.2.2.3).
    assert_eq!(out[1], [0x0c, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00]);
    assert_eq!(r.ch.formats, [mono_44, STEREO_48K]);
}

/// MS-RDPEA 4.1.3 / 4.1.4 (data elided in the spec; filled with a pattern).
#[test]
fn spec_training_confirm() {
    let mut r = rig();
    let mut training = vec![0x06, 0x23, 0xfc, 0x03, 0xda, 0x89, 0x00, 0x04];
    training.extend((0..1016u32).map(|i| (i * 7) as u8));
    assert_eq!(training.len(), 1024);
    let out = r.feed(&training).unwrap();
    // 4.1.4 has bPad 0x55 (arbitrary); the client sends 0.
    assert_eq!(
        out,
        vec![vec![0x06, 0x00, 0x04, 0x00, 0xda, 0x89, 0x00, 0x04]]
    );
    assert!(r.events().is_empty());
}

/// MS-RDPEA 4.2.3 with bPad sent as 0.
#[test]
fn spec_wave_confirm_bytes() {
    assert_eq!(
        wave_confirm(0x5ab7, 8),
        [0x05, 0x00, 0x04, 0x00, 0xb7, 0x5a, 0x08, 0x00]
    );
}

/// MS-RDPEA 4.2.1 WaveInfo + 4.2.2 Wave (data partly elided in the spec).
fn spec_wave_info_and_wave() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let info = vec![
        0x02, 0x7e, 0x51, 0x02, 0xd7, 0xad, 0x0f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x48, 0x17,
        0xd6,
    ];
    // BodySize 593 = 12 + 581 Wave data bytes; audio is 585 bytes.
    let mut rest = vec![0x84, 0x02, 0x80, 0x24, 0x49, 0x92, 0x24, 0x89];
    rest.extend((0..573u32).map(|i| (i * 13 + 5) as u8));
    let mut wave = vec![0, 0, 0, 0];
    wave.extend_from_slice(&rest);
    let mut sample = vec![0x20, 0x48, 0x17, 0xd6];
    sample.extend_from_slice(&rest);
    assert_eq!(sample.len(), 585);
    (info, wave, sample)
}

/// The spec's WaveInfo uses format #15: give the client 16 formats.
fn sixteen_formats(r: &mut Rig) {
    r.ch.formats = vec![STEREO_48K; 16];
}

#[test]
fn spec_wave_info_and_wave_reassemble_when_on() {
    let mut r = rig();
    sixteen_formats(&mut r);
    r.handle.set_enabled(true);
    let (info, wave, sample) = spec_wave_info_and_wave();
    assert!(r.feed(&info).unwrap().is_empty());
    assert!(r.events().is_empty());
    let out = r.feed(&wave).unwrap();
    assert_eq!(
        out,
        vec![vec![0x05, 0x00, 0x04, 0x00, 0xd7, 0xad, 0x08, 0x00]]
    );
    assert_eq!(r.events(), [Ev::Open(STEREO_48K), Ev::Write(sample)]);
}

/// The confirm timestamp adds the time from receipt to confirm
/// (MS-RDPEA 3.2.5.2.1.6); here the backend write takes 5 ms.
#[test]
fn wave_confirm_adds_handling_time() {
    let mut r = rig_with(5, false);
    sixteen_formats(&mut r);
    r.handle.set_enabled(true);
    let (info, wave, _) = spec_wave_info_and_wave();
    r.feed(&info).unwrap();
    let out = r.feed(&wave).unwrap();
    assert_eq!(out, vec![wave_confirm(0xaddc, 8)]);
    // Timestamps wrap at 16 bits.
    let out = r.feed(&wave2_pdu(0xfffe, 0, 9, &[1, 2, 3, 4])).unwrap();
    assert_eq!(out, vec![wave_confirm(0x0003, 9)]);
}

/// MS-RDPEA 4.2.4 Wave2 (data partly elided in the spec).
#[test]
fn spec_wave2_plays_and_confirms() {
    let mut r = rig();
    sixteen_formats(&mut r);
    r.ch.formats[3] = PcmFormat {
        channels: 1,
        sample_rate: 44_100,
        bits: 16,
    };
    r.handle.set_enabled(true);
    let mut msg = vec![
        0x0d, 0x00, 0x04, 0x01, 0x16, 0xa1, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc2, 0xb8, 0xac,
        0x0d,
    ];
    let mut data = vec![0x27, 0x0c, 0x45, 0x83];
    data.extend((0..244u32).map(|i| (i * 3) as u8));
    msg.extend_from_slice(&data);
    assert_eq!(msg.len(), 4 + 260);
    let out = r.feed(&msg).unwrap();
    assert_eq!(
        out,
        vec![vec![0x05, 0x00, 0x04, 0x00, 0x16, 0xa1, 0x02, 0x00]]
    );
    assert_eq!(r.events(), [Ev::Open(r.ch.formats[3]), Ev::Write(data)]);
}

#[test]
fn off_drops_samples_but_confirms() {
    let mut r = rig();
    negotiated(&mut r);
    let out = r.feed(&wave2_pdu(100, 0, 1, &[9; 16])).unwrap();
    assert_eq!(out, vec![wave_confirm(100, 1)]);
    let (info, wave, _) = spec_wave_info_and_wave();
    let mut info = info;
    info[6] = 1; // format #1
    r.feed(&info).unwrap();
    assert_eq!(r.feed(&wave).unwrap(), vec![wave_confirm(0xadd7, 8)]);
    assert!(r.events().is_empty());
}

#[test]
fn switching_on_and_off_mid_stream() {
    let mut r = rig();
    negotiated(&mut r);
    r.feed(&wave2_pdu(1, 0, 1, &[1; 8])).unwrap();
    assert!(r.events().is_empty());
    r.handle.set_enabled(true);
    let out = r.feed(&wave2_pdu(2, 0, 2, &[2; 8])).unwrap();
    assert_eq!(out, vec![wave_confirm(2, 2)]);
    assert_eq!(r.events(), [Ev::Open(STEREO_48K), Ev::Write(vec![2; 8])]);
    // Same format: no reopen.
    r.feed(&wave2_pdu(3, 0, 3, &[3; 8])).unwrap();
    assert_eq!(r.events(), [Ev::Write(vec![3; 8])]);
    // Format change: close, reopen.
    r.feed(&wave2_pdu(4, 1, 4, &[4; 8])).unwrap();
    assert_eq!(
        r.events(),
        [Ev::Close, Ev::Open(r.ch.formats[1]), Ev::Write(vec![4; 8])]
    );
    // Off: the next poll releases the device; waves are still confirmed.
    r.handle.set_enabled(false);
    r.tick();
    assert_eq!(r.events(), [Ev::Close]);
    r.tick();
    assert!(r.events().is_empty());
    assert_eq!(
        r.feed(&wave2_pdu(5, 0, 5, &[5; 8])).unwrap(),
        vec![wave_confirm(5, 5)]
    );
    assert!(r.events().is_empty());
}

#[test]
fn open_failure_drops_audio_but_confirms() {
    let mut r = rig_with(0, true);
    negotiated(&mut r);
    r.handle.set_enabled(true);
    let out = r.feed(&wave2_pdu(7, 0, 7, &[7; 8])).unwrap();
    assert_eq!(out, vec![wave_confirm(7, 7)]);
    assert_eq!(r.events(), [Ev::Open(STEREO_48K)]);
    // Retried with the next wave.
    r.feed(&wave2_pdu(8, 0, 8, &[8; 8])).unwrap();
    assert_eq!(r.events(), [Ev::Open(STEREO_48K)]);
}

#[test]
fn close_pdu_stops_backend() {
    let mut r = rig();
    negotiated(&mut r);
    r.handle.set_enabled(true);
    r.feed(&wave2_pdu(1, 0, 1, &[1; 8])).unwrap();
    r.events();
    assert!(r.feed(&[0x01, 0x00, 0x00, 0x00]).unwrap().is_empty());
    assert_eq!(r.events(), [Ev::Close]);
    // A second Close has nothing to stop.
    r.feed(&[0x01, 0x00, 0x00, 0x00]).unwrap();
    assert!(r.events().is_empty());
}

#[test]
fn new_server_formats_restart_the_protocol() {
    let mut r = rig();
    negotiated(&mut r);
    r.handle.set_enabled(true);
    r.feed(&wave2_pdu(1, 0, 1, &[1; 8])).unwrap();
    r.events();
    let out = r.feed(SPEC_SERVER_FORMATS).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(r.events(), [Ev::Close]);
    assert!(r.ch.formats.is_empty());
    // Format 0 no longer exists.
    assert!(r.feed(&wave2_pdu(2, 0, 2, &[2; 8])).is_err());
}

#[test]
fn volume_and_pitch_are_ignored() {
    let mut r = rig();
    negotiated(&mut r);
    r.handle.set_enabled(true);
    for t in [SNDC_SETVOLUME, SNDC_SETPITCH] {
        let out = r.feed(&pdu(t, &[0xff, 0xff, 0x00, 0x80])).unwrap();
        assert!(out.is_empty());
    }
    // UDP-only and unknown PDUs too.
    r.feed(&pdu(SNDC_CRYPTKEY, &[0; 36])).unwrap();
    r.feed(&pdu(0x7f, &[1, 2])).unwrap();
    assert!(r.events().is_empty());
}

#[test]
fn malformed_pdus_are_errors() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short header", vec![0x07, 0x00, 0x10]),
        (
            "BodySize beyond data",
            vec![0x06, 0x00, 0x08, 0x00, 1, 2, 3, 4],
        ),
        ("training short", pdu(SNDC_TRAINING, &[1, 2])),
        ("volume short", pdu(SNDC_SETVOLUME, &[1, 2])),
        ("formats short", pdu(SNDC_FORMATS, &[0; 10])),
        ("format count too large", {
            let mut p = server_formats_pdu(8, &[pcm_entry(STEREO_48K)]);
            p[18] = 0xff;
            p[19] = 0xff;
            p
        }),
        ("format extra beyond data", {
            let mut e = pcm_entry(STEREO_48K);
            e[16] = 4;
            server_formats_pdu(8, &[e])
        }),
        ("wave info BodySize below 12", {
            let mut p = spec_wave_info_and_wave().0;
            p[2] = 11;
            p[3] = 0;
            p
        }),
        (
            "wave info truncated",
            spec_wave_info_and_wave().0[..12].to_vec(),
        ),
        ("wave2 short", pdu(SNDC_WAVE2, &[0; 11])),
        ("wave2 unknown format", wave2_pdu(1, 2, 1, &[0; 4])),
    ];
    for (name, msg) in cases {
        let mut r = rig();
        negotiated(&mut r);
        r.handle.set_enabled(true);
        assert!(r.feed(&msg).is_err(), "{name} accepted");
        assert!(r.events().is_empty(), "{name} reached the backend");
    }
}

#[test]
fn wave_shorter_than_announced_is_an_error() {
    let mut r = rig();
    sixteen_formats(&mut r);
    r.handle.set_enabled(true);
    let (info, wave, _) = spec_wave_info_and_wave();
    r.feed(&info).unwrap();
    assert!(r.feed(&wave[..wave.len() - 1]).is_err());
    assert!(r.events().is_empty());
    // An unknown format in the WaveInfo fails when the Wave completes it.
    let mut r = rig();
    negotiated(&mut r);
    r.feed(&info).unwrap();
    assert!(r.feed(&wave).is_err());
}

/// Every prefix of every valid PDU parses or fails cleanly, never panics.
#[test]
fn truncated_pdus_never_panic() {
    let (info, wave, _) = spec_wave_info_and_wave();
    let pdus = [
        SPEC_SERVER_FORMATS.to_vec(),
        wave2_pdu(1, 0, 1, &[0; 8]),
        training_confirm(1, 2),
        info.clone(),
    ];
    for p in &pdus {
        for n in 0..=p.len() {
            let mut r = rig();
            negotiated(&mut r);
            r.handle.set_enabled(true);
            let _ = r.feed(&p[..n]);
        }
    }
    for n in 0..=wave.len() {
        let mut r = rig();
        sixteen_formats(&mut r);
        r.feed(&info).unwrap();
        let _ = r.feed(&wave[..n]);
    }
}
