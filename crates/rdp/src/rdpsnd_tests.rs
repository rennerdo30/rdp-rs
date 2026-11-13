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
    Dec(Dec),
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
pub(crate) const SPEC_SERVER_FORMATS: &[u8] = &[
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

/// A negotiated PCM entry of the client's format list.
fn pcm_slot(f: PcmFormat) -> (AudioFormat, Codec) {
    let bytes = pcm_entry(f);
    let mut r = Reader::new(&bytes);
    (AudioFormat::parse(&mut r).unwrap(), Codec::Pcm(f))
}

/// The PCM formats of the client's format list.
fn pcm_list(r: &Rig) -> Vec<PcmFormat> {
    let pcm = |c: &Codec| match c {
        Codec::Pcm(p) => *p,
        _ => panic!("not PCM: {c:?}"),
    };
    r.ch.formats.iter().map(|(_, c)| pcm(c)).collect()
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
    assert_eq!(pcm_list(&r), [mono_44, STEREO_48K]);
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
    r.ch.formats = vec![pcm_slot(STEREO_48K); 16];
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
    r.ch.formats[3] = pcm_slot(PcmFormat {
        channels: 1,
        sample_rate: 44_100,
        bits: 16,
    });
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
    assert_eq!(r.events(), [Ev::Open(pcm_list(&r)[3]), Ev::Write(data)]);
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
        [Ev::Close, Ev::Open(pcm_list(&r)[1]), Ev::Write(vec![4; 8])]
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

// Compressed formats: ADPCM in the library, others through an AudioDecoder.

use super::codec::{
    WAVE_FORMAT_AAC_MS, WAVE_FORMAT_ADPCM, WAVE_FORMAT_DVI_ADPCM, WAVE_FORMAT_MPEGLAYER3,
};

/// Decodes by mapping each input byte b to the 16-bit sample b * 2 (so
/// the output is checkable), after `latency` waves of no output. Takes
/// MP3 and AAC; records its calls in the rig's log.
struct FakeDecoder {
    log: Arc<Mutex<Vec<Ev>>>,
    latency: usize,
    fail: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Dec {
    Open(u16, u32),
    Close,
}

impl AudioDecoder for FakeDecoder {
    fn accepts(&self, f: &AudioFormat) -> bool {
        matches!(f.tag, WAVE_FORMAT_MPEGLAYER3 | WAVE_FORMAT_AAC_MS)
    }
    fn open(&mut self, f: &AudioFormat) -> std::result::Result<PcmFormat, String> {
        self.log
            .lock()
            .unwrap()
            .push(Ev::Dec(Dec::Open(f.tag, f.avg_bytes_per_sec)));
        Ok(PcmFormat {
            channels: f.channels,
            sample_rate: f.samples_per_sec,
            bits: 16,
        })
    }
    fn decode(&mut self, data: &[u8], pcm: &mut Vec<u8>) -> std::result::Result<(), String> {
        if self.fail {
            return Err("corrupt frame".into());
        }
        if self.latency > 0 {
            self.latency -= 1;
            return Ok(());
        }
        for &b in data {
            pcm.extend_from_slice(&(u16::from(b) * 2).to_le_bytes());
        }
        Ok(())
    }
    fn close(&mut self) {
        self.log.lock().unwrap().push(Ev::Dec(Dec::Close));
    }
}

/// A rig with ADPCM on or off and an optional fake decoder (latency, fail).
fn codec_rig(adpcm: bool, decoder: Option<(usize, bool)>) -> Rig {
    let log = Arc::new(Mutex::new(Vec::new()));
    let decoder = decoder.map(|(latency, fail)| {
        Box::new(FakeDecoder {
            log: log.clone(),
            latency,
            fail,
        }) as Box<dyn AudioDecoder>
    });
    let (mut ch, handle) = rdpsnd_with(
        Box::new(Mock {
            log: log.clone(),
            now_ms: Arc::new(AtomicU64::new(0)),
            write_ms: 0,
            fail_open: false,
        }),
        AudioCodecs { adpcm, decoder },
    );
    let base = Instant::now();
    ch.clock = Arc::new(move || base);
    Rig { ch, handle, log }
}

/// An AUDIO_FORMAT entry, 44.1 kHz stereo, with the given fields.
fn entry(tag: u16, avg: u32, block_align: u16, bits: u16, extra: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u16(tag);
    v.put_u16(2);
    v.put_u32(44_100);
    v.put_u32(avg);
    v.put_u16(block_align);
    v.put_u16(bits);
    v.put_u16(extra.len() as u16);
    v.put_bytes(extra);
    v
}

/// The MS-RDPEA 4.1.1 MS ADPCM entry: 22.05 kHz stereo, nBlockAlign 1024.
fn ms_adpcm_entry() -> Vec<u8> {
    SPEC_SERVER_FORMATS[78..128].to_vec()
}

/// The MS-RDPEA 4.1.1 IMA ADPCM entry: 22.05 kHz stereo, nBlockAlign 1024.
fn ima_entry() -> Vec<u8> {
    SPEC_SERVER_FORMATS[128..].to_vec()
}

/// With ADPCM on, the MS-RDPEA 4.1.1 server list (PCM 22.05 kHz, A-law,
/// mu-law, MS ADPCM, IMA ADPCM) yields both ADPCM entries, byte-exact,
/// and (the spec's server is version 5, so only from a version 8 server)
/// a Quality Mode PDU asking for DYNAMIC_QUALITY.
#[test]
fn spec_server_formats_with_adpcm() {
    assert_eq!(ms_adpcm_entry()[..2], [0x02, 0x00]);
    assert_eq!(ima_entry()[..2], [0x11, 0x00]);
    let mut r = codec_rig(true, None);
    let out = r.feed(SPEC_SERVER_FORMATS).unwrap();
    let mut want = client_formats(TSSNDCAPS_ALIVE, 0, 0, 0, 8, &[]);
    want[2] = (20 + 50 + 20) as u8;
    want[18] = 2;
    want.extend(ms_adpcm_entry());
    want.extend(ima_entry());
    assert_eq!(out, vec![want.clone()]);
    let mut v8 = SPEC_SERVER_FORMATS.to_vec();
    v8[21] = 8;
    let out = r.feed(&v8).unwrap();
    assert_eq!(out, vec![want, quality_mode(DYNAMIC_QUALITY)]);
    assert!(matches!(r.ch.formats[0].1, Codec::MsAdpcm(_)));
    assert!(matches!(r.ch.formats[1].1, Codec::ImaAdpcm(_)));
}

/// The client lists AAC (the 12 kB/s entry first), MP3, MS ADPCM,
/// IMA ADPCM, then PCM, whatever the server's order; formats nobody
/// decodes are left out; wFormatNo then indexes the client's list.
#[test]
fn negotiation_offers_best_first_and_selects_by_index() {
    let mut r = codec_rig(true, Some((0, false)));
    let pcm = pcm_entry(STEREO_48K);
    let aac_hi = entry(WAVE_FORMAT_AAC_MS, 24_000, 4, 16, &[]);
    let aac = entry(WAVE_FORMAT_AAC_MS, 12_000, 4, 16, &[]);
    let mp3_extra = [1, 0, 2, 0, 0, 0, 0x80, 1, 1, 0, 0x71, 5];
    let mp3 = entry(WAVE_FORMAT_MPEGLAYER3, 16_000, 1, 0, &mp3_extra);
    let gsm = entry(0x0031, 8_000, 65, 0, &[64, 1]);
    let server = [
        pcm.clone(),
        ima_entry(),
        mp3.clone(),
        aac_hi.clone(),
        gsm,
        ms_adpcm_entry(),
        aac.clone(),
    ];
    let out = r.feed(&server_formats_pdu(8, &server)).unwrap();
    let list = parse_server_formats(&out[0][4..]).unwrap();
    let tags: Vec<u16> = list.formats.iter().map(|f| f.tag).collect();
    assert_eq!(
        tags,
        [
            WAVE_FORMAT_AAC_MS,
            WAVE_FORMAT_AAC_MS,
            WAVE_FORMAT_MPEGLAYER3,
            WAVE_FORMAT_ADPCM,
            WAVE_FORMAT_DVI_ADPCM,
            WAVE_FORMAT_PCM,
        ]
    );
    // Each entry is the server's, byte-exact.
    let body = &out[0][4 + 20..];
    let want = [aac, aac_hi, mp3, ms_adpcm_entry(), ima_entry(), pcm].concat();
    assert_eq!(body, &want[..]);
    assert_eq!(out[1], quality_mode(DYNAMIC_QUALITY));
    // Format 2 is the MP3 entry: the decoder opens for it, its PCM plays.
    r.handle.set_enabled(true);
    let out = r.feed(&wave2_pdu(10, 2, 1, &[1, 2])).unwrap();
    assert_eq!(out, vec![wave_confirm(10, 1)]);
    let mp3_pcm = PcmFormat {
        channels: 2,
        sample_rate: 44_100,
        bits: 16,
    };
    assert_eq!(
        r.events(),
        [
            Ev::Dec(Dec::Open(WAVE_FORMAT_MPEGLAYER3, 16_000)),
            Ev::Open(mp3_pcm),
            Ev::Write(vec![2, 0, 4, 0]),
        ]
    );
    // Format 5 is PCM: decoder and device close, PCM plays as is.
    r.feed(&wave2_pdu(11, 5, 2, &[7; 4])).unwrap();
    assert_eq!(
        r.events(),
        [
            Ev::Close,
            Ev::Dec(Dec::Close),
            Ev::Open(STEREO_48K),
            Ev::Write(vec![7; 4]),
        ]
    );
    // Format 0 is the 12 kB/s AAC entry.
    r.feed(&wave2_pdu(12, 0, 3, &[0])).unwrap();
    assert_eq!(
        r.events()[1],
        Ev::Dec(Dec::Open(WAVE_FORMAT_AAC_MS, 12_000))
    );
}

/// PCM-only lists keep HIGH_QUALITY; without ADPCM or a decoder the
/// compressed entries are not offered.
#[test]
fn pcm_only_keeps_high_quality() {
    let mut r = codec_rig(false, None);
    let server = [ms_adpcm_entry(), pcm_entry(STEREO_48K), ima_entry()];
    let out = r.feed(&server_formats_pdu(8, &server)).unwrap();
    assert_eq!(out[0][18], 1);
    assert_eq!(out[1], quality_mode(HIGH_QUALITY));
}

/// A WaveInfo + Wave pair carrying two MS-ADPCM blocks of 1024 bytes
/// (the spec's format) plays as 2 x 1012 stereo sample frames.
#[test]
fn ms_adpcm_wave_pdus_decode_whole_blocks() {
    let mut r = codec_rig(true, None);
    r.feed(&server_formats_pdu(8, &[ms_adpcm_entry()])).unwrap();
    r.handle.set_enabled(true);
    // Block: predictors 0/0, deltas 16, iSamp1 300/-300, iSamp2 0, nibbles 0.
    let mut block = vec![0, 0, 16, 0, 16, 0];
    block.extend(300i16.to_le_bytes());
    block.extend((-300i16).to_le_bytes());
    block.extend([0; 4]);
    block.resize(1024, 0);
    let audio = [block.clone(), block].concat();
    let mut msg = vec![SNDC_WAVE, 0];
    msg.put_u16((8 + audio.len()) as u16);
    msg.put_u16(0x1111);
    msg.put_u16(0);
    msg.put_u8(3);
    msg.put_zeros(3);
    msg.put_bytes(&audio[..4]);
    assert!(r.feed(&msg).unwrap().is_empty());
    let mut wave = vec![0; 4];
    wave.extend_from_slice(&audio[4..]);
    assert_eq!(r.feed(&wave).unwrap(), vec![wave_confirm(0x1111, 3)]);
    let ev = r.events();
    assert_eq!(ev.len(), 2);
    assert_eq!(
        ev[0],
        Ev::Open(PcmFormat {
            channels: 2,
            sample_rate: 22_050,
            bits: 16,
        })
    );
    let Ev::Write(pcm) = &ev[1] else {
        panic!("{ev:?}")
    };
    assert_eq!(pcm.len(), 2 * 1012 * 4);
    let s: Vec<i16> = pcm
        .chunks(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    // iSamp2 pair, iSamp1 pair, then the predictor (256, 0) holds 300/-300.
    assert_eq!(s[..6], [0, 0, 300, -300, 300, -300]);
    assert_eq!(s[2024..2028], [0, 0, 300, -300]);
}

/// IMA ADPCM through Wave2: the header samples come first.
#[test]
fn ima_adpcm_wave2_plays() {
    let mut r = codec_rig(true, None);
    r.feed(&server_formats_pdu(8, &[ima_entry()])).unwrap();
    r.handle.set_enabled(true);
    let mut block = vec![0u8; 1024];
    block[0..2].copy_from_slice(&1234i16.to_le_bytes());
    block[4..6].copy_from_slice(&(-1234i16).to_le_bytes());
    r.feed(&wave2_pdu(1, 0, 1, &block)).unwrap();
    let ev = r.events();
    let Ev::Write(pcm) = &ev[1] else {
        panic!("{ev:?}")
    };
    assert_eq!(pcm.len(), 1017 * 4);
    assert_eq!(pcm[..8], [0xd2, 0x04, 0x2e, 0xfb, 0xd2, 0x04, 0x2e, 0xfb]);
}

/// A decoder with latency writes nothing until it has output; a decode
/// error drops that wave; every wave is still confirmed; a Close PDU
/// closes the decoder too.
#[test]
fn decoder_latency_errors_and_close() {
    let mp3 = entry(WAVE_FORMAT_MPEGLAYER3, 16_000, 1, 0, &[]);
    let mut r = codec_rig(false, Some((1, false)));
    r.feed(&server_formats_pdu(8, std::slice::from_ref(&mp3)))
        .unwrap();
    r.handle.set_enabled(true);
    assert_eq!(
        r.feed(&wave2_pdu(1, 0, 1, &[5])).unwrap(),
        vec![wave_confirm(1, 1)]
    );
    assert_eq!(r.events().len(), 2, "decoder and device open, no write");
    r.feed(&wave2_pdu(2, 0, 2, &[6])).unwrap();
    assert_eq!(r.events(), [Ev::Write(vec![12, 0])]);
    r.feed(&[0x01, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(r.events(), [Ev::Close, Ev::Dec(Dec::Close)]);

    let mut r = codec_rig(false, Some((0, true)));
    r.feed(&server_formats_pdu(8, &[mp3])).unwrap();
    r.handle.set_enabled(true);
    assert_eq!(
        r.feed(&wave2_pdu(3, 0, 3, &[5])).unwrap(),
        vec![wave_confirm(3, 3)]
    );
    let ev = r.events();
    assert!(!ev.iter().any(|e| matches!(e, Ev::Write(_))), "{ev:?}");
}
