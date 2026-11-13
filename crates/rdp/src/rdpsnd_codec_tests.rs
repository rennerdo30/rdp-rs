//! ADPCM decoder tests against hand-computed samples (worked through the
//! step and adaptation tables by hand, see each test) and the MS-RDPEA 4.1.1
//! example formats.

use super::*;

fn samples(pcm: &[u8]) -> Vec<i16> {
    pcm.as_chunks::<2>()
        .0
        .iter()
        .map(|&b| i16::from_le_bytes(b))
        .collect()
}

fn format(tag: u16, channels: u16, block_align: u16, extra: Vec<u8>) -> AudioFormat {
    AudioFormat {
        tag,
        channels,
        samples_per_sec: 22_050,
        avg_bytes_per_sec: 11_100,
        block_align,
        bits_per_sample: 4,
        extra,
    }
}

/// wSamplesPerBlock, wNumCoef and the seven standard coefficient pairs.
fn ms_extra(per_block: u16) -> Vec<u8> {
    let mut e = per_block.to_le_bytes().to_vec();
    e.extend(7u16.to_le_bytes());
    for (a, b) in [
        (256i16, 0i16),
        (512, -256),
        (0, 0),
        (192, 64),
        (240, 0),
        (460, -208),
        (392, -232),
    ] {
        e.extend(a.to_le_bytes());
        e.extend(b.to_le_bytes());
    }
    e
}

fn ms_mono(block_align: u16) -> MsAdpcm {
    MsAdpcm::new(&format(
        WAVE_FORMAT_ADPCM,
        1,
        block_align,
        ms_extra(block_align * 2 - 12),
    ))
    .unwrap()
}

/// Predictor 0 (256, 0), iDelta 16, iSamp1 100, iSamp2 50; nibbles 1, -1:
/// 100 + 1 * 16 = 116, delta 16 * 230 >> 8 = 14 -> floor 16; 116 - 16 = 100.
#[test]
fn ms_adpcm_mono_hand_computed() {
    let d = ms_mono(8);
    let mut pcm = Vec::new();
    d.decode(&[0, 16, 0, 100, 0, 50, 0, 0x1F], &mut pcm)
        .unwrap();
    assert_eq!(samples(&pcm), [50, 100, 116, 100]);
}

/// Predictor 1 (512, -256), iDelta 20, iSamp1 10, iSamp2 4.
/// The adaptation table is indexed by the unsigned nibble (7 -> 614, 8 -> 768).
/// n=7: predict (5120 - 1024) >> 8 = 16, + 7 * 20 = 156, delta 20 * 614 >> 8 = 47.
/// n=8 (-8): predict (156*512 - 10*256) >> 8 = 302, - 8 * 47 = -74, delta 47 * 768 >> 8 = 141.
/// n=4: predict (-74*512 - 156*256) >> 8 = -304, + 4 * 141 = 260, delta 141 * 307 >> 8 = 169.
/// n=0: predict (260*512 + 74*256) >> 8 = 594.
#[test]
fn ms_adpcm_adapts_and_uses_coefficients() {
    let d = ms_mono(9);
    let mut pcm = Vec::new();
    d.decode(&[1, 20, 0, 10, 0, 4, 0, 0x78, 0x40], &mut pcm)
        .unwrap();
    assert_eq!(samples(&pcm), [4, 10, 156, -74, 260, 594]);
}

/// Stereo: headers per field per channel; high nibble left, low right.
/// Left: predictor 0, delta 16, s1 1000, s2 0; nibble 7 -> 1000 + 112 = 1112.
/// Right: predictor 2 (0, 0), delta 32, s1 -5, s2 -7; nibble -2 -> -64.
#[test]
fn ms_adpcm_stereo_interleaves() {
    let f = format(WAVE_FORMAT_ADPCM, 2, 15, ms_extra(15 * 2 / 2 - 12));
    let d = MsAdpcm::new(&f).unwrap();
    let mut block = vec![0, 2, 16, 0, 32, 0];
    block.extend(1000i16.to_le_bytes());
    block.extend((-5i16).to_le_bytes());
    block.extend(0i16.to_le_bytes());
    block.extend((-7i16).to_le_bytes());
    block.push(0x7E);
    let mut pcm = Vec::new();
    d.decode(&block, &mut pcm).unwrap();
    assert_eq!(samples(&pcm), [0, -7, 1000, -5, 1112, -64]);
}

/// Output saturates at the 16-bit limits.
#[test]
fn ms_adpcm_clamps() {
    let d = ms_mono(8);
    let mut pcm = Vec::new();
    let mut block = vec![0, 0x00, 0x40];
    block.extend(32_000i16.to_le_bytes());
    block.extend(0i16.to_le_bytes());
    block.push(0x78);
    d.decode(&block, &mut pcm).unwrap();
    assert_eq!(samples(&pcm), [0, 32_000, 32_767, -32_768]);
}

#[test]
fn ms_adpcm_rejects_bad_blocks() {
    let d = ms_mono(8);
    // Predictor 7 of 7 coefficient sets.
    assert!(
        d.decode(&[7, 16, 0, 0, 0, 0, 0, 0], &mut Vec::new())
            .is_err()
    );
    // Shorter than the header.
    assert!(d.decode(&[0, 16, 0, 0, 0, 0], &mut Vec::new()).is_err());
}

/// Two blocks in one wave decode one after the other.
#[test]
fn ms_adpcm_decodes_each_block() {
    let d = ms_mono(8);
    let mut pcm = Vec::new();
    let one = [0, 16, 0, 100, 0, 50, 0, 0x1F];
    d.decode(&[one, one].concat(), &mut pcm).unwrap();
    assert_eq!(samples(&pcm), [50, 100, 116, 100, 50, 100, 116, 100]);
}

fn ima(channels: u16, block_align: u16) -> ImaAdpcm {
    let per_block = (block_align - 4 * channels) * 2 / channels + 1;
    ImaAdpcm::new(&format(
        WAVE_FORMAT_DVI_ADPCM,
        channels,
        block_align,
        per_block.to_le_bytes().to_vec(),
    ))
    .unwrap()
}

/// Header sample 0, index 0; nibbles 7 then seven 0s (low nibble first).
/// n=7 at step 7: 0 + 1 + 3 + 7 = 11, index 8 (step 16);
/// n=0: + 16 >> 3 = 2 -> 13, index 7 (step 14); then +1 each while the
/// index walks down 6..1 (steps 13, 12, 11, 10, 9; each >> 3 is 1).
#[test]
fn ima_adpcm_mono_hand_computed() {
    let d = ima(1, 8);
    let mut pcm = Vec::new();
    d.decode(&[0, 0, 0, 0, 0x07, 0, 0, 0], &mut pcm).unwrap();
    assert_eq!(samples(&pcm), [0, 11, 13, 14, 15, 16, 17, 18, 19]);
}

/// Negative nibbles and clamping: start 32767 at index 88 (step 32767).
/// Nibbles 7, 15, 8, 0, 8, 8, 8, 8:
/// n=7: + 4095 + 8191 + 16383 + 32767 -> clamps to 32767, index stays 88;
/// n=15 (sign set): - 61436 -> -28669, index 88;
/// n=8: - 4095 -> -32764, index 87 (step 29794);
/// n=0: + 3724 -> -29040, index 86 (27086);
/// n=8: - 3385 -> -32425, index 85 (24623);
/// n=8: - 3077 -> clamps to -32768, then stays there.
#[test]
fn ima_adpcm_sign_and_clamp() {
    let d = ima(1, 8);
    let mut pcm = Vec::new();
    let mut block = 32_767i16.to_le_bytes().to_vec();
    block.extend([88, 0, 0xF7, 0x08, 0x88, 0x88]);
    d.decode(&block, &mut pcm).unwrap();
    assert_eq!(
        samples(&pcm),
        [
            32_767, 32_767, -28_669, -32_764, -29_040, -32_425, -32_768, -32_768, -32_768
        ]
    );
}

/// Stereo: 4 bytes of left nibbles, then 4 of right, interleaved on output.
/// Left as the mono test; right starts at 100 index 0 with nibble 8 (-0)
/// then zeros: 100 - 0 = 100 (index 0), then +0 each (step 7 >> 3 = 0).
#[test]
fn ima_adpcm_stereo_interleaves() {
    let d = ima(2, 16);
    let mut block = vec![0, 0, 0, 0];
    block.extend(100i16.to_le_bytes());
    block.extend([0, 0]);
    block.extend([0x07, 0, 0, 0, 0x08, 0, 0, 0]);
    let mut pcm = Vec::new();
    d.decode(&block, &mut pcm).unwrap();
    let s = samples(&pcm);
    let left: Vec<i16> = s.iter().step_by(2).copied().collect();
    let right: Vec<i16> = s.iter().skip(1).step_by(2).copied().collect();
    assert_eq!(left, [0, 11, 13, 14, 15, 16, 17, 18, 19]);
    assert_eq!(right, [100; 9]);
}

#[test]
fn ima_adpcm_rejects_bad_index() {
    let d = ima(1, 8);
    assert!(
        d.decode(&[0, 0, 89, 0, 0, 0, 0, 0], &mut Vec::new())
            .is_err()
    );
    assert!(d.decode(&[0, 0, 0], &mut Vec::new()).is_err());
}

/// The MS-RDPEA 4.1.1 example lists MS ADPCM and IMA ADPCM, 22.05 kHz
/// stereo, nBlockAlign 1024, with wSamplesPerBlock 1012 and 1017.
#[test]
fn spec_example_adpcm_formats_are_accepted() {
    let pdu = crate::rdpsnd::tests::SPEC_SERVER_FORMATS;
    let server = crate::rdpsnd::parse_server_formats(&pdu[4..]).unwrap();
    let ms = MsAdpcm::new(&server.formats[3]).unwrap();
    assert_eq!(ms.coefs.len(), 7);
    assert_eq!(ms.coefs[5], (460, -208));
    assert_eq!(ms.block_align, 1024);
    let ima = ImaAdpcm::new(&server.formats[4]).unwrap();
    assert_eq!(ima.output.channels, 2);
    assert_eq!(ima.output.sample_rate, 22_050);
    // Neither decoder takes the other's format or PCM.
    assert!(MsAdpcm::new(&server.formats[4]).is_none());
    assert!(ImaAdpcm::new(&server.formats[3]).is_none());
    assert!(ImaAdpcm::new(&server.formats[0]).is_none());
}

#[test]
fn inconsistent_adpcm_formats_are_refused() {
    // wSamplesPerBlock that does not match nBlockAlign.
    assert!(MsAdpcm::new(&format(WAVE_FORMAT_ADPCM, 1, 8, ms_extra(5))).is_none());
    assert!(ImaAdpcm::new(&format(WAVE_FORMAT_DVI_ADPCM, 1, 8, vec![8, 0])).is_none());
    // Coefficient table shorter than wNumCoef.
    let mut e = ms_extra(4);
    e.truncate(20);
    assert!(MsAdpcm::new(&format(WAVE_FORMAT_ADPCM, 1, 8, e)).is_none());
    // 8-bit, three channels, partial word groups.
    let mut f = format(WAVE_FORMAT_DVI_ADPCM, 1, 8, vec![]);
    f.bits_per_sample = 8;
    assert!(ImaAdpcm::new(&f).is_none());
    assert!(ImaAdpcm::new(&format(WAVE_FORMAT_DVI_ADPCM, 3, 24, vec![])).is_none());
    assert!(ImaAdpcm::new(&format(WAVE_FORMAT_DVI_ADPCM, 2, 12, vec![])).is_none());
}

#[test]
fn rank_orders_aac_mp3_adpcm_pcm() {
    let f = |tag, avg| AudioFormat {
        avg_bytes_per_sec: avg,
        ..format(tag, 2, 4, vec![])
    };
    let order: Vec<u8> = [
        f(WAVE_FORMAT_AAC_MS, 12_000),
        f(WAVE_FORMAT_AAC_MS, 24_000),
        f(WAVE_FORMAT_MPEGLAYER3, 16_000),
        f(WAVE_FORMAT_ADPCM, 0),
        f(WAVE_FORMAT_DVI_ADPCM, 0),
        f(0x0031, 0),
        f(WAVE_FORMAT_PCM, 0),
    ]
    .iter()
    .map(rank)
    .collect();
    assert_eq!(order, [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(rank(&f(WAVE_FORMAT_MPEG_HEAAC, 12_000)), 0);
}
