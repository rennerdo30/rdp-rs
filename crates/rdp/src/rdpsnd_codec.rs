//! Compressed audio formats for the audio output channel (MS-RDPEA 2.2.2.1.1
//! and its product note <4>): the two ADPCM codecs are decoded here, in pure
//! Rust; AAC and MP3 go to an [`AudioDecoder`] the client supplies (on
//! Windows, the Media Foundation decoders).
//!
//! The client offers every server format it can play, best first: AAC, MP3,
//! MS-ADPCM, IMA ADPCM, other formats the decoder accepts, then PCM
//! ([`rank`]). Every format is decoded to 16-bit PCM before the
//! [`AudioBackend`](super::AudioBackend).
//!
//! References for the ADPCM bitstreams:
//! - Microsoft ADPCM: `ADPCMWAVEFORMAT` (mmreg.h / audiodefs.h: wSamplesPerBlock,
//!   wNumCoef, aCoef; wSamplesPerBlock = nBlockAlign * 2 / nChannels - 12)
//!   and the Microsoft Multimedia Standards Update (RIFF ADPCM block layout);
//! - IMA ADPCM (WAVE_FORMAT_DVI_ADPCM): IMA Digital Audio Technical Working
//!   Group, "Recommended Practices for Enhancing Digital Audio Compatibility
//!   in Multimedia Systems", rev. 3.00 (1992), with the same RIFF block layout.

use super::{AudioFormat, PcmFormat, WAVE_FORMAT_PCM};

/// Microsoft ADPCM (MS-RDPEA note <4>).
pub const WAVE_FORMAT_ADPCM: u16 = 0x0002;
/// IMA (Intel DVI) ADPCM.
pub const WAVE_FORMAT_DVI_ADPCM: u16 = 0x0011;
/// ISO/MPEG Layer 3 (MS-RDPEA note <4>).
pub const WAVE_FORMAT_MPEGLAYER3: u16 = 0x0055;
/// HE-AAC / AAC with an HEAACWAVEINFO tail in the format's extra data.
pub const WAVE_FORMAT_MPEG_HEAAC: u16 = 0x1610;
/// Microsoft AAC, the tag Windows 8 and later servers use (MS-RDPEA note <4>).
pub const WAVE_FORMAT_AAC_MS: u16 = 0xA106;
/// Windows servers use AAC only for a client entry with this
/// nAvgBytesPerSec (MS-RDPEA 2.2.2.2, product note <5>).
pub const AAC_AVG_BYTES_PER_SEC: u32 = 12_000;

/// A decoder for compressed formats the library does not decode itself
/// (AAC, MP3), supplied by the client. Runs on the session worker thread,
/// so every call must return quickly.
pub trait AudioDecoder: Send {
    /// Whether this decoder can play `format`; asked during the format
    /// negotiation for every server format, so it must be cheap.
    fn accepts(&self, format: &AudioFormat) -> bool;
    /// Prepares to decode `format` and returns the PCM it will produce.
    /// Called before the first wave of a format (after [`AudioDecoder::close`]).
    fn open(&mut self, format: &AudioFormat) -> Result<PcmFormat, String>;
    /// Decodes one audio sample (the data of one wave) and appends the PCM to
    /// `pcm`. A decoder with latency may append nothing for the first waves.
    fn decode(&mut self, data: &[u8], pcm: &mut Vec<u8>) -> Result<(), String>;
    /// Releases the decoder state.
    fn close(&mut self);
}

/// Offer order of a format tag: lower ranks are listed first in the Client
/// Audio Formats and Version PDU.
pub fn rank(format: &AudioFormat) -> u8 {
    match format.tag {
        // Windows only streams the 12 kB/s AAC entry (note <5>).
        WAVE_FORMAT_AAC_MS | WAVE_FORMAT_MPEG_HEAAC => {
            u8::from(format.avg_bytes_per_sec != AAC_AVG_BYTES_PER_SEC)
        }
        WAVE_FORMAT_MPEGLAYER3 => 2,
        WAVE_FORMAT_ADPCM => 3,
        WAVE_FORMAT_DVI_ADPCM => 4,
        WAVE_FORMAT_PCM => 6,
        _ => 5,
    }
}

fn le16(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

/// Mono or stereo, a sane rate and 4-bit samples: what both ADPCM decoders
/// take. Returns the 16-bit PCM they produce.
fn adpcm_output(f: &AudioFormat, tag: u16) -> Option<PcmFormat> {
    (f.tag == tag
        && f.bits_per_sample == 4
        && (1..=2).contains(&f.channels)
        && (1..=192_000).contains(&f.samples_per_sec))
    .then_some(PcmFormat {
        channels: f.channels,
        sample_rate: f.samples_per_sec,
        bits: 16,
    })
}

/// AdaptationTable of Microsoft ADPCM: the step size scale per nibble.
const MS_ADAPT: [i32; 16] = [
    230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230,
];

/// A Microsoft ADPCM format (WAVE_FORMAT_ADPCM) with its coefficient sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsAdpcm {
    pub output: PcmFormat,
    block_align: usize,
    coefs: Vec<(i32, i32)>,
}

impl MsAdpcm {
    /// The decoder for `f`, if it is a consistent Microsoft ADPCM format:
    /// extra data wSamplesPerBlock, wNumCoef and wNumCoef (iCoef1, iCoef2)
    /// pairs, with wSamplesPerBlock = nBlockAlign * 2 / nChannels - 12.
    pub fn new(f: &AudioFormat) -> Option<Self> {
        let output = adpcm_output(f, WAVE_FORMAT_ADPCM)?;
        let ch = usize::from(f.channels);
        let block_align = usize::from(f.block_align);
        let e = &f.extra;
        if block_align <= 7 * ch || e.len() < 4 {
            return None;
        }
        let per_block = le16(e, 0) as u16 as usize;
        let count = le16(e, 2) as u16 as usize;
        if per_block != block_align * 2 / ch - 12 || count == 0 || e.len() < 4 + 4 * count {
            return None;
        }
        let coefs = (0..count)
            .map(|i| (le16(e, 4 + 4 * i).into(), le16(e, 6 + 4 * i).into()))
            .collect();
        Some(Self {
            output,
            block_align,
            coefs,
        })
    }

    /// Decodes whole blocks (a short last block as far as it goes).
    pub fn decode(&self, data: &[u8], pcm: &mut Vec<u8>) -> Result<(), String> {
        data.chunks(self.block_align)
            .try_for_each(|b| self.block(b, pcm))
    }

    /// One block: per channel bPredictor, then iDelta, iSamp1 and iSamp2 per
    /// channel; iSamp2 and iSamp1 are the first two output samples; then
    /// nibbles, high nibble first, alternating channels in stereo.
    fn block(&self, b: &[u8], pcm: &mut Vec<u8>) -> Result<(), String> {
        let ch = usize::from(self.output.channels);
        if b.len() < 7 * ch {
            return Err(format!("MS-ADPCM block of {} bytes", b.len()));
        }
        // (coef1, coef2, delta, samp1, samp2) per channel.
        let mut st = [(0i32, 0i32, 0i32, 0i32, 0i32); 2];
        for c in 0..ch {
            let &(c1, c2) = self
                .coefs
                .get(usize::from(b[c]))
                .ok_or_else(|| format!("MS-ADPCM predictor {} of {}", b[c], self.coefs.len()))?;
            let at = |k: usize| i32::from(le16(b, ch + 2 * (k * ch + c)));
            st[c] = (c1, c2, at(0), at(1), at(2));
        }
        for s in &st[..ch] {
            pcm.extend_from_slice(&(s.4 as i16).to_le_bytes());
        }
        for s in &st[..ch] {
            pcm.extend_from_slice(&(s.3 as i16).to_le_bytes());
        }
        let nibbles = b[7 * ch..].iter().flat_map(|&v| [v >> 4, v & 0x0F]);
        for (i, nib) in nibbles.enumerate() {
            let (c1, c2, delta, s1, s2) = &mut st[i % ch];
            let signed = i32::from((nib << 4) as i8 >> 4);
            let predict = (*s1 * *c1 + *s2 * *c2) >> 8;
            let sample = (predict + signed * *delta).clamp(-32_768, 32_767);
            *s2 = *s1;
            *s1 = sample;
            *delta = ((MS_ADAPT[usize::from(nib)] * *delta) >> 8).max(16);
            pcm.extend_from_slice(&(sample as i16).to_le_bytes());
        }
        Ok(())
    }
}

/// IMA ADPCM step sizes (89 entries, index 0 to 88).
const IMA_STEP: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// IMA ADPCM step index change per nibble magnitude.
const IMA_INDEX: [i32; 8] = [-1, -1, -1, -1, 2, 4, 6, 8];

/// An IMA ADPCM format (WAVE_FORMAT_DVI_ADPCM).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImaAdpcm {
    pub output: PcmFormat,
    block_align: usize,
}

impl ImaAdpcm {
    /// The decoder for `f`, if it is a consistent IMA ADPCM format: blocks
    /// hold a 4-byte header per channel and whole 4-byte words per channel;
    /// a wSamplesPerBlock in the extra data must match the block size.
    pub fn new(f: &AudioFormat) -> Option<Self> {
        let output = adpcm_output(f, WAVE_FORMAT_DVI_ADPCM)?;
        let ch = usize::from(f.channels);
        let block_align = usize::from(f.block_align);
        if block_align <= 4 * ch || (block_align - 4 * ch) % (4 * ch) != 0 {
            return None;
        }
        let per_block = (block_align - 4 * ch) * 2 / ch + 1;
        if f.extra.len() >= 2 && le16(&f.extra, 0) as u16 as usize != per_block {
            return None;
        }
        Some(Self {
            output,
            block_align,
        })
    }

    /// Decodes whole blocks (a short last block as far as it goes).
    pub fn decode(&self, data: &[u8], pcm: &mut Vec<u8>) -> Result<(), String> {
        data.chunks(self.block_align)
            .try_for_each(|b| self.block(b, pcm))
    }

    /// One block: per channel the first sample (i16), the step index and a
    /// reserved byte; then per channel in turn 4 bytes (8 samples, low nibble
    /// first). A trailing partial word group is ignored.
    fn block(&self, b: &[u8], pcm: &mut Vec<u8>) -> Result<(), String> {
        let ch = usize::from(self.output.channels);
        if b.len() < 4 * ch {
            return Err(format!("IMA ADPCM block of {} bytes", b.len()));
        }
        // (predictor, step index) per channel.
        let mut st = [(0i32, 0i32); 2];
        for c in 0..ch {
            let index = i32::from(b[4 * c + 2]);
            if index > 88 {
                return Err(format!("IMA ADPCM step index {index}"));
            }
            st[c] = (i32::from(le16(b, 4 * c)), index);
            pcm.extend_from_slice(&le16(b, 4 * c).to_le_bytes());
        }
        let mut group = [[0i16; 8]; 2];
        for words in b[4 * ch..].chunks_exact(4 * ch) {
            for c in 0..ch {
                let (pred, index) = &mut st[c];
                let nibbles = words[4 * c..4 * c + 4]
                    .iter()
                    .flat_map(|&v| [v & 0x0F, v >> 4]);
                for (k, nib) in nibbles.enumerate() {
                    let step = IMA_STEP[*index as usize];
                    let mut diff = step >> 3;
                    if nib & 1 != 0 {
                        diff += step >> 2;
                    }
                    if nib & 2 != 0 {
                        diff += step >> 1;
                    }
                    if nib & 4 != 0 {
                        diff += step;
                    }
                    if nib & 8 != 0 {
                        diff = -diff;
                    }
                    *pred = (*pred + diff).clamp(-32_768, 32_767);
                    *index = (*index + IMA_INDEX[usize::from(nib & 7)]).clamp(0, 88);
                    group[c][k] = *pred as i16;
                }
            }
            for k in 0..8 {
                for g in &group[..ch] {
                    pcm.extend_from_slice(&g[k].to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

/// How the samples of one negotiated format become PCM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Codec {
    Pcm(PcmFormat),
    MsAdpcm(MsAdpcm),
    ImaAdpcm(ImaAdpcm),
    /// The client's [`AudioDecoder`].
    External,
}

#[cfg(test)]
#[path = "rdpsnd_codec_tests.rs"]
mod tests;
