//! Interleaved RLE bitmap codec, decoder side (MS-RDPBCGR 2.2.9.1.1.3.1.2.4).

use crate::cursor::Reader;
use crate::error::{Error, Result, proto};

const REGULAR_BG_RUN: u8 = 0x0;
const REGULAR_FG_RUN: u8 = 0x1;
const REGULAR_FGBG_IMAGE: u8 = 0x2;
const REGULAR_COLOR_RUN: u8 = 0x3;
const REGULAR_COLOR_IMAGE: u8 = 0x4;
const LITE_SET_FG_FG_RUN: u8 = 0xC;
const LITE_SET_FG_FGBG_IMAGE: u8 = 0xD;
const LITE_DITHERED_RUN: u8 = 0xE;
const MEGA_MEGA_BG_RUN: u8 = 0xF0;
const MEGA_MEGA_FG_RUN: u8 = 0xF1;
const MEGA_MEGA_FGBG_IMAGE: u8 = 0xF2;
const MEGA_MEGA_COLOR_RUN: u8 = 0xF3;
const MEGA_MEGA_COLOR_IMAGE: u8 = 0xF4;
const MEGA_MEGA_SET_FG_RUN: u8 = 0xF6;
const MEGA_MEGA_SET_FGBG_IMAGE: u8 = 0xF7;
const MEGA_MEGA_DITHERED_RUN: u8 = 0xF8;
const SPECIAL_FGBG_1: u8 = 0xF9;
const SPECIAL_FGBG_2: u8 = 0xFA;
const SPECIAL_WHITE: u8 = 0xFD;
const SPECIAL_BLACK: u8 = 0xFE;

fn code_id(h: u8) -> u8 {
    if h & 0xC0 != 0xC0 {
        h >> 5
    } else if h & 0xF0 == 0xF0 {
        h
    } else {
        h >> 4
    }
}

fn run_length(code: u8, h: u8, r: &mut Reader) -> Result<usize> {
    Ok(match code {
        REGULAR_FGBG_IMAGE => match h & 0x1F {
            0 => r.u8()? as usize + 1,
            n => n as usize * 8,
        },
        LITE_SET_FG_FGBG_IMAGE => match h & 0x0F {
            0 => r.u8()? as usize + 1,
            n => n as usize * 8,
        },
        REGULAR_BG_RUN | REGULAR_FG_RUN | REGULAR_COLOR_RUN | REGULAR_COLOR_IMAGE => match h & 0x1F
        {
            0 => r.u8()? as usize + 32,
            n => n as usize,
        },
        LITE_SET_FG_FG_RUN | LITE_DITHERED_RUN => match h & 0x0F {
            0 => r.u8()? as usize + 16,
            n => n as usize,
        },
        MEGA_MEGA_BG_RUN..=MEGA_MEGA_DITHERED_RUN => r.u16()? as usize,
        _ => 0,
    })
}

struct Out {
    px: Vec<u32>,
    w: usize,
    total: usize,
    first_line: bool,
}

impl Out {
    fn push(&mut self, v: u32) -> Result<()> {
        if self.px.len() >= self.total {
            return proto("interleaved RLE writes past the bitmap");
        }
        self.px.push(v);
        Ok(())
    }

    fn above(&self) -> u32 {
        self.px[self.px.len() - self.w]
    }

    fn fgbg(&mut self, mask: u8, bits: usize, fg: u32) -> Result<()> {
        for i in 0..bits {
            let set = mask & (1 << i) != 0;
            let v = if self.first_line {
                if set { fg } else { 0 }
            } else if set {
                self.above() ^ fg
            } else {
                self.above()
            };
            self.push(v)?;
        }
        Ok(())
    }
}

/// Decodes into top-down 0x00RRGGBB pixels.
pub fn decode(src: &[u8], w: usize, h: usize, bpp: u16) -> Result<Vec<u32>> {
    let (bytes, white) = match bpp {
        15 => (2, 0x7FFF),
        16 => (2, 0xFFFF),
        24 => (3, 0xFF_FFFF),
        _ => return Err(Error::Unsupported(format!("interleaved RLE at {bpp} bpp"))),
    };
    let read_px = |r: &mut Reader| -> Result<u32> {
        let b = r.bytes(bytes)?;
        Ok(b.iter()
            .enumerate()
            .fold(0u32, |v, (i, &x)| v | (x as u32) << (8 * i)))
    };

    let mut o = Out {
        px: Vec::with_capacity(w * h),
        w,
        total: w * h,
        first_line: true,
    };
    let mut r = Reader::new(src);
    let mut fg = white;
    let mut insert_fg = false;

    while r.remaining() > 0 {
        if o.first_line && o.px.len() >= w {
            o.first_line = false;
            insert_fg = false;
        }
        let header = r.u8()?;
        let code = code_id(header);
        let run = run_length(code, header, &mut r)?;

        if code == REGULAR_BG_RUN || code == MEGA_MEGA_BG_RUN {
            let mut n = run;
            if insert_fg && n > 0 {
                let v = if o.first_line { fg } else { o.above() ^ fg };
                o.push(v)?;
                n -= 1;
            }
            for _ in 0..n {
                let v = if o.first_line { 0 } else { o.above() };
                o.push(v)?;
            }
            insert_fg = true;
            continue;
        }
        insert_fg = false;

        match code {
            REGULAR_FG_RUN | MEGA_MEGA_FG_RUN | LITE_SET_FG_FG_RUN | MEGA_MEGA_SET_FG_RUN => {
                if code == LITE_SET_FG_FG_RUN || code == MEGA_MEGA_SET_FG_RUN {
                    fg = read_px(&mut r)?;
                }
                for _ in 0..run {
                    let v = if o.first_line { fg } else { o.above() ^ fg };
                    o.push(v)?;
                }
            }
            LITE_DITHERED_RUN | MEGA_MEGA_DITHERED_RUN => {
                let a = read_px(&mut r)?;
                let b = read_px(&mut r)?;
                for _ in 0..run {
                    o.push(a)?;
                    o.push(b)?;
                }
            }
            REGULAR_COLOR_RUN | MEGA_MEGA_COLOR_RUN => {
                let c = read_px(&mut r)?;
                for _ in 0..run {
                    o.push(c)?;
                }
            }
            REGULAR_FGBG_IMAGE
            | MEGA_MEGA_FGBG_IMAGE
            | LITE_SET_FG_FGBG_IMAGE
            | MEGA_MEGA_SET_FGBG_IMAGE => {
                if code == LITE_SET_FG_FGBG_IMAGE || code == MEGA_MEGA_SET_FGBG_IMAGE {
                    fg = read_px(&mut r)?;
                }
                let mut n = run;
                while n > 8 {
                    let mask = r.u8()?;
                    o.fgbg(mask, 8, fg)?;
                    n -= 8;
                }
                if n > 0 {
                    let mask = r.u8()?;
                    o.fgbg(mask, n, fg)?;
                }
            }
            REGULAR_COLOR_IMAGE | MEGA_MEGA_COLOR_IMAGE => {
                for _ in 0..run {
                    let p = read_px(&mut r)?;
                    o.push(p)?;
                }
            }
            SPECIAL_FGBG_1 => o.fgbg(0x03, 8, fg)?,
            SPECIAL_FGBG_2 => o.fgbg(0x05, 8, fg)?,
            SPECIAL_WHITE => o.push(white)?,
            SPECIAL_BLACK => o.push(0)?,
            _ => return proto(format!("invalid interleaved RLE order {header:#04x}")),
        }
    }
    if o.px.len() != o.total {
        return proto(format!(
            "interleaved RLE produced {} of {} pixels",
            o.px.len(),
            o.total
        ));
    }
    Ok(super::to_rgb_top_down(&o.px, w, h, bpp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_run_then_bg_run_copies_line_above() {
        // 4x2 at 16 bpp: row 0 = color run of 4 x 0xF800 (red); row 1 = BG run of 4.
        let src = [0x64, 0x00, 0xF8, 0x04];
        let px = decode(&src, 4, 2, 16).unwrap();
        assert!(px.iter().all(|&p| p == 0xFF0000));
    }

    #[test]
    fn first_line_bg_run_is_black_and_fg_run_is_white() {
        // 2x1: BG run 1 (black), then FG run 1 on the first line (white).
        let src = [0x01, 0x21];
        let px = decode(&src, 2, 1, 16).unwrap();
        assert_eq!(px, vec![0x000000, 0xFFFFFF]);
    }

    #[test]
    fn color_image_and_specials_24bpp() {
        // 3x1: color image of 1 pixel (B,G,R = 1,2,3), white, black.
        let src = [0x81, 1, 2, 3, SPECIAL_WHITE, SPECIAL_BLACK];
        let px = decode(&src, 3, 1, 24).unwrap();
        assert_eq!(px, vec![0x030201, 0xFFFFFF, 0]);
    }

    #[test]
    fn overrun_is_an_error() {
        assert!(decode(&[0x05], 2, 1, 16).is_err());
    }
}
