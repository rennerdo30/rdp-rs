//! DES and Triple DES in CBC mode (FIPS 46-3, SP 800-67), for the FIPS
//! level of Standard RDP Security (MS-RDPBCGR 5.3.5.2): one EDE3 CBC
//! stream per direction whose chaining runs across packets.
//!
//! Written from the standard's tables; the round function uses S-box
//! tables with the P permutation folded in, built once. Not constant
//! time: legacy RDP security is opt-in and weak anyway (see
//! [`crate::security`]).

use std::sync::OnceLock;

/// Initial permutation (bit 1 is the most significant of 64).
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, //
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, //
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, //
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// The permutation after the S-boxes.
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, //
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

/// Permuted choice 1: the 56 key bits without the parity bits.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, //
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, //
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, //
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

/// Permuted choice 2: a round key's 48 bits from C and D.
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, //
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, //
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, //
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Left rotations of C and D before each round.
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// The eight S-boxes, four rows of 16 each.
pub(crate) const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, //
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, //
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, //
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, //
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, //
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, //
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, //
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, //
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, //
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, //
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, //
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, //
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, //
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, //
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, //
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, //
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, //
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, //
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, //
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, //
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, //
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, //
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, //
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, //
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// `table.len()` bits taken from `input` (`width` bits wide): output bit
/// j (most significant first) is input bit `table[j]` (1 = most
/// significant).
fn permute(input: u64, width: u32, table: &[u8]) -> u64 {
    table.iter().fold(0, |out, &bit| {
        (out << 1) | ((input >> (width - bit as u32)) & 1)
    })
}

/// The inverse of [`IP`].
fn fp_table() -> [u8; 64] {
    let mut fp = [0u8; 64];
    for (j, &bit) in IP.iter().enumerate() {
        fp[bit as usize - 1] = j as u8 + 1;
    }
    fp
}

struct Tables {
    fp: [u8; 64],
    /// S-box i with P applied: the round function's share of 6 input bits.
    sp: [[u32; 64]; 8],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut sp = [[0u32; 64]; 8];
        for (i, table) in sp.iter_mut().enumerate() {
            for (v, out) in table.iter_mut().enumerate() {
                let row = ((v >> 4) & 2) | (v & 1);
                let col = (v >> 1) & 0xF;
                let s = S[i][row * 16 + col] as u64;
                *out = permute(s << (28 - 4 * i), 32, &P) as u32;
            }
        }
        Tables { fp: fp_table(), sp }
    })
}

/// One DES key: its 16 round keys of 48 bits.
struct Des {
    round: [u64; 16],
}

impl Des {
    /// The round keys from an 8-byte key; the parity bits (the least
    /// significant of each byte) are ignored.
    fn new(key: &[u8; 8]) -> Des {
        let cd = permute(u64::from_be_bytes(*key), 64, &PC1);
        let (mut c, mut d) = ((cd >> 28) as u32, (cd & 0x0FFF_FFFF) as u32);
        let rot = |x: u32, n: u32| ((x << n) | (x >> (28 - n))) & 0x0FFF_FFFF;
        let mut round = [0u64; 16];
        for (k, &n) in round.iter_mut().zip(&SHIFTS) {
            c = rot(c, n);
            d = rot(d, n);
            *k = permute(((c as u64) << 28) | d as u64, 56, &PC2);
        }
        Des { round }
    }

    /// One block; `decrypt` runs the round keys backwards.
    fn block(&self, input: u64, decrypt: bool) -> u64 {
        let t = tables();
        let x = permute(input, 64, &IP);
        let (mut l, mut r) = ((x >> 32) as u32, x as u32);
        for i in 0..16 {
            let k = self.round[if decrypt { 15 - i } else { i }];
            // E(R): chunk j is bits 4j..4j+5 (1-based, 0 meaning 32).
            let e = r.rotate_right(1);
            let mut f = 0u32;
            for (j, sp) in t.sp.iter().enumerate() {
                let chunk = (e.rotate_left(4 * j as u32) >> 26) & 0x3F;
                let kj = ((k >> (42 - 6 * j)) & 0x3F) as u32;
                f |= sp[(chunk ^ kj) as usize];
            }
            (l, r) = (r, l ^ f);
        }
        permute(((r as u64) << 32) | l as u64, 64, &t.fp)
    }
}

impl Drop for Des {
    fn drop(&mut self) {
        self.round.fill(0);
        std::hint::black_box(&self.round);
    }
}

/// DES encryption of one block with one key, for the known-answer tests.
#[cfg(test)]
pub(crate) fn des_encrypt_block(key: &[u8; 8], block: [u8; 8]) -> [u8; 8] {
    Des::new(key)
        .block(u64::from_be_bytes(block), false)
        .to_be_bytes()
}

/// Triple DES (EDE3) in CBC mode, one direction. The chaining value
/// carries over from one call to the next, as RDP's FIPS level wants.
pub struct TripleDesCbc {
    k1: Des,
    k2: Des,
    k3: Des,
    chain: u64,
    decrypt: bool,
}

impl TripleDesCbc {
    /// `key` is K1, K2 and K3; `iv` the first chaining value.
    pub fn new(key: &[u8; 24], iv: [u8; 8], decrypt: bool) -> TripleDesCbc {
        let k = |i: usize| Des::new(key[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        TripleDesCbc {
            k1: k(0),
            k2: k(1),
            k3: k(2),
            chain: u64::from_be_bytes(iv),
            decrypt,
        }
    }

    /// Encrypts or decrypts `data` in place. Its length must be a
    /// multiple of 8; the caller pads.
    pub fn process(&mut self, data: &mut [u8]) {
        assert!(
            data.len().is_multiple_of(8),
            "3DES data must be whole blocks"
        );
        for b in data.as_chunks_mut::<8>().0 {
            let x = u64::from_be_bytes(*b);
            let y = if self.decrypt {
                let p = self
                    .k1
                    .block(self.k2.block(self.k3.block(x, true), false), true)
                    ^ self.chain;
                self.chain = x;
                p
            } else {
                let c = self.k3.block(
                    self.k2.block(self.k1.block(x ^ self.chain, false), true),
                    false,
                );
                self.chain = c;
                c
            };
            b.copy_from_slice(&y.to_be_bytes());
        }
    }
}

#[cfg(test)]
#[path = "des_tests.rs"]
mod tests;
