//! The legacy primitives NTLM needs (MD4, MD5, HMAC-MD5, RC4), written here,
//! plus SHA-256 and randomness from `ring`.

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().try_into().expect("sha256 is 32 bytes")
}

/// SHA-1, for the licensing key derivation and MAC (MS-RDPELE 5.1.2, 5.1.5).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    d.as_ref().try_into().expect("sha1 is 20 bytes")
}

/// Textbook RSA as RDP uses it (MS-RDPBCGR 5.3.4.1, MS-RDPELE 5.1.1.1):
/// `data`, the `modulus` and the result are unsigned little-endian
/// integers, and there is no padding. The result has the modulus length
/// plus the 8 zero bytes RDP appends. The exponent is the RSA public
/// exponent (65537 in practice); the modulus is at most 4,096 bits.
pub fn rsa_encrypt_le(data: &[u8], modulus: &[u8], exponent: u32) -> Option<Vec<u8>> {
    let n = Big::from_le(modulus);
    let bits = n.bits();
    if !(64..=4096).contains(&bits) || exponent == 0 {
        return None;
    }
    let m = Big::from_le(data);
    if m.cmp(&n) != std::cmp::Ordering::Less {
        return None;
    }
    let mut result = Big::from_le(&[1]);
    for i in (0..32 - exponent.leading_zeros()).rev() {
        result = result.mul(&result).rem(&n);
        if exponent >> i & 1 != 0 {
            result = result.mul(&m).rem(&n);
        }
    }
    let len = bits.div_ceil(8);
    let mut out = result.to_le(len);
    out.resize(len + 8, 0);
    Some(out)
}

/// Unsigned big integer, 32-bit limbs, least significant first. Only what
/// public-key RSA needs; the operands are public, so nothing here has to
/// run in constant time.
#[derive(Clone, Debug)]
struct Big(Vec<u32>);

impl Big {
    fn from_le(b: &[u8]) -> Big {
        let mut v: Vec<u32> = b
            .chunks(4)
            .map(|c| {
                let mut w = [0u8; 4];
                w[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(w)
            })
            .collect();
        while v.last() == Some(&0) {
            v.pop();
        }
        Big(v)
    }

    fn to_le(&self, len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = self.0.iter().flat_map(|w| w.to_le_bytes()).collect();
        out.resize(len, 0);
        out
    }

    fn bits(&self) -> usize {
        self.0
            .last()
            .map_or(0, |&top| self.0.len() * 32 - top.leading_zeros() as usize)
    }

    fn bit(&self, i: usize) -> bool {
        self.0.get(i / 32).is_some_and(|w| w >> (i % 32) & 1 != 0)
    }

    fn cmp(&self, o: &Big) -> std::cmp::Ordering {
        self.0
            .len()
            .cmp(&o.0.len())
            .then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }

    fn mul(&self, o: &Big) -> Big {
        let mut r = vec![0u32; self.0.len() + o.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in o.0.iter().enumerate() {
                let t = a as u64 * b as u64 + r[i + j] as u64 + carry;
                r[i + j] = t as u32;
                carry = t >> 32;
            }
            r[i + o.0.len()] = carry as u32;
        }
        let mut b = Big(r);
        b.trim();
        b
    }

    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    /// `self mod n` by binary long division (shift in one bit, subtract).
    fn rem(&self, n: &Big) -> Big {
        let mut r = Big(Vec::with_capacity(n.0.len() + 1));
        for i in (0..self.bits()).rev() {
            r.shl1(self.bit(i));
            if r.cmp(n) != std::cmp::Ordering::Less {
                r.sub(n);
            }
        }
        r
    }

    fn shl1(&mut self, low: bool) {
        let mut carry = low as u32;
        for w in &mut self.0 {
            let next = *w >> 31;
            *w = *w << 1 | carry;
            carry = next;
        }
        if carry != 0 {
            self.0.push(carry);
        }
    }

    /// `self -= o`, with `self >= o`.
    fn sub(&mut self, o: &Big) {
        let mut borrow = 0i64;
        for i in 0..self.0.len() {
            let t = self.0[i] as i64 - o.0.get(i).copied().unwrap_or(0) as i64 - borrow;
            borrow = (t < 0) as i64;
            self.0[i] = t.rem_euclid(1 << 32) as u32;
        }
        self.trim();
    }
}

pub fn random<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG failed");
    b
}

fn md_pad(data: &[u8]) -> Vec<u8> {
    let mut m = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bit_len.to_le_bytes());
    m
}

fn words(block: &[u8]) -> [u32; 16] {
    let mut x = [0u32; 16];
    for (i, w) in x.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    x
}

fn digest_out(s: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, v) in s.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// MD4 (RFC 1320).
pub fn md4(data: &[u8]) -> [u8; 16] {
    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let mut s = IV;
    for block in md_pad(data).chunks(64) {
        let x = words(block);
        let [mut a, mut b, mut c, mut d] = s;
        for &i in &[0usize, 4, 8, 12] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(3);
            d = d
                .wrapping_add(f(a, b, c))
                .wrapping_add(x[i + 1])
                .rotate_left(7);
            c = c
                .wrapping_add(f(d, a, b))
                .wrapping_add(x[i + 2])
                .rotate_left(11);
            b = b
                .wrapping_add(f(c, d, a))
                .wrapping_add(x[i + 3])
                .rotate_left(19);
        }
        const K2: u32 = 0x5A82_7999;
        for i in 0..4 {
            a = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(K2)
                .rotate_left(3);
            d = d
                .wrapping_add(g(a, b, c))
                .wrapping_add(x[i + 4])
                .wrapping_add(K2)
                .rotate_left(5);
            c = c
                .wrapping_add(g(d, a, b))
                .wrapping_add(x[i + 8])
                .wrapping_add(K2)
                .rotate_left(9);
            b = b
                .wrapping_add(g(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(K2)
                .rotate_left(13);
        }
        const K3: u32 = 0x6ED9_EBA1;
        for &i in &[0usize, 2, 1, 3] {
            a = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(K3)
                .rotate_left(3);
            d = d
                .wrapping_add(h(a, b, c))
                .wrapping_add(x[i + 8])
                .wrapping_add(K3)
                .rotate_left(9);
            c = c
                .wrapping_add(h(d, a, b))
                .wrapping_add(x[i + 4])
                .wrapping_add(K3)
                .rotate_left(11);
            b = b
                .wrapping_add(h(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(K3)
                .rotate_left(15);
        }
        s = [
            s[0].wrapping_add(a),
            s[1].wrapping_add(b),
            s[2].wrapping_add(c),
            s[3].wrapping_add(d),
        ];
    }
    digest_out(s)
}

/// MD5 (RFC 1321).
pub fn md5(data: &[u8]) -> [u8; 16] {
    const SHIFT: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    let k: [u32; 64] =
        std::array::from_fn(|i| (((i + 1) as f64).sin().abs() * 4_294_967_296.0) as u32);
    let mut s = IV;
    for block in md_pad(data).chunks(64) {
        let m = words(block);
        let [mut a, mut b, mut c, mut d] = s;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(SHIFT[(i / 16) * 4 + i % 4]));
        }
        s = [
            s[0].wrapping_add(a),
            s[1].wrapping_add(b),
            s[2].wrapping_add(c),
            s[3].wrapping_add(d),
        ];
    }
    digest_out(s)
}

/// HMAC-MD5 (RFC 2104).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..16].copy_from_slice(&md5(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(data);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&md5(&inner));
    md5(&outer)
}

/// RC4 stream cipher. NTLM keeps one handle per direction for the whole session.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

pub fn rc4_once(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    Rc4::new(key).process(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md4_vectors() {
        assert_eq!(hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex(&md4(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }

    #[test]
    fn md5_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn hmac_md5_rfc2104() {
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn sha1_vector() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn rsa_small_key() {
        // n = 61 * 53 * 65537 * 65539 * 4294967291 (76 bits), e = 17: 65^17 mod n,
        // little-endian, plus the 8 zero bytes.
        let n: u128 = 61 * 53 * 65537 * 65539 * 4_294_967_291;
        let want = (0..17).fold(1u128, |a, _| a * 65 % n);
        let c = rsa_encrypt_le(&[65], &n.to_le_bytes(), 17).unwrap();
        let len = (128 - n.leading_zeros() as usize).div_ceil(8);
        assert_eq!(c.len(), len + 8);
        let mut got = [0u8; 16];
        got[..len].copy_from_slice(&c[..len]);
        assert_eq!(u128::from_le_bytes(got), want);
        assert!(c[len..].iter().all(|&b| b == 0));
        // Data not below the modulus is refused.
        assert!(rsa_encrypt_le(&n.to_le_bytes(), &n.to_le_bytes(), 17).is_none());
    }

    #[test]
    fn rc4_vector() {
        assert_eq!(hex(&rc4_once(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
    }
}
