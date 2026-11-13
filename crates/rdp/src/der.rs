//! Minimal ASN.1 DER/BER: enough for CredSSP TSRequest, MCS connect PDUs and
//! pulling the public key out of the server's X.509 certificate.

use crate::error::{Error, Result, proto};

pub fn put_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n < 0x1_0000 {
        out.push(0x82);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x83);
        out.extend_from_slice(&(n as u32).to_be_bytes()[1..]);
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    put_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

pub fn integer(v: u32) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut i = 0;
    while i < 3 && b[i] == 0 && b[i + 1] & 0x80 == 0 {
        i += 1;
    }
    let mut c = b[i..].to_vec();
    if c[0] & 0x80 != 0 {
        c.insert(0, 0);
    }
    tlv(0x02, &c)
}

pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// Context-specific constructed (explicit) tag `[n]`.
pub fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, content)
}

pub struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reads one TLV with a single-byte tag and returns (tag, content).
    pub fn read(&mut self) -> Result<(u8, &'a [u8])> {
        let d = &self.data[self.pos..];
        let (hdr, len) = header_len(d).ok_or_else(|| Error::Protocol("bad DER length".into()))?;
        let end = hdr
            .checked_add(len)
            .filter(|&e| e <= d.len())
            .ok_or_else(|| Error::Protocol("DER element exceeds buffer".into()))?;
        let tag = d[0];
        self.pos += end;
        Ok((tag, &d[hdr..end]))
    }

    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, c) = self.read()?;
        if t != tag {
            return proto(format!("expected DER tag {tag:#04x}, got {t:#04x}"));
        }
        Ok(c)
    }
}

/// Returns (header length, content length) for a single-byte-tag element, if complete enough.
fn header_len(d: &[u8]) -> Option<(usize, usize)> {
    let b = *d.get(1)?;
    if b < 0x80 {
        return Some((2, b as usize));
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | *d.get(2 + i)? as usize;
    }
    Some((2 + n, len))
}

/// Total size of the DER element at the start of `buf`, once its header is complete.
pub fn frame_len(buf: &[u8]) -> Option<usize> {
    header_len(buf).map(|(h, l)| h + l)
}

pub fn parse_integer(c: &[u8]) -> Result<i64> {
    if c.is_empty() || c.len() > 8 {
        return proto("bad DER integer");
    }
    let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in c {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

/// Extracts the `subjectPublicKey` BIT STRING contents (without the unused-bits byte)
/// from a DER X.509 certificate. CredSSP binds authentication to these bytes.
pub fn subject_public_key(cert: &[u8]) -> Result<Vec<u8>> {
    let cert_seq = DerReader::new(cert).expect(0x30)?;
    let tbs = DerReader::new(cert_seq).expect(0x30)?;
    let mut r = DerReader::new(tbs);
    let mut elems = Vec::new();
    while !r.is_empty() {
        elems.push(r.read()?);
    }
    if elems.first().map(|e| e.0) == Some(0xA0) {
        elems.remove(0); // explicit version
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    let spki = elems
        .get(5)
        .filter(|e| e.0 == 0x30)
        .ok_or_else(|| Error::Protocol("certificate has no subjectPublicKeyInfo".into()))?;
    let mut r = DerReader::new(spki.1);
    r.expect(0x30)?; // algorithm
    let bits = r.expect(0x03)?;
    if bits.is_empty() {
        return proto("empty subjectPublicKey");
    }
    Ok(bits[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_minimal() {
        assert_eq!(integer(0), [2, 1, 0]);
        assert_eq!(integer(6), [2, 1, 6]);
        assert_eq!(integer(0x80), [2, 2, 0, 0x80]);
        assert_eq!(integer(65535), [2, 3, 0, 0xFF, 0xFF]);
        assert_eq!(
            parse_integer(&[0xC0, 0, 0, 0x6D]).unwrap() as u32,
            0xC000_006D
        );
    }

    #[test]
    fn long_lengths_round_trip() {
        let e = octet(&[7u8; 300]);
        assert_eq!(&e[..4], &[0x04, 0x82, 0x01, 0x2C]);
        assert_eq!(frame_len(&e), Some(304));
        let (t, c) = DerReader::new(&e).read().unwrap();
        assert_eq!((t, c.len()), (0x04, 300));
    }
}
