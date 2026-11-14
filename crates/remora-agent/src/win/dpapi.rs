//! DPAPI for the agent's key (`CryptProtectData`, user scope): only this
//! user on this machine can unprotect it. In-memory only; the key store
//! writes the file.

use std::io;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use super::wide;
use crate::keystore::Protector;

/// Extra entropy: another program of the user calling CryptUnprotectData on
/// the file needs this too (a speed bump, not a boundary).
const ENTROPY: &[u8] = b"Remora-Link v1 agent static key";
const DESCRIPTION: &str = "Remora Agent key";

pub struct Dpapi;

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Copies and frees a DPAPI output blob.
///
/// # Safety
/// `out` must come from a successful CryptProtectData/CryptUnprotectData.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: per the caller; the buffer is LocalAlloc'd by DPAPI.
    unsafe {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        // Plaintext output: wipe before freeing.
        std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(out.pbData.cast());
        v
    }
}

impl Protector for Dpapi {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let desc = wide(DESCRIPTION);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: valid input blobs; DPAPI allocates `out`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                desc.as_ptr(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful call.
        Ok(unsafe { take(out) })
    }

    fn unprotect(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let input = blob(data);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: valid input blobs; DPAPI allocates `out`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful call.
        Ok(unsafe { take(out) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In memory only: no file is written.
    #[test]
    fn round_trip_and_tamper() {
        let d = Dpapi;
        let plain = b"RAKP0123456789abcdef0123456789abcdef";
        let blob = d.protect(plain).unwrap();
        assert!(!blob.windows(plain.len()).any(|w| w == plain));
        assert_eq!(d.unprotect(&blob).unwrap(), plain);
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(d.unprotect(&bad).is_err());
    }
}
