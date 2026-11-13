//! The encrypted connection vault (`%APPDATA%\rdp-rs\vault.bin`).
//!
//! File layout (all little-endian):
//! `"RDPRSVLT"` | version u16 | Argon2id m_cost (KiB) u32 | t_cost u32 |
//! p_cost u32 | salt [16] | nonce [24] | XChaCha20-Poly1305 ciphertext+tag.
//! The whole header is the AEAD's associated data, so changing any parameter
//! fails authentication. The key comes from the master password with Argon2id;
//! a wrong password and a damaged file fail the same way, never with partial
//! data. Keys and plaintext live in `Zeroizing` buffers.
//!
//! Optional "remember on this PC": the derived key, protected with Windows
//! DPAPI for the current Windows user, in `vault.key`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"RDPRSVLT";
const FORMAT: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 4 * 3 + 16 + 24;

/// Argon2id cost: 64 MiB, 3 passes, 1 lane (about half a second on a desktop PC).
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 16],
}

impl KdfParams {
    /// Fresh parameters with a random salt (new vault or new master password).
    pub fn fresh() -> KdfParams {
        KdfParams {
            m_kib: M_COST_KIB,
            t: T_COST,
            p: P_COST,
            salt: rdp::crypto::random(),
        }
    }
}

/// A derived vault key and the parameters it was derived with.
#[derive(Clone)]
pub struct VaultKey {
    pub key: Zeroizing<[u8; 32]>,
    pub params: KdfParams,
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(..)")
    }
}

/// Derives the key from the master password (slow on purpose: run it off the UI thread).
pub fn derive(master: &str, params: KdfParams) -> Result<VaultKey, String> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| format!("vault parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(master.as_bytes(), &params.salt, &mut key[..])
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(VaultKey { key, params })
}

fn header(params: &KdfParams, nonce: &[u8; 24]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&FORMAT.to_le_bytes());
    h.extend_from_slice(&params.m_kib.to_le_bytes());
    h.extend_from_slice(&params.t.to_le_bytes());
    h.extend_from_slice(&params.p.to_le_bytes());
    h.extend_from_slice(&params.salt);
    h.extend_from_slice(nonce);
    h
}

/// Reads the key-derivation parameters from a vault file's header.
pub fn read_params(bytes: &[u8]) -> Result<KdfParams, String> {
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err("not an rdp-rs vault".into());
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    if u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT {
        return Err("vault was written by a newer rdpc".into());
    }
    let params = KdfParams {
        m_kib: u32_at(10),
        t: u32_at(14),
        p: u32_at(18),
        salt: bytes[22..38].try_into().unwrap(),
    };
    // Refuse absurd costs from a tampered header before spending memory on them.
    if params.m_kib > 4 * 1024 * 1024
        || params.t > 64
        || params.p > 16
        || params.m_kib < 8 * params.p
    {
        return Err("vault parameters out of range".into());
    }
    Ok(params)
}

/// Encrypts `plaintext` with a fresh nonce.
pub fn seal(key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = rdp::crypto::random();
    let head = header(&key.params, &nonce);
    let cipher = XChaCha20Poly1305::new(&Key::from(*key.key));
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &head,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let mut out = head;
    out.extend_from_slice(&ct);
    out
}

/// Decrypts a vault file with a derived key.
pub fn open(key: &VaultKey, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let params = read_params(bytes)?;
    if params != key.params {
        return Err("Wrong master password.".into());
    }
    let nonce: [u8; 24] = bytes[38..62].try_into().unwrap();
    let cipher = XChaCha20Poly1305::new(&Key::from(*key.key));
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &bytes[HEADER_LEN..],
                aad: &bytes[..HEADER_LEN],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "Wrong master password, or the vault file is damaged.".to_string())
}

/// Protects the derived key for "remember on this PC" (Windows DPAPI, current user).
#[cfg(windows)]
pub fn protect_key(key: &VaultKey) -> Option<Vec<u8>> {
    let mut plain = Zeroizing::new(Vec::with_capacity(32 + 28));
    plain.extend_from_slice(&key.key[..]);
    plain.extend_from_slice(&key.params.m_kib.to_le_bytes());
    plain.extend_from_slice(&key.params.t.to_le_bytes());
    plain.extend_from_slice(&key.params.p.to_le_bytes());
    plain.extend_from_slice(&key.params.salt);
    dpapi::protect(&plain)
}

#[cfg(windows)]
pub fn unprotect_key(blob: &[u8]) -> Option<VaultKey> {
    let plain = dpapi::unprotect(blob)?;
    if plain.len() != 32 + 28 {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(plain[o..o + 4].try_into().unwrap());
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain[..32]);
    Some(VaultKey {
        key,
        params: KdfParams {
            m_kib: u32_at(32),
            t: u32_at(36),
            p: u32_at(40),
            salt: plain[44..60].try_into().unwrap(),
        },
    })
}

#[cfg(not(windows))]
pub fn protect_key(_key: &VaultKey) -> Option<Vec<u8>> {
    None
}

#[cfg(not(windows))]
pub fn unprotect_key(_blob: &[u8]) -> Option<VaultKey> {
    None
}

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use zeroize::Zeroizing;

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Copies and frees a DPAPI output blob.
    ///
    /// # Safety
    /// `out` must come from a successful CryptProtectData/CryptUnprotectData call.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        unsafe {
            let v = Zeroizing::new(
                std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec(),
            );
            // Wipe DPAPI's copy before freeing it.
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData as HLOCAL);
            v
        }
    }

    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        let input = blob(data);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: input points to `data` for the call; DPAPI allocates `out`, freed in `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: successful call above.
        Some(unsafe { take(out) }.to_vec())
    }

    pub fn unprotect(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let input = blob(data);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: successful call above.
        Some(unsafe { take(out) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so tests stay fast; the format is the same.
    fn quick(master: &str) -> VaultKey {
        derive(
            master,
            KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                salt: [7; 16],
            },
        )
        .unwrap()
    }

    #[test]
    fn seal_and_open_round_trip() {
        let k = quick("correct horse");
        let file = seal(&k, b"secret connections");
        assert_eq!(&open(&k, &file).unwrap()[..], b"secret connections");
        assert_eq!(read_params(&file).unwrap(), k.params);
    }

    #[test]
    fn wrong_password_fails_without_data() {
        let file = seal(&quick("correct horse"), b"secret");
        let wrong = derive("battery staple", read_params(&file).unwrap()).unwrap();
        assert!(open(&wrong, &file).is_err());
    }

    #[test]
    fn any_tampering_fails_authentication() {
        let k = quick("pw");
        let file = seal(&k, b"secret");
        for i in [10, 22, 40, HEADER_LEN, file.len() - 1] {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(
                open(&k, &bad).is_err(),
                "byte {i} changed but the vault opened"
            );
        }
        assert!(read_params(b"not a vault at all, just text............................").is_err());
    }

    #[test]
    fn same_plaintext_gets_a_fresh_nonce() {
        let k = quick("pw");
        assert_ne!(seal(&k, b"x"), seal(&k, b"x"));
    }

    #[test]
    fn absurd_header_costs_are_refused() {
        let k = quick("pw");
        let mut file = seal(&k, b"x");
        file[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_params(&file).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_for_this_user() {
        let k = quick("pw");
        let blob = protect_key(&k).expect("DPAPI protect");
        let back = unprotect_key(&blob).expect("DPAPI unprotect");
        assert_eq!(*back.key, *k.key);
        assert_eq!(back.params, k.params);
    }
}
