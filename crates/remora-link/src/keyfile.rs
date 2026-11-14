//! A long-term static key in a file, protected for the current user
//! (Windows DPAPI on both ends: the helper's key on the server, Remora's
//! client key on the client). The platform protection comes in through
//! [`Protector`]; this module owns the format and the recovery rules.
//!
//! File: 4-byte file magic, `u32` little-endian length, the protected blob.
//! The blob's plaintext is a 4-byte plain magic and the 32-byte private
//! key; the public key is derived again. A file that cannot be read,
//! parsed or unprotected is moved to `<file>.old` and a new key is made:
//! the peer then sees a changed key and asks to compare codes again, which
//! is correct, because the old key is gone.

use std::io;
use std::path::Path;

use zeroize::Zeroizing;

use crate::StaticKey;

/// Largest blob accepted (DPAPI adds a few hundred bytes to 36).
const MAX_BLOB: usize = 64 * 1024;

/// The magics that tell one kind of key file from another.
#[derive(Clone, Copy, Debug)]
pub struct Format {
    pub file: [u8; 4],
    pub plain: [u8; 4],
}

/// The helper's key (`agent-key.bin`).
pub const AGENT: Format = Format {
    file: *b"RAK1",
    plain: *b"RAKP",
};

/// Remora's client key (`link-client-key.bin`).
pub const CLIENT: Format = Format {
    file: *b"RCK1",
    plain: *b"RCKP",
};

/// Encrypts and decrypts the key for this user (DPAPI on Windows).
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>>;
}

/// No protection: only for platforms without DPAPI (tests, previews); the
/// file is then readable by the user alone (mode 0600 where supported).
pub struct Plain;

impl Protector for Plain {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        Ok(plain.to_vec())
    }
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
        Ok(blob.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Read from the file.
    Loaded,
    /// No file yet: a new key.
    Created,
    /// The file was unusable (the reason, without key material): a new key.
    Replaced(String),
}

pub struct LoadedKey {
    pub key: StaticKey,
    pub origin: KeyOrigin,
    /// Writing the new key failed: it lives for this process only.
    pub save_error: Option<String>,
}

pub fn encode_file(format: Format, blob: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + blob.len());
    v.extend_from_slice(&format.file);
    v.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    v.extend_from_slice(blob);
    v
}

/// The blob inside a key file, or why the file is unusable.
pub fn decode_file(format: Format, data: &[u8]) -> Result<&[u8], &'static str> {
    if data.len() < 8 || data[..4] != format.file {
        return Err("not a key file of this kind");
    }
    let n = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if n == 0 || n > MAX_BLOB || data.len() != 8 + n {
        return Err("key file has a bad length");
    }
    Ok(&data[8..])
}

pub fn plain_for(format: Format, key: &StaticKey) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::with_capacity(36));
    p.extend_from_slice(&format.plain);
    p.extend_from_slice(key.private());
    p
}

pub fn key_from_plain(format: Format, plain: &[u8]) -> Result<StaticKey, &'static str> {
    if plain.len() != 36 || plain[..4] != format.plain {
        return Err("key file content is not a key");
    }
    let mut private = Zeroizing::new([0u8; 32]);
    private.copy_from_slice(&plain[4..]);
    StaticKey::from_private(&private).map_err(|_| "key cannot be used")
}

/// Reads the key, or makes and stores a new one.
pub fn load_or_create(
    format: Format,
    path: &Path,
    protector: &dyn Protector,
    generate: &dyn Fn() -> io::Result<StaticKey>,
) -> io::Result<LoadedKey> {
    let reason = match std::fs::read(path) {
        Ok(data) => match load(format, &data, protector) {
            Ok(key) => {
                return Ok(LoadedKey {
                    key,
                    origin: KeyOrigin::Loaded,
                    save_error: None,
                });
            }
            Err(why) => Some(why),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => Some(format!("cannot read the key file: {e}")),
    };
    let key = generate()?;
    let mut old = path.as_os_str().to_owned();
    old.push(".old");
    if reason.is_some() {
        // Keep the unusable file once, for diagnosis; replaces an older one.
        let _ = std::fs::rename(path, &old);
    }
    let save_error = save(format, path, &key, protector)
        .err()
        .map(|e| e.to_string());
    Ok(LoadedKey {
        key,
        origin: match reason {
            Some(r) => KeyOrigin::Replaced(r),
            None => KeyOrigin::Created,
        },
        save_error,
    })
}

/// Reads an existing key file without making one.
pub fn load_existing(
    format: Format,
    path: &Path,
    protector: &dyn Protector,
) -> io::Result<StaticKey> {
    let data = std::fs::read(path)?;
    load(format, &data, protector).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn load(format: Format, data: &[u8], protector: &dyn Protector) -> Result<StaticKey, String> {
    let blob = decode_file(format, data).map_err(String::from)?;
    let plain = Zeroizing::new(
        protector
            .unprotect(blob)
            .map_err(|e| format!("cannot decrypt the key file: {e}"))?,
    );
    key_from_plain(format, &plain).map_err(String::from)
}

/// Protects and writes the key (temporary file, then rename). The file is
/// for this user only where the platform has modes.
pub fn save(
    format: Format,
    path: &Path,
    key: &StaticKey,
    protector: &dyn Protector,
) -> io::Result<()> {
    let plain = plain_for(format, key);
    let data = encode_file(format, &protector.protect(&plain)?);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
