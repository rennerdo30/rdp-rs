//! The agent's static X25519 key (HELPER-PROTOCOL.md 3.1): one per user,
//! generated once, stored protected (DPAPI, user scope, in `win::dpapi`) at
//! `%LOCALAPPDATA%\rdp-rs\agent-key.bin`.
//!
//! File: `"RAK1"`, `u32` little-endian length, the protected blob. The
//! blob's plaintext is `"RAKP"` and the 32-byte private key; the public
//! key is derived again. A file that cannot be read, parsed or unprotected
//! is moved to `agent-key.bin.old` and a new key is made; Remora then warns
//! the user about a changed key and asks to compare codes again, which is
//! correct: the old key is gone.

use std::io;
use std::path::{Path, PathBuf};

use remora_link::StaticKey;

const FILE_MAGIC: &[u8; 4] = b"RAK1";
const PLAIN_MAGIC: &[u8; 4] = b"RAKP";
/// Largest blob accepted (DPAPI adds a few hundred bytes to 36).
const MAX_BLOB: usize = 64 * 1024;

/// Encrypts and decrypts the key for this user (DPAPI on Windows).
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>>;
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

/// `%LOCALAPPDATA%\rdp-rs\agent-key.bin`.
pub fn default_key_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("rdp-rs").join("agent-key.bin"))
}

/// Overwrites a buffer in a way the optimizer keeps.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

pub fn encode_file(blob: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + blob.len());
    v.extend_from_slice(FILE_MAGIC);
    v.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    v.extend_from_slice(blob);
    v
}

/// The blob inside a key file, or why the file is unusable.
pub fn decode_file(data: &[u8]) -> Result<&[u8], &'static str> {
    if data.len() < 8 || &data[..4] != FILE_MAGIC {
        return Err("not an agent key file");
    }
    let n = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if n == 0 || n > MAX_BLOB || data.len() != 8 + n {
        return Err("key file has a bad length");
    }
    Ok(&data[8..])
}

fn plain_for(key: &StaticKey) -> Vec<u8> {
    let mut p = Vec::with_capacity(36);
    p.extend_from_slice(PLAIN_MAGIC);
    p.extend_from_slice(key.private());
    p
}

fn key_from_plain(plain: &[u8]) -> Result<StaticKey, &'static str> {
    if plain.len() != 36 || &plain[..4] != PLAIN_MAGIC {
        return Err("key file content is not a key");
    }
    let mut private = [0u8; 32];
    private.copy_from_slice(&plain[4..]);
    let key = StaticKey::from_private(&private).map_err(|_| "key cannot be used");
    wipe(&mut private);
    key
}

/// Reads the key, or makes and stores a new one.
pub fn load_or_create(
    path: &Path,
    protector: &dyn Protector,
    generate: &dyn Fn() -> io::Result<StaticKey>,
) -> io::Result<LoadedKey> {
    let reason = match std::fs::read(path) {
        Ok(data) => match load(&data, protector) {
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
    let save_error = save(path, &key, protector).err().map(|e| e.to_string());
    Ok(LoadedKey {
        key,
        origin: match reason {
            Some(r) => KeyOrigin::Replaced(r),
            None => KeyOrigin::Created,
        },
        save_error,
    })
}

fn load(data: &[u8], protector: &dyn Protector) -> Result<StaticKey, String> {
    let blob = decode_file(data).map_err(String::from)?;
    let mut plain = protector
        .unprotect(blob)
        .map_err(|e| format!("cannot decrypt the key file: {e}"))?;
    let key = key_from_plain(&plain).map_err(String::from);
    wipe(&mut plain);
    key
}

/// Protects and writes the key (temporary file, then rename).
pub fn save(path: &Path, key: &StaticKey, protector: &dyn Protector) -> io::Result<()> {
    let mut plain = plain_for(key);
    let blob = protector.protect(&plain);
    wipe(&mut plain);
    let data = encode_file(&blob?);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, &data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A stand-in for DPAPI: XOR with a byte plus a tag, so tampering and
    /// "another user" (another byte) fail like DPAPI would.
    struct FakeProtector {
        byte: u8,
        fail_protect: bool,
        calls: Cell<u32>,
    }

    impl FakeProtector {
        fn new(byte: u8) -> Self {
            FakeProtector {
                byte,
                fail_protect: false,
                calls: Cell::new(0),
            }
        }
    }

    impl Protector for FakeProtector {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            if self.fail_protect {
                return Err(io::Error::other("no protector"));
            }
            let mut v = vec![b'T', self.byte];
            v.extend(plain.iter().map(|b| b ^ self.byte));
            Ok(v)
        }
        fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
            if blob.len() < 2 || blob[0] != b'T' || blob[1] != self.byte {
                return Err(io::Error::other("bad blob"));
            }
            Ok(blob[2..].iter().map(|b| b ^ self.byte).collect())
        }
    }

    fn gen_() -> io::Result<StaticKey> {
        StaticKey::generate().map_err(|e| io::Error::other(e.to_string()))
    }

    fn temp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("remora-agent-key-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("sub").join("agent-key.bin")
    }

    #[test]
    fn create_then_load_same_key() {
        let path = temp("roundtrip");
        let p = FakeProtector::new(0x5A);
        let a = load_or_create(&path, &p, &gen_).unwrap();
        assert_eq!(a.origin, KeyOrigin::Created);
        assert!(a.save_error.is_none());
        let b = load_or_create(&path, &p, &gen_).unwrap();
        assert_eq!(b.origin, KeyOrigin::Loaded);
        assert_eq!(a.key.public(), b.key.public());
        // The private key is not in the file in the clear.
        let data = std::fs::read(&path).unwrap();
        assert!(!data.windows(32).any(|w| w == a.key.private().as_slice()));
        assert!(decode_file(&data).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn unusable_files_are_replaced_and_kept_once() {
        let path = temp("corrupt");
        let p = FakeProtector::new(0x11);
        let first = load_or_create(&path, &p, &gen_).unwrap().key.public();
        type Damage = Box<dyn Fn(&mut Vec<u8>)>;
        let cases: Vec<(&str, Damage)> = vec![
            ("magic", Box::new(|d: &mut Vec<u8>| d[0] = b'X')),
            (
                "truncated",
                Box::new(|d: &mut Vec<u8>| d.truncate(d.len() - 1)),
            ),
            ("trailing", Box::new(|d: &mut Vec<u8>| d.push(0))),
            ("tampered", Box::new(|d: &mut Vec<u8>| d[8] ^= 1)),
            ("empty", Box::new(|d: &mut Vec<u8>| d.clear())),
        ];
        let mut prev = first;
        for (what, damage) in cases {
            let mut data = std::fs::read(&path).unwrap();
            damage(&mut data);
            std::fs::write(&path, &data).unwrap();
            let r = load_or_create(&path, &p, &gen_).unwrap();
            assert!(
                matches!(r.origin, KeyOrigin::Replaced(_)),
                "{what}: {:?}",
                r.origin
            );
            assert_ne!(r.key.public(), prev, "{what}: a new key");
            let mut old = path.as_os_str().to_owned();
            old.push(".old");
            assert_eq!(std::fs::read(&old).unwrap(), data, "{what}: kept");
            // And the new one loads.
            let again = load_or_create(&path, &p, &gen_).unwrap();
            assert_eq!(again.origin, KeyOrigin::Loaded, "{what}");
            assert_eq!(again.key.public(), r.key.public());
            prev = r.key.public();
        }
        // Another user's protector cannot read it: replaced, not reused.
        let other = FakeProtector::new(0x22);
        let r = load_or_create(&path, &other, &gen_).unwrap();
        assert!(matches!(r.origin, KeyOrigin::Replaced(ref w) if w.contains("decrypt")));
        assert_ne!(r.key.public(), prev);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn save_failure_keeps_a_working_key() {
        let path = temp("nosave");
        let mut p = FakeProtector::new(1);
        p.fail_protect = true;
        let r = load_or_create(&path, &p, &gen_).unwrap();
        assert_eq!(r.origin, KeyOrigin::Created);
        assert!(r.save_error.is_some());
        assert!(!path.exists());
        assert_eq!(p.calls.get(), 1);
    }

    #[test]
    fn plaintext_format() {
        let k = gen_().unwrap();
        let plain = plain_for(&k);
        assert_eq!(&plain[..4], b"RAKP");
        assert_eq!(key_from_plain(&plain).unwrap().public(), k.public());
        assert!(key_from_plain(&plain[..35]).is_err());
        let mut bad = plain.clone();
        bad[0] = b'X';
        assert!(key_from_plain(&bad).is_err());
        assert_eq!(decode_file(&encode_file(b"abc")).unwrap(), b"abc");
        assert!(decode_file(&encode_file(b"")).is_err());
    }
}
