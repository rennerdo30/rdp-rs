//! A long-term static key in a file, protected for the current user
//! (Windows DPAPI on both ends: the helper's key on the server, Remora's
//! client key on the client). The platform protection comes in through
//! [`Protector`]; this module owns the format and the recovery rules.
//!
//! File: 4-byte file magic, `u32` little-endian length, the protected blob.
//! The blob's plaintext is a 4-byte plain magic and the 32-byte private
//! key; the public key is derived again.
//!
//! A key is replaced only when its file is definitely unusable: it does
//! not parse, or the platform refuses to decrypt it on every one of
//! [`ATTEMPTS`] tries. The file is then kept as `<file>.old.<n>` (a new
//! number each time, never overwritten) and a new key is made: the peer
//! sees a changed key and asks to compare codes again, which is correct,
//! because the old key is gone. A file that cannot be read (locked, no
//! access) is retried and then an error: a transient problem never
//! rotates the key. Creating and replacing happen under the file's lock
//! (`<file>.lock`), and the file is read again under it, so two processes
//! starting at once end with one key.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::StaticKey;

/// Largest blob accepted (DPAPI adds a few hundred bytes to 36).
const MAX_BLOB: usize = 64 * 1024;
/// Reads and decrypts tried before giving up (read) or replacing (decrypt).
pub const ATTEMPTS: u32 = 3;
const RETRY_PAUSE: Duration = Duration::from_millis(50);
/// Numbered backups of unusable key files kept at most.
const MAX_BACKUPS: u32 = 100;

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

/// What reading the key file found.
enum Found {
    Key(StaticKey),
    Missing,
    /// Definitely unusable (the reason, and the bytes to keep).
    Unusable(String, Vec<u8>),
}

/// Reads and decrypts the key file. Read errors other than "missing" are
/// retried, then returned; a decrypt failure is retried, then unusable.
fn read_key(format: Format, path: &Path, protector: &dyn Protector) -> io::Result<Found> {
    let mut tries = 0;
    loop {
        tries += 1;
        let last = tries >= ATTEMPTS;
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Found::Missing),
            Err(e) if last => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot read the key file: {e}"),
                ));
            }
            Err(_) => {
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };
        let blob = match decode_file(format, &data) {
            Ok(b) => b,
            Err(why) => return Ok(Found::Unusable(why.into(), data)),
        };
        let plain = match protector.unprotect(blob) {
            Ok(p) => Zeroizing::new(p),
            Err(e) if last => {
                return Ok(Found::Unusable(
                    format!("cannot decrypt the key file: {e}"),
                    data,
                ));
            }
            Err(_) => {
                std::thread::sleep(RETRY_PAUSE);
                continue;
            }
        };
        return Ok(match key_from_plain(format, &plain) {
            Ok(k) => Found::Key(k),
            Err(why) => Found::Unusable(why.into(), data),
        });
    }
}

/// Keeps an unusable key file's bytes as `<file>.old.<n>`, a number not
/// used yet (never overwrites an earlier backup).
fn back_up(path: &Path, data: &[u8]) -> io::Result<PathBuf> {
    use std::io::Write;
    for n in 1..=MAX_BACKUPS {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".old.{n}"));
        let backup = PathBuf::from(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup)
        {
            Ok(mut f) => {
                f.write_all(data)?;
                f.sync_all()?;
                return Ok(backup);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("too many old key files to keep another"))
}

/// Reads the key, or makes and stores a new one (see the module docs for
/// when a key is replaced). An error means no key could be loaded or made
/// safely; nothing was replaced then.
pub fn load_or_create(
    format: Format,
    path: &Path,
    protector: &dyn Protector,
    generate: &dyn Fn() -> io::Result<StaticKey>,
) -> io::Result<LoadedKey> {
    if let Found::Key(key) = read_key(format, path, protector)? {
        return Ok(LoadedKey {
            key,
            origin: KeyOrigin::Loaded,
            save_error: None,
        });
    }
    // Missing or unusable: decide again under the lock, where another
    // process may have made the key meanwhile.
    let under_lock = crate::store::locked(path, crate::store::LOCK_WAIT, || {
        let reason = match read_key(format, path, protector)? {
            Found::Key(key) => {
                return Ok(LoadedKey {
                    key,
                    origin: KeyOrigin::Loaded,
                    save_error: None,
                });
            }
            Found::Missing => None,
            Found::Unusable(why, data) => {
                back_up(path, &data)?;
                Some(why)
            }
        };
        let key = generate()?;
        let save_error = write_key(format, path, &key, protector)
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
    });
    match under_lock {
        Ok(k) => Ok(k),
        // The settings folder cannot even hold a lock file (read-only,
        // missing rights): a key for this process only, as when saving fails.
        Err(e) if e.kind() != io::ErrorKind::WouldBlock && !path.exists() => Ok(LoadedKey {
            key: generate()?,
            origin: KeyOrigin::Created,
            save_error: Some(e.to_string()),
        }),
        Err(e) => Err(e),
    }
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

/// Protects and writes the key under the file's lock (a unique temporary
/// file created new, then a rename). The file is for this user only where
/// the platform has modes.
pub fn save(
    format: Format,
    path: &Path,
    key: &StaticKey,
    protector: &dyn Protector,
) -> io::Result<()> {
    crate::store::locked(path, crate::store::LOCK_WAIT, || {
        write_key(format, path, key, protector)
    })
}

/// [`save`] with the lock already held.
fn write_key(
    format: Format,
    path: &Path,
    key: &StaticKey,
    protector: &dyn Protector,
) -> io::Result<()> {
    let plain = plain_for(format, key);
    let data = encode_file(format, &protector.protect(&plain)?);
    crate::store::write_new_then_rename(path, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// XOR "protection" that can fail its first `fail_unprotect` decrypts
    /// and is slow to protect (widens a creation race).
    struct Flaky {
        fail_unprotect: AtomicU32,
        slow: Duration,
    }

    impl Flaky {
        fn new(fail_unprotect: u32, slow: Duration) -> Flaky {
            Flaky {
                fail_unprotect: AtomicU32::new(fail_unprotect),
                slow,
            }
        }
    }

    impl Protector for Flaky {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            std::thread::sleep(self.slow);
            Ok(plain.iter().map(|b| b ^ 0x5A).collect())
        }
        fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
            let left = self.fail_unprotect.load(Ordering::SeqCst);
            if left > 0 {
                self.fail_unprotect.store(left - 1, Ordering::SeqCst);
                return Err(io::Error::other("busy"));
            }
            Ok(blob.iter().map(|b| b ^ 0x5A).collect())
        }
    }

    fn gen_() -> io::Result<StaticKey> {
        StaticKey::generate().map_err(|e| io::Error::other(e.to_string()))
    }

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("remora-link-key-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("k.bin")
    }

    /// Review 2 item 7: a file that cannot be read right now is an error,
    /// never a reason to make a new key; a decrypt that fails a few times
    /// and then works keeps the key.
    #[test]
    fn transient_errors_never_rotate_the_key() {
        let path = temp("transient");
        // A folder where the file should be: reading it fails, not "missing".
        std::fs::create_dir_all(&path).unwrap();
        let p = Flaky::new(0, Duration::ZERO);
        assert!(load_or_create(CLIENT, &path, &p, &gen_).is_err());
        assert!(path.is_dir(), "left alone");
        std::fs::remove_dir(&path).unwrap();
        let first = load_or_create(CLIENT, &path, &p, &gen_).unwrap();
        assert_eq!(first.origin, KeyOrigin::Created);
        let p = Flaky::new(ATTEMPTS - 1, Duration::ZERO);
        let again = load_or_create(CLIENT, &path, &p, &gen_).unwrap();
        assert_eq!(again.origin, KeyOrigin::Loaded);
        assert_eq!(again.key.public(), first.key.public());
        // Refused every time: definitely unusable, replaced.
        let p = Flaky::new(u32::MAX, Duration::ZERO);
        let r = load_or_create(CLIENT, &path, &p, &gen_).unwrap();
        assert!(matches!(r.origin, KeyOrigin::Replaced(ref w) if w.contains("decrypt")));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Review 2 item 7: every replaced file is kept under a new number.
    #[test]
    fn backups_are_numbered_and_never_overwritten() {
        let path = temp("backups");
        let p = Flaky::new(0, Duration::ZERO);
        load_or_create(CLIENT, &path, &p, &gen_).unwrap();
        for n in 1..=3u8 {
            std::fs::write(&path, [b'X', n]).unwrap();
            let r = load_or_create(CLIENT, &path, &p, &gen_).unwrap();
            assert!(matches!(r.origin, KeyOrigin::Replaced(_)));
        }
        for n in 1..=3u8 {
            let mut b = path.as_os_str().to_owned();
            b.push(format!(".old.{n}"));
            assert_eq!(std::fs::read(PathBuf::from(b)).unwrap(), [b'X', n]);
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Review 2 item 7: two processes making the key at once end with one
    /// key, the one in the file.
    #[test]
    fn racing_creators_end_with_one_key() {
        let path = temp("race");
        let p = Arc::new(Flaky::new(0, Duration::from_millis(100)));
        let start = Arc::new(std::sync::Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (path, p, start) = (path.clone(), p.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    load_or_create(CLIENT, &path, &*p, &gen_)
                        .unwrap()
                        .key
                        .public()
                })
            })
            .collect();
        let keys: Vec<[u8; 32]> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let on_disk = load_existing(CLIENT, &path, &*p).unwrap().public();
        assert!(keys.iter().all(|k| *k == on_disk), "one key");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
