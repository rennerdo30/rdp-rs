//! The agent's static X25519 key (HELPER-PROTOCOL.md 3.1): one per user,
//! generated once, stored protected (DPAPI, user scope, in `win::dpapi`) at
//! `%LOCALAPPDATA%\rdp-rs\agent-key.bin`.
//!
//! The format and recovery rules are `remora_link::keyfile` (shared with
//! Remora's client key): `"RAK1"`, `u32` little-endian length, the
//! protected blob, whose plaintext is `"RAKP"` and the 32-byte private key.
//! A file that cannot be read, parsed or unprotected is moved to
//! `agent-key.bin.old` and a new key is made; Remora then warns the user
//! about a changed key and asks to compare codes again, which is correct:
//! the old key is gone.

use std::io;
use std::path::{Path, PathBuf};

use remora_link::StaticKey;
use remora_link::keyfile::{self, AGENT};
pub use remora_link::keyfile::{KeyOrigin, LoadedKey, Protector};

/// `%LOCALAPPDATA%\rdp-rs\agent-key.bin`.
pub fn default_key_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("rdp-rs").join("agent-key.bin"))
}

/// `%LOCALAPPDATA%\rdp-rs\agent-clients.json`: the Remora clients this
/// user confirmed (HELPER-PROTOCOL.md 4).
pub fn default_clients_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(
        PathBuf::from(base)
            .join("rdp-rs")
            .join("agent-clients.json"),
    )
}

#[cfg(test)]
fn encode_file(blob: &[u8]) -> Vec<u8> {
    keyfile::encode_file(AGENT, blob)
}

#[cfg(test)]
fn decode_file(data: &[u8]) -> Result<&[u8], &'static str> {
    keyfile::decode_file(AGENT, data)
}

#[cfg(test)]
fn plain_for(key: &StaticKey) -> Vec<u8> {
    keyfile::plain_for(AGENT, key).to_vec()
}

#[cfg(test)]
fn key_from_plain(plain: &[u8]) -> Result<StaticKey, &'static str> {
    keyfile::key_from_plain(AGENT, plain)
}

/// Reads the key, or makes and stores a new one.
pub fn load_or_create(
    path: &Path,
    protector: &dyn Protector,
    generate: &dyn Fn() -> io::Result<StaticKey>,
) -> io::Result<LoadedKey> {
    keyfile::load_or_create(AGENT, path, protector, generate)
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
