//! Remora's own Remora-Link key (HELPER-PROTOCOL.md 3.1, 4): one X25519
//! key per Windows user, so a server helper can pin this PC and send data
//! (files, links) only to a client it knows. Stored DPAPI-protected (user
//! scope) in `%APPDATA%\rdp-rs\link-client-key.bin`; elsewhere (tests,
//! previews) unprotected with mode 0600. Format and recovery rules are
//! `remora_link::keyfile` (shared with the helper's key): an unusable file
//! is kept as `.old` and a new key made, which the helpers then ask to
//! confirm again.

use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use remora_link::StaticKey;
use remora_link::keyfile::{self, CLIENT, KeyOrigin, Protector};

/// `%APPDATA%\rdp-rs\link-client-key.bin`.
pub fn path() -> Option<PathBuf> {
    crate::store::data_dir().map(|d| d.join("link-client-key.bin"))
}

/// DPAPI, current user (the vault's binding).
#[cfg(windows)]
struct Dpapi;

#[cfg(windows)]
impl Protector for Dpapi {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        crate::vault::dpapi::protect(plain).ok_or_else(|| io::Error::other("DPAPI refused"))
    }
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
        crate::vault::dpapi::unprotect(blob)
            .map(|z| z.to_vec())
            .ok_or_else(|| io::Error::other("DPAPI could not decrypt"))
    }
}

fn protector() -> &'static dyn Protector {
    #[cfg(windows)]
    {
        &Dpapi
    }
    #[cfg(not(windows))]
    {
        &keyfile::Plain
    }
}

fn generate() -> io::Result<StaticKey> {
    StaticKey::generate().map_err(|e| io::Error::other(e.to_string()))
}

/// The key, loaded (or made) once per process. Without a usable file it
/// lives for this process only: helpers then ask to confirm this PC on
/// every start, which is safe.
pub fn key() -> StaticKey {
    static KEY: OnceLock<StaticKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let loaded = path().map(|p| keyfile::load_or_create(CLIENT, &p, protector(), &generate));
        match loaded {
            Some(Ok(k)) => {
                if let KeyOrigin::Replaced(why) = &k.origin {
                    rdp::trace!("link key replaced: {why}");
                }
                if let Some(e) = &k.save_error {
                    rdp::trace!("link key not saved: {e}");
                }
                k.key
            }
            _ => StaticKey::generate().expect("OS random generator"),
        }
    })
    .clone()
}

/// This PC's fingerprint, for `remora-agent trust-client` on a server
/// (Settings → Security).
pub fn fingerprint() -> String {
    remora_link::fingerprint(&key().public())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client key survives a restart (same file, same key) and is not
    /// in the file in the clear.
    #[test]
    fn the_client_key_is_kept_and_protected() {
        let dir = std::env::temp_dir().join(format!("remora-link-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("link-client-key.bin");
        let a = keyfile::load_or_create(CLIENT, &p, protector(), &generate).unwrap();
        assert_eq!(a.origin, KeyOrigin::Created);
        let b = keyfile::load_or_create(CLIENT, &p, protector(), &generate).unwrap();
        assert_eq!(b.origin, KeyOrigin::Loaded);
        assert_eq!(a.key.public(), b.key.public());
        let data = std::fs::read(&p).unwrap();
        assert_eq!(&data[..4], b"RCK1");
        #[cfg(windows)]
        assert!(
            !data.windows(32).any(|w| w == a.key.private().as_slice()),
            "DPAPI-protected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
