//! Pinned helper keys on the client, like SSH's `known_hosts`: the first
//! contact with a server's helper is confirmed by the user through the SAS,
//! then that helper's static public key is remembered for the server. A
//! later session with the same key pairs silently; a different key is
//! reported as changed and is never accepted without the user.
//!
//! The store is a JSON object `{ server id: { key, first_seen, last_seen } }`.
//! The app decides the file (for example `%LOCALAPPDATA%\rdp-rs\helpers.json`)
//! and the server id ([`server_id`]). Only public keys are stored.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::wire::{hex, unhex};

/// One pinned helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHelper {
    /// The helper's static X25519 public key, lower-case hex.
    pub key: String,
    /// Seconds since the Unix epoch when the user confirmed it.
    pub first_seen: u64,
    /// Seconds since the Unix epoch of the last session with it.
    #[serde(default)]
    pub last_seen: u64,
}

/// Result of [`PinStore::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinCheck {
    /// Pinned and identical: no SAS needed.
    Known,
    /// Nothing pinned for this server: first contact, confirm the SAS.
    New,
    /// A different key is pinned: warn, and pin the new one only if the
    /// user confirms the SAS again.
    Changed { previous: [u8; 32], first_seen: u64 },
}

/// The key a store uses for a server: lower-case `host:port`.
pub fn server_id(host: &str, port: u16) -> String {
    format!("{}:{port}", host.to_lowercase())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinStore {
    entries: BTreeMap<String, PinnedHelper>,
}

impl PinStore {
    pub fn new() -> PinStore {
        PinStore::default()
    }

    /// Parses a store. A malformed file is an error, never an empty store:
    /// treating it as empty would turn a changed key into a "new" one.
    pub fn from_json(bytes: &[u8]) -> Result<PinStore> {
        let entries: BTreeMap<String, PinnedHelper> = serde_json::from_slice(bytes)
            .map_err(|e| Error::Malformed(format!("pin store: {e}")))?;
        for (id, p) in &entries {
            if unhex::<32>(&p.key).is_none() {
                return Err(Error::Malformed(format!("pin store: bad key for {id}")));
            }
        }
        Ok(PinStore { entries })
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.entries).unwrap_or_default()
    }

    /// Loads `path`; a missing file is an empty store.
    pub fn load(path: &Path) -> Result<PinStore> {
        match std::fs::read(path) {
            Ok(b) => PinStore::from_json(&b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PinStore::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes `path` through a temporary file and a rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, self.to_json())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn check(&self, server: &str, key: &[u8; 32]) -> PinCheck {
        match self.entries.get(server) {
            None => PinCheck::New,
            Some(p) => match unhex::<32>(&p.key) {
                Some(k) if k == *key => PinCheck::Known,
                Some(k) => PinCheck::Changed {
                    previous: k,
                    first_seen: p.first_seen,
                },
                // from_json rejects bad keys; a bad one here still never matches.
                None => PinCheck::Changed {
                    previous: [0; 32],
                    first_seen: p.first_seen,
                },
            },
        }
    }

    /// Pins `key` for `server` (after the user confirmed the SAS).
    pub fn pin(&mut self, server: &str, key: &[u8; 32], now: u64) {
        self.entries.insert(
            server.to_string(),
            PinnedHelper {
                key: hex(key),
                first_seen: now,
                last_seen: now,
            },
        );
    }

    /// Records a session with an already pinned key.
    pub fn touch(&mut self, server: &str, now: u64) {
        if let Some(p) = self.entries.get_mut(server) {
            p.last_seen = now;
        }
    }

    pub fn forget(&mut self, server: &str) -> bool {
        self.entries.remove(server).is_some()
    }

    pub fn get(&self, server: &str) -> Option<&PinnedHelper> {
        self.entries.get(server)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PinnedHelper)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_known_changed() {
        let mut s = PinStore::new();
        let id = server_id("Host.Example", 3389);
        assert_eq!(id, "host.example:3389");
        assert_eq!(s.check(&id, &[1; 32]), PinCheck::New);
        s.pin(&id, &[1; 32], 100);
        assert_eq!(s.check(&id, &[1; 32]), PinCheck::Known);
        assert_eq!(
            s.check(&id, &[2; 32]),
            PinCheck::Changed {
                previous: [1; 32],
                first_seen: 100
            }
        );
        // Another port is another server.
        assert_eq!(
            s.check(&server_id("host.example", 3390), &[1; 32]),
            PinCheck::New
        );
    }

    #[test]
    fn json_round_trip_and_files() {
        let mut s = PinStore::new();
        s.pin("a:1", &[0xAB; 32], 5);
        s.touch("a:1", 9);
        let back = PinStore::from_json(&s.to_json()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.get("a:1").unwrap().last_seen, 9);
        let dir = std::env::temp_dir().join(format!("remora-link-pins-{}", std::process::id()));
        let p = dir.join("helpers.json");
        assert_eq!(
            PinStore::load(&p).unwrap(),
            PinStore::new(),
            "missing = empty"
        );
        s.save(&p).unwrap();
        assert_eq!(PinStore::load(&p).unwrap(), s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_store_is_an_error_not_empty() {
        assert!(PinStore::from_json(b"not json").is_err());
        assert!(PinStore::from_json(br#"{"a:1":{"key":"zz","first_seen":1}}"#).is_err());
        assert!(PinStore::from_json(b"{}").unwrap().iter().next().is_none());
    }
}
