//! Pinned keys, like SSH's `known_hosts`.
//!
//! - [`PinStore`] (client, `helpers.json`): the helper key per server and
//!   user. The first contact is confirmed by the user through the SAS (or
//!   an admin-set fingerprint); a later session with the same key pairs
//!   silently; a different key is reported as changed and never accepted
//!   without the user.
//! - [`AttemptLog`] (client, `helper-attempts.json`): pairings that ended
//!   before the user answered, per server; three within 24 hours block
//!   pairing with that server until the user retries (HELPER-PROTOCOL.md
//!   3.3: the 10^-6 SAS bound holds only with this limit).
//! - [`ClientStore`] (helper, `agent-clients.json`): the Remora client keys
//!   the user confirmed on the server.
//!
//! Every change goes through [`crate::store::update`]: re-read, merge and
//! write under a lock file, through a unique temporary file and a rename.
//! Only public keys are stored.

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

/// A server as the user names it: lower-case `host:port`. Forgetting a
/// server and listing paired servers use this form.
pub fn server_id(host: &str, port: u16) -> String {
    format!("{}:{port}", host.to_lowercase())
}

/// The key a [`PinStore`] uses for a helper: `user@host:port` in lower
/// case, because the helper's key is per user on the server. Without a
/// user name (it is asked at logon) the key is the plain [`server_id`].
///
/// Migration: stores written before helper keys were per user hold plain
/// `host:port` keys. A lookup for `user@host:port` without its own entry
/// uses that `host:port` entry as the same pin; pinning then writes the
/// user's own entry and drops the plain one if it holds the same key.
pub fn pin_id(host: &str, port: u16, user: &str) -> String {
    let user = user.trim();
    if user.is_empty() {
        server_id(host, port)
    } else {
        format!("{}@{}", user.to_lowercase(), server_id(host, port))
    }
}

/// The `host:port` part of a [`pin_id`] (user names may contain `@`;
/// host names never do).
pub fn host_part(id: &str) -> &str {
    id.rsplit_once('@').map_or(id, |(_, h)| h)
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

    /// Writes `path` whole (unique temporary file, then a rename). Use
    /// [`PinStore::update`] for a change: it merges with other writers.
    pub fn save(&self, path: &Path) -> Result<()> {
        crate::store::write_atomic(path, &self.to_json())?;
        Ok(())
    }

    /// Re-reads `path`, applies `change` and writes the result, under the
    /// store's lock. A malformed store is left alone (an error).
    pub fn update<R>(path: &Path, change: impl FnOnce(&mut PinStore) -> R) -> Result<R> {
        crate::store::update(path, |cur| {
            let mut s = match cur {
                Some(b) => PinStore::from_json(&b)?,
                None => PinStore::new(),
            };
            let before = s.clone();
            let r = change(&mut s);
            Ok(((s != before).then(|| s.to_json()), r))
        })
    }

    /// The entry for `id`, or for its plain `host:port` (migration).
    fn entry(&self, id: &str) -> Option<&PinnedHelper> {
        self.entries
            .get(id)
            .or_else(|| self.entries.get(host_part(id)))
    }

    pub fn check(&self, id: &str, key: &[u8; 32]) -> PinCheck {
        match self.entry(id) {
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

    /// Pins `key` for `id` (after the user confirmed the SAS). A plain
    /// `host:port` entry with the same key has become this one.
    pub fn pin(&mut self, id: &str, key: &[u8; 32], now: u64) {
        let host = host_part(id);
        if host != id
            && self
                .entries
                .get(host)
                .is_some_and(|p| unhex::<32>(&p.key) == Some(*key))
        {
            self.entries.remove(host);
        }
        self.entries.insert(
            id.to_string(),
            PinnedHelper {
                key: hex(key),
                first_seen: now,
                last_seen: now,
            },
        );
    }

    /// Records a session with an already pinned key.
    pub fn touch(&mut self, id: &str, now: u64) {
        let id = if self.entries.contains_key(id) {
            id
        } else {
            host_part(id)
        };
        if let Some(p) = self.entries.get_mut(id) {
            p.last_seen = now;
        }
    }

    pub fn forget(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Forgets every helper pinned for a server (`host:port`), for all
    /// users. Returns how many were removed.
    pub fn forget_server(&mut self, server: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|id, _| host_part(id) != server);
        before - self.entries.len()
    }

    pub fn get(&self, id: &str) -> Option<&PinnedHelper> {
        self.entries.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PinnedHelper)> {
        self.entries.iter()
    }

    /// The servers (`host:port`) with at least one pinned helper.
    pub fn servers(&self) -> std::collections::BTreeSet<String> {
        self.entries
            .keys()
            .map(|id| host_part(id).to_string())
            .collect()
    }
}

/// Pairings that may end before the user answers, per server, within
/// [`ATTEMPT_WINDOW`] seconds.
pub const MAX_ABORTS: usize = 3;
/// The window [`MAX_ABORTS`] counts in (24 hours).
pub const ATTEMPT_WINDOW: u64 = 24 * 3600;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Attempts {
    /// When pairings ended unanswered (seconds since the Unix epoch).
    #[serde(default)]
    aborts: Vec<u64>,
    /// Pairing is blocked until the user retries.
    #[serde(default)]
    blocked: bool,
}

/// Aborted pairings per server (`helper-attempts.json`): an attacker in the
/// middle that silently drops pairings until the codes happen to match is
/// stopped after [`MAX_ABORTS`] tries a day, and the user is told.
pub struct AttemptLog;

impl AttemptLog {
    fn read(bytes: Option<Vec<u8>>) -> BTreeMap<String, Attempts> {
        // A damaged log is started over (it only ever blocks, never trusts).
        bytes
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Records a pairing for `id` that ended before the user answered.
    /// Returns whether pairing with that server is now blocked.
    pub fn record_abort(path: &Path, id: &str, now: u64) -> Result<bool> {
        crate::store::update(path, |cur| {
            let mut log = AttemptLog::read(cur);
            let a = log.entry(id.to_string()).or_default();
            a.aborts.retain(|&t| t + ATTEMPT_WINDOW > now && t <= now);
            a.aborts.push(now);
            if a.aborts.len() >= MAX_ABORTS {
                a.blocked = true;
            }
            let blocked = a.blocked;
            let json =
                serde_json::to_vec_pretty(&log).map_err(|e| Error::Malformed(e.to_string()))?;
            Ok((Some(json), blocked))
        })
    }

    /// Pairing with `id` is blocked (until [`AttemptLog::clear`]).
    pub fn is_blocked(path: &Path, id: &str) -> bool {
        AttemptLog::read(std::fs::read(path).ok())
            .get(id)
            .is_some_and(|a| a.blocked)
    }

    /// The user retries pairing with `id`: forget its aborts and the block.
    pub fn clear(path: &Path, id: &str) -> Result<()> {
        crate::store::update(path, |cur| {
            let mut log = AttemptLog::read(cur);
            if log.remove(id).is_none() {
                return Ok((None, ()));
            }
            let json =
                serde_json::to_vec_pretty(&log).map_err(|e| Error::Malformed(e.to_string()))?;
            Ok((Some(json), ()))
        })
    }
}

/// One Remora client the user confirmed on the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedClient {
    /// The client's static X25519 public key, lower-case hex; empty for a
    /// client pre-seeded by its fingerprint only (`trust-client`).
    #[serde(default)]
    pub key: String,
    /// Seconds since the Unix epoch when it was pinned.
    pub first_seen: u64,
    /// What the client called itself (untrusted, for the list only).
    #[serde(default)]
    pub label: String,
}

/// The helper's pinned Remora clients (`agent-clients.json`), keyed by the
/// client key's fingerprint ([`crate::fingerprint`], 40 hex digits): a
/// fingerprint alone (an admin pre-seeding a client) is a full pin.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientStore {
    entries: BTreeMap<String, PinnedClient>,
}

impl ClientStore {
    pub fn new() -> ClientStore {
        ClientStore::default()
    }

    pub fn from_json(bytes: &[u8]) -> Result<ClientStore> {
        let entries: BTreeMap<String, PinnedClient> = serde_json::from_slice(bytes)
            .map_err(|e| Error::Malformed(format!("client store: {e}")))?;
        for (fp, c) in &entries {
            let fp_ok = unhex::<{ crate::FINGERPRINT_LEN }>(fp).is_some();
            let key_ok = c.key.is_empty()
                || unhex::<32>(&c.key)
                    .is_some_and(|k| crate::fingerprint_bytes(&k) == unhex(fp).unwrap_or_default());
            if !fp_ok || !key_ok {
                return Err(Error::Malformed(format!("client store: bad entry {fp}")));
            }
        }
        Ok(ClientStore { entries })
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.entries).unwrap_or_default()
    }

    /// Loads `path`; a missing file is an empty store.
    pub fn load(path: &Path) -> Result<ClientStore> {
        match std::fs::read(path) {
            Ok(b) => ClientStore::from_json(&b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ClientStore::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Re-reads `path`, applies `change` and writes the result under the
    /// store's lock. A malformed store is left alone (an error).
    pub fn update<R>(path: &Path, change: impl FnOnce(&mut ClientStore) -> R) -> Result<R> {
        crate::store::update(path, |cur| {
            let mut s = match cur {
                Some(b) => ClientStore::from_json(&b)?,
                None => ClientStore::new(),
            };
            let before = s.clone();
            let r = change(&mut s);
            Ok(((s != before).then(|| s.to_json()), r))
        })
    }

    pub fn is_pinned(&self, key: &[u8; 32]) -> bool {
        self.entries
            .contains_key(&hex(&crate::fingerprint_bytes(key)))
    }

    /// Pins a client key the user confirmed (keeps an existing entry's date).
    pub fn pin(&mut self, key: &[u8; 32], label: &str, now: u64) {
        let fp = hex(&crate::fingerprint_bytes(key));
        let e = self.entries.entry(fp).or_insert(PinnedClient {
            key: String::new(),
            first_seen: now,
            label: String::new(),
        });
        e.key = hex(key);
        if !label.is_empty() {
            e.label = label.to_string();
        }
    }

    /// Pins a client by its fingerprint alone (`remora-agent trust-client`).
    pub fn trust(&mut self, fp: &[u8; crate::FINGERPRINT_LEN], label: &str, now: u64) -> bool {
        let id = hex(fp);
        if self.entries.contains_key(&id) {
            return false;
        }
        self.entries.insert(
            id,
            PinnedClient {
                key: String::new(),
                first_seen: now,
                label: label.to_string(),
            },
        );
        true
    }

    /// Forgets the client with this fingerprint.
    pub fn forget(&mut self, fp: &[u8; crate::FINGERPRINT_LEN]) -> bool {
        self.entries.remove(&hex(fp)).is_some()
    }

    /// `(fingerprint, entry)` in fingerprint order.
    pub fn iter(&self) -> impl Iterator<Item = ([u8; crate::FINGERPRINT_LEN], &PinnedClient)> {
        self.entries
            .iter()
            .filter_map(|(fp, c)| unhex(fp).map(|f| (f, c)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("remora-link-pins-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn new_known_changed() {
        let mut s = PinStore::new();
        let id = pin_id("Host.Example", 3389, "");
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
            s.check(&pin_id("host.example", 3390, ""), &[1; 32]),
            PinCheck::New
        );
    }

    /// Helper keys are per user on the server: two users of one server
    /// have their own pins, and a plain `host:port` pin from before counts
    /// for a user until that user's own entry exists.
    #[test]
    fn pins_are_per_user_and_migrate_from_host_only_entries() {
        let mut s = PinStore::new();
        s.pin("srv:3389", &[1; 32], 5); // written by the older version
        let alice = pin_id("SRV", 3389, r"CORP\Alice");
        let bob = pin_id("srv", 3389, "bob@corp.example");
        assert_eq!(alice, r"corp\alice@srv:3389");
        assert_eq!(host_part(&bob), "srv:3389");
        assert_eq!(s.check(&alice, &[1; 32]), PinCheck::Known, "migrated");
        assert!(matches!(s.check(&bob, &[2; 32]), PinCheck::Changed { .. }));
        // Bob confirms his own helper: his entry; the plain one stays for Alice.
        s.pin(&bob, &[2; 32], 6);
        assert_eq!(s.check(&bob, &[2; 32]), PinCheck::Known);
        assert_eq!(s.check(&alice, &[1; 32]), PinCheck::Known);
        // Alice re-pins the same key: the plain entry became hers.
        s.pin(&alice, &[1; 32], 7);
        assert!(s.get("srv:3389").is_none());
        assert_eq!(s.servers().into_iter().collect::<Vec<_>>(), ["srv:3389"]);
        assert_eq!(s.forget_server("srv:3389"), 2);
        assert!(s.iter().next().is_none());
    }

    #[test]
    fn json_round_trip_and_files() {
        let mut s = PinStore::new();
        s.pin("a:1", &[0xAB; 32], 5);
        s.touch("a:1", 9);
        let back = PinStore::from_json(&s.to_json()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.get("a:1").unwrap().last_seen, 9);
        let dir = temp("files");
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

    /// Review 14: two windows pinning different servers at the same time
    /// both keep their pin (each update re-reads under the lock).
    #[test]
    fn concurrent_pins_from_two_windows_are_both_kept() {
        let dir = temp("race");
        let p = dir.join("helpers.json");
        let threads: Vec<_> = (0..6u8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    PinStore::update(&p, |s| s.pin(&format!("h{i}:3389"), &[i; 32], 1)).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(PinStore::load(&p).unwrap().iter().count(), 6);
        // A malformed store is never overwritten by an update.
        std::fs::write(&p, b"garbage").unwrap();
        assert!(PinStore::update(&p, |s| s.pin("x:1", &[9; 32], 1)).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"garbage");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_store_is_an_error_not_empty() {
        assert!(PinStore::from_json(b"not json").is_err());
        assert!(PinStore::from_json(br#"{"a:1":{"key":"zz","first_seen":1}}"#).is_err());
        assert!(PinStore::from_json(b"{}").unwrap().iter().next().is_none());
    }

    #[test]
    fn three_aborts_in_a_day_block_until_cleared() {
        let dir = temp("attempts");
        let p = dir.join("helper-attempts.json");
        let day = ATTEMPT_WINDOW;
        assert!(!AttemptLog::record_abort(&p, "s:1", 1000).unwrap());
        // An old one falls out of the window.
        assert!(!AttemptLog::record_abort(&p, "s:1", 1000 + day).unwrap());
        assert!(!AttemptLog::record_abort(&p, "s:1", 1001 + day).unwrap());
        assert!(!AttemptLog::is_blocked(&p, "s:1"));
        assert!(AttemptLog::record_abort(&p, "s:1", 1002 + day).unwrap());
        assert!(AttemptLog::is_blocked(&p, "s:1"));
        assert!(!AttemptLog::is_blocked(&p, "other:1"), "per server");
        // Blocked stays blocked, however old the aborts get...
        assert!(AttemptLog::record_abort(&p, "s:1", 10 * day).unwrap());
        // ...until the user retries.
        AttemptLog::clear(&p, "s:1").unwrap();
        assert!(!AttemptLog::is_blocked(&p, "s:1"));
        assert!(!AttemptLog::record_abort(&p, "s:1", 10 * day).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_store_pins_by_fingerprint() {
        let mut c = ClientStore::new();
        let key = [7u8; 32];
        assert!(!c.is_pinned(&key));
        c.pin(&key, "LAPTOP", 3);
        assert!(c.is_pinned(&key));
        assert!(!c.is_pinned(&[8; 32]));
        let back = ClientStore::from_json(&c.to_json()).unwrap();
        assert_eq!(back, c);
        // A fingerprint alone (admin pre-seed) pins too.
        let other = [9u8; 32];
        let fp = crate::fingerprint_bytes(&other);
        assert!(c.trust(&fp, "", 4));
        assert!(!c.trust(&fp, "", 5), "already there");
        assert!(c.is_pinned(&other));
        assert_eq!(c.iter().count(), 2);
        assert!(c.forget(&fp));
        assert!(!c.is_pinned(&other));
        // A key that does not match its fingerprint is malformed.
        let bad = format!(
            r#"{{"{}":{{"key":"{}","first_seen":1}}}}"#,
            hex(&fp),
            hex(&key)
        );
        assert!(ClientStore::from_json(bad.as_bytes()).is_err());
    }
}
