//! Saved connections.
//!
//! - Without a master password: `%APPDATA%\rdp-rs\connections.json`, plain,
//!   and never with a password in it.
//! - With a master password: `%APPDATA%\rdp-rs\vault.bin`, encrypted (see
//!   `vault.rs`), which may hold saved passwords. Creating the vault moves the
//!   connections into it; `connections.json` is removed only after the vault
//!   was written and read back.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::vault::{self, VaultKey};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// `user`, `DOMAIN\user` or `user@domain`.
    pub user: String,
    /// 0 x 0: fit the session to the tab ("Fit window").
    pub width: u16,
    pub height: u16,
    /// Session settings applied on connect (and changeable live in the
    /// drawer). Missing in older files: everything off, Auto scale.
    #[serde(default)]
    pub options: SessionOptions,
    /// Saved password; only ever written into the encrypted vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// What a connection shares and how it scales, from the first moment of the
/// session (sharing is switched on before logon, so shared folders and
/// printers are already there when the desktop appears).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionOptions {
    /// Desktop scale in percent; None follows this PC's Windows scaling.
    pub scale: Option<u32>,
    pub clipboard: bool,
    pub sound: bool,
    pub printers: bool,
    pub smart_cards: bool,
    /// Local folders shared as drives.
    pub drives: Vec<String>,
}

enum Backend {
    /// Snapshots and tests: never touches disk.
    Memory,
    Plain(PathBuf),
    /// A vault exists but is not unlocked: no connections in memory.
    Locked(PathBuf),
    Vault {
        path: PathBuf,
        key: VaultKey,
    },
}

pub struct Store {
    pub connections: Vec<Connection>,
    backend: Backend,
}

impl Default for Store {
    fn default() -> Self {
        Store::memory(Vec::new())
    }
}

fn data_dir() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(base).join("rdp-rs"))
}

/// Write then rename, so a crash never leaves a half-written file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

fn wipe(connections: &mut Vec<Connection>) {
    for c in connections.iter_mut() {
        if let Some(p) = c.password.as_mut() {
            p.zeroize();
        }
    }
    connections.clear();
}

impl Store {
    pub fn load() -> Store {
        let Some(dir) = data_dir() else {
            return Store::memory(Vec::new());
        };
        let vault = dir.join("vault.bin");
        if vault.exists() {
            return Store {
                connections: Vec::new(),
                backend: Backend::Locked(vault),
            };
        }
        let plain = dir.join("connections.json");
        let mut connections: Vec<Connection> = std::fs::read(&plain)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // A plain file never carries passwords; drop any that slipped in.
        for c in &mut connections {
            c.password = None;
        }
        Store {
            connections,
            backend: Backend::Plain(plain),
        }
    }

    /// An in-memory store that never touches disk (snapshots).
    pub fn memory(connections: Vec<Connection>) -> Store {
        Store {
            connections,
            backend: Backend::Memory,
        }
    }

    pub fn is_locked(&self) -> bool {
        matches!(self.backend, Backend::Locked(_))
    }

    /// True when connections live in the encrypted vault (passwords can be saved).
    pub fn is_vault(&self) -> bool {
        matches!(self.backend, Backend::Vault { .. })
    }

    /// A locked store for `--snapshot-ui` (never touches disk).
    pub fn locked_sample() -> Store {
        Store {
            connections: Vec::new(),
            backend: Backend::Locked(PathBuf::new()),
        }
    }

    /// The locked vault's file bytes, to read its key parameters.
    pub fn vault_bytes(&self) -> Option<Vec<u8>> {
        match &self.backend {
            Backend::Locked(p) | Backend::Vault { path: p, .. } => std::fs::read(p).ok(),
            _ => None,
        }
    }

    /// Where the "remember on this PC" key lives.
    pub fn remembered_key_path(&self) -> Option<PathBuf> {
        match &self.backend {
            Backend::Locked(p) | Backend::Vault { path: p, .. } => {
                Some(p.with_file_name("vault.key"))
            }
            _ => None,
        }
    }

    /// Opens the vault with a derived key.
    pub fn unlock(&mut self, key: VaultKey) -> Result<(), String> {
        let Backend::Locked(path) = &self.backend else {
            return Ok(());
        };
        let path = path.clone();
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let plain = vault::open(&key, &bytes)?;
        self.connections =
            serde_json::from_slice(&plain).map_err(|e| format!("vault content: {e}"))?;
        self.backend = Backend::Vault { path, key };
        Ok(())
    }

    /// Forgets the key and every connection in memory.
    pub fn lock(&mut self) {
        if let Backend::Vault { path, .. } = &self.backend {
            let path = path.clone();
            wipe(&mut self.connections);
            self.backend = Backend::Locked(path);
        }
    }

    /// Moves the connections into a new vault encrypted with `key`. The plain
    /// file is removed only after the vault was written and opened again.
    pub fn create_vault(&mut self, key: VaultKey) -> Result<(), String> {
        let Backend::Plain(plain) = &self.backend else {
            return Err("a vault already exists".into());
        };
        let plain = plain.clone();
        let path = plain.with_file_name("vault.bin");
        let bytes = vault::seal(
            &key,
            &serde_json::to_vec(&self.connections).map_err(|e| e.to_string())?,
        );
        write_atomic(&path, &bytes)?;
        let check = std::fs::read(&path).map_err(|e| e.to_string())?;
        let back: Vec<Connection> =
            serde_json::from_slice(&vault::open(&key, &check)?).map_err(|e| e.to_string())?;
        if back != self.connections {
            return Err("vault check failed; connections.json was kept".into());
        }
        let _ = std::fs::remove_file(&plain);
        self.backend = Backend::Vault { path, key };
        Ok(())
    }

    pub fn save(&self) -> Result<(), String> {
        match &self.backend {
            Backend::Memory => Ok(()),
            Backend::Locked(_) => Err("the vault is locked".into()),
            Backend::Plain(path) => {
                let mut list = self.connections.clone();
                for c in &mut list {
                    c.password = None;
                }
                let json = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
                write_atomic(path, &json)
            }
            Backend::Vault { path, key } => {
                let json = zeroize::Zeroizing::new(
                    serde_json::to_vec(&self.connections).map_err(|e| e.to_string())?,
                );
                write_atomic(path, &vault::seal(key, &json))
            }
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        wipe(&mut self.connections);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{KdfParams, derive};

    #[test]
    fn connections_saved_before_session_options_still_load() {
        let old =
            r#"[{"name":"pc","host":"10.0.0.1","port":3389,"user":"u","width":0,"height":0}]"#;
        let list: Vec<Connection> = serde_json::from_str(old).unwrap();
        assert_eq!(list[0].options, SessionOptions::default());
        assert_eq!(list[0].password, None);
    }

    #[test]
    fn session_options_round_trip() {
        let c = Connection {
            name: "pc".into(),
            options: SessionOptions {
                scale: Some(150),
                clipboard: true,
                drives: vec!["C:/Share".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let back: Connection = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rdpc-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn plain_file_never_contains_a_password() {
        let dir = temp_dir("plain");
        let plain = dir.join("connections.json");
        let s = Store {
            connections: vec![Connection {
                name: "pc".into(),
                password: Some("hunter2".into()),
                ..Default::default()
            }],
            backend: Backend::Plain(plain.clone()),
        };
        s.save().unwrap();
        let text = std::fs::read_to_string(&plain).unwrap();
        assert!(
            !text.contains("hunter2") && !text.contains("password"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_vault_migrates_then_lock_and_unlock() {
        let dir = temp_dir("vault");
        let plain = dir.join("connections.json");
        std::fs::write(
            &plain,
            br#"[{"name":"pc","host":"h","port":3389,"user":"u","width":0,"height":0}]"#,
        )
        .unwrap();
        let key = derive(
            "master",
            KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                salt: [3; 16],
            },
        )
        .unwrap();
        let mut s = Store {
            connections: Vec::new(),
            backend: Backend::Plain(plain.clone()),
        };
        s.connections = serde_json::from_slice(&std::fs::read(&plain).unwrap()).unwrap();
        s.create_vault(key.clone()).unwrap();
        assert!(!plain.exists(), "plain file removed after a verified vault");
        let vault_path = dir.join("vault.bin");
        assert!(vault_path.exists());

        s.connections[0].password = Some("hunter2".into());
        s.save().unwrap();
        let raw = std::fs::read(&vault_path).unwrap();
        assert!(
            !raw.windows(7).any(|w| w == b"hunter2"),
            "password visible in the vault file"
        );

        s.lock();
        assert!(s.is_locked() && s.connections.is_empty());
        let wrong = derive("nope", key.params).unwrap();
        assert!(s.unlock(wrong).is_err() && s.is_locked());
        s.unlock(key).unwrap();
        assert_eq!(s.connections[0].password.as_deref(), Some("hunter2"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
