//! Saved connections: `%APPDATA%\rdp-rs\connections.json`. Passwords are never stored.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// `user`, `DOMAIN\user` or `user@domain`.
    pub user: String,
    pub width: u16,
    pub height: u16,
}

#[derive(Default)]
pub struct Store {
    pub connections: Vec<Connection>,
    path: Option<PathBuf>,
}

fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(base).join("rdp-rs").join("connections.json"))
}

impl Store {
    pub fn load() -> Store {
        let path = store_path();
        let connections = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Store { connections, path }
    }

    /// An in-memory store that never touches disk (snapshots).
    pub fn memory(connections: Vec<Connection>) -> Store {
        Store {
            connections,
            path: None,
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let json = serde_json::to_vec_pretty(&self.connections).map_err(|e| e.to_string())?;
        // Write then rename, so a crash never leaves a half-written file.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
    }
}
