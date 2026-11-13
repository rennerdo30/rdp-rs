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
    /// 0 x 0: fit the session to the tab ("Fit window").
    pub width: u16,
    pub height: u16,
    /// Session settings applied on connect (and changeable live in the
    /// drawer). Missing in older files: everything off, Auto scale.
    #[serde(default)]
    pub options: SessionOptions,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_saved_before_session_options_still_load() {
        let old =
            r#"[{"name":"pc","host":"10.0.0.1","port":3389,"user":"u","width":0,"height":0}]"#;
        let list: Vec<Connection> = serde_json::from_str(old).unwrap();
        assert_eq!(list[0].options, SessionOptions::default());
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
}
