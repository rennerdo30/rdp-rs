//! Servers whose certificate the user trusted (`%APPDATA%\rdp-rs\known_hosts.json`).
//!
//! Trust on first use: the first connection to a host asks, a matching
//! certificate later connects silently, and a changed one asks again with a
//! warning. Only SHA-256 fingerprints are stored, nothing secret.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn path() -> Option<PathBuf> {
    crate::store::data_dir().map(|d| d.join("known_hosts.json"))
}

fn key(host: &str, port: u16) -> String {
    format!("{}:{port}", host.to_lowercase())
}

fn load(p: &Path) -> BTreeMap<String, String> {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// The remembered fingerprint (lower-case hex SHA-256) of a host.
pub fn lookup(host: &str, port: u16) -> Option<String> {
    lookup_in(&path()?, host, port)
}

pub fn remember(host: &str, port: u16, sha256_hex: &str) -> Result<(), String> {
    let p = path().ok_or("no settings folder")?;
    remember_in(&p, host, port, sha256_hex)
}

fn lookup_in(p: &Path, host: &str, port: u16) -> Option<String> {
    load(p).get(&key(host, port)).cloned()
}

fn remember_in(p: &Path, host: &str, port: u16, sha256_hex: &str) -> Result<(), String> {
    let mut all = load(p);
    all.insert(key(host, port), sha256_hex.to_string());
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_per_host_and_port() {
        let dir = std::env::temp_dir().join(format!("remora-known-{}", std::process::id()));
        let p = dir.join("known_hosts.json");
        assert_eq!(lookup_in(&p, "PC", 3389), None);
        remember_in(&p, "PC", 3389, "aa").unwrap();
        assert_eq!(
            lookup_in(&p, "pc", 3389).as_deref(),
            Some("aa"),
            "host names ignore case"
        );
        assert_eq!(
            lookup_in(&p, "pc", 3390),
            None,
            "another port is another server"
        );
        remember_in(&p, "pc", 3389, "bb").unwrap();
        assert_eq!(lookup_in(&p, "PC", 3389).as_deref(), Some("bb"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
