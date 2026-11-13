//! App settings (`%APPDATA%\rdp-rs\settings.json`): not secret, plain JSON.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Lock the vault after this many idle minutes; 0: never.
    pub auto_lock_minutes: u32,
    /// Installed copies look for a newer release once a day.
    pub check_updates: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            auto_lock_minutes: 15,
            check_updates: true,
        }
    }
}

/// Auto-lock choices offered in Settings, in minutes (0: never).
pub const AUTO_LOCK: [u32; 4] = [0, 5, 15, 60];

impl AppSettings {
    fn path() -> Option<std::path::PathBuf> {
        crate::store::data_dir().map(|d| d.join("settings.json"))
    }

    pub fn load() -> AppSettings {
        Self::path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::path().ok_or("no settings folder")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_take_the_defaults() {
        let s: AppSettings = serde_json::from_str(r#"{"check_updates":false}"#).unwrap();
        assert_eq!(s.auto_lock_minutes, 15);
        assert!(!s.check_updates);
    }
}
