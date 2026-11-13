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
    /// Group path ("Work/Servers"); empty: top level.
    #[serde(default)]
    pub group: String,
    /// RD Gateway as host[:port]; empty: direct. Part of Credentials.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    /// Sections taken from the group instead of this connection.
    #[serde(default)]
    pub inherit: Inherit,
}

/// Which settings come from the enclosing group (or, for a group, its parent).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Inherit {
    /// User name and saved password.
    pub credentials: bool,
    /// Size and scale.
    pub display: bool,
    /// Clipboard, sound, printers, smart cards and shared folders.
    pub sharing: bool,
}

impl Inherit {
    pub const ALL: Inherit = Inherit {
        credentials: true,
        display: true,
        sharing: true,
    };
}

/// A group of connections ("Work/Servers"): settings its members can inherit.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    /// Full path, segments separated by '/'.
    pub path: String,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// RD Gateway as host[:port]; empty: direct.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    pub width: u16,
    pub height: u16,
    pub options: SessionOptions,
    /// Sections taken from the parent group.
    pub inherit: Inherit,
}

impl Group {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn parent(&self) -> &str {
        parent_of(&self.path)
    }
}

pub fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

/// Cleans a typed group path: trims segments, drops empty ones.
pub fn normalize_path(path: &str) -> String {
    path.split(['/', '\\'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// What is written to disk (version 2). Version 1 was a bare list of connections.
#[derive(Serialize, Deserialize)]
struct FileV2 {
    version: u32,
    #[serde(default)]
    groups: Vec<Group>,
    #[serde(default)]
    connections: Vec<Connection>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AnyFile {
    V2(FileV2),
    V1(Vec<Connection>),
}

fn parse(bytes: &[u8]) -> Result<(Vec<Group>, Vec<Connection>), String> {
    match serde_json::from_slice::<AnyFile>(bytes).map_err(|e| e.to_string())? {
        AnyFile::V2(f) => Ok((f.groups, f.connections)),
        AnyFile::V1(c) => Ok((Vec::new(), c)),
    }
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
    /// Output device for the session's sound, by name; None: the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<String>,
    /// This PC's microphone in the session, and its device by name.
    pub microphone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mic: Option<String>,
    /// Picture quality and desktop experience (part of Display for inheritance).
    pub quality: Quality,
    /// Where Windows key combinations go (part of Display for inheritance).
    pub win_keys: WinKeys,
}

/// Where Win, Alt+Tab and the like go, as mstsc's "Apply Windows key combinations".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WinKeys {
    /// This PC keeps them.
    Local,
    /// The remote session gets them whenever it has the keyboard.
    Remote,
    /// The remote session gets them only in full screen (mstsc's default).
    #[default]
    FullScreen,
}

impl WinKeys {
    pub const ALL: [WinKeys; 3] = [WinKeys::Local, WinKeys::Remote, WinKeys::FullScreen];

    pub fn label(self) -> &'static str {
        match self {
            WinKeys::Local => "This PC",
            WinKeys::Remote => "Remote",
            WinKeys::FullScreen => "Full screen",
        }
    }
}

/// Picture quality, as on mstsc's Display and Experience tabs. Fixed at
/// logon: a change applies on the next connect or reconnect.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Quality {
    /// Connection speed (MS-RDPBCGR connectionType): 6 LAN, 5 WAN,
    /// 4 broadband, 2 low-speed broadband, 1 modem.
    pub connection: u8,
    /// 15, 16, 24 or 32 bits per pixel.
    pub color_depth: u16,
    pub wallpaper: bool,
    pub font_smoothing: bool,
    pub composition: bool,
    pub window_drag: bool,
    pub animations: bool,
    pub visual_styles: bool,
    /// Bulk compression (advertised; the server may pick a lower one).
    pub compression: Comp,
    /// Graphics pipeline (MS-RDPEGFX, H.264) instead of bitmap updates.
    pub gfx: bool,
}

/// Bulk compression setting, saved by name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comp {
    #[default]
    Off,
    Rdp5,
    Rdp6,
    Rdp61,
}

impl Comp {
    fn library(self) -> rdp::Compression {
        match self {
            Comp::Off => rdp::Compression::Off,
            Comp::Rdp5 => rdp::Compression::Rdp5,
            Comp::Rdp6 => rdp::Compression::Rdp6,
            Comp::Rdp61 => rdp::Compression::Rdp61,
        }
    }
}

/// Compression choices in the UI: (setting, label).
pub const COMPRESSION: [(Comp, &str); 4] = [
    (Comp::Off, "Off"),
    (Comp::Rdp61, "RDP 6.1"),
    (Comp::Rdp6, "RDP 6.0"),
    (Comp::Rdp5, "RDP 5.0"),
];

impl Default for Quality {
    fn default() -> Self {
        Quality::preset(rdp::ConnectionType::Lan as u8, 32)
    }
}

/// The speed presets offered in the form: (connection type, label).
pub const PRESETS: [(u8, &str); 5] = [
    (6, "LAN"),
    (5, "WAN"),
    (4, "Broadband"),
    (2, "Low bandwidth"),
    (1, "Modem"),
];

pub fn preset_name(connection: u8) -> &'static str {
    match connection {
        3 => "Satellite",
        c => PRESETS.iter().find(|p| p.0 == c).map_or("LAN", |p| p.1),
    }
}

impl Quality {
    /// What mstsc enables at that speed; the colour depth stays as given.
    pub fn preset(connection: u8, color_depth: u16) -> Quality {
        let ct = rdp::ConnectionType::from_u8(connection).unwrap_or_default();
        let e = rdp::Experience::for_connection(ct);
        Quality {
            connection: ct as u8,
            color_depth,
            wallpaper: e.wallpaper,
            font_smoothing: e.font_smoothing,
            composition: e.desktop_composition,
            window_drag: e.window_drag,
            animations: e.animations,
            visual_styles: e.visual_styles,
            compression: Comp::Off,
            gfx: false,
        }
    }

    pub fn apply(&self, cfg: &mut rdp::Config) {
        let ct = rdp::ConnectionType::from_u8(self.connection).unwrap_or_default();
        cfg.connection_type = ct;
        cfg.color_depth = rdp::experience::valid_color_depth(self.color_depth);
        cfg.compression = self.compression.library();
        if self.gfx {
            cfg.graphics = rdp::Graphics::Gfx;
            #[cfg(windows)]
            {
                cfg.h264 = Some(crate::h264_mf::factory());
            }
        } else {
            cfg.graphics = rdp::Graphics::Bitmap;
            cfg.h264 = None;
        }
        cfg.experience = rdp::Experience {
            wallpaper: self.wallpaper,
            font_smoothing: self.font_smoothing,
            desktop_composition: self.composition,
            window_drag: self.window_drag,
            animations: self.animations,
            visual_styles: self.visual_styles,
            cursor_shadow: rdp::Experience::for_connection(ct).cursor_shadow,
        };
    }
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
    pub groups: Vec<Group>,
    backend: Backend,
}

impl Default for Store {
    fn default() -> Self {
        Store::memory(Vec::new())
    }
}

/// Opens a backup (or vault) file with a key derived from its password.
pub fn read_backup(bytes: &[u8], key: &VaultKey) -> Result<(Vec<Group>, Vec<Connection>), String> {
    parse(&vault::open(key, bytes)?)
}

pub fn data_dir() -> Option<PathBuf> {
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
                groups: Vec::new(),
                backend: Backend::Locked(vault),
            };
        }
        let plain = dir.join("connections.json");
        let (mut groups, mut connections) = std::fs::read(&plain)
            .ok()
            .and_then(|b| parse(&b).ok())
            .unwrap_or_default();
        // A plain file never carries passwords; drop any that slipped in.
        for c in &mut connections {
            c.password = None;
        }
        for g in &mut groups {
            g.password = None;
        }
        Store {
            connections,
            groups,
            backend: Backend::Plain(plain),
        }
    }

    /// An in-memory store that never touches disk (snapshots).
    pub fn memory(connections: Vec<Connection>) -> Store {
        Store {
            connections,
            groups: Vec::new(),
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
    /// Snapshots only: pretend this in-memory store is an open vault.
    pub fn vault_sample(&mut self) {
        self.backend = Backend::Vault {
            path: PathBuf::new(),
            key: VaultKey {
                key: zeroize::Zeroizing::new([0; 32]),
                params: vault::KdfParams::fresh(),
            },
        };
    }

    pub fn locked_sample() -> Store {
        Store {
            connections: Vec::new(),
            groups: Vec::new(),
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
        let (groups, connections) = parse(&plain).map_err(|e| format!("vault content: {e}"))?;
        self.groups = groups;
        self.connections = connections;
        self.backend = Backend::Vault { path, key };
        Ok(())
    }

    /// The open vault's key (for "remember on this PC" and backups).
    pub fn vault_key(&self) -> Option<&VaultKey> {
        match &self.backend {
            Backend::Vault { key, .. } => Some(key),
            _ => None,
        }
    }

    /// Re-encrypts the vault with a new key (a new master password). The
    /// file is replaced only after the new one was written and read back.
    pub fn rekey(&mut self, key: VaultKey) -> Result<(), String> {
        let Backend::Vault { path, .. } = &self.backend else {
            return Err("no vault is open".into());
        };
        let path = path.clone();
        let bytes = vault::seal(&key, &self.file_json(true)?);
        let (groups, back) = parse(&vault::open(&key, &bytes)?)?;
        if back != self.connections || groups != self.groups {
            return Err("re-encryption check failed; the vault was not changed".into());
        }
        write_atomic(&path, &bytes)?;
        self.backend = Backend::Vault { path, key };
        Ok(())
    }

    /// An encrypted backup of every connection and group (same format as the
    /// vault, opened with the master password that was current when exported).
    pub fn export_backup(&self) -> Result<Vec<u8>, String> {
        let key = self
            .vault_key()
            .ok_or("set a master password first: backups are encrypted with it")?;
        Ok(vault::seal(key, &self.file_json(true)?))
    }

    /// Adds the groups and connections of a backup; connections that already
    /// exist (same name, host and group) are skipped. Returns how many were added.
    pub fn merge(&mut self, groups: Vec<Group>, connections: Vec<Connection>) -> usize {
        for g in groups {
            if self.group_index(&g.path).is_none() {
                self.groups.push(g);
            }
        }
        let mut added = 0;
        for c in connections {
            let dup = self
                .connections
                .iter()
                .any(|o| o.name == c.name && o.host == c.host && o.group == c.group);
            if !dup {
                if !c.group.is_empty() {
                    self.ensure_group(&c.group);
                }
                self.connections.push(c);
                added += 1;
            }
        }
        self.groups.sort_by_key(|g| g.path.to_lowercase());
        added
    }

    /// Forgets the key and every connection in memory.
    pub fn lock(&mut self) {
        if let Backend::Vault { path, .. } = &self.backend {
            let path = path.clone();
            wipe(&mut self.connections);
            wipe_groups(&mut self.groups);
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
        let bytes = vault::seal(&key, &self.file_json(true)?);
        write_atomic(&path, &bytes)?;
        let check = std::fs::read(&path).map_err(|e| e.to_string())?;
        let (groups, back) = parse(&vault::open(&key, &check)?)?;
        if back != self.connections || groups != self.groups {
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
            Backend::Plain(path) => write_atomic(path, &self.file_json(false)?),
            Backend::Vault { path, key } => {
                let json = zeroize::Zeroizing::new(self.file_json(true)?);
                write_atomic(path, &vault::seal(key, &json))
            }
        }
    }

    /// The file contents; passwords only when they go into the vault.
    fn file_json(&self, with_passwords: bool) -> Result<Vec<u8>, String> {
        let mut file = FileV2 {
            version: 2,
            groups: self.groups.clone(),
            connections: self.connections.clone(),
        };
        if !with_passwords {
            for c in &mut file.connections {
                c.password = None;
            }
            for g in &mut file.groups {
                g.password = None;
            }
        }
        let out = if with_passwords {
            serde_json::to_vec(&file)
        } else {
            serde_json::to_vec_pretty(&file)
        };
        wipe(&mut file.connections);
        wipe_groups(&mut file.groups);
        out.map_err(|e| e.to_string())
    }

    /// Creates groups that connections name but that are missing.
    pub fn adopt_groups(&mut self) {
        let paths: Vec<String> = self
            .connections
            .iter()
            .filter(|c| !c.group.is_empty())
            .map(|c| c.group.clone())
            .collect();
        for path in paths {
            self.ensure_group(&path);
        }
    }

    /// Connections in a group or any of its sub-groups.
    pub fn members<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a Connection> + 'a {
        self.connections.iter().filter(move |c| {
            c.group == path
                || c.group
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    pub fn group_index(&self, path: &str) -> Option<usize> {
        self.groups.iter().position(|g| g.path == path)
    }

    /// Creates the group and any missing parents.
    pub fn ensure_group(&mut self, path: &str) {
        let mut prefix = String::new();
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            if self.group_index(&prefix).is_none() {
                self.groups.push(Group {
                    path: prefix.clone(),
                    ..Default::default()
                });
            }
        }
        self.groups.sort_by_key(|g| g.path.to_lowercase());
    }

    /// Renames a group path, moving its sub-groups and connections along.
    pub fn rename_group(&mut self, old: &str, new: &str) {
        if old == new || old.is_empty() {
            return;
        }
        let moved = |p: &str| -> Option<String> {
            if p == old {
                Some(new.to_string())
            } else {
                p.strip_prefix(old)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .map(|rest| format!("{new}/{rest}"))
            }
        };
        for g in &mut self.groups {
            if let Some(p) = moved(&g.path) {
                g.path = p;
            }
        }
        for c in &mut self.connections {
            if let Some(p) = moved(&c.group) {
                c.group = p;
            }
        }
        self.ensure_group(new);
    }

    /// Removes a group; its connections and sub-groups move up to its parent.
    pub fn delete_group(&mut self, path: &str) {
        let parent = parent_of(path).to_string();
        self.groups.retain(|g| g.path != path);
        let up = |p: &str| -> Option<String> {
            let rest = p.strip_prefix(path)?.strip_prefix('/')?;
            Some(if parent.is_empty() {
                rest.to_string()
            } else {
                format!("{parent}/{rest}")
            })
        };
        for g in &mut self.groups {
            if let Some(p) = up(&g.path) {
                g.path = p;
            }
        }
        for c in &mut self.connections {
            if c.group == path {
                c.group = parent.clone();
            } else if let Some(p) = up(&c.group) {
                c.group = p;
            }
        }
        self.groups.sort_by_key(|g| g.path.to_lowercase());
    }

    /// The group that provides a section for something at `path` (a group
    /// path): the nearest group up the tree that does not inherit it.
    fn provider(&self, mut path: &str, pick: fn(&Inherit) -> bool) -> Option<&Group> {
        while !path.is_empty() {
            if let Some(g) = self.groups.iter().find(|g| g.path == path)
                && !pick(&g.inherit)
            {
                return Some(g);
            }
            path = parent_of(path);
        }
        None
    }

    /// The group a connection's (or group's) section comes from, if inherited.
    pub fn source_of(
        &self,
        group_path: &str,
        inherit: &Inherit,
        pick: fn(&Inherit) -> bool,
    ) -> Option<&Group> {
        if pick(inherit) {
            self.provider(group_path, pick)
        } else {
            None
        }
    }

    /// A connection with every inherited section filled in from its groups.
    pub fn resolve(&self, c: &Connection) -> Connection {
        let mut out = c.clone();
        if let Some(g) = self.source_of(&c.group, &c.inherit, |i| i.credentials) {
            out.user = g.user.clone();
            out.password = g.password.clone();
            out.gateway = g.gateway.clone();
        }
        if let Some(g) = self.source_of(&c.group, &c.inherit, |i| i.display) {
            out.width = g.width;
            out.height = g.height;
            out.options.scale = g.options.scale;
            out.options.quality = g.options.quality;
            out.options.win_keys = g.options.win_keys;
        }
        if let Some(g) = self.source_of(&c.group, &c.inherit, |i| i.sharing) {
            let own = out.options.clone();
            out.options = g.options.clone();
            out.options.scale = own.scale;
            out.options.quality = own.quality;
            out.options.win_keys = own.win_keys;
        }
        out
    }
}

fn wipe_groups(groups: &mut Vec<Group>) {
    for g in groups.iter_mut() {
        if let Some(p) = g.password.as_mut() {
            p.zeroize();
        }
    }
    groups.clear();
}

impl Drop for Store {
    fn drop(&mut self) {
        wipe(&mut self.connections);
        wipe_groups(&mut self.groups);
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
            groups: Vec::new(),
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
            groups: Vec::new(),
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

    fn store_with(groups: Vec<Group>, connections: Vec<Connection>) -> Store {
        let mut s = Store::memory(connections);
        s.groups = groups;
        s
    }

    #[test]
    fn inheritance_takes_the_nearest_group_that_defines_a_section() {
        let work = Group {
            path: "Work".into(),
            user: r"CORP\alex".into(),
            width: 1920,
            height: 1080,
            options: SessionOptions {
                clipboard: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // Servers inherits credentials from Work but sets its own display.
        let servers = Group {
            path: "Work/Servers".into(),
            user: "ignored".into(),
            width: 1280,
            height: 800,
            inherit: Inherit {
                credentials: true,
                display: false,
                sharing: true,
            },
            ..Default::default()
        };
        let c = Connection {
            name: "db".into(),
            user: "own".into(),
            group: "Work/Servers".into(),
            inherit: Inherit {
                credentials: true,
                display: true,
                sharing: true,
            },
            ..Default::default()
        };
        let s = store_with(vec![work, servers], vec![c.clone()]);
        let r = s.resolve(&c);
        assert_eq!(
            r.user, r"CORP\alex",
            "credentials from Work (Servers inherits them)"
        );
        assert_eq!((r.width, r.height), (1280, 800), "display from Servers");
        assert!(r.options.clipboard, "sharing from Work");
        let own = Connection {
            inherit: Inherit::default(),
            ..c
        };
        assert_eq!(s.resolve(&own).user, "own", "no inheritance: own values");
    }

    #[test]
    fn version_1_files_load_and_version_2_round_trips() {
        let v1 = br#"[{"name":"pc","host":"h","port":3389,"user":"u","width":0,"height":0}]"#;
        let (g, c) = parse(v1).unwrap();
        assert!(g.is_empty() && c.len() == 1 && c[0].group.is_empty());
        let mut s = store_with(vec![], c);
        s.ensure_group("Work/Servers");
        s.connections[0].group = "Work/Servers".into();
        let json = s.file_json(false).unwrap();
        let (g2, c2) = parse(&json).unwrap();
        assert_eq!(
            g2.iter().map(|g| g.path.as_str()).collect::<Vec<_>>(),
            ["Work", "Work/Servers"]
        );
        assert_eq!(c2[0].group, "Work/Servers");
    }

    #[test]
    fn rename_and_delete_move_members() {
        let mut s = store_with(
            vec![],
            vec![Connection {
                group: "A/B".into(),
                ..Default::default()
            }],
        );
        s.ensure_group("A/B/C");
        s.rename_group("A/B", "A/X");
        assert_eq!(s.connections[0].group, "A/X");
        assert!(s.group_index("A/X/C").is_some() && s.group_index("A/B").is_none());
        s.delete_group("A/X");
        assert_eq!(s.connections[0].group, "A", "members move up to the parent");
        assert!(s.group_index("A/C").is_some(), "sub-groups move up too");
        assert_eq!(normalize_path(" Work / /Servers/ "), "Work/Servers");
    }

    #[test]
    fn plain_file_never_contains_a_group_password() {
        let s = store_with(
            vec![Group {
                path: "W".into(),
                password: Some("hunter2".into()),
                ..Default::default()
            }],
            vec![],
        );
        let json = String::from_utf8(s.file_json(false).unwrap()).unwrap();
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn quality_is_inherited_with_display_not_with_sharing() {
        let modem = SessionOptions {
            clipboard: true,
            quality: Quality::preset(1, 16),
            ..Default::default()
        };
        let g = Group {
            path: "W".into(),
            options: modem,
            ..Default::default()
        };
        let sharing_only = Connection {
            group: "W".into(),
            inherit: Inherit {
                sharing: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let s = store_with(vec![g], vec![]);
        let r = s.resolve(&sharing_only);
        assert!(r.options.clipboard);
        assert_eq!(r.options.quality, Quality::default(), "own quality kept");
        let display = Connection {
            inherit: Inherit {
                display: true,
                ..Default::default()
            },
            ..sharing_only
        };
        let r = s.resolve(&display);
        assert_eq!(r.options.quality.connection, 1);
        assert_eq!(r.options.quality.color_depth, 16);
        assert!(!r.options.quality.wallpaper);
        let mut cfg = rdp::Config::new("h", "u", "p");
        r.options.quality.apply(&mut cfg);
        assert_eq!(cfg.color_depth, 16);
        assert_eq!(cfg.experience.performance_flags() & 1, 1, "wallpaper off");
    }

    #[test]
    fn saved_options_without_quality_load_as_lan() {
        let o: SessionOptions = serde_json::from_str(r#"{"clipboard":true}"#).unwrap();
        assert_eq!(o.quality, Quality::default());
        assert!(o.quality.wallpaper && o.quality.color_depth == 32);
    }

    #[test]
    fn backup_round_trip_and_merge_skips_duplicates() {
        let key = derive(
            "pw",
            KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                salt: [9; 16],
            },
        )
        .unwrap();
        let conn = Connection {
            name: "pc".into(),
            host: "h".into(),
            group: "Work".into(),
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let mut s = Store::memory(vec![conn.clone()]);
        s.ensure_group("Work");
        s.backend = Backend::Vault {
            path: PathBuf::new(),
            key: key.clone(),
        };
        let backup = s.export_backup().unwrap();
        assert!(
            !backup.windows(7).any(|w| w == b"hunter2"),
            "backup is encrypted"
        );
        let (g, c) = read_backup(&backup, &key).unwrap();
        assert_eq!(c, vec![conn.clone()]);
        let mut other = Store::memory(vec![conn]);
        assert_eq!(
            other.merge(g.clone(), c.clone()),
            0,
            "same connection skipped"
        );
        let fresh = Connection {
            name: "new".into(),
            ..c[0].clone()
        };
        assert_eq!(other.merge(g, vec![fresh]), 1);
        assert!(other.group_index("Work").is_some());
        let wrong = derive("nope", key.params).unwrap();
        assert!(read_backup(&backup, &wrong).is_err());
        s.backend = Backend::Memory;
    }
}
