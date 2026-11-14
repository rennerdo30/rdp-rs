//! Where the host keeps its files: the password hash, the TLS certificate
//! and its protected private key.
//!
//! - Windows: `%LOCALAPPDATA%\rdp-rs\host\` (the user's profile; its ACL
//!   already admits only the user, SYSTEM and administrators).
//! - Linux and other Unix: `$XDG_DATA_HOME/rdp-rs/host/`, else
//!   `~/.local/share/rdp-rs/host/`; the directory is 0700, files 0600.
//! - macOS: `~/Library/Application Support/rdp-rs/host/`, the same modes.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The default data directory; None when the environment names no home.
pub fn default_data_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
    } else if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var_os("HOME")?)
            .join("Library")
            .join("Application Support")
    } else {
        match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            Some(x) => PathBuf::from(x),
            None => PathBuf::from(std::env::var_os("HOME")?)
                .join(".local")
                .join("share"),
        }
    };
    Some(base.join("rdp-rs").join("host"))
}

/// Creates the directory (owner-only on Unix).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes a file readable only by its owner (0600 on Unix), through a
/// temporary file and a rename, so a crash never leaves half a file.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir_ends_in_rdp_rs_host() {
        if let Some(d) = default_data_dir() {
            assert!(d.ends_with(Path::new("rdp-rs").join("host")), "{d:?}");
        }
    }

    #[test]
    fn private_files_replace_old_ones() {
        let dir = std::env::temp_dir().join(format!("remora-host-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("sub").join("f");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
