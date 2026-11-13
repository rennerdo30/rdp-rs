//! Keeps every server path inside a drive's shared root.
//!
//! Server paths (MS-RDPEFS 2.2.1.4.1, 2.2.3.3.9.1, 2.2.3.3.10) are
//! backslash-separated and relative to the drive, for example `\dir\a.txt`.
//! A path is refused before it touches the file system when it is a UNC or
//! device path, names a drive letter or an alternate data stream (any `:`),
//! has a `.` or `..` component, a character Windows does not allow in names,
//! a trailing dot or space (Windows would strip it), or a reserved DOS
//! device name (`CON`, `NUL`, `COM1`, ...). Then the joined path is
//! canonicalized (resolving symlinks and junctions) and must still lie under
//! the canonical root; for a path that does not exist yet its parent is
//! checked instead, and a dangling symlink is refused.
//!
//! A local process racing to swap a checked directory for a link between the
//! check and the open is outside this model (the shared root belongs to the
//! local user).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::fscc::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, status_from_io,
};

fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

const RESERVED: [&str; 24] = [
    "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

/// Checks one name component; `wildcards` allows `*`, `?`, `<`, `>`, `"`.
pub fn check_name(c: &str, wildcards: bool) -> Result<(), u32> {
    if c == ".." {
        return Err(STATUS_ACCESS_DENIED);
    }
    if c.is_empty() || c == "." || (c.ends_with('.') && !wildcards) || c.ends_with(' ') {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let bad = |ch: char| {
        (ch as u32) < 0x20
            || matches!(ch, ':' | '|' | '\\' | '/')
            || (!wildcards && matches!(ch, '*' | '?' | '<' | '>' | '"'))
    };
    if c.chars().any(bad) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let stem = c.split('.').next().unwrap_or(c).trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(())
}

/// Splits and checks a server path into its name components.
pub fn components(server_path: &str) -> Result<Vec<&str>, u32> {
    let mut chars = server_path.chars();
    if chars.next().is_some_and(is_sep) && chars.next().is_some_and(is_sep) {
        return Err(STATUS_OBJECT_NAME_INVALID); // UNC or \\?\ device path
    }
    if server_path.contains(':') {
        return Err(STATUS_OBJECT_NAME_INVALID); // drive letter or stream
    }
    let parts: Vec<&str> = server_path
        .split(is_sep)
        .filter(|c| !c.is_empty())
        .collect();
    for c in &parts {
        check_name(c, false)?;
    }
    Ok(parts)
}

/// A server path mapped into the shared root.
#[derive(Debug)]
pub struct Resolved {
    /// Canonical path if it exists, else canonical parent plus the name.
    pub path: PathBuf,
    pub exists: bool,
    /// The path is the shared root itself.
    pub is_root: bool,
}

fn inside(path: &Path, root: &Path) -> Result<(), u32> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(STATUS_ACCESS_DENIED)
    }
}

/// Maps `server_path` into `root`; see the module docs for the checks.
pub fn resolve(root: &Path, server_path: &str) -> Result<Resolved, u32> {
    let parts = components(server_path)?;
    let root = root
        .canonicalize()
        .map_err(|_| STATUS_OBJECT_PATH_NOT_FOUND)?;
    let joined = parts.iter().fold(root.clone(), |p, c| p.join(c));
    let Some((last, parent_parts)) = parts.split_last() else {
        return Ok(Resolved {
            path: root,
            exists: true,
            is_root: true,
        });
    };
    match joined.canonicalize() {
        Ok(c) => {
            inside(&c, &root)?;
            let is_root = c == root;
            Ok(Resolved {
                path: c,
                exists: true,
                is_root,
            })
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if fs::symlink_metadata(&joined).is_ok() {
                return Err(STATUS_ACCESS_DENIED); // dangling link
            }
            let parent = parent_parts.iter().fold(root.clone(), |p, c| p.join(c));
            let parent = match parent.canonicalize() {
                Ok(p) => p,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                }
                Err(e) => return Err(status_from_io(&e)),
            };
            inside(&parent, &root)?;
            if !fs::metadata(&parent).is_ok_and(|m| m.is_dir()) {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            Ok(Resolved {
                path: parent.join(last),
                exists: false,
                is_root: false,
            })
        }
        Err(e) if e.kind() == ErrorKind::NotADirectory => Err(STATUS_OBJECT_PATH_NOT_FOUND),
        Err(e) => match status_from_io(&e) {
            STATUS_OBJECT_NAME_NOT_FOUND => Err(STATUS_OBJECT_PATH_NOT_FOUND),
            s => Err(s),
        },
    }
}

/// Splits a directory query path (`\dir\*.txt`) into the directory and the
/// pattern, both checked.
pub fn split_pattern(server_path: &str) -> Result<(&str, &str), u32> {
    let (dir, pattern) = match server_path.rfind(is_sep) {
        Some(i) => (&server_path[..i], &server_path[i + 1..]),
        None => ("", server_path),
    };
    let pattern = if pattern.is_empty() { "*" } else { pattern };
    if pattern != "*" {
        check_name(pattern, true)?;
    }
    Ok((dir, pattern))
}

/// Windows wildcard match, case-insensitive: `*` any run, `?` one character;
/// the DOS forms `<`, `>` and `"` count as `*`, `?` and `.`.
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern
        .chars()
        .map(|c| match c {
            '<' => '*',
            '>' => '?',
            '"' => '.',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect();
    let n: Vec<char> = name.chars().flat_map(char::to_lowercase).collect();
    // Iterative match with backtracking to the last `*`.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}
