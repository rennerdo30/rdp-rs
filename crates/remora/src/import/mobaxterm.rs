//! MobaXterm sessions (RDP-89): `MobaXterm.ini` (in `%APPDATA%\MobaXterm`,
//! or next to a portable `MobaXterm.exe`) or an exported `.mxtsessions`
//! file. Both keep the sessions in `[Bookmarks]` and `[Bookmarks_N]`
//! sections: `SubRep` is the folder (sub-folders separated by `\`), and
//! every other line is one session, `name=` and a `#`-separated value whose
//! third item is the `%`-separated connection fields. MobaXterm publishes no
//! specification; the field positions follow the community description of
//! version 26 (older files have fewer fields, which read as defaults).
//!
//! - Type 0 (SSH): host, port, user, private key file, SSH gateway.
//! - Type 4 (RDP): host, port, user, RD Gateway (when set to Always or
//!   Detect), SSH gateway (becomes the jump host).
//! - Other types (VNC, Telnet, SFTP, ...) are skipped and counted.
//! - Session lines hold no passwords (MobaXterm keeps them apart, encrypted
//!   with its own master password), so none come over.

use std::collections::BTreeSet;

use super::{Imported, Resolved};
use crate::store::{Group, Protocol, normalize_path};

/// Whether `text` has MobaXterm's session sections.
pub(super) fn looks_like(text: &str) -> bool {
    text.lines().any(|l| bookmarks_section(l.trim()).is_some())
}

/// `[Bookmarks]` or `[Bookmarks_N]` (any case).
fn bookmarks_section(line: &str) -> Option<()> {
    let name = line
        .strip_prefix('[')?
        .strip_suffix(']')?
        .to_ascii_lowercase();
    let rest = name.strip_prefix("bookmarks")?;
    (rest.is_empty()
        || rest
            .strip_prefix('_')
            .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit())))
    .then_some(())
}

/// The text of the file: UTF-8 (with or without a BOM) when it is valid,
/// else Windows-1252, MobaXterm's own charset.
pub(super) fn decode(bytes: &[u8]) -> String {
    let b = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    b.iter().map(|&c| cp1252(c)).collect()
}

fn cp1252(c: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž',
        '\u{8F}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}',
        'ž', 'Ÿ',
    ];
    match c {
        0x80..=0x9F => HIGH[(c - 0x80) as usize],
        _ => c as char,
    }
}

/// MobaXterm's escapes in values.
fn unescape(s: &str) -> String {
    s.replace("__PIPE__", "|")
        .replace("__DIEZE__", "#")
        .replace("__PTVIRG__", ";")
        .replace("__DBLQUO__", "\"")
        .replace("__PERCENT__", "%")
        .replace("_CurrentDrive_", "C")
        .trim()
        .to_string()
}

/// `user@host:port` (`host` alone when the user is empty, no `:22`), or
/// None when there is no gateway. Err when there are several hops, which
/// Remora cannot chain.
fn ssh_gateway(host: &str, port: &str, user: &str) -> Result<Option<String>, ()> {
    if host.contains("__PIPE__") || host.contains('|') {
        return Err(());
    }
    let host = unescape(host);
    if host.is_empty() {
        return Ok(None);
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let user = unescape(user);
    let port = port.trim().parse::<u16>().unwrap_or(22);
    let mut out = if user.is_empty() || user == "<default>" {
        host
    } else {
        format!("{user}@{host}")
    };
    if port != 22 {
        out += &format!(":{port}");
    }
    Ok(Some(out))
}

pub(super) fn read(text: &str) -> Imported {
    let mut out = Imported::default();
    let mut folders = BTreeSet::new();
    let mut in_bookmarks = false;
    let mut folder = String::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let t = line.trim();
        if t.starts_with('[') {
            in_bookmarks = bookmarks_section(t).is_some();
            folder.clear();
            continue;
        }
        if !in_bookmarks || t.is_empty() || t.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "SubRep" => {
                folder = normalize_path(&unescape(value));
                // Every level, so parents exist too.
                let mut at = String::new();
                for part in folder.split('/').filter(|p| !p.is_empty()) {
                    if !at.is_empty() {
                        at.push('/');
                    }
                    at.push_str(part);
                    folders.insert(at.clone());
                }
            }
            "ImgNum" => {}
            name => session(&mut out, name, value, &folder),
        }
    }
    out.groups = folders
        .into_iter()
        .map(|path| Group {
            path,
            ..Group::default()
        })
        .collect();
    out
}

fn session(out: &mut Imported, name: &str, value: &str, folder: &str) {
    // logout flag # icon # connection fields # terminal settings # ...
    let Some(fields) = value.split('#').nth(2) else {
        out.report.not_rdp += 1;
        return;
    };
    let f: Vec<&str> = fields.split('%').collect();
    let get = |i: usize| f.get(i).copied().unwrap_or("");
    let host = unescape(get(1));
    let user = match unescape(get(3)) {
        u if u == "<default>" => String::new(),
        u => u,
    };
    let port = get(2).trim().parse::<u16>().unwrap_or(0);
    let (protocol, jump_fields, key) = match get(0).trim() {
        "0" => (Protocol::Ssh, (8, 9, 10), Some(14)),
        "4" => (Protocol::Rdp, (13, 14, 15), None),
        _ => {
            out.report.not_rdp += 1;
            return;
        }
    };
    if host.is_empty() {
        out.report.not_rdp += 1;
        return;
    }
    let mut r = Resolved {
        host,
        port,
        user,
        protocol,
        ..Resolved::default()
    };
    if protocol == Protocol::Rdp {
        // Expert settings: 1 = use the gateway (0 never, 1 detect, 2 always),
        // 2 = its host; older files keep the host at field 20 only.
        let expert: Vec<&str> = get(31).split(',').collect();
        let use_gw = expert.get(1).map(|s| s.trim());
        let gw = expert
            .get(2)
            .map(|s| unescape(s))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| unescape(get(20)));
        if matches!(use_gw, Some("1" | "2")) || (use_gw.is_none() && !gw.is_empty()) {
            r.gateway = gw;
        }
    }
    let (h, p, u) = jump_fields;
    let mut c = match ssh_gateway(get(h), get(p), get(u)) {
        Ok(jump) => {
            let mut c = r.connection(name, folder);
            match jump {
                // A gateway and a jump host exclude each other in Remora.
                Some(_) if !c.gateway.is_empty() => out.report.no_jump += 1,
                Some(j) => c.jump = j,
                None => {}
            }
            c
        }
        Err(()) => {
            out.report.no_jump += 1;
            r.connection(name, folder)
        }
    };
    if let Some(k) = key {
        c.ssh_key = unescape(get(k));
    }
    out.connections.push(c);
}
