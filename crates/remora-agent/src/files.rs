//! File transfer on the agent's side (RDP-43), the platform-independent
//! parts: where received files go, their Mark-of-the-Web, which files may
//! be sent, the `send` request on the local pipe, the Send To shortcut as
//! data, and the `send` subcommand's logic behind traits.

use std::path::{Path, PathBuf};

/// Folder under the user's Downloads that receives files from Remora.
pub const RECEIVE_FOLDER: &str = "From Remora";

/// `<Downloads>\From Remora`, with Downloads from the known folder or,
/// failing that, `%USERPROFILE%\Downloads`.
pub fn receive_folder(
    downloads: Option<PathBuf>,
    user_profile: Option<PathBuf>,
) -> Option<PathBuf> {
    downloads
        .or_else(|| user_profile.map(|p| p.join("Downloads")))
        .map(|d| d.join(RECEIVE_FOLDER))
}

/// The `Zone.Identifier` stream for a received file: zone 3 (Internet), so
/// Windows warns before running it and Office opens it in Protected View.
pub const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";

/// `<file>:Zone.Identifier`, the alternate data stream Windows reads.
pub fn zone_stream(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(":Zone.Identifier");
    PathBuf::from(s)
}

/// Names the transfer engine uses for its own working files. Never offered,
/// and receivers refuse them.
pub fn reserved_name(name: &str) -> bool {
    remora_link::transfer::path::is_working_file(name)
}

/// What the agent knows about a file opened for sending (from the handle,
/// so a swap between check and open is impossible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// `GetFileType` says `FILE_TYPE_DISK`.
    pub disk_file: bool,
}

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_DEVICE: u32 = 0x40;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Version 1.0 sends regular files only. Other attributes (offline cloud
/// placeholders, hidden, read-only) do not matter: reading works or fails
/// like for any program.
pub fn check_facts(f: FileFacts) -> Result<(), &'static str> {
    if f.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err("folders cannot be sent yet");
    }
    if f.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("links and junctions are not sent");
    }
    if f.attributes & FILE_ATTRIBUTE_DEVICE != 0 || !f.disk_file {
        return Err("not a regular file");
    }
    Ok(())
}

// --------------------------------------------------------- pipe: send

const SEND_MAGIC: &[u8; 4] = b"RMS1";
/// Files per request.
pub const MAX_SEND_FILES: usize = 64;
/// Longest path (UTF-8 bytes) in a request.
pub const MAX_SEND_PATH: usize = 8192;
/// Largest request; larger selections go as several requests.
pub const MAX_SEND_REQUEST_LEN: usize = 64 * 1024;
/// The agent's answer: status, offered (u16), failed (u16).
pub const SEND_REPLY_LEN: usize = 5;

pub fn is_send_request(b: &[u8]) -> bool {
    b.starts_with(SEND_MAGIC)
}

/// `RMS1`, `u16` count, then per path `u16` length and UTF-8. Paths are
/// absolute. Selections too large for one request are split.
pub fn encode_send_requests(paths: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut count = 0usize;
    let flush = |cur: &mut Vec<u8>, count: &mut usize, out: &mut Vec<Vec<u8>>| {
        if *count > 0 {
            cur[4..6].copy_from_slice(&(*count as u16).to_le_bytes());
            out.push(std::mem::take(cur));
            *count = 0;
        }
    };
    for p in paths {
        if p.is_empty() || p.len() > MAX_SEND_PATH || p.contains('\0') {
            return Err(format!("path of {} bytes cannot be sent", p.len()));
        }
        if count == MAX_SEND_FILES || cur.len() + 2 + p.len() > MAX_SEND_REQUEST_LEN {
            flush(&mut cur, &mut count, &mut out);
        }
        if count == 0 {
            cur.extend_from_slice(SEND_MAGIC);
            cur.extend_from_slice(&[0, 0]);
        }
        cur.extend_from_slice(&(p.len() as u16).to_le_bytes());
        cur.extend_from_slice(p.as_bytes());
        count += 1;
    }
    flush(&mut cur, &mut count, &mut out);
    Ok(out)
}

/// Absolute: `C:\...` or `\\server\...` (including `\\?\`).
fn is_absolute_windows(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with(r"\\")
}

/// Parses a request; the pipe is an input like any other.
pub fn decode_send_request(b: &[u8]) -> Option<Vec<PathBuf>> {
    if b.len() < 6 || b.len() > MAX_SEND_REQUEST_LEN || !is_send_request(b) {
        return None;
    }
    let n = u16::from_le_bytes([b[4], b[5]]) as usize;
    if n == 0 || n > MAX_SEND_FILES {
        return None;
    }
    let mut at = 6;
    let mut paths = Vec::with_capacity(n);
    for _ in 0..n {
        let len = u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize;
        at += 2;
        let s = std::str::from_utf8(b.get(at..at + len)?).ok()?;
        at += len;
        if s.is_empty() || len > MAX_SEND_PATH || s.contains('\0') || !is_absolute_windows(s) {
            return None;
        }
        paths.push(PathBuf::from(s));
    }
    (at == b.len()).then_some(paths)
}

/// The agent's answer to a send request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReply {
    Offered { offered: u16, failed: u16 },
    NoClient,
    Rejected,
}

pub fn encode_send_reply(r: SendReply) -> [u8; SEND_REPLY_LEN] {
    let (status, a, b) = match r {
        SendReply::Offered { offered, failed } => (1u8, offered, failed),
        SendReply::NoClient => (0, 0, 0),
        SendReply::Rejected => (2, 0, 0),
    };
    let [a0, a1] = a.to_le_bytes();
    let [b0, b1] = b.to_le_bytes();
    [status, a0, a1, b0, b1]
}

pub fn decode_send_reply(b: &[u8]) -> SendReply {
    match b {
        [1, a0, a1, b0, b1] => SendReply::Offered {
            offered: u16::from_le_bytes([*a0, *a1]),
            failed: u16::from_le_bytes([*b0, *b1]),
        },
        [0, 0, 0, 0, 0] => SendReply::NoClient,
        _ => SendReply::Rejected,
    }
}

// --------------------------------------------------------- Send To

/// File name of the shortcut in the user's SendTo folder.
pub const SENDTO_NAME: &str = "Send to my PC (Remora).lnk";

/// The shortcut `install` creates (and `uninstall` removes), as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortcut {
    pub path: PathBuf,
    pub target: String,
    pub arguments: String,
    pub description: String,
    pub icon: String,
}

pub fn sendto_shortcut(sendto_dir: &Path, exe: &str) -> Shortcut {
    Shortcut {
        path: sendto_dir.join(SENDTO_NAME),
        target: exe.to_string(),
        // Explorer appends the selected files, each quoted.
        arguments: "send".into(),
        description: "Send the selected files to the PC you connect from, through Remora.".into(),
        icon: exe.to_string(),
    }
}

impl std::fmt::Display for Shortcut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "shortcut {} -> \"{}\" {} <files>",
            self.path.display(),
            self.target,
            self.arguments
        )
    }
}

// --------------------------------------------------------- send command

/// What the `send` process shows the user (a message box on Windows).
pub trait Notifier {
    fn notify(&mut self, text: &str);
}

/// The running agent's answer to one request, or why there was none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forwarded {
    Reply(SendReply),
    NoAgent,
    Error(String),
}

/// `remora-agent send <files>`: checks each path (`check` returns the
/// absolute path or a short reason), hands the good ones to the agent and
/// tells the user only about problems. Returns the exit code.
pub fn send_command(
    args: &[String],
    check: &mut dyn FnMut(&str) -> Result<String, String>,
    forward: &mut dyn FnMut(&[u8]) -> Forwarded,
    notifier: &mut dyn Notifier,
) -> i32 {
    let mut good = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    for a in args {
        match check(a) {
            Ok(p) => good.push(p),
            Err(why) => {
                let name = Path::new(a)
                    .file_name()
                    .map_or_else(|| a.clone(), |n| n.to_string_lossy().into_owned());
                problems.push(format!("{name}: {why}"));
            }
        }
    }
    if good.is_empty() {
        notifier.notify(&format!("Nothing was sent.\n\n{}", problems.join("\n")));
        return 2;
    }
    let requests = match encode_send_requests(&good) {
        Ok(r) => r,
        Err(e) => {
            notifier.notify(&format!("Nothing was sent: {e}"));
            return 2;
        }
    };
    let (mut offered, mut failed) = (0u32, 0u32);
    for req in &requests {
        match forward(req) {
            Forwarded::Reply(SendReply::Offered {
                offered: o,
                failed: f,
            }) => {
                offered += u32::from(o);
                failed += u32::from(f);
            }
            Forwarded::Reply(SendReply::NoClient) | Forwarded::NoAgent => {
                notifier.notify(
                    "Remora is not connected to this session, or sending files to your PC is \
                     not switched on there (or not confirmed on this computer yet).\n\n\
                     Connect with Remora, allow files to your PC, and try again.",
                );
                return 3;
            }
            Forwarded::Reply(SendReply::Rejected) | Forwarded::Error(_) => {
                notifier.notify("The Remora agent in this session refused the request.");
                return 3;
            }
        }
    }
    if failed > 0 {
        problems.push(format!("{failed} file(s) could not be read by the agent"));
    }
    if !problems.is_empty() {
        notifier.notify(&format!(
            "{offered} file(s) offered to Remora. Not sent:\n\n{}",
            problems.join("\n")
        ));
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder() {
        assert_eq!(
            receive_folder(Some(r"D:\Dl".into()), Some(r"C:\Users\u".into())),
            Some(PathBuf::from(r"D:\Dl").join("From Remora"))
        );
        assert_eq!(
            receive_folder(None, Some(PathBuf::from(r"C:\Users\u"))),
            Some(
                PathBuf::from(r"C:\Users\u")
                    .join("Downloads")
                    .join("From Remora")
            )
        );
        assert_eq!(receive_folder(None, None), None);
    }

    #[test]
    fn zone() {
        assert_eq!(
            zone_stream(Path::new(r"C:\x\a.txt")),
            PathBuf::from(r"C:\x\a.txt:Zone.Identifier")
        );
        assert!(ZONE_IDENTIFIER.contains("ZoneId=3"));
    }

    #[test]
    fn reserved() {
        for n in ["a.remora-part", "A.REMORA-PART.META", "x.tmp", "x.TMP"] {
            assert!(reserved_name(n), "{n}");
        }
        for n in ["a.txt", "remora-part", "a.tmpl", "a.remora-partx"] {
            assert!(!reserved_name(n), "{n}");
        }
    }

    #[test]
    fn facts() {
        let ok = FileFacts {
            attributes: 0x20,
            disk_file: true,
        };
        assert!(check_facts(ok).is_ok());
        // FILE_ATTRIBUTE_OFFLINE | HIDDEN | READONLY: still a file.
        assert!(
            check_facts(FileFacts {
                attributes: 0x1000 | 0x2 | 0x1,
                ..ok
            })
            .is_ok()
        );
        for a in [
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_DEVICE,
        ] {
            assert!(
                check_facts(FileFacts {
                    attributes: a,
                    ..ok
                })
                .is_err(),
                "{a:#x}"
            );
        }
        assert!(
            check_facts(FileFacts {
                disk_file: false,
                ..ok
            })
            .is_err()
        );
    }

    #[test]
    fn send_request_round_trip_and_split() {
        let paths: Vec<String> = (0..150).map(|i| format!(r"C:\data\file {i}.bin")).collect();
        let reqs = encode_send_requests(&paths).unwrap();
        assert_eq!(reqs.len(), 3, "64 per request");
        let back: Vec<String> = reqs
            .iter()
            .flat_map(|r| decode_send_request(r).unwrap())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(back, paths);
        // Long paths split by size too.
        let long: Vec<String> = (0..20)
            .map(|i| format!(r"C:\{}{i}", "x".repeat(8000)))
            .collect();
        let reqs = encode_send_requests(&long).unwrap();
        assert!(reqs.len() > 1);
        assert!(reqs.iter().all(|r| r.len() <= MAX_SEND_REQUEST_LEN));
        assert_eq!(
            reqs.iter()
                .map(|r| decode_send_request(r).unwrap().len())
                .sum::<usize>(),
            20
        );
        assert!(encode_send_requests(&["x".repeat(MAX_SEND_PATH + 1)]).is_err());
        assert!(encode_send_requests(&[String::new()]).is_err());
        assert_eq!(encode_send_requests(&[]).unwrap().len(), 0);
    }

    #[test]
    fn send_request_rejects_malformed() {
        let good = encode_send_requests(&[r"C:\a.txt".into()])
            .unwrap()
            .remove(0);
        assert!(decode_send_request(&good).is_some());
        for n in 0..good.len() {
            assert!(decode_send_request(&good[..n]).is_none(), "truncated {n}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_send_request(&trailing).is_none());
        let mut zero = good.clone();
        zero[4] = 0;
        assert!(decode_send_request(&zero).is_none());
        let mut magic = good.clone();
        magic[3] = b'2';
        assert!(decode_send_request(&magic).is_none());
        for rel in ["a.txt", r"..\a.txt", "C:a.txt", "\0"] {
            let mut r = b"RMS1\x01\x00".to_vec();
            r.extend_from_slice(&(rel.len() as u16).to_le_bytes());
            r.extend_from_slice(rel.as_bytes());
            assert!(decode_send_request(&r).is_none(), "{rel:?}");
        }
        let unc = encode_send_requests(&[r"\\srv\share\a".into()]).unwrap();
        assert!(decode_send_request(&unc[0]).is_some());
        // The open-url magic is not a send request.
        assert!(!is_send_request(b"RMU1...."));
    }

    #[test]
    fn send_reply() {
        for r in [
            SendReply::Offered {
                offered: 3,
                failed: 1,
            },
            SendReply::NoClient,
            SendReply::Rejected,
        ] {
            assert_eq!(decode_send_reply(&encode_send_reply(r)), r);
        }
        assert_eq!(decode_send_reply(&[1, 0]), SendReply::Rejected);
        assert_eq!(decode_send_reply(&[]), SendReply::Rejected);
    }

    #[test]
    fn shortcut_plan() {
        let s = sendto_shortcut(
            Path::new(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\SendTo"),
            r"C:\Tools\remora-agent.exe",
        );
        assert_eq!(
            s.path,
            PathBuf::from(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\SendTo")
                .join("Send to my PC (Remora).lnk")
        );
        assert_eq!(s.target, r"C:\Tools\remora-agent.exe");
        assert_eq!(s.arguments, "send");
        assert!(s.to_string().contains("send <files>"));
    }

    #[derive(Default)]
    struct Boxes(Vec<String>);
    impl Notifier for Boxes {
        fn notify(&mut self, text: &str) {
            self.0.push(text.to_string());
        }
    }

    fn check_ok(a: &str) -> Result<String, String> {
        if a.ends_with('\\') {
            Err("folders cannot be sent yet".into())
        } else {
            Ok(format!(r"C:\{a}"))
        }
    }

    #[test]
    fn send_command_paths() {
        // All good, agent offers: silent success.
        let mut boxes = Boxes::default();
        let mut sent = Vec::new();
        let code = send_command(
            &["a.txt".into(), "b.txt".into()],
            &mut check_ok,
            &mut |r| {
                sent.push(decode_send_request(r).unwrap());
                Forwarded::Reply(SendReply::Offered {
                    offered: 2,
                    failed: 0,
                })
            },
            &mut boxes,
        );
        assert_eq!(code, 0);
        assert!(boxes.0.is_empty());
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0][1], PathBuf::from(r"C:\b.txt"));

        // No agent or no client: one message, no retry.
        for f in [Forwarded::NoAgent, Forwarded::Reply(SendReply::NoClient)] {
            let mut boxes = Boxes::default();
            let code = send_command(&["a".into()], &mut check_ok, &mut |_| f.clone(), &mut boxes);
            assert_eq!(code, 3);
            assert_eq!(boxes.0.len(), 1);
            assert!(boxes.0[0].contains("not connected"));
        }

        // A folder among files: the files go, the user hears about the folder.
        let mut boxes = Boxes::default();
        let code = send_command(
            &["a.txt".into(), r"dir\".into()],
            &mut check_ok,
            &mut |_| {
                Forwarded::Reply(SendReply::Offered {
                    offered: 1,
                    failed: 0,
                })
            },
            &mut boxes,
        );
        assert_eq!(code, 1);
        assert!(boxes.0[0].contains("folders"), "{:?}", boxes.0);

        // Only folders: nothing is forwarded.
        let mut boxes = Boxes::default();
        let mut called = false;
        let code = send_command(
            &[r"dir\".into()],
            &mut check_ok,
            &mut |_| {
                called = true;
                Forwarded::NoAgent
            },
            &mut boxes,
        );
        assert_eq!(code, 2);
        assert!(!called);
        assert!(boxes.0[0].starts_with("Nothing was sent"));
    }
}
