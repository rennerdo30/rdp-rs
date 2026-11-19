//! SSH connections (RDP-87): Windows' own OpenSSH client (`ssh.exe`) in a
//! terminal window, Windows Terminal when it is there, else a console.
//!
//! - The command is an argument list, never a shell line: `-p port`,
//!   `-l user`, `-i key`, `--`, host. A host or user that starts with `-`
//!   (an option), or has spaces, quotes, control characters or `;` (Windows
//!   Terminal's command separator) is refused before anything starts.
//! - No password: `ssh.exe` cannot take one, so it asks in the terminal, or
//!   signs in with a key or the OpenSSH agent.
//! - The terminal is the user's own program: Remora starts it and lets go.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The program and arguments to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// No Windows Terminal: start ssh.exe in a console window of its own.
    pub new_console: bool,
}

/// What Remora says when there is no `ssh.exe`.
pub const NO_SSH: &str = "Windows' OpenSSH client is not installed. Add it in Settings → System → Optional features → OpenSSH Client, then open this connection again.";

/// Refuses a host that could be read as an option or break the command:
/// only letters, digits and `.-_:%` (names, IPv4, IPv6 with a zone), not
/// starting with `-`.
pub fn check_host(host: &str) -> Result<(), String> {
    let ok = !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:%".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{host:?} is not a host name or address SSH can use: letters, digits, dots, dashes and colons only."
        ))
    }
}

/// Refuses a user name that could be read as an option or break the
/// command. `DOMAIN\user` and `user@domain` (Windows OpenSSH servers) pass.
pub fn check_user(user: &str) -> Result<(), String> {
    let bad = user.starts_with('-')
        || user
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\";'`".contains(c));
    if bad {
        Err(format!(
            "{user:?} is not a user name SSH can use: no spaces, quotes or semicolons, and no leading dash."
        ))
    } else {
        Ok(())
    }
}

fn check_key(key: &Path) -> Result<(), String> {
    let s = key.to_string_lossy();
    if s.contains(';') || s.contains('"') || s.chars().any(char::is_control) {
        return Err(format!(
            "The key file path {s:?} has a semicolon or quote; move or rename the file."
        ));
    }
    Ok(())
}

/// `ssh.exe`'s arguments for a connection; the user may be empty (ssh then
/// uses the Windows user name), the key None (the agent or ~/.ssh keys).
pub fn ssh_args(
    host: &str,
    port: u16,
    user: &str,
    key: Option<&Path>,
    jump: Option<&str>,
) -> Result<Vec<OsString>, String> {
    check_host(host)?;
    check_user(user)?;
    let mut a: Vec<OsString> = Vec::new();
    if let Some(j) = jump.map(str::trim).filter(|j| !j.is_empty()) {
        a.extend(["-J".into(), jump_arg(j)?.into()]);
    }
    if port != 22 && port != 0 {
        a.extend(["-p".into(), port.to_string().into()]);
    }
    if !user.is_empty() {
        a.extend(["-l".into(), user.into()]);
    }
    if let Some(k) = key {
        check_key(k)?;
        a.extend(["-i".into(), k.as_os_str().to_owned()]);
    }
    // Nothing after this is an option.
    a.extend(["--".into(), host.into()]);
    Ok(a)
}

/// `-J`'s value for a jump host (`[user@]host[:port]`), with the same
/// checks as the host and user.
fn jump_arg(j: &str) -> Result<String, String> {
    let bad = || format!("{j:?} is not a jump host: write it as user@host or user@host:port.");
    let t = crate::ssh_tunnel::parse(j, "u").ok_or_else(bad)?;
    check_host(&t.host).map_err(|_| bad())?;
    let explicit_user = j.contains('@');
    if explicit_user {
        check_user(&t.user).map_err(|_| bad())?;
    }
    let host = if t.host.contains(':') {
        format!("[{}]", t.host)
    } else {
        t.host.clone()
    };
    let mut out = if explicit_user {
        format!("{}@{host}", t.user)
    } else {
        host
    };
    if t.port != 22 {
        out += &format!(":{}", t.port);
    }
    Ok(out)
}

/// A tab title Windows Terminal takes as one argument: printable, no `;`,
/// at most 60 characters.
fn title(name: &str) -> String {
    let t: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == ';' || c == '"' { ',' } else { c })
        .take(60)
        .collect();
    // Never something Windows Terminal could take for an option.
    match t.trim_start_matches(['-', ' ']) {
        "" => "SSH".into(),
        rest => rest.to_string(),
    }
}

/// The command: Windows Terminal's new tab with ssh.exe in it, or ssh.exe
/// in a console of its own.
pub fn command(ssh: &Path, wt: Option<&Path>, name: &str, args: Vec<OsString>) -> Launch {
    match wt {
        Some(wt) => {
            let mut a: Vec<OsString> = vec!["new-tab".into(), "--title".into(), title(name).into()];
            a.push(ssh.as_os_str().to_owned());
            a.extend(args);
            Launch {
                program: wt.to_path_buf(),
                args: a,
                new_console: false,
            }
        }
        None => Launch {
            program: ssh.to_path_buf(),
            args,
            new_console: true,
        },
    }
}

/// The first `file` in the directories of a PATH value.
fn on_path(path_var: Option<&OsStr>, file: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var?)
        .map(|d| d.join(file))
        .find(|p| p.is_file())
}

/// `%SystemRoot%\System32\OpenSSH\ssh.exe`, else `ssh.exe` on PATH.
pub fn find_ssh(system_root: Option<&Path>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    system_root
        .map(|r| r.join("System32").join("OpenSSH").join("ssh.exe"))
        .filter(|p| p.is_file())
        .or_else(|| on_path(path_var, "ssh.exe"))
}

/// Windows Terminal's `wt.exe` (an app alias in
/// `%LOCALAPPDATA%\Microsoft\WindowsApps`), else on PATH.
pub fn find_wt(local_app_data: Option<&Path>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    local_app_data
        .map(|d| d.join("Microsoft").join("WindowsApps").join("wt.exe"))
        // An app alias is a reparse point: it exists without being a file.
        .filter(|p| p.symlink_metadata().is_ok())
        .or_else(|| on_path(path_var, "wt.exe"))
}

/// The launch for a connection, from this PC's environment.
pub fn launch_for(
    name: &str,
    host: &str,
    port: u16,
    user: &str,
    key: Option<&Path>,
    jump: Option<&str>,
) -> Result<Launch, String> {
    let args = ssh_args(host, port, user, key, jump)?;
    let env = |k| std::env::var_os(k).map(PathBuf::from);
    let path = std::env::var_os("PATH");
    let ssh = find_ssh(env("SystemRoot").as_deref(), path.as_deref()).ok_or(NO_SSH)?;
    let wt = find_wt(env("LOCALAPPDATA").as_deref(), path.as_deref());
    Ok(command(&ssh, wt.as_deref(), name, args))
}

/// Starts it; the terminal then runs on its own.
pub fn start(l: &Launch) -> Result<(), String> {
    let mut cmd = std::process::Command::new(&l.program);
    cmd.args(&l.args);
    #[cfg(windows)]
    if l.new_console {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        cmd.creation_flags(CREATE_NEW_CONSOLE);
    }
    cmd.spawn()
        .map(drop)
        .map_err(|e| format!("Cannot start {}: {e}", l.program.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(a: &[OsString]) -> Vec<&str> {
        a.iter().map(|s| s.to_str().unwrap()).collect()
    }

    #[test]
    fn builds_ssh_arguments() {
        assert_eq!(
            strs(&ssh_args("web1", 22, "", None, None).unwrap()),
            ["--", "web1"]
        );
        assert_eq!(
            strs(
                &ssh_args(
                    "10.0.0.5",
                    2222,
                    "ops",
                    Some(Path::new(r"C:\keys\id ed")),
                    None
                )
                .unwrap()
            ),
            [
                "-p",
                "2222",
                "-l",
                "ops",
                "-i",
                r"C:\keys\id ed",
                "--",
                "10.0.0.5"
            ]
        );
        assert_eq!(
            strs(&ssh_args("fe80::1%3", 22, r"CORP\ann", None, None).unwrap()),
            ["-l", r"CORP\ann", "--", "fe80::1%3"]
        );
        assert!(ssh_args("host", 22, "ann@corp.example", None, None).is_ok());
    }

    #[test]
    fn a_jump_host_goes_to_ssh_as_minus_j() {
        assert_eq!(
            strs(&ssh_args("db1", 22, "ops", None, Some("me@bastion:2222")).unwrap()),
            ["-J", "me@bastion:2222", "-l", "ops", "--", "db1"]
        );
        assert_eq!(
            strs(&ssh_args("db1", 22, "", None, Some("bastion")).unwrap())[..2],
            ["-J", "bastion"],
            "no user: ssh's own default"
        );
        assert_eq!(
            strs(&ssh_args("db1", 22, "", None, Some("fd00::1")).unwrap())[1],
            "[fd00::1]"
        );
        for bad in ["-oProxyCommand=x", "a;b", "me@x;calc", "me@\"q\"@h", "h:x"] {
            assert!(ssh_args("db1", 22, "", None, Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_options_and_separators() {
        for host in [
            "-oProxyCommand=calc",
            "",
            "a b",
            "host;calc",
            "host\"",
            "h\nx",
            "[::1]",
            "host/x",
        ] {
            assert!(
                ssh_args(host, 22, "u", None, None).is_err(),
                "host {host:?}"
            );
        }
        for user in ["-oX=y", "a b", "u;calc", "u\"", "u'", "u\t"] {
            assert!(
                ssh_args("host", 22, user, None, None).is_err(),
                "user {user:?}"
            );
        }
        assert!(ssh_args("host", 22, "u", Some(Path::new(r"C:\k;calc")), None).is_err());
    }

    #[test]
    fn windows_terminal_gets_a_new_tab() {
        let args = ssh_args("web1", 22, "ops", None, None).unwrap();
        let ssh = Path::new(r"C:\Windows\System32\OpenSSH\ssh.exe");
        let wt = Path::new(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\wt.exe");
        let l = command(ssh, Some(wt), "Web; prod\"1", args.clone());
        assert_eq!(l.program, wt);
        assert!(!l.new_console);
        assert_eq!(
            strs(&l.args),
            [
                "new-tab",
                "--title",
                "Web, prod,1",
                r"C:\Windows\System32\OpenSSH\ssh.exe",
                "-l",
                "ops",
                "--",
                "web1"
            ]
        );
        let dashed = command(ssh, Some(wt), "--help -d C:\\x", args.clone());
        assert_eq!(dashed.args[2], "help -d C:\\x", "no option as the title");
        assert_eq!(command(ssh, Some(wt), "-", args.clone()).args[2], "SSH");
        let console = command(ssh, None, "Web", args.clone());
        assert_eq!(
            (console.program.as_path(), console.new_console),
            (ssh, true)
        );
        assert_eq!(console.args, args);
    }

    #[test]
    fn finds_ssh_and_wt() {
        let dir = std::env::temp_dir().join(format!("remora-ssh-find-{}", std::process::id()));
        let root = dir.join("Windows");
        let bin = dir.join("bin");
        let local = dir.join("Local");
        std::fs::create_dir_all(root.join("System32").join("OpenSSH")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(local.join("Microsoft").join("WindowsApps")).unwrap();
        let path = std::env::join_paths([&bin]).unwrap();
        assert_eq!(find_ssh(Some(&root), Some(&path)), None);
        std::fs::write(bin.join("ssh.exe"), b"").unwrap();
        assert_eq!(
            find_ssh(Some(&root), Some(&path)),
            Some(bin.join("ssh.exe"))
        );
        let system = root.join("System32").join("OpenSSH").join("ssh.exe");
        std::fs::write(&system, b"").unwrap();
        assert_eq!(
            find_ssh(Some(&root), Some(&path)),
            Some(system),
            "Windows' own first"
        );
        assert_eq!(find_wt(Some(&local), Some(&path)), None);
        let wt = local.join("Microsoft").join("WindowsApps").join("wt.exe");
        std::fs::write(&wt, b"").unwrap();
        assert_eq!(find_wt(Some(&local), Some(&path)), Some(wt));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
