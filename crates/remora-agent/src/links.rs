//! Open links clicked in the session on the user's local PC (RDP-44): URL
//! checks, the per-user "browser" registration as data, the local browser
//! fallback, and the message `open-url` sends to the running agent.
//!
//! Flow: the user picks "Remora Agent" once as the default app for http and
//! https (Settings > Apps > Default apps). Windows then starts
//! `remora-agent.exe open-url "<url>"`, which validates the URL and hands it
//! over a named pipe to the agent running in the same session. The agent
//! passes it to the protocol, which sends it to the Remora client; the
//! client asks the user before opening it.
//!
//! The agent cannot make itself the default browser: since Windows 10 the
//! `UserChoice` keys carry a hash, and on current Windows 11 the UCPD driver
//! blocks writes to them. The user picks it once, or an admin deploys a
//! default-associations XML (`dism /Import-DefaultAppAssociations`).
//!
//! Fallback when no Remora client is connected: the browser that was the
//! http default when the user registered the agent. Its `shell\open\command`
//! is captured at registration time and stored with the agent's settings;
//! `open-url` starts that program directly (`CreateProcess`, no shell) with
//! the validated URL as one argument. Without a captured browser the link is
//! dropped and logged; the agent never guesses a browser.

/// Longest URL the agent forwards. Browsers take longer ones, but links
/// clicked in documents and mail stay far below this.
pub const MAX_URL_LEN: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    Empty,
    TooLong(usize),
    /// Only `http` and `https`.
    Scheme,
    NoHost,
    /// `user:password@host`: a phishing pattern; not forwarded.
    UserInfo,
    /// Whitespace, control characters or quotes inside the URL.
    BadChar,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty URL"),
            Self::TooLong(n) => write!(f, "URL of {n} bytes over {MAX_URL_LEN}"),
            Self::Scheme => write!(f, "only http and https links are forwarded"),
            Self::NoHost => write!(f, "URL has no host"),
            Self::UserInfo => write!(f, "URL with user name or password"),
            Self::BadChar => write!(f, "URL contains spaces, quotes or control characters"),
        }
    }
}

/// Checks a URL and returns it with a lower-case scheme.
pub fn validate_url(raw: &str) -> Result<String, UrlError> {
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    if s.is_empty() {
        return Err(UrlError::Empty);
    }
    if s.len() > MAX_URL_LEN {
        return Err(UrlError::TooLong(s.len()));
    }
    if s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '"')
    {
        return Err(UrlError::BadChar);
    }
    let (scheme, rest) = s.split_once("://").ok_or(UrlError::Scheme)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(UrlError::Scheme);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(UrlError::UserInfo);
    }
    if authority.is_empty() || authority.starts_with(':') {
        return Err(UrlError::NoHost);
    }
    Ok(format!("{scheme}://{rest}"))
}

/// The open-url pipe: one per session and user. Named pipes have no session
/// namespace, so the name carries both; the pipe's DACL admits only the
/// user, and the client checks the server's session before sending.
pub fn pipe_name(session_id: u32, user_sid: &str) -> String {
    format!(r"\\.\pipe\RemoraAgent-{session_id}-{user_sid}-open-url")
}

const PIPE_MAGIC: &[u8; 4] = b"RMU1";
/// Largest request on the pipe.
pub const MAX_REQUEST_LEN: usize = 8 + MAX_URL_LEN;

/// The agent's one-byte answer.
pub const REPLY_FORWARDED: u8 = 1;
pub const REPLY_NO_CLIENT: u8 = 0;
pub const REPLY_REJECTED: u8 = 2;

/// `RMU1`, `u32` little-endian length, UTF-8 URL.
pub fn encode_request(url: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + url.len());
    v.extend_from_slice(PIPE_MAGIC);
    v.extend_from_slice(&(url.len() as u32).to_le_bytes());
    v.extend_from_slice(url.as_bytes());
    v
}

/// Parses a request and validates the URL again: the pipe is an input like
/// any other.
pub fn decode_request(b: &[u8]) -> Option<String> {
    if b.len() < 8 || b.len() > MAX_REQUEST_LEN || &b[..4] != PIPE_MAGIC {
        return None;
    }
    let n = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize;
    if b.len() != 8 + n {
        return None;
    }
    let url = std::str::from_utf8(&b[8..]).ok()?;
    validate_url(url).ok()
}

/// One `HKEY_CURRENT_USER` change. The plan is data so it can be printed
/// (`--dry-run`) and tested; `win::apply` executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegOp {
    /// Create the key if needed and set a `REG_SZ` value (`None`: default).
    SetString {
        key: String,
        name: Option<String>,
        value: String,
    },
    /// Delete a key with all its subkeys (missing is fine).
    DeleteTree { key: String },
    /// Delete one value (missing is fine).
    DeleteValue { key: String, name: String },
}

impl std::fmt::Display for RegOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegOp::SetString { key, name, value } => write!(
                f,
                "set    HKCU\\{key} [{}] = {value}",
                name.as_deref().unwrap_or("(default)")
            ),
            RegOp::DeleteTree { key } => write!(f, "delete HKCU\\{key} (tree)"),
            RegOp::DeleteValue { key, name } => write!(f, "delete HKCU\\{key} [{name}]"),
        }
    }
}

pub const PROG_ID: &str = "RemoraAgent.Url";
pub const APP_NAME: &str = "Remora Agent";
/// The agent's own settings key.
pub const AGENT_KEY: &str = r"Software\rdp-rs\RemoraAgent";
pub const CAPABILITIES_KEY: &str = r"Software\rdp-rs\RemoraAgent\Capabilities";
pub const REGISTERED_APPS_KEY: &str = r"Software\RegisteredApplications";
pub const FALLBACK_VALUE: &str = "FallbackBrowserCommand";
const DESCRIPTION: &str =
    "Opens links from this remote session in the browser on your own PC, through Remora.";

fn prog_id_key() -> String {
    format!(r"Software\Classes\{PROG_ID}")
}

/// `"<exe>" open-url "%1"`, the command Windows runs for a link.
pub fn open_command(exe: &str) -> String {
    format!("\"{exe}\" open-url \"%1\"")
}

/// Registers the agent as an app that can open http and https links:
/// a ProgId, Capabilities with URL associations, and the
/// RegisteredApplications entry that lists it in Default apps.
pub fn register_plan(exe: &str, fallback_command: Option<&str>) -> Vec<RegOp> {
    let set = |key: &str, name: Option<&str>, value: &str| RegOp::SetString {
        key: key.to_string(),
        name: name.map(String::from),
        value: value.to_string(),
    };
    let pk = prog_id_key();
    let icon = format!("\"{exe}\",0");
    let mut ops = vec![
        set(&pk, None, "Remora link"),
        set(&format!(r"{pk}\DefaultIcon"), None, &icon),
        set(
            &format!(r"{pk}\shell\open\command"),
            None,
            &open_command(exe),
        ),
        set(
            &format!(r"{pk}\Application"),
            Some("ApplicationName"),
            APP_NAME,
        ),
        set(
            &format!(r"{pk}\Application"),
            Some("ApplicationDescription"),
            DESCRIPTION,
        ),
        set(CAPABILITIES_KEY, Some("ApplicationName"), APP_NAME),
        set(
            CAPABILITIES_KEY,
            Some("ApplicationDescription"),
            DESCRIPTION,
        ),
        set(CAPABILITIES_KEY, Some("ApplicationIcon"), &icon),
        set(
            &format!(r"{CAPABILITIES_KEY}\URLAssociations"),
            Some("http"),
            PROG_ID,
        ),
        set(
            &format!(r"{CAPABILITIES_KEY}\URLAssociations"),
            Some("https"),
            PROG_ID,
        ),
        set(REGISTERED_APPS_KEY, Some(APP_NAME), CAPABILITIES_KEY),
    ];
    ops.push(match fallback_command {
        Some(cmd) => set(AGENT_KEY, Some(FALLBACK_VALUE), cmd),
        None => RegOp::DeleteValue {
            key: AGENT_KEY.into(),
            name: FALLBACK_VALUE.into(),
        },
    });
    ops
}

/// Undoes [`register_plan`]. If the user had picked the agent as their
/// browser, Windows falls back to asking which app to use.
pub fn unregister_plan() -> Vec<RegOp> {
    vec![
        RegOp::DeleteValue {
            key: REGISTERED_APPS_KEY.into(),
            name: APP_NAME.into(),
        },
        RegOp::DeleteTree { key: prog_id_key() },
        RegOp::DeleteTree {
            key: CAPABILITIES_KEY.into(),
        },
        RegOp::DeleteValue {
            key: AGENT_KEY.into(),
            name: FALLBACK_VALUE.into(),
        },
    ]
}

/// A program and its arguments, split from a `shell\open\command` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    pub exe: String,
    pub args: Vec<String>,
}

/// Splits a `shell\open\command` value. The program is the first quoted
/// token or, unquoted, everything up to the first `.exe` (paths with spaces
/// are often unquoted there). Arguments split on whitespace outside quotes.
pub fn parse_command(s: &str) -> Option<CommandLine> {
    let s = s.trim();
    let (exe, rest) = if let Some(q) = s.strip_prefix('"') {
        let end = q.find('"')?;
        (q[..end].to_string(), &q[end + 1..])
    } else {
        let lower = s.to_ascii_lowercase();
        let mut end = None;
        for (i, _) in lower.match_indices(".exe") {
            let after = i + 4;
            if lower[after..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace())
            {
                end = Some(after);
                break;
            }
        }
        let end = end?;
        (s[..end].to_string(), &s[end..])
    };
    let mut args = Vec::new();
    let mut cur = String::new();
    let (mut in_quotes, mut has_token) = (false, false);
    for c in rest.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(cur);
    }
    Some(CommandLine { exe, args })
}

/// Whether a captured browser command can serve as the fallback: an
/// absolute `.exe` path without environment variables, and not the agent.
pub fn usable_fallback(cmd: &str, own_exe: &str) -> Option<CommandLine> {
    let c = parse_command(cmd)?;
    let lower = c.exe.to_ascii_lowercase();
    let absolute = c.exe.len() > 3 && c.exe.as_bytes()[1] == b':' && c.exe.as_bytes()[2] == b'\\';
    if !absolute || !lower.ends_with(".exe") || c.exe.contains('%') {
        return None;
    }
    if c.exe.eq_ignore_ascii_case(own_exe) || lower.ends_with("\\remora-agent.exe") {
        return None;
    }
    Some(c)
}

/// The arguments for the fallback browser: `%1` / `%L` replaced by the URL,
/// or the URL appended if the command has no placeholder.
pub fn fallback_args(cmd: &CommandLine, url: &str) -> Vec<String> {
    let mut placed = false;
    let mut out: Vec<String> = cmd
        .args
        .iter()
        .map(|a| {
            if a.contains("%1") || a.contains("%L") || a.contains("%l") {
                placed = true;
                a.replace("%1", url).replace("%L", url).replace("%l", url)
            } else {
                a.clone()
            }
        })
        .collect();
    if !placed {
        out.push(url.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation() {
        assert_eq!(
            validate_url("  HTTPS://Example.com/a?b=c#d \n").as_deref(),
            Ok("https://Example.com/a?b=c#d")
        );
        assert_eq!(
            validate_url("http://h:8080").as_deref(),
            Ok("http://h:8080")
        );
        assert!(validate_url("https://例え.jp/パス").is_ok());
        assert_eq!(validate_url(""), Err(UrlError::Empty));
        assert_eq!(validate_url("file:///C:/x"), Err(UrlError::Scheme));
        assert_eq!(validate_url("javascript:alert(1)"), Err(UrlError::Scheme));
        assert_eq!(validate_url("ms-settings://x"), Err(UrlError::Scheme));
        assert_eq!(validate_url("https:/x"), Err(UrlError::Scheme));
        assert_eq!(validate_url("https://"), Err(UrlError::NoHost));
        assert_eq!(validate_url("https:///path"), Err(UrlError::NoHost));
        assert_eq!(validate_url("https://:80/"), Err(UrlError::NoHost));
        assert_eq!(
            validate_url("https://bank.com@evil.example/"),
            Err(UrlError::UserInfo)
        );
        // An @ after the authority is fine.
        assert!(validate_url("https://h/@user").is_ok());
        assert_eq!(validate_url("https://h/a b"), Err(UrlError::BadChar));
        assert_eq!(validate_url("https://h/\" --evil"), Err(UrlError::BadChar));
        assert_eq!(validate_url("https://h/\u{7}"), Err(UrlError::BadChar));
        let long = format!("https://h/{}", "a".repeat(MAX_URL_LEN));
        assert!(matches!(validate_url(&long), Err(UrlError::TooLong(_))));
        let max = format!("https://h/{}", "a".repeat(MAX_URL_LEN - 10));
        assert!(validate_url(&max).is_ok());
    }

    #[test]
    fn pipe_messages() {
        let r = encode_request("https://e.example/x");
        assert_eq!(decode_request(&r).as_deref(), Some("https://e.example/x"));
        assert_eq!(decode_request(&r[..r.len() - 1]), None);
        let mut bad = r.clone();
        bad[0] = b'X';
        assert_eq!(decode_request(&bad), None);
        // A well-formed message with a bad URL is refused too.
        assert_eq!(decode_request(&encode_request("file:///etc")), None);
        let big = vec![0u8; MAX_REQUEST_LEN + 1];
        assert_eq!(decode_request(&big), None);
        assert!(pipe_name(3, "S-1-5-21-1").starts_with(r"\\.\pipe\RemoraAgent-3-S-1-5-21-1"));
    }

    #[test]
    fn registration_plan() {
        let exe = r"C:\Users\ann\AppData\Local\Programs\Remora\remora-agent.exe";
        let ops = register_plan(exe, Some(r#""C:\b\msedge.exe" --single-argument %1"#));
        let get = |key: &str, name: Option<&str>| {
            ops.iter().find_map(|o| match o {
                RegOp::SetString {
                    key: k,
                    name: n,
                    value,
                } if k == key && n.as_deref() == name => Some(value.clone()),
                _ => None,
            })
        };
        assert_eq!(
            get(r"Software\Classes\RemoraAgent.Url\shell\open\command", None).as_deref(),
            Some(r#""C:\Users\ann\AppData\Local\Programs\Remora\remora-agent.exe" open-url "%1""#)
        );
        // RegisteredApplications points at the Capabilities key, which maps
        // both schemes to the ProgId.
        let caps = get(REGISTERED_APPS_KEY, Some(APP_NAME)).unwrap();
        assert_eq!(caps, CAPABILITIES_KEY);
        let assoc = format!(r"{caps}\URLAssociations");
        assert_eq!(get(&assoc, Some("http")).as_deref(), Some(PROG_ID));
        assert_eq!(get(&assoc, Some("https")).as_deref(), Some(PROG_ID));
        assert!(get(AGENT_KEY, Some(FALLBACK_VALUE)).is_some());
        // Everything stays under HKCU\Software, never UserChoice.
        for o in &ops {
            let k = match o {
                RegOp::SetString { key, .. }
                | RegOp::DeleteTree { key }
                | RegOp::DeleteValue { key, .. } => key,
            };
            assert!(k.starts_with("Software\\"), "{k}");
            assert!(!k.contains("UserChoice"));
        }
        // Without a fallback the old value is removed.
        assert!(register_plan(exe, None).contains(&RegOp::DeleteValue {
            key: AGENT_KEY.into(),
            name: FALLBACK_VALUE.into()
        }));
        // Unregistering removes what registering created.
        let un = unregister_plan();
        assert!(un.contains(&RegOp::DeleteTree {
            key: r"Software\Classes\RemoraAgent.Url".into()
        }));
        assert!(un.contains(&RegOp::DeleteTree {
            key: CAPABILITIES_KEY.into()
        }));
        assert!(un.contains(&RegOp::DeleteValue {
            key: REGISTERED_APPS_KEY.into(),
            name: APP_NAME.into()
        }));
    }

    #[test]
    fn browser_commands() {
        let edge = parse_command(
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument %1"#,
        )
        .unwrap();
        assert_eq!(
            edge.exe,
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        );
        assert_eq!(edge.args, ["--single-argument", "%1"]);
        assert_eq!(
            fallback_args(&edge, "https://e.example/"),
            ["--single-argument", "https://e.example/"]
        );
        let ff =
            parse_command(r#""C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "%1""#)
                .unwrap();
        assert_eq!(
            fallback_args(&ff, "https://e.example/"),
            ["-osint", "-url", "https://e.example/"]
        );
        let unquoted = parse_command(r"C:\Program Files\Br\br.exe %1").unwrap();
        assert_eq!(unquoted.exe, r"C:\Program Files\Br\br.exe");
        assert_eq!(unquoted.args, ["%1"]);
        let bare = parse_command(r"C:\b\x.exe").unwrap();
        assert_eq!(fallback_args(&bare, "https://e/"), ["https://e/"]);
        assert_eq!(parse_command(r#""C:\unterminated"#), None);
        assert_eq!(parse_command("notepad"), None);

        let own = r"C:\p\remora-agent.exe";
        assert!(usable_fallback(r#""C:\b\msedge.exe" %1"#, own).is_some());
        assert!(usable_fallback(&open_command(own), own).is_none());
        assert!(usable_fallback(r#""%ProgramFiles%\b.exe" %1"#, own).is_none());
        assert!(usable_fallback("b.exe %1", own).is_none());
        assert!(usable_fallback(r#""C:\b\run.cmd" %1"#, own).is_none());
    }
}
