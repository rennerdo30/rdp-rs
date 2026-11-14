//! Start-up integration: a per-user scheduled task (RDP-41 "How it starts").
//!
//! Why a scheduled task and not `HKCU\...\Run`: Run keys are processed by
//! Explorer, and a RemoteApp session has no Explorer (its shell is
//! `rdpshell.exe`), so a Run entry never starts there. A task with a logon
//! trigger starts in every kind of session, and its session-state-change
//! trigger ("on remote connect") restarts the agent if it was not running
//! when a client reconnects.
//!
//! The task:
//! - runs only as the current user, only while they are logged on
//!   (`InteractiveToken`), with least privileges, hidden;
//! - has a logon trigger and a remote-connect trigger, both for this user;
//! - allows parallel instances, because one user can have several sessions
//!   on an RDS host; the agent's per-session mutex keeps one per session;
//! - restarts the agent up to 3 times, a minute apart, if it fails;
//! - has no time limit.
//!
//! It is created with `schtasks.exe /Create /XML` (no COM), from
//! `%SystemRoot%\System32` by absolute path. This module builds the XML and
//! the command lines as data; `win::apply` runs them.

/// The task name: one per user, so two users on one host never collide.
pub fn task_name(user_sid: &str) -> String {
    format!("Remora Agent {user_sid}")
}

/// What the task needs to know about the user and the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    /// Full path of `remora-agent.exe` (where it stays installed).
    pub exe: String,
    /// The user's SID (`S-1-5-21-...`), for the principal.
    pub user_sid: String,
    /// `DOMAIN\user`, for the triggers.
    pub user_account: String,
    pub agent_version: String,
}

/// The arguments the task starts the agent with.
pub const TASK_ARGUMENTS: &str = "run";

/// Escapes text for XML element content and attribute values.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The Task Scheduler 1.2 XML (schema `2004/02/mit/task`), as text. Write
/// it as UTF-16LE with a BOM ([`utf16_with_bom`]); schtasks rejects some
/// UTF-8 files.
pub fn task_xml(spec: &TaskSpec) -> String {
    let exe = xml_escape(&spec.exe);
    let sid = xml_escape(&spec.user_sid);
    let account = xml_escape(&spec.user_account);
    let version = xml_escape(&spec.agent_version);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>{account}</Author>
    <Description>Remora agent {version}: connects this session to the Remora client (file transfer, links, session info). Runs only while you are logged on, without elevation.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{account}</UserId>
    </LogonTrigger>
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <StateChange>RemoteConnect</StateChange>
      <UserId>{account}</UserId>
    </SessionStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{exe}"</Command>
      <Arguments>{TASK_ARGUMENTS}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// UTF-16LE bytes with a byte-order mark, as schtasks expects for `/XML`.
pub fn utf16_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// `schtasks.exe` arguments (the program path is resolved separately).
pub fn create_args(name: &str, xml_path: &str) -> Vec<String> {
    ["/Create", "/TN", name, "/XML", xml_path, "/F"]
        .map(String::from)
        .to_vec()
}

pub fn delete_args(name: &str) -> Vec<String> {
    ["/Delete", "/TN", name, "/F"].map(String::from).to_vec()
}

pub fn query_args(name: &str) -> Vec<String> {
    ["/Query", "/TN", name, "/XML", "ONE"]
        .map(String::from)
        .to_vec()
}

/// What `status` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    NotInstalled,
    Installed {
        enabled: bool,
        /// The task starts this very executable.
        points_here: bool,
        command: String,
    },
    /// schtasks failed in a way that says nothing about the task.
    Unknown(String),
}

/// Decodes schtasks output: UTF-16LE (with or without BOM) or 8-bit text.
pub fn decode_output(bytes: &[u8]) -> String {
    let utf16 = bytes.starts_with(&[0xFF, 0xFE])
        || (bytes.len() >= 4 && bytes.len().is_multiple_of(2) && bytes[1] == 0 && bytes[3] == 0);
    if utf16 {
        let body = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// The text of the first `<tag>...</tag>` after `from`.
fn element<'a>(xml: &'a str, tag: &str, from: usize) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.get(from..)?.find(&open)? + from + open.len();
    let end = xml.get(start..)?.find(&close)? + start;
    xml.get(start..end)
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Interprets `schtasks /Query /TN <name> /XML ONE`. Exit code 0 with a
/// task document means installed; exit code 1 is "task does not exist"
/// (schtasks' error text is localized, so only the code is used).
pub fn parse_query(exit_code: Option<i32>, stdout: &[u8], this_exe: &str) -> TaskStatus {
    match exit_code {
        Some(0) => {}
        Some(1) => return TaskStatus::NotInstalled,
        other => return TaskStatus::Unknown(format!("schtasks exit code {other:?}")),
    }
    let xml = decode_output(stdout);
    let Some(exec) = xml.find("<Exec>") else {
        return TaskStatus::Unknown("no <Exec> action in the task".into());
    };
    let command = element(&xml, "Command", exec)
        .map(|c| xml_unescape(c.trim()))
        .unwrap_or_default();
    // The task-level <Enabled> is the one in <Settings> (no nested settings
    // block has one); trigger <Enabled> elements come before <Settings>.
    // Missing means enabled (the schema default).
    let enabled = xml
        .find("<Settings>")
        .and_then(|s| {
            let settings = &xml[s..s + xml[s..].find("</Settings>")?];
            element(settings, "Enabled", 0)
        })
        .is_none_or(|v| v.trim().eq_ignore_ascii_case("true"));
    let unquoted = command.trim_matches('"');
    TaskStatus::Installed {
        enabled,
        points_here: unquoted.eq_ignore_ascii_case(this_exe),
        command,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> TaskSpec {
        TaskSpec {
            exe: r"C:\Users\Ann & Bob\AppData\Local\Programs\Remora\remora-agent.exe".into(),
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            user_account: r"HOST\ann<x>".into(),
            agent_version: "0.1.0".into(),
        }
    }

    #[test]
    fn task_xml_has_the_required_shape() {
        let x = task_xml(&spec());
        assert!(x.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"));
        assert!(x.contains("<LogonTrigger>"));
        assert!(x.contains("<StateChange>RemoteConnect</StateChange>"));
        // Both triggers are for this user only, never "any user".
        assert_eq!(x.matches(r"<UserId>HOST\ann&lt;x&gt;</UserId>").count(), 2);
        assert!(x.contains("<UserId>S-1-5-21-1-2-3-1001</UserId>"));
        assert!(x.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(x.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(!x.contains("HighestAvailable"));
        assert!(x.contains("<Hidden>true</Hidden>"));
        assert!(x.contains("<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"));
        assert!(x.contains("<RestartOnFailure>"));
        assert!(x.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        // The path is quoted and escaped.
        assert!(x.contains(
            r#"<Command>"C:\Users\Ann &amp; Bob\AppData\Local\Programs\Remora\remora-agent.exe"</Command>"#
        ));
        assert!(x.contains("<Arguments>run</Arguments>"));
        // Every opened element is closed (a cheap well-formedness check).
        for tag in [
            "Task",
            "Triggers",
            "Principals",
            "Settings",
            "Actions",
            "Exec",
            "LogonTrigger",
            "SessionStateChangeTrigger",
            "IdleSettings",
            "RestartOnFailure",
        ] {
            assert_eq!(
                x.matches(&format!("<{tag}>")).count() + x.matches(&format!("<{tag} ")).count(),
                x.matches(&format!("</{tag}>")).count(),
                "{tag}"
            );
        }
    }

    #[test]
    fn escaping() {
        assert_eq!(xml_escape(r#"a&b<c>"d'"#), "a&amp;b&lt;c&gt;&quot;d&apos;");
        assert_eq!(
            xml_unescape(&xml_escape(r#"a&b<c>"d'&amp;"#)),
            r#"a&b<c>"d'&amp;"#
        );
    }

    #[test]
    fn utf16_bom() {
        assert_eq!(utf16_with_bom("A<"), vec![0xFF, 0xFE, b'A', 0, b'<', 0]);
        assert_eq!(decode_output(&utf16_with_bom("Täsk")), "Täsk");
    }

    #[test]
    fn command_lines() {
        let n = task_name("S-1-5-21-9");
        assert_eq!(n, "Remora Agent S-1-5-21-9");
        assert_eq!(
            create_args(&n, r"C:\t\a.xml"),
            [
                "/Create",
                "/TN",
                "Remora Agent S-1-5-21-9",
                "/XML",
                r"C:\t\a.xml",
                "/F"
            ]
        );
        assert_eq!(delete_args(&n)[0], "/Delete");
        assert_eq!(query_args(&n)[3..], ["/XML", "ONE"]);
    }

    #[test]
    fn status_parsing() {
        let s = spec();
        let xml = task_xml(&s);
        let here = parse_query(Some(0), &utf16_with_bom(&xml), &s.exe);
        assert_eq!(
            here,
            TaskStatus::Installed {
                enabled: true,
                points_here: true,
                command: format!("\"{}\"", s.exe),
            }
        );
        // 8-bit output and a task pointing elsewhere, disabled.
        let other = xml.replace("Programs\\Remora", "Old").replace(
            "<Enabled>true</Enabled>\n    <Hidden>",
            "<Enabled>false</Enabled>\n    <Hidden>",
        );
        match parse_query(Some(0), other.as_bytes(), &s.exe) {
            TaskStatus::Installed {
                enabled,
                points_here,
                ..
            } => {
                assert!(!enabled);
                assert!(!points_here);
            }
            st => panic!("{st:?}"),
        }
        // Disabled triggers alone do not make the task disabled.
        let trig_off = xml.replacen("<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 2);
        assert!(matches!(
            parse_query(Some(0), trig_off.as_bytes(), &s.exe),
            TaskStatus::Installed { enabled: true, .. }
        ));
        assert_eq!(
            parse_query(Some(1), b"ERROR: ...", &s.exe),
            TaskStatus::NotInstalled
        );
        assert!(matches!(
            parse_query(None, b"", &s.exe),
            TaskStatus::Unknown(_)
        ));
        assert!(matches!(
            parse_query(Some(0), b"<Task></Task>", &s.exe),
            TaskStatus::Unknown(_)
        ));
    }
}
