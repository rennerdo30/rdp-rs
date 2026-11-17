//! Command line.

pub const USAGE: &str = "\
remora-agent: Remora's helper inside a Windows remote desktop session.

Usage:
  remora-agent [run]                 Run in this session (the default).
  remora-agent install [--dry-run]   Start automatically: a per-user scheduled task
                                     (at logon and on remote connect). No admin.
  remora-agent uninstall [--dry-run] Remove the task and the link registration.
  remora-agent status                Show whether the task is installed.
  remora-agent print-task-xml        Print the scheduled task definition.
  remora-agent register-links [--dry-run]
                                     Offer the agent as the app for http/https links
                                     (pick it once in Settings > Default apps).
  remora-agent unregister-links [--dry-run]
  remora-agent open-url <url>        Open a link on the local PC via Remora
                                     (what Windows runs for a link).
  remora-agent send <file>...        Send files to the PC Remora connects from
                                     (what \"Send to my PC (Remora)\" runs).
  remora-agent session-info          Print the session information the agent reports.
  remora-agent capture-probe [secs]  Measure whether and how fast this session's picture
                                     can be captured, and list video encoders (shows a
                                     small blinking square while it runs; default 10 s).
  remora-agent tune apply|restore    Set this server's remote graphics for Remora
                                     (60 fps, H.264/AVC 444, hardware encoding), or
                                     back to Windows' defaults. Needs administrator
                                     rights; Remora's Improve button runs it.
  remora-agent fingerprint           Print this helper's key fingerprint, to compare
                                     with Remora's helper card or to set it as the
                                     connection's expected helper in Remora.
  remora-agent clients               List the Remora clients paired with this helper.
  remora-agent forget-client <fingerprint>
                                     Unpair a client: it must confirm the code again.
  remora-agent trust-client <fingerprint>
                                     Pair a client by the fingerprint Remora shows in
                                     Settings > Security (no code to compare here).
                                     Turns on pinned clients only.
  remora-agent strict [on|off]       Pinned clients only: refuse unknown Remora clients
                                     without showing a code (also on after trust-client,
                                     or by the PinnedClientsOnly policy).
  remora-agent --version | --help

The agent never needs administrator rights (only `tune` does) and opens no
network ports.
Log: %LOCALAPPDATA%\\rdp-rs\\logs\\remora-agent.log
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run,
    /// `run --replace <pid>`: started by an update (RDP-61); waits for the
    /// helper it replaces to exit first.
    RunReplacing(u32),
    Install {
        dry_run: bool,
    },
    Uninstall {
        dry_run: bool,
    },
    Status,
    PrintTaskXml,
    RegisterLinks {
        dry_run: bool,
    },
    UnregisterLinks {
        dry_run: bool,
    },
    OpenUrl(String),
    Send(Vec<String>),
    SessionInfo,
    /// `capture-probe [seconds]` (RDP-67): can this session be captured.
    CaptureProbe(u64),
    Fingerprint,
    Clients,
    ForgetClient(String),
    TrustClient(String),
    /// `strict`: None shows the state.
    Strict(Option<bool>),
    /// `tune apply|restore` (RDP-59), run elevated.
    Tune(remora_link::msg::TuneAction),
    Version,
    Help,
}

/// Parses the arguments after the program name.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Command, String> {
    let args: Vec<&str> = args.iter().map(|a| a.as_ref()).collect();
    let flag_only = |rest: &[&str]| -> Result<bool, String> {
        match rest {
            [] => Ok(false),
            ["--dry-run"] => Ok(true),
            other => Err(format!("unexpected arguments: {}", other.join(" "))),
        }
    };
    let none = |rest: &[&str], c: Command| -> Result<Command, String> {
        if rest.is_empty() {
            Ok(c)
        } else {
            Err(format!("unexpected arguments: {}", rest.join(" ")))
        }
    };
    let Some((&first, rest)) = args.split_first() else {
        return Ok(Command::Run);
    };
    match first {
        "run" => match rest {
            [] => Ok(Command::Run),
            ["--replace", pid] => pid
                .parse()
                .map(Command::RunReplacing)
                .map_err(|_| "run --replace takes a process id".to_string()),
            other => Err(format!("unexpected arguments: {}", other.join(" "))),
        },
        "install" => Ok(Command::Install {
            dry_run: flag_only(rest)?,
        }),
        "uninstall" => Ok(Command::Uninstall {
            dry_run: flag_only(rest)?,
        }),
        "status" => none(rest, Command::Status),
        "print-task-xml" | "--print-task-xml" => none(rest, Command::PrintTaskXml),
        "register-links" => Ok(Command::RegisterLinks {
            dry_run: flag_only(rest)?,
        }),
        "unregister-links" => Ok(Command::UnregisterLinks {
            dry_run: flag_only(rest)?,
        }),
        // Exactly one argument: Windows passes the quoted "%1".
        "open-url" => match rest {
            [url] => Ok(Command::OpenUrl((*url).to_string())),
            _ => Err("open-url takes exactly one URL".into()),
        },
        // Explorer's Send To passes each selected item as one argument.
        "send" => match rest {
            [] => Err("send takes one or more files".into()),
            files => Ok(Command::Send(files.iter().map(|f| f.to_string()).collect())),
        },
        "session-info" => none(rest, Command::SessionInfo),
        "fingerprint" => none(rest, Command::Fingerprint),
        "capture-probe" => match rest {
            [] => Ok(Command::CaptureProbe(10)),
            [s] => s
                .parse()
                .ok()
                .filter(|s| (1..=120).contains(s))
                .map(Command::CaptureProbe)
                .ok_or_else(|| "capture-probe takes 1 to 120 seconds".to_string()),
            _ => Err("capture-probe takes at most one number".into()),
        },
        "clients" => none(rest, Command::Clients),
        // A fingerprint is pasted as one argument or as its ten groups.
        "forget-client" if !rest.is_empty() => Ok(Command::ForgetClient(rest.join(" "))),
        "trust-client" if !rest.is_empty() => Ok(Command::TrustClient(rest.join(" "))),
        "forget-client" | "trust-client" => Err(format!("{first} takes a fingerprint")),
        "strict" => match rest {
            [] => Ok(Command::Strict(None)),
            ["on"] => Ok(Command::Strict(Some(true))),
            ["off"] => Ok(Command::Strict(Some(false))),
            _ => Err("strict takes on or off".into()),
        },
        "tune" => match rest {
            ["apply"] => Ok(Command::Tune(remora_link::msg::TuneAction::Apply)),
            ["restore"] => Ok(Command::Tune(remora_link::msg::TuneAction::Restore)),
            _ => Err("tune takes apply or restore".into()),
        },
        "--version" | "-V" | "version" => none(rest, Command::Version),
        "--help" | "-h" | "/?" | "help" => Ok(Command::Help),
        other => Err(format!("unknown command: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let none: [&str; 0] = [];
        assert_eq!(parse(&none), Ok(Command::Run));
        assert_eq!(parse(&["run"]), Ok(Command::Run));
        assert_eq!(
            parse(&["install", "--dry-run"]),
            Ok(Command::Install { dry_run: true })
        );
        assert_eq!(
            parse(&["uninstall"]),
            Ok(Command::Uninstall { dry_run: false })
        );
        assert_eq!(parse(&["--print-task-xml"]), Ok(Command::PrintTaskXml));
        assert_eq!(
            parse(&["open-url", "https://e.example/"]),
            Ok(Command::OpenUrl("https://e.example/".into()))
        );
        assert!(parse(&["open-url"]).is_err());
        assert_eq!(
            parse(&["tune", "apply"]),
            Ok(Command::Tune(remora_link::msg::TuneAction::Apply))
        );
        assert_eq!(
            parse(&["tune", "restore"]),
            Ok(Command::Tune(remora_link::msg::TuneAction::Restore))
        );
        assert!(parse(&["tune"]).is_err());
        assert_eq!(
            parse(&["run", "--replace", "1234"]),
            Ok(Command::RunReplacing(1234))
        );
        assert!(parse(&["run", "--replace", "x"]).is_err());
        assert!(parse(&["run", "x"]).is_err());
        assert!(parse(&["tune", "apply", "x"]).is_err());
        assert!(parse(&["open-url", "a", "b"]).is_err());
        assert_eq!(
            parse(&["send", r"C:\a b.txt", "--dry-run"]),
            Ok(Command::Send(vec![
                r"C:\a b.txt".into(),
                "--dry-run".into()
            ]))
        );
        assert!(parse(&["send"]).is_err());
        assert!(parse(&["install", "--force"]).is_err());
        assert!(parse(&["run", "x"]).is_err());
        assert!(parse(&["bogus"]).is_err());
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
        assert_eq!(parse(&["fingerprint"]), Ok(Command::Fingerprint));
        assert_eq!(parse(&["clients"]), Ok(Command::Clients));
        assert_eq!(
            parse(&["forget-client", "ab12", "cd34"]),
            Ok(Command::ForgetClient("ab12 cd34".into()))
        );
        assert_eq!(
            parse(&["trust-client", "ab12cd34"]),
            Ok(Command::TrustClient("ab12cd34".into()))
        );
        assert!(parse(&["trust-client"]).is_err());
        assert_eq!(parse(&["strict"]), Ok(Command::Strict(None)));
        assert_eq!(parse(&["strict", "on"]), Ok(Command::Strict(Some(true))));
        assert_eq!(parse(&["strict", "off"]), Ok(Command::Strict(Some(false))));
        assert!(parse(&["strict", "maybe"]).is_err());
        assert!(parse(&["clients", "x"]).is_err());
    }
}
