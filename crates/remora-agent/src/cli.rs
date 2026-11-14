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
  remora-agent fingerprint           Print this helper's key fingerprint, to compare
                                     with Remora's helper card or to set it as the
                                     connection's expected helper in Remora.
  remora-agent clients               List the Remora clients paired with this helper.
  remora-agent forget-client <fingerprint>
                                     Unpair a client: it must confirm the code again.
  remora-agent trust-client <fingerprint>
                                     Pair a client by the fingerprint Remora shows in
                                     Settings > Security (no code to compare here).
  remora-agent --version | --help

The agent never needs administrator rights and opens no network ports.
Log: %LOCALAPPDATA%\\rdp-rs\\logs\\remora-agent.log
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run,
    Install { dry_run: bool },
    Uninstall { dry_run: bool },
    Status,
    PrintTaskXml,
    RegisterLinks { dry_run: bool },
    UnregisterLinks { dry_run: bool },
    OpenUrl(String),
    Send(Vec<String>),
    SessionInfo,
    Fingerprint,
    Clients,
    ForgetClient(String),
    TrustClient(String),
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
        "run" => none(rest, Command::Run),
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
        "clients" => none(rest, Command::Clients),
        // A fingerprint is pasted as one argument or as its ten groups.
        "forget-client" if !rest.is_empty() => Ok(Command::ForgetClient(rest.join(" "))),
        "trust-client" if !rest.is_empty() => Ok(Command::TrustClient(rest.join(" "))),
        "forget-client" | "trust-client" => Err(format!("{first} takes a fingerprint")),
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
        assert!(parse(&["clients", "x"]).is_err());
    }
}
