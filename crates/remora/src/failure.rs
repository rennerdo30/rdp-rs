//! Why a session failed or ended, in plain language: the cause of an
//! [`rdp::Error`] (weighed with the connection step it happened in) or of
//! the server's Set Error Info code (MS-RDPBCGR 2.2.5.1.1), with an icon
//! and a suggested fix for the error and ended screens.

use rdp::ConnectStep;

use crate::icons::Icon;
use crate::theme::Tone;

/// What went wrong, as the user can act on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// DNS has no address for the name.
    HostNotFound,
    /// Nothing listens on the port (Remote Desktop off, wrong port).
    Refused,
    /// No answer in time (asleep, off, a firewall dropping packets).
    TimedOut,
    /// No route to the server (network, VPN).
    Unreachable,
    /// NLA rejected the user name or password.
    WrongPassword,
    AccountLocked,
    AccountDisabled,
    AccountExpired,
    PasswordExpired,
    /// The account may not sign in remotely (group, policy, logon hours).
    NotAllowed,
    /// The server wants the password typed again (no saved credentials).
    SignInAgain,
    /// The server's (or the gateway's) certificate was refused.
    CertificateRejected,
    /// The RD Gateway refused the sign-in or its policy refused the server.
    GatewayAuth,
    /// The RD Gateway itself could not be reached.
    GatewayUnreachable,
    /// The RD Gateway works but could not open the server.
    Gateway,
    /// No licence, or the licence server is unreachable.
    License,
    /// The server (or the connection broker) turned the connection down.
    ServerDenied,
    /// The TLS handshake failed.
    SecureChannel,
    /// The server needs a feature Remora does not have.
    Unsupported,
    /// Malformed or unexpected data: a bug on one side.
    Protocol,
    /// The network dropped the running session and reconnecting failed.
    ConnectionLost,
    Unknown,
}

/// How a session ended without an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// Disconnect in Remora.
    ByYou,
    /// Signed out inside the session (ERRINFO_LOGOFF_BY_USER).
    SignedOut,
    /// Disconnected from inside the session (Start > Disconnect).
    DisconnectedOnServer,
    DisconnectedByAdmin,
    LoggedOffByAdmin,
    /// Someone else connected to this session.
    OtherConnection,
    Idle,
    LogonTimeout,
    /// The user cancelled an automatic reconnect.
    ReconnectCancelled,
    /// The server ended the connection and gave no reason.
    ServerEnded,
}

/// A failure: its cause and the connection step it happened in (None
/// once the session was running).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub cause: Cause,
    pub step: Option<ConnectStep>,
}

/// Either kind of end, from a Set Error Info code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ended(EndReason),
    Failed(Cause),
}

/// The NTSTATUS or SSPI code an authentication error names, if any
/// ("server error 0xc000006d STATUS_LOGON_FAILURE").
fn status_code(msg: &str) -> Option<u32> {
    let at = msg.find("0x")?;
    let hex: String = msg[at + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    u32::from_str_radix(&hex, 16).ok()
}

/// The cause of a failed connection or session. `step` is the last
/// connection step reached (None after the session was up).
pub fn classify(e: &rdp::Error, step: Option<&ConnectStep>) -> Cause {
    use rdp::Error as E;
    use std::io::ErrorKind as K;
    let msg = e.to_string();
    if msg.contains("certificate was not trusted") || msg.contains("certificate differs") {
        return Cause::CertificateRejected;
    }
    let io_kind = match e {
        E::Io(io) => Some(io.kind()),
        _ => None,
    };
    let unreachable = |k: K| {
        matches!(
            k,
            K::HostUnreachable | K::NetworkUnreachable | K::NetworkDown | K::AddrNotAvailable
        )
    };
    match step {
        Some(ConnectStep::Resolving) => return Cause::HostNotFound,
        Some(ConnectStep::Tcp) => {
            return match (e, io_kind) {
                (_, Some(K::ConnectionRefused)) => Cause::Refused,
                (E::Timeout, _) | (_, Some(K::TimedOut)) => Cause::TimedOut,
                _ => Cause::Unreachable,
            };
        }
        Some(ConnectStep::Gateway) => {
            return match (e, io_kind) {
                (E::Auth(_), _) => Cause::GatewayAuth,
                (E::Tls(_), _) => Cause::SecureChannel,
                (E::Timeout, _) => Cause::GatewayUnreachable,
                (_, Some(K::ConnectionRefused | K::TimedOut)) => Cause::GatewayUnreachable,
                (_, Some(k)) if unreachable(k) => Cause::GatewayUnreachable,
                (E::Protocol(m), _) if m.starts_with("cannot resolve") => Cause::GatewayUnreachable,
                _ => Cause::Gateway,
            };
        }
        _ => {}
    }
    match e {
        E::Protocol(m) if m.starts_with("cannot resolve") => Cause::HostNotFound,
        E::Auth(m) => match status_code(m) {
            Some(0xC000_006D | 0x8009_030C) => Cause::WrongPassword,
            Some(0xC000_0234) => Cause::AccountLocked,
            Some(0xC000_0072) => Cause::AccountDisabled,
            Some(0xC000_0193) => Cause::AccountExpired,
            Some(0xC000_0071 | 0xC000_0224) => Cause::PasswordExpired,
            Some(0xC000_006E | 0xC000_0070 | 0xC000_015B | 0xC000_0413) => Cause::NotAllowed,
            _ if m.contains("early user authorization denied") => Cause::NotAllowed,
            _ => Cause::WrongPassword,
        },
        E::Tls(_) => Cause::SecureChannel,
        E::Unsupported(_) => Cause::Unsupported,
        E::Protocol(m) if m.contains("licens") => Cause::License,
        E::Protocol(_) => Cause::Protocol,
        E::Disconnected(_) if step == Some(&ConnectStep::Licensing) => Cause::License,
        E::Disconnected(_) => Cause::ServerDenied,
        E::Timeout => Cause::TimedOut,
        _ if e.is_network_drop() => Cause::ConnectionLost,
        E::Io(_) => Cause::ConnectionLost,
        E::ConnectionLost(_) => Cause::ConnectionLost,
    }
}

/// A session the server closed: an ordinary end, or a failure, from its
/// Set Error Info code (MS-RDPBCGR 2.2.5.1.1; 0 = none sent).
pub fn closed(error_info: u32) -> Outcome {
    use Outcome::{Ended, Failed};
    match error_info {
        0x0000_0001 => Ended(EndReason::DisconnectedByAdmin),
        0x0000_0002 => Ended(EndReason::LoggedOffByAdmin),
        0x0000_0003 => Ended(EndReason::Idle),
        0x0000_0004 => Ended(EndReason::LogonTimeout),
        0x0000_0005 => Ended(EndReason::OtherConnection),
        0x0000_0006 | 0x0000_0007 => Failed(Cause::ServerDenied),
        0x0000_0009 => Failed(Cause::NotAllowed),
        0x0000_000A => Failed(Cause::SignInAgain),
        0x0000_000B => Ended(EndReason::DisconnectedOnServer),
        0x0000_000C => Ended(EndReason::SignedOut),
        // Licensing (ERRINFO_LICENSE_*), including NO_REMOTE_CONNECTIONS.
        0x0000_0100..=0x0000_010A => Failed(Cause::License),
        // Connection broker (ERRINFO_CB_*).
        0x0000_0400..=0x0000_040D => Failed(Cause::ServerDenied),
        // The server rejected a PDU of ours.
        0x0000_10C9..=0x0000_1195 => Failed(Cause::Protocol),
        _ => Ended(EndReason::ServerEnded),
    }
}

/// Where to look for the cause: what a fix names.
pub struct Context<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub gateway: Option<&'a str>,
}

impl Cause {
    /// True for causes a later attempt may cure on its own (an automatic
    /// reconnect keeps trying after these).
    pub fn is_network(self) -> bool {
        matches!(
            self,
            Cause::Refused
                | Cause::TimedOut
                | Cause::Unreachable
                | Cause::HostNotFound
                | Cause::ConnectionLost
                | Cause::GatewayUnreachable
        )
    }

    pub fn icon(self) -> Icon {
        match self {
            Cause::HostNotFound => Icon::Globe,
            Cause::Refused | Cause::Unreachable | Cause::ConnectionLost => Icon::Unplug,
            Cause::TimedOut | Cause::PasswordExpired | Cause::AccountExpired => Icon::Clock,
            Cause::WrongPassword | Cause::SignInAgain => Icon::Key,
            Cause::AccountLocked | Cause::AccountDisabled => Icon::Lock,
            Cause::NotAllowed | Cause::CertificateRejected | Cause::GatewayAuth => {
                Icon::ShieldAlert
            }
            Cause::SecureChannel => Icon::Lock,
            Cause::GatewayUnreachable | Cause::Gateway => Icon::Globe,
            Cause::License => Icon::FileText,
            Cause::ServerDenied => Icon::Power,
            Cause::Unsupported | Cause::Protocol | Cause::Unknown => Icon::Warning,
        }
    }

    /// Credential problems the user fixes here are a warning; the rest
    /// are errors.
    pub fn tone(self) -> Tone {
        match self {
            Cause::WrongPassword | Cause::SignInAgain | Cause::CertificateRejected => Tone::Warning,
            _ => Tone::Danger,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Cause::HostNotFound => "Server name not found",
            Cause::Refused => "The server refused the connection",
            Cause::TimedOut => "The server did not answer",
            Cause::Unreachable => "The server cannot be reached",
            Cause::WrongPassword => "Wrong user name or password",
            Cause::AccountLocked => "This account is locked",
            Cause::AccountDisabled => "This account is disabled",
            Cause::AccountExpired => "This account has expired",
            Cause::PasswordExpired => "The password has expired",
            Cause::NotAllowed => "Not allowed to sign in remotely",
            Cause::SignInAgain => "The server asks for the password again",
            Cause::CertificateRejected => "The server's certificate was not trusted",
            Cause::GatewayAuth => "The RD Gateway refused the sign-in",
            Cause::GatewayUnreachable => "The RD Gateway cannot be reached",
            Cause::Gateway => "The RD Gateway could not reach the server",
            Cause::License => "A licensing problem on the server",
            Cause::ServerDenied => "The server turned the connection down",
            Cause::SecureChannel => "The secure connection failed",
            Cause::Unsupported => "This server needs a feature Remora lacks",
            Cause::Protocol => "Unexpected answer from the server",
            Cause::ConnectionLost => "The connection was lost",
            Cause::Unknown => "Could not connect",
        }
    }

    /// What to try, naming the connection's own host, port and user.
    pub fn fix(self, c: &Context) -> String {
        let (host, port, user) = (c.host, c.port, c.user);
        let gw = c.gateway.unwrap_or("the gateway");
        match self {
            Cause::HostNotFound => format!(
                "Check the spelling of {host}. A name on a work network may need the VPN first."
            ),
            Cause::Refused => format!(
                "Remote Desktop may be off on that PC, or port {port} is wrong or blocked by a firewall."
            ),
            Cause::TimedOut => format!(
                "The PC may be asleep or off, or a firewall drops port {port}. Wake it and try again."
            ),
            Cause::Unreachable => {
                format!("Check this PC's network or VPN: no route to {host} from here.")
            }
            Cause::WrongPassword => {
                let who = if user.is_empty() { "the user name" } else { user };
                format!(
                    "Check {who} and the password. Domain accounts look like DOMAIN\\name or name@domain."
                )
            }
            Cause::AccountLocked => {
                "Too many failed sign-ins locked it. Wait a while, or ask an administrator to unlock it."
                    .into()
            }
            Cause::AccountDisabled | Cause::AccountExpired => {
                "Ask an administrator of the domain to enable the account again.".into()
            }
            Cause::PasswordExpired => {
                "Change the password on a PC in that domain, then sign in here with the new one."
                    .into()
            }
            Cause::NotAllowed => format!(
                "Add the account to Remote Desktop Users on {host}, or ask its administrator about the sign-in policy."
            ),
            Cause::SignInAgain => "Type the password again; this server does not take saved ones.".into(),
            Cause::CertificateRejected => {
                "Retry and choose Trust if you know this server, or check that the address is right."
                    .into()
            }
            Cause::GatewayAuth => format!(
                "Check the credentials for {gw}, and that its policy lets you reach {host}."
            ),
            Cause::GatewayUnreachable => {
                format!("Check the gateway address ({gw}) and this PC's network.")
            }
            Cause::Gateway => format!(
                "The gateway answered but could not open {host}: it may be off, or the gateway's policy blocks it."
            ),
            Cause::License => {
                "The server has no free Remote Desktop licence, or cannot reach its licence server. Ask its administrator."
                    .into()
            }
            Cause::ServerDenied => {
                "It is not taking connections right now. Try again later, or ask its administrator."
                    .into()
            }
            Cause::SecureChannel => {
                "The TLS handshake did not finish. The server may need other security settings, or the network interferes."
                    .into()
            }
            Cause::Unsupported => "Copy the details to see which feature is missing.".into(),
            Cause::Protocol => {
                "This looks like a bug in Remora or the server. Copy the details and report it."
                    .into()
            }
            Cause::ConnectionLost => {
                "The network dropped and reconnecting did not work. Check the network, then retry."
                    .into()
            }
            Cause::Unknown => "Copy the details for the technical cause.".into(),
        }
    }
}

impl EndReason {
    /// The line under "Session ended".
    pub fn text(self) -> &'static str {
        match self {
            EndReason::ByYou => "You disconnected.",
            EndReason::SignedOut => "You signed out of the remote PC.",
            EndReason::DisconnectedOnServer => {
                "You disconnected from inside the session; it keeps running there."
            }
            EndReason::DisconnectedByAdmin => "An administrator disconnected the session.",
            EndReason::LoggedOffByAdmin => "An administrator signed you out.",
            EndReason::OtherConnection => "Someone connected to this session from another PC.",
            EndReason::Idle => "The server disconnected the idle session.",
            EndReason::LogonTimeout => "The sign-in took too long, so the server ended it.",
            EndReason::ReconnectCancelled => "You cancelled reconnecting.",
            EndReason::ServerEnded => "The server ended the session.",
        }
    }

    pub fn icon(self) -> Icon {
        match self {
            EndReason::ByYou | EndReason::SignedOut | EndReason::ReconnectCancelled => Icon::Power,
            EndReason::DisconnectedByAdmin | EndReason::LoggedOffByAdmin => Icon::ShieldAlert,
            EndReason::OtherConnection => Icon::User,
            EndReason::Idle | EndReason::LogonTimeout => Icon::Clock,
            EndReason::DisconnectedOnServer | EndReason::ServerEnded => Icon::Unplug,
        }
    }
}

/// A short duration: "45 s", "12 min", "1 h 05 min".
pub fn duration_text(d: std::time::Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", s / 60),
        _ => format!("{} h {:02} min", s / 3600, s % 3600 / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::Error as E;
    use std::io::{Error as Io, ErrorKind as K};

    fn io(k: K) -> E {
        E::Io(Io::from(k))
    }

    #[test]
    fn network_failures_by_step() {
        let s = ConnectStep::Resolving;
        // Any error while resolving is a name that does not resolve
        // (Windows reports WSAHOST_NOT_FOUND as an uncategorised error).
        assert_eq!(
            classify(&E::Io(Io::from_raw_os_error(11001)), Some(&s)),
            Cause::HostNotFound
        );
        assert_eq!(
            classify(&E::Protocol("cannot resolve x".into()), None),
            Cause::HostNotFound
        );
        let s = ConnectStep::Tcp;
        assert_eq!(
            classify(&io(K::ConnectionRefused), Some(&s)),
            Cause::Refused
        );
        assert_eq!(classify(&io(K::TimedOut), Some(&s)), Cause::TimedOut);
        assert_eq!(classify(&E::Timeout, Some(&s)), Cause::TimedOut);
        assert_eq!(
            classify(&io(K::HostUnreachable), Some(&s)),
            Cause::Unreachable
        );
        // Later, a timeout is the server going quiet, a reset a lost link.
        let s = ConnectStep::Capabilities;
        assert_eq!(classify(&E::Timeout, Some(&s)), Cause::TimedOut);
        assert_eq!(
            classify(&io(K::ConnectionReset), Some(&s)),
            Cause::ConnectionLost
        );
    }

    #[test]
    fn sign_in_failures_by_status() {
        let s = Some(ConnectStep::SignIn);
        let auth = |code: &str| {
            classify(
                &E::Auth(format!("server error {code} STATUS_SOMETHING")),
                s.as_ref(),
            )
        };
        assert_eq!(auth("0xc000006d"), Cause::WrongPassword);
        assert_eq!(auth("0xc0000234"), Cause::AccountLocked);
        assert_eq!(auth("0xc0000072"), Cause::AccountDisabled);
        assert_eq!(auth("0xc0000193"), Cause::AccountExpired);
        assert_eq!(auth("0xc0000071"), Cause::PasswordExpired);
        assert_eq!(auth("0xc0000224"), Cause::PasswordExpired);
        assert_eq!(auth("0xc000015b"), Cause::NotAllowed);
        assert_eq!(
            classify(
                &E::Auth("early user authorization denied (0x5)".into()),
                s.as_ref()
            ),
            Cause::NotAllowed
        );
        // The server hanging up during NLA is the usual wrong password.
        assert_eq!(
            classify(
                &E::Auth("server closed the connection during NLA (wrong credentials?)".into()),
                s.as_ref()
            ),
            Cause::WrongPassword
        );
    }

    #[test]
    fn certificates_gateway_licensing_and_protocol() {
        let refused = E::Auth("the server certificate was not trusted".into());
        assert_eq!(
            classify(&refused, Some(&ConnectStep::Tls)),
            Cause::CertificateRejected
        );
        let gw = Some(ConnectStep::Gateway);
        let gw_cert = E::Auth("the gateway certificate was not trusted".into());
        assert_eq!(classify(&gw_cert, gw.as_ref()), Cause::CertificateRejected);
        assert_eq!(
            classify(
                &E::Auth("RD Gateway rejected the credentials".into()),
                gw.as_ref()
            ),
            Cause::GatewayAuth
        );
        assert_eq!(
            classify(&io(K::ConnectionRefused), gw.as_ref()),
            Cause::GatewayUnreachable
        );
        assert_eq!(
            classify(
                &E::Protocol("RD Gateway closed the tunnel: E_PROXY_x".into()),
                gw.as_ref()
            ),
            Cause::Gateway
        );
        assert_eq!(
            classify(
                &E::Protocol("licensing error 0x3 (x)".into()),
                Some(&ConnectStep::Licensing)
            ),
            Cause::License
        );
        assert_eq!(
            classify(
                &E::Disconnected("MCS disconnect, reason 3".into()),
                Some(&ConnectStep::Licensing)
            ),
            Cause::License
        );
        assert_eq!(
            classify(
                &E::Disconnected("MCS disconnect".into()),
                Some(&ConnectStep::Capabilities)
            ),
            Cause::ServerDenied
        );
        assert_eq!(
            classify(&E::Protocol("bad PDU".into()), None),
            Cause::Protocol
        );
        assert_eq!(
            classify(&E::Unsupported("no RemoteApp".into()), None),
            Cause::Unsupported
        );
    }

    #[test]
    fn error_info_codes() {
        use Outcome::{Ended, Failed};
        assert_eq!(closed(0), Ended(EndReason::ServerEnded));
        assert_eq!(closed(0xC), Ended(EndReason::SignedOut));
        assert_eq!(closed(0xB), Ended(EndReason::DisconnectedOnServer));
        assert_eq!(closed(0x1), Ended(EndReason::DisconnectedByAdmin));
        assert_eq!(closed(0x2), Ended(EndReason::LoggedOffByAdmin));
        assert_eq!(closed(0x5), Ended(EndReason::OtherConnection));
        assert_eq!(closed(0x3), Ended(EndReason::Idle));
        assert_eq!(closed(0x9), Failed(Cause::NotAllowed));
        assert_eq!(closed(0x7), Failed(Cause::ServerDenied));
        assert_eq!(closed(0x102), Failed(Cause::License));
        assert_eq!(closed(0x10A), Failed(Cause::License));
        assert_eq!(closed(0x10C9), Failed(Cause::Protocol));
    }

    #[test]
    fn fixes_name_the_connection() {
        let c = Context {
            host: "build-01.lab.local",
            port: 3390,
            user: r"LAB\builder",
            gateway: Some("rdg.corp.example"),
        };
        assert!(Cause::HostNotFound.fix(&c).contains("build-01.lab.local"));
        assert!(Cause::Refused.fix(&c).contains("3390"));
        assert!(Cause::WrongPassword.fix(&c).contains(r"LAB\builder"));
        assert!(Cause::GatewayAuth.fix(&c).contains("rdg.corp.example"));
        assert!(Cause::ConnectionLost.is_network() && !Cause::WrongPassword.is_network());
    }

    #[test]
    fn durations_read_short() {
        use std::time::Duration as D;
        assert_eq!(duration_text(D::from_secs(42)), "42 s");
        assert_eq!(duration_text(D::from_secs(12 * 60 + 5)), "12 min");
        assert_eq!(duration_text(D::from_secs(3600 + 5 * 60)), "1 h 05 min");
    }
}
