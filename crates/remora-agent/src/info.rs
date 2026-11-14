//! Session information the agent reports to Remora (RDP-42): lock state,
//! idle time, CPU and memory load, OS build, session kind and the
//! redirection policies that switch file transfer off.
//!
//! This module holds the data and the decisions; `win::sys` reads the
//! values from Windows and calls into here.

/// One snapshot. Fields the agent could not read are `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    pub agent_version: &'static str,
    pub os: OsVersion,
    pub kind: SessionKind,
    pub policy: PolicyFlags,
    /// The session is locked (`WTSSessionInfoEx` → `SessionFlags`).
    pub locked: Option<bool>,
    /// Milliseconds since the session's last input (`GetLastInputInfo`).
    pub idle_ms: Option<u64>,
    /// Machine-wide CPU load since the previous snapshot, 0..=100.
    pub cpu_percent: Option<f32>,
    pub memory: Option<Memory>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    /// Update build revision (`UBR`), the number after the build.
    pub ubr: u32,
    /// "Windows 11 Pro", "Windows Server 2022 Datacenter", ...
    pub product_name: String,
    /// "24H2", ...
    pub display_version: String,
    /// "Client", "Server" or "Server Core".
    pub installation_type: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    pub total_bytes: u64,
    pub available_bytes: u64,
    /// `MEMORYSTATUSEX::dwMemoryLoad`, 0..=100.
    pub load_percent: u32,
}

/// What kind of session the agent runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// The physical console (no RDP client can attach a channel).
    Console,
    /// A full remote desktop.
    Desktop,
    /// A RemoteApp (RAIL) session: no desktop shell, only published apps.
    RemoteApp,
    /// The session could not be classified.
    Unknown,
}

/// The process images that mark a RemoteApp session. `rdpinit.exe` starts
/// RemoteApp sessions (it is the RAIL logon program) and `rdpshell.exe` is
/// the RemoteApp shell that replaces Explorer there. Neither runs in a full
/// desktop session. Confidence: medium; to be confirmed on a real RDS host
/// (Windows Server 2019+ and Windows 10/11 multi-session).
const REMOTEAPP_PROCESSES: [&str; 2] = ["rdpshell.exe", "rdpinit.exe"];

/// Classifies the session from `WTSIsRemoteSession` and the image names of
/// the processes running in it.
///
/// - Not remote → [`SessionKind::Console`].
/// - A RemoteApp process present → [`SessionKind::RemoteApp`]. This wins
///   over Explorer, which a RemoteApp session can run as a published app.
/// - Otherwise a remote session is a desktop, with or without Explorer
///   (Server Core has no Explorer).
pub fn classify_session<S: AsRef<str>>(remote: Option<bool>, processes: &[S]) -> SessionKind {
    if remote == Some(false) {
        return SessionKind::Console;
    }
    let remote_app = processes.iter().any(|p| {
        let name = p.as_ref();
        REMOTEAPP_PROCESSES
            .iter()
            .any(|r| name.eq_ignore_ascii_case(r))
    });
    match (remote_app, remote) {
        (true, _) => SessionKind::RemoteApp,
        (false, Some(true)) => SessionKind::Desktop,
        _ => SessionKind::Unknown,
    }
}

/// Redirection policies that also switch the agent's file transfer off
/// (RDP-41: "if clipboard or drive redirection is disabled, file transfer
/// is off too").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyFlags {
    /// `fDisableClip`: clipboard redirection is off.
    pub clipboard_disabled: bool,
    /// `fDisableCdm`: drive redirection is off.
    pub drives_disabled: bool,
}

impl PolicyFlags {
    pub fn file_transfer_disabled(self) -> bool {
        self.clipboard_disabled || self.drives_disabled
    }
}

/// Where a policy value can be set. Each is read as a DWORD.
pub const POLICY_SOURCES: [(PolicyRoot, &str); 3] = [
    (
        PolicyRoot::LocalMachine,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
    ),
    (
        PolicyRoot::CurrentUser,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
    ),
    // The listener's own setting (Remote Desktop Session Host
    // configuration), which applies without Group Policy.
    (
        PolicyRoot::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRoot {
    LocalMachine,
    CurrentUser,
}

/// The policy values found, in [`POLICY_SOURCES`] order (`None`: not set).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyValues {
    pub disable_clip: [Option<u32>; 3],
    pub disable_cdm: [Option<u32>; 3],
}

/// Fails closed: any source that sets a non-zero value disables the
/// feature. Group Policy would let a machine `0` override a user `1`, but
/// the agent never needs that precision; when in doubt, file transfer is
/// off.
pub fn decide_policy(v: &PolicyValues) -> PolicyFlags {
    let any = |vals: &[Option<u32>]| vals.iter().flatten().any(|&x| x != 0);
    PolicyFlags {
        clipboard_disabled: any(&v.disable_clip),
        drives_disabled: any(&v.disable_cdm),
    }
}

/// `SessionFlags` of `WTSINFOEX_LEVEL1_W`: `WTS_SESSIONSTATE_LOCK` (0) and
/// `WTS_SESSIONSTATE_UNLOCK` (1). Windows 7 / Server 2008 R2 report the two
/// swapped (documented); the agent targets Windows 10 and later, where they
/// are correct.
pub fn locked_from_session_flags(flags: i32) -> Option<bool> {
    match flags {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

/// Idle time from `GetTickCount` and `LASTINPUTINFO::dwTime`; both wrap
/// after 49.7 days.
pub fn idle_ms(now_tick: u32, last_input_tick: u32) -> u64 {
    u64::from(now_tick.wrapping_sub(last_input_tick))
}

/// Cumulative `GetSystemTimes` values in 100 ns units. Kernel time
/// includes idle time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub idle: u64,
    pub kernel: u64,
    pub user: u64,
}

/// CPU load between two samples, 0..=100; `None` if no time passed or the
/// counters went backwards.
pub fn cpu_percent(prev: CpuTimes, cur: CpuTimes) -> Option<f32> {
    let idle = cur.idle.checked_sub(prev.idle)?;
    let kernel = cur.kernel.checked_sub(prev.kernel)?;
    let user = cur.user.checked_sub(prev.user)?;
    let total = kernel.checked_add(user)?;
    if total == 0 || idle > total {
        return None;
    }
    Some(((total - idle) as f64 * 100.0 / total as f64) as f32)
}

/// `ProductName` still says "Windows 10" on Windows 11 (Microsoft kept the
/// registry value); build 22000 and later on a client is Windows 11.
pub fn fix_product_name(name: &str, build: u32, installation_type: &str) -> String {
    if build >= 22000
        && installation_type.eq_ignore_ascii_case("Client")
        && let Some(rest) = name.strip_prefix("Windows 10")
    {
        return format!("Windows 11{rest}");
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_kind() {
        let none: [&str; 0] = [];
        assert_eq!(
            classify_session(Some(false), &["rdpshell.exe"]),
            SessionKind::Console
        );
        assert_eq!(
            classify_session(Some(true), &["explorer.exe", "RDPShell.exe"]),
            SessionKind::RemoteApp
        );
        assert_eq!(
            classify_session(Some(true), &["rdpinit.exe"]),
            SessionKind::RemoteApp
        );
        assert_eq!(
            classify_session(Some(true), &["explorer.exe", "rdpclip.exe"]),
            SessionKind::Desktop
        );
        // Server Core: no Explorer, still a desktop.
        assert_eq!(
            classify_session(Some(true), &["cmd.exe", "sconfig.cmd"]),
            SessionKind::Desktop
        );
        assert_eq!(classify_session(None, &none), SessionKind::Unknown);
        assert_eq!(
            classify_session(None, &["rdpshell.exe"]),
            SessionKind::RemoteApp
        );
        // A look-alike name is not the shell.
        assert_eq!(
            classify_session(Some(true), &["rdpshell.exe.bak"]),
            SessionKind::Desktop
        );
    }

    #[test]
    fn policy_fails_closed() {
        let mut v = PolicyValues::default();
        assert_eq!(decide_policy(&v), PolicyFlags::default());
        assert!(!decide_policy(&v).file_transfer_disabled());
        // Explicit zeros everywhere: allowed.
        v.disable_clip = [Some(0); 3];
        v.disable_cdm = [Some(0); 3];
        assert!(!decide_policy(&v).file_transfer_disabled());
        // A user policy disables even with the machine set to allow.
        v.disable_clip[1] = Some(1);
        let f = decide_policy(&v);
        assert!(f.clipboard_disabled && !f.drives_disabled);
        assert!(f.file_transfer_disabled());
        // The listener setting alone disables drives.
        let mut v = PolicyValues::default();
        v.disable_cdm[2] = Some(1);
        let f = decide_policy(&v);
        assert!(f.drives_disabled && !f.clipboard_disabled);
        assert!(f.file_transfer_disabled());
        // Any non-zero counts.
        let mut v = PolicyValues::default();
        v.disable_clip[0] = Some(2);
        assert!(decide_policy(&v).clipboard_disabled);
    }

    #[test]
    fn lock_flags() {
        assert_eq!(locked_from_session_flags(0), Some(true));
        assert_eq!(locked_from_session_flags(1), Some(false));
        assert_eq!(locked_from_session_flags(-1), None);
    }

    #[test]
    fn idle_wraps() {
        assert_eq!(idle_ms(5000, 1000), 4000);
        assert_eq!(idle_ms(10, u32::MAX - 9), 20);
        assert_eq!(idle_ms(7, 7), 0);
    }

    #[test]
    fn cpu() {
        let a = CpuTimes {
            idle: 1000,
            kernel: 1500,
            user: 500,
        };
        // 1000 units passed (kernel 600 incl. idle 400, user 400): 60 % busy.
        let b = CpuTimes {
            idle: 1400,
            kernel: 2100,
            user: 900,
        };
        assert_eq!(cpu_percent(a, b), Some(60.0));
        assert_eq!(cpu_percent(a, a), None);
        assert_eq!(cpu_percent(b, a), None);
        let all_idle = CpuTimes {
            idle: 2000,
            kernel: 2500,
            user: 500,
        };
        assert_eq!(cpu_percent(a, all_idle), Some(0.0));
    }

    #[test]
    fn product_name() {
        assert_eq!(
            fix_product_name("Windows 10 Pro", 26100, "Client"),
            "Windows 11 Pro"
        );
        assert_eq!(
            fix_product_name("Windows 10 Pro", 19045, "Client"),
            "Windows 10 Pro"
        );
        assert_eq!(
            fix_product_name("Windows Server 2025 Datacenter", 26100, "Server"),
            "Windows Server 2025 Datacenter"
        );
    }
}
