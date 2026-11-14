//! `remora-agent clients`, `forget-client`, `trust-client` and `strict`:
//! the Remora clients this user confirmed on the server
//! (`agent-clients.json`, HELPER-PROTOCOL.md 4) and the pinned-clients-only
//! switch. Only a pinned client receives files or links from the server.
//! Platform independent; `win` prints the results.

use std::path::Path;

use remora_link::pins::{ClientOrigin, clean_label};
use remora_link::{ClientStore, format_fingerprint, parse_fingerprint};

/// The policy key (under `HKEY_LOCAL_MACHINE`) and its DWORD value: 1
/// turns pinned clients only on for every user of the server.
pub const POLICY_KEY: &str = r"SOFTWARE\Policies\Remora\Agent";
pub const POLICY_VALUE: &str = "PinnedClientsOnly";

/// The per-user setting file's content when pinned clients only is on.
const SETTING_ON: &str = "pinned-clients-only\n";

/// Whether the per-user setting turns pinned clients only on. Missing is
/// off; anything else that is not the "on" content (unreadable, changed)
/// counts as on (fail closed).
fn setting_on(path: &Path) -> bool {
    match std::fs::read(path) {
        Ok(b) => b != b"off\n",
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Pinned clients only: an unknown client key is refused without the
/// pairing dialog. On when the `PinnedClientsOnly` policy is 1, when the
/// user switched it on (`remora-agent strict on`), or once an admin
/// trusted a client by fingerprint (`trust-client`; out-of-band trust is
/// only worth something when the dialog cannot be clicked through). A
/// client list that cannot be read counts as such trust (fail closed).
/// Returns why, or None when off.
pub fn strict_mode(
    policy: Option<u32>,
    setting: Option<&Path>,
    clients: Option<&Path>,
) -> Option<&'static str> {
    if policy.is_some_and(|v| v != 0) {
        return Some("the PinnedClientsOnly policy is set");
    }
    if setting.is_some_and(setting_on) {
        return Some("pinned clients only is switched on (remora-agent strict)");
    }
    let admin = clients.is_some_and(|p| !ClientStore::load(p).is_ok_and(|s| !s.has_admin_trust()));
    admin.then_some("a client was trusted by fingerprint (trust-client)")
}

/// `strict on|off`: the per-user switch. Turning it off leaves the other
/// reasons in force, and says so.
pub fn set_strict(
    on: bool,
    setting: &Path,
    policy: Option<u32>,
    clients: Option<&Path>,
) -> Result<String, String> {
    if on {
        if let Some(dir) = setting.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        remora_link::store::write_atomic(setting, SETTING_ON.as_bytes())
            .map_err(|e| e.to_string())?;
    } else {
        match std::fs::remove_file(setting) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(strict_status(setting, policy, clients))
}

/// `strict`: whether unknown clients can still pair through the dialog.
pub fn strict_status(setting: &Path, policy: Option<u32>, clients: Option<&Path>) -> String {
    match strict_mode(policy, Some(setting), clients) {
        Some(why) => format!(
            "Pinned clients only: on ({why}). Unknown Remora clients are refused without asking.\n"
        ),
        None => "Pinned clients only: off. An unknown Remora client shows the pairing \
                 code here to confirm.\n"
            .to_string(),
    }
}

/// The user's own "pinned clients only" switch (the tray's check mark).
pub fn user_strict(setting: &Path) -> bool {
    setting_on(setting)
}

/// Pinned clients only for a reason the user cannot switch off (policy,
/// or a client trusted by fingerprint): that reason.
pub fn forced_strict(policy: Option<u32>, clients: Option<&Path>) -> Option<&'static str> {
    strict_mode(policy, None, clients)
}

/// The paired Remora PCs for the tray menu, labels cleaned. Empty when the
/// list cannot be read (the menu then offers nothing to forget).
pub fn paired(path: &Path) -> Vec<crate::tray::PairedPc> {
    let Ok(store) = ClientStore::load(path) else {
        return Vec::new();
    };
    store
        .iter()
        .map(|(fp, c)| crate::tray::PairedPc {
            label: clean_label(&c.label),
            fingerprint: format_fingerprint(&fp),
        })
        .collect()
}

/// The list as printed by `remora-agent clients`.
pub fn list(path: &Path) -> Result<String, String> {
    let store = ClientStore::load(path).map_err(|e| format!("cannot read the client list: {e}"))?;
    let mut out = String::new();
    for (fp, c) in store.iter() {
        // The label is the client's own word: printed cleaned.
        let label = clean_label(&c.label);
        let label = if label.is_empty() {
            "(no name)".to_string()
        } else {
            label
        };
        let how = if c.origin() == ClientOrigin::Admin {
            ", trusted by fingerprint"
        } else {
            ""
        };
        out.push_str(&format!(
            "{}  {label}  (since {}{how})\n",
            format_fingerprint(&fp),
            date(c.first_seen)
        ));
    }
    if out.is_empty() {
        out.push_str("No Remora client is paired with this helper yet.\n");
    }
    Ok(out)
}

/// `forget-client <fingerprint>`: that client must pair again (the user
/// confirms the code on the server) before it gets files or links.
pub fn forget(path: &Path, fingerprint: &str) -> Result<String, String> {
    let fp = parse_fingerprint(fingerprint)
        .ok_or("not a fingerprint (40 hex digits, as `remora-agent clients` shows)")?;
    let removed = ClientStore::update(path, |s| s.forget(&fp)).map_err(|e| e.to_string())?;
    Ok(if removed {
        format!("Forgot {}.", format_fingerprint(&fp))
    } else {
        format!("{} was not paired.", format_fingerprint(&fp))
    })
}

/// `trust-client <fingerprint>`: pins a Remora client by the fingerprint
/// Remora shows in Settings → Security, so it pairs without the code here
/// (an admin pre-seeding a known PC). From then on the helper accepts
/// pinned clients only ([`strict_mode`]).
pub fn trust(path: &Path, fingerprint: &str, now: u64) -> Result<String, String> {
    let fp = parse_fingerprint(fingerprint)
        .ok_or("not a fingerprint (40 hex digits, as Remora shows it in Settings → Security)")?;
    let added = ClientStore::update(path, |s| s.trust(&fp, "", now)).map_err(|e| e.to_string())?;
    Ok(if added {
        format!(
            "Trusted {}. This helper now accepts paired clients only: an unknown \
             Remora client is refused without showing a code.",
            format_fingerprint(&fp)
        )
    } else {
        format!("{} was already trusted.", format_fingerprint(&fp))
    })
}

/// `YYYY-MM-DD` (UTC) for seconds since the Unix epoch.
fn date(secs: u64) -> String {
    // Civil from days (H. Hinnant's algorithm).
    let days = (secs / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_list_forget() {
        let dir = std::env::temp_dir().join(format!("remora-agent-clients-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("agent-clients.json");
        assert!(list(&p).unwrap().contains("No Remora client"));
        let key = [5u8; 32];
        let fp = remora_link::fingerprint(&key);
        assert!(trust(&p, "nope", 0).is_err());
        assert!(
            trust(&p, &fp.to_uppercase(), 1_763_164_800)
                .unwrap()
                .starts_with("Trusted")
        );
        assert!(trust(&p, &fp, 0).unwrap().contains("already"));
        // The pre-seeded fingerprint pins that key.
        assert!(ClientStore::load(&p).unwrap().is_pinned(&key));
        let l = list(&p).unwrap();
        assert!(l.contains(&fp) && l.contains("2025-11-15"), "{l}");
        assert!(
            forget(&p, &fp.replace(' ', ""))
                .unwrap()
                .starts_with("Forgot")
        );
        assert!(!ClientStore::load(&p).unwrap().is_pinned(&key));
        assert!(forget(&p, &fp).unwrap().contains("was not paired"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review 2 item 1: pinned clients only by policy, by the user's
    /// switch, or after an admin trusted a client; a dialog pin alone does
    /// not turn it on.
    #[test]
    fn strict_mode_sources() {
        let dir = std::env::temp_dir().join(format!("remora-agent-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (clients, setting) = (dir.join("agent-clients.json"), dir.join("agent-strict"));
        let off = |policy| strict_mode(policy, Some(&setting), Some(&clients));
        assert_eq!(off(None), None);
        assert_eq!(off(Some(0)), None);
        assert!(off(Some(1)).is_some_and(|w| w.contains("policy")));
        // A client paired through the dialog: still off.
        ClientStore::update(&clients, |s| s.pin(&[1; 32], "PC", 1)).unwrap();
        assert_eq!(off(None), None);
        // The user's switch.
        assert!(
            set_strict(true, &setting, None, Some(&clients))
                .unwrap()
                .contains(": on")
        );
        assert!(off(None).is_some_and(|w| w.contains("switched on")));
        assert!(
            set_strict(false, &setting, None, Some(&clients))
                .unwrap()
                .contains(": off")
        );
        assert_eq!(off(None), None);
        // A changed setting file fails closed.
        std::fs::write(&setting, b"garbage").unwrap();
        assert!(off(None).is_some());
        std::fs::remove_file(&setting).unwrap();
        // An admin's trust turns it on, and `strict off` says it stays on.
        let fp = remora_link::fingerprint(&[2; 32]);
        trust(&clients, &fp, 0).unwrap();
        assert!(off(None).is_some_and(|w| w.contains("trust-client")));
        assert!(
            set_strict(false, &setting, None, Some(&clients))
                .unwrap()
                .contains(": on")
        );
        assert!(list(&clients).unwrap().contains("trusted by fingerprint"));
        // A client list that cannot be read: on.
        std::fs::write(&clients, b"garbage").unwrap();
        assert!(off(None).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review 2 item 11: a client's own name is printed without control or
    /// direction characters.
    #[test]
    fn labels_are_printed_clean() {
        let dir = std::env::temp_dir().join(format!("remora-agent-label-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("agent-clients.json");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = remora_link::wire::hex(&remora_link::fingerprint_bytes(&[3; 32]));
        // Written by an older version that kept the label as sent.
        std::fs::write(
            &p,
            format!(
                r#"{{"{fp}":{{"key":"{}","first_seen":1,"label":"PC\u202e\u001b[2Jexe.txt"}}}}"#,
                remora_link::wire::hex(&[3; 32])
            ),
        )
        .unwrap();
        let l = list(&p).unwrap();
        assert!(l.contains("PC[2Jexe.txt"), "{l}");
        assert!(!l.contains('\u{202e}') && !l.contains('\u{1b}'), "{l:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_763_164_800), "2025-11-15");
    }
}
