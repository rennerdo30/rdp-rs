//! `remora-agent clients`, `forget-client` and `trust-client`: the Remora
//! clients this user confirmed on the server (`agent-clients.json`,
//! HELPER-PROTOCOL.md 4). Only a pinned client receives files or links from
//! the server. Platform independent; `win` prints the results.

use std::path::Path;

use remora_link::{ClientStore, format_fingerprint, parse_fingerprint};

/// The list as printed by `remora-agent clients`.
pub fn list(path: &Path) -> Result<String, String> {
    let store = ClientStore::load(path).map_err(|e| format!("cannot read the client list: {e}"))?;
    let mut out = String::new();
    for (fp, c) in store.iter() {
        let label = if c.label.is_empty() {
            "(no name)"
        } else {
            c.label.as_str()
        };
        let how = if c.key.is_empty() {
            ", added by fingerprint"
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
/// (an admin pre-seeding a known PC).
pub fn trust(path: &Path, fingerprint: &str, now: u64) -> Result<String, String> {
    let fp = parse_fingerprint(fingerprint)
        .ok_or("not a fingerprint (40 hex digits, as Remora shows it in Settings → Security)")?;
    let added = ClientStore::update(path, |s| s.trust(&fp, "", now)).map_err(|e| e.to_string())?;
    Ok(if added {
        format!("Trusted {}.", format_fingerprint(&fp))
    } else {
        format!("{} was already paired.", format_fingerprint(&fp))
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

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_763_164_800), "2025-11-15");
    }
}
