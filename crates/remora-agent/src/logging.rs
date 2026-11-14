//! The agent's log: `%LOCALAPPDATA%\rdp-rs\logs\remora-agent.log`, next to
//! Remora's own log. Size-capped: past [`MAX_LOG_BYTES`] the file moves to
//! `remora-agent.log.1` (replacing the older one) and a new file starts, so
//! the log never takes more than twice the cap.
//!
//! What is logged: lifecycle (start, channel open and close, session
//! events, pairing, transfer ids and sizes), errors and sizes. Never message
//! contents, keys or URLs; file names only at debug level ([`set_debug`]).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_LOG_BYTES: u64 = 1 << 20;

pub fn default_log_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(
        PathBuf::from(base)
            .join("rdp-rs")
            .join("logs")
            .join("remora-agent.log"),
    )
}

struct Inner {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    cap: u64,
}

pub struct Logger {
    inner: Mutex<Option<Inner>>,
    tag: &'static str,
}

impl Logger {
    /// Opens (appends to) the log at `path`, creating its folder.
    pub fn open(path: &Path, cap: u64, tag: &'static str) -> Self {
        let mut inner = Inner {
            path: path.to_path_buf(),
            file: None,
            size: 0,
            cap,
        };
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        inner.reopen();
        Self {
            inner: Mutex::new(Some(inner)),
            tag,
        }
    }

    pub fn log(&self, level: &str, msg: &str) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let Some(inner) = guard.as_mut() else {
            return;
        };
        let line = format!(
            "{} {level} [{} {}] {msg}\n",
            timestamp(SystemTime::now()),
            self.tag,
            std::process::id()
        );
        inner.write(line.as_bytes());
    }
}

impl Inner {
    fn reopen(&mut self) {
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        self.size = self
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map_or(0, |m| m.len());
    }

    fn write(&mut self, line: &[u8]) {
        if self.size + line.len() as u64 > self.cap {
            self.rotate();
        }
        if let Some(f) = self.file.as_mut()
            && f.write_all(line).is_ok()
        {
            self.size += line.len() as u64;
        }
    }

    fn rotate(&mut self) {
        self.file = None;
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        let _ = fs::remove_file(&old);
        let _ = fs::rename(&self.path, &old);
        self.reopen();
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC) without a date crate.
pub fn timestamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

static LOGGER: Mutex<Option<&'static Logger>> = Mutex::new(None);

/// Installs the process-wide logger used by the `info!`-style macros.
pub fn install(logger: Logger) {
    let leaked: &'static Logger = Box::leak(Box::new(logger));
    if let Ok(mut g) = LOGGER.lock() {
        *g = Some(leaked);
    }
}

pub fn log(level: &str, msg: &str) {
    let logger = LOGGER.lock().ok().and_then(|g| *g);
    if let Some(l) = logger {
        l.log(level, msg);
    }
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Debug lines (file names of transfers) are off unless switched on
/// (`REMORA_AGENT_DEBUG=1` in the agent's environment).
pub fn set_debug(on: bool) {
    DEBUG.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(std::sync::atomic::Ordering::Relaxed)
}

/// Debug level: may name files; never contents, keys or links.
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => {
        if $crate::logging::debug_enabled() {
            $crate::logging::log("DEBUG", &format!($($t)*))
        }
    };
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::logging::log("INFO", &format!($($t)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { $crate::logging::log("WARN", &format!($($t)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-11-14T14:41:49Z
        let t = UNIX_EPOCH + Duration::from_secs(1_794_667_309);
        assert_eq!(timestamp(t), "2026-11-14T14:41:49Z");
        // A leap day.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(timestamp(t), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn rotates_at_the_cap() {
        let dir =
            std::env::temp_dir().join(format!("remora-agent-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("logs").join("a.log");
        let l = Logger::open(&path, 300, "t");
        for i in 0..20 {
            l.log("INFO", &format!("line {i} ------------------------------"));
        }
        let cur = fs::metadata(&path).unwrap().len();
        let old = fs::metadata(dir.join("logs").join("a.log.1"))
            .unwrap()
            .len();
        assert!(cur <= 300 && old <= 300, "{cur} {old}");
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("line 19"));
        assert!(!text.contains("line 0 "));
        let _ = fs::remove_dir_all(&dir);
    }
}
