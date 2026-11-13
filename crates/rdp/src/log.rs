//! Protocol tracing: to stderr, and to a log file when one is set.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static VERBOSE: AtomicBool = AtomicBool::new(false);

struct LogFile {
    file: std::fs::File,
    start: Instant,
    written: u64,
}

static FILE: Mutex<Option<LogFile>> = Mutex::new(None);

/// A log file stops growing at this size (a long session would fill a disk).
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// Enables protocol tracing.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Also writes every trace line to `path` (replacing an old file), with the
/// time since the log started. None stops writing to a file.
pub fn set_log_file(path: Option<&Path>) -> std::io::Result<()> {
    let next = match path {
        Some(p) => {
            if let Some(dir) = p.parent() {
                std::fs::create_dir_all(dir)?;
            }
            Some(LogFile {
                file: std::fs::File::create(p)?,
                start: Instant::now(),
                written: 0,
            })
        }
        None => None,
    };
    *FILE.lock().unwrap_or_else(|e| e.into_inner()) = next;
    Ok(())
}

/// Writes one trace line (used by [`trace!`]).
pub fn emit(line: &str) {
    eprintln!("[rdp] {line}");
    let mut guard = FILE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = guard.as_mut()
        && f.written < MAX_LOG_BYTES
    {
        let t = f.start.elapsed();
        let text = format!("{:>5}.{:03} {line}\n", t.as_secs(), t.subsec_millis());
        f.written += text.len() as u64;
        let _ = f.file.write_all(text.as_bytes());
        if f.written >= MAX_LOG_BYTES {
            let _ = f
                .file
                .write_all(b"(log size limit reached; later lines are not written)\n");
        }
    }
}

#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        if $crate::log::verbose() {
            $crate::log::emit(&format!($($t)*));
        }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn lines_go_to_the_file() {
        let p = std::env::temp_dir().join(format!("rdp-log-test-{}.log", std::process::id()));
        super::set_log_file(Some(&p)).unwrap();
        super::emit("hello file");
        super::set_log_file(None).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("hello file"), "{text}");
        let _ = std::fs::remove_file(&p);
    }
}
