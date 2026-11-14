//! Small JSON stores shared by several processes (the pinned helpers,
//! pairing attempts, the helper's pinned clients): every change re-reads
//! the file, merges the change and writes it back under a lock file, so
//! two Remora windows (or two agent commands) never lose each other's
//! update. Writes go to a per-process unique temporary file that is then
//! renamed over the store, so a reader sees the old or the new file, never
//! half of one.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How long a writer waits for the lock before giving up.
const LOCK_WAIT: Duration = Duration::from_secs(2);
/// A lock file older than this is left over from a crashed writer.
const LOCK_STALE: Duration = Duration::from_secs(10);
const LOCK_RETRY: Duration = Duration::from_millis(10);

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Holds `<store>.lock` (created new) until dropped.
struct Lock(PathBuf);

impl Lock {
    fn take(store: &Path) -> io::Result<Lock> {
        let path = with_suffix(store, ".lock");
        let start = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = write!(f, "{}", std::process::id());
                    return Ok(Lock(path));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| SystemTime::now().duration_since(t).ok())
                        .is_some_and(|age| age > LOCK_STALE);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed() > LOCK_WAIT {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            format!("{} is locked by another writer", store.display()),
                        ));
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Replaces `path` with `data` through a unique temporary file and a rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut nonce = [0u8; 8];
    crate::random(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
    let tmp = with_suffix(
        path,
        &format!(".{}.{}.tmp", std::process::id(), crate::wire::hex(&nonce)),
    );
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(data)?;
            f.sync_all()
        });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Reads `path` (None when missing), lets `change` compute the new content
/// and writes it, all under the store's lock file. `change` returning
/// `Ok(None)` leaves the file as it is.
pub fn update<R>(
    path: &Path,
    change: impl FnOnce(Option<Vec<u8>>) -> crate::Result<(Option<Vec<u8>>, R)>,
) -> crate::Result<R> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _lock = Lock::take(path)?;
    let current = match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let (next, r) = change(current)?;
    if let Some(data) = next {
        write_atomic(path, &data)?;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("remora-link-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("s.json")
    }

    /// Two writers adding to the same file at the same time: with a plain
    /// read-modify-write one of them would lose its entry.
    #[test]
    fn concurrent_updates_are_merged() {
        let p = temp("merge");
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for j in 0..5 {
                        update(&p, |cur| {
                            let mut v: Vec<u32> = cur
                                .map(|b| serde_json::from_slice(&b).unwrap())
                                .unwrap_or_default();
                            // Widen the race window a little.
                            std::thread::sleep(Duration::from_millis(1));
                            v.push(i * 10 + j);
                            Ok((Some(serde_json::to_vec(&v).unwrap()), ()))
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let v: Vec<u32> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v.len(), 40, "every update kept");
        let dir = p.parent().unwrap();
        let left: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["s.json"], "no lock or temporary file left");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_stale_lock_is_taken_over_and_an_error_writes_nothing() {
        let p = temp("stale");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let lock = with_suffix(&p, ".lock");
        std::fs::write(&lock, b"1").unwrap();
        let old = SystemTime::now() - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        update(&p, |_| Ok((Some(b"1".to_vec()), ()))).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"1");
        let r: crate::Result<()> = update(&p, |_| Err(crate::Error::State("no")));
        assert!(r.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"1", "unchanged");
        assert!(!lock.exists());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
