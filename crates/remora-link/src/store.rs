//! Small JSON stores shared by several processes (the pinned helpers,
//! pairing attempts, the helper's pinned clients) and the key files: every
//! change re-reads the file, merges the change and writes it back under a
//! lock file, so two Remora windows (or two agent commands) never lose each
//! other's update. Writes go to a unique temporary file (created new, never
//! an existing one) that is then renamed over the store, so a reader sees
//! the old or the new file, never half of one.
//!
//! # The lock file
//!
//! `<store>.lock` is created with `create_new` and holds a random owner id
//! and the time it was taken (`<32 hex> <ms since the Unix epoch>`).
//! - **Release** removes it only while it still names this owner: a holder
//!   whose lock was taken over (it held it too long) never deletes the new
//!   holder's lock.
//! - **Stale** after [`LOCK_STALE`] by the time written inside (a copied or
//!   touched file keeps its age), or by its modification time when the
//!   content is unreadable (a crash between create and write). A time more
//!   than [`LOCK_SKEW`] in the future is stale too (a clock set back must
//!   not block writers for good).
//! - **Takeover** renames the stale lock to a unique name first and checks
//!   it moved the lock it judged stale. Two writers that both judged it
//!   stale cannot both win: the second rename finds nothing, or finds the
//!   first writer's fresh lock, which it puts back.
//! - **Waiting** is bounded by elapsed time on every path ([`update_within`]
//!   with a short wait suits a thread that must not stall; [`defer`] queues
//!   a write for a background thread instead).

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant, SystemTime};

/// How long a writer waits for the lock before giving up.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);
/// A lock file older than this is left over from a crashed writer.
pub const LOCK_STALE: Duration = Duration::from_secs(10);
/// A lock time this far in the future is stale too.
pub const LOCK_SKEW: Duration = Duration::from_secs(60);
const LOCK_RETRY: Duration = Duration::from_millis(10);
/// Takeovers per attempt to take the lock at most.
const MAX_TAKEOVERS: u32 = 3;

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn unique_suffix() -> io::Result<String> {
    let mut nonce = [0u8; 8];
    crate::random(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(crate::wire::hex(&nonce))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The owner id and time in a lock file, if it is in the current format.
fn parse_lock(content: &[u8]) -> Option<(&str, u64)> {
    let s = std::str::from_utf8(content).ok()?.trim_end();
    let (owner, ms) = s.split_once(' ')?;
    if owner.len() != 32 || !owner.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((owner, ms.parse().ok()?))
}

/// Whether a lock taken at `then` (ms) is stale at `now` (ms).
fn stale_at(then: u64, now: u64) -> bool {
    let stale = LOCK_STALE.as_millis() as u64;
    let skew = LOCK_SKEW.as_millis() as u64;
    now.saturating_sub(then) > stale || then > now.saturating_add(skew)
}

/// The lock file's content if the lock is stale (the exact bytes judged).
fn stale_content(path: &Path) -> Option<Vec<u8>> {
    let content = std::fs::read(path).ok()?;
    let now = now_ms();
    let then = match parse_lock(&content) {
        Some((_, ms)) => ms,
        // Unreadable content: being written right now, or a crash between
        // create and write. Its modification time decides.
        None => {
            let m = std::fs::metadata(path).ok()?.modified().ok()?;
            match m.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(d) => d.as_millis() as u64,
                Err(_) => 0,
            }
        }
    };
    stale_at(then, now).then_some(content)
}

/// Moves the stale lock `judged` out of the way. False when the lock at
/// `path` is no longer that one (released, or taken over and fresh again):
/// a fresh lock moved by mistake is put back.
fn take_over(path: &Path, judged: &[u8]) -> bool {
    let Ok(suffix) = unique_suffix() else {
        return false;
    };
    let aside = with_suffix(path, &format!(".{suffix}.stale"));
    if std::fs::rename(path, &aside).is_err() {
        return false;
    }
    let moved = std::fs::read(&aside).ok();
    if moved.as_deref() == Some(judged) {
        let _ = std::fs::remove_file(&aside);
        return true;
    }
    // Someone took the lock between our check and our rename. Put it back
    // unless yet another lock exists; either way its owner's release (which
    // checks the owner id) does not touch a lock that is not its own.
    let _ = std::fs::hard_link(&aside, path);
    let _ = std::fs::remove_file(&aside);
    false
}

/// Holds `<store>.lock` until dropped.
pub(crate) struct Lock {
    path: PathBuf,
    owner: String,
}

impl Lock {
    /// Takes the lock, waiting at most `wait` (`WouldBlock` after that).
    pub(crate) fn take(store: &Path, wait: Duration) -> io::Result<Lock> {
        let path = with_suffix(store, ".lock");
        let owner = format!("{}{}", unique_suffix()?, unique_suffix()?);
        let deadline = Instant::now() + wait;
        let mut takeovers = 0;
        // On Windows a lock file another writer just deleted stays "delete
        // pending" for a moment, and creating it then fails with Access
        // denied instead of AlreadyExists: busy, not an error. A denial that
        // lasts until the deadline is reported as itself.
        let mut denied: Option<io::Error>;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if let Err(e) = write!(f, "{owner} {}", now_ms()) {
                        drop(f);
                        let _ = std::fs::remove_file(&path);
                        return Err(e);
                    }
                    return Ok(Lock { path, owner });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => denied = None,
                Err(e) if cfg!(windows) && e.kind() == io::ErrorKind::PermissionDenied => {
                    denied = Some(e);
                }
                Err(e) => return Err(e),
            }
            // A takeover earns one more immediate try, a bounded number of
            // times; everything else waits, and never past the deadline.
            let took = takeovers < MAX_TAKEOVERS
                && stale_content(&path).is_some_and(|c| take_over(&path, &c));
            if took {
                takeovers += 1;
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                if let Some(e) = denied {
                    return Err(e);
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("{} is locked by another writer", store.display()),
                ));
            }
            std::thread::sleep(LOCK_RETRY.min(deadline - now));
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Only our own lock: after a takeover it belongs to someone else.
        let ours = std::fs::read(&self.path)
            .ok()
            .is_some_and(|c| parse_lock(&c).is_some_and(|(o, _)| o == self.owner));
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Replaces `path` with `data` through a unique temporary file (created
/// new) and a rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    write_new_then_rename(path, data, false)
}

/// [`write_atomic`]; `private`: the file is for this user only where the
/// platform has modes (key files).
pub(crate) fn write_new_then_rename(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = with_suffix(
        path,
        &format!(".{}.{}.tmp", std::process::id(), unique_suffix()?),
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    rename_retrying(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// `rename`, retried briefly on Windows' Access denied: replacing a file
/// that is "delete pending" (just removed while another handle was still
/// open) fails that way for a moment.
fn rename_retrying(from: &Path, to: &Path) -> io::Result<()> {
    let mut tries = 0;
    loop {
        match std::fs::rename(from, to) {
            Err(e)
                if cfg!(windows) && e.kind() == io::ErrorKind::PermissionDenied && tries < 20 =>
            {
                tries += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            r => return r,
        }
    }
}

/// Runs `f` under `path`'s lock file (waiting at most `wait`).
pub(crate) fn locked<R>(
    path: &Path,
    wait: Duration,
    f: impl FnOnce() -> io::Result<R>,
) -> io::Result<R> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _lock = Lock::take(path, wait)?;
    f()
}

/// Reads `path` (None when missing), lets `change` compute the new content
/// and writes it, all under the store's lock file. `change` returning
/// `Ok(None)` leaves the file as it is.
pub fn update<R>(
    path: &Path,
    change: impl FnOnce(Option<Vec<u8>>) -> crate::Result<(Option<Vec<u8>>, R)>,
) -> crate::Result<R> {
    update_within(path, LOCK_WAIT, change)
}

/// [`update`], waiting at most `wait` for the lock: then an
/// `io::ErrorKind::WouldBlock` error ([`is_busy`]) and nothing changed.
pub fn update_within<R>(
    path: &Path,
    wait: Duration,
    change: impl FnOnce(Option<Vec<u8>>) -> crate::Result<(Option<Vec<u8>>, R)>,
) -> crate::Result<R> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _lock = Lock::take(path, wait)?;
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

/// The error of an update that gave up waiting for another writer.
pub fn is_busy(e: &crate::Error) -> bool {
    matches!(e, crate::Error::Io(io) if io.kind() == io::ErrorKind::WouldBlock)
}

type Job = Box<dyn FnOnce() + Send>;

/// The background store writer: one thread, jobs in order.
static WRITER: Mutex<Option<Sender<Job>>> = Mutex::new(None);

/// Runs `job` on the background store writer thread, after every job
/// queued before it: for a write that may wait for another process's lock
/// (up to [`LOCK_WAIT`]) when the caller must not. Without a thread the
/// job runs here.
pub fn defer(job: impl FnOnce() + Send + 'static) {
    let mut w = WRITER.lock().unwrap_or_else(|p| p.into_inner());
    let mut job: Job = Box::new(job);
    if let Some(tx) = w.as_ref() {
        match tx.send(job) {
            Ok(()) => return,
            Err(mpsc::SendError(back)) => job = back,
        }
    }
    let (tx, rx) = mpsc::channel::<Job>();
    let spawned = std::thread::Builder::new()
        .name("remora-store".into())
        .spawn(move || {
            for job in rx {
                job();
            }
        });
    match spawned {
        Ok(_) => {
            let _ = tx.send(job);
            *w = Some(tx);
        }
        Err(_) => {
            drop(w);
            job();
        }
    }
}

/// Waits until every job [`defer`]red before has run (tests, shutdown);
/// false after `timeout`.
pub fn flush_deferred(timeout: Duration) -> bool {
    let (tx, rx) = mpsc::channel();
    defer(move || {
        let _ = tx.send(());
    });
    rx.recv_timeout(timeout).is_ok()
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

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
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
        assert_eq!(names(dir), ["s.json"], "no lock or temporary file left");
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

    /// Review 2 item 8: the age comes from the time inside the lock (a
    /// fresh modification time does not keep an old lock alive), and a
    /// time far in the future (a clock set back) is stale too, by content
    /// or by modification time.
    #[test]
    fn lock_age_by_content_and_future_times_are_stale() {
        let p = temp("future");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let lock = with_suffix(&p, ".lock");
        let owner = "ab".repeat(16);
        let fast = Duration::from_millis(300);
        // Old by content, fresh by modification time.
        std::fs::write(&lock, format!("{owner} {}", now_ms() - 60_000)).unwrap();
        update_within(&p, fast, |_| Ok((Some(b"1".to_vec()), ()))).unwrap();
        // An hour in the future by content.
        std::fs::write(&lock, format!("{owner} {}", now_ms() + 3_600_000)).unwrap();
        update_within(&p, fast, |_| Ok((Some(b"2".to_vec()), ()))).unwrap();
        // Old format, modification time an hour in the future.
        std::fs::write(&lock, b"1234").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(3600))
            .unwrap();
        update_within(&p, fast, |_| Ok((Some(b"3".to_vec()), ()))).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"3");
        // A fresh lock holds, and the wait is bounded by time.
        std::fs::write(&lock, format!("{owner} {}", now_ms())).unwrap();
        let t = Instant::now();
        let e = update_within(&p, fast, |_| Ok((Some(b"4".to_vec()), ()))).unwrap_err();
        assert!(is_busy(&e), "{e}");
        assert!(t.elapsed() < Duration::from_secs(2));
        assert_eq!(std::fs::read(&p).unwrap(), b"3");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Review 2 item 8: a holder releases only its own lock; one taken
    /// over meanwhile stays with its new owner.
    #[test]
    fn release_removes_only_its_own_lock() {
        let p = temp("owner");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let lock_path = with_suffix(&p, ".lock");
        let lock = Lock::take(&p, LOCK_WAIT).unwrap();
        let other = format!("{} {}", "cd".repeat(16), now_ms());
        std::fs::write(&lock_path, &other).unwrap();
        drop(lock);
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), other);
        let lock = {
            std::fs::remove_file(&lock_path).unwrap();
            Lock::take(&p, LOCK_WAIT).unwrap()
        };
        drop(lock);
        assert!(!lock_path.exists(), "its own lock is removed");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Review 2 item 8: a takeover that finds a different (fresh) lock
    /// than the stale one it judged leaves that lock in place.
    #[test]
    fn a_takeover_never_removes_a_fresh_lock() {
        let p = temp("takeover");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let lock = with_suffix(&p, ".lock");
        let stale = format!("{} {}", "ab".repeat(16), now_ms() - 60_000);
        let fresh = format!("{} {}", "cd".repeat(16), now_ms());
        // Another writer replaced the stale lock between check and takeover.
        std::fs::write(&lock, &fresh).unwrap();
        assert!(!take_over(&lock, stale.as_bytes()));
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), fresh);
        // The stale one it judged is moved away.
        std::fs::write(&lock, &stale).unwrap();
        assert!(take_over(&lock, stale.as_bytes()));
        assert!(!lock.exists());
        assert_eq!(names(p.parent().unwrap()), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn deferred_jobs_run_in_order() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        for i in 0..5 {
            let s = seen.clone();
            defer(move || s.lock().unwrap().push(i));
        }
        assert!(flush_deferred(Duration::from_secs(10)));
        assert_eq!(*seen.lock().unwrap(), [0, 1, 2, 3, 4]);
    }
}
