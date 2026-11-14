//! The host password and logon rate limiting.
//!
//! The password is stored as an Argon2id hash in the PHC string format
//! (`password.argon2` in the data directory); the plain password is never
//! written. Verification is Argon2's own constant-time comparison. Any user
//! name is accepted: the password is the host's single credential.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

use crate::backend::Authenticator;

/// The shortest password `set-password` takes.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Argon2id cost: 64 MiB, 3 passes, 1 lane (as Remora's vault): about half
/// a second per logon attempt on a desktop PC, which also slows guessing.
fn params() -> Params {
    Params::new(64 * 1024, 3, 1, None).expect("valid Argon2 parameters")
}

/// `<data dir>/password.argon2`.
pub fn password_path(dir: &Path) -> PathBuf {
    dir.join("password.argon2")
}

/// Hashes a password with Argon2id and a random salt (PHC string).
pub fn hash_password(password: &str) -> io::Result<String> {
    hash_with(password, params())
}

fn hash_with(password: &str, params: Params) -> io::Result<String> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| io::Error::other(format!("cannot hash the password: {e}")))
}

/// Writes the hash of a new password (replacing an old one).
pub fn set_password(dir: &Path, password: &str) -> io::Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the password needs at least {MIN_PASSWORD_CHARS} characters"),
        ));
    }
    let hash = hash_password(password)?;
    crate::paths::write_private(&password_path(dir), hash.as_bytes())
}

/// Checks passwords against the stored Argon2id hash.
pub struct PasswordAuthenticator {
    hash: String,
}

impl PasswordAuthenticator {
    /// From a PHC string, as `hash_password` makes it.
    pub fn from_hash(hash: &str) -> io::Result<PasswordAuthenticator> {
        let hash = hash.trim();
        argon2::PasswordHash::new(hash)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad hash: {e}")))?;
        if !hash.starts_with("$argon2id$") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored hash is not Argon2id",
            ));
        }
        Ok(PasswordAuthenticator { hash: hash.into() })
    }

    /// Loads the stored hash; NotFound when no password was set.
    pub fn load(dir: &Path) -> io::Result<PasswordAuthenticator> {
        let text = std::fs::read_to_string(password_path(dir))?;
        Self::from_hash(&text)
    }
}

impl Authenticator for PasswordAuthenticator {
    fn check(&self, _user: &str, _domain: &str, password: &str) -> bool {
        // The hash string carries its own parameters and salt.
        !password.is_empty()
            && Argon2::default()
                .verify_password(password.as_bytes(), self.hash.as_str())
                .is_ok()
    }
}

/// Logon failure limits per source address.
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    /// The answer to the first wrong password waits this long; each further
    /// consecutive failure doubles it, up to `max_delay`.
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// After this many failures within `window`, new connections from the
    /// address are refused until the window has passed.
    pub max_failures: u32,
    pub window: Duration,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            max_failures: 5,
            window: Duration::from_secs(60),
        }
    }
}

struct Entry {
    /// Consecutive failures (reset by a successful logon).
    consecutive: u32,
    /// Failures since `window_start`.
    in_window: u32,
    window_start: Instant,
}

/// Counts logon failures per IP address.
pub struct RateLimiter {
    limit: RateLimit,
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> RateLimiter {
        RateLimiter {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// False while the address has used up its failures in the window.
    pub fn allowed(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.entries();
        let Some(e) = map.get_mut(&ip) else {
            return true;
        };
        if now.duration_since(e.window_start) >= self.limit.window {
            e.in_window = 0;
            e.window_start = now;
        }
        e.in_window < self.limit.max_failures
    }

    /// Records a failure; returns how long to wait before answering.
    pub fn failure(&self, ip: IpAddr, now: Instant) -> Duration {
        let mut map = self.entries();
        let e = map.entry(ip).or_insert(Entry {
            consecutive: 0,
            in_window: 0,
            window_start: now,
        });
        if now.duration_since(e.window_start) >= self.limit.window {
            e.in_window = 0;
            e.window_start = now;
        }
        e.consecutive = e.consecutive.saturating_add(1);
        e.in_window = e.in_window.saturating_add(1);
        let factor = 1u32 << (e.consecutive - 1).min(16);
        self.limit
            .base_delay
            .saturating_mul(factor)
            .min(self.limit.max_delay)
    }

    /// A successful logon resets the address's consecutive failures.
    pub fn success(&self, ip: IpAddr) {
        if let Some(e) = self.entries().get_mut(&ip) {
            e.consecutive = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap(password: &str) -> PasswordAuthenticator {
        let p = Params::new(64, 1, 1, None).unwrap();
        PasswordAuthenticator::from_hash(&hash_with(password, p).unwrap()).unwrap()
    }

    #[test]
    fn password_is_checked_against_the_hash() {
        let a = cheap("correct horse");
        assert!(a.hash.starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
        assert!(!a.hash.contains("correct"));
        assert!(a.check("anyone", "", "correct horse"));
        assert!(!a.check("anyone", "", "correct hors"));
        assert!(!a.check("anyone", "", "correct horse "));
        assert!(!a.check("anyone", "", ""));
        // Other algorithms or garbage are refused when loading.
        assert!(PasswordAuthenticator::from_hash("plain").is_err());
        let argon2i = a.hash.replacen("argon2id", "argon2i", 1);
        assert!(PasswordAuthenticator::from_hash(&argon2i).is_err());
    }

    #[test]
    fn set_password_stores_only_a_hash() {
        let dir = std::env::temp_dir().join(format!("remora-host-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(set_password(&dir, "short").is_err());
        assert!(PasswordAuthenticator::load(&dir).is_err());
        set_password(&dir, "a long enough one").unwrap();
        let stored = std::fs::read_to_string(password_path(&dir)).unwrap();
        assert!(!stored.contains("long enough"));
        let a = PasswordAuthenticator::load(&dir).unwrap();
        assert!(a.check("u", "", "a long enough one"));
        assert!(!a.check("u", "", "a long enough two"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failures_back_off_and_lock_out() {
        let l = RateLimiter::new(RateLimit {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(350),
            max_failures: 3,
            window: Duration::from_secs(60),
        });
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        let t0 = Instant::now();
        assert!(l.allowed(ip, t0));
        let delays: Vec<u128> = (0..3).map(|_| l.failure(ip, t0).as_millis()).collect();
        assert_eq!(delays, [100, 200, 350]);
        assert!(!l.allowed(ip, t0), "three failures in the window");
        assert!(l.allowed(other, t0), "per address");
        // After the window the address may try again; the delay keeps growing
        // until a success.
        let later = t0 + Duration::from_secs(61);
        assert!(l.allowed(ip, later));
        assert_eq!(l.failure(ip, later).as_millis(), 350);
        l.success(ip);
        assert_eq!(l.failure(ip, later).as_millis(), 100);
    }
}
