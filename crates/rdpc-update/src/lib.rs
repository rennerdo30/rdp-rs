//! Update checks for rdpc: release discovery on GitHub, version order,
//! channel choice, checksum verification and bounded HTTPS downloads.
//!
//! The parsing and selection logic has no I/O and is unit-tested. Network
//! access goes through WinHTTP on Windows and the system `curl` elsewhere,
//! so no HTTP or TLS crate enters the build. Only GitHub's fixed release
//! URLs for this repository are ever fetched.
//!
//! The UI needs only a few calls, all of them blocking (run them on a
//! worker thread, never on the UI thread):
//!
//! 1. [`due`] with [`stamp_path`]: is a daily check due? Then [`check`] and
//!    [`write_stamp`] (also after a failed check: no retry storm).
//! 2. [`is_installed_copy`]: only a copy installed by the setup installs
//!    updates; other copies only name [`RELEASE_PAGE`].
//! 3. [`download_verified`], then [`launch_setup`] (Windows), then close
//!    rdpc: the setup waits for it to exit, installs and restarts it.
//!
//! Release asset contract: `rdpc-<version>-setup.exe` and `SHA256SUMS.txt`.

use serde_json::Value;
use std::cmp::Ordering;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const REPO: &str = "rennerdo30/rdp-rs";
pub const RELEASE_PAGE: &str = "https://github.com/rennerdo30/rdp-rs/releases";
/// The product (and executable) name; also the install folder name.
pub const PRODUCT: &str = "rdpc";
const API_PREFIX: &str = "https://api.github.com/repos/rennerdo30/rdp-rs/";
const API_URL: &str = "https://api.github.com/repos/rennerdo30/rdp-rs/releases?per_page=30";
const DOWNLOAD_PREFIX: &str = "https://github.com/rennerdo30/rdp-rs/releases/download/";
pub const SUMS: &str = "SHA256SUMS.txt";
pub const MAX_METADATA: usize = 8 * 1024 * 1024;
pub const MAX_SETUP: usize = 200 * 1024 * 1024;
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}

/// A SemVer version, `MAJOR.MINOR.PATCH[-PRE]`, no build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Text(String),
}

impl Version {
    /// Strict parse; a leading `v` (tags) is accepted.
    pub fn parse(input: &str) -> Result<Version, Error> {
        let input = input.strip_prefix('v').unwrap_or(input);
        if input.len() > 64 {
            return Err(err("version is too long"));
        }
        let (core, pre) = match input.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (input, None),
        };
        let mut parts = core.split('.');
        let mut number = || -> Result<u64, Error> {
            let s = parts
                .next()
                .ok_or_else(|| err("version needs major.minor.patch"))?;
            if s.is_empty()
                || (s.len() > 1 && s.starts_with('0'))
                || !s.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(err("invalid numeric version component"));
            }
            s.parse().map_err(|_| err("version component is too large"))
        };
        let (major, minor, patch) = (number()?, number()?, number()?);
        if parts.next().is_some() {
            return Err(err("version needs exactly three numeric components"));
        }
        let mut ids = Vec::new();
        if let Some(pre) = pre {
            for part in pre.split('.') {
                if part.is_empty() || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                {
                    return Err(err("invalid prerelease identifier"));
                }
                if part.bytes().all(|c| c.is_ascii_digit()) {
                    if part.len() > 1 && part.starts_with('0') {
                        return Err(err("numeric prerelease identifier has a leading zero"));
                    }
                    ids.push(Ident::Num(
                        part.parse()
                            .map_err(|_| err("prerelease number is too large"))?,
                    ));
                } else {
                    ids.push(Ident::Text(part.to_owned()));
                }
            }
        }
        Ok(Version {
            major,
            minor,
            patch,
            pre: ids,
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    /// SemVer precedence: a release ranks above its prereleases; numeric
    /// identifiers compare numerically and below text identifiers.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let c = match (a, b) {
                            (Ident::Num(x), Ident::Num(y)) => x.cmp(y),
                            (Ident::Num(_), Ident::Text(_)) => Ordering::Less,
                            (Ident::Text(_), Ident::Num(_)) => Ordering::Greater,
                            (Ident::Text(x), Ident::Text(y)) => x.cmp(y),
                        };
                        if c != Ordering::Equal {
                            return c;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, p) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match p {
                Ident::Num(n) => write!(f, "{n}")?,
                Ident::Text(s) => f.write_str(s)?,
            }
        }
        Ok(())
    }
}

/// Which releases an install is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Published stable releases only.
    Stable,
    /// The newest published release, prerelease or stable.
    Beta,
}

impl Channel {
    /// A prerelease build follows Beta, a stable build follows Stable.
    pub fn for_version(v: &Version) -> Channel {
        if v.is_prerelease() {
            Channel::Beta
        } else {
            Channel::Stable
        }
    }

    pub fn from_setting(s: Option<&str>, current: &Version) -> Channel {
        match s {
            Some("stable") => Channel::Stable,
            Some("beta") => Channel::Beta,
            _ => Channel::for_version(current),
        }
    }
}

pub fn setup_name(v: &Version) -> String {
    format!("rdpc-{v}-setup.exe")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub version: Version,
    pub setup_url: String,
    pub sums_url: String,
}

/// The newest release newer than `current` that `channel` offers, from the
/// GitHub releases list. Drafts, unparseable tags, downgrades and releases
/// without the setup and checksum assets are skipped; Stable never takes a
/// prerelease.
pub fn pick(current: &Version, channel: Channel, body: &[u8]) -> Result<Option<Candidate>, Error> {
    if body.len() > MAX_METADATA {
        return Err(err("release metadata exceeds 8 MiB"));
    }
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| err(format!("unexpected answer from GitHub: {e}")))?;
    let list = v
        .as_array()
        .ok_or_else(|| err("unexpected answer from GitHub: not a list"))?;
    let mut best: Option<Candidate> = None;
    for rel in list {
        if rel.get("draft").and_then(Value::as_bool) != Some(false) {
            continue;
        }
        let Some(version) = rel
            .get("tag_name")
            .and_then(Value::as_str)
            .and_then(|t| Version::parse(t).ok())
        else {
            continue;
        };
        let pre = rel
            .get("prerelease")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if version <= *current || (channel == Channel::Stable && (pre || version.is_prerelease())) {
            continue;
        }
        let Some(assets) = rel.get("assets").and_then(Value::as_array) else {
            continue;
        };
        let url = |name: &str| {
            assets
                .iter()
                .find(|a| a.get("name").and_then(Value::as_str) == Some(name))
                .and_then(|a| a.get("browser_download_url"))
                .and_then(Value::as_str)
                .filter(|u| u.starts_with(DOWNLOAD_PREFIX))
                .map(str::to_owned)
        };
        let (Some(setup_url), Some(sums_url)) = (url(&setup_name(&version)), url(SUMS)) else {
            continue;
        };
        if best.as_ref().is_none_or(|b| version > b.version) {
            best = Some(Candidate {
                version,
                setup_url,
                sums_url,
            });
        }
    }
    Ok(best)
}

/// The expected SHA-256 (lowercase hex) of `name` in a sha256sum file.
/// Exactly one well-formed line for the name is required.
pub fn expected_hash(sums: &str, name: &str) -> Result<String, Error> {
    let mut found = Vec::new();
    for line in sums.lines() {
        let line = line.trim_end_matches('\r');
        let Some((hash, file)) = line.split_once(' ') else {
            continue;
        };
        let file = file.trim_start_matches([' ', '*']);
        if file == name {
            if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err(format!("{SUMS} has a malformed entry for {name}")));
            }
            found.push(hash.to_ascii_lowercase());
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(err(format!("{SUMS} has no checksum for {name}"))),
        _ => Err(err(format!("{SUMS} lists {name} more than once"))),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Whether a daily check is due, from the timestamp file of the last one.
pub fn due(stamp: &Path, now: SystemTime) -> bool {
    let last = std::fs::read_to_string(stamp)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    last.is_none_or(|l| now.saturating_sub(l) >= CHECK_INTERVAL.as_secs() || l > now)
}

pub fn write_stamp(stamp: &Path, now: SystemTime) -> Result<(), Error> {
    if let Some(dir) = stamp.parent() {
        std::fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    }
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    std::fs::write(stamp, secs.to_string()).map_err(|e| err(e.to_string()))
}

/// Asks GitHub for the release list and picks a candidate.
pub fn check(current: &Version, channel: Channel) -> Result<Option<Candidate>, Error> {
    let body = fetch(API_URL, MAX_METADATA)?;
    pick(current, channel, &body)
}

/// Downloads `SHA256SUMS.txt` and the setup of `c`, and returns the setup
/// bytes only when they match their published checksum.
pub fn download_verified(c: &Candidate) -> Result<Vec<u8>, Error> {
    let sums = fetch(&c.sums_url, 1024 * 1024)?;
    let sums = String::from_utf8(sums).map_err(|_| err(format!("{SUMS} is not text")))?;
    let expected = expected_hash(&sums, &setup_name(&c.version))?;
    let setup = fetch(&c.setup_url, MAX_SETUP)?;
    if sha256_hex(&setup) != expected {
        return Err(err(
            "the downloaded setup does not match its published checksum, so it was not run",
        ));
    }
    Ok(setup)
}

/// The current build's version (`CARGO_PKG_VERSION` of the workspace).
pub fn current_version() -> Result<Version, Error> {
    Version::parse(env!("CARGO_PKG_VERSION"))
}

/// The file that records when the last update check ran: in the per-user,
/// non-roaming data folder (`%LOCALAPPDATA%\rdp-rs\update-check` on
/// Windows), never next to the roaming settings in `%APPDATA%\rdp-rs`.
pub fn stamp_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let d = std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("rdp-rs"));
    #[cfg(target_os = "macos")]
    let d = std::env::var_os("HOME")
        .map(|p| PathBuf::from(p).join("Library/Application Support/rdp-rs"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let d = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .map(|p| p.join("rdp-rs"));
    d.map(|d| d.join("update-check"))
}

/// Where the setup installs rdpc: `<LOCALAPPDATA>\Programs\rdpc`.
pub fn install_dir_in(local_app_data: &Path) -> PathBuf {
    local_app_data.join("Programs").join(PRODUCT)
}

/// Whether `exe` sits directly in the setup's install folder under
/// `local_app_data` (compared case-insensitively, as Windows paths are).
pub fn is_installed_at(exe: &Path, local_app_data: &Path) -> bool {
    let dir = install_dir_in(local_app_data);
    exe.parent().is_some_and(|p| {
        p.to_string_lossy()
            .eq_ignore_ascii_case(&dir.to_string_lossy())
    })
}

/// Whether the running executable is a copy installed by the setup
/// (`%LOCALAPPDATA%\Programs\rdpc`), so it can update itself. Portable
/// copies, development builds and every non-Windows build return false.
pub fn is_installed_copy() -> bool {
    #[cfg(windows)]
    {
        let (Ok(exe), Some(local)) = (std::env::current_exe(), std::env::var_os("LOCALAPPDATA"))
        else {
            return false;
        };
        is_installed_at(&exe, Path::new(&local))
    }
    #[cfg(not(windows))]
    false
}

/// Writes the verified `setup` of version `version` into a fresh temporary
/// folder and starts it detached with `/S /UPDATE`. On `Ok` the caller
/// closes rdpc; the setup waits up to 30 s for it to exit, installs and
/// starts rdpc again. `setup` must come from [`download_verified`]; the
/// file on disk is checked against it again right before it runs.
///
/// Refuses unless [`is_installed_copy`] holds. Windows only: elsewhere it
/// returns an error that names the release page.
pub fn launch_setup(setup: &[u8], version: &Version) -> Result<PathBuf, Error> {
    #[cfg(not(windows))]
    {
        let _ = setup;
        Err(err(format!("Download rdpc {version} from {RELEASE_PAGE}")))
    }
    #[cfg(windows)]
    {
        if !is_installed_copy() {
            return Err(err(format!(
                "This copy was not installed by the setup; get rdpc {version} from {RELEASE_PAGE}"
            )));
        }
        // A fresh folder per attempt: never runs a file someone else placed.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rdpc-update-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir)
            .map_err(|e| err(format!("could not create the download folder: {e}")))?;
        let path = dir.join(setup_name(version));
        std::fs::write(&path, setup).map_err(|e| err(format!("could not save the setup: {e}")))?;
        let on_disk = std::fs::read(&path).map_err(|e| err(e.to_string()))?;
        if sha256_hex(&on_disk) != sha256_hex(setup) {
            return Err(err("the saved setup changed on disk, so it was not run"));
        }
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        std::process::Command::new(&path)
            .args(["/S", "/UPDATE"])
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map_err(|e| err(format!("could not start the setup: {e}")))?;
        Ok(path)
    }
}

fn allowed(url: &str) -> bool {
    url.starts_with(API_PREFIX) || url.starts_with(DOWNLOAD_PREFIX)
}

#[cfg(not(windows))]
fn fetch(url: &str, limit: usize) -> Result<Vec<u8>, Error> {
    use std::process::{Command, Stdio};
    if !allowed(url) {
        return Err(err("refusing a URL outside rdp-rs's GitHub releases"));
    }
    let out = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "60",
        ])
        .args([
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-filesize",
            &limit.to_string(),
        ])
        .args([
            "--user-agent",
            concat!("rdpc/", env!("CARGO_PKG_VERSION")),
            url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| err(format!("could not run curl: {e}")))?;
    if !out.status.success() {
        return Err(err(format!("download failed (curl {})", out.status)));
    }
    if out.stdout.len() > limit {
        return Err(err("download exceeds its size limit"));
    }
    Ok(out.stdout)
}

#[cfg(windows)]
fn fetch(url: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if !allowed(url) {
        return Err(err("refusing a URL outside rdp-rs's GitHub releases"));
    }
    winhttp::get(url, limit)
}

#[cfg(windows)]
mod winhttp {
    use super::{Error, err};
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Networking::WinHttp::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Closes a WinHTTP handle when dropped, on every return path.
    struct H(*mut c_void);
    impl Drop for H {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from WinHTTP and is closed once.
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    pub fn get(url: &str, limit: usize) -> Result<Vec<u8>, Error> {
        let agent = wide(concat!("rdpc/", env!("CARGO_PKG_VERSION")));
        let u = wide(url);
        // SAFETY: every pointer passed below points into a live, NUL-terminated
        // buffer owned by this function; handles are wrapped in `H`.
        unsafe {
            let session = H(WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                ptr::null(),
                ptr::null(),
                0,
            ));
            if session.0.is_null() {
                return Err(err("WinHTTP is unavailable"));
            }
            WinHttpSetTimeouts(session.0, 15_000, 15_000, 60_000, 60_000);
            let mut parts: URL_COMPONENTS = std::mem::zeroed();
            parts.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
            parts.dwHostNameLength = u32::MAX;
            parts.dwUrlPathLength = u32::MAX;
            parts.dwExtraInfoLength = u32::MAX;
            if WinHttpCrackUrl(u.as_ptr(), 0, 0, &mut parts) == 0
                || parts.nScheme != WINHTTP_INTERNET_SCHEME_HTTPS
            {
                return Err(err("not an HTTPS URL"));
            }
            let slice = |p: *mut u16, n: u32| {
                String::from_utf16_lossy(std::slice::from_raw_parts(p, n as usize))
            };
            let host = slice(parts.lpszHostName, parts.dwHostNameLength);
            if host != "api.github.com" && host != "github.com" {
                return Err(err("refusing a host other than GitHub"));
            }
            let path = slice(parts.lpszUrlPath, parts.dwUrlPathLength)
                + &slice(parts.lpszExtraInfo, parts.dwExtraInfoLength);
            let hw = wide(&host);
            let conn = H(WinHttpConnect(session.0, hw.as_ptr(), parts.nPort, 0));
            if conn.0.is_null() {
                return Err(err("could not connect to GitHub"));
            }
            let (pw, get) = (wide(&path), wide("GET"));
            let req = H(WinHttpOpenRequest(
                conn.0,
                get.as_ptr(),
                pw.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                WINHTTP_FLAG_SECURE,
            ));
            if req.0.is_null() {
                return Err(err("could not create the request"));
            }
            // Redirects to GitHub's download CDN are followed (HTTPS only).
            let headers = wide("Accept: application/vnd.github+json\r\n");
            if WinHttpSendRequest(req.0, headers.as_ptr(), u32::MAX, ptr::null(), 0, 0, 0) == 0
                || WinHttpReceiveResponse(req.0, ptr::null_mut()) == 0
            {
                return Err(err("the request to GitHub failed (network or proxy)"));
            }
            let mut status: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as u32;
            if WinHttpQueryHeaders(
                req.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                ptr::null(),
                (&mut status as *mut u32).cast(),
                &mut len,
                ptr::null_mut(),
            ) == 0
                || status != 200
            {
                return Err(err(format!("GitHub answered with HTTP {status}")));
            }
            let mut out = Vec::new();
            loop {
                let mut avail = 0u32;
                if WinHttpQueryDataAvailable(req.0, &mut avail) == 0 {
                    return Err(err("the download was interrupted"));
                }
                if avail == 0 {
                    break;
                }
                if out.len().saturating_add(avail as usize) > limit {
                    return Err(err("download exceeds its size limit"));
                }
                let old = out.len();
                out.resize(old + avail as usize, 0);
                let mut read = 0u32;
                if WinHttpReadData(req.0, out[old..].as_mut_ptr().cast(), avail, &mut read) == 0 {
                    return Err(err("the download was interrupted"));
                }
                out.truncate(old + read as usize);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn semver_order() {
        let order = [
            "0.1.0-alpha",
            "0.1.0-beta.2",
            "0.1.0-beta.10",
            "0.1.0-poc",
            "0.1.0-rc.1",
            "0.1.0",
            "0.1.1",
            "1.0.0",
        ];
        for p in order.windows(2) {
            assert!(v(p[0]) < v(p[1]), "{} < {}", p[0], p[1]);
        }
        assert_eq!(v("v0.1.0-beta.12").to_string(), "0.1.0-beta.12");
        for bad in [
            "1.0",
            "01.0.0",
            "1.0.0-01",
            "1.0.0-",
            "1.0.0-a..b",
            "1.0.0.0",
            "x.y.z",
            "",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Channel::for_version(&v("0.1.0-poc")), Channel::Beta);
        assert_eq!(
            Channel::from_setting(Some("stable"), &v("0.1.0-poc")),
            Channel::Stable
        );
    }

    fn release(tag: &str, pre: bool, draft: bool, assets: bool) -> String {
        let ver = tag.trim_start_matches('v');
        let a = if assets {
            format!(
                r#"[{{"name":"rdpc-{ver}-setup.exe","browser_download_url":"{DOWNLOAD_PREFIX}{tag}/rdpc-{ver}-setup.exe"}},{{"name":"SHA256SUMS.txt","browser_download_url":"{DOWNLOAD_PREFIX}{tag}/SHA256SUMS.txt"}}]"#
            )
        } else {
            "[]".into()
        };
        format!(r#"{{"tag_name":"{tag}","prerelease":{pre},"draft":{draft},"assets":{a}}}"#)
    }

    #[test]
    fn channels_pick_the_right_release() {
        let list = format!(
            "[{},{},{},{},{}]",
            release("v0.3.0-beta.1", true, false, true),
            release("v0.2.0", false, false, true),
            release("v0.9.0", false, true, true),
            release("v0.4.0", false, false, false),
            release("not-a-version", false, false, true),
        );
        let cur = v("0.1.0-poc");
        let beta = pick(&cur, Channel::Beta, list.as_bytes()).unwrap().unwrap();
        assert_eq!(beta.version, v("0.3.0-beta.1"));
        let stable = pick(&cur, Channel::Stable, list.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(
            stable.version,
            v("0.2.0"),
            "drafts, prereleases and releases without assets are skipped"
        );
        assert!(
            pick(&v("0.3.0"), Channel::Beta, list.as_bytes())
                .unwrap()
                .is_none(),
            "never a downgrade"
        );
        assert!(pick(&cur, Channel::Beta, b"{oops").is_err());
        let foreign = r#"[{"tag_name":"v1.0.0","prerelease":false,"draft":false,"assets":[{"name":"rdpc-1.0.0-setup.exe","browser_download_url":"https://evil.example/x"},{"name":"SHA256SUMS.txt","browser_download_url":"https://evil.example/y"}]}]"#;
        assert!(
            pick(&cur, Channel::Stable, foreign.as_bytes())
                .unwrap()
                .is_none(),
            "URLs outside rdp-rs's releases are refused"
        );
    }

    #[test]
    fn checksum_file() {
        let h = "a".repeat(64);
        let sums = format!(
            "{h}  rdpc-1.0.0-setup.exe\r\n{}  other.zip\n",
            "b".repeat(64)
        );
        assert_eq!(expected_hash(&sums, "rdpc-1.0.0-setup.exe").unwrap(), h);
        assert!(expected_hash(&sums, "missing.exe").is_err());
        assert!(expected_hash(&format!("{h}  x\n{h}  x\n"), "x").is_err());
        assert!(expected_hash("short  x", "x").is_err());
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Talks to GitHub; run by hand with `cargo test -p rdpc-update -- --ignored`.
    #[test]
    #[ignore]
    fn live_release_list() {
        let r = check(&v("0.0.1"), Channel::Beta);
        assert!(r.is_ok(), "{r:?}");
        assert!(
            fetch("https://example.com/", 10).is_err(),
            "foreign hosts are refused"
        );
    }

    #[test]
    fn only_this_repositorys_release_urls_are_fetched() {
        assert!(allowed(API_URL));
        assert!(allowed(&format!("{DOWNLOAD_PREFIX}v1.0.0/{SUMS}")));
        for bad in [
            "https://api.github.com/repos/rennerdo30/ffwd/releases",
            "https://api.github.com/repos/rennerdo30/rdp-rs-evil/releases",
            "https://github.com/rennerdo30/rdp-rs/archive/main.zip",
            "http://github.com/rennerdo30/rdp-rs/releases/download/v1.0.0/x",
            "https://example.com/",
        ] {
            assert!(!allowed(bad), "{bad}");
            assert!(
                fetch(bad, 10).is_err(),
                "{bad} must be refused before any network access"
            );
        }
        assert_eq!(
            setup_name(&v("0.2.0-beta.1")),
            "rdpc-0.2.0-beta.1-setup.exe"
        );
        assert_eq!(current_version().unwrap(), v(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn installed_copy_is_the_setup_folder() {
        let local = Path::new(r"C:\Users\u\AppData\Local");
        let dir = local.join("Programs").join("rdpc");
        assert!(is_installed_at(&dir.join("rdpc.exe"), local));
        let upper = PathBuf::from(dir.to_string_lossy().to_uppercase()).join("rdpc.exe");
        assert!(
            is_installed_at(&upper, local),
            "Windows paths compare case-insensitively"
        );
        assert!(!is_installed_at(&dir.join("sub").join("rdpc.exe"), local));
        assert!(!is_installed_at(
            &local.join("Programs").join("ffwd").join("rdpc.exe"),
            local
        ));
        assert!(!is_installed_at(Path::new(r"C:\tools\rdpc.exe"), local));
    }

    #[test]
    fn daily_stamp() {
        let dir = std::env::temp_dir().join(format!("rdpc-update-test-{}", std::process::id()));
        let stamp = dir.join("update-check");
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(due(&stamp, t0));
        write_stamp(&stamp, t0).unwrap();
        assert!(!due(&stamp, t0 + Duration::from_secs(3600)));
        assert!(due(&stamp, t0 + Duration::from_secs(25 * 3600)));
        assert!(
            due(&stamp, t0 - Duration::from_secs(10)),
            "a stamp from the future does not block checks"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
