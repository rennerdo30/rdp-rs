//! What the app does for the server helper on this PC (RDP-42/43/44): the
//! capabilities a connection allows, the download folder, the hooks the
//! helper adapter calls (free space, Mark-of-the-Web) and opening a link.
//!
//! Nothing here trusts the helper: links are checked again right before
//! they open, and received files only ever go into the connection's folder.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use remora_link::msg::TransferId;
use remora_link::{PinStore, cap};

use crate::store::HelperOptions;

/// The capability bits a connection's settings allow (`HelloAck` offers no
/// more). Session info is always allowed once a helper paired.
pub fn capabilities(o: &HelperOptions) -> u32 {
    let mut bits = cap::SESSION_INFO;
    if o.open_links {
        bits |= cap::OPEN_URL;
    }
    if o.send_files {
        bits |= cap::FILE_UP;
    }
    if o.receive_files {
        bits |= cap::FILE_DOWN;
    }
    bits
}

/// `%USERPROFILE%\Downloads\Remora`.
pub fn default_download_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("Downloads").join("Remora")
}

/// Where a connection's received files go.
pub fn download_dir(o: &HelperOptions) -> PathBuf {
    match o.download_dir.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => default_download_dir(),
    }
}

/// A folder as the user reads it: below the user's profile without it
/// (`Downloads\Remora`), otherwise as it is.
pub fn short_dir(dir: &Path) -> String {
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from)
        && let Ok(rest) = dir.strip_prefix(&home)
        && !rest.as_os_str().is_empty()
    {
        return rest.display().to_string();
    }
    dir.display().to_string()
}

/// The Mark-of-the-Web written next to a received file: the Internet zone
/// (3), no referrer or host URL (the helper's word is not evidence).
pub const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";

/// Marks `file` as coming from the Internet (`file:Zone.Identifier`), so
/// SmartScreen and Office's Protected View treat it like a download.
pub fn mark_of_the_web(file: &Path) -> std::io::Result<()> {
    let mut ads = file.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    std::fs::write(PathBuf::from(ads), ZONE_IDENTIFIER)
}

/// Whether the volume of `dir` keeps named streams (where the
/// Mark-of-the-Web lives): NTFS and ReFS do, FAT and exFAT do not. None
/// when the volume cannot be asked.
pub fn named_streams(dir: &Path) -> Option<bool> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
        /// `FILE_NAMED_STREAMS`, a `GetVolumeInformationW` flag.
        const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
        let wide: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        let mut root = [0u16; 1024];
        // SAFETY: a NUL-terminated path and an output buffer of its size.
        if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return None;
        }
        let mut flags = 0u32;
        // SAFETY: `root` is NUL-terminated by the call above; the optional
        // buffers are null with size 0.
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut flags,
                std::ptr::null_mut(),
                0,
            )
        };
        (ok != 0).then_some(flags & FILE_NAMED_STREAMS != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        None
    }
}

/// The receive-folder check: a volume that cannot keep the Mark-of-the-Web
/// is refused before a transfer writes anything there. When the volume
/// cannot be asked the transfer goes ahead and the mark itself decides (a
/// file that cannot be marked is not stored).
pub fn check_marks(dir: &Path) -> std::io::Result<()> {
    match named_streams(dir) {
        Some(false) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            remora_link::transfer::NO_MARK,
        )),
        _ => Ok(()),
    }
}

/// Bytes still to come for every accepted download, by transfer, with the
/// folder it goes to: a new download must fit next to all of them, not
/// just into today's free space.
static RESERVED: Mutex<Vec<(TransferId, PathBuf, u64)>> = Mutex::new(Vec::new());

fn reserved() -> std::sync::MutexGuard<'static, Vec<(TransferId, PathBuf, u64)>> {
    RESERVED.lock().unwrap_or_else(|p| p.into_inner())
}

/// A download into `dir` was accepted, or progressed: `left` bytes to come.
pub fn reserve(id: TransferId, dir: &Path, left: u64) {
    let mut r = reserved();
    match r.iter_mut().find(|e| e.0 == id) {
        Some(e) => e.2 = left,
        None => r.push((id, dir.to_path_buf(), left)),
    }
}

/// The download finished, failed or was cancelled.
pub fn release(id: TransferId) {
    reserved().retain(|e| e.0 != id);
}

/// The volume part of a path (`C:`, `\\server\share`).
fn volume(p: &Path) -> Option<std::path::Component<'_>> {
    p.components().next()
}

/// The free-space hook for download `id`: what is free on the volume of
/// `dir` minus what the *other* downloads accepted onto that volume still
/// need (its own reservation is what it checks against, not a debt).
pub fn free_for_downloads(dir: &Path, id: TransferId) -> Option<u64> {
    Some(net_free(free_space(dir)?, dir, id))
}

/// `free` minus what downloads other than `id` onto `dir`'s volume need.
fn net_free(free: u64, dir: &Path, id: TransferId) -> u64 {
    free.saturating_sub(held_on(dir, Some(id)))
}

/// Bytes the accepted downloads onto `dir`'s volume still need, without
/// `except`.
fn held_on(dir: &Path, except: Option<TransferId>) -> u64 {
    reserved()
        .iter()
        .filter(|e| volume(&e.1) == volume(dir) && Some(e.0) != except)
        .map(|e| e.2)
        .sum()
}

/// Free bytes for the current user on the volume of `dir`.
pub fn free_space(dir: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        let mut free = 0u64;
        // SAFETY: a NUL-terminated path; the other out-pointers may be null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        None
    }
}

/// The host a link goes to, as shown in its confirmation: ASCII, an
/// international name in its punycode form (`xn--…`), so look-alike
/// letters cannot pass for another site.
pub fn link_host(url: &str) -> Option<String> {
    crate::helper::web_url(url).and_then(|u| u.host_str().map(str::to_string))
}

/// Opens an http or https link in this PC's default browser. The link is
/// parsed and checked again here, whatever was checked before, and only
/// its WHATWG serialization goes to the shell as the file to open (no
/// command line is built).
pub fn open_web_url(url: &str) -> Result<(), String> {
    let Some(u) = crate::helper::web_url(url) else {
        return Err("not a web link".into());
    };
    if !matches!(u.scheme(), "http" | "https") {
        return Err("not a web link".into());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::{
            SEE_MASK_FLAG_NO_UI, SHELLEXECUTEINFOW, ShellExecuteExW,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            AllowSetForegroundWindow, SW_SHOWNORMAL,
        };
        let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
        let (verb, target) = (wide("open"), wide(u.as_str()));
        // SAFETY: a zeroed SHELLEXECUTEINFOW with its size, verb and file
        // set; the strings are NUL-terminated and outlive the call.
        let ok = unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_FLAG_NO_UI;
            info.lpVerb = verb.as_ptr();
            info.lpFile = target.as_ptr();
            info.nShow = SW_SHOWNORMAL;
            // The browser may bring its window to the front.
            AllowSetForegroundWindow(u32::MAX);
            ShellExecuteExW(&mut info)
        };
        if ok == 0 {
            return Err(format!(
                "the browser did not start ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("opening links needs Windows".into())
    }
}

/// The pin store of the helpers (`helpers.json` next to the connections).
pub fn pins_path() -> Option<PathBuf> {
    crate::store::data_dir().map(|d| d.join("helpers.json"))
}

/// The log of pairings that ended unanswered (`helper-attempts.json`).
pub fn attempts_path() -> Option<PathBuf> {
    crate::store::data_dir().map(|d| d.join("helper-attempts.json"))
}

/// The helper fingerprint an admin set for a connection. One that does not
/// parse matches no key (fail closed: the helper is refused, never paired
/// by code instead).
pub fn expected_fingerprint(o: &HelperOptions) -> Option<[u8; remora_link::FINGERPRINT_LEN]> {
    let text = o
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    Some(remora_link::parse_fingerprint(text).unwrap_or([0; remora_link::FINGERPRINT_LEN]))
}

/// Servers with a paired helper (`host:port`, lower case), for any user.
pub fn pinned_servers() -> HashSet<String> {
    pins_path()
        .and_then(|p| PinStore::load(&p).ok())
        .map(|s| s.servers().into_iter().collect())
        .unwrap_or_default()
}

/// Forgets the helpers pinned for `server` (`host:port`, every user) in the
/// store at `path`: their next session asks to pair again. False when none
/// was pinned. Merged with other windows' changes under the store's lock.
pub fn forget_pin(path: &Path, server: &str) -> Result<bool, String> {
    PinStore::update(path, |s| s.forget_server(server) > 0).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "remora-helper-app-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn capabilities_follow_the_switches_and_default_to_session_info() {
        assert_eq!(capabilities(&HelperOptions::default()), cap::SESSION_INFO);
        let all = HelperOptions {
            open_links: true,
            receive_files: true,
            send_files: true,
            ..Default::default()
        };
        assert_eq!(capabilities(&all), cap::ALL);
        let down = HelperOptions {
            receive_files: true,
            ..Default::default()
        };
        assert_eq!(capabilities(&down), cap::SESSION_INFO | cap::FILE_DOWN);
    }

    #[test]
    fn download_dir_defaults_to_downloads_remora() {
        let d = download_dir(&HelperOptions::default());
        assert!(d.ends_with(Path::new("Downloads").join("Remora")), "{d:?}");
        let own = HelperOptions {
            download_dir: Some(r"D:\Inbox".into()),
            ..Default::default()
        };
        assert_eq!(download_dir(&own), PathBuf::from(r"D:\Inbox"));
        let blank = HelperOptions {
            download_dir: Some("  ".into()),
            ..Default::default()
        };
        assert_eq!(download_dir(&blank), default_download_dir());
    }

    #[test]
    fn links_are_checked_again_before_the_shell_sees_them() {
        for bad in [
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "ms-settings:",
            r"\\server\share\x.exe",
            "https://",
            "https://a b",
            "C:\\x.exe",
        ] {
            assert!(open_web_url(bad).is_err(), "{bad}");
        }
    }

    /// The Zone.Identifier stream lands on the file (NTFS) and says
    /// Internet zone, nothing else.
    #[test]
    #[cfg(windows)]
    fn mark_of_the_web_writes_the_internet_zone() {
        let d = temp_dir("motw");
        let f = d.join("report.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        match mark_of_the_web(&f) {
            Ok(()) => {
                let mut ads = f.as_os_str().to_owned();
                ads.push(":Zone.Identifier");
                let text = std::fs::read_to_string(PathBuf::from(ads)).unwrap();
                assert_eq!(text, ZONE_IDENTIFIER);
                assert!(text.contains("ZoneId=3") && !text.contains("Url"));
                // The file itself is unchanged.
                assert_eq!(std::fs::read(&f).unwrap(), b"%PDF");
            }
            // A temp folder on a volume without streams (FAT): nothing to check.
            Err(e) => eprintln!("no alternate data streams here: {e}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    #[cfg(windows)]
    fn downloads_reserve_space_on_their_volume() {
        let (a, b) = ([0xA1; 16], [0xB2; 16]);
        let q = Path::new(r"Q:\Other");
        let base = held_on(q, None);
        reserve(a, Path::new(r"Q:\In"), 100);
        reserve(b, Path::new(r"R:\In"), 50);
        assert_eq!(held_on(q, None), base + 100, "only the same volume counts");
        reserve(a, Path::new(r"Q:\In"), 40);
        assert_eq!(held_on(q, None), base + 40, "progress lowers it");
        release(a);
        release(b);
        assert_eq!(held_on(q, None), base);
    }

    /// Review 2 item 6: a download's own reservation is not counted
    /// against it (its check ran after the app reserved its size), only
    /// the others' on the same volume.
    #[test]
    #[cfg(windows)]
    fn a_download_is_not_charged_its_own_reservation() {
        let (a, b) = ([0xC3; 16], [0xD4; 16]);
        let v = Path::new(r"P:\In");
        let base = held_on(v, None);
        reserve(a, v, 700);
        assert_eq!(net_free(base + 1000, v, a), 1000, "own size not held");
        reserve(b, v, 200);
        assert_eq!(net_free(base + 1000, v, a), 800, "the other one is");
        assert_eq!(net_free(base + 1000, v, b), 300);
        release(a);
        release(b);
    }

    #[test]
    #[cfg(windows)]
    fn the_temp_volume_keeps_named_streams() {
        let d = temp_dir("streams");
        assert_eq!(named_streams(&d), Some(true));
        assert!(check_marks(&d).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn forget_removes_only_that_server() {
        let d = temp_dir("forget");
        let p = d.join("helpers.json");
        let mut s = PinStore::new();
        s.pin("a:3389", &[1; 32], 1);
        s.pin("alice@a:3389", &[3; 32], 1);
        s.pin("b:3389", &[2; 32], 1);
        s.save(&p).unwrap();
        assert_eq!(forget_pin(&p, "a:3389"), Ok(true));
        assert_eq!(forget_pin(&p, "a:3389"), Ok(false));
        let back = PinStore::load(&p).unwrap();
        assert!(back.get("a:3389").is_none() && back.get("b:3389").is_some());
        assert!(
            back.get("alice@a:3389").is_none(),
            "every user of the server"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
