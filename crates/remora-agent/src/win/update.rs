//! The helper replaces itself (RDP-61): Remora sent a newer
//! `remora-agent.exe` (checked by `remora_link::update::Receiver`). The
//! running exe is renamed to `.old` (Windows allows renaming a running
//! image), the new one takes its name, and a new process starts with
//! `run --replace <pid>`: it waits until this one has exited, then runs.
//! The scheduled task keeps pointing at the same path.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{info, warn};

fn with_suffix(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Writes `new` in place of the running exe and starts it. On any failure
/// the old exe is back in place.
pub fn replace_and_restart(new: &[u8]) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    swap(&exe, new)?;
    let undo = |e: io::Error| {
        unswap(&exe);
        e
    };
    let pid = std::process::id().to_string();
    // Null stdio: a GUI process's inherited handles may be stale (RDP-50).
    std::process::Command::new(&exe)
        .args(["run", "--replace", &pid])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(undo)?;
    info!("update installed; the new helper starts once this one has exited");
    Ok(())
}

/// Puts `new` at `exe` (which may be running) and keeps the old one as
/// `exe.old`; on failure everything is as before.
fn swap(exe: &Path, new: &[u8]) -> io::Result<()> {
    let staged = with_suffix(exe, ".new");
    let old = with_suffix(exe, ".old");
    std::fs::write(&staged, new)?;
    // A leftover from an earlier update (gone at the last start, normally).
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(exe, &old) {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&staged, exe) {
        unswap(exe);
        return Err(e);
    }
    Ok(())
}

/// Undoes [`swap`]: the old exe back in place.
fn unswap(exe: &Path) {
    let _ = std::fs::remove_file(exe);
    let _ = std::fs::rename(with_suffix(exe, ".old"), exe);
    let _ = std::fs::remove_file(with_suffix(exe, ".new"));
}

/// `run --replace <pid>`: waits (up to 30 s) for the helper being replaced
/// to exit, so its single-instance lock is free.
pub fn wait_for(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: a handle we open and close; waiting has no other effect.
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() {
            return; // already gone
        }
        WaitForSingleObject(h, Duration::from_secs(30).as_millis() as u32);
        CloseHandle(h);
    }
}

/// At start: the exe an update replaced, if one is left over.
pub fn clean_up() {
    if let Ok(exe) = std::env::current_exe() {
        let old = with_suffix(&exe, ".old");
        if old.exists() {
            match std::fs::remove_file(&old) {
                Ok(()) => info!("removed the replaced helper"),
                Err(e) => warn!("cannot remove the replaced helper yet: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows lets a running image be renamed: the swap works while the
    /// exe runs, and undoing it puts the old one back.
    #[test]
    fn a_running_exe_is_swapped() {
        let dir = std::env::temp_dir().join(format!("remora-agent-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("a.exe");
        let sys =
            std::env::var_os("SystemRoot").map_or(PathBuf::from(r"C:\Windows"), PathBuf::from);
        std::fs::copy(sys.join(r"System32\PING.EXE"), &exe).unwrap();
        let original = std::fs::read(&exe).unwrap();
        // Our own child, ended below (only this PID).
        let mut child = std::process::Command::new(&exe)
            .args(["-n", "6", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        swap(&exe, b"new helper").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new helper");
        assert_eq!(std::fs::read(with_suffix(&exe, ".old")).unwrap(), original);
        unswap(&exe);
        assert_eq!(std::fs::read(&exe).unwrap(), original);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suffixes_keep_the_full_name() {
        let p = Path::new(r"C:\x\remora-agent.exe");
        assert_eq!(
            with_suffix(p, ".old"),
            PathBuf::from(r"C:\x\remora-agent.exe.old")
        );
    }
}
