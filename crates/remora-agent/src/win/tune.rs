//! The server's graphics settings (RDP-59): read here without admin, and
//! changed by `remora-agent tune apply|restore`, which the running helper
//! starts elevated (`runas`) when Remora asks. Windows then shows its
//! administrator prompt in the session, and the user there decides.
//!
//! Only these three values are ever written or deleted; the elevated
//! process takes no other input.

use std::io;

use remora_link::msg::{ServerSettings, TuneAction, TuneStatus};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GetLastError, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use super::{sys, wide};
use crate::{info, warn};

/// Where Windows reads the remote session frame-rate cap.
pub const WINSTATIONS: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations";
/// The Remote Desktop Services policies (TerminalServer.admx).
pub const TS_POLICIES: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

/// (key, value name, recommended value).
fn values() -> [(&'static str, &'static str, u32); 3] {
    let r = ServerSettings::RECOMMENDED;
    [
        (
            WINSTATIONS,
            "DWMFRAMEINTERVAL",
            r.frame_interval.unwrap_or_default(),
        ),
        (
            TS_POLICIES,
            "AVC444ModePreferred",
            r.avc444.unwrap_or_default(),
        ),
        (
            TS_POLICIES,
            "AVCHardwareEncodePreferred",
            r.avc_hw.unwrap_or_default(),
        ),
    ]
}

/// The settings as they are now (no admin needed).
pub fn read() -> ServerSettings {
    let get = |key, name| sys::reg_dword(HKEY_LOCAL_MACHINE, key, name);
    ServerSettings {
        frame_interval: get(WINSTATIONS, "DWMFRAMEINTERVAL"),
        avc444: get(TS_POLICIES, "AVC444ModePreferred"),
        avc_hw: get(TS_POLICIES, "AVCHardwareEncodePreferred"),
    }
}

/// `remora-agent tune apply|restore`, run elevated: writes (or deletes)
/// the three values. Exit code 0 on success.
pub fn write(action: TuneAction) -> io::Result<()> {
    for (key, name, value) in values() {
        let (k, n) = (wide(key), wide(name));
        // SAFETY: NUL-terminated key and value names; a DWORD of 4 bytes.
        let r = unsafe {
            match action {
                TuneAction::Apply => RegSetKeyValueW(
                    HKEY_LOCAL_MACHINE,
                    k.as_ptr(),
                    n.as_ptr(),
                    REG_DWORD,
                    (&raw const value).cast(),
                    4,
                ),
                TuneAction::Restore => {
                    RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), n.as_ptr())
                }
            }
        };
        let gone = action == TuneAction::Restore && r == ERROR_FILE_NOT_FOUND;
        if r != ERROR_SUCCESS && !gone {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
    }
    Ok(())
}

/// Starts `remora-agent tune <action>` elevated and waits for it (up to
/// ten minutes for the user to answer the prompt and the write to finish).
/// Blocks: call it on a thread of its own.
pub fn run_elevated(action: TuneAction) -> TuneStatus {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!("tune: no path to this program: {e}");
            return TuneStatus::Failed;
        }
    };
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(match action {
        TuneAction::Apply => "tune apply",
        TuneAction::Restore => "tune restore",
    });
    // SAFETY: a zeroed SHELLEXECUTEINFOW with its size and the strings
    // above, which outlive the call.
    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.nShow = SW_HIDE;
    info!("tune {action:?}: asking for administrator rights");
    // SAFETY: see above; the process handle is closed below.
    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        let e = unsafe { GetLastError() };
        return if e == ERROR_CANCELLED {
            info!("tune: the administrator prompt was declined");
            TuneStatus::Declined
        } else {
            warn!("tune: could not start elevated ({e})");
            TuneStatus::Failed
        };
    }
    if sei.hProcess.is_null() {
        return TuneStatus::Failed;
    }
    // SAFETY: the process handle from ShellExecuteExW, closed once.
    let status = unsafe {
        let mut code = 1u32;
        let ok = WaitForSingleObject(sei.hProcess, 10 * 60 * 1000) == WAIT_OBJECT_0
            && GetExitCodeProcess(sei.hProcess, &mut code) != 0
            && code == 0;
        CloseHandle(sei.hProcess);
        if ok {
            TuneStatus::Done
        } else {
            warn!("tune: the elevated process failed (exit code {code})");
            TuneStatus::Failed
        }
    };
    if status == TuneStatus::Done {
        info!("tune {action:?}: done");
    }
    status
}
