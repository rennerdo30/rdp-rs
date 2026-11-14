//! The Windows side: transport, session events, the local pipe, start-up
//! integration (task, Send To), the key's DPAPI protection, the pairing
//! dialog, the transfer folders and the event loop.

mod agent;
mod apply;
mod dpapi;
mod files;
mod pipe;
mod shortcut;
mod sys;
mod ui;
mod window;
mod wts;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    SetStdHandle,
};

use crate::cli::{self, Command};
use crate::logging::{self, Logger, MAX_LOG_BYTES};

/// A kernel handle closed on drop. Shared between threads only for
/// thread-safe operations (overlapped IO, `CancelIoEx`).
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

// SAFETY: kernel handles are process-wide; the IO done on them from several
// threads is overlapped with per-thread OVERLAPPED structures and events.
unsafe impl Send for OwnedHandle {}
// SAFETY: see above.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// NUL-terminated UTF-16.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: caller guarantees termination.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// A GUI-subsystem program has no console. For commands that print, attach
/// to the console of the shell that started us (if any); output redirected
/// to a file or pipe already has valid handles and is left alone.
fn attach_parent_console() {
    // SAFETY: plain console calls; the CONOUT$ handle lives for the process.
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        if !out.is_null() && out != INVALID_HANDLE_VALUE {
            return;
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        if out.is_null() || out == INVALID_HANDLE_VALUE {
            let name = wide("CONOUT$");
            let h = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if h != INVALID_HANDLE_VALUE {
                SetStdHandle(STD_OUTPUT_HANDLE, h);
                SetStdHandle(STD_ERROR_HANDLE, h);
            }
        }
    }
}

fn open_log(tag: &'static str) {
    if let Some(path) = logging::default_log_path() {
        logging::install(Logger::open(&path, MAX_LOG_BYTES, tag));
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            attach_parent_console();
            eprintln!("remora-agent: {e}\n\n{}", cli::USAGE);
            return 2;
        }
    };
    match cmd {
        Command::Run => {
            open_log("run");
            agent::run()
        }
        Command::OpenUrl(url) => {
            open_log("open-url");
            apply::open_url(&url)
        }
        // Started by Explorer (Send To): no console; problems go to a
        // message box and the log.
        Command::Send(files) => {
            open_log("send");
            apply::send_files(&files)
        }
        other => {
            attach_parent_console();
            match other {
                Command::Version => {
                    println!("remora-agent {}", env!("CARGO_PKG_VERSION"));
                    0
                }
                Command::Help => {
                    println!("{}", cli::USAGE);
                    0
                }
                Command::Install { dry_run } => apply::install(dry_run),
                Command::Uninstall { dry_run } => apply::uninstall(dry_run),
                Command::Status => apply::status(),
                Command::PrintTaskXml => apply::print_task_xml(),
                Command::RegisterLinks { dry_run } => apply::register_links(dry_run),
                Command::UnregisterLinks { dry_run } => apply::unregister_links(dry_run),
                Command::SessionInfo => apply::print_session_info(),
                Command::Fingerprint => print_fingerprint(),
                Command::Clients => clients_command(crate::clients::list),
                Command::ForgetClient(fp) => {
                    clients_command(|p| crate::clients::forget(p, &fp).map(|s| s + "\n"))
                }
                Command::TrustClient(fp) => clients_command(|p| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    crate::clients::trust(p, &fp, now).map(|s| s + "\n")
                }),
                Command::Strict(set) => {
                    let Some(setting) = crate::keystore::default_strict_path() else {
                        eprintln!("remora-agent: LOCALAPPDATA is not set");
                        return 1;
                    };
                    let policy = sys::pinned_clients_policy();
                    clients_command(|p| match set {
                        Some(on) => crate::clients::set_strict(on, &setting, policy, Some(p)),
                        None => Ok(crate::clients::strict_status(&setting, policy, Some(p))),
                    })
                }
                Command::Run | Command::OpenUrl(_) | Command::Send(_) => unreachable!(),
            }
        }
    }
}

/// `remora-agent fingerprint`: the helper key's fingerprint (the key is
/// made now if the agent never ran, exactly as `run` would).
fn print_fingerprint() -> i32 {
    let Some(path) = crate::keystore::default_key_path() else {
        eprintln!("remora-agent: LOCALAPPDATA is not set");
        return 1;
    };
    let generate =
        || remora_link::StaticKey::generate().map_err(|e| std::io::Error::other(e.to_string()));
    match crate::keystore::load_or_create(&path, &dpapi::Dpapi, &generate) {
        Ok(k) if k.save_error.is_none() => {
            println!("{}", remora_link::fingerprint(&k.key.public()));
            0
        }
        Ok(k) => {
            eprintln!(
                "remora-agent: the key could not be saved ({}); no lasting fingerprint",
                k.save_error.unwrap_or_default()
            );
            1
        }
        Err(e) => {
            eprintln!("remora-agent: {e}");
            1
        }
    }
}

/// Runs a client-list command on `agent-clients.json` and prints its text.
fn clients_command(f: impl FnOnce(&std::path::Path) -> Result<String, String>) -> i32 {
    let Some(path) = crate::keystore::default_clients_path() else {
        eprintln!("remora-agent: LOCALAPPDATA is not set");
        return 1;
    };
    match f(&path) {
        Ok(text) => {
            print!("{text}");
            0
        }
        Err(e) => {
            eprintln!("remora-agent: {e}");
            1
        }
    }
}
