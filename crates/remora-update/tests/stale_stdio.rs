//! RDP-50: a Remora started by the setup has stale standard handle values;
//! starting the next setup with inherited stdio then failed with
//! ERROR_NOT_SUPPORTED (os error 50). Its own test binary, because it
//! changes this process's standard output handle.

#![cfg(windows)]

use std::ffi::c_void;
use std::path::PathBuf;

type Handle = *mut c_void;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const DUPLICATE_SAME_ACCESS: u32 = 2;
const ERROR_NOT_SUPPORTED: i32 = 50;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(which: u32) -> Handle;
    fn SetStdHandle(which: u32, h: Handle) -> i32;
    fn GetCurrentProcess() -> Handle;
    fn DuplicateHandle(
        src_proc: Handle,
        src: Handle,
        dst_proc: Handle,
        dst: *mut Handle,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn CloseHandle(h: Handle) -> i32;
    fn GetLastError() -> u32;
}

/// A handle value in this process that DuplicateHandle refuses with
/// ERROR_NOT_SUPPORTED (ETW registrations and the like): what a stale
/// standard handle value can name.
fn undup_handle() -> Option<Handle> {
    (4..0x4000usize).step_by(4).find_map(|v| {
        let h = v as Handle;
        let mut out: Handle = std::ptr::null_mut();
        // SAFETY: duplicating within this process; the copy is closed.
        unsafe {
            let me = GetCurrentProcess();
            if DuplicateHandle(me, h, me, &mut out, 0, 1, DUPLICATE_SAME_ACCESS) != 0 {
                CloseHandle(out);
                None
            } else {
                (GetLastError() as i32 == ERROR_NOT_SUPPORTED).then_some(h)
            }
        }
    })
}

fn whoami() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join("whoami.exe")
}

#[test]
fn a_stale_standard_handle_does_not_stop_the_setup_from_starting() {
    let Some(stale) = undup_handle() else {
        eprintln!("no non-duplicable handle in this process; nothing to show");
        return;
    };
    // SAFETY: swaps this test process's stdout handle and restores it.
    let old = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    unsafe { SetStdHandle(STD_OUTPUT_HANDLE, stale) };
    // The failure the updater hit: inherited stdio duplicates the handle.
    let inherited = std::process::Command::new(whoami()).spawn();
    // The fix: no inherited stdio.
    let detached = remora_update::spawn_detached(&whoami(), &[]);
    unsafe { SetStdHandle(STD_OUTPUT_HANDLE, old) };
    match inherited {
        Err(e) => assert_eq!(e.raw_os_error(), Some(ERROR_NOT_SUPPORTED), "{e}"),
        Ok(mut c) => {
            let _ = c.wait();
            panic!("inherited stdio started despite the stale handle");
        }
    }
    let mut child = detached.expect("starts without inherited stdio");
    assert!(child.wait().expect("waits").success());
}
