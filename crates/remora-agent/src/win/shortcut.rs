//! The Send To shortcut: written with the shell's own `IShellLinkW` and
//! saved through `IPersistFile`, so Explorer reads it like any other.
//! Only `install` and `uninstall` (not their `--dry-run`) call this.

use std::io;

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize, IPersistFile,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::core::{HSTRING, Interface};

use crate::files::Shortcut;

fn com_err(e: windows::core::Error) -> io::Error {
    io::Error::other(format!("{e}"))
}

/// Creates (or replaces) the shortcut.
pub fn create(s: &Shortcut) -> io::Result<()> {
    if let Some(dir) = s.path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // SAFETY: COM on this thread, balanced below; interfaces are released
    // when they drop, before CoUninitialize.
    unsafe {
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let r = (|| -> windows::core::Result<()> {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&HSTRING::from(s.target.as_str()))?;
            link.SetArguments(&HSTRING::from(s.arguments.as_str()))?;
            link.SetDescription(&HSTRING::from(s.description.as_str()))?;
            link.SetIconLocation(&HSTRING::from(s.icon.as_str()), 0)?;
            let file: IPersistFile = link.cast()?;
            file.Save(&HSTRING::from(s.path.as_os_str()), true)
        })();
        if init.is_ok() {
            CoUninitialize();
        }
        r.map_err(com_err)
    }
}

/// Removes the shortcut; a missing one is fine.
pub fn remove(s: &Shortcut) -> io::Result<()> {
    match std::fs::remove_file(&s.path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}
