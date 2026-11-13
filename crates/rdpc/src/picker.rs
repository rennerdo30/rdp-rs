//! The Windows folder picker for shared folders (rfd: the system's own
//! IFileOpenDialog in folder mode). It runs on its own thread, owned by the
//! main window, so the window keeps painting while it is open.

use std::path::PathBuf;

/// Opens the folder picker over `owner` (an HWND) and calls `done` with the
/// chosen folder, or None when it was cancelled.
pub fn pick_folder(owner: isize, done: impl FnOnce(Option<PathBuf>) + Send + 'static) {
    std::thread::spawn(move || {
        #[cfg(windows)]
        let picked = {
            let mut dialog = rfd::FileDialog::new().set_title("Share a folder");
            if let Some(parent) = Owner::new(owner) {
                dialog = dialog.set_parent(&parent);
            }
            dialog.pick_folder()
        };
        #[cfg(not(windows))]
        let picked = {
            let _ = owner;
            None
        };
        done(picked);
    });
}

/// The main window as the dialog's owner.
#[cfg(windows)]
struct Owner(std::num::NonZeroIsize);

#[cfg(windows)]
impl Owner {
    fn new(hwnd: isize) -> Option<Owner> {
        std::num::NonZeroIsize::new(hwnd).map(Owner)
    }
}

#[cfg(windows)]
impl winit::raw_window_handle::HasWindowHandle for Owner {
    fn window_handle(
        &self,
    ) -> Result<winit::raw_window_handle::WindowHandle<'_>, winit::raw_window_handle::HandleError>
    {
        let raw = winit::raw_window_handle::Win32WindowHandle::new(self.0);
        // SAFETY: the main window outlives the dialog (the dialog is modal to it).
        Ok(unsafe { winit::raw_window_handle::WindowHandle::borrow_raw(raw.into()) })
    }
}

#[cfg(windows)]
impl winit::raw_window_handle::HasDisplayHandle for Owner {
    fn display_handle(
        &self,
    ) -> Result<winit::raw_window_handle::DisplayHandle<'_>, winit::raw_window_handle::HandleError>
    {
        Ok(winit::raw_window_handle::DisplayHandle::windows())
    }
}
