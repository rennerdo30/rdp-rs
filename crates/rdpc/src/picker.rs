//! The Windows folder picker for shared folders (rfd: the system's own
//! IFileOpenDialog in folder mode).
//!
//! The first file dialog in a process loads the shell's COM components,
//! which takes seconds. So one long-lived picker thread joins a COM
//! apartment and creates (and drops) a dialog object at start-up, off the UI
//! thread; later pickers open on that warmed thread at once. Each picker is
//! owned by the main window, which keeps painting while it is open.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};

type Done = Box<dyn FnOnce(Option<PathBuf>) + Send>;

struct Request {
    owner: isize,
    done: Done,
}

static PICKER: Mutex<Option<Sender<Request>>> = Mutex::new(None);

/// Starts the picker thread and warms the shell's dialog components.
pub fn prewarm() {
    let mut slot = PICKER.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_some() {
        return;
    }
    let (tx, rx) = channel::<Request>();
    let spawned = std::thread::Builder::new()
        .name("folder-picker".into())
        .spawn(move || {
            #[cfg(windows)]
            warm();
            for req in rx {
                (req.done)(pick(req.owner));
            }
        });
    if spawned.is_ok() {
        *slot = Some(tx);
    }
}

/// Opens the folder picker over `owner` (an HWND) and calls `done` with the
/// chosen folder, or None when it was cancelled.
pub fn pick_folder(owner: isize, done: impl FnOnce(Option<PathBuf>) + Send + 'static) {
    prewarm();
    let slot = PICKER.lock().unwrap_or_else(|p| p.into_inner());
    let req = Request {
        owner,
        done: Box::new(done),
    };
    if let Some(tx) = slot.as_ref()
        && let Err(e) = tx.send(req)
    {
        (e.0.done)(None);
    }
}

fn pick(owner: isize) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let mut dialog = rfd::FileDialog::new().set_title("Share a folder");
        if let Some(parent) = Owner::new(owner) {
            dialog = dialog.set_parent(&parent);
        }
        dialog.pick_folder()
    }
    #[cfg(not(windows))]
    {
        let _ = owner;
        None
    }
}

/// Joins a single-threaded COM apartment for this thread's lifetime and
/// creates one file dialog object, which loads the shell components.
#[cfg(windows)]
fn warm() {
    use windows_sys::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    };
    use windows_sys::Win32::UI::Shell::FileOpenDialog;
    use windows_sys::core::GUID;
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
    // SAFETY: COM initialisation for this thread (kept: the thread lives as
    // long as the process). CoCreateInstance writes an IUnknown pointer,
    // released through its vtable (slot 2, Release).
    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
        let mut obj: *mut core::ffi::c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &FileOpenDialog,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IUNKNOWN,
            &mut obj,
        );
        if hr >= 0 && !obj.is_null() {
            type Release = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
            let vtable = *(obj as *const *const Release);
            (*vtable.add(2))(obj);
        }
    }
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
