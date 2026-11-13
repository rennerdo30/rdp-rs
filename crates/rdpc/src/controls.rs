//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::{ClipboardHandle, DisplayHandle, Drdynvc, StaticChannel};

use crate::clipboard::WindowsClipboard;

pub struct Controls {
    display: DisplayHandle,
    clipboard: ClipboardHandle,
}

impl Controls {
    /// The channel handlers for a new session, and the handles to steer them.
    pub fn build() -> (Vec<Box<dyn StaticChannel>>, Controls) {
        let (display, display_handle) = rdp::display_control();
        let (cliprdr, clipboard) = rdp::cliprdr(Box::new(WindowsClipboard));
        let channels: Vec<Box<dyn StaticChannel>> = vec![
            Box::new(Drdynvc::new(vec![Box::new(display)])),
            Box::new(cliprdr),
        ];
        (
            channels,
            Controls {
                display: display_handle,
                clipboard,
            },
        )
    }

    /// Text clipboard sharing, both directions; applies on the next session poll.
    pub fn set_clipboard(&self, on: bool) -> Result<(), String> {
        self.clipboard.set_enabled(on);
        Ok(())
    }

    /// Asks the server to resize the desktop to the tab. The request waits
    /// until the server has opened the Display Control channel; servers
    /// without it (before Windows 8.1 / Server 2012 R2) keep their size.
    pub fn request_resize(&self, width: u32, height: u32) -> bool {
        self.display.request_resize(width, height);
        true
    }

    pub fn add_drive(&self, _name: &str, _path: &str) -> Result<u32, String> {
        Err("folder sharing is not available in this build".into())
    }

    pub fn remove_drive(&self, _device_id: u32) {}
}
