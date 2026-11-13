//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::{ClipboardHandle, DisplayHandle, Drdynvc, RdpdrHandle, StaticChannel};

use crate::clipboard::WindowsClipboard;

pub struct Controls {
    display: DisplayHandle,
    clipboard: ClipboardHandle,
    devices: RdpdrHandle,
}

impl Controls {
    /// The channel handlers for a new session, and the handles to steer them.
    pub fn build(client_name: &str) -> (Vec<Box<dyn StaticChannel>>, Controls) {
        let (display_channel, display) = rdp::display_control();
        let (cliprdr, clipboard) = rdp::cliprdr(Box::new(WindowsClipboard));
        let (rdpdr, devices) = rdp::rdpdr(client_name);
        let channels: Vec<Box<dyn StaticChannel>> = vec![
            Box::new(Drdynvc::new(vec![Box::new(display_channel)])),
            Box::new(cliprdr),
            Box::new(rdpdr),
        ];
        (
            channels,
            Controls {
                display,
                clipboard,
                devices,
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

    /// Shares a local folder as a drive; it appears in the remote Explorer
    /// once the server has logged the user on.
    pub fn add_drive(&self, name: &str, path: &str) -> Result<u32, String> {
        let root = std::path::PathBuf::from(path);
        if !root.is_dir() {
            return Err(format!("{path} is not a folder."));
        }
        Ok(self.devices.add_drive(name, root, false))
    }

    /// Stops sharing a folder; files the remote side had open are closed.
    pub fn remove_drive(&self, device_id: u32) {
        self.devices.remove(device_id);
    }
}
