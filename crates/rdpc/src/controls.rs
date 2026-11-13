//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::{AudioHandle, ClipboardHandle, DisplayHandle, Drdynvc, RdpdrHandle, StaticChannel};

use crate::audio::WaveOut;

use std::sync::{Arc, Mutex};

use crate::clipboard::WindowsClipboard;
use crate::printing::WindowsSpooler;
use crate::smartcard::WinSCard;

pub struct Controls {
    display: DisplayHandle,
    clipboard: ClipboardHandle,
    devices: RdpdrHandle,
    audio: AudioHandle,
    /// Device ids of the printers currently shared.
    printers: Mutex<Vec<u32>>,
    /// Device id of the shared smart card subsystem, while shared.
    smart_card: Mutex<Option<u32>>,
}

impl Controls {
    /// The channel handlers for a new session, and the handles to steer them.
    /// `owner`: the main window's HWND, needed to set the local clipboard.
    pub fn build(client_name: &str, owner: isize) -> (Vec<Box<dyn StaticChannel>>, Controls) {
        let (display_channel, display) = rdp::display_control();
        let (cliprdr, clipboard) = rdp::cliprdr(Box::new(WindowsClipboard { owner }));
        let (rdpdr, devices) = rdp::rdpdr(client_name);
        // Windows servers only use rdpsnd when rdpdr is also declared (MS-RDPEA 2.1).
        let (rdpsnd, audio) = rdp::rdpsnd(Box::new(WaveOut::default()));
        let channels: Vec<Box<dyn StaticChannel>> = vec![
            Box::new(Drdynvc::new(vec![Box::new(display_channel)])),
            Box::new(cliprdr),
            Box::new(rdpdr),
            Box::new(rdpsnd),
        ];
        (
            channels,
            Controls {
                display,
                clipboard,
                devices,
                audio,
                printers: Mutex::new(Vec::new()),
                smart_card: Mutex::new(None),
            },
        )
    }

    /// Text clipboard sharing, both directions; applies on the next session poll.
    pub fn set_clipboard(&self, on: bool) -> Result<(), String> {
        self.clipboard.set_enabled(on);
        Ok(())
    }

    /// Plays the session's sound locally; off drops the audio (no renegotiation).
    pub fn set_sound(&self, on: bool) -> Result<(), String> {
        self.audio.set_enabled(on);
        Ok(())
    }

    /// Shares every local printer (Easy Print: the server needs no drivers).
    pub fn set_printers(&self, on: bool) -> Result<(), String> {
        let mut shared = self.printers.lock().unwrap_or_else(|p| p.into_inner());
        for id in shared.drain(..) {
            self.devices.remove(id);
        }
        if on {
            let backend: rdp::rdpdr::SharedBackend =
                Arc::new(Mutex::new(WindowsSpooler::default()));
            *shared = rdp::share_printers(&self.devices, backend);
            if shared.is_empty() {
                return Err("No local printers found to share.".into());
            }
        }
        Ok(())
    }

    /// Shares the local smart card readers and cards (calls go to WinSCard).
    pub fn set_smart_cards(&self, on: bool) -> Result<(), String> {
        let mut shared = self.smart_card.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(id) = shared.take() {
            // Releases every local card and context the session held.
            self.devices.remove(id);
        }
        if on {
            let device = rdp::smart_card_device(Arc::new(WinSCard));
            *shared = Some(self.devices.add_device(device));
        }
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
