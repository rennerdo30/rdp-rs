//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::{
    AudioHandle, ClipboardHandle, DisplayHandle, Drdynvc, RdpdrHandle, StaticChannel, StaticOverDvc,
};

use crate::audio::{DEFAULT_DEVICE, Speaker, WaveOut};
use std::sync::atomic::{AtomicU32, Ordering};

use std::sync::{Arc, Mutex};

use crate::clipboard::WindowsClipboard;
use crate::printing::WindowsSpooler;
use crate::smartcard::WinSCard;

pub struct Controls {
    display: DisplayHandle,
    clipboard: ClipboardHandle,
    devices: RdpdrHandle,
    /// Sound over `rdpsnd` and over `AUDIO_PLAYBACK_DVC`; the server uses one.
    audio: [AudioHandle; 2],
    speaker: Speaker,
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
        // Windows 8+ opens audio as the AUDIO_PLAYBACK_DVC dynamic channel and
        // falls back to the static rdpsnd channel, which also needs rdpdr
        // declared (MS-RDPEA 2.1). Offer both; whichever opens plays.
        let speaker: Speaker = Arc::new(AtomicU32::new(DEFAULT_DEVICE));
        let (rdpsnd, audio_static) = rdp::rdpsnd(Box::new(WaveOut::new(speaker.clone())));
        let (audio_dvc_channel, audio_dvc) = rdp::rdpsnd(Box::new(WaveOut::new(speaker.clone())));
        let dynamic: Vec<Box<dyn rdp::DynamicChannel>> = vec![
            Box::new(display_channel),
            Box::new(StaticOverDvc::new("AUDIO_PLAYBACK_DVC", audio_dvc_channel)),
        ];
        // Same channels and order as mstsc: rdpdr, rdpsnd, cliprdr, drdynvc.
        let channels: Vec<Box<dyn StaticChannel>> = vec![
            Box::new(rdpdr),
            Box::new(rdpsnd),
            Box::new(cliprdr),
            Box::new(Drdynvc::new(dynamic)),
        ];
        let audio = [audio_static, audio_dvc];
        (
            channels,
            Controls {
                display,
                clipboard,
                devices,
                audio,
                speaker,
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

    /// Where the session's sound plays: a waveOut device index, or None for
    /// the default output. Applies at once (the next wave reopens the device).
    pub fn set_speaker(&self, device: Option<u32>) {
        self.speaker
            .store(device.unwrap_or(DEFAULT_DEVICE), Ordering::Relaxed);
    }

    /// Plays the session's sound locally; off drops the audio (no renegotiation).
    pub fn set_sound(&self, on: bool) -> Result<(), String> {
        for a in &self.audio {
            a.set_enabled(on);
        }
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

    /// Desktop scale in percent; the session re-renders at once.
    pub fn set_scale(&self, percent: u32) {
        self.display.set_scale(percent);
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
