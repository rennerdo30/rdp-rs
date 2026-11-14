//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::{
    AudioHandle, AudioInputHandle, ClipboardHandle, DisplayHandle, Drdynvc, RdpdrHandle,
    StaticChannel, StaticOverDvc,
};

use crate::audio::{DEFAULT_DEVICE, Speaker, WaveOut};
use crate::mic::{DeviceChoice, WaveIn};
use std::sync::atomic::{AtomicU32, Ordering};

use std::sync::{Arc, Mutex, OnceLock};

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
    /// Microphone over the `AUDIO_INPUT` dynamic channel (MS-RDPEAI).
    microphone: AudioInputHandle,
    /// Capture device for the microphone; read when capture starts.
    mic_device: DeviceChoice,
    /// Device ids of the printers currently shared.
    printers: Mutex<Vec<u32>>,
    /// Device id of the shared smart card subsystem, while shared.
    smart_card: Mutex<Option<u32>>,
    /// Touch and pen over `Microsoft::Windows::RDS::Input` (MS-RDPEI); only
    /// declared when this PC has a digitizer (MS-RDPEI 3.3.3).
    touch: Option<rdp::TouchHandle>,
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
        // Compressed formats: ADPCM in the library, AAC and MP3 on Media
        // Foundation where present; PCM stays the fallback.
        let codecs = || rdp::AudioCodecs {
            adpcm: true,
            decoder: crate::audio_mf::decoder(),
        };
        let (rdpsnd, audio_static) =
            rdp::rdpsnd_with(Box::new(WaveOut::new(speaker.clone())), codecs());
        let (audio_dvc_channel, audio_dvc) =
            rdp::rdpsnd_with(Box::new(WaveOut::new(speaker.clone())), codecs());
        let mic_device: DeviceChoice = Arc::new(Mutex::new(None));
        let (audin, microphone) = rdp::audin(Box::new(WaveIn::new(mic_device.clone())));
        let mut dynamic: Vec<Box<dyn rdp::DynamicChannel>> = vec![
            Box::new(display_channel),
            Box::new(StaticOverDvc::new("AUDIO_PLAYBACK_DVC", audio_dvc_channel)),
            Box::new(audin),
        ];
        let touch = crate::touch::digitizer_present().then(|| {
            let (channel, handle) = rdp::touch_input(rdp::TouchOptions {
                show_touch_visuals: false,
                max_touch_contacts: crate::touch::max_contacts(),
            });
            dynamic.push(Box::new(channel));
            handle
        });
        // Same channels and order as mstsc: rdpdr, rdpsnd, cliprdr, drdynvc.
        let channels: Vec<Box<dyn StaticChannel>> = vec![
            Box::new(rdpdr),
            Box::new(rdpsnd),
            Box::new(cliprdr),
            Box::new(Drdynvc::new(dynamic)),
        ];
        let audio = [audio_static, audio_dvc];
        let controls = Controls {
            display,
            clipboard,
            devices,
            audio,
            speaker,
            microphone,
            mic_device,
            printers: Mutex::new(Vec::new()),
            smart_card: Mutex::new(None),
            touch,
        };
        if let Some(&device) = CLI_MICROPHONE.get() {
            controls.set_microphone_device(device);
            let _ = controls.set_microphone(true);
        }
        (channels, controls)
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

    /// Sends this PC's microphone to the session when the server records;
    /// off closes the local device and sends nothing (the channel stays open).
    pub fn set_microphone(&self, on: bool) -> Result<(), String> {
        self.microphone.set_enabled(on);
        Ok(())
    }

    /// Capture device: an index into [`crate::mic::input_devices`], or None
    /// for the system default. Takes effect on the next capture start (the
    /// server opening the recording, a format change, or the microphone
    /// being switched on).
    pub fn set_microphone_device(&self, device: Option<u32>) {
        *self.mic_device.lock().unwrap_or_else(|p| p.into_inner()) = device;
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

    /// Touch and pen input to the session, when this PC has a digitizer.
    pub fn touch(&self) -> Option<&rdp::TouchHandle> {
        self.touch.as_ref()
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

/// `--microphone [index]` from the command line: every session starts with
/// the microphone on, on that device (manual testing).
static CLI_MICROPHONE: OnceLock<Option<u32>> = OnceLock::new();

pub fn enable_microphone_for_all(device: Option<u32>) {
    let _ = CLI_MICROPHONE.set(device);
}
