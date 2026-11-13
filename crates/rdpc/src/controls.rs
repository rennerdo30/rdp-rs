//! Live per-session controls: the virtual channels a session opens and the
//! handles the UI uses to switch sharing on and off without reconnecting.
//!
//! Every session declares all channels at connect time (the protocol cannot
//! add them later); sharing itself starts off and follows the drawer toggles.

use rdp::StaticChannel;

#[derive(Default)]
pub struct Controls {}

impl Controls {
    /// The channel handlers for a new session, and the handles to steer them.
    pub fn build() -> (Vec<Box<dyn StaticChannel>>, Controls) {
        (Vec::new(), Controls::default())
    }

    pub fn set_clipboard(&self, _on: bool) -> Result<(), String> {
        Err("clipboard sharing is not available in this build".into())
    }

    /// Asks the server to resize the desktop to the tab; false if the server
    /// does not support live resizing.
    pub fn request_resize(&self, _width: u32, _height: u32) -> bool {
        false
    }

    pub fn add_drive(&self, _name: &str, _path: &str) -> Result<u32, String> {
        Err("folder sharing is not available in this build".into())
    }

    pub fn remove_drive(&self, _device_id: u32) {}
}
