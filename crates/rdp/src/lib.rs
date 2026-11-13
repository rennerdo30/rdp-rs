//! A from-scratch RDP client protocol stack.
//!
//! Layering (bottom to top), each in its own module:
//! - [`transport`]: TCP, TLS upgrade (rustls) and PDU framing (TPKT / fast-path / DER)
//! - [`x224`]: TPKT + X.224 connection request/confirm with RDP negotiation (MS-RDPBCGR 2.2.1.1/2)
//! - [`credssp`] + [`ntlm`]: network level authentication (MS-CSSP, MS-NLMP NTLMv2)
//! - [`mcs`] + [`gcc`]: T.125 MCS domain and T.124 GCC conference data (MS-RDPBCGR 2.2.1.3-2.2.1.9)
//! - [`pdu`]: share control/data PDUs, client info, capabilities, finalization
//! - [`fastpath`] + [`input`]: fast-path output updates and fast-path input events
//! - [`codec`]: interleaved RLE and planar bitmap codecs (MS-RDPBCGR 2.2.9.1.1.3.1.2.4, MS-RDPEGDI 2.2.2.5.1)
//! - [`dvc`] + [`disp`]: dynamic virtual channels (MS-RDPEDYC) and Display Control (MS-RDPEDISP)
//! - [`cliprdr`]: clipboard redirection on the `cliprdr` channel (MS-RDPECLIP)
//! - [`client`]: the connection sequence and the session loop
//! - [`rdpdr`]: device redirection (MS-RDPEFS) with shared drives and smart cards (MS-RDPESC)

pub mod channel;
pub mod client;
pub mod cliprdr;
pub mod codec;
pub mod credssp;
pub mod crypto;
pub mod cursor;
pub mod der;
pub mod disp;
pub mod dvc;
pub mod error;
pub mod fastpath;
pub mod framebuffer;
pub mod gcc;
pub mod input;
pub mod log;
pub mod mcs;
pub mod ntlm;
pub mod pdu;
pub mod rdpdr;
pub mod transport;
pub mod x224;

pub use channel::{ChannelOut, StaticChannel};
pub use client::{Client, Config, ConnectionInfo, PollOutcome};
pub use cliprdr::{ClipboardBackend, ClipboardHandle, Cliprdr, cliprdr};
pub use disp::{DisplayControl, DisplayHandle, display_control};
pub use dvc::{Drdynvc, DvcOut, DynamicChannel};
pub use error::{Error, Result};
pub use framebuffer::{Damage, Framebuffer};
pub use input::InputEvent;
pub use log::set_verbose;
pub use rdpdr::{
    Device, Drive, IoCompletion, IoRequest, Rdpdr, RdpdrHandle, SmartCardBackend, rdpdr,
    smart_card_device,
};
