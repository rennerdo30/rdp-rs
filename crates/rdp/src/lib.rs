//! A from-scratch RDP client protocol stack.
//!
//! Layering (bottom to top), each in its own module:
//! - [`transport`]: TCP, TLS upgrade (rustls) and PDU framing (TPKT / fast-path / DER)
//! - [`gateway`]: RD Gateway tunnel (MS-TSGU HTTP transport over a WebSocket)
//! - [`x224`]: TPKT + X.224 connection request/confirm with RDP negotiation (MS-RDPBCGR 2.2.1.1/2)
//! - [`credssp`] + [`ntlm`]: network level authentication (MS-CSSP, MS-NLMP NTLMv2)
//! - [`mcs`] + [`gcc`]: T.125 MCS domain and T.124 GCC conference data (MS-RDPBCGR 2.2.1.3-2.2.1.9)
//! - [`pdu`]: share control/data PDUs, client info, capabilities, finalization
//! - [`fastpath`] + [`input`]: fast-path output updates and fast-path input events
//! - [`compress`]: bulk decompression, RDP 4.0 to 6.1 (MS-RDPBCGR 3.1.8, MS-RDPEGDI 3.1.8)
//! - [`codec`]: interleaved RLE and planar bitmap codecs (MS-RDPBCGR 2.2.9.1.1.3.1.2.4, MS-RDPEGDI 2.2.2.5.1)
//! - [`dvc`] + [`disp`]: dynamic virtual channels (MS-RDPEDYC) and Display Control (MS-RDPEDISP)
//! - [`monitor`]: multi-monitor layouts (MS-RDPBCGR 2.2.1.3.6, 2.2.1.3.10, 2.2.12.1)
//! - [`gfx`]: the graphics pipeline (MS-RDPEGFX), opt-in through [`Graphics::Gfx`]
//! - [`surfcmd`]: surface commands with RemoteFX and NSCodec (MS-RDPBCGR 2.2.9.2, MS-RDPRFX)
//! - [`license`]: the licensing exchange (MS-RDPELE)
//! - [`cliprdr`]: clipboard redirection on the `cliprdr` channel (MS-RDPECLIP)
//! - [`client`]: the connection sequence and the session loop
//! - [`autodetect`]: network auto-detection, RTT and bandwidth (MS-RDPBCGR 2.2.14)
//! - [`redirect`]: server redirection (session broker, load balancing) and RDSTLS
//! - [`rdpsnd`]: audio output on the `rdpsnd` channel (MS-RDPEA)
//! - [`audin`]: microphone redirection on the `AUDIO_INPUT` dynamic channel (MS-RDPEAI)
//! - [`rail`]: RemoteApp, the `rail` channel and window orders (MS-RDPERP)
//! - [`rdpei`]: touch and pen input on the `Microsoft::Windows::RDS::Input` dynamic channel (MS-RDPEI)
//! - [`rdpdr`]: device redirection (MS-RDPEFS) with shared drives, printers (MS-RDPEPC) and smart cards (MS-RDPESC)

pub mod audin;
pub mod autodetect;
pub mod channel;
pub mod client;
pub mod cliprdr;
pub mod codec;
pub mod compress;
pub mod credssp;
pub mod crypto;
pub mod cursor;
pub mod der;
pub mod disp;
pub mod dvc;
pub mod error;
pub mod experience;
pub mod fastpath;
pub mod framebuffer;
pub mod gateway;
pub mod gcc;
pub mod gfx;
pub mod input;
pub mod license;
pub mod log;
pub mod mcs;
pub mod monitor;
pub mod ntlm;
pub mod pdu;
pub mod pointer;
pub mod rail;
pub mod rdpdr;
pub mod rdpei;
pub mod rdpsnd;
pub mod redirect;
pub mod surfcmd;
pub mod transport;
pub mod x224;

pub use audin::{AudioInput, AudioInputHandle, CaptureBackend, audin};
pub use autodetect::NetworkCharacteristics;
pub use channel::{ChannelOut, StaticChannel};
pub use client::{
    CertificateCheck, Client, CloseReason, Config, ConnectionInfo, PollOutcome, ServerCertificate,
};
pub use cliprdr::{ClipboardBackend, ClipboardHandle, Cliprdr, cliprdr};
pub use compress::Compression;
pub use credssp::{AuthFactory, AuthPackage, AuthParams, Step};
pub use disp::{DisplayControl, DisplayHandle, display_control};
pub use dvc::{Drdynvc, DvcOut, DynamicChannel, StaticOverDvc};
pub use error::{Error, Result};
pub use experience::{ConnectionType, Experience};
pub use framebuffer::{Damage, Framebuffer};
pub use gateway::GatewayConfig;
pub use gfx::Graphics;
pub use gfx::h264::{H264Decoder, H264Factory, Yuv420Frame};
pub use input::InputEvent;
pub use log::set_verbose;
pub use monitor::{Monitor, Orientation, VirtualDesktop};
pub use pdu::AutoReconnectCookie;
pub use pointer::{PointerShape, PointerUpdate};
pub use rail::{RailEvent, RailHandle, RailState, RailWindow, RemoteApp};
pub use rdpdr::{
    Device, Drive, IoCompletion, IoRequest, PrintBackend, PrintFormat, Printer, PrinterInfo, Rdpdr,
    RdpdrHandle, SmartCardBackend, rdpdr, share_printers, smart_card_device,
};
pub use rdpei::{
    PenContact, PenFrame, TouchContact, TouchFrame, TouchHandle, TouchInput, TouchOptions,
    touch_input,
};
pub use rdpsnd::{
    AudioBackend, AudioCodecs, AudioDecoder, AudioHandle, PcmFormat, Rdpsnd, rdpsnd, rdpsnd_with,
};
pub use redirect::Redirection;
