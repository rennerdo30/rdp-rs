//! Remora Host (experimental): an RDP server that Remora and other RDP
//! clients connect to, to see this machine's desktop and use its keyboard
//! and mouse. The protocol is the `rdp` crate's [`rdp::server`] module;
//! this crate adds the session loop, frame pacing and damage tiles, the
//! password and TLS identity, and the platform backends.
//!
//! See `docs/HOST.md` for the architecture and roadmap and the crate's
//! README for how to try it.

pub mod auth;
pub mod backend;
pub mod cert;
pub mod host;
pub mod paths;
pub mod tiles;

pub use backend::{Authenticator, Backend, Button, Capturer, Frame, InputSink, Toggles};
pub use host::{Desktop, Host, HostConfig, SessionEnd, SessionError, serve_connection};
