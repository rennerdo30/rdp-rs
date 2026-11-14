//! `remora-agent`: Remora's helper inside a Windows remote desktop session
//! (RDP-41, RDP-42, RDP-44).
//!
//! It runs as the logged-on user, opens the dynamic virtual channel
//! `Remora::Ctl` whenever a Remora client is attached (and `Remora::Bulk`
//! once paired), reports session information, forwards links the user
//! clicks, and moves files both ways. The helper protocol (handshake,
//! encryption, pairing, file transfer) is `remora-link`, driven by
//! [`link::LinkProtocol`] through [`seam::Protocol`].
//!
//! A GUI-subsystem program: it never shows a console window. Subcommands
//! that print attach to the console of the shell that started them.

#![cfg_attr(windows, windows_subsystem = "windows")]
// Off Windows only the pure modules and their tests are used.
#![cfg_attr(not(windows), allow(dead_code))]

mod cli;
mod clients;
mod files;
mod framing;
mod info;
mod keystore;
mod lifecycle;
mod link;
mod links;
mod logging;
mod seam;
mod task;
#[cfg(windows)]
mod win;

fn main() {
    #[cfg(windows)]
    std::process::exit(win::main());
    #[cfg(not(windows))]
    {
        // The pure modules build and test everywhere; the agent itself
        // needs Windows' RDP session APIs.
        let _ = cli::parse(&std::env::args().skip(1).collect::<Vec<_>>());
        eprintln!("remora-agent runs on Windows only.");
        std::process::exit(1);
    }
}
