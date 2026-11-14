//! The seam between the agent's plumbing and the helper protocol.
//!
//! The agent owns the Windows side: channels, session events, timers, the
//! local pipe (`open-url`, `send`). It turns all of that into
//! [`AgentEvent`]s and hands them, one at a time on a single thread, to a
//! [`Protocol`]. The protocol answers with [`Action`]s that the agent
//! carries out. [`crate::link::LinkProtocol`] (remora-link: Noise
//! handshake, pairing, messages, file transfer) is the implementation.
//!
//! Contract for implementations:
//! - One DVC message is one protocol message ([`AgentEvent::Message`] and
//!   [`Action::Send`] carry whole messages of at most
//!   [`crate::framing::MAX_WIRE_MESSAGE_LEN`] bytes).
//! - The agent is the Noise initiator: on [`AgentEvent::ChannelOpened`]
//!   the protocol sends first.
//! - The agent opens `Remora::Ctl` whenever a client connects.
//!   `Remora::Bulk` is opened only when the protocol asks for it with
//!   [`Action::OpenChannel`] (after `HelloAck`, HELPER-PROTOCOL.md 1).
//! - A channel can close and reopen any number of times (client reconnects);
//!   every [`AgentEvent::ChannelOpened`] starts a fresh handshake.
//! - [`Action::Close`] closes a channel without an
//!   [`AgentEvent::ChannelClosed`] coming back; the agent does not reopen
//!   it before the next client connect (or, for Bulk, the next
//!   [`Action::OpenChannel`]).
//! - [`Action::Send`] on a closed channel is dropped and logged.
//! - `on_event` must not block; the agent's event loop runs it inline.
//!   [`Protocol::next_deadline`] asks for an [`AgentEvent::Timer`].

use std::path::PathBuf;
use std::time::Instant;

use crate::info::SessionInfo;

/// The agent's two dynamic virtual channels (RDP-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// `Remora::Ctl`, PRI_MED: handshake, control, small messages.
    Ctl,
    /// `Remora::Bulk`, PRI_LOW: file data.
    Bulk,
}

impl Channel {
    pub const ALL: [Channel; 2] = [Channel::Ctl, Channel::Bulk];

    /// The DVC name (ANSI, as `WTSVirtualChannelOpenEx` takes it).
    pub fn dvc_name(self) -> &'static str {
        self.link().name()
    }

    pub fn index(self) -> usize {
        match self {
            Channel::Ctl => 0,
            Channel::Bulk => 1,
        }
    }

    /// The same channel in remora-link's terms.
    pub fn link(self) -> remora_link::Channel {
        match self {
            Channel::Ctl => remora_link::Channel::Ctl,
            Channel::Bulk => remora_link::Channel::Bulk,
        }
    }

    pub fn from_link(c: remora_link::Channel) -> Channel {
        match c {
            remora_link::Channel::Ctl => Channel::Ctl,
            remora_link::Channel::Bulk => Channel::Bulk,
        }
    }
}

/// What happened, as the protocol sees it.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// The channel is open; the protocol may (and as initiator, should) send.
    ChannelOpened(Channel),
    /// The channel closed (client gone, read error, disconnect). Any
    /// session state bound to it is void.
    ChannelClosed(Channel),
    /// One whole message arrived.
    Message(Channel, Vec<u8>),
    /// A fresh session snapshot: right after `Remora::Ctl` opened, then
    /// every few seconds while it is open.
    SessionInfoTick(SessionInfo),
    /// The user clicked a link in the session (already validated: http or
    /// https, bounded length). Answer with [`Action::OpenUrlResult`] and the
    /// same `id`.
    OpenUrl { id: u64, url: String },
    /// `remora-agent send <files>` (Send To): offer these files to Remora.
    /// Answer with [`Action::SendFilesResult`] and the same `id`.
    SendFiles { id: u64, paths: Vec<PathBuf> },
    /// The user answered the pairing dialog on the server (the `ticket`
    /// that [`crate::link::PairingUi::show_sas`] got).
    PairingAnswer { ticket: u64, confirmed: bool },
    /// The deadline from [`Protocol::next_deadline`] passed.
    Timer,
    /// The agent is exiting (logoff, `WM_ENDSESSION`). Last chance to send.
    Shutdown,
}

/// What the protocol wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send one whole message on the channel.
    Send(Channel, Vec<u8>),
    /// Close the channel (protocol error, failed authentication, rejected
    /// pairing, or Bulk after Ctl closed).
    Close(Channel),
    /// Open the channel now (Bulk after `HelloAck`).
    OpenChannel(Channel),
    /// The answer to [`AgentEvent::OpenUrl`]; the `open-url` process waits
    /// for it and falls back to the local browser if it is not `Forwarded`.
    OpenUrlResult { id: u64, outcome: UrlOutcome },
    /// The answer to [`AgentEvent::SendFiles`].
    SendFilesResult { id: u64, outcome: SendOutcome },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlOutcome {
    /// Remora took the link (opened it, is asking the user, or the user
    /// declined it there): do not open it locally.
    Forwarded,
    /// No paired Remora client with links enabled: the local fallback runs.
    NoClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// `offered` files were queued for Remora; `failed` could not be read.
    Offered { offered: u16, failed: u16 },
    /// No paired Remora client with "files to this PC" enabled.
    NoClient,
}

/// The helper protocol, driven by the agent's event loop.
pub trait Protocol {
    fn on_event(&mut self, ev: AgentEvent) -> Vec<Action>;

    /// When the protocol next wants an [`AgentEvent::Timer`] (heartbeats,
    /// link answer timeouts, file transfer pacing). `None`: no timer.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// What the tray icon shows now.
    fn status(&self) -> AgentStatus {
        AgentStatus::default()
    }

    /// Things worth a tray notification since the last call.
    fn take_notices(&mut self) -> Vec<Notice> {
        Vec::new()
    }
}

/// Where the helper stands with Remora, for the tray icon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Phase {
    /// No Remora channel open (mstsc, console, or Remora not connected).
    #[default]
    Waiting,
    /// A Remora channel is open; the handshake or pairing is under way.
    Connecting,
    /// The pairing dialog waits for the user here.
    Pairing,
    /// Paired with a Remora PC the user confirmed (now or before).
    Connected,
}

/// The helper's state as the tray shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentStatus {
    pub phase: Phase,
    /// The Remora PC's name for itself (cleaned), when it sent one.
    pub client: String,
    /// File transfers moving or paused right now.
    pub transfers: usize,
}

/// Something the user may want to know without looking at the tray.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// The pairing dialog opened.
    PairingWaiting,
    /// A file from Remora was stored (its stored name).
    FileReceived(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names() {
        assert_eq!(Channel::Ctl.dvc_name(), "Remora::Ctl");
        assert_eq!(Channel::Bulk.dvc_name(), "Remora::Bulk");
        // WTSVirtualChannelOpenEx takes an ANSI name; keep it ASCII.
        for c in Channel::ALL {
            assert!(c.dvc_name().is_ascii());
            assert_eq!(Channel::ALL[c.index()], c);
            assert_eq!(Channel::from_link(c.link()), c);
        }
    }
}
