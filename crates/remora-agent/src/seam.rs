//! The seam between the agent's plumbing and the helper protocol.
//!
//! The agent owns the Windows side: channels, session events, timers, the
//! open-URL forwarder. It turns all of that into [`AgentEvent`]s and hands
//! them, one at a time on a single thread, to a [`Protocol`]. The protocol
//! answers with [`Action`]s that the agent carries out. `remora-link` (the
//! Noise handshake, pairing, message types and file transfer) plugs in here
//! by implementing [`Protocol`]; until then [`NullProtocol`] stands in.
//!
//! Contract for implementations:
//! - One DVC message is one protocol message ([`AgentEvent::Message`] and
//!   [`Action::Send`] carry whole messages of at most
//!   [`crate::framing::MAX_WIRE_MESSAGE_LEN`] bytes).
//! - The agent is the Noise initiator: on [`AgentEvent::ChannelOpened`]
//!   the protocol sends first.
//! - A channel can close and reopen any number of times (client reconnects);
//!   every [`AgentEvent::ChannelOpened`] starts a fresh handshake.
//! - [`Action::Send`] on a closed channel is dropped and logged.
//! - `on_event` must not block; the agent's event loop runs it inline.

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
        match self {
            Channel::Ctl => "Remora::Ctl",
            Channel::Bulk => "Remora::Bulk",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Channel::Ctl => 0,
            Channel::Bulk => 1,
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
    /// A fresh session snapshot, every few seconds while `Remora::Ctl` is
    /// open. Doubles as the protocol's clock for heartbeats and timeouts.
    SessionInfoTick(SessionInfo),
    /// The user clicked a link in the session (already validated: http or
    /// https, bounded length). Answer with [`Action::OpenUrlResult`].
    OpenUrl(String),
    /// The agent is exiting (logoff, `WM_ENDSESSION`). Last chance to send.
    Shutdown,
}

/// What the protocol wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "Send and Close come from remora-link once integrated"
)]
pub enum Action {
    /// Send one whole message on the channel.
    Send(Channel, Vec<u8>),
    /// Close the channel (protocol error, failed authentication). The agent
    /// reopens it only on the next client connect.
    Close(Channel),
    /// The answer to [`AgentEvent::OpenUrl`]; the `open-url` process waits
    /// for it and falls back to the local browser if it is not `Forwarded`.
    OpenUrlResult(UrlOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "Forwarded comes from remora-link once integrated")]
pub enum UrlOutcome {
    /// Sent to the Remora client.
    Forwarded,
    /// No paired Remora client is connected.
    NoClient,
}

/// The helper protocol, driven by the agent's event loop.
pub trait Protocol {
    fn on_event(&mut self, ev: AgentEvent) -> Vec<Action>;
}

/// Stand-in until `remora-link` is integrated: speaks nothing, so no URL is
/// ever forwarded. It keeps the events it would have acted on, which lets
/// the agent's plumbing be exercised end to end.
#[derive(Debug, Default)]
pub struct NullProtocol {
    /// Links that would be sent as an `OpenUrl` message on `Remora::Ctl`.
    pub outgoing: Vec<OutgoingEvent>,
}

/// A high-level message the protocol would send once it is real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutgoingEvent {
    OpenUrl(String),
}

/// How many pending events the stand-in keeps.
const NULL_QUEUE_CAP: usize = 16;

impl Protocol for NullProtocol {
    fn on_event(&mut self, ev: AgentEvent) -> Vec<Action> {
        match ev {
            AgentEvent::OpenUrl(url) => {
                if self.outgoing.len() >= NULL_QUEUE_CAP {
                    self.outgoing.remove(0);
                }
                self.outgoing.push(OutgoingEvent::OpenUrl(url));
                vec![Action::OpenUrlResult(UrlOutcome::NoClient)]
            }
            AgentEvent::ChannelOpened(_)
            | AgentEvent::ChannelClosed(_)
            | AgentEvent::Message(..)
            | AgentEvent::SessionInfoTick(_)
            | AgentEvent::Shutdown => Vec::new(),
        }
    }
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
        }
    }

    #[test]
    fn null_protocol_never_forwards_and_stays_bounded() {
        let mut p = NullProtocol::default();
        assert!(
            p.on_event(AgentEvent::ChannelOpened(Channel::Ctl))
                .is_empty()
        );
        assert!(
            p.on_event(AgentEvent::Message(Channel::Ctl, vec![1, 2]))
                .is_empty()
        );
        for i in 0..40 {
            let a = p.on_event(AgentEvent::OpenUrl(format!("https://e.example/{i}")));
            assert_eq!(a, vec![Action::OpenUrlResult(UrlOutcome::NoClient)]);
        }
        assert_eq!(p.outgoing.len(), NULL_QUEUE_CAP);
        assert_eq!(
            p.outgoing.last(),
            Some(&OutgoingEvent::OpenUrl("https://e.example/39".into()))
        );
    }
}
