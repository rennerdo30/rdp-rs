//! The server's connection sequence and session (MS-RDPBCGR 1.3.1.1, 3.3.5)
//! as a sans-IO state machine: fed one complete PDU at a time (after TLS),
//! it queues the PDUs to send and reports what the host must act on.
//!
//! Order of the sequence (server view):
//! 1. MCS Connect Initial -> Connect Response with the GCC server data.
//! 2. Erect Domain, Attach User -> Attach User Confirm, Channel Joins ->
//!    Channel Join Confirms.
//! 3. Client Info -> [`Event::Logon`]; the host checks the credentials and
//!    calls [`ServerSession::accept_logon`] (licensing "valid client" and
//!    Demand Active follow) or [`ServerSession::reject_logon`].
//! 4. Confirm Active, then the client's finalization PDUs, each answered
//!    (Synchronize, Cooperate, Granted Control, Font Map) -> [`Event::Active`].
//! 5. Input, Refresh Rect and Suppress Output -> events; the host sends
//!    bitmap updates with [`ServerSession::send_tiles`].

use crate::error::{Error, Result, proto};
use crate::pdu::{self, PDUTYPE_CONFIRMACTIVE, PDUTYPE_DATA};
use crate::trace;
use crate::x224;

use super::Rect;
use super::connect::{self, ChannelPlan, ClientData, ClientDomainPdu};
use super::input::{ClientInput, parse_fastpath_input};
use super::output::{self, Tile};
use super::pdu::{self as spdu, ClientShareData, ConfirmActive, Credentials};

/// The share id of the session (2.2.1.13.1.1); Windows uses the same.
const SHARE_ID: u32 = 0x0001_03EA;

/// The fixed settings of one session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The desktop size of the Demand Active PDU; the client adapts to it.
    pub width: u16,
    pub height: u16,
    /// requestedProtocols of the client's X.224 request, echoed in the
    /// Server Core Data (2.2.1.4.2).
    pub requested_protocols: u32,
    /// The protocol the Connection Confirm selected; the client's core data
    /// MUST name the same (3.3.5.3.3).
    pub selected_protocol: u32,
}

/// What the host must act on.
#[derive(Debug)]
pub enum Event {
    /// The Client Info PDU arrived: check the credentials, then call
    /// [`ServerSession::accept_logon`] or [`ServerSession::reject_logon`].
    Logon(Credentials),
    /// Connection finalization is done: send the whole desktop.
    Active,
    /// Input events, in order.
    Input(Vec<ClientInput>),
    /// The client asks for these areas again (Refresh Rect, 2.2.11.2),
    /// clipped to the desktop.
    Refresh(Vec<Rect>),
    /// Suppress Output (2.2.11.3): false stops updates; true resumes them
    /// and the area must be sent again.
    Output { allowed: bool, area: Option<Rect> },
    /// The client ended the session (Shutdown Request, 2.2.2.2, or MCS
    /// Disconnect Provider Ultimatum, 2.2.2.3).
    Closed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ConnectInitial,
    ErectDomain,
    AttachUser,
    /// Channel joins, until the Client Info arrives.
    Joining,
    /// Waiting for the host's logon decision.
    Logon,
    ConfirmActive,
    Finalizing,
    Active,
    Closed,
}

/// The server half of one RDP connection after TLS.
pub struct ServerSession {
    cfg: SessionConfig,
    state: State,
    client: Option<ClientData>,
    plan: ChannelPlan,
    confirm: Option<ConfirmActive>,
    /// Update size limit: the client's MaxRequestSize, or one fast-path
    /// PDU's worth when it sent none (2.2.7.2.6).
    max_update: usize,
    out: Vec<Vec<u8>>,
}

impl ServerSession {
    pub fn new(cfg: SessionConfig) -> ServerSession {
        ServerSession {
            cfg,
            state: State::ConnectInitial,
            client: None,
            plan: ChannelPlan::new(0),
            confirm: None,
            max_update: output::MAX_FRAGMENT,
            out: Vec::new(),
        }
    }

    /// The client's conference data, once received.
    pub fn client(&self) -> Option<&ClientData> {
        self.client.as_ref()
    }

    /// The client's Confirm Active capabilities, once received.
    pub fn confirm_active(&self) -> Option<&ConfirmActive> {
        self.confirm.as_ref()
    }

    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// The PDUs to send, in order.
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    fn send_mcs(&mut self, mcs: &[u8]) {
        self.out.push(x224::data(mcs));
    }

    fn send_io(&mut self, data: &[u8]) {
        let pdu = connect::send_data_indication(self.plan.io_channel, data);
        self.send_mcs(&pdu);
    }

    /// Handles one complete PDU from the client: a TPKT packet or a
    /// fast-path input PDU.
    pub fn handle(&mut self, frame: &[u8]) -> Result<Vec<Event>> {
        if self.state == State::Closed {
            return Ok(Vec::new());
        }
        if frame.first() != Some(&0x03) {
            // Fast-path input (2.2.8.1.2): only once the client may send input.
            let input = parse_fastpath_input(frame)?;
            return Ok(match self.state {
                State::Finalizing | State::Active if !input.is_empty() => {
                    vec![Event::Input(input)]
                }
                State::Finalizing | State::Active => Vec::new(),
                s => return proto(format!("fast-path input in state {s:?}")),
            });
        }
        let mcs = x224::data_payload(frame)?;
        if self.state == State::ConnectInitial {
            return self.connect_initial(mcs);
        }
        match connect::parse_client_domain_pdu(mcs)? {
            ClientDomainPdu::ErectDomain if self.state == State::ErectDomain => {
                self.state = State::AttachUser;
                Ok(Vec::new())
            }
            ClientDomainPdu::AttachUser if self.state == State::AttachUser => {
                let confirm = connect::attach_user_confirm(self.plan.user_channel);
                self.send_mcs(&confirm);
                self.state = State::Joining;
                Ok(Vec::new())
            }
            ClientDomainPdu::ChannelJoin {
                user_channel,
                channel,
            } if self.state == State::Joining => {
                self.channel_join(user_channel, channel)?;
                Ok(Vec::new())
            }
            ClientDomainPdu::SendData { channel, data, .. } if channel == self.plan.io_channel => {
                let data = data.to_vec();
                self.io_data(&data)
            }
            ClientDomainPdu::SendData { channel, data, .. } => {
                // Static virtual channels are joined and then ignored.
                trace!("server: {} bytes on channel {channel} ignored", data.len());
                Ok(Vec::new())
            }
            ClientDomainPdu::Disconnect { reason } => {
                self.state = State::Closed;
                Ok(vec![Event::Closed(format!(
                    "the client disconnected (MCS reason {reason})"
                ))])
            }
            pdu => proto(format!(
                "unexpected MCS PDU {pdu:?} in state {:?}",
                self.state
            )),
        }
    }

    fn connect_initial(&mut self, mcs: &[u8]) -> Result<Vec<Event>> {
        let gcc = connect::parse_connect_initial(mcs)?;
        let client = connect::parse_conference_create_request(&gcc)?;
        if let Some(p) = client.server_selected_protocol
            && p != self.cfg.selected_protocol
        {
            // 3.3.5.3.3: the server MUST end the connection.
            return proto(format!(
                "client core data names protocol {p:#x}, the server selected {:#x}",
                self.cfg.selected_protocol
            ));
        }
        trace!(
            "server: client {:?} build {}, {}x{}, channels {:?}",
            client.client_name, client.client_build, client.width, client.height, client.channels
        );
        self.plan = ChannelPlan::new(client.channels.len());
        let blocks = connect::server_data_blocks(self.cfg.requested_protocols, &self.plan);
        let response = connect::connect_response(&connect::conference_create_response(&blocks));
        self.send_mcs(&response);
        self.client = Some(client);
        self.state = State::ErectDomain;
        Ok(Vec::new())
    }

    fn channel_join(&mut self, user_channel: u16, channel: u16) -> Result<()> {
        if user_channel != self.plan.user_channel {
            return proto(format!("channel join from unknown user {user_channel}"));
        }
        let known = channel == self.plan.user_channel
            || channel == self.plan.io_channel
            || self.plan.static_channels.contains(&channel);
        let confirm = if known {
            connect::channel_join_confirm(user_channel, channel)
        } else {
            connect::channel_join_refused(user_channel, channel)
        };
        self.send_mcs(&confirm);
        Ok(())
    }

    fn io_data(&mut self, data: &[u8]) -> Result<Vec<Event>> {
        match self.state {
            State::Joining => {
                let creds = spdu::parse_client_info(data)?;
                self.state = State::Logon;
                Ok(vec![Event::Logon(creds)])
            }
            State::ConfirmActive | State::Finalizing | State::Active => self.share_pdus(data),
            s => proto(format!("I/O channel data in state {s:?}")),
        }
    }

    /// Accepts the logon: the licensing "valid client" PDU (2.2.1.12) and
    /// the Demand Active PDU (2.2.1.13.1) follow.
    pub fn accept_logon(&mut self) -> Result<()> {
        if self.state != State::Logon {
            return proto("no logon to accept");
        }
        self.send_io(&spdu::license_valid_client());
        let demand = spdu::demand_active(SHARE_ID, self.cfg.width, self.cfg.height);
        self.send_io(&demand);
        self.state = State::ConfirmActive;
        Ok(())
    }

    /// Refuses the logon: Set Error Info with `error_info` (2.2.5.1.1), then
    /// the Disconnect Provider Ultimatum. The connection is over.
    pub fn reject_logon(&mut self, error_info: u32) {
        self.disconnect(error_info);
    }

    /// Ends the session from the server side: Set Error Info when
    /// `error_info` is nonzero, then the Disconnect Provider Ultimatum.
    pub fn disconnect(&mut self, error_info: u32) {
        if self.state == State::Closed {
            return;
        }
        if error_info != 0 && self.state != State::ConnectInitial {
            self.send_io(&spdu::error_info_pdu(SHARE_ID, error_info));
        }
        self.send_mcs(&connect::disconnect_provider_ultimatum());
        self.state = State::Closed;
    }

    fn share_pdus(&mut self, data: &[u8]) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (ty, body) in pdu::split_share_control(data)? {
            match ty {
                PDUTYPE_CONFIRMACTIVE if self.state == State::ConfirmActive => {
                    let ca = spdu::parse_confirm_active(body)?;
                    if ca.share_id != SHARE_ID {
                        return proto(format!("Confirm Active for share {:#x}", ca.share_id));
                    }
                    if !ca.fastpath_output() {
                        return Err(Error::Unsupported(
                            "the client takes no fast-path output".into(),
                        ));
                    }
                    // The reassembly buffer bounds one update (2.2.7.2.6).
                    self.max_update = ca
                        .max_request_size
                        .map_or(output::MAX_FRAGMENT, |m| (m as usize).min(1 << 20))
                        .max(output::bitmap_data_len(64, 64) + 4);
                    trace!("server: confirm active {ca:?}");
                    self.confirm = Some(ca);
                    self.state = State::Finalizing;
                }
                PDUTYPE_DATA if self.state != State::ConfirmActive => {
                    let (_, pdu) = spdu::parse_client_share_data(body)?;
                    self.share_data(pdu, &mut events);
                }
                _ => trace!("server: share PDU type {ty} ignored in {:?}", self.state),
            }
        }
        Ok(events)
    }

    fn share_data(&mut self, pdu: ClientShareData, events: &mut Vec<Event>) {
        let reply = spdu::finalization_reply(SHARE_ID, self.plan.user_channel, &pdu);
        if !reply.is_empty() {
            self.send_io(&reply);
        }
        match pdu {
            ClientShareData::FontList if self.state == State::Finalizing => {
                self.state = State::Active;
                events.push(Event::Active);
            }
            ClientShareData::RefreshRect(rects) => {
                let rects: Vec<Rect> = rects.iter().filter_map(|r| self.clip(r)).collect();
                if !rects.is_empty() {
                    events.push(Event::Refresh(rects));
                }
            }
            ClientShareData::SuppressOutput(area) => events.push(Event::Output {
                allowed: area.is_some(),
                area: area.and_then(|r| self.clip(&r)),
            }),
            ClientShareData::Input(input) if !input.is_empty() => {
                events.push(Event::Input(input));
            }
            ClientShareData::ShutdownRequest => {
                // 3.3.5.5.1 lets the server deny it; the host has no
                // session to keep, so it ends the connection instead.
                self.disconnect(0);
                events.push(Event::Closed("the client shut the session down".into()));
            }
            other => trace!("server: share data {other:?}"),
        }
    }

    fn clip(&self, r: &Rect) -> Option<Rect> {
        r.clip(self.cfg.width, self.cfg.height)
    }

    /// Queues bitmap updates for the tiles (fast-path, uncompressed 32 bpp).
    /// Nothing is sent before the session is active.
    pub fn send_tiles(&mut self, tiles: &[Tile]) {
        if !matches!(self.state, State::Active) {
            return;
        }
        self.out
            .extend(output::bitmap_updates(tiles, self.max_update));
    }

    /// Queues the system default pointer.
    pub fn send_default_pointer(&mut self) {
        if self.state == State::Active {
            self.out.push(output::pointer_default());
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
