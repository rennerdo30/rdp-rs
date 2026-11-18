//! The multiparty virtual channel `encomsp` (MS-RDPEMC): who else watches a
//! shared desktop, what this participant may do (view or interact), whether
//! the picture is paused, and the request for control.
//!
//! Windows Desktop Sharing, Remote Assistance (versions 2 and 3) and session
//! shadowing (MS-TSTS RpcShadow2) run it over a static channel (2.1). The
//! sharing manager (the server) announces participants, applications and
//! windows; the participant (this client) asks for another control level
//! (2.2.4.3) or for a shared window to be shown (2.2.3.6).
//!
//! [`multiparty`] gives the channel handler and a [`MultipartyHandle`] for the
//! UI. A malformed message is a protocol error, which disables this channel
//! only (the session keeps running; Windows would disconnect, 3.1.5.1 <8>).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::{Put, Reader};
use crate::error::{Error, Result};
use crate::trace;

/// The static channel name (2.1).
pub const CHANNEL_NAME: &str = "encomsp";

// ORDER_HDR Type values (2.2.1).
const ODTYPE_FILTER_STATE_UPDATED: u16 = 0x0001;
const ODTYPE_APP_REMOVED: u16 = 0x0002;
const ODTYPE_APP_CREATED: u16 = 0x0003;
const ODTYPE_WND_REMOVED: u16 = 0x0004;
const ODTYPE_WND_CREATED: u16 = 0x0005;
const ODTYPE_WND_SHOW: u16 = 0x0006;
const ODTYPE_PARTICIPANT_REMOVED: u16 = 0x0007;
const ODTYPE_PARTICIPANT_CREATED: u16 = 0x0008;
const ODTYPE_PARTICIPANT_CTRL_CHANGED: u16 = 0x0009;
const ODTYPE_GRAPHICS_STREAM_PAUSED: u16 = 0x000A;
const ODTYPE_GRAPHICS_STREAM_RESUMED: u16 = 0x000B;
const ODTYPE_WND_RGN_UPDATE: u16 = 0x000C;
const ODTYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE: u16 = 0x000D;

/// ORDER_HDR size: Type and Length, u16 each (2.2.1).
const HEADER_LEN: usize = 4;
/// UNICODE_STRING cchString limit (2.2.2).
const MAX_CCH: u16 = 1024;

/// Participant flags (2.2.4.1).
pub const MAY_VIEW: u16 = 0x0001;
pub const MAY_INTERACT: u16 = 0x0002;
pub const IS_PARTICIPANT: u16 = 0x0004;

/// Control level request flags (2.2.4.3, 2.2.4.4).
pub const REQUEST_VIEW: u16 = 0x0001;
pub const REQUEST_INTERACT: u16 = 0x0002;
pub const ALLOW_CONTROL_REQUESTS: u16 = 0x0008;

/// APPLICATION_SHARED (2.2.3.2) and WINDOW_SHARED (2.2.3.4).
pub const SHARED: u16 = 0x0001;

/// One multiparty PDU (an "order", 2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Order {
    /// OD_FILTER_STATE_UPDATED (2.2.3.1): application filtering on or off.
    FilterUpdated { enabled: bool },
    /// OD_APP_CREATED (2.2.3.2): an application was added or changed.
    AppCreated {
        flags: u16,
        app_id: u32,
        name: String,
    },
    /// OD_APP_REMOVED (2.2.3.3).
    AppRemoved { app_id: u32 },
    /// OD_WND_CREATED (2.2.3.4): a window was added or changed.
    WndCreated {
        flags: u16,
        app_id: u32,
        wnd_id: u32,
        name: String,
    },
    /// OD_WND_REMOVED (2.2.3.5).
    WndRemoved { wnd_id: u32 },
    /// OD_WND_SHOW (2.2.3.6): participant asks to show a shared window.
    WndShow { wnd_id: u32 },
    /// OD_PARTICIPANT_REMOVED (2.2.4.2).
    ParticipantRemoved {
        id: u32,
        disc_type: u32,
        disc_code: u32,
    },
    /// OD_PARTICIPANT_CREATED (2.2.4.1): a participant joined or its
    /// control level changed.
    ParticipantCreated {
        id: u32,
        group_id: u32,
        flags: u16,
        name: String,
    },
    /// OD_PARTICIPANT_CTRL_CHANGE (2.2.4.3): participant asks for a control level.
    ParticipantCtrlChange { flags: u16, id: u32 },
    /// OD_GRAPHICS_STREAM_PAUSED (2.2.5.1).
    StreamPaused,
    /// OD_GRAPHICS_STREAM_RESUMED (2.2.5.2).
    StreamResumed,
    /// OD_WND_REGION_UPDATE (2.2.3.7): inclusive window rectangle.
    WndRegionUpdate {
        left: u32,
        top: u32,
        right: u32,
        bottom: u32,
    },
    /// OD_PARTICIPANT_CTRL_CHANGE_RESPONSE (2.2.4.4).
    CtrlChangeResponse { flags: u16, id: u32, reason: u32 },
}

/// Reads a UNICODE_STRING (2.2.2, 3.1.5.2). A body that ends before the
/// string is an empty name: Windows treats Name as optional (6 <10>).
fn unicode_string(r: &mut Reader) -> Result<String> {
    if r.remaining() == 0 {
        return Ok(String::new());
    }
    let cch = r.u16()?;
    if cch > MAX_CCH {
        return Err(Error::Protocol(format!(
            "encomsp: UNICODE_STRING of {cch} characters (max {MAX_CCH})"
        )));
    }
    let raw = r.bytes(usize::from(cch) * 2)?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Parses one ORDER_HDR body. Data past the known fields is ignored (6 <9>).
fn parse_body(ty: u16, body: &[u8]) -> Result<Option<Order>> {
    let mut r = Reader::new(body);
    let order = match ty {
        ODTYPE_FILTER_STATE_UPDATED => Order::FilterUpdated {
            enabled: r.u8()? & 0x01 != 0,
        },
        ODTYPE_APP_REMOVED => Order::AppRemoved { app_id: r.u32()? },
        ODTYPE_APP_CREATED => Order::AppCreated {
            flags: r.u16()?,
            app_id: r.u32()?,
            name: unicode_string(&mut r)?,
        },
        ODTYPE_WND_REMOVED => Order::WndRemoved { wnd_id: r.u32()? },
        ODTYPE_WND_CREATED => Order::WndCreated {
            flags: r.u16()?,
            app_id: r.u32()?,
            wnd_id: r.u32()?,
            name: unicode_string(&mut r)?,
        },
        ODTYPE_WND_SHOW => Order::WndShow { wnd_id: r.u32()? },
        ODTYPE_PARTICIPANT_REMOVED => Order::ParticipantRemoved {
            id: r.u32()?,
            disc_type: r.u32()?,
            disc_code: r.u32()?,
        },
        ODTYPE_PARTICIPANT_CREATED => Order::ParticipantCreated {
            id: r.u32()?,
            group_id: r.u32()?,
            flags: r.u16()?,
            name: unicode_string(&mut r)?,
        },
        ODTYPE_PARTICIPANT_CTRL_CHANGED => Order::ParticipantCtrlChange {
            flags: r.u16()?,
            id: r.u32()?,
        },
        ODTYPE_GRAPHICS_STREAM_PAUSED => Order::StreamPaused,
        ODTYPE_GRAPHICS_STREAM_RESUMED => Order::StreamResumed,
        ODTYPE_WND_RGN_UPDATE => Order::WndRegionUpdate {
            left: r.u32()?,
            top: r.u32()?,
            right: r.u32()?,
            bottom: r.u32()?,
        },
        ODTYPE_PARTICIPANT_CTRL_CHANGE_RESPONSE => Order::CtrlChangeResponse {
            flags: r.u16()?,
            id: r.u32()?,
            reason: r.u32()?,
        },
        // Unknown types are ignored (3.1.5.1 <7>).
        _ => return Ok(None),
    };
    Ok(Some(order))
}

/// Splits one channel message into its orders (3.1.5.1): each carries its
/// own ORDER_HDR, whose Length includes the header and must fit the message.
pub fn parse(msg: &[u8]) -> Result<Vec<Order>> {
    let mut r = Reader::new(msg);
    let mut orders = Vec::new();
    while r.remaining() > 0 {
        let ty = r.u16()?;
        let len = usize::from(r.u16()?);
        if len < HEADER_LEN || len - HEADER_LEN > r.remaining() {
            return Err(Error::Protocol(format!(
                "encomsp: order {ty:#06x} length {len} with {} bytes left",
                r.remaining() + HEADER_LEN
            )));
        }
        let body = r.bytes(len - HEADER_LEN)?;
        let order = parse_body(ty, body)
            .map_err(|e| Error::Protocol(format!("encomsp: order {ty:#06x}: {e}")))?;
        orders.extend(order);
    }
    Ok(orders)
}

fn header(ty: u16, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body_len);
    out.put_u16(ty);
    out.put_u16((HEADER_LEN + body_len) as u16);
    out
}

/// OD_PARTICIPANT_CTRL_CHANGE (2.2.4.3): asks for the control level in
/// `flags` (REQUEST_VIEW, REQUEST_INTERACT) for participant `id`.
pub fn ctrl_change(flags: u16, id: u32) -> Vec<u8> {
    let mut out = header(ODTYPE_PARTICIPANT_CTRL_CHANGED, 6);
    out.put_u16(flags);
    out.put_u32(id);
    out
}

/// OD_WND_SHOW (2.2.3.6): asks the sharing manager to show window `wnd_id`.
pub fn wnd_show(wnd_id: u32) -> Vec<u8> {
    let mut out = header(ODTYPE_WND_SHOW, 4);
    out.put_u32(wnd_id);
    out
}

/// What this participant may do with the shared desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Control {
    /// Not announced yet, or neither view nor interact.
    #[default]
    None,
    /// MAY_VIEW: watch only; the sharer ignores input.
    View,
    /// MAY_INTERACT: mouse and keyboard reach the shared desktop.
    Interact,
}

impl Control {
    fn from_flags(flags: u16) -> Self {
        if flags & MAY_INTERACT != 0 {
            Control::Interact
        } else if flags & MAY_VIEW != 0 {
            Control::View
        } else {
            Control::None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub name: String,
    pub group_id: u32,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedApp {
    pub name: String,
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWindow {
    pub app_id: u32,
    pub name: String,
    pub shared: bool,
}

/// The participant's view of the sharing session (3.1.1, 3.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipartyState {
    /// This client's ParticipantId, once a Participant-Created PDU with
    /// IS_PARTICIPANT named it (3.2.5.2.1 <18>).
    pub me: Option<u32>,
    pub participants: BTreeMap<u32, Participant>,
    pub apps: BTreeMap<u32, SharedApp>,
    pub windows: BTreeMap<u32, SharedWindow>,
    /// Application filtering is on (2.2.3.1).
    pub filter_enabled: bool,
    /// The sharer suspended the picture (2.2.5.1), for example at a lock
    /// screen or a secure-desktop prompt.
    pub paused: bool,
}

impl MultipartyState {
    /// This participant's control level.
    pub fn control(&self) -> Control {
        self.me
            .and_then(|id| self.participants.get(&id))
            .map_or(Control::None, |p| Control::from_flags(p.flags))
    }

    /// Applies one order from the sharing manager (3.2.5) and says what
    /// changed for the UI. Updates and creations share a PDU (3.1.5.3).
    pub fn apply(&mut self, order: Order) -> Option<MultipartyEvent> {
        match order {
            Order::ParticipantCreated {
                id,
                group_id,
                flags,
                name,
            } => {
                if flags & IS_PARTICIPANT != 0 {
                    self.me = Some(id);
                }
                let before = self.control();
                let p = Participant {
                    name: name.clone(),
                    group_id,
                    flags,
                };
                let known = self.participants.insert(id, p).is_some();
                if self.me == Some(id) {
                    let after = self.control();
                    (after != before).then_some(MultipartyEvent::ControlChanged(after))
                } else {
                    (!known).then_some(MultipartyEvent::Joined { id, name })
                }
            }
            Order::ParticipantRemoved { id, disc_code, .. } => {
                let p = self.participants.remove(&id)?;
                Some(MultipartyEvent::Left {
                    id,
                    name: p.name,
                    code: disc_code,
                })
            }
            Order::CtrlChangeResponse { flags, id, reason } => {
                Some(MultipartyEvent::ControlResponse { flags, id, reason })
            }
            Order::StreamPaused => (!std::mem::replace(&mut self.paused, true))
                .then_some(MultipartyEvent::Paused(true)),
            Order::StreamResumed => {
                std::mem::replace(&mut self.paused, false).then_some(MultipartyEvent::Paused(false))
            }
            Order::FilterUpdated { enabled } => {
                // A new list follows (3.2.5.1.3 <13>).
                self.filter_enabled = enabled;
                self.apps.clear();
                self.windows.clear();
                None
            }
            Order::AppCreated {
                flags,
                app_id,
                name,
            } => {
                let shared = flags & SHARED != 0;
                self.apps.insert(app_id, SharedApp { name, shared });
                None
            }
            Order::AppRemoved { app_id } => {
                // Its windows go with it (3.1.5.3).
                if self.apps.remove(&app_id).is_some() {
                    self.windows.retain(|_, w| w.app_id != app_id);
                }
                None
            }
            Order::WndCreated {
                flags,
                app_id,
                wnd_id,
                name,
            } => {
                let shared = flags & SHARED != 0;
                let w = SharedWindow {
                    app_id,
                    name,
                    shared,
                };
                self.windows.insert(wnd_id, w);
                None
            }
            Order::WndRemoved { wnd_id } => {
                self.windows.remove(&wnd_id);
                None
            }
            // Participant-to-sharer orders and the stateless region update.
            Order::WndShow { .. }
            | Order::ParticipantCtrlChange { .. }
            | Order::WndRegionUpdate { .. } => None,
        }
    }
}

/// Changes the UI shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartyEvent {
    /// This participant's control level changed.
    ControlChanged(Control),
    /// Another participant joined.
    Joined { id: u32, name: String },
    /// A participant left; `code` is DiscCode (2.2.4.2).
    Left { id: u32, name: String, code: u32 },
    /// The sharer answered a control request (2.2.4.4); the granted level
    /// itself arrives as [`MultipartyEvent::ControlChanged`].
    ControlResponse { flags: u16, id: u32, reason: u32 },
    /// The picture was paused (true) or resumed (false) (2.2.5).
    Paused(bool),
}

#[derive(Default)]
struct Shared {
    state: MultipartyState,
    events: Vec<MultipartyEvent>,
    outgoing: Vec<Vec<u8>>,
}

/// The `encomsp` channel handler. Create it with [`multiparty`].
pub struct Multiparty {
    shared: Arc<Mutex<Shared>>,
}

/// The UI's side of the channel. Clone freely.
#[derive(Clone)]
pub struct MultipartyHandle {
    shared: Arc<Mutex<Shared>>,
}

fn lock(s: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

/// The `encomsp` channel and its handle.
pub fn multiparty() -> (Multiparty, MultipartyHandle) {
    let shared = Arc::new(Mutex::new(Shared::default()));
    let handle = MultipartyHandle {
        shared: shared.clone(),
    };
    (Multiparty { shared }, handle)
}

impl MultipartyHandle {
    pub fn state(&self) -> MultipartyState {
        lock(&self.shared).state.clone()
    }

    pub fn control(&self) -> Control {
        lock(&self.shared).state.control()
    }

    /// Events since the last call, in order.
    pub fn take_events(&self) -> Vec<MultipartyEvent> {
        std::mem::take(&mut lock(&self.shared).events)
    }

    /// Asks the sharer for mouse and keyboard control (`true`) or to go back
    /// to watching (`false`) (2.2.4.3, MS-RA 3.15.5). The answer comes as
    /// [`MultipartyEvent::ControlResponse`] and, when granted, a new level.
    pub fn request_control(&self, interact: bool) {
        let flags = if interact {
            REQUEST_VIEW | REQUEST_INTERACT
        } else {
            REQUEST_VIEW
        };
        let mut s = lock(&self.shared);
        let id = s.state.me.unwrap_or(0);
        s.outgoing.push(ctrl_change(flags, id));
    }

    /// Asks the sharer to show a shared window (2.2.3.6).
    pub fn show_window(&self, wnd_id: u32) {
        lock(&self.shared).outgoing.push(wnd_show(wnd_id));
    }
}

impl StaticChannel for Multiparty {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let orders = parse(msg)?;
        let mut s = lock(&self.shared);
        for order in orders {
            trace!("encomsp: {order:?}");
            if let Some(ev) = s.state.apply(order) {
                s.events.push(ev);
            }
        }
        drop(s);
        self.tick(out)
    }

    fn tick(&mut self, out: &mut ChannelOut) -> Result<()> {
        for msg in std::mem::take(&mut lock(&self.shared).outgoing) {
            out.send(msg);
        }
        Ok(())
    }

    /// Orders are small; a whole message of them stays far below this.
    fn max_message_size(&self) -> usize {
        1 << 20
    }
}

#[cfg(test)]
#[path = "encomsp_tests.rs"]
mod tests;
