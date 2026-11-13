//! Smart card redirection (MS-RDPESC) over the `rdpdr` channel.
//!
//! [`smart_card_device`] wraps a [`SmartCardBackend`] (the local PC/SC
//! layer, WinSCard on Windows) into a [`Device`] the UI adds with
//! [`super::RdpdrHandle::add_device`] and removes with
//! [`super::RdpdrHandle::remove`] at any time. The server opens the device
//! (IRP_MJ_CREATE) and sends every SCard call as IRP_MJ_DEVICE_CONTROL
//! (MS-RDPEFS 2.2.1.4.5) with an IOCTL_SCARD_* code and an NDR-serialized
//! call structure ([`ndr`], [`pack`]).
//!
//! Security model: the context and card handles the server sees are ids this
//! device hands out; they are looked up in a table owned by the device and
//! never interpreted as local handles. Unknown ids get
//! `SCARD_E_INVALID_HANDLE`. Removing the device, a redirection restart and
//! dropping the session release every local card handle and context.
//!
//! Calls that can block (GetStatusChange, Connect, Reconnect,
//! BeginTransaction, Transmit, Control, AccessStartedEvent) run on a short
//! worker thread each and complete from `tick`; Cancel reaches the backend
//! at once, so a waiting GetStatusChange returns `SCARD_E_CANCELLED`.
//! APDUs, PINs and card data are never traced, only IOCTL names and sizes.

mod device;
pub mod ndr;
pub mod pack;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use super::Device;

pub use device::SmartCard;

/// SCard call result: the value or a SCARD_* / Win32 return code
/// (MS-RDPESC 2.2.8), sent to the server unchanged.
pub type ScResult<T> = Result<T, u32>;

/// IOCTL codes (MS-RDPESC 3.1.4).
pub const SCARD_IOCTL_ESTABLISHCONTEXT: u32 = 0x0009_0014;
pub const SCARD_IOCTL_RELEASECONTEXT: u32 = 0x0009_0018;
pub const SCARD_IOCTL_ISVALIDCONTEXT: u32 = 0x0009_001C;
pub const SCARD_IOCTL_LISTREADERGROUPSA: u32 = 0x0009_0020;
pub const SCARD_IOCTL_LISTREADERGROUPSW: u32 = 0x0009_0024;
pub const SCARD_IOCTL_LISTREADERSA: u32 = 0x0009_0028;
pub const SCARD_IOCTL_LISTREADERSW: u32 = 0x0009_002C;
pub const SCARD_IOCTL_INTRODUCEREADERGROUPA: u32 = 0x0009_0050;
pub const SCARD_IOCTL_REMOVEREADERFROMGROUPW: u32 = 0x0009_007C;
pub const SCARD_IOCTL_LOCATECARDSA: u32 = 0x0009_0098;
pub const SCARD_IOCTL_LOCATECARDSW: u32 = 0x0009_009C;
pub const SCARD_IOCTL_GETSTATUSCHANGEA: u32 = 0x0009_00A0;
pub const SCARD_IOCTL_GETSTATUSCHANGEW: u32 = 0x0009_00A4;
pub const SCARD_IOCTL_CANCEL: u32 = 0x0009_00A8;
pub const SCARD_IOCTL_CONNECTA: u32 = 0x0009_00AC;
pub const SCARD_IOCTL_CONNECTW: u32 = 0x0009_00B0;
pub const SCARD_IOCTL_RECONNECT: u32 = 0x0009_00B4;
pub const SCARD_IOCTL_DISCONNECT: u32 = 0x0009_00B8;
pub const SCARD_IOCTL_BEGINTRANSACTION: u32 = 0x0009_00BC;
pub const SCARD_IOCTL_ENDTRANSACTION: u32 = 0x0009_00C0;
pub const SCARD_IOCTL_STATE: u32 = 0x0009_00C4;
pub const SCARD_IOCTL_STATUSA: u32 = 0x0009_00C8;
pub const SCARD_IOCTL_STATUSW: u32 = 0x0009_00CC;
pub const SCARD_IOCTL_TRANSMIT: u32 = 0x0009_00D0;
pub const SCARD_IOCTL_CONTROL: u32 = 0x0009_00D4;
pub const SCARD_IOCTL_GETATTRIB: u32 = 0x0009_00D8;
pub const SCARD_IOCTL_SETATTRIB: u32 = 0x0009_00DC;
pub const SCARD_IOCTL_ACCESSSTARTEDEVENT: u32 = 0x0009_00E0;
pub const SCARD_IOCTL_RELEASETARTEDEVENT: u32 = 0x0009_00E4;
pub const SCARD_IOCTL_LOCATECARDSBYATRA: u32 = 0x0009_00E8;
pub const SCARD_IOCTL_LOCATECARDSBYATRW: u32 = 0x0009_00EC;
pub const SCARD_IOCTL_READCACHEA: u32 = 0x0009_00F0;
pub const SCARD_IOCTL_READCACHEW: u32 = 0x0009_00F4;
pub const SCARD_IOCTL_WRITECACHEA: u32 = 0x0009_00F8;
pub const SCARD_IOCTL_WRITECACHEW: u32 = 0x0009_00FC;
pub const SCARD_IOCTL_GETTRANSMITCOUNT: u32 = 0x0009_0100;
pub const SCARD_IOCTL_GETREADERICON: u32 = 0x0009_0104;
pub const SCARD_IOCTL_GETDEVICETYPEID: u32 = 0x0009_0108;

/// Return codes (MS-RDPESC 2.2.8).
pub const SCARD_S_SUCCESS: u32 = 0;
pub const SCARD_F_INTERNAL_ERROR: u32 = 0x8010_0001;
pub const SCARD_E_CANCELLED: u32 = 0x8010_0002;
pub const SCARD_E_INVALID_HANDLE: u32 = 0x8010_0003;
pub const SCARD_E_INVALID_PARAMETER: u32 = 0x8010_0004;
pub const SCARD_E_NO_MEMORY: u32 = 0x8010_0006;
pub const SCARD_E_INSUFFICIENT_BUFFER: u32 = 0x8010_0008;
pub const SCARD_E_UNKNOWN_READER: u32 = 0x8010_0009;
pub const SCARD_E_TIMEOUT: u32 = 0x8010_000A;
pub const SCARD_E_NO_SMARTCARD: u32 = 0x8010_000C;
pub const SCARD_E_UNSUPPORTED_FEATURE: u32 = 0x8010_0022;
pub const SCARD_E_NO_SERVICE: u32 = 0x8010_001D;
pub const SCARD_E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
pub const SCARD_E_SERVER_TOO_BUSY: u32 = 0x8010_0031;
pub const SCARD_W_CACHE_ITEM_NOT_FOUND: u32 = 0x8010_0070;

/// SCARD_AUTOALLOCATE: "any length" in the cch/cb fields (2.2.2.4).
pub const SCARD_AUTOALLOCATE: u32 = 0xFFFF_FFFF;
/// Card dispositions (2.2.2.16).
pub const SCARD_LEAVE_CARD: u32 = 0;
pub const SCARD_RESET_CARD: u32 = 1;
/// Reader states (2.2.7).
pub const SCARD_STATE_UNAWARE: u32 = 0x0000;
pub const SCARD_STATE_CHANGED: u32 = 0x0002;
pub const SCARD_STATE_EMPTY: u32 = 0x0010;
pub const SCARD_STATE_PRESENT: u32 = 0x0020;
pub const SCARD_STATE_INUSE: u32 = 0x0100;
/// Protocols (2.2.5).
pub const SCARD_PROTOCOL_T0: u32 = 0x0001;
pub const SCARD_PROTOCOL_T1: u32 = 0x0002;

/// The IOCTL name for traces (never the call's data).
pub fn ioctl_name(ioctl: u32) -> &'static str {
    match ioctl {
        SCARD_IOCTL_ESTABLISHCONTEXT => "EstablishContext",
        SCARD_IOCTL_RELEASECONTEXT => "ReleaseContext",
        SCARD_IOCTL_ISVALIDCONTEXT => "IsValidContext",
        SCARD_IOCTL_LISTREADERSA => "ListReadersA",
        SCARD_IOCTL_LISTREADERSW => "ListReadersW",
        SCARD_IOCTL_GETSTATUSCHANGEA => "GetStatusChangeA",
        SCARD_IOCTL_GETSTATUSCHANGEW => "GetStatusChangeW",
        SCARD_IOCTL_CANCEL => "Cancel",
        SCARD_IOCTL_CONNECTA => "ConnectA",
        SCARD_IOCTL_CONNECTW => "ConnectW",
        SCARD_IOCTL_RECONNECT => "Reconnect",
        SCARD_IOCTL_DISCONNECT => "Disconnect",
        SCARD_IOCTL_BEGINTRANSACTION => "BeginTransaction",
        SCARD_IOCTL_ENDTRANSACTION => "EndTransaction",
        SCARD_IOCTL_STATE => "State",
        SCARD_IOCTL_STATUSA => "StatusA",
        SCARD_IOCTL_STATUSW => "StatusW",
        SCARD_IOCTL_TRANSMIT => "Transmit",
        SCARD_IOCTL_CONTROL => "Control",
        SCARD_IOCTL_GETATTRIB => "GetAttrib",
        SCARD_IOCTL_SETATTRIB => "SetAttrib",
        SCARD_IOCTL_ACCESSSTARTEDEVENT => "AccessStartedEvent",
        SCARD_IOCTL_RELEASETARTEDEVENT => "ReleaseStartedEvent",
        SCARD_IOCTL_READCACHEA | SCARD_IOCTL_READCACHEW => "ReadCache",
        SCARD_IOCTL_WRITECACHEA | SCARD_IOCTL_WRITECACHEW => "WriteCache",
        SCARD_IOCTL_GETDEVICETYPEID => "GetDeviceTypeId",
        _ => "other",
    }
}

/// True for the Unicode variant of an A/W call pair (W codes are A + 4).
fn is_wide(ioctl: u32) -> bool {
    matches!(
        ioctl,
        SCARD_IOCTL_LISTREADERGROUPSW
            | SCARD_IOCTL_LISTREADERSW
            | SCARD_IOCTL_LOCATECARDSW
            | SCARD_IOCTL_GETSTATUSCHANGEW
            | SCARD_IOCTL_CONNECTW
            | SCARD_IOCTL_STATUSW
            | SCARD_IOCTL_LOCATECARDSBYATRW
            | SCARD_IOCTL_READCACHEW
            | SCARD_IOCTL_WRITECACHEW
            | SCARD_IOCTL_GETDEVICETYPEID
    )
}

/// One reader in SCardGetStatusChange (ReaderState_Common_Call 2.2.1.5 /
/// ReaderState_Return 2.2.1.11). The backend updates `event_state` and
/// `atr`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReaderState {
    pub reader: String,
    pub current_state: u32,
    pub event_state: u32,
    /// At most 36 bytes.
    pub atr: Vec<u8>,
}

/// SCardIO_Request (2.2.1.8): protocol and protocol control information.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoPci {
    pub protocol: u32,
    pub extra: Vec<u8>,
}

/// SCardStatus result (Status_Return 2.2.3.10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardStatus {
    pub readers: Vec<String>,
    pub state: u32,
    pub protocol: u32,
    pub atr: Vec<u8>,
}

/// SCardTransmit result (Transmit_Return 2.2.3.11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transmitted {
    /// Returned only when the call passed a receive PCI.
    pub recv_pci: Option<IoPci>,
    pub data: Vec<u8>,
}

/// The local smart card layer (PC/SC). Handles are the backend's own
/// opaque values; the server never sees them. Every method may be called
/// from a worker thread, concurrently with others (Cancel during a waiting
/// GetStatusChange on the same context).
pub trait SmartCardBackend: Send + Sync {
    /// SCardAccessStartedEvent: Ok once the service runs (may block).
    fn access_started(&self) -> ScResult<()> {
        Ok(())
    }
    fn establish_context(&self, scope: u32) -> ScResult<u64>;
    fn release_context(&self, context: u64) -> ScResult<()>;
    fn is_valid_context(&self, context: u64) -> ScResult<()>;
    /// Reader names in `groups` (all readers when empty).
    fn list_readers(&self, context: u64, groups: &[String]) -> ScResult<Vec<String>>;
    /// Blocks until a state differs from `current_state`, `timeout_ms`
    /// passes (0xFFFFFFFF: never) or [`SmartCardBackend::cancel`] is called
    /// on `context`.
    fn get_status_change(
        &self,
        context: u64,
        timeout_ms: u32,
        states: &mut [ReaderState],
    ) -> ScResult<()>;
    fn cancel(&self, context: u64) -> ScResult<()>;
    /// Returns the card handle and the active protocol.
    fn connect(
        &self,
        context: u64,
        reader: &str,
        share_mode: u32,
        protocols: u32,
    ) -> ScResult<(u64, u32)>;
    /// Returns the active protocol.
    fn reconnect(&self, card: u64, share_mode: u32, protocols: u32, init: u32) -> ScResult<u32>;
    fn disconnect(&self, card: u64, disposition: u32) -> ScResult<()>;
    fn begin_transaction(&self, card: u64) -> ScResult<()>;
    fn end_transaction(&self, card: u64, disposition: u32) -> ScResult<()>;
    fn status(&self, card: u64) -> ScResult<CardStatus>;
    /// `recv_max`: the largest response accepted.
    fn transmit(
        &self,
        card: u64,
        send_pci: &IoPci,
        send: &[u8],
        recv_pci: Option<&IoPci>,
        recv_max: usize,
    ) -> ScResult<Transmitted>;
    fn control(&self, card: u64, code: u32, input: &[u8], out_max: usize) -> ScResult<Vec<u8>>;
    fn get_attrib(&self, card: u64, attr: u32, max: usize) -> ScResult<Vec<u8>>;
    fn set_attrib(&self, card: u64, attr: u32, data: &[u8]) -> ScResult<()>;
    fn get_device_type_id(&self, context: u64, reader: &str) -> ScResult<u32>;
}

/// The smart card device for [`super::RdpdrHandle::add_device`].
pub fn smart_card_device(backend: Arc<dyn SmartCardBackend>) -> Box<dyn Device> {
    Box::new(SmartCard::new(backend))
}
