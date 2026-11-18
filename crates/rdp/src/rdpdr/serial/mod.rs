//! Serial and parallel port redirection (MS-RDPESP) over the `rdpdr`
//! channel.
//!
//! [`port_device`] wraps one local port, reached through a [`SerialBackend`]
//! (the Win32 communications API on Windows), into a [`Device`] the UI adds
//! with [`super::RdpdrHandle::add_device`] and removes with
//! [`super::RdpdrHandle::remove`] at any time.
//!
//! # Messages (MS-RDPESP 2.2.2)
//!
//! MS-RDPESP defines no PDUs of its own; it uses the MS-RDPEFS ones:
//! - announce (2.2.2.1): a DEVICE_ANNOUNCE with DeviceType
//!   [`RDPDR_DTYP_SERIAL`] or [`RDPDR_DTYP_PARALLEL`], the port name
//!   ("COM3", "LPT1") as PreferredDosName and no DeviceData;
//! - create / close (2.2.2.2-3, 2.2.2.7-8): open and close one instance of
//!   the port; the create answer carries a FileId and Information 0
//!   (3.2.5.1.7);
//! - read / write (2.2.2.4-5, 2.2.2.9-10): Offset is ignored, partial reads
//!   are allowed (3.2.5.1.4, 3.2.5.1.9);
//! - device control (2.2.2.6, 2.2.2.11): the serial and parallel IOCTLs of
//!   the table in 2.2.2.6 with the ntddser.h / ntddpar.h buffers
//!   (Appendix A note 2): InputBuffer is the IRP's system buffer and the
//!   response's OutputBuffer the bytes the driver returned.
//!
//! The Client Drive Device List Remove PDU "is not supported by the
//! MS-RDPESP protocol" (2.2.2.1, note). The core still sends it when a port
//! is unshared; Windows servers remove any announced device by DeviceId, a
//! server that keeps the port gets `STATUS_NOT_SUPPORTED` for every later
//! request on it from the core (the device id is unknown then).
//!
//! # IOCTLs
//!
//! [`decode_ioctl`] turns an IoControlCode and its InputBuffer into a typed
//! [`SerialControl`], checking buffer sizes and values the way the Windows
//! serial driver does (`STATUS_BUFFER_TOO_SMALL`, `STATUS_INVALID_PARAMETER`);
//! the backend answers with a [`ControlOut`] that [`ControlOut::encode`] turns
//! into the OutputBuffer. IOCTLs of the 2.2.2.6 table that have no typed form
//! (statistics, modem control, FIFO control, LSR/MST insertion, reset and
//! every parallel port IOCTL) reach the backend as [`SerialControl::Raw`];
//! codes outside the table are answered `STATUS_NOT_SUPPORTED` and never
//! reach the local driver. IOCTL_SERIAL_XOFF_COUNTER (a request that stays
//! pending until a counter runs out) is not supported.
//!
//! # Pending requests and cancel
//!
//! Reads, writes and IOCTL_SERIAL_WAIT_ON_MASK can block for as long as the
//! port's timeouts allow (forever, with the default timeouts), so they never
//! run on the session worker: every open instance has one worker thread per
//! kind of work (read, write, wait, control), each running its requests in
//! the order they came, and their completions are sent from `tick`. Opening
//! a port runs on a short worker thread too (Bluetooth ports connect while
//! they open). Pending requests end:
//! - IRP_MJ_CLOSE: every pending request of that instance completes with
//!   `STATUS_CANCELLED` before the close response (3.2.5.1.3: the client
//!   "MUST also cancel pending IO operations");
//! - IOCTL_SERIAL_PURGE with SERIAL_PURGE_RXABORT / TXABORT: pending reads /
//!   writes complete with `STATUS_CANCELLED`;
//! - IOCTL_SERIAL_SET_WAIT_MASK: a pending WAIT_ON_MASK completes with
//!   `STATUS_SUCCESS` and an event mask of 0 (the serial driver's rule);
//! - device removal or a redirection restart: every instance is closed and
//!   nothing more is sent for it.
//!
//! Each pending request carries an internal token, so a late result from the
//! backend for a request already answered is dropped even when the server
//! has reused its CompletionId. Data read from the port is never traced.

mod device;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use super::Device;
use crate::cursor::{Put, Reader};

pub use super::{RDPDR_DTYP_PARALLEL, RDPDR_DTYP_SERIAL};
pub use device::SerialPortDevice;

/// A backend result: the value or the NTSTATUS (MS-ERREF 2.3) sent to the
/// server.
pub type PortResult<T> = Result<T, u32>;

/// STATUS_CANCELLED (MS-ERREF 2.3.1).
pub const STATUS_CANCELLED: u32 = 0xC000_0120;
/// STATUS_BUFFER_TOO_SMALL (MS-ERREF 2.3.1).
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// STATUS_INSUFFICIENT_RESOURCES (MS-ERREF 2.3.1).
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// STATUS_DEVICE_REMOVED (MS-ERREF 2.3.1): the port went away (USB unplug).
pub const STATUS_DEVICE_REMOVED: u32 = 0xC000_02B6;

/// Serial IOCTL codes (MS-RDPESP 2.2.2.6).
pub const IOCTL_SERIAL_SET_BAUD_RATE: u32 = 0x001B_0004;
pub const IOCTL_SERIAL_GET_BAUD_RATE: u32 = 0x001B_0050;
pub const IOCTL_SERIAL_SET_LINE_CONTROL: u32 = 0x001B_000C;
pub const IOCTL_SERIAL_GET_LINE_CONTROL: u32 = 0x001B_0054;
pub const IOCTL_SERIAL_SET_TIMEOUTS: u32 = 0x001B_001C;
pub const IOCTL_SERIAL_GET_TIMEOUTS: u32 = 0x001B_0020;
pub const IOCTL_SERIAL_SET_CHARS: u32 = 0x001B_0058;
pub const IOCTL_SERIAL_GET_CHARS: u32 = 0x001B_005C;
pub const IOCTL_SERIAL_SET_DTR: u32 = 0x001B_0024;
pub const IOCTL_SERIAL_CLR_DTR: u32 = 0x001B_0028;
pub const IOCTL_SERIAL_RESET_DEVICE: u32 = 0x001B_002C;
pub const IOCTL_SERIAL_SET_RTS: u32 = 0x001B_0030;
pub const IOCTL_SERIAL_CLR_RTS: u32 = 0x001B_0034;
pub const IOCTL_SERIAL_SET_XOFF: u32 = 0x001B_0038;
pub const IOCTL_SERIAL_SET_XON: u32 = 0x001B_003C;
pub const IOCTL_SERIAL_SET_BREAK_ON: u32 = 0x001B_0010;
pub const IOCTL_SERIAL_SET_BREAK_OFF: u32 = 0x001B_0014;
pub const IOCTL_SERIAL_SET_QUEUE_SIZE: u32 = 0x001B_0008;
pub const IOCTL_SERIAL_GET_WAIT_MASK: u32 = 0x001B_0040;
pub const IOCTL_SERIAL_SET_WAIT_MASK: u32 = 0x001B_0044;
pub const IOCTL_SERIAL_WAIT_ON_MASK: u32 = 0x001B_0048;
pub const IOCTL_SERIAL_IMMEDIATE_CHAR: u32 = 0x001B_0018;
pub const IOCTL_SERIAL_PURGE: u32 = 0x001B_004C;
pub const IOCTL_SERIAL_GET_HANDFLOW: u32 = 0x001B_0060;
pub const IOCTL_SERIAL_SET_HANDFLOW: u32 = 0x001B_0064;
pub const IOCTL_SERIAL_GET_MODEMSTATUS: u32 = 0x001B_0068;
pub const IOCTL_SERIAL_GET_DTRRTS: u32 = 0x001B_0078;
pub const IOCTL_SERIAL_GET_COMMSTATUS: u32 = 0x001B_006C;
pub const IOCTL_SERIAL_GET_PROPERTIES: u32 = 0x001B_0074;
pub const IOCTL_SERIAL_XOFF_COUNTER: u32 = 0x001B_0070;
pub const IOCTL_SERIAL_LSRMST_INSERT: u32 = 0x001B_007C;
pub const IOCTL_SERIAL_CONFIG_SIZE: u32 = 0x001B_0080;
pub const IOCTL_SERIAL_GET_STATS: u32 = 0x001B_008C;
pub const IOCTL_SERIAL_CLEAR_STATS: u32 = 0x001B_0090;
pub const IOCTL_SERIAL_GET_MODEM_CONTROL: u32 = 0x001B_0094;
pub const IOCTL_SERIAL_SET_MODEM_CONTROL: u32 = 0x001B_0098;
pub const IOCTL_SERIAL_SET_FIFO_CONTROL: u32 = 0x001B_009C;

/// Parallel IOCTL codes (MS-RDPESP 2.2.2.6).
pub const IOCTL_PAR_QUERY_INFORMATION: u32 = 0x0016_0004;
pub const IOCTL_PAR_SET_INFORMATION: u32 = 0x0016_0008;
pub const IOCTL_PAR_QUERY_DEVICE_ID: u32 = 0x0016_000C;
pub const IOCTL_PAR_QUERY_DEVICE_ID_SIZE: u32 = 0x0016_0010;
pub const IOCTL_IEEE1284_GET_MODE: u32 = 0x0016_0014;
pub const IOCTL_IEEE1284_NEGOTIATE: u32 = 0x0016_0018;
pub const IOCTL_PAR_SET_WRITE_ADDRESS: u32 = 0x0016_001C;
pub const IOCTL_PAR_SET_READ_ADDRESS: u32 = 0x0016_0020;
pub const IOCTL_PAR_GET_DEVICE_CAPS: u32 = 0x0016_0024;
pub const IOCTL_PAR_GET_DEFAULT_MODES: u32 = 0x0016_0028;
pub const IOCTL_PAR_QUERY_RAW_DEVICE_ID: u32 = 0x0016_0030;
pub const IOCTL_PAR_IS_PORT_FREE: u32 = 0x0016_0054;

/// The 2.2.2.6 IOCTLs passed to the local driver unchanged
/// ([`SerialControl::Raw`]): no typed form, but in the table.
pub const RAW_SERIAL_IOCTLS: [u32; 7] = [
    IOCTL_SERIAL_RESET_DEVICE,
    IOCTL_SERIAL_LSRMST_INSERT,
    IOCTL_SERIAL_GET_STATS,
    IOCTL_SERIAL_CLEAR_STATS,
    IOCTL_SERIAL_GET_MODEM_CONTROL,
    IOCTL_SERIAL_SET_MODEM_CONTROL,
    IOCTL_SERIAL_SET_FIFO_CONTROL,
];
pub const PARALLEL_IOCTLS: [u32; 12] = [
    IOCTL_PAR_QUERY_INFORMATION,
    IOCTL_PAR_SET_INFORMATION,
    IOCTL_PAR_QUERY_DEVICE_ID,
    IOCTL_PAR_QUERY_DEVICE_ID_SIZE,
    IOCTL_IEEE1284_GET_MODE,
    IOCTL_IEEE1284_NEGOTIATE,
    IOCTL_PAR_SET_WRITE_ADDRESS,
    IOCTL_PAR_SET_READ_ADDRESS,
    IOCTL_PAR_GET_DEVICE_CAPS,
    IOCTL_PAR_GET_DEFAULT_MODES,
    IOCTL_PAR_QUERY_RAW_DEVICE_ID,
    IOCTL_PAR_IS_PORT_FREE,
];

/// SERIAL_LINE_CONTROL values (ntddser.h).
pub const STOP_BIT_1: u8 = 0;
pub const STOP_BITS_1_5: u8 = 1;
pub const STOP_BITS_2: u8 = 2;
pub const NO_PARITY: u8 = 0;
pub const ODD_PARITY: u8 = 1;
pub const EVEN_PARITY: u8 = 2;
pub const MARK_PARITY: u8 = 3;
pub const SPACE_PARITY: u8 = 4;

/// SERIAL_HANDFLOW ControlHandShake bits (ntddser.h).
pub const SERIAL_DTR_MASK: u32 = 0x0000_0003;
pub const SERIAL_DTR_CONTROL: u32 = 0x0000_0001;
pub const SERIAL_DTR_HANDSHAKE: u32 = 0x0000_0002;
pub const SERIAL_CTS_HANDSHAKE: u32 = 0x0000_0008;
pub const SERIAL_DSR_HANDSHAKE: u32 = 0x0000_0010;
pub const SERIAL_DCD_HANDSHAKE: u32 = 0x0000_0020;
pub const SERIAL_DSR_SENSITIVITY: u32 = 0x0000_0040;
pub const SERIAL_ERROR_ABORT: u32 = 0x8000_0000;
pub const SERIAL_CONTROL_INVALID: u32 = 0x7FFF_FF84;
/// SERIAL_HANDFLOW FlowReplace bits (ntddser.h).
pub const SERIAL_AUTO_TRANSMIT: u32 = 0x0000_0001;
pub const SERIAL_AUTO_RECEIVE: u32 = 0x0000_0002;
pub const SERIAL_ERROR_CHAR: u32 = 0x0000_0004;
pub const SERIAL_NULL_STRIPPING: u32 = 0x0000_0008;
pub const SERIAL_BREAK_CHAR: u32 = 0x0000_0010;
pub const SERIAL_RTS_MASK: u32 = 0x0000_00C0;
pub const SERIAL_RTS_CONTROL: u32 = 0x0000_0040;
pub const SERIAL_RTS_HANDSHAKE: u32 = 0x0000_0080;
pub const SERIAL_TRANSMIT_TOGGLE: u32 = 0x0000_00C0;
pub const SERIAL_XOFF_CONTINUE: u32 = 0x8000_0000;
pub const SERIAL_FLOW_INVALID: u32 = 0x7FFF_FF20;

/// Wait mask events (SERIAL_EV_*, ntddser.h); the Win32 EV_* values are the
/// same.
pub const SERIAL_EV_RXCHAR: u32 = 0x0001;
pub const SERIAL_EV_RXFLAG: u32 = 0x0002;
pub const SERIAL_EV_TXEMPTY: u32 = 0x0004;
pub const SERIAL_EV_CTS: u32 = 0x0008;
pub const SERIAL_EV_DSR: u32 = 0x0010;
pub const SERIAL_EV_RLSD: u32 = 0x0020;
pub const SERIAL_EV_BREAK: u32 = 0x0040;
pub const SERIAL_EV_ERR: u32 = 0x0080;
pub const SERIAL_EV_RING: u32 = 0x0100;
pub const SERIAL_EV_PERR: u32 = 0x0200;
pub const SERIAL_EV_RX80FULL: u32 = 0x0400;
pub const SERIAL_EV_EVENT1: u32 = 0x0800;
pub const SERIAL_EV_EVENT2: u32 = 0x1000;
/// Every defined event bit.
pub const SERIAL_EV_ALL: u32 = 0x1FFF;

/// Purge bits (SERIAL_PURGE_*, ntddser.h); the Win32 PURGE_* values are the
/// same.
pub const SERIAL_PURGE_TXABORT: u32 = 0x0000_0001;
pub const SERIAL_PURGE_RXABORT: u32 = 0x0000_0002;
pub const SERIAL_PURGE_TXCLEAR: u32 = 0x0000_0004;
pub const SERIAL_PURGE_RXCLEAR: u32 = 0x0000_0008;

/// IOCTL_SERIAL_GET_DTRRTS bits (ntddser.h).
pub const SERIAL_DTR_STATE: u32 = 0x0000_0001;
pub const SERIAL_RTS_STATE: u32 = 0x0000_0002;

/// SERIAL_STATUS Errors bits (ntddser.h).
pub const SERIAL_ERROR_BREAK: u32 = 0x0000_0001;
pub const SERIAL_ERROR_FRAMING: u32 = 0x0000_0002;
pub const SERIAL_ERROR_OVERRUN: u32 = 0x0000_0004;
pub const SERIAL_ERROR_QUEUEOVERRUN: u32 = 0x0000_0008;
pub const SERIAL_ERROR_PARITY: u32 = 0x0000_0010;
/// SERIAL_STATUS HoldReasons bits (ntddser.h).
pub const SERIAL_TX_WAITING_FOR_CTS: u32 = 0x0000_0001;
pub const SERIAL_TX_WAITING_FOR_DSR: u32 = 0x0000_0002;
pub const SERIAL_TX_WAITING_FOR_DCD: u32 = 0x0000_0004;
pub const SERIAL_TX_WAITING_FOR_XON: u32 = 0x0000_0008;
pub const SERIAL_TX_WAITING_XOFF_SENT: u32 = 0x0000_0010;
pub const SERIAL_TX_WAITING_ON_BREAK: u32 = 0x0000_0020;
pub const SERIAL_RX_WAITING_FOR_DSR: u32 = 0x0000_0040;

/// Size of SERIAL_COMMPROP (ntddser.h): 60 bytes of fields, one WCHAR
/// ProvChar, padded to 4.
pub const SERIAL_COMMPROP_LEN: usize = 64;
/// Size of SERIAL_STATUS (ntddser.h): 4 ULONGs, 2 BOOLEANs, padded to 4.
pub const SERIAL_STATUS_LEN: usize = 20;

/// Serial or parallel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    Serial,
    Parallel,
}

impl PortKind {
    /// The DeviceType of the announce (MS-RDPESP 2.2.2.1).
    pub fn device_type(self) -> u32 {
        match self {
            PortKind::Serial => RDPDR_DTYP_SERIAL,
            PortKind::Parallel => RDPDR_DTYP_PARALLEL,
        }
    }

    /// From a Windows port name: COMn serial, LPTn parallel.
    pub fn of_name(name: &str) -> Option<PortKind> {
        let upper = name.to_ascii_uppercase();
        let (kind, digits) = match upper.strip_prefix("COM") {
            Some(d) => (PortKind::Serial, d),
            None => (PortKind::Parallel, upper.strip_prefix("LPT")?),
        };
        let ok = !digits.is_empty()
            && digits.len() <= 3
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0');
        ok.then_some(kind)
    }
}

/// SERIAL_LINE_CONTROL (ntddser.h): StopBits, Parity, WordLength.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineControl {
    pub stop_bits: u8,
    pub parity: u8,
    pub word_length: u8,
}

impl LineControl {
    pub const LEN: usize = 3;

    pub fn decode(b: &[u8]) -> PortResult<Self> {
        let mut r = reader(b, Self::LEN)?;
        let v = Self {
            stop_bits: r.u8().map_err(too_small)?,
            parity: r.u8().map_err(too_small)?,
            word_length: r.u8().map_err(too_small)?,
        };
        // The serial driver's checks: 5-8 data bits, defined parity and stop
        // bits, no 1.5 stop bits with more than 5 data bits nor 2 with 5.
        let valid = (5..=8).contains(&v.word_length)
            && v.parity <= SPACE_PARITY
            && v.stop_bits <= STOP_BITS_2
            && !(v.stop_bits == STOP_BITS_1_5 && v.word_length != 5)
            && !(v.stop_bits == STOP_BITS_2 && v.word_length == 5);
        if valid { Ok(v) } else { Err(INVALID) }
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![self.stop_bits, self.parity, self.word_length]
    }
}

/// SERIAL_TIMEOUTS (ntddser.h), the same layout as Win32 COMMTIMEOUTS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timeouts {
    pub read_interval: u32,
    pub read_total_multiplier: u32,
    pub read_total_constant: u32,
    pub write_total_multiplier: u32,
    pub write_total_constant: u32,
}

impl Timeouts {
    pub const LEN: usize = 20;

    pub fn decode(b: &[u8]) -> PortResult<Self> {
        let mut r = reader(b, Self::LEN)?;
        let mut next = || r.u32().map_err(too_small);
        let v = Self {
            read_interval: next()?,
            read_total_multiplier: next()?,
            read_total_constant: next()?,
            write_total_multiplier: next()?,
            write_total_constant: next()?,
        };
        // Both MAXULONG is reserved (serial driver).
        if v.read_interval == u32::MAX && v.read_total_constant == u32::MAX {
            return Err(INVALID);
        }
        Ok(v)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::LEN);
        for x in [
            self.read_interval,
            self.read_total_multiplier,
            self.read_total_constant,
            self.write_total_multiplier,
            self.write_total_constant,
        ] {
            v.put_u32(x);
        }
        v
    }
}

/// SERIAL_CHARS (ntddser.h).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Chars {
    pub eof: u8,
    pub error: u8,
    pub brk: u8,
    pub event: u8,
    pub xon: u8,
    pub xoff: u8,
}

impl Chars {
    pub const LEN: usize = 6;

    pub fn decode(b: &[u8]) -> PortResult<Self> {
        let b: [u8; 6] = b
            .get(..Self::LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(STATUS_BUFFER_TOO_SMALL)?;
        let v = Self {
            eof: b[0],
            error: b[1],
            brk: b[2],
            event: b[3],
            xon: b[4],
            xoff: b[5],
        };
        Ok(v)
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.eof, self.error, self.brk, self.event, self.xon, self.xoff,
        ]
    }
}

/// SERIAL_HANDFLOW (ntddser.h).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Handflow {
    pub control_handshake: u32,
    pub flow_replace: u32,
    pub xon_limit: i32,
    pub xoff_limit: i32,
}

impl Handflow {
    pub const LEN: usize = 16;

    pub fn decode(b: &[u8]) -> PortResult<Self> {
        let mut r = reader(b, Self::LEN)?;
        let mut next = || r.u32().map_err(too_small);
        let v = Self {
            control_handshake: next()?,
            flow_replace: next()?,
            xon_limit: next()? as i32,
            xoff_limit: next()? as i32,
        };
        // Reserved bits, DTR control and handshake together, negative
        // limits: the serial driver refuses them.
        let valid = v.control_handshake & SERIAL_CONTROL_INVALID == 0
            && v.flow_replace & SERIAL_FLOW_INVALID == 0
            && v.control_handshake & SERIAL_DTR_MASK != SERIAL_DTR_MASK
            && v.xon_limit >= 0
            && v.xoff_limit >= 0;
        if valid { Ok(v) } else { Err(INVALID) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::LEN);
        v.put_u32(self.control_handshake);
        v.put_u32(self.flow_replace);
        v.put_u32(self.xon_limit as u32);
        v.put_u32(self.xoff_limit as u32);
        v
    }
}

/// SERIAL_STATUS (ntddser.h): IOCTL_SERIAL_GET_COMMSTATUS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommStatus {
    /// SERIAL_ERROR_* bits, cleared by the read.
    pub errors: u32,
    /// SERIAL_TX_WAITING_* / SERIAL_RX_WAITING_* bits.
    pub hold_reasons: u32,
    pub in_queue: u32,
    pub out_queue: u32,
    pub eof_received: bool,
    pub wait_for_immediate: bool,
}

impl CommStatus {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SERIAL_STATUS_LEN);
        v.put_u32(self.errors);
        v.put_u32(self.hold_reasons);
        v.put_u32(self.in_queue);
        v.put_u32(self.out_queue);
        v.put_u8(self.eof_received as u8);
        v.put_u8(self.wait_for_immediate as u8);
        v.put_zeros(2);
        v
    }
}

/// SERIAL_COMMPROP (ntddser.h), the same layout as Win32 COMMPROP:
/// IOCTL_SERIAL_GET_PROPERTIES.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommProp {
    pub packet_length: u16,
    pub packet_version: u16,
    pub service_mask: u32,
    pub max_tx_queue: u32,
    pub max_rx_queue: u32,
    pub max_baud: u32,
    pub prov_sub_type: u32,
    pub prov_capabilities: u32,
    pub settable_params: u32,
    pub settable_baud: u32,
    pub settable_data: u16,
    pub settable_stop_parity: u16,
    pub current_tx_queue: u32,
    pub current_rx_queue: u32,
    pub prov_spec1: u32,
    pub prov_spec2: u32,
}

impl CommProp {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SERIAL_COMMPROP_LEN);
        v.put_u16(self.packet_length);
        v.put_u16(self.packet_version);
        v.put_u32(self.service_mask);
        v.put_u32(0); // Reserved1
        for x in [
            self.max_tx_queue,
            self.max_rx_queue,
            self.max_baud,
            self.prov_sub_type,
            self.prov_capabilities,
            self.settable_params,
            self.settable_baud,
        ] {
            v.put_u32(x);
        }
        v.put_u16(self.settable_data);
        v.put_u16(self.settable_stop_parity);
        for x in [
            self.current_tx_queue,
            self.current_rx_queue,
            self.prov_spec1,
            self.prov_spec2,
        ] {
            v.put_u32(x);
        }
        v.put_zeros(SERIAL_COMMPROP_LEN - v.len()); // ProvChar and padding
        v
    }
}

/// Line signal changes (the IOCTLs without buffers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineOp {
    SetDtr,
    ClrDtr,
    SetRts,
    ClrRts,
    /// Act as if XOFF was received.
    SetXoff,
    /// Act as if XON was received.
    SetXon,
    BreakOn,
    BreakOff,
}

/// One decoded device control request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialControl {
    SetBaudRate(u32),
    GetBaudRate,
    SetLineControl(LineControl),
    GetLineControl,
    SetTimeouts(Timeouts),
    GetTimeouts,
    SetChars(Chars),
    GetChars,
    SetHandflow(Handflow),
    GetHandflow,
    /// SERIAL_QUEUE_SIZE: recommended input and output buffer sizes.
    SetQueueSize {
        input: u32,
        output: u32,
    },
    SetWaitMask(u32),
    GetWaitMask,
    /// SERIAL_PURGE_* bits.
    Purge(u32),
    Line(LineOp),
    ImmediateChar(u8),
    /// The modem status register (CTS 0x10, DSR 0x20, RI 0x40, DCD 0x80).
    GetModemStatus,
    /// SERIAL_DTR_STATE | SERIAL_RTS_STATE.
    GetDtrRts,
    GetCommStatus,
    GetProperties,
    /// A 2.2.2.6 IOCTL without a typed form ([`RAW_SERIAL_IOCTLS`],
    /// [`PARALLEL_IOCTLS`]), for the local driver as it is.
    Raw {
        code: u32,
        input: Vec<u8>,
        output_len: u32,
    },
}

/// What a [`SerialControl`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOut {
    None,
    U32(u32),
    LineControl(LineControl),
    Timeouts(Timeouts),
    Chars(Chars),
    Handflow(Handflow),
    Status(CommStatus),
    Properties(CommProp),
    /// A raw IOCTL's output, cut to the request's OutputBufferLength.
    Bytes(Vec<u8>),
}

impl ControlOut {
    /// The OutputBuffer bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ControlOut::None => Vec::new(),
            ControlOut::U32(v) => v.to_le_bytes().to_vec(),
            ControlOut::LineControl(v) => v.encode(),
            ControlOut::Timeouts(v) => v.encode(),
            ControlOut::Chars(v) => v.encode(),
            ControlOut::Handflow(v) => v.encode(),
            ControlOut::Status(v) => v.encode(),
            ControlOut::Properties(v) => v.encode(),
            ControlOut::Bytes(v) => v.clone(),
        }
    }
}

const INVALID: u32 = super::fscc::STATUS_INVALID_PARAMETER;

fn too_small(_: crate::error::Error) -> u32 {
    STATUS_BUFFER_TOO_SMALL
}

fn reader(b: &[u8], need: usize) -> PortResult<Reader<'_>> {
    if b.len() < need {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(Reader::new(b))
}

fn u32_in(b: &[u8]) -> PortResult<u32> {
    let mut r = reader(b, 4)?;
    r.u32().map_err(too_small)
}

/// The OutputBufferLength a request needs (the serial driver answers
/// `STATUS_BUFFER_TOO_SMALL` below it).
pub fn output_needed(c: &SerialControl) -> usize {
    match c {
        SerialControl::GetBaudRate
        | SerialControl::GetWaitMask
        | SerialControl::GetModemStatus
        | SerialControl::GetDtrRts => 4,
        SerialControl::GetLineControl => LineControl::LEN,
        SerialControl::GetTimeouts => Timeouts::LEN,
        SerialControl::GetChars => Chars::LEN,
        SerialControl::GetHandflow => Handflow::LEN,
        SerialControl::GetCommStatus => SERIAL_STATUS_LEN,
        SerialControl::GetProperties => SERIAL_COMMPROP_LEN,
        _ => 0,
    }
}

/// Decodes one DR_CONTROL_REQ (MS-RDPESP 2.2.2.6) for a port of `kind`.
/// IOCTL_SERIAL_WAIT_ON_MASK and IOCTL_SERIAL_CONFIG_SIZE are answered by the
/// device itself and are not decoded here. `Err` is the NTSTATUS to answer.
pub fn decode_ioctl(
    kind: PortKind,
    code: u32,
    input: &[u8],
    output_len: u32,
) -> PortResult<SerialControl> {
    use SerialControl as C;
    if kind == PortKind::Parallel {
        return if PARALLEL_IOCTLS.contains(&code) {
            Ok(C::Raw {
                code,
                input: input.to_vec(),
                output_len,
            })
        } else {
            Err(super::fscc::STATUS_NOT_SUPPORTED)
        };
    }
    let c = match code {
        IOCTL_SERIAL_SET_BAUD_RATE => {
            let baud = u32_in(input)?;
            if baud == 0 {
                return Err(INVALID);
            }
            C::SetBaudRate(baud)
        }
        IOCTL_SERIAL_GET_BAUD_RATE => C::GetBaudRate,
        IOCTL_SERIAL_SET_LINE_CONTROL => C::SetLineControl(LineControl::decode(input)?),
        IOCTL_SERIAL_GET_LINE_CONTROL => C::GetLineControl,
        IOCTL_SERIAL_SET_TIMEOUTS => C::SetTimeouts(Timeouts::decode(input)?),
        IOCTL_SERIAL_GET_TIMEOUTS => C::GetTimeouts,
        IOCTL_SERIAL_SET_CHARS => C::SetChars(Chars::decode(input)?),
        IOCTL_SERIAL_GET_CHARS => C::GetChars,
        IOCTL_SERIAL_SET_HANDFLOW => C::SetHandflow(Handflow::decode(input)?),
        IOCTL_SERIAL_GET_HANDFLOW => C::GetHandflow,
        IOCTL_SERIAL_SET_QUEUE_SIZE => {
            let mut r = reader(input, 8)?;
            C::SetQueueSize {
                input: r.u32().map_err(too_small)?,
                output: r.u32().map_err(too_small)?,
            }
        }
        IOCTL_SERIAL_SET_WAIT_MASK => {
            let mask = u32_in(input)?;
            if mask & !SERIAL_EV_ALL != 0 {
                return Err(INVALID);
            }
            C::SetWaitMask(mask)
        }
        IOCTL_SERIAL_GET_WAIT_MASK => C::GetWaitMask,
        IOCTL_SERIAL_PURGE => {
            let mask = u32_in(input)?;
            let all = SERIAL_PURGE_TXABORT
                | SERIAL_PURGE_RXABORT
                | SERIAL_PURGE_TXCLEAR
                | SERIAL_PURGE_RXCLEAR;
            if mask == 0 || mask & !all != 0 {
                return Err(INVALID);
            }
            C::Purge(mask)
        }
        IOCTL_SERIAL_SET_DTR => C::Line(LineOp::SetDtr),
        IOCTL_SERIAL_CLR_DTR => C::Line(LineOp::ClrDtr),
        IOCTL_SERIAL_SET_RTS => C::Line(LineOp::SetRts),
        IOCTL_SERIAL_CLR_RTS => C::Line(LineOp::ClrRts),
        IOCTL_SERIAL_SET_XOFF => C::Line(LineOp::SetXoff),
        IOCTL_SERIAL_SET_XON => C::Line(LineOp::SetXon),
        IOCTL_SERIAL_SET_BREAK_ON => C::Line(LineOp::BreakOn),
        IOCTL_SERIAL_SET_BREAK_OFF => C::Line(LineOp::BreakOff),
        IOCTL_SERIAL_IMMEDIATE_CHAR => {
            C::ImmediateChar(*input.first().ok_or(STATUS_BUFFER_TOO_SMALL)?)
        }
        IOCTL_SERIAL_GET_MODEMSTATUS => C::GetModemStatus,
        IOCTL_SERIAL_GET_DTRRTS => C::GetDtrRts,
        IOCTL_SERIAL_GET_COMMSTATUS => C::GetCommStatus,
        IOCTL_SERIAL_GET_PROPERTIES => C::GetProperties,
        c if RAW_SERIAL_IOCTLS.contains(&c) => C::Raw {
            code,
            input: input.to_vec(),
            output_len,
        },
        _ => return Err(super::fscc::STATUS_NOT_SUPPORTED),
    };
    if (output_len as usize) < output_needed(&c) {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(c)
}

/// The local ports, as the UI and settings name them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInfo {
    /// "COM3", "LPT1": the name opened and announced.
    pub name: String,
    pub kind: PortKind,
}

impl PortInfo {
    /// None unless `name` is COMn or LPTn.
    pub fn new(name: &str) -> Option<PortInfo> {
        let kind = PortKind::of_name(name)?;
        Some(PortInfo {
            name: name.to_ascii_uppercase(),
            kind,
        })
    }
}

/// The local port system: opens ports by name.
pub trait SerialBackend: Send + Sync {
    /// Opens `port` ("COM3", "LPT1") for exclusive use. May block for a
    /// while (it runs on a worker thread). `Err`: the NTSTATUS for the
    /// server (for example `STATUS_ACCESS_DENIED` when another program has
    /// the port open).
    fn open(&self, port: &str) -> PortResult<Arc<dyn SerialPort>>;
}

/// One open instance of a local port. Every method may run on a different
/// worker thread at the same time as the others (a read pending while a
/// write and an IOCTL run). A blocked [`SerialPort::read`],
/// [`SerialPort::write`] or [`SerialPort::wait_event`] must return
/// `Err(STATUS_CANCELLED)` (or its result) promptly after a purge with the
/// matching abort bit, a new wait mask, or [`SerialPort::close`].
pub trait SerialPort: Send + Sync {
    /// Reads up to `max` bytes, as the port's timeouts say (a read may
    /// return fewer bytes, or none on a timeout).
    fn read(&self, max: usize) -> PortResult<Vec<u8>>;
    /// Writes `data`; returns the bytes written (fewer on a write timeout).
    fn write(&self, data: &[u8]) -> PortResult<u32>;
    /// Waits for one of the wait mask's events; returns the events seen
    /// (0 when the wait mask was changed meanwhile).
    fn wait_event(&self) -> PortResult<u32>;
    /// Runs one device control request.
    fn control(&self, c: &SerialControl) -> PortResult<ControlOut>;
    /// Cancels everything pending and releases the port; later calls fail.
    fn close(&self);
}

/// The device for one local port, for [`super::RdpdrHandle::add_device`].
/// `None` unless `port` is a COMn or LPTn name.
pub fn port_device(port: &str, backend: Arc<dyn SerialBackend>) -> Option<Box<dyn Device>> {
    let info = PortInfo::new(port)?;
    Some(Box::new(SerialPortDevice::new(info, backend)))
}
