//! Device redirection, client side (MS-RDPEFS) on the `rdpdr` static channel.
//!
//! [`rdpdr`] returns the channel handler ([`Rdpdr`], given to
//! [`crate::Client::connect_with`]) and a [`RdpdrHandle`] the UI keeps. The
//! handle adds and removes devices at any time; the changes are applied on the
//! session worker in [`Rdpdr`]'s `tick`. Devices added before the server's
//! User Logged On PDU wait and are announced right after it (MS-RDPEFS
//! 3.2.5.1.6/3.2.5.1.7); later additions are announced at once and removals
//! send a Client Drive Device List Remove (2.2.3.2) and close every handle the
//! server still had open on that device.
//!
//! Modules:
//! - [`core`] (private): the core PDUs (2.2.2.x) and the channel state machine
//! - [`drive`]: the file system device ([`Drive`], 2.2.3 / 3.2.5.2)
//! - [`path`]: the path checks that keep every server path inside a drive root
//! - [`printer`]: the printer device ([`Printer`], MS-RDPEPC) and its
//!   [`PrintBackend`]
//! - [`fscc`]: NTSTATUS values, FILETIME conversion and MS-FSCC structures
//! - [`smartcard`]: smart card redirection (MS-RDPESC), [`smart_card_device`]
//!
//! # Devices
//!
//! Every redirected device implements [`Device`]. The core owns device ids,
//! the announce/remove PDUs and the Device I/O Request/Response framing
//! (2.2.1.4/2.2.1.5); a device only sees decoded [`IoRequest`]s and returns
//! the function-specific tail of its response in an [`IoCompletion`].
//! Requests for an unknown device id, or that a device does not handle, are
//! completed with `STATUS_NOT_SUPPORTED`, never dropped.
//!
//! How the planned devices (RDP-7) plug in, without core or capability changes
//! (the client already advertises printer, port and smart card capability sets):
//! - **Printer (MS-RDPEPC):** `device_type` = [`RDPDR_DTYP_PRINT`]; `device_data`
//!   is the DR_PRN_DEVICE_ANNOUNCE data (MS-RDPEPC 2.2.2.1: flags, code page,
//!   PnP/driver/printer names, cached config). `io` handles IRP_MJ_CREATE (open
//!   a print job), IRP_MJ_WRITE (spool data) and IRP_MJ_CLOSE (send the job to
//!   the local printer) and completes each at once.
//! - **Smart card (MS-RDPESC):** `device_type` = [`RDPDR_DTYP_SMARTCARD`],
//!   `preferred_dos_name` "SCARD", `announce_before_logon` returns true (smart
//!   cards are needed for logon). `io` receives IRP_MJ_DEVICE_CONTROL with an
//!   IOCTL_SCARD_* code and an NDR-encoded call; calls that block (for example
//!   SCardGetStatusChange) return `None`, run on a worker thread of the device,
//!   and their completions are returned from `tick` when ready.

mod core;
pub mod drive;
pub mod fscc;
pub mod path;
pub mod printer;
pub mod smartcard;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub use self::core::Rdpdr;
pub use self::drive::Drive;
pub use self::printer::{
    PrintBackend, PrintFormat, Printer, PrinterInfo, SharedBackend, share_printers,
};
pub use self::smartcard::{SmartCard, SmartCardBackend, smart_card_device};

/// DeviceType values (MS-RDPEFS 2.2.1.3).
pub const RDPDR_DTYP_SERIAL: u32 = 0x0000_0001;
pub const RDPDR_DTYP_PARALLEL: u32 = 0x0000_0002;
pub const RDPDR_DTYP_PRINT: u32 = 0x0000_0004;
pub const RDPDR_DTYP_FILESYSTEM: u32 = 0x0000_0008;
pub const RDPDR_DTYP_SMARTCARD: u32 = 0x0000_0020;

/// MajorFunction values of the Device I/O Request (MS-RDPEFS 2.2.1.4).
pub const IRP_MJ_CREATE: u32 = 0x0000_0000;
pub const IRP_MJ_CLOSE: u32 = 0x0000_0002;
pub const IRP_MJ_READ: u32 = 0x0000_0003;
pub const IRP_MJ_WRITE: u32 = 0x0000_0004;
pub const IRP_MJ_QUERY_INFORMATION: u32 = 0x0000_0005;
pub const IRP_MJ_SET_INFORMATION: u32 = 0x0000_0006;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u32 = 0x0000_000A;
pub const IRP_MJ_SET_VOLUME_INFORMATION: u32 = 0x0000_000B;
pub const IRP_MJ_DIRECTORY_CONTROL: u32 = 0x0000_000C;
pub const IRP_MJ_DEVICE_CONTROL: u32 = 0x0000_000E;
pub const IRP_MJ_LOCK_CONTROL: u32 = 0x0000_0011;
/// MinorFunction values for IRP_MJ_DIRECTORY_CONTROL (MS-RDPEFS 2.2.1.4).
pub const IRP_MN_QUERY_DIRECTORY: u32 = 0x0000_0001;
pub const IRP_MN_NOTIFY_CHANGE_DIRECTORY: u32 = 0x0000_0002;

/// One Device I/O Request (MS-RDPEFS 2.2.1.4), decoded up to the
/// function-specific part.
#[derive(Debug, Clone, Copy)]
pub struct IoRequest<'a> {
    pub device_id: u32,
    pub file_id: u32,
    pub completion_id: u32,
    pub major: u32,
    pub minor: u32,
    /// Function-specific bytes after the 24-byte DR_DEVICE_IOREQUEST header.
    pub data: &'a [u8],
}

/// The answer to one [`IoRequest`]: the core wraps it in a Device I/O
/// Response (MS-RDPEFS 2.2.1.5) with the device's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoCompletion {
    pub completion_id: u32,
    /// NTSTATUS (MS-ERREF 2.3), see [`fscc`] for the values used here.
    pub status: u32,
    /// Function-specific bytes after IoStatus (for example DR_READ_RSP's
    /// Length and ReadData).
    pub data: Vec<u8>,
}

impl IoCompletion {
    pub fn new(req: &IoRequest<'_>, status: u32, data: Vec<u8>) -> Self {
        Self {
            completion_id: req.completion_id,
            status,
            data,
        }
    }
}

/// A redirected device (drive, printer, port, smart card).
pub trait Device: Send {
    /// RDPDR_DTYP_* (MS-RDPEFS 2.2.1.3).
    fn device_type(&self) -> u32;
    /// PreferredDosName: at most 7 ASCII characters (longer names are cut and
    /// non-ASCII characters replaced by the core).
    fn preferred_dos_name(&self) -> String;
    /// DeviceData of the DEVICE_ANNOUNCE (MS-RDPEFS 2.2.1.3).
    fn device_data(&self) -> Vec<u8>;
    /// Name shown to the user by [`RdpdrHandle::devices`].
    fn display_name(&self) -> String {
        self.preferred_dos_name()
    }
    /// True for devices the server needs before user logon (smart cards):
    /// they are announced right after the Server Client ID Confirm.
    fn announce_before_logon(&self) -> bool {
        false
    }
    /// Handles one request. `None` leaves it pending; the device then returns
    /// the completion later from [`Device::tick`] (or never, for requests
    /// such as directory change notifications that may stay pending).
    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion>;
    /// Called on every channel tick: completions of pending requests. Must be
    /// cheap and must not allocate when idle.
    fn tick(&mut self) -> Vec<IoCompletion> {
        Vec::new()
    }
    /// The device was removed or the redirection session restarted: close
    /// every open handle.
    fn closed(&mut self) {}
}

enum Op {
    Add(u32, Box<dyn Device>),
    Remove(u32),
}

#[derive(Default)]
struct Shared {
    ops: Vec<Op>,
    /// What the user sees: added and not removed, in order.
    list: Vec<(u32, String)>,
}

struct Inner {
    shared: Mutex<Shared>,
    /// Set when `ops` is non-empty, so an idle tick does not lock.
    pending: AtomicBool,
    next_id: AtomicU32,
}

/// Thread-safe control of the redirected devices; cheap to clone.
#[derive(Clone)]
pub struct RdpdrHandle {
    inner: Arc<Inner>,
}

impl RdpdrHandle {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.inner
            .shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Shares `root` as a drive named `name`; returns its device id.
    pub fn add_drive(&self, name: &str, root: PathBuf, read_only: bool) -> u32 {
        self.add_device(Box::new(Drive::new(name, root, read_only)))
    }

    /// Adds any device; returns its device id.
    pub fn add_device(&self, dev: Box<dyn Device>) -> u32 {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let mut s = self.lock();
        s.list.push((id, dev.display_name()));
        s.ops.push(Op::Add(id, dev));
        self.inner.pending.store(true, Ordering::Release);
        id
    }

    /// Removes a device (unknown ids are ignored).
    pub fn remove(&self, device_id: u32) {
        let mut s = self.lock();
        let before = s.list.len();
        s.list.retain(|(id, _)| *id != device_id);
        if s.list.len() != before {
            s.ops.push(Op::Remove(device_id));
            self.inner.pending.store(true, Ordering::Release);
        }
    }

    /// The devices currently added: (device id, display name).
    pub fn devices(&self) -> Vec<(u32, String)> {
        self.lock().list.clone()
    }

    /// Takes the queued changes (worker side).
    fn take_ops(&self) -> Option<Vec<Op>> {
        if !self.inner.pending.swap(false, Ordering::Acquire) {
            return None;
        }
        Some(std::mem::take(&mut self.lock().ops))
    }
}

/// Creates the `rdpdr` channel handler and its control handle.
/// `computer_name` is sent in the Client Name Request (MS-RDPEFS 2.2.2.4).
pub fn rdpdr(computer_name: &str) -> (Rdpdr, RdpdrHandle) {
    let handle = RdpdrHandle {
        inner: Arc::new(Inner {
            shared: Mutex::new(Shared::default()),
            pending: AtomicBool::new(false),
            next_id: AtomicU32::new(1),
        }),
    };
    (Rdpdr::new(computer_name, handle.clone()), handle)
}
