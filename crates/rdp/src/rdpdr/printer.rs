//! Printer redirection (MS-RDPEPC) as an rdpdr [`Device`]: local printers
//! appear in the remote session and its print jobs come out locally.
//!
//! # Announce (MS-RDPEPC 2.2.2.1)
//!
//! Each printer is a DEVICE_ANNOUNCE (MS-RDPEFS 2.2.1.3) with DeviceType
//! [`RDPDR_DTYP_PRINT`], a PreferredDosName of "PRN" plus digits (2.2.2.1:
//! the port name; the rest MUST be digits) and DR_PRN_DEVICE_ANNOUNCE data
//! ([`announce_data`]): Flags, CodePage 0, the PnP, driver and printer names
//! as null-terminated UTF-16LE with their lengths in bytes, and no cached
//! configuration (CachedFieldsLen 0).
//!
//! # Data format decision: XPS (Easy Print) first, the printer's own format otherwise
//!
//! Every printer is announced with [`RDPDR_PRINTER_ANNOUNCE_FLAG_XPSFORMAT`]
//! and the local driver name, exactly as Windows' own client does (MS-RDPEPC
//! 4.1.1). With that flag, Windows Server 2008 and later use the terminal
//! server's XPS driver ("Remote Desktop Easy Print") and ignore the
//! DriverName (MS-RDPEPC 3.1.1.2 XPS Mode and Appendix A note 1), so the
//! printer appears without any driver installed on the server and without
//! the user installing anything: the server sends each job as an XPS
//! document (an OPC/ZIP package) in the Printer Write Requests (2.2.2.9).
//!
//! The server MAY instead use the driver-specific format (3.1.1.2; group
//! policy, Appendix A note 3): then it loads the driver whose name matches
//! DriverName exactly (note 1) and the job is that driver's printer language
//! (a "PRN file", 2.2.2.9), which the local printer takes as-is.
//!
//! The choice is signalled per printer by Server Printer Set XPS Mode
//! (DR_PRN_USING_XPS, 2.2.2.2), a RDPDR_CTYP_PRN message the rdpdr core
//! currently drops before devices see it. Until the core forwards it, each
//! job's format is taken from its first bytes: an XPS document is a ZIP
//! package and starts with the local file header signature `PK\x03\x04`
//! (APPNOTE 4.3.7); anything else is printer language. Both cases are named
//! by [`PrintFormat`] and handed to the backend, which must:
//! - [`PrintFormat::Xps`]: submit the document to the spooler as an XPS job.
//!   On Windows that is datatype `XPS_PASS` for XPS-capable drivers (v4 and
//!   XPSDrv) and `XPS2GDI` (the spooler converts XPS to GDI) for v3 GDI
//!   drivers. Elsewhere it would need an XPS renderer or converter.
//! - [`PrintFormat::Raw`]: send the bytes unchanged (Windows datatype `RAW`).
//!
//! What does not work:
//! - The XPS Print Virtual Channel Extension (MS-RDPEXPS, dynamic channel
//!   TSVCTKT) is not implemented: the server cannot ask the client for the
//!   printer's capabilities, print ticket conversions or preferences dialog,
//!   so remote print settings fall back to the server driver's defaults.
//! - Cached printer configuration (2.2.2.3-2.2.2.6) is neither sent nor
//!   stored.
//! - The protocol carries no document name; jobs are named [`JOB_NAME`].
//!
//! # Jobs
//!
//! IRP_MJ_CREATE (DR_PRN_CREATE_REQ, 2.2.2.7) opens a job and answers
//! DR_PRN_CREATE_RSP (2.2.2.10) with a FileId chosen here; IRP_MJ_WRITE
//! (DR_PRN_WRITE_REQ, 2.2.2.9; Offset ignored) appends data and answers
//! DR_PRN_WRITE_RSP (2.2.2.12) with the length written; IRP_MJ_CLOSE
//! (DR_PRN_CLOSE_REQ, 2.2.2.8) hands the job to the backend and answers
//! DR_PRN_CLOSE_RSP (2.2.2.11). Every other request gets
//! `STATUS_NOT_SUPPORTED`. Several jobs may be open at once, keyed by FileId.
//! The backend job starts at the first write (when the format is known);
//! jobs still open when the device is removed, or the redirection restarts,
//! are cancelled.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::fscc::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use super::{
    Device, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_WRITE, IoCompletion,
    IoRequest, RDPDR_DTYP_PRINT, RdpdrHandle,
};
use crate::cursor::{Put, Reader, utf16le_z};
use crate::error::Result;
use crate::trace;

/// Flags of DR_PRN_DEVICE_ANNOUNCE (MS-RDPEPC 2.2.2.1).
pub const RDPDR_PRINTER_ANNOUNCE_FLAG_ASCII: u32 = 0x0000_0001;
pub const RDPDR_PRINTER_ANNOUNCE_FLAG_DEFAULTPRINTER: u32 = 0x0000_0002;
pub const RDPDR_PRINTER_ANNOUNCE_FLAG_NETWORKPRINTER: u32 = 0x0000_0004;
pub const RDPDR_PRINTER_ANNOUNCE_FLAG_TSPRINTER: u32 = 0x0000_0008;
pub const RDPDR_PRINTER_ANNOUNCE_FLAG_XPSFORMAT: u32 = 0x0000_0010;

/// STATUS_INSUFFICIENT_RESOURCES (MS-ERREF 2.3.1).
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Name of every job in the local queue (the protocol carries none).
pub const JOB_NAME: &str = "Remote Desktop print job";

/// Jobs one printer keeps open at once; more creates are refused.
const MAX_OPEN_JOBS: usize = 64;

/// ZIP local file header signature (PKWARE APPNOTE 4.3.7): every XPS
/// document starts with it.
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";

/// A local printer as the backend reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterInfo {
    /// Printer name, also the name the server user sees.
    pub name: String,
    /// Local driver name (sent as DriverName; ignored by Easy Print).
    pub driver: String,
    pub is_default: bool,
}

/// What a job's bytes are (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintFormat {
    /// An XPS document from the server's Easy Print driver.
    Xps,
    /// Printer language from a server driver matching the local one.
    Raw,
}

/// The local print system. Runs on the session worker thread (inside
/// [`Device::io`]), so calls must not block for long or show any UI;
/// spooler writes are fine.
pub trait PrintBackend: Send {
    /// The printers that can be shared.
    fn printers(&mut self) -> Vec<PrinterInfo>;
    /// Opens a job on `printer`; returns a job handle.
    fn start(
        &mut self,
        printer: &str,
        job_name: &str,
        format: PrintFormat,
    ) -> std::result::Result<u64, String>;
    /// Appends data to a job.
    fn write(&mut self, job: u64, data: &[u8]) -> std::result::Result<(), String>;
    /// Ends the job: it prints.
    fn finish(&mut self, job: u64) -> std::result::Result<(), String>;
    /// Drops the job: nothing prints.
    fn cancel(&mut self, job: u64);
}

/// A backend shared by every printer device of a session.
pub type SharedBackend = Arc<Mutex<dyn PrintBackend>>;

fn lock(b: &SharedBackend) -> MutexGuard<'_, dyn PrintBackend + 'static> {
    b.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// DR_PRN_DEVICE_ANNOUNCE device data (MS-RDPEPC 2.2.2.1): CodePage 0, no
/// cached config; an empty name is sent with length 0.
pub fn announce_data(flags: u32, pnp_name: &str, driver_name: &str, printer_name: &str) -> Vec<u8> {
    let name = |s: &str| {
        if s.is_empty() {
            Vec::new()
        } else {
            utf16le_z(s)
        }
    };
    let (pnp, driver, printer) = (name(pnp_name), name(driver_name), name(printer_name));
    let mut v = Vec::with_capacity(24 + pnp.len() + driver.len() + printer.len());
    v.put_u32(flags);
    v.put_u32(0); // CodePage
    v.put_u32(pnp.len() as u32);
    v.put_u32(driver.len() as u32);
    v.put_u32(printer.len() as u32);
    v.put_u32(0); // CachedFieldsLen
    v.put_bytes(&pnp);
    v.put_bytes(&driver);
    v.put_bytes(&printer);
    v
}

enum Job {
    /// Created, format not known yet: the first bytes (fewer than 4).
    Pending(Vec<u8>),
    /// Started in the backend.
    Open(u64),
    /// The backend failed; later writes fail too, close only frees it.
    Failed,
}

/// One redirected local printer.
pub struct Printer {
    info: PrinterInfo,
    port: u32,
    backend: SharedBackend,
    jobs: HashMap<u32, Job>,
    next_file: u32,
}

type Reply = (u32, Vec<u8>);

impl Printer {
    /// `port` gives the PreferredDosName "PRN<port>" (1..=9999).
    pub fn new(info: PrinterInfo, port: u32, backend: SharedBackend) -> Self {
        Self {
            info,
            port: port.clamp(1, 9999),
            backend,
            jobs: HashMap::new(),
            next_file: 0,
        }
    }

    pub fn info(&self) -> &PrinterInfo {
        &self.info
    }

    /// Jobs the server has open.
    pub fn open_jobs(&self) -> usize {
        self.jobs.len()
    }

    /// IRP_MJ_CREATE: DR_PRN_CREATE_REQ (2.2.2.7) / DR_PRN_CREATE_RSP
    /// (2.2.2.10, FileId only).
    fn create(&mut self, r: &mut Reader<'_>) -> Result<Reply> {
        r.skip(4 + 8 + 4 + 4 + 4 + 4)?; // access, allocation, attrs, share, disposition, options
        let path_len = r.u32()? as usize;
        r.skip(path_len)?;
        if self.jobs.len() >= MAX_OPEN_JOBS {
            return Ok((STATUS_INSUFFICIENT_RESOURCES, vec![0; 4]));
        }
        let mut id = self.next_file;
        while self.jobs.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_file = id.wrapping_add(1);
        self.jobs.insert(id, Job::Pending(Vec::new()));
        trace!("rdpdr printer {}: job {id} created", self.port);
        Ok((STATUS_SUCCESS, id.to_le_bytes().to_vec()))
    }

    /// Starts the backend job and writes `first`; the job is Open or Failed.
    fn start(&mut self, first: &[u8]) -> Job {
        let format = if first.starts_with(&ZIP_MAGIC) {
            PrintFormat::Xps
        } else {
            PrintFormat::Raw
        };
        let mut b = lock(&self.backend);
        let job = match b.start(&self.info.name, JOB_NAME, format) {
            Ok(job) => job,
            Err(e) => {
                trace!("rdpdr printer {}: start failed: {e}", self.port);
                return Job::Failed;
            }
        };
        trace!("rdpdr printer {}: {format:?} job started", self.port);
        match b.write(job, first) {
            Ok(()) => Job::Open(job),
            Err(e) => {
                trace!("rdpdr printer {}: write failed: {e}", self.port);
                b.cancel(job);
                Job::Failed
            }
        }
    }

    /// IRP_MJ_WRITE: DR_PRN_WRITE_REQ (2.2.2.9) / DR_PRN_WRITE_RSP (2.2.2.12:
    /// Length, 1 byte Padding).
    fn write(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let len = r.u32()? as usize;
        r.skip(8 + 20)?; // Offset (ignored, 2.2.2.9), Padding
        let data = r.bytes(len)?;
        let fail = |s| (s, vec![0; 5]);
        let Some(job) = self.jobs.get_mut(&id) else {
            return Ok(fail(STATUS_INVALID_HANDLE));
        };
        trace!("rdpdr printer {}: job {id} write {len} bytes", self.port);
        let next = match job {
            Job::Failed => return Ok(fail(STATUS_UNSUCCESSFUL)),
            Job::Open(h) => {
                let h = *h;
                let mut b = lock(&self.backend);
                match b.write(h, data) {
                    Ok(()) => Job::Open(h),
                    Err(e) => {
                        trace!("rdpdr printer {}: write failed: {e}", self.port);
                        b.cancel(h);
                        Job::Failed
                    }
                }
            }
            Job::Pending(buf) => {
                buf.extend_from_slice(data);
                if buf.len() < ZIP_MAGIC.len() {
                    let mut v = Vec::with_capacity(5);
                    v.put_u32(len as u32);
                    v.put_u8(0);
                    return Ok((STATUS_SUCCESS, v));
                }
                let first = std::mem::take(buf);
                self.start(&first)
            }
        };
        let ok = !matches!(next, Job::Failed);
        self.jobs.insert(id, next);
        if !ok {
            return Ok(fail(STATUS_UNSUCCESSFUL));
        }
        let mut v = Vec::with_capacity(5);
        v.put_u32(len as u32);
        v.put_u8(0); // Padding
        Ok((STATUS_SUCCESS, v))
    }

    /// IRP_MJ_CLOSE: DR_PRN_CLOSE_REQ (2.2.2.8) / DR_PRN_CLOSE_RSP (2.2.2.11,
    /// 4 bytes Padding). The job prints; an empty job prints nothing.
    fn close(&mut self, id: u32) -> Reply {
        let Some(job) = self.jobs.remove(&id) else {
            return (STATUS_INVALID_HANDLE, vec![0; 4]);
        };
        let job = match job {
            Job::Pending(buf) if buf.is_empty() => return (STATUS_SUCCESS, vec![0; 4]),
            Job::Pending(buf) => self.start(&buf),
            other => other,
        };
        let status = match job {
            Job::Open(h) => match lock(&self.backend).finish(h) {
                Ok(()) => {
                    trace!("rdpdr printer {}: job {id} printed", self.port);
                    STATUS_SUCCESS
                }
                Err(e) => {
                    trace!("rdpdr printer {}: finish failed: {e}", self.port);
                    STATUS_UNSUCCESSFUL
                }
            },
            // The failure was reported on the write; the handle is closed.
            Job::Failed | Job::Pending(_) => STATUS_SUCCESS,
        };
        (status, vec![0; 4])
    }

    fn handle(&mut self, req: &IoRequest<'_>) -> Result<Reply> {
        let mut r = Reader::new(req.data);
        Ok(match req.major {
            IRP_MJ_CREATE => self.create(&mut r)?,
            IRP_MJ_WRITE => self.write(req.file_id, &mut r)?,
            IRP_MJ_CLOSE => self.close(req.file_id),
            // Device Control Response (MS-RDPEFS 2.2.1.5.5): OutputBufferLength 0.
            IRP_MJ_DEVICE_CONTROL => (STATUS_NOT_SUPPORTED, vec![0; 4]),
            _ => (STATUS_NOT_SUPPORTED, Vec::new()),
        })
    }

    /// Cancels every open job.
    fn cancel_all(&mut self) {
        if self.jobs.is_empty() {
            return;
        }
        let mut b = lock(&self.backend);
        for (_, job) in self.jobs.drain() {
            if let Job::Open(h) = job {
                b.cancel(h);
            }
        }
    }
}

impl Device for Printer {
    fn device_type(&self) -> u32 {
        RDPDR_DTYP_PRINT
    }

    /// "PRN" followed by digits (MS-RDPEPC 2.2.2.1).
    fn preferred_dos_name(&self) -> String {
        format!("PRN{}", self.port)
    }

    fn device_data(&self) -> Vec<u8> {
        let mut flags = RDPDR_PRINTER_ANNOUNCE_FLAG_XPSFORMAT;
        if self.info.is_default {
            flags |= RDPDR_PRINTER_ANNOUNCE_FLAG_DEFAULTPRINTER;
        }
        announce_data(flags, "", &self.info.driver, &self.info.name)
    }

    fn display_name(&self) -> String {
        self.info.name.clone()
    }

    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        Some(match self.handle(req) {
            Ok((status, data)) => IoCompletion::new(req, status, data),
            // Truncated request: answer instead of leaving the server waiting.
            Err(_) => IoCompletion::new(req, STATUS_INVALID_PARAMETER, Vec::new()),
        })
    }

    fn closed(&mut self) {
        self.cancel_all();
    }
}

impl Drop for Printer {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

/// Next port number for PreferredDosName, unique per process (1..=9999).
fn next_port() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed) % 9999 + 1
}

/// Shares every printer `backend` reports; returns their device ids (remove
/// them with [`RdpdrHandle::remove`]). Safe to call from the UI thread: it
/// only enumerates printers and queues the devices; the announce and all
/// printing run on the session worker. Enumeration waits while the worker is
/// inside a backend call of an earlier shared printer.
pub fn share_printers(handle: &RdpdrHandle, backend: SharedBackend) -> Vec<u32> {
    let list = lock(&backend).printers();
    list.into_iter()
        .map(|info| {
            let dev = Printer::new(info, next_port(), backend.clone());
            handle.add_device(Box::new(dev))
        })
        .collect()
}

#[cfg(test)]
#[path = "printer_tests.rs"]
mod tests;
