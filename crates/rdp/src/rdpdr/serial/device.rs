//! The port device (MS-RDPESP 3.2.5): IRP dispatch, the open instances and
//! their worker lanes; see the [module docs](super).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use super::*;
use crate::cursor::{Put, Reader};
use crate::error::Result;
use crate::rdpdr::fscc::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::rdpdr::{
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, IoCompletion,
    IoRequest,
};
use crate::trace;

/// Largest read handed to the port; longer requests get a partial read
/// (allowed by MS-RDPESP 3.2.5.1.9).
pub const MAX_READ: usize = 64 * 1024;
/// Requests waiting for a worker at once; more are refused with
/// `STATUS_INSUFFICIENT_RESOURCES`.
pub const MAX_PENDING: usize = 256;
/// Open instances of one port (Windows ports are exclusive, so normally 1).
pub const MAX_OPEN: usize = 8;

/// What a pending request is, for cancel and for its failure answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Create,
    Close,
    Read,
    Write,
    Wait,
    Control,
}

impl Kind {
    /// The function-specific part of a failure answer (MS-RDPEFS 2.2.1.5.x):
    /// create FileId + Information, close Padding, read Length, write Length
    /// + Padding, control OutputBufferLength.
    fn empty(self) -> Vec<u8> {
        match self {
            Kind::Create | Kind::Write => vec![0; 5],
            Kind::Close | Kind::Read | Kind::Wait | Kind::Control => vec![0; 4],
        }
    }
}

struct Pending {
    completion_id: u32,
    file_id: u32,
    kind: Kind,
}

/// A worker result, tagged with the token of its request.
enum Done {
    Opened {
        token: u64,
        result: PortResult<Arc<dyn SerialPort>>,
    },
    Io {
        token: u64,
        status: u32,
        data: Vec<u8>,
    },
}

type Job = Box<dyn FnOnce() -> (u32, Vec<u8>) + Send>;

/// One worker thread running its jobs in order; it ends when the lane is
/// dropped and its queue is empty.
struct Lane {
    tx: Sender<(u64, Job)>,
}

impl Lane {
    fn spawn(results: Sender<Done>, name: &str) -> std::io::Result<Lane> {
        let (tx, rx) = channel::<(u64, Job)>();
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                for (token, job) in rx {
                    let (status, data) = job();
                    if results
                        .send(Done::Io {
                            token,
                            status,
                            data,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Lane { tx })
    }
}

/// Lane indices of an open instance.
const READ: usize = 0;
const WRITE: usize = 1;
const WAIT: usize = 2;
const CONTROL: usize = 3;
const LANE_NAMES: [&str; 4] = [
    "rdp-port-read",
    "rdp-port-write",
    "rdp-port-wait",
    "rdp-port-ctl",
];

struct Open {
    port: Arc<dyn SerialPort>,
    lanes: [Option<Lane>; 4],
}

/// Releases a port off the session worker (closing may wait briefly for
/// cancelled I/O to finish).
fn close_detached(port: Arc<dyn SerialPort>) {
    let spawned = std::thread::Builder::new()
        .name("rdp-port-close".into())
        .spawn({
            let port = port.clone();
            move || port.close()
        });
    if spawned.is_err() {
        port.close();
    }
}

/// DR_CONTROL_RSP data (MS-RDPEFS 2.2.1.5.5): OutputBufferLength and the
/// output.
fn control_rsp(out: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + out.len());
    v.put_u32(out.len() as u32);
    v.put_bytes(out);
    v
}

/// One redirected local serial or parallel port.
pub struct SerialPortDevice {
    info: PortInfo,
    backend: Arc<dyn SerialBackend>,
    files: HashMap<u32, Open>,
    next_file: u32,
    next_token: u64,
    pending: HashMap<u64, Pending>,
    /// Answers produced outside `io` (cancels), sent from `tick` in order.
    ready: Vec<IoCompletion>,
    tx: Sender<Done>,
    rx: Receiver<Done>,
}

impl SerialPortDevice {
    pub fn new(info: PortInfo, backend: Arc<dyn SerialBackend>) -> Self {
        let (tx, rx) = channel();
        Self {
            info,
            backend,
            files: HashMap::new(),
            next_file: 0,
            next_token: 0,
            pending: HashMap::new(),
            ready: Vec::new(),
            tx,
            rx,
        }
    }

    pub fn info(&self) -> &PortInfo {
        &self.info
    }

    /// Instances the server has open.
    pub fn open_files(&self) -> usize {
        self.files.len()
    }

    /// Requests waiting for the port.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn token(&mut self, req: &IoRequest<'_>, kind: Kind) -> u64 {
        self.next_token += 1;
        let token = self.next_token;
        self.pending.insert(
            token,
            Pending {
                completion_id: req.completion_id,
                file_id: req.file_id,
                kind,
            },
        );
        token
    }

    /// Answers the pending requests of `file` that `pick` selects with
    /// `status` (and `data`, or the kind's empty answer); their later
    /// worker results are dropped.
    fn finish_pending(
        &mut self,
        file: u32,
        pick: impl Fn(Kind) -> bool,
        status: u32,
        data: Option<&[u8]>,
    ) {
        let mut hit: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.file_id == file && pick(p.kind))
            .map(|(t, _)| *t)
            .collect();
        hit.sort_unstable(); // oldest first
        for t in hit {
            if let Some(p) = self.pending.remove(&t) {
                let data = data.map_or_else(|| p.kind.empty(), <[u8]>::to_vec);
                self.ready.push(IoCompletion {
                    completion_id: p.completion_id,
                    status,
                    data,
                });
            }
        }
    }

    /// Queues `job` on the lane of `file`; `Err` is the status to answer.
    fn submit(
        &mut self,
        req: &IoRequest<'_>,
        lane: usize,
        kind: Kind,
        job: impl FnOnce(&dyn SerialPort) -> (u32, Vec<u8>) + Send + 'static,
    ) -> std::result::Result<(), u32> {
        if self.pending.len() >= MAX_PENDING {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let results = self.tx.clone();
        let open = self
            .files
            .get_mut(&req.file_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if open.lanes[lane].is_none() {
            let l = Lane::spawn(results, LANE_NAMES[lane])
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            open.lanes[lane] = Some(l);
        }
        let port = open.port.clone();
        let tx = open.lanes[lane].as_ref().map(|l| l.tx.clone());
        let token = self.token(req, kind);
        let job: Job = Box::new(move || job(port.as_ref()));
        if tx.is_none_or(|tx| tx.send((token, job)).is_err()) {
            self.pending.remove(&token);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(())
    }

    /// IRP_MJ_CREATE: DR_CREATE_REQ (MS-RDPEFS 2.2.1.4.1, MS-RDPESP 2.2.2.2);
    /// answered from `tick` once the port is open.
    fn create(&mut self, req: &IoRequest<'_>) -> Result<Option<(u32, Vec<u8>)>> {
        let mut r = Reader::new(req.data);
        // DesiredAccess, AllocationSize, FileAttributes, SharedAccess,
        // CreateDisposition, CreateOptions: opaque to MS-RDPESP (2.2.2.2).
        r.skip(4 + 8 + 4 + 4 + 4 + 4)?;
        let path_len = r.u32()? as usize; // MUST be 0 (2.2.2.2); tolerated
        r.skip(path_len)?;
        let opening = self
            .pending
            .values()
            .filter(|p| p.kind == Kind::Create)
            .count();
        if self.files.len() + opening >= MAX_OPEN || self.pending.len() >= MAX_PENDING {
            return Ok(Some((STATUS_INSUFFICIENT_RESOURCES, Kind::Create.empty())));
        }
        let token = self.token(req, Kind::Create);
        let backend = self.backend.clone();
        let name = self.info.name.clone();
        let tx = self.tx.clone();
        let spawned = std::thread::Builder::new()
            .name("rdp-port-open".into())
            .spawn(move || {
                let result = backend.open(&name);
                if let Err(e) = tx.send(Done::Opened { token, result }) {
                    // The device is gone: release what was opened.
                    if let Done::Opened { result: Ok(p), .. } = e.0 {
                        p.close();
                    }
                }
            });
        if spawned.is_err() {
            self.pending.remove(&token);
            return Ok(Some((STATUS_INSUFFICIENT_RESOURCES, Kind::Create.empty())));
        }
        Ok(None)
    }

    /// IRP_MJ_CLOSE (MS-RDPESP 3.2.5.1.3): cancels the instance's pending
    /// requests, then closes the port on its control lane and answers.
    fn close(&mut self, req: &IoRequest<'_>) -> Option<(u32, Vec<u8>)> {
        let file = req.file_id;
        if !self.files.contains_key(&file) {
            return Some((STATUS_INVALID_HANDLE, Kind::Close.empty()));
        }
        self.finish_pending(file, |_| true, STATUS_CANCELLED, None);
        let submitted = self.submit(req, CONTROL, Kind::Close, |port| {
            port.close();
            (STATUS_SUCCESS, Kind::Close.empty())
        });
        let open = self.files.remove(&file);
        trace!("rdpdr port {}: file {file} closed", self.info.name);
        if submitted.is_err() {
            if let Some(o) = open {
                close_detached(o.port);
            }
            return Some((STATUS_SUCCESS, Kind::Close.empty()));
        }
        // The lanes end once their queues (the close job) are done.
        None
    }

    /// IRP_MJ_READ: DR_READ_REQ (MS-RDPEFS 2.2.1.4.3; Offset ignored,
    /// MS-RDPESP 3.2.5.1.4) / DR_READ_RSP (2.2.1.5.3).
    fn read(&mut self, req: &IoRequest<'_>) -> Result<Option<(u32, Vec<u8>)>> {
        let mut r = Reader::new(req.data);
        let len = r.u32()? as usize;
        let max = len.min(MAX_READ);
        let res = self.submit(req, READ, Kind::Read, move |port| match port.read(max) {
            Ok(mut data) => {
                data.truncate(max);
                let mut v = Vec::with_capacity(4 + data.len());
                v.put_u32(data.len() as u32);
                v.put_bytes(&data);
                (STATUS_SUCCESS, v)
            }
            Err(s) => (s, Kind::Read.empty()),
        });
        Ok(res.err().map(|s| (s, Kind::Read.empty())))
    }

    /// IRP_MJ_WRITE: DR_WRITE_REQ (MS-RDPEFS 2.2.1.4.4; Offset ignored,
    /// MS-RDPESP 3.2.5.1.5) / DR_WRITE_RSP (2.2.1.5.4: Length, Padding).
    fn write(&mut self, req: &IoRequest<'_>) -> Result<Option<(u32, Vec<u8>)>> {
        let mut r = Reader::new(req.data);
        let len = r.u32()? as usize;
        r.skip(8 + 20)?; // Offset, Padding
        let data = r.bytes(len)?.to_vec();
        let res = self.submit(req, WRITE, Kind::Write, move |port| {
            match port.write(&data) {
                Ok(n) => {
                    let mut v = Vec::with_capacity(5);
                    v.put_u32(n.min(data.len() as u32));
                    v.put_u8(0);
                    (STATUS_SUCCESS, v)
                }
                Err(s) => (s, Kind::Write.empty()),
            }
        });
        Ok(res.err().map(|s| (s, Kind::Write.empty())))
    }

    /// IRP_MJ_DEVICE_CONTROL: DR_CONTROL_REQ (MS-RDPEFS 2.2.1.4.5,
    /// MS-RDPESP 2.2.2.6) / DR_CONTROL_RSP (2.2.1.5.5).
    fn control(&mut self, req: &IoRequest<'_>) -> Result<Option<(u32, Vec<u8>)>> {
        let mut r = Reader::new(req.data);
        let output_len = r.u32()?;
        let input_len = r.u32()? as usize;
        let code = r.u32()?;
        r.skip(20)?; // Padding
        let input = r.bytes(input_len)?;
        let fail = |s: u32| Ok(Some((s, Kind::Control.empty())));
        if !self.files.contains_key(&req.file_id) {
            return fail(STATUS_INVALID_HANDLE);
        }
        let serial = self.info.kind == PortKind::Serial;
        if serial && code == IOCTL_SERIAL_WAIT_ON_MASK {
            if output_len < 4 {
                return fail(STATUS_BUFFER_TOO_SMALL);
            }
            // One wait at a time per instance (serial driver rule).
            let busy = self
                .pending
                .values()
                .any(|p| p.file_id == req.file_id && p.kind == Kind::Wait);
            if busy {
                return fail(STATUS_INVALID_PARAMETER);
            }
            let res = self.submit(req, WAIT, Kind::Wait, |port| match port.wait_event() {
                Ok(mask) => (STATUS_SUCCESS, control_rsp(&mask.to_le_bytes())),
                Err(s) => (s, Kind::Wait.empty()),
            });
            return Ok(res.err().map(|s| (s, Kind::Control.empty())));
        }
        if serial && code == IOCTL_SERIAL_CONFIG_SIZE {
            // No configuration data (the serial driver answers 0).
            if output_len < 4 {
                return fail(STATUS_BUFFER_TOO_SMALL);
            }
            return Ok(Some((STATUS_SUCCESS, control_rsp(&0u32.to_le_bytes()))));
        }
        let c = match decode_ioctl(self.info.kind, code, input, output_len) {
            Ok(c) => c,
            Err(s) => {
                trace!(
                    "rdpdr port {}: IOCTL {code:#010x} refused ({s:#010x})",
                    self.info.name
                );
                return fail(s);
            }
        };
        match c {
            // A new wait mask ends the pending wait with no events.
            SerialControl::SetWaitMask(_) => self.finish_pending(
                req.file_id,
                |k| k == Kind::Wait,
                STATUS_SUCCESS,
                Some(&control_rsp(&0u32.to_le_bytes())),
            ),
            SerialControl::Purge(mask) => {
                let reads = mask & SERIAL_PURGE_RXABORT != 0;
                let writes = mask & SERIAL_PURGE_TXABORT != 0;
                self.finish_pending(
                    req.file_id,
                    |k| (reads && k == Kind::Read) || (writes && k == Kind::Write),
                    STATUS_CANCELLED,
                    None,
                );
            }
            _ => {}
        }
        let limit = output_len as usize;
        let res = self.submit(req, CONTROL, Kind::Control, move |port| {
            match port.control(&c) {
                Ok(out) => {
                    let mut bytes = out.encode();
                    bytes.truncate(limit);
                    (STATUS_SUCCESS, control_rsp(&bytes))
                }
                Err(s) => (s, Kind::Control.empty()),
            }
        });
        Ok(res.err().map(|s| (s, Kind::Control.empty())))
    }

    fn handle(&mut self, req: &IoRequest<'_>) -> Result<Option<(u32, Vec<u8>)>> {
        match req.major {
            IRP_MJ_CREATE => self.create(req),
            IRP_MJ_CLOSE => Ok(self.close(req)),
            IRP_MJ_READ | IRP_MJ_WRITE if !self.files.contains_key(&req.file_id) => {
                let kind = if req.major == IRP_MJ_READ {
                    Kind::Read
                } else {
                    Kind::Write
                };
                Ok(Some((STATUS_INVALID_HANDLE, kind.empty())))
            }
            IRP_MJ_READ => self.read(req),
            IRP_MJ_WRITE => self.write(req),
            IRP_MJ_DEVICE_CONTROL => self.control(req),
            _ => Ok(Some((super::super::fscc::STATUS_NOT_SUPPORTED, Vec::new()))),
        }
    }

    /// Closes every instance and forgets every pending request.
    fn close_all(&mut self) {
        for (_, open) in self.files.drain() {
            close_detached(open.port);
        }
        self.pending.clear();
        self.ready.clear();
    }
}

impl Device for SerialPortDevice {
    fn device_type(&self) -> u32 {
        self.info.kind.device_type()
    }

    /// The port name, "COM3" or "LPT1" (MS-RDPESP 2.2.2.1, Appendix A
    /// note 1).
    fn preferred_dos_name(&self) -> String {
        self.info.name.clone()
    }

    /// No DeviceData for ports (MS-RDPESP 2.2.2.1: DeviceDataLength 0).
    fn device_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn display_name(&self) -> String {
        self.info.name.clone()
    }

    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        let (status, data) = match self.handle(req) {
            Ok(Some(answer)) => answer,
            Ok(None) => return None,
            // Truncated request: answer instead of leaving the server waiting.
            Err(_) => (STATUS_INVALID_PARAMETER, Vec::new()),
        };
        let c = IoCompletion::new(req, status, data);
        if self.ready.is_empty() {
            Some(c)
        } else {
            // Keep the order: cancels produced by this request go first.
            self.ready.push(c);
            None
        }
    }

    fn tick(&mut self) -> Vec<IoCompletion> {
        let mut out = std::mem::take(&mut self.ready);
        while let Ok(done) = self.rx.try_recv() {
            match done {
                Done::Opened { token, result } => {
                    let Some(p) = self.pending.remove(&token) else {
                        // Answered meanwhile (device closed): release it.
                        if let Ok(port) = result {
                            close_detached(port);
                        }
                        continue;
                    };
                    let (status, data) = match result {
                        Ok(port) => {
                            let mut id = self.next_file.wrapping_add(1).max(1);
                            while self.files.contains_key(&id) {
                                id = id.wrapping_add(1).max(1);
                            }
                            self.next_file = id;
                            self.files.insert(
                                id,
                                Open {
                                    port,
                                    lanes: [None, None, None, None],
                                },
                            );
                            trace!("rdpdr port {}: opened as file {id}", self.info.name);
                            // DR_CREATE_RSP: FileId, Information 0
                            // (MS-RDPESP 3.2.5.1.7).
                            let mut v = Vec::with_capacity(5);
                            v.put_u32(id);
                            v.put_u8(0);
                            (STATUS_SUCCESS, v)
                        }
                        Err(s) => {
                            trace!("rdpdr port {}: open failed {s:#010x}", self.info.name);
                            (s, Kind::Create.empty())
                        }
                    };
                    out.push(IoCompletion {
                        completion_id: p.completion_id,
                        status,
                        data,
                    });
                }
                Done::Io {
                    token,
                    status,
                    data,
                } => {
                    if let Some(p) = self.pending.remove(&token) {
                        out.push(IoCompletion {
                            completion_id: p.completion_id,
                            status,
                            data,
                        });
                    }
                }
            }
        }
        out
    }

    fn closed(&mut self) {
        self.close_all();
    }
}

impl Drop for SerialPortDevice {
    fn drop(&mut self) {
        self.close_all();
    }
}
