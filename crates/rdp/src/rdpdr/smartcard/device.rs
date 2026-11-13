//! The smart card device (MS-RDPESC 3.1): IRP dispatch, the remote-to-local
//! handle table and the worker threads for blocking calls.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

use super::ndr::multi_string;
use super::pack::{Call, RemoteCard, Reply, decode};
use super::*;
use crate::cursor::{Put, Reader};
use crate::rdpdr::fscc::{STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};
use crate::rdpdr::{
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IoCompletion, IoRequest,
    RDPDR_DTYP_SMARTCARD,
};
use crate::trace;

/// Most calls running on worker threads at once; more are answered with
/// SCARD_E_SERVER_TOO_BUSY.
const MAX_WORKERS: usize = 64;
/// Largest Transmit/Control buffer (MS-RDPESC 2.2.2.19 range).
const MAX_IO: usize = 66560;
/// Largest attribute or name list (2.2.2.21 range).
const MAX_ATTR: usize = 65536;
/// Information of the Device Create Response (MS-RDPEFS 2.2.1.5.1).
const FILE_OPENED: u8 = 1;

/// What a worker produced.
enum Done {
    Reply(Reply),
    /// SCardConnect succeeded: the card enters the table in `tick`.
    Connected {
        context_id: u32,
        card: u64,
        protocol: u32,
    },
}

impl Done {
    /// Releases what the result holds when nobody will take it.
    fn discard(self, backend: &dyn SmartCardBackend) {
        if let Done::Connected { card, .. } = self {
            let _ = backend.disconnect(card, SCARD_LEAVE_CARD);
        }
    }
}

struct Finished {
    generation: u64,
    completion_id: u32,
    ioctl: u32,
    done: Done,
}

/// How a request is answered.
enum Step {
    Now(Reply),
    /// IoStatus failure with an empty output buffer (3.1.4).
    Status(u32),
    Later,
}

/// Remote ids (4 bytes on the wire) to local handles. Ids are never 0 and
/// never reused while in use.
#[derive(Default)]
struct Table {
    next_id: u32,
    contexts: HashMap<u32, u64>,
    /// card id -> (context id, local card)
    cards: HashMap<u32, (u32, u64)>,
}

fn remote_id(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

fn id_bytes(id: u32) -> Vec<u8> {
    id.to_le_bytes().to_vec()
}

impl Table {
    fn alloc(&mut self) -> u32 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            let id = self.next_id;
            if id != 0 && !self.contexts.contains_key(&id) && !self.cards.contains_key(&id) {
                return id;
            }
        }
    }

    fn context(&self, remote: &[u8]) -> ScResult<(u32, u64)> {
        let id = remote_id(remote).ok_or(SCARD_E_INVALID_HANDLE)?;
        let local = self.contexts.get(&id).ok_or(SCARD_E_INVALID_HANDLE)?;
        Ok((id, *local))
    }

    /// The card's local handle; its context must be the one it was
    /// connected on.
    fn card(&self, remote: &RemoteCard) -> ScResult<(u32, u64)> {
        let (ctx, _) = self.context(&remote.context)?;
        let id = remote_id(&remote.handle).ok_or(SCARD_E_INVALID_HANDLE)?;
        match self.cards.get(&id) {
            Some(&(c, local)) if c == ctx => Ok((id, local)),
            _ => Err(SCARD_E_INVALID_HANDLE),
        }
    }

    /// Removes the cards of `ctx` and returns their local handles.
    fn take_cards(&mut self, ctx: u32) -> Vec<u64> {
        let ids: Vec<u32> = self
            .cards
            .iter()
            .filter(|(_, (c, _))| *c == ctx)
            .map(|(id, _)| *id)
            .collect();
        ids.iter()
            .filter_map(|id| self.cards.remove(id))
            .map(|(_, card)| card)
            .collect()
    }
}

/// The redirected smart card subsystem; see the [module docs](super).
pub struct SmartCard {
    backend: Arc<dyn SmartCardBackend>,
    table: Table,
    next_file: u32,
    /// Bumped by `closed`: results of older workers are discarded.
    generation: u64,
    tx: Sender<Finished>,
    rx: Receiver<Finished>,
    workers: Arc<AtomicUsize>,
}

/// Decrements the worker count when a worker ends (also on panic).
struct WorkerGuard(Arc<AtomicUsize>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn code<T>(r: &ScResult<T>) -> u32 {
    match r {
        Ok(_) => SCARD_S_SUCCESS,
        Err(c) => *c,
    }
}

/// A length-query aware byte reply: `is_null` or a zero size asks for the
/// length only; a fixed size smaller than the data is
/// SCARD_E_INSUFFICIENT_BUFFER (2.2.2.4, 2.2.2.21). `unit` converts the
/// size field (characters) to bytes.
fn sized(ioctl: u32, data: Vec<u8>, is_null: bool, size: u32, unit: usize) -> Reply {
    let len = data.len() as u32;
    if is_null || size == 0 {
        return Reply::Bytes {
            code: 0,
            len,
            data: None,
        };
    }
    if size != SCARD_AUTOALLOCATE && data.len() > size as usize * unit {
        return Reply::error(ioctl, SCARD_E_INSUFFICIENT_BUFFER);
    }
    Reply::Bytes {
        code: 0,
        len,
        data: Some(data),
    }
}

/// The buffer limit for a size field (SCARD_AUTOALLOCATE or a length query
/// get the protocol maximum).
fn limit(is_null: bool, size: u32, max: usize) -> usize {
    if is_null || size == 0 || size == SCARD_AUTOALLOCATE {
        max
    } else {
        (size as usize).min(max)
    }
}

/// DR_CONTROL_RSP (MS-RDPEFS 2.2.1.5.5) carrying `reply`.
fn complete(completion_id: u32, reply: &Reply) -> IoCompletion {
    let out = reply.encode();
    let mut data = Vec::with_capacity(4 + out.len());
    data.put_u32(out.len() as u32);
    data.put_bytes(&out);
    IoCompletion {
        completion_id,
        status: STATUS_SUCCESS,
        data,
    }
}

impl SmartCard {
    pub fn new(backend: Arc<dyn SmartCardBackend>) -> Self {
        let (tx, rx) = channel();
        Self {
            backend,
            table: Table::default(),
            next_file: 0,
            generation: 0,
            tx,
            rx,
            workers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Runs `job` on a worker thread; its result completes from `tick`.
    fn spawn<F>(&mut self, ioctl: u32, completion_id: u32, job: F) -> Step
    where
        F: FnOnce(&dyn SmartCardBackend) -> Done + Send + 'static,
    {
        if self.workers.fetch_add(1, Ordering::AcqRel) >= MAX_WORKERS {
            self.workers.fetch_sub(1, Ordering::AcqRel);
            return Step::Now(Reply::error(ioctl, SCARD_E_SERVER_TOO_BUSY));
        }
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        let generation = self.generation;
        let workers = self.workers.clone();
        let spawned = std::thread::Builder::new()
            .name("rdp-scard".into())
            .spawn(move || {
                let _guard = WorkerGuard(workers);
                let done = job(backend.as_ref());
                let finished = Finished {
                    generation,
                    completion_id,
                    ioctl,
                    done,
                };
                if let Err(e) = tx.send(finished) {
                    // The device is gone: release what the call opened.
                    e.0.done.discard(backend.as_ref());
                }
            });
        match spawned {
            Ok(_) => Step::Later,
            Err(_) => {
                self.workers.fetch_sub(1, Ordering::AcqRel);
                Step::Now(Reply::error(ioctl, SCARD_E_NO_MEMORY))
            }
        }
    }

    /// Answers one IOCTL (3.1.4).
    fn dispatch(&mut self, ioctl: u32, input: &[u8], completion_id: u32) -> Step {
        match ioctl {
            // ScardAccessStartedEvent_Call is 4 uninitialized bytes (2.2.2.30).
            SCARD_IOCTL_ACCESSSTARTEDEVENT => self.spawn(ioctl, completion_id, |b| {
                Done::Reply(Reply::Long(code(&b.access_started())))
            }),
            // "Not used" (3.1.4.46): answered without effect.
            SCARD_IOCTL_RELEASETARTEDEVENT => Step::Now(Reply::Long(SCARD_S_SUCCESS)),
            // No cache on this client: every lookup misses, writes are
            // accepted and dropped (3.1.4.42-3.1.4.45).
            SCARD_IOCTL_READCACHEA | SCARD_IOCTL_READCACHEW => {
                Step::Now(Reply::error(ioctl, SCARD_W_CACHE_ITEM_NOT_FOUND))
            }
            SCARD_IOCTL_WRITECACHEA | SCARD_IOCTL_WRITECACHEW => {
                Step::Now(Reply::Long(SCARD_S_SUCCESS))
            }
            SCARD_IOCTL_LISTREADERGROUPSA
            | SCARD_IOCTL_LISTREADERGROUPSW
            | SCARD_IOCTL_INTRODUCEREADERGROUPA..=SCARD_IOCTL_REMOVEREADERFROMGROUPW
            | SCARD_IOCTL_LOCATECARDSA
            | SCARD_IOCTL_LOCATECARDSW
            | SCARD_IOCTL_LOCATECARDSBYATRA
            | SCARD_IOCTL_LOCATECARDSBYATRW
            | SCARD_IOCTL_GETTRANSMITCOUNT
            | SCARD_IOCTL_GETREADERICON => {
                Step::Now(Reply::error(ioctl, SCARD_E_UNSUPPORTED_FEATURE))
            }
            SCARD_IOCTL_ESTABLISHCONTEXT
            | SCARD_IOCTL_RELEASECONTEXT
            | SCARD_IOCTL_ISVALIDCONTEXT
            | SCARD_IOCTL_CANCEL
            | SCARD_IOCTL_LISTREADERSA
            | SCARD_IOCTL_LISTREADERSW
            | SCARD_IOCTL_GETSTATUSCHANGEA
            | SCARD_IOCTL_GETSTATUSCHANGEW
            | SCARD_IOCTL_CONNECTA
            | SCARD_IOCTL_CONNECTW
            | SCARD_IOCTL_RECONNECT
            | SCARD_IOCTL_DISCONNECT
            | SCARD_IOCTL_BEGINTRANSACTION
            | SCARD_IOCTL_ENDTRANSACTION
            | SCARD_IOCTL_STATE
            | SCARD_IOCTL_STATUSA
            | SCARD_IOCTL_STATUSW
            | SCARD_IOCTL_TRANSMIT
            | SCARD_IOCTL_CONTROL
            | SCARD_IOCTL_GETATTRIB
            | SCARD_IOCTL_SETATTRIB
            | SCARD_IOCTL_GETDEVICETYPEID => match decode(ioctl, input) {
                Ok(call) => match self.call(ioctl, call, completion_id) {
                    Ok(step) => step,
                    Err(c) => Step::Now(Reply::error(ioctl, c)),
                },
                Err(e) => {
                    trace!("rdpdr scard: {} undecodable: {e}", ioctl_name(ioctl));
                    Step::Status(STATUS_INVALID_PARAMETER)
                }
            },
            _ => Step::Status(STATUS_NOT_SUPPORTED),
        }
    }

    /// Runs one decoded call. `Err` is a return code for the zeroed reply.
    fn call(&mut self, ioctl: u32, call: Call, completion_id: u32) -> ScResult<Step> {
        let b = self.backend.clone();
        let wide = is_wide(ioctl);
        let unit = if wide { 2 } else { 1 };
        let reply = match call {
            Call::EstablishContext { scope } => {
                let local = b.establish_context(scope)?;
                let id = self.table.alloc();
                self.table.contexts.insert(id, local);
                Reply::EstablishContext(SCARD_S_SUCCESS, id_bytes(id))
            }
            Call::Context(ctx) => {
                let (id, local) = self.table.context(&ctx)?;
                match ioctl {
                    SCARD_IOCTL_RELEASECONTEXT => {
                        // Card handles die with their context.
                        for card in self.table.take_cards(id) {
                            let _ = b.disconnect(card, SCARD_LEAVE_CARD);
                        }
                        b.release_context(local)?;
                        self.table.contexts.remove(&id);
                        Reply::Long(SCARD_S_SUCCESS)
                    }
                    SCARD_IOCTL_ISVALIDCONTEXT => Reply::Long(code(&b.is_valid_context(local))),
                    _ => Reply::Long(code(&b.cancel(local))),
                }
            }
            Call::ListReaders {
                context,
                groups,
                readers_is_null,
                cch_readers,
            } => {
                let (_, local) = self.table.context(&context)?;
                let names = b.list_readers(local, &groups)?;
                if names.is_empty() {
                    return Err(SCARD_E_NO_READERS_AVAILABLE);
                }
                let msz = multi_string(&names, wide);
                sized(ioctl, msz, readers_is_null, cch_readers, unit)
            }
            Call::GetStatusChange {
                context,
                timeout,
                mut states,
            } => {
                let (_, local) = self.table.context(&context)?;
                return Ok(self.spawn(ioctl, completion_id, move |b| {
                    Done::Reply(match b.get_status_change(local, timeout, &mut states) {
                        Ok(()) => Reply::StatusChange(SCARD_S_SUCCESS, states),
                        Err(c) => Reply::error(ioctl, c),
                    })
                }));
            }
            Call::Connect {
                context,
                reader,
                share_mode,
                protocols,
            } => {
                let (context_id, local) = self.table.context(&context)?;
                return Ok(self.spawn(ioctl, completion_id, move |b| {
                    match b.connect(local, &reader, share_mode, protocols) {
                        Ok((card, protocol)) => Done::Connected {
                            context_id,
                            card,
                            protocol,
                        },
                        Err(c) => Done::Reply(Reply::error(ioctl, c)),
                    }
                }));
            }
            Call::Reconnect {
                card,
                share_mode,
                protocols,
                initialization,
            } => {
                let (_, local) = self.table.card(&card)?;
                return Ok(self.spawn(ioctl, completion_id, move |b| {
                    Done::Reply(
                        match b.reconnect(local, share_mode, protocols, initialization) {
                            Ok(p) => Reply::Value(SCARD_S_SUCCESS, p),
                            Err(c) => Reply::error(ioctl, c),
                        },
                    )
                }));
            }
            Call::CardDisposition { card, disposition } => {
                let (id, local) = self.table.card(&card)?;
                match ioctl {
                    SCARD_IOCTL_DISCONNECT => {
                        b.disconnect(local, disposition)?;
                        self.table.cards.remove(&id);
                        Reply::Long(SCARD_S_SUCCESS)
                    }
                    SCARD_IOCTL_BEGINTRANSACTION => {
                        return Ok(self.spawn(ioctl, completion_id, move |b| {
                            Done::Reply(Reply::Long(code(&b.begin_transaction(local))))
                        }));
                    }
                    _ => Reply::Long(code(&b.end_transaction(local, disposition))),
                }
            }
            Call::State {
                card,
                atr_is_null,
                cb_atr,
            } => {
                let (_, local) = self.table.card(&card)?;
                let st = b.status(local)?;
                let Reply::Bytes { len, data, .. } = sized(ioctl, st.atr, atr_is_null, cb_atr, 1)
                else {
                    return Err(SCARD_E_INSUFFICIENT_BUFFER);
                };
                Reply::State {
                    code: SCARD_S_SUCCESS,
                    state: st.state,
                    protocol: st.protocol,
                    len,
                    atr: data,
                }
            }
            Call::Status {
                card,
                names_is_null,
                cch_names,
            } => {
                let (_, local) = self.table.card(&card)?;
                let st = b.status(local)?;
                let msz = multi_string(&st.readers, wide);
                let Reply::Bytes { len, data, .. } =
                    sized(ioctl, msz, names_is_null, cch_names, unit)
                else {
                    return Err(SCARD_E_INSUFFICIENT_BUFFER);
                };
                Reply::Status {
                    code: SCARD_S_SUCCESS,
                    len,
                    names: data,
                    state: st.state,
                    protocol: st.protocol,
                    atr: st.atr,
                }
            }
            Call::Transmit {
                card,
                send_pci,
                send,
                recv_pci,
                recv_is_null,
                cb_recv,
            } => {
                let (_, local) = self.table.card(&card)?;
                let max = limit(recv_is_null, cb_recv, MAX_IO);
                return Ok(self.spawn(ioctl, completion_id, move |b| {
                    let r = b.transmit(local, &send_pci, &send, recv_pci.as_ref(), max);
                    Done::Reply(match r {
                        Ok(t) => match sized(ioctl, t.data, recv_is_null, cb_recv, 1) {
                            Reply::Bytes { len, data, .. } => Reply::Transmit {
                                code: SCARD_S_SUCCESS,
                                recv_pci: recv_pci.and(t.recv_pci),
                                len,
                                data,
                            },
                            err => Reply::error(ioctl, err.code()),
                        },
                        Err(c) => Reply::error(ioctl, c),
                    })
                }));
            }
            Call::Control {
                card,
                code: control,
                input,
                out_is_null,
                cb_out,
            } => {
                let (_, local) = self.table.card(&card)?;
                let max = limit(out_is_null, cb_out, MAX_IO);
                return Ok(self.spawn(ioctl, completion_id, move |b| {
                    Done::Reply(match b.control(local, control, &input, max) {
                        Ok(out) => sized(ioctl, out, out_is_null, cb_out, 1),
                        Err(c) => Reply::error(ioctl, c),
                    })
                }));
            }
            Call::GetAttrib {
                card,
                attr,
                attr_is_null,
                cb_attr,
            } => {
                let (_, local) = self.table.card(&card)?;
                let data = b.get_attrib(local, attr, limit(attr_is_null, cb_attr, MAX_ATTR))?;
                sized(ioctl, data, attr_is_null, cb_attr, 1)
            }
            Call::SetAttrib { card, attr, data } => {
                let (_, local) = self.table.card(&card)?;
                Reply::Long(code(&b.set_attrib(local, attr, &data)))
            }
            Call::GetDeviceTypeId { context, reader } => {
                let (_, local) = self.table.context(&context)?;
                Reply::Value(SCARD_S_SUCCESS, b.get_device_type_id(local, &reader)?)
            }
        };
        Ok(Step::Now(reply))
    }

    /// IRP_MJ_DEVICE_CONTROL: DR_CONTROL_REQ (MS-RDPEFS 2.2.1.4.5).
    fn device_control(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        let mut r = Reader::new(req.data);
        let parsed = (|| {
            let _out_len = r.u32()?;
            let in_len = r.u32()? as usize;
            let ioctl = r.u32()?;
            r.skip(20)?;
            Ok::<_, crate::Error>((ioctl, r.bytes(in_len)?))
        })();
        let Ok((ioctl, input)) = parsed else {
            return Some(IoCompletion::new(req, STATUS_INVALID_PARAMETER, vec![0; 4]));
        };
        trace!(
            "rdpdr scard: {} ({ioctl:#010x}), {} bytes in",
            ioctl_name(ioctl),
            input.len()
        );
        match self.dispatch(ioctl, input, req.completion_id) {
            Step::Now(reply) => Some(self.finish(req.completion_id, ioctl, &reply)),
            Step::Status(status) => Some(IoCompletion::new(req, status, vec![0; 4])),
            Step::Later => None,
        }
    }

    fn finish(&self, completion_id: u32, ioctl: u32, reply: &Reply) -> IoCompletion {
        let c = complete(completion_id, reply);
        trace!(
            "rdpdr scard: {} -> {:#010x}, {} bytes out",
            ioctl_name(ioctl),
            reply.code(),
            c.data.len() - 4
        );
        c
    }

    /// Number of remote contexts and cards in the table (tests).
    #[cfg(test)]
    pub(super) fn handle_count(&self) -> (usize, usize) {
        (self.table.contexts.len(), self.table.cards.len())
    }
}

impl Device for SmartCard {
    fn device_type(&self) -> u32 {
        RDPDR_DTYP_SMARTCARD
    }

    fn preferred_dos_name(&self) -> String {
        "SCARD".into()
    }

    /// No DeviceData for smart cards (MS-RDPESC 3.1.3).
    fn device_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn display_name(&self) -> String {
        "Smart cards".into()
    }

    fn announce_before_logon(&self) -> bool {
        true
    }

    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        match req.major {
            IRP_MJ_CREATE => {
                // Device Create Response (MS-RDPEFS 2.2.1.5.1).
                self.next_file = self.next_file.wrapping_add(1).max(1);
                let mut data = Vec::with_capacity(5);
                data.put_u32(self.next_file);
                data.put_u8(FILE_OPENED);
                Some(IoCompletion::new(req, STATUS_SUCCESS, data))
            }
            // Device Close Response (2.2.1.5.2): Padding.
            IRP_MJ_CLOSE => Some(IoCompletion::new(req, STATUS_SUCCESS, vec![0; 4])),
            IRP_MJ_DEVICE_CONTROL => self.device_control(req),
            _ => Some(IoCompletion::new(req, STATUS_NOT_SUPPORTED, Vec::new())),
        }
    }

    fn tick(&mut self) -> Vec<IoCompletion> {
        let mut out = Vec::new();
        while let Ok(f) = self.rx.try_recv() {
            if f.generation != self.generation {
                f.done.discard(self.backend.as_ref());
                continue;
            }
            let reply = match f.done {
                Done::Reply(r) => r,
                Done::Connected {
                    context_id,
                    card,
                    protocol,
                } => {
                    if self.table.contexts.contains_key(&context_id) {
                        let id = self.table.alloc();
                        self.table.cards.insert(id, (context_id, card));
                        let card = RemoteCard {
                            context: id_bytes(context_id),
                            handle: id_bytes(id),
                        };
                        Reply::Connect(SCARD_S_SUCCESS, card, protocol)
                    } else {
                        // The context was released while connecting.
                        let _ = self.backend.disconnect(card, SCARD_LEAVE_CARD);
                        Reply::error(f.ioctl, SCARD_E_INVALID_HANDLE)
                    }
                }
            };
            out.push(self.finish(f.completion_id, f.ioctl, &reply));
        }
        out
    }

    /// Releases every local card and context; pending calls are cancelled
    /// and their results discarded.
    fn closed(&mut self) {
        self.generation += 1;
        let b = self.backend.clone();
        for (_, (_, card)) in self.table.cards.drain() {
            let _ = b.disconnect(card, SCARD_LEAVE_CARD);
        }
        for (_, ctx) in self.table.contexts.drain() {
            let _ = b.cancel(ctx);
            let _ = b.release_context(ctx);
        }
    }
}

impl Drop for SmartCard {
    fn drop(&mut self) {
        self.closed();
    }
}
