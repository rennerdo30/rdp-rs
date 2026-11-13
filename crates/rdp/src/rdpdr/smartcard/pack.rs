//! MS-RDPESC call structures (2.2.2) decoded from, and return structures
//! (2.2.3) encoded to, NDR ([`super::ndr`]). The field orders follow the
//! IDL of MS-RDPESC section 6.

use super::ndr::{NdrReader, NdrWriter, parse_multi_string};
use super::*;
use crate::error::{Result, proto};

/// REDIR_SCARDCONTEXT (2.2.1.1): opaque bytes the client handed out.
pub type RemoteContext = Vec<u8>;

/// REDIR_SCARDHANDLE (2.2.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCard {
    pub context: RemoteContext,
    pub handle: Vec<u8>,
}

/// One decoded call (2.2.2.x), by IOCTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// EstablishContext_Call (2.2.2.1).
    EstablishContext { scope: u32 },
    /// Context_Call (2.2.2.2): ReleaseContext, IsValidContext, Cancel.
    Context(RemoteContext),
    /// ListReaders_Call (2.2.2.4).
    ListReaders {
        context: RemoteContext,
        groups: Vec<String>,
        readers_is_null: bool,
        cch_readers: u32,
    },
    /// GetStatusChangeA_Call / GetStatusChangeW_Call (2.2.2.11/2.2.2.12).
    GetStatusChange {
        context: RemoteContext,
        timeout: u32,
        states: Vec<ReaderState>,
    },
    /// ConnectA_Call / ConnectW_Call (2.2.2.13/2.2.2.14).
    Connect {
        context: RemoteContext,
        reader: String,
        share_mode: u32,
        protocols: u32,
    },
    /// Reconnect_Call (2.2.2.15).
    Reconnect {
        card: RemoteCard,
        share_mode: u32,
        protocols: u32,
        initialization: u32,
    },
    /// HCardAndDisposition_Call (2.2.2.16): Disconnect, Begin/EndTransaction.
    CardDisposition { card: RemoteCard, disposition: u32 },
    /// State_Call (2.2.2.17).
    State {
        card: RemoteCard,
        atr_is_null: bool,
        cb_atr: u32,
    },
    /// Status_Call (2.2.2.18).
    Status {
        card: RemoteCard,
        names_is_null: bool,
        cch_names: u32,
    },
    /// Transmit_Call (2.2.2.19).
    Transmit {
        card: RemoteCard,
        send_pci: IoPci,
        send: Vec<u8>,
        recv_pci: Option<IoPci>,
        recv_is_null: bool,
        cb_recv: u32,
    },
    /// Control_Call (2.2.2.20).
    Control {
        card: RemoteCard,
        code: u32,
        input: Vec<u8>,
        out_is_null: bool,
        cb_out: u32,
    },
    /// GetAttrib_Call (2.2.2.21).
    GetAttrib {
        card: RemoteCard,
        attr: u32,
        attr_is_null: bool,
        cb_attr: u32,
    },
    /// SetAttrib_Call (2.2.2.22).
    SetAttrib {
        card: RemoteCard,
        attr: u32,
        data: Vec<u8>,
    },
    /// GetDeviceTypeId_Call (2.2.2.32).
    GetDeviceTypeId {
        context: RemoteContext,
        reader: String,
    },
}

/// Fixed part of REDIR_SCARDCONTEXT: cbContext and the pointer.
fn context_head(r: &mut NdrReader<'_>) -> Result<(u32, bool)> {
    Ok((r.ranged(16)?, r.ptr()?))
}

fn context_body(r: &mut NdrReader<'_>, (len, present): (u32, bool)) -> Result<RemoteContext> {
    if present {
        r.conformant_bytes(len)
    } else {
        Ok(Vec::new())
    }
}

/// Fixed part of REDIR_SCARDHANDLE: context head, cbHandle, pointer.
type CardHead = ((u32, bool), (u32, bool));

fn card_head(r: &mut NdrReader<'_>) -> Result<CardHead> {
    Ok((context_head(r)?, (r.ranged(16)?, r.ptr()?)))
}

fn card_body(r: &mut NdrReader<'_>, (ctx, handle): CardHead) -> Result<RemoteCard> {
    Ok(RemoteCard {
        context: context_body(r, ctx)?,
        handle: context_body(r, handle)?,
    })
}

fn opt_bytes(r: &mut NdrReader<'_>, len: u32, present: bool) -> Result<Vec<u8>> {
    if present {
        r.conformant_bytes(len)
    } else {
        Ok(Vec::new())
    }
}

fn bool32(v: u32) -> bool {
    v != 0
}

/// Decodes the call for `ioctl` from its serialized input buffer.
pub fn decode(ioctl: u32, buf: &[u8]) -> Result<Call> {
    let mut r = NdrReader::new(buf)?;
    let r = &mut r;
    let wide = is_wide(ioctl);
    Ok(match ioctl {
        SCARD_IOCTL_ESTABLISHCONTEXT => Call::EstablishContext { scope: r.u32()? },
        SCARD_IOCTL_RELEASECONTEXT | SCARD_IOCTL_ISVALIDCONTEXT | SCARD_IOCTL_CANCEL => {
            let h = context_head(r)?;
            Call::Context(context_body(r, h)?)
        }
        SCARD_IOCTL_LISTREADERSA | SCARD_IOCTL_LISTREADERSW => {
            let h = context_head(r)?;
            let len = r.ranged(65536)?;
            let groups = r.ptr()?;
            let readers_is_null = bool32(r.u32()?);
            let cch_readers = r.u32()?;
            let context = context_body(r, h)?;
            let groups = parse_multi_string(&opt_bytes(r, len, groups)?, wide);
            Call::ListReaders {
                context,
                groups,
                readers_is_null,
                cch_readers,
            }
        }
        SCARD_IOCTL_GETSTATUSCHANGEA | SCARD_IOCTL_GETSTATUSCHANGEW => {
            let h = context_head(r)?;
            let timeout = r.u32()?;
            let count = r.ranged(11)?;
            let present = r.ptr()?;
            let context = context_body(r, h)?;
            let states = if present {
                reader_states(r, count, wide)?
            } else if count == 0 {
                Vec::new()
            } else {
                return proto("rdpesc: null rgReaderStates");
            };
            Call::GetStatusChange {
                context,
                timeout,
                states,
            }
        }
        SCARD_IOCTL_CONNECTA | SCARD_IOCTL_CONNECTW => {
            let reader = r.ptr()?;
            let h = context_head(r)?;
            let share_mode = r.u32()?;
            let protocols = r.u32()?;
            if !reader {
                return proto("rdpesc: null szReader");
            }
            let reader = r.string(wide)?;
            Call::Connect {
                context: context_body(r, h)?,
                reader,
                share_mode,
                protocols,
            }
        }
        SCARD_IOCTL_RECONNECT => {
            let h = card_head(r)?;
            let (share_mode, protocols, initialization) = (r.u32()?, r.u32()?, r.u32()?);
            Call::Reconnect {
                card: card_body(r, h)?,
                share_mode,
                protocols,
                initialization,
            }
        }
        SCARD_IOCTL_DISCONNECT | SCARD_IOCTL_BEGINTRANSACTION | SCARD_IOCTL_ENDTRANSACTION => {
            let h = card_head(r)?;
            let disposition = r.u32()?;
            Call::CardDisposition {
                card: card_body(r, h)?,
                disposition,
            }
        }
        SCARD_IOCTL_STATE => {
            let h = card_head(r)?;
            let (atr_is_null, cb_atr) = (bool32(r.u32()?), r.u32()?);
            Call::State {
                card: card_body(r, h)?,
                atr_is_null,
                cb_atr,
            }
        }
        SCARD_IOCTL_STATUSA | SCARD_IOCTL_STATUSW => {
            let h = card_head(r)?;
            let (names_is_null, cch_names) = (bool32(r.u32()?), r.u32()?);
            let _cb_atr_len = r.u32()?; // unused (2.2.2.18)
            Call::Status {
                card: card_body(r, h)?,
                names_is_null,
                cch_names,
            }
        }
        SCARD_IOCTL_TRANSMIT => {
            let h = card_head(r)?;
            let send_pci = (r.u32()?, r.ranged(1024)?, r.ptr()?);
            let send_len = r.ranged(66560)?;
            let send_present = r.ptr()?;
            let recv_pci = r.ptr()?;
            let recv_is_null = bool32(r.u32()?);
            let cb_recv = r.u32()?;
            let card = card_body(r, h)?;
            let send_pci = IoPci {
                protocol: send_pci.0,
                extra: opt_bytes(r, send_pci.1, send_pci.2)?,
            };
            let send = opt_bytes(r, send_len, send_present)?;
            let recv_pci = if recv_pci {
                let (protocol, len, present) = (r.u32()?, r.ranged(1024)?, r.ptr()?);
                Some(IoPci {
                    protocol,
                    extra: opt_bytes(r, len, present)?,
                })
            } else {
                None
            };
            Call::Transmit {
                card,
                send_pci,
                send,
                recv_pci,
                recv_is_null,
                cb_recv,
            }
        }
        SCARD_IOCTL_CONTROL => {
            let h = card_head(r)?;
            let code = r.u32()?;
            let len = r.ranged(66560)?;
            let present = r.ptr()?;
            let (out_is_null, cb_out) = (bool32(r.u32()?), r.u32()?);
            let card = card_body(r, h)?;
            Call::Control {
                card,
                code,
                input: opt_bytes(r, len, present)?,
                out_is_null,
                cb_out,
            }
        }
        SCARD_IOCTL_GETATTRIB => {
            let h = card_head(r)?;
            let attr = r.u32()?;
            let (attr_is_null, cb_attr) = (bool32(r.u32()?), r.u32()?);
            Call::GetAttrib {
                card: card_body(r, h)?,
                attr,
                attr_is_null,
                cb_attr,
            }
        }
        SCARD_IOCTL_SETATTRIB => {
            let h = card_head(r)?;
            let attr = r.u32()?;
            let len = r.ranged(65536)?;
            let present = r.ptr()?;
            let card = card_body(r, h)?;
            Call::SetAttrib {
                card,
                attr,
                data: opt_bytes(r, len, present)?,
            }
        }
        SCARD_IOCTL_GETDEVICETYPEID => {
            let h = context_head(r)?;
            let reader = r.ptr()?;
            let context = context_body(r, h)?;
            if !reader {
                return proto("rdpesc: null szReaderName");
            }
            Call::GetDeviceTypeId {
                context,
                reader: r.wstring()?,
            }
        }
        _ => return proto(format!("rdpesc: no decoder for {ioctl:#010x}")),
    })
}

/// The referent of `ReaderStateA/W *rgReaderStates` (2.2.1.6/2.2.1.7):
/// MaximumCount, `count` fixed parts (szReader pointer and
/// ReaderState_Common_Call, 2.2.1.5), then the reader names in order.
fn reader_states(r: &mut NdrReader<'_>, count: u32, wide: bool) -> Result<Vec<ReaderState>> {
    if r.u32()? != count {
        return proto("rdpesc: rgReaderStates count mismatch");
    }
    let mut heads = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let named = r.ptr()?;
        let current_state = r.u32()?;
        let event_state = r.u32()?;
        let cb_atr = r.ranged(36)? as usize;
        let atr = r.bytes(36)?[..cb_atr].to_vec();
        heads.push((named, current_state, event_state, atr));
    }
    heads
        .into_iter()
        .map(|(named, current_state, event_state, atr)| {
            if !named {
                return proto("rdpesc: null szReader");
            }
            Ok(ReaderState {
                reader: r.string(wide)?,
                current_state,
                event_state,
                atr,
            })
        })
        .collect()
}

/// One return structure (2.2.3.x). [`Reply::error`] builds the zeroed
/// structure with a failure code (2.2.3: "all other fields MUST be set to
/// zero").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Long_Return (2.2.3.3).
    Long(u32),
    /// EstablishContext_Return (2.2.3.2).
    EstablishContext(u32, RemoteContext),
    /// A ReturnCode, a byte count and a `[unique, size_is]` byte pointer:
    /// ListReaders_Return (2.2.3.4), ReadCache_Return (2.2.3.1),
    /// Control_Return (2.2.3.6), GetAttrib_Return (2.2.3.12). `data` None
    /// sends a null pointer with `len` (a length query).
    Bytes {
        code: u32,
        len: u32,
        data: Option<Vec<u8>>,
    },
    /// GetStatusChange_Return / LocateCards_Return (2.2.3.5).
    StatusChange(u32, Vec<ReaderState>),
    /// Connect_Return (2.2.3.8).
    Connect(u32, RemoteCard, u32),
    /// Reconnect_Return (2.2.3.7), GetTransmitCount_Return (2.2.3.13),
    /// GetDeviceTypeId_Return (2.2.3.15): ReturnCode and one value.
    Value(u32, u32),
    /// State_Return (2.2.3.9).
    State {
        code: u32,
        state: u32,
        protocol: u32,
        len: u32,
        atr: Option<Vec<u8>>,
    },
    /// Status_Return (2.2.3.10).
    Status {
        code: u32,
        len: u32,
        names: Option<Vec<u8>>,
        state: u32,
        protocol: u32,
        atr: Vec<u8>,
    },
    /// Transmit_Return (2.2.3.11).
    Transmit {
        code: u32,
        recv_pci: Option<IoPci>,
        len: u32,
        data: Option<Vec<u8>>,
    },
}

impl Reply {
    /// The return structure of `ioctl` carrying only the failure `code`.
    pub fn error(ioctl: u32, code: u32) -> Reply {
        let bytes = Reply::Bytes {
            code,
            len: 0,
            data: None,
        };
        match ioctl {
            SCARD_IOCTL_ESTABLISHCONTEXT => Reply::EstablishContext(code, Vec::new()),
            SCARD_IOCTL_LISTREADERGROUPSA
            | SCARD_IOCTL_LISTREADERGROUPSW
            | SCARD_IOCTL_LISTREADERSA
            | SCARD_IOCTL_LISTREADERSW
            | SCARD_IOCTL_CONTROL
            | SCARD_IOCTL_GETATTRIB
            | SCARD_IOCTL_READCACHEA
            | SCARD_IOCTL_READCACHEW
            | SCARD_IOCTL_GETREADERICON => bytes,
            SCARD_IOCTL_GETSTATUSCHANGEA
            | SCARD_IOCTL_GETSTATUSCHANGEW
            | SCARD_IOCTL_LOCATECARDSA
            | SCARD_IOCTL_LOCATECARDSW
            | SCARD_IOCTL_LOCATECARDSBYATRA
            | SCARD_IOCTL_LOCATECARDSBYATRW => Reply::StatusChange(code, Vec::new()),
            SCARD_IOCTL_CONNECTA | SCARD_IOCTL_CONNECTW => Reply::Connect(
                code,
                RemoteCard {
                    context: Vec::new(),
                    handle: Vec::new(),
                },
                0,
            ),
            SCARD_IOCTL_RECONNECT | SCARD_IOCTL_GETTRANSMITCOUNT | SCARD_IOCTL_GETDEVICETYPEID => {
                Reply::Value(code, 0)
            }
            SCARD_IOCTL_STATE => Reply::State {
                code,
                state: 0,
                protocol: 0,
                len: 0,
                atr: None,
            },
            SCARD_IOCTL_STATUSA | SCARD_IOCTL_STATUSW => Reply::Status {
                code,
                len: 0,
                names: None,
                state: 0,
                protocol: 0,
                atr: Vec::new(),
            },
            SCARD_IOCTL_TRANSMIT => Reply::Transmit {
                code,
                recv_pci: None,
                len: 0,
                data: None,
            },
            _ => Reply::Long(code),
        }
    }

    /// The ReturnCode field.
    pub fn code(&self) -> u32 {
        match self {
            Reply::Long(c)
            | Reply::EstablishContext(c, _)
            | Reply::StatusChange(c, _)
            | Reply::Connect(c, _, _)
            | Reply::Value(c, _) => *c,
            Reply::Bytes { code, .. }
            | Reply::State { code, .. }
            | Reply::Status { code, .. }
            | Reply::Transmit { code, .. } => *code,
        }
    }

    /// The serialized structure (MS-RPCE 2.2.6).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = NdrWriter::default();
        w.u32(self.code());
        match self {
            Reply::Long(_) => {}
            Reply::EstablishContext(_, ctx) => {
                w.u32(ctx.len() as u32);
                w.ptr(!ctx.is_empty());
                opt_body(&mut w, ctx);
            }
            Reply::Bytes { len, data, .. } => {
                w.u32(*len);
                w.ptr(data.is_some());
                if let Some(d) = data {
                    w.conformant_bytes(d);
                }
            }
            Reply::StatusChange(_, states) => {
                w.u32(states.len() as u32);
                w.ptr(!states.is_empty());
                if !states.is_empty() {
                    // ReaderState_Return (2.2.1.11): no pointers inside.
                    w.u32(states.len() as u32);
                    for s in states {
                        w.u32(s.current_state);
                        w.u32(s.event_state);
                        let n = s.atr.len().min(36);
                        w.u32(n as u32);
                        let mut atr = [0u8; 36];
                        atr[..n].copy_from_slice(&s.atr[..n]);
                        w.bytes(&atr);
                    }
                }
            }
            Reply::Connect(_, card, protocol) => {
                w.u32(card.context.len() as u32);
                w.ptr(!card.context.is_empty());
                w.u32(card.handle.len() as u32);
                w.ptr(!card.handle.is_empty());
                w.u32(*protocol);
                opt_body(&mut w, &card.context);
                opt_body(&mut w, &card.handle);
            }
            Reply::Value(_, v) => w.u32(*v),
            Reply::State {
                state,
                protocol,
                len,
                atr,
                ..
            } => {
                w.u32(*state);
                w.u32(*protocol);
                w.u32(*len);
                w.ptr(atr.is_some());
                if let Some(a) = atr {
                    w.conformant_bytes(a);
                }
            }
            Reply::Status {
                len,
                names,
                state,
                protocol,
                atr,
                ..
            } => {
                w.u32(*len);
                w.ptr(names.is_some());
                w.u32(*state);
                w.u32(*protocol);
                let n = atr.len().min(32);
                let mut fixed = [0u8; 32];
                fixed[..n].copy_from_slice(&atr[..n]);
                w.bytes(&fixed);
                w.u32(n as u32);
                if let Some(names) = names {
                    w.conformant_bytes(names);
                }
            }
            Reply::Transmit {
                recv_pci,
                len,
                data,
                ..
            } => {
                w.ptr(recv_pci.is_some());
                w.u32(*len);
                w.ptr(data.is_some());
                if let Some(pci) = recv_pci {
                    // SCardIO_Request (2.2.1.8) and its pbExtraBytes.
                    w.u32(pci.protocol);
                    w.u32(pci.extra.len() as u32);
                    w.ptr(!pci.extra.is_empty());
                    opt_body(&mut w, &pci.extra);
                }
                if let Some(d) = data {
                    w.conformant_bytes(d);
                }
            }
        }
        w.finish()
    }
}

/// The referent of a pointer written as non-null exactly when `b` is not
/// empty.
fn opt_body(w: &mut NdrWriter, b: &[u8]) {
    if !b.is_empty() {
        w.conformant_bytes(b);
    }
}
