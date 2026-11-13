//! Tests: NDR bytes for the MS-RDPESC 4.x examples, and the device against
//! a mock backend (no reader or card is ever touched).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::ndr::{NdrReader, NdrWriter, multi_string, parse_multi_string};
use super::pack::{Call, RemoteCard, Reply, decode};
use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::{Put, utf16le_z};
use crate::rdpdr::fscc::{STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};
use crate::rdpdr::{IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IoCompletion, IoRequest};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Common and private type headers for a body of `len` bytes.
fn headers(len: u32) -> Vec<u8> {
    let mut v = hex("01100800 cccccccc");
    v.put_u32(len);
    v.put_u32(0);
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const READER: &str = "Gemplus USB Smart Card Reader 0";
const CTX: [u8; 4] = [0x00, 0x00, 0x01, 0xcd];
const HCARD: [u8; 4] = [0x00, 0x00, 0x01, 0xea];
const ATR: [u8; 9] = [0x3b, 0x16, 0x94, 0x41, 0x73, 0x74, 0x72, 0x69, 0x64];

/// [string] wchar_t referent: MaximumCount, Offset, ActualCount, data.
fn wstr_bytes(s: &str) -> Vec<u8> {
    let u = utf16le_z(s);
    let n = (u.len() / 2) as u32;
    let mut v = Vec::new();
    v.put_u32(n);
    v.put_u32(0);
    v.put_u32(n);
    v.put_bytes(&u);
    v
}

// ---- NDR: MS-RDPESC 4.1-4.18 ----

#[test]
fn establish_context_call_4_1() {
    let buf = cat(&[&headers(8), &hex("02000000 00000000")]);
    assert_eq!(
        decode(SCARD_IOCTL_ESTABLISHCONTEXT, &buf).unwrap(),
        Call::EstablishContext { scope: 2 } // SCARD_SCOPE_SYSTEM
    );
}

#[test]
fn establish_context_return_4_2() {
    let want = cat(&[
        &headers(24),
        &hex("00000000 04000000 00000200 04000000 000001cd 00000000"),
    ]);
    assert_eq!(Reply::EstablishContext(0, CTX.to_vec()).encode(), want);
}

#[test]
fn list_readers_call_4_3() {
    let groups = utf16le_z("SCard$DefaultReaders\0");
    assert_eq!(groups.len(), 44);
    let buf = cat(&[
        &headers(80),
        &hex("04000000 00000200 2c000000 04000200 00000000 ffffffff"),
        &hex("04000000 000001cd 2c000000"),
        &groups,
    ]);
    assert_eq!(
        decode(SCARD_IOCTL_LISTREADERSW, &buf).unwrap(),
        Call::ListReaders {
            context: CTX.to_vec(),
            groups: vec!["SCard$DefaultReaders".into()],
            readers_is_null: false,
            cch_readers: SCARD_AUTOALLOCATE,
        }
    );
}

#[test]
fn list_readers_return_4_4_padded_to_8() {
    let msz = multi_string(&[READER.to_string()], true);
    assert_eq!(msz.len(), 66);
    let want = cat(&[
        &headers(88),
        &hex("00000000 42000000 00000200 42000000"),
        &msz,
        &[0; 6],
    ]);
    let reply = Reply::Bytes {
        code: 0,
        len: 66,
        data: Some(msz),
    };
    assert_eq!(reply.encode(), want);
}

#[test]
fn get_status_change_call_4_5() {
    let buf = cat(&[
        &headers(160),
        &hex("04000000 00000200 00000000 01000000 04000200"),
        &hex("04000000 000001cd"),
        &hex("01000000 08000200 00000000 00000000 00000000"),
        &[0; 36],
        &wstr_bytes(READER),
    ]);
    assert_eq!(buf.len(), 16 + 160);
    assert_eq!(
        decode(SCARD_IOCTL_GETSTATUSCHANGEW, &buf).unwrap(),
        Call::GetStatusChange {
            context: CTX.to_vec(),
            timeout: 0,
            states: vec![ReaderState {
                reader: READER.into(),
                current_state: SCARD_STATE_UNAWARE,
                event_state: 0,
                atr: Vec::new(),
            }],
        }
    );
}

#[test]
fn get_status_change_return_4_6() {
    let mut atr36 = ATR.to_vec();
    atr36.resize(36, 0);
    let want = cat(&[
        &headers(64),
        &hex("00000000 01000000 00000200 01000000 00000000 22010000 09000000"),
        &atr36,
    ]);
    let reply = Reply::StatusChange(
        0,
        vec![ReaderState {
            reader: READER.into(),
            current_state: SCARD_STATE_UNAWARE,
            event_state: SCARD_STATE_CHANGED | SCARD_STATE_PRESENT | SCARD_STATE_INUSE,
            atr: ATR.to_vec(),
        }],
    );
    assert_eq!(reply.encode(), want);
}

#[test]
fn connect_call_4_7_string_before_context() {
    let buf = cat(&[
        &headers(104),
        &hex("00000200 04000000 04000200 02000000 03000000"),
        &wstr_bytes(READER),
        &hex("04000000 000001cd"),
    ]);
    assert_eq!(
        decode(SCARD_IOCTL_CONNECTW, &buf).unwrap(),
        Call::Connect {
            context: CTX.to_vec(),
            reader: READER.into(),
            share_mode: 2, // SCARD_SHARE_SHARED
            protocols: SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        }
    );
}

#[test]
fn connect_return_4_8() {
    let want = cat(&[
        &headers(40),
        &hex("00000000 04000000 00000200 04000000 04000200 01000000"),
        &hex("04000000 000001cd 04000000 000001ea"),
    ]);
    let card = RemoteCard {
        context: CTX.to_vec(),
        handle: HCARD.to_vec(),
    };
    assert_eq!(Reply::Connect(0, card, SCARD_PROTOCOL_T0).encode(), want);
}

#[test]
fn hcard_and_disposition_calls_4_9_4_13_4_15() {
    for (ioctl, disposition) in [
        (SCARD_IOCTL_BEGINTRANSACTION, 0),
        (SCARD_IOCTL_ENDTRANSACTION, SCARD_LEAVE_CARD),
        (SCARD_IOCTL_DISCONNECT, SCARD_RESET_CARD),
    ] {
        let mut d = Vec::new();
        d.put_u32(disposition);
        let buf = cat(&[
            &headers(40),
            &hex("04000000 00000200 04000000 04000200"),
            &d,
            &hex("04000000 000001cd 04000000 000001ea 00000000"),
        ]);
        assert_eq!(
            decode(ioctl, &buf).unwrap(),
            Call::CardDisposition {
                card: RemoteCard {
                    context: CTX.to_vec(),
                    handle: HCARD.to_vec(),
                },
                disposition,
            }
        );
    }
}

#[test]
fn long_return_4_10() {
    assert_eq!(
        Reply::Long(0).encode(),
        cat(&[&headers(8), &hex("00000000 00000000")])
    );
    assert_eq!(
        Reply::Long(SCARD_E_CANCELLED).encode(),
        cat(&[&headers(8), &hex("02001080 00000000")])
    );
}

#[test]
fn status_call_4_11() {
    let buf = cat(&[
        &headers(48),
        &hex("04000000 00000200 04000000 04000200 00000000 ffffffff 24000000"),
        &hex("04000000 000001cd 04000000 000001ea 00000000"),
    ]);
    assert_eq!(
        decode(SCARD_IOCTL_STATUSW, &buf).unwrap(),
        Call::Status {
            card: RemoteCard {
                context: CTX.to_vec(),
                handle: HCARD.to_vec(),
            },
            names_is_null: false,
            cch_names: SCARD_AUTOALLOCATE,
        }
    );
}

#[test]
fn status_return_4_12_fixed_atr_then_deferred_names() {
    let msz = multi_string(&[READER.to_string()], true);
    let mut atr32 = ATR.to_vec();
    atr32.resize(32, 0);
    let want = cat(&[
        &headers(128),
        &hex("00000000 42000000 00000200 06000000 01000000"),
        &atr32,
        &hex("09000000 42000000"),
        &msz,
        &[0; 2],
    ]);
    let reply = Reply::Status {
        code: 0,
        len: 66,
        names: Some(msz),
        state: 6, // SCARD_SPECIFICMODE
        protocol: SCARD_PROTOCOL_T0,
        atr: ATR.to_vec(),
    };
    assert_eq!(reply.encode(), want);
}

#[test]
fn release_context_call_4_17() {
    let buf = cat(&[&headers(16), &hex("04000000 00000200 04000000 000001cd")]);
    for ioctl in [SCARD_IOCTL_RELEASECONTEXT, SCARD_IOCTL_CANCEL] {
        assert_eq!(decode(ioctl, &buf).unwrap(), Call::Context(CTX.to_vec()));
    }
}

#[test]
fn ansi_string_and_odd_byte_arrays_are_aligned() {
    // ConnectA with "ab": 3 string bytes, then 1 pad byte before the
    // context's MaximumCount.
    let buf = cat(&[
        &headers(48),
        &hex("00000200 03000000 04000200 01000000 02000000"),
        &hex("03000000 00000000 03000000 616200 00"),
        &hex("03000000 aabbcc 00 00000000"),
    ]);
    assert_eq!(
        decode(SCARD_IOCTL_CONNECTA, &buf).unwrap(),
        Call::Connect {
            context: vec![0xaa, 0xbb, 0xcc],
            reader: "ab".into(),
            share_mode: 1,
            protocols: 2,
        }
    );
    // ListReadersA return: 5 bytes "a\0b\0\0", padded to 8.
    let msz = multi_string(&["a".into(), "b".into()], false);
    assert_eq!(msz, b"a\0b\0\0");
    let reply = Reply::Bytes {
        code: 0,
        len: 5,
        data: Some(msz),
    };
    assert_eq!(
        reply.encode(),
        cat(&[
            &headers(24),
            &hex("00000000 05000000 00000200 05000000 6100620000 000000"),
        ])
    );
}

#[test]
fn transmit_call_with_pci_extra_bytes_and_recv_pci() {
    let buf = cat(&[
        &headers(96),
        &hex("04000000 00000200 04000000 04000200"), // hCard
        &hex("02000000 03000000 08000200"),          // ioSendPci, 3 extra bytes
        &hex("05000000 0c000200 10000200 00000000 02010000"), // send, recvPci, flag, cbRecv
        &hex("04000000 000001cd 04000000 000001ea"),
        &hex("03000000 010203 00"),
        &hex("05000000 00a4040000 000000"),
        &hex("02000000 00000000 00000000"), // pioRecvPci: T1, no extra
    ]);
    assert_eq!(
        decode(SCARD_IOCTL_TRANSMIT, &buf).unwrap(),
        Call::Transmit {
            card: RemoteCard {
                context: CTX.to_vec(),
                handle: HCARD.to_vec(),
            },
            send_pci: IoPci {
                protocol: 2,
                extra: vec![1, 2, 3],
            },
            send: vec![0x00, 0xa4, 0x04, 0x00, 0x00],
            recv_pci: Some(IoPci {
                protocol: 2,
                extra: Vec::new(),
            }),
            recv_is_null: false,
            cb_recv: 258,
        }
    );
}

#[test]
fn transmit_return_pci_before_data() {
    let reply = Reply::Transmit {
        code: 0,
        recv_pci: Some(IoPci {
            protocol: 2,
            extra: vec![9],
        }),
        len: 2,
        data: Some(vec![0x90, 0x00]),
    };
    let want = cat(&[
        &headers(48),
        &hex("00000000 00000200 02000000 04000200"),
        &hex("02000000 01000000 08000200 01000000 09 000000"),
        &hex("02000000 9000 000000000000"),
    ]);
    assert_eq!(reply.encode(), want);
}

#[test]
fn error_replies_are_zeroed_structures() {
    let e = SCARD_E_UNSUPPORTED_FEATURE;
    assert_eq!(
        Reply::error(SCARD_IOCTL_LOCATECARDSW, e).encode(),
        cat(&[&headers(16), &hex("22001080 00000000 00000000 00000000")])
    );
    let status = Reply::error(SCARD_IOCTL_STATUSW, e).encode();
    // ReturnCode, cBytes, ptr, state, protocol, pbAtr[32], cbAtrLen.
    assert_eq!(status.len(), 16 + 56);
    assert!(status[20..].iter().all(|&b| b == 0));
}

#[test]
fn malformed_input_is_an_error_never_a_panic() {
    let good = cat(&[
        &headers(160),
        &hex("04000000 00000200 00000000 01000000 04000200"),
        &hex("04000000 000001cd"),
        &hex("01000000 08000200 00000000 00000000 00000000"),
        &[0; 36],
        &wstr_bytes(READER),
    ]);
    for n in 0..good.len() {
        assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &good[..n]).is_err());
    }
    let mut bad = good.clone();
    bad[16 + 12] = 12; // cReaders 12 > range 11
    assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &bad).is_err());
    let mut bad = good.clone();
    bad[16 + 20] = 5; // context MaximumCount != cbContext
    assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &bad).is_err());
    let mut bad = good.clone();
    bad[16 + 28] = 2; // rgReaderStates MaximumCount != cReaders
    assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &bad).is_err());
    let mut bad = good.clone();
    bad[1] = 0x00; // big-endian stream
    assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &bad).is_err());
    let mut bad = good;
    bad[16 + 44] = 37; // cbAtr 37 > 36
    assert!(decode(SCARD_IOCTL_GETSTATUSCHANGEW, &bad).is_err());
}

#[test]
fn multi_string_round_trip() {
    let names = vec!["Reader A".to_string(), "Ä reader".to_string()];
    for wide in [true, false] {
        let back = parse_multi_string(&multi_string(&names, wide), wide);
        assert_eq!(back, names);
    }
    assert_eq!(multi_string(&[], true), vec![0, 0, 0, 0]);
}

// ---- Device against a mock backend ----

const MOCK_READER: &str = "Mock Reader 0";
const APDU_RESPONSE: [u8; 4] = [0xde, 0xad, 0x90, 0x00];

#[derive(Default)]
struct MockState {
    next: u64,
    contexts: HashSet<u64>,
    cards: HashMap<u64, u64>,
    released: Vec<u64>,
    disconnected: Vec<u64>,
    waiting: HashSet<u64>,
    cancelled: HashSet<u64>,
    card_present: bool,
    hold_connect: bool,
    calls: usize,
    transmitted: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Mock {
    s: Mutex<MockState>,
    cv: Condvar,
}

impl Mock {
    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        let mut s = self.s.lock().unwrap();
        s.calls += 1;
        s
    }
    fn with<R>(&self, f: impl FnOnce(&mut MockState) -> R) -> R {
        let r = f(&mut self.s.lock().unwrap());
        self.cv.notify_all();
        r
    }
    fn card(&self, card: u64) -> ScResult<()> {
        self.lock()
            .cards
            .contains_key(&card)
            .then_some(())
            .ok_or(SCARD_E_INVALID_HANDLE)
    }
}

impl SmartCardBackend for Mock {
    fn establish_context(&self, _scope: u32) -> ScResult<u64> {
        let mut s = self.lock();
        s.next += 1;
        let id = 1000 + s.next;
        s.contexts.insert(id);
        Ok(id)
    }
    fn release_context(&self, context: u64) -> ScResult<()> {
        let mut s = self.lock();
        if !s.contexts.remove(&context) {
            return Err(SCARD_E_INVALID_HANDLE);
        }
        s.released.push(context);
        self.cv.notify_all();
        Ok(())
    }
    fn is_valid_context(&self, context: u64) -> ScResult<()> {
        let ok = self.lock().contexts.contains(&context);
        ok.then_some(()).ok_or(SCARD_E_INVALID_HANDLE)
    }
    fn list_readers(&self, context: u64, _groups: &[String]) -> ScResult<Vec<String>> {
        self.is_valid_context(context)?;
        Ok(vec![MOCK_READER.into(), "Mock Reader 1".into()])
    }
    fn get_status_change(
        &self,
        ctx: u64,
        timeout: u32,
        states: &mut [ReaderState],
    ) -> ScResult<()> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout));
        let mut s = self.lock();
        s.waiting.insert(ctx);
        let r = loop {
            if s.cancelled.remove(&ctx) {
                break Err(SCARD_E_CANCELLED);
            }
            if !s.contexts.contains(&ctx) {
                break Err(SCARD_E_INVALID_HANDLE);
            }
            let actual = if s.card_present {
                SCARD_STATE_PRESENT
            } else {
                SCARD_STATE_EMPTY
            };
            let mut changed = false;
            for st in states.iter_mut() {
                if st.current_state & (SCARD_STATE_PRESENT | SCARD_STATE_EMPTY) != actual {
                    st.event_state = actual | SCARD_STATE_CHANGED;
                    st.atr = if s.card_present {
                        ATR.to_vec()
                    } else {
                        Vec::new()
                    };
                    changed = true;
                }
            }
            if changed {
                break Ok(());
            }
            let now = Instant::now();
            if timeout != 0xFFFF_FFFF && now >= deadline {
                break Err(SCARD_E_TIMEOUT);
            }
            s = self.cv.wait_timeout(s, deadline - now).unwrap().0;
        };
        s.waiting.remove(&ctx);
        r
    }
    fn cancel(&self, context: u64) -> ScResult<()> {
        let mut s = self.lock();
        if s.waiting.contains(&context) {
            s.cancelled.insert(context);
        }
        self.cv.notify_all();
        Ok(())
    }
    fn connect(&self, context: u64, reader: &str, _share: u32, _p: u32) -> ScResult<(u64, u32)> {
        let mut s = self.lock();
        while s.hold_connect {
            s = self.cv.wait(s).unwrap();
        }
        if !s.contexts.contains(&context) {
            return Err(SCARD_E_INVALID_HANDLE);
        }
        if reader != MOCK_READER {
            return Err(SCARD_E_UNKNOWN_READER);
        }
        if !s.card_present {
            return Err(SCARD_E_NO_SMARTCARD);
        }
        s.next += 1;
        let card = 5000 + s.next;
        s.cards.insert(card, context);
        Ok((card, SCARD_PROTOCOL_T1))
    }
    fn reconnect(&self, card: u64, _s: u32, _p: u32, _i: u32) -> ScResult<u32> {
        self.card(card).map(|_| SCARD_PROTOCOL_T1)
    }
    fn disconnect(&self, card: u64, _disposition: u32) -> ScResult<()> {
        let mut s = self.lock();
        s.cards.remove(&card).ok_or(SCARD_E_INVALID_HANDLE)?;
        s.disconnected.push(card);
        Ok(())
    }
    fn begin_transaction(&self, card: u64) -> ScResult<()> {
        self.card(card)
    }
    fn end_transaction(&self, card: u64, _disposition: u32) -> ScResult<()> {
        self.card(card)
    }
    fn status(&self, card: u64) -> ScResult<CardStatus> {
        self.card(card)?;
        Ok(CardStatus {
            readers: vec![MOCK_READER.into()],
            state: 6,
            protocol: SCARD_PROTOCOL_T1,
            atr: ATR.to_vec(),
        })
    }
    fn transmit(
        &self,
        card: u64,
        _pci: &IoPci,
        send: &[u8],
        recv_pci: Option<&IoPci>,
        recv_max: usize,
    ) -> ScResult<Transmitted> {
        self.card(card)?;
        if recv_max < APDU_RESPONSE.len() {
            return Err(SCARD_E_INSUFFICIENT_BUFFER);
        }
        self.lock().transmitted.push(send.to_vec());
        Ok(Transmitted {
            recv_pci: recv_pci.cloned(),
            data: APDU_RESPONSE.to_vec(),
        })
    }
    fn control(&self, card: u64, _code: u32, input: &[u8], _max: usize) -> ScResult<Vec<u8>> {
        self.card(card)
            .map(|_| input.iter().rev().copied().collect())
    }
    fn get_attrib(&self, card: u64, _attr: u32, _max: usize) -> ScResult<Vec<u8>> {
        self.card(card).map(|_| ATR.to_vec())
    }
    fn set_attrib(&self, card: u64, _attr: u32, _data: &[u8]) -> ScResult<()> {
        self.card(card)
    }
    fn get_device_type_id(&self, _context: u64, _reader: &str) -> ScResult<u32> {
        Ok(4)
    }
}

/// The device plus a running completion id.
struct Harness {
    mock: Arc<Mock>,
    dev: SmartCard,
    next: u32,
}

impl Harness {
    fn new() -> Self {
        let mock = Arc::new(Mock::default());
        let dev = SmartCard::new(mock.clone());
        Self { mock, dev, next: 0 }
    }

    /// Sends one IOCTL; returns its completion id and immediate answer.
    fn send(&mut self, ioctl: u32, input: &[u8]) -> (u32, Option<IoCompletion>) {
        self.next += 1;
        let mut data = Vec::new();
        data.put_u32(2048);
        data.put_u32(input.len() as u32);
        data.put_u32(ioctl);
        data.put_zeros(20);
        data.put_bytes(input);
        let req = IoRequest {
            device_id: 1,
            file_id: 1,
            completion_id: self.next,
            major: IRP_MJ_DEVICE_CONTROL,
            minor: 0,
            data: &data,
        };
        (self.next, self.dev.io(&req))
    }

    /// Sends an IOCTL answered at once.
    fn now(&mut self, ioctl: u32, input: &[u8]) -> IoCompletion {
        let (id, c) = self.send(ioctl, input);
        let c = c.expect("immediate completion");
        assert_eq!(c.completion_id, id);
        c
    }

    /// Waits (bounded) for the completion of `id` from `tick`.
    fn wait(&mut self, id: u32) -> IoCompletion {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(c) = self.dev.tick().into_iter().find(|c| c.completion_id == id) {
                return c;
            }
            assert!(Instant::now() < end, "completion {id} never arrived");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Sends an IOCTL that runs on a worker and waits for it.
    fn later(&mut self, ioctl: u32, input: &[u8]) -> IoCompletion {
        let (id, c) = self.send(ioctl, input);
        assert!(c.is_none(), "{} must complete from tick", ioctl_name(ioctl));
        self.wait(id)
    }

    fn establish(&mut self) -> Vec<u8> {
        let mut w = NdrWriter::default();
        w.u32(2);
        let c = self.now(SCARD_IOCTL_ESTABLISHCONTEXT, &w.finish());
        let mut r = out(&c);
        assert_eq!(r.u32().unwrap(), 0);
        let len = r.u32().unwrap();
        assert!(r.ptr().unwrap());
        r.conformant_bytes(len).unwrap()
    }
}

/// NDR reader on a successful DR_CONTROL_RSP's OutputBuffer.
fn out(c: &IoCompletion) -> NdrReader<'_> {
    assert_eq!(c.status, 0, "IoStatus");
    let len = u32::from_le_bytes(c.data[..4].try_into().unwrap()) as usize;
    assert_eq!(len, c.data.len() - 4);
    NdrReader::new(&c.data[4..]).unwrap()
}

fn return_code(c: &IoCompletion) -> u32 {
    out(c).u32().unwrap()
}

fn context_call(ctx: &[u8]) -> Vec<u8> {
    let mut w = NdrWriter::default();
    w.u32(ctx.len() as u32);
    w.ptr(true);
    w.conformant_bytes(ctx);
    w.finish()
}

fn wstring(w: &mut NdrWriter, s: &str) {
    let u = utf16le_z(s);
    let n = (u.len() / 2) as u32;
    w.u32(n);
    w.u32(0);
    w.u32(n);
    w.bytes(&u);
}

fn list_readers_call(ctx: &[u8], cch: u32) -> Vec<u8> {
    let mut w = NdrWriter::default();
    w.u32(ctx.len() as u32);
    w.ptr(true);
    w.u32(0);
    w.ptr(false);
    w.u32(0);
    w.u32(cch);
    w.conformant_bytes(ctx);
    w.finish()
}

fn status_change_call(ctx: &[u8], timeout: u32, current: u32) -> Vec<u8> {
    let mut w = NdrWriter::default();
    w.u32(ctx.len() as u32);
    w.ptr(true);
    w.u32(timeout);
    w.u32(1);
    w.ptr(true);
    w.conformant_bytes(ctx);
    w.u32(1);
    w.ptr(true);
    w.u32(current);
    w.u32(0);
    w.u32(0);
    w.bytes(&[0; 36]);
    wstring(&mut w, MOCK_READER);
    w.finish()
}

fn connect_call(ctx: &[u8]) -> Vec<u8> {
    let mut w = NdrWriter::default();
    w.ptr(true);
    w.u32(ctx.len() as u32);
    w.ptr(true);
    w.u32(2);
    w.u32(3);
    wstring(&mut w, MOCK_READER);
    w.conformant_bytes(ctx);
    w.finish()
}

fn card_head(w: &mut NdrWriter, card: &RemoteCard) {
    w.u32(card.context.len() as u32);
    w.ptr(true);
    w.u32(card.handle.len() as u32);
    w.ptr(true);
}

fn card_body(w: &mut NdrWriter, card: &RemoteCard) {
    w.conformant_bytes(&card.context);
    w.conformant_bytes(&card.handle);
}

fn disposition_call(card: &RemoteCard, disposition: u32) -> Vec<u8> {
    let mut w = NdrWriter::default();
    card_head(&mut w, card);
    w.u32(disposition);
    card_body(&mut w, card);
    w.finish()
}

fn transmit_call(card: &RemoteCard, apdu: &[u8], cb_recv: u32) -> Vec<u8> {
    let mut w = NdrWriter::default();
    card_head(&mut w, card);
    w.u32(SCARD_PROTOCOL_T1);
    w.u32(0);
    w.ptr(false);
    w.u32(apdu.len() as u32);
    w.ptr(true);
    w.ptr(false);
    w.u32(0);
    w.u32(cb_recv);
    card_body(&mut w, card);
    w.conformant_bytes(apdu);
    w.finish()
}

fn status_call(card: &RemoteCard) -> Vec<u8> {
    let mut w = NdrWriter::default();
    card_head(&mut w, card);
    w.u32(0);
    w.u32(SCARD_AUTOALLOCATE);
    w.u32(36);
    card_body(&mut w, card);
    w.finish()
}

/// Connects to the mock reader (card inserted) and returns the handle.
fn connect(h: &mut Harness, ctx: &[u8]) -> RemoteCard {
    h.mock.with(|s| s.card_present = true);
    let c = h.later(SCARD_IOCTL_CONNECTW, &connect_call(ctx));
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    let (cl, cp) = (r.u32().unwrap(), r.ptr().unwrap());
    let (hl, hp) = (r.u32().unwrap(), r.ptr().unwrap());
    assert!(cp && hp);
    assert_eq!(r.u32().unwrap(), SCARD_PROTOCOL_T1);
    RemoteCard {
        context: r.conformant_bytes(cl).unwrap(),
        handle: r.conformant_bytes(hl).unwrap(),
    }
}

#[test]
fn full_session_flow() {
    let mut h = Harness::new();
    let create = IoRequest {
        device_id: 1,
        file_id: 0,
        completion_id: 99,
        major: IRP_MJ_CREATE,
        minor: 0,
        data: &[],
    };
    assert_eq!(h.dev.io(&create).unwrap().data, vec![1, 0, 0, 0, 1]);

    // AccessStartedEvent: a 4-byte non-NDR buffer.
    let c = h.later(SCARD_IOCTL_ACCESSSTARTEDEVENT, &[0xAB; 4]);
    assert_eq!(return_code(&c), 0);

    let ctx = h.establish();
    assert_eq!(ctx.len(), 4);
    // The server never sees the backend's handle value.
    assert!(
        !h.mock
            .with(|s| s.contexts.iter().any(|&l| l.to_le_bytes()[..4] == ctx[..]))
    );
    assert_eq!(
        return_code(&h.now(SCARD_IOCTL_ISVALIDCONTEXT, &context_call(&ctx))),
        0
    );

    let c = h.now(
        SCARD_IOCTL_LISTREADERSW,
        &list_readers_call(&ctx, SCARD_AUTOALLOCATE),
    );
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    let len = r.u32().unwrap();
    assert!(r.ptr().unwrap());
    let msz = r.conformant_bytes(len).unwrap();
    assert_eq!(
        parse_multi_string(&msz, true),
        vec![MOCK_READER.to_string(), "Mock Reader 1".to_string()]
    );

    // Immediate: UNAWARE differs from EMPTY.
    let c = h.later(
        SCARD_IOCTL_GETSTATUSCHANGEW,
        &status_change_call(&ctx, 0, SCARD_STATE_UNAWARE),
    );
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32().unwrap(), 1);
    assert!(r.ptr().unwrap());
    assert_eq!(r.u32().unwrap(), 1);
    assert_eq!(r.u32().unwrap(), SCARD_STATE_UNAWARE);
    assert_eq!(r.u32().unwrap(), SCARD_STATE_EMPTY | SCARD_STATE_CHANGED);

    // Blocking: EMPTY stays EMPTY until a card is inserted.
    let (id, now) = h.send(
        SCARD_IOCTL_GETSTATUSCHANGEW,
        &status_change_call(&ctx, 0xFFFF_FFFF, SCARD_STATE_EMPTY),
    );
    assert!(now.is_none());
    std::thread::sleep(Duration::from_millis(30));
    assert!(h.dev.tick().is_empty(), "completed before any change");
    h.mock.with(|s| s.card_present = true);
    let c = h.wait(id);
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    r.u32().unwrap();
    r.ptr().unwrap();
    r.u32().unwrap();
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), SCARD_STATE_PRESENT | SCARD_STATE_CHANGED);
    assert_eq!(r.u32().unwrap(), 9);
    assert_eq!(r.bytes(9).unwrap(), ATR);

    let card = connect(&mut h, &ctx);
    assert_eq!(card.context, ctx);
    assert_eq!(h.dev.handle_count(), (1, 1));

    let c = h.later(
        SCARD_IOCTL_BEGINTRANSACTION,
        &disposition_call(&card, SCARD_LEAVE_CARD),
    );
    assert_eq!(return_code(&c), 0);

    let apdu = [0x00, 0xa4, 0x04, 0x00];
    let c = h.later(SCARD_IOCTL_TRANSMIT, &transmit_call(&card, &apdu, 258));
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    assert!(!r.ptr().unwrap(), "no receive PCI was asked for");
    assert_eq!(r.u32().unwrap(), 4);
    assert!(r.ptr().unwrap());
    assert_eq!(r.conformant_bytes(4).unwrap(), APDU_RESPONSE);
    assert_eq!(h.mock.with(|s| s.transmitted.clone()), vec![apdu.to_vec()]);

    let c = h.now(SCARD_IOCTL_STATUSW, &status_call(&card));
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    let len = r.u32().unwrap();
    assert!(r.ptr().unwrap());
    assert_eq!(r.u32().unwrap(), 6);
    assert_eq!(r.u32().unwrap(), SCARD_PROTOCOL_T1);
    assert_eq!(&r.bytes(32).unwrap()[..9], ATR);
    assert_eq!(r.u32().unwrap(), 9);
    let names = r.conformant_bytes(len).unwrap();
    assert_eq!(
        parse_multi_string(&names, true),
        vec![MOCK_READER.to_string()]
    );

    let c = h.now(
        SCARD_IOCTL_ENDTRANSACTION,
        &disposition_call(&card, SCARD_LEAVE_CARD),
    );
    assert_eq!(return_code(&c), 0);
    let c = h.now(
        SCARD_IOCTL_DISCONNECT,
        &disposition_call(&card, SCARD_RESET_CARD),
    );
    assert_eq!(return_code(&c), 0);
    assert_eq!(h.dev.handle_count(), (1, 0));
    assert_eq!(h.mock.with(|s| s.disconnected.len()), 1);

    let c = h.now(SCARD_IOCTL_RELEASECONTEXT, &context_call(&ctx));
    assert_eq!(return_code(&c), 0);
    assert_eq!(h.dev.handle_count(), (0, 0));
    assert!(h.mock.with(|s| s.contexts.is_empty()));
    // A released id is unknown from now on.
    let c = h.now(SCARD_IOCTL_ISVALIDCONTEXT, &context_call(&ctx));
    assert_eq!(return_code(&c), SCARD_E_INVALID_HANDLE);
}

#[test]
fn cancel_completes_a_waiting_status_change() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let (id, now) = h.send(
        SCARD_IOCTL_GETSTATUSCHANGEW,
        &status_change_call(&ctx, 0xFFFF_FFFF, SCARD_STATE_EMPTY),
    );
    assert!(now.is_none());
    // Wait until the worker is inside the backend.
    let end = Instant::now() + Duration::from_secs(5);
    while !h.mock.with(|s| s.waiting.contains(&1001)) {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    let c = h.now(SCARD_IOCTL_CANCEL, &context_call(&ctx));
    assert_eq!(return_code(&c), 0);
    assert_eq!(return_code(&h.wait(id)), SCARD_E_CANCELLED);
}

#[test]
fn status_change_timeout_is_passed_to_the_backend() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let c = h.later(
        SCARD_IOCTL_GETSTATUSCHANGEW,
        &status_change_call(&ctx, 20, SCARD_STATE_EMPTY),
    );
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), SCARD_E_TIMEOUT);
    assert_eq!(r.u32().unwrap(), 0, "no states on failure");
}

#[test]
fn unknown_and_forged_handles_are_rejected() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let card = connect(&mut h, &ctx);
    let ctx2 = h.establish();
    let c = h.later(SCARD_IOCTL_TRANSMIT, &transmit_call(&card, &[0], 258));
    assert_eq!(return_code(&c), 0, "the real handle works");
    let calls = h.mock.with(|s| s.calls);

    // Unknown context id, wrong length, and the backend's own value.
    for bad in [
        vec![9, 9, 9, 9],
        vec![],
        ctx.repeat(2),
        1001u32.to_le_bytes().to_vec(),
    ] {
        let c = h.now(SCARD_IOCTL_LISTREADERSW, &list_readers_call(&bad, 0));
        assert_eq!(return_code(&c), SCARD_E_INVALID_HANDLE, "{bad:?}");
    }
    // A real card id under another context.
    let crossed = RemoteCard {
        context: ctx2.clone(),
        handle: card.handle.clone(),
    };
    let c = h.now(SCARD_IOCTL_TRANSMIT, &transmit_call(&crossed, &[0], 258));
    assert_eq!(return_code(&c), SCARD_E_INVALID_HANDLE);
    // A context id used as a card id.
    let swapped = RemoteCard {
        context: ctx.clone(),
        handle: ctx.clone(),
    };
    let c = h.now(SCARD_IOCTL_STATUSW, &status_call(&swapped));
    assert_eq!(return_code(&c), SCARD_E_INVALID_HANDLE);
    assert_eq!(
        h.mock.with(|s| s.calls),
        calls,
        "backend reached with a bad handle"
    );
}

#[test]
fn removing_the_device_releases_everything() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let _card = connect(&mut h, &ctx);
    let _ctx2 = h.establish();
    let (id, now) = h.send(
        SCARD_IOCTL_GETSTATUSCHANGEW,
        &status_change_call(&ctx, 0xFFFF_FFFF, SCARD_STATE_PRESENT),
    );
    assert!(now.is_none());
    let end = Instant::now() + Duration::from_secs(5);
    while !h.mock.with(|s| s.waiting.contains(&1001)) {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    h.dev.closed();
    let s = h
        .mock
        .with(|s| (s.contexts.len(), s.cards.len(), s.released.len()));
    assert_eq!(s, (0, 0, 2));
    assert_eq!(h.dev.handle_count(), (0, 0));
    // The cancelled call's result belongs to the old session: dropped.
    let end = Instant::now() + Duration::from_millis(200);
    while Instant::now() < end {
        assert!(h.dev.tick().iter().all(|c| c.completion_id != id));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(h.mock.with(|s| s.waiting.is_empty()));
}

#[test]
fn a_connect_finishing_after_removal_is_disconnected() {
    let mut h = Harness::new();
    let ctx = h.establish();
    h.mock.with(|s| {
        s.card_present = true;
        s.hold_connect = true;
    });
    let (_, now) = h.send(SCARD_IOCTL_CONNECTW, &connect_call(&ctx));
    assert!(now.is_none());
    let Harness { mock, dev, .. } = h;
    drop(dev); // releases the context; the worker is still in connect
    // Re-create the context the held connect will use, then let it run.
    mock.with(|s| {
        s.contexts.insert(1001);
        s.hold_connect = false;
    });
    let end = Instant::now() + Duration::from_secs(5);
    while mock.with(|s| s.disconnected.is_empty()) {
        assert!(Instant::now() < end, "card handle leaked");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(mock.with(|s| s.cards.is_empty()));
}

#[test]
fn length_queries_and_small_buffers() {
    let mut h = Harness::new();
    let ctx = h.establish();
    // cchReaders 0: length only, null msz.
    let c = h.now(SCARD_IOCTL_LISTREADERSW, &list_readers_call(&ctx, 0));
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    let full = multi_string(&[MOCK_READER.into(), "Mock Reader 1".into()], true);
    assert_eq!(r.u32().unwrap() as usize, full.len());
    assert!(!r.ptr().unwrap());
    // Exactly enough characters, then one too few.
    let chars = (full.len() / 2) as u32;
    let c = h.now(SCARD_IOCTL_LISTREADERSW, &list_readers_call(&ctx, chars));
    assert_eq!(return_code(&c), 0);
    let c = h.now(
        SCARD_IOCTL_LISTREADERSW,
        &list_readers_call(&ctx, chars - 1),
    );
    assert_eq!(return_code(&c), SCARD_E_INSUFFICIENT_BUFFER);
    // ANSI: one byte per character.
    let c = h.now(
        SCARD_IOCTL_LISTREADERSA,
        &list_readers_call(&ctx, SCARD_AUTOALLOCATE),
    );
    let mut r = out(&c);
    assert_eq!(r.u32().unwrap(), 0);
    let len = r.u32().unwrap();
    r.ptr().unwrap();
    assert_eq!(
        r.conformant_bytes(len).unwrap(),
        b"Mock Reader 0\0Mock Reader 1\0\0"
    );
    // Transmit into a 2-byte buffer: the 4-byte response does not fit.
    let card = connect(&mut h, &ctx);
    let c = h.later(SCARD_IOCTL_TRANSMIT, &transmit_call(&card, &[0], 2));
    assert_eq!(return_code(&c), SCARD_E_INSUFFICIENT_BUFFER);
}

#[test]
fn unsupported_unknown_and_malformed_ioctls() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let c = h.now(SCARD_IOCTL_LOCATECARDSW, &context_call(&ctx));
    assert_eq!(
        c.data[4..],
        Reply::error(SCARD_IOCTL_LOCATECARDSW, SCARD_E_UNSUPPORTED_FEATURE).encode()[..]
    );
    assert_eq!(
        return_code(&h.now(SCARD_IOCTL_READCACHEW, &[])),
        SCARD_W_CACHE_ITEM_NOT_FOUND
    );
    assert_eq!(return_code(&h.now(SCARD_IOCTL_WRITECACHEW, &[])), 0);
    assert_eq!(
        return_code(&h.now(SCARD_IOCTL_RELEASETARTEDEVENT, &[0; 4])),
        0
    );

    let c = h.now(0x0009_0200, &[]);
    assert_eq!(
        (c.status, c.data.clone()),
        (STATUS_NOT_SUPPORTED, vec![0; 4])
    );
    let good = connect_call(&ctx);
    for n in [0, 8, 16, 20, good.len() - 1] {
        let c = h.now(SCARD_IOCTL_CONNECTW, &good[..n]);
        assert_eq!(
            (c.status, c.data.clone()),
            (STATUS_INVALID_PARAMETER, vec![0; 4])
        );
    }
    // A DR_CONTROL_REQ shorter than its own header.
    let req = IoRequest {
        device_id: 1,
        file_id: 1,
        completion_id: 7,
        major: IRP_MJ_DEVICE_CONTROL,
        minor: 0,
        data: &[1, 2, 3],
    };
    assert_eq!(h.dev.io(&req).unwrap().status, STATUS_INVALID_PARAMETER);
    let read = IoRequest {
        major: IRP_MJ_READ,
        ..req
    };
    assert_eq!(h.dev.io(&read).unwrap().status, STATUS_NOT_SUPPORTED);
}

#[test]
fn device_is_announced_before_logon_and_removed_live() {
    let mock = Arc::new(Mock::default());
    let (mut ch, handle) = crate::rdpdr::rdpdr("PC");
    let id = handle.add_device(smart_card_device(mock.clone()));
    let mut feed = |msg: &[u8]| {
        let mut out = ChannelOut::default();
        ch.process(msg, &mut out).unwrap();
        ch.tick(&mut out).unwrap();
        out.take()
    };
    // Server Announce (MS-RDPEFS 2.2.2.2), then Client ID Confirm (2.2.2.6):
    // no User Logged On yet.
    feed(&hex("7244 6e49 0100 0c00 07000000"));
    let out = feed(&hex("7244 4343 0100 0c00 07000000"));
    let mut announce = hex("7244 4144 01000000 20000000");
    announce.put_u32(id);
    announce.put_bytes(b"SCARD\0\0\0");
    announce.put_u32(0);
    assert_eq!(out, vec![announce]);

    // EstablishContext through the channel, then a live removal.
    let mut call = hex("7244 5249");
    call.put_u32(id);
    call.put_bytes(&hex("01000000 05000000 0e000000 00000000"));
    let mut w = NdrWriter::default();
    w.u32(2);
    let input = w.finish();
    call.put_u32(2048);
    call.put_u32(input.len() as u32);
    call.put_u32(SCARD_IOCTL_ESTABLISHCONTEXT);
    call.put_zeros(20);
    call.put_bytes(&input);
    let out = feed(&call);
    assert_eq!(out.len(), 1);
    // Device I/O Response (2.2.1.5): device id, completion id 5, success.
    let mut head = hex("7244 4349");
    head.put_u32(id);
    head.put_bytes(&hex("05000000 00000000"));
    assert_eq!(out[0][..16], head[..]);
    assert_eq!(mock.with(|s| s.contexts.len()), 1);

    handle.remove(id);
    let mut out = ChannelOut::default();
    ch.tick(&mut out).unwrap();
    let mut remove = hex("7244 4d44 01000000");
    remove.put_u32(id);
    assert_eq!(out.take(), vec![remove]);
    assert_eq!(mock.with(|s| (s.contexts.len(), s.released.len())), (0, 1));
}

#[test]
fn releasing_a_context_disconnects_its_cards() {
    let mut h = Harness::new();
    let ctx = h.establish();
    let card = connect(&mut h, &ctx);
    let other = h.establish();
    let _other_card = connect(&mut h, &other);
    let c = h.now(SCARD_IOCTL_RELEASECONTEXT, &context_call(&ctx));
    assert_eq!(return_code(&c), 0);
    assert_eq!(h.dev.handle_count(), (1, 1));
    assert_eq!(
        h.mock.with(|s| s.cards.len()),
        1,
        "card of the released context leaked"
    );
    let c = h.now(SCARD_IOCTL_STATUSW, &status_call(&card));
    assert_eq!(return_code(&c), SCARD_E_INVALID_HANDLE);
}
