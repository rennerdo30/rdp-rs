//! Tests: the MS-RDPESP 4.x example bytes, the IOCTL buffers of ntddser.h,
//! and the device against a mock port (no real port is ever opened).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::Put;
use crate::rdpdr::fscc::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};
use crate::rdpdr::{
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, IoCompletion,
    IoRequest, Rdpdr, rdpdr,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- mock port ----

#[derive(Default)]
struct State {
    rx: VecDeque<u8>,
    written: Vec<u8>,
    /// Writes wait while set (a port held by flow control).
    hold_writes: bool,
    baud: u32,
    line: LineControl,
    timeouts: Timeouts,
    chars: Chars,
    handflow: Handflow,
    wait_mask: u32,
    events: u32,
    read_epoch: u64,
    write_epoch: u64,
    wait_epoch: u64,
    closed: bool,
    closes: usize,
    controls: Vec<SerialControl>,
}

#[derive(Default)]
struct Shared {
    s: Mutex<State>,
    cv: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.s.lock().unwrap()
    }
    fn change(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.lock());
        self.cv.notify_all();
    }
}

struct MockPort(Arc<Shared>);

impl SerialPort for MockPort {
    fn read(&self, max: usize) -> PortResult<Vec<u8>> {
        let mut s = self.0.lock();
        let epoch = s.read_epoch;
        loop {
            if s.closed || s.read_epoch != epoch {
                return Err(STATUS_CANCELLED);
            }
            if !s.rx.is_empty() {
                let n = max.min(s.rx.len());
                return Ok(s.rx.drain(..n).collect());
            }
            s = self.0.cv.wait(s).unwrap();
        }
    }

    fn write(&self, data: &[u8]) -> PortResult<u32> {
        let mut s = self.0.lock();
        let epoch = s.write_epoch;
        while s.hold_writes {
            if s.closed || s.write_epoch != epoch {
                return Err(STATUS_CANCELLED);
            }
            s = self.0.cv.wait(s).unwrap();
        }
        s.written.extend_from_slice(data);
        Ok(data.len() as u32)
    }

    fn wait_event(&self) -> PortResult<u32> {
        let mut s = self.0.lock();
        let epoch = s.wait_epoch;
        loop {
            if s.closed {
                return Err(STATUS_CANCELLED);
            }
            if s.wait_epoch != epoch {
                return Ok(0);
            }
            let hit = s.events & s.wait_mask;
            if hit != 0 {
                s.events &= !hit;
                return Ok(hit);
            }
            s = self.0.cv.wait(s).unwrap();
        }
    }

    fn control(&self, c: &SerialControl) -> PortResult<ControlOut> {
        let mut s = self.0.lock();
        s.controls.push(c.clone());
        let out = match c {
            SerialControl::SetBaudRate(b) => {
                s.baud = *b;
                ControlOut::None
            }
            SerialControl::GetBaudRate => ControlOut::U32(s.baud),
            SerialControl::SetLineControl(v) => {
                s.line = *v;
                ControlOut::None
            }
            SerialControl::GetLineControl => ControlOut::LineControl(s.line),
            SerialControl::SetTimeouts(v) => {
                s.timeouts = *v;
                ControlOut::None
            }
            SerialControl::GetTimeouts => ControlOut::Timeouts(s.timeouts),
            SerialControl::SetChars(v) => {
                s.chars = *v;
                ControlOut::None
            }
            SerialControl::GetChars => ControlOut::Chars(s.chars),
            SerialControl::SetHandflow(v) => {
                s.handflow = *v;
                ControlOut::None
            }
            SerialControl::GetHandflow => ControlOut::Handflow(s.handflow),
            SerialControl::SetWaitMask(m) => {
                s.wait_mask = *m;
                s.wait_epoch += 1;
                ControlOut::None
            }
            SerialControl::GetWaitMask => ControlOut::U32(s.wait_mask),
            SerialControl::Purge(m) => {
                if m & SERIAL_PURGE_RXABORT != 0 {
                    s.read_epoch += 1;
                }
                if m & SERIAL_PURGE_TXABORT != 0 {
                    s.write_epoch += 1;
                }
                if m & SERIAL_PURGE_RXCLEAR != 0 {
                    s.rx.clear();
                }
                ControlOut::None
            }
            SerialControl::GetModemStatus => ControlOut::U32(0x30),
            SerialControl::GetDtrRts => ControlOut::U32(SERIAL_DTR_STATE),
            SerialControl::GetCommStatus => ControlOut::Status(CommStatus {
                in_queue: s.rx.len() as u32,
                ..CommStatus::default()
            }),
            SerialControl::GetProperties => ControlOut::Properties(CommProp {
                packet_length: 64,
                max_baud: 0x1000_0000,
                ..CommProp::default()
            }),
            SerialControl::Raw { output_len, .. } => {
                ControlOut::Bytes(vec![0xAB; *output_len as usize + 8])
            }
            _ => ControlOut::None,
        };
        drop(s);
        self.0.cv.notify_all();
        Ok(out)
    }

    fn close(&self) {
        self.0.change(|s| {
            s.closed = true;
            s.closes += 1;
        });
    }
}

#[derive(Default)]
struct MockBackend {
    port: Arc<Shared>,
    fail: Option<u32>,
    opens: AtomicUsize,
}

impl MockBackend {
    fn new() -> Arc<MockBackend> {
        let b = MockBackend::default();
        b.port.lock().baud = 9600;
        Arc::new(b)
    }
}

impl SerialBackend for MockBackend {
    fn open(&self, port: &str) -> PortResult<Arc<dyn SerialPort>> {
        assert!(PortKind::of_name(port).is_some(), "only port names: {port}");
        if let Some(e) = self.fail {
            return Err(e);
        }
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.port.change(|s| s.closed = false);
        Ok(Arc::new(MockPort(self.port.clone())))
    }
}

// ---- device helpers ----

fn device(name: &str, b: &Arc<MockBackend>) -> SerialPortDevice {
    SerialPortDevice::new(PortInfo::new(name).unwrap(), b.clone())
}

fn req<'a>(file: u32, cid: u32, major: u32, data: &'a [u8]) -> IoRequest<'a> {
    IoRequest {
        device_id: 1,
        file_id: file,
        completion_id: cid,
        major,
        minor: 0,
        data,
    }
}

/// Ticks until `n` completions came (or 5 s passed).
fn wait_for(d: &mut SerialPortDevice, n: usize) -> Vec<IoCompletion> {
    let start = Instant::now();
    let mut out = Vec::new();
    while out.len() < n {
        out.extend(d.tick());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "only {} of {n} completions: {out:?}",
            out.len()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    out
}

/// No completion within a short while.
fn quiet(d: &mut SerialPortDevice) {
    std::thread::sleep(Duration::from_millis(30));
    let out = d.tick();
    assert!(out.is_empty(), "unexpected {out:?}");
}

fn create_req() -> Vec<u8> {
    // MS-RDPESP 4.2: DesiredAccess, AllocationSize, FileAttributes,
    // SharedAccess, CreateDisposition, CreateOptions, PathLength 0.
    hex(
        "80 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 07 00 00 00 01 00 00 00 60 00 00 00 00 00 00 00",
    )
}

fn open(d: &mut SerialPortDevice) -> u32 {
    assert!(d.io(&req(0, 100, IRP_MJ_CREATE, &create_req())).is_none());
    let c = wait_for(d, 1);
    assert_eq!(c[0].status, STATUS_SUCCESS);
    assert_eq!(c[0].data.len(), 5);
    assert_eq!(c[0].data[4], 0, "Information 0 (MS-RDPESP 3.2.5.1.7)");
    u32::from_le_bytes(c[0].data[..4].try_into().unwrap())
}

fn read_req(len: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u32(len);
    v.put_zeros(8 + 20);
    v
}

fn write_req(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u32(data.len() as u32);
    v.put_zeros(8 + 20);
    v.put_bytes(data);
    v
}

fn control_req(code: u32, input: &[u8], output_len: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u32(output_len);
    v.put_u32(input.len() as u32);
    v.put_u32(code);
    v.put_zeros(20);
    v.put_bytes(input);
    v
}

/// Runs one IOCTL to its completion.
fn ioctl(d: &mut SerialPortDevice, file: u32, code: u32, input: &[u8], out: u32) -> IoCompletion {
    let r = control_req(code, input, out);
    match d.io(&req(file, 77, IRP_MJ_DEVICE_CONTROL, &r)) {
        Some(c) => c,
        None => wait_for(d, 1).remove(0),
    }
}

/// DR_CONTROL_RSP output bytes.
fn output(c: &IoCompletion) -> &[u8] {
    let n = u32::from_le_bytes(c.data[..4].try_into().unwrap()) as usize;
    assert_eq!(c.data.len(), 4 + n);
    &c.data[4..]
}

// ---- MS-RDPESP 4.1: announce ----

const SERVER_ANNOUNCE: &str = "72 44 6e 49 01 00 0c 00 02 00 00 00";
const CLIENT_ID_CONFIRM: &str = "72 44 43 43 01 00 0c 00 02 00 00 00";
const USER_LOGGED_ON: &str = "72 44 4c 55";

fn feed(ch: &mut Rdpdr, msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = ChannelOut::default();
    ch.process(msg, &mut out).unwrap();
    out.take()
}

fn tick(ch: &mut Rdpdr) -> Vec<Vec<u8>> {
    let mut out = ChannelOut::default();
    ch.tick(&mut out).unwrap();
    out.take()
}

fn logged_on() -> (Rdpdr, crate::rdpdr::RdpdrHandle) {
    let (mut ch, h) = rdpdr("x");
    feed(&mut ch, &hex(SERVER_ANNOUNCE));
    feed(&mut ch, &hex(CLIENT_ID_CONFIRM));
    feed(&mut ch, &hex(USER_LOGGED_ON));
    (ch, h)
}

/// Ticks the channel until `n` PDUs went out.
fn tick_for(ch: &mut Rdpdr, n: usize) -> Vec<Vec<u8>> {
    let start = Instant::now();
    let mut out = Vec::new();
    while out.len() < n {
        out.extend(tick(ch));
        assert!(start.elapsed() < Duration::from_secs(5), "{out:?}");
        std::thread::sleep(Duration::from_millis(1));
    }
    out
}

#[test]
fn com2_announce_is_the_spec_example_4_1() {
    let b = MockBackend::new();
    let (mut ch, h) = logged_on();
    h.add_device(port_device("COM2", b.clone()).unwrap());
    assert_eq!(
        tick(&mut ch),
        vec![hex("72 44 41 44 01 00 00 00 01 00 00 00 01 00 00 00
             43 4f 4d 32 00 00 00 00 00 00 00 00")]
    );
}

#[test]
fn lpt1_device_entry_is_the_spec_example_4_1() {
    let b = MockBackend::new();
    let (mut ch, h) = logged_on();
    h.add_device(port_device("COM1", b.clone()).unwrap());
    h.add_device(port_device("lpt1", b.clone()).unwrap());
    let out = tick(&mut ch);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][4..8], &[2, 0, 0, 0], "two devices");
    // The LPT1 DEVICE_ANNOUNCE of 4.1: parallel, id 2, "LPT1", no data.
    assert!(
        out[0].ends_with(&hex(
            "02 00 00 00 02 00 00 00 4c 50 54 31 00 00 00 00 00 00 00 00"
        )),
        "{:02x?}",
        out[0]
    );
}

#[test]
fn only_com_and_lpt_names_become_devices() {
    let b = MockBackend::new();
    for bad in [
        "",
        "COM",
        "COM0",
        "COM01",
        "COM1234",
        "PRN1",
        "COM1;",
        r"\\.\COM1",
        "LPTX",
    ] {
        assert!(port_device(bad, b.clone()).is_none(), "{bad}");
    }
    assert_eq!(PortKind::of_name("com12"), Some(PortKind::Serial));
    assert_eq!(PortKind::of_name("LPT3"), Some(PortKind::Parallel));
    assert_eq!(PortInfo::new("com12").unwrap().name, "COM12");
}

#[test]
fn live_remove_closes_the_port_and_sends_device_list_remove() {
    let b = MockBackend::new();
    let (mut ch, h) = logged_on();
    let id = h.add_device(port_device("COM3", b.clone()).unwrap());
    assert_eq!(tick(&mut ch).len(), 1);
    // Open it and leave a read pending.
    let mut create = hex("72 44 52 49 01 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00");
    create.extend(create_req());
    assert!(feed(&mut ch, &create).is_empty(), "answered from tick");
    let opened = tick_for(&mut ch, 1);
    assert_eq!(
        opened[0],
        hex("72 44 43 49 01 00 00 00 05 00 00 00 00 00 00 00 01 00 00 00 00")
    );
    let mut read = hex("72 44 52 49 01 00 00 00 01 00 00 00 06 00 00 00 03 00 00 00 00 00 00 00");
    read.extend(read_req(16));
    assert!(feed(&mut ch, &read).is_empty());
    h.remove(id);
    assert_eq!(
        tick(&mut ch),
        vec![hex("72 44 4d 44 01 00 00 00 01 00 00 00")]
    );
    // The port is released and the cancelled read sends nothing.
    let start = Instant::now();
    while !b.port.lock().closed {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(20));
    assert!(tick(&mut ch).is_empty());
    // Shared again: a new id, announced at once.
    let again = h.add_device(port_device("COM3", b.clone()).unwrap());
    assert_ne!(again, id);
    let out = tick(&mut ch);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][12..16], &again.to_le_bytes());
    assert_eq!(&out[0][16..24], &hex("43 4f 4d 33 00 00 00 00")[..]);
}

// ---- MS-RDPESP 4.2-4.4: create, read, write, control, close ----

#[test]
fn io_examples_4_2_to_4_4_answer_with_the_spec_bytes() {
    let com1 = MockBackend::new();
    let com2 = MockBackend::new();
    let (mut ch, h) = logged_on();
    assert_eq!(h.add_device(port_device("COM1", com1.clone()).unwrap()), 1);
    assert_eq!(h.add_device(port_device("COM2", com2.clone()).unwrap()), 2);
    assert_eq!(tick(&mut ch).len(), 1);

    // 4.2 Server Create Request (device 1, completion 1, PathLength 0), and
    // the same on each device twice: files 1 and 2 on both.
    let create = |dev: u8, cid: u8| {
        let mut v = hex(&format!(
            "72 44 52 49 {dev:02x} 00 00 00 00 00 00 00 {cid:02x} 00 00 00 00 00 00 00 00 00 00 00"
        ));
        v.extend(create_req());
        v
    };
    assert_eq!(
        create(1, 1),
        hex("72 44 52 49 01 00 00 00 00 00 00 00 01 00 00 00
             00 00 00 00 00 00 00 00 80 00 10 00 00 00 00 00
             00 00 00 00 00 00 00 00 07 00 00 00 01 00 00 00
             60 00 00 00 00 00 00 00"),
        "the 4.2 bytes"
    );
    feed(&mut ch, &create(1, 1));
    // 4.3: FileId 1, Information 0 (DeviceId/CompletionId of the request).
    assert_eq!(
        tick_for(&mut ch, 1),
        vec![hex(
            "72 44 43 49 01 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00"
        )]
    );
    for (dev, cid) in [(1, 2), (2, 3), (2, 4)] {
        feed(&mut ch, &create(dev, cid));
        let r = tick_for(&mut ch, 1);
        assert_eq!(&r[0][12..16], &[0, 0, 0, 0], "success");
    }

    // 4.4 Server read request: device 2, file 2, 0x208 bytes.
    let payload: Vec<u8> = (0..0x208u32).map(|i| (i * 7) as u8).collect();
    com2.port.change(|s| s.rx.extend(payload.iter().copied()));
    let read = hex("72 44 52 49 02 00 00 00 02 00 00 00 00 00 00 00
         03 00 00 00 00 00 00 00 08 02 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00");
    assert!(feed(&mut ch, &read).is_empty());
    let r = tick_for(&mut ch, 1);
    let mut expect = hex("72 44 43 49 02 00 00 00 00 00 00 00 00 00 00 00 08 02 00 00");
    expect.extend(&payload);
    assert_eq!(r, vec![expect], "4.4 Client read response");

    // 4.4 Server write request: device 1, file 2, 0x208 bytes.
    let mut write = hex("72 44 52 49 01 00 00 00 02 00 00 00 00 00 00 00
         04 00 00 00 00 00 00 00 08 02 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00");
    write.extend(&payload);
    feed(&mut ch, &write);
    assert_eq!(
        tick_for(&mut ch, 1),
        vec![hex(
            "72 44 43 49 01 00 00 00 00 00 00 00 00 00 00 00 08 02 00 00 00"
        )],
        "4.4 Client write response"
    );
    assert_eq!(com1.port.lock().written, payload);

    // 4.4 Server device control request: IOCTL_SERIAL_GET_BAUD_RATE.
    let control = hex("72 44 52 49 02 00 00 00 02 00 00 00 00 00 00 00
         0E 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
         50 00 1b 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00");
    feed(&mut ch, &control);
    assert_eq!(
        tick_for(&mut ch, 1),
        vec![hex(
            "72 44 43 49 02 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 80 25 00 00"
        )],
        "4.4 Client device control response: 9600 baud"
    );

    // 4.4 Server close request: device 1, file 1, completion 1.
    let close = hex("72 44 52 49 01 00 00 00 01 00 00 00 01 00 00 00
         02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00");
    feed(&mut ch, &close);
    assert_eq!(
        tick_for(&mut ch, 1),
        vec![hex(
            "72 44 43 49 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00"
        )],
        "4.4 Client close response"
    );
    assert_eq!(com1.port.lock().closes, 1);
}

#[test]
fn open_failure_answers_the_backend_status() {
    let b = Arc::new(MockBackend {
        fail: Some(STATUS_ACCESS_DENIED),
        ..MockBackend::default()
    });
    let mut d = device("COM4", &b);
    assert!(d.io(&req(0, 3, IRP_MJ_CREATE, &create_req())).is_none());
    let c = wait_for(&mut d, 1);
    assert_eq!(
        c,
        vec![IoCompletion {
            completion_id: 3,
            status: STATUS_ACCESS_DENIED,
            data: vec![0; 5],
        }]
    );
    assert_eq!(d.open_files(), 0);
}

#[test]
fn requests_on_unknown_files_and_truncated_requests_are_answered() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let c = d.io(&req(9, 1, IRP_MJ_READ, &read_req(4))).unwrap();
    assert_eq!((c.status, c.data), (STATUS_INVALID_HANDLE, vec![0; 4]));
    let c = d.io(&req(9, 2, IRP_MJ_CLOSE, &[0; 32])).unwrap();
    assert_eq!(c.status, STATUS_INVALID_HANDLE);
    let f = open(&mut d);
    // Write claiming more data than sent; control with a short header.
    let mut w = write_req(b"abc");
    w[0] = 200;
    let c = d.io(&req(f, 3, IRP_MJ_WRITE, &w)).unwrap();
    assert_eq!(c.status, STATUS_INVALID_PARAMETER);
    let c = d.io(&req(f, 4, IRP_MJ_DEVICE_CONTROL, &[1, 2, 3])).unwrap();
    assert_eq!(c.status, STATUS_INVALID_PARAMETER);
    assert!(b.port.lock().written.is_empty());
}

// ---- IOCTL buffers (ntddser.h) ----

#[test]
fn ioctl_input_buffers_decode_and_validate() {
    let k = PortKind::Serial;
    let d = |code, input: &[u8]| decode_ioctl(k, code, input, 64);
    assert_eq!(
        d(IOCTL_SERIAL_SET_BAUD_RATE, &hex("00 c2 01 00")),
        Ok(SerialControl::SetBaudRate(115_200))
    );
    assert_eq!(
        d(IOCTL_SERIAL_SET_BAUD_RATE, &[0, 0, 0, 0]),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        d(IOCTL_SERIAL_SET_BAUD_RATE, &[1, 0]),
        Err(STATUS_BUFFER_TOO_SMALL)
    );
    // StopBits, Parity, WordLength: 1 stop bit, even, 7 bits.
    assert_eq!(
        d(IOCTL_SERIAL_SET_LINE_CONTROL, &[0, 2, 7]),
        Ok(SerialControl::SetLineControl(LineControl {
            stop_bits: STOP_BIT_1,
            parity: EVEN_PARITY,
            word_length: 7
        }))
    );
    for bad in [
        [0, 0, 9],
        [0, 5, 8],
        [3, 0, 8],
        [1, 0, 8],
        [2, 0, 5],
        [0, 0, 4],
    ] {
        assert_eq!(
            d(IOCTL_SERIAL_SET_LINE_CONTROL, &bad),
            Err(STATUS_INVALID_PARAMETER),
            "{bad:?}"
        );
    }
    assert_eq!(
        d(IOCTL_SERIAL_SET_LINE_CONTROL, &[0, 0]),
        Err(STATUS_BUFFER_TOO_SMALL)
    );
    assert_eq!(
        d(
            IOCTL_SERIAL_SET_TIMEOUTS,
            &hex("ff ff ff ff 00 00 00 00 00 00 00 00 0a 00 00 00 e8 03 00 00")
        ),
        Ok(SerialControl::SetTimeouts(Timeouts {
            read_interval: u32::MAX,
            read_total_multiplier: 0,
            read_total_constant: 0,
            write_total_multiplier: 10,
            write_total_constant: 1000,
        }))
    );
    assert_eq!(
        d(
            IOCTL_SERIAL_SET_TIMEOUTS,
            &hex("ff ff ff ff 00 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00")
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        d(IOCTL_SERIAL_SET_CHARS, &[0x1a, 0, 0, 0x0d, 0x11, 0x13]),
        Ok(SerialControl::SetChars(Chars {
            eof: 0x1a,
            error: 0,
            brk: 0,
            event: 0x0d,
            xon: 0x11,
            xoff: 0x13
        }))
    );
    // CTS handshake, DTR control; RTS handshake; limits 2048 / 512.
    assert_eq!(
        d(
            IOCTL_SERIAL_SET_HANDFLOW,
            &hex("09 00 00 00 80 00 00 00 00 08 00 00 00 02 00 00")
        ),
        Ok(SerialControl::SetHandflow(Handflow {
            control_handshake: SERIAL_CTS_HANDSHAKE | SERIAL_DTR_CONTROL,
            flow_replace: SERIAL_RTS_HANDSHAKE,
            xon_limit: 2048,
            xoff_limit: 512,
        }))
    );
    for bad in [
        "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", // DTR control + handshake
        "04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", // reserved control bit
        "00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00", // reserved flow bit
        "00 00 00 00 00 00 00 00 ff ff ff ff 00 00 00 00", // negative XonLimit
    ] {
        assert_eq!(
            d(IOCTL_SERIAL_SET_HANDFLOW, &hex(bad)),
            Err(STATUS_INVALID_PARAMETER),
            "{bad}"
        );
    }
    assert_eq!(
        d(IOCTL_SERIAL_SET_QUEUE_SIZE, &hex("00 10 00 00 00 08 00 00")),
        Ok(SerialControl::SetQueueSize {
            input: 4096,
            output: 2048
        })
    );
    assert_eq!(
        d(IOCTL_SERIAL_SET_WAIT_MASK, &hex("81 01 00 00")),
        Ok(SerialControl::SetWaitMask(
            SERIAL_EV_RXCHAR | SERIAL_EV_ERR | SERIAL_EV_RING
        ))
    );
    assert_eq!(
        d(IOCTL_SERIAL_SET_WAIT_MASK, &hex("00 20 00 00")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        d(IOCTL_SERIAL_PURGE, &hex("0a 00 00 00")),
        Ok(SerialControl::Purge(0x0a))
    );
    assert_eq!(
        d(IOCTL_SERIAL_PURGE, &hex("00 00 00 00")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        d(IOCTL_SERIAL_PURGE, &hex("10 00 00 00")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        d(IOCTL_SERIAL_IMMEDIATE_CHAR, &[0x13]),
        Ok(SerialControl::ImmediateChar(0x13))
    );
    assert_eq!(
        d(IOCTL_SERIAL_IMMEDIATE_CHAR, &[]),
        Err(STATUS_BUFFER_TOO_SMALL)
    );
    for (code, op) in [
        (IOCTL_SERIAL_SET_DTR, LineOp::SetDtr),
        (IOCTL_SERIAL_CLR_DTR, LineOp::ClrDtr),
        (IOCTL_SERIAL_SET_RTS, LineOp::SetRts),
        (IOCTL_SERIAL_CLR_RTS, LineOp::ClrRts),
        (IOCTL_SERIAL_SET_XOFF, LineOp::SetXoff),
        (IOCTL_SERIAL_SET_XON, LineOp::SetXon),
        (IOCTL_SERIAL_SET_BREAK_ON, LineOp::BreakOn),
        (IOCTL_SERIAL_SET_BREAK_OFF, LineOp::BreakOff),
    ] {
        assert_eq!(d(code, &[]), Ok(SerialControl::Line(op)), "{code:#x}");
    }
}

#[test]
fn ioctl_codes_outside_the_table_never_reach_the_driver() {
    let s = PortKind::Serial;
    let p = PortKind::Parallel;
    // Not in the 2.2.2.6 table (a disk IOCTL, a smart card one).
    assert_eq!(
        decode_ioctl(s, 0x0007_405C, &[], 64),
        Err(STATUS_NOT_SUPPORTED)
    );
    assert_eq!(
        decode_ioctl(s, 0x0009_0014, &[], 64),
        Err(STATUS_NOT_SUPPORTED)
    );
    // XOFF_COUNTER stays pending in drivers: not supported here.
    assert_eq!(
        decode_ioctl(s, IOCTL_SERIAL_XOFF_COUNTER, &[0; 9], 0),
        Err(STATUS_NOT_SUPPORTED)
    );
    // Table IOCTLs without a typed form go through raw, cut at nothing.
    assert_eq!(
        decode_ioctl(s, IOCTL_SERIAL_GET_STATS, &[], 24),
        Ok(SerialControl::Raw {
            code: IOCTL_SERIAL_GET_STATS,
            input: vec![],
            output_len: 24
        })
    );
    // Parallel ports: only the parallel IOCTLs.
    assert_eq!(
        decode_ioctl(p, IOCTL_PAR_QUERY_DEVICE_ID, &[1], 256),
        Ok(SerialControl::Raw {
            code: IOCTL_PAR_QUERY_DEVICE_ID,
            input: vec![1],
            output_len: 256
        })
    );
    assert_eq!(
        decode_ioctl(p, IOCTL_SERIAL_GET_BAUD_RATE, &[], 4),
        Err(STATUS_NOT_SUPPORTED)
    );
    assert_eq!(
        decode_ioctl(s, IOCTL_PAR_IS_PORT_FREE, &[], 4),
        Err(STATUS_NOT_SUPPORTED)
    );
}

#[test]
fn ioctl_output_too_small_is_refused() {
    let s = PortKind::Serial;
    for (code, need) in [
        (IOCTL_SERIAL_GET_BAUD_RATE, 4),
        (IOCTL_SERIAL_GET_LINE_CONTROL, 3),
        (IOCTL_SERIAL_GET_TIMEOUTS, 20),
        (IOCTL_SERIAL_GET_CHARS, 6),
        (IOCTL_SERIAL_GET_HANDFLOW, 16),
        (IOCTL_SERIAL_GET_WAIT_MASK, 4),
        (IOCTL_SERIAL_GET_MODEMSTATUS, 4),
        (IOCTL_SERIAL_GET_DTRRTS, 4),
        (IOCTL_SERIAL_GET_COMMSTATUS, 20),
        (IOCTL_SERIAL_GET_PROPERTIES, 64),
    ] {
        assert_eq!(
            decode_ioctl(s, code, &[], need - 1),
            Err(STATUS_BUFFER_TOO_SMALL),
            "{code:#x}"
        );
        assert!(decode_ioctl(s, code, &[], need).is_ok(), "{code:#x}");
    }
}

#[test]
fn output_structures_have_the_ntddser_layout() {
    let status = CommStatus {
        errors: SERIAL_ERROR_PARITY,
        hold_reasons: SERIAL_TX_WAITING_FOR_CTS,
        in_queue: 3,
        out_queue: 0x0102,
        eof_received: true,
        wait_for_immediate: false,
    };
    assert_eq!(
        status.encode(),
        hex("10 00 00 00 01 00 00 00 03 00 00 00 02 01 00 00 01 00 00 00")
    );
    let prop = CommProp {
        packet_length: 64,
        packet_version: 2,
        service_mask: 1,
        max_tx_queue: 2,
        max_rx_queue: 3,
        max_baud: 0x1000_0000,
        prov_sub_type: 1,
        prov_capabilities: 0xff,
        settable_params: 0x7f,
        settable_baud: 0x1000_0000,
        settable_data: 0x000f,
        settable_stop_parity: 0x1f07,
        current_tx_queue: 4,
        current_rx_queue: 5,
        prov_spec1: 6,
        prov_spec2: 7,
    };
    let b = prop.encode();
    assert_eq!(b.len(), SERIAL_COMMPROP_LEN);
    assert_eq!(&b[..4], &hex("40 00 02 00"));
    assert_eq!(&b[8..12], &[0; 4], "Reserved1");
    assert_eq!(&b[20..24], &hex("00 00 00 10"), "MaxBaud at 20");
    assert_eq!(
        &b[40..44],
        &hex("0f 00 07 1f"),
        "SettableData/StopParity at 40"
    );
    assert_eq!(
        &b[44..60],
        &hex("04 00 00 00 05 00 00 00 06 00 00 00 07 00 00 00")
    );
    assert_eq!(&b[60..], &[0; 4], "ProvChar and padding");
    let h = Handflow {
        control_handshake: 1,
        flow_replace: 0x40,
        xon_limit: 10,
        xoff_limit: 20,
    };
    assert_eq!(Handflow::decode(&h.encode()), Ok(h));
    let t = Timeouts {
        read_interval: 1,
        read_total_multiplier: 2,
        read_total_constant: 3,
        write_total_multiplier: 4,
        write_total_constant: 5,
    };
    assert_eq!(Timeouts::decode(&t.encode()), Ok(t));
}

#[test]
fn settings_round_trip_through_the_device() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    for (set, get, value) in [
        (
            IOCTL_SERIAL_SET_BAUD_RATE,
            IOCTL_SERIAL_GET_BAUD_RATE,
            hex("00 c2 01 00"),
        ),
        (
            IOCTL_SERIAL_SET_LINE_CONTROL,
            IOCTL_SERIAL_GET_LINE_CONTROL,
            hex("02 01 08"),
        ),
        (
            IOCTL_SERIAL_SET_TIMEOUTS,
            IOCTL_SERIAL_GET_TIMEOUTS,
            hex("32 00 00 00 01 00 00 00 64 00 00 00 02 00 00 00 c8 00 00 00"),
        ),
        (
            IOCTL_SERIAL_SET_CHARS,
            IOCTL_SERIAL_GET_CHARS,
            hex("1a 3f 00 0d 11 13"),
        ),
        (
            IOCTL_SERIAL_SET_HANDFLOW,
            IOCTL_SERIAL_GET_HANDFLOW,
            hex("21 00 00 00 83 00 00 00 00 01 00 00 00 04 00 00"),
        ),
        (
            IOCTL_SERIAL_SET_WAIT_MASK,
            IOCTL_SERIAL_GET_WAIT_MASK,
            hex("05 00 00 00"),
        ),
    ] {
        let c = ioctl(&mut d, f, set, &value, 0);
        assert_eq!(
            (c.status, output(&c)),
            (STATUS_SUCCESS, &[][..]),
            "{set:#x}"
        );
        let c = ioctl(&mut d, f, get, &[], 64);
        assert_eq!(
            (c.status, output(&c)),
            (STATUS_SUCCESS, &value[..]),
            "{get:#x}"
        );
    }
    // Status and properties come back at their full size.
    let c = ioctl(&mut d, f, IOCTL_SERIAL_GET_COMMSTATUS, &[], 20);
    assert_eq!(output(&c).len(), SERIAL_STATUS_LEN);
    let c = ioctl(&mut d, f, IOCTL_SERIAL_GET_PROPERTIES, &[], 64);
    assert_eq!(output(&c).len(), SERIAL_COMMPROP_LEN);
    // CONFIG_SIZE is answered here: no configuration data.
    let c = ioctl(&mut d, f, IOCTL_SERIAL_CONFIG_SIZE, &[], 4);
    assert_eq!(output(&c), &[0; 4]);
    // A raw IOCTL's output is cut to OutputBufferLength.
    let c = ioctl(&mut d, f, IOCTL_SERIAL_GET_STATS, &[], 24);
    assert_eq!(output(&c), &[0xAB; 24][..]);
    // Refused ones: NTSTATUS and an empty output.
    let c = ioctl(&mut d, f, IOCTL_SERIAL_GET_PROPERTIES, &[], 8);
    assert_eq!((c.status, c.data), (STATUS_BUFFER_TOO_SMALL, vec![0; 4]));
    let c = ioctl(&mut d, f, 0x0007_405C, &[], 8);
    assert_eq!(c.status, STATUS_NOT_SUPPORTED);
    let ran = b.port.lock().controls.len();
    assert_eq!(ran, 15, "refused requests never reach the port");
}

// ---- pending requests and cancel ----

#[test]
fn pending_read_does_not_block_and_completes_when_data_arrives() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    let started = Instant::now();
    assert!(d.io(&req(f, 10, IRP_MJ_READ, &read_req(4))).is_none());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "io returned at once"
    );
    quiet(&mut d);
    // Other requests still run while the read waits.
    let c = ioctl(&mut d, f, IOCTL_SERIAL_GET_BAUD_RATE, &[], 4);
    assert_eq!(output(&c), &9600u32.to_le_bytes());
    let c = d.io(&req(f, 11, IRP_MJ_WRITE, &write_req(b"AT\r")));
    let c = c.unwrap_or_else(|| wait_for(&mut d, 1).remove(0));
    assert_eq!((c.completion_id, c.data), (11, hex("03 00 00 00 00")));
    // Ten bytes arrive; the read asked for four (never more than requested).
    b.port.change(|s| s.rx.extend(*b"OK\r\nmore..."));
    let c = wait_for(&mut d, 1);
    assert_eq!(c[0].completion_id, 10);
    assert_eq!(c[0].data, hex("04 00 00 00 4f 4b 0d 0a"));
    assert_eq!(d.pending(), 0);
}

#[test]
fn purge_rxabort_cancels_pending_reads_and_reused_completion_ids_stay_apart() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    assert!(d.io(&req(f, 7, IRP_MJ_READ, &read_req(8))).is_none());
    quiet(&mut d);
    let purge = control_req(IOCTL_SERIAL_PURGE, &hex("0a 00 00 00"), 0);
    assert!(d.io(&req(f, 8, IRP_MJ_DEVICE_CONTROL, &purge)).is_none());
    let c = wait_for(&mut d, 2);
    assert_eq!((c[0].completion_id, c[0].status), (7, STATUS_CANCELLED));
    assert_eq!(c[0].data, vec![0; 4]);
    assert_eq!((c[1].completion_id, c[1].status), (8, STATUS_SUCCESS));
    assert_eq!(c.len(), 2, "{c:?}");
    // The old read's worker has ended by now; its late result was dropped.
    quiet(&mut d);
    // The server reuses completion id 7: only the new read answers it, the
    // old read's late result is dropped.
    assert!(d.io(&req(f, 7, IRP_MJ_READ, &read_req(8))).is_none());
    b.port.change(|s| s.rx.extend(*b"xy"));
    let c = wait_for(&mut d, 1);
    assert_eq!(
        c,
        vec![IoCompletion {
            completion_id: 7,
            status: STATUS_SUCCESS,
            data: hex("02 00 00 00 78 79"),
        }]
    );
    quiet(&mut d);
}

#[test]
fn purge_txabort_cancels_a_held_write() {
    let b = MockBackend::new();
    b.port.change(|s| s.hold_writes = true);
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    assert!(
        d.io(&req(f, 1, IRP_MJ_WRITE, &write_req(b"held")))
            .is_none()
    );
    quiet(&mut d);
    let purge = control_req(IOCTL_SERIAL_PURGE, &hex("01 00 00 00"), 0);
    assert!(d.io(&req(f, 2, IRP_MJ_DEVICE_CONTROL, &purge)).is_none());
    let c = wait_for(&mut d, 2);
    assert_eq!(
        (c[0].completion_id, c[0].status, &c[0].data[..]),
        (1, STATUS_CANCELLED, &[0u8; 5][..])
    );
    assert_eq!((c[1].completion_id, c[1].status), (2, STATUS_SUCCESS));
    quiet(&mut d);
    assert!(b.port.lock().written.is_empty());
}

#[test]
fn wait_on_mask_pends_completes_on_events_and_ends_on_a_new_mask() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    let set = |m: u32| control_req(IOCTL_SERIAL_SET_WAIT_MASK, &m.to_le_bytes(), 0);
    let wait = control_req(IOCTL_SERIAL_WAIT_ON_MASK, &[], 4);
    ioctl(
        &mut d,
        f,
        IOCTL_SERIAL_SET_WAIT_MASK,
        &(SERIAL_EV_RXCHAR | SERIAL_EV_CTS).to_le_bytes(),
        0,
    );
    assert!(d.io(&req(f, 20, IRP_MJ_DEVICE_CONTROL, &wait)).is_none());
    quiet(&mut d);
    // A second wait while one pends is refused (serial driver rule).
    let c = d.io(&req(f, 21, IRP_MJ_DEVICE_CONTROL, &wait)).unwrap();
    assert_eq!((c.status, c.data), (STATUS_INVALID_PARAMETER, vec![0; 4]));
    // An event outside the mask does nothing; one inside completes it.
    b.port.change(|s| s.events = SERIAL_EV_RING);
    quiet(&mut d);
    b.port.change(|s| s.events |= SERIAL_EV_CTS);
    let c = wait_for(&mut d, 1);
    assert_eq!(
        (c[0].completion_id, &c[0].data[..]),
        (20, &hex("04 00 00 00 08 00 00 00")[..])
    );
    // Wait again, then change the mask: the wait ends with mask 0 first.
    assert!(d.io(&req(f, 22, IRP_MJ_DEVICE_CONTROL, &wait)).is_none());
    quiet(&mut d);
    assert!(
        d.io(&req(f, 23, IRP_MJ_DEVICE_CONTROL, &set(SERIAL_EV_RXCHAR)))
            .is_none()
    );
    let c = wait_for(&mut d, 2);
    assert_eq!(
        (c[0].completion_id, c[0].status, &c[0].data[..]),
        (22, STATUS_SUCCESS, &hex("04 00 00 00 00 00 00 00")[..])
    );
    assert_eq!((c[1].completion_id, c[1].status), (23, STATUS_SUCCESS));
    // The waiting worker was released: a new wait works.
    assert!(d.io(&req(f, 24, IRP_MJ_DEVICE_CONTROL, &wait)).is_none());
    b.port.change(|s| s.events = SERIAL_EV_RXCHAR);
    let c = wait_for(&mut d, 1);
    assert_eq!(
        (c[0].completion_id, &c[0].data[4..]),
        (24, &[1, 0, 0, 0][..])
    );
    quiet(&mut d);
}

#[test]
fn close_cancels_pending_requests_before_its_answer() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    ioctl(
        &mut d,
        f,
        IOCTL_SERIAL_SET_WAIT_MASK,
        &SERIAL_EV_RXCHAR.to_le_bytes(),
        0,
    );
    let wait = control_req(IOCTL_SERIAL_WAIT_ON_MASK, &[], 4);
    assert!(d.io(&req(f, 30, IRP_MJ_READ, &read_req(16))).is_none());
    assert!(d.io(&req(f, 31, IRP_MJ_DEVICE_CONTROL, &wait)).is_none());
    quiet(&mut d);
    assert!(d.io(&req(f, 32, IRP_MJ_CLOSE, &[0; 32])).is_none());
    let c = wait_for(&mut d, 3);
    let got: Vec<(u32, u32)> = c.iter().map(|c| (c.completion_id, c.status)).collect();
    assert_eq!(
        got,
        vec![
            (30, STATUS_CANCELLED),
            (31, STATUS_CANCELLED),
            (32, STATUS_SUCCESS)
        ]
    );
    assert_eq!(c[2].data, vec![0; 4], "DR_CLOSE_RSP padding");
    assert_eq!(b.port.lock().closes, 1);
    assert_eq!(d.open_files(), 0);
    quiet(&mut d);
    // The instance is gone.
    let c = d.io(&req(f, 33, IRP_MJ_READ, &read_req(1))).unwrap();
    assert_eq!(c.status, STATUS_INVALID_HANDLE);
}

#[test]
fn closed_device_forgets_pending_requests_and_releases_the_port() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    assert!(d.io(&req(f, 40, IRP_MJ_READ, &read_req(16))).is_none());
    crate::rdpdr::Device::closed(&mut d);
    let start = Instant::now();
    while b.port.lock().closes == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    quiet(&mut d);
    assert_eq!((d.open_files(), d.pending()), (0, 0));
}

#[test]
fn pending_requests_are_bounded() {
    let b = MockBackend::new();
    let mut d = device("COM1", &b);
    let f = open(&mut d);
    for i in 0..device::MAX_PENDING as u32 {
        assert!(d.io(&req(f, i, IRP_MJ_READ, &read_req(1))).is_none());
    }
    let c = d.io(&req(f, 9999, IRP_MJ_READ, &read_req(1))).unwrap();
    assert_eq!(c.status, STATUS_INSUFFICIENT_RESOURCES);
    crate::rdpdr::Device::closed(&mut d);
}
