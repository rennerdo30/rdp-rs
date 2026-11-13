//! Printer tests: MS-RDPEPC 4.1 example bytes and print jobs against a mock
//! backend (nothing is printed for real).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::Put;
use crate::rdpdr::fscc::STATUS_UNSUCCESSFUL;
use crate::rdpdr::{IRP_MJ_QUERY_INFORMATION, IRP_MJ_READ, Rdpdr, rdpdr};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Start(u64, String, PrintFormat),
    Finish(u64),
    Cancel(u64),
}

#[derive(Default)]
struct Mock {
    printers: Vec<PrinterInfo>,
    next: u64,
    events: Vec<Ev>,
    /// Bytes written per job handle.
    data: HashMap<u64, Vec<u8>>,
    fail_start: bool,
    /// Fail every write once this many writes succeeded.
    fail_write_after: Option<usize>,
    writes: usize,
}

impl PrintBackend for Mock {
    fn printers(&mut self) -> Vec<PrinterInfo> {
        self.printers.clone()
    }
    fn start(
        &mut self,
        printer: &str,
        job_name: &str,
        format: PrintFormat,
    ) -> std::result::Result<u64, String> {
        assert_eq!(job_name, JOB_NAME);
        if self.fail_start {
            return Err("offline".into());
        }
        self.next += 1;
        self.events
            .push(Ev::Start(self.next, printer.to_string(), format));
        self.data.insert(self.next, Vec::new());
        Ok(self.next)
    }
    fn write(&mut self, job: u64, data: &[u8]) -> std::result::Result<(), String> {
        if self.fail_write_after.is_some_and(|n| self.writes >= n) {
            return Err("paper jam".into());
        }
        self.writes += 1;
        self.data
            .get_mut(&job)
            .ok_or("no job")?
            .extend_from_slice(data);
        Ok(())
    }
    fn finish(&mut self, job: u64) -> std::result::Result<(), String> {
        self.events.push(Ev::Finish(job));
        Ok(())
    }
    fn cancel(&mut self, job: u64) {
        self.events.push(Ev::Cancel(job));
    }
}

fn mock() -> Arc<Mutex<Mock>> {
    Arc::new(Mutex::new(Mock::default()))
}

fn info(name: &str, driver: &str, is_default: bool) -> PrinterInfo {
    PrinterInfo {
        name: name.into(),
        driver: driver.into(),
        is_default,
    }
}

fn printer(name: &str, b: &Arc<Mutex<Mock>>) -> Printer {
    Printer::new(info(name, "Drv", false), 1, b.clone())
}

fn irp(p: &mut Printer, major: u32, file: u32, data: &[u8]) -> IoCompletion {
    let req = IoRequest {
        device_id: 1,
        file_id: file,
        completion_id: 9,
        major,
        minor: 0,
        data,
    };
    p.io(&req).expect("printers answer at once")
}

/// DR_PRN_CREATE_REQ body as in MS-RDPEPC 4.1.7.
const CREATE_BODY: &str = "9f 01 12 00 00 00 00 00 00 00 00 00 00 00 00 00
    03 00 00 00 01 00 00 00 40 00 00 00 00 00 00 00";

fn create(p: &mut Printer) -> u32 {
    let c = irp(p, IRP_MJ_CREATE, 0, &hex(CREATE_BODY));
    assert_eq!(c.status, STATUS_SUCCESS);
    assert_eq!(c.data.len(), 4, "DR_PRN_CREATE_RSP carries the FileId only");
    u32::from_le_bytes(c.data[..4].try_into().unwrap())
}

fn write_body(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u32(data.len() as u32);
    v.put_bytes(&[0xEE; 8]); // Offset: any value, ignored (2.2.2.9)
    v.put_bytes(&[0; 20]);
    v.put_bytes(data);
    v
}

fn write(p: &mut Printer, file: u32, data: &[u8]) -> IoCompletion {
    irp(p, IRP_MJ_WRITE, file, &write_body(data))
}

fn close(p: &mut Printer, file: u32) -> IoCompletion {
    irp(p, IRP_MJ_CLOSE, file, &[0; 32])
}

fn ok_write(len: usize) -> Vec<u8> {
    let mut v = (len as u32).to_le_bytes().to_vec();
    v.push(0);
    v
}

// MS-RDPEPC 4.1.1: the two printers' DeviceData.
const APOLLO_DATA: &str = "10 00 00 00 00 00 00 00 00 00 00 00 1c 00 00 00
    1c 00 00 00 00 00 00 00 41 00 70 00 6f 00 6c 00 6c 00 6f 00
    20 00 50 00 2d 00 31 00 32 00 30 00 30 00 00 00
    41 00 70 00 6f 00 6c 00 6c 00 6f 00 20 00 50 00
    2d 00 31 00 32 00 30 00 30 00 00 00";
const CANON_DATA: &str = "12 00 00 00 00 00 00 00 00 00 00 00 2e 00 00 00
    2e 00 00 00 00 00 00 00 43 00 61 00 6e 00 6f 00
    6e 00 20 00 42 00 75 00 62 00 62 00 6c 00 65 00
    2d 00 4a 00 65 00 74 00 20 00 42 00 4a 00 2d 00
    33 00 30 00 00 00 43 00 61 00 6e 00 6f 00 6e 00
    20 00 42 00 75 00 62 00 62 00 6c 00 65 00 2d 00
    4a 00 65 00 74 00 20 00 42 00 4a 00 2d 00 33 00
    30 00 00 00";

#[test]
fn announce_data_matches_spec_example() {
    let b = mock();
    let apollo = Printer::new(info("Apollo P-1200", "Apollo P-1200", false), 4, b.clone());
    assert_eq!(apollo.device_type(), RDPDR_DTYP_PRINT);
    assert_eq!(apollo.preferred_dos_name(), "PRN4");
    assert_eq!(apollo.device_data(), hex(APOLLO_DATA));
    let canon = Printer::new(
        info("Canon Bubble-Jet BJ-30", "Canon Bubble-Jet BJ-30", true),
        3,
        b,
    );
    assert_eq!(canon.preferred_dos_name(), "PRN3");
    assert_eq!(canon.device_data(), hex(CANON_DATA));
    assert_eq!(
        announce_data(0, "P", "", ""),
        hex("00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 00 00 00")
    );
}

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

/// Server Announce, capabilities, Client ID Confirm, User Logged On.
fn logon(ch: &mut Rdpdr) -> Vec<Vec<u8>> {
    feed(ch, &hex("72 44 6e 49 01 00 0c 00 02 00 00 00"));
    feed(
        ch,
        &hex("72 44 50 53 05 00 00 00
            01 00 2c 00 02 00 00 00 02 00 00 00 00 00 06 00 01 00 0c 00 ff ff 00 00
            00 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            02 00 08 00 01 00 00 00 03 00 08 00 01 00 00 00
            04 00 08 00 02 00 00 00 05 00 08 00 01 00 00 00"),
    );
    feed(ch, &hex("72 44 43 43 01 00 0c 00 02 00 00 00"));
    feed(ch, &hex("72 44 4c 55"))
}

/// The MS-RDPEPC 4.1 sequence through the rdpdr core: announce (4.1.1),
/// create (4.1.7/4.1.10), write (4.1.9/4.1.12) and close (4.1.8/4.1.11),
/// with the example's device id 2 and FileId 0.
#[test]
fn spec_job_sequence_through_core() {
    let b = mock();
    let (mut ch, h) = rdpdr("x");
    let first = h.add_device(Box::new(printer("Unused", &b)));
    h.remove(first);
    let id = h.add_device(Box::new(Printer::new(
        info("Apollo P-1200", "Apollo P-1200", false),
        4,
        b.clone(),
    )));
    assert_eq!(id, 2);
    tick(&mut ch);
    let out = logon(&mut ch);
    let mut announce = hex("72 44 41 44 01 00 00 00 04 00 00 00 02 00 00 00
        50 52 4e 34 00 00 00 00 50 00 00 00");
    announce.extend(hex(APOLLO_DATA));
    assert_eq!(out, vec![announce]);

    let create = hex("72 44 52 49 02 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 9f 01 12 00 00 00 00 00
        00 00 00 00 00 00 00 00 03 00 00 00 01 00 00 00
        40 00 00 00 00 00 00 00");
    assert_eq!(
        feed(&mut ch, &create),
        vec![hex(
            "72 44 43 49 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        )]
    );

    let job: Vec<u8> = (0..0x1_0000u32).map(|i| (i * 7) as u8).collect();
    let mut wr = hex("72 44 52 49 02 00 00 00 00 00 00 00 00 00 00 00
        04 00 00 00 00 00 00 00");
    wr.extend(write_body(&job));
    assert_eq!(
        feed(&mut ch, &wr),
        vec![hex(
            "72 44 43 49 02 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00"
        )]
    );

    let mut cl = hex("72 44 52 49 02 00 00 00 00 00 00 00 00 00 00 00
        02 00 00 00 00 00 00 00");
    cl.extend([0; 32]);
    assert_eq!(
        feed(&mut ch, &cl),
        vec![hex(
            "72 44 43 49 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        )]
    );
    let m = b.lock().unwrap();
    assert_eq!(
        m.events,
        vec![
            Ev::Start(1, "Apollo P-1200".into(), PrintFormat::Raw),
            Ev::Finish(1)
        ]
    );
    assert_eq!(m.data[&1], job);
}

#[test]
fn several_writes_make_one_job_on_the_right_printer() {
    let b = mock();
    let mut p = printer("Office", &b);
    let f = create(&mut p);
    // An XPS package (ZIP) split so the signature spans two writes.
    let parts: [&[u8]; 4] = [b"PK", b"\x03\x04rest", b"", b"of the document"];
    for part in parts {
        let c = write(&mut p, f, part);
        assert_eq!((c.status, c.data), (STATUS_SUCCESS, ok_write(part.len())));
    }
    assert_eq!(p.open_jobs(), 1);
    let c = close(&mut p, f);
    assert_eq!((c.status, c.data), (STATUS_SUCCESS, vec![0; 4]));
    assert_eq!(p.open_jobs(), 0);
    let m = b.lock().unwrap();
    assert_eq!(
        m.events,
        vec![
            Ev::Start(1, "Office".into(), PrintFormat::Xps),
            Ev::Finish(1)
        ]
    );
    assert_eq!(m.data[&1], parts.concat());
}

#[test]
fn short_raw_job_and_empty_job() {
    let b = mock();
    let mut p = printer("P", &b);
    let f = create(&mut p);
    assert_eq!(write(&mut p, f, b"\x1bE").status, STATUS_SUCCESS);
    assert!(b.lock().unwrap().events.is_empty(), "format not known yet");
    assert_eq!(close(&mut p, f).status, STATUS_SUCCESS);
    let empty = create(&mut p);
    assert_eq!(close(&mut p, empty).status, STATUS_SUCCESS);
    let m = b.lock().unwrap();
    assert_eq!(
        m.events,
        vec![Ev::Start(1, "P".into(), PrintFormat::Raw), Ev::Finish(1)],
        "the empty job prints nothing"
    );
    assert_eq!(m.data[&1], b"\x1bE");
}

#[test]
fn two_interleaved_jobs() {
    let b = mock();
    let mut p = printer("P", &b);
    let a = create(&mut p);
    let c = create(&mut p);
    assert_ne!(a, c);
    write(&mut p, a, b"AAAA-1 ");
    write(&mut p, c, b"PK\x03\x04-1 ");
    write(&mut p, a, b"AAAA-2");
    write(&mut p, c, b"CCCC-2");
    assert_eq!(close(&mut p, c).status, STATUS_SUCCESS);
    write(&mut p, a, b" end");
    assert_eq!(close(&mut p, a).status, STATUS_SUCCESS);
    let m = b.lock().unwrap();
    assert_eq!(
        m.events,
        vec![
            Ev::Start(1, "P".into(), PrintFormat::Raw),
            Ev::Start(2, "P".into(), PrintFormat::Xps),
            Ev::Finish(2),
            Ev::Finish(1),
        ]
    );
    assert_eq!(m.data[&1], b"AAAA-1 AAAA-2 end");
    assert_eq!(m.data[&2], b"PK\x03\x04-1 CCCC-2");
}

#[test]
fn removing_the_device_cancels_open_jobs() {
    let b = mock();
    let (mut ch, h) = rdpdr("x");
    let id = h.add_device(Box::new(printer("P", &b)));
    tick(&mut ch);
    logon(&mut ch);
    let io = |file: u32, major: u32, body: &[u8]| {
        let mut v = hex("72 44 52 49");
        for x in [id, file, 5, major, 0] {
            v.put_u32(x);
        }
        v.put_bytes(body);
        v
    };
    for _ in 0..3 {
        feed(&mut ch, &io(0, IRP_MJ_CREATE, &hex(CREATE_BODY)));
    }
    // Jobs 0 and 1 started (data written), job 2 only created.
    feed(&mut ch, &io(0, IRP_MJ_WRITE, &write_body(b"data 0")));
    feed(&mut ch, &io(1, IRP_MJ_WRITE, &write_body(b"data 1")));
    h.remove(id);
    tick(&mut ch);
    let mut ev = b.lock().unwrap().events.clone();
    ev.sort_by_key(|e| format!("{e:?}"));
    assert_eq!(
        ev,
        vec![
            Ev::Cancel(1),
            Ev::Cancel(2),
            Ev::Start(1, "P".into(), PrintFormat::Raw),
            Ev::Start(2, "P".into(), PrintFormat::Raw),
        ]
    );
}

#[test]
fn dropping_the_device_cancels_open_jobs() {
    let b = mock();
    let mut p = printer("P", &b);
    let f = create(&mut p);
    write(&mut p, f, b"data");
    drop(p);
    assert_eq!(b.lock().unwrap().events.last(), Some(&Ev::Cancel(1)));
}

#[test]
fn unsupported_majors_get_not_supported() {
    let b = mock();
    let mut p = printer("P", &b);
    let f = create(&mut p);
    for major in [
        IRP_MJ_READ,
        IRP_MJ_QUERY_INFORMATION,
        IRP_MJ_DEVICE_CONTROL,
        0x1F,
    ] {
        let c = irp(&mut p, major, f, &[0; 32]);
        assert_eq!(c.status, STATUS_NOT_SUPPORTED, "major {major:#x}");
        assert_eq!(c.completion_id, 9);
    }
    assert_eq!(p.open_jobs(), 1, "the job stays open");
}

#[test]
fn unknown_handles_and_truncated_requests_are_answered() {
    let b = mock();
    let mut p = printer("P", &b);
    assert_eq!(write(&mut p, 42, b"x").status, STATUS_INVALID_HANDLE);
    assert_eq!(close(&mut p, 42).status, STATUS_INVALID_HANDLE);
    let f = create(&mut p);
    let mut short = write_body(b"abcdef");
    short.truncate(short.len() - 1);
    for (major, body) in [
        (IRP_MJ_CREATE, &hex(CREATE_BODY)[..20]),
        (IRP_MJ_CREATE, &[0xFF; 32][..]), // PathLength beyond the data
        (IRP_MJ_WRITE, &short[..]),
        (IRP_MJ_WRITE, &[][..]),
    ] {
        assert_eq!(irp(&mut p, major, f, body).status, STATUS_INVALID_PARAMETER);
    }
    assert_eq!(p.open_jobs(), 1);
    assert!(b.lock().unwrap().events.is_empty());
}

#[test]
fn backend_failures_fail_the_job_and_cancel_it() {
    let b = mock();
    b.lock().unwrap().fail_start = true;
    let mut p = printer("P", &b);
    let f = create(&mut p);
    assert_eq!(write(&mut p, f, b"data").status, STATUS_UNSUCCESSFUL);
    assert_eq!(write(&mut p, f, b"more").status, STATUS_UNSUCCESSFUL);
    assert_eq!(close(&mut p, f).status, STATUS_SUCCESS);
    assert_eq!(p.open_jobs(), 0);

    let mut m = b.lock().unwrap();
    m.fail_start = false;
    m.fail_write_after = Some(1);
    drop(m);
    let f = create(&mut p);
    assert_eq!(write(&mut p, f, b"page 1").status, STATUS_SUCCESS);
    assert_eq!(write(&mut p, f, b"page 2").status, STATUS_UNSUCCESSFUL);
    assert_eq!(write(&mut p, f, b"page 3").status, STATUS_UNSUCCESSFUL);
    close(&mut p, f);
    assert_eq!(
        b.lock().unwrap().events,
        vec![Ev::Start(1, "P".into(), PrintFormat::Raw), Ev::Cancel(1)],
        "a failed job is cancelled, never finished"
    );

    // The very first write fails: the just-started job is cancelled too.
    let mut m = b.lock().unwrap();
    m.events.clear();
    m.fail_write_after = Some(0);
    drop(m);
    let f = create(&mut p);
    assert_eq!(write(&mut p, f, b"page 1").status, STATUS_UNSUCCESSFUL);
    assert_eq!(close(&mut p, f).status, STATUS_SUCCESS);
    assert_eq!(
        b.lock().unwrap().events,
        vec![Ev::Start(2, "P".into(), PrintFormat::Raw), Ev::Cancel(2)]
    );
}

#[test]
fn file_ids_of_open_jobs_are_never_reused() {
    let b = mock();
    let mut p = printer("P", &b);
    let ids: Vec<u32> = (0..5).map(|_| create(&mut p)).collect();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 5, "{ids:?}");
    // After the counter wraps around onto open jobs, they are skipped.
    p.next_file = ids[1];
    let next = create(&mut p);
    assert!(!ids.contains(&next), "{next} reused");
    assert_eq!(p.open_jobs(), 6);
}

#[test]
fn too_many_open_jobs_are_refused() {
    let b = mock();
    let mut p = printer("P", &b);
    for _ in 0..64 {
        create(&mut p);
    }
    let c = irp(&mut p, IRP_MJ_CREATE, 0, &hex(CREATE_BODY));
    assert_ne!(c.status, STATUS_SUCCESS);
    assert_eq!(p.open_jobs(), 64);
}

#[test]
fn share_printers_adds_one_device_per_printer() {
    let b = mock();
    b.lock().unwrap().printers = vec![info("Laser", "PCL6", false), info("Ink", "IPP", true)];
    let (mut ch, h) = rdpdr("x");
    let backend: SharedBackend = b.clone();
    let ids = share_printers(&h, backend);
    assert_eq!(ids.len(), 2);
    assert_eq!(
        h.devices(),
        vec![(ids[0], "Laser".to_string()), (ids[1], "Ink".to_string())]
    );
    tick(&mut ch);
    let out = logon(&mut ch);
    assert_eq!(out.len(), 1);
    let pdu = &out[0];
    assert_eq!(&pdu[4..8], &[2, 0, 0, 0], "two devices");
    let dev = &pdu[8..];
    assert_eq!(&dev[0..4], &[4, 0, 0, 0], "RDPDR_DTYP_PRINT");
    assert_eq!(&dev[8..11], b"PRN", "PreferredDosName is PRN + digits");
    assert!(
        dev[11..16]
            .iter()
            .take_while(|&&c| c != 0)
            .all(u8::is_ascii_digit)
    );
    let first_len = u32::from_le_bytes(dev[16..20].try_into().unwrap()) as usize;
    let second = &dev[20 + first_len..];
    assert_eq!(&second[20..24], &[0x12, 0, 0, 0], "default + XPS");
    assert_eq!(&dev[20..24], &[0x10, 0, 0, 0], "XPS only");
    for id in ids {
        h.remove(id);
    }
    assert!(h.devices().is_empty());
}
