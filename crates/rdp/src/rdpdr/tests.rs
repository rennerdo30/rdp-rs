//! Tests: exact PDU bytes for the core sequence, live add/remove, and drive
//! IRPs on a temporary directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::fscc::*;
use super::*;
use crate::channel::{ChannelOut, StaticChannel};
use crate::cursor::{Put, utf16le, utf16le_z};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A unique directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "rdp-rs-rdpdr-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

// MS-RDPEFS 4.1 / 4.6 / 4.8: Server Announce (1.12, client id 2),
// Server Client ID Confirm, Server User Logged On.
const SERVER_ANNOUNCE: &str = "72 44 6e 49 01 00 0c 00 02 00 00 00";
const CLIENT_ID_CONFIRM: &str = "72 44 43 43 01 00 0c 00 02 00 00 00";
const USER_LOGGED_ON: &str = "72 44 4c 55";
const SERVER_CAPS: &str = "72 44 50 53 05 00 00 00
    01 00 2c 00 02 00 00 00 02 00 00 00 00 00 06 00 01 00 0c 00 ff ff 00 00
    00 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    02 00 08 00 01 00 00 00 03 00 08 00 01 00 00 00
    04 00 08 00 02 00 00 00 05 00 08 00 01 00 00 00";

fn handshake(ch: &mut Rdpdr) {
    feed(ch, &hex(SERVER_ANNOUNCE));
    feed(ch, &hex(SERVER_CAPS));
    feed(ch, &hex(CLIENT_ID_CONFIRM));
}

#[test]
fn announce_reply_and_client_name_exact_bytes() {
    let (mut ch, _h) = rdpdr("ab");
    let out = feed(&mut ch, &hex(SERVER_ANNOUNCE));
    assert_eq!(out.len(), 2);
    assert_eq!(out[0], hex("72 44 43 43 01 00 0c 00 02 00 00 00"));
    assert_eq!(
        out[1],
        hex("72 44 4e 43 01 00 00 00 00 00 00 00 06 00 00 00 61 00 62 00 00 00")
    );
    assert_eq!(ch.client_id(), 2);
}

#[test]
fn announce_reply_caps_minor_version_at_0x0d() {
    let (mut ch, _h) = rdpdr("x");
    let out = feed(&mut ch, &hex("72 44 6e 49 01 00 0f 00 07 00 00 00"));
    assert_eq!(out[0], hex("72 44 43 43 01 00 0d 00 07 00 00 00"));
}

#[test]
fn capability_exchange_exact_bytes() {
    let (mut ch, _h) = rdpdr("x");
    feed(&mut ch, &hex(SERVER_ANNOUNCE));
    let out = feed(&mut ch, &hex(SERVER_CAPS));
    assert_eq!(out.len(), 1);
    let expected = hex("72 44 50 43 05 00 00 00
         01 00 2c 00 02 00 00 00 00 00 00 00 00 00 00 00 01 00 0c 00 9d 3d 00 00
         00 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         02 00 08 00 01 00 00 00 03 00 08 00 01 00 00 00
         04 00 08 00 02 00 00 00 05 00 08 00 01 00 00 00");
    assert_eq!(out[0], expected);
}

fn drive_announce(id: u8, dos: &str, name: &str) -> Vec<u8> {
    let mut v = hex("72 44 41 44 01 00 00 00 08 00 00 00");
    v.put_u32(u32::from(id));
    let mut d = [0u8; 8];
    d[..dos.len()].copy_from_slice(dos.as_bytes());
    v.put_bytes(&d);
    let data = utf16le_z(name);
    v.put_u32(data.len() as u32);
    v.put_bytes(&data);
    v
}

#[test]
fn drive_added_before_logon_waits_then_is_announced() {
    let dir = TempDir::new();
    let (mut ch, h) = rdpdr("x");
    let id = h.add_drive("Share", dir.path().into(), false);
    assert_eq!(id, 1);
    assert!(tick(&mut ch).is_empty());
    handshake(&mut ch);
    assert!(tick(&mut ch).is_empty(), "no drive before user logon");
    let out = feed(&mut ch, &hex(USER_LOGGED_ON));
    assert_eq!(out, vec![drive_announce(1, "Share", "Share")]);
    // Exact bytes of the announce for the record.
    assert_eq!(
        out[0],
        hex(
            "72 44 41 44 01 00 00 00 08 00 00 00 01 00 00 00 53 68 61 72 65 00 00 00
             0c 00 00 00 53 00 68 00 61 00 72 00 65 00 00 00"
        )
    );
    assert!(tick(&mut ch).is_empty(), "announced once");
}

#[test]
fn live_add_and_remove_after_logon() {
    let dir = TempDir::new();
    let (mut ch, h) = rdpdr("x");
    handshake(&mut ch);
    feed(&mut ch, &hex(USER_LOGGED_ON));
    let a = h.add_drive("Documents", dir.path().into(), false);
    let b = h.add_drive("ro", dir.path().into(), true);
    assert_eq!(
        h.devices(),
        vec![(a, "Documents".to_string()), (b, "ro".to_string())]
    );
    let out = tick(&mut ch);
    assert_eq!(out.len(), 1, "both in one announce");
    assert_eq!(&out[0][4..8], &[2, 0, 0, 0]);
    assert_eq!(&out[0][16..24], b"Documen\0");
    h.remove(a);
    assert_eq!(h.devices(), vec![(b, "ro".to_string())]);
    assert_eq!(
        tick(&mut ch),
        vec![hex("72 44 4d 44 01 00 00 00 01 00 00 00")]
    );
    // I/O to the removed device is answered, not dropped.
    let req = io_request(a, 1, 9, IRP_MJ_READ, 0, &[0; 32]);
    assert_eq!(
        feed(&mut ch, &req),
        vec![hex("72 44 43 49 01 00 00 00 09 00 00 00 bb 00 00 c0")]
    );
    h.remove(a); // unknown now: no second PDU
    assert!(tick(&mut ch).is_empty());
}

#[test]
fn remove_before_logon_sends_nothing() {
    let dir = TempDir::new();
    let (mut ch, h) = rdpdr("x");
    let a = h.add_drive("A", dir.path().into(), false);
    tick(&mut ch);
    h.remove(a);
    assert!(tick(&mut ch).is_empty());
    handshake(&mut ch);
    assert!(feed(&mut ch, &hex(USER_LOGGED_ON)).is_empty());
}

#[test]
fn remove_closes_open_handles() {
    let dir = TempDir::new();
    std::fs::write(dir.path().join("tmp.txt"), b"x").unwrap();
    let (mut ch, h) = rdpdr("x");
    let id = h.add_drive("A", dir.path().into(), false);
    tick(&mut ch);
    handshake(&mut ch);
    feed(&mut ch, &hex(USER_LOGGED_ON));
    let create = create_data("\\tmp.txt", 0x0001_0080, 1, 0x1000);
    let out = feed(&mut ch, &io_request(id, 0, 1, IRP_MJ_CREATE, 0, &create));
    assert_eq!(&out[0][12..16], &[0, 0, 0, 0], "create succeeded");
    assert!(dir.path().join("tmp.txt").exists());
    h.remove(id);
    tick(&mut ch);
    assert!(
        !dir.path().join("tmp.txt").exists(),
        "removal closed the delete-on-close handle"
    );
}

struct Mock {
    early: bool,
    closed: Arc<AtomicBool>,
    pending: Option<u32>,
}

impl Device for Mock {
    fn device_type(&self) -> u32 {
        RDPDR_DTYP_SMARTCARD
    }
    fn preferred_dos_name(&self) -> String {
        "SCARD:toolong".into()
    }
    fn device_data(&self) -> Vec<u8> {
        Vec::new()
    }
    fn announce_before_logon(&self) -> bool {
        self.early
    }
    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        self.pending = Some(req.completion_id);
        None
    }
    fn tick(&mut self) -> Vec<IoCompletion> {
        match self.pending.take() {
            Some(id) => vec![IoCompletion {
                completion_id: id,
                status: 0,
                data: vec![0xAA],
            }],
            None => Vec::new(),
        }
    }
    fn closed(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[test]
fn early_device_announced_at_client_id_confirm_and_pending_completes_in_tick() {
    let closed = Arc::new(AtomicBool::new(false));
    let (mut ch, h) = rdpdr("x");
    let id = h.add_device(Box::new(Mock {
        early: true,
        closed: closed.clone(),
        pending: None,
    }));
    tick(&mut ch);
    feed(&mut ch, &hex(SERVER_ANNOUNCE));
    feed(&mut ch, &hex(SERVER_CAPS));
    let out = feed(&mut ch, &hex(CLIENT_ID_CONFIRM));
    assert_eq!(
        out,
        vec![hex(
            "72 44 41 44 01 00 00 00 20 00 00 00 01 00 00 00 53 43 41 52 44 5f 74 00 00 00 00 00"
        )]
    );
    let req = io_request(id, 0, 77, IRP_MJ_DEVICE_CONTROL, 0, &[0; 32]);
    assert!(feed(&mut ch, &req).is_empty(), "pending");
    assert_eq!(
        tick(&mut ch),
        vec![hex("72 44 43 49 01 00 00 00 4d 00 00 00 00 00 00 00 aa")]
    );
    // A new server announce restarts redirection: handles closed, re-announced.
    feed(&mut ch, &hex(SERVER_ANNOUNCE));
    assert!(closed.load(Ordering::SeqCst));
    assert_eq!(feed(&mut ch, &hex(CLIENT_ID_CONFIRM)).len(), 1);
}

#[test]
fn old_server_without_logon_pdu_gets_drives_at_confirm() {
    let dir = TempDir::new();
    let (mut ch, h) = rdpdr("x");
    h.add_drive("A", dir.path().into(), false);
    tick(&mut ch);
    feed(&mut ch, &hex("72 44 6e 49 01 00 05 00 02 00 00 00"));
    assert_eq!(
        feed(&mut ch, &hex("72 44 43 43 01 00 05 00 02 00 00 00")).len(),
        1
    );
}

#[test]
fn truncated_pdus_are_errors_not_panics() {
    let (mut ch, _h) = rdpdr("x");
    for msg in [
        &[][..],
        &[0x72],
        &[0x72, 0x44, 0x6e, 0x49, 1, 0],
        &[0x72, 0x44, 0x52, 0x49, 1, 0, 0, 0],
    ] {
        let mut out = ChannelOut::default();
        assert!(ch.process(msg, &mut out).is_err());
    }
}

// ---- drive IRPs ----

fn io_request(dev: u32, file: u32, cid: u32, major: u32, minor: u32, data: &[u8]) -> Vec<u8> {
    let mut v = hex("72 44 52 49");
    for x in [dev, file, cid, major, minor] {
        v.put_u32(x);
    }
    v.put_bytes(data);
    v
}

fn create_data(path: &str, access: u32, disposition: u32, options: u32) -> Vec<u8> {
    let p = utf16le_z(path);
    let mut v = Vec::new();
    v.put_u32(access);
    v.put_zeros(8);
    v.put_u32(0x80);
    v.put_u32(7);
    v.put_u32(disposition);
    v.put_u32(options);
    v.put_u32(p.len() as u32);
    v.put_bytes(&p);
    v
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;
const OPEN: u32 = 1;
const CREATE: u32 = 2;
const OPEN_IF: u32 = 3;
const OVERWRITE_IF: u32 = 5;
const DIR: u32 = 1;
const NON_DIR: u32 = 0x40;

fn irp(d: &mut Drive, major: u32, minor: u32, file: u32, data: &[u8]) -> IoCompletion {
    let req = IoRequest {
        device_id: 1,
        file_id: file,
        completion_id: 5,
        major,
        minor,
        data,
    };
    d.io(&req).expect("completed")
}

fn open(d: &mut Drive, path: &str, access: u32, disp: u32, opts: u32) -> Result<u32, u32> {
    let c = irp(
        d,
        IRP_MJ_CREATE,
        0,
        0,
        &create_data(path, access, disp, opts),
    );
    assert_eq!(c.data.len(), 5);
    if c.status == STATUS_SUCCESS {
        Ok(u32::from_le_bytes(c.data[..4].try_into().unwrap()))
    } else {
        Err(c.status)
    }
}

fn read(d: &mut Drive, f: u32, len: u32, off: u64) -> IoCompletion {
    let mut v = Vec::new();
    v.put_u32(len);
    v.put_bytes(&off.to_le_bytes());
    v.put_zeros(20);
    irp(d, IRP_MJ_READ, 0, f, &v)
}

fn write(d: &mut Drive, f: u32, off: u64, data: &[u8]) -> IoCompletion {
    let mut v = Vec::new();
    v.put_u32(data.len() as u32);
    v.put_bytes(&off.to_le_bytes());
    v.put_zeros(20);
    v.put_bytes(data);
    irp(d, IRP_MJ_WRITE, 0, f, &v)
}

fn close(d: &mut Drive, f: u32) -> IoCompletion {
    irp(d, IRP_MJ_CLOSE, 0, f, &[0; 32])
}

fn info_req(class: u32, buf: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.put_u32(class);
    v.put_u32(buf.len() as u32);
    v.put_zeros(24);
    v.put_bytes(buf);
    v
}

fn query(d: &mut Drive, f: u32, class: u32) -> IoCompletion {
    irp(d, IRP_MJ_QUERY_INFORMATION, 0, f, &info_req(class, &[]))
}

fn set(d: &mut Drive, f: u32, class: u32, buf: &[u8]) -> u32 {
    irp(d, IRP_MJ_SET_INFORMATION, 0, f, &info_req(class, buf)).status
}

fn rename_buf(to: &str, replace: bool) -> Vec<u8> {
    let n = utf16le(to);
    let mut v = vec![replace as u8, 0];
    v.put_u32(n.len() as u32);
    v.put_bytes(&n);
    v
}

fn query_dir(d: &mut Drive, f: u32, class: u32, initial: bool, path: &str) -> IoCompletion {
    let p = utf16le_z(path);
    let mut v = Vec::new();
    v.put_u32(class);
    v.put_u8(initial as u8);
    v.put_u32(p.len() as u32);
    v.put_zeros(23);
    v.put_bytes(&p);
    irp(d, IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY, f, &v)
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[test]
fn create_write_read_close() {
    let dir = TempDir::new();
    let mut d = Drive::new("t", dir.path().into(), false);
    let f = open(
        &mut d,
        "\\new.txt",
        GENERIC_READ | GENERIC_WRITE,
        CREATE,
        NON_DIR,
    )
    .unwrap();
    // Create response: FileId then Information FILE_SUPERSEDED (created).
    let c = irp(
        &mut d,
        IRP_MJ_CREATE,
        0,
        0,
        &create_data("\\new2.txt", GENERIC_WRITE, CREATE, 0),
    );
    assert_eq!(c.status, 0);
    assert_eq!(c.data[4], 0);
    let w = write(&mut d, f, 0, b"hello world");
    assert_eq!((w.status, w.data), (0, vec![11, 0, 0, 0, 0]));
    let r = read(&mut d, f, 5, 6);
    assert_eq!(r.status, 0);
    assert_eq!(r.data, [&[5, 0, 0, 0][..], b"world"].concat());
    // Past the end: success with no data.
    assert_eq!(read(&mut d, f, 5, 100).data, vec![0, 0, 0, 0]);
    assert_eq!(
        close(&mut d, f),
        IoCompletion {
            completion_id: 5,
            status: 0,
            data: vec![0; 4]
        }
    );
    assert_eq!(close(&mut d, f).status, STATUS_INVALID_HANDLE);
    assert_eq!(
        std::fs::read(dir.path().join("new.txt")).unwrap(),
        b"hello world"
    );
    assert_eq!(d.open_handles(), 1);
    // Existing: FILE_CREATE collides, FILE_OPEN_IF opens (Information FILE_OPENED).
    assert_eq!(
        open(&mut d, "\\new.txt", GENERIC_READ, CREATE, 0),
        Err(STATUS_OBJECT_NAME_COLLISION)
    );
    let c = irp(
        &mut d,
        IRP_MJ_CREATE,
        0,
        0,
        &create_data("\\new.txt", GENERIC_READ, OPEN_IF, 0),
    );
    assert_eq!((c.status, c.data[4]), (0, 1));
    // FILE_OVERWRITE_IF truncates (FILE_OVERWRITTEN).
    let c = irp(
        &mut d,
        IRP_MJ_CREATE,
        0,
        0,
        &create_data("\\new.txt", GENERIC_WRITE, OVERWRITE_IF, 0),
    );
    assert_eq!((c.status, c.data[4]), (0, 3));
    assert_eq!(
        std::fs::metadata(dir.path().join("new.txt")).unwrap().len(),
        0
    );
    assert_eq!(
        open(&mut d, "\\missing", GENERIC_READ, OPEN, 0),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        open(&mut d, "\\nodir\\x", GENERIC_READ, OPEN, 0),
        Err(STATUS_OBJECT_PATH_NOT_FOUND)
    );
}

#[test]
fn directories_and_create_options() {
    let dir = TempDir::new();
    std::fs::write(dir.path().join("f"), b"").unwrap();
    let mut d = Drive::new("t", dir.path().into(), false);
    let sub = open(&mut d, "\\sub", GENERIC_READ, CREATE, DIR).unwrap();
    assert!(dir.path().join("sub").is_dir());
    assert_eq!(
        open(&mut d, "\\sub", GENERIC_READ, OPEN, NON_DIR),
        Err(STATUS_FILE_IS_A_DIRECTORY)
    );
    assert_eq!(
        open(&mut d, "\\f", GENERIC_READ, OPEN, DIR),
        Err(STATUS_NOT_A_DIRECTORY)
    );
    assert!(open(&mut d, "", GENERIC_READ, OPEN, DIR).is_ok(), "root");
    let q = query(&mut d, sub, FILE_STANDARD_INFORMATION);
    assert_eq!(q.data[4 + 21], 1, "Directory flag");
}

#[test]
fn query_information_classes() {
    let dir = TempDir::new();
    std::fs::write(dir.path().join("a.bin"), vec![7u8; 5000]).unwrap();
    let mut d = Drive::new("t", dir.path().into(), false);
    let f = open(&mut d, "\\a.bin", GENERIC_READ, OPEN, 0).unwrap();
    let b = query(&mut d, f, FILE_BASIC_INFORMATION);
    assert_eq!((b.status, le32(&b.data, 0)), (0, 36));
    let written = le64(&b.data, 4 + 16);
    let now = filetime(std::time::SystemTime::now());
    assert!(
        written <= now && now - written < 10 * 60 * 10_000_000,
        "LastWriteTime"
    );
    assert_eq!(le32(&b.data, 4 + 32) & FILE_ATTRIBUTE_DIRECTORY, 0);
    let s = query(&mut d, f, FILE_STANDARD_INFORMATION);
    assert_eq!(le32(&s.data, 0), 22);
    assert_eq!(le64(&s.data, 4), 8192, "AllocationSize");
    assert_eq!(le64(&s.data, 12), 5000, "EndOfFile");
    assert_eq!(&s.data[4 + 20..], &[0, 0], "not deleting, not a directory");
    let t = query(&mut d, f, FILE_ATTRIBUTE_TAG_INFORMATION);
    assert_eq!(le32(&t.data, 0), 8);
    assert_eq!(query(&mut d, f, 6).status, 0xC000_0003, "unsupported class");
    assert_eq!(
        query(&mut d, 999, FILE_BASIC_INFORMATION).status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn set_information_size_times_and_attributes() {
    let dir = TempDir::new();
    let mut d = Drive::new("t", dir.path().into(), false);
    let f = open(&mut d, "\\s", GENERIC_READ | GENERIC_WRITE, CREATE, 0).unwrap();
    assert_eq!(
        set(
            &mut d,
            f,
            FILE_END_OF_FILE_INFORMATION,
            &100u64.to_le_bytes()
        ),
        0
    );
    assert_eq!(std::fs::metadata(dir.path().join("s")).unwrap().len(), 100);
    assert_eq!(
        set(
            &mut d,
            f,
            FILE_ALLOCATION_INFORMATION,
            &4096u64.to_le_bytes()
        ),
        0
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("s")).unwrap().len(),
        100,
        "grow: no change"
    );
    assert_eq!(
        set(&mut d, f, FILE_ALLOCATION_INFORMATION, &10u64.to_le_bytes()),
        0
    );
    assert_eq!(std::fs::metadata(dir.path().join("s")).unwrap().len(), 10);
    // 2020-01-01T00:00:00Z as FILETIME.
    let ft: i64 = 132_223_104_000_000_000;
    let mut basic = Vec::new();
    for t in [0, 0, ft, 0] {
        basic.put_bytes(&i64::to_le_bytes(t));
    }
    basic.put_u32(0);
    assert_eq!(set(&mut d, f, FILE_BASIC_INFORMATION, &basic), 0);
    let m = std::fs::metadata(dir.path().join("s"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(filetime(m), ft as u64);
}

#[test]
fn directory_listing_with_pattern_and_restart() {
    let dir = TempDir::new();
    for n in ["b.txt", "a.TXT", "c.log"] {
        std::fs::write(dir.path().join(n), b"12").unwrap();
    }
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("inner.txt"), b"").unwrap();
    let mut d = Drive::new("t", dir.path().into(), false);
    let root = open(&mut d, "\\", GENERIC_READ, OPEN, DIR).unwrap();
    // FileNameLength sits at 60 in the directory classes, 8 in names.
    let name_at = |c: &IoCompletion, off: usize| {
        let len = le32(&c.data, 4 + if off == 12 { 8 } else { 60 }) as usize;
        String::from_utf16(
            &c.data[4 + off..4 + off + len]
                .chunks(2)
                .map(|x| u16::from_le_bytes([x[0], x[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let first = query_dir(&mut d, root, FILE_DIRECTORY_INFORMATION, true, "\\*.txt");
    assert_eq!(first.status, 0);
    assert_eq!(le32(&first.data, 0) as usize, first.data.len() - 4);
    assert_eq!(name_at(&first, 64), "a.TXT");
    assert_eq!(le64(&first.data, 4 + 40), 2, "EndOfFile");
    let second = query_dir(&mut d, root, FILE_DIRECTORY_INFORMATION, false, "");
    assert_eq!(name_at(&second, 64), "b.txt");
    let end = query_dir(&mut d, root, FILE_DIRECTORY_INFORMATION, false, "");
    assert_eq!((end.status, end.data), (STATUS_NO_MORE_FILES, vec![0; 5]));
    // Restart scan: an initial query starts over, here in every class.
    for (class, off) in [
        (FILE_FULL_DIRECTORY_INFORMATION, 68),
        (FILE_BOTH_DIRECTORY_INFORMATION, 94),
        (FILE_NAMES_INFORMATION, 12),
    ] {
        let c = query_dir(&mut d, root, class, true, "\\?.txt");
        assert_eq!(name_at(&c, off), "a.TXT", "class {class}");
    }
    let all = query_dir(&mut d, root, FILE_NAMES_INFORMATION, true, "\\*");
    assert_eq!(name_at(&all, 12), "a.TXT");
    let sub = query_dir(&mut d, root, FILE_NAMES_INFORMATION, true, "\\sub\\*");
    assert_eq!(name_at(&sub, 12), "inner.txt");
    let none = query_dir(&mut d, root, FILE_NAMES_INFORMATION, true, "\\*.doc");
    assert_eq!(none.status, STATUS_NO_SUCH_FILE);
    let esc = query_dir(&mut d, root, FILE_NAMES_INFORMATION, true, "\\..\\*");
    assert_eq!(esc.status, STATUS_ACCESS_DENIED);
    // Change notification stays pending.
    let req = IoRequest {
        device_id: 1,
        file_id: root,
        completion_id: 1,
        major: IRP_MJ_DIRECTORY_CONTROL,
        minor: IRP_MN_NOTIFY_CHANGE_DIRECTORY,
        data: &[0; 32],
    };
    assert!(d.io(&req).is_none());
}

#[test]
fn rename_and_delete() {
    let dir = TempDir::new();
    let p = dir.path();
    std::fs::write(p.join("a"), b"A").unwrap();
    std::fs::write(p.join("b"), b"B").unwrap();
    std::fs::create_dir(p.join("d")).unwrap();
    std::fs::write(p.join("d").join("x"), b"").unwrap();
    let mut d = Drive::new("t", p.into(), false);
    let a = open(&mut d, "\\a", DELETE, OPEN, 0).unwrap();
    assert_eq!(
        set(
            &mut d,
            a,
            FILE_RENAME_INFORMATION,
            &rename_buf("\\b", false)
        ),
        STATUS_OBJECT_NAME_COLLISION
    );
    assert_eq!(
        set(
            &mut d,
            a,
            FILE_RENAME_INFORMATION,
            &rename_buf("\\..\\a", true)
        ),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        set(
            &mut d,
            a,
            FILE_RENAME_INFORMATION,
            &rename_buf("\\d\\moved", false)
        ),
        0
    );
    assert_eq!(std::fs::read(p.join("d").join("moved")).unwrap(), b"A");
    assert!(!p.join("a").exists());
    assert_eq!(
        set(&mut d, a, FILE_RENAME_INFORMATION, &rename_buf("\\b", true)),
        0
    );
    assert_eq!(std::fs::read(p.join("b")).unwrap(), b"A");
    // Delete via FileDispositionInformation, executed on close.
    assert_eq!(set(&mut d, a, FILE_DISPOSITION_INFORMATION, &[1]), 0);
    assert!(p.join("b").exists());
    close(&mut d, a);
    assert!(!p.join("b").exists());
    // A non-empty directory cannot be deleted.
    let dd = open(&mut d, "\\d", DELETE, OPEN, DIR).unwrap();
    assert_eq!(
        set(&mut d, dd, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_DIRECTORY_NOT_EMPTY
    );
    // FILE_DELETE_ON_CLOSE.
    let x = open(&mut d, "\\d\\x", DELETE, OPEN, 0x1000).unwrap();
    close(&mut d, x);
    assert!(!p.join("d").join("x").exists());
    // The root can be neither deleted nor renamed.
    let root = open(&mut d, "\\", GENERIC_READ, OPEN, DIR).unwrap();
    assert_eq!(
        set(&mut d, root, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        set(
            &mut d,
            root,
            FILE_RENAME_INFORMATION,
            &rename_buf("\\r", false)
        ),
        STATUS_ACCESS_DENIED
    );
    assert!(p.exists());
}

#[test]
fn volume_information() {
    let dir = TempDir::new();
    let mut d = Drive::new("Vol", dir.path().into(), false);
    let q = |d: &mut Drive, class| {
        irp(
            d,
            IRP_MJ_QUERY_VOLUME_INFORMATION,
            0,
            0,
            &info_req(class, &[]),
        )
    };
    let v = q(&mut d, FILE_FS_VOLUME_INFORMATION);
    assert_eq!(v.status, 0);
    assert_eq!(le32(&v.data, 0), 18 + 6);
    assert_eq!(le32(&v.data, 4 + 12), 6, "VolumeLabelLength");
    assert_eq!(&v.data[4 + 18..], &utf16le("Vol")[..]);
    let s = q(&mut d, FILE_FS_SIZE_INFORMATION);
    assert_eq!(le32(&s.data, 0), 24);
    assert!(le64(&s.data, 4) > 0, "TotalAllocationUnits");
    assert_eq!((le32(&s.data, 4 + 16), le32(&s.data, 4 + 20)), (8, 512));
    let f = q(&mut d, FILE_FS_FULL_SIZE_INFORMATION);
    assert_eq!(le32(&f.data, 0), 32);
    let a = q(&mut d, FILE_FS_ATTRIBUTE_INFORMATION);
    assert_eq!(&a.data[4 + 12..], &utf16le("FAT32")[..]);
    let dv = q(&mut d, FILE_FS_DEVICE_INFORMATION);
    assert_eq!(dv.data, vec![8, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(q(&mut d, 2).status, 0xC000_0003);
}

#[test]
fn unsupported_and_malformed_requests_are_answered() {
    let dir = TempDir::new();
    let mut d = Drive::new("t", dir.path().into(), false);
    let root = open(&mut d, "\\", GENERIC_READ, OPEN, DIR).unwrap();
    let c = irp(&mut d, IRP_MJ_DEVICE_CONTROL, 0, root, &[0; 32]);
    assert_eq!((c.status, c.data), (STATUS_NOT_SUPPORTED, vec![0; 4]));
    assert_eq!(
        irp(&mut d, IRP_MJ_SET_VOLUME_INFORMATION, 0, root, &[0; 32]).status,
        STATUS_NOT_SUPPORTED
    );
    assert_eq!(irp(&mut d, 0x42, 0, root, &[]).status, STATUS_NOT_SUPPORTED);
    assert_eq!(
        irp(&mut d, IRP_MJ_LOCK_CONTROL, 0, root, &[0; 32]).status,
        0
    );
    assert_eq!(
        irp(&mut d, IRP_MJ_CREATE, 0, 0, &[1, 2, 3]).status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        irp(&mut d, IRP_MJ_WRITE, 0, root, &[0; 8]).status,
        STATUS_INVALID_PARAMETER
    );
    // Bad UTF-16 in a path.
    let mut bad = create_data("", GENERIC_READ, OPEN, 0);
    bad.truncate(bad.len() - 6); // PathLength and the empty path
    bad.put_u32(4);
    bad.put_bytes(&[0x00, 0xD8, 0, 0]); // lone surrogate
    assert_eq!(
        irp(&mut d, IRP_MJ_CREATE, 0, 0, &bad).status,
        STATUS_OBJECT_NAME_INVALID
    );
}

#[test]
fn read_only_drive_rejects_every_write() {
    let dir = TempDir::new();
    let p = dir.path();
    std::fs::write(p.join("keep.txt"), b"keep").unwrap();
    std::fs::create_dir(p.join("d")).unwrap();
    let mut d = Drive::new("ro", p.into(), true);
    for (access, disp, opts) in [
        (GENERIC_WRITE, OPEN, 0),
        (GENERIC_READ, OVERWRITE_IF, 0),
        (GENERIC_READ, 0, 0), // FILE_SUPERSEDE
        (GENERIC_READ, 4, 0), // FILE_OVERWRITE
        (DELETE, OPEN, 0),
        (GENERIC_READ, OPEN, 0x1000), // delete on close
        (0x0000_0100, OPEN, 0),       // FILE_WRITE_ATTRIBUTES
    ] {
        assert_eq!(
            open(&mut d, "\\keep.txt", access, disp, opts),
            Err(STATUS_ACCESS_DENIED),
            "{access:#x} {disp} {opts:#x}"
        );
    }
    assert_eq!(
        open(&mut d, "\\new", GENERIC_READ, CREATE, 0),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        open(&mut d, "\\new", GENERIC_READ, OPEN_IF, 0),
        Err(STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        open(&mut d, "\\nd", GENERIC_READ, CREATE, DIR),
        Err(STATUS_ACCESS_DENIED)
    );
    // Reading still works, MAXIMUM_ALLOWED included.
    let f = open(&mut d, "\\keep.txt", GENERIC_READ | 0x0200_0000, OPEN_IF, 0).unwrap();
    assert_eq!(&read(&mut d, f, 10, 0).data[4..], b"keep");
    assert_eq!(write(&mut d, f, 0, b"XXXX").status, STATUS_ACCESS_DENIED);
    for (class, buf) in [
        (FILE_END_OF_FILE_INFORMATION, vec![0; 8]),
        (FILE_ALLOCATION_INFORMATION, vec![0; 8]),
        (FILE_DISPOSITION_INFORMATION, vec![1]),
        (FILE_RENAME_INFORMATION, rename_buf("\\other", true)),
        (FILE_BASIC_INFORMATION, vec![0; 36]),
    ] {
        assert_eq!(
            set(&mut d, f, class, &buf),
            STATUS_ACCESS_DENIED,
            "class {class}"
        );
    }
    close(&mut d, f);
    let f = open(&mut d, "\\keep.txt", GENERIC_READ, OPEN, 0).unwrap();
    let b = query(&mut d, f, FILE_BASIC_INFORMATION);
    assert_ne!(le32(&b.data, 4 + 32) & FILE_ATTRIBUTE_READONLY, 0);
    assert_eq!(std::fs::read(p.join("keep.txt")).unwrap(), b"keep");
    assert!(!p.join("new").exists() && !p.join("nd").exists());
}

#[test]
fn traversal_and_escape_paths_are_refused() {
    let base = TempDir::new();
    let root = base.path().join("share");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(base.path().join("secret.txt"), b"secret").unwrap();
    std::fs::write(root.join("ok.txt"), b"ok").unwrap();
    let mut d = Drive::new("t", root.clone(), false);
    let secret = base.path().join("secret.txt");
    let abs = secret.to_str().unwrap().to_string();
    let cases: Vec<(&str, u32)> = vec![
        ("\\..\\secret.txt", STATUS_ACCESS_DENIED),
        ("..\\secret.txt", STATUS_ACCESS_DENIED),
        ("\\sub\\..\\..\\secret.txt", STATUS_ACCESS_DENIED),
        ("/../secret.txt", STATUS_ACCESS_DENIED),
        ("\\ok.txt\\..", STATUS_ACCESS_DENIED),
        ("\\.\\ok.txt", STATUS_OBJECT_NAME_INVALID),
        ("C:\\Windows\\win.ini", STATUS_OBJECT_NAME_INVALID),
        ("\\C:secret.txt", STATUS_OBJECT_NAME_INVALID),
        (&abs, STATUS_OBJECT_NAME_INVALID),
        ("\\\\server\\share\\x", STATUS_OBJECT_NAME_INVALID),
        ("\\\\?\\C:\\x", STATUS_OBJECT_NAME_INVALID),
        ("//server/share/x", STATUS_OBJECT_NAME_INVALID),
        ("\\ok.txt:stream", STATUS_OBJECT_NAME_INVALID),
        ("\\ok.txt::$DATA", STATUS_OBJECT_NAME_INVALID),
        ("\\ok.txt.", STATUS_OBJECT_NAME_INVALID),
        ("\\ok.txt ", STATUS_OBJECT_NAME_INVALID),
        ("\\CON", STATUS_OBJECT_NAME_INVALID),
        ("\\nul.txt", STATUS_OBJECT_NAME_INVALID),
        ("\\a*b", STATUS_OBJECT_NAME_INVALID),
        ("\\a\u{1}b", STATUS_OBJECT_NAME_INVALID),
    ];
    for (path, status) in &cases {
        for disp in [OPEN, CREATE, OPEN_IF] {
            assert_eq!(
                open(&mut d, path, GENERIC_READ | GENERIC_WRITE, disp, 0),
                Err(*status),
                "{path:?} disposition {disp}"
            );
        }
    }
    // The absolute path really points at the secret; only the check stops it.
    assert!(Path::new(&abs).exists());
    assert_eq!(std::fs::read(&secret).unwrap(), b"secret");
    assert!(!base.path().join("sub").exists());
    assert!(open(&mut d, "\\ok.txt", GENERIC_READ, OPEN, 0).is_ok());
    assert!(
        open(&mut d, "ok.txt", GENERIC_READ, OPEN, 0).is_ok(),
        "no leading slash"
    );
}

/// Creates a symlink, or returns false where the OS does not allow it
/// (Windows without developer mode or the privilege).
fn symlink(target: &Path, link: &Path, dir: bool) -> bool {
    #[cfg(windows)]
    let r = if dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    };
    #[cfg(unix)]
    let r = {
        let _ = dir;
        std::os::unix::fs::symlink(target, link)
    };
    r.is_ok()
}

#[test]
fn symlink_escapes_are_refused() {
    let base = TempDir::new();
    let root = base.path().join("share");
    let outside = base.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
    if !symlink(&outside, &root.join("link"), true) {
        eprintln!("symlinks not permitted here; symlink escape test skipped");
        return;
    }
    assert!(symlink(
        &outside.join("secret.txt"),
        &root.join("file"),
        false
    ));
    assert!(symlink(
        &outside.join("gone.txt"),
        &root.join("dangling"),
        false
    ));
    std::fs::create_dir(root.join("inner")).unwrap();
    assert!(symlink(&root.join("inner"), &root.join("inlink"), true));
    let mut d = Drive::new("t", root.clone(), false);
    for path in [
        "\\link\\secret.txt",
        "\\link",
        "\\file",
        "\\link\\new.txt",
        "\\dangling",
    ] {
        for disp in [OPEN, OPEN_IF] {
            assert_eq!(
                open(&mut d, path, GENERIC_READ | GENERIC_WRITE, disp, 0),
                Err(STATUS_ACCESS_DENIED),
                "{path} disposition {disp}"
            );
        }
    }
    assert!(!outside.join("new.txt").exists() && !outside.join("gone.txt").exists());
    let r = open(&mut d, "\\", GENERIC_READ, OPEN, DIR).unwrap();
    let c = query_dir(&mut d, r, FILE_NAMES_INFORMATION, true, "\\link\\*");
    assert_eq!(c.status, STATUS_ACCESS_DENIED);
    // A link that stays inside the root is fine.
    assert!(open(&mut d, "\\inlink\\x.txt", GENERIC_WRITE, CREATE, 0).is_ok());
}

#[test]
fn wildcards_and_filetime() {
    use super::path::wildcard_match as m;
    assert!(m("*", "anything"));
    assert!(m("*.txt", "A.TXT"));
    assert!(!m("*.txt", "a.txt.bak"));
    assert!(m("a?c", "abc"));
    assert!(!m("a?c", "ac"));
    assert!(m("*a*b", "xxaxxb"));
    assert!(m("<.txt", "x.txt"));
    assert!(!m("abc", "abcd"));
    assert_eq!(filetime(std::time::UNIX_EPOCH), 116_444_736_000_000_000);
    let t = from_filetime(132_223_104_000_000_000).unwrap();
    assert_eq!(filetime(t), 132_223_104_000_000_000);
    assert!(from_filetime(0).is_none() && from_filetime(-1).is_none());
}
