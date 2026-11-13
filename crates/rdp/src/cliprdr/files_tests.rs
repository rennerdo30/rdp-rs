//! File transfer tests: spec bytes (MS-RDPECLIP 4.1.3, 4.4.3, 4.4.4, 4.5)
//! and flows against a fake clipboard and a private temp folder.

use super::files::*;
use super::*;
use std::fs;
use std::path::Path;

#[derive(Default)]
struct Fake {
    seq: u32,
    text: Option<String>,
    files: Option<Vec<PathBuf>>,
    file_writes: Vec<Vec<PathBuf>>,
    /// Number of upcoming write_files calls that fail (clipboard busy).
    busy: u32,
}

struct Mock(Arc<Mutex<Fake>>);

impl ClipboardBackend for Mock {
    fn sequence(&mut self) -> u32 {
        self.0.lock().unwrap().seq
    }
    fn read_text(&mut self) -> Option<String> {
        self.0.lock().unwrap().text.clone()
    }
    fn write_text(&mut self, text: &str) -> bool {
        let mut f = self.0.lock().unwrap();
        f.seq += 1;
        f.text = Some(text.to_string());
        true
    }
    fn supports_files(&self) -> bool {
        true
    }
    fn read_files(&mut self) -> Option<Vec<PathBuf>> {
        self.0.lock().unwrap().files.clone()
    }
    fn write_files(&mut self, paths: &[PathBuf]) -> bool {
        let mut f = self.0.lock().unwrap();
        f.seq += 1;
        if f.busy > 0 {
            f.busy -= 1;
            return false;
        }
        f.files = Some(paths.to_vec());
        f.file_writes.push(paths.to_vec());
        true
    }
}

/// A private folder under the system temp folder, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("rdp17-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hex(s: &str) -> Vec<u8> {
    let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// A spec dump given as its non-zero lines: (offset, bytes), rest zeros.
fn sparse(len: usize, lines: &[(usize, &str)]) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for &(at, bytes) in lines {
        let b = hex(bytes);
        v[at..at + b.len()].copy_from_slice(&b);
    }
    v
}

// MS-RDPECLIP 4.1.1 Server Clipboard Capabilities PDU (generalFlags 0x0e).
const SERVER_CAPS: [u8; 24] = [
    0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
];
const MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const LIST_RESPONSE_OK: [u8; 8] = [0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
const LIST_EMPTY: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// MS-RDPECLIP 4.1.3 Client Clipboard Capabilities PDU (flags 0x0e).
fn spec_413() -> Vec<u8> {
    hex("07 00 00 00 10 00 00 00 01 00 00 00 01 00 0c 00 02 00 00 00 0e 00 00 00")
}

/// MS-RDPECLIP 4.5.1 Format List PDU: FileGroupDescriptorW as 0xc079. (The
/// dump's annotation says dataLen 0x7a; its bytes and the text say 0x2e.)
fn spec_451() -> Vec<u8> {
    hex("02 00 00 00 2e 00 00 00 79 c0 00 00 46 00 69 00
         6c 00 65 00 47 00 72 00 6f 00 75 00 70 00 44 00
         65 00 73 00 63 00 72 00 69 00 70 00 74 00 6f 00
         72 00 57 00 00 00")
}

/// MS-RDPECLIP 4.5.3 Format Data Request PDU for format 0xc079.
fn spec_453() -> Vec<u8> {
    hex("04 00 00 00 04 00 00 00 79 c0 00 00")
}

/// MS-RDPECLIP 4.5.4 Format Data Response PDU: File1.txt (44 bytes) and
/// File2.txt (10 bytes); the dump's non-zero lines.
fn spec_454() -> Vec<u8> {
    sparse(
        0x4ac,
        &[
            (0x000, "05 00 01 00 a4 04 00 00 02 00 00 00 64 40 00 00"),
            (0x030, "20 00 00 00"),
            (0x044, "08 5d 30 2c f3 55 ca 01 00 00 00 00"),
            (0x050, "2c 00 00 00 46 00 69 00 6c 00 65 00 31 00 2e 00"),
            (0x060, "74 00 78 00 74 00"),
            (0x25c, "64 40 00 00"),
            (0x280, "20 00 00 00"),
            (0x294, "08 5d 30 2c f3 55 ca 01 00 00 00 00"),
            (0x2a0, "0a 00 00 00 46 00 69 00 6c 00 65 00 32 00 2e 00"),
            (0x2b0, "74 00 78 00 74 00"),
        ],
    )
}

fn spec_454_descriptors() -> Vec<FileDescriptor> {
    let d = |size, name: &str| FileDescriptor {
        flags: FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME | FD_SHOWPROGRESSUI,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        write_time: 0x01ca_55f3_2c30_5d08,
        size,
        name: name.into(),
    };
    vec![d(44, "File1.txt"), d(10, "File2.txt")]
}

fn file(name: &str, size: u64) -> FileDescriptor {
    FileDescriptor {
        flags: FD_ATTRIBUTES | FD_FILESIZE,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        write_time: 0,
        size,
        name: name.into(),
    }
}

fn dir(name: &str) -> FileDescriptor {
    FileDescriptor {
        flags: FD_ATTRIBUTES,
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        write_time: 0,
        size: 0,
        name: name.into(),
    }
}

fn list_response(files: &[FileDescriptor]) -> Vec<u8> {
    pdu(
        CB_FORMAT_DATA_RESPONSE,
        CB_RESPONSE_OK,
        &encode_file_list(files),
    )
}

fn feed(c: &mut Cliprdr, msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = ChannelOut::default();
    c.process(msg, &mut out).unwrap();
    out.take()
}

fn tick(c: &mut Cliprdr) -> Vec<Vec<u8>> {
    let mut out = ChannelOut::default();
    c.tick(&mut out).unwrap();
    out.take()
}

/// Session with a file-capable backend after initialization, sharing on,
/// remote files stored under `root`.
fn connected(root: &Path) -> (Cliprdr, ClipboardHandle, Arc<Mutex<Fake>>) {
    let fake = Arc::new(Mutex::new(Fake::default()));
    let (mut c, h) = cliprdr(Box::new(Mock(fake.clone())));
    c.set_file_root(root.to_path_buf());
    h.set_enabled(true);
    feed(&mut c, &SERVER_CAPS);
    let out = feed(&mut c, &MONITOR_READY);
    assert_eq!(out, vec![spec_413(), LIST_EMPTY.to_vec()]);
    assert!(tick(&mut c).is_empty());
    (c, h, fake)
}

/// Fields of one File Contents Request the client sent.
fn request(msg: &[u8]) -> FileContentsRequest {
    let (t, f, body) = parse_header(msg).unwrap();
    assert_eq!((t, f, body.len()), (CB_FILECONTENTS_REQUEST, 0, 24));
    parse_file_contents_request(body).unwrap()
}

fn size_response(stream: u32, size: u64) -> Vec<u8> {
    file_contents_response(stream, Some(&size.to_le_bytes()))
}

/// Subfolders of the temp root (one per transfer).
fn transfer_dirs(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Answers every request the client makes from `files` (lindex -> bytes)
/// until it goes quiet; returns the requests seen.
fn serve_all(c: &mut Cliprdr, files: &[Option<&[u8]>]) -> Vec<FileContentsRequest> {
    let mut seen = Vec::new();
    for _ in 0..1000 {
        let out = tick(c);
        if out.is_empty() {
            return seen;
        }
        assert_eq!(out.len(), 1, "one request in flight");
        let req = request(&out[0]);
        seen.push(req);
        let data = files[req.lindex as usize].expect("no requests for directories");
        let reply = if req.flags == FILECONTENTS_SIZE {
            size_response(req.stream_id, data.len() as u64)
        } else {
            let at = req.position as usize;
            let end = (at + req.requested as usize).min(data.len());
            file_contents_response(req.stream_id, Some(&data[at..end]))
        };
        assert!(feed(c, &reply).is_empty());
    }
    panic!("transfer did not finish");
}

#[test]
fn capabilities_with_files() {
    // Spec server (0x0e): the client answers exactly 4.1.3.
    let tmp = TempDir::new("caps");
    connected(&tmp.0);
    // Windows 11 server (0x3e): long names, streams, no paths, huge files;
    // never locking, which the client does not use.
    let fake = Arc::new(Mutex::new(Fake::default()));
    let (mut c, _h) = cliprdr(Box::new(Mock(fake)));
    let mut caps = SERVER_CAPS;
    caps[20] = 0x3e;
    feed(&mut c, &caps);
    let out = feed(&mut c, &MONITOR_READY);
    assert_eq!(out[0], capabilities(0x2e));
    // A server without file streams gets long names only.
    let fake = Arc::new(Mutex::new(Fake::default()));
    let (mut c, _h) = cliprdr(Box::new(Mock(fake)));
    caps[20] = 0x02;
    feed(&mut c, &caps);
    assert_eq!(feed(&mut c, &MONITOR_READY)[0], capabilities(0x02));
}

#[test]
fn file_list_spec_bytes() {
    let msg = spec_454();
    assert_eq!(list_response(&spec_454_descriptors()), msg);
    let (t, f, body) = parse_header(&msg).unwrap();
    assert_eq!((t, f), (CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK));
    assert_eq!(parse_file_list(body).unwrap(), spec_454_descriptors());
    assert!(!spec_454_descriptors()[0].is_dir());
    assert!(dir("d").is_dir());
    // Truncated or oversized lists are errors, never panics.
    assert!(parse_file_list(&body[..body.len() - 1]).is_err());
    assert!(parse_file_list(&[0xff, 0xff, 0xff, 0x7f]).is_err());
    assert!(parse_file_list(&[1, 0]).is_err());
    assert_eq!(parse_file_list(&[0, 0, 0, 0]).unwrap(), vec![]);
    // Names are cut to 259 units plus NUL.
    let long = "x".repeat(300);
    let parsed = parse_file_list(&encode_file_list(&[file(&long, 1)])).unwrap();
    assert_eq!(parsed[0].name.len(), 259);
    // 64-bit sizes use both halves.
    let big = parse_file_list(&encode_file_list(&[file("b", 0x1_0000_0002)])).unwrap();
    assert_eq!(big[0].size, 0x1_0000_0002);
}

#[test]
fn file_contents_spec_bytes() {
    // 4.4.3.1 size request, 4.4.3.2 range request.
    let size_req = hex("08 00 00 00 18 00 00 00 02 00 00 00 01 00 00 00
         01 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00");
    let range_req = hex("08 00 00 00 18 00 00 00 02 00 00 00 01 00 00 00
         02 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00");
    assert_eq!(
        file_contents_request(2, 1, FILECONTENTS_SIZE, 0, 8),
        size_req
    );
    assert_eq!(
        file_contents_request(2, 1, FILECONTENTS_RANGE, 0, 0x10000),
        range_req
    );
    let (_, _, body) = parse_header(&range_req).unwrap();
    assert_eq!(
        parse_file_contents_request(body).unwrap(),
        FileContentsRequest {
            stream_id: 2,
            lindex: 1,
            flags: FILECONTENTS_RANGE,
            position: 0,
            requested: 0x10000
        }
    );
    // 64-bit positions; a trailing clipDataId is ignored.
    let mut b = file_contents_request(7, 3, FILECONTENTS_RANGE, 0x2_0000_0010, 5)[8..].to_vec();
    b.extend([9, 0, 0, 0]);
    assert_eq!(
        parse_file_contents_request(&b).unwrap().position,
        0x2_0000_0010
    );
    assert!(parse_file_contents_request(&b[..20]).is_err());
    // 4.4.4.1 size response (44), 4.4.4.2 range response.
    assert_eq!(
        size_response(2, 44),
        hex("09 00 01 00 0c 00 00 00 02 00 00 00 2c 00 00 00 00 00 00 00")
    );
    let fox = b"The quick brown fox jumps over the lazy dog.";
    let mut want = hex("09 00 01 00 30 00 00 00 02 00 00 00");
    want.extend(fox);
    assert_eq!(file_contents_response(2, Some(fox)), want);
    assert_eq!(
        file_contents_response(2, None),
        hex("09 00 02 00 04 00 00 00 02 00 00 00")
    );
}

#[test]
fn unsafe_names_rejected() {
    for bad in [
        "",
        "..",
        "..\\evil.txt",
        "a\\..\\..\\evil.txt",
        "\\abs.txt",
        "/abs.txt",
        "\\\\server\\share\\x",
        "C:\\Windows\\x.dll",
        "C:x",
        "a:stream",
        "a\\\\b",
        ".",
        "a\\.\\b",
        "dir\\",
        "CON",
        "nul.txt",
        "com1",
        "trailing.",
        "space ",
        "q?.txt",
        "a\u{1}b",
        "../evil",
    ] {
        assert_eq!(safe_relative_path(bad), None, "{bad:?} must be rejected");
    }
    assert_eq!(
        safe_relative_path("dir\\sub\\a b.txt"),
        Some(Path::new("dir").join("sub").join("a b.txt"))
    );
    assert_eq!(
        safe_relative_path("..hidden"),
        Some(PathBuf::from("..hidden"))
    );
    assert_eq!(
        safe_relative_path("console.log"),
        Some(PathBuf::from("console.log"))
    );
}

#[test]
fn remote_files_fetched_in_chunks_and_put_on_clipboard() {
    let tmp = TempDir::new("fetch");
    let (mut c, h, fake) = connected(&tmp.0);
    // 4.5.1 -> 4.5.2 response and 4.5.3 request.
    let out = feed(&mut c, &spec_451());
    assert_eq!(out, vec![LIST_RESPONSE_OK.to_vec(), spec_453()]);
    let big: Vec<u8> = (0..(2 * CHUNK + CHUNK / 2))
        .map(|i| (i % 251) as u8)
        .collect();
    let small = b"0123456789".to_vec();
    let list = [
        dir("dir"),
        file("dir\\big.bin", big.len() as u64),
        dir("dir\\empty"),
        file("b.txt", small.len() as u64),
        file("zero.txt", 0),
    ];
    assert!(feed(&mut c, &list_response(&list)).is_empty());
    let status = h.transfer().expect("status while running");
    assert_eq!(status.direction, Direction::ToLocal);
    assert_eq!((status.done, status.total), (0, big.len() as u64 + 10));

    let reqs = serve_all(&mut c, &[None, Some(&big), None, Some(&small), Some(&[])]);
    let shape: Vec<(i32, u32, u64, u32)> = reqs
        .iter()
        .map(|r| (r.lindex, r.flags, r.position, r.requested))
        .collect();
    let (s, r) = (FILECONTENTS_SIZE, FILECONTENTS_RANGE);
    assert_eq!(
        shape,
        vec![
            (1, s, 0, 8),
            (1, r, 0, CHUNK),
            (1, r, CHUNK as u64, CHUNK),
            (1, r, 2 * CHUNK as u64, CHUNK / 2),
            (3, s, 0, 8),
            (3, r, 0, 10),
            (4, s, 0, 8),
        ]
    );
    // Fresh stream id per request.
    let mut ids: Vec<u32> = reqs.iter().map(|r| r.stream_id).collect();
    ids.dedup();
    assert_eq!(ids.len(), reqs.len());

    let f = fake.lock().unwrap();
    assert_eq!(f.file_writes.len(), 1, "write_files called once");
    let dirs = transfer_dirs(&tmp.0);
    assert_eq!(dirs.len(), 1);
    let root = &dirs[0];
    assert_eq!(
        f.file_writes[0],
        vec![root.join("dir"), root.join("b.txt"), root.join("zero.txt")]
    );
    assert_eq!(fs::read(root.join("dir").join("big.bin")).unwrap(), big);
    assert_eq!(fs::read(root.join("b.txt")).unwrap(), small);
    assert_eq!(fs::read(root.join("zero.txt")).unwrap(), b"");
    assert!(root.join("dir").join("empty").is_dir());
    drop(f);
    assert_eq!(h.transfer(), None, "status cleared when done");
    // No echo of our own clipboard write.
    assert!(tick(&mut c).is_empty());
}

#[test]
fn status_reports_progress() {
    let tmp = TempDir::new("status");
    let (mut c, h, _fake) = connected(&tmp.0);
    feed(&mut c, &spec_451());
    let data = vec![7u8; CHUNK as usize + 5];
    feed(&mut c, &list_response(&[file("a.bin", data.len() as u64)]));
    let req = request(&tick(&mut c)[0]);
    feed(&mut c, &size_response(req.stream_id, data.len() as u64));
    let req = request(&tick(&mut c)[0]);
    let chunk = &data[..req.requested as usize];
    feed(&mut c, &file_contents_response(req.stream_id, Some(chunk)));
    let s = h.transfer().unwrap();
    assert_eq!(
        (s.name.as_str(), s.done, s.total),
        ("a.bin", CHUNK as u64, data.len() as u64)
    );
}

#[test]
fn busy_clipboard_retries_file_write() {
    let tmp = TempDir::new("busy");
    let (mut c, _h, fake) = connected(&tmp.0);
    fake.lock().unwrap().busy = 2;
    feed(&mut c, &spec_451());
    feed(&mut c, &list_response(&[file("a.txt", 3)]));
    serve_all(&mut c, &[Some(b"abc")]);
    assert!(fake.lock().unwrap().file_writes.is_empty());
    assert!(tick(&mut c).is_empty());
    assert!(tick(&mut c).is_empty());
    assert_eq!(fake.lock().unwrap().file_writes.len(), 1);
    assert!(tick(&mut c).is_empty(), "no echo after a retried write");
}

/// Starts a transfer of one 3-chunk file and fetches its first chunk.
fn half_done(c: &mut Cliprdr) -> u32 {
    feed(c, &spec_451());
    feed(c, &list_response(&[file("a.bin", 3 * CHUNK as u64)]));
    let req = request(&tick(c)[0]);
    feed(c, &size_response(req.stream_id, 3 * CHUNK as u64));
    let req = request(&tick(c)[0]);
    feed(
        c,
        &file_contents_response(req.stream_id, Some(&vec![1u8; CHUNK as usize])),
    );
    request(&tick(c)[0]).stream_id
}

#[test]
fn new_local_copy_cancels_transfer() {
    let tmp = TempDir::new("cancel-local");
    let (mut c, h, fake) = connected(&tmp.0);
    let stream = half_done(&mut c);
    assert_eq!(transfer_dirs(&tmp.0).len(), 1);
    {
        let mut f = fake.lock().unwrap();
        f.seq += 1;
        f.text = Some("local".into());
    }
    assert_eq!(tick(&mut c), vec![format_list(LOCAL_FORMATS, true)]);
    assert!(transfer_dirs(&tmp.0).is_empty(), "partial files deleted");
    assert_eq!(h.transfer(), None);
    // The late answer is ignored; nothing more is requested or written.
    let late = file_contents_response(stream, Some(&[1u8; 16]));
    assert!(feed(&mut c, &late).is_empty());
    assert!(tick(&mut c).is_empty());
    assert!(fake.lock().unwrap().file_writes.is_empty());
}

#[test]
fn new_remote_copy_cancels_transfer() {
    let tmp = TempDir::new("cancel-remote");
    let (mut c, _h, fake) = connected(&tmp.0);
    half_done(&mut c);
    let first = transfer_dirs(&tmp.0);
    // The server copies text: the file transfer stops, text is fetched.
    let text_list = format_list(&[(CF_UNICODETEXT, "")], true);
    let out = feed(&mut c, &text_list);
    assert_eq!(out[1], format_data_request(CF_UNICODETEXT));
    assert!(transfer_dirs(&tmp.0).is_empty());
    assert!(!first[0].exists());
    assert!(tick(&mut c).is_empty());
    assert!(fake.lock().unwrap().file_writes.is_empty());
}

#[test]
fn sharing_off_cancels_transfer() {
    let tmp = TempDir::new("cancel-off");
    let (mut c, h, fake) = connected(&tmp.0);
    half_done(&mut c);
    h.set_enabled(false);
    assert_eq!(tick(&mut c), vec![LIST_EMPTY.to_vec()]);
    assert!(transfer_dirs(&tmp.0).is_empty());
    assert!(tick(&mut c).is_empty());
    assert!(fake.lock().unwrap().file_writes.is_empty());
}

#[test]
fn server_failure_aborts_transfer() {
    let tmp = TempDir::new("fail");
    let (mut c, _h, fake) = connected(&tmp.0);
    feed(&mut c, &spec_451());
    feed(&mut c, &list_response(&[file("a.txt", 3)]));
    let req = request(&tick(&mut c)[0]);
    feed(&mut c, &file_contents_response(req.stream_id, None));
    assert!(tick(&mut c).is_empty());
    assert!(transfer_dirs(&tmp.0).is_empty());
    assert!(fake.lock().unwrap().file_writes.is_empty());
    // More data than requested is a failure too.
    feed(&mut c, &spec_451());
    feed(&mut c, &list_response(&[file("a.txt", 3)]));
    let req = request(&tick(&mut c)[0]);
    feed(&mut c, &size_response(req.stream_id, 3));
    let req = request(&tick(&mut c)[0]);
    feed(
        &mut c,
        &file_contents_response(req.stream_id, Some(b"abcd")),
    );
    assert!(tick(&mut c).is_empty());
    assert!(transfer_dirs(&tmp.0).is_empty());
}

#[test]
fn traversal_names_rejected() {
    let tmp = TempDir::new("traversal");
    let (mut c, h, fake) = connected(&tmp.0);
    for evil in [
        "..\\evil.txt",
        "C:\\evil.txt",
        "\\evil.txt",
        "ok\\..\\..\\evil.txt",
    ] {
        feed(&mut c, &spec_451());
        let list = [file("fine.txt", 1), file(evil, 1)];
        assert!(feed(&mut c, &list_response(&list)).is_empty());
        assert!(tick(&mut c).is_empty(), "{evil}: nothing requested");
        assert_eq!(h.transfer(), None);
    }
    assert!(transfer_dirs(&tmp.0).is_empty());
    assert!(!tmp.0.parent().unwrap().join("evil.txt").exists());
    assert!(fake.lock().unwrap().file_writes.is_empty());
}

#[test]
fn size_cap_enforced() {
    let tmp = TempDir::new("cap");
    let (mut c, _h, fake) = connected(&tmp.0);
    // Listed sizes over the cap: rejected before anything is fetched.
    feed(&mut c, &spec_451());
    let list = [file("a", MAX_TRANSFER_BYTES), file("b", 1)];
    feed(&mut c, &list_response(&list));
    assert!(tick(&mut c).is_empty());
    // Sizes the list hid (no FD_FILESIZE) are checked on FILECONTENTS_SIZE.
    feed(&mut c, &spec_451());
    let mut hidden = file("a", 0);
    hidden.flags = FD_ATTRIBUTES;
    feed(&mut c, &list_response(&[hidden]));
    let req = request(&tick(&mut c)[0]);
    feed(
        &mut c,
        &size_response(req.stream_id, MAX_TRANSFER_BYTES + 1),
    );
    assert!(tick(&mut c).is_empty());
    assert!(transfer_dirs(&tmp.0).is_empty());
    assert!(fake.lock().unwrap().file_writes.is_empty());
}

#[test]
fn remote_text_still_works_with_file_backend() {
    let tmp = TempDir::new("text");
    let (mut c, _h, fake) = connected(&tmp.0);
    let out = feed(&mut c, &format_list(&[(CF_UNICODETEXT, "")], true));
    assert_eq!(
        out,
        vec![
            LIST_RESPONSE_OK.to_vec(),
            format_data_request(CF_UNICODETEXT)
        ]
    );
    let reply = pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, &utf16le_z("hi"));
    feed(&mut c, &reply);
    assert_eq!(fake.lock().unwrap().text.as_deref(), Some("hi"));
    assert!(tick(&mut c).is_empty());
}

#[test]
fn local_files_listed_and_served() {
    let tmp = TempDir::new("serve");
    let src = tmp.0.join("src");
    fs::create_dir_all(src.join("top").join("sub")).unwrap();
    fs::write(src.join("top").join("a.txt"), b"hello").unwrap();
    fs::write(src.join("top").join("sub").join("c.bin"), [9u8; 300]).unwrap();
    fs::write(src.join("one.txt"), b"The quick brown fox").unwrap();
    let (mut c, h, fake) = connected(&tmp.0.join("in"));
    {
        let mut f = fake.lock().unwrap();
        f.seq += 1;
        f.files = Some(vec![src.join("top"), src.join("one.txt")]);
    }
    let announced = tick(&mut c);
    assert_eq!(
        announced,
        vec![format_list(
            &[(LOCAL_FILE_LIST_ID, "FileGroupDescriptorW")],
            true
        )]
    );
    feed(&mut c, &LIST_RESPONSE_OK);
    let out = feed(&mut c, &format_data_request(LOCAL_FILE_LIST_ID));
    let (t, f, body) = parse_header(&out[0]).unwrap();
    assert_eq!((t, f), (CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK));
    let list = parse_file_list(body).unwrap();
    let names: Vec<(&str, bool, u64)> = list
        .iter()
        .map(|d| (d.name.as_str(), d.is_dir(), d.size))
        .collect();
    assert_eq!(
        names,
        vec![
            ("top", true, 0),
            ("top\\a.txt", false, 5),
            ("top\\sub", true, 0),
            ("top\\sub\\c.bin", false, 300),
            ("one.txt", false, 19),
        ]
    );
    assert!(list.iter().all(|d| d.flags == 0x4064 && d.write_time > 0));

    let ask = |c: &mut Cliprdr, lindex: u32, flags, pos, n| {
        let out = feed(c, &file_contents_request(5, lindex, flags, pos, n));
        assert_eq!(out.len(), 1);
        out[0].clone()
    };
    assert_eq!(
        ask(&mut c, 4, FILECONTENTS_SIZE, 0, 8),
        size_response(5, 19)
    );
    let mut want = vec![];
    want.extend(b"quick");
    assert_eq!(
        ask(&mut c, 4, FILECONTENTS_RANGE, 4, 5),
        file_contents_response(5, Some(&want))
    );
    // Ranges are cut at the end of the file; the end itself is empty.
    assert_eq!(
        ask(&mut c, 1, FILECONTENTS_RANGE, 3, 100),
        file_contents_response(5, Some(b"lo"))
    );
    assert_eq!(
        ask(&mut c, 1, FILECONTENTS_RANGE, 5, 100),
        file_contents_response(5, Some(&[]))
    );
    let fail = file_contents_response(5, None);
    // Past the end, unknown index, directory, bad flags: failures.
    assert_eq!(ask(&mut c, 1, FILECONTENTS_RANGE, 6, 1), fail);
    assert_eq!(ask(&mut c, 5, FILECONTENTS_SIZE, 0, 8), fail);
    assert_eq!(ask(&mut c, 0xffff_ffff, FILECONTENTS_SIZE, 0, 8), fail);
    assert_eq!(ask(&mut c, 0, FILECONTENTS_SIZE, 0, 8), fail);
    assert_eq!(ask(&mut c, 1, 3, 0, 8), fail);
    let s = h.transfer().expect("serving shows progress");
    assert_eq!(s.direction, Direction::ToRemote);
    // A file that vanished fails.
    fs::remove_file(src.join("top").join("sub").join("c.bin")).unwrap();
    assert_eq!(ask(&mut c, 3, FILECONTENTS_SIZE, 0, 8), fail);
    assert_eq!(ask(&mut c, 3, FILECONTENTS_RANGE, 0, 8), fail);
    // Sharing off: nothing is served.
    h.set_enabled(false);
    tick(&mut c);
    assert_eq!(ask(&mut c, 4, FILECONTENTS_SIZE, 0, 8), fail);
    assert_eq!(h.transfer(), None);
}

#[test]
fn local_files_and_text_announced_together() {
    let tmp = TempDir::new("both");
    fs::write(tmp.0.join("x.txt"), b"x").unwrap();
    let (mut c, _h, fake) = connected(&tmp.0.join("in"));
    {
        let mut f = fake.lock().unwrap();
        f.seq += 1;
        f.files = Some(vec![tmp.0.join("x.txt")]);
        f.text = Some("x.txt".into());
    }
    assert_eq!(
        tick(&mut c),
        vec![format_list(
            &[(LOCAL_FILE_LIST_ID, FILE_LIST_FORMAT), (CF_UNICODETEXT, "")],
            true
        )]
    );
}

#[test]
fn text_only_backend_never_offers_files() {
    // The default backend methods: no file flags, file lists ignored.
    struct TextOnly;
    impl ClipboardBackend for TextOnly {
        fn sequence(&mut self) -> u32 {
            0
        }
        fn read_text(&mut self) -> Option<String> {
            None
        }
        fn write_text(&mut self, _: &str) -> bool {
            true
        }
    }
    let (mut c, h) = cliprdr(Box::new(TextOnly));
    h.set_enabled(true);
    let mut caps = SERVER_CAPS;
    caps[20] = 0x3e;
    feed(&mut c, &caps);
    assert_eq!(feed(&mut c, &MONITOR_READY)[0], capabilities(0x02));
    assert_eq!(feed(&mut c, &spec_451()), vec![LIST_RESPONSE_OK.to_vec()]);
    let req = file_contents_request(1, 0, FILECONTENTS_SIZE, 0, 8);
    assert_eq!(feed(&mut c, &req), vec![file_contents_response(1, None)]);
}
