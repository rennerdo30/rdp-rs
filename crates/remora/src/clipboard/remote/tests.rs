//! The data object and its streams against a fake server: a thread drives
//! a real `Cliprdr` channel and answers its requests like rdpclip. The test
//! reads through the COM interfaces like a pasting program; the system
//! clipboard is never touched.

use super::*;
use rdp::StaticChannel;
use rdp::channel::ChannelOut;
use rdp::cliprdr::files::{file_contents_response, parse_file_contents_request};
use rdp::cliprdr::{
    CB_FILECONTENTS_REQUEST, CB_FORMAT_DATA_REQUEST, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL,
    CB_RESPONSE_OK, ClipboardBackend, format_list, parse_header, pdu,
};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use windows::Win32::Foundation::HGLOBAL;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Memory::GlobalSize;
use windows::Win32::System::Ole::ReleaseStgMedium;

const FILES_ID: u32 = 0xc0a1;
const PNG_ID: u32 = 0xc0b2;
const MIB: u64 = 1 << 20;

/// A server file: a folder, bytes, or a large file whose byte at `i` is
/// [`pattern`] (nothing that big is ever held in memory).
#[derive(Clone)]
enum Content {
    Dir,
    Bytes(Vec<u8>),
    Pattern(u64),
}

fn pattern(i: u64) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 13) ^ (i >> 32)) as u8
}

fn size(c: &Content) -> u64 {
    match c {
        Content::Dir => 0,
        Content::Bytes(b) => b.len() as u64,
        Content::Pattern(n) => *n,
    }
}

/// The lazy backend: hands the offer to the test.
struct Capture(Arc<Mutex<Option<RemoteOffer>>>);

impl ClipboardBackend for Capture {
    fn sequence(&mut self) -> u32 {
        0
    }
    fn read_text(&mut self) -> Option<String> {
        None
    }
    fn write_text(&mut self, _: &str) -> bool {
        false
    }
    fn supports_files(&self) -> bool {
        true
    }
    fn lazy_remote(&self) -> bool {
        true
    }
    fn remote_offer(&mut self, offer: Option<RemoteOffer>) {
        *self.0.lock().unwrap() = offer;
    }
}

/// The server: what its clipboard holds.
#[derive(Clone, Default)]
struct Server {
    text: Option<String>,
    dib: Option<Vec<u8>>,
    png: Option<Vec<u8>>,
    files: Vec<(String, Content)>,
}

struct Harness {
    offer: RemoteOffer,
    stop: Arc<AtomicBool>,
    /// Requests the server answered.
    requests: Arc<AtomicUsize>,
    /// Largest number of File Contents Requests seen in one tick.
    pipelined: Arc<AtomicUsize>,
    pump: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(p) = self.pump.take() {
            let _ = p.join();
        }
    }
}

fn serve(server: Server) -> Harness {
    let got = Arc::new(Mutex::new(None));
    let (mut c, h) = rdp::cliprdr(Box::new(Capture(got.clone())));
    h.set_enabled(true);
    let mut out = ChannelOut::default();
    // Server capabilities as Windows sends them (flags 0x3e), Monitor Ready.
    let caps = [
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00,
    ];
    c.process(&caps, &mut out).unwrap();
    c.process(&pdu(1, 0, &[]), &mut out).unwrap();
    let mut formats: Vec<(u32, &str)> = Vec::new();
    if !server.files.is_empty() {
        formats.push((FILES_ID, "FileGroupDescriptorW"));
    }
    if server.text.is_some() {
        formats.push((13, ""));
    }
    if server.png.is_some() {
        formats.push((PNG_ID, "PNG"));
    }
    if server.dib.is_some() {
        formats.push((8, ""));
    }
    c.process(&format_list(&formats, true), &mut out).unwrap();
    let offer = got.lock().unwrap().clone().expect("an offer");
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let pipelined = Arc::new(AtomicUsize::new(0));
    let (s, r, p) = (stop.clone(), requests.clone(), pipelined.clone());
    let pump = std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            let mut out = ChannelOut::default();
            c.tick(&mut out).unwrap();
            let msgs = out.take();
            let ranges = msgs
                .iter()
                .filter(|m| m.first() == Some(&(CB_FILECONTENTS_REQUEST as u8)))
                .count();
            p.fetch_max(ranges, Ordering::Relaxed);
            for m in msgs {
                let reply = answer(&server, &m);
                r.fetch_add(1, Ordering::Relaxed);
                let mut out = ChannelOut::default();
                c.process(&reply, &mut out).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    Harness {
        offer,
        stop,
        requests,
        pipelined,
        pump: Some(pump),
    }
}

/// rdpclip's answer to one request.
fn answer(server: &Server, msg: &[u8]) -> Vec<u8> {
    let (t, _, body) = parse_header(msg).unwrap();
    let fail = pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[]);
    if t == CB_FORMAT_DATA_REQUEST {
        let id = u32::from_le_bytes(body[..4].try_into().unwrap());
        let data = match id {
            13 => server.text.as_ref().map(|t| {
                t.encode_utf16()
                    .chain(Some(0))
                    .flat_map(u16::to_le_bytes)
                    .collect()
            }),
            8 => server.dib.clone(),
            PNG_ID => server.png.clone(),
            FILES_ID => {
                let list: Vec<FileDescriptor> = server
                    .files
                    .iter()
                    .map(|(name, c)| FileDescriptor {
                        flags: FD_ATTRIBUTES | FD_FILESIZE,
                        attributes: if matches!(c, Content::Dir) {
                            0x10
                        } else {
                            0x20
                        },
                        write_time: 0,
                        size: size(c),
                        name: name.clone(),
                    })
                    .collect();
                Some(encode_file_list(&list))
            }
            _ => None,
        };
        return match data {
            Some(d) => pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, &d),
            None => fail,
        };
    }
    assert_eq!(t, CB_FILECONTENTS_REQUEST, "unexpected request {t}");
    let req = parse_file_contents_request(body).unwrap();
    let (_, c) = &server.files[req.lindex as usize];
    if req.flags == 1 {
        return file_contents_response(req.stream_id, Some(&size(c).to_le_bytes()));
    }
    let len = size(c);
    let from = req.position.min(len);
    let to = (req.position + req.requested as u64).min(len);
    let data: Vec<u8> = match c {
        Content::Dir => return file_contents_response(req.stream_id, None),
        Content::Bytes(b) => b[from as usize..to as usize].to_vec(),
        Content::Pattern(_) => (from..to).map(pattern).collect(),
    };
    file_contents_response(req.stream_id, Some(&data))
}

/// COM on the test thread (an STA, like the clipboard thread).
struct Com;

impl Com {
    fn init() -> Com {
        // SAFETY: balanced in Drop on the same thread.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().unwrap() };
        Com
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: matches the CoInitializeEx above.
        unsafe { CoUninitialize() };
    }
}

fn get(obj: &IDataObject, cf: u16, tymed: i32, lindex: i32) -> windows::core::Result<STGMEDIUM> {
    let mut f = etc(cf, tymed);
    f.lindex = lindex;
    // SAFETY: a valid FORMATETC.
    unsafe { obj.GetData(&f) }
}

fn global_bytes(m: &mut STGMEDIUM) -> Vec<u8> {
    // SAFETY: an HGLOBAL medium from GetData, released here.
    unsafe {
        let h: HGLOBAL = m.u.hGlobal;
        let n = GlobalSize(h);
        let p = GlobalLock(h) as *const u8;
        let v = std::slice::from_raw_parts(p, n).to_vec();
        let _ = GlobalUnlock(h);
        ReleaseStgMedium(m);
        v
    }
}

fn stream_of(m: &mut STGMEDIUM) -> IStream {
    // SAFETY: an IStream medium from GetData; our clone keeps the stream.
    unsafe {
        let s = (*m.u.pstm).clone().unwrap();
        ReleaseStgMedium(m);
        s
    }
}

/// Reads a stream to its end in `chunk`-byte calls, like Explorer does.
fn read_all(s: &IStream, chunk: usize) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0u8; chunk];
    loop {
        let mut n = 0u32;
        // SAFETY: our buffer and out count.
        let hr = unsafe { s.Read(buf.as_mut_ptr().cast(), chunk as u32, Some(&mut n)) };
        assert!(hr.is_ok(), "read failed: {hr:?}");
        if n == 0 {
            return all;
        }
        all.extend_from_slice(&buf[..n as usize]);
    }
}

fn tree() -> Vec<(String, Content)> {
    vec![
        ("folder".into(), Content::Dir),
        ("folder\\a.txt".into(), Content::Bytes(b"hello".to_vec())),
        ("folder\\empty.txt".into(), Content::Bytes(Vec::new())),
        ("folder\\sub".into(), Content::Dir),
        (
            "folder\\sub\\big.bin".into(),
            Content::Pattern(3 * MIB + 12_345),
        ),
        ("top.txt".into(), Content::Bytes(b"top".to_vec())),
    ]
}

#[test]
fn a_folder_tree_is_pasted_from_streams() {
    let _com = Com::init();
    let h = serve(Server {
        files: tree(),
        ..Server::default()
    });
    let (obj, _cache) = RemoteData::create(h.offer.clone());
    let cf = Formats::get();
    assert_eq!(
        h.requests.load(Ordering::Relaxed),
        0,
        "nothing fetched on copy"
    );
    // The descriptor: FILEGROUPDESCRIPTORW with the server's names and sizes.
    let mut m = get(&obj, cf.descriptor, TYMED_HGLOBAL.0, -1).unwrap();
    let group = global_bytes(&mut m);
    assert_eq!(
        size_of::<windows::Win32::UI::Shell::FILEDESCRIPTORW>(),
        592,
        "same layout as the RDP file descriptor"
    );
    let list = rdp::cliprdr::files::parse_file_list(&group).unwrap();
    let names: Vec<&str> = list.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "folder",
            "folder\\a.txt",
            "folder\\empty.txt",
            "folder\\sub",
            "folder\\sub\\big.bin",
            "top.txt"
        ]
    );
    assert!(list.iter().all(|f| f.flags & FD_SHOWPROGRESSUI != 0));
    assert!(list[0].is_dir() && list[3].is_dir());
    // Each file through its stream.
    for (i, (_, content)) in tree().iter().enumerate() {
        let r = get(&obj, cf.contents, TYMED_ISTREAM.0, i as i32);
        match content {
            Content::Dir => assert!(r.is_err(), "folders have no contents"),
            Content::Bytes(b) => assert_eq!(&read_all(&stream_of(&mut r.unwrap()), 65_536), b),
            Content::Pattern(n) => {
                let got = read_all(&stream_of(&mut r.unwrap()), 65_536);
                assert_eq!(got.len() as u64, *n);
                assert!(got.iter().enumerate().all(|(i, &b)| b == pattern(i as u64)));
            }
        }
    }
    assert!(
        h.pipelined.load(Ordering::Relaxed) > 1,
        "ranges are requested ahead of the reader"
    );
}

#[test]
fn files_over_4_gib_are_read_at_their_offsets() {
    let _com = Com::init();
    let big = 5 * (1u64 << 30) + 7;
    let h = serve(Server {
        files: vec![("huge.iso".into(), Content::Pattern(big))],
        ..Server::default()
    });
    let (obj, _cache) = RemoteData::create(h.offer.clone());
    let cf = Formats::get();
    let s = stream_of(&mut get(&obj, cf.contents, TYMED_ISTREAM.0, 0).unwrap());
    let mut st = STATSTG::default();
    // SAFETY: our out structure; no name asked for.
    unsafe { s.Stat(&mut st, STATFLAG_NONAME).unwrap() };
    assert_eq!(st.cbSize, big);
    for at in [(1u64 << 32) - 3, (1u64 << 32) + 100, big - 10] {
        let mut pos = 0u64;
        // SAFETY: plain seek with our out value.
        unsafe { s.Seek(at as i64, STREAM_SEEK_SET, Some(&mut pos)).unwrap() };
        assert_eq!(pos, at);
        let mut buf = [0u8; 64];
        let mut n = 0u32;
        // SAFETY: our buffer and out count.
        let hr = unsafe { s.Read(buf.as_mut_ptr().cast(), 64, Some(&mut n)) };
        assert!(hr.is_ok());
        let want = (big - at).min(64) as usize;
        assert_eq!(n as usize, want);
        for (k, &b) in buf[..want].iter().enumerate() {
            assert_eq!(b, pattern(at + k as u64), "byte {} after {at}", k);
        }
    }
    // At the end: nothing more.
    let mut n = 1u32;
    let mut buf = [0u8; 8];
    // SAFETY: our buffer and out count.
    let hr = unsafe { s.Read(buf.as_mut_ptr().cast(), 8, Some(&mut n)) };
    assert!(hr.is_ok() && n == 0);
}

#[test]
fn text_and_images_are_fetched_once_and_kept() {
    let _com = Com::init();
    let h = serve(Server {
        text: Some("héllo".into()),
        dib: Some(vec![40, 0, 0, 0, 9, 9]),
        png: Some(b"\x89PNG-data".to_vec()),
        ..Server::default()
    });
    let (obj, cache) = RemoteData::create(h.offer.clone());
    let cf = Formats::get();
    let text = global_bytes(&mut get(&obj, CF_UNICODETEXT, TYMED_HGLOBAL.0, -1).unwrap());
    assert_eq!(rdp::cliprdr::decode_text(&text), "héllo");
    let before = h.requests.load(Ordering::Relaxed);
    let again = global_bytes(&mut get(&obj, CF_UNICODETEXT, TYMED_HGLOBAL.0, -1).unwrap());
    assert_eq!(again, text);
    assert_eq!(
        h.requests.load(Ordering::Relaxed),
        before,
        "served from the cache"
    );
    assert_eq!(
        global_bytes(&mut get(&obj, CF_DIB, TYMED_HGLOBAL.0, -1).unwrap()),
        [40, 0, 0, 0, 9, 9]
    );
    // The offer ends: fetched formats stay, others are gone.
    cache.close();
    assert!(get(&obj, CF_UNICODETEXT, TYMED_HGLOBAL.0, -1).is_ok());
    assert!(get(&obj, CF_DIB, TYMED_HGLOBAL.0, -1).is_ok());
    assert!(get(&obj, cf.png, TYMED_HGLOBAL.0, -1).is_err());
}

#[test]
fn only_offered_formats_are_listed_and_served() {
    let _com = Com::init();
    let h = serve(Server {
        text: Some("x".into()),
        ..Server::default()
    });
    let (obj, _cache) = RemoteData::create(h.offer.clone());
    let cf = Formats::get();
    // SAFETY: valid FORMATETCs.
    unsafe {
        assert_eq!(
            obj.QueryGetData(&etc(CF_UNICODETEXT, TYMED_HGLOBAL.0)),
            S_OK
        );
        assert_eq!(
            obj.QueryGetData(&etc(CF_DIB, TYMED_HGLOBAL.0)),
            DV_E_FORMATETC
        );
        assert_eq!(
            obj.QueryGetData(&etc(cf.contents, TYMED_ISTREAM.0)),
            DV_E_FORMATETC
        );
        assert_eq!(
            obj.QueryGetData(&etc(CF_UNICODETEXT, TYMED_ISTREAM.0)),
            DV_E_TYMED
        );
        let e = obj.EnumFormatEtc(DATADIR_GET.0 as u32).unwrap();
        let mut got = [FORMATETC::default(); 4];
        let mut n = 0u32;
        let _ = e.Next(&mut got, Some(&mut n));
        assert_eq!(n, 1);
        assert_eq!(got[0].cfFormat, CF_UNICODETEXT);
    }
}

#[test]
fn unsafe_names_are_refused() {
    let _com = Com::init();
    let h = serve(Server {
        files: vec![("..\\evil.txt".into(), Content::Bytes(b"x".to_vec()))],
        ..Server::default()
    });
    let (obj, _cache) = RemoteData::create(h.offer.clone());
    let cf = Formats::get();
    assert!(get(&obj, cf.descriptor, TYMED_HGLOBAL.0, -1).is_err());
    assert!(get(&obj, cf.contents, TYMED_ISTREAM.0, 0).is_err());
}

#[test]
fn an_outdated_offer_fails_fast() {
    let _com = Com::init();
    let h = serve(Server {
        files: tree(),
        ..Server::default()
    });
    let (obj, cache) = RemoteData::create(h.offer.clone());
    cache.close();
    let cf = Formats::get();
    let t = std::time::Instant::now();
    assert!(get(&obj, cf.descriptor, TYMED_HGLOBAL.0, -1).is_err());
    assert!(t.elapsed() < Duration::from_secs(1));
}

#[test]
fn the_server_reads_virtual_files_of_this_pcs_clipboard() {
    // Our own data object stands in for a zip folder's files on this PC's
    // clipboard (the real clipboard is never touched here).
    let _com = Com::init();
    let h = serve(Server {
        files: tree(),
        ..Server::default()
    });
    let (obj, _cache) = RemoteData::create(h.offer.clone());
    let mut cache = None;
    let list = read_virtual(&obj, 1, LocalRead::List, &mut cache).unwrap();
    let list = rdp::cliprdr::files::parse_file_list(&list).unwrap();
    assert_eq!(list.len(), tree().len());
    // The big file (index 4) in two ranges, one after a seek back.
    let tail = read_virtual(
        &obj,
        1,
        LocalRead::Range {
            lindex: 4,
            position: 3 * MIB,
            size: 1 << 20,
        },
        &mut cache,
    )
    .unwrap();
    assert_eq!(tail.len(), 12_345, "short at the end");
    assert!(
        tail.iter()
            .enumerate()
            .all(|(i, &b)| b == pattern(3 * MIB + i as u64))
    );
    let head = read_virtual(
        &obj,
        1,
        LocalRead::Range {
            lindex: 4,
            position: 10,
            size: 100,
        },
        &mut cache,
    )
    .unwrap();
    assert!(
        head.iter()
            .enumerate()
            .all(|(i, &b)| b == pattern(10 + i as u64))
    );
    // Another file: its own stream.
    let a = read_virtual(
        &obj,
        1,
        LocalRead::Range {
            lindex: 1,
            position: 0,
            size: 64,
        },
        &mut cache,
    )
    .unwrap();
    assert_eq!(a, b"hello");
}
