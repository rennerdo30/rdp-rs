//! The server's clipboard on demand (RDP-62, RDP-63) and images.

use super::files::{
    FILECONTENTS_RANGE, FILECONTENTS_SIZE, file_contents_response, parse_file_contents_request,
};
use super::*;
use std::time::Duration;

/// A lazy backend: records offers; the local clipboard holds what the
/// test says.
#[derive(Default)]
struct Lazy {
    seq: u32,
    have: LocalFormats,
    offers: Vec<Option<RemoteOffer>>,
    /// The local clipboard holds our offer.
    own: bool,
}

struct LazyMock(Arc<Mutex<Lazy>>);

impl ClipboardBackend for LazyMock {
    fn sequence(&mut self) -> u32 {
        self.0.lock().unwrap().seq
    }
    fn read_text(&mut self) -> Option<String> {
        let f = self.0.lock().unwrap();
        f.have.text.then(|| "text".to_string())
    }
    fn write_text(&mut self, _text: &str) -> bool {
        panic!("a lazy backend is never written eagerly");
    }
    fn supports_files(&self) -> bool {
        true
    }
    fn available(&mut self) -> LocalFormats {
        self.0.lock().unwrap().have
    }
    fn read_dib(&mut self) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .have
            .dib
            .then(|| vec![0x28, 0, 0, 0, 1, 2, 3])
    }
    fn read_png(&mut self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().have.png.then(|| b"\x89PNG".to_vec())
    }
    fn lazy_remote(&self) -> bool {
        true
    }
    fn remote_offer(&mut self, offer: Option<RemoteOffer>) {
        let mut f = self.0.lock().unwrap();
        f.own = offer.is_some();
        f.seq += 1; // OleSetClipboard changes the clipboard
        f.offers.push(offer);
    }
    fn owns_clipboard(&mut self) -> bool {
        self.0.lock().unwrap().own
    }
}

// MS-RDPECLIP 4.1.1 Server Clipboard Capabilities PDU (flags 0x0e: long
// names, stream file clip, no file paths).
const SERVER_CAPS: [u8; 24] = [
    0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
];
const MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

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

fn connected() -> (Cliprdr, ClipboardHandle, Arc<Mutex<Lazy>>) {
    let fake = Arc::new(Mutex::new(Lazy::default()));
    let (mut c, h) = cliprdr(Box::new(LazyMock(fake.clone())));
    h.set_enabled(true);
    feed(&mut c, &SERVER_CAPS);
    feed(&mut c, &MONITOR_READY);
    assert!(tick(&mut c).is_empty());
    (c, h, fake)
}

/// A server Format List (long names).
fn server_list(formats: &[(u32, &str)]) -> Vec<u8> {
    format_list(formats, true)
}

const FILES_ID: u32 = 0xc0a1;
const PNG_ID: u32 = 0xc0b2;

fn everything() -> Vec<u8> {
    server_list(&[
        (CF_UNICODETEXT, ""),
        (CF_DIB, ""),
        (PNG_ID, "PNG"),
        (FILES_ID, "FileGroupDescriptorW"),
        (0xc0c0, "HTML Format"),
    ])
}

fn last_offer(fake: &Arc<Mutex<Lazy>>) -> RemoteOffer {
    fake.lock()
        .unwrap()
        .offers
        .last()
        .cloned()
        .flatten()
        .expect("an offer")
}

fn data_response(body: &[u8]) -> Vec<u8> {
    pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, body)
}

const NOW: Duration = Duration::from_millis(0);

#[test]
fn a_server_copy_is_offered_without_fetching_anything() {
    let (mut c, _h, fake) = connected();
    let out = feed(&mut c, &everything());
    assert_eq!(out, vec![pdu(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[])]);
    let offer = last_offer(&fake);
    assert!(offer.text && offer.dib && offer.png && offer.files);
    assert!(offer.source.current());
    assert!(tick(&mut c).is_empty(), "nothing fetched, nothing echoed");
}

#[test]
fn a_paste_fetches_the_format_it_needs() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    let src = last_offer(&fake).source;
    let png = src.data(RemoteFormat::Png);
    let text = src.data(RemoteFormat::Text);
    assert_eq!(
        tick(&mut c),
        vec![
            format_data_request(PNG_ID),
            format_data_request(CF_UNICODETEXT)
        ]
    );
    // Answers come in request order.
    feed(&mut c, &data_response(b"png-bytes"));
    feed(&mut c, &data_response(&utf16le_z("hi")));
    assert_eq!(remote::wait(&png, NOW).as_deref(), Some(&b"png-bytes"[..]));
    assert_eq!(
        decode_text(&remote::wait(&text, NOW).unwrap()),
        "hi".to_string()
    );
}

#[test]
fn a_failed_answer_is_none() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    let dib = last_offer(&fake).source.data(RemoteFormat::Dib);
    assert_eq!(tick(&mut c), vec![format_data_request(CF_DIB)]);
    feed(&mut c, &pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, &[]));
    assert_eq!(remote::wait(&dib, NOW), None);
}

#[test]
fn dibv5_alone_counts_as_an_image() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &server_list(&[(CF_DIBV5, "")]));
    let offer = last_offer(&fake);
    assert!(offer.dib && !offer.text && !offer.files);
    let _p = offer.source.data(RemoteFormat::Dib);
    assert_eq!(tick(&mut c), vec![format_data_request(CF_DIBV5)]);
}

#[test]
fn file_ranges_are_pipelined_and_matched_by_stream() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    let src = last_offer(&fake).source;
    let size = src.size(2);
    let a = src.range(2, 0, 1 << 20);
    let b = src.range(2, 1 << 20, 1 << 20);
    let out = tick(&mut c);
    assert_eq!(out.len(), 3, "all three in flight at once");
    let reqs: Vec<_> = out
        .iter()
        .map(|m| parse_file_contents_request(parse_header(m).unwrap().2).unwrap())
        .collect();
    assert_eq!(reqs[0].flags, FILECONTENTS_SIZE);
    assert_eq!(
        (reqs[1].flags, reqs[1].lindex, reqs[1].position),
        (FILECONTENTS_RANGE, 2, 0)
    );
    assert_eq!(reqs[2].position, 1 << 20);
    // The server may answer out of order: streams sort it out.
    feed(
        &mut c,
        &file_contents_response(reqs[2].stream_id, Some(b"BB")),
    );
    feed(
        &mut c,
        &file_contents_response(reqs[1].stream_id, Some(b"AA")),
    );
    feed(
        &mut c,
        &file_contents_response(reqs[0].stream_id, Some(&(5u64 << 32).to_le_bytes())),
    );
    assert_eq!(remote::wait(&a, NOW).as_deref(), Some(&b"AA"[..]));
    assert_eq!(remote::wait(&b, NOW).as_deref(), Some(&b"BB"[..]));
    let n = u64::from_le_bytes(remote::wait(&size, NOW).unwrap().try_into().unwrap());
    assert_eq!(n, 5 << 32, "sizes over 4 GiB");
}

#[test]
fn a_new_server_copy_outdates_the_old_source() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    let old = last_offer(&fake).source;
    let pending = old.range(0, 0, 10);
    feed(&mut c, &server_list(&[(CF_UNICODETEXT, "")]));
    assert!(!old.current());
    assert_eq!(remote::wait(&pending, NOW), None, "dropped at once");
    assert_eq!(remote::wait(&old.data(RemoteFormat::Text), NOW), None);
    let new = last_offer(&fake);
    assert!(new.text && !new.files);
    // Files are not in the new offer: their requests are not sent.
    let _p = new.source.range(0, 0, 10);
    assert!(tick(&mut c).is_empty());
}

#[test]
fn sharing_off_withdraws_the_offer() {
    let (mut c, h, fake) = connected();
    feed(&mut c, &everything());
    let src = last_offer(&fake).source;
    h.set_enabled(false);
    tick(&mut c);
    assert!(fake.lock().unwrap().offers.last().unwrap().is_none());
    assert!(!src.current());
    assert_eq!(remote::wait(&src.data(RemoteFormat::Text), NOW), None);
    assert!(tick(&mut c).is_empty());
}

#[test]
fn the_end_of_the_session_withdraws_the_offer() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    let src = last_offer(&fake).source;
    drop(c);
    assert!(fake.lock().unwrap().offers.last().unwrap().is_none());
    assert_eq!(remote::wait(&src.data(RemoteFormat::Text), NOW), None);
}

#[test]
fn a_server_copy_with_nothing_usable_withdraws_the_earlier_one() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    feed(&mut c, &server_list(&[(0xc0c0, "HTML Format")]));
    assert!(fake.lock().unwrap().offers.last().unwrap().is_none());
}

#[test]
fn our_own_offer_is_not_announced_back() {
    let (mut c, _h, fake) = connected();
    feed(&mut c, &everything());
    assert!(tick(&mut c).is_empty());
    // Another program copies: that is announced.
    {
        let mut f = fake.lock().unwrap();
        f.own = false;
        f.seq += 1;
        f.have.text = true;
    }
    assert_eq!(
        tick(&mut c),
        vec![format_list(&[(CF_UNICODETEXT, "")], true)]
    );
}

#[test]
fn files_are_not_offered_without_stream_file_clip() {
    let fake = Arc::new(Mutex::new(Lazy::default()));
    let (mut c, h) = cliprdr(Box::new(LazyMock(fake.clone())));
    h.set_enabled(true);
    let mut caps = SERVER_CAPS;
    caps[20] = 0x02; // long names only
    feed(&mut c, &caps);
    feed(&mut c, &MONITOR_READY);
    feed(&mut c, &everything());
    let offer = last_offer(&fake);
    assert!(offer.text && !offer.files);
}

#[test]
fn a_local_image_is_announced_as_an_image_not_text() {
    let (mut c, _h, fake) = connected();
    {
        let mut f = fake.lock().unwrap();
        f.seq += 1;
        f.have = LocalFormats {
            dib: true,
            png: true,
            ..LocalFormats::default()
        };
    }
    assert_eq!(
        tick(&mut c),
        vec![format_list(&[(CF_DIB, ""), (LOCAL_PNG_ID, "PNG")], true)]
    );
    let req = pdu(CB_FORMAT_DATA_REQUEST, 0, &CF_DIB.to_le_bytes());
    assert_eq!(
        feed(&mut c, &req),
        vec![pdu(
            CB_FORMAT_DATA_RESPONSE,
            CB_RESPONSE_OK,
            &[0x28, 0, 0, 0, 1, 2, 3]
        )]
    );
    let req = pdu(CB_FORMAT_DATA_REQUEST, 0, &LOCAL_PNG_ID.to_le_bytes());
    assert_eq!(
        feed(&mut c, &req),
        vec![pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, b"\x89PNG")]
    );
}

#[test]
fn nothing_on_the_local_clipboard_announces_an_empty_list() {
    let (mut c, _h, fake) = connected();
    fake.lock().unwrap().seq += 1;
    assert_eq!(tick(&mut c), vec![format_list(&[], true)]);
}
