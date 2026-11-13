use super::*;
use std::sync::Mutex;

/// Fake system clipboard, shared with the test through an Arc.
#[derive(Default)]
struct Fake {
    seq: u32,
    text: Option<String>,
    writes: Vec<String>,
    /// Number of upcoming write_text calls that fail (clipboard busy).
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
        f.seq += 1; // EmptyClipboard bumps the sequence even on failure
        if f.busy > 0 {
            f.busy -= 1;
            return false;
        }
        f.seq += 1;
        f.text = Some(text.to_string());
        f.writes.push(text.to_string());
        true
    }
}

impl Fake {
    /// A local copy by another application.
    fn user_copies(&mut self, text: &str) {
        self.seq += 1;
        self.text = Some(text.to_string());
    }
}

// MS-RDPECLIP 4.1.1 Server Clipboard Capabilities PDU.
const SERVER_CAPS: [u8; 24] = [
    0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
];
// MS-RDPECLIP 4.1.2 Server Monitor Ready PDU.
const MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
// MS-RDPECLIP 4.1.6 Format List Response PDU (CB_RESPONSE_OK).
const LIST_RESPONSE_OK: [u8; 8] = [0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
// MS-RDPECLIP 4.4.1 Format Data Request PDU (CF_UNICODETEXT).
const DATA_REQUEST_TEXT: [u8; 12] = [
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
];
// MS-RDPECLIP 4.4.2 Format Data Response PDU ("hello world").
const DATA_RESPONSE_HELLO: [u8; 32] = [
    0x05, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00,
    0x6f, 0x00, 0x20, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x00, 0x00,
];
// MS-RDPECLIP 4.3.1 Lock Clipboard Data PDU.
const LOCK: [u8; 12] = [
    0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
];
const DATA_RESPONSE_FAIL: [u8; 8] = [0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
/// Client Clipboard Capabilities: MS-RDPECLIP 4.1.3 with generalFlags
/// 0x02 (long names only; the example also has the file-stream flags).
const CLIENT_CAPS: [u8; 24] = [
    0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
];
/// Long-name Format List with CF_UNICODETEXT and an empty name.
const LIST_TEXT_LONG: [u8; 14] = [
    0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const LIST_EMPTY: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// MS-RDPECLIP 4.2.1 Format List PDU (long names, includes CF_UNICODETEXT).
fn spec_format_list_421() -> Vec<u8> {
    let hex = "            02 00 00 00 e0 00 00 00 8a c0 00 00 52 00 69 00             63 00 68 00 20 00 54 00 65 00 78 00 74 00 20 00             46 00 6f 00 72 00 6d 00 61 00 74 00 00 00 45 c1             00 00 52 00 69 00 63 00 68 00 20 00 54 00 65 00             78 00 74 00 20 00 46 00 6f 00 72 00 6d 00 61 00             74 00 20 00 57 00 69 00 74 00 68 00 6f 00 75 00             74 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00             73 00 00 00 43 c1 00 00 52 00 54 00 46 00 20 00             41 00 73 00 20 00 54 00 65 00 78 00 74 00 00 00             01 00 00 00 00 00 0d 00 00 00 00 00 04 c0 00 00             4e 00 61 00 74 00 69 00 76 00 65 00 00 00 0e c0             00 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00             44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00             6f 00 72 00 00 00 03 00 00 00 00 00 10 00 00 00             00 00 07 00 00 00 00 00";
    let hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn setup() -> (Cliprdr, ClipboardHandle, Arc<Mutex<Fake>>) {
    let fake = Arc::new(Mutex::new(Fake::default()));
    let (c, h) = cliprdr(Box::new(Mock(fake.clone())));
    (c, h, fake)
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

/// Session after the initialization sequence, with sharing as given.
fn connected(on: bool) -> (Cliprdr, ClipboardHandle, Arc<Mutex<Fake>>) {
    let (mut c, h, fake) = setup();
    h.set_enabled(on);
    assert!(feed(&mut c, &SERVER_CAPS).is_empty());
    feed(&mut c, &MONITOR_READY);
    assert!(tick(&mut c).is_empty());
    (c, h, fake)
}

#[test]
fn channel_definition() {
    let (c, h, _) = setup();
    assert_eq!(c.name(), "cliprdr");
    // Same as mstsc (INITIALIZED | ENCRYPT_RDP | COMPRESS_RDP | SHOW_PROTOCOL).
    assert_eq!(c.options(), 0xC0A0_0000);
    assert!(!h.enabled(), "sharing starts off");
    fn send_sync<T: Send + Sync + Clone>(_: &T) {}
    send_sync(&h);
}

#[test]
fn capabilities_bytes() {
    assert_eq!(capabilities(CB_USE_LONG_FORMAT_NAMES), CLIENT_CAPS);
    let (t, f, body) = parse_header(&SERVER_CAPS).unwrap();
    assert_eq!((t, f), (CB_CLIP_CAPS, 0));
    assert_eq!(parse_capabilities(body).unwrap(), 0x0e);
    // No general set: default flags 0 (2.2.2.1.1.1).
    assert_eq!(parse_capabilities(&[0, 0, 0, 0]).unwrap(), 0);
}

#[test]
fn monitor_ready_sends_caps_then_empty_list_when_off() {
    let (mut c, _h, fake) = setup();
    fake.lock().unwrap().user_copies("local");
    feed(&mut c, &SERVER_CAPS);
    let out = feed(&mut c, &MONITOR_READY);
    assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_EMPTY.to_vec()]);
}

#[test]
fn monitor_ready_announces_text_when_on() {
    let (mut c, h, fake) = setup();
    h.set_enabled(true);
    fake.lock().unwrap().user_copies("local");
    feed(&mut c, &SERVER_CAPS);
    let out = feed(&mut c, &MONITOR_READY);
    assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_TEXT_LONG.to_vec()]);
    // Nothing to re-announce on the next tick.
    assert!(tick(&mut c).is_empty());
}

#[test]
fn monitor_ready_on_without_text_sends_empty_list() {
    let (mut c, h, _) = setup();
    h.set_enabled(true);
    feed(&mut c, &SERVER_CAPS);
    let out = feed(&mut c, &MONITOR_READY);
    assert_eq!(out, vec![CLIENT_CAPS.to_vec(), LIST_EMPTY.to_vec()]);
}

#[test]
fn short_names_without_server_long_name_flag() {
    let (mut c, h, fake) = setup();
    h.set_enabled(true);
    fake.lock().unwrap().user_copies("x");
    // Server capabilities without CB_USE_LONG_FORMAT_NAMES.
    let mut caps = SERVER_CAPS;
    caps[20] = 0x0c;
    feed(&mut c, &caps);
    let out = feed(&mut c, &MONITOR_READY);
    let mut want = vec![
        0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0d, 0, 0, 0,
    ];
    want.extend([0u8; 32]);
    assert_eq!(out[1], want);
}

#[test]
fn format_list_encoding_long_and_short() {
    // Long: the first entries of MS-RDPECLIP 4.1.5.
    let list = format_list(&[(0xc004, "Native"), (3, ""), (8, ""), (17, "")], true);
    let spec_415: [u8; 44] = [
        0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x4e, 0x00, 0x61,
        0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(list, spec_415);
    // Short: Unicode names in 32-byte blocks, truncated to 15 units + NUL.
    let short = format_list(
        &[(0xc004, "Native"), (0xc0ff, "ABCDEFGHIJKLMNOPQRS")],
        false,
    );
    assert_eq!(short.len(), 8 + 72);
    assert_eq!(&short[..8], &[0x02, 0, 0, 0, 72, 0, 0, 0]);
    assert_eq!(&short[8..12], &[0x04, 0xc0, 0, 0]);
    assert_eq!(&short[12..24], &utf16le("Native")[..]);
    assert!(short[24..44].iter().all(|&b| b == 0));
    assert_eq!(&short[48..78], &utf16le("ABCDEFGHIJKLMNO")[..]);
    assert_eq!(&short[78..80], &[0, 0]);
    let (_, f, body) = parse_header(&short).unwrap();
    assert_eq!(
        parse_format_list(f, body, false).unwrap(),
        vec![
            (0xc004, "Native".into()),
            (0xc0ff, "ABCDEFGHIJKLMNO".into())
        ]
    );
}

#[test]
fn format_list_parsing() {
    let msg = spec_format_list_421();
    assert_eq!(msg.len(), 8 + 0xe0);
    let (t, f, body) = parse_header(&msg).unwrap();
    assert_eq!(t, CB_FORMAT_LIST);
    let list = parse_format_list(f, body, true).unwrap();
    let ids: Vec<u32> = list.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        ids,
        [0xc08a, 0xc145, 0xc143, 1, 13, 0xc004, 0xc00e, 3, 16, 7]
    );
    assert_eq!(list[1].1, "Rich Text Format Without Objects");
    assert_eq!(list[6].1, "Object Descriptor");
    // ASCII short names (CB_ASCII_NAMES).
    let mut body = vec![0x04, 0xc0, 0, 0];
    body.extend(b"Native");
    body.resize(36, 0);
    assert_eq!(
        parse_format_list(CB_ASCII_NAMES, &body, false).unwrap(),
        vec![(0xc004, "Native".into())]
    );
    // Malformed data is an error, never a panic.
    assert!(parse_format_list(0, &body[..35], false).is_err());
    assert!(parse_format_list(0, &[13, 0, 0, 0, b'a', 0], true).is_err());
    assert!(parse_format_list(0, &[13, 0], true).is_err());
    assert!(parse_header(&[0x02, 0, 0, 0, 9, 0, 0, 0, 1]).is_err());
}

#[test]
fn data_request_and_response_bytes() {
    assert_eq!(format_data_request(CF_UNICODETEXT), DATA_REQUEST_TEXT);
    assert_eq!(
        pdu(
            CB_FORMAT_DATA_RESPONSE,
            CB_RESPONSE_OK,
            &utf16le_z("hello world")
        ),
        DATA_RESPONSE_HELLO
    );
    let (_, _, body) = parse_header(&DATA_RESPONSE_HELLO).unwrap();
    assert_eq!(decode_text(body), "hello world");
    assert_eq!(decode_text(&[0x41, 0x00, 0x42]), "A");
}

#[test]
fn remote_text_reaches_local_backend() {
    let (mut c, _h, fake) = connected(true);
    let out = feed(&mut c, &spec_format_list_421());
    assert_eq!(
        out,
        vec![LIST_RESPONSE_OK.to_vec(), DATA_REQUEST_TEXT.to_vec()]
    );
    assert!(feed(&mut c, &DATA_RESPONSE_HELLO).is_empty());
    assert_eq!(fake.lock().unwrap().writes, ["hello world"]);
    // No echo: our own write is not announced back.
    assert!(tick(&mut c).is_empty());
    assert!(tick(&mut c).is_empty());
}

#[test]
fn remote_list_without_text_is_acknowledged_only() {
    let (mut c, _h, _) = connected(true);
    let out = feed(&mut c, &format_list(&[(0xc004, "Native")], true));
    assert_eq!(out, vec![LIST_RESPONSE_OK.to_vec()]);
}

#[test]
fn local_change_is_announced_and_served() {
    let (mut c, _h, fake) = connected(true);
    fake.lock().unwrap().user_copies("hello world");
    assert_eq!(tick(&mut c), vec![LIST_TEXT_LONG.to_vec()]);
    assert!(tick(&mut c).is_empty(), "announced once");
    assert!(feed(&mut c, &LIST_RESPONSE_OK).is_empty());
    let out = feed(&mut c, &DATA_REQUEST_TEXT);
    assert_eq!(out, vec![DATA_RESPONSE_HELLO.to_vec()]);
    // Unknown formats fail.
    let out = feed(&mut c, &format_data_request(0xc004));
    assert_eq!(out, vec![DATA_RESPONSE_FAIL.to_vec()]);
}

#[test]
fn sharing_off_blocks_both_directions() {
    let (mut c, h, fake) = connected(true);
    h.set_enabled(false);
    assert_eq!(
        tick(&mut c),
        vec![LIST_EMPTY.to_vec()],
        "withdrawn on switch off"
    );
    // Remote list: acknowledged, but no request and no local write.
    let out = feed(&mut c, &spec_format_list_421());
    assert_eq!(out, vec![LIST_RESPONSE_OK.to_vec()]);
    assert!(feed(&mut c, &DATA_RESPONSE_HELLO).is_empty());
    // Local copies are neither announced nor served.
    fake.lock().unwrap().user_copies("secret");
    assert!(tick(&mut c).is_empty());
    assert_eq!(
        feed(&mut c, &DATA_REQUEST_TEXT),
        vec![DATA_RESPONSE_FAIL.to_vec()]
    );
    assert!(fake.lock().unwrap().writes.is_empty());
}

#[test]
fn response_after_switch_off_is_not_written() {
    let (mut c, h, fake) = connected(true);
    feed(&mut c, &spec_format_list_421());
    h.set_enabled(false);
    tick(&mut c);
    feed(&mut c, &DATA_RESPONSE_HELLO);
    assert!(fake.lock().unwrap().writes.is_empty());
}

#[test]
fn switching_on_announces_local_text() {
    let (mut c, h, fake) = connected(false);
    fake.lock().unwrap().user_copies("hello world");
    assert!(tick(&mut c).is_empty());
    h.set_enabled(true);
    assert_eq!(tick(&mut c), vec![LIST_TEXT_LONG.to_vec()]);
    assert!(
        tick(&mut c).is_empty(),
        "the change made while off is not sent twice"
    );
    assert_eq!(
        feed(&mut c, &DATA_REQUEST_TEXT),
        vec![DATA_RESPONSE_HELLO.to_vec()]
    );
}

#[test]
fn busy_clipboard_write_is_retried_on_tick() {
    let (mut c, _h, fake) = connected(true);
    fake.lock().unwrap().busy = 2;
    feed(&mut c, &spec_format_list_421());
    feed(&mut c, &DATA_RESPONSE_HELLO);
    assert!(fake.lock().unwrap().writes.is_empty());
    assert!(tick(&mut c).is_empty());
    assert!(tick(&mut c).is_empty());
    assert_eq!(fake.lock().unwrap().writes, ["hello world"]);
    assert!(tick(&mut c).is_empty(), "no echo after a retried write");
}

#[test]
fn nothing_sent_before_monitor_ready() {
    let (mut c, h, fake) = setup();
    h.set_enabled(true);
    fake.lock().unwrap().user_copies("x");
    assert!(tick(&mut c).is_empty());
    // Lock / Unlock are accepted and ignored.
    assert!(feed(&mut c, &LOCK).is_empty());
    let mut unlock = LOCK;
    unlock[0] = 0x0b;
    assert!(feed(&mut c, &unlock).is_empty());
}
