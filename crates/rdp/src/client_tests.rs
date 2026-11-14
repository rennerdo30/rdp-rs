//! Session-loop tests over a loopback TCP pair: the auto-reconnect cookie is
//! stored from a Save Session Info PDU, and a closed session reports whether
//! it may be resumed (MS-RDPBCGR 5.5).

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use super::*;

/// A client in the session loop, plus the server end of its socket.
fn session() -> (Client, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut f = Framer::new(sock);
    f.set_read_timeout(Duration::from_millis(20)).unwrap();
    let client = Client {
        f,
        user_id: 1007,
        io_channel: 1003,
        share_id: 0x0001_03ea,
        keyboard_layout: 0x409,
        color_depth: 32,
        fb: Framebuffer::new(4, 4),
        fastpath: Reassembler::default(),
        bulk: Decompressor::default(),
        info: ConnectionInfo {
            protocol: x224::PROTOCOL_HYBRID,
            certificate_sha256: [0; 32],
            gateway_certificate_sha256: None,
            server_rdp_version: 0x0008_0004,
            width: 4,
            height: 4,
            bpp: 32,
        },
        active: true,
        last_error_info: 0,
        heartbeat: None,
        last_seen: std::time::Instant::now(),
        channels: Vec::new(),
        pointers: PointerCache::default(),
        arc_cookie: None,
        gfx: None,
        monitor_layout: Vec::new(),
        redirection: None,
        rail: None,
        message_channel: None,
        autodetect: AutoDetect::default(),
        host: "broker.example".into(),
        follow: false,
        surface: None,
    };
    (client, server)
}

/// Polls until the session reports its end (bounded).
fn poll_until_closed(client: &mut Client) -> CloseReason {
    for _ in 0..100 {
        if let Some(c) = client.poll(Duration::from_millis(20)).unwrap().closed {
            return c;
        }
    }
    panic!("session did not close");
}

/// MS-RDPBCGR 4.3.3 (decrypted): Save Session Info with an auto-reconnect cookie.
fn save_session_info_pdu(logon_id: u8) -> Vec<u8> {
    let mut p = vec![
        0x76, 0x02, 0x17, 0x00, 0xea, 0x03, 0xea, 0x03, 0x02, 0x00, 0x00, 0x01, 0x76, 0x02, 0x26,
        0x00, 0x00, 0x00, // share control + share data header
        0x03, 0x00, 0x00, 0x00, 0x26, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, logon_id, 0x00, 0x00, 0x00,
    ];
    p.extend([
        0xa8, 0x02, 0xe7, 0x25, 0xe2, 0x4c, 0x82, 0xb7, 0x52, 0xa5, 0x53, 0x50, 0x34, 0x98, 0xa1,
        0xa8,
    ]);
    p.extend([0u8; 570]);
    assert_eq!(p.len(), 0x276);
    p
}

#[test]
fn stores_the_latest_auto_reconnect_cookie() {
    let (mut client, _server) = session();
    assert!(client.auto_reconnect_cookie().is_none());
    let mut out = PollOutcome::default();
    client
        .handle_share(&save_session_info_pdu(2), &mut out)
        .unwrap();
    let cookie = client.auto_reconnect_cookie().unwrap();
    assert_eq!(cookie.logon_id, 2);
    assert_eq!(cookie.random[0], 0xa8);
    // The hourly refresh (5.5) replaces the stored cookie.
    client
        .handle_share(&save_session_info_pdu(9), &mut out)
        .unwrap();
    assert_eq!(client.auto_reconnect_cookie().unwrap().logon_id, 9);
    // A malformed Save Session Info PDU never ends the session or drops the cookie.
    let mut bad = save_session_info_pdu(3);
    bad[32] = 0x1d; // ARC_SC cbLen
    client.handle_share(&bad, &mut out).unwrap();
    assert_eq!(client.auto_reconnect_cookie().unwrap().logon_id, 9);
    assert!(out.closed.is_none());
}

#[test]
fn eof_without_error_info_is_a_network_drop() {
    let (mut client, server) = session();
    drop(server);
    let closed = poll_until_closed(&mut client);
    assert!(closed.reconnectable, "{closed:?}");
    assert_eq!(closed.error_info, 0);
    assert_eq!(closed.text, "connection closed by server");
}

#[test]
fn eof_after_error_info_is_a_server_end() {
    let (mut client, server) = session();
    // Set Error Info PDU (2.2.5.1.1): ERRINFO_LOGOFF_BY_USER, then the socket closes.
    let pdu = pdu::share_data(
        0x0001_03ea,
        0x03ea,
        pdu::PDUTYPE2_SET_ERROR_INFO,
        &[0x0c, 0, 0, 0],
    );
    let mut out = PollOutcome::default();
    client.handle_share(&pdu, &mut out).unwrap();
    drop(server);
    let closed = poll_until_closed(&mut client);
    assert!(!closed.reconnectable, "{closed:?}");
    assert_eq!(closed.error_info, 0x0c);
    assert!(closed.text.contains("logged off by the user"), "{closed:?}");
}

#[test]
fn disconnect_provider_ultimatum_is_a_server_end() {
    let (mut client, mut server) = session();
    server
        .write_all(&x224::data(&mcs::disconnect_provider_ultimatum()))
        .unwrap();
    let closed = poll_until_closed(&mut client);
    assert!(!closed.reconnectable, "{closed:?}");
    assert_eq!(closed.error_info, 0);
    assert!(closed.text.starts_with("server disconnected"), "{closed:?}");
}

#[test]
fn close_reason_classification() {
    let drop = close_reason(CloseCause::Transport("connection reset by server"), 0);
    assert!(drop.reconnectable);
    assert_eq!(drop.to_string(), "connection reset by server");
    // Any error info means the server chose to end: admin disconnect,
    // another connection, shutdown, licensing or protocol errors.
    for code in [0x1, 0x2, 0x3, 0x5, 0xB, 0xC, 0x19, 0x1A, 0x100, 0x10C9] {
        let r = close_reason(CloseCause::Transport("connection closed by server"), code);
        assert!(!r.reconnectable, "{code:#x}");
        assert_eq!(r.error_info, code);
    }
    assert!(!close_reason(CloseCause::Ultimatum("server disconnected"), 0).reconnectable);
}

#[test]
fn error_is_network_drop() {
    use std::io::{Error as IoError, ErrorKind};
    assert!(Error::ConnectionLost("x".into()).is_network_drop());
    assert!(Error::Timeout.is_network_drop());
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::BrokenPipe,
        ErrorKind::UnexpectedEof,
        ErrorKind::TimedOut,
        ErrorKind::NetworkUnreachable,
        ErrorKind::HostUnreachable,
    ] {
        assert!(Error::Io(IoError::from(kind)).is_network_drop(), "{kind:?}");
    }
    assert!(!Error::Io(IoError::from(ErrorKind::PermissionDenied)).is_network_drop());
    assert!(!Error::Disconnected("MCS".into()).is_network_drop());
    assert!(!Error::Auth("denied".into()).is_network_drop());
    assert!(!Error::Protocol("bad".into()).is_network_drop());
    // ConnectionLost keeps the text callers already show.
    assert_eq!(
        Error::ConnectionLost("connection closed by server".into()).to_string(),
        "disconnected: connection closed by server"
    );
}

#[test]
fn config_defaults_to_a_fresh_logon() {
    let cfg = Config::new("h", "u", "p");
    assert!(cfg.auto_reconnect.is_none());
    assert_eq!(cfg.compression, Compression::Off);
}

/// A slow-path Set Error Info PDU whose payload is bulk-compressed
/// (TS_SHAREDATAHEADER compressedType = PACKET_COMPRESSED | 64K).
#[test]
fn compressed_share_data_is_decompressed() {
    let (mut client, _server) = session();
    client.bulk = Decompressor::new(Compression::Rdp5);
    // shareId, pad1, streamId, uncompressedLength, pduType2 = 47,
    // compressedType, compressedLength; then MPPC "A" + <1,3> (RDP 5.0).
    let mut body = vec![
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 47, 0x21, 0x03, 0x00,
    ];
    body.extend_from_slice(&[0x41, 0xF8, 0x20]);
    let mut out = PollOutcome::default();
    client.handle_data(&body, &mut out).unwrap();
    assert_eq!(client.last_error_info, 0x4141_4141);
    client.bulk = Decompressor::default();
    assert!(client.handle_data(&body, &mut out).is_err());
}

#[test]
fn gfx_channel_joins_drdynvc_or_brings_its_own() {
    let mut cfg = Config::new("h", "u", "p");
    cfg.graphics = crate::Graphics::Gfx;
    let create = {
        let mut v = vec![0x10, 0x05];
        v.extend_from_slice(crate::gfx::CHANNEL_NAME.as_bytes());
        v.push(0);
        v
    };
    let opens = |h: &mut Box<dyn StaticChannel>| {
        let mut out = ChannelOut::default();
        h.process(&create, &mut out).unwrap();
        out.take()[0] == [0x10, 0x05, 0, 0, 0, 0]
    };
    // Joins an existing drdynvc.
    let mut handlers: Vec<Box<dyn StaticChannel>> = vec![Box::new(crate::Drdynvc::new(vec![]))];
    add_gfx_channel(&cfg, &mut handlers);
    assert_eq!(handlers.len(), 1);
    assert!(opens(&mut handlers[0]));
    // Brings its own when there is none.
    let mut handlers: Vec<Box<dyn StaticChannel>> = Vec::new();
    add_gfx_channel(&cfg, &mut handlers);
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0].name(), "drdynvc");
    assert!(opens(&mut handlers[0]));
}

#[test]
fn gfx_reset_resizes_the_session_framebuffer() {
    let (mut client, _server) = session();
    let (mut channel, handle) = crate::gfx::graphics(None);
    client.gfx = Some(handle);
    // ResetGraphics to 8x2, a surface filled red, mapped, end of frame.
    let mut msg = vec![0xE0, 0x04];
    let mut reset = vec![0x0E, 0, 0, 0, 0x54, 0x01, 0, 0, 8, 0, 0, 0, 2, 0, 0, 0];
    reset.resize(340, 0);
    msg.extend(reset);
    msg.extend([0x09, 0, 0, 0, 15, 0, 0, 0, 1, 0, 8, 0, 2, 0, 0x20]);
    msg.extend([
        0x0F, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    msg.extend([
        0x04, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0,
    ]);
    msg.extend([0x0C, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0]);
    let mut out = crate::DvcOut::default();
    crate::DynamicChannel::process(&mut channel, &msg, &mut out).unwrap();
    let mut poll = PollOutcome::default();
    client.present_gfx(&mut poll);
    assert!(poll.resized && poll.updated);
    assert_eq!((client.info.width, client.info.height), (8, 2));
    let fb = client.framebuffer();
    assert_eq!((fb.width, fb.height), (8, 2));
    assert!(fb.pixels.iter().all(|&p| p == 0x00FF_0000));
    // Nothing new: nothing to present.
    let mut poll = PollOutcome::default();
    client.present_gfx(&mut poll);
    assert!(!poll.resized && !poll.updated && poll.damage.is_empty());
}

#[test]
fn monitor_layout_pdu_is_stored_and_reported() {
    let (mut client, _server) = session();
    assert!(client.monitor_layout().is_empty());
    // Monitor Layout PDU (2.2.12.1): two monitors, the second left of the primary.
    let mut body = vec![2, 0, 0, 0];
    for v in [0, 0, 1919, 1079, 1, -1280, 0, -1, 1023, 0i32] {
        body.extend(v.to_le_bytes());
    }
    let pdu = pdu::share_data(
        0x0001_03ea,
        0x03ea,
        crate::monitor::PDUTYPE2_MONITOR_LAYOUT_PDU,
        &body,
    );
    let mut out = PollOutcome::default();
    client.handle_share(&pdu, &mut out).unwrap();
    let want = vec![
        crate::Monitor::new(0, 0, 1920, 1080, true),
        crate::Monitor::new(-1280, 0, 1280, 1024, false),
    ];
    assert_eq!(out.monitors.as_ref(), Some(&want));
    assert_eq!(client.monitor_layout(), &want[..]);
    // A malformed layout is dropped; the session and the old layout stay.
    let bad = pdu::share_data(
        0x0001_03ea,
        0x03ea,
        crate::monitor::PDUTYPE2_MONITOR_LAYOUT_PDU,
        &body[..30],
    );
    let mut out = PollOutcome::default();
    client.handle_share(&bad, &mut out).unwrap();
    assert!(out.monitors.is_none() && out.closed.is_none());
    assert_eq!(client.monitor_layout(), &want[..]);
}

#[test]
fn negotiation_flags_from_connection_confirm() {
    // X.224 Connection Confirm with RDP_NEG_RSP (2.2.1.2): flags 0x1F, HYBRID.
    let mut cc = vec![0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0];
    cc.extend([0x02, 0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
    assert_eq!(x224::parse_connection_confirm(&cc).unwrap(), 2);
    assert_eq!(x224::negotiation_flags(&cc), 0x1f);
    cc[12] = 0x00;
    assert_eq!(x224::negotiation_flags(&cc), 0);
    // A failure response or no negotiation data has no flags.
    cc[11] = 0x03;
    cc[12] = 0x01;
    assert_eq!(x224::negotiation_flags(&cc), 0);
    assert_eq!(x224::negotiation_flags(&cc[..11]), 0);
}

/// Enhanced Security Server Redirection PDU (2.2.13.3.1) with only RedirFlags set.
fn redirection_pdu(flags: u32) -> Vec<u8> {
    let mut p = vec![0x16, 0x00, 0x0a, 0x00, 0xea, 0x03, 0x00, 0x00]; // header, pad2Octets
    p.extend([0x00, 0x04, 0x0c, 0x00, 0x05, 0x00, 0x00, 0x00]); // Flags, Length, SessionID 5
    p.extend(flags.to_le_bytes());
    p.extend([0x00, 0x00]); // pad
    p
}

#[test]
fn redirection_after_activation_ends_the_session() {
    let (mut client, _server) = session();
    let mut out = PollOutcome::default();
    // LB_NOREDIRECT: kept for a reconnect, the session goes on.
    client
        .handle_share(&redirection_pdu(0x80), &mut out)
        .unwrap();
    assert!(out.closed.is_none());
    assert!(client.redirection().unwrap().no_redirect());
    // A real redirection ends the session (not as a network drop) and the
    // caller gets the PDU to reconnect with new channel handlers.
    client.handle_share(&redirection_pdu(0), &mut out).unwrap();
    let closed = out.closed.unwrap();
    assert!(!closed.reconnectable, "{closed:?}");
    assert!(closed.text.contains("redirected"), "{closed:?}");
    let r = client.redirection().unwrap();
    assert_eq!((r.session_id, r.no_redirect()), (5, false));
}

#[test]
fn mid_session_redirection_continues_the_hop_chain() {
    let mut cfg = Config::new("broker.example", "user", "pw");
    cfg.redirects = 1; // one connect-time hop already
    let (mut client, _server) = session();
    let mut out = PollOutcome::default();
    assert!(client.follow_redirection(&cfg).is_none(), "no redirection yet");
    // LB_NOREDIRECT is information only: nothing to follow.
    client
        .handle_share(&redirection_pdu(0x80), &mut out)
        .unwrap();
    assert!(client.follow_redirection(&cfg).is_none());
    // A real one: the next hop goes back to the sender (no target, 1.3.8),
    // with the redirection and the hop count, other settings unchanged.
    client.handle_share(&redirection_pdu(0), &mut out).unwrap();
    let next = client.follow_redirection(&cfg).unwrap().unwrap();
    assert_eq!(next.host, "broker.example");
    assert_eq!(next.redirects, 2);
    assert_eq!(next.redirection.as_ref().unwrap().session_id, 5);
    assert_eq!((next.username.as_str(), next.password.as_str()), ("user", "pw"));
    // The hop limit counts across connect-time and mid-session hops.
    let mut far = cfg.clone();
    far.redirects = redirect::MAX_REDIRECTS;
    let Some(Err(err)) = client.follow_redirection(&far) else {
        panic!("hop limit not enforced");
    };
    assert!(err.to_string().contains("more than 3"), "{err}");
}

/// An MCS Send Data Indication from the server on `channel` (T.125 SDin).
fn indication(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut ind = vec![0x68, 0x00, 0x01];
    ind.extend(channel.to_be_bytes());
    ind.push(0x70);
    mcs::put_per_len(&mut ind, data.len());
    ind.extend_from_slice(data);
    x224::data(&ind)
}

/// Reads one client Send Data Request: (channel, user data).
fn read_request(server: &mut TcpStream) -> (u16, Vec<u8>) {
    use std::io::Read;
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head = [0u8; 4];
    server.read_exact(&mut head).unwrap();
    let mut frame = vec![0u8; u16::from_be_bytes([head[2], head[3]]) as usize - 4];
    server.read_exact(&mut frame).unwrap();
    let m = &frame[3..];
    assert_eq!(m[0] >> 2, 25, "Send Data Request");
    let channel = u16::from_be_bytes([m[3], m[4]]);
    let (len, n) = mcs::read_per_len(m, 6).unwrap();
    (channel, m[6 + n..6 + n + len].to_vec())
}

#[test]
fn message_channel_auto_detect_is_answered_and_reported() {
    let (mut client, mut server) = session();
    client.message_channel = Some(1004);
    // RTT Measure Request (2.2.14.1.1), seq 7, after the connection sequence.
    let rtt = [0x00, 0x10, 0x00, 0x00, 0x06, 0x00, 0x07, 0x00, 0x01, 0x00];
    server.write_all(&indication(1004, &rtt)).unwrap();
    let mut answered = None;
    for _ in 0..100 {
        assert!(client.poll(Duration::from_millis(20)).unwrap().closed.is_none());
        server.set_nonblocking(true).unwrap();
        let ready = server.peek(&mut [0u8; 1]).is_ok();
        server.set_nonblocking(false).unwrap();
        if ready {
            answered = Some(read_request(&mut server));
            break;
        }
    }
    // The RTT Measure Response on the message channel (2.2.14.4, 2.2.14.2.1).
    let (channel, data) = answered.expect("RTT answered");
    // Network Characteristics Result (2.2.14.1.5), 0x0880: 2000 kbps, 25 ms.
    let mut result = vec![0x00, 0x10, 0x00, 0x00, 0x0E, 0x00, 0x08, 0x00, 0x80, 0x08];
    result.extend(2000u32.to_le_bytes());
    result.extend(25u32.to_le_bytes());
    server.write_all(&indication(1004, &result)).unwrap();
    let mut network = None;
    for _ in 0..100 {
        network = client.poll(Duration::from_millis(20)).unwrap().network;
        if network.is_some() {
            break;
        }
    }
    assert_eq!(channel, 1004);
    assert_eq!(data, [0x00, 0x20, 0x00, 0x00, 0x06, 0x01, 0x07, 0x00, 0x00, 0x00]);
    let n = network.expect("network characteristics reported");
    assert_eq!((n.bandwidth_kbps, n.average_rtt_ms), (Some(2000), Some(25)));
    assert_eq!(client.network(), n);
    // A heartbeat on the message channel (2.2.16.1) is taken as one.
    server
        .write_all(&indication(1004, &[0x00, 0x40, 0, 0, 0, 5, 3, 10]))
        .unwrap();
    for _ in 0..50 {
        client.poll(Duration::from_millis(20)).unwrap();
        if client.heartbeat.is_some() {
            break;
        }
    }
    assert_eq!(client.heartbeat.map(|h| h.period), Some(5));
}

/// A New Window order (MS-RDPERP 2.2.1.3.1.2.1) with only a title.
fn new_window_order(id: u32, title: &str) -> Vec<u8> {
    use crate::cursor::Put;
    use crate::rail::orders::*;
    let text = crate::cursor::utf16le(title);
    let mut o = vec![0x2e];
    o.put_u16((11 + 2 + text.len()) as u16);
    o.put_u32(WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_STATE_NEW | WINDOW_ORDER_FIELD_TITLE);
    o.put_u32(id);
    o.put_u16(text.len() as u16);
    o.extend(text);
    o
}

fn remote_app_session() -> (Client, TcpStream, crate::RailHandle) {
    let (mut client, server) = session();
    let (_, handle) = crate::rail::rail(
        crate::RemoteApp {
            program: "notepad".into(),
            ..Default::default()
        },
        4,
        4,
        0,
    )
    .unwrap();
    client.rail = Some(handle.clone());
    (client, server, handle)
}

/// Fast-path orders update (MS-RDPEGDI 2.2.2.2) reaches the window model and
/// the poll outcome.
#[test]
fn fastpath_window_orders_reach_the_poll_outcome() {
    let (mut client, mut server, rail) = remote_app_session();
    let order = new_window_order(42, "Notepad");
    let mut update = vec![1, 0]; // numberOrders
    update.extend(&order);
    let mut frame = vec![0x00, (2 + 3 + update.len()) as u8, 0x00];
    frame.extend((update.len() as u16).to_le_bytes());
    frame.extend(&update);
    server.write_all(&frame).unwrap();
    let mut events = Vec::new();
    for _ in 0..50 {
        events.extend(client.poll(Duration::from_millis(20)).unwrap().rail);
        if !events.is_empty() {
            break;
        }
    }
    assert_eq!(events, vec![crate::RailEvent::WindowCreated(42)]);
    assert_eq!(rail.window(42).unwrap().title, "Notepad");
    assert_eq!(client.rail().unwrap().state().windows.len(), 1);
}

/// Slow-path orders (PDUTYPE2_UPDATE, updateType UPDATETYPE_ORDERS) go to the
/// model, and a desktop session ignores window orders.
#[test]
fn slowpath_window_orders_and_non_remoteapp_sessions() {
    let mut body = vec![0xea, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 2, 0, 0, 0];
    body.extend([0, 0, 0, 0, 1, 0, 0, 0]);
    body.extend(new_window_order(7, "A"));
    let (mut client, _server, rail) = remote_app_session();
    let mut out = PollOutcome::default();
    client.handle_data(&body, &mut out).unwrap();
    assert_eq!(rail.window(7).unwrap().title, "A");

    let (mut plain, _server) = session();
    plain.handle_data(&body, &mut out).unwrap();
    assert!(plain.rail().is_none());
    // Garbage orders never end the session.
    let mut bad = body.clone();
    bad.truncate(body.len() - 3);
    client.handle_data(&bad, &mut out).unwrap();
}

#[test]
fn remote_app_config() {
    let mut cfg = Config::new("h", "u", "p");
    assert!(cfg.remote_app.is_none());
    cfg.remote_app = Some(crate::RemoteApp::default());
    // An empty program is refused before any network traffic.
    assert!(matches!(
        Client::connect(&cfg),
        Err(Error::Protocol(m)) if m.contains("RemoteApp")
    ));
}
