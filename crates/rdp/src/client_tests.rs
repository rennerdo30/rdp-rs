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
        keyboard: crate::KeyboardInfo::default(),
        color_depth: 32,
        fb: Framebuffer::new(4, 4),
        fastpath: Reassembler::default(),
        bulk: Decompressor::default(),
        channel_bulk: Decompressor::default(),
        info: ConnectionInfo {
            protocol: x224::PROTOCOL_HYBRID,
            certificate_sha256: [0; 32],
            encryption_method: 0,
            encryption_level: 0,
            gateway_certificate_sha256: None,
            server_rdp_version: 0x0008_0004,
            width: 4,
            height: 4,
            bpp: 32,
            input_flags: 0,
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
        orders: None,
        sec: None,
        udp: Udp::off(),
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
fn video_channels_are_offered_only_with_video_gfx_and_a_decoder() {
    struct NoPicture;
    impl crate::H264Decoder for NoPicture {
        fn decode(&mut self, _: &[u8]) -> Result<Option<crate::Yuv420Frame>> {
            Ok(None)
        }
    }
    let accepted = |cfg: &Config, name: &str| {
        let mut handlers: Vec<Box<dyn StaticChannel>> = Vec::new();
        let handle = add_gfx_channel(cfg, &mut handlers);
        let mut create = vec![0x10, 0x07];
        create.extend_from_slice(name.as_bytes());
        create.push(0);
        let mut out = ChannelOut::default();
        handlers[0].process(&create, &mut out).unwrap();
        let ok = out.take()[0] == [0x10, 0x07, 0, 0, 0, 0];
        (ok, handle.video_stats().is_some())
    };
    let decoder: crate::H264Factory =
        std::sync::Arc::new(|| Some(Box::new(NoPicture) as Box<dyn crate::H264Decoder>));
    let mut cfg = Config::new("h", "u", "p");
    cfg.graphics = crate::Graphics::Gfx;
    cfg.h264 = Some(decoder);
    for name in [
        crate::video::CONTROL_CHANNEL,
        crate::video::DATA_CHANNEL,
        crate::video::geometry::CHANNEL_NAME,
    ] {
        assert_eq!(
            accepted(&cfg, name),
            (false, false),
            "{name}: not asked for"
        );
        cfg.video = true;
        assert_eq!(accepted(&cfg, name), (true, true), "{name}: offered");
        cfg.video = false;
    }
    // No decoder on this machine: not offered.
    cfg.video = true;
    cfg.h264 = Some(std::sync::Arc::new(|| None));
    assert_eq!(
        accepted(&cfg, crate::video::CONTROL_CHANNEL),
        (false, false)
    );
    cfg.h264 = None;
    assert_eq!(
        accepted(&cfg, crate::video::CONTROL_CHANNEL),
        (false, false)
    );
    // The graphics channel itself is still there.
    assert_eq!(accepted(&cfg, crate::gfx::CHANNEL_NAME), (true, false));
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

#[test]
fn negotiation_failure_from_connection_confirm() {
    // RDP_NEG_FAILURE (2.2.1.2.2): SSL_NOT_ALLOWED_BY_SERVER, the answer of
    // a server that allows only Standard RDP Security.
    let mut cc = vec![0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0];
    cc.extend([0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
    assert_eq!(
        x224::negotiation_failure(&cc),
        Some(x224::SSL_NOT_ALLOWED_BY_SERVER)
    );
    assert!(x224::parse_connection_confirm(&cc).is_err());
    // A response, or no negotiation data, is no failure.
    assert_eq!(x224::negotiation_failure(&cc[..11]), None);
    cc[11] = 0x02;
    assert_eq!(x224::negotiation_failure(&cc), None);
    // The refusal names the setting that allows it.
    let e = security::legacy_refused().to_string();
    assert!(
        e.contains(security::LEGACY_REFUSED) && e.contains("legacy_security"),
        "{e}"
    );
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
    assert!(
        client.follow_redirection(&cfg).is_none(),
        "no redirection yet"
    );
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
    assert_eq!(
        (next.username.as_str(), next.password.as_str()),
        ("user", "pw")
    );
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
        assert!(
            client
                .poll(Duration::from_millis(20))
                .unwrap()
                .closed
                .is_none()
        );
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
    assert_eq!(
        data,
        [0x00, 0x20, 0x00, 0x00, 0x06, 0x01, 0x07, 0x00, 0x00, 0x00]
    );
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

/// With drawing orders on, a fast-path orders update draws into the
/// framebuffer and reports the damage; window orders in the same update
/// still reach the RemoteApp model (MS-RDPEGDI 2.2.2.2).
#[test]
fn fastpath_drawing_orders_reach_the_framebuffer() {
    let (mut client, mut server, rail) = remote_app_session();
    client.orders = Some(Box::new(crate::orders::Orders::new(None)));
    // OpaqueRect (1, 1, 2, 2) in 0x102030, then a window order.
    let opaque = [0x09, 0x0A, 0x7F, 1, 0, 1, 0, 2, 0, 2, 0, 0x10, 0x20, 0x30];
    let mut update = vec![2, 0];
    update.extend(opaque);
    update.extend(new_window_order(42, "Notepad"));
    let mut frame = vec![0x00, (2 + 3 + update.len()) as u8, 0x00];
    frame.extend((update.len() as u16).to_le_bytes());
    frame.extend(&update);
    server.write_all(&frame).unwrap();
    let mut damage = Vec::new();
    let mut events = Vec::new();
    for _ in 0..50 {
        let out = client.poll(Duration::from_millis(20)).unwrap();
        damage.extend(out.damage);
        events.extend(out.rail);
        if !damage.is_empty() {
            break;
        }
    }
    assert_eq!(
        damage,
        vec![Damage {
            x: 1,
            y: 1,
            w: 2,
            h: 2
        }]
    );
    assert_eq!(client.framebuffer().pixels[5], 0x102030);
    assert_eq!(client.framebuffer().pixels[0], 0);
    assert_eq!(events, vec![crate::RailEvent::WindowCreated(42)]);
    assert!(rail.window(42).is_some());
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

/// Progress reports the steps as they start: a refused port stops after
/// the address lookup and the TCP connect, and nothing later is reported.
#[test]
fn progress_reports_the_steps_reached() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }; // closed again: the connect is refused
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut cfg = Config::new("127.0.0.1", "user", "secret");
    cfg.port = port;
    cfg.timeout = Duration::from_secs(5);
    let s = seen.clone();
    cfg.progress = Some(crate::ConnectProgress::new(move |step| {
        s.lock().unwrap().push(step.clone())
    }));
    assert!(Client::connect(&cfg).is_err());
    assert_eq!(
        *seen.lock().unwrap(),
        [ConnectStep::Resolving, ConnectStep::Tcp]
    );
}

/// Standard RDP Security (MS-RDPBCGR 5.3) in the session loop: the test
/// plays the server with the client's keys, encryption and decryption
/// swapped (5.3.5.1).
#[test]
fn legacy_security_encrypts_and_checks_every_pdu() {
    use crate::security::{KeyStrength, SessionKeys, session_keys};
    let k = session_keys(&[1; 32], &[2; 32], KeyStrength::Bits128);
    let swapped = SessionKeys {
        mac: k.mac.clone(),
        encrypt: k.decrypt.clone(),
        decrypt: k.encrypt.clone(),
    };
    let level = crate::security::ENCRYPTION_LEVEL_HIGH;
    let mut srv = StandardSecurity::from_keys(KeyStrength::Bits128, level, &swapped);
    let (mut client, mut server) = session();
    client.sec = Some(Box::new(StandardSecurity::from_keys(
        KeyStrength::Bits128,
        level,
        &k,
    )));

    // An encrypted Save Session Info PDU reaches the session.
    let pdu = srv.wrap(0, &save_session_info_pdu(5));
    server.write_all(&indication(1003, &pdu)).unwrap();
    for _ in 0..100 {
        client.poll(Duration::from_millis(20)).unwrap();
        if client.arc_cookie.is_some() {
            break;
        }
    }
    assert_eq!(client.arc_cookie.as_ref().map(|c| c.logon_id), Some(5));

    // Slow-path output is encrypted: the server decrypts a Refresh Rect.
    client.request_refresh().unwrap();
    let (channel, data) = read_request(&mut server);
    assert_eq!(channel, 1003);
    assert_eq!(&data[..2], &[0x08, 0x00], "SEC_ENCRYPT");
    let plain = srv.unwrap(&data).unwrap();
    assert_eq!(plain[14], pdu::PDUTYPE2_REFRESH_RECT);

    // Fast-path input too.
    use std::io::Read;
    let event = InputEvent::mouse_move(10, 20);
    client.send_input(std::slice::from_ref(&event)).unwrap();
    let mut head = [0u8; 2];
    server.read_exact(&mut head).unwrap();
    let mut frame = head.to_vec();
    frame.resize(head[1] as usize, 0);
    server.read_exact(&mut frame[2..]).unwrap();
    assert_eq!(frame[0] >> 6, 0x2, "FASTPATH_INPUT_ENCRYPTED");
    assert_eq!(
        srv.fastpath_output(&frame).unwrap(),
        fastpath_input(&[event])
    );

    // A changed byte fails the MAC and ends the session with an error.
    let mut bad = srv.wrap(0, &save_session_info_pdu(6));
    *bad.last_mut().unwrap() ^= 0x40;
    server.write_all(&indication(1003, &bad)).unwrap();
    let mut failed = None;
    for _ in 0..100 {
        if let Err(e) = client.poll(Duration::from_millis(20)) {
            failed = Some(e);
            break;
        }
    }
    assert!(failed.is_some_and(|e| e.to_string().contains("MAC mismatch")));
}

/// One TPKT frame from the client.
fn read_tpkt(s: &mut TcpStream) -> Vec<u8> {
    use std::io::Read;
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut frame = vec![0u8; 4];
    s.read_exact(&mut frame).unwrap();
    frame.resize(u16::from_be_bytes([frame[2], frame[3]]) as usize, 0);
    s.read_exact(&mut frame[4..]).unwrap();
    frame
}

/// The client's next Send Data Request on `channel`.
fn read_send_data(s: &mut TcpStream, channel: u16) -> Vec<u8> {
    use crate::server::connect::{ClientDomainPdu, parse_client_domain_pdu};
    let frame = read_tpkt(s);
    match parse_client_domain_pdu(x224::data_payload(&frame).unwrap()).unwrap() {
        ClientDomainPdu::SendData {
            channel: c, data, ..
        } if c == channel => data.to_vec(),
        other => panic!("expected data on channel {channel}, got {other:?}"),
    }
}

/// A server that allows only Standard RDP Security (MS-RDPBCGR 5.3) with
/// the 4.8 sample key in a proprietary certificate signed by the Terminal
/// Services key: it refuses TLS (SSL_NOT_ALLOWED_BY_SERVER), then runs the
/// connection sequence up to the Confirm Active, checking what the client
/// encrypts. Returns the client random it decrypted.
fn legacy_server(listener: TcpListener, cert: Vec<u8>) -> [u8; 32] {
    use crate::security::tests::{SAMPLE_MODULUS, SAMPLE_PRIVATE_EXPONENT};
    use crate::security::{KeyStrength, SessionKeys, session_keys};
    use crate::server::connect::*;
    let (mut s, _) = listener.accept().unwrap();
    let cr = parse_connection_request(&read_tpkt(&mut s)).unwrap();
    assert_ne!(cr.requested_protocols.unwrap() & x224::PROTOCOL_SSL, 0);
    s.write_all(&negotiation_failure(x224::SSL_NOT_ALLOWED_BY_SERVER))
        .unwrap();
    drop(s);

    let (mut s, _) = listener.accept().unwrap();
    let cr = parse_connection_request(&read_tpkt(&mut s)).unwrap();
    assert_eq!(cr.requested_protocols, Some(x224::PROTOCOL_RDP));
    s.write_all(&connection_confirm(x224::PROTOCOL_RDP, 0))
        .unwrap();
    let gcc = parse_connect_initial(x224::data_payload(&read_tpkt(&mut s)).unwrap()).unwrap();
    // Client Security Data: 40, 56 and 128-bit RC4 and FIPS (2.2.1.3.3).
    assert!(
        gcc.windows(8)
            .any(|w| w == [0x02, 0xC0, 12, 0, 0x1B, 0, 0, 0])
    );
    let server_random = [0x5A; 32];
    let mut blocks = vec![0x01, 0x0C, 12, 0, 0x04, 0, 0x08, 0, 0, 0, 0, 0];
    let mut sec = Vec::new();
    for v in [2u32, 2, 32, cert.len() as u32] {
        sec.extend(v.to_le_bytes());
    }
    sec.extend(server_random);
    sec.extend(&cert);
    blocks.extend(0x0C02u16.to_le_bytes());
    blocks.extend(((sec.len() + 4) as u16).to_le_bytes());
    blocks.extend(sec);
    blocks.extend([0x03, 0x0C, 8, 0, 0xEB, 0x03, 0, 0]);
    let response = connect_response(&conference_create_response(&blocks));
    s.write_all(&x224::data(&response)).unwrap();
    read_tpkt(&mut s); // Erect Domain
    read_tpkt(&mut s); // Attach User
    s.write_all(&x224::data(&attach_user_confirm(1007)))
        .unwrap();
    for ch in [1007, 1003] {
        read_tpkt(&mut s);
        s.write_all(&x224::data(&channel_join_confirm(1007, ch)))
            .unwrap();
    }
    // Security Exchange PDU (2.2.1.10): decrypt the client random (5.3.4.2).
    let exchange = read_send_data(&mut s, 1003);
    assert_eq!(&exchange[..8], &[0x01, 0x02, 0, 0, 72, 0, 0, 0]);
    let random =
        crate::crypto::rsa_modpow_le(&exchange[8..72], &SAMPLE_MODULUS, &SAMPLE_PRIVATE_EXPONENT);
    let client_random: [u8; 32] = random[..32].try_into().unwrap();
    let k = session_keys(&client_random, &server_random, KeyStrength::Bits128);
    let server_keys = SessionKeys {
        mac: k.mac.clone(),
        encrypt: k.decrypt.clone(),
        decrypt: k.encrypt.clone(),
    };
    let level = crate::security::ENCRYPTION_LEVEL_CLIENT_COMPATIBLE;
    let mut srv = StandardSecurity::from_keys(KeyStrength::Bits128, level, &server_keys);
    // Client Info, encrypted (SEC_INFO_PKT | SEC_ENCRYPT, 4.1.10).
    let info = read_send_data(&mut s, 1003);
    assert_eq!(&info[..2], &[0x48, 0x00]);
    let creds = crate::server::pdu::parse_client_info(&srv.unwrap(&info).unwrap()).unwrap();
    assert_eq!(
        (creds.user.as_str(), creds.password.as_str()),
        ("alice", "secret")
    );
    // An encrypted "valid client" licensing PDU (4.1.11), then Demand Active.
    srv.license_encrypt = true;
    let lic = crate::server::pdu::license_valid_client();
    let lic = srv.wrap(u16::from_le_bytes([lic[0], lic[1]]) | 0x0200, &lic[4..]);
    s.write_all(&x224::data(&send_data_indication(1003, &lic)))
        .unwrap();
    let demand = srv.wrap(0, &crate::server::pdu::demand_active(0x103EA, 800, 600));
    s.write_all(&x224::data(&send_data_indication(1003, &demand)))
        .unwrap();
    // Confirm Active, encrypted.
    let confirm = srv.unwrap(&read_send_data(&mut s, 1003)).unwrap();
    assert_eq!(confirm[2] & 0x0F, pdu::PDUTYPE_CONFIRMACTIVE as u8);
    // Synchronize, Control (cooperate, request control), Font List.
    for ty in [31, 20, 20, 39] {
        let data = srv.unwrap(&read_send_data(&mut s, 1003)).unwrap();
        assert_eq!(data[14], ty);
    }
    client_random
}

#[test]
fn legacy_security_connects_only_when_allowed() {
    use crate::security::tests::{SAMPLE_MODULUS, proprietary_certificate};
    let cert = proprietary_certificate(&SAMPLE_MODULUS);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = Config::new("127.0.0.1", "alice", "secret");
    cfg.port = listener.local_addr().unwrap().port();
    cfg.timeout = Duration::from_secs(10);

    // Not allowed: refused at negotiation, naming the setting.
    let refusing = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        read_tpkt(&mut s);
        s.write_all(&crate::server::connect::negotiation_failure(2))
            .unwrap();
        listener
    });
    let e = Client::connect(&cfg).err().expect("refused").to_string();
    assert!(e.contains(security::LEGACY_REFUSED), "{e}");
    let listener = refusing.join().unwrap();

    // Allowed: the certificate goes to the trust check first.
    cfg.legacy_security = true;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    cfg.verify_certificate = Some(CertificateCheck(std::sync::Arc::new(move |c| {
        log.lock().unwrap().push(c.sha256);
        true
    })));
    let expected = sha256(&cert);
    let server = std::thread::spawn(move || legacy_server(listener, cert));
    let client = Client::connect(&cfg).unwrap();
    let client_random = server.join().unwrap();
    assert_ne!(client_random, [0; 32]);
    assert_eq!(*seen.lock().unwrap(), [expected]);
    let info = client.info();
    assert_eq!(info.protocol, x224::PROTOCOL_RDP);
    assert_eq!((info.encryption_method, info.encryption_level), (2, 2));
    assert_eq!(info.certificate_sha256, expected);
}

/// Client Send Data Requests that are waiting, without blocking.
fn requests(server: &mut TcpStream) -> Vec<(u16, Vec<u8>)> {
    let mut v = Vec::new();
    loop {
        server.set_nonblocking(true).unwrap();
        let ready = server.peek(&mut [0u8; 1]).is_ok();
        server.set_nonblocking(false).unwrap();
        if !ready {
            return v;
        }
        v.push(read_request(server));
    }
}

/// An Initiate Multitransport Request (MS-RDPBCGR 2.2.15.1) for `protocol`.
fn initiate_request(protocol: u16) -> Vec<u8> {
    let mut v = vec![0x02, 0x00, 0x00, 0x00];
    v.extend(7u32.to_le_bytes());
    v.extend(protocol.to_le_bytes());
    v.extend([0, 0]);
    v.extend(crate::multitransport::tests::COOKIE);
    v
}

/// A DVC that answers each message with "re:" and the message.
struct EchoDvc;

impl crate::DynamicChannel for EchoDvc {
    fn name(&self) -> &str {
        "ECHO"
    }
    fn process(&mut self, msg: &[u8], out: &mut crate::DvcOut) -> Result<()> {
        out.send([b"re:".as_slice(), msg].concat());
        Ok(())
    }
}

/// A session with the message channel 1004 and `drdynvc` on 1005 holding
/// [`EchoDvc`], UDP offered to a server with the given multitransport flags.
fn udp_session(server_flags: u32, certificate: Vec<u8>) -> (Client, TcpStream) {
    let (mut client, server) = session();
    client.message_channel = Some(1004);
    client.channels.push(Slot {
        id: 1005,
        handler: Box::new(crate::Drdynvc::new(vec![Box::new(EchoDvc)])),
        defrag: Default::default(),
        failed: false,
    });
    client.udp = Udp {
        offered: true,
        server_flags,
        state: UdpState::Offered,
        certificate,
        ..Udp::off()
    };
    (client, server)
}

/// Static `drdynvc` data from the server: one chunk.
fn dvc_indication(pdu: &[u8]) -> Vec<u8> {
    indication(1005, &channel::chunk(pdu, false).remove(0))
}

#[test]
fn multitransport_requests_are_declined_unless_usable() {
    use crate::multitransport::{
        E_ABORT, PROTOCOL_UDPFECL, PROTOCOL_UDPFECR, SOFTSYNC_TCP_TO_UDP, TRANSPORTTYPE_UDPFECR,
        initiate_response,
    };
    let declined = |client: &mut Client, server: &mut TcpStream, protocol| {
        server
            .write_all(&indication(1004, &initiate_request(protocol)))
            .unwrap();
        let mut got = Vec::new();
        for _ in 0..50 {
            assert!(
                client
                    .poll(Duration::from_millis(10))
                    .unwrap()
                    .closed
                    .is_none()
            );
            got.extend(requests(server));
            if !got.is_empty() {
                break;
            }
        }
        assert_eq!(got, vec![(1004, initiate_response(7, E_ABORT))]);
    };
    // The lossy transport needs DTLS.
    let flags = TRANSPORTTYPE_UDPFECR | SOFTSYNC_TCP_TO_UDP;
    let (mut client, mut server) = udp_session(flags, vec![1]);
    declined(&mut client, &mut server, PROTOCOL_UDPFECL);
    assert!(client.udp.tunnel.is_none());
    // A server without Soft-Sync.
    let (mut client, mut server) = udp_session(TRANSPORTTYPE_UDPFECR, vec![1]);
    declined(&mut client, &mut server, PROTOCOL_UDPFECR);
    // UDP not offered (the setting is off).
    let (mut client, mut server) = session();
    client.message_channel = Some(1004);
    declined(&mut client, &mut server, PROTOCOL_UDPFECR);
    assert_eq!(client.stats().udp.state, UdpState::Off);
}

#[test]
fn a_udp_setup_failure_keeps_the_session_on_tcp() {
    use crate::multitransport::{CLIENT_FLAGS, E_ABORT, PROTOCOL_UDPFECR, initiate_response};
    // Nothing listens on the server's UDP port: the tunnel fails (port
    // unreachable, or at the latest the setup timeout) and the request is
    // declined; the session goes on.
    let (mut client, mut server) = udp_session(CLIENT_FLAGS, vec![1]);
    server
        .write_all(&indication(1004, &initiate_request(PROTOCOL_UDPFECR)))
        .unwrap();
    let start = Instant::now();
    let mut got = Vec::new();
    while got.is_empty() && start.elapsed() < Duration::from_secs(15) {
        assert!(
            client
                .poll(Duration::from_millis(20))
                .unwrap()
                .closed
                .is_none()
        );
        got.extend(requests(&mut server));
    }
    assert_eq!(got, vec![(1004, initiate_response(7, E_ABORT))]);
    assert_eq!(client.stats().udp.state, UdpState::Failed);
    assert!(client.udp_failure().is_some());
    // TCP still works: a DVC message is answered on the static channel.
    server.write_all(&dvc_indication(&[0x50, 0, 1, 0])).unwrap();
    let mut got = Vec::new();
    for _ in 0..50 {
        assert!(
            client
                .poll(Duration::from_millis(10))
                .unwrap()
                .closed
                .is_none()
        );
        got.extend(requests(&mut server));
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got[0].0, 1005);
}

#[test]
fn udp_tunnel_carries_the_dynamic_channels_after_soft_sync() {
    use crate::dvc::{TUNNELTYPE_UDPFECR, soft_sync_request, soft_sync_response};
    use crate::multitransport::tests::{COOKIE, FakeServer, identity};
    use crate::multitransport::{CLIENT_FLAGS, PROTOCOL_UDPFECR, S_OK, initiate_response};
    use std::net::UdpSocket;

    let (cert, key) = identity("broker.example");
    let (mut client, mut server) = udp_session(CLIENT_FLAGS, cert.clone());
    // The fake server's UDP side on the TCP connection's port (3.1.3).
    let udp = UdpSocket::bind(server.local_addr().unwrap()).unwrap();
    udp.set_nonblocking(true).unwrap();
    let mut fake = FakeServer::new(&cert, &key, S_OK);
    fake.echo = false;
    let mut peer = None;
    let mut seen: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut pump = |client: &mut Client,
                    server: &mut TcpStream,
                    fake: &mut FakeServer,
                    seen: &mut Vec<(u16, Vec<u8>)>| {
        let out = client.poll(Duration::from_millis(2)).unwrap();
        assert!(out.closed.is_none(), "{:?}", out.closed);
        let mut buf = [0u8; 2048];
        let mut incoming = Vec::new();
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            peer = Some(from);
            incoming.push(buf[..n].to_vec());
        }
        for d in fake.step(incoming, Instant::now()) {
            udp.send_to(&d, peer.unwrap()).unwrap();
        }
        seen.extend(requests(server));
    };

    // The DVC host opens ECHO as channel 3 over TCP.
    server.write_all(&dvc_indication(&[0x50, 0, 1, 0])).unwrap();
    server
        .write_all(&dvc_indication(b"\x10\x03ECHO\0"))
        .unwrap();
    server
        .write_all(&indication(1004, &initiate_request(PROTOCOL_UDPFECR)))
        .unwrap();
    for _ in 0..2_000 {
        pump(&mut client, &mut server, &mut fake, &mut seen);
        if client.stats().udp.state == UdpState::Active && !seen.is_empty() {
            break;
        }
    }
    assert_eq!(client.stats().udp.state, UdpState::Active);
    // The tunnel carried the request's ID and cookie (MS-RDPEMT 2.2.2.1),
    // and the server heard S_OK on the message channel (2.2.15.2).
    assert_eq!(fake.create, Some((7, COOKIE)));
    for _ in 0..50 {
        pump(&mut client, &mut server, &mut fake, &mut seen);
    }
    assert!(seen.contains(&(1004, initiate_response(7, S_OK))));

    // Soft-Sync moves channel 3 (2.2.5.1); the answer comes on TCP.
    seen.clear();
    server
        .write_all(&dvc_indication(&soft_sync_request(&[(
            TUNNELTYPE_UDPFECR,
            &[3],
        )])))
        .unwrap();
    for _ in 0..500 {
        pump(&mut client, &mut server, &mut fake, &mut seen);
        if !seen.is_empty() {
            break;
        }
    }
    let rsp = soft_sync_response(&[TUNNELTYPE_UDPFECR]);
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].0, &seen[0].1[8..]), (1005, &rsp[..]));

    // Channel data now flows over UDP both ways.
    fake.send(b"\x30\x03ping");
    for _ in 0..2_000 {
        pump(&mut client, &mut server, &mut fake, &mut seen);
        if !fake.data.is_empty() {
            break;
        }
    }
    assert_eq!(fake.data, vec![b"\x30\x03re:ping".to_vec()]);
    let st = client.stats().udp;
    assert_eq!((st.state, st.channels), (UdpState::Active, 1));
    assert!(st.bytes_in > 0 && st.bytes_out > 0);
    assert!(client.stats().bytes_in >= st.bytes_in);
    // Nothing for the channel went over TCP after the switch.
    assert_eq!(seen.len(), 1);
}
