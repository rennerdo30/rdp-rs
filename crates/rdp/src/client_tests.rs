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
