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
        channels: Vec::new(),
        pointers: PointerCache::default(),
        arc_cookie: None,
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
    assert!(Config::new("h", "u", "p").auto_reconnect.is_none());
}
