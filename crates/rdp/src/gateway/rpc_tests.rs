//! Loopback tests of the RPC over HTTP transport against a fake gateway:
//! both channels with HTTP NTLM, the RTS virtual connection, the sealed
//! DCE/RPC bind and the TsProxy calls, flow control both ways, the RDP
//! bytes through the pipe, and the fallback from the HTTP transport.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::dcerpc::{self as dce, Header, Security};
use super::rts::{self, Command, Rts};
use super::tests::{header, ntlm_challenge};
use super::tsproxy::{self as tsg, server};
use super::*;
use crate::cursor::Put;
use crate::ntlm::Ntlm;
use crate::transport::Framer;

const TUNNEL: tsg::Handle = [7; 20];
const CHANNEL: tsg::Handle = [
    0, 0, 0, 0, 0x36, 0x41, 0x18, 0x41, 0xdd, 0x2d, 0x84, 0x43, 0x83, 0x63, 0x82, 0xcc, 0xb6, 0xea,
    0xf3, 0xf9,
];
const PAYLOAD_LEN: usize = 40_000;

fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|i| (i * 13 % 251) as u8).collect()
}

/// What the fake gateway answers.
#[derive(Clone, Copy)]
struct Script {
    /// Status of the OUT channel's answer to the NTLM AUTHENTICATE.
    out_auth: u16,
    /// HRESULT of TsProxyCreateChannel.
    channel_hresult: u32,
    /// The inbound proxy's receive window (CONN/C2).
    in_window: u32,
    /// A WebSocket upgrade comes first and gets this status.
    websocket_first: Option<u16>,
}

const OK: Script = Script {
    out_auth: 200,
    channel_hresult: 0,
    in_window: 16384,
    websocket_first: None,
};

/// What the fake gateway saw.
#[derive(Debug, Default)]
struct Seen {
    data: Vec<u8>,
    opnums: Vec<u16>,
    /// procIds of the TsProxyMakeTunnelCall requests.
    msg_procs: Vec<u32>,
    /// The client acknowledged OUT channel bytes (FlowControlAckWithDestination).
    client_acks: Vec<rts::Ack>,
    pings: usize,
}

struct Chan {
    sock: TcpStream,
    buf: Vec<u8>,
}

impl Chan {
    fn new(sock: TcpStream) -> Self {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            sock,
            buf: Vec::new(),
        }
    }

    /// More bytes; false at the end of the stream.
    fn more(&mut self) -> bool {
        let mut tmp = [0u8; 65536];
        match self.sock.read(&mut tmp) {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
        }
    }

    fn head(&mut self) -> String {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return String::from_utf8(self.buf.drain(..end + 4).collect()).unwrap();
            }
            assert!(self.more(), "client closed during a request head");
        }
    }

    fn body(&mut self, n: usize) -> Vec<u8> {
        while self.buf.len() < n {
            assert!(self.more(), "client closed during a body");
        }
        self.buf.drain(..n).collect()
    }

    /// The next PDU; None at the end of the stream.
    fn pdu(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(n) = dce::pdu_len(&self.buf).unwrap()
                && self.buf.len() >= n
            {
                return Some(self.buf.drain(..n).collect());
            }
            if !self.more() {
                return None;
            }
        }
    }

    fn send(&mut self, b: &[u8]) {
        self.sock.write_all(b).unwrap();
    }
}

/// The NTLM token of an HTTP request, with its message type checked.
fn ntlm_message(head: &str, kind: u8) {
    let auth = header(head, "Authorization");
    let token = auth.strip_prefix("NTLM ").expect("NTLM scheme");
    let msg = ws::base64_decode(token).unwrap();
    assert_eq!(&msg[..8], b"NTLMSSP\0");
    assert_eq!(msg[8], kind);
}

/// HTTP NTLM on one channel: 401 with a challenge, then the real request.
fn channel_auth(c: &mut Chan, method: &str) -> String {
    let head = c.head();
    assert!(
        head.starts_with(&format!(
            "{method} /rpc/rpcproxy.dll?localhost:3388 HTTP/1.1\r\n"
        )),
        "{head}"
    );
    assert_eq!(header(&head, "Content-Length"), "0");
    ntlm_message(&head, 1);
    let challenge = ws::base64_encode(&ntlm_challenge());
    c.send(
        format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {challenge}\r\n\
             Content-Length: 2\r\n\r\nno"
        )
        .as_bytes(),
    );
    let head = c.head();
    assert!(head.starts_with(method));
    assert_eq!(header(&head, "User-Agent"), "MSRPC");
    ntlm_message(&head, 3);
    head
}

/// The auth token at the end of a bind or rpc_auth_3.
fn auth_token(pdu: &[u8]) -> Vec<u8> {
    let h = Header::parse(pdu).unwrap();
    pdu[pdu.len() - h.auth_length as usize..].to_vec()
}

fn bind_ack(call_id: u32, token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    Header {
        ptype: dce::PTYPE_BIND_ACK,
        flags: 0x07,
        frag_length: 0,
        auth_length: token.len() as u16,
        call_id,
    }
    .write(&mut b);
    b.put_u16(5840);
    b.put_u16(5840);
    b.put_u32(0x5555);
    b.put_u16(5);
    b.put_bytes(b"3388\0");
    b.put_zeros(1); // align to 4
    b.put_bytes(&[1, 0, 0, 0]);
    b.put_u16(0);
    b.put_u16(0);
    b.put_bytes(&dce::NDR20.uuid);
    b.put_u32(dce::NDR20.version);
    b.put_bytes(&[dce::AUTHN_WINNT, dce::AUTHN_LEVEL_PKT_PRIVACY, 0, 0]);
    b.put_u32(0);
    b.put_bytes(token);
    let n = b.len() as u16;
    b[8..10].copy_from_slice(&n.to_le_bytes());
    b
}

fn fake_gateway(listener: TcpListener, script: Script) -> JoinHandle<Seen> {
    std::thread::spawn(move || {
        let mut seen = Seen::default();
        if let Some(status) = script.websocket_first {
            let (sock, _) = listener.accept().unwrap();
            let mut c = Chan::new(sock);
            let head = c.head();
            assert!(head.starts_with("GET /remoteDesktopGateway/ HTTP/1.1\r\n"));
            c.send(format!("HTTP/1.1 {status} Not Found\r\nContent-Length: 0\r\n\r\n").as_bytes());
        }
        let mut out = Chan::new(listener.accept().unwrap().0);
        let mut inn = Chan::new(listener.accept().unwrap().0);

        // MS-RPCH 2.1.2.1.2: the OUT channel with CONN/A1 as its body.
        let head = channel_auth(&mut out, "RPC_OUT_DATA");
        assert_eq!(header(&head, "Content-Length"), "76");
        if script.out_auth != 200 {
            out.send(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
            // The IN channel is set up meanwhile, as on a real gateway.
            channel_auth(&mut inn, "RPC_IN_DATA");
            inn.pdu();
            return seen;
        }
        let a1 = Rts::parse(&out.body(76)).unwrap();
        let [
            Command::Version(1),
            Command::Cookie(_),
            Command::Cookie(out_cookie),
            Command::ReceiveWindowSize(0x10000),
        ] = a1.commands[..]
        else {
            panic!("not CONN/A1: {a1:?}");
        };

        // 2.1.2.1.1: the IN channel, CONN/B1 first in its body.
        let head = channel_auth(&mut inn, "RPC_IN_DATA");
        assert_eq!(header(&head, "Content-Length"), "1073741824");
        let b1 = Rts::parse(&inn.pdu().unwrap()).unwrap();
        let Command::Cookie(in_cookie) = b1.commands[2] else {
            panic!("not CONN/B1: {b1:?}");
        };
        assert_eq!(b1.commands.len(), 6);

        // 3.2.1.5.3.1: OUT channel response, CONN/A3, CONN/C2.
        let mut opened =
            b"HTTP/1.1 200 Success\r\nContent-Type: application/rpc\r\nContent-Length: 1073741824\r\n\r\n"
                .to_vec();
        opened.extend(Rts::new(0, vec![Command::ConnectionTimeout(120_000)]).encode());
        opened.extend(
            Rts::new(
                0,
                vec![
                    Command::Version(1),
                    Command::ReceiveWindowSize(script.in_window),
                    Command::ConnectionTimeout(120_000),
                ],
            )
            .encode(),
        );
        out.send(&opened);

        // The bind with NTLM; the session key comes from the AUTHENTICATE.
        let bind = inn.pdu().unwrap();
        assert_eq!(bind[2], dce::PTYPE_BIND);
        assert_eq!(&auth_token(&bind)[8..9], &[1]);
        let mut in_bytes = bind.len() as u64;
        out.send(&bind_ack(1, &ntlm_challenge()));
        let auth3 = inn.pdu().unwrap();
        assert_eq!(auth3[2], dce::PTYPE_AUTH3);
        in_bytes += auth3.len() as u64;
        let exported = Ntlm::exported_key(&auth_token(&auth3), "secret", "alice", "DOM");
        let mut sec = Security {
            ntlm: Ntlm::with_session_key(exported, true),
            level: dce::AUTHN_LEVEL_PKT_PRIVACY,
            header_sign: true,
        };
        let respond = |out: &mut Chan, sec: &mut Security, id: u32, flags: u8, stub: &[u8]| {
            let pdu = sec
                .call_pdu(dce::PTYPE_RESPONSE, id, 0, stub.len() as u32, flags, stub)
                .unwrap();
            out.send(&pdu);
        };
        const WHOLE: u8 = dce::PFC_FIRST_FRAG | dce::PFC_LAST_FRAG;

        let mut pipe = None;
        let mut echoed = false;
        let mut acked = 0u64;
        while let Some(mut pdu) = inn.pdu() {
            if pdu[2] == dce::PTYPE_RTS {
                let r = Rts::parse(&pdu).unwrap();
                if let Some(ack) = r.ack() {
                    assert_eq!(r.commands[0], Command::Destination(rts::FD_OUT_PROXY));
                    assert_eq!(ack.channel_cookie, out_cookie);
                    seen.client_acks.push(ack);
                } else if r.flags == rts::FLAG_PING {
                    seen.pings += 1;
                }
                continue;
            }
            // Flow control for the IN channel: an ack once half the window
            // is used, so the client has to wait for some.
            in_bytes += pdu.len() as u64;
            assert!(
                in_bytes - acked <= script.in_window as u64,
                "the client overran the IN channel window"
            );
            if in_bytes - acked >= script.in_window as u64 / 2 {
                acked = in_bytes;
                let ack = rts::Ack {
                    bytes_received: in_bytes as u32,
                    available_window: script.in_window,
                    channel_cookie: in_cookie,
                };
                out.send(&rts::flow_control_ack(rts::FD_CLIENT, ack));
            }
            let opnum = u16::from_le_bytes([pdu[22], pdu[23]]);
            let req = sec.open_call(dce::PTYPE_REQUEST, &mut pdu).unwrap();
            assert_eq!(req.flags, WHOLE);
            seen.opnums.push(opnum);
            match opnum {
                tsg::OP_CREATE_TUNNEL => {
                    assert_eq!(server::read_create_tunnel(&req.stub).unwrap(), 0x0A);
                    let stub =
                        server::create_tunnel_response(0, &TUNNEL, 1, 0x0A, Some("cert"), None);
                    respond(&mut out, &mut sec, req.call_id, WHOLE, &stub);
                }
                tsg::OP_AUTHORIZE_TUNNEL => {
                    let (h, name) = server::read_authorize_tunnel(&req.stub).unwrap();
                    assert_eq!((h, name.as_str()), (TUNNEL, "CLIENT"));
                    let stub = server::authorize_response(0, Some(30));
                    respond(&mut out, &mut sec, req.call_id, WHOLE, &stub);
                }
                tsg::OP_MAKE_TUNNEL_CALL => {
                    assert_eq!(&req.stub[..20], &TUNNEL);
                    let proc_id = u32::from_le_bytes(req.stub[20..24].try_into().unwrap());
                    seen.msg_procs.push(proc_id);
                    // The first call gets a message at once (it arrives while
                    // the client waits for the channel); the next stays open.
                    if seen.msg_procs.len() == 1 {
                        let stub = server::message_response("Test");
                        respond(&mut out, &mut sec, req.call_id, WHOLE, &stub);
                    }
                }
                tsg::OP_CREATE_CHANNEL => {
                    let (h, host, port) = server::read_create_channel(&req.stub).unwrap();
                    assert_eq!((h, host.as_str(), port), (TUNNEL, "target", 3389));
                    let stub = server::create_channel_response(script.channel_hresult, &CHANNEL, 1);
                    respond(&mut out, &mut sec, req.call_id, WHOLE, &stub);
                    if script.channel_hresult != 0 {
                        return seen;
                    }
                }
                tsg::OP_SETUP_RECEIVE_PIPE => {
                    assert_eq!(req.stub, CHANNEL);
                    pipe = Some(req.call_id);
                }
                tsg::OP_SEND_TO_SERVER => {
                    let (h, data) = server::read_send_to_server(&req.stub).unwrap();
                    assert_eq!(h, CHANNEL);
                    assert!(!data.is_empty());
                    seen.data.extend_from_slice(&data);
                    respond(&mut out, &mut sec, req.call_id, WHOLE, &[0; 4]);
                }
                tsg::OP_CLOSE_CHANNEL | tsg::OP_CLOSE_TUNNEL => {
                    let h = if opnum == tsg::OP_CLOSE_CHANNEL {
                        CHANNEL
                    } else {
                        TUNNEL
                    };
                    assert_eq!(req.stub, h);
                    if opnum == tsg::OP_CLOSE_TUNNEL {
                        return seen;
                    }
                }
                op => panic!("unexpected opnum {op}"),
            }
            if seen.data.len() == PAYLOAD_LEN && !echoed {
                echoed = true;
                // 3.6.5.4: the data back in pipe responses, a ping and the
                // outbound proxy's own traffic in between.
                let id = pipe.expect("receive pipe set up");
                out.send(&rts::ping());
                for (i, part) in seen.data.clone().chunks(5000).enumerate() {
                    let flags = if i == 0 { dce::PFC_FIRST_FRAG } else { 0 };
                    respond(&mut out, &mut sec, id, flags, part);
                }
                // 3.6.5.5: the final response ends the stream.
                let code = tsg::ERROR_GRACEFUL_DISCONNECT.to_le_bytes();
                respond(&mut out, &mut sec, id, dce::PFC_LAST_FRAG, &code);
            }
        }
        seen
    })
}

fn config(transport: GatewayTransport) -> GatewayConfig {
    let mut gw = GatewayConfig::new("127.0.0.1", "DOM\\alice", "secret");
    gw.transport = transport;
    gw
}

fn target() -> Target<'static> {
    Target {
        host: "target",
        port: 3389,
        client_name: "CLIENT",
    }
}

/// The RPC transport on two sockets to a fake gateway.
fn rpc_tunnel(script: Script) -> (Result<Tunnel>, JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = fake_gateway(listener, script);
    let out = TcpStream::connect(addr).unwrap();
    let inn = TcpStream::connect(addr).unwrap();
    let gw = config(GatewayTransport::Rpc);
    let deadline = Instant::now() + Duration::from_secs(10);
    (
        rpc::open(out, inn, &gw, false, &target(), deadline, None, None),
        server,
    )
}

/// Runs RDP bytes both ways through a tunnel and checks the end.
fn carry(t: Tunnel, server: JoinHandle<Seen>) -> Seen {
    assert!(t.certificate.is_none());
    let mut f = Framer::over(Box::new(t.stream), Box::new(t.reader));
    let deadline = Instant::now() + Duration::from_secs(10);
    let data = payload();
    f.write(&data).unwrap();
    assert_eq!(f.read_exact(PAYLOAD_LEN, deadline).unwrap(), data);
    // After the final pipe response the stream ends like a TCP close.
    let end = f.read_frame(Some(deadline));
    assert!(
        matches!(end, Err(Error::ConnectionLost(_))),
        "{:?}",
        end.err()
    );
    drop(f); // shutdown: cancel, close channel, close tunnel
    let seen = server.join().unwrap();
    assert_eq!(seen.data, data);
    seen
}

#[test]
fn rpc_tunnel_carries_rdp_bytes_both_ways() {
    let (t, server) = rpc_tunnel(OK);
    let seen = carry(t.expect("tunnel up"), server);
    assert_eq!(&seen.opnums[..5], &[1, 2, 3, 4, 8], "setup order");
    // Many small calls: the data was split to fit one fragment each.
    let sends = seen.opnums.iter().filter(|&&o| o == 9).count();
    assert!(sends >= PAYLOAD_LEN / 4000, "{sends} sends");
    // The message call: asked, answered, asked again, cancelled on close.
    assert_eq!(seen.msg_procs, vec![1, 1, 2]);
    assert_eq!(&seen.opnums[seen.opnums.len() - 2..], &[6, 7]);
    // The client acknowledged the OUT channel once half its window was used.
    let ack = seen.client_acks.first().expect("a flow control ack");
    assert!(ack.bytes_received >= rpc::RECEIVE_WINDOW / 2);
    assert_eq!(ack.available_window, rpc::RECEIVE_WINDOW);
}

#[test]
fn small_in_window_waits_for_acknowledgments() {
    // The minimum window (8 KiB, MS-RPCH 2.2.3.5.1): two requests fit, the
    // rest waits for the gateway's acks.
    let (t, server) = rpc_tunnel(Script {
        in_window: 8192,
        ..OK
    });
    carry(t.expect("tunnel up"), server);
}

#[test]
fn rejected_channel_credentials_name_the_channel() {
    let (t, server) = rpc_tunnel(Script {
        out_auth: 401,
        ..OK
    });
    match t {
        Err(Error::Auth(m)) => {
            assert!(
                m.contains("RPC OUT channel") && m.contains("rejected"),
                "{m}"
            )
        }
        Err(e) => panic!("wrong error {e}"),
        Ok(_) => panic!("tunnel opened"),
    }
    server.join().unwrap();
}

#[test]
fn refused_channel_names_the_call_and_the_policy() {
    let (t, server) = rpc_tunnel(Script {
        channel_hresult: 0x8007_59DA,
        ..OK
    });
    match t {
        Err(Error::Protocol(m)) => {
            assert!(m.contains("TsProxyCreateChannel"), "{m}");
            assert!(m.contains("resource policy"), "{m}");
        }
        Err(e) => panic!("wrong error {e}"),
        Ok(_) => panic!("tunnel opened"),
    }
    server.join().unwrap();
}

/// Auto: the WebSocket upgrade gets 404, so the client uses RPC over HTTP.
#[test]
fn auto_falls_back_to_rpc_when_http_transport_is_missing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = fake_gateway(
        listener,
        Script {
            websocket_first: Some(404),
            ..OK
        },
    );
    let mut gw = config(GatewayTransport::Auto);
    gw.port = port;
    let deadline = Instant::now() + Duration::from_secs(10);
    let t = connect_with(&gw, &target(), false, deadline, None).expect("tunnel up");
    assert!(matches!(t.stream, GatewayStream::Rpc(_)));
    carry(t, server);
}

/// Forced HTTP: the same gateway is an error that suggests RPC over HTTP.
#[test]
fn forced_http_reports_the_missing_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut c = Chan::new(listener.accept().unwrap().0);
        c.head();
        c.send(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    });
    let mut gw = config(GatewayTransport::Http);
    gw.port = port;
    let deadline = Instant::now() + Duration::from_secs(10);
    match connect_with(&gw, &target(), false, deadline, None) {
        Err(Error::Unsupported(m)) => assert!(m.contains("RPC over HTTP"), "{m}"),
        Err(e) => panic!("wrong error {e}"),
        Ok(_) => panic!("tunnel opened"),
    }
    server.join().unwrap();
}
