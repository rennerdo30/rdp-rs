//! Loopback tests of the tunnel state machine against a fake gateway that
//! speaks the MS-TSGU HTTP transport over a plain-TCP WebSocket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::packets as p;
use super::*;
use crate::cursor::{Put, utf16le};
use crate::transport::Framer;

/// What the fake gateway answers.
#[derive(Clone, Copy)]
struct Script {
    /// Status of the reply to the NTLM AUTHENTICATE request (101 = accept).
    auth_status: u16,
    /// errorCode of HTTP_TUNNEL_AUTH_RESPONSE.
    tunnel_auth_error: u32,
}

const OK: Script = Script {
    auth_status: 101,
    tunnel_auth_error: 0,
};

/// Bytes the client is asked to send through the tunnel.
const PAYLOAD_LEN: usize = 40_000;

fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|i| (i * 7 % 251) as u8).collect()
}

struct Peer {
    sock: TcpStream,
    buf: Vec<u8>,
    stream: Vec<u8>,
}

enum Event {
    Packet(u16, Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

impl Peer {
    fn more(&mut self) {
        let mut tmp = [0u8; 65536];
        let n = self.sock.read(&mut tmp).expect("fake gateway read");
        assert!(n > 0, "client closed early");
        self.buf.extend_from_slice(&tmp[..n]);
    }

    /// One HTTP request head.
    fn request(&mut self) -> String {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8(self.buf.drain(..end + 4).collect()).unwrap();
                return head;
            }
            self.more();
        }
    }

    /// The next client event; asserts every client frame is masked.
    fn event(&mut self) -> Event {
        loop {
            if let Some(n) = p::packet_len(&self.stream).unwrap()
                && self.stream.len() >= n
            {
                let pkt: Vec<u8> = self.stream.drain(..n).collect();
                let (t, body) = p::split(&pkt);
                return Event::Packet(t, body.to_vec());
            }
            if self.buf.len() >= 2 {
                assert!(self.buf[1] & 0x80 != 0, "client frame not masked");
            }
            match ws::decode(&mut self.buf).unwrap() {
                None => self.more(),
                Some(f) => match f.opcode {
                    ws::OP_BINARY | ws::OP_CONTINUATION => self.stream.extend(f.payload),
                    ws::OP_PONG => return Event::Pong(f.payload),
                    ws::OP_CLOSE => return Event::Close,
                    op => panic!("unexpected client opcode {op}"),
                },
            }
        }
    }

    fn packet(&mut self) -> (u16, Vec<u8>) {
        match self.event() {
            Event::Packet(t, b) => (t, b),
            _ => panic!("expected a packet"),
        }
    }

    /// An unmasked server frame.
    fn frame(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(payload);
        self.sock.write_all(&f).unwrap();
    }

    fn send(&mut self, pkt: &[u8]) {
        self.frame(true, ws::OP_BINARY, pkt);
    }
}

fn header<'a>(head: &'a str, name: &str) -> &'a str {
    head.split("\r\n")
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("no {name} header in {head:?}"))
}

/// A CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) with extended session security.
fn ntlm_challenge() -> Vec<u8> {
    let mut ti = Vec::new();
    ti.put_u16(2); // MsvAvNbDomainName
    ti.put_u16(4);
    ti.put_bytes(&utf16le("DM"));
    ti.put_u32(0); // MsvAvEOL
    let mut m = b"NTLMSSP\0".to_vec();
    m.put_u32(2);
    m.put_u16(0);
    m.put_u16(0);
    m.put_u32(56); // TargetNameFields
    m.put_u32(0xE289_8235); // includes NEGOTIATE_EXTENDED_SESSIONSECURITY
    m.put_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]);
    m.put_zeros(8);
    m.put_u16(ti.len() as u16);
    m.put_u16(ti.len() as u16);
    m.put_u32(56);
    m.put_bytes(&[10, 0, 0x61, 0x4A, 0, 0, 0, 0x0F]);
    m.put_bytes(&ti);
    m
}

fn ntlm_message(head: &str, kind: u8) {
    let auth = header(head, "Authorization");
    let token = auth.strip_prefix("NTLM ").expect("NTLM scheme");
    let msg = ws::base64_decode(token).unwrap();
    assert_eq!(&msg[..8], b"NTLMSSP\0");
    assert_eq!(msg[8], kind);
}

/// The fake gateway. Returns the bytes the client tunnelled to it.
fn fake_gateway(listener: TcpListener, script: Script) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut peer = Peer {
            sock,
            buf: Vec::new(),
            stream: Vec::new(),
        };

        // MS-TSGU 3.3.5.1 over a WebSocket Upgrade, NTLM in HTTP headers.
        let head = peer.request();
        assert!(head.starts_with("GET /remoteDesktopGateway/ HTTP/1.1\r\n"));
        assert_eq!(header(&head, "Upgrade"), "websocket");
        assert_eq!(header(&head, "Sec-WebSocket-Version"), "13");
        assert!(header(&head, "RDG-Connection-Id").starts_with('{'));
        ntlm_message(&head, 1);
        let challenge = ws::base64_encode(&ntlm_challenge());
        let reply = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n\
             WWW-Authenticate: NTLM {challenge}\r\nContent-Length: 4\r\n\r\nnope"
        );
        peer.sock.write_all(reply.as_bytes()).unwrap();

        let head = peer.request();
        ntlm_message(&head, 3);
        if script.auth_status != 101 {
            let reply = format!(
                "HTTP/1.1 {} Denied\r\nContent-Length: 0\r\n\r\n",
                script.auth_status
            );
            peer.sock.write_all(reply.as_bytes()).unwrap();
            return Vec::new();
        }
        let accept = ws::accept_key(header(&head, "Sec-WebSocket-Key"));
        let reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        peer.sock.write_all(reply.as_bytes()).unwrap();

        // 3.3.5.2: handshake. The reply comes after a keep-alive and is split
        // over a binary frame and a continuation frame.
        assert_eq!(
            peer.packet(),
            (p::PKT_TYPE_HANDSHAKE_REQUEST, vec![1, 0, 0, 0, 0, 0])
        );
        peer.send(&p::keepalive());
        let mut hs = vec![2, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        peer.frame(false, ws::OP_BINARY, &hs[..5]);
        hs.extend_from_slice(&[0, 0]);
        peer.frame(true, ws::OP_CONTINUATION, &hs[5..]);

        let (t, body) = peer.packet();
        assert_eq!(t, p::PKT_TYPE_TUNNEL_CREATE);
        assert_eq!(&body[4..6], &[0, 0], "no optional tunnel fields");
        peer.send(&[
            5, 0, 0, 0, 26, 0, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 6, 0, 0, 0, 0x0A, 0, 0, 0,
        ]);

        let (t, body) = peer.packet();
        assert_eq!(t, p::PKT_TYPE_TUNNEL_AUTH);
        assert_eq!(&body[4..4 + 12], &utf16le("CLIENT")[..]);
        let mut auth = script.tunnel_auth_error.to_le_bytes().to_vec();
        auth.extend_from_slice(&[0, 0, 0, 0]);
        peer.send(&[&[7, 0, 0, 0, 16, 0, 0, 0][..], &auth].concat());
        if script.tunnel_auth_error != 0 {
            return Vec::new();
        }

        let (t, body) = peer.packet();
        assert_eq!(t, p::PKT_TYPE_CHANNEL_CREATE);
        assert_eq!(&body[..6], &[1, 0, 0x3D, 0x0D, 3, 0]);
        assert_eq!(&body[8..8 + 12], &utf16le("target")[..]);
        peer.send(&[9, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);

        // 3.3.5.4: RDP bytes in HTTP_DATA_PACKETs, each at most 64 KiB.
        let mut got = Vec::new();
        while got.len() < PAYLOAD_LEN {
            let (t, body) = peer.packet();
            assert_eq!(t, p::PKT_TYPE_DATA);
            got.extend_from_slice(p::parse_data(&body).unwrap());
        }
        // Echo in two data packets with a keep-alive between, in one frame;
        // a ping first.
        peer.frame(true, ws::OP_PING, b"p1");
        let mut echo = p::data(&got[..30_000]);
        echo.extend(p::keepalive());
        echo.extend(p::data(&got[30_000..]));
        peer.sock
            .write_all(&[&[0x82, 127][..], &(echo.len() as u64).to_be_bytes(), &echo].concat())
            .unwrap();
        match peer.event() {
            Event::Pong(b) => assert_eq!(b, b"p1"),
            Event::Packet(t, _) => panic!("unexpected packet {t:#x}"),
            Event::Close => panic!("unexpected close"),
        }

        // 3.3.5.5: the gateway closes the channel; the client confirms.
        peer.send(&p::close(p::PKT_TYPE_CLOSE_CHANNEL, 0));
        assert_eq!(
            peer.packet(),
            (p::PKT_TYPE_CLOSE_CHANNEL_RESPONSE, vec![0; 4])
        );
        got
    })
}

fn tunnel(script: Script) -> (Result<Tunnel>, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = fake_gateway(listener, script);
    let sock = TcpStream::connect(addr).unwrap();
    let gw = GatewayConfig::new("gw.test", "DOM\\alice", "secret");
    let deadline = Instant::now() + Duration::from_secs(10);
    (
        open(sock, &gw, false, "target", 3389, "CLIENT", deadline, None),
        server,
    )
}

#[test]
fn tunnel_carries_rdp_bytes_both_ways() {
    let (t, server) = tunnel(OK);
    let t = t.expect("tunnel up");
    assert!(t.certificate.is_none());
    let mut f = Framer::over(Box::new(t.stream), Box::new(t.reader));
    let deadline = Instant::now() + Duration::from_secs(10);

    let data = payload();
    f.write(&data).unwrap();
    assert_eq!(f.read_exact(PAYLOAD_LEN, deadline).unwrap(), data);

    // After the channel close the stream ends like a TCP close.
    let end = f.read_frame(Some(deadline));
    assert!(
        matches!(end, Err(Error::ConnectionLost(_))),
        "{:?}",
        end.err()
    );
    assert_eq!(server.join().unwrap(), data);
}

#[test]
fn rejected_credentials_are_an_auth_error() {
    let (t, server) = tunnel(Script {
        auth_status: 401,
        ..OK
    });
    match t {
        Err(Error::Auth(m)) => assert!(m.contains("rejected the credentials"), "{m}"),
        Err(e) => panic!("wrong error {e}"),
        Ok(_) => panic!("tunnel opened"),
    }
    server.join().unwrap();
}

#[test]
fn tunnel_auth_denial_names_the_policy() {
    let (t, server) = tunnel(Script {
        tunnel_auth_error: 0x8007_59DB,
        ..OK
    });
    match t {
        Err(Error::Auth(m)) => assert!(m.contains("connection policy"), "{m}"),
        Err(e) => panic!("wrong error {e}"),
        Ok(_) => panic!("tunnel opened"),
    }
    server.join().unwrap();
}

#[test]
fn vectored_writes_share_one_data_packet() {
    // TLS hands its records over as several slices; each slice in a
    // packet of its own would multiply the per-packet overhead.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut s = GatewayStream {
        link: Arc::new(Mutex::new(Link { sock, tls: None })),
        closed: false,
    };
    let big = vec![7u8; p::MAX_DATA];
    let n = s
        .write_vectored(&[
            IoSlice::new(b"abc"),
            IoSlice::new(b"de"),
            IoSlice::new(&big),
        ])
        .unwrap();
    assert_eq!(n, p::MAX_DATA, "fills one packet");
    let mut buf = Vec::new();
    let frame = loop {
        if let Some(f) = ws::decode(&mut buf).unwrap() {
            break f;
        }
        let mut tmp = [0u8; 65536];
        let k = peer.read(&mut tmp).unwrap();
        assert!(k > 0);
        buf.extend_from_slice(&tmp[..k]);
    };
    let (t, body) = p::split(&frame.payload);
    assert_eq!(t, p::PKT_TYPE_DATA);
    let data = p::parse_data(body).unwrap();
    assert_eq!(&data[..5], b"abcde");
    assert_eq!(data.len(), p::MAX_DATA);
}

#[test]
fn debug_output_hides_the_password() {
    let gw = GatewayConfig::new("gw.test", "alice", "hunter2-secret");
    let s = format!("{gw:?}");
    assert!(s.contains("gw.test") && s.contains("443"));
    assert!(!s.contains("hunter2"), "{s}");
}
