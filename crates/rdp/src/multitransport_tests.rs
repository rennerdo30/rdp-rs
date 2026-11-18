use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rustls::ServerConnection;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

const COOKIE: [u8; 16] = [
    0xe2, 0xf0, 0xd1, 0x08, 0x56, 0x7f, 0xb4, 0x3a, 0xdc, 0xf4, 0xb3, 0xdc, 0x16, 0x92, 0x1e, 0x3a,
];

fn request() -> InitiateRequest {
    InitiateRequest {
        request_id: 7,
        protocol: PROTOCOL_UDPFECR,
        cookie: COOKIE,
    }
}

#[test]
fn spec_tunnel_create_request() {
    // MS-RDPEMT 4.1, from its annotations.
    let want = hex("00 18 00 04 07 00 00 00 00 00 00 00 \
         e2 f0 d1 08 56 7f b4 3a dc f4 b3 dc 16 92 1e 3a");
    assert_eq!(tunnel_create_request(&request()), want);
    let (pdu, n) = split_tunnel_pdu(&want).unwrap().unwrap();
    assert_eq!(
        (pdu.action, n, pdu.payload.len()),
        (ACTION_CREATEREQUEST, 28, 24)
    );
}

#[test]
fn spec_tunnel_create_response() {
    // MS-RDPEMT 4.2.
    let want = hex("01 04 00 04 00 00 00 00");
    assert_eq!(tunnel_create_response(S_OK), want);
    let (pdu, n) = split_tunnel_pdu(&want).unwrap().unwrap();
    assert_eq!(pdu.action, ACTION_CREATERESPONSE);
    assert_eq!((n, pdu.payload), (8, &[0u8; 4][..]));
}

#[test]
fn tunnel_data_framing() {
    let d = tunnel_data(b"\x30\x05hello").unwrap();
    assert_eq!(&d[..4], &[0x02, 7, 0, 4]);
    // Incomplete: wait for more.
    assert_eq!(split_tunnel_pdu(&d[..3]).unwrap(), None);
    assert_eq!(split_tunnel_pdu(&d[..8]).unwrap(), None);
    let (pdu, n) = split_tunnel_pdu(&d).unwrap().unwrap();
    assert_eq!((pdu.payload, n), (&b"\x30\x05hello"[..], 11));
    // A subheader (an auto-detect request, MS-RDPEMT 2.2.1.1.1) is skipped.
    let with_sub = hex("02 02 00 08 04 00 aa bb 30 05");
    let (pdu, n) = split_tunnel_pdu(&with_sub).unwrap().unwrap();
    assert_eq!(pdu.subheaders, &[0x04, 0x00, 0xaa, 0xbb]);
    assert_eq!((pdu.payload, n), (&[0x30u8, 0x05][..], 10));
    // HeaderLength below 4 is an error.
    assert!(split_tunnel_pdu(&hex("02 00 00 03")).is_err());
    assert!(tunnel_data(&vec![0; 65536]).is_err());
}

#[test]
fn initiate_request_and_response() {
    // MS-RDPBCGR 2.2.15.1: Basic Security Header (SEC_TRANSPORT_REQ),
    // requestId, requestedProtocol, reserved, securityCookie.
    let mut pdu = hex("02 00 00 00 07 00 00 00 01 00 00 00");
    pdu.extend(COOKIE);
    let r = parse_initiate_request(&pdu).unwrap().unwrap();
    assert_eq!(r, request());
    // The cookie never shows in a log.
    assert!(!format!("{r:?}").contains("226"));
    assert!(format!("{r:?}").contains("redacted"));
    // Not a transport request: a heartbeat, or too short.
    assert_eq!(
        parse_initiate_request(&hex("00 40 00 00 00 05 02 03")).unwrap(),
        None
    );
    assert_eq!(parse_initiate_request(&[2]).unwrap(), None);
    assert!(parse_initiate_request(&pdu[..20]).is_err());
    // 2.2.15.2: SEC_TRANSPORT_RSP, requestId, hrResponse.
    assert_eq!(
        initiate_response(7, E_ABORT),
        hex("04 00 00 00 07 00 00 00 04 40 00 80")
    );
    assert_eq!(
        initiate_response(0x1234, S_OK),
        hex("04 00 00 00 34 12 00 00 00 00 00 00")
    );
}

#[test]
fn records_split_on_their_boundaries() {
    let mut buf = hex("16 03 03 00 02 aa bb");
    buf.extend(hex("17 03 03 00 01 cc"));
    buf.extend(hex("17 03"));
    let r = split_records(&buf);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0], &hex("16 03 03 00 02 aa bb")[..]);
    assert_eq!(r[1], &hex("17 03 03 00 01 cc")[..]);
    assert_eq!(r[2], &[0x17, 0x03]);
}

/// Datagrams in flight between the tunnel and the fake server, with loss,
/// duplicates and reordering from a fixed seed.
#[derive(Default)]
struct Wire {
    to_server: Vec<Vec<u8>>,
    to_client: VecDeque<Vec<u8>>,
}

struct MemSock(Arc<Mutex<Wire>>, bool);

impl DatagramSocket for MemSock {
    fn send(&mut self, d: &[u8]) -> io::Result<()> {
        self.0.lock().unwrap().to_server.push(d.to_vec());
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if self.1 {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        Ok(self.0.lock().unwrap().to_client.pop_front().map(|d| {
            buf[..d.len()].copy_from_slice(&d);
            d.len()
        }))
    }
}

fn identity(name: &str) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

/// The server side: RDP-UDP-R, rustls and the tunnel PDUs. It echoes
/// every Tunnel Data PDU back with "re:" in front.
struct FakeServer {
    udp: Option<Endpoint>,
    tls: ServerConnection,
    plain: Vec<u8>,
    hr: u32,
    create: Option<(u32, [u8; 16])>,
    data: Vec<Vec<u8>>,
}

impl FakeServer {
    fn new(cert: &[u8], key: &[u8], hr: u32) -> FakeServer {
        let config = crate::server::transport::tls_config(cert.to_vec(), key.to_vec()).unwrap();
        FakeServer {
            udp: None,
            tls: ServerConnection::new(config).unwrap(),
            plain: Vec::new(),
            hr,
            create: None,
            data: Vec::new(),
        }
    }

    fn step(&mut self, incoming: Vec<Vec<u8>>, now: Instant) -> Vec<Vec<u8>> {
        for d in incoming {
            match &mut self.udp {
                Some(u) => u.on_datagram(&d, now),
                None => self.udp = Some(Endpoint::accept(&d, 0x5000, now).unwrap()),
            }
        }
        let Some(udp) = self.udp.as_mut() else {
            return Vec::new();
        };
        let cipher = udp.take_incoming();
        let mut rd = &cipher[..];
        let mut tmp = [0u8; 4096];
        loop {
            if !rd.is_empty() {
                self.tls.read_tls(&mut rd).unwrap();
                self.tls.process_new_packets().unwrap();
            }
            while let Ok(n) = self.tls.reader().read(&mut tmp) {
                if n == 0 {
                    break;
                }
                self.plain.extend_from_slice(&tmp[..n]);
            }
            if rd.is_empty() {
                break;
            }
        }
        while let Some((pdu, n)) = split_tunnel_pdu(&self.plain).unwrap() {
            match pdu.action {
                ACTION_CREATEREQUEST => {
                    let mut r = Reader::new(pdu.payload);
                    let id = r.u32().unwrap();
                    r.skip(4).unwrap();
                    self.create = Some((id, r.array().unwrap()));
                    self.tls
                        .writer()
                        .write_all(&tunnel_create_response(self.hr))
                        .unwrap();
                }
                ACTION_DATA => {
                    self.data.push(pdu.payload.to_vec());
                    let echo = [b"re:".as_slice(), pdu.payload].concat();
                    self.tls
                        .writer()
                        .write_all(&tunnel_data(&echo).unwrap())
                        .unwrap();
                }
                _ => panic!("unexpected action"),
            }
            self.plain.drain(..n);
        }
        let mut out = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut out).unwrap();
        }
        for r in split_records(&out) {
            udp.send(r);
        }
        udp.poll(now)
    }
}

struct Rig {
    now: Instant,
    wire: Arc<Mutex<Wire>>,
    tunnel: Tunnel,
    server: FakeServer,
    rng: u64,
    loss: u64,
    events: Vec<TunnelEvent>,
}

impl Rig {
    fn new(server_cert: (&[u8], &[u8]), tcp_cert: &[u8], hr: u32, loss: u64) -> Rig {
        let now = Instant::now();
        let wire = Arc::new(Mutex::new(Wire::default()));
        let sock = Box::new(MemSock(wire.clone(), false));
        Rig {
            now,
            tunnel: Tunnel::start(sock, request(), "rdp.test", tcp_cert.to_vec(), now),
            wire,
            server: FakeServer::new(server_cert.0, server_cert.1, hr),
            rng: 42,
            loss,
            events: Vec::new(),
        }
    }

    fn lost(&mut self) -> bool {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) % 100 < self.loss
    }

    fn step(&mut self) {
        self.now += Duration::from_millis(2);
        let now = self.now;
        self.events.extend(self.tunnel.poll(now));
        let up: Vec<_> = std::mem::take(&mut self.wire.lock().unwrap().to_server);
        let up: Vec<_> = up.into_iter().filter(|_| !self.lost()).collect();
        let down = self.server.step(up, now);
        for d in down {
            if !self.lost() {
                // Reordered: every other datagram jumps the queue.
                let mut w = self.wire.lock().unwrap();
                if self.rng % 2 == 0 {
                    w.to_client.push_front(d);
                } else {
                    w.to_client.push_back(d);
                }
            }
        }
    }

    fn run(&mut self, steps: usize, done: impl Fn(&Rig) -> bool) -> bool {
        for _ in 0..steps {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }
}

fn failed(ev: &[TunnelEvent]) -> Option<&str> {
    ev.iter().find_map(|e| match e {
        TunnelEvent::Failed(m) => Some(m.as_str()),
        _ => None,
    })
}

fn tunnel_carries_data(loss: u64) {
    let (cert, key) = identity("rdp.test");
    let mut rig = Rig::new((&cert, &key), &cert, S_OK, loss);
    assert!(
        rig.run(5_000, |r| r.tunnel.phase() == Phase::Ready),
        "not ready: {:?}",
        rig.events
    );
    assert_eq!(rig.events, vec![TunnelEvent::Ready]);
    // The server saw the request ID and cookie of the Initiate Request.
    assert_eq!(rig.server.create, Some((7, COOKIE)));
    // DVC PDUs both ways, some larger than one datagram.
    let msgs: Vec<Vec<u8>> = (0..40u32)
        .map(|i| (0..(i * 97 % 3000 + 1)).map(|b| (b + i) as u8).collect())
        .collect();
    for m in &msgs {
        rig.tunnel.send(m).unwrap();
    }
    let n = msgs.len();
    assert!(rig.run(20_000, |r| r.events.len() > n));
    assert_eq!(rig.server.data, msgs);
    let echoes: Vec<Vec<u8>> = rig.events[1..]
        .iter()
        .map(|e| match e {
            TunnelEvent::Data(d) => d.clone(),
            e => panic!("{e:?}"),
        })
        .collect();
    let want: Vec<Vec<u8>> = msgs
        .iter()
        .map(|m| [b"re:".as_slice(), m].concat())
        .collect();
    assert_eq!(echoes, want);
}

#[test]
fn tunnel_setup_and_data_on_a_clean_link() {
    tunnel_carries_data(0);
}

#[test]
fn tunnel_setup_and_data_with_loss_and_reordering() {
    tunnel_carries_data(10);
}

#[test]
fn another_certificate_on_udp_fails_the_tunnel() {
    let (cert, key) = identity("rdp.test");
    let (tcp_cert, _) = identity("rdp.test");
    let mut rig = Rig::new((&cert, &key), &tcp_cert, S_OK, 0);
    assert!(rig.run(5_000, |r| r.tunnel.phase() == Phase::Failed));
    assert!(failed(&rig.events).unwrap().contains("certificate"));
    // The cookie never went out to that server.
    assert_eq!(rig.server.create, None);
    assert!(rig.tunnel.send(b"x").is_err());
}

#[test]
fn a_refused_tunnel_fails() {
    let (cert, key) = identity("rdp.test");
    let mut rig = Rig::new((&cert, &key), &cert, 0x8000_4005, 0);
    assert!(rig.run(5_000, |r| r.tunnel.phase() == Phase::Failed));
    assert!(failed(&rig.events).unwrap().contains("refused"));
}

#[test]
fn a_silent_server_fails_the_tunnel_in_time() {
    let (cert, key) = identity("rdp.test");
    let mut rig = Rig::new((&cert, &key), &cert, S_OK, 100);
    assert!(rig.run(10_000, |r| r.tunnel.phase() == Phase::Failed));
    assert!(rig.now - rig.tunnel.started <= SETUP_TIMEOUT + Duration::from_millis(10));
    assert_eq!(rig.events.len(), 1);
    // Nothing more after the failure.
    rig.run(100, |_| false);
    assert_eq!(rig.events.len(), 1);
}

#[test]
fn an_unreachable_port_fails_at_once() {
    let now = Instant::now();
    let wire = Arc::new(Mutex::new(Wire::default()));
    let mut t = Tunnel::start(
        Box::new(MemSock(wire, true)),
        request(),
        "rdp.test",
        vec![1],
        now,
    );
    let ev = t.poll(now);
    assert!(failed(&ev).unwrap().contains("unreachable"));
    assert_eq!(t.phase(), Phase::Failed);
}
