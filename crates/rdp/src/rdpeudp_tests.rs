use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn spec_syn_example_parses() {
    // MS-RDPEUDP 4.1.1, zero-padded to 1232 bytes.
    let mut d = hex("ff ff ff ff 04 00 0A 01 00 00 00 42 04 D0 04 D0 \
         D2 35 AC 43 89 41 42 DA B1 0E DD 68 87 F7 F9 FB");
    d.resize(1232, 0);
    let p = parse(&d).unwrap();
    assert_eq!(
        p.header,
        FecHeader {
            sn_source_ack: 0xFFFF_FFFF,
            receive_window: 1024,
            flags: FLAG_CORRELATION_ID | FLAG_SYNLOSSY | FLAG_SYN,
        }
    );
    assert_eq!(
        p.syn,
        Some(SynData {
            initial_seq: 0x42,
            up_mtu: 1232,
            down_mtu: 1232
        })
    );
    assert_eq!(p.correlation_id.unwrap()[..4], [0xD2, 0x35, 0xAC, 0x43]);
    assert_eq!(p.synex, None);
    assert_eq!(p.ack_vector, None);
}

#[test]
fn spec_syn_ack_example_parses() {
    // MS-RDPEUDP 4.1.2 (its table: flags SYN | ACK).
    let mut d = hex("00 00 00 42 04 00 00 05 00 00 00 42 04 D0 04 D0");
    d.resize(1232, 0);
    let p = parse(&d).unwrap();
    assert_eq!(p.header.sn_source_ack, 0x42);
    assert_eq!(p.header.flags, FLAG_SYN | FLAG_ACK);
    assert_eq!(p.syn.unwrap().initial_seq, 0x42);
    // No ACK vector in a SYN+ACK, although RDPUDP_FLAG_ACK is set.
    assert_eq!(p.ack_vector, None);
}

#[test]
fn spec_source_packet_example_parses() {
    // MS-RDPEUDP 4.2.1.
    let d = hex(
        "d6 cf 0a b8 04 00 00 0c 00 01 04 00 ec 47 1a e4 ec 47 1a e4 \
         17 03 03 00 40 bb",
    );
    let p = parse(&d).unwrap();
    assert_eq!(p.header.sn_source_ack, 0xd6cf_0ab8);
    assert_eq!(p.header.receive_window, 1024);
    assert_eq!(p.header.flags, FLAG_DATA | FLAG_ACK);
    assert_eq!(p.ack_vector, Some(&[0x04][..]));
    assert_eq!(
        p.source,
        Some(SourceHeader {
            coded: 0xec47_1ae4,
            source_start: 0xec47_1ae4
        })
    );
    // The payload is a TLS application data record.
    assert_eq!(p.payload, &[0x17, 0x03, 0x03, 0x00, 0x40, 0xbb]);
}

#[test]
fn spec_fec_packet_example_parses() {
    // MS-RDPEUDP 4.2.2, the capture line.
    let d = hex(
        "d6 cf 0a cb 04 00 00 1c 00 01 04 00 ec 47 1a fd ec 47 1a fd \
         10 01 00 00 40 25 04 f1",
    );
    let p = parse(&d).unwrap();
    assert_eq!(p.header.flags, FLAG_FEC | FLAG_DATA | FLAG_ACK);
    assert_eq!(
        p.fec,
        Some(FecPayloadHeader {
            coded: 0xec47_1afd,
            source_start: 0xec47_1afd,
            range: 0x10,
            fec_index: 0x01
        })
    );
    assert_eq!(p.source, None);
    assert_eq!(p.payload, &[0x40, 0x25, 0x04, 0xf1]);
}

#[test]
fn spec_ack_of_acks_example_parses() {
    // MS-RDPEUDP 4.2.3.
    let d = hex(
        "d6 cf 0a b8 04 00 01 0c 00 01 04 00 d6 cf 0a b8 ec 47 1a e4 \
         ec 47 1a e4 17 03 03 00",
    );
    let p = parse(&d).unwrap();
    assert_eq!(p.header.flags, FLAG_ACK_OF_ACKS | FLAG_DATA | FLAG_ACK);
    assert_eq!(p.ack_of_acks, Some(0xd6cf_0ab8));
    assert_eq!(p.source.unwrap().source_start, 0xec47_1ae4);
    assert_eq!(p.payload, &[0x17, 0x03, 0x03, 0x00]);
    // Our encoder writes the same bytes.
    let again = ack_datagram(
        FecHeader {
            sn_source_ack: 0xd6cf_0ab8,
            receive_window: 1024,
            flags: 0,
        },
        &[0x04],
        Some(0xd6cf_0ab8),
        Some((p.source.unwrap(), p.payload)),
    );
    assert_eq!(again, d);
}

#[test]
fn truncated_datagrams_are_errors_not_panics() {
    let mut syn = Endpoint::client(7, Instant::now()).syn.clone();
    syn.truncate(30);
    let samples = [
        hex("d6 cf 0a b8 04 00 01 0c 00 01 04 00 d6 cf 0a b8 ec 47 1a e4 ec 47 1a e4"),
        hex("d6 cf 0a cb 04 00 00 1c 00 01 04 00 ec 47 1a fd ec 47 1a fd 10 01 00 00"),
        syn,
    ];
    for s in &samples {
        for n in 0..s.len() {
            let _ = parse(&s[..n]);
        }
    }
    assert!(parse(&samples[0][..23]).is_err());
    // An ACK vector longer than 2048 bytes is refused.
    let mut big = hex("00 00 00 01 04 00 00 04 08 01");
    big.resize(10 + 2049, 0);
    assert!(parse(&big).is_err());
}

#[test]
fn client_syn_offers_version_2_and_is_padded() {
    let e = Endpoint::client(0x1234_5678, Instant::now());
    assert_eq!(e.syn.len(), 1232);
    let p = parse(&e.syn).unwrap();
    assert_eq!(p.header.sn_source_ack, u32::MAX);
    assert_eq!(p.header.flags, FLAG_SYN | FLAG_SYNEX);
    assert_eq!(p.header.receive_window, RECEIVE_WINDOW);
    assert_eq!(p.syn.unwrap().initial_seq, 0x1234_5678);
    assert_eq!(
        p.synex,
        Some(SynEx {
            flags: VERSION_INFO_VALID,
            version: VERSION_2,
            cookie_hash: None
        })
    );
    // Bytes 16..20: uSynExFlags and uUdpVer, then zero padding.
    assert_eq!(&e.syn[16..20], &[0, 1, 0, 2]);
    assert!(e.syn[20..].iter().all(|&b| b == 0));
}

#[test]
fn version_3_syn_carries_the_cookie_hash() {
    let syn = syn_datagram(
        None,
        64,
        SynData {
            initial_seq: 1,
            up_mtu: 1232,
            down_mtu: 1232,
        },
        Some(SynEx {
            flags: VERSION_INFO_VALID,
            version: VERSION_3,
            cookie_hash: Some([0xAB; 32]),
        }),
    );
    let p = parse(&syn).unwrap();
    assert_eq!(p.synex.unwrap().cookie_hash, Some([0xAB; 32]));
}

#[test]
fn ack_vector_runs() {
    // Five received: one element, length field 4 (run minus one).
    assert_eq!(encode_ack_vector([true; 5]), vec![0x04]);
    // A gap: received 3, not received 1, received 2.
    let v = encode_ack_vector([true, true, true, false, true, true]);
    assert_eq!(v, vec![0x02, 0xC0, 0x01]);
    assert_eq!(
        decode_ack_vector(&v).collect::<Vec<_>>(),
        vec![(true, 3), (false, 1), (true, 2)]
    );
    // Runs are at most 64 long.
    let v = encode_ack_vector([true; 130]);
    assert_eq!(v, vec![0x3F, 0x3F, 0x01]);
    assert_eq!(decode_ack_vector(&v).map(|r| r.1).sum::<u32>(), 130);
    assert!(encode_ack_vector([]).is_empty());
}

/// A simulated network between a client and a server endpoint: loss,
/// duplicates and reordering from a fixed seed, on a simulated clock.
struct Net {
    rng: u64,
    loss: u32,
    dup: u32,
    jitter_ms: u64,
    flying: Vec<(Instant, bool, Vec<u8>)>,
}

impl Net {
    fn rand(&mut self) -> u64 {
        // SplitMix64.
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn send(&mut self, now: Instant, to_server: bool, d: Vec<u8>) {
        if (self.rand() % 100) < self.loss as u64 {
            return;
        }
        let copies = if (self.rand() % 100) < self.dup as u64 {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let delay = 5 + self.rand() % (self.jitter_ms + 1);
            self.flying
                .push((now + Duration::from_millis(delay), to_server, d.clone()));
        }
    }

    fn due(&mut self, now: Instant) -> Vec<(bool, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.flying.len() {
            if self.flying[i].0 <= now {
                let (_, s, d) = self.flying.swap_remove(i);
                out.push((s, d));
            } else {
                i += 1;
            }
        }
        out
    }
}

struct Pair {
    now: Instant,
    client: Endpoint,
    server: Option<Endpoint>,
    net: Net,
    got_client: Vec<u8>,
    got_server: Vec<u8>,
}

impl Pair {
    fn new(loss: u32, dup: u32, jitter_ms: u64, seed: u64) -> Pair {
        let now = Instant::now();
        Pair {
            now,
            client: Endpoint::client(0xFFFF_FFF0, now),
            server: None,
            net: Net {
                rng: seed,
                loss,
                dup,
                jitter_ms,
                flying: Vec::new(),
            },
            got_client: Vec::new(),
            got_server: Vec::new(),
        }
    }

    /// One millisecond of simulated time.
    fn step(&mut self) {
        self.now += Duration::from_millis(1);
        let now = self.now;
        for (to_server, d) in self.net.due(now) {
            if to_server {
                match &mut self.server {
                    Some(s) => s.on_datagram(&d, now),
                    None => self.server = Some(Endpoint::accept(&d, 0x7FFF_FFF8, now).unwrap()),
                }
            } else {
                self.client.on_datagram(&d, now);
            }
        }
        for d in self.client.poll(now) {
            self.net.send(now, true, d);
        }
        if let Some(s) = &mut self.server {
            for d in s.poll(now) {
                self.net.send(now, false, d);
            }
            self.got_server.extend(s.take_incoming());
        }
        self.got_client.extend(self.client.take_incoming());
    }

    fn run_until(&mut self, ms: u32, done: impl Fn(&Pair) -> bool) -> bool {
        for _ in 0..ms {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }
}

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

#[test]
fn handshake_on_a_clean_link() {
    let mut p = Pair::new(0, 0, 0, 1);
    assert!(p.run_until(200, |p| {
        p.client.state() == State::Established
            && p.server
                .as_ref()
                .is_some_and(|s| s.state() == State::Established)
    }));
    assert_eq!(p.client.version(), VERSION_2);
    assert_eq!(p.client.max_payload(), 1232 - 64);
}

fn transfer(loss: u32, dup: u32, jitter: u64, seed: u64) -> Pair {
    let mut p = Pair::new(loss, dup, jitter, seed);
    let up = pattern(300_000, 1);
    let down = pattern(400_000, 2);
    // Written in uneven pieces, some larger than one datagram.
    for c in up.chunks(1500) {
        p.client.send(c);
    }
    assert!(p.run_until(5_000, |p| p.server.is_some()));
    for c in down.chunks(700) {
        p.server.as_mut().unwrap().send(c);
    }
    let ok = p.run_until(120_000, |p| {
        p.got_server.len() >= up.len() && p.got_client.len() >= down.len()
    });
    assert!(
        ok,
        "transfer incomplete: up {} / {}, down {} / {}; client {:?}, server {:?}",
        p.got_server.len(),
        up.len(),
        p.got_client.len(),
        down.len(),
        p.client.close_reason(),
        p.server
            .as_ref()
            .map(|s| (s.state(), s.close_reason(), s.recv_next))
    );
    assert_eq!(p.got_server, up, "client to server stream differs");
    assert_eq!(p.got_client, down, "server to client stream differs");
    assert_eq!(p.client.state(), State::Established);
    p
}

#[test]
fn reliable_delivery_on_a_clean_link() {
    let p = transfer(0, 0, 0, 7);
    assert_eq!(p.client.stats().retransmits, 0);
}

#[test]
fn reliable_delivery_with_loss_duplicates_and_reordering() {
    for seed in [3, 11, 2026] {
        let p = transfer(10, 5, 30, seed);
        let s = p.server.as_ref().unwrap();
        assert!(p.client.stats().retransmits > 0 && s.stats().retransmits > 0);
        assert!(p.client.rtt().is_some());
    }
}

#[test]
fn reliable_delivery_with_heavy_loss() {
    // 20 % each way: one datagram in three needs a retransmission or an
    // answer again, still well inside the retransmit limit.
    transfer(20, 10, 60, 99);
}

#[test]
fn no_answer_closes_after_the_syn_retries() {
    let now = Instant::now();
    let mut c = Endpoint::client(1, now);
    let mut syns = 0;
    for ms in 0..10_000u64 {
        syns += c.poll(now + Duration::from_millis(ms)).len();
        if c.state() == State::Closed {
            break;
        }
    }
    assert_eq!(c.state(), State::Closed);
    // The first SYN and three retries (note <7>).
    assert_eq!(syns, 4);
    assert!(c.close_reason().unwrap().contains("handshake"));
}

#[test]
fn a_silent_peer_ends_the_connection() {
    let mut p = Pair::new(0, 0, 0, 5);
    assert!(p.run_until(200, |p| p.client.state() == State::Established));
    p.client.send(b"hello");
    // The server stops answering: the data is retransmitted until the
    // limit, then the connection closes.
    p.server = None;
    p.net.loss = 100;
    let mut sent = 0;
    for _ in 0..200_000 {
        p.now += Duration::from_millis(10);
        sent += p.client.poll(p.now).len();
        if p.client.state() == State::Closed {
            break;
        }
    }
    assert_eq!(p.client.state(), State::Closed);
    assert!(p.client.close_reason().unwrap().contains("retransmit"));
    // One transmission and five retransmissions, plus any acknowledgements.
    assert!(sent >= 6);
    assert_eq!(p.client.stats().retransmits, RETRANSMIT_LIMIT as u64);
}

#[test]
fn idle_connection_sends_keepalives_and_times_out() {
    let mut p = Pair::new(0, 0, 0, 9);
    assert!(p.run_until(200, |p| p.client.state() == State::Established));
    let start = p.now;
    let mut keepalives = 0;
    while p.now - start < Duration::from_secs(64) {
        p.now += Duration::from_millis(100);
        keepalives += p.client.poll(p.now).len();
    }
    // Every 15 s while nothing else goes out (3.1.1.9).
    assert_eq!(keepalives, 4);
    assert_eq!(p.client.state(), State::Established);
    p.now += Duration::from_secs(2);
    p.client.poll(p.now);
    assert_eq!(p.client.state(), State::Closed);
}

#[test]
fn a_version_3_answer_closes_the_connection() {
    let now = Instant::now();
    let mut c = Endpoint::client(10, now);
    c.poll(now);
    let synack = syn_datagram(
        Some(10),
        64,
        SynData {
            initial_seq: 99,
            up_mtu: 1232,
            down_mtu: 1232,
        },
        Some(SynEx {
            flags: VERSION_INFO_VALID,
            version: VERSION_3,
            cookie_hash: None,
        }),
    );
    c.on_datagram(&synack, now);
    assert_eq!(c.state(), State::Closed);
}

#[test]
fn syn_ack_for_another_syn_and_data_before_it_are_ignored() {
    let now = Instant::now();
    let mut c = Endpoint::client(10, now);
    c.poll(now);
    let sd = SynData {
        initial_seq: 99,
        up_mtu: 1232,
        down_mtu: 1232,
    };
    c.on_datagram(&syn_datagram(Some(11), 64, sd, None), now);
    assert_eq!(c.state(), State::SynSent);
    let data = ack_datagram(
        FecHeader {
            sn_source_ack: 10,
            receive_window: 64,
            flags: 0,
        },
        &[],
        None,
        Some((
            SourceHeader {
                coded: 100,
                source_start: 100,
            },
            b"early",
        )),
    );
    c.on_datagram(&data, now);
    assert!(c.take_incoming().is_empty());
    // Version 1 when the SYN+ACK carries no SYNEX.
    c.on_datagram(&syn_datagram(Some(10), 64, sd, None), now);
    assert_eq!((c.state(), c.version()), (State::Established, VERSION_1));
    // The ACK for the SYN+ACK goes out with an empty vector.
    let out = c.poll(now);
    let p = parse(&out[0]).unwrap();
    assert_eq!(p.header.sn_source_ack, 99);
    assert_eq!(p.ack_vector, Some(&[][..]));
}

#[test]
fn out_of_window_and_duplicate_data_is_not_delivered() {
    let now = Instant::now();
    let mut c = Endpoint::client(10, now);
    c.poll(now);
    let sd = SynData {
        initial_seq: 99,
        up_mtu: 1232,
        down_mtu: 1232,
    };
    c.on_datagram(&syn_datagram(Some(10), 64, sd, None), now);
    let data = |seq: u32, p: &'static [u8]| {
        ack_datagram(
            FecHeader {
                sn_source_ack: 10,
                receive_window: 64,
                flags: 0,
            },
            &[],
            None,
            Some((
                SourceHeader {
                    coded: seq,
                    source_start: seq,
                },
                p,
            )),
        )
    };
    c.on_datagram(&data(100 + RECEIVE_WINDOW as u32, b"far"), now);
    c.on_datagram(&data(101, b"b"), now);
    assert!(c.take_incoming().is_empty());
    c.on_datagram(&data(100, b"a"), now);
    c.on_datagram(&data(100, b"a"), now);
    assert_eq!(c.take_incoming(), b"ab");
    // The acknowledgement covers 100 and 101: one run of two.
    let out = c.poll(now);
    let p = parse(out.last().unwrap()).unwrap();
    assert_eq!(p.header.sn_source_ack, 101);
    assert_eq!(p.ack_vector, Some(&[0x01][..]));
}
