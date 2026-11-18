//! RDP-UDP reliable transport, RDP-UDP-R (MS-RDPEUDP versions 1 and 2).
//!
//! A sans-IO endpoint: the caller hands it every datagram that arrives
//! ([`Endpoint::on_datagram`]) and sends whatever [`Endpoint::poll`]
//! returns; bytes written with [`Endpoint::send`] come out of the peer's
//! [`Endpoint::take_incoming`] in order, exactly once, whatever the network
//! drops, duplicates or reorders. The multitransport tunnel
//! ([`crate::multitransport`]) runs TLS over it.
//!
//! What is implemented, all in network byte order (2.2):
//! - the SYN / SYN+ACK / ACK handshake (1.3.2.1, 3.1.5.1.1 to 3.1.5.1.3),
//!   offering [`VERSION_2`] in the RDPUDP_SYNDATAEX_PAYLOAD. A server that
//!   knows version 3 (MS-RDPEUDP2, Windows 10 1809 / Server 2019 and later)
//!   answers with the highest version both sides know, so version 2;
//! - Source Packets with ACK vectors (2.2.2.7), ACK of ACKs (2.2.2.6),
//!   retransmission on a timer and after three later packets were
//!   acknowledged (3.1.1.4.1, 3.1.1.5, 3.1.6.1), the retransmit limit
//!   (3.1.5.4.1), keepalives and the 65 second silence limit (3.1.1.9);
//! - flow control by the peer's receive window (3.1.1.7) and NewReno-style
//!   congestion control with Congestion Notification / Window Reset
//!   (3.1.1.8).
//!
//! FEC Packets (3.1.1.6) are not sent, and received ones are ignored: they
//! only speed up recovery, and in the reliable mode the sender retransmits
//! what is lost anyway (3.1.1.6.3). The lossy mode (RDP-UDP-L) is not
//! offered: it needs DTLS above it (MS-RDPEMT 1.4).
//!
//! The ACK vector covers the receiver's queue from the ACK-of-ACKs reset
//! point (at first the peer's initial sequence number plus one) up to and
//! including `snSourceAck`; each element's six low bits hold the run length
//! minus one. That is the reading of Microsoft's RDP test suite, which
//! checks exactly these vectors from the Windows client. Received vectors
//! are read from their end (`snSourceAck`) backwards, so a peer that starts
//! its vector somewhere else is still understood.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::cursor::Reader;
use crate::error::{Error, Result, proto};
use crate::trace;

/// RDPUDP_FEC_HEADER uFlags (2.2.2.1).
pub const FLAG_SYN: u16 = 0x0001;
pub const FLAG_FIN: u16 = 0x0002;
pub const FLAG_ACK: u16 = 0x0004;
pub const FLAG_DATA: u16 = 0x0008;
pub const FLAG_FEC: u16 = 0x0010;
pub const FLAG_CN: u16 = 0x0020;
pub const FLAG_CWR: u16 = 0x0040;
pub const FLAG_ACK_OF_ACKS: u16 = 0x0100;
pub const FLAG_SYNLOSSY: u16 = 0x0200;
pub const FLAG_ACKDELAYED: u16 = 0x0400;
pub const FLAG_CORRELATION_ID: u16 = 0x0800;
pub const FLAG_SYNEX: u16 = 0x1000;

/// RDPUDP_SYNDATAEX_PAYLOAD uSynExFlags (2.2.2.9).
pub const VERSION_INFO_VALID: u16 = 0x0001;
/// uUdpVer values (2.2.2.9).
pub const VERSION_1: u16 = 0x0001;
pub const VERSION_2: u16 = 0x0002;
/// Data transfer as MS-RDPEUDP2; not offered by this client.
pub const VERSION_3: u16 = 0x0101;

/// VECTOR_ELEMENT_STATE (2.2.1.1).
pub const DATAGRAM_RECEIVED: u8 = 0;
pub const DATAGRAM_NOT_YET_RECEIVED: u8 = 3;

/// MTU range for uUpStreamMtu / uDownStreamMtu (2.2.2.5, 3.1.1.3).
pub const MAX_MTU: u16 = 1232;
pub const MIN_MTU: u16 = 1132;

/// Receive window this endpoint advertises, in datagrams (2.2.2.1).
pub const RECEIVE_WINDOW: u16 = 1024;
/// Largest uAckVectorSize (2.2.2.7).
const MAX_ACK_VECTOR: usize = 2048;
/// Room a data datagram keeps for its headers and ACK vector: the payload
/// is at most the MTU minus this.
const HEADROOM: usize = 64;
/// SYN retransmissions and their interval (3.1.5.2 and its note <7>:
/// Windows sends the SYN three more times, 800 ms apart).
const SYN_RETRIES: u32 = 3;
const SYN_INTERVAL: Duration = Duration::from_millis(800);
/// Retransmissions of one datagram before the connection is given up
/// (3.1.5.4.1, note <9>: Windows retransmits five times).
const RETRANSMIT_LIMIT: u32 = 5;
/// Retransmit time-out ceiling (3.1.6.1, note <10>).
const MAX_RTO: Duration = Duration::from_secs(120);
/// No datagram from the peer for this long ends the connection (3.1.1.9).
const SILENCE_LIMIT: Duration = Duration::from_secs(65);
/// A keepalive ACK when nothing was sent for this long (note <5>: Windows
/// sends four in 65 seconds).
const KEEPALIVE: Duration = Duration::from_secs(15);
/// ACK of ACKs once the cumulative acknowledgement moved this far (2.2.2.6:
/// SHOULD be sent after every 20 packets).
const ACK_OF_ACKS_EVERY: u32 = 20;
/// Initial congestion window, datagrams.
const INITIAL_CWND: f64 = 10.0;

/// `a < b` in sequence-number space (RFC 793 3.3, 3.1.1.2).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn be16(r: &mut Reader) -> Result<u16> {
    Ok(u16::from_be_bytes(r.array()?))
}

fn be32(r: &mut Reader) -> Result<u32> {
    Ok(u32::from_be_bytes(r.array()?))
}

/// RDPUDP_FEC_HEADER (2.2.2.1): starts every datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecHeader {
    pub sn_source_ack: u32,
    pub receive_window: u16,
    pub flags: u16,
}

/// RDPUDP_SYNDATA_PAYLOAD (2.2.2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynData {
    pub initial_seq: u32,
    pub up_mtu: u16,
    pub down_mtu: u16,
}

/// RDPUDP_SYNDATAEX_PAYLOAD (2.2.2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynEx {
    pub flags: u16,
    pub version: u16,
    /// SHA-256 of the multitransport security cookie; only in a client SYN
    /// offering [`VERSION_3`].
    pub cookie_hash: Option<[u8; 32]>,
}

impl SynEx {
    /// The version this side offers; version 1 without the valid flag.
    pub fn offered(&self) -> u16 {
        if self.flags & VERSION_INFO_VALID != 0 {
            self.version
        } else {
            VERSION_1
        }
    }
}

/// RDPUDP_SOURCE_PAYLOAD_HEADER (2.2.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceHeader {
    pub coded: u32,
    pub source_start: u32,
}

/// RDPUDP_FEC_PAYLOAD_HEADER (2.2.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecPayloadHeader {
    pub coded: u32,
    pub source_start: u32,
    pub range: u8,
    pub fec_index: u8,
}

/// One parsed datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub header: FecHeader,
    pub syn: Option<SynData>,
    /// RDPUDP_CORRELATION_ID_PAYLOAD uCorrelationId (2.2.2.8).
    pub correlation_id: Option<[u8; 16]>,
    pub synex: Option<SynEx>,
    /// RDPUDP_ACK_VECTOR_HEADER AckVector elements (2.2.2.7); None in SYN
    /// datagrams and datagrams without RDPUDP_FLAG_ACK.
    pub ack_vector: Option<&'a [u8]>,
    /// RDPUDP_ACK_OF_ACKVECTOR_HEADER snResetSeqNum (2.2.2.6).
    pub ack_of_acks: Option<u32>,
    pub source: Option<SourceHeader>,
    pub fec: Option<FecPayloadHeader>,
    /// The data after a source or FEC payload header; empty otherwise
    /// (the zero padding of a SYN is not returned).
    pub payload: &'a [u8],
}

/// Parses one datagram. Every length is checked against the datagram
/// (5.1.2); a bad datagram is an error, never a panic.
pub fn parse(d: &[u8]) -> Result<Datagram<'_>> {
    let mut r = Reader::new(d);
    let header = FecHeader {
        sn_source_ack: be32(&mut r)?,
        receive_window: be16(&mut r)?,
        flags: be16(&mut r)?,
    };
    let mut out = Datagram {
        header,
        syn: None,
        correlation_id: None,
        synex: None,
        ack_vector: None,
        ack_of_acks: None,
        source: None,
        fec: None,
        payload: &[],
    };
    let flags = header.flags;
    if flags & FLAG_SYN != 0 {
        // SYN and SYN+ACK (3.1.5.1.1, 3.1.5.1.3): no ACK vector even with
        // RDPUDP_FLAG_ACK set.
        out.syn = Some(SynData {
            initial_seq: be32(&mut r)?,
            up_mtu: be16(&mut r)?,
            down_mtu: be16(&mut r)?,
        });
        if flags & FLAG_CORRELATION_ID != 0 {
            out.correlation_id = Some(r.array()?);
            r.skip(16)?; // uReserved
        }
        if flags & FLAG_SYNEX != 0 {
            let ex_flags = be16(&mut r)?;
            let version = be16(&mut r)?;
            // The cookie hash is in a client SYN offering version 3 only.
            let hash = (flags & FLAG_ACK == 0
                && ex_flags & VERSION_INFO_VALID != 0
                && version == VERSION_3)
                .then(|| r.array())
                .transpose()?;
            out.synex = Some(SynEx {
                flags: ex_flags,
                version,
                cookie_hash: hash,
            });
        }
        return Ok(out);
    }
    if flags & FLAG_ACK != 0 {
        let size = be16(&mut r)? as usize;
        if size > MAX_ACK_VECTOR {
            return proto(format!("RDP-UDP ACK vector of {size} bytes"));
        }
        out.ack_vector = Some(r.bytes(size)?);
        r.skip(pad4(2 + size))?;
    }
    if flags & FLAG_ACK_OF_ACKS != 0 {
        out.ack_of_acks = Some(be32(&mut r)?);
    }
    if flags & FLAG_DATA != 0 {
        if flags & FLAG_FEC != 0 {
            out.fec = Some(FecPayloadHeader {
                coded: be32(&mut r)?,
                source_start: be32(&mut r)?,
                range: r.u8()?,
                fec_index: r.u8()?,
            });
            r.skip(2)?; // uPadding
        } else {
            out.source = Some(SourceHeader {
                coded: be32(&mut r)?,
                source_start: be32(&mut r)?,
            });
        }
        out.payload = r.rest();
    }
    Ok(out)
}

/// Padding after `n` bytes to the next DWORD boundary (2.2.2.7).
fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put_header(v: &mut Vec<u8>, h: FecHeader) {
    put32(v, h.sn_source_ack);
    put16(v, h.receive_window);
    put16(v, h.flags);
}

/// A SYN (3.1.5.1.1) or, with `ack` = the peer's initial sequence number,
/// a SYN+ACK (3.1.5.1.3), zero-padded to the MTU (step 6).
pub fn syn_datagram(ack: Option<u32>, window: u16, syn: SynData, synex: Option<SynEx>) -> Vec<u8> {
    let mut flags = FLAG_SYN;
    if ack.is_some() {
        flags |= FLAG_ACK;
    }
    if synex.is_some() {
        flags |= FLAG_SYNEX;
    }
    let mut v = Vec::with_capacity(MAX_MTU as usize);
    put_header(
        &mut v,
        FecHeader {
            sn_source_ack: ack.unwrap_or(u32::MAX),
            receive_window: window,
            flags,
        },
    );
    put32(&mut v, syn.initial_seq);
    put16(&mut v, syn.up_mtu);
    put16(&mut v, syn.down_mtu);
    if let Some(ex) = synex {
        put16(&mut v, ex.flags);
        put16(&mut v, ex.version);
        if let Some(h) = ex.cookie_hash {
            v.extend_from_slice(&h);
        }
    }
    let size = syn.up_mtu.min(syn.down_mtu) as usize;
    v.resize(v.len().max(size), 0);
    v
}

/// An ACK datagram (3.1.5.1.2), with a Source Packet when `source` is set
/// (3.1.5.1.4). `vector` holds encoded ACK Vector Elements.
pub fn ack_datagram(
    header: FecHeader,
    vector: &[u8],
    ack_of_acks: Option<u32>,
    source: Option<(SourceHeader, &[u8])>,
) -> Vec<u8> {
    let mut h = header;
    h.flags |= FLAG_ACK;
    if ack_of_acks.is_some() {
        h.flags |= FLAG_ACK_OF_ACKS;
    }
    if source.is_some() {
        h.flags |= FLAG_DATA;
    }
    let payload = source.map_or(0, |(_, p)| p.len());
    let mut v = Vec::with_capacity(8 + 2 + vector.len() + 3 + 4 + 8 + payload);
    put_header(&mut v, h);
    put16(&mut v, vector.len() as u16);
    v.extend_from_slice(vector);
    v.resize(v.len() + pad4(2 + vector.len()), 0);
    if let Some(x) = ack_of_acks {
        put32(&mut v, x);
    }
    if let Some((s, p)) = source {
        put32(&mut v, s.coded);
        put32(&mut v, s.source_start);
        v.extend_from_slice(p);
    }
    v
}

/// Run-length encodes received states (true = received) into ACK Vector
/// Elements (2.2.2.7.1): state in the two high bits, run length minus one
/// in the six low bits.
pub fn encode_ack_vector(states: impl IntoIterator<Item = bool>) -> Vec<u8> {
    let mut v = Vec::new();
    let mut run: Option<(bool, u8)> = None;
    let flush = |v: &mut Vec<u8>, (got, n): (bool, u8)| {
        let state = if got {
            DATAGRAM_RECEIVED
        } else {
            DATAGRAM_NOT_YET_RECEIVED
        };
        v.push((state << 6) | (n - 1));
    };
    for s in states {
        run = match run {
            Some((got, n)) if got == s && n < 64 => Some((got, n + 1)),
            Some(prev) => {
                flush(&mut v, prev);
                Some((s, 1))
            }
            None => Some((s, 1)),
        };
    }
    if let Some(prev) = run {
        flush(&mut v, prev);
    }
    v
}

/// The runs of an ACK vector: (received, count). The reserved states count
/// as not received.
pub fn decode_ack_vector(v: &[u8]) -> impl Iterator<Item = (bool, u32)> + '_ {
    v.iter()
        .map(|e| (e >> 6 == DATAGRAM_RECEIVED, (e & 0x3F) as u32 + 1))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Client: SYN sent, waiting for the SYN+ACK.
    SynSent,
    /// Server: SYN+ACK sent, waiting for the client's ACK.
    SynReceived,
    Established,
    Closed,
}

/// One Source Packet sent and not yet acknowledged, or acknowledged out of
/// order (behind an older unacknowledged one).
struct Sent {
    seq: u32,
    data: Vec<u8>,
    /// Last (re)transmission.
    at: Instant,
    rto: Duration,
    /// Transmissions so far.
    tries: u32,
    acked: bool,
    /// Due for a fast retransmission: three later packets were
    /// acknowledged (3.1.1.4.1).
    fast: bool,
    /// Already fast-retransmitted once; later losses wait for the timer.
    fast_done: bool,
}

/// Counters for a statistics display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retransmits: u64,
}

/// One end of an RDP-UDP-R connection.
pub struct Endpoint {
    state: State,
    closed: Option<String>,
    client: bool,
    version: u16,
    mtu: usize,
    /// The handshake datagram this side retransmits (SYN or SYN+ACK).
    syn: Vec<u8>,
    syn_at: Option<Instant>,
    syn_tries: u32,

    // Sender.
    isn: u32,
    next_seq: u32,
    next_coded: u32,
    queue: VecDeque<Vec<u8>>,
    /// From the oldest unacknowledged Source Packet on, in sequence order.
    flight: VecDeque<Sent>,
    remote_window: u32,
    cwnd: f64,
    ssthresh: f64,
    /// Loss reactions wait until this sequence number is acknowledged (one
    /// reaction per round trip, 3.1.1.8).
    recover: Option<u32>,
    cwr_next: bool,
    /// The packet that carried RDPUDP_FLAG_CWR: Congestion Notifications in
    /// acknowledgements older than it are not reacted to again.
    cwr_seq: Option<u32>,
    srtt: Option<Duration>,
    /// The last snResetSeqNum this side sent.
    reset_sent: u32,

    // Receiver.
    peer_isn: u32,
    recv_next: u32,
    highest: u32,
    /// Start of the ACK vector (InSnResetSeqNum).
    vector_base: u32,
    /// Out-of-order datagrams; index 0 is `recv_next`.
    ooo: VecDeque<Option<Vec<u8>>>,
    incoming: Vec<u8>,
    ack_due: bool,
    /// A loss was seen and the sender has not answered with CWR yet.
    cn: bool,
    cn_mark: u32,

    last_recv: Instant,
    last_send: Instant,
    stats: EndpointStats,
}

impl Endpoint {
    fn new(client: bool, isn: u32, now: Instant) -> Endpoint {
        Endpoint {
            state: if client {
                State::SynSent
            } else {
                State::SynReceived
            },
            closed: None,
            client,
            version: VERSION_1,
            mtu: MAX_MTU as usize,
            syn: Vec::new(),
            syn_at: None,
            syn_tries: 0,
            isn,
            next_seq: isn.wrapping_add(1),
            next_coded: isn.wrapping_add(1),
            queue: VecDeque::new(),
            flight: VecDeque::new(),
            remote_window: 64,
            cwnd: INITIAL_CWND,
            ssthresh: f64::MAX,
            recover: None,
            cwr_next: false,
            cwr_seq: None,
            srtt: None,
            reset_sent: isn,
            peer_isn: 0,
            recv_next: 0,
            highest: 0,
            vector_base: 0,
            ooo: VecDeque::new(),
            incoming: Vec::new(),
            ack_due: false,
            cn: false,
            cn_mark: 0,
            last_recv: now,
            last_send: now,
            stats: EndpointStats::default(),
        }
    }

    /// A client endpoint; its SYN goes out with the first [`Self::poll`].
    /// `isn` is the random initial sequence number (3.1.1.2).
    pub fn client(isn: u32, now: Instant) -> Endpoint {
        let mut e = Endpoint::new(true, isn, now);
        e.syn = syn_datagram(
            None,
            RECEIVE_WINDOW,
            SynData {
                initial_seq: isn,
                up_mtu: MAX_MTU,
                down_mtu: MAX_MTU,
            },
            Some(SynEx {
                flags: VERSION_INFO_VALID,
                version: VERSION_2,
                cookie_hash: None,
            }),
        );
        e
    }

    /// A server endpoint answering the client SYN `syn` (3.1.5.1.3), at
    /// most version 2. Used by the tests' server side.
    pub fn accept(syn: &[u8], isn: u32, now: Instant) -> Result<Endpoint> {
        let d = parse(syn)?;
        let Some(sd) = d.syn.filter(|_| d.header.flags & FLAG_ACK == 0) else {
            return proto("RDP-UDP: not a SYN");
        };
        let mut e = Endpoint::new(false, isn, now);
        e.version = d.synex.map_or(VERSION_1, |x| x.offered().min(VERSION_2));
        e.mtu = sd.up_mtu.min(sd.down_mtu).clamp(MIN_MTU, MAX_MTU) as usize;
        e.start_receiving(sd.initial_seq);
        e.remote_window = d.header.receive_window.max(1) as u32;
        let mtu = e.mtu as u16;
        e.syn = syn_datagram(
            Some(sd.initial_seq),
            RECEIVE_WINDOW,
            SynData {
                initial_seq: isn,
                up_mtu: mtu,
                down_mtu: mtu,
            },
            d.synex.map(|_| SynEx {
                flags: VERSION_INFO_VALID,
                version: e.version,
                cookie_hash: None,
            }),
        );
        Ok(e)
    }

    fn start_receiving(&mut self, peer_isn: u32) {
        self.peer_isn = peer_isn;
        self.recv_next = peer_isn.wrapping_add(1);
        self.highest = peer_isn;
        self.vector_base = self.recv_next;
        self.cn_mark = peer_isn;
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Why the connection closed.
    pub fn close_reason(&self) -> Option<&str> {
        self.closed.as_deref()
    }

    /// The negotiated RDP-UDP version (valid once established).
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The smoothed round-trip time, once measured.
    pub fn rtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn stats(&self) -> EndpointStats {
        self.stats
    }

    /// Largest payload of one Source Packet.
    pub fn max_payload(&self) -> usize {
        self.mtu - HEADROOM
    }

    /// Ends the connection locally (3.1.4.4); nothing is sent any more.
    pub fn close(&mut self, why: &str) {
        if self.state != State::Closed {
            trace!("RDP-UDP closed: {why}");
            self.state = State::Closed;
            self.closed = Some(why.to_string());
        }
    }

    /// Queues `data` for reliable, ordered delivery. Each call starts a new
    /// Source Packet; data longer than [`Self::max_payload`] is split.
    pub fn send(&mut self, data: &[u8]) {
        if self.state == State::Closed || data.is_empty() {
            return;
        }
        self.queue.push_back(data.to_vec());
    }

    /// Bytes not yet handed to the peer or not yet acknowledged.
    pub fn unacknowledged(&self) -> usize {
        self.queue.iter().map(Vec::len).sum::<usize>()
            + self
                .flight
                .iter()
                .filter(|s| !s.acked)
                .map(|s| s.data.len())
                .sum::<usize>()
    }

    /// The bytes delivered in order since the last call.
    pub fn take_incoming(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.incoming)
    }

    /// Handles one received datagram. Malformed, duplicate and out-of-window
    /// datagrams are dropped (3.1.5, 5.1.1, 5.1.2).
    pub fn on_datagram(&mut self, raw: &[u8], now: Instant) {
        if self.state == State::Closed {
            return;
        }
        let d = match parse(raw) {
            Ok(d) => d,
            Err(e) => {
                trace!("RDP-UDP datagram ignored: {e}");
                return;
            }
        };
        self.stats.bytes_in += raw.len() as u64;
        let flags = d.header.flags;
        if let Some(sd) = d.syn {
            self.on_syn(&d, sd, now);
            return;
        }
        match self.state {
            State::SynSent => return, // nothing but a SYN+ACK counts yet
            State::SynReceived if flags & FLAG_ACK != 0 => {
                self.state = State::Established;
            }
            State::SynReceived => return,
            _ => {}
        }
        self.last_recv = now;
        if flags & FLAG_CWR != 0 {
            self.cn = false;
        }
        if let Some(v) = d.ack_vector {
            self.on_ack(d.header, v, now);
        }
        if let Some(x) = d.ack_of_acks {
            // The sender knows everything up to x arrived: later vectors
            // start there (2.2.2.6). Never beyond what was received.
            if seq_lt(self.vector_base, x) && !seq_lt(self.recv_next, x) {
                self.vector_base = x;
            }
        }
        if let Some(s) = d.source {
            self.on_source(s.source_start, d.payload);
        }
    }

    fn on_syn(&mut self, d: &Datagram, sd: SynData, now: Instant) {
        let flags = d.header.flags;
        match self.state {
            State::SynSent if flags & FLAG_ACK != 0 => {
                if d.header.sn_source_ack != self.isn {
                    trace!("RDP-UDP SYN+ACK for another SYN ignored");
                    return;
                }
                let theirs = d.synex.map_or(VERSION_1, |x| x.offered());
                if theirs > VERSION_2 {
                    self.close("the server chose RDP-UDP version 3 (MS-RDPEUDP2)");
                    return;
                }
                self.version = theirs.max(VERSION_1);
                self.mtu = sd.up_mtu.min(sd.down_mtu).clamp(MIN_MTU, MAX_MTU) as usize;
                self.remote_window = d.header.receive_window.max(1) as u32;
                self.start_receiving(sd.initial_seq);
                self.state = State::Established;
                self.last_recv = now;
                // The ACK for the SYN+ACK (3.1.5.2 step 4).
                self.ack_due = true;
                trace!(
                    "RDP-UDP connected: version {}, MTU {}",
                    self.version, self.mtu
                );
            }
            // Our ACK was lost and the SYN+ACK came again.
            State::Established if self.client && flags & FLAG_ACK != 0 => {
                if sd.initial_seq == self.peer_isn {
                    self.ack_due = true;
                }
            }
            // The SYN+ACK was lost and the SYN came again.
            State::SynReceived | State::Established if !self.client => {
                if sd.initial_seq == self.peer_isn {
                    self.syn_at = None;
                }
            }
            _ => {}
        }
    }

    /// A received Source Packet (3.1.5.3.3).
    fn on_source(&mut self, seq: u32, payload: &[u8]) {
        let off = seq.wrapping_sub(self.recv_next) as i32;
        if off < 0 {
            // A duplicate: acknowledge again, the earlier ACK may be lost.
            self.ack_due = true;
            return;
        }
        let off = off as usize;
        if off >= RECEIVE_WINDOW as usize {
            trace!("RDP-UDP datagram {seq} outside the receive window dropped");
            return;
        }
        self.ack_due = true;
        if self.ooo.len() <= off {
            self.ooo.resize(off + 1, None);
        }
        if self.ooo[off].is_some() {
            return;
        }
        self.ooo[off] = Some(payload.to_vec());
        if seq_lt(self.highest, seq) {
            self.highest = seq;
        }
        // A gap with three later datagrams behind it is a loss (3.1.1.4.1):
        // Congestion Notification until the sender answers with CWR.
        let later = self.ooo.iter().skip(1).filter(|s| s.is_some()).count();
        if self.ooo[0].is_none() && later >= 3 && seq_lt(self.cn_mark, self.recv_next) {
            self.cn = true;
            self.cn_mark = self.highest;
        }
        while let Some(Some(_)) = self.ooo.front() {
            let p = self.ooo.pop_front().flatten().expect("checked");
            self.incoming.extend_from_slice(&p);
            self.recv_next = self.recv_next.wrapping_add(1);
        }
    }

    /// An acknowledgement from the peer (3.1.1.4, 3.1.1.7, 3.1.1.8).
    fn on_ack(&mut self, h: FecHeader, vector: &[u8], now: Instant) {
        self.remote_window = h.receive_window.max(1) as u32;
        let end = h.sn_source_ack;
        // Only what was sent can be acknowledged (5.1.1).
        if !seq_lt(end, self.next_seq) || seq_lt(end, self.isn) {
            return;
        }
        if h.flags & FLAG_CN != 0 && self.cwr_seq.is_none_or(|c| !seq_lt(end, c)) {
            self.loss(end, false);
        }
        let total: u32 = decode_ack_vector(vector).map(|(_, n)| n).sum();
        if total == 0 {
            return;
        }
        let Some(first) = self.flight.front().map(|s| s.seq) else {
            return;
        };
        let start = end.wrapping_sub(total - 1);
        let mut seq = start;
        let mut newest_acked = None;
        for (got, n) in decode_ack_vector(vector) {
            if got {
                for k in 0..n {
                    let s = seq.wrapping_add(k);
                    let i = s.wrapping_sub(first) as i32;
                    if i < 0 || i as usize >= self.flight.len() {
                        continue;
                    }
                    let p = &mut self.flight[i as usize];
                    newest_acked = Some(s);
                    if p.acked {
                        continue;
                    }
                    p.acked = true;
                    // RTT from first transmissions only, not from delayed
                    // acknowledgements (2.2.2.1 RDPUDP_FLAG_ACKDELAYED).
                    if p.tries == 1 && h.flags & FLAG_ACKDELAYED == 0 {
                        let sample = now.saturating_duration_since(p.at);
                        self.srtt = Some(match self.srtt {
                            Some(r) => (r * 7 + sample) / 8,
                            None => sample,
                        });
                    }
                    if self.cwnd < self.ssthresh {
                        self.cwnd += 1.0;
                    } else {
                        self.cwnd += 1.0 / self.cwnd;
                    }
                }
            }
            seq = seq.wrapping_add(n);
        }
        while self.flight.front().is_some_and(|s| s.acked) {
            self.flight.pop_front();
        }
        if let Some(r) = self.recover
            && !seq_lt(self.cum_acked(), r)
        {
            self.recover = None;
        }
        // Three later packets acknowledged: the gap is lost (3.1.1.4.1).
        if let Some(newest) = newest_acked {
            let mut lost = None;
            for p in self.flight.iter_mut() {
                if !seq_lt(p.seq.wrapping_add(3), newest.wrapping_add(1)) {
                    break;
                }
                if !p.acked && !p.fast_done {
                    p.fast = true;
                    p.fast_done = true;
                    lost.get_or_insert(p.seq);
                }
            }
            if let Some(s) = lost {
                self.loss(s, false);
            }
        }
    }

    /// Highest sequence number with everything up to it acknowledged.
    fn cum_acked(&self) -> u32 {
        self.flight
            .front()
            .map_or(self.next_seq, |s| s.seq)
            .wrapping_sub(1)
    }

    /// A congestion event: lower the window once per round trip and mark
    /// the next Source Packet with RDPUDP_FLAG_CWR (3.1.1.8).
    fn loss(&mut self, seq: u32, timeout: bool) {
        if self.recover.is_some_and(|r| !seq_lt(r, seq)) && !timeout {
            return;
        }
        self.ssthresh = (self.cwnd / 2.0).max(2.0);
        self.cwnd = if timeout { 2.0 } else { self.ssthresh };
        self.recover = Some(self.next_seq.wrapping_sub(1));
        self.cwr_next = true;
    }

    fn min_rto(&self) -> Duration {
        // 3.1.6.1: 500 ms for version 1, 300 ms for version 2.
        if self.version >= VERSION_2 {
            Duration::from_millis(300)
        } else {
            Duration::from_millis(500)
        }
    }

    fn rto(&self) -> Duration {
        self.srtt
            .map_or(self.min_rto() * 2, |r| (r * 2).max(self.min_rto()))
    }

    fn header(&self, flags: u16) -> FecHeader {
        let mut flags = flags;
        if self.cn {
            flags |= FLAG_CN;
        }
        FecHeader {
            sn_source_ack: self.highest,
            receive_window: RECEIVE_WINDOW,
            flags,
        }
    }

    /// The receiver's queue from the vector start to `snSourceAck`
    /// (3.1.5.1.2); falls back to the out-of-order part alone if that does
    /// not fit `limit` bytes.
    fn ack_vector(&self, limit: usize) -> Vec<u8> {
        let build = |from: u32| {
            if seq_lt(self.highest, from) {
                return Vec::new();
            }
            let n = self.highest.wrapping_sub(from).wrapping_add(1);
            if n as usize > limit * 64 {
                return vec![0; limit + 1]; // cannot fit
            }
            encode_ack_vector((0..n).map(|k| {
                let s = from.wrapping_add(k);
                let i = s.wrapping_sub(self.recv_next) as i32;
                i < 0 || self.ooo.get(i as usize).is_some_and(Option::is_some)
            }))
        };
        let v = build(self.vector_base);
        if v.len() <= limit {
            return v;
        }
        let v = build(self.recv_next);
        if v.len() <= limit { v } else { Vec::new() }
    }

    /// RDPUDP_ACK_OF_ACKVECTOR_HEADER once the cumulative acknowledgement
    /// moved far enough (2.2.2.6).
    fn ack_of_acks(&mut self) -> Option<u32> {
        let cum = self.cum_acked();
        if cum.wrapping_sub(self.reset_sent) >= ACK_OF_ACKS_EVERY && seq_lt(self.reset_sent, cum) {
            self.reset_sent = cum;
            return Some(cum);
        }
        None
    }

    fn emit(&mut self, out: &mut Vec<Vec<u8>>, d: Vec<u8>, now: Instant) {
        self.stats.bytes_out += d.len() as u64;
        self.last_send = now;
        out.push(d);
    }

    fn data_datagram(&mut self, i: usize, cwr: bool) -> Vec<u8> {
        let coded = self.next_coded;
        self.next_coded = coded.wrapping_add(1);
        let room = self.mtu - 8 - 4 - 8 - self.flight[i].data.len();
        let mut vector = self.ack_vector(room.saturating_sub(4));
        if 2 + vector.len() + pad4(2 + vector.len()) > room {
            vector.clear();
        } else {
            self.ack_due = false;
        }
        let aoa = self.ack_of_acks();
        let flags = if cwr { FLAG_CWR } else { 0 };
        let p = &self.flight[i];
        let src = SourceHeader {
            coded,
            source_start: p.seq,
        };
        ack_datagram(self.header(flags), &vector, aoa, Some((src, &p.data)))
    }

    /// Datagrams to send now: handshake (re)transmissions, retransmissions,
    /// new data the windows allow, acknowledgements and keepalives. Also
    /// runs the timers; check [`Self::state`] afterwards.
    pub fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        match self.state {
            State::Closed => return out,
            State::SynSent | State::SynReceived => {
                if self
                    .syn_at
                    .is_none_or(|t| now.saturating_duration_since(t) >= SYN_INTERVAL)
                {
                    if self.syn_tries > SYN_RETRIES {
                        self.close("no answer to the RDP-UDP handshake");
                        return out;
                    }
                    self.syn_tries += 1;
                    self.syn_at = Some(now);
                    let syn = self.syn.clone();
                    self.emit(&mut out, syn, now);
                }
                if self.state == State::SynSent {
                    return out;
                }
            }
            State::Established => {}
        }
        if self.state == State::Established
            && now.saturating_duration_since(self.last_recv) > SILENCE_LIMIT
        {
            self.close("no datagram from the peer for 65 s");
            return out;
        }

        // Retransmissions (3.1.6.1).
        for i in 0..self.flight.len() {
            let p = &self.flight[i];
            if p.acked || (!p.fast && now.saturating_duration_since(p.at) < p.rto) {
                continue;
            }
            if p.tries > RETRANSMIT_LIMIT {
                self.close("retransmit limit reached");
                return out;
            }
            let (seq, fast) = (p.seq, p.fast);
            if !fast {
                self.loss(seq, true);
            }
            let cwr = std::mem::take(&mut self.cwr_next);
            let d = self.data_datagram(i, cwr);
            let rto = self.rto();
            let p = &mut self.flight[i];
            p.tries += 1;
            p.fast = false;
            p.at = now;
            // Each retransmission waits twice as long (note <10>).
            p.rto = (p.rto * 2).max(rto).min(MAX_RTO);
            self.stats.retransmits += 1;
            if cwr {
                self.cwr_seq = Some(seq);
            }
            self.emit(&mut out, d, now);
        }

        // New data within the receive window (3.1.1.7) and the congestion
        // window (3.1.1.8).
        if self.state == State::Established {
            let max = self.max_payload();
            while !self.queue.is_empty() {
                let in_flight = self.flight.iter().filter(|s| !s.acked).count();
                let window_end = self.cum_acked().wrapping_add(self.remote_window);
                if in_flight as f64 >= self.cwnd.floor()
                    || !seq_lt(self.next_seq, window_end.wrapping_add(1))
                {
                    break;
                }
                let front = self.queue.front_mut().expect("not empty");
                let data = if front.len() > max {
                    let rest = front.split_off(max);
                    std::mem::replace(front, rest)
                } else {
                    self.queue.pop_front().expect("front exists")
                };
                let seq = self.next_seq;
                self.next_seq = seq.wrapping_add(1);
                self.flight.push_back(Sent {
                    seq,
                    data,
                    at: now,
                    rto: self.rto(),
                    tries: 1,
                    acked: false,
                    fast: false,
                    fast_done: false,
                });
                let cwr = std::mem::take(&mut self.cwr_next);
                if cwr {
                    self.cwr_seq = Some(seq);
                }
                let d = self.data_datagram(self.flight.len() - 1, cwr);
                self.emit(&mut out, d, now);
            }
        }

        if self.state == State::Established
            && (self.ack_due || now.saturating_duration_since(self.last_send) >= KEEPALIVE)
        {
            self.ack_due = false;
            let limit = (self.mtu - 16).min(MAX_ACK_VECTOR);
            let vector = self.ack_vector(limit);
            let aoa = self.ack_of_acks();
            let d = ack_datagram(self.header(0), &vector, aoa, None);
            self.emit(&mut out, d, now);
        }
        out
    }
}

/// An error for a transport that closed.
pub fn closed_error(e: &Endpoint) -> Error {
    Error::ConnectionLost(format!(
        "UDP transport closed: {}",
        e.close_reason().unwrap_or("closed")
    ))
}

#[cfg(test)]
#[path = "rdpeudp_tests.rs"]
mod tests;
