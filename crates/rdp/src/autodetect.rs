//! Network auto-detection (MS-RDPBCGR 1.3.1.1 "Optional Connect-Time
//! Auto-Detection", 2.2.14; the server's use of the answers is 3.3.5.14).
//!
//! The server measures the link: it asks for round-trip time samples (RTT
//! Measure Request, 2.2.14.1.1), sends a bandwidth burst framed by Bandwidth
//! Measure Start and Stop (2.2.14.1.2, 2.2.14.1.4), and tells the client what
//! it found (Network Characteristics Result, 2.2.14.1.5). The client only
//! answers: an RTT Measure Response (2.2.14.2.1) at once, and Bandwidth
//! Measure Results (2.2.14.2.2) with the time and byte count it saw.
//!
//! Requests come in Server Auto-Detect Request PDUs (2.2.14.3) on the MCS
//! message channel (Server Message Channel Data, 2.2.1.4.5), both during the
//! connection sequence (between licensing and the capability exchange) and
//! after it; responses go back in Client Auto-Detect Response PDUs (2.2.14.4)
//! on the same channel. The client asks for all this with
//! RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT and the Client Message Channel Data
//! (2.2.1.3.7), which this crate sends for
//! [`ConnectionType::Auto`](crate::ConnectionType::Auto).
//!
//! Malformed requests are traced and dropped; they never end the session.

use std::time::Instant;

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};

/// Basic Security Header flag of a Server Auto-Detect Request PDU (2.2.8.1.1.2.1).
pub const SEC_AUTODETECT_REQ: u16 = 0x1000;
/// Basic Security Header flag of a Client Auto-Detect Response PDU (2.2.8.1.1.2.1).
pub const SEC_AUTODETECT_RSP: u16 = 0x2000;

const TYPE_ID_AUTODETECT_REQUEST: u8 = 0x00;
const TYPE_ID_AUTODETECT_RESPONSE: u8 = 0x01;

/// RTT Measure Request after the connection sequence (2.2.14.1.1).
pub const RTT_REQUEST_CONTINUOUS: u16 = 0x0001;
/// RTT Measure Request during connect-time auto-detection (2.2.14.1.1).
pub const RTT_REQUEST_CONNECTTIME: u16 = 0x1001;
/// Bandwidth Measure Start after the connection sequence, or tunneled over
/// reliable UDP (2.2.14.1.2).
pub const BW_START_CONTINUOUS: u16 = 0x0014;
/// Bandwidth Measure Start tunneled over lossy UDP (2.2.14.1.2).
pub const BW_START_LOSSY: u16 = 0x0114;
/// Bandwidth Measure Start during connect-time auto-detection (2.2.14.1.2).
pub const BW_START_CONNECTTIME: u16 = 0x1014;
/// Bandwidth Measure Payload, connect-time only (2.2.14.1.3).
pub const BW_PAYLOAD: u16 = 0x0002;
/// Bandwidth Measure Stop during connect-time auto-detection; carries a
/// payload (2.2.14.1.4).
pub const BW_STOP_CONNECTTIME: u16 = 0x002B;
/// Bandwidth Measure Stop after the connection sequence, or tunneled over
/// reliable UDP (2.2.14.1.4).
pub const BW_STOP_CONTINUOUS: u16 = 0x0429;
/// Bandwidth Measure Stop tunneled over lossy UDP (2.2.14.1.4).
pub const BW_STOP_LOSSY: u16 = 0x0629;
/// Network Characteristics Result with baseRTT and averageRTT (2.2.14.1.5).
pub const NETCHAR_RESULT_RTT: u16 = 0x0840;
/// Network Characteristics Result with bandwidth and averageRTT (2.2.14.1.5).
pub const NETCHAR_RESULT_BANDWIDTH: u16 = 0x0880;
/// Network Characteristics Result with all three fields (2.2.14.1.5).
pub const NETCHAR_RESULT_ALL: u16 = 0x08C0;

/// RTT Measure Response responseType (2.2.14.2.1).
pub const RTT_RESPONSE: u16 = 0x0000;
/// Bandwidth Measure Results answering a connect-time stop (2.2.14.2.2).
pub const BW_RESULTS_CONNECTTIME: u16 = 0x0003;
/// Bandwidth Measure Results answering a stop after the connection sequence (2.2.14.2.2).
pub const BW_RESULTS_CONTINUOUS: u16 = 0x000B;

/// One server auto-detect message (TS_AUTODETECT_REQ variants, 2.2.14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// RTT Measure Request (2.2.14.1.1) with its requestType.
    Rtt { request_type: u16 },
    /// Bandwidth Measure Start (2.2.14.1.2).
    BandwidthStart { request_type: u16 },
    /// Bandwidth Measure Payload (2.2.14.1.3): `len` bytes of random data.
    BandwidthPayload { len: u16 },
    /// Bandwidth Measure Stop (2.2.14.1.4); the connect-time variant
    /// carries `payload_len` more bytes of random data.
    BandwidthStop { request_type: u16, payload_len: u16 },
    /// Network Characteristics Result (2.2.14.1.5).
    Result(NetworkCharacteristics),
    /// A requestType this client does not know; ignored.
    Other { request_type: u16 },
}

/// What the server measured about the link (2.2.14.1.5). Fields the
/// server did not send stay `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkCharacteristics {
    /// Lowest detected round-trip time, milliseconds.
    pub base_rtt_ms: Option<u32>,
    /// Current bandwidth, kilobits per second.
    pub bandwidth_kbps: Option<u32>,
    /// Current average round-trip time, milliseconds.
    pub average_rtt_ms: Option<u32>,
}

impl NetworkCharacteristics {
    /// Merges a newer result: fields it lacks keep their old values.
    fn merge(&mut self, newer: NetworkCharacteristics) {
        self.base_rtt_ms = newer.base_rtt_ms.or(self.base_rtt_ms);
        self.bandwidth_kbps = newer.bandwidth_kbps.or(self.bandwidth_kbps);
        self.average_rtt_ms = newer.average_rtt_ms.or(self.average_rtt_ms);
    }

    /// "RTT 12 ms · 48.0 Mbit/s", or None before the server sent anything.
    pub fn summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(rtt) = self.average_rtt_ms.or(self.base_rtt_ms) {
            parts.push(format!("RTT {rtt} ms"));
        }
        if let Some(kbps) = self.bandwidth_kbps {
            parts.push(if kbps >= 1000 {
                format!("{:.1} Mbit/s", kbps as f64 / 1000.0)
            } else {
                format!("{kbps} kbit/s")
            });
        }
        (!parts.is_empty()).then(|| parts.join(" · "))
    }
}

/// The TS_AUTODETECT_REQ in a message channel PDU, if its Basic Security
/// Header (2.2.8.1.1.2.1) has SEC_AUTODETECT_REQ.
pub fn request_data(data: &[u8]) -> Option<&[u8]> {
    let flags = crate::cursor::le16(data, 0)?;
    (flags & SEC_AUTODETECT_REQ != 0)
        .then(|| data.get(4..))
        .flatten()
}

/// Parses one TS_AUTODETECT_REQ (2.2.14.1): (sequenceNumber, message).
pub fn parse_request(data: &[u8]) -> Result<(u16, Request)> {
    let mut r = Reader::new(data);
    let header_len = r.u8()? as usize;
    if r.u8()? != TYPE_ID_AUTODETECT_REQUEST {
        return proto("auto-detect request with a wrong headerTypeId");
    }
    let seq = r.u16()?;
    let request_type = r.u16()?;
    if header_len < 6 || header_len > data.len() {
        return proto("auto-detect request with a bad headerLength");
    }
    let req = match request_type {
        RTT_REQUEST_CONTINUOUS | RTT_REQUEST_CONNECTTIME => Request::Rtt { request_type },
        BW_START_CONTINUOUS | BW_START_LOSSY | BW_START_CONNECTTIME => {
            Request::BandwidthStart { request_type }
        }
        BW_PAYLOAD => {
            let len = r.u16()?;
            r.bytes(len as usize)?;
            Request::BandwidthPayload { len }
        }
        BW_STOP_CONNECTTIME | BW_STOP_CONTINUOUS | BW_STOP_LOSSY => {
            // payloadLength is present only for 0x002B (headerLength 0x08).
            let payload_len = if request_type == BW_STOP_CONNECTTIME && header_len >= 8 {
                let len = r.u16()?;
                r.bytes(len as usize)?;
                len
            } else {
                0
            };
            Request::BandwidthStop {
                request_type,
                payload_len,
            }
        }
        NETCHAR_RESULT_RTT | NETCHAR_RESULT_BANDWIDTH | NETCHAR_RESULT_ALL => {
            let base = request_type & 0x0040 != 0;
            let bandwidth = request_type & 0x0080 != 0;
            Request::Result(NetworkCharacteristics {
                base_rtt_ms: if base { Some(r.u32()?) } else { None },
                bandwidth_kbps: if bandwidth { Some(r.u32()?) } else { None },
                average_rtt_ms: Some(r.u32()?),
            })
        }
        _ => Request::Other { request_type },
    };
    Ok((seq, req))
}

/// A Client Auto-Detect Response PDU's I/O data (2.2.14.4): the Basic
/// Security Header with SEC_AUTODETECT_RSP, then the TS_AUTODETECT_RSP.
fn response(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.put_u16(SEC_AUTODETECT_RSP);
    out.put_u16(0); // flagsHi
    out.put_bytes(body);
    out
}

/// RTT Measure Response (2.2.14.2.1), with its security header.
pub fn rtt_response(seq: u16) -> Vec<u8> {
    let mut b = vec![0x06, TYPE_ID_AUTODETECT_RESPONSE];
    b.put_u16(seq);
    b.put_u16(RTT_RESPONSE);
    response(&b)
}

/// Bandwidth Measure Results (2.2.14.2.2), with its security header.
pub fn bandwidth_results(seq: u16, response_type: u16, time_delta_ms: u32, bytes: u32) -> Vec<u8> {
    let mut b = vec![0x0E, TYPE_ID_AUTODETECT_RESPONSE];
    b.put_u16(seq);
    b.put_u16(response_type);
    b.put_u32(time_delta_ms);
    b.put_u32(bytes);
    response(&b)
}

/// A bandwidth measurement in progress.
#[derive(Debug, Clone, Copy)]
struct Measure {
    started: Instant,
    /// Started after the connection sequence: every PDU from the server
    /// counts, not only payload messages (2.2.14.2.2).
    continuous: bool,
    bytes: u64,
}

/// Client side of network auto-detection: answers requests and keeps the
/// latest Network Characteristics Result.
#[derive(Debug, Default)]
pub struct AutoDetect {
    measure: Option<Measure>,
    network: NetworkCharacteristics,
    /// Set by a new result; taken by [`AutoDetect::take_update`].
    updated: bool,
}

impl AutoDetect {
    /// The network characteristics the server reported so far.
    pub fn network(&self) -> NetworkCharacteristics {
        self.network
    }

    /// The characteristics once after each new result.
    pub fn take_update(&mut self) -> Option<NetworkCharacteristics> {
        std::mem::take(&mut self.updated).then_some(self.network)
    }

    /// Counts `n` bytes received from the server while a measurement that
    /// started after the connection sequence runs.
    pub fn received(&mut self, n: usize) {
        if let Some(m) = self.measure.as_mut().filter(|m| m.continuous) {
            m.bytes += n as u64;
        }
    }

    /// Handles one message channel PDU (its I/O data, security header
    /// first). Returns the response to send on the message channel, if one
    /// is due. Anything that is not an auto-detect request is ignored.
    pub fn on_pdu(&mut self, data: &[u8], now: Instant) -> Option<Vec<u8>> {
        let req = request_data(data)?;
        match parse_request(req) {
            Ok((seq, r)) => self.on_request(seq, r, now),
            Err(e) => {
                crate::trace!("auto-detect request ignored: {e}");
                None
            }
        }
    }

    fn on_request(&mut self, seq: u16, req: Request, now: Instant) -> Option<Vec<u8>> {
        match req {
            Request::Rtt { .. } => Some(rtt_response(seq)),
            Request::BandwidthStart { request_type } => {
                self.measure = Some(Measure {
                    started: now,
                    continuous: request_type != BW_START_CONNECTTIME,
                    bytes: 0,
                });
                None
            }
            Request::BandwidthPayload { len } => {
                if let Some(m) = self.measure.as_mut().filter(|m| !m.continuous) {
                    m.bytes += len as u64;
                }
                None
            }
            Request::BandwidthStop {
                request_type,
                payload_len,
            } => {
                let Some(mut m) = self.measure.take() else {
                    crate::trace!("bandwidth measure stop without a start ignored");
                    return None;
                };
                if !m.continuous {
                    m.bytes += payload_len as u64;
                }
                let delta = now.saturating_duration_since(m.started).as_millis();
                let response_type = if request_type == BW_STOP_CONNECTTIME {
                    BW_RESULTS_CONNECTTIME
                } else {
                    BW_RESULTS_CONTINUOUS
                };
                Some(bandwidth_results(
                    seq,
                    response_type,
                    delta.min(u32::MAX as u128) as u32,
                    m.bytes.min(u32::MAX as u64) as u32,
                ))
            }
            Request::Result(n) => {
                crate::trace!("network characteristics: {n:?}");
                self.network.merge(n);
                self.updated = true;
                None
            }
            Request::Other { request_type } => {
                crate::trace!("auto-detect request type {request_type:#06x} ignored");
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "autodetect_tests.rs"]
mod tests;
