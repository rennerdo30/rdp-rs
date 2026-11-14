//! Auto-detect PDUs built byte by byte from the MS-RDPBCGR 2.2.14 field
//! tables (section 4 has no annotated auto-detect example).

use std::time::{Duration, Instant};

use super::*;

/// A Server Auto-Detect Request PDU's I/O data (2.2.14.3): Basic Security
/// Header with SEC_AUTODETECT_REQ, then `req`.
fn pdu(req: &[u8]) -> Vec<u8> {
    let mut p = vec![0x00, 0x10, 0x00, 0x00];
    p.extend_from_slice(req);
    p
}

#[test]
fn rtt_request_gets_an_rtt_response_with_its_sequence_number() {
    // 2.2.14.1.1: headerLength 6, TYPE_ID_AUTODETECT_REQUEST, seq 0x1234,
    // requestType 0x1001 (connect-time).
    let req = pdu(&[0x06, 0x00, 0x34, 0x12, 0x01, 0x10]);
    let mut ad = AutoDetect::default();
    let rsp = ad.on_pdu(&req, Instant::now()).unwrap();
    // 2.2.14.4 + 2.2.14.2.1: SEC_AUTODETECT_RSP (0x2000), headerLength 6,
    // TYPE_ID_AUTODETECT_RESPONSE, seq, responseType 0.
    assert_eq!(
        rsp,
        [0x00, 0x20, 0x00, 0x00, 0x06, 0x01, 0x34, 0x12, 0x00, 0x00]
    );
    // The continuous variant (0x0001) is answered the same way.
    let req = pdu(&[0x06, 0x00, 0x02, 0x00, 0x01, 0x00]);
    assert_eq!(
        ad.on_pdu(&req, Instant::now()).unwrap()[4..],
        [0x06, 0x01, 0x02, 0x00, 0x00, 0x00]
    );
}

#[test]
fn connect_time_bandwidth_counts_payload_bytes() {
    let t0 = Instant::now();
    let mut ad = AutoDetect::default();
    // Start 0x1014 (2.2.14.1.2).
    assert!(
        ad.on_pdu(&pdu(&[0x06, 0x00, 1, 0, 0x14, 0x10]), t0)
            .is_none()
    );
    // Two payloads of 4 and 3 bytes (2.2.14.1.3, requestType 0x0002).
    let p1 = pdu(&[0x08, 0x00, 2, 0, 0x02, 0x00, 4, 0, 9, 9, 9, 9]);
    let p2 = pdu(&[0x08, 0x00, 3, 0, 0x02, 0x00, 3, 0, 7, 7, 7]);
    assert!(ad.on_pdu(&p1, t0).is_none());
    assert!(ad.on_pdu(&p2, t0).is_none());
    // Frame bytes do not count in connect-time measurement.
    ad.received(1000);
    // Stop 0x002B with a 2-byte payload (headerLength 8, 2.2.14.1.4).
    let stop = pdu(&[0x08, 0x00, 4, 0, 0x2B, 0x00, 2, 0, 1, 1]);
    let rsp = ad.on_pdu(&stop, t0 + Duration::from_millis(250)).unwrap();
    // 2.2.14.2.2: headerLength 0x0E, seq of the stop, responseType 0x0003,
    // timeDelta 250 ms, byteCount 4 + 3 + 2.
    assert_eq!(
        rsp,
        [
            0x00, 0x20, 0x00, 0x00, 0x0E, 0x01, 4, 0, 0x03, 0x00, 250, 0, 0, 0, 9, 0, 0, 0
        ]
    );
}

#[test]
fn continuous_bandwidth_counts_every_received_byte() {
    let t0 = Instant::now();
    let mut ad = AutoDetect::default();
    ad.received(500); // before the start: not counted
    ad.on_pdu(&pdu(&[0x06, 0x00, 9, 0, 0x14, 0x00]), t0);
    ad.received(1200);
    ad.received(34);
    // Stop 0x0429: no payloadLength (headerLength 6).
    let rsp = ad
        .on_pdu(
            &pdu(&[0x06, 0x00, 10, 0, 0x29, 0x04]),
            t0 + Duration::from_millis(1000),
        )
        .unwrap();
    assert_eq!(&rsp[4..10], &[0x0E, 0x01, 10, 0, 0x0B, 0x00]);
    assert_eq!(&rsp[10..14], &1000u32.to_le_bytes());
    assert_eq!(&rsp[14..18], &1234u32.to_le_bytes());
    // A stop without a start is ignored.
    assert!(
        ad.on_pdu(&pdu(&[0x06, 0x00, 11, 0, 0x29, 0x04]), t0)
            .is_none()
    );
}

#[test]
fn network_characteristics_results_are_stored_and_merged() {
    let mut ad = AutoDetect::default();
    assert_eq!(ad.take_update(), None);
    assert_eq!(ad.network().summary(), None);
    // 0x08C0 (headerLength 0x12): baseRTT 10, bandwidth 50000, averageRTT 14.
    let mut all = vec![0x12, 0x00, 5, 0, 0xC0, 0x08];
    all.extend(10u32.to_le_bytes());
    all.extend(50_000u32.to_le_bytes());
    all.extend(14u32.to_le_bytes());
    assert!(ad.on_pdu(&pdu(&all), Instant::now()).is_none());
    let n = ad.take_update().unwrap();
    assert_eq!(
        n,
        NetworkCharacteristics {
            base_rtt_ms: Some(10),
            bandwidth_kbps: Some(50_000),
            average_rtt_ms: Some(14),
        }
    );
    assert_eq!(ad.take_update(), None, "reported once");
    assert_eq!(n.summary().unwrap(), "RTT 14 ms · 50.0 Mbit/s");
    // 0x0840 (headerLength 0x0E): baseRTT, averageRTT; bandwidth stays.
    let mut rtt = vec![0x0E, 0x00, 6, 0, 0x40, 0x08];
    rtt.extend(8u32.to_le_bytes());
    rtt.extend(20u32.to_le_bytes());
    ad.on_pdu(&pdu(&rtt), Instant::now());
    assert_eq!(
        ad.network(),
        NetworkCharacteristics {
            base_rtt_ms: Some(8),
            bandwidth_kbps: Some(50_000),
            average_rtt_ms: Some(20),
        }
    );
    // 0x0880: bandwidth, averageRTT.
    let mut bw = vec![0x0E, 0x00, 7, 0, 0x80, 0x08];
    bw.extend(900u32.to_le_bytes());
    bw.extend(30u32.to_le_bytes());
    ad.on_pdu(&pdu(&bw), Instant::now());
    let n = ad.take_update().unwrap();
    assert_eq!((n.bandwidth_kbps, n.average_rtt_ms), (Some(900), Some(30)));
    assert_eq!(n.summary().unwrap(), "RTT 30 ms · 900 kbit/s");
}

#[test]
fn malformed_or_foreign_data_never_panics_or_answers() {
    let mut ad = AutoDetect::default();
    let now = Instant::now();
    // Not an auto-detect PDU: a heartbeat (SEC_HEARTBEAT) and a licensing PDU.
    assert!(ad.on_pdu(&[0x00, 0x40, 0, 0, 0, 5, 3, 10], now).is_none());
    assert!(ad.on_pdu(&[0x80, 0x00, 0, 0], now).is_none());
    // Every truncation of valid requests.
    let mut all = vec![0x12, 0x00, 5, 0, 0xC0, 0x08];
    all.extend([0u8; 12]);
    let samples = [
        vec![0x06, 0x00, 1, 0, 0x01, 0x10],
        vec![0x08, 0x00, 2, 0, 0x02, 0x00, 4, 0, 9, 9, 9, 9],
        vec![0x08, 0x00, 4, 0, 0x2B, 0x00, 2, 0, 1, 1],
        all,
    ];
    for s in &samples {
        for n in 0..s.len() {
            let _ = ad.on_pdu(&pdu(&s[..n]), now);
            let _ = parse_request(&s[..n]);
        }
    }
    // Wrong headerTypeId (a response) and an unknown request type.
    assert!(parse_request(&[0x06, 0x01, 1, 0, 0x01, 0x00]).is_err());
    assert_eq!(
        parse_request(&[0x06, 0x00, 1, 0, 0x77, 0x00]).unwrap().1,
        Request::Other {
            request_type: 0x0077
        }
    );
    assert!(
        ad.on_pdu(&pdu(&[0x06, 0x00, 1, 0, 0x77, 0x00]), now)
            .is_none()
    );
    // A payload longer than the data is refused.
    assert!(parse_request(&[0x08, 0x00, 2, 0, 0x02, 0x00, 9, 0, 1]).is_err());
}
