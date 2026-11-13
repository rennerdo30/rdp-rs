//! T.125 MCS: BER-encoded connect PDUs and PER-encoded domain PDUs.

use crate::cursor::Put;
use crate::der::{DerReader, integer, octet, put_len, seq, tlv};
use crate::error::{Result, proto};

const USER_ID_BASE: u16 = 1001;

fn domain_parameters(v: [u32; 8]) -> Vec<u8> {
    let c: Vec<u8> = v.iter().flat_map(|&x| integer(x)).collect();
    seq(&c)
}

/// MCS Connect Initial carrying the GCC Conference Create Request.
pub fn connect_initial(gcc: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(octet(&[1])); // callingDomainSelector
    body.extend(octet(&[1])); // calledDomainSelector
    body.extend(tlv(0x01, &[0xFF])); // upwardFlag
    body.extend(domain_parameters([34, 2, 0, 1, 0, 1, 65535, 2]));
    body.extend(domain_parameters([1, 1, 1, 1, 0, 1, 1056, 2]));
    body.extend(domain_parameters([65535, 64535, 65535, 1, 0, 1, 65535, 2]));
    body.extend(octet(gcc));
    let mut out = vec![0x7F, 0x65];
    put_len(&mut out, body.len());
    out.extend(body);
    out
}

/// Parses MCS Connect Response and returns its user data (GCC Conference Create Response).
pub fn parse_connect_response(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 2 || data[0] != 0x7F || data[1] != 0x66 {
        return proto("expected MCS Connect Response");
    }
    let body = DerReader::new(&data[1..]).expect(0x66)?;
    let mut r = DerReader::new(body);
    let result = r.expect(0x0A)?;
    if result.first().copied() != Some(0) {
        return proto(format!("MCS connect rejected, result {:?}", result.first()));
    }
    r.expect(0x02)?; // calledConnectId
    r.expect(0x30)?; // domainParameters
    Ok(r.expect(0x04)?.to_vec())
}

pub fn put_per_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.put_u16_be(0x8000 | n as u16);
    }
}

pub fn read_per_len(d: &[u8], at: usize) -> Result<(usize, usize)> {
    let b = *d.get(at).ok_or_else(|| crate::Error::Protocol("truncated PER length".into()))?;
    if b & 0x80 == 0 {
        return Ok((b as usize, 1));
    }
    if b & 0x40 != 0 {
        return proto("fragmented PER length not supported");
    }
    let lo = *d.get(at + 1).ok_or_else(|| crate::Error::Protocol("truncated PER length".into()))?;
    Ok(((((b & 0x3F) as usize) << 8) | lo as usize, 2))
}

pub fn erect_domain_request() -> Vec<u8> {
    vec![0x04, 0x01, 0x00, 0x01, 0x00]
}

pub fn attach_user_request() -> Vec<u8> {
    vec![0x28]
}

pub fn parse_attach_user_confirm(d: &[u8]) -> Result<u16> {
    if d.len() < 4 || d[0] >> 2 != 11 {
        return proto("expected MCS Attach User Confirm");
    }
    if d[1] != 0 {
        return proto(format!("attach user failed, result {}", d[1]));
    }
    Ok(u16::from_be_bytes([d[2], d[3]]) + USER_ID_BASE)
}

pub fn channel_join_request(user_id: u16, channel: u16) -> Vec<u8> {
    let mut out = vec![0x38];
    out.put_u16_be(user_id - USER_ID_BASE);
    out.put_u16_be(channel);
    out
}

pub fn parse_channel_join_confirm(d: &[u8]) -> Result<u16> {
    if d.len() < 6 || d[0] >> 2 != 15 {
        return proto("expected MCS Channel Join Confirm");
    }
    if d[1] != 0 {
        return proto(format!("channel join failed, result {}", d[1]));
    }
    let requested = u16::from_be_bytes([d[4], d[5]]);
    Ok(if d.len() >= 8 { u16::from_be_bytes([d[6], d[7]]) } else { requested })
}

pub fn send_data_request(user_id: u16, channel: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x64];
    out.put_u16_be(user_id - USER_ID_BASE);
    out.put_u16_be(channel);
    out.put_u8(0x70); // high priority, begin + end segmentation
    put_per_len(&mut out, data.len());
    out.put_bytes(data);
    out
}

/// Disconnect Provider Ultimatum, reason rn-user-requested.
pub fn disconnect_provider_ultimatum() -> Vec<u8> {
    vec![0x21, 0x80]
}

pub enum DomainPdu<'a> {
    SendDataIndication { channel: u16, data: &'a [u8] },
    DisconnectProviderUltimatum { reason: u8 },
    Other(u8),
}

pub fn parse_domain_pdu(d: &[u8]) -> Result<DomainPdu<'_>> {
    let Some(&first) = d.first() else { return proto("empty MCS PDU") };
    match first >> 2 {
        26 => {
            if d.len() < 6 {
                return proto("truncated Send Data Indication");
            }
            let channel = u16::from_be_bytes([d[3], d[4]]);
            let (len, n) = read_per_len(d, 6)?;
            let start = 6 + n;
            let data = d
                .get(start..start + len)
                .ok_or_else(|| crate::Error::Protocol("Send Data Indication length exceeds PDU".into()))?;
            Ok(DomainPdu::SendDataIndication { channel, data })
        }
        8 => {
            let reason = ((first & 3) << 1) | (d.get(1).copied().unwrap_or(0) >> 7);
            Ok(DomainPdu::DisconnectProviderUltimatum { reason })
        }
        other => Ok(DomainPdu::Other(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_data_request_round_trips_through_indication_parser() {
        let payload = vec![0xAB; 300];
        let mut req = send_data_request(1007, 1003, &payload);
        req[0] = 26 << 2; // pretend the server echoed it as an indication
        match parse_domain_pdu(&req).unwrap() {
            DomainPdu::SendDataIndication { channel, data } => {
                assert_eq!(channel, 1003);
                assert_eq!(data, &payload[..]);
            }
            _ => panic!("wrong PDU"),
        }
    }

    #[test]
    fn connect_initial_header() {
        let ci = connect_initial(&[0u8; 300]);
        assert_eq!(&ci[..2], &[0x7F, 0x65]);
        assert_eq!(ci[2], 0x82);
        let len = u16::from_be_bytes([ci[3], ci[4]]) as usize;
        assert_eq!(len + 5, ci.len());
    }
}
