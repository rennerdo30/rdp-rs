//! Server side of the connection setup: X.224 negotiation (MS-RDPBCGR
//! 2.2.1.1, 2.2.1.2), the MCS connect and domain PDUs (2.2.1.3 to 2.2.1.9,
//! T.125) and the GCC conference data (2.2.1.3, 2.2.1.4, T.124).
//!
//! The encoders mirror the client's parsers in [`crate::x224`],
//! [`crate::mcs`] and [`crate::gcc`]; the tests run every PDU through them.

use crate::cursor::{Put, Reader, le32};
use crate::der::{DerReader, integer, octet, put_len, seq, tlv};
use crate::error::{Error, Result, proto};
use crate::mcs::{put_per_len, read_per_len};
use crate::x224::{PROTOCOL_SSL, tpkt};

/// RDP_NEG_FAILURE failureCode (2.2.1.2.2): the server requires TLS
/// (Enhanced RDP Security) and the client did not offer it.
pub const SSL_REQUIRED_BY_SERVER: u32 = 0x0000_0001;

/// MCS channel ids (2.2.1.4.4): the I/O channel, then one per requested
/// static channel, then the user channel.
pub const IO_CHANNEL: u16 = 0x03EB;
/// The first static virtual channel id.
const FIRST_STATIC_CHANNEL: u16 = IO_CHANNEL + 1;
/// MCS user ids are channel ids counted from 1001 (T.125 `UserId`, PER
/// encoded as the offset from 1001).
const USER_ID_BASE: u16 = 1001;

/// Server Core Data version (2.2.1.4.2): RDP 5.0 to 8.1 servers.
const RDP_VERSION_5_PLUS: u32 = 0x0008_0004;

const CS_CORE: u16 = 0xC001;
const CS_SECURITY: u16 = 0xC002;
const CS_NET: u16 = 0xC003;
const CS_MCS_MSGCHANNEL: u16 = 0xC006;
const SC_CORE: u16 = 0x0C01;
const SC_SECURITY: u16 = 0x0C02;
const SC_NET: u16 = 0x0C03;

/// The X.224 Connection Request (2.2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// requestedProtocols of the RDP Negotiation Request (2.2.1.1.1);
    /// None when the client sent none (it only speaks legacy RDP security).
    pub requested_protocols: Option<u32>,
    /// The routing token or cookie line ("Cookie: mstshash=user"), without
    /// its CR LF; None when there was none.
    pub cookie: Option<String>,
}

/// Parses a TPKT-framed X.224 Connection Request (2.2.1.1): the cookie or
/// routing token up to CR LF, then the optional RDP_NEG_REQ (type 0x01).
/// An RDP Correlation Info after it (2.2.1.1.2) is ignored.
pub fn parse_connection_request(frame: &[u8]) -> Result<ConnectionRequest> {
    let p = frame.get(4..).unwrap_or_default();
    if frame.first() != Some(&0x03) || p.len() < 7 || p[1] & 0xF0 != 0xE0 {
        return proto("expected X.224 Connection Request");
    }
    let li = p[0] as usize;
    let tpdu = p
        .get(..li + 1)
        .ok_or_else(|| Error::Protocol("X.224 length indicator exceeds the PDU".into()))?;
    let mut rest = tpdu.get(7..).unwrap_or_default();
    let mut cookie = None;
    // The variable part starts with the cookie or token unless it is the
    // negotiation request itself.
    if !rest.is_empty() && rest[0] != 0x01 {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| Error::Protocol("X.224 cookie not terminated by CR LF".into()))?;
        cookie = Some(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[end + 2..];
    }
    let requested_protocols = match rest {
        [0x01, _flags, 8, 0, ..] if rest.len() >= 8 => le32(rest, 4),
        [] => None,
        _ => return proto("malformed RDP Negotiation Request"),
    };
    Ok(ConnectionRequest {
        requested_protocols,
        cookie,
    })
}

/// Picks the security protocol (3.3.5.3.1). Remora Host speaks TLS only:
/// PROTOCOL_SSL when the client offers it, also when it offers CredSSP
/// (HYBRID, HYBRID_EX) next to it, because NLA is not implemented yet.
/// Anything else, legacy RDP security included, is refused with
/// SSL_REQUIRED_BY_SERVER; plaintext RDP is never selected.
pub fn select_protocol(requested: Option<u32>) -> std::result::Result<u32, u32> {
    match requested {
        Some(p) if p & PROTOCOL_SSL != 0 => Ok(PROTOCOL_SSL),
        _ => Err(SSL_REQUIRED_BY_SERVER),
    }
}

/// X.224 Connection Confirm header (2.2.1.2): LI 14, CC, dst-ref 0,
/// src-ref 0x1234 (as in the spec's example, 4.1.2), class 0.
fn confirm(neg: [u8; 8]) -> Vec<u8> {
    let mut b = vec![14, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00];
    b.put_bytes(&neg);
    tpkt(&b)
}

/// X.224 Connection Confirm with an RDP Negotiation Response (2.2.1.2.1).
pub fn connection_confirm(selected: u32, flags: u8) -> Vec<u8> {
    let mut neg = [0u8; 8];
    neg[0] = 0x02; // TYPE_RDP_NEG_RSP
    neg[1] = flags;
    neg[2] = 8;
    neg[4..].copy_from_slice(&selected.to_le_bytes());
    confirm(neg)
}

/// X.224 Connection Confirm with an RDP Negotiation Failure (2.2.1.2.2).
pub fn negotiation_failure(code: u32) -> Vec<u8> {
    let mut neg = [0u8; 8];
    neg[0] = 0x03; // TYPE_RDP_NEG_FAILURE
    neg[2] = 8;
    neg[4..].copy_from_slice(&code.to_le_bytes());
    confirm(neg)
}

/// Parses MCS Connect Initial (2.2.1.3, T.125 BER) and returns its user
/// data: the GCC Conference Create Request.
pub fn parse_connect_initial(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 2 || data[0] != 0x7F || data[1] != 0x65 {
        return proto("expected MCS Connect Initial");
    }
    let body = DerReader::new(&data[1..]).expect(0x65)?;
    let mut r = DerReader::new(body);
    r.expect(0x04)?; // callingDomainSelector
    r.expect(0x04)?; // calledDomainSelector
    r.expect(0x01)?; // upwardFlag
    r.expect(0x30)?; // targetParameters
    r.expect(0x30)?; // minimumParameters
    r.expect(0x30)?; // maximumParameters
    Ok(r.expect(0x04)?.to_vec())
}

/// MCS Connect Response (2.2.1.4) with result rt-successful and the
/// domain parameters of the spec's example (4.1.4).
pub fn connect_response(gcc: &[u8]) -> Vec<u8> {
    let params: Vec<u8> = [22u32, 3, 0, 1, 0, 1, 0xFFF8, 2]
        .iter()
        .flat_map(|&v| integer(v))
        .collect();
    let mut body = tlv(0x0A, &[0]); // result: rt-successful
    body.extend(integer(0)); // calledConnectId
    body.extend(seq(&params)); // domainParameters
    body.extend(octet(gcc)); // userData
    let mut out = vec![0x7F, 0x66];
    put_len(&mut out, body.len());
    out.extend(body);
    out
}

/// What the server needs from the client's GCC conference data (2.2.1.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientData {
    /// Client Core Data (2.2.1.3.2) version, e.g. 0x00080004.
    pub version: u32,
    pub width: u16,
    pub height: u16,
    pub client_name: String,
    pub keyboard_layout: u32,
    pub client_build: u32,
    /// highColorDepth, when present.
    pub high_color_depth: Option<u16>,
    /// earlyCapabilityFlags, when present.
    pub early_capability_flags: u16,
    /// serverSelectedProtocol, when present (2.2.1.3.2): MUST match the
    /// protocol of the Connection Confirm.
    pub server_selected_protocol: Option<u32>,
    /// encryptionMethods of the Client Security Data (2.2.1.3.3).
    pub encryption_methods: u32,
    /// Static virtual channels the client asked for (2.2.1.3.4): name and
    /// options, in order.
    pub channels: Vec<(String, u32)>,
    /// The client sent Client Message Channel Data (2.2.1.3.7).
    pub message_channel: bool,
}

/// Parses the GCC Conference Create Request (T.124 ConnectData, 2.2.1.3)
/// and its client data blocks. Unknown blocks are skipped.
pub fn parse_conference_create_request(data: &[u8]) -> Result<ClientData> {
    let Some(pos) = data.windows(4).position(|w| w == b"Duca") else {
        return proto("GCC request without client data key");
    };
    let (len, n) = read_per_len(data, pos + 4)?;
    let start = pos + 4 + n;
    let blocks = data
        .get(start..start + len)
        .ok_or_else(|| Error::Protocol("GCC client data truncated".into()))?;
    let mut cd = ClientData::default();
    let mut core = false;
    let mut r = Reader::new(blocks);
    while r.remaining() >= 4 {
        let ty = r.u16()?;
        let blen = r.u16()? as usize;
        if blen < 4 {
            return proto("bad client data block length");
        }
        let body = r.bytes(blen - 4)?;
        let mut b = Reader::new(body);
        match ty {
            CS_CORE => {
                core = true;
                parse_core(&mut b, &mut cd)?;
            }
            CS_SECURITY => cd.encryption_methods = b.u32()?,
            CS_NET => {
                let count = b.u32()?;
                if count > 31 {
                    // CHANNEL_MAX_COUNT (2.2.1.3.4.1).
                    return proto(format!("{count} static channels requested"));
                }
                for _ in 0..count {
                    let name = b.bytes(8)?;
                    let end = name.iter().position(|&c| c == 0).unwrap_or(8);
                    let options = b.u32()?;
                    cd.channels
                        .push((String::from_utf8_lossy(&name[..end]).into_owned(), options));
                }
            }
            CS_MCS_MSGCHANNEL => cd.message_channel = true,
            _ => {}
        }
    }
    if !core {
        return proto("client sent no core data");
    }
    if cd.width == 0 || cd.height == 0 {
        return proto("client core data with an empty desktop");
    }
    Ok(cd)
}

/// TS_UD_CS_CORE (2.2.1.3.2): the fixed part, then the optional fields as
/// far as the client sent them.
fn parse_core(b: &mut Reader, cd: &mut ClientData) -> Result<()> {
    cd.version = b.u32()?;
    cd.width = b.u16()?;
    cd.height = b.u16()?;
    b.u16()?; // colorDepth
    b.u16()?; // SASSequence
    cd.keyboard_layout = b.u32()?;
    cd.client_build = b.u32()?;
    let name = b.bytes(32)?;
    cd.client_name = utf16_until_null(name);
    b.skip(12)?; // keyboardType, keyboardSubType, keyboardFunctionKey
    b.skip(64)?; // imeFileName
    // Optional fields: each present only if all before it are.
    if b.remaining() < 2 {
        return Ok(());
    }
    b.u16()?; // postBeta2ColorDepth
    if b.remaining() < 2 {
        return Ok(());
    }
    b.u16()?; // clientProductId
    if b.remaining() < 4 {
        return Ok(());
    }
    b.u32()?; // serialNumber
    if b.remaining() < 2 {
        return Ok(());
    }
    cd.high_color_depth = Some(b.u16()?);
    if b.remaining() < 2 {
        return Ok(());
    }
    b.u16()?; // supportedColorDepths
    if b.remaining() < 2 {
        return Ok(());
    }
    cd.early_capability_flags = b.u16()?;
    if b.remaining() < 64 {
        return Ok(());
    }
    b.skip(64)?; // clientDigProductId
    if b.remaining() < 2 {
        return Ok(());
    }
    b.skip(2)?; // connectionType, pad1octet
    if b.remaining() < 4 {
        return Ok(());
    }
    cd.server_selected_protocol = Some(b.u32()?);
    Ok(())
}

pub(crate) fn utf16_until_null(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The channel ids the server assigns for a client's conference data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPlan {
    pub io_channel: u16,
    /// One id per requested static channel, in the client's order.
    pub static_channels: Vec<u16>,
    /// The MCS user channel of the client (Attach User Confirm).
    pub user_channel: u16,
}

impl ChannelPlan {
    /// I/O channel 1003, the static channels from 1004 on, then the user
    /// channel, as Windows assigns them.
    pub fn new(static_count: usize) -> ChannelPlan {
        let static_channels: Vec<u16> = (0..static_count as u16)
            .map(|i| FIRST_STATIC_CHANNEL + i)
            .collect();
        ChannelPlan {
            io_channel: IO_CHANNEL,
            user_channel: FIRST_STATIC_CHANNEL + static_count as u16,
            static_channels,
        }
    }
}

/// The server data blocks (2.2.1.4): Server Core Data echoing the client's
/// requested protocols, Server Security Data without encryption (TLS
/// protects the connection: ENCRYPTION_METHOD_NONE and ENCRYPTION_LEVEL_NONE,
/// so no server random or certificate follows, 2.2.1.4.3), and Server Network
/// Data with the I/O channel and an id for every requested static channel
/// (2.2.1.4.4). No message channel (2.2.1.4.5) is offered.
pub fn server_data_blocks(requested_protocols: u32, plan: &ChannelPlan) -> Vec<u8> {
    let mut out = Vec::new();
    let block = |out: &mut Vec<u8>, ty: u16, body: &[u8]| {
        out.put_u16(ty);
        out.put_u16((body.len() + 4) as u16);
        out.put_bytes(body);
    };
    let mut core = Vec::new();
    core.put_u32(RDP_VERSION_5_PLUS);
    core.put_u32(requested_protocols); // clientRequestedProtocols
    core.put_u32(0); // earlyCapabilityFlags
    block(&mut out, SC_CORE, &core);

    let mut sec = Vec::new();
    sec.put_u32(0); // encryptionMethod: ENCRYPTION_METHOD_NONE
    sec.put_u32(0); // encryptionLevel: ENCRYPTION_LEVEL_NONE
    block(&mut out, SC_SECURITY, &sec);

    let mut net = Vec::new();
    net.put_u16(plan.io_channel);
    net.put_u16(plan.static_channels.len() as u16);
    for id in &plan.static_channels {
        net.put_u16(*id);
    }
    if plan.static_channels.len() % 2 == 1 {
        net.put_u16(0); // Pad
    }
    block(&mut out, SC_NET, &net);
    out
}

/// GCC Conference Create Response in T.124 ConnectData (2.2.1.4), laid out
/// as in the spec's example (4.1.4): the server data key "McDn" and the
/// blocks.
pub fn conference_create_response(blocks: &[u8]) -> Vec<u8> {
    // t124Identifier (0.0.20.124.0.1), connectPDU length (0x2A, as Windows
    // and the example send it), ConferenceCreateResponse, nodeID 0x79F3,
    // tag 1, result success, one userData set of type h221NonStandard.
    let mut out = vec![
        0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01, 0x2A, 0x14, 0x76, 0x0A, 0x01, 0x01, 0x00, 0x01,
        0xC0, 0x00,
    ];
    out.put_bytes(b"McDn");
    put_per_len(&mut out, blocks.len());
    out.put_bytes(blocks);
    out
}

/// A client-to-server MCS domain PDU (T.125 PER, 2.2.1.5 to 2.2.1.8, 2.2.8).
#[derive(Debug, PartialEq, Eq)]
pub enum ClientDomainPdu<'a> {
    /// Erect Domain Request (2.2.1.5).
    ErectDomain,
    /// Attach User Request (2.2.1.6).
    AttachUser,
    /// Channel Join Request (2.2.1.8): the user channel and the channel.
    ChannelJoin { user_channel: u16, channel: u16 },
    /// Send Data Request: data on a channel.
    SendData {
        user_channel: u16,
        channel: u16,
        data: &'a [u8],
    },
    /// Disconnect Provider Ultimatum (2.2.2.3).
    Disconnect { reason: u8 },
    /// Any other DomainMCSPDU choice.
    Other(u8),
}

/// Parses one client domain PDU.
pub fn parse_client_domain_pdu(d: &[u8]) -> Result<ClientDomainPdu<'_>> {
    let Some(&first) = d.first() else {
        return proto("empty MCS PDU");
    };
    let user = |at: usize| -> Result<u16> {
        let v = d
            .get(at..at + 2)
            .ok_or_else(|| Error::Protocol("truncated MCS PDU".into()))?;
        Ok(u16::from_be_bytes([v[0], v[1]]) + USER_ID_BASE)
    };
    let be16 = |at: usize| -> Result<u16> {
        let v = d
            .get(at..at + 2)
            .ok_or_else(|| Error::Protocol("truncated MCS PDU".into()))?;
        Ok(u16::from_be_bytes([v[0], v[1]]))
    };
    match first >> 2 {
        1 => Ok(ClientDomainPdu::ErectDomain),
        8 => {
            let reason = ((first & 3) << 1) | (d.get(1).copied().unwrap_or(0) >> 7);
            Ok(ClientDomainPdu::Disconnect { reason })
        }
        10 => Ok(ClientDomainPdu::AttachUser),
        14 => Ok(ClientDomainPdu::ChannelJoin {
            user_channel: user(1)?,
            channel: be16(3)?,
        }),
        25 => {
            let user_channel = user(1)?;
            let channel = be16(3)?;
            let (len, n) = read_per_len(d, 6)?;
            let start = 6 + n;
            let data = d
                .get(start..start + len)
                .ok_or_else(|| Error::Protocol("Send Data Request length exceeds PDU".into()))?;
            Ok(ClientDomainPdu::SendData {
                user_channel,
                channel,
                data,
            })
        }
        other => Ok(ClientDomainPdu::Other(other)),
    }
}

/// Attach User Confirm (2.2.1.7): result rt-successful and the initiator,
/// the client's user channel.
pub fn attach_user_confirm(user_channel: u16) -> Vec<u8> {
    let mut out = vec![(11 << 2) | 0x02, 0x00];
    out.put_u16_be(user_channel - USER_ID_BASE);
    out
}

/// Channel Join Confirm (2.2.1.9): rt-successful, the initiator, the
/// requested channel and the joined channel.
pub fn channel_join_confirm(user_channel: u16, channel: u16) -> Vec<u8> {
    let mut out = vec![(15 << 2) | 0x02, 0x00];
    out.put_u16_be(user_channel - USER_ID_BASE);
    out.put_u16_be(channel);
    out.put_u16_be(channel);
    out
}

/// Channel Join Confirm refusing the channel (rt-no-such-channel, T.125).
pub fn channel_join_refused(user_channel: u16, channel: u16) -> Vec<u8> {
    let mut out = vec![15 << 2, 14];
    out.put_u16_be(user_channel - USER_ID_BASE);
    out.put_u16_be(channel);
    out
}

/// Send Data Indication: server data on a channel, from the server's own
/// MCS user (1002), high priority, one segment.
pub fn send_data_indication(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![26 << 2];
    out.put_u16_be(1); // initiator: user 1002
    out.put_u16_be(channel);
    out.put_u8(0x70); // high priority, begin + end segmentation
    put_per_len(&mut out, data.len());
    out.put_bytes(data);
    out
}

/// Disconnect Provider Ultimatum (2.2.2.3) with reason rn-provider-initiated.
pub fn disconnect_provider_ultimatum() -> Vec<u8> {
    // DomainMCSPDU choice 8 (0x20), then the 3-bit reason 1 split across
    // the two low bits of the first byte and the top bit of the second.
    vec![0x20, 0x80]
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
