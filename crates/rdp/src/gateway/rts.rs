//! RTS PDUs of RPC over HTTP v2 (MS-RPCH 2.2.3, 2.2.4): the control PDUs
//! that open the virtual connection (CONN/A1, CONN/B1 from the client;
//! CONN/A3, CONN/C2 from the outbound proxy), acknowledge received bytes
//! (FlowControlAck) and keep the channels alive (Ping).

use crate::cursor::{Put, Reader};
use crate::error::{Result, proto};

use super::dcerpc::{HEADER_LEN, Header, PFC_FIRST_FRAG, PFC_LAST_FRAG, PTYPE_RTS};

/// RTS header flags (MS-RPCH 2.2.3.6.1).
pub const FLAG_NONE: u16 = 0x0000;
pub const FLAG_PING: u16 = 0x0001;
pub const FLAG_OTHER_CMD: u16 = 0x0002;
pub const FLAG_RECYCLE_CHANNEL: u16 = 0x0004;
pub const FLAG_IN_CHANNEL: u16 = 0x0008;
pub const FLAG_OUT_CHANNEL: u16 = 0x0010;
pub const FLAG_EOF: u16 = 0x0020;
pub const FLAG_ECHO: u16 = 0x0040;

/// Forward destinations (MS-RPCH 2.2.3.3).
pub const FD_CLIENT: u32 = 0;
pub const FD_IN_PROXY: u32 = 1;
pub const FD_SERVER: u32 = 2;
pub const FD_OUT_PROXY: u32 = 3;

/// An RTS cookie (MS-RPCH 2.2.3.1).
pub type Cookie = [u8; 16];

/// The Flow Control Acknowledgment structure (MS-RPCH 2.2.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub bytes_received: u32,
    pub available_window: u32,
    pub channel_cookie: Cookie,
}

/// An RTS command (MS-RPCH 2.2.3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    ReceiveWindowSize(u32),
    FlowControlAck(Ack),
    ConnectionTimeout(u32),
    Cookie(Cookie),
    ChannelLifetime(u32),
    ClientKeepalive(u32),
    Version(u32),
    Empty,
    /// The number of padding bytes.
    Padding(u32),
    NegativeAnce,
    Ance,
    /// IPv4 (4 bytes) or IPv6 (16 bytes) address (2.2.3.2).
    ClientAddress(Vec<u8>),
    AssociationGroupId(Cookie),
    Destination(u32),
    PingTrafficSentNotify(u32),
}

impl Command {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Command::ReceiveWindowSize(v) => {
                out.put_u32(0);
                out.put_u32(*v);
            }
            Command::FlowControlAck(a) => {
                out.put_u32(1);
                out.put_u32(a.bytes_received);
                out.put_u32(a.available_window);
                out.put_bytes(&a.channel_cookie);
            }
            Command::ConnectionTimeout(v) => {
                out.put_u32(2);
                out.put_u32(*v);
            }
            Command::Cookie(c) => {
                out.put_u32(3);
                out.put_bytes(c);
            }
            Command::ChannelLifetime(v) => {
                out.put_u32(4);
                out.put_u32(*v);
            }
            Command::ClientKeepalive(v) => {
                out.put_u32(5);
                out.put_u32(*v);
            }
            Command::Version(v) => {
                out.put_u32(6);
                out.put_u32(*v);
            }
            Command::Empty => out.put_u32(7),
            Command::Padding(n) => {
                out.put_u32(8);
                out.put_u32(*n);
                out.put_zeros(*n as usize);
            }
            Command::NegativeAnce => out.put_u32(9),
            Command::Ance => out.put_u32(10),
            Command::ClientAddress(a) => {
                out.put_u32(11);
                out.put_u32(if a.len() == 16 { 1 } else { 0 });
                out.put_bytes(a);
                out.put_zeros(12);
            }
            Command::AssociationGroupId(c) => {
                out.put_u32(12);
                out.put_bytes(c);
            }
            Command::Destination(v) => {
                out.put_u32(13);
                out.put_u32(*v);
            }
            Command::PingTrafficSentNotify(v) => {
                out.put_u32(14);
                out.put_u32(*v);
            }
        }
    }

    fn read(r: &mut Reader) -> Result<Command> {
        Ok(match r.u32()? {
            0 => Command::ReceiveWindowSize(r.u32()?),
            1 => Command::FlowControlAck(Ack {
                bytes_received: r.u32()?,
                available_window: r.u32()?,
                channel_cookie: r.array()?,
            }),
            2 => Command::ConnectionTimeout(r.u32()?),
            3 => Command::Cookie(r.array()?),
            4 => Command::ChannelLifetime(r.u32()?),
            5 => Command::ClientKeepalive(r.u32()?),
            6 => Command::Version(r.u32()?),
            7 => Command::Empty,
            8 => {
                let n = r.u32()?;
                r.skip(n as usize)?;
                Command::Padding(n)
            }
            9 => Command::NegativeAnce,
            10 => Command::Ance,
            11 => {
                let len = match r.u32()? {
                    0 => 4,
                    1 => 16,
                    t => return proto(format!("RTS client address type {t}")),
                };
                let a = r.bytes(len)?.to_vec();
                r.skip(12)?;
                Command::ClientAddress(a)
            }
            12 => Command::AssociationGroupId(r.array()?),
            13 => Command::Destination(r.u32()?),
            14 => Command::PingTrafficSentNotify(r.u32()?),
            t => return proto(format!("unknown RTS command {t}")),
        })
    }
}

/// An RTS PDU: header flags and commands (MS-RPCH 2.2.3.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rts {
    pub flags: u16,
    pub commands: Vec<Command>,
}

impl Rts {
    pub fn new(flags: u16, commands: Vec<Command>) -> Self {
        Self { flags, commands }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        Header {
            ptype: PTYPE_RTS,
            flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            frag_length: 0,
            auth_length: 0,
            call_id: 0,
        }
        .write(&mut b);
        b.put_u16(self.flags);
        b.put_u16(self.commands.len() as u16);
        for c in &self.commands {
            c.write(&mut b);
        }
        let n = b.len() as u16;
        b[8..10].copy_from_slice(&n.to_le_bytes());
        b
    }

    /// Parses one whole RTS PDU.
    pub fn parse(pdu: &[u8]) -> Result<Rts> {
        let h = Header::parse(pdu)?;
        if h.ptype != PTYPE_RTS {
            return proto(format!("RPC PDU type {} instead of RTS", h.ptype));
        }
        let mut r = Reader::new(pdu);
        r.skip(HEADER_LEN)?;
        let flags = r.u16()?;
        let n = r.u16()?;
        let mut commands = Vec::with_capacity(n.min(16) as usize);
        for _ in 0..n {
            commands.push(Command::read(&mut r)?);
        }
        if r.remaining() != 0 {
            return proto("trailing bytes after the RTS commands");
        }
        Ok(Rts { flags, commands })
    }

    /// The first command's u32 value of a kind picked by `f`.
    pub fn find<T>(&self, f: impl Fn(&Command) -> Option<T>) -> Option<T> {
        self.commands.iter().find_map(f)
    }

    /// The flow control acknowledgment this PDU carries, if any
    /// (FlowControlAck 2.2.4.50 or FlowControlAckWithDestination 2.2.4.51).
    pub fn ack(&self) -> Option<Ack> {
        self.find(|c| match c {
            Command::FlowControlAck(a) => Some(*a),
            _ => None,
        })
    }

    /// The ConnectionTimeout command, if any.
    pub fn connection_timeout(&self) -> Option<u32> {
        self.find(|c| match c {
            Command::ConnectionTimeout(v) => Some(*v),
            _ => None,
        })
    }

    /// The ReceiveWindowSize command, if any.
    pub fn receive_window(&self) -> Option<u32> {
        self.find(|c| match c {
            Command::ReceiveWindowSize(v) => Some(*v),
            _ => None,
        })
    }

    fn kinds(&self) -> Vec<u32> {
        self.commands
            .iter()
            .map(|c| {
                let mut b = Vec::new();
                c.write(&mut b);
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            })
            .collect()
    }

    /// CONN/A3: flags none, one ConnectionTimeout (2.2.4.4).
    pub fn is_conn_a3(&self) -> bool {
        self.flags == FLAG_NONE && self.kinds() == [2]
    }

    /// CONN/C2: flags none; Version, ReceiveWindowSize, ConnectionTimeout
    /// (2.2.4.9).
    pub fn is_conn_c2(&self) -> bool {
        self.flags == FLAG_NONE && self.kinds() == [6, 0, 2]
    }
}

/// The RPC over HTTP v2 version the client speaks (2.2.3.5.7).
pub const VERSION: u32 = 1;

/// CONN/A1, client to outbound proxy on the OUT channel (2.2.4.2).
pub fn conn_a1(vc: &Cookie, out_channel: &Cookie, receive_window: u32) -> Vec<u8> {
    Rts::new(
        FLAG_NONE,
        vec![
            Command::Version(VERSION),
            Command::Cookie(*vc),
            Command::Cookie(*out_channel),
            Command::ReceiveWindowSize(receive_window),
        ],
    )
    .encode()
}

/// CONN/B1, client to inbound proxy on the IN channel (2.2.4.5).
pub fn conn_b1(
    vc: &Cookie,
    in_channel: &Cookie,
    lifetime: u32,
    keepalive: u32,
    association: &Cookie,
) -> Vec<u8> {
    Rts::new(
        FLAG_NONE,
        vec![
            Command::Version(VERSION),
            Command::Cookie(*vc),
            Command::Cookie(*in_channel),
            Command::ChannelLifetime(lifetime),
            Command::ClientKeepalive(keepalive),
            Command::AssociationGroupId(*association),
        ],
    )
    .encode()
}

/// FlowControlAckWithDestination (2.2.4.51): the client acknowledges the
/// OUT channel's bytes to the outbound proxy, forwarded by the inbound proxy.
pub fn flow_control_ack(destination: u32, ack: Ack) -> Vec<u8> {
    Rts::new(
        FLAG_OTHER_CMD,
        vec![
            Command::Destination(destination),
            Command::FlowControlAck(ack),
        ],
    )
    .encode()
}

/// Ping (2.2.4.49): keeps the IN channel alive.
pub fn ping() -> Vec<u8> {
    Rts::new(FLAG_PING, Vec::new()).encode()
}

/// The sender's available window after an acknowledgment
/// (MS-RPCH 3.2.1.5.1.1): the acknowledged window minus what is still in
/// flight. None when the acknowledgment is impossible.
pub fn sender_window(ack: &Ack, bytes_sent: u64) -> Option<u32> {
    let in_flight = bytes_sent.checked_sub(ack.bytes_received as u64)?;
    (ack.available_window as u64)
        .checked_sub(in_flight)
        .map(|w| w as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VC: Cookie = [0x11; 16];
    const OUT: Cookie = [0x22; 16];
    const IN: Cookie = [0x33; 16];
    const ASSOC: Cookie = [0x44; 16];

    #[test]
    fn conn_a1_layout() {
        // 76 bytes, the OUT channel request's Content-Length (2.1.2.1.2).
        let b = conn_a1(&VC, &OUT, 0x10000);
        assert_eq!(b.len(), 76);
        assert_eq!(
            &b[..16],
            &[5, 0, 20, 3, 0x10, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&b[16..20], &[0, 0, 4, 0], "flags none, 4 commands");
        assert_eq!(&b[20..28], &[6, 0, 0, 0, 1, 0, 0, 0], "Version 1");
        assert_eq!(&b[28..32], &[3, 0, 0, 0]);
        assert_eq!(&b[32..48], &VC);
        assert_eq!(&b[52..68], &OUT);
        assert_eq!(&b[68..], &[0, 0, 0, 0, 0, 0, 1, 0], "window 64 KiB");
    }

    #[test]
    fn conn_b1_layout() {
        let b = conn_b1(&VC, &IN, 0x4000_0000, 300_000, &ASSOC);
        assert_eq!(b.len(), 104);
        let r = Rts::parse(&b).unwrap();
        assert_eq!(r.flags, FLAG_NONE);
        assert_eq!(
            r.commands,
            vec![
                Command::Version(1),
                Command::Cookie(VC),
                Command::Cookie(IN),
                Command::ChannelLifetime(0x4000_0000),
                Command::ClientKeepalive(300_000),
                Command::AssociationGroupId(ASSOC),
            ]
        );
        assert_eq!(&b[84..88], &[12, 0, 0, 0], "AssociationGroupId last");
    }

    #[test]
    fn every_command_round_trips() {
        let all = vec![
            Command::ReceiveWindowSize(65536),
            Command::FlowControlAck(Ack {
                bytes_received: 1,
                available_window: 2,
                channel_cookie: OUT,
            }),
            Command::ConnectionTimeout(120_000),
            Command::Cookie(VC),
            Command::ChannelLifetime(0x4000_0000),
            Command::ClientKeepalive(0),
            Command::Version(1),
            Command::Empty,
            Command::Padding(5),
            Command::NegativeAnce,
            Command::Ance,
            Command::ClientAddress(vec![127, 0, 0, 1]),
            Command::ClientAddress(vec![0xfe; 16]),
            Command::AssociationGroupId(ASSOC),
            Command::Destination(FD_OUT_PROXY),
            Command::PingTrafficSentNotify(9),
        ];
        let pdu = Rts::new(FLAG_OTHER_CMD | FLAG_ECHO, all.clone()).encode();
        let back = Rts::parse(&pdu).unwrap();
        assert_eq!(back.commands, all);
        assert_eq!(back.flags, FLAG_OTHER_CMD | FLAG_ECHO);
    }

    #[test]
    fn recognises_conn_a3_and_c2() {
        let a3 = Rts::new(FLAG_NONE, vec![Command::ConnectionTimeout(120_000)]).encode();
        assert_eq!(a3.len(), 28);
        let a3 = Rts::parse(&a3).unwrap();
        assert!(a3.is_conn_a3() && !a3.is_conn_c2());
        assert_eq!(a3.connection_timeout(), Some(120_000));
        let c2 = Rts::new(
            FLAG_NONE,
            vec![
                Command::Version(1),
                Command::ReceiveWindowSize(0x10000),
                Command::ConnectionTimeout(120_000),
            ],
        )
        .encode();
        assert_eq!(c2.len(), 44);
        let c2 = Rts::parse(&c2).unwrap();
        assert!(c2.is_conn_c2() && !c2.is_conn_a3());
        assert_eq!(c2.receive_window(), Some(0x10000));
    }

    #[test]
    fn flow_control_ack_with_destination_layout() {
        let ack = Ack {
            bytes_received: 0x1234,
            available_window: 0x10000,
            channel_cookie: OUT,
        };
        let b = flow_control_ack(FD_OUT_PROXY, ack);
        assert_eq!(b.len(), 56);
        assert_eq!(&b[16..20], &[2, 0, 2, 0]);
        assert_eq!(&b[20..28], &[13, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(Rts::parse(&b).unwrap().ack(), Some(ack));
        assert_eq!(ping().len(), 20);
        assert_eq!(Rts::parse(&ping()).unwrap().flags, FLAG_PING);
    }

    #[test]
    fn malformed_rts_is_an_error() {
        let mut b = conn_a1(&VC, &OUT, 0x10000);
        b[18] = 5; // five commands, four present
        assert!(Rts::parse(&b).is_err());
        let mut b = conn_a1(&VC, &OUT, 0x10000);
        b[68] = 99; // unknown command type
        assert!(Rts::parse(&b).is_err());
        let mut b = Rts::new(FLAG_NONE, vec![Command::Padding(4)]).encode();
        b[24] = 200; // padding longer than the PDU
        assert!(Rts::parse(&b).is_err());
    }

    /// MS-RPCH 4.2: the sender's window after each acknowledgment.
    #[test]
    fn sender_window_follows_the_spec_example() {
        let ack = |bytes_received, available_window| Ack {
            bytes_received,
            available_window,
            channel_cookie: IN,
        };
        // 750 bytes sent; acks (250, 850), (750, 550), (750, 1000).
        assert_eq!(sender_window(&ack(250, 850), 750), Some(350));
        assert_eq!(sender_window(&ack(750, 550), 750), Some(550));
        assert_eq!(sender_window(&ack(750, 1000), 750), Some(1000));
        // More acknowledged than sent, or more in flight than the window.
        assert_eq!(sender_window(&ack(800, 1000), 750), None);
        assert_eq!(sender_window(&ack(0, 100), 750), None);
    }
}
