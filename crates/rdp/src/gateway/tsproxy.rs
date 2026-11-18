//! NDR marshaling of the TsProxyRpcInterface calls (MS-TSGU 2.2.9, 3.6.5
//! and the IDL in its appendix A), NDR 2.0 little-endian ([C706] 14).
//!
//! Requests are built exactly; responses are parsed with bounds checks.
//! Every response ends with fixed-size out parameters (context handle,
//! id, HRESULT), which are read from the end of the stub; the TSG_PACKET
//! before them is parsed for what the client uses (capabilities, idle
//! timeout, redirection flags, messages).

use crate::cursor::{Put, Reader, utf16le};
use crate::error::{Error, Result, proto};

/// Opnums (MS-TSGU 3.2.6).
pub const OP_CREATE_TUNNEL: u16 = 1;
pub const OP_AUTHORIZE_TUNNEL: u16 = 2;
pub const OP_MAKE_TUNNEL_CALL: u16 = 3;
pub const OP_CREATE_CHANNEL: u16 = 4;
pub const OP_CLOSE_CHANNEL: u16 = 6;
pub const OP_CLOSE_TUNNEL: u16 = 7;
pub const OP_SETUP_RECEIVE_PIPE: u16 = 8;
pub const OP_SEND_TO_SERVER: u16 = 9;

/// Packet types (MS-TSGU 2.2.5.2).
pub const TSG_PACKET_TYPE_HEADER: u32 = 0x4844;
pub const TSG_PACKET_TYPE_VERSIONCAPS: u32 = 0x5643;
pub const TSG_PACKET_TYPE_QUARREQUEST: u32 = 0x5152;
pub const TSG_PACKET_TYPE_RESPONSE: u32 = 0x5052;
pub const TSG_PACKET_TYPE_QUARENC_RESPONSE: u32 = 0x4552;
pub const TSG_PACKET_TYPE_CAPS_RESPONSE: u32 = 0x4350;
pub const TSG_PACKET_TYPE_MSGREQUEST_PACKET: u32 = 0x4752;
pub const TSG_PACKET_TYPE_MESSAGE_PACKET: u32 = 0x4750;
pub const TSG_CAPABILITY_TYPE_NAP: u32 = 1;
/// TSG_PACKET_HEADER ComponentId "TS Gateway Transport" (2.2.9.2.1.1).
pub const TS_GATEWAY_TRANSPORT: u16 = 0x5452;

/// NAP and messaging capabilities (2.2.5.2.19 to 2.2.5.2.23).
pub const TSG_NAP_CAPABILITY_QUAR_SOH: u32 = 0x01;
pub const TSG_NAP_CAPABILITY_IDLE_TIMEOUT: u32 = 0x02;
pub const TSG_MESSAGING_CAP_CONSENT_SIGN: u32 = 0x04;
pub const TSG_MESSAGING_CAP_SERVICE_MSG: u32 = 0x08;
pub const TSG_MESSAGING_CAP_REAUTH: u32 = 0x10;

/// Async message types and TsProxyMakeTunnelCall procIds (2.2.5.2.14 to
/// 2.2.5.2.18).
pub const TSG_ASYNC_MESSAGE_CONSENT_MESSAGE: u32 = 1;
pub const TSG_ASYNC_MESSAGE_SERVICE_MESSAGE: u32 = 2;
pub const TSG_ASYNC_MESSAGE_REAUTH: u32 = 3;
pub const TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST: u32 = 1;
pub const TSG_TUNNEL_CANCEL_ASYNC_MSG_REQUEST: u32 = 2;

/// ERROR_GRACEFUL_DISCONNECT: the final TsProxySetupReceivePipe response
/// after a close (MS-TSGU 4.1.1).
pub const ERROR_GRACEFUL_DISCONNECT: u32 = 0x4CA;

/// The protocol id of TSENDPOINTINFO.Port (2.2.9.1).
const PROTOCOL_RDP: u32 = 3;

/// A context handle on the wire: attributes and a UUID ([C706] N).
pub type Handle = [u8; 20];

/// NDR output: alignment counted from the start of the stub, unique
/// pointers as nonzero referent ids.
struct Ndr {
    b: Vec<u8>,
    next_ref: u32,
}

impl Ndr {
    fn new() -> Self {
        Self {
            b: Vec::new(),
            next_ref: 0x0002_0000,
        }
    }
    fn align(&mut self, n: usize) {
        let pad = (n - self.b.len() % n) % n;
        self.b.put_zeros(pad);
    }
    fn u16(&mut self, v: u16) {
        self.align(2);
        self.b.put_u16(v);
    }
    fn u32(&mut self, v: u32) {
        self.align(4);
        self.b.put_u32(v);
    }
    /// A non-null unique/full pointer's referent id.
    fn ptr(&mut self) {
        let r = self.next_ref;
        self.next_ref += 4;
        self.u32(r);
    }
    /// A [string] wchar_t* pointee: conformant varying, with its null.
    fn wstring(&mut self, s: &str) {
        let mut w = utf16le(s);
        w.put_u16(0);
        let n = (w.len() / 2) as u32;
        self.u32(n); // MaximumCount
        self.u32(0); // Offset
        self.u32(n); // ActualCount
        self.b.put_bytes(&w);
    }
    fn handle(&mut self, h: &Handle) {
        self.align(4);
        self.b.put_bytes(h);
    }
}

/// NDR input over a stub, with alignment from its start.
struct Rd<'a> {
    r: Reader<'a>,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { r: Reader::new(b) }
    }
    fn align(&mut self, n: usize) -> Result<()> {
        self.r.skip((n - self.r.pos() % n) % n)
    }
    fn u16(&mut self) -> Result<u16> {
        self.align(2)?;
        self.r.u16()
    }
    fn u32(&mut self) -> Result<u32> {
        self.align(4)?;
        self.r.u32()
    }
    /// A unique pointer: false when null.
    fn ptr(&mut self) -> Result<bool> {
        Ok(self.u32()? != 0)
    }
    /// The union discriminant, which must match the field it switches on.
    fn switch(&mut self, want: u32) -> Result<()> {
        let got = self.u32()?;
        if got != want {
            return proto(format!("NDR union switch {got:#x} for {want:#x}"));
        }
        Ok(())
    }
    /// A conformant varying wide string (with or without its null).
    fn wstring(&mut self) -> Result<String> {
        let max = self.u32()?;
        let offset = self.u32()?;
        let actual = self.u32()?;
        if offset != 0 || actual > max {
            return proto(format!("NDR string {offset}/{actual}/{max}"));
        }
        self.wchars(actual)
    }
    /// A conformant wchar_t array (size_is, no varying part).
    fn wchar_array(&mut self) -> Result<String> {
        let n = self.u32()?;
        self.wchars(n)
    }
    fn wchars(&mut self, n: u32) -> Result<String> {
        let raw = self.r.bytes(n as usize * 2)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
    /// A conformant byte array.
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()?;
        Ok(self.r.bytes(n as usize)?.to_vec())
    }
}

/// TSG_PACKET_VERSIONCAPS fields after its header (2.2.9.2.1.2), with the
/// TSGCaps pointee: the NAP capabilities of the first capability.
fn read_versioncaps(d: &mut Rd) -> Result<u32> {
    d.u16()?; // ComponentId
    d.u16()?; // PacketId
    let has_caps = d.ptr()?;
    let n = d.u32()?;
    d.u16()?; // majorVersion
    d.u16()?; // minorVersion
    d.u16()?; // quarantineCapabilities
    let mut caps = 0;
    if has_caps {
        let max = d.u32()?;
        if max < n || n > 32 {
            return proto(format!("TSG capability count {n} of {max}"));
        }
        for i in 0..n {
            let kind = d.u32()?;
            d.switch(kind)?;
            if kind != TSG_CAPABILITY_TYPE_NAP {
                return proto(format!("TSG capability type {kind}"));
            }
            let v = d.u32()?;
            if i == 0 {
                caps = v;
            }
        }
    }
    Ok(caps)
}

/// The fixed tail of a response: `n` bytes before the end.
fn tail(stub: &[u8], n: usize) -> Result<Reader<'_>> {
    let at = stub
        .len()
        .checked_sub(n)
        .ok_or_else(|| Error::Protocol(format!("TsProxy response of {} bytes", stub.len())))?;
    Ok(Reader::new(&stub[at..]))
}

// ---------------------------------------------------------------- requests

/// TsProxyCreateTunnel (3.2.6.1.1): a TSG_PACKET_VERSIONCAPS, version 1.1,
/// one NAP capability.
pub fn create_tunnel(capabilities: u32) -> Vec<u8> {
    let mut n = Ndr::new();
    n.u32(TSG_PACKET_TYPE_VERSIONCAPS); // packetId
    n.u32(TSG_PACKET_TYPE_VERSIONCAPS); // union switch
    n.ptr(); // packetVersionCaps
    n.u16(TS_GATEWAY_TRANSPORT);
    n.u16(TSG_PACKET_TYPE_VERSIONCAPS as u16);
    n.ptr(); // TSGCaps
    n.u32(1); // numCapabilities
    n.u16(1); // majorVersion
    n.u16(1); // minorVersion
    n.u16(0); // quarantineCapabilities
    n.u32(1); // TSGCaps: MaximumCount
    n.u32(TSG_CAPABILITY_TYPE_NAP);
    n.u32(TSG_CAPABILITY_TYPE_NAP); // union switch
    n.u32(capabilities);
    n.b
}

/// TsProxyAuthorizeTunnel (3.2.6.1.2): a TSG_PACKET_QUARREQUEST with the
/// client's name and no statement of health.
pub fn authorize_tunnel(tunnel: &Handle, machine_name: &str) -> Vec<u8> {
    let mut n = Ndr::new();
    n.handle(tunnel);
    n.u32(TSG_PACKET_TYPE_QUARREQUEST);
    n.u32(TSG_PACKET_TYPE_QUARREQUEST);
    n.ptr(); // packetQuarRequest
    n.u32(0); // flags
    n.ptr(); // machineName
    n.u32(machine_name.encode_utf16().count() as u32 + 1); // nameLength
    n.u32(0); // data: null
    n.u32(0); // dataLen
    n.wstring(machine_name);
    n.align(4);
    n.b
}

/// TsProxyMakeTunnelCall (3.2.6.1.3): ask for (procId 1) or cancel (2) the
/// administrative messages, one per batch.
pub fn make_tunnel_call(tunnel: &Handle, proc_id: u32) -> Vec<u8> {
    let mut n = Ndr::new();
    n.handle(tunnel);
    n.u32(proc_id);
    n.u32(TSG_PACKET_TYPE_MSGREQUEST_PACKET);
    n.u32(TSG_PACKET_TYPE_MSGREQUEST_PACKET);
    n.ptr(); // packetMsgRequest
    n.u32(1); // maxMessagesPerBatch
    n.b
}

/// TsProxyCreateChannel (3.2.6.1.4): one resource name, protocol RDP.
pub fn create_channel(tunnel: &Handle, host: &str, port: u16) -> Vec<u8> {
    let mut n = Ndr::new();
    n.handle(tunnel);
    n.ptr(); // resourceName
    n.u32(1); // numResourceNames
    n.u32(0); // alternateResourceNames: null
    n.u16(0); // numAlternateResourceNames
    n.u32((port as u32) << 16 | PROTOCOL_RDP); // Port
    n.u32(1); // resourceName: MaximumCount
    n.ptr(); // resourceName[0]
    n.wstring(host);
    n.align(4);
    n.b
}

/// TsProxyCloseChannel / TsProxyCloseTunnel (3.2.6.3): the context handle.
pub fn close(context: &Handle) -> Vec<u8> {
    context.to_vec()
}

/// TsProxySetupReceivePipe (3.6.5.3): the channel's context handle, not NDR.
pub fn setup_receive_pipe(channel: &Handle) -> Vec<u8> {
    channel.to_vec()
}

/// The most RDP bytes one TsProxySendToServer stub carries here; the
/// interface allows 32767 (max_is in the IDL).
pub const SEND_MAX: usize = 32_000;

/// TsProxySendToServer (3.6.5.1, 2.2.9.3): the channel handle, then the
/// sizes in network byte order and one buffer.
pub fn send_to_server(channel: &Handle, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + data.len());
    b.put_bytes(channel);
    b.extend_from_slice(&(data.len() as u32 + 4).to_be_bytes()); // totalDataBytes
    b.extend_from_slice(&1u32.to_be_bytes()); // numBuffers
    b.extend_from_slice(&(data.len() as u32).to_be_bytes()); // buffer1Length
    b.put_bytes(data);
    b
}

// --------------------------------------------------------------- responses

/// What the gateway answered to TsProxyCreateTunnel.
#[derive(Debug, PartialEq, Eq)]
pub struct TunnelCreated {
    pub hresult: u32,
    pub tunnel: Handle,
    pub tunnel_id: u32,
    /// Negotiated capabilities (TSG_NAP_CAPABILITY_*, TSG_MESSAGING_CAP_*).
    pub capabilities: u32,
    /// A consent message sent along (TSG_PACKET_CAPS_RESPONSE).
    pub consent: Option<String>,
}

/// TsProxyCreateTunnel out parameters: the response packet
/// (TSG_PACKET_QUARENC_RESPONSE or TSG_PACKET_CAPS_RESPONSE), tunnel
/// context, tunnel id, HRESULT.
pub fn parse_create_tunnel(stub: &[u8]) -> Result<TunnelCreated> {
    let mut t = tail(stub, 28)?;
    let tunnel: Handle = t.array()?;
    let tunnel_id = t.u32()?;
    let hresult = t.u32()?;
    let mut out = TunnelCreated {
        hresult,
        tunnel,
        tunnel_id,
        capabilities: 0,
        consent: None,
    };
    if hresult != 0 {
        return Ok(out);
    }
    let mut d = Rd::new(&stub[..stub.len() - 28]);
    if !d.ptr()? {
        return proto("TsProxyCreateTunnel returned no packet");
    }
    let id = d.u32()?;
    d.switch(id)?;
    if !d.ptr()? {
        return proto("TsProxyCreateTunnel returned an empty packet");
    }
    let caps_response = match id {
        TSG_PACKET_TYPE_QUARENC_RESPONSE => false,
        TSG_PACKET_TYPE_CAPS_RESPONSE => true,
        _ => return proto(format!("TsProxyCreateTunnel packet type {id:#x}")),
    };
    // TSG_PACKET_QUARENC_RESPONSE (2.2.9.2.1.6).
    d.u32()?; // flags
    d.u32()?; // certChainLen
    let has_cert = d.ptr()?;
    d.align(4)?;
    d.r.skip(16)?; // nonce
    let has_caps = d.ptr()?;
    // TSG_PACKET_MSG_RESPONSE inline in a CAPS_RESPONSE (2.2.9.2.1.7).
    let mut message = None;
    if caps_response {
        d.u32()?; // msgID
        let msg_type = d.u32()?;
        let present = d.u32()? != 0;
        d.switch(msg_type)?;
        let has_msg = d.ptr()?;
        message = Some((msg_type, present && has_msg));
    }
    if has_cert {
        d.wstring()?; // certChainData
    }
    if has_caps {
        out.capabilities = read_versioncaps(&mut d)?;
    }
    if let Some((msg_type, true)) = message {
        out.consent = read_message(&mut d, msg_type)?;
    }
    Ok(out)
}

/// The pointee of TSG_PACKET_TYPE_MESSAGE_UNION (2.2.9.2.1.9.1): the text
/// of a consent or service message; None for a reauthentication request.
fn read_message(d: &mut Rd, msg_type: u32) -> Result<Option<String>> {
    match msg_type {
        TSG_ASYNC_MESSAGE_CONSENT_MESSAGE | TSG_ASYNC_MESSAGE_SERVICE_MESSAGE => {
            d.u32()?; // isDisplayMandatory
            d.u32()?; // isConsentMandatory
            d.u32()?; // msgBytes
            if !d.ptr()? {
                return Ok(Some(String::new()));
            }
            d.wchar_array().map(Some)
        }
        TSG_ASYNC_MESSAGE_REAUTH => Ok(None),
        t => proto(format!("TSG message type {t}")),
    }
}

/// TSG_REDIRECTION_FLAGS (2.2.9.2.1.5.2), as the gateway set them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Redirection {
    pub enable_all: bool,
    pub disable_all: bool,
    pub drive_disabled: bool,
    pub printer_disabled: bool,
    pub port_disabled: bool,
    pub clipboard_disabled: bool,
    pub pnp_disabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Authorized {
    pub hresult: u32,
    pub redirection: Redirection,
    /// TSG_PACKET_RESPONSE.responseData (2.2.9.2.1.5.1).
    pub response_data: Vec<u8>,
}

/// TsProxyAuthorizeTunnel out parameters: a TSG_PACKET_RESPONSE, HRESULT.
pub fn parse_authorize_tunnel(stub: &[u8]) -> Result<Authorized> {
    let hresult = tail(stub, 4)?.u32()?;
    let mut out = Authorized {
        hresult,
        redirection: Redirection::default(),
        response_data: Vec::new(),
    };
    if hresult != 0 {
        return Ok(out);
    }
    let mut d = Rd::new(&stub[..stub.len() - 4]);
    if !d.ptr()? {
        return proto("TsProxyAuthorizeTunnel returned no packet");
    }
    let id = d.u32()?;
    d.switch(id)?;
    if id != TSG_PACKET_TYPE_RESPONSE {
        return proto(format!("TsProxyAuthorizeTunnel packet type {id:#x}"));
    }
    if !d.ptr()? {
        return proto("TsProxyAuthorizeTunnel returned an empty packet");
    }
    d.u32()?; // flags
    d.u32()?; // reserved
    let has_data = d.ptr()?;
    d.u32()?; // responseDataLen
    let mut f = [false; 8];
    for v in &mut f {
        *v = d.u32()? != 0;
    }
    out.redirection = Redirection {
        enable_all: f[0],
        disable_all: f[1],
        drive_disabled: f[2],
        printer_disabled: f[3],
        port_disabled: f[4],
        clipboard_disabled: f[6],
        pnp_disabled: f[7],
    };
    if has_data {
        out.response_data = d.bytes()?;
    }
    Ok(out)
}

/// TsProxyMakeTunnelCall out parameters: a TSG_PACKET_MSG_RESPONSE (or
/// none after a cancel), HRESULT. Returns the HRESULT and the message type
/// with its text.
pub fn parse_make_tunnel_call(stub: &[u8]) -> Result<(u32, Option<(u32, String)>)> {
    let hresult = tail(stub, 4)?.u32()?;
    if hresult != 0 {
        return Ok((hresult, None));
    }
    let mut d = Rd::new(&stub[..stub.len() - 4]);
    if !d.ptr()? {
        return Ok((hresult, None));
    }
    let id = d.u32()?;
    d.switch(id)?;
    if id != TSG_PACKET_TYPE_MESSAGE_PACKET || !d.ptr()? {
        return Ok((hresult, None));
    }
    d.u32()?; // msgID
    let msg_type = d.u32()?;
    let present = d.u32()? != 0;
    d.switch(msg_type)?;
    let has_msg = d.ptr()?;
    if !(present && has_msg) {
        return Ok((hresult, None));
    }
    let text = read_message(&mut d, msg_type)?.unwrap_or_default();
    Ok((hresult, Some((msg_type, text))))
}

/// TsProxyCreateChannel out parameters: channel context, id, HRESULT.
pub fn parse_create_channel(stub: &[u8]) -> Result<(u32, Handle, u32)> {
    let mut t = tail(stub, 28)?;
    let channel: Handle = t.array()?;
    let id = t.u32()?;
    Ok((t.u32()?, channel, id))
}

/// The return value of TsProxyCloseChannel / CloseTunnel (after the
/// cleared handle), TsProxySendToServer and the final
/// TsProxySetupReceivePipe response: the last four bytes.
pub fn parse_return(stub: &[u8]) -> Result<u32> {
    tail(stub, 4)?.u32()
}

/// The gateway's side of the calls, for the loopback tests: request
/// parsers and response builders.
#[cfg(test)]
pub(crate) mod server {
    use super::*;

    /// TsProxyCreateTunnel: the capabilities the client offered.
    pub fn read_create_tunnel(stub: &[u8]) -> Result<u32> {
        let mut d = Rd::new(stub);
        d.switch_pair(TSG_PACKET_TYPE_VERSIONCAPS)?;
        if !d.ptr()? {
            return proto("no version caps");
        }
        read_versioncaps(&mut d)
    }

    /// TsProxyAuthorizeTunnel: the tunnel handle and the machine name.
    pub fn read_authorize_tunnel(stub: &[u8]) -> Result<(Handle, String)> {
        let mut d = Rd::new(stub);
        let h: Handle = d.r.array()?;
        d.switch_pair(TSG_PACKET_TYPE_QUARREQUEST)?;
        d.ptr()?;
        d.u32()?; // flags
        let has_name = d.ptr()?;
        let len = d.u32()?;
        let has_data = d.ptr()?;
        d.u32()?;
        let name = if has_name {
            d.wstring()?
        } else {
            String::new()
        };
        if has_data || name.encode_utf16().count() as u32 + 1 != len {
            return proto("quarrequest");
        }
        Ok((h, name))
    }

    /// TsProxyCreateChannel: tunnel handle, host, port.
    pub fn read_create_channel(stub: &[u8]) -> Result<(Handle, String, u16)> {
        let mut d = Rd::new(stub);
        let h: Handle = d.r.array()?;
        let has_names = d.ptr()?;
        let n = d.u32()?;
        let has_alt = d.ptr()?;
        d.u16()?;
        let port = d.u32()?;
        if !has_names || n != 1 || has_alt || port & 0xFFFF != PROTOCOL_RDP {
            return proto("endpoint info");
        }
        if d.u32()? != 1 || !d.ptr()? {
            return proto("resource names");
        }
        Ok((h, d.wstring()?, (port >> 16) as u16))
    }

    /// TsProxySendToServer: the channel handle and the data.
    pub fn read_send_to_server(stub: &[u8]) -> Result<(Handle, Vec<u8>)> {
        let mut r = Reader::new(stub);
        let h: Handle = r.array()?;
        let be = |r: &mut Reader| r.array::<4>().map(u32::from_be_bytes);
        let total = be(&mut r)?;
        let count = be(&mut r)?;
        if count == 0 || count > 3 {
            return proto("buffer count");
        }
        let lens: Vec<u32> = (0..count).map(|_| be(&mut r)).collect::<Result<_>>()?;
        if total != lens.iter().map(|l| l + 4).sum::<u32>() {
            return proto("totalDataBytes");
        }
        let mut data = Vec::new();
        for l in lens {
            data.extend_from_slice(r.bytes(l as usize)?);
        }
        Ok((h, data))
    }

    fn versioncaps(n: &mut Ndr, caps: u32) {
        n.u16(TS_GATEWAY_TRANSPORT);
        n.u16(TSG_PACKET_TYPE_VERSIONCAPS as u16);
        n.ptr();
        n.u32(1);
        n.u16(1);
        n.u16(1);
        n.u16(0);
        n.u32(1);
        n.u32(TSG_CAPABILITY_TYPE_NAP);
        n.u32(TSG_CAPABILITY_TYPE_NAP);
        n.u32(caps);
    }

    fn string_message(n: &mut Ndr, text: &str) {
        let w: Vec<u16> = text.encode_utf16().chain([0]).collect();
        n.u32(1); // isDisplayMandatory
        n.u32(0); // isConsentMandatory
        n.u32(w.len() as u32); // msgBytes
        n.ptr();
        n.u32(w.len() as u32);
        for u in w {
            n.b.put_u16(u);
        }
    }

    /// A TsProxyCreateTunnel response: QUARENC_RESPONSE, or CAPS_RESPONSE
    /// when a consent message is given.
    pub fn create_tunnel_response(
        hresult: u32,
        tunnel: &Handle,
        id: u32,
        caps: u32,
        cert: Option<&str>,
        consent: Option<&str>,
    ) -> Vec<u8> {
        let mut n = Ndr::new();
        if hresult != 0 {
            n.u32(0);
        } else {
            n.ptr();
            let kind = if consent.is_some() {
                TSG_PACKET_TYPE_CAPS_RESPONSE
            } else {
                TSG_PACKET_TYPE_QUARENC_RESPONSE
            };
            n.u32(kind);
            n.u32(kind);
            n.ptr();
            n.u32(0); // flags
            n.u32(cert.map_or(0, |c| c.encode_utf16().count() as u32 + 1));
            if cert.is_some() {
                n.ptr();
            } else {
                n.u32(0);
            }
            n.b.put_bytes(&[0xAB; 16]); // nonce
            n.ptr(); // versionCaps
            if consent.is_some() {
                n.u32(0); // msgID
                n.u32(TSG_ASYNC_MESSAGE_CONSENT_MESSAGE);
                n.u32(1);
                n.u32(TSG_ASYNC_MESSAGE_CONSENT_MESSAGE);
                n.ptr();
            }
            if let Some(c) = cert {
                n.wstring(c);
            }
            versioncaps(&mut n, caps);
            if let Some(c) = consent {
                string_message(&mut n, c);
            }
        }
        n.handle(tunnel);
        n.u32(id);
        n.u32(hresult);
        n.b
    }

    /// A TsProxyAuthorizeTunnel response with an idle timeout in minutes.
    pub fn authorize_response(hresult: u32, idle_minutes: Option<u32>) -> Vec<u8> {
        let mut n = Ndr::new();
        if hresult != 0 {
            n.u32(0);
        } else {
            n.ptr();
            n.u32(TSG_PACKET_TYPE_RESPONSE);
            n.u32(TSG_PACKET_TYPE_RESPONSE);
            n.ptr();
            n.u32(TSG_PACKET_TYPE_QUARREQUEST); // flags
            n.u32(0);
            let data = idle_minutes.map(u32::to_le_bytes);
            if data.is_some() {
                n.ptr();
            } else {
                n.u32(0);
            }
            n.u32(data.map_or(0, |d| d.len() as u32));
            for v in [0, 0, 1, 0, 0, 0, 1, 0] {
                n.u32(v); // drive and clipboard redirection disabled
            }
            if let Some(d) = data {
                n.u32(4);
                n.b.put_bytes(&d);
            }
        }
        n.u32(hresult);
        n.b
    }

    /// A TsProxyMakeTunnelCall response carrying a service message.
    pub fn message_response(text: &str) -> Vec<u8> {
        let mut n = Ndr::new();
        n.ptr();
        n.u32(TSG_PACKET_TYPE_MESSAGE_PACKET);
        n.u32(TSG_PACKET_TYPE_MESSAGE_PACKET);
        n.ptr();
        n.u32(1); // msgID
        n.u32(TSG_ASYNC_MESSAGE_SERVICE_MESSAGE);
        n.u32(1);
        n.u32(TSG_ASYNC_MESSAGE_SERVICE_MESSAGE);
        n.ptr();
        string_message(&mut n, text);
        n.u32(0);
        n.b
    }

    pub fn create_channel_response(hresult: u32, channel: &Handle, id: u32) -> Vec<u8> {
        let mut n = Ndr::new();
        n.handle(channel);
        n.u32(id);
        n.u32(hresult);
        n.b
    }

    impl Rd<'_> {
        fn switch_pair(&mut self, want: u32) -> Result<()> {
            let id = self.u32()?;
            if id != want {
                return proto(format!("packet id {id:#x}"));
            }
            self.switch(want)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::server::*;
    use super::*;

    const TUNNEL: Handle = [
        0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0x01,
    ];

    /// MS-TSGU 4.1.1 TsProxySendToServer example: four bytes of data.
    #[test]
    fn send_to_server_matches_the_spec_example() {
        let channel: Handle = [
            0x00, 0x00, 0x00, 0x00, 0x36, 0x41, 0x18, 0x41, 0xdd, 0x2d, 0x84, 0x43, 0x83, 0x63,
            0x82, 0xcc, 0xb6, 0xea, 0xf3, 0xf9,
        ];
        let stub = send_to_server(&channel, &[0x04, 0x00, 0x00, 0x03]);
        let mut want = channel.to_vec();
        want.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 4, 4, 0, 0, 3]);
        assert_eq!(stub, want);
        assert_eq!(
            read_send_to_server(&stub).unwrap(),
            (channel, vec![4, 0, 0, 3])
        );
    }

    /// MS-TSGU 4.1.1 TsProxySetupReceivePipe example: the stub is the
    /// channel context handle as is.
    #[test]
    fn setup_receive_pipe_matches_the_spec_example() {
        let pipe: Handle = [
            0x00, 0x00, 0x00, 0x00, 0xEC, 0xEC, 0x2E, 0x7D, 0xDB, 0xE2, 0xE3, 0x4A, 0xAE, 0x61,
            0xA3, 0x51, 0xDC, 0x53, 0x55, 0x61,
        ];
        assert_eq!(setup_receive_pipe(&pipe), pipe.to_vec());
        assert_eq!(close(&pipe), pipe.to_vec());
    }

    /// The TsProxyCreateTunnel request of MS-TSGU 4.1.1 (version 1.1, one
    /// NAP capability) in NDR: 52 bytes, field by field.
    #[test]
    fn create_tunnel_request_layout() {
        let b = create_tunnel(0x0A);
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            0x43, 0x56, 0, 0,  0x43, 0x56, 0, 0,  0, 0, 2, 0,   // packetId, switch, pointer
            0x52, 0x54, 0x43, 0x56,                            // TSG_PACKET_HEADER
            4, 0, 2, 0,  1, 0, 0, 0,                           // TSGCaps pointer, numCapabilities
            1, 0, 1, 0, 0, 0,  0, 0,                           // 1.1, quarantine, pad
            1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  0x0A, 0, 0, 0, // count, type, switch, caps
        ];
        assert_eq!(b, want);
        assert_eq!(read_create_tunnel(&b).unwrap(), 0x0A);
    }

    #[test]
    fn authorize_and_channel_requests_round_trip() {
        let b = authorize_tunnel(&TUNNEL, "mymachine");
        // nameLength 10 as in the 4.1.1 example.
        assert_eq!(&b[40..44], &[10, 0, 0, 0]);
        assert_eq!(b.len() % 4, 0);
        assert_eq!(
            read_authorize_tunnel(&b).unwrap(),
            (TUNNEL, "mymachine".to_string())
        );
        let b = create_channel(&TUNNEL, "myTsMachine", 3389);
        // Port 222101507 as in the 4.1.1 example.
        assert_eq!(&b[36..40], &222_101_507u32.to_le_bytes());
        assert_eq!(
            read_create_channel(&b).unwrap(),
            (TUNNEL, "myTsMachine".to_string(), 3389)
        );
        let b = make_tunnel_call(&TUNNEL, TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST);
        assert_eq!(&b[20..24], &[1, 0, 0, 0]);
        assert_eq!(&b[24..28], &[0x52, 0x47, 0, 0]);
        assert_eq!(b.len(), 40);
    }

    #[test]
    fn create_tunnel_responses_round_trip() {
        let b = create_tunnel_response(0, &TUNNEL, 7, 0x0A, Some("MIIB..."), None);
        assert_eq!(
            parse_create_tunnel(&b).unwrap(),
            TunnelCreated {
                hresult: 0,
                tunnel: TUNNEL,
                tunnel_id: 7,
                capabilities: 0x0A,
                consent: None
            }
        );
        let b = create_tunnel_response(0, &TUNNEL, 8, 0x1E, None, Some("Accept"));
        let t = parse_create_tunnel(&b).unwrap();
        assert_eq!((t.tunnel_id, t.capabilities), (8, 0x1E));
        assert_eq!(t.consent.as_deref(), Some("Accept"));
        let b = create_tunnel_response(0x8007_59DB, &[0; 20], 0, 0, None, None);
        assert_eq!(parse_create_tunnel(&b).unwrap().hresult, 0x8007_59DB);
    }

    #[test]
    fn authorize_and_message_responses_round_trip() {
        let a = parse_authorize_tunnel(&authorize_response(0, Some(30))).unwrap();
        assert_eq!(a.hresult, 0);
        assert_eq!(a.response_data, 30u32.to_le_bytes());
        assert!(a.redirection.drive_disabled && a.redirection.clipboard_disabled);
        assert!(!a.redirection.printer_disabled && !a.redirection.disable_all);
        let a = parse_authorize_tunnel(&authorize_response(0, None)).unwrap();
        assert!(a.response_data.is_empty());
        let a = parse_authorize_tunnel(&authorize_response(0x8007_59ED, None)).unwrap();
        assert_eq!(a.hresult, 0x8007_59ED);

        let (hr, msg) = parse_make_tunnel_call(&message_response("Test")).unwrap();
        assert_eq!(hr, 0);
        assert_eq!(
            msg,
            Some((TSG_ASYNC_MESSAGE_SERVICE_MESSAGE, "Test".into()))
        );

        let b = create_channel_response(0, &TUNNEL, 1);
        assert_eq!(parse_create_channel(&b).unwrap(), (0, TUNNEL, 1));
        assert_eq!(
            parse_return(&[0xCA, 4, 0, 0]).unwrap(),
            ERROR_GRACEFUL_DISCONNECT
        );
    }

    #[test]
    fn short_or_broken_responses_are_errors() {
        assert!(parse_create_tunnel(&[0; 27]).is_err());
        assert!(parse_create_channel(&[0; 3]).is_err());
        assert!(parse_return(&[]).is_err());
        // A packet cut in the middle.
        let b = create_tunnel_response(0, &TUNNEL, 7, 0x0A, Some("cert"), None);
        let mut cut = b[..20].to_vec();
        cut.extend_from_slice(&b[b.len() - 28..]);
        assert!(parse_create_tunnel(&cut).is_err());
        // A wrong union switch.
        let mut b = create_tunnel_response(0, &TUNNEL, 7, 0x0A, None, None);
        b[8] ^= 1;
        assert!(parse_create_tunnel(&b).is_err());
        // A string longer than its maximum.
        let mut b = create_tunnel_response(0, &TUNNEL, 7, 0x0A, Some("cert"), None);
        b[56] = 99; // certChainData ActualCount
        assert!(parse_create_tunnel(&b).is_err());
    }
}
