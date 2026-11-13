//! Core PDUs (MS-RDPEFS 2.2.1, 2.2.2, 2.2.3.2) and the client state machine
//! (MS-RDPEFS 3.2.5.1).

use super::fscc::STATUS_NOT_SUPPORTED;
use super::{Device, IoCompletion, IoRequest, Op, RdpdrHandle};
use crate::channel::{
    CHANNEL_OPTION_ENCRYPT_RDP, CHANNEL_OPTION_INITIALIZED, ChannelOut, StaticChannel,
};
use crate::cursor::{Put, Reader, utf16le_z};
use crate::error::Result;
use crate::trace;

/// RDPDR_HEADER Component values (MS-RDPEFS 2.2.1.1).
pub const RDPDR_CTYP_CORE: u16 = 0x4472;
pub const RDPDR_CTYP_PRN: u16 = 0x5052;

/// RDPDR_HEADER PacketId values (MS-RDPEFS 2.2.1.1).
pub const PAKID_CORE_SERVER_ANNOUNCE: u16 = 0x496E;
pub const PAKID_CORE_CLIENTID_CONFIRM: u16 = 0x4343;
pub const PAKID_CORE_CLIENT_NAME: u16 = 0x434E;
pub const PAKID_CORE_DEVICELIST_ANNOUNCE: u16 = 0x4441;
pub const PAKID_CORE_DEVICE_REPLY: u16 = 0x6472;
pub const PAKID_CORE_DEVICE_IOREQUEST: u16 = 0x4952;
pub const PAKID_CORE_DEVICE_IOCOMPLETION: u16 = 0x4943;
pub const PAKID_CORE_SERVER_CAPABILITY: u16 = 0x5350;
pub const PAKID_CORE_CLIENT_CAPABILITY: u16 = 0x4350;
pub const PAKID_CORE_DEVICELIST_REMOVE: u16 = 0x444D;
pub const PAKID_CORE_USER_LOGGEDON: u16 = 0x554C;

/// Highest protocol minor version this client speaks (MS-RDPEFS 2.2.2.3).
pub const CLIENT_VERSION_MINOR: u16 = 0x000D;

/// CapabilityType values (MS-RDPEFS 2.2.1.2).
const CAP_GENERAL_TYPE: u16 = 1;
const CAP_PRINTER_TYPE: u16 = 2;
const CAP_PORT_TYPE: u16 = 3;
const CAP_DRIVE_TYPE: u16 = 4;
const CAP_SMARTCARD_TYPE: u16 = 5;

/// ioCode1 bits (MS-RDPEFS 2.2.2.7.1): the major functions the client handles.
pub const IO_CODE1: u32 = 0x0001 // RDPDR_IRP_MJ_CREATE
    | 0x0004 // CLOSE
    | 0x0008 // READ
    | 0x0010 // WRITE
    | 0x0080 // DEVICE_CONTROL
    | 0x0100 // QUERY_VOLUME_INFORMATION
    | 0x0400 // QUERY_INFORMATION
    | 0x0800 // SET_INFORMATION
    | 0x1000 // DIRECTORY_CONTROL
    | 0x2000; // LOCK_CONTROL

/// extendedPDU: RDPDR_DEVICE_REMOVE_PDUS | RDPDR_CLIENT_DISPLAY_NAME_PDU |
/// RDPDR_USER_LOGGEDON_PDU (MS-RDPEFS 2.2.2.7.1).
pub const EXTENDED_PDU: u32 = 0x1 | 0x2 | 0x4;

fn header(packet_id: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.put_u16(RDPDR_CTYP_CORE);
    v.put_u16(packet_id);
    v
}

/// Client Announce Reply (MS-RDPEFS 2.2.2.3).
pub fn client_announce_reply(minor: u16, client_id: u32) -> Vec<u8> {
    let mut v = header(PAKID_CORE_CLIENTID_CONFIRM);
    v.put_u16(1);
    v.put_u16(minor);
    v.put_u32(client_id);
    v
}

/// Client Name Request, Unicode (MS-RDPEFS 2.2.2.4).
pub fn client_name_request(name: &str) -> Vec<u8> {
    let name = utf16le_z(name);
    let mut v = header(PAKID_CORE_CLIENT_NAME);
    v.put_u32(1); // UnicodeFlag
    v.put_u32(0); // CodePage
    v.put_u32(name.len() as u32);
    v.put_bytes(&name);
    v
}

/// Client Core Capability Response (MS-RDPEFS 2.2.2.8): general (2.2.2.7.1),
/// printer, port, drive and smart card capability sets (2.2.2.7.2-5).
pub fn client_capability_response(minor: u16) -> Vec<u8> {
    let mut v = header(PAKID_CORE_CLIENT_CAPABILITY);
    v.put_u16(5); // numCapabilities
    v.put_u16(0); // Padding
    // General capability, GENERAL_CAPABILITY_VERSION_02.
    v.put_u16(CAP_GENERAL_TYPE);
    v.put_u16(44);
    v.put_u32(2);
    v.put_u32(0); // osType (ignored)
    v.put_u32(0); // osVersion (ignored)
    v.put_u16(1); // protocolMajorVersion
    v.put_u16(minor);
    v.put_u32(IO_CODE1);
    v.put_u32(0); // ioCode2
    v.put_u32(EXTENDED_PDU);
    v.put_u32(0); // extraFlags1 (no ENABLE_ASYNCIO)
    v.put_u32(0); // extraFlags2
    v.put_u32(0); // SpecialTypeDeviceCap
    for (ty, version) in [
        (CAP_PRINTER_TYPE, 1),
        (CAP_PORT_TYPE, 1),
        (CAP_DRIVE_TYPE, 2), // DRIVE_CAPABILITY_VERSION_02
        (CAP_SMARTCARD_TYPE, 1),
    ] {
        v.put_u16(ty);
        v.put_u16(8);
        v.put_u32(version);
    }
    v
}

/// PreferredDosName: 7 ASCII characters at most, null padded to 8
/// (MS-RDPEFS 2.2.1.3).
fn dos_name(name: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (o, c) in out.iter_mut().take(7).zip(name.chars()) {
        *o = if c.is_ascii_graphic() && c != ':' {
            c as u8
        } else {
            b'_'
        };
    }
    out
}

/// Client Device List Announce Request (MS-RDPEFS 2.2.2.9) with one
/// DEVICE_ANNOUNCE (2.2.1.3) per device.
pub fn device_list_announce(devs: &[(u32, &dyn Device)]) -> Vec<u8> {
    let mut v = header(PAKID_CORE_DEVICELIST_ANNOUNCE);
    v.put_u32(devs.len() as u32);
    for (id, dev) in devs {
        let data = dev.device_data();
        v.put_u32(dev.device_type());
        v.put_u32(*id);
        v.put_bytes(&dos_name(&dev.preferred_dos_name()));
        v.put_u32(data.len() as u32);
        v.put_bytes(&data);
    }
    v
}

/// Client Drive Device List Remove (MS-RDPEFS 2.2.3.2).
pub fn device_list_remove(ids: &[u32]) -> Vec<u8> {
    let mut v = header(PAKID_CORE_DEVICELIST_REMOVE);
    v.put_u32(ids.len() as u32);
    for id in ids {
        v.put_u32(*id);
    }
    v
}

/// Device I/O Response (MS-RDPEFS 2.2.1.5).
pub fn io_response(device_id: u32, c: &IoCompletion) -> Vec<u8> {
    let mut v = header(PAKID_CORE_DEVICE_IOCOMPLETION);
    v.put_u32(device_id);
    v.put_u32(c.completion_id);
    v.put_u32(c.status);
    v.put_bytes(&c.data);
    v
}

/// Device I/O Request header (MS-RDPEFS 2.2.1.4), after the RDPDR_HEADER.
fn parse_io_request<'a>(r: &mut Reader<'a>) -> Result<IoRequest<'a>> {
    Ok(IoRequest {
        device_id: r.u32()?,
        file_id: r.u32()?,
        completion_id: r.u32()?,
        major: r.u32()?,
        minor: r.u32()?,
        data: r.rest(),
    })
}

struct Slot {
    id: u32,
    dev: Box<dyn Device>,
    announced: bool,
}

/// The `rdpdr` channel handler; see the [module docs](super).
pub struct Rdpdr {
    computer_name: String,
    handle: RdpdrHandle,
    devices: Vec<Slot>,
    client_id: u32,
    minor: u16,
    /// Server Client ID Confirm seen: early devices (smart cards) may go out.
    confirmed: bool,
    logged_on: bool,
}

impl Rdpdr {
    pub(super) fn new(computer_name: &str, handle: RdpdrHandle) -> Self {
        Self {
            computer_name: computer_name.to_string(),
            handle,
            devices: Vec::new(),
            client_id: 0,
            minor: CLIENT_VERSION_MINOR,
            confirmed: false,
            logged_on: false,
        }
    }

    /// ClientId the server assigned (MS-RDPEFS 2.2.2.6).
    pub fn client_id(&self) -> u32 {
        self.client_id
    }

    /// True once the server may receive this device's announce.
    fn may_announce(&self, dev: &dyn Device) -> bool {
        // Servers before 0x0006 never send User Logged On (MS-RDPEFS 3.2.5.1.6).
        self.logged_on || (self.confirmed && (dev.announce_before_logon() || self.minor < 0x0006))
    }

    /// Announces every device that may be announced and was not yet.
    /// `always` sends the list even when it is empty: the answer to Server
    /// User Logged On (MS-RDPEFS 3.2.5.1.7). Windows completes its device
    /// redirection setup on it, and the user-mode channels (`rdpsnd`,
    /// `cliprdr`) are only started after that, so it must not be skipped
    /// when nothing is shared (`mstsc` sends it with zero devices too).
    fn announce_ready(&mut self, out: &mut ChannelOut, always: bool) {
        let ready: Vec<usize> = (0..self.devices.len())
            .filter(|&i| {
                let s = &self.devices[i];
                !s.announced && self.may_announce(s.dev.as_ref())
            })
            .collect();
        if ready.is_empty() && !always {
            return;
        }
        let list: Vec<(u32, &dyn Device)> = ready
            .iter()
            .map(|&i| (self.devices[i].id, self.devices[i].dev.as_ref()))
            .collect();
        trace!("rdpdr: announce {} device(s)", list.len());
        out.send(device_list_announce(&list));
        for i in ready {
            self.devices[i].announced = true;
        }
    }

    fn apply_ops(&mut self, out: &mut ChannelOut) {
        let Some(ops) = self.handle.take_ops() else {
            return;
        };
        for op in ops {
            match op {
                Op::Add(id, dev) => self.devices.push(Slot {
                    id,
                    dev,
                    announced: false,
                }),
                Op::Remove(id) => {
                    let Some(i) = self.devices.iter().position(|s| s.id == id) else {
                        continue;
                    };
                    let mut slot = self.devices.remove(i);
                    slot.dev.closed();
                    if slot.announced {
                        trace!("rdpdr: remove device {id}");
                        out.send(device_list_remove(&[id]));
                    }
                }
            }
        }
        self.announce_ready(out, false);
    }

    fn device_io(&mut self, req: &IoRequest<'_>, out: &mut ChannelOut) {
        let completion = match self
            .devices
            .iter_mut()
            .find(|s| s.id == req.device_id && s.announced)
        {
            Some(slot) => slot.dev.io(req),
            None => {
                trace!("rdpdr: I/O for unknown device {}", req.device_id);
                Some(IoCompletion::new(req, STATUS_NOT_SUPPORTED, Vec::new()))
            }
        };
        if let Some(c) = completion {
            out.send(io_response(req.device_id, &c));
        }
    }

    /// The server restarted the redirection session: every handle is gone.
    fn reset(&mut self) {
        for s in &mut self.devices {
            if s.announced {
                s.dev.closed();
            }
            s.announced = false;
        }
        self.confirmed = false;
        self.logged_on = false;
    }
}

impl StaticChannel for Rdpdr {
    fn name(&self) -> &str {
        "rdpdr"
    }

    fn options(&self) -> u32 {
        CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP
    }

    fn process(&mut self, msg: &[u8], out: &mut ChannelOut) -> Result<()> {
        let mut r = Reader::new(msg);
        let component = r.u16()?;
        let packet = r.u16()?;
        if component == RDPDR_CTYP_PRN {
            // Printer cache data and XPS mode (MS-RDPEPC 2.2.2.3-2.2.2.9).
            trace!("rdpdr: printer packet {packet:#x} ignored");
            return Ok(());
        }
        if component != RDPDR_CTYP_CORE {
            trace!("rdpdr: component {component:#x} packet {packet:#x} ignored");
            return Ok(());
        }
        match packet {
            PAKID_CORE_SERVER_ANNOUNCE => {
                // Server Announce Request (2.2.2.2).
                let _major = r.u16()?;
                let minor = r.u16()?;
                let client_id = r.u32()?;
                self.reset();
                self.minor = minor.min(CLIENT_VERSION_MINOR);
                self.client_id = client_id;
                trace!("rdpdr: server announce version 1.{minor:#x}, client id {client_id}");
                out.send(client_announce_reply(self.minor, client_id));
                out.send(client_name_request(&self.computer_name));
            }
            PAKID_CORE_SERVER_CAPABILITY => {
                // Server Core Capability Request (2.2.2.7); every set we know
                // is accepted, so its content does not change the reply.
                let n = r.u16()?;
                trace!("rdpdr: server capabilities ({n} sets)");
                out.send(client_capability_response(self.minor));
            }
            PAKID_CORE_CLIENTID_CONFIRM => {
                // Server Client ID Confirm (2.2.2.6).
                let _major = r.u16()?;
                let _minor = r.u16()?;
                self.client_id = r.u32()?;
                self.confirmed = true;
                self.announce_ready(out, false);
            }
            PAKID_CORE_USER_LOGGEDON => {
                // Server User Logged On (2.2.2.5).
                self.confirmed = true;
                self.logged_on = true;
                self.announce_ready(out, true);
            }
            PAKID_CORE_DEVICE_REPLY => {
                // Server Device Announce Response (2.2.2.1).
                let id = r.u32()?;
                let status = r.u32()?;
                trace!("rdpdr: device {id} announce result {status:#010x}");
            }
            PAKID_CORE_DEVICE_IOREQUEST => {
                let req = parse_io_request(&mut r)?;
                self.device_io(&req, out);
            }
            other => trace!("rdpdr: packet {other:#x} ignored"),
        }
        Ok(())
    }

    fn tick(&mut self, out: &mut ChannelOut) -> Result<()> {
        self.apply_ops(out);
        for s in &mut self.devices {
            if !s.announced {
                continue;
            }
            for c in s.dev.tick() {
                out.send(io_response(s.id, &c));
            }
        }
        Ok(())
    }
}
