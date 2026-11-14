//! Touch and pen input, client side (MS-RDPEI) on the
//! `Microsoft::Windows::RDS::Input` dynamic virtual channel (MS-RDPEI 2.1).
//!
//! Flow (MS-RDPEI 3.3.5):
//! - the server opens the channel and sends RDPINPUT_SC_READY_PDU with its
//!   protocol version; the client answers RDPINPUT_CS_READY_PDU with the
//!   highest version both sides know (at most 3.0.0) and starts remoting;
//! - the UI hands touch and pen frames to [`TouchHandle`]; every channel tick
//!   sends the queued frames as one RDPINPUT_TOUCH_EVENT_PDU and one
//!   RDPINPUT_PEN_EVENT_PDU, with frameOffset and encodeTime timing;
//! - RDPINPUT_SUSPEND_INPUT_PDU / RDPINPUT_RESUME_INPUT_PDU switch the
//!   Input Transmission Suspended state (3.3.1.1); while suspended (or before
//!   SC_READY) [`TouchHandle::is_ready`] is false and frames are dropped, so
//!   the UI lets the local system turn touch into mouse input instead;
//! - pen frames need a server at version 2.0.0 or later (Pen Input Allowed,
//!   3.3.1.2).
//!
//! Server messages with an unexpected eventId or a pduLength that does not
//! match the data are ignored (MS-RDPEI 3.1.5.1). A structurally broken
//! message is an [`crate::Error::Protocol`], which closes only this channel.
//!
//! All variable-length integers (MS-RDPEI 2.2.2.1 to 2.2.2.5) are big-endian
//! within the structure, with a length (and sign) prefix in the top bits of
//! the first byte; signed values are sign and magnitude, not two's
//! complement.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::cursor::{Put, Reader};
use crate::dvc::{DvcOut, DynamicChannel};
use crate::error::{Result, proto};
use crate::trace;

/// Dynamic virtual channel name (MS-RDPEI 2.1).
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Input";

// RDPINPUT_HEADER eventId values (MS-RDPEI 2.2.2.6).
pub const EVENTID_SC_READY: u16 = 0x0001;
pub const EVENTID_CS_READY: u16 = 0x0002;
pub const EVENTID_TOUCH: u16 = 0x0003;
pub const EVENTID_SUSPEND_INPUT: u16 = 0x0004;
pub const EVENTID_RESUME_INPUT: u16 = 0x0005;
pub const EVENTID_DISMISS_HOVERING_TOUCH_CONTACT: u16 = 0x0006;
pub const EVENTID_PEN: u16 = 0x0008;

/// Size of RDPINPUT_HEADER (MS-RDPEI 2.2.2.6).
pub const HEADER_SIZE: usize = 6;

// protocolVersion values (MS-RDPEI 2.2.3.1, 2.2.3.2).
pub const PROTOCOL_V100: u32 = 0x0001_0000;
pub const PROTOCOL_V101: u32 = 0x0001_0001;
pub const PROTOCOL_V200: u32 = 0x0002_0000;
pub const PROTOCOL_V300: u32 = 0x0003_0000;

/// SC_READY_MULTIPEN_INJECTION_SUPPORTED (MS-RDPEI 2.2.3.1).
pub const SC_READY_MULTIPEN_INJECTION_SUPPORTED: u32 = 0x0000_0001;

// RDPINPUT_CS_READY_PDU flags (MS-RDPEI 2.2.3.2).
pub const CS_READY_FLAGS_SHOW_TOUCH_VISUALS: u32 = 0x0000_0001;
pub const CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION: u32 = 0x0000_0002;
pub const CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION: u32 = 0x0000_0004;

// RDPINPUT_TOUCH_CONTACT fieldsPresent (MS-RDPEI 2.2.3.3.1.1).
pub const TOUCH_CONTACT_CONTACTRECT_PRESENT: u16 = 0x0001;
pub const TOUCH_CONTACT_ORIENTATION_PRESENT: u16 = 0x0002;
pub const TOUCH_CONTACT_PRESSURE_PRESENT: u16 = 0x0004;

// contactFlags of touch and pen contacts (MS-RDPEI 2.2.3.3.1.1, 2.2.3.7.1.1).
pub const CONTACT_FLAG_DOWN: u32 = 0x0001;
pub const CONTACT_FLAG_UPDATE: u32 = 0x0002;
pub const CONTACT_FLAG_UP: u32 = 0x0004;
pub const CONTACT_FLAG_INRANGE: u32 = 0x0008;
pub const CONTACT_FLAG_INCONTACT: u32 = 0x0010;
pub const CONTACT_FLAG_CANCELED: u32 = 0x0020;

// RDPINPUT_PEN_CONTACT fieldsPresent (MS-RDPEI 2.2.3.7.1.1).
pub const PEN_CONTACT_PENFLAGS_PRESENT: u16 = 0x0001;
pub const PEN_CONTACT_PRESSURE_PRESENT: u16 = 0x0002;
pub const PEN_CONTACT_ROTATION_PRESENT: u16 = 0x0004;
pub const PEN_CONTACT_TILTX_PRESENT: u16 = 0x0008;
pub const PEN_CONTACT_TILTY_PRESENT: u16 = 0x0010;

// penFlags (MS-RDPEI 2.2.3.7.1.1).
pub const PEN_FLAG_BARREL_PRESSED: u32 = 0x0001;
pub const PEN_FLAG_ERASER_PRESSED: u32 = 0x0002;
pub const PEN_FLAG_INVERTED: u32 = 0x0004;

/// Largest TWO_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.1).
pub const TWO_BYTE_UNSIGNED_MAX: u16 = 0x7FFF;
/// Largest magnitude of a TWO_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.2).
pub const TWO_BYTE_SIGNED_MAX: i16 = 0x3FFF;
/// Largest FOUR_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.3).
pub const FOUR_BYTE_UNSIGNED_MAX: u32 = 0x3FFF_FFFF;
/// Largest magnitude of a FOUR_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.4).
pub const FOUR_BYTE_SIGNED_MAX: i32 = 0x1FFF_FFFF;
/// Largest EIGHT_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.5).
pub const EIGHT_BYTE_UNSIGNED_MAX: u64 = 0x1FFF_FFFF_FFFF_FFFF;

/// Pressure range of touch and pen contacts (MS-RDPEI 2.2.3.3.1.1, 2.2.3.7.1.1).
pub const PRESSURE_MAX: u32 = 1024;
/// Pen tilt range in degrees, both signs (MS-RDPEI 2.2.3.7.1.1).
pub const TILT_MAX: i16 = 90;

/// maxTouchContacts the client announces by default (MS-RDPEI 2.2.3.2).
pub const DEFAULT_MAX_TOUCH_CONTACTS: u16 = 10;

/// Frames queued per kind while the session worker is slow; beyond this,
/// new frames are dropped (and [`TouchHandle::send_touch`] says so).
pub const MAX_QUEUED_FRAMES: usize = 512;
/// Frames per TOUCH/PEN event PDU; more wait for the next tick.
pub const MAX_FRAMES_PER_PDU: usize = 64;

// ---------------------------------------------------------------------------
// Variable-length integers (MS-RDPEI 2.2.2).
// ---------------------------------------------------------------------------

/// Writes `n` low bytes of `v`, most significant first, after a first byte
/// whose top bits are `prefix` and whose low `low_bits` hold the rest of `v`.
fn put_var(out: &mut Vec<u8>, prefix: u8, low_bits: u32, v: u64, n: usize) {
    let rest_bits = 8 * (n - 1) as u32;
    let first = (v >> rest_bits) as u8 & ((1u16 << low_bits) - 1) as u8;
    out.push(prefix | first);
    for i in (0..n - 1).rev() {
        out.push((v >> (8 * i)) as u8);
    }
}

/// Reads `extra` more bytes after `first_val`, most significant first.
fn get_var(r: &mut Reader, first_val: u64, extra: usize) -> Result<u64> {
    let mut v = first_val;
    for &b in r.bytes(extra)? {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

/// TWO_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.1): 0..=0x7FFF in one or two
/// bytes. Larger values are clamped to 0x7FFF.
pub fn put_two_byte_unsigned(out: &mut Vec<u8>, v: u16) {
    let v = v.min(TWO_BYTE_UNSIGNED_MAX) as u64;
    if v <= 0x7F {
        put_var(out, 0x00, 7, v, 1);
    } else {
        put_var(out, 0x80, 7, v, 2);
    }
}

pub fn read_two_byte_unsigned(r: &mut Reader) -> Result<u16> {
    let b = r.u8()?;
    let extra = (b >> 7) as usize;
    Ok(get_var(r, (b & 0x7F) as u64, extra)? as u16)
}

/// TWO_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.2): -0x3FFF..=0x3FFF in one or two
/// bytes, sign and magnitude. Values outside are clamped.
pub fn put_two_byte_signed(out: &mut Vec<u8>, v: i16) {
    let v = v.clamp(-TWO_BYTE_SIGNED_MAX, TWO_BYTE_SIGNED_MAX);
    let sign = if v < 0 { 0x40 } else { 0 };
    let m = v.unsigned_abs() as u64;
    if m <= 0x3F {
        put_var(out, sign, 6, m, 1);
    } else {
        put_var(out, 0x80 | sign, 6, m, 2);
    }
}

pub fn read_two_byte_signed(r: &mut Reader) -> Result<i16> {
    let b = r.u8()?;
    let extra = (b >> 7) as usize;
    let m = get_var(r, (b & 0x3F) as u64, extra)? as i16;
    Ok(if b & 0x40 != 0 { -m } else { m })
}

/// FOUR_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.3): 0..=0x3FFFFFFF in one to
/// four bytes. Larger values are clamped.
pub fn put_four_byte_unsigned(out: &mut Vec<u8>, v: u32) {
    let v = v.min(FOUR_BYTE_UNSIGNED_MAX) as u64;
    let n = match v {
        0..=0x3F => 1,
        0x40..=0x3FFF => 2,
        0x4000..=0x3F_FFFF => 3,
        _ => 4,
    };
    put_var(out, ((n - 1) as u8) << 6, 6, v, n);
}

pub fn read_four_byte_unsigned(r: &mut Reader) -> Result<u32> {
    let b = r.u8()?;
    let extra = (b >> 6) as usize;
    Ok(get_var(r, (b & 0x3F) as u64, extra)? as u32)
}

/// FOUR_BYTE_SIGNED_INTEGER (MS-RDPEI 2.2.2.4): -0x1FFFFFFF..=0x1FFFFFFF in
/// one to four bytes, sign and magnitude. Values outside are clamped.
pub fn put_four_byte_signed(out: &mut Vec<u8>, v: i32) {
    let v = v.clamp(-FOUR_BYTE_SIGNED_MAX, FOUR_BYTE_SIGNED_MAX);
    let sign = if v < 0 { 0x20 } else { 0 };
    let m = v.unsigned_abs() as u64;
    let n = match m {
        0..=0x1F => 1,
        0x20..=0x1FFF => 2,
        0x2000..=0x1F_FFFF => 3,
        _ => 4,
    };
    put_var(out, ((n - 1) as u8) << 6 | sign, 5, m, n);
}

pub fn read_four_byte_signed(r: &mut Reader) -> Result<i32> {
    let b = r.u8()?;
    let extra = (b >> 6) as usize;
    let m = get_var(r, (b & 0x1F) as u64, extra)? as i32;
    Ok(if b & 0x20 != 0 { -m } else { m })
}

/// EIGHT_BYTE_UNSIGNED_INTEGER (MS-RDPEI 2.2.2.5): 0..=0x1FFFFFFFFFFFFFFF in
/// one to eight bytes. Larger values are clamped.
pub fn put_eight_byte_unsigned(out: &mut Vec<u8>, v: u64) {
    let v = v.min(EIGHT_BYTE_UNSIGNED_MAX);
    // Bytes needed: the first byte holds 5 bits, every further one 8.
    let mut n = 1;
    while n < 8 && v >> (5 + 8 * (n - 1)) != 0 {
        n += 1;
    }
    put_var(out, ((n - 1) as u8) << 5, 5, v, n);
}

pub fn read_eight_byte_unsigned(r: &mut Reader) -> Result<u64> {
    let b = r.u8()?;
    let extra = (b >> 5) as usize;
    get_var(r, (b & 0x1F) as u64, extra)
}

// ---------------------------------------------------------------------------
// Messages.
// ---------------------------------------------------------------------------

/// The contactFlags combinations MS-RDPEI 2.2.3.3.1.1 allows (the same list
/// holds for pen contacts, 2.2.3.7.1.1), with the state change each means
/// (3.1.1.1).
pub const VALID_CONTACT_FLAGS: [u32; 8] = [
    // Engaged -> out of range.
    CONTACT_FLAG_UP,
    CONTACT_FLAG_UP | CONTACT_FLAG_CANCELED,
    // Hovering -> out of range.
    CONTACT_FLAG_UPDATE,
    CONTACT_FLAG_UPDATE | CONTACT_FLAG_CANCELED,
    // Out of range or hovering -> engaged.
    CONTACT_FLAG_DOWN | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT,
    // Engaged, moving.
    CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE | CONTACT_FLAG_INCONTACT,
    // Engaged -> hovering.
    CONTACT_FLAG_UP | CONTACT_FLAG_INRANGE,
    // Hovering, moving (or out of range -> hovering).
    CONTACT_FLAG_UPDATE | CONTACT_FLAG_INRANGE,
];

/// True for a contactFlags value in [`VALID_CONTACT_FLAGS`].
pub fn valid_contact_flags(flags: u32) -> bool {
    VALID_CONTACT_FLAGS.contains(&flags)
}

/// RDPINPUT_TOUCH_CONTACT (MS-RDPEI 2.2.3.3.1.1). Coordinates are relative
/// to the remote virtual desktop origin.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TouchContact {
    pub contact_id: u8,
    pub x: i32,
    pub y: i32,
    /// `CONTACT_FLAG_*`; see [`valid_contact_flags`].
    pub flags: u32,
    /// Contact rectangle (left, top, right, bottom) relative to (x, y).
    pub rect: Option<(i16, i16, i16, i16)>,
    /// Degrees, 0..=359, counter-clockwise from the y-axis.
    pub orientation: Option<u32>,
    /// 0..=1024.
    pub pressure: Option<u32>,
}

/// RDPINPUT_TOUCH_FRAME contacts (MS-RDPEI 2.2.3.3.1); the frameOffset is
/// computed when the frame is sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TouchFrame {
    pub contacts: Vec<TouchContact>,
}

/// RDPINPUT_PEN_CONTACT (MS-RDPEI 2.2.3.7.1.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PenContact {
    /// Zero unless multipen injection was negotiated (it is not).
    pub device_id: u8,
    pub x: i32,
    pub y: i32,
    /// `CONTACT_FLAG_*`; see [`valid_contact_flags`].
    pub flags: u32,
    /// `PEN_FLAG_*`.
    pub pen_flags: Option<u32>,
    /// 0..=1024.
    pub pressure: Option<u32>,
    /// Clockwise twist in degrees, 0..=359.
    pub rotation: Option<u16>,
    /// -90..=90, positive to the right.
    pub tilt_x: Option<i16>,
    /// -90..=90, positive toward the user.
    pub tilt_y: Option<i16>,
}

/// RDPINPUT_PEN_FRAME contacts (MS-RDPEI 2.2.3.7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PenFrame {
    pub contacts: Vec<PenContact>,
}

/// Writes an RDPINPUT_HEADER (MS-RDPEI 2.2.2.6) with a placeholder length.
fn start(event: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.put_u16(event);
    v.put_u32(0);
    v
}

/// Patches pduLength once the PDU is complete.
fn finish(mut v: Vec<u8>) -> Vec<u8> {
    let len = v.len() as u32;
    v[2..6].copy_from_slice(&len.to_le_bytes());
    v
}

/// RDPINPUT_SC_READY_PDU (MS-RDPEI 2.2.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScReady {
    pub protocol_version: u32,
    /// Present for version 3.0.0 servers.
    pub supported_features: Option<u32>,
}

/// Parses an RDPINPUT_SC_READY_PDU (MS-RDPEI 2.2.3.1), header included.
pub fn parse_sc_ready(msg: &[u8]) -> Result<ScReady> {
    let mut r = Reader::new(msg);
    let event = r.u16()?;
    let len = r.u32()? as usize;
    if event != EVENTID_SC_READY {
        return proto(format!("rdpei: event {event} is not SC_READY"));
    }
    if len < HEADER_SIZE + 4 || len > msg.len() {
        return proto(format!("rdpei SC_READY length {len}"));
    }
    let protocol_version = r.u32()?;
    let supported_features = if len >= HEADER_SIZE + 8 {
        Some(r.u32()?)
    } else {
        None
    };
    Ok(ScReady {
        protocol_version,
        supported_features,
    })
}

/// The version the client answers with: the highest version both sides know,
/// at most 3.0.0 (MS-RDPEI 2.2.3.2). An unknown server version below 1.0.0
/// still gets 1.0.0.
pub fn negotiate_version(server: u32) -> u32 {
    match server {
        v if v >= PROTOCOL_V300 => PROTOCOL_V300,
        v if v >= PROTOCOL_V200 => PROTOCOL_V200,
        v if v >= PROTOCOL_V101 => PROTOCOL_V101,
        _ => PROTOCOL_V100,
    }
}

/// RDPINPUT_CS_READY_PDU (MS-RDPEI 2.2.3.2).
pub fn cs_ready_pdu(flags: u32, protocol_version: u32, max_touch_contacts: u16) -> Vec<u8> {
    let mut v = start(EVENTID_CS_READY);
    v.put_u32(flags);
    v.put_u32(protocol_version);
    v.put_u16(max_touch_contacts);
    finish(v)
}

/// RDPINPUT_TOUCH_CONTACT (MS-RDPEI 2.2.3.3.1.1). Values outside their
/// ranges are clamped (orientation wraps).
pub fn put_touch_contact(out: &mut Vec<u8>, c: &TouchContact) {
    let mut fields = 0;
    if c.rect.is_some() {
        fields |= TOUCH_CONTACT_CONTACTRECT_PRESENT;
    }
    if c.orientation.is_some() {
        fields |= TOUCH_CONTACT_ORIENTATION_PRESENT;
    }
    if c.pressure.is_some() {
        fields |= TOUCH_CONTACT_PRESSURE_PRESENT;
    }
    out.put_u8(c.contact_id);
    put_two_byte_unsigned(out, fields);
    put_four_byte_signed(out, c.x);
    put_four_byte_signed(out, c.y);
    put_four_byte_unsigned(out, c.flags);
    if let Some((l, t, r, b)) = c.rect {
        for v in [l, t, r, b] {
            put_two_byte_signed(out, v);
        }
    }
    if let Some(o) = c.orientation {
        put_four_byte_unsigned(out, o % 360);
    }
    if let Some(p) = c.pressure {
        put_four_byte_unsigned(out, p.min(PRESSURE_MAX));
    }
}

pub fn read_touch_contact(r: &mut Reader) -> Result<TouchContact> {
    let contact_id = r.u8()?;
    let fields = read_two_byte_unsigned(r)?;
    let x = read_four_byte_signed(r)?;
    let y = read_four_byte_signed(r)?;
    let flags = read_four_byte_unsigned(r)?;
    let rect = if fields & TOUCH_CONTACT_CONTACTRECT_PRESENT != 0 {
        Some((
            read_two_byte_signed(r)?,
            read_two_byte_signed(r)?,
            read_two_byte_signed(r)?,
            read_two_byte_signed(r)?,
        ))
    } else {
        None
    };
    let orientation = if fields & TOUCH_CONTACT_ORIENTATION_PRESENT != 0 {
        Some(read_four_byte_unsigned(r)?)
    } else {
        None
    };
    let pressure = if fields & TOUCH_CONTACT_PRESSURE_PRESENT != 0 {
        Some(read_four_byte_unsigned(r)?)
    } else {
        None
    };
    Ok(TouchContact {
        contact_id,
        x,
        y,
        flags,
        rect,
        orientation,
        pressure,
    })
}

/// RDPINPUT_PEN_CONTACT (MS-RDPEI 2.2.3.7.1.1). Values outside their ranges
/// are clamped (rotation wraps).
pub fn put_pen_contact(out: &mut Vec<u8>, c: &PenContact) {
    let mut fields = 0;
    if c.pen_flags.is_some() {
        fields |= PEN_CONTACT_PENFLAGS_PRESENT;
    }
    if c.pressure.is_some() {
        fields |= PEN_CONTACT_PRESSURE_PRESENT;
    }
    if c.rotation.is_some() {
        fields |= PEN_CONTACT_ROTATION_PRESENT;
    }
    if c.tilt_x.is_some() {
        fields |= PEN_CONTACT_TILTX_PRESENT;
    }
    if c.tilt_y.is_some() {
        fields |= PEN_CONTACT_TILTY_PRESENT;
    }
    out.put_u8(c.device_id);
    put_two_byte_unsigned(out, fields);
    put_four_byte_signed(out, c.x);
    put_four_byte_signed(out, c.y);
    put_four_byte_unsigned(out, c.flags);
    if let Some(f) = c.pen_flags {
        put_four_byte_unsigned(out, f);
    }
    if let Some(p) = c.pressure {
        put_four_byte_unsigned(out, p.min(PRESSURE_MAX));
    }
    if let Some(rot) = c.rotation {
        put_two_byte_unsigned(out, rot % 360);
    }
    if let Some(t) = c.tilt_x {
        put_two_byte_signed(out, t.clamp(-TILT_MAX, TILT_MAX));
    }
    if let Some(t) = c.tilt_y {
        put_two_byte_signed(out, t.clamp(-TILT_MAX, TILT_MAX));
    }
}

pub fn read_pen_contact(r: &mut Reader) -> Result<PenContact> {
    let device_id = r.u8()?;
    let fields = read_two_byte_unsigned(r)?;
    let x = read_four_byte_signed(r)?;
    let y = read_four_byte_signed(r)?;
    let flags = read_four_byte_unsigned(r)?;
    let opt_u32 = |r: &mut Reader, bit: u16| -> Result<Option<u32>> {
        Ok(if fields & bit != 0 {
            Some(read_four_byte_unsigned(r)?)
        } else {
            None
        })
    };
    let pen_flags = opt_u32(r, PEN_CONTACT_PENFLAGS_PRESENT)?;
    let pressure = opt_u32(r, PEN_CONTACT_PRESSURE_PRESENT)?;
    let rotation = if fields & PEN_CONTACT_ROTATION_PRESENT != 0 {
        Some(read_two_byte_unsigned(r)?)
    } else {
        None
    };
    let tilt_x = if fields & PEN_CONTACT_TILTX_PRESENT != 0 {
        Some(read_two_byte_signed(r)?)
    } else {
        None
    };
    let tilt_y = if fields & PEN_CONTACT_TILTY_PRESENT != 0 {
        Some(read_two_byte_signed(r)?)
    } else {
        None
    };
    Ok(PenContact {
        device_id,
        x,
        y,
        flags,
        pen_flags,
        pressure,
        rotation,
        tilt_x,
        tilt_y,
    })
}

/// RDPINPUT_TOUCH_EVENT_PDU (MS-RDPEI 2.2.3.3): `frames` as (frameOffset in
/// microseconds, frame), oldest first; `encode_time` in milliseconds.
pub fn touch_event_pdu(encode_time: u32, frames: &[(u64, &TouchFrame)]) -> Vec<u8> {
    let mut v = start(EVENTID_TOUCH);
    put_four_byte_unsigned(&mut v, encode_time);
    put_two_byte_unsigned(&mut v, frames.len() as u16);
    for (offset, f) in frames {
        // RDPINPUT_TOUCH_FRAME (MS-RDPEI 2.2.3.3.1).
        put_two_byte_unsigned(&mut v, f.contacts.len() as u16);
        put_eight_byte_unsigned(&mut v, *offset);
        for c in &f.contacts {
            put_touch_contact(&mut v, c);
        }
    }
    finish(v)
}

/// RDPINPUT_PEN_EVENT_PDU (MS-RDPEI 2.2.3.7), like [`touch_event_pdu`].
pub fn pen_event_pdu(encode_time: u32, frames: &[(u64, &PenFrame)]) -> Vec<u8> {
    let mut v = start(EVENTID_PEN);
    put_four_byte_unsigned(&mut v, encode_time);
    put_two_byte_unsigned(&mut v, frames.len() as u16);
    for (offset, f) in frames {
        // RDPINPUT_PEN_FRAME (MS-RDPEI 2.2.3.7.1).
        put_two_byte_unsigned(&mut v, f.contacts.len() as u16);
        put_eight_byte_unsigned(&mut v, *offset);
        for c in &f.contacts {
            put_pen_contact(&mut v, c);
        }
    }
    finish(v)
}

/// A decoded TOUCH or PEN event PDU: encodeTime and (frameOffset, contacts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventPdu<C> {
    pub encode_time: u32,
    pub frames: Vec<(u64, Vec<C>)>,
}

fn parse_event<C>(
    msg: &[u8],
    event: u16,
    read: fn(&mut Reader) -> Result<C>,
) -> Result<EventPdu<C>> {
    let mut r = Reader::new(msg);
    let id = r.u16()?;
    let len = r.u32()? as usize;
    if id != event || len != msg.len() {
        return proto(format!("rdpei event {id} length {len}"));
    }
    let encode_time = read_four_byte_unsigned(&mut r)?;
    let count = read_two_byte_unsigned(&mut r)?;
    let mut frames = Vec::new();
    for _ in 0..count {
        let n = read_two_byte_unsigned(&mut r)?;
        let offset = read_eight_byte_unsigned(&mut r)?;
        // Every contact takes at least 5 bytes: no allocation beyond the data.
        let mut contacts = Vec::with_capacity((n as usize).min(r.remaining() / 5));
        for _ in 0..n {
            contacts.push(read(&mut r)?);
        }
        frames.push((offset, contacts));
    }
    if r.remaining() != 0 {
        return proto(format!(
            "rdpei event {id}: {} trailing bytes",
            r.remaining()
        ));
    }
    Ok(EventPdu {
        encode_time,
        frames,
    })
}

/// Parses an RDPINPUT_TOUCH_EVENT_PDU (MS-RDPEI 2.2.3.3).
pub fn parse_touch_event(msg: &[u8]) -> Result<EventPdu<TouchContact>> {
    parse_event(msg, EVENTID_TOUCH, read_touch_contact)
}

/// Parses an RDPINPUT_PEN_EVENT_PDU (MS-RDPEI 2.2.3.7).
pub fn parse_pen_event(msg: &[u8]) -> Result<EventPdu<PenContact>> {
    parse_event(msg, EVENTID_PEN, read_pen_contact)
}

/// RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU (MS-RDPEI 2.2.3.6).
pub fn dismiss_hovering_pdu(contact_id: u8) -> Vec<u8> {
    let mut v = start(EVENTID_DISMISS_HOVERING_TOUCH_CONTACT);
    v.put_u8(contact_id);
    finish(v)
}

// ---------------------------------------------------------------------------
// Channel and handle.
// ---------------------------------------------------------------------------

/// Client choices for RDPINPUT_CS_READY_PDU (MS-RDPEI 2.2.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchOptions {
    /// CS_READY_FLAGS_SHOW_TOUCH_VISUALS: the server draws touch feedback.
    pub show_touch_visuals: bool,
    pub max_touch_contacts: u16,
}

impl Default for TouchOptions {
    fn default() -> Self {
        TouchOptions {
            show_touch_visuals: false,
            max_touch_contacts: DEFAULT_MAX_TOUCH_CONTACTS,
        }
    }
}

#[derive(Default)]
struct Queue {
    touch: Vec<(Instant, TouchFrame)>,
    pen: Vec<(Instant, PenFrame)>,
    dismiss: Vec<u8>,
}

struct Shared {
    /// CS_READY sent and the channel open.
    ready: AtomicBool,
    /// Input Transmission Suspended (MS-RDPEI 3.3.1.1).
    suspended: AtomicBool,
    /// Pen Input Allowed (MS-RDPEI 3.3.1.2).
    pen: AtomicBool,
    /// Negotiated protocol version, 0 before SC_READY.
    version: AtomicU32,
    queue: Mutex<Queue>,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// UI side of the input channel. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct TouchHandle {
    shared: Arc<Shared>,
}

impl TouchHandle {
    /// True while touch frames reach the server: SC_READY was answered and
    /// the server has not suspended input. When false, the UI should let
    /// the local system turn touch into mouse input.
    pub fn is_ready(&self) -> bool {
        self.shared.ready.load(Ordering::Acquire) && !self.shared.suspended.load(Ordering::Acquire)
    }

    /// True while pen frames reach the server ([`Self::is_ready`] and a
    /// server at version 2.0.0 or later, MS-RDPEI 3.3.1.2).
    pub fn pen_ready(&self) -> bool {
        self.is_ready() && self.shared.pen.load(Ordering::Acquire)
    }

    /// Negotiated protocol version, 0 before the server is ready.
    pub fn version(&self) -> u32 {
        self.shared.version.load(Ordering::Acquire)
    }

    /// Queues a touch frame generated now; it goes out on the next channel
    /// tick. False (frame dropped) when not ready or the queue is full.
    pub fn send_touch(&self, frame: TouchFrame) -> bool {
        self.send_touch_at(frame, Instant::now())
    }

    /// Like [`Self::send_touch`] for a frame generated at `time`.
    pub fn send_touch_at(&self, frame: TouchFrame, time: Instant) -> bool {
        if !self.is_ready() || frame.contacts.is_empty() {
            return false;
        }
        let mut q = self.shared.queue();
        if q.touch.len() >= MAX_QUEUED_FRAMES {
            return false;
        }
        q.touch.push((time, frame));
        true
    }

    /// Queues a pen frame generated now. False when pen input is not
    /// allowed, not ready, or the queue is full.
    pub fn send_pen(&self, frame: PenFrame) -> bool {
        self.send_pen_at(frame, Instant::now())
    }

    /// Like [`Self::send_pen`] for a frame generated at `time`.
    pub fn send_pen_at(&self, frame: PenFrame, time: Instant) -> bool {
        if !self.pen_ready() || frame.contacts.is_empty() {
            return false;
        }
        let mut q = self.shared.queue();
        if q.pen.len() >= MAX_QUEUED_FRAMES {
            return false;
        }
        q.pen.push((time, frame));
        true
    }

    /// Asks the server to move a hovering contact out of range
    /// (RDPINPUT_DISMISS_HOVERING_TOUCH_CONTACT_PDU, MS-RDPEI 3.3.5.6).
    pub fn dismiss_hovering(&self, contact_id: u8) -> bool {
        if !self.is_ready() {
            return false;
        }
        self.shared.queue().dismiss.push(contact_id);
        true
    }
}

/// Time source; injectable for tests.
pub type Clock = Box<dyn Fn() -> Instant + Send>;

/// The `Microsoft::Windows::RDS::Input` dynamic channel handler.
pub struct TouchInput {
    shared: Arc<Shared>,
    options: TouchOptions,
    /// Generation time of the last touch / pen frame sent, for frameOffset.
    last_touch: Option<Instant>,
    last_pen: Option<Instant>,
    clock: Clock,
}

/// Creates the channel and the handle the UI keeps.
pub fn touch_input(options: TouchOptions) -> (TouchInput, TouchHandle) {
    touch_input_with_clock(options, Box::new(Instant::now))
}

/// Like [`touch_input`] with an injected time source.
pub fn touch_input_with_clock(options: TouchOptions, clock: Clock) -> (TouchInput, TouchHandle) {
    let shared = Arc::new(Shared {
        ready: AtomicBool::new(false),
        suspended: AtomicBool::new(false),
        pen: AtomicBool::new(false),
        version: AtomicU32::new(0),
        queue: Mutex::new(Queue::default()),
    });
    let ch = TouchInput {
        shared: shared.clone(),
        options,
        last_touch: None,
        last_pen: None,
        clock,
    };
    (ch, TouchHandle { shared })
}

/// Microseconds from `prev` to `t` (0 for the first frame or a clock that
/// went backwards), the frameOffset of MS-RDPEI 2.2.3.3.1.
fn offset_us(prev: Option<Instant>, t: Instant) -> u64 {
    prev.map_or(0, |p| t.saturating_duration_since(p).as_micros() as u64)
}

/// encodeTime: milliseconds from the oldest frame to now (MS-RDPEI 2.2.3.3).
fn encode_ms(now: Instant, oldest: Instant) -> u32 {
    now.saturating_duration_since(oldest)
        .as_millis()
        .min(FOUR_BYTE_UNSIGNED_MAX as u128) as u32
}

impl TouchInput {
    fn reset(&mut self) {
        self.shared.ready.store(false, Ordering::Release);
        self.shared.suspended.store(false, Ordering::Release);
        self.shared.pen.store(false, Ordering::Release);
        self.shared.version.store(0, Ordering::Release);
        *self.shared.queue() = Queue::default();
        self.last_touch = None;
        self.last_pen = None;
    }
}

impl DynamicChannel for TouchInput {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    fn process(&mut self, msg: &[u8], out: &mut DvcOut) -> Result<()> {
        // RDPINPUT_HEADER (MS-RDPEI 2.2.2.6, 3.1.5.1).
        let mut r = Reader::new(msg);
        let event = r.u16()?;
        let len = r.u32()? as usize;
        if len < HEADER_SIZE || len != msg.len() {
            trace!("rdpei: event {event} length {len} of {} ignored", msg.len());
            return Ok(());
        }
        match event {
            EVENTID_SC_READY => {
                let sc = parse_sc_ready(msg)?;
                let version = negotiate_version(sc.protocol_version);
                let mut flags = 0;
                if self.options.show_touch_visuals {
                    flags |= CS_READY_FLAGS_SHOW_TOUCH_VISUALS;
                }
                trace!(
                    "rdpei: server {:#010x} features {:?}, using {version:#010x}",
                    sc.protocol_version, sc.supported_features
                );
                // A repeated SC_READY restarts the exchange.
                self.reset();
                out.send(cs_ready_pdu(
                    flags,
                    version,
                    self.options.max_touch_contacts,
                ));
                self.shared.version.store(version, Ordering::Release);
                self.shared
                    .pen
                    .store(sc.protocol_version >= PROTOCOL_V200, Ordering::Release);
                self.shared.ready.store(true, Ordering::Release);
            }
            EVENTID_SUSPEND_INPUT => {
                trace!("rdpei: input suspended");
                self.shared.suspended.store(true, Ordering::Release);
                let mut q = self.shared.queue();
                q.touch.clear();
                q.pen.clear();
                q.dismiss.clear();
            }
            EVENTID_RESUME_INPUT => {
                trace!("rdpei: input resumed");
                self.shared.suspended.store(false, Ordering::Release);
            }
            _ => trace!("rdpei: event {event} ignored"),
        }
        Ok(())
    }

    fn tick(&mut self, out: &mut DvcOut) -> Result<()> {
        if !self.shared.ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let (touch, pen, dismiss) = {
            let mut q = self.shared.queue();
            if q.touch.is_empty() && q.pen.is_empty() && q.dismiss.is_empty() {
                return Ok(());
            }
            if self.shared.suspended.load(Ordering::Acquire) {
                *q = Queue::default();
                return Ok(());
            }
            (
                std::mem::take(&mut q.touch),
                std::mem::take(&mut q.pen),
                std::mem::take(&mut q.dismiss),
            )
        };
        let now = (self.clock)();
        for chunk in touch.chunks(MAX_FRAMES_PER_PDU) {
            let mut frames = Vec::with_capacity(chunk.len());
            for (t, f) in chunk {
                frames.push((offset_us(self.last_touch, *t), f));
                self.last_touch = Some(*t);
            }
            out.send(touch_event_pdu(encode_ms(now, chunk[0].0), &frames));
        }
        for chunk in pen.chunks(MAX_FRAMES_PER_PDU) {
            let mut frames = Vec::with_capacity(chunk.len());
            for (t, f) in chunk {
                frames.push((offset_us(self.last_pen, *t), f));
                self.last_pen = Some(*t);
            }
            out.send(pen_event_pdu(encode_ms(now, chunk[0].0), &frames));
        }
        for id in dismiss {
            out.send(dismiss_hovering_pdu(id));
        }
        Ok(())
    }

    fn closed(&mut self) {
        self.reset();
    }
}

/// A session that ends drops its channels without a close: the handle then
/// stops reporting ready.
impl Drop for TouchInput {
    fn drop(&mut self) {
        self.reset();
    }
}

#[cfg(test)]
#[path = "rdpei_tests.rs"]
mod tests;
