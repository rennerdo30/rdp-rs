//! [`WinSerial`]: the serial and parallel port backend (RDP-74) for
//! `rdp::port_device` (MS-RDPESP), on the Win32 communications API.
//!
//! Ports are listed from the registry keys the port drivers fill in,
//! `HKLM\HARDWARE\DEVICEMAP\SERIALCOMM` (value data "COM3") and
//! `HKLM\HARDWARE\DEVICEMAP\PARALLEL PORTS` (value data
//! "\DosDevices\LPT1"); only COMn and LPTn names are ever opened, as
//! `\\.\COMn` with exclusive access and overlapped I/O.
//!
//! How each request reaches the port:
//! - reads, writes and WAIT_ON_MASK: overlapped ReadFile, WriteFile and
//!   WaitCommEvent, each waited for on the device's worker thread;
//! - timeouts, wait mask, purge, queue size, DTR/RTS/XON/XOFF/break, the
//!   immediate character, modem status and properties: SetCommTimeouts /
//!   GetCommTimeouts, SetCommMask / GetCommMask, PurgeComm, SetupComm,
//!   EscapeCommFunction, TransmitCommChar, GetCommModemStatus and
//!   GetCommProperties, whose Win32 structures carry the IOCTL's fields one
//!   to one;
//! - baud rate, line control, special characters, handflow, DTR/RTS state
//!   and comm status: the IOCTL itself through DeviceIoControl.
//!   SetCommState / GetCommState and ClearCommError are not used: the DCB
//!   has no field for SERIAL_DCD_HANDSHAKE, SERIAL_BREAK_CHAR and the break
//!   character, and COMSTAT none for SERIAL_TX_WAITING_ON_BREAK and
//!   SERIAL_RX_WAITING_FOR_DSR, so a DCB round trip would silently clear
//!   settings the server application made;
//! - the other IOCTLs of the MS-RDPESP 2.2.2.6 table (statistics, modem and
//!   FIFO control, parallel port requests): DeviceIoControl unchanged.
//!
//! Close cancels every pending operation (CancelIoEx) and waits until they
//! returned before the handle is closed, so the port is free again for the
//! next open. Port data is never logged.

use rdp::rdpdr::serial::{PortInfo, PortKind};

/// Win32 error codes (MS-ERREF 2.2) this backend maps.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_SEM_TIMEOUT: u32 = 121;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_COUNTER_TIMEOUT: u32 = 1121;
const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
const ERROR_DEVICE_REMOVED: u32 = 1617;

/// The NTSTATUS (MS-ERREF 2.3) the server gets for a Win32 error.
pub fn ntstatus(win32: u32) -> u32 {
    use rdp::rdpdr::fscc::*;
    use rdp::rdpdr::serial::{STATUS_BUFFER_TOO_SMALL, STATUS_CANCELLED, STATUS_DEVICE_REMOVED};
    match win32 {
        ERROR_OPERATION_ABORTED => STATUS_CANCELLED,
        ERROR_INVALID_PARAMETER => STATUS_INVALID_PARAMETER,
        ERROR_ACCESS_DENIED => STATUS_ACCESS_DENIED,
        ERROR_SHARING_VIOLATION => STATUS_SHARING_VIOLATION,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => STATUS_OBJECT_NAME_NOT_FOUND,
        ERROR_INSUFFICIENT_BUFFER => STATUS_BUFFER_TOO_SMALL,
        ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED => STATUS_NOT_SUPPORTED,
        ERROR_DEVICE_REMOVED | ERROR_DEVICE_NOT_CONNECTED => STATUS_DEVICE_REMOVED,
        ERROR_SEM_TIMEOUT => 0xC000_00B5,     // STATUS_IO_TIMEOUT
        ERROR_COUNTER_TIMEOUT => 0x0000_0102, // STATUS_TIMEOUT
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// Port names from the registry values' data: "COM3" or "\DosDevices\LPT1"
/// to valid, distinct names, serial first, then by number.
pub fn port_names(values: impl IntoIterator<Item = String>) -> Vec<PortInfo> {
    let mut out: Vec<PortInfo> = Vec::new();
    for v in values {
        let name = v.trim_end_matches('\0').rsplit('\\').next().unwrap_or("");
        if let Some(p) = PortInfo::new(name)
            && !out.iter().any(|o| o.name == p.name)
        {
            out.push(p);
        }
    }
    let number = |p: &PortInfo| p.name[3..].parse::<u32>().unwrap_or(0);
    out.sort_by_key(|p| (p.kind == PortKind::Parallel, number(p)));
    out
}

/// The local serial and parallel ports, as Windows lists them now.
pub fn local_ports() -> Vec<PortInfo> {
    #[cfg(windows)]
    {
        let mut values = win::device_map(r"HARDWARE\DEVICEMAP\SERIALCOMM");
        values.extend(win::device_map(r"HARDWARE\DEVICEMAP\PARALLEL PORTS"));
        port_names(values)
    }
    #[cfg(not(windows))]
    Vec::new()
}

/// The local port system for [`rdp::port_device`].
#[derive(Default)]
pub struct WinSerial;

#[cfg(not(windows))]
impl rdp::SerialBackend for WinSerial {
    fn open(&self, _: &str) -> rdp::rdpdr::serial::PortResult<std::sync::Arc<dyn rdp::SerialPort>> {
        Err(rdp::rdpdr::fscc::STATUS_NOT_SUPPORTED)
    }
}

#[cfg(windows)]
mod win {
    use std::ptr::{null, null_mut};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use rdp::rdpdr::serial::*;
    use rdp::{SerialBackend, SerialPort};
    use windows_sys::Win32::Devices::Communication::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, GENERIC_READ,
        GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::IO::{
        CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
    };
    use windows_sys::Win32::System::Threading::CreateEventW;

    use super::{WinSerial, ntstatus};

    fn wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// The string values of a DEVICEMAP key (empty when it does not exist:
    /// no port of that kind).
    pub fn device_map(key: &str) -> Vec<String> {
        let mut out = Vec::new();
        let path = wide_z(key);
        let mut hkey: HKEY = null_mut();
        // SAFETY: valid null-terminated path and out pointer.
        let rc =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut hkey) };
        if rc != ERROR_SUCCESS {
            return out;
        }
        for index in 0..256u32 {
            let mut name = [0u16; 256];
            let mut name_len = name.len() as u32;
            let mut data = [0u16; 256];
            let mut data_len = (data.len() * 2) as u32;
            let mut kind = 0u32;
            // SAFETY: buffers and their lengths (characters for the name,
            // bytes for the data) match.
            let rc = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    null(),
                    &mut kind,
                    data.as_mut_ptr().cast(),
                    &mut data_len,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS || kind != REG_SZ {
                continue;
            }
            let units = (data_len as usize / 2).min(data.len());
            out.push(String::from_utf16_lossy(&data[..units]));
        }
        // SAFETY: opened above.
        unsafe { RegCloseKey(hkey) };
        out
    }

    impl SerialBackend for WinSerial {
        fn open(&self, port: &str) -> PortResult<Arc<dyn SerialPort>> {
            // Only COMn / LPTn: nothing else is ever opened.
            let info = PortInfo::new(port).ok_or(rdp::rdpdr::fscc::STATUS_OBJECT_NAME_INVALID)?;
            let path = wide_z(&format!(r"\\.\{}", info.name));
            // SAFETY: valid path; exclusive (share mode 0), no template.
            let h = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            };
            if h == INVALID_HANDLE_VALUE {
                // SAFETY: no arguments.
                return Err(ntstatus(unsafe { GetLastError() }));
            }
            Ok(Arc::new(WinPort {
                handle: h,
                state: Mutex::new(Use::default()),
                idle: Condvar::new(),
            }))
        }
    }

    #[derive(Default)]
    struct Use {
        /// Calls in progress on the handle.
        active: usize,
        /// `close` started: new calls fail.
        closing: bool,
        /// The handle is closed.
        closed: bool,
    }

    struct WinPort {
        handle: HANDLE,
        state: Mutex<Use>,
        idle: Condvar,
    }

    // SAFETY: a file handle may be used from any thread; overlapped calls
    // from several threads at once are what the handle is opened for, and
    // `state` keeps the handle open while any call runs.
    unsafe impl Send for WinPort {}
    unsafe impl Sync for WinPort {}

    /// One call in progress (see `WinPort::enter`).
    struct Active<'a>(&'a WinPort);

    impl Drop for Active<'_> {
        fn drop(&mut self) {
            let mut s = self.0.lock();
            s.active -= 1;
            if s.active == 0 {
                self.0.idle.notify_all();
            }
        }
    }

    /// A manual-reset event, closed on drop.
    struct Event(HANDLE);

    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: created by CreateEventW and owned here.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn last_error() -> u32 {
        // SAFETY: no arguments.
        unsafe { GetLastError() }
    }

    impl WinPort {
        fn lock(&self) -> std::sync::MutexGuard<'_, Use> {
            self.state.lock().unwrap_or_else(|p| p.into_inner())
        }

        fn enter(&self) -> PortResult<Active<'_>> {
            let mut s = self.lock();
            if s.closing || s.closed {
                return Err(STATUS_CANCELLED);
            }
            s.active += 1;
            Ok(Active(self))
        }

        /// Runs a synchronous Comm call.
        fn sync(&self, call: impl FnOnce(HANDLE) -> i32) -> PortResult<()> {
            let _a = self.enter()?;
            if call(self.handle) != 0 {
                Ok(())
            } else {
                Err(ntstatus(last_error()))
            }
        }

        /// Issues an overlapped call and waits for it; returns the bytes
        /// transferred. Buffers the call uses must outlive this function,
        /// which returns only once the I/O completed or was cancelled.
        fn overlapped(
            &self,
            issue: impl FnOnce(HANDLE, *mut OVERLAPPED) -> i32,
        ) -> PortResult<u32> {
            let _a = self.enter()?;
            // SAFETY: an unnamed manual-reset event, owned by `Event`.
            let event = unsafe { CreateEventW(null(), 1, 0, null()) };
            if event.is_null() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            let event = Event(event);
            let mut ov = OVERLAPPED {
                hEvent: event.0,
                ..Default::default()
            };
            if issue(self.handle, &mut ov) == 0 {
                let e = last_error();
                if e != ERROR_IO_PENDING {
                    return Err(ntstatus(e));
                }
            }
            let mut n = 0u32;
            // SAFETY: `ov` belongs to the call issued above; waiting (bWait
            // TRUE) means it is not used after this returns.
            if unsafe { GetOverlappedResult(self.handle, &ov, &mut n, 1) } == 0 {
                return Err(ntstatus(last_error()));
            }
            Ok(n)
        }

        /// DeviceIoControl with `input`, returning up to `out_len` bytes.
        fn ioctl(&self, code: u32, input: &[u8], out_len: usize) -> PortResult<Vec<u8>> {
            let mut out = vec![0u8; out_len];
            let n = self.overlapped(|h, ov| {
                // SAFETY: buffers and lengths match; both outlive the wait in
                // `overlapped`.
                unsafe {
                    DeviceIoControl(
                        h,
                        code,
                        if input.is_empty() {
                            null()
                        } else {
                            input.as_ptr().cast()
                        },
                        input.len() as u32,
                        if out.is_empty() {
                            null_mut()
                        } else {
                            out.as_mut_ptr().cast()
                        },
                        out.len() as u32,
                        null_mut(),
                        ov,
                    )
                }
            })?;
            out.truncate(n as usize);
            Ok(out)
        }

        fn ioctl_u32(&self, code: u32) -> PortResult<u32> {
            let b = self.ioctl(code, &[], 4)?;
            Ok(u32::from_le_bytes(
                b.get(..4)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(STATUS_BUFFER_TOO_SMALL)?,
            ))
        }

        fn ioctl_struct(&self, code: u32, len: usize) -> PortResult<Vec<u8>> {
            let b = self.ioctl(code, &[], len)?;
            if b.len() < len {
                return Err(STATUS_BUFFER_TOO_SMALL);
            }
            Ok(b)
        }
    }

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    impl SerialPort for WinPort {
        fn read(&self, max: usize) -> PortResult<Vec<u8>> {
            let mut buf = vec![0u8; max];
            let n = self.overlapped(|h, ov| {
                // SAFETY: `buf` holds `max` bytes and outlives the wait.
                unsafe { ReadFile(h, buf.as_mut_ptr(), max as u32, null_mut(), ov) }
            })?;
            buf.truncate(n as usize);
            Ok(buf)
        }

        fn write(&self, data: &[u8]) -> PortResult<u32> {
            self.overlapped(|h, ov| {
                // SAFETY: `data` outlives the wait.
                unsafe { WriteFile(h, data.as_ptr(), data.len() as u32, null_mut(), ov) }
            })
        }

        fn wait_event(&self) -> PortResult<u32> {
            let mut mask = 0u32;
            self.overlapped(|h, ov| {
                // SAFETY: `mask` outlives the wait.
                unsafe { WaitCommEvent(h, &mut mask, ov) }
            })?;
            Ok(mask)
        }

        fn control(&self, c: &SerialControl) -> PortResult<ControlOut> {
            use SerialControl as C;
            Ok(match c {
                C::SetBaudRate(b) => {
                    self.ioctl(IOCTL_SERIAL_SET_BAUD_RATE, &b.to_le_bytes(), 0)?;
                    ControlOut::None
                }
                C::GetBaudRate => ControlOut::U32(self.ioctl_u32(IOCTL_SERIAL_GET_BAUD_RATE)?),
                C::SetLineControl(v) => {
                    self.ioctl(IOCTL_SERIAL_SET_LINE_CONTROL, &v.encode(), 0)?;
                    ControlOut::None
                }
                C::GetLineControl => {
                    let b = self.ioctl_struct(IOCTL_SERIAL_GET_LINE_CONTROL, LineControl::LEN)?;
                    ControlOut::LineControl(LineControl {
                        stop_bits: b[0],
                        parity: b[1],
                        word_length: b[2],
                    })
                }
                C::SetChars(v) => {
                    self.ioctl(IOCTL_SERIAL_SET_CHARS, &v.encode(), 0)?;
                    ControlOut::None
                }
                C::GetChars => ControlOut::Chars(Chars::decode(
                    &self.ioctl_struct(IOCTL_SERIAL_GET_CHARS, Chars::LEN)?,
                )?),
                C::SetHandflow(v) => {
                    self.ioctl(IOCTL_SERIAL_SET_HANDFLOW, &v.encode(), 0)?;
                    ControlOut::None
                }
                C::GetHandflow => {
                    let b = self.ioctl_struct(IOCTL_SERIAL_GET_HANDFLOW, Handflow::LEN)?;
                    ControlOut::Handflow(Handflow {
                        control_handshake: le32(&b, 0),
                        flow_replace: le32(&b, 4),
                        xon_limit: le32(&b, 8) as i32,
                        xoff_limit: le32(&b, 12) as i32,
                    })
                }
                C::GetDtrRts => ControlOut::U32(self.ioctl_u32(IOCTL_SERIAL_GET_DTRRTS)?),
                C::GetCommStatus => {
                    let b = self.ioctl_struct(IOCTL_SERIAL_GET_COMMSTATUS, 18)?;
                    ControlOut::Status(CommStatus {
                        errors: le32(&b, 0),
                        hold_reasons: le32(&b, 4),
                        in_queue: le32(&b, 8),
                        out_queue: le32(&b, 12),
                        eof_received: b[16] != 0,
                        wait_for_immediate: b[17] != 0,
                    })
                }
                C::SetTimeouts(t) => {
                    let ct = COMMTIMEOUTS {
                        ReadIntervalTimeout: t.read_interval,
                        ReadTotalTimeoutMultiplier: t.read_total_multiplier,
                        ReadTotalTimeoutConstant: t.read_total_constant,
                        WriteTotalTimeoutMultiplier: t.write_total_multiplier,
                        WriteTotalTimeoutConstant: t.write_total_constant,
                    };
                    // SAFETY: pointer to a local.
                    self.sync(|h| unsafe { SetCommTimeouts(h, &ct) })?;
                    ControlOut::None
                }
                C::GetTimeouts => {
                    let mut ct = COMMTIMEOUTS::default();
                    // SAFETY: out pointer to a local.
                    self.sync(|h| unsafe { GetCommTimeouts(h, &mut ct) })?;
                    ControlOut::Timeouts(Timeouts {
                        read_interval: ct.ReadIntervalTimeout,
                        read_total_multiplier: ct.ReadTotalTimeoutMultiplier,
                        read_total_constant: ct.ReadTotalTimeoutConstant,
                        write_total_multiplier: ct.WriteTotalTimeoutMultiplier,
                        write_total_constant: ct.WriteTotalTimeoutConstant,
                    })
                }
                C::SetQueueSize { input, output } => {
                    // SAFETY: plain arguments.
                    self.sync(|h| unsafe { SetupComm(h, *input, *output) })?;
                    ControlOut::None
                }
                C::SetWaitMask(m) => {
                    // SAFETY: plain arguments; ends a pending WaitCommEvent.
                    self.sync(|h| unsafe { SetCommMask(h, *m) })?;
                    ControlOut::None
                }
                C::GetWaitMask => {
                    let mut m = 0u32;
                    // SAFETY: out pointer to a local.
                    self.sync(|h| unsafe { GetCommMask(h, &mut m) })?;
                    ControlOut::U32(m)
                }
                C::Purge(m) => {
                    // SAFETY: plain arguments; PURGE_* equal SERIAL_PURGE_*.
                    self.sync(|h| unsafe { PurgeComm(h, *m) })?;
                    ControlOut::None
                }
                C::Line(op) => {
                    let f = match op {
                        LineOp::SetDtr => SETDTR,
                        LineOp::ClrDtr => CLRDTR,
                        LineOp::SetRts => SETRTS,
                        LineOp::ClrRts => CLRRTS,
                        LineOp::SetXoff => SETXOFF,
                        LineOp::SetXon => SETXON,
                        LineOp::BreakOn => SETBREAK,
                        LineOp::BreakOff => CLRBREAK,
                    };
                    // SAFETY: plain arguments.
                    self.sync(|h| unsafe { EscapeCommFunction(h, f) })?;
                    ControlOut::None
                }
                C::ImmediateChar(c) => {
                    // SAFETY: plain arguments.
                    self.sync(|h| unsafe { TransmitCommChar(h, *c as i8) })?;
                    ControlOut::None
                }
                C::GetModemStatus => {
                    let mut s = 0u32;
                    // SAFETY: out pointer to a local.
                    self.sync(|h| unsafe { GetCommModemStatus(h, &mut s) })?;
                    ControlOut::U32(s)
                }
                C::GetProperties => {
                    let mut p = COMMPROP::default();
                    // SAFETY: out pointer to a local of the API's type.
                    self.sync(|h| unsafe { GetCommProperties(h, &mut p) })?;
                    ControlOut::Properties(CommProp {
                        packet_length: p.wPacketLength,
                        packet_version: p.wPacketVersion,
                        service_mask: p.dwServiceMask,
                        max_tx_queue: p.dwMaxTxQueue,
                        max_rx_queue: p.dwMaxRxQueue,
                        max_baud: p.dwMaxBaud,
                        prov_sub_type: p.dwProvSubType,
                        prov_capabilities: p.dwProvCapabilities,
                        settable_params: p.dwSettableParams,
                        settable_baud: p.dwSettableBaud,
                        settable_data: p.wSettableData,
                        settable_stop_parity: p.wSettableStopParity,
                        current_tx_queue: p.dwCurrentTxQueue,
                        current_rx_queue: p.dwCurrentRxQueue,
                        prov_spec1: p.dwProvSpec1,
                        prov_spec2: p.dwProvSpec2,
                    })
                }
                C::Raw {
                    code,
                    input,
                    output_len,
                } => {
                    // Only table IOCTLs arrive here (rdp::rdpdr::serial).
                    let max = (*output_len as usize).min(64 * 1024);
                    ControlOut::Bytes(self.ioctl(*code, input, max)?)
                }
            })
        }

        fn close(&self) {
            {
                let mut s = self.lock();
                if s.closing || s.closed {
                    return;
                }
                s.closing = true;
            }
            // Cancel until every call returned: a call may issue its I/O
            // just after a cancel, so repeat while any is active.
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut s = self.lock();
            while s.active > 0 && Instant::now() < deadline {
                // SAFETY: the handle stays open while calls are active.
                unsafe { CancelIoEx(self.handle, null()) };
                s = self
                    .idle
                    .wait_timeout(s, Duration::from_millis(20))
                    .map(|(g, _)| g)
                    .unwrap_or_else(|p| p.into_inner().0);
            }
            if s.active == 0 {
                s.closed = true;
                // SAFETY: no call uses the handle any more.
                unsafe { CloseHandle(self.handle) };
            }
            // Otherwise a call ignored the cancel: Drop closes the handle
            // once the last reference (that call's) is gone.
        }
    }

    impl Drop for WinPort {
        fn drop(&mut self) {
            let s = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
            if !s.closed {
                s.closed = true;
                // SAFETY: nothing else can hold `self` now.
                unsafe { CloseHandle(self.handle) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::rdpdr::serial::STATUS_CANCELLED;

    #[test]
    fn registry_values_become_sorted_port_names() {
        let values = [
            "COM10",
            r"\DosDevices\LPT1",
            "COM3",
            "COM3",
            "COM2\0",
            "PRN",
            r"\Device\Serial0",
            "",
        ]
        .map(String::from);
        let names: Vec<String> = port_names(values).into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["COM2", "COM3", "COM10", "LPT1"]);
    }

    #[test]
    fn win32_errors_map_to_ntstatus() {
        assert_eq!(ntstatus(ERROR_OPERATION_ABORTED), STATUS_CANCELLED);
        assert_eq!(ntstatus(ERROR_ACCESS_DENIED), 0xC000_0022);
        assert_eq!(ntstatus(ERROR_FILE_NOT_FOUND), 0xC000_0034);
        assert_eq!(ntstatus(ERROR_DEVICE_REMOVED), 0xC000_02B6);
        assert_eq!(ntstatus(9999), 0xC000_0001);
    }

    #[test]
    fn only_port_names_are_opened() {
        use rdp::SerialBackend;
        // Refused before any system call: no file or device is touched.
        for name in [
            r"\\.\PhysicalDrive0",
            "C:",
            "NUL",
            "COM1:",
            r"..\COM1",
            "COM0",
        ] {
            assert!(WinSerial.open(name).is_err(), "{name}");
        }
    }

    #[test]
    fn local_ports_are_valid_names() {
        // Read-only registry listing; whatever this PC has.
        for p in local_ports() {
            assert_eq!(PortInfo::new(&p.name), Some(p.clone()));
        }
    }
}
