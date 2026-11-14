//! The DVC transport on the server: open, overlapped chunk reads, whole
//! message writes. Framing is in [`crate::framing`].

use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CHANNEL_OPTION_DYNAMIC, WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS,
    WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW, WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED, WTS_CURRENT_SESSION,
    WTSFreeMemory, WTSVirtualChannelClose, WTSVirtualChannelOpenEx, WTSVirtualChannelQuery,
    WTSVirtualFileHandle,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, INFINITE, WaitForSingleObject,
};

use super::OwnedHandle;
use crate::framing::ChunkIo;
use crate::seam::Channel;

/// How long one message write may take before the channel is given up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// The `WTSVirtualChannelOpenEx` flags for a channel: dynamic, its
/// priority, and no compression (Remora closes a channel on compressed DVC
/// data).
pub fn open_flags(ch: Channel) -> u32 {
    let priority = match ch {
        Channel::Ctl => WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED,
        Channel::Bulk => WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW,
    };
    WTS_CHANNEL_OPTION_DYNAMIC | priority | WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS
}

/// Opens a DVC in this session and returns its file handle (overlapped).
/// Blocks until the client accepted or refused the channel, so it runs on a
/// worker thread. Follows Microsoft's DVC server sample: query the file
/// handle, duplicate it, then free the query buffer and close the WTS handle.
pub fn open_channel(ch: Channel) -> io::Result<OwnedHandle> {
    let mut name = ch.dvc_name().as_bytes().to_vec();
    name.push(0);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let wts =
        unsafe { WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, name.as_ptr(), open_flags(ch)) };
    if wts.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut buf: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: valid WTS handle and out pointers.
    let ok = unsafe { WTSVirtualChannelQuery(wts, WTSVirtualFileHandle, &mut buf, &mut len) };
    let result = if ok == 0 {
        Err(io::Error::last_os_error())
    } else if buf.is_null() || len as usize != size_of::<HANDLE>() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WTSVirtualChannelQuery returned no file handle",
        ))
    } else {
        // SAFETY: the buffer holds one HANDLE (checked length).
        let file = unsafe { *(buf as *const HANDLE) };
        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: duplicating a handle within this process.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file,
                GetCurrentProcess(),
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedHandle(dup))
        }
    };
    // SAFETY: freeing what WTSVirtualChannelQuery allocated; closing the WTS
    // handle leaves the duplicated file handle open.
    unsafe {
        if !buf.is_null() {
            WTSFreeMemory(buf);
        }
        WTSVirtualChannelClose(wts);
    }
    result
}

/// A manual-reset event for overlapped IO.
pub struct Event(OwnedHandle);

impl Event {
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain unnamed event.
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(OwnedHandle(h)))
    }
}

pub enum Op<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
    /// `ConnectNamedPipe` on a pipe server handle.
    Connect,
}

/// One overlapped operation with a timeout (`None`: wait forever).
/// `Ok(None)` if it timed out and was cancelled without transferring data.
/// Every started operation is finished (`GetOverlappedResult` with wait)
/// before this returns, so the buffer and `OVERLAPPED` never outlive it.
pub fn overlapped(
    handle: HANDLE,
    event: &Event,
    op: Op<'_>,
    timeout: Option<Duration>,
) -> io::Result<Option<u32>> {
    // SAFETY: zeroed OVERLAPPED is valid; it lives until the IO finished.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.0.0;
    let is_connect = matches!(op, Op::Connect);
    // SAFETY: buffers and `ov` stay alive until GetOverlappedResult below.
    let ok = unsafe {
        match op {
            Op::Read(b) => {
                let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
                ReadFile(handle, b.as_mut_ptr(), len, std::ptr::null_mut(), &mut ov)
            }
            Op::Write(b) => {
                let len = u32::try_from(b.len())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                WriteFile(handle, b.as_ptr(), len, std::ptr::null_mut(), &mut ov)
            }
            Op::Connect => ConnectNamedPipe(handle, &mut ov),
        }
    };
    let mut timed_out = false;
    if ok == 0 {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        if is_connect && err == ERROR_PIPE_CONNECTED {
            return Ok(Some(0));
        }
        if err != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let ms = timeout.map_or(INFINITE, |t| {
            u32::try_from(t.as_millis())
                .unwrap_or(INFINITE - 1)
                .min(INFINITE - 1)
        });
        // SAFETY: valid event handle.
        let w = unsafe { WaitForSingleObject(event.0.0, ms) };
        if w != WAIT_OBJECT_0 {
            timed_out = w == WAIT_TIMEOUT;
            // SAFETY: cancels only this operation.
            unsafe { CancelIoEx(handle, &ov) };
        }
    }
    let mut n = 0u32;
    // SAFETY: waits for the operation to finish (completed or cancelled).
    if unsafe { GetOverlappedResult(handle, &ov, &mut n, 1) } == 0 {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        if timed_out && err == ERROR_OPERATION_ABORTED {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(Some(n))
}

/// One direction of an open channel. Reader and writer each own one, with
/// their own event, on the same shared handle.
pub struct WtsChunkIo {
    file: Arc<OwnedHandle>,
    event: Event,
}

impl WtsChunkIo {
    pub fn new(file: Arc<OwnedHandle>) -> io::Result<Self> {
        Ok(Self {
            file,
            event: Event::new()?,
        })
    }
}

impl ChunkIo for WtsChunkIo {
    fn read_chunk(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let n = overlapped(self.file.0, &self.event, Op::Read(buf), Some(timeout))?;
        Ok(n.map(|n| n as usize))
    }

    fn write_message(&mut self, msg: &[u8]) -> io::Result<()> {
        match overlapped(
            self.file.0,
            &self.event,
            Op::Write(msg),
            Some(WRITE_TIMEOUT),
        )? {
            None => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DVC write timed out",
            )),
            // A second WriteFile would be a second message: give up instead.
            Some(n) if n as usize != msg.len() => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short DVC write: {n} of {} bytes", msg.len()),
            )),
            Some(_) => Ok(()),
        }
    }
}

/// Aborts every pending read and write on the handle (any thread).
pub fn cancel_all(file: &OwnedHandle) {
    // SAFETY: cancelling IO on a handle we own.
    unsafe { CancelIoEx(file.0, std::ptr::null()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_follow_the_design() {
        assert_eq!(open_flags(Channel::Ctl), 1 | 2 | 8);
        assert_eq!(open_flags(Channel::Bulk), 1 | 8);
    }
}
