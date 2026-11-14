//! The open-URL pipe between `remora-agent open-url` and the running agent
//! in the same session (RDP-44). Local only, message mode.
//!
//! Server: `PIPE_REJECT_REMOTE_CLIENTS`, a DACL that admits only the
//! current user, `FILE_FLAG_FIRST_PIPE_INSTANCE` (fails if someone else
//! already holds the name), and a client in another session is refused.
//! Client: refuses a server in another session or running as another user
//! (a squatter could have taken the name while no agent ran), and connects
//! at identification level so the server cannot impersonate it.

use std::io;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId,
    GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT, SetNamedPipeHandleState,
    WaitNamedPipeW,
};

use super::agent::Input;
use super::wts::{Event, Op, overlapped};
use super::{OwnedHandle, sys, wide};
use crate::links::{self, MAX_REQUEST_LEN, REPLY_FORWARDED, REPLY_NO_CLIENT, REPLY_REJECTED};
use crate::seam::UrlOutcome;
use crate::{info, warn};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the server waits for the protocol's answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);

/// The pipe's security descriptor: protected DACL, full access for the
/// user only.
pub fn pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;{user_sid})")
}

/// Starts the pipe server thread. Fails if the name is taken.
pub fn spawn_server(name: &str, user_sid: &str, tx: Sender<Input>) -> io::Result<()> {
    let sddl = wide(&pipe_sddl(user_sid));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: SDDL conversion; the descriptor is freed after CreateNamedPipeW.
    let handle = unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let n = wide(name);
        let h = CreateNamedPipeW(
            n.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            16,
            MAX_REQUEST_LEN as u32,
            0,
            &sa,
        );
        LocalFree(sd);
        h
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let pipe = OwnedHandle(handle);
    let session = sys::current_session_id();
    std::thread::Builder::new()
        .name("open-url-pipe".into())
        .spawn(move || serve(pipe, session, tx))?;
    Ok(())
}

fn serve(pipe: OwnedHandle, session: u32, tx: Sender<Input>) {
    let Ok(event) = Event::new() else { return };
    let mut buf = vec![0u8; MAX_REQUEST_LEN + 1];
    loop {
        if let Err(e) = overlapped(pipe.0, &event, Op::Connect, None) {
            warn!("open-url pipe: connect failed: {e}");
            return;
        }
        // `None`: the event loop is gone (the agent is exiting).
        let reply = handle_client(&pipe, &event, session, &mut buf, &tx);
        let r = reply.unwrap_or(REPLY_NO_CLIENT);
        if let Ok(Some(_)) = overlapped(pipe.0, &event, Op::Write(&[r]), Some(IO_TIMEOUT)) {
            // DisconnectNamedPipe drops unread data. Instead of an unbounded
            // FlushFileBuffers, wait (bounded) for the client to read the
            // answer and close its end, which ends this read.
            let mut eof = [0u8; 1];
            let _ = overlapped(pipe.0, &event, Op::Read(&mut eof), Some(IO_TIMEOUT));
        }
        // SAFETY: our pipe handle.
        unsafe { DisconnectNamedPipe(pipe.0) };
        if reply.is_none() {
            return;
        }
    }
}

fn handle_client(
    pipe: &OwnedHandle,
    event: &Event,
    session: u32,
    buf: &mut [u8],
    tx: &Sender<Input>,
) -> Option<u8> {
    let mut client_session = u32::MAX;
    // SAFETY: plain query on our pipe.
    let ok = unsafe { GetNamedPipeClientSessionId(pipe.0, &mut client_session) };
    if ok == 0 || client_session != session {
        warn!("open-url pipe: client from another session refused");
        return Some(REPLY_REJECTED);
    }
    let n = match overlapped(pipe.0, event, Op::Read(buf), Some(IO_TIMEOUT)) {
        Ok(Some(n)) => n as usize,
        // Timeout, oversize (ERROR_MORE_DATA) or a broken client.
        _ => return Some(REPLY_REJECTED),
    };
    let Some(url) = links::decode_request(&buf[..n]) else {
        warn!("open-url pipe: malformed request of {n} bytes");
        return Some(REPLY_REJECTED);
    };
    let (rtx, rrx) = mpsc::channel();
    if tx.send(Input::OpenUrl { url, reply: rtx }).is_err() {
        return None;
    }
    Some(match rrx.recv_timeout(ANSWER_TIMEOUT) {
        Ok(UrlOutcome::Forwarded) => REPLY_FORWARDED,
        _ => REPLY_NO_CLIENT,
    })
}

/// What the running agent answered.
#[derive(Debug, PartialEq, Eq)]
pub enum ForwardResult {
    Forwarded,
    NoClient,
    Rejected,
    /// No agent runs in this session.
    NoAgent,
}

/// Sends one URL to the agent in this session.
pub fn forward(url: &str) -> io::Result<ForwardResult> {
    let (sid, _) = sys::current_user()?;
    let session = sys::current_session_id();
    let name = wide(&links::pipe_name(session, &sid));
    let open = || {
        // SAFETY: opening a local pipe by name.
        unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        }
    };
    let mut h = open();
    if h == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            info!("open-url: no agent pipe ({e})");
            return Ok(ForwardResult::NoAgent);
        }
        // SAFETY: waits for the single instance to become free.
        unsafe { WaitNamedPipeW(name.as_ptr(), 2000) };
        h = open();
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
    }
    let pipe = OwnedHandle(h);
    let (mut server_session, mut server_pid) = (u32::MAX, 0u32);
    // SAFETY: plain queries on our handle.
    let ok = unsafe {
        GetNamedPipeServerSessionId(pipe.0, &mut server_session) != 0
            && GetNamedPipeServerProcessId(pipe.0, &mut server_pid) != 0
    };
    if !ok || server_session != session {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server is in another session",
        ));
    }
    if sys::process_user_sid(Some(server_pid))? != sid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server runs as another user",
        ));
    }
    let mode = PIPE_READMODE_MESSAGE;
    // SAFETY: our handle.
    unsafe { SetNamedPipeHandleState(pipe.0, &mode, std::ptr::null(), std::ptr::null()) };
    let event = Event::new()?;
    let req = links::encode_request(url);
    match overlapped(pipe.0, &event, Op::Write(&req), Some(IO_TIMEOUT))? {
        Some(n) if n as usize == req.len() => {}
        _ => return Err(io::Error::new(io::ErrorKind::TimedOut, "pipe write")),
    }
    let mut reply = [0u8; 1];
    let answer_wait = ANSWER_TIMEOUT + IO_TIMEOUT;
    Ok(
        match overlapped(pipe.0, &event, Op::Read(&mut reply), Some(answer_wait))? {
            Some(1) if reply[0] == REPLY_FORWARDED => ForwardResult::Forwarded,
            Some(1) if reply[0] == REPLY_NO_CLIENT => ForwardResult::NoClient,
            _ => ForwardResult::Rejected,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_admits_only_the_user() {
        let s = pipe_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(s, "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        // Protected: no inherited entries; exactly one allow entry.
        assert!(s.starts_with("D:P"));
        assert_eq!(s.matches("(A;").count(), 1);
        assert!(!s.contains(";WD)") && !s.contains(";AU)") && !s.contains(";BU)"));
    }
}
