//! The local pipe between `remora-agent open-url` / `remora-agent send` and
//! the running agent in the same session (RDP-44, RDP-43). Local only,
//! message mode, one request and one answer per connection:
//! - `RMU1` + URL (`links::encode_request`) → one byte;
//! - `RMS1` + file paths (`files::encode_send_requests`) → five bytes.
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
use crate::files::{self, SendReply};
use crate::links::{self, MAX_REQUEST_LEN, REPLY_FORWARDED, REPLY_NO_CLIENT, REPLY_REJECTED};
use crate::seam::{SendOutcome, UrlOutcome};
use crate::{info, warn};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the server waits for the protocol's answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);
/// Largest request of either kind.
const MAX_IN: usize = if MAX_REQUEST_LEN > files::MAX_SEND_REQUEST_LEN {
    MAX_REQUEST_LEN
} else {
    files::MAX_SEND_REQUEST_LEN
};

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
            MAX_IN as u32,
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
        .name("agent-pipe".into())
        .spawn(move || serve(pipe, session, tx))?;
    Ok(())
}

fn serve(pipe: OwnedHandle, session: u32, tx: Sender<Input>) {
    let Ok(event) = Event::new() else { return };
    let mut buf = vec![0u8; MAX_IN + 1];
    loop {
        if let Err(e) = overlapped(pipe.0, &event, Op::Connect, None) {
            warn!("agent pipe: connect failed: {e}");
            return;
        }
        let (reply, alive) = handle_client(&pipe, &event, session, &mut buf, &tx);
        if let Ok(Some(_)) = overlapped(pipe.0, &event, Op::Write(&reply), Some(IO_TIMEOUT)) {
            // DisconnectNamedPipe drops unread data. Instead of an unbounded
            // FlushFileBuffers, wait (bounded) for the client to read the
            // answer and close its end, which ends this read.
            let mut eof = [0u8; 1];
            let _ = overlapped(pipe.0, &event, Op::Read(&mut eof), Some(IO_TIMEOUT));
        }
        // SAFETY: our pipe handle.
        unsafe { DisconnectNamedPipe(pipe.0) };
        if !alive {
            return;
        }
    }
}

/// The answer to one client, and whether the event loop is still there.
fn handle_client(
    pipe: &OwnedHandle,
    event: &Event,
    session: u32,
    buf: &mut [u8],
    tx: &Sender<Input>,
) -> (Vec<u8>, bool) {
    let rejected = vec![REPLY_REJECTED];
    let mut client_session = u32::MAX;
    // SAFETY: plain query on our pipe.
    let ok = unsafe { GetNamedPipeClientSessionId(pipe.0, &mut client_session) };
    if ok == 0 || client_session != session {
        warn!("agent pipe: client from another session refused");
        return (rejected, true);
    }
    let n = match overlapped(pipe.0, event, Op::Read(buf), Some(IO_TIMEOUT)) {
        Ok(Some(n)) => n as usize,
        // Timeout, oversize (ERROR_MORE_DATA) or a broken client.
        _ => return (rejected, true),
    };
    let req = &buf[..n];
    if files::is_send_request(req) {
        let rejected = files::encode_send_reply(SendReply::Rejected).to_vec();
        let Some(paths) = files::decode_send_request(req) else {
            warn!("agent pipe: malformed send request of {n} bytes");
            return (rejected, true);
        };
        let (rtx, rrx) = mpsc::channel();
        if tx.send(Input::SendFiles { paths, reply: rtx }).is_err() {
            return (
                files::encode_send_reply(SendReply::NoClient).to_vec(),
                false,
            );
        }
        let r = match rrx.recv_timeout(ANSWER_TIMEOUT) {
            Ok(SendOutcome::Offered { offered, failed }) => SendReply::Offered { offered, failed },
            _ => SendReply::NoClient,
        };
        return (files::encode_send_reply(r).to_vec(), true);
    }
    let Some(url) = links::decode_request(req) else {
        warn!("agent pipe: malformed request of {n} bytes");
        return (rejected, true);
    };
    let (rtx, rrx) = mpsc::channel();
    if tx.send(Input::OpenUrl { url, reply: rtx }).is_err() {
        return (vec![REPLY_NO_CLIENT], false);
    }
    let r = match rrx.recv_timeout(ANSWER_TIMEOUT) {
        Ok(UrlOutcome::Forwarded) => REPLY_FORWARDED,
        _ => REPLY_NO_CLIENT,
    };
    (vec![r], true)
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

/// Connects to the agent of this session and checks who serves the pipe.
/// `None`: no agent.
fn connect() -> io::Result<Option<OwnedHandle>> {
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
            info!("no agent pipe ({e})");
            return Ok(None);
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
    Ok(Some(pipe))
}

/// One request, one answer of at most `reply.len()` bytes. `None`: no agent.
fn exchange(req: &[u8], reply: &mut [u8]) -> io::Result<Option<usize>> {
    let Some(pipe) = connect()? else {
        return Ok(None);
    };
    let event = Event::new()?;
    match overlapped(pipe.0, &event, Op::Write(req), Some(IO_TIMEOUT))? {
        Some(n) if n as usize == req.len() => {}
        _ => return Err(io::Error::new(io::ErrorKind::TimedOut, "pipe write")),
    }
    let answer_wait = ANSWER_TIMEOUT + IO_TIMEOUT;
    match overlapped(pipe.0, &event, Op::Read(reply), Some(answer_wait))? {
        Some(n) => Ok(Some(n as usize)),
        None => Err(io::Error::new(io::ErrorKind::TimedOut, "pipe read")),
    }
}

/// Sends one URL to the agent in this session.
pub fn forward(url: &str) -> io::Result<ForwardResult> {
    let mut reply = [0u8; 1];
    Ok(match exchange(&links::encode_request(url), &mut reply)? {
        None => ForwardResult::NoAgent,
        Some(1) if reply[0] == REPLY_FORWARDED => ForwardResult::Forwarded,
        Some(1) if reply[0] == REPLY_NO_CLIENT => ForwardResult::NoClient,
        Some(_) => ForwardResult::Rejected,
    })
}

/// Sends one `RMS1` request; `None`: no agent.
pub fn forward_send(req: &[u8]) -> io::Result<Option<SendReply>> {
    let mut reply = [0u8; files::SEND_REPLY_LEN];
    Ok(exchange(req, &mut reply)?.map(|n| files::decode_send_reply(&reply[..n])))
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
