//! Shadowing another user's session on a Windows server, the way
//! `mstsc /v:host /shadow:ID [/control] [/noConsentPrompt]` does it (RDP-77):
//!
//! 1. [`request_invitation`]: the RPC `RpcShadow2` (opnum 0) of the
//!    `SessEnvPublicRpc` interface over the named pipe
//!    `\PIPE\SessEnvPublicRpc` (MS-TSTS 1.9, 3.10.4.1.1), as the logged-on
//!    Windows user. The server's SessionEnv service starts a Desktop Sharing
//!    sharer in the target session, asks its user first when consent is
//!    requested, and returns an invitation (MS-RAI 2.2.2).
//! 2. Connect to the invitation with [`rdp::Config::assistance`] and the
//!    `encomsp` channel (MS-RA 2.2.7.2, MS-RDPEMC); see `main.rs`.
//!
//! [`list_sessions`] lists the server's sessions (WTSEnumerateSessionsW),
//! like `qwinsta /server:host`. Both need SMB (TCP 445) to the server; the
//! sharer listens on a dynamic port ("Remote Desktop - Shadow (TCP-In)").

use std::net::IpAddr;

/// What the sharer's user answered, or why policy refused
/// (SHADOW_REQUEST_RESPONSE, MS-TSTS 2.2.1.21).
pub fn response_text(code: u16) -> &'static str {
    match code {
        0 => "allowed",
        1 => "the user declined the request",
        2 => "policy requires the user's permission: ask for consent",
        3 => "shadowing is disabled by policy on the server",
        4 => "policy allows view-only shadowing: leave out control",
        5 => "policy allows view-only shadowing with the user's permission",
        6 => "another shadow session already controls this session",
        _ => "unknown answer",
    }
}

/// A shared desktop's news for the status line (MS-RDPEMC).
pub fn event_text(ev: &rdp::MultipartyEvent) -> String {
    use rdp::{Control, MultipartyEvent as E};
    match ev {
        E::ControlChanged(Control::Interact) => {
            "You control the shared desktop: mouse and keyboard reach it.".into()
        }
        E::ControlChanged(Control::View) => {
            "View only: the shared desktop ignores your mouse and keyboard.".into()
        }
        E::ControlChanged(Control::None) => "The sharer withdrew your view.".into(),
        E::Joined { name, .. } => format!("{name} joined the shared desktop."),
        E::Left { name, .. } => format!("{name} left the shared desktop."),
        // The granted level itself comes as ControlChanged (MS-RDPEMC 2.2.4.4).
        E::ControlResponse { reason, .. } => {
            format!("The sharer answered your control request (reason {reason:#x}).")
        }
        E::Paused(true) => {
            "The picture is paused (the session is locked or shows a secure prompt).".into()
        }
        E::Paused(false) => "The picture resumed.".into(),
    }
}

/// The listener to connect to: one whose address is an address of the
/// server the user named (`server`, resolved by the caller), else the first
/// IPv4 one, else the first. Returns host, port and the transport's SID.
pub fn pick_target(inv: &rdp::Invitation, server: &[IpAddr]) -> Option<(String, u16, u32)> {
    let targets = inv.targets();
    let ip = |h: &str| h.split('%').next().and_then(|a| a.parse::<IpAddr>().ok());
    targets
        .iter()
        .find(|(l, _)| ip(&l.host).is_some_and(|a| server.contains(&a)))
        .or_else(|| {
            targets
                .iter()
                .find(|(l, _)| matches!(ip(&l.host), Some(IpAddr::V4(_))))
        })
        .or(targets.first())
        .map(|(l, sid)| (l.host.clone(), l.port, *sid))
}

/// The text of an invitation file: UTF-16 with a byte order mark (as
/// Windows saves `.msrcIncident` files) or UTF-8.
pub fn invitation_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// One session of a server (WTS_SESSION_INFOW plus its user).
#[derive(Debug, Clone)]
pub struct RemoteSession {
    pub id: u32,
    pub station: String,
    pub state: &'static str,
    pub user: String,
}

/// WTS_CONNECTSTATE_CLASS names.
#[cfg(windows)]
fn state_name(s: i32) -> &'static str {
    match s {
        0 => "Active",
        1 => "Connected",
        2 => "ConnectQuery",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listen",
        7 => "Reset",
        8 => "Down",
        9 => "Init",
        _ => "?",
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A NUL-terminated wide string from Windows.
#[cfg(windows)]
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: the caller passes a NUL-terminated string.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: n units were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// The sessions of `server` (WTSOpenServerW, WTSEnumerateSessionsW), with
/// `DOMAIN\user` where one is logged on. Needs WINSTATION_QUERY there
/// (Administrators and Remote Desktop Users by default).
#[cfg(windows)]
pub fn list_sessions(server: &str) -> Result<Vec<RemoteSession>, String> {
    use windows_sys::Win32::System::RemoteDesktop::*;
    let name = wide(server);
    // SAFETY: a NUL-terminated name; the handle is closed below.
    let h = unsafe { WTSOpenServerW(name.as_ptr()) };
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: out pointers to locals; the buffer is freed below.
    let ok = unsafe { WTSEnumerateSessionsW(h, 0, 1, &mut info, &mut count) };
    if ok == 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: the handle from WTSOpenServerW.
        unsafe { WTSCloseServer(h) };
        return Err(format!("cannot list the sessions of {server}: {e}"));
    }
    let query = |id: u32, class: WTS_INFO_CLASS| -> String {
        let mut buf: windows_sys::core::PWSTR = std::ptr::null_mut();
        let mut bytes = 0u32;
        // SAFETY: out pointers to locals; the buffer is freed right after.
        if unsafe { WTSQuerySessionInformationW(h, id, class, &mut buf, &mut bytes) } == 0 {
            return String::new();
        }
        // SAFETY: WTS returns a NUL-terminated string, freed with WTSFreeMemory.
        let s = unsafe { from_wide(buf) };
        unsafe { WTSFreeMemory(buf.cast()) };
        s
    };
    // SAFETY: WTSEnumerateSessionsW returned `count` entries at `info`.
    let entries = unsafe { std::slice::from_raw_parts(info, count as usize) };
    let sessions = entries
        .iter()
        .map(|e| {
            let user = query(e.SessionId, WTSUserName);
            let domain = query(e.SessionId, WTSDomainName);
            RemoteSession {
                id: e.SessionId,
                // SAFETY: a NUL-terminated name inside the WTS buffer.
                station: unsafe { from_wide(e.pWinStationName) },
                state: state_name(e.State),
                user: match (domain.is_empty(), user.is_empty()) {
                    (_, true) => String::new(),
                    (true, false) => user,
                    (false, false) => format!("{domain}\\{user}"),
                },
            }
        })
        .collect();
    // SAFETY: the buffer and handle from the calls above.
    unsafe {
        WTSFreeMemory(info.cast());
        WTSCloseServer(h);
    }
    Ok(sessions)
}

/// What to ask the server for.
#[derive(Debug, Clone, Copy)]
pub struct ShadowRequest {
    pub session_id: u32,
    /// SHADOW_CONTROL_REQUEST_TAKECONTROL instead of _VIEW (`/control`).
    pub control: bool,
    /// SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION; false is
    /// `/noConsentPrompt`, which policy must allow.
    pub consent: bool,
}

/// Format strings MIDL 8.01.0628 generates for RpcShadow2 with
/// `/env x64 /Oicf /protocol dce` and the ACF `[comm_status, fault_status]`,
/// so communication errors and server faults come back as the
/// error_status_t return value instead of an exception (which Rust cannot
/// catch). IDL: MS-TSTS 3.10.4.1.1 with enum16 enums.
#[cfg(all(windows, target_arch = "x86_64"))]
mod ndr {
    pub static PROC: [u8; 73] = [
        0x00, 0x68, // handle type 0 (explicit), Oi flags: comm/fault status
        0x00, 0x00, 0x00, 0x00, // rpc flags
        0x00, 0x00, // procnum 0
        0x40, 0x00, // stack size 64
        0x32, 0x00, 0x00, 0x00, // FC_BIND_PRIMITIVE at stack offset 0
        0x1c, 0x00, // client buffer size
        0x22, 0x00, // server buffer size
        0x45, 0x07, // Oi2 flags (srv must size, has return, has ext), 7 params
        0x0a, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // extensions
        0x48, 0x00, 0x08, 0x00, 0x08, 0x00, // TargetSessionId: in, FC_LONG
        0x48, 0x00, 0x10, 0x00, 0x0d, 0x00, // eRequestControl: in, FC_ENUM16
        0x48, 0x00, 0x18, 0x00, 0x0d, 0x00, // eRequestPermission: in, FC_ENUM16
        0x10, 0x20, 0x20, 0x00, 0x02, 0x00, // pePermission: out, type 2
        0x13, 0x01, 0x28, 0x00, 0x0a, 0x00, // pszInvitation: out, type 10
        0x88, 0x00, 0x30, 0x00, 0x12, 0x00, // cchInvitation: in, range at 18
        0x70, 0x00, 0x38, 0x00, 0x10, 0x00, // return: FC_ERROR_STATUS_T
        0x00,
    ];
    pub static TYPES: [u8; 29] = [
        0x00, 0x00, //
        0x11, 0x0c, 0x0d, 0x5c, // 2: FC_RP [alloced_on_stack] FC_ENUM16
        0x11, 0x00, 0x02, 0x00, // 6: FC_RP to 10
        0x25, 0x44, // 10: FC_C_WSTRING, FC_STRING_SIZED
        0x29, 0x00, 0x30, 0x00, 0x00, 0x00, // size_is(cchInvitation)
        0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, // range 1..8192
        0x00,
    ];
}

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe extern "system" fn midl_alloc(n: usize) -> *mut core::ffi::c_void {
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc};
    // SAFETY: the process heap.
    unsafe { HeapAlloc(GetProcessHeap(), 0, n) }
}

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe extern "system" fn midl_free(p: *mut core::ffi::c_void) {
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
    if !p.is_null() {
        // SAFETY: allocated by midl_alloc.
        unsafe { HeapFree(GetProcessHeap(), 0, p) };
    }
}

/// Largest invitation RpcShadow2 returns (cchInvitation range, 3.10.4.1.1).
#[cfg(all(windows, target_arch = "x86_64"))]
const MAX_INVITATION: u32 = 8192;

/// Asks `server` for a shadow invitation to session `req.session_id`
/// (RpcShadow2). Blocks while the session's user decides (up to about 30 s).
/// Authenticates as the logged-on Windows user (Negotiate: Kerberos for
/// `host/<server>`, else NTLM) with packet privacy, as mstsc does.
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn request_invitation(server: &str, req: ShadowRequest) -> Result<String, String> {
    use core::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::System::Com::RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    use windows_sys::Win32::System::Rpc::*;
    use windows_sys::core::GUID;

    let rpc_err = |what: &str, st: i32| format!("{what} failed: RPC status {st}");
    let mut string_binding: windows_sys::core::PWSTR = null_mut();
    let (protseq, host, endpoint) = (
        wide("ncacn_np"),
        wide(server),
        wide("\\pipe\\SessEnvPublicRpc"),
    );
    // SAFETY: NUL-terminated inputs; the string is freed below.
    let st = unsafe {
        RpcStringBindingComposeW(
            null(),
            protseq.as_ptr(),
            host.as_ptr(),
            endpoint.as_ptr(),
            null(),
            &mut string_binding,
        )
    };
    if st != RPC_S_OK {
        return Err(rpc_err("RpcStringBindingCompose", st));
    }
    let mut binding: *mut c_void = null_mut();
    // SAFETY: the string from above, freed right after.
    let st = unsafe { RpcBindingFromStringBindingW(string_binding, &mut binding) };
    unsafe { RpcStringFreeW(&mut string_binding) };
    if st != RPC_S_OK {
        return Err(rpc_err("RpcBindingFromStringBinding", st));
    }
    let spn = wide(&format!("host/{server}"));
    // SAFETY: a valid binding; NULL identity is the logged-on user.
    let st = unsafe {
        RpcBindingSetAuthInfoExW(
            binding,
            spn.as_ptr(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_GSS_NEGOTIATE,
            null(),
            RPC_C_AUTHZ_NONE,
            null(),
        )
    };
    if st != RPC_S_OK {
        unsafe { RpcBindingFree(&mut binding) };
        return Err(rpc_err("RpcBindingSetAuthInfoEx", st));
    }

    let ndr_syntax = RPC_SYNTAX_IDENTIFIER {
        SyntaxGUID: GUID::from_u128(0x8a885d04_1ceb_11c9_9fe8_08002b104860),
        SyntaxVersion: RPC_VERSION {
            MajorVersion: 2,
            MinorVersion: 0,
        },
    };
    let mut interface = RPC_CLIENT_INTERFACE {
        Length: size_of::<RPC_CLIENT_INTERFACE>() as u32,
        InterfaceId: RPC_SYNTAX_IDENTIFIER {
            SyntaxGUID: GUID::from_u128(0x1257b580_ce2f_4109_82d6_a9459d0bf6bc),
            SyntaxVersion: RPC_VERSION {
                MajorVersion: 1,
                MinorVersion: 0,
            },
        },
        TransferSyntax: ndr_syntax,
        ..Default::default()
    };
    let comm_fault = [COMM_FAULT_OFFSETS {
        CommOffset: -1,
        FaultOffset: -1,
    }];
    let mut auto_handle: *mut c_void = null_mut();
    let mut desc = MIDL_STUB_DESC {
        RpcInterfaceInformation: (&mut interface as *mut RPC_CLIENT_INTERFACE).cast(),
        pfnAllocate: Some(midl_alloc),
        pfnFree: Some(midl_free),
        IMPLICIT_HANDLE_INFO: MIDL_STUB_DESC_0 {
            pAutoHandle: &mut auto_handle,
        },
        pFormatTypes: ndr::TYPES.as_ptr(),
        fCheckBounds: 1,
        Version: 0x5_0002,
        MIDLVersion: 0x0801_0274,
        CommFaultOffsets: comm_fault.as_ptr(),
        mFlags: 1,
        ..Default::default()
    };
    let mut permission: u16 = 0xFFFF;
    let mut invitation = vec![0u16; MAX_INVITATION as usize];
    // SAFETY: the arguments match the format string: the binding, ULONG,
    // two enum16 passed as ints, an out enum16 pointer, an out buffer of
    // cchInvitation WCHARs, and cchInvitation; the stub descriptor and the
    // interface live until the call returns.
    let status = unsafe {
        NdrClientCall2(
            &mut desc,
            ndr::PROC.as_ptr().cast_mut(),
            binding,
            req.session_id,
            u32::from(req.control),
            u32::from(req.consent),
            &mut permission as *mut u16,
            invitation.as_mut_ptr(),
            MAX_INVITATION,
        )
        .Simple
    } as u32;
    unsafe { RpcBindingFree(&mut binding) };
    match status {
        0 => {}
        5 => {
            return Err(format!(
                "access denied by {server}: shadowing needs an administrator there"
            ));
        }
        1722 | 1726 | 1727 => {
            return Err(format!(
                "{server} is not reachable over SMB (TCP 445) or its SessionEnv service does not answer (RPC status {status})"
            ));
        }
        s => return Err(format!("RpcShadow2 failed: status {s:#x}")),
    }
    if permission != 0 {
        return Err(format!(
            "{server} refused to shadow session {}: {}",
            req.session_id,
            response_text(permission)
        ));
    }
    let n = invitation
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(invitation.len());
    Ok(String::from_utf16_lossy(&invitation[..n]))
}

/// Shadowing needs the x64 RPC stub; other builds report it.
#[cfg(not(all(windows, target_arch = "x86_64")))]
pub fn request_invitation(_server: &str, _req: ShadowRequest) -> Result<String, String> {
    Err("shadowing needs Remora for Windows x64 (the Windows RPC runtime)".into())
}

#[cfg(not(windows))]
pub fn list_sessions(_server: &str) -> Result<Vec<RemoteSession>, String> {
    Err("listing a server's sessions needs Windows (WTS API)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = r#"<E><A KH="k" ID="auth"/><C><T ID="1" SID="7">
        <L P="49749" N="fe80::5%12"/><L P="49750" N="2001:db8::5"/>
        <L P="49751" N="10.0.0.5"/><L P="49752" N="192.168.1.5"/></T></C></E>"#;

    #[test]
    fn picks_the_listener_of_the_named_server_else_ipv4() {
        let inv = rdp::Invitation::parse(INV).unwrap();
        let named: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(
            pick_target(&inv, &[named]),
            Some(("192.168.1.5".into(), 49752, 7))
        );
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(pick_target(&inv, &[v6]).unwrap().1, 49750);
        // A zone suffix still matches its address.
        let ll: IpAddr = "fe80::5".parse().unwrap();
        assert_eq!(pick_target(&inv, &[ll]).unwrap().1, 49749);
        // Unknown server address: the first IPv4 listener.
        assert_eq!(pick_target(&inv, &[]), Some(("10.0.0.5".into(), 49751, 7)));
        let only_v6 = rdp::Invitation::parse(
            r#"<E><A ID="a"/><C><T ID="1" SID="2"><L P="5" N="h.example"/></T></C></E>"#,
        )
        .unwrap();
        assert_eq!(pick_target(&only_v6, &[]), Some(("h.example".into(), 5, 2)));
        let none = rdp::Invitation::parse(r#"<E><A ID="a"/></E>"#).unwrap();
        assert_eq!(pick_target(&none, &[]), None);
    }

    #[test]
    fn invitation_files_in_utf16_and_utf8() {
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend("<E>x</E>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(invitation_text(&utf16), "<E>x</E>");
        assert_eq!(invitation_text(b"\xEF\xBB\xBF<E/>"), "<E/>");
        assert_eq!(invitation_text(b"<E/>"), "<E/>");
    }

    #[test]
    fn every_shadow_answer_has_a_reason() {
        assert_eq!(response_text(0), "allowed");
        for code in 1..=6 {
            assert_ne!(response_text(code), "unknown answer", "{code}");
        }
        assert_eq!(response_text(7), "unknown answer");
    }
}
