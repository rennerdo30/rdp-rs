//! Read-only queries: the user, the session, the registry, and the
//! [`SessionInfo`] collectors.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FILETIME, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ,
    RRF_RT_REG_SZ, RegGetValueW,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_PROCESS_INFOW,
    WTSActive, WTSEnumerateProcessesW, WTSFreeMemory, WTSINFOEXW, WTSIsRemoteSession,
    WTSQuerySessionInformationW, WTSSessionInfoEx,
};
use windows_sys::Win32::System::SystemInformation::{
    GetTickCount, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetSystemTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

use super::{OwnedHandle, from_wide_ptr, wide};
use crate::info::{
    self, CpuTimes, Memory, OsVersion, POLICY_SOURCES, PolicyRoot, PolicyValues, SessionInfo,
    SessionKind,
};

pub fn current_session_id() -> u32 {
    let mut id = 0;
    // SAFETY: plain query for this process.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) };
    id
}

/// The SID string of the user a process runs as (`None`: this process).
pub fn process_user_sid(pid: Option<u32>) -> io::Result<String> {
    // SAFETY: handles are owned and closed by OwnedHandle.
    unsafe {
        let process = match pid {
            None => None,
            Some(pid) => {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if h.is_null() {
                    return Err(io::Error::last_os_error());
                }
                Some(OwnedHandle(h))
            }
        };
        let ph = process.as_ref().map_or(GetCurrentProcess(), |p| p.0);
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(ph, TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        with_token_user(token.0, |sid| sid_to_string(sid))?
    }
}

/// Runs `f` with the token's user SID.
unsafe fn with_token_user<T>(token: HANDLE, f: impl FnOnce(*mut c_void) -> T) -> io::Result<T> {
    let mut len = 0u32;
    // SAFETY: size query, then a buffer of that size (u64-aligned).
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        Ok(f(user.User.Sid))
    }
}

unsafe fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
    let mut s: *mut u16 = std::ptr::null_mut();
    // SAFETY: valid SID; the string is freed with LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut s) == 0 {
            return Err(io::Error::last_os_error());
        }
        let out = from_wide_ptr(s);
        LocalFree(s.cast());
        Ok(out)
    }
}

/// The current user: SID string and `DOMAIN\user`.
pub fn current_user() -> io::Result<(String, String)> {
    // SAFETY: as in process_user_sid; LookupAccountSidW with sized buffers.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        with_token_user(token.0, |sid| -> io::Result<(String, String)> {
            let sid_s = sid_to_string(sid)?;
            let mut name = [0u16; 257];
            let mut domain = [0u16; 257];
            let (mut nl, mut dl) = (name.len() as u32, domain.len() as u32);
            let mut used: SID_NAME_USE = 0;
            if LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut nl,
                domain.as_mut_ptr(),
                &mut dl,
                &mut used,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let name = String::from_utf16_lossy(&name[..nl as usize]);
            let domain = String::from_utf16_lossy(&domain[..dl as usize]);
            Ok((sid_s, format!(r"{domain}\{name}")))
        })?
    }
}

fn hkey(root: PolicyRoot) -> HKEY {
    match root {
        PolicyRoot::LocalMachine => HKEY_LOCAL_MACHINE,
        PolicyRoot::CurrentUser => HKEY_CURRENT_USER,
    }
}

pub fn reg_dword(root: HKEY, key: &str, name: &str) -> Option<u32> {
    let (k, n) = (wide(key), wide(name));
    let mut v = 0u32;
    let mut len = 4u32;
    // SAFETY: DWORD-sized buffer, typed read.
    let r = unsafe {
        RegGetValueW(
            root,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut v as *mut u32).cast(),
            &mut len,
        )
    };
    (r == ERROR_SUCCESS).then_some(v)
}

/// A `REG_SZ` (or `REG_EXPAND_SZ`, unexpanded) value; empty name: default.
pub fn reg_string(root: HKEY, key: &str, name: &str) -> Option<String> {
    let k = wide(key);
    let n = (!name.is_empty()).then(|| wide(name));
    let np = n.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    // RRF_NOEXPAND (0x10000000) keeps %VAR% as written.
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | 0x1000_0000;
    let mut len = 0u32;
    // SAFETY: size query, then a read into a buffer of that size.
    unsafe {
        let r = RegGetValueW(
            root,
            k.as_ptr(),
            np,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        );
        if r != ERROR_SUCCESS || len > 64 * 1024 {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
        let mut len = (buf.len() * 2) as u32;
        let r = RegGetValueW(
            root,
            k.as_ptr(),
            np,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        );
        if r != ERROR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

pub fn policy_values() -> PolicyValues {
    let mut v = PolicyValues::default();
    for (i, (root, key)) in POLICY_SOURCES.iter().enumerate() {
        v.disable_clip[i] = reg_dword(hkey(*root), key, "fDisableClip");
        v.disable_cdm[i] = reg_dword(hkey(*root), key, "fDisableCdm");
    }
    v
}

pub fn os_version() -> OsVersion {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let m = HKEY_LOCAL_MACHINE;
    let build = reg_string(m, KEY, "CurrentBuildNumber")
        .and_then(|b| b.trim().parse().ok())
        .unwrap_or(0);
    let installation_type = reg_string(m, KEY, "InstallationType").unwrap_or_default();
    let product = reg_string(m, KEY, "ProductName").unwrap_or_default();
    OsVersion {
        major: reg_dword(m, KEY, "CurrentMajorVersionNumber").unwrap_or(0),
        minor: reg_dword(m, KEY, "CurrentMinorVersionNumber").unwrap_or(0),
        build,
        ubr: reg_dword(m, KEY, "UBR").unwrap_or(0),
        product_name: info::fix_product_name(&product, build, &installation_type),
        display_version: reg_string(m, KEY, "DisplayVersion").unwrap_or_default(),
        installation_type,
    }
}

/// `WTSIsRemoteSession` for this session.
pub fn is_remote_session() -> Option<bool> {
    let mut buf: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: WTS allocates the buffer; freed below.
    unsafe {
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSIsRemoteSession,
            &mut buf,
            &mut len,
        ) == 0
            || buf.is_null()
        {
            return None;
        }
        let v = (len >= 1).then(|| *(buf as *const u8) != 0);
        WTSFreeMemory(buf.cast());
        v
    }
}

/// `(state is WTSActive, locked)` from `WTSSessionInfoEx`.
pub fn session_state() -> Option<(bool, Option<bool>)> {
    let mut buf: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: WTS allocates a WTSINFOEXW; length checked before reading.
    unsafe {
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buf,
            &mut len,
        ) == 0
            || buf.is_null()
        {
            return None;
        }
        let out = (len as usize >= size_of::<WTSINFOEXW>()).then(|| {
            let info = &*(buf as *const WTSINFOEXW);
            if info.Level != 1 {
                return (false, None);
            }
            let l1 = info.Data.WTSInfoExLevel1;
            (
                l1.SessionState == WTSActive,
                info::locked_from_session_flags(l1.SessionFlags),
            )
        });
        WTSFreeMemory(buf.cast());
        out
    }
}

/// Whether a client is attached over RDP right now.
pub fn remote_connected() -> bool {
    is_remote_session() == Some(true) && session_state().is_some_and(|(active, _)| active)
}

/// Image names of the processes in a session.
pub fn session_processes(session: u32) -> Vec<String> {
    let mut list: *mut WTS_PROCESS_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    let mut out = Vec::new();
    // SAFETY: WTS allocates `count` entries; freed below.
    unsafe {
        if WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut count) == 0
            || list.is_null()
        {
            return out;
        }
        for p in std::slice::from_raw_parts(list, count as usize) {
            if p.SessionId == session && !p.pProcessName.is_null() {
                out.push(from_wide_ptr(p.pProcessName));
            }
        }
        WTSFreeMemory(list.cast());
    }
    out
}

fn ft(f: FILETIME) -> u64 {
    (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)
}

pub fn cpu_times() -> Option<CpuTimes> {
    let z = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut i, mut k, mut u) = (z, z, z);
    // SAFETY: three out FILETIMEs.
    (unsafe { GetSystemTimes(&mut i, &mut k, &mut u) } != 0).then(|| CpuTimes {
        idle: ft(i),
        kernel: ft(k),
        user: ft(u),
    })
}

pub fn memory() -> Option<Memory> {
    // SAFETY: dwLength set as the API requires.
    let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    (unsafe { GlobalMemoryStatusEx(&mut m) } != 0).then_some(Memory {
        total_bytes: m.ullTotalPhys,
        available_bytes: m.ullAvailPhys,
        load_percent: m.dwMemoryLoad,
    })
}

pub fn idle_ms() -> Option<u64> {
    let mut li = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: cbSize set.
    if unsafe { GetLastInputInfo(&mut li) } == 0 {
        return None;
    }
    // SAFETY: plain call.
    Some(info::idle_ms(unsafe { GetTickCount() }, li.dwTime))
}

/// The parts that change rarely: read when `Remora::Ctl` opens.
#[derive(Debug, Clone)]
pub struct StaticInfo {
    pub os: OsVersion,
    pub kind: SessionKind,
    pub policy: info::PolicyFlags,
}

pub fn static_info() -> StaticInfo {
    StaticInfo {
        os: os_version(),
        kind: info::classify_session(
            is_remote_session(),
            &session_processes(current_session_id()),
        ),
        policy: info::decide_policy(&policy_values()),
    }
}

/// A full snapshot; `cpu_prev` carries the previous CPU sample.
pub fn collect(s: &StaticInfo, cpu_prev: &mut Option<CpuTimes>) -> SessionInfo {
    let cur = cpu_times();
    let cpu_percent = match (*cpu_prev, cur) {
        (Some(p), Some(c)) => info::cpu_percent(p, c),
        _ => None,
    };
    *cpu_prev = cur;
    SessionInfo {
        agent_version: env!("CARGO_PKG_VERSION"),
        os: s.os.clone(),
        kind: s.kind,
        policy: s.policy,
        locked: session_state().and_then(|(_, l)| l),
        idle_ms: idle_ms(),
        cpu_percent,
        memory: memory(),
    }
}
