//! Subcommands that change or inspect the user's setup: the scheduled task,
//! the link registration, `open-url`, `session-info`. Each change has a
//! `--dry-run` that prints the plan and touches nothing.

use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RegDeleteKeyValueW, RegDeleteTreeW,
    RegSetKeyValueW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};

use super::pipe::{self, ForwardResult};
use super::{sys, wide};
use crate::links::{self, RegOp};
use crate::task::{self, TaskSpec, TaskStatus};
use crate::{info, warn};

/// schtasks gets this long before it is stopped.
const SCHTASKS_TIMEOUT: Duration = Duration::from_secs(30);
/// No console window for child processes of this GUI program.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn this_exe() -> io::Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

fn task_spec() -> io::Result<TaskSpec> {
    let (sid, account) = sys::current_user()?;
    Ok(TaskSpec {
        exe: this_exe()?,
        user_sid: sid,
        user_account: account,
        agent_version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// `%SystemRoot%\System32\schtasks.exe` by absolute path (never via PATH).
fn schtasks_exe() -> io::Result<PathBuf> {
    let mut buf = [0u16; 260];
    // SAFETY: buffer and its length.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])).join("schtasks.exe"))
}

/// Runs schtasks with a timeout; returns (exit code, stdout, stderr).
fn schtasks(args: &[String]) -> io::Result<(Option<i32>, Vec<u8>, Vec<u8>)> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    let mut child = Command::new(schtasks_exe()?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = o.take(1 << 20).read_to_end(&mut v);
        }
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(e) = err.as_mut() {
            let _ = e.take(1 << 16).read_to_end(&mut v);
        }
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > SCHTASKS_TIMEOUT {
            // Our own child, by handle.
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "schtasks timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = out_t.join().unwrap_or_default();
    let err = err_t.join().unwrap_or_default();
    Ok((status.code(), out, err))
}

fn report(r: io::Result<(Option<i32>, Vec<u8>, Vec<u8>)>, what: &str) -> i32 {
    match r {
        Ok((Some(0), _, _)) => {
            println!("{what}: done");
            0
        }
        Ok((code, out, err)) => {
            eprintln!(
                "{what}: schtasks failed ({code:?}): {}{}",
                task::decode_output(&out).trim(),
                task::decode_output(&err).trim()
            );
            1
        }
        Err(e) => {
            eprintln!("{what}: {e}");
            1
        }
    }
}

pub fn print_task_xml() -> i32 {
    match task_spec() {
        Ok(s) => {
            print!("{}", task::task_xml(&s));
            0
        }
        Err(e) => {
            eprintln!("cannot read the current user: {e}");
            1
        }
    }
}

pub fn install(dry_run: bool) -> i32 {
    let spec = match task_spec() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read the current user: {e}");
            return 1;
        }
    };
    let name = task::task_name(&spec.user_sid);
    let Some(dir) = crate::logging::default_log_path()
        .and_then(|p| p.parent().and_then(|p| p.parent()).map(|p| p.to_path_buf()))
    else {
        eprintln!("LOCALAPPDATA is not set");
        return 1;
    };
    let xml_path = dir.join("remora-agent-task.xml");
    let args = task::create_args(&name, &xml_path.to_string_lossy());
    if dry_run {
        println!("Would write {} (UTF-16) with:\n", xml_path.display());
        print!("{}", task::task_xml(&spec));
        println!("\nWould run: schtasks.exe {}", args.join(" "));
        return 0;
    }
    let write = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(&xml_path, task::utf16_with_bom(&task::task_xml(&spec))));
    if let Err(e) = write {
        eprintln!("cannot write {}: {e}", xml_path.display());
        return 1;
    }
    let code = report(schtasks(&args), "install");
    let _ = std::fs::remove_file(&xml_path);
    if code == 0 {
        info!("scheduled task installed");
        println!("The agent now starts at logon and when a client reconnects.");
    }
    code
}

pub fn uninstall(dry_run: bool) -> i32 {
    let (sid, _) = match sys::current_user() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("cannot read the current user: {e}");
            return 1;
        }
    };
    let args = task::delete_args(&task::task_name(&sid));
    if dry_run {
        println!("Would run: schtasks.exe {}", args.join(" "));
        return unregister_links(true);
    }
    let task_code = match schtasks(&args) {
        // Exit code 1: no such task; nothing to remove.
        Ok((Some(0 | 1), _, _)) => {
            println!("task: removed (or was not installed)");
            0
        }
        other => report(other, "task removal"),
    };
    let links_code = unregister_links(false);
    task_code.max(links_code)
}

pub fn status() -> i32 {
    let (sid, exe) = match (sys::current_user(), this_exe()) {
        (Ok((sid, _)), Ok(exe)) => (sid, exe),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let st = match schtasks(&task::query_args(&task::task_name(&sid))) {
        Ok((code, out, _)) => task::parse_query(code, &out, &exe),
        Err(e) => TaskStatus::Unknown(e.to_string()),
    };
    match st {
        TaskStatus::NotInstalled => println!("Scheduled task: not installed"),
        TaskStatus::Installed {
            enabled,
            points_here,
            command,
        } => {
            println!(
                "Scheduled task: installed, {}",
                if enabled { "enabled" } else { "disabled" }
            );
            if !points_here {
                println!("  It starts {command}, not this program.");
            }
        }
        TaskStatus::Unknown(why) => println!("Scheduled task: unknown ({why})"),
    }
    0
}

/// The browser that is the https default now, if it can be the fallback.
fn capture_fallback(own_exe: &str) -> Option<String> {
    let hkcu = HKEY_CURRENT_USER;
    let choice = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice";
    let prog_id = sys::reg_string(hkcu, choice, "ProgId")?;
    if prog_id == links::PROG_ID {
        // Already us: keep the browser captured earlier.
        return sys::reg_string(hkcu, links::AGENT_KEY, links::FALLBACK_VALUE)
            .filter(|c| links::usable_fallback(c, own_exe).is_some());
    }
    let key = format!(r"Software\Classes\{prog_id}\shell\open\command");
    let cmd = sys::reg_string(hkcu, &key, "")
        .or_else(|| sys::reg_string(HKEY_LOCAL_MACHINE, &key, ""))?;
    links::usable_fallback(&cmd, own_exe).map(|_| cmd)
}

fn apply_reg(ops: &[RegOp]) -> io::Result<()> {
    for op in ops {
        // SAFETY: registry calls on HKCU with NUL-terminated strings.
        let r = unsafe {
            match op {
                RegOp::SetString { key, name, value } => {
                    let k = wide(key);
                    let n = name.as_deref().map(wide);
                    let v = wide(value);
                    RegSetKeyValueW(
                        HKEY_CURRENT_USER,
                        k.as_ptr(),
                        n.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                        REG_SZ,
                        v.as_ptr().cast(),
                        (v.len() * 2) as u32,
                    )
                }
                RegOp::DeleteTree { key } => {
                    let k = wide(key);
                    match RegDeleteTreeW(HKEY_CURRENT_USER, k.as_ptr()) {
                        2 => ERROR_SUCCESS, // ERROR_FILE_NOT_FOUND: already gone
                        r => r,
                    }
                }
                RegOp::DeleteValue { key, name } => {
                    let (k, n) = (wide(key), wide(name));
                    match RegDeleteKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), n.as_ptr()) {
                        2 => ERROR_SUCCESS,
                        r => r,
                    }
                }
            }
        };
        if r != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
    }
    // SAFETY: tells Explorer and Settings that associations changed.
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED as i32,
            SHCNF_IDLIST,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    Ok(())
}

fn print_plan(ops: &[RegOp]) {
    for op in ops {
        println!("  {op}");
    }
}

pub fn register_links(dry_run: bool) -> i32 {
    let exe = match this_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let fallback = capture_fallback(&exe);
    let ops = links::register_plan(&exe, fallback.as_deref());
    if dry_run {
        println!("Would change (HKEY_CURRENT_USER only):");
        print_plan(&ops);
        return 0;
    }
    match apply_reg(&ops) {
        Ok(()) => {
            info!(
                "registered for links (fallback browser: {})",
                fallback.is_some()
            );
            println!(
                "Registered. Pick \"{}\" for HTTP and HTTPS in Settings > Apps > Default apps.",
                links::APP_NAME
            );
            if fallback.is_none() {
                println!(
                    "No current browser was found to fall back to when Remora is not connected."
                );
            }
            0
        }
        Err(e) => {
            eprintln!("registration failed: {e}");
            1
        }
    }
}

pub fn unregister_links(dry_run: bool) -> i32 {
    let ops = links::unregister_plan();
    if dry_run {
        println!("Would change (HKEY_CURRENT_USER only):");
        print_plan(&ops);
        return 0;
    }
    match apply_reg(&ops) {
        Ok(()) => {
            println!("links: unregistered");
            0
        }
        Err(e) => {
            eprintln!("links: unregistration failed: {e}");
            1
        }
    }
}

/// `open-url <url>`: forward to the agent, or open the fallback browser.
pub fn open_url(raw: &str) -> i32 {
    let url = match links::validate_url(raw) {
        Ok(u) => u,
        Err(e) => {
            warn!("open-url: refused: {e}");
            return 2;
        }
    };
    match pipe::forward(&url) {
        Ok(ForwardResult::Forwarded) => {
            info!("open-url: forwarded ({} bytes)", url.len());
            return 0;
        }
        Ok(r) => info!("open-url: not forwarded ({r:?})"),
        Err(e) => warn!("open-url: pipe error: {e}"),
    }
    let exe = this_exe().unwrap_or_default();
    let fallback = sys::reg_string(HKEY_CURRENT_USER, links::AGENT_KEY, links::FALLBACK_VALUE)
        .and_then(|c| links::usable_fallback(&c, &exe));
    let Some(cmd) = fallback else {
        warn!("open-url: no Remora client and no fallback browser; link dropped");
        return 3;
    };
    use std::os::windows::process::CommandExt;
    // CreateProcess with an argument vector: no shell, the URL is one
    // argument (it has no spaces or quotes after validation).
    match Command::new(&cmd.exe)
        .args(links::fallback_args(&cmd, &url))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(_) => {
            info!("open-url: opened in the fallback browser");
            0
        }
        Err(e) => {
            warn!("open-url: fallback browser failed: {e}");
            3
        }
    }
}

pub fn print_session_info() -> i32 {
    let s = sys::static_info();
    let mut prev = sys::cpu_times();
    std::thread::sleep(Duration::from_millis(250));
    let info = sys::collect(&s, &mut prev);
    println!("{info:#?}");
    println!("remote-connected: {}", sys::remote_connected());
    println!(
        "file transfer: {}",
        if info.policy.file_transfer_disabled() {
            "disabled by policy"
        } else {
            "allowed"
        }
    );
    0
}
