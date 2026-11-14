//! The notification-area icon on the server (RDP-48): the Remora icon with
//! a status dot, a tooltip, a right-click menu and balloon notes. It lives
//! on the session window's thread; the event loop hands it the status
//! through [`TrayFeed`] and posts [`WM_TRAY_STATUS`]. Without a shell
//! (Server Core) adding the icon fails and the helper runs without one.
//! What it shows and offers is [`crate::tray`].

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject, GetDC, GetDIBits, HBITMAP, ReleaseDC,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIIF_RESPECT_QUIET_TIME,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICON_VERSION_4,
    NOTIFYICONDATAW, Shell_NotifyIconW, ShellExecuteW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, DestroyIcon, DestroyMenu, GetCursorPos,
    GetIconInfo, GetSystemMetrics, HICON, HMENU, ICONINFO, IDYES, IMAGE_ICON, LR_DEFAULTCOLOR,
    LoadImageW, MB_ICONQUESTION, MB_YESNO, MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR,
    MF_STRING, MessageBoxW, PostMessageW, SM_CXSMICON, SW_SHOWNORMAL, SetForegroundWindow,
    TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, WM_APP, WM_CONTEXTMENU, WM_NULL,
    WM_RBUTTONUP,
};

use super::agent::Input;
use super::wide;
use crate::seam::{AgentStatus, Notice};
use crate::tray::{self, Cmd, Dot, Entry, MenuModel, Strict};
use crate::{clients, info, keystore, warn};

/// The icon's callback message (mouse and keyboard on the icon).
pub const WM_TRAY: u32 = WM_APP + 1;
/// The event loop changed [`TrayFeed`].
pub const WM_TRAY_STATUS: u32 = WM_APP + 2;
const ICON_ID: u32 = 1;
/// `CF_UNICODETEXT`.
const CF_UNICODETEXT: u32 = 13;
/// `NIN_KEYSELECT` (`NIN_SELECT | NINF_KEY`): the icon chosen by keyboard.
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;

/// What the event loop hands the tray: the latest status and the notices
/// not shown yet.
#[derive(Default)]
pub struct TrayFeed {
    pub status: AgentStatus,
    pub notices: Vec<Notice>,
}

pub type SharedFeed = Arc<Mutex<TrayFeed>>;

pub struct Tray {
    hwnd: HWND,
    /// One icon per [`Dot`]; null where it could not be made.
    icons: [HICON; 3],
    added: bool,
    /// Adding failed once (no shell): logged once, retried on
    /// `TaskbarCreated` only.
    failed: bool,
    status: AgentStatus,
    fingerprint: String,
}

impl Tray {
    pub fn new(hwnd: HWND, fingerprint: String) -> Tray {
        let mut t = Tray {
            hwnd,
            icons: make_icons(),
            added: false,
            failed: false,
            status: AgentStatus::default(),
            fingerprint,
        };
        t.add();
        t
    }

    fn data(&self) -> NOTIFYICONDATAW {
        let mut d = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uID: ICON_ID,
            ..Default::default()
        };
        d.hIcon = self.icons[tray::dot(self.status.phase).index()];
        fill(&mut d.szTip, &tray::tooltip(&self.status));
        d
    }

    /// Adds the icon (at start and after Explorer restarted).
    pub fn add(&mut self) {
        let mut d = self.data();
        d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        d.uCallbackMessage = WM_TRAY;
        // SAFETY: a filled NOTIFYICONDATAW for our window.
        let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &d) } != 0;
        if !ok {
            if !self.failed {
                info!("no notification area (no shell?); the helper runs without a tray icon");
            }
            self.failed = true;
            self.added = false;
            return;
        }
        d.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_SETVERSION, &d) };
        self.added = true;
        self.failed = false;
    }

    /// Explorer started again: its new taskbar has no icons.
    pub fn taskbar_created(&mut self) {
        self.added = false;
        self.add();
    }

    pub fn set_status(&mut self, status: AgentStatus) {
        if status == self.status {
            return;
        }
        self.status = status;
        if self.added {
            let mut d = self.data();
            d.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
            // SAFETY: as above.
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
        }
    }

    pub fn notify(&self, n: &Notice) {
        if !self.added {
            return;
        }
        let (title, text) = tray::notice_text(n);
        let mut d = self.data();
        d.uFlags = NIF_INFO;
        d.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
        fill(&mut d.szInfoTitle, &title);
        fill(&mut d.szInfo, &text);
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
    }

    pub fn remove(&mut self) {
        if self.added {
            let d = self.data();
            // SAFETY: as above.
            unsafe { Shell_NotifyIconW(NIM_DELETE, &d) };
            self.added = false;
        }
    }

    /// The callback's event (`LOWORD(lParam)` with version 4) opens the menu
    /// for a right click, a left click or the keyboard.
    pub fn wants_menu(event: u32) -> bool {
        matches!(
            event,
            WM_CONTEXTMENU | WM_RBUTTONUP | NIN_SELECT | NIN_KEYSELECT
        )
    }

    /// Shows the menu and runs the choice. Runs a modal loop: the caller
    /// must not hold any borrow the window procedure needs.
    pub fn show_menu(&mut self, tx: &Sender<Input>) {
        let model = menu_model(self.status.clone(), self.fingerprint.clone());
        let entries = tray::menu(&model);
        // SAFETY: a popup menu we build, track and destroy here.
        let choice = unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            append(menu, &entries);
            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            // The menu closes on a click elsewhere only when our window is
            // in the foreground (documented TrackPopupMenu caveat).
            SetForegroundWindow(self.hwnd);
            let id = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                pt.x,
                pt.y,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);
            id as u32
        };
        if let Some(cmd) = Cmd::from_id(choice, model.paired.len()) {
            self.run(cmd, &model, tx);
        }
    }

    fn run(&self, cmd: Cmd, model: &MenuModel, tx: &Sender<Input>) {
        match cmd {
            Cmd::OpenReceived => match super::files::receive_folder() {
                Some(dir) => {
                    let _ = std::fs::create_dir_all(&dir);
                    explorer(self.hwnd, &format!("\"{}\"", dir.display()));
                }
                None => warn!("tray: no Downloads folder"),
            },
            Cmd::OpenLog => {
                if let Some(log) = crate::logging::default_log_path() {
                    let arg = if log.exists() {
                        format!("/select,\"{}\"", log.display())
                    } else {
                        let dir = log.parent().unwrap_or(&log);
                        let _ = std::fs::create_dir_all(dir);
                        format!("\"{}\"", dir.display())
                    };
                    explorer(self.hwnd, &arg);
                }
            }
            Cmd::CopyFingerprint => {
                if !copy_text(self.hwnd, &model.fingerprint) {
                    warn!("tray: the fingerprint could not be copied");
                }
            }
            Cmd::Forget(i) => {
                let Some(pc) = model.paired.get(i) else {
                    return;
                };
                let name = if pc.label.is_empty() {
                    "this Remora PC"
                } else {
                    &pc.label
                };
                let q = format!(
                    "Forget {name} ({})?\n\nIt has to pair again (compare the code here) \
                     before it gets files or links.",
                    pc.fingerprint
                );
                if ask(self.hwnd, &q)
                    && let Some(path) = keystore::default_clients_path()
                {
                    match clients::forget(&path, &pc.fingerprint) {
                        Ok(msg) => info!("tray: {msg}"),
                        Err(e) => warn!("tray: forget failed: {e}"),
                    }
                }
            }
            Cmd::ToggleStrict => {
                let (Some(setting), clients) = (
                    keystore::default_strict_path(),
                    keystore::default_clients_path(),
                ) else {
                    return;
                };
                let r = clients::set_strict(
                    !model.strict.user_on,
                    &setting,
                    super::sys::pinned_clients_policy(),
                    clients.as_deref(),
                );
                match r {
                    Ok(msg) => info!("tray: {}", msg.trim_end()),
                    Err(e) => warn!("tray: strict switch failed: {e}"),
                }
            }
            Cmd::Quit => {
                let q = "Quit the Remora helper?\n\nRemora loses session info, links and \
                         file transfer for this session. The helper starts again at your \
                         next logon or reconnect.";
                if ask(self.hwnd, q) {
                    info!("tray: quit");
                    let _ = tx.send(Input::Shutdown { done: None });
                }
            }
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.remove();
        for icon in self.icons {
            if !icon.is_null() {
                // SAFETY: icons we created.
                unsafe { DestroyIcon(icon) };
            }
        }
    }
}

/// The menu's data, read fresh each time it opens (other processes such as
/// `remora-agent forget-client` change the stores).
fn menu_model(status: AgentStatus, fingerprint: String) -> MenuModel {
    let clients_path = keystore::default_clients_path();
    let paired = clients_path
        .as_deref()
        .map(clients::paired)
        .unwrap_or_default();
    let strict = Strict {
        user_on: keystore::default_strict_path()
            .as_deref()
            .is_some_and(clients::user_strict),
        forced: clients::forced_strict(
            super::sys::pinned_clients_policy(),
            clients_path.as_deref(),
        )
        .map(short_reason),
    };
    MenuModel {
        status,
        strict,
        paired,
        fingerprint,
    }
}

/// The menu's word for why pinned PCs only is forced on.
fn short_reason(why: &str) -> String {
    if why.contains("policy") {
        "set by policy".into()
    } else {
        "a PC was trusted by fingerprint".into()
    }
}

/// Appends `entries` to `menu` (submenus recursively).
///
/// # Safety
/// `menu` must be a valid menu handle.
unsafe fn append(menu: HMENU, entries: &[Entry]) {
    for e in entries {
        match e {
            Entry::Label(text) => {
                let w = wide(&menu_text(text));
                // SAFETY: valid menu, NUL-terminated text.
                unsafe { AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, w.as_ptr()) };
            }
            Entry::Separator => {
                // SAFETY: valid menu.
                unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null()) };
            }
            Entry::Item {
                label,
                cmd,
                checked,
                enabled,
            } => {
                let mut flags = MF_STRING;
                if *checked {
                    flags |= MF_CHECKED;
                }
                if !enabled {
                    flags |= MF_GRAYED;
                }
                let w = wide(&menu_text(label));
                // SAFETY: valid menu, NUL-terminated text.
                unsafe { AppendMenuW(menu, flags, cmd.id() as usize, w.as_ptr()) };
            }
            Entry::Submenu { label, entries } => {
                // SAFETY: a new popup that the parent menu owns once appended.
                unsafe {
                    let sub = CreatePopupMenu();
                    if sub.is_null() {
                        continue;
                    }
                    append(sub, entries);
                    let w = wide(&menu_text(label));
                    AppendMenuW(menu, MF_STRING | MF_POPUP, sub as usize, w.as_ptr());
                }
            }
        }
    }
}

/// Menu text with `&` shown literally (it marks the access key otherwise).
fn menu_text(s: &str) -> String {
    s.replace('&', "&&")
}

/// Copies `s` into the fixed-size, NUL-terminated `buf`.
fn fill(buf: &mut [u16], s: &str) {
    let max = buf.len() - 1;
    let units: Vec<u16> = tray::clip_utf16(s, max).encode_utf16().collect();
    buf[..units.len()].copy_from_slice(&units);
    buf[units.len()] = 0;
}

fn explorer(hwnd: HWND, args: &str) {
    let (verb, exe, params) = (wide("open"), wide("explorer.exe"), wide(args));
    // SAFETY: NUL-terminated strings that outlive the call.
    let r = unsafe {
        ShellExecuteW(
            hwnd,
            verb.as_ptr(),
            exe.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (r as usize) <= 32 {
        warn!("tray: Explorer did not start (code {})", r as usize);
    }
}

fn ask(hwnd: HWND, text: &str) -> bool {
    let (t, c) = (wide(text), wide("Remora helper"));
    // SAFETY: NUL-terminated strings; a modal box on our thread.
    unsafe { MessageBoxW(hwnd, t.as_ptr(), c.as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

fn copy_text(hwnd: HWND, s: &str) -> bool {
    let w = wide(s);
    let bytes = w.len() * 2;
    // SAFETY: the clipboard protocol: open, empty, hand over a moveable
    // global block (the clipboard owns it on success), close.
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return false;
        }
        EmptyClipboard();
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        let mut ok = false;
        if !mem.is_null() {
            let p = GlobalLock(mem) as *mut u16;
            if !p.is_null() {
                std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
                GlobalUnlock(mem);
                ok = !SetClipboardData(CF_UNICODETEXT, mem).is_null();
            }
            if !ok {
                windows_sys::Win32::Foundation::GlobalFree(mem);
            }
        }
        CloseClipboard();
        ok
    }
}

/// The Remora icon at the small icon size, once per status dot.
fn make_icons() -> [HICON; 3] {
    // SAFETY: plain call.
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) }.clamp(16, 64);
    // SAFETY: the exe's own icon group (resource 1, see build.rs).
    let base = unsafe {
        LoadImageW(
            GetModuleHandleW(std::ptr::null()),
            // MAKEINTRESOURCEW(1): an integer id in the pointer.
            std::ptr::without_provenance::<u16>(1),
            IMAGE_ICON,
            size,
            size,
            LR_DEFAULTCOLOR,
        )
    } as HICON;
    if base.is_null() {
        warn!("tray: no embedded icon");
        return [std::ptr::null_mut(); 3];
    }
    let icons = Dot::ALL.map(|d| {
        // SAFETY: a valid icon of `size` pixels.
        unsafe { with_dot(base, size, d.argb()) }.unwrap_or(std::ptr::null_mut())
    });
    // SAFETY: our loaded copy; the dotted icons are separate.
    unsafe { DestroyIcon(base) };
    icons
}

/// A copy of `base` with the status dot painted in.
///
/// # Safety
/// `base` must be a valid icon of `size` x `size` pixels.
unsafe fn with_dot(base: HICON, size: i32, argb: u32) -> Option<HICON> {
    let n = size as usize;
    // SAFETY (whole block): GDI calls on objects created and deleted here;
    // `px` has room for size x size 32-bit pixels.
    unsafe {
        let mut ii: ICONINFO = std::mem::zeroed();
        if GetIconInfo(base, &mut ii) == 0 {
            return None;
        }
        let cleanup = |ii: &ICONINFO| {
            if !ii.hbmColor.is_null() {
                DeleteObject(ii.hbmColor);
            }
            if !ii.hbmMask.is_null() {
                DeleteObject(ii.hbmMask);
            }
        };
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = size;
        bmi.bmiHeader.biHeight = -size; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        let dc = GetDC(std::ptr::null_mut());
        let mut px = vec![0u32; n * n];
        let got = !ii.hbmColor.is_null()
            && GetDIBits(
                dc,
                ii.hbmColor,
                0,
                size as u32,
                px.as_mut_ptr().cast(),
                &mut bmi,
                DIB_RGB_COLORS,
            ) != 0;
        if got && px.iter().all(|p| p >> 24 == 0) {
            // An icon without alpha: opaque where its mask is black.
            let mut mask = vec![0u32; n * n];
            let mut mbmi = bmi;
            if GetDIBits(
                dc,
                ii.hbmMask,
                0,
                size as u32,
                mask.as_mut_ptr().cast(),
                &mut mbmi,
                DIB_RGB_COLORS,
            ) != 0
            {
                for (p, m) in px.iter_mut().zip(&mask) {
                    if m & 0x00FF_FFFF == 0 {
                        *p |= 0xFF00_0000;
                    }
                }
            }
        }
        if !got {
            ReleaseDC(std::ptr::null_mut(), dc);
            cleanup(&ii);
            return None;
        }
        tray::paint_dot(&mut px, n, argb);
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let color: HBITMAP =
            CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        ReleaseDC(std::ptr::null_mut(), dc);
        cleanup(&ii);
        if color.is_null() || bits.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(px.as_ptr(), bits.cast::<u32>(), n * n);
        // An all-zero mask: the colour bitmap's alpha decides.
        let stride = n.div_ceil(16) * 2;
        let zeros = vec![0u8; stride * n];
        let mask = CreateBitmap(size, size, 1, 1, zeros.as_ptr().cast());
        let info = ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        };
        let icon = CreateIconIndirect(&info);
        DeleteObject(color);
        if !mask.is_null() {
            DeleteObject(mask);
        }
        (!icon.is_null()).then_some(icon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory icon of one colour (ARGB), `size` x `size`.
    unsafe fn solid_icon(size: i32, argb: u32) -> HICON {
        let n = size as usize;
        // SAFETY: GDI objects made and handed to the icon here.
        unsafe {
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = size;
            bmi.bmiHeader.biHeight = -size;
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;
            let dc = GetDC(std::ptr::null_mut());
            let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
            let color =
                CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
            ReleaseDC(std::ptr::null_mut(), dc);
            std::slice::from_raw_parts_mut(bits.cast::<u32>(), n * n).fill(argb);
            let zeros = vec![0u8; n.div_ceil(16) * 2 * n];
            let mask = CreateBitmap(size, size, 1, 1, zeros.as_ptr().cast());
            let icon = CreateIconIndirect(&ICONINFO {
                fIcon: 1,
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: mask,
                hbmColor: color,
            });
            DeleteObject(color);
            DeleteObject(mask);
            icon
        }
    }

    /// The icon's pixels (ARGB, top-down).
    unsafe fn pixels(icon: HICON, size: i32) -> Vec<u32> {
        let n = size as usize;
        // SAFETY: GDI reads into a buffer of the right size.
        unsafe {
            let mut ii: ICONINFO = std::mem::zeroed();
            assert_ne!(GetIconInfo(icon, &mut ii), 0);
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = size;
            bmi.bmiHeader.biHeight = -size;
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;
            let dc = GetDC(std::ptr::null_mut());
            let mut px = vec![0u32; n * n];
            GetDIBits(
                dc,
                ii.hbmColor,
                0,
                size as u32,
                px.as_mut_ptr().cast(),
                &mut bmi,
                DIB_RGB_COLORS,
            );
            ReleaseDC(std::ptr::null_mut(), dc);
            DeleteObject(ii.hbmColor);
            DeleteObject(ii.hbmMask);
            px
        }
    }

    #[test]
    fn the_dot_is_drawn_into_a_copy_of_the_icon_with_alpha_kept() {
        let size = 16;
        let blue = 0xFF20_40C0;
        // SAFETY: icons made and destroyed in this test; no window.
        unsafe {
            let base = solid_icon(size, blue);
            assert!(!base.is_null());
            let dotted = with_dot(base, size, Dot::Green.argb()).expect("an icon");
            let px = pixels(dotted, size);
            assert_eq!(px[0], blue, "the icon itself is unchanged and opaque");
            let r = (size as f32 * 0.22).max(3.0);
            let c = (size as f32 - r - 0.5) as usize;
            assert_eq!(px[c * 16 + c], Dot::Green.argb(), "the dot, opaque");
            // The base icon is left alone.
            assert_eq!(pixels(base, size)[c * 16 + c], blue);
            DestroyIcon(dotted);
            DestroyIcon(base);
        }
    }

    #[test]
    fn tray_text_fits_its_buffer() {
        let mut tip = [0u16; 128];
        fill(&mut tip, &"y".repeat(500));
        let end = tip.iter().position(|&u| u == 0).expect("NUL-terminated");
        assert_eq!(end, 127);
        assert_eq!(menu_text("Tom & Jerry"), "Tom && Jerry");
    }
}
