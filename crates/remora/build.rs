//! Embeds the app icon (`assets/remora.ico`) in the Windows executable,
//! so Explorer, pinned taskbar buttons and shortcuts show the Remora logo.
//!
//! Writes a compiled resource file (`.res`) directly and hands it to the
//! linker. Both `link.exe` and `rust-lld` take `.res` input, so this needs
//! no resource compiler and no extra crate. Other targets do nothing.

use std::path::PathBuf;

fn main() {
    let ico = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("../../assets/remora.ico");
    println!("cargo:rerun-if-changed={}", ico.display());
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|v| v == "windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|v| v == "msvc");
    if !(windows && msvc) {
        return;
    }
    let data = match std::fs::read(&ico) {
        Ok(d) => d,
        Err(e) => {
            println!(
                "cargo:warning=no app icon embedded: cannot read {}: {e}",
                ico.display()
            );
            return;
        }
    };
    let res = match icon_res(&data) {
        Some(r) => r,
        None => {
            println!(
                "cargo:warning=no app icon embedded: {} is not a valid .ico",
                ico.display()
            );
            return;
        }
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("remora-icon.res");
    if let Err(e) = std::fs::write(&out, res) {
        println!(
            "cargo:warning=no app icon embedded: cannot write {}: {e}",
            out.display()
        );
        return;
    }
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
/// MOVEABLE | PURE | DISCARDABLE, as resource compilers write for icons.
const FLAGS: u16 = 0x1010 | 0x0020;
const LANG_EN_US: u16 = 0x0409;

/// One resource entry with a numeric type and name.
fn entry(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, lang: u16, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&32u32.to_le_bytes()); // header size
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // data version
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&lang.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // version
    out.extend_from_slice(&0u32.to_le_bytes()); // characteristics
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A `.res` with every image of the `.ico` as RT_ICON 1..n and the group
/// as RT_GROUP_ICON 1 (the lowest id, which Windows takes as the app icon).
fn icon_res(ico: &[u8]) -> Option<Vec<u8>> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(ico.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(ico.get(o..o + 4)?.try_into().ok()?));
    if u16_at(0)? != 0 || u16_at(2)? != 1 {
        return None;
    }
    let n = u16_at(4)? as usize;
    if n == 0 || n > 64 {
        return None;
    }
    let mut res = Vec::new();
    // The empty first entry every .res starts with.
    entry(&mut res, 0, 0, 0, 0, &[]);
    let mut group = Vec::with_capacity(6 + 14 * n);
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&(n as u16).to_le_bytes());
    for i in 0..n {
        let d = 6 + 16 * i;
        let dir = ico.get(d..d + 16)?;
        let (size, offset) = (u32_at(d + 8)? as usize, u32_at(d + 12)? as usize);
        let image = ico.get(offset..offset.checked_add(size)?)?;
        let id = i as u16 + 1;
        entry(&mut res, RT_ICON, id, FLAGS, LANG_EN_US, image);
        // GRPICONDIRENTRY: the directory entry with the id for the offset.
        group.extend_from_slice(&dir[..12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    entry(&mut res, RT_GROUP_ICON, 1, 0x1030, LANG_EN_US, &group);
    Some(res)
}
