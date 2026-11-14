//! Windows resources for `remora-agent.exe`: the Remora icon, a version
//! resource (Explorer's Details tab, AppLocker publisher/version rules) and
//! an `asInvoker` manifest (never elevates; declares Windows 10/11 so
//! version APIs are not shimmed).
//!
//! Like `crates/remora/build.rs`, it writes a compiled `.res` directly and
//! hands it to the linker (`link.exe` and `rust-lld` both take `.res`), so
//! it needs no resource compiler and no extra crate.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let ico = dir.join("../../assets/remora.ico");
    println!("cargo:rerun-if-changed={}", ico.display());
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|v| v == "windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|v| v == "msvc");
    if !(windows && msvc) {
        return;
    }
    let mut res = Vec::new();
    // The empty first entry every .res starts with.
    entry(&mut res, 0, 0, 0, 0, &[]);
    match std::fs::read(&ico)
        .ok()
        .and_then(|d| icon_entries(&mut res, &d))
    {
        Some(()) => {}
        None => println!(
            "cargo:warning=no icon embedded: cannot use {}",
            ico.display()
        ),
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    entry(
        &mut res,
        RT_VERSION,
        1,
        0x0030,
        LANG_EN_US,
        &version_info(&version),
    );
    entry(
        &mut res,
        RT_MANIFEST,
        1,
        0x0030,
        LANG_EN_US,
        MANIFEST.as_bytes(),
    );
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("remora-agent.res");
    if let Err(e) = std::fs::write(&out, res) {
        println!(
            "cargo:warning=no resources embedded: cannot write {}: {e}",
            out.display()
        );
        return;
    }
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
const RT_MANIFEST: u16 = 24;
/// MOVEABLE | PURE | DISCARDABLE, as resource compilers write for icons.
const ICON_FLAGS: u16 = 0x1010 | 0x0020;
const LANG_EN_US: u16 = 0x0409;

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"#;

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
    pad4(out);
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// Every image of the `.ico` as RT_ICON 1..n and the group as
/// RT_GROUP_ICON 1 (the lowest id, which Windows takes as the app icon).
fn icon_entries(res: &mut Vec<u8>, ico: &[u8]) -> Option<()> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(ico.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(ico.get(o..o + 4)?.try_into().ok()?));
    if u16_at(0)? != 0 || u16_at(2)? != 1 {
        return None;
    }
    let n = u16_at(4)? as usize;
    if n == 0 || n > 64 {
        return None;
    }
    let mut group = Vec::with_capacity(6 + 14 * n);
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&(n as u16).to_le_bytes());
    let mut images = Vec::new();
    for i in 0..n {
        let d = 6 + 16 * i;
        let dir = ico.get(d..d + 16)?;
        let (size, offset) = (u32_at(d + 8)? as usize, u32_at(d + 12)? as usize);
        images.push(ico.get(offset..offset.checked_add(size)?)?);
        group.extend_from_slice(&dir[..12]);
        group.extend_from_slice(&(i as u16 + 1).to_le_bytes());
    }
    for (i, image) in images.into_iter().enumerate() {
        entry(res, RT_ICON, i as u16 + 1, ICON_FLAGS, LANG_EN_US, image);
    }
    entry(res, RT_GROUP_ICON, 1, 0x1030, LANG_EN_US, &group);
    Some(())
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

/// One version-resource block: `wLength`, `wValueLength`, `wType`, the
/// key, padding, the value, padding, the children (each 32-bit aligned).
/// `value_len` is in words for text values, in bytes for binary ones.
fn block(key: &str, text: bool, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend_from_slice(&value_len.to_le_bytes());
    b.extend_from_slice(&u16::from(text).to_le_bytes());
    b.extend_from_slice(&utf16z(key));
    pad4(&mut b);
    b.extend_from_slice(value);
    for c in children {
        pad4(&mut b);
        b.extend_from_slice(c);
    }
    let len = b.len() as u16;
    b[..2].copy_from_slice(&len.to_le_bytes());
    b
}

fn string(key: &str, value: &str) -> Vec<u8> {
    let v = utf16z(value);
    block(key, true, &v, (v.len() / 2) as u16, &[])
}

/// `VS_VERSIONINFO` with `VS_FIXEDFILEINFO` and English strings.
fn version_info(version: &str) -> Vec<u8> {
    // "0.1.0-beta.4" -> 0.1.0.0: numeric parts only.
    let mut nums = version
        .split(['.', '-', '+'])
        .map_while(|p| p.parse::<u16>().ok())
        .chain(std::iter::repeat(0));
    let (a, b, c) = (
        u32::from(nums.next().unwrap_or(0)),
        u32::from(nums.next().unwrap_or(0)),
        u32::from(nums.next().unwrap_or(0)),
    );
    let (ms, ls) = ((a << 16) | b, c << 16);
    let mut fixed = Vec::with_capacity(52);
    for v in [
        0xFEEF_04BDu32, // signature
        0x0001_0000,    // struct version
        ms,
        ls, // file version
        ms,
        ls,          // product version
        0x3F,        // flags mask
        0,           // flags
        0x0004_0004, // VOS_NT_WINDOWS32
        1,           // VFT_APP
        0,
        0,
        0,
    ] {
        fixed.extend_from_slice(&v.to_le_bytes());
    }
    let strings = block(
        "040904B0",
        true,
        &[],
        0,
        &[
            string("CompanyName", "rdp-rs"),
            string(
                "FileDescription",
                "Remora Agent (helper in a remote desktop session)",
            ),
            string("FileVersion", version),
            string("InternalName", "remora-agent"),
            string("LegalCopyright", "MIT OR Apache-2.0"),
            string("OriginalFilename", "remora-agent.exe"),
            string("ProductName", "Remora"),
            string("ProductVersion", version),
        ],
    );
    let string_info = block("StringFileInfo", true, &[], 0, &[strings]);
    let translation = block("Translation", false, &[0x09, 0x04, 0xB0, 0x04], 4, &[]);
    let var_info = block("VarFileInfo", true, &[], 0, &[translation]);
    block(
        "VS_VERSION_INFO",
        false,
        &fixed,
        52,
        &[string_info, var_info],
    )
}
