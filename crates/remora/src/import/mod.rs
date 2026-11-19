//! Importing connections: a Remora backup, mRemoteNG's `confCons.xml` or a
//! Remote Desktop Connection Manager (RDCMan) `.rdg` file. The format is
//! told from the content, never from the file name.
//!
//! The parsers are pure: they take the file's bytes, the password the user
//! typed (if any) and a DPAPI hook, and return groups, connections and a
//! report of what could not come over. Nothing here touches disk or the UI.

mod mremoteng;
mod rdcman;
#[cfg(test)]
mod tests;
mod xml;

use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use crate::store::{Connection, Group, Inherit};

/// Larger files are refused before parsing (real ones are kilobytes).
const MAX_FILE: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Remora,
    MRemoteNg,
    RdcMan,
}

/// What a picked file is, and whether the import needs a password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub format: Format,
    pub needs_password: bool,
}

/// Why a saved password did not come over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unreadable {
    /// DPAPI: saved by another Windows user or on another PC.
    OtherUser,
    /// RDCMan: encrypted with a certificate.
    Certificate,
    /// RDCMan: a credential profile kept in RDCMan's own settings.
    RdcmanSettings,
    /// mRemoteNG: a cipher other than AES-GCM, or a file older than 2.6.
    Cipher,
    /// The stored value does not decrypt.
    Damaged,
}

impl Unreadable {
    fn reason(self) -> &'static str {
        match self {
            Unreadable::OtherUser => "saved by another Windows user or PC",
            Unreadable::Certificate => "encrypted with a certificate",
            Unreadable::RdcmanSettings => "kept in RDCMan's own settings",
            Unreadable::Cipher => "older or non-AES encryption",
            Unreadable::Damaged => "damaged",
        }
    }
}

/// What did not come over, for the result line.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    /// Connections that are neither RDP nor SSH (VNC, Telnet, ...).
    pub not_rdp: usize,
    /// Passwords of SSH connections, left out: ssh asks in the terminal.
    pub ssh_passwords: usize,
    /// Connections already present (same name, host and group).
    pub duplicates: usize,
    pub unreadable: BTreeMap<Unreadable, usize>,
    /// Passwords left out because there is no vault to keep them in.
    pub no_vault: usize,
}

impl Report {
    fn unreadable(&mut self, why: Unreadable) {
        *self.unreadable.entry(why).or_default() += 1;
    }

    /// "Imported 12 connections. Skipped 3 that aren't RDP and 2 already
    /// here. ..." Only the parts that apply.
    pub fn summary(&self, added: usize) -> String {
        let plural =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut out = format!("Imported {}.", plural(added, "connection", "connections"));
        let mut skipped = Vec::new();
        if self.not_rdp > 0 {
            skipped.push(format!("{} that aren't RDP or SSH", self.not_rdp));
        }
        if self.duplicates > 0 {
            skipped.push(format!("{} already here", self.duplicates));
        }
        if !skipped.is_empty() {
            out += &format!(" Skipped {}.", skipped.join(" and "));
        }
        let lost: usize = self.unreadable.values().sum();
        if lost > 0 {
            let why: Vec<String> = self
                .unreadable
                .iter()
                .map(|(r, n)| {
                    if self.unreadable.len() == 1 {
                        r.reason().to_string()
                    } else {
                        format!("{n} {}", r.reason())
                    }
                })
                .collect();
            out += &format!(
                " {} could not be read: {}.",
                plural(lost, "password", "passwords"),
                why.join(", ")
            );
        }
        if self.no_vault > 0 {
            out += &format!(
                " {} left out: set up a master password under Security to import passwords.",
                plural(self.no_vault, "password", "passwords")
            );
        }
        if self.ssh_passwords > 0 {
            out += &format!(
                " {} left out: ssh asks for {} in the terminal.",
                plural(self.ssh_passwords, "SSH password", "SSH passwords"),
                if self.ssh_passwords == 1 {
                    "it"
                } else {
                    "them"
                }
            );
        }
        out
    }
}

/// The contents of an imported file. Passwords are wiped when it drops.
#[derive(Default)]
pub struct Imported {
    pub groups: Vec<Group>,
    pub connections: Vec<Connection>,
    pub report: Report,
}

impl Imported {
    /// Leaves passwords out (no vault to keep them in) and counts them.
    pub fn drop_passwords(&mut self) {
        let mut n = 0;
        let groups = self.groups.iter_mut().map(|g| &mut g.password);
        for p in groups.chain(self.connections.iter_mut().map(|c| &mut c.password)) {
            if let Some(mut s) = p.take() {
                s.zeroize();
                n += 1;
            }
        }
        self.report.no_vault += n;
    }
}

/// Counts only: never prints a password.
impl std::fmt::Debug for Imported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Imported")
            .field("groups", &self.groups.len())
            .field("connections", &self.connections.len())
            .field("report", &self.report)
            .finish()
    }
}

impl Drop for Imported {
    fn drop(&mut self) {
        let groups = self.groups.iter_mut().map(|g| &mut g.password);
        for p in groups.chain(self.connections.iter_mut().map(|c| &mut c.password)) {
            if let Some(s) = p.as_mut() {
                s.zeroize();
            }
        }
    }
}

/// Windows DPAPI for the current user, behind a trait so the parsers are
/// tested anywhere.
pub trait Dpapi {
    fn unprotect(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}

/// The real DPAPI (`CryptUnprotectData`); nothing decrypts off Windows.
pub struct SystemDpapi;

impl Dpapi for SystemDpapi {
    fn unprotect(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        #[cfg(windows)]
        return crate::vault::dpapi::unprotect(blob);
        #[cfg(not(windows))]
        {
            let _ = blob;
            None
        }
    }
}

enum Parsed {
    Remora,
    Xml(xml::Elem),
}

/// Reads a picked file, refusing one too large to be a connections file
/// before it is in memory.
pub fn read_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let cannot = |e: std::io::Error| format!("Cannot read {}: {e}", path.display());
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes))
        .map_err(cannot)?;
    Ok(bytes)
}

fn parse(bytes: &[u8]) -> Result<(Format, Parsed), String> {
    if bytes.len() > MAX_FILE {
        return Err("The file is too large to be a connections file.".into());
    }
    if crate::vault::read_params(bytes).is_ok() {
        return Ok((Format::Remora, Parsed::Remora));
    }
    let not_known = "This is not a Remora backup, an mRemoteNG connections file \
                     or a Remote Desktop Connection Manager (.rdg) file.";
    let text = xml::decode(bytes).map_err(|_| not_known.to_string())?;
    if !text.trim_start().starts_with('<') {
        return Err(not_known.into());
    }
    let mut doc = xml::parse(&text)?;
    let root = doc.children.pop().filter(|_| doc.children.is_empty());
    match root {
        Some(r) if r.name == "Connections" => Ok((Format::MRemoteNg, Parsed::Xml(r))),
        Some(r) if r.name == "RDCMan" => Ok((Format::RdcMan, Parsed::Xml(r))),
        _ => Err(not_known.into()),
    }
}

/// Tells the format and whether the password row is needed: always for a
/// Remora backup, for mRemoteNG only with a custom master password, never
/// for RDCMan.
pub fn probe(bytes: &[u8]) -> Result<Probe, String> {
    let (format, parsed) = parse(bytes)?;
    let needs_password = match &parsed {
        Parsed::Remora => true,
        Parsed::Xml(root) if format == Format::MRemoteNg => mremoteng::needs_password(root),
        Parsed::Xml(_) => false,
    };
    Ok(Probe {
        format,
        needs_password,
    })
}

/// Reads a file. `password` is the backup's or mRemoteNG's master password
/// (empty when none was asked for).
pub fn read(bytes: &[u8], password: &str, dpapi: &dyn Dpapi) -> Result<Imported, String> {
    match parse(bytes)? {
        (_, Parsed::Remora) => {
            if password.is_empty() {
                return Err("Enter the backup's master password.".into());
            }
            let key =
                crate::vault::read_params(bytes).and_then(|p| crate::vault::derive(password, p))?;
            let (groups, connections) = crate::store::read_backup(bytes, &key)?;
            Ok(Imported {
                groups,
                connections,
                report: Report::default(),
            })
        }
        (Format::MRemoteNg, Parsed::Xml(root)) => mremoteng::read(&root, password, dpapi),
        (_, Parsed::Xml(root)) => rdcman::read(&root, dpapi),
    }
}

/// The settings an imported connection carries, already resolved.
#[derive(Default)]
struct Resolved {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    /// User and password come from the group.
    inherit_credentials: bool,
    /// RDP, or SSH (no session settings).
    protocol: crate::store::Protocol,
    gateway: String,
    /// 0 x 0: fit to the tab.
    size: (u16, u16),
    clipboard: bool,
    sound: bool,
    printers: bool,
    smart_cards: bool,
    microphone: bool,
}

impl Resolved {
    fn connection(self, name: &str, group: &str) -> Connection {
        let mut c = Connection {
            name: if name.trim().is_empty() {
                self.host.clone()
            } else {
                name.trim().to_string()
            },
            port: if self.port == 0 {
                self.protocol.default_port()
            } else {
                self.port
            },
            protocol: self.protocol,
            host: self.host,
            user: self.user,
            password: self.password,
            width: self.size.0,
            height: self.size.1,
            group: group.to_string(),
            gateway: self.gateway,
            inherit: Inherit {
                credentials: self.inherit_credentials,
                ..Inherit::default()
            },
            ..Connection::default()
        };
        let o = &mut c.options;
        o.clipboard = self.clipboard;
        o.sound = self.sound;
        o.printers = self.printers;
        o.smart_cards = self.smart_cards;
        o.microphone = self.microphone;
        c
    }
}

fn group(path: &str, user: String, password: Option<String>) -> Group {
    Group {
        path: path.to_string(),
        user,
        password,
        ..Group::default()
    }
}

/// `DOMAIN\user`, unless the user already names a domain (`\` or `@`).
fn user_with_domain(user: &str, domain: &str) -> String {
    let (user, domain) = (user.trim(), domain.trim());
    if user.is_empty() || domain.is_empty() || user.contains(['\\', '@']) {
        user.to_string()
    } else {
        format!("{domain}\\{user}")
    }
}

/// A group path below `parent`; `/` and `\` in a name would split it.
fn child_path(parent: &str, name: &str) -> String {
    let name = name.trim().replace(['/', '\\'], "-");
    let name = if name.is_empty() { "Folder" } else { &name };
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// `host`, `host:port` or `[v6]:port`.
fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        return (
            host.to_string(),
            tail.strip_prefix(':').and_then(|p| p.parse().ok()),
        );
    }
    match s.split_once(':') {
        Some((h, p)) if !p.contains(':') => match p.parse() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (s.to_string(), None),
        },
        _ => (s.to_string(), None),
    }
}

/// `1024 x 768`, `1024x768` or mRemoteNG's `Res1024x768`.
fn parse_size(s: &str) -> Option<(u16, u16)> {
    let s = s.trim();
    let s = s.strip_prefix("Res").unwrap_or(s);
    let (w, h) = s.split_once(['x', 'X'])?;
    let (w, h) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

fn is_true(v: Option<&str>) -> bool {
    v.is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Standard base64; whitespace (line breaks in a pretty-printed file) is
/// ignored.
fn base64(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    rdp::gateway::ws::base64_decode(&clean).ok()
}
