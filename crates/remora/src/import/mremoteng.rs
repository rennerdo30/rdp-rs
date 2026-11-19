//! mRemoteNG `confCons.xml` (schema 2.6 to 2.9).
//!
//! Checked against mRemoteNG's sources (`XmlConnectionsDeserializer`,
//! `XmlConnectionNodeSerializer28/29`, `XmlRootNodeSerializer`,
//! `AeadCryptographyProvider`, `Pkcs5S2KeyGenerator`, `XmlConnectionsDecryptor`):
//!
//! - A password is base64 of salt (16 bytes), nonce (16), then ciphertext
//!   with a 16-byte tag: AES-256-GCM, the salt as associated data, the key
//!   PBKDF2-HMAC-SHA1(master, salt, `KdfIterations`, 32 bytes). The master's
//!   bytes are one per character (BouncyCastle `Pkcs5PasswordToBytes`), not
//!   UTF-8; characters above U+00FF cannot be in a master password.
//! - The root's `Protected` decrypts to `ThisIsNotProtected` under the default
//!   master `mR3m`; a custom master makes it `ThisIsProtected`.
//! - `FullFileEncryption="true"`: the root's text is the encrypted XML of the nodes.
//! - 2.9 `KeyProtection="Dpapi"`: values are DPAPI blobs of UTF-8 text.
//! - `Inherit<Name>="true"` takes `<Name>` from the parent container.

use std::collections::HashMap;
use std::num::NonZeroU32;

use aes_gcm::aead::AeadInOut;
use aes_gcm::aes::Aes256;
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::{AesGcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use super::xml::Elem;
use super::{
    Dpapi, Imported, Resolved, Unreadable, base64, child_path, group, is_true, parse_size,
    user_with_domain,
};

/// mRemoteNG's built-in master password (public, in its source).
const DEFAULT_MASTER: &str = "mR3m";
const NOT_PROTECTED: &[u8] = b"ThisIsNotProtected";
/// More PBKDF2 rounds than this are not a file mRemoteNG writes; refusing
/// them keeps a hostile file from hanging the import.
const MAX_ITERATIONS: u32 = 1_000_000;

#[derive(Clone, Copy, PartialEq)]
enum Cipher {
    Aead {
        iterations: NonZeroU32,
    },
    Dpapi,
    /// Serpent, Twofish, CCM, EAX, or the CBC scheme before 2.6.
    Unsupported,
}

fn cipher(root: &Elem) -> Cipher {
    if root.attr("KeyProtection") == Some("Dpapi") {
        return Cipher::Dpapi;
    }
    let version: f64 = root
        .attr("ConfVersion")
        .and_then(|v| v.trim().replace(',', ".").parse().ok())
        .unwrap_or(0.0);
    let is = |name: &str, default: &str, want: &str| {
        root.attr(name)
            .unwrap_or(default)
            .trim()
            .eq_ignore_ascii_case(want)
    };
    if version < 2.6
        || !is("EncryptionEngine", "AES", "AES")
        || !is("BlockCipherMode", "GCM", "GCM")
    {
        return Cipher::Unsupported;
    }
    let iterations = root
        .attr("KdfIterations")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1000);
    match NonZeroU32::new(iterations) {
        Some(iterations) if iterations.get() <= MAX_ITERATIONS => Cipher::Aead { iterations },
        _ => Cipher::Unsupported,
    }
}

/// The master's bytes as BouncyCastle derives them: one per character.
fn master_bytes(master: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(master.len()));
    for c in master.chars() {
        out.push(u8::try_from(u32::from(c)).ok()?);
    }
    Some(out)
}

/// Decrypts one value of mRemoteNG's AES-GCM scheme.
pub(super) fn decrypt(
    value: &str,
    master: &str,
    iterations: NonZeroU32,
) -> Option<Zeroizing<Vec<u8>>> {
    let raw = base64(value)?;
    if raw.len() < 16 + 16 + 16 {
        return None;
    }
    let (salt, rest) = raw.split_at(16);
    let (nonce, sealed) = rest.split_at(16);
    let mut key = Zeroizing::new([0u8; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        iterations,
        salt,
        &master_bytes(master)?,
        &mut key[..],
    );
    let aead = AesGcm::<Aes256, U16>::new_from_slice(&key[..]).ok()?;
    let nonce = Nonce::<U16>::try_from(nonce).ok()?;
    let mut buf = Zeroizing::new(sealed.to_vec());
    aead.decrypt_in_place(&nonce, salt, &mut *buf).ok()?;
    Some(buf)
}

/// True when the file has a custom master password (the default does not
/// open it). Only AES-GCM files can tell; others never ask.
pub(super) fn needs_password(root: &Elem) -> bool {
    match (cipher(root), root.attr("Protected").map(str::trim)) {
        (Cipher::Aead { iterations }, Some(p)) if !p.is_empty() => {
            decrypt(p, DEFAULT_MASTER, iterations)
                .as_deref()
                .map(Vec::as_slice)
                != Some(NOT_PROTECTED)
        }
        _ => false,
    }
}

struct Reader<'a> {
    cipher: Cipher,
    master: Zeroizing<String>,
    dpapi: &'a dyn Dpapi,
    /// DPAPI could not open the root marker: no value will open either.
    dpapi_failed: bool,
    /// Each stored value is decrypted (and counted when it fails) once.
    cache: HashMap<String, Option<Zeroizing<String>>>,
    out: Imported,
}

impl Reader<'_> {
    fn plain(&self, value: &str) -> Result<Zeroizing<Vec<u8>>, Unreadable> {
        match self.cipher {
            Cipher::Unsupported => Err(Unreadable::Cipher),
            Cipher::Aead { iterations } => {
                decrypt(value, &self.master, iterations).ok_or(Unreadable::Damaged)
            }
            Cipher::Dpapi if self.dpapi_failed => Err(Unreadable::OtherUser),
            Cipher::Dpapi => {
                let blob = base64(value).ok_or(Unreadable::Damaged)?;
                self.dpapi.unprotect(&blob).ok_or(Unreadable::OtherUser)
            }
        }
    }

    fn password(&mut self, value: Option<&str>) -> Option<String> {
        let value = value?.trim();
        if value.is_empty() {
            return None;
        }
        if !self.cache.contains_key(value) {
            let plain = self.plain(value).and_then(|p| {
                String::from_utf8(p.to_vec())
                    .map(Zeroizing::new)
                    .map_err(|_| Unreadable::Damaged)
            });
            let plain = plain.map_err(|why| self.out.report.unreadable(why)).ok();
            self.cache.insert(value.to_string(), plain);
        }
        self.cache[value].as_ref().map(|p| p.to_string())
    }

    fn walk<'e>(&mut self, nodes: &'e [Elem], chain: &[&'e Elem], path: &str) {
        for node in nodes.iter().filter(|n| n.name == "Node") {
            let get = |key: &str| value(node, chain, key);
            if node
                .attr("Type")
                .is_some_and(|t| t.eq_ignore_ascii_case("Container"))
            {
                let sub = child_path(path, node.attr("Name").unwrap_or(""));
                let user =
                    user_with_domain(get("Username").unwrap_or(""), get("Domain").unwrap_or(""));
                let password = self.password(get("Password"));
                self.out.groups.push(group(&sub, user, password));
                let mut below = chain.to_vec();
                below.push(node);
                self.walk(&node.children, &below, &sub);
                continue;
            }
            let protocol = get("Protocol").unwrap_or("RDP").trim();
            let ssh = ["SSH1", "SSH2"]
                .iter()
                .any(|p| protocol.eq_ignore_ascii_case(p));
            if !ssh && !protocol.eq_ignore_ascii_case("RDP") {
                self.out.report.not_rdp += 1;
                continue;
            }
            let own = |k: &str| is_true(node.attr(&format!("Inherit{k}")));
            let inherit_credentials = !chain.is_empty()
                && own("Username")
                && own("Password")
                && (own("Domain") || node.attr("Domain").is_none_or(|d| d.trim().is_empty()));
            if ssh {
                // RDP-87: host, port and user; ssh asks for a password.
                let user = if inherit_credentials {
                    String::new()
                } else {
                    get("Username").unwrap_or("").trim().to_string()
                };
                if !inherit_credentials && get("Password").is_some_and(|p| !p.trim().is_empty()) {
                    self.out.report.ssh_passwords += 1;
                }
                let r = Resolved {
                    host: node.attr("Hostname").unwrap_or("").trim().to_string(),
                    port: get("Port").and_then(|p| p.trim().parse().ok()).unwrap_or(0),
                    user,
                    inherit_credentials,
                    protocol: crate::store::Protocol::Ssh,
                    ..Resolved::default()
                };
                let c = r.connection(node.attr("Name").unwrap_or(""), path);
                self.out.connections.push(c);
                continue;
            }
            let (user, password) = if inherit_credentials {
                (String::new(), None)
            } else {
                let user =
                    user_with_domain(get("Username").unwrap_or(""), get("Domain").unwrap_or(""));
                (user, self.password(get("Password")))
            };
            let gateway = match get("RDGatewayUsageMethod").map(str::trim) {
                Some("Always" | "Detect" | "1" | "2") => {
                    get("RDGatewayHostname").unwrap_or("").trim()
                }
                _ => "",
            };
            let r = Resolved {
                host: node.attr("Hostname").unwrap_or("").trim().to_string(),
                port: get("Port").and_then(|p| p.trim().parse().ok()).unwrap_or(0),
                user,
                password,
                inherit_credentials,
                protocol: crate::store::Protocol::Rdp,
                gateway: gateway.to_string(),
                size: get("Resolution").and_then(parse_size).unwrap_or((0, 0)),
                clipboard: is_true(get("RedirectClipboard")),
                sound: matches!(
                    get("RedirectSound").map(str::trim),
                    Some("BringToThisComputer" | "0")
                ),
                printers: is_true(get("RedirectPrinters")),
                smart_cards: is_true(get("RedirectSmartCards")),
                microphone: is_true(get("RedirectAudioCapture")),
            };
            let c = r.connection(node.attr("Name").unwrap_or(""), path);
            self.out.connections.push(c);
        }
    }
}

/// `key` on `node`, or on the nearest container it inherits it from.
/// Inheriting from the root gives mRemoteNG's default (None here).
fn value<'a>(node: &'a Elem, parents: &[&'a Elem], key: &str) -> Option<&'a str> {
    let inherit = format!("Inherit{key}");
    let mut cur = node;
    let mut up = parents.iter().rev();
    while is_true(cur.attr(&inherit)) {
        cur = up.next()?;
    }
    cur.attr(key)
}

pub(super) fn read(root: &Elem, password: &str, dpapi: &dyn Dpapi) -> Result<Imported, String> {
    let cipher = cipher(root);
    let protected = root.attr("Protected").map(str::trim).unwrap_or("");
    let mut master = Zeroizing::new(DEFAULT_MASTER.to_string());
    let mut dpapi_failed = false;
    match cipher {
        Cipher::Aead { iterations } if needs_password(root) => {
            if password.is_empty() {
                return Err("Enter the mRemoteNG master password.".into());
            }
            if decrypt(protected, password, iterations).is_none() {
                return Err("Wrong mRemoteNG master password; nothing was imported.".into());
            }
            master = Zeroizing::new(password.to_string());
        }
        Cipher::Dpapi => {
            dpapi_failed = base64(protected)
                .and_then(|b| dpapi.unprotect(&b))
                .is_none_or(|p| p.as_slice() != NOT_PROTECTED);
        }
        _ => {}
    }
    let mut r = Reader {
        cipher,
        master,
        dpapi,
        dpapi_failed,
        cache: HashMap::new(),
        out: Imported::default(),
    };
    let full = is_true(root.attr("FullFileEncryption")) && cipher != Cipher::Unsupported;
    if is_true(root.attr("FullFileEncryption")) && cipher == Cipher::Unsupported {
        return Err(
            "This mRemoteNG file is encrypted as a whole with a cipher Remora cannot read. \
                    In mRemoteNG, switch to AES-GCM or turn off full file encryption, then save."
                .into(),
        );
    }
    if full {
        let plain = r.plain(root.text.trim()).map_err(|why| match why {
            Unreadable::OtherUser => {
                "This mRemoteNG file was protected for another Windows user or PC.".to_string()
            }
            _ => "The mRemoteNG file's encrypted content is damaged.".to_string(),
        })?;
        let text = std::str::from_utf8(&plain).map_err(|_| "The decrypted content is not text.")?;
        let nodes = super::xml::parse(text)?;
        r.walk(&nodes.children, &[], "");
    } else {
        r.walk(&root.children, &[], "");
    }
    Ok(std::mem::take(&mut r.out))
}
