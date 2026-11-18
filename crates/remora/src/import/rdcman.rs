//! Remote Desktop Connection Manager `.rdg` files: schema 3 (RDCMan 2.7 to
//! 2.93) and the older schema 1/2 (2.2), where a group's settings sit in its
//! `properties` and a server's directly under `server`.
//!
//! Element names follow RDCMan's settings classes (`LogonCredentials`,
//! `GatewaySettings`, `RemoteDesktopSettings`, `LocalResourcesSettings`,
//! `EncryptionSettings`, `CredentialsStore`) and mRemoteNG's RDCMan importer:
//!
//! - A settings element with `inherit="FromParent"`, or none at all, takes
//!   the enclosing group's (or file's) settings; `inherit="None"` its own.
//! - `logonCredentials/profileName@scope`: `Local` keeps the user, password
//!   and domain inline; `File` names a `file/credentialsProfiles/
//!   credentialsProfile`; `Global` lives in RDCMan.settings on the PC that
//!   wrote the file and cannot be resolved.
//! - Passwords are base64 DPAPI blobs of UTF-16LE text for the current user
//!   (`encryptionMethod` `LogonCredentials`), or RSA for a certificate;
//!   schema 1 may store them with `storeAsClearText="True"`.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::xml::Elem;
use super::{
    Dpapi, Imported, Resolved, Unreadable, base64, child_path, group, is_true, parse_size,
    split_host_port, user_with_domain,
};

struct Reader<'a> {
    /// Schema 1/2: group settings inside `properties`.
    old: bool,
    profiles: Vec<&'a Elem>,
    dpapi: &'a dyn Dpapi,
    /// Each credentials element is resolved (and counted) once, by address.
    cache: HashMap<usize, (String, Option<Zeroizing<String>>)>,
    out: Imported,
}

/// The effective settings element `key` for the last holder of `chain`,
/// and the index of the holder that defines it.
fn setting<'a>(chain: &[&'a Elem], key: &str) -> Option<(usize, &'a Elem)> {
    chain.iter().enumerate().rev().find_map(|(i, holder)| {
        let e = holder.child(key)?;
        let inherits = e
            .attr("inherit")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("FromParent"));
        (!inherits).then_some((i, e))
    })
}

impl<'a> Reader<'a> {
    /// Where a group's or the file's settings are.
    fn holder(&self, node: &'a Elem) -> &'a Elem {
        match (self.old, node.child("properties")) {
            (true, Some(p)) => p,
            _ => node,
        }
    }

    /// User and password from the effective `logonCredentials` of `chain`.
    fn credentials(&mut self, chain: &[&'a Elem]) -> (String, Option<String>) {
        let Some((at, creds)) = setting(chain, "logonCredentials") else {
            return (String::new(), None);
        };
        let key = creds as *const Elem as usize;
        if !self.cache.contains_key(&key) {
            let resolved = self.resolve(&chain[..=at], creds);
            self.cache.insert(key, resolved);
        }
        let (user, password) = &self.cache[&key];
        (user.clone(), password.as_ref().map(|p| p.to_string()))
    }

    fn resolve(
        &mut self,
        chain: &[&'a Elem],
        creds: &'a Elem,
    ) -> (String, Option<Zeroizing<String>>) {
        let profile = creds.child("profileName");
        let scope = profile
            .and_then(|p| p.attr("scope"))
            .unwrap_or("Local")
            .trim();
        let name = profile.map_or("", |p| p.text.trim());
        let inline = creds.child("userName").is_some();
        let (source, chain) = if scope.eq_ignore_ascii_case("File") {
            let found = self.profiles.iter().copied().find(|p| {
                p.child_text("profileName")
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            });
            match found {
                // Profiles are encrypted with the file's settings.
                Some(p) => (p, &chain[..1]),
                None => {
                    self.out.report.unreadable(Unreadable::RdcmanSettings);
                    return (String::new(), None);
                }
            }
        } else if scope.eq_ignore_ascii_case("Global") && !inline {
            self.out.report.unreadable(Unreadable::RdcmanSettings);
            return (String::new(), None);
        } else {
            (creds, chain)
        };
        let user = user_with_domain(
            source.child_text("userName").unwrap_or(""),
            source.child_text("domain").unwrap_or(""),
        );
        let password = source
            .child("password")
            .filter(|p| !p.text.trim().is_empty())
            .and_then(|p| self.password(chain, p));
        (user, password)
    }

    fn password(&mut self, chain: &[&'a Elem], p: &Elem) -> Option<Zeroizing<String>> {
        if is_true(p.attr("storeAsClearText")) {
            return Some(Zeroizing::new(p.text.trim().to_string()));
        }
        let method = setting(chain, "encryptionSettings")
            .and_then(|(_, e)| e.child_text("encryptionMethod"))
            .unwrap_or("LogonCredentials");
        let plain = if matches!(method, "Certificate" | "1") {
            Err(Unreadable::Certificate)
        } else {
            base64(&p.text)
                .ok_or(Unreadable::Damaged)
                .and_then(|blob| self.dpapi.unprotect(&blob).ok_or(Unreadable::OtherUser))
                .and_then(|b| utf16(&b).ok_or(Unreadable::Damaged))
        };
        plain.map_err(|why| self.out.report.unreadable(why)).ok()
    }

    fn group(&mut self, node: &'a Elem, chain: &[&'a Elem], path: &str) {
        let mut chain = chain.to_vec();
        chain.push(self.holder(node));
        let name = node
            .child("properties")
            .and_then(|p| p.child_text("name"))
            .unwrap_or("");
        let path = child_path(path, if name.is_empty() { "RDCMan" } else { name });
        let (user, password) = self.credentials(&chain);
        self.out.groups.push(group(&path, user, password));
        for child in &node.children {
            match child.name.as_str() {
                "group" => self.group(child, &chain, &path),
                "server" => self.server(child, &chain, &path),
                // smartGroup, serverRef, properties, settings.
                _ => {}
            }
        }
    }

    fn server(&mut self, node: &'a Elem, chain: &[&'a Elem], path: &str) {
        let props = match (self.old, node.child("properties")) {
            (false, Some(p)) => p,
            _ => node,
        };
        let mut chain = chain.to_vec();
        chain.push(node);
        let own = chain.len() - 1;
        let get = |key: &str| setting(&chain, key).map(|(_, e)| e);
        let (host, name_port) = split_host_port(props.child_text("name").unwrap_or(""));
        let inherit_credentials = setting(&chain, "logonCredentials").is_none_or(|(i, _)| i < own);
        let (user, password) = if inherit_credentials {
            (String::new(), None)
        } else {
            self.credentials(&chain)
        };
        let settings_port = get("connectionSettings")
            .and_then(|c| c.child_text("port"))
            .and_then(|p| p.parse().ok());
        let gateway = get("gatewaySettings")
            .filter(|g| is_true(g.child_text("enabled")))
            .and_then(|g| g.child_text("hostName"))
            .unwrap_or("");
        let size = get("remoteDesktop").map_or((0, 0), |d| {
            let fit = is_true(d.child_text("sameSizeAsClientArea"))
                // RDCMan's default for a missing fullScreen is on.
                || d.child_text("fullScreen").is_none_or(|v| is_true(Some(v)));
            match d.child_text("size").and_then(parse_size) {
                Some(s) if !fit => s,
                _ => (0, 0),
            }
        });
        let res = get("localResources");
        let flag = |k: &str| is_true(res.and_then(|r| r.child_text(k)));
        let pick = |k: &str, on: [&str; 2]| {
            res.and_then(|r| r.child_text(k))
                .is_some_and(|v| on.contains(&v))
        };
        let r = Resolved {
            host,
            port: name_port.or(settings_port).unwrap_or(0),
            user,
            password,
            inherit_credentials,
            gateway: gateway.to_string(),
            size,
            clipboard: flag("redirectClipboard"),
            sound: pick("audioRedirection", ["Client", "0"]),
            printers: flag("redirectPrinters"),
            smart_cards: flag("redirectSmartCards"),
            microphone: pick("audioCaptureRedirection", ["Record", "1"]),
        };
        let display = props.child_text("displayName").unwrap_or("");
        let c = r.connection(display, path);
        self.out.connections.push(c);
    }
}

/// UTF-16LE without trailing NULs.
fn utf16(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let units: Zeroizing<Vec<u16>> = Zeroizing::new(
        bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    );
    let end = units.iter().rposition(|&u| u != 0).map_or(0, |i| i + 1);
    String::from_utf16(&units[..end]).ok().map(Zeroizing::new)
}

pub(super) fn read(root: &Elem, dpapi: &dyn Dpapi) -> Result<Imported, String> {
    let schema = root.attr("schemaVersion").map(str::trim);
    let old = match schema.map(str::parse::<u32>) {
        Some(Ok(1 | 2)) => true,
        Some(Ok(3)) => false,
        None => root.child("version").is_some(),
        _ => {
            return Err(format!(
                "This RDCMan file's schema version ({}) is not supported.",
                schema.unwrap_or("?")
            ));
        }
    };
    let file = root
        .child("file")
        .ok_or("The RDCMan file holds no connections.")?;
    let profiles = file
        .child("credentialsProfiles")
        .map(|p| {
            p.children
                .iter()
                .filter(|c| c.name == "credentialsProfile")
                .collect()
        })
        .unwrap_or_default();
    let mut r = Reader {
        old,
        profiles,
        dpapi,
        cache: HashMap::new(),
        out: Imported::default(),
    };
    r.group(file, &[], "");
    Ok(std::mem::take(&mut r.out))
}
