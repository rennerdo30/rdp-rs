//! Import tests. Every fixture is built here; no real mRemoteNG or RDCMan
//! file from this PC is ever read (they hold credentials).

use std::num::NonZeroU32;

use aes_gcm::aead::AeadInOut;
use aes_gcm::aes::Aes256;
use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::{AesGcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use super::*;

/// A DPAPI stand-in: blobs that start with `ME:` are this user's.
struct FakeDpapi;

impl Dpapi for FakeDpapi {
    fn unprotect(&self, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        blob.strip_prefix(b"ME:")
            .map(|p| Zeroizing::new(p.to_vec()))
    }
}

fn b64(data: &[u8]) -> String {
    rdp::gateway::ws::base64_encode(data)
}

fn iters(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// mRemoteNG's AES-GCM encryption (fixed salt and nonce: tests only).
fn seal(plain: &str, master: &str, iterations: u32) -> String {
    let (salt, nonce) = ([7u8; 16], [9u8; 16]);
    let master: Vec<u8> = master.chars().map(|c| c as u8).collect();
    let mut key = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        iters(iterations),
        &salt,
        &master,
        &mut key,
    );
    let aead = AesGcm::<Aes256, U16>::new_from_slice(&key).unwrap();
    let mut buf = plain.as_bytes().to_vec();
    aead.encrypt_in_place(
        &Nonce::<U16>::try_from(&nonce[..]).unwrap(),
        &salt,
        &mut buf,
    )
    .unwrap();
    b64(&[&salt[..], &nonce[..], &buf[..]].concat())
}

fn by_name<'a>(i: &'a Imported, name: &str) -> &'a crate::store::Connection {
    i.connections
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no connection {name}"))
}

fn by_path<'a>(i: &'a Imported, path: &str) -> &'a crate::store::Group {
    i.groups
        .iter()
        .find(|g| g.path == path)
        .unwrap_or_else(|| panic!("no group {path}"))
}

// --- mRemoteNG ---------------------------------------------------------------

#[test]
fn mremoteng_crypto_matches_mremoteng_own_test_files() {
    // Root `Protected` values of mRemoteNGTests/Resources/confCons_v2_6.xml,
    // confCons_v2_6_passwordis_Password.xml and confCons_v2_6_5k-iterations.xml
    // (github.com/mRemoteNG/mRemoteNG), with the masters those tests use.
    let cases = [
        (
            "8LmIO3+MWBY0zTmfjfOEdCGxhTAwnlohb1veTGNZFt6lAYvY2UOzWyjVzkx6V93smpbP0ZOuexN15u7rvwJEjawC",
            "mR3m",
            1000,
            &b"ThisIsNotProtected"[..],
        ),
        (
            "e/T6ajrPtNNlHreSeD4QBqToTuiqtNACKiPJv7vU+l6TWCu9JNsmL+Y8lJ4aTl5YVcstXpQjxsZ9i8+YV4Gs",
            "Password",
            1000,
            b"ThisIsProtected",
        ),
        (
            "Z1IOT8h7neJ5V7es5Iv63A2WsDG6QWl10F/Rb9ljKxvCseEITty1BfMNgiaVPfm7w61uabQKqu2waDCXUpLo1OZW",
            "mR3m",
            5000,
            b"ThisIsNotProtected",
        ),
    ];
    for (value, master, n, plain) in cases {
        let out = mremoteng::decrypt(value, master, iters(n)).expect("decrypts");
        assert_eq!(out.as_slice(), plain);
        assert!(mremoteng::decrypt(value, "wrong", iters(n)).is_none());
        assert!(mremoteng::decrypt(value, master, iters(n + 1)).is_none());
    }
}

#[test]
fn mremoteng_master_bytes_are_one_per_character_not_utf8() {
    // Made with Python's `cryptography` and hashlib: PBKDF2 over the
    // Latin-1 bytes of "Mäster", salt 00..0f, nonce 10..1f, plaintext "Grüße".
    let v = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+Nhx0gg3V/sxH3ZRS+PyuKRxvBHYEmcQ==";
    let out = mremoteng::decrypt(v, "Mäster", iters(1000)).unwrap();
    assert_eq!(std::str::from_utf8(&out).unwrap(), "Grüße");
    // A character BouncyCastle cannot turn into one byte never matches.
    assert!(mremoteng::decrypt(v, "Mäster€", iters(1000)).is_none());
}

fn mrng_nodes(master: &str) -> String {
    let work = seal("work-pw", master, 1000);
    let own = seal("own-pw", master, 1000);
    format!(
        r#"
  <Node Name="Work" Type="Container" Username="admin" Domain="CORP" Password="{work}" Protocol="RDP" Resolution="FitToWindow" RedirectClipboard="true" RedirectSound="BringToThisComputer" RDGatewayUsageMethod="Always" RDGatewayHostname="gw.corp">
    <Node Name="Servers/Prod" Type="Container" Protocol="SSH2" InheritUsername="true" InheritPassword="true" InheritDomain="true" InheritRDGatewayUsageMethod="true" InheritRDGatewayHostname="true" InheritRedirectClipboard="true" InheritRedirectSound="true">
      <Node Name="db1" Type="Connection" Hostname="db1.corp" Port="3390" Protocol="RDP" InheritUsername="true" InheritPassword="true" InheritDomain="true" InheritRDGatewayUsageMethod="true" InheritRDGatewayHostname="true" InheritRedirectClipboard="true" InheritRedirectSound="true" Resolution="Res1280x1024" RedirectPrinters="True" RedirectAudioCapture="true"/>
      <Node Name="ssh1" Type="Connection" Hostname="ssh1" Protocol="SSH2"/>
      <Node Name="inherits-ssh" Type="Connection" Hostname="x" Protocol="RDP" InheritProtocol="true"/>
    </Node>
    <Node Name="own" Type="Connection" Hostname="own.corp" Username="bob@corp" Domain="X" Password="{own}" Protocol="RDP" Port="0" Resolution="SmartSize" RedirectSound="LeaveAtRemoteComputer" RedirectSmartCards="true" RDGatewayUsageMethod="Never" RDGatewayHostname="gw.ignored"/>
  </Node>
  <Node Name="vnc" Type="Connection" Hostname="v" Protocol="VNC"/>
  <Node Name="" Type="Connection" Hostname="bare" Protocol="RDP" Username="u" Domain="D" InheritUsername="true" InheritPassword="true"/>
"#
    )
}

fn mrng_file(master: &str, root_attrs: &str, body: &str) -> Vec<u8> {
    let protected = seal(
        if master == "mR3m" {
            "ThisIsNotProtected"
        } else {
            "ThisIsProtected"
        },
        master,
        1000,
    );
    format!(
        "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" \
         Name=\"Connections\" Export=\"false\" EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" \
         KdfIterations=\"1000\" Protected=\"{protected}\" {root_attrs}>{body}</mrng:Connections>"
    )
    .into_bytes()
}

fn check_mrng_tree(i: &Imported, with_passwords: bool) {
    let pw = |s: &str| with_passwords.then(|| s.to_string());
    let work = by_path(i, "Work");
    assert_eq!(
        (work.user.as_str(), work.password.clone()),
        ("CORP\\admin", pw("work-pw"))
    );
    // A container that inherits gets the effective values; '/' in a name
    // does not split the path.
    let prod = by_path(i, "Work/Servers-Prod");
    assert_eq!(
        (prod.user.as_str(), prod.password.clone()),
        ("CORP\\admin", pw("work-pw"))
    );

    let db1 = by_name(i, "db1");
    assert_eq!(db1.group, "Work/Servers-Prod");
    assert_eq!((db1.host.as_str(), db1.port), ("db1.corp", 3390));
    assert!(db1.inherit.credentials && db1.user.is_empty() && db1.password.is_none());
    assert_eq!(db1.gateway, "gw.corp");
    assert_eq!((db1.width, db1.height), (1280, 1024));
    let o = &db1.options;
    assert!(o.clipboard && o.sound && o.printers && o.microphone && !o.smart_cards);

    let own = by_name(i, "own");
    assert_eq!(own.group, "Work");
    assert_eq!((own.user.as_str(), own.port), ("bob@corp", 3389));
    assert_eq!(own.password, pw("own-pw"));
    assert!(!own.inherit.credentials);
    assert_eq!((own.width, own.height, own.gateway.as_str()), (0, 0, ""));
    assert!(own.options.smart_cards && !own.options.sound && !own.options.clipboard);

    let bare = by_name(i, "bare");
    assert_eq!((bare.group.as_str(), bare.user.as_str()), ("", ""));
    assert!(!bare.inherit.credentials);

    // SSH entries come over as SSH connections (RDP-87); VNC does not.
    let ssh1 = by_name(i, "ssh1");
    assert_eq!(ssh1.protocol, crate::store::Protocol::Ssh);
    assert_eq!((ssh1.host.as_str(), ssh1.port), ("ssh1", 22));
    assert_eq!(ssh1.group, "Work/Servers-Prod");
    assert_eq!(ssh1.password, None);
    assert_eq!(
        by_name(i, "inherits-ssh").protocol,
        crate::store::Protocol::Ssh,
        "the protocol is inherited from the container"
    );
    assert_eq!(by_name(i, "db1").protocol, crate::store::Protocol::Rdp);
    assert_eq!(i.connections.len(), 5);
    assert_eq!(i.report.not_rdp, 1, "vnc");
}

#[test]
fn mremoteng_default_master_imports_tree_with_inheritance() {
    let file = mrng_file(
        "mR3m",
        r#"FullFileEncryption="false" ConfVersion="2.8""#,
        &mrng_nodes("mR3m"),
    );
    let p = probe(&file).unwrap();
    assert_eq!(
        p,
        Probe {
            format: Format::MRemoteNg,
            needs_password: false
        }
    );
    let i = read(&file, "", &FakeDpapi).unwrap();
    check_mrng_tree(&i, true);
    assert!(i.report.unreadable.is_empty());
}

#[test]
fn mremoteng_custom_master_is_asked_and_checked() {
    let file = mrng_file("s3cret!", r#"ConfVersion="2.7""#, &mrng_nodes("s3cret!"));
    assert!(probe(&file).unwrap().needs_password);
    assert!(
        read(&file, "", &FakeDpapi)
            .unwrap_err()
            .contains("Enter the mRemoteNG master password")
    );
    assert!(
        read(&file, "mR3m", &FakeDpapi)
            .unwrap_err()
            .contains("Wrong mRemoteNG master password")
    );
    check_mrng_tree(&read(&file, "s3cret!", &FakeDpapi).unwrap(), true);
}

#[test]
fn mremoteng_full_file_encryption() {
    for master in ["mR3m", "s3cret!"] {
        let body = seal(&mrng_nodes(master), master, 1000);
        let file = mrng_file(
            master,
            r#"FullFileEncryption="True" ConfVersion="2.6""#,
            &body,
        );
        let typed = if master == "mR3m" { "" } else { master };
        check_mrng_tree(&read(&file, typed, &FakeDpapi).unwrap(), true);
    }
}

#[test]
fn mremoteng_other_ciphers_import_without_passwords() {
    for attrs in [
        r#"EncryptionEngine="Serpent" ConfVersion="2.8""#,
        r#"BlockCipherMode="EAX" ConfVersion="2.8""#,
        r#"ConfVersion="2.5""#,
    ] {
        // Later attributes of the same name would be invalid XML; replace.
        let file = String::from_utf8(mrng_file("mR3m", "", &mrng_nodes("mR3m"))).unwrap();
        let file = file
            .replace(r#"EncryptionEngine="AES""#, "")
            .replace(r#"BlockCipherMode="GCM""#, "")
            .replace("<mrng:Connections ", &format!("<mrng:Connections {attrs} "));
        assert!(!probe(file.as_bytes()).unwrap().needs_password, "{attrs}");
        let i = read(file.as_bytes(), "", &FakeDpapi).unwrap();
        check_mrng_tree(&i, false);
        // The work password is stored once (the inheriting container shares it).
        assert_eq!(
            i.report.unreadable.get(&Unreadable::Cipher),
            Some(&2),
            "{attrs}"
        );
    }
    let file = String::from_utf8(mrng_file(
        "mR3m",
        r#"FullFileEncryption="true" ConfVersion="2.8""#,
        "x",
    ))
    .unwrap()
    .replace(r#"EncryptionEngine="AES""#, r#"EncryptionEngine="Twofish""#);
    assert!(
        read(file.as_bytes(), "", &FakeDpapi)
            .unwrap_err()
            .contains("cipher")
    );
}

#[test]
fn mremoteng_dpapi_key_protection() {
    let me = |s: &str| b64(&[b"ME:", s.as_bytes()].concat());
    let body = format!(
        r#"<Node Name="a" Type="Connection" Hostname="a" Protocol="RDP" Username="u" Password="{}"/>
           <Node Name="b" Type="Connection" Hostname="b" Protocol="RDP" Username="u" Password="{}"/>"#,
        me("pw-a"),
        b64(b"SOMEONE-ELSE")
    );
    let xml = format!(
        r#"<mrng:Connections xmlns:mrng="x" KeyProtection="Dpapi" Protected="{}" ConfVersion="2.9">{body}</mrng:Connections>"#,
        me("ThisIsNotProtected")
    );
    assert!(!probe(xml.as_bytes()).unwrap().needs_password);
    let i = read(xml.as_bytes(), "", &FakeDpapi).unwrap();
    assert_eq!(by_name(&i, "a").password.as_deref(), Some("pw-a"));
    assert_eq!(by_name(&i, "b").password, None);
    assert_eq!(i.report.unreadable.get(&Unreadable::OtherUser), Some(&1));
}

#[test]
fn mremoteng_damaged_values_do_not_panic() {
    let body = r#"<Node Name="a" Hostname="a" Password="!!notbase64" Port="99999" Resolution="Resx"/>
                  <Node Name="b" Hostname="b" Password="AAAA"/>"#;
    let file = mrng_file("mR3m", r#"ConfVersion="2.8""#, body);
    let i = read(&file, "", &FakeDpapi).unwrap();
    assert_eq!(i.connections.len(), 2);
    assert_eq!(by_name(&i, "a").port, 3389);
    assert_eq!(i.report.unreadable.get(&Unreadable::Damaged), Some(&2));
}

// --- RDCMan ------------------------------------------------------------------

fn me16(s: &str) -> String {
    let mut blob = b"ME:".to_vec();
    blob.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    blob.extend([0, 0]); // a trailing NUL, as some writers add
    b64(&blob)
}

fn rdg3() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.93" schemaVersion="3">
  <file>
    <credentialsProfiles>
      <credentialsProfile inherit="None">
        <profileName scope="Local">ops</profileName>
        <userName>operator</userName>
        <password>{ops}</password>
        <domain>LAB</domain>
      </credentialsProfile>
    </credentialsProfiles>
    <properties><expanded>True</expanded><name>Lab</name></properties>
    <logonCredentials inherit="None">
      <profileName scope="Local">Custom</profileName>
      <userName>root-user</userName>
      <password>{root}</password>
      <domain>LAB</domain>
    </logonCredentials>
    <localResources inherit="None">
      <audioRedirection>Client</audioRedirection>
      <audioCaptureRedirection>Record</audioCaptureRedirection>
      <redirectClipboard>True</redirectClipboard>
      <redirectPrinters>False</redirectPrinters>
      <redirectSmartCards>True</redirectSmartCards>
    </localResources>
    <smartGroup><properties><name>All</name></properties></smartGroup>
    <group>
      <properties><name>Web</name></properties>
      <logonCredentials inherit="None"><profileName scope="File">OPS</profileName></logonCredentials>
      <gatewaySettings inherit="None"><enabled>True</enabled><hostName>gw.lab</hostName></gatewaySettings>
      <server>
        <properties><displayName>Web 1</displayName><name>web1.lab:3391</name></properties>
        <remoteDesktop inherit="None"><size>1600 x 900</size><sameSizeAsClientArea>False</sameSizeAsClientArea><fullScreen>False</fullScreen></remoteDesktop>
      </server>
      <server>
        <properties><name>web2.lab</name></properties>
        <logonCredentials inherit="FromParent" />
        <connectionSettings inherit="None"><port>4000</port></connectionSettings>
        <localResources inherit="None"><audioRedirection>NoSound</audioRedirection></localResources>
        <gatewaySettings inherit="None"><enabled>False</enabled><hostName>gw.lab</hostName></gatewaySettings>
        <remoteDesktop inherit="None"><size>1600 x 900</size><sameSizeAsClientArea>True</sameSizeAsClientArea></remoteDesktop>
      </server>
      <serverRef ref="x" />
    </group>
    <group>
      <properties><name>Other</name></properties>
      <server>
        <properties><name>away.lab</name></properties>
        <logonCredentials inherit="None"><profileName scope="Local">Custom</profileName><userName>me</userName><password>{other}</password><domain /></logonCredentials>
      </server>
      <server>
        <properties><name>global.lab</name></properties>
        <logonCredentials inherit="None"><profileName scope="Global">corp</profileName></logonCredentials>
      </server>
    </group>
    <group>
      <properties><name>Cert</name></properties>
      <encryptionSettings inherit="None"><encryptionMethod>Certificate</encryptionMethod><credentialName>c</credentialName><credentialData>AB12</credentialData></encryptionSettings>
      <server>
        <properties><name>cert.lab</name></properties>
        <logonCredentials inherit="None"><profileName scope="Local">Custom</profileName><userName>c</userName><password>{cert}</password><domain>D</domain></logonCredentials>
      </server>
    </group>
  </file>
  <connected /><favorites /><recentlyUsed />
</RDCMan>"#,
        ops = me16("ops-pw"),
        root = me16("root-pw"),
        other = b64(b"OTHER-USER-BLOB"),
        cert = b64(b"rsa"),
    )
}

#[test]
fn rdcman_schema3_groups_profiles_and_settings() {
    let file = rdg3();
    assert_eq!(
        probe(file.as_bytes()).unwrap(),
        Probe {
            format: Format::RdcMan,
            needs_password: false
        }
    );
    let i = read(file.as_bytes(), "", &FakeDpapi).unwrap();
    let lab = by_path(&i, "Lab");
    assert_eq!(
        (lab.user.as_str(), lab.password.as_deref()),
        ("LAB\\root-user", Some("root-pw"))
    );
    // A file credential profile, matched without regard to case.
    let web = by_path(&i, "Lab/Web");
    assert_eq!(
        (web.user.as_str(), web.password.as_deref()),
        ("LAB\\operator", Some("ops-pw"))
    );

    let w1 = by_name(&i, "Web 1");
    assert_eq!(
        (w1.host.as_str(), w1.port, w1.group.as_str()),
        ("web1.lab", 3391, "Lab/Web")
    );
    assert!(w1.inherit.credentials && w1.password.is_none());
    assert_eq!(w1.gateway, "gw.lab");
    assert_eq!((w1.width, w1.height), (1600, 900));
    let o = &w1.options;
    assert!(o.sound && o.microphone && o.clipboard && o.smart_cards && !o.printers);

    let w2 = by_name(&i, "web2.lab");
    assert_eq!(w2.port, 4000);
    assert!(w2.inherit.credentials);
    assert_eq!((w2.width, w2.height, w2.gateway.as_str()), (0, 0, ""));
    // Its own localResources replace the file's as a whole.
    assert!(!w2.options.sound && !w2.options.clipboard);

    let away = by_name(&i, "away.lab");
    assert!(!away.inherit.credentials);
    assert_eq!((away.user.as_str(), away.password.as_deref()), ("me", None));
    let global = by_name(&i, "global.lab");
    assert_eq!(
        (global.user.as_str(), global.password.as_deref()),
        ("", None)
    );
    assert_eq!(by_name(&i, "cert.lab").password, None);

    assert_eq!(
        i.connections.len(),
        5,
        "smartGroup and serverRef are skipped"
    );
    let u = &i.report.unreadable;
    assert_eq!(u.get(&Unreadable::OtherUser), Some(&1));
    assert_eq!(u.get(&Unreadable::RdcmanSettings), Some(&1));
    assert_eq!(u.get(&Unreadable::Certificate), Some(&1));
    assert_eq!(i.report.not_rdp, 0);
}

#[test]
fn rdcman_schema1_properties_and_clear_text() {
    let file = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan schemaVersion="1">
  <version>2.2</version>
  <file>
    <properties>
      <name>Old</name>
      <logonCredentials inherit="None"><userName>admin</userName><domain>OLD</domain><password storeAsClearText="True">plain-pw</password></logonCredentials>
      <localResources inherit="None"><audioRedirection>0</audioRedirection><audioCaptureRedirection>1</audioCaptureRedirection><redirectClipboard>True</redirectClipboard></localResources>
    </properties>
    <group>
      <properties><name>G</name><logonCredentials inherit="FromParent" /></properties>
      <server>
        <name>s1</name>
        <displayName>Server One</displayName>
        <logonCredentials inherit="None"><userName>x\y</userName><domain>D</domain><password storeAsClearText="False">{pw}</password></logonCredentials>
        <connectionSettings inherit="None"><port>9933</port></connectionSettings>
        <remoteDesktop inherit="None"><size>1024 x 768</size><sameSizeAsClientArea>False</sameSizeAsClientArea><fullScreen>False</fullScreen></remoteDesktop>
      </server>
      <server><name>s2</name><displayName>s2</displayName><logonCredentials inherit="FromParent" /></server>
    </group>
  </file>
</RDCMan>"#,
        pw = me16("s1-pw")
    );
    let i = read(file.as_bytes(), "", &FakeDpapi).unwrap();
    let old = by_path(&i, "Old");
    assert_eq!(
        (old.user.as_str(), old.password.as_deref()),
        ("OLD\\admin", Some("plain-pw"))
    );
    let g = by_path(&i, "Old/G");
    assert_eq!(
        (g.user.as_str(), g.password.as_deref()),
        ("OLD\\admin", Some("plain-pw"))
    );
    let s1 = by_name(&i, "Server One");
    assert_eq!(
        (s1.host.as_str(), s1.port, s1.group.as_str()),
        ("s1", 9933, "Old/G")
    );
    assert_eq!(
        (s1.user.as_str(), s1.password.as_deref()),
        ("x\\y", Some("s1-pw"))
    );
    assert_eq!((s1.width, s1.height), (1024, 768));
    assert!(s1.options.sound && s1.options.microphone && s1.options.clipboard);
    assert!(by_name(&i, "s2").inherit.credentials);
    assert!(i.report.unreadable.is_empty());
}

#[test]
fn rdcman_unknown_schema_is_an_error() {
    let file = r#"<RDCMan schemaVersion="9"><file/></RDCMan>"#;
    assert!(
        read(file.as_bytes(), "", &FakeDpapi)
            .unwrap_err()
            .contains("schema version (9)")
    );
}

/// CryptProtectData for this Windows user, then the import reads it back.
#[cfg(windows)]
#[test]
#[ignore = "uses this Windows user's DPAPI keys"]
fn rdcman_dpapi_round_trip_for_this_user() {
    let utf16: Vec<u8> = "Pässwort-1"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let blob = crate::vault::dpapi::protect(&utf16).expect("CryptProtectData");
    let file = format!(
        r#"<RDCMan programVersion="2.93" schemaVersion="3"><file><properties><name>F</name></properties>
           <server><properties><name>h</name></properties>
           <logonCredentials inherit="None"><profileName scope="Local">Custom</profileName><userName>u</userName><password>{}</password><domain /></logonCredentials>
           </server></file></RDCMan>"#,
        b64(&blob)
    );
    let i = read(file.as_bytes(), "", &SystemDpapi).unwrap();
    assert_eq!(by_name(&i, "h").password.as_deref(), Some("Pässwort-1"));
}

// --- Common ------------------------------------------------------------------

#[test]
fn format_comes_from_the_content() {
    let key = crate::vault::derive(
        "pw",
        crate::vault::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            salt: [1; 16],
        },
    )
    .unwrap();
    let backup = crate::vault::seal(&key, br#"{"version":5,"groups":[],"connections":[{"name":"n","host":"h","port":3389,"user":"","width":0,"height":0}]}"#);
    assert_eq!(
        probe(&backup).unwrap(),
        Probe {
            format: Format::Remora,
            needs_password: true
        }
    );
    assert!(read(&backup, "", &FakeDpapi).is_err());
    assert_eq!(
        read(&backup, "pw", &FakeDpapi).unwrap().connections.len(),
        1
    );

    for junk in [
        &b"hello"[..],
        b"<html><body/></html>",
        b"\x00\x01\x02",
        b"<a/><b/>",
    ] {
        assert!(probe(junk).is_err());
    }
}

#[test]
fn summary_names_what_did_not_come_over() {
    let mut r = Report::default();
    assert_eq!(r.summary(1), "Imported 1 connection.");
    r.not_rdp = 3;
    r.ssh_passwords = 1;
    r.duplicates = 2;
    r.unreadable(Unreadable::OtherUser);
    r.no_vault = 4;
    assert_eq!(
        r.summary(12),
        "Imported 12 connections. Skipped 3 that aren't RDP or SSH and 2 already here. \
         1 password could not be read: saved by another Windows user or PC. \
         4 passwords left out: set up a master password under Security to import passwords. \
         1 SSH password left out: ssh asks for it in the terminal."
    );
    r.unreadable(Unreadable::Certificate);
    assert!(r.summary(0).contains(
        "2 passwords could not be read: 1 saved by another Windows user or PC, 1 encrypted with a certificate."
    ));
}

#[test]
fn passwords_are_dropped_and_counted_without_a_vault() {
    let file = mrng_file("mR3m", r#"ConfVersion="2.8""#, &mrng_nodes("mR3m"));
    let mut i = read(&file, "", &FakeDpapi).unwrap();
    i.drop_passwords();
    check_mrng_tree(&i, false);
    // Work and Work/Servers-Prod (a group each) and own.
    assert_eq!(i.report.no_vault, 3);
}

#[test]
fn helpers() {
    assert_eq!(user_with_domain("u", "D"), "D\\u");
    assert_eq!(user_with_domain("u@x", "D"), "u@x");
    assert_eq!(user_with_domain("", "D"), "");
    assert_eq!(split_host_port("h:3390"), ("h".into(), Some(3390)));
    assert_eq!(
        split_host_port("[fe80::1]:3390"),
        ("fe80::1".into(), Some(3390))
    );
    assert_eq!(split_host_port("fe80::1"), ("fe80::1".into(), None));
    assert_eq!(parse_size("1920 x 1080"), Some((1920, 1080)));
    assert_eq!(parse_size("FitToWindow"), None);
}
