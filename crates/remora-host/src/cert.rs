//! The host's TLS identity: a self-signed certificate made on first run,
//! kept in the data directory with its private key protected.
//!
//! - `host-cert.der`: the certificate (public).
//! - `host-key.bin`: `"RHK1"`, a `u32` little-endian length, then the
//!   protected PKCS#8 private key. On Windows the protection is DPAPI in
//!   user scope (only this user on this machine can unprotect it, as
//!   remora-agent's key); elsewhere the key is stored as is in a 0600 file
//!   in a 0700 directory, the usual protection of an SSH host key.
//!
//! A key file that is damaged or cannot be unprotected (another user,
//! another machine) is kept as `host-key.bin.old` and a new identity is
//! made: the fingerprint changes and clients warn, which is right, the old
//! key is gone. A file that cannot be read for another reason is an error,
//! never a silent new key.

use std::io;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"RHK1";

/// Protects the private key at rest.
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>>;
}

/// No protection beyond the file's permissions (non-Windows platforms).
pub struct FileModeOnly;

impl Protector for FileModeOnly {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        Ok(plain.to_vec())
    }
    fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
        Ok(blob.to_vec())
    }
}

/// The platform's protector: DPAPI on Windows, file modes elsewhere.
pub fn platform_protector() -> Box<dyn Protector> {
    #[cfg(windows)]
    {
        Box::new(dpapi::Dpapi)
    }
    #[cfg(not(windows))]
    {
        Box::new(FileModeOnly)
    }
}

/// How the identity came to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Loaded,
    Created,
    /// The old key was unusable (the reason) and a new identity was made.
    Replaced(String),
}

/// The certificate and its private key.
pub struct Identity {
    pub certificate: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub origin: Origin,
}

impl Identity {
    /// SHA-256 of the certificate as "AB:CD:...", the form Remora shows
    /// when it asks whether to trust a server.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.certificate)
    }
}

/// SHA-256 of a DER certificate as colon-separated hex.
pub fn fingerprint(der: &[u8]) -> String {
    rdp::crypto::sha256(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join("host-cert.der")
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("host-key.bin")
}

/// The name in the certificate: the computer's name, else "remora-host".
fn host_name() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "remora-host".into())
}

/// A new self-signed certificate: ECDSA P-256, the host name as subject
/// and DNS name, server authentication, valid 2020 to 2045.
pub fn generate() -> io::Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, date_time_ymd,
    };
    let err = |e: rcgen::Error| io::Error::other(format!("cannot make the certificate: {e}"));
    let name = host_name();
    let key = KeyPair::generate().map_err(err)?;
    let mut params = CertificateParams::new(vec![name.clone()]).map_err(err)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2045, 1, 1);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).map_err(err)?;
    Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
}

fn encode_key_file(blob: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend((blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
    out
}

fn decode_key_file(data: &[u8]) -> Result<&[u8], &'static str> {
    if data.len() < 8 || &data[..4] != MAGIC {
        return Err("not a host key file");
    }
    let len = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) as usize;
    if data.len() != 8 + len {
        return Err("host key file has the wrong length");
    }
    Ok(&data[8..])
}

/// Reads the certificate and key; Err(reason) when they are unusable, an
/// io::Error when a file cannot be read at all.
fn load(dir: &Path, protector: &dyn Protector) -> io::Result<Result<Identity, String>> {
    let certificate = std::fs::read(cert_path(dir))?;
    let data = std::fs::read(key_path(dir))?;
    let blob = match decode_key_file(&data) {
        Ok(b) => b,
        Err(e) => return Ok(Err(e.into())),
    };
    let key = match protector.unprotect(blob) {
        Ok(k) => Zeroizing::new(k),
        Err(e) => return Ok(Err(format!("cannot decrypt the key: {e}"))),
    };
    // rustls checks that the key loads and belongs to the certificate.
    if let Err(e) = rdp::server::tls_config(certificate.clone(), key.to_vec()) {
        return Ok(Err(format!("key and certificate do not fit: {e}")));
    }
    Ok(Ok(Identity {
        certificate,
        private_key: key,
        origin: Origin::Loaded,
    }))
}

fn save(dir: &Path, protector: &dyn Protector, cert: &[u8], key: &[u8]) -> io::Result<()> {
    let blob = protector.protect(key)?;
    crate::paths::write_private(&key_path(dir), &encode_key_file(&blob))?;
    crate::paths::write_private(&cert_path(dir), cert)
}

/// Loads the identity, or makes and stores a new one.
pub fn load_or_create(dir: &Path, protector: &dyn Protector) -> io::Result<Identity> {
    let have_cert = cert_path(dir).exists();
    let have_key = key_path(dir).exists();
    let origin = match (have_cert, have_key) {
        (false, false) => Origin::Created,
        (true, true) => match load(dir, protector)? {
            Ok(id) => return Ok(id),
            Err(why) => Origin::Replaced(why),
        },
        (true, false) => Origin::Replaced("the key file is missing".into()),
        (false, true) => Origin::Replaced("the certificate file is missing".into()),
    };
    if have_key {
        let mut old = key_path(dir).into_os_string();
        old.push(".old");
        std::fs::rename(key_path(dir), old)?;
    }
    let (certificate, private_key) = generate()?;
    save(dir, protector, &certificate, &private_key)?;
    Ok(Identity {
        certificate,
        private_key,
        origin,
    })
}

#[cfg(windows)]
mod dpapi {
    //! DPAPI (`CryptProtectData`, user scope) for the host key, in memory.

    use std::io;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    /// Extra entropy: another program of the user needs it too to unprotect
    /// the file (a speed bump, not a boundary).
    const ENTROPY: &[u8] = b"Remora Host TLS key v1";

    pub struct Dpapi;

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr().cast_mut(),
        }
    }

    /// Copies, wipes and frees a DPAPI output blob.
    ///
    /// # Safety
    /// `out` must come from a successful CryptProtectData/CryptUnprotectData.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: per the caller; DPAPI LocalAlloc'd the buffer.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData.cast());
            v
        }
    }

    impl super::Protector for Dpapi {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let input = blob(plain);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: valid input blobs; DPAPI allocates `out`.
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful call.
            Ok(unsafe { take(out) })
        }

        fn unprotect(&self, data: &[u8]) -> io::Result<Vec<u8>> {
            let input = blob(data);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: valid input blobs; DPAPI allocates `out`.
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful call.
            Ok(unsafe { take(out) })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::Protector;
        use super::*;

        /// In memory only: no file is written.
        #[test]
        fn round_trip_and_tamper() {
            let plain = b"a PKCS#8 key would be here";
            let sealed = Dpapi.protect(plain).unwrap();
            assert!(!sealed.windows(plain.len()).any(|w| w == plain));
            assert_eq!(Dpapi.unprotect(&sealed).unwrap(), plain);
            let mut bad = sealed.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(Dpapi.unprotect(&bad).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XOR with a byte plus a tag, so "another user" (another byte) fails.
    struct Fake(u8);

    impl Protector for Fake {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let mut v = vec![b'T', self.0];
            v.extend(plain.iter().map(|b| b ^ self.0));
            Ok(v)
        }
        fn unprotect(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
            if blob.len() < 2 || blob[..2] != [b'T', self.0] {
                return Err(io::Error::other("bad blob"));
            }
            Ok(blob[2..].iter().map(|b| b ^ self.0).collect())
        }
    }

    fn temp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("remora-host-cert-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn created_once_then_loaded() {
        let dir = temp("roundtrip");
        let a = load_or_create(&dir, &Fake(0x5A)).unwrap();
        assert_eq!(a.origin, Origin::Created);
        // A usable server identity.
        rdp::server::tls_config(a.certificate.clone(), a.private_key.to_vec()).unwrap();
        let b = load_or_create(&dir, &Fake(0x5A)).unwrap();
        assert_eq!(b.origin, Origin::Loaded);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 32 * 3 - 1);
        // The key is not in the file in the clear.
        let file = std::fs::read(key_path(&dir)).unwrap();
        assert!(
            !file
                .windows(a.private_key.len())
                .any(|w| w == &a.private_key[..])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unusable_keys_are_replaced_and_kept() {
        let dir = temp("replace");
        let first = load_or_create(&dir, &Fake(1)).unwrap().fingerprint();
        // Another user's protector cannot read it.
        let r = load_or_create(&dir, &Fake(2)).unwrap();
        assert!(matches!(r.origin, Origin::Replaced(ref w) if w.contains("decrypt")));
        assert_ne!(r.fingerprint(), first);
        let mut old = key_path(&dir).into_os_string();
        old.push(".old");
        assert!(PathBuf::from(old).exists());
        // A damaged file.
        let mut data = std::fs::read(key_path(&dir)).unwrap();
        data.truncate(data.len() - 1);
        std::fs::write(key_path(&dir), &data).unwrap();
        let r2 = load_or_create(&dir, &Fake(2)).unwrap();
        assert!(matches!(r2.origin, Origin::Replaced(_)));
        assert_ne!(r2.fingerprint(), r.fingerprint());
        // And it loads again.
        assert_eq!(
            load_or_create(&dir, &Fake(2)).unwrap().origin,
            Origin::Loaded
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
