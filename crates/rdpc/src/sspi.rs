//! Kerberos for NLA: the Windows SSPI "Negotiate" package (Kerberos, with
//! NTLM as SPNEGO's fallback) as the CredSSP security package
//! ([`rdp::AuthPackage`]). MS-CSSP 3.1.5 treats the package's tokens and its
//! encryption as opaque, so SSPI does all of it; CredSSP itself stays in the
//! `rdp` crate.
//!
//! - Credentials: AcquireCredentialsHandleW with an explicit
//!   SEC_WINNT_AUTH_IDENTITY_W when a password is given, otherwise the
//!   logged-on user's (single sign-on).
//! - Context: InitializeSecurityContextW for the service `TERMSRV/<host>`
//!   (the Remote Desktop service principal name).
//! - wrap: EncryptMessage over a token buffer of `cbSecurityTrailer` bytes
//!   and the data buffer; the wire blob is token then data.
//! - unwrap: DecryptMessage. Kerberos tokens vary in size, so a Kerberos
//!   blob goes in as one SECBUFFER_STREAM that SSPI splits (SSPI/Kerberos
//!   interoperability with GSSAPI); NTLM's fixed 16-byte signature is split
//!   off as the token buffer.
//!
//! Nothing here traces tokens, keys or passwords; errors carry status codes.

use std::ptr::{null, null_mut};
use std::sync::Arc;

use rdp::{AuthFactory, AuthPackage, AuthParams, Step};
use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE};
use windows_sys::Win32::Foundation::{SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W};
use zeroize::Zeroizing;

/// Context requirements: mutual authentication when Kerberos is used,
/// confidentiality for pubKeyAuth and authInfo, integrity, and delegation as
/// CredSSP asks for; SSPI allocates the output tokens.
const ISC_FLAGS: u32 = ISC_REQ_MUTUAL_AUTH
    | ISC_REQ_CONFIDENTIALITY
    | ISC_REQ_INTEGRITY
    | ISC_REQ_DELEGATE
    | ISC_REQ_ALLOCATE_MEMORY;
/// ISC_RET_CONFIDENTIALITY: the established context can encrypt.
const RET_CONFIDENTIALITY: u32 = 0x10;
/// The quality of protection DecryptMessage reports for signed-only data.
const SECQOP_WRAP_NO_ENCRYPT: u32 = 0x8000_0001;

/// Builds a Negotiate package per connection.
pub fn factory() -> AuthFactory {
    Arc::new(|p: &AuthParams<'_>| Ok(Box::new(Negotiate::new(p)?) as Box<dyn AuthPackage>))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn failed(what: &str, status: i32) -> rdp::Error {
    rdp::Error::Auth(format!("SSPI {what} failed with {:#010x}", status as u32))
}

/// A credentials handle and, once started, a security context.
pub struct Negotiate {
    cred: SecHandle,
    ctx: Option<SecHandle>,
    /// `TERMSRV/<host>`, NUL-terminated.
    target: Vec<u16>,
    sizes: SecPkgContext_Sizes,
    /// Decrypt as one SECBUFFER_STREAM: every negotiated package but NTLM.
    stream: bool,
}

// SSPI handles are opaque values owned by this process, usable from any thread.
unsafe impl Send for Negotiate {}

impl Negotiate {
    pub fn new(p: &AuthParams<'_>) -> rdp::Result<Self> {
        let cred = acquire(p)?;
        let mut target = wide(&format!("TERMSRV/{}", p.host));
        target.push(0);
        Ok(Self {
            cred,
            ctx: None,
            target,
            sizes: SecPkgContext_Sizes::default(),
            stream: false,
        })
    }

    fn ctx(&self) -> rdp::Result<&SecHandle> {
        self.ctx
            .as_ref()
            .ok_or_else(|| rdp::Error::Auth("SSPI context not established".into()))
    }

    /// Reads the sizes and the negotiated package once the context is done.
    fn established(&mut self, attrs: u32) -> rdp::Result<()> {
        if attrs & RET_CONFIDENTIALITY == 0 {
            return Err(rdp::Error::Auth(
                "SSPI context without confidentiality".into(),
            ));
        }
        let ctx = *self.ctx()?;
        let st = unsafe {
            QueryContextAttributesW(
                &ctx,
                SECPKG_ATTR_SIZES,
                (&mut self.sizes as *mut SecPkgContext_Sizes).cast(),
            )
        };
        if st != SEC_E_OK {
            return Err(failed("QueryContextAttributes(SIZES)", st));
        }
        let mut info = SecPkgContext_NegotiationInfoW::default();
        let st = unsafe {
            QueryContextAttributesW(
                &ctx,
                SECPKG_ATTR_NEGOTIATION_INFO,
                (&mut info as *mut SecPkgContext_NegotiationInfoW).cast(),
            )
        };
        if st == SEC_E_OK && !info.PackageInfo.is_null() {
            let name = unsafe { wide_cstr((*info.PackageInfo).Name) };
            self.stream = !name.eq_ignore_ascii_case("NTLM");
            rdp::trace!("SSPI: negotiated {name}");
            unsafe { FreeContextBuffer(info.PackageInfo.cast()) };
        }
        Ok(())
    }
}

/// A NUL-terminated UTF-16 string from SSPI.
unsafe fn wide_cstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

fn acquire(p: &AuthParams<'_>) -> rdp::Result<SecHandle> {
    let package = wide("Negotiate\0");
    let mut user = wide(p.user);
    let mut domain = wide(p.domain);
    let mut password = Zeroizing::new(wide(p.password));
    let mut identity = SEC_WINNT_AUTH_IDENTITY_W {
        User: user.as_mut_ptr(),
        UserLength: user.len() as u32,
        Domain: domain.as_mut_ptr(),
        DomainLength: domain.len() as u32,
        Password: password.as_mut_ptr(),
        PasswordLength: password.len() as u32,
        Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };
    // Without a password: the logged-on user's credentials (single sign-on).
    let auth_data: *const core::ffi::c_void = if p.password.is_empty() {
        null()
    } else {
        (&mut identity as *mut SEC_WINNT_AUTH_IDENTITY_W).cast()
    };
    let mut cred = SecHandle::default();
    let mut expiry = 0i64;
    let st = unsafe {
        AcquireCredentialsHandleW(
            null(),
            package.as_ptr(),
            SECPKG_CRED_OUTBOUND,
            null(),
            auth_data,
            None,
            null(),
            &mut cred,
            &mut expiry,
        )
    };
    if st != SEC_E_OK {
        return Err(failed("AcquireCredentialsHandle(Negotiate)", st));
    }
    Ok(cred)
}

impl AuthPackage for Negotiate {
    fn step(&mut self, input: Option<&[u8]>) -> rdp::Result<Step> {
        let mut in_data = input.map(<[u8]>::to_vec).unwrap_or_default();
        let mut in_buf = SecBuffer {
            cbBuffer: in_data.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: in_data.as_mut_ptr().cast(),
        };
        let in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf,
        };
        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };
        let old = self.ctx;
        let mut new_ctx = old.unwrap_or_default();
        let mut attrs = 0u32;
        let mut expiry = 0i64;
        let st = unsafe {
            InitializeSecurityContextW(
                &self.cred,
                old.as_ref().map_or(null(), |c| c as *const SecHandle),
                self.target.as_ptr(),
                ISC_FLAGS,
                0,
                SECURITY_NATIVE_DREP,
                if input.is_some() { &in_desc } else { null() },
                0,
                &mut new_ctx,
                &mut out_desc,
                &mut attrs,
                &mut expiry,
            )
        };
        if old.is_none() && (st >= 0) {
            self.ctx = Some(new_ctx);
        }
        // CompleteAuthToken finishes the output token in place, before it is
        // copied out and its SSPI allocation freed.
        let mut status = st;
        if st == SEC_I_COMPLETE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE {
            let c = *self.ctx()?;
            let done = unsafe { CompleteAuthToken(&c, &out_desc) };
            if done != SEC_E_OK {
                status = done;
            }
        }
        let token = if out_buf.pvBuffer.is_null() {
            Vec::new()
        } else {
            let t = unsafe {
                std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize)
            }
            .to_vec();
            unsafe { FreeContextBuffer(out_buf.pvBuffer) };
            t
        };
        if st < 0 {
            return Err(failed("InitializeSecurityContext", st));
        }
        if status != st {
            return Err(failed("CompleteAuthToken", status));
        }
        let done = st == SEC_E_OK || st == SEC_I_COMPLETE_NEEDED;
        if !done && st != SEC_I_CONTINUE_NEEDED && st != SEC_I_COMPLETE_AND_CONTINUE {
            return Err(failed("InitializeSecurityContext (unexpected status)", st));
        }
        if done {
            self.established(attrs)?;
        }
        Ok(Step { token, done })
    }

    fn wrap(&mut self, data: &[u8]) -> rdp::Result<Vec<u8>> {
        let ctx = *self.ctx()?;
        let mut token = vec![0u8; self.sizes.cbSecurityTrailer as usize];
        let mut body = data.to_vec();
        let mut bufs = [
            SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_mut_ptr().cast(),
            },
            SecBuffer {
                cbBuffer: body.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: body.as_mut_ptr().cast(),
            },
        ];
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: bufs.len() as u32,
            pBuffers: bufs.as_mut_ptr(),
        };
        let st = unsafe { EncryptMessage(&ctx, 0, &desc, 0) };
        if st != SEC_E_OK {
            return Err(failed("EncryptMessage", st));
        }
        // The package may use less of the token buffer than the trailer size.
        token.truncate(bufs[0].cbBuffer as usize);
        body.truncate(bufs[1].cbBuffer as usize);
        token.extend_from_slice(&body);
        Ok(token)
    }

    fn unwrap(&mut self, data: &[u8]) -> rdp::Result<Vec<u8>> {
        let ctx = *self.ctx()?;
        let mut blob = data.to_vec();
        let split = self.sizes.cbSecurityTrailer as usize;
        let mut bufs = if self.stream {
            [
                SecBuffer {
                    cbBuffer: blob.len() as u32,
                    BufferType: SECBUFFER_STREAM,
                    pvBuffer: blob.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: 0,
                    BufferType: SECBUFFER_DATA,
                    pvBuffer: null_mut(),
                },
            ]
        } else {
            if blob.len() < split {
                return Err(rdp::Error::Auth("sealed message too short".into()));
            }
            let (tok, body) = blob.split_at_mut(split);
            [
                SecBuffer {
                    cbBuffer: tok.len() as u32,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: tok.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: body.len() as u32,
                    BufferType: SECBUFFER_DATA,
                    pvBuffer: body.as_mut_ptr().cast(),
                },
            ]
        };
        let desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: bufs.len() as u32,
            pBuffers: bufs.as_mut_ptr(),
        };
        let mut qop = 0u32;
        let st = unsafe { DecryptMessage(&ctx, &desc, 0, &mut qop) };
        if st != SEC_E_OK {
            return Err(failed("DecryptMessage", st));
        }
        if qop == SECQOP_WRAP_NO_ENCRYPT {
            return Err(rdp::Error::Auth("server message was not encrypted".into()));
        }
        // The data buffer points into `blob`, decrypted in place.
        let out = &bufs[1];
        if out.pvBuffer.is_null() {
            return Err(rdp::Error::Auth("DecryptMessage returned no data".into()));
        }
        Ok(
            unsafe { std::slice::from_raw_parts(out.pvBuffer as *const u8, out.cbBuffer as usize) }
                .to_vec(),
        )
    }
}

impl Drop for Negotiate {
    fn drop(&mut self) {
        unsafe {
            if let Some(c) = self.ctx.take() {
                DeleteSecurityContext(&c);
            }
            FreeCredentialsHandle(&self.cred);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acquires a Negotiate credentials handle for the logged-on user and
    /// frees it. No context is started, so no server or KDC is contacted.
    #[test]
    #[ignore = "uses the logged-on Windows account's SSPI credentials"]
    fn acquires_and_frees_current_user_credentials() {
        let p = AuthParams {
            host: "localhost",
            user: "",
            domain: "",
            password: "",
            workstation: "",
        };
        let n = Negotiate::new(&p).expect("Negotiate credentials for the current user");
        assert!(n.cred.dwLower != 0 || n.cred.dwUpper != 0);
        assert_eq!(n.target.last(), Some(&0));
        drop(n);
    }
}
