//! [`WinSCard`]: the smart card redirection backend (RDP-8) on the Windows
//! smart card API (winscard.dll). Every call maps to one SCard*W function;
//! return codes go to the server unchanged (MS-RDPESC 3.1.4). No card data
//! is logged.

/// The local PC/SC layer for [`rdp::smart_card_device`].
#[allow(dead_code)] // wired in by RDP-3 integration
#[derive(Default)]
pub struct WinSCard;

#[cfg(windows)]
#[allow(dead_code)] // wired in by RDP-3 integration
mod win {
    use std::ptr::{null, null_mut};

    use rdp::SmartCardBackend;
    use rdp::rdpdr::smartcard::{
        CardStatus, IoPci, ReaderState, SCARD_E_INSUFFICIENT_BUFFER, SCARD_E_NO_SERVICE, ScResult,
        Transmitted,
    };
    use windows_sys::Win32::Security::Credentials::*;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    use super::WinSCard;

    /// How long AccessStartedEvent waits for the smart card service.
    const SERVICE_WAIT_MS: u32 = 10_000;
    const WAIT_OBJECT_0: u32 = 0;
    /// Size of SCARD_IO_REQUEST (dwProtocol, cbPciLength).
    const PCI_HEADER: usize = 8;

    fn check(rc: i32) -> ScResult<()> {
        if rc == 0 { Ok(()) } else { Err(rc as u32) }
    }

    fn wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// A UTF-16 multi-string into its names.
    fn split_multi(units: &[u16]) -> Vec<String> {
        units
            .split(|&u| u == 0)
            .take_while(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    /// A SCARD_IO_REQUEST followed by its protocol control bytes, 4-byte
    /// aligned as the API expects.
    fn pci_buffer(protocol: u32, extra: &[u8], capacity: usize) -> Vec<u32> {
        let len = PCI_HEADER + extra.len().max(capacity);
        let mut words = vec![0u32; len.div_ceil(4)];
        words[0] = protocol;
        words[1] = (PCI_HEADER + extra.len()) as u32;
        let bytes: &mut [u8] = words_as_bytes(&mut words);
        bytes[PCI_HEADER..PCI_HEADER + extra.len()].copy_from_slice(extra);
        words
    }

    fn words_as_bytes(words: &mut [u32]) -> &mut [u8] {
        // SAFETY: u32 has no padding and any byte pattern is a valid u32;
        // the slice covers exactly the words' memory.
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), words.len() * 4) }
    }

    fn handle(v: u64) -> usize {
        v as usize
    }

    impl SmartCardBackend for WinSCard {
        fn access_started(&self) -> ScResult<()> {
            // SAFETY: no arguments; the event is released below.
            let event = unsafe { SCardAccessStartedEvent() };
            if event.is_null() {
                return Err(SCARD_E_NO_SERVICE);
            }
            // SAFETY: a valid event handle owned by winscard until released.
            let r = unsafe { WaitForSingleObject(event, SERVICE_WAIT_MS) };
            // SAFETY: pairs the SCardAccessStartedEvent above.
            unsafe { SCardReleaseStartedEvent() };
            if r == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err(SCARD_E_NO_SERVICE)
            }
        }

        fn establish_context(&self, scope: u32) -> ScResult<u64> {
            let mut ctx = 0usize;
            // SAFETY: out pointer to a local.
            check(unsafe { SCardEstablishContext(scope, null(), null(), &mut ctx) })?;
            Ok(ctx as u64)
        }

        fn release_context(&self, context: u64) -> ScResult<()> {
            // SAFETY: plain handle argument; winscard validates it.
            check(unsafe { SCardReleaseContext(handle(context)) })
        }

        fn is_valid_context(&self, context: u64) -> ScResult<()> {
            // SAFETY: plain handle argument.
            check(unsafe { SCardIsValidContext(handle(context)) })
        }

        fn list_readers(&self, context: u64, groups: &[String]) -> ScResult<Vec<String>> {
            let groups: Option<Vec<u16>> = (!groups.is_empty()).then(|| {
                let mut v: Vec<u16> = groups.iter().flat_map(|g| wide_z(g)).collect();
                v.push(0);
                v
            });
            let gp = groups.as_ref().map_or(null(), |g| g.as_ptr());
            // The list can grow between the size query and the read: retry.
            for _ in 0..3 {
                let mut cch = 0u32;
                // SAFETY: size query with a null buffer.
                check(unsafe { SCardListReadersW(handle(context), gp, null_mut(), &mut cch) })?;
                let mut buf = vec![0u16; cch as usize];
                // SAFETY: `buf` holds `cch` characters.
                let rc =
                    unsafe { SCardListReadersW(handle(context), gp, buf.as_mut_ptr(), &mut cch) };
                if rc as u32 == SCARD_E_INSUFFICIENT_BUFFER {
                    continue;
                }
                check(rc)?;
                buf.truncate(cch as usize);
                return Ok(split_multi(&buf));
            }
            Err(SCARD_E_INSUFFICIENT_BUFFER)
        }

        fn get_status_change(
            &self,
            context: u64,
            timeout_ms: u32,
            states: &mut [ReaderState],
        ) -> ScResult<()> {
            let names: Vec<Vec<u16>> = states.iter().map(|s| wide_z(&s.reader)).collect();
            let mut raw: Vec<SCARD_READERSTATEW> = states
                .iter()
                .zip(&names)
                .map(|(s, n)| {
                    let mut r = SCARD_READERSTATEW {
                        szReader: n.as_ptr(),
                        dwCurrentState: s.current_state,
                        cbAtr: s.atr.len().min(36) as u32,
                        ..Default::default()
                    };
                    r.rgbAtr[..r.cbAtr as usize].copy_from_slice(&s.atr[..r.cbAtr as usize]);
                    r
                })
                .collect();
            // SAFETY: `raw` and the names it points into outlive the call.
            check(unsafe {
                SCardGetStatusChangeW(
                    handle(context),
                    timeout_ms,
                    raw.as_mut_ptr(),
                    raw.len() as u32,
                )
            })?;
            for (s, r) in states.iter_mut().zip(&raw) {
                s.event_state = r.dwEventState;
                s.atr = r.rgbAtr[..(r.cbAtr as usize).min(36)].to_vec();
            }
            Ok(())
        }

        fn cancel(&self, context: u64) -> ScResult<()> {
            // SAFETY: plain handle argument.
            check(unsafe { SCardCancel(handle(context)) })
        }

        fn connect(
            &self,
            context: u64,
            reader: &str,
            share_mode: u32,
            protocols: u32,
        ) -> ScResult<(u64, u32)> {
            let name = wide_z(reader);
            let (mut card, mut active) = (0usize, 0u32);
            // SAFETY: null-terminated name; out pointers to locals.
            check(unsafe {
                SCardConnectW(
                    handle(context),
                    name.as_ptr(),
                    share_mode,
                    protocols,
                    &mut card,
                    &mut active,
                )
            })?;
            Ok((card as u64, active))
        }

        fn reconnect(&self, card: u64, share: u32, protocols: u32, init: u32) -> ScResult<u32> {
            let mut active = 0u32;
            // SAFETY: out pointer to a local.
            check(unsafe { SCardReconnect(handle(card), share, protocols, init, &mut active) })?;
            Ok(active)
        }

        fn disconnect(&self, card: u64, disposition: u32) -> ScResult<()> {
            // SAFETY: plain handle argument.
            check(unsafe { SCardDisconnect(handle(card), disposition) })
        }

        fn begin_transaction(&self, card: u64) -> ScResult<()> {
            // SAFETY: plain handle argument.
            check(unsafe { SCardBeginTransaction(handle(card)) })
        }

        fn end_transaction(&self, card: u64, disposition: u32) -> ScResult<()> {
            // SAFETY: plain handle argument.
            check(unsafe { SCardEndTransaction(handle(card), disposition) })
        }

        fn status(&self, card: u64) -> ScResult<CardStatus> {
            let (mut state, mut protocol) = (0u32, 0u32);
            let mut atr = [0u8; 36];
            for _ in 0..3 {
                let (mut cch, mut cb_atr) = (0u32, atr.len() as u32);
                // SAFETY: size query for the names; ATR buffer of `cb_atr`.
                check(unsafe {
                    SCardStatusW(
                        handle(card),
                        null_mut(),
                        &mut cch,
                        &mut state,
                        &mut protocol,
                        atr.as_mut_ptr(),
                        &mut cb_atr,
                    )
                })?;
                let mut names = vec![0u16; cch as usize];
                cb_atr = atr.len() as u32;
                // SAFETY: `names` holds `cch` characters, `atr` `cb_atr` bytes.
                let rc = unsafe {
                    SCardStatusW(
                        handle(card),
                        names.as_mut_ptr(),
                        &mut cch,
                        &mut state,
                        &mut protocol,
                        atr.as_mut_ptr(),
                        &mut cb_atr,
                    )
                };
                if rc as u32 == SCARD_E_INSUFFICIENT_BUFFER {
                    continue;
                }
                check(rc)?;
                names.truncate(cch as usize);
                return Ok(CardStatus {
                    readers: split_multi(&names),
                    state,
                    protocol,
                    atr: atr[..(cb_atr as usize).min(atr.len())].to_vec(),
                });
            }
            Err(SCARD_E_INSUFFICIENT_BUFFER)
        }

        fn transmit(
            &self,
            card: u64,
            send_pci: &IoPci,
            send: &[u8],
            recv_pci: Option<&IoPci>,
            recv_max: usize,
        ) -> ScResult<Transmitted> {
            let send_buf = pci_buffer(send_pci.protocol, &send_pci.extra, 0);
            let mut recv_buf = recv_pci.map(|p| pci_buffer(p.protocol, &p.extra, p.extra.len()));
            let recv_ptr = recv_buf
                .as_mut()
                .map_or(null_mut(), |b| b.as_mut_ptr().cast::<SCARD_IO_REQUEST>());
            let mut out = vec![0u8; recv_max];
            let mut len = recv_max as u32;
            // SAFETY: both PCI buffers start with an aligned SCARD_IO_REQUEST
            // whose cbPciLength covers the bytes after it; `out` holds `len`.
            check(unsafe {
                SCardTransmit(
                    handle(card),
                    send_buf.as_ptr().cast(),
                    send.as_ptr(),
                    send.len() as u32,
                    recv_ptr,
                    out.as_mut_ptr(),
                    &mut len,
                )
            })?;
            out.truncate(len as usize);
            let recv_pci = recv_buf.map(|mut b| {
                let protocol = b[0];
                let total = (b[1] as usize).clamp(PCI_HEADER, b.len() * 4);
                IoPci {
                    protocol,
                    extra: words_as_bytes(&mut b)[PCI_HEADER..total].to_vec(),
                }
            });
            Ok(Transmitted {
                recv_pci,
                data: out,
            })
        }

        fn control(&self, card: u64, code: u32, input: &[u8], out_max: usize) -> ScResult<Vec<u8>> {
            let mut out = vec![0u8; out_max];
            let mut len = 0u32;
            // SAFETY: input and output buffers with their exact lengths.
            check(unsafe {
                SCardControl(
                    handle(card),
                    code,
                    input.as_ptr().cast(),
                    input.len() as u32,
                    out.as_mut_ptr().cast(),
                    out_max as u32,
                    &mut len,
                )
            })?;
            out.truncate(len as usize);
            Ok(out)
        }

        fn get_attrib(&self, card: u64, attr: u32, max: usize) -> ScResult<Vec<u8>> {
            let mut out = vec![0u8; max];
            let mut len = max as u32;
            // SAFETY: `out` holds `len` bytes.
            check(unsafe { SCardGetAttrib(handle(card), attr, out.as_mut_ptr(), &mut len) })?;
            out.truncate(len as usize);
            Ok(out)
        }

        fn set_attrib(&self, card: u64, attr: u32, data: &[u8]) -> ScResult<()> {
            // SAFETY: `data` with its exact length.
            check(unsafe { SCardSetAttrib(handle(card), attr, data.as_ptr(), data.len() as u32) })
        }

        fn get_device_type_id(&self, context: u64, reader: &str) -> ScResult<u32> {
            let name = wide_z(reader);
            let mut id = 0u32;
            // SAFETY: null-terminated name; out pointer to a local.
            check(unsafe { SCardGetDeviceTypeIdW(handle(context), name.as_ptr(), &mut id) })?;
            Ok(id)
        }
    }
}
