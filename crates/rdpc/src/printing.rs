//! [`WindowsSpooler`]: the local print system for printer redirection
//! (`rdp::rdpdr::printer`, MS-RDPEPC). Lists the local and connected
//! printers and spools the session's jobs with the Win32 spooler API, never
//! with a dialog. XPS jobs (Easy Print) go in as datatype `XPS_PASS` for
//! XPS-capable drivers (v4 or XPSDrv) and `XPS2GDI` for v3 GDI drivers, so
//! the spooler converts them; printer-language jobs go in as `RAW`.
#![allow(dead_code)] // wired in by RDP-3 integration

use std::collections::HashMap;

use rdp::rdpdr::printer::{PrintBackend, PrintFormat, PrinterInfo};

/// Print backend on the Windows spooler. Runs on the session worker; every
/// call is a spooler call without UI.
#[derive(Default)]
pub struct WindowsSpooler {
    /// Job handle to the printer handle its document was started on.
    jobs: HashMap<u64, usize>,
    next: u64,
}

#[cfg(windows)]
impl PrintBackend for WindowsSpooler {
    fn printers(&mut self) -> Vec<PrinterInfo> {
        win::printers()
    }

    fn start(&mut self, printer: &str, job_name: &str, format: PrintFormat) -> Result<u64, String> {
        let h = win::start(printer, job_name, format)?;
        self.next += 1;
        self.jobs.insert(self.next, h);
        Ok(self.next)
    }

    fn write(&mut self, job: u64, data: &[u8]) -> Result<(), String> {
        let h = *self.jobs.get(&job).ok_or("unknown job")?;
        win::write(h, data)
    }

    fn finish(&mut self, job: u64) -> Result<(), String> {
        let h = self.jobs.remove(&job).ok_or("unknown job")?;
        win::finish(h)
    }

    fn cancel(&mut self, job: u64) {
        if let Some(h) = self.jobs.remove(&job) {
            win::cancel(h);
        }
    }
}

#[cfg(not(windows))]
impl PrintBackend for WindowsSpooler {
    fn printers(&mut self) -> Vec<PrinterInfo> {
        Vec::new()
    }
    fn start(&mut self, _: &str, _: &str, _: PrintFormat) -> Result<u64, String> {
        Err("printing needs Windows".into())
    }
    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), String> {
        Err("printing needs Windows".into())
    }
    fn finish(&mut self, _: u64) -> Result<(), String> {
        Err("printing needs Windows".into())
    }
    fn cancel(&mut self, _: u64) {}
}

impl Drop for WindowsSpooler {
    fn drop(&mut self) {
        #[cfg(windows)]
        for (_, h) in self.jobs.drain() {
            win::cancel(h);
        }
    }
}

#[cfg(windows)]
mod win {
    use rdp::rdpdr::printer::{PrintFormat, PrinterInfo};
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Graphics::Printing::{
        AbortPrinter, ClosePrinter, DOC_INFO_1W, DRIVER_INFO_8W, EndDocPrinter, EnumPrintersW,
        GetDefaultPrinterW, GetPrinterDriverW, OpenPrinterW, PRINTER_DRIVER_XPS,
        PRINTER_ENUM_CONNECTIONS, PRINTER_ENUM_LOCAL, PRINTER_HANDLE, PRINTER_INFO_2W,
        StartDocPrinterW, WritePrinter,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// A null-terminated wide string; empty for null.
    ///
    /// # Safety
    /// `p` is null or points to a null-terminated UTF-16 string.
    unsafe fn from_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        // SAFETY: the caller guarantees a terminator.
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    fn error(op: &str) -> String {
        // SAFETY: no arguments.
        format!("{op} failed: error {}", unsafe { GetLastError() })
    }

    fn handle(h: usize) -> PRINTER_HANDLE {
        PRINTER_HANDLE { Value: h as _ }
    }

    /// A buffer of `bytes` bytes aligned for the spooler's structures.
    fn buffer(bytes: u32) -> Vec<u64> {
        vec![0u64; (bytes as usize).div_ceil(8).max(1)]
    }

    fn default_printer() -> Option<String> {
        let mut len = 0u32;
        // SAFETY: a null buffer with length 0 asks for the size.
        unsafe { GetDefaultPrinterW(std::ptr::null_mut(), &mut len) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        // SAFETY: `buf` holds `len` characters.
        if unsafe { GetDefaultPrinterW(buf.as_mut_ptr(), &mut len) } == 0 {
            return None;
        }
        // SAFETY: the call wrote a terminated name into `buf`.
        Some(unsafe { from_wide(buf.as_ptr()) })
    }

    /// Local and connected printers (PRINTER_INFO_2: name and driver).
    pub fn printers() -> Vec<PrinterInfo> {
        let flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
        let (mut needed, mut count) = (0u32, 0u32);
        // SAFETY: a null buffer of size 0 asks for the size.
        unsafe {
            EnumPrintersW(
                flags,
                std::ptr::null(),
                2,
                std::ptr::null_mut(),
                0,
                &mut needed,
                &mut count,
            )
        };
        if needed == 0 {
            return Vec::new();
        }
        let mut buf = buffer(needed);
        // SAFETY: `buf` holds `needed` bytes, aligned for PRINTER_INFO_2W.
        let ok = unsafe {
            EnumPrintersW(
                flags,
                std::ptr::null(),
                2,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
                &mut count,
            )
        };
        if ok == 0 {
            return Vec::new();
        }
        let default = default_printer();
        // SAFETY: the spooler wrote `count` PRINTER_INFO_2W at the start of
        // `buf`; their strings point into `buf`, which outlives this use.
        let infos = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().cast::<PRINTER_INFO_2W>(), count as usize)
        };
        infos
            .iter()
            .map(|i| {
                // SAFETY: see above.
                let (name, driver) =
                    unsafe { (from_wide(i.pPrinterName), from_wide(i.pDriverName)) };
                let is_default = default.as_deref() == Some(name.as_str());
                PrinterInfo {
                    name,
                    driver,
                    is_default,
                }
            })
            .filter(|p| !p.name.is_empty())
            .collect()
    }

    /// `XPS_PASS` for drivers that take XPS (v4, or XPSDrv per
    /// DRIVER_INFO_8 PRINTER_DRIVER_XPS), `XPS2GDI` for GDI drivers.
    fn xps_datatype(h: PRINTER_HANDLE) -> &'static str {
        let mut needed = 0u32;
        // SAFETY: a null buffer of size 0 asks for the size.
        unsafe { GetPrinterDriverW(h, std::ptr::null(), 8, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return "XPS_PASS";
        }
        let mut buf = buffer(needed);
        // SAFETY: `buf` holds `needed` bytes, aligned for DRIVER_INFO_8W.
        let ok = unsafe {
            GetPrinterDriverW(
                h,
                std::ptr::null(),
                8,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return "XPS_PASS";
        }
        // SAFETY: the spooler wrote a DRIVER_INFO_8W at the start of `buf`.
        let d = unsafe { &*buf.as_ptr().cast::<DRIVER_INFO_8W>() };
        if d.cVersion >= 4 || d.dwPrinterDriverAttributes & PRINTER_DRIVER_XPS != 0 {
            "XPS_PASS"
        } else {
            "XPS2GDI"
        }
    }

    /// Opens `printer` and starts a document; returns the printer handle.
    pub fn start(printer: &str, job_name: &str, format: PrintFormat) -> Result<usize, String> {
        let name = wide(printer);
        let mut h = PRINTER_HANDLE::default();
        // SAFETY: `name` is terminated; no PRINTER_DEFAULTS.
        if unsafe { OpenPrinterW(name.as_ptr(), &mut h, std::ptr::null()) } == 0 {
            return Err(error("OpenPrinter"));
        }
        let datatype = match format {
            PrintFormat::Xps => xps_datatype(h),
            PrintFormat::Raw => "RAW",
        };
        let mut doc_name = wide(job_name);
        let mut datatype = wide(datatype);
        let doc = DOC_INFO_1W {
            pDocName: doc_name.as_mut_ptr(),
            pOutputFile: std::ptr::null_mut(),
            pDatatype: datatype.as_mut_ptr(),
        };
        // SAFETY: `h` is open; `doc` points to live terminated strings.
        if unsafe { StartDocPrinterW(h, 1, &doc) } == 0 {
            let e = error("StartDocPrinter");
            // SAFETY: `h` is open and closed once.
            unsafe { ClosePrinter(h) };
            return Err(e);
        }
        Ok(h.Value as usize)
    }

    pub fn write(h: usize, mut data: &[u8]) -> Result<(), String> {
        while !data.is_empty() {
            let chunk = data.len().min(u32::MAX as usize);
            let mut written = 0u32;
            // SAFETY: `h` has a started document; `data` holds `chunk` bytes.
            let ok = unsafe {
                WritePrinter(handle(h), data.as_ptr().cast(), chunk as u32, &mut written)
            };
            if ok == 0 || written == 0 {
                return Err(error("WritePrinter"));
            }
            data = &data[(written as usize).min(data.len())..];
        }
        Ok(())
    }

    /// Ends the document (it prints) and closes the printer.
    pub fn finish(h: usize) -> Result<(), String> {
        // SAFETY: `h` has a started document; it is closed once here.
        unsafe {
            let ok = EndDocPrinter(handle(h));
            let e = (ok == 0).then(|| error("EndDocPrinter"));
            ClosePrinter(handle(h));
            e.map_or(Ok(()), Err)
        }
    }

    /// Deletes the document (nothing prints) and closes the printer.
    pub fn cancel(h: usize) {
        // SAFETY: `h` has a started document; it is closed once here.
        unsafe {
            AbortPrinter(handle(h));
            ClosePrinter(handle(h));
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Read-only: enumerates the real spooler, never starts a document.
    #[test]
    #[ignore = "reads the machine's printer list"]
    fn lists_local_printers() {
        let list = WindowsSpooler::default().printers();
        for p in &list {
            println!("{p:?}");
            assert!(!p.name.is_empty());
        }
        assert!(list.iter().filter(|p| p.is_default).count() <= 1);
    }
}
