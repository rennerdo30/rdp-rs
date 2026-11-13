//! The file system device (MS-RDPEFS 2.2.3.3 / 2.2.3.4, 3.2.5.2) mapped to
//! `std::fs`. Every server path goes through [`super::path::resolve`].

use std::collections::HashMap;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::fscc::*;
use super::path::{self, wildcard_match};
use super::{
    Device, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_DIRECTORY_CONTROL,
    IRP_MJ_LOCK_CONTROL, IRP_MJ_QUERY_INFORMATION, IRP_MJ_QUERY_VOLUME_INFORMATION, IRP_MJ_READ,
    IRP_MJ_SET_INFORMATION, IRP_MJ_WRITE, IRP_MN_NOTIFY_CHANGE_DIRECTORY, IRP_MN_QUERY_DIRECTORY,
    IoCompletion, IoRequest, RDPDR_DTYP_FILESYSTEM,
};
use crate::cursor::{Put, Reader, utf16le_z};
use crate::error::Result;
use crate::trace;

/// STATUS_INVALID_INFO_CLASS (MS-ERREF 2.3.1).
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

/// CreateDisposition (MS-RDPEFS 2.2.1.4.1 / MS-SMB2 2.2.13).
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
/// CreateOptions.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
/// DesiredAccess bits that modify (MS-SMB2 2.2.13.1.1): FILE_WRITE_DATA,
/// FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
/// DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
const WRITE_ACCESS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// Information of the Device Create Response (MS-RDPEFS 2.2.1.5.1).
const FILE_SUPERSEDED: u8 = 0;
const FILE_OPENED: u8 = 1;
const FILE_OVERWRITTEN: u8 = 3;

/// Largest read served at once (servers ask for at most 64 KiB).
const MAX_READ: usize = 1 << 20;

struct Open {
    path: PathBuf,
    file: Option<File>,
    is_dir: bool,
    is_root: bool,
    delete_on_close: bool,
    listing: Vec<(String, FileInfo)>,
    pos: usize,
}

/// A shared local folder.
pub struct Drive {
    name: String,
    root: PathBuf,
    read_only: bool,
    files: HashMap<u32, Open>,
    next_file: u32,
}

type Reply = (u32, Vec<u8>);

fn fail(status: u32) -> Reply {
    (status, Vec::new())
}

/// The Length + buffer form most drive responses use.
fn with_length(buf: Vec<u8>) -> Reply {
    let mut v = Vec::with_capacity(4 + buf.len());
    v.put_u32(buf.len() as u32);
    v.put_bytes(&buf);
    (STATUS_SUCCESS, v)
}

fn length_fail(status: u32) -> Reply {
    (status, vec![0; 4])
}

/// A counted UTF-16LE string, trailing nulls dropped.
fn utf16_path(b: &[u8]) -> std::result::Result<String, u32> {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let end = units.iter().rposition(|&u| u != 0).map_or(0, |i| i + 1);
    String::from_utf16(&units[..end]).map_err(|_| STATUS_OBJECT_NAME_INVALID)
}

impl Drive {
    /// `name` is shown to the server user; `root` is the shared folder.
    pub fn new(name: &str, root: PathBuf, read_only: bool) -> Self {
        Self {
            name: name.to_string(),
            root,
            read_only,
            files: HashMap::new(),
            next_file: 1,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Number of handles the server has open.
    pub fn open_handles(&self) -> usize {
        self.files.len()
    }

    fn info(&self, path: &Path, file: Option<&File>) -> std::io::Result<FileInfo> {
        let md = match file {
            Some(f) => f.metadata()?,
            None => fs::metadata(path)?,
        };
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        Ok(FileInfo::from_metadata(&md, name, self.read_only))
    }

    /// IRP_MJ_CREATE: Device Create Request (2.2.1.4.1) / Response (2.2.1.5.1).
    fn create(&mut self, r: &mut Reader<'_>) -> Result<Reply> {
        let access = r.u32()?;
        r.skip(8)?; // AllocationSize
        let _attributes = r.u32()?;
        let _shared = r.u32()?;
        let disposition = r.u32()?;
        let options = r.u32()?;
        let len = r.u32()? as usize;
        let raw = r.bytes(len)?;
        let reply = match utf16_path(raw).and_then(|p| self.open(&p, access, disposition, options))
        {
            Ok((id, info)) => {
                let mut v = Vec::with_capacity(5);
                v.put_u32(id);
                v.put_u8(info);
                (STATUS_SUCCESS, v)
            }
            Err(status) => (status, vec![0; 5]),
        };
        Ok(reply)
    }

    fn open(
        &mut self,
        server_path: &str,
        access: u32,
        disposition: u32,
        options: u32,
    ) -> std::result::Result<(u32, u8), u32> {
        let res = path::resolve(&self.root, server_path)?;
        let delete = options & FILE_DELETE_ON_CLOSE != 0;
        let truncate = matches!(
            disposition,
            FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
        );
        let creates = !res.exists && matches!(disposition, FILE_CREATE | FILE_OPEN_IF)
            || matches!(
                disposition,
                FILE_SUPERSEDE | FILE_OVERWRITE_IF | FILE_CREATE
            );
        let writes = access & WRITE_ACCESS != 0 || delete || truncate || creates;
        if self.read_only && writes {
            return Err(STATUS_ACCESS_DENIED);
        }
        if res.is_root && (delete || truncate) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let (file, is_dir, info) = if res.exists {
            let is_dir = fs::metadata(&res.path)
                .map_err(|e| status_from_io(&e))?
                .is_dir();
            if want_dir && !is_dir {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
            if options & FILE_NON_DIRECTORY_FILE != 0 && is_dir {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            if disposition == FILE_CREATE {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            if is_dir {
                if truncate {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                (None, true, FILE_OPENED)
            } else {
                let write =
                    !self.read_only && (access & (WRITE_ACCESS | MAXIMUM_ALLOWED) != 0 || truncate);
                let mut o = OpenOptions::new();
                o.read(true).write(write).truncate(truncate);
                let file = match o.open(&res.path) {
                    Err(e)
                        if e.kind() == std::io::ErrorKind::PermissionDenied
                            && access & WRITE_ACCESS == 0
                            && !truncate =>
                    {
                        File::open(&res.path)
                    }
                    other => other,
                }
                .map_err(|e| status_from_io(&e))?;
                let info = match disposition {
                    FILE_SUPERSEDE => FILE_SUPERSEDED,
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => FILE_OVERWRITTEN,
                    _ => FILE_OPENED,
                };
                (Some(file), false, info)
            }
        } else {
            if matches!(disposition, FILE_OPEN | FILE_OVERWRITE) {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            }
            if want_dir {
                fs::create_dir(&res.path).map_err(|e| status_from_io(&e))?;
                (None, true, FILE_SUPERSEDED)
            } else {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&res.path)
                    .map_err(|e| status_from_io(&e))?;
                (Some(file), false, FILE_SUPERSEDED)
            }
        };
        let id = self.next_file;
        self.next_file = self.next_file.wrapping_add(1).max(1);
        trace!("rdpdr drive: open {} as {id}", res.path.display());
        self.files.insert(
            id,
            Open {
                path: res.path,
                file,
                is_dir,
                is_root: res.is_root,
                delete_on_close: delete,
                listing: Vec::new(),
                pos: 0,
            },
        );
        Ok((id, info))
    }

    /// Drops a handle; runs a pending delete.
    fn close_handle(&mut self, id: u32) -> bool {
        let Some(mut h) = self.files.remove(&id) else {
            return false;
        };
        h.file.take();
        if h.delete_on_close && !self.read_only {
            let r = if h.is_dir {
                fs::remove_dir(&h.path)
            } else {
                fs::remove_file(&h.path)
            };
            if let Err(e) = r {
                trace!("rdpdr drive: delete {} failed: {e}", h.path.display());
            }
        }
        true
    }

    /// IRP_MJ_READ: Device Read Request (2.2.1.4.3) / Response (2.2.1.5.3).
    fn read(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let len = (r.u32()? as usize).min(MAX_READ);
        let offset = u64::from(r.u32()?) | u64::from(r.u32()?) << 32;
        let Some(file) = self.files.get(&id).and_then(|h| h.file.as_ref()) else {
            return Ok(length_fail(STATUS_INVALID_HANDLE));
        };
        let mut f = file;
        let mut buf = Vec::with_capacity(len);
        let res = f
            .seek(SeekFrom::Start(offset))
            .and_then(|_| f.take(len as u64).read_to_end(&mut buf));
        Ok(match res {
            Ok(_) => with_length(buf),
            Err(e) => length_fail(status_from_io(&e)),
        })
    }

    /// IRP_MJ_WRITE: Device Write Request (2.2.1.4.4) / Response (2.2.1.5.4).
    fn write(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let len = r.u32()? as usize;
        let offset = u64::from(r.u32()?) | u64::from(r.u32()?) << 32;
        r.skip(20)?;
        let data = r.bytes(len)?;
        let fail = |s| (s, vec![0; 5]);
        if self.read_only {
            return Ok(fail(STATUS_ACCESS_DENIED));
        }
        let Some(file) = self.files.get(&id).and_then(|h| h.file.as_ref()) else {
            return Ok(fail(STATUS_INVALID_HANDLE));
        };
        let mut f = file;
        Ok(
            match f
                .seek(SeekFrom::Start(offset))
                .and_then(|_| f.write_all(data))
            {
                Ok(()) => {
                    let mut v = Vec::with_capacity(5);
                    v.put_u32(len as u32);
                    v.put_u8(0); // Padding
                    (STATUS_SUCCESS, v)
                }
                Err(e) => fail(status_from_io(&e)),
            },
        )
    }

    /// IRP_MJ_QUERY_INFORMATION (2.2.3.3.8 / 2.2.3.4.8).
    fn query_information(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let class = r.u32()?;
        let Some(h) = self.files.get(&id) else {
            return Ok(length_fail(STATUS_INVALID_HANDLE));
        };
        let info = match self.info(&h.path, h.file.as_ref()) {
            Ok(i) => i,
            Err(e) => return Ok(length_fail(status_from_io(&e))),
        };
        Ok(match class {
            FILE_BASIC_INFORMATION => with_length(basic_information(&info)),
            FILE_STANDARD_INFORMATION => {
                with_length(standard_information(&info, h.delete_on_close))
            }
            FILE_ATTRIBUTE_TAG_INFORMATION => with_length(attribute_tag_information(&info)),
            _ => length_fail(STATUS_INVALID_INFO_CLASS),
        })
    }

    /// IRP_MJ_SET_INFORMATION (2.2.3.3.9 / 2.2.3.4.9).
    fn set_information(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let class = r.u32()?;
        let length = r.u32()?;
        r.skip(24)?;
        let buf = r.rest();
        if self.read_only {
            return Ok(length_fail(STATUS_ACCESS_DENIED));
        }
        if !self.files.contains_key(&id) {
            return Ok(length_fail(STATUS_INVALID_HANDLE));
        }
        let status = match self.set(id, class, length, buf) {
            Ok(()) => STATUS_SUCCESS,
            Err(s) => s,
        };
        let mut v = Vec::with_capacity(4);
        v.put_u32(if status == STATUS_SUCCESS { length } else { 0 });
        Ok((status, v))
    }

    fn set(
        &mut self,
        id: u32,
        class: u32,
        length: u32,
        buf: &[u8],
    ) -> std::result::Result<(), u32> {
        let io = |e: std::io::Error| status_from_io(&e);
        let mut r = Reader::new(buf);
        let bad = |_| STATUS_INVALID_PARAMETER;
        let h = self.files.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match class {
            FILE_BASIC_INFORMATION => {
                // MS-FSCC 2.4.7
                let mut t = [0i64; 4];
                for x in &mut t {
                    *x = i64::from_le_bytes(r.array().map_err(bad)?);
                }
                let attributes = r.u32().map_err(bad)?;
                if h.is_dir {
                    return Ok(());
                }
                let mut times = FileTimes::new();
                if let Some(a) = from_filetime(t[1]) {
                    times = times.set_accessed(a);
                }
                if let Some(w) = from_filetime(t[2]) {
                    times = times.set_modified(w);
                }
                #[cfg(windows)]
                if let Some(c) = from_filetime(t[0]) {
                    use std::os::windows::fs::FileTimesExt;
                    times = times.set_created(c);
                }
                let f = OpenOptions::new().write(true).open(&h.path).map_err(io)?;
                f.set_times(times).map_err(io)?;
                if attributes != 0 {
                    let mut p = f.metadata().map_err(io)?.permissions();
                    p.set_readonly(attributes & FILE_ATTRIBUTE_READONLY != 0);
                    fs::set_permissions(&h.path, p).map_err(io)?;
                }
                Ok(())
            }
            FILE_END_OF_FILE_INFORMATION | FILE_ALLOCATION_INFORMATION => {
                // MS-FSCC 2.4.13 / 2.4.4
                let size = u64::from_le_bytes(r.array().map_err(bad)?);
                let f = h.file.as_ref().ok_or(STATUS_FILE_IS_A_DIRECTORY)?;
                if class == FILE_ALLOCATION_INFORMATION && size >= f.metadata().map_err(io)?.len() {
                    return Ok(());
                }
                f.set_len(size).map_err(io)
            }
            FILE_DISPOSITION_INFORMATION => {
                // MS-FSCC 2.4.11; an empty buffer means delete (FreeRDP, Windows).
                let delete = length == 0 || r.u8().map_err(bad)? != 0;
                if h.is_root {
                    return Err(STATUS_ACCESS_DENIED);
                }
                if delete && h.is_dir && fs::read_dir(&h.path).map_err(io)?.next().is_some() {
                    return Err(STATUS_DIRECTORY_NOT_EMPTY);
                }
                h.delete_on_close = delete;
                Ok(())
            }
            FILE_RENAME_INFORMATION => {
                // RDP_FILE_RENAME_INFORMATION (MS-RDPEFS 2.2.3.3.9.1)
                let replace = r.u8().map_err(bad)? != 0;
                let _root_dir = r.u8().map_err(bad)?;
                let n = r.u32().map_err(bad)? as usize;
                let name = utf16_path(r.bytes(n).map_err(bad)?)?;
                if h.is_root {
                    return Err(STATUS_ACCESS_DENIED);
                }
                let target = path::resolve(&self.root, &name)?;
                if target.is_root {
                    return Err(STATUS_ACCESS_DENIED);
                }
                // A case-only rename resolves to the file itself.
                let same = target.exists && target.path == h.path;
                if target.exists && !replace && !same {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                let dest = match (same, target.path.parent(), name.rsplit(['\\', '/']).next()) {
                    (true, Some(parent), Some(last)) => parent.join(last),
                    _ => target.path,
                };
                fs::rename(&h.path, &dest).map_err(io)?;
                trace!(
                    "rdpdr drive: rename {} -> {}",
                    h.path.display(),
                    dest.display()
                );
                h.path = dest;
                Ok(())
            }
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

    /// IRP_MJ_QUERY_VOLUME_INFORMATION (2.2.3.3.6 / 2.2.3.4.6).
    fn query_volume(&mut self, r: &mut Reader<'_>) -> Result<Reply> {
        let class = r.u32()?;
        let (total_bytes, free_bytes) = disk_space(&self.root).unwrap_or((1 << 40, 1 << 39));
        let serial = self.name.bytes().fold(0x811C_9DC5u32, |h, b| {
            (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
        });
        let vol = Volume {
            label: &self.name,
            serial,
            total_bytes,
            free_bytes: if self.read_only { 0 } else { free_bytes },
        };
        Ok(match volume_information(class, &vol) {
            Some(b) => with_length(b),
            None => length_fail(STATUS_INVALID_INFO_CLASS),
        })
    }

    /// IRP_MN_QUERY_DIRECTORY (2.2.3.3.10 / 2.2.3.4.10): one entry per reply.
    fn query_directory(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Reply> {
        let class = r.u32()?;
        let initial = r.u8()? != 0;
        let len = r.u32()? as usize;
        r.skip(23)?;
        let raw = r.bytes(len)?;
        // Failures carry Length 0 and one Padding byte.
        let fail = |s| (s, vec![0; 5]);
        if !self.files.get(&id).is_some_and(|h| h.is_dir) {
            return Ok(fail(STATUS_INVALID_HANDLE));
        }
        if initial {
            match utf16_path(raw).and_then(|p| self.list(&p)) {
                Ok(listing) => {
                    let h = self.files.get_mut(&id).expect("checked above");
                    h.listing = listing;
                    h.pos = 0;
                }
                Err(s) => return Ok(fail(s)),
            }
        }
        let h = self.files.get_mut(&id).expect("checked above");
        let Some((name, info)) = h.listing.get(h.pos) else {
            let status = if initial {
                STATUS_NO_SUCH_FILE
            } else {
                STATUS_NO_MORE_FILES
            };
            return Ok(fail(status));
        };
        let Some(entry) = directory_entry(class, info, name) else {
            return Ok(fail(STATUS_INVALID_INFO_CLASS));
        };
        h.pos += 1;
        Ok(with_length(entry))
    }

    fn list(&self, server_path: &str) -> std::result::Result<Vec<(String, FileInfo)>, u32> {
        let (dir, pattern) = path::split_pattern(server_path)?;
        let res = path::resolve(&self.root, dir)?;
        if !res.exists {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        let io = |e: std::io::Error| status_from_io(&e);
        let mut out = Vec::new();
        for entry in fs::read_dir(&res.path).map_err(io)? {
            let Ok(entry) = entry else { continue };
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !wildcard_match(pattern, &name) {
                continue;
            }
            let Ok(md) = entry.metadata() else { continue };
            out.push((
                name.clone(),
                FileInfo::from_metadata(&md, &name, self.read_only),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn handle(&mut self, req: &IoRequest<'_>) -> Result<Option<Reply>> {
        let mut r = Reader::new(req.data);
        let id = req.file_id;
        Ok(Some(match req.major {
            IRP_MJ_CREATE => self.create(&mut r)?,
            // Device Close Response (2.2.1.5.2): 4 bytes Padding.
            IRP_MJ_CLOSE => match self.close_handle(id) {
                true => (STATUS_SUCCESS, vec![0; 4]),
                false => (STATUS_INVALID_HANDLE, vec![0; 4]),
            },
            IRP_MJ_READ => self.read(id, &mut r)?,
            IRP_MJ_WRITE => self.write(id, &mut r)?,
            IRP_MJ_QUERY_INFORMATION => self.query_information(id, &mut r)?,
            IRP_MJ_SET_INFORMATION => self.set_information(id, &mut r)?,
            IRP_MJ_QUERY_VOLUME_INFORMATION => self.query_volume(&mut r)?,
            IRP_MJ_DIRECTORY_CONTROL => match req.minor {
                IRP_MN_QUERY_DIRECTORY => self.query_directory(id, &mut r)?,
                // Change notifications stay pending (no watcher yet).
                IRP_MN_NOTIFY_CHANGE_DIRECTORY => return Ok(None),
                _ => fail(STATUS_NOT_SUPPORTED),
            },
            // Server Drive Lock Control (2.2.3.3.12): granted; 5 bytes Padding.
            IRP_MJ_LOCK_CONTROL => (STATUS_SUCCESS, vec![0; 5]),
            // Device Control Response (2.2.1.5.5): OutputBufferLength 0.
            IRP_MJ_DEVICE_CONTROL => length_fail(STATUS_NOT_SUPPORTED),
            _ => fail(STATUS_NOT_SUPPORTED),
        }))
    }
}

impl Device for Drive {
    fn device_type(&self) -> u32 {
        RDPDR_DTYP_FILESYSTEM
    }

    fn preferred_dos_name(&self) -> String {
        let s: String = self
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(7)
            .collect();
        if s.is_empty() { "DRIVE".into() } else { s }
    }

    /// The full name as a null-terminated Unicode string, required with
    /// DRIVE_CAPABILITY_VERSION_02 (MS-RDPEFS 2.2.1.3).
    fn device_data(&self) -> Vec<u8> {
        utf16le_z(&self.name)
    }

    fn display_name(&self) -> String {
        self.name.clone()
    }

    fn io(&mut self, req: &IoRequest<'_>) -> Option<IoCompletion> {
        match self.handle(req) {
            Ok(Some((status, data))) => Some(IoCompletion::new(req, status, data)),
            Ok(None) => None,
            // Truncated request: answer instead of leaving the server waiting.
            Err(_) => Some(IoCompletion::new(req, STATUS_INVALID_PARAMETER, Vec::new())),
        }
    }

    fn closed(&mut self) {
        let ids: Vec<u32> = self.files.keys().copied().collect();
        for id in ids {
            self.close_handle(id);
        }
    }
}
