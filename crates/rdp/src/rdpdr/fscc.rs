//! NTSTATUS values (MS-ERREF 2.3), FILETIME conversion and the MS-FSCC
//! information structures the drive device returns.

use std::fs::Metadata;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cursor::{Put, utf16le};

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub const STATUS_DISK_FULL: u32 = 0xC000_007F;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;

/// FileAttributes (MS-FSCC 2.6).
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// FileInformationClass values (MS-FSCC 2.4).
pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_RENAME_INFORMATION: u32 = 10;
pub const FILE_NAMES_INFORMATION: u32 = 12;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_ALLOCATION_INFORMATION: u32 = 19;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 35;

/// FsInformationClass values (MS-FSCC 2.5).
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;

/// FILETIME of the Unix epoch (100 ns intervals since 1601-01-01).
const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// SystemTime to FILETIME; times before 1601 clamp to 0.
pub fn filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => EPOCH_AS_FILETIME + (d.as_nanos() / 100) as u64,
        Err(e) => EPOCH_AS_FILETIME.saturating_sub((e.duration().as_nanos() / 100) as u64),
    }
}

/// FILETIME to SystemTime. 0 and -1 mean "do not change" (MS-FSCC 2.4.7)
/// and give `None`.
pub fn from_filetime(ft: i64) -> Option<SystemTime> {
    if ft <= 0 {
        return None;
    }
    let ft = ft as u64;
    Some(if ft >= EPOCH_AS_FILETIME {
        UNIX_EPOCH + Duration::from_nanos((ft - EPOCH_AS_FILETIME).saturating_mul(100))
    } else {
        UNIX_EPOCH - Duration::from_nanos((EPOCH_AS_FILETIME - ft).saturating_mul(100))
    })
}

/// Maps a local I/O error to the closest NTSTATUS.
pub fn status_from_io(e: &io::Error) -> u32 {
    use io::ErrorKind::*;
    #[cfg(windows)]
    if matches!(e.raw_os_error(), Some(32 | 33)) {
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
        return STATUS_SHARING_VIOLATION;
    }
    match e.kind() {
        NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        PermissionDenied | ReadOnlyFilesystem => STATUS_ACCESS_DENIED,
        AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        DirectoryNotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        NotADirectory => STATUS_NOT_A_DIRECTORY,
        IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
        InvalidInput | InvalidFilename => STATUS_OBJECT_NAME_INVALID,
        StorageFull | QuotaExceeded | FileTooLarge => STATUS_DISK_FULL,
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// The file facts every information class is built from.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub created: u64,
    pub accessed: u64,
    pub written: u64,
    pub changed: u64,
    pub size: u64,
    pub attributes: u32,
    pub is_dir: bool,
}

impl FileInfo {
    /// `read_only` marks files read-only on a read-only drive.
    pub fn from_metadata(md: &Metadata, name: &str, read_only: bool) -> Self {
        let written = md.modified().map(filetime).unwrap_or(0);
        let is_dir = md.is_dir();
        Self {
            created: md.created().map(filetime).unwrap_or(written),
            accessed: md.accessed().map(filetime).unwrap_or(written),
            written,
            changed: written,
            size: if is_dir { 0 } else { md.len() },
            attributes: attributes(md, name, read_only),
            is_dir,
        }
    }

    pub fn allocation(&self) -> u64 {
        self.size.div_ceil(4096) * 4096
    }

    fn put_times(&self, v: &mut Vec<u8>) {
        for t in [self.created, self.accessed, self.written, self.changed] {
            v.put_bytes(&t.to_le_bytes());
        }
    }
}

fn attributes(md: &Metadata, name: &str, read_only: bool) -> u32 {
    #[cfg(windows)]
    let mut a = {
        use std::os::windows::fs::MetadataExt;
        // Only plain attributes: reparse points, sparse files and the like
        // are hidden from the server.
        md.file_attributes() & 0x0000_01B7
    };
    #[cfg(not(windows))]
    let mut a = {
        let mut a = 0;
        if md.permissions().readonly() {
            a |= FILE_ATTRIBUTE_READONLY;
        }
        if name.starts_with('.') {
            a |= FILE_ATTRIBUTE_HIDDEN;
        }
        if md.is_file() {
            a |= FILE_ATTRIBUTE_ARCHIVE;
        }
        a
    };
    let _ = name;
    if md.is_dir() {
        a |= FILE_ATTRIBUTE_DIRECTORY;
    } else if read_only {
        a |= FILE_ATTRIBUTE_READONLY;
    }
    if a == 0 { FILE_ATTRIBUTE_NORMAL } else { a }
}

/// FILE_BASIC_INFORMATION (MS-FSCC 2.4.7) without the trailing Reserved
/// field, 36 bytes as RDP clients send it.
pub fn basic_information(f: &FileInfo) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    f.put_times(&mut v);
    v.put_u32(f.attributes);
    v
}

/// FILE_STANDARD_INFORMATION (MS-FSCC 2.4.41) without Reserved, 22 bytes.
pub fn standard_information(f: &FileInfo, delete_pending: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(22);
    v.put_bytes(&f.allocation().to_le_bytes());
    v.put_bytes(&f.size.to_le_bytes());
    v.put_u32(1); // NumberOfLinks
    v.put_u8(delete_pending as u8);
    v.put_u8(f.is_dir as u8);
    v
}

/// FILE_ATTRIBUTE_TAG_INFORMATION (MS-FSCC 2.4.6).
pub fn attribute_tag_information(f: &FileInfo) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.put_u32(f.attributes);
    v.put_u32(0); // ReparseTag
    v
}

/// One directory entry in the given class: FileDirectoryInformation
/// (MS-FSCC 2.4.10), FileFullDirectoryInformation (2.4.14),
/// FileBothDirectoryInformation (2.4.8) or FileNamesInformation (2.4.28).
/// `None` for any other class.
pub fn directory_entry(class: u32, f: &FileInfo, name: &str) -> Option<Vec<u8>> {
    let name = utf16le(name);
    let mut v = Vec::with_capacity(96 + name.len());
    v.put_u32(0); // NextEntryOffset: one entry per response
    v.put_u32(0); // FileIndex
    if class == FILE_NAMES_INFORMATION {
        v.put_u32(name.len() as u32);
        v.put_bytes(&name);
        return Some(v);
    }
    if !matches!(
        class,
        FILE_DIRECTORY_INFORMATION
            | FILE_FULL_DIRECTORY_INFORMATION
            | FILE_BOTH_DIRECTORY_INFORMATION
    ) {
        return None;
    }
    f.put_times(&mut v);
    v.put_bytes(&f.size.to_le_bytes());
    v.put_bytes(&f.allocation().to_le_bytes());
    v.put_u32(f.attributes);
    v.put_u32(name.len() as u32);
    if class != FILE_DIRECTORY_INFORMATION {
        v.put_u32(0); // EaSize
    }
    if class == FILE_BOTH_DIRECTORY_INFORMATION {
        v.put_u8(0); // ShortNameLength
        v.put_u8(0); // Reserved1
        v.put_zeros(24); // ShortName
    }
    v.put_bytes(&name);
    Some(v)
}

/// Volume facts for the FileFs* classes.
pub struct Volume<'a> {
    pub label: &'a str,
    pub serial: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
}

const SECTORS_PER_UNIT: u32 = 8;
const BYTES_PER_SECTOR: u32 = 512;
const UNIT: u64 = (SECTORS_PER_UNIT * BYTES_PER_SECTOR) as u64;

/// The FileFs* structure for `class` (MS-FSCC 2.5); `None` if unsupported.
pub fn volume_information(class: u32, vol: &Volume<'_>) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(64);
    match class {
        FILE_FS_VOLUME_INFORMATION => {
            // MS-FSCC 2.5.9
            let label = utf16le(vol.label);
            v.put_bytes(&0u64.to_le_bytes()); // VolumeCreationTime
            v.put_u32(vol.serial);
            v.put_u32(label.len() as u32);
            v.put_u8(0); // SupportsObjects
            v.put_u8(0); // Reserved
            v.put_bytes(&label);
        }
        FILE_FS_SIZE_INFORMATION | FILE_FS_FULL_SIZE_INFORMATION => {
            // MS-FSCC 2.5.8 / 2.5.4
            v.put_bytes(&(vol.total_bytes / UNIT).to_le_bytes());
            v.put_bytes(&(vol.free_bytes / UNIT).to_le_bytes());
            if class == FILE_FS_FULL_SIZE_INFORMATION {
                v.put_bytes(&(vol.free_bytes / UNIT).to_le_bytes());
            }
            v.put_u32(SECTORS_PER_UNIT);
            v.put_u32(BYTES_PER_SECTOR);
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            // MS-FSCC 2.5.1: case-preserving, Unicode names, no ACLs/streams.
            let fs = utf16le("FAT32");
            v.put_u32(0x0000_0002 | 0x0000_0004); // CASE_PRESERVED_NAMES | UNICODE_ON_DISK
            v.put_u32(255); // MaximumComponentNameLength
            v.put_u32(fs.len() as u32);
            v.put_bytes(&fs);
        }
        FILE_FS_DEVICE_INFORMATION => {
            // MS-FSCC 2.5.10
            v.put_u32(0x0000_0007); // FILE_DEVICE_DISK
            v.put_u32(0); // Characteristics
        }
        _ => return None,
    }
    Some(v)
}

/// (total, free) bytes of the volume holding `path`.
#[cfg(windows)]
pub fn disk_space(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            dir: *const u16,
            free_to_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: `wide` is a null-terminated UTF-16 string that outlives the
    // call; the three out pointers point to live u64s.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free) };
    (ok != 0).then_some((total, free))
}

/// (total, free) bytes of the volume holding `path`; std has no portable
/// query, so other platforms report none.
#[cfg(not(windows))]
pub fn disk_space(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}
