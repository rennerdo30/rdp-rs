//! The file system for transfers: the receive folder (with free space and
//! the Mark-of-the-Web), and files opened for sending (regular files only,
//! checked on the opened handle).

use std::fs::File;
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use remora_link::transfer::io::{FsDir, Source, TargetDir};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK, GetDiskFreeSpaceExW, GetFileType,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_Downloads, FOLDERID_SendTo, SHGetKnownFolderPath};

use super::{from_wide_ptr, wide};
use crate::files::{self, FileFacts};
use crate::link::Files;
use crate::warn;

/// A known folder's path (`SHGetKnownFolderPath`).
fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the shell allocates `p`; freed below in every case.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) };
    // SAFETY: `p` is null or a NUL-terminated string from the shell.
    let s = unsafe { from_wide_ptr(p) };
    // SAFETY: CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(p.cast()) };
    (hr >= 0 && !s.is_empty()).then(|| PathBuf::from(s))
}

/// `<Downloads>\From Remora`.
pub fn receive_folder() -> Option<PathBuf> {
    files::receive_folder(
        known_folder(&FOLDERID_Downloads),
        std::env::var_os("USERPROFILE").map(PathBuf::from),
    )
}

/// The user's SendTo folder.
pub fn sendto_folder() -> Option<PathBuf> {
    known_folder(&FOLDERID_SendTo).or_else(|| {
        std::env::var_os("APPDATA").map(|a| {
            PathBuf::from(a)
                .join("Microsoft")
                .join("Windows")
                .join("SendTo")
        })
    })
}

/// Free bytes for this user on the folder's volume.
pub fn free_space(dir: &Path) -> Option<u64> {
    let w = wide(&dir.to_string_lossy());
    let mut avail = 0u64;
    // SAFETY: valid path and out pointer.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            w.as_ptr(),
            &mut avail,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(avail)
}

/// Writes the `Zone.Identifier` stream (ZoneId=3) on a received file.
pub fn mark_of_the_web(file: &Path) -> io::Result<()> {
    std::fs::write(files::zone_stream(file), files::ZONE_IDENTIFIER)
}

/// A file opened for sending.
struct FileSource(File);

impl Source for FileSource {
    fn stat(&mut self) -> io::Result<(u64, u64)> {
        let m = self.0.metadata()?;
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        Ok((m.len(), mtime))
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        let mut n = 0;
        while n < buf.len() {
            match self.0.seek_read(&mut buf[n..], offset + n as u64)? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

/// Opens `path` for sending without following links, then checks the
/// opened object: a regular file on disk, nothing else.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let m = f.metadata()?;
    // SAFETY: a valid handle owned by `f`.
    let kind = unsafe { GetFileType(f.as_raw_handle()) };
    files::check_facts(FileFacts {
        attributes: m.file_attributes(),
        disk_file: kind == FILE_TYPE_DISK,
    })
    .map_err(|why| io::Error::new(io::ErrorKind::InvalidInput, why))?;
    Ok(f)
}

/// The agent's [`Files`]: `<Downloads>\From Remora` and real files.
pub struct WinFiles;

impl Files for WinFiles {
    fn receive_dir(&mut self) -> io::Result<Box<dyn TargetDir>> {
        let dir = receive_folder()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Downloads folder"))?;
        std::fs::create_dir_all(&dir)?;
        Ok(Box::new(
            FsDir::new(dir)
                .with_free_space(free_space)
                .on_finished(|p| {
                    if let Err(e) = mark_of_the_web(p) {
                        warn!("received file not marked as downloaded: {e}");
                    }
                }),
        ))
    }

    fn open_source(&mut self, path: &Path) -> io::Result<(String, Box<dyn Source>)> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no usable file name"))?
            .to_string();
        let f = open_regular(path)?;
        Ok((name, Box::new(FileSource(f))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("remora-agent-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn motw_stream_is_written() {
        let d = temp("motw");
        let f = d.join("got.txt");
        std::fs::write(&f, b"x").unwrap();
        mark_of_the_web(&f).unwrap();
        let zone = std::fs::read_to_string(files::zone_stream(&f)).unwrap();
        assert!(zone.contains("ZoneId=3"));
        assert_eq!(std::fs::read(&f).unwrap(), b"x", "content untouched");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_regular_files_open() {
        let d = temp("open");
        let f = d.join("a.bin");
        std::fs::write(&f, b"hello").unwrap();
        let mut src = FileSource(open_regular(&f).unwrap());
        assert_eq!(src.stat().unwrap().0, 5);
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(1, &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"ello");
        assert!(open_regular(&d).is_err(), "a folder");
        assert!(open_regular(&d.join("missing")).is_err());
        assert!(free_space(&d).is_some_and(|n| n > 0));
        let _ = std::fs::remove_dir_all(&d);
    }
}
