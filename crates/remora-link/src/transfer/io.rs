//! I/O for the transfer engine, behind traits so the client and the helper
//! share the engine and tests run in memory.
//!
//! Names passed to a [`TargetDir`] are always plain file names that passed
//! [`super::path::check_name`] (plus the `.remora-part` and
//! `.remora-part.meta` suffixes the engine adds).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// The file being sent.
pub trait Source: Send {
    /// Current size and last-write time (ms since the Unix epoch). Checked
    /// again before a resume: a changed file is not continued.
    fn stat(&mut self) -> io::Result<(u64, u64)>;
    /// Reads at `offset`; returns fewer bytes only at the end of the file.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}

/// The partial file being received.
pub trait PartFile: Send {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn set_len(&mut self, len: u64) -> io::Result<()>;
    /// Flushes data to stable storage (before the sidecar records a block).
    fn sync(&mut self) -> io::Result<()>;
}

/// The folder the user chose for received files.
pub trait TargetDir: Send {
    fn exists(&self, name: &str) -> bool;
    /// Creates a new empty file; fails if it exists.
    fn create_new(&mut self, name: &str) -> io::Result<Box<dyn PartFile>>;
    /// Opens an existing file for reading and writing.
    fn open(&mut self, name: &str) -> io::Result<Box<dyn PartFile>>;
    fn read_small(&self, name: &str) -> io::Result<Vec<u8>>;
    /// Replaces a small file (the sidecar) atomically where possible.
    fn write_small(&mut self, name: &str, data: &[u8]) -> io::Result<()>;
    fn remove(&mut self, name: &str) -> io::Result<()>;
    /// Renames `from` to `to`; fails with `AlreadyExists` instead of
    /// replacing an existing `to`.
    fn rename_new(&mut self, from: &str, to: &str) -> io::Result<()>;
    /// File names in the folder (for finding resumable sidecars).
    fn list(&self) -> io::Result<Vec<String>>;
    /// Free bytes on the volume, when known. None skips the check.
    fn free_space(&self) -> Option<u64> {
        None
    }
    /// A file was stored under `name`. The client marks it with the
    /// Mark-of-the-Web here (app layer).
    fn finished(&mut self, _name: &str) {}
}

// ---------------------------------------------------------------- memory

/// An in-memory folder for tests and previews. Clones share the files.
#[derive(Clone, Default)]
pub struct MemDir {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    free: Option<u64>,
    finished: Arc<Mutex<Vec<String>>>,
    /// Fail every write after this many bytes (simulated full disk).
    fail_writes_after: Option<u64>,
}

impl MemDir {
    pub fn new() -> MemDir {
        MemDir::default()
    }

    pub fn with_free_space(mut self, free: u64) -> MemDir {
        self.free = Some(free);
        self
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.files.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        self.lock().get(name).cloned()
    }

    pub fn put(&self, name: &str, data: Vec<u8>) {
        self.lock().insert(name.to_string(), data);
    }

    pub fn names(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// Names passed to [`TargetDir::finished`].
    pub fn finished_names(&self) -> Vec<String> {
        self.finished
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Flips one byte of a stored file (simulated disk corruption).
    pub fn corrupt(&self, name: &str, at: usize) {
        if let Some(f) = self.lock().get_mut(name)
            && let Some(b) = f.get_mut(at)
        {
            *b ^= 0xFF;
        }
    }
}

struct MemPart {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    name: String,
    fail_after: Option<u64>,
}

impl MemPart {
    fn with<T>(&self, f: impl FnOnce(&mut Vec<u8>) -> T) -> io::Result<T> {
        let mut files = self.files.lock().unwrap_or_else(|p| p.into_inner());
        let v = files
            .get_mut(&self.name)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(f(v))
    }
}

impl PartFile for MemPart {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        if let Some(limit) = self.fail_after
            && offset + data.len() as u64 > limit
        {
            return Err(io::Error::other("disk full"));
        }
        self.with(|v| {
            let end = offset as usize + data.len();
            if v.len() < end {
                v.resize(end, 0);
            }
            v[offset as usize..end].copy_from_slice(data);
        })
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.with(|v| {
            let start = (offset as usize).min(v.len());
            let n = buf.len().min(v.len() - start);
            buf[..n].copy_from_slice(&v[start..start + n]);
            n
        })
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.with(|v| v.resize(len as usize, 0))
    }
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TargetDir for MemDir {
    fn exists(&self, name: &str) -> bool {
        self.lock().contains_key(name)
    }
    fn create_new(&mut self, name: &str) -> io::Result<Box<dyn PartFile>> {
        let mut files = self.lock();
        if files.contains_key(name) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        files.insert(name.to_string(), Vec::new());
        Ok(Box::new(MemPart {
            files: self.files.clone(),
            name: name.to_string(),
            fail_after: self.fail_writes_after,
        }))
    }
    fn open(&mut self, name: &str) -> io::Result<Box<dyn PartFile>> {
        if !self.exists(name) {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(Box::new(MemPart {
            files: self.files.clone(),
            name: name.to_string(),
            fail_after: self.fail_writes_after,
        }))
    }
    fn read_small(&self, name: &str) -> io::Result<Vec<u8>> {
        self.get(name).ok_or_else(|| io::ErrorKind::NotFound.into())
    }
    fn write_small(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        self.put(name, data.to_vec());
        Ok(())
    }
    fn remove(&mut self, name: &str) -> io::Result<()> {
        self.lock()
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
    fn rename_new(&mut self, from: &str, to: &str) -> io::Result<()> {
        let mut files = self.lock();
        if files.contains_key(to) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let v = files
            .remove(from)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        files.insert(to.to_string(), v);
        Ok(())
    }
    fn list(&self) -> io::Result<Vec<String>> {
        Ok(self.names())
    }
    fn free_space(&self) -> Option<u64> {
        self.free
    }
    fn finished(&mut self, name: &str) {
        self.finished
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(name.to_string());
    }
}

/// A file held in memory, for tests.
pub struct MemSource {
    pub data: Arc<Mutex<Vec<u8>>>,
    pub mtime: Arc<Mutex<u64>>,
}

impl MemSource {
    pub fn new(data: Vec<u8>, mtime: u64) -> MemSource {
        MemSource {
            data: Arc::new(Mutex::new(data)),
            mtime: Arc::new(Mutex::new(mtime)),
        }
    }
}

impl Source for MemSource {
    fn stat(&mut self) -> io::Result<(u64, u64)> {
        let len = self.data.lock().unwrap_or_else(|p| p.into_inner()).len() as u64;
        Ok((len, *self.mtime.lock().unwrap_or_else(|p| p.into_inner())))
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let d = self.data.lock().unwrap_or_else(|p| p.into_inner());
        let start = (offset as usize).min(d.len());
        let n = buf.len().min(d.len() - start);
        buf[..n].copy_from_slice(&d[start..start + n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------- std::fs

/// Free-space query for [`FsDir`].
pub type FreeSpaceFn = Box<dyn Fn(&Path) -> Option<u64> + Send>;
/// Called with each stored file's path (Mark-of-the-Web hook).
pub type FinishedFn = Box<dyn FnMut(&Path) + Send>;

/// A real folder through `std::fs` (no platform APIs). The app supplies the
/// free-space query and the Mark-of-the-Web hook.
pub struct FsDir {
    root: PathBuf,
    free_space: Option<FreeSpaceFn>,
    on_finished: Option<FinishedFn>,
}

impl FsDir {
    pub fn new(root: impl Into<PathBuf>) -> FsDir {
        FsDir {
            root: root.into(),
            free_space: None,
            on_finished: None,
        }
    }

    pub fn with_free_space(mut self, f: impl Fn(&Path) -> Option<u64> + Send + 'static) -> FsDir {
        self.free_space = Some(Box::new(f));
        self
    }

    /// Called with the full path of every stored file.
    pub fn on_finished(mut self, f: impl FnMut(&Path) + Send + 'static) -> FsDir {
        self.on_finished = Some(Box::new(f));
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Joins a plain name; anything that is not one is refused.
    fn path(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() || name.contains(['/', '\\', ':']) || name == "." || name == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a plain file name",
            ));
        }
        Ok(self.root.join(name))
    }
}

struct FsPart(std::fs::File);

impl PartFile for FsPart {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.write_all(data)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        self.0.seek(SeekFrom::Start(offset))?;
        let mut n = 0;
        while n < buf.len() {
            match self.0.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_data()
    }
}

impl TargetDir for FsDir {
    fn exists(&self, name: &str) -> bool {
        self.path(name).map(|p| p.exists()).unwrap_or(true)
    }
    fn create_new(&mut self, name: &str) -> io::Result<Box<dyn PartFile>> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.path(name)?)?;
        Ok(Box::new(FsPart(f)))
    }
    fn open(&mut self, name: &str) -> io::Result<Box<dyn PartFile>> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(name)?)?;
        Ok(Box::new(FsPart(f)))
    }
    fn read_small(&self, name: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(name)?)
    }
    fn write_small(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        let p = self.path(name)?;
        let tmp = self.path(&format!("{name}.tmp"))?;
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &p)
    }
    fn remove(&mut self, name: &str) -> io::Result<()> {
        std::fs::remove_file(self.path(name)?)
    }
    fn rename_new(&mut self, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (self.path(from)?, self.path(to)?);
        // std::fs::rename replaces an existing target on Windows. A hard link
        // fails instead when `to` exists; then the part file is removed.
        match std::fs::hard_link(&from, &to) {
            Ok(()) => std::fs::remove_file(&from),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
            // Volumes without hard links (FAT, exFAT): check, then rename.
            // A file created in between would be replaced; that window is
            // the only one, and only on such volumes.
            Err(_) => {
                if to.exists() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                std::fs::rename(&from, &to)
            }
        }
    }
    fn list(&self) -> io::Result<Vec<String>> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(&self.root)? {
            if let Some(n) = e?.file_name().to_str() {
                v.push(n.to_string());
            }
        }
        Ok(v)
    }
    fn free_space(&self) -> Option<u64> {
        self.free_space.as_ref().and_then(|f| f(&self.root))
    }
    fn finished(&mut self, name: &str) {
        if let (Some(f), Ok(p)) = (
            self.on_finished.as_mut(),
            self.root.join(name).canonicalize(),
        ) {
            f(&p);
        }
    }
}

/// A local file through `std::fs`.
pub struct FsSource {
    file: std::fs::File,
}

impl FsSource {
    pub fn open(path: &Path) -> io::Result<FsSource> {
        Ok(FsSource {
            file: std::fs::File::open(path)?,
        })
    }
}

impl Source for FsSource {
    fn stat(&mut self) -> io::Result<(u64, u64)> {
        let m = self.file.metadata()?;
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        Ok((m.len(), mtime))
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(offset))?;
        let mut n = 0;
        while n < buf.len() {
            match self.file.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_dir_never_overwrites_and_refuses_paths() {
        let dir = std::env::temp_dir().join(format!("remora-link-fsdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut d = FsDir::new(&dir);
        let mut p = d.create_new("a.remora-part").unwrap();
        p.write_at(0, b"hello").unwrap();
        drop(p);
        assert!(d.create_new("a.remora-part").is_err(), "create_new");
        std::fs::write(dir.join("a.txt"), b"keep").unwrap();
        let e = d.rename_new("a.remora-part", "a.txt").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"keep");
        d.rename_new("a.remora-part", "b.txt").unwrap();
        assert_eq!(std::fs::read(dir.join("b.txt")).unwrap(), b"hello");
        assert!(!dir.join("a.remora-part").exists());
        for bad in ["../x", "a\\b", "c:x", "..", ""] {
            assert!(d.create_new(bad).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
