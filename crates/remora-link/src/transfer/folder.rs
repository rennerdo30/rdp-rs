//! Folder transfers (protocol 1.2, [`crate::msg::cap::FOLDERS`], RDP-64).
//!
//! A folder travels as its files, each an ordinary transfer (resume,
//! BLAKE3 blocks, Mark-of-the-Web) whose [`FileOffer`] names the folder in
//! a [`FolderRef`]: the folder's own id, its name, the file's subfolders and
//! the folder's totals. Above the wire the [`Engine`] shows the app *one*
//! transfer per folder, under the folder's id:
//!
//! - **Sending:** [`Engine::send_folder`] takes the list of files and
//!   offers [`FOLDER_PARALLEL`] at a time, the next when one completes.
//!   Progress adds up; the folder completes with its last file. A failed
//!   file (or [`Engine::cancel`] of the folder) cancels the rest.
//! - **Receiving:** the first file of a folder raises one `Offered` event
//!   for the folder (name, total size, `files`). [`Engine::accept`] of the
//!   folder's id creates the folder in the chosen directory, as
//!   `name (2)` and so on when the name is taken (never into an existing
//!   folder), and takes every file of it into its subfolder from then on;
//!   [`Engine::reject`] refuses all of them.
//! - **Names:** the folder name and every subfolder go through
//!   [`path::check_name`] like file names, at most [`MAX_FOLDER_DEPTH`]
//!   deep; a folder whose ref breaks a rule is refused file by file.
//! - Empty subfolders are not sent (only files carry a path).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};

use super::io::{Source, TargetDir};
use super::{Direction, Engine, MAX_ACTIVE, TransferEvent, new_id, path, reason};
use crate::msg::{FolderRef, TransferId};

/// Files of one folder in flight at a time.
pub const FOLDER_PARALLEL: usize = 4;
/// Most files in one folder transfer.
pub const MAX_FOLDER_FILES: u32 = 100_000;
/// Deepest subfolder below a folder.
pub const MAX_FOLDER_DEPTH: usize = 32;
/// `name (2)` .. `name (999)` are tried for a received folder.
const MAX_VARIANTS: u32 = 999;

/// One file of a folder to send.
pub struct FolderFile {
    /// Subfolders below the folder, `\\`-separated ("" for its top).
    pub path: String,
    pub name: String,
    pub size: u64,
    /// Opens the file when its turn comes.
    pub open: Box<dyn FnOnce() -> io::Result<Box<dyn Source>> + Send>,
}

/// A folder being sent.
pub(super) struct FolderOut {
    top: String,
    queue: VecDeque<FolderFile>,
    /// Files in flight: (bytes done, size).
    active: HashMap<TransferId, (u64, u64)>,
    files: u32,
    bytes: u64,
    /// Bytes of finished files.
    done: u64,
    paused: bool,
}

impl FolderOut {
    /// Files not offered yet.
    pub(super) fn queued(&self) -> usize {
        self.queue.len()
    }
}

pub(super) enum InState {
    /// Waiting for the app; the files offered so far.
    Offered(Vec<TransferId>),
    /// Accepted: the folder created for it and its final name.
    Accepted(Box<dyn TargetDir>, String),
    /// Rejected, failed or complete: later files are refused.
    Closed,
}

/// A folder being received.
pub(super) struct FolderIn {
    top: String,
    files: u32,
    bytes: u64,
    state: InState,
    /// Files in flight: (bytes done, size).
    active: HashMap<TransferId, (u64, u64)>,
    done: u64,
    done_files: u32,
    paused: bool,
}

/// Folder bookkeeping of an [`Engine`].
#[derive(Default)]
pub(super) struct Folders {
    pub(super) out: HashMap<TransferId, FolderOut>,
    pub(super) inc: HashMap<TransferId, FolderIn>,
    /// File transfer id -> its folder's id (until the file's last event).
    pub(super) member: HashMap<TransferId, TransferId>,
    /// Events for the app, after folder translation.
    pub(super) ready: VecDeque<TransferEvent>,
}

/// The subfolder parts of a folder file's ref, checked like file names.
pub fn check_folder(f: &FolderRef) -> Result<Vec<String>, String> {
    path::check_name(&f.top).map_err(|e| format!("folder name: {e}"))?;
    if f.files == 0 || f.files > MAX_FOLDER_FILES {
        return Err(format!("a folder of {} files", f.files));
    }
    if f.path.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<String> = f.path.split('\\').map(str::to_string).collect();
    if parts.len() > MAX_FOLDER_DEPTH {
        return Err(format!("{} subfolders deep", parts.len()));
    }
    for p in &parts {
        path::check_name(p).map_err(|e| format!("subfolder: {e}"))?;
    }
    Ok(parts)
}

/// A local folder's files for [`Engine::send_folder`]: every regular file
/// below `root`, in name order, with its subfolders. Links, junctions and
/// other reparse points are left out (never followed); so are names the
/// receiver would refuse. Returns the folder's name and the files.
pub fn walk(
    root: &Path,
    open: impl Fn(&Path) -> io::Result<Box<dyn Source>> + Clone + Send + 'static,
) -> io::Result<(String, Vec<FolderFile>)> {
    let top = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a folder"))?;
    path::check_name(&top)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut files = Vec::new();
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(root.to_path_buf(), Vec::new())];
    while let Some((dir, parts)) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        let mut subdirs = Vec::new();
        for e in entries {
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if meta.file_type().is_symlink() || is_reparse(&meta) {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if path::check_name(&name).is_err() || path::is_working_file(&name) {
                continue;
            }
            if meta.is_dir() {
                if parts.len() < MAX_FOLDER_DEPTH {
                    let mut p = parts.clone();
                    p.push(name);
                    subdirs.push((e.path(), p));
                }
            } else if meta.is_file() {
                if files.len() as u32 >= MAX_FOLDER_FILES {
                    return Err(io::Error::other(format!(
                        "more than {MAX_FOLDER_FILES} files"
                    )));
                }
                let full = e.path();
                let open = open.clone();
                files.push(FolderFile {
                    path: parts.join("\\"),
                    name,
                    size: meta.len(),
                    open: Box::new(move || open(&full)),
                });
            }
        }
        // Depth first, in name order.
        stack.extend(subdirs.into_iter().rev());
    }
    Ok((top, files))
}

#[cfg(windows)]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_: &std::fs::Metadata) -> bool {
    false
}

fn event_id(e: &TransferEvent) -> TransferId {
    match e {
        TransferEvent::Offered { id, .. }
        | TransferEvent::Progress { id, .. }
        | TransferEvent::Paused { id, .. }
        | TransferEvent::Completed { id, .. }
        | TransferEvent::Failed { id, .. } => *id,
    }
}

impl Engine {
    /// Sends a folder (see the module docs): its name and files, as from
    /// [`walk`]. The peer must have [`crate::msg::cap::FOLDERS`].
    pub fn send_folder(&mut self, top: &str, files: Vec<FolderFile>) -> crate::Result<TransferId> {
        self.send_folder_with_id(new_id()?, top, files)
    }

    /// [`Engine::send_folder`] with an id chosen by the caller.
    pub fn send_folder_with_id(
        &mut self,
        id: TransferId,
        top: &str,
        files: Vec<FolderFile>,
    ) -> crate::Result<TransferId> {
        let bad = |m: String| crate::Error::Malformed(m);
        if !self.allow_send {
            return Err(crate::Error::State("sending files is switched off"));
        }
        path::check_name(top).map_err(|e| bad(e.to_string()))?;
        if files.is_empty() {
            return Err(crate::Error::State("the folder has no files"));
        }
        if files.len() > MAX_FOLDER_FILES as usize {
            return Err(crate::Error::State("too many files in the folder"));
        }
        let probe = FolderRef {
            id,
            top: top.to_string(),
            path: String::new(),
            files: files.len() as u32,
            bytes: 0,
        };
        for f in &files {
            path::check_name(&f.name).map_err(|e| bad(format!("{}: {e}", f.name)))?;
            check_folder(&FolderRef {
                path: f.path.clone(),
                ..probe.clone()
            })
            .map_err(bad)?;
        }
        if self.folders.out.contains_key(&id) {
            return Err(crate::Error::State("transfer id in use"));
        }
        let bytes = files.iter().map(|f| f.size).sum();
        self.folders.out.insert(
            id,
            FolderOut {
                top: top.to_string(),
                files: files.len() as u32,
                queue: files.into(),
                active: HashMap::new(),
                bytes,
                done: 0,
                paused: false,
            },
        );
        self.pump_folder(id);
        Ok(id)
    }

    /// Offers the folder's next files, up to [`FOLDER_PARALLEL`] in flight.
    fn pump_folder(&mut self, id: TransferId) {
        loop {
            let Some(f) = self.folders.out.get_mut(&id) else {
                return;
            };
            if f.active.len() >= FOLDER_PARALLEL || self.sending.len() >= MAX_ACTIVE {
                return;
            }
            let Some(file) = f.queue.pop_front() else {
                if f.active.is_empty() {
                    // Nothing left and nothing in flight.
                    let f = self.folders.out.remove(&id).expect("checked above");
                    self.folders.ready.push_back(TransferEvent::Completed {
                        id,
                        direction: Direction::Send,
                        name: f.top,
                    });
                }
                return;
            };
            let folder = FolderRef {
                id,
                top: f.top.clone(),
                path: file.path.clone(),
                files: f.files,
                bytes: f.bytes,
            };
            let name = file.name.clone();
            let r = new_id().map_err(|e| e.to_string()).and_then(|fid| {
                let src = (file.open)().map_err(|e| e.to_string())?;
                self.offer_file(fid, &name, src, Some(folder))
                    .map_err(|e| e.to_string())
            });
            match r {
                Ok(fid) => {
                    let f = self.folders.out.get_mut(&id).expect("checked above");
                    f.active.insert(fid, (0, file.size));
                    self.folders.member.insert(fid, id);
                }
                Err(e) => {
                    self.fail_folder_out(id, reason::IO, false, &format!("{name}: {e}"));
                    return;
                }
            }
        }
    }

    /// Ends a folder being sent: its files in flight are cancelled.
    pub(super) fn fail_folder_out(
        &mut self,
        id: TransferId,
        code: u8,
        by_peer: bool,
        detail: &str,
    ) {
        let Some(f) = self.folders.out.remove(&id) else {
            return;
        };
        for fid in f.active.keys() {
            self.fail_send(*fid, code, "the folder was cancelled", true);
        }
        self.folders.ready.push_back(TransferEvent::Failed {
            id,
            direction: Direction::Send,
            reason: code,
            by_peer,
            detail: detail.to_string(),
        });
    }

    /// Ends a folder being received: its files are refused or cancelled.
    pub(super) fn fail_folder_in(&mut self, id: TransferId, code: u8, by_peer: bool, detail: &str) {
        let Some(f) = self.folders.inc.get_mut(&id) else {
            return;
        };
        if matches!(f.state, InState::Closed) {
            return;
        }
        let mut ids: Vec<TransferId> = f.active.keys().copied().collect();
        if let InState::Offered(held) = std::mem::replace(&mut f.state, InState::Closed) {
            ids.extend(held);
        }
        for fid in ids {
            self.fail_receive(fid, code, "the folder was cancelled", true);
        }
        self.folders.ready.push_back(TransferEvent::Failed {
            id,
            direction: Direction::Receive,
            reason: code,
            by_peer,
            detail: detail.to_string(),
        });
    }

    /// Accepts an offered folder into `dir` (see the module docs).
    pub(super) fn accept_folder(
        &mut self,
        id: TransferId,
        mut dir: Box<dyn TargetDir>,
    ) -> crate::Result<()> {
        let Some(f) = self.folders.inc.get_mut(&id) else {
            return Err(crate::Error::State("no such offer"));
        };
        if !matches!(f.state, InState::Offered(_)) {
            return Err(crate::Error::State("already accepted"));
        }
        let top = f.top.clone();
        let mut made = None;
        for n in 1..=MAX_VARIANTS {
            let name = if n == 1 {
                top.clone()
            } else {
                format!("{top} ({n})")
            };
            match dir.create_dir_new(&name) {
                Ok(()) => {
                    made = Some(name);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    self.fail_folder_in(id, reason::IO, false, &e.to_string());
                    return Ok(());
                }
            }
        }
        let Some(name) = made else {
            self.fail_folder_in(id, reason::IO, false, "no free folder name");
            return Ok(());
        };
        let root = match dir.subdir(std::slice::from_ref(&name)) {
            Ok(r) => r,
            Err(e) => {
                self.fail_folder_in(id, reason::IO, false, &e.to_string());
                return Ok(());
            }
        };
        let f = self.folders.inc.get_mut(&id).expect("checked above");
        let InState::Offered(held) = std::mem::replace(&mut f.state, InState::Accepted(root, name))
        else {
            unreachable!("checked above");
        };
        for fid in held {
            self.accept_member(id, fid);
        }
        Ok(())
    }

    /// Takes a file of an accepted folder into its subfolder.
    fn accept_member(&mut self, folder: TransferId, fid: TransferId) {
        let parts = self
            .receiving
            .get(&fid)
            .and_then(|r| r.offer.folder.as_ref())
            .map(check_folder);
        let dir = match (parts, self.folders.inc.get(&folder).map(|f| &f.state)) {
            (Some(Ok(parts)), Some(InState::Accepted(root, _))) => root.subdir(&parts),
            (Some(Err(e)), _) => Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
            _ => return,
        };
        match dir {
            Ok(d) => {
                if let Some(f) = self.folders.inc.get_mut(&folder) {
                    let size = self.receiving.get(&fid).map_or(0, |r| r.offer.size);
                    f.active.insert(fid, (0, size));
                }
                let _ = self.accept_file(fid, d);
            }
            Err(e) => self.fail_folder_in(folder, reason::IO, false, &e.to_string()),
        }
    }

    /// A file offer that names a folder (already checked by `on_offer`).
    pub(super) fn folder_file_offered(&mut self, fid: TransferId, fr: FolderRef) {
        self.folders.member.insert(fid, fr.id);
        match self.folders.inc.get_mut(&fr.id).map(|f| &mut f.state) {
            None => {
                self.folders.inc.insert(
                    fr.id,
                    FolderIn {
                        top: fr.top.clone(),
                        files: fr.files,
                        bytes: fr.bytes,
                        state: InState::Offered(vec![fid]),
                        active: HashMap::new(),
                        done: 0,
                        done_files: 0,
                        paused: false,
                    },
                );
                self.folders.ready.push_back(TransferEvent::Offered {
                    id: fr.id,
                    name: fr.top,
                    size: fr.bytes,
                    mtime: 0,
                    files: fr.files,
                });
            }
            Some(InState::Offered(held)) => held.push(fid),
            Some(InState::Accepted(..)) => self.accept_member(fr.id, fid),
            Some(InState::Closed) => self.fail_receive(fid, reason::USER, "folder closed", true),
        }
    }

    /// Next event for the app: file events of folders become folder events.
    pub(super) fn translate(&mut self, e: TransferEvent) {
        let id = event_id(&e);
        let Some(&folder) = self.folders.member.get(&id) else {
            self.folders.ready.push_back(e);
            return;
        };
        let last = matches!(
            e,
            TransferEvent::Completed { .. } | TransferEvent::Failed { .. }
        );
        if last {
            self.folders.member.remove(&id);
        }
        let send = match &e {
            TransferEvent::Progress { direction, .. }
            | TransferEvent::Paused { direction, .. }
            | TransferEvent::Completed { direction, .. }
            | TransferEvent::Failed { direction, .. } => *direction == Direction::Send,
            TransferEvent::Offered { .. } => false,
        };
        if send {
            self.translate_out(folder, id, e);
        } else {
            self.translate_in(folder, id, e);
        }
    }

    fn translate_out(&mut self, folder: TransferId, fid: TransferId, e: TransferEvent) {
        let Some(f) = self.folders.out.get_mut(&folder) else {
            return; // the folder already ended
        };
        match e {
            TransferEvent::Progress { done, .. } => {
                if let Some(a) = f.active.get_mut(&fid) {
                    a.0 = done;
                }
                f.paused = false;
                let done = f.done + f.active.values().map(|a| a.0).sum::<u64>();
                self.folders.ready.push_back(TransferEvent::Progress {
                    id: folder,
                    direction: Direction::Send,
                    done,
                    total: f.bytes,
                });
            }
            TransferEvent::Paused { .. } => {
                if !f.paused {
                    f.paused = true;
                    self.folders.ready.push_back(TransferEvent::Paused {
                        id: folder,
                        direction: Direction::Send,
                    });
                }
            }
            TransferEvent::Completed { .. } => {
                if let Some((_, size)) = f.active.remove(&fid) {
                    f.done += size;
                }
                self.pump_folder(folder);
            }
            TransferEvent::Failed {
                reason,
                by_peer,
                detail,
                ..
            } => {
                f.active.remove(&fid);
                self.fail_folder_out(folder, reason, by_peer, &detail);
            }
            TransferEvent::Offered { .. } => {}
        }
    }

    fn translate_in(&mut self, folder: TransferId, fid: TransferId, e: TransferEvent) {
        let Some(f) = self.folders.inc.get_mut(&folder) else {
            return;
        };
        if matches!(f.state, InState::Closed) {
            return;
        }
        match e {
            TransferEvent::Progress { done, .. } => {
                if let Some(a) = f.active.get_mut(&fid) {
                    a.0 = done;
                }
                f.paused = false;
                let done = f.done + f.active.values().map(|a| a.0).sum::<u64>();
                self.folders.ready.push_back(TransferEvent::Progress {
                    id: folder,
                    direction: Direction::Receive,
                    done,
                    total: f.bytes,
                });
            }
            TransferEvent::Paused { .. } => {
                if !f.paused {
                    f.paused = true;
                    self.folders.ready.push_back(TransferEvent::Paused {
                        id: folder,
                        direction: Direction::Receive,
                    });
                }
            }
            TransferEvent::Completed { .. } => {
                if let Some((_, size)) = f.active.remove(&fid) {
                    f.done += size;
                }
                f.done_files += 1;
                if f.done_files >= f.files && f.active.is_empty() {
                    let name = match std::mem::replace(&mut f.state, InState::Closed) {
                        InState::Accepted(_, name) => name,
                        _ => f.top.clone(),
                    };
                    self.folders.ready.push_back(TransferEvent::Completed {
                        id: folder,
                        direction: Direction::Receive,
                        name,
                    });
                }
            }
            TransferEvent::Failed {
                reason,
                by_peer,
                detail,
                ..
            } => {
                f.active.remove(&fid);
                if let InState::Offered(held) = &mut f.state {
                    held.retain(|h| *h != fid);
                }
                self.fail_folder_in(folder, reason, by_peer, &detail);
            }
            TransferEvent::Offered { .. } => {}
        }
    }

    /// Whether `id` is a folder this engine sends or receives.
    pub(super) fn is_folder(&self, id: &TransferId) -> (bool, bool) {
        (
            self.folders.out.contains_key(id),
            self.folders.inc.contains_key(id),
        )
    }
}
