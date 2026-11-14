//! The Persistent Bitmap Cache on disk (MS-RDPEGDI 3.2.1.4) and the
//! Persistent Key List PDU (MS-RDPBCGR 2.2.1.17).
//!
//! One file per bitmap: `<dir>/c<cacheId>/<key as 16 hex digits>.bmp`, a
//! small header and the pixels as B, G, R bytes. The directory is held to a
//! byte cap by deleting the oldest files (by modification time); loading a
//! bitmap at connect refreshes its time.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::Bitmap;
use crate::cursor::Put;
use crate::trace;

const MAGIC: &[u8; 4] = b"RDPB";
const VERSION: u8 = 1;
const HEADER: usize = 9;
/// Largest bitmap side kept on disk (bitmap cache tiles are 64 x 64).
const MAX_SIDE: usize = 256;

/// PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST (MS-RDPBCGR 2.2.1.17.1).
pub const PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST: u8 = 43;
/// Keys per Persistent Key List PDU (2.2.1.17.1: SHOULD be at most 169).
pub const KEYS_PER_PDU: usize = 169;
const PERSIST_PDU_FIRST: u8 = 0x01;
const PERSIST_PDU_LAST: u8 = 0x02;

pub struct Store {
    dir: PathBuf,
    cap: u64,
    used: u64,
}

struct Entry {
    path: PathBuf,
    size: u64,
    time: SystemTime,
}

impl Store {
    /// Opens (creating) the cache directory and trims it to `cap` bytes.
    pub fn open(dir: &Path, cap: u64) -> io::Result<Store> {
        fs::create_dir_all(dir)?;
        let mut s = Store {
            dir: dir.to_path_buf(),
            cap,
            used: 0,
        };
        s.evict(cap);
        Ok(s)
    }

    fn path(&self, cache: u8, key: u64) -> PathBuf {
        self.dir
            .join(format!("c{cache}"))
            .join(format!("{key:016x}.bmp"))
    }

    fn entries(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        let Ok(dirs) = fs::read_dir(&self.dir) else {
            return out;
        };
        for d in dirs.flatten() {
            let Ok(files) = fs::read_dir(d.path()) else {
                continue;
            };
            for f in files.flatten() {
                let Ok(m) = f.metadata() else { continue };
                if m.is_file() {
                    out.push(Entry {
                        path: f.path(),
                        size: m.len(),
                        time: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    });
                }
            }
        }
        out
    }

    /// Deletes the oldest files until at most `target` bytes remain.
    fn evict(&mut self, target: u64) {
        let mut all = self.entries();
        let mut total: u64 = all.iter().map(|e| e.size).sum();
        all.sort_by_key(|e| e.time);
        for e in all {
            if total <= target {
                break;
            }
            if fs::remove_file(&e.path).is_ok() {
                total -= e.size;
            }
        }
        self.used = total;
    }

    /// Up to `max` bitmaps of cache `cache`, newest first, as (key, bitmap).
    /// Unreadable files are deleted.
    pub fn load(&mut self, cache: u8, max: usize) -> Vec<(u64, Bitmap)> {
        let dir = self.dir.join(format!("c{cache}"));
        let mut files: Vec<(SystemTime, u64, PathBuf)> = fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|f| {
                let name = f.file_name().into_string().ok()?;
                let key = u64::from_str_radix(name.strip_suffix(".bmp")?, 16).ok()?;
                let time = f.metadata().ok()?.modified().ok()?;
                Some((time, key, f.path()))
            })
            .collect();
        files.sort_by_key(|f| std::cmp::Reverse(f.0));
        let mut out = Vec::new();
        for (_, key, path) in files {
            if out.len() >= max {
                break;
            }
            match fs::read(&path).ok().and_then(|b| decode(&b)) {
                Some(bmp) => {
                    // Loaded bitmaps count as used: keep them longest.
                    if let Ok(f) = fs::File::options().write(true).open(&path) {
                        let _ = f.set_modified(SystemTime::now());
                    }
                    out.push((key, bmp));
                }
                None => {
                    trace!("persistent bitmap {} unreadable, removed", path.display());
                    let _ = fs::remove_file(&path);
                }
            }
        }
        out
    }

    /// Stores a bitmap under its key. Errors are traced, never fatal.
    pub fn save(&mut self, cache: u8, key: u64, bmp: &Bitmap) {
        let Some(bytes) = encode(bmp) else { return };
        let path = self.path(cache, key);
        if path.exists() {
            return;
        }
        if self.used + bytes.len() as u64 > self.cap {
            self.evict(self.cap / 10 * 9);
        }
        let tmp = path.with_extension("tmp");
        let written = path
            .parent()
            .map_or(Ok(()), fs::create_dir_all)
            .and_then(|_| fs::write(&tmp, &bytes))
            .and_then(|_| fs::rename(&tmp, &path));
        match written {
            Ok(()) => self.used += bytes.len() as u64,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                trace!("persistent bitmap not saved: {e}");
            }
        }
    }
}

fn encode(b: &Bitmap) -> Option<Vec<u8>> {
    if b.w == 0 || b.h == 0 || b.w > MAX_SIDE || b.h > MAX_SIDE {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER + b.px.len() * 3);
    out.put_bytes(MAGIC);
    out.put_u8(VERSION);
    out.put_u16(b.w as u16);
    out.put_u16(b.h as u16);
    for p in &b.px {
        out.put_bytes(&[*p as u8, (p >> 8) as u8, (p >> 16) as u8]);
    }
    Some(out)
}

fn decode(d: &[u8]) -> Option<Bitmap> {
    if d.len() < HEADER || &d[..4] != MAGIC || d[4] != VERSION {
        return None;
    }
    let w = u16::from_le_bytes([d[5], d[6]]) as usize;
    let h = u16::from_le_bytes([d[7], d[8]]) as usize;
    if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE || d.len() != HEADER + w * h * 3 {
        return None;
    }
    let px = d[HEADER..]
        .as_chunks::<3>()
        .0
        .iter()
        .map(|c| c[0] as u32 | (c[1] as u32) << 8 | (c[2] as u32) << 16)
        .collect();
    Some(Bitmap { w, h, px })
}

/// Persistent Key List PDU bodies (MS-RDPBCGR 2.2.1.17.1) for `keys`, one
/// list per bitmap cache in cache-index order. Each body goes in a share
/// data PDU of type PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST. Empty when there
/// are no keys.
pub fn key_list_pdus(keys: &[Vec<u64>]) -> Vec<Vec<u8>> {
    let mut totals = [0u16; 5];
    let mut flat = Vec::new();
    for (cache, list) in keys.iter().enumerate().take(5) {
        totals[cache] = list.len() as u16;
        flat.extend(list.iter().map(|&k| (cache, k)));
    }
    let chunks: Vec<&[(usize, u64)]> = flat.chunks(KEYS_PER_PDU).collect();
    let last = chunks.len().saturating_sub(1);
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut n = [0u16; 5];
            for (cache, _) in chunk.iter() {
                n[*cache] += 1;
            }
            let mut b = Vec::with_capacity(24 + chunk.len() * 8);
            n.iter().for_each(|v| b.put_u16(*v));
            totals.iter().for_each(|v| b.put_u16(*v));
            let mut mask = 0;
            if i == 0 {
                mask |= PERSIST_PDU_FIRST;
            }
            if i == last {
                mask |= PERSIST_PDU_LAST;
            }
            b.put_u8(mask);
            b.put_u8(0);
            b.put_u16(0);
            for (_, k) in chunk.iter() {
                b.put_u32(*k as u32);
                b.put_u32((k >> 32) as u32);
            }
            b
        })
        .collect()
}
