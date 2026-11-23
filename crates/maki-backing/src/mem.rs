//! Simple in-memory backing (always-durable; no crash semantics).
//! For unit tests and benchmarks. Crash simulation lives in
//! `maki-test-support::CrashableBacking`.
//!
//! The namespace follows POSIX path rules like the real backings: every
//! ancestor of a path must be an existing directory (`NotFound`, or
//! `NotADirectory` when one is a file), and a directory name cannot be
//! opened, locked, renamed over or removed as a file (`IsADirectory`).

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::path::validate;
use crate::{Backing, BackingFile, VolumeLock};

#[derive(Default)]
struct Namespace {
    files: BTreeMap<String, Arc<MemFile>>,
    dirs: HashSet<String>,
}

impl Namespace {
    /// `dir` ("" = root) and each of its ancestors must be a directory,
    /// as for a path lookup on a filesystem.
    fn require_dir(&self, dir: &str) -> io::Result<()> {
        let mut prefix = String::new();
        for part in dir.split('/').filter(|part| !part.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if self.files.contains_key(&prefix) {
                return Err(io::Error::new(io::ErrorKind::NotADirectory, prefix));
            }
            if !self.dirs.contains(&prefix) {
                return Err(io::Error::new(io::ErrorKind::NotFound, prefix));
            }
        }
        Ok(())
    }

    /// The parent of `path` exists and `path` itself is not a directory.
    fn require_file_name(&self, path: &str) -> io::Result<()> {
        self.require_dir(parent(path))?;
        if self.dirs.contains(path) {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                path.to_string(),
            ));
        }
        Ok(())
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// In-memory `Backing`. All operations are immediately "durable".
#[derive(Default)]
pub struct MemBacking {
    ns: Mutex<Namespace>,
}

impl MemBacking {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default)]
pub struct MemFile {
    data: Mutex<Vec<u8>>,
    locked: AtomicBool,
}

impl BackingFile for MemFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let data = self.data.lock();
        let start = usize::try_from(offset).map_err(bad_offset)?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| bad_offset("overflow"))?;
        if end > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("read past EOF: {end} > {}", data.len()),
            ));
        }
        buf.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_at(&self, offset: u64, src: &[u8]) -> io::Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        let mut data = self.data.lock();
        let start = usize::try_from(offset).map_err(bad_offset)?;
        let end = start
            .checked_add(src.len())
            .ok_or_else(|| bad_offset("overflow"))?;
        if data.len() < end {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(src);
        Ok(())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let mut data = self.data.lock();
        let len = usize::try_from(len).map_err(bad_offset)?;
        let truncated = len < data.len();
        data.resize(len, 0);
        // Leave room for Vec's growth so alternating a tail write and a small
        // truncation doesn't repeatedly free and reallocate the same buffer.
        if truncated && len <= data.capacity() / 4 {
            data.shrink_to_fit();
        }
        Ok(())
    }

    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| bad_offset("allocation overflow"))?;
        let end = usize::try_from(end).map_err(bad_offset)?;
        let mut data = self.data.lock();
        if data.len() < end {
            data.resize(end, 0);
        }
        Ok(())
    }

    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| bad_offset("hole-punch overflow"))?;
        let mut data = self.data.lock();
        if offset >= data.len() as u64 {
            return Ok(());
        }
        let start = usize::try_from(offset).map_err(bad_offset)?;
        let end = usize::try_from(end.min(data.len() as u64)).map_err(bad_offset)?;
        data[start..end].fill(0);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.data.lock().len() as u64)
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }
}

fn bad_offset<E: std::fmt::Debug>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("bad offset: {e:?}"))
}

struct MemLock {
    file: Arc<MemFile>,
}

impl VolumeLock for MemLock {}

impl Drop for MemLock {
    fn drop(&mut self) {
        self.file.locked.store(false, Ordering::Release);
    }
}

impl Backing for MemBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate(path, false)?;
        let mut ns = self.ns.lock();
        ns.require_file_name(path)?;
        if let Some(file) = ns.files.get(path) {
            return Ok(file.clone());
        }
        if !create {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such file: {path}"),
            ));
        }
        let file = Arc::new(MemFile::default());
        ns.files.insert(path.to_string(), file.clone());
        Ok(file)
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        validate(path, false)?;
        let ns = self.ns.lock();
        match ns.require_dir(parent(path)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            result => result?,
        }
        Ok(ns.files.contains_key(path) || ns.dirs.contains(path))
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut ns = self.ns.lock();
        ns.require_file_name(path)?;
        ns.files
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("remove: {path}")))
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate(from, false)?;
        validate(to, false)?;
        let mut ns = self.ns.lock();
        ns.require_dir(parent(from))?;
        if ns.dirs.contains(from) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "directory rename is unsupported",
            ));
        }
        ns.require_file_name(to)?;
        let data = ns
            .files
            .remove(from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("rename: {from}")))?;
        ns.files.insert(to.to_string(), data);
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut ns = self.ns.lock();
        let mut cur = String::new();
        for comp in path.split('/') {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(comp);
            if ns.files.contains_key(&cur) {
                return Err(io::Error::new(io::ErrorKind::NotADirectory, cur));
            }
            ns.dirs.insert(cur.clone());
        }
        Ok(())
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        validate(dir, true)?;
        let ns = self.ns.lock();
        ns.require_dir(dir)?;
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut out: Vec<String> = Vec::new();
        for name in ns.files.keys().chain(ns.dirs.iter()) {
            if let Some(rest) = name.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    out.push(rest.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        validate(dir, true)?;
        self.ns.lock().require_dir(dir)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        validate(path, false)?;
        let mut ns = self.ns.lock();
        ns.require_file_name(path)?;
        let file = ns.files.entry(path.to_string()).or_default();
        if file.locked.swap(true, Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            ));
        }
        Ok(Box::new(MemLock { file: file.clone() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_truncations_keep_room_for_repeated_tail_writes() {
        let file = MemFile::default();
        file.set_len(4096).unwrap();
        file.write_at(4096, b"x").unwrap();
        let capacity = file.data.lock().capacity();
        file.set_len(4096).unwrap();
        assert_eq!(file.data.lock().capacity(), capacity);
    }

    #[test]
    fn truncating_a_memory_file_releases_its_large_buffer() {
        let file = MemFile::default();
        file.set_len(1 << 20).unwrap();
        file.write_at(0, b"abc").unwrap();
        file.set_len(3).unwrap();
        assert!(file.data.lock().capacity() < 1 << 20);
        let mut prefix = [0; 3];
        file.read_at(0, &mut prefix).unwrap();
        assert_eq!(&prefix, b"abc");

        file.set_len(0).unwrap();
        assert_eq!(file.data.lock().capacity(), 0);
        file.write_at(2, b"z").unwrap();
        file.read_at(0, &mut prefix).unwrap();
        assert_eq!(&prefix, b"\0\0z");
    }
}
