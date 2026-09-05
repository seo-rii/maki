//! `CrashableBacking` — an in-memory `Backing` with POSIX-faithful crash
//! semantics (SPEC §42 `CrashableBacking`).
//!
//! Durability rules simulated:
//! - `write_at`/`set_len` are volatile until `sync_data` on the file,
//! - file creation/removal is volatile until `sync_dir` on the parent,
//! - on crash, each volatile operation is independently kept or lost,
//! - optionally, the last surviving write of a file may be *torn* (prefix
//!   kept at a configurable granularity),
//! - a removal that was never dir-synced may resurrect the file,
//! - a creation that was never dir-synced may vanish even if its data was
//!   fdatasync'd (orphan inode).
//!
//! Fault injection: a hook may fail any operation (e.g. ENOSPC on append,
//! EIO on fsync) — used by journal/checkpoint failpoint tests.
//!
//! Failure semantics are Linux-faithful, not "the syscall never happened":
//! - a failed `sync_data` marks every dirty write *clean without persisting
//!   it* (the page cache keeps showing the bytes, a later `sync_data` has
//!   nothing left to write, a crash drops them) — the writeback-error
//!   behaviour PostgreSQL's `data_sync_retry` documents (F01);
//! - a `write_at` may persist a prefix and then fail (the partial-write
//!   hook), leaving the file longer than the caller's logical end (F03).

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::Rng;

use maki_backing::path::validate;
use maki_backing::{Backing, BackingFile, VolumeLock};

/// Operation descriptor passed to the fault hook.
#[derive(Debug)]
pub enum FaultOp<'a> {
    Open {
        path: &'a str,
        create: bool,
    },
    WriteAt {
        path: &'a str,
        offset: u64,
        len: usize,
    },
    SetLen {
        path: &'a str,
        len: u64,
    },
    SyncData {
        path: &'a str,
    },
    SyncDir {
        dir: &'a str,
    },
    Remove {
        path: &'a str,
    },
    Rename {
        from: &'a str,
        to: &'a str,
    },
}

pub type FaultHook = Arc<dyn Fn(&FaultOp<'_>) -> Option<io::Error> + Send + Sync>;

/// A hook that turns a `write_at` into a *partial* write: `Some((n, err))`
/// persists the first `n` bytes of the write (as a normal dirty write) and
/// returns `err` to the caller, exactly like `write_all_at` failing on its
/// second `pwrite`.
pub type PartialWriteHook = Arc<dyn Fn(&FaultOp<'_>) -> Option<(usize, io::Error)> + Send + Sync>;

#[derive(Clone, Debug)]
enum Pend {
    Write { offset: u64, data: Vec<u8> },
    SetLen(u64),
}

#[derive(Clone, Debug, Default)]
struct FileState {
    /// Content known durable (data-synced). `None` = no durable content.
    durable: Option<Vec<u8>>,
    /// Whether the directory entry is durable.
    dirent_durable: bool,
    /// Volatile existence + pending ops. `None` = removed in volatile view.
    volatile: Option<Volatile>,
}

#[derive(Clone, Debug, Default)]
struct Volatile {
    /// If false, the durable image of the next successful sync starts from
    /// an empty file (fresh inode after re-create), not from the durable
    /// content.
    base_durable: bool,
    /// Dirty operations: what the next successful `sync_data` persists.
    pending: Vec<Pend>,
    /// The page-cache view: every operation ever applied, including writes
    /// a failed `sync_data` marked clean without persisting.
    image: Vec<u8>,
}

impl Volatile {
    fn fresh() -> Self {
        Self::default()
    }

    fn from_durable(durable: &[u8]) -> Self {
        Self {
            base_durable: true,
            pending: Vec::new(),
            image: durable.to_vec(),
        }
    }
}

#[derive(Default)]
struct Inner {
    files: BTreeMap<String, FileState>,
    /// dir path -> dirent durable?
    dirs: BTreeMap<String, bool>,
    locks: std::collections::HashSet<String>,
    hook: Option<FaultHook>,
    partial_hook: Option<PartialWriteHook>,
    /// When set, a failed `sync_data` leaves its dirty writes dirty (the
    /// "syscall never happened" model). The default is the Linux model:
    /// the writes are marked clean and lost.
    lenient_sync_failures: bool,
    stats_pending_writes: usize,
    /// Simulated free space reported by `Backing::free_bytes`.
    free_bytes: Option<u64>,
}

impl Inner {
    fn check(&self, op: &FaultOp<'_>) -> io::Result<()> {
        if let Some(hook) = &self.hook {
            if let Some(err) = hook(op) {
                return Err(err);
            }
        }
        Ok(())
    }

    fn compose(&self, state: &FileState) -> Option<Vec<u8>> {
        state.volatile.as_ref().map(|vol| vol.image.clone())
    }
}

/// The content a successful `sync_data` makes durable: the durable base
/// (or an empty fresh inode) plus every *dirty* operation, in order. Writes
/// an earlier failed sync marked clean are not part of it.
fn durable_after_sync(state: &FileState, vol: &Volatile) -> Vec<u8> {
    let mut data = if vol.base_durable {
        state.durable.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    for p in &vol.pending {
        apply(&mut data, p);
    }
    data
}

fn apply(data: &mut Vec<u8>, p: &Pend) {
    match p {
        Pend::Write { offset, data: src } => {
            let start = *offset as usize;
            let end = start + src.len();
            if data.len() < end {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(src);
        }
        Pend::SetLen(len) => data.resize(*len as usize, 0),
    }
}

/// Persist a write partially at sector granularity `gran`: either only a
/// prefix of its sectors reached the disk (the file did not grow past it),
/// or every sector but one random one did (a hole of stale bytes inside an
/// otherwise complete write).
fn apply_torn(data: &mut Vec<u8>, offset: u64, src: &[u8], gran: usize, rng: &mut impl Rng) {
    let sectors = src.len().div_ceil(gran);
    if sectors == 0 {
        return;
    }
    if rng.random_bool(0.5) {
        let keep = (rng.random_range(0..sectors) * gran).min(src.len());
        apply(
            data,
            &Pend::Write {
                offset,
                data: src[..keep].to_vec(),
            },
        );
    } else {
        let hole = rng.random_range(0..sectors);
        let hole_start = hole * gran;
        let hole_end = (hole_start + gran).min(src.len());
        apply(
            data,
            &Pend::Write {
                offset,
                data: src[..hole_start].to_vec(),
            },
        );
        if hole_end < src.len() {
            apply(
                data,
                &Pend::Write {
                    offset: offset + hole_end as u64,
                    data: src[hole_end..].to_vec(),
                },
            );
        } else if data.len() < offset as usize + src.len() {
            // The hole is the final sector: the file still grew to cover
            // it (sectors persist in any order), holding stale bytes.
            data.resize(offset as usize + src.len(), 0);
        }
    }
}

/// In-memory crash-simulating backing.
#[derive(Clone, Default)]
pub struct CrashableBacking {
    inner: Arc<Mutex<Inner>>,
    /// Tear granularity for torn writes during random crashes (None = off).
    tearing: Option<usize>,
}

impl CrashableBacking {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable random torn-write simulation at `granularity` bytes.
    pub fn with_tearing(mut self, granularity: usize) -> Self {
        assert!(granularity > 0);
        self.tearing = Some(granularity);
        self
    }

    pub fn set_fault_hook(&self, hook: Option<FaultHook>) {
        self.inner.lock().hook = hook;
    }

    /// Install a partial-write hook (see [`PartialWriteHook`]).
    pub fn set_partial_write_hook(&self, hook: Option<PartialWriteHook>) {
        self.inner.lock().partial_hook = hook;
    }

    /// Choose what a failed `sync_data` does to the dirty writes it could
    /// not persist. `false` (the default) is the Linux model: they are
    /// marked clean and lost, a retry of the sync has nothing to write.
    /// `true` keeps them dirty, as if the syscall had never run.
    pub fn set_lenient_sync_failures(&self, lenient: bool) {
        self.inner.lock().lenient_sync_failures = lenient;
    }

    /// Simulate the free space the backing filesystem reports (`None` =
    /// unknown, the default).
    pub fn set_free_bytes(&self, free: Option<u64>) {
        self.inner.lock().free_bytes = free;
    }

    pub fn pending_write_count(&self) -> usize {
        self.inner.lock().stats_pending_writes
    }

    /// Simulate a crash: every volatile operation is independently kept or
    /// lost; the last surviving write of each file may be torn if tearing is
    /// enabled. Afterwards, everything that survived is durable.
    pub fn crash(&self, rng: &mut impl Rng) {
        let tearing = self.tearing;
        let mut inner = self.inner.lock();
        inner.stats_pending_writes = 0;

        // Directories: unsynced dirs may vanish (only if empty of surviving
        // files — for simplicity keep dirs whose creation survived the coin).
        let dirs: Vec<String> = inner.dirs.keys().cloned().collect();
        for d in dirs {
            let durable = inner.dirs[&d];
            if !durable {
                if rng.random_bool(0.5) {
                    inner.dirs.insert(d, true);
                } else {
                    inner.dirs.remove(&d);
                }
            }
        }

        let names: Vec<String> = inner.files.keys().cloned().collect();
        for name in names {
            let state = inner.files.get(&name).unwrap().clone();
            let new_state = match &state.volatile {
                None => {
                    // Removed in volatile view.
                    let deletion_durable = !state.dirent_durable;
                    if deletion_durable || rng.random_bool(0.5) {
                        None // deletion persisted
                    } else {
                        // deletion lost: file resurrects with durable content
                        state.durable.as_ref().map(|d| FileState {
                            durable: Some(d.clone()),
                            dirent_durable: true,
                            volatile: Some(Volatile::from_durable(d)),
                        })
                    }
                }
                Some(vol) => {
                    let dirent_survives = state.dirent_durable || rng.random_bool(0.5);
                    if !dirent_survives {
                        None
                    } else {
                        let mut data = if vol.base_durable {
                            state.durable.clone().unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        // Keep each pending op independently. With tearing
                        // enabled *any* kept write may persist partially at
                        // sector granularity — not only the last one: sectors
                        // of unsynced writes reach the platter in any order,
                        // so an earlier record can be torn while a later one
                        // is intact (SPEC §27 torn-tail classification).
                        let kept: Vec<&Pend> = vol
                            .pending
                            .iter()
                            .filter(|_| rng.random_bool(0.5))
                            .collect();
                        for p in kept {
                            if let (Some(gran), Pend::Write { offset, data: src }) = (tearing, p) {
                                if rng.random_bool(0.3) {
                                    apply_torn(&mut data, *offset, src, gran, rng);
                                    continue;
                                }
                            }
                            apply(&mut data, p);
                        }
                        Some(FileState {
                            volatile: Some(Volatile::from_durable(&data)),
                            durable: Some(data),
                            dirent_durable: true,
                        })
                    }
                }
            };
            match new_state {
                Some(s) => {
                    inner.files.insert(name, s);
                }
                None => {
                    inner.files.remove(&name);
                }
            }
        }
    }

    /// Crash losing *every* volatile operation (worst case): unsynced writes
    /// dropped, unsynced creations vanish, unsynced deletions resurrect.
    pub fn crash_all_lost(&self) {
        let mut inner = self.inner.lock();
        inner.stats_pending_writes = 0;
        let names: Vec<String> = inner.files.keys().cloned().collect();
        for name in names {
            let state = inner.files.get(&name).unwrap().clone();
            let survives = state.dirent_durable && state.durable.is_some();
            if survives {
                let durable = state.durable.clone().unwrap_or_default();
                inner.files.insert(
                    name,
                    FileState {
                        volatile: Some(Volatile::from_durable(&durable)),
                        durable: Some(durable),
                        dirent_durable: true,
                    },
                );
            } else {
                inner.files.remove(&name);
            }
        }
        let dirs: Vec<String> = inner.dirs.keys().cloned().collect();
        for d in dirs {
            if !inner.dirs[&d] {
                inner.dirs.remove(&d);
            }
        }
    }

    /// Deterministic torn-tail crash for journal tests: all pending ops of
    /// `path` are applied except the final write, which keeps only its first
    /// `keep_bytes` bytes. Other files crash losing all volatile state.
    pub fn crash_keep_torn_prefix(&self, path: &str, keep_bytes: usize) {
        {
            let mut inner = self.inner.lock();
            let state = inner.files.get(path).expect("file must exist").clone();
            let vol = state.volatile.as_ref().expect("file removed");
            let mut data = if vol.base_durable {
                state.durable.clone().unwrap_or_default()
            } else {
                Vec::new()
            };
            let last_write_idx = vol
                .pending
                .iter()
                .rposition(|p| matches!(p, Pend::Write { .. }));
            for (i, p) in vol.pending.iter().enumerate() {
                if Some(i) == last_write_idx {
                    if let Pend::Write { offset, data: src } = p {
                        let keep = keep_bytes.min(src.len());
                        // Torn tail: the file only grew as far as the kept
                        // prefix reaches.
                        let end = *offset as usize + keep;
                        apply(
                            &mut data,
                            &Pend::Write {
                                offset: *offset,
                                data: src[..keep].to_vec(),
                            },
                        );
                        data.truncate(end.max(if vol.base_durable {
                            state.durable.as_ref().map_or(0, |d| d.len())
                        } else {
                            0
                        }));
                        continue;
                    }
                }
                apply(&mut data, p);
            }
            inner.files.insert(
                path.to_string(),
                FileState {
                    volatile: Some(Volatile::from_durable(&data)),
                    durable: Some(data),
                    dirent_durable: true,
                },
            );
        }
        // Everything else: worst case.
        let inner = self.inner.lock();
        let names: Vec<String> = inner
            .files
            .keys()
            .filter(|n| n.as_str() != path)
            .cloned()
            .collect();
        drop(inner);
        for name in names {
            let mut inner = self.inner.lock();
            let state = inner.files.get(&name).unwrap().clone();
            let survives = state.dirent_durable && state.durable.is_some();
            if survives {
                let durable = state.durable.clone().unwrap_or_default();
                inner.files.insert(
                    name,
                    FileState {
                        volatile: Some(Volatile::from_durable(&durable)),
                        durable: Some(durable),
                        dirent_durable: true,
                    },
                );
            } else {
                inner.files.remove(&name);
            }
        }
    }
}

pub struct CrashFile {
    inner: Arc<Mutex<Inner>>,
    path: String,
}

impl CrashFile {
    fn with_state<R>(
        &self,
        f: impl FnOnce(&mut Inner, &mut FileState) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut inner = self.inner.lock();
        let mut state = inner
            .files
            .get(&self.path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, self.path.clone()))?;
        if state.volatile.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} (removed)", self.path),
            ));
        }
        // A failing operation can still have changed the file (a partial
        // write persisted its prefix, a failed sync marked pages clean):
        // keep the state whatever the outcome.
        let r = f(&mut inner, &mut state);
        inner.files.insert(self.path.clone(), state);
        r
    }
}

impl BackingFile for CrashFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.with_state(|inner, state| {
            let data = inner.compose(state).unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("read {}..{} past EOF {}", start, end, data.len()),
                ));
            }
            buf.copy_from_slice(&data[start..end]);
            Ok(())
        })
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.with_state(|inner, state| {
            let op = FaultOp::WriteAt {
                path: &self.path,
                offset,
                len: data.len(),
            };
            inner.check(&op)?;
            let partial = inner.partial_hook.as_ref().and_then(|hook| hook(&op));
            let (written, outcome) = match partial {
                Some((n, err)) => (&data[..n.min(data.len())], Err(err)),
                None => (data, Ok(())),
            };
            if !written.is_empty() {
                let pend = Pend::Write {
                    offset,
                    data: written.to_vec(),
                };
                let vol = state.volatile.as_mut().unwrap();
                apply(&mut vol.image, &pend);
                vol.pending.push(pend);
                inner.stats_pending_writes += 1;
            }
            outcome
        })
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.with_state(|inner, state| {
            inner.check(&FaultOp::SetLen {
                path: &self.path,
                len,
            })?;
            let vol = state.volatile.as_mut().unwrap();
            apply(&mut vol.image, &Pend::SetLen(len));
            vol.pending.push(Pend::SetLen(len));
            Ok(())
        })
    }

    fn len(&self) -> io::Result<u64> {
        self.with_state(|inner, state| Ok(inner.compose(state).unwrap().len() as u64))
    }

    fn sync_data(&self) -> io::Result<()> {
        self.with_state(|inner, state| {
            if let Err(e) = inner.check(&FaultOp::SyncData { path: &self.path }) {
                if !inner.lenient_sync_failures {
                    // Writeback failed: the kernel marks the pages clean and
                    // keeps their (unpersisted) content in the page cache. A
                    // retry of fsync has nothing dirty to write and succeeds
                    // without touching the disk.
                    state.volatile.as_mut().unwrap().pending.clear();
                }
                return Err(e);
            }
            let vol = state.volatile.as_ref().unwrap();
            let data = durable_after_sync(state, vol);
            state.durable = Some(data);
            let vol = state.volatile.as_mut().unwrap();
            vol.base_durable = true;
            vol.pending.clear();
            Ok(())
        })
    }
}

struct CrashLock {
    inner: Arc<Mutex<Inner>>,
    path: String,
}

impl VolumeLock for CrashLock {}

impl Drop for CrashLock {
    fn drop(&mut self) {
        self.inner.lock().locks.remove(&self.path);
    }
}

impl Backing for CrashableBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate(path, false)?;
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::Open { path, create })?;
        let exists = inner
            .files
            .get(path)
            .map(|s| s.volatile.is_some())
            .unwrap_or(false);
        if !exists {
            if !create {
                return Err(io::Error::new(io::ErrorKind::NotFound, path.to_string()));
            }
            let prev = inner.files.get(path).cloned().unwrap_or_default();
            inner.files.insert(
                path.to_string(),
                FileState {
                    durable: prev.durable,
                    dirent_durable: false,
                    volatile: Some(Volatile::fresh()),
                },
            );
        }
        Ok(Arc::new(CrashFile {
            inner: self.inner.clone(),
            path: path.to_string(),
        }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        validate(path, false)?;
        let inner = self.inner.lock();
        Ok(inner
            .files
            .get(path)
            .map(|s| s.volatile.is_some())
            .unwrap_or(false)
            || inner.dirs.contains_key(path))
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::Remove { path })?;
        match inner.files.get_mut(path) {
            Some(state) if state.volatile.is_some() => {
                state.volatile = None;
                Ok(())
            }
            _ => Err(io::Error::new(io::ErrorKind::NotFound, path.to_string())),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate(from, false)?;
        validate(to, false)?;
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::Rename { from, to })?;
        let src = inner
            .files
            .get(from)
            .cloned()
            .filter(|s| s.volatile.is_some())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, from.to_string()))?;
        let content = inner.compose(&src).unwrap();
        // Fresh volatile file at `to` with the moved content.
        let prev_to = inner.files.get(to).cloned().unwrap_or_default();
        inner.files.insert(
            to.to_string(),
            FileState {
                durable: prev_to.durable,
                dirent_durable: false,
                volatile: Some(Volatile {
                    base_durable: false,
                    pending: vec![Pend::Write {
                        offset: 0,
                        data: content.clone(),
                    }],
                    image: content,
                }),
            },
        );
        inner.files.get_mut(from).unwrap().volatile = None;
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut inner = self.inner.lock();
        let mut cur = String::new();
        for comp in path.split('/') {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(comp);
            inner.dirs.entry(cur.clone()).or_insert(false);
        }
        Ok(())
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        validate(dir, true)?;
        let inner = self.inner.lock();
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut out: Vec<String> = Vec::new();
        for (name, st) in &inner.files {
            if st.volatile.is_none() {
                continue;
            }
            if let Some(rest) = name.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    out.push(rest.to_string());
                }
            }
        }
        for name in inner.dirs.keys() {
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
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::SyncDir { dir })?;
        // Commit namespace state for entries directly inside `dir`.
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let names: Vec<String> = inner.files.keys().cloned().collect();
        for name in names {
            let direct = name
                .strip_prefix(&prefix)
                .map(|r| !r.is_empty() && !r.contains('/'))
                .unwrap_or(false);
            if !direct {
                continue;
            }
            let state = inner.files.get_mut(&name).unwrap();
            match &state.volatile {
                Some(_) => state.dirent_durable = true,
                None => {
                    // deletion becomes durable
                    if state.durable.is_some() || state.dirent_durable {
                        inner.files.remove(&name);
                    }
                }
            }
        }
        if !dir.is_empty() {
            inner.dirs.insert(dir.to_string(), true);
        }
        let dirnames: Vec<String> = inner.dirs.keys().cloned().collect();
        for name in dirnames {
            let direct = name
                .strip_prefix(&prefix)
                .map(|r| !r.is_empty() && !r.contains('/'))
                .unwrap_or(false);
            if direct {
                inner.dirs.insert(name, true);
            }
        }
        Ok(())
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        Ok(self.inner.lock().free_bytes)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        validate(path, false)?;
        let mut inner = self.inner.lock();
        if !inner.locks.insert(path.to_string()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            ));
        }
        Ok(Box::new(CrashLock {
            inner: self.inner.clone(),
            path: path.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eio() -> io::Error {
        io::Error::other("injected EIO")
    }

    /// The Linux writeback-error model: a failed fsync leaves the bytes
    /// visible but unpersisted, a retried fsync succeeds without writing
    /// them, and only a rewrite makes them durable.
    #[test]
    fn failed_sync_marks_dirty_writes_clean_and_lost() {
        let backing = CrashableBacking::new();
        let file = backing.open("f", true).unwrap();
        backing.sync_dir("").unwrap();
        file.write_at(0, b"hello").unwrap();
        let fail_next = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = fail_next.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { .. } if flag.swap(false, std::sync::atomic::Ordering::SeqCst) => {
                Some(eio())
            }
            _ => None,
        })));
        assert!(file.sync_data().is_err());
        let mut buf = [0u8; 5];
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello", "the page cache still shows the bytes");
        file.sync_data().unwrap(); // nothing dirty: succeeds, writes nothing
        backing.crash_all_lost();
        let file = backing.open("f", false).unwrap();
        assert_eq!(
            file.len().unwrap(),
            0,
            "lost writeback must not survive a crash"
        );

        // Rewriting the same bytes dirties them again; the next sync persists them.
        file.write_at(0, b"hello").unwrap();
        file.sync_data().unwrap();
        backing.crash_all_lost();
        let file = backing.open("f", false).unwrap();
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn lenient_mode_keeps_failed_sync_writes_dirty() {
        let backing = CrashableBacking::new();
        backing.set_lenient_sync_failures(true);
        let file = backing.open("f", true).unwrap();
        backing.sync_dir("").unwrap();
        file.write_at(0, b"hello").unwrap();
        let once = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = once.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { .. } if flag.swap(false, std::sync::atomic::Ordering::SeqCst) => {
                Some(eio())
            }
            _ => None,
        })));
        assert!(file.sync_data().is_err());
        file.sync_data().unwrap();
        backing.crash_all_lost();
        assert_eq!(backing.open("f", false).unwrap().len().unwrap(), 5);
    }

    /// A partial write persists its prefix (the file grows past the
    /// caller's logical end) and reports the error.
    #[test]
    fn partial_write_hook_persists_a_prefix_and_fails() {
        let backing = CrashableBacking::new();
        let file = backing.open("f", true).unwrap();
        backing.sync_dir("").unwrap();
        backing.set_partial_write_hook(Some(Arc::new(|op| match op {
            FaultOp::WriteAt { len, .. } if *len == 8 => Some((3, eio())),
            _ => None,
        })));
        assert!(file.write_at(0, b"abcdefgh").is_err());
        assert_eq!(file.len().unwrap(), 3);
        file.write_at(0, b"xy").unwrap();
        let mut buf = [0u8; 3];
        file.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"xyc", "the torn prefix outlives a shorter overwrite");
        file.sync_data().unwrap();
        backing.crash_all_lost();
        assert_eq!(backing.open("f", false).unwrap().len().unwrap(), 3);
    }
}
