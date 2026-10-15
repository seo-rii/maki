//! `CrashableBacking` — an in-memory `Backing` with POSIX-faithful crash
//! semantics (SPEC §42 `CrashableBacking`).
//!
//! Durability rules simulated:
//! - `write_at`/`set_len` are volatile until `sync_data` on the file,
//! - file creation/removal/rename is volatile until `sync_dir` on the parent;
//!   names and inodes are separate, so a durable name can survive with its
//!   unsynced data lost and a rename is kept or undone as a whole,
//! - on crash, each volatile operation is independently kept or lost,
//! - optionally, any surviving write may be *torn* at sector boundaries of
//!   a configurable granularity, aligned to the file (a prefix of sectors
//!   kept, or one sector missing),
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

type InodeId = u64;

/// File content, independent of any name (TEST-004): an open handle keeps
/// its inode across `remove` and `rename`, a re-created name is a new inode,
/// and a name can survive a crash while its inode's data does not.
#[derive(Clone, Debug, Default)]
struct Inode {
    /// Content known durable (data-synced). A new inode is empty on disk.
    durable: Vec<u8>,
    /// Dirty operations: what the next successful `sync_data` persists.
    pending: Vec<Pend>,
    /// The page-cache view: every operation ever applied, including writes
    /// a failed `sync_data` marked clean without persisting.
    image: Vec<u8>,
}

impl Inode {
    fn from_content(content: Vec<u8>) -> Self {
        Self {
            image: content.clone(),
            durable: content,
            pending: Vec::new(),
        }
    }
}

/// A directory entry. Namespace changes are volatile until the parent
/// directory is synced: a crash keeps each pending change or loses it, and
/// the names one operation changed (both names of a rename) go together.
#[derive(Clone, Debug, Default)]
struct Name {
    /// The inode the on-disk directory names.
    durable: Option<InodeId>,
    /// The inode the in-memory directory names (`None` = removed/absent).
    volatile: Option<InodeId>,
    /// The operation that last changed this name.
    change: u64,
}

impl Name {
    fn pending(&self) -> bool {
        self.durable != self.volatile
    }
}

#[derive(Default)]
struct Inner {
    inodes: BTreeMap<InodeId, Inode>,
    names: BTreeMap<String, Name>,
    /// Open handles per inode: an unlinked inode stays usable while open.
    handles: BTreeMap<InodeId, usize>,
    next_inode: InodeId,
    next_change: u64,
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
    /// Bytes returned by `read_at` since creation (cache-efficiency tests).
    stats_read_bytes: u64,
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

    fn volatile(&self, path: &str) -> Option<InodeId> {
        self.names.get(path).and_then(|name| name.volatile)
    }

    /// Point `path` at `inode` in the volatile namespace as part of `change`.
    fn relink(&mut self, path: &str, inode: Option<InodeId>, change: u64) {
        let name = self.names.entry(path.to_string()).or_default();
        name.volatile = inode;
        name.change = change;
    }

    /// Drop inodes that no name (durable or volatile) and no handle reaches.
    fn collect_garbage(&mut self) {
        let mut reached: std::collections::BTreeSet<InodeId> =
            self.handles.keys().copied().collect();
        for name in self.names.values() {
            reached.extend(name.durable);
            reached.extend(name.volatile);
        }
        self.inodes.retain(|id, _| reached.contains(id));
    }

    fn new_change(&mut self) -> u64 {
        self.next_change += 1;
        self.next_change
    }

    /// Settle the namespace after a crash: each pending change (`keep`
    /// decides per change, so both names of a rename agree) either reached
    /// the disk or did not. Returns the inodes still named afterwards.
    fn settle_names(&mut self, mut keep: impl FnMut(&str, u64) -> bool) -> Vec<InodeId> {
        let mut decided: BTreeMap<u64, bool> = BTreeMap::new();
        let paths: Vec<String> = self.names.keys().cloned().collect();
        for path in paths {
            let name = self.names.get_mut(&path).unwrap();
            if name.pending() {
                let kept = *decided
                    .entry(name.change)
                    .or_insert_with(|| keep(&path, name.change));
                let target = if kept { name.volatile } else { name.durable };
                name.durable = target;
                name.volatile = target;
            }
            if name.durable.is_none() {
                self.names.remove(&path);
            }
        }
        let mut live: Vec<InodeId> = self.names.values().filter_map(|n| n.durable).collect();
        live.sort_unstable();
        live.dedup();
        self.inodes.retain(|id, _| live.binary_search(id).is_ok());
        live
    }
}

/// The content a successful `sync_data` makes durable: the durable content
/// plus every *dirty* operation, in order. Writes an earlier failed sync
/// marked clean are not part of it.
fn durable_after_sync(inode: &Inode) -> Vec<u8> {
    let mut data = inode.durable.clone();
    for p in &inode.pending {
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
/// otherwise complete write). Sectors are aligned to the file, not to the
/// write: a write starting inside a sector can persist that sector's part
/// without the next one (TEST-004).
fn apply_torn(data: &mut Vec<u8>, offset: u64, src: &[u8], gran: usize, rng: &mut impl Rng) {
    if src.is_empty() {
        return;
    }
    // Cut points inside `src` at absolute multiples of `gran`, plus both ends.
    let mut cuts = vec![0];
    let mut next = gran - (offset % gran as u64) as usize;
    while next < src.len() {
        cuts.push(next);
        next += gran;
    }
    cuts.push(src.len());
    let sectors = cuts.len() - 1;
    if rng.random_bool(0.5) {
        let keep = cuts[rng.random_range(0..sectors)];
        apply(
            data,
            &Pend::Write {
                offset,
                data: src[..keep].to_vec(),
            },
        );
    } else {
        let hole = rng.random_range(0..sectors);
        let (hole_start, hole_end) = (cuts[hole], cuts[hole + 1]);
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

    /// Total bytes served by `read_at` on any file of this backing.
    pub fn read_bytes(&self) -> u64 {
        self.inner.lock().stats_read_bytes
    }

    /// Simulate a crash: every pending namespace change and every dirty
    /// write is independently kept or lost (a rename as one change); with
    /// tearing enabled any kept write may persist partially. Afterwards,
    /// everything that survived is durable.
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

        let live = inner.settle_names(|_, _| rng.random_bool(0.5));
        for id in live {
            let inode = inner.inodes.get_mut(&id).unwrap();
            let mut data = inode.durable.clone();
            // Keep each pending op independently. With tearing enabled *any*
            // kept write may persist partially at sector granularity — not
            // only the last one: sectors of unsynced writes reach the platter
            // in any order, so an earlier record can be torn while a later
            // one is intact (SPEC §27 torn-tail classification).
            for p in &inode.pending {
                if !rng.random_bool(0.5) {
                    continue;
                }
                if let (Some(gran), Pend::Write { offset, data: src }) = (tearing, p) {
                    if rng.random_bool(0.3) {
                        apply_torn(&mut data, *offset, src, gran, rng);
                        continue;
                    }
                }
                apply(&mut data, p);
            }
            *inode = Inode::from_content(data);
        }
    }

    /// Crash losing *every* volatile operation (worst case): unsynced writes
    /// dropped, unsynced creations vanish, unsynced deletions and renames
    /// are undone.
    pub fn crash_all_lost(&self) {
        let mut inner = self.inner.lock();
        inner.stats_pending_writes = 0;
        for id in inner.settle_names(|_, _| false) {
            let inode = inner.inodes.get_mut(&id).unwrap();
            *inode = Inode::from_content(std::mem::take(&mut inode.durable));
        }
        inner.dirs.retain(|_, durable| *durable);
    }

    /// Deterministic torn-tail crash for journal tests: all pending ops of
    /// `path` are applied except the final write, which keeps only its first
    /// `keep_bytes` bytes, and its directory entry survives. Everything else
    /// crashes losing all volatile state.
    pub fn crash_keep_torn_prefix(&self, path: &str, keep_bytes: usize) {
        let mut inner = self.inner.lock();
        inner.stats_pending_writes = 0;
        let torn = inner.volatile(path).expect("file must exist");
        let inode = inner.inodes[&torn].clone();
        let mut data = inode.durable.clone();
        let last_write_idx = inode
            .pending
            .iter()
            .rposition(|p| matches!(p, Pend::Write { .. }));
        for (i, p) in inode.pending.iter().enumerate() {
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
                    data.truncate(end.max(inode.durable.len()));
                    continue;
                }
            }
            apply(&mut data, p);
        }
        let torn_change = inner.names[path].change;
        for id in inner.settle_names(|name, change| name == path || change == torn_change) {
            let inode = inner.inodes.get_mut(&id).unwrap();
            let content = if id == torn {
                data.clone()
            } else {
                std::mem::take(&mut inode.durable)
            };
            *inode = Inode::from_content(content);
        }
        inner.dirs.retain(|_, durable| *durable);
    }
}

pub struct CrashFile {
    inner: Arc<Mutex<Inner>>,
    /// The name the file was opened by (fault hooks and messages).
    path: String,
    inode: InodeId,
}

impl Drop for CrashFile {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if let Some(count) = inner.handles.get_mut(&self.inode) {
            *count -= 1;
            if *count == 0 {
                inner.handles.remove(&self.inode);
                inner.collect_garbage();
            }
        }
    }
}

impl CrashFile {
    fn with_inode<R>(
        &self,
        f: impl FnOnce(&mut Inner, &mut Inode) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut inner = self.inner.lock();
        let mut inode = inner.inodes.get(&self.inode).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} (lost in a crash)", self.path),
            )
        })?;
        // A failing operation can still have changed the file (a partial
        // write persisted its prefix, a failed sync marked pages clean):
        // keep the state whatever the outcome.
        let r = f(&mut inner, &mut inode);
        inner.inodes.insert(self.inode, inode);
        r
    }
}

impl BackingFile for CrashFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.with_inode(|inner, inode| {
            let data = &inode.image;
            let start = offset as usize;
            let end = start + buf.len();
            if end > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("read {}..{} past EOF {}", start, end, data.len()),
                ));
            }
            buf.copy_from_slice(&data[start..end]);
            inner.stats_read_bytes += buf.len() as u64;
            Ok(())
        })
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.with_inode(|inner, inode| {
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
                apply(&mut inode.image, &pend);
                inode.pending.push(pend);
                inner.stats_pending_writes += 1;
            }
            outcome
        })
    }

    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.with_inode(|inner, inode| {
            let end = offset
                .checked_add(len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "punch overflow"))?;
            let file_len = inode.image.len() as u64;
            let end = end.min(file_len);
            if offset >= end {
                return Ok(());
            }
            let len = usize::try_from(end - offset).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "punch range too large")
            })?;
            let zeros = vec![0; len];
            let op = FaultOp::WriteAt {
                path: &self.path,
                offset,
                len,
            };
            inner.check(&op)?;
            let pend = Pend::Write {
                offset,
                data: zeros,
            };
            apply(&mut inode.image, &pend);
            inode.pending.push(pend);
            inner.stats_pending_writes += 1;
            Ok(())
        })
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.with_inode(|inner, inode| {
            inner.check(&FaultOp::SetLen {
                path: &self.path,
                len,
            })?;
            apply(&mut inode.image, &Pend::SetLen(len));
            inode.pending.push(Pend::SetLen(len));
            Ok(())
        })
    }

    fn len(&self) -> io::Result<u64> {
        self.with_inode(|_, inode| Ok(inode.image.len() as u64))
    }
    fn sync_data(&self) -> io::Result<()> {
        self.with_inode(|inner, inode| {
            if let Err(e) = inner.check(&FaultOp::SyncData { path: &self.path }) {
                if !inner.lenient_sync_failures {
                    // Writeback failed: the kernel marks the pages clean and
                    // keeps their (unpersisted) content in the page cache. A
                    // retry of fsync has nothing dirty to write and succeeds
                    // without touching the disk.
                    inode.pending.clear();
                }
                return Err(e);
            }
            inode.durable = durable_after_sync(inode);
            inode.pending.clear();
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
        let inode = match inner.volatile(path) {
            Some(inode) => inode,
            None if create => {
                // A new, empty inode: nothing of an unlinked predecessor at
                // this name is visible through it, before or after a crash.
                inner.next_inode += 1;
                let inode = inner.next_inode;
                inner.inodes.insert(inode, Inode::default());
                let change = inner.new_change();
                inner.relink(path, Some(inode), change);
                inode
            }
            None => return Err(io::Error::new(io::ErrorKind::NotFound, path.to_string())),
        };
        *inner.handles.entry(inode).or_default() += 1;
        Ok(Arc::new(CrashFile {
            inner: self.inner.clone(),
            path: path.to_string(),
            inode,
        }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        validate(path, false)?;
        let inner = self.inner.lock();
        Ok(inner.volatile(path).is_some() || inner.dirs.contains_key(path))
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::Remove { path })?;
        if inner.volatile(path).is_none() {
            return Err(io::Error::new(io::ErrorKind::NotFound, path.to_string()));
        }
        let change = inner.new_change();
        inner.relink(path, None, change);
        Ok(())
    }

    /// Atomic replace: `to` names `from`'s inode (with the data already
    /// synced in it) and `from` disappears, as one namespace change that a
    /// crash before the directory sync keeps or undoes as a whole.
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate(from, false)?;
        validate(to, false)?;
        let mut inner = self.inner.lock();
        inner.check(&FaultOp::Rename { from, to })?;
        let inode = inner
            .volatile(from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, from.to_string()))?;
        if from == to {
            return Ok(());
        }
        let change = inner.new_change();
        inner.relink(to, Some(inode), change);
        inner.relink(from, None, change);
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
        for (name, entry) in &inner.names {
            if entry.volatile.is_none() {
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
        inner.names.retain(|name, entry| {
            let direct = name
                .strip_prefix(&prefix)
                .is_some_and(|r| !r.is_empty() && !r.contains('/'));
            if direct {
                entry.durable = entry.volatile;
            }
            entry.durable.is_some() || entry.volatile.is_some()
        });
        inner.collect_garbage();
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
