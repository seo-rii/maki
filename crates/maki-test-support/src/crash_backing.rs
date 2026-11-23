//! `CrashableBacking` — an in-memory `Backing` with explicit crash
//! semantics (SPEC §42 `CrashableBacking`).
//!
//! Durability rules simulated:
//! - `write_at`/`set_len` are volatile until `sync_data` on the file,
//! - file creation/removal/rename is volatile until `sync_dir` on the parent;
//!   names and inodes are separate, so a durable name can survive with its
//!   unsynced data lost and a rename is kept or undone as a whole,
//! - namespace operations are sampled independently, then their predecessor
//!   dependencies are retained too; operations sharing a name stay ordered,
//! - directory names are published by syncing their parent; a lost ancestor
//!   makes its entire subtree unreachable,
//! - optionally, any surviving write may be *torn* at sector boundaries of
//!   a configurable granularity, aligned to the file (a prefix of sectors
//!   kept, or one sector missing),
//! - a removal that was never dir-synced may resurrect the file,
//! - a creation that was never dir-synced may vanish even if its data was
//!   fdatasync'd (orphan inode).
//!
//! Renames are indivisible in this model, including cross-directory renames:
//! syncing either parent persists the whole operation and its predecessors.
//! This is an explicit model assumption, not a general filesystem crash
//! guarantee. Qualification of directory-local rename persistence needs an
//! additional model or a real filesystem campaign.
//!
//! Fault injection: a hook may fail any operation (e.g. ENOSPC on append,
//! EIO on fsync) — used by journal/checkpoint failpoint tests.
//!
//! Failure semantics follow Linux writeback, not "the syscall never
//! happened":
//! - a failed `sync_data` marks every dirty operation *clean with unknown
//!   persistence* — the writeback-error behaviour PostgreSQL's
//!   `data_sync_retry` documents (F01). The page cache keeps showing the
//!   bytes and a retried `sync_data` has nothing left to write, so they never
//!   become certain on their own; but the flusher, or the failing sync before
//!   the page that failed, may already have written them, so a later crash
//!   keeps each of them independently (and tears it, with tearing enabled),
//!   exactly like an unsynced operation. `crash_all_lost` and
//!   `crash_keep_torn_prefix` drop them;
//! - writeback is page granular ([`PAGE_SIZE`]): a successful `sync_data`
//!   writes every page a dirty write touched *whole*, as the page cache holds
//!   it (zero past end-of-file), so a later write anywhere in a page makes the
//!   bytes of an earlier failed sync in that page durable. Bytes a successful
//!   sync rewrote or truncated are never brought back by an older failed
//!   writeback. A length change dirties no page; one whose sync failed may
//!   survive a crash until the next successful `sync_data`, after which it
//!   counts as lost (a lost truncation stays possible after a bare retry);
//! - a `write_at` may persist a prefix and then fail (the partial-write
//!   hook), leaving the file longer than the caller's logical end (F03).
//!
//! A power loss (`crash*`) kills every process: it releases every lock, and
//! every file or lock handle opened before it is dead. Each file operation
//! through such a handle fails with an `ErrorKind::Other` I/O error (the
//! model's EIO) without touching the recovered state, and dropping it
//! releases nothing. A process's namespace access dies with it too: the code
//! under test runs on a process view ([`CrashableBacking::process`]), and
//! every `Backing` operation of a view started before a power loss (open,
//! create, remove, rename, list, `sync_dir`, `try_lock`, ...) fails the same
//! way, so a volume, engine or worker the test still holds cannot create or
//! sync a file afterwards. The backing a test creates is the machine, not a
//! process: no power loss ends it, so the test inspects and damages files
//! through it and starts every later process on a new view. A process
//! restart (`drop` + reopen, page cache intact) is not a crash and
//! invalidates nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use parking_lot::{Mutex, MutexGuard};
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

/// Page size of the simulated page cache: a successful `sync_data` writes
/// back every page a dirty write touched as a whole.
pub const PAGE_SIZE: usize = 4096;

/// File content, independent of any name (TEST-004): an open handle keeps
/// its inode across `remove` and `rename`, a re-created name is a new inode,
/// and a name can survive a crash while its inode's data does not.
#[derive(Clone, Debug, Default)]
struct Inode {
    /// Content known durable (data-synced). A new inode is empty on disk.
    durable: Vec<u8>,
    /// Operations of failed syncs, oldest first: clean in the page cache,
    /// possibly on disk. Each is newer than the `durable` bytes it covers
    /// (successful syncs cut out what they rewrote or truncated) and older
    /// than every `pending` operation. A crash may keep any of them; no sync
    /// replays them.
    uncertain: Vec<Pend>,
    /// Dirty operations: what the next successful `sync_data` persists.
    pending: Vec<Pend>,
    /// The page-cache view: every operation ever applied, including writes
    /// a failed `sync_data` marked clean.
    image: Vec<u8>,
}

impl Inode {
    fn from_content(content: Vec<u8>) -> Self {
        Self {
            image: content.clone(),
            durable: content,
            uncertain: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// A successful `sync_data`: persist the dirty operations, then every
    /// page they wrote as the page cache holds it. Uncertain bytes inside
    /// those pages or beyond a persisted truncation are settled; uncertain
    /// length changes count as lost.
    fn sync(&mut self) {
        let pages = dirty_pages(&self.pending);
        for op in &self.pending {
            apply(&mut self.durable, op);
        }
        for &page in &pages {
            write_back_page(&mut self.durable, &self.image, page);
        }
        let cut = self
            .pending
            .iter()
            .filter_map(|op| match op {
                Pend::SetLen(len) => Some(*len),
                Pend::Write { .. } => None,
            })
            .min();
        self.uncertain = std::mem::take(&mut self.uncertain)
            .into_iter()
            .flat_map(|op| unsettled(op, &pages, cut))
            .collect();
        self.pending.clear();
    }
}

/// A directory entry. Namespace changes are volatile until the parent
/// directory is synced. `change` remains meaningful even when the durable
/// and volatile values agree: a rename round trip has intermediate states.
#[derive(Clone, Debug, Default)]
struct Name {
    /// The inode the on-disk directory names.
    durable: Option<InodeId>,
    /// The inode the in-memory directory names (`None` = removed/absent).
    volatile: Option<InodeId>,
    /// The operation that last changed this name.
    change: u64,
}

/// One indivisible operation and the prior operations on its affected names.
/// Keep intermediate inode references until the history is settled, even if
/// no current name or open handle still points at those inodes.
#[derive(Clone, Debug)]
struct NamespaceChange {
    entries: Vec<(String, Option<InodeId>)>,
    predecessors: BTreeSet<u64>,
}

/// Fault injection and counters shared by file and namespace operations.
#[derive(Default)]
struct IoState {
    hook: Option<FaultHook>,
    partial_hook: Option<PartialWriteHook>,
    /// When set, a failed `sync_data` leaves its dirty writes dirty (the
    /// "syscall never happened" model). The default is the Linux model:
    /// the writes are marked clean, possibly but not certainly persisted.
    lenient_sync_failures: bool,
    writes_since_crash: usize,
    /// Bytes returned by `read_at` since creation (cache-efficiency tests).
    stats_read_bytes: u64,
}

impl IoState {
    fn check(&self, op: &FaultOp<'_>) -> io::Result<()> {
        if let Some(hook) = &self.hook {
            if let Some(err) = hook(op) {
                return Err(err);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Inner {
    /// Number of power losses so far. Handles of an earlier epoch are dead.
    epoch: u64,
    inodes: BTreeMap<InodeId, Inode>,
    names: BTreeMap<String, Name>,
    /// Open handles per inode: an unlinked inode stays usable while open.
    handles: BTreeMap<InodeId, usize>,
    next_inode: InodeId,
    next_change: u64,
    namespace_changes: BTreeMap<u64, NamespaceChange>,
    /// dir path -> dirent durable?
    dirs: BTreeMap<String, bool>,
    locks: std::collections::HashSet<InodeId>,
    io: IoState,
    /// Simulated free space reported by `Backing::free_bytes`.
    free_bytes: Option<u64>,
}

impl Inner {
    /// Every process dies: its handles are dead and its locks released.
    fn power_loss(&mut self) {
        self.epoch += 1;
        self.handles.clear();
        self.locks.clear();
        self.io.writes_since_crash = 0;
    }

    fn volatile(&self, path: &str) -> Option<InodeId> {
        self.names.get(path).and_then(|name| name.volatile)
    }

    /// Record all endpoints together, before another operation can replace
    /// their last-change links. Unrelated names have no shared dependency.
    fn relink(&mut self, entries: Vec<(String, Option<InodeId>)>) {
        let predecessors = entries
            .iter()
            .filter_map(|(path, _)| self.names.get(path).map(|name| name.change))
            .filter(|change| self.namespace_changes.contains_key(change))
            .collect();
        self.next_change += 1;
        let change = self.next_change;
        for (path, inode) in &entries {
            let name = self.names.entry(path.clone()).or_default();
            name.volatile = *inode;
            name.change = change;
        }
        self.namespace_changes.insert(
            change,
            NamespaceChange {
                entries,
                predecessors,
            },
        );
    }

    fn require_dir(&self, dir: &str) -> io::Result<()> {
        let mut prefix = String::new();
        for part in dir.split('/').filter(|part| !part.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if self.volatile(&prefix).is_some() {
                return Err(io::Error::new(io::ErrorKind::NotADirectory, prefix));
            }
            if !self.dirs.contains_key(&prefix) {
                return Err(io::Error::new(io::ErrorKind::NotFound, prefix));
            }
        }
        Ok(())
    }

    fn open_or_create_inode(&mut self, path: &str) -> InodeId {
        if let Some(inode) = self.volatile(path) {
            return inode;
        }
        // Recreating an unlinked name gets a fresh, empty inode.
        self.next_inode += 1;
        let inode = self.next_inode;
        self.inodes.insert(inode, Inode::default());
        self.relink(vec![(path.to_string(), Some(inode))]);
        inode
    }

    /// The parent of `path` exists and `path` itself is not a directory: a
    /// directory name cannot be opened, locked, renamed over or unlinked as
    /// a file (EISDIR, as Linux `FileBacking` reports).
    fn require_file_name(&self, path: &str) -> io::Result<()> {
        self.require_dir(parent(path))?;
        if self.dirs.contains_key(path) {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                path.to_string(),
            ));
        }
        Ok(())
    }

    /// Persist only the selected operations and their dependency closure.
    /// A predecessor already compacted by an earlier sync is satisfied.
    fn persist_namespace(&mut self, selected: impl IntoIterator<Item = u64>) {
        let mut pending: Vec<_> = selected.into_iter().collect();
        let mut selected = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if let Some(change) = self.namespace_changes.get(&id) {
                if selected.insert(id) {
                    pending.extend(&change.predecessors);
                }
            }
        }
        for id in selected {
            let change = self.namespace_changes.remove(&id).unwrap();
            for (path, inode) in change.entries {
                self.names.get_mut(&path).unwrap().durable = inode;
            }
        }
    }

    /// Drop inodes that no name (durable or volatile) and no handle reaches.
    fn collect_garbage(&mut self) {
        let mut reached: std::collections::BTreeSet<InodeId> =
            self.handles.keys().copied().collect();
        for name in self.names.values() {
            reached.extend(name.durable);
            reached.extend(name.volatile);
        }
        for change in self.namespace_changes.values() {
            reached.extend(change.entries.iter().filter_map(|(_, inode)| *inode));
        }
        self.inodes
            .retain(|id, _| reached.contains(id) || self.locks.contains(id));
    }

    /// Settle selected namespace operations, then permanently drop names
    /// below missing ancestors. Recreating a directory cannot expose them.
    fn settle_names(&mut self, selected: impl IntoIterator<Item = u64>) -> Vec<InodeId> {
        self.persist_namespace(selected);
        self.namespace_changes.clear();
        for name in self.names.values_mut() {
            name.volatile = name.durable;
        }
        // Lexical order visits every parent before its descendants.
        for (dir, durable) in std::mem::take(&mut self.dirs) {
            if self.volatile(&dir).is_none() && self.require_dir(parent(&dir)).is_ok() {
                self.dirs.insert(dir, durable);
            }
        }
        let dirs = &self.dirs;
        self.names.retain(|path, name| {
            name.volatile = name.durable;
            name.durable.is_some() && (parent(path).is_empty() || dirs.contains_key(parent(path)))
        });
        let mut live: Vec<InodeId> = self.names.values().filter_map(|n| n.durable).collect();
        live.sort_unstable();
        live.dedup();
        self.inodes.retain(|id, _| live.binary_search(id).is_ok());
        live
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Pages a dirty write touched.
fn dirty_pages(pending: &[Pend]) -> BTreeSet<u64> {
    let page = PAGE_SIZE as u64;
    let mut pages = BTreeSet::new();
    for op in pending {
        if let Pend::Write { offset, data } = op {
            if !data.is_empty() {
                pages.extend(offset / page..=(offset + data.len() as u64 - 1) / page);
            }
        }
    }
    pages
}

/// Write back one cached page whole: its bytes up to end-of-file, then the
/// zeros the kernel writes past end-of-file. A page truncated out of the
/// cache since it was dirtied is not written.
fn write_back_page(durable: &mut Vec<u8>, image: &[u8], page: u64) {
    let start = page as usize * PAGE_SIZE;
    if start >= image.len() {
        return;
    }
    let cached = (start + PAGE_SIZE).min(image.len());
    if durable.len() < cached {
        durable.resize(cached, 0);
    }
    durable[start..cached].copy_from_slice(&image[start..cached]);
    let page_end = (start + PAGE_SIZE).min(durable.len());
    if cached < page_end {
        durable[cached..page_end].fill(0);
    }
}

/// What remains uncertain of an operation of a failed sync after a later
/// successful one: the bytes outside the pages it wrote back and below its
/// shortest persisted length. An uncertain length change is dropped.
fn unsettled(op: Pend, pages: &BTreeSet<u64>, cut: Option<u64>) -> Vec<Pend> {
    let Pend::Write { offset, data } = op else {
        return Vec::new();
    };
    let page = PAGE_SIZE as u64;
    let end = cut.map_or(offset + data.len() as u64, |cut| {
        cut.min(offset + data.len() as u64)
    });
    let mut kept = Vec::new();
    let mut start = offset;
    while start < end {
        let next_page = ((start / page + 1) * page).min(end);
        if pages.contains(&(start / page)) {
            start = next_page;
            continue;
        }
        let mut stop = next_page;
        while stop < end && !pages.contains(&(stop / page)) {
            stop = ((stop / page + 1) * page).min(end);
        }
        kept.push(Pend::Write {
            offset: start,
            data: data[(start - offset) as usize..(stop - offset) as usize].to_vec(),
        });
        start = stop;
    }
    kept
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
    /// The power-loss epoch the process using this view started in; `None`
    /// for the backing the test created, which no power loss ends.
    process: Option<u64>,
}

impl CrashableBacking {
    pub fn new() -> Self {
        Self::default()
    }

    /// The backing as one process of the code under test sees it, started
    /// now. The view shares every file, name and lock with this backing, but
    /// a power loss kills it: afterwards each of its `Backing` operations
    /// fails with an `ErrorKind::Other` I/O error (the model's EIO) and
    /// changes nothing, like the process's file and lock handles. Clones of
    /// the view belong to the same process. Start every `Volume`, `Engine`
    /// or adapter of the test on its own view; a process started after the
    /// power loss takes a new one.
    pub fn process(&self) -> Arc<Self> {
        let epoch = self.inner.lock().epoch;
        Arc::new(Self {
            inner: self.inner.clone(),
            tearing: self.tearing,
            process: Some(epoch),
        })
    }

    /// The shared state for a `Backing` operation of this view, refused once
    /// a power loss has killed the view's process.
    fn live(&self, op: &str, path: &str) -> io::Result<MutexGuard<'_, Inner>> {
        let inner = self.inner.lock();
        match self.process {
            Some(epoch) if epoch != inner.epoch => {
                let what = if path.is_empty() {
                    op.to_string()
                } else {
                    format!("{op} {path}")
                };
                Err(io::Error::other(format!(
                    "{what}: process killed by a power loss (EIO)"
                )))
            }
            _ => Ok(inner),
        }
    }

    /// Enable random torn-write simulation at `granularity` bytes.
    pub fn with_tearing(mut self, granularity: usize) -> Self {
        assert!(granularity > 0);
        self.tearing = Some(granularity);
        self
    }

    pub fn set_fault_hook(&self, hook: Option<FaultHook>) {
        self.inner.lock().io.hook = hook;
    }

    /// Install a partial-write hook (see [`PartialWriteHook`]).
    pub fn set_partial_write_hook(&self, hook: Option<PartialWriteHook>) {
        self.inner.lock().io.partial_hook = hook;
    }

    /// Choose what a failed `sync_data` does to the dirty writes it could
    /// not persist. `false` (the default) is the Linux model: they are
    /// marked clean with unknown persistence (a crash may or may not keep
    /// them) and a retry of the sync has nothing to write. `true` keeps them
    /// dirty, as if the syscall had never run.
    pub fn set_lenient_sync_failures(&self, lenient: bool) {
        self.inner.lock().io.lenient_sync_failures = lenient;
    }

    /// Simulate the free space the backing filesystem reports (`None` =
    /// unknown, the default).
    pub fn set_free_bytes(&self, free: Option<u64>) {
        self.inner.lock().free_bytes = free;
    }

    /// Dirty writes and hole punches across all retained inodes. A failed
    /// writeback counts only if the model leaves the operation dirty.
    /// Length changes are tracked separately from writes in the crash model.
    pub fn pending_write_count(&self) -> usize {
        self.inner
            .lock()
            .inodes
            .values()
            .flat_map(|inode| &inode.pending)
            .filter(|op| matches!(op, Pend::Write { .. }))
            .count()
    }

    /// Nonempty writes and hole punches applied since the last power loss,
    /// including partial writes. Syncing a file leaves this count unchanged.
    pub fn write_count_since_crash(&self) -> usize {
        self.inner.lock().io.writes_since_crash
    }

    /// Total bytes served by `read_at` on any file of this backing.
    pub fn read_bytes(&self) -> u64 {
        self.inner.lock().io.stats_read_bytes
    }

    /// Simulate a crash: sample pending namespace operations, keeping their
    /// predecessor dependencies too (a rename as one change). Dirty and
    /// uncertain (failed-sync) operations are independently kept or lost, in
    /// order; with tearing enabled any kept write may persist partially.
    /// Afterwards, everything that survived is durable.
    pub fn crash(&self, rng: &mut impl Rng) {
        let tearing = self.tearing;
        let mut inner = self.inner.lock();
        inner.power_loss();

        // Sample directory publication independently. settle_names removes
        // every unreachable descendant after settling the file namespace.
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

        let selected: Vec<_> = inner
            .namespace_changes
            .keys()
            .copied()
            .filter(|_| rng.random_bool(0.5))
            .collect();
        let live = inner.settle_names(selected);
        for id in live {
            let inode = inner.inodes.get_mut(&id).unwrap();
            let mut data = inode.durable.clone();
            // Keep each pending op independently. With tearing enabled *any*
            // kept write may persist partially at sector granularity — not
            // only the last one: sectors of unsynced writes reach the platter
            // in any order, so an earlier record can be torn while a later
            // one is intact (SPEC §27 torn-tail classification).
            for p in inode.uncertain.iter().chain(&inode.pending) {
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

    /// Crash losing *every* volatile operation (worst case): unsynced and
    /// failed-sync writes dropped, unsynced creations vanish, unsynced
    /// deletions and renames are undone.
    pub fn crash_all_lost(&self) {
        let mut inner = self.inner.lock();
        inner.power_loss();
        inner.dirs.retain(|_, durable| *durable);
        for id in inner.settle_names([]) {
            let inode = inner.inodes.get_mut(&id).unwrap();
            *inode = Inode::from_content(std::mem::take(&mut inode.durable));
        }
    }

    /// Deterministic torn-tail crash for journal tests: all pending ops of
    /// `path` are applied except the final write, which keeps only its first
    /// `keep_bytes` bytes, and its directory entry survives. Its namespace
    /// predecessors and ancestors survive too, so the selected path remains
    /// reachable. All other volatile operations, and every failed sync's
    /// uncertain operations, are lost.
    pub fn crash_keep_torn_prefix(&self, path: &str, keep_bytes: usize) {
        let mut inner = self.inner.lock();
        inner.power_loss();
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
                    if keep > 0 {
                        apply(
                            &mut data,
                            &Pend::Write {
                                offset: *offset,
                                data: src[..keep].to_vec(),
                            },
                        );
                    }
                    continue;
                }
            }
            apply(&mut data, p);
        }
        let mut selected = vec![inner.names[path].change];
        let mut ancestor = parent(path);
        while !ancestor.is_empty() {
            *inner
                .dirs
                .get_mut(ancestor)
                .expect("file parent must exist") = true;
            // A directory may replace a removed durable file. Preserve that
            // unlink too, or restoring the old file would hide the torn path.
            if let Some(name) = inner.names.get(ancestor) {
                selected.push(name.change);
            }
            ancestor = parent(ancestor);
        }
        inner.dirs.retain(|_, durable| *durable);
        for id in inner.settle_names(selected) {
            let inode = inner.inodes.get_mut(&id).unwrap();
            let content = if id == torn {
                data.clone()
            } else {
                std::mem::take(&mut inode.durable)
            };
            *inode = Inode::from_content(content);
        }
    }
}

pub struct CrashFile {
    inner: Arc<Mutex<Inner>>,
    /// The name the file was opened by (fault hooks and messages).
    path: String,
    inode: InodeId,
    /// The power-loss epoch the handle was opened in.
    epoch: u64,
}

impl Drop for CrashFile {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if inner.epoch != self.epoch {
            return;
        }
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
        f: impl FnOnce(&mut IoState, &mut Inode) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut inner = self.inner.lock();
        if inner.epoch != self.epoch {
            return Err(io::Error::other(format!(
                "{}: handle opened before a power loss (EIO)",
                self.path
            )));
        }
        let Inner { inodes, io, .. } = &mut *inner;
        let inode = inodes.get_mut(&self.inode).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} (lost in a crash)", self.path),
            )
        })?;
        f(io, inode)
    }
}

impl BackingFile for CrashFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.with_inode(|io, inode| {
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
            io.stats_read_bytes += buf.len() as u64;
            Ok(())
        })
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.with_inode(|io, inode| {
            let op = FaultOp::WriteAt {
                path: &self.path,
                offset,
                len: data.len(),
            };
            io.check(&op)?;
            let partial = io.partial_hook.as_ref().and_then(|hook| hook(&op));
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
                io.writes_since_crash += 1;
            }
            outcome
        })
    }

    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        self.with_inode(|io, inode| {
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
            io.check(&op)?;
            let pend = Pend::Write {
                offset,
                data: zeros,
            };
            apply(&mut inode.image, &pend);
            inode.pending.push(pend);
            io.writes_since_crash += 1;
            Ok(())
        })
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.with_inode(|io, inode| {
            io.check(&FaultOp::SetLen {
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
        self.with_inode(|io, inode| {
            if let Err(e) = io.check(&FaultOp::SyncData { path: &self.path }) {
                if !io.lenient_sync_failures {
                    // Writeback failed: the kernel marks the pages clean and
                    // keeps their content in the page cache. A retry of fsync
                    // has nothing dirty to write and succeeds without
                    // touching the disk, but some of the pages may already
                    // have reached it.
                    let failed = std::mem::take(&mut inode.pending);
                    inode.uncertain.extend(failed);
                }
                return Err(e);
            }
            inode.sync();
            Ok(())
        })
    }
}

struct CrashLock {
    inner: Arc<Mutex<Inner>>,
    inode: InodeId,
    // Fast reachability check when the original name still exists.
    path: String,
    /// The power-loss epoch the lock was taken in; a crash released it.
    epoch: u64,
}

impl VolumeLock for CrashLock {}

impl Drop for CrashLock {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if inner.epoch == self.epoch {
            inner.locks.remove(&self.inode);
            if inner.volatile(&self.path) != Some(self.inode) {
                inner.collect_garbage();
            }
        }
    }
}

impl Backing for CrashableBacking {
    fn check_freshness(&self) -> io::Result<()> {
        self.live("check_freshness", "").map(drop)
    }

    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate(path, false)?;
        let mut inner = self.live("open", path)?;
        inner.io.check(&FaultOp::Open { path, create })?;
        inner.require_file_name(path)?;
        let inode = if create {
            inner.open_or_create_inode(path)
        } else {
            inner
                .volatile(path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_string()))?
        };
        *inner.handles.entry(inode).or_default() += 1;
        Ok(Arc::new(CrashFile {
            inner: self.inner.clone(),
            path: path.to_string(),
            inode,
            epoch: inner.epoch,
        }))
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        validate(path, false)?;
        let inner = self.live("exists", path)?;
        if let Err(error) = inner.require_dir(parent(path)) {
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            };
        }
        Ok(inner.volatile(path).is_some() || inner.dirs.contains_key(path))
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut inner = self.live("remove", path)?;
        inner.io.check(&FaultOp::Remove { path })?;
        inner.require_file_name(path)?;
        if inner.volatile(path).is_none() {
            return Err(io::Error::new(io::ErrorKind::NotFound, path.to_string()));
        }
        inner.relink(vec![(path.to_string(), None)]);
        Ok(())
    }

    /// Atomic replace: `to` names `from`'s inode (with the data already
    /// synced in it) and `from` disappears, as one namespace change that a
    /// crash before the directory sync keeps or undoes as a whole.
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate(from, false)?;
        validate(to, false)?;
        let mut inner = self.live("rename", from)?;
        inner.io.check(&FaultOp::Rename { from, to })?;
        inner.require_dir(parent(from))?;
        if inner.dirs.contains_key(from) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "directory rename is unsupported",
            ));
        }
        inner.require_file_name(to)?;
        let inode = inner
            .volatile(from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, from.to_string()))?;
        if from == to {
            return Ok(());
        }
        inner.relink(vec![
            (from.to_string(), None),
            (to.to_string(), Some(inode)),
        ]);
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        validate(path, false)?;
        let mut inner = self.live("create_dir_all", path)?;
        let mut cur = String::new();
        for comp in path.split('/') {
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(comp);
            if inner.volatile(&cur).is_some() {
                return Err(io::Error::new(io::ErrorKind::NotADirectory, cur));
            }
            inner.dirs.entry(cur.clone()).or_insert(false);
        }
        Ok(())
    }

    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        validate(dir, true)?;
        let inner = self.live("list", dir)?;
        inner.require_dir(dir)?;
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
        let mut inner = self.live("sync_dir", dir)?;
        inner.io.check(&FaultOp::SyncDir { dir })?;
        inner.require_dir(dir)?;
        // Commit operations on entries directly inside `dir` and their
        // predecessors. A rename persists as one operation, never half.
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let selected: Vec<_> = inner
            .names
            .iter()
            .filter(|(name, _)| parent(name) == dir)
            .map(|(_, entry)| entry.change)
            .collect();
        inner.persist_namespace(selected);
        let Inner {
            names,
            namespace_changes,
            ..
        } = &mut *inner;
        names.retain(|_, entry| {
            entry.durable.is_some()
                || entry.volatile.is_some()
                || namespace_changes.contains_key(&entry.change)
        });
        inner.collect_garbage();
        use std::ops::Bound::{Included, Unbounded};
        for (name, durable) in inner
            .dirs
            .range_mut::<str, _>((Included(prefix.as_str()), Unbounded))
        {
            let Some(rest) = name.strip_prefix(&prefix) else {
                break;
            };
            if !rest.is_empty() && !rest.contains('/') {
                *durable = true;
            }
        }
        Ok(())
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        Ok(self.live("free_bytes", "")?.free_bytes)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        validate(path, false)?;
        let mut inner = self.live("try_lock", path)?;
        inner.require_file_name(path)?;
        let inode = inner.open_or_create_inode(path);
        if !inner.locks.insert(inode) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VOLUME_ALREADY_ATTACHED",
            ));
        }
        Ok(Box::new(CrashLock {
            inner: self.inner.clone(),
            inode,
            path: path.to_string(),
            epoch: inner.epoch,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eio() -> io::Error {
        io::Error::other("injected EIO")
    }

    #[test]
    fn syncing_an_unchanged_file_keeps_its_durable_allocation() {
        let mut inode = Inode::from_content(vec![7; 8192]);
        let original = inode.durable.as_ptr();
        inode.sync();
        assert_eq!(inode.durable.as_ptr(), original);
    }

    #[test]
    fn length_and_reads_keep_the_files_image_in_place() {
        let backing = CrashableBacking::new();
        let file = backing.open("f", true).unwrap();
        file.write_at(0, &[1; PAGE_SIZE]).unwrap();
        file.sync_data().unwrap();
        let image_address = || {
            let inner = backing.inner.lock();
            inner.inodes[&inner.volatile("f").unwrap()].image.as_ptr()
        };
        let address = image_address();
        assert_eq!(file.len().unwrap(), PAGE_SIZE as u64);
        assert_eq!(image_address(), address);
        let mut byte = [0];
        file.read_at(0, &mut byte).unwrap();
        assert_eq!(byte, [1]);
        assert_eq!(image_address(), address);
    }

    /// The Linux writeback-error model: a failed fsync leaves the bytes
    /// visible but not durable, a retried fsync succeeds without writing
    /// them (the worst-case crash still loses them), and only a rewrite
    /// makes them durable.
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
            "a retried sync must not make failed writeback durable"
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
