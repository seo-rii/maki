//! A read-only view of a rollback-protected backing, for the commands that
//! only read a volume (`maki check`, `maki check --deep`, `maki volume
//! inspect`).
//!
//! Opening a protected backing to write makes what it authenticated durable
//! before a writer resumes: [`RollbackBacking::open`] re-dirties and syncs
//! every committed page, rewrites the selected manifest and the format
//! marker, reserves storage and publishes the witness anchor again, and
//! [`RollbackBacking::open_remote`] claims a writer at the authority and
//! copies the current generation into a namespace of its own. Each holds
//! its locks exclusively. A command that only reads needs none of that,
//! and where it may not write it cannot do it.
//!
//! [`ReadOnlyRollbackBacking`] performs the same authentication: the format
//! marker; the manifest the witness selects, exact and canonical, of the
//! witness's identity and generation, in a slot of its capacity's size; the
//! arena's size; and every committed page against its digest. It creates,
//! writes, syncs and removes nothing, below the backing root and in the
//! witness directory. It takes the locks a writer holds for its whole
//! session, shared and only where their files exist, so no writer runs
//! while it is open, and other readers are admitted. It asks a remote
//! authority only to inspect, and writes no operation guard. What it reads
//! after opening is authenticated again on every read, and every operation
//! first asks the witness whether it still selects what was read, as a
//! writer's view does: a change stops the view for good. What it reads may
//! exist only in the page cache, which a check through it says
//! ([`Backing::is_read_only`]).

use std::fmt;

use super::*;
use crate::remote_witness::{Record, Rpc};

use super::gc::OPERATION_LOCK;

/// A rollback-protected backing opened only to read (see the module
/// documentation). Every change is refused with `ReadOnlyFilesystem`.
pub struct ReadOnlyRollbackBacking {
    view: Arc<View>,
}

struct View {
    manifest: Manifest,
    arena: Arc<dyn BackingFile>,
    witness: Mutex<Freshness>,
    /// Why the view stopped, recorded once.
    stopped: OnceLock<String>,
    /// The shared locks that keep a writer out while the view is open.
    _locks: Vec<Box<dyn VolumeLock>>,
}

/// What tells the view whether the witness still selects what it read.
enum Freshness {
    /// A local witness opened read-only ([`FileWitness::open_read_only`]).
    Local(FileWitness),
    /// The remote authority, and its record when the view was opened.
    Remote { rpc: Arc<dyn Rpc>, record: Record },
}

impl Freshness {
    fn verify_current(&self) -> io::Result<()> {
        match self {
            Self::Local(witness) => witness.verify_current(),
            Self::Remote { rpc, record } => {
                if remote::inspect(rpc.as_ref())? != *record {
                    return Err(invalid(
                        "the remote authority changed after the backing was opened read-only",
                    ));
                }
                Ok(())
            }
        }
    }

    /// As [`Witness::stops_session`] decides for a writer's session.
    fn stops_view(&self, error: &io::Error) -> bool {
        match self {
            Self::Local(witness) => witness.is_poisoned(),
            Self::Remote { .. } => remote::stops_remote_session(error),
        }
    }
}

fn read_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::ReadOnlyFilesystem,
        "read-only rollback-protected backing view",
    )
}

/// `error`, met taking the lock file `name` shared, in words that say what
/// it means for a read-only open. `holder` says who holds the lock when it
/// is held.
fn shared_lock_refusal(error: io::Error, name: &str, holder: &str) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock => io::Error::new(
            error.kind(),
            format!(
                "{name} is held by another process ({holder}), and a read-only open does not \
                 run beside it: detach the volume or let that command finish, then run this one \
                 again"
            ),
        ),
        io::ErrorKind::NotFound => io::Error::new(
            error.kind(),
            format!(
                "{name} is missing, and a read-only open cannot create it: without it a writer \
                 could start while the backing is read, so nothing was read (opening the backing \
                 where it can be written recreates the file)"
            ),
        ),
        _ => error,
    }
}

/// Who holds a local backing's or witness's lock exclusively.
const LOCAL_WRITER: &str = "an attached volume, or a command that opened the backing to write";

impl ReadOnlyRollbackBacking {
    /// Open the local rollback-protected backing at `root`, with its witness
    /// directory `witness`, only to read it. Neither directory is created:
    /// one that is missing, is not a directory or cannot be opened is
    /// refused with its setting, as [`RollbackBacking::open`] refuses it.
    pub fn open(root: &Path, witness: &Path) -> io::Result<Self> {
        if cfg!(target_os = "linux") {
            configured::BACKING_ROOT.reachable(root)?;
            configured::WITNESS_ROOT.reachable(witness)?;
        }
        independent_paths(root, witness)?;
        Self::open_on(
            Arc::new(FileBacking::read_only(root)?),
            Arc::new(FileBacking::read_only(witness)?),
        )
    }

    /// [`Self::open`] over read-only views of a backing and of its witness
    /// directory that the caller hosts. The caller answers for what the
    /// path form checks: that the witness is independent of the backing.
    #[doc(hidden)]
    pub fn open_on(disk: Arc<dyn Backing>, witness: Arc<dyn Backing>) -> io::Result<Self> {
        let disk_lock = disk
            .try_lock_shared_existing(LOCK)
            .map_err(|error| shared_lock_refusal(error, LOCK, LOCAL_WRITER))?;
        let listed = witness.clone();
        open_marker(disk.as_ref(), move || listed.list(""))?;
        let witness = FileWitness::open_read_only(witness, |error| {
            shared_lock_refusal(error, "the witness directory's witness.lock", LOCAL_WRITER)
        })?;
        let (_, manifest) = select_manifest(disk.as_ref(), witness.anchor())?;
        let arena = open_arena(disk.as_ref(), &manifest)?;
        authenticate_pages(arena.as_ref(), &manifest)?;
        Ok(Self::assemble(
            manifest,
            arena,
            Freshness::Local(witness),
            vec![disk_lock],
        ))
    }

    /// Open the remote rollback-protected backing at `root`, whose
    /// authority `rpc` reaches, only to read the authority's current
    /// generation where it is: in the namespace the authority names. The
    /// authority is sent only inspections.
    ///
    /// The root's operation lock is taken shared, which keeps out every
    /// operation that changes the root (an attach while it opens, a
    /// takeover, a restore, a snapshot, GC, an enrollment), and so is the
    /// lock of the current namespace, which its writer holds while the
    /// volume is attached. The authority's record is read again once both
    /// are held, and must not have changed.
    pub fn open_remote(root: &Path, rpc: Arc<dyn Rpc>) -> io::Result<Self> {
        let disk = remote::backup_root(root)?;
        let operation = disk
            .try_lock_shared_existing(OPERATION_LOCK)
            .map_err(|error| {
                shared_lock_refusal(
                    error,
                    OPERATION_LOCK,
                    "an operation that changes the root: an attach while it opens, a takeover, \
                     a restore, a snapshot, GC or an enrollment",
                )
            })?;
        let record = remote::inspect(rpc.as_ref())?;
        let manifest = remote::holds_current(&disk, &record)?;
        let current = record
            .current
            .as_ref()
            .ok_or_else(|| invalid("uninitialized remote backing"))?;
        let namespace = remote::scope(disk.clone(), &current.namespace)?;
        let lock = format!("{}/{LOCK}", current.namespace);
        let writer = namespace.try_lock_shared_existing(LOCK).map_err(|error| {
            shared_lock_refusal(
                error,
                &lock,
                "the writer session of this namespace: an attached volume, or a command that \
                 opened the volume to write",
            )
        })?;
        if remote::inspect(rpc.as_ref())? != record {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the remote authority changed while the backing was opened read-only: run the \
                 command again",
            ));
        }
        let arena = open_arena(namespace.as_ref(), &manifest)?;
        authenticate_pages(arena.as_ref(), &manifest)?;
        Ok(Self::assemble(
            manifest,
            arena,
            Freshness::Remote { rpc, record },
            vec![operation, writer],
        ))
    }

    fn assemble(
        manifest: Manifest,
        arena: Arc<dyn BackingFile>,
        witness: Freshness,
        locks: Vec<Box<dyn VolumeLock>>,
    ) -> Self {
        Self {
            view: Arc::new(View {
                manifest,
                arena,
                witness: Mutex::new(witness),
                stopped: OnceLock::new(),
                _locks: locks,
            }),
        }
    }

    /// The logical-page capacity of the authenticated manifest, as
    /// [`RollbackBacking::capacity`] reports it.
    pub fn capacity(&self) -> io::Result<u64> {
        self.view.check()?;
        Ok(self.view.manifest.capacity)
    }
}

impl View {
    /// Refuse every operation once the view has stopped, and stop it when
    /// the witness no longer selects what it read.
    fn check(&self) -> io::Result<()> {
        if self.stopped.get().is_some() {
            return Err(invalid(
                "rollback session stopped; reopen against the independent witness",
            ));
        }
        let witness = self.witness.lock();
        if let Err(error) = witness.verify_current() {
            if witness.stops_view(&error) {
                self.stop(&error);
            }
            return Err(error);
        }
        Ok(())
    }

    fn stop(&self, cause: &dyn fmt::Display) {
        if self
            .stopped
            .set(format!("rollback session stopped: {cause}"))
            .is_ok()
        {
            tracing::warn!(
                "read-only rollback session stopped: {cause}; every operation fails until the \
                 volume is opened again against the witness"
            );
        }
    }

    fn node(&self, id: u64) -> io::Result<&Node> {
        self.manifest.files.get(&id).ok_or_else(missing)
    }

    /// The identity of the file `name`.
    fn file(&self, name: &str) -> io::Result<u64> {
        lookup_directory(&self.manifest.entries, path::parent(name))?;
        match self.manifest.entries.get(name) {
            Some(Entry::File(id)) => Ok(*id),
            Some(Entry::Directory) => Err(io::Error::new(io::ErrorKind::IsADirectory, name)),
            None => Err(missing()),
        }
    }

    /// Read and authenticate one committed page, as a writer's view does
    /// (`State::read_page`).
    fn read_page(&self, page: &PageRef, bytes: &mut [u8]) -> io::Result<()> {
        if let Err(error) = self.arena.read_at(page.slot * PAGE, bytes) {
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
            ) {
                self.stop(&format_args!("arena page read failed: {error}"));
            }
            return Err(error);
        }
        if page_digest(&self.manifest.identity, bytes) != page.hash {
            let error = invalid("rollback arena page authentication failed");
            self.stop(&error);
            return Err(error);
        }
        Ok(())
    }
}

/// A file of the view: reads are authenticated, changes refused.
struct ViewFile {
    view: Arc<View>,
    id: u64,
}

impl BackingFile for ViewFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let view = &self.view;
        view.check()?;
        if buf.is_empty() {
            return Ok(());
        }
        let node = view.node(self.id)?;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| input("read overflow"))?;
        if end > node.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond rollback file",
            ));
        }
        // Authenticate into private scratch before exposing any bytes of a
        // page. A hole-only read never needs to allocate it.
        let mut bytes = Vec::new();
        let mut at = offset;
        while at < end {
            let dest = (at - offset) as usize;
            let Some((&index, page)) = node.pages.range(at / PAGE..=(end - 1) / PAGE).next() else {
                buf[dest..].fill(0);
                break;
            };
            let page_start = index * PAGE;
            if at < page_start {
                buf[dest..(page_start - offset) as usize].fill(0);
                at = page_start;
            }
            bytes.resize(PAGE as usize, 0);
            view.read_page(page, &mut bytes)?;
            let count = (PAGE - at % PAGE).min(end - at) as usize;
            let start = (at % PAGE) as usize;
            let dest = (at - offset) as usize;
            buf[dest..dest + count].copy_from_slice(&bytes[start..start + count]);
            at += count as u64;
        }
        Ok(())
    }
    fn write_at(&self, _offset: u64, _data: &[u8]) -> io::Result<()> {
        Err(read_only())
    }
    fn set_len(&self, _len: u64) -> io::Result<()> {
        Err(read_only())
    }
    fn allocate_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(read_only())
    }
    fn punch_hole(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(read_only())
    }
    fn len(&self) -> io::Result<u64> {
        self.view.check()?;
        Ok(self.view.node(self.id)?.len)
    }
    fn sync_data(&self) -> io::Result<()> {
        Err(read_only())
    }
    fn sync_all(&self) -> io::Result<()> {
        Err(read_only())
    }
}

/// What [`Backing::try_lock_shared_existing`] hands out for a file of the
/// view. The view itself holds the shared locks that keep every writer out
/// for as long as it is open, so a lock within it has nothing to add: any
/// number of readers may hold it at once.
struct SharedLock;
impl VolumeLock for SharedLock {}

impl Backing for ReadOnlyRollbackBacking {
    fn check_freshness(&self) -> io::Result<()> {
        self.view.check()
    }
    fn session_stopped(&self) -> Option<String> {
        self.view.stopped.get().cloned()
    }
    fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate_name(name, false)?;
        if create {
            return Err(read_only());
        }
        self.view.check()?;
        let id = self.view.file(name)?;
        Ok(Arc::new(ViewFile {
            view: self.view.clone(),
            id,
        }))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        validate_name(name, false)?;
        self.view.check()?;
        let entries = &self.view.manifest.entries;
        match lookup_directory(entries, path::parent(name)) {
            Ok(()) => Ok(entries.contains_key(name)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    fn remove(&self, _name: &str) -> io::Result<()> {
        Err(read_only())
    }
    fn rename(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(read_only())
    }
    fn create_dir_all(&self, _name: &str) -> io::Result<()> {
        Err(read_only())
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        validate_name(dir, true)?;
        self.view.check()?;
        let entries = &self.view.manifest.entries;
        lookup_directory(entries, dir)?;
        Ok(directory_entries(entries, dir)
            .map(|(child, _)| child.to_owned())
            .collect())
    }
    fn sync_dir(&self, _dir: &str) -> io::Result<()> {
        Err(read_only())
    }
    fn try_lock(&self, _name: &str) -> io::Result<Box<dyn VolumeLock>> {
        Err(read_only())
    }
    fn is_read_only(&self) -> bool {
        true
    }
    fn try_lock_shared_existing(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
        validate_name(name, false)?;
        self.view.check()?;
        self.view.file(name)?;
        Ok(Box::new(SharedLock))
    }
    /// The capacity the committed manifest has not reserved. A writer's view
    /// first reclaims the pages of files that were closed after their last
    /// name went, which this view cannot, so it may report less.
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.view.check()?;
        let manifest = &self.view.manifest;
        Ok(Some(manifest.capacity - manifest.reserved_pages() * PAGE))
    }
}
