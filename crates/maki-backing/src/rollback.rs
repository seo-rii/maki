//! Opt-in, bounded copy-on-write backing with an independent local witness.
//!
//! The arena and both manifest slots are physically reserved at enrollment
//! and before reopening an authenticated backing.
//! A manifest authenticates the entire namespace and every referenced page.
//! Only the independent witness selects a recoverable manifest. Unsynced
//! bytes remain in a separately authenticated, process-local working view.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::witness::FileWitness;

#[cfg(all(test, target_os = "linux"))]
mod arena_read_tests;
mod enrollment;
pub mod gc;
#[cfg(all(test, target_os = "linux"))]
mod local_creation_tests;
#[cfg(all(test, target_os = "linux"))]
mod local_load_tests;
mod remote;
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod review_restore;
use crate::{configured, path, Backing, BackingFile, FileBacking, VolumeLock};
use remote::Witness;

const PAGE: u64 = 4096;
const MAX_CAPACITY: u64 = 1 << 30;
const MAX_ENTRIES: usize = 4096;
const MARKER: &str = "rollback.format";
/// The format marker while a creation writes it, before it is renamed into
/// place (`publish_marker`).
const MARKER_NEXT: &str = "rollback.format.next";
const MAGIC: &[u8] = b"MAKI-WITNESS-COW-V1\n";
const LOCK: &str = "rollback.lock";
const ENROLL_LOCK: &str = "remote.enroll.lock";
const ARENA: &str = "rollback.arena";
const MANIFESTS: [&str; 2] = ["rollback.manifest.0", "rollback.manifest.1"];

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn missing() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "rollback namespace entry not found",
    )
}
fn no_space() -> io::Error {
    io::Error::from_raw_os_error(28)
}
fn manifest_bound(capacity: u64) -> u64 {
    (8 << 20) + capacity / PAGE * 256
}
fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
fn page_digest(identity: &[u8; 16], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"maki.rollback.page.v1\0");
    hash.update(identity);
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
    slot: u64,
    hash: [u8; 32],
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    len: u64,
    pages: BTreeMap<u64, PageRef>,
    // Explicit capacity promises, including reserved authenticated zeroes.
    reserved: BTreeSet<u64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Entry {
    Directory,
    File(u64),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    identity: [u8; 16],
    generation: u64,
    capacity: u64,
    next_id: u64,
    entries: BTreeMap<String, Entry>,
    files: BTreeMap<u64, Node>,
}

impl Manifest {
    fn reserved_pages(&self) -> u64 {
        self.files
            .values()
            .map(|file| file.reserved.len() as u64)
            .sum()
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() as u64 + 8 > manifest_bound(self.capacity) {
            return Err(no_space());
        }
        Ok(bytes)
    }

    fn validate(&self) -> io::Result<()> {
        validate_capacity(self.capacity)?;
        if self.format != 1
            || self.identity == [0; 16]
            || self.next_id == 0
            || self.entries.len() > MAX_ENTRIES
            || self.files.len() > MAX_ENTRIES
        {
            return Err(invalid("invalid rollback manifest header or entry count"));
        }
        let mut linked = BTreeSet::new();
        for (name, entry) in &self.entries {
            validate_name(name, false)?;
            let parent = path::parent(name);
            if !parent.is_empty() && self.entries.get(parent) != Some(&Entry::Directory) {
                return Err(invalid("manifest entry has no parent directory"));
            }
            if let Entry::File(id) = entry {
                if !self.files.contains_key(id) || !linked.insert(*id) {
                    return Err(invalid("manifest has missing or aliased file identity"));
                }
            }
        }
        let mut physical = BTreeSet::new();
        let mut reserved = 0u64;
        for (id, node) in &self.files {
            if *id == 0 || *id >= self.next_id {
                return Err(invalid("invalid manifest file identity"));
            }
            reserved = reserved
                .checked_add(node.reserved.len() as u64)
                .ok_or_else(|| invalid("reservation overflow"))?;
            for (index, page) in &node.pages {
                if *index >= node.len.div_ceil(PAGE)
                    || !node.reserved.contains(index)
                    || page.slot >= 2 * self.capacity / PAGE
                    || !physical.insert(page.slot)
                {
                    return Err(invalid("invalid or aliased manifest page"));
                }
            }
            if node
                .reserved
                .iter()
                .any(|index| *index > (u64::MAX - PAGE) / PAGE)
            {
                return Err(invalid("reservation offset overflow"));
            }
        }
        if reserved > self.capacity / PAGE {
            return Err(invalid("manifest exceeds reserved capacity"));
        }
        Ok(())
    }
}

fn validate_capacity(capacity: u64) -> io::Result<()> {
    if capacity == 0 || capacity > MAX_CAPACITY || !capacity.is_multiple_of(PAGE) {
        return Err(input(
            "rollback capacity must be a positive multiple of 4096, at most 1 GiB",
        ));
    }
    Ok(())
}
fn validate_name(name: &str, empty: bool) -> io::Result<()> {
    path::validate(name, empty)?;
    if name.len() > 1024 {
        return Err(input("rollback namespace path exceeds 1024 bytes"));
    }
    Ok(())
}

/// A bounded Linux storage format. `capacity_bytes` is usable reserved
/// logical page capacity; physical footprint is twice that plus two manifests.
/// The witness MUST have an independent, durable restore policy. A different
/// filesystem is enforced, but does not prove administrative independence.
pub struct RollbackBacking {
    state: Arc<Mutex<State>>,
    /// Why the session stopped, recorded once when [`State::stop`] runs.
    /// Read without the state lock, which commits hold across storage and
    /// witness I/O, so a status query never waits for them.
    stopped: Arc<OnceLock<String>>,
}

struct State {
    disk: Arc<dyn Backing>,
    arena: Arc<dyn BackingFile>,
    witness: Witness,
    _disk_lock: Box<dyn VolumeLock>,
    committed: Manifest,
    manifest_slot: usize,
    // Every working reservation is published before reserve() returns. A
    // shrink/punch only releases committed capacity after its own sync.
    reserved_pages: u64,
    entries: BTreeMap<String, Entry>,
    files: BTreeMap<u64, Node>,
    // Only these working nodes can differ from an existing committed node.
    possibly_dirty: BTreeSet<u64>,
    handles: BTreeMap<u64, usize>,
    // Identities with neither a working nor a committed name. They become
    // reclaimable at last close. Unlink or replacement can invalidate this set.
    unlinked_files: Option<BTreeSet<u64>>,
    next_id: u64,
    locks: BTreeSet<u64>,
    poisoned: bool,
    /// Shared with [`RollbackBacking::stopped`].
    stopped: Arc<OnceLock<String>>,
    /// Arena slots the committed manifest references; recomputed only when
    /// a commit succeeds.
    committed_slots: BTreeSet<u64>,
    /// Committed and working slots together, or `None` when an operation
    /// that can free a slot made it stale. Allocation only adds to it, so it
    /// is never smaller than the slots in use.
    used_slots: Option<BTreeSet<u64>>,
    /// Where the next free-slot search starts.
    free_hint: u64,
}

/// Arena slots referenced by a set of file nodes.
fn slots_of<'a>(nodes: impl Iterator<Item = &'a Node>) -> BTreeSet<u64> {
    nodes
        .flat_map(|node| node.pages.values().map(|page| page.slot))
        .collect()
}

fn independent_paths(root: &Path, witness: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::canonicalize(root)?;
        let b = std::fs::canonicalize(witness)?;
        if a.starts_with(&b)
            || b.starts_with(&a)
            || std::fs::metadata(&a)?.dev() == std::fs::metadata(&b)?.dev()
        {
            return Err(input(
                "rollback witness must be outside the backing tree on a different filesystem",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, witness);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "rollback backing requires Linux",
        ))
    }
}

impl RollbackBacking {
    /// Physical root entries occupied by a local or remote rollback backing.
    /// The inner volume layout lives in the arena and owns no host pathnames.
    pub fn owns_host_entry(name: &str, remote: bool) -> bool {
        if remote {
            matches!(
                name,
                MARKER
                    | MARKER_NEXT
                    | ENROLL_LOCK
                    | gc::OPERATION_LOCK
                    | enrollment::FILE
                    | enrollment::FILE_NEXT
            ) || gc::namespace_fence(name.strip_prefix(gc::TOMBSTONE).unwrap_or(name)).is_some()
        } else {
            matches!(name, MARKER | MARKER_NEXT | ARENA | LOCK) || MANIFESTS.contains(&name)
        }
    }

    /// The immutable logical-page capacity in the authenticated manifest.
    /// A revoked or uncertain session cannot supply usable format geometry.
    pub fn capacity(&self) -> io::Result<u64> {
        let mut state = self.state.lock();
        state.check()?;
        Ok(state.committed.capacity)
    }

    /// Enroll an empty backing and a previously unused independent witness.
    ///
    /// A creation that stopped before it published the witness anchor, its
    /// last step, is completed by running it again: nothing could open that
    /// volume, so nothing was acknowledged. What it may find is checked by
    /// `require_unpublished_local`; anything else is refused as before, and
    /// there is no other implicit enrollment.
    pub fn create(root: &Path, witness: &Path, capacity_bytes: u64) -> io::Result<Self> {
        validate_capacity(capacity_bytes)?;
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rollback backing requires Linux",
            ));
        }
        let disk = FileBacking::new(root)?;
        // Creation of directories is authorized only on this explicit path.
        let witness_dir = FileBacking::new(witness)?;
        independent_paths(root, witness)?;
        Self::create_backing(Arc::new(disk), Arc::new(witness_dir), capacity_bytes)
    }

    // One creation path for the real backing and the executable crash model.
    fn create_backing(
        disk: Arc<dyn Backing>,
        witness: Arc<dyn Backing>,
        capacity_bytes: u64,
    ) -> io::Result<Self> {
        let disk_lock = disk.try_lock(LOCK)?;
        require_unpublished_local(disk.as_ref(), witness.as_ref())?;
        publish_marker(disk.as_ref(), MAGIC)?;
        let arena = disk.open(ARENA, true)?;
        reserve_storage(disk.as_ref(), arena.as_ref(), capacity_bytes)?;
        let manifest = Manifest {
            format: 1,
            identity: *uuid::Uuid::new_v4().as_bytes(),
            generation: 0,
            capacity: capacity_bytes,
            next_id: 1,
            entries: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let bytes = manifest.encode()?;
        // The initial manifest goes into slot 0 with its length in one
        // write, far smaller than a sector, so a cut leaves the slot as it
        // was (zeros, or an earlier attempt's initial manifest) or holding
        // this one whole: never a part `require_unpublished_local` would
        // have to tell apart from damage.
        let slot = disk.open(MANIFESTS[0], false)?;
        let mut record = (bytes.len() as u64).to_le_bytes().to_vec();
        record.extend_from_slice(&bytes);
        slot.write_at(0, &record)?;
        slot.sync_data()?;
        disk.sync_dir("")?;
        let witness = FileWitness::create_backing(
            witness,
            manifest.identity,
            digest(b"maki.rollback.manifest.v1\0", &bytes),
        )?;
        Ok(Self::assemble_witness(
            disk,
            arena,
            Witness::Local(witness),
            disk_lock,
            manifest,
            0,
        ))
    }

    /// Open only the exact manifest selected by the existing witness.
    pub fn open(root: &Path, witness: &Path) -> io::Result<Self> {
        // Name a configured directory this process cannot open before the
        // checks below report its bare error. Opening never creates either.
        if cfg!(target_os = "linux") {
            configured::BACKING_ROOT.reachable(root)?;
            configured::WITNESS_ROOT.reachable(witness)?;
        }
        independent_paths(root, witness)?;
        Self::open_backing(Arc::new(FileBacking::new(root)?), witness)
    }

    /// [`Self::create`] over a backing and a witness directory the caller
    /// hosts, for the executable crash model of a creation that is
    /// completed above this layer. The caller answers for what the path
    /// form checks: that the witness is independent of the backing.
    #[doc(hidden)]
    pub fn create_on(
        disk: Arc<dyn Backing>,
        witness: Arc<dyn Backing>,
        capacity_bytes: u64,
    ) -> io::Result<Self> {
        validate_capacity(capacity_bytes)?;
        Self::create_backing(disk, witness, capacity_bytes)
    }

    /// [`Self::open`] over a backing and a witness directory the caller
    /// hosts (see [`Self::create_on`]).
    #[doc(hidden)]
    pub fn open_on(disk: Arc<dyn Backing>, witness: Arc<dyn Backing>) -> io::Result<Self> {
        let listed = witness.clone();
        Self::open_witnessed(
            disk,
            move || listed.list(""),
            || FileWitness::open_backing(witness),
        )
    }

    // Keep authentication and readiness barriers on one path for the real
    // backing and the executable crash model.
    fn open_backing(disk: Arc<dyn Backing>, witness: &Path) -> io::Result<Self> {
        Self::open_witnessed(
            disk,
            || FileBacking::read_only(witness)?.list(""),
            || FileWitness::open(witness),
        )
    }

    /// `listing` lists the witness directory, only to word the refusal of
    /// a backing without its marker; `witness` opens the witness.
    fn open_witnessed(
        disk: Arc<dyn Backing>,
        listing: impl FnOnce() -> io::Result<Vec<String>>,
        witness: impl FnOnce() -> io::Result<FileWitness>,
    ) -> io::Result<Self> {
        let disk_lock = disk.try_lock(LOCK)?;
        let marker = disk.open(MARKER, false).map_err(|error| {
            if error.kind() != io::ErrorKind::NotFound {
                return error;
            }
            no_marker(disk.as_ref(), listing())
        })?;
        let mut magic = vec![0; MAGIC.len()];
        if marker.len()? != MAGIC.len() as u64 {
            return Err(invalid("invalid rollback format marker"));
        }
        marker.read_at(0, &mut magic)?;
        if magic != MAGIC {
            return Err(invalid("unsupported rollback format"));
        }
        let witness = witness()?;
        let anchor = witness.anchor();
        let mut selected = None;
        let mut storage_error = None;
        for (slot, name) in MANIFESTS.iter().enumerate() {
            let candidate = (|| {
                let file = disk.open(name, false)?;
                let mut header = [0; 8];
                file.read_at(0, &mut header)?;
                let len = u64::from_le_bytes(header);
                // The length is unauthenticated. A canonical manifest fits
                // its slot, so refuse one the file cannot hold before
                // allocating for it.
                if len == 0
                    || len > manifest_bound(MAX_CAPACITY) - 8
                    || len > file.len()?.saturating_sub(8)
                {
                    return Err(invalid("invalid rollback manifest length"));
                }
                let mut bytes = vec![0; len as usize];
                file.read_at(8, &mut bytes)?;
                if digest(b"maki.rollback.manifest.v1\0", &bytes) != anchor.root {
                    return Err(invalid("manifest does not match independent witness"));
                }
                let manifest: Manifest = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("invalid rollback manifest encoding"))?;
                manifest
                    .validate()
                    .map_err(|_| invalid("invalid rollback manifest content"))?;
                if manifest
                    .encode()
                    .map_err(|_| invalid("invalid rollback manifest size"))?
                    != bytes
                    || manifest.identity != anchor.identity
                    || manifest.generation != anchor.generation
                    || file.len()? != manifest_bound(manifest.capacity)
                {
                    return Err(invalid("noncanonical or foreign rollback manifest"));
                }
                Ok(manifest)
            })();
            match candidate {
                Ok(manifest) => {
                    selected = Some((slot, manifest));
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::InvalidData
                    ) => {}
                Err(error) => {
                    // A readable exact copy can still recover the backing.
                    // If neither candidate can be authenticated, preserve
                    // inability to read storage instead of claiming rollback.
                    if storage_error.is_none() {
                        storage_error = Some(error);
                    }
                }
            }
        }
        let (slot, manifest) = selected.ok_or_else(|| {
            storage_error.unwrap_or_else(|| {
                invalid("no exact witnessed manifest: backing may be rolled back or incomplete")
            })
        })?;
        let arena = disk.open(ARENA, false)?;
        if arena.len()? != manifest.capacity * 2 {
            return Err(invalid("rollback arena size mismatch"));
        }
        // Authenticate every committed extent before exposing readiness.
        let mut bytes = vec![0; PAGE as usize];
        for node in manifest.files.values() {
            for page in node.pages.values() {
                arena.read_at(page.slot * PAGE, &mut bytes)?;
                if page_digest(&manifest.identity, &bytes) != page.hash {
                    return Err(invalid("rollback arena page authentication failed"));
                }
            }
        }
        // File lengths and authenticated bytes do not prove that a sparse
        // backup/restore preserved physical reservations. Reestablish them
        // before any caller can depend on the recorded capacity promises.
        // Only the inactive manifest may have been missing or the wrong size;
        // selected evidence and arena length were validated above.
        reserve_storage(disk.as_ref(), arena.as_ref(), manifest.capacity)?;
        // A failed restore/reopen writeback can leave authenticated bytes
        // readable but clean and absent from disk, even in a new process.
        // Re-dirty every selected page before admitting another writer. Keep
        // the buffer bounded, and recheck each page immediately before the
        // rewrite; all pages were authenticated before any mutation above.
        for node in manifest.files.values() {
            for page in node.pages.values() {
                arena.read_at(page.slot * PAGE, &mut bytes)?;
                if page_digest(&manifest.identity, &bytes) != page.hash {
                    return Err(invalid("rollback arena changed during restore"));
                }
                arena.write_at(page.slot * PAGE, &bytes)?;
            }
        }
        arena.sync_data()?;
        // The exact selected envelope and marker can also be cache-only after
        // failed writeback. Re-publish the already authenticated bytes without
        // advancing the independent witness or changing the on-disk format.
        write_manifest(disk.as_ref(), slot, &manifest.encode()?)?;
        marker.write_at(0, MAGIC)?;
        marker.set_len(MAGIC.len() as u64)?;
        marker.sync_data()?;
        disk.sync_dir("")?;
        Ok(Self::assemble_witness(
            disk,
            arena,
            Witness::Local(witness),
            disk_lock,
            manifest,
            slot,
        ))
    }

    fn assemble_witness(
        disk: Arc<dyn Backing>,
        arena: Arc<dyn BackingFile>,
        witness: Witness,
        disk_lock: Box<dyn VolumeLock>,
        manifest: Manifest,
        slot: usize,
    ) -> Self {
        let stopped = Arc::new(OnceLock::new());
        Self {
            stopped: stopped.clone(),
            state: Arc::new(Mutex::new(State {
                committed_slots: slots_of(manifest.files.values()),
                reserved_pages: manifest.reserved_pages(),
                used_slots: None,
                free_hint: 0,
                entries: manifest.entries.clone(),
                files: manifest.files.clone(),
                next_id: manifest.next_id,
                committed: manifest,
                manifest_slot: slot,
                disk,
                arena,
                witness,
                _disk_lock: disk_lock,
                possibly_dirty: BTreeSet::new(),
                handles: BTreeMap::new(),
                unlinked_files: None,
                locks: BTreeSet::new(),
                poisoned: false,
                stopped,
            })),
        }
    }

    fn retain_file(&self, state: &mut State, id: u64) -> CowFile {
        *state.handles.entry(id).or_default() += 1;
        CowFile {
            state: self.state.clone(),
            id,
        }
    }
}

fn directory_entries<'a>(
    entries: &'a BTreeMap<String, Entry>,
    dir: &str,
) -> impl Iterator<Item = (&'a str, &'a Entry)> {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    entries
        .range(prefix.clone()..)
        .map_while(move |(name, entry)| name.strip_prefix(&prefix).map(|child| (child, entry)))
        .filter(|(child, _)| !child.contains('/'))
}

fn reserve_storage(disk: &dyn Backing, arena: &dyn BackingFile, capacity: u64) -> io::Result<()> {
    // Matching cached lengths do not prove that an earlier set_len survived
    // failed writeback. Reassert them before the successful reservation sync.
    arena.set_len(capacity * 2)?;
    arena.allocate_range(0, capacity * 2)?;
    // Reopening a sparse restore can allocate unwritten extents inside an
    // already durable EOF. Persist their metadata before promising space.
    arena.sync_all()?;
    let bound = manifest_bound(capacity);
    for name in MANIFESTS {
        let file = disk.open(name, true)?;
        file.set_len(bound)?;
        file.allocate_range(0, bound)?;
        file.sync_all()?;
    }
    disk.sync_dir("")
}

/// Publish the format marker `magic`. Called with the root's creation
/// locks held.
///
/// The marker is written and synced under its staging name, renamed into
/// place, and the directory is synced, so `rollback.format` never names an
/// empty or torn marker, whatever kills this process, cuts the power or
/// fails in between. Until the rename nothing is published and the creation
/// can simply be run again. A staged marker that a failed write or sync
/// left is never synced as it is: it is truncated and written again through
/// a new descriptor first.
fn publish_marker(disk: &dyn Backing, magic: &[u8]) -> io::Result<()> {
    // Whatever an earlier run left under the staged name is never read.
    // Remove it first, as a leftover `anchor.next` is, so the staged marker
    // is a file this run creates (for the directory's owner when root runs
    // it): a root-run creation killed between creating the name and giving
    // it away leaves a file the daemon user may not open but may remove.
    // What is not a regular file with one name was refused before this
    // (`leftover`).
    match disk.remove(MARKER_NEXT) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let staged = (|| {
        let marker = disk.open(MARKER_NEXT, true)?;
        marker.set_len(0)?;
        marker.write_at(0, magic)?;
        marker.set_len(magic.len() as u64)?;
        marker.sync_data()
    })();
    if let Err(error) = staged {
        // Leave the root as this run found it where that still works. A
        // staged marker that stays does no harm: the next creation accepts
        // and rewrites it.
        let _ = disk.remove(MARKER_NEXT);
        return Err(error);
    }
    disk.rename(MARKER_NEXT, MARKER)?;
    disk.sync_dir("")
}

/// Whether `rollback.format` was created and never completely written: it
/// is empty or a torn copy of `magic`, each byte the marker's or still
/// zero. The marker itself is not.
fn unwritten_marker(disk: &dyn Backing, magic: &[u8]) -> io::Result<bool> {
    let marker = disk.open(MARKER, false)?;
    let len = marker.len()?;
    if len > magic.len() as u64 {
        return Ok(false);
    }
    let mut bytes = vec![0; len as usize];
    marker.read_at(0, &mut bytes)?;
    Ok(bytes != magic
        && bytes
            .iter()
            .zip(magic)
            .all(|(byte, expected)| *byte == 0 || byte == expected))
}

/// Refuse a local backing and witness directory in which a creation has
/// published anything, or which hold anything a creation does not write.
///
/// The witness may hold only its lock and a staged anchor: a creation
/// publishes the anchor last, renaming it into place, so an `anchor` that
/// is present (an empty one too, which earlier releases installed before
/// writing the record, and which is also what a truncated anchor looks
/// like) is never created over. The backing may hold its lock, the marker
/// (staged, published, or created and never written by an earlier
/// release), the arena and the two manifest slots, each holding only what
/// a creation writes there (`unpublished_slot`): slot 1 nothing at all,
/// slot 0 nothing or the empty generation-0 manifest. Such a backing names
/// no data that any witness could select, so a creation over it loses
/// nothing. Every volume that committed anything wrote generation 1 to
/// slot 1 before its witness moved past the initial manifest, and a slot
/// holding anything else, bytes that do not decode included, is a
/// volume's slot in whatever state damage left it: it is refused whatever
/// the witness directory holds, an empty one included (a witness that is
/// not mounted). The marker refuses anything but this format. The staged
/// marker, the arena and the slots must each be a regular file with one
/// name, which the creation can write again (`leftover`): a staged marker
/// this user may not open is removed before the marker is staged anew, and
/// an arena or slot this user may not open is refused with the way out.
fn require_unpublished_local(disk: &dyn Backing, witness: &dyn Backing) -> io::Result<()> {
    let refused = || {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "rollback enrollment requires empty backing and witness directories",
        )
    };
    for name in disk.list("")? {
        match leftover(disk, &name)? {
            Leftover::Unpublished => {}
            Leftover::Other => return Err(refused()),
            Leftover::Unopenable(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "the backing directory holds {name:?}, which this user may not open \
                         ({error}): give it to the user this command runs as (chown), let that \
                         user read and write it (chmod) and run the command again"
                    ),
                ))
            }
        }
    }
    if witness
        .list("")?
        .iter()
        .any(|name| !FileWitness::left_by_an_unpublished_creation(name))
    {
        return Err(refused());
    }
    Ok(())
}

/// What the backing entry `name` tells a creation (see
/// `require_unpublished_local`).
enum Leftover {
    /// What a creation that published nothing may have left, holding only
    /// what it writes there.
    Unpublished,
    /// Anything else: a creation never runs over it.
    Other,
    /// A file a creation reserves that this user may not open (the error):
    /// what a creation run as root leaves when it is killed between
    /// creating the file under its name and giving it to the directory's
    /// owner.
    Unopenable(io::Error),
}

fn leftover(disk: &dyn Backing, name: &str) -> io::Result<Leftover> {
    // A creation writes what it stages and reserves under these names again
    // from the start, which holds only for a regular file with one name, so
    // anything else is refused here, named, before anything is published.
    // Unrefused, a link, a directory, a FIFO or a second name under the
    // arena fails the creation after its marker is published, and every
    // later run the same way; a link or a directory under the staged
    // marker's name fails every run before the marker, since
    // `publish_marker` can remove neither; and any of them under a slot
    // fails the check of the slot's contents (`unpublished_slot`) with the
    // system's error. The lock is taken before this, by both commands.
    // The staged marker is never read, and `publish_marker` removes the
    // file under its name before it stages the marker, so one this user
    // may not open (what a root-run creation leaves when it is killed
    // before it gives the file away) does not stop a creation.
    if name == MARKER_NEXT {
        return Ok(match remote::unwritable(disk, name)? {
            None => Leftover::Unpublished,
            Some(error) if error.kind() == io::ErrorKind::PermissionDenied => Leftover::Unpublished,
            Some(_) => Leftover::Other,
        });
    }
    // The arena and the slots are opened and written as they are: one this
    // user may not open stops a creation, with the way out.
    if name == ARENA || MANIFESTS.contains(&name) {
        match remote::unwritable(disk, name)? {
            Some(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(Leftover::Unopenable(error))
            }
            Some(_) => return Ok(Leftover::Other),
            None => {}
        }
    }
    let unpublished = match name {
        LOCK | ARENA => true,
        MARKER => {
            let marker = disk.open(MARKER, false)?;
            let mut bytes = vec![0; MAGIC.len()];
            let complete = marker.len()? == MAGIC.len() as u64 && {
                marker.read_at(0, &mut bytes)?;
                bytes == MAGIC
            };
            complete || unwritten_marker(disk, MAGIC)?
        }
        slot if slot == MANIFESTS[0] => unpublished_slot(disk, 0)?,
        slot if slot == MANIFESTS[1] => unpublished_slot(disk, 1)?,
        _ => false,
    };
    Ok(if unpublished {
        Leftover::Unpublished
    } else {
        Leftover::Other
    })
}

/// The refusal of a backing without its format marker. That is what a
/// creation leaves that stopped before it published the marker, and what
/// a wrong `backing.root` looks like. Running `volume create` again
/// continues only the first, and only when nothing in either directory
/// stops it (`require_unpublished_local`): then the refusal says so.
/// Otherwise it names the entries that stop a creation, which `volume
/// create` refuses every time it runs, and offers nothing. `witness` is
/// the listing of the witness directory; when either listing cannot be
/// made, what a creation would do cannot be told and nothing is offered.
fn no_marker(disk: &dyn Backing, witness: io::Result<Vec<String>>) -> io::Error {
    // The entries that stop a creation: in the backing directory those it
    // never runs over and those this user may not open, in the witness
    // directory those it never runs over.
    type Stopping = (Vec<String>, Vec<String>, Vec<String>);
    let stopping = (|| -> io::Result<Stopping> {
        let (mut other, mut unopenable) = (Vec::new(), Vec::new());
        for name in disk.list("")? {
            match leftover(disk, &name)? {
                Leftover::Unpublished => {}
                Leftover::Other => other.push(name),
                Leftover::Unopenable(_) => unopenable.push(name),
            }
        }
        let witness = witness?
            .into_iter()
            .filter(|name| !FileWitness::left_by_an_unpublished_creation(name))
            .collect();
        Ok((other, unopenable, witness))
    })();
    let message = match stopping {
        Ok((other, unopenable, witness))
            if other.is_empty() && unopenable.is_empty() && witness.is_empty() =>
        {
            format!(
                "this rollback backing holds no format marker ({MARKER}): either a volume \
                 create did not complete here, which running volume create again continues, \
                 or this is not the volume's backing root"
            )
        }
        Ok((other, unopenable, witness)) => {
            let mut reasons = Vec::new();
            let holds: Vec<String> = [("backing", other), ("witness", witness)]
                .into_iter()
                .filter(|(_, names)| !names.is_empty())
                .map(|(directory, names)| {
                    format!("the {directory} directory holds {}", entry_names(names))
                })
                .collect();
            let foreign = !holds.is_empty();
            if foreign {
                reasons.push(format!(
                    "{}, which an interrupted creation does not leave",
                    holds.join(" and ")
                ));
            }
            if !unopenable.is_empty() {
                reasons.push(format!(
                    "the backing directory holds {}, which this user may not open: give it to \
                     the user this command runs as (chown), let that user read and write it \
                     (chmod) and run the command again",
                    entry_names(unopenable)
                ));
            }
            let mut message = format!(
                "this rollback backing holds no format marker ({MARKER}), and volume create \
                 does not continue a creation here: {}",
                reasons.join("; ")
            );
            if foreign {
                message.push_str(
                    ". Either this is not the volume's backing root, or volume create needs \
                     directories that hold nothing else",
                );
            }
            message
        }
        Err(_) => format!(
            "this rollback backing holds no format marker ({MARKER}): either a volume create \
             did not complete here, or this is not the volume's backing root"
        ),
    };
    io::Error::new(io::ErrorKind::NotFound, message)
}

/// A bounded, quoted list of directory entries for a message.
fn entry_names(mut names: Vec<String>) -> String {
    const SHOWN: usize = 4;
    names.sort();
    let mut text = names
        .iter()
        .take(SHOWN)
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        text.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    text
}

/// Whether manifest slot `index` holds only what a creation writes there.
/// A creation reserves both slots (zeros) and writes the empty
/// generation-0 manifest to slot 0 with its length in one write, so a slot
/// it left is all zeros, or, for slot 0, exactly that manifest. Anything
/// else, a slot whose length or bytes do not decode included, is refused:
/// only an all-zero slot is unwritten (S-01).
fn unpublished_slot(disk: &dyn Backing, index: usize) -> io::Result<bool> {
    let file = disk.open(MANIFESTS[index], false)?;
    let size = file.len()?;
    let mut chunk = vec![0; 64 << 10];
    let mut offset = 0;
    while offset < size {
        let part = &mut chunk[..(size - offset).min(64 << 10) as usize];
        file.read_at(offset, part)?;
        if part.iter().any(|byte| *byte != 0) {
            break;
        }
        offset += part.len() as u64;
    }
    if offset >= size {
        return Ok(true);
    }
    if index != 0 || size < 8 {
        return Ok(false);
    }
    let mut header = [0; 8];
    file.read_at(0, &mut header)?;
    let len = u64::from_le_bytes(header);
    if len == 0 || len > manifest_bound(MAX_CAPACITY) - 8 || len > size - 8 {
        return Ok(false);
    }
    let mut bytes = vec![0; len as usize];
    file.read_at(8, &mut bytes)?;
    Ok(
        serde_json::from_slice::<Manifest>(&bytes).is_ok_and(|manifest| {
            manifest.generation == 0 && manifest.entries.is_empty() && manifest.files.is_empty()
        }),
    )
}

fn write_manifest(disk: &dyn Backing, slot: usize, bytes: &[u8]) -> io::Result<()> {
    let file = disk.open(MANIFESTS[slot], false)?;
    file.write_at(8, bytes)?;
    file.write_at(0, &(bytes.len() as u64).to_le_bytes())?;
    file.sync_data()
}

impl State {
    fn check(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid(
                "rollback session stopped; reopen against the independent witness",
            ));
        }
        if let Err(error) = self.witness.verify_current() {
            if self.witness.stops_session(&error) {
                self.stop(&error);
            }
            return Err(error);
        }
        Ok(())
    }

    /// Stop the session for good: every later operation of every handle
    /// fails. The first cause is recorded for [`Backing::session_stopped`]
    /// and logged once; the engine reports the volume degraded with it.
    fn stop(&mut self, cause: &dyn std::fmt::Display) {
        self.poisoned = true;
        if self
            .stopped
            .set(format!("rollback session stopped: {cause}"))
            .is_ok()
        {
            tracing::warn!(
                "rollback session stopped: {cause}; every operation fails until the volume \
                 is opened again against the witness"
            );
        }
    }

    fn directory(&self, name: &str) -> io::Result<()> {
        if name.is_empty() || self.entries.get(name) == Some(&Entry::Directory) {
            return Ok(());
        }
        let mut path = name;
        while !path.is_empty() {
            match self.entries.get(path) {
                Some(Entry::File(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        path.to_owned(),
                    ))
                }
                Some(Entry::Directory) => break,
                None => path = path::parent(path),
            }
        }
        Err(missing())
    }

    fn open_file(&mut self, name: &str, create: bool) -> io::Result<u64> {
        self.directory(path::parent(name))?;
        let id = match self.entries.get(name) {
            Some(Entry::File(id)) => *id,
            Some(Entry::Directory) => {
                return Err(io::Error::new(io::ErrorKind::IsADirectory, name))
            }
            None if create => {
                if self.entries.len() >= MAX_ENTRIES {
                    return Err(no_space());
                }
                if self.files.len() >= MAX_ENTRIES {
                    self.reclaim_closed_files()?;
                }
                if self.files.len() >= MAX_ENTRIES {
                    return Err(no_space());
                }
                let id = self.next_id;
                self.next_id = id
                    .checked_add(1)
                    .ok_or_else(|| invalid("file identity exhausted"))?;
                self.files.insert(id, Node::default());
                self.entries.insert(name.to_owned(), Entry::File(id));
                id
            }
            None => return Err(missing()),
        };
        Ok(id)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn coordinates(&self) -> BTreeSet<(u64, u64)> {
        self.committed
            .files
            .iter()
            .chain(self.files.iter())
            .flat_map(|(id, node)| node.reserved.iter().map(move |index| (*id, *index)))
            .collect()
    }

    fn reclaim_closed_files(&mut self) -> io::Result<()> {
        let unlinked = self.unlinked_files.get_or_insert_with(|| {
            let mut ids: BTreeSet<_> = self.files.keys().copied().collect();
            for entry in self.committed.entries.values().chain(self.entries.values()) {
                if let Entry::File(id) = entry {
                    ids.remove(id);
                }
            }
            ids
        });
        if unlinked.iter().any(|id| !self.handles.contains_key(id)) {
            // Last-close cannot report commit errors. Defer reclamation until
            // the next space query, reservation or identity-limited creation,
            // where errors can propagate.
            // Publish the pruned manifest before counting or reusing its pages;
            // a pending unlink still has a committed name and is retained.
            self.commit(self.committed.clone())?;
        }
        Ok(())
    }

    fn commit(&mut self, mut candidate: Manifest) -> io::Result<()> {
        self.check()?;
        candidate.next_id = self.next_id;
        candidate.generation = self
            .witness
            .anchor()
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("rollback generation exhausted"))?;
        let mut retain: BTreeSet<u64> = candidate
            .entries
            .values()
            .chain(self.entries.values())
            .filter_map(|entry| match entry {
                Entry::File(id) => Some(*id),
                _ => None,
            })
            .collect();
        let mut unlinked = BTreeSet::new();
        for id in self.handles.keys() {
            if retain.insert(*id) {
                // Only this handle keeps the identity in the new manifest.
                unlinked.insert(*id);
            }
        }
        candidate.files.retain(|id, _| retain.contains(id));
        candidate.validate()?;
        let bytes = candidate.encode()?;
        let slot = 1 - self.manifest_slot;
        let result = (|| {
            // reserve_storage fully syncs the entire physical footprint
            // before State exists. Commits change data and logical mappings,
            // without allocating new filesystem extents.
            self.arena.sync_data()?;
            write_manifest(self.disk.as_ref(), slot, &bytes)?;
            self.witness
                .advance(digest(b"maki.rollback.manifest.v1\0", &bytes))
        })();
        if let Err(error) = result {
            self.stop(&format_args!("manifest commit failed: {error}"));
            return Err(error);
        }
        self.unlinked_files = Some(unlinked);
        self.reserved_pages = candidate.reserved_pages();
        self.committed = candidate;
        self.manifest_slot = slot;
        self.files.retain(|id, _| retain.contains(id));
        self.possibly_dirty.retain(|id| retain.contains(id));
        self.committed_slots = slots_of(self.committed.files.values());
        self.used_slots = None;
        Ok(())
    }

    fn reserve(&mut self, id: u64, offset: u64, len: u64) -> io::Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| input("reservation overflow"))?;
        if len == 0 {
            return Ok(());
        }
        let range = offset / PAGE..end.div_ceil(PAGE);
        if range.end > (u64::MAX - PAGE) / PAGE
            || (range.end - range.start) > self.committed.capacity / PAGE
        {
            return Err(no_space());
        }
        // Already reserved in both views: nothing new to reserve or commit,
        // so the capacity count cannot change (the common case of writes
        // into a preallocated range).
        let covered = |node: Option<&Node>| {
            node.is_some_and(|node| range.clone().all(|index| node.reserved.contains(&index)))
        };
        if covered(self.committed.files.get(&id)) && covered(self.files.get(&id)) {
            let node = self.files.get_mut(&id).ok_or_else(missing)?;
            if node.len < end {
                node.len = end;
                self.possibly_dirty.insert(id);
            }
            return Ok(());
        }
        self.reclaim_closed_files()?;
        let durable = self.committed.files.get(&id);
        let additional = range
            .clone()
            .filter(|index| !durable.is_some_and(|file| file.reserved.contains(index)))
            .count() as u64;
        if additional > self.committed.capacity / PAGE - self.reserved_pages {
            return Err(no_space());
        }
        if additional != 0 {
            let mut candidate = self.committed.clone();
            let durable = candidate.files.entry(id).or_default();
            durable.reserved.extend(range.clone());
            // Allocation itself may persist EOF, but never unsynced bytes.
            durable.len = durable.len.max(end);
            self.commit(candidate)?;
        }
        let node = self.files.get_mut(&id).ok_or_else(missing)?;
        node.reserved.extend(range);
        node.len = node.len.max(end);
        self.possibly_dirty.insert(id);
        Ok(())
    }

    /// The working view's reference to one page of a file, if any.
    fn page_ref(&self, id: u64, index: u64) -> io::Result<Option<PageRef>> {
        Ok(self
            .files
            .get(&id)
            .ok_or_else(missing)?
            .pages
            .get(&index)
            .cloned())
    }

    fn page(&mut self, page: Option<PageRef>) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; PAGE as usize];
        if let Some(page) = page {
            self.read_page(&page, &mut bytes)?;
        }
        Ok(bytes)
    }

    fn read_page(&mut self, page: &PageRef, bytes: &mut [u8]) -> io::Result<()> {
        if let Err(error) = self.arena.read_at(page.slot * PAGE, bytes) {
            // No mutation or uncertain commit happened here. An ordinary
            // I/O failure refuses this operation; the next one checks the
            // witness and authenticates the page again. Missing, short or
            // invalid referenced evidence still stops every handle, even
            // if the original bytes are later restored.
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
            ) {
                self.stop(&format_args!("arena page read failed: {error}"));
            }
            return Err(error);
        }
        if page_digest(&self.committed.identity, bytes) != page.hash {
            let error = invalid("rollback arena page authentication failed");
            self.stop(&error);
            return Err(error);
        }
        Ok(())
    }

    /// A slot neither the committed manifest nor the working view uses.
    fn allocate_slot(&mut self) -> io::Result<u64> {
        let slots = 2 * self.committed.capacity / PAGE;
        if self.used_slots.is_none() {
            let mut used = self.committed_slots.clone();
            used.extend(slots_of(self.files.values()));
            self.used_slots = Some(used);
            self.free_hint = 0;
        }
        let used = self.used_slots.as_mut().expect("just computed");
        let start = self.free_hint.min(slots);
        let slot = (start..slots)
            .chain(0..start)
            .find(|slot| !used.contains(slot))
            .ok_or_else(|| invalid("rollback arena reservation invariant violated"))?;
        used.insert(slot);
        self.free_hint = slot + 1;
        Ok(slot)
    }

    fn write_page(&mut self, id: u64, index: u64, bytes: &[u8]) -> io::Result<()> {
        let current = self.page_ref(id, index)?.map(|page| page.slot);
        let slot = match current.filter(|slot| !self.committed_slots.contains(slot)) {
            // A page written since the last commit is rewritten in place.
            Some(slot) => slot,
            None => self.allocate_slot()?,
        };
        if let Err(error) = self.arena.write_at(slot * PAGE, bytes) {
            self.stop(&format_args!("arena page write failed: {error}"));
            return Err(error);
        }
        self.possibly_dirty.insert(id);
        self.files.get_mut(&id).ok_or_else(missing)?.pages.insert(
            index,
            PageRef {
                slot,
                hash: page_digest(&self.committed.identity, bytes),
            },
        );
        Ok(())
    }
}

struct CowFile {
    state: Arc<Mutex<State>>,
    id: u64,
}

impl Drop for CowFile {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if let Some(count) = state.handles.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                state.handles.remove(&self.id);
            }
        }
    }
}

impl BackingFile for CowFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        if buf.is_empty() {
            return Ok(());
        }
        let len = state.files.get(&self.id).ok_or_else(missing)?.len;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| input("read overflow"))?;
        if end > len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond rollback file",
            ));
        }
        // Authenticate into private scratch before exposing any bytes from
        // this page. A hole-only read never needs to allocate it.
        let mut bytes = Vec::new();
        let mut at = offset;
        while at < end {
            let dest = (at - offset) as usize;
            let Some((&index, page)) = state.files[&self.id]
                .pages
                .range(at / PAGE..=(end - 1) / PAGE)
                .next()
            else {
                buf[dest..].fill(0);
                break;
            };
            let page = page.clone();
            let page_start = index * PAGE;
            if at < page_start {
                buf[dest..(page_start - offset) as usize].fill(0);
                at = page_start;
            }
            bytes.resize(PAGE as usize, 0);
            state.read_page(&page, &mut bytes)?;
            let count = (PAGE - at % PAGE).min(end - at) as usize;
            let start = (at % PAGE) as usize;
            let dest = (at - offset) as usize;
            buf[dest..dest + count].copy_from_slice(&bytes[start..start + count]);
            at += count as u64;
        }
        Ok(())
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        state.reserve(self.id, offset, data.len() as u64)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| input("write overflow"))?;
        let mut at = offset;
        let mut scratch = Vec::new();
        while at < end {
            let page = state.page_ref(self.id, at / PAGE)?;
            let count = (PAGE - at % PAGE).min(end - at) as usize;
            let src = (at - offset) as usize;
            let fragment = &data[src..src + count];
            if let Some(page) = page {
                // Authenticate the old mapping even before a full overwrite.
                scratch.resize(PAGE as usize, 0);
                state.read_page(&page, &mut scratch)?;
            } else if count < PAGE as usize {
                scratch.clear();
                scratch.resize(PAGE as usize, 0);
            }
            if count == PAGE as usize {
                state.write_page(self.id, at / PAGE, fragment)?;
            } else {
                let start = (at % PAGE) as usize;
                scratch[start..start + count].copy_from_slice(fragment);
                state.write_page(self.id, at / PAGE, &scratch)?;
            }
            at += count as u64;
        }
        Ok(())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        let node = state.files.get_mut(&self.id).ok_or_else(missing)?;
        if len == node.len {
            return Ok(());
        }
        if len > node.len {
            node.len = len;
            state.possibly_dirty.insert(self.id);
            return Ok(());
        }
        let tail = state.page_ref(self.id, len / PAGE)?;
        if !len.is_multiple_of(PAGE) && tail.is_some() {
            let mut bytes = state.page(tail)?;
            bytes[(len % PAGE) as usize..].fill(0);
            state.write_page(self.id, len / PAGE, &bytes)?;
        }
        let node = state.files.get_mut(&self.id).ok_or_else(missing)?;
        node.len = len;
        node.pages.retain(|index, _| *index < len.div_ceil(PAGE));
        node.reserved.retain(|index| *index < len.div_ceil(PAGE));
        state.possibly_dirty.insert(self.id);
        // Dropped pages may free slots.
        state.used_slots = None;
        Ok(())
    }
    fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        state.reserve(self.id, offset, len)
    }
    fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        let file_len = state.files.get(&self.id).ok_or_else(missing)?.len;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| input("hole range overflow"))?;
        let visible_end = end.min(file_len);
        if offset >= visible_end {
            return Ok(());
        }

        // Every mapped page has a reservation, including reserved zero pages.
        // Visit only existing reservations, even for a very large sparse range.
        let mut next = offset / PAGE;
        let limit = visible_end.div_ceil(PAGE);
        while let Some(index) = state.files[&self.id]
            .reserved
            .range(next..limit)
            .next()
            .copied()
        {
            let page_start = index * PAGE;
            if offset <= page_start && index < end / PAGE {
                // A whole-page request also releases a short final page.
                let node = state.files.get_mut(&self.id).ok_or_else(missing)?;
                node.pages.remove(&index);
                node.reserved.remove(&index);
                state.possibly_dirty.insert(self.id);
                state.used_slots = None;
            } else if let Some(page) = state.page_ref(self.id, index)? {
                let mut bytes = state.page(Some(page))?;
                let from = offset.saturating_sub(page_start) as usize;
                let to = (visible_end - page_start).min(PAGE) as usize;
                if bytes[from..to].iter().any(|&byte| byte != 0) {
                    bytes[from..to].fill(0);
                    state.write_page(self.id, index, &bytes)?;
                }
            }
            next = index + 1;
        }
        Ok(())
    }
    fn len(&self) -> io::Result<u64> {
        let mut state = self.state.lock();
        state.check()?;
        Ok(state.files.get(&self.id).ok_or_else(missing)?.len)
    }
    // The inherited sync_all uses this transaction barrier too: physical
    // arena/manifest reservations were fully synced before State assembly;
    // logical reservations are authenticated manifest data committed here.
    fn sync_data(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        let node = state.files.get(&self.id).ok_or_else(missing)?;
        if state
            .committed
            .files
            .get(&self.id)
            .is_some_and(|durable| !state.possibly_dirty.contains(&self.id) || durable == node)
        {
            state.possibly_dirty.remove(&self.id);
            return state.reclaim_closed_files();
        }
        let mut candidate = state.committed.clone();
        candidate.files.insert(self.id, node.clone());
        state.commit(candidate)?;
        state.possibly_dirty.remove(&self.id);
        Ok(())
    }
}

struct CowLock {
    file: CowFile,
}
impl VolumeLock for CowLock {}
impl Drop for CowLock {
    fn drop(&mut self) {
        self.file.state.lock().locks.remove(&self.file.id);
    }
}

impl Backing for RollbackBacking {
    fn check_freshness(&self) -> io::Result<()> {
        self.state.lock().check()
    }
    fn session_stopped(&self) -> Option<String> {
        self.stopped.get().cloned()
    }
    fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        let id = state.open_file(name, create)?;
        Ok(Arc::new(self.retain_file(&mut state, id)))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        match state.directory(path::parent(name)) {
            Ok(()) => Ok(state.entries.contains_key(name)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(path::parent(name))?;
        if state.entries.get(name) == Some(&Entry::Directory) {
            return Err(input("directory removal is unsupported"));
        }
        state.entries.remove(name).ok_or_else(missing)?;
        state.unlinked_files = None;
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate_name(from, false)?;
        validate_name(to, false)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(path::parent(from))?;
        state.directory(path::parent(to))?;
        let entry = state.entries.get(from).ok_or_else(missing)?.clone();
        if entry == Entry::Directory || state.entries.get(to) == Some(&Entry::Directory) {
            return Err(input("directory rename is unsupported"));
        }
        if path::parent(from) != path::parent(to) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cross-directory rename requires a transaction",
            ));
        }
        state.entries.remove(from);
        if state.entries.insert(to.to_owned(), entry).is_some() {
            state.unlinked_files = None;
        }
        Ok(())
    }
    fn create_dir_all(&self, name: &str) -> io::Result<()> {
        validate_name(name, true)?;
        let mut state = self.state.lock();
        state.check()?;
        let mut prefix = String::new();
        for part in name.split('/').filter(|part| !part.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            match state.entries.get(&prefix) {
                Some(Entry::File(_)) => {
                    return Err(io::Error::new(io::ErrorKind::NotADirectory, prefix))
                }
                Some(Entry::Directory) => (),
                None => {
                    if state.entries.len() >= MAX_ENTRIES {
                        return Err(no_space());
                    }
                    state.entries.insert(prefix.clone(), Entry::Directory);
                }
            }
        }
        Ok(())
    }
    fn list(&self, dir: &str) -> io::Result<Vec<String>> {
        validate_name(dir, true)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(dir)?;
        Ok(directory_entries(&state.entries, dir)
            .map(|(child, _)| child.to_owned())
            .collect())
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        validate_name(dir, true)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(dir)?;
        // Syncing a child also publishes any missing ancestors. Once the
        // directory is durable, only changes to its immediate names matter.
        if (dir.is_empty() || state.committed.entries.get(dir) == Some(&Entry::Directory))
            && directory_entries(&state.entries, dir)
                .eq(directory_entries(&state.committed.entries, dir))
        {
            return state.reclaim_closed_files();
        }
        let mut candidate = state.committed.clone();
        candidate
            .entries
            .retain(|name, _| path::parent(name) != dir);
        for (name, entry) in &state.entries {
            if path::parent(name) == dir {
                candidate.entries.insert(name.clone(), entry.clone());
                if let Entry::File(id) = entry {
                    candidate.files.entry(*id).or_default();
                }
            }
        }
        // Make only the ancestors necessary to reach this synced directory
        // durable, never siblings or unrelated working bindings.
        let mut ancestor = dir;
        while !ancestor.is_empty() {
            candidate
                .entries
                .insert(ancestor.to_owned(), Entry::Directory);
            ancestor = path::parent(ancestor);
        }
        state.commit(candidate)
    }
    fn try_lock(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        let id = state.open_file(name, true)?;
        if !state.locks.insert(id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "volume already attached",
            ));
        }
        Ok(Box::new(CowLock {
            file: self.retain_file(&mut state, id),
        }))
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        let mut state = self.state.lock();
        state.check()?;
        state.reclaim_closed_files()?;
        Ok(Some(state.committed.capacity - state.reserved_pages * PAGE))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn punching_an_already_zero_part_of_a_mapped_page_is_idle() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), 4 * PAGE).unwrap();
        let file = backing.open("file", true).unwrap();
        file.write_at(0, &[1, 0, 2]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        let generation = backing.state.lock().committed.generation;
        file.punch_hole(1, 1).unwrap();
        file.sync_data().unwrap();
        assert_eq!(backing.state.lock().committed.generation, generation);
        file.punch_hole(0, 1).unwrap();
        file.sync_data().unwrap();
        assert_eq!(backing.state.lock().committed.generation, generation + 1);
        let mut bytes = [0; 3];
        file.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0, 0, 2]);
    }

    #[test]
    fn clean_file_and_directory_barriers_leave_the_witness_generation_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), 4 * PAGE).unwrap();
        backing.create_dir_all("data/sub").unwrap();
        let file = backing.open("data/file", true).unwrap();
        file.write_at(0, b"first").unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("data").unwrap();
        let generation = || backing.state.lock().committed.generation;
        let clean = generation();
        for _ in 0..3 {
            file.sync_data().unwrap();
            backing.sync_dir("data").unwrap();
        }
        assert_eq!(generation(), clean);
        file.write_at(0, b"other").unwrap();
        backing.sync_dir("data").unwrap();
        assert_eq!(generation(), clean);
        file.sync_data().unwrap();
        assert_eq!(generation(), clean + 1);
        backing.open("data/sub/pending", true).unwrap();
        backing.sync_dir("data").unwrap();
        assert_eq!(generation(), clean + 1);
        backing.sync_dir("data/sub").unwrap();
        assert_eq!(generation(), clean + 2);
        drop((file, backing));
        let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
        let mut bytes = [0; 5];
        reopened
            .open("data/file", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"other");
        assert!(reopened.exists("data/sub/pending").unwrap());
    }

    #[test]
    fn listing_only_returns_direct_children_of_the_exact_directory() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
        backing.create_dir_all("data/nested").unwrap();
        backing.create_dir_all("database").unwrap();
        backing.open("data/a", true).unwrap();
        backing.open("data/nested/hidden", true).unwrap();
        backing.open("database/other", true).unwrap();
        assert_eq!(backing.list("").unwrap(), ["data", "database"]);
        assert_eq!(backing.list("data").unwrap(), ["a", "nested"]);
        assert_eq!(backing.list("data/nested").unwrap(), ["hidden"]);
    }

    #[test]
    fn retaining_or_extending_file_length_keeps_the_arena_slot_index() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), 2 * PAGE).unwrap();
        let file = backing.open("pages", true).unwrap();
        file.write_at(0, b"x").unwrap();
        assert!(backing.state.lock().used_slots.is_some());
        file.set_len(file.len().unwrap()).unwrap();
        assert!(backing.state.lock().used_slots.is_some());
        file.set_len(PAGE + 1).unwrap();
        assert!(backing.state.lock().used_slots.is_some());
        let mut bytes = [1; 2];
        file.read_at(PAGE - 1, &mut bytes).unwrap();
        assert_eq!(bytes, [0, 0]);
    }

    #[test]
    fn manifest_and_page_domains_have_fixed_vectors() {
        let manifest = Manifest {
            format: 1,
            identity: [1; 16],
            generation: 7,
            capacity: PAGE,
            next_id: 1,
            entries: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let hex = |bytes: [u8; 32]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hex(digest(
                b"maki.rollback.manifest.v1\0",
                &manifest.encode().unwrap()
            )),
            "0895d1def328371d11fb3cdbe0bfde8e4853517d622f272e09bab017428b693c"
        );
        assert_eq!(
            hex(page_digest(&[1; 16], &[2; PAGE as usize])),
            "bf806cddecb545f41adc7c32ba229eb192de25714124390624b5e6ba84505254"
        );
    }

    /// A manifest with a directory, files, mapped pages and reservations.
    /// The empty manifest above holds none of the nested records, and a
    /// manifest re-encoded differently from its stored bytes is refused.
    #[test]
    fn populated_manifest_has_a_fixed_vector() {
        let manifest = Manifest {
            format: 1,
            identity: std::array::from_fn(|i| 17 + i as u8),
            generation: 7,
            capacity: 4 * PAGE,
            next_id: 4,
            entries: BTreeMap::from([
                ("volume.lock".to_string(), Entry::File(3)),
                ("data/shard-00000000.dat".to_string(), Entry::File(1)),
                ("data".to_string(), Entry::Directory),
            ]),
            files: BTreeMap::from([
                (3, Node::default()),
                (
                    1,
                    Node {
                        len: 2 * PAGE + 5,
                        pages: BTreeMap::from([
                            (
                                2,
                                PageRef {
                                    slot: 1,
                                    hash: std::array::from_fn(|i| 192 + i as u8),
                                },
                            ),
                            (
                                0,
                                PageRef {
                                    slot: 5,
                                    hash: std::array::from_fn(|i| 160 + i as u8),
                                },
                            ),
                        ]),
                        reserved: BTreeSet::from([2, 0, 1]),
                    },
                ),
            ]),
        };
        manifest.validate().unwrap();
        let expected = concat!(
            r#"{"format":1,"identity":[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],"#,
            r#""generation":7,"capacity":16384,"next_id":4,"#,
            r#""entries":{"data":"Directory","data/shard-00000000.dat":{"File":1},"#,
            r#""volume.lock":{"File":3}},"#,
            r#""files":{"1":{"len":8197,"pages":{"#,
            r#""0":{"slot":5,"hash":[160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,"#,
            r#"175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191]},"#,
            r#""2":{"slot":1,"hash":[192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,"#,
            r#"207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223]}},"#,
            r#""reserved":[0,1,2]},"#,
            r#""3":{"len":0,"pages":{},"reserved":[]}}}"#,
        );
        let bytes = manifest.encode().unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
        let root: String = digest(b"maki.rollback.manifest.v1\0", &bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            root,
            "022e67a7dccc1684d502bf346987caf4f37c435bb4aa726126b8c0b91cb796da"
        );
        let decoded: Manifest = serde_json::from_str(expected).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    /// The local format marker, and a manifest slot as enrollment writes it:
    /// the manifest's length as a little-endian u64, then the manifest.
    #[test]
    fn local_marker_and_manifest_slot_have_fixed_encodings() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), 2 * PAGE).unwrap();
        let identity = backing.state.lock().committed.identity;
        assert_eq!(
            std::fs::read(root.path().join("rollback.format")).unwrap(),
            b"MAKI-WITNESS-COW-V1\n"
        );
        let identity: Vec<String> = identity.iter().map(u8::to_string).collect();
        let expected = format!(
            concat!(
                r#"{{"format":1,"identity":[{}],"generation":0,"capacity":8192,"#,
                r#""next_id":1,"entries":{{}},"files":{{}}}}"#
            ),
            identity.join(",")
        );
        let slot = std::fs::read(root.path().join("rollback.manifest.0")).unwrap();
        assert_eq!(slot[..8], (expected.len() as u64).to_le_bytes());
        assert_eq!(
            std::str::from_utf8(&slot[8..8 + expected.len()]).unwrap(),
            expected
        );
    }

    struct FailingSync(Arc<dyn BackingFile>);
    impl BackingFile for FailingSync {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.0.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
            self.0.write_at(offset, buf)
        }
        fn set_len(&self, len: u64) -> io::Result<()> {
            self.0.set_len(len)
        }
        fn len(&self) -> io::Result<u64> {
            self.0.len()
        }
        fn sync_data(&self) -> io::Result<()> {
            Err(io::Error::other("injected arena sync failure"))
        }
    }

    #[test]
    fn reopen_reestablishes_physical_reservations_after_sparse_restore() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let capacity = 64 * PAGE;
        let backing = RollbackBacking::create(root.path(), witness.path(), capacity).unwrap();
        let file = backing.open("evidence", true).unwrap();
        file.write_at(0, &[0x42; PAGE as usize]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        let committed_slots = backing.state.lock().committed_slots.clone();
        let anchor = std::fs::read(witness.path().join("anchor")).unwrap();
        drop((file, backing));

        // A sparse copy preserves every byte but loses preallocated extents.
        let disk = FileBacking::new(root.path()).unwrap();
        let arena = disk.open(ARENA, false).unwrap();
        for slot in 0..capacity * 2 / PAGE {
            if !committed_slots.contains(&slot) {
                arena.punch_hole(slot * PAGE, PAGE).unwrap();
            }
        }
        arena.sync_data().unwrap();
        for name in MANIFESTS {
            let file = disk.open(name, false).unwrap();
            let mut header = [0; 8];
            file.read_at(0, &mut header).unwrap();
            let tail = (8 + u64::from_le_bytes(header)).div_ceil(PAGE) * PAGE;
            file.punch_hole(tail, file.len().unwrap() - tail).unwrap();
            file.sync_data().unwrap();
        }
        for name in [ARENA, MANIFESTS[0], MANIFESTS[1]] {
            let metadata = std::fs::metadata(root.path().join(name)).unwrap();
            assert!(
                metadata.blocks() * 512 < metadata.len(),
                "{name} was not sparse"
            );
        }

        let recovered = RollbackBacking::open(root.path(), witness.path()).unwrap();
        for name in [ARENA, MANIFESTS[0], MANIFESTS[1]] {
            let metadata = std::fs::metadata(root.path().join(name)).unwrap();
            assert!(
                metadata.blocks() * 512 >= metadata.len(),
                "{name} remains sparse"
            );
        }
        let mut bytes = [0; PAGE as usize];
        recovered
            .open("evidence", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0x42; PAGE as usize]);
        assert_eq!(
            std::fs::read(witness.path().join("anchor")).unwrap(),
            anchor
        );
    }

    #[test]
    fn reopen_restores_only_the_inactive_manifest_slot() {
        use std::os::unix::fs::MetadataExt;

        for damage in ["missing", "short", "long", "directory"] {
            let root = tempfile::tempdir().unwrap();
            let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
                return;
            };
            let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
            let slot = backing.state.lock().manifest_slot;
            let selected = root.path().join(MANIFESTS[slot]);
            let inactive = root.path().join(MANIFESTS[1 - slot]);
            let evidence = std::fs::read(&selected).unwrap();
            let anchor = std::fs::read(witness.path().join("anchor")).unwrap();
            drop(backing);
            match damage {
                "missing" => std::fs::remove_file(&inactive).unwrap(),
                "directory" => {
                    std::fs::remove_file(&inactive).unwrap();
                    std::fs::create_dir(&inactive).unwrap();
                    // The selected evidence remains usable, but readiness
                    // requires a second reserved slot for the next commit.
                    assert!(RollbackBacking::open(root.path(), witness.path()).is_err());
                    std::fs::remove_dir(&inactive).unwrap();
                }
                _ => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&inactive)
                    .unwrap()
                    .set_len(if damage == "short" {
                        0
                    } else {
                        manifest_bound(PAGE) * 2
                    })
                    .unwrap(),
            }
            let recovered = RollbackBacking::open(root.path(), witness.path()).unwrap();
            let metadata = std::fs::metadata(&inactive).unwrap();
            assert_eq!(metadata.len(), manifest_bound(PAGE), "{damage}");
            assert!(metadata.blocks() * 512 >= metadata.len(), "{damage}");
            assert_eq!(std::fs::read(&selected).unwrap(), evidence, "{damage}");
            assert_eq!(
                std::fs::read(witness.path().join("anchor")).unwrap(),
                anchor,
                "{damage}"
            );
            drop(recovered);
            // A missing selected slot must never be manufactured from scratch.
            std::fs::remove_file(&selected).unwrap();
            assert!(RollbackBacking::open(root.path(), witness.path()).is_err());
            assert!(!selected.exists());
        }
    }

    #[test]
    fn reopen_authenticates_selected_evidence_before_repairing_storage() {
        for damage in ["short_manifest", "long_manifest", "page"] {
            let root = tempfile::tempdir().unwrap();
            let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
                return;
            };
            let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
            let file = backing.open("evidence", true).unwrap();
            file.write_at(0, b"evidence").unwrap();
            file.sync_data().unwrap();
            backing.sync_dir("").unwrap();
            let slot = backing.state.lock().manifest_slot;
            let selected = root.path().join(MANIFESTS[slot]);
            let inactive = root.path().join(MANIFESTS[1 - slot]);
            drop((file, backing));
            std::fs::remove_file(&inactive).unwrap();
            if damage == "page" {
                FileBacking::new(root.path())
                    .unwrap()
                    .open(ARENA, false)
                    .unwrap()
                    .punch_hole(0, PAGE * 2)
                    .unwrap();
            } else {
                let len = manifest_bound(PAGE) + if damage == "long_manifest" { PAGE } else { 0 };
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&selected)
                    .unwrap()
                    .set_len(if damage == "short_manifest" {
                        len - PAGE
                    } else {
                        len
                    })
                    .unwrap();
            }
            let original_len = std::fs::metadata(&selected).unwrap().len();
            assert!(
                RollbackBacking::open(root.path(), witness.path()).is_err(),
                "{damage}"
            );
            assert!(
                !inactive.exists(),
                "{damage} repaired storage before authentication"
            );
            assert_eq!(std::fs::metadata(&selected).unwrap().len(), original_len);
        }
    }

    struct ReservationFaultBacking {
        disk: FileBacking,
        path: &'static str,
        operation: &'static str,
    }

    struct ReservationFaultFile {
        file: Arc<dyn BackingFile>,
        operation: &'static str,
    }

    impl BackingFile for ReservationFaultFile {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.file.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
            self.file.write_at(offset, buf)
        }
        fn set_len(&self, len: u64) -> io::Result<()> {
            self.file.set_len(len)
        }
        fn len(&self) -> io::Result<u64> {
            self.file.len()
        }
        fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
            if self.operation == "allocate" {
                return Err(no_space());
            }
            self.file.allocate_range(offset, len)
        }
        fn sync_data(&self) -> io::Result<()> {
            if self.operation == "sync" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.file.sync_data()
        }
        fn sync_all(&self) -> io::Result<()> {
            if matches!(self.operation, "sync" | "full-sync") {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.file.sync_all()
        }
    }

    impl Backing for ReservationFaultBacking {
        fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
            let file = self.disk.open(name, create)?;
            if name == self.path {
                Ok(Arc::new(ReservationFaultFile {
                    file,
                    operation: self.operation,
                }))
            } else {
                Ok(file)
            }
        }
        fn exists(&self, name: &str) -> io::Result<bool> {
            self.disk.exists(name)
        }
        fn remove(&self, name: &str) -> io::Result<()> {
            self.disk.remove(name)
        }
        fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            self.disk.rename(from, to)
        }
        fn create_dir_all(&self, name: &str) -> io::Result<()> {
            self.disk.create_dir_all(name)
        }
        fn list(&self, dir: &str) -> io::Result<Vec<String>> {
            self.disk.list(dir)
        }
        fn try_lock(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
            self.disk.try_lock(name)
        }
        fn sync_dir(&self, dir: &str) -> io::Result<()> {
            if self.path.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.disk.sync_dir(dir)
        }
    }

    #[test]
    fn storage_reservation_propagates_allocation_and_sync_failures() {
        for path in [ARENA, MANIFESTS[0], MANIFESTS[1], ""] {
            for operation in ["allocate", "sync"] {
                let root = tempfile::tempdir().unwrap();
                let disk = ReservationFaultBacking {
                    disk: FileBacking::new(root.path()).unwrap(),
                    path,
                    operation,
                };
                let arena = disk.open(ARENA, true).unwrap();
                let error = reserve_storage(&disk, arena.as_ref(), PAGE).unwrap_err();
                assert_eq!(
                    error.raw_os_error(),
                    Some(if operation == "allocate" && !path.is_empty() {
                        libc::ENOSPC
                    } else {
                        libc::EIO
                    }),
                    "{path} {operation}"
                );
                // Retrying with storage healthy completes the whole footprint.
                let arena = disk.disk.open(ARENA, false).unwrap();
                reserve_storage(&disk.disk, arena.as_ref(), PAGE).unwrap();
                assert_eq!(arena.len().unwrap(), 2 * PAGE);
                for name in MANIFESTS {
                    assert_eq!(
                        disk.disk.open(name, false).unwrap().len().unwrap(),
                        manifest_bound(PAGE)
                    );
                }
            }
        }
    }

    #[test]
    fn review_f09_physical_rollback_reservations_require_full_file_barriers() {
        for path in [ARENA, MANIFESTS[0], MANIFESTS[1]] {
            let root = tempfile::tempdir().unwrap();
            let disk = ReservationFaultBacking {
                disk: FileBacking::new(root.path()).unwrap(),
                path,
                operation: "full-sync",
            };
            let healthy_arena = disk.disk.open(ARENA, true).unwrap();
            // Establish a durable EOF first: retrying allocation within that
            // length must still require the distinct metadata barrier.
            reserve_storage(&disk.disk, healthy_arena.as_ref(), PAGE).unwrap();
            let arena = disk.open(ARENA, false).unwrap();
            let error = reserve_storage(&disk, arena.as_ref(), PAGE)
                .expect_err("fdatasync cannot substitute for the allocation fsync");
            assert_eq!(error.raw_os_error(), Some(libc::EIO), "{path}");
        }
    }

    #[test]
    fn creation_reclaims_closed_identities_at_the_limit() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
        for _ in 0..MAX_ENTRIES {
            let file = backing.open("temporary", true).unwrap();
            backing.remove("temporary").unwrap();
            drop(file);
        }
        assert!(backing.list("").unwrap().is_empty());
        let replacement = backing.open("replacement", true).unwrap();
        replacement.write_at(0, b"new").unwrap();
        replacement.sync_data().unwrap();
        // Reclamation must not publish this newly created name.
        drop((replacement, backing));
        let backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
        assert!(backing.list("").unwrap().is_empty());
    }

    #[test]
    fn creation_preserves_live_handles_and_pending_unlinks_at_the_limit() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
        let durable = backing.open("durable", true).unwrap();
        durable.write_at(0, b"old").unwrap();
        durable.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        backing.remove("durable").unwrap();
        drop(durable);
        let mut handles = Vec::new();
        for _ in 1..MAX_ENTRIES {
            handles.push(backing.open("temporary", true).unwrap());
            backing.remove("temporary").unwrap();
        }
        assert_eq!(
            backing
                .open("replacement", true)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOSPC)
        );
        // One final close makes exactly one identity reusable.
        handles.pop();
        let replacement = backing.open("replacement", true).unwrap();
        for handle in &handles {
            assert_eq!(handle.len().unwrap(), 0);
        }
        assert_eq!(backing.state.lock().files.len(), MAX_ENTRIES);
        drop((replacement, handles, backing));
        let backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
        let mut bytes = [0; 3];
        backing
            .open("durable", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"old");
        assert!(!backing.exists("replacement").unwrap());
    }

    #[test]
    fn persistence_failures_preserve_previous_root_and_stop_all_handles() {
        for boundary in ["arena", "manifest", "witness"] {
            let root = tempfile::tempdir().unwrap();
            let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
                return;
            };
            let backing = RollbackBacking::create(root.path(), witness.path(), 64 * PAGE).unwrap();
            let file = backing.open("a", true).unwrap();
            file.write_at(0, b"old").unwrap();
            file.sync_data().unwrap();
            backing.sync_dir("").unwrap();
            file.write_at(0, b"new").unwrap();
            let blocker = match boundary {
                "arena" => {
                    let mut state = backing.state.lock();
                    state.arena = Arc::new(FailingSync(state.arena.clone()));
                    None
                }
                "manifest" => {
                    let state = backing.state.lock();
                    let path = root.path().join(MANIFESTS[1 - state.manifest_slot]);
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                    Some(path)
                }
                "witness" => {
                    let path = witness.path().join("anchor.next");
                    std::fs::create_dir(&path).unwrap();
                    Some(path)
                }
                _ => unreachable!(),
            };
            assert!(file.sync_data().is_err(), "{boundary}");
            assert!(file.read_at(0, &mut [0; 3]).is_err(), "{boundary}");
            assert!(backing.check_freshness().is_err(), "{boundary}");
            assert!(file.write_at(0, b"bad").is_err(), "{boundary}");
            let stopped = backing.session_stopped().expect(boundary);
            assert!(
                stopped.starts_with("rollback session stopped: manifest commit failed: "),
                "{boundary}: {stopped}"
            );
            drop((file, backing));
            if let Some(path) = blocker {
                std::fs::remove_dir(path).unwrap();
            }
            let recovered = RollbackBacking::open(root.path(), witness.path()).unwrap();
            let mut bytes = [0; 3];
            recovered
                .open("a", false)
                .unwrap()
                .read_at(0, &mut bytes)
                .unwrap();
            assert_eq!(&bytes, b"old", "{boundary}");
        }
    }

    #[test]
    fn reclamation_failures_preserve_witnessed_pages_until_retry() {
        for trigger in ["free_bytes", "reservation", "creation"] {
            for boundary in ["arena", "manifest", "witness"] {
                let root = tempfile::tempdir().unwrap();
                let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
                    return;
                };
                let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
                let old = backing.open("old", true).unwrap();
                old.write_at(0, &[0x44; PAGE as usize]).unwrap();
                old.sync_data().unwrap();
                backing.sync_dir("").unwrap();
                backing.remove("old").unwrap();
                backing.sync_dir("").unwrap();
                drop(old);

                if trigger == "creation" {
                    for _ in 1..MAX_ENTRIES {
                        let file = backing.open("temporary", true).unwrap();
                        backing.remove("temporary").unwrap();
                        drop(file);
                    }
                }

                let (old_id, committed, coordinates) = {
                    let state = backing.state.lock();
                    let old_id = *state.committed.files.keys().next().unwrap();
                    (
                        old_id,
                        state.committed.encode().unwrap(),
                        state.coordinates(),
                    )
                };
                let mut original_arena = None;
                let mut blocker = None;
                let mut saved_manifest = None;
                match boundary {
                    "arena" => {
                        let mut state = backing.state.lock();
                        let arena = state.arena.clone();
                        state.arena = Arc::new(FailingSync(arena.clone()));
                        original_arena = Some(arena);
                    }
                    "manifest" => {
                        let state = backing.state.lock();
                        let path = root.path().join(MANIFESTS[1 - state.manifest_slot]);
                        drop(state);
                        let saved = root.path().join("rollback.manifest.saved");
                        std::fs::rename(&path, &saved).unwrap();
                        std::fs::create_dir(&path).unwrap();
                        blocker = Some(path);
                        saved_manifest = Some(saved);
                    }
                    "witness" => {
                        let path = witness.path().join("anchor.next");
                        std::fs::create_dir(&path).unwrap();
                        blocker = Some(path);
                    }
                    _ => unreachable!(),
                }

                let replacement =
                    (trigger == "reservation").then(|| backing.open("replacement", true).unwrap());
                let result = match &replacement {
                    Some(file) => file.allocate_range(0, PAGE),
                    None if trigger == "creation" => backing.open("replacement", true).map(|_| ()),
                    None => backing.free_bytes().map(|_| ()),
                };
                assert!(
                    result.is_err(),
                    "{trigger} unexpectedly survived {boundary}"
                );
                assert!(
                    backing.check_freshness().is_err(),
                    "{trigger} did not poison the session at {boundary}"
                );
                let stopped = backing.session_stopped();
                assert!(
                    stopped.as_deref().is_some_and(|reason| reason
                        .starts_with("rollback session stopped: manifest commit failed: ")),
                    "{trigger} {boundary}: {stopped:?}"
                );
                {
                    let state = backing.state.lock();
                    assert!(state.poisoned, "{trigger} {boundary}");
                    assert_eq!(
                        state.committed.encode().unwrap(),
                        committed,
                        "{trigger} {boundary}"
                    );
                    assert_eq!(state.coordinates(), coordinates, "{trigger} {boundary}");
                    assert!(state.files.contains_key(&old_id), "{trigger} {boundary}");
                }

                if let Some(arena) = original_arena {
                    backing.state.lock().arena = arena;
                }
                if let Some(path) = blocker {
                    std::fs::remove_dir(&path).unwrap();
                    if let Some(saved) = saved_manifest {
                        std::fs::rename(saved, path).unwrap();
                    }
                }
                drop((replacement, backing));

                let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
                assert_eq!(
                    reopened.state.lock().committed.encode().unwrap(),
                    committed,
                    "{trigger} {boundary} reopened a different root"
                );
                assert_eq!(reopened.session_stopped(), None, "{trigger} {boundary}");
                assert_eq!(reopened.free_bytes().unwrap(), Some(PAGE));
                let replacement = reopened.open("replacement", true).unwrap();
                replacement.write_at(0, &[0x55; PAGE as usize]).unwrap();
                replacement.sync_data().unwrap();
                reopened.sync_dir("").unwrap();
                drop((replacement, reopened));

                let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
                let replacement = reopened.open("replacement", false).unwrap();
                let mut bytes = vec![0; PAGE as usize];
                replacement.read_at(0, &mut bytes).unwrap();
                assert_eq!(bytes, vec![0x55; PAGE as usize], "{trigger} {boundary}");
            }
        }
    }

    #[test]
    fn uncommitted_overwrites_and_truncation_cannot_destroy_previous_pages() {
        let root = tempfile::tempdir().unwrap();
        let Some(witness) = crate::other_filesystem::tempdir(root.path()) else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), 2 * PAGE).unwrap();
        let file = backing.open("a", true).unwrap();
        file.write_at(0, &[0x42; 8192]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        for _ in 0..8 {
            file.write_at(0, &[0x24; 8192]).unwrap();
            file.set_len(1024).unwrap();
            file.set_len(8192).unwrap();
            let mut tail = [0xff; 7168];
            file.read_at(1024, &mut tail).unwrap();
            assert_eq!(tail, [0; 7168]);
        }
        drop((file, backing));
        let recovered = RollbackBacking::open(root.path(), witness.path()).unwrap();
        let mut bytes = [0; 8192];
        recovered
            .open("a", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0x42; 8192]);
    }
}
