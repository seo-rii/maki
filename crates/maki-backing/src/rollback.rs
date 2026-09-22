//! Opt-in, bounded copy-on-write backing with an independent local witness.
//!
//! The arena and both manifest slots are physically reserved at enrollment.
//! A manifest authenticates the entire namespace and every referenced page.
//! Only the independent witness selects a recoverable manifest. Unsynced
//! bytes remain in a separately authenticated, process-local working view.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::witness::FileWitness;
use crate::{path, Backing, BackingFile, FileBacking, VolumeLock};

const PAGE: u64 = 4096;
const MAX_CAPACITY: u64 = 1 << 30;
const MAX_ENTRIES: usize = 4096;
const MARKER: &str = "rollback.format";
const MAGIC: &[u8] = b"MAKI-WITNESS-COW-V1\n";
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
    slot: u64,
    hash: [u8; 32],
}

#[derive(Clone, Default, Serialize, Deserialize)]
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
}

struct State {
    disk: FileBacking,
    arena: Arc<dyn BackingFile>,
    witness: FileWitness,
    _disk_lock: Box<dyn VolumeLock>,
    committed: Manifest,
    manifest_slot: usize,
    entries: BTreeMap<String, Entry>,
    files: BTreeMap<u64, Node>,
    handles: BTreeMap<u64, usize>,
    next_id: u64,
    locks: BTreeSet<String>,
    poisoned: bool,
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
    /// Enroll an empty backing and a previously unused independent witness.
    /// Interrupted enrollment is deliberately not resumed implicitly.
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
        let disk_lock = disk.try_lock("rollback.lock")?;
        if disk.list("")?.iter().any(|name| name != "rollback.lock")
            || !witness_dir.list("")?.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "rollback enrollment requires empty backing and witness directories",
            ));
        }
        let marker = disk.open(MARKER, true)?;
        marker.write_at(0, MAGIC)?;
        marker.sync_data()?;
        disk.sync_dir("")?;
        let arena = disk.open(ARENA, true)?;
        arena.allocate_range(0, capacity_bytes * 2)?;
        arena.sync_data()?;
        for name in MANIFESTS {
            let file = disk.open(name, true)?;
            file.allocate_range(0, manifest_bound(capacity_bytes))?;
            file.sync_data()?;
        }
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
        write_manifest(&disk, 0, &bytes)?;
        disk.sync_dir("")?;
        let witness = FileWitness::create(
            witness,
            manifest.identity,
            digest(b"maki.rollback.manifest.v1\0", &bytes),
        )?;
        Ok(Self::assemble(disk, arena, witness, disk_lock, manifest, 0))
    }

    /// Open only the exact manifest selected by the existing witness.
    pub fn open(root: &Path, witness: &Path) -> io::Result<Self> {
        independent_paths(root, witness)?;
        let disk = FileBacking::new(root)?;
        let disk_lock = disk.try_lock("rollback.lock")?;
        let marker = disk.open(MARKER, false)?;
        let mut magic = vec![0; MAGIC.len()];
        if marker.len()? != MAGIC.len() as u64 {
            return Err(invalid("invalid rollback format marker"));
        }
        marker.read_at(0, &mut magic)?;
        if magic != MAGIC {
            return Err(invalid("unsupported rollback format"));
        }
        let witness = FileWitness::open(witness)?;
        let anchor = witness.anchor();
        let mut selected = None;
        for (slot, name) in MANIFESTS.iter().enumerate() {
            let candidate = (|| {
                let file = disk.open(name, false)?;
                let mut header = [0; 8];
                file.read_at(0, &mut header)?;
                let len = u64::from_le_bytes(header);
                if len == 0 || len > manifest_bound(MAX_CAPACITY) - 8 {
                    return Err(invalid("invalid rollback manifest length"));
                }
                let mut bytes = vec![0; len as usize];
                file.read_at(8, &mut bytes)?;
                if digest(b"maki.rollback.manifest.v1\0", &bytes) != anchor.root {
                    return Err(invalid("manifest does not match independent witness"));
                }
                let manifest: Manifest =
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                manifest.validate()?;
                if manifest.encode()? != bytes
                    || manifest.identity != anchor.identity
                    || manifest.generation != anchor.generation
                    || file.len()? != manifest_bound(manifest.capacity)
                {
                    return Err(invalid("noncanonical or foreign rollback manifest"));
                }
                Ok(manifest)
            })();
            if let Ok(manifest) = candidate {
                selected = Some((slot, manifest));
                break;
            }
        }
        let (slot, manifest) = selected.ok_or_else(|| {
            invalid("no exact witnessed manifest: backing may be rolled back or incomplete")
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
        Ok(Self::assemble(
            disk, arena, witness, disk_lock, manifest, slot,
        ))
    }

    fn assemble(
        disk: FileBacking,
        arena: Arc<dyn BackingFile>,
        witness: FileWitness,
        disk_lock: Box<dyn VolumeLock>,
        manifest: Manifest,
        slot: usize,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                entries: manifest.entries.clone(),
                files: manifest.files.clone(),
                next_id: manifest.next_id,
                committed: manifest,
                manifest_slot: slot,
                disk,
                arena,
                witness,
                _disk_lock: disk_lock,
                handles: BTreeMap::new(),
                locks: BTreeSet::new(),
                poisoned: false,
            })),
        }
    }
}

fn write_manifest(disk: &FileBacking, slot: usize, bytes: &[u8]) -> io::Result<()> {
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
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn directory(&self, name: &str) -> io::Result<()> {
        if name.is_empty() || self.entries.get(name) == Some(&Entry::Directory) {
            Ok(())
        } else {
            Err(missing())
        }
    }

    fn coordinates(&self) -> BTreeSet<(u64, u64)> {
        self.committed
            .files
            .iter()
            .chain(self.files.iter())
            .flat_map(|(id, node)| node.reserved.iter().map(move |index| (*id, *index)))
            .collect()
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
        retain.extend(self.handles.keys());
        candidate.files.retain(|id, _| retain.contains(id));
        candidate.validate()?;
        let bytes = candidate.encode()?;
        let slot = 1 - self.manifest_slot;
        let result = (|| {
            self.arena.sync_data()?;
            write_manifest(&self.disk, slot, &bytes)?;
            self.witness
                .advance(digest(b"maki.rollback.manifest.v1\0", &bytes))
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.committed = candidate;
        self.manifest_slot = slot;
        self.files.retain(|id, _| retain.contains(id));
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
        let mut coordinates = self.coordinates();
        coordinates.extend(range.clone().map(|index| (id, index)));
        if coordinates.len() as u64 > self.committed.capacity / PAGE {
            return Err(no_space());
        }
        let mut candidate = self.committed.clone();
        let durable = candidate.files.entry(id).or_default();
        let changed = range
            .clone()
            .any(|index| !durable.reserved.contains(&index));
        if changed {
            durable.reserved.extend(range.clone());
            // Allocation itself may persist EOF, but never unsynced bytes.
            durable.len = durable.len.max(end);
            self.commit(candidate)?;
        }
        let node = self.files.get_mut(&id).ok_or_else(missing)?;
        node.reserved.extend(range);
        node.len = node.len.max(end);
        Ok(())
    }

    fn page(&mut self, node: &Node, index: u64) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; PAGE as usize];
        if let Some(page) = node.pages.get(&index) {
            if let Err(error) = self.arena.read_at(page.slot * PAGE, &mut bytes) {
                self.poisoned = true;
                return Err(error);
            }
            if page_digest(&self.committed.identity, &bytes) != page.hash {
                self.poisoned = true;
                return Err(invalid("rollback arena page authentication failed"));
            }
        }
        Ok(bytes)
    }

    fn write_page(&mut self, id: u64, index: u64, bytes: &[u8]) -> io::Result<()> {
        let committed: BTreeSet<u64> = self
            .committed
            .files
            .values()
            .flat_map(|node| node.pages.values().map(|page| page.slot))
            .collect();
        let current = self.files[&id].pages.get(&index).map(|page| page.slot);
        let slot = if let Some(slot) = current.filter(|slot| !committed.contains(slot)) {
            slot
        } else {
            let mut used = committed;
            used.extend(
                self.files
                    .values()
                    .flat_map(|node| node.pages.values().map(|page| page.slot)),
            );
            (0..2 * self.committed.capacity / PAGE)
                .find(|slot| !used.contains(slot))
                .ok_or_else(|| invalid("rollback arena reservation invariant violated"))?
        };
        if let Err(error) = self.arena.write_at(slot * PAGE, bytes) {
            self.poisoned = true;
            return Err(error);
        }
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
        let node = state.files.get(&self.id).ok_or_else(missing)?.clone();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| input("read overflow"))?;
        if end > node.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond rollback file",
            ));
        }
        let mut at = offset;
        while at < end {
            let bytes = state.page(&node, at / PAGE)?;
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
        while at < end {
            let node = state.files[&self.id].clone();
            let mut bytes = state.page(&node, at / PAGE)?;
            let count = (PAGE - at % PAGE).min(end - at) as usize;
            let start = (at % PAGE) as usize;
            let src = (at - offset) as usize;
            bytes[start..start + count].copy_from_slice(&data[src..src + count]);
            state.write_page(self.id, at / PAGE, &bytes)?;
            at += count as u64;
        }
        Ok(())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        let node = state.files[&self.id].clone();
        if len < node.len && !len.is_multiple_of(PAGE) && node.pages.contains_key(&(len / PAGE)) {
            let mut bytes = state.page(&node, len / PAGE)?;
            bytes[(len % PAGE) as usize..].fill(0);
            state.write_page(self.id, len / PAGE, &bytes)?;
        }
        let node = state.files.get_mut(&self.id).ok_or_else(missing)?;
        node.len = len;
        node.pages.retain(|index, _| *index < len.div_ceil(PAGE));
        node.reserved.retain(|index| *index < len.div_ceil(PAGE));
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
        let node = state.files[&self.id].clone();
        let end = offset
            .checked_add(len)
            .ok_or_else(|| input("hole range overflow"))?
            .min(node.len);
        let mut at = offset;
        while at < end {
            let count = (PAGE - at % PAGE).min(end - at);
            if at.is_multiple_of(PAGE) && count == PAGE {
                let node = state.files.get_mut(&self.id).ok_or_else(missing)?;
                node.pages.remove(&(at / PAGE));
                node.reserved.remove(&(at / PAGE));
            } else if node.pages.contains_key(&(at / PAGE)) {
                let mut bytes = state.page(&node, at / PAGE)?;
                bytes[(at % PAGE) as usize..(at % PAGE + count) as usize].fill(0);
                state.write_page(self.id, at / PAGE, &bytes)?;
            }
            at += count;
        }
        Ok(())
    }
    fn len(&self) -> io::Result<u64> {
        let mut state = self.state.lock();
        state.check()?;
        Ok(state.files.get(&self.id).ok_or_else(missing)?.len)
    }
    fn sync_data(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        state.check()?;
        let mut candidate = state.committed.clone();
        candidate.files.insert(
            self.id,
            state.files.get(&self.id).ok_or_else(missing)?.clone(),
        );
        state.commit(candidate)
    }
}

struct CowLock {
    state: Arc<Mutex<State>>,
    path: String,
}
impl VolumeLock for CowLock {}
impl Drop for CowLock {
    fn drop(&mut self) {
        self.state.lock().locks.remove(&self.path);
    }
}

impl Backing for RollbackBacking {
    fn check_freshness(&self) -> io::Result<()> {
        self.state.lock().check()
    }
    fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(path::parent(name))?;
        let id = match state.entries.get(name) {
            Some(Entry::File(id)) => *id,
            Some(Entry::Directory) => return Err(input("cannot open a directory as a file")),
            None if create => {
                if state.entries.len() >= MAX_ENTRIES || state.files.len() >= MAX_ENTRIES {
                    return Err(no_space());
                }
                let id = state.next_id;
                state.next_id = id
                    .checked_add(1)
                    .ok_or_else(|| invalid("file identity exhausted"))?;
                state.files.insert(id, Node::default());
                state.entries.insert(name.to_owned(), Entry::File(id));
                id
            }
            None => return Err(missing()),
        };
        *state.handles.entry(id).or_default() += 1;
        Ok(Arc::new(CowFile {
            state: self.state.clone(),
            id,
        }))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        Ok(state.entries.contains_key(name))
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        validate_name(name, false)?;
        let mut state = self.state.lock();
        state.check()?;
        if state.entries.get(name) == Some(&Entry::Directory) {
            return Err(input("directory removal is unsupported"));
        }
        state.entries.remove(name).ok_or_else(missing)?;
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        validate_name(from, false)?;
        validate_name(to, false)?;
        let mut state = self.state.lock();
        state.check()?;
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
        state.entries.insert(to.to_owned(), entry);
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
                Some(Entry::File(_)) => return Err(input("parent is a file")),
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
        Ok(state
            .entries
            .keys()
            .filter(|name| path::parent(name) == dir)
            .map(|name| path::file_name(name).to_owned())
            .collect())
    }
    fn sync_dir(&self, dir: &str) -> io::Result<()> {
        validate_name(dir, true)?;
        let mut state = self.state.lock();
        state.check()?;
        state.directory(dir)?;
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
        if !state.locks.insert(name.to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "volume already attached",
            ));
        }
        Ok(Box::new(CowLock {
            state: self.state.clone(),
            path: name.to_owned(),
        }))
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        let mut state = self.state.lock();
        state.check()?;
        Ok(Some(
            state.committed.capacity - state.coordinates().len() as u64 * PAGE,
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

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
    fn persistence_failures_preserve_previous_root_and_stop_all_handles() {
        for boundary in ["arena", "manifest", "witness"] {
            let root = tempfile::tempdir().unwrap();
            let witness = tempfile::tempdir_in("/dev/shm").unwrap();
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
    fn uncommitted_overwrites_and_truncation_cannot_destroy_previous_pages() {
        let root = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir_in("/dev/shm").unwrap();
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
