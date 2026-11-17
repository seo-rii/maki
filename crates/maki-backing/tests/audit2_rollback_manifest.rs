//! audit2 (decoder-fuzz): digest-VALID, structure-aware mutation of the
//! local rollback manifest (`rollback.manifest.{0,1}`), the arena page
//! references it authenticates, and the format marker.
//!
//! The manifest is pinned by the independent witness (SHA-256 of its exact
//! bytes), so random bytes never reach the JSON decoder or `validate`. Here
//! every mutated manifest is re-serialized canonically through a field-for-
//! field mirror of the private `Manifest` (identical serde output, checked
//! against the module's golden vector) and the witness anchor is rewritten
//! to its digest and generation, so `RollbackBacking::open` reaches the
//! JSON decoder, `Manifest::validate`, the canonical-bytes check, page
//! authentication and the post-open API. Properties:
//!   * open never panics and never hangs;
//!   * an accepted backing survives a bounded tour of its API (list, open,
//!     read, write, set_len, punch_hole, sync, free_bytes) without panic,
//!     `free_bytes` never exceeds the capacity, and a reopen still succeeds;
//!   * open's peak allocation is bounded (counting allocator).

#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use maki_backing::{Backing, RollbackBacking};

// ---------------------------------------------------------------- allocator

struct Counting;
thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}
fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as isize));
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(start));
    let out = f();
    let peak = PEAK.with(|p| p.get());
    (out, (peak - start).max(0) as usize)
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

// ---------------------------------------------------------------- mirror

const PAGE: u64 = 4096;
const MANIFESTS: [&str; 2] = ["rollback.manifest.0", "rollback.manifest.1"];
const MANIFEST_DOMAIN: &[u8] = b"maki.rollback.manifest.v1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
    slot: u64,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    len: u64,
    pages: BTreeMap<u64, PageRef>,
    reserved: BTreeSet<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Entry {
    Directory,
    File(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

fn page_digest(identity: &[u8; 16], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"maki.rollback.page.v1\0");
    h.update(identity);
    h.update(bytes);
    h.finalize().into()
}

fn manifest_bound(capacity: u64) -> u64 {
    (8 << 20) + capacity / PAGE * 256
}

fn hex(b: [u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn mirror_matches_the_module_golden_vector() {
    let m = Manifest {
        format: 1,
        identity: [1; 16],
        generation: 7,
        capacity: PAGE,
        next_id: 1,
        entries: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    assert_eq!(
        hex(digest(MANIFEST_DOMAIN, &serde_json::to_vec(&m).unwrap())),
        "0895d1def328371d11fb3cdbe0bfde8e4853517d622f272e09bab017428b693c"
    );
}

// ---------------------------------------------------------------- witness anchor

fn anchor_bytes(identity: [u8; 16], generation: u64, root: [u8; 32]) -> Vec<u8> {
    let mut b = vec![0u8; 104];
    b[..8].copy_from_slice(b"MAKIWIT1");
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[16..32].copy_from_slice(&identity);
    b[32..40].copy_from_slice(&generation.to_le_bytes());
    b[40..72].copy_from_slice(&root);
    let sum = digest(b"maki-file-witness-anchor-v1\0", &b[..72]);
    b[72..].copy_from_slice(&sum);
    b
}

fn read_anchor(witness: &Path) -> (u64, [u8; 32]) {
    let b = std::fs::read(witness.join("anchor")).unwrap();
    (
        u64::from_le_bytes(b[32..40].try_into().unwrap()),
        b[40..72].try_into().unwrap(),
    )
}

// ---------------------------------------------------------------- fixture

struct Fixture {
    root: tempfile::TempDir,
    witness: tempfile::TempDir,
    base_files: BTreeMap<String, Vec<u8>>,
    base_anchor: Vec<u8>,
    selected: usize,
    manifest: Manifest,
}

const CAPACITY: u64 = 64 * PAGE;

impl Fixture {
    fn new() -> Self {
        // Root on tmpfs (cheap fallocate/fsync), witness on the root fs:
        // RollbackBacking requires different filesystems.
        let root = tempfile::tempdir_in("/dev/shm").unwrap();
        let witness = tempfile::tempdir().unwrap();
        {
            let b = RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap();
            b.create_dir_all("d/e").unwrap();
            let a = b.open("a", true).unwrap();
            a.write_at(0, &vec![0xa1; 3 * PAGE as usize]).unwrap();
            a.sync_data().unwrap();
            let f = b.open("d/b", true).unwrap();
            f.write_at(100, &vec![0xb2; 10_000]).unwrap();
            f.sync_data().unwrap();
            let c = b.open("d/e/c", true).unwrap();
            c.allocate_range(0, 2 * PAGE).unwrap();
            c.write_at(PAGE, b"cee").unwrap();
            c.sync_data().unwrap();
            b.sync_dir("d/e").unwrap();
            b.sync_dir("d").unwrap();
            b.sync_dir("").unwrap();
            // A second generation of "a".
            a.write_at(PAGE, &vec![0xa2; 10]).unwrap();
            a.sync_data().unwrap();
        }
        let mut base_files = BTreeMap::new();
        for entry in std::fs::read_dir(root.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if name.ends_with(".lock") {
                continue;
            }
            base_files.insert(name, std::fs::read(entry.path()).unwrap());
        }
        let base_anchor = std::fs::read(witness.path().join("anchor")).unwrap();
        let (_, anchor_root) = read_anchor(witness.path());
        let mut selected = None;
        for (slot, name) in MANIFESTS.iter().enumerate() {
            let bytes = &base_files[*name];
            let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
            if len > 0 && 8 + len <= bytes.len() && digest(MANIFEST_DOMAIN, &bytes[8..8 + len]) == anchor_root {
                selected = Some(slot);
            }
        }
        let selected = selected.expect("one manifest slot matches the witness");
        let bytes = &base_files[MANIFESTS[selected]];
        let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        let manifest: Manifest = serde_json::from_slice(&bytes[8..8 + len]).unwrap();
        assert_eq!(
            serde_json::to_vec(&manifest).unwrap(),
            &bytes[8..8 + len],
            "mirror re-encodes the real manifest exactly"
        );
        Self {
            root,
            witness,
            base_files,
            base_anchor,
            selected,
            manifest,
        }
    }

    fn restore(&self) {
        for entry in std::fs::read_dir(self.root.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if !name.ends_with(".lock") && !self.base_files.contains_key(&name) {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
        for (name, bytes) in &self.base_files {
            std::fs::write(self.root.path().join(name), bytes).unwrap();
        }
        let _ = std::fs::remove_file(self.witness.path().join("anchor.next"));
        std::fs::write(self.witness.path().join("anchor"), &self.base_anchor).unwrap();
    }

    fn arena(&self) -> &[u8] {
        &self.base_files["rollback.arena"]
    }

    /// Install `manifest` as the witnessed manifest in the selected slot.
    fn install(&self, manifest: &Manifest, file_capacity: u64, rehash: bool, arena_capacity: u64) -> Vec<u8> {
        let mut manifest = manifest.clone();
        if rehash {
            let arena = self.arena();
            for node in manifest.files.values_mut() {
                for page in node.pages.values_mut() {
                    let at = page.slot.saturating_mul(PAGE) as usize;
                    if at < arena.len() && at + PAGE as usize <= arena.len() {
                        page.hash = page_digest(&manifest.identity, &arena[at..at + PAGE as usize]);
                    }
                }
            }
        }
        let body = serde_json::to_vec(&manifest).unwrap();
        let path = self.root.path().join(MANIFESTS[self.selected]);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(manifest_bound(file_capacity)).unwrap();
        use std::os::unix::fs::FileExt;
        file.write_all_at(&(body.len() as u64).to_le_bytes(), 0).unwrap();
        file.write_all_at(&body, 8).unwrap();
        if arena_capacity != CAPACITY {
            let arena = std::fs::OpenOptions::new()
                .write(true)
                .open(self.root.path().join("rollback.arena"))
                .unwrap();
            arena.set_len(arena_capacity * 2).unwrap();
        }
        let generation = manifest.generation.min(i64::MAX as u64);
        std::fs::write(
            self.witness.path().join("anchor"),
            anchor_bytes(manifest.identity, generation, digest(MANIFEST_DOMAIN, &body)),
        )
        .unwrap();
        body
    }
}

// ---------------------------------------------------------------- mutation

fn interesting_u64(rng: &mut StdRng, current: u64) -> u64 {
    match rng.random_range(0..13u32) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => u64::MAX - 1,
        4 => i64::MAX as u64,
        5 => current.wrapping_add(1),
        6 => current.wrapping_sub(1),
        7 => current.wrapping_add(PAGE),
        8 => (u64::MAX - PAGE) / PAGE,
        9 => (u64::MAX - PAGE) / PAGE + 1,
        10 => rng.random_range(0..200),
        11 => 1 << rng.random_range(0..64),
        _ => rng.random(),
    }
}

fn mutate(rng: &mut StdRng, m: &mut Manifest) -> String {
    let ids: Vec<u64> = m.files.keys().copied().collect();
    let names: Vec<String> = m.entries.keys().cloned().collect();
    match rng.random_range(0..20u32) {
        0 => {
            m.format = [0, 2, u32::MAX][rng.random_range(0..3)];
            format!("format {}", m.format)
        }
        1 => {
            m.identity = if rng.random_bool(0.5) { [0; 16] } else { [rng.random(); 16] };
            "identity".into()
        }
        2 => {
            m.generation = interesting_u64(rng, m.generation);
            format!("generation {}", m.generation)
        }
        3 => {
            m.capacity = [0, PAGE, CAPACITY / 2, CAPACITY - PAGE, CAPACITY + PAGE, 1 << 30, (1 << 30) + PAGE, 4097, u64::MAX]
                [rng.random_range(0..9)];
            format!("capacity {}", m.capacity)
        }
        4 => {
            m.next_id = interesting_u64(rng, m.next_id);
            format!("next_id {}", m.next_id)
        }
        5 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            node.len = interesting_u64(rng, node.len);
            format!("file {id} len {}", node.len)
        }
        6 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            let index = interesting_u64(rng, 3);
            node.reserved.insert(index);
            format!("file {id} reserve index {index}")
        }
        7 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            let k = node.reserved.iter().next().copied();
            if let Some(k) = k {
                node.reserved.remove(&k);
            }
            format!("file {id} unreserve {k:?}")
        }
        8 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            if let Some((_, page)) = node.pages.iter_mut().next() {
                page.slot = interesting_u64(rng, page.slot) % 512;
            }
            format!("file {id} page slot moved")
        }
        9 if !ids.is_empty() => {
            // Alias: two pages, one slot.
            let a = ids[0];
            let b = ids[ids.len() - 1];
            let slot = m.files[&a].pages.values().next().map(|p| p.slot);
            if let Some(slot) = slot {
                let node = m.files.get_mut(&b).unwrap();
                node.len = node.len.max(9 * PAGE);
                node.reserved.insert(8);
                node.pages.insert(8, PageRef { slot, hash: [0; 32] });
            }
            format!("alias slot {slot:?} into file {b}")
        }
        10 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            let index = interesting_u64(rng, 1);
            node.pages.insert(index, PageRef { slot: rng.random_range(0..128), hash: [0; 32] });
            node.reserved.insert(index);
            format!("file {id} page at index {index}")
        }
        11 => {
            let n = rng.random_range(1..6000);
            for i in 0..n {
                m.entries.insert(format!("x{i}"), Entry::Directory);
            }
            format!("{n} extra directories")
        }
        12 => {
            let id = interesting_u64(rng, m.next_id);
            m.files.insert(id, Node::default());
            format!("orphan file id {id}")
        }
        13 if !names.is_empty() => {
            let name = names[rng.random_range(0..names.len())].clone();
            let e = m.entries.remove(&name).unwrap();
            let new = match rng.random_range(0..8u32) {
                0 => "".to_string(),
                1 => "/abs".to_string(),
                2 => format!("{name}/"),
                3 => format!("../{name}"),
                4 => "a\0b".to_string(),
                5 => "x".repeat(1100),
                6 => format!("nodir/{name}"),
                _ => format!("{name}/./x"),
            };
            m.entries.insert(new.clone(), e);
            format!("rename entry {name:?} -> {:?}", &new[..new.len().min(20)])
        }
        14 if !names.is_empty() => {
            let name = names[rng.random_range(0..names.len())].clone();
            let id = ids.first().copied().unwrap_or(1);
            m.entries.insert(name.clone(), Entry::File(id));
            format!("entry {name} -> file {id} (alias/dir-to-file)")
        }
        15 => {
            m.entries.insert("d".into(), Entry::File(ids.first().copied().unwrap_or(1)));
            "parent directory becomes a file".into()
        }
        16 if !ids.is_empty() => {
            // Reserve beyond capacity.
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            for i in 0..(CAPACITY / PAGE + 1) {
                node.reserved.insert(1000 + i);
            }
            format!("file {id} reserves over capacity")
        }
        17 if !ids.is_empty() => {
            let id = ids[rng.random_range(0..ids.len())];
            let node = m.files.get_mut(&id).unwrap();
            node.len = u64::MAX;
            let top = (u64::MAX - PAGE) / PAGE;
            node.reserved.insert(top);
            node.pages.insert(top, PageRef { slot: 100, hash: [0; 32] });
            format!("file {id} page at the last representable index")
        }
        18 => {
            m.entries.clear();
            "no entries (all files orphaned)".into()
        }
        _ => {
            for node in m.files.values_mut() {
                node.reserved.clear();
            }
            "every reservation dropped".into()
        }
    }
}

// ---------------------------------------------------------------- API tour

fn walk(b: &RollbackBacking, dir: &str, out: &mut Vec<String>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Ok(names) = b.list(dir) else { return };
    for name in names {
        let path = if dir.is_empty() { name } else { format!("{dir}/{name}") };
        if b.open(&path, false).is_ok() {
            out.push(path);
        } else {
            walk(b, &path, out, depth + 1);
        }
    }
}

fn tour(rng: &mut StdRng, b: &RollbackBacking) -> Result<(), String> {
    let capacity = b.capacity().map_err(|e| format!("capacity: {e}"))?;
    let mut files = Vec::new();
    walk(b, "", &mut files, 0);
    let mut buf = vec![0u8; 3 * PAGE as usize];
    for path in files.iter().take(32) {
        let Ok(f) = b.open(path, false) else { continue };
        let Ok(len) = f.len() else { continue };
        let n = (len.min(buf.len() as u64)) as usize;
        let _ = f.read_at(0, &mut buf[..n]);
        if len > n as u64 {
            let _ = f.read_at(len - n as u64, &mut buf[..n]);
        }
        let off = rng.random_range(0..4 * PAGE);
        let _ = f.write_at(off, b"tour");
        let _ = f.punch_hole(0, PAGE.min(len));
        if rng.random_bool(0.3) {
            let _ = f.set_len(rng.random_range(0..8 * PAGE));
        }
        let _ = f.sync_data();
    }
    let _ = b.create_dir_all("t/u");
    if let Ok(f) = b.open("t/u/new", true) {
        let _ = f.write_at(0, &[7; 100]);
        let _ = f.sync_data();
    }
    let _ = b.sync_dir("t/u");
    let _ = b.sync_dir("t");
    let _ = b.sync_dir("");
    if let Ok(Some(free)) = b.free_bytes() {
        if free > capacity {
            return Err(format!("free_bytes {free} > capacity {capacity}"));
        }
    }
    Ok(())
}

#[test]
fn rollback_manifest_digest_valid_mutations() {
    let seed = 0x0B0B_0001;
    let mut rng = StdRng::seed_from_u64(seed);
    let fx = Fixture::new();
    let mut failures: Vec<String> = Vec::new();
    let mut accepted = BTreeMap::new();
    let mut refused = 0u64;
    let mut max_peak = 0usize;
    let iterations = 1200;
    for i in 0..iterations {
        fx.restore();
        let mut m = fx.manifest.clone();
        let mut what = Vec::new();
        for _ in 0..rng.random_range(1..=2) {
            what.push(mutate(&mut rng, &mut m));
        }
        let what = what.join(", ");
        let capacity_ok = m.capacity > 0 && m.capacity <= 1 << 30 && m.capacity % PAGE == 0;
        let (file_capacity, arena_capacity) = if capacity_ok && m.capacity <= 4 * CAPACITY && rng.random_bool(0.8) {
            (m.capacity, m.capacity)
        } else {
            (CAPACITY, CAPACITY)
        };
        let rehash = rng.random_bool(0.85);
        fx.install(&m, file_capacity, rehash, arena_capacity);
        let opened = catch_unwind(AssertUnwindSafe(|| {
            measured(|| RollbackBacking::open(fx.root.path(), fx.witness.path()))
        }));
        let (result, peak) = match opened {
            Err(p) => {
                failures.push(format!("iter {i} ({what}): open panicked: {}", panic_text(p)));
                continue;
            }
            Ok(v) => v,
        };
        max_peak = max_peak.max(peak);
        let backing = match result {
            Err(_) => {
                refused += 1;
                continue;
            }
            Ok(b) => b,
        };
        *accepted.entry(what.split(' ').next().unwrap_or("").to_string()).or_insert(0u64) += 1;
        let toured = catch_unwind(AssertUnwindSafe(|| tour(&mut rng, &backing)));
        match toured {
            Err(p) => failures.push(format!("iter {i} ({what}): API tour panicked: {}", panic_text(p))),
            Ok(Err(e)) => failures.push(format!("iter {i} ({what}): {e}")),
            Ok(Ok(())) => {}
        }
        drop(backing);
        let reopened = catch_unwind(AssertUnwindSafe(|| {
            RollbackBacking::open(fx.root.path(), fx.witness.path())
        }));
        match reopened {
            Err(p) => failures.push(format!("iter {i} ({what}): reopen panicked: {}", panic_text(p))),
            Ok(Err(e)) => failures.push(format!("iter {i} ({what}): accepted, then reopen refused: {e}")),
            Ok(Ok(_)) => {}
        }
    }
    eprintln!(
        "[audit2 rollback] seed {seed:#x}: {iterations} digest-valid manifests, refused {refused}, \
         accepted by first mutation kind {accepted:?}, max open peak {max_peak} bytes"
    );
    for f in failures.iter().take(10) {
        eprintln!("[audit2 rollback]   {f}");
    }
    assert!(failures.is_empty(), "{} failures (see above)", failures.len());
}

/// The witness digest is checked before JSON decoding, but the decoder
/// then builds the whole namespace before `validate` applies its 4096-entry
/// and capacity bounds. Measure the amplification for a witnessed manifest
/// at the stated length bound's order of magnitude (needs witness control).
#[test]
fn rollback_manifest_decode_amplification_before_validate() {
    let fx = Fixture::new();
    fx.restore();
    let mut m = fx.manifest.clone();
    let id = *m.files.keys().next().unwrap();
    // ~8 MiB of JSON: one node with ~1M reserved indices (validate refuses
    // anything above capacity / 4096 = 64).
    let node = m.files.get_mut(&id).unwrap();
    for i in 0..1_000_000u64 {
        node.reserved.insert(i);
    }
    let body = fx.install(&m, CAPACITY + 0, true, CAPACITY);
    let (result, peak) = measured(|| RollbackBacking::open(fx.root.path(), fx.witness.path()));
    eprintln!(
        "[audit2 rollback] witnessed {}-byte manifest with 1M reservations: open -> {:?}, \
         peak {} bytes ({:.1}x the manifest)",
        body.len(),
        result.as_ref().err().map(|e| e.to_string()),
        peak,
        peak as f64 / body.len() as f64
    );
    assert!(result.is_err());
}

/// The 8-byte length header of a manifest slot is read BEFORE the witness
/// digest and before the file length is compared; anyone who can write the
/// backing root sets it. Measure what one open allocates for it.
#[test]
fn rollback_manifest_length_header_allocation_before_authentication() {
    let fx = Fixture::new();
    fx.restore();
    let other = 0; // open tries slot 0 first
    use std::os::unix::fs::FileExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(fx.root.path().join(MANIFESTS[other]))
        .unwrap();
    // The largest length the check admits: manifest_bound(1 GiB) - 8.
    let claimed = manifest_bound(1 << 30) - 8;
    file.write_all_at(&claimed.to_le_bytes(), 0).unwrap();
    let ((result, peak), file_len) = (
        measured(|| RollbackBacking::open(fx.root.path(), fx.witness.path())),
        std::fs::metadata(fx.root.path().join(MANIFESTS[other])).unwrap().len(),
    );
    eprintln!(
        "[audit2 rollback] slot {other} header claims {claimed} bytes (file is {file_len}); \
         open -> {:?}, peak {peak} bytes",
        result.as_ref().err().map(|e| e.to_string())
    );
}
