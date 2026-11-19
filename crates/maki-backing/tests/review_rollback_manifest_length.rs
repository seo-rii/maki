//! A rollback manifest slot starts with an 8-byte length that is read before
//! anything authenticates it, and anyone who can write the backing root can
//! set it. A canonical manifest always fits its slot file, whose length is
//! known before the read, so opening a backing must never allocate more for
//! a claimed length than that file holds. Before, a damaged length on the
//! stale slot made every open, takeover and GC pass allocate up to the
//! 1 GiB capacity's bound (72 MiB) for a slot file of about 8 MiB.
#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, MemBacking, RollbackBacking};

struct Counting;

thread_local! {
    static PAGE_ALLOCS: Cell<usize> = const { Cell::new(0) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn grew(size: usize) {
    if size == PAGE as usize {
        let _ = PAGE_ALLOCS.try_with(|n| n.set(n.get() + 1));
    }
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size;
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

fn shrank(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(size)));
}

// SAFETY: every call is forwarded unchanged to the system allocator; the
// thread-local counters never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        shrank(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        shrank(layout.size());
        grew(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The most this thread had allocated at once while running `f`, above what
/// it held before.
fn peak_while<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(start));
    let value = f();
    (value, PEAK.with(Cell::get) - start)
}

const PAGE: u64 = 4096;
/// The length check's ceiling: the slot size of a 1 GiB backing, minus the
/// length field.
const LARGEST_CLAIM: u64 = (8 << 20) + (1 << 30) / PAGE * 256 - 8;

/// The manifest slot in `dir` that the backing does not select: the one
/// holding the older generation, or nothing.
fn stale_slot(dir: &Path) -> PathBuf {
    let generation = |slot: &Path| {
        let bytes = std::fs::read(slot).unwrap();
        let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        (len > 0).then(|| {
            let manifest: serde_json::Value = serde_json::from_slice(&bytes[8..8 + len]).unwrap();
            manifest["generation"].as_u64().unwrap()
        })
    };
    let [zero, one] = ["rollback.manifest.0", "rollback.manifest.1"].map(|name| dir.join(name));
    if generation(&zero) < generation(&one) {
        zero
    } else {
        one
    }
}

/// Overwrite a slot's length field, returning the slot file's length.
fn claim_length(slot: &Path, length: u64) -> u64 {
    let file = std::fs::OpenOptions::new().write(true).open(slot).unwrap();
    file.write_all_at(&length.to_le_bytes(), 0).unwrap();
    file.sync_all().unwrap();
    file.metadata().unwrap().len()
}

fn write_payload(backing: &dyn Backing, payload: &[u8]) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, payload).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

fn read_payload(backing: &dyn Backing) -> Vec<u8> {
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

#[test]
fn local_manifest_length_beyond_its_slot_is_refused_before_allocating() {
    // The witness must live on another filesystem than the backing.
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing = RollbackBacking::create(root.path(), witness.path(), 16 * PAGE).unwrap();
    write_payload(&backing, b"committed");
    drop(backing);
    let slot_len = claim_length(&stale_slot(root.path()), LARGEST_CLAIM);

    let (opened, peak) = peak_while(|| RollbackBacking::open(root.path(), witness.path()));
    let backing = opened.unwrap();
    assert_eq!(read_payload(&backing), b"committed");
    assert!(
        (peak as u64) < slot_len,
        "open allocated {peak} bytes for a {slot_len}-byte manifest slot"
    );
}

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
}

impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(Role::Writer, request)
    }
}

fn current_namespace(rpc: &dyn Rpc) -> String {
    rpc.call(&Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
    .current
    .unwrap()
    .namespace
}

#[test]
fn remote_manifest_length_beyond_its_slot_is_refused_before_allocating() {
    let rpc = Arc::new(LocalRpc {
        store: Arc::new(Mutex::new(
            StateStore::create_backing(Arc::new(MemBacking::new()), [1; 16]).unwrap(),
        )),
    });
    let root = tempfile::tempdir().unwrap();
    let backing = RollbackBacking::create_remote(root.path(), rpc.clone(), 16 * PAGE).unwrap();
    write_payload(&backing, b"committed");
    drop(backing);
    let current = current_namespace(rpc.as_ref());
    let slot_len = claim_length(&stale_slot(&root.path().join(&current)), LARGEST_CLAIM);

    // Authentication, the fork's source load and the GC pass after it each
    // read the current generation.
    let (opened, peak) = peak_while(|| RollbackBacking::open_remote(root.path(), rpc.clone()));
    let backing = opened.unwrap();
    assert_eq!(read_payload(&backing), b"committed");
    assert_ne!(current_namespace(rpc.as_ref()), current);
    assert!(
        (peak as u64) < slot_len,
        "open_remote allocated {peak} bytes for a {slot_len}-byte manifest slot"
    );
}

#[test]
fn sparse_reads_do_not_allocate_zero_pages() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let backing = RollbackBacking::create(root.path(), witness.path(), PAGE).unwrap();
    let file = backing.open("sparse", true).unwrap();
    let mut out = vec![0x55; 64 * PAGE as usize];
    file.set_len(out.len() as u64).unwrap();
    let before = PAGE_ALLOCS.with(Cell::get);
    file.read_at(0, &mut out).unwrap();
    assert_eq!(PAGE_ALLOCS.with(Cell::get), before);
    assert!(out.iter().all(|byte| *byte == 0));
}
