//! MAKI-028: identical internal overlay versions and checkpoint snapshots
//! must share ciphertext. Public owned snapshots and logical byte charging
//! remain unchanged; these measurements do not bound total process RSS.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::overlay::{Overlay, OverlayVersion};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::{failpoints, CrashableBacking};
use uuid::Uuid;

const PAYLOAD: usize = 64 * 1024;
const UNITS: u64 = 64;

#[derive(Clone, Copy, Debug, Default)]
struct Allocations {
    live: isize,
    peak: usize,
    largest: usize,
}

thread_local! {
    static ALLOCATIONS: Cell<Option<Allocations>> = const { Cell::new(None) };
}

struct MeasuredAllocator;

fn account(delta: isize, allocated: usize) {
    let _ = ALLOCATIONS.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            stats.live += delta;
            stats.peak = stats.peak.max(stats.live.max(0) as usize);
            stats.largest = stats.largest.max(allocated);
            cell.set(Some(stats));
        }
    });
}

unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize, layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            account(layout.size() as isize, layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize), 0);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if !ptr.is_null() {
            account(size as isize - layout.size() as isize, size);
        }
        ptr
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x2800),
        provider_type: "fake".into(),
        crypto_compatibility_id: "overlay-memory".into(),
        key_identity: "key".into(),
        geometry: Geometry::compute(
            512,
            PAYLOAD as u32,
            512,
            PAYLOAD as u32,
            UNITS * PAYLOAD as u64,
            UNITS * PAYLOAD as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 8 * 1024 * 1024,
    }
}

#[test]
fn durable_promotion_does_not_duplicate_ciphertext_allocations() {
    let mut overlay = Overlay::new();
    for unit in 0..UNITS {
        overlay.publish(unit, unit + 1, vec![unit as u8; PAYLOAD]);
    }
    // Only promotion is measured. All payloads are initialized and owned
    // before measurement; the allocator observes sizes, never freed bytes.
    ALLOCATIONS.with(|cell| cell.set(Some(Allocations::default())));
    overlay.promote(UNITS);
    let stats = ALLOCATIONS.with(|cell| cell.replace(None).unwrap());
    eprintln!("durable promotion allocations: {stats:?}");
    assert!(
        stats.peak <= 128 * 1024 && stats.largest < PAYLOAD,
        "promotion duplicated existing ciphertext: {stats:?}"
    );
    assert_eq!(overlay.bytes(), 2 * UNITS * PAYLOAD as u64);
    overlay.check_invariants();
}

#[test]
fn checkpoint_snapshot_does_not_duplicate_all_durable_ciphertext() {
    let _guard = failpoints::test_lock();
    let directory = tempfile::tempdir().unwrap();
    let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(directory.path()).unwrap());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let mut volume = Volume::recover(backing, options()).unwrap();
    // Initialize the shard/allocation metadata before measurement. The real
    // file backing avoids mock file-image copies and retained event traces.
    volume.write_ct(0, &vec![0xff; PAYLOAD], true).unwrap();
    volume.checkpoint().unwrap();
    for unit in 0..UNITS {
        volume
            .write_ct(unit, &vec![unit as u8; PAYLOAD], false)
            .unwrap();
    }
    volume.flush().unwrap();
    let durable = volume.journal_durable_sequence();
    ALLOCATIONS.with(|cell| cell.set(Some(Allocations::default())));
    let result = volume.checkpoint();
    let stats = ALLOCATIONS.with(|cell| cell.replace(None).unwrap());
    assert_eq!(result.unwrap(), durable);
    eprintln!("checkpoint snapshot allocations: {stats:?}");
    // Allow per-slot encoding and snapshot/index metadata. A copy of all
    // 64 payloads costs 4 MiB and cannot fit this deliberately loose bound.
    assert!(
        stats.peak <= 512 * 1024,
        "checkpoint copied the full durable ciphertext set: {stats:?}"
    );
    assert_eq!(volume.overlay_len(), 0);
    for unit in 0..UNITS {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            vec![unit as u8; PAYLOAD]
        );
    }
}

#[test]
fn public_owned_snapshot_and_logical_accounting_remain_independent() {
    let mut overlay = Overlay::new();
    overlay.publish(9, 1, vec![0xa1; 8]);
    overlay.promote(1);
    assert_eq!(overlay.bytes(), 16);
    overlay.publish(9, 2, vec![0xb2; 12]);
    assert_eq!(overlay.bytes(), 20);
    assert_eq!(overlay.get(9).unwrap().ciphertext, vec![0xb2; 12]);
    let mut owned: Vec<(u64, OverlayVersion)> = overlay.collect_durable(1);
    assert_eq!(owned[0].1.sequence, 1);
    owned[0].1.ciphertext.fill(0xff);
    assert_eq!(overlay.collect_durable(1)[0].1.ciphertext, vec![0xa1; 8]);
    overlay.retire(1);
    assert_eq!(overlay.bytes(), 12);
    assert_eq!(overlay.get(9).unwrap().sequence, 2);
    assert!(overlay.collect_durable(1).is_empty());
    overlay.promote(2);
    assert_eq!(overlay.bytes(), 24);
    assert_eq!(overlay.collect_durable(2)[0].1.ciphertext, vec![0xb2; 12]);
    overlay.retire(2);
    assert_eq!(overlay.bytes(), 0);
    assert!(overlay.is_empty());
    assert_eq!(owned[0].1.ciphertext, vec![0xff; 8]);
}

#[test]
fn checkpoint_retry_preserves_old_durable_or_newly_flushed_overwrite() {
    let _guard = failpoints::test_lock();
    for flush_overwrite in [false, true] {
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        let mut volume = Volume::recover(backing.clone(), options()).unwrap();
        volume.write_ct(0, &[0; 512], true).unwrap();
        let baseline = volume.checkpoint().unwrap();
        let old = volume.write_ct(0, &[0xa1; 512], true).unwrap();
        let latest = volume.write_ct(0, &[0xb2; 512], false).unwrap();
        let fail = Arc::new(AtomicBool::new(true));
        let failure = fail.clone();
        backing.set_fault_hook(Some(Arc::new(move |op| match op {
            FaultOp::SyncData { path }
                if path.starts_with("data/")
                    && path.ends_with(".dat")
                    && failure.swap(false, Ordering::SeqCst) =>
            {
                Some(io::Error::other("injected checkpoint shard sync failure"))
            }
            _ => None,
        })));
        assert!(volume.checkpoint().is_err());
        assert!(!fail.load(Ordering::SeqCst), "fault must be exercised");
        assert_eq!(volume.checkpoint_sequence(), baseline);
        assert_eq!(volume.journal_durable_sequence(), old);
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, [0xb2; 512]);
        if flush_overwrite {
            volume.flush().unwrap();
            assert_eq!(volume.journal_durable_sequence(), latest);
        }
        let expected_sequence = if flush_overwrite { latest } else { old };
        let expected_byte = if flush_overwrite { 0xb2 } else { 0xa1 };
        assert_eq!(volume.checkpoint().unwrap(), expected_sequence);
        assert_eq!(volume.read_ct(0).unwrap().unwrap().1, [0xb2; 512]);
        assert_eq!(volume.overlay_len(), usize::from(!flush_overwrite));
        drop(volume);
        backing.crash_all_lost();
        let recovered = Volume::recover(backing, options()).unwrap();
        assert_eq!(recovered.checkpoint_sequence(), expected_sequence);
        assert_eq!(
            recovered.read_ct(0).unwrap().unwrap(),
            (expected_sequence, vec![expected_byte; 512]),
            "checkpoint retry must retain the version at its durable boundary"
        );
    }
}
