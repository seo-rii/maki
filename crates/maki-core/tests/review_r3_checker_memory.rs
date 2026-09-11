//! MAKI-023: offline checks must not materialize one ID per allocated unit.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use maki_backing::Backing;
use maki_core::store::SlotStore;
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::geometry::Geometry;
use maki_format::layout;
use maki_test_support::CrashableBacking;

thread_local! {
    // Thread-local accounting excludes allocations by the parallel test runner.
    static ALLOCATION_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn record_allocation(size: usize) {
    ALLOCATION_BYTES.with(|counter| {
        if let Some(bytes) = counter.get() {
            counter.set(Some(bytes + size));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Store real A/B maps and a catalog. Slot bodies are irrelevant to enumeration;
/// the existing deep-check tests exercise their headers and ciphertext CRCs.
fn store_with_maps(units_per_shard: u64, shards: &[(u64, AllocationMap)]) -> SlotStore {
    let backing = Arc::new(CrashableBacking::new());
    backing.create_dir_all(layout::DATA_DIR).unwrap();
    let geometry = Geometry::compute(
        512,
        512,
        512,
        512,
        units_per_shard * 512 * 8,
        units_per_shard * 512,
    )
    .unwrap();
    let mut catalog = ShardCatalog::new();
    for (shard, map) in shards {
        catalog.insert(*shard);
        let mut map = map.clone();
        let ab = AbStore::new(layout::shard_alloc_a(*shard), layout::shard_alloc_b(*shard));
        // Both valid copies avoid the unrelated slot-header repair scan at open.
        ab.store(backing.as_ref(), &mut map).unwrap();
        ab.store(backing.as_ref(), &mut map).unwrap();
        backing.open(&layout::shard_data(*shard), true).unwrap();
    }
    AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B)
        .store(backing.as_ref(), &mut catalog)
        .unwrap();
    SlotStore::open(backing, geometry).unwrap()
}

#[test]
fn allocated_units_remain_complete_and_sorted_across_sparse_shards() {
    let mut first = AllocationMap::new(16);
    first.set(0, true);
    first.set(15, true);
    let mut last = AllocationMap::new(16);
    last.set(4, true);
    last.set(6, true);
    let store = store_with_maps(16, &[(5, last), (3, AllocationMap::new(16)), (1, first)]);
    let mut units = Vec::new();
    for unit in store.allocated_units() {
        units.push(unit);
    }
    assert_eq!(units, [16, 31, 84, 86]);

    let empty = store_with_maps(16, &[]);
    let mut count = 0;
    for _ in empty.allocated_units() {
        count += 1;
    }
    assert_eq!(count, 0);
}

fn enumeration_allocations(units: u64) -> usize {
    let mut map = AllocationMap::new(units);
    for unit in 0..units {
        map.set(unit, true);
    }
    let store = store_with_maps(units, &[(0, map)]);

    ALLOCATION_BYTES.with(|counter| counter.set(Some(0)));
    let mut count = 0;
    let mut ordered = true;
    for unit in store.allocated_units() {
        ordered &= unit == count;
        count += 1;
    }
    let allocated = ALLOCATION_BYTES.with(|counter| counter.replace(None).unwrap());

    assert!(
        ordered,
        "allocated units must be visited exactly once in order"
    );
    assert_eq!(count, units);
    allocated
}

#[test]
fn enumeration_memory_is_bounded_when_allocated_unit_count_grows() {
    // The dense map grows from 128 bytes to 16 KiB, all allocated before
    // measurement. A checker needs the map, but must not add an ID list that
    // is 64 times larger than the map. Allow modest fixed traversal overhead.
    let small = enumeration_allocations(1_024);
    let large = enumeration_allocations(131_072);
    assert!(
        large <= small + 4_096 && large <= 8_192,
        "enumeration must stream unit IDs: small allocated {small} bytes, large allocated {large} bytes"
    );
}
