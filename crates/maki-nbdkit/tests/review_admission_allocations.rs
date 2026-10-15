//! Waiting NBD callbacks must borrow their input and allocate plaintext only
//! after the engine's byte/count budget has admitted them.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_nbdkit::adapter::NbdAdapter;
use maki_test_support::{FakeCryptoProvider, ManualClock};

const UNIT: usize = 64 * 1024;
thread_local! { static TRACK: Cell<bool> = const { Cell::new(false) }; }
static LARGE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
struct Allocator;
fn account(size: usize) {
    if size >= UNIT && TRACK.try_with(Cell::get).unwrap_or(false) {
        LARGE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
    }
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        account(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        account(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        account(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn wait(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "callback did not reach admission"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn queued_writes_and_zeroes_do_not_allocate_request_sized_plaintext() {
    let backing = Arc::new(maki_backing::MemBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xad01),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT as u32,
                512,
                UNIT as u32 + 8,
                (16 * UNIT) as u64,
                (8 * UNIT) as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = runtime.handle().clone();
    let provider = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let mut options = EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    options.limits.max_active_callbacks = 1;
    options.limits.max_plaintext_bytes = UNIT as u64;
    let engine = runtime
        .block_on(Engine::attach(backing, provider.clone(), options))
        .unwrap();
    runtime.block_on(engine.stop_checkpoint_worker());
    let adapter = Arc::new(NbdAdapter::from_engine(engine.clone(), runtime));
    for zero in [false, true] {
        let clock = Arc::new(ManualClock::new());
        provider.set_latency(clock.clone(), Duration::from_secs(1));
        let first_adapter = adapter.clone();
        let first = std::thread::spawn(move || first_adapter.pwrite(&vec![0x41; UNIT], 0, false));
        wait(|| clock.sleeper_count() == 1);
        LARGE_ALLOCATIONS.store(0, Ordering::SeqCst);
        let second_adapter = adapter.clone();
        let second = std::thread::spawn(move || {
            let bytes = vec![0x55; UNIT];
            TRACK.set(true);
            let result = if zero {
                second_adapter.zero(UNIT as u64, UNIT, false, true)
            } else {
                second_adapter.pwrite(&bytes, UNIT as u64, true)
            };
            TRACK.set(false);
            result
        });
        wait(|| handle.block_on(engine.stats()).active_requests == 2);
        let allocated_before_admission = LARGE_ALLOCATIONS.load(Ordering::SeqCst);
        provider.set_latency(clock.clone(), Duration::ZERO);
        clock.advance(Duration::from_secs(1));
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert_eq!(
            allocated_before_admission, 0,
            "queued zero={zero} copied/allocated plaintext before admission"
        );
        let expected = if zero { 0 } else { 0x55 };
        assert_eq!(
            handle.block_on(engine.read(UNIT as u64, UNIT)).unwrap(),
            vec![expected; UNIT]
        );
    }
    drop(engine);
    adapter.shutdown().unwrap();
}
