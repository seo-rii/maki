//! Test-only observation of allocations immediately before release.
//!
//! Every allocation is initialized by this allocator, including newly grown
//! capacity. Observers therefore inspect live, initialized bytes, never freed
//! memory. Records are fixed-size thread-local data so allocator callbacks do
//! not allocate. Watches must be armed and queried on the releasing thread.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Clone, Copy)]
struct Record {
    address: usize,
    armed: bool,
    releases: usize,
    all_zero: bool,
}

const EMPTY: Record = Record {
    address: 0,
    armed: false,
    releases: 0,
    all_zero: true,
};

thread_local! {
    static RECORDS: Cell<[Record; 16]> = const { Cell::new([EMPTY; 16]) };
}

struct ObservingAllocator;

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Initializing all capacity makes full-layout observation well-defined.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { observe_release(pointer, layout.size()) };
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(next_layout) = Layout::from_size_align(size, layout.align()) else {
            return std::ptr::null_mut();
        };
        let next = unsafe { System.alloc_zeroed(next_layout) };
        if !next.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(pointer, next, layout.size().min(size)) };
            unsafe { self.dealloc(pointer, layout) };
        }
        next
    }
}

unsafe fn observe_release(pointer: *mut u8, size: usize) {
    let _ = RECORDS.try_with(|records| {
        let mut current = records.get();
        for record in &mut current {
            if record.armed && record.address == pointer as usize {
                // The allocator initialized every byte and still owns this
                // allocation. Inspection precedes the call to System.dealloc.
                let bytes = unsafe { std::slice::from_raw_parts(pointer, size) };
                record.all_zero &= bytes.iter().all(|byte| *byte == 0);
                record.releases += 1;
                record.armed = false;
            }
        }
        records.set(current);
    });
}

/// Arm an observer for an allocation's base pointer (for example Vec::as_ptr).
/// The observer's assertion also checks that the allocation was released.
pub fn watch(pointer: *const u8) -> Watch {
    assert!(!pointer.is_null());
    RECORDS.with(|records| {
        let mut current = records.get();
        let slot = current
            .iter()
            .position(|record| record.address == 0)
            .expect("too many simultaneous allocation watches");
        current[slot] = Record {
            address: pointer as usize,
            armed: true,
            ..EMPTY
        };
        records.set(current);
        Watch {
            slot,
            _thread: PhantomData,
        }
    })
}

/// A thread-local watch; dropping it removes the metadata, not the allocation.
pub struct Watch {
    slot: usize,
    _thread: PhantomData<Rc<()>>,
}

impl Watch {
    pub fn assert_zeroized(&self) {
        RECORDS.with(|records| {
            let record = records.get()[self.slot];
            assert_eq!(record.releases, 1, "watched allocation was not released");
            assert!(
                record.all_zero,
                "allocation contained nonzero bytes at release"
            );
        });
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = RECORDS.try_with(|records| {
            let mut current = records.get();
            current[self.slot] = EMPTY;
            records.set(current);
        });
    }
}
