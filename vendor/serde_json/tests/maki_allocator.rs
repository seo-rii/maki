//! Shared test-only observer; inspect initialized allocations before free.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const TRACKED: usize = 256;

#[derive(Clone, Copy, Default, Debug)]
pub struct Inspection {
    pub allocations: usize,
    pub frees: usize,
    pub wiped_frees: usize,
    pub secret_frees: usize,
    pub overflowed: bool,
    pub watched_frees: usize,
    pub watched_wiped_frees: usize,
}

#[derive(Clone, Copy)]
struct Tracking {
    enabled: bool,
    alignment: usize,
    watched: usize,
    pointers: [usize; TRACKED],
    inspection: Inspection,
}

const EMPTY: Tracking = Tracking {
    enabled: false,
    alignment: 0,
    watched: 0,
    pointers: [0; TRACKED],
    inspection: Inspection {
        allocations: 0,
        frees: 0,
        wiped_frees: 0,
        secret_frees: 0,
        overflowed: false,
        watched_frees: 0,
        watched_wiped_frees: 0,
    },
};

thread_local! {
    static TRACKING: Cell<Tracking> = const { Cell::new(EMPTY) };
}

fn selected(layout: Layout, alignment: usize) -> bool {
    if alignment == 0 {
        layout.align() == 1 && (8..=32768).contains(&layout.size())
    } else {
        layout.align() == alignment && layout.size() != 0
    }
}

fn track(pointer: *mut u8, layout: Layout) {
    if pointer.is_null() {
        return;
    }
    let _ = TRACKING.try_with(|cell| {
        let mut tracking = cell.get();
        if tracking.enabled && selected(layout, tracking.alignment) {
            tracking.inspection.allocations += 1;
            if let Some(slot) = tracking.pointers.iter_mut().find(|slot| **slot == 0) {
                *slot = pointer as usize;
            } else {
                tracking.inspection.overflowed = true;
            }
            cell.set(tracking);
        }
    });
}

struct InspectAllocator;

// SAFETY: System owns every allocation. Every allocation has its complete
// range initialized from allocation, including spare capacity. Default realloc
// can copy spare bytes from an unselected old layout into a selected new one.
// Observation occurs immediately before System.dealloc, never after free.
// Tracking uses fixed TLS storage and does not allocate.
unsafe impl GlobalAlloc for InspectAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        track(pointer, layout);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        track(pointer, layout);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = TRACKING.try_with(|cell| {
            let mut tracking = cell.get();
            if tracking.enabled && tracking.watched == pointer as usize {
                // SAFETY: every allocation is fully initialized by this
                // allocator, even layouts outside the marker scan range.
                let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                tracking.inspection.watched_frees += 1;
                tracking.inspection.watched_wiped_frees +=
                    usize::from(bytes.iter().all(|byte| *byte == 0));
                tracking.watched = 0;
                cell.set(tracking);
            }
            if tracking.enabled && selected(layout, tracking.alignment) {
                if let Some(slot) = tracking
                    .pointers
                    .iter_mut()
                    .find(|slot| **slot == pointer as usize)
                {
                    *slot = 0;
                    // SAFETY: the selected allocation is initialized and live.
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    tracking.inspection.frees += 1;
                    tracking.inspection.wiped_frees +=
                        usize::from(bytes.iter().all(|byte| *byte == 0));
                    tracking.inspection.secret_frees += usize::from(bytes.windows(16).any(|run| {
                        run.iter().all(|b| *b == b'Q') || run.iter().all(|b| *b == b'7')
                    }));
                    cell.set(tracking);
                }
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: InspectAllocator = InspectAllocator;

pub fn observe<T>(operation: impl FnOnce() -> T) -> (T, Inspection) {
    observe_with_alignment(0, operation)
}

/// Inspect only allocations made in a pure arithmetic operation. The selected
/// alignment must not include caller outputs or panic/runtime allocations.
#[allow(dead_code)] // The string/number test binaries use the default mode.
pub fn observe_aligned<T>(alignment: usize, operation: impl FnOnce() -> T) -> (T, Inspection) {
    assert!(alignment.is_power_of_two());
    observe_with_alignment(alignment, operation)
}

fn observe_with_alignment<T>(alignment: usize, operation: impl FnOnce() -> T) -> (T, Inspection) {
    TRACKING.with(|cell| {
        assert!(!cell.get().enabled);
        cell.set(Tracking {
            enabled: true,
            alignment,
            ..EMPTY
        });
    });
    let output = operation();
    let inspection = TRACKING.with(|cell| cell.replace(EMPTY).inspection);
    (output, inspection)
}

pub fn assert_wiped(inspection: Inspection) {
    assert!(
        !inspection.overflowed,
        "observer exceeded its fixed storage"
    );
    assert_eq!(
        inspection.secret_frees, 0,
        "private allocation released secret bytes: {inspection:?}",
    );
    assert!(
        inspection.wiped_frees > 0,
        "no erased private allocation was observed: {inspection:?}",
    );
}

#[allow(dead_code)] // Only the pure limb arithmetic tests assert every release.
pub fn assert_all_wiped(inspection: Inspection) {
    assert!(
        !inspection.overflowed,
        "observer exceeded its fixed storage"
    );
    assert!(
        inspection.frees > 0,
        "no arithmetic allocation was released"
    );
    assert_eq!(
        inspection.allocations, inspection.frees,
        "private allocation escaped: {inspection:?}"
    );
    assert_eq!(
        inspection.frees, inspection.wiped_frees,
        "private arithmetic allocation was not erased: {inspection:?}"
    );
}

/// Register an existing live owner before passing it to a library consumer.
/// This also covers one-byte strings and verifies the entire spare capacity.
pub fn watch(pointer: *const u8) {
    assert!(!pointer.is_null());
    TRACKING.with(|cell| {
        let mut tracking = cell.get();
        assert!(tracking.enabled, "watch is outside an observation");
        assert_eq!(tracking.watched, 0, "previous owner is still live");
        tracking.watched = pointer as usize;
        cell.set(tracking);
    });
}

pub fn assert_watched(inspection: Inspection) {
    assert_eq!(
        inspection.watched_frees, 1,
        "watched owner was not freed: {inspection:?}"
    );
    assert_eq!(
        inspection.watched_wiped_frees, 1,
        "watched allocation was not fully erased: {inspection:?}"
    );
}
