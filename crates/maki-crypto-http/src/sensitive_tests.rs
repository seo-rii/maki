//! MAKI-015: partial HTTP payload decodes must wipe their output allocation
//! when malformed input is rejected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use super::{append_response_chunk, PayloadEncoding};

const PAYLOAD_LEN: usize = 257;
const FILL: u8 = 0xa5;

#[derive(Clone, Copy, Default, Debug)]
struct Inspection {
    enabled: bool,
    allocations: usize,
    deallocations: usize,
    zeroized: usize,
    plaintext_deallocations: usize,
}

thread_local! {
    static INSPECTION: Cell<Inspection> = const { Cell::new(Inspection {
        enabled: false,
        allocations: 0,
        deallocations: 0,
        zeroized: 0,
        plaintext_deallocations: 0,
    }) };
}

struct InspectDecodeAllocation;

fn selected(layout: Layout) -> bool {
    [
        PAYLOAD_LEN,
        PAYLOAD_LEN + 1,
        PAYLOAD_LEN.next_power_of_two() / 2,
    ]
    .contains(&layout.size())
}

// SAFETY: every operation delegates to System. Selected allocations are
// zero-initialized, so the observer may read their complete live allocation
// immediately before delegating deallocation. The thread-local counters do not
// allocate and are disabled outside each focused decoder call.
unsafe impl GlobalAlloc for InspectDecodeAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watching = INSPECTION
            .try_with(|cell| cell.get().enabled && selected(layout))
            .unwrap_or(false);
        if watching {
            unsafe { self.alloc_zeroed(layout) }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && selected(layout) {
            let _ = INSPECTION.try_with(|cell| {
                let mut inspection = cell.get();
                if inspection.enabled {
                    inspection.allocations += 1;
                    cell.set(inspection);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if selected(layout) {
            let _ = INSPECTION.try_with(|cell| {
                let mut inspection = cell.get();
                if inspection.enabled {
                    // SAFETY: `pointer` still names the selected live
                    // zero-initialized allocation and `layout.size()` bytes
                    // are readable until System.dealloc below.
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    inspection.deallocations += 1;
                    inspection.zeroized += usize::from(bytes.iter().all(|byte| *byte == 0));
                    inspection.plaintext_deallocations += usize::from(
                        bytes.len() >= 64 && bytes[..64].iter().all(|byte| *byte == FILL),
                    );
                    cell.set(inspection);
                }
            });
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectDecodeAllocation = InspectDecodeAllocation;

fn inspect_rejected_decode(encoding: PayloadEncoding, encoded: &str) -> Inspection {
    INSPECTION.with(|cell| {
        let previous = cell.replace(Inspection {
            enabled: true,
            ..Inspection::default()
        });
        assert!(!previous.enabled, "nested decoder allocation inspection");
    });
    let result = encoding.decode(encoded);
    assert!(result.is_err(), "malformed payload was accepted");
    drop(result);
    INSPECTION.with(|cell| {
        let inspection = cell.get();
        cell.set(Inspection::default());
        inspection
    })
}

fn assert_partial_output_wiped(inspection: Inspection) {
    assert!(
        inspection.allocations > 0 && inspection.deallocations > 0,
        "decoder output allocation was not observed: {inspection:?}"
    );
    assert_eq!(
        inspection.plaintext_deallocations, 0,
        "partial plaintext was freed without zeroization: {inspection:?}"
    );
    assert!(
        inspection.zeroized > 0,
        "decoder output was not wiped before deallocation: {inspection:?}"
    );
}

#[test]
fn malformed_base64_erases_partial_decoded_output() {
    let mut encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [FILL; PAYLOAD_LEN],
    )
    .into_bytes();
    encoded[PAYLOAD_LEN] = b'!';
    let encoded = String::from_utf8(encoded).unwrap();

    let inspection = inspect_rejected_decode(PayloadEncoding::Base64, &encoded);
    assert_partial_output_wiped(inspection);
}

#[test]
fn malformed_hex_erases_partial_decoded_output() {
    let mut encoded = "a5".repeat(PAYLOAD_LEN).into_bytes();
    let invalid = encoded.len() - 2;
    encoded[invalid..].copy_from_slice(b"gg");
    let encoded = String::from_utf8(encoded).unwrap();

    let inspection = inspect_rejected_decode(PayloadEncoding::HexLower, &encoded);
    assert_partial_output_wiped(inspection);
}

#[test]
fn response_growth_erases_the_replaced_plaintext_allocation() {
    INSPECTION.with(|cell| {
        let previous = cell.replace(Inspection {
            enabled: true,
            ..Inspection::default()
        });
        assert!(!previous.enabled, "nested response allocation inspection");
    });

    let mut response = zeroize::Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    response.extend_from_slice(&[FILL; PAYLOAD_LEN]);
    append_response_chunk(&mut response, &[FILL], PAYLOAD_LEN + 1).unwrap();
    drop(response);

    let inspection = INSPECTION.with(|cell| {
        let inspection = cell.get();
        cell.set(Inspection::default());
        inspection
    });
    assert_eq!(inspection.plaintext_deallocations, 0, "{inspection:?}");
    assert!(inspection.zeroized >= 2, "{inspection:?}");
}
