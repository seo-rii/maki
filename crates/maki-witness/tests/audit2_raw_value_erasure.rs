//! Round-2 audit: which owned raw_value copies reach the allocator un-erased.
//!
//! vendor/README.md: "Passing an owned String to an arbitrary visitor
//! transfers cleanup responsibility at `visit_string`; the library's own
//! visitors immediately adopt it again." `&RawValue`'s own seed
//! (`ReferenceFromString`) does not implement `visit_string`, so serde's
//! default drops the owned raw text as an ordinary String.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use serde_json::value::RawValue;

struct Observer;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static RETAINED: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());
const MARKER: &[u8] = b"AUDIT2-RAW-SECRET-MARKER";

unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Initialize every byte so the observation below is defined.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if OBSERVE.load(Ordering::SeqCst) {
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            if bytes.windows(MARKER.len()).any(|w| w == MARKER) {
                RETAINED.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

fn retained_by<T>(work: impl FnOnce() -> T) -> usize {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    RETAINED.store(0, Ordering::SeqCst);
    OBSERVE.store(true, Ordering::SeqCst);
    let output = work();
    OBSERVE.store(false, Ordering::SeqCst);
    // Caller-owned outputs are dropped outside the observation window.
    drop(output);
    RETAINED.load(Ordering::SeqCst)
}

fn wire() -> String {
    format!("{{\"k\":\"{}\"}}", std::str::from_utf8(MARKER).unwrap())
}

#[test]
fn audit2_controls_erase_private_raw_copies() {
    // Borrowed (the witness path) and boxed reader/value paths: no private copy.
    let input = wire();
    assert_eq!(
        retained_by(|| serde_json::from_str::<&RawValue>(&input).map(|r| r.get().len())),
        0
    );
    assert_eq!(
        retained_by(|| serde_json::from_reader::<_, Box<RawValue>>(input.as_bytes())),
        0
    );
    let value: serde_json::Value = serde_json::from_str(&input).unwrap();
    assert_eq!(
        // Borrow the Value: consuming it would drop its caller-owned strings.
        retained_by(|| <Box<RawValue> as serde::Deserialize>::deserialize(&value)),
        0
    );
}

#[test]
fn audit2_reference_raw_value_from_owned_text_drops_it_unerased() {
    let input = wire();
    let reader = retained_by(|| {
        let mut de = serde_json::Deserializer::from_reader(input.as_bytes());
        let result = <&RawValue as serde::Deserialize>::deserialize(&mut de).map(|_| ());
        assert!(result.is_err());
    });
    let value: serde_json::Value = serde_json::from_str(&input).unwrap();
    let from_value = retained_by(|| {
        let result = <&RawValue as serde::Deserialize>::deserialize(&value).map(|_| ());
        assert!(result.is_err());
    });
    println!("un-erased deallocations holding the raw text: from_reader {reader}, Value {from_value}");
    assert_eq!(
        (reader, from_value),
        (0, 0),
        "&RawValue's seed let serde's default visit_string free the owned raw copy un-erased"
    );
}
