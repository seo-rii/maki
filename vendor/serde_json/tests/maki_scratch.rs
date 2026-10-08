//! Inspect live allocations before free; never inspect freed memory.
use serde::{de, Deserialize, Deserializer};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt;

#[derive(Clone, Copy, Default, Debug)]
struct Inspection {
    enabled: bool,
    frees: usize,
    secret_frees: usize,
    wiped_frees: usize,
}

thread_local! {
    static INSPECTION: Cell<Inspection> = const { Cell::new(Inspection {
        enabled: false,
        frees: 0,
        secret_frees: 0,
        wiped_frees: 0,
    }) };
}

struct InspectAllocator;

fn selected(layout: Layout) -> bool {
    layout.align() == 1 && layout.size() >= 8 && layout.size() <= 8192
}

// SAFETY: System owns every allocation. Selected allocations are initialized
// from the start, including spare capacity, so observing the complete live
// range immediately before System.dealloc is defined. TLS inspection allocates
// nothing, and is enabled only inside a test's parsing operation.
unsafe impl GlobalAlloc for InspectAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if selected(layout) {
            unsafe { System.alloc_zeroed(layout) }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = INSPECTION.try_with(|cell| {
            let mut inspection = cell.get();
            if inspection.enabled && selected(layout) {
                // SAFETY: selected allocations were initialized before use,
                // and remain live until the delegation below.
                let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                inspection.frees += 1;
                inspection.wiped_frees += usize::from(bytes.iter().all(|byte| *byte == 0));
                inspection.secret_frees += usize::from(bytes.windows(16).any(|window| {
                    window.iter().all(|byte| *byte == b'Q')
                        || window.iter().all(|byte| *byte == b'7')
                }));
                cell.set(inspection);
            }
        });
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectAllocator = InspectAllocator;

fn inspect(operation: impl FnOnce()) -> Inspection {
    INSPECTION.with(|cell| {
        assert!(!cell.get().enabled);
        cell.set(Inspection {
            enabled: true,
            ..Inspection::default()
        });
    });
    operation();
    INSPECTION.with(|cell| cell.replace(Inspection::default()))
}

fn assert_wiped(inspection: Inspection) {
    assert!(
        inspection.wiped_frees > 0,
        "no wiped parser allocation: {inspection:?}"
    );
    assert_eq!(
        inspection.secret_frees, 0,
        "parser freed secret bytes: {inspection:?}"
    );
}

struct DiscardString;

impl<'de> Deserialize<'de> for DiscardString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = DiscardString;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                assert!(!value.is_empty());
                Ok(DiscardString)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[test]
fn escaped_strings_erase_scratch_on_success_and_growth_for_all_inputs() {
    let wire = format!("\"{}\\uD83D\\uDE00\"", "\\u0051".repeat(1025));
    assert_wiped(inspect(|| {
        let _: DiscardString = serde_json::from_slice(wire.as_bytes()).unwrap();
    }));
    assert_wiped(inspect(|| {
        let _: DiscardString = serde_json::from_str(&wire).unwrap();
    }));
    assert_wiped(inspect(|| {
        let _: DiscardString = serde_json::from_reader(wire.as_bytes()).unwrap();
    }));
}

#[test]
fn malformed_escaped_strings_erase_partial_scratch_before_any_visitor() {
    for suffix in ["\\x\"", "\\uD800\"", "\\u12", ""] {
        let wire = format!("\"{}{suffix}", "\\u0051".repeat(1025));
        assert_wiped(inspect(|| {
            let result = serde_json::from_slice::<DiscardString>(wire.as_bytes());
            assert!(result.is_err());
            drop(result);
        }));
        assert_wiped(inspect(|| {
            let result = serde_json::from_reader::<_, DiscardString>(wire.as_bytes());
            assert!(result.is_err());
            drop(result);
        }));
    }
}

struct PanicString;

impl<'de> Deserialize<'de> for PanicString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = PanicString;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                panic!("test visitor panic");
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[test]
fn visitor_panic_erases_owned_deserializer_scratch_during_unwind() {
    let wire = format!("\"{}\"", "\\u0051".repeat(1025));
    assert_wiped(inspect(|| {
        let result = std::panic::catch_unwind(|| {
            // Own the Deserializer inside the unwind boundary. A caller that
            // retains it outside this boundary controls its eventual Drop.
            let mut deserializer = serde_json::Deserializer::from_str(&wire);
            let _ = PanicString::deserialize(&mut deserializer);
        });
        assert!(result.is_err(), "visitor did not panic");
        drop(result);
    }));
}

thread_local! {
    static PREVIOUS: Cell<(*const u8, usize)> = const { Cell::new((std::ptr::null(), 0)) };
}

struct CheckCleared;

impl<'de> Deserialize<'de> for CheckCleared {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = CheckCleared;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                PREVIOUS.with(|cell| {
                    let (pointer, previous_len) = cell.replace((value.as_ptr(), value.len()));
                    if !pointer.is_null() && value.len() < previous_len {
                        assert_eq!(pointer, value.as_ptr(), "fixture unexpectedly grew scratch");
                        // SAFETY: the same parser allocation is still live, the
                        // former string initialized previous_len bytes, and
                        // the current reference covers only the prefix.
                        let tail = unsafe {
                            std::slice::from_raw_parts(
                                pointer.add(value.len()),
                                previous_len - value.len(),
                            )
                        };
                        assert!(
                            tail.iter().all(|byte| *byte == 0),
                            "clear retained the previous string"
                        );
                    }
                });
                Ok(CheckCleared)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[test]
fn scratch_is_erased_before_reusing_it_for_a_shorter_string() {
    PREVIOUS.with(|cell| cell.set((std::ptr::null(), 0)));
    let wire = format!("[\"{}\",\"\\u0052\"]", "\\u0051".repeat(257));
    let _: Vec<CheckCleared> = serde_json::from_str(&wire).unwrap();
    PREVIOUS.with(|cell| cell.set((std::ptr::null(), 0)));
}

#[test]
fn integer128_temporaries_are_erased_on_success_and_overflow() {
    let success = "7".repeat(32);
    assert_wiped(inspect(|| {
        let _: i128 = serde_json::from_str(&success).unwrap();
        let _: u128 = serde_json::from_str(&success).unwrap();
    }));
    let overflow = "7".repeat(257);
    assert_wiped(inspect(|| {
        assert!(serde_json::from_str::<i128>(&overflow).is_err());
        assert!(serde_json::from_str::<u128>(&overflow).is_err());
    }));
}

#[test]
fn data_errors_erase_formatted_input_copies_and_keep_their_message() {
    let wire = format!("\"{}\"", "\\u0051".repeat(257));
    assert_wiped(inspect(|| {
        let error = serde_json::from_str::<bool>(&wire).err().unwrap();
        assert!(error.is_data());
        struct Discard;
        impl fmt::Write for Discard {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                Ok(())
            }
        }
        // Debug previously made another unguarded intermediate String.
        fmt::write(&mut Discard, format_args!("{error:?}")).unwrap();
        drop(error);
    }));
    let error = serde_json::from_str::<bool>("\"hello\"").err().unwrap();
    assert_eq!(
        error.to_string(),
        "invalid type: string \"hello\", expected a boolean at line 1 column 7"
    );
}

#[test]
fn unicode_and_escaped_object_keys_keep_serde_json_semantics() {
    let value: serde_json::Value =
        serde_json::from_str(r#"{"\u006b\u0065y":"line\n\uD83D\uDE00\u00df","key":"replacement"}"#)
            .unwrap();
    assert_eq!(value["key"], "replacement");
    let decoded: String = serde_json::from_str(r#""line\n\uD83D\uDE00\u00df""#).unwrap();
    assert_eq!(decoded, "line\n😀ß");
    for malformed in [r#""\uD800""#, r#""\uDC00""#, r#""\uD800\u0041""#] {
        assert!(serde_json::from_str::<String>(malformed).is_err());
    }
}
