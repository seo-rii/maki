//! The per-call plaintext-echo check (BUG-105) searches every encrypt result
//! for its own plaintext. It must not leave plaintext-derived state in
//! ordinary heap memory: such state is neither page-locked under
//! `secure-buffers` nor erased when freed. The search used to build a
//! failure table of one machine word per plaintext byte in a plain vector;
//! for a unit whose bytes take two values (an allocation bitmap, a 0x00/0xFF
//! block) that table alone reproduces the plaintext.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use async_trait::async_trait;
use maki_crypto::checked::{validate_encrypt_result, CheckedProvider};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

const UNIT: usize = 4096;
/// Nonce and tag of an AEAD profile: room for a framed echo.
const OVERHEAD: usize = 28;

/// Heap blocks allocated on this thread while armed. Blocks freed before
/// disarming must be all zeros by then.
#[derive(Clone, Copy)]
struct Watch {
    armed: bool,
    live: [usize; 16],
    untracked: usize,
    allocations: usize,
    unerased: usize,
    largest_unerased: usize,
}

impl Watch {
    const IDLE: Watch = Watch {
        armed: false,
        live: [0; 16],
        untracked: 0,
        allocations: 0,
        unerased: 0,
        largest_unerased: 0,
    };
}

thread_local! { static WATCH: Cell<Watch> = const { Cell::new(Watch::IDLE) }; }

fn track(pointer: *mut u8) {
    if pointer.is_null() {
        return;
    }
    let _ = WATCH.try_with(|watch| {
        let mut state = watch.get();
        if state.armed {
            state.allocations += 1;
            match state.live.iter_mut().find(|slot| **slot == 0) {
                Some(slot) => *slot = pointer as usize,
                None => state.untracked += 1,
            }
            watch.set(state);
        }
    });
}

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: every call delegates to System with the same layout. A watched
// block is inspected while still live, before it is returned to System, and
// the callbacks touch only fixed-size thread-local state.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        track(pointer);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        track(pointer);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            let mut state = watch.get();
            if let Some(slot) = state
                .live
                .iter_mut()
                .find(|slot| **slot == pointer as usize)
            {
                *slot = 0;
                let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                if bytes.iter().any(|byte| *byte != 0) {
                    state.unerased += 1;
                    state.largest_unerased = state.largest_unerased.max(layout.size());
                }
                watch.set(state);
            }
        });
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn arm() {
    WATCH.with(|watch| {
        watch.set(Watch {
            armed: true,
            ..Watch::IDLE
        })
    });
}

fn disarm() -> Watch {
    let watch = WATCH.with(|watch| watch.replace(Watch::IDLE));
    assert_eq!(watch.untracked, 0, "too many live allocations to watch");
    watch
}

fn assert_erased(watch: &Watch, case: &str) {
    assert_eq!(
        watch.unerased, 0,
        "{case}: checking a {UNIT}-byte unit freed {} unerased heap block(s), the largest \
         {} bytes: plaintext-derived scan state outside guarded memory",
        watch.unerased, watch.largest_unerased
    );
}

/// A secret allocation bitmap: 0x00/0xFF bytes from a fixed LCG.
fn bitmap() -> SecretBuffer {
    let mut secret = SecretBuffer::zeroed(UNIT);
    let mut x: u32 = 0x2545_F491;
    for byte in secret.expose_mut() {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = if (x >> 16) & 1 == 1 { 0xFF } else { 0x00 };
    }
    secret
}

fn items() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 7,
        data: bitmap(),
    }]
}

/// Bytes unrelated to the plaintext, as a cipher returns.
fn ciphertext() -> Vec<u8> {
    (0..UNIT + OVERHEAD)
        .map(|n| (n * 131 % 251) as u8 ^ 0x5A)
        .collect()
}

/// nonce ‖ plaintext ‖ tag: an integrity-only (null cipher) answer.
fn framed_echo(item: &PlaintextUnit) -> Vec<u8> {
    [&[0x5A; 12][..], item.data.expose(), &[0xA5; 16]].concat()
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "review-scan-memory".into(),
        crypto_compatibility_id: "review-scan-memory-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: (UNIT + OVERHEAD) as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 1,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Verified,
        context_binding: Capability::Verified,
        replay_protection: Capability::Absent,
    }
}

#[test]
fn checking_an_encrypt_result_frees_no_unerased_scan_state() {
    let caps = caps();
    let items = items();
    for (case, data, accepted) in [
        ("ciphertext", ciphertext(), true),
        ("framed echo", framed_echo(&items[0]), false),
    ] {
        let out = [CiphertextUnit {
            unit_index: 7,
            data,
        }];
        arm();
        let result = validate_encrypt_result(&items, &out, &caps);
        let watch = disarm();
        match result {
            Ok(()) => assert!(accepted, "{case}: an echo was accepted"),
            Err(CryptoError::Contract(_)) => assert!(!accepted, "{case}: refused"),
            Err(other) => panic!("{case}: unexpected {other:?}"),
        }
        assert_erased(&watch, case);
    }
}

#[test]
fn an_accepted_encrypt_result_is_checked_without_heap_allocation() {
    // Nothing the scan derives from the plaintext may reach ordinary heap
    // memory, which `secure-buffers` does not lock.
    let caps = caps();
    let items = items();
    let out = [CiphertextUnit {
        unit_index: 7,
        data: ciphertext(),
    }];
    arm();
    let result = validate_encrypt_result(&items, &out, &caps);
    let watch = disarm();
    result.expect("unrelated ciphertext is accepted");
    assert_eq!(
        watch.allocations, 0,
        "checking a {UNIT}-byte unit allocated {} heap block(s)",
        watch.allocations
    );
}

/// Answers with `ciphertext()` or a framed echo, then starts watching the
/// allocations its caller makes while validating the answer.
struct Answering {
    echo: bool,
}

#[async_trait]
impl CryptoProvider for Answering {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(caps())
    }
    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let out = items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: if self.echo {
                    framed_echo(item)
                } else {
                    ciphertext()
                },
            })
            .collect();
        arm();
        Ok(out)
    }
    async fn decrypt_batch(
        &self,
        _: &CryptoContext,
        _: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        unreachable!()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn checked_provider_frees_no_unerased_scan_state() {
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 3,
        crypto_compatibility_id: "review-scan-memory-v1".into(),
    };
    let items = items();
    for (case, echo) in [("ciphertext", false), ("framed echo", true)] {
        let checked = CheckedProvider::pinned(Arc::new(Answering { echo }), UNIT as u32);
        let result = checked.encrypt_batch(&context, &items).await;
        let watch = disarm();
        assert!(watch.armed, "{case}: the provider was not called");
        match result {
            Ok(_) => assert!(!echo, "{case}: an echo was accepted"),
            Err(CryptoError::Contract(_)) => assert!(echo, "{case}: refused"),
            Err(other) => panic!("{case}: unexpected {other:?}"),
        }
        assert_erased(&watch, case);
    }
}
