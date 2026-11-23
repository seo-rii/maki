//! Audit round 4 (plaintext-echo scan, checked.rs `contains_plaintext`):
//! the KMP failure table the scan builds for every encrypt result is a pure
//! function of the plaintext, lives in an ordinary `Vec<usize>` (not page
//! locked) and is freed without zeroization. For a unit whose bytes take two
//! values (a bitmap, a sparse block) the table alone reconstructs the
//! plaintext up to swapping those two values.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

const UNIT: usize = 4093; // distinctive: the table is UNIT * 8 bytes
const TABLE: usize = UNIT * std::mem::size_of::<usize>();

struct Capture(UnsafeCell<[u8; TABLE]>);
// SAFETY: written once by the allocator before CAPTURED is published, read
// only after it is.
unsafe impl Sync for Capture {}
static CAPTURE: Capture = Capture(UnsafeCell::new([0; TABLE]));
static ARMED: AtomicBool = AtomicBool::new(false);
static CAPTURED: AtomicBool = AtomicBool::new(false);

struct Spy;
// SAFETY: delegates to System; reads only the live block being freed.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == TABLE && ARMED.swap(false, Ordering::SeqCst) {
            unsafe { std::ptr::copy_nonoverlapping(ptr, CAPTURE.0.get().cast::<u8>(), TABLE) };
            CAPTURED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Spy = Spy;

/// Returns bytes unrelated to the plaintext, as a cipher would.
struct Opaque;

#[async_trait]
impl CryptoProvider for Opaque {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "opaque".into(),
            crypto_compatibility_id: "opaque-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32 + 28,
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
        })
    }
    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        Ok(items
            .iter()
            .map(|i| CiphertextUnit {
                unit_index: i.unit_index,
                data: (0..UNIT + 28)
                    .map(|n| (n * 131 % 251) as u8 ^ 0x5A)
                    .collect(),
            })
            .collect())
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
async fn freed_scan_table_reconstructs_two_valued_plaintext() {
    // A secret "bitmap": 0x00/0xFF bytes from a fixed LCG.
    let mut secret = SecretBuffer::zeroed(UNIT);
    let mut x: u32 = 0x2545_F491;
    for byte in secret.expose_mut() {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *byte = if (x >> 16) & 1 == 1 { 0xFF } else { 0x00 };
    }
    let items = [PlaintextUnit {
        unit_index: 7,
        data: secret,
    }];
    let checked = CheckedProvider::new(Arc::new(Opaque));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 3,
        crypto_compatibility_id: "opaque-v1".into(),
    };
    ARMED.store(true, Ordering::SeqCst);
    checked.encrypt_batch(&context, &items).await.unwrap();
    ARMED.store(false, Ordering::SeqCst);
    assert!(CAPTURED.load(Ordering::SeqCst), "no scan table was freed");

    // SAFETY: published by CAPTURED above; nothing writes it again.
    let raw = unsafe { &*CAPTURE.0.get() };
    let table: Vec<usize> = raw
        .chunks_exact(std::mem::size_of::<usize>())
        .map(|c| usize::from_ne_bytes(c.try_into().unwrap()))
        .collect();
    assert!(table.iter().any(|&v| v != 0), "the freed table was erased");

    // Rebuild the plaintext from the freed table alone (binary alphabet:
    // a zero border means "differs from the first byte").
    let mut rebuilt = vec![0u8; UNIT];
    for i in 1..UNIT {
        rebuilt[i] = if table[i] > 0 {
            rebuilt[table[i] - 1]
        } else {
            0xFF
        };
    }
    let plain = items[0].data.expose();
    let complement: Vec<u8> = rebuilt.iter().map(|b| !b).collect();
    let recovered = rebuilt == plain || complement == plain;
    let agree = rebuilt.iter().zip(plain).filter(|(a, b)| a == b).count();
    eprintln!(
        "recovered={recovered}; positions agreeing with plaintext (or its complement): {}",
        agree.max(UNIT - agree)
    );
    assert!(
        !recovered,
        "the plaintext ({UNIT} bytes) was reconstructed from a freed, unzeroized scan table"
    );
}
