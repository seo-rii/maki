use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider};
use uuid::Uuid;

// Distinctive payload size keeps unrelated runtime allocations out of the count.
const UNIT: usize = 4093;
const PROFILE: &str = "profile-for-the-associated-data-allocation-regression";
const AAD_LEN: usize = 16 + 8 + 4 + PROFILE.len();
thread_local! {
    static AAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
    static PAYLOAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
}

struct Allocator;

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: all allocation and deallocation is delegated to System.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == UNIT {
            PAYLOAD_ALLOCS.with(|count| count.set(count.get() + 1));
        }
        if layout.size() == AAD_LEN {
            AAD_ALLOCS.with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[tokio::test]
async fn encrypts_directly_in_the_framed_output_allocation() {
    let mut keys = MapKeySource::new();
    keys.insert("test-key", vec![35; 32]);
    let provider = AesGcmSivProvider::new(&keys, "test-key", UNIT as u32, "test-profile").unwrap();
    let context = CryptoContext {
        volume_uuid: Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "test-profile".into(),
    };
    let input = [PlaintextUnit {
        unit_index: 17,
        data: SecretBuffer::from_slice(&[0x79; UNIT]),
    }];
    let before = PAYLOAD_ALLOCS.with(Cell::get);
    let frames = provider.encrypt_batch(&context, &input).await.unwrap();
    assert_eq!(PAYLOAD_ALLOCS.with(Cell::get), before);
    assert_eq!(frames[0].data.len(), UNIT + 28);
    let decoded = provider.decrypt_batch(&context, &frames).await.unwrap();
    assert_eq!(decoded[0].data.expose(), input[0].data.expose());
}

#[tokio::test]
async fn associated_data_allocations_are_shared_within_each_batch() {
    let mut keys = MapKeySource::new();
    keys.insert("test-key", vec![35; 32]);
    let provider = AesGcmSivProvider::new(&keys, "test-key", UNIT as u32, PROFILE).unwrap();
    let ctx = CryptoContext {
        volume_uuid: Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: PROFILE.into(),
    };
    let input: Vec<_> = [19, 4, u64::MAX]
        .into_iter()
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_slice(&[0x79; UNIT]),
        })
        .collect();
    let before = AAD_ALLOCS.with(Cell::get);
    assert!(provider.encrypt_batch(&ctx, &[]).await.unwrap().is_empty());
    assert!(provider.decrypt_batch(&ctx, &[]).await.unwrap().is_empty());
    assert_eq!(AAD_ALLOCS.with(Cell::get), before);
    let mut frames = provider.encrypt_batch(&ctx, &input).await.unwrap();
    assert!(AAD_ALLOCS.with(Cell::get) - before <= 1);
    let before = AAD_ALLOCS.with(Cell::get);
    let plain = provider.decrypt_batch(&ctx, &frames).await.unwrap();
    assert!(AAD_ALLOCS.with(Cell::get) - before <= 1);
    for (actual, expected) in plain.iter().zip(&input) {
        assert_eq!(actual.unit_index, expected.unit_index);
        assert_eq!(actual.data, expected.data);
    }
    frames[1].unit_index = frames[0].unit_index;
    assert!(provider.decrypt_batch(&ctx, &frames).await.is_err());
}
