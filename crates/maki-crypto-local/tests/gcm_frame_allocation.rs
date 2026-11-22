use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_local::{keysource::MapKeySource, AesGcmSivProvider};
use uuid::Uuid;

// Distinctive payload size keeps unrelated runtime allocations out of the count.
const UNIT: usize = 4093;
thread_local! {
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
