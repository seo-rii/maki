//! F02: every allocation returned by an untrusted encrypt provider is erased
//! before release when any item violates the encrypt contract.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use async_trait::async_trait;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

#[derive(Clone, Copy)]
struct Record {
    address: usize,
    released: bool,
    zeroed: bool,
}
const EMPTY: Record = Record {
    address: 0,
    released: false,
    zeroed: false,
};
thread_local! { static WATCHES: Cell<[Record; 8]> = const { Cell::new([EMPTY; 8]) }; }
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
// SAFETY: every allocation is initialized and inspected while still live;
// callbacks use only fixed-size thread-local state before delegating to System.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCHES.try_with(|watches| {
            let mut records = watches.get();
            for record in &mut records {
                if record.address == pointer as usize && !record.released {
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    record.released = true;
                    record.zeroed = bytes.iter().all(|byte| *byte == 0);
                }
            }
            watches.set(records);
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[derive(Clone, Copy)]
enum Fault {
    Echo,
    Count,
    Order,
    Index,
    Empty,
    Size,
    LaterEcho,
}
struct Provider(Fault);
fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "review-f02".into(),
        crypto_compatibility_id: "review-f02".into(),
        supported_plaintext_sizes: vec![512],
        max_ciphertext_size: 1024,
        stateless: true,
        retry_safe: false,
        batch: BatchCapability {
            supported: true,
            max_items: 4,
            max_bytes: 2048,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}
#[async_trait]
impl CryptoProvider for Provider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(caps())
    }
    async fn encrypt_batch(
        &self,
        _: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let count = items.len() + usize::from(matches!(self.0, Fault::Count));
        let mut out: Vec<_> = (0..count)
            .map(|i| {
                // Initialize spare capacity with sensitive bytes too: erasing just
                // the logical payload must not leave an older, truncated suffix.
                let mut data = vec![0xa5; 2048];
                data[..513].fill(0x32);
                data.truncate(513);
                CiphertextUnit {
                    unit_index: i as u64,
                    data,
                }
            })
            .collect();
        match self.0 {
            Fault::Echo => out[0].data[..512].fill(0xa5),
            Fault::Count => {}
            Fault::Order => out.swap(0, 1),
            Fault::Index => out[0].unit_index = 100,
            Fault::Empty => out[1].data.clear(),
            Fault::Size => out[1].data.resize(1100, 0xa5),
            Fault::LaterEcho => out[2].data[..512].fill(0xa5),
        }
        WATCHES.with(|watches| {
            let mut records = [EMPTY; 8];
            for (record, unit) in records.iter_mut().zip(&out) {
                record.address = unit.data.as_ptr() as usize;
            }
            watches.set(records);
        });
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
async fn rejected(fault: Fault) {
    let provider = CheckedProvider::new(Arc::new(Provider(fault)));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "review-f02".into(),
    };
    let input: Vec<_> = (0..3)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_slice(&[0xa5; 512]),
        })
        .collect();
    assert!(matches!(
        provider.encrypt_batch(&context, &input).await,
        Err(CryptoError::Contract(_))
    ));
    assert_outputs_erased();
}
fn assert_outputs_erased() {
    let records = WATCHES.with(|watches| watches.replace([EMPTY; 8]));
    assert!(
        records.iter().any(|record| record.address != 0),
        "provider returned no watched allocations"
    );
    for (i, record) in records
        .iter()
        .filter(|record| record.address != 0)
        .enumerate()
    {
        assert!(record.released, "output {i} was retained");
        assert!(record.zeroed, "output {i} retained bytes at deallocation");
    }
}
#[tokio::test]
async fn f02_echo_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Echo).await;
}
#[tokio::test]
async fn f02_count_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Count).await;
}
#[tokio::test]
async fn f02_order_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Order).await;
}
#[tokio::test]
async fn f02_index_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Index).await;
}
#[tokio::test]
async fn f02_empty_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Empty).await;
}
#[tokio::test]
async fn f02_size_erases_all_owned_encrypt_payloads() {
    rejected(Fault::Size).await;
}
#[tokio::test]
async fn f02_later_echo_erases_earlier_owned_encrypt_payloads() {
    rejected(Fault::LaterEcho).await;
}

#[tokio::test]
async fn f02_selftest_erases_a_malformed_owned_encrypt_batch() {
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "review-f02".into(),
    };
    assert!(maki_crypto::selftest::provider_self_test(
        &Provider(Fault::Count),
        &context,
        512,
        "review-f02"
    )
    .await
    .is_err());
    assert_outputs_erased();
}
