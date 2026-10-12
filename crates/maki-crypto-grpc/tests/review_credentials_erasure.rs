//! Inspect live allocations immediately before deallocation, never after free.
use maki_crypto::{BatchCapability, Capability, CryptoCapabilities};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct Observer;
static POINTER: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicBool = AtomicBool::new(false);
static ERASED: AtomicBool = AtomicBool::new(false);
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if POINTER.load(Ordering::SeqCst) == pointer as usize {
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            ERASED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            RELEASED.store(true, Ordering::SeqCst);
            POINTER.store(0, Ordering::SeqCst);
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

fn watch(value: &str) {
    POINTER.store(value.as_ptr() as usize, Ordering::SeqCst);
    RELEASED.store(false, Ordering::SeqCst);
    ERASED.store(false, Ordering::SeqCst);
}
fn spec() -> GrpcProviderSpec {
    let credential = "M".repeat(256);
    watch(&credential);
    GrpcProviderSpec {
        url: "malformed-url".into(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![("authorization".into(), credential)],
        capabilities: CryptoCapabilities {
            provider_id: "remote-grpc".into(),
            crypto_compatibility_id: "review-v1".into(),
            supported_plaintext_sizes: vec![4096],
            max_ciphertext_size: 4384,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(1),
        max_message_bytes: 65536,
    }
}
fn assert_erased(case: &str) {
    assert!(
        RELEASED.load(Ordering::SeqCst),
        "{case}: credential not released"
    );
    assert!(
        ERASED.load(Ordering::SeqCst),
        "{case}: credential survived in allocation"
    );
}
#[test]
fn every_owned_spec_and_provider_erases_credentials() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    drop(spec());
    assert_erased("spec drop");
    let original = spec();
    let cloned = original.clone();
    watch(&cloned.metadata[0].1);
    drop(cloned);
    assert_erased("clone drop");
    watch(&original.metadata[0].1);
    drop(original);
    assert_erased("original drop");
    assert!(GrpcCryptoProvider::new(spec()).is_err());
    assert_erased("bad URL");
    let mut valid = spec();
    valid.url = "http://127.0.0.1:7000".into();
    drop(GrpcCryptoProvider::new(valid).unwrap());
    assert_erased("provider drop");
    let mut invalid_metadata = spec();
    invalid_metadata.url = "http://127.0.0.1:7000".into();
    invalid_metadata.metadata[0].0 = "bad key".into();
    assert!(GrpcCryptoProvider::new(invalid_metadata).is_err());
    assert_erased("bad metadata");
}
