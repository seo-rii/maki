//! Audit round 3 (nbdkit-adapter): durability of requests the adapter splits
//! into several engine calls, and the panic boundary's effect on admission.
//!
//! - A FUA write longer than `nbd.maximum_io` carries FUA on its last chunk
//!   only; every earlier chunk must still survive a crash that drops every
//!   unsynced operation.
//! - A FUA WRITE_ZEROES with `may_trim` on a discard volume is a head write,
//!   a unit trim and a tail write; only the last step carries FUA.
//! - A panic inside one chunk must release the drain gate's callback count
//!   so a later shutdown neither hangs nor reports a failure.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::adapter::{NbdAdapter, EIO};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const BLOCK: u32 = 512;
const UNIT: u32 = 4096;
const SIZE: u64 = 256 * UNIT as u64; // 1 MiB
const MAX_IO: u64 = 8192;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0xA3_0001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, SIZE, 64 * UNIT as u64).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            // The worker must not checkpoint behind the test's back.
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        limits: EngineLimits {
            max_request_bytes: MAX_IO,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn adapter(backing: &Arc<CrashableBacking>, provider: Arc<dyn CryptoProvider>) -> NbdAdapter {
    let rt = runtime();
    let engine = rt
        .block_on(Engine::attach(
            backing.clone() as Arc<dyn Backing>,
            provider,
            options(),
        ))
        .unwrap();
    NbdAdapter::from_engine(engine, rt)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) | 1)
        .collect()
}

/// A 20 KiB FUA write against an 8 KiB maximum: three engine writes, only
/// the last with FUA. A power loss that drops every unsynced operation must
/// keep all 20 KiB.
#[test]
fn chunked_fua_write_survives_a_total_power_loss() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let a = adapter(&backing, Arc::new(FakeCryptoProvider::new(UNIT)));
    assert_eq!(a.block_sizes(), (BLOCK, UNIT, MAX_IO as u32));
    // Unit-misaligned start so every chunk boundary is inside a unit (RMW).
    let offset = 3 * BLOCK as u64;
    let data = pattern(20 * 1024, 7);
    a.pwrite(&data, offset, true).unwrap();
    backing.crash_all_lost();
    drop(a);

    let b = adapter(&backing, Arc::new(FakeCryptoProvider::new(UNIT)));
    let mut read = vec![0u8; data.len()];
    b.pread(&mut read, offset).unwrap();
    assert_eq!(read, data, "a FUA-acknowledged chunked write lost data");
}

/// WRITE_ZEROES + FUA + may_trim on a discard volume, unit-misaligned at both
/// ends: head zero write, unit trim, tail zero write (FUA on the tail only).
#[test]
fn chunked_fua_zero_with_trim_survives_a_total_power_loss() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    let a = adapter(&backing, Arc::new(FakeCryptoProvider::new(UNIT)));
    assert!(a.can_trim());
    let before = pattern(16 * UNIT as usize, 9);
    a.pwrite(&before, 0, true).unwrap();
    // Zero [1.5 KiB, 13.5 KiB + 512): head in unit 0, whole units 1..=2,
    // tail in unit 3; plus a long zero that needs several write chunks.
    let (offset, len) = (3 * BLOCK as u64, 3 * UNIT as usize);
    a.zero(offset, len, true, true).unwrap();
    let (offset2, len2) = (8 * UNIT as u64 + 512, 6 * UNIT as usize + 1024);
    a.zero(offset2, len2, false, true).unwrap();
    backing.crash_all_lost();
    drop(a);

    let b = adapter(&backing, Arc::new(FakeCryptoProvider::new(UNIT)));
    let mut read = vec![0xEEu8; before.len()];
    b.pread(&mut read, 0).unwrap();
    let mut expected = before.clone();
    expected[offset as usize..offset as usize + len].fill(0);
    expected[offset2 as usize..offset2 as usize + len2].fill(0);
    assert_eq!(read, expected, "FUA-acknowledged zeroes did not survive");
}

/// Encrypt panics for one unit index: the second chunk of a chunked write.
struct PanicOnUnit {
    inner: FakeCryptoProvider,
    unit: u64,
    armed: AtomicBool,
}

#[async_trait]
impl CryptoProvider for PanicOnUnit {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if self.armed.load(Ordering::SeqCst) && items.iter().any(|i| i.unit_index == self.unit) {
            panic!("audit3: injected encrypt panic");
        }
        self.inner.encrypt_batch(context, items).await
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if self.armed.load(Ordering::SeqCst) && items.iter().any(|i| i.unit_index == self.unit) {
            panic!("audit3: injected decrypt panic");
        }
        self.inner.decrypt_batch(context, items).await
    }
}

/// A panic in the middle of a chunked request: EIO, the admission count is
/// released, and shutdown completes (bounded wait) and releases the lock.
#[test]
fn a_panic_in_a_later_chunk_does_not_wedge_drain() {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    let provider = Arc::new(PanicOnUnit {
        inner: FakeCryptoProvider::new(UNIT),
        unit: 5,
        armed: AtomicBool::new(false),
    });
    let a = Arc::new(adapter(&backing, provider.clone()));
    a.pwrite(&pattern(8 * UNIT as usize, 3), 0, true).unwrap();
    provider.armed.store(true, Ordering::SeqCst);
    // Chunks: units 0-1, 2-3, 4-5 (panics), 6-7.
    let err = a
        .pwrite(&pattern(8 * UNIT as usize, 4), 0, true)
        .unwrap_err();
    assert_eq!(err.errno, EIO, "{err}");
    let mut buf = vec![0u8; 8 * UNIT as usize];
    let err = a.pread(&mut buf, 0).unwrap_err();
    assert_eq!(err.errno, EIO, "{err}");
    provider.armed.store(false, Ordering::SeqCst);
    // Later requests are still served.
    a.pread(&mut buf, 0).unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let closer = {
        let a = a.clone();
        std::thread::spawn(move || tx.send(a.shutdown()).unwrap())
    };
    let outcome = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("shutdown hung after a panicking callback (leaked admission?)");
    closer.join().unwrap();
    outcome.unwrap();
    assert!(
        backing.try_lock(maki_format::layout::VOLUME_LOCK).is_ok(),
        "volume lock retained after shutdown"
    );
}
