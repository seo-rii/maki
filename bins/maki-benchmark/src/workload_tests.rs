use super::*;
use async_trait::async_trait;
use maki_core::engine::{CheckpointPolicy, EngineOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};
use std::sync::atomic::AtomicBool;

struct ReplayProvider {
    inner: FakeCryptoProvider,
    stale: AtomicBool,
    writes: Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl CryptoProvider for ReplayProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        tokio::task::yield_now().await;
        let encrypted = self.inner.encrypt_batch(context, items).await?;
        for item in items.iter().filter(|item| item.unit_index == 0) {
            self.writes
                .lock()
                .unwrap()
                .push(item.data.expose().to_vec());
        }
        Ok(encrypted)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut plaintext = self.inner.decrypt_batch(context, items).await?;
        if self.stale.load(Ordering::Acquire) {
            let writes = self.writes.lock().unwrap();
            for item in plaintext.iter_mut().filter(|item| item.unit_index == 0) {
                item.data = SecretBuffer::from_slice(&writes[writes.len() - 2]);
            }
        }
        Ok(plaintext)
    }
}

async fn fixture() -> (Engine, Arc<ReplayProvider>) {
    let provider = Arc::new(ReplayProvider {
        inner: FakeCryptoProvider::new(4096),
        stale: AtomicBool::new(false),
        writes: Mutex::new(Vec::new()),
    });
    let engine = attach_provider(provider.clone()).await;
    provider.writes.lock().unwrap().clear();
    (engine, provider)
}

async fn attach_provider(provider: Arc<dyn CryptoProvider>) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: "00000000-0000-0000-0000-000000000046".parse().unwrap(),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 4096, 512, 4104, 128 * 4096, 16 * 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Engine::attach(
        backing,
        provider,
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

/// Retain each setup ciphertext, then acknowledge selected encrypt calls with
/// that old value. The real Engine completes writes successfully, while a later
/// read sees the setup bytes. No production fault switch is needed.
struct AckWithoutDataProvider {
    inner: FakeCryptoProvider,
    armed: AtomicBool,
    discard_unit: Option<u64>,
    setup_ciphertexts: Mutex<HashMap<u64, Vec<u8>>>,
    discarded: AtomicU64,
}

#[async_trait]
impl CryptoProvider for AckWithoutDataProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let mut encrypted = self.inner.encrypt_batch(context, items).await?;
        if self.armed.load(Ordering::Acquire) {
            let mut setup = self.setup_ciphertexts.lock().unwrap();
            for item in &mut encrypted {
                if let Some(old) = setup.get(&item.unit_index) {
                    if self.discard_unit.is_none_or(|unit| unit == item.unit_index) {
                        item.data.clone_from(old);
                        self.discarded.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    setup.insert(item.unit_index, item.data.clone());
                }
            }
        }
        Ok(encrypted)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

async fn faulty_fixture(discard_unit: Option<u64>) -> (Engine, Arc<AckWithoutDataProvider>) {
    let provider = Arc::new(AckWithoutDataProvider {
        inner: FakeCryptoProvider::new(4096),
        armed: AtomicBool::new(false),
        discard_unit,
        setup_ciphertexts: Mutex::new(HashMap::new()),
        discarded: AtomicU64::new(0),
    });
    let engine = attach_provider(provider.clone()).await;
    provider.armed.store(true, Ordering::Release);
    (engine, provider)
}

#[tokio::test]
async fn mixed_final_verification_rejects_acknowledged_but_discarded_writes() {
    // The wrapped 50% plan and the no-wrap default-sized working set both read
    // only setup slots during measurement. Each must fail on final readback.
    for (slots, ops, read_percent) in [(100, 1000, 50), (32, 32, 70)] {
        let (engine, provider) = faulty_fixture(None).await;
        let mut options = options();
        options.ops = ops;
        options.read_percent = Some(read_percent);
        let result = run(engine, &options, slots * 4096).await;
        let error = result
            .err()
            .expect("discarded measured writes passed the benchmark");
        assert!(
            error.starts_with("final verification failed at offset 0"),
            "{error}"
        );
        assert_eq!(
            provider.discarded.load(Ordering::Relaxed),
            ops - ops * read_percent / 100
        );
    }
}

#[tokio::test]
async fn mixed_final_verification_checks_the_last_write_without_a_later_measured_read() {
    // Index 6 is the last measured operation, a write to unit 6. All earlier
    // writes and every measured read are correct; only final readback can fail.
    let (engine, provider) = faulty_fixture(Some(6)).await;
    let mut options = options();
    options.ops = 7;
    options.read_percent = Some(50);
    let result = run(engine, &options, 8 * 4096).await;
    let error = result
        .err()
        .expect("the last discarded write passed the benchmark");
    assert_eq!(
        error,
        "final verification failed at offset 24576 (expected generation 1)"
    );
    assert_eq!(provider.discarded.load(Ordering::Relaxed), 1);
}

fn options() -> Options {
    Options {
        config_path: String::new(),
        destroy_data: false,
        json: true,
        fua: false,
        ops: 16,
        io_size: 4096,
        concurrency: 8,
        random: false,
        read_percent: None,
        working_set: Some(4096),
        flush_every: None,
        seed: 1,
    }
}

fn samples() -> Samples {
    Samples {
        writes: Latencies::new(),
        reads: Latencies::new(),
        flushes: Latencies::new(),
    }
}

#[tokio::test]
async fn same_address_previous_generation_fails_the_real_read_phase() {
    let (engine, provider) = fixture().await;
    let options = options();
    let oracle = Arc::new(Oracle::new(1).unwrap());
    let pending = Arc::new(Pending::default());
    let mut samples = samples();
    phase(
        &engine,
        &options,
        1,
        Kind::Write,
        &oracle,
        &pending,
        &mut samples,
    )
    .await
    .unwrap();
    let generations: Vec<_> = provider
        .writes
        .lock()
        .unwrap()
        .iter()
        .map(|bytes| u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
        .collect();
    assert_eq!(generations, (1..=16).collect::<Vec<_>>());
    provider.stale.store(true, Ordering::Release);
    let error = phase(
        &engine,
        &options,
        1,
        Kind::Read,
        &oracle,
        &pending,
        &mut samples,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        "read verification failed at offset 0 (expected generation 16)"
    );
    assert_eq!(samples.reads.report().samples, 0);
    assert_eq!(oracle.generations[0].load(Ordering::Acquire), 16);
    provider.stale.store(false, Ordering::Release);
    phase(
        &engine,
        &options,
        1,
        Kind::Read,
        &oracle,
        &pending,
        &mut samples,
    )
    .await
    .unwrap();
    assert_eq!(samples.reads.report().samples, 16);
}

#[tokio::test]
async fn hot_address_mixed_reads_follow_successful_writes_in_submission_order() {
    let (engine, provider) = fixture().await;
    let mut options = options();
    options.ops = 32;
    options.read_percent = Some(50);
    options.random = true;
    let result = run(engine, &options, 4096).await.unwrap();
    assert_eq!(result.reads.report().samples, 16);
    assert_eq!(result.writes.report().samples, 16);
    assert_eq!(result.resources.oracle_generation_bytes, 8);
    assert_eq!(result.resources.pending_operations_at_exit, 0);
    assert_eq!(result.verification.written_slots, 1);
    assert_eq!(result.verification.read_after_write_verified_slots, 1);
    assert_eq!(result.verification.final_sweep_verified_slots, 1);
    let generations: Vec<_> = provider
        .writes
        .lock()
        .unwrap()
        .iter()
        .map(|bytes| u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
        .collect();
    assert_eq!(generations, (0..=16).collect::<Vec<_>>());
}

#[tokio::test]
async fn measured_read_coverage_survives_a_later_unread_overwrite() {
    let (engine, _) = fixture().await;
    let mut options = options();
    options.ops = 1;
    let oracle = Arc::new(Oracle::new(1).unwrap());
    let pending = Arc::new(Pending::default());
    let mut samples = samples();
    for kind in [Kind::Write, Kind::Read, Kind::Write] {
        phase(&engine, &options, 1, kind, &oracle, &pending, &mut samples)
            .await
            .unwrap();
    }
    assert_eq!(oracle.generation(0), 2);
    assert_eq!(samples.reads.report().samples, 1);
    let verification = verify_final(&engine, &options, &oracle).await.unwrap();
    assert_eq!(verification.written_slots, 1);
    assert_eq!(verification.read_after_write_verified_slots, 1);
    assert_eq!(verification.final_sweep_verified_slots, 1);
    assert_eq!(samples.reads.report().samples, 1);
}

#[tokio::test]
async fn rejected_write_does_not_advance_expected_generation() {
    let (engine, provider) = fixture().await;
    let mut options = options();
    options.ops = 1;
    let oracle = Arc::new(Oracle::new(1).unwrap());
    provider
        .inner
        .fail_next([CryptoError::NonRetryableRequest("injected".into())]);
    let result = phase(
        &engine,
        &options,
        1,
        Kind::Write,
        &oracle,
        &Arc::new(Pending::default()),
        &mut samples(),
    )
    .await;
    assert!(result.unwrap_err().contains("write at offset 0 failed"));
    assert_eq!(oracle.generations[0].load(Ordering::Acquire), 0);
    assert!(provider.writes.lock().unwrap().is_empty());
}

#[test]
fn oracle_capacity_has_an_explicit_byte_bound() {
    let max_slots = MAX_ORACLE_BYTES / std::mem::size_of::<AtomicU64>() as u64;
    assert!(validate_oracle_capacity(max_slots).is_ok());
    assert!(validate_oracle_capacity(max_slots + 1).is_err());
    assert!(validate_oracle_capacity(u64::MAX).is_err());
    let oracle = Oracle::new(512).unwrap();
    assert_eq!(oracle.generations.len(), 512);
}
