//! BUG-049: batch bytes mean plaintext bytes, independently of encoded size.
use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::sync::Arc;

#[path = "../../maki-crypto/tests/common/compact_provider.rs"]
mod compact;
use compact::{CompactProvider, UNIT};

fn config(resident: u64) -> SchedulerConfig {
    SchedulerConfig {
        target_items: 1,
        target_bytes: UNIT as u64,
        max_items: 2,
        max_bytes: UNIT as u64,
        max_pending_ciphertext_bytes: resident,
        ..Default::default()
    }
}
async fn engine(provider: Arc<dyn CryptoProvider>) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(49),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(
                512,
                UNIT,
                512,
                UNIT + 8,
                64 * UNIT as u64,
                16 * UNIT as u64,
            )
            .unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    Engine::attach(
        backing as Arc<dyn Backing>,
        provider,
        EngineOptions {
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            clock: Some(Arc::new(ManualClock::new())),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn small_ciphertexts_support_individual_combined_and_partial_reads() {
    let short = Arc::new(CompactProvider::new(2, UNIT as u64, true));
    let provider = Arc::new(BatchScheduler::with_unit_size(
        short.clone(),
        config(16 * 1024),
        Arc::new(ManualClock::new()),
        UNIT,
    ));
    let engine = engine(provider).await;
    let mut data = vec![0x49; UNIT as usize];
    data.extend(vec![0x91; UNIT as usize]);
    engine.write(0, &data, true).await.unwrap();
    engine.checkpoint().await.unwrap();
    for unit in 0..2 {
        let offset = unit * UNIT as usize;
        assert_eq!(
            engine.read(offset as u64, UNIT as usize).await.unwrap(),
            data[offset..offset + UNIT as usize]
        );
    }
    assert_eq!(engine.read(0, data.len()).await.unwrap(), data);
    assert_eq!(
        engine.read(512, UNIT as usize).await.unwrap(),
        data[512..512 + UNIT as usize]
    );
    // Partial write spans two existing units and uses the same decrypt split.
    engine
        .write(512, &[0x77; UNIT as usize], true)
        .await
        .unwrap();
    data[512..512 + UNIT as usize].fill(0x77);
    assert_eq!(engine.read(0, data.len()).await.unwrap(), data);
    assert!(short.encrypt_groups().iter().all(|count| *count == 1));
    assert!(short.decrypt_groups().iter().all(|count| *count == 1));
    engine.stop_checkpoint_worker().await;
}

#[tokio::test]
async fn expanded_ciphertexts_still_obey_resident_admission() {
    let fake = Arc::new(FakeCryptoProvider::new(UNIT).with_max_batch(2, UNIT as u64));
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(49),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    };
    let ct = fake
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 0,
                data: maki_crypto::SecretBuffer::from_slice(&[0x49; UNIT as usize]),
            }],
        )
        .await
        .unwrap();
    assert_eq!(ct[0].data.len(), UNIT as usize + 8);
    let rejected = BatchScheduler::with_unit_size(
        fake.clone(),
        config(UNIT as u64 + 7),
        Arc::new(ManualClock::new()),
        UNIT,
    );
    let error = rejected.decrypt_batch(&context, &ct).await.unwrap_err();
    assert!(
        matches!(error, CryptoError::NonRetryableRequest(_)),
        "{error}"
    );
    assert_eq!(fake.decrypt_calls(), 0);
    assert_eq!(rejected.stats().pending_bytes(), 0);
    let accepted = BatchScheduler::with_unit_size(
        fake.clone(),
        config(UNIT as u64 + 8),
        Arc::new(ManualClock::new()),
        UNIT,
    );
    assert_eq!(
        accepted.decrypt_batch(&context, &ct).await.unwrap()[0]
            .data
            .len(),
        UNIT as usize
    );
}
