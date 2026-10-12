//! BUG-049: batch bytes mean plaintext bytes, independently of encoded size.
use async_trait::async_trait;
use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const UNIT: u32 = 4096;

// The fake's complete bound ciphertext is retained under a short token. This
// models reversible variable-length encoding without weakening its checks.
struct ShortProvider {
    fake: FakeCryptoProvider,
    encoded: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}
#[async_trait]
impl CryptoProvider for ShortProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.fake.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let mut result = self.fake.encrypt_batch(ctx, items).await?;
        let mut stored = self.encoded.lock().unwrap();
        for item in &mut result {
            let mut token = vec![0; 512];
            token[..8].copy_from_slice(&(stored.len() as u64).to_le_bytes());
            stored.insert(token.clone(), std::mem::replace(&mut item.data, token));
        }
        Ok(result)
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let expanded = {
            let stored = self.encoded.lock().unwrap();
            items
                .iter()
                .map(|item| {
                    Ok(CiphertextUnit {
                        unit_index: item.unit_index,
                        data: stored
                            .get(&item.data)
                            .cloned()
                            .ok_or_else(|| CryptoError::Integrity("unknown token".into()))?,
                    })
                })
                .collect::<Result<Vec<_>, CryptoError>>()?
        };
        self.fake.decrypt_batch(ctx, &expanded).await
    }
}

// Isolate the Engine read path from attach's separate self-test splitting:
// enable the scheduler's admission checks only after attach completes.
struct AfterAttachScheduler {
    raw: Arc<ShortProvider>,
    scheduler: BatchScheduler,
    active: AtomicBool,
}
#[async_trait]
impl CryptoProvider for AfterAttachScheduler {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.scheduler.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        if self.active.load(Ordering::SeqCst) {
            self.scheduler.encrypt_batch(ctx, items).await
        } else {
            self.raw.encrypt_batch(ctx, items).await
        }
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if self.active.load(Ordering::SeqCst) {
            self.scheduler.decrypt_batch(ctx, items).await
        } else {
            self.raw.decrypt_batch(ctx, items).await
        }
    }
}
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
    let short = Arc::new(ShortProvider {
        fake: FakeCryptoProvider::new(UNIT).with_max_batch(2, UNIT as u64),
        encoded: Mutex::default(),
    });
    let provider = Arc::new(AfterAttachScheduler {
        raw: short.clone(),
        scheduler: BatchScheduler::with_unit_size(
            short,
            config(16 * 1024),
            Arc::new(ManualClock::new()),
            UNIT,
        ),
        active: AtomicBool::new(false),
    });
    let engine = engine(provider.clone()).await;
    provider.active.store(true, Ordering::SeqCst);
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
