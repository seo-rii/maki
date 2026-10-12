use async_trait::async_trait;
use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{fake_provider::FakeCryptoProvider, CrashableBacking, ManualClock};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU8, AtomicUsize, Ordering},
    Arc,
};
use std::task::Poll;
use tokio::sync::Notify;
use uuid::Uuid;
const UNIT: u32 = 1024;

async fn once<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    futures_util::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}
struct GatedProvider {
    inner: FakeCryptoProvider,
    mode: AtomicU8,
    release: Notify,
    error_seen: Notify,
    errors: AtomicUsize,
    calls: AtomicUsize,
    gate_unit: Option<u64>,
}
impl GatedProvider {
    fn new(gate_unit: Option<u64>) -> Self {
        Self {
            inner: FakeCryptoProvider::new(UNIT).with_max_batch(1, 1 << 20),
            mode: AtomicU8::new(0),
            release: Notify::new(),
            error_seen: Notify::new(),
            errors: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            gate_unit,
        }
    }
    async fn barrier(&self, unit: u64, phase: u8) -> Result<(), CryptoError> {
        if self.gate_unit == Some(unit) && self.mode.load(Ordering::SeqCst) == 3 {
            self.release.notified().await;
        }
        if self.mode.load(Ordering::SeqCst) == phase {
            if unit == 0 {
                self.release.notified().await;
            }
            if unit == 1 {
                self.errors.fetch_add(1, Ordering::SeqCst);
                self.error_seen.notify_one();
                return Err(CryptoError::NonRetryableRequest(
                    "batch 2 is permanently rejected".into(),
                ));
            }
        }
        Ok(())
    }
}
#[async_trait]
impl CryptoProvider for GatedProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.barrier(items[0].unit_index, 1).await?;
        self.inner.encrypt_batch(ctx, items).await
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.barrier(items[0].unit_index, 2).await?;
        self.inner.decrypt_batch(ctx, items).await
    }
}
async fn engine(provider: Arc<GatedProvider>) -> Engine {
    let backing = Arc::new(CrashableBacking::new().with_tearing(512));
    let sb = Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(39),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            512,
            UNIT,
            512,
            UNIT + 8,
            256 * UNIT as u64,
            64 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    };
    init::create_volume(backing.as_ref(), sb).unwrap();
    Engine::attach(
        backing as Arc<dyn Backing>,
        provider,
        EngineOptions {
            limits: EngineLimits {
                max_active_callbacks: 2,
                max_plaintext_bytes: 1 << 20,
                max_request_bytes: 1 << 20,
                ..Default::default()
            },
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
async fn check_later_batch_error(decrypt: bool) {
    let provider = Arc::new(GatedProvider::new(None));
    let engine = engine(provider.clone()).await;
    let data = vec![0x39; 2 * UNIT as usize];
    if decrypt {
        engine.write(0, &data, true).await.unwrap();
    }
    provider
        .mode
        .store(if decrypt { 2 } else { 1 }, Ordering::SeqCst);
    let error_seen = provider.error_seen.notified();
    let mut request: Pin<Box<dyn Future<Output = Result<(), maki_core::CoreError>> + Send + '_>> =
        if decrypt {
            Box::pin(async { engine.read_secret(0, data.len()).await.map(|_| ()) })
        } else {
            Box::pin(engine.write(0, &data, false))
        };
    let completed = tokio::select! {
     biased;
     _ = error_seen => None,
     result = request.as_mut() => Some(result),
    };
    assert_eq!(provider.errors.load(Ordering::SeqCst), 1);
    let result = match completed {
        Some(result) => result,
        None => match once(request.as_mut()).await {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("a permanent error in batch 2 must cancel pending batch 1"),
        },
    };
    drop(request);
    assert!(
        matches!(
            result,
            Err(maki_core::CoreError::Crypto(
                CryptoError::NonRetryableRequest(_)
            ))
        ),
        "{result:?}"
    );
    let stats = engine.stats().await;
    assert_eq!(stats.active_callbacks, 0);
    assert_eq!(stats.plaintext_bytes_in_flight, 0);
    provider.mode.store(0, Ordering::SeqCst);
    engine.write(0, &data, true).await.unwrap();
    assert_eq!(engine.read(0, data.len()).await.unwrap(), data);
    engine.stop_checkpoint_worker().await;
}
#[tokio::test(flavor = "current_thread")]
async fn encrypt_later_permanent_error_cancels_first_batch() {
    check_later_batch_error(false).await;
}
#[tokio::test(flavor = "current_thread")]
async fn decrypt_later_permanent_error_cancels_first_batch() {
    check_later_batch_error(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn out_of_order_success_keeps_unit_order() {
    let provider = Arc::new(GatedProvider::new(Some(0)));
    let engine = engine(provider.clone()).await;
    provider.calls.store(0, Ordering::SeqCst);
    provider.mode.store(3, Ordering::SeqCst);
    let mut data = vec![0x23; UNIT as usize];
    data.extend(vec![0x97; UNIT as usize]);
    let mut request = Box::pin(engine.write(0, &data, true));
    while provider.calls.load(Ordering::SeqCst) < 2 {
        assert!(once(request.as_mut()).await.is_pending());
        tokio::task::yield_now().await;
    }
    provider.release.notify_one();
    request.await.unwrap();
    // Decrypt unit zero also uses the gate; release it before reading.
    provider.release.notify_one();
    assert_eq!(engine.read(0, data.len()).await.unwrap(), data);
    engine.stop_checkpoint_worker().await;
}
