//! Repeatable latency/failure/recovery comparison without modifying a real
//! endpoint. Every wait advances the injected clock; no wall-time sleeps.
#[path = "../src/latency.rs"]
mod latency;
use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::Clock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::{FakeCryptoProvider, ManualClock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const UNIT: usize = 512;
struct Peer {
    provider: FakeCryptoProvider,
    clock: Arc<ManualClock>,
    delay: Duration,
    failing: AtomicBool,
    calls: AtomicU64,
    successes: AtomicU64,
}
impl Peer {
    fn new(clock: Arc<ManualClock>, delay: u64) -> Self {
        Self {
            provider: FakeCryptoProvider::new(UNIT as u32).with_compat_id("synthetic-v1"),
            clock,
            delay: Duration::from_millis(delay),
            failing: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            successes: AtomicU64::new(0),
        }
    }
    async fn wait(&self) -> Result<(), CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.sleep(self.delay).await;
        if self.failing.load(Ordering::SeqCst) {
            return Err(CryptoError::Retryable("synthetic temporary outage".into()));
        }
        self.successes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[async_trait]
impl CryptoProvider for Peer {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.provider.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.wait().await?;
        self.provider.encrypt_batch(ctx, items).await
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.wait().await?;
        self.provider.decrypt_batch(ctx, items).await
    }
}
struct PendingGuard(Arc<AtomicU64>);
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn stage(
    set: &Arc<EndpointSet>,
    clock: &Arc<ManualClock>,
    concurrency: usize,
    verifier: &Arc<Peer>,
) -> serde_json::Value {
    let pending = Arc::new(AtomicU64::new(0));
    let mut jobs = tokio::task::JoinSet::new();
    let mut launched = 0;
    let mut completed = 0;
    let mut peak_pending = 0;
    let mut peak_global = 0;
    let mut peak_global_bytes = 0;
    let began = clock.now();
    let mut latency = latency::Latencies::new();
    for _ in 0..10_000 {
        while launched < 64 && jobs.len() < concurrency {
            let index = launched;
            launched += 1;
            let set = set.clone();
            let clock = clock.clone();
            let verifier = verifier.clone();
            let items = [PlaintextUnit {
                unit_index: index,
                data: SecretBuffer::from_slice(&[0x47; UNIT]),
            }];
            let count = pending.fetch_add(1, Ordering::SeqCst) + 1;
            peak_pending = peak_pending.max(count);
            let guard = PendingGuard(pending.clone());
            jobs.spawn(async move {
                let _guard = guard;
                let context = CryptoContext {
                    volume_uuid: Default::default(),
                    format_version: 1,
                    crypto_compatibility_id: "synthetic-v1".into(),
                };
                let began = clock.now();
                let ciphertext = set.encrypt_batch(&context, &items).await.unwrap();
                let elapsed = clock.now() - began;
                let plaintext = verifier
                    .provider
                    .decrypt_batch(&context, &ciphertext)
                    .await
                    .unwrap();
                assert_eq!(plaintext[0].data.expose(), items[0].data.expose());
                elapsed
            });
        }
        tokio::task::yield_now().await;
        let (global, bytes) = set.global_inflight();
        peak_global = peak_global.max(global);
        peak_global_bytes = peak_global_bytes.max(bytes);
        while let Some(result) = jobs.try_join_next() {
            latency.record(result.unwrap());
            completed += 1;
        }
        if completed == 64 {
            break;
        }
        if clock.sleeper_count() > 0 {
            clock.advance(Duration::from_millis(1));
        }
    }
    assert_eq!(completed, 64, "scenario did not finish under virtual time");
    assert_eq!(pending.load(Ordering::SeqCst), 0);
    assert_eq!(set.global_inflight(), (0, 0));
    assert_eq!(peak_pending, concurrency as u64);
    assert!(peak_global <= 2 && peak_global_bytes <= 1024);
    let elapsed = clock.now() - began;
    let report = latency.report();
    assert!(report.p95_upper_us <= report.p99_upper_us && report.p99_upper_us <= report.max_us);
    serde_json::json!({"concurrency":concurrency,"operations":completed,
        "elapsed_virtual_ms":elapsed.as_secs_f64()*1000.0,"latency":report,
        "peak_pending":peak_pending,"peak_input_plaintext_bytes":peak_pending*UNIT as u64,
        "peak_global_calls":peak_global,"peak_global_bytes":peak_global_bytes})
}

#[tokio::test]
async fn asymmetric_peers_temporary_outage_and_recovery_are_comparable_and_bounded() {
    for concurrency in [1, 2, 8, 32] {
        let clock = Arc::new(ManualClock::new());
        let slow = Arc::new(Peer::new(clock.clone(), 20));
        let fast = Arc::new(Peer::new(clock.clone(), 2));
        let config = DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 100,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 1,
                open_initial: Duration::from_millis(5),
                open_max: Duration::from_millis(20),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 1024,
            per_endpoint_max_inflight: 1,
            per_endpoint_max_bytes: 512,
            max_attempts: None,
            max_operation_time: None,
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        };
        let set = Arc::new(EndpointSet::new(
            vec![("slow".into(), slow.clone()), ("fast".into(), fast.clone())],
            config,
            clock.clone(),
        ));
        let healthy = stage(&set, &clock, concurrency, &fast).await;
        if concurrency > 1 {
            assert!(
                fast.successes.load(Ordering::SeqCst) > slow.successes.load(Ordering::SeqCst),
                "idle healthy peer was not utilized"
            );
        }
        let previous_slow_successes = slow.successes.load(Ordering::SeqCst);
        let previous_fast_successes = fast.successes.load(Ordering::SeqCst);
        slow.failing.store(true, Ordering::SeqCst);
        let outage = stage(&set, &clock, concurrency, &fast).await;
        assert_eq!(
            slow.successes.load(Ordering::SeqCst),
            previous_slow_successes
        );
        assert_eq!(
            fast.successes.load(Ordering::SeqCst) - previous_fast_successes,
            64
        );
        assert!(set.metrics().failovers_total() > 0);
        slow.failing.store(false, Ordering::SeqCst);
        clock.advance(Duration::from_millis(21));
        let recovery = stage(&set, &clock, concurrency, &fast).await;
        assert!(
            slow.successes.load(Ordering::SeqCst) > previous_slow_successes,
            "recovered peer was not admitted again"
        );
        assert_eq!(clock.sleeper_count(), 0, "scenario retained pending timers");
        println!(
            "{}",
            serde_json::json!({"healthy":healthy,"temporary_outage":outage,"recovered":recovery})
        );
    }
}
