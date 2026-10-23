//! BUG-154: the exported deadline counter includes each scheduler caller,
//! even when queueing consumes its budget before the dispatcher expires.

use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_control::server::ControlBackend;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_nbdkit::control::EngineControlBackend;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::{CrashableBacking, ManualClock};
use tokio::task::JoinHandle;
use uuid::Uuid;

const UNIT: u32 = 4096;
const DEADLINE: Duration = Duration::from_millis(100);
const COUNTER: &str = "maki_crypto_deadline_exceeded_total";

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: Uuid::from_u128(154),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        target_items: 8,
        max_wait: Duration::from_secs(1),
        max_inflight_batches: 1,
        ..SchedulerConfig::default()
    }
}

struct Fixture {
    clock: Arc<ManualClock>,
    provider: Arc<FakeCryptoProvider>,
    endpoints: Arc<EndpointSet>,
    scheduler: Arc<BatchScheduler>,
    backend: EngineControlBackend,
}

impl Fixture {
    async fn new(config: SchedulerConfig, endpoint_clock: Option<Arc<ManualClock>>) -> Self {
        let clock = Arc::new(ManualClock::new());
        let provider = Arc::new(FakeCryptoProvider::new(UNIT));
        let endpoints = Arc::new(EndpointSet::new(
            vec![("only".into(), provider.clone())],
            DispatchConfig {
                retry: RetryPolicy {
                    initial_delay: Duration::ZERO,
                    max_delay: Duration::ZERO,
                },
                budget: RetryBudgetConfig {
                    retry_ratio: 1.0,
                    burst: 8,
                    min_probe_per_sec: 0.0,
                },
                breaker: BreakerConfig::default(),
                global_max_inflight_batches: 8,
                global_max_inflight_bytes: 1 << 20,
                per_endpoint_max_inflight: 8,
                per_endpoint_max_bytes: 1 << 20,
                max_attempts: Some(1),
                max_operation_time: Some(DEADLINE),
                retry_safe: true,
                validation_interval: Duration::from_secs(1),
            },
            endpoint_clock.unwrap_or_else(|| clock.clone()),
        ));
        let scheduler = Arc::new(BatchScheduler::new(
            endpoints.clone(),
            config,
            clock.clone(),
        ));
        // Attach independently so attach/self-test traffic does not affect the
        // counter under test. These are the actual scheduler/dispatcher stats
        // wired into the same control backend used by the daemon.
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: context().volume_uuid,
                provider_type: "fake".into(),
                crypto_compatibility_id: "test-profile-v1".into(),
                key_identity: "k".into(),
                geometry: Geometry::compute(
                    512,
                    UNIT,
                    512,
                    UNIT + 8,
                    64 * u64::from(UNIT),
                    16 * u64::from(UNIT),
                )
                .unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let engine = Engine::attach(
            backing as Arc<dyn Backing>,
            Arc::new(FakeCryptoProvider::new(UNIT)),
            EngineOptions {
                checkpoint: CheckpointPolicy {
                    emergency_reserve_bytes: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let backend = EngineControlBackend::new(engine, "deadline-test")
            .with_endpoints(Some(endpoints.clone()))
            .with_crypto_stats(Some(scheduler.stats()));
        Self {
            clock,
            provider,
            endpoints,
            scheduler,
            backend,
        }
    }

    fn request(&self, index: u64, decrypt: bool) -> JoinHandle<Result<(), CryptoError>> {
        request(self.scheduler.clone(), index, decrypt)
    }

    async fn count(&self) -> u64 {
        self.backend.metrics().await[COUNTER].as_u64().unwrap()
    }
}

fn request(
    provider: Arc<dyn CryptoProvider>,
    index: u64,
    decrypt: bool,
) -> JoinHandle<Result<(), CryptoError>> {
    tokio::spawn(async move {
        let items = [PlaintextUnit {
            unit_index: index,
            data: SecretBuffer::zeroed(UNIT as usize),
        }];
        if decrypt {
            let ciphertext = FakeCryptoProvider::new(UNIT)
                .encrypt_batch(&context(), &items)
                .await?;
            provider.decrypt_batch(&context(), &ciphertext).await?;
        } else {
            provider.encrypt_batch(&context(), &items).await?;
        }
        Ok(())
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

async fn expired(task: JoinHandle<Result<(), CryptoError>>) {
    assert!(task.is_finished(), "request did not finish at its deadline");
    assert!(task
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
}

#[tokio::test]
async fn coalescing_expiry_is_exported_for_encrypt_and_decrypt() {
    for decrypt in [false, true] {
        let f = Fixture::new(config(), None).await;
        let task = f.request(1, decrypt);
        settle().await;
        f.clock.advance(DEADLINE);
        settle().await;
        expired(task).await;
        assert_eq!(f.provider.encrypt_calls() + f.provider.decrypt_calls(), 0);
        assert_eq!(f.endpoints.metrics().deadline_exceeded_total(), 0);
        assert_eq!(f.count().await, 1, "queue-only timeout must be visible");
    }
}

#[tokio::test]
async fn rpc_expiry_after_coalescing_is_exported_for_both_lanes() {
    for decrypt in [false, true] {
        let f = Fixture::new(
            SchedulerConfig {
                max_wait: Duration::from_millis(40),
                ..config()
            },
            None,
        )
        .await;
        f.provider
            .set_latency(f.clock.clone(), Duration::from_secs(1));
        let task = f.request(1, decrypt);
        settle().await;
        f.clock.advance(Duration::from_millis(40));
        settle().await;
        assert_eq!(f.provider.encrypt_calls() + f.provider.decrypt_calls(), 1);
        f.clock.advance(Duration::from_millis(60));
        settle().await;
        expired(task).await;
        assert_eq!(f.endpoints.metrics().deadline_exceeded_total(), 0);
        assert_eq!(
            f.count().await,
            1,
            "the caller expires before the RPC timer"
        );
    }
}

#[tokio::test]
async fn admission_waiters_are_counted_separately() {
    let f = Fixture::new(
        SchedulerConfig {
            max_pending_items: 1,
            ..config()
        },
        None,
    )
    .await;
    let first = f.request(1, false);
    settle().await;
    let second = f.request(2, false);
    settle().await;
    assert_eq!(f.scheduler.stats().pending_items(), 1);
    f.clock.advance(DEADLINE);
    settle().await;
    expired(first).await;
    expired(second).await;
    assert_eq!(f.provider.encrypt_calls(), 0);
    assert_eq!(f.count().await, 2);
}

#[tokio::test]
async fn batch_slot_waiters_are_counted_separately() {
    let f = Fixture::new(
        SchedulerConfig {
            target_items: 1,
            ..config()
        },
        None,
    )
    .await;
    f.provider
        .set_latency(f.clock.clone(), Duration::from_secs(1));
    let first = f.request(1, false);
    settle().await;
    let second = f.request(2, false);
    settle().await;
    assert_eq!(f.provider.encrypt_calls(), 1);
    assert_eq!(f.scheduler.stats().pending_items(), 1);
    f.clock.advance(DEADLINE);
    settle().await;
    expired(first).await;
    expired(second).await;
    assert_eq!(f.count().await, 2);
}

#[tokio::test]
async fn shared_rpc_counts_each_expired_caller_once() {
    let f = Fixture::new(
        SchedulerConfig {
            target_items: 2,
            ..config()
        },
        None,
    )
    .await;
    f.provider
        .set_latency(f.clock.clone(), Duration::from_secs(1));
    let first = f.request(1, false);
    settle().await;
    let second = f.request(2, false);
    settle().await;
    assert_eq!(f.provider.encrypt_calls(), 1);
    f.clock.advance(DEADLINE);
    settle().await;
    expired(first).await;
    expired(second).await;
    assert_eq!(
        f.count().await,
        2,
        "do not add the shared dispatcher's counter"
    );
}

#[tokio::test]
async fn propagated_dispatcher_expiry_is_counted_once() {
    // Independent clocks force the dispatcher timer to win, without relying
    // on Tokio's poll order when the two timers become ready together.
    let endpoint_clock = Arc::new(ManualClock::new());
    let f = Fixture::new(
        SchedulerConfig {
            target_items: 1,
            ..config()
        },
        Some(endpoint_clock.clone()),
    )
    .await;
    f.provider
        .set_latency(endpoint_clock.clone(), Duration::from_secs(1));
    let task = f.request(1, false);
    settle().await;
    endpoint_clock.advance(DEADLINE);
    settle().await;
    expired(task).await;
    assert_eq!(f.endpoints.metrics().deadline_exceeded_total(), 1);
    assert_eq!(
        f.count().await,
        1,
        "inner and outer accounting must not add up"
    );
}

#[tokio::test]
async fn dispatcher_counter_is_used_without_a_scheduler() {
    let mut f = Fixture::new(config(), None).await;
    f.backend = f.backend.with_crypto_stats(None);
    f.provider
        .set_latency(f.clock.clone(), Duration::from_secs(1));
    let task = request(f.endpoints.clone(), 1, false);
    settle().await;
    f.clock.advance(DEADLINE);
    settle().await;
    expired(task).await;
    assert_eq!(f.count().await, 1);
}

#[tokio::test]
async fn cancellation_success_and_request_errors_are_not_deadlines() {
    let f = Fixture::new(config(), None).await;
    let task = f.request(1, false);
    settle().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    f.clock.advance(DEADLINE);
    settle().await;
    assert_eq!(f.count().await, 0);

    let f = Fixture::new(
        SchedulerConfig {
            target_items: 1,
            ..config()
        },
        None,
    )
    .await;
    f.request(1, false).await.unwrap().unwrap();
    f.provider
        .fail_next([CryptoError::NonRetryableRequest("invalid request".into())]);
    assert!(f.request(2, false).await.unwrap().is_err());
    assert_eq!(f.count().await, 0);
}
