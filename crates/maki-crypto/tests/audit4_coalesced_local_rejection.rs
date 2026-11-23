//! Audit round 4 (crypto-dispatch): a request the stack rejects *locally*,
//! before any RPC, still fails every request coalesced with it when the
//! provider is not retry-safe.
//!
//! The scheduler checks each group's ciphertext against the maximum size,
//! but not for an empty unit; the dispatcher refuses an empty unit for the
//! whole call with `NonRetryableRequest` before sending anything. The
//! scheduler then fans that error out to every caller in the batch: its
//! per-request re-send is reserved for retry-safe providers (R5-004),
//! although here nothing was ever sent.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{CiphertextUnit, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: u32 = 256;

struct TokioClock(tokio::time::Instant);
impl maki_crypto::Clock for TokioClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) -> maki_crypto::clock::SleepFuture {
        Box::pin(tokio::time::sleep(d))
    }
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xC0A1),
        format_version: 3,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn dispatch() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig::default(),
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: false,
        validation_interval: Duration::from_secs(1),
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_empty_unit_fails_a_coalesced_healthy_read_although_nothing_was_sent() {
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    let set = Arc::new(
        EndpointSet::new(
            vec![("only".into(), provider.clone())],
            dispatch(),
            Arc::new(TokioClock(tokio::time::Instant::now())),
        )
        .with_plaintext_size(UNIT),
    );
    let healthy_ct = set
        .encrypt_batch(
            &ctx(),
            &[PlaintextUnit {
                unit_index: 1,
                data: SecretBuffer::from_slice(&[7; UNIT as usize]),
            }],
        )
        .await
        .unwrap();
    let calls_before = provider.decrypt_calls();

    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        set,
        SchedulerConfig {
            target_items: 2,
            target_bytes: 2 * u64::from(UNIT),
            max_wait: Duration::from_secs(5),
            ..SchedulerConfig::default()
        },
        Arc::new(TokioClock(tokio::time::Instant::now())),
        UNIT,
    ));
    // Alone, the healthy read succeeds.
    let alone = scheduler.decrypt_batch(&ctx(), &healthy_ct).await;
    assert!(alone.is_ok(), "{:?}", alone.err());

    let a = {
        let s = scheduler.clone();
        let ct = healthy_ct.clone();
        tokio::spawn(async move { s.decrypt_batch(&ctx(), &ct).await })
    };
    let b = {
        let s = scheduler.clone();
        tokio::spawn(async move {
            s.decrypt_batch(
                &ctx(),
                &[CiphertextUnit {
                    unit_index: 2,
                    data: Vec::new(),
                }],
            )
            .await
        })
    };
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert!(b.is_err(), "the empty unit itself must fail");
    let rpcs = provider.decrypt_calls() - calls_before;
    assert!(
        a.is_ok(),
        "a healthy read failed only because it shared a batch with a unit the stack \
         refused locally ({rpcs} decrypt RPC(s) in all, 1 from the solo read): {:?}",
        a.err()
    );
}
