//! Audit (crypto-core): a contract violation by one endpoint ends the whole
//! operation even when a *healthy* peer only failed transiently or is merely
//! cooling down, so under the `stall` policy (`max_attempts: None`) the
//! outcome depends on which endpoint least-inflight routing tried first.
//!
//! The documented rule (R5-005 follow-up) is that "the violation is reported
//! once only such endpoints remain". The two tests below keep a healthy,
//! non-violating peer in the set; the control shows the same faults in the
//! opposite order stall-retry and succeed.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA0D1),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[i as u8 ^ 0x3c; UNIT]),
    }
}

/// `stall`: no pass bound, no deadline.
fn stall_cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: Duration::from_secs(1),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 2,
            success_threshold: 1,
        },
        global_max_inflight_batches: 32,
        global_max_inflight_bytes: 32 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 8 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn contract() -> CryptoError {
    CryptoError::Contract("response body is not valid JSON".into())
}

/// Drive backoff/cooldown sleeps on the manual clock until the task ends.
async fn drive<T: Send + 'static>(clock: &ManualClock, task: tokio::task::JoinHandle<T>) -> T {
    for _ in 0..10_000 {
        if task.is_finished() {
            return task.await.unwrap();
        }
        clock.advance(Duration::from_millis(100));
        tokio::task::yield_now().await;
    }
    panic!("operation did not finish");
}

async fn encrypt_one(set: Arc<EndpointSet>) -> Result<Vec<CiphertextUnit>, CryptoError> {
    set.encrypt_batch(&ctx(), &[pt(7)]).await
}

/// Control: broken endpoint first, then one transient failure on the healthy
/// peer. The stall policy backs off and the healthy peer serves the request.
#[tokio::test]
async fn control_contract_then_transient_stalls_and_succeeds() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    healthy.fail_next([CryptoError::Retryable("connection reset".into())]);
    let set = Arc::new(EndpointSet::new(
        vec![
            ("broken".into(), broken.clone() as Arc<dyn CryptoProvider>),
            ("healthy".into(), healthy.clone() as Arc<dyn CryptoProvider>),
        ],
        stall_cfg(),
        clock.clone(),
    ));
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert!(result.is_ok(), "control must succeed: {result:?}");
    assert_eq!(broken.encrypt_calls(), 1);
    assert_eq!(healthy.encrypt_calls(), 2);
}

/// Same two faults, opposite routing order: the healthy peer's one transient
/// failure comes first, then the broken peer's contract violation. The
/// operation fails at once with the contract error although the healthy,
/// non-violating peer is still in the set and would answer on the next pass.
#[tokio::test]
async fn transient_then_contract_fails_the_stalled_operation_at_once() {
    let clock = Arc::new(ManualClock::new());
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    healthy.fail_next([CryptoError::Retryable("connection reset".into())]);
    broken.fail_next((0..100).map(|_| contract()));
    let set = Arc::new(EndpointSet::new(
        vec![
            ("healthy".into(), healthy.clone() as Arc<dyn CryptoProvider>),
            ("broken".into(), broken.clone() as Arc<dyn CryptoProvider>),
        ],
        stall_cfg(),
        clock.clone(),
    ));
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert_eq!(healthy.encrypt_calls(), 1, "healthy peer tried once");
    assert_eq!(broken.encrypt_calls(), 1, "broken peer tried once");
    assert!(
        result.is_ok(),
        "stall policy: the healthy peer only failed transiently and must be retried, \
         but the operation ended with {:?}",
        result.err()
    );
}

/// Variant: the healthy peer's circuit is merely cooling down (an
/// `EndpointFatal` answer opens it at once, BUG-094) when the broken peer
/// violates the contract. Top-of-pass `candidates()` omits the cooling
/// circuit, so "only contract-failed endpoints remain" and the stalled
/// operation ends instead of waiting for the healthy peer's probe deadline.
#[tokio::test]
async fn contract_then_cooling_circuit_fails_the_stalled_operation() {
    let clock = Arc::new(ManualClock::new());
    let broken = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    broken.fail_next((0..100).map(|_| contract()));
    healthy.fail_next([CryptoError::EndpointFatal(
        "HTTP 401 from auth proxy".into(),
    )]);
    let set = Arc::new(EndpointSet::new(
        vec![
            ("broken".into(), broken.clone() as Arc<dyn CryptoProvider>),
            ("healthy".into(), healthy.clone() as Arc<dyn CryptoProvider>),
        ],
        stall_cfg(),
        clock.clone(),
    ));
    let result = drive(&clock, tokio::spawn(encrypt_one(set))).await;
    assert_eq!(broken.encrypt_calls(), 1);
    assert!(
        result.is_ok(),
        "stall policy: the healthy peer's circuit reopens after open_initial; the \
         operation ended with {:?} after {} healthy call(s)",
        result.as_ref().err(),
        healthy.encrypt_calls()
    );
}
