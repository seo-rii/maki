//! BUG-056: an RPC's successful transport status is not a successful result.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::{FakeCryptoProvider, Misbehavior};
use maki_test_support::ManualClock;

const UNIT: usize = 256;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(56),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn items() -> Vec<PlaintextUnit> {
    (0..2)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_slice(&vec![unit_index as u8; UNIT]),
        })
        .collect()
}

fn config(retry_safe: bool) -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 1,
            open_initial: Duration::from_secs(30),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 2,
        global_max_inflight_bytes: 4096,
        per_endpoint_max_inflight: 1,
        per_endpoint_max_bytes: 4096,
        max_attempts: None,
        max_operation_time: None,
        retry_safe,
        validation_interval: Duration::from_secs(30),
    }
}

fn endpoints(
    broken: Arc<dyn CryptoProvider>,
    healthy: Arc<dyn CryptoProvider>,
    retry_safe: bool,
) -> EndpointSet {
    EndpointSet::new(
        vec![("broken".into(), broken), ("healthy".into(), healthy)],
        config(retry_safe),
        Arc::new(ManualClock::new()),
    )
}

fn assert_released_and_attributed(set: &EndpointSet) {
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(set.endpoint_states()[1].1, CircuitState::Closed);
    assert_eq!(set.global_inflight(), (0, 0));
    assert!(set.endpoint_inflight().iter().all(|(_, count)| *count == 0));
}

#[tokio::test]
async fn successful_encrypt_payload_violations_fail_over_before_breaker_success() {
    for violation in [
        Misbehavior::DropLastItem,
        Misbehavior::DuplicateFirstItem,
        Misbehavior::ReorderResults,
        Misbehavior::MismatchedIndex,
        Misbehavior::OversizeCiphertext,
    ] {
        let bad = Arc::new(FakeCryptoProvider::new(UNIT as u32));
        let good = Arc::new(FakeCryptoProvider::new(UNIT as u32));
        bad.set_misbehavior(Some(violation));
        let set = endpoints(bad.clone(), good.clone(), true);
        let input = items();
        for _ in 0..10 {
            let output = set.encrypt_batch(&context(), &input).await.unwrap();
            let plain = good.decrypt_batch(&context(), &output).await.unwrap();
            for (actual, expected) in plain.iter().zip(&input) {
                assert_eq!(actual.unit_index, expected.unit_index);
                assert_eq!(actual.data, expected.data);
            }
        }
        assert_eq!(bad.encrypt_calls(), 1, "{violation:?}");
        assert_eq!(good.encrypt_calls(), 10, "{violation:?}");
        assert_released_and_attributed(&set);
    }
}

#[tokio::test]
async fn successful_decrypt_payload_violations_fail_over_before_breaker_success() {
    for violation in [
        Misbehavior::DropLastItem,
        Misbehavior::DuplicateFirstItem,
        Misbehavior::ReorderResults,
        Misbehavior::MismatchedIndex,
    ] {
        let bad = Arc::new(MalformedDecrypt {
            inner: FakeCryptoProvider::new(UNIT as u32),
            behavior: violation,
        });
        let good = Arc::new(FakeCryptoProvider::new(UNIT as u32));
        let input = items();
        let ciphertext = good.encrypt_batch(&context(), &input).await.unwrap();
        let set = endpoints(bad.clone(), good.clone(), true);
        for _ in 0..10 {
            let output = set.decrypt_batch(&context(), &ciphertext).await.unwrap();
            for (actual, expected) in output.iter().zip(&input) {
                assert_eq!(actual.unit_index, expected.unit_index);
                assert_eq!(actual.data, expected.data);
            }
        }
        assert_eq!(bad.inner.decrypt_calls(), 1, "{violation:?}");
        assert_eq!(good.decrypt_calls(), 10, "{violation:?}");
        assert_released_and_attributed(&set);
    }
}

struct MalformedDecrypt {
    inner: FakeCryptoProvider,
    behavior: Misbehavior,
}

#[async_trait]
impl CryptoProvider for MalformedDecrypt {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut output = self.inner.decrypt_batch(context, items).await?;
        match self.behavior {
            Misbehavior::DropLastItem => {
                output.pop();
            }
            Misbehavior::DuplicateFirstItem => output.push(PlaintextUnit {
                unit_index: output[0].unit_index,
                data: SecretBuffer::from_slice(output[0].data.expose()),
            }),
            Misbehavior::ReorderResults => output.swap(0, 1),
            Misbehavior::MismatchedIndex => output[0].unit_index += 100,
            Misbehavior::OversizeCiphertext => unreachable!("decrypt shape fixture"),
        }
        Ok(output)
    }
}

struct ShortPlaintext(FakeCryptoProvider);

#[async_trait]
impl CryptoProvider for ShortPlaintext {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.0.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.0.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut output = self.0.decrypt_batch(context, items).await?;
        output[0].data = SecretBuffer::zeroed(UNIT - 1);
        Ok(output)
    }
}

#[tokio::test]
async fn unsupported_plaintext_size_is_an_endpoint_failure() {
    let bad = Arc::new(ShortPlaintext(FakeCryptoProvider::new(UNIT as u32)));
    let good = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let input = items();
    let ciphertext = good.encrypt_batch(&context(), &input).await.unwrap();
    let set = endpoints(bad.clone(), good, true);
    let output = set.decrypt_batch(&context(), &ciphertext).await.unwrap();
    assert_eq!(output[0].data, input[0].data);
    assert_eq!(bad.0.decrypt_calls(), 1);
    assert_released_and_attributed(&set);
}

#[tokio::test]
async fn each_endpoint_must_obey_its_own_ciphertext_limit() {
    let bad = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    bad.set_misbehavior(Some(Misbehavior::OversizeCiphertext));
    let good = Arc::new(FakeCryptoProvider::new(UNIT as u32).with_overhead(128));
    let set = endpoints(bad.clone(), good.clone(), true);
    assert_eq!(set.capabilities().await.unwrap().max_ciphertext_size, 384);
    let output = set.encrypt_batch(&context(), &items()).await.unwrap();
    assert_eq!(output[0].data.len(), 384);
    assert_eq!(bad.encrypt_calls(), 1);
    assert_eq!(good.encrypt_calls(), 1);
    assert_released_and_attributed(&set);
}

#[tokio::test]
async fn unsafe_payload_violation_charges_breaker_without_resending() {
    let bad = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    let good = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    bad.set_misbehavior(Some(Misbehavior::OversizeCiphertext));
    let set = endpoints(bad.clone(), good.clone(), false);
    assert!(matches!(
        set.encrypt_batch(&context(), &items()).await,
        Err(CryptoError::Contract(_))
    ));
    assert_eq!(bad.encrypt_calls(), 1);
    assert_eq!(good.encrypt_calls(), 0);
    assert_released_and_attributed(&set);
}

#[tokio::test]
async fn single_endpoint_payload_violation_returns_without_stall_retries() {
    let bad = Arc::new(FakeCryptoProvider::new(UNIT as u32));
    bad.set_misbehavior(Some(Misbehavior::OversizeCiphertext));
    let set = EndpointSet::new(
        vec![("only".into(), bad.clone())],
        config(true),
        Arc::new(ManualClock::new()),
    );
    assert!(matches!(
        set.encrypt_batch(&context(), &items()).await,
        Err(CryptoError::Contract(_))
    ));
    assert_eq!(bad.encrypt_calls(), 1);
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(set.global_inflight(), (0, 0));
}
