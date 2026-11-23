//! Audit round 4 (crypto-dispatch): a quarantined endpoint that returns one
//! malformed reply while it is being validated is excluded for the life of
//! the set, although nothing proved it non-interchangeable.
//!
//! In serving, the same `Contract` reply only charges the endpoint's breaker
//! and excludes it from that one operation (R5-005). During background
//! validation (`promote_quarantined`) every `ProviderFatal`-class result,
//! `Contract` included, sets `rejected`, which is never cleared: M-011 meant
//! *proven* non-interchangeability to be permanent.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::{Clock, SleepFuture};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;

const UNIT: u32 = 256;

struct TokioClock(tokio::time::Instant);
impl Clock for TokioClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) -> SleepFuture {
        Box::pin(tokio::time::sleep(d))
    }
}

/// Healthy except for its first `glitches` encrypt calls, which answer with
/// one item missing (a truncated batch reply, say from a proxy during the
/// endpoint's restart).
struct Glitchy {
    inner: FakeCryptoProvider,
    glitches: AtomicU32,
    encrypts: AtomicU32,
}

#[async_trait]
impl CryptoProvider for Glitchy {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }
    async fn encrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.encrypts.fetch_add(1, Ordering::SeqCst);
        let mut out = self.inner.encrypt_batch(ctx, items).await?;
        if self
            .glitches
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |g| g.checked_sub(1))
            .is_ok()
        {
            out.pop();
        }
        Ok(out)
    }
    async fn decrypt_batch(
        &self,
        ctx: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(ctx, items).await
    }
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA4_C0),
        format_version: 3,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig::default(),
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&[(i as u8) ^ 0x3c; UNIT as usize]),
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn one_malformed_validation_reply_excludes_a_healthy_endpoint_forever() {
    let reference = Arc::new(FakeCryptoProvider::new(UNIT));
    let returning = Arc::new(Glitchy {
        inner: FakeCryptoProvider::new(UNIT),
        glitches: AtomicU32::new(1),
        encrypts: AtomicU32::new(0),
    });
    // The daemon's validator also runs the cross-endpoint self-test.
    let validator: EndpointValidator = Arc::new(|reference, candidate, context| {
        Box::pin(async move {
            maki_crypto::selftest::cross_endpoint_self_test(
                reference.as_ref(),
                candidate.as_ref(),
                &context,
                UNIT as usize,
            )
            .await
        })
    });
    let set = EndpointSet::with_quarantine(
        vec![
            ("reference".into(), reference.clone(), true),
            ("returning".into(), returning.clone(), false),
        ],
        Some(validator),
        cfg(),
        Arc::new(TokioClock(tokio::time::Instant::now())),
    );
    // Traffic drives validation once per interval for a minute.
    for i in 0..60u64 {
        set.encrypt_batch(&ctx(), &[pt(i)]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let status = &set.endpoint_status()[1];
    let validation_encrypts = returning.encrypts.load(Ordering::SeqCst);
    assert!(
        status.validated && !status.rejected,
        "after one truncated reply (and {validation_encrypts} encrypt call(s) in all) the \
         healthy endpoint is still excluded: {status:?}"
    );
}
