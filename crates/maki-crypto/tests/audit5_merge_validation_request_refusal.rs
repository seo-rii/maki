//! Round-5 audit (merge-interactions): #343 made background validation of a
//! quarantined endpoint reject it for the life of the set only on proof that
//! it serves another contract; "everything else shows only that an exchange
//! failed" (`proves_another_contract`, SPEC §34). One generic request-class
//! reply during validation is still turned into such a proof:
//!
//! - `selftest::classify_probe_err` relabels a negative probe answered with a
//!   `NonRetryableRequest` (what the HTTP transport makes of a generic 4xx
//!   such as 400, 409, 421 or 425: "do not infer integrity from a generic
//!   4xx") as `ProviderFatal` "the capability is not proven";
//! - `cross_endpoint_self_test_attributed` relabels a `NonRetryableRequest`
//!   from the decrypting side as `ProviderFatal` "endpoints are not
//!   interchangeable", and `ValidationProvider::failure` keeps that class
//!   for the validated *reference* too, so the reference's own one-off 4xx
//!   excludes the healthy candidate.
//!
//! Each case below glitches exactly once and is healthy afterwards. Under
//! #343's rule the endpoint is deferred and admitted by the next validation;
//! on e6f52d6 it is `rejected` and never validated again.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointStatus, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::selftest::{cross_endpoint_self_test, provider_self_test};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;

const U: usize = 256;
const INTERVAL: Duration = Duration::from_secs(1);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x5e_7a11),
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
        breaker: BreakerConfig {
            failure_threshold: 3,
            open_initial: INTERVAL,
            open_max: Duration::from_secs(8),
            half_open_max_requests: 2,
            success_threshold: 2,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 4,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: None,
        retry_safe: true,
        validation_interval: INTERVAL,
    }
}

/// When the peer answers one decrypt with a generic request-class error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Glitch {
    /// Instead of the integrity failure a negative self-test probe is due.
    NegativeProbe,
    /// Its next decrypt, whatever it carries.
    NextDecrypt,
    /// Its next decrypt, with a transport error instead (the control).
    NextDecryptTransport,
}

/// What the HTTP transport returns for a generic 4xx
/// (`maki-crypto-http` `classify_status`: `400..=499 => NonRetryableRequest`).
fn generic_4xx() -> CryptoError {
    CryptoError::NonRetryableRequest("HTTP 421".into())
}

struct Peer {
    inner: FakeCryptoProvider,
    glitch: Mutex<Option<Glitch>>,
    decrypts: AtomicUsize,
}

impl Peer {
    fn new(glitch: Option<Glitch>) -> Arc<Self> {
        Arc::new(Self {
            inner: FakeCryptoProvider::new(U as u32),
            glitch: Mutex::new(glitch),
            decrypts: AtomicUsize::new(0),
        })
    }

    fn take(&self, glitch: Glitch) -> bool {
        let mut slot = self.glitch.lock().unwrap();
        if *slot == Some(glitch) {
            *slot = None;
            true
        } else {
            false
        }
    }

    fn glitch_pending(&self) -> bool {
        self.glitch.lock().unwrap().is_some()
    }
}

#[async_trait]
impl CryptoProvider for Peer {
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
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        if self.take(Glitch::NextDecrypt) {
            return Err(generic_4xx());
        }
        if self.take(Glitch::NextDecryptTransport) {
            return Err(CryptoError::Retryable("HTTP 503".into()));
        }
        match self.inner.decrypt_batch(context, items).await {
            Err(CryptoError::Integrity(_)) if self.take(Glitch::NegativeProbe) => {
                Err(generic_4xx())
            }
            result => result,
        }
    }
}

/// The daemon's validator without its volume canary: the candidate's own
/// self-test (when `self_test`), then the cross-endpoint check.
fn validator(self_test: bool, runs: Arc<AtomicUsize>) -> EndpointValidator {
    Arc::new(move |reference, candidate, context| {
        runs.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self_test {
                provider_self_test(
                    candidate.as_ref(),
                    &context,
                    U,
                    &context.crypto_compatibility_id,
                )
                .await?;
            }
            cross_endpoint_self_test(reference.as_ref(), candidate.as_ref(), &context, U).await
        })
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

fn status(set: &EndpointSet, name: &str) -> EndpointStatus {
    set.endpoint_status()
        .into_iter()
        .find(|status| status.name == name)
        .unwrap()
}

async fn serve(set: &EndpointSet, unit: u64) {
    let request = PlaintextUnit {
        unit_index: (1 << 20) + unit,
        data: SecretBuffer::from_slice(&[unit as u8; U]),
    };
    set.encrypt_batch(&ctx(), std::slice::from_ref(&request))
        .await
        .unwrap();
}

/// Run one glitched validation, then give the endpoint every chance to be
/// validated again. Returns what went wrong, if anything.
async fn one_generic_refusal(
    case: &str,
    self_test: bool,
    reference_glitch: Option<Glitch>,
    candidate_glitch: Option<Glitch>,
) -> Option<String> {
    let clock = Arc::new(ManualClock::new());
    let reference = Peer::new(reference_glitch);
    let candidate = Peer::new(candidate_glitch);
    let runs = Arc::new(AtomicUsize::new(0));
    let set = EndpointSet::with_quarantine(
        vec![
            (
                "reference".to_string(),
                reference.clone() as Arc<dyn CryptoProvider>,
                true,
            ),
            (
                "candidate".to_string(),
                candidate.clone() as Arc<dyn CryptoProvider>,
                false,
            ),
        ],
        Some(validator(self_test, runs.clone())),
        cfg(),
        clock.clone(),
    );
    serve(&set, 1).await;
    settle().await;
    assert!(
        !reference.glitch_pending() && !candidate.glitch_pending(),
        "{case}: the glitch must hit the first validation"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1, "{case}");
    let first = status(&set, "candidate");
    assert!(!first.validated, "{case}: {first:?}");

    // Both peers are healthy from here on. Give validation a minute of
    // traffic, far beyond the 8 s backoff cap.
    for second in 0..60 {
        clock.advance(INTERVAL);
        serve(&set, 2 + second).await;
        settle().await;
    }
    let last = status(&set, "candidate");
    (last.rejected || !last.validated).then(|| {
        format!(
            "{case}: after one generic request-class reply (HTTP 421) the healthy endpoint is \
             {last:?} after {} validation run(s) in 60 s",
            runs.load(Ordering::SeqCst)
        )
    })
}

#[tokio::test(flavor = "current_thread")]
async fn one_generic_request_refusal_during_validation_is_not_proof_of_another_contract() {
    let mut excluded = Vec::new();
    for (case, self_test, reference_glitch, candidate_glitch) in [
        (
            "candidate answers a negative self-test probe with a generic 4xx",
            true,
            None,
            Some(Glitch::NegativeProbe),
        ),
        (
            "candidate answers the cross-check decrypt with a generic 4xx",
            false,
            None,
            Some(Glitch::NextDecrypt),
        ),
        (
            "the validated reference answers the cross-check decrypt with a generic 4xx",
            false,
            Some(Glitch::NextDecrypt),
            None,
        ),
    ] {
        excluded
            .extend(one_generic_refusal(case, self_test, reference_glitch, candidate_glitch).await);
    }
    assert!(excluded.is_empty(), "{excluded:#?}");
}

/// Control: the same harness admits the endpoint when the one-off failure is
/// a transport error (HTTP 503), so the cases above differ only in the class
/// of the single bad reply.
#[tokio::test(flavor = "current_thread")]
async fn control_one_transport_failure_during_validation_only_defers() {
    assert_eq!(
        one_generic_refusal(
            "candidate answers the cross-check decrypt with HTTP 503",
            false,
            None,
            Some(Glitch::NextDecryptTransport),
        )
        .await,
        None
    );
    assert_eq!(
        one_generic_refusal(
            "the validated reference answers the cross-check decrypt with HTTP 503",
            false,
            Some(Glitch::NextDecryptTransport),
            None,
        )
        .await,
        None
    );
}
