//! Quarantined endpoints and inconclusive validation.
//!
//! A quarantined endpoint whose validation failed only because one exchange
//! went wrong (a truncated batch reply, an empty success where a refusal was
//! due, a request refused without an integrity verdict by either peer or by
//! the set's own admission limits) has not been shown to serve another
//! contract. It stays out of the serving pool, is revalidated with
//! exponential backoff (the validation interval, doubled per inconclusive
//! attempt, capped by the circuit breaker's `open_max`) and is admitted
//! after a complete successful validation. Proof that it serves another
//! contract (another key, a foreign compatibility id, a capability it does
//! not honour) still excludes it for the life of the set. No request
//! reaches an endpoint before it validates, and admission keeps the
//! aggregate contract that already counted the quarantined endpoint
//! (R3-004). Attach is stricter and keeps its verdicts: there a refusal
//! that proves nothing still refuses the endpoint.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet, EndpointStatus, EndpointValidator};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::selftest::{
    cross_endpoint_self_test, cross_endpoint_self_test_attributed, provider_self_test,
    CrossCheckSide,
};
use maki_crypto::{
    Capability, CiphertextUnit, Clock, ContextField, CryptoCapabilities, CryptoContext,
    CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_test_support::fake_provider::{FakeCryptoProvider, Misbehavior};
use maki_test_support::ManualClock;

const U: usize = 256;
/// Serving requests use unit indices from here on; validation probes use
/// small ones, so each peer can tell the two apart.
const SERVING: u64 = 1 << 20;
const INTERVAL: Duration = Duration::from_secs(1);
const CAP: Duration = Duration::from_secs(8);
const STEP: Duration = Duration::from_millis(500);

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
            open_max: CAP,
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

fn pt(unit: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_slice(&[(unit as u8) ^ 0x5a; U]),
    }
}

fn fake() -> FakeCryptoProvider {
    FakeCryptoProvider::new(U as u32)
}

/// An unauthenticated cipher: another key decrypts to the wrong plaintext
/// instead of refusing.
fn unauthenticated() -> FakeCryptoProvider {
    fake().with_integrity_check(false)
}

/// What the transports make of a refusal that carries no integrity verdict:
/// a generic HTTP 4xx, a WebSocket `bad-request`, a gRPC `InvalidArgument`.
fn refusal() -> CryptoError {
    CryptoError::NonRetryableRequest("HTTP 421".into())
}

/// One bad reply, the next time the endpoint makes the matching call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Glitch {
    /// An encrypt reply one item short.
    ShortEncrypt,
    /// A decrypt reply one item short.
    ShortDecrypt,
    /// An empty success where the endpoint should refuse a negative
    /// self-test probe with an integrity failure.
    EmptyRefusal,
    /// A [`refusal`] where the endpoint should refuse the first negative
    /// self-test probe (the moved unit index) with an integrity failure.
    RefusedProbe,
    /// A [`refusal`] where it should refuse the tampered ciphertext.
    RefusedTamper,
    /// A [`refusal`] of the next decrypt, whatever it carries.
    RefusedDecrypt,
    /// `ProviderFatal` instead of the next validation encrypt.
    FatalEncrypt,
    /// `ProviderFatal` instead of the next decrypt.
    FatalDecrypt,
    /// A refusal of the volume's format version instead of the next
    /// decrypt.
    ContextRefusedDecrypt,
}

/// The unit whose ciphertext the self-test tampers with.
const TAMPERED_UNIT: u64 = 2;

/// A peer that serves another contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Foreign {
    /// Claims integrity although its cipher does not check it.
    UncheckedIntegrity,
    /// Refuses the volume's format version.
    FormatVersion,
}

struct Peer {
    inner: FakeCryptoProvider,
    /// Encrypts with this provider (another key) while decrypting with
    /// `inner`.
    encrypts_with: Option<FakeCryptoProvider>,
    foreign: Option<Foreign>,
    glitch: Mutex<Option<Glitch>>,
    /// While set, every other reply is one item short.
    flapping: AtomicBool,
    calls: AtomicUsize,
    served: Mutex<Vec<u64>>,
    largest_served: AtomicUsize,
}

impl Peer {
    fn new(inner: FakeCryptoProvider) -> Arc<Self> {
        Self::with(inner, None)
    }

    fn with(inner: FakeCryptoProvider, foreign: Option<Foreign>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            encrypts_with: None,
            foreign,
            glitch: Mutex::new(None),
            flapping: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            served: Mutex::new(Vec::new()),
            largest_served: AtomicUsize::new(0),
        })
    }

    fn glitching(glitch: Option<Glitch>) -> Arc<Self> {
        let peer = Self::new(fake());
        *peer.glitch.lock().unwrap() = glitch;
        peer
    }

    /// Decrypts like `inner`, but encrypts like `other`.
    fn encrypting_with(inner: FakeCryptoProvider, other: FakeCryptoProvider) -> Arc<Self> {
        let mut peer = Self::with(inner, None);
        Arc::get_mut(&mut peer).unwrap().encrypts_with = Some(other);
        peer
    }

    fn foreign(foreign: Foreign) -> Arc<Self> {
        let inner = match foreign {
            Foreign::UncheckedIntegrity => fake().with_integrity_check(false),
            Foreign::FormatVersion => fake(),
        };
        Self::with(inner, Some(foreign))
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn served(&self) -> Vec<u64> {
        self.served.lock().unwrap().clone()
    }

    fn glitch_pending(&self) -> bool {
        self.glitch.lock().unwrap().is_some()
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

    /// Account for one call; whether its reply flaps.
    fn call(&self, units: impl Iterator<Item = u64>) -> Result<bool, CryptoError> {
        let serving: Vec<u64> = units.filter(|unit| *unit >= SERVING).collect();
        if !serving.is_empty() {
            self.largest_served
                .fetch_max(serving.len(), Ordering::SeqCst);
            self.served.lock().unwrap().extend(serving);
        }
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.foreign == Some(Foreign::FormatVersion) {
            return Err(CryptoError::UnsupportedContext(ContextField::FormatVersion));
        }
        Ok(self.flapping.load(Ordering::SeqCst) && call % 2 == 1)
    }
}

#[async_trait]
impl CryptoProvider for Peer {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut caps = self.inner.capabilities().await?;
        if self.foreign == Some(Foreign::UncheckedIntegrity) {
            caps.integrity = Capability::Contractual;
        }
        Ok(caps)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let flap = self.call(items.iter().map(|item| item.unit_index))?;
        let validation = items.first().is_some_and(|item| item.unit_index < SERVING);
        if validation && self.take(Glitch::FatalEncrypt) {
            return Err(CryptoError::ProviderFatal("backend misconfigured".into()));
        }
        let cipher = self.encrypts_with.as_ref().unwrap_or(&self.inner);
        let mut out = cipher.encrypt_batch(context, items).await?;
        if self.take(Glitch::ShortEncrypt) || flap {
            out.pop();
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let flap = self.call(items.iter().map(|item| item.unit_index))?;
        if self.take(Glitch::RefusedDecrypt) {
            return Err(refusal());
        }
        if self.take(Glitch::FatalDecrypt) {
            return Err(CryptoError::ProviderFatal("backend misconfigured".into()));
        }
        if self.take(Glitch::ContextRefusedDecrypt) {
            return Err(CryptoError::UnsupportedContext(ContextField::FormatVersion));
        }
        let tampered = items.first().map(|item| item.unit_index) == Some(TAMPERED_UNIT);
        match self.inner.decrypt_batch(context, items).await {
            Ok(mut out) => {
                if self.take(Glitch::ShortDecrypt) || flap {
                    out.pop();
                }
                Ok(out)
            }
            Err(CryptoError::Integrity(_)) if self.take(Glitch::EmptyRefusal) => Ok(Vec::new()),
            Err(CryptoError::Integrity(_))
                if self.take(Glitch::RefusedProbe)
                    || (tampered && self.take(Glitch::RefusedTamper)) =>
            {
                Err(refusal())
            }
            Err(error) => Err(error),
        }
    }
}

/// Which checks a validation runs against the candidate.
#[derive(Debug, Clone, Copy)]
enum Check {
    /// The cross-endpoint check alone.
    Cross,
    /// The candidate's own self-test, then the cross-endpoint check (the
    /// daemon's validator, without its volume canary).
    Full,
}

fn validator(check: Check, runs: Arc<AtomicUsize>) -> EndpointValidator {
    Arc::new(move |reference, candidate, context| {
        runs.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if matches!(check, Check::Full) {
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

fn quarantine(
    endpoints: Vec<(&str, Arc<Peer>, bool)>,
    validator: EndpointValidator,
    clock: &Arc<ManualClock>,
) -> EndpointSet {
    quarantine_with(cfg(), endpoints, validator, clock)
}

fn quarantine_with(
    config: DispatchConfig,
    endpoints: Vec<(&str, Arc<Peer>, bool)>,
    validator: EndpointValidator,
    clock: &Arc<ManualClock>,
) -> EndpointSet {
    EndpointSet::with_quarantine(
        endpoints
            .into_iter()
            .map(|(name, peer, validated)| {
                (name.to_string(), peer as Arc<dyn CryptoProvider>, validated)
            })
            .collect(),
        Some(validator),
        config,
        clock.clone(),
    )
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

/// Encrypt one serving unit and check the result against the reference
/// key, so a malformed or misrouted reply can never pass as a result.
async fn serve(set: &EndpointSet, unit: &mut u64) -> u64 {
    *unit += 1;
    let request = pt(*unit);
    let out = set
        .encrypt_batch(&ctx(), std::slice::from_ref(&request))
        .await
        .unwrap();
    let back = fake().decrypt_batch(&ctx(), &out).await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].unit_index, *unit);
    assert_eq!(back[0].data, request.data);
    *unit
}

fn assert_gauges_idle(set: &EndpointSet) {
    assert_eq!(set.global_inflight(), (0, 0));
    assert!(
        set.endpoint_inflight()
            .iter()
            .all(|(_, inflight)| *inflight == 0),
        "{:?}",
        set.endpoint_inflight()
    );
    for status in set.endpoint_status() {
        assert!(!(status.validated && status.rejected), "{status:?}");
        assert_eq!(status.inflight, 0, "{status:?}");
    }
}

/// Calls a healthy candidate makes while one validation admits it.
async fn healthy_validation_calls(check: Check) -> usize {
    let clock = Arc::new(ManualClock::new());
    let candidate = Peer::new(fake());
    let set = quarantine(
        vec![
            ("reference", Peer::new(fake()), true),
            ("candidate", candidate.clone(), false),
        ],
        validator(check, Arc::new(AtomicUsize::new(0))),
        &clock,
    );
    let mut unit = SERVING;
    serve(&set, &mut unit).await;
    settle().await;
    assert!(status(&set, "candidate").validated);
    candidate.calls()
}

/// The first validation meets the one glitch the peers carry: it must only
/// defer the candidate, which the next validation, one interval later,
/// admits. `Err` describes a candidate that the glitch excluded instead.
async fn deferred_once_then_admitted(
    case: &str,
    check: Check,
    reference_glitch: Option<Glitch>,
    candidate_glitch: Option<Glitch>,
) -> Result<(), String> {
    let full_validation = healthy_validation_calls(check).await;
    let clock = Arc::new(ManualClock::new());
    let reference = Peer::glitching(reference_glitch);
    let candidate = Peer::glitching(candidate_glitch);
    let runs = Arc::new(AtomicUsize::new(0));
    let set = quarantine(
        vec![
            ("reference", reference.clone(), true),
            ("candidate", candidate.clone(), false),
        ],
        validator(check, runs.clone()),
        &clock,
    );
    let mut unit = SERVING;

    serve(&set, &mut unit).await;
    settle().await;
    assert!(
        !reference.glitch_pending() && !candidate.glitch_pending(),
        "{case}: the glitch must hit validation"
    );
    let deferred = status(&set, "candidate");
    if deferred.rejected {
        return Err(format!(
            "{case}: one failed exchange proves nothing, yet the endpoint is excluded for the \
             life of the set: {deferred:?}"
        ));
    }
    assert!(!deferred.validated, "{case}: {deferred:?}");

    // Not again before the validation interval has passed.
    clock.advance(INTERVAL / 2);
    serve(&set, &mut unit).await;
    settle().await;
    assert_eq!(runs.load(Ordering::SeqCst), 1, "{case}");

    clock.advance(INTERVAL / 2);
    let before = candidate.calls();
    serve(&set, &mut unit).await;
    settle().await;
    assert_eq!(runs.load(Ordering::SeqCst), 2, "{case}");
    let admitted = status(&set, "candidate");
    assert!(
        admitted.validated && !admitted.rejected,
        "{case}: {admitted:?}"
    );
    assert_eq!(
        candidate.calls() - before,
        full_validation,
        "{case}: admission must follow a complete validation"
    );
    assert!(
        candidate.served().is_empty(),
        "{case}: served before it validated"
    );

    // Admitted: it now takes over when the reference fails.
    reference
        .inner
        .fail_next([CryptoError::Retryable("blip".into())]);
    let taken_over = serve(&set, &mut unit).await;
    assert_eq!(candidate.served(), [taken_over], "{case}");
    assert_gauges_idle(&set);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn one_malformed_validation_reply_defers_the_endpoint_until_it_revalidates() {
    let mut excluded = Vec::new();
    for (check, glitch) in [
        (Check::Cross, Glitch::ShortEncrypt),
        (Check::Cross, Glitch::ShortDecrypt),
        (Check::Full, Glitch::ShortEncrypt),
        (Check::Full, Glitch::ShortDecrypt),
        (Check::Full, Glitch::EmptyRefusal),
    ] {
        let case = format!("{check:?} validation, {glitch:?}");
        excluded.extend(
            deferred_once_then_admitted(&case, check, None, Some(glitch))
                .await
                .err(),
        );
    }
    assert!(excluded.is_empty(), "{excluded:#?}");
}

/// A request refused without an integrity verdict (a proxy's 421, a 400
/// while the endpoint restarts) says that one exchange failed, whichever
/// peer sent it and whatever the request was: a probe that is due an
/// integrity failure, or the decrypt of the other peer's ciphertext.
#[tokio::test(flavor = "current_thread")]
async fn one_generic_request_refusal_defers_the_endpoint_until_it_revalidates() {
    let mut excluded = Vec::new();
    for (case, check, reference_glitch, candidate_glitch) in [
        (
            "the candidate refuses a context-binding probe",
            Check::Full,
            None,
            Some(Glitch::RefusedProbe),
        ),
        (
            "the candidate refuses the tamper probe",
            Check::Full,
            None,
            Some(Glitch::RefusedTamper),
        ),
        (
            "the candidate refuses the decrypt of the reference's ciphertext",
            Check::Cross,
            None,
            Some(Glitch::RefusedDecrypt),
        ),
        (
            "the validated reference refuses the decrypt of the candidate's ciphertext",
            Check::Cross,
            Some(Glitch::RefusedDecrypt),
            None,
        ),
        (
            "the validated reference refuses that decrypt after the candidate's self-test",
            Check::Full,
            Some(Glitch::RefusedDecrypt),
            None,
        ),
    ] {
        excluded.extend(
            deferred_once_then_admitted(case, check, reference_glitch, candidate_glitch)
                .await
                .err(),
        );
    }
    assert!(excluded.is_empty(), "{excluded:#?}");
}

/// What would be a verdict from the candidate (a fatal provider error, a
/// refusal of the volume's context) says nothing about the candidate when
/// the validated reference sends it.
#[tokio::test(flavor = "current_thread")]
async fn a_failure_of_the_validated_reference_never_excludes_the_candidate() {
    let mut excluded = Vec::new();
    for check in [Check::Cross, Check::Full] {
        for glitch in [
            Glitch::FatalEncrypt,
            Glitch::FatalDecrypt,
            Glitch::ContextRefusedDecrypt,
        ] {
            let case = format!("{check:?} validation, reference {glitch:?}");
            excluded.extend(
                deferred_once_then_admitted(&case, check, Some(glitch), None)
                    .await
                    .err(),
            );
        }
    }
    assert!(excluded.is_empty(), "{excluded:#?}");
}

/// A validation RPC that does not fit the set's own byte budget is refused
/// before it is sent. That says nothing about the endpoint either.
#[tokio::test(flavor = "current_thread")]
async fn a_validation_rpc_over_the_admission_limit_only_defers_the_endpoint() {
    let clock = Arc::new(ManualClock::new());
    let candidate = Peer::new(fake());
    let runs = Arc::new(AtomicUsize::new(0));
    let mut config = cfg();
    // One plaintext unit fits; the ciphertext the cross-check has the
    // candidate decrypt (8 bytes longer) does not.
    config.global_max_inflight_bytes = U as u64 + 4;
    let set = quarantine_with(
        config,
        vec![
            ("reference", Peer::new(fake()), true),
            ("candidate", candidate.clone(), false),
        ],
        validator(Check::Cross, runs.clone()),
        &clock,
    );
    let mut unit = SERVING;
    for _ in 0..120 {
        serve(&set, &mut unit).await;
        settle().await;
        let candidate = status(&set, "candidate");
        assert!(
            !candidate.rejected && !candidate.validated,
            "a refusal by the set's own admission limit is not proof: {candidate:?}"
        );
        clock.advance(STEP);
    }
    assert!(
        runs.load(Ordering::SeqCst) >= 5,
        "validation must keep retrying"
    );
    assert_eq!(candidate.calls(), 0, "the refused RPC was sent");
    assert!(candidate.served().is_empty());
    assert_gauges_idle(&set);
}

/// Attach is unchanged: an endpoint that answers a negative probe, or the
/// decrypt of its peer's ciphertext, with a refusal that proves nothing is
/// refused with the same verdicts as before, whichever side sent it.
#[tokio::test(flavor = "current_thread")]
async fn at_attach_a_generic_request_refusal_still_refuses_with_a_verdict() {
    for (glitch, probe) in [
        (Glitch::RefusedProbe, "context-binding (unit index)"),
        (Glitch::RefusedTamper, "integrity"),
    ] {
        let endpoint = Peer::glitching(Some(glitch));
        let error =
            provider_self_test(endpoint.as_ref(), &ctx(), U, &ctx().crypto_compatibility_id)
                .await
                .unwrap_err();
        let verdict = format!(
            "{probe} self-test: the negative probe was rejected with a \
             NonRetryableRequest-class error, not a definitive integrity failure — the \
             capability is not proven; attach refused"
        );
        assert!(
            matches!(&error, CryptoError::ProviderFatal(reason) if *reason == verdict),
            "{glitch:?}: {error:?}"
        );
        assert!(!endpoint.glitch_pending(), "{glitch:?}");
    }
    for (reference_glitch, candidate_glitch, side, direction) in [
        (
            None,
            Some(Glitch::RefusedDecrypt),
            CrossCheckSide::Candidate,
            "A→B",
        ),
        (
            Some(Glitch::RefusedDecrypt),
            None,
            CrossCheckSide::Reference,
            "B→A",
        ),
    ] {
        let reference = Peer::glitching(reference_glitch);
        let candidate = Peer::glitching(candidate_glitch);
        let (failed, error) =
            cross_endpoint_self_test_attributed(reference.as_ref(), candidate.as_ref(), &ctx(), U)
                .await
                .unwrap_err();
        let verdict = format!(
            "cross-endpoint decrypt {direction} failed: non-retryable request: HTTP 421 — \
             endpoints are not interchangeable"
        );
        assert_eq!(failed, side, "{direction}");
        assert!(
            matches!(&error, CryptoError::ProviderFatal(reason) if *reason == verdict),
            "{direction}: {error:?}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn inconclusive_validations_back_off_exponentially_up_to_the_breaker_cap() {
    let clock = Arc::new(ManualClock::new());
    let candidate = Peer::new(fake());
    candidate
        .inner
        .set_misbehavior(Some(Misbehavior::DropLastItem));
    let runs = Arc::new(AtomicUsize::new(0));
    let set = quarantine(
        vec![
            ("reference", Peer::new(fake()), true),
            ("candidate", candidate.clone(), false),
        ],
        validator(Check::Full, runs.clone()),
        &clock,
    );
    let mut unit = SERVING;
    let mut attempts = Vec::new();
    while clock.now() <= Duration::from_secs(40) {
        let before = runs.load(Ordering::SeqCst);
        serve(&set, &mut unit).await;
        settle().await;
        match runs.load(Ordering::SeqCst) - before {
            0 => {}
            1 => attempts.push(clock.now().as_millis()),
            more => panic!("{more} validations started at once"),
        }
        let candidate = status(&set, "candidate");
        assert!(!candidate.validated, "{candidate:?}");
        clock.advance(STEP);
    }
    // Spacing 1 s, 2 s, 4 s, then 8 s (the breaker's `open_max`).
    assert_eq!(
        attempts,
        [0, 1_000, 3_000, 7_000, 15_000, 23_000, 31_000, 39_000],
        "validation attempt times (ms); final status {:?}",
        status(&set, "candidate")
    );
    assert!(!status(&set, "candidate").rejected);
    assert!(candidate.served().is_empty());
    assert_gauges_idle(&set);
}

#[tokio::test(flavor = "current_thread")]
async fn proof_of_another_contract_excludes_the_endpoint_for_the_life_of_the_set() {
    for (case, check, reference, candidate, expected_runs) in [
        // The candidate refuses the reference's ciphertext with an
        // integrity failure.
        (
            "different key",
            Check::Full,
            fake(),
            Peer::new(fake().with_key(99)),
            1,
        ),
        // Without authentication it decrypts it to the wrong plaintext.
        (
            "different key, unauthenticated cipher",
            Check::Full,
            unauthenticated(),
            Peer::new(unauthenticated().with_key(99)),
            1,
        ),
        // The validated reference refuses the candidate's ciphertext with
        // an integrity failure: evidence about that ciphertext, unlike the
        // reference's other failures.
        (
            "encrypts under another key",
            Check::Cross,
            fake(),
            Peer::encrypting_with(fake(), fake().with_key(99)),
            1,
        ),
        // Without authentication the reference decrypts it to the wrong
        // plaintext.
        (
            "encrypts under another key, unauthenticated cipher",
            Check::Cross,
            unauthenticated(),
            Peer::encrypting_with(unauthenticated(), unauthenticated().with_key(99)),
            1,
        ),
        (
            "integrity claimed but not enforced",
            Check::Full,
            fake(),
            Peer::foreign(Foreign::UncheckedIntegrity),
            1,
        ),
        (
            "volume format version refused",
            Check::Full,
            fake(),
            Peer::foreign(Foreign::FormatVersion),
            1,
        ),
        (
            "foreign compatibility id",
            Check::Full,
            fake(),
            Peer::new(fake().with_compat_id("foreign-profile-v1")),
            0,
        ),
    ] {
        let clock = Arc::new(ManualClock::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let set = quarantine(
            vec![
                ("reference", Peer::new(reference), true),
                ("candidate", candidate.clone(), false),
            ],
            validator(check, runs.clone()),
            &clock,
        );
        let mut unit = SERVING;
        serve(&set, &mut unit).await;
        settle().await;
        let verdict = status(&set, "candidate");
        assert!(
            verdict.rejected && !verdict.validated,
            "{case}: {verdict:?}"
        );
        let calls = candidate.calls();
        for _ in 0..120 {
            clock.advance(STEP);
            serve(&set, &mut unit).await;
            settle().await;
        }
        let later = status(&set, "candidate");
        assert!(later.rejected && !later.validated, "{case}: {later:?}");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            expected_runs,
            "{case}: never revalidated"
        );
        assert_eq!(candidate.calls(), calls, "{case}: no validation RPCs");
        assert!(candidate.served().is_empty(), "{case}");
        assert_gauges_idle(&set);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_flapping_endpoint_never_receives_a_request_before_it_validates() {
    let clock = Arc::new(ManualClock::new());
    let reference = Peer::new(fake());
    let candidate = Peer::new(fake());
    candidate.flapping.store(true, Ordering::SeqCst);
    let runs = Arc::new(AtomicUsize::new(0));
    // Listed first: least-inflight routing picks it as soon as it is admitted.
    let set = quarantine(
        vec![
            ("candidate", candidate.clone(), false),
            ("reference", reference.clone(), true),
        ],
        validator(Check::Full, runs.clone()),
        &clock,
    );
    let mut unit = SERVING;

    // Every validation run meets a malformed reply.
    for _ in 0..60 {
        serve(&set, &mut unit).await;
        settle().await;
        clock.advance(STEP);
    }
    let flapping = status(&set, "candidate");
    assert!(!flapping.validated && !flapping.rejected, "{flapping:?}");
    assert!(
        candidate.served().is_empty(),
        "a quarantined endpoint received requests: {:?}",
        candidate.served()
    );
    assert!(
        runs.load(Ordering::SeqCst) >= 5,
        "validation must keep retrying"
    );

    // Stable again: admitted by the next validation, then it serves.
    candidate.flapping.store(false, Ordering::SeqCst);
    let mut admitted_after = None;
    for _ in 0..40 {
        let issued = serve(&set, &mut unit).await;
        settle().await;
        if admitted_after.is_none() && status(&set, "candidate").validated {
            admitted_after = Some(issued);
        }
        clock.advance(STEP);
    }
    let admitted_after = admitted_after.expect("a stable endpoint must be admitted");
    let served = candidate.served();
    assert!(!served.is_empty());
    assert!(
        served.iter().all(|unit| *unit >= admitted_after),
        "served {served:?} before its admission after unit {admitted_after}"
    );

    // Flapping in service only charges its breaker: requests fail over and
    // every caller still gets a correct result.
    candidate.flapping.store(true, Ordering::SeqCst);
    let failed_over = reference.served().len();
    for _ in 0..20 {
        serve(&set, &mut unit).await;
        settle().await;
        clock.advance(STEP);
    }
    let serving = status(&set, "candidate");
    assert!(serving.validated && !serving.rejected, "{serving:?}");
    assert!(
        reference.served().len() > failed_over,
        "nothing failed over"
    );
    assert_gauges_idle(&set);
}

#[tokio::test(flavor = "current_thread")]
async fn a_readmitted_endpoint_keeps_the_aggregate_contract() {
    let clock = Arc::new(ManualClock::new());
    let reference = Peer::new(fake());
    let candidate = Peer::new(fake().with_max_batch(1, U as u64));
    *candidate.glitch.lock().unwrap() = Some(Glitch::ShortEncrypt);
    let set = quarantine(
        vec![
            ("reference", reference.clone(), true),
            ("candidate", candidate.clone(), false),
        ],
        validator(Check::Full, Arc::new(AtomicUsize::new(0))),
        &clock,
    );
    let before = set.capabilities().await.unwrap();
    assert_eq!(
        before.batch.max_items, 1,
        "a quarantined endpoint counts towards the aggregate"
    );
    let mut unit = SERVING;
    serve(&set, &mut unit).await;
    settle().await;
    let deferred = status(&set, "candidate");
    assert!(!deferred.validated && !deferred.rejected, "{deferred:?}");
    clock.advance(INTERVAL);
    serve(&set, &mut unit).await;
    settle().await;
    assert!(status(&set, "candidate").validated);
    assert_eq!(set.capabilities().await.unwrap(), before);

    // A batch planned against the aggregate fails over intact to it.
    reference
        .inner
        .fail_next([CryptoError::Retryable("blip".into())]);
    let items: Vec<_> = (1..=4).map(|i| pt(unit + i)).collect();
    let out = set.encrypt_batch(&ctx(), &items).await.unwrap();
    assert_eq!(out.len(), items.len());
    assert_eq!(candidate.served().len(), 1);
    assert_eq!(candidate.largest_served.load(Ordering::SeqCst), 1);
    assert_gauges_idle(&set);
}
