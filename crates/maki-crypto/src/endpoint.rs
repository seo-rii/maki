//! Multi-endpoint crypto dispatcher (SPEC §30–§35).
//!
//! `EndpointSet` implements `CryptoProvider` over N interchangeable
//! endpoints (same compatibility profile — verified at attach by the
//! cross-endpoint self-test). Per call:
//!
//! - endpoint selection: validated + healthy + circuit admits + least
//!   inflight (§34),
//! - global and per-endpoint count+byte semaphores held **only** around the
//!   RPC — never across a backoff sleep (§31),
//! - within one pass, failure on one endpoint fails over to the next (§34);
//! - between passes: full-jitter backoff; retries into an endpoint are gated
//!   by that endpoint's own retry budget, whose minimum probe rate keeps a
//!   recovery path alive even at zero budget (§32);
//! - `max_attempts: None` = the `stall` availability policy (§35);
//!   `max_operation_time` is an absolute wall-clock deadline for
//!   `bounded-error`: it bounds backoff *and* cancels an in-flight RPC
//!   (review M-010);
//! - a provider that is not `retry_safe` is never sent the same request
//!   twice: after an RPC has been sent, no retry and no failover happens
//!   (review M-010);
//! - endpoints whose cross-endpoint validation could not run at attach are
//!   quarantined: they never serve until the validator (run against a
//!   validated endpoint, with the real volume context) succeeds (review
//!   M-011).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::breaker::{BreakerConfig, CircuitBreaker, CircuitState};
use crate::clock::Clock;
use crate::error::{CryptoError, ErrorClass};
use crate::flow::DualSemaphore;
use crate::provider::CryptoProvider;
use crate::retry::{full_jitter_delay, RetryBudget, RetryBudgetConfig, RetryPolicy};
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};

#[derive(Debug, Clone)]
pub struct DispatchConfig {
    pub retry: RetryPolicy,
    pub budget: RetryBudgetConfig,
    pub breaker: BreakerConfig,
    pub global_max_inflight_batches: u32,
    pub global_max_inflight_bytes: u64,
    pub per_endpoint_max_inflight: u32,
    pub per_endpoint_max_bytes: u64,
    /// `None` = stall (retry forever, bounded memory and frequency);
    /// `Some(n)` = bounded-error after n passes (SPEC §35).
    pub max_attempts: Option<u32>,
    /// Absolute wall-clock budget for one operation (SPEC §35
    /// `bounded-error`): backoff never sleeps past it and an in-flight RPC
    /// is abandoned when it expires. `None` = no deadline.
    pub max_operation_time: Option<Duration>,
    /// The provider's declared `retry_safe` capability. When false, a
    /// request is sent at most once: no retry, no failover.
    pub retry_safe: bool,
    /// Minimum spacing between validation attempts of a quarantined
    /// endpoint.
    pub validation_interval: Duration,
}

#[derive(Default)]
pub struct DispatchMetrics {
    retries: AtomicU64,
    failovers: AtomicU64,
    deadline_exceeded: AtomicU64,
    retries_refused_unsafe: AtomicU64,
}

impl DispatchMetrics {
    pub fn retries_total(&self) -> u64 {
        self.retries.load(Ordering::SeqCst)
    }

    pub fn failovers_total(&self) -> u64 {
        self.failovers.load(Ordering::SeqCst)
    }

    pub fn deadline_exceeded_total(&self) -> u64 {
        self.deadline_exceeded.load(Ordering::SeqCst)
    }

    /// Retries that would have happened but were refused because the
    /// provider is not retry-safe.
    pub fn retries_refused_unsafe_total(&self) -> u64 {
        self.retries_refused_unsafe.load(Ordering::SeqCst)
    }
}

pub type ValidationFuture = Pin<Box<dyn Future<Output = Result<(), CryptoError>> + Send>>;

/// Proves a quarantined endpoint interchangeable with a validated one,
/// under the real volume context (SPEC §34).
pub type EndpointValidator = Arc<
    dyn Fn(Arc<dyn CryptoProvider>, Arc<dyn CryptoProvider>, CryptoContext) -> ValidationFuture
        + Send
        + Sync,
>;

struct Endpoint {
    name: String,
    provider: Arc<dyn CryptoProvider>,
    breaker: CircuitBreaker,
    budget: RetryBudget,
    semaphore: DualSemaphore,
    inflight: AtomicU32,
    /// Cross-endpoint validation passed (at attach or later).
    validated: AtomicBool,
    /// Validation proved the endpoint *not* interchangeable: never retried.
    rejected: AtomicBool,
    /// A background validation of this endpoint is running.
    validating: AtomicBool,
    last_validation_attempt: parking_lot::Mutex<Option<Duration>>,
}

/// Decrements the endpoint's inflight count when dropped, so an RPC future
/// abandoned at the deadline still returns its slot (C-06).
struct InflightGuard<'a>(&'a AtomicU32);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Snapshot of one endpoint's admission state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointStatus {
    pub name: String,
    pub circuit: CircuitState,
    pub validated: bool,
    pub rejected: bool,
    pub inflight: u32,
}

pub struct EndpointSet {
    endpoints: Vec<Arc<Endpoint>>,
    global: DualSemaphore,
    policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    config: DispatchConfig,
    metrics: DispatchMetrics,
    validator: Option<EndpointValidator>,
}

enum Request<'a> {
    Encrypt(&'a [PlaintextUnit]),
    Decrypt(&'a [CiphertextUnit]),
}

enum Response {
    Encrypted(Vec<CiphertextUnit>),
    Decrypted(Vec<PlaintextUnit>),
}

impl Request<'_> {
    fn bytes(&self) -> u64 {
        match self {
            Request::Encrypt(items) => items.iter().map(|i| i.data.len() as u64).sum(),
            Request::Decrypt(items) => items.iter().map(|i| i.data.len() as u64).sum(),
        }
    }
}

const DEADLINE_MESSAGE: &str = "operation deadline exceeded";

fn deadline_error() -> CryptoError {
    CryptoError::Retryable(DEADLINE_MESSAGE.to_string())
}

/// The *operation's* wall-clock budget ran out; says nothing about the
/// health of whichever endpoint happened to be in flight.
fn is_deadline_error(err: &CryptoError) -> bool {
    matches!(err, CryptoError::Retryable(m) if m == DEADLINE_MESSAGE)
}

impl EndpointSet {
    /// All endpoints validated (the caller ran the cross-endpoint self-test
    /// for every pair before building the set).
    pub fn new(
        endpoints: Vec<(String, Arc<dyn CryptoProvider>)>,
        config: DispatchConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_quarantine(
            endpoints
                .into_iter()
                .map(|(name, provider)| (name, provider, true))
                .collect(),
            None,
            config,
            clock,
        )
    }

    /// Endpoints with an explicit validated flag; unvalidated ones are
    /// quarantined until `validator` succeeds for them. At least one
    /// endpoint must be validated.
    pub fn with_quarantine(
        endpoints: Vec<(String, Arc<dyn CryptoProvider>, bool)>,
        validator: Option<EndpointValidator>,
        config: DispatchConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        assert!(!endpoints.is_empty(), "at least one endpoint required");
        assert!(
            endpoints.iter().any(|(_, _, validated)| *validated),
            "at least one validated endpoint required"
        );
        let endpoints = endpoints
            .into_iter()
            .map(|(name, provider, validated)| {
                Arc::new(Endpoint {
                    name,
                    provider,
                    breaker: CircuitBreaker::new(config.breaker.clone(), clock.clone()),
                    budget: RetryBudget::new(config.budget.clone(), clock.clone()),
                    semaphore: DualSemaphore::new(
                        config.per_endpoint_max_inflight,
                        config.per_endpoint_max_bytes,
                    ),
                    inflight: AtomicU32::new(0),
                    validated: AtomicBool::new(validated),
                    rejected: AtomicBool::new(false),
                    validating: AtomicBool::new(false),
                    last_validation_attempt: parking_lot::Mutex::new(None),
                })
            })
            .collect();
        Self {
            endpoints,
            global: DualSemaphore::new(
                config.global_max_inflight_batches,
                config.global_max_inflight_bytes,
            ),
            policy: config.retry.clone(),
            clock,
            config,
            metrics: DispatchMetrics::default(),
            validator,
        }
    }

    pub fn metrics(&self) -> &DispatchMetrics {
        &self.metrics
    }

    pub fn endpoint_states(&self) -> Vec<(String, CircuitState)> {
        self.endpoints
            .iter()
            .map(|e| (e.name.clone(), e.breaker.state()))
            .collect()
    }

    pub fn endpoint_inflight(&self) -> Vec<(String, u32)> {
        self.endpoints
            .iter()
            .map(|e| (e.name.clone(), e.inflight.load(Ordering::SeqCst)))
            .collect()
    }

    pub fn endpoint_status(&self) -> Vec<EndpointStatus> {
        self.endpoints
            .iter()
            .map(|e| EndpointStatus {
                name: e.name.clone(),
                circuit: e.breaker.state(),
                validated: e.validated.load(Ordering::SeqCst),
                rejected: e.rejected.load(Ordering::SeqCst),
                inflight: e.inflight.load(Ordering::SeqCst),
            })
            .collect()
    }

    /// Admissible endpoints, least-inflight first (SPEC §34): validated and
    /// with a circuit that would admit a call.
    fn candidates(&self) -> Vec<Arc<Endpoint>> {
        let mut out: Vec<Arc<Endpoint>> = self
            .endpoints
            .iter()
            .filter(|e| e.validated.load(Ordering::SeqCst) && e.breaker.would_allow())
            .cloned()
            .collect();
        out.sort_by_key(|e| e.inflight.load(Ordering::SeqCst));
        out
    }

    /// Start validating quarantined endpoints (bounded by
    /// `validation_interval`, one run per endpoint at a time) against a
    /// validated, admitting reference. The validator makes real RPCs to an
    /// endpoint that was unreachable at attach and may be so still, so it
    /// runs in a background task: awaiting it on the request path stalled
    /// every request behind that endpoint's transport timeout (C-03).
    fn promote_quarantined(&self, context: &CryptoContext) {
        let Some(validator) = &self.validator else {
            return;
        };
        let pending: Vec<Arc<Endpoint>> = self
            .endpoints
            .iter()
            .filter(|e| {
                !e.validated.load(Ordering::SeqCst)
                    && !e.rejected.load(Ordering::SeqCst)
                    && !e.validating.load(Ordering::SeqCst)
                    && e.breaker.would_allow()
            })
            .cloned()
            .collect();
        if pending.is_empty() {
            return;
        }
        let Some(reference) = self
            .endpoints
            .iter()
            .find(|e| e.validated.load(Ordering::SeqCst) && e.breaker.would_allow())
            .cloned()
        else {
            return;
        };
        let now = self.clock.now();
        for endpoint in pending {
            {
                let mut last = endpoint.last_validation_attempt.lock();
                if let Some(at) = *last {
                    if now.saturating_sub(at) < self.config.validation_interval {
                        continue;
                    }
                }
                *last = Some(now);
            }
            if endpoint.validating.swap(true, Ordering::SeqCst) {
                continue;
            }
            // The validator is *invoked* here (its attempt is accounted
            // synchronously); only the resulting future runs in the
            // background.
            let attempt = validator(
                reference.provider.clone(),
                endpoint.provider.clone(),
                context.clone(),
            );
            tokio::spawn(async move {
                let result = attempt.await;
                match result {
                    Ok(()) => {
                        endpoint.validated.store(true, Ordering::SeqCst);
                        tracing::info!("endpoint {:?} validated and admitted", endpoint.name);
                    }
                    Err(e) if matches!(e.class(), ErrorClass::ProviderFatal) => {
                        endpoint.rejected.store(true, Ordering::SeqCst);
                        tracing::error!(
                            "endpoint {:?} is not interchangeable and stays excluded: {e}",
                            endpoint.name
                        );
                    }
                    Err(e) => {
                        // Which side was unreachable is unknown here; leave
                        // the breakers to real traffic and try again later.
                        tracing::warn!(
                            "endpoint {:?} validation deferred (endpoint unavailable): {e}",
                            endpoint.name
                        );
                    }
                }
                endpoint.validating.store(false, Ordering::SeqCst);
            });
        }
    }

    async fn call_endpoint(
        &self,
        endpoint: &Endpoint,
        context: &CryptoContext,
        request: &Request<'_>,
        bytes: u64,
    ) -> Result<Response, CryptoError> {
        // Permits live only for the duration of the RPC.
        let _global = self.global.acquire(bytes).await;
        let _local = endpoint.semaphore.acquire(bytes).await;
        endpoint.inflight.fetch_add(1, Ordering::SeqCst);
        let _inflight = InflightGuard(&endpoint.inflight);
        match request {
            Request::Encrypt(items) => endpoint
                .provider
                .encrypt_batch(context, items)
                .await
                .map(Response::Encrypted),
            Request::Decrypt(items) => endpoint
                .provider
                .decrypt_batch(context, items)
                .await
                .map(Response::Decrypted),
        }
    }

    /// The RPC, abandoned at the deadline (the dropped future cancels the
    /// transport request).
    async fn call_with_deadline(
        &self,
        endpoint: &Endpoint,
        context: &CryptoContext,
        request: &Request<'_>,
        bytes: u64,
        deadline: Option<Duration>,
    ) -> Result<Response, CryptoError> {
        let call = self.call_endpoint(endpoint, context, request, bytes);
        match deadline {
            None => call.await,
            Some(deadline) => {
                let remaining = deadline.saturating_sub(self.clock.now());
                if remaining.is_zero() {
                    return Err(deadline_error());
                }
                let timer = self.clock.sleep(remaining);
                tokio::select! {
                    result = call => result,
                    _ = timer => {
                        self.metrics.deadline_exceeded.fetch_add(1, Ordering::SeqCst);
                        Err(deadline_error())
                    }
                }
            }
        }
    }

    async fn dispatch(
        &self,
        context: &CryptoContext,
        request: Request<'_>,
    ) -> Result<Response, CryptoError> {
        let bytes = request.bytes();
        let started = self.clock.now();
        let deadline = self
            .config
            .max_operation_time
            .map(|d| started.saturating_add(d));
        let mut calls_made = 0u32;
        let mut pass = 0u32;
        let mut last_error: Option<CryptoError> = None;
        // Endpoints this operation has already been sent to: a repeat
        // attempt on one of them is a retry charged to *its* budget; a first
        // attempt on another endpoint is a failover (a fresh request for it).
        let mut tried: Vec<Arc<Endpoint>> = Vec::new();

        loop {
            if let Some(max) = self.config.max_attempts {
                if pass >= max {
                    return Err(last_error.unwrap_or_else(|| {
                        CryptoError::Retryable("attempts exhausted".to_string())
                    }));
                }
            }
            if let Some(dl) = deadline {
                if self.clock.now() >= dl {
                    self.metrics
                        .deadline_exceeded
                        .fetch_add(1, Ordering::SeqCst);
                    return Err(last_error.unwrap_or_else(deadline_error));
                }
            }

            self.promote_quarantined(context);

            // One pass: try each admissible endpoint once, failing over
            // between them.
            let candidates = self.candidates();
            let mut tried_any = false;
            for endpoint in candidates {
                if !endpoint.breaker.allow() {
                    continue;
                }
                if calls_made > 0 {
                    // A re-send of a request that already reached a provider.
                    if !self.config.retry_safe {
                        self.metrics
                            .retries_refused_unsafe
                            .fetch_add(1, Ordering::SeqCst);
                        return Err(last_error.unwrap_or_else(|| {
                            CryptoError::Retryable("provider is not retry-safe".to_string())
                        }));
                    }
                    let repeat = tried.iter().any(|t| Arc::ptr_eq(t, &endpoint));
                    if repeat {
                        // Endpoint-local retry budget (SPEC §32).
                        if !endpoint.budget.allow_retry() {
                            continue;
                        }
                    } else {
                        endpoint.budget.note_request();
                    }
                    self.metrics.retries.fetch_add(1, Ordering::SeqCst);
                    if tried_any {
                        self.metrics.failovers.fetch_add(1, Ordering::SeqCst);
                    }
                } else {
                    endpoint.budget.note_request();
                }
                if !tried.iter().any(|t| Arc::ptr_eq(t, &endpoint)) {
                    tried.push(endpoint.clone());
                }
                tried_any = true;
                calls_made += 1;
                match self
                    .call_with_deadline(&endpoint, context, &request, bytes, deadline)
                    .await
                {
                    Ok(response) => {
                        endpoint.breaker.on_success();
                        return Ok(response);
                    }
                    Err(err) => {
                        if is_deadline_error(&err) {
                            // The operation's budget ran out mid-RPC: not
                            // an endpoint failure, so no breaker or budget
                            // charge (C-06).
                            return Err(err);
                        }
                        match err.class() {
                            ErrorClass::Retryable
                            | ErrorClass::Throttled
                            | ErrorClass::EndpointFatal => {
                                endpoint.breaker.on_failure();
                                last_error = Some(err);
                                if let Some(dl) = deadline {
                                    if self.clock.now() >= dl {
                                        return Err(last_error.unwrap());
                                    }
                                }
                                if !self.config.retry_safe {
                                    // The request may have reached the
                                    // provider: never send it again.
                                    self.metrics
                                        .retries_refused_unsafe
                                        .fetch_add(1, Ordering::SeqCst);
                                    return Err(last_error.unwrap());
                                }
                                // fall through to the next endpoint
                            }
                            ErrorClass::NonRetryableRequest | ErrorClass::ProviderFatal => {
                                // Not the endpoint's fault (or fatal for the
                                // whole provider): never retried into.
                                return Err(err);
                            }
                        }
                    }
                }
            }

            // Whole pass failed (or nothing admissible): back off with full
            // jitter — no permits are held here (SPEC §31) — never past
            // the deadline.
            let mut delay = {
                let mut rng = rand::rng();
                full_jitter_delay(&self.policy, pass, &mut rng)
            };
            if let Some(dl) = deadline {
                delay = delay.min(dl.saturating_sub(self.clock.now()));
            }
            self.clock.sleep(delay).await;
            pass += 1;
        }
    }
}

#[async_trait]
impl CryptoProvider for EndpointSet {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        // Endpoints are interchangeable (verified by the cross-endpoint
        // self-test); report a validated one's contract.
        let endpoint = self
            .endpoints
            .iter()
            .find(|e| e.validated.load(Ordering::SeqCst))
            .unwrap_or(&self.endpoints[0]);
        endpoint.provider.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        match self.dispatch(context, Request::Encrypt(items)).await? {
            Response::Encrypted(out) => Ok(out),
            Response::Decrypted(_) => unreachable!(),
        }
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        match self.dispatch(context, Request::Decrypt(items)).await? {
            Response::Decrypted(out) => Ok(out),
            Response::Encrypted(_) => unreachable!(),
        }
    }
}
