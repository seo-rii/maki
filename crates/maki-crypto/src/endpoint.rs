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
use tokio::sync::OnceCell;

use crate::breaker::{BreakerConfig, CircuitBreaker, CircuitState};
use crate::checked::{validate_decrypt_result, validate_encrypt_result};
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
    /// Completed RPC attempts and their total latency in nanoseconds
    /// (SPEC §40 `maki_crypto_latency_seconds`); an attempt abandoned at
    /// the deadline is not a sample.
    rpc_count: AtomicU64,
    rpc_nanos: AtomicU64,
}

impl DispatchMetrics {
    pub fn retries_total(&self) -> u64 {
        self.retries.load(Ordering::SeqCst)
    }

    /// Completed RPC attempts (successful or failed).
    pub fn rpc_count(&self) -> u64 {
        self.rpc_count.load(Ordering::SeqCst)
    }

    /// Total latency of completed RPC attempts, in seconds.
    pub fn rpc_seconds_sum(&self) -> f64 {
        self.rpc_nanos.load(Ordering::SeqCst) as f64 / 1e9
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
    caps: OnceCell<CryptoCapabilities>,
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

pub(crate) fn deadline_error() -> CryptoError {
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
            caps: OnceCell::new(),
        }
    }

    /// Freeze the contract across all configured peers, including ones that
    /// are quarantined. Promotion must never lower the serving limits.
    async fn common_caps(&self) -> Result<&CryptoCapabilities, CryptoError> {
        self.caps
            .get_or_try_init(|| async {
                let first = self
                    .endpoints
                    .iter()
                    .position(|e| e.validated.load(Ordering::SeqCst))
                    .expect("EndpointSet requires a validated endpoint");
                let mut common = self.endpoints[first].provider.capabilities().await?;
                // Preserve the validated endpoint's identity, while including
                // the limits of every compatible peer that might later serve.
                for index in std::iter::once(first)
                    .chain((0..self.endpoints.len()).filter(|index| *index != first))
                {
                    let endpoint = &self.endpoints[index];
                    let caps = if index == first {
                        common.clone()
                    } else {
                        endpoint.provider.capabilities().await?
                    };
                    if caps.crypto_compatibility_id != common.crypto_compatibility_id {
                        if !endpoint.validated.load(Ordering::SeqCst) {
                            // A known incompatible peer cannot serve under
                            // this contract, even if its validator is lax.
                            endpoint.rejected.store(true, Ordering::SeqCst);
                            continue;
                        }
                        return Err(CryptoError::Contract(format!(
                            "endpoint {:?} reports compatibility id {:?}, the set requires {:?}",
                            endpoint.name,
                            caps.crypto_compatibility_id,
                            common.crypto_compatibility_id
                        )));
                    }
                    if caps.batch.max_items == 0
                        || caps.batch.max_bytes == 0
                        || caps.max_ciphertext_size == 0
                        || caps.supported_plaintext_sizes.is_empty()
                        || caps.supported_plaintext_sizes.contains(&0)
                    {
                        return Err(CryptoError::ProviderFatal(format!(
                            "endpoint {:?} advertises an empty crypto contract",
                            endpoint.name
                        )));
                    }
                    if index != first {
                        common = common.intersect(&caps);
                    }
                }
                common.supported_plaintext_sizes.sort_unstable();
                common.supported_plaintext_sizes.dedup();
                if !common.batch.supported {
                    common.batch.max_items = 1;
                }
                Ok(common)
            })
            .await
    }

    async fn common_caps_with_deadline(
        &self,
        deadline: Option<Duration>,
    ) -> Result<&CryptoCapabilities, CryptoError> {
        let Some(deadline) = deadline else {
            return self.common_caps().await;
        };
        let remaining = deadline.saturating_sub(self.clock.now());
        if !remaining.is_zero() {
            let timer = self.clock.sleep(remaining);
            tokio::select! {
                result = self.common_caps() => return result,
                _ = timer => {}
            }
        }
        self.metrics
            .deadline_exceeded
            .fetch_add(1, Ordering::SeqCst);
        Err(deadline_error())
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

    /// Retry-budget tokens available per endpoint (SPEC §40
    /// `maki_retry_budget_tokens`).
    pub fn endpoint_budget_tokens(&self) -> Vec<(String, f64)> {
        self.endpoints
            .iter()
            .map(|e| (e.name.clone(), e.budget.tokens()))
            .collect()
    }

    /// RPCs and bytes currently holding the set's global permits
    /// (`maki_crypto_inflight_batches`, `maki_crypto_inflight_bytes`).
    pub fn global_inflight(&self) -> (u64, u64) {
        (
            (self.global.max_items() - self.global.available_items()) as u64,
            self.global.max_bytes() - self.global.available_bytes(),
        )
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
        let _global = self.global.acquire(bytes).await?;
        let _local = endpoint.semaphore.acquire(bytes).await?;
        endpoint.inflight.fetch_add(1, Ordering::SeqCst);
        let _inflight = InflightGuard(&endpoint.inflight);
        let started = self.clock.now();
        let result = match request {
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
        };
        let elapsed = self.clock.now().saturating_sub(started);
        self.metrics.rpc_count.fetch_add(1, Ordering::SeqCst);
        self.metrics.rpc_nanos.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::SeqCst,
        );
        result
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
        deadline: Option<Duration>,
        retry_safe: bool,
    ) -> Result<Response, CryptoError> {
        let bytes = request.bytes();
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
                let Some(probe) = endpoint.breaker.acquire() else {
                    continue;
                };
                if calls_made > 0 {
                    // A re-send of a request that already reached a provider.
                    if !retry_safe {
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
                        probe.on_success();
                        return Ok(response);
                    }
                    Err(err) => {
                        if is_deadline_error(&err) {
                            // The operation's budget ran out mid-RPC: not
                            // an endpoint failure, so no breaker or budget
                            // charge (C-06). The probe permit drops here
                            // and returns its half-open slot without a
                            // verdict, or abandoned probes would wedge the
                            // circuit (BUG-004 / N-10).
                            return Err(err);
                        }
                        match err.class() {
                            ErrorClass::Retryable
                            | ErrorClass::Throttled
                            | ErrorClass::EndpointFatal => {
                                probe.on_failure();
                                last_error = Some(err);
                                if let Some(dl) = deadline {
                                    if self.clock.now() >= dl {
                                        return Err(last_error.unwrap());
                                    }
                                }
                                if !retry_safe {
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
    fn max_operation_time(&self) -> Option<Duration> {
        self.config.max_operation_time
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.common_caps().await?.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let deadline = self
            .config
            .max_operation_time
            .map(|d| self.clock.now().saturating_add(d));
        let caps = self.common_caps_with_deadline(deadline).await?;
        // Validate the entire input before sending even the first chunk.
        if items.iter().any(|item| {
            !caps.accepts_plaintext_size(item.data.len())
                || item.data.len() as u64 > caps.batch.max_bytes
        }) {
            return Err(CryptoError::NonRetryableRequest(
                "plaintext unit exceeds the common endpoint contract".into(),
            ));
        }
        let mut out = Vec::with_capacity(items.len());
        let mut start = 0;
        while start < items.len() {
            let mut end = start;
            let mut bytes = 0u64;
            while end < items.len() && end - start < caps.batch.max_items as usize {
                let size = items[end].data.len() as u64;
                if size > caps.batch.max_bytes - bytes {
                    break;
                }
                bytes += size;
                end += 1;
            }
            let chunk = &items[start..end];
            match self
                .dispatch(
                    context,
                    Request::Encrypt(chunk),
                    deadline,
                    self.config.retry_safe && caps.retry_safe,
                )
                .await?
            {
                Response::Encrypted(mut result) => {
                    validate_encrypt_result(chunk, &result, caps)?;
                    out.append(&mut result);
                }
                Response::Decrypted(_) => unreachable!(),
            }
            start = end;
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let deadline = self
            .config
            .max_operation_time
            .map(|d| self.clock.now().saturating_add(d));
        let caps = self.common_caps_with_deadline(deadline).await?;
        if items
            .iter()
            .any(|item| item.data.is_empty() || item.data.len() > caps.max_ciphertext_size as usize)
        {
            return Err(CryptoError::NonRetryableRequest(
                "ciphertext unit exceeds the common endpoint contract".into(),
            ));
        }
        // Ciphertext length is not plaintext length. Without a pinned volume
        // size, reserve the largest common plaintext size for every item.
        let logical_size = u64::from(*caps.supported_plaintext_sizes.last().ok_or_else(|| {
            CryptoError::NonRetryableRequest("endpoints have no common plaintext unit size".into())
        })?);
        let chunk_size =
            (caps.batch.max_bytes / logical_size).min(u64::from(caps.batch.max_items)) as usize;
        if chunk_size == 0 {
            return Err(CryptoError::NonRetryableRequest(
                "plaintext unit exceeds the common endpoint batch byte limit".into(),
            ));
        }
        let mut out = Vec::with_capacity(items.len());
        for chunk in items.chunks(chunk_size) {
            match self
                .dispatch(
                    context,
                    Request::Decrypt(chunk),
                    deadline,
                    self.config.retry_safe && caps.retry_safe,
                )
                .await?
            {
                Response::Decrypted(mut result) => {
                    validate_decrypt_result(chunk, &result, caps)?;
                    out.append(&mut result);
                }
                Response::Encrypted(_) => unreachable!(),
            }
        }
        Ok(out)
    }
}
