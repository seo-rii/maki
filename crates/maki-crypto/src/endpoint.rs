//! Multi-endpoint crypto dispatcher (SPEC §30–§35).
//!
//! `EndpointSet` implements `CryptoProvider` over N interchangeable
//! endpoints (same compatibility profile — verified at attach by the
//! cross-endpoint self-test). Per call:
//!
//! - endpoint selection: healthy + circuit admits + least inflight (§34),
//! - global and per-endpoint count+byte semaphores held **only** around the
//!   RPC — never across a backoff sleep (§31),
//! - within one pass, failure on one endpoint fails over to the next (§34);
//! - between passes: full-jitter backoff gated by the retry budget, whose
//!   minimum probe rate keeps a recovery path alive even at zero budget
//!   (§32); `max_attempts: None` = the `stall` availability policy (§35).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

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
    /// `Some(n)` = bounded-error after n attempts (SPEC §35).
    pub max_attempts: Option<u32>,
}

#[derive(Default)]
pub struct DispatchMetrics {
    retries: AtomicU64,
    failovers: AtomicU64,
}

impl DispatchMetrics {
    pub fn retries_total(&self) -> u64 {
        self.retries.load(Ordering::SeqCst)
    }

    pub fn failovers_total(&self) -> u64 {
        self.failovers.load(Ordering::SeqCst)
    }
}

struct Endpoint {
    name: String,
    provider: Arc<dyn CryptoProvider>,
    breaker: CircuitBreaker,
    semaphore: DualSemaphore,
    inflight: AtomicU32,
}

pub struct EndpointSet {
    endpoints: Vec<Arc<Endpoint>>,
    global: DualSemaphore,
    budget: RetryBudget,
    policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    config: DispatchConfig,
    metrics: DispatchMetrics,
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

impl EndpointSet {
    pub fn new(
        endpoints: Vec<(String, Arc<dyn CryptoProvider>)>,
        config: DispatchConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        assert!(!endpoints.is_empty(), "at least one endpoint required");
        let endpoints = endpoints
            .into_iter()
            .map(|(name, provider)| {
                Arc::new(Endpoint {
                    name,
                    provider,
                    breaker: CircuitBreaker::new(config.breaker.clone(), clock.clone()),
                    semaphore: DualSemaphore::new(
                        config.per_endpoint_max_inflight,
                        config.per_endpoint_max_bytes,
                    ),
                    inflight: AtomicU32::new(0),
                })
            })
            .collect();
        Self {
            endpoints,
            global: DualSemaphore::new(
                config.global_max_inflight_batches,
                config.global_max_inflight_bytes,
            ),
            budget: RetryBudget::new(config.budget.clone(), clock.clone()),
            policy: config.retry.clone(),
            clock,
            config,
            metrics: DispatchMetrics::default(),
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

    /// Admissible endpoints, least-inflight first (SPEC §34).
    fn candidates(&self) -> Vec<Arc<Endpoint>> {
        let mut out: Vec<Arc<Endpoint>> = self
            .endpoints
            .iter()
            .filter(|e| e.breaker.would_allow())
            .cloned()
            .collect();
        out.sort_by_key(|e| e.inflight.load(Ordering::SeqCst));
        out
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
        endpoint.inflight.fetch_sub(1, Ordering::SeqCst);
        result
    }

    async fn dispatch(
        &self,
        context: &CryptoContext,
        request: Request<'_>,
    ) -> Result<Response, CryptoError> {
        self.budget.note_request();
        let bytes = request.bytes();
        let mut calls_made = 0u32;
        let mut pass = 0u32;
        let mut last_error: Option<CryptoError> = None;

        loop {
            if let Some(max) = self.config.max_attempts {
                if pass >= max {
                    return Err(last_error.unwrap_or_else(|| {
                        CryptoError::Retryable("attempts exhausted".to_string())
                    }));
                }
            }

            // One pass: try each admissible endpoint once, failing over
            // between them.
            let candidates = self.candidates();
            let mut tried_any = false;
            for endpoint in candidates {
                if !endpoint.breaker.allow() {
                    continue;
                }
                if calls_made > 0 {
                    self.metrics.retries.fetch_add(1, Ordering::SeqCst);
                }
                if tried_any {
                    self.metrics.failovers.fetch_add(1, Ordering::SeqCst);
                }
                tried_any = true;
                calls_made += 1;
                match self.call_endpoint(&endpoint, context, &request, bytes).await {
                    Ok(response) => {
                        endpoint.breaker.on_success();
                        return Ok(response);
                    }
                    Err(err) => {
                        match err.class() {
                            ErrorClass::Retryable
                            | ErrorClass::Throttled
                            | ErrorClass::EndpointFatal => {
                                endpoint.breaker.on_failure();
                                last_error = Some(err);
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
            // jitter — no permits are held here (SPEC §31) — then respect
            // the retry budget / minimum probe rate (SPEC §32).
            let delay = {
                let mut rng = rand::rng();
                full_jitter_delay(&self.policy, pass, &mut rng)
            };
            self.clock.sleep(delay).await;
            while !self.budget.allow_retry() {
                let delay = {
                    let mut rng = rand::rng();
                    full_jitter_delay(&self.policy, u32::MAX, &mut rng)
                };
                self.clock.sleep(delay).await;
            }
            pass += 1;
        }
    }
}

#[async_trait]
impl CryptoProvider for EndpointSet {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        // Endpoints are interchangeable (verified by the cross-endpoint
        // self-test at attach); report the first one's contract.
        self.endpoints[0].provider.capabilities().await
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
