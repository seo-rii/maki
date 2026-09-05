//! Engine-backed control backend (SPEC §7): status, metrics snapshot,
//! graceful checkpoint, hot reloads.
//!
//! Reload sections that the engine cannot apply at runtime return an
//! explicit error (review M-005): a silent `Ok` for an unapplied change is
//! more dangerous than a refusal.

use async_trait::async_trait;
use serde_json::{json, Value};

use std::sync::Arc;

use maki_control::server::ControlBackend;
use maki_core::engine::{Engine, EngineState};
use maki_crypto::breaker::CircuitState;
use maki_crypto::endpoint::EndpointSet;
use maki_crypto::scheduler::SchedulerStats;

pub struct EngineControlBackend {
    engine: Engine,
    volume_name: String,
    crypto_stats: Option<Arc<SchedulerStats>>,
    endpoints: Option<Arc<EndpointSet>>,
}

impl EngineControlBackend {
    pub fn new(engine: Engine, volume_name: impl Into<String>) -> Self {
        Self {
            engine,
            volume_name: volume_name.into(),
            crypto_stats: None,
            endpoints: None,
        }
    }

    /// Attach the batch scheduler's counters (remote providers).
    pub fn with_crypto_stats(mut self, stats: Option<Arc<SchedulerStats>>) -> Self {
        self.crypto_stats = stats;
        self
    }

    /// Attach the endpoint dispatcher (remote providers) for the per-endpoint
    /// and retry metrics SPEC §40 requires.
    pub fn with_endpoints(mut self, endpoints: Option<Arc<EndpointSet>>) -> Self {
        self.endpoints = endpoints;
        self
    }

    fn crypto_json(&self) -> Value {
        match &self.crypto_stats {
            None => json!({ "batched": false, "endpoints": self.endpoints_json() }),
            Some(s) => json!({
                "batched": true,
                "pending_items": s.pending_items(),
                "pending_bytes": s.pending_bytes(),
                "inflight_batches": s.inflight_batches(),
                "batches_total": s.batches_total(),
                "batched_items_total": s.batched_items_total(),
                "coalesced_batches_total": s.coalesced_batches_total(),
                "endpoints": self.endpoints_json(),
            }),
        }
    }

    /// One entry per endpoint: circuit, validation, inflight, budget.
    fn endpoints_json(&self) -> Value {
        let Some(set) = &self.endpoints else {
            return json!([]);
        };
        let tokens: std::collections::HashMap<String, f64> =
            set.endpoint_budget_tokens().into_iter().collect();
        Value::Array(
            set.endpoint_status()
                .into_iter()
                .map(|e| {
                    json!({
                        "name": e.name,
                        "circuit": circuit_label(e.circuit),
                        "validated": e.validated,
                        "rejected": e.rejected,
                        "inflight": e.inflight,
                        "retry_budget_tokens": tokens.get(&e.name).copied().unwrap_or(0.0),
                    })
                })
                .collect(),
        )
    }

    /// Per-endpoint gauges keyed by endpoint name (a bounded label set).
    fn per_endpoint(&self, f: impl Fn(&EndpointSet) -> Vec<(String, Value)>) -> Value {
        match &self.endpoints {
            None => json!({}),
            Some(set) => Value::Object(f(set).into_iter().collect()),
        }
    }
}

fn circuit_label(state: CircuitState) -> &'static str {
    match state {
        CircuitState::Closed => "closed",
        CircuitState::Open => "open",
        CircuitState::HalfOpen => "half-open",
    }
}

/// `maki_circuit_state` code: 0 closed, 1 open, 2 half-open.
fn circuit_code(state: CircuitState) -> u64 {
    match state {
        CircuitState::Closed => 0,
        CircuitState::Open => 1,
        CircuitState::HalfOpen => 2,
    }
}

fn state_label(state: &EngineState) -> (&'static str, u64, Option<String>) {
    match state {
        EngineState::Ready => ("ready", 1, None),
        EngineState::Degraded { reason } => ("degraded", 2, Some(reason.clone())),
    }
}

#[async_trait]
impl ControlBackend for EngineControlBackend {
    async fn status(&self) -> Value {
        let stats = self.engine.stats().await;
        let (label, _, reason) = state_label(&stats.state);
        json!({
            "state": label,
            "degraded_reason": reason,
            "volume": self.volume_name,
            "size": self.engine.size(),
            "durable_sequence": stats.durable_sequence,
            "appended_sequence": stats.appended_sequence,
            "checkpoint_sequence": stats.checkpoint_sequence,
            "journal_bytes": stats.journal_total_bytes,
            "journal_pending_bytes": stats.journal_pending_bytes,
            "journal_sync_failures_total": stats.journal_sync_failures_total,
            "journal_writeback_uncertain": stats.journal_writeback_uncertain,
            "backing_free_bytes": stats.backing_free_bytes,
            "checkpoints_total": stats.checkpoints_total,
            "checkpoint_failures_total": stats.checkpoint_failures_total,
            "security": crate::security::posture_json(),
            "crypto": self.crypto_json(),
        })
    }

    async fn metrics(&self) -> Value {
        let stats = self.engine.stats().await;
        let (_, state_code, _) = state_label(&stats.state);
        let dispatch = self.endpoints.as_ref().map(|set| set.metrics());
        let (inflight_rpcs, inflight_bytes) = self
            .endpoints
            .as_ref()
            .map(|set| set.global_inflight())
            .unwrap_or((0, 0));
        // SPEC §40 required gauges and counters (built as its own document:
        // one `json!` with every key exceeds the macro recursion limit).
        let spec = json!({
            "maki_active_callbacks": stats.active_callbacks,
            "maki_plaintext_bytes": stats.plaintext_bytes_in_flight,
            // Ciphertext held in memory: journal records not yet checkpointed.
            "maki_ciphertext_bytes": stats.overlay_bytes,
            "maki_submission_queue_items": self.crypto_stats.as_ref().map(|s| s.pending_items()).unwrap_or(0),
            "maki_submission_queue_bytes": self.crypto_stats.as_ref().map(|s| s.pending_bytes()).unwrap_or(0),
            "maki_crypto_inflight_batches": self.crypto_stats.as_ref().map(|s| s.inflight_batches()).unwrap_or(inflight_rpcs),
            "maki_crypto_inflight_bytes": inflight_bytes,
            "maki_endpoint_inflight": self.per_endpoint(|set| {
                set.endpoint_inflight()
                    .into_iter()
                    .map(|(name, n)| (name, json!(n)))
                    .collect()
            }),
            "maki_crypto_latency_seconds_sum": dispatch.map(|m| m.rpc_seconds_sum()).unwrap_or(0.0),
            "maki_crypto_latency_seconds_count": dispatch.map(|m| m.rpc_count()).unwrap_or(0),
            "maki_crypto_retries_total": dispatch.map(|m| m.retries_total()).unwrap_or(0),
            "maki_crypto_retries_refused_unsafe_total": dispatch.map(|m| m.retries_refused_unsafe_total()).unwrap_or(0),
            "maki_crypto_deadline_exceeded_total": dispatch.map(|m| m.deadline_exceeded_total()).unwrap_or(0),
            "maki_retry_budget_tokens": self.per_endpoint(|set| {
                set.endpoint_budget_tokens()
                    .into_iter()
                    .map(|(name, tokens)| (name, json!(tokens)))
                    .collect()
            }),
            "maki_circuit_state": self.per_endpoint(|set| {
                set.endpoint_states()
                    .into_iter()
                    .map(|(name, state)| (name, json!(circuit_code(state))))
                    .collect()
            }),
            "maki_endpoint_failover_total": dispatch.map(|m| m.failovers_total()).unwrap_or(0),
            "maki_flush_seconds_sum": stats.flush_latency.seconds_sum,
            "maki_flush_seconds_count": stats.flush_latency.count,
            "maki_flush_seconds_max": stats.flush_latency.seconds_max,
            "maki_fua_seconds_sum": stats.fua_latency.seconds_sum,
            "maki_fua_seconds_count": stats.fua_latency.count,
            "maki_fua_seconds_max": stats.fua_latency.seconds_max,
        });
        let mut doc = json!({
            "maki_volume_state": state_code,
            "maki_journal_appended_sequence": stats.appended_sequence,
            "maki_journal_durable_sequence": stats.durable_sequence,
            "maki_checkpoint_sequence": stats.checkpoint_sequence,
            "maki_journal_segments": stats.journal_segments,
            "maki_journal_bytes": stats.journal_total_bytes,
            "maki_journal_pending_bytes": stats.journal_pending_bytes,
            "maki_journal_sync_failures_total": stats.journal_sync_failures_total,
            "maki_journal_writeback_uncertain": u8::from(stats.journal_writeback_uncertain),
            "maki_checkpoint_lag_bytes": stats.overlay_bytes,
            "maki_checkpoints_total": stats.checkpoints_total,
            "maki_checkpoint_failures_total": stats.checkpoint_failures_total,
            "maki_backing_free_bytes": stats.backing_free_bytes,
            "maki_overlay_units": stats.overlay_units,
            "maki_overlay_bytes": stats.overlay_bytes,
            "maki_cache_hits_total": stats.cache_hits,
            "maki_cache_misses_total": stats.cache_misses,
            "maki_cache_bytes": stats.cache_bytes,
            "maki_cache_entries": stats.cache_entries,
            "maki_crypto_pending_items": self.crypto_stats.as_ref().map(|s| s.pending_items()).unwrap_or(0),
            "maki_crypto_pending_bytes": self.crypto_stats.as_ref().map(|s| s.pending_bytes()).unwrap_or(0),
            "maki_crypto_batches_total": self.crypto_stats.as_ref().map(|s| s.batches_total()).unwrap_or(0),
            "maki_crypto_coalesced_batches_total": self.crypto_stats.as_ref().map(|s| s.coalesced_batches_total()).unwrap_or(0),
        });
        if let (Some(into), Value::Object(from)) = (doc.as_object_mut(), spec) {
            into.extend(from);
        }
        doc
    }

    async fn checkpoint(&self) -> Result<u64, String> {
        self.engine.checkpoint().await.map_err(|e| e.to_string())
    }

    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String> {
        match section {
            // Hot-reloadable and actually applied (SPEC §20).
            "cache" => {
                let Some(max_bytes) = payload.get("max_bytes").and_then(|v| v.as_u64()) else {
                    return Err("reload cache: payload.max_bytes (integer) is required \
                                (`maki reload <config> cache --max-bytes N`)"
                        .to_string());
                };
                if !self.engine.resize_cache(max_bytes) {
                    return Err(
                        "reload cache: this daemon runs with cache.mode = off, so there is no \
                         cache to resize; the change was NOT applied (restart with cache.mode = read)"
                            .to_string(),
                    );
                }
                Ok(())
            }
            // Listed as hot-reloadable by SPEC §20 but not applied by this
            // engine yet: say so instead of pretending.
            "retry" | "circuit-breaker" | "batch" | "limits" | "timeouts" | "semaphores" => {
                Err(format!(
                    "section {section:?} is not applied at runtime by this build: \
                     the change was NOT applied; restart the daemon to pick it up"
                ))
            }
            "endpoints" | "credentials" => Err(format!(
                "section {section:?} reload is not applied at runtime by this build: \
                 the change was NOT applied; restart the daemon to pick it up"
            )),
            other => Err(format!(
                "section {other:?} is not hot-reloadable (SPEC §20)"
            )),
        }
    }
}
