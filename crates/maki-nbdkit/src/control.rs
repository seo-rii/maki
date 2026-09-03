//! Engine-backed control backend (SPEC §7): status, metrics snapshot,
//! graceful checkpoint, hot reloads.
//!
//! Reload sections that the engine cannot apply at runtime return an
//! explicit error (review M-005): a silent `Ok` for an unapplied change is
//! more dangerous than a refusal.

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::server::ControlBackend;
use maki_core::engine::{Engine, EngineState};

pub struct EngineControlBackend {
    engine: Engine,
    volume_name: String,
}

impl EngineControlBackend {
    pub fn new(engine: Engine, volume_name: impl Into<String>) -> Self {
        Self {
            engine,
            volume_name: volume_name.into(),
        }
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
            "backing_free_bytes": stats.backing_free_bytes,
            "checkpoints_total": stats.checkpoints_total,
            "checkpoint_failures_total": stats.checkpoint_failures_total,
            "security": crate::security::posture_json(),
        })
    }

    async fn metrics(&self) -> Value {
        let stats = self.engine.stats().await;
        let (_, state_code, _) = state_label(&stats.state);
        json!({
            "maki_volume_state": state_code,
            "maki_journal_appended_sequence": stats.appended_sequence,
            "maki_journal_durable_sequence": stats.durable_sequence,
            "maki_checkpoint_sequence": stats.checkpoint_sequence,
            "maki_journal_segments": stats.journal_segments,
            "maki_journal_bytes": stats.journal_total_bytes,
            "maki_journal_pending_bytes": stats.journal_pending_bytes,
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
        })
    }

    async fn checkpoint(&self) -> Result<u64, String> {
        self.engine.checkpoint().await.map_err(|e| e.to_string())
    }

    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String> {
        match section {
            // Hot-reloadable and actually applied (SPEC §20).
            "cache" => {
                let Some(max_bytes) = payload.get("max_bytes").and_then(|v| v.as_u64()) else {
                    return Err("reload cache: payload.max_bytes (integer) is required".to_string());
                };
                self.engine.resize_cache(max_bytes);
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
