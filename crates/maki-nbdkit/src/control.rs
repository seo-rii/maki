//! Engine-backed control backend (SPEC §7): status, metrics snapshot,
//! graceful checkpoint, hot reloads.

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::server::ControlBackend;
use maki_core::engine::Engine;

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

#[async_trait]
impl ControlBackend for EngineControlBackend {
    async fn status(&self) -> Value {
        let stats = self.engine.stats().await;
        json!({
            "state": "ready",
            "volume": self.volume_name,
            "size": self.engine.size(),
            "durable_sequence": stats.durable_sequence,
            "appended_sequence": stats.appended_sequence,
            "checkpoint_sequence": stats.checkpoint_sequence,
        })
    }

    async fn metrics(&self) -> Value {
        let stats = self.engine.stats().await;
        json!({
            "maki_volume_state": 1,
            "maki_journal_appended_sequence": stats.appended_sequence,
            "maki_journal_durable_sequence": stats.durable_sequence,
            "maki_checkpoint_sequence": stats.checkpoint_sequence,
            "maki_journal_segments": stats.journal_segments,
            "maki_journal_bytes": stats.journal_pending_bytes,
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
            // Hot-reloadable sections (SPEC §20).
            "cache" => {
                if let Some(max_bytes) = payload.get("max_bytes").and_then(|v| v.as_u64()) {
                    self.engine.resize_cache(max_bytes);
                }
                Ok(())
            }
            "retry" | "circuit-breaker" | "batch" | "limits" => Ok(()),
            "endpoints" | "credentials" => Err(format!(
                "section {section:?} reload requires a remote provider"
            )),
            other => Err(format!(
                "section {other:?} is not hot-reloadable (SPEC §20)"
            )),
        }
    }
}
