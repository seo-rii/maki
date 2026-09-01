//! Control server: dispatches protocol requests to a `ControlBackend`.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::protocol::{read_line, ProtocolError, Request};

/// What the daemon exposes to the control plane (SPEC §7).
#[async_trait]
pub trait ControlBackend: Send + Sync + 'static {
    async fn status(&self) -> Value;
    async fn metrics(&self) -> Value;
    async fn checkpoint(&self) -> Result<u64, String>;
    /// Hot reload of a reloadable section (SPEC §20): endpoints,
    /// credentials, timeouts, retry, circuit-breaker, semaphores, batch,
    /// cache.
    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String>;
}

/// Privileged verbs that must never be served here (PRIV-009).
const PRIVILEGED_VERBS: &[&str] = &[
    "attach",
    "detach",
    "mount",
    "umount",
    "grow",
    "nbd-connect",
    "nbd-disconnect",
    "lvm",
];

async fn handle(backend: &Arc<dyn ControlBackend>, request: Request) -> Value {
    match request.command.as_str() {
        "status" => json!({"ok": true, "data": backend.status().await}),
        "metrics" => json!({"ok": true, "data": backend.metrics().await}),
        "checkpoint" => match backend.checkpoint().await {
            Ok(seq) => json!({"ok": true, "data": {"checkpoint_sequence": seq}}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        "reload" => {
            let section = request.section.as_deref().unwrap_or("");
            match backend.reload(section, &request.payload).await {
                Ok(()) => json!({"ok": true, "data": {}}),
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        verb if PRIVILEGED_VERBS.contains(&verb) => json!({
            "ok": false,
            "error": format!(
                "{verb:?} is a privileged operation: use the maki-attach \
                 privileged helper (maki attach/detach/grow), not the control socket"
            ),
        }),
        other => json!({
            "ok": false,
            "error": format!("unknown command {other:?}"),
        }),
    }
}

/// Serve one connection until EOF. Errors terminate the session (bounded
/// input; a protocol violation never grows memory unboundedly).
pub async fn serve_connection<S>(
    stream: S,
    backend: Arc<dyn ControlBackend>,
) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        let line = match read_line(&mut rd).await {
            Ok(line) => line,
            Err(ProtocolError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(request) => handle(&backend, request).await,
            Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
        };
        let mut bytes = serde_json::to_vec(&response)?;
        bytes.push(b'\n');
        wr.write_all(&bytes).await?;
        wr.flush().await?;
    }
}
