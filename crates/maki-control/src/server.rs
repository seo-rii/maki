//! Control server: dispatches protocol requests to a `ControlBackend`.
//!
//! Sessions are bounded (third review, F10): a fixed number are served at
//! once (the rest wait in the listen backlog), an idle session is closed
//! after a timeout, a client that does not drain its response is
//! disconnected, and mutating verbs (`checkpoint`, `reload`, `drain`) run one at a
//! time — a second one is refused as busy instead of queueing behind the
//! first, so `status` and `metrics` are never buried under a pile of
//! administrative requests.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::protocol::{read_line, ProtocolError, Request};

/// Bounds on control sessions. Fixed values: the control plane is local
/// and single-purpose, so there is nothing to tune per deployment.
#[derive(Debug, Clone, Copy)]
pub struct ControlLimits {
    /// Sessions served concurrently; further connections wait in the
    /// listen backlog until one ends.
    pub max_sessions: usize,
    /// A session that sends no request for this long is closed.
    pub idle_timeout: Duration,
    /// A client that does not drain a response within this long is
    /// disconnected.
    pub write_timeout: Duration,
}

impl Default for ControlLimits {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            idle_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(10),
        }
    }
}

/// Runs at most one mutating verb at a time; a concurrent `checkpoint` or
/// `reload` is refused with a `busy` error rather than queued.
pub struct SerializedBackend {
    inner: Arc<dyn ControlBackend>,
    gate: Semaphore,
}

impl SerializedBackend {
    pub fn new(inner: Arc<dyn ControlBackend>) -> Self {
        Self {
            inner,
            gate: Semaphore::new(1),
        }
    }

    fn busy() -> String {
        "busy: another administrative mutation is in progress; retry later".to_string()
    }
}

#[async_trait]
impl ControlBackend for SerializedBackend {
    async fn status(&self) -> Value {
        self.inner.status().await
    }

    async fn metrics(&self) -> Value {
        self.inner.metrics().await
    }

    async fn checkpoint(&self) -> Result<u64, String> {
        let _slot = self.gate.try_acquire().map_err(|_| Self::busy())?;
        self.inner.checkpoint().await
    }

    async fn drain(&self) -> Result<u64, String> {
        let _slot = self.gate.try_acquire().map_err(|_| Self::busy())?;
        self.inner.drain().await
    }

    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String> {
        let _slot = self.gate.try_acquire().map_err(|_| Self::busy())?;
        self.inner.reload(section, payload).await
    }
}

/// What the daemon exposes to the control plane (SPEC §7).
#[async_trait]
pub trait ControlBackend: Send + Sync + 'static {
    async fn status(&self) -> Value;
    async fn metrics(&self) -> Value;
    async fn checkpoint(&self) -> Result<u64, String>;
    /// Close I/O admission, wait for callbacks, flush and checkpoint. A
    /// successful sequence acknowledges drain; the control socket stays live.
    async fn drain(&self) -> Result<u64, String> {
        Err("drain is unsupported by this backend".to_owned())
    }
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
        "drain" => match backend.drain().await {
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

/// Serve one connection until EOF, the idle timeout, or a write timeout.
/// Errors terminate the session (bounded input; a protocol violation never
/// grows memory unboundedly).
pub async fn serve_connection<S>(
    stream: S,
    backend: Arc<dyn ControlBackend>,
    limits: ControlLimits,
) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        let line = match tokio::time::timeout(limits.idle_timeout, read_line(&mut rd)).await {
            Ok(Ok(line)) => line,
            Ok(Err(ProtocolError::Closed)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => return Err(ProtocolError::IdleTimeout),
        };
        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(request) => handle(&backend, request).await,
            Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
        };
        let mut bytes = serde_json::to_vec(&response)?;
        bytes.push(b'\n');
        let write = async {
            wr.write_all(&bytes).await?;
            wr.flush().await
        };
        match tokio::time::timeout(limits.write_timeout, write).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(ProtocolError::WriteTimeout),
        }
    }
}
