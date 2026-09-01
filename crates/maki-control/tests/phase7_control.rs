//! Phase 7 — control socket (SPEC §7, §49).
//!
//! PRIV-008: maki-admin can perform status/reload over the control socket.
//! PRIV-009: attach/mount/detach are NOT expressible over the control
//! socket — those verbs only exist in the privileged helper.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::protocol::{read_response, send_command, Request};
use maki_control::server::{serve_connection, ControlBackend};

#[derive(Default)]
struct FakeBackend {
    checkpoints: AtomicU64,
    reloads: parking_lot::Mutex<Vec<(String, Value)>>,
}

#[async_trait]
impl ControlBackend for FakeBackend {
    async fn status(&self) -> Value {
        json!({"state": "ready", "volume": "testvol"})
    }

    async fn metrics(&self) -> Value {
        json!({"maki_volume_state": 1, "maki_journal_durable_sequence": 42})
    }

    async fn checkpoint(&self) -> Result<u64, String> {
        Ok(self.checkpoints.fetch_add(1, Ordering::SeqCst) + 100)
    }

    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String> {
        if section == "endpoints" || section == "credentials" || section == "cache" {
            self.reloads
                .lock()
                .push((section.to_string(), payload.clone()));
            Ok(())
        } else {
            Err(format!("section {section:?} is not hot-reloadable"))
        }
    }
}

async fn roundtrip(backend: Arc<FakeBackend>, request: Request) -> Value {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move { serve_connection(server, backend).await });
    let (mut rd, mut wr) = tokio::io::split(client);
    send_command(&mut wr, &request).await.unwrap();
    let response = read_response(&mut rd).await.unwrap();
    drop(wr);
    drop(rd);
    let _ = server_task.await;
    response
}

#[tokio::test]
async fn status_and_metrics_work() {
    let backend = Arc::new(FakeBackend::default());
    let r = roundtrip(backend.clone(), Request::new("status")).await;
    assert_eq!(r["ok"], true);
    assert_eq!(r["data"]["state"], "ready");

    let r = roundtrip(backend, Request::new("metrics")).await;
    assert_eq!(r["ok"], true);
    assert_eq!(r["data"]["maki_journal_durable_sequence"], 42);
}

#[tokio::test]
async fn checkpoint_and_hot_reload_work() {
    let backend = Arc::new(FakeBackend::default());
    let r = roundtrip(backend.clone(), Request::new("checkpoint")).await;
    assert_eq!(r["ok"], true);
    assert_eq!(r["data"]["checkpoint_sequence"], 100);

    let mut req = Request::new("reload");
    req.section = Some("cache".to_string());
    req.payload = json!({"max_bytes": 1048576});
    let r = roundtrip(backend.clone(), req).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(backend.reloads.lock()[0].0, "cache");
}

/// PRIV-009: privileged verbs do not exist on the control plane.
#[tokio::test]
async fn privileged_verbs_are_rejected() {
    for verb in ["attach", "detach", "mount", "umount", "grow", "nbd-connect"] {
        let backend = Arc::new(FakeBackend::default());
        let r = roundtrip(backend, Request::new(verb)).await;
        assert_eq!(r["ok"], false, "{verb} must be rejected");
        let msg = r["error"].as_str().unwrap();
        assert!(
            msg.contains("privileged helper"),
            "{verb}: error must direct to the privileged helper, got {msg}"
        );
    }
}

/// Malformed requests get an error response, never a crash or hang.
#[tokio::test]
async fn malformed_requests_are_rejected_cleanly() {
    let backend = Arc::new(FakeBackend::default());
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { serve_connection(server, backend).await });
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut rd, mut wr) = tokio::io::split(client);
    wr.write_all(b"this is not json\n").await.unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        rd.read_exact(&mut byte).await.unwrap();
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    let v: Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(v["ok"], false);
    // Both halves must drop for the duplex to close and the server to see EOF.
    drop(wr);
    drop(rd);
    let _ = task.await;
}

/// Oversized requests are refused (bounded input — control plane cannot be
/// memory-bombed).
#[tokio::test]
async fn oversized_request_line_is_refused() {
    let backend = Arc::new(FakeBackend::default());
    let (client, server) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move { serve_connection(server, backend).await });
    use tokio::io::AsyncWriteExt;
    let (rd, mut wr) = tokio::io::split(client);
    let huge = vec![b'x'; 512 * 1024];
    // Server must drop the connection rather than buffer unboundedly.
    let _ = wr.write_all(&huge).await;
    let _ = wr.write_all(b"\n").await;
    drop(wr);
    drop(rd);
    let served = task.await.unwrap();
    assert!(served.is_err(), "oversized line must terminate the session");
}
