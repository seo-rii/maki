//! Regression for a BUG-015 follow-up found in code review: the serve loop
//! must observe the shutdown signal even when every session slot is busy.
//! The loop used to `acquire_owned()` a session slot *before* selecting on
//! the shutdown receiver, so with all `max_sessions` slots held by live
//! sessions it parked on the slot wait and never drained — hanging a clean
//! detach (`NbdAdapter::stop_control` blocks on the serve task).

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use maki_control::protocol::{read_response, send_command, Request};
use maki_control::server::{ControlBackend, ControlLimits};
use maki_control::uds::{bind_control_socket, serve_with_shutdown};

struct Fake;

#[async_trait]
impl ControlBackend for Fake {
    async fn status(&self) -> Value {
        json!({ "state": "ready" })
    }
    async fn metrics(&self) -> Value {
        json!({})
    }
    async fn checkpoint(&self) -> Result<u64, String> {
        Ok(1)
    }
    async fn reload(&self, _section: &str, _payload: &Value) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_when_all_session_slots_are_busy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let listener = bind_control_socket(&path, None).unwrap();

    let (shutdown, rx) = tokio::sync::watch::channel(false);
    // One slot only, so a single live session fills the table.
    let limits = ControlLimits {
        max_sessions: 1,
        idle_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(10),
    };
    let server = tokio::spawn(serve_with_shutdown(listener, Arc::new(Fake), limits, rx));

    // Occupy the single session slot with a live connection: one request,
    // read its reply, then keep the connection open so the slot stays held
    // and the accept loop parks waiting for a second slot.
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    send_command(&mut wr, &Request::new("status"))
        .await
        .unwrap();
    let response = read_response(&mut rd).await.unwrap();
    assert_eq!(response["ok"], json!(true));

    // Signal shutdown. The drain must run promptly despite the busy slot;
    // before the fix this hung forever (the loop was parked on the slot
    // acquisition, blind to the signal).
    shutdown.send(true).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), server).await;
    assert!(
        outcome.is_ok(),
        "serve_with_shutdown hung while a session slot was busy"
    );
    outcome
        .unwrap()
        .expect("serve task panicked")
        .expect("serve returned an error");

    // The live session was terminated by the drain: its socket is closed.
    drop(wr);
    let mut buf = [0u8; 1];
    use tokio::io::AsyncReadExt;
    let n = tokio::time::timeout(Duration::from_secs(2), rd.read(&mut buf))
        .await
        .expect("read after shutdown should not block")
        .unwrap_or(0);
    assert_eq!(n, 0, "the live session was not terminated by the drain");
}
