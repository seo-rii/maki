//! BUG-075: every backend response respects the existing 64 KiB framing.

use std::sync::Arc;

use async_trait::async_trait;
use maki_control::protocol::{read_response, send_command, Request, MAX_LINE};
use maki_control::server::{serve_connection, ControlBackend, ControlLimits};
use serde_json::{json, Value};

struct Backend {
    payload: String,
}

#[async_trait]
impl ControlBackend for Backend {
    async fn status(&self) -> Value {
        json!({"payload": self.payload})
    }

    async fn metrics(&self) -> Value {
        json!({"small": true})
    }

    async fn checkpoint(&self) -> Result<u64, String> {
        Err(self.payload.clone())
    }

    async fn reload(&self, _: &str, _: &Value) -> Result<(), String> {
        Ok(())
    }
}

async fn response(payload: String, command: &str) -> Value {
    let (client, server) = tokio::io::duplex(2 * MAX_LINE);
    let task = tokio::spawn(serve_connection(
        server,
        Arc::new(Backend { payload }),
        ControlLimits::default(),
    ));
    let (mut reader, mut writer) = tokio::io::split(client);
    send_command(&mut writer, &Request::new(command))
        .await
        .unwrap();
    let response = read_response(&mut reader)
        .await
        .expect("backend must return a readable bounded response");
    // Refusing one oversized snapshot must leave the framing intact for the
    // next command on the same connection.
    send_command(&mut writer, &Request::new("metrics"))
        .await
        .unwrap();
    let next = read_response(&mut reader).await.unwrap();
    assert_eq!(next["ok"], true);
    assert_eq!(next["data"]["small"], true);
    drop(reader);
    drop(writer);
    task.await.unwrap().unwrap();
    response
}

#[tokio::test]
async fn oversized_snapshot_returns_explicit_error_without_truncating_data() {
    let response = response("x".repeat(MAX_LINE), "status").await;
    assert_eq!(response["ok"], false);
    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("response exceeds"));
    assert!(response.get("data").is_none());
}

#[tokio::test]
async fn oversized_mutation_error_also_remains_readable() {
    let response = response("\u{0001}".repeat(MAX_LINE / 6), "checkpoint").await;
    assert_eq!(response["ok"], false);
    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("response exceeds"));
}

#[tokio::test]
async fn exact_frame_boundary_keeps_the_complete_snapshot() {
    let overhead = serde_json::to_vec(&json!({"ok": true, "data": {"payload": ""}}))
        .unwrap()
        .len();
    let payload = "x".repeat(MAX_LINE - overhead);
    let response = response(payload.clone(), "status").await;
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["payload"], payload);
    assert_eq!(serde_json::to_vec(&response).unwrap().len(), MAX_LINE);
}

#[tokio::test]
async fn one_byte_above_frame_boundary_is_refused() {
    let overhead = serde_json::to_vec(&json!({"ok": true, "data": {"payload": ""}}))
        .unwrap()
        .len();
    let response = response("x".repeat(MAX_LINE - overhead + 1), "status").await;
    assert_eq!(response["ok"], false);
}
