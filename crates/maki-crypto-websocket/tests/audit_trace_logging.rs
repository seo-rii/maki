//! Audit: docs/operations.md and docs/observability.md promise that payload
//! bytes are never logged at any `MAKI_LOG` threshold. The daemon's sink
//! (`maki_core::logging::install_default_logging`) is a tracing-subscriber
//! `fmt` subscriber whose `try_init` also installs the `log` -> `tracing`
//! bridge, so the `log::trace!` calls inside (vendored) tungstenite reach
//! stderr when an operator raises the threshold for diagnosis. tungstenite
//! traces every frame's payload (hex) and every received text message, which
//! here are the request plaintext and the decrypted plaintext.
//!
//! The parent runs this binary again as a child with `MAKI_LOG=trace`, so the
//! process-global subscriber does not leak into other tests.

use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const CHILD: &str = "MAKI_AUDIT_TRACE_LOGGING_CHILD";
const UNIT: usize = 48;
// Distinctive plaintext; its base64 is "U0VDUkVULVBMQUlOVEVYVC1VTklULU1BUktFUi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAw".
const PLAINTEXT: &[u8; UNIT] = b"SECRET-PLAINTEXT-UNIT-MARKER-0000000000000000000";

fn provider(url: String) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: CryptoCapabilities {
            provider_id: "audit-trace".into(),
            crypto_compatibility_id: "audit-trace-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: false,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: UNIT as u64,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_frame_bytes: 4096,
        tls: None,
    })
}

#[tokio::test]
async fn child_performs_ws_crypto_with_maki_log_trace() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    assert!(maki_core::logging::install_default_logging());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            let Ok(text) = message.into_text() else {
                continue;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            // Identity "cipher" so the response for decrypt is the plaintext.
            let items: Vec<_> = request["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| json!({"unit": item["unit"], "data": item["data"]}))
                .collect();
            let response = json!({"id": request["id"], "items": items});
            if ws.send(response.to_string().into()).await.is_err() {
                break;
            }
        }
    });
    let provider = provider(url);
    let context = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(7),
        format_version: 1,
        crypto_compatibility_id: "audit-trace-v1".into(),
    };
    provider
        .encrypt_batch(
            &context,
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_slice(PLAINTEXT),
            }],
        )
        .await
        .unwrap();
    provider
        .decrypt_batch(
            &context,
            &[CiphertextUnit {
                unit_index: 0,
                data: PLAINTEXT.to_vec(),
            }],
        )
        .await
        .unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn maki_log_trace_must_not_write_plaintext_payloads() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_performs_ws_crypto_with_maki_log_trace",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("MAKI_LOG", "trace")
        .output()
        .unwrap();
    assert!(output.status.success(), "child failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let encoded = base64::engine::general_purpose::STANDARD.encode(PLAINTEXT);
    let as_text = stderr.matches(encoded.as_str()).count();
    let as_hex = stderr.matches(hex(encoded.as_bytes()).as_str()).count();
    let tungstenite_lines = stderr.lines().filter(|l| l.contains("tungstenite")).count();
    eprintln!(
        "child stderr: {} bytes, {tungstenite_lines} tungstenite lines; plaintext base64 found \
         {as_text}x as text and {as_hex}x hex-encoded",
        stderr.len()
    );
    for line in stderr
        .lines()
        .filter(|l| l.contains(encoded.as_str()) || l.contains(hex(encoded.as_bytes()).as_str()))
    {
        let shown: String = line.chars().take(160).collect();
        eprintln!("  leaked: {shown}...");
    }
    assert_eq!(
        as_text + as_hex,
        0,
        "MAKI_LOG=trace wrote the unit plaintext to the daemon log"
    );
}
