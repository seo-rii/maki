//! Raising `MAKI_LOG` for diagnosis must not put payloads or credentials in
//! the daemon log (docs/observability.md: payload bytes are never logged).
//!
//! The daemon's sink (`maki_core::logging::install_default_logging`) also
//! bridges the `log` crate into `tracing`, and tungstenite logs through
//! `log`: at trace level it prints every frame's payload (hex), every received
//! text message and the client upgrade request (URL path and query). Encrypt
//! requests and decrypt responses carry the unit plaintext, base64-encoded.
//!
//! The parent runs this binary again as a child for each `MAKI_LOG` value, so
//! the process-global subscriber never leaks into other tests.

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

const CHILD: &str = "MAKI_REVIEW_TRACE_LOGGING_CHILD";
const UNIT: usize = 48;
const PLAINTEXT: &[u8; UNIT] = b"SECRET-PLAINTEXT-UNIT-MARKER-0000000000000000000";
const QUERY_SECRET: &str = "query-credential-marker";
const CHILD_TRACE_MARKER: &str = "review child trace marker";

fn provider(url: String) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: CryptoCapabilities {
            provider_id: "review-trace".into(),
            crypto_compatibility_id: "review-trace-v1".into(),
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
async fn child_performs_websocket_crypto_under_maki_log() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    assert!(maki_core::logging::install_default_logging());
    tracing::trace!("{CHILD_TRACE_MARKER}");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "ws://{}/crypto?token={QUERY_SECRET}",
        listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            let Ok(text) = message.into_text() else {
                continue;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            // An identity "cipher": the decrypt response is the plaintext.
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
        crypto_compatibility_id: "review-trace-v1".into(),
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

fn child_stderr(filter: &str) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_performs_websocket_crypto_under_maki_log",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("MAKI_LOG", filter)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "child failed under MAKI_LOG={filter}: {:?}",
        output.status
    );
    stderr
}

#[test]
fn raised_maki_log_never_writes_websocket_payloads_or_upgrade_query() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(PLAINTEXT);
    let forbidden = [
        ("unit plaintext (base64)", encoded.clone()),
        ("unit plaintext (base64, hex)", hex(encoded.as_bytes())),
        ("unit plaintext (hex)", hex(PLAINTEXT)),
        ("upgrade query credential", QUERY_SECRET.to_string()),
        (
            "upgrade query credential (hex)",
            hex(QUERY_SECRET.as_bytes()),
        ),
    ];
    for filter in [
        "trace",
        "warn,tungstenite=trace,tokio_tungstenite=trace",
        // More specific than any crate-level cap directive.
        "warn,tungstenite::protocol=trace,tungstenite::handshake=trace",
    ] {
        let stderr = child_stderr(filter);
        for (what, needle) in &forbidden {
            let leaked: Vec<&str> = stderr
                .lines()
                .filter(|line| line.contains(needle.as_str()))
                .collect();
            assert!(
                leaked.is_empty(),
                "MAKI_LOG={filter} wrote the {what} to the log, e.g. {:?}",
                leaked
                    .first()
                    .map(|line| line.chars().take(160).collect::<String>())
            );
        }
        // The bridge is live: tungstenite's connection diagnostics still
        // reach the log, so the check above would have seen a payload.
        assert!(
            stderr.contains(" tungstenite::"),
            "MAKI_LOG={filter}: no tungstenite diagnostics reached the log:\n{stderr}"
        );
    }
    // The operator's threshold still applies to everything else.
    assert!(child_stderr("trace").contains(CHILD_TRACE_MARKER));
}
