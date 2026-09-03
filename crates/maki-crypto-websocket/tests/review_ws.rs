//! Review M-012 / M-010 for the WebSocket transport: every response item
//! must echo its request unit in request order, and a provider that is not
//! retry-safe is never sent the same request twice.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};

const UNIT: usize = 256;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Correct: echo unit, keep order.
    Echo,
    /// Swap the first two items (units and data).
    Reorder,
    /// Omit the unit field.
    NoUnit,
    /// Echo the wrong unit.
    WrongUnit,
    /// Close the connection without answering.
    DropRequest,
}

fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

async fn server(mode: Mode) -> (String, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicU32::new(0));
    let count = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                while let Some(Ok(msg)) = source.next().await {
                    let Ok(text) = msg.into_text() else { continue };
                    let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    if mode == Mode::DropRequest {
                        let _ = sink.close().await;
                        return;
                    }
                    let mut items: Vec<serde_json::Value> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = base64::engine::general_purpose::STANDARD
                                .decode(item["data"].as_str().unwrap())
                                .unwrap();
                            let out: Vec<u8> = data.iter().map(|b| b ^ 0x5A).collect();
                            let unit = item["unit"].as_u64().unwrap();
                            match mode {
                                Mode::NoUnit => json!({"data": b64(&out)}),
                                Mode::WrongUnit => json!({"unit": unit + 1, "data": b64(&out)}),
                                _ => json!({"unit": unit, "data": b64(&out)}),
                            }
                        })
                        .collect();
                    if mode == Mode::Reorder && items.len() >= 2 {
                        items.swap(0, 1);
                    }
                    let response = json!({"id": request["id"], "items": items});
                    let _ = sink.send(response.to_string().into()).await;
                }
            });
        }
    });
    (format!("ws://{addr}"), connections)
}

fn caps(retry_safe: bool) -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-websocket".into(),
        crypto_compatibility_id: "vendor-profile-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn provider(url: &str, retry_safe: bool) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: url.to_string(),
        capabilities: caps(retry_safe),
        timeout: Duration::from_secs(5),
        max_frame_bytes: 1 << 20,
    })
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(7),
        format_version: 1,
        crypto_compatibility_id: "vendor-profile-v1".into(),
    }
}

fn pt(i: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![i as u8; UNIT]),
    }
}

async fn encrypt_two(mode: Mode) -> Result<Vec<maki_crypto::CiphertextUnit>, CryptoError> {
    let (url, _) = server(mode).await;
    provider(&url, true)
        .encrypt_batch(&ctx(), &[pt(10), pt(11)])
        .await
}

#[tokio::test]
async fn ws_accepts_correct_unit_echo() {
    let cts = encrypt_two(Mode::Echo).await.unwrap();
    assert_eq!(cts[0].unit_index, 10);
    assert_eq!(cts[1].unit_index, 11);
    assert_eq!(cts[0].data, vec![10u8 ^ 0x5A; UNIT]);
}

#[tokio::test]
async fn ws_rejects_reordered_batch_items() {
    let err = encrypt_two(Mode::Reorder).await.unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err}");
    assert!(err.to_string().contains("echoes unit"), "{err}");
}

#[tokio::test]
async fn ws_rejects_missing_unit_echo() {
    let err = encrypt_two(Mode::NoUnit).await.unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err}");
}

#[tokio::test]
async fn ws_rejects_wrong_unit_echo() {
    let err = encrypt_two(Mode::WrongUnit).await.unwrap_err();
    assert!(matches!(err, CryptoError::Contract(_)), "{err}");
}

#[tokio::test]
async fn non_retry_safe_websocket_never_resends_after_a_transport_failure() {
    let (url, connections) = server(Mode::DropRequest).await;
    let unsafe_provider = provider(&url, false);
    let err = unsafe_provider
        .encrypt_batch(&ctx(), &[pt(1)])
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "one connection: the request was not re-sent"
    );

    let (url, connections) = server(Mode::DropRequest).await;
    let safe_provider = provider(&url, true);
    let err = safe_provider
        .encrypt_batch(&ctx(), &[pt(1)])
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "retry-safe: one transparent reconnect + resend"
    );
}
