//! Phase 9 — WebSocket transport (SPEC §51): correlation IDs, out-of-order
//! responses, reconnection, stale responses, frame-size limits, plus the
//! shared provider conformance suite.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;

use maki_crypto::selftest::provider_conformance;
use maki_crypto::{CryptoContext, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};

const UNIT: usize = 256;
const XOR: u8 = 0x44;

fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA1),
        format_version: 1,
        crypto_compatibility_id: "ws-profile-v1".to_string(),
    }
}

fn caps() -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "remote-ws-test".to_string(),
        crypto_compatibility_id: "ws-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: maki_crypto::BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: maki_crypto::Capability::Absent,
        context_binding: maki_crypto::Capability::Absent,
        replay_protection: maki_crypto::Capability::Absent,
    }
}

fn pt(i: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![fill; UNIT]),
    }
}

/// Server behavior modes for one connection.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    Padded(usize),
    /// Buffer two requests, answer them in reverse order.
    OutOfOrderPairs,
    /// Send a bogus-id response before each real one.
    StaleFirst,
    /// Close the connection after the first response.
    DropAfterFirst,
    /// Respond with a giant frame.
    HugeResponse,
}

fn xor_response(request: &serde_json::Value) -> serde_json::Value {
    let id = request["id"].clone();
    let items: Vec<serde_json::Value> = request["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let data = b64d(item["data"].as_str().unwrap());
            let out: Vec<u8> = data.iter().map(|b| b ^ XOR).collect();
            json!({"unit": item["unit"], "data": b64(&out)})
        })
        .collect();
    json!({"id": id, "items": items})
}

async fn ws_server(mode: Mode) -> (String, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicU32::new(0));
    let conn_count = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            conn_count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                let mut answered = 0u32;
                let mut buffered: Vec<serde_json::Value> = Vec::new();
                while let Some(Ok(msg)) = source.next().await {
                    let Ok(text) = msg.into_text() else { continue };
                    let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    match mode {
                        Mode::Normal => {
                            let r = xor_response(&request);
                            let _ = sink.send(r.to_string().into()).await;
                        }
                        Mode::Padded(cipher_len) => {
                            let items: Vec<_> = request["items"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|item| {
                                    let mut data = b64d(item["data"].as_str().unwrap());
                                    data.iter_mut().for_each(|byte| *byte ^= XOR);
                                    if request["op"] == "encrypt" {
                                        assert_eq!(data.len(), 4096);
                                        data.resize(cipher_len, 0);
                                    } else {
                                        assert_eq!(data.len(), cipher_len);
                                        data.truncate(4096);
                                    }
                                    json!({"unit": item["unit"], "data": b64(&data)})
                                })
                                .collect();
                            let r = json!({"id":request["id"],"items":items});
                            let _ = sink.send(r.to_string().into()).await;
                        }
                        Mode::OutOfOrderPairs => {
                            buffered.push(request);
                            if buffered.len() == 2 {
                                for req in buffered.drain(..).rev() {
                                    let r = xor_response(&req);
                                    let _ = sink.send(r.to_string().into()).await;
                                }
                            }
                        }
                        Mode::StaleFirst => {
                            let stale = json!({"id": 999_999_999u64, "items": []});
                            let _ = sink.send(stale.to_string().into()).await;
                            let r = xor_response(&request);
                            let _ = sink.send(r.to_string().into()).await;
                        }
                        Mode::DropAfterFirst => {
                            let r = xor_response(&request);
                            let _ = sink.send(r.to_string().into()).await;
                            answered += 1;
                            if answered == 1 {
                                let _ = sink.close().await;
                                return;
                            }
                        }
                        Mode::HugeResponse => {
                            let huge = json!({
                                "id": request["id"],
                                "items": [{"data": "A".repeat(600 * 1024)}]
                            });
                            let _ = sink.send(huge.to_string().into()).await;
                        }
                    }
                }
            });
        }
    });
    (format!("ws://{addr}"), connections)
}

fn provider(url: &str) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: url.to_string(),
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_frame_bytes: 512 * 1024,
        tls: None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roundtrip_with_correlation_ids() {
    let (url, _) = ws_server(Mode::Normal).await;
    let p = provider(&url);
    let cts = p
        .encrypt_batch(&ctx(), &[pt(1, 0x10), pt(2, 0x20)])
        .await
        .unwrap();
    assert_eq!(cts[0].data, vec![0x10 ^ XOR; UNIT]);
    let pts = p.decrypt_batch(&ctx(), &cts).await.unwrap();
    assert_eq!(pts[1].data.expose(), &vec![0x20; UNIT][..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn out_of_order_responses_resolve_by_correlation_id() {
    let (url, _) = ws_server(Mode::OutOfOrderPairs).await;
    let p = Arc::new(provider(&url));
    // Two concurrent requests; the server answers them in reverse order.
    let p1 = p.clone();
    let t1 = tokio::spawn(async move { p1.encrypt_batch(&ctx(), &[pt(1, 0x01)]).await });
    let p2 = p.clone();
    let t2 = tokio::spawn(async move { p2.encrypt_batch(&ctx(), &[pt(2, 0x02)]).await });
    let r1 = t1.await.unwrap().unwrap();
    let r2 = t2.await.unwrap().unwrap();
    assert_eq!(r1[0].data, vec![0x01 ^ XOR; UNIT], "t1 got t1's answer");
    assert_eq!(r2[0].data, vec![0x02 ^ XOR; UNIT], "t2 got t2's answer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_responses_are_dropped() {
    let (url, _) = ws_server(Mode::StaleFirst).await;
    let p = provider(&url);
    let cts = p.encrypt_batch(&ctx(), &[pt(5, 0x55)]).await.unwrap();
    assert_eq!(cts[0].data, vec![0x55 ^ XOR; UNIT]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnects_after_server_drop() {
    let (url, connections) = ws_server(Mode::DropAfterFirst).await;
    let p = provider(&url);
    let first = p.encrypt_batch(&ctx(), &[pt(1, 0x0A)]).await.unwrap();
    assert_eq!(first[0].data, vec![0x0A ^ XOR; UNIT]);
    // Server closed the connection; the next call must transparently
    // reconnect.
    let second = p.encrypt_batch(&ctx(), &[pt(2, 0x0B)]).await.unwrap();
    assert_eq!(second[0].data, vec![0x0B ^ XOR; UNIT]);
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "a new connection must have been established"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_incoming_frame_is_an_error() {
    let (url, _) = ws_server(Mode::HugeResponse).await;
    let p = provider(&url); // max_frame_bytes = 512 KiB < huge response
    let err = p.encrypt_batch(&ctx(), &[pt(1, 0x01)]).await.unwrap_err();
    assert!(
        matches!(err, maki_crypto::CryptoError::Contract(_)),
        "oversized frame violates the endpoint contract: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_outgoing_request_is_rejected_before_send() {
    let (url, _) = ws_server(Mode::Normal).await;
    let p = WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: caps(),
        timeout: Duration::from_secs(2),
        max_frame_bytes: 128, // smaller than any encoded request
        tls: None,
    });
    let err = p.encrypt_batch(&ctx(), &[pt(1, 0x01)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::NonRetryableRequest, "{err:?}");
}

/// Every transport must pass the same provider conformance suite (SPEC §51).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_passes_provider_conformance() {
    let (url, _) = ws_server(Mode::Normal).await;
    let p = provider(&url);
    provider_conformance(&p, &ctx(), UNIT, "ws-profile-v1")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validated_full_batches_roundtrip_at_serialized_websocket_boundary() {
    use maki_format::config::{parse_config, ByteSize};
    for cipher_len in [4383, 4384, 4385] {
        let (url, _) = ws_server(Mode::Padded(cipher_len)).await;
        let mut cfg = parse_config(&format!(
            r#"
config_schema_version = 1
[volume]
name = "transport-boundary"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "ws-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = {cipher_len}
[crypto.batch]
max_items = 128
max_bytes = "512KiB"
[crypto.websocket]
[[crypto.websocket.endpoint]]
name = "test"
url = "{url}"
[backing]
root = "/unused"
"#
        ))
        .unwrap();
        // Include both two-byte JSON escapes and the six-byte control escape.
        cfg.crypto.crypto_compatibility_id = "profile-\"\\\n\u{1}-한글".into();
        let mut context = ctx();
        context.crypto_compatibility_id = cfg.crypto.crypto_compatibility_id.clone();
        context.format_version = u32::MAX;
        let request = json!({
            "format": context.format_version,
            "id": u64::MAX,
            "items": (0..128).map(|i| json!({
                "unit": u64::MAX-i,
                "data": b64(&vec![0xAB; cipher_len]),
            })).collect::<Vec<_>>(),
            "op": "decrypt",
            "profile": context.crypto_compatibility_id,
            "volume": context.volume_uuid,
        });
        let boundary = serde_json::to_vec(&request).unwrap().len();
        cfg.crypto.websocket.as_mut().unwrap().max_frame_bytes =
            Some(ByteSize(boundary as u64 - 1));
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_frame_bytes"));
        for limit in [boundary, boundary + 1] {
            cfg.crypto.websocket.as_mut().unwrap().max_frame_bytes = Some(ByteSize(limit as u64));
            cfg.validate().unwrap();
            let mut capabilities = caps();
            capabilities.crypto_compatibility_id = context.crypto_compatibility_id.clone();
            capabilities.supported_plaintext_sizes = vec![4096];
            capabilities.max_ciphertext_size = cipher_len as u32;
            capabilities.batch.max_items = 128;
            let p = WsCryptoProvider::new(WsProviderSpec {
                url: url.clone(),
                capabilities,
                timeout: Duration::from_secs(5),
                max_frame_bytes: limit,
                tls: None,
            });
            let plaintext: Vec<_> = (0..128)
                .map(|i| PlaintextUnit {
                    unit_index: u64::MAX - i,
                    data: SecretBuffer::from_slice(&vec![i as u8; 4096]),
                })
                .collect();
            let encrypted = p.encrypt_batch(&context, &plaintext).await.unwrap();
            assert!(encrypted.iter().all(|item| item.data.len() == cipher_len));
            let decrypted = p.decrypt_batch(&context, &encrypted).await.unwrap();
            for (expected, actual) in plaintext.iter().zip(&decrypted) {
                assert_eq!(expected.data.expose(), actual.data.expose());
            }
        }
    }
}
