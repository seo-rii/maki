//! BUG-117: the reader dropped, without a word, any frame it could not parse
//! as a JSON response or match to a request: non-JSON text, JSON without a
//! numeric `id`, and Binary frames (a Binary frame that happened to be UTF-8
//! was even parsed as a response). The contract is one JSON response per
//! text frame with a correlation id; only unknown or stale ids are to be
//! discarded. A peer that broke it therefore looked like a slow one: every
//! request waited out its whole timeout and failed as Retryable, was resent
//! when retry-safe, and under `stall` retried forever. Such a frame is now a
//! receive-contract violation that fails the connection generation at once,
//! while ping and pong control frames are still ignored.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const UNIT: usize = 512;

#[derive(Clone, Copy, Debug)]
enum Reply {
    NotJson,
    NoId,
    StringId,
    Binary,
    PingThenAnswer,
}

/// A server that answers the first request of each connection as `reply`.
async fn server(reply: Reply) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    counted.fetch_add(1, Ordering::SeqCst);
                    let answer = || {
                        let items: Vec<_> = request["items"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|item| {
                                let data = base64::engine::general_purpose::STANDARD
                                    .decode(item["data"].as_str().unwrap())
                                    .unwrap();
                                let data: Vec<_> = data.iter().map(|byte| byte ^ 0x5a).collect();
                                json!({
                                    "unit": item["unit"],
                                    "data": base64::engine::general_purpose::STANDARD.encode(data)
                                })
                            })
                            .collect();
                        json!({"id": request["id"], "items": items}).to_string()
                    };
                    let sent = match reply {
                        Reply::NotJson => ws.send("<html>502 Bad Gateway</html>".into()).await,
                        Reply::NoId => ws.send(json!({"items": []}).to_string().into()).await,
                        Reply::StringId => {
                            let id = request["id"].to_string();
                            ws.send(json!({"id": id, "items": []}).to_string().into())
                                .await
                        }
                        Reply::Binary => {
                            ws.send(Message::Binary(answer().into_bytes().into())).await
                        }
                        Reply::PingThenAnswer => {
                            if ws
                                .send(Message::Ping(b"keepalive".to_vec().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            ws.send(answer().into()).await
                        }
                    };
                    if sent.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (url, requests)
}

fn provider(url: String) -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: CryptoCapabilities {
            provider_id: "review-ws-unmatched".into(),
            crypto_compatibility_id: "review-unmatched-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 2,
                max_bytes: 1024,
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

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(117),
        format_version: 1,
        crypto_compatibility_id: "review-unmatched-v1".into(),
    }
}

fn input() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

#[tokio::test]
async fn a_frame_that_breaks_the_response_contract_fails_at_once() {
    for reply in [Reply::NotJson, Reply::NoId, Reply::StringId, Reply::Binary] {
        let (url, requests) = server(reply).await;
        let provider = provider(url);
        let started = Instant::now();
        let result = provider.encrypt_batch(&context(), &input()).await;
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{reply:?}: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{reply:?}: waited {:?} for a peer that had already answered",
            started.elapsed()
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{reply:?}: resent");
    }
}

#[tokio::test]
async fn ping_frames_are_still_ignored() {
    let (url, _) = server(Reply::PingThenAnswer).await;
    let ciphertext = provider(url)
        .encrypt_batch(&context(), &input())
        .await
        .expect("a ping before the answer is not a contract violation");
    assert_eq!(ciphertext[0].data, vec![0x42 ^ 0x5a; UNIT]);
}
