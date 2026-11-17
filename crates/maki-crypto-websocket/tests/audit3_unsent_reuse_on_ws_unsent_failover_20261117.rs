//! Round-3 audit probe for PR #174 (NotSent failover) on the WebSocket
//! transport's cached connection. The flaky peer upgrades one connection,
//! answers the first request, stops listening (so a reconnect is refused, a
//! connect failure that is marked not sent) and then closes or drops the
//! connection racing the client's second request. Invariant: whenever a
//! request that is not retry-safe fails over to the good peer, the flaky
//! peer never received its frame.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const UNIT: usize = 512;
const XOR: u8 = 0x5a;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xA3_0174),
        format_version: 1,
        crypto_compatibility_id: "review-unsent-v1".into(),
    }
}

fn input(index: u64) -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

fn answer(text: &str) -> String {
    let request: Value = serde_json::from_str(text).unwrap();
    let items: Vec<_> = request["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let data: Vec<u8> = base64::engine::general_purpose::STANDARD
                .decode(item["data"].as_str().unwrap())
                .unwrap()
                .into_iter()
                .map(|byte| byte ^ XOR)
                .collect();
            json!({
                "unit": item["unit"],
                "data": base64::engine::general_purpose::STANDARD.encode(data),
            })
        })
        .collect();
    json!({"id": request["id"], "items": items}).to_string()
}

fn unit_of(text: &str) -> u64 {
    let request: Value = serde_json::from_str(text).unwrap();
    request["items"][0]["unit"].as_u64().unwrap()
}

struct Peer {
    url: String,
    seen: Arc<parking_lot::Mutex<Vec<u64>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `close_after`: after answering the first frame, wait this long for more
/// frames (recording them, never answering), then drop the socket.
async fn flaky(close_after: Duration, graceful: bool) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        drop(listener);
        let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
            return;
        };
        let Some(Ok(first)) = ws.next().await else {
            return;
        };
        let text = first.into_text().unwrap();
        log.lock().push(unit_of(&text));
        let _ = ws.send(answer(&text).into()).await;
        let deadline = tokio::time::Instant::now() + close_after;
        loop {
            match tokio::time::timeout_at(deadline, ws.next()).await {
                Ok(Some(Ok(message))) => {
                    if let Ok(text) = message.into_text() {
                        if !text.is_empty() {
                            log.lock().push(unit_of(&text));
                        }
                    }
                }
                _ => break,
            }
        }
        if graceful {
            let _ = ws.close(None).await;
        }
        drop(ws);
    });
    Peer { url, seen, task }
}

async fn good() -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    log.lock().push(unit_of(&text));
                    if ws.send(answer(&text).into()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Peer { url, seen, task }
}

fn provider(url: &str) -> Arc<dyn CryptoProvider> {
    Arc::new(WsCryptoProvider::new(WsProviderSpec {
        url: url.to_string(),
        capabilities: CryptoCapabilities {
            provider_id: "review-ws-unsent".into(),
            crypto_compatibility_id: context().crypto_compatibility_id,
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: false,
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
        max_frame_bytes: 2048,
        tls: None,
    }))
}

fn not_retry_safe(peers: Vec<(&str, Arc<dyn CryptoProvider>)>) -> EndpointSet {
    EndpointSet::new(
        peers
            .into_iter()
            .map(|(name, peer)| (name.into(), peer))
            .collect(),
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 100,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 100,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(1),
            max_operation_time: None,
            retry_safe: false,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closing_cached_connection_never_duplicates_a_request() {
    let mut outcomes = std::collections::BTreeMap::new();
    let mut duplicates = Vec::new();
    for round in 0..60u64 {
        let close_after = Duration::from_micros((round % 6) * 400);
        let pause = Duration::from_micros((round / 12) * 500);
        let graceful = round % 2 == 0;
        let flaky = flaky(close_after, graceful).await;
        let good = good().await;
        let flaky_provider = provider(&flaky.url);
        flaky_provider
            .encrypt_batch(&context(), &input(1))
            .await
            .expect("first request");
        tokio::time::sleep(pause).await;
        let set = not_retry_safe(vec![
            ("flaky", flaky_provider.clone()),
            ("good", provider(&good.url)),
        ]);
        let second = set.encrypt_batch(&context(), &input(2)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let at_flaky = flaky.seen.lock().contains(&2);
        let at_good = good.seen.lock().contains(&2);
        *outcomes
            .entry((at_flaky, at_good, second.is_ok()))
            .or_insert(0u32) += 1;
        if at_flaky && at_good {
            duplicates.push(round);
        }
    }
    eprintln!("outcomes (at_flaky, at_good, ok) -> count: {outcomes:?}");
    assert!(duplicates.is_empty(), "duplicated requests in rounds {duplicates:?}");
}
