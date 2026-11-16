//! Audit: a WebSocket *upgrade* refusal carries no crypto request (the
//! upgrade is the same static GET for every connection), yet a generic 4xx
//! such as 400 or 426 is reported as `NonRetryableRequest`. The dispatcher
//! treats that class as "the request's fault": it neither charges the
//! endpoint's breaker nor fails over. One broken endpoint (a proxy that
//! cannot upgrade) then fails every request routed to it, although a healthy
//! peer is configured.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer, SystemClock,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const UNIT: usize = 512;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(4242),
        format_version: 1,
        crypto_compatibility_id: "audit-upgrade-v1".into(),
    }
}

fn input() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

async fn refusing(status: u16) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let mut used = 0;
            loop {
                let received = socket.read(&mut request[used..]).await.unwrap();
                if received == 0 {
                    return;
                }
                used += received;
                if request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let _ = socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await;
        }
    });
    (url, calls)
}

async fn healthy() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    let items: Vec<_> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = base64::engine::general_purpose::STANDARD
                                .decode(item["data"].as_str().unwrap())
                                .unwrap();
                            let data: Vec<_> = data.iter().map(|b| b ^ 0x5a).collect();
                            json!({"unit": item["unit"],
                                   "data": base64::engine::general_purpose::STANDARD.encode(data)})
                        })
                        .collect();
                    let response = json!({"id": request["id"], "items": items});
                    if ws.send(response.to_string().into()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (url, calls)
}

fn provider(url: String) -> Arc<dyn CryptoProvider> {
    Arc::new(WsCryptoProvider::new(WsProviderSpec {
        url,
        capabilities: CryptoCapabilities {
            provider_id: "audit-ws".into(),
            crypto_compatibility_id: context().crypto_compatibility_id,
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
        max_frame_bytes: 2048,
        tls: None,
    }))
}

fn dispatcher(peers: Vec<(String, Arc<dyn CryptoProvider>)>) -> EndpointSet {
    EndpointSet::new(
        peers,
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
                failure_threshold: 3,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: None,
            max_operation_time: None,
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

#[tokio::test]
async fn a_peer_that_cannot_upgrade_must_not_fail_requests_a_healthy_peer_can_serve() {
    for status in [400u16, 426] {
        let (bad_url, bad_calls) = refusing(status).await;
        let (good_url, good_calls) = healthy().await;
        let set = dispatcher(vec![
            ("bad".into(), provider(bad_url)),
            ("good".into(), provider(good_url)),
        ]);
        let mut failures = Vec::new();
        for _ in 0..10 {
            if let Err(error) = set.encrypt_batch(&context(), &input()).await {
                failures.push(format!("{:?}: {error}", error.class()));
            }
        }
        eprintln!(
            "HTTP {status}: {} of 10 requests failed; bad upgrades={}, good requests={}; first={:?}",
            failures.len(),
            bad_calls.load(Ordering::SeqCst),
            good_calls.load(Ordering::SeqCst),
            failures.first()
        );
        assert!(
            failures.is_empty(),
            "HTTP {status} on upgrade: {} of 10 requests failed with a healthy peer available \
             ({:?}); the broken peer's breaker was never charged",
            failures.len(),
            failures.first()
        );
    }
}
