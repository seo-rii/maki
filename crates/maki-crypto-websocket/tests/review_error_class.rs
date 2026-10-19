//! BUG-063: malformed remote error classes belong to the endpoint contract.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

const UNIT: usize = 512;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(63),
        format_version: 1,
        crypto_compatibility_id: "review-error-v1".into(),
    }
}

fn input() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

struct Server {
    url: String,
    error: Arc<Mutex<Option<Value>>>,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn refuse_upgrade(status: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0; 4096];
                let mut used = 0;
                loop {
                    assert!(
                        used < request.len(),
                        "upgrade request header exceeded fixture limit"
                    );
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
                socket.write_all(format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            calls,
            error: Arc::new(Mutex::new(None)),
            task,
        }
    }

    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let error = Arc::new(Mutex::new(None::<Value>));
        let calls = Arc::new(AtomicUsize::new(0));
        let state = error.clone();
        let count = calls.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let state = state.clone();
                let count = count.clone();
                connections.spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                    while let Some(Ok(message)) = ws.next().await {
                        let Ok(text) = message.into_text() else {
                            continue;
                        };
                        let request: Value = serde_json::from_str(&text).unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let error = state.lock().unwrap().clone();
                        let response = match error {
                            Some(error) => json!({"id": request["id"], "error": error}),
                            None => {
                                let items: Vec<_> = request["items"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|item| {
                                        let data = base64::engine::general_purpose::STANDARD
                                            .decode(item["data"].as_str().unwrap())
                                            .unwrap();
                                        let data: Vec<_> = data.iter().map(|byte| byte ^ 0x5a).collect();
                                        json!({"unit": item["unit"], "data": base64::engine::general_purpose::STANDARD.encode(data)})
                                    })
                                    .collect();
                                json!({"id": request["id"], "items": items})
                            }
                        };
                        if ws.send(response.to_string().into()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            url,
            error,
            calls,
            task,
        }
    }

    fn provider(&self, retry_safe: bool) -> Arc<WsCryptoProvider> {
        Arc::new(WsCryptoProvider::new(WsProviderSpec {
            url: self.url.clone(),
            capabilities: CryptoCapabilities {
                provider_id: "review-ws".into(),
                crypto_compatibility_id: context().crypto_compatibility_id,
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                retry_safe,
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
}

fn dispatcher(peers: &[(&str, Arc<WsCryptoProvider>)], retry_safe: bool) -> EndpointSet {
    EndpointSet::new(
        peers
            .iter()
            .map(|(name, peer)| ((*name).into(), peer.clone() as Arc<dyn CryptoProvider>))
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
                failure_threshold: 3,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: None,
            max_operation_time: None,
            retry_safe,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

#[tokio::test]
async fn unknown_class_after_conformance_fails_over_and_opens_bad_peer() {
    let bad = Server::start().await;
    let good = Server::start().await;
    let bad_provider = bad.provider(true);
    let good_provider = good.provider(true);
    for peer in [&bad_provider, &good_provider] {
        maki_crypto::selftest::provider_conformance(
            peer.as_ref(),
            &context(),
            UNIT,
            "review-error-v1",
        )
        .await
        .unwrap();
    }
    bad.calls.store(0, Ordering::SeqCst);
    good.calls.store(0, Ordering::SeqCst);
    *bad.error.lock().unwrap() = Some(json!({"class": "unknown-class"}));
    let set = dispatcher(&[("bad", bad_provider), ("good", good_provider)], true);
    for _ in 0..10 {
        let output = set.encrypt_batch(&context(), &input()).await.unwrap();
        assert_eq!(output[0].data, vec![0x42 ^ 0x5a; UNIT]);
    }
    assert_eq!(bad.calls.load(Ordering::SeqCst), 3);
    assert_eq!(good.calls.load(Ordering::SeqCst), 10);
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Open);
}

#[tokio::test]
async fn missing_and_malformed_error_classes_are_contract_violations() {
    let server = Server::start().await;
    let provider = server.provider(true);
    for error in [
        Value::Null,
        json!({}),
        json!({"class": null}),
        json!({"class": 7}),
        json!({"class": "unrecognized"}),
    ] {
        *server.error.lock().unwrap() = Some(error);
        let error = provider
            .encrypt_batch(&context(), &input())
            .await
            .unwrap_err();
        assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn unsafe_unknown_class_never_reaches_the_second_peer() {
    let bad = Server::start().await;
    let good = Server::start().await;
    *bad.error.lock().unwrap() = Some(json!({"class": "unknown-class"}));
    let set = dispatcher(
        &[("bad", bad.provider(false)), ("good", good.provider(false))],
        false,
    );
    let error = set.encrypt_batch(&context(), &input()).await.unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(bad.calls.load(Ordering::SeqCst), 1);
    assert_eq!(good.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn all_unknown_class_peers_return_a_terminal_contract_even_with_stall() {
    let left = Server::start().await;
    let right = Server::start().await;
    for server in [&left, &right] {
        *server.error.lock().unwrap() = Some(json!({"class": "unknown-class"}));
    }
    let set = dispatcher(
        &[
            ("left", left.provider(true)),
            ("right", right.provider(true)),
        ],
        true,
    );
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        set.encrypt_batch(&context(), &input()),
    )
    .await
    .expect("contract failure stalled")
    .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(left.calls.load(Ordering::SeqCst), 1);
    assert_eq!(right.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recognized_request_and_retry_classes_keep_their_meaning() {
    let server = Server::start().await;
    let provider = server.provider(true);
    for (class, expected) in [
        ("bad-request", maki_crypto::ErrorClass::NonRetryableRequest),
        ("retryable", maki_crypto::ErrorClass::Retryable),
        ("throttled", maki_crypto::ErrorClass::Throttled),
    ] {
        *server.error.lock().unwrap() = Some(json!({"class": class}));
        let error = provider
            .encrypt_batch(&context(), &input())
            .await
            .unwrap_err();
        assert_eq!(error.class(), expected);
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn f04_auth_upgrade_refusal_fails_over_without_repeating_bad_credentials() {
    for status in [401, 403, 407] {
        let bad = Server::refuse_upgrade(status).await;
        let good = Server::start().await;
        let set = dispatcher(
            &[("bad", bad.provider(true)), ("good", good.provider(true))],
            true,
        );
        let output = set.encrypt_batch(&context(), &input()).await.unwrap();
        assert_eq!(output[0].data, vec![0x42 ^ 0x5a; UNIT]);
        assert_eq!(
            bad.calls.load(Ordering::SeqCst),
            1,
            "HTTP {status} repeated rejected authentication"
        );
        assert_eq!(good.calls.load(Ordering::SeqCst), 1);
    }
}
