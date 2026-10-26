//! BUG-140: callers queued behind a handshake share one budget per attempt.
//! These tests use loopback peers and virtual time; no storage is opened.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use tokio::net::TcpListener;

#[path = "common/paused_time.rs"]
mod paused_time;

struct TokioClock(tokio::time::Instant);

impl maki_crypto::clock::Clock for TokioClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, duration: Duration) -> maki_crypto::clock::SleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

const TIMEOUT: Duration = Duration::from_millis(100);

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(12),
        format_version: 1,
        crypto_compatibility_id: "queue-timeout-v1".into(),
    }
}

fn provider(
    address: std::net::SocketAddr,
    retry_safe: bool,
    timeout: Duration,
) -> Arc<WsCryptoProvider> {
    Arc::new(WsCryptoProvider::new(WsProviderSpec {
        url: format!("ws://{address}"),
        capabilities: CryptoCapabilities {
            provider_id: "queue-timeout-test".into(),
            crypto_compatibility_id: "queue-timeout-v1".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 512,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout,
        max_frame_bytes: 4096,
        tls: None,
    }))
}

async fn settle() {
    for _ in 0..500 {
        tokio::task::yield_now().await;
    }
}

async fn silent_peer_elapsed(
    requests: usize,
    outer_deadline: Option<Duration>,
    retry_safe: bool,
) -> Vec<Duration> {
    paused_time::bounded(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw = provider(listener.local_addr().unwrap(), retry_safe, TIMEOUT);
        let provider: Arc<dyn CryptoProvider> = match outer_deadline {
            None => raw,
            Some(deadline) => Arc::new(maki_crypto::endpoint::EndpointSet::new(
                vec![("silent".into(), raw)],
                maki_crypto::endpoint::DispatchConfig {
                    retry: maki_crypto::retry::RetryPolicy {
                        initial_delay: Duration::ZERO,
                        max_delay: Duration::ZERO,
                    },
                    budget: maki_crypto::retry::RetryBudgetConfig {
                        retry_ratio: 1.0,
                        burst: 8,
                        min_probe_per_sec: 1.0,
                    },
                    breaker: maki_crypto::breaker::BreakerConfig::default(),
                    global_max_inflight_batches: 8,
                    global_max_inflight_bytes: 4096,
                    per_endpoint_max_inflight: 8,
                    per_endpoint_max_bytes: 4096,
                    max_attempts: None,
                    max_operation_time: Some(deadline),
                    retry_safe: false,
                    validation_interval: Duration::from_secs(1),
                },
                Arc::new(TokioClock(tokio::time::Instant::now())),
            )),
        };
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = accepted.clone();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut sockets = Vec::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                sockets.push(socket);
                accepted_server.fetch_add(1, Ordering::SeqCst);
                accepted_tx.send(()).unwrap();
            }
        });
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut calls = Vec::new();
        for unit in 0..requests {
            let provider = provider.clone();
            let started_tx = started_tx.clone();
            calls.push(tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                started_tx.send(()).unwrap();
                let result = provider
                    .encrypt_batch(
                        &context(),
                        &[PlaintextUnit {
                            unit_index: unit as u64,
                            data: SecretBuffer::from_slice(&[3; 64]),
                        }],
                    )
                    .await;
                assert!(result.unwrap_err().is_retryable());
                start.elapsed()
            }));
        }
        drop(started_tx);
        for _ in 0..requests {
            started_rx.recv().await.expect("caller did not start");
        }
        accepted_rx
            .recv()
            .await
            .expect("silent peer did not accept TCP");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        for _ in 0..=requests * 2 {
            tokio::time::advance(outer_deadline.unwrap_or(TIMEOUT) + Duration::from_millis(1))
                .await;
            settle().await;
            if calls.iter().all(tokio::task::JoinHandle::is_finished) {
                break;
            }
        }
        assert!(calls.iter().all(tokio::task::JoinHandle::is_finished));
        let mut elapsed = Vec::new();
        for call in calls {
            elapsed.push(call.await.unwrap());
        }
        server.abort();
        elapsed
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn control_one_request_observes_transport_timeout() {
    let elapsed = silent_peer_elapsed(1, None, false).await;
    assert!(elapsed[0] <= TIMEOUT + Duration::from_millis(1));
}

#[tokio::test(start_paused = true)]
async fn queued_requests_must_not_renew_timeout_after_each_predecessor() {
    let elapsed = silent_peer_elapsed(4, None, false).await;
    assert!(elapsed.iter().all(|d| *d <= TIMEOUT + Duration::from_millis(1)),
        "each caller should time out from its own invocation, not after all earlier connection attempts: {elapsed:?}");
}

#[tokio::test(start_paused = true)]
async fn retry_safe_requests_remain_bounded_by_two_attempts() {
    let elapsed = silent_peer_elapsed(4, None, true).await;
    assert!(
        elapsed
            .iter()
            .all(|d| *d >= TIMEOUT * 2 && *d <= (TIMEOUT + Duration::from_millis(1)) * 2),
        "a reconnect must not multiply its budget by the number of waiters: {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn control_outer_bounded_error_caps_all_connection_waiters() {
    let elapsed = silent_peer_elapsed(4, Some(Duration::from_millis(50)), false).await;
    assert!(
        elapsed.iter().all(|d| *d <= Duration::from_millis(51)),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn control_normal_peer_serves_all_concurrent_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = provider(
        listener.local_addr().unwrap(),
        false,
        Duration::from_secs(5),
    );
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        for _ in 0..4 {
            let request = socket.next().await.unwrap().unwrap();
            let value: serde_json::Value =
                serde_json::from_str(request.to_text().unwrap()).unwrap();
            let data = base64::engine::general_purpose::STANDARD.encode([9; 64]);
            let response = serde_json::json!({"id":value["id"],"items":[{"unit":value["items"][0]["unit"],"data":data}]});
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    response.to_string().into(),
                ))
                .await
                .unwrap();
        }
    });
    let calls = (0..4).map(|unit| {
        let provider = provider.clone();
        async move {
            let result = provider
                .encrypt_batch(
                    &context(),
                    &[PlaintextUnit {
                        unit_index: unit,
                        data: SecretBuffer::from_slice(&[3; 64]),
                    }],
                )
                .await
                .unwrap();
            assert_eq!(result[0].data, [9; 64]);
        }
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        futures_util::future::join_all(calls),
    )
    .await
    .unwrap();
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn handshake_and_reply_wait_use_the_same_attempt_budget() {
    paused_time::bounded(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = provider(listener.local_addr().unwrap(), false, TIMEOUT);
        let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
        let (received_tx, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_millis(70)).await;
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            socket.next().await.unwrap().unwrap();
            received_tx.send(()).unwrap();
            // Retain the connection; the client must use only its remaining 30ms.
            futures_util::future::pending::<()>().await;
        });
        let call = tokio::spawn(async move {
            provider
                .encrypt_batch(
                    &context(),
                    &[PlaintextUnit {
                        unit_index: 1,
                        data: SecretBuffer::from_slice(&[3; 64]),
                    }],
                )
                .await
        });
        accepted.await.unwrap();
        tokio::time::advance(Duration::from_millis(70)).await;
        received.await.unwrap();
        tokio::time::advance(Duration::from_millis(31)).await;
        settle().await;
        assert!(
            call.is_finished(),
            "response wait restarted the attempt budget after handshake"
        );
        assert!(call.await.unwrap().unwrap_err().is_retryable());
        server.abort();
    })
    .await;
}
