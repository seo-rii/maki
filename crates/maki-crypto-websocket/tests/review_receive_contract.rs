//! BUG-064: receive framing violations retain their endpoint provenance.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
use tokio_tungstenite::tungstenite::protocol::frame::{
    coding::{Data, OpCode},
    Frame,
};
use tokio_tungstenite::tungstenite::Message;

const UNIT: usize = 512;
const NORMAL: usize = 0;
const LARGE_FRAME: usize = 1;
const LARGE_MESSAGE: usize = 2;
const INVALID_UTF8: usize = 3;
const DISCONNECT_ONCE: usize = 4;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(64),
        format_version: 1,
        crypto_compatibility_id: "review-receive-v1".into(),
    }
}

fn input(unit: u64) -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

struct Server {
    url: String,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(mode: usize, pair: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicUsize::new(mode));
        let calls = Arc::new(AtomicUsize::new(0));
        let state = mode.clone();
        let count = calls.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let state = state.clone();
                let count = count.clone();
                connections.spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                    let mut received = 0;
                    while let Some(Ok(message)) = ws.next().await {
                        let Ok(text) = message.into_text() else { continue };
                        assert!(text.len() < 2048, "request itself fits the frame cap");
                        let request: Value = serde_json::from_str(&text).unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        received += 1;
                        if pair && received < 2 { continue; }
                        let result = match state.load(Ordering::SeqCst) {
                            LARGE_FRAME => ws.send("A".repeat(4096).into()).await,
                            LARGE_MESSAGE => {
                                let first = Frame::message(vec![b'A'; 1300], OpCode::Data(Data::Text), false);
                                let last = Frame::message(vec![b'A'; 1300], OpCode::Data(Data::Continue), true);
                                if ws.send(Message::Frame(first)).await.is_err() { break; }
                                ws.send(Message::Frame(last)).await
                            }
                            INVALID_UTF8 => ws.send(Message::Frame(Frame::message(vec![0xff], OpCode::Data(Data::Text), true))).await,
                            DISCONNECT_ONCE => {
                                state.store(NORMAL, Ordering::SeqCst);
                                return; // Abrupt ordinary TCP loss, without a closing handshake.
                            }
                            NORMAL => {
                                let items: Vec<_> = request["items"].as_array().unwrap().iter().map(|item| {
                                    let data = base64::engine::general_purpose::STANDARD.decode(item["data"].as_str().unwrap()).unwrap();
                                    let data: Vec<_> = data.iter().map(|byte| byte ^ 0x5a).collect();
                                    json!({"unit": item["unit"], "data": base64::engine::general_purpose::STANDARD.encode(data)})
                                }).collect();
                                ws.send(json!({"id": request["id"], "items": items}).to_string().into()).await
                            }
                            _ => unreachable!(),
                        };
                        if result.is_err() { break; }
                    }
                });
            }
        });
        Self {
            url,
            mode,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_is_contract_without_transparent_resend() {
    for safe in [false, true] {
        let server = Server::start(LARGE_FRAME, false).await;
        let error = server
            .provider(safe)
            .encrypt_batch(&context(), &input(0))
            .await
            .unwrap_err();
        assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragmented_message_over_the_limit_is_contract() {
    let server = Server::start(LARGE_MESSAGE, false).await;
    let error = server
        .provider(true)
        .encrypt_batch(&context(), &input(0))
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_text_encoding_is_contract() {
    let server = Server::start(INVALID_UTF8, false).await;
    let error = server
        .provider(true)
        .encrypt_batch(&context(), &input(0))
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_receive_peer_after_conformance_fails_over_and_opens() {
    let bad = Server::start(NORMAL, false).await;
    let good = Server::start(NORMAL, false).await;
    let bad_provider = bad.provider(true);
    let good_provider = good.provider(true);
    for peer in [&bad_provider, &good_provider] {
        maki_crypto::selftest::provider_conformance(
            peer.as_ref(),
            &context(),
            UNIT,
            "review-receive-v1",
        )
        .await
        .unwrap();
    }
    bad.calls.store(0, Ordering::SeqCst);
    good.calls.store(0, Ordering::SeqCst);
    bad.mode.store(LARGE_FRAME, Ordering::SeqCst);
    let set = dispatcher(&[("bad", bad_provider), ("good", good_provider)], true);
    for _ in 0..10 {
        let output = set.encrypt_batch(&context(), &input(0)).await.unwrap();
        assert_eq!(output[0].data, vec![0x42 ^ 0x5a; UNIT]);
    }
    assert_eq!(bad.calls.load(Ordering::SeqCst), 3);
    assert_eq!(good.calls.load(Ordering::SeqCst), 10);
    assert_eq!(set.endpoint_status()[0].circuit, CircuitState::Open);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stall_returns_after_all_receive_contracts_fail() {
    let left = Server::start(LARGE_FRAME, false).await;
    let right = Server::start(LARGE_FRAME, false).await;
    let set = dispatcher(
        &[
            ("left", left.provider(true)),
            ("right", right.provider(true)),
        ],
        true,
    );
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        set.encrypt_batch(&context(), &input(0)),
    )
    .await
    .expect("receive contract stalled")
    .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(left.calls.load(Ordering::SeqCst), 1);
    assert_eq!(right.calls.load(Ordering::SeqCst), 1);
    assert_eq!(set.global_inflight(), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_failure_reaches_every_pending_caller_on_the_generation() {
    let server = Server::start(LARGE_FRAME, true).await;
    let provider = server.provider(false);
    let context = context();
    let left = input(1);
    let right = input(2);
    let (left, right) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            provider.encrypt_batch(&context, &left),
            provider.encrypt_batch(&context, &right)
        )
    })
    .await
    .expect("generation cleanup missed a pending caller");
    for result in [left, right] {
        assert!(
            matches!(result, Err(CryptoError::Contract(_))),
            "{result:?}"
        );
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_failure_does_not_poison_a_healthy_successor() {
    let server = Server::start(LARGE_FRAME, false).await;
    let provider = server.provider(true);
    let error = provider
        .encrypt_batch(&context(), &input(0))
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    server.mode.store(NORMAL, Ordering::SeqCst);
    for _ in 0..2 {
        provider.encrypt_batch(&context(), &input(0)).await.unwrap();
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_abrupt_disconnect_still_reconnects_when_safe() {
    let server = Server::start(DISCONNECT_ONCE, false).await;
    let output = server
        .provider(true)
        .encrypt_batch(&context(), &input(0))
        .await
        .unwrap();
    assert_eq!(output[0].data, vec![0x42 ^ 0x5a; UNIT]);
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsafe_receive_failure_never_reaches_a_healthy_peer() {
    let bad = Server::start(LARGE_FRAME, false).await;
    let good = Server::start(NORMAL, false).await;
    let set = dispatcher(
        &[("bad", bad.provider(false)), ("good", good.provider(false))],
        false,
    );
    let error = set.encrypt_batch(&context(), &input(0)).await.unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(bad.calls.load(Ordering::SeqCst), 1);
    assert_eq!(good.calls.load(Ordering::SeqCst), 0);
}
