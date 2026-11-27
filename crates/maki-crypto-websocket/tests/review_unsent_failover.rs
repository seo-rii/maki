//! A WebSocket request is written only after the TCP connection, TLS and the
//! HTTP upgrade have succeeded. A failure in any of those steps proves that
//! no byte of the crypto request left Maki, so the dispatcher may send that
//! request to a peer even when the provider is not retry-safe (refused
//! upgrades: `review_error_class.rs`). Once a request frame was handed to
//! the connection it may have been delivered, and such a request is never
//! sent again, including after the transport's own reconnect attempt failed
//! before sending.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const UNIT: usize = 512;
const XOR: u8 = 0x5a;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0057),
        format_version: 1,
        crypto_compatibility_id: "review-unsent-v1".into(),
    }
}

fn input() -> [PlaintextUnit; 1] {
    [PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

/// What a peer does with one accepted TCP connection.
#[derive(Clone, Copy)]
enum Connection {
    /// Upgrade and answer every request frame.
    Serve,
    /// Upgrade, read one request frame, then drop the connection unanswered.
    DropAfterFrame,
    /// Refuse the upgrade with this HTTP status.
    Refuse(u16),
}

struct Peer {
    url: String,
    /// Request frames received.
    frames: Arc<AtomicUsize>,
    /// Upgrades refused.
    refusals: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    /// `plan(n)` decides the fate of the n-th accepted connection (from 0).
    async fn start(plan: fn(usize) -> Connection) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let frames = Arc::new(AtomicUsize::new(0));
        let refusals = Arc::new(AtomicUsize::new(0));
        let (frame_count, refusal_count) = (frames.clone(), refusals.clone());
        let task = tokio::spawn(async move {
            let mut accepted = 0;
            while let Ok((socket, _)) = listener.accept().await {
                let behaviour = plan(accepted);
                accepted += 1;
                let frames = frame_count.clone();
                let refusals = refusal_count.clone();
                tokio::spawn(async move {
                    match behaviour {
                        Connection::Refuse(status) => refuse(socket, status, &refusals).await,
                        Connection::Serve => serve(socket, &frames, false).await,
                        Connection::DropAfterFrame => serve(socket, &frames, true).await,
                    }
                });
            }
        });
        Self {
            url,
            frames,
            refusals,
            task,
        }
    }

    fn provider(&self, retry_safe: bool) -> Arc<dyn CryptoProvider> {
        provider(&self.url, retry_safe)
    }
}

async fn refuse(mut socket: tokio::net::TcpStream, status: u16, refusals: &AtomicUsize) {
    let mut request = [0; 4096];
    let mut used = 0;
    loop {
        let Ok(received) = socket.read(&mut request[used..]).await else {
            return;
        };
        if received == 0 {
            return;
        }
        used += received;
        if request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            break;
        }
    }
    refusals.fetch_add(1, Ordering::SeqCst);
    let _ = socket
        .write_all(
            format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await;
}

async fn serve(socket: tokio::net::TcpStream, frames: &AtomicUsize, drop_after_frame: bool) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
        return;
    };
    while let Some(Ok(message)) = ws.next().await {
        let Ok(text) = message.into_text() else {
            continue;
        };
        frames.fetch_add(1, Ordering::SeqCst);
        if drop_after_frame {
            return;
        }
        let request: Value = serde_json::from_str(&text).unwrap();
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
        let response = json!({"id": request["id"], "items": items});
        if ws.send(response.to_string().into()).await.is_err() {
            return;
        }
    }
}

fn provider(url: &str, retry_safe: bool) -> Arc<dyn CryptoProvider> {
    Arc::new(WsCryptoProvider::new(WsProviderSpec {
        url: url.to_string(),
        capabilities: CryptoCapabilities {
            provider_id: "review-ws-unsent".into(),
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

/// A dispatcher for a provider that is not retry-safe, under `stall`.
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
                failure_threshold: 3,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: None,
            max_operation_time: None,
            retry_safe: false,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

/// An endpoint that refuses every connection for as long as it lives: its
/// socket is bound and never listens. The bound socket also keeps the port;
/// a listener dropped once its address was taken frees it, and the kernel
/// may give it to the next `127.0.0.1:0` bind of any test.
struct ClosedPort {
    url: String,
    _socket: tokio::net::TcpSocket,
}

impl ClosedPort {
    fn new() -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        Self {
            url: format!("ws://{}", socket.local_addr().unwrap()),
            _socket: socket,
        }
    }
}

/// The tests of this file run side by side in one process, and each binds
/// `127.0.0.1:0` for its peers. The refused endpoint's port must stay out of
/// their reach for as long as a test uses it: one that another test's peer
/// is given is no longer refused, and its request is served there.
#[tokio::test]
async fn the_refused_endpoint_keeps_its_port_while_a_test_uses_it() {
    let down = ClosedPort::new();
    let address: std::net::SocketAddr = down.url.strip_prefix("ws://").unwrap().parse().unwrap();
    // The kernel gives a listener only a port that it could bind like this.
    let taken = TcpListener::bind(address).await;
    assert!(
        matches!(&taken, Err(error) if error.kind() == std::io::ErrorKind::AddrInUse),
        "another listener could take the refused endpoint's port: {taken:?}"
    );
    let connected = tokio::net::TcpStream::connect(address).await;
    assert!(
        matches!(&connected, Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused),
        "the refused endpoint did not refuse the connection: {connected:?}"
    );
}

#[tokio::test]
async fn a_refused_connection_fails_a_non_retry_safe_request_over_to_a_peer() {
    let down = ClosedPort::new();
    let good = Peer::start(|_| Connection::Serve).await;
    let set = not_retry_safe(vec![
        ("down", provider(&down.url, false)),
        ("good", good.provider(false)),
    ]);
    let output = set
        .encrypt_batch(&context(), &input())
        .await
        .unwrap_or_else(|error| {
            panic!("a refused TCP connection failed a request that was never sent: {error:?}")
        });
    assert_eq!(output[0].data, vec![0x42 ^ XOR; UNIT]);
    assert_eq!(good.frames.load(Ordering::SeqCst), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
}

/// Negative control: the frame reached the peer before the connection died,
/// so the request is never sent to another endpoint.
#[tokio::test]
async fn a_request_lost_after_its_frame_was_written_is_not_failed_over() {
    let lost = Peer::start(|_| Connection::DropAfterFrame).await;
    let good = Peer::start(|_| Connection::Serve).await;
    let set = not_retry_safe(vec![
        ("lost", lost.provider(false)),
        ("good", good.provider(false)),
    ]);
    let error = set
        .encrypt_batch(&context(), &input())
        .await
        .expect_err("a request that may have been delivered was sent again");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(lost.frames.load(Ordering::SeqCst), 1);
    assert_eq!(good.frames.load(Ordering::SeqCst), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}

/// The transport reconnects once on its own when its capabilities declare
/// retry safety. If the first attempt's frame was written, the reconnect's
/// refused upgrade must not make the whole call look unsent to a dispatcher
/// configured as not retry-safe.
#[tokio::test]
async fn an_unsent_reconnect_after_a_written_frame_is_not_failed_over() {
    let lost = Peer::start(|connection| {
        if connection == 0 {
            Connection::DropAfterFrame
        } else {
            Connection::Refuse(400)
        }
    })
    .await;
    let good = Peer::start(|_| Connection::Serve).await;
    let set = not_retry_safe(vec![
        ("lost", lost.provider(true)),
        ("good", good.provider(true)),
    ]);
    let error = set
        .encrypt_batch(&context(), &input())
        .await
        .expect_err("a request that may have been delivered was sent again");
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
    assert_eq!(lost.frames.load(Ordering::SeqCst), 1);
    assert_eq!(
        lost.refusals.load(Ordering::SeqCst),
        1,
        "the transport's reconnect did not run"
    );
    assert_eq!(good.frames.load(Ordering::SeqCst), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}
