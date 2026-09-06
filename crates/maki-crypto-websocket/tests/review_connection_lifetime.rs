//! BUG-005: retired generations must release their socket and reader/writer
//! tasks, including when an outer operation cancels the transport future.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

struct Server {
    url: String,
    accepted: Arc<AtomicUsize>,
    requests: mpsc::UnboundedReceiver<usize>,
    closed: mpsc::UnboundedReceiver<usize>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    /// Echo on generations at or above `first_echo`; earlier ones never
    /// reply or initiate a close, leaving teardown entirely to the client.
    async fn start(first_echo: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let (request_tx, requests) = mpsc::unbounded_channel();
        let (closed_tx, closed) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let generation = count.fetch_add(1, Ordering::SeqCst) + 1;
                let requests = request_tx.clone();
                let closed = closed_tx.clone();
                connections.spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                    while let Some(Ok(message)) = ws.next().await {
                        let Ok(text) = message.into_text() else {
                            continue;
                        };
                        let request: Value = serde_json::from_str(&text).unwrap();
                        let _ = requests.send(generation);
                        if generation >= first_echo {
                            let response = json!({"id": request["id"], "items": request["items"]});
                            if ws.send(response.to_string().into()).await.is_err() {
                                break;
                            }
                        }
                    }
                    let _ = closed.send(generation);
                });
            }
        });
        Self {
            url,
            accepted,
            requests,
            closed,
            task,
        }
    }

    fn provider(&self, timeout: Duration) -> Arc<WsCryptoProvider> {
        Arc::new(WsCryptoProvider::new(WsProviderSpec {
            url: self.url.clone(),
            capabilities: CryptoCapabilities {
                provider_id: "websocket-test".into(),
                crypto_compatibility_id: "test-v1".into(),
                supported_plaintext_sizes: vec![64],
                max_ciphertext_size: 64,
                stateless: true,
                retry_safe: false,
                batch: BatchCapability {
                    supported: true,
                    max_items: 8,
                    max_bytes: 4096,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout,
            max_frame_bytes: 4096,
        }))
    }

    async fn expect_closed(&mut self, generation: usize) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), self.closed.recv())
                .await
                .expect("retired connection still owns its socket"),
            Some(generation)
        );
    }

    async fn expect_request(&mut self, generation: usize) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), self.requests.recv())
                .await
                .unwrap(),
            Some(generation)
        );
    }
}

async fn encrypt(
    provider: &WsCryptoProvider,
) -> Result<Vec<maki_crypto::CiphertextUnit>, maki_crypto::CryptoError> {
    provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(5),
                format_version: 1,
                crypto_compatibility_id: "test-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 1,
                data: SecretBuffer::zeroed(64),
            }],
        )
        .await
}

#[tokio::test]
async fn every_timeout_closes_its_socket_before_another_request() {
    let mut server = Server::start(usize::MAX).await;
    let provider = server.provider(Duration::from_millis(100));
    for generation in 1..=4 {
        assert!(encrypt(&provider).await.unwrap_err().is_retryable());
        server.expect_request(generation).await;
        server.expect_closed(generation).await;
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn dropping_an_idle_provider_closes_its_live_connection() {
    let mut server = Server::start(1).await;
    let provider = server.provider(Duration::from_secs(5));
    assert_eq!(encrypt(&provider).await.unwrap()[0].data, vec![0; 64]);
    server.expect_request(1).await;
    drop(provider);
    server.expect_closed(1).await;
}

#[tokio::test]
async fn cancelling_an_outer_request_closes_the_socket_without_waiting_for_transport_timeout() {
    let mut server = Server::start(usize::MAX).await;
    let provider = server.provider(Duration::from_secs(60));
    let request = tokio::spawn({
        let provider = provider.clone();
        async move { encrypt(&provider).await }
    });
    server.expect_request(1).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    server.expect_closed(1).await;
}

#[tokio::test]
async fn retirement_of_an_old_generation_leaves_a_healthy_successor_reusable() {
    let mut server = Server::start(2).await;
    let provider = server.provider(Duration::from_millis(100));
    assert!(encrypt(&provider).await.is_err());
    server.expect_request(1).await;
    assert_eq!(encrypt(&provider).await.unwrap()[0].data, vec![0; 64]);
    server.expect_request(2).await;
    server.expect_closed(1).await;
    assert_eq!(encrypt(&provider).await.unwrap()[0].data, vec![0; 64]);
    server.expect_request(2).await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    drop(provider);
    server.expect_closed(2).await;
}
