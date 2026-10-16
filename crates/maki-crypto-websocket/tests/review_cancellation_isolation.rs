//! BUG-126: one cancelled multiplexed request must not fail its live siblings.
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_websocket::{WsCryptoProvider, WsProviderSpec};
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};

struct Request {
    generation: usize,
    id: Value,
    unit: u64,
    reply: mpsc::UnboundedSender<Value>,
}

impl Request {
    fn respond(&self) {
        self.reply
            .send(json!({"id": self.id, "items": [{
                "unit": self.unit,
                "data": base64::engine::general_purpose::STANDARD.encode([0x5a; 64]),
            }]}))
            .unwrap();
    }
}

struct Server {
    url: String,
    requests: mpsc::UnboundedReceiver<Request>,
    closed: mpsc::UnboundedReceiver<usize>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let (closed_tx, closed) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut generation = 0;
            while let Ok((socket, _)) = listener.accept().await {
                generation += 1;
                let requests = requests_tx.clone();
                let closed = closed_tx.clone();
                connections.spawn(async move {
                    let ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                    let (mut sink, mut source) = ws.split();
                    let (reply, mut replies) = mpsc::unbounded_channel::<Value>();
                    loop {
                        tokio::select! {
                            message = source.next() => {
                                let Some(Ok(message)) = message else { break };
                                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                                requests.send(Request {
                                    generation,
                                    id: request["id"].clone(),
                                    unit: request["items"][0]["unit"].as_u64().unwrap(),
                                    reply: reply.clone(),
                                }).unwrap();
                            },
                            Some(response) = replies.recv() => {
                                if sink.send(response.to_string().into()).await.is_err() { break; }
                            }
                        }
                    }
                    let _ = closed.send(generation);
                });
            }
        });
        Self {
            url,
            requests,
            closed,
            task,
        }
    }

    fn provider(&self) -> Arc<WsCryptoProvider> {
        Arc::new(WsCryptoProvider::new(WsProviderSpec {
            url: self.url.clone(),
            capabilities: CryptoCapabilities {
                provider_id: "cancellation-test".into(),
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
            timeout: Duration::from_secs(60),
            max_frame_bytes: 4096,
            tls: None,
        }))
    }

    async fn request(&mut self, unit: u64, generation: usize) -> Request {
        let request = tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
            .await
            .expect("request was not sent")
            .unwrap();
        assert_eq!((request.unit, request.generation), (unit, generation));
        request
    }

    async fn closed(&mut self, generation: usize) {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), self.closed.recv())
                .await
                .expect("retired connection still owns its socket"),
            Some(generation)
        );
    }
}

fn launch(
    provider: &Arc<WsCryptoProvider>,
    unit_index: u64,
) -> JoinHandle<Result<Vec<CiphertextUnit>, CryptoError>> {
    let provider = provider.clone();
    tokio::spawn(async move {
        provider
            .encrypt_batch(
                &CryptoContext {
                    volume_uuid: uuid::Uuid::from_u128(5),
                    format_version: 1,
                    crypto_compatibility_id: "test-v1".into(),
                },
                &[PlaintextUnit {
                    unit_index,
                    data: SecretBuffer::zeroed(64),
                }],
            )
            .await
    })
}

async fn success(task: JoinHandle<Result<Vec<CiphertextUnit>, CryptoError>>, unit: u64) {
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("live request stalled")
        .unwrap()
        .unwrap();
    assert_eq!(result[0].unit_index, unit);
    assert_eq!(result[0].data, vec![0x5a; 64]);
}

#[tokio::test]
async fn cancelling_one_request_preserves_sibling_and_discards_late_response() {
    let mut server = Server::start().await;
    let provider = server.provider();
    let cancelled = launch(&provider, 1);
    let late = server.request(1, 1).await;
    let survivor = launch(&provider, 2);
    let response = server.request(2, 1).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    late.respond();
    response.respond();
    success(survivor, 2).await;
    server.closed(1).await;
    assert!(
        server.requests.try_recv().is_err(),
        "retry-unsafe requests were resent"
    );
}

#[tokio::test]
async fn replacement_can_serve_while_the_cancelled_generation_drains() {
    let mut server = Server::start().await;
    let provider = server.provider();
    let cancelled = launch(&provider, 1);
    let late = server.request(1, 1).await;
    let survivor = launch(&provider, 2);
    let response = server.request(2, 1).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let fresh = launch(&provider, 3);
    server.request(3, 2).await.respond();
    success(fresh, 3).await;
    late.respond();
    response.respond();
    success(survivor, 2).await;
    server.closed(1).await;
    let reused = launch(&provider, 4);
    server.request(4, 2).await.respond();
    success(reused, 4).await;
    drop(provider);
    server.closed(2).await;
}

#[tokio::test]
async fn cancelling_the_final_sibling_closes_the_draining_socket() {
    let mut server = Server::start().await;
    let provider = server.provider();
    let first = launch(&provider, 1);
    server.request(1, 1).await;
    let second = launch(&provider, 2);
    server.request(2, 1).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    second.abort();
    assert!(second.await.unwrap_err().is_cancelled());
    server.closed(1).await;
}

#[tokio::test]
async fn successful_concurrent_requests_keep_the_connection_reusable() {
    let mut server = Server::start().await;
    let provider = server.provider();
    let first = launch(&provider, 1);
    let response = server.request(1, 1).await;
    let second = launch(&provider, 2);
    server.request(2, 1).await.respond();
    response.respond();
    success(first, 1).await;
    success(second, 2).await;
    let third = launch(&provider, 3);
    server.request(3, 1).await.respond();
    success(third, 3).await;
}
