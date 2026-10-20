//! BUG-136: definite peer syntax errors must not become transport retries.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UNIT: usize = 64;
const MARKER: &str = "PRIVATE-RESPONSE-MARKER";

enum Response {
    Bytes(Vec<u8>),
    Stall,
}

struct Server {
    url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(responses: Vec<Response>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut responses = VecDeque::from(responses);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                // Read the whole request before closing, so the transient
                // controls deliberately send EOF instead of a TCP reset.
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let length = socket.read(&mut buffer).await.unwrap();
                    if length == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..length]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let body_length = headers
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + body_length {
                            break;
                        }
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let response = if responses.len() > 1 {
                    responses.pop_front().unwrap()
                } else {
                    match responses.front().unwrap() {
                        Response::Bytes(bytes) => Response::Bytes(bytes.clone()),
                        Response::Stall => Response::Stall,
                    }
                };
                match response {
                    Response::Bytes(bytes) => {
                        // A client may reject the headers before consuming the
                        // whole malformed response.
                        let _ = socket.write_all(&bytes).await;
                        let _ = socket.shutdown().await;
                    }
                    Response::Stall => {
                        std::future::pending::<()>().await;
                    }
                }
            }
        });
        Self { url, calls, task }
    }

    fn provider(&self, retry_safe: bool, timeout: Duration) -> Arc<dyn CryptoProvider> {
        let operation = OpSpec {
            method: "POST".into(),
            path: "/encrypt".into(),
            headers: vec![],
            query: vec![],
            body: BodySpec::Raw,
            response: RespSpec {
                kind: RespKind::Raw,
                data_path: None,
                encoding: PayloadEncoding::Base64,
                items_path: None,
                item_index_path: None,
            },
        };
        Arc::new(
            HttpCryptoProvider::new(HttpProviderSpec {
                base_url: format!("{}?marker={MARKER}", self.url),
                encrypt: operation.clone(),
                decrypt: operation,
                capabilities: CryptoCapabilities {
                    provider_id: "http-framing".into(),
                    crypto_compatibility_id: "http-framing-v1".into(),
                    supported_plaintext_sizes: vec![UNIT as u32],
                    max_ciphertext_size: UNIT as u32,
                    stateless: true,
                    retry_safe,
                    batch: BatchCapability {
                        supported: false,
                        max_items: 1,
                        max_bytes: UNIT as u64,
                    },
                    integrity: Capability::Absent,
                    context_binding: Capability::Absent,
                    replay_protection: Capability::Absent,
                },
                timeout,
                max_response_bytes: 4096,
                tls: None,
            })
            .unwrap(),
        )
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(136),
        format_version: 1,
        crypto_compatibility_id: "http-framing-v1".into(),
    }
}

fn plaintext() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 0,
        data: SecretBuffer::from_slice(&[0x44; UNIT]),
    }]
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    response.extend_from_slice(body);
    response
}

fn healthy() -> Vec<u8> {
    let mut body = b"40\r\n".to_vec();
    body.extend([0x22; UNIT]);
    body.extend(b"\r\n0\r\nx-check: complete\r\n\r\n");
    chunked(&body)
}

fn dispatch(providers: &[&Server], retry_safe: bool) -> EndpointSet {
    EndpointSet::new(
        providers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                (
                    format!("peer-{index}"),
                    server.provider(retry_safe, Duration::from_secs(5)),
                )
            })
            .collect(),
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 16,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 8,
                open_initial: Duration::from_secs(1),
                open_max: Duration::from_secs(1),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(2),
            max_operation_time: Some(Duration::from_secs(10)),
            retry_safe,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
}

fn assert_contract(error: CryptoError) {
    assert!(
        matches!(error, CryptoError::Contract(_)),
        "definite HTTP syntax violation must be Contract: {error}"
    );
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(MARKER), "{rendered}");
        assert!(!rendered.contains("http://"), "{rendered}");
    }
}

#[tokio::test]
async fn malformed_response_heads_are_contract_errors() {
    for response in [
        b"HTTP/1.1 BAD invalid\r\nContent-Length: 0\r\n\r\n".to_vec(),
        format!("HTTP/1.1 200 OK\r\n{MARKER} bad: value\r\n\r\n").into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n".to_vec(),
    ] {
        let server = Server::start(vec![Response::Bytes(response)]).await;
        let error = server
            .provider(true, Duration::from_secs(5))
            .encrypt_batch(&context(), &plaintext())
            .await
            .unwrap_err();
        assert_contract(error);
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn malformed_chunk_sizes_delimiters_and_trailers_are_contract_errors() {
    for body in [
        b"Z\r\n".as_slice(),
        b"1Z\r\n",
        b"1 2\r\n",
        b"10000000000000000\r\n",
        b"1;extension\n",
        b"1\rX",
        b"1\r\nxX",
        b"1\r\nx\rX",
        b"0\r\ninvalid trailer\r\n\r\n",
        b"0\r\nx-test: PRIVATE-RESPONSE-MARKER\rX",
        b"0\r\n\rX",
    ] {
        let server = Server::start(vec![Response::Bytes(chunked(body))]).await;
        let error = server
            .provider(true, Duration::from_secs(5))
            .encrypt_batch(&context(), &plaintext())
            .await
            .unwrap_err();
        assert_contract(error);
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn malformed_peer_is_never_resent_the_same_operation() {
    let server = Server::start(vec![Response::Bytes(chunked(b"Z\r\n"))]).await;
    let set = dispatch(&[&server], true);
    let error = set
        .encrypt_batch(&context(), &plaintext())
        .await
        .unwrap_err();
    assert_eq!(server.count(), 1, "malformed response triggered a retry");
    assert_eq!(set.metrics().rpc_count(), 1);
    assert_contract(error);
}

#[tokio::test]
async fn malformed_peer_fails_over_once_when_retry_safe() {
    let broken = Server::start(vec![Response::Bytes(chunked(b"Z\r\n"))]).await;
    let healthy = Server::start(vec![Response::Bytes(healthy())]).await;
    let set = dispatch(&[&broken, &healthy], true);
    let output = set.encrypt_batch(&context(), &plaintext()).await.unwrap();
    assert_eq!(output[0].data, vec![0x22; UNIT]);
    assert_eq!(broken.count(), 1);
    assert_eq!(healthy.count(), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
}

#[tokio::test]
async fn malformed_peer_does_not_fail_over_when_not_retry_safe() {
    let broken = Server::start(vec![Response::Bytes(chunked(b"Z\r\n"))]).await;
    let healthy = Server::start(vec![Response::Bytes(healthy())]).await;
    let set = dispatch(&[&broken, &healthy], false);
    let error = set
        .encrypt_batch(&context(), &plaintext())
        .await
        .unwrap_err();
    assert_eq!(broken.count(), 1);
    assert_eq!(healthy.count(), 0);
    assert_contract(error);
}

#[tokio::test]
async fn eof_and_truncated_headers_or_bodies_remain_retryable() {
    for response in [
        vec![],
        b"HTTP/1.1 200".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nshort".to_vec(),
        chunked(b"4"),
        chunked(b"4\r\nsh"),
        chunked(b"4\r\nbody\r\n0\r\n"),
    ] {
        let server = Server::start(vec![Response::Bytes(response)]).await;
        let error = server
            .provider(true, Duration::from_secs(5))
            .encrypt_batch(&context(), &plaintext())
            .await
            .unwrap_err();
        assert!(matches!(error, CryptoError::Retryable(_)), "{error}");
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn transient_close_is_retried_and_healthy_chunked_body_succeeds() {
    let server = Server::start(vec![Response::Bytes(vec![]), Response::Bytes(healthy())]).await;
    let set = dispatch(&[&server], true);
    let output = set.encrypt_batch(&context(), &plaintext()).await.unwrap();
    assert_eq!(output[0].data, vec![0x22; UNIT]);
    assert_eq!(server.count(), 2);
    assert_eq!(set.metrics().rpc_count(), 2);
}

#[tokio::test]
async fn stalled_http_response_remains_a_retryable_timeout() {
    let server = Server::start(vec![Response::Stall]).await;
    let error = server
        .provider(true, Duration::from_millis(100))
        .encrypt_batch(&context(), &plaintext())
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Retryable(_)), "{error}");
    assert!(error.to_string().contains("timeout"), "{error}");
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn tcp_connection_refusal_remains_retryable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        url: format!("http://{}", listener.local_addr().unwrap()),
        calls: Arc::new(AtomicUsize::new(0)),
        task: tokio::spawn(std::future::pending()),
    };
    drop(listener);
    let error = server
        .provider(true, Duration::from_secs(5))
        .encrypt_batch(&context(), &plaintext())
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Retryable(_)), "{error}");
}
