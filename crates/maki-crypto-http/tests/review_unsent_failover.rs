//! An HTTP request is written only on an established connection. A refused
//! TCP connection or a failed TLS handshake (reqwest's `is_connect`) proves
//! that no byte of the request left Maki, so the dispatcher may send that
//! request to a peer even when the provider is not retry-safe. Once the
//! request may have been written, it is never sent again: not after a lost
//! response, and not for a per-item mapping whose earlier item was already
//! sent when a later item's connection was refused.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
    TlsSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const UNIT: usize = 64;
const XOR: u8 = 0x3c;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0057),
        format_version: 1,
        crypto_compatibility_id: "http-unsent-v1".into(),
    }
}

fn unit(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }
}

/// What a peer does with each accepted connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer every request (one per connection).
    Serve,
    /// Read the whole request, then close without a response.
    DropAfterRequest,
    /// Serve the first connection only; stop listening before answering it,
    /// so every later connection is refused.
    ServeOnce,
}

struct Peer {
    url: String,
    /// Complete requests received.
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    async fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                if mode == Mode::ServeOnce {
                    drop(listener);
                    answer(socket, &count, true).await;
                    return;
                }
                let count = count.clone();
                tokio::spawn(async move { answer(socket, &count, mode == Mode::Serve).await });
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// Read one request; answer it with the XOR of its raw body when `respond`.
async fn answer(mut socket: TcpStream, requests: &AtomicUsize, respond: bool) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    let body = loop {
        let Ok(length) = socket.read(&mut buffer).await else {
            return;
        };
        if length == 0 {
            return;
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
                break request[end + 4..end + 4 + body_length].to_vec();
            }
        }
    };
    requests.fetch_add(1, Ordering::SeqCst);
    if !respond {
        return;
    }
    let body: Vec<u8> = body.iter().map(|byte| byte ^ XOR).collect();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    let _ = socket.shutdown().await;
}

/// A raw per-item mapping: one HTTP request per unit.
fn provider(url: &str, tls: Option<TlsSpec>) -> Arc<dyn CryptoProvider> {
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
            base_url: url.to_string(),
            encrypt: operation.clone(),
            decrypt: operation,
            capabilities: CryptoCapabilities {
                provider_id: "http-unsent".into(),
                crypto_compatibility_id: context().crypto_compatibility_id,
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                retry_safe: false,
                batch: BatchCapability {
                    supported: true,
                    max_items: 2,
                    max_bytes: 2 * UNIT as u64,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(5),
            max_response_bytes: 4096,
            tls,
        })
        .unwrap(),
    )
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

#[tokio::test]
async fn a_refused_connection_fails_a_non_retry_safe_request_over_to_a_peer() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let good = Peer::start(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("down", provider(&down, None)),
        ("good", provider(&good.url, None)),
    ]);
    let output = set
        .encrypt_batch(&context(), &[unit(0)])
        .await
        .unwrap_or_else(|error| {
            panic!("a refused TCP connection failed a request that was never sent: {error:?}")
        });
    assert_eq!(output[0].data, vec![0x42 ^ XOR; UNIT]);
    assert_eq!(good.requests(), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
}

/// The server's certificate is not trusted, so the handshake fails before
/// the request is written.
#[tokio::test]
async fn a_failed_tls_handshake_fails_a_non_retry_safe_request_over_to_a_peer() {
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let attempts = Arc::new(AtomicUsize::new(0));
    let handshakes = Arc::new(AtomicUsize::new(0));
    let (attempted, completed) = (attempts.clone(), handshakes.clone());
    let untrusted = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            attempted.fetch_add(1, Ordering::SeqCst);
            if acceptor.accept(socket).await.is_ok() {
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let good = Peer::start(Mode::Serve).await;
    let set = not_retry_safe(vec![
        (
            "untrusted",
            provider(
                &format!("https://127.0.0.1:{port}"),
                Some(TlsSpec::default()),
            ),
        ),
        ("good", provider(&good.url, None)),
    ]);
    let output = set
        .encrypt_batch(&context(), &[unit(0)])
        .await
        .unwrap_or_else(|error| {
            panic!("a failed TLS handshake failed a request that was never sent: {error:?}")
        });
    assert_eq!(output[0].data, vec![0x42 ^ XOR; UNIT]);
    assert!(attempts.load(Ordering::SeqCst) >= 1, "TLS was never tried");
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);
    assert_eq!(good.requests(), 1);
    assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
    untrusted.abort();
}

/// Negative control: the request was written before the connection closed,
/// so it is never sent to another endpoint.
#[tokio::test]
async fn a_request_lost_after_it_was_written_is_not_failed_over() {
    let lost = Peer::start(Mode::DropAfterRequest).await;
    let good = Peer::start(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("lost", provider(&lost.url, None)),
        ("good", provider(&good.url, None)),
    ]);
    let error = set
        .encrypt_batch(&context(), &[unit(0)])
        .await
        .expect_err("a request that may have been delivered was sent again");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(lost.requests(), 1);
    assert_eq!(good.requests(), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}

/// A per-item mapping sends one HTTP request per unit. The first unit was
/// sent before the second unit's connection was refused, so the provider
/// call as a whole may have reached the endpoint and is not failed over.
#[tokio::test]
async fn a_refused_connection_after_an_earlier_item_was_sent_is_not_failed_over() {
    let once = Peer::start(Mode::ServeOnce).await;
    let good = Peer::start(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("once", provider(&once.url, None)),
        ("good", provider(&good.url, None)),
    ]);
    let error = set
        .encrypt_batch(&context(), &[unit(0), unit(1)])
        .await
        .expect_err("a call whose first item was delivered was sent again");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(once.requests(), 1);
    assert_eq!(good.requests(), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}
