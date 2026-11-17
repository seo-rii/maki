//! A truncated or short raw encrypt response must never become a unit's
//! ciphertext. The write would be acknowledged and only the later read would
//! fail its integrity check: acknowledged data loss.
//!
//! - A 2xx body with neither Content-Length nor chunked transfer coding ends
//!   when the connection closes (RFC 9112 §6.3). A provider that dies
//!   mid-body sends FIN, which looks exactly like the end of the body.
//! - A well-framed 2xx body that is shorter than the plaintext it answers (a
//!   proxy's maintenance page) cannot carry that plaintext's ciphertext; the
//!   raw mapping has no other structure to reject it by.
//!
//! Both are endpoint faults: a contract error that charges the endpoint and
//! fails over when the request is retry-safe.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::checked::CheckedProvider;
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, FieldSource, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind,
    RespSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UNIT: usize = 4096;
const CIPHER: usize = UNIT + 28;
const HTML: &[u8] = b"<html><body>Service under maintenance</body></html>";

/// Builds the complete response bytes for one request body.
type Respond = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

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
    /// One response per connection, then FIN (a clean close, as when the
    /// provider process exits), never a reset.
    async fn start(respond: Respond) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let respond = respond.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let body = read_request(&mut socket).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = socket.write_all(&respond(&body)).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { url, calls, task }
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let length = socket.read(&mut buffer).await.unwrap();
        if length == 0 {
            return Vec::new();
        }
        request.extend_from_slice(&buffer[..length]);
        if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let head = std::str::from_utf8(&request[..end]).unwrap();
            let body_length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if request.len() >= end + 4 + body_length {
                return request[end + 4..end + 4 + body_length].to_vec();
            }
        }
    }
}

/// nonce || plaintext ^ 0x5a || tag: a length-correct "ciphertext".
fn seal(plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = vec![0x11u8; 12];
    cipher.extend(plaintext.iter().map(|byte| byte ^ 0x5a));
    cipher.extend([0x22u8; 16]);
    cipher
}

fn json_seal(request: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let request: serde_json::Value = serde_json::from_slice(request).unwrap();
    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(request["data"].as_str().unwrap())
        .unwrap();
    let data = base64::engine::general_purpose::STANDARD.encode(seal(&plaintext));
    serde_json::to_vec(&serde_json::json!({ "data": data })).unwrap()
}

fn content_length(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    response
}

/// A body delimited only by the connection close, after `head`.
fn close_delimited(head: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!("{head}\r\n\r\n").into_bytes();
    response.extend_from_slice(body);
    response
}

#[derive(Clone, Copy)]
enum Mapping {
    Raw,
    Json,
}

fn operation(mapping: Mapping) -> OpSpec {
    let (body, response) = match mapping {
        Mapping::Raw => (
            BodySpec::Raw,
            RespSpec {
                kind: RespKind::Raw,
                data_path: None,
                encoding: PayloadEncoding::Base64,
                items_path: None,
                item_index_path: None,
            },
        ),
        Mapping::Json => (
            BodySpec::Json {
                fields: vec![(
                    "/data".into(),
                    FieldSource::Payload(PayloadEncoding::Base64),
                )],
                items_path: None,
                item_fields: vec![],
            },
            RespSpec {
                kind: RespKind::Json,
                data_path: Some("/data".into()),
                encoding: PayloadEncoding::Base64,
                items_path: None,
                item_index_path: None,
            },
        ),
    };
    OpSpec {
        method: "POST".into(),
        path: "/crypto".into(),
        headers: vec![],
        query: vec![],
        body,
        response,
    }
}

/// The provider as volume I/O sees it: behind the caller-side validator.
fn provider(server: &Server, mapping: Mapping, retry_safe: bool) -> Arc<dyn CryptoProvider> {
    let operation = operation(mapping);
    let inner = HttpCryptoProvider::new(HttpProviderSpec {
        base_url: server.url.clone(),
        encrypt: operation.clone(),
        decrypt: operation,
        capabilities: CryptoCapabilities {
            provider_id: "short-raw".into(),
            crypto_compatibility_id: "short-raw-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: CIPHER as u32,
            stateless: true,
            retry_safe,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: UNIT as u64,
            },
            integrity: Capability::Contractual,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 1 << 20,
        tls: None,
    })
    .unwrap();
    Arc::new(CheckedProvider::new(Arc::new(inner)))
}

fn dispatch(servers: &[&Server]) -> EndpointSet {
    EndpointSet::new(
        servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                (
                    format!("peer-{index}"),
                    provider(server, Mapping::Raw, true),
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
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: Some(2),
            max_operation_time: Some(Duration::from_secs(10)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(9),
        format_version: 1,
        crypto_compatibility_id: "short-raw-v1".into(),
    }
}

fn plaintext() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }]
}

async fn encrypt(respond: Respond, mapping: Mapping) -> Result<Vec<u8>, CryptoError> {
    let server = Server::start(respond).await;
    let result = provider(&server, mapping, true)
        .encrypt_batch(&context(), &plaintext())
        .await
        .map(|mut out| std::mem::take(&mut out[0].data));
    assert_eq!(server.count(), 1, "one request per encrypt");
    result
}

/// Every case is checked before failing, so one run reports all of them.
fn refusal_failure(case: &str, result: Result<Vec<u8>, CryptoError>) -> Option<String> {
    match result {
        Ok(ciphertext) => Some(format!(
            "{case}: accepted {} bytes as the ciphertext of a {UNIT}-byte unit",
            ciphertext.len()
        )),
        Err(CryptoError::Contract(_)) => None,
        Err(error) => Some(format!(
            "{case}: an endpoint fault must be a contract error: {error}"
        )),
    }
}

fn assert_no_failures(failures: Vec<String>) {
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn close_delimited_success_bodies_are_contract_errors() {
    let cases: [(&str, Mapping, Respond); 5] = [
        (
            "provider died after 2000 of its ciphertext bytes",
            Mapping::Raw,
            Arc::new(|body| {
                close_delimited("HTTP/1.1 200 OK\r\nconnection: close", &seal(body)[..2000])
            }),
        ),
        (
            "complete body, but only the close marks its end",
            Mapping::Raw,
            Arc::new(|body| close_delimited("HTTP/1.1 200 OK\r\nconnection: close", &seal(body))),
        ),
        (
            "HTTP/1.0 without Content-Length",
            Mapping::Raw,
            Arc::new(|body| close_delimited("HTTP/1.0 200 OK", &seal(body))),
        ),
        (
            "a final transfer coding other than chunked reads until close",
            Mapping::Raw,
            Arc::new(|body| {
                close_delimited(
                    "HTTP/1.1 200 OK\r\ntransfer-encoding: identity",
                    &seal(body),
                )
            }),
        ),
        (
            "JSON mapping",
            Mapping::Json,
            Arc::new(|body| {
                close_delimited("HTTP/1.1 200 OK\r\nconnection: close", &json_seal(body))
            }),
        ),
    ];
    let mut failures = Vec::new();
    for (case, mapping, respond) in cases {
        failures.extend(refusal_failure(case, encrypt(respond, mapping).await));
    }
    assert_no_failures(failures);
}

#[tokio::test]
async fn length_and_chunk_delimited_success_bodies_are_accepted() {
    let cases: [(&str, Mapping, Respond); 3] = [
        (
            "Content-Length",
            Mapping::Raw,
            Arc::new(|body| content_length(&seal(body))),
        ),
        (
            "chunked",
            Mapping::Raw,
            Arc::new(|body| chunked(&seal(body))),
        ),
        (
            "JSON with Content-Length",
            Mapping::Json,
            Arc::new(|body| content_length(&json_seal(body))),
        ),
    ];
    for (case, mapping, respond) in cases {
        let ciphertext = encrypt(respond, mapping)
            .await
            .unwrap_or_else(|e| panic!("{case}: {e}"));
        assert!(
            ciphertext == seal(&[0x42; UNIT]),
            "{case}: {} bytes",
            ciphertext.len()
        );
    }
    // A Content-Length body cut short is still detected by the framing and
    // stays a retryable transport failure.
    let error = encrypt(
        Arc::new(|body| {
            let mut response = content_length(&seal(body));
            response.truncate(response.len() - 100);
            response
        }),
        Mapping::Raw,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, CryptoError::Retryable(_)), "{error}");
}

#[tokio::test]
async fn short_well_framed_raw_encrypt_bodies_are_contract_errors() {
    let cases: [(&str, Respond); 3] = [
        (
            "text/html maintenance page",
            Arc::new(|_| content_length(HTML)),
        ),
        (
            "one byte shorter than the plaintext",
            Arc::new(|body| content_length(&seal(body)[12..12 + UNIT - 1])),
        ),
        (
            "chunked half unit",
            Arc::new(|body| chunked(&seal(body)[..UNIT / 2])),
        ),
    ];
    let mut failures = Vec::new();
    for (case, respond) in cases {
        failures.extend(refusal_failure(case, encrypt(respond, Mapping::Raw).await));
    }
    assert_no_failures(failures);
    // A length-preserving cipher (XTS-like) returns exactly its plaintext
    // length; that is not short.
    let ciphertext = encrypt(
        Arc::new(|body| content_length(&seal(body)[12..12 + UNIT])),
        Mapping::Raw,
    )
    .await
    .unwrap();
    assert_eq!(ciphertext.len(), UNIT);
}

#[tokio::test]
async fn truncated_or_short_raw_encrypt_fails_over_to_a_healthy_endpoint() {
    let broken: [Respond; 2] = [
        Arc::new(|body| {
            close_delimited("HTTP/1.1 200 OK\r\nconnection: close", &seal(body)[..2000])
        }),
        Arc::new(|_| content_length(HTML)),
    ];
    for respond in broken {
        let broken = Server::start(respond).await;
        let healthy = Server::start(Arc::new(|body| content_length(&seal(body)))).await;
        let set = dispatch(&[&broken, &healthy]);
        let output = set.encrypt_batch(&context(), &plaintext()).await.unwrap();
        assert!(
            output[0].data == seal(&[0x42; UNIT]),
            "accepted {} bytes from the broken endpoint",
            output[0].data.len()
        );
        assert_eq!(broken.count(), 1);
        assert_eq!(healthy.count(), 1);
        assert_eq!(set.metrics().failovers_total(), 1);
    }
}
