//! The gRPC provider establishes its connection (TCP and TLS) without an RPC
//! body and hands the request to tonic only once that connection is ready.
//! A refused connection, a failed or unfinished handshake, or an RPC timeout
//! that expires before the hand-over proves that no byte of the request left
//! Maki, so the dispatcher may send that request to a peer even when the
//! provider is not retry-safe. Once the request was handed to tonic it may
//! have been delivered, and it is never sent again: not after an error
//! status, and not after a timeout while waiting for the response.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status};

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
    GrpcTlsConfig,
};

const UNIT: usize = 256;
const XOR: u8 = 0x66;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x0057),
        format_version: 1,
        crypto_compatibility_id: "grpc-unsent-v1".to_string(),
    }
}

fn unit() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 3,
        data: SecretBuffer::from_slice(&[0x42; UNIT]),
    }
}

/// How the service answers an RPC.
#[derive(Clone, Copy)]
enum Mode {
    Serve,
    Fail(Code),
    /// Never answer.
    Stall,
}

#[derive(Clone)]
struct CryptoServer {
    mode: Mode,
    calls: Arc<AtomicUsize>,
}

impl CryptoServer {
    async fn handle(
        self,
        request: Request<CryptoBatchRequest>,
    ) -> Result<Response<CryptoBatchResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            Mode::Serve => {}
            Mode::Fail(code) => return Err(Status::new(code, "injected")),
            Mode::Stall => std::future::pending::<()>().await,
        }
        let items = request
            .into_inner()
            .items
            .into_iter()
            .map(|item| CryptoItem {
                unit_index: item.unit_index,
                data: item.data.iter().map(|byte| byte ^ XOR).collect(),
            })
            .collect();
        Ok(Response::new(CryptoBatchResponse { items }))
    }
}

impl NamedService for CryptoServer {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for CryptoServer
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        struct Unary(CryptoServer);
        impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
            type Response = CryptoBatchResponse;
            type Future = BoxFuture<Response<Self::Response>, Status>;
            fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                Box::pin(self.0.clone().handle(request))
            }
        }
        let server = self.clone();
        Box::pin(async move {
            let codec: tonic::codec::ProstCodec<CryptoBatchResponse, CryptoBatchRequest> =
                tonic::codec::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(Unary(server), request)
                .await)
        })
    }
}

struct ListenerStream(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for ListenerStream {
    type Item = std::io::Result<tokio::net::TcpStream>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0
            .poll_accept(cx)
            .map(|accepted| Some(accepted.map(|(stream, _)| stream)))
    }
}

/// A plaintext loopback gRPC server and its RPC counter.
async fn server(mode: Mode) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let service = CryptoServer {
        mode,
        calls: calls.clone(),
    };
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(ListenerStream(listener))
            .await;
    });
    (url, calls)
}

fn spec(url: &str, timeout: Duration) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url: url.to_string(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "remote-grpc-unsent".to_string(),
            crypto_compatibility_id: context().crypto_compatibility_id,
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: false,
            batch: BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 1 << 20,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout,
        max_message_bytes: 1 << 20,
    }
}

fn provider(url: &str, timeout: Duration) -> Arc<dyn CryptoProvider> {
    Arc::new(GrpcCryptoProvider::new(spec(url, timeout)).unwrap())
}

/// A dispatcher for a provider that is not retry-safe, under
/// `bounded-error` (a generous deadline only bounds a broken test).
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
            global_max_inflight_batches: 4,
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: Some(5),
            max_operation_time: Some(Duration::from_secs(20)),
            retry_safe: false,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(UNIT as u32)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connection_fails_a_non_retry_safe_request_over_to_a_peer() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let (good, served) = server(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("down", provider(&down, Duration::from_secs(5))),
        ("good", provider(&good, Duration::from_secs(5))),
    ]);
    let output = set
        .encrypt_batch(&context(), &[unit()])
        .await
        .unwrap_or_else(|error| {
            panic!("a refused TCP connection failed a request that was never sent: {error:?}")
        });
    assert_eq!(output[0].data, vec![0x42 ^ XOR; UNIT]);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 0);
}

/// The peer accepts TCP and never answers the ClientHello: the RPC's own
/// timeout expires while it still waits for the connection, before any
/// request byte is handed to tonic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfinished_tls_handshake_fails_a_non_retry_safe_request_over_to_a_peer() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counted = accepts.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for socket in listener.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
            held.push(socket);
        }
    });
    let authority = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let silent: Arc<dyn CryptoProvider> = Arc::new(
        GrpcCryptoProvider::new_with_tls(
            spec(
                &format!("https://127.0.0.1:{port}"),
                Duration::from_millis(250),
            ),
            GrpcTlsConfig {
                ca_certificate_pem: Some(authority.cert.pem().into_bytes()),
                ..GrpcTlsConfig::default()
            },
        )
        .unwrap(),
    );
    let (good, served) = server(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("silent", silent),
        ("good", provider(&good, Duration::from_secs(5))),
    ]);
    let output = set
        .encrypt_batch(&context(), &[unit()])
        .await
        .unwrap_or_else(|error| {
            panic!("an unfinished TLS handshake failed a request that was never sent: {error:?}")
        });
    assert_eq!(output[0].data, vec![0x42 ^ XOR; UNIT]);
    assert!(
        accepts.load(Ordering::SeqCst) >= 1,
        "the silent peer was never tried"
    );
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(set.metrics().failovers_total(), 1);
}

/// Negative control: an error status answers a request that reached the
/// server, so the request is never sent to another endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_error_status_after_the_request_was_sent_is_not_failed_over() {
    let (failing, failed) = server(Mode::Fail(Code::Unavailable)).await;
    let (good, served) = server(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("failing", provider(&failing, Duration::from_secs(5))),
        ("good", provider(&good, Duration::from_secs(5))),
    ]);
    let error = set
        .encrypt_batch(&context(), &[unit()])
        .await
        .expect_err("a request that reached its endpoint was sent again");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(failed.load(Ordering::SeqCst), 1);
    assert_eq!(served.load(Ordering::SeqCst), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}

/// Negative control: the RPC timeout expires after the request was handed
/// to an established connection, so it may have been delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timeout_after_the_request_was_handed_over_is_not_failed_over() {
    let (stalled, received) = server(Mode::Stall).await;
    let (good, served) = server(Mode::Serve).await;
    let set = not_retry_safe(vec![
        ("stalled", provider(&stalled, Duration::from_millis(250))),
        ("good", provider(&good, Duration::from_secs(5))),
    ]);
    let error = set
        .encrypt_batch(&context(), &[unit()])
        .await
        .expect_err("a request that may have been delivered was sent again");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
    assert_eq!(received.load(Ordering::SeqCst), 1);
    assert_eq!(served.load(Ordering::SeqCst), 0);
    assert_eq!(set.metrics().retries_refused_unsafe_total(), 1);
}
