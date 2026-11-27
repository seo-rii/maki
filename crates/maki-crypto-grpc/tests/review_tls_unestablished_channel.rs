//! A TLS failure inside a gRPC call retires the cached channel, also one
//! that never completed an RPC.
//!
//! A channel no RPC has completed on is otherwise kept for its first
//! `4 x timeout` (the initial progress window, `connection.rs`), so that a
//! slow handshake can finish for the next call. When the calls on it so far
//! were only answered retryably (here `Unavailable`, a server warming up),
//! the channel is still in that window when the connection under it closes
//! and tonic's reconnect inside it fails its TLS handshake (a server
//! restarted with a certificate the client does not trust). That call fails
//! as an endpoint failure counted as sent: tonic held its request while it
//! reconnected. Kept, the channel would hand the next call to tonic's
//! reconnect too, with the same result, and an `EndpointSet` whose provider
//! is not retry-safe would refuse to send the request to a healthy peer. The
//! next call must go through the provider's own payload-free connection
//! attempt instead, whose TLS failure proves the request unsent.
//!
//! The controls are the same sequence after a completed first call
//! (`review_tls_failure_in_call.rs`).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use maki_crypto::breaker::BreakerConfig;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
    GrpcTlsConfig,
};
use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};

const TLS_FAILURE: &str = "endpoint fatal: grpc TLS authentication or protocol failure";

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "tls-unestablished-channel".into(),
            crypto_compatibility_id: "tls-unestablished-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 528,
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
        timeout: Duration::from_secs(5),
        max_message_bytes: 4096,
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(1019),
        format_version: 1,
        crypto_compatibility_id: "tls-unestablished-v1".into(),
    }
}

fn unit(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[0x65; 512]),
    }
}

async fn encrypt(provider: &GrpcCryptoProvider) -> Result<(), CryptoError> {
    provider
        .encrypt_batch(&context(), &[unit(7)])
        .await
        .map(|_| ())
}

/// An XOR service; while `unavailable` is set, every call is answered
/// `Unavailable`, a retryable status that completes no RPC.
#[derive(Clone)]
struct Xor {
    unavailable: Arc<AtomicBool>,
}

impl tonic::server::NamedService for Xor {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for Xor
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let unavailable = self.unavailable.load(Ordering::SeqCst);
        Box::pin(async move {
            struct Unary(bool);
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                fn call(&mut self, request: tonic::Request<CryptoBatchRequest>) -> Self::Future {
                    let unavailable = self.0;
                    Box::pin(async move {
                        if unavailable {
                            return Err(tonic::Status::unavailable("warming up"));
                        }
                        let items = request
                            .into_inner()
                            .items
                            .into_iter()
                            .map(|item| CryptoItem {
                                unit_index: item.unit_index,
                                data: item.data.iter().map(|byte| byte ^ 0x5a).collect(),
                            })
                            .collect();
                        Ok(tonic::Response::new(CryptoBatchResponse { items }))
                    })
                }
            }
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(Unary(unavailable), request)
                .await)
        })
    }
}

struct Incoming(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for Incoming {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A TLS gRPC server with a new self-signed certificate for `127.0.0.1`;
/// returns its address and certificate.
async fn tls_server(unavailable: Arc<AtomicBool>) -> (std::net::SocketAddr, String) {
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let pem = certificate.cert.pem();
    let tls =
        tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
            certificate.cert.pem(),
            certificate.key_pair.serialize_pem(),
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(Xor { unavailable })
            .serve_with_incoming(Incoming(listener))
            .await
            .unwrap();
    });
    (address, pem)
}

fn provider(port: u16, trusted_pem: &str) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new_with_tls(
        spec(format!("https://127.0.0.1:{port}")),
        GrpcTlsConfig {
            ca_certificate_pem: Some(trusted_pem.as_bytes().to_vec()),
            client_identity: None,
        },
    )
    .unwrap()
}

type Cut = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

struct AfterTlsFailure {
    provider: Arc<GrpcCryptoProvider>,
    trusted: std::net::SocketAddr,
    trusted_pem: String,
    connections: Arc<AtomicUsize>,
}

/// A provider whose first call was answered (`first_ok`) or refused
/// `Unavailable`, and whose second call reconnected inside its channel to a
/// server with a certificate the client does not trust: a TLS failure
/// inside the call.
///
/// A proxy sends each connection to the trusted server or, once `replaced`
/// is set, to the other. It can cut a connection it carries: it drops the
/// upstream side, closes its side towards the client and reports when the
/// client has closed its end too. tonic may still hand the second call to
/// the dying connection, which then fails without a new connection; the
/// proxy's connection count tells the two apart without timing, and the
/// scenario is repeated with a fresh provider until a call reconnected
/// (bounded).
async fn after_a_tls_failure_in_a_call(first_ok: bool) -> AfterTlsFailure {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let unavailable = Arc::new(AtomicBool::new(!first_ok));
    let (trusted, trusted_pem) = tls_server(unavailable.clone()).await;
    let (other, _) = tls_server(Arc::new(AtomicBool::new(false))).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let carried: Arc<Mutex<Vec<Cut>>> = Arc::default();
    let connections = Arc::new(AtomicUsize::new(0));
    let replaced = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let carried = carried.clone();
        let connections = connections.clone();
        let replaced = replaced.clone();
        async move {
            while let Ok((mut client, _)) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                let target = if replaced.load(Ordering::SeqCst) {
                    other
                } else {
                    trusted
                };
                let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                let (cut, cut_requested) = tokio::sync::oneshot::channel();
                let (closed, client_closed) = tokio::sync::oneshot::channel();
                carried.lock().unwrap().push((cut, client_closed));
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                        _ = cut_requested => {}
                    }
                    drop(upstream);
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut client).await;
                    let mut sink = [0u8; 4096];
                    while let Ok(1..) = tokio::io::AsyncReadExt::read(&mut client, &mut sink).await
                    {
                    }
                    let _ = closed.send(());
                });
            }
        }
    });
    for _ in 0..20 {
        replaced.store(false, Ordering::SeqCst);
        unavailable.store(!first_ok, Ordering::SeqCst);
        let provider = Arc::new(provider(port, &trusted_pem));
        let first = encrypt(&provider).await;
        if first_ok {
            first.unwrap();
        } else {
            let first = first.unwrap_err();
            assert_eq!(first.class(), ErrorClass::Retryable, "{first}");
        }
        unavailable.store(false, Ordering::SeqCst);

        // Replace the server and cut the connection under the cached
        // channel; wait until the client has closed its end.
        replaced.store(true, Ordering::SeqCst);
        let cuts: Vec<Cut> = carried.lock().unwrap().drain(..).collect();
        for (cut, client_closed) in cuts {
            let _ = cut.send(());
            tokio::time::timeout(Duration::from_secs(10), client_closed)
                .await
                .expect("the client did not close the cut connection")
                .unwrap();
        }
        let before = connections.load(Ordering::SeqCst);
        let refused = encrypt(&provider).await.unwrap_err();
        if connections.load(Ordering::SeqCst) == before {
            // The call went to the dying connection; try again.
            continue;
        }
        // tonic held the request while it reconnected: counted as sent.
        assert_eq!(refused.to_string(), TLS_FAILURE);
        assert!(!refused.is_not_sent(), "{refused:?}");
        return AfterTlsFailure {
            provider,
            trusted,
            trusted_pem,
            connections,
        };
    }
    panic!("no call reconnected inside its channel in 20 attempts");
}

/// The call after the TLS failure.
async fn next_call(first_ok: bool) -> CryptoError {
    let failed = after_a_tls_failure_in_a_call(first_ok).await;
    let before = failed.connections.load(Ordering::SeqCst);
    let next = encrypt(&failed.provider).await.unwrap_err();
    assert_eq!(
        failed.connections.load(Ordering::SeqCst),
        before + 1,
        "the next call opens one new connection"
    );
    next
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_after_a_completed_call_the_next_call_is_a_payload_free_attempt() {
    let next = next_call(true).await;
    assert_eq!(next.to_string(), TLS_FAILURE);
    assert!(next.is_not_sent(), "{next:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_only_retryable_answers_the_next_call_is_a_payload_free_attempt() {
    let next = next_call(false).await;
    assert_eq!(next.to_string(), TLS_FAILURE);
    assert!(
        next.is_not_sent(),
        "the call after a TLS failure reused the channel no RPC had completed on \
         (tonic's own reconnect, its request handed over) instead of the \
         payload-free attempt: {next:?}"
    );
}

/// The effect at the dispatcher: a provider that is not retry-safe, two
/// endpoints, the first one the provider above (its circuit admits at once:
/// `open_initial` 0), the second a healthy endpoint. An unsent failure of
/// the first fails over to the second; a failure that may have been sent
/// ends the operation.
async fn through_a_set(first_ok: bool) -> (Result<(), CryptoError>, u64) {
    let failed = after_a_tls_failure_in_a_call(first_ok).await;
    let healthy: Arc<dyn CryptoProvider> =
        Arc::new(provider(failed.trusted.port(), &failed.trusted_pem));
    let set = EndpointSet::new(
        vec![
            (
                "refusing".into(),
                failed.provider.clone() as Arc<dyn CryptoProvider>,
            ),
            ("healthy".into(), healthy),
        ],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 0.2,
                burst: 16,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 8,
                open_initial: Duration::ZERO,
                open_max: Duration::ZERO,
                half_open_max_requests: 2,
                success_threshold: 1,
            },
            global_max_inflight_batches: 8,
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 8,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: None,
            max_operation_time: None,
            retry_safe: false,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    );
    let result = set.encrypt_batch(&context(), &[unit(9)]).await.map(|_| ());
    (result, set.metrics().failovers_total())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_a_set_fails_over_after_a_completed_call() {
    let (result, failovers) = through_a_set(true).await;
    result.unwrap();
    assert_eq!(failovers, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_set_fails_over_after_only_retryable_answers() {
    let (result, failovers) = through_a_set(false).await;
    result.expect("a TLS failure that never sent the request failed the operation");
    assert_eq!(failovers, 1);
}
