//! Phase 9 — gRPC transport (SPEC §51): native protocol roundtrip against a
//! hand-rolled tonic service, metadata, status mapping, message-size limits,
//! and the shared provider conformance suite.

use std::sync::Arc;
use std::time::Duration;

use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status};

use maki_crypto::selftest::provider_conformance;
use maki_crypto::{CryptoContext, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer};
use maki_crypto_grpc::{
    class_of_code, map_status, CryptoBatchRequest, CryptoBatchResponse, CryptoItem,
    GrpcCryptoProvider, GrpcProviderSpec,
};

const UNIT: usize = 256;
const XOR: u8 = 0x66;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xB2),
        format_version: 1,
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
    }
}

fn caps() -> maki_crypto::CryptoCapabilities {
    maki_crypto::CryptoCapabilities {
        provider_id: "remote-grpc-test".to_string(),
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: maki_crypto::BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: maki_crypto::Capability::Absent,
        context_binding: maki_crypto::Capability::Absent,
        replay_protection: maki_crypto::Capability::Absent,
    }
}

// ---------------------------------------------------------------- server

/// Behavior knobs shared with the service.
#[derive(Default)]
struct ServerState {
    require_token: Option<String>,
    padded_lengths: Option<(usize, usize)>,
    fail_with: parking_lot_lite::Mutex<Option<Code>>,
    reorder: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}

// tiny local mutex shim to avoid a dev-dependency
mod parking_lot_lite {
    pub struct Mutex<T>(std::sync::Mutex<T>);
    impl<T> Mutex<T> {
        pub fn new(v: T) -> Self {
            Self(std::sync::Mutex::new(v))
        }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.0.lock().unwrap()
        }
    }
    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }
}

#[derive(Clone)]
struct CryptoServer {
    state: Arc<ServerState>,
}

impl CryptoServer {
    #[allow(clippy::result_large_err)] // tonic::Status is the natural error type for a gRPC handler
    fn handle(&self, request: Request<CryptoBatchRequest>) -> Result<CryptoBatchResponse, Status> {
        self.state
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(token) = &self.state.require_token {
            match request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
            {
                Some(got) if got == token => {}
                _ => return Err(Status::new(Code::Unauthenticated, "bad token")),
            }
        }
        if let Some(code) = self.state.fail_with.lock().take() {
            return Err(Status::new(code, "injected"));
        }
        let message = request.into_inner();
        assert_eq!(message.compatibility_id, "grpc-profile-v1");
        let mut items: Vec<CryptoItem> = message
            .items
            .into_iter()
            .map(|item| {
                let mut data: Vec<_> = item.data.iter().map(|b| b ^ XOR).collect();
                if let Some((plain, cipher)) = self.state.padded_lengths {
                    if data.len() == plain {
                        data.resize(cipher, 0);
                    } else {
                        assert_eq!(data.len(), cipher);
                        data.truncate(plain);
                    }
                }
                CryptoItem {
                    unit_index: item.unit_index,
                    data,
                }
            })
            .collect();
        if self.state.reorder.load(std::sync::atomic::Ordering::SeqCst) && items.len() >= 2 {
            items.swap(0, 1);
        }
        Ok(CryptoBatchResponse { items })
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

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let this = self.clone();
        let path = req.uri().path().to_string();
        Box::pin(async move {
            match path.as_str() {
                "/maki.CryptoService/EncryptBatch" | "/maki.CryptoService/DecryptBatch" => {
                    struct Svc(CryptoServer);
                    impl tonic::server::UnaryService<CryptoBatchRequest> for Svc {
                        type Response = CryptoBatchResponse;
                        type Future = BoxFuture<Response<Self::Response>, Status>;
                        fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                            let server = self.0.clone();
                            Box::pin(async move { server.handle(request).map(Response::new) })
                        }
                    }
                    let codec: tonic::codec::ProstCodec<CryptoBatchResponse, CryptoBatchRequest> =
                        tonic::codec::ProstCodec::default();
                    let mut grpc = tonic::server::Grpc::new(codec);
                    Ok(grpc.unary(Svc(this), req).await)
                }
                _ => Ok(http::Response::builder()
                    .status(200)
                    .header("grpc-status", (Code::Unimplemented as i32).to_string())
                    .header("content-type", "application/grpc")
                    .body(tonic::body::Body::empty())
                    .unwrap()),
            }
        })
    }
}

async fn grpc_server(state: Arc<ServerState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream_wrapper::listener_stream(listener);
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(CryptoServer { state })
            .serve_with_incoming(incoming)
            .await;
    });
    format!("http://{addr}")
}

/// Adapter: TcpListener → Stream<Item = io::Result<TcpStream>>.
mod tokio_stream_wrapper {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct ListenerStream(tokio::net::TcpListener);

    impl futures_core_shim::Stream for ListenerStream {
        type Item = std::io::Result<tokio::net::TcpStream>;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    // tonic accepts any futures_core::Stream; use the one it re-exports.
    pub mod futures_core_shim {
        pub use tonic::codegen::tokio_stream::Stream;
    }

    pub fn listener_stream(l: tokio::net::TcpListener) -> ListenerStream {
        ListenerStream(l)
    }
}

fn provider(url: &str, metadata: Vec<(String, String)>) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: url.to_string(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
        metadata,
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_message_bytes: 1 << 20,
    })
    .unwrap()
}

fn pt(i: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: i,
        data: SecretBuffer::from_slice(&vec![fill; UNIT]),
    }
}

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_protocol_roundtrip() {
    let url = grpc_server(Arc::new(ServerState::default())).await;
    let p = provider(&url, vec![]);
    let cts = p
        .encrypt_batch(&ctx(), &[pt(1, 0x21), pt(2, 0x22)])
        .await
        .unwrap();
    assert_eq!(cts[0].data, vec![0x21 ^ XOR; UNIT]);
    let pts = p.decrypt_batch(&ctx(), &cts).await.unwrap();
    assert_eq!(pts[1].data.expose(), &vec![0x22; UNIT][..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_is_sent_and_enforced() {
    let state = Arc::new(ServerState {
        require_token: Some("Bearer grpc-secret".to_string()),
        ..Default::default()
    });
    let url = grpc_server(state).await;

    // Without the token: Unauthenticated → EndpointFatal.
    let p = provider(&url, vec![]);
    let err = p.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::EndpointFatal, "{err:?}");

    // With the token: works.
    let p = provider(
        &url,
        vec![(
            "authorization".to_string(),
            "Bearer grpc-secret".to_string(),
        )],
    );
    p.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_mapping_covers_grpc_codes() {
    assert_eq!(
        class_of_code(Code::ResourceExhausted),
        ErrorClass::Throttled
    );
    assert_eq!(class_of_code(Code::Unavailable), ErrorClass::Retryable);
    assert_eq!(class_of_code(Code::DeadlineExceeded), ErrorClass::Retryable);
    assert_eq!(
        class_of_code(Code::Unauthenticated),
        ErrorClass::EndpointFatal
    );
    assert_eq!(
        class_of_code(Code::InvalidArgument),
        ErrorClass::NonRetryableRequest
    );
    assert_eq!(
        class_of_code(Code::Unimplemented),
        ErrorClass::EndpointFatal
    );

    // And over the wire:
    let state = Arc::new(ServerState::default());
    let url = grpc_server(state.clone()).await;
    let p = provider(&url, vec![]);
    *state.fail_with.lock() = Some(Code::ResourceExhausted);
    let err = p.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::Throttled, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reordered_response_is_detected_via_index_echo() {
    let state = Arc::new(ServerState::default());
    state
        .reorder
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let url = grpc_server(state).await;
    let p = provider(&url, vec![]);
    let err = p
        .encrypt_batch(&ctx(), &[pt(10, 1), pt(20, 2)])
        .await
        .unwrap_err();
    assert!(
        matches!(err, maki_crypto::CryptoError::Contract(_)),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn message_size_limit_is_enforced_client_side() {
    let url = grpc_server(Arc::new(ServerState::default())).await;
    let p = GrpcCryptoProvider::new(GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
        metadata: vec![],
        capabilities: caps(),
        timeout: Duration::from_secs(5),
        max_message_bytes: 128,
    })
    .unwrap();
    let err = p.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::NonRetryableRequest, "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_metadata_fails_closed_at_construction() {
    let bad = GrpcCryptoProvider::new(GrpcProviderSpec {
        url: "http://localhost:1".to_string(),
        encrypt_path: "/x/Y".to_string(),
        decrypt_path: "/x/Z".to_string(),
        metadata: vec![("bad header name!".to_string(), "v".to_string())],
        capabilities: caps(),
        timeout: Duration::from_secs(1),
        max_message_bytes: 1024,
    });
    assert!(bad.is_err());
}

/// Every transport must pass the same provider conformance suite (SPEC §51).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_passes_provider_conformance() {
    let url = grpc_server(Arc::new(ServerState::default())).await;
    let p = provider(&url, vec![]);
    provider_conformance(&p, &ctx(), UNIT, "grpc-profile-v1")
        .await
        .unwrap();
}

/// MAKI-016 / FUP-006: a remote gRPC status message is untrusted and may
/// reflect secrets or inject log lines. `map_status` drops the remote text
/// entirely — only the allowlisted status code reaches the error — while
/// preserving the mapped class. Control-character sanitization alone is not
/// redaction.
#[test]
fn followup_remote_status_does_not_expose_reflected_secrets() {
    let error = map_status(&Status::internal(
        "token=SECRET plaintext=PRIVATE\ninjected",
    ));
    let text = error.to_string();
    assert!(
        !text.contains("SECRET") && !text.contains("PRIVATE") && !text.contains('\n'),
        "remote status text must not reach the error: {text}"
    );
    assert_eq!(error.class(), ErrorClass::Retryable);
}

#[tokio::test]
async fn unimplemented_only_poisoned_endpoint_and_respects_retry_safety() {
    use maki_crypto::breaker::{BreakerConfig, CircuitState};
    use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
    use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
    use std::sync::atomic::Ordering;
    for (retry_safe, all_failed) in [(true, false), (false, false), (true, true)] {
        let left = Arc::new(ServerState::default());
        let right = Arc::new(ServerState::default());
        let left_url = grpc_server(left.clone()).await;
        let right_url = grpc_server(right.clone()).await;
        let config = DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 10,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 1,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 1 << 20,
            per_endpoint_max_inflight: 1,
            per_endpoint_max_bytes: 1 << 20,
            max_attempts: Some(1),
            max_operation_time: Some(Duration::from_secs(2)),
            retry_safe,
            validation_interval: Duration::from_secs(1),
        };
        let set = EndpointSet::new(
            vec![
                ("left".into(), Arc::new(provider(&left_url, vec![]))),
                ("right".into(), Arc::new(provider(&right_url, vec![]))),
            ],
            config,
            Arc::new(maki_crypto::SystemClock::new()),
        );
        set.encrypt_batch(&ctx(), &[pt(1, 1)]).await.unwrap();
        *left.fail_with.lock() = Some(Code::Unimplemented);
        if all_failed {
            *right.fail_with.lock() = Some(Code::Unimplemented);
        }
        let result = set.encrypt_batch(&ctx(), &[pt(2, 2)]).await;
        if retry_safe && !all_failed {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(result.is_err());
        }
        assert_eq!(set.endpoint_states()[0].1, CircuitState::Open);
        assert_eq!(right.calls.load(Ordering::SeqCst), usize::from(retry_safe));
        assert_eq!(set.global_inflight(), (0, 0));
        if all_failed {
            assert_eq!(set.endpoint_states()[1].1, CircuitState::Open);
        }
    }
}

// The limit is measured by the real protobuf serializer, then used by both
// configuration validation and tonic's live request/response codecs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validated_full_batches_roundtrip_at_serialized_grpc_boundary() {
    use maki_format::config::{parse_config, ByteSize};
    use prost::Message;
    for cipher_len in [4383, 4384, 4385] {
        let state = Arc::new(ServerState {
            padded_lengths: Some((4096, cipher_len)),
            ..Default::default()
        });
        let url = grpc_server(state).await;
        let mut cfg = parse_config(&format!(
            r#"
config_schema_version = 1
[volume]
name = "transport-boundary"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "grpc-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = {cipher_len}
[crypto.batch]
max_items = 128
max_bytes = "512KiB"
[crypto.grpc]
[[crypto.grpc.endpoint]]
name = "test"
url = "{url}"
[backing]
root = "/unused"
"#
        ))
        .unwrap();
        let mut context = ctx();
        context.format_version = u32::MAX;
        let message = CryptoBatchRequest {
            volume_id: context.volume_uuid.to_string(),
            compatibility_id: context.crypto_compatibility_id.clone(),
            format_version: context.format_version,
            items: (0..128)
                .map(|i| CryptoItem {
                    unit_index: u64::MAX - i,
                    data: vec![0xAB; cipher_len],
                })
                .collect(),
        };
        let serialized = message.encode_to_vec();
        let boundary = serialized.len();
        assert_eq!(boundary, message.encoded_len());
        cfg.crypto.grpc.as_mut().unwrap().max_message_bytes = Some(ByteSize(boundary as u64 - 1));
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_message_bytes"));
        for limit in [boundary, boundary + 1] {
            cfg.crypto.grpc.as_mut().unwrap().max_message_bytes = Some(ByteSize(limit as u64));
            cfg.validate().unwrap();
            let mut capabilities = caps();
            capabilities.supported_plaintext_sizes = vec![4096];
            capabilities.max_ciphertext_size = cipher_len as u32;
            capabilities.batch.max_items = 128;
            let p = GrpcCryptoProvider::new(GrpcProviderSpec {
                url: url.clone(),
                encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
                decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
                metadata: vec![],
                capabilities,
                timeout: Duration::from_secs(5),
                max_message_bytes: limit,
            })
            .unwrap();
            let plaintext: Vec<_> = (0..128)
                .map(|i| PlaintextUnit {
                    unit_index: u64::MAX - i,
                    data: SecretBuffer::from_slice(&vec![i as u8; 4096]),
                })
                .collect();
            let encrypted = p.encrypt_batch(&context, &plaintext).await.unwrap();
            assert!(encrypted.iter().all(|item| item.data.len() == cipher_len));
            let decrypted = p.decrypt_batch(&context, &encrypted).await.unwrap();
            for (expected, actual) in plaintext.iter().zip(&decrypted) {
                assert_eq!(expected.data.expose(), actual.data.expose());
            }
        }
    }
}

/// Keep the first established TCP connection open but stop forwarding every
/// byte. Later connections use the same healthy backend, so success requires
/// retiring the unresponsive channel rather than retrying its dead socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresponsive_established_channel_is_replaced_after_timeout_or_cancellation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::{TcpListener, TcpStream};

    for cancel in [false, true] {
        let backend = grpc_server(Arc::new(ServerState::default())).await;
        let backend = backend.strip_prefix("http://").unwrap().to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop_forwarding = Arc::new(tokio::sync::Notify::new());
        let parked = Arc::new(tokio::sync::Notify::new());
        let proxy = tokio::spawn({
            let accepted = accepted.clone();
            let stop_forwarding = stop_forwarding.clone();
            let parked = parked.clone();
            async move {
                loop {
                    let (mut client, _) = listener.accept().await.unwrap();
                    let first = accepted.fetch_add(1, Ordering::SeqCst) == 0;
                    let mut upstream = TcpStream::connect(&backend).await.unwrap();
                    let stop_forwarding = stop_forwarding.clone();
                    let parked = parked.clone();
                    tokio::spawn(async move {
                        if first {
                            tokio::select! {
                                _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                                _ = stop_forwarding.notified() => {
                                    parked.notify_one();
                                    let held_open = (client, upstream);
                                    std::future::pending::<()>().await;
                                    drop(held_open);
                                }
                            }
                        } else {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                        }
                    });
                }
            }
        });
        let p = GrpcCryptoProvider::new(GrpcProviderSpec {
            url: format!("http://{address}"),
            encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
            metadata: vec![],
            capabilities: caps(),
            timeout: Duration::from_secs(1),
            max_message_bytes: 1 << 20,
        })
        .unwrap();
        let context = ctx();
        let plaintext = [pt(1, 0xAB)];
        p.encrypt_batch(&context, &plaintext).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        stop_forwarding.notify_one();
        tokio::time::timeout(Duration::from_secs(5), parked.notified())
            .await
            .unwrap();

        if cancel {
            assert!(tokio::time::timeout(
                Duration::from_millis(50),
                p.encrypt_batch(&context, &plaintext)
            )
            .await
            .is_err());
        } else {
            let failure = p.encrypt_batch(&context, &plaintext).await.unwrap_err();
            assert_eq!(failure.class(), ErrorClass::Retryable);
        }
        let encrypted = p.encrypt_batch(&context, &plaintext).await.expect(
            "next RPC must use a fresh connection after an established channel stops responding",
        );
        let decrypted = p.decrypt_batch(&context, &encrypted).await.unwrap();
        assert_eq!(decrypted[0].data.expose(), plaintext[0].data.expose());
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "reuse the healthy replacement"
        );
        proxy.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_tls_handshake_survives_an_rpc_timeout_and_later_succeeds() {
    use maki_crypto_grpc::GrpcTlsConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::{TcpListener, TcpStream};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let tls =
        tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
            certificate.cert.pem(),
            certificate.key_pair.serialize_pem(),
        ));
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(CryptoServer {
                state: Arc::new(ServerState::default()),
            })
            .serve_with_incoming(tokio_stream_wrapper::listener_stream(backend))
            .await
            .unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let forwarding = Arc::new(tokio::sync::Notify::new());
    let proxy = tokio::spawn({
        let accepted = accepted.clone();
        let forwarding = forwarding.clone();
        async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let mut upstream = TcpStream::connect(backend_address).await.unwrap();
                let forwarding = forwarding.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(750)).await;
                    forwarding.notify_one();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        }
    });
    let p = GrpcCryptoProvider::new_with_tls(
        GrpcProviderSpec {
            url: format!("https://{address}"),
            encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
            metadata: vec![],
            capabilities: caps(),
            timeout: Duration::from_millis(500),
            max_message_bytes: 1 << 20,
        },
        GrpcTlsConfig {
            ca_certificate_pem: Some(certificate.cert.pem().into_bytes()),
            client_identity: None,
        },
    )
    .unwrap();
    let context = ctx();
    let plaintext = [pt(7, 0xAB)];
    assert_eq!(
        p.encrypt_batch(&context, &plaintext)
            .await
            .unwrap_err()
            .class(),
        ErrorClass::Retryable
    );
    tokio::time::timeout(Duration::from_secs(5), forwarding.notified())
        .await
        .unwrap();
    let encrypted = p.encrypt_batch(&context, &plaintext).await.unwrap();
    assert_eq!(encrypted[0].data, vec![0xAB ^ XOR; UNIT]);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "finish the original bounded TLS attempt"
    );
    proxy.abort();
    server.abort();
}
