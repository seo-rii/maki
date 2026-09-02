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
    class_of_code, CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider,
    GrpcProviderSpec,
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
    fail_with: parking_lot_lite::Mutex<Option<Code>>,
    reorder: std::sync::atomic::AtomicBool,
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
            .map(|item| CryptoItem {
                unit_index: item.unit_index,
                data: item.data.iter().map(|b| b ^ XOR).collect(),
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
    type Response = http::Response<tonic::body::BoxBody>;
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
                    .body(tonic::body::empty_body())
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
        ErrorClass::ProviderFatal
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
