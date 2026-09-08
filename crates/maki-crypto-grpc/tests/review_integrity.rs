//! R3-001: authenticated gRPC error metadata through the complete engine path.
#[path = "common/integrity.rs"]
mod common;

use common::*;
use maki_crypto::{
    CiphertextUnit, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status};

#[derive(Clone)]
enum Mode {
    Authenticated(u8),
    Error(Code, Vec<String>),
    Stall,
}
#[derive(Clone)]
struct Server(Arc<Mutex<Mode>>);
impl Server {
    async fn handle(
        &self,
        request: Request<CryptoBatchRequest>,
        decrypt: bool,
    ) -> Result<CryptoBatchResponse, Status> {
        let mode = self.0.lock().unwrap().clone();
        match mode {
            Mode::Error(code, reasons) => {
                let mut status = Status::new(code, REMOTE_SECRET);
                for reason in reasons {
                    status
                        .metadata_mut()
                        .append("maki-crypto-error", reason.parse().unwrap());
                }
                Err(status)
            }
            Mode::Stall => std::future::pending().await,
            Mode::Authenticated(seed) => {
                let message = request.into_inner();
                let context = maki_crypto::CryptoContext {
                    volume_uuid: message.volume_id.parse().unwrap(),
                    format_version: 1,
                    crypto_compatibility_id: message.compatibility_id,
                };
                let provider = local(seed);
                let result = if decrypt {
                    let items: Vec<_> = message
                        .items
                        .into_iter()
                        .map(|i| CiphertextUnit {
                            unit_index: i.unit_index,
                            data: i.data,
                        })
                        .collect();
                    provider.decrypt_batch(&context, &items).await.map(|items| {
                        items
                            .into_iter()
                            .map(|i| CryptoItem {
                                unit_index: i.unit_index,
                                data: i.data.expose().to_vec(),
                            })
                            .collect()
                    })
                } else {
                    let items: Vec<_> = message
                        .items
                        .into_iter()
                        .map(|i| PlaintextUnit {
                            unit_index: i.unit_index,
                            data: SecretBuffer::from_vec(i.data),
                        })
                        .collect();
                    provider.encrypt_batch(&context, &items).await.map(|items| {
                        items
                            .into_iter()
                            .map(|i| CryptoItem {
                                unit_index: i.unit_index,
                                data: i.data,
                            })
                            .collect()
                    })
                };
                result
                    .map(|items| CryptoBatchResponse { items })
                    .map_err(|error| {
                        assert!(matches!(error, CryptoError::Integrity(_)), "{error}");
                        let mut status = Status::new(Code::FailedPrecondition, REMOTE_SECRET);
                        status
                            .metadata_mut()
                            .insert("maki-crypto-error", "auth-tag-mismatch".parse().unwrap());
                        status
                    })
            }
        }
    }
}
impl NamedService for Server {
    const NAME: &'static str = "maki.CryptoService";
}
impl<B> Service<http::Request<B>> for Server
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let this = self.clone();
        let decrypt = request.uri().path().ends_with("DecryptBatch");
        Box::pin(async move {
            struct Unary(Server, bool);
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<Response<Self::Response>, Status>;
                fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                    let server = self.0.clone();
                    let decrypt = self.1;
                    Box::pin(
                        async move { server.handle(request, decrypt).await.map(Response::new) },
                    )
                }
            }
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(Unary(this, decrypt), request)
                .await)
        })
    }
}
struct Incoming(tokio::net::TcpListener);
impl tonic::codegen::tokio_stream::Stream for Incoming {
    type Item = std::io::Result<tokio::net::TcpStream>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0
            .poll_accept(cx)
            .map(|result| Some(result.map(|(stream, _)| stream)))
    }
}
async fn server(mode: Mode) -> (String, Arc<Mutex<Mode>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(mode));
    let service = Server(state.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(Incoming(listener))
            .await
            .unwrap();
    });
    (url, state)
}
async fn provider(url: &str, timeout: Duration) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: url.into(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: capabilities().await,
        timeout,
        max_message_bytes: 1 << 20,
    })
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_grpc_engine_pipeline() {
    let (url, _) = server(Mode::Authenticated(1)).await;
    let (wrong_url, _) = server(Mode::Authenticated(2)).await;
    let remote = Arc::new(provider(&url, Duration::from_secs(2)).await);
    verify_engine(
        remote,
        Arc::new(provider(&wrong_url, Duration::from_secs(2)).await),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_integrity_requires_exact_status_and_one_allowlisted_reason() {
    let (url, state) = server(Mode::Authenticated(1)).await;
    let provider = provider(&url, Duration::from_secs(2)).await;
    for reason in ["auth-tag-mismatch", "context-mismatch"] {
        *state.lock().unwrap() = Mode::Error(Code::FailedPrecondition, vec![reason.into()]);
        let error = provider
            .decrypt_batch(
                &context(),
                &[CiphertextUnit {
                    unit_index: 7,
                    data: vec![0; UNIT + 28],
                }],
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, CryptoError::Integrity(_)),
            "{reason}: {error}"
        );
        assert_private(&error);
    }
    for (code, reasons) in [
        (Code::InvalidArgument, vec!["auth-tag-mismatch".to_string()]),
        (Code::Unavailable, vec!["auth-tag-mismatch".to_string()]),
        (Code::FailedPrecondition, vec![]),
        (Code::FailedPrecondition, vec!["unknown".into()]),
        (
            Code::FailedPrecondition,
            vec!["auth-tag-mismatch, context-mismatch".into()],
        ),
        (
            Code::FailedPrecondition,
            vec!["auth-tag-mismatch".into(), "auth-tag-mismatch".into()],
        ),
        (
            Code::FailedPrecondition,
            vec!["context-mismatch".into(), "unknown".into()],
        ),
        (Code::FailedPrecondition, vec!["SECRET".repeat(1024)]),
    ] {
        *state.lock().unwrap() = Mode::Error(code, reasons);
        let error = provider
            .encrypt_batch(&context(), &[plaintext()])
            .await
            .unwrap_err();
        assert!(
            !matches!(error, CryptoError::Integrity(_)),
            "ambiguous metadata became integrity proof: {error}"
        );
        assert_private(&error);
        assert_eq!(
            error.class(),
            if code == Code::Unavailable {
                ErrorClass::Retryable
            } else {
                ErrorClass::NonRetryableRequest
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_timeout_remains_inconclusive_through_scheduler() {
    let (url, _) = server(Mode::Stall).await;
    let provider = pipeline(Arc::new(provider(&url, Duration::from_millis(50)).await));
    let error = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert_eq!(error.class(), ErrorClass::Retryable);
    assert_private(&error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_grpc_tamper_and_context_probes() {
    let (url, _) = server(Mode::Authenticated(1)).await;
    verify_probes(&provider(&url, Duration::from_secs(2)).await).await;
}
