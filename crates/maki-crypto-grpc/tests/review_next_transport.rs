//! BUG-017: a gRPC server that accepts the connection but never completes
//! the response (stalls after headers, or between message and trailers)
//! must not hold the RPC open past the configured transport timeout. The
//! `Channel::timeout` bounds only the connection, so the provider now wraps
//! readiness plus the unary exchange in one `tokio::time::timeout`.

use std::time::{Duration, Instant};

use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::NamedService;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec};

const UNIT: usize = 256;
const TIMEOUT: Duration = Duration::from_millis(250);

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xB17),
        format_version: 1,
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
    }
}

fn caps() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "remote-grpc-stall".to_string(),
        crypto_compatibility_id: "grpc-profile-v1".to_string(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 64,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

/// A server that establishes the HTTP/2 connection (so `ready()` succeeds)
/// but never answers the RPC: the handler sleeps far longer than the
/// client's timeout, so no response header, message, or trailer is sent.
#[derive(Clone)]
struct StallServer;

impl NamedService for StallServer {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for StallServer
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

    fn call(&mut self, _req: http::Request<B>) -> Self::Future {
        Box::pin(async move {
            // Stall well past the client timeout without ever responding.
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(http::Response::builder()
                .status(200)
                .header("grpc-status", "0")
                .header("content-type", "application/grpc")
                .body(tonic::body::empty_body())
                .unwrap())
        })
    }
}

mod listener {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct ListenerStream(pub tokio::net::TcpListener);

    impl tonic::codegen::tokio_stream::Stream for ListenerStream {
        type Item = std::io::Result<tokio::net::TcpStream>;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

async fn stall_server() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(StallServer)
            .serve_with_incoming(listener::ListenerStream(l))
            .await;
    });
    format!("http://{addr}")
}

fn provider(url: &str) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: url.to_string(),
        encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
        metadata: vec![],
        capabilities: caps(),
        timeout: TIMEOUT,
        max_message_bytes: 1 << 20,
    })
    .unwrap()
}

fn unit(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&[index as u8; UNIT]),
    }
}

#[tokio::test]
async fn a_stalled_grpc_response_is_bounded_by_the_transport_timeout() {
    let url = stall_server().await;
    let provider = provider(&url);

    let started = Instant::now();
    let result = provider.encrypt_batch(&ctx(), &[unit(0)]).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a stalled server must not return a successful response"
    );
    assert!(
        matches!(result, Err(CryptoError::Retryable(_))),
        "a timed-out RPC is retryable, got {result:?}"
    );
    // The 30s server stall must be cut off near the 250ms timeout, not held
    // open. Allow generous slack for CI scheduling.
    assert!(
        elapsed < Duration::from_secs(5),
        "RPC ran for {elapsed:?}; the transport timeout did not bound it"
    );
}

mod response_body {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use maki_crypto::{
        BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError,
        CryptoProvider, PlaintextUnit, SecretBuffer,
    };
    use maki_crypto_grpc::{
        CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
    };
    use tonic::codegen::http;
    use tonic::codegen::tokio_stream::Stream;
    use tonic::codegen::{BoxFuture, Service, StdError};
    use tonic::server::NamedService;
    use tonic::{Request, Response, Status};

    const UNIT: usize = 64;
    const TRANSPORT_TIMEOUT: Duration = Duration::from_millis(250);

    #[derive(Clone, Copy)]
    enum ReplyMode {
        Complete,
        NoMessage,
        NoTrailers,
    }

    struct ResponseStream {
        message: Option<CryptoBatchResponse>,
        mode: ReplyMode,
        stalled: Arc<tokio::sync::Notify>,
    }

    impl Stream for ResponseStream {
        type Item = Result<CryptoBatchResponse, Status>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if let Some(message) = self.message.take() {
                return Poll::Ready(Some(Ok(message)));
            }
            if matches!(self.mode, ReplyMode::Complete) {
                Poll::Ready(None)
            } else {
                self.stalled.notify_one();
                Poll::Pending
            }
        }
    }

    #[derive(Clone)]
    struct CryptoServer {
        mode: ReplyMode,
        stalled: Arc<tokio::sync::Notify>,
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

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            let server = self.clone();
            Box::pin(async move {
                struct Svc(CryptoServer);
                impl tonic::server::ServerStreamingService<CryptoBatchRequest> for Svc {
                    type Response = CryptoBatchResponse;
                    type ResponseStream = ResponseStream;
                    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;

                    fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                        let server = self.0.clone();
                        Box::pin(async move {
                            let message = CryptoBatchResponse {
                                items: request
                                    .into_inner()
                                    .items
                                    .into_iter()
                                    .map(|item| CryptoItem {
                                        unit_index: item.unit_index,
                                        data: item.data.iter().map(|byte| byte ^ 0x55).collect(),
                                    })
                                    .collect(),
                            };
                            Ok(Response::new(ResponseStream {
                                message: (!matches!(server.mode, ReplyMode::NoMessage))
                                    .then_some(message),
                                mode: server.mode,
                                stalled: server.stalled,
                            }))
                        })
                    }
                }
                let codec =
                    tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
                // gRPC unary and streaming responses share the same wire format.
                // This sends initial headers and then can withhold either the
                // message or the final trailers of the unary response.
                let mut grpc = tonic::server::Grpc::new(codec);
                Ok(grpc.server_streaming(Svc(server), request).await)
            })
        }
    }

    struct ListenerStream(tokio::net::TcpListener);

    impl Stream for ListenerStream {
        type Item = std::io::Result<tokio::net::TcpStream>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.0
                .poll_accept(cx)
                .map(|result| Some(result.map(|(stream, _)| stream)))
        }
    }

    async fn run(mode: ReplyMode) -> Option<Result<Vec<maki_crypto::CiphertextUnit>, CryptoError>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stalled = Arc::new(tokio::sync::Notify::new());
        let service = CryptoServer {
            mode,
            stalled: stalled.clone(),
        };
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(ListenerStream(listener))
                .await
                .unwrap();
        });
        let provider = GrpcCryptoProvider::new(GrpcProviderSpec {
            url,
            encrypt_path: "/maki.CryptoService/EncryptBatch".to_string(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".to_string(),
            metadata: vec![],
            capabilities: CryptoCapabilities {
                provider_id: "audit-grpc".to_string(),
                crypto_compatibility_id: "audit-profile".to_string(),
                supported_plaintext_sizes: vec![UNIT as u32],
                max_ciphertext_size: UNIT as u32,
                stateless: true,
                retry_safe: true,
                batch: BatchCapability {
                    supported: true,
                    max_items: 8,
                    max_bytes: 1 << 20,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: TRANSPORT_TIMEOUT,
            max_message_bytes: 1 << 20,
        })
        .unwrap();
        let mut request = tokio::spawn(async move {
            provider
                .encrypt_batch(
                    &CryptoContext {
                        volume_uuid: uuid::Uuid::from_u128(71),
                        format_version: 1,
                        crypto_compatibility_id: "audit-profile".to_string(),
                    },
                    &[PlaintextUnit {
                        unit_index: 7,
                        data: SecretBuffer::from_slice(&[0x11; UNIT]),
                    }],
                )
                .await
        });
        if !matches!(mode, ReplyMode::Complete) {
            tokio::time::timeout(Duration::from_secs(5), stalled.notified())
                .await
                .expect("the server must reach its response-body stall");
        }
        // An eight-times margin distinguishes a missing timeout from clock jitter.
        let result = match tokio::time::timeout(TRANSPORT_TIMEOUT * 8, &mut request).await {
            Ok(result) => Some(result.unwrap()),
            Err(_) => {
                request.abort();
                let _ = request.await;
                None
            }
        };
        server.abort();
        let _ = server.await;
        result
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_transport_timeout_includes_waiting_for_the_response_message() {
        let result = run(ReplyMode::NoMessage).await;
        assert!(
            result.is_some(),
            "gRPC stayed pending for 2s after headers despite a 250ms transport timeout"
        );
        assert!(matches!(result.unwrap(), Err(CryptoError::Retryable(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_transport_timeout_includes_waiting_for_response_trailers() {
        let result = run(ReplyMode::NoTrailers).await;
        assert!(
            result.is_some(),
            "gRPC stayed pending for 2s after its message despite a 250ms transport timeout"
        );
        assert!(matches!(result.unwrap(), Err(CryptoError::Retryable(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_grpc_response_is_a_passing_control() {
        let result = run(ReplyMode::Complete).await.unwrap().unwrap();
        assert_eq!(result[0].unit_index, 7);
        assert_eq!(result[0].data, vec![0x11 ^ 0x55; UNIT]);
    }
}
