//! BUG-057: locally rejected gRPC response bytes are endpoint contract
//! failures. A real remote OutOfRange status remains a request error.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::clock::SystemClock;
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
};
use prost::bytes::BufMut;
use tonic::codec::{Codec, EncodeBuf, Encoder, ProstCodec};
use tonic::codegen::{http, BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Code, Request, Response, Status};

const UNIT: usize = 512;
const LIMIT: usize = 1024;
const LOCAL_LIMIT_MESSAGE: &str = "grpc response exceeds the message-size limit";

#[derive(Clone)]
enum Reply {
    Data(usize),
    RemoteRange(String),
    InvalidProtobuf,
}

struct State {
    reply: Mutex<Reply>,
    calls: AtomicUsize,
}

#[derive(Clone)]
struct ServiceImpl(Arc<State>);

impl NamedService for ServiceImpl {
    const NAME: &'static str = "maki.CryptoService";
}

struct ResponseCodec {
    inner: ProstCodec<CryptoBatchResponse, CryptoBatchRequest>,
    invalid: bool,
}

struct ResponseEncoder {
    inner: <ProstCodec<CryptoBatchResponse, CryptoBatchRequest> as Codec>::Encoder,
    invalid: bool,
}

impl Encoder for ResponseEncoder {
    type Item = CryptoBatchResponse;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        if self.invalid {
            // A truncated nested data field, rejected by the client's
            // protected decoder rather than by a remote status.
            dst.put_slice(&[0x0a, 0x03, 0x12, 0x05, 0x11]);
            Ok(())
        } else {
            self.inner.encode(item, dst)
        }
    }
}

impl Codec for ResponseCodec {
    type Encode = CryptoBatchResponse;
    type Decode = CryptoBatchRequest;
    type Encoder = ResponseEncoder;
    type Decoder = <ProstCodec<CryptoBatchResponse, CryptoBatchRequest> as Codec>::Decoder;

    fn encoder(&mut self) -> Self::Encoder {
        ResponseEncoder {
            inner: self.inner.encoder(),
            invalid: self.invalid,
        }
    }

    fn decoder(&mut self) -> Self::Decoder {
        self.inner.decoder()
    }
}

impl<B> Service<http::Request<B>> for ServiceImpl
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
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
        let reply = self.0.reply.lock().unwrap().clone();
        Box::pin(async move {
            struct Unary(ServiceImpl, Reply);
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<Response<Self::Response>, Status>;

                fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                    let state = self.0 .0.clone();
                    let reply = self.1.clone();
                    Box::pin(async move {
                        state.calls.fetch_add(1, Ordering::SeqCst);
                        if let Reply::RemoteRange(message) = reply {
                            return Err(Status::new(Code::OutOfRange, message));
                        }
                        let len = match reply {
                            Reply::Data(len) => len,
                            _ => UNIT,
                        };
                        let items = request
                            .into_inner()
                            .items
                            .into_iter()
                            .map(|item| {
                                let mut data = vec![0x11; len];
                                for (out, input) in data.iter_mut().zip(item.data) {
                                    *out = input ^ 0x5a;
                                }
                                CryptoItem {
                                    unit_index: item.unit_index,
                                    data,
                                }
                            })
                            .collect();
                        Ok(Response::new(CryptoBatchResponse { items }))
                    })
                }
            }
            let codec = ResponseCodec {
                inner: ProstCodec::default(),
                invalid: matches!(reply, Reply::InvalidProtobuf),
            };
            Ok(tonic::server::Grpc::new(codec)
                .unary(Unary(this, reply), request)
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
        match self.0.poll_accept(cx) {
            std::task::Poll::Ready(Ok((stream, _))) => std::task::Poll::Ready(Some(Ok(stream))),
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Some(Err(error))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

struct Server {
    url: String,
    state: Arc<State>,
    owner: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.owner.abort();
    }
}

impl Server {
    async fn start(reply: Reply) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(State {
            reply: Mutex::new(reply),
            calls: AtomicUsize::new(0),
        });
        let service = ServiceImpl(state.clone());
        let owner = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(Incoming(listener))
                .await
                .unwrap();
        });
        Self { url, state, owner }
    }

    fn provider(&self, retry_safe: bool) -> Arc<GrpcCryptoProvider> {
        Arc::new(
            GrpcCryptoProvider::new(GrpcProviderSpec {
                url: self.url.clone(),
                encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
                decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
                metadata: vec![],
                capabilities: capabilities(retry_safe),
                timeout: Duration::from_secs(2),
                max_message_bytes: LIMIT,
            })
            .unwrap(),
        )
    }

    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x57),
        format_version: 1,
        crypto_compatibility_id: "grpc-receive-v1".into(),
    }
}

fn capabilities(retry_safe: bool) -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "grpc-receive".into(),
        crypto_compatibility_id: "grpc-receive-v1".into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: LIMIT as u32,
        stateless: true,
        retry_safe,
        batch: BatchCapability {
            supported: true,
            max_items: 1,
            max_bytes: UNIT as u64,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn set(left: &Server, right: &Server, retry_safe: bool) -> EndpointSet {
    EndpointSet::new(
        vec![
            ("left".into(), left.provider(retry_safe)),
            ("right".into(), right.provider(retry_safe)),
        ],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 16,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 3,
                open_initial: Duration::from_secs(60),
                open_max: Duration::from_secs(60),
                half_open_max_requests: 1,
                success_threshold: 1,
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(1),
            max_operation_time: Some(Duration::from_secs(2)),
            retry_safe,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
}

fn plaintext() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(UNIT),
    }
}

#[tokio::test]
async fn oversized_successful_response_fails_over_and_opens_its_breaker() {
    let left = Server::start(Reply::Data(UNIT)).await;
    let right = Server::start(Reply::Data(UNIT)).await;
    let endpoints = set(&left, &right, true);
    endpoints
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap();
    *left.state.reply.lock().unwrap() = Reply::Data(2048);
    for _ in 0..10 {
        let result = endpoints.encrypt_batch(&context(), &[plaintext()]).await;
        assert!(
            result.is_ok(),
            "healthy peer must receive the retry: {result:?}"
        );
    }
    assert_eq!(left.calls(), 4); // Initial success, then the failure threshold.
    assert_eq!(right.calls(), 10);
    assert_eq!(endpoints.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(endpoints.global_inflight(), (0, 0));
}

#[tokio::test]
async fn oversized_decrypt_response_is_an_endpoint_contract_error() {
    let server = Server::start(Reply::Data(2048)).await;
    let error = server
        .provider(true)
        .decrypt_batch(
            &context(),
            &[CiphertextUnit {
                unit_index: 1,
                data: vec![0; UNIT],
            }],
        )
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
}

#[tokio::test]
async fn oversized_response_without_replay_permission_is_not_resent() {
    let left = Server::start(Reply::Data(2048)).await;
    let right = Server::start(Reply::Data(UNIT)).await;
    let endpoints = set(&left, &right, false);
    let error = endpoints
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    assert_eq!(left.calls(), 1);
    assert_eq!(right.calls(), 0);
    assert_eq!(endpoints.global_inflight(), (0, 0));
}

#[tokio::test]
async fn actual_remote_out_of_range_remains_a_request_error_even_with_local_error_text() {
    for message in [
        "request index rejected",
        LOCAL_LIMIT_MESSAGE,
        "Error, decoded message length too large: found 2048 bytes, the limit is: 1024 bytes",
    ] {
        let left = Server::start(Reply::RemoteRange(message.into())).await;
        let right = Server::start(Reply::Data(UNIT)).await;
        let endpoints = set(&left, &right, true);
        let error = endpoints
            .encrypt_batch(&context(), &[plaintext()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, CryptoError::NonRetryableRequest(_)),
            "{error:?}"
        );
        assert_eq!(left.calls(), 1);
        assert_eq!(right.calls(), 0);
        assert_eq!(endpoints.endpoint_states()[0].1, CircuitState::Closed);
    }
}

#[tokio::test]
async fn invalid_response_protobuf_is_a_contract_error_and_can_fail_over() {
    let left = Server::start(Reply::InvalidProtobuf).await;
    let right = Server::start(Reply::Data(UNIT)).await;
    let error = left
        .provider(true)
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
    let endpoints = set(&left, &right, true);
    endpoints
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap();
    assert_eq!(right.calls(), 1);
}

#[tokio::test]
async fn exact_message_limit_is_accepted_and_one_byte_over_is_refused() {
    use prost::Message;
    let response = CryptoBatchResponse {
        items: vec![CryptoItem {
            unit_index: 1,
            data: vec![0; LIMIT - 8],
        }],
    };
    assert_eq!(response.encoded_len(), LIMIT);
    let server = Server::start(Reply::Data(LIMIT - 8)).await;
    assert!(server
        .provider(true)
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .is_ok());
    *server.state.reply.lock().unwrap() = Reply::Data(LIMIT - 7);
    let error = server
        .provider(true)
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
}

#[tokio::test]
async fn oversized_input_is_still_a_local_request_error_without_sending() {
    let server = Server::start(Reply::Data(UNIT)).await;
    let item = PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(2048),
    };
    let error = server
        .provider(true)
        .encrypt_batch(&context(), &[item])
        .await
        .unwrap_err();
    assert!(
        matches!(error, CryptoError::NonRetryableRequest(_)),
        "{error:?}"
    );
    assert_eq!(server.calls(), 0);
}
