//! BUG-062: bound the complete protobuf request and keep local failures neutral.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer, SystemClock,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
};
use prost::Message;
use tonic::codegen::{http, BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

const UNIT: usize = 512;

#[derive(Clone, Copy)]
enum Reply {
    Data,
    Internal,
}

#[derive(Clone)]
struct ServiceImpl {
    calls: Arc<AtomicUsize>,
    reply: Reply,
}

impl NamedService for ServiceImpl {
    const NAME: &'static str = "maki.CryptoService";
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
        let service = self.clone();
        Box::pin(async move {
            struct Unary(ServiceImpl);

            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<Response<Self::Response>, Status>;

                fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                    let service = self.0.clone();
                    Box::pin(async move {
                        service.calls.fetch_add(1, Ordering::SeqCst);
                        if matches!(service.reply, Reply::Internal) {
                            return Err(Status::internal("server processing failed"));
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
                        Ok(Response::new(CryptoBatchResponse { items }))
                    })
                }
            }

            let codec = tonic::codec::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec)
                .max_decoding_message_size(4096)
                .max_encoding_message_size(4096)
                .unary(Unary(service), request)
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
    calls: Arc<AtomicUsize>,
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
        let calls = Arc::new(AtomicUsize::new(0));
        let service = ServiceImpl {
            calls: calls.clone(),
            reply,
        };
        let owner = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(Incoming(listener))
                .await
                .unwrap();
        });
        Self { url, calls, owner }
    }

    fn provider(&self, limit: usize, compatibility_id: &str) -> Arc<GrpcCryptoProvider> {
        Arc::new(
            GrpcCryptoProvider::new(GrpcProviderSpec {
                url: self.url.clone(),
                encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
                decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
                metadata: vec![],
                capabilities: capabilities(compatibility_id),
                timeout: Duration::from_secs(2),
                max_message_bytes: limit,
            })
            .unwrap(),
        )
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn context(compatibility_id: &str, format_version: u32) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x62),
        format_version,
        crypto_compatibility_id: compatibility_id.into(),
    }
}

fn capabilities(compatibility_id: &str) -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "grpc-size".into(),
        crypto_compatibility_id: compatibility_id.into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: UNIT as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 2,
            max_bytes: 2 * UNIT as u64,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn plaintext(unit_index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index,
        data: SecretBuffer::from_slice(&[0x33; UNIT]),
    }
}

fn request_len(context: &CryptoContext, units: &[u64]) -> usize {
    CryptoBatchRequest {
        volume_id: context.volume_uuid.to_string(),
        compatibility_id: context.crypto_compatibility_id.clone(),
        items: units
            .iter()
            .map(|unit_index| CryptoItem {
                unit_index: *unit_index,
                data: vec![0x33; UNIT],
            })
            .collect(),
        format_version: context.format_version,
    }
    .encoded_len()
}

fn endpoint_set(endpoints: Vec<(String, Arc<dyn CryptoProvider>)>, unit: u32) -> EndpointSet {
    EndpointSet::new(
        endpoints,
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            budget: RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 8,
                min_probe_per_sec: 1.0,
            },
            breaker: BreakerConfig {
                failure_threshold: 1,
                ..BreakerConfig::default()
            },
            global_max_inflight_batches: 2,
            global_max_inflight_bytes: 4096,
            per_endpoint_max_inflight: 2,
            per_endpoint_max_bytes: 4096,
            max_attempts: Some(1),
            max_operation_time: Some(Duration::from_secs(5)),
            retry_safe: true,
            validation_interval: Duration::from_secs(1),
        },
        Arc::new(SystemClock::new()),
    )
    .with_plaintext_size(unit)
}

#[tokio::test]
async fn fitting_request_is_not_rejected_by_a_larger_estimate() {
    let server = Server::start(Reply::Data).await;
    let context = context("a", 1);
    assert_eq!(request_len(&context, &[0]), 561);
    let provider = server.provider(580, "a");
    let encrypted = provider
        .encrypt_batch(&context, &[plaintext(0)])
        .await
        .unwrap();
    assert_eq!(encrypted[0].data, vec![0x33 ^ 0x5a; UNIT]);
    assert_eq!(server.calls(), 1);
}

#[tokio::test]
async fn exact_boundary_includes_context_item_lengths_and_varints() {
    let server = Server::start(Reply::Data).await;
    let mut calls = 0;
    for compatibility_len in [1, 127, 128] {
        let compatibility_id = "x".repeat(compatibility_len);
        for format in [0, 1, 127, 128, u32::MAX] {
            let context = context(&compatibility_id, format);
            for units in [
                vec![0],
                vec![127],
                vec![128],
                vec![u64::MAX],
                vec![0, u64::MAX],
            ] {
                let limit = request_len(&context, &units);
                let provider = server.provider(limit, &compatibility_id);
                let input: Vec<_> = units.iter().copied().map(plaintext).collect();
                let output = provider.encrypt_batch(&context, &input).await.unwrap_or_else(|error| {
                    panic!("compat={compatibility_len}, format={format}, units={units:?}, limit={limit}: {error}")
                });
                assert_eq!(output.len(), input.len());
                assert!(output
                    .iter()
                    .all(|item| item.data == vec![0x33 ^ 0x5a; UNIT]));
                calls += 1;
            }
        }
    }
    assert_eq!(server.calls(), calls);
}

#[tokio::test]
async fn one_byte_over_the_complete_request_limit_is_a_local_error() {
    let server = Server::start(Reply::Data).await;
    for compatibility_id in ["a".to_string(), "x".repeat(128)] {
        let context = context(&compatibility_id, u32::MAX);
        let limit = request_len(&context, &[u64::MAX]) - 1;
        let error = server
            .provider(limit, &compatibility_id)
            .encrypt_batch(&context, &[plaintext(u64::MAX)])
            .await
            .unwrap_err();
        assert!(
            matches!(error, CryptoError::NonRetryableRequest(_)),
            "{error}"
        );
    }
    assert_eq!(server.calls(), 0);
}

#[tokio::test]
async fn oversized_context_is_a_local_error_for_encrypt_and_decrypt() {
    let server = Server::start(Reply::Data).await;
    let compatibility_id = "x".repeat(128);
    let context = context(&compatibility_id, 1);
    assert_eq!(request_len(&context, &[0]), 689);
    let provider = server.provider(600, &compatibility_id);
    let encrypt = provider
        .encrypt_batch(&context, &[plaintext(0)])
        .await
        .unwrap_err();
    let decrypt = provider
        .decrypt_batch(
            &context,
            &[CiphertextUnit {
                unit_index: 0,
                data: vec![0x33; UNIT],
            }],
        )
        .await
        .unwrap_err();
    for error in [encrypt, decrypt] {
        assert!(
            matches!(error, CryptoError::NonRetryableRequest(_)),
            "{error}"
        );
    }
    assert_eq!(server.calls(), 0);
}

#[tokio::test]
async fn local_encoding_limit_does_not_fail_over_or_open_healthy_breakers() {
    let left = Server::start(Reply::Data).await;
    let right = Server::start(Reply::Data).await;
    let compatibility_id = "x".repeat(128);
    let endpoints = endpoint_set(
        vec![
            ("left".into(), left.provider(600, &compatibility_id)),
            ("right".into(), right.provider(600, &compatibility_id)),
        ],
        UNIT as u32,
    );
    let error = endpoints
        .encrypt_batch(&context(&compatibility_id, 1), &[plaintext(0)])
        .await
        .unwrap_err();
    assert!(
        matches!(error, CryptoError::NonRetryableRequest(_)),
        "{error}"
    );
    assert!(endpoints
        .endpoint_states()
        .iter()
        .all(|(_, state)| *state == CircuitState::Closed));
    assert_eq!(endpoints.metrics().retries_total(), 0);
    assert_eq!(endpoints.metrics().failovers_total(), 0);
    assert_eq!(left.calls() + right.calls(), 0);
    assert_eq!(endpoints.global_inflight(), (0, 0));
}

#[tokio::test]
async fn real_remote_internal_is_still_retryable() {
    let server = Server::start(Reply::Internal).await;
    let error = server
        .provider(1024, "a")
        .encrypt_batch(&context("a", 1), &[plaintext(0)])
        .await
        .unwrap_err();
    assert!(matches!(error, CryptoError::Retryable(_)), "{error}");
    assert_eq!(server.calls(), 1);
}

#[tokio::test]
async fn real_remote_internal_still_charges_the_failed_peer_and_fails_over() {
    let failed = Server::start(Reply::Internal).await;
    let healthy = Server::start(Reply::Data).await;
    let endpoints = endpoint_set(
        vec![
            ("failed".into(), failed.provider(1024, "a")),
            ("healthy".into(), healthy.provider(1024, "a")),
        ],
        UNIT as u32,
    );
    endpoints
        .encrypt_batch(&context("a", 1), &[plaintext(0)])
        .await
        .unwrap();
    assert_eq!(failed.calls(), 1);
    assert_eq!(healthy.calls(), 1);
    assert_eq!(endpoints.endpoint_states()[0].1, CircuitState::Open);
    assert_eq!(endpoints.endpoint_states()[1].1, CircuitState::Closed);
    assert_eq!(endpoints.metrics().failovers_total(), 1);
}

#[test]
fn both_reported_message_size_configurations_validate() {
    let backing_root = if cfg!(windows) {
        r"C:\maki-grpc-size-unused"
    } else {
        "/unused/grpc-size"
    };
    for (compatibility_id, limit) in [("a".to_string(), 580), ("x".repeat(128), 600)] {
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "grpc_size"
max_virtual_size = "1GiB"
device_block_size = 512
crypto_unit_size = 512
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "{compatibility_id}"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
stateless = true
retry_safe = true
[crypto.batch]
target_items = 1
target_bytes = 512
max_items = 1
max_bytes = 512
[crypto.grpc]
timeout = "2s"
max_message_bytes = {limit}
[[crypto.grpc.endpoint]]
name = "test"
url = "http://127.0.0.1:18080"
[backing]
root = '{backing_root}'
"#
        );
        let config = maki_format::config::parse_config(&raw).unwrap();
        config.validate().unwrap();
    }
}
