//! BUG-162: transport limits cover reachable batches, including serialization overhead.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
};
use maki_format::config::{parse_config, ConfigError, VolumeConfig};
use prost::Message as _;
use tonic::codegen::{http, BoxFuture, Service, StdError};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

const UNIT: usize = 4096;
const CIPHER: usize = 4384;
const LIMIT: usize = 16 << 10;
const PROFILE: &str = "effective-batch-v1";

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(162),
        format_version: u32::MAX,
        crypto_compatibility_id: PROFILE.into(),
    }
}

fn capabilities() -> CryptoCapabilities {
    CryptoCapabilities {
        provider_id: "effective-batch".into(),
        crypto_compatibility_id: PROFILE.into(),
        supported_plaintext_sizes: vec![UNIT as u32],
        max_ciphertext_size: CIPHER as u32,
        stateless: true,
        retry_safe: true,
        batch: BatchCapability {
            supported: true,
            max_items: 1,
            max_bytes: 1 << 20,
        },
        integrity: Capability::Absent,
        context_binding: Capability::Absent,
        replay_protection: Capability::Absent,
    }
}

fn plain(unit: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_vec((0..UNIT).map(|i| i as u8).collect()),
    }
}

fn transform(data: &[u8], decrypt: bool) -> Vec<u8> {
    if decrypt {
        assert_eq!(data.len(), CIPHER);
        data[CIPHER - UNIT..].iter().map(|b| b ^ 0x5a).collect()
    } else {
        assert_eq!(data.len(), UNIT);
        let mut result = vec![0xa5; CIPHER - UNIT];
        result.extend(data.iter().map(|b| b ^ 0x5a));
        result
    }
}

fn validated(raw: &str) -> Result<VolumeConfig, ConfigError> {
    let config = parse_config(raw)?;
    config.validate()?;
    Ok(config)
}

fn config(limit: &str, batch_bytes: &str, max_items: usize) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "effective-batch"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "{PROFILE}"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
integrity = "none"
context_binding = "none"
replay_protection = "none"
[crypto.batch]
target_items = {max_items}
max_items = {max_items}
target_bytes = "{batch_bytes}"
max_bytes = "{batch_bytes}"
[crypto.grpc]
max_message_bytes = "{limit}"
[[crypto.grpc.endpoint]]
name = "local-fixture"
url = "http://127.0.0.1:7000"
[backing]
root = "/unused/batch-limits"
"#
    )
}

#[test]
fn singleton_configuration_accepts_a_limit_that_fits_its_largest_legal_item() {
    let result = validated(&config("16KiB", "1MiB", 1));
    assert!(
        result.is_ok(),
        "one 4096-byte unit / 4384-byte ciphertext fits a 16KiB transport limit: {result:?}"
    );
}

#[test]
fn increasing_transport_limit_preserves_an_otherwise_identical_configuration() {
    let parsed = validated(&config("2MiB", "1MiB", 1)).unwrap();
    assert_eq!(parsed.crypto.batch.max_items, 1);
    assert_eq!(parsed.crypto.batch.max_bytes.0, 1 << 20);
}

#[test]
fn reducing_unused_logical_byte_ceiling_makes_same_transport_limit_validate() {
    let parsed = validated(&config("16KiB", "4KiB", 1)).unwrap();
    assert_eq!(parsed.crypto.batch.max_items, 1);
    assert_eq!(parsed.crypto.capabilities.max_ciphertext_size, 4384);
}

#[test]
fn a_larger_legal_batch_really_requires_a_larger_transport_limit() {
    let error = validated(&config("16KiB", "1MiB", 32))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_message_bytes"), "{error}");
}

#[test]
fn serialized_singleton_message_limit_has_an_exact_boundary() {
    // Use prost's real request encoder, with the widest context and a
    // maximum-size ciphertext as sent by decrypt. A response is smaller.
    let bound = CryptoBatchRequest {
        volume_id: context().volume_uuid.to_string(),
        compatibility_id: PROFILE.into(),
        format_version: u32::MAX,
        items: vec![CryptoItem {
            unit_index: u64::MAX,
            data: vec![0; CIPHER],
        }],
    }
    .encoded_len();
    let error = validated(&config(&(bound - 1).to_string(), "1MiB", 1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_message_bytes"), "{error}");
    for limit in [bound, bound + 1] {
        validated(&config(&limit.to_string(), "1MiB", 1)).unwrap();
    }
}

#[test]
fn byte_ceiling_counts_only_complete_provider_units() {
    // The transport holds one ciphertext, but not two. Up to one byte below
    // the second unit's plaintext budget, only a singleton is reachable.
    for bytes in [UNIT, 2 * UNIT - 1] {
        validated(&config("7000", &bytes.to_string(), 32)).unwrap();
    }
    let error = validated(&config("7000", &(2 * UNIT).to_string(), 32))
        .unwrap_err()
        .to_string();
    assert!(error.contains("max_message_bytes"), "{error}");
}

#[test]
fn other_supported_unit_sizes_do_not_expand_this_volumes_batch() {
    let raw = config("16KiB", "1MiB", 1).replace(
        "supported_plaintext_sizes = [4096]",
        "supported_plaintext_sizes = [4096, 65536]",
    );
    let config = validated(&raw).unwrap();
    assert_eq!(config.provider_plaintext_size().unwrap(), UNIT as u32);
}

#[derive(Clone)]
struct Fixture {
    requests: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
impl NamedService for Fixture {
    const NAME: &'static str = "maki.CryptoService";
}
impl<B> Service<http::Request<B>> for Fixture
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
        let fixture = self.clone();
        let decrypt = request.uri().path().ends_with("/DecryptBatch");
        Box::pin(async move {
            struct Unary(Fixture, bool);
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<Response<Self::Response>, Status>;
                fn call(&mut self, request: Request<CryptoBatchRequest>) -> Self::Future {
                    let fixture = self.0.clone();
                    let decrypt = self.1;
                    Box::pin(async move {
                        let request = request.into_inner();
                        fixture.calls.fetch_add(1, Ordering::SeqCst);
                        fixture
                            .requests
                            .fetch_max(request.encoded_len(), Ordering::SeqCst);
                        let response = CryptoBatchResponse {
                            items: request
                                .items
                                .into_iter()
                                .map(|item| CryptoItem {
                                    unit_index: item.unit_index,
                                    data: transform(&item.data, decrypt),
                                })
                                .collect(),
                        };
                        fixture
                            .responses
                            .fetch_max(response.encoded_len(), Ordering::SeqCst);
                        Ok(Response::new(response))
                    })
                }
            }
            Ok(
                tonic::server::Grpc::new(tonic::codec::ProstCodec::default())
                    .max_decoding_message_size(LIMIT)
                    .max_encoding_message_size(LIMIT)
                    .unary(Unary(fixture, decrypt), request)
                    .await,
            )
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
            .map(|r| Some(r.map(|(stream, _)| stream)))
    }
}

#[tokio::test]
async fn maximum_singleton_roundtrip_and_self_test_fit_and_oversized_batch_does_not() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fixture = Fixture {
        requests: Arc::new(AtomicUsize::new(0)),
        responses: Arc::new(AtomicUsize::new(0)),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let serving = fixture.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let owner = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(serving)
            .serve_with_incoming_shutdown(Incoming(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let provider = GrpcCryptoProvider::new(GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: capabilities(),
        timeout: Duration::from_secs(3),
        max_message_bytes: LIMIT,
    })
    .unwrap();
    // Use the same valid singleton contract as the configuration regression.
    let config = validated(&config("16KiB", "1MiB", 1)).unwrap();
    assert_eq!(
        config.crypto.batch.max_items,
        provider.capabilities().await.unwrap().batch.max_items
    );
    let context = context();
    let items = [plain(u64::MAX)];
    let encrypted = provider.encrypt_batch(&context, &items).await.unwrap();
    assert_eq!(encrypted[0].data.len(), CIPHER);
    assert_eq!(
        provider.decrypt_batch(&context, &encrypted).await.unwrap()[0].data,
        items[0].data
    );
    maki_crypto::selftest::provider_self_test(&provider, &context, UNIT, PROFILE)
        .await
        .unwrap();
    let before = fixture.calls.load(Ordering::SeqCst);
    let oversized: Vec<_> = (0..32).map(plain).collect();
    let error = provider
        .encrypt_batch(&context, &oversized)
        .await
        .unwrap_err();
    assert!(
        matches!(error, maki_crypto::CryptoError::NonRetryableRequest(_)),
        "{error}"
    );
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        before,
        "oversized local request must not reach server"
    );
    assert!(fixture.requests.load(Ordering::SeqCst) <= LIMIT);
    assert!(fixture.responses.load(Ordering::SeqCst) <= LIMIT);
    drop(provider);
    stop.send(()).unwrap();
    owner.await.unwrap();
}
