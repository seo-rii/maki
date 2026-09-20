use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service};

use super::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcClientIdentity, GrpcCryptoProvider,
    GrpcProviderSpec, GrpcTlsConfig,
};
use maki_crypto::{
    Capability, CryptoCapabilities, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer,
};

#[derive(Clone)]
struct FixedReply(Arc<Mutex<Option<CryptoBatchResponse>>>);

impl tonic::server::NamedService for FixedReply {
    const NAME: &'static str = "crypto";
}

impl tonic::server::UnaryService<CryptoBatchRequest> for FixedReply {
    type Response = CryptoBatchResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<CryptoBatchRequest>) -> Self::Future {
        let response = self.0.lock().unwrap().take().unwrap();
        Box::pin(async move { Ok(tonic::Response::new(response)) })
    }
}

impl<B> Service<http::Request<B>> for FixedReply
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(handler, request)
                .await)
        })
    }
}

struct ListenerStream(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for ListenerStream {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn tls_server(
    san: &str,
    require_client_cert_from: Option<&rcgen::CertifiedKey>,
) -> (std::net::SocketAddr, Vec<u8>) {
    install_crypto_provider();
    let server = rcgen::generate_simple_self_signed(vec![san.to_owned()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity =
        tonic::transport::Identity::from_pem(server.cert.pem(), server.key_pair.serialize_pem());
    let mut tls = tonic::transport::ServerTlsConfig::new().identity(identity);
    if let Some(client) = require_client_cert_from {
        tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(client.cert.pem()));
    }
    let reply = FixedReply(Arc::new(Mutex::new(Some(CryptoBatchResponse {
        items: vec![CryptoItem {
            unit_index: 7,
            data: vec![0x35; 64],
        }],
    }))));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(reply)
            .serve_with_incoming(ListenerStream(listener))
            .await
            .unwrap();
    });
    (address, server.cert.pem().into_bytes())
}

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "tls-test".into(),
            crypto_compatibility_id: "profile".into(),
            supported_plaintext_sizes: vec![64],
            max_ciphertext_size: 64,
            stateless: true,
            retry_safe: true,
            batch: Default::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(2),
        max_message_bytes: 1 << 20,
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "profile".into(),
    }
}

fn plaintext() -> PlaintextUnit {
    PlaintextUnit {
        unit_index: 7,
        data: SecretBuffer::from_slice(&[0x11; 64]),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_and_verified_server_name_succeed() {
    let (address, ca) = tls_server("localhost", None).await;
    let provider = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://localhost:{}", address.port())),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    )
    .unwrap();
    let output = provider
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .unwrap();
    assert_eq!(output[0].data, vec![0x35; 64]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_trust_and_wrong_server_name_are_rejected() {
    let (untrusted_address, _) = tls_server("localhost", None).await;
    let untrusted = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://localhost:{}", untrusted_address.port())),
        GrpcTlsConfig::default(),
    )
    .unwrap();
    assert!(untrusted
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .is_err());

    let (wrong_name_address, ca) = tls_server("wrong.invalid", None).await;
    let wrong_name = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://localhost:{}", wrong_name_address.port())),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    )
    .unwrap();
    assert!(wrong_name
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_rejects_missing_client_identity_and_accepts_configured_identity() {
    let client = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    let (address, ca) = tls_server("localhost", Some(&client)).await;
    let url = format!("https://localhost:{}", address.port());
    let missing = GrpcCryptoProvider::new_with_tls(
        spec(url.clone()),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca.clone()),
            client_identity: None,
        },
    )
    .unwrap();
    assert!(missing
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .is_err());

    let configured = GrpcCryptoProvider::new_with_tls(
        spec(url),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: Some(GrpcClientIdentity {
                certificate_pem: client.cert.pem().into_bytes(),
                private_key_pem: SecretBuffer::from_vec(
                    client.key_pair.serialize_pem().into_bytes(),
                ),
            }),
        },
    )
    .unwrap();
    assert!(configured
        .encrypt_batch(&context(), &[plaintext()])
        .await
        .is_ok());
}

#[test]
fn transport_mode_mismatch_is_rejected_without_downgrade() {
    assert!(GrpcCryptoProvider::new(spec("https://localhost:443".into())).is_err());
    assert!(GrpcCryptoProvider::new_with_tls(
        spec("http://localhost:80".into()),
        GrpcTlsConfig::default(),
    )
    .is_err());
    assert!(GrpcCryptoProvider::new(spec("ftp://localhost:21".into())).is_err());
}

#[tokio::test]
async fn plaintext_endpoints_are_limited_to_loopback() {
    for url in [
        "http://localhost:7000",
        "http://127.0.0.1:7000",
        "http://[::1]:7000",
    ] {
        assert!(
            GrpcCryptoProvider::new(spec(url.into())).is_ok(),
            "loopback plaintext endpoint {url} should remain available for local fixtures"
        );
    }

    for url in [
        "http://crypto.internal:7000",
        "http://192.0.2.1:7000",
        "http://[2001:db8::1]:7000",
    ] {
        assert!(
            GrpcCryptoProvider::new(spec(url.into())).is_err(),
            "non-loopback plaintext endpoint {url} must be rejected"
        );
    }
}
