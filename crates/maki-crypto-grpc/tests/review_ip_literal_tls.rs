//! Configuration validation accepts `https://[v6-literal]:port` gRPC
//! endpoints, but the provider left the TLS server name to tonic, which hands
//! rustls the bracketed URI host ("[::1]"). That is neither a DNS name nor an
//! IP address, so no IPv6-literal TLS endpoint could be built. A literal must
//! be verified as an IP-address server name, against the certificate's IP
//! SANs, exactly as an IPv4 literal already is.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use maki_crypto::{
    Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
    GrpcTlsConfig,
};
use tonic::codegen::{http, BoxFuture, Service};

const UNIT: usize = 64;

/// Answers every RPC with one item echoing unit 7.
#[derive(Clone)]
struct Echo;

impl tonic::server::NamedService for Echo {
    const NAME: &'static str = "crypto";
}

impl tonic::server::UnaryService<CryptoBatchRequest> for Echo {
    type Response = CryptoBatchResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<CryptoBatchRequest>) -> Self::Future {
        Box::pin(async {
            Ok(tonic::Response::new(CryptoBatchResponse {
                items: vec![CryptoItem {
                    unit_index: 7,
                    data: vec![0x35; UNIT],
                }],
            }))
        })
    }
}

impl<B> Service<http::Request<B>> for Echo
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
        Box::pin(async move {
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec).unary(Echo, request).await)
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

/// A TLS gRPC server on `bind` whose self-signed certificate (also the CA)
/// lists `names` as SANs; rcgen makes an IP SAN of every IP literal. `None`
/// when the host cannot bind that address family.
async fn tls_server(bind: &str, names: &[&str]) -> Option<(SocketAddr, Vec<u8>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind(bind).await.ok()?;
    let address = listener.local_addr().unwrap();
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let server = rcgen::generate_simple_self_signed(names).unwrap();
    let identity =
        tonic::transport::Identity::from_pem(server.cert.pem(), server.key_pair.serialize_pem());
    let tls = tonic::transport::ServerTlsConfig::new().identity(identity);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(Echo)
            .serve_with_incoming(ListenerStream(listener))
            .await
            .unwrap();
    });
    Some((address, server.cert.pem().into_bytes()))
}

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "ip-literal-tls".into(),
            crypto_compatibility_id: "ip-literal-tls-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
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

fn provider(url: String, ca: Vec<u8>) -> Result<GrpcCryptoProvider, CryptoError> {
    GrpcCryptoProvider::new_with_tls(
        spec(url),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    )
}

async fn encrypt(provider: &GrpcCryptoProvider) -> Result<(), CryptoError> {
    let output = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(0x1b6),
                format_version: 1,
                crypto_compatibility_id: "ip-literal-tls-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x11; UNIT]),
            }],
        )
        .await?;
    assert_eq!(output[0].data, vec![0x35; UNIT]);
    Ok(())
}

/// Serves `literal` with a certificate for itself, for another address and
/// for `localhost` only; only the first may be accepted.
async fn verify_literal(bind: &str, literal: &str, other: &str) -> Option<Vec<String>> {
    let mut wrong = Vec::new();
    for (names, accepted) in [
        (vec![literal], true),
        (vec![other], false),
        (vec!["localhost"], false),
    ] {
        let (address, ca) = tls_server(bind, &names).await?;
        let url = format!("https://{address}");
        let result = match provider(url.clone(), ca) {
            Ok(provider) => encrypt(&provider).await,
            Err(error) => Err(error),
        };
        match (&result, accepted) {
            (Ok(()), true) => {}
            (Err(error), false) if error.class() == ErrorClass::EndpointFatal => {}
            _ => wrong.push(format!("{url} with SANs {names:?}: {result:?}")),
        }
    }
    Some(wrong)
}

#[test]
fn ipv6_literal_https_endpoints_can_be_built() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = rcgen::generate_simple_self_signed(vec!["::1".into()])
        .unwrap()
        .cert
        .pem()
        .into_bytes();
    let mut wrong = Vec::new();
    for url in [
        // Controls: a DNS name and an IPv4 literal.
        "https://localhost:7443",
        "https://127.0.0.1:7443",
        "https://[::1]:7443",
        "https://[2001:db8::10]:7443",
        "https://[::ffff:192.0.2.10]:7443",
        "https://[2001:db8::10]",
    ] {
        // Every URL passes the configuration's endpoint check.
        maki_format::config::parse_endpoint_url(url).unwrap();
        if let Err(error) = provider(url.into(), ca.clone()) {
            wrong.push(format!("{url}: {error:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "validated TLS endpoints could not be built:\n{}",
        wrong.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv4_literal_is_verified_against_the_certificate_ip_address() {
    let wrong = verify_literal("127.0.0.1:0", "127.0.0.1", "127.0.0.2")
        .await
        .expect("IPv4 loopback is available");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv6_literal_is_verified_against_the_certificate_ip_address() {
    let Some(wrong) = verify_literal("[::1]:0", "::1", "::2").await else {
        eprintln!("skipped: this host cannot bind the IPv6 loopback address");
        return;
    };
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
