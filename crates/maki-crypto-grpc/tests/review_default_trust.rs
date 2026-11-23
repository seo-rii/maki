//! The gRPC transport trusts the same roots as the HTTP and WebSocket
//! transports: the host's trust store, the public roots compiled into the
//! binary, and the configured `ca_file`, which adds to them. The compiled-in
//! roots make that set non-empty, so a provider with no `ca_file` is built
//! on a host whose store is empty; an endpoint none of the roots vouches for
//! is refused at the handshake.
//!
//! The host's store is pointed at a test bundle through `SSL_CERT_FILE` and
//! `SSL_CERT_DIR`, which are process-global, so this file is a binary of its
//! own with a single test. The variables are set before the runtime starts;
//! later the bundle file itself is emptied rather than the environment
//! changed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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

/// Answers every RPC with one item for unit 7.
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

/// A CA with a name of its own, so that a server it did not issue fails as
/// an unknown issuer rather than on a same-subject anchor's key.
struct Authority {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn authority(name: &str) -> Authority {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Authority {
        cert: params.self_signed(&key).unwrap(),
        key,
    }
}

impl Authority {
    fn pem(&self) -> Vec<u8> {
        self.cert.pem().into_bytes()
    }
}

/// A TLS gRPC server for `localhost` whose certificate `issuer` signed.
async fn server(issuer: &Authority) -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&key, &issuer.cert, &issuer.key)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = tonic::transport::Identity::from_pem(leaf.pem(), key.serialize_pem());
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
    address
}

fn spec(address: SocketAddr) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url: format!("https://localhost:{}", address.port()),
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "default-trust".into(),
            crypto_compatibility_id: "default-trust-v1".into(),
            supported_plaintext_sizes: vec![UNIT as u32],
            max_ciphertext_size: UNIT as u32,
            stateless: true,
            retry_safe: true,
            batch: Default::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_message_bytes: 1 << 20,
    }
}

/// What the daemon builds for an `https://` endpoint: no `[crypto.grpc.tls]`
/// section is an empty TLS configuration.
fn no_ca_file() -> GrpcTlsConfig {
    GrpcTlsConfig::default()
}

fn ca_file(issuer: &Authority) -> GrpcTlsConfig {
    GrpcTlsConfig {
        ca_certificate_pem: Some(issuer.pem()),
        client_identity: None,
    }
}

async fn encrypt(provider: &GrpcCryptoProvider) -> Result<(), CryptoError> {
    let output = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(0x7e5),
                format_version: 1,
                crypto_compatibility_id: "default-trust-v1".into(),
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

/// Builds a provider and sends one request; records a deviation from
/// `trusted` in `wrong`.
async fn check(
    wrong: &mut Vec<String>,
    case: &str,
    address: SocketAddr,
    tls: GrpcTlsConfig,
    trusted: bool,
) {
    let result = match GrpcCryptoProvider::new_with_tls(spec(address), tls) {
        Ok(provider) => encrypt(&provider).await,
        Err(error) => {
            wrong.push(format!("{case}: provider construction failed: {error:?}"));
            return;
        }
    };
    match (&result, trusted) {
        (Ok(()), true) => {}
        (Err(error), false) if error.class() == ErrorClass::EndpointFatal => {}
        _ => wrong.push(format!(
            "{case}: expected trusted={trusted}, got {result:?}"
        )),
    }
}

fn write_store(path: &Path, issuers: &[&Authority]) {
    let bundle: Vec<u8> = issuers.iter().flat_map(|issuer| issuer.pem()).collect();
    std::fs::write(path, bundle).unwrap();
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_host_store_and_ca_file_add_to_the_compiled_in_roots() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = RemoveOnDrop(
        std::env::temp_dir().join(format!("maki-grpc-default-trust-{}", std::process::id())),
    );
    let store = directory.0.join("host-store.pem");
    let store_dir = directory.0.join("host-store.d");
    std::fs::create_dir_all(&store_dir).unwrap();
    let host = authority("maki host-store test authority");
    let configured = authority("maki ca_file test authority");
    let unrelated = authority("maki untrusted test authority");
    write_store(&store, &[&host]);
    std::env::set_var("SSL_CERT_FILE", &store);
    std::env::set_var("SSL_CERT_DIR", &store_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let wrong = runtime.block_on(async {
        let host_server = server(&host).await;
        let configured_server = server(&configured).await;
        let unrelated_server = server(&unrelated).await;
        let mut wrong = Vec::new();

        // A CA in the host's store authenticates the endpoint with no
        // ca_file and next to a configured CA.
        check(&mut wrong, "host store", host_server, no_ca_file(), true).await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "host store next to ca_file",
            host_server,
            ca,
            true,
        )
        .await;

        // A configured CA adds to the roots.
        let ca = ca_file(&configured);
        check(&mut wrong, "ca_file", configured_server, ca, true).await;

        // A CA that is in neither is refused, with or without ca_file.
        check(
            &mut wrong,
            "untrusted",
            unrelated_server,
            no_ca_file(),
            false,
        )
        .await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "untrusted, ca_file",
            unrelated_server,
            ca,
            false,
        )
        .await;

        // With an empty host store the compiled-in public roots remain, so
        // a provider with no ca_file is still built; the private CA is no
        // longer trusted and ca_file still is.
        write_store(&store, &[]);
        check(
            &mut wrong,
            "empty host store",
            host_server,
            no_ca_file(),
            false,
        )
        .await;
        let ca = ca_file(&configured);
        check(
            &mut wrong,
            "empty host store, ca_file",
            configured_server,
            ca,
            true,
        )
        .await;
        wrong
    });
    assert!(wrong.is_empty(), "{wrong:#?}");
}
