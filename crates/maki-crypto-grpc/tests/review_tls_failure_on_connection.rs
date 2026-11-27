//! A TLS protocol failure on an established gRPC connection, while a call
//! waits for its response, does not reach the provider as a TLS error.
//!
//! The server writes an application-data record the client cannot decrypt
//! (rustls `DecryptError`) in front of its response. The TLS stream reports
//! the rustls error inside an I/O error, but the HTTP/2 library under tonic
//! keeps only that I/O error's kind and text, and the call fails with an
//! I/O error rebuilt from them: no rustls error is left anywhere in the
//! status tonic makes, and Maki never classifies by text. The call is
//! classified by the status's code, which is retryable, and counts as sent.
//! This is the documented exception of `docs/configuration.md` (provider
//! error signals), the same one as a TLS 1.3 refusal of the client
//! certificate (`review_tls_failure_in_call.rs`); the WebSocket and HTTP
//! transports recognise the same failure as an endpoint failure.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{
    CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcCryptoProvider, GrpcProviderSpec,
    GrpcTlsConfig,
};

const PATH: &str = "/maki.CryptoService/EncryptBatch";

/// An application-data record no traffic key decrypts.
fn undecryptable_record() -> Vec<u8> {
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x40];
    record.extend((0..0x40u8).map(|i| i.wrapping_mul(37)));
    record
}

/// The server's side of a TCP connection. Once `armed` is set, its next
/// write is preceded by an undecryptable record: TLS writes whole records,
/// so the record lands between two of the server's own.
struct Tampered {
    tcp: tokio::net::TcpStream,
    armed: Arc<AtomicBool>,
    record: Vec<u8>,
}

impl tonic::transport::server::Connected for Tampered {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for Tampered {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tampered {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.armed.swap(false, Ordering::SeqCst) {
            this.record = undecryptable_record();
        }
        while !this.record.is_empty() {
            match Pin::new(&mut this.tcp).poll_write(cx, &this.record) {
                Poll::Ready(Ok(written)) => {
                    this.record.drain(..written);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.tcp).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

struct Incoming {
    listener: tokio::net::TcpListener,
    armed: Arc<AtomicBool>,
}

impl tonic::codegen::tokio_stream::Stream for Incoming {
    type Item = std::io::Result<Tampered>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((tcp, _))) => Poll::Ready(Some(Ok(Tampered {
                tcp,
                armed: self.armed.clone(),
                record: Vec::new(),
            }))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// An XOR service that arms the record in front of its first response.
#[derive(Clone)]
struct Xor {
    armed: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl tonic::server::NamedService for Xor {
    const NAME: &'static str = "maki.CryptoService";
}

impl<B> Service<http::Request<B>> for Xor
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.armed.store(true, Ordering::SeqCst);
        }
        Box::pin(async move {
            struct Unary;
            impl tonic::server::UnaryService<CryptoBatchRequest> for Unary {
                type Response = CryptoBatchResponse;
                type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                fn call(&mut self, request: tonic::Request<CryptoBatchRequest>) -> Self::Future {
                    Box::pin(async move {
                        let items = request
                            .into_inner()
                            .items
                            .into_iter()
                            .map(|item| CryptoItem {
                                unit_index: item.unit_index,
                                data: item.data.iter().map(|byte| byte ^ 0x5a).collect(),
                            })
                            .collect();
                        Ok(tonic::Response::new(CryptoBatchResponse { items }))
                    })
                }
            }
            let codec =
                tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
            Ok(tonic::server::Grpc::new(codec).unary(Unary, request).await)
        })
    }
}

struct Server {
    address: std::net::SocketAddr,
    pem: String,
    calls: Arc<AtomicUsize>,
}

/// A TLS gRPC server with a new self-signed certificate for `127.0.0.1`
/// that breaks the TLS session in front of its first response.
async fn server() -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let pem = certificate.cert.pem();
    let tls =
        tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
            certificate.cert.pem(),
            certificate.key_pair.serialize_pem(),
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let service = Xor {
        armed: armed.clone(),
        calls: calls.clone(),
    };
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(service)
            .serve_with_incoming(Incoming { listener, armed })
            .await
            .unwrap();
    });
    Server {
        address,
        pem,
        calls,
    }
}

fn request() -> CryptoBatchRequest {
    CryptoBatchRequest {
        volume_id: uuid::Uuid::from_u128(23).to_string(),
        compatibility_id: "tls-on-connection-v1".into(),
        items: vec![CryptoItem {
            unit_index: 7,
            data: vec![0x65; 512],
        }],
        format_version: 1,
    }
}

/// Every error reachable from `error`: its source chain, the custom error
/// inside an I/O error, and the I/O error an `h2::Error` keeps.
fn reachable<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Vec<&'a (dyn std::error::Error + 'static)> {
    let mut found = vec![error];
    if let Some(inner) = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
    {
        found.extend(reachable(inner));
    }
    if let Some(io) = error
        .downcast_ref::<h2::Error>()
        .and_then(h2::Error::get_io)
    {
        found.extend(reachable(io));
    }
    if let Some(source) = error.source() {
        found.extend(reachable(source));
    }
    found
}

/// The premise, at tonic's level: the call fails with the connection's I/O
/// error, of the kind the TLS stream gives a rustls error, as the HTTP/2
/// library rebuilt it from its kind and text; no rustls error is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_of_a_tls_failure_on_an_established_connection_holds_no_tls_error() {
    let server = server().await;
    let channel = tonic::transport::Endpoint::from_shared(format!(
        "https://127.0.0.1:{}",
        server.address.port()
    ))
    .unwrap()
    .tls_config(
        tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(&server.pem))
            .domain_name("127.0.0.1"),
    )
    .unwrap()
    .connect()
    .await
    .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    let status = grpc
        .unary(
            tonic::Request::new(request()),
            http::uri::PathAndQuery::from_static(PATH),
            tonic::codec::ProstCodec::<CryptoBatchRequest, CryptoBatchResponse>::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(server.calls.load(Ordering::SeqCst), 1, "{status:?}");
    let source = std::error::Error::source(&status).expect("a local status has a source");
    let reachable = reachable(source);
    assert!(
        reachable.iter().all(|error| !error.is::<rustls::Error>()),
        "a rustls error reached the call: {status:?}"
    );
    assert!(
        reachable
            .iter()
            .filter_map(|error| error.downcast_ref::<std::io::Error>())
            .any(|io| io.kind() == std::io::ErrorKind::InvalidData),
        "the call did not fail with the connection's TLS read error: {status:?}"
    );
}

/// What the provider makes of it: the status's code decides, which is
/// retryable, and the request was handed over, so it counts as sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_failure_on_an_established_connection_is_classified_by_its_status() {
    let server = server().await;
    let provider = GrpcCryptoProvider::new_with_tls(
        GrpcProviderSpec {
            url: format!("https://127.0.0.1:{}", server.address.port()),
            encrypt_path: PATH.into(),
            decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
            metadata: vec![],
            capabilities: CryptoCapabilities {
                provider_id: "tls-on-connection".into(),
                crypto_compatibility_id: "tls-on-connection-v1".into(),
                supported_plaintext_sizes: vec![512],
                max_ciphertext_size: 528,
                stateless: true,
                retry_safe: false,
                batch: BatchCapability {
                    supported: true,
                    max_items: 8,
                    max_bytes: 4096,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(5),
            max_message_bytes: 4096,
        },
        GrpcTlsConfig {
            ca_certificate_pem: Some(server.pem.clone().into_bytes()),
            client_identity: None,
        },
    )
    .unwrap();
    let error = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(23),
                format_version: 1,
                crypto_compatibility_id: "tls-on-connection-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x65; 512]),
            }],
        )
        .await
        .unwrap_err();
    assert_eq!(server.calls.load(Ordering::SeqCst), 1, "{error}");
    assert_eq!(error.class(), ErrorClass::Retryable, "{error}");
    assert_eq!(
        error.to_string(),
        "retryable: grpc status Unknown from remote crypto provider"
    );
    assert!(!error.is_not_sent(), "{error:?}");
}
