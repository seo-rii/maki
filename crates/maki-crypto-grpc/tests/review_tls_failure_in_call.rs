//! A TLS authentication or protocol failure is an endpoint failure on every
//! transport (`docs/configuration.md`, provider error signals). The gRPC
//! provider recognises one during its own connection attempt, but tonic
//! also dials inside an established channel: when the connection under a
//! cached channel closes, the next call reconnects, and a handshake that
//! fails there reaches the call as a status whose source holds the rustls
//! error. That status is an endpoint failure too, and the channel is retired
//! so the following call reconnects through the provider's own attempt.
//!
//! A status that a peer sends carries no source, so neither its code nor
//! its text can claim a local TLS failure.
//!
//! One case cannot be recognised: under TLS 1.3 a server checks the client
//! certificate after the client has finished its side of the handshake, so
//! its refusal reaches the first call, and the HTTP/2 library keeps only the
//! kind and text of the connection's error (or cancels the call with
//! "connection closed"). That documented exception is pinned below with
//! TLS 1.2, where the refusal happens inside the handshake, as the control.

use std::net::TcpListener;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{
    map_status, CryptoBatchRequest, CryptoBatchResponse, CryptoItem, GrpcClientIdentity,
    GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig,
};
use tonic::codegen::http;
use tonic::codegen::{BoxFuture, Service, StdError};

const TLS_FAILURE: &str = "endpoint fatal: grpc TLS authentication or protocol failure";

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "tls-failure-in-call".into(),
            crypto_compatibility_id: "tls-in-call-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 528,
            stateless: true,
            retry_safe: true,
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
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(19),
        format_version: 1,
        crypto_compatibility_id: "tls-in-call-v1".into(),
    }
}

async fn encrypt(provider: &GrpcCryptoProvider) -> Result<(), CryptoError> {
    provider
        .encrypt_batch(
            &context(),
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x65; 512]),
            }],
        )
        .await
        .map(|_| ())
}

// -------------------------------------------------- a TLS server that serves

#[derive(Clone)]
struct Xor;

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

struct Incoming(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for Incoming {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A TLS gRPC server with a new self-signed certificate for `localhost`;
/// returns its address and certificate.
async fn tls_server() -> (std::net::SocketAddr, String) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = certificate.cert.pem();
    let tls =
        tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
            certificate.cert.pem(),
            certificate.key_pair.serialize_pem(),
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(Xor)
            .serve_with_incoming(Incoming(listener))
            .await
            .unwrap();
    });
    (address, pem)
}

/// The endpoint's certificate is replaced by one the client does not trust
/// while the provider holds a cached channel (a server restarted with
/// another certificate). A proxy sends the first connection to the trusted
/// server and every later one to the other. It can cut a connection it
/// carries: it drops the upstream side, closes its side towards the client
/// and reports when the client has closed its end too, which the client
/// does once its HTTP/2 connection has seen the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_refused_when_a_cached_channel_reconnects_is_an_endpoint_failure() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (trusted, trusted_pem) = tls_server().await;
    let (replaced, _) = tls_server().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    type Cut = (
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    );
    let carried: Arc<Mutex<Vec<Cut>>> = Arc::default();
    let connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let carried = carried.clone();
        let connections = connections.clone();
        async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let first = connections.fetch_add(1, Ordering::SeqCst) == 0;
                let target = if first { trusted } else { replaced };
                let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                let (cut, cut_requested) = tokio::sync::oneshot::channel();
                let (closed, client_closed) = tokio::sync::oneshot::channel();
                carried.lock().unwrap().push((cut, client_closed));
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                        _ = cut_requested => {}
                    }
                    drop(upstream);
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut client).await;
                    let mut sink = [0u8; 4096];
                    while let Ok(1..) = tokio::io::AsyncReadExt::read(&mut client, &mut sink).await
                    {
                    }
                    let _ = closed.send(());
                });
            }
        }
    });
    let provider = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://localhost:{port}")),
        GrpcTlsConfig {
            ca_certificate_pem: Some(trusted_pem.into_bytes()),
            client_identity: None,
        },
    )
    .unwrap();
    encrypt(&provider).await.unwrap();

    // Cut the connection under the cached channel and wait until the
    // client has closed its end, so the next call reconnects inside that
    // channel rather than failing on the dying connection.
    let cuts: Vec<Cut> = carried.lock().unwrap().drain(..).collect();
    for (cut, client_closed) in cuts {
        let _ = cut.send(());
        tokio::time::timeout(Duration::from_secs(10), client_closed)
            .await
            .expect("the client did not close the cut connection")
            .unwrap();
    }

    let refused = encrypt(&provider).await.unwrap_err();
    assert_eq!(refused.class(), ErrorClass::EndpointFatal, "{refused}");
    assert_eq!(refused.to_string(), TLS_FAILURE);
    assert_eq!(connections.load(Ordering::SeqCst), 2);

    // The failure ended that channel: the next call is a new connection
    // attempt of the provider's own, which fails before the request is
    // handed to tonic.
    let next = encrypt(&provider).await.unwrap_err();
    assert_eq!(next.class(), ErrorClass::EndpointFatal, "{next}");
    assert_eq!(next.to_string(), TLS_FAILURE);
    assert!(
        next.is_not_sent(),
        "the call after a TLS failure reused the channel instead of reconnecting: {next:?}"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 3);
}

#[test]
fn a_local_status_whose_source_is_a_tls_error_is_an_endpoint_failure() {
    use tonic::Code;
    let alert = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired),
        )
    };
    // tonic keeps the transport error as the status's source; the rustls
    // error may sit directly there or inside an io::Error.
    let statuses = [
        tonic::Status::from_error(Box::new(alert())),
        tonic::Status::from_error(Box::new(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))),
        {
            let mut status = tonic::Status::new(Code::Unavailable, "connection error");
            status.set_source(Arc::new(alert()));
            status
        },
        {
            let mut status = tonic::Status::new(Code::Cancelled, "stream reset");
            status.set_source(Arc::new(alert()));
            status
        },
    ];
    for status in statuses {
        let error = map_status(&status);
        assert_eq!(error.class(), ErrorClass::EndpointFatal, "{status:?}");
        assert_eq!(error.to_string(), TLS_FAILURE);
    }
}

#[test]
fn a_status_without_a_tls_source_keeps_the_class_of_its_code() {
    use tonic::Code;
    let text = "TLS authentication or protocol failure: received fatal alert: BadCertificate";
    for (code, class) in [
        (Code::Unknown, ErrorClass::Retryable),
        (Code::Unavailable, ErrorClass::Retryable),
        (Code::Cancelled, ErrorClass::Retryable),
        (Code::Internal, ErrorClass::Retryable),
        (Code::InvalidArgument, ErrorClass::NonRetryableRequest),
    ] {
        let error = map_status(&tonic::Status::new(code, text));
        assert_eq!(error.class(), class, "{code:?}");
        // A source that is not a rustls error, with TLS words in its text
        // (as the HTTP/2 library leaves a connection's TLS error), is not one.
        let mut other = tonic::Status::new(code, text);
        other.set_source(Arc::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "received fatal alert: CertificateRequired",
        )));
        assert_eq!(
            map_status(&other).class(),
            class,
            "{code:?} with an I/O source"
        );
    }
}

/// A peer that answers with an error status naming a TLS failure, in its
/// trailers or as an HTTP/2 reset, is classified by what it sent: what
/// arrives over the wire has no local TLS error behind it.
#[tokio::test]
async fn a_status_a_peer_sends_cannot_claim_a_tls_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut calls = 0usize;
        while let Ok((socket, _)) = listener.accept().await {
            let mut connection = h2::server::handshake(socket).await.unwrap();
            while let Some(Ok((_request, mut respond))) = connection.accept().await {
                calls += 1;
                if calls.is_multiple_of(2) {
                    respond.send_reset(h2::Reason::CANCEL);
                    continue;
                }
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "2")
                    .header(
                        "grpc-message",
                        "TLS%20authentication%20or%20protocol%20failure%3A%20bad_certificate",
                    )
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
            }
        }
    });
    let provider = GrpcCryptoProvider::new(spec(url)).unwrap();
    for expected in ["Unknown", "Cancelled"] {
        let error = encrypt(&provider).await.unwrap_err();
        assert_eq!(error.class(), ErrorClass::Retryable, "{error}");
        assert_eq!(
            error.to_string(),
            format!("retryable: grpc status {expected} from remote crypto provider")
        );
    }
}

// ------------------------------- refusal of the client certificate (mTLS)

fn would_block(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Serve one connection that requires a client certificate issued by
/// `client_ca`. After the handshake fails, keep reading for `hold`, so the
/// client reads the alert. Returns the server's handshake error.
fn refusing_server(
    tls13: bool,
    client_ca: rcgen::CertifiedKey,
    hold: Duration,
) -> (
    std::net::SocketAddr,
    Vec<u8>,
    std::thread::JoinHandle<Option<std::io::Error>>,
) {
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let server_pem = certificate.cert.pem().into_bytes();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(client_ca.cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let versions: &[&rustls::SupportedProtocolVersion] = if tls13 {
            &[&rustls::version::TLS13]
        } else {
            &[&rustls::version::TLS12]
        };
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate.cert.der().clone()], key.into())
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut failure = None;
        while connection.is_handshaking() {
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(error) if would_block(&error) => {}
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        let end = Instant::now() + hold;
        let mut sink = [0u8; 4096];
        while Instant::now() < end {
            match std::io::Read::read(&mut socket, &mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if would_block(&error) => {}
                Err(_) => break,
            }
        }
        failure
    });
    (address, server_pem, handle)
}

/// The client's error for a refused client certificate, after checking that
/// the fixture really refused it (and did not just time out).
async fn refusal(tls13: bool, present_foreign_certificate: bool) -> CryptoError {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_ca = rcgen::generate_simple_self_signed(vec!["client-ca".into()]).unwrap();
    let (address, server_pem, server) = refusing_server(tls13, client_ca, Duration::from_secs(2));
    let client_identity = present_foreign_certificate.then(|| {
        let foreign = rcgen::generate_simple_self_signed(vec!["foreign-client".into()]).unwrap();
        GrpcClientIdentity {
            certificate_pem: foreign.cert.pem().into_bytes(),
            private_key_pem: SecretBuffer::from_vec(foreign.key_pair.serialize_pem().into_bytes()),
        }
    });
    let provider = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://{address}")),
        GrpcTlsConfig {
            ca_certificate_pem: Some(server_pem),
            client_identity,
        },
    )
    .unwrap();
    let error = encrypt(&provider).await.unwrap_err();
    let refused = server
        .join()
        .unwrap()
        .expect("the fixture must refuse the client certificate");
    assert!(
        refused
            .get_ref()
            .is_some_and(|source| source.is::<rustls::Error>()),
        "the fixture's handshake must fail in rustls, not on the socket: {refused:?}"
    );
    error
}

/// The documented exception: what the HTTP/2 library hands the call after a
/// TLS 1.3 refusal carries no TLS error, so the status's code decides.
fn assert_tls13_refusal(error: &CryptoError) {
    assert_eq!(error.class(), ErrorClass::Retryable, "{error}");
    assert!(
        ["Unknown", "Cancelled", "Unavailable"].iter().any(|code| {
            error.to_string()
                == format!("retryable: grpc status {code} from remote crypto provider")
        }),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls13_refusal_of_a_missing_client_certificate_reaches_the_call_as_its_status() {
    assert_tls13_refusal(&refusal(true, false).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls13_refusal_of_an_untrusted_client_certificate_reaches_the_call_as_its_status() {
    assert_tls13_refusal(&refusal(true, true).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls12_refusal_inside_the_handshake_is_an_endpoint_failure() {
    for foreign in [false, true] {
        let error = refusal(false, foreign).await;
        assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error}");
        assert_eq!(error.to_string(), TLS_FAILURE);
        assert!(error.is_not_sent(), "{error:?}");
    }
}
