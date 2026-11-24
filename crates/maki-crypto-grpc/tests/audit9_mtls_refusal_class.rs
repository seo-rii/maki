//! Round-9 audit (providers-native): a server that refuses the client
//! certificate is a TLS authentication failure, which
//! `docs/configuration.md` ("Provider error signals") classifies as an
//! endpoint failure on all three transports. Under TLS 1.3 the server
//! verifies the client certificate after the client has finished its own
//! handshake, so the alert reaches the gRPC client inside the first call
//! instead of during the connection attempt.
//!
//! The fixture is a rustls server that requires a client certificate, sends
//! its alert and then keeps the socket open (reading and discarding), so the
//! client reads the alert itself; nothing races a reset. The TLS 1.2 case is
//! the control: there the refusal happens inside the client's handshake.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcClientIdentity, GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit9-mtls".into(),
            crypto_compatibility_id: "audit-v1".into(),
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

/// Serve one connection: require a client certificate issued by `client_ca`,
/// and after the handshake fails keep reading for `hold` so the alert is
/// read by the client. Returns the server-side handshake error.
fn refusing_server(
    tls13: bool,
    client_ca: rcgen::CertifiedKey,
    hold: Duration,
) -> (std::net::SocketAddr, Vec<u8>, std::thread::JoinHandle<Option<String>>) {
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
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
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
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    failure = Some(format!("{error:?}"));
                    break;
                }
            }
        }
        // Keep the connection open: the client must read the alert.
        let end = Instant::now() + hold;
        let mut sink = [0u8; 4096];
        while Instant::now() < end {
            match std::io::Read::read(&mut socket, &mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
        failure
    });
    (address, server_pem, handle)
}

async fn refusal_class(tls13: bool, present_foreign_certificate: bool) -> (ErrorClass, String, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_ca = rcgen::generate_simple_self_signed(vec!["audit9-client-ca".into()]).unwrap();
    let (address, server_pem, server) = refusing_server(tls13, client_ca, Duration::from_secs(2));
    let client_identity = present_foreign_certificate.then(|| {
        let foreign = rcgen::generate_simple_self_signed(vec!["audit9-foreign-client".into()]).unwrap();
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
    let error = provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(19),
                format_version: 1,
                crypto_compatibility_id: "audit-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 7,
                data: SecretBuffer::from_slice(&[0x65; 512]),
            }],
        )
        .await
        .unwrap_err();
    let server_error = server
        .join()
        .unwrap()
        .expect("the fixture must refuse the client certificate");
    (error.class(), error.to_string(), server_error)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls12_refused_client_certificate_is_endpoint_fatal_control() {
    for foreign in [false, true] {
        let (class, message, server) = refusal_class(false, foreign).await;
        eprintln!("tls1.2 foreign={foreign}: client {class:?} {message:?}; server {server}");
        assert_eq!(class, ErrorClass::EndpointFatal, "{message}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_missing_client_certificate_is_endpoint_fatal() {
    let (class, message, server) = refusal_class(true, false).await;
    eprintln!("tls1.3 missing: client {class:?} {message:?}; server {server}");
    assert_eq!(class, ErrorClass::EndpointFatal, "{message}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_foreign_client_certificate_is_endpoint_fatal() {
    let (class, message, server) = refusal_class(true, true).await;
    eprintln!("tls1.3 foreign: client {class:?} {message:?}; server {server}");
    assert_eq!(class, ErrorClass::EndpointFatal, "{message}");
}
