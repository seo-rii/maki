//! A TLS protocol failure on an established HTTPS connection is an endpoint
//! failure (`docs/configuration.md`, provider error signals), as on the
//! WebSocket transport (`maki-crypto-websocket`'s test of the same name).
//!
//! After the handshake and the request, the server breaks the TLS session
//! instead of answering: it writes an application-data record the client
//! cannot decrypt (rustls `DecryptError`), or it reads one itself, and its
//! TLS library answers with a fatal alert. The HTTP/1.1 client keeps the
//! rustls error under its I/O error. The request was written, so the
//! failure counts as sent.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
    ErrorClass, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
    TlsSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

const TLS_FAILURE: &str = "endpoint fatal: TLS authentication or protocol failure";

/// An application-data record no traffic key decrypts.
fn undecryptable_record() -> Vec<u8> {
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x40];
    record.extend((0..0x40u8).map(|i| i.wrapping_mul(37)));
    record
}

/// The error of a request to a server that breaks the TLS session once it
/// has read the request: with an undecryptable record, or (`alert`) with
/// the fatal alert its own TLS library sends after reading one.
async fn error_after_the_request(alert: bool) -> CryptoError {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_pem = certified.cert.pem().into_bytes();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        // Read the request head and its 512-byte body.
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = tls.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            seen.extend_from_slice(&buffer[..n]);
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                if seen.len() >= end + 4 + 512 {
                    break;
                }
            }
        }
        let (tcp, session) = tls.get_mut();
        let bytes = if alert {
            session
                .read_tls(&mut undecryptable_record().as_slice())
                .unwrap();
            let refused = session.process_new_packets().unwrap_err();
            assert_eq!(refused, rustls::Error::DecryptError);
            let mut alert = Vec::new();
            while session.wants_write() {
                session.write_tls(&mut alert).unwrap();
            }
            alert
        } else {
            undecryptable_record()
        };
        tcp.write_all(&bytes).await.unwrap();
        tcp.flush().await.unwrap();
        // Keep the connection open: the client reads what it was sent
        // rather than a reset.
        std::future::pending::<()>().await;
    });
    let op = OpSpec {
        method: "POST".into(),
        path: "/crypt".into(),
        headers: vec![],
        query: vec![],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    let provider = HttpCryptoProvider::new(HttpProviderSpec {
        base_url: format!("https://127.0.0.1:{}", address.port()),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "https-tls-failure".into(),
            crypto_compatibility_id: "https-tls-failure-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 512,
            stateless: true,
            retry_safe: false,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(5),
        max_response_bytes: 4096,
        tls: Some(TlsSpec {
            ca_pem: Some(cert_pem),
            identity_pem: None,
        }),
    })
    .unwrap();
    provider
        .encrypt_batch(
            &CryptoContext {
                volume_uuid: uuid::Uuid::from_u128(11),
                format_version: 1,
                crypto_compatibility_id: "https-tls-failure-v1".into(),
            },
            &[PlaintextUnit {
                unit_index: 3,
                data: SecretBuffer::from_slice(&[0x31; 512]),
            }],
        )
        .await
        .unwrap_err()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecryptable_record_on_an_established_connection_is_an_endpoint_failure() {
    let error = error_after_the_request(false).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error}");
    assert_eq!(error.to_string(), TLS_FAILURE);
    assert!(!error.is_not_sent(), "the request was written: {error:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fatal_alert_on_an_established_connection_is_an_endpoint_failure() {
    let error = error_after_the_request(true).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error}");
    assert_eq!(error.to_string(), TLS_FAILURE);
    assert!(!error.is_not_sent(), "the request was written: {error:?}");
}
