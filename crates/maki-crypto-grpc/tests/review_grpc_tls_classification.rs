//! Additional audit: TLS identity failures must retain endpoint-fatal provenance.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use maki_crypto::{
    BatchCapability, Capability, CryptoCapabilities, CryptoContext, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/maki.CryptoService/EncryptBatch".into(),
        decrypt_path: "/maki.CryptoService/DecryptBatch".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-tls".into(),
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

async fn encrypt_error(provider: &GrpcCryptoProvider) -> maki_crypto::CryptoError {
    provider
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
        .unwrap_err()
}

async fn identity_failure(wrong_hostname: bool) -> maki_crypto::CryptoError {
    let name = if wrong_hostname {
        "different-host.invalid"
    } else {
        "127.0.0.1"
    };
    let certificate = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let ca = if wrong_hostname {
        certificate.cert.pem()
    } else {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["unrelated-ca.invalid".into()]).unwrap();
        // Distinct issuer names ensure this exercises UnknownCA rather than
        // trying the unrelated key of a same-subject trust anchor.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "unrelated audit authority");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while connection.is_handshaking() {
            if let Err(error) = connection.complete_io(&mut socket) {
                return Some(error);
            }
        }
        None
    });
    let provider = GrpcCryptoProvider::new_with_tls(
        spec(format!("https://{address}")),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca.into_bytes()),
            client_identity: None,
        },
    )
    .unwrap();
    let error = encrypt_error(&provider).await;
    let handshake_error = server
        .join()
        .unwrap()
        .expect("the client unexpectedly completed the invalid server's TLS handshake");
    let tls_error = handshake_error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>());
    let expected_alert = if wrong_hostname {
        rustls::AlertDescription::BadCertificate
    } else {
        rustls::AlertDescription::UnknownCA
    };
    assert!(
        matches!(tls_error, Some(rustls::Error::AlertReceived(alert)) if *alert == expected_alert),
        "the TLS fixture must receive {expected_alert:?}, not a socket timeout/reset: \
         {handshake_error:?}"
    );
    error
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_certificate_hostname_is_endpoint_fatal() {
    let error = identity_failure(true).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_certificate_authority_is_endpoint_fatal() {
    let error = identity_failure(false).await;
    assert_eq!(error.class(), ErrorClass::EndpointFatal, "{error:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_before_grpc_handshake_remains_retryable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });
    let provider = GrpcCryptoProvider::new(spec(format!("http://{address}"))).unwrap();
    let error = encrypt_error(&provider).await;
    server.await.unwrap();
    assert_eq!(error.class(), ErrorClass::Retryable, "{error:?}");
}
