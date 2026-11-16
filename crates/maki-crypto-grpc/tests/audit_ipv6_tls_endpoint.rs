//! Audit: configuration validation accepts `https://[v6-literal]:port` gRPC
//! endpoints (and WebSocket strips the brackets before TLS verification), but
//! the gRPC provider hands tonic the bracketed host as the TLS server name.
//! rustls cannot parse "[::1]" as a DNS name or an IP address, so the
//! provider cannot be built for any IPv6-literal TLS endpoint.

use std::time::Duration;

use maki_crypto::{Capability, CryptoCapabilities};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};

fn spec(url: &str) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url: url.into(),
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "audit-ipv6".into(),
            crypto_compatibility_id: "audit-ipv6-v1".into(),
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

#[tokio::test]
async fn an_ipv6_literal_https_endpoint_can_be_constructed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = rcgen::generate_simple_self_signed(vec!["::1".into(), "localhost".into()])
        .unwrap()
        .cert
        .pem()
        .into_bytes();
    // The same URL passes the configuration's endpoint parser.
    let url = "https://[::1]:7443";
    maki_format::config::parse_endpoint_url(url).unwrap();

    let control = GrpcCryptoProvider::new_with_tls(
        spec("https://localhost:7443"),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca.clone()),
            client_identity: None,
        },
    );
    assert!(control.is_ok(), "control: {:?}", control.err());

    let ipv6 = GrpcCryptoProvider::new_with_tls(
        spec(url),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    );
    assert!(
        ipv6.is_ok(),
        "a validated IPv6-literal TLS endpoint cannot be built: {:?}",
        ipv6.err()
    );
}
