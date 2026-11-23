//! BUG-097: an endpoint configured with its own CA must not depend on the
//! host's trust store. tonic refuses to build a TLS connector when native
//! roots were requested and none load, so on a minimal or distroless host
//! whose OS store is empty every gRPC attach failed although the configured
//! CA alone authenticates the endpoint (HTTP and WebSocket worked there).
//!
//! Without a CA the provider is built on such a host as well: every remote
//! transport also trusts the public roots compiled into the binary, so its
//! roots are never empty, and an endpoint none of them vouches for is
//! refused at the handshake instead (`review_default_trust.rs`).
//!
//! The OS store is emptied for this whole process through rustls-native-
//! certs' `SSL_CERT_FILE`/`SSL_CERT_DIR` overrides, so this test has a binary
//! of its own.

use std::time::Duration;

use maki_crypto::{Capability, CryptoCapabilities};
use maki_crypto_grpc::{GrpcCryptoProvider, GrpcProviderSpec, GrpcTlsConfig};

fn spec() -> GrpcProviderSpec {
    GrpcProviderSpec {
        url: "https://localhost:1".into(),
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: CryptoCapabilities {
            provider_id: "trust-test".into(),
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

#[tokio::test]
async fn an_empty_host_trust_store_does_not_prevent_construction() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = std::env::temp_dir().join(format!("maki-empty-trust-{}", std::process::id()));
    std::fs::create_dir_all(root.join("certs")).unwrap();
    std::fs::write(root.join("empty.pem"), "").unwrap();
    std::env::set_var("SSL_CERT_FILE", root.join("empty.pem"));
    std::env::set_var("SSL_CERT_DIR", root.join("certs"));

    let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .unwrap()
        .cert
        .pem()
        .into_bytes();
    let with_ca = GrpcCryptoProvider::new_with_tls(
        spec(),
        GrpcTlsConfig {
            ca_certificate_pem: Some(ca),
            client_identity: None,
        },
    );
    // No CA and no host roots: the compiled-in public roots remain.
    let without_ca = GrpcCryptoProvider::new_with_tls(
        spec(),
        GrpcTlsConfig {
            ca_certificate_pem: None,
            client_identity: None,
        },
    );
    let _ = std::fs::remove_dir_all(&root);

    assert!(with_ca.is_ok(), "{:?}", with_ca.err());
    assert!(without_ca.is_ok(), "{:?}", without_ca.err());
}
