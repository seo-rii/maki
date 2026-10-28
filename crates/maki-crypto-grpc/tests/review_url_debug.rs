//! Regression coverage for BUG-174 in the public gRPC specification Debug.
//! These cases construct metadata only, without connecting to any endpoint.

use std::time::Duration;

use maki_crypto::{BatchCapability, Capability, CryptoCapabilities};
use maki_crypto_grpc::GrpcProviderSpec;

const URL_PATH_SECRET: &str = "AUDIT_GRPC_PATH_SECRET_10c5a3d4";
const URL_QUERY_SECRET: &str = "AUDIT_GRPC_QUERY_SECRET_75c004a7";
const METADATA_SECRET: &str = "AUDIT_GRPC_METADATA_SECRET_c938d5bc";

fn spec(url: String) -> GrpcProviderSpec {
    GrpcProviderSpec {
        url,
        encrypt_path: "/audit.Crypto/Encrypt".into(),
        decrypt_path: "/audit.Crypto/Decrypt".into(),
        metadata: vec![("authorization".into(), METADATA_SECRET.into())],
        capabilities: CryptoCapabilities {
            provider_id: "audit-grpc-debug".into(),
            crypto_compatibility_id: "audit-grpc-debug-v1".into(),
            supported_plaintext_sizes: vec![512],
            max_ciphertext_size: 512,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: false,
                max_items: 1,
                max_bytes: 512,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_secs(1),
        max_message_bytes: 4096,
    }
}

#[test]
fn grpc_spec_debug_already_redacts_metadata() {
    let rendered = format!("{:?}", spec("http://127.0.0.1:1".into()));
    assert!(!rendered.contains(METADATA_SECRET));
    assert!(rendered.contains("authorization"));
}

#[test]
fn grpc_spec_debug_redacts_url_tokens() {
    let url = format!("http://127.0.0.1:1/{URL_PATH_SECRET}?token={URL_QUERY_SECRET}");
    maki_format::config::parse_endpoint_url(&url).unwrap();
    let rendered = format!("{:?}", spec(url));
    assert!(
        !rendered.contains(URL_PATH_SECRET) && !rendered.contains(URL_QUERY_SECRET),
        "public specification Debug exposed URL credential markers"
    );
}

#[test]
fn grpc_spec_debug_redacts_all_url_components_and_malformed_urls() {
    let userinfo = "SYNTHETIC_GRPC_USERINFO_SECRET";
    let fragment = "SYNTHETIC_GRPC_FRAGMENT_SECRET";
    let malformed = "SYNTHETIC_GRPC_MALFORMED_SECRET";
    for url in [
        format!("https://user:{userinfo}@localhost/{URL_PATH_SECRET}?token={URL_QUERY_SECRET}#{fragment}"),
        format!("not a URL {malformed}"),
        format!("https://{malformed}@[/invalid?token={URL_QUERY_SECRET}"),
    ] {
        let configuration = spec(url);
        for rendered in [format!("{configuration:?}"), format!("{configuration:#?}")] {
            for marker in [URL_PATH_SECRET, URL_QUERY_SECRET, userinfo, fragment, malformed, METADATA_SECRET] {
                assert!(!rendered.contains(marker), "gRPC Debug exposed a credential component");
            }
        }
    }
}

#[test]
fn grpc_spec_debug_preserves_nonsecret_diagnostics() {
    let rendered = format!("{:?}", spec("http://127.0.0.1:1".into()));
    for field in [
        "GrpcProviderSpec",
        "encrypt_path",
        "metadata",
        "authorization",
        "capabilities",
        "timeout",
        "max_message_bytes",
    ] {
        assert!(
            rendered.contains(field),
            "gRPC Debug lost a diagnostic field"
        );
    }
    assert!(!rendered.contains(METADATA_SECRET));
}

#[tokio::test]
async fn grpc_spec_debug_redacts_supported_method_paths_in_both_formats() {
    let encrypt_marker = "SYNTHETIC_GRPC_ENCRYPT_PATH_SECRET";
    let decrypt_marker = "SYNTHETIC_GRPC_DECRYPT_PATH_SECRET";
    let mut configuration = spec("http://127.0.0.1:1".into());
    configuration.encrypt_path = format!("/audit.Crypto/{encrypt_marker}?token={URL_QUERY_SECRET}");
    configuration.decrypt_path = format!("/audit.Crypto/{decrypt_marker}");
    // Constructor-only validation proves these are accepted method paths;
    // the connection cache does not make any request at construction.
    maki_crypto_grpc::GrpcCryptoProvider::new(configuration.clone()).unwrap();
    for rendered in [format!("{configuration:?}"), format!("{configuration:#?}")] {
        for marker in [encrypt_marker, decrypt_marker, URL_QUERY_SECRET] {
            assert!(
                !rendered.contains(marker),
                "gRPC Debug exposed a method path component"
            );
        }
    }
}
