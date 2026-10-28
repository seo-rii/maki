//! Regression coverage for BUG-174: URL credentials never enter public Debug output.
//! No request is made and all credential markers are synthetic.

use std::time::Duration;

use maki_crypto::{BatchCapability, Capability, CryptoCapabilities};
use maki_crypto_http::{
    BodySpec, HttpCryptoProvider, HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};

const PATH_MARKER: &str = "AUDIT_HTTP_PATH_SECRET_71d42a95";
const QUERY_MARKER: &str = "AUDIT_HTTP_QUERY_SECRET_481d29d9";
const HEADER_MARKER: &str = "AUDIT_HTTP_HEADER_SECRET_2a3de8a8";
const OP_QUERY_MARKER: &str = "AUDIT_HTTP_OP_QUERY_SECRET_31d2cd99";

fn spec(url: String) -> HttpProviderSpec {
    let operation = OpSpec {
        method: "POST".into(),
        path: "/encrypt".into(),
        headers: vec![("authorization".into(), HEADER_MARKER.into())],
        query: vec![("key".into(), OP_QUERY_MARKER.into())],
        body: BodySpec::Raw,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    };
    HttpProviderSpec {
        base_url: url,
        encrypt: operation.clone(),
        decrypt: operation,
        capabilities: CryptoCapabilities {
            provider_id: "audit-http-debug".into(),
            crypto_compatibility_id: "audit-http-debug-v1".into(),
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
        max_response_bytes: 4096,
        tls: None,
    }
}

fn path_url() -> String {
    format!("http://127.0.0.1:1/{PATH_MARKER}/api")
}

fn query_url() -> String {
    format!("http://127.0.0.1:1/api?token={QUERY_MARKER}")
}

#[test]
fn endpoint_validator_accepts_path_and_query_urls() {
    for url in [path_url(), query_url()] {
        maki_format::config::parse_endpoint_url(&url).unwrap();
    }
}

#[test]
fn existing_header_and_operation_query_redaction_still_works() {
    let text = format!("{:?}", spec("http://127.0.0.1:1".into()));
    assert!(!text.contains(HEADER_MARKER));
    assert!(!text.contains(OP_QUERY_MARKER));
    assert!(text.contains("authorization"));
}

#[test]
fn spec_debug_redacts_base_url_path() {
    let text = format!("{:?}", spec(path_url()));
    assert!(
        !text.contains(PATH_MARKER),
        "Debug exposed the URL path marker"
    );
}

#[test]
fn spec_debug_redacts_base_url_query() {
    let text = format!("{:?}", spec(query_url()));
    assert!(
        !text.contains(QUERY_MARKER),
        "Debug exposed the URL query marker"
    );
}

#[tokio::test]
async fn provider_debug_redacts_base_url_path() {
    let provider = HttpCryptoProvider::new(spec(path_url())).unwrap();
    let text = format!("{provider:?}");
    assert!(
        !text.contains(PATH_MARKER),
        "Debug exposed the URL path marker"
    );
}

#[tokio::test]
async fn provider_debug_redacts_base_url_query() {
    let provider = HttpCryptoProvider::new(spec(query_url())).unwrap();
    let text = format!("{provider:?}");
    assert!(
        !text.contains(QUERY_MARKER),
        "Debug exposed the URL query marker"
    );
}

#[test]
fn operation_debug_redacts_url_path() {
    let mut configuration = spec("http://127.0.0.1:1".into());
    configuration.encrypt.path = format!("/{PATH_MARKER}/encrypt");
    let text = format!("{:?}", configuration.encrypt);
    assert!(
        !text.contains(PATH_MARKER),
        "Debug exposed the operation URL path marker"
    );
}

#[test]
fn operation_debug_redacts_url_query() {
    let mut configuration = spec("http://127.0.0.1:1".into());
    configuration.encrypt.path = format!("/encrypt?token={QUERY_MARKER}");
    let text = format!("{:?}", configuration.encrypt);
    assert!(
        !text.contains(QUERY_MARKER),
        "Debug exposed the operation URL query marker"
    );
}

const USERINFO_MARKER: &str = "SYNTHETIC_HTTP_USERINFO_SECRET";
const FRAGMENT_MARKER: &str = "SYNTHETIC_HTTP_FRAGMENT_SECRET";
const MALFORMED_MARKER: &str = "SYNTHETIC_HTTP_MALFORMED_SECRET";

#[test]
fn spec_debug_redacts_complete_urls_even_when_invalid_or_pretty_printed() {
    let urls = [
        format!("https://user:{USERINFO_MARKER}@localhost/{PATH_MARKER}?token={QUERY_MARKER}#{FRAGMENT_MARKER}"),
        format!("not a URL {MALFORMED_MARKER}"),
        format!("https://{MALFORMED_MARKER}@[/invalid?token={QUERY_MARKER}"),
    ];
    for url in urls {
        let configuration = spec(url);
        for rendered in [format!("{configuration:?}"), format!("{configuration:#?}")] {
            for marker in [
                PATH_MARKER,
                QUERY_MARKER,
                USERINFO_MARKER,
                FRAGMENT_MARKER,
                MALFORMED_MARKER,
            ] {
                assert!(
                    !rendered.contains(marker),
                    "spec Debug exposed a URL component"
                );
            }
        }
    }
}

#[tokio::test]
async fn provider_debug_redacts_userinfo_and_fragments_in_both_formats() {
    let url = format!("http://user:{USERINFO_MARKER}@127.0.0.1:1/{PATH_MARKER}?token={QUERY_MARKER}#{FRAGMENT_MARKER}");
    let provider = HttpCryptoProvider::new(spec(url)).unwrap();
    for rendered in [format!("{provider:?}"), format!("{provider:#?}")] {
        for marker in [PATH_MARKER, QUERY_MARKER, USERINFO_MARKER, FRAGMENT_MARKER] {
            assert!(
                !rendered.contains(marker),
                "provider Debug exposed a URL component"
            );
        }
    }
}

#[test]
fn operation_debug_redacts_arbitrary_paths_in_both_formats() {
    for path in [
        format!("/{PATH_MARKER}/encrypt?token={QUERY_MARKER}#{FRAGMENT_MARKER}"),
        format!("malformed operation path {MALFORMED_MARKER}"),
    ] {
        let mut configuration = spec("http://127.0.0.1:1".into());
        configuration.encrypt.path = path;
        for rendered in [
            format!("{:?}", configuration.encrypt),
            format!("{:#?}", configuration.encrypt),
        ] {
            for marker in [PATH_MARKER, QUERY_MARKER, FRAGMENT_MARKER, MALFORMED_MARKER] {
                assert!(
                    !rendered.contains(marker),
                    "operation Debug exposed a path component"
                );
            }
        }
    }
}

#[test]
fn spec_debug_preserves_nonsecret_diagnostics() {
    let rendered = format!("{:?}", spec("http://127.0.0.1:1".into()));
    for field in [
        "HttpProviderSpec",
        "base_url",
        "encrypt",
        "decrypt",
        "POST",
        "authorization",
        "capabilities",
        "timeout",
        "max_response_bytes",
        "tls",
    ] {
        assert!(rendered.contains(field), "Debug lost a diagnostic field");
    }
    assert!(!rendered.contains(HEADER_MARKER));
    assert!(!rendered.contains(OP_QUERY_MARKER));
}
