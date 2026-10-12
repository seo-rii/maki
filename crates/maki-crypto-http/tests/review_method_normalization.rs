//! BUG-047: validation permits case-insensitive POST/PUT configuration.

#[path = "common/request_capture.rs"]
mod request_capture;
use request_capture::{exchange, Case};

#[test]
fn validated_encrypt_methods_are_sent_in_canonical_case() {
    for (method, canonical) in [
        ("POST", "POST"),
        ("post", "POST"),
        ("PUT", "PUT"),
        ("pUt", "PUT"),
    ] {
        let observed = exchange(Case {
            base_suffix: "/gateway",
            operation_path: "/encrypt",
            method,
            canonical_method: canonical,
            expected_target: "/gateway/encrypt",
            configured_query: false,
            decrypt: false,
        });
        assert!(
            observed.result.is_ok(),
            "validated {method}: wire={} result={:?}",
            observed.request_line,
            observed.result
        );
        assert_eq!(
            observed.request_line,
            format!("{canonical} /gateway/encrypt HTTP/1.1")
        );
    }
}

#[test]
fn validated_decrypt_methods_are_sent_in_canonical_case() {
    for (method, canonical) in [
        ("POST", "POST"),
        ("post", "POST"),
        ("PUT", "PUT"),
        ("pUt", "PUT"),
    ] {
        let observed = exchange(Case {
            base_suffix: "/gateway",
            operation_path: "/decrypt",
            method,
            canonical_method: canonical,
            expected_target: "/gateway/decrypt",
            configured_query: false,
            decrypt: true,
        });
        assert!(
            observed.result.is_ok(),
            "validated {method}: wire={} result={:?}",
            observed.request_line,
            observed.result
        );
        assert_eq!(
            observed.request_line,
            format!("{canonical} /gateway/decrypt HTTP/1.1")
        );
    }
}
