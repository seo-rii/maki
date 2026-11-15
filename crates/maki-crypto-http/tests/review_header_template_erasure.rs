//! Observe initialized byte owners immediately before deallocation. Moving
//! reallocations expose abandoned credential fragments without reading freed memory.
use maki_crypto::{CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;
use maki_format::config::{parse_config, VolumeConfig};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

#[derive(Clone, Copy, Default, Debug)]
struct Observation {
    enabled: bool,
    selected_releases: usize,
    retained_marker_releases: usize,
}

thread_local! {
    static OBSERVED: Cell<Observation> = const { Cell::new(Observation {
        enabled: false, selected_releases: 0, retained_marker_releases: 0,
    }) };
}

struct Observe;
// SAFETY: all allocations are initialized by System.alloc_zeroed. Only live
// alignment-one byte allocations in the template's capacity range are read,
// before delegation to System.dealloc. Thread-local bookkeeping allocates no
// memory. Default GlobalAlloc::realloc moves via alloc-copy-dealloc, exercising
// the old owner's erasure regardless of the platform allocator's growth policy.
unsafe impl GlobalAlloc for Observe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if layout.align() == 1 && (256..=1024).contains(&layout.size()) {
            let _ = OBSERVED.try_with(|cell| {
                let mut observation = cell.get();
                if observation.enabled {
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    observation.selected_releases += 1;
                    observation.retained_marker_releases += usize::from(
                        bytes
                            .windows(64)
                            .any(|part| part.iter().all(|byte| *byte == b'K')),
                    );
                    cell.set(observation);
                }
            });
        }
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Observe = Observe;

fn config(template: Option<&str>) -> VolumeConfig {
    let format = template
        .map(|value| format!(", format = {}", serde_json::to_string(value).unwrap()))
        .unwrap_or_default();
    let config = parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "header-template"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "header-template-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4096
[[crypto.http.endpoint]]
name = "loopback"
url = "http://127.0.0.1:1"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = {{ source = "credential", name = "token"{format} }}
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "/unused"
"#
    ))
    .unwrap();
    config.validate().unwrap();
    config
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Success,
    InvalidEndpoint,
    InvalidHeader,
}

fn observe(template: Option<&str>, outcome: Outcome) -> Observation {
    let config = config(template);
    let mut keys = MapKeySource::new();
    keys.insert("token", vec![b'K'; 256]);
    OBSERVED.with(|cell| {
        cell.set(Observation {
            enabled: true,
            ..Observation::default()
        })
    });
    // No request is sent: the only credential copies are the key-source owner
    // and the resolved specification. The endpoint error exercises a later
    // constructor failure; the header error exercises the formatting guard.
    let endpoint = match outcome {
        Outcome::InvalidEndpoint => "invalid-endpoint",
        _ => "http://127.0.0.1:1",
    };
    let result = HttpCryptoProvider::from_config(&config, endpoint, &keys);
    let correct_outcome = match (&result, outcome) {
        (Ok(_), Outcome::Success) => true,
        (Err(error), Outcome::InvalidEndpoint) => {
            error.to_string().contains("invalid HTTP endpoint URL")
        }
        (Err(error), Outcome::InvalidHeader) => {
            error.to_string().contains("invalid HTTP header value")
        }
        _ => false,
    };
    drop(result);
    let observation = OBSERVED.with(|cell| cell.replace(Observation::default()));
    assert!(
        correct_outcome,
        "unexpected constructor outcome: {outcome:?}"
    );
    assert!(observation.selected_releases >= 2, "{observation:?}");
    observation
}

#[test]
fn review_header_template_erases_credential_allocations_after_success() {
    for template in [
        None,
        Some("{}"),
        Some("Bearer {}"),
        Some("{}; version=1"),
        Some("{} {}"),
        Some("{}{}"),
    ] {
        let observed = observe(template, Outcome::Success);
        assert_eq!(
            observed.retained_marker_releases, 0,
            "{template:?}: {observed:?}"
        );
    }
}

#[test]
fn review_header_template_erases_credential_allocations_on_later_error() {
    for template in [
        None,
        Some("{}"),
        Some("Bearer {}"),
        Some("{}; version=1"),
        Some("{} {}"),
        Some("{}{}"),
    ] {
        let observed = observe(template, Outcome::InvalidEndpoint);
        assert_eq!(
            observed.retained_marker_releases, 0,
            "{template:?}: {observed:?}"
        );
    }
}

#[test]
fn review_header_template_erases_credential_allocations_on_invalid_header() {
    for template in ["{}\n", "{} {}\r", "prefix:{}\0suffix"] {
        let observed = observe(Some(template), Outcome::InvalidHeader);
        assert_eq!(observed.retained_marker_releases, 0, "{observed:?}");
    }
}

#[tokio::test]
async fn review_header_template_preserves_placeholders_and_credential_trimming() {
    for (template, expected) in [
        (None, "abc"),
        (Some("{}"), "abc"),
        (Some("Bearer {}"), "Bearer abc"),
        (Some("{}; version=1"), "abc; version=1"),
        (Some("{} {}"), "abc abc"),
        (Some("{}{}"), "abcabc"),
        (Some("{{}}"), "{abc}"),
        (Some("fixed"), "fixed"),
        (Some(""), ""),
    ] {
        let server = TestServer::start(Arc::new(|_| ResponseSpec::raw(vec![0x5a; 4096]))).await;
        let mut keys = MapKeySource::new();
        keys.insert("token", b" \t abc \r\n".to_vec());
        let provider =
            HttpCryptoProvider::from_config(&config(template), &server.url(), &keys).unwrap();
        provider
            .encrypt_batch(
                &CryptoContext {
                    volume_uuid: uuid::Uuid::from_u128(1),
                    format_version: 1,
                    crypto_compatibility_id: "header-template-v1".into(),
                },
                &[PlaintextUnit {
                    unit_index: 7,
                    data: SecretBuffer::from_slice(&[0x33; 4096]),
                }],
            )
            .await
            .unwrap();
        let requests = server.requests.lock();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers.get("authorization").map(String::as_str),
            Some(expected)
        );
    }
}
