//! MAKI-015: partial HTTP payload decodes must wipe their output allocation
//! when malformed input is rejected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use std::time::Duration;
use std::{future::Future, task::Context};

use super::{
    append_response_chunk, pointer_set, zeroize_json, BodySpec, FieldSource, HttpCryptoProvider,
    HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec,
};
use maki_crypto::{BatchCapability, Capability, CryptoCapabilities, CryptoContext, SecretBuffer};
use maki_crypto_local::keysource::MapKeySource;
use serde_json::{json, Value};

const PAYLOAD_LEN: usize = 257;
const FILL: u8 = 0xa5;
const JSON_FILL: u8 = b'Q';

#[derive(Clone, Copy, Default, Debug)]
struct Inspection {
    enabled: bool,
    total_allocations: usize,
    total_deallocations: usize,
    allocations: usize,
    deallocations: usize,
    zeroized: usize,
    plaintext_deallocations: usize,
}

thread_local! {
    static SELECTED_SIZE: Cell<usize> = const { Cell::new(0) };
    static INSPECTION: Cell<Inspection> = const { Cell::new(Inspection {
        enabled: false,
        total_allocations: 0,
        total_deallocations: 0,
        allocations: 0,
        deallocations: 0,
        zeroized: 0,
        plaintext_deallocations: 0,
    }) };
}

struct InspectDecodeAllocation;

fn selected(layout: Layout) -> bool {
    let selected_size = SELECTED_SIZE.try_with(Cell::get).unwrap_or(0);
    if selected_size != 0 {
        return layout.size() == selected_size;
    }
    [
        PAYLOAD_LEN,
        PAYLOAD_LEN + 1,
        PAYLOAD_LEN.next_power_of_two() / 2,
    ]
    .contains(&layout.size())
}

// SAFETY: every operation delegates to System. Selected allocations are
// zero-initialized, so the observer may read their complete live allocation
// immediately before delegating deallocation. The thread-local counters do not
// allocate and are disabled outside each focused encoding or ownership check.
unsafe impl GlobalAlloc for InspectDecodeAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watching = INSPECTION
            .try_with(|cell| cell.get().enabled && selected(layout))
            .unwrap_or(false);
        if watching {
            unsafe { self.alloc_zeroed(layout) }
        } else {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                let _ = INSPECTION.try_with(|cell| {
                    let mut inspection = cell.get();
                    if inspection.enabled {
                        inspection.total_allocations += 1;
                        cell.set(inspection);
                    }
                });
            }
            pointer
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            let _ = INSPECTION.try_with(|cell| {
                let mut inspection = cell.get();
                if inspection.enabled {
                    inspection.total_allocations += 1;
                    inspection.allocations += usize::from(selected(layout));
                    cell.set(inspection);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = INSPECTION.try_with(|cell| {
            let mut inspection = cell.get();
            if inspection.enabled {
                inspection.total_deallocations += 1;
                if selected(layout) {
                    // SAFETY: `pointer` still names the selected live
                    // zero-initialized allocation and `layout.size()` bytes
                    // are readable until System.dealloc below.
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    inspection.deallocations += 1;
                    inspection.zeroized += usize::from(bytes.iter().all(|byte| *byte == 0));
                    inspection.plaintext_deallocations += usize::from(
                        bytes.len() >= 64
                            && (bytes[..64].iter().all(|byte| *byte == FILL)
                                || bytes[..64].iter().all(|byte| *byte == JSON_FILL)),
                    );
                }
                cell.set(inspection);
            }
        });
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectDecodeAllocation = InspectDecodeAllocation;

fn inspect_rejected_decode(encoding: PayloadEncoding, encoded: &str) -> Inspection {
    begin_inspection();
    let result = encoding.decode(encoded);
    assert!(result.is_err(), "malformed payload was accepted");
    drop(result);
    finish_inspection()
}

fn begin_inspection() {
    INSPECTION.with(|cell| {
        let previous = cell.replace(Inspection {
            enabled: true,
            ..Inspection::default()
        });
        assert!(!previous.enabled, "nested decoder allocation inspection");
    });
}

fn begin_inspection_for_size(size: usize) {
    SELECTED_SIZE.with(|cell| cell.set(size));
    begin_inspection();
}

fn finish_inspection() -> Inspection {
    SELECTED_SIZE.with(|cell| cell.set(0));
    INSPECTION.with(|cell| {
        let inspection = cell.get();
        cell.set(Inspection::default());
        inspection
    })
}

fn sensitive_string() -> String {
    String::from_utf8(vec![JSON_FILL; PAYLOAD_LEN]).unwrap()
}

fn assert_sensitive_allocations_wiped(inspection: Inspection, minimum: usize) {
    assert_eq!(
        inspection.plaintext_deallocations, 0,
        "sensitive allocation was freed without zeroization: {inspection:?}"
    );
    assert!(
        inspection.zeroized >= minimum,
        "expected at least {minimum} wiped sensitive allocation(s): {inspection:?}"
    );
}

fn assert_partial_output_wiped(inspection: Inspection) {
    assert!(
        inspection.allocations > 0 && inspection.deallocations > 0,
        "decoder output allocation was not observed: {inspection:?}"
    );
    assert_eq!(
        inspection.plaintext_deallocations, 0,
        "partial plaintext was freed without zeroization: {inspection:?}"
    );
    assert!(
        inspection.zeroized > 0,
        "decoder output was not wiped before deallocation: {inspection:?}"
    );
}

#[test]
fn hex_encoding_keeps_only_its_final_allocation() {
    for encoding in [PayloadEncoding::HexLower, PayloadEncoding::HexUpper] {
        for payload in [&[][..], &[FILL][..], &[FILL; PAYLOAD_LEN][..]] {
            begin_inspection();
            let encoded = encoding.encode(payload);
            let inspection = finish_inspection();

            assert_eq!(
                inspection.total_deallocations, 0,
                "hex encoding freed an intermediate plaintext allocation: {inspection:?}"
            );
            assert_eq!(
                inspection.total_allocations,
                usize::from(!payload.is_empty()),
                "hex encoding allocated storage beyond its final output: {inspection:?}"
            );
            assert_eq!(encoded.len(), payload.len() * 2);
            assert_eq!(encoding.decode(&encoded).unwrap().as_slice(), payload);
        }
    }
}

#[test]
fn hex_encoding_preserves_case_and_all_byte_values() {
    let example = [0x00, 0x0f, 0x10, 0xab, 0xff];
    assert_eq!(PayloadEncoding::HexLower.encode(&example), "000f10abff");
    assert_eq!(PayloadEncoding::HexUpper.encode(&example), "000F10ABFF");

    let all_bytes: Vec<u8> = (0..=255).collect();
    let lower = PayloadEncoding::HexLower.encode(&all_bytes);
    let upper = PayloadEncoding::HexUpper.encode(&all_bytes);
    assert_eq!(lower.to_ascii_uppercase(), upper);
    assert_eq!(
        PayloadEncoding::HexLower.decode(&lower).unwrap().as_slice(),
        all_bytes
    );
    assert_eq!(
        PayloadEncoding::HexUpper.decode(&upper).unwrap().as_slice(),
        all_bytes
    );
}

#[test]
fn malformed_base64_erases_partial_decoded_output() {
    let mut encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [FILL; PAYLOAD_LEN],
    )
    .into_bytes();
    encoded[PAYLOAD_LEN] = b'!';
    let encoded = String::from_utf8(encoded).unwrap();

    let inspection = inspect_rejected_decode(PayloadEncoding::Base64, &encoded);
    assert_partial_output_wiped(inspection);
}

#[test]
fn malformed_hex_erases_partial_decoded_output() {
    let mut encoded = "a5".repeat(PAYLOAD_LEN).into_bytes();
    let invalid = encoded.len() - 2;
    encoded[invalid..].copy_from_slice(b"gg");
    let encoded = String::from_utf8(encoded).unwrap();

    let inspection = inspect_rejected_decode(PayloadEncoding::HexLower, &encoded);
    assert_partial_output_wiped(inspection);
}

#[test]
fn response_growth_erases_the_replaced_plaintext_allocation() {
    begin_inspection();

    let mut response = SecretBuffer::with_capacity(PAYLOAD_LEN).unwrap();
    response
        .try_extend_from_slice(&[FILL; PAYLOAD_LEN])
        .unwrap();
    append_response_chunk(&mut response, &[FILL], PAYLOAD_LEN + 1).unwrap();
    drop(response);

    let inspection = finish_inspection();
    assert_eq!(inspection.plaintext_deallocations, 0, "{inspection:?}");
    assert!(inspection.zeroized >= 2, "{inspection:?}");
}

#[test]
fn owned_response_unique_chunk_reuses_its_allocation() {
    let mut out = SecretBuffer::zeroed(0);
    begin_inspection();
    let source = vec![FILL; PAYLOAD_LEN];
    let address = source.as_ptr();
    super::append_owned_response_chunk(&mut out, source.into(), PAYLOAD_LEN).unwrap();
    let adopted = out.expose().as_ptr();
    let capacity = out.capacity();
    drop(out);
    let inspection = finish_inspection();
    assert_eq!(adopted, address, "unique response chunk was copied");
    assert_eq!(capacity, PAYLOAD_LEN);
    assert_eq!(inspection.allocations, 1, "{inspection:?}");
    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn owned_response_unique_slice_reuses_and_erases_full_backing() {
    let mut out = SecretBuffer::zeroed(0);
    begin_inspection();
    let source = vec![FILL; PAYLOAD_LEN + 1];
    let address = source.as_ptr();
    let chunk = bytes::Bytes::from(source).slice(1..PAYLOAD_LEN);
    super::append_owned_response_chunk(&mut out, chunk, PAYLOAD_LEN + 1).unwrap();
    let adopted = out.expose().as_ptr();
    let capacity = out.capacity();
    assert_eq!(out.expose(), &[FILL; PAYLOAD_LEN - 1]);
    drop(out);
    let inspection = finish_inspection();
    assert_eq!(adopted, address, "unique sliced backing was copied");
    assert_eq!(capacity, PAYLOAD_LEN + 1);
    assert_eq!(inspection.allocations, 1, "{inspection:?}");
    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn owned_response_shared_chunk_preserves_the_surviving_owner() {
    let source = bytes::Bytes::from(vec![FILL; PAYLOAD_LEN]);
    let alias = source.clone();
    let mut out = SecretBuffer::zeroed(0);
    super::append_owned_response_chunk(&mut out, source, PAYLOAD_LEN).unwrap();
    assert_ne!(out.expose().as_ptr(), alias.as_ptr());
    assert_eq!(out.expose(), alias.as_ref());
    drop(out);
    assert_eq!(alias.as_ref(), &[FILL; PAYLOAD_LEN]);
}

#[test]
fn owned_response_rejection_erases_unique_chunk_and_preserves_aggregate() {
    let mut out = SecretBuffer::from_slice(b"kept");
    begin_inspection();
    let chunk = bytes::Bytes::from(vec![FILL; PAYLOAD_LEN]);
    let error = super::append_owned_response_chunk(&mut out, chunk, PAYLOAD_LEN).unwrap_err();
    let inspection = finish_inspection();
    assert!(matches!(
        error,
        maki_crypto::CryptoError::NonRetryableRequest(_)
    ));
    assert_eq!(out.expose(), b"kept");
    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn owned_response_does_not_retain_capacity_above_body_limit() {
    let mut source = bytes::BytesMut::with_capacity(PAYLOAD_LEN);
    source.extend_from_slice(b"ok");
    let mut out = SecretBuffer::zeroed(0);
    super::append_owned_response_chunk(&mut out, source.freeze(), 2).unwrap();
    assert_eq!(out.expose(), b"ok");
    assert!(out.capacity() <= 2);
}

#[test]
fn owned_response_later_chunks_keep_order_through_growth() {
    let mut out = SecretBuffer::zeroed(0);
    for chunk in [b"first".as_slice(), b"second", b"third"] {
        super::append_owned_response_chunk(&mut out, bytes::Bytes::copy_from_slice(chunk), 16)
            .unwrap();
    }
    assert_eq!(out.expose(), b"firstsecondthird");
}

#[test]
fn response_owner_is_page_lock_capable_before_plaintext_is_written() {
    use maki_crypto::secret::{page_lock_failures, set_page_locking};

    set_page_locking(true);
    let before = page_lock_failures();
    let mut response = SecretBuffer::with_capacity(PAYLOAD_LEN).unwrap();
    assert!(response.is_page_locked() || page_lock_failures() > before);
    append_response_chunk(&mut response, &[FILL; PAYLOAD_LEN], PAYLOAD_LEN).unwrap();
    assert_eq!(response.expose(), &[FILL; PAYLOAD_LEN]);
    super::response::check_json_page_locks();
    let before = page_lock_failures();
    let request = super::request::encode_single(&[], &test_context(), 0, 0, &[]).unwrap();
    assert!(request.is_page_locked() || page_lock_failures() > before);
    set_page_locking(false);
}

#[test]
fn zeroize_json_erases_object_key_allocations() {
    begin_inspection();
    let mut root = Value::Object(serde_json::Map::from_iter([(
        sensitive_string(),
        Value::Null,
    )]));
    zeroize_json(&mut root);
    drop(root);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn pointer_error_erases_the_incoming_value() {
    begin_inspection();
    let mut root = json!({});
    let result = pointer_set(
        &mut root,
        "missing-leading-slash",
        Value::String(sensitive_string()),
    );
    assert!(result.is_err());
    drop(result);
    drop(root);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn pointer_overwrite_erases_the_replaced_value() {
    begin_inspection();
    let mut root = Value::Object(serde_json::Map::from_iter([(
        "secret".to_string(),
        Value::String(sensitive_string()),
    )]));
    pointer_set(&mut root, "/secret", Value::Null).unwrap();
    drop(root);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn pointer_descent_erases_a_replaced_intermediate_value() {
    begin_inspection();
    let mut root = Value::Object(serde_json::Map::from_iter([(
        "secret".to_string(),
        Value::String(sensitive_string()),
    )]));
    pointer_set(&mut root, "/secret/child", Value::Null).unwrap();
    drop(root);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

fn test_context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: sensitive_string(),
    }
}

fn test_op(body: BodySpec) -> OpSpec {
    OpSpec {
        method: "POST".to_string(),
        path: "/unused".to_string(),
        headers: Vec::new(),
        query: Vec::new(),
        body,
        response: RespSpec {
            kind: RespKind::Raw,
            data_path: None,
            encoding: PayloadEncoding::Base64,
            items_path: None,
            item_index_path: None,
        },
    }
}

fn test_provider(op: &OpSpec) -> HttpCryptoProvider {
    HttpCryptoProvider {
        client: reqwest::Client::new(),
        spec: HttpProviderSpec {
            base_url: "http://127.0.0.1:1".to_string(),
            encrypt: op.clone(),
            decrypt: op.clone(),
            capabilities: CryptoCapabilities {
                provider_id: "json-wipe-test".to_string(),
                crypto_compatibility_id: "json-wipe-test".to_string(),
                supported_plaintext_sizes: vec![1],
                max_ciphertext_size: 1,
                stateless: true,
                retry_safe: false,
                batch: BatchCapability::default(),
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_millis(1),
            max_response_bytes: 1,
            tls: None,
        },
    }
}

#[test]
fn http_json_malformed_response_erases_completed_strings_and_keys() {
    let secret = sensitive_string();
    let wires = [
        format!(r#"{{"secret":"{secret}","broken":["#),
        format!(r#"{{"{secret}":0,"broken":["#),
        format!(r#"{{"nested":[{{"secret":"{secret}"}},"#),
        // The key is already owned when parsing its value fails.
        format!(r#"{{"{secret}":"#),
    ];
    let mut op = test_op(BodySpec::Raw);
    op.response.kind = RespKind::Json;
    op.response.data_path = Some("/data".into());
    let provider = test_provider(&op);
    for wire in wires {
        let body = SecretBuffer::from_slice(wire.as_bytes());
        begin_inspection();
        let result = provider.parse_single(&op, body);
        let failed = result.is_err();
        drop(result);
        let inspection = finish_inspection();
        assert!(failed, "malformed JSON was accepted");
        assert_sensitive_allocations_wiped(inspection, 1);
    }
}

#[test]
fn http_json_duplicate_values_are_erased_before_replacement() {
    let wire = format!(
        r#"{{"secret":"{}","secret":null,"data":"YQ=="}}"#,
        sensitive_string()
    );
    let mut op = test_op(BodySpec::Raw);
    op.response.kind = RespKind::Json;
    op.response.data_path = Some("/data".into());
    let provider = test_provider(&op);
    let body = SecretBuffer::from_slice(wire.as_bytes());
    begin_inspection();
    let result = provider.parse_single(&op, body).unwrap();
    let inspection = finish_inspection();
    assert_eq!(result.expose(), b"a");
    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn http_json_duplicate_keys_are_erased_before_discarding() {
    let secret = sensitive_string();
    let wire = format!(r#"{{"{secret}":null,"{secret}":false,"data":"YQ=="}}"#);
    let mut op = test_op(BodySpec::Raw);
    op.response.kind = RespKind::Json;
    op.response.data_path = Some("/data".into());
    let provider = test_provider(&op);
    let body = SecretBuffer::from_slice(wire.as_bytes());
    begin_inspection();
    let result = provider.parse_single(&op, body).unwrap();
    let inspection = finish_inspection();
    assert_eq!(result.expose(), b"a");
    assert_sensitive_allocations_wiped(inspection, 2);
}

#[test]
fn http_json_complete_response_erases_strings_on_success_and_contract_errors() {
    let secret = sensitive_string();
    let mut op = test_op(BodySpec::Raw);
    op.response.kind = RespKind::Json;
    op.response.data_path = Some("/data".into());
    let provider = test_provider(&op);
    for data in [r#""YQ==""#, "false", r#""invalid!""#] {
        let wire = format!(r#"{{"{secret}":["{secret}"],"data":{data}}}"#);
        let body = SecretBuffer::from_slice(wire.as_bytes());
        begin_inspection();
        let result = provider.parse_single(&op, body);
        let succeeded = result.is_ok();
        drop(result);
        let inspection = finish_inspection();
        assert_eq!(succeeded, data == r#""YQ==""#);
        assert_sensitive_allocations_wiped(inspection, 2);
    }
}

#[test]
fn http_json_batch_rejection_erases_earlier_decoded_payloads_and_json_strings() {
    let secret = sensitive_string();
    let encoded = PayloadEncoding::HexLower.encode(&[FILL; PAYLOAD_LEN]);
    let wire = format!(
        r#"{{"items":[{{"unit":3,"data":"{encoded}"}},{{"unit":4,"data":false}}],"unknown":"{secret}"}}"#
    );
    let mut op = test_op(BodySpec::Raw);
    op.response.items_path = Some("/items".into());
    op.response.data_path = Some("/data".into());
    op.response.item_index_path = Some("/unit".into());
    op.response.encoding = PayloadEncoding::HexLower;
    let items = [(3, SecretBuffer::zeroed(0)), (4, SecretBuffer::zeroed(0))];
    begin_inspection();
    let value = super::response::parse(wire.as_bytes()).unwrap();
    let result = HttpCryptoProvider::extract_batch(&op, &value, &items);
    let rejected = result.is_err();
    drop(result);
    drop(value);
    let inspection = finish_inspection();
    assert!(rejected);
    // One completed payload plus the unused response string are erased.
    assert_sensitive_allocations_wiped(inspection, 2);
}

fn sensitive_credentials_spec(tls: Option<super::TlsSpec>) -> HttpProviderSpec {
    let op = OpSpec {
        method: "POST".to_string(),
        path: "/unused".to_string(),
        headers: vec![("authorization".to_string(), sensitive_string())],
        query: vec![("api_key".to_string(), sensitive_string())],
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
        base_url: "http://127.0.0.1:1".to_string(),
        encrypt: op.clone(),
        decrypt: op,
        capabilities: CryptoCapabilities {
            provider_id: "credential-wipe-test".to_string(),
            crypto_compatibility_id: "credential-wipe-test".to_string(),
            supported_plaintext_sizes: vec![1],
            max_ciphertext_size: 1,
            stateless: true,
            retry_safe: false,
            batch: BatchCapability::default(),
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        },
        timeout: Duration::from_millis(1),
        max_response_bytes: 1,
        tls,
    }
}

#[test]
fn provider_drop_erases_owned_header_and_query_values() {
    let spec = sensitive_credentials_spec(None);

    begin_inspection();
    let provider = HttpCryptoProvider::new(spec).unwrap();
    drop(provider);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 4);
}

#[test]
fn provider_construction_error_erases_owned_credentials() {
    let spec = sensitive_credentials_spec(Some(super::TlsSpec {
        ca_pem: None,
        // Keep this outside the watched allocation size. reqwest's parser may
        // make transport-owned copies that this crate cannot erase.
        identity_pem: Some(b"invalid client identity".to_vec()),
    }));

    begin_inspection();
    let result = HttpCryptoProvider::new(spec);
    assert!(result.is_err(), "invalid client identity was accepted");
    drop(result);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 4);
}

#[test]
fn tls_spec_drop_erases_identity_pem() {
    let tls = super::TlsSpec {
        ca_pem: None,
        identity_pem: Some(vec![JSON_FILL; PAYLOAD_LEN]),
    };

    begin_inspection();
    drop(tls);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

#[test]
fn config_error_erases_a_resolved_credential_header() {
    let mut config = maki_format::config::parse_config(
        r#"
config_schema_version = 1
[volume]
name = "credential-wipe-test"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "credential-wipe-test"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[[crypto.http.endpoint]]
name = "primary"
url = "https://crypto.internal"
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.encrypt.headers]
Authorization = { source = "credential", name = "token", format = "{}" }
[crypto.http.encrypt.body]
type = "json"
[crypto.http.encrypt.body.fields]
"/data" = { source = "payload", encoding = "base64" }
[crypto.http.decrypt]
method = "POST"
path = "/decrypt"
[backing]
root = "/tmp/unused"
"#,
    )
    .unwrap();
    config
        .crypto
        .http
        .as_mut()
        .unwrap()
        .encrypt
        .as_mut()
        .unwrap()
        .body
        .as_mut()
        .unwrap()
        .fields
        .get_mut("/data")
        .unwrap()
        .source = "invalid-after-credential-resolution".to_string();
    let mut keys = MapKeySource::new();
    keys.insert("token", vec![JSON_FILL; PAYLOAD_LEN]);

    begin_inspection();
    let result = HttpCryptoProvider::from_config(&config, "https://crypto.internal", &keys);
    assert!(result.is_err(), "invalid field source was accepted");
    drop(result);
    let inspection = finish_inspection();

    // The KeySource result and the resolved header allocation must both wipe.
    assert_sensitive_allocations_wiped(inspection, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn per_item_build_error_does_not_copy_borrowed_request_metadata() {
    let op = test_op(BodySpec::Json {
        fields: vec![
            ("/secret".to_string(), FieldSource::CompatibilityId),
            ("invalid".to_string(), FieldSource::UnitIndex),
        ],
        items_path: None,
        item_fields: Vec::new(),
    });
    let provider = test_provider(&op);
    let context = test_context();
    let items = vec![(0, SecretBuffer::from_slice(&[0]))];

    begin_inspection();
    let result = provider.run_per_item(&op, &context, &items).await;
    assert!(result.is_err());
    drop(result);
    let inspection = finish_inspection();

    assert_eq!(inspection.allocations, 0, "{inspection:?}");
    assert!(context
        .crypto_compatibility_id
        .bytes()
        .all(|byte| byte == JSON_FILL));
}

#[tokio::test(flavor = "current_thread")]
async fn batch_build_error_does_not_copy_borrowed_item_metadata() {
    let op = test_op(BodySpec::Json {
        fields: Vec::new(),
        items_path: Some("invalid".to_string()),
        item_fields: vec![("/secret".to_string(), FieldSource::CompatibilityId)],
    });
    let provider = test_provider(&op);
    let context = test_context();
    let items = vec![
        (0, SecretBuffer::from_slice(&[0])),
        (1, SecretBuffer::from_slice(&[0])),
    ];

    begin_inspection();
    let result = provider
        .run_batched(
            &op,
            &context,
            &items,
            "invalid",
            &[],
            &[("/secret".to_string(), FieldSource::CompatibilityId)],
        )
        .await;
    assert!(result.is_err());
    drop(result);
    let inspection = finish_inspection();

    assert_eq!(inspection.allocations, 0, "{inspection:?}");
    assert!(context
        .crypto_compatibility_id
        .bytes()
        .all(|byte| byte == JSON_FILL));
}

#[tokio::test]
async fn http_request_borrows_compatibility_id_without_an_owned_copy() {
    let op = test_op(BodySpec::Json {
        fields: vec![("/profile".into(), FieldSource::CompatibilityId)],
        items_path: None,
        item_fields: Vec::new(),
    });
    let provider = test_provider(&op);
    let context = test_context();
    let items = [(3, SecretBuffer::zeroed(0))];
    let mut operation = std::pin::pin!(provider.run_per_item(&op, &context, &items));
    begin_inspection_for_size(PAYLOAD_LEN);
    let result = operation.as_mut().poll(&mut Context::from_waker(
        futures_util::task::noop_waker_ref(),
    ));
    drop(result);
    let inspection = finish_inspection();
    assert_eq!(
        inspection.allocations, 0,
        "request copied its borrowed compatibility id: {inspection:?}"
    );
}

#[tokio::test]
async fn http_request_streams_payload_encoding_without_an_owned_string() {
    for encoding in [
        PayloadEncoding::Base64,
        PayloadEncoding::Base64Url,
        PayloadEncoding::HexLower,
        PayloadEncoding::HexUpper,
    ] {
        let op = test_op(BodySpec::Json {
            fields: vec![("/data".into(), FieldSource::Payload(encoding))],
            items_path: None,
            item_fields: Vec::new(),
        });
        let provider = test_provider(&op);
        let context = test_context();
        let items = [(3, SecretBuffer::from_slice(&[FILL; PAYLOAD_LEN]))];
        let length = encoding.encode(items[0].1.expose()).len();
        let mut operation = std::pin::pin!(provider.run_per_item(&op, &context, &items));
        begin_inspection_for_size(length);
        let result = operation.as_mut().poll(&mut Context::from_waker(
            futures_util::task::noop_waker_ref(),
        ));
        drop(result);
        let inspection = finish_inspection();
        assert_eq!(
            inspection.allocations, 0,
            "request allocated a reversible encoded payload: {encoding:?} {inspection:?}"
        );
    }
}

#[test]
fn http_request_partial_fixed_serialization_erases_its_output() {
    struct FailAfterSecret;
    impl serde::Serialize for FailAfterSecret {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element("encoded-plaintext-before-injected-error")?;
            Err(serde::ser::Error::custom("injected serialization failure"))
        }
    }

    for mode in 0..3 {
        begin_inspection_for_size(if mode == 1 { 20 } else { PAYLOAD_LEN });
        let result = match mode {
            0 => super::request::serialize_fixed(&FailAfterSecret, PAYLOAD_LEN),
            // A fixed writer must reject both growth and a shorter second
            // serialization pass, erasing anything already written.
            1 => super::request::serialize_fixed(&["first-secret", "second-secret"], 20),
            _ => super::request::serialize_fixed(&"short-secret", PAYLOAD_LEN),
        };
        let inspection = finish_inspection();
        assert!(matches!(
            result,
            Err(maki_crypto::CryptoError::NonRetryableRequest(_))
        ));
        assert_eq!(inspection.allocations, 1, "{inspection:?}");
        assert_eq!(inspection.deallocations, 1, "{inspection:?}");
        assert_eq!(inspection.zeroized, 1, "{inspection:?}");
    }
}

#[tokio::test]
async fn http_request_cancellation_erases_the_guarded_wire_body() {
    let op = test_op(BodySpec::Json {
        fields: vec![(
            "/data".into(),
            FieldSource::Payload(PayloadEncoding::Base64),
        )],
        items_path: None,
        item_fields: Vec::new(),
    });
    let provider = test_provider(&op);
    let context = test_context();
    let items = [(3, SecretBuffer::from_slice(&[FILL; PAYLOAD_LEN]))];
    let wire_len = format!(
        "{{\"data\":\"{}\"}}",
        PayloadEncoding::Base64.encode(items[0].1.expose())
    )
    .len();
    let mut operation = Box::pin(provider.run_per_item(&op, &context, &items));
    begin_inspection_for_size(wire_len);
    let result = operation.as_mut().poll(&mut Context::from_waker(
        futures_util::task::noop_waker_ref(),
    ));
    assert!(
        result.is_pending(),
        "request did not reach its cancellable send"
    );
    drop(operation);
    let inspection = finish_inspection();
    assert_eq!(inspection.allocations, 1, "{inspection:?}");
    assert_eq!(inspection.deallocations, 1, "{inspection:?}");
    assert_eq!(
        inspection.zeroized, 1,
        "cancelled request body was not wiped: {inspection:?}"
    );
}

#[tokio::test]
async fn empty_per_item_request_does_not_evaluate_invalid_mapping() {
    let op = test_op(BodySpec::Json {
        fields: vec![(
            "invalid-pointer".into(),
            FieldSource::Payload(PayloadEncoding::HexLower),
        )],
        items_path: None,
        item_fields: Vec::new(),
    });
    let provider = test_provider(&op);
    assert!(provider
        .run_per_item(&op, &test_context(), &[])
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        provider
            .run_per_item(&op, &test_context(), &[(1, SecretBuffer::zeroed(0))])
            .await,
        Err(maki_crypto::CryptoError::ProviderFatal(_))
    ));
}

#[test]
fn http_request_mapping_errors_and_duplicate_keys_erase_owned_key_storage() {
    let key = sensitive_string();
    let pointer = format!("/{key}");
    let context = test_context();
    for rejected in [false, true] {
        let fields = vec![
            (pointer.clone(), FieldSource::UnitIndex),
            (
                if rejected {
                    "invalid".into()
                } else {
                    pointer.clone()
                },
                FieldSource::BatchIndex,
            ),
        ];
        begin_inspection_for_size(PAYLOAD_LEN);
        let result = super::request::encode_single(&fields, &context, 3, 1, b"payload");
        let failed = result.is_err();
        drop(result);
        let inspection = finish_inspection();
        assert_eq!(failed, rejected);
        assert_eq!(
            inspection.allocations,
            if rejected { 1 } else { 2 },
            "{inspection:?}"
        );
        assert_eq!(
            inspection.deallocations, inspection.allocations,
            "{inspection:?}"
        );
        assert_eq!(
            inspection.zeroized, inspection.allocations,
            "{inspection:?}"
        );
    }
}
