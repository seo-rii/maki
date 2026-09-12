//! MAKI-015: partial HTTP payload decodes must wipe their output allocation
//! when malformed input is rejected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use std::time::Duration;

use maki_crypto::{BatchCapability, Capability, CryptoCapabilities, CryptoContext};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    append_response_chunk, pointer_set, zeroize_json, BodySpec, FieldSource, HttpCryptoProvider,
    HttpProviderSpec, OpSpec, PayloadEncoding, RespKind, RespSpec, Sensitive,
};

const PAYLOAD_LEN: usize = 257;
const FILL: u8 = 0xa5;
const JSON_FILL: u8 = b'Q';

#[derive(Clone, Copy, Default, Debug)]
struct Inspection {
    enabled: bool,
    allocations: usize,
    deallocations: usize,
    zeroized: usize,
    plaintext_deallocations: usize,
}

thread_local! {
    static INSPECTION: Cell<Inspection> = const { Cell::new(Inspection {
        enabled: false,
        allocations: 0,
        deallocations: 0,
        zeroized: 0,
        plaintext_deallocations: 0,
    }) };
}

struct InspectDecodeAllocation;

fn selected(layout: Layout) -> bool {
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
// allocate and are disabled outside each focused decoder call.
unsafe impl GlobalAlloc for InspectDecodeAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let watching = INSPECTION
            .try_with(|cell| cell.get().enabled && selected(layout))
            .unwrap_or(false);
        if watching {
            unsafe { self.alloc_zeroed(layout) }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && selected(layout) {
            let _ = INSPECTION.try_with(|cell| {
                let mut inspection = cell.get();
                if inspection.enabled {
                    inspection.allocations += 1;
                    cell.set(inspection);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if selected(layout) {
            let _ = INSPECTION.try_with(|cell| {
                let mut inspection = cell.get();
                if inspection.enabled {
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
                    cell.set(inspection);
                }
            });
        }
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

fn finish_inspection() -> Inspection {
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
        "sensitive JSON allocation was freed without zeroization: {inspection:?}"
    );
    assert!(
        inspection.zeroized >= minimum,
        "expected at least {minimum} wiped JSON allocation(s): {inspection:?}"
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

    let mut response = zeroize::Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    response.extend_from_slice(&[FILL; PAYLOAD_LEN]);
    append_response_chunk(&mut response, &[FILL], PAYLOAD_LEN + 1).unwrap();
    drop(response);

    let inspection = finish_inspection();
    assert_eq!(inspection.plaintext_deallocations, 0, "{inspection:?}");
    assert!(inspection.zeroized >= 2, "{inspection:?}");
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

#[tokio::test(flavor = "current_thread")]
async fn per_item_build_error_erases_the_partial_request_tree() {
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
    let items: Vec<(u64, Sensitive)> = vec![(0, Zeroizing::new(vec![0]))];

    begin_inspection();
    let result = provider.run_per_item(&op, &context, &items).await;
    assert!(result.is_err());
    drop(result);
    let inspection = finish_inspection();

    assert_sensitive_allocations_wiped(inspection, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn batch_build_error_erases_all_completed_item_trees() {
    let op = test_op(BodySpec::Json {
        fields: Vec::new(),
        items_path: Some("invalid".to_string()),
        item_fields: vec![("/secret".to_string(), FieldSource::CompatibilityId)],
    });
    let provider = test_provider(&op);
    let context = test_context();
    let items: Vec<(u64, Sensitive)> =
        vec![(0, Zeroizing::new(vec![0])), (1, Zeroizing::new(vec![0]))];

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

    assert_sensitive_allocations_wiped(inspection, 2);
}
