//! Wire and dynamic mapping compatibility for borrowed HTTP serialization.

use std::io::Write;

use maki_crypto::{CryptoContext, CryptoError, SecretBuffer};
use serde_json::Value;

use super::{pointer_set, request, FieldSource, HttpCryptoProvider, PayloadEncoding, WipedJson};

fn context(profile: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::parse_str("37c891de-8744-4b8e-b9f1-f9d6d485433a").unwrap(),
        format_version: u32::MAX,
        crypto_compatibility_id: profile.into(),
    }
}

fn golden_single(
    fields: &[(String, FieldSource)],
    context: &CryptoContext,
    unit: u64,
    ordinal: usize,
    payload: &[u8],
) -> Result<SecretBuffer, CryptoError> {
    let mut root = WipedJson::new(Value::Object(Default::default()));
    for (pointer, source) in fields {
        pointer_set(
            &mut root.0,
            pointer,
            HttpCryptoProvider::scalar(source, context, unit, ordinal, payload),
        )?;
    }
    HttpCryptoProvider::encode_and_wipe(&mut root.0)
}

fn golden_batch(
    fields: &[(String, FieldSource)],
    items_path: &str,
    item_fields: &[(String, FieldSource)],
    context: &CryptoContext,
    items: &[(u64, SecretBuffer)],
) -> Result<SecretBuffer, CryptoError> {
    let mut root = WipedJson::new(Value::Object(Default::default()));
    for (pointer, source) in fields {
        pointer_set(
            &mut root.0,
            pointer,
            HttpCryptoProvider::scalar(source, context, 0, 0, &[]),
        )?;
    }
    let mut array = WipedJson::new(Value::Array(Vec::with_capacity(items.len())));
    for (ordinal, (unit, payload)) in items.iter().enumerate() {
        let mut element = WipedJson::new(Value::Object(Default::default()));
        for (pointer, source) in item_fields {
            pointer_set(
                &mut element.0,
                pointer,
                HttpCryptoProvider::scalar(source, context, *unit, ordinal, payload.expose()),
            )?;
        }
        array.0.as_array_mut().unwrap().push(element.take());
    }
    pointer_set(&mut root.0, items_path, array.take())?;
    HttpCryptoProvider::encode_and_wipe(&mut root.0)
}

#[test]
fn borrowed_request_preserves_wire_bytes_for_all_payload_encodings() {
    for profile in ["borrowed-http", "quotes\" slash\\ line\n nul\0 한글"] {
        let context = context(profile);
        for encoding in [
            PayloadEncoding::Base64,
            PayloadEncoding::Base64Url,
            PayloadEncoding::HexLower,
            PayloadEncoding::HexUpper,
        ] {
            let fields = vec![
                ("/z/data".into(), FieldSource::Payload(encoding)),
                ("/unit".into(), FieldSource::UnitIndex),
                ("/profile".into(), FieldSource::CompatibilityId),
                ("/volume".into(), FieldSource::VolumeId),
                ("/format".into(), FieldSource::FormatVersion),
                ("/ordinal".into(), FieldSource::BatchIndex),
            ];
            for length in [0, 1, 2, 3, 767, 768, 769, 4096] {
                let payload: Vec<_> = (0..length).map(|index| index as u8).collect();
                let expected =
                    golden_single(&fields, &context, u64::MAX, usize::MAX, &payload).unwrap();
                let encoded =
                    request::encode_single(&fields, &context, u64::MAX, usize::MAX, &payload)
                        .unwrap();
                assert_eq!(encoded.expose(), expected.expose(), "{encoding:?} {length}");
            }
        }
    }
}

#[test]
fn borrowed_request_preserves_decoded_key_order_and_replacement_semantics() {
    let context = context("profile");
    let payload = b"reversible payload";
    let field_sets = [
        vec![
            ("/~".into(), FieldSource::Payload(PayloadEncoding::Base64)),
            ("/~0".into(), FieldSource::UnitIndex),
            ("/Z".into(), FieldSource::UnitIndex),
            ("/~1".into(), FieldSource::CompatibilityId),
            ("/~01".into(), FieldSource::VolumeId),
            ("/a//b".into(), FieldSource::BatchIndex),
            ("/".into(), FieldSource::FormatVersion),
            ("/0".into(), FieldSource::UnitIndex),
            ("/-".into(), FieldSource::BatchIndex),
            ("/한글\"\\\n".into(), FieldSource::CompatibilityId),
            ("/invalid~2escape".into(), FieldSource::VolumeId),
        ],
        vec![
            ("/a".into(), FieldSource::Payload(PayloadEncoding::HexLower)),
            ("/a/b".into(), FieldSource::CompatibilityId),
            ("/a".into(), FieldSource::VolumeId),
            ("/a/c".into(), FieldSource::UnitIndex),
            ("/a/c".into(), FieldSource::FormatVersion),
        ],
        vec![
            ("/a/b".into(), FieldSource::Payload(PayloadEncoding::Base64)),
            ("/a/c".into(), FieldSource::CompatibilityId),
            ("/a".into(), FieldSource::UnitIndex),
        ],
        Vec::new(),
    ];
    for fields in field_sets {
        let expected = golden_single(&fields, &context, 13, 7, payload).unwrap();
        let encoded = request::encode_single(&fields, &context, 13, 7, payload).unwrap();
        assert_eq!(encoded.expose(), expected.expose());
    }
}

#[test]
fn borrowed_batch_preserves_root_collisions_item_order_and_empty_payloads() {
    let context = context("quotes\" 한글");
    let item_fields = vec![
        ("/unit".into(), FieldSource::UnitIndex),
        ("/ordinal".into(), FieldSource::BatchIndex),
        ("/data/overwritten".into(), FieldSource::CompatibilityId),
        (
            "/data".into(),
            FieldSource::Payload(PayloadEncoding::Base64Url),
        ),
    ];
    for (fields, items_path) in [
        (
            vec![
                ("/items/tail".into(), FieldSource::UnitIndex),
                (
                    "/root_data".into(),
                    FieldSource::Payload(PayloadEncoding::HexUpper),
                ),
            ],
            "/items",
        ),
        (
            vec![("/envelope".into(), FieldSource::VolumeId)],
            "/envelope/items",
        ),
        (vec![("/a/b".into(), FieldSource::FormatVersion)], "/a"),
        (vec![("/".into(), FieldSource::CompatibilityId)], "/"),
    ] {
        for lengths in [&[][..], &[0][..], &[1, 2, 3, 769][..]] {
            let items: Vec<_> = lengths
                .iter()
                .enumerate()
                .map(|(index, length)| {
                    (
                        u64::MAX - index as u64,
                        SecretBuffer::from_slice(&vec![index as u8; *length]),
                    )
                })
                .collect();
            let expected =
                golden_batch(&fields, items_path, &item_fields, &context, &items).unwrap();
            let encoded =
                request::encode_batch(&fields, items_path, &item_fields, &context, &items).unwrap();
            assert_eq!(encoded.expose(), expected.expose());
        }
    }
}

#[test]
fn borrowed_batch_preserves_mapping_error_order_for_empty_and_nonempty_items() {
    let context = context("profile");
    let malformed_root = vec![("bad-root".into(), FieldSource::CompatibilityId)];
    let malformed_item = vec![(
        "bad-item".into(),
        FieldSource::Payload(PayloadEncoding::HexLower),
    )];
    let valid = vec![("/field".into(), FieldSource::UnitIndex)];
    let empty = [];
    let one = [(1, SecretBuffer::from_slice(b"payload"))];
    for (fields, path, item_fields, items) in [
        (&malformed_root, "bad-items", &malformed_item, &one[..]),
        (&valid, "bad-items", &malformed_item, &one[..]),
        (&valid, "bad-items", &malformed_item, &empty[..]),
        (&valid, "/items", &malformed_item, &empty[..]),
    ] {
        let expected = golden_batch(fields, path, item_fields, &context, items);
        let encoded = request::encode_batch(fields, path, item_fields, &context, items);
        match (expected, encoded) {
            (Ok(expected), Ok(encoded)) => assert_eq!(encoded.expose(), expected.expose()),
            (Err(expected), Err(encoded)) => {
                assert!(matches!(encoded, CryptoError::ProviderFatal(_)));
                assert_eq!(encoded.to_string(), expected.to_string());
            }
            other => panic!("mapping outcome changed: {other:?}"),
        }
    }
    for pointer in ["", "missing-leading-slash"] {
        let fields = vec![(
            pointer.into(),
            FieldSource::Payload(PayloadEncoding::Base64),
        )];
        let expected = golden_single(&fields, &context, 0, 0, b"payload").unwrap_err();
        let encoded = request::encode_single(&fields, &context, 0, 0, b"payload").unwrap_err();
        assert_eq!(encoded.to_string(), expected.to_string());
    }
}

#[test]
fn http_request_length_counting_rejects_overflow_before_advancing() {
    for initial in [usize::MAX - 1, isize::MAX as usize] {
        let mut counter = request::LengthCounter { bytes: initial };
        assert!(counter.write_all(&[1, 2]).is_err());
        assert_eq!(counter.bytes, initial);
    }
    let mut counter = request::LengthCounter { bytes: 0 };
    counter.write_all(&[1, 2, 3]).unwrap();
    assert_eq!(counter.bytes, 3);
}
