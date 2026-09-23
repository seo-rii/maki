//! MAKI-015 (partial): protect owned request encodings, including cancellation
//! before connecting. Transport-private scratch is outside this test's scope.

use std::io::Write;
use std::task::{Context, Poll};

use super::decoded_response_tests::{provider, Watch};
use super::*;

const UNIT: usize = 257;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(8),
        format_version: 1,
        crypto_compatibility_id: "request-secrets".into(),
    }
}

fn input() -> Vec<PlaintextUnit> {
    vec![PlaintextUnit {
        unit_index: 17,
        data: SecretBuffer::from_slice(&[0xA5; UNIT]),
    }]
}

fn golden(context: &CryptoContext, items: &[PlaintextUnit]) -> String {
    json!({
        "id": 1,
        "op": "encrypt",
        "profile": context.crypto_compatibility_id,
        "volume": context.volume_uuid.to_string(),
        "format": context.format_version,
        "items": items.iter().map(|item| json!({
            "unit": item.unit_index,
            "data": b64(item.data.expose()),
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

#[test]
fn cancelling_a_request_waiting_for_connection_wipes_its_owned_encodings() {
    let provider = provider();
    let context = context();
    let items = input();
    let frame_len = golden(&context, &items).len();
    // The held mutex makes the real encrypt/request/request_once path stop
    // after encoding and before opening a socket. No runtime or network is
    // involved; the future's cancellation releases its owned encodings.
    let _connection = provider.connection.try_lock().unwrap();
    let mut future = provider.encrypt_batch(&context, &items);
    let watch = Watch::sizes([UNIT.div_ceil(3) * 4, frame_len]);
    assert!(matches!(
        future.as_mut().poll(&mut Context::from_waker(
            futures_util::task::noop_waker_ref()
        )),
        Poll::Pending
    ));
    drop(future);
    let inspection = watch.finish();
    assert!(
        inspection.allocated > 0,
        "no request allocation was observed"
    );
    assert_eq!(inspection.freed, inspection.allocated);
    assert!(
        inspection.all_zero,
        "request cancellation freed encoded plaintext: {inspection:?}"
    );
}

#[test]
fn oversized_request_is_rejected_before_allocating_its_owned_encoding() {
    let mut provider = provider();
    provider.spec.max_frame_bytes = 32;
    let context = context();
    let items = input();
    let frame_len = golden(&context, &items).len();
    let mut future = provider.encrypt_batch(&context, &items);
    let watch = Watch::sizes([UNIT.div_ceil(3) * 4, frame_len]);
    let result = future.as_mut().poll(&mut Context::from_waker(
        futures_util::task::noop_waker_ref(),
    ));
    drop(future);
    let inspection = watch.finish();
    assert!(matches!(
        result,
        Poll::Ready(Err(CryptoError::NonRetryableRequest(ref error)))
            if error.contains("frame limit")
    ));
    assert_eq!(
        inspection.allocated, 0,
        "frame limit must precede encoded-output allocation: {inspection:?}"
    );
}

#[test]
fn direct_encoding_preserves_the_existing_json_wire() {
    let mut context = context();
    for profile in ["request-secrets", "quotes\" slash\\ line\n nul\0 한글"] {
        context.crypto_compatibility_id = profile.into();
        for lengths in [
            vec![],
            vec![0],
            vec![1, 2, 3, UNIT],
            vec![767, 768, 769, 1537, 4096],
        ] {
            let items: Vec<_> = lengths
                .into_iter()
                .enumerate()
                .map(|(index, len)| PlaintextUnit {
                    unit_index: u64::MAX - index as u64,
                    data: SecretBuffer::from_slice(&vec![index as u8; len]),
                })
                .collect();
            let expected = golden(&context, &items);
            let payloads: Vec<_> = items
                .iter()
                .map(|item| (item.unit_index, item.data.expose()))
                .collect();
            let encoded =
                request::encode_request(1, "encrypt", &context, &payloads, expected.len()).unwrap();
            assert_eq!(encoded.expose(), expected.as_bytes());
            assert!(matches!(
                request::encode_request(1, "encrypt", &context, &payloads, expected.len() - 1),
                Err(CryptoError::NonRetryableRequest(_))
            ));
        }
    }
}

#[test]
fn message_clones_retain_the_secret_owner_until_the_last_drop() {
    let context = context();
    let items = input();
    let expected = golden(&context, &items);
    let payloads = [(items[0].unit_index, items[0].data.expose())];
    let watch = Watch::sizes([expected.len(), 0]);
    let encoded =
        request::encode_request(1, "encrypt", &context, &payloads, expected.len()).unwrap();
    let message = request::into_message(encoded).unwrap();
    let clone = message.clone();
    drop(message);
    assert_eq!(clone.to_text().unwrap(), expected);
    drop(clone);
    let inspection = watch.finish();
    assert_eq!(inspection.allocated, 1);
    assert_eq!(inspection.freed, 1);
    assert!(
        inspection.all_zero,
        "last frame owner did not wipe: {inspection:?}"
    );
}

#[test]
fn partial_fixed_buffer_serialization_errors_wipe_the_written_prefix() {
    struct FailAfterSecret;
    impl serde::Serialize for FailAfterSecret {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element("encoded-plaintext-before-injected-error")?;
            Err(serde::ser::Error::custom("injected serialization failure"))
        }
    }

    let encoded = b64(&[0xA5; UNIT]);
    for injected in [false, true] {
        let watch = Watch::sizes([UNIT, 0]);
        let result = if injected {
            request::serialize_fixed(&FailAfterSecret, UNIT)
        } else {
            // The fixed cursor writes a prefix, then refuses to grow.
            request::serialize_fixed(&encoded, UNIT)
        };
        let inspection = watch.finish();
        assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
        assert_eq!(inspection.allocated, 1);
        assert_eq!(inspection.freed, 1);
        assert!(
            inspection.all_zero,
            "partial encoding survived: {inspection:?}"
        );
    }
}

#[test]
fn length_counting_refuses_overflow_and_frame_limit_without_advancing() {
    let mut counter = request::LengthCounter {
        bytes: usize::MAX - 1,
        limit: usize::MAX,
    };
    assert!(counter.write_all(&[1, 2]).is_err());
    assert_eq!(counter.bytes, usize::MAX - 1);
    let mut counter = request::LengthCounter { bytes: 0, limit: 3 };
    counter.write_all(&[1, 2, 3]).unwrap();
    assert!(counter.write_all(&[4]).is_err());
    assert_eq!(counter.bytes, 3);
}

#[test]
fn length_counting_refuses_unaddressable_vec_capacity() {
    let mut counter = request::LengthCounter {
        bytes: isize::MAX as usize,
        limit: usize::MAX,
    };
    assert!(
        counter.write_all(&[1]).is_err(),
        "a permissive frame limit must not admit a capacity Vec cannot represent"
    );
    assert_eq!(counter.bytes, isize::MAX as usize);
}
