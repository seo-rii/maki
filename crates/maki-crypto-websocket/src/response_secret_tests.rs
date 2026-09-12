use super::decoded_response_tests::Watch;
use super::*;

const SECRET_LEN: usize = 347;

#[test]
fn response_value_strings_are_wiped_when_the_response_is_dropped() {
    let secret = "Q".repeat(SECRET_LEN);
    let wire = json!({"id": 1, "error": {"class": "bad-request", "message": secret}}).to_string();
    let value = response::parse(&wire).unwrap();
    let bytes = value
        .get("error")
        .unwrap()
        .get("message")
        .unwrap()
        .as_str()
        .unwrap()
        .as_bytes();
    let watch = Watch::initialized(bytes);
    drop(value);
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(
        inspection.all_zero,
        "response string survived: {inspection:?}"
    );
}

#[test]
fn malformed_json_wipes_strings_and_keys_created_before_the_error() {
    let secret = "Q".repeat(SECRET_LEN);
    let wires = [
        format!("{{\"first\":\"{secret}\",\"broken\":"),
        format!("{{\"{secret}\":0,\"broken\":"),
    ];
    for wire in wires {
        let watch = Watch::plain_sizes([SECRET_LEN, 0]);
        let result = response::parse(&wire);
        let inspection = watch.finish();
        assert!(result.is_err());
        assert_eq!(inspection.allocated, 1);
        assert_eq!(inspection.freed, 1);
        assert!(inspection.all_zero, "partial JSON survived: {inspection:?}");
    }
}

#[test]
fn provider_owned_incoming_frame_is_wiped_on_drop() {
    let text = tokio_tungstenite::tungstenite::Utf8Bytes::from("Q".repeat(SECRET_LEN));
    let frame = response::own_message(Message::Text(text)).unwrap();
    let watch = Watch::initialized(frame.expose());
    drop(frame);
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(
        inspection.all_zero,
        "incoming frame survived: {inspection:?}"
    );
}

#[test]
fn invalid_utf8_payload_is_wiped_before_it_is_discarded() {
    let bytes = tokio_tungstenite::tungstenite::Bytes::from(vec![0xff; SECRET_LEN]);
    let watch = Watch::initialized(&bytes);
    assert!(response::own_message(Message::Binary(bytes)).is_none());
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(
        inspection.all_zero,
        "invalid UTF-8 payload survived: {inspection:?}"
    );
}

#[test]
fn unique_payload_is_adopted_without_a_copy() {
    let bytes = tokio_tungstenite::tungstenite::Bytes::from(vec![b'Q'; SECRET_LEN]);
    let address = bytes.as_ptr();
    let frame = response::own_message(Message::Binary(bytes)).unwrap();
    assert_eq!(frame.expose().as_ptr(), address);
}

#[test]
fn shared_payload_is_copied_and_only_the_owned_copy_is_wiped() {
    let source = tokio_tungstenite::tungstenite::Bytes::from(vec![b'Q'; SECRET_LEN]);
    let frame = response::own_message(Message::Binary(source.clone())).unwrap();
    assert_ne!(frame.expose().as_ptr(), source.as_ptr());
    assert_eq!(frame.expose(), source.as_ref());
    let watch = Watch::initialized(frame.expose());
    drop(frame);
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(inspection.all_zero);
    assert!(source.iter().all(|byte| *byte == b'Q'));
}

#[test]
fn all_message_payload_kinds_preserve_text_conversion_behavior() {
    use tokio_tungstenite::tungstenite::{protocol::CloseFrame, Bytes};
    let wire = r#"{"id":7}"#;
    for message in [
        Message::Text(wire.into()),
        Message::Binary(Bytes::copy_from_slice(wire.as_bytes())),
        Message::Ping(Bytes::copy_from_slice(wire.as_bytes())),
        Message::Pong(Bytes::copy_from_slice(wire.as_bytes())),
        Message::Close(Some(CloseFrame {
            code: 1000.into(),
            reason: wire.into(),
        })),
        Message::Close(None),
    ] {
        let expected = message.clone().into_text().unwrap();
        let frame = response::own_message(message).unwrap();
        assert_eq!(frame.expose(), expected.as_bytes());
    }
    for message in [
        Message::Ping(vec![0xff].into()),
        Message::Pong(vec![0xff].into()),
    ] {
        assert!(response::own_message(message).is_none());
    }
}

#[test]
fn owned_string_deserializer_transfers_the_original_allocation() {
    use serde::Deserialize;
    let string = "Q".repeat(SECRET_LEN);
    let address = string.as_ptr();
    let deserializer = serde::de::value::StringDeserializer::<serde::de::value::Error>::new(string);
    let value = response::Value::deserialize(deserializer).unwrap();
    assert_eq!(value.as_str().unwrap().as_ptr(), address);
    let watch = Watch::initialized(value.as_str().unwrap().as_bytes());
    drop(value);
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(inspection.all_zero);
}

#[test]
fn cancelled_response_receiver_wipes_the_rejected_tree() {
    let wire = json!({"id": 1, "unknown": ["Q".repeat(SECRET_LEN)]}).to_string();
    let value = response::parse(&wire).unwrap();
    let string = value.get("unknown").unwrap().as_array().unwrap()[0]
        .as_str()
        .unwrap();
    let watch = Watch::initialized(string.as_bytes());
    let (tx, rx) = oneshot::channel();
    drop(rx);
    drop(tx.send(value));
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(inspection.all_zero);
}

#[test]
fn escaped_strings_keys_and_duplicate_values_keep_their_wire_meaning() {
    let value = response::parse(
        r#"{
        "i\u0064": 1, "id": 2,
        "items": [], "it\u0065ms": [{"unit": 3, "data": "Y\u0051=="}],
        "unknown": {"\u0073ecret-key": [null, true, -1, 1.25, "secret\nvalue"]}
    }"#,
    )
    .unwrap();
    assert_eq!(value.get("id").unwrap().as_u64(), Some(2));
    assert_eq!(
        value
            .get("unknown")
            .unwrap()
            .get("secret-key")
            .unwrap()
            .as_array()
            .unwrap()[4]
            .as_str(),
        Some("secret\nvalue")
    );
    let output = decoded_response_tests::provider()
        .parse_response(&value, &[(3, &[])])
        .unwrap();
    assert_eq!(output[0].expose(), b"a");
    assert_eq!(format!("{value:?}"), "ResponseValue(redacted)");
}

#[test]
fn probe_envelope_shape_matches_the_previous_derived_parser() {
    // These fixtures reproduce the previous strict parser solely as a
    // differential oracle; production no longer builds its String fields or
    // errors containing Unexpected::Str when a field has the wrong type.
    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(rename = "id")]
        _id: u64,
        #[serde(rename = "error")]
        _error: ErrorFields,
    }
    #[derive(serde::Deserialize)]
    struct ErrorFields {
        #[serde(rename = "class")]
        _class: String,
        #[serde(rename = "reason")]
        _reason: String,
    }
    let fields = r#"{"class":"integrity","reason":"auth-tag-mismatch"}"#;
    let mut wires = vec![
        format!(r#"{{"id":1,"error":{fields}}}"#),
        format!(r#"{{"id":"secret","id":1,"error":{fields}}}"#),
        format!(r#"{{"id":1,"error":"secret","error":{fields}}}"#),
        format!(r#"{{"id":1,"error":{fields},"error":{fields}}}"#),
        format!(r#"{{"id":1,"i\u0064":1,"error":{fields}}}"#),
        format!(r#"{{"id":1,"error":{fields},"unknown":"secret","unknown":{{"nested":[null,true]}}}}"#),
        format!(r#"{{"id":1,"error":{fields},"class":0,"class":1}}"#),
        r#"{"id":1,"error":{"class":"secret","class":"integrity","reason":"auth-tag-mismatch"}}"#.into(),
        r#"{"id":1,"error":{"class":false,"class":"integrity","reason":"auth-tag-mismatch"}}"#.into(),
        r#"{"id":1,"error":{"class":"integrity","reason":"secret","reason":"auth-tag-mismatch"}}"#.into(),
        r#"{"id":1,"error":{"cl\u0061ss":"integrity","re\u0061son":"auth-tag-mismatch"}}"#.into(),
        r#"{"id":1,"error":{"class":"integrity","reason":"auth-tag-mismatch","id":0,"id":1,"unknown":0,"unknown":1}}"#.into(),
        r#"{"id":1,"error":{"class":"integrity"}}"#.into(),
        r#"{"id":1,"error":{"reason":"auth-tag-mismatch"}}"#.into(),
        r#"{"id":1,"error":{"class":"integrity","reason":false}}"#.into(),
        r#"{"id":1,"error":null}"#.into(),
        r#"{"id":1}"#.into(),
        format!(r#"{{"error":{fields}}}"#),
    ];
    for id in [
        "0",
        "-0",
        "-1",
        "1.0",
        "1e0",
        "18446744073709551615",
        "18446744073709551616",
        "null",
        "true",
        r#""secret""#,
    ] {
        wires.push(format!(r#"{{"id":{id},"error":{fields}}}"#));
    }
    for wire in wires {
        let old = serde_json::from_str::<Envelope>(&wire).is_ok();
        let value = response::parse(&wire).unwrap();
        assert_eq!(value.valid_probe_envelope(), old, "shape: {wire}");
    }
}

#[test]
fn guarded_json_keeps_the_default_recursion_and_syntax_limits() {
    for wire in [
        format!("{}0{}", "[".repeat(130), "]".repeat(130)),
        r#"{"secret":"value"} trailing"#.into(),
        r#"{"secret":"\uD800"}"#.into(),
        "1e10000".into(),
    ] {
        assert!(serde_json::from_str::<serde_json::Value>(&wire).is_err());
        assert!(response::parse(&wire).is_err());
    }
}

#[test]
fn adopting_a_unique_slice_wipes_its_original_initialized_capacity() {
    let bytes = tokio_tungstenite::tungstenite::Bytes::from(vec![b'Q'; SECRET_LEN]);
    let address = bytes.as_ptr();
    // Register the original initialized allocation, including the prefix and
    // suffix that will be outside the subsequently exposed slice.
    let watch = Watch::initialized(&bytes);
    let slice = bytes.slice(23..SECRET_LEN - 29);
    drop(bytes);
    let frame = response::own_message(Message::Binary(slice)).unwrap();
    assert_eq!(frame.expose().as_ptr(), address);
    assert_eq!(frame.expose().len(), SECRET_LEN - 23 - 29);
    assert!(frame.expose().iter().all(|byte| *byte == b'Q'));
    drop(frame);
    let inspection = watch.finish();
    assert_eq!(inspection.freed, 1);
    assert!(
        inspection.all_zero,
        "sliced source capacity survived: {inspection:?}"
    );
}

#[test]
fn replacing_a_duplicate_field_wipes_its_previous_string() {
    let wire = format!(r#"{{"data":"{}","data":false}}"#, "Q".repeat(SECRET_LEN));
    let watch = Watch::plain_sizes([SECRET_LEN, 0]);
    let value = response::parse(&wire).unwrap();
    let inspection = watch.finish();
    assert!(value.get("data").unwrap().as_str().is_none());
    assert_eq!(inspection.allocated, 1);
    assert_eq!(inspection.freed, 1);
    assert!(inspection.all_zero);
}
