//! The fuzz harness's way into the HTTP provider's reading of a response
//! (`fuzz/harness`, target `http_response`). Built only with the `fuzzing`
//! feature, which only the harness enables: nothing here is part of the
//! provider.
//!
//! An input is one response. Its first byte selects how it is read (modulo
//! [`READERS`]): a JSON mapping of a single item or of a batch, a raw body,
//! or the status line and headers. The second byte is the reader's
//! parameter: the unit a single item answers, the number of items a batch
//! asked for (1 to 4, units 40 upwards), or a raw body's direction and
//! plaintext length. For a status, the next two bytes are the code and the
//! rest are header lines (`name:value`). Otherwise the rest is the body,
//! delivered in three chunks through the provider's bounded accumulation
//! (the second one shared, as a chunk reqwest still holds is) and then read
//! with the mapping's own code: `parse_item` per item, `parse_batch` for a
//! batch, `classify_status` for a status.
//!
//! The selective parser (`response::parse`) keeps only what the mapping
//! reads, and claims to accept exactly the documents serde_json accepts and
//! to answer every lookup the mapping makes as the complete document does.
//! The target holds it to that against `serde_json::Value`.

use maki_crypto::{CryptoError, SecretBuffer};
use serde_json::Value as Document;

use crate::response::{self, Value};
use crate::{
    append_owned_response_chunk, classify_status, Direction, HttpCryptoProvider, OpSpec,
    PayloadEncoding, RespKind, RespSpec,
};

/// The largest response the target's provider accepts.
pub const MAX_RESPONSE_BYTES: usize = 2048;
/// The first unit of a batch.
pub const FIRST_UNIT: u64 = 40;

/// How each selector reads a response: JSON mappings of one item and of a
/// batch, a raw body, and the status.
pub const READERS: u8 = 8;
pub const RAW: u8 = 6;
pub const STATUS: u8 = 7;

/// The JSON mapping a selector below [`RAW`] reads with, and whether it is
/// a batch.
fn mapping(selector: u8) -> (RespSpec, bool) {
    let spec = |data: Option<&str>, encoding, items: Option<&str>, index: Option<&str>| RespSpec {
        kind: RespKind::Json,
        data_path: data.map(str::to_string),
        encoding,
        items_path: items.map(str::to_string),
        item_index_path: index.map(str::to_string),
    };
    match selector {
        0 => (
            spec(Some("/ciphertext"), PayloadEncoding::Base64, None, None),
            false,
        ),
        1 => (
            spec(
                Some("/result/data"),
                PayloadEncoding::HexLower,
                None,
                Some("/result/unit"),
            ),
            false,
        ),
        2 => (
            spec(
                Some("/a~1b/~0c/1"),
                PayloadEncoding::Base64Url,
                None,
                Some("/unit"),
            ),
            false,
        ),
        3 => (spec(Some(""), PayloadEncoding::HexUpper, None, None), false),
        4 => (
            spec(
                Some("/data"),
                PayloadEncoding::Base64,
                Some("/results"),
                Some("/unit"),
            ),
            true,
        ),
        _ => (
            spec(
                Some("/payload/value"),
                PayloadEncoding::Base64Url,
                Some("/out/0/items"),
                Some("/meta/unit"),
            ),
            true,
        ),
    }
}

fn operation(response: RespSpec) -> OpSpec {
    OpSpec {
        method: "POST".into(),
        path: "/crypto".into(),
        headers: Vec::new(),
        query: Vec::new(),
        body: crate::BodySpec::Raw,
        response,
    }
}

/// Read the response in `data` as its selector says, and return whether
/// the provider accepted it. Panics where the selective parser disagrees
/// with serde_json, or where an accepted payload is not the one the
/// response holds.
pub fn response(data: &[u8]) -> bool {
    let [selector, parameter, body @ ..] = data else {
        return false;
    };
    let selector = selector % READERS;
    if selector == STATUS {
        return status(body);
    }
    let Some(body) = received(body) else {
        return false;
    };
    if selector == RAW {
        return raw(*parameter, body);
    }
    let (spec, batch) = mapping(selector);
    // A body serde_json's `Value` reads otherwise has no reference.
    let reference = (!reads_raw_value(body.expose()))
        .then(|| serde_json::from_slice::<Document>(body.expose()));
    let op = operation(spec);
    if batch {
        let count = 1 + usize::from(parameter % 4);
        let units: Vec<(u64, SecretBuffer)> = (0..count as u64)
            .map(|i| (FIRST_UNIT + i, SecretBuffer::zeroed(0)))
            .collect();
        if let Some(reference) = &reference {
            agrees_batch(&op.response, body.expose(), count, reference);
        }
        let parsed = HttpCryptoProvider::parse_batch(&op, body, &units);
        if let (Ok(payloads), Some(Ok(reference))) = (&parsed, &reference) {
            let items = reference
                .pointer(op.response.items_path.as_deref().unwrap_or_default())
                .and_then(Document::as_array)
                .expect("an accepted batch has its array");
            assert_eq!(payloads.len(), count);
            for ((payload, element), (unit, _)) in payloads.iter().zip(items).zip(&units) {
                let echoed = element
                    .pointer(op.response.item_index_path.as_deref().unwrap_or_default())
                    .and_then(Document::as_u64);
                assert_eq!(echoed, Some(*unit), "an accepted element of another unit");
                let text = element
                    .pointer(op.response.data_path.as_deref().unwrap_or_default())
                    .and_then(Document::as_str)
                    .expect("an accepted element has its payload");
                encodes_to(op.response.encoding, payload, text);
            }
        }
        parsed.is_ok()
    } else {
        let unit = u64::from(*parameter);
        if let Some(reference) = &reference {
            agrees_single(&op.response, body.expose(), reference);
        }
        let parsed = HttpCryptoProvider::parse_item(&op, Direction::Decrypt, body, unit, 0);
        if let (Ok(payload), Some(Ok(reference))) = (&parsed, &reference) {
            if let Some(index) = &op.response.item_index_path {
                assert_eq!(
                    reference.pointer(index).and_then(Document::as_u64),
                    Some(unit)
                );
            }
            let text = reference
                .pointer(op.response.data_path.as_deref().unwrap_or_default())
                .and_then(Document::as_str)
                .expect("an accepted response has its payload");
            encodes_to(op.response.encoding, payload, text);
        }
        parsed.is_ok()
    }
}

/// Whether serde_json's `Value` reads some object of `json` as something
/// else. With the `raw_value` feature, which the witness enables and
/// feature unification spreads, `Value` reads an object whose first key,
/// decoded, is serde_json's private raw-value token as the JSON text of
/// that key's string value. The walk decodes keys as `Value` does (an
/// escaped token is the token) and stops where the document stops parsing,
/// which is where `Value` stops before it meets one.
fn reads_raw_value(json: &[u8]) -> bool {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    use std::cell::Cell;

    const TOKEN: &str = "$serde_json::private::RawValue";

    struct Walk<'a>(&'a Cell<bool>);

    impl<'de> DeserializeSeed<'de> for Walk<'_> {
        type Value = ();

        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Walk<'_> {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON value")
        }

        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }

        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }

        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }

        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }

        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }

        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
            while sequence.next_element_seed(Walk(self.0))?.is_some() {}
            Ok(())
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut first = true;
            while let Some(key) = map.next_key::<String>()? {
                if first && key == TOKEN {
                    self.0.set(true);
                }
                first = false;
                map.next_value_seed(Walk(self.0))?;
            }
            Ok(())
        }
    }

    let found = Cell::new(false);
    let _ = Walk(&found).deserialize(&mut serde_json::Deserializer::from_slice(json));
    found.get()
}

/// `body` as the provider holds it after reading it in three chunks within
/// its limit, or `None` where it refused the length.
fn received(body: &[u8]) -> Option<SecretBuffer> {
    let (first, rest) = body.split_at(body.len() / 3);
    let (second, third) = rest.split_at(rest.len() / 2);
    let shared = bytes::Bytes::copy_from_slice(second);
    let _held = shared.clone();
    let mut out = SecretBuffer::zeroed(0);
    let mut within = true;
    for chunk in [
        bytes::Bytes::copy_from_slice(first),
        shared,
        bytes::Bytes::copy_from_slice(third),
    ] {
        if append_owned_response_chunk(&mut out, chunk, MAX_RESPONSE_BYTES).is_err() {
            within = false;
            break;
        }
    }
    assert_eq!(
        within,
        body.len() <= MAX_RESPONSE_BYTES,
        "a response of {} bytes",
        body.len()
    );
    if within {
        assert_eq!(out.expose(), body, "the accumulated body differs");
    }
    within.then_some(out)
}

fn raw(parameter: u8, body: SecretBuffer) -> bool {
    let direction = if parameter & 1 == 0 {
        Direction::Encrypt
    } else {
        Direction::Decrypt
    };
    let plaintext = usize::from(parameter >> 1) * 8;
    let op = operation(RespSpec {
        kind: RespKind::Raw,
        data_path: None,
        encoding: PayloadEncoding::Base64,
        items_path: None,
        item_index_path: None,
    });
    let copy = body.expose().to_vec();
    match HttpCryptoProvider::parse_item(&op, direction, body, 9, plaintext) {
        Ok(payload) => {
            assert_eq!(payload.expose(), copy.as_slice(), "a raw body changed");
            assert!(direction == Direction::Decrypt || copy.len() >= plaintext);
            true
        }
        Err(error) => {
            assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
            assert!(direction == Direction::Encrypt && copy.len() < plaintext);
            false
        }
    }
}

/// The status line and headers: whether the provider reads a success.
fn status(data: &[u8]) -> bool {
    let [high, low, lines @ ..] = data else {
        return false;
    };
    let code = 100 + u16::from_be_bytes([*high, *low]) % 900;
    let status = reqwest::StatusCode::from_u16(code).expect("a three-digit status");
    let mut headers = reqwest::header::HeaderMap::new();
    for line in lines.split(|byte| *byte == b'\n') {
        let Some(at) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(&line[..at]),
            reqwest::header::HeaderValue::from_bytes(&line[at + 1..]),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    let error = classify_status(status, &headers);
    let reasons: Vec<&[u8]> = headers
        .get_all("maki-crypto-error")
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    match &error {
        None => assert!(status.is_success(), "HTTP {code} read as a success"),
        // Only the explicit wire contract proves a cryptographic refusal.
        Some(CryptoError::Integrity(_) | CryptoError::UnsupportedContext(_)) => {
            assert_eq!(code, 422);
            assert!(
                matches!(
                    reasons.as_slice(),
                    [b"auth-tag-mismatch"
                        | b"context-mismatch"
                        | b"unsupported-format-version"
                        | b"unsupported-compatibility-id"]
                ),
                "a refusal read from {reasons:?}"
            );
        }
        Some(_) => assert!(!status.is_success()),
    }
    error.is_none()
}

/// A payload the provider accepted encodes again to the text it was read
/// from (either case of hexadecimal digits decodes).
fn encodes_to(encoding: PayloadEncoding, payload: &SecretBuffer, text: &str) {
    let again = encoding.encode(payload.expose());
    match encoding {
        PayloadEncoding::HexLower | PayloadEncoding::HexUpper => {
            assert!(again.eq_ignore_ascii_case(text), "hex payload changed")
        }
        _ => assert_eq!(again, text, "a payload is not its own encoding"),
    }
}

fn as_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn as_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

/// The selective parse of a single item's response answers as the
/// complete document does.
fn agrees_single(spec: &RespSpec, body: &[u8], reference: &serde_json::Result<Document>) {
    let parsed = response::parse(body, &spec.single_selection());
    let (parsed, reference) = match (parsed, reference) {
        (Ok(parsed), Ok(reference)) => (parsed, reference),
        (Err(_), Err(_)) => return,
        (parsed, reference) => panic!(
            "the selective parser {} a document serde_json {}",
            if parsed.is_ok() { "accepts" } else { "refuses" },
            if reference.is_ok() {
                "accepts"
            } else {
                "refuses"
            }
        ),
    };
    if let Some(path) = &spec.data_path {
        assert_eq!(
            as_str(parsed.pointer(path)),
            reference.pointer(path).and_then(Document::as_str),
            "{path}"
        );
    }
    if let Some(path) = &spec.item_index_path {
        assert_eq!(
            as_u64(parsed.pointer(path)),
            reference.pointer(path).and_then(Document::as_u64),
            "{path}"
        );
    }
}

/// The selective parse of a batch response keeps the first `count`
/// elements whole and counts the others, as the complete document has them.
fn agrees_batch(
    spec: &RespSpec,
    body: &[u8],
    count: usize,
    reference: &serde_json::Result<Document>,
) {
    let parsed = response::parse(body, &spec.batch_selection(count));
    let (parsed, reference) = match (parsed, reference) {
        (Ok(parsed), Ok(reference)) => (parsed, reference),
        (Err(_), Err(_)) => return,
        (parsed, reference) => panic!(
            "the selective parser {} a batch serde_json {}",
            if parsed.is_ok() { "accepts" } else { "refuses" },
            if reference.is_ok() {
                "accepts"
            } else {
                "refuses"
            }
        ),
    };
    let path = spec.items_path.as_deref().unwrap_or_default();
    let array = parsed.pointer(path).and_then(Value::as_array);
    let expected = reference.pointer(path).and_then(Document::as_array);
    assert_eq!(
        array.map(|(length, _)| length),
        expected.map(Vec::len),
        "{path}"
    );
    let (Some((_, kept)), Some(expected)) = (array, expected) else {
        return;
    };
    assert_eq!(
        kept.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        (0..expected.len().min(count)).collect::<Vec<_>>(),
        "the kept elements"
    );
    for ((_, element), expected) in kept.iter().zip(expected) {
        let data = spec.data_path.as_deref().unwrap_or_default();
        assert_eq!(
            as_str(element.pointer(data)),
            expected.pointer(data).and_then(Document::as_str)
        );
        if let Some(index) = &spec.item_index_path {
            assert_eq!(
                as_u64(element.pointer(index)),
                expected.pointer(index).and_then(Document::as_u64)
            );
        }
    }
}

/// `selector` and `parameter` followed by `body`.
fn input(selector: u8, parameter: u8, body: &[u8]) -> Vec<u8> {
    [&[selector, parameter][..], body].concat()
}

/// The committed seeds of `http_response`: responses a provider that
/// speaks each mapping sends, and copies changed where the provider must
/// refuse them. A seed's name says what [`response`] returns for it
/// (`valid-` true, `refused-` false, `noise-` either).
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));
    let payload = |i: u8| -> Vec<u8> { (0..48).map(|b| b ^ i).collect() };
    let b64 = |bytes: &[u8]| PayloadEncoding::Base64.encode(bytes);
    let b64url = |bytes: &[u8]| PayloadEncoding::Base64Url.encode(bytes);
    let hex = |bytes: &[u8]| PayloadEncoding::HexLower.encode(bytes);

    let single = format!(
        r#"{{"ciphertext":"{}","request_id":"r-1"}}"#,
        b64(&payload(1))
    );
    add("valid-single", input(0, 7, single.as_bytes()));
    add(
        "valid-single-escaped-and-duplicate",
        input(
            0,
            7,
            format!(
                r#"{{"ciphertext":"bm90IHRoaXM=","pad":[1e3,-0,{{"x":null}}],"ciphertext":"{}"}}"#,
                b64(&payload(2))
            )
            .as_bytes(),
        ),
    );
    add(
        "refused-single-not-base64",
        input(0, 7, br#"{"ciphertext":"bm90IHRo!XM="}"#),
    );
    add(
        "refused-single-noncanonical-padding",
        input(0, 7, br#"{"ciphertext":"YR=="}"#),
    );
    add(
        "refused-single-payload-not-a-string",
        input(0, 7, br#"{"ciphertext":12}"#),
    );
    add(
        "refused-single-trailing-bytes",
        input(0, 7, format!("{single} {{}}").as_bytes()),
    );
    add(
        "refused-single-cut",
        input(0, 7, &single.as_bytes()[..single.len() - 2]),
    );
    let deep = format!(
        r#"{{"ciphertext":"{}","pad":{}null{}}}"#,
        b64(&payload(1)),
        "[".repeat(130),
        "]".repeat(130)
    );
    add(
        "refused-single-beyond-recursion-limit",
        input(0, 7, deep.as_bytes()),
    );
    let echoed = format!(r#"{{"result":{{"unit":9,"data":"{}"}}}}"#, hex(&payload(3)));
    add("valid-single-hex-echo", input(1, 9, echoed.as_bytes()));
    add(
        "valid-single-hex-upper-case-digits",
        input(
            1,
            9,
            echoed
                .replace(&hex(&payload(3)), &hex(&payload(3)).to_uppercase())
                .as_bytes(),
        ),
    );
    add(
        "refused-single-echo-of-another-unit",
        input(1, 8, echoed.as_bytes()),
    );
    add(
        "refused-single-odd-hex",
        input(1, 9, br#"{"result":{"unit":9,"data":"abc"}}"#),
    );
    add(
        "refused-single-echo-a-float",
        input(1, 9, br#"{"result":{"unit":9.0,"data":"ab"}}"#),
    );
    add(
        "valid-single-escaped-pointer",
        input(
            2,
            3,
            format!(
                r#"{{"unit":3,"a/b":{{"~c":["x","{}"]}}}}"#,
                b64url(&payload(4))
            )
            .as_bytes(),
        ),
    );
    add(
        "refused-single-unescaped-pointer",
        input(
            2,
            3,
            format!(
                r#"{{"unit":3,"a":{{"b":{{"~c":["x","{}"]}}}}}}"#,
                b64url(&payload(4))
            )
            .as_bytes(),
        ),
    );
    add(
        "valid-single-whole-document",
        input(
            3,
            0,
            format!("\"{}\"", hex(&payload(5)).to_uppercase()).as_bytes(),
        ),
    );
    // serde_json's `Value` would read this as `{"ciphertext":"YQ=="}`; the
    // provider reads an object with one member it does not look for.
    add(
        "refused-single-raw-value-token-escaped",
        input(
            0,
            7,
            br#"{"\u0024serde_json::private::RawValue":"{\"ciphertext\":\"YQ==\"}"}"#,
        ),
    );
    add(
        "refused-single-invalid-utf16-escape",
        input(3, 0, br#""\uD800""#),
    );

    let batch = |count: u8, unit: &dyn Fn(u8) -> u64| -> String {
        let elements: Vec<String> = (0..count)
            .map(|i| {
                format!(
                    r#"{{"unit":{},"data":"{}","status":"ok"}}"#,
                    unit(i),
                    b64(&payload(i))
                )
            })
            .collect();
        format!(r#"{{"results":[{}],"took_ms":3}}"#, elements.join(","))
    };
    let in_order = |i: u8| FIRST_UNIT + u64::from(i);
    add(
        "valid-batch-one",
        input(4, 0, batch(1, &in_order).as_bytes()),
    );
    add(
        "valid-batch-four",
        input(4, 3, batch(4, &in_order).as_bytes()),
    );
    add(
        "refused-batch-fewer-elements",
        input(4, 3, batch(3, &in_order).as_bytes()),
    );
    add(
        "refused-batch-more-elements",
        input(4, 2, batch(4, &in_order).as_bytes()),
    );
    add(
        "refused-batch-reordered",
        input(
            4,
            1,
            batch(2, &|i| FIRST_UNIT + 1 - u64::from(i)).as_bytes(),
        ),
    );
    add(
        "refused-batch-duplicated",
        input(4, 1, batch(2, &|_| FIRST_UNIT).as_bytes()),
    );
    add(
        "refused-batch-not-an-array",
        input(4, 0, br#"{"results":{"0":{"unit":40,"data":"YQ=="}}}"#),
    );
    add(
        "refused-batch-element-not-an-object",
        input(4, 0, br#"{"results":["YQ=="]}"#),
    );
    let nested = format!(
        r#"{{"out":[{{"items":[{{"meta":{{"unit":40}},"payload":{{"value":"{}"}}}},{{"meta":{{"unit":41}},"payload":{{"value":"{}"}}}}]}}]}}"#,
        b64url(&payload(6)),
        b64url(&payload(7))
    );
    add("valid-batch-nested", input(5, 1, nested.as_bytes()));
    add(
        "valid-batch-nested-object-index",
        input(
            5,
            0,
            format!(
                r#"{{"out":{{"0":{{"items":[{{"meta":{{"unit":40}},"payload":{{"value":"{}"}}}}]}}}}}}"#,
                b64url(&payload(8))
            )
            .as_bytes(),
        ),
    );
    add(
        "refused-batch-nested-padded-base64url",
        input(
            5,
            0,
            br#"{"out":[{"items":[{"meta":{"unit":40},"payload":{"value":"YQ=="}}]}]}"#,
        ),
    );
    add(
        "noise-batch-four",
        input(4, 3, &flipped(batch(4, &in_order).as_bytes(), 60)),
    );
    add("noise-single", input(0, 7, &flipped(single.as_bytes(), 20)));

    add("valid-raw-encrypt", input(RAW, 4, &payload(9)));
    add("valid-raw-decrypt-short", input(RAW, 9, b"ct"));
    add(
        "refused-raw-encrypt-shorter-than-plaintext",
        input(RAW, 14, &payload(9)),
    );
    add(
        "refused-raw-beyond-limit",
        input(RAW, 1, &vec![0x5a; MAX_RESPONSE_BYTES + 1]),
    );

    let status = |code: u16, headers: &str| -> Vec<u8> {
        let mut bytes = vec![STATUS, 0];
        bytes.extend_from_slice(&(code - 100).to_be_bytes());
        bytes.extend_from_slice(headers.as_bytes());
        bytes
    };
    add(
        "valid-status-ok",
        status(200, "content-type:application/json"),
    );
    add("valid-status-no-content", status(204, ""));
    add(
        "refused-status-auth-tag-mismatch",
        status(422, "maki-crypto-error:auth-tag-mismatch"),
    );
    add(
        "refused-status-unsupported-format-version",
        status(422, "maki-crypto-error:unsupported-format-version"),
    );
    add(
        "refused-status-two-reasons",
        status(
            422,
            "maki-crypto-error:auth-tag-mismatch\nmaki-crypto-error:context-mismatch",
        ),
    );
    add(
        "refused-status-reason-on-another-code",
        status(400, "maki-crypto-error:auth-tag-mismatch"),
    );
    add(
        "refused-status-redirect",
        status(307, "location:http://elsewhere.invalid/"),
    );
    add("refused-status-throttled", status(429, "retry-after:1"));
    add("refused-status-unavailable", status(503, ""));
    seeds
}

/// `bytes` with byte `at` changed.
fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[at] ^= 0x08;
    changed
}

#[cfg(test)]
mod tests {
    use super::reads_raw_value;

    /// The oracle skips exactly the documents serde_json's `Value` reads
    /// otherwise: an object whose first key decodes to the raw-value token,
    /// at any depth. Every other document is compared, so a classifier that
    /// skipped everything would leave the target without its oracle.
    #[test]
    fn only_a_first_key_that_decodes_to_the_token_skips_the_reference() {
        for flagged in [
            r#"{"$serde_json::private::RawValue":"1"}"#,
            r#"{"\u0024serde_json::private::RawValue":"1"}"#,
            r#"{"$s\u0065rde_json::private::RawValue":"1"}"#,
            r#"{"$serde_json\u003a:private::RawValue":"1"}"#,
            r#"{"id":5,"trace":{"$serde_json::private::RawValue":"[1]"}}"#,
            r#"[1,{"$serde_json::private::RawValue":"{}"}]"#,
        ] {
            assert!(reads_raw_value(flagged.as_bytes()), "{flagged}");
        }
        for compared in [
            r#"{"id":1,"$serde_json::private::RawValue":"1"}"#,
            r#"{"id":1,"note":"$serde_json::private::RawValue"}"#,
            r#"{"$serde_json::private::RawValueX":"1"}"#,
            r#"["$serde_json::private::RawValue"]"#,
            r#"{"id":5,"items":[{"unit":20,"data":"YQ=="}],"error":null}"#,
            "",
            "[",
        ] {
            assert!(!reads_raw_value(compared.as_bytes()), "{compared}");
        }
        // The token as a second key is a member like any other, with the
        // `raw_value` feature or without it (the harness turns it on
        // through the witness; this crate's own tests do not).
        let second: serde_json::Value =
            serde_json::from_str(r#"{"id":1,"$serde_json::private::RawValue":"1"}"#).unwrap();
        assert_eq!(second["$serde_json::private::RawValue"], "1");
    }
}
