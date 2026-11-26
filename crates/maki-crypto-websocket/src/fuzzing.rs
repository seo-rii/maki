//! The fuzz harness's way into the WebSocket provider's reading of what its
//! peer sends (`fuzz/harness`, target `websocket_response`). Built only with
//! the `fuzzing` feature, which only the harness enables: nothing here is
//! part of the provider.
//!
//! An input is one message. Its first byte selects the message's type (its
//! low three bits: text, binary, ping, pong, close, and text again for the
//! other three), how many units the request it may answer carries (bits
//! 3-4: one to four, units 20 upwards) and whether a request of two more
//! items is registered on the connection as well (bit 5), which makes the
//! reader keep that many items. The rest is the payload: a text message
//! that is not UTF-8 never reaches the reader (tungstenite refuses it).
//! The message goes through the connection reader's own `receive`, and a
//! response through the provider's `parse_response`.
//!
//! The frame parser keeps only what the response handling reads, and
//! claims to accept exactly the documents serde_json accepts and to answer
//! every read as the complete document does. The target holds it to that
//! against `serde_json::Value`.

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use maki_crypto::{BatchCapability, Capability, CryptoCapabilities, CryptoError};
use serde_json::Value as Document;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};

use crate::{receive, response, Received, WsCryptoProvider, WsProviderSpec};

pub const TEXT: u8 = 0;
pub const BINARY: u8 = 1;
pub const PING: u8 = 2;
pub const PONG: u8 = 3;
pub const CLOSE: u8 = 4;
/// Bits 3-4: the request carries one to four units.
pub const UNITS_SHIFT: u8 = 3;
/// A request of two more items is registered as well.
pub const LARGER: u8 = 0x20;
/// The first unit of the request.
pub const FIRST_UNIT: u64 = 20;

fn provider() -> &'static WsCryptoProvider {
    static PROVIDER: OnceLock<WsCryptoProvider> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        WsCryptoProvider::new(WsProviderSpec {
            url: "ws://127.0.0.1:1/crypto".into(),
            capabilities: CryptoCapabilities {
                provider_id: "remote-websocket-fuzz".into(),
                crypto_compatibility_id: "fuzz-v1".into(),
                supported_plaintext_sizes: vec![4096],
                max_ciphertext_size: 4096 + 64,
                stateless: true,
                retry_safe: true,
                batch: BatchCapability {
                    supported: true,
                    max_items: 8,
                    max_bytes: 1 << 20,
                },
                integrity: Capability::Absent,
                context_binding: Capability::Absent,
                replay_protection: Capability::Absent,
            },
            timeout: Duration::from_secs(1),
            max_frame_bytes: 1 << 20,
            tls: None,
        })
    })
}

/// Feed the message in `data` to the reader, and a response to the
/// provider, and return whether the provider accepted the response as the
/// results of the request. Panics where the frame parser disagrees with
/// serde_json, or where an accepted result is not the one the frame holds.
pub fn message(data: &[u8]) -> bool {
    let Some((&selector, payload)) = data.split_first() else {
        return false;
    };
    let kind = match selector & 7 {
        5..=7 => TEXT,
        kind => kind,
    };
    let count = 1 + usize::from((selector >> UNITS_SHIFT) & 3);
    let items = count + if selector & LARGER != 0 { 2 } else { 0 };
    let bytes = Bytes::copy_from_slice(payload);
    let text = std::str::from_utf8(payload).ok();
    let message = match kind {
        TEXT => match Utf8Bytes::try_from(bytes) {
            Ok(text) => Message::Text(text),
            Err(_) => return false,
        },
        BINARY => Message::Binary(bytes),
        PING => Message::Ping(bytes),
        PONG => Message::Pong(bytes),
        _ => Message::Close(text.map(|reason| CloseFrame {
            code: CloseCode::Normal,
            reason: Utf8Bytes::from(reason.to_string()),
        })),
    };
    // With the `raw_value` feature (the witness enables it), serde_json's
    // `Value` reads an object whose first key is its private raw-value token as
    // the JSON text of its value: such a frame has no reference.
    let reference = text
        .filter(|text| !text.contains("$serde_json::private::"))
        .map(serde_json::from_str::<Document>);
    if kind == TEXT {
        if let (Some(text), Some(reference)) = (text, &reference) {
            agrees(text, items, reference);
        }
    }
    let received = match receive(message, || items) {
        Ok(received) => received,
        Err(error) => {
            match kind {
                CLOSE => assert!(matches!(error, CryptoError::Retryable(_)), "{error:?}"),
                _ => assert!(matches!(error, CryptoError::Contract(_)), "{error:?}"),
            }
            return false;
        }
    };
    let (id, frame) = match received {
        Received::Control => {
            assert!(
                matches!(kind, PING | PONG),
                "a message of type {kind} skipped"
            );
            return false;
        }
        Received::Response(id, frame) => (id, frame),
    };
    assert_eq!(kind, TEXT, "a response from a message of type {kind}");
    let reference = reference.map(|reference| reference.expect("serde_json accepts a response"));
    if let Some(reference) = &reference {
        assert_eq!(reference["id"].as_u64(), Some(id), "the response id");
    }
    let value = match frame {
        Ok(value) => value,
        Err(error) => {
            assert!(matches!(error, CryptoError::Contract(_)), "{error:?}");
            if let Some(reference) = &reference {
                assert!(
                    matches!(
                        reference["error"]["class"].as_str(),
                        Some("integrity" | "unsupported-context")
                    ),
                    "an envelope refused for another class"
                );
            }
            return false;
        }
    };
    let requested: Vec<(u64, &[u8])> = (0..count as u64)
        .map(|i| (FIRST_UNIT + i, &[][..]))
        .collect();
    let results = provider().parse_response(&value, &requested);
    // The attach self-test trusts a cryptographic refusal only from an
    // unambiguous envelope: the reader refuses any other.
    if matches!(
        results,
        Err(CryptoError::Integrity(_) | CryptoError::UnsupportedContext(_))
    ) {
        assert!(
            value.valid_probe_envelope(),
            "a refusal delivered from an ambiguous envelope"
        );
    }
    let Some(reference) = reference else {
        return results.is_ok();
    };
    match &results {
        Ok(results) => {
            assert!(
                reference.get("error").is_none(),
                "a refusal read as results"
            );
            let items = reference["items"]
                .as_array()
                .expect("accepted results have their items");
            assert_eq!((results.len(), items.len()), (count, count));
            for ((result, item), (unit, _)) in results.iter().zip(items).zip(&requested) {
                assert_eq!(
                    item["unit"].as_u64(),
                    Some(*unit),
                    "a result of another unit"
                );
                assert_eq!(
                    base64::engine::general_purpose::STANDARD.encode(result.expose()),
                    item["data"]
                        .as_str()
                        .expect("an accepted item has its data"),
                    "a result is not its own encoding"
                );
            }
        }
        Err(CryptoError::Integrity(_)) => {
            assert_eq!(reference["error"]["class"].as_str(), Some("integrity"));
            assert!(matches!(
                reference["error"]["reason"].as_str(),
                Some("auth-tag-mismatch" | "context-mismatch")
            ));
        }
        Err(CryptoError::UnsupportedContext(_)) => {
            assert_eq!(
                reference["error"]["class"].as_str(),
                Some("unsupported-context")
            );
        }
        Err(_) => {}
    }
    results.is_ok()
}

/// The frame parser accepts what serde_json accepts and reads the id, the
/// error and the kept items as the complete document has them.
fn agrees(text: &str, items: usize, reference: &serde_json::Result<Document>) {
    let parsed = response::parse(text, items);
    let (parsed, reference) = match (parsed, reference) {
        (Ok(parsed), Ok(reference)) => (parsed, reference),
        (Err(_), Err(_)) => return,
        (parsed, reference) => panic!(
            "the frame parser {} a frame serde_json {}",
            if parsed.is_ok() { "accepts" } else { "refuses" },
            if reference.is_ok() {
                "accepts"
            } else {
                "refuses"
            }
        ),
    };
    if !reference.is_object() {
        assert!(parsed.get("id").is_none());
        return;
    }
    assert_eq!(
        parsed.get("id").and_then(response::Value::as_u64),
        reference["id"].as_u64()
    );
    let error = parsed.get("error");
    for field in ["class", "reason"] {
        assert_eq!(
            error
                .and_then(|error| error.get(field))
                .and_then(response::Value::as_str),
            reference["error"][field].as_str(),
            "error.{field}"
        );
    }
    let kept = parsed.get("items").and_then(response::Value::as_array);
    let expected = reference["items"].as_array();
    assert_eq!(
        kept.map(|(length, _)| length),
        expected.map(Vec::len),
        "the items' count"
    );
    if let (Some((_, kept)), Some(expected)) = (kept, expected) {
        assert_eq!(kept.len(), expected.len().min(items), "the kept items");
        for (item, expected) in kept.iter().zip(expected) {
            assert_eq!(
                item.get("unit").and_then(response::Value::as_u64),
                expected["unit"].as_u64()
            );
            assert_eq!(
                item.get("data").and_then(response::Value::as_str),
                expected["data"].as_str()
            );
        }
    }
}

/// `selector` followed by `payload`.
fn input(selector: u8, payload: &[u8]) -> Vec<u8> {
    [&[selector][..], payload].concat()
}

/// The selector of a text message answering a request of `count` units.
fn text(count: u8) -> u8 {
    TEXT | ((count - 1) << UNITS_SHIFT)
}

/// The committed seeds of `websocket_response`: the frames a provider that
/// speaks Maki's WebSocket protocol sends, and messages the reader must
/// refuse. A seed's name says what [`message`] returns for it (`valid-`
/// true, `refused-` false, `noise-` either).
pub fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));
    let b64 = |i: u64| {
        base64::engine::general_purpose::STANDARD
            .encode((0..40u8).map(|b| b ^ i as u8).collect::<Vec<_>>())
    };
    let response = |units: &[u64]| -> String {
        let items: Vec<String> = units
            .iter()
            .map(|unit| format!(r#"{{"unit":{unit},"data":"{}"}}"#, b64(*unit)))
            .collect();
        format!(r#"{{"id":5,"items":[{}]}}"#, items.join(","))
    };
    add("valid-one-item", input(text(1), response(&[20]).as_bytes()));
    let three = response(&[20, 21, 22]);
    add("valid-three-items", input(text(3), three.as_bytes()));
    add(
        "valid-three-items-larger-request-registered",
        input(text(3) | LARGER, three.as_bytes()),
    );
    add(
        "valid-unread-members",
        input(
            text(1),
            format!(
                r#"{{"trace":{{"a":[1,2.5,-0,null]}},"id":5,"items":[{{"unit":20,"data":"{}","note":"x"}}],"id":5}}"#,
                b64(20)
            )
            .as_bytes(),
        ),
    );
    add(
        "refused-fewer-items",
        input(text(3), response(&[20, 21]).as_bytes()),
    );
    add("refused-more-items", input(text(2), three.as_bytes()));
    add(
        "refused-more-items-larger-request-registered",
        input(text(2) | LARGER, three.as_bytes()),
    );
    add(
        "refused-reordered-items",
        input(text(2), response(&[21, 20]).as_bytes()),
    );
    add(
        "refused-item-without-data",
        input(text(1), br#"{"id":5,"items":[{"unit":20}]}"#),
    );
    add(
        "refused-item-not-base64",
        input(text(1), br#"{"id":5,"items":[{"unit":20,"data":"a!=="}]}"#),
    );
    add(
        "refused-item-unpadded-base64",
        input(text(1), br#"{"id":5,"items":[{"unit":20,"data":"YQ"}]}"#),
    );
    for (name, error) in [
        ("throttled", r#"{"class":"throttled","reason":"slow down"}"#),
        ("retryable", r#"{"class":"retryable","reason":"restart"}"#),
        ("bad-request", r#"{"class":"bad-request","reason":"no"}"#),
        (
            "integrity",
            r#"{"class":"integrity","reason":"auth-tag-mismatch"}"#,
        ),
        (
            "unsupported-context",
            r#"{"class":"unsupported-context","reason":"unsupported-format-version"}"#,
        ),
        (
            "integrity-unknown-reason",
            r#"{"class":"integrity","reason":"other"}"#,
        ),
        (
            "integrity-duplicate-class",
            r#"{"class":"throttled","class":"integrity","reason":"context-mismatch"}"#,
        ),
        ("integrity-without-reason", r#"{"class":"integrity"}"#),
        ("unknown-class", r#"{"class":"teapot","reason":"x"}"#),
    ] {
        add(
            &format!("refused-error-{name}"),
            input(text(1), format!(r#"{{"id":5,"error":{error}}}"#).as_bytes()),
        );
    }
    add(
        "refused-error-integrity-duplicate-id",
        input(
            text(1),
            br#"{"id":5,"id":5,"error":{"class":"integrity","reason":"auth-tag-mismatch"}}"#,
        ),
    );
    add(
        "refused-id-a-string",
        input(text(1), br#"{"id":"5","items":[]}"#),
    );
    add(
        "refused-id-negative",
        input(text(1), br#"{"id":-5,"items":[]}"#),
    );
    add("refused-without-id", input(text(1), br#"{"items":[]}"#));
    add("refused-not-json", input(text(1), br#"{"id":5,"items":[}"#));
    add("refused-not-an-object", input(text(1), b"[5]"));
    add("refused-text-not-utf8", input(text(1), b"{\"id\":5\xff}"));
    add("refused-binary", input(BINARY, response(&[20]).as_bytes()));
    add("refused-ping", input(PING, b"keepalive"));
    add("refused-pong", input(PONG, b""));
    add("refused-close", input(CLOSE, b"going away"));
    let mut noise = three.clone().into_bytes();
    noise[30] ^= 0x01;
    add("noise-three-items", input(text(3), &noise));
    seeds
}
