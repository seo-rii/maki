//! HTTP response JSON owns every completed string and key in guarded memory.
//! The pinned serde_json patch separately erases parser-private scratch;
//! transport framing copies remain separate owners. The original HTTP body
//! has its own SecretBuffer. See docs/transport-memory.md.

use std::{borrow::Borrow, collections::BTreeMap, fmt};

use maki_crypto::SecretBuffer;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

pub(super) struct SecretString(SecretBuffer);

impl SecretString {
    fn from_str(value: &str) -> Self {
        let mut buffer = SecretBuffer::zeroed(value.len());
        buffer.expose_mut().copy_from_slice(value.as_bytes());
        Self(buffer)
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.0.expose()).expect("JSON strings are UTF-8")
    }
}

impl Borrow<str> for SecretString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SecretString {}

impl PartialOrd for SecretString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecretString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor;
        impl Visitor<'_> for StringVisitor {
            type Value = SecretString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretString::from_str(value))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretString(SecretBuffer::from_vec(value.into_bytes())))
            }
        }
        deserializer.deserialize_string(StringVisitor)
    }
}

pub(super) enum Value {
    Null,
    Bool,
    Number(serde_json::Number),
    String(SecretString),
    Array(Vec<Value>),
    Object(BTreeMap<SecretString, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseValue(redacted)")
    }
}

impl Value {
    /// Preserve serde_json::Value's RFC 6901 lookups, including its array
    /// index rules. Tokens come from configuration, not response contents.
    pub(super) fn pointer(&self, pointer: &str) -> Option<&Self> {
        if pointer.is_empty() {
            return Some(self);
        }
        pointer
            .strip_prefix('/')?
            .split('/')
            .try_fold(self, |value, token| {
                let token = super::decode_pointer_token(token);
                match value {
                    Self::Object(values) => values.get(token.as_str()),
                    Self::Array(values) => {
                        if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
                            return None;
                        }
                        values.get(token.parse::<usize>().ok()?)
                    }
                    _ => None,
                }
            })
    }

    pub(super) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub(super) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.as_u64(),
            _ => None,
        }
    }

    pub(super) fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Value, E> {
                Ok(Value::Bool)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
                Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(SecretString::from_str(value)))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(SecretString(SecretBuffer::from_vec(
                    value.into_bytes(),
                ))))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<SecretString>()? {
                    // The key is already guarded if its value is malformed.
                    let value = map.next_value()?;
                    // Match serde_json's last-value-wins semantics. Replaced
                    // values and unused duplicate keys wipe on drop too.
                    values.insert(key, value);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

pub(super) fn parse(bytes: &[u8]) -> serde_json::Result<Value> {
    // Preserve serde_json's syntax, number, UTF-8 and recursion-limit checks.
    serde_json::from_slice(bytes)
}

// The existing page-lock test owns the process-global locking setting and
// calls this while it is enabled, avoiding competing tests toggling it.
#[cfg(test)]
pub(super) fn check_json_page_locks() {
    use maki_crypto::secret::page_lock_failures;

    let before = page_lock_failures();
    let Value::Object(values) = parse(br#"{"key":"payload"}"#).unwrap() else {
        panic!("expected object");
    };
    let (key, Value::String(value)) = values.first_key_value().unwrap() else {
        panic!("expected string");
    };
    assert!((key.0.is_page_locked() && value.0.is_page_locked()) || page_lock_failures() > before);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_pointer_and_value_types_match_the_previous_response_parser() {
        let wire = br#"{
            "": "empty", "a/b": {"m~n": ["first", "second"]},
            "~1": "escaped", "~2": "literal", "dupe": "first", "dupe": "last",
            "str": "escaped\n\u0051", "false": false, "null": null,
            "numbers": [0, -0, -1, 1.5, 1e0, 18446744073709551615]
        }"#;
        let old: serde_json::Value = serde_json::from_slice(wire).unwrap();
        let guarded = parse(wire).unwrap();
        for pointer in [
            "",
            "/",
            "/a~1b/m~0n/0",
            "/a~1b/m~0n/1",
            "/a~1b/m~0n/01",
            "/a~1b/m~0n/+1",
            "/a~1b/m~0n/-1",
            "/a~1b/m~0n/-",
            "/a~1b/m~0n/2",
            "/~01",
            "/~2",
            "/dupe",
            "/str",
            "/false",
            "/null",
            "/missing",
            "str",
            "/str/0",
            "/numbers/0",
            "/numbers/1",
            "/numbers/2",
            "/numbers/3",
            "/numbers/4",
            "/numbers/5",
        ] {
            let expected = old.pointer(pointer);
            let actual = guarded.pointer(pointer);
            assert_eq!(actual.is_some(), expected.is_some(), "{pointer}");
            assert_eq!(
                actual.and_then(Value::as_str),
                expected.and_then(serde_json::Value::as_str),
                "{pointer}"
            );
            assert_eq!(
                actual.and_then(Value::as_u64),
                expected.and_then(serde_json::Value::as_u64),
                "{pointer}"
            );
            assert_eq!(
                actual.and_then(Value::as_array).map(<[Value]>::len),
                expected.and_then(serde_json::Value::as_array).map(Vec::len),
                "{pointer}"
            );
        }
        assert_eq!(format!("{guarded:?}"), "ResponseValue(redacted)");
    }

    #[test]
    fn invalid_json_and_recursion_limit_are_still_refused() {
        let deeply_nested = format!("{}null{}", "[".repeat(130), "]".repeat(130));
        for wire in [
            br#"{"data":"x"} null"#.as_slice(),
            br#"{"data":"\uD800"}"#,
            br#"{"number":1e999}"#,
            b"\"\xff\"",
            deeply_nested.as_bytes(),
        ] {
            assert!(serde_json::from_slice::<serde_json::Value>(wire).is_err());
            assert!(parse(wire).is_err());
        }
    }
}
