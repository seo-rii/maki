//! Provider-owned response payloads and JSON strings. Library read buffers and
//! serde's escape-decoding scratch remain outside these owners.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use maki_crypto::SecretBuffer;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio_tungstenite::tungstenite::{Bytes, Message};

pub(super) struct Frame(SecretBuffer);

impl Frame {
    pub(super) fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

fn own_frame(bytes: Bytes) -> Frame {
    let buffer = match bytes.try_into_mut() {
        Ok(unique) => SecretBuffer::from_vec(unique.into()),
        Err(shared) => {
            // Never modify a Bytes allocation that still has another owner.
            // Our copy is guarded immediately; the library's shared source
            // retains its own lifetime and cannot be wiped here.
            let mut buffer = SecretBuffer::zeroed(shared.len());
            buffer.expose_mut().copy_from_slice(&shared);
            buffer
        }
    };
    Frame(buffer)
}

pub(super) fn own_message(message: Message) -> Option<Frame> {
    // into_data selects the same payload as into_text, including Close reasons,
    // but lets us guard Binary/Ping/Pong bytes before UTF-8 rejection frees them.
    let frame = own_frame(message.into_data());
    std::str::from_utf8(frame.expose()).ok()?;
    Some(frame)
}

pub(super) struct SecretString(SecretBuffer);

impl SecretString {
    fn as_str(&self) -> &str {
        std::str::from_utf8(self.0.expose()).expect("JSON strings are UTF-8")
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(redacted)")
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
                let mut buffer = SecretBuffer::zeroed(value.len());
                buffer.expose_mut().copy_from_slice(value.as_bytes());
                Ok(SecretString(buffer))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretString(SecretBuffer::from_vec(value.into_bytes())))
            }
        }
        deserializer.deserialize_string(StringVisitor)
    }
}

const ID: u8 = 1;
const ERROR: u8 = 2;
const CLASS: u8 = 4;
const REASON: u8 = 8;

pub(super) struct Object {
    values: BTreeMap<SecretString, Value>,
    duplicate_probe_fields: u8,
}

pub(super) enum Value {
    Null,
    Bool,
    Number(serde_json::Number),
    String(SecretString),
    Array(Vec<Value>),
    Object(Object),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseValue(redacted)")
    }
}

impl Value {
    pub(super) fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(object) => object.values.get(key),
            _ => None,
        }
    }

    pub(super) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(string) => Some(string.as_str()),
            _ => None,
        }
    }

    pub(super) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(number) => number.as_u64(),
            _ => None,
        }
    }

    pub(super) fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    // Ordinary responses keep last-value-wins semantics. Negative self-tests
    // require the same unambiguous object envelope as the previous derived
    // structs: only their four known fields reject duplicates, at their own
    // nesting level. Inspecting the guarded tree avoids a second deserialize
    // that could copy secret strings into fields or type-error diagnostics.
    pub(super) fn valid_probe_envelope(&self) -> bool {
        let Self::Object(root) = self else {
            return false;
        };
        if root.duplicate_probe_fields & (ID | ERROR) != 0
            || self.get("id").and_then(Self::as_u64).is_none()
        {
            return false;
        }
        let Some(Self::Object(error)) = self.get("error") else {
            return false;
        };
        error.duplicate_probe_fields & (CLASS | REASON) == 0
            && error.values.get("class").and_then(Self::as_str).is_some()
            && error.values.get("reason").and_then(Self::as_str).is_some()
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
                let mut buffer = SecretBuffer::zeroed(value.len());
                buffer.expose_mut().copy_from_slice(value.as_bytes());
                Ok(Value::String(SecretString(buffer)))
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
                let mut duplicate_probe_fields = 0;
                while let Some(key) = map.next_key::<SecretString>()? {
                    let value = map.next_value()?;
                    if values.contains_key(key.as_str()) {
                        duplicate_probe_fields |= match key.as_str() {
                            "id" => ID,
                            "error" => ERROR,
                            "class" => CLASS,
                            "reason" => REASON,
                            _ => 0,
                        };
                    }
                    // Preserve serde_json::Value's last-value-wins lookups.
                    // BTreeMap drops both overwritten values and unused keys.
                    values.insert(key, value);
                }
                Ok(Value::Object(Object {
                    values,
                    duplicate_probe_fields,
                }))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

pub(super) fn parse(text: &str) -> serde_json::Result<Value> {
    // Keep serde_json's default recursion limit and syntax/number validation.
    serde_json::from_str(text)
}
