//! Provider-owned response payloads and JSON strings. Library read buffers and
//! transport framing copies remain separate owners. The pinned serde_json
//! patch separately erases escape-decoding scratch; see docs/transport-memory.md.
//!
//! A frame is parsed against the response protocol. Only what the response
//! handling reads is kept: the `id`, the `error` object's `class` and
//! `reason`, and the `unit` and `data` of at most a given number of `items`
//! (later items are only counted). Everything else is validated exactly as
//! before (syntax, numbers, UTF-8, recursion limit) and dropped without being
//! copied. A frame therefore costs memory in proportion to what is read from
//! it, not to its node count, which `max_frame_bytes` alone does not bound.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use maki_crypto::SecretBuffer;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio_tungstenite::tungstenite::{Bytes, Message};

pub(super) struct Frame(SecretBuffer);

impl Frame {
    pub(super) fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    // The returned tree owns its strings and keys. Consuming the source owner
    // releases it before routing, payload decoding or a parse error reaches
    // the caller, rather than retaining both representations in the reader.
    /// Keep at most `items` response items; later ones are only counted.
    pub(super) fn parse(self, items: usize) -> serde_json::Result<Value> {
        let text = std::str::from_utf8(self.expose()).expect("WebSocket text is UTF-8");
        parse(text, items)
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
    fn from_str(value: &str) -> Self {
        let mut buffer = SecretBuffer::zeroed(value.len());
        buffer.expose_mut().copy_from_slice(value.as_bytes());
        Self(buffer)
    }

    fn from_string(value: String) -> Self {
        Self(SecretBuffer::from_vec(value.into_bytes()))
    }

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

const ID: u8 = 1;
const ERROR: u8 = 2;
const CLASS: u8 = 4;
const REASON: u8 = 8;

/// What the response handling reads at one position of a frame.
#[derive(Clone, Copy)]
enum Shape {
    /// The frame: `id`, `error` and `items`, keeping at most `items` items.
    Response {
        items: usize,
    },
    /// The `error` object: `class` and `reason`.
    Error,
    /// The `items` array: the first `n` elements are items, the rest are
    /// only counted.
    Items(usize),
    /// One item: `unit` and `data`.
    Item,
    Number,
    String,
}

impl Shape {
    /// The shape of the member `key` of an object read as `self`, and the
    /// probe-envelope field it is, or `None` when nothing reads that member.
    fn member(self, key: &str) -> Option<(Self, u8)> {
        match (self, key) {
            (Self::Response { .. }, "id") => Some((Self::Number, ID)),
            (Self::Response { .. }, "error") => Some((Self::Error, ERROR)),
            (Self::Response { items }, "items") => Some((Self::Items(items), 0)),
            (Self::Error, "class") => Some((Self::String, CLASS)),
            (Self::Error, "reason") => Some((Self::String, REASON)),
            (Self::Item, "unit") => Some((Self::Number, 0)),
            (Self::Item, "data") => Some((Self::String, 0)),
            _ => None,
        }
    }

    fn is_object(self) -> bool {
        matches!(self, Self::Response { .. } | Self::Error | Self::Item)
    }
}

pub(super) struct Object {
    values: BTreeMap<SecretString, Value>,
    duplicate_probe_fields: u8,
}

/// The parts of a frame the response handling reads. Lookups of those parts
/// give the same result as on the complete document.
pub(super) enum Value {
    /// A value nothing reads here: another type, or a container no read
    /// enters. It was validated, never copied.
    Skipped,
    Number(serde_json::Number),
    String(SecretString),
    /// The array's length and its kept leading elements.
    Array(usize, Vec<Value>),
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

    /// The array's full length and the leading elements that were kept.
    pub(super) fn as_array(&self) -> Option<(usize, &[Self])> {
        match self {
            Self::Array(length, values) => Some((*length, values)),
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

/// Parse one value, keeping what its shape reads.
struct Select(Shape);

impl<'de> DeserializeSeed<'de> for Select {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Select {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Value, E> {
        Ok(Value::Skipped)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Skipped)
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(match self.0 {
            Shape::Number => Value::Number(value.into()),
            _ => Value::Skipped,
        })
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(match self.0 {
            Shape::Number => Value::Number(value.into()),
            _ => Value::Skipped,
        })
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(match self.0 {
            Shape::Number => {
                serde_json::Number::from_f64(value).map_or(Value::Skipped, Value::Number)
            }
            _ => Value::Skipped,
        })
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(match self.0 {
            Shape::String => Value::String(SecretString::from_str(value)),
            _ => Value::Skipped,
        })
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        // Adopt the owned string either way, so an unread one is erased.
        let value = SecretString::from_string(value);
        Ok(match self.0 {
            Shape::String => Value::String(value),
            _ => Value::Skipped,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let Shape::Items(limit) = self.0 else {
            while sequence.next_element::<Skip>()?.is_some() {}
            return Ok(Value::Skipped);
        };
        let mut kept = Vec::new();
        let mut length = 0usize;
        loop {
            if length < limit {
                match sequence.next_element_seed(Select(Shape::Item))? {
                    Some(item) => kept.push(item),
                    None => break,
                }
            } else if sequence.next_element::<Skip>()?.is_none() {
                break;
            }
            length += 1;
        }
        Ok(Value::Array(length, kept))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if !self.0.is_object() {
            while map.next_entry::<Skip, Skip>()?.is_some() {}
            return Ok(Value::Skipped);
        }
        let mut values = BTreeMap::new();
        let mut duplicate_probe_fields = 0;
        while let Some(member) = map.next_key_seed(Member(self.0))? {
            match member {
                Some((key, shape, field)) => {
                    // The key is already guarded if its value is malformed.
                    let value = map.next_value_seed(Select(shape))?;
                    // Preserve serde_json::Value's last-value-wins lookups.
                    // BTreeMap drops both overwritten values and unused keys.
                    if values.insert(key, value).is_some() {
                        duplicate_probe_fields |= field;
                    }
                }
                None => {
                    map.next_value::<Skip>()?;
                }
            }
        }
        Ok(Value::Object(Object {
            values,
            duplicate_probe_fields,
        }))
    }
}

/// An object key, kept with the shape of its value only when the response
/// handling reads that member.
struct Member(Shape);

impl<'de> DeserializeSeed<'de> for Member {
    type Value = Option<(SecretString, Shape, u8)>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for Member {
    type Value = Option<(SecretString, Shape, u8)>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object key")
    }

    fn visit_str<E: serde::de::Error>(self, key: &str) -> Result<Self::Value, E> {
        Ok(self
            .0
            .member(key)
            .map(|(shape, field)| (SecretString::from_str(key), shape, field)))
    }

    fn visit_string<E: serde::de::Error>(self, key: String) -> Result<Self::Value, E> {
        let key = SecretString::from_string(key);
        Ok(self
            .0
            .member(key.as_str())
            .map(|(shape, field)| (key, shape, field)))
    }
}

/// A value nothing reads. It is parsed through `deserialize_any` like a kept
/// value, not `deserialize_ignored_any`: the latter skips serde_json's
/// recursion limit and number range checks.
struct Skip;

impl<'de> Deserialize<'de> for Skip {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Skip)
    }
}

impl<'de> Visitor<'de> for Skip {
    type Value = Skip;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_u64<E: serde::de::Error>(self, _value: u64) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Skip, E> {
        Ok(Skip)
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Skip, E> {
        drop(SecretString::from_string(value));
        Ok(Skip)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Skip, A::Error> {
        while sequence.next_element::<Skip>()?.is_some() {}
        Ok(Skip)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Skip, A::Error> {
        while map.next_entry::<Skip, Skip>()?.is_some() {}
        Ok(Skip)
    }
}

/// Parse a response frame, keeping at most `items` response items.
pub(super) fn parse(text: &str, items: usize) -> serde_json::Result<Value> {
    // Preserve serde_json's syntax, number, trailing-input and recursion-limit
    // checks (serde_json::from_str with a seed).
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = Select(Shape::Response { items }).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Parse one string where it is read (`kept`) or where nothing reads it, for
/// tests of owned-string adoption.
#[cfg(test)]
pub(super) fn deserialize_string<'de, D: Deserializer<'de>>(
    deserializer: D,
    kept: bool,
) -> Result<Value, D::Error> {
    let shape = if kept { Shape::String } else { Shape::Number };
    Select(shape).deserialize(deserializer)
}
