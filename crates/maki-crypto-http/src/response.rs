//! HTTP response JSON is parsed against the configured response mapping.
//! Only values that a configured JSON pointer reaches are kept; everything
//! else is validated exactly as before (syntax, numbers, UTF-8, recursion
//! limit) and dropped without being copied. A response therefore costs
//! memory in proportion to what the mapping reads, not to its node count,
//! which `max_response_bytes` alone does not bound.
//!
//! Every kept string and object key is owned in guarded memory. The pinned
//! serde_json patch separately erases parser-private scratch; transport
//! framing copies remain separate owners. The original HTTP body has its own
//! SecretBuffer. See docs/transport-memory.md.

use std::{borrow::Borrow, collections::BTreeMap, fmt};

use maki_crypto::SecretBuffer;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
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

/// What a response mapping reads at one position of a document: the
/// configured JSON pointers merged into a tree of their decoded tokens.
#[derive(Default)]
pub(super) struct Selection {
    /// Keep a string here (a payload).
    string: bool,
    /// Keep a number here (an echoed unit index).
    number: bool,
    /// Keep the first `limit` elements of an array here, each read by the
    /// boxed selection, and only count the rest (a batch's results).
    elements: Option<(usize, Box<Selection>)>,
    /// Object members by name, and array elements by index token.
    tokens: BTreeMap<String, Selection>,
}

impl Selection {
    /// The node a pointer names, created on demand. A pointer that is
    /// neither empty nor starts with `/` never resolves (`Value::pointer`),
    /// so it selects nothing.
    fn node(&mut self, pointer: &str) -> Option<&mut Self> {
        if pointer.is_empty() {
            return Some(self);
        }
        let tokens = pointer.strip_prefix('/')?;
        Some(tokens.split('/').fold(self, |node, token| {
            node.tokens
                .entry(super::decode_pointer_token(token))
                .or_default()
        }))
    }

    pub(super) fn string(&mut self, pointer: &str) {
        if let Some(node) = self.node(pointer) {
            node.string = true;
        }
    }

    pub(super) fn number(&mut self, pointer: &str) {
        if let Some(node) = self.node(pointer) {
            node.number = true;
        }
    }

    pub(super) fn elements(&mut self, pointer: &str, limit: usize, element: Selection) {
        if let Some(node) = self.node(pointer) {
            node.elements = Some((limit, Box::new(element)));
        }
    }
}

/// serde_json::Value's RFC 6901 array index rule: no sign, no leading zero.
fn array_index(token: &str) -> Option<usize> {
    if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
        return None;
    }
    token.parse().ok()
}

/// The parts of a response a [`Selection`] keeps. Lookups along selected
/// pointers give the same result as on the complete document.
pub(super) enum Value {
    /// A value the mapping does not read here: another type, or a container
    /// no configured pointer enters. It was validated, never copied.
    Skipped,
    Number(serde_json::Number),
    String(SecretString),
    /// The array's length and its kept elements by index, in index order.
    Array(usize, Vec<(usize, Value)>),
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
                    Self::Array(_, values) => {
                        let index = array_index(&token)?;
                        let at = values.binary_search_by_key(&index, |(i, _)| *i).ok()?;
                        Some(&values[at].1)
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

    /// The array's full length and the elements its selection kept.
    pub(super) fn as_array(&self) -> Option<(usize, &[(usize, Self)])> {
        match self {
            Self::Array(length, values) => Some((*length, values)),
            _ => None,
        }
    }
}

/// Parse one value, keeping what `self.0` selects.
struct Select<'s>(&'s Selection);

impl<'de> DeserializeSeed<'de> for Select<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Select<'_> {
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
        Ok(if self.0.number {
            Value::Number(value.into())
        } else {
            Value::Skipped
        })
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(if self.0.number {
            Value::Number(value.into())
        } else {
            Value::Skipped
        })
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(if self.0.number {
            serde_json::Number::from_f64(value).map_or(Value::Skipped, Value::Number)
        } else {
            Value::Skipped
        })
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(if self.0.string {
            Value::String(SecretString::from_str(value))
        } else {
            Value::Skipped
        })
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        // Adopt the owned string either way, so an unselected one is erased.
        let value = SecretString(SecretBuffer::from_vec(value.into_bytes()));
        Ok(if self.0.string {
            Value::String(value)
        } else {
            Value::Skipped
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let selection = self.0;
        let indices: Vec<(usize, &Selection)> = selection
            .tokens
            .iter()
            .filter_map(|(token, child)| Some((array_index(token)?, child)))
            .collect();
        if selection.elements.is_none() && indices.is_empty() {
            while sequence.next_element::<Skip>()?.is_some() {}
            return Ok(Value::Skipped);
        }
        let mut kept = Vec::new();
        let mut length = 0usize;
        loop {
            let child = match &selection.elements {
                Some((limit, element)) if length < *limit => Some(&**element),
                _ => indices
                    .iter()
                    .find(|(index, _)| *index == length)
                    .map(|(_, child)| *child),
            };
            match child {
                Some(child) => match sequence.next_element_seed(Select(child))? {
                    Some(value) => kept.push((length, value)),
                    None => break,
                },
                None => {
                    if sequence.next_element::<Skip>()?.is_none() {
                        break;
                    }
                }
            }
            length += 1;
        }
        Ok(Value::Array(length, kept))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let selection = self.0;
        if selection.tokens.is_empty() {
            while map.next_entry::<Skip, Skip>()?.is_some() {}
            return Ok(Value::Skipped);
        }
        let mut values = BTreeMap::new();
        while let Some(member) = map.next_key_seed(Member(&selection.tokens))? {
            match member {
                Some((key, child)) => {
                    // The key is already guarded if its value is malformed.
                    let value = map.next_value_seed(Select(child))?;
                    // Match serde_json's last-value-wins semantics. Replaced
                    // values and unused duplicate keys wipe on drop too.
                    values.insert(key, value);
                }
                None => {
                    map.next_value::<Skip>()?;
                }
            }
        }
        Ok(Value::Object(values))
    }
}

/// An object key, kept with the selection for its value only when a
/// configured pointer names it.
struct Member<'s>(&'s BTreeMap<String, Selection>);

impl<'de, 's> DeserializeSeed<'de> for Member<'s> {
    type Value = Option<(SecretString, &'s Selection)>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de, 's> Visitor<'de> for Member<'s> {
    type Value = Option<(SecretString, &'s Selection)>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object key")
    }

    fn visit_str<E: serde::de::Error>(self, key: &str) -> Result<Self::Value, E> {
        Ok(self
            .0
            .get(key)
            .map(|child| (SecretString::from_str(key), child)))
    }

    fn visit_string<E: serde::de::Error>(self, key: String) -> Result<Self::Value, E> {
        let key = SecretString(SecretBuffer::from_vec(key.into_bytes()));
        Ok(self.0.get(key.as_str()).map(|child| (key, child)))
    }
}

/// A value no configured pointer reaches. It is parsed through
/// `deserialize_any` like a kept value, not `deserialize_ignored_any`: the
/// latter skips serde_json's recursion limit and number range checks.
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
        drop(SecretBuffer::from_vec(value.into_bytes()));
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

pub(super) fn parse(bytes: &[u8], selection: &Selection) -> serde_json::Result<Value> {
    // Preserve serde_json's syntax, number, UTF-8, trailing-input and
    // recursion-limit checks (serde_json::from_slice with a seed).
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Select(selection).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

// The existing page-lock test owns the process-global locking setting and
// calls this while it is enabled, avoiding competing tests toggling it.
#[cfg(test)]
pub(super) fn check_json_page_locks() {
    use maki_crypto::secret::page_lock_failures;

    let before = page_lock_failures();
    let mut selection = Selection::default();
    selection.string("/key");
    let Value::Object(values) = parse(br#"{"key":"payload"}"#, &selection).unwrap() else {
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

    const WIRE: &[u8] = br#"{
        "": "empty", "a/b": {"m~n": ["first", "second"]},
        "~1": "escaped", "~2": "literal", "dupe": "first", "dupe": "last",
        "str": "escaped\n\u0051", "false": false, "null": null,
        "numbers": [0, -0, -1, 1.5, 1e0, 18446744073709551615],
        "nested": [{"x": [7, "seven"]}, {"x": [8, "eight"]}, {"x": 9}]
    }"#;

    const POINTERS: &[&str] = &[
        "",
        "/",
        "/a~1b",
        "/a~1b/m~0n",
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
        "/numbers",
        "/numbers/0",
        "/numbers/1",
        "/numbers/2",
        "/numbers/3",
        "/numbers/4",
        "/numbers/5",
        "/nested/1/x/1",
        "/nested/2/x",
        "/nested/0/x/0",
    ];

    /// A selection of `pointer` alone answers every lookup of it exactly as
    /// the complete serde_json document does.
    #[test]
    fn selected_pointers_match_the_complete_document() {
        let complete: serde_json::Value = serde_json::from_slice(WIRE).unwrap();
        for pointer in POINTERS {
            let expected = complete.pointer(pointer);
            let mut strings = Selection::default();
            strings.string(pointer);
            let mut numbers = Selection::default();
            numbers.number(pointer);
            let mut arrays = Selection::default();
            arrays.elements(pointer, 0, Selection::default());
            for (selection, kind) in [(strings, "string"), (numbers, "number"), (arrays, "array")] {
                let value = parse(WIRE, &selection).unwrap();
                let actual = value.pointer(pointer);
                assert_eq!(actual.is_some(), expected.is_some(), "{kind} {pointer}");
                match kind {
                    "string" => assert_eq!(
                        actual.and_then(Value::as_str),
                        expected.and_then(serde_json::Value::as_str),
                        "{pointer}"
                    ),
                    "number" => assert_eq!(
                        actual.and_then(Value::as_u64),
                        expected.and_then(serde_json::Value::as_u64),
                        "{pointer}"
                    ),
                    _ => assert_eq!(
                        actual.and_then(Value::as_array).map(|(length, _)| length),
                        expected.and_then(serde_json::Value::as_array).map(Vec::len),
                        "{pointer}"
                    ),
                }
            }
        }
    }

    /// Several pointers share one selection: each still resolves as on the
    /// complete document, and an array keeps only the selected elements.
    #[test]
    fn merged_selections_keep_only_what_they_name() {
        let complete: serde_json::Value = serde_json::from_slice(WIRE).unwrap();
        let mut selection = Selection::default();
        for pointer in ["/nested/1/x/1", "/a~1b/m~0n/1", "/dupe", "/str", "/~2"] {
            selection.string(pointer);
        }
        selection.number("/nested/0/x/0");
        let value = parse(WIRE, &selection).unwrap();
        for pointer in ["/nested/1/x/1", "/a~1b/m~0n/1", "/dupe", "/str", "/~2"] {
            assert_eq!(
                value.pointer(pointer).and_then(Value::as_str),
                complete
                    .pointer(pointer)
                    .and_then(serde_json::Value::as_str),
                "{pointer}"
            );
        }
        assert_eq!(
            value.pointer("/nested/0/x/0").and_then(Value::as_u64),
            Some(7)
        );
        let (length, kept) = value.pointer("/nested").unwrap().as_array().unwrap();
        assert_eq!(length, 3);
        assert_eq!(kept.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 1]);
        let (length, kept) = value.pointer("/a~1b/m~0n").unwrap().as_array().unwrap();
        assert_eq!((length, kept.len()), (2, 1));
        // Unselected members are not kept at all.
        assert!(value.pointer("/false").is_none());
        assert!(value.pointer("/numbers").is_none());
        assert_eq!(format!("{value:?}"), "ResponseValue(redacted)");
    }

    #[test]
    fn element_selection_keeps_a_prefix_and_counts_every_element() {
        let mut element = Selection::default();
        element.number("/x/0");
        let mut selection = Selection::default();
        selection.elements("/nested", 2, element);
        let value = parse(WIRE, &selection).unwrap();
        let (length, kept) = value.pointer("/nested").unwrap().as_array().unwrap();
        assert_eq!(length, 3);
        let echoes: Vec<_> = kept
            .iter()
            .map(|(i, element)| (*i, element.pointer("/x/0").and_then(Value::as_u64)))
            .collect();
        assert_eq!(echoes, [(0, Some(7)), (1, Some(8))]);
    }

    #[test]
    fn invalid_json_and_recursion_limit_are_still_refused_where_nothing_is_kept() {
        let nested =
            |open: &str, close: &str| format!("{}null{}", open.repeat(130), close.repeat(130));
        let deep_arrays = nested("[", "]");
        let deep_skipped = format!(r#"{{"data":"x","pad":{}}}"#, nested("[", "]"));
        let deep_objects = format!(r#"{{"data":"x","pad":{}}}"#, nested(r#"{"a":"#, "}"));
        let deep_element = format!(r#"{{"r":["x",{}]}}"#, nested("[", "]"));
        for wire in [
            br#"{"data":"x"} null"#.as_slice(),
            br#"{"data":"\uD800"}"#,
            br#"{"data":"x","pad":"\uD800"}"#,
            br#"{"data":"x","\uD800":0}"#,
            br#"{"number":1e999}"#,
            br#"{"data":"x","pad":[1e999]}"#,
            b"\"\xff\"",
            b"{\"data\":\"x\",\"pad\":\"\xff\"}",
            b"{\"data\":\"x\",\"\xff\":0}",
            br#"{"data":"x","pad":[1,]}"#,
            br#"{"data":"x","pad":{"a":}}"#,
            deep_arrays.as_bytes(),
            deep_skipped.as_bytes(),
            deep_objects.as_bytes(),
            deep_element.as_bytes(),
        ] {
            assert!(serde_json::from_slice::<serde_json::Value>(wire).is_err());
            let mut data = Selection::default();
            data.string("/data");
            data.string("/r/0");
            for selection in [Selection::default(), data] {
                assert!(parse(wire, &selection).is_err());
            }
        }
    }
}
