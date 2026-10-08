//! Dynamic request mappings contain only borrowed payloads and metadata.
//! Serialization counts first, then writes directly into fixed guarded storage.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use base64::display::Base64Display;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use maki_crypto::{CryptoContext, CryptoError, SecretBuffer};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use zeroize::Zeroize;

use super::{decode_pointer_token, fatal, FieldSource, PayloadEncoding};

// Keys are configuration metadata, but retain the previous request tree's
// erasure on duplicate keys, replaced subtrees, errors and normal completion.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key(String);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

enum MappedValue<'a> {
    Object(BTreeMap<Key, Self>),
    Array(Vec<Self>),
    Scalar(Scalar<'a>),
}

impl<'a> MappedValue<'a> {
    fn object() -> Self {
        Self::Object(BTreeMap::new())
    }

    fn set(&mut self, pointer: &str, value: Self) -> Result<(), CryptoError> {
        let mut tokens = pointer
            .strip_prefix('/')
            .ok_or_else(|| fatal(format!("JSON pointer {pointer:?} must start with '/'")))?
            .split('/')
            .peekable();
        let mut current = self;
        while let Some(token) = tokens.next() {
            if !matches!(current, Self::Object(_)) {
                *current = Self::object();
            }
            let Self::Object(map) = current else {
                unreachable!("request pointer descent creates an object")
            };
            let key = Key(decode_pointer_token(token));
            if tokens.peek().is_none() {
                // BTreeMap retains the original key on replacement. Key's
                // Drop erases the unused incoming key as well as old subtrees.
                map.insert(key, value);
                return Ok(());
            }
            current = map.entry(key).or_insert_with(Self::object);
        }
        Err(fatal(format!("empty JSON pointer {pointer:?}")))
    }
}

impl Serialize for MappedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Object(fields) => {
                // Match serde_json's default Value object key order, after
                // decoding reference tokens rather than sorting raw pointers.
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(&key.0, value)?;
                }
                map.end()
            }
            Self::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
            Self::Scalar(value) => value.serialize(serializer),
        }
    }
}

enum Scalar<'a> {
    Payload(PayloadEncoding, &'a [u8]),
    Number(u64),
    Text(&'a str),
    Uuid(&'a uuid::Uuid),
}

impl<'a> Scalar<'a> {
    fn from_source(
        source: &FieldSource,
        context: &'a CryptoContext,
        unit_index: u64,
        batch_index: usize,
        payload: &'a [u8],
    ) -> Self {
        match source {
            FieldSource::Payload(encoding) => Self::Payload(*encoding, payload),
            FieldSource::UnitIndex => Self::Number(unit_index),
            FieldSource::VolumeId => Self::Uuid(&context.volume_uuid),
            FieldSource::CompatibilityId => Self::Text(&context.crypto_compatibility_id),
            FieldSource::FormatVersion => Self::Number(u64::from(context.format_version)),
            FieldSource::BatchIndex => Self::Number(batch_index as u64),
        }
    }
}

impl Serialize for Scalar<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Payload(PayloadEncoding::Base64, payload) => {
                serializer.collect_str(&Base64Display::new(payload, &STANDARD))
            }
            Self::Payload(PayloadEncoding::Base64Url, payload) => {
                serializer.collect_str(&Base64Display::new(payload, &URL_SAFE_NO_PAD))
            }
            Self::Payload(encoding, payload) => serializer.collect_str(&HexDisplay {
                bytes: payload,
                upper: matches!(encoding, PayloadEncoding::HexUpper),
            }),
            Self::Number(number) => serializer.serialize_u64(*number),
            Self::Text(text) => serializer.serialize_str(text),
            Self::Uuid(uuid) => uuid.serialize(serializer),
        }
    }
}

struct HexDisplay<'a> {
    bytes: &'a [u8],
    upper: bool,
}

impl fmt::Display for HexDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = if self.upper {
            b"0123456789ABCDEF"
        } else {
            b"0123456789abcdef"
        };
        let mut encoded = [0; 128];
        for chunk in self.bytes.chunks(encoded.len() / 2) {
            for (byte, pair) in chunk.iter().zip(encoded.chunks_exact_mut(2)) {
                pair[0] = digits[usize::from(byte >> 4)];
                pair[1] = digits[usize::from(byte & 0x0f)];
            }
            let text = std::str::from_utf8(&encoded[..chunk.len() * 2])
                .expect("hexadecimal digits are ASCII");
            formatter.write_str(text)?;
        }
        Ok(())
    }
}

pub(super) fn encode_single(
    fields: &[(String, FieldSource)],
    context: &CryptoContext,
    unit_index: u64,
    batch_index: usize,
    payload: &[u8],
) -> Result<SecretBuffer, CryptoError> {
    let mut root = MappedValue::object();
    for (pointer, source) in fields {
        root.set(
            pointer,
            MappedValue::Scalar(Scalar::from_source(
                source,
                context,
                unit_index,
                batch_index,
                payload,
            )),
        )?;
    }
    encode(&root)
}

pub(super) fn encode_batch(
    fields: &[(String, FieldSource)],
    items_path: &str,
    item_fields: &[(String, FieldSource)],
    context: &CryptoContext,
    items: &[(u64, SecretBuffer)],
) -> Result<SecretBuffer, CryptoError> {
    let mut root = MappedValue::object();
    for (pointer, source) in fields {
        root.set(
            pointer,
            MappedValue::Scalar(Scalar::from_source(source, context, 0, 0, &[])),
        )?;
    }
    let mut array = Vec::with_capacity(items.len());
    for (batch_index, (unit_index, payload)) in items.iter().enumerate() {
        let mut element = MappedValue::object();
        for (pointer, source) in item_fields {
            element.set(
                pointer,
                MappedValue::Scalar(Scalar::from_source(
                    source,
                    context,
                    *unit_index,
                    batch_index,
                    payload.expose(),
                )),
            )?;
        }
        array.push(element);
    }
    // The batch insertion deliberately occurs last and may replace earlier
    // scalars or subtrees. Empty batches do not evaluate any item mappings.
    root.set(items_path, MappedValue::Array(array))?;
    encode(&root)
}

pub(super) struct LengthCounter {
    pub(super) bytes: usize,
}

impl Write for LengthCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|length| *length <= isize::MAX as usize)
            .ok_or_else(|| io::Error::other("serialized request size overflow"))?;
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize) -> Result<SecretBuffer, CryptoError> {
    let mut counter = LengthCounter { bytes: 0 };
    serde_json::to_writer(&mut counter, value)
        .map_err(|e| CryptoError::NonRetryableRequest(format!("request encode failed: {e}")))?;
    serialize_fixed(value, counter.bytes)
}

pub(super) fn serialize_fixed(
    value: &impl Serialize,
    length: usize,
) -> Result<SecretBuffer, CryptoError> {
    struct GuardedWriter<'a>(&'a mut SecretBuffer);
    impl Write for GuardedWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .try_extend_from_slice(bytes)
                .map_err(|_| io::Error::other("serialized request size changed"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Guard the final allocation before the first encoded byte is written;
    // fixed capacity prevents growth from abandoning a plaintext allocation.
    let mut encoded = SecretBuffer::with_capacity(length).map_err(|_| {
        CryptoError::NonRetryableRequest(format!(
            "serialized request of {length} bytes cannot be allocated"
        ))
    })?;
    serde_json::to_writer(GuardedWriter(&mut encoded), value)
        .map_err(|e| CryptoError::NonRetryableRequest(format!("request encode failed: {e}")))?;
    if encoded.len() != length {
        return Err(CryptoError::NonRetryableRequest(
            "request encode failed: serialized request size changed".into(),
        ));
    }
    Ok(encoded)
}
