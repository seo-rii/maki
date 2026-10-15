//! Serialized size bounds for the fixed transport contracts and configured
//! HTTP response mappings. No payload or batch-sized allocation is needed.
//!
//! JSON bounds describe compact documents containing the mapped fields. A
//! remote peer's extra metadata, whitespace or redundant escaping still counts
//! against the hard response cap; no finite config can bound arbitrary extras.

use super::{invalid, BodyConfig, ConfigError, HttpOpConfig, VolumeConfig};

fn base64_len(bytes: u64) -> u64 {
    bytes.div_ceil(3).saturating_mul(4)
}

fn varint_len(value: u64) -> u64 {
    u64::from((64 - value.leading_zeros()).max(1).div_ceil(7))
}

fn delimited_len(bytes: u64) -> u64 {
    // Every field in the reference protobuf schema has a one-byte tag.
    1u64.saturating_add(varint_len(bytes)).saturating_add(bytes)
}

fn json_string_len(value: &str) -> u64 {
    value.bytes().fold(2, |length, byte| {
        length.saturating_add(match byte {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
            0..=31 => 6,
            _ => 1,
        })
    })
}

/// Object wrappers needed to reach a value through an RFC 6901 pointer.
/// Shared ancestors are counted twice when combining paths: conservative,
/// without constructing a potentially deeply nested JSON tree at validation.
fn pointer_overhead(pointer: &str) -> Result<u64, ConfigError> {
    if pointer.is_empty() {
        return Ok(0);
    }
    let tokens = pointer
        .strip_prefix('/')
        .ok_or_else(|| invalid("HTTP response JSON pointers must be empty or begin with '/'"))?;
    Ok(tokens.split('/').fold(0u64, |length, token| {
        let key = token.replace("~1", "/").replace("~0", "~");
        // {"key":VALUE}: braces and colon plus the serialized key.
        length.saturating_add(json_string_len(&key).saturating_add(3))
    }))
}

impl VolumeConfig {
    fn transport_batch_items(&self) -> Result<u64, ConfigError> {
        Ok(u64::from(self.crypto.batch.max_items)
            .min(self.crypto.batch.max_bytes.0 / u64::from(self.provider_plaintext_size()?).max(1)))
    }

    pub(super) fn grpc_message_bound(&self) -> Result<u64, ConfigError> {
        let count = self.transport_batch_items()?;
        let payload = u64::from(self.crypto.capabilities.max_ciphertext_size)
            .max(u64::from(self.provider_plaintext_size()?));
        // Worst legal unit index and format version, UUID text, profile text,
        // payload field, and each repeated item's nested-message delimiter.
        let item = 11u64.saturating_add(delimited_len(payload));
        let context = delimited_len(36)
            .saturating_add(delimited_len(
                self.crypto.effective_compatibility_id().len() as u64,
            ))
            .saturating_add(6);
        Ok(context
            .saturating_add(count.saturating_mul(delimited_len(item)))
            .max(self.crypto.batch.max_bytes.0))
    }

    pub(super) fn websocket_frame_bound(&self) -> Result<u64, ConfigError> {
        let count = self.transport_batch_items()?;
        let payload = u64::from(self.crypto.capabilities.max_ciphertext_size)
            .max(u64::from(self.provider_plaintext_size()?));
        // Count the real request shape, then substitute escaped profile and
        // repeated items. Encrypt/decrypt have equal-length operation names;
        // a successful response's {id,items} is strictly smaller.
        let envelope = r#"{"format":4294967295,"id":18446744073709551615,"items":[],"op":"decrypt","profile":,"volume":"00000000-0000-0000-0000-000000000000"}"#.len() as u64;
        let item = (r#"{"data":"","unit":18446744073709551615}"#.len() as u64)
            .saturating_add(base64_len(payload));
        let bound = envelope
            .saturating_add(json_string_len(&self.crypto.effective_compatibility_id()))
            .saturating_add(count.saturating_mul(item))
            .saturating_add(count.saturating_sub(1));
        Ok(bound.max(base64_len(self.crypto.batch.max_bytes.0)))
    }

    pub(super) fn http_response_bound(
        &self,
        op: &HttpOpConfig,
        encrypt: bool,
    ) -> Result<u64, ConfigError> {
        let batch = op.body.as_ref().is_some_and(BodyConfig::is_batch);
        let count = if batch {
            self.transport_batch_items()?
        } else {
            1
        };
        let payload = if encrypt {
            u64::from(self.crypto.capabilities.max_ciphertext_size)
        } else {
            u64::from(self.provider_plaintext_size()?)
        };
        let Some(response) = &op.response else {
            // An omitted response mapping is a raw single-item response.
            return Ok(payload);
        };
        if response.response_type == "raw" {
            if batch {
                return Err(invalid("batched HTTP responses require type = json"));
            }
            return Ok(payload);
        }
        let encoded = match response.encoding.as_deref().unwrap_or("base64") {
            "base64" => base64_len(payload),
            "base64url" => payload.saturating_mul(4).div_ceil(3),
            "hex" | "hex-lower" | "hex-upper" => payload.saturating_mul(2),
            _ => return Err(invalid("unsupported HTTP response payload encoding")),
        };
        let data_path = response.data_path.as_deref().unwrap_or("");
        if !batch && response.data_path.is_none() {
            return Err(invalid("single-item HTTP JSON response requires data_path"));
        }
        let mut item = pointer_overhead(data_path)?
            .saturating_add(encoded)
            .saturating_add(2);
        if batch {
            let index_path = response.item_index_path.as_deref().unwrap_or("");
            // These must address separate leaves; otherwise a JSON element
            // cannot contain both a string payload and a numeric echo.
            if data_path.is_empty()
                || index_path.is_empty()
                || data_path == index_path
                || data_path
                    .strip_prefix(index_path)
                    .is_some_and(|tail| tail.starts_with('/'))
                || index_path
                    .strip_prefix(data_path)
                    .is_some_and(|tail| tail.starts_with('/'))
            {
                return Err(invalid(
                    "HTTP batch payload and index paths must address separate fields",
                ));
            }
            item = item
                .saturating_add(pointer_overhead(index_path)?)
                .saturating_add(20)
                // Two independently wrapped objects merge into one: remove
                // two braces and add a comma. Shared ancestors overestimate.
                .saturating_sub(1);
            let wrapper = pointer_overhead(response.items_path.as_deref().unwrap_or(""))?;
            Ok(wrapper
                .saturating_add(2)
                .saturating_add(count.saturating_mul(item))
                .saturating_add(count.saturating_sub(1)))
        } else {
            Ok(item)
        }
    }
}
