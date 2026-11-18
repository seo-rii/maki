//! HTTP request field mappings (SPEC §18–§19).
//!
//! Configuration validation and the HTTP provider build a JSON request
//! mapping with the same [`BodyConfig::request_mapping`], so a body mapping
//! that validates is exactly one the provider constructs, and every mapped
//! field reaches the wire: an unknown source or encoding, an `encoding` the
//! source would ignore, a pointer the request builder cannot apply,
//! pointers that would replace one another, an item source the batch
//! encoder evaluates with no item, and `item_fields` a per-item body never
//! sends are all refused before a volume is created.

use std::collections::BTreeMap;

use super::{invalid, BodyConfig, ConfigError, FieldMapping};

/// Encoding of a binary payload in a JSON request field or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPayloadEncoding {
    /// `base64`: RFC 4648 §4 alphabet, padded. The default.
    Base64,
    /// `base64url`: RFC 4648 §5 alphabet, unpadded.
    Base64Url,
    /// `hex-lower` (alias `hex`).
    HexLower,
    /// `hex-upper`.
    HexUpper,
}

impl HttpPayloadEncoding {
    /// The configuration spelling of a payload encoding, or `None` for a
    /// name the provider does not implement.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "base64" => Some(Self::Base64),
            "base64url" => Some(Self::Base64Url),
            "hex-lower" | "hex" => Some(Self::HexLower),
            "hex-upper" => Some(Self::HexUpper),
            _ => None,
        }
    }
}

/// What a JSON request field carries. Only the payload is encoded; every
/// other source has one fixed JSON representation and takes no `encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFieldSource {
    /// The item's plaintext (encrypt) or ciphertext (decrypt), encoded.
    Payload(HttpPayloadEncoding),
    /// The item's unit index: an unsigned JSON integer.
    UnitIndex,
    /// The volume UUID: a lowercase, hyphenated JSON string.
    VolumeId,
    /// The crypto compatibility ID: a JSON string.
    CompatibilityId,
    /// The volume's on-disk format version: an unsigned JSON integer.
    FormatVersion,
    /// The item's position within its request: an unsigned JSON integer.
    BatchIndex,
}

impl HttpFieldSource {
    /// Whether the value belongs to one item (its payload, unit index or
    /// position) and so must be evaluated for each item: in `fields` of a
    /// per-item body, in `item_fields` of a batch.
    pub fn is_per_item(self) -> bool {
        matches!(self, Self::Payload(_) | Self::UnitIndex | Self::BatchIndex)
    }

    /// Parse a field mapping's `source` and optional `encoding`. The error
    /// says what is wrong, without a configuration section.
    pub fn parse(source: &str, encoding: Option<&str>) -> Result<Self, String> {
        let fixed = |parsed: Self, representation: &str| match encoding {
            None => Ok(parsed),
            Some(encoding) => Err(format!(
                "source {source:?} takes no encoding (got {encoding:?}): it is always sent as \
                 {representation}; only source = \"payload\" is encoded"
            )),
        };
        match source {
            "payload" => {
                let name = encoding.unwrap_or("base64");
                HttpPayloadEncoding::parse(name)
                    .map(Self::Payload)
                    .ok_or_else(|| {
                        format!(
                            "unknown payload encoding {name:?} (supported: base64, base64url, \
                             hex-lower, hex-upper)"
                        )
                    })
            }
            "unit_index" => fixed(Self::UnitIndex, "an unsigned JSON integer"),
            "volume_id" => fixed(Self::VolumeId, "a hyphenated UUID string"),
            "compatibility_id" => fixed(Self::CompatibilityId, "a JSON string"),
            "format_version" => fixed(Self::FormatVersion, "an unsigned JSON integer"),
            "batch_index" => fixed(Self::BatchIndex, "an unsigned JSON integer"),
            other => Err(format!(
                "unknown field source {other:?} (supported: payload, unit_index, volume_id, \
                 compatibility_id, format_version, batch_index)"
            )),
        }
    }
}

/// Decode one JSON Pointer reference token (RFC 6901 §4): `~1` is `/` and
/// `~0` is `~`, in that order, so `~01` decodes to `~1` and a literal
/// slash or tilde in a field name round-trips. The response side reads
/// with `serde_json`'s `Value::pointer`, which decodes the same way; the
/// request side must match it or a vendor field named `key/slot` is sent
/// as the wrong field `key~1slot` (BUG-024). Any other `~` is kept as is.
pub fn decode_pointer_token(token: &str) -> String {
    // A single allocation also avoids abandoning an intermediate decoded key
    // before the request mapping takes over its wipe duty.
    let mut decoded = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    while let Some(ch) = chars.next() {
        let replacement = if ch == '~' {
            match chars.peek() {
                Some('1') => Some('/'),
                Some('0') => Some('~'),
                _ => None,
            }
        } else {
            None
        };
        if let Some(replacement) = replacement {
            chars.next();
            decoded.push(replacement);
        } else {
            decoded.push(ch);
        }
    }
    decoded
}

/// The object keys a request pointer descends through, decoded; `None`
/// when the request builder cannot apply it (no leading `/`).
fn pointer_keys(pointer: &str) -> Option<Vec<String>> {
    pointer
        .strip_prefix('/')
        .map(|tokens| tokens.split('/').map(decode_pointer_token).collect())
}

/// A JSON request mapping, parsed exactly as the HTTP provider builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestMapping {
    /// Top-level fields, in the order the provider applies them.
    pub fields: Vec<(String, HttpFieldSource)>,
    /// Batch layout: where the array of per-item objects is inserted.
    pub items_path: Option<String>,
    /// Fields of each batch element; always empty without `items_path`
    /// (a per-item body would never send them, so they are refused).
    pub item_fields: Vec<(String, HttpFieldSource)>,
}

impl HttpRequestMapping {
    /// Fields evaluated once per item: `fields` of a per-item body,
    /// `item_fields` of a batch. Top-level batch fields are evaluated once
    /// per request, so they may carry only the context, never an item's
    /// payload, unit or position.
    pub fn per_item_fields(&self) -> &[(String, HttpFieldSource)] {
        match self.items_path {
            Some(_) => &self.item_fields,
            None => &self.fields,
        }
    }

    /// Every field the provider serializes.
    pub fn sent_fields(&self) -> impl Iterator<Item = &(String, HttpFieldSource)> {
        let items = self.items_path.as_ref().map(|_| &self.item_fields);
        self.fields.iter().chain(items.into_iter().flatten())
    }
}

struct Parsed {
    fields: Vec<(String, HttpFieldSource)>,
    keys: Vec<Vec<String>>,
}

fn parse_fields(
    section: &str,
    fields: &BTreeMap<String, FieldMapping>,
) -> Result<Parsed, ConfigError> {
    let mut parsed = Parsed {
        fields: Vec::with_capacity(fields.len()),
        keys: Vec::with_capacity(fields.len()),
    };
    for (pointer, mapping) in fields {
        let keys = pointer_keys(pointer).ok_or_else(|| {
            invalid(format!(
                "[{section}] request pointer {pointer:?} must start with '/'"
            ))
        })?;
        let source = HttpFieldSource::parse(&mapping.source, mapping.encoding.as_deref())
            .map_err(|error| invalid(format!("[{section}] {pointer:?}: {error}")))?;
        parsed.fields.push((pointer.clone(), source));
        parsed.keys.push(keys);
    }
    Ok(parsed)
}

/// One pointer applied to a JSON object: a mapped field, or the batch
/// `items_path`.
struct Applied<'a> {
    pointer: &'a str,
    keys: &'a [String],
    items_path: bool,
}

fn applied<'a>(parsed: &'a Parsed) -> impl Iterator<Item = Applied<'a>> {
    parsed
        .fields
        .iter()
        .zip(&parsed.keys)
        .map(|((pointer, _), keys)| Applied {
            pointer,
            keys,
            items_path: false,
        })
}

/// Refuse two pointers of one JSON object when one addresses the other or
/// a field inside it. The request builder applies pointers in order and
/// replaces: a later pointer below an earlier value turns that value into
/// an object, and a later equal or enclosing pointer overwrites the
/// earlier value or subtree. Either way a mapped field never reaches the
/// wire. Keys are compared decoded, so `~2` and `~02` are one key.
fn refuse_overlap(section: &str, mut entries: Vec<Applied<'_>>) -> Result<(), ConfigError> {
    // A pointer sorts directly before the pointers it is a prefix of, so
    // adjacent pairs are enough to find every overlap.
    entries.sort_by(|a, b| a.keys.cmp(b.keys));
    for pair in entries.windows(2) {
        let (first, second) = (&pair[0], &pair[1]);
        if !second.keys.starts_with(first.keys) {
            continue;
        }
        let message = if first.items_path || second.items_path {
            let (field, items) = if first.items_path {
                (second, first)
            } else {
                (first, second)
            };
            format!(
                "[{section}] field {:?} overlaps items_path {:?}: the batch array is inserted \
                 last and replaces any field at, under or above it, so the field never \
                 reaches the wire",
                field.pointer, items.pointer
            )
        } else {
            format!(
                "[{section}] request pointers {:?} and {:?} overlap: one addresses the other \
                 or a field inside it, so one mapped value replaces the other and never \
                 reaches the wire",
                first.pointer, second.pointer
            )
        };
        return Err(invalid(message));
    }
    Ok(())
}

impl BodyConfig {
    /// Parse a JSON body mapping as the HTTP provider builds it, refusing
    /// any mapping the provider cannot build or send as written: unknown
    /// sources and payload encodings, an `encoding` on a non-payload
    /// source, request pointers without a leading `/`, pointers whose
    /// fields would replace one another on the wire (including fields at,
    /// under or above a batch `items_path`), an item source (payload, unit
    /// index, position) among the top-level fields of a batch, and
    /// `item_fields` on a per-item body. `op` names the operation in
    /// errors. Does not look at `type`: a raw body sends no fields.
    pub fn request_mapping(&self, op: &str) -> Result<HttpRequestMapping, ConfigError> {
        let body = format!("crypto.http.{op}.body");
        let fields = parse_fields(&format!("{body}.fields"), &self.fields)?;
        let item_fields = parse_fields(&format!("{body}.item_fields"), &self.item_fields)?;
        if self.items_path.is_some() {
            // The batch encoder evaluates top-level fields once per request,
            // with no item: an item source there is sent as an empty payload
            // or 0 in every request.
            if let Some((pointer, _)) = fields.fields.iter().find(|(_, s)| s.is_per_item()) {
                return Err(invalid(format!(
                    "[{body}.fields] {pointer:?}: source {:?} describes one item, but a batch \
                     evaluates its top-level fields once per request, with no item, and would \
                     send an empty payload or 0; map it in item_fields",
                    self.fields[pointer].source
                )));
            }
        } else if !item_fields.fields.is_empty() {
            // A per-item body sends `fields` for each item and nothing else.
            return Err(invalid(format!(
                "[{body}.item_fields] are sent only inside a batch (items_path); a per-item \
                 body sends its fields once per item and would drop them, so map them in fields"
            )));
        }
        let items_keys = match &self.items_path {
            Some(path) => Some(pointer_keys(path).ok_or_else(|| {
                invalid(format!("[{body}] items_path {path:?} must start with '/'"))
            })?),
            None => None,
        };

        let mut top: Vec<Applied<'_>> = applied(&fields).collect();
        if let (Some(pointer), Some(keys)) = (&self.items_path, &items_keys) {
            top.push(Applied {
                pointer,
                keys,
                items_path: true,
            });
            // Each batch element is its own object.
            refuse_overlap(
                &format!("{body}.item_fields"),
                applied(&item_fields).collect(),
            )?;
        }
        refuse_overlap(&body, top)?;

        let mapping = HttpRequestMapping {
            fields: fields.fields,
            items_path: self.items_path.clone(),
            item_fields: item_fields.fields,
        };
        let sources = mapping.per_item_fields();
        if !sources
            .iter()
            .any(|(_, source)| matches!(source, HttpFieldSource::Payload(_)))
        {
            return Err(invalid(format!(
                "[{body}] must send a payload field for each item"
            )));
        }
        if mapping.items_path.is_some()
            && !sources
                .iter()
                .any(|(_, source)| *source == HttpFieldSource::UnitIndex)
        {
            return Err(invalid(format!("[{body}.item_fields] must send unit_index for the required response echo, independent of context_binding")));
        }
        Ok(mapping)
    }
}
