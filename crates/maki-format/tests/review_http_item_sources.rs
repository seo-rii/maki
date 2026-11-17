//! HTTP JSON body fields that validated but never carry what they name:
//!
//! - A batch body evaluates its top-level `fields` once per request, with
//!   no item, so a `payload`, `unit_index` or `batch_index` source there was
//!   sent as an empty payload or 0 in every request. Those sources describe
//!   one item and belong in `item_fields`.
//! - A per-item body (no `items_path`) sends `fields` once per item and
//!   never sends `item_fields`, which were parsed and silently dropped.

use maki_format::config::parse_config;

const SINGLE_RESPONSE: &str = "data_path = \"/data\"\nencoding = \"base64\"\n";
const BATCH_RESPONSE: &str =
    "items_path = \"/items\"\nitem_index_path = \"/unit\"\ndata_path = \"/data\"\nencoding = \"base64\"\n";

const PAYLOAD: &str = "\"/data\" = { source = \"payload\", encoding = \"base64\" }\n";
const UNIT: &str = "\"/unit\" = { source = \"unit_index\" }\n";
const CONTEXT: &str = "\"/volume\" = { source = \"volume_id\" }\n\
                       \"/profile\" = { source = \"compatibility_id\" }\n\
                       \"/format\" = { source = \"format_version\" }\n";

/// A complete remote-http configuration with `body` (`{op}` replaced by the
/// operation name) and `response` for both operations.
fn config(context_binding: &str, body: &str, response: &str) -> String {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n{}\n[crypto.http.{op}.response]\n{response}\n",
            body.replace("{op}", op)
        );
    }
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
context_binding = "{context_binding}"
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
{ops}
[backing]
root = "/x"
"#
    )
}

/// A per-item JSON body (no `items_path`) with both field tables.
fn single(context_binding: &str, fields: &str, item_fields: &str) -> String {
    config(
        context_binding,
        &format!(
            "[crypto.http.{{op}}.body]\ntype = \"json\"\n\
             [crypto.http.{{op}}.body.fields]\n{fields}\n\
             [crypto.http.{{op}}.body.item_fields]\n{item_fields}\n"
        ),
        SINGLE_RESPONSE,
    )
}

/// A batched JSON body with the request array at `/items`.
fn batch(context_binding: &str, fields: &str, item_fields: &str) -> String {
    config(
        context_binding,
        &format!(
            "[crypto.http.{{op}}.body]\ntype = \"json\"\nitems_path = \"/items\"\n\
             [crypto.http.{{op}}.body.fields]\n{fields}\n\
             [crypto.http.{{op}}.body.item_fields]\n{item_fields}\n"
        ),
        BATCH_RESPONSE,
    )
}

fn validate(raw: &str) -> Result<(), String> {
    parse_config(raw)
        .unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
        .validate()
        .map_err(|e| e.to_string())
}

fn assert_refused(raw: &str, needles: &[&str], case: &str) {
    match validate(raw) {
        Ok(()) => panic!("validated a field the request never carries: {case}"),
        Err(error) => {
            for needle in needles {
                assert!(
                    error.contains(needle),
                    "{case}: error lacks {needle:?}: {error}"
                );
            }
        }
    }
}

#[test]
fn item_sources_in_top_level_batch_fields_are_refused() {
    for source in ["payload", "unit_index", "batch_index"] {
        let field = format!("\"/top\" = {{ source = {source:?} }}\n");
        for binding in ["none", "contractual"] {
            assert_refused(
                &batch(
                    binding,
                    &format!("{CONTEXT}{field}"),
                    &format!("{PAYLOAD}{UNIT}"),
                ),
                &[source, "item_fields", "/top"],
                &format!("top-level {source} in a batch, context_binding = {binding}"),
            );
        }
    }
}

#[test]
fn item_fields_of_a_per_item_body_are_refused() {
    for item_fields in [
        "\"/ordinal\" = { source = \"batch_index\" }\n",
        "\"/payload\" = { source = \"payload\" }\n",
        CONTEXT,
    ] {
        for binding in ["none", "contractual"] {
            assert_refused(
                &single(binding, &format!("{PAYLOAD}{UNIT}{CONTEXT}"), item_fields),
                &["item_fields", "items_path"],
                &format!("per-item body with item_fields {item_fields:?}, {binding}"),
            );
        }
    }
}

#[test]
fn fields_the_request_carries_still_validate() {
    for binding in ["none", "contractual"] {
        // Context at the top level of a batch, item sources per element.
        validate(&batch(binding, CONTEXT, &format!("{PAYLOAD}{UNIT}"))).unwrap();
        validate(&batch(
            binding,
            "",
            &format!("{PAYLOAD}{UNIT}{CONTEXT}\"/ordinal\" = {{ source = \"batch_index\" }}\n"),
        ))
        .unwrap();
        // A per-item body carries every source in `fields`; an empty
        // `item_fields` table sends nothing and loses nothing.
        validate(&single(
            binding,
            &format!("{PAYLOAD}{UNIT}{CONTEXT}\"/ordinal\" = {{ source = \"batch_index\" }}\n"),
            "",
        ))
        .unwrap();
    }
    // A raw body sends the payload alone and is not a JSON mapping.
    let raw = config(
        "none",
        "[crypto.http.{op}.body]\ntype = \"raw\"\n",
        SINGLE_RESPONSE,
    );
    validate(&raw).unwrap();
}
