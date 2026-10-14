//! R3-006 follow-up: a remote-http configuration that declares context
//! binding must carry the whole crypto context in its request bodies, or the
//! provider cannot possibly bind to it and every attach fails at the
//! self-test instead of at validation.

use maki_format::config::parse_config;

fn config(context_binding: &str, fields: &str) -> String {
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
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
{fields}
[crypto.http.encrypt.response]
data_path = "/ct"
encoding = "base64"
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.body.fields]
"/data" = {{ source = "payload", encoding = "base64" }}
{fields}
[crypto.http.decrypt.response]
data_path = "/pt"
encoding = "base64"
[backing]
root = "/x"
"#
    )
}

const FULL_CONTEXT: &str = r#"
"/volume" = { source = "volume_id" }
"/profile" = { source = "compatibility_id" }
"/format" = { source = "format_version" }
"#;

fn validate(raw: &str) -> Result<(), String> {
    parse_config(raw)
        .map_err(|e| e.to_string())?
        .validate()
        .map_err(|e| e.to_string())
}

#[test]
fn declared_context_binding_requires_every_context_field_on_the_wire() {
    validate(&config("contractual", FULL_CONTEXT)).unwrap();
    for missing in ["volume_id", "compatibility_id", "format_version"] {
        let fields: String = FULL_CONTEXT
            .lines()
            .filter(|line| !line.contains(missing))
            .collect::<Vec<_>>()
            .join("\n");
        let err = validate(&config("contractual", &fields))
            .expect_err("a context binding without the field on the wire must be refused");
        assert!(
            err.contains(missing) && err.contains("context_binding"),
            "missing {missing}: {err}"
        );
    }
}

#[test]
fn without_context_binding_the_context_fields_are_optional() {
    validate(&config("none", "")).unwrap();
}

/// BUG-093: only mappings the HTTP provider actually sends can carry the
/// context. A raw body sends the payload alone, and a per-item JSON body
/// (no `items_path`) sends `fields` but never `item_fields`; counting those
/// let a configuration validate and then fail the attach self-test (R3-006).
#[test]
fn context_fields_count_only_where_the_provider_sends_them() {
    // Context declared only in item_fields of a per-item body.
    let mut item_fields_only = config("contractual", "");
    for op in ["encrypt", "decrypt"] {
        item_fields_only = item_fields_only.replace(
            &format!("[crypto.http.{op}.response]"),
            &format!(
                "[crypto.http.{op}.body.item_fields]\n{FULL_CONTEXT}\n[crypto.http.{op}.response]"
            ),
        );
    }
    let err = validate(&item_fields_only).expect_err("item_fields are not sent per item");
    assert!(err.contains("context_binding"), "{err}");

    // Context declared in the fields of a raw body.
    let mut raw = config("contractual", FULL_CONTEXT);
    for op in ["encrypt", "decrypt"] {
        raw = raw.replace(
            &format!("[crypto.http.{op}.body.fields]"),
            &format!("[crypto.http.{op}.body]\ntype = \"raw\"\n[crypto.http.{op}.body.fields]"),
        );
    }
    let err = validate(&raw).expect_err("a raw body sends no fields");
    assert!(err.contains("context_binding"), "{err}");

    // Control: the same context in item_fields of a batched body is sent.
    let mut batched = String::new();
    for op in ["encrypt", "decrypt"] {
        batched += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n[crypto.http.{op}.body]\nitems_path = \"/items\"\n\
             [crypto.http.{op}.body.item_fields]\n\"/data\" = {{ source = \"payload\", encoding = \"base64\" }}\n\
             \"/unit\" = {{ source = \"unit_index\" }}\n{FULL_CONTEXT}\n\
             [crypto.http.{op}.response]\nitems_path = \"/items\"\nitem_index_path = \"/unit\"\n\
             data_path = \"/data\"\nencoding = \"base64\"\n"
        );
    }
    let head = config("contractual", "");
    let head = &head[..head.find("[crypto.http.encrypt]").unwrap()];
    validate(&format!("{head}{batched}[backing]\nroot = \"/x\"\n")).unwrap();
}

/// BUG-093: a raw body is always sent one item per request, even with a
/// stray `items_path`; only a JSON body with `items_path` is a batch.
#[test]
fn a_raw_body_with_items_path_counts_as_one_item_per_batch() {
    let mut raw = config("none", "");
    for op in ["encrypt", "decrypt"] {
        raw = raw.replace(
            &format!("[crypto.http.{op}.body.fields]"),
            &format!("[crypto.http.{op}.body]\ntype = \"raw\"\nitems_path = \"/items\"\n[crypto.http.{op}.body.fields]"),
        );
    }
    let config = parse_config(&raw).unwrap();
    config.validate().unwrap();
    assert_eq!(config.effective_batch_max_items(), 1);
}
