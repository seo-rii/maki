//! HTTP request field mappings: `validate()` must refuse every mapping the
//! HTTP provider cannot build or send as written, so `volume create` never
//! accepts a configuration whose attach, or every request, fails later.
//!
//! - Field sources and payload encodings were never validated: an unknown
//!   name was refused only at provider construction (attach), and an
//!   `encoding` on a non-payload source was silently dropped.
//! - A request pointer without a leading `/` validated, then failed every
//!   request.
//! - Request pointers are applied with replace semantics: an equal pointer,
//!   a pointer below another one (after RFC 6901 decoding), or a field at,
//!   under or above the batch `items_path` silently loses a mapped field, so
//!   a context field counted by the context-binding check (R3-006) never
//!   reached the wire.
//! - A declared context binding without a per-item `unit_index` validated,
//!   but the attach self-test's unit-index probe always refuses it.

use maki_format::config::parse_config;

const SINGLE_RESPONSE: &str = "data_path = \"/data\"\nencoding = \"base64\"\n";
const BATCH_RESPONSE: &str =
    "items_path = \"/items\"\nitem_index_path = \"/unit\"\ndata_path = \"/data\"\nencoding = \"base64\"\n";

/// A complete remote-http configuration. `body` is used for both
/// operations, with `{op}` replaced by the operation name.
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

/// A per-item JSON body: one request per unit, `fields` only.
fn single(context_binding: &str, fields: &str) -> String {
    config(
        context_binding,
        &format!("[crypto.http.{{op}}.body]\ntype = \"json\"\n[crypto.http.{{op}}.body.fields]\n{fields}\n"),
        SINGLE_RESPONSE,
    )
}

/// A batched JSON body with the request array at `items_path`.
fn batch_at(context_binding: &str, items_path: &str, fields: &str, item_fields: &str) -> String {
    config(
        context_binding,
        &format!(
            "[crypto.http.{{op}}.body]\ntype = \"json\"\nitems_path = {items_path:?}\n\
             [crypto.http.{{op}}.body.fields]\n{fields}\n\
             [crypto.http.{{op}}.body.item_fields]\n{item_fields}\n"
        ),
        BATCH_RESPONSE,
    )
}

fn batch(context_binding: &str, fields: &str, item_fields: &str) -> String {
    batch_at(context_binding, "/items", fields, item_fields)
}

fn validate(raw: &str) -> Result<(), String> {
    parse_config(raw)
        .unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
        .validate()
        .map_err(|e| e.to_string())
}

fn assert_refused(raw: &str, needles: &[&str], case: &str) {
    match validate(raw) {
        Ok(()) => panic!("validated a mapping the provider cannot send as written: {case}"),
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

const PAYLOAD: &str = "\"/data\" = { source = \"payload\", encoding = \"base64\" }\n";
const UNIT: &str = "\"/unit\" = { source = \"unit_index\" }\n";
const CONTEXT: &str = "\"/volume\" = { source = \"volume_id\" }\n\
                       \"/profile\" = { source = \"compatibility_id\" }\n\
                       \"/format\" = { source = \"format_version\" }\n";

#[test]
fn unknown_field_sources_are_refused() {
    for source in ["volume_uuid", "plaintext", "Payload", ""] {
        let mapping = format!("\"/x\" = {{ source = {source:?} }}\n");
        assert_refused(
            &single("none", &format!("{PAYLOAD}{mapping}")),
            &["source"],
            &format!("fields source {source:?}"),
        );
        assert_refused(
            &batch("none", "", &format!("{PAYLOAD}{UNIT}{mapping}")),
            &["source"],
            &format!("item_fields source {source:?}"),
        );
    }
}

#[test]
fn unknown_payload_encodings_are_refused() {
    for encoding in [
        "utf8", "base-64", "base85", "integer", "uuid", "raw", "HEX", "",
    ] {
        let payload = format!("\"/data\" = {{ source = \"payload\", encoding = {encoding:?} }}\n");
        assert_refused(
            &single("none", &payload),
            &["encoding"],
            &format!("fields payload encoding {encoding:?}"),
        );
        assert_refused(
            &batch("none", "", &format!("{payload}{UNIT}")),
            &["encoding"],
            &format!("item_fields payload encoding {encoding:?}"),
        );
    }
}

/// Only the payload is encoded; every other source has one fixed JSON
/// representation. An `encoding` there used to be accepted and ignored, so
/// `unit_index` with `encoding = "utf8"` was still sent as a number.
#[test]
fn an_encoding_on_a_non_payload_source_is_refused() {
    for source in [
        "unit_index",
        "volume_id",
        "compatibility_id",
        "format_version",
        "batch_index",
    ] {
        for encoding in ["utf8", "integer", "uuid", "base64"] {
            let mapping = format!("\"/x\" = {{ source = {source:?}, encoding = {encoding:?} }}\n");
            assert_refused(
                &single("none", &format!("{PAYLOAD}{mapping}")),
                &["encoding", source],
                &format!("{source} with encoding {encoding:?}"),
            );
        }
    }
}

#[test]
fn every_supported_source_and_payload_encoding_validates() {
    for encoding in ["base64", "base64url", "hex", "hex-lower", "hex-upper"] {
        let payload = format!("\"/data\" = {{ source = \"payload\", encoding = {encoding:?} }}\n");
        validate(&single("none", &payload)).unwrap();
        validate(&batch("none", "", &format!("{payload}{UNIT}"))).unwrap();
    }
    validate(&single("none", "\"/data\" = { source = \"payload\" }\n")).unwrap();
    validate(&single(
        "contractual",
        &format!("{PAYLOAD}{UNIT}{CONTEXT}\"/ordinal\" = {{ source = \"batch_index\" }}\n"),
    ))
    .unwrap();
}

/// A request pointer without a leading `/` validated, then every request
/// failed with "JSON pointer ... must start with '/'".
#[test]
fn request_pointers_must_start_with_a_slash() {
    for pointer in ["data", "", "~1data"] {
        let payload = format!("{pointer:?} = {{ source = \"payload\" }}\n");
        assert_refused(
            &single("none", &payload),
            &["must start with"],
            &format!("fields pointer {pointer:?}"),
        );
        assert_refused(
            &batch("none", "", &format!("{payload}{UNIT}")),
            &["must start with"],
            &format!("item_fields pointer {pointer:?}"),
        );
    }
    assert_refused(
        &batch_at("none", "items", "", &format!("{PAYLOAD}{UNIT}")),
        &["items_path", "must start with"],
        "items_path without a slash",
    );
}

/// Pointers are applied in order with replace semantics: a later pointer
/// below an earlier scalar replaces it with an object, and an equal pointer
/// (after RFC 6901 decoding) replaces the earlier value.
#[test]
fn overlapping_request_pointers_are_refused() {
    for (case, fields) in [
        (
            "volume replaced by a nested profile",
            "\"/volume\" = { source = \"volume_id\" }\n\"/volume/profile\" = { source = \"compatibility_id\" }\n",
        ),
        (
            "payload replaced by a nested field",
            "\"/data/unit\" = { source = \"unit_index\" }\n",
        ),
        (
            "two spellings of one field",
            "\"/x~2\" = { source = \"volume_id\" }\n\"/x~02\" = { source = \"format_version\" }\n",
        ),
        (
            "the empty key and a key below it",
            "\"/\" = { source = \"volume_id\" }\n\"//\" = { source = \"format_version\" }\n",
        ),
    ] {
        assert_refused(
            &single("none", &format!("{PAYLOAD}{fields}")),
            &["overlap"],
            case,
        );
        assert_refused(
            &batch("none", "", &format!("{PAYLOAD}{UNIT}{fields}")),
            &["overlap"],
            &format!("item_fields: {case}"),
        );
    }
}

/// The batch array is inserted last and replaces whatever a top-level field
/// put at, under or above `items_path`.
#[test]
fn fields_at_under_or_above_items_path_are_refused() {
    let items = format!("{PAYLOAD}{UNIT}");
    for (case, items_path, field) in [
        ("field at items_path", "/items", "/items"),
        ("field under items_path", "/items", "/items/volume"),
        ("field above items_path", "/request/items", "/request"),
        ("same key spelled differently", "/it~02ems", "/it~2ems"),
    ] {
        let fields = format!("{field:?} = {{ source = \"volume_id\" }}\n");
        assert_refused(
            &batch_at("none", items_path, &fields, &items),
            &["items_path"],
            case,
        );
    }
}

/// Distinct fields that merely share a textual prefix, or nest as siblings,
/// all reach the wire.
#[test]
fn distinct_request_pointers_validate() {
    validate(&single(
        "none",
        &format!(
            "{PAYLOAD}\"/vol\" = {{ source = \"volume_id\" }}\n\"/volume\" = {{ source = \"volume_id\" }}\n\
             \"/a~1b\" = {{ source = \"format_version\" }}\n\"/a/b\" = {{ source = \"format_version\" }}\n\
             \"/ctx/profile\" = {{ source = \"compatibility_id\" }}\n\"/ctx/format\" = {{ source = \"format_version\" }}\n"
        ),
    ))
    .unwrap();
    validate(&batch_at(
        "none",
        "/request/items",
        "\"/request/volume\" = { source = \"volume_id\" }\n\"/itemsx\" = { source = \"format_version\" }\n",
        &format!("{PAYLOAD}{UNIT}"),
    ))
    .unwrap();
}

/// The audit reproduction: `/ctx` (volume_id) is replaced by `/ctx/format`,
/// and in a batch a field under `items_path` by the items array; both were
/// counted as sent by the context-binding check.
#[test]
fn overlapping_context_pointers_do_not_satisfy_context_binding() {
    let fields = "\"/ctx\" = { source = \"volume_id\" }\n\
                  \"/ctx/format\" = { source = \"format_version\" }\n\
                  \"/profile\" = { source = \"compatibility_id\" }\n";
    assert_refused(
        &single("contractual", &format!("{PAYLOAD}{UNIT}{fields}")),
        &["overlap"],
        "single layout",
    );
    assert_refused(
        &batch("contractual", fields, &format!("{PAYLOAD}{UNIT}")),
        &["overlap"],
        "batch layout",
    );
    let under_items = "\"/items/volume\" = { source = \"volume_id\" }\n\
                       \"/format\" = { source = \"format_version\" }\n\
                       \"/profile\" = { source = \"compatibility_id\" }\n";
    assert_refused(
        &batch("contractual", under_items, &format!("{PAYLOAD}{UNIT}")),
        &["items_path"],
        "context field under items_path",
    );
}

/// The attach self-test probes the unit index along with the context, so a
/// declared binding needs the unit index in every item: in `fields` of a
/// per-item body, in `item_fields` of a batch (top-level batch fields carry
/// no unit).
#[test]
fn declared_context_binding_requires_a_per_item_unit_index() {
    assert_refused(
        &single("contractual", &format!("{PAYLOAD}{CONTEXT}")),
        &["unit_index", "context_binding"],
        "per-item body without unit_index",
    );
    assert_refused(
        &batch("contractual", CONTEXT, PAYLOAD),
        &["unit_index", "context_binding"],
        "batch without unit_index",
    );
    // A top-level unit index of a batch is refused whatever the binding:
    // it is sent as 0 (review_http_item_sources.rs).
    assert_refused(
        &batch("contractual", &format!("{CONTEXT}{UNIT}"), PAYLOAD),
        &["unit_index", "item_fields"],
        "batch with unit_index only at the top level",
    );
    assert_refused(
        &single("verified", &format!("{PAYLOAD}{CONTEXT}")),
        &["unit_index", "context_binding"],
        "verified context binding without unit_index",
    );

    validate(&single("contractual", &format!("{PAYLOAD}{UNIT}{CONTEXT}"))).unwrap();
    validate(&batch("contractual", CONTEXT, &format!("{PAYLOAD}{UNIT}"))).unwrap();
    validate(&batch(
        "contractual",
        "",
        &format!("{PAYLOAD}{UNIT}{CONTEXT}"),
    ))
    .unwrap();
    // Without a declared binding the unit index stays optional.
    validate(&single("none", &format!("{PAYLOAD}{CONTEXT}"))).unwrap();
}

/// Every shipped or documented complete HTTP configuration still validates.
#[test]
fn shipped_http_configurations_still_validate() {
    let spec = include_str!("../../../SPEC.md");
    let mut fences = Vec::new();
    let mut current: Option<String> = None;
    for line in spec.lines() {
        match &mut current {
            None if line.trim_start().starts_with("```toml") => current = Some(String::new()),
            Some(body) if line.trim_start().starts_with("```") => {
                fences.push(std::mem::take(body));
                current = None;
            }
            Some(body) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    let complete: Vec<_> = fences
        .iter()
        .filter(|f| f.contains("config_schema_version") && f.contains("remote-http"))
        .collect();
    assert!(!complete.is_empty(), "SPEC §57 example not found");
    for fence in complete {
        validate(fence).unwrap();
    }
    validate(include_str!(
        "../../../packaging/examples/postgres-prod.toml"
    ))
    .unwrap();
    validate(include_str!("data/full_config.toml")).unwrap();

    // The SPEC §19 mapping example shows the encrypt operation of a
    // per-item body; it carries the whole context, so it also satisfies a
    // declared context binding.
    let example = fences
        .iter()
        .find(|f| f.contains("[crypto.http.encrypt.body.fields]") && !f.contains("[volume]"))
        .expect("SPEC §19 example not found");
    let encrypt = &example[example.find("[crypto.http.encrypt]").unwrap()..];
    let decrypt = encrypt.replace("crypto.http.encrypt", "crypto.http.decrypt");
    for binding in ["none", "contractual"] {
        let raw = config(binding, "", "");
        let head = &raw[..raw.find("[crypto.http.encrypt]").unwrap()];
        validate(&format!(
            "{head}{encrypt}\n{decrypt}\n[backing]\nroot = \"/x\"\n"
        ))
        .unwrap();
    }
}
