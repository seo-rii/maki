//! Audit (config-format): settings `validate()` accepts although a later
//! stage always refuses or silently ignores them, and validation errors that
//! echo values the rest of the code treats as possibly secret.

use maki_format::canary::CANARY_UNIT_INDEX;
use maki_format::config::{parse_config, VolumeConfig};

const SECRET: &str = "S3NT1NEL0123456789abcdef";

fn remote_http(encrypt_extra: &str, encrypt_path: &str) -> String {
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
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.http.encrypt]
path = "{encrypt_path}"
{encrypt_extra}
[crypto.http.encrypt.response]
data_path = "/ct"
encoding = "base64"
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.response]
data_path = "/pt"
encoding = "base64"
[backing]
root = "/x"
"#
    )
}

fn local(key: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {key}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/x"
"#
    )
}

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
}

/// BUG-174 redacts HTTP operation paths in every Debug output because they
/// can carry path or query tokens; the validation error prints the path.
#[test]
fn an_invalid_operation_path_is_not_echoed_into_the_error() {
    let raw = remote_http("", &format!("v1/encrypt?api_key={SECRET}"));
    let error = parse(&raw).validate().expect_err("path without a slash");
    let (display, debug) = (error.to_string(), format!("{error:?}"));
    assert!(
        !display.contains(SECRET) && !debug.contains(SECRET),
        "validation error echoed the operation path's token: {display}"
    );
}

/// A credential template without exactly one `{}` sends its literal text
/// and drops the loaded credential (daemon.rs / maki-crypto-http lib.rs
/// split the template on "{}"): a literal secret passes the SPEC §9 check.
#[test]
fn a_credential_template_without_a_placeholder_is_refused() {
    let headers = format!(
        "[crypto.http.encrypt.headers]\nAuthorization = {{ source = \"credential\", name = \"tok\", format = \"Bearer {SECRET}\" }}\n"
    );
    let raw = remote_http(&headers, "/encrypt");
    assert!(
        parse(&raw).validate().is_err(),
        "a literal bearer token inside `format` (no placeholder) validated"
    );
}

/// Every loader refuses these names (`valid_credential_name` in
/// maki-crypto-local keysource.rs: [A-Za-z0-9._-], no leading dot; `file`
/// splits the path and checks the leaf). `volume create` does not load the
/// key, so the volume is created with this name as its immutable
/// `key_identity`, and no attach can ever load it.
#[test]
fn credential_names_no_loader_accepts_are_refused_by_validation() {
    let accepted = [
        r#"{ source = "credential", name = "keys/vol-key" }"#,
        r#"{ source = "credential", name = ".vol-key" }"#,
        r#"{ source = "file", name = "/etc/maki/keys/.vol-key" }"#,
        r#"{ source = "file", name = "/etc/maki/keys/vol key" }"#,
        r#"{ source = "file", name = "/" }"#,
    ]
    .into_iter()
    .filter(|key| parse(&local(key)).validate().is_ok())
    .collect::<Vec<_>>();
    assert!(
        accepted.is_empty(),
        "validated, but every credential loader refuses these names: {accepted:?}"
    );
}

/// Unknown body field sources/encodings are refused only when the HTTP
/// provider is constructed (maki-crypto-http lib.rs FieldSource::parse), i.e.
/// at attach, never by `validate()` / `volume create`.
#[test]
fn unknown_http_field_sources_are_refused_by_validation() {
    for body in [
        "[crypto.http.encrypt.body]\nfields = { \"/data\" = { source = \"plaintext\" } }\n",
        "[crypto.http.encrypt.body]\nfields = { \"/data\" = { source = \"payload\", encoding = \"base85\" } }\n",
    ] {
        let raw = remote_http(body, "/encrypt");
        assert!(
            parse(&raw).validate().is_err(),
            "validated a body mapping the provider refuses at construction:\n{body}"
        );
    }
}

/// BUG-093 counts only context fields that reach the wire. Overlapping
/// pointers do not: request.rs `MappedValue::set` replaces a scalar ancestor
/// with an object, and `encode_batch` sets `items_path` after `fields`, so
/// `/ctx` (volume_id) is dropped by `/ctx/format`, and `/items/volume` by the
/// items array. Validation still counts both as sent.
#[test]
fn overlapping_context_pointers_do_not_satisfy_context_binding() {
    let mapping = |op: &str, items: &str| {
        format!(
            r#"
[crypto.http.{op}.body]
type = "json"
items_path = "{items}"
[crypto.http.{op}.body.fields]
"/ctx" = {{ source = "volume_id" }}
"/ctx/format" = {{ source = "format_version" }}
"/profile" = {{ source = "compatibility_id" }}
[crypto.http.{op}.body.item_fields]
"/unit" = {{ source = "unit_index" }}
"/data" = {{ source = "payload" }}
[crypto.http.{op}.response]
type = "json"
items_path = "/items"
item_index_path = "/unit"
data_path = "/data"
"#
        )
    };
    let raw = format!(
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
context_binding = "contractual"
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.http.encrypt]
path = "/encrypt"
{}
[crypto.http.decrypt]
path = "/decrypt"
{}
[backing]
root = "/x"
"#,
        mapping("encrypt", "/items"),
        mapping("decrypt", "/items"),
    );
    assert!(
        parse(&raw).validate().is_err(),
        "volume_id at /ctx is overwritten by /ctx/format on the wire, yet context binding validated"
    );
}

/// engine.rs refuses to attach a geometry whose units reach the reserved
/// canary index; validation and `volume create` accept it.
#[test]
fn a_geometry_that_reaches_the_canary_index_is_refused_by_validation() {
    let units = CANARY_UNIT_INDEX + 1;
    let size = units * 512;
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = {size}
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "1TiB"
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "v1"
key = {{ source = "credential", name = "k" }}
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[nbd]
minimum_io = 512
preferred_io = 512
[backing]
root = "/x"
"#
    );
    let config = parse(&raw);
    let validated = config.validate();
    let geometry = config.geometry().unwrap();
    assert!(geometry.num_units() > CANARY_UNIT_INDEX);
    assert!(
        validated.is_err(),
        "validated a volume of {} units, which attach refuses (canary index {CANARY_UNIT_INDEX})",
        geometry.num_units()
    );
}
