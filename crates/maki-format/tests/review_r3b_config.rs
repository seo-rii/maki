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
