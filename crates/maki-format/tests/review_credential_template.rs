//! A credential reference's `format` template is split on `{}` by its
//! consumers (HTTP headers in maki-crypto-http, gRPC metadata in the daemon)
//! and the loaded credential is inserted at each placeholder. Validation
//! never looked at the template: with no placeholder the value sent is the
//! template text alone, so a literal secret written into `format` passed the
//! SPEC §9 literal-secret rule and was sent, and a typo such as
//! `"Bearer {token}"` silently dropped the loaded credential; every request
//! then failed at the server. Two placeholders send the credential twice
//! (`"Basic {}:{}"` is not a user/password pair). `format` on a key or a TLS
//! private key was ignored without a word.

use maki_format::config::{parse_config, VolumeConfig};

const SECRET: &str = "S3NT1NEL0123456789abcdef";

fn remote_http(headers: &str) -> String {
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
path = "/encrypt"
[crypto.http.encrypt.headers]
{headers}
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

fn remote_grpc(metadata: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.grpc.endpoint]]
name = "a"
url = "https://crypto.internal"
[crypto.grpc.metadata]
{metadata}
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

fn reference(format: &str) -> String {
    format!(
        "{{ source = \"credential\", name = \"tok\", format = {} }}",
        toml_string(format)
    )
}

fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The error refuses the reference, says why, and never quotes the template
/// (it may hold the very secret it is refused for).
fn assert_refused(raw: &str, diagnosis: &str) {
    let config = parse(raw);
    for error in [
        config.validate().expect_err("validated"),
        // The public provider preflight checks references on its own.
        config
            .validate_credential_sources()
            .expect_err("passed the credential preflight"),
    ] {
        let (display, debug) = (error.to_string(), format!("{error:?}"));
        assert!(
            !display.contains(SECRET) && !debug.contains(SECRET),
            "the error echoed the template: {display}"
        );
        assert!(display.contains(diagnosis), "{display}");
    }
}

#[test]
fn a_header_template_without_exactly_one_placeholder_is_refused() {
    for template in [
        format!("Bearer {SECRET}"),
        format!("{SECRET}{{token}}"),
        format!("Basic {{}}:{{}}{SECRET}"),
        format!("{{}}{{}}{SECRET}"),
        SECRET.to_string(),
    ] {
        assert_refused(
            &remote_http(&format!("Authorization = {}", reference(&template))),
            "exactly one {} placeholder",
        );
        // A header whose name is not sensitive is still a credential.
        assert_refused(
            &remote_http(&format!("X-Trace = {}", reference(&template))),
            "exactly one {} placeholder",
        );
    }
    assert_refused(
        &remote_http(&format!("Authorization = {}", reference(""))),
        "exactly one {} placeholder",
    );
}

#[test]
fn a_metadata_template_without_exactly_one_placeholder_is_refused() {
    for template in [format!("Bearer {SECRET}"), format!("{{}} {{}}{SECRET}")] {
        assert_refused(
            &remote_grpc(&format!("authorization = {}", reference(&template))),
            "exactly one {} placeholder",
        );
    }
}

#[test]
fn templates_with_one_placeholder_still_validate() {
    for template in ["Bearer {}", "{}", "{}; version=1", "{{}}", "Token token={}"] {
        let raw = remote_http(&format!("Authorization = {}", reference(template)));
        parse(&raw)
            .validate()
            .unwrap_or_else(|e| panic!("{template:?}: {e}"));
        let raw = remote_grpc(&format!("authorization = {}", reference(template)));
        parse(&raw)
            .validate()
            .unwrap_or_else(|e| panic!("{template:?}: {e}"));
    }
    parse(&remote_http(
        "Authorization = { source = \"credential\", name = \"tok\" }",
    ))
    .validate()
    .unwrap();
}

#[test]
fn a_template_where_nothing_formats_the_credential_is_refused() {
    assert_refused(
        &local(&format!(
            "{{ source = \"credential\", name = \"k\", format = \"{SECRET}{{}}\" }}"
        )),
        "crypto.key",
    );
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("client.pem");
    std::fs::write(&certificate, b"certificate").unwrap();
    let certificate = certificate.to_str().unwrap().replace('\\', "/");
    let client_key = format!(
        "client_cert_file = \"{certificate}\"\n\
         client_key = {{ source = \"credential\", name = \"client\", format = \"{SECRET}{{}}\" }}\n"
    );
    let http = format!(
        "{}[crypto.http.tls]\n{client_key}",
        remote_http("X-Trace = \"1\"")
    );
    assert_refused(&http, "crypto.http.tls");
    let grpc = format!(
        "{}[crypto.grpc.tls]\n{client_key}",
        remote_grpc("x-trace = \"1\"")
    );
    assert_refused(&grpc, "crypto.grpc.tls");
    let websocket = format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-websocket"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[[crypto.websocket.endpoint]]
name = "a"
url = "wss://crypto.internal"
[crypto.websocket.tls]
{client_key}
[backing]
root = "/x"
"#
    );
    assert_refused(&websocket, "crypto.websocket.tls");
    // Control: the same references without `format` validate.
    for raw in [http, grpc, websocket] {
        let raw = raw.replace(&format!(", format = \"{SECRET}{{}}\""), "");
        parse(&raw)
            .validate()
            .unwrap_or_else(|e| panic!("{e}\n{raw}"));
    }
}
