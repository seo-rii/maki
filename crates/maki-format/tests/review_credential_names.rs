//! Credential names every loader refuses passed validation. The credential
//! loaders (maki-crypto-local `FileKeySource`) accept only `[A-Za-z0-9._-]`
//! names that do not start with a dot: the whole name for a systemd
//! `credential`, the final path component for a `file`, which must also have
//! one. `maki volume create` never loads the key, so it stored such a name as
//! the volume's immutable key identity; every attach then failed to load
//! the key, and switching to a loadable name is refused as an identity
//! mismatch, so the volume had to be re-created.

use maki_format::config::{parse_config, VolumeConfig};

const SECRET: &str = "S3NT1NEL0123456789abcdef";

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

fn remote_http(header: &str) -> String {
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
Authorization = {header}
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

fn parse(raw: &str) -> VolumeConfig {
    parse_config(raw).unwrap_or_else(|e| panic!("parse: {e}\n{raw}"))
}

fn reference(source: &str, name: &str) -> String {
    format!(
        "{{ source = \"{source}\", name = \"{}\" }}",
        name.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\0', "\\u0000")
    )
}

/// Names the loaders refuse, each carrying a marker that must not be echoed.
fn unloadable() -> Vec<(&'static str, String)> {
    vec![
        ("credential", format!("keys/{SECRET}")),
        ("credential", format!(".{SECRET}")),
        ("credential", format!("{SECRET} key")),
        ("credential", format!("{SECRET}:key")),
        ("credential", format!("{SECRET}\u{e9}")),
        ("credential", format!("{SECRET}\n")),
        ("file", format!("/etc/maki/{SECRET}\0dir/key")),
        ("file", format!("/etc/maki/keys/.{SECRET}")),
        ("file", format!("/etc/maki/keys/{SECRET} key")),
        ("file", format!("/etc/maki/{SECRET}/..")),
        ("file", "/".to_string()),
    ]
}

fn assert_refused(raw: &str, case: &str) {
    let config = parse(raw);
    for error in [
        config.validate().err(),
        // The public provider preflight checks references on its own.
        config.validate_credential_sources().err(),
    ] {
        let error = error.unwrap_or_else(|| panic!("validated a name no loader accepts: {case}"));
        let (display, debug) = (error.to_string(), format!("{error:?}"));
        assert!(
            !display.contains(SECRET) && !debug.contains(SECRET),
            "the error echoed the credential name: {display}"
        );
        assert!(display.contains("credential name"), "{case}: {display}");
    }
}

#[test]
fn a_key_name_no_loader_accepts_is_refused_before_create() {
    for (source, name) in unloadable() {
        assert_refused(
            &local(&reference(source, &name)),
            &format!("{source} {name:?}"),
        );
    }
}

#[test]
fn a_header_credential_name_no_loader_accepts_is_refused() {
    for (source, name) in unloadable() {
        assert_refused(
            &remote_http(&reference(source, &name)),
            &format!("{source} {name:?}"),
        );
    }
}

#[test]
fn names_the_loaders_accept_still_validate() {
    for (source, name) in [
        ("credential", "vol-key"),
        ("credential", "vol.key"),
        ("credential", "Vol_Key-2.hex"),
        ("file", "/etc/maki/keys/vol-key"),
        // Only the file name is a credential name; directories are free.
        ("file", "/etc/maki/.keys/vol key dir/vol-key"),
        // Development-only environment names are not file names.
        ("env", "vol-key"),
    ] {
        for raw in [
            local(&reference(source, name)),
            remote_http(&reference(source, name)),
        ] {
            parse(&raw)
                .validate()
                .unwrap_or_else(|e| panic!("{source} {name:?}: {e}"));
        }
    }
}
