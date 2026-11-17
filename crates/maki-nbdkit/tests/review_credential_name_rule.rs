//! Configuration validation and the credential loader each carry the
//! credential name rule (maki-crypto-local does not depend on maki-format).
//! A name validation accepts but the loader refuses is stored as a volume's
//! immutable key identity by `volume create`, and no attach can then load
//! the key; pin the two rules to each other.

use maki_crypto_local::keysource::{FileKeySource, KeySource};
use maki_format::config::parse_config;

fn validates(source: &str, name: &str) -> bool {
    let escaped = name
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "name-rule"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "{source}", name = "{escaped}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/unused-name-rule"
"#
    ))
    .unwrap()
    .validate()
    .is_ok()
}

#[test]
fn validation_accepts_exactly_the_names_the_loader_accepts() {
    let directory = tempfile::tempdir().unwrap();
    let loader = FileKeySource::new(directory.path());
    let root = directory.path().to_str().unwrap().replace('\\', "/");
    for name in [
        "vol-key",
        "vol.key",
        "Vol_Key-2.hex",
        "a",
        "-",
        "a..b",
        "keys/vol-key",
        ".vol-key",
        "..",
        "vol key",
        "vol:key",
        "vol\\key",
        "vol-key\n",
        "cl\u{e9}",
    ] {
        // No file exists: an accepted name is merely unavailable.
        let error = loader.load(name).expect_err("no credential file exists");
        let loader_accepts = !error.to_string().contains("invalid credential name");
        assert_eq!(
            validates("credential", name),
            loader_accepts,
            "credential {name:?}: {error}"
        );
        if !name.contains(['/', '\\']) {
            assert_eq!(
                validates("file", &format!("{root}/{name}")),
                loader_accepts,
                "file {name:?}: {error}"
            );
        }
    }
}
