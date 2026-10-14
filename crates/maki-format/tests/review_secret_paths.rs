//! BUG-122: a `file` credential's name and a TLS `ca_file` or
//! `client_cert_file` are paths, but validation accepted relative ones.
//! They resolve against the working directory of whichever process reads
//! them: `maki volume create` run from /etc/maki validated `ca.pem` there,
//! while the daemon under systemd (working directory `/`) read `/ca.pem`, and
//! a key file named relatively could be planted in a writable directory a
//! tool happened to run from. Every other path in the configuration (backing
//! root, sockets, witness TLS files) already has to be absolute.

use maki_format::config::parse_config;

fn local(key_name: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "secret-paths"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "test"
key = {{ source = "file", name = "{key_name}" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/tmp/unused-secret-paths"
"#
    )
}

fn http_with_ca(ca_file: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "secret-paths"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[[crypto.http.endpoint]]
name = "primary"
url = "https://crypto.example"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.encrypt.response]
data_path = "/ct"
[crypto.http.decrypt]
path = "/decrypt"
[crypto.http.decrypt.response]
data_path = "/pt"
[crypto.http.tls]
ca_file = "{ca_file}"
[backing]
root = "/tmp/unused-secret-paths"
"#
    )
}

fn validate(raw: &str) -> Result<(), String> {
    parse_config(raw)
        .map_err(|e| e.to_string())?
        .validate()
        .map_err(|e| e.to_string())
}

#[test]
fn a_file_credential_must_name_an_absolute_path() {
    for relative in ["volume.key", "secrets/volume.key", "./volume.key"] {
        let error = validate(&local(relative)).expect_err(relative);
        assert!(error.contains("absolute"), "{relative}: {error}");
    }
    validate(&local("/etc/maki/secrets/volume.key")).unwrap();
}

#[test]
fn tls_files_must_be_absolute_paths() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.pem"), b"pem").unwrap();
    // The relative name exists in this process's working directory; the
    // daemon would look elsewhere.
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let error = validate(&http_with_ca("ca.pem"));
    std::env::set_current_dir(previous).unwrap();
    let error = error.expect_err("a relative ca_file was accepted");
    assert!(error.contains("absolute"), "{error}");
    // Forward slashes keep a Windows path valid inside a TOML basic string.
    let absolute = dir
        .path()
        .join("ca.pem")
        .to_str()
        .unwrap()
        .replace('\\', "/");
    validate(&http_with_ca(&absolute)).unwrap();
}
