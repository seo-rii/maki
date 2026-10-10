use maki_format::config::parse_config;

fn config(section: &str) -> String {
    format!(
        r#"config_schema_version = 1
[volume]
name = "remote-witness"
max_virtual_size = "1GiB"
shard_logical_size = "8MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "MAKI_TEST_KEY" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/var/lib/maki/remote"
checkpoint_reserve_bytes = "64KiB"
journal_emergency_reserve_bytes = "64KiB"
[backing.rollback_protection]
capacity = "64MiB"
{section}
"#
    )
}

fn remote() -> &'static str {
    r#"[backing.rollback_protection.remote]
address = "127.0.0.1:9443"
server_name = "witness.example.test"
timeout_ms = 1500
ca_file = "/etc/maki/witness-ca.pem"
client_cert_file = "/etc/maki/writer.pem"
client_key_file = "/run/credentials/maki/writer-key.pem""#
}

#[test]
fn remote_witness_config_is_explicit_and_mutually_exclusive() {
    let cfg = parse_config(&config(remote())).expect("remote witness schema");
    cfg.validate().expect("valid remote witness config");
    let both = config(&format!("witness_root = \"/witness\"\n{}", remote()));
    assert!(parse_config(&both).unwrap().validate().is_err());
    assert!(parse_config(&config("")).unwrap().validate().is_err());
}

#[test]
fn remote_witness_requires_bounded_authenticated_transport() {
    for (old, new) in [
        ("127.0.0.1:9443", "witness.example.test:9443"),
        ("127.0.0.1:9443", "127.0.0.1:0"),
        ("witness.example.test", ""),
        ("timeout_ms = 1500", "timeout_ms = 0"),
        ("timeout_ms = 1500", "timeout_ms = 60001"),
        ("/etc/maki/witness-ca.pem", "relative.pem"),
        ("/etc/maki/writer.pem", "relative.pem"),
        ("/run/credentials/maki/writer-key.pem", "relative.pem"),
    ] {
        let source = config(&remote().replace(old, new));
        let parsed = parse_config(&source).expect("syntactically valid");
        assert!(parsed.validate().is_err(), "accepted {old} -> {new}");
    }
}
