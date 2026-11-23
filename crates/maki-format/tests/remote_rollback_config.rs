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

fn remote() -> String {
    let drive = if cfg!(windows) { "C:" } else { "" };
    format!(
        r#"[backing.rollback_protection.remote]
address = "127.0.0.1:9443"
server_name = "witness.example.test"
timeout_ms = 1500
ca_file = "{drive}/etc/maki/witness-ca.pem"
client_cert_file = "{drive}/etc/maki/writer.pem"
client_key_file = "{drive}/run/credentials/maki/writer-key.pem""#
    )
}

#[test]
fn remote_witness_config_is_explicit_and_mutually_exclusive() {
    let cfg = parse_config(&config(&remote())).expect("remote witness schema");
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
        ("witness.example.test", "witness.example.test:9443"),
        ("witness.example.test", "witness..test"),
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

#[test]
fn multiple_witness_addresses_require_an_explicit_storage_identity() {
    let section = remote().replace("address = \"127.0.0.1:9443\"", "addresses = [\"127.0.0.1:9443\", \"127.0.0.1:9444\"]\nstorage_identity = \"11111111-1111-4111-8111-111111111111\"");
    let parsed = parse_config(&config(&section)).expect("HA endpoint schema");
    parsed.validate().expect("valid identity-pinned HA config");
    for bad in [
        section.replace(
            "storage_identity = \"11111111-1111-4111-8111-111111111111\"",
            "",
        ),
        section.replace("127.0.0.1:9444", "127.0.0.1:9443"),
        section.replace(
            "11111111-1111-4111-8111-111111111111",
            "00000000-0000-0000-0000-000000000000",
        ),
        format!("address = \"127.0.0.1:9445\"\n{section}"),
    ] {
        assert!(
            parse_config(&config(&bad))
                .and_then(|cfg| cfg.validate())
                .is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn witness_tls_names_accept_both_ip_families() {
    for address in ["127.0.0.1", "::1"] {
        let cfg =
            parse_config(&config(&remote().replace("witness.example.test", address))).unwrap();
        cfg.validate().unwrap();
    }
}

#[test]
fn remote_rollback_sockets_respect_writer_namespaces() {
    let mut volume = parse_config(&config(&remote())).unwrap();
    let namespace = "remote-0000000000000001-10000000000000000000000000000000";
    for entry in [
        "remote.enrollment".to_string(),
        "remote.enroll.lock".to_string(),
        "remote.operation.lock".to_string(),
        "rollback.format".to_string(),
        format!("{namespace}/rollback.arena"),
        format!(".remote-gc-{namespace}/rollback.lock"),
    ] {
        volume.control.socket = Some(format!("{}/{entry}", volume.backing.root));
        assert!(volume
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control.socket"));
    }
    volume.control.socket = Some(format!("{}/custom.sock", volume.backing.root));
    volume.validate().unwrap();
}
