use maki_format::config::{parse_config, VolumeConfig};

fn config(transport: &str, url: &str, tls: &str) -> String {
    let mappings = if transport == "http" {
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.encrypt.response]\ndata_path = \"/ct\"\n[crypto.http.decrypt]\npath = \"/decrypt\"\n[crypto.http.decrypt.response]\ndata_path = \"/pt\""
    } else {
        ""
    };
    format!(
        r#"
config_schema_version = 1
[volume]
name = "tls-config"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-{transport}"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[[crypto.{transport}.endpoint]]
name = "primary"
url = "{url}"
{mappings}
{tls}
[backing]
root = "/tmp/unused-tls-config"
"#
    )
}

fn validate(raw: &str) -> Result<VolumeConfig, String> {
    let cfg = parse_config(raw).map_err(|error| error.to_string())?;
    cfg.validate().map_err(|error| error.to_string())?;
    Ok(cfg)
}

#[test]
fn encrypted_websocket_and_grpc_endpoints_validate_with_default_trust() {
    for (transport, url) in [
        ("websocket", "wss://crypto.example:8443"),
        ("grpc", "https://crypto.example:8443"),
    ] {
        validate(&config(transport, url, "")).unwrap();
    }
}

#[test]
fn tls_options_are_never_ignored_on_plaintext_loopback_endpoints() {
    for (transport, url) in [
        ("http", "http://127.0.0.1:7000"),
        ("websocket", "ws://127.0.0.1:7000"),
        ("grpc", "http://127.0.0.1:7000"),
    ] {
        let tls = format!("[crypto.{transport}.tls]");
        let error = validate(&config(transport, url, &tls)).unwrap_err();
        assert!(error.contains("requires an encrypted endpoint"), "{error}");
    }
}

#[test]
fn websocket_client_key_is_routed_as_a_declared_credential() {
    let certificate = tempfile::NamedTempFile::new().unwrap();
    let tls = format!(
        "[crypto.websocket.tls]\nclient_cert_file = {:?}\nclient_key = {{ source = \"env\", name = \"client-key\" }}",
        certificate.path().to_str().unwrap()
    );
    let cfg = validate(&config("websocket", "wss://crypto.example", &tls)).unwrap();
    let refs = cfg.credential_refs();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].source, "env");
    assert_eq!(refs[0].name, "client-key");
}

#[test]
fn each_encrypted_transport_checks_tls_material_and_identity_pairing() {
    let certificate = tempfile::NamedTempFile::new().unwrap();
    for (transport, scheme) in [("websocket", "wss"), ("grpc", "https")] {
        let url = format!("{scheme}://crypto.example");
        for (options, expected) in [
            ("ca_file = \"/no/such/maki-test-ca.pem\"", "not readable"),
            ("server_name = \"other.example\"", "server_name"),
            (
                "client_key = { source = \"env\", name = \"client-key\" }",
                "client_key requires client_cert_file",
            ),
        ] {
            let tls = format!("[crypto.{transport}.tls]\n{options}");
            let error = validate(&config(transport, &url, &tls)).unwrap_err();
            assert!(error.contains(expected), "{transport}: {error}");
        }
        let tls = format!(
            "[crypto.{transport}.tls]\nclient_cert_file = {:?}",
            certificate.path().to_str().unwrap()
        );
        let error = validate(&config(transport, &url, &tls)).unwrap_err();
        assert!(
            error.contains("client_cert_file requires client_key"),
            "{error}"
        );
    }
}

#[test]
fn adding_tls_support_does_not_enable_plaintext_remote_endpoints() {
    for (transport, url) in [
        ("websocket", "ws://crypto.example"),
        ("grpc", "http://crypto.example"),
    ] {
        let error = validate(&config(transport, url, "")).unwrap_err();
        assert!(error.contains("only allowed to loopback"), "{error}");
    }
}
