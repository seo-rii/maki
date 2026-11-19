use maki_format::config::parse_config;

#[test]
fn protocol_byte_caps_must_fit_the_running_platform() {
    let http = include_str!("data/full_config.toml").replacen(
        "[[crypto.http.endpoint]]",
        "[crypto.http]\nmax_response_bytes = \"4GiB\"\n[[crypto.http.endpoint]]",
        1,
    );
    let mut cases = vec![("max_response_bytes", http)];
    for (protocol, field, address) in [
        ("websocket", "max_frame_bytes", "ws://localhost:7000"),
        ("grpc", "max_message_bytes", "http://localhost:7000"),
    ] {
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "v"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-{protocol}"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[crypto.{protocol}]
{field} = "4GiB"
[[crypto.{protocol}.endpoint]]
name = "peer"
url = "{address}"
[backing]
root = "/unused"
"#
        );
        cases.push((field, raw));
    }
    for (field, raw) in cases {
        parse_config(&raw.replacen(r#""4GiB""#, r#""8MiB""#, 1))
            .unwrap()
            .validate()
            .unwrap();
        let result = parse_config(&raw).unwrap().validate();
        if usize::BITS == 32 {
            let err = result.expect_err(field).to_string();
            assert!(err.contains(field), "{err}");
        } else {
            result.unwrap();
        }
    }
}
