#![cfg(unix)]
//! BUG-051: the documented TTL reload is reachable through the real CLI.
use serde_json::{json, Value};
use std::process::Command;

async fn reload(flags: &[&str]) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let config = dir.path().join("volume.toml");
    std::fs::write(
        &config,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "cache-reload-cli"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "test"
key = {{ source = "env", name = "test-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = {:?}
[control]
socket = {:?}
"#,
            dir.path().join("volume").to_string_lossy(),
            socket.to_string_lossy()
        ),
    )
    .unwrap();
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let flags: Vec<String> = flags.iter().map(|flag| flag.to_string()).collect();
    let mut child = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(["reload"])
            .arg(config)
            .arg("cache")
            .args(flags)
            .output()
            .unwrap()
    });
    let (stream, _) = tokio::select! {
        result = listener.accept() => result.unwrap(),
        output = &mut child => panic!("CLI rejected valid reload: {}", String::from_utf8_lossy(&output.unwrap().stderr)),
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let request = maki_control::protocol::read_line(&mut rd).await.unwrap();
    let request: Value = serde_json::from_slice(&request).unwrap();
    use tokio::io::AsyncWriteExt;
    wr.write_all(b"{\"ok\":true,\"data\":{}}\n").await.unwrap();
    let output = child.await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request["command"], "reload");
    assert_eq!(request["section"], "cache");
    request["payload"].clone()
}

#[tokio::test]
async fn cli_sends_size_and_ttl_in_either_option_order() {
    for flags in [
        ["--max-bytes", "4096", "--ttl", "1s"],
        ["--ttl", "1s", "--max-bytes", "4096"],
    ] {
        assert_eq!(
            reload(&flags).await,
            json!({"max_bytes": 4096, "ttl": "1s"})
        );
    }
}

#[tokio::test]
async fn cli_retains_size_only_reload_payload() {
    assert_eq!(
        reload(&["--max-bytes", "4096"]).await,
        json!({"max_bytes": 4096})
    );
}

#[test]
fn invalid_reload_options_are_rejected_before_loading_config() {
    for flags in [
        vec!["--max-bytes", "4096", "--ttl"],
        vec!["--max-bytes", "4096", "--ttl", "0s"],
        vec!["--max-bytes", "4096", "--ttl", "bogus"],
        vec!["--max-bytes", "4096", "--ttl", "1s", "--ttl", "2s"],
        vec!["--max-bytes", "4096", "--tt1", "1s"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(["reload", "/nonexistent-cache-reload-config.toml", "cache"])
            .args(flags)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            !error.contains("No such file"),
            "options must be validated first: {error}"
        );
    }
}
