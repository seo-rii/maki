//! Review M-005 / M-017: the daemon path (`NbdAdapter::open_config`) binds
//! and serves the per-volume control socket, `status` reflects the engine,
//! unsupported reloads are refused explicitly, and shutdown removes the
//! socket. Unix only (Unix-domain sockets).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use serde_json::{json, Value};

use maki_control::protocol::{read_response, send_command, Request};
use maki_nbdkit::adapter::NbdAdapter;

fn config(root: &str, socket: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "ctlvol"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{root}"
[control]
socket = "{socket}"
"#
    )
}

struct Client {
    runtime: tokio::runtime::Runtime,
    socket: String,
}

impl Client {
    fn new(socket: &str) -> Self {
        Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            socket: socket.to_string(),
        }
    }

    fn call(&self, command: &str, section: Option<&str>, payload: Value) -> Value {
        let socket = self.socket.clone();
        let mut request = Request::new(command);
        request.section = section.map(|s| s.to_string());
        request.payload = payload;
        self.runtime.block_on(async move {
            let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
            let (mut rd, mut wr) = tokio::io::split(stream);
            send_command(&mut wr, &request).await.unwrap();
            read_response(&mut rd).await.unwrap()
        })
    }
}

#[test]
fn control_socket_is_created_served_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    // A read cache is on so that `reload cache` has something to apply
    // (O-09: with the cache off the verb is refused, see below).
    let raw = format!("{}
[cache]
mode = \"read\"
", config(&root, &socket));
    let config_path = dir.path().join("vol.toml");
    std::fs::write(&config_path, &raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();

    let adapter = NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();
    assert_eq!(
        adapter.control_socket_path().unwrap().to_str().unwrap(),
        socket
    );
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "socket mode");

    let client = Client::new(&socket);
    let status = client.call("status", None, Value::Null);
    assert_eq!(status["ok"], json!(true), "{status}");
    assert_eq!(status["data"]["state"], json!("ready"));
    assert_eq!(status["data"]["volume"], json!("ctlvol"));

    adapter.pwrite(&vec![0x42; 4096], 0, true).unwrap();
    let ck = client.call("checkpoint", None, Value::Null);
    assert_eq!(ck["ok"], json!(true), "{ck}");
    assert!(ck["data"]["checkpoint_sequence"].as_u64().unwrap() >= 1);

    let metrics = client.call("metrics", None, Value::Null);
    assert_eq!(metrics["data"]["maki_volume_state"], json!(1));
    assert!(metrics["data"]["maki_checkpoints_total"].as_u64().unwrap() >= 1);

    // Unsupported reload sections are refused, not silently accepted.
    for section in ["retry", "circuit-breaker", "batch", "limits", "endpoints"] {
        let r = client.call("reload", Some(section), json!({}));
        assert_eq!(r["ok"], json!(false), "{section}: {r}");
        assert!(
            r["error"].as_str().unwrap().contains("NOT applied"),
            "{section}: {r}"
        );
    }
    let cache = client.call("reload", Some("cache"), json!({ "max_bytes": 4096 }));
    assert_eq!(cache["ok"], json!(true), "{cache}");
    let bad = client.call("reload", Some("cache"), json!({}));
    assert_eq!(bad["ok"], json!(false), "{bad}");

    let attach = client.call("attach", None, Value::Null);
    assert_eq!(attach["ok"], json!(false));

    adapter.shutdown().unwrap();
    assert!(
        !std::path::Path::new(&socket).exists(),
        "socket removed on shutdown"
    );
}

#[test]
fn missing_control_socket_directory_fails_attach() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("no-such-dir")
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    let raw = config(&root, &socket);
    let config_path = dir.path().join("vol.toml");
    std::fs::write(&config_path, &raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();

    let err = NbdAdapter::open_config(config_path.to_str().unwrap())
        .err()
        .expect("attach must fail without a control socket");
    assert!(err.message.contains("control socket"), "{err}");
}

/// O-09: `reload cache` on a daemon running without a cache used to
/// answer `ok` although nothing was applied; the CLI could not even send
/// the size. It must refuse explicitly.
#[test]
fn reload_cache_without_a_cache_is_refused_not_silently_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    let raw = format!(
        "{}
[cache]
mode = \"off\"
",
        config(&root, &socket)
    );
    let config_path = dir.path().join("vol.toml");
    std::fs::write(&config_path, &raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
    let adapter = NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();
    let client = Client::new(&socket);
    let r = client.call("reload", Some("cache"), json!({ "max_bytes": 4096 }));
    assert_eq!(r["ok"], json!(false), "{r}");
    assert!(r["error"].as_str().unwrap().contains("NOT applied"), "{r}");
    adapter.shutdown().unwrap();
}
