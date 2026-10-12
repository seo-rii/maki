//! BUG-059: the largest valid volume name is readable through the official client.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use maki_nbdkit::adapter::NbdAdapter;
use maki_nbdkit::daemon;

fn config(root: &Path, socket: &Path, name: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "{name}"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "64KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {:?}
journal_emergency_reserve_bytes = "0B"
[control]
socket = {:?}
[security]
disable_core_dump = false
madv_dontdump = false
memory_lock_mode = "off"
[cache]
lock_memory = false
"#,
        root.to_str().unwrap(),
        socket.to_str().unwrap()
    )
}

#[test]
fn maximum_length_name_attaches_writes_and_returns_official_status() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control.sock");
    let name = "v".repeat(64);
    let raw = config(&directory.path().join("volume"), &socket, &name);
    let path = directory.path().join("volume.toml");
    std::fs::write(&path, &raw).unwrap();
    daemon::create_volume_from_config_str(&raw).unwrap();
    let adapter = NbdAdapter::open_config(path.to_str().unwrap()).unwrap();
    adapter.pwrite(&vec![0x72; 4096], 0, true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        maki_control::protocol::send_command(
            &mut writer,
            &maki_control::protocol::Request::new("status"),
        )
        .await
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            maki_control::protocol::read_response(&mut reader),
        )
        .await
        .unwrap()
        .unwrap()
    });
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["volume"], name);
    adapter.shutdown().unwrap();
}

#[test]
fn an_overlong_name_is_rejected_before_attach_opens_the_backing() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("missing-volume");
    let socket = directory.path().join("control.sock");
    let path = directory.path().join("volume.toml");
    std::fs::write(&path, config(&root, &socket, &"v".repeat(65_536))).unwrap();
    let error = match NbdAdapter::open_config(path.to_str().unwrap()) {
        Ok(_) => panic!("an overlong volume name attached"),
        Err(error) => error,
    };
    assert!(error.message.contains("volume name"), "{error}");
    assert!(error.message.contains("64"), "{error}");
    assert!(!root.exists(), "invalid configuration opened the backing");
}
