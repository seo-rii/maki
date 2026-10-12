//! BUG-055: one volume cannot take another volume's live control address.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use maki_nbdkit::adapter::NbdAdapter;
use maki_nbdkit::daemon;

fn create_config(directory: &Path, socket: &Path, name: &str) -> PathBuf {
    let raw = format!(
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
        directory.join(name).to_str().unwrap(),
        socket.to_str().unwrap()
    );
    let path = directory.join(format!("{name}.toml"));
    std::fs::write(&path, &raw).unwrap();
    daemon::create_volume_from_config_str(&raw).unwrap();
    path
}

fn status(socket: &Path) -> serde_json::Value {
    let stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut client = BufReader::new(stream);
    client
        .get_mut()
        .write_all(b"{\"command\":\"status\"}\n")
        .unwrap();
    let mut response = String::new();
    client.read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

#[test]
fn second_attach_refuses_a_live_address_and_leaves_the_first_volume_operable() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("shared.sock");
    let first_config = create_config(directory.path(), &socket, "first");
    let second_config = create_config(directory.path(), &socket, "second");
    let first = NbdAdapter::open_config(first_config.to_str().unwrap()).unwrap();
    let second = NbdAdapter::open_config(second_config.to_str().unwrap());
    assert!(
        second.is_err(),
        "second attach took a live volume's control address"
    );
    assert_eq!(status(&socket)["data"]["volume"], "first");
    first.pwrite(&vec![0x37; 4096], 0, true).unwrap();
    first.shutdown().unwrap();
    let second = NbdAdapter::open_config(second_config.to_str().unwrap()).unwrap();
    assert_eq!(status(&socket)["data"]["volume"], "second");
    second.shutdown().unwrap();
    assert!(!socket.exists());
}

#[test]
fn predecessor_shutdown_does_not_remove_a_successor_address() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("shared.sock");
    let first_config = create_config(directory.path(), &socket, "first");
    let second_config = create_config(directory.path(), &socket, "second");
    let first = NbdAdapter::open_config(first_config.to_str().unwrap()).unwrap();
    std::fs::remove_file(&socket).unwrap();
    let second = NbdAdapter::open_config(second_config.to_str().unwrap()).unwrap();
    first.shutdown().unwrap();
    assert_eq!(status(&socket)["data"]["volume"], "second");
    second.pwrite(&vec![0x72; 4096], 0, true).unwrap();
    second.shutdown().unwrap();
    assert!(!socket.exists());
}
