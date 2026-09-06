//! BUG-015: a clean `shutdown` must terminate every live control session,
//! not just stop accepting new ones. A session task that stays alive keeps
//! its `Engine` reference — and therefore the volume lock — so a detach
//! that reported success would leave the volume `VOLUME_ALREADY_ATTACHED`
//! and its control socket still answering `ready`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

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

/// Connect, send one `status`, read its response, and return the still-open
/// stream so the session stays alive on the server (blocked reading the
/// next request) while the caller holds it.
fn open_live_session(socket: &str) -> (UnixStream, String) {
    let stream = UnixStream::connect(socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    writer.write_all(b"{\"command\":\"status\"}\n").unwrap();
    writer.flush().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    (stream, line)
}

#[test]
fn shutdown_terminates_live_sessions_and_releases_the_volume_lock() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let socket = dir
        .path()
        .join("control.sock")
        .to_string_lossy()
        .into_owned();
    let raw = config(&root, &socket);
    let config_path = dir.path().join("vol.toml");
    std::fs::write(&config_path, &raw).unwrap();
    maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();

    let adapter = NbdAdapter::open_config(config_path.to_str().unwrap()).unwrap();

    // A live control session, held open across the shutdown.
    let (held, first) = open_live_session(&socket);
    assert!(first.contains("ready"), "status before shutdown: {first}");

    adapter.shutdown().unwrap();
    drop(adapter);

    // The socket path is gone, so no new session can be opened.
    assert!(
        UnixStream::connect(&socket).is_err(),
        "control socket must be removed on shutdown"
    );
    // The held session was terminated: its end of the socket is closed, so a
    // read returns EOF (empty) rather than another `ready` response.
    let mut reader = BufReader::new(held);
    let mut after = String::new();
    let n = reader.read_line(&mut after).unwrap();
    assert_eq!(n, 0, "the live session was not terminated: {after:?}");

    // Definitive proof the lock was released: the volume re-attaches. Before
    // the fix the surviving session held the Engine and this failed with
    // VOLUME_ALREADY_ATTACHED.
    let again = NbdAdapter::open_config(config_path.to_str().unwrap())
        .expect("shutdown must release the volume lock");
    again.shutdown().unwrap();
}
