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

// Keep the local regressions that hold the adapter alive across shutdown.
mod retained_adapter {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;

    use maki_nbdkit::adapter::NbdAdapter;
    use maki_nbdkit::daemon;

    struct Fixture {
        _directory: tempfile::TempDir,
        config: PathBuf,
        socket: PathBuf,
        raw: String,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("volume");
            let socket = directory.path().join("control.sock");
            let raw = format!(
                r#"
    config_schema_version = 1
    [volume]
    name = "shutdown-review"
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
    root = "{}"
    [control]
    socket = "{}"
    [security]
    disable_core_dump = false
    madv_dontdump = false
    memory_lock_mode = "off"
    [cache]
    lock_memory = false
    "#,
                root.display(),
                socket.display()
            );
            let config = directory.path().join("volume.toml");
            std::fs::write(&config, &raw).unwrap();
            daemon::create_volume_from_config_str(&raw).unwrap();
            Self {
                _directory: directory,
                config,
                socket,
                raw,
            }
        }

        fn open(&self) -> NbdAdapter {
            NbdAdapter::open_config(self.config.to_str().unwrap()).unwrap()
        }

        fn accepted_client(&self) -> BufReader<UnixStream> {
            let stream = UnixStream::connect(&self.socket).unwrap();
            // A deadlock guard for real socket I/O, not an assumed task delay.
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
            let response: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["ok"], true);
            // The successful roundtrip proves this is an accepted session
            // holding its backend, rather than a pending socket connection.
            client
        }
    }

    #[test]
    fn shutdown_releases_the_volume_lock_even_with_an_idle_control_session() {
        let fixture = Fixture::new();
        let adapter = fixture.open();
        let _client = fixture.accepted_client();
        adapter.shutdown().unwrap();

        let config = daemon::parse_and_validate(&fixture.raw).unwrap();
        let backing = daemon::build_backing(&config).unwrap();
        let lock = backing.try_lock("volume.lock");
        assert!(
            lock.is_ok(),
            "successful shutdown still holds the volume lock: {:?}",
            lock.err()
        );
    }

    #[test]
    fn shutdown_closes_previously_accepted_control_sessions() {
        let fixture = Fixture::new();
        let adapter = fixture.open();
        let mut client = fixture.accepted_client();
        adapter.shutdown().unwrap();

        if client
            .get_mut()
            .write_all(b"{\"command\":\"status\"}\n")
            .is_err()
        {
            return; // The server has already closed the session.
        }
        let mut response = String::new();
        match client.read_line(&mut response) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!(
                "successful shutdown left the control session active: {other:?}; response={response}"
            ),
        }
    }
}
