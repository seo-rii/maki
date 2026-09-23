//! R4-001: runtime `tracing` events from the engine, the store and the
//! control server must reach the process's stderr (which nbdkit and systemd
//! capture) in the default plugin execution path. Without a subscriber the
//! macros are no-ops, so a checkpoint failure or a repaired allocation map
//! would leave no trace in the service journal.
//!
//! The scenario is deterministic: a zero-length orphan shard data file makes
//! `SlotStore::open` emit a `tracing::warn!` during recovery, before READY.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(8);

fn native_available() -> bool {
    match Command::new("nbdkit").arg("--version").output() {
        Ok(output) => {
            assert!(output.status.success(), "installed nbdkit cannot run");
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("nbdkit unavailable; skipping optional native logging qualification");
            false
        }
        Err(error) => panic!("nbdkit probe failed: {error}"),
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    config: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("volume");
        let control = dir.path().join("control.sock");
        let config = dir.path().join("volume.toml");
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "native-logging"
max_virtual_size = "2MiB"
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {root:?}
[control]
socket = {control:?}
"#
        );
        std::fs::write(&config, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        Self { dir, config, root }
    }
}

struct Server {
    child: Child,
    stderr: tempfile::NamedTempFile,
}

impl Server {
    fn start(fixture: &Fixture, notify: &Path, env: &[(&str, &str)]) -> Self {
        let plugin = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("libmaki_nbdkit.so");
        assert!(plugin.is_file(), "missing cargo-built native plugin");
        let stderr = tempfile::NamedTempFile::new_in(fixture.dir.path()).unwrap();
        let stdout = tempfile::NamedTempFile::new_in(fixture.dir.path()).unwrap();
        let mut command = Command::new("nbdkit");
        command
            .args(["--foreground", "--exit-with-parent", "-U"])
            .arg(fixture.dir.path().join("nbd.sock"))
            .arg(plugin)
            .arg(format!("config={}", fixture.config.display()))
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .env("NOTIFY_SOCKET", notify)
            .env_remove("MAKI_LOG");
        for (key, value) in env {
            command.env(key, value);
        }
        Self {
            child: command
                .spawn()
                .expect("nbdkit is required for this native test"),
            stderr,
        }
    }

    fn wait_ready(&mut self, socket: &UnixDatagram) {
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            let mut buffer = [0; 4096];
            match socket.recv(&mut buffer) {
                Ok(count)
                    if buffer[..count]
                        .split(|byte| *byte == b'\n')
                        .any(|line| line == b"READY=1") =>
                {
                    return;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("notification receive failed: {error}"),
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "startup exited before READY: {}",
                self.stop_and_read()
            );
        }
        panic!(
            "startup did not send READY before the deadline: {}",
            self.stop_and_read()
        );
    }

    /// Stop the server (SIGTERM first so unload runs) and return its stderr.
    fn stop_and_read(&mut self) -> String {
        use std::io::Read;
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGTERM);
            }
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5)
                && self.child.try_wait().ok().flatten().is_none()
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.child.try_wait().ok().flatten().is_none() {
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                let _ = self.child.wait();
            }
        }
        let mut bytes = Vec::new();
        self.stderr
            .reopen()
            .unwrap()
            .take(64 * 1024)
            .read_to_end(&mut bytes)
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }
}

fn notify_socket(fixture: &Fixture) -> (UnixDatagram, PathBuf) {
    let path = fixture.dir.path().join("notify.sock");
    // Each server start gets a fresh receiver at the same path.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(fixture.dir.path().join("nbd.sock"));
    let socket = UnixDatagram::bind(&path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    (socket, path)
}

/// An orphan shard file with no allocation copy is adopted at open with a
/// `tracing::warn!` explaining that its creation never finished.
fn plant_orphan_shard(fixture: &Fixture) {
    let data_dir = fixture.root.join(maki_format::layout::DATA_DIR);
    std::fs::create_dir_all(&data_dir).unwrap();
    let orphan = fixture
        .root
        .join(maki_format::layout::shard_data(1));
    std::fs::write(&orphan, b"").unwrap();
    assert_eq!(std::fs::metadata(&orphan).unwrap().len(), 0);
}

const ORPHAN_WARNING: &str = "uncataloged shard with an empty allocation map";

/// A first clean run binds the key canary; an orphan shard on a volume
/// without a canary would be refused as "data but no key canary".
fn bind_canary(fixture: &Fixture) {
    let (notify, notify_path) = notify_socket(fixture);
    let mut server = Server::start(fixture, &notify_path, &[]);
    server.wait_ready(&notify);
    let stderr = server.stop_and_read();
    assert!(
        !stderr.contains(ORPHAN_WARNING),
        "a clean volume must not report an orphan:\n{stderr}"
    );
}

#[test]
fn runtime_warnings_reach_stderr_in_the_default_plugin_path() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    bind_canary(&fixture);
    plant_orphan_shard(&fixture);
    let (notify, notify_path) = notify_socket(&fixture);
    let mut server = Server::start(&fixture, &notify_path, &[]);
    server.wait_ready(&notify);
    let stderr = server.stop_and_read();
    assert!(
        stderr.contains(ORPHAN_WARNING),
        "the store's recovery warning must be in the captured stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("WARN"),
        "the level must be visible so journald filters work:\n{stderr}"
    );
    for forbidden in ["fixture-plaintext", "Bearer ", "key ="] {
        assert!(!stderr.contains(forbidden), "no payloads or secrets:\n{stderr}");
    }
}

#[test]
fn maki_log_filters_the_default_plugin_output() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    bind_canary(&fixture);
    plant_orphan_shard(&fixture);
    let (notify, notify_path) = notify_socket(&fixture);
    let mut server = Server::start(&fixture, &notify_path, &[("MAKI_LOG", "error")]);
    server.wait_ready(&notify);
    let stderr = server.stop_and_read();
    assert!(
        !stderr.contains(ORPHAN_WARNING),
        "MAKI_LOG=error must suppress warnings:\n{stderr}"
    );
}
