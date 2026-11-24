//! The privileged helper's NBD handshake against Maki's own plugin in a
//! real nbdkit. The helper refuses an export that does not advertise
//! FLUSH and FUA (SPEC §6): without SEND_FLUSH the kernel would complete a
//! filesystem's barriers without asking the server, and SEND_FUA is
//! required by policy, so that a FUA write is not emulated with a full
//! flush. The plugin must therefore always advertise both, natively, and
//! TRIM exactly where the volume keeps discards.
//!
//! The handshake is the helper's own source, compiled here by path: a
//! dependency on maki-privileged would change the lockfile, and this way
//! the test runs exactly the code `maki-attach` runs. Without nbdkit the
//! test is skipped with a notice; `MAKI_TEST_REQUIRE_NBDKIT=1`, which the
//! CI jobs that install nbdkit set, makes that a failure.
#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

#[allow(dead_code)]
#[path = "../../maki-privileged/src/nbd_kernel/handshake.rs"]
mod handshake;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use handshake::{
    NBD_FLAG_CAN_MULTI_CONN, NBD_FLAG_HAS_FLAGS, NBD_FLAG_READ_ONLY, NBD_FLAG_SEND_FLUSH,
    NBD_FLAG_SEND_FUA, NBD_FLAG_SEND_TRIM, NBD_FLAG_SEND_WRITE_ZEROES,
};

const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBDKIT";
const DEADLINE: Duration = Duration::from_secs(30);

fn nbdkit_available(test: &str) -> bool {
    let reason = match Command::new("nbdkit").arg("--version").output() {
        Ok(output) if output.status.success() => return true,
        Ok(output) => format!("`nbdkit --version` exited with {}", output.status),
        Err(error) => format!("nbdkit cannot run ({error})"),
    };
    assert!(
        std::env::var_os(REQUIRE).is_none_or(|value| value != "1"),
        "{REQUIRE}=1, but {reason}"
    );
    eprintln!("{test}: skipped: {reason} (set {REQUIRE}=1 to fail instead)");
    false
}

fn config(root: &Path, control: &Path) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "helper-handshake"
max_virtual_size = "2MiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = {}
journal_emergency_reserve_bytes = "0B"
[control]
socket = {}
"#,
        serde_json::to_string(root.to_str().unwrap()).unwrap(),
        serde_json::to_string(control.to_str().unwrap()).unwrap()
    )
}

/// Maki's plugin serving a new fake-provider volume, with or without
/// discard, on a private socket.
struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn start(discard: bool) -> Self {
        let directory = short_dir::tempdir().unwrap();
        let raw = config(
            &directory.path().join("volume"),
            &directory.path().join("control.sock"),
        );
        let config_path = directory.path().join("volume.toml");
        volume_config::write(&config_path, &raw).unwrap();
        if discard {
            maki_nbdkit::daemon::create_volume_with_discard_from_config_str(&raw).unwrap();
        } else {
            maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        }
        let socket = directory.path().join("nbd.sock");
        let pid_file = directory.path().join("nbdkit.pid");
        let log = std::fs::File::create(directory.path().join("nbdkit.log")).unwrap();
        let child = Command::new("nbdkit")
            .args(["--foreground", "--exit-with-parent", "-U"])
            .arg(&socket)
            .arg("-P")
            .arg(&pid_file)
            .arg(native_plugin::path())
            .arg(format!("config={}", config_path.display()))
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start nbdkit");
        let mut daemon = Self {
            directory,
            child,
            socket,
        };
        // nbdkit writes its PID file once it accepts connections.
        let started = Instant::now();
        while !std::fs::read_to_string(&pid_file).is_ok_and(|pid| pid.ends_with('\n')) {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!("nbdkit exited with {status}: {}", daemon.log());
            }
            assert!(
                started.elapsed() < DEADLINE,
                "nbdkit did not start: {}",
                daemon.log()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        daemon
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("nbdkit.log")).unwrap_or_default()
    }

    fn negotiate(&self) -> handshake::Export {
        let stream = UnixStream::connect(&self.socket).unwrap();
        handshake::negotiate(&stream, Instant::now() + DEADLINE)
            .unwrap_or_else(|error| panic!("{error}: {}", self.log()))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_plugin_passes_the_helpers_handshake_with_flush_and_fua() {
    if !nbdkit_available("the_plugin_passes_the_helpers_handshake_with_flush_and_fua") {
        return;
    }
    for discard in [false, true] {
        let daemon = Daemon::start(discard);
        let export = daemon.negotiate();
        let flags = export.transmission_flags;
        assert_eq!(export.size, 2 << 20, "discard {discard}");
        for (flag, name) in [
            (NBD_FLAG_HAS_FLAGS, "HAS_FLAGS"),
            (NBD_FLAG_SEND_FLUSH, "SEND_FLUSH"),
            (NBD_FLAG_SEND_FUA, "SEND_FUA"),
            (NBD_FLAG_SEND_WRITE_ZEROES, "SEND_WRITE_ZEROES"),
        ] {
            assert_ne!(
                flags & flag,
                0,
                "discard {discard}: {name} missing from {flags:#06x}"
            );
        }
        assert_eq!(flags & NBD_FLAG_READ_ONLY, 0, "{flags:#06x}");
        assert_eq!(flags & NBD_FLAG_CAN_MULTI_CONN, 0, "{flags:#06x}");
        assert_eq!(
            flags & NBD_FLAG_SEND_TRIM != 0,
            discard,
            "TRIM is advertised exactly where the volume keeps discards: {flags:#06x}"
        );
    }
}

/// The plugin serves one connection. While one is open, as the kernel's is
/// after a connect, nbdkit answers the next `NBD_OPT_GO` that the export is
/// not available, and it closes a connection only a moment after its peer
/// did. The helper waits for exactly this answer (SPEC §6), so it must be
/// the one the handshake tells apart, and it must end once the first
/// connection is closed.
#[test]
fn a_second_connection_is_answered_unavailable_until_the_first_is_closed() {
    if !nbdkit_available("a_second_connection_is_answered_unavailable_until_the_first_is_closed") {
        return;
    }
    let daemon = Daemon::start(false);
    let open = || {
        let stream = UnixStream::connect(&daemon.socket).unwrap();
        handshake::negotiate(&stream, Instant::now() + DEADLINE).map(|export| (stream, export))
    };
    let first = open().unwrap_or_else(|error| panic!("{error}: {}", daemon.log()));
    for _ in 0..3 {
        let refusal = open().expect_err("a second connection was served");
        assert!(
            handshake::export_unavailable(&refusal),
            "{refusal}: {}",
            daemon.log()
        );
    }
    drop(first);
    // Not necessarily at once, but well within the five seconds the helper
    // waits.
    let closed = Instant::now();
    loop {
        match open() {
            Ok(_) => break,
            Err(error) => {
                assert!(handshake::export_unavailable(&error), "{error}");
                assert!(
                    closed.elapsed() < Duration::from_secs(5),
                    "the export stayed unavailable: {}",
                    daemon.log()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// nbdkit gives a client no reason for that answer, so the daemon's own log
/// has to say that the export exists and is taken.
#[test]
fn the_daemon_says_why_it_refuses_a_second_connection() {
    if !nbdkit_available("the_daemon_says_why_it_refuses_a_second_connection") {
        return;
    }
    let daemon = Daemon::start(false);
    let first = UnixStream::connect(&daemon.socket).unwrap();
    handshake::negotiate(&first, Instant::now() + DEADLINE)
        .unwrap_or_else(|error| panic!("{error}: {}", daemon.log()));
    let second = UnixStream::connect(&daemon.socket).unwrap();
    assert!(handshake::negotiate(&second, Instant::now() + DEADLINE).is_err());
    let started = Instant::now();
    while !daemon
        .log()
        .contains("the volume serves one connection at a time")
    {
        assert!(
            started.elapsed() < DEADLINE,
            "the daemon's log does not say why: {}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
