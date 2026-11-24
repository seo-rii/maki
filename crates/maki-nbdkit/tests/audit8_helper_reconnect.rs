//! Round-8 audit (slug `privileged-nbd`): the helper's busy retry against
//! Maki's own plugin in a real nbdkit.
//!
//! When the kernel refuses `NBD_CMD_CONNECT` with `EBUSY`, the helper closes
//! the connection it had negotiated, sleeps 100 ms and negotiates a fresh one
//! (`nbd_kernel::connect_retrying`, SPEC §6 "each time on a fresh connection
//! to the daemon"). Maki's plugin serves ONE connection at a time
//! (`plugin.rs`, `ACTIVE_CONNECTION`: a second `open` fails with `EBUSY`
//! until nbdkit has run `close` for the first). So every retry depends on
//! nbdkit noticing the closed socket and running the plugin's `close` within
//! the helper's 100 ms. These tests measure that, and show what the helper
//! reports when it does not hold.
//!
//! The handshake is the helper's own source, compiled by path, as
//! `review_helper_nbd_handshake.rs` does. Run through the wrapper that
//! passes the plugin:
//! `python3 scripts/run_cargo_tests.py -p maki-nbdkit --locked --test audit8_helper_reconnect -- --test-threads=1 --nocapture`
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
name = "audit8-reconnect"
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

/// Maki's plugin serving a new fake-provider volume on a private socket.
struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        let directory = short_dir::tempdir().unwrap();
        let raw = config(
            &directory.path().join("volume"),
            &directory.path().join("control.sock"),
        );
        let config_path = directory.path().join("volume.toml");
        volume_config::write(&config_path, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
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

    /// What `nbd_kernel::open_export` does: connect, then the handshake.
    fn open(&self) -> std::io::Result<(UnixStream, handshake::Export)> {
        let stream = UnixStream::connect(&self.socket)?;
        let export = handshake::negotiate(&stream, Instant::now() + DEADLINE)?;
        Ok((stream, export))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The plugin serves one connection: while one negotiated socket is open
/// (the kernel's, after a connect), a second handshake is refused, and the
/// helper's message names "no default export".
#[test]
fn audit8_a_second_handshake_is_refused_while_a_connection_is_open() {
    if !nbdkit_available("audit8_a_second_handshake_is_refused_while_a_connection_is_open") {
        return;
    }
    let daemon = Daemon::start();
    let first = daemon.open().unwrap_or_else(|error| panic!("{error}: {}", daemon.log()));
    let second = daemon.open();
    let message = second.as_ref().map(|_| ()).unwrap_err().to_string();
    eprintln!("audit8: a second handshake while one connection is open: {message}");
    assert!(message.contains("NBD_REP_ERR_UNKNOWN"), "{message}");
    drop(first);
}

/// How soon after the helper closed a negotiated connection a fresh
/// handshake is accepted again.
#[test]
fn audit8_a_fresh_handshake_after_a_closed_one_depends_on_the_pause() {
    if !nbdkit_available("audit8_a_fresh_handshake_after_a_closed_one_depends_on_the_pause") {
        return;
    }
    let daemon = Daemon::start();
    let mut table = Vec::new();
    for (pause, rounds) in [
        (Duration::ZERO, 300),
        (Duration::from_micros(100), 300),
        (Duration::from_millis(1), 200),
        (Duration::from_millis(10), 60),
        // The helper's BUSY_RETRY_INTERVAL.
        (Duration::from_millis(100), 40),
    ] {
        let mut refused = 0;
        let mut first_refusal = None;
        for _ in 0..rounds {
            // Start from a daemon that accepts a connection.
            let started = Instant::now();
            let connection = loop {
                match daemon.open() {
                    Ok(connection) => break connection,
                    Err(error) => {
                        assert!(
                            started.elapsed() < DEADLINE,
                            "the daemon never accepted again: {error}: {}",
                            daemon.log()
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };
            // The kernel answered EBUSY: the helper closes its socket ...
            drop(connection);
            // ... sleeps, and negotiates a fresh connection.
            std::thread::sleep(pause);
            match daemon.open() {
                Ok(connection) => drop(connection),
                Err(error) => {
                    refused += 1;
                    first_refusal.get_or_insert_with(|| error.to_string());
                }
            }
            // Let the daemon settle before the next round.
            std::thread::sleep(Duration::from_millis(20));
        }
        eprintln!(
            "audit8: pause {pause:?}: {refused} of {rounds} fresh handshakes refused{}",
            first_refusal
                .as_ref()
                .map(|message| format!(" ({message})"))
                .unwrap_or_default()
        );
        table.push((pause, rounds, refused));
    }
    // The mechanism: right after the close, the daemon still refuses. How
    // often it still does at the helper's 100 ms depends on the host's load
    // (`audit8_measure_refusals_at_the_helpers_interval` counted 2 of 1500
    // on a loaded 4-core host), so no count is asserted for the longer pauses.
    let (_, _, right_after_the_close) = table[0];
    assert!(
        right_after_the_close > 0,
        "no fresh handshake was refused right after a close: {table:?}"
    );
}

/// A longer measurement of the same, for the tail at and below the helper's
/// 100 ms (`-- --ignored --nocapture`; about five minutes).
#[test]
#[ignore = "a measurement: several minutes"]
fn audit8_measure_the_tail_of_the_daemons_close() {
    if !nbdkit_available("audit8_measure_the_tail_of_the_daemons_close") {
        return;
    }
    let daemon = Daemon::start();
    // How long after the close the daemon accepts a handshake again.
    let mut latencies = Vec::new();
    for _ in 0..1500 {
        let started = Instant::now();
        let connection = loop {
            match daemon.open() {
                Ok(connection) => break connection,
                Err(error) => {
                    assert!(started.elapsed() < DEADLINE, "{error}: {}", daemon.log());
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        drop(connection);
        let closed = Instant::now();
        let mut refusals = 0;
        loop {
            match daemon.open() {
                Ok(connection) => {
                    drop(connection);
                    break;
                }
                Err(_) => {
                    refusals += 1;
                    assert!(closed.elapsed() < DEADLINE, "{}", daemon.log());
                    std::thread::sleep(Duration::from_micros(500));
                }
            }
        }
        // The last refusal ended no earlier than this long after the close.
        latencies.push(if refusals == 0 { Duration::ZERO } else { closed.elapsed() });
        std::thread::sleep(Duration::from_millis(5));
    }
    latencies.sort();
    let at = |fraction: f64| latencies[((latencies.len() - 1) as f64 * fraction) as usize];
    let over = |limit: Duration| latencies.iter().filter(|latency| **latency > limit).count();
    eprintln!(
        "audit8: after a close, the daemon accepted again within: median {:?}, 90% {:?}, 99% {:?}, max {:?}; over 10 ms: {}, over 50 ms: {}, over 100 ms: {} of {}",
        at(0.5),
        at(0.9),
        at(0.99),
        latencies.last().unwrap(),
        over(Duration::from_millis(10)),
        over(Duration::from_millis(50)),
        over(Duration::from_millis(100)),
        latencies.len()
    );
}

/// The helper's own schedule, many times: close, sleep exactly the busy
/// retry's 100 ms (or 30 ms, about what separates a detach from the attach
/// that follows it in a unit restart), one fresh handshake
/// (`-- --ignored --nocapture`; about four minutes).
#[test]
#[ignore = "a measurement: several minutes"]
fn audit8_measure_refusals_at_the_helpers_interval() {
    if !nbdkit_available("audit8_measure_refusals_at_the_helpers_interval") {
        return;
    }
    let daemon = Daemon::start();
    for (pause, rounds) in [
        (Duration::from_millis(30), 800),
        (Duration::from_millis(100), 1500),
    ] {
        let mut refused = 0;
        for _ in 0..rounds {
            let started = Instant::now();
            let connection = loop {
                match daemon.open() {
                    Ok(connection) => break connection,
                    Err(error) => {
                        assert!(started.elapsed() < DEADLINE, "{error}: {}", daemon.log());
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };
            drop(connection);
            std::thread::sleep(pause);
            if daemon.open().is_err() {
                refused += 1;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        eprintln!("audit8: pause {pause:?}: {refused} of {rounds} fresh handshakes refused");
    }
}
