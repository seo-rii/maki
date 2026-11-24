//! nbdkit on a private Unix socket, for the tests that run the helper's
//! NBD handshake (and its kernel connect) against a real server.
//!
//! Where nbdkit cannot run, a test says that it is skipped and passes;
//! `MAKI_TEST_REQUIRE_NBDKIT=1`, which the CI jobs that install nbdkit set,
//! makes that a failure.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBDKIT";

static SCRATCH: AtomicU64 = AtomicU64::new(0);

/// Whether nbdkit runs here. When it does not, `test` reports that it is
/// skipped, or fails when nbdkit is required.
pub fn available(test: &str) -> bool {
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

/// `TMPDIR`, or `/tmp` where `TMPDIR` is too long for the socket below it:
/// a Unix socket path holds at most 107 bytes.
pub fn short_temp_dir() -> PathBuf {
    let temp = std::env::temp_dir();
    if temp.as_os_str().len() <= 60 {
        temp
    } else {
        PathBuf::from("/tmp")
    }
}

/// A running `nbdkit --foreground -U <socket> <arguments>`, stopped and
/// removed with its directory when dropped.
pub struct Server {
    child: Child,
    directory: PathBuf,
    socket: PathBuf,
}

impl Server {
    pub fn start(arguments: &[&str]) -> Self {
        let directory = short_temp_dir().join(format!(
            "maki-nbdkit-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("nbd.sock");
        let pid_file = directory.join("nbdkit.pid");
        let log = std::fs::File::create(directory.join("nbdkit.log")).unwrap();
        let child = Command::new("nbdkit")
            .args(["--foreground", "--exit-with-parent", "-U"])
            .arg(&socket)
            .arg("-P")
            .arg(&pid_file)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start nbdkit");
        let mut server = Self {
            child,
            directory,
            socket,
        };
        // nbdkit writes its PID file once it accepts connections.
        let started = Instant::now();
        while !std::fs::read_to_string(&pid_file).is_ok_and(|pid| pid.ends_with('\n')) {
            if let Some(status) = server.child.try_wait().unwrap() {
                panic!(
                    "nbdkit {arguments:?} exited with {status}: {}",
                    server.log()
                );
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "nbdkit {arguments:?} did not start: {}",
                server.log()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        server
    }

    pub fn socket(&self) -> &str {
        self.socket.to_str().unwrap()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("nbdkit.log")).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
