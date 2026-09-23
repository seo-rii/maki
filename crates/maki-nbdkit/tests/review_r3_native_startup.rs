//! Native, rootless startup qualification. No NBD client is opened before
//! readiness: recovery, provider validation and control binding must happen
//! independently of the first connection.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(8);

fn native_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| match Command::new("nbdkit").arg("--version").output() {
        Ok(output) => {
            assert!(output.status.success(), "installed nbdkit cannot run");
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("nbdkit unavailable; skipping optional native startup qualification");
            false
        }
        Err(error) => panic!("nbdkit probe failed: {error}"),
    })
}

struct Fixture {
    dir: tempfile::TempDir,
    config: PathBuf,
    control: PathBuf,
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
name = "native-startup"
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
        Self {
            dir,
            config,
            control,
            root,
        }
    }

    fn notify(&self) -> (UnixDatagram, PathBuf) {
        let path = self.dir.path().join("notify.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        (socket, path)
    }
}

struct Server {
    child: Child,
    stderr: tempfile::NamedTempFile,
}

impl Server {
    fn start(fixture: &Fixture, notify: Option<&Path>) -> Self {
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
            .stderr(stderr.reopen().unwrap());
        if let Some(notify) = notify {
            command.env("NOTIFY_SOCKET", notify);
        } else {
            command.env_remove("NOTIFY_SOCKET");
        }
        Self {
            child: command
                .spawn()
                .expect("nbdkit is required for this native test"),
            stderr,
        }
    }

    fn diagnostics(&mut self) -> String {
        use std::io::Read;
        // Inspect a bounded log only after this process has fully exited.
        if !self.stop_and_reap() {
            return "native process could not be reaped before the deadline; log left unread"
                .into();
        }
        let mut bytes = Vec::new();
        self.stderr
            .reopen()
            .unwrap()
            .take(4096)
            .read_to_end(&mut bytes)
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn stop_and_reap(&mut self) -> bool {
        if self.child.try_wait().ok().flatten().is_some() {
            return true;
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if self.child.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn wait_ready(&mut self, socket: &UnixDatagram) {
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            if ready(socket) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "startup exited before READY: {}",
                self.diagnostics()
            );
        }
        panic!(
            "startup did not send READY before the deadline: {}",
            self.diagnostics()
        );
    }

    fn wait_failure_without_ready(&mut self, socket: &UnixDatagram) -> ExitStatus {
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            assert!(!ready(socket), "failed startup announced READY");
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(!status.success(), "invalid startup exited successfully");
                assert!(!ready(socket), "failed startup left a READY notification");
                return status;
            }
        }
        panic!(
            "invalid startup stayed alive until the deadline: {}",
            self.diagnostics()
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Only the test's own process group. Every polling loop has a bound.
        self.stop_and_reap();
    }
}

fn ready(socket: &UnixDatagram) -> bool {
    let mut buffer = [0; 4096];
    match socket.recv(&mut buffer) {
        Ok(count) => buffer[..count]
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"READY=1"),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            false
        }
        Err(error) => panic!("notification receive failed: {error}"),
    }
}

fn status(path: &Path) -> serde_json::Value {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut stream = tokio::net::UnixStream::connect(path)
                    .await
                    .expect("READY requires an already bound control socket");
                maki_control::protocol::send_command(
                    &mut stream,
                    &maki_control::protocol::Request::new("status"),
                )
                .await
                .unwrap();
                maki_control::protocol::read_response(&mut stream)
                    .await
                    .unwrap()
            })
            .await
            .expect("control status deadline")
        })
}

#[test]
fn ready_without_a_first_nbd_client_requires_recovery_and_control_binding() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    let (notify, notify_path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&notify_path));
    server.wait_ready(&notify);
    let response = status(&fixture.control);
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"]["io_state"], "running");
    use maki_backing::Backing;
    let backing = maki_backing::FileBacking::new(&fixture.root).unwrap();
    assert!(
        backing.try_lock(maki_format::layout::VOLUME_LOCK).is_err(),
        "recovered volume lock must already be held at READY"
    );
}

#[test]
fn invalid_configuration_exits_without_ready_or_a_client() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::write(&fixture.config, "not valid TOML").unwrap();
    let (notify, notify_path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&notify_path));
    server.wait_failure_without_ready(&notify);
    assert!(!fixture.control.exists());
}

#[test]
fn failed_recovery_exits_without_ready_or_a_client() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.root.join(maki_format::layout::SUPERBLOCK_A)).unwrap();
    std::fs::remove_file(fixture.root.join(maki_format::layout::SUPERBLOCK_B)).unwrap();
    let (notify, notify_path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&notify_path));
    server.wait_failure_without_ready(&notify);
    assert!(!fixture.control.exists());
}

#[test]
fn provider_selftest_failure_exits_without_ready() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    let raw = std::fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("test-profile-v1", "different-profile");
    std::fs::write(&fixture.config, raw).unwrap();
    let (notify, path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&path));
    server.wait_failure_without_ready(&notify);
    assert!(
        server.diagnostics().contains("compatibility"),
        "{}",
        server.diagnostics()
    );
    assert!(!fixture.control.exists());
}

#[test]
fn control_bind_failure_exits_without_ready() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::create_dir(&fixture.control).unwrap();
    let (notify, path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&path));
    server.wait_failure_without_ready(&notify);
    assert!(
        server.diagnostics().contains("control socket"),
        "{}",
        server.diagnostics()
    );
}

#[test]
fn malformed_and_unreachable_notify_destinations_fail_startup() {
    if !native_available() {
        return;
    }
    for malformed in [false, true] {
        let fixture = Fixture::new();
        let (notify, _) = fixture.notify();
        let path = if malformed {
            PathBuf::from("relative-notify")
        } else {
            fixture.dir.path().join("absent.sock")
        };
        let mut server = Server::start(&fixture, Some(&path));
        server.wait_failure_without_ready(&notify);
        assert!(
            server.diagnostics().contains("readiness notification"),
            "{}",
            server.diagnostics()
        );
    }
}

#[test]
fn abstract_notification_completes_before_the_first_client() {
    if !native_available() {
        return;
    }
    use std::os::linux::net::SocketAddrExt;
    let fixture = Fixture::new();
    let name = format!(
        "maki-native-{}-{}",
        std::process::id(),
        fixture.dir.path().file_name().unwrap().to_str().unwrap()
    );
    let notify = UnixDatagram::bind_addr(
        &std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap(),
    )
    .unwrap();
    notify
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut server = Server::start(&fixture, Some(Path::new(&format!("@{name}"))));
    server.wait_ready(&notify);
    assert_eq!(status(&fixture.control)["ok"], true);
}

#[test]
fn manual_start_without_notify_still_initializes_before_any_client() {
    if !native_available() {
        return;
    }
    let fixture = Fixture::new();
    let mut server = Server::start(&fixture, None);
    let started = Instant::now();
    while !fixture.control.exists() && started.elapsed() < DEADLINE {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "{}",
            server.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        fixture.control.exists(),
        "manual startup must initialize control without a client"
    );
    assert_eq!(status(&fixture.control)["ok"], true);
}

#[test]
fn first_nbd_opens_do_not_reinitialize_or_send_duplicate_ready() {
    if !native_available() {
        return;
    }
    for program in ["nbdinfo", "timeout"] {
        if Command::new(program).arg("--version").output().is_err() {
            eprintln!("{program} unavailable; skipping native first-open qualification");
            return;
        }
    }
    let fixture = Fixture::new();
    let (notify, path) = fixture.notify();
    let mut server = Server::start(&fixture, Some(&path));
    server.wait_ready(&notify);
    for _ in 0..2 {
        let output = Command::new("timeout")
            .args(["--kill-after=1s", "5s", "nbdinfo", "--json", "--list"])
            .arg(format!(
                "nbd+unix:///?socket={}",
                fixture.dir.path().join("nbd.sock").display()
            ))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "native first-open negotiation failed"
        );
    }
    assert!(!ready(&notify), "first opens must not send another READY");
    assert_eq!(status(&fixture.control)["ok"], true);
}
