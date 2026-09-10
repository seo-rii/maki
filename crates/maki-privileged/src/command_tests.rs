//! Safe subprocess fixtures: even the baseline implementation finishes within
//! three seconds. These tests never call a storage utility or touch a device.
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::command::{capture, Policy};

/// Fixture directories are named by pid + wall clock; the clock can repeat
/// within one process (coarse ticks), so a per-process sequence keeps them
/// unique.
static FIXTURE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn policy() -> Policy {
    Policy {
        timeout: Duration::from_millis(150),
        terminate_grace: Duration::from_millis(50),
        reap_timeout: Duration::from_millis(500),
        max_output_bytes: 64 * 1024,
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                | (u128::from(FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    << 96)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn command(&self, scenario: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "exec::command_tests::child_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("MAKI_COMMAND_SCENARIO", scenario)
        .env("MAKI_COMMAND_FIXTURE_DIR", &self.0)
        .process_group(0);
        cmd
    }
    fn pid(&self, name: &str) -> i32 {
        std::fs::read_to_string(self.0.join(name))
            .unwrap()
            .parse()
            .unwrap()
    }
    fn assert_reaped(&self, name: &str) {
        let pid = self.pid(name);
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "fixture {name} still exists"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Each fixture also exits naturally after three seconds. Clean up
        // the known descendant if an assertion fails before its normal exit.
        if let Ok(pid) = std::fs::read_to_string(self.0.join("descendant")) {
            if let Ok(pid) = pid.parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                unsafe {
                    libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn hung_command_has_a_deadline_and_is_reaped() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let error = capture(&mut fixture.command("hang"), policy()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
    fixture.assert_reaped("parent");
}

#[test]
fn excessive_stdout_is_rejected_and_child_is_reaped() {
    let fixture = Fixture::new();
    let error = capture(&mut fixture.command("stdout"), policy()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    fixture.assert_reaped("parent");
}

#[test]
fn excessive_stderr_is_rejected_and_child_is_reaped() {
    let fixture = Fixture::new();
    let error = capture(&mut fixture.command("stderr"), policy()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    fixture.assert_reaped("parent");
}

#[test]
fn exited_parent_with_descendant_holding_pipe_still_times_out() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let error = capture(&mut fixture.command("descendant"), policy()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
    fixture.assert_reaped("parent");
    fixture.assert_reaped("descendant");
}

#[test]
fn successful_daemonization_preserves_the_daemon() {
    let fixture = Fixture::new();
    let output = capture(&mut fixture.command("daemon"), policy()).unwrap();
    assert!(output.status.success());
    fixture.assert_reaped("parent");
    assert_eq!(unsafe { libc::kill(fixture.pid("descendant"), 0) }, 0);
}

#[test]
fn ordinary_exit_status_and_captured_output_are_preserved() {
    let fixture = Fixture::new();
    let output = capture(&mut fixture.command("failure"), policy()).unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.ends_with(b"fixture stdout\n"));
    assert_eq!(output.stderr, b"fixture stderr\n");
    fixture.assert_reaped("parent");
}

#[test]
#[ignore = "subprocess fixture, invoked explicitly by the command tests"]
fn child_fixture() {
    let scenario = std::env::var("MAKI_COMMAND_SCENARIO").unwrap();
    let directory = PathBuf::from(std::env::var_os("MAKI_COMMAND_FIXTURE_DIR").unwrap());
    std::fs::write(directory.join("parent"), std::process::id().to_string()).unwrap();
    match scenario.as_str() {
        "hang" => {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        "stdout" => io::stdout().write_all(&vec![b'x'; 70 * 1024]).unwrap(),
        "stderr" => io::stderr().write_all(&vec![b'x'; 70 * 1024]).unwrap(),
        "descendant" | "daemon" => {
            let mut descendant = Command::new("/bin/sleep");
            descendant.arg("3").stdin(Stdio::null());
            if scenario == "daemon" {
                descendant.stdout(Stdio::null()).stderr(Stdio::null());
            }
            // This fixture must exit before its child to reproduce inherited
            // pipes and successful daemonization. The harness owns cleanup.
            #[allow(clippy::zombie_processes)]
            let child = descendant.spawn().unwrap();
            std::fs::write(directory.join("descendant"), child.id().to_string()).unwrap();
        }
        "failure" => {
            println!("fixture stdout");
            eprintln!("fixture stderr");
            std::process::exit(7);
        }
        _ => panic!("unknown fixture scenario"),
    }
    std::process::exit(0);
}
