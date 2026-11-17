//! `maki-witness init` and `serve` opened the authority's state directory
//! with no owner or mode check, so a directory another user owns, or one
//! group or others may write, was enrolled into or served; whoever could
//! write it could put an older authority record back. Both commands now
//! refuse it before writing state or binding the listener. The finer cases
//! (the `remote.*` files inside, accepted modes) are covered next to the
//! store in maki-backing's `review_witness_state_owner.rs`.
//!
//! Changing an owner needs root, so those cases skip otherwise.

#![cfg(unix)]

use std::io::{BufRead, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use maki_witness::{Principal, Role, ServerOptions, TlsFiles};

/// An unprivileged uid and gid that is neither root nor this process.
const NOBODY: u32 = 65534;
const IDENTITY: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn chown(path: &Path, owner: u32) {
    std::os::unix::fs::chown(path, Some(owner), Some(owner)).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn init(state: &Path) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_maki-witness"))
        .args(["init", state.to_str().unwrap(), IDENTITY])
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `serve`: `Ok(())` once it reports readiness (the guard stops it),
/// or `Err(stderr)` when it exits first.
fn serve(config: &Path) -> Result<(), String> {
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_maki-witness"))
            .args(["serve", config.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    let (line, wait) = mpsc::channel();
    std::thread::spawn(move || {
        let mut first = String::new();
        let _ = std::io::BufReader::new(stdout).read_line(&mut first);
        let _ = line.send(first);
    });
    let first = wait
        .recv_timeout(Duration::from_secs(10))
        .expect("serve neither became ready nor exited");
    if first.starts_with("maki-witness listening ") {
        return Ok(());
    }
    // Its output ended without readiness: it is exiting with an error.
    let mut text = String::new();
    stderr.read_to_string(&mut text).unwrap();
    Err(text)
}

/// A local-authority server configuration with real credentials, so that
/// `serve` reaches the state directory.
fn server_config(dir: &Path, state: &Path) -> std::path::PathBuf {
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let writer = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
    let tls = TlsFiles {
        ca_file: dir.join("client-ca.pem"),
        cert_file: dir.join("server.cert.pem"),
        key_file: dir.join("server.key.pem"),
    };
    std::fs::write(&tls.ca_file, writer.cert.pem()).unwrap();
    std::fs::write(&tls.cert_file, server.cert.pem()).unwrap();
    std::fs::write(&tls.key_file, server.key_pair.serialize_pem()).unwrap();
    chmod(&tls.key_file, 0o600);
    let options = ServerOptions {
        tls,
        principals: vec![Principal {
            certificate_sha256: maki_witness::certificate_fingerprint(writer.cert.der()),
            role: Role::Writer,
        }],
        timeout_ms: 1000,
        max_connections: 1,
    };
    let config = dir.join("server.toml");
    let text = toml::to_string(
        &serde_json::json!({"state_dir": state, "listen": "127.0.0.1:0", "server": options}),
    )
    .unwrap();
    std::fs::write(&config, text).unwrap();
    config
}

#[test]
fn init_refuses_a_state_directory_another_user_owns_or_can_write() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    chmod(&state, 0o777);
    let (enrolled, stderr) = init(&state);
    assert!(!enrolled, "init enrolled into a world-writable directory");
    assert!(
        stderr.contains("state directory must not be writable by group or others"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    if !is_root() {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping the owner case");
        return;
    }
    chmod(&state, 0o700);
    chown(&state, NOBODY);
    let (enrolled, stderr) = init(&state);
    assert!(
        !enrolled,
        "init enrolled into a directory uid {NOBODY} owns"
    );
    assert!(
        stderr.contains("state directory is owned by uid 65534"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
}

#[test]
fn serve_refuses_a_state_directory_another_user_owns_or_can_write() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = server_config(dir.path(), &state);
    assert!(init(&state).0);
    chmod(&state, 0o770);
    let stderr = serve(&config).expect_err("served a group-writable authority");
    assert!(
        stderr.contains("state directory must not be writable by group or others"),
        "{stderr}"
    );
    chmod(&state, 0o700);
    if is_root() {
        chown(&state, NOBODY);
        let stderr = serve(&config).expect_err("served an authority uid 65534 owns");
        assert!(
            stderr.contains("state directory is owned by uid 65534"),
            "{stderr}"
        );
        chown(&state, 0);
    } else {
        eprintln!("needs root to chown the fixture to uid {NOBODY}; skipping the owner case");
    }
    serve(&config).expect("the enrolled private authority serves");
}
