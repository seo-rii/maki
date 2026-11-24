#![cfg(unix)]
//! BUG-108: the control commands could only find the daemon through the
//! volume configuration, which they read and fully validated first.
//!
//! - The packaged configuration is `root:maki 0640`, so a `maki-admin`
//!   member, whom the control socket admits, could not run `maki status`.
//!   `--socket <path>` names the socket directly.
//! - A configuration edited ahead of the next start and failing validation
//!   blocked `maki drain` on the running daemon. Control commands need only
//!   the socket address, so they parse the configuration without the
//!   attach-time validation.
#[path = "support/volume_config.rs"]
mod volume_config;

#[path = "support/short_dir.rs"]
mod short_dir;

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

const VALID: &str = r#"
config_schema_version = 1
[volume]
name = "control-cli"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "test"
key = { source = "env", name = "test-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
"#;

fn config(dir: &Path, socket: &Path, extra: &str) -> std::path::PathBuf {
    let path = dir.join("volume.toml");
    volume_config::write(
        &path,
        format!(
            "{VALID}[backing]\nroot = {:?}\n[control]\nsocket = {:?}\n{extra}",
            dir.join("volume").to_string_lossy(),
            socket.to_string_lossy()
        ),
    )
    .unwrap();
    path
}

/// Run the CLI against a fake daemon; return its output and the request.
async fn run(socket: &Path, args: Vec<String>) -> (Output, Option<Value>) {
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let mut child = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(args)
            .output()
            .unwrap()
    });
    let stream = tokio::select! {
        accepted = listener.accept() => accepted.unwrap().0,
        output = &mut child => return (output.unwrap(), None),
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let request = maki_control::protocol::read_line(&mut rd).await.unwrap();
    use tokio::io::AsyncWriteExt;
    wr.write_all(b"{\"ok\":true,\"data\":{}}\n").await.unwrap();
    let output = child.await.unwrap();
    (output, Some(serde_json::from_slice(&request).unwrap()))
}

#[tokio::test]
async fn socket_option_reaches_the_daemon_without_any_configuration() {
    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let args = ["status", "--socket"]
        .iter()
        .map(|s| s.to_string())
        .chain([socket.to_string_lossy().into_owned()])
        .collect();
    let (output, request) = run(&socket, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request.unwrap()["command"], "status");
}

#[tokio::test]
async fn socket_option_works_for_reload_cache() {
    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let args = vec![
        "reload".into(),
        "--socket".into(),
        socket.to_string_lossy().into_owned(),
        "cache".into(),
        "--max-bytes".into(),
        "4096".into(),
    ];
    let (output, request) = run(&socket, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = request.unwrap();
    assert_eq!(request["command"], "reload");
    assert_eq!(request["section"], "cache");
    assert_eq!(request["payload"]["max_bytes"], 4096);
}

#[tokio::test]
async fn drain_reaches_the_daemon_although_the_edited_configuration_is_invalid() {
    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    // Parses, but fails attach-time validation (multi-connection is refused).
    let path = config(dir.path(), &socket, "[nbd]\nconnections = 2\n");
    let (output, request) = run(&socket, vec!["drain".into(), path.to_string_lossy().into()]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request.unwrap()["command"], "drain");
}

#[test]
fn socket_and_configuration_together_are_refused() {
    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let path = config(dir.path(), &socket, "");
    let output = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["status", path.to_str().unwrap(), "--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("either"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn socket_option_is_refused_outside_control_commands() {
    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let path = config(dir.path(), &socket, "");
    let output = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["check", path.to_str().unwrap(), "--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--socket"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn checkpoint_output(ok: bool, stdout: std::process::Stdio) -> Output {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let dir = short_dir::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&request).unwrap()["command"],
            "checkpoint"
        );
        writeln!(stream, "{{\"ok\":{ok}}}").unwrap();
    });
    let result = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["checkpoint", "--socket"])
        .arg(socket)
        .stdout(stdout)
        .output()
        .unwrap();
    daemon.join().unwrap();
    result
}

#[test]
fn closed_output_pipe_preserves_the_daemons_verdict() {
    for ok in [true, false] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let result = checkpoint_output(ok, writer.into());
        assert_eq!(result.status.code(), Some(if ok { 0 } else { 1 }));
        assert!(
            result.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn failed_output_reports_the_received_verdict() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let result = checkpoint_output(true, full.into());
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("daemon reported success"));
}
