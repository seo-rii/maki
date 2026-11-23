//! Audit round 5 (docs-ops): the read-only commands print with `println!`,
//! which panics when stdout is a pipe whose reader has gone (`| head -1`,
//! `| grep -q ...`). The process then exits 101 with a Rust panic message
//! instead of the command's own verdict, so under `set -o pipefail` a
//! pipeline such as `maki check <cfg> --deep | grep -q 'verdict: clean'`
//! fails on a clean volume. `volume create` and the control commands already
//! treat a broken pipe as "the reader has what it wanted".
//!
//! These tests demonstrate the behaviour on the current code: they FAIL
//! (status 101, panic text on stderr) until the commands handle EPIPE.
#![cfg(unix)]

use std::process::{Command, Stdio};

/// Run `maki` with stdout connected to a pipe that nobody reads.
fn run_with_closed_stdout(args: &[&str]) -> (Option<i32>, String) {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn help_does_not_panic_when_the_reader_has_gone() {
    let (status, stderr) = run_with_closed_stdout(&["--help"]);
    assert!(
        !stderr.contains("panicked"),
        "maki --help panicked on a closed stdout: {stderr}"
    );
    assert_ne!(status, Some(101), "panic exit status; stderr: {stderr}");
}

#[test]
fn an_offline_check_does_not_panic_when_the_reader_has_gone() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let config = dir.path().join("volume.toml");
    std::fs::write(
        &config,
        format!(
            "config_schema_version = 1\n\
             [volume]\nname = \"audit5\"\nmax_virtual_size = \"16MiB\"\n\
             device_block_size = 4096\ncrypto_unit_size = 4096\nshard_logical_size = \"8MiB\"\n\
             [crypto]\nprovider = \"local-aes-gcm-siv\"\n\
             crypto_compatibility_id = \"local-aes-gcm-siv-v1\"\n\
             key = {{ source = \"credential\", name = \"crypto-token\" }}\n\
             [crypto.capabilities]\nsupported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n\
             [backing]\nroot = \"{}\"\njournal_segment_size = \"1MiB\"\njournal_max_bytes = \"4MiB\"\n\
             checkpoint_reserve_bytes = \"1MiB\"\njournal_emergency_reserve_bytes = \"1MiB\"\n",
            root.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let created = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(["volume", "create", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "volume create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    for args in [
        vec!["check", config.to_str().unwrap(), "--deep"],
        vec!["volume", "inspect", config.to_str().unwrap()],
    ] {
        let (status, stderr) = run_with_closed_stdout(&args);
        assert!(
            !stderr.contains("panicked"),
            "maki {args:?} panicked on a closed stdout: {stderr}"
        );
        assert_ne!(status, Some(101), "{args:?}: panic exit status");
    }
}
