//! A command's output must never replace its exit status. `println!` panics
//! when the write fails, so a reader that closed the pipe early turned a
//! clean check into status 101:
//!
//! ```text
//! set -o pipefail
//! maki check "$cfg" --deep | grep -q 'deep check verdict: clean'
//! ```
//!
//! A closed stdout is not a failure: the reader has what it wanted, and the
//! command exits with its own verdict, as the control commands and
//! `volume create` already did. Any other failure to write a report (a full
//! destination) is reported on stderr and fails a command whose output is
//! its result.
//!
//! `eprintln!` panics the same way: with a stderr nobody reads, misuse (2),
//! the helper-verb instruction (3) and every error (1) all became 101. A
//! diagnostic that cannot be delivered is dropped; the status stands.
#![cfg(unix)]

#[path = "support/volume_config.rs"]
mod volume_config;

use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Output, Stdio};

const KEY: (&str, &str) = (
    "MAKI_CREDENTIAL_CLOSED_OUTPUT_KEY",
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
);

/// A pipe whose read end is already closed: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn maki(args: &[&str], stdout: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env(KEY.0, KEY.1)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn maki")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

struct Volume {
    _dir: tempfile::TempDir,
    root: String,
    config: String,
}

fn created_volume() -> Volume {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let config = dir
        .path()
        .join("volume.toml")
        .to_string_lossy()
        .into_owned();
    volume_config::write(
        &config,
        format!(
            r#"
config_schema_version = 1
[volume]
name = "closed-output"
max_virtual_size = "1MiB"
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "local-aes-gcm-siv-v1"
key = {{ source = "env", name = "closed-output-key" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "{root}"
"#
        ),
    )
    .unwrap();
    let created = maki(&["volume", "create", &config], Stdio::piped());
    assert!(created.status.success(), "{}", stderr(&created));
    Volume {
        _dir: dir,
        root,
        config,
    }
}

/// Damage both superblock copies: the fast check then reports `check FAILED`.
fn corrupt(volume: &Volume) {
    for copy in ["superblock.a", "superblock.b"] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{}/{copy}", volume.root))
            .unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&[0xFF; 16]).unwrap();
    }
}

#[test]
fn help_and_version_succeed_when_the_stdout_reader_has_gone() {
    for flag in ["--help", "-h", "help", "--version", "-V"] {
        let output = maki(&[flag], closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stderr}");
        assert!(!stderr.contains("writing"), "{flag}: {stderr}");
    }
}

#[test]
fn a_clean_check_stays_clean_when_the_stdout_reader_has_gone() {
    let volume = created_volume();
    for args in [
        vec!["check", volume.config.as_str()],
        vec!["check", volume.config.as_str(), "--deep"],
        vec!["volume", "inspect", volume.config.as_str()],
    ] {
        let output = maki(&args, closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(!stderr.contains("writing"), "{args:?}: {stderr}");
    }
}

#[test]
fn a_failed_check_still_fails_when_the_stdout_reader_has_gone() {
    let volume = created_volume();
    corrupt(&volume);
    let args = ["check", volume.config.as_str()];
    // The verdict, not an error before the report, is what exits 1 here.
    let read = maki(&args, Stdio::piped());
    assert_eq!(read.status.code(), Some(1), "{}", stderr(&read));
    assert!(String::from_utf8_lossy(&read.stdout).contains("check FAILED"));

    let output = maki(&args, closed_pipe());
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[cfg(target_os = "linux")]
fn full_device() -> Stdio {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap()
        .into()
}

#[cfg(target_os = "linux")]
#[test]
fn a_report_that_cannot_be_written_fails_the_command_and_names_the_verdict() {
    let volume = created_volume();
    let check = maki(&["check", &volume.config, "--deep"], full_device());
    assert_eq!(check.status.code(), Some(1), "{}", stderr(&check));
    assert!(
        stderr(&check).contains("check passed, but writing the report failed"),
        "{}",
        stderr(&check)
    );
    for args in [
        vec!["volume", "inspect", volume.config.as_str()],
        vec!["--help"],
        vec!["--version"],
    ] {
        let output = maki(&args, full_device());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("error: writing the output failed"),
            "{args:?}: {stderr}"
        );
    }

    corrupt(&volume);
    let failed = maki(&["check", &volume.config], full_device());
    assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
    assert!(
        stderr(&failed).contains("check FAILED, but writing the report failed"),
        "{}",
        stderr(&failed)
    );
}

#[test]
fn diagnostics_nobody_reads_do_not_replace_the_exit_status() {
    let missing = "/nonexistent-maki-closed-output/volume.toml";
    for (args, status) in [
        (vec![], 2),
        (vec!["no-such-command"], 2),
        (vec!["check", missing, "--timeout", "5"], 2),
        (vec!["attach", "--volume", "example"], 3),
        (vec!["check", missing], 1),
        (vec!["volume", "inspect", missing], 1),
        (vec!["status", missing, "--timeout", "0"], 1),
        (vec!["status", "--socket"], 1),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(&args)
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(closed_pipe())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(status), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

/// The logging sink writes to stderr too: an event nobody can read (here
/// the refusal of an invalid `MAKI_LOG`) must not stop the command.
#[test]
fn a_log_event_nobody_reads_does_not_stop_the_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_maki"))
        .arg("--version")
        .env("MAKI_LOG", "warning")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(closed_pipe())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("maki {}", env!("CARGO_PKG_VERSION"))
    );
}
