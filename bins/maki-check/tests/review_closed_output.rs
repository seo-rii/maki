//! `maki-check` printed its report with `println!`, which panics when the
//! write fails: a reader that closed the pipe early (`maki-check <root> |
//! grep -q 'check passed'` under `set -o pipefail`) turned a clean check
//! into status 101. A closed stdout is not a failure and never hides the
//! verdict; any other failure to write the report is reported on stderr and
//! fails the command.
#![cfg(unix)]

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use maki_backing::FileBacking;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;

/// A pipe whose read end is already closed: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn check(args: &[&str], stdout: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-check"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn maki-check")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn created_volume(dir: &Path) -> String {
    let root = dir.join("vol");
    let backing = FileBacking::new(&root).unwrap();
    init::create_volume(
        &backing,
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xC105ED),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(4096, 4096, 512, 4384, 1 << 20, 64 << 10).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    root.to_string_lossy().into_owned()
}

/// Damage both superblock copies: the fast check then reports `check FAILED`.
fn corrupt(root: &str) {
    for copy in ["superblock.a", "superblock.b"] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("{root}/{copy}"))
            .unwrap();
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&[0xFF; 16]).unwrap();
    }
}

#[test]
fn help_and_version_succeed_when_the_stdout_reader_has_gone() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let output = check(&[flag], closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stderr}");
        assert!(!stderr.contains("writing"), "{flag}: {stderr}");
    }
}

#[test]
fn the_verdict_survives_a_stdout_reader_that_has_gone() {
    let dir = tempfile::tempdir().unwrap();
    let root = created_volume(dir.path());
    for args in [vec![root.as_str()], vec![root.as_str(), "--deep"]] {
        let output = check(&args, closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(!stderr.contains("writing"), "{args:?}: {stderr}");
    }

    corrupt(&root);
    // The verdict, not an error before the report, is what exits 1 here.
    let read = check(&[&root], Stdio::piped());
    assert_eq!(read.status.code(), Some(1), "{}", stderr(&read));
    assert!(String::from_utf8_lossy(&read.stdout).contains("check FAILED"));
    let output = check(&[&root], closed_pipe());
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_report_that_cannot_be_written_fails_the_command_and_names_the_verdict() {
    let full = || -> Stdio {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
            .into()
    };
    let dir = tempfile::tempdir().unwrap();
    let root = created_volume(dir.path());
    let passed = check(&[&root, "--deep"], full());
    assert_eq!(passed.status.code(), Some(1), "{}", stderr(&passed));
    assert!(
        stderr(&passed).contains("check passed, but writing the report failed"),
        "{}",
        stderr(&passed)
    );
    for flag in ["--help", "--version"] {
        let output = check(&[flag], full());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{flag}: {stderr}");
        assert!(
            stderr.contains("error: writing the output failed"),
            "{flag}: {stderr}"
        );
    }

    corrupt(&root);
    let failed = check(&[&root], full());
    assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
    assert!(
        stderr(&failed).contains("check FAILED, but writing the report failed"),
        "{}",
        stderr(&failed)
    );
}
