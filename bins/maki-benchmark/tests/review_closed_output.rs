//! `maki-benchmark --help` printed with `println!`, which panics when the
//! write fails: `maki-benchmark --help | head -1` exited 101. A stdout
//! reader that has gone is not a failure, as for the report itself.
#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn help_succeeds_when_the_stdout_reader_has_gone() {
    for flag in ["--help", "-h"] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
            .arg(flag)
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stderr}");
        assert!(!stderr.contains("writing"), "{flag}: {stderr}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn help_that_cannot_be_written_fails() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .arg("--help")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("error: writing the output failed"),
        "{stderr}"
    );
}
