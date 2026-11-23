//! `maki-attach` printed its plans with `print!`/`println!`, which panic
//! when the write fails: `maki-attach attach --volume v --plan | head -3`
//! exited 101. A stdout reader that has gone is not a failure; any other
//! failure to write a requested plan is reported on stderr and fails the
//! preview, which produces nothing else.
#![cfg(unix)]

use std::process::{Command, Output, Stdio};

const VOLUME: &str = "closed-output-fixture";

/// A pipe whose read end is already closed: every write fails with `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn helper(args: &[&str], stdout: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .env_remove("SERVICE_RESULT")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn maki-attach")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every command that prints a plan and executes nothing.
fn plans() -> Vec<Vec<&'static str>> {
    let mut plans: Vec<Vec<&str>> = ["attach", "detach", "recover", "cleanup", "verify"]
        .into_iter()
        .map(|verb| vec![verb, "--volume", VOLUME, "--plan"])
        .collect();
    plans.push(vec![
        "grow",
        "--volume",
        VOLUME,
        "--size-bytes",
        "8589934592",
        "--plan",
    ]);
    plans.push(vec!["recover-failed-start", "--volume", VOLUME, "--plan"]);
    plans
}

#[test]
fn plans_succeed_when_the_stdout_reader_has_gone() {
    for args in plans() {
        // The preview is not empty: a reader would have seen a plan.
        let read = helper(&args, Stdio::piped());
        assert_eq!(read.status.code(), Some(0), "{args:?}: {}", stderr(&read));
        assert!(!read.stdout.is_empty(), "{args:?}");

        let output = helper(&args, closed_pipe());
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(!stderr.contains("writing"), "{args:?}: {stderr}");
    }
}

#[test]
fn the_failed_start_preview_succeeds_when_the_stdout_reader_has_gone() {
    let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(["recover-failed-start", "--volume", VOLUME, "--plan"])
        .env("RUST_BACKTRACE", "0")
        .env("SERVICE_RESULT", "exit-code")
        .env("EXIT_CODE", "exited")
        .env("EXIT_STATUS", "1")
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn a_plan_that_cannot_be_written_fails_the_preview() {
    for args in plans() {
        let full: Stdio = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
            .into();
        let output = helper(&args, full);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("error: writing the plan failed"),
            "{args:?}: {stderr}"
        );
    }
}
