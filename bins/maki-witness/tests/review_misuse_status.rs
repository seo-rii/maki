//! `maki-witness` reported misuse with status 1, the status of a failed
//! command: an unknown command, a missing or extra argument and a volume
//! identity that is not a UUID all exited 1, where the other binaries exit 2
//! for a command line they refuse. And it read its arguments with
//! `std::env::args`, which panics on an argument that is not UTF-8, so such
//! an argument ended the command with status 101 and a Rust panic message
//! instead of a usage error.

use std::path::Path;
use std::process::{Command, Output};

const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const USAGE: &str = "maki-witness init STATE_DIRECTORY VOLUME_UUID";

fn witness<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-witness"))
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn an_unknown_command_or_a_wrong_argument_count_exits_2_with_the_usage() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = dir.path().join("missing.toml");
    for args in [
        vec![],
        vec!["unknown"],
        vec!["init"],
        vec!["init", text(&state)],
        vec!["init", text(&state), UUID, "extra"],
        vec!["init-etcd", text(&config)],
        vec!["serve"],
        vec!["serve", text(&config), "extra"],
        vec!["inspect"],
        vec!["fingerprint"],
        vec!["--help", "extra"],
        vec!["--version", "--help"],
    ] {
        let output = witness(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(USAGE), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(
        !state.exists(),
        "a refused init created its state directory"
    );
}

#[test]
fn a_volume_identity_that_is_not_a_uuid_exits_2_before_anything_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = dir.path().join("missing.toml");
    for args in [
        ["init", text(&state), "not-a-uuid"],
        ["init-etcd", text(&config), "not-a-uuid"],
    ] {
        let output = witness(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("volume identity must be a UUID"),
            "{args:?}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(
        !state.exists(),
        "a refused init created its state directory"
    );
}

/// A command whose arguments are well formed still exits 1 when it fails.
#[test]
fn a_command_that_fails_still_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    for args in [
        ["serve", text(&missing)],
        ["inspect", text(&missing)],
        ["fingerprint", text(&missing)],
    ] {
        let output = witness(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(!stderr.contains(USAGE), "{args:?}: {stderr}");
    }
    let output = witness(&["init-etcd", text(&missing), UUID]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

/// Every position: the command word, a path, a volume identity and an
/// argument after `--help`. None reaches a command.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_is_refused_with_status_2() {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let invalid = OsStr::from_bytes(b"caf\xe9");
    let state = dir.path().join(invalid);
    let os = |text: &str| OsString::from(text);
    for args in [
        vec![invalid.to_owned()],
        vec![os("fingerprint"), dir.path().join(invalid).into_os_string()],
        vec![os("init"), state.clone().into_os_string(), os(UUID)],
        vec![
            os("init"),
            dir.path().join("state").into(),
            invalid.to_owned(),
        ],
        vec![os("serve"), dir.path().join(invalid).into_os_string()],
        vec![os("--help"), invalid.to_owned()],
    ] {
        let output = witness(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("arguments must be valid UTF-8"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(
        !state.exists(),
        "a refused init created its state directory"
    );
    assert!(!dir.path().join("state").exists());
}
