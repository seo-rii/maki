//! `maki` refused an unknown command or a wrong number of arguments with
//! status 2, but an option or argument it could not use with status 1, the
//! status of a command that failed: `--timeout` without a positive number
//! of seconds, `--socket` without a path, beside a configuration or on a
//! command without a control round trip, every malformed `reload cache`
//! option, and an approval whose fence, root or storage identity is
//! malformed (which was noticed only after the configuration had been read
//! and its witness client built). Each is misuse, refused with status 2
//! before anything is read or contacted.
//!
//! The configuration and socket named here do not exist: a command that got
//! as far as reading or connecting would fail with status 1.
//!
//! An option given where the command expects a path or a reload section
//! (`maki check --deep`, the configuration forgotten) was taken for that
//! path: `maki` tried to open a file named `--deep` and exited 1 with "No
//! such file or directory". It is misuse too.

#[path = "support/short_dir.rs"]
mod short_dir;

use std::process::{Command, Output};

const ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn maki<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .env_remove("MAKI_LOG")
        .output()
        .unwrap()
}

/// `maki` run in `directory`, where a relative path is looked up.
fn maki_in(directory: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .current_dir(directory)
        .env_remove("MAKI_LOG")
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn malformed_options_and_approvals_exit_2_before_anything_is_read() {
    let dir = short_dir::tempdir().unwrap();
    let config = dir.path().join("missing.toml");
    let config = config.to_str().unwrap();
    let socket = dir.path().join("missing.sock");
    let socket = socket.to_str().unwrap();
    let backup = dir.path().join("backup");
    let backup = backup.to_str().unwrap();
    let upper = "A".repeat(64);
    for args in [
        vec!["status", config, "--timeout"],
        vec!["status", config, "--timeout", "0"],
        vec!["status", config, "--timeout", "soon"],
        vec!["--timeout", "-5", "drain", config],
        vec!["status", "--socket"],
        vec!["status", "--socket", "--timeout", "5"],
        vec!["status", config, "--socket", socket],
        vec!["check", config, "--socket", socket],
        vec!["volume", "inspect", "--socket", socket],
        vec!["reload", config, "cache"],
        vec!["reload", config, "cache", "--max-bytes"],
        vec!["reload", config, "cache", "--max-bytes", "lots"],
        vec![
            "reload",
            config,
            "cache",
            "--max-bytes",
            "1",
            "--max-bytes",
            "2",
        ],
        vec!["reload", config, "cache", "--max-bytes", "1", "--ttl", "0"],
        vec!["reload", config, "cache", "--max-bytes", "1", "--ttl"],
        vec!["reload", config, "cache", "--size", "1"],
        vec!["reload", "--socket", socket, "cache", "--size", "1"],
        vec!["volume", "takeover", config, "one", ROOT],
        vec!["volume", "takeover", config, "1", &upper],
        vec!["volume", "takeover", config, "1", "00"],
        vec!["volume", "restore", config, backup, "1", ROOT, "zz"],
        vec!["volume", "restore", config, backup, "-1", ROOT, ROOT],
        vec!["volume", "restore", config, backup, "1", "0x00", ROOT],
        vec!["volume", "resume-enrollment", config, "1", "not-a-uuid"],
        vec!["volume", "resume-enrollment", config, "x", UUID],
        vec![
            "volume",
            "resume-enrollment",
            config,
            "1",
            "not-a-uuid",
            "--discard",
        ],
        vec![
            "volume",
            "resume-enrollment",
            config,
            "1",
            "00000000-0000-0000-0000-000000000000",
        ],
    ] {
        let output = maki(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("No such file"),
            "{args:?} read its configuration or socket: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

/// Every word that stands where a configuration, an administrator
/// configuration, a backup directory or a reload section belongs. The
/// working directory holds a file of each such name whose contents are not
/// a configuration, so a command that opened one would fail with status 1
/// and a parse error.
#[test]
fn an_option_where_a_path_belongs_exits_2_before_anything_is_read() {
    let dir = short_dir::tempdir().unwrap();
    let config = dir.path().join("missing.toml");
    let config = config.to_str().unwrap();
    let socket = dir.path().join("missing.sock");
    let socket = socket.to_str().unwrap();
    let words = [
        "--deep",
        "--help",
        "--discard",
        "--bogus",
        "--dir",
        "--section",
        "-v",
        "-",
    ];
    for word in words {
        std::fs::write(dir.path().join(word), "not a configuration\n").unwrap();
    }
    let mut failures = Vec::new();
    for args in [
        vec!["check", "--deep"],
        vec!["check", "--help"],
        vec!["check", "-", "--deep"],
        vec!["volume", "create", "--discard"],
        vec!["volume", "inspect", "--help"],
        vec!["volume", "witness", "-v"],
        vec!["volume", "gc", "--bogus"],
        vec!["volume", "snapshot", config, "--dir"],
        vec!["volume", "snapshot", "--bogus", "--dir"],
        vec!["volume", "takeover", "--bogus", "1", ROOT],
        vec!["volume", "restore", config, "--dir", "1", ROOT, ROOT],
        vec!["volume", "resume-enrollment", "--discard", "1", UUID],
        vec!["status", "--help"],
        vec!["metrics", "-v"],
        vec!["checkpoint", "--bogus"],
        vec!["drain", "--bogus"],
        vec!["reload", "--deep", "cache", "--max-bytes", "4096"],
        vec!["reload", "--help", "limits"],
        vec!["reload", config, "--section"],
        vec!["reload", "--socket", socket, "--section"],
        vec!["status", "--timeout", "5", "--help"],
    ] {
        let output = maki_in(dir.path(), &args);
        let stderr = stderr(&output);
        if output.status.code() != Some(2)
            || !stderr.starts_with("error: ")
            || !stderr.contains("usage:")
            || stderr.contains("No such file")
            || stderr.contains("TOML")
            || !output.stdout.is_empty()
        {
            failures.push(format!("{args:?}: {:?}: {stderr}", output.status.code()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // A file whose name starts with `-` is still named as a path.
    let output = maki_in(dir.path(), &["check", "./--deep"]);
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("invalid TOML"), "{stderr}");
    for word in words {
        assert_eq!(
            std::fs::read_to_string(dir.path().join(word)).unwrap(),
            "not a configuration\n"
        );
    }
}

/// The same command lines with well-formed values get as far as the
/// configuration or the socket, and fail there with status 1.
#[test]
fn well_formed_commands_that_fail_still_exit_1() {
    let dir = short_dir::tempdir().unwrap();
    let config = dir.path().join("missing.toml");
    let config = config.to_str().unwrap();
    let socket = dir.path().join("missing.sock");
    let socket = socket.to_str().unwrap();
    let backup = dir.path().join("backup");
    let backup = backup.to_str().unwrap();
    for args in [
        vec!["status", config, "--timeout", "5"],
        vec!["status", "--socket", socket],
        vec![
            "reload",
            config,
            "cache",
            "--max-bytes",
            "4096",
            "--ttl",
            "1s",
        ],
        vec!["volume", "takeover", config, "1", ROOT],
        vec!["volume", "restore", config, backup, "1", ROOT, ROOT],
        vec![
            "volume",
            "resume-enrollment",
            config,
            "1",
            UUID,
            "--discard",
        ],
    ] {
        let output = maki(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
    }
}

#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_exits_2() {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;

    let invalid = OsStr::from_bytes(b"caf\xe9").to_owned();
    for args in [
        vec![invalid.clone()],
        vec![OsString::from("check"), invalid.clone()],
        vec![
            OsString::from("status"),
            OsString::from("--socket"),
            invalid,
        ],
    ] {
        let output = maki(&args);
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("arguments must be valid UTF-8"),
            "{args:?}: {stderr}"
        );
    }
}
