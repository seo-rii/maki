//! BUG-112: `maki --help` printed the usage to stderr and exited with the
//! misuse status 2, and neither `maki` nor `maki-check` had `--version`,
//! although operators are asked to record the Maki revision with every
//! capture and restore. Help goes to stdout with status 0; a bare or wrong
//! invocation still exits 2.
use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_maki"))
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn help_is_printed_to_stdout_and_succeeds() {
    for flag in ["--help", "-h", "help"] {
        let (status, stdout, _) = run(&[flag]);
        assert_eq!(status, 0, "{flag}");
        assert!(stdout.contains("usage:"), "{flag}: {stdout}");
    }
}

#[test]
fn version_names_the_package_version() {
    for flag in ["--version", "-V"] {
        let (status, stdout, _) = run(&[flag]);
        assert_eq!(status, 0, "{flag}");
        assert_eq!(stdout.trim(), format!("maki {}", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn misuse_still_exits_two_with_usage_on_stderr() {
    for args in [&[][..], &["no-such-command"][..]] {
        let (status, stdout, stderr) = run(args);
        assert_eq!(status, 2, "{args:?}");
        assert!(stdout.is_empty() && stderr.contains("usage:"), "{args:?}");
    }
}
