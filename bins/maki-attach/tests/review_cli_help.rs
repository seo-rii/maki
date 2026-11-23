//! `maki-attach --help` was a usage error (status 2, `unknown command
//! "--help"`) and the helper had no `--version`, although `maki` and
//! `maki-check` answer both (BUG-112) and operators are asked to record the
//! Maki revision. Help goes to stdout with status 0, and the version line
//! has the form of `maki --version`.
//!
//! Both are answered only as the sole argument, before the arguments are
//! validated and before any configuration or attachment state is looked at.
//! Inside a verb's argument list they remain usage errors, so strict
//! parsing is unchanged.
use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
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
        let (status, stdout, stderr) = run(&[flag]);
        assert_eq!(status, 0, "{flag}: {stderr}");
        assert!(stdout.starts_with("usage:"), "{flag}: {stdout}");
        for verb in [
            "attach",
            "detach",
            "recover",
            "cleanup",
            "recover-failed-start",
            "verify",
            "grow",
        ] {
            assert!(
                stdout.contains(&format!("maki-attach {verb} ")),
                "{flag}: {verb} is missing from {stdout}"
            );
        }
        assert!(
            stdout.contains("maki-attach --help | --version"),
            "{stdout}"
        );
        assert!(stderr.is_empty(), "{flag}: {stderr}");
    }
}

#[test]
fn version_names_the_package_version() {
    for flag in ["--version", "-V"] {
        let (status, stdout, stderr) = run(&[flag]);
        assert_eq!(status, 0, "{flag}: {stderr}");
        assert_eq!(
            stdout,
            format!("maki-attach {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(stderr.is_empty(), "{flag}: {stderr}");
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

#[test]
fn help_and_version_are_honoured_only_as_the_sole_argument() {
    for args in [
        &["attach", "--help"][..],
        &["attach", "--volume", "help-fixture", "--help"],
        &["attach", "--volume", "help-fixture", "--plan", "-h"],
        &["verify", "--volume", "help-fixture", "--plan", "--version"],
        &[
            "grow",
            "--volume",
            "help-fixture",
            "--size-bytes",
            "4096",
            "-V",
        ],
        &["--help", "attach"],
        &["--help", "--version"],
        &["--version", "--plan"],
        &["help", "attach"],
        &["attach", "help"],
    ] {
        let (status, stdout, stderr) = run(args);
        assert_eq!(status, 2, "{args:?}: {stderr}");
        assert!(stdout.is_empty(), "{args:?} printed {stdout}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
    }
}
