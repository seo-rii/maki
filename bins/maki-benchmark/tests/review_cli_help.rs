//! `maki-benchmark --version` was a usage error (`unknown option:
//! --version`, status 2), although a benchmark report is only comparable
//! with the revision that produced it (BUG-112 added `--version` to `maki`
//! and `maki-check`). The version line has the form of `maki --version`
//! and, like `--help`, is answered only as the sole argument, before any
//! configuration is read.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maki-benchmark"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn version_names_the_package_version() {
    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stderr}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("maki-benchmark {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(output.stderr.is_empty(), "{flag}: {stderr}");
    }
}

#[test]
fn help_names_the_version_option() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.starts_with("usage: maki-benchmark "), "{help}");
    assert!(help.contains("maki-benchmark --help | --version"), "{help}");
}

#[test]
fn version_with_another_argument_is_still_a_usage_error() {
    for args in [
        &["--version", "volume.toml"][..],
        &["volume.toml", "--version"],
        &["--version", "--help"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage:"),
            "{args:?}"
        );
    }
}
