//! `maki-witness --version` printed the usage as an error and exited 1:
//! the witness service was the one deployed binary that could not report
//! its revision (BUG-112 added `--version` to `maki` and `maki-check`).
//! The version line has the form of `maki --version` and, like `--help`, is
//! answered only as the sole argument.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maki-witness"))
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
            format!("maki-witness {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(output.stderr.is_empty(), "{flag}: {stderr}");
    }
}

#[test]
fn help_names_the_version_option_and_goes_to_stdout() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("maki-witness --help | --version"), "{help}");
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn version_with_another_argument_is_still_refused() {
    for args in [
        &["--version", "extra"][..],
        &["serve", "--version"],
        &["--version", "--help"],
    ] {
        let output = run(args);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
}
