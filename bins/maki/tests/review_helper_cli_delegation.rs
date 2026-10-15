//! The administrative wrapper must preserve helper arguments, including the
//! NBD socket override that shares its name with the control socket option.

use std::process::Command;

#[test]
fn helper_socket_arguments_reach_the_delegation_instruction_unchanged() {
    for args in [
        vec!["attach", "example", "--socket", "/run/nbd.sock"],
        vec![
            "attach",
            "--volume",
            "example",
            "--socket",
            "/run/nbd.sock",
            "--plan",
        ],
        vec!["detach", "--volume", "example", "--socket", "/run/nbd.sock"],
        vec![
            "grow",
            "--volume",
            "example",
            "--size-bytes",
            "8589934592",
            "--socket",
            "/run/nbd.sock",
        ],
        // The helper owns validation, including its rejection of equals
        // syntax; the wrapper still preserves the original arguments.
        vec!["attach", "--volume", "example", "--socket=/run/nbd.sock"],
        vec![
            "attach",
            "--volume",
            "example",
            "--timeout",
            "helper-owned",
            "--socket",
            "/run/nbd.sock",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(&args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!("run `maki-attach {}`", args.join(" "))),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn leading_timeout_keeps_the_existing_helper_route() {
    for args in [
        vec!["attach", "example"],
        vec!["attach", "--volume", "example", "--socket", "/run/nbd.sock"],
        vec!["detach", "--volume", "example", "--socket", "/run/nbd.sock"],
        vec![
            "grow",
            "--volume",
            "example",
            "--size-bytes",
            "8589934592",
            "--socket",
            "/run/nbd.sock",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki"))
            .args(["--timeout", "5"])
            .args(&args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!("run `maki-attach {}`", args.join(" "))),
            "{args:?}: {stderr}"
        );
    }
}
