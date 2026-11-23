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

/// The usage described these verbs as "delegated to maki-attach
/// (privileged)". Nothing is delegated: `maki` starts no helper, prints the
/// `maki-attach` command to run and exits 3. The usage says what happens.
#[test]
fn usage_says_the_helper_verbs_only_print_the_command_to_run() {
    let help = Command::new(env!("CARGO_BIN_EXE_maki"))
        .arg("--help")
        .output()
        .unwrap();
    let usage = String::from_utf8_lossy(&help.stdout);
    let line = usage
        .lines()
        .find(|line| line.contains("maki attach|detach|grow"))
        .expect("the usage lists the helper verbs");
    assert!(!line.contains("delegated"), "{line}");
    for stated in ["not run here", "maki-attach command", "exit 3"] {
        assert!(line.contains(stated), "{stated:?} is missing from {line:?}");
    }
}
