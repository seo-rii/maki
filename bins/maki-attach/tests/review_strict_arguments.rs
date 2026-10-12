use std::process::Command;

#[test]
fn malformed_options_fail_before_config_or_plan() {
    for verb in ["attach", "detach", "recover", "cleanup", "grow", "verify"] {
        let cases: &[&[&str]] = &[
            &["--mountpoint"],
            &["--config"],
            &["--unknown"],
            &["--mountpoint", "/srv/first", "--mountpoint", "/srv/second"],
            &["--volume", "second"],
            &["--plan"],
            &["extra-position"],
            &["--config", "--uuid"],
        ];
        for extra in cases {
            let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
                .args([verb, "--volume", "strict-audit-missing-config", "--plan"])
                .args(*extra)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{verb} {extra:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(output.stdout.is_empty(), "invalid arguments printed a plan");
        }
    }
}

#[test]
fn flags_specific_to_another_verb_are_rejected() {
    for (verb, flag, value) in [
        ("attach", "--size-bytes", Some("4096")),
        ("detach", "--init-sentinel", None),
        ("recover", "--init-sentinel", None),
        ("cleanup", "--size-bytes", Some("4096")),
        ("grow", "--init-sentinel", None),
        (
            "verify",
            "--uuid",
            Some("11111111-2222-3333-4444-555555555555"),
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_maki-attach"));
        command.args([
            verb,
            "--volume",
            "strict-audit-missing-config",
            "--plan",
            flag,
        ]);
        if let Some(value) = value {
            command.arg(value);
        }
        assert_eq!(command.output().unwrap().status.code(), Some(2));
    }
}

#[test]
fn valid_plans_keep_defaults_and_growth_arguments() {
    for verb in ["attach", "detach", "recover", "cleanup", "verify", "grow"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_maki-attach"));
        command.args([verb, "--volume", "strict-audit-missing-config", "--plan"]);
        if verb == "grow" {
            command.args(["--size-bytes", "1048576"]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{verb}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
