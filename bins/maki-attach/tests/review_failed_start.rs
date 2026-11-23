use std::process::Command;

fn plan(result: &str, code: &str, status: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .env_clear()
        .env("SERVICE_RESULT", result)
        .env("EXIT_CODE", code)
        .env("EXIT_STATUS", status)
        .args([
            "recover-failed-start",
            "--volume",
            "recovery-fixture",
            "--plan",
        ])
        .output()
        .unwrap()
}

#[test]
fn failed_start_plan_uses_the_workload_coordinator_without_configuration() {
    for (result, code, status) in [
        ("exit-code", "exited", "1"),
        ("timeout", "killed", "TERM"),
        ("signal", "killed", "KILL"),
        ("oom-kill", "killed", "KILL"),
    ] {
        let output = plan(result, code, status);
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("schedule maki-recover@recovery-fixture.service"));
        assert!(
            stdout.contains("only if the manager still has the original attach start job running")
        );
        assert!(stdout.contains("stops workloads before identity-checked cleanup"));
    }
}

/// `maki-recover@` stops the daemon before its cleanup, and an activation
/// whose helper died before recording the mapping can only be deactivated
/// through LVM, which reads the volume group from the NBD device. The hook
/// therefore finishes that rollback itself, while the daemon still serves it.
#[test]
fn failed_start_plan_finishes_an_interrupted_activation_before_the_daemon_stops() {
    let output = plan("timeout", "killed", "TERM");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("roll back an interrupted LVM activation"),
        "{stdout}"
    );
    assert!(
        stdout.contains("while the daemon still serves the device"),
        "{stdout}"
    );
    assert!(stdout.contains("never unmounts"), "{stdout}");
}

#[test]
fn successful_main_or_unknown_result_plans_do_not_restart() {
    for (result, code, status) in [
        ("success", "exited", "0"),
        ("exit-code", "exited", "0"),
        ("timeout", "exited", "0"),
        ("success", "killed", "TERM"),
        ("start-limit-hit", "exited", "1"),
        ("", "", ""),
    ] {
        let output = plan(result, code, status);
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("no automatic recovery"));
    }
}

/// Each is misuse (status 2), with or without `--plan`. An instance name
/// outside `[A-Za-z0-9_-]` was refused only inside the hook, with status 1.
#[test]
fn hook_rejects_device_overrides_and_invalid_instance_names() {
    for arguments in [
        vec!["--volume", "safe", "--config", "/tmp/fixture.toml"],
        vec!["--volume", "safe", "--mountpoint", "/tmp/fixture"],
        vec!["--volume", "../other"],
        vec!["--volume", "safe.service"],
        vec!["--volume", "a.b"],
        vec!["--volume", "safe", "--volume", "other"],
    ] {
        for plan in [true, false] {
            let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
                .env_clear()
                .arg("recover-failed-start")
                .args(&arguments)
                .args(plan.then_some("--plan"))
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{arguments:?} plan={plan}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
        }
    }
}

/// Without Linux there is no systemd to run the hook and nothing it could
/// schedule: like every other action, it executes only on Linux (status 3
/// elsewhere), and its plan still runs. On Linux, a run without evidence of
/// a failed start does nothing and succeeds.
#[test]
fn the_hook_executes_only_on_linux() {
    let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .env_clear()
        .args(["recover-failed-start", "--volume", "recovery-fixture"])
        .output()
        .unwrap();
    let expected = if cfg!(target_os = "linux") { 0 } else { 3 };
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn packaged_oneshot_uses_a_bounded_failed_start_hook() {
    let unit = include_str!("../../../packaging/systemd/maki-attach@.service");
    assert!(unit.contains("Type=oneshot"));
    assert!(unit.contains("RemainAfterExit=yes"));
    assert!(unit.contains("StartLimitIntervalSec=300"));
    assert!(unit.contains("StartLimitBurst=3"));
    assert!(unit.contains("ExecStopPost=/usr/bin/maki-attach recover-failed-start --volume %i"));
    assert!(!unit.lines().any(|line| line.starts_with("OnFailure=")));
    let coordinator = include_str!("../../../packaging/systemd/maki-recover@.service");
    assert!(coordinator
        .contains("After=maki-workload@%i.target maki-attach@%i.service maki@%i.service"));
    assert!(coordinator.contains("ExecStart=/usr/bin/maki-attach cleanup --volume %i"));
    assert!(coordinator.contains("OnSuccess=maki-workload@%i.target"));
}
