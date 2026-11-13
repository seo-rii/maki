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
        assert!(stdout.contains("stops workloads before identity-checked cleanup"));
    }
}

#[test]
fn failed_stop_and_operator_cancellation_plans_do_not_restart() {
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

#[test]
fn hook_rejects_device_overrides_and_invalid_instance_names() {
    for arguments in [
        vec!["--volume", "safe", "--config", "/tmp/fixture.toml"],
        vec!["--volume", "safe", "--mountpoint", "/tmp/fixture"],
        vec!["--volume", "../other"],
        vec!["--volume", "safe.service"],
        vec!["--volume", "safe", "--volume", "other"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
            .env_clear()
            .arg("recover-failed-start")
            .args(arguments)
            .arg("--plan")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
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
