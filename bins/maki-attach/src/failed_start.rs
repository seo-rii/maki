//! The oneshot helper's ExecStopPost hook. Failed starts never run ExecStop,
//! while failures in a later ExecStop must not restart an intentionally stopped
//! workload. systemd supplies the *main* (ExecStart) process's exit status here.

#[cfg(target_os = "linux")]
use std::process::Command;

fn failed_start(result: Option<&str>, code: Option<&str>, status: Option<&str>) -> bool {
    if !matches!(
        result,
        Some("exit-code" | "signal" | "core-dump" | "timeout" | "watchdog" | "oom-kill")
    ) {
        // In particular, an explicit stop during startup has result=success.
        // Unknown/missing evidence cannot authorize automatic recovery.
        return false;
    }
    match (code, status) {
        (Some("exited"), Some(status)) => {
            !status.is_empty()
                && status.bytes().all(|byte| byte.is_ascii_digit())
                && status.parse::<u8>().is_ok_and(|status| status != 0)
        }
        (Some("killed" | "dumped"), Some(status)) => {
            !status.is_empty()
                && status.len() <= 32
                && status
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }
        _ => false,
    }
}

pub(super) fn run(volume: &str, plan_only: bool) -> Result<(), String> {
    maki_privileged::config::check_volume_name(volume).map_err(|error| error.to_string())?;
    let result = std::env::var("SERVICE_RESULT").ok();
    let code = std::env::var("EXIT_CODE").ok();
    let status = std::env::var("EXIT_STATUS").ok();
    if !failed_start(result.as_deref(), code.as_deref(), status.as_deref()) {
        if plan_only {
            println!("# no automatic recovery: no failed ExecStart is established");
        }
        return Ok(());
    }
    let unit = format!("maki-recover@{volume}.service");
    if plan_only {
        println!("# schedule {unit}; coordinator stops workloads before identity-checked cleanup");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // Never run cleanup here. The coordinator first stops registered
        // workloads, then cleans up, and starts a new lifecycle only on success.
        // Waiting for its job would deadlock: it is ordered after this hook.
        let status = Command::new("/usr/bin/systemctl")
            .args([
                "--no-ask-password",
                "--no-block",
                "--job-mode=fail",
                "start",
                &unit,
            ])
            .status()
            .map_err(|error| format!("cannot schedule failed-start recovery: {error}"))?;
        if !status.success() {
            return Err(
                "failed-start recovery job was not accepted; inspect the stopped lifecycle".into(),
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("failed-start recovery scheduling requires Linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::failed_start;

    #[test]
    fn failed_main_processes_schedule_recovery() {
        for (result, code, status) in [
            ("exit-code", "exited", "1"),
            ("exit-code", "exited", "255"),
            ("signal", "killed", "KILL"),
            ("core-dump", "dumped", "ABRT"),
            ("timeout", "killed", "TERM"),
            ("timeout", "killed", "KILL"),
            ("oom-kill", "killed", "KILL"),
        ] {
            assert!(failed_start(Some(result), Some(code), Some(status)));
        }
    }

    #[test]
    fn failed_stop_and_cancelled_start_do_not_restart_the_workload() {
        for result in ["success", "exit-code", "timeout", "signal", "oom-kill"] {
            assert!(!failed_start(Some(result), Some("exited"), Some("0")));
        }
        assert!(!failed_start(Some("success"), Some("killed"), Some("TERM")));
        assert!(!failed_start(Some("success"), Some("killed"), Some("KILL")));
    }

    #[test]
    fn missing_or_unrecognized_status_never_schedules_recovery() {
        for (result, code, status) in [
            (None, None, None),
            (Some("timeout"), None, None),
            (Some("start-limit-hit"), Some("exited"), Some("1")),
            (Some("unknown"), Some("exited"), Some("1")),
            (Some("exit-code"), Some("unknown"), Some("1")),
            (Some("exit-code"), Some("exited"), Some("+1")),
            (Some("exit-code"), Some("exited"), Some("256")),
            (Some("signal"), Some("killed"), Some("")),
            (Some("signal"), Some("killed"), Some("untrusted\ntext")),
        ] {
            assert!(!failed_start(result, code, status));
        }
    }
}
