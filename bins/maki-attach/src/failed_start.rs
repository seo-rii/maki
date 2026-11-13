//! The oneshot helper's ExecStopPost hook. Failed starts never run ExecStop,
//! while failures in a later ExecStop must not restart an intentionally stopped
//! workload. systemd supplies the *main* (ExecStart) process's exit status here.
//! A cancelled oneshot start can also have a failed main-process status, so the
//! hook additionally requires the manager's original start job to be running.

#[cfg(target_os = "linux")]
use std::process::Command;

fn failed_main_process(result: Option<&str>, code: Option<&str>, status: Option<&str>) -> bool {
    if !matches!(
        result,
        Some("exit-code" | "signal" | "core-dump" | "timeout" | "watchdog" | "oom-kill")
    ) {
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

#[cfg(any(target_os = "linux", test))]
fn running_start_job(jobs: &str, unit: &str) -> bool {
    // list-jobs --no-legend --plain --full returns job/unit/type/state. Require
    // one exact row; missing, ambiguous or unfamiliar evidence must hold.
    let mut rows = jobs.lines().filter(|line| !line.trim().is_empty());
    let Some(row) = rows.next() else {
        return false;
    };
    if rows.next().is_some() {
        return false;
    }
    let mut fields = row.split_ascii_whitespace();
    let Some(id) = fields.next() else {
        return false;
    };
    id.bytes().all(|byte| byte.is_ascii_digit())
        && id.parse::<u32>().is_ok_and(|id| id != 0)
        && fields.next() == Some(unit)
        && fields.next() == Some("start")
        && fields.next() == Some("running")
        && fields.next().is_none()
}

pub(super) fn run(volume: &str, plan_only: bool) -> Result<(), String> {
    maki_privileged::config::check_volume_name(volume).map_err(|error| error.to_string())?;
    let result = std::env::var("SERVICE_RESULT").ok();
    let code = std::env::var("EXIT_CODE").ok();
    let status = std::env::var("EXIT_STATUS").ok();
    if !failed_main_process(result.as_deref(), code.as_deref(), status.as_deref()) {
        if plan_only {
            println!("# no automatic recovery: no failed ExecStart is established");
        }
        return Ok(());
    }
    let unit = format!("maki-recover@{volume}.service");
    if plan_only {
        println!("# would schedule {unit} only if the manager still has the original attach start job running");
        println!("# coordinator stops workloads before identity-checked cleanup");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // SIGTERM from an operator cancellation is a failure for Type=oneshot.
        // Its stop/restart job is the distinguishing evidence, not SERVICE_RESULT.
        let attach = format!("maki-attach@{volume}.service");
        let jobs = Command::new("/usr/bin/systemctl")
            .args([
                "--no-ask-password",
                "--no-pager",
                "--no-legend",
                "--plain",
                "--full",
                "list-jobs",
                &attach,
            ])
            .env("LC_ALL", "C")
            .env("SYSTEMD_COLORS", "0")
            .env("SYSTEMD_URLIFY", "0")
            .output()
            .map_err(|error| format!("cannot inspect failed-start job: {error}"))?;
        if !jobs.status.success() {
            return Err("cannot inspect failed-start job; no recovery was queued".into());
        }
        let jobs = std::str::from_utf8(&jobs.stdout)
            .map_err(|_| "invalid failed-start job response; no recovery was queued".to_string())?;
        if !running_start_job(jobs, &attach) {
            return Ok(());
        }

        // Never run cleanup here. The coordinator first stops registered
        // workloads, then cleans up, and starts a new lifecycle only on success.
        // Waiting for its job would deadlock: it is ordered after this hook.
        // The original start job remains installed until ExecStopPost ends, so
        // the coordinator's Conflicts= stop job must replace it. This is not an
        // atomic compare-and-replace: an operator stop between the read above
        // and this enqueue can still be replaced. Deliberately interrupting
        // recovery requires masking the coordinator before stopping it and the
        // workload target. Do not use replace-irreversibly here.
        let status = Command::new("/usr/bin/systemctl")
            .args([
                "--no-ask-password",
                "--no-block",
                "--job-mode=replace",
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
    use super::{failed_main_process, running_start_job};

    const ATTACH: &str = "maki-attach@recovery-fixture.service";

    #[test]
    fn failed_main_processes_require_manager_job_confirmation() {
        for (result, code, status) in [
            ("exit-code", "exited", "1"),
            ("exit-code", "exited", "255"),
            ("signal", "killed", "KILL"),
            ("core-dump", "dumped", "ABRT"),
            ("timeout", "killed", "TERM"),
            ("timeout", "killed", "KILL"),
            ("oom-kill", "killed", "KILL"),
        ] {
            assert!(failed_main_process(Some(result), Some(code), Some(status)));
        }
    }

    #[test]
    fn successful_main_process_does_not_restart_after_failed_stop() {
        for result in ["success", "exit-code", "timeout", "signal", "oom-kill"] {
            assert!(!failed_main_process(
                Some(result),
                Some("exited"),
                Some("0")
            ));
        }
        assert!(!failed_main_process(
            Some("success"),
            Some("killed"),
            Some("TERM")
        ));
        assert!(!failed_main_process(
            Some("success"),
            Some("killed"),
            Some("KILL")
        ));
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
            assert!(!failed_main_process(result, code, status));
        }
    }

    #[test]
    fn only_the_exact_running_start_job_authorizes_recovery() {
        assert!(running_start_job(
            &format!("42 {ATTACH} start running\n"),
            ATTACH
        ));
        assert!(running_start_job(
            &format!("  4294967295\t{ATTACH}   start running \n"),
            ATTACH,
        ));
        for job in [
            "stop running",
            "stop waiting",
            "restart running",
            "start waiting",
            "reload running",
        ] {
            assert!(!running_start_job(&format!("42 {ATTACH} {job}\n"), ATTACH));
        }
    }

    #[test]
    fn cancelled_oneshot_start_does_not_authorize_recovery() {
        // A normal systemctl stop kills the pending main process with SIGTERM.
        // systemd reports that as a failure for oneshot services, but its job is
        // now stop, rather than the original running start.
        assert!(failed_main_process(
            Some("signal"),
            Some("killed"),
            Some("TERM")
        ));
        assert!(!running_start_job(
            &format!("43 {ATTACH} stop running\n"),
            ATTACH
        ));
    }

    #[test]
    fn missing_or_malformed_jobs_do_not_authorize_recovery() {
        for jobs in [
            String::new(),
            "\n \t\n".into(),
            format!("0 {ATTACH} start running\n"),
            format!("+42 {ATTACH} start running\n"),
            format!("4294967296 {ATTACH} start running\n"),
            format!("42 {ATTACH} start\n"),
            format!("42 {ATTACH} start running extra\n"),
            format!("42 {ATTACH} start running\n43 {ATTACH} start running\n"),
            format!("JOB UNIT TYPE STATE\n42 {ATTACH} start running\n"),
            "42 maki-attach@other.service start running\n".into(),
            format!("42 \u{1b}[1m{ATTACH} start running\n"),
        ] {
            assert!(!running_start_job(&jobs, ATTACH), "accepted {jobs:?}");
        }
    }
}
