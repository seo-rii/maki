//! The oneshot helper's ExecStopPost hook. Failed starts never run ExecStop,
//! while failures in a later ExecStop must not restart an intentionally stopped
//! workload. systemd supplies the *main* (ExecStart) process's exit status here.
//! A cancelled oneshot start can also have a failed main-process status, so the
//! hook additionally requires the manager's original start job to be running.
//!
//! On that evidence the hook queues the recovery coordinator and then, while
//! the daemon is still running, finishes the one rollback the coordinator
//! cannot do after it stopped the daemon: that of an LVM activation whose
//! helper died before it recorded the mapping.

#[cfg(any(target_os = "linux", test))]
use maki_privileged::config::AttachConfig;
#[cfg(any(target_os = "linux", test))]
use maki_privileged::plan::Plan;
#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

/// How long the hook waits for processes the failed start left in the unit's
/// control group, and how long the rollback may then take. Together they
/// must stay well inside the unit's `TimeoutStopSec`, which bounds this hook,
/// and inside the coordinator's `JobTimeoutSec`, which includes waiting for it.
#[cfg(any(target_os = "linux", test))]
const SETTLE_WAIT: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "linux", test))]
const ROLLBACK_BUDGET: Duration = Duration::from_secs(30);

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

/// The control group directory of this process on the unified hierarchy, if
/// it is `unit`'s own. `proc_cgroup` is the text of `/proc/self/cgroup`.
#[cfg(any(target_os = "linux", test))]
fn unit_cgroup(proc_cgroup: &str, unit: &str) -> Option<PathBuf> {
    let path = proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))?;
    if path
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
        || path.rsplit('/').next() != Some(unit)
    {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(path))
}

/// Whether a `cgroup.procs` listing names a process other than `own`. `None`
/// when the listing is not what the kernel writes, or does not contain `own`.
#[cfg(any(target_os = "linux", test))]
fn other_processes(cgroup_procs: &str, own: u32) -> Option<bool> {
    let mut found_own = false;
    let mut others = false;
    for line in cgroup_procs.lines() {
        if !line.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        match line.parse::<u32>().ok()? {
            pid if pid == own => found_own = true,
            _ => others = true,
        }
    }
    found_own.then_some(others)
}

/// Wait until this hook is the only process left in the attach unit's control
/// group. systemd starts ExecStopPost as soon as the failed helper is gone,
/// while a command it had started (a `vgchange` that defers signals until it
/// has finished activating) can still be running; with `KillMode=control-group`
/// it stays in this group. Rolling back around a command that is still
/// changing the same devices would race it, so anything but a settled group,
/// including one that cannot be read, leaves the cleanup to the coordinator.
#[cfg(target_os = "linux")]
fn unit_settled(unit: &str, wait: Duration) -> bool {
    let Some(listing) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| unit_cgroup(&text, unit))
        .map(|directory| directory.join("cgroup.procs"))
    else {
        return false;
    };
    let started = Instant::now();
    loop {
        let others = std::fs::read_to_string(&listing)
            .ok()
            .and_then(|text| other_processes(&text, std::process::id()));
        match others {
            Some(false) => return true,
            Some(true) if started.elapsed() < wait => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => return false,
        }
    }
}

/// The plan `maki-attach cleanup --volume <volume>` runs on `config`: the
/// rollback acts on exactly the attachment the coordinator's cleanup would.
#[cfg(any(target_os = "linux", test))]
fn detach_plan(volume: &str, config: AttachConfig) -> Result<Plan, String> {
    match crate::verb_plan("cleanup", volume, config, &[], false) {
        Ok((_, plan)) => Ok(plan),
        Err(crate::Refusal::Invalid(reason)) => Err(reason),
        Err(crate::Refusal::Usage) => Err("cleanup has no plan for this volume".into()),
    }
}

/// The attach configuration `maki-attach cleanup --volume <volume>` reads
/// from `path`, its default: only a root-controlled file, or the built-in
/// defaults when there is none.
#[cfg(target_os = "linux")]
fn hook_config(path: &std::path::Path) -> Result<AttachConfig, String> {
    crate::attach_config(path, false, false)
}

/// What the hook does once a failed `ExecStart` is established: ask the
/// manager, read the attach state, roll back. `LinuxHost` does it; the
/// tests record it.
#[cfg(any(target_os = "linux", test))]
trait Host {
    /// Whether the manager still runs the original start job of `attach`.
    fn start_job_running(&mut self, attach: &str) -> Result<bool, String>;
    /// Ask the manager to queue `unit`, without waiting for its job.
    fn schedule(&mut self, unit: &str) -> Result<(), String>;
    /// Whether this hook is, or within `SETTLE_WAIT` becomes, the only
    /// process in `attach`'s control group.
    fn settled(&mut self, attach: &str) -> bool;
    /// The attach configuration of `volume`, as `hook_config` reads it.
    fn config(&mut self, volume: &str) -> Result<AttachConfig, String>;
    /// `maki_privileged::exec::finish_interrupted_activation` with `plan`.
    fn roll_back(&mut self, plan: &Plan) -> Result<bool, String>;
    /// A line for the journal.
    fn report(&mut self, message: &str);
}

#[cfg(target_os = "linux")]
struct LinuxHost;

#[cfg(target_os = "linux")]
impl Host for LinuxHost {
    fn start_job_running(&mut self, attach: &str) -> Result<bool, String> {
        let jobs = Command::new("/usr/bin/systemctl")
            .args([
                "--no-ask-password",
                "--no-pager",
                "--no-legend",
                "--plain",
                "--full",
                "list-jobs",
                attach,
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
        Ok(running_start_job(jobs, attach))
    }

    fn schedule(&mut self, unit: &str) -> Result<(), String> {
        let status = Command::new("/usr/bin/systemctl")
            .args([
                "--no-ask-password",
                "--no-block",
                "--job-mode=replace",
                "start",
                unit,
            ])
            .status()
            .map_err(|error| format!("cannot schedule failed-start recovery: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("failed-start recovery job was not accepted; inspect the stopped lifecycle".into())
        }
    }

    fn settled(&mut self, attach: &str) -> bool {
        unit_settled(attach, SETTLE_WAIT)
    }

    fn config(&mut self, volume: &str) -> Result<AttachConfig, String> {
        hook_config(std::path::Path::new(
            &maki_privileged::config::default_path(volume),
        ))
    }

    fn roll_back(&mut self, plan: &Plan) -> Result<bool, String> {
        maki_privileged::exec::finish_interrupted_activation(plan, Instant::now() + ROLLBACK_BUDGET)
            .map_err(|error| error.to_string())
    }

    /// `eprintln!` panics when the write fails, and nothing here may end
    /// the hook before it returns its result.
    fn report(&mut self, message: &str) {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "maki-attach: {message}");
    }
}

/// Roll back an LVM activation the failed helper did not live to record,
/// while the daemon still serves the device. The coordinator is already
/// queued and runs its cleanup whatever happens here, so every failure is
/// only reported.
#[cfg(any(target_os = "linux", test))]
fn finish_interrupted_activation(volume: &str, attach: &str, host: &mut impl Host) {
    if !host.settled(attach) {
        host.report(&format!(
            "processes of the failed start are still running, or the control group of {attach} \
             cannot be read; leaving all cleanup to the recovery coordinator"
        ));
        return;
    }
    let outcome = host
        .config(volume)
        .and_then(|config| detach_plan(volume, config))
        .and_then(|plan| host.roll_back(&plan));
    match outcome {
        Ok(true) => host.report(&format!(
            "rolled back the interrupted LVM activation of volume {volume}"
        )),
        Ok(false) => {}
        Err(error) => host.report(&format!(
            "could not roll back an interrupted LVM activation of volume {volume}: {error}; \
             the recovery coordinator retries cleanup after it stopped the daemon"
        )),
    }
}

/// The hook after the failed main process is established: confirm the
/// original start job, queue the coordinator, roll back.
#[cfg(any(target_os = "linux", test))]
fn recover(volume: &str, host: &mut impl Host) -> Result<(), String> {
    // SIGTERM from an operator cancellation is a failure for Type=oneshot.
    // Its stop/restart job is the distinguishing evidence, not SERVICE_RESULT.
    let attach = format!("maki-attach@{volume}.service");
    if !host.start_job_running(&attach)? {
        return Ok(());
    }

    // Never run the general cleanup here. The coordinator first stops
    // registered workloads, then cleans up, and starts a new lifecycle only
    // on success. Waiting for its job would deadlock: it is ordered after
    // this hook. The original start job remains installed until
    // ExecStopPost ends, so the coordinator's Conflicts= stop job must
    // replace it. This is not an atomic compare-and-replace: an operator
    // stop between the read above and this enqueue can still be replaced.
    // Deliberately interrupting recovery requires masking the coordinator
    // before stopping it and the workload target. Do not use
    // replace-irreversibly here.
    let scheduled = host.schedule(&format!("maki-recover@{volume}.service"));
    // Queue first, roll back second: if this process is killed or runs
    // into the stop timeout below, the coordinator is already on its way.
    // Its stop of the daemon is ordered after this unit's stop job, which
    // cannot finish before this hook does, so the daemon is still serving.
    finish_interrupted_activation(volume, &attach, host);
    scheduled
}

pub(super) fn run(volume: &str, plan_only: bool) -> Result<(), String> {
    maki_privileged::config::check_instance_name(volume).map_err(|error| error.to_string())?;
    let result = std::env::var("SERVICE_RESULT").ok();
    let code = std::env::var("EXIT_CODE").ok();
    let status = std::env::var("EXIT_STATUS").ok();
    if !failed_main_process(result.as_deref(), code.as_deref(), status.as_deref()) {
        if plan_only {
            crate::print_plan("# no automatic recovery: no failed ExecStart is established\n")?;
        }
        return Ok(());
    }
    let unit = format!("maki-recover@{volume}.service");
    if plan_only {
        return crate::print_plan(&format!(
            "# would schedule {unit} only if the manager still has the original attach start job running\n\
             # coordinator stops workloads before identity-checked cleanup\n\
             # would then roll back an interrupted LVM activation (a record holding only the \
             activation intent, on its own connection) while the daemon still serves the \
             device: scoped VG deactivation, then NBD disconnect; never unmounts\n"
        ));
    }
    #[cfg(target_os = "linux")]
    {
        recover(volume, &mut LinuxHost)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("failed-start recovery scheduling requires Linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        failed_main_process, other_processes, recover, running_start_job, unit_cgroup, Host,
        ROLLBACK_BUDGET, SETTLE_WAIT,
    };
    use maki_privileged::config::{parse, AttachConfig};
    use maki_privileged::plan::Plan;
    use std::ffi::OsString;
    use std::path::Path;

    const ATTACH: &str = "maki-attach@recovery-fixture.service";

    /// A configuration that differs from the defaults in everything the
    /// detach plan names.
    const CONFIG: &str = r#"
volume_uuid = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"
nbd_device = "/dev/nbd5"
nbd_socket = "/run/maki/pg/other.sock"
vg_name = "vg_custom"
lv_name = "db"
mountpoint = "/srv/custom"
"#;

    /// What the hook would do on a host whose manager, attach state and
    /// rollback answer as configured, recorded in order.
    struct FakeHost {
        job_running: Result<bool, String>,
        scheduled: Result<(), String>,
        /// What the volume's trusted record holds: `Ok(true)` an activation
        /// intent, `Ok(false)` no intent or no record, `Err` an unreadable
        /// record. The rollback checks it again under the lock.
        intent: Result<bool, String>,
        settled: bool,
        config: Result<AttachConfig, String>,
        /// The rollback's answer for a record that holds an intent.
        rollback: Result<bool, String>,
        actions: Vec<String>,
        reports: Vec<String>,
        plan: Option<Plan>,
    }

    impl FakeHost {
        fn new() -> Self {
            Self {
                job_running: Ok(true),
                scheduled: Ok(()),
                intent: Ok(true),
                settled: true,
                config: Ok(parse(CONFIG).unwrap()),
                rollback: Ok(true),
                actions: Vec::new(),
                reports: Vec::new(),
                plan: None,
            }
        }

        fn did(&self, action: &str) -> Option<usize> {
            self.actions.iter().position(|done| done == action)
        }
    }

    impl Host for FakeHost {
        fn start_job_running(&mut self, attach: &str) -> Result<bool, String> {
            self.actions.push(format!("list-jobs {attach}"));
            self.job_running.clone()
        }
        fn schedule(&mut self, unit: &str) -> Result<(), String> {
            self.actions.push(format!("start {unit}"));
            self.scheduled.clone()
        }
        fn settled(&mut self, attach: &str) -> bool {
            self.actions.push(format!("settle {attach}"));
            self.settled
        }
        fn config(&mut self, volume: &str) -> Result<AttachConfig, String> {
            self.actions.push(format!("config {volume}"));
            self.config.clone()
        }
        fn roll_back(&mut self, plan: &Plan) -> Result<bool, String> {
            self.actions.push(format!("roll back {}", plan.volume));
            self.plan = Some(plan.clone());
            match &self.intent {
                Ok(true) => self.rollback.clone(),
                other => other.clone(),
            }
        }
        fn report(&mut self, message: &str) {
            self.reports.push(message.to_string());
        }
    }

    /// The plan `maki-attach cleanup --volume pg` runs on `config`.
    fn cleanup_plan(config: AttachConfig) -> Plan {
        let args: Vec<OsString> = ["cleanup", "--volume", "pg"].map(OsString::from).into();
        match crate::verb_plan("cleanup", "pg", config, &args, false) {
            Ok((_, plan)) => plan,
            Err(_) => panic!("cleanup has a plan"),
        }
    }

    /// The hook rolls back with the coordinator's own cleanup plan, after it
    /// has queued the coordinator.
    #[test]
    fn an_interrupted_activation_is_rolled_back_with_the_plan_cleanup_runs() {
        let mut host = FakeHost::new();
        assert_eq!(recover("pg", &mut host), Ok(()));
        let queued = host.did("start maki-recover@pg.service").expect("queued");
        let rolled_back = host.did("roll back pg").expect("rolled back");
        assert!(queued < rolled_back, "{:?}", host.actions);
        assert_eq!(
            host.actions
                .iter()
                .filter(|done| done.starts_with("roll back"))
                .count(),
            1
        );
        let expected = cleanup_plan(parse(CONFIG).unwrap());
        assert_eq!(format!("{:?}", host.plan), format!("{:?}", Some(expected)));
        assert_ne!(
            format!("{:?}", host.plan),
            format!("{:?}", Some(cleanup_plan(AttachConfig::default()))),
            "the configuration did not reach the plan"
        );
        assert_eq!(
            host.reports,
            ["rolled back the interrupted LVM activation of volume pg"]
        );
    }

    /// A masked coordinator refuses the request (the maintenance procedure
    /// masks it). The rollback is identity-checked and never unmounts, so
    /// it still runs; the hook fails with the refusal.
    #[test]
    fn the_rollback_runs_when_the_manager_refuses_the_coordinator() {
        let refused = "failed-start recovery job was not accepted; inspect the stopped lifecycle";
        let mut host = FakeHost::new();
        host.scheduled = Err(refused.into());
        assert_eq!(recover("pg", &mut host), Err(refused.into()));
        assert!(host.did("roll back pg").is_some(), "{:?}", host.actions);
    }

    #[test]
    fn only_the_running_start_job_lets_the_hook_act() {
        for job in [
            Ok(false),
            Err("cannot inspect failed-start job".to_string()),
        ] {
            let mut host = FakeHost::new();
            host.job_running = job.clone();
            assert_eq!(recover("pg", &mut host), job.map(drop));
            assert_eq!(host.actions, ["list-jobs maki-attach@pg.service"]);
            assert!(host.reports.is_empty());
        }
    }

    /// Most failed starts leave no intent: an attach config the hook cannot
    /// use is then none of its business, and saying it "could not roll back
    /// an interrupted activation" reported one that never happened.
    #[test]
    fn without_an_interrupted_activation_the_hook_reads_no_configuration() {
        let mut host = FakeHost::new();
        host.intent = Ok(false);
        host.config = Err(
            "attach config \"/etc/maki/attach/pg.toml\" must be a root-owned regular file below \
             root-owned directories without group/other write access: mode 0664"
                .into(),
        );
        assert_eq!(recover("pg", &mut host), Ok(()));
        assert_eq!(host.did("config pg"), None, "{:?}", host.actions);
        assert_eq!(host.did("settle maki-attach@pg.service"), None);
        assert_eq!(host.did("roll back pg"), None);
        assert!(host.reports.is_empty(), "{:?}", host.reports);
    }

    #[test]
    fn an_unreadable_attach_record_is_reported_as_what_could_not_be_checked() {
        let unreadable = "attach state ancestor must be a root-owned directory without \
                          group/other write access";
        let mut host = FakeHost::new();
        host.intent = Err(unreadable.into());
        assert_eq!(recover("pg", &mut host), Ok(()));
        assert_eq!(host.did("config pg"), None, "{:?}", host.actions);
        assert_eq!(host.did("roll back pg"), None);
        assert_eq!(
            host.reports,
            [format!(
                "cannot tell whether volume pg has an interrupted LVM activation to roll back: \
                 {unreadable}; leaving all cleanup to the recovery coordinator"
            )]
        );
    }

    #[test]
    fn an_interrupted_activation_with_an_unusable_configuration_names_both() {
        let unusable = "attach config parse error: expected `=`";
        let mut host = FakeHost::new();
        host.config = Err(unusable.into());
        assert_eq!(recover("pg", &mut host), Ok(()));
        assert_eq!(host.did("roll back pg"), None);
        assert_eq!(
            host.reports,
            [format!(
                "could not roll back the interrupted LVM activation of volume pg: {unusable}; \
                 the recovery coordinator retries cleanup after it stopped the daemon"
            )]
        );
    }

    #[test]
    fn an_unsettled_unit_leaves_the_interrupted_activation_to_the_coordinator() {
        let mut host = FakeHost::new();
        host.settled = false;
        assert_eq!(recover("pg", &mut host), Ok(()));
        assert_eq!(host.did("config pg"), None, "{:?}", host.actions);
        assert_eq!(host.did("roll back pg"), None);
        assert_eq!(
            host.reports,
            ["volume pg has an interrupted LVM activation, but processes of the failed start are \
              still running, or the control group of maki-attach@pg.service cannot be read; \
              leaving all cleanup to the recovery coordinator"]
        );
    }

    /// The record was read without the lock. Under it, an explicit cleanup
    /// may have retired the record, or the device may no longer carry the
    /// recorded connection: the rollback then does nothing, and says so.
    #[test]
    fn a_rollback_that_finds_nothing_to_do_under_the_lock_says_so() {
        let mut host = FakeHost::new();
        host.rollback = Ok(false);
        assert_eq!(recover("pg", &mut host), Ok(()));
        assert_eq!(
            host.reports,
            [
                "did not roll back the interrupted LVM activation of volume pg: under the attach \
              lock its record no longer holds the activation intent, or its device no longer \
              carries the recorded connection; leaving cleanup to the recovery coordinator"
            ]
        );
    }

    /// The rollback runs as root on what the configuration says, exactly as
    /// cleanup does: a file others can write is refused, a missing one is
    /// the built-in defaults.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_rollback_reads_only_a_trusted_attach_configuration() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        assert_eq!(
            format!("{:?}", super::hook_config(&missing)),
            format!("{:?}", Ok::<_, String>(AttachConfig::default()))
        );
        let shared = directory.path().join("pg.toml");
        std::fs::write(&shared, CONFIG).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o664)).unwrap();
        let error = super::hook_config(&shared).unwrap_err();
        assert!(
            error.contains("must be a root-owned regular file"),
            "{error}"
        );
    }

    #[test]
    fn only_the_attach_units_own_unified_control_group_is_inspected() {
        let own = format!("/system.slice/system-maki\\x2dattach.slice/{ATTACH}");
        assert_eq!(
            unit_cgroup(&format!("0::{own}\n"), ATTACH).as_deref(),
            Some(Path::new(&format!("/sys/fs/cgroup{own}")))
        );
        for listing in [
            String::new(),
            // A legacy or hybrid hierarchy has no usable unified entry.
            format!("1:name=systemd:{own}\n"),
            "0::/\n".into(),
            // Another unit's group, a session scope, or a sub-group.
            "0::/system.slice/maki-attach@other.service\n".into(),
            "0::/user.slice/user-0.slice/session-3.scope\n".into(),
            format!("0::{own}/payload\n"),
            format!("0::/system.slice/../{ATTACH}\n"),
            format!("0::/system.slice//{ATTACH}\n"),
            format!("0::{ATTACH}\n"),
        ] {
            assert_eq!(unit_cgroup(&listing, ATTACH), None, "{listing:?}");
        }
    }

    #[test]
    fn a_control_group_is_settled_only_when_this_hook_is_alone_in_it() {
        assert_eq!(other_processes("4242\n", 4242), Some(false));
        assert_eq!(other_processes("17\n4242\n", 4242), Some(true));
        assert_eq!(other_processes("4242\n4243\n", 4242), Some(true));
        // Evidence that is empty, malformed or about other processes only
        // is not proof of a settled group.
        for listing in ["", "17\n", "4242 \n", "+4242\n", "pid\n4242\n"] {
            assert_eq!(other_processes(listing, 4242), None, "{listing:?}");
        }
    }

    /// The unit's stop timeout bounds this hook, and the coordinator's job
    /// timeout includes the wait for it. The rollback gives up long before
    /// either: a command the deadline ends is killed within about two
    /// seconds more.
    #[test]
    fn the_rollback_budget_fits_the_packaged_timeouts() {
        let seconds = |unit: &str, key: &str| -> u64 {
            unit.lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap_or_else(|| panic!("no {key}"))
                .parse()
                .unwrap()
        };
        let attach = include_str!("../../../packaging/systemd/maki-attach@.service");
        let recovery = include_str!("../../../packaging/systemd/maki-recover@.service");
        let budget = (SETTLE_WAIT + ROLLBACK_BUDGET).as_secs();
        assert!(2 * budget <= seconds(attach, "TimeoutStopSec="));
        assert!(4 * budget <= seconds(recovery, "JobTimeoutSec="));
    }

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
