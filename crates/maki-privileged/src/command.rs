//! Linux subprocess limits for the one-shot privileged helper. A deadline
//! includes draining stdout/stderr: an exited parent is not completion if a
//! descendant still holds a pipe. Failure cleanup targets only the process
//! group created for this command, never all children of the helper.
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy)]
pub(super) struct Policy {
    pub(super) timeout: Duration,
    pub(super) terminate_grace: Duration,
    pub(super) reap_timeout: Duration,
    pub(super) max_output_bytes: usize,
}

impl Policy {
    // Leave room below the service's 180-second start timeout for readiness
    // observation and normal rollback. This is a per-command limit, not a
    // promise that a multi-step attach/rollback fits one overall deadline.
    pub(super) const STEP: Self = Self {
        timeout: Duration::from_secs(120),
        terminate_grace: Duration::from_secs(1),
        reap_timeout: Duration::from_secs(1),
        max_output_bytes: 64 * 1024,
    };
    pub(super) const PROBE: Self = Self {
        timeout: Duration::from_secs(15),
        ..Self::STEP
    };
}

thread_local! {
    static FINISH_BY: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// Restores the previous limit when dropped; see [`finish_by`].
pub(crate) struct Deadline(Option<Instant>);

impl Drop for Deadline {
    fn drop(&mut self) {
        FINISH_BY.set(self.0);
    }
}

/// Until the returned guard is dropped, every command this thread starts
/// must also finish by `deadline`, whatever its own policy allows, and none
/// is started after it. A caller that itself runs inside a time limit (the
/// failed-start hook, inside the unit's stop timeout) bounds all of its
/// commands at once this way.
pub(crate) fn finish_by(deadline: Instant) -> Deadline {
    Deadline(FINISH_BY.replace(Some(deadline)))
}

/// When a step the helper performs itself, without an external command
/// (the NBD connect and disconnect), must end: after the time an external
/// step command may take, or at the thread's [`finish_by`] deadline when
/// that comes first. No step starts once that deadline has passed.
pub(crate) fn step_deadline() -> io::Result<Instant> {
    let now = Instant::now();
    let limit = now + Policy::STEP.timeout;
    match FINISH_BY.get() {
        Some(deadline) if deadline <= now => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no time left to start an NBD step",
        )),
        Some(deadline) => Ok(limit.min(deadline)),
        None => Ok(limit),
    }
}

/// The limit [`finish_by`] set for this thread, if any.
#[cfg(test)]
pub(super) fn finish_by_limit() -> Option<Instant> {
    FINISH_BY.get()
}

/// A command with a controlled environment: nothing inherited from the
/// caller (no `LD_*`, no hostile `PATH`), a fixed system `PATH`, and
/// `LC_ALL=C` so parsed output never depends on the caller's locale.
pub(crate) fn controlled(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        // systemd's default service PATH: root-controlled locations only.
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C");
    command
}

#[cfg(test)]
thread_local! {
    static RECORDED: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// Until the guard is dropped, the commands this thread would start are
/// recorded by program name and fail without being started.
#[cfg(test)]
pub(crate) fn record_commands() -> Recording {
    Recording(RECORDED.replace(Some(Vec::new())))
}

#[cfg(test)]
pub(crate) struct Recording(Option<Vec<String>>);

#[cfg(test)]
impl Recording {
    pub(crate) fn programs(&self) -> Vec<String> {
        RECORDED.with_borrow(|recorded| recorded.clone().unwrap_or_default())
    }
}

#[cfg(test)]
impl Drop for Recording {
    fn drop(&mut self) {
        RECORDED.set(self.0.take());
    }
}

pub(super) fn capture(command: &mut Command, mut policy: Policy) -> io::Result<Output> {
    #[cfg(test)]
    if RECORDED
        .with_borrow_mut(|recorded| {
            recorded
                .as_mut()
                .map(|programs| programs.push(command.get_program().to_string_lossy().into_owned()))
        })
        .is_some()
    {
        return Err(io::Error::other(
            "this test records commands instead of starting them",
        ));
    }
    if let Some(deadline) = FINISH_BY.get() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no time left to start an external command",
            ));
        }
        policy.timeout = policy.timeout.min(remaining);
    }
    // Orphans must be reaped here even on hosts whose PID 1 does not promptly
    // reap. This process-wide setting remains enabled for the helper's short
    // lifetime. Reaping below is restricted to this command's process group;
    // the descendants a successful command leaves running are left alone.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let started = Instant::now();
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            // The operating system's error alone does not say which program
            // is missing or may not be run.
            io::Error::new(
                error.kind(),
                format!(
                    "cannot run {}: {error}",
                    command.get_program().to_string_lossy()
                ),
            )
        })?;
    let result = collect(&mut child, started, policy);
    match result {
        Ok(output) if output.status.success() => {
            // collect observed an exited parent without reaping it. Never
            // terminate an intentionally daemonized successful command.
            child.try_wait()?.ok_or_else(|| {
                io::Error::other("external command exit status became unavailable")
            })?;
            Ok(output)
        }
        result => {
            if !terminate_group(&child, policy) {
                return Err(io::Error::other(
                    "external command failed; process-group cleanup did not finish within its deadline",
                ));
            }
            result
        }
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(pipe: &mut Option<impl Read>, output: &mut Vec<u8>, limit: usize) -> io::Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    // A bounded amount per poll also bounds work when a child continuously
    // writes: neither stream nor the deadline can be starved by the other.
    let mut buffer = [0; 8192];
    match reader.read(&mut buffer) {
        Ok(0) => *pipe = None,
        Ok(count) => {
            if count > limit.saturating_sub(output.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "external command exceeded its output limit",
                ));
            }
            output.extend_from_slice(&buffer[..count]);
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn collect(child: &mut Child, started: Instant, policy: Policy) -> io::Result<Output> {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    nonblocking(stdout.as_ref().expect("stdout is piped"))?;
    nonblocking(stderr.as_ref().expect("stderr is piped"))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        if started.elapsed() >= policy.timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "external command exceeded its execution deadline",
            ));
        }
        drain(&mut stdout, &mut out, policy.max_output_bytes)?;
        drain(&mut stderr, &mut err, policy.max_output_bytes)?;
        if stdout.is_none() && stderr.is_none() {
            if let Some(status) = exited_status(child)? {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        std::thread::sleep(POLL_INTERVAL.min(policy.timeout.saturating_sub(started.elapsed())));
    }
}

fn exited_status(child: &Child) -> io::Result<Option<ExitStatus>> {
    // Keep the group leader unreaped until after the last possible signal.
    // Its PID cannot be reused for an unrelated process group while we are
    // deciding whether a failed command requires TERM/KILL cleanup.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let status = unsafe { info.si_status() };
    let raw = match info.si_code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_KILLED => status,
        libc::CLD_DUMPED => status | 0x80,
        _ => return Err(io::Error::other("unexpected external command wait status")),
    };
    Ok(Some(ExitStatus::from_raw(raw)))
}

fn terminate_group(child: &Child, policy: Policy) -> bool {
    let group = -(child.id() as libc::pid_t);
    // child is still unreaped, so its group identifier cannot refer to an
    // unrelated group. The final signal always precedes any waitpid reaping.
    if unsafe { libc::kill(group, libc::SIGTERM) } == -1
        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return false;
    }
    std::thread::sleep(policy.terminate_grace);
    if unsafe { libc::kill(group, libc::SIGKILL) } == -1
        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return false;
    }
    let started = Instant::now();
    loop {
        let waited = unsafe { libc::waitpid(group, std::ptr::null_mut(), libc::WNOHANG) };
        if waited == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return unsafe { libc::kill(group, 0) } == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return false;
            }
        }
        // Include every reap attempt in the bound, even if descendants keep
        // exiting. An uninterruptible kernel task may outlive SIGKILL; never
        // hold the attach lock forever waiting for it, or claim clean reaping.
        if started.elapsed() >= policy.reap_timeout {
            return false;
        }
        if waited <= 0 {
            std::thread::sleep(
                POLL_INTERVAL.min(policy.reap_timeout.saturating_sub(started.elapsed())),
            );
        }
    }
}
