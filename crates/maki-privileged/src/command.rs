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

pub(super) fn capture(command: &mut Command, policy: Policy) -> io::Result<Output> {
    // Orphans must be reaped here even on hosts whose PID 1 does not promptly
    // reap. This process-wide setting remains enabled for the helper's short
    // lifetime. Reaping below is restricted to this command's process group;
    // successful daemonized nbd-client children are left running.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let started = Instant::now();
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
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
