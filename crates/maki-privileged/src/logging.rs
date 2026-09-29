//! Process-wide `tracing` sink for `maki-attach`.
//!
//! The executor reports every step it runs and, more importantly, every
//! rollback it halts ("keeping the attach record", "backend unreadable")
//! only through `tracing` macros, which are no-ops until a subscriber is
//! installed. Without this sink an operator saw a failed exit status and
//! none of the reasons. This mirrors `maki_core::logging` (R4-001) without
//! depending on it: `maki-core` pulls in crypto crates, which the helper
//! must never link (PRIV-010).

use std::io;

use tracing_subscriber::EnvFilter;

/// Environment variable holding a `tracing_subscriber::EnvFilter` directive
/// list, shared with the daemon (`maki_core::logging::LOG_ENV`).
pub const LOG_ENV: &str = "MAKI_LOG";

/// The level used when [`LOG_ENV`] is unset or unparsable.
pub const DEFAULT_LEVEL: &str = "info";

/// Install the default stderr subscriber once per process. Returns `false`
/// when a subscriber was already present.
pub fn install_default_logging() -> bool {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LEVEL));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    const CHILD_ENV: &str = "MAKI_PRIVILEGED_LOGGING_TEST_CHILD";

    /// Runs this test binary again with the child marker set, so the child
    /// installs the process-global subscriber without affecting the parent.
    fn child_stderr(filter: Option<&str>) -> String {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "logging::tests::child_emits_events",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .env_remove(super::LOG_ENV);
        if let Some(filter) = filter {
            command.env(super::LOG_ENV, filter);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "child test binary failed");
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn child_emits_events() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        assert!(super::install_default_logging());
        assert!(!super::install_default_logging(), "second install is a no-op");
        tracing::info!("maki-attach: fixture step");
        tracing::error!("maki-attach: rollback halted, fixture reason");
        tracing::debug!("fixture debug is hidden by default");
    }

    #[test]
    fn rollback_errors_and_steps_reach_stderr_without_ansi() {
        let stderr = child_stderr(None);
        assert!(stderr.contains("maki-attach: fixture step"), "{stderr}");
        assert!(stderr.contains("ERROR"), "{stderr}");
        assert!(stderr.contains("rollback halted, fixture reason"), "{stderr}");
        assert!(!stderr.contains("fixture debug is hidden"), "{stderr}");
        assert!(!stderr.contains("\u{1b}["), "no ANSI escapes in a journal:\n{stderr}");
    }

    #[test]
    fn maki_log_directives_filter_the_output() {
        let stderr = child_stderr(Some("error"));
        assert!(stderr.contains("rollback halted"), "{stderr}");
        assert!(!stderr.contains("fixture step"), "{stderr}");
    }
}
