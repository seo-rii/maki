//! Process-wide `tracing` sink for the plugin and the administrative
//! binaries (R4-001).
//!
//! `tracing` macros are no-ops until a subscriber is installed. The engine,
//! store, control server and providers report runtime failures (a checkpoint
//! that failed, a journal sync that failed, an allocation map repaired at
//! open, a quarantined endpoint) only through those macros, so a process
//! that never installs a subscriber loses them. This module installs one
//! that writes to stderr, which nbdkit forwards to its log and systemd to
//! the journal.
//!
//! Events carry operation names, error classes and identifiers only. Keys,
//! plaintext and credentials are never passed to a tracing macro (SPEC §36);
//! [`SecretBuffer`](maki_crypto::SecretBuffer) redacts itself in `Debug`.

use std::io;

use tracing_subscriber::EnvFilter;

/// Environment variable holding a `tracing_subscriber::EnvFilter` directive
/// list, for example `warn`, `info,maki_core=debug`.
pub const LOG_ENV: &str = "MAKI_LOG";

/// The level used when [`LOG_ENV`] is unset or unparsable.
pub const DEFAULT_LEVEL: &str = "info";

/// Install the default stderr subscriber once per process.
///
/// Returns `true` when this call installed it and `false` when a subscriber
/// was already present (a test harness, or an earlier call). Either way the
/// process ends up with a working sink, so callers can ignore the result.
pub fn install_default_logging() -> bool {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LEVEL));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(true)
        .try_init()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    const CHILD_ENV: &str = "MAKI_LOGGING_TEST_CHILD";

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
        tracing::warn!(volume = "fixture", "fixture warning reaches stderr");
        tracing::info!("fixture info reaches stderr");
        tracing::debug!("fixture debug is hidden by default");
        tracing::error!(error = %"fixture error class", "fixture error reaches stderr");
    }

    #[test]
    fn default_install_writes_info_and_above_to_stderr_without_ansi() {
        let stderr = child_stderr(None);
        assert!(stderr.contains("fixture warning reaches stderr"), "{stderr}");
        assert!(stderr.contains("volume=\"fixture\""), "{stderr}");
        assert!(stderr.contains("fixture info reaches stderr"), "{stderr}");
        assert!(stderr.contains("fixture error reaches stderr"), "{stderr}");
        assert!(!stderr.contains("fixture debug is hidden"), "{stderr}");
        assert!(stderr.contains("WARN") && stderr.contains("ERROR"), "{stderr}");
        assert!(!stderr.contains("\u{1b}["), "no ANSI escapes in a journal:\n{stderr}");
    }

    #[test]
    fn maki_log_directives_filter_the_output() {
        let stderr = child_stderr(Some("error"));
        assert!(stderr.contains("fixture error reaches stderr"), "{stderr}");
        assert!(!stderr.contains("fixture warning reaches stderr"), "{stderr}");
        let stderr = child_stderr(Some("debug"));
        assert!(stderr.contains("fixture debug is hidden"), "{stderr}");
    }
}
