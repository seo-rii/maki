//! Process-wide `tracing` sink for `maki-attach`.
//!
//! The executor reports every step it runs and, more importantly, every
//! rollback it halts ("keeping the attach record", "backend unreadable")
//! only through `tracing` macros, which are no-ops until a subscriber is
//! installed. Without this sink an operator saw a failed exit status and
//! none of the reasons. This mirrors `maki_core::logging` (R4-001) without
//! depending on it: `maki-core` pulls in crypto crates, which the helper
//! must never link (PRIV-010). It accepts the same `MAKI_LOG` values, so
//! the small value check is duplicated rather than shared.

use std::ffi::OsStr;
use std::io;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

/// Environment variable holding a `tracing_subscriber::EnvFilter` directive
/// list, shared with the daemon (`maki_core::logging::LOG_ENV`). Every
/// directive names its level (see `parse_filter`).
pub const LOG_ENV: &str = "MAKI_LOG";

/// The level used when [`LOG_ENV`] is unset, empty or invalid.
pub const DEFAULT_LEVEL: &str = "info";

/// Install the default stderr subscriber once per process. Returns `false`
/// when a subscriber was already present. An invalid [`LOG_ENV`] value is
/// reported once, by the call that installs the sink.
pub fn install_default_logging() -> bool {
    let value = std::env::var_os(LOG_ENV);
    let (filter, refused) = match value.as_deref().map(parse_filter) {
        Some(Ok(Some(filter))) => (filter, None),
        Some(Err(reason)) => (EnvFilter::new(DEFAULT_LEVEL), Some(reason)),
        Some(Ok(None)) | None => (EnvFilter::new(DEFAULT_LEVEL), None),
    };
    let installed = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(false)
        // This builder's default reports an event it could not write with
        // `eprintln!`, which panics when stderr is the writer that failed (a
        // pipe whose reader has gone): the helper would die at the first
        // step it logs. An event that cannot be delivered is dropped.
        .log_internal_errors(false)
        .try_init()
        .is_ok();
    if let (true, Some(reason)) = (installed, refused) {
        tracing::warn!(
            %reason,
            "MAKI_LOG is not a valid filter; logging at {DEFAULT_LEVEL}"
        );
    }
    installed
}

/// Parse a [`LOG_ENV`] value: `Ok(None)` when it holds no directive (empty),
/// which means the default like an unset variable.
///
/// EnvFilter reads a directive without a level as a target, or a span,
/// enabled at trace, and turns every target no directive names off. A
/// misspelt level (`warning`, `err`) would then hide every halted rollback,
/// so each directive must be a level or end in `=<level>`, as for the daemon
/// (`maki_core::logging`).
fn parse_filter(value: &OsStr) -> Result<Option<EnvFilter>, String> {
    let value = value.to_str().ok_or("the value is not UTF-8")?;
    // EnvFilter splits the same way and skips empty directives.
    let directives: Vec<&str> = value.split(',').filter(|d| !d.is_empty()).collect();
    if directives.is_empty() {
        return Ok(None);
    }
    if let Some(index) = directives.iter().position(|d| !names_level(d)) {
        let index = index + 1;
        return Err(format!(
            "directive {index} does not name a level; use off, error, warn, info, \
             debug or trace, alone or as <target>=<level>"
        ));
    }
    EnvFilter::try_new(value).map(Some).map_err(|_| {
        // Selector values and parser errors may contain user data. Locate
        // the failed directive without formatting its input or error.
        let index = directives
            .iter()
            .position(|directive| {
                directive
                    .parse::<tracing_subscriber::filter::Directive>()
                    .is_err()
            })
            .unwrap_or(0)
            + 1;
        format!("directive {index} has invalid filter syntax")
    })
}

/// Whether `directive` is a level or ends in `=<level>`. Whatever precedes
/// the `=` is left to EnvFilter's parser.
fn names_level(directive: &str) -> bool {
    let level = directive
        .rsplit_once('=')
        .map_or(directive, |(_, level)| level);
    // `LevelFilter` parses "" as ERROR, but EnvFilter reads `target=` as trace.
    !level.is_empty() && level.parse::<LevelFilter>().is_ok()
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
        assert!(
            !super::install_default_logging(),
            "second install is a no-op"
        );
        tracing::info!("maki-attach: fixture step");
        tracing::error!("maki-attach: rollback halted, fixture reason");
        tracing::debug!("fixture debug is hidden by default");
    }

    #[test]
    fn rollback_errors_and_steps_reach_stderr_without_ansi() {
        let stderr = child_stderr(None);
        assert!(stderr.contains("maki-attach: fixture step"), "{stderr}");
        assert!(stderr.contains("ERROR"), "{stderr}");
        assert!(
            stderr.contains("rollback halted, fixture reason"),
            "{stderr}"
        );
        assert!(!stderr.contains("fixture debug is hidden"), "{stderr}");
        assert!(
            !stderr.contains("\u{1b}["),
            "no ANSI escapes in a journal:\n{stderr}"
        );
    }

    /// With a stderr nobody reads the sink cannot write its events. It must
    /// drop them: the executor logs every step, and a panic there would end
    /// the helper in the middle of an attach or a detach.
    #[test]
    fn events_nobody_reads_are_dropped_without_a_panic() {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logging::tests::child_emits_events",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .env_remove(super::LOG_ENV)
            .env("RUST_BACKTRACE", "0")
            .stdout(std::process::Stdio::null())
            .stderr(writer)
            .status()
            .unwrap();
        assert!(status.success(), "the child failed on its first event");
    }

    #[test]
    fn maki_log_directives_filter_the_output() {
        let stderr = child_stderr(Some("error"));
        assert!(stderr.contains("rollback halted"), "{stderr}");
        assert!(!stderr.contains("fixture step"), "{stderr}");
    }

    const REFUSED: &str = "MAKI_LOG is not a valid filter";

    #[test]
    fn invalid_filter_diagnostics_never_expose_selector_values() {
        const SECRET: &str = "FILTER_SELECTOR_SECRET_7e9b6c";
        for (value, reason) in [
            (
                format!("info,[auth{{token={SECRET}}}]=bogus"),
                "directive 2 does not name a level",
            ),
            (
                format!("info,[auth{{token={SECRET}(}}]=trace"),
                "directive 2 has invalid filter syntax",
            ),
        ] {
            let stderr = child_stderr(Some(&value));
            assert!(!stderr.contains(SECRET), "selector value leaked:\n{stderr}");
            assert_eq!(stderr.matches(REFUSED).count(), 1, "{stderr}");
            assert!(stderr.contains(reason), "{stderr}");
        }
    }

    /// A directive without a level is a target at trace for EnvFilter, which
    /// then drops every other target: `MAKI_LOG=warning` hid halted
    /// rollbacks. Such a value means `info`, and the helper says so once.
    #[test]
    fn a_maki_log_value_without_a_level_falls_back_to_info_and_says_so() {
        for value in [
            "warning",
            "err",
            "notice",
            "wran",
            "maki_privileged",
            "maki_privileged=",
            "warn,maki_privileged",
            "[fixture]",
            "info,maki_privileged=bogus",
        ] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("rollback halted, fixture reason")
                    && stderr.contains("maki-attach: fixture step"),
                "MAKI_LOG={value:?} hid the helper's log:\n{stderr}"
            );
            assert!(
                !stderr.contains("fixture debug is hidden"),
                "MAKI_LOG={value:?} did not fall back to info:\n{stderr}"
            );
            assert_eq!(
                stderr.matches(REFUSED).count(),
                1,
                "MAKI_LOG={value:?} must be reported once:\n{stderr}"
            );
            assert!(
                stderr.contains("reason=directive")
                    && stderr.contains("does not name a level")
                    && !stderr.contains("value="),
                "the report identifies the failure without the value:\n{stderr}"
            );
        }
    }

    #[test]
    fn documented_maki_log_forms_keep_working_without_a_report() {
        for value in ["error", "ERROR", "1", "error,[fixture]=trace"] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("rollback halted") && !stderr.contains("fixture step"),
                "MAKI_LOG={value:?}:\n{stderr}"
            );
            assert!(!stderr.contains(REFUSED), "MAKI_LOG={value:?}:\n{stderr}");
        }
        let stderr = child_stderr(Some("info,maki_privileged=debug"));
        assert!(
            stderr.contains("fixture debug is hidden") && !stderr.contains(REFUSED),
            "{stderr}"
        );
    }

    /// An empty value (`Environment=MAKI_LOG=`) is an EnvFilter without any
    /// directive, which enables nothing. It names no filter, like an unset
    /// variable.
    #[test]
    fn an_empty_maki_log_means_info_like_an_unset_one() {
        for value in ["", ","] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("rollback halted")
                    && stderr.contains("fixture step")
                    && !stderr.contains("fixture debug is hidden"),
                "MAKI_LOG={value:?}:\n{stderr}"
            );
            assert!(!stderr.contains(REFUSED), "MAKI_LOG={value:?}:\n{stderr}");
        }
    }
}
