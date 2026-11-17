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
//!
//! The sink also receives dependencies' `log` records (tracing-subscriber's
//! `tracing-log` bridge). Some dependencies print payload or credential bytes
//! at their most verbose levels, so those targets are capped whatever
//! [`LOG_ENV`] says (see `CAPPED_TARGETS`).

use std::io;

use tracing_subscriber::filter::{FilterExt, LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Environment variable holding a `tracing_subscriber::EnvFilter` directive
/// list, for example `warn`, `info,maki_core=debug`.
pub const LOG_ENV: &str = "MAKI_LOG";

/// The level used when [`LOG_ENV`] is unset or unparsable.
pub const DEFAULT_LEVEL: &str = "info";

/// Dependency targets (and their submodules) whose more verbose levels print
/// payload or credential bytes, with the most verbose level each may reach
/// whatever [`LOG_ENV`] says:
///
/// - `tungstenite` logs every frame's payload (hex), every received text
///   message and the client upgrade request (URL path, query and headers) at
///   trace. WebSocket requests and responses carry the unit plaintext.
///   Its `protocol` target also prints peer-supplied close reasons and the
///   reply frame at debug, so that subtree is capped at info.
/// - `tokio_tungstenite` is its async wrapper and is capped at debug.
/// - `reqwest` dumps the raw bytes it reads and writes above TLS at trace
///   when a client enables `connection_verbose`. The HTTP provider does not;
///   the cap keeps request bodies out of the log should that ever change.
///
/// Outside the protocol subtree, their debug output on Maki's transport
/// paths is connection lifecycle and error descriptions. The other libraries
/// on the plaintext path print no payload or credential bytes
/// at any level: hyper is built without logging, h2 leaves DATA payloads and
/// header fields out of its frame formatting, rustls logs public handshake
/// data only, and tonic, tower and hyper-util log connection state.
const CAPPED_TARGETS: [(&str, LevelFilter); 4] = [
    ("tungstenite", LevelFilter::DEBUG),
    ("tungstenite::protocol", LevelFilter::INFO),
    ("tokio_tungstenite", LevelFilter::DEBUG),
    ("reqwest", LevelFilter::DEBUG),
];

/// Install the default stderr subscriber once per process.
///
/// Returns `true` when this call installed it and `false` when a subscriber
/// was already present (a test harness, or an earlier call). Either way the
/// process ends up with a working sink, so callers can ignore the result.
pub fn install_default_logging() -> bool {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LEVEL));
    // An event must pass both filters. Adding cap directives to the operator's
    // EnvFilter would not do: a more specific target directive
    // (`tungstenite::protocol=trace`) or a span directive (`[name]=trace`)
    // overrides them.
    let cap = Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_targets(CAPPED_TARGETS);
    let layer = fmt::layer()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(true)
        .with_filter(filter.and(cap));
    tracing_subscriber::registry()
        .with(layer)
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
        child_stderr_of("logging::tests::child_emits_events", filter)
    }

    fn child_stderr_of(child: &str, filter: Option<&str>) -> String {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", child, "--nocapture", "--test-threads=1"])
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
        tracing::warn!(volume = "fixture", "fixture warning reaches stderr");
        tracing::info!("fixture info reaches stderr");
        tracing::debug!("fixture debug is hidden by default");
        tracing::error!(error = %"fixture error class", "fixture error reaches stderr");
    }

    #[test]
    fn default_install_writes_info_and_above_to_stderr_without_ansi() {
        let stderr = child_stderr(None);
        assert!(
            stderr.contains("fixture warning reaches stderr"),
            "{stderr}"
        );
        assert!(stderr.contains("volume=\"fixture\""), "{stderr}");
        assert!(stderr.contains("fixture info reaches stderr"), "{stderr}");
        assert!(stderr.contains("fixture error reaches stderr"), "{stderr}");
        assert!(!stderr.contains("fixture debug is hidden"), "{stderr}");
        assert!(
            stderr.contains("WARN") && stderr.contains("ERROR"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("\u{1b}["),
            "no ANSI escapes in a journal:\n{stderr}"
        );
    }

    #[test]
    fn maki_log_directives_filter_the_output() {
        let stderr = child_stderr(Some("error"));
        assert!(stderr.contains("fixture error reaches stderr"), "{stderr}");
        assert!(
            !stderr.contains("fixture warning reaches stderr"),
            "{stderr}"
        );
        let stderr = child_stderr(Some("debug"));
        assert!(stderr.contains("fixture debug is hidden"), "{stderr}");
    }

    /// Payload-carrying targets and whether their debug output is safe.
    const CAPPED: [(&str, bool); 4] = [
        ("tungstenite::protocol::frame", false),
        ("tungstenite::handshake::client", true),
        ("tokio_tungstenite::compat", true),
        ("reqwest::connect", true),
    ];

    #[test]
    fn child_emits_dependency_events() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        assert!(super::install_default_logging());
        macro_rules! emit {
            ($target:literal) => {
                tracing::trace!(target: $target, "trace from {}", $target);
                tracing::debug!(target: $target, "debug from {}", $target);
                tracing::info!(target: $target, "info from {}", $target);
            };
        }
        let span = tracing::info_span!("cap_probe");
        let _entered = span.enter();
        emit!("tungstenite::protocol::frame");
        emit!("tungstenite::handshake::client");
        emit!("tokio_tungstenite::compat");
        emit!("reqwest::connect");
        emit!("maki_core::fixture");
    }

    #[test]
    fn dependency_payload_targets_cannot_exceed_safe_levels_whatever_maki_log_says() {
        for filter in [
            "trace",
            "warn,tungstenite=trace,tokio_tungstenite=trace,reqwest=trace",
            // More specific than a crate-level directive.
            "warn,tungstenite::protocol::frame=trace,tungstenite::handshake::client=trace,\
             tokio_tungstenite::compat=trace,reqwest::connect=trace",
            // A span directive enables every target inside the span.
            "warn,[cap_probe]=trace",
        ] {
            let stderr = child_stderr_of(
                "logging::tests::child_emits_dependency_events",
                Some(filter),
            );
            for (target, debug_safe) in CAPPED {
                assert!(
                    !stderr.contains(&format!("trace from {target}")),
                    "MAKI_LOG={filter} let {target} log at trace:\n{stderr}"
                );
                assert_eq!(
                    stderr.contains(&format!("debug from {target}")),
                    debug_safe,
                    "MAKI_LOG={filter} did not enforce {target}'s debug cap:\n{stderr}"
                );
                assert!(
                    stderr.contains(&format!("info from {target}")),
                    "MAKI_LOG={filter} hid {target} info diagnostics:\n{stderr}"
                );
            }
        }
        let stderr = child_stderr_of(
            "logging::tests::child_emits_dependency_events",
            Some("trace"),
        );
        assert!(
            stderr.contains("trace from maki_core::fixture"),
            "Maki's own targets keep the operator's threshold:\n{stderr}"
        );
        let stderr = child_stderr_of("logging::tests::child_emits_dependency_events", None);
        for (target, _) in CAPPED {
            assert!(
                !stderr.contains(&format!("debug from {target}")),
                "the default threshold stays info:\n{stderr}"
            );
        }
    }
}
