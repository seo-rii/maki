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
//!
//! A command can hold back what the sink writes ([`hold`]) until it may
//! report it: `maki`'s read-only commands of a remote-protected volume write
//! what they logged while they read only once the authority has answered
//! that it still selects what was read (SPEC §27), and drop it otherwise.

use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tracing_subscriber::filter::{FilterExt, LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Environment variable holding a `tracing_subscriber::EnvFilter` directive
/// list, for example `warn`, `info,maki_core=debug`. Every directive names
/// its level (see `parse_filter`).
pub const LOG_ENV: &str = "MAKI_LOG";

/// The level used when [`LOG_ENV`] is unset, empty or invalid.
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
/// An invalid [`LOG_ENV`] value is reported once, by the call that installs
/// the sink.
pub fn install_default_logging() -> bool {
    let value = std::env::var_os(LOG_ENV);
    let (filter, refused) = match value.as_deref().map(parse_filter) {
        Some(Ok(Some(filter))) => (filter, None),
        Some(Err(reason)) => (EnvFilter::new(DEFAULT_LEVEL), Some(reason)),
        Some(Ok(None)) | None => (EnvFilter::new(DEFAULT_LEVEL), None),
    };
    // An event must pass both filters. Adding cap directives to the operator's
    // EnvFilter would not do: a more specific target directive
    // (`tungstenite::protocol=trace`) or a span directive (`[name]=trace`)
    // overrides them.
    let cap = Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_targets(CAPPED_TARGETS);
    let layer = fmt::layer()
        .with_writer(|| Sink)
        .with_ansi(false)
        .with_target(true)
        .with_filter(filter.and(cap));
    let installed = tracing_subscriber::registry()
        .with(layer)
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

/// The most log text [`hold`] keeps, in bytes. Lines held back beyond it are
/// counted, not kept.
const HELD_BYTES: usize = 16 << 20;

/// Whether the sink holds back what it writes ([`hold`]). Read before
/// [`HELD`] is locked, so a process that never holds (the plugin) writes as
/// before; it changes only with [`HELD`] locked.
static HOLDING: AtomicBool = AtomicBool::new(false);

static HELD: Mutex<Held> = Mutex::new(Held::EMPTY);

/// What the sink holds back.
struct Held {
    /// The text held back and kept, in the order it was written.
    text: Vec<u8>,
    /// The lines `text` holds.
    lines: usize,
    /// The lines held back and not kept, which came after `text` filled
    /// [`HELD_BYTES`].
    unkept: usize,
}

impl Held {
    const EMPTY: Self = Self {
        text: Vec::new(),
        lines: 0,
        unkept: 0,
    };

    /// Keep `text`, one event's lines, while it fits and nothing before it
    /// was left out: what is written later is then everything held back up
    /// to a point, in order.
    fn keep(&mut self, text: &[u8]) {
        let lines = text.iter().filter(|&&byte| byte == b'\n').count()
            + usize::from(text.last().is_some_and(|&byte| byte != b'\n'));
        if self.unkept == 0 && text.len() <= HELD_BYTES - self.text.len() {
            self.text.extend_from_slice(text);
            self.lines += lines;
        } else {
            self.unkept += lines;
        }
    }
}

fn held() -> MutexGuard<'static, Held> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default sink's writer: stderr, or [`HELD`] while lines are held.
/// The fmt layer formats an event and writes it with one `write_all`, so
/// one event is held back or written whole.
struct Sink;

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if HOLDING.load(Ordering::Acquire) {
            let mut held = held();
            // Asked again under the lock: lines released meanwhile have
            // been written, and this one follows them.
            if HOLDING.load(Ordering::Relaxed) {
                held.keep(buf);
                return Ok(buf.len());
            }
        }
        io::stderr().lock().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// Hold back the lines the default sink writes from now on, until the
/// returned [`HeldLines`] is released or dropped, which writes them to
/// stderr in order, or discarded. `None` while lines are held already. At
/// most 16 MiB of text is kept: lines held back beyond it are counted, and
/// the release says how many were not kept. Nothing changes for a process
/// whose subscriber is not the default sink ([`install_default_logging`]).
pub fn hold() -> Option<HeldLines> {
    let _held = held();
    if HOLDING.swap(true, Ordering::AcqRel) {
        return None;
    }
    Some(HeldLines(()))
}

/// The lines the default sink holds back ([`hold`]). Dropping it writes
/// them, as [`HeldLines::release`] does.
#[must_use = "dropping it writes the held lines at once"]
pub struct HeldLines(());

impl HeldLines {
    /// Write the held lines to stderr, in the order they were logged, and
    /// write later lines at once again.
    pub fn release(self) {
        // `Drop` writes them.
    }

    /// Drop the held lines unwritten, and write later lines at once again.
    /// Returns how many lines were held back, kept or not.
    pub fn discard(self) -> usize {
        std::mem::forget(self);
        end(false)
    }
}

impl Drop for HeldLines {
    fn drop(&mut self) {
        end(true);
    }
}

/// Stop holding: write what was kept to stderr where `write`, before any
/// line logged after it, and return how many lines were held back.
fn end(write: bool) -> usize {
    let mut held = held();
    let Held {
        text,
        lines,
        unkept,
    } = std::mem::replace(&mut *held, Held::EMPTY);
    if write {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(&text);
        let _ = stderr.flush();
    }
    HOLDING.store(false, Ordering::Release);
    drop(held);
    if write && unkept > 0 {
        tracing::warn!(
            lines = unkept,
            "log lines held back beyond {} MiB of log text were not kept",
            HELD_BYTES >> 20
        );
    }
    lines + unkept
}

/// Parse a [`LOG_ENV`] value: `Ok(None)` when it holds no directive (empty),
/// which means the default like an unset variable.
///
/// EnvFilter reads a directive without a level as a target, or a span,
/// enabled at trace, and turns every target no directive names off. A
/// misspelt level (`warning`, `err`) would then silence every Maki event,
/// ERROR included, so each directive must be a level or end in `=<level>`.
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

    /// EnvFilter reads a directive without a level as a target enabled at
    /// trace and turns every other target off, so a misspelt level such as
    /// `warning` silenced every Maki event, ERROR included. Such a value is
    /// invalid and means `info`, like any other invalid value, and the
    /// process says so once.
    #[test]
    fn a_maki_log_value_without_a_level_falls_back_to_info_and_says_so() {
        for value in [
            "warning",
            "err",
            "notice",
            "wran",
            "maki_core",
            "maki_core=",
            "warn,maki_core",
            "[cap_probe]",
            "info,maki_core=bogus",
        ] {
            let stderr = child_stderr(Some(value));
            for line in [
                "fixture warning reaches stderr",
                "fixture info reaches stderr",
                "fixture error reaches stderr",
            ] {
                assert!(
                    stderr.contains(line),
                    "MAKI_LOG={value:?} hid {line:?}:\n{stderr}"
                );
            }
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
        for value in ["warn", "WARN", "Warn", "2", "warn,[cap_probe]=trace"] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("fixture warning reaches stderr")
                    && stderr.contains("fixture error reaches stderr")
                    && !stderr.contains("fixture info reaches stderr"),
                "MAKI_LOG={value:?}:\n{stderr}"
            );
            assert!(!stderr.contains(REFUSED), "MAKI_LOG={value:?}:\n{stderr}");
        }
        for value in ["info,maki_core=debug", "info,maki_core::logging=debug"] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("fixture debug is hidden") && stderr.contains("fixture info"),
                "MAKI_LOG={value:?}:\n{stderr}"
            );
            assert!(!stderr.contains(REFUSED), "MAKI_LOG={value:?}:\n{stderr}");
        }
    }

    /// An empty value (`Environment=MAKI_LOG=`) is an EnvFilter without any
    /// directive, which enables nothing. It names no filter, like an unset
    /// variable.
    #[test]
    fn an_empty_maki_log_means_info_like_an_unset_one() {
        for value in ["", ","] {
            let stderr = child_stderr(Some(value));
            assert!(
                stderr.contains("fixture warning reaches stderr")
                    && stderr.contains("fixture info reaches stderr")
                    && stderr.contains("fixture error reaches stderr")
                    && !stderr.contains("fixture debug is hidden"),
                "MAKI_LOG={value:?}:\n{stderr}"
            );
            assert!(!stderr.contains(REFUSED), "MAKI_LOG={value:?}:\n{stderr}");
        }
    }

    #[test]
    fn child_holds_lines() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        assert!(super::install_default_logging());
        tracing::warn!("logged before the hold");
        let held = super::hold().unwrap();
        assert!(super::hold().is_none(), "one hold at a time");
        tracing::warn!("held, then released");
        // Another thread's lines are held back too.
        std::thread::spawn(|| tracing::warn!("held from another thread"))
            .join()
            .unwrap();
        held.release();
        tracing::warn!("logged after the release");
        let held = super::hold().unwrap();
        tracing::warn!("held, then discarded\nwith a second line");
        assert_eq!(held.discard(), 2);
        tracing::warn!("logged after the discard");
        {
            let _held = super::hold().unwrap();
            tracing::warn!("held, then written by the drop");
        }
        let held = super::hold().unwrap();
        tracing::warn!("held and kept before the bound");
        tracing::warn!("{}", "x".repeat(super::HELD_BYTES));
        tracing::warn!("held after the bound, not kept");
        held.release();
        let held = super::hold().unwrap();
        tracing::warn!("{}", "y".repeat(super::HELD_BYTES));
        tracing::warn!("held after the bound, then discarded");
        assert_eq!(held.discard(), 2);
        tracing::warn!("logged last");
    }

    /// Held lines are written at the release, after every line logged
    /// before the hold and before every line logged after it, from any
    /// thread; discarded ones are not written and are counted. At most
    /// `HELD_BYTES` of text is kept, and what is not kept is counted and
    /// said, never dropped unsaid.
    #[test]
    fn held_lines_are_written_in_order_at_the_release_and_counted_when_discarded() {
        let stderr = child_stderr_of("logging::tests::child_holds_lines", None);
        let at = |line: &str| {
            stderr
                .find(line)
                .unwrap_or_else(|| panic!("{line:?} is missing:\n{stderr}"))
        };
        let order = [
            "logged before the hold",
            "held, then released",
            "logged after the release",
            "logged after the discard",
            "held, then written by the drop",
            "held and kept before the bound",
            "lines=2",
            "logged last",
        ]
        .map(at);
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{stderr}");
        assert!(at("held from another thread") > order[1], "{stderr}");
        assert!(at("held from another thread") < order[2], "{stderr}");
        for unwritten in [
            "held, then discarded",
            "with a second line",
            "held after the bound",
            &"x".repeat(64),
            &"y".repeat(64),
        ] {
            assert!(!stderr.contains(unwritten), "{unwritten:?}:\n{stderr}");
        }
        assert_eq!(
            stderr
                .matches("log lines held back beyond 16 MiB of log text were not kept")
                .count(),
            1,
            "{stderr}"
        );
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
