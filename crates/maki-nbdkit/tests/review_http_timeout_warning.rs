//! An HTTP provider `timeout` under 600 ms is accepted with a warning.
//!
//! The HTTP transport starts the other address family of an endpoint's host
//! 300 ms after the first, or at once when the first family has failed
//! (hyper-util's delay, which reqwest does not let the provider change;
//! docs/configuration.md, remote HTTP mapping). While the first family does
//! not answer, the other gets less than half of a `timeout` under 600 ms
//! and is never tried at 300 ms or less, so such a host can fail every
//! connect. `maki check` (through
//! `report_configuration_mismatches`) and attach say so, naming the value;
//! a longer or unset `timeout`, and the WebSocket and gRPC transports, which
//! start the other family halfway through a short timeout, get no warning.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use maki_format::checker::CheckReport;
use maki_nbdkit::daemon::{
    attach_from_config, create_volume_from_config_str, parse_and_validate,
    report_configuration_mismatches,
};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};

/// How long an attach may take before the test gives up on it.
const BOUND: Duration = Duration::from_secs(30);

/// The warning for an HTTP `timeout` printed as `value`.
fn warning(value: &str) -> String {
    format!(
        "[crypto.http] timeout is {value}: while the first address family of an endpoint's \
         host does not answer, the other family gets less than half of a timeout under 600 ms \
         and is never tried at 300 ms or less, so such a host can fail every connect"
    )
}

/// A remote volume's configuration for `provider` whose transport section
/// has `timeout` (none when empty).
fn config(root: &str, provider: &str, url: &str, timeout: &str) -> String {
    let section = match provider {
        "remote-http" => "http",
        "remote-websocket" => "websocket",
        _ => "grpc",
    };
    let timeout = match timeout {
        "" => String::new(),
        value => format!("timeout = \"{value}\"\n"),
    };
    let mapping = if provider == "remote-http" {
        "[crypto.http.encrypt]\npath = \"/encrypt\"\n[crypto.http.decrypt]\npath = \"/decrypt\"\n"
    } else {
        ""
    };
    format!(
        r#"
config_schema_version = 1
[volume]
name = "http-timeout"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "remote-v1"
availability_policy = "bounded-error"
max_operation_time = "5s"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
stateless = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 512
target_bytes = 512
max_wait = "0ms"
[crypto.{section}]
{timeout}[[crypto.{section}.endpoint]]
name = "only"
url = "{url}"
{mapping}
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    )
}

fn root(directory: &tempfile::TempDir, name: &str) -> String {
    directory
        .path()
        .join(name)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The warnings `maki check` reports for `raw` over the volume it created.
fn check_warnings(raw: &str) -> Vec<String> {
    let config = parse_and_validate(raw).unwrap();
    create_volume_from_config_str(raw).unwrap();
    let backing = maki_backing::FileBacking::new(&config.backing.root).unwrap();
    let mut report = CheckReport::default();
    report_configuration_mismatches(&config, &backing, &mut report).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    report.warnings
}

#[test]
fn maki_check_warns_about_an_http_timeout_under_600_ms() {
    let directory = tempfile::tempdir().unwrap();
    for (index, (timeout, printed)) in [("300ms", "300ms"), ("150ms", "150ms"), ("599ms", "599ms")]
        .into_iter()
        .enumerate()
    {
        let raw = config(
            &root(&directory, &format!("short-{index}")),
            "remote-http",
            "http://127.0.0.1:9",
            timeout,
        );
        assert_eq!(
            check_warnings(&raw),
            [warning(printed)],
            "timeout {timeout}"
        );
    }
    for (index, timeout) in ["600ms", "1s", ""].into_iter().enumerate() {
        let raw = config(
            &root(&directory, &format!("long-{index}")),
            "remote-http",
            "http://127.0.0.1:9",
            timeout,
        );
        assert_eq!(
            check_warnings(&raw),
            Vec::<String>::new(),
            "timeout {timeout:?}"
        );
    }
    for (provider, url) in [
        ("remote-websocket", "ws://127.0.0.1:9"),
        ("remote-grpc", "http://127.0.0.1:9"),
    ] {
        let raw = config(&root(&directory, provider), provider, url, "300ms");
        assert_eq!(check_warnings(&raw), Vec::<String>::new(), "{provider}");
    }
}

/// Records the message of every event on the thread it is the default for.
struct Capture(Mutex<mpsc::Sender<String>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        let line = format!("{} {}", event.metadata().level(), message.0);
        let _ = self.0.lock().unwrap().send(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Create the volume of `raw` and attach it on a thread whose events are
/// recorded; return whether the attach succeeded and every event.
fn attach_events(raw: String) -> (Result<(), String>, Vec<String>) {
    let config = parse_and_validate(&raw).unwrap();
    create_volume_from_config_str(&raw).unwrap();
    let (done, outcome) = mpsc::channel();
    let (lines, log) = mpsc::channel();
    std::thread::spawn(move || {
        let _capture = tracing::subscriber::set_default(Capture(Mutex::new(lines)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            attach_from_config(&config)
                .await
                .map(drop)
                .map_err(|error| error.to_string())
        });
        let _ = done.send(result);
    });
    let result = outcome
        .recv_timeout(BOUND)
        .expect("the attach did not end in time");
    (result, log.try_iter().collect())
}

#[test]
fn attach_warns_about_an_http_timeout_under_600_ms() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(TestServer::start(Arc::new(|request| {
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    })));
    let directory = tempfile::tempdir().unwrap();
    // The warning comes before any endpoint is asked, whatever the attach
    // then makes of the endpoint.
    let (_, events) = attach_events(config(
        &root(&directory, "short"),
        "remote-http",
        &server.url(),
        "300ms",
    ));
    let expected = format!("WARN {}", warning("300ms"));
    assert_eq!(
        events.iter().filter(|line| **line == expected).count(),
        1,
        "{events:#?}"
    );
    let (attached, events) = attach_events(config(
        &root(&directory, "long"),
        "remote-http",
        &server.url(),
        "600ms",
    ));
    attached.expect("the fixture attaches");
    assert!(
        !events
            .iter()
            .any(|line| line.contains("[crypto.http] timeout")),
        "{events:#?}"
    );
}
