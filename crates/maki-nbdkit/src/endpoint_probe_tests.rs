//! The attach probe of a set's endpoints (`dispatch_endpoint_set`), on
//! tokio's paused clock: every endpoint is probed at once, so endpoints that
//! do not answer delay the attach by about one probe however many of them
//! are listed before one that serves (C3: probed one after another, three
//! WebSocket endpoints that never answered held a healthy fourth past
//! `maki@.service`'s `TimeoutStartSec=180` at the default 10 s timeout).
//! Each probe keeps its own attempts, the key canary checks still run one at
//! a time in configuration order, and the results are reported in that
//! order, as the serial probe gave them.

use super::*;
use maki_crypto::{CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, PlaintextUnit};
use maki_format::canary::CANARY_UNIT_INDEX;
use maki_test_support::fake_provider::FakeCryptoProvider;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const COMPATIBILITY_ID: &str = "endpoint-probes-v1";
/// `crypto.retry.initial_delay`: the spacing of a probe's attempts.
const DELAY: Duration = Duration::from_millis(100);
/// How long a request to an endpoint that does not answer takes to fail.
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum Answer {
    Serve,
    /// Fails every request as one that timed out (a transport failure).
    Away,
    /// Refuses every request with a failure that refuses the attach.
    Refuse,
}

/// An endpoint whose every request first takes `latency` on the paused
/// clock, then is served by a fake provider, fails or is refused.
struct Scripted {
    inner: FakeCryptoProvider,
    latency: Duration,
    answer: Answer,
    retry_safe: bool,
    requests: AtomicUsize,
    canary_encrypts: AtomicUsize,
    canary_decrypts: AtomicUsize,
}

impl Scripted {
    fn new(answer: Answer, latency: Duration) -> Arc<Self> {
        Self::with_retry_safety(answer, latency, true)
    }

    fn with_retry_safety(answer: Answer, latency: Duration, retry_safe: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: FakeCryptoProvider::new(512).with_compat_id(COMPATIBILITY_ID),
            latency,
            answer,
            retry_safe,
            requests: AtomicUsize::new(0),
            canary_encrypts: AtomicUsize::new(0),
            canary_decrypts: AtomicUsize::new(0),
        })
    }

    async fn request(&self, canary: bool, canaries: &AtomicUsize) -> Result<(), CryptoError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if canary {
            canaries.fetch_add(1, Ordering::SeqCst);
        }
        tokio::time::sleep(self.latency).await;
        match self.answer {
            Answer::Serve => Ok(()),
            Answer::Away => Err(CryptoError::Retryable("timed out".into())),
            Answer::Refuse => Err(CryptoError::ProviderFatal("refused".into())),
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl CryptoProvider for Scripted {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        let mut capabilities = self.inner.capabilities().await?;
        capabilities.retry_safe = self.retry_safe;
        Ok(capabilities)
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let canary = items
            .iter()
            .any(|item| item.unit_index == CANARY_UNIT_INDEX);
        self.request(canary, &self.canary_encrypts).await?;
        self.inner.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let canary = items
            .iter()
            .any(|item| item.unit_index == CANARY_UNIT_INDEX);
        self.request(canary, &self.canary_decrypts).await?;
        self.inner.decrypt_batch(context, items).await
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    config: VolumeConfig,
}

/// A created volume whose configuration names a remote provider; the
/// endpoints themselves are the scripted ones each test hands the probe.
fn fixture(retry_safe: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let raw = format!(
        r#"
config_schema_version = 1
[volume]
name = "endpoint-probes"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "{COMPATIBILITY_ID}"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 520
retry_safe = {retry_safe}
stateless = true
[crypto.retry]
initial_delay = "100ms"
max_delay = "100ms"
[crypto.http]
timeout = "10s"
[[crypto.http.endpoint]]
name = "configured"
url = "http://127.0.0.1:9"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#
    );
    create_volume_from_config_str(&raw).unwrap();
    Fixture {
        config: parse_and_validate(&raw).unwrap(),
        directory,
    }
}

fn named(endpoints: &[Arc<Scripted>]) -> Vec<NamedEndpoint> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            (
                format!("ep{index}"),
                endpoint.clone() as Arc<dyn CryptoProvider>,
            )
        })
        .collect()
}

/// Probe `endpoints` as attach does, and how long it took on the paused
/// clock.
async fn probe(
    config: &VolumeConfig,
    endpoints: &[Arc<Scripted>],
) -> (Duration, Result<Arc<EndpointSet>, DaemonError>) {
    let started = tokio::time::Instant::now();
    let result = dispatch_endpoint_set(config, named(endpoints), None, None).await;
    (started.elapsed(), result)
}

/// Each endpoint's name and whether it serves, by name (the set lists the
/// validated endpoints first).
fn validated(set: &EndpointSet) -> Vec<(String, bool)> {
    let mut states: Vec<_> = set
        .endpoint_status()
        .into_iter()
        .map(|status| (status.name, status.validated))
        .collect();
    states.sort();
    states
}

/// The time one probe of an endpoint that never answers takes.
fn one_probe(attempts: u32) -> Duration {
    TIMEOUT * attempts + DELAY * (attempts - 1)
}

#[tokio::test(start_paused = true)]
async fn endpoints_that_do_not_answer_cost_one_probe_however_many_are_listed() {
    for retry_safe in [true, false] {
        let attempts = if retry_safe { 3 } else { 1 };
        for away in [1, 4] {
            let volume = fixture(retry_safe);
            let mut endpoints: Vec<_> = (0..away)
                .map(|_| Scripted::with_retry_safety(Answer::Away, TIMEOUT, retry_safe))
                .collect();
            endpoints.push(Scripted::with_retry_safety(
                Answer::Serve,
                Duration::ZERO,
                retry_safe,
            ));
            let (elapsed, set) = probe(&volume.config, &endpoints).await;
            let set = set.unwrap();
            let mut expected: Vec<_> = (0..away).map(|i| (format!("ep{i}"), false)).collect();
            expected.push((format!("ep{away}"), true));
            assert_eq!(validated(&set), expected);
            // Each probe keeps its own attempts: three for a retry-safe
            // provider, one otherwise.
            for endpoint in &endpoints[..away] {
                assert_eq!(endpoint.requests(), attempts as usize);
            }
            assert_eq!(
                elapsed,
                one_probe(attempts),
                "{away} endpoints that do not answer before one that serves \
                 (retry_safe = {retry_safe})"
            );
        }
    }
}

/// On a new volume the first endpoint in configuration order that passes
/// its self-test establishes the key canary and the others verify it, as
/// when they were probed one after another, even when a later endpoint
/// answers first and one between them has finished its probe before the
/// first: the canary check loads and writes the volume's canary.
#[tokio::test(start_paused = true)]
async fn the_first_endpoint_in_configuration_order_establishes_the_key_canary() {
    let volume = fixture(true);
    let slow = Scripted::new(Answer::Serve, Duration::from_secs(1));
    let away = Scripted::new(Answer::Away, Duration::ZERO);
    let fast = Scripted::new(Answer::Serve, Duration::ZERO);
    let (_, set) = probe(&volume.config, &[slow.clone(), away, fast.clone()]).await;
    assert_eq!(
        validated(&set.unwrap()),
        [
            ("ep0".to_string(), true),
            ("ep1".to_string(), false),
            ("ep2".to_string(), true)
        ]
    );
    assert_eq!(slow.canary_encrypts.load(Ordering::SeqCst), 1);
    assert_eq!(fast.canary_encrypts.load(Ordering::SeqCst), 0);
    assert_eq!(fast.canary_decrypts.load(Ordering::SeqCst), 1);
    let root = volume.directory.path().join("volume");
    for copy in [
        maki_format::layout::KEY_CANARY_A,
        maki_format::layout::KEY_CANARY_B,
    ] {
        assert!(root.join(copy).exists(), "{copy} was not written");
    }
}

/// An endpoint that refuses the attach stops the probe before any endpoint
/// listed after it reaches the volume, as when the probe ended at it: a
/// later endpoint that passed its self-test meanwhile writes no canary,
/// also while an endpoint before the refusing one is still being probed.
#[tokio::test(start_paused = true)]
async fn a_refusal_keeps_the_endpoints_after_it_from_the_volume() {
    for away_before in [false, true] {
        let volume = fixture(true);
        let refusing = Scripted::new(Answer::Refuse, Duration::from_secs(1));
        let serving = Scripted::new(Answer::Serve, Duration::ZERO);
        let mut endpoints = vec![refusing, serving.clone()];
        if away_before {
            endpoints.insert(0, Scripted::new(Answer::Away, TIMEOUT));
        }
        let (_, result) = probe(&volume.config, &endpoints).await;
        let error = result.err().expect("the refusal refuses the attach");
        let refused = usize::from(away_before);
        assert_eq!(
            error.to_string(),
            format!(
                "unsupported: endpoint \"ep{refused}\" failed its self-test: provider fatal: \
                 refused"
            )
        );
        assert!(
            serving.requests() > 0,
            "the endpoint after it is probed at the same time"
        );
        assert_eq!(serving.canary_encrypts.load(Ordering::SeqCst), 0);
        assert_eq!(serving.canary_decrypts.load(Ordering::SeqCst), 0);
        let root = volume.directory.path().join("volume");
        for copy in [
            maki_format::layout::KEY_CANARY_A,
            maki_format::layout::KEY_CANARY_B,
        ] {
            assert!(!root.join(copy).exists(), "{copy} was written");
        }
    }
}

/// The results are reported in configuration order, whichever probe ends
/// first: the refusal names the endpoints in that order, and the first
/// endpoint that refuses the attach is the one named.
#[tokio::test(start_paused = true)]
async fn results_are_reported_in_configuration_order() {
    let volume = fixture(true);
    let away: Vec<_> = [3, 2, 1]
        .into_iter()
        .map(|seconds| Scripted::new(Answer::Away, Duration::from_secs(seconds)))
        .collect();
    let (elapsed, result) = probe(&volume.config, &away).await;
    let error = result.err().expect("no endpoint is reachable");
    let failure = "retryable: timed out";
    assert_eq!(
        error.to_string(),
        format!(
            "unsupported: no remote endpoint is reachable; attach refused (\"ep0\": \
             {failure}; \"ep1\": {failure}; \"ep2\": {failure})"
        )
    );
    assert_eq!(elapsed, Duration::from_secs(3) * 3 + DELAY * 2);

    let volume = fixture(true);
    let first = Scripted::new(Answer::Refuse, Duration::from_secs(2));
    let second = Scripted::new(Answer::Refuse, Duration::ZERO);
    let (_, result) = probe(&volume.config, &[first, second]).await;
    assert_eq!(
        result.err().expect("refused").to_string(),
        "unsupported: endpoint \"ep0\" failed its self-test: provider fatal: refused"
    );
}

/// Probe `endpoints` as the native plugin's attach does, and when each
/// report of the probe's progress came, on the paused clock, from `started`
/// to `ended`.
async fn probe_reporting(
    config: &VolumeConfig,
    endpoints: &[Arc<Scripted>],
) -> (Vec<tokio::time::Instant>, Arc<EndpointSet>) {
    let reports = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let progress: Arc<ProbeProgress> = {
        let reports = reports.clone();
        Arc::new(move || reports.lock().push(tokio::time::Instant::now()))
    };
    let started = tokio::time::Instant::now();
    let set = dispatch_endpoint_set(config, named(endpoints), None, Some(progress))
        .await
        .unwrap();
    let ended = tokio::time::Instant::now();
    let mut times = vec![started];
    times.extend(reports.lock().iter().copied());
    times.push(ended);
    // The set's own requests (its validation of quarantined endpoints) do
    // not report: nothing extends the start deadline once the set is built.
    let reported = reports.lock().len();
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(reports.lock().len(), reported, "reported after the probes");
    (times, set)
}

/// The longest time without a report between the probe's start and end.
fn longest_gap(times: &[tokio::time::Instant]) -> Duration {
    times
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .max()
        .unwrap()
}

/// Each probe request that ends reports progress, which the native plugin
/// turns into `EXTEND_TIMEOUT_USEC` (`startup.rs`): a probe of an endpoint
/// whose requests time out after 60 s runs past `TimeoutStartSec=180`, and
/// no time between reports is longer than one request and the delay before
/// the next attempt.
#[tokio::test(start_paused = true)]
async fn every_probe_request_that_ends_reports_progress() {
    let volume = fixture(true);
    let request = Duration::from_secs(60);
    let endpoints = [
        Scripted::new(Answer::Away, request),
        Scripted::new(Answer::Serve, Duration::ZERO),
    ];
    let (times, _set) = probe_reporting(&volume.config, &endpoints).await;
    let elapsed = *times.last().unwrap() - times[0];
    assert!(elapsed > Duration::from_secs(180), "{elapsed:?}");
    assert!(longest_gap(&times) <= request + DELAY, "{times:?}");
}

/// The cross-endpoint check after the probes reports each request that
/// ends as well: a check against an endpoint that answers each request in
/// 50 s makes several of them.
#[tokio::test(start_paused = true)]
async fn every_cross_endpoint_check_request_that_ends_reports_progress() {
    let volume = fixture(true);
    let request = Duration::from_secs(50);
    let endpoints = [
        Scripted::new(Answer::Serve, Duration::ZERO),
        Scripted::new(Answer::Serve, request),
    ];
    let (times, set) = probe_reporting(&volume.config, &endpoints).await;
    assert_eq!(
        validated(&set),
        [("ep0".to_string(), true), ("ep1".to_string(), true)]
    );
    assert!(longest_gap(&times) <= request, "{times:?}");
}
