//! Under `bounded-error` an operation can run out of time in several places:
//! with no time left when it starts, at the top of a retry pass, right after
//! a failed RPC, while it waits for endpoint admission or while an RPC is in
//! flight. Through the batch scheduler the caller's own budget, which starts
//! before queueing, usually runs out first. These exits answered
//! differently: an RPC cut off by the deadline, and a scheduler caller whose
//! own budget ran out, returned the bare "operation deadline exceeded" even
//! though an endpoint had already failed the operation, while the other
//! exits returned that endpoint's error. The exit right after a failed RPC
//! did not count the expiry, and with batching the deadline counter missed
//! every caller that received an endpoint error at its deadline.
//!
//! Every exit now returns the last endpoint error the operation received
//! before its deadline, with that error's own class, or the deadline error
//! when no endpoint failed it, and every operation that ended because its
//! own deadline ran out counts once in `deadline_exceeded_total`, whatever
//! it returned. A nested set's expiry is a failure of that peer: the nested
//! set counts it, and neither the outer set nor a scheduler caller does.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use maki_crypto::breaker::{BreakerConfig, CircuitState};
use maki_crypto::clock::{Clock, SleepFuture};
use maki_crypto::endpoint::{DispatchConfig, EndpointSet};
use maki_crypto::retry::{RetryBudgetConfig, RetryPolicy};
use maki_crypto::scheduler::{BatchScheduler, SchedulerConfig};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, RandomPrefixProvider, SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::ManualClock;
use tokio::task::JoinHandle;

const UNIT: u32 = 256;
const PREFIX: u32 = 16;
const DEADLINE: Duration = Duration::from_millis(100);
const FAILURE: &str = "HTTP 429 from the first endpoint";
const DEADLINE_MESSAGE: &str = "operation deadline exceeded";
const COMPAT: &str = "test-profile-v1";
const PREFIX_COMPAT: &str = "test-profile-v1+prefix";

fn ctx(compat: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xDEAD),
        format_version: 1,
        crypto_compatibility_id: compat.into(),
    }
}

fn pt(unit: u64, size: u32) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: unit,
        data: SecretBuffer::from_slice(&vec![unit as u8 ^ 0x3c; size as usize]),
    }
}

/// `bounded-error`, retry-safe, a breaker that stays closed. Backoff is
/// capped by the remaining budget, so a failed pass sleeps to the deadline.
fn cfg() -> DispatchConfig {
    DispatchConfig {
        retry: RetryPolicy {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(1),
        },
        budget: RetryBudgetConfig {
            retry_ratio: 1.0,
            burst: 16,
            min_probe_per_sec: 1.0,
        },
        breaker: BreakerConfig {
            failure_threshold: 100,
            open_initial: Duration::from_secs(60),
            open_max: Duration::from_secs(60),
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        global_max_inflight_batches: 8,
        global_max_inflight_bytes: 1 << 20,
        per_endpoint_max_inflight: 8,
        per_endpoint_max_bytes: 1 << 20,
        max_attempts: None,
        max_operation_time: Some(DEADLINE),
        retry_safe: true,
        validation_interval: Duration::from_secs(1),
    }
}

fn failure() -> CryptoError {
    CryptoError::Throttled(FAILURE.into())
}

/// An endpoint that answers every call at once with [`failure`].
fn failing(unit: u32) -> Arc<FakeCryptoProvider> {
    let provider = Arc::new(FakeCryptoProvider::new(unit));
    provider.fail_next((0..1000).map(|_| failure()));
    provider
}

/// An endpoint whose calls outlive every budget in this file.
fn slow(unit: u32, clock: Arc<dyn Clock>) -> Arc<FakeCryptoProvider> {
    let provider = Arc::new(FakeCryptoProvider::new(unit));
    provider.set_latency(clock, Duration::from_secs(3600));
    provider
}

fn set_of(
    peers: Vec<(&str, Arc<dyn CryptoProvider>)>,
    config: DispatchConfig,
    clock: Arc<dyn Clock>,
) -> Arc<EndpointSet> {
    Arc::new(EndpointSet::new(
        peers
            .into_iter()
            .map(|(name, peer)| (name.to_string(), peer))
            .collect(),
        config,
        clock,
    ))
}

fn spawn_encrypt(
    provider: Arc<dyn CryptoProvider>,
    compat: &'static str,
    unit: u64,
    size: u32,
) -> JoinHandle<Result<(), CryptoError>> {
    tokio::spawn(async move {
        provider
            .encrypt_batch(&ctx(compat), &[pt(unit, size)])
            .await
            .map(drop)
    })
}

/// None of these calls completes, so the ciphertext only needs a valid size.
fn spawn_decrypt(
    provider: Arc<dyn CryptoProvider>,
    compat: &'static str,
    unit: u64,
    ciphertext: u32,
) -> JoinHandle<Result<(), CryptoError>> {
    tokio::spawn(async move {
        let items = [CiphertextUnit {
            unit_index: unit,
            data: vec![unit as u8; ciphertext as usize],
        }];
        provider.decrypt_batch(&ctx(compat), &items).await.map(drop)
    })
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

async fn finished(task: JoinHandle<Result<(), CryptoError>>) -> Result<(), CryptoError> {
    assert!(
        task.is_finished(),
        "the operation did not end at its deadline"
    );
    task.await.unwrap()
}

/// The endpoint's own error, with its own class and message.
fn assert_endpoint_error(result: Result<(), CryptoError>) {
    let error = result.expect_err("the operation must fail at its deadline");
    assert!(
        matches!(&error, CryptoError::Throttled(message) if message == FAILURE),
        "the deadline exit dropped the endpoint's error: {error:?}"
    );
    assert_eq!(error.class(), ErrorClass::Throttled);
}

fn assert_deadline_error(result: Result<(), CryptoError>) {
    let error = result.expect_err("the operation must fail at its deadline");
    assert!(
        matches!(&error, CryptoError::Retryable(message) if message == DEADLINE_MESSAGE),
        "{error:?}"
    );
}

// ---------- the dispatcher's exits ----------

#[tokio::test]
async fn a_deadline_at_the_top_of_a_pass_returns_the_last_endpoint_error() {
    let clock = Arc::new(ManualClock::new());
    let only = failing(UNIT);
    let set = set_of(vec![("only", only.clone())], cfg(), clock.clone());
    let task = spawn_encrypt(set.clone(), COMPAT, 1, UNIT);
    settle().await;
    assert_eq!(only.encrypt_calls(), 1);
    assert!(
        !task.is_finished(),
        "the operation backs off until its deadline"
    );
    clock.advance(DEADLINE);
    settle().await;
    assert_endpoint_error(finished(task).await);
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(only.encrypt_calls(), 1);
}

#[tokio::test]
async fn an_rpc_cut_off_by_the_deadline_returns_the_last_endpoint_error() {
    let clock = Arc::new(ManualClock::new());
    let first = failing(UNIT);
    let second = slow(UNIT, clock.clone());
    let set = set_of(
        vec![("first", first.clone()), ("second", second.clone())],
        cfg(),
        clock.clone(),
    );
    let task = spawn_encrypt(set.clone(), COMPAT, 1, UNIT);
    settle().await;
    assert_eq!((first.encrypt_calls(), second.encrypt_calls()), (1, 1));
    assert!(!task.is_finished(), "the failover RPC is in flight");
    clock.advance(DEADLINE);
    settle().await;
    assert_endpoint_error(finished(task).await);
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    // Cutting the RPC off is the operation's budget, not the peer's fault.
    assert_eq!(set.endpoint_status()[1].circuit, CircuitState::Closed);
    assert_eq!(set.endpoint_inflight()[1].1, 0);
}

/// A `ManualClock` that jumps to `target` at its `n`-th reading after it is
/// armed: time spent in synchronous work between two of the dispatcher's
/// deadline checks, which a manual clock alone cannot show.
#[derive(Default)]
struct JumpClock {
    manual: ManualClock,
    armed: Mutex<Option<(usize, Duration)>>,
}

impl JumpClock {
    fn arm(&self, reading: usize, target: Duration) {
        *self.armed.lock().unwrap() = Some((reading, target));
    }
}

impl Clock for JumpClock {
    fn now(&self) -> Duration {
        let mut armed = self.armed.lock().unwrap();
        if let Some((reading, target)) = armed.as_mut() {
            *reading -= 1;
            if *reading == 0 {
                self.manual.set(*target);
                *armed = None;
            }
        }
        self.manual.now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        self.manual.sleep(duration)
    }
}

/// Fails every call and arms the clock as it returns the failure.
struct FailAndJump {
    inner: Arc<FakeCryptoProvider>,
    clock: Arc<JumpClock>,
    reading: usize,
}

#[async_trait]
impl CryptoProvider for FailAndJump {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let result = self.inner.encrypt_batch(context, items).await;
        assert!(result.is_err());
        self.clock.arm(self.reading, DEADLINE);
        result
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

/// After the failing endpoint returns, the dispatcher reads the clock for
/// the RPC latency sample and to check that the RPC beat the deadline; the
/// third reading (the breaker charge) jumps to the deadline, so the check
/// right after the failed RPC sees it.
#[tokio::test]
async fn a_deadline_right_after_a_failed_rpc_is_counted() {
    let clock = Arc::new(JumpClock::default());
    let only = failing(UNIT);
    let set = set_of(
        vec![(
            "only",
            Arc::new(FailAndJump {
                inner: only.clone(),
                clock: clock.clone(),
                reading: 3,
            }),
        )],
        cfg(),
        clock.clone(),
    );
    let result = set.encrypt_batch(&ctx(COMPAT), &[pt(1, UNIT)]).await;
    assert_eq!(clock.now(), DEADLINE, "the clock did not jump");
    assert_endpoint_error(result.map(drop));
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(
        set.metrics().rpc_count(),
        1,
        "the failed RPC beat the deadline"
    );
    assert_eq!(only.encrypt_calls(), 1);
}

/// The fifth reading after the failure is the failover's admission, which
/// then has no time left: it must not reach the healthy peer.
#[tokio::test]
async fn an_admission_with_no_time_left_returns_the_last_endpoint_error() {
    let clock = Arc::new(JumpClock::default());
    let first = failing(UNIT);
    let healthy = Arc::new(FakeCryptoProvider::new(UNIT));
    let set = set_of(
        vec![
            (
                "first",
                Arc::new(FailAndJump {
                    inner: first.clone(),
                    clock: clock.clone(),
                    reading: 5,
                }),
            ),
            ("healthy", healthy.clone()),
        ],
        cfg(),
        clock.clone(),
    );
    let result = set.encrypt_batch(&ctx(COMPAT), &[pt(1, UNIT)]).await;
    assert_eq!(clock.now(), DEADLINE, "the clock did not jump");
    assert_endpoint_error(result.map(drop));
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(
        healthy.encrypt_calls(),
        0,
        "an RPC started after the deadline"
    );
}

#[tokio::test]
async fn an_operation_with_no_time_left_never_reaches_an_endpoint() {
    let clock = Arc::new(ManualClock::new());
    let only = Arc::new(FakeCryptoProvider::new(UNIT));
    let set = set_of(
        vec![("only", only.clone())],
        DispatchConfig {
            max_operation_time: Some(Duration::ZERO),
            ..cfg()
        },
        clock.clone(),
    );
    let scheduler = Arc::new(BatchScheduler::new(
        set.clone(),
        SchedulerConfig {
            target_items: 1,
            ..SchedulerConfig::default()
        },
        clock.clone(),
    ));
    for top in [
        set.clone() as Arc<dyn CryptoProvider>,
        scheduler.clone() as Arc<dyn CryptoProvider>,
    ] {
        let task = spawn_encrypt(top, COMPAT, 1, UNIT);
        settle().await;
        assert_deadline_error(finished(task).await);
    }
    assert_eq!(set.metrics().deadline_exceeded_total(), 1);
    assert_eq!(scheduler.stats().deadline_exceeded_total(), 1);
    assert_eq!(only.encrypt_calls(), 0);
}

// ---------- through the batch scheduler ----------

/// The serving stack: scheduler, optional random-prefix wrapper, set.
struct Stack {
    clock: Arc<ManualClock>,
    first: Arc<FakeCryptoProvider>,
    set: Arc<EndpointSet>,
    scheduler: Arc<BatchScheduler>,
    compat: &'static str,
    ciphertext: u32,
}

/// `first` fails every call at once; with `failover`, a second peer never
/// answers. The scheduler keeps its own clock when `endpoint_clock` is
/// given.
async fn stack(
    prefix: bool,
    failover: bool,
    scheduler: SchedulerConfig,
    endpoint_clock: Option<Arc<ManualClock>>,
) -> Stack {
    let clock = Arc::new(ManualClock::new());
    let endpoint_clock = endpoint_clock.unwrap_or_else(|| clock.clone());
    let wire = if prefix { UNIT + PREFIX } else { UNIT };
    let first = failing(wire);
    let mut peers: Vec<(&str, Arc<dyn CryptoProvider>)> = vec![("first", first.clone())];
    if failover {
        peers.push(("second", slow(wire, endpoint_clock.clone())));
    }
    let set = set_of(peers, cfg(), endpoint_clock);
    let mut inner: Arc<dyn CryptoProvider> = set.clone();
    let mut compat = COMPAT;
    if prefix {
        inner = Arc::new(
            RandomPrefixProvider::new(inner, UNIT, PREFIX, PREFIX_COMPAT.into())
                .await
                .unwrap(),
        );
        compat = PREFIX_COMPAT;
    }
    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        inner,
        scheduler,
        clock.clone(),
        UNIT,
    ));
    Stack {
        clock,
        first,
        set,
        scheduler,
        compat,
        ciphertext: wire + 8,
    }
}

impl Stack {
    fn request(&self, unit: u64, decrypt: bool) -> JoinHandle<Result<(), CryptoError>> {
        let top = self.scheduler.clone() as Arc<dyn CryptoProvider>;
        if decrypt {
            spawn_decrypt(top, self.compat, unit, self.ciphertext)
        } else {
            spawn_encrypt(top, self.compat, unit, UNIT)
        }
    }

    fn calls(&self) -> usize {
        self.first.encrypt_calls() + self.first.decrypt_calls()
    }
}

/// Both callers are coalesced into one batch, dispatched 40 ms into their
/// 100 ms budgets: the dispatcher's own deadline is 40 ms later, so each
/// caller leaves on its own timer while the failover RPC is still running.
#[tokio::test]
async fn scheduler_callers_leaving_at_their_deadline_return_the_last_endpoint_error() {
    for prefix in [false, true] {
        for decrypt in [false, true] {
            let stack = stack(
                prefix,
                true,
                SchedulerConfig {
                    target_items: 8,
                    max_wait: Duration::from_millis(40),
                    max_inflight_batches: 1,
                    ..SchedulerConfig::default()
                },
                None,
            )
            .await;
            let callers = [stack.request(1, decrypt), stack.request(2, decrypt)];
            settle().await;
            stack.clock.advance(Duration::from_millis(40));
            settle().await;
            assert_eq!(stack.calls(), 1, "prefix={prefix} decrypt={decrypt}");
            assert_eq!(stack.scheduler.stats().coalesced_batches_total(), 1);
            stack.clock.advance(DEADLINE - Duration::from_millis(40));
            settle().await;
            for caller in callers {
                assert_endpoint_error(finished(caller).await);
            }
            assert_eq!(
                stack.scheduler.stats().deadline_exceeded_total(),
                2,
                "prefix={prefix} decrypt={decrypt}: each expired caller counts once"
            );
            assert_eq!(stack.set.metrics().deadline_exceeded_total(), 0);
            assert_eq!(stack.set.endpoint_inflight()[1].1, 0, "RPC not abandoned");
        }
    }
}

/// The dispatcher's own timer (a separate clock) ends the call first: the
/// caller receives the endpoint's error before its own budget runs out, and
/// that is still a deadline, at the top of a pass (one endpoint) and for a
/// cut-off failover RPC.
#[tokio::test]
async fn a_dispatcher_deadline_reaching_a_scheduler_caller_is_counted_whatever_it_returns() {
    for failover in [false, true] {
        for decrypt in [false, true] {
            let endpoint_clock = Arc::new(ManualClock::new());
            let stack = stack(
                false,
                failover,
                SchedulerConfig {
                    target_items: 1,
                    ..SchedulerConfig::default()
                },
                Some(endpoint_clock.clone()),
            )
            .await;
            let caller = stack.request(1, decrypt);
            settle().await;
            assert_eq!(stack.calls(), 1);
            assert!(!caller.is_finished());
            endpoint_clock.advance(DEADLINE);
            settle().await;
            assert_endpoint_error(finished(caller).await);
            assert_eq!(stack.set.metrics().deadline_exceeded_total(), 1);
            assert_eq!(
                stack.scheduler.stats().deadline_exceeded_total(),
                1,
                "failover={failover} decrypt={decrypt}"
            );
        }
    }
}

/// One call of a scripted endpoint.
enum Step {
    Fail,
    Reject,
    Serve,
    Hang,
}

/// An endpoint that answers each encrypt call with the next step.
struct Scripted {
    inner: FakeCryptoProvider,
    steps: Mutex<VecDeque<Step>>,
}

#[async_trait]
impl CryptoProvider for Scripted {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.inner.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let step = self.steps.lock().unwrap().pop_front();
        match step.expect("unscripted call") {
            Step::Fail => Err(failure()),
            Step::Reject => Err(CryptoError::NonRetryableRequest(
                "one request of the batch is invalid".into(),
            )),
            Step::Serve => self.inner.encrypt_batch(context, items).await,
            Step::Hang => std::future::pending().await,
        }
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.inner.decrypt_batch(context, items).await
    }
}

/// The set sends a coalesced two-request batch as two RPCs of one item.
/// The first RPC fails and its retry succeeds; the second is still running
/// when both callers' budgets run out. Nothing has failed the RPC in
/// progress, so they leave with the deadline error, as the dispatcher
/// itself would.
#[tokio::test]
async fn scheduler_callers_report_only_the_dispatch_in_progress() {
    let clock = Arc::new(ManualClock::new());
    let only = Arc::new(Scripted {
        inner: FakeCryptoProvider::new(UNIT).with_max_batch(1, u64::from(UNIT)),
        steps: Mutex::new([Step::Fail, Step::Serve, Step::Hang].into()),
    });
    let set = set_of(
        vec![("only", only.clone())],
        DispatchConfig {
            retry: RetryPolicy {
                initial_delay: Duration::from_millis(10),
                max_delay: Duration::from_millis(10),
            },
            ..cfg()
        },
        clock.clone(),
    );
    let scheduler = Arc::new(BatchScheduler::new(
        set.clone(),
        SchedulerConfig {
            target_items: 8,
            max_wait: Duration::from_millis(40),
            max_inflight_batches: 1,
            ..SchedulerConfig::default()
        },
        clock.clone(),
    ));
    let callers = [
        spawn_encrypt(scheduler.clone(), COMPAT, 1, UNIT),
        spawn_encrypt(scheduler.clone(), COMPAT, 2, UNIT),
    ];
    settle().await;
    // Dispatch; the first RPC fails and backs off for at most 10 ms.
    clock.advance(Duration::from_millis(40));
    settle().await;
    clock.advance(Duration::from_millis(10));
    settle().await;
    assert!(
        only.steps.lock().unwrap().is_empty(),
        "the second RPC is not in flight"
    );
    clock.advance(DEADLINE - Duration::from_millis(50));
    settle().await;
    for caller in callers {
        assert_deadline_error(finished(caller).await);
    }
    assert_eq!(scheduler.stats().deadline_exceeded_total(), 2);
    assert_eq!(set.metrics().deadline_exceeded_total(), 0);
}

/// A request-specific rejection of a coalesced batch re-sends each request
/// alone. Each retry fails on the first endpoint and its failover never
/// answers: each caller leaves at its deadline with its own retry's
/// endpoint error.
#[tokio::test]
async fn scheduler_callers_resent_alone_report_their_own_dispatch() {
    let clock = Arc::new(ManualClock::new());
    let scripted = |steps: Vec<Step>| {
        Arc::new(Scripted {
            inner: FakeCryptoProvider::new(UNIT),
            steps: Mutex::new(steps.into()),
        })
    };
    let first = scripted(vec![Step::Reject, Step::Fail, Step::Fail]);
    let second = scripted(vec![Step::Hang, Step::Hang]);
    let set = set_of(
        vec![("first", first.clone()), ("second", second.clone())],
        cfg(),
        clock.clone(),
    );
    let scheduler = Arc::new(BatchScheduler::new(
        set.clone(),
        SchedulerConfig {
            target_items: 8,
            max_wait: Duration::from_millis(40),
            max_inflight_batches: 2,
            ..SchedulerConfig::default()
        },
        clock.clone(),
    ));
    let callers = [
        spawn_encrypt(scheduler.clone(), COMPAT, 1, UNIT),
        spawn_encrypt(scheduler.clone(), COMPAT, 2, UNIT),
    ];
    settle().await;
    clock.advance(Duration::from_millis(40));
    settle().await;
    assert!(first.steps.lock().unwrap().is_empty());
    assert!(second.steps.lock().unwrap().is_empty(), "both retries hang");
    assert_eq!(scheduler.stats().batches_total(), 3);
    clock.advance(DEADLINE - Duration::from_millis(40));
    settle().await;
    for caller in callers {
        assert_endpoint_error(finished(caller).await);
    }
    assert_eq!(scheduler.stats().deadline_exceeded_total(), 2);
}

// ---------- nested sets ----------

/// An inner set used as one peer of an outer set, with its own short
/// budget. Its expiry is that peer's failure.
fn nested(peer: Arc<FakeCryptoProvider>, clock: &Arc<ManualClock>) -> (Arc<EndpointSet>, Duration) {
    let budget = Duration::from_millis(10);
    let inner = set_of(
        vec![("peer", peer)],
        DispatchConfig {
            max_operation_time: Some(budget),
            ..cfg()
        },
        clock.clone(),
    );
    (inner, budget)
}

/// The inner set ends its own operation at its 10 ms budget with its
/// endpoint's error; the outer set receives that as the inner peer's
/// failure, fails over, and its own deadline then cuts the failover off.
#[tokio::test]
async fn a_nested_set_and_its_outer_set_count_their_own_operations() {
    let clock = Arc::new(ManualClock::new());
    let failing_peer = failing(UNIT);
    let (inner, budget) = nested(failing_peer.clone(), &clock);
    let outer = set_of(
        vec![
            ("inner", inner.clone()),
            ("slow", slow(UNIT, clock.clone())),
        ],
        cfg(),
        clock.clone(),
    );
    let task = spawn_encrypt(outer.clone(), COMPAT, 1, UNIT);
    settle().await;
    clock.advance(budget);
    settle().await;
    assert_eq!(inner.metrics().deadline_exceeded_total(), 1);
    assert_eq!(outer.metrics().failovers_total(), 1);
    assert!(!task.is_finished());
    clock.advance(DEADLINE - budget);
    settle().await;
    assert_endpoint_error(finished(task).await);
    assert_eq!(inner.metrics().deadline_exceeded_total(), 1);
    assert_eq!(outer.metrics().deadline_exceeded_total(), 1);
    assert_eq!(failing_peer.encrypt_calls(), 1);
}

/// Neither a peer's own expiry nor its deadline-shaped error is the
/// scheduler caller's deadline: the caller's budget has 90 ms left.
#[tokio::test]
async fn a_nested_peer_deadline_is_not_a_scheduler_callers_deadline() {
    for retry_safe in [true, false] {
        let clock = Arc::new(ManualClock::new());
        let (inner, budget) = nested(slow(UNIT, clock.clone()), &clock);
        let healthy = Arc::new(FakeCryptoProvider::new(UNIT));
        let outer = set_of(
            vec![("inner", inner.clone()), ("healthy", healthy.clone())],
            DispatchConfig {
                retry_safe,
                ..cfg()
            },
            clock.clone(),
        );
        let scheduler = Arc::new(BatchScheduler::new(
            outer.clone(),
            SchedulerConfig {
                target_items: 1,
                ..SchedulerConfig::default()
            },
            clock.clone(),
        ));
        let task = spawn_encrypt(scheduler.clone(), COMPAT, 1, UNIT);
        settle().await;
        clock.advance(budget);
        settle().await;
        let result = finished(task).await;
        assert_eq!(inner.metrics().deadline_exceeded_total(), 1);
        assert_eq!(outer.metrics().deadline_exceeded_total(), 0);
        assert_eq!(
            scheduler.stats().deadline_exceeded_total(),
            0,
            "retry_safe={retry_safe}: {result:?}"
        );
        if retry_safe {
            result.unwrap();
            assert_eq!(healthy.encrypt_calls(), 1);
        } else {
            // Not retry-safe: the peer's failure ends the operation.
            assert_deadline_error(result);
            assert_eq!(healthy.encrypt_calls(), 0);
            assert_eq!(outer.metrics().retries_refused_unsafe_total(), 1);
        }
    }
}
