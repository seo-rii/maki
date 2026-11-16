//! Regression tests: the test doubles in `maki-test-support` must be no more
//! permissive than the runtime or provider contract they stand in for. A
//! double that accepts what production refuses lets a test pass for code
//! that fails (or hangs) in production.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use maki_crypto::{
    CiphertextUnit, Clock, CryptoContext, CryptoError, CryptoProvider, ErrorClass, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::sched::{yield_now, DeterministicScheduler};
use maki_test_support::{FakeCryptoProvider, ManualClock};

const UNIT: u32 = 4096;

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xD0_0B1E),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

fn plaintexts(count: u64) -> Vec<PlaintextUnit> {
    (0..count)
        .map(|unit_index| PlaintextUnit {
            unit_index,
            data: SecretBuffer::from_vec(vec![unit_index as u8; UNIT as usize]),
        })
        .collect()
}

// ---------- DeterministicScheduler: wakers, not spurious polls ----------

/// Returns `Pending` once *without* arranging a wake-up, then `Ready`: the
/// classic lost wakeup of a hand-written lock, queue or notify. A real
/// executor never polls it again, so the task hangs.
struct LostWakeup {
    polled: bool,
}

impl Future for LostWakeup {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.polled {
            Poll::Ready(())
        } else {
            self.polled = true;
            Poll::Pending
        }
    }
}

#[test]
fn scheduler_does_not_complete_a_task_whose_wakeup_was_lost() {
    let mut sched = DeterministicScheduler::new(7);
    let done = Rc::new(Cell::new(false));
    {
        let done = done.clone();
        sched.spawn(async move {
            LostWakeup { polled: false }.await;
            done.set(true);
        });
    }
    assert!(
        !sched.run_bounded(1_000),
        "the scheduler completed a task whose only wake-up was lost"
    );
    assert!(!done.get(), "a never-woken task was polled again");
}

#[test]
#[should_panic(expected = "stalled")]
fn running_to_completion_reports_a_lost_wakeup_as_a_stall() {
    let mut sched = DeterministicScheduler::new(7);
    sched.spawn(async {
        LostWakeup { polled: false }.await;
    });
    sched.run();
}

/// A waker slot shared by a waiting task and the task that releases it.
#[derive(Default)]
struct Gate {
    open: Cell<bool>,
    waiter: RefCell<Option<Waker>>,
    polls: Cell<u32>,
}

struct WaitGate(Rc<Gate>);

impl Future for WaitGate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.polls.set(self.0.polls.get() + 1);
        if self.0.open.get() {
            Poll::Ready(())
        } else {
            *self.0.waiter.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A task is polled again only after its waker fires: exactly once to park
/// and once after the release, however long the releasing task runs first.
/// Every seed must complete (the wake-up is delivered) and none may poll
/// the parked task spuriously.
#[test]
fn a_parked_task_is_polled_only_after_its_waker_fires() {
    for seed in 0..64 {
        let mut sched = DeterministicScheduler::new(seed);
        let gate = Rc::new(Gate::default());
        sched.spawn(WaitGate(gate.clone()));
        {
            let gate = gate.clone();
            sched.spawn(async move {
                // Give the waiter every chance to be polled spuriously.
                while gate.polls.get() == 0 {
                    yield_now().await;
                }
                for _ in 0..32 {
                    yield_now().await;
                }
                gate.open.set(true);
                if let Some(waker) = gate.waiter.borrow_mut().take() {
                    waker.wake();
                }
            });
        }
        sched.run();
        assert_eq!(
            gate.polls.get(),
            2,
            "seed {seed}: the parked task was polled without a wake-up"
        );
    }
}

/// The same seed yields the same interleaving; different seeds explore
/// different ones.
#[test]
fn interleavings_are_reproducible_per_seed() {
    fn trace(seed: u64) -> Vec<u32> {
        let mut sched = DeterministicScheduler::new(seed);
        let log = Rc::new(RefCell::new(Vec::new()));
        for task in 0..4u32 {
            let log = log.clone();
            sched.spawn(async move {
                for _ in 0..8 {
                    log.borrow_mut().push(task);
                    yield_now().await;
                }
            });
        }
        sched.run();
        let trace = log.borrow().clone();
        trace
    }
    for seed in 0..16 {
        assert_eq!(trace(seed), trace(seed), "seed {seed}");
    }
    assert!(
        (1..16).any(|seed| trace(seed) != trace(0)),
        "every seed produced the same interleaving"
    );
}

// ---------- FakeCryptoProvider: the declared batch byte limit ----------

fn assert_refused_as_request<T>(result: Result<T, CryptoError>, what: &str) {
    match result {
        Ok(_) => panic!("{what} was accepted"),
        Err(error) => assert_eq!(
            error.class(),
            ErrorClass::NonRetryableRequest,
            "{what}: {error}"
        ),
    }
}

/// `batch.max_bytes` is the plaintext bytes one batch may carry (SPEC §16,
/// `BatchCapability`). A vendor endpoint refuses a larger request, so a
/// caller that over-packs a batch by bytes must fail against the fake too.
#[test]
fn the_fake_refuses_an_encrypt_batch_over_its_declared_byte_limit() {
    let provider = FakeCryptoProvider::new(UNIT).with_max_batch(128, 2 * UNIT as u64);
    let caps = block_on(provider.capabilities()).unwrap();
    assert_eq!(caps.batch.max_bytes, 2 * UNIT as u64);
    let at_limit = block_on(provider.encrypt_batch(&context(), &plaintexts(2)));
    assert_eq!(at_limit.unwrap().len(), 2, "a batch at the limit is valid");
    assert_refused_as_request(
        block_on(provider.encrypt_batch(&context(), &plaintexts(3))),
        "a 3-unit encrypt batch under a 2-unit byte limit",
    );
}

/// A decrypt batch is measured by the plaintext it produces (one unit per
/// item), the way the dispatcher sizes decrypt chunks.
#[test]
fn the_fake_refuses_a_decrypt_batch_whose_plaintext_exceeds_the_byte_limit() {
    let unlimited = FakeCryptoProvider::new(UNIT);
    let ciphertexts: Vec<CiphertextUnit> =
        block_on(unlimited.encrypt_batch(&context(), &plaintexts(3))).unwrap();
    let provider = FakeCryptoProvider::new(UNIT).with_max_batch(128, 2 * UNIT as u64);
    let at_limit = block_on(provider.decrypt_batch(&context(), &ciphertexts[..2]));
    assert_eq!(at_limit.unwrap().len(), 2, "a batch at the limit is valid");
    assert_refused_as_request(
        block_on(provider.decrypt_batch(&context(), &ciphertexts)),
        "a 3-unit decrypt batch under a 2-unit byte limit",
    );
}

// ---------- ManualClock: reproducible wake order ----------

/// Sleepers that reach their deadline in one `advance` are woken in
/// (deadline, registration) order. Under tokio the wake order is the run
/// order, so a wake order that varies between runs (a `HashMap`'s) makes
/// the same test interleave the woken tasks differently each time.
#[test]
fn manual_clock_wakes_due_sleepers_in_deadline_then_registration_order() {
    struct Recorder {
        id: usize,
        log: Arc<Mutex<Vec<usize>>>,
    }
    impl Wake for Recorder {
        fn wake(self: Arc<Self>) {
            self.log.lock().unwrap().push(self.id);
        }
    }

    let seconds = [3u64, 1, 2, 1, 3, 2, 1, 2, 3, 1, 2, 3];
    let mut expected: Vec<usize> = (0..seconds.len()).collect();
    expected.sort_by_key(|id| (seconds[*id], *id));
    for round in 0..8 {
        let clock = ManualClock::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sleeps: Vec<_> = seconds
            .iter()
            .map(|s| clock.sleep(Duration::from_secs(*s)))
            .collect();
        for (id, sleep) in sleeps.iter_mut().enumerate() {
            let waker = Waker::from(Arc::new(Recorder {
                id,
                log: log.clone(),
            }));
            assert!(sleep
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
        }
        clock.advance(Duration::from_secs(3));
        assert_eq!(*log.lock().unwrap(), expected, "round {round}");
    }
}
