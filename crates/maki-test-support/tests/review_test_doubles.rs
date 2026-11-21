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

use maki_backing::Backing;
use maki_crypto::{
    Capability, CiphertextUnit, Clock, CryptoContext, CryptoError, CryptoProvider, ErrorClass,
    PlaintextUnit, SecretBuffer,
};
use maki_test_support::sched::{yield_now, DeterministicScheduler};
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};

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

#[test]
fn a_finished_tasks_waker_cannot_wake_a_new_task() {
    let mut sched = DeterministicScheduler::new(7);
    let first = Rc::new(Gate::default());
    sched.spawn(WaitGate(first.clone()));
    assert!(!sched.run_bounded(1));
    let stale = first.waiter.borrow_mut().take().unwrap();
    first.open.set(true);
    stale.wake_by_ref();
    assert!(sched.run_bounded(1));

    let next = Rc::new(Gate::default());
    sched.spawn(WaitGate(next.clone()));
    assert!(!sched.run_bounded(1));
    stale.wake();
    assert!(!sched.run_bounded(1));
    assert_eq!(next.polls.get(), 1);
    assert_eq!(sched.pending(), 1);

    next.open.set(true);
    next.waiter.borrow_mut().take().unwrap().wake();
    assert!(sched.run_bounded(1));
    assert_eq!(sched.pending(), 0);
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

#[test]
fn concurrent_sets_only_reach_the_requested_deadline() {
    const THREADS: usize = 8;
    const ROUNDS: u64 = 256;
    let clock = ManualClock::new();
    let barrier = std::sync::Barrier::new(THREADS + 1);
    let mut greatest_overshoot = Duration::ZERO;
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for round in 1..=ROUNDS {
                    barrier.wait();
                    clock.set(Duration::from_secs(round));
                    barrier.wait();
                }
            });
        }
        for round in 1..=ROUNDS {
            barrier.wait();
            barrier.wait();
            let target = Duration::from_secs(round);
            greatest_overshoot = greatest_overshoot.max(clock.now().saturating_sub(target));
        }
    });
    assert_eq!(greatest_overshoot, Duration::ZERO);
    assert_eq!(clock.now(), Duration::from_secs(ROUNDS));
}

// ---------- FakeCryptoProvider: no framing check without integrity ----------

fn damaged_ciphertexts(original: &CiphertextUnit) -> Vec<(&'static str, CiphertextUnit)> {
    let size = original.data.len();
    let with = |data: Vec<u8>| CiphertextUnit {
        unit_index: original.unit_index,
        data,
    };
    let mut header = original.data.clone();
    header[0] ^= 0xFF;
    let mut body = original.data.clone();
    body[size / 2] ^= 0xFF;
    vec![
        ("zeroed", with(vec![0; size])),
        ("overwritten", with(vec![0xA5; size])),
        ("header-damaged", with(header)),
        ("body-damaged", with(body)),
    ]
}

/// With integrity off the fake stands in for an unauthenticated cipher
/// (`local-aes-xts`): every ciphertext of the right length decrypts, a
/// zeroed or overwritten unit to garbage, without an error. Refusing it on
/// the fake's own framing would let a test of "damaged data is never
/// served" pass for an unauthenticated profile even if the engine's slot
/// checks were missing.
#[test]
fn an_unauthenticated_fake_decrypts_any_well_sized_ciphertext() {
    let provider = FakeCryptoProvider::new(UNIT).with_integrity_check(false);
    let caps = block_on(provider.capabilities()).unwrap();
    assert_eq!(caps.integrity, Capability::Absent);
    let original = block_on(provider.encrypt_batch(&context(), &plaintexts(1)))
        .unwrap()
        .remove(0);
    assert_eq!(original.data.len(), caps.max_ciphertext_size as usize);
    for (what, damaged) in damaged_ciphertexts(&original) {
        let plaintext = block_on(provider.decrypt_batch(&context(), &[damaged]))
            .unwrap_or_else(|error| panic!("{what} ciphertext was refused: {error}"));
        assert_eq!(plaintext.len(), 1, "{what}");
        assert_eq!(plaintext[0].data.len(), UNIT as usize, "{what}");
    }
    // Like XTS, a ciphertext that is not exactly one unit is still refused.
    for len in [0, original.data.len() - 1, original.data.len() + 1] {
        let wrong = CiphertextUnit {
            unit_index: 0,
            data: vec![0; len],
        };
        let result = block_on(provider.decrypt_batch(&context(), &[wrong]));
        assert!(
            matches!(result, Err(CryptoError::Integrity(_))),
            "a {len}-byte ciphertext was not refused: {:?}",
            result.map(|units| units.len())
        );
    }
}

/// The authenticated default refuses the same damage.
#[test]
fn an_authenticated_fake_refuses_damaged_ciphertext() {
    let provider = FakeCryptoProvider::new(UNIT);
    let original = block_on(provider.encrypt_batch(&context(), &plaintexts(1)))
        .unwrap()
        .remove(0);
    for (what, damaged) in damaged_ciphertexts(&original) {
        let result = block_on(provider.decrypt_batch(&context(), &[damaged]));
        assert!(
            matches!(result, Err(CryptoError::Integrity(_))),
            "{what} ciphertext was not refused: {:?}",
            result.map(|units| units.len())
        );
    }
}

// ---------- CrashableBacking: zero-length allocation ----------

/// The crash simulator uses the trait's default `allocate_range`, which
/// must agree with every other backing that `allocate_range(_, 0)` is a
/// no-op: it neither fails nor extends the file to the offset.
#[test]
fn zero_length_allocation_does_not_change_a_crashable_file() {
    let backing = CrashableBacking::new();
    let file = backing.open("f", true).unwrap();
    for offset in [0, 4096] {
        file.allocate_range(offset, 0).unwrap();
        assert_eq!(file.len().unwrap(), 0, "allocate_range({offset}, 0)");
    }
}

// ---------- CrashableBacking: POSIX namespace rules ----------

#[path = "../../maki-backing/tests/common/namespace_parity.rs"]
mod namespace_parity;

/// The crash simulator runs the namespace table `MemBacking` and Linux
/// `FileBacking` run (maki-backing `review_mem_backing_parity.rs`): a
/// directory name is neither a lock file nor unlinked as a file (EISDIR).
#[test]
fn crashable_backing_namespace_follows_posix_path_rules() {
    namespace_parity::check("CrashableBacking", || Box::new(CrashableBacking::new()));
}

#[test]
fn torn_overwrite_preserves_the_earlier_pending_suffix() {
    for (offset, keep, expected) in [
        (1, 0, &b"ABCDEFGH"[..]),
        (1, 2, b"AxyDEFGH"),
        (10, 0, b"ABCDEFGH"),
    ] {
        let backing = CrashableBacking::new().with_tearing(1);
        let file = backing.process().open("sample", true).unwrap();
        file.write_at(0, b"ABCDEFGH").unwrap();
        file.write_at(offset, b"xyz").unwrap();
        backing.crash_keep_torn_prefix("sample", keep);
        let recovered = backing.process().open("sample", false).unwrap();
        let mut data = vec![0; recovered.len().unwrap() as usize];
        recovered.read_at(0, &mut data).unwrap();
        assert_eq!(data, expected);
    }
}

#[test]
fn a_new_crash_backing_lock_has_an_ordinary_file_name() {
    let backing = CrashableBacking::new();
    let live = backing.process();
    let guard = live.try_lock("lock").unwrap();
    assert_eq!(live.list("").unwrap(), ["lock"]);
    assert!(live.try_lock("lock").is_err());
    assert_eq!(live.open("lock", false).unwrap().len().unwrap(), 0);
    drop(guard);
    live.sync_dir("").unwrap();
    backing.crash_all_lost();
    let recovered = backing.process();
    assert!(recovered.exists("lock").unwrap());
    drop(recovered.try_lock("lock").unwrap());
    drop(recovered.try_lock("unsynced").unwrap());
    backing.crash_all_lost();
    assert!(!backing.process().exists("unsynced").unwrap());
}
