//! Regression tests: the test doubles in `maki-test-support` must be no more
//! permissive than the runtime or provider contract they stand in for. A
//! double that accepts what production refuses lets a test pass for code
//! that fails (or hangs) in production.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use maki_test_support::sched::{yield_now, DeterministicScheduler};

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
