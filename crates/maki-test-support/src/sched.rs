//! `DeterministicScheduler` — a seeded, single-threaded interleaving executor
//! (SPEC §42). Each step polls one randomly chosen *runnable* task, so a seed
//! fully determines the interleaving and failures are reproducible.
//!
//! Like a real executor, a task is polled again only after its waker fires
//! (or once when spawned). A future that returns `Pending` without arranging
//! a wake-up therefore stays parked here exactly as it would hang under
//! tokio: when no task is runnable but some are unfinished, the scheduler
//! has stalled. `run` panics on a stall; `run_bounded` returns `false`, which
//! is also how a test waits for a wake-up from outside the scheduler (for
//! example `ManualClock::advance`) before running again.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use parking_lot::Mutex;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Ids of the tasks whose waker fired since they were last polled. Ordered,
/// so the seeded choice among them is reproducible.
type ReadySet = Arc<Mutex<BTreeSet<u64>>>;

struct TaskWaker {
    id: u64,
    ready: ReadySet,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.lock().insert(self.id);
    }
}

struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
    waker: Waker,
}

enum Outcome {
    Completed,
    Stalled,
    BudgetExhausted,
}

pub struct DeterministicScheduler {
    tasks: BTreeMap<u64, Task>,
    next_id: u64,
    ready: ReadySet,
    rng: ChaCha8Rng,
}

impl DeterministicScheduler {
    pub fn new(seed: u64) -> Self {
        Self {
            tasks: BTreeMap::new(),
            next_id: 0,
            ready: ReadySet::default(),
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    /// Add a task; it is runnable until its first poll.
    pub fn spawn(&mut self, fut: impl Future<Output = ()> + 'static) {
        // Wakers can outlive their tasks, so an ID must never be reassigned.
        let id = self.next_id;
        self.next_id = id.checked_add(1).expect("scheduler task ID exhausted");
        let waker = Waker::from(Arc::new(TaskWaker {
            id,
            ready: self.ready.clone(),
        }));
        self.tasks.insert(
            id,
            Task {
                future: Box::pin(fut),
                waker,
            },
        );
        self.ready.lock().insert(id);
    }

    /// Unfinished tasks, runnable or parked.
    pub fn pending(&self) -> usize {
        self.tasks.len()
    }

    /// Run until all tasks complete. Panics if the tasks stall (unfinished,
    /// none woken: a lost wakeup, or a wait for an event nothing inside the
    /// scheduler will deliver) or exhaust the poll budget (livelock guard).
    pub fn run(&mut self) {
        const BUDGET: usize = 5_000_000;
        match self.drive(BUDGET) {
            Outcome::Completed => {}
            Outcome::Stalled => panic!(
                "deterministic scheduler stalled: {} unfinished task(s) returned Pending \
                 and nothing woke them (lost wakeup, or a wait for an event outside the \
                 scheduler)",
                self.pending()
            ),
            Outcome::BudgetExhausted => panic!(
                "deterministic scheduler: {} task(s) still runnable after {BUDGET} polls \
                 (livelock?)",
                self.pending()
            ),
        }
    }

    /// Poll up to `max_polls` times; returns true if all tasks completed.
    /// Returns `false` early once no task is runnable: the unfinished ones
    /// wait for a wake-up from outside (after which this may be called again).
    pub fn run_bounded(&mut self, max_polls: usize) -> bool {
        matches!(self.drive(max_polls), Outcome::Completed)
    }

    fn drive(&mut self, max_polls: usize) -> Outcome {
        for _ in 0..max_polls {
            let runnable: Vec<u64> = {
                let mut ready = self.ready.lock();
                // A finished task can still be woken by a stale waker clone.
                ready.retain(|id| self.tasks.contains_key(id));
                ready.iter().copied().collect()
            };
            if runnable.is_empty() {
                return if self.pending() == 0 {
                    Outcome::Completed
                } else {
                    Outcome::Stalled
                };
            }
            let pick = runnable[self.rng.random_range(0..runnable.len())];
            // Clear the flag before polling: a wake during the poll (such as
            // `yield_now`) makes the task runnable again.
            self.ready.lock().remove(&pick);
            let Task { future, waker } = self
                .tasks
                .get_mut(&pick)
                .expect("a runnable task is unfinished");
            if future
                .as_mut()
                .poll(&mut Context::from_waker(waker))
                .is_ready()
            {
                self.tasks.remove(&pick);
            }
        }
        if self.pending() == 0 {
            Outcome::Completed
        } else {
            Outcome::BudgetExhausted
        }
    }
}

/// Yield once: returns Pending on the first poll (waking itself, so the task
/// stays runnable), Ready on the next.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
