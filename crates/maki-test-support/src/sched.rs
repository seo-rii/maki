//! `DeterministicScheduler` — a seeded, single-threaded interleaving executor
//! (SPEC §42). Each step polls one randomly chosen unfinished task, so a seed
//! fully determines the interleaving and failures are reproducible.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct DeterministicScheduler {
    tasks: Vec<Option<Pin<Box<dyn Future<Output = ()>>>>>,
    rng: ChaCha8Rng,
}

impl DeterministicScheduler {
    pub fn new(seed: u64) -> Self {
        Self {
            tasks: Vec::new(),
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    pub fn spawn(&mut self, fut: impl Future<Output = ()> + 'static) {
        self.tasks.push(Some(Box::pin(fut)));
    }

    /// Run until all tasks complete. Panics after an excessive poll budget
    /// (deadlock/livelock guard).
    pub fn run(&mut self) {
        assert!(
            self.run_bounded(5_000_000),
            "deterministic scheduler: tasks did not complete (deadlock?)"
        );
    }

    /// Poll up to `max_polls` times; returns true if all tasks completed.
    pub fn run_bounded(&mut self, max_polls: usize) -> bool {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        for _ in 0..max_polls {
            let unfinished: Vec<usize> = self
                .tasks
                .iter()
                .enumerate()
                .filter_map(|(i, t)| t.is_some().then_some(i))
                .collect();
            if unfinished.is_empty() {
                return true;
            }
            let pick = unfinished[self.rng.random_range(0..unfinished.len())];
            let task = self.tasks[pick].as_mut().unwrap();
            if let Poll::Ready(()) = task.as_mut().poll(&mut cx) {
                self.tasks[pick] = None;
            }
        }
        self.tasks.iter().all(|t| t.is_none())
    }
}

/// Yield once: returns Pending on the first poll, Ready on the next.
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
