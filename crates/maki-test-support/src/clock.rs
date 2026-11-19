//! Manually advanced clock (SPEC §42 `ManualClock`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use parking_lot::Mutex;

use maki_crypto::clock::{Clock, SleepFuture};

#[derive(Default)]
struct Inner {
    now: Duration,
    next_id: u64,
    /// Keyed by (deadline, registration id), so due sleepers are woken in
    /// one reproducible order.
    sleepers: BTreeMap<(Duration, u64), Option<Waker>>,
}

/// A `Clock` whose time only moves when `advance`/`set` is called.
/// Sleep futures complete exactly when their deadline is reached. Sleepers
/// that become due in one `advance` are woken by deadline, then in the
/// order they were created, so the run order of the woken tasks is the same
/// on every run.
#[derive(Clone, Default)]
pub struct ManualClock {
    inner: Arc<Mutex<Inner>>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&self, d: Duration) {
        self.update_time(|now| now + d);
    }

    pub fn set(&self, t: Duration) {
        self.update_time(|now| now.max(t));
    }

    fn update_time(&self, next: impl FnOnce(Duration) -> Duration) {
        let wakers: Vec<Waker> = {
            let mut inner = self.inner.lock();
            let now = next(inner.now);
            if now == inner.now {
                return;
            }
            inner.now = now;
            inner
                .sleepers
                .range_mut(..=(now, u64::MAX))
                .filter_map(|(_, waker)| waker.take())
                .collect()
        };
        for w in wakers {
            w.wake();
        }
    }

    /// Number of currently parked sleepers (diagnostics).
    pub fn sleeper_count(&self) -> usize {
        self.inner.lock().sleepers.len()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        self.inner.lock().now
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        let mut inner = self.inner.lock();
        let id = inner.next_id;
        inner.next_id += 1;
        let deadline = inner.now + duration;
        inner.sleepers.insert((deadline, id), None);
        drop(inner);
        Box::pin(ManualSleep {
            inner: self.inner.clone(),
            id,
            deadline,
        })
    }
}

struct ManualSleep {
    inner: Arc<Mutex<Inner>>,
    id: u64,
    deadline: Duration,
}

impl Future for ManualSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.lock();
        let key = (self.deadline, self.id);
        if inner.now >= self.deadline {
            inner.sleepers.remove(&key);
            Poll::Ready(())
        } else {
            if let Some(waker) = inner.sleepers.get_mut(&key) {
                *waker = Some(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        self.inner.lock().sleepers.remove(&(self.deadline, self.id));
    }
}
