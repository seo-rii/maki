//! Manually advanced clock (SPEC §42 `ManualClock`).

use std::collections::HashMap;
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
    sleepers: HashMap<u64, (Duration, Option<Waker>)>,
}

/// A `Clock` whose time only moves when `advance`/`set` is called.
/// Sleep futures complete exactly when their deadline is reached.
#[derive(Clone, Default)]
pub struct ManualClock {
    inner: Arc<Mutex<Inner>>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&self, d: Duration) {
        let wakers: Vec<Waker> = {
            let mut inner = self.inner.lock();
            inner.now += d;
            let now = inner.now;
            inner
                .sleepers
                .values_mut()
                .filter(|(deadline, _)| *deadline <= now)
                .filter_map(|(_, w)| w.take())
                .collect()
        };
        for w in wakers {
            w.wake();
        }
    }

    pub fn set(&self, t: Duration) {
        let cur = self.inner.lock().now;
        if t > cur {
            self.advance(t - cur);
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
        inner.sleepers.insert(id, (deadline, None));
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
        if inner.now >= self.deadline {
            inner.sleepers.remove(&self.id);
            Poll::Ready(())
        } else {
            if let Some(entry) = inner.sleepers.get_mut(&self.id) {
                entry.1 = Some(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        self.inner.lock().sleepers.remove(&self.id);
    }
}
