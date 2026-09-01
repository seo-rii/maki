//! Injectable time source so retry/backoff/circuit logic is testable with a
//! manual clock (SPEC §42 `ManualClock`).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Monotonic clock + sleep facility.
pub trait Clock: Send + Sync + 'static {
    /// Time since an arbitrary fixed epoch. Monotonic.
    fn now(&self) -> Duration;

    /// Completes after `duration` of *this clock's* time has elapsed.
    fn sleep(&self, duration: Duration) -> SleepFuture;
}

/// Real clock backed by `std::time::Instant` and `tokio::time::sleep`.
pub struct SystemClock {
    start: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}
