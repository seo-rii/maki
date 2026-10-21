use std::future::Future;
use std::time::{Duration, Instant};

/// Keep paused time under explicit test control while loopback IO is pending.
/// A wall-clock guard makes a missing server event fail instead of hanging.
pub async fn bounded<T>(future: impl Future<Output = T>) -> T {
    let started = Instant::now();
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = tokio::task::yield_now() => {
                assert!(started.elapsed() < Duration::from_secs(10),
                    "paused-time test made no bounded progress within 10 seconds");
            }
        }
    }
}
