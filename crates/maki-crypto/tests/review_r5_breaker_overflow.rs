//! R5-013: breaker durations come from configuration without an upper
//! bound, and the transitions used `Duration` `+`/`*`, which panic on
//! overflow. A huge `open_initial` or `open_max` must mean "open for a very
//! long time", never a panic inside the dispatcher.

use std::sync::Arc;
use std::time::Duration;

use maki_crypto::breaker::{BreakerConfig, CircuitBreaker, CircuitState};
use maki_crypto::Clock;
use maki_test_support::ManualClock;

fn breaker(clock: &Arc<ManualClock>, open_initial: Duration) -> CircuitBreaker {
    CircuitBreaker::new(
        BreakerConfig {
            failure_threshold: 1,
            open_initial,
            open_max: Duration::MAX,
            half_open_max_requests: 1,
            success_threshold: 1,
        },
        clock.clone() as Arc<dyn Clock>,
    )
}

#[test]
fn opening_with_a_huge_duration_saturates() {
    let clock = Arc::new(ManualClock::new());
    clock.advance(Duration::from_secs(10));
    let breaker = breaker(&clock, Duration::MAX - Duration::from_secs(5));
    assert!(breaker.allow());
    breaker.on_failure();
    assert_eq!(breaker.state(), CircuitState::Open);
    clock.advance(Duration::from_secs(365 * 24 * 3600));
    assert!(!breaker.would_allow(), "still open a year later");
}

#[test]
fn doubling_a_huge_duration_after_a_failed_probe_saturates() {
    let clock = Arc::new(ManualClock::new());
    let open = Duration::MAX / 2 + Duration::from_secs(1);
    let breaker = breaker(&clock, open);
    assert!(breaker.allow());
    breaker.on_failure();
    clock.advance(open);
    assert!(breaker.allow(), "half-open probe");
    breaker.on_failure();
    assert_eq!(breaker.state(), CircuitState::Open);
    assert!(!breaker.would_allow());
}
