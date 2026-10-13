//! BUG-077: exponential full jitter reaches its actual configured cap.

use std::time::Duration;

use maki_crypto::retry::{full_jitter_delay, RetryPolicy};
use rand::{rngs::StdRng, SeedableRng};

fn samples(policy: &RetryPolicy, attempt: u32) -> Vec<Duration> {
    let mut rng = StdRng::seed_from_u64(77);
    (0..256)
        .map(|_| full_jitter_delay(policy, attempt, &mut rng))
        .collect()
}

#[test]
fn exponential_jitter_keeps_growing_after_attempt_31() {
    let policy = RetryPolicy {
        initial_delay: Duration::from_micros(1),
        max_delay: Duration::from_secs(3600),
    };
    let earlier_cap = policy.initial_delay * (1u32 << 31);
    let before = samples(&policy, 31);
    let after = samples(&policy, 32);
    assert!(before.iter().all(|delay| *delay <= earlier_cap));
    assert!(
        after.iter().any(|delay| *delay > earlier_cap),
        "attempt 32 must reach the newly available part of the full-jitter range"
    );
    assert!(after.iter().all(|delay| *delay <= policy.max_delay));
    assert_ne!(before, after);
    assert_eq!(after, samples(&policy, u32::MAX));
}

#[test]
fn early_attempts_remain_bounded_and_spread() {
    let policy = RetryPolicy {
        initial_delay: Duration::from_micros(1),
        max_delay: Duration::from_secs(3600),
    };
    for attempt in [0, 1, 16, 30, 31] {
        let values = samples(&policy, attempt);
        let cap = policy.initial_delay * (1u32 << attempt);
        assert!(values.iter().all(|delay| *delay <= cap));
        assert!(values.iter().any(|delay| *delay > cap / 2));
        assert!(values.iter().any(|delay| *delay < cap / 2));
    }
}

#[test]
fn a_zero_initial_delay_stays_zero_at_extreme_attempts() {
    let policy = RetryPolicy {
        initial_delay: Duration::ZERO,
        max_delay: Duration::MAX,
    };
    for attempt in [0, 31, 32, 127, 128, u32::MAX] {
        assert!(samples(&policy, attempt).iter().all(Duration::is_zero));
    }
}

#[test]
fn a_zero_maximum_delay_stays_zero() {
    let policy = RetryPolicy {
        initial_delay: Duration::MAX,
        max_delay: Duration::ZERO,
    };
    assert!(samples(&policy, u32::MAX).iter().all(Duration::is_zero));
}

#[test]
fn direct_library_callers_can_use_the_entire_duration_range() {
    let policy = RetryPolicy {
        initial_delay: Duration::from_nanos(1),
        max_delay: Duration::MAX,
    };
    let values = samples(&policy, u32::MAX);
    assert!(values.iter().all(|delay| *delay <= Duration::MAX));
    assert!(
        values
            .iter()
            .any(|delay| *delay > Duration::from_nanos(u64::MAX)),
        "a duration cap must not be narrowed to a u64 nanosecond count"
    );
    assert_eq!(values, samples(&policy, 128));
}

#[test]
fn large_initial_delays_saturate_without_wrapping() {
    let policy = RetryPolicy {
        initial_delay: Duration::MAX,
        max_delay: Duration::from_secs(3600),
    };
    let at_zero = samples(&policy, 0);
    assert_eq!(at_zero, samples(&policy, u32::MAX));
    assert!(at_zero.iter().all(|delay| *delay <= policy.max_delay));
    assert!(at_zero.iter().any(|delay| *delay > policy.max_delay / 2));
}
