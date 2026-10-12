use maki_crypto::retry::{RetryBudget, RetryBudgetConfig};
use maki_test_support::ManualClock;
use std::{sync::Arc, time::Duration};

#[test]
fn invalid_and_unrepresentable_library_probe_rates_never_panic_or_probe() {
    for rate in [
        1e-20,
        f64::MIN_POSITIVE,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        0.0,
        -1.0,
    ] {
        let clock = Arc::new(ManualClock::new());
        let budget = RetryBudget::new(
            RetryBudgetConfig {
                retry_ratio: 1.0,
                burst: 1,
                min_probe_per_sec: rate,
            },
            clock.clone(),
        );
        assert!(!budget.allow_retry(), "rate {rate}");
        clock.advance(Duration::from_secs(1000));
        assert!(
            !budget.allow_retry(),
            "invalid rates cannot bypass the retry budget: {rate}"
        );
        budget.note_request();
        assert!(budget.allow_retry(), "earned tokens still work: {rate}");
        assert!(!budget.allow_retry());
    }
}

#[test]
fn valid_probe_interval_is_observed_without_drift() {
    let clock = Arc::new(ManualClock::new());
    let budget = RetryBudget::new(
        RetryBudgetConfig {
            retry_ratio: 0.0,
            burst: 1,
            min_probe_per_sec: 0.25,
        },
        clock.clone(),
    );
    clock.advance(Duration::from_secs(3));
    assert!(!budget.allow_retry());
    clock.advance(Duration::from_secs(1));
    assert!(budget.allow_retry());
    assert!(!budget.allow_retry());
    clock.advance(Duration::from_secs(4));
    assert!(budget.allow_retry());
}
