//! BUG-157: fractional retry credits survive accumulation and consumption.

use std::{sync::Arc, time::Duration};

use maki_crypto::retry::{RetryBudget, RetryBudgetConfig};
use maki_test_support::ManualClock;

fn budget(ratio: f64, burst: u32) -> RetryBudget {
    RetryBudget::new(
        RetryBudgetConfig {
            retry_ratio: ratio,
            burst,
            min_probe_per_sec: 0.0,
        },
        Arc::new(ManualClock::new()),
    )
}

#[test]
fn decimal_tenth_earns_one_retry_after_ten_requests() {
    let budget = budget(0.1, 16);
    for _ in 0..10 {
        budget.note_request();
    }
    assert!(budget.allow_retry(), "ten tenths earn one retry");
    assert!(!budget.allow_retry(), "only one retry was earned");
}

#[test]
fn default_ratio_earns_two_retries_after_ten_requests() {
    let budget = budget(0.2, 16);
    for _ in 0..10 {
        budget.note_request();
    }
    assert!(budget.allow_retry());
    assert!(budget.allow_retry(), "ten fifths earn two retries");
    assert!(!budget.allow_retry(), "only two retries were earned");
}

#[test]
fn represented_ratio_deficit_survives_multiple_token_spends() {
    // These f64 values are below their decimal spellings. Retain that
    // deficit even when the visible token sum rounds to an integer.
    for (ratio, earned) in [(0.3, 2), (0.7, 6)] {
        let budget = budget(ratio, 16);
        for _ in 0..10 {
            budget.note_request();
        }
        for _ in 0..earned {
            assert!(budget.allow_retry());
        }
        assert!(
            !budget.allow_retry(),
            "ratio {ratio} is below its next token"
        );
        budget.note_request();
        assert!(budget.allow_retry(), "the eleventh request earns the token");
        assert!(!budget.allow_retry());
    }
}

#[test]
fn fractional_credit_survives_interleaved_earning_and_spending() {
    for (ratio, requests_per_retry) in [(0.1, 10), (0.2, 5), (0.25, 4), (0.01, 100)] {
        let budget = budget(ratio, 4);
        let mut retries = 0;
        for requests in 1..=10_000 {
            budget.note_request();
            if budget.allow_retry() {
                retries += 1;
            }
            assert_eq!(retries, requests / requests_per_retry, "ratio {ratio}");
        }
    }
}

#[test]
fn below_threshold_credit_never_borrows_a_retry() {
    for (ratio, requests) in [
        (1.0_f64.next_down(), 1),
        (0.1_f64.next_down(), 10),
        (1.0 / 3.0, 3),
    ] {
        let budget = budget(ratio, 4);
        for _ in 0..requests {
            budget.note_request();
        }
        assert!(
            !budget.allow_retry(),
            "ratio {ratio} has not earned a token"
        );
        budget.note_request();
        assert!(budget.allow_retry());
        assert!(!budget.allow_retry());
    }
}

#[test]
fn burst_clipping_discards_excess_credit_before_earning_again() {
    let budget = budget(0.3, 2);
    for _ in 0..100 {
        budget.note_request();
    }
    assert_eq!(budget.tokens(), 2.0);
    assert!(budget.allow_retry());
    assert!(budget.allow_retry());
    assert!(!budget.allow_retry());
    for _ in 0..3 {
        budget.note_request();
    }
    assert!(!budget.allow_retry(), "clipped credit cannot reappear");
    budget.note_request();
    assert!(budget.allow_retry());
    assert!(!budget.allow_retry());
}

#[test]
fn zero_burst_discards_even_large_earned_credit() {
    for ratio in [0.0, 0.1, f64::MAX] {
        let budget = budget(ratio, 0);
        for _ in 0..10 {
            budget.note_request();
        }
        assert_eq!(budget.tokens(), 0.0);
        assert!(!budget.allow_retry());
    }
}

#[test]
fn large_finite_credit_is_capped_and_remains_spendable() {
    let budget = budget(f64::MAX, 2);
    for _ in 0..2 {
        budget.note_request();
        assert_eq!(budget.tokens(), 2.0);
        assert!(budget.allow_retry());
        assert!(budget.allow_retry());
        assert!(!budget.allow_retry());
    }
}

#[test]
fn invalid_direct_api_ratios_disable_earning_but_preserve_probes() {
    for ratio in [0.0, -0.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let clock = Arc::new(ManualClock::new());
        let budget = RetryBudget::new(
            RetryBudgetConfig {
                retry_ratio: ratio,
                burst: 2,
                min_probe_per_sec: 1.0,
            },
            clock.clone(),
        );
        for _ in 0..10 {
            budget.note_request();
        }
        assert_eq!(budget.tokens(), 0.0, "ratio {ratio}");
        assert!(!budget.allow_retry());
        clock.advance(Duration::from_secs(1));
        assert!(
            budget.allow_retry(),
            "minimum probe is independent of credit"
        );
        assert!(!budget.allow_retry());
    }
}
