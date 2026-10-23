//! Retry policy: exponential full jitter + endpoint-scoped retry budget
//! (SPEC §31–§32).

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::Rng;

use crate::clock::Clock;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

/// `delay = random(0, min(max_delay, initial_delay × 2^attempt))` (SPEC §31).
pub fn full_jitter_delay(policy: &RetryPolicy, attempt: u32, rng: &mut impl Rng) -> Duration {
    // Keep the exponent and sampling range wide enough for Duration's full
    // range. Saturating the factor to u32 stops growth at attempt 31 even
    // when the configured maximum has not yet been reached.
    let factor = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
    let cap_nanos = policy
        .initial_delay
        .as_nanos()
        .saturating_mul(factor)
        .min(policy.max_delay.as_nanos());
    let nanos = rng.random_range(0..=cap_nanos);
    // cap_nanos is bounded by a Duration, so its seconds always fit u64.
    Duration::new(
        (nanos / 1_000_000_000) as u64,
        (nanos % 1_000_000_000) as u32,
    )
}

#[derive(Debug, Clone)]
pub struct RetryBudgetConfig {
    /// Tokens earned per initial request (e.g. 0.20), using the supplied
    /// binary `f64` value without rounding it to a decimal fraction. Negative
    /// or non-finite ratios supplied directly to this API disable earning.
    pub retry_ratio: f64,
    /// Token cap.
    pub burst: u32,
    /// Probes per second allowed even with an empty budget (SPEC §32:
    /// "Even during complete endpoint failure, a low-rate recovery probe
    /// MUST continue").
    pub min_probe_per_sec: f64,
}

struct BudgetState {
    tokens: f64,
    // Low component of the compensated credit: tokens + compensation.
    compensation: f64,
    last_probe: Duration,
}

impl BudgetState {
    fn add_tokens(&mut self, delta: f64) {
        // TwoSum retains the rounding error of this addition. Add it to
        // the previous low component, then normalize the pair. Folding the
        // low component into delta first can lose it when spending a whole
        // token, granting a retry that the represented ratio has not earned.
        let sum = self.tokens + delta;
        let virtual_delta = sum - self.tokens;
        let error = (self.tokens - (sum - virtual_delta)) + (delta - virtual_delta);
        let correction = self.compensation + error;
        let total = sum + correction;
        self.compensation = correction - (total - sum);
        self.tokens = total;
    }

    fn has_tokens(&self, amount: f64) -> bool {
        // At an exact rounded boundary, a negative compensation means the
        // actual credit is still below it. Never round up eligibility.
        self.tokens > amount || (self.tokens == amount && self.compensation >= 0.0)
    }
}

/// Token-bucket retry budget.
pub struct RetryBudget {
    config: RetryBudgetConfig,
    probe_interval: Option<Duration>,
    clock: Arc<dyn Clock>,
    state: Mutex<BudgetState>,
}

impl RetryBudget {
    pub fn new(config: RetryBudgetConfig, clock: Arc<dyn Clock>) -> Self {
        let now = clock.now();
        // Direct library callers can bypass configuration validation. Invalid
        // or unrepresentable rates disable free probes; earned tokens still
        // work. Compute once, using the fallible conversion to avoid a panic
        // in the request path.
        let probe_interval = (config.min_probe_per_sec.is_finite()
            && config.min_probe_per_sec > 0.0)
            .then(|| Duration::try_from_secs_f64(1.0 / config.min_probe_per_sec).ok())
            .flatten()
            .filter(|interval| !interval.is_zero());
        Self {
            config,
            probe_interval,
            clock,
            state: Mutex::new(BudgetState {
                tokens: 0.0,
                compensation: 0.0,
                last_probe: now,
            }),
        }
    }

    /// Record an initial (non-retry) request: earns `retry_ratio` tokens.
    pub fn note_request(&self) {
        if !self.config.retry_ratio.is_finite() || self.config.retry_ratio <= 0.0 {
            return;
        }
        let mut state = self.state.lock();
        state.add_tokens(self.config.retry_ratio);
        let cap = f64::from(self.config.burst);
        if state.has_tokens(cap) {
            state.tokens = cap;
            // Clipped credit must not reappear after the bucket is spent.
            state.compensation = 0.0;
        }
    }

    /// May a retry be sent now? Consumes a token, or falls back to the
    /// minimum probe rate when the bucket is empty.
    pub fn allow_retry(&self) -> bool {
        let mut state = self.state.lock();
        if state.has_tokens(1.0) {
            state.add_tokens(-1.0);
            return true;
        }
        let Some(interval) = self.probe_interval else {
            return false;
        };
        let now = self.clock.now();
        if now.saturating_sub(state.last_probe) >= interval {
            state.last_probe = now;
            return true;
        }
        false
    }

    pub fn tokens(&self) -> f64 {
        self.state.lock().tokens
    }
}
