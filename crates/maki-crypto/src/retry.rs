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
    let factor = 2u32.saturating_pow(attempt.min(31));
    let cap = policy
        .max_delay
        .min(policy.initial_delay.saturating_mul(factor));
    Duration::from_nanos(rng.random_range(0..=cap.as_nanos().min(u64::MAX as u128) as u64))
}

#[derive(Debug, Clone)]
pub struct RetryBudgetConfig {
    /// Tokens earned per initial request (e.g. 0.20).
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
    last_probe: Duration,
}

/// Token-bucket retry budget.
pub struct RetryBudget {
    config: RetryBudgetConfig,
    clock: Arc<dyn Clock>,
    state: Mutex<BudgetState>,
}

impl RetryBudget {
    pub fn new(config: RetryBudgetConfig, clock: Arc<dyn Clock>) -> Self {
        let now = clock.now();
        Self {
            config,
            clock,
            state: Mutex::new(BudgetState {
                tokens: 0.0,
                last_probe: now,
            }),
        }
    }

    /// Record an initial (non-retry) request: earns `retry_ratio` tokens.
    pub fn note_request(&self) {
        let mut state = self.state.lock();
        state.tokens = (state.tokens + self.config.retry_ratio).min(self.config.burst as f64);
    }

    /// May a retry be sent now? Consumes a token, or falls back to the
    /// minimum probe rate when the bucket is empty.
    pub fn allow_retry(&self) -> bool {
        let mut state = self.state.lock();
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            return true;
        }
        if self.config.min_probe_per_sec <= 0.0 {
            return false;
        }
        let interval = Duration::from_secs_f64(1.0 / self.config.min_probe_per_sec);
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
