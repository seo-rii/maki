//! Per-endpoint circuit breaker (SPEC §33):
//! `CLOSED → OPEN → HALF_OPEN → CLOSED/OPEN`, open interval doubling up to
//! `open_max`.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::clock::Clock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub open_initial: Duration,
    pub open_max: Duration,
    pub half_open_max_requests: u32,
    pub success_threshold: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 8,
            open_initial: Duration::from_secs(1),
            open_max: Duration::from_secs(30),
            half_open_max_requests: 2,
            success_threshold: 2,
        }
    }
}

struct Inner {
    state: CircuitState,
    consecutive_failures: u32,
    open_until: Duration,
    open_duration: Duration,
    half_open_started: u32,
    half_open_successes: u32,
    /// Probes that finished (either way) since the circuit went half-open.
    half_open_completed: u32,
}

pub struct CircuitBreaker {
    config: BreakerConfig,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig, clock: Arc<dyn Clock>) -> Self {
        let open_duration = config.open_initial;
        Self {
            config,
            clock,
            inner: Mutex::new(Inner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                open_until: Duration::ZERO,
                open_duration,
                half_open_started: 0,
                half_open_successes: 0,
                half_open_completed: 0,
            }),
        }
    }

    pub fn state(&self) -> CircuitState {
        self.inner.lock().state
    }

    /// Would a request be admitted, without consuming a half-open slot?
    /// `half_open_max_requests` bounds probes *in flight*; a completed
    /// probe returns its slot (C-07: `success_threshold` above the slot
    /// count used to wedge the circuit half-open forever).
    pub fn would_allow(&self) -> bool {
        let inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => self.clock.now() >= inner.open_until,
            CircuitState::HalfOpen => {
                inner.half_open_started - inner.half_open_completed
                    < self.config.half_open_max_requests
            }
        }
    }

    /// Admit a request. In HALF_OPEN this consumes one of the limited probe
    /// slots until the probe completes.
    pub fn allow(&self) -> bool {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if self.clock.now() >= inner.open_until {
                    inner.state = CircuitState::HalfOpen;
                    inner.half_open_started = 1;
                    inner.half_open_completed = 0;
                    inner.half_open_successes = 0;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if inner.half_open_started - inner.half_open_completed
                    < self.config.half_open_max_requests
                {
                    inner.half_open_started += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn on_success(&self) {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => inner.consecutive_failures = 0,
            CircuitState::HalfOpen => {
                inner.half_open_successes += 1;
                inner.half_open_completed += 1;
                if inner.half_open_successes >= self.config.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.consecutive_failures = 0;
                    inner.open_duration = self.config.open_initial;
                }
            }
            CircuitState::Open => {}
        }
    }

    pub fn on_failure(&self) {
        let mut inner = self.inner.lock();
        let now = self.clock.now();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures += 1;
                if inner.consecutive_failures >= self.config.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.open_until = now + inner.open_duration;
                }
            }
            CircuitState::HalfOpen => {
                inner.open_duration = (inner.open_duration * 2).min(self.config.open_max);
                inner.state = CircuitState::Open;
                inner.open_until = now + inner.open_duration;
                inner.half_open_started = 0;
                inner.half_open_completed = 0;
            }
            CircuitState::Open => {}
        }
    }
}
