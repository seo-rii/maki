//! Fixed-memory latency histogram. 32 subdivisions per power of two bound
//! quantile overestimation by 3.125%, without retaining one sample per I/O.

use std::time::Duration;

use serde::Serialize;

const SUBDIVISIONS: usize = 32;

pub struct Latencies {
    buckets: [u64; 64 * SUBDIVISIONS],
    count: u64,
    zeroes: u64,
    sum_ns: u128,
    max_ns: u64,
}

#[derive(Serialize)]
pub struct LatencyReport {
    pub samples: u64,
    pub mean_us: f64,
    pub p50_upper_us: f64,
    pub p95_upper_us: f64,
    pub p99_upper_us: f64,
    pub max_us: f64,
}

impl Latencies {
    pub fn new() -> Self {
        Self {
            buckets: [0; 64 * SUBDIVISIONS],
            count: 0,
            zeroes: 0,
            sum_ns: 0,
            max_ns: 0,
        }
    }

    pub fn record(&mut self, duration: Duration) {
        let ns = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.count += 1;
        self.sum_ns += ns as u128;
        self.max_ns = self.max_ns.max(ns);
        if ns == 0 {
            self.zeroes += 1;
            return;
        }
        let exponent = (63 - ns.leading_zeros()) as usize;
        let shift = exponent.saturating_sub(5);
        let subdivision = ((ns - (1u64 << exponent)) >> shift) as usize;
        self.buckets[exponent * SUBDIVISIONS + subdivision] += 1;
    }

    fn percentile(&self, percent: u64) -> u64 {
        let rank = (self.count as u128 * percent as u128).div_ceil(100) as u64;
        let mut count = self.zeroes;
        if count >= rank {
            return 0;
        }
        for (index, samples) in self.buckets.iter().enumerate() {
            count += samples;
            if count >= rank {
                let exponent = index / SUBDIVISIONS;
                let subdivision = index % SUBDIVISIONS;
                let upper = (1u128 << exponent)
                    + (((subdivision + 1) as u128) << exponent.saturating_sub(5))
                    - 1;
                return upper.min(self.max_ns as u128) as u64;
            }
        }
        self.max_ns
    }

    pub fn report(&self) -> LatencyReport {
        LatencyReport {
            samples: self.count,
            mean_us: self.sum_ns as f64 / self.count.max(1) as f64 / 1000.0,
            p50_upper_us: self.percentile(50) as f64 / 1000.0,
            p95_upper_us: self.percentile(95) as f64 / 1000.0,
            p99_upper_us: self.percentile(99) as f64 / 1000.0,
            max_us: self.max_ns as f64 / 1000.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_bounds_cover_exact_ranks_across_bucket_edges() {
        let mut values = vec![0, 1, 2, 31, 32, 63, 64, 65, u64::MAX];
        for exponent in 6..64 {
            let value = 1u64 << exponent;
            values.extend([value - 1, value, value + 1]);
        }
        values.sort_unstable();
        let mut histogram = Latencies::new();
        for value in &values {
            histogram.record(Duration::from_nanos(*value));
        }
        for percent in 1..=100 {
            let index = (values.len() * percent as usize).div_ceil(100) - 1;
            let exact = values[index];
            let upper = histogram.percentile(percent);
            assert!(upper >= exact, "{percent}: {upper} < {exact}");
            assert!(
                upper as u128 * 32 <= exact as u128 * 33,
                "{percent}: {upper} exceeds the 3.125% bound for {exact}"
            );
        }
    }

    #[test]
    fn empty_zero_and_repeated_samples_have_finite_consistent_reports() {
        let mut histogram = Latencies::new();
        assert_eq!(histogram.report().mean_us, 0.0);
        assert_eq!(histogram.percentile(99), 0);
        histogram.record(Duration::ZERO);
        for _ in 0..99 {
            histogram.record(Duration::from_micros(10));
        }
        let report = histogram.report();
        assert_eq!(report.samples, 100);
        assert_eq!(report.mean_us, 9.9);
        assert_eq!(report.p50_upper_us, 10.0);
        assert_eq!(report.p99_upper_us, 10.0);
        assert_eq!(report.max_us, 10.0);
    }
}
