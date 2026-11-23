//! `ReferenceBlockModel` — the durability oracle (SPEC §42).
//!
//! The model captures the *weakest allowed contract* of a crash-consistent
//! block store at crypto-unit granularity:
//!
//! - a unit never read/written is zeros,
//! - an acknowledged (non-FUA, non-flushed) write may, after a crash, surface
//!   as the new value, any earlier acknowledged-unflushed value, or the last
//!   durable value,
//! - after a successful FLUSH, everything acknowledged before it is durable,
//! - a FUA-successful write is durable,
//! - nothing else may ever appear (no torn units, no fabricated data).

use std::collections::HashMap;

/// Returned when observed post-crash content is not in the allowed set.
#[derive(Debug, thiserror::Error)]
#[error("durability oracle violation at unit {unit}: {detail}")]
pub struct OracleViolation {
    pub unit: u64,
    pub detail: String,
}

pub struct ReferenceBlockModel {
    unit_size: usize,
    num_units: u64,
    /// Durable content per unit; absent = zeros.
    durable: HashMap<u64, Vec<u8>>,
    /// Acknowledged-but-unflushed versions per unit, oldest first.
    pending: HashMap<u64, Vec<Vec<u8>>>,
}

impl ReferenceBlockModel {
    pub fn new(unit_size: usize, num_units: u64) -> Self {
        Self {
            unit_size,
            num_units,
            durable: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub fn unit_size(&self) -> usize {
        self.unit_size
    }

    pub fn num_units(&self) -> u64 {
        self.num_units
    }

    fn check_unit(&self, unit: u64, data: &[u8]) {
        assert!(unit < self.num_units, "unit {unit} out of range");
        assert_eq!(data.len(), self.unit_size, "unit-sized data required");
    }

    /// Acknowledge a normal write (volatile until FLUSH).
    pub fn write(&mut self, unit: u64, data: &[u8]) {
        self.check_unit(unit, data);
        self.pending.entry(unit).or_default().push(data.to_vec());
    }

    /// Acknowledge a FUA write: durable immediately.
    pub fn write_fua(&mut self, unit: u64, data: &[u8]) {
        self.check_unit(unit, data);
        self.durable.insert(unit, data.to_vec());
        self.pending.remove(&unit);
    }

    /// Acknowledge a FLUSH: every acknowledged write becomes durable.
    pub fn flush(&mut self) {
        for (unit, versions) in self.pending.drain() {
            if let Some(last) = versions.into_iter().last() {
                self.durable.insert(unit, last);
            }
        }
    }

    /// Current (pre-crash) view of a unit.
    pub fn read(&self, unit: u64) -> Vec<u8> {
        assert!(unit < self.num_units);
        if let Some(versions) = self.pending.get(&unit) {
            if let Some(last) = versions.last() {
                return last.clone();
            }
        }
        self.durable
            .get(&unit)
            .cloned()
            .unwrap_or_else(|| vec![0u8; self.unit_size])
    }

    /// All values this unit may legally hold immediately after a crash.
    pub fn allowed_after_crash(&self, unit: u64) -> Vec<Vec<u8>> {
        if unit >= self.num_units {
            return Vec::new();
        }
        let mut out = vec![self
            .durable
            .get(&unit)
            .cloned()
            .unwrap_or_else(|| vec![0u8; self.unit_size])];
        if let Some(versions) = self.pending.get(&unit) {
            for v in versions {
                if !out.contains(v) {
                    out.push(v.clone());
                }
            }
        }
        out
    }

    /// Check the observed post-crash content of `unit` against the allowed
    /// set, then adopt it as the new durable state.
    pub fn crash_adopt(&mut self, unit: u64, actual: &[u8]) -> Result<(), OracleViolation> {
        if unit >= self.num_units {
            return Err(OracleViolation {
                unit,
                detail: format!("unit outside volume of {} units", self.num_units),
            });
        }
        let matches_durable = match self.durable.get(&unit) {
            Some(durable) => durable == actual,
            None => actual.len() == self.unit_size && actual.iter().all(|&byte| byte == 0),
        };
        if !matches_durable
            && !self
                .pending
                .get(&unit)
                .is_some_and(|versions| versions.iter().any(|version| version == actual))
        {
            return Err(OracleViolation {
                unit,
                detail: format!(
                    "observed {} matches no durable or pending value; observed-prefix={:02x?}",
                    summarize(actual),
                    &actual[..actual.len().min(8)]
                ),
            });
        }
        if !matches_durable {
            self.durable.insert(unit, actual.to_vec());
        }
        self.pending.remove(&unit);
        Ok(())
    }
}

fn summarize(v: &[u8]) -> String {
    format!("[{} bytes, first={:?}]", v.len(), v.first())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_outside_the_volume_are_never_legal() {
        for count in [0, 1] {
            let mut model = ReferenceBlockModel::new(4, count);
            for invalid in [count, u64::MAX] {
                assert!(model.allowed_after_crash(invalid).is_empty());
                assert_eq!(
                    model.crash_adopt(invalid, &[0; 4]).unwrap_err().unit,
                    invalid
                );
                assert!(!model.durable.contains_key(&invalid));
            }
        }
    }
    #[test]
    fn adoption_checks_borrowed_history_and_preserves_it_on_rejection() {
        let mut model = ReferenceBlockModel::new(4, 1);
        assert!(model.crash_adopt(0, &[0; 3]).is_err());
        model.crash_adopt(0, &[0; 4]).unwrap();
        model.write_fua(0, &[1; 4]);
        for byte in [2, 2, 3] {
            model.write(0, &[byte; 4]);
        }
        assert!(model.crash_adopt(0, &[0; 4]).is_err());
        model.crash_adopt(0, &[2; 4]).unwrap();
        assert_eq!(model.allowed_after_crash(0), vec![vec![2; 4]]);
    }
}
