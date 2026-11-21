//! Randomized durability-oracle sequences — the Phase 0 gate (SPEC §42).
//!
//! Drives a trivial direct-write store over `CrashableBacking` and the
//! `ReferenceBlockModel` with the same random op stream, then checks every
//! observation (reads and post-crash content) against the model.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use maki_backing::{Backing, BackingFile};

use crate::crash_backing::CrashableBacking;
use crate::model::{OracleViolation, ReferenceBlockModel};

#[derive(Debug, Clone)]
pub struct SequenceConfig {
    pub num_units: u64,
    pub unit_size: usize,
    pub ops: usize,
}

fn fill_write_payload(data: &mut [u8], rng: &mut StdRng) {
    if let Some((stamp, rest)) = data.split_first_mut() {
        // Keep successive one-byte writes distinguishable from each other and from unwritten zeros.
        *stamp = stamp.wrapping_add(1).max(1);
        rng.fill_bytes(rest);
    }
}

/// Run one random op sequence; `Err` on any durability-oracle violation.
pub fn run_random_sequence(seed: u64, cfg: &SequenceConfig) -> Result<(), OracleViolation> {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
    let backing = CrashableBacking::new();
    let mut file = backing.open("data", true).expect("open");
    let total = cfg.num_units * cfg.unit_size as u64;
    file.set_len(total).expect("set_len");
    file.sync_data().expect("sync");
    backing.sync_dir("").expect("sync_dir");

    let mut model = ReferenceBlockModel::new(cfg.unit_size, cfg.num_units);
    // Generating position-sensitive data must not change the seeded operation or crash schedule.
    let mut payload_rng = StdRng::seed_from_u64(seed);
    let mut data = vec![0; cfg.unit_size];

    let read_unit = |file: &dyn BackingFile, unit: u64| -> Vec<u8> {
        let mut buf = vec![0u8; cfg.unit_size];
        file.read_at(unit * cfg.unit_size as u64, &mut buf)
            .expect("read");
        buf
    };

    for _ in 0..cfg.ops {
        let operation = rng.random_range(0..100u32);
        match operation {
            0..=64 => {
                let unit = rng.random_range(0..cfg.num_units);
                fill_write_payload(&mut data, &mut payload_rng);
                file.write_at(unit * cfg.unit_size as u64, &data)
                    .expect("write");
                if operation < 50 {
                    model.write(unit, &data);
                } else {
                    file.sync_data().expect("sync");
                    model.write_fua(unit, &data);
                }
            }
            // FLUSH
            65..=79 => {
                file.sync_data().expect("sync");
                model.flush();
            }
            // crash + oracle check on every unit; the crash killed the
            // process, so the rest of the sequence uses a new handle
            _ => {
                backing.crash(&mut rng);
                file = backing.open("data", false).expect("reopen");
                for unit in 0..cfg.num_units {
                    let actual = read_unit(file.as_ref(), unit);
                    model.crash_adopt(unit, &actual)?;
                }
            }
        }

        // Occasional live-view check: the process view must match exactly.
        if rng.random_bool(0.25) {
            let unit = rng.random_range(0..cfg.num_units);
            let actual = read_unit(file.as_ref(), unit);
            let expected = model.read(unit);
            if actual != expected {
                return Err(OracleViolation {
                    unit,
                    detail: format!(
                        "live view mismatch: got first-byte {:?}, expected {:?}",
                        actual.first(),
                        expected.first()
                    ),
                });
            }
        }
    }

    // Final live-view check on all units.
    for unit in 0..cfg.num_units {
        let actual = read_unit(file.as_ref(), unit);
        let expected = model.read(unit);
        if actual != expected {
            return Err(OracleViolation {
                unit,
                detail: "final live view mismatch".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_rejects_reordered_bytes_and_sectors_in_a_written_unit() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut data = vec![0; 4096];
        fill_write_payload(&mut data, &mut rng);
        let mut model = ReferenceBlockModel::new(data.len(), 1);
        model.write_fua(0, &data);
        for offset in [1, 256, 512] {
            let mut reordered = data.clone();
            reordered.rotate_left(offset);
            assert!(model.crash_adopt(0, &reordered).is_err());
        }
        model.crash_adopt(0, &data).unwrap();
    }
}
