//! Randomized durability-oracle sequences — the Phase 0 gate (SPEC §42).
//!
//! Drives a trivial direct-write store over `CrashableBacking` and the
//! `ReferenceBlockModel` with the same random op stream, then checks every
//! observation (reads and post-crash content) against the model.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_backing::{Backing, BackingFile};

use crate::crash_backing::CrashableBacking;
use crate::model::{OracleViolation, ReferenceBlockModel};

#[derive(Debug, Clone)]
pub struct SequenceConfig {
    pub num_units: u64,
    pub unit_size: usize,
    pub ops: usize,
}

/// Run one random op sequence; `Err` on any durability-oracle violation.
pub fn run_random_sequence(seed: u64, cfg: &SequenceConfig) -> Result<(), OracleViolation> {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
    let backing = CrashableBacking::new();
    let file = backing.open("data", true).expect("open");
    let total = cfg.num_units * cfg.unit_size as u64;
    file.set_len(total).expect("set_len");
    file.sync_data().expect("sync");
    backing.sync_dir("").expect("sync_dir");

    let mut model = ReferenceBlockModel::new(cfg.unit_size, cfg.num_units);
    let mut stamp: u8 = 0;
    let mut next_stamp = || {
        stamp = stamp.wrapping_add(1);
        if stamp == 0 {
            stamp = 1;
        }
        stamp
    };

    let read_unit = |file: &dyn BackingFile, unit: u64| -> Vec<u8> {
        let mut buf = vec![0u8; cfg.unit_size];
        file.read_at(unit * cfg.unit_size as u64, &mut buf)
            .expect("read");
        buf
    };

    for _ in 0..cfg.ops {
        match rng.random_range(0..100u32) {
            // normal write
            0..=49 => {
                let unit = rng.random_range(0..cfg.num_units);
                let data = vec![next_stamp(); cfg.unit_size];
                file.write_at(unit * cfg.unit_size as u64, &data)
                    .expect("write");
                model.write(unit, &data);
            }
            // FUA write
            50..=64 => {
                let unit = rng.random_range(0..cfg.num_units);
                let data = vec![next_stamp(); cfg.unit_size];
                file.write_at(unit * cfg.unit_size as u64, &data)
                    .expect("write");
                file.sync_data().expect("sync");
                model.write_fua(unit, &data);
            }
            // FLUSH
            65..=79 => {
                file.sync_data().expect("sync");
                model.flush();
            }
            // crash + oracle check on every unit
            _ => {
                backing.crash(&mut rng);
                let file = backing.open("data", false).expect("reopen");
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
