//! Deep offline check (`maki check --deep`, `maki-check --deep`; review
//! M-018).
//!
//! The fast checker in `maki-format` looks at the superblock, the shard
//! catalog, allocation-map sizes and file presence. That is not enough to
//! justify "check passed" for a volume that holds data: it says nothing
//! about checkpoint state, the journal, or the slots themselves. The deep
//! check reuses the *real* recovery scanner and the *real* slot reader, so
//! anything that would refuse attach or return EIO at runtime is reported
//! here, and nothing the runtime accepts is reported as an error.
//!
//! The volume lock is taken for the duration: a check must never race a
//! live daemon.

use std::sync::Arc;

use maki_backing::Backing;
use maki_format::ab::AbStore;
use maki_format::canary::KeyCanary;
use maki_format::checker::CheckReport;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::layout;

use crate::error::CoreError;
use crate::journal::effective_segment_size;
use crate::recovery::{
    acquire_lock, load_checkpoint_state, load_durable_mark, load_superblock, scan_journal,
    JournalRepair, RecoveryError,
};
use crate::store::SlotStore;

/// Cap on individually reported slot errors (the count is always exact).
const MAX_SLOT_ERRORS: usize = 64;

/// Run the fast checks, then verify checkpoint state, the key canary, the
/// durable mark, the whole journal (read-only, with the recovery scanner),
/// and every allocated slot.
pub fn deep_check(backing: Arc<dyn Backing>, segment_size: u64) -> Result<CheckReport, CoreError> {
    let mut report = maki_format::checker::check_volume(backing.as_ref())?;
    report.info.push("deep check: enabled".to_string());

    let _lock = match acquire_lock(&backing) {
        Ok(lock) => lock,
        Err(RecoveryError::AlreadyAttached) => {
            report.errors.push(
                "volume lock is held (daemon attached); detach before running a deep check"
                    .to_string(),
            );
            return Ok(report);
        }
        Err(RecoveryError::Io(e)) => return Err(CoreError::Io(e)),
        Err(e) => {
            report.errors.push(e.to_string());
            return Ok(report);
        }
    };

    let superblock = match load_superblock(&backing) {
        Ok(sb) => sb,
        Err(_) => return Ok(report), // already reported by the fast check
    };

    // Checkpoint state: both copies inspected, at least one required.
    let ck_ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    match ck_ab.side_generations::<CheckpointState>(backing.as_ref()) {
        Ok((a, b)) => {
            report.info.push(format!(
                "checkpoint state: copy a {}, copy b {}",
                describe_side(a),
                describe_side(b)
            ));
            if a.is_none() && b.is_some() || b.is_none() && a.is_some() {
                report.warnings.push(
                    "checkpoint state: one copy is invalid (A/B fallback in use)".to_string(),
                );
            }
        }
        Err(e) => report.errors.push(format!("checkpoint state: {e}")),
    }
    let checkpoint_sequence = match load_checkpoint_state(&backing) {
        Ok(state) => {
            report.info.push(format!(
                "checkpoint sequence: {}",
                state.checkpoint_sequence
            ));
            state.checkpoint_sequence
        }
        Err(RecoveryError::Io(e)) => return Err(CoreError::Io(e)),
        Err(e) => {
            report.errors.push(e.to_string());
            return Ok(report);
        }
    };

    // Key canary: informational (bound on first attach).
    let canary_ab = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B);
    match canary_ab.load::<KeyCanary>(backing.as_ref()) {
        Ok(Some(canary)) if canary.volume_uuid == superblock.volume_uuid => {
            report.info.push("key canary: present".to_string());
        }
        Ok(Some(_)) => report
            .errors
            .push("key canary belongs to a different volume".to_string()),
        Ok(None) => report.warnings.push(
            "key canary: absent (bound on the next attach; a volume with data needs an \
             integrity-capable provider for that)"
                .to_string(),
        ),
        Err(e) => report.errors.push(format!("key canary: {e}")),
    }

    // Durable mark.
    match load_durable_mark(&backing) {
        Ok(Some(mark)) => report.info.push(format!(
            "durable mark: segment {} durable to byte {}",
            mark.segment_index, mark.durable_size
        )),
        Ok(None) => report
            .info
            .push("durable mark: absent (heuristic torn-tail classification)".to_string()),
        Err(RecoveryError::Io(e)) => return Err(CoreError::Io(e)),
        Err(e) => report.errors.push(format!("durable mark: {e}")),
    }

    // Journal, exactly as recovery would see it.
    match scan_journal(
        &backing,
        &superblock,
        checkpoint_sequence,
        effective_segment_size(segment_size),
    ) {
        Ok(scan) => {
            report.info.push(format!(
                "journal: {} segment(s), {} record(s) newer than the checkpoint, durable sequence {}",
                scan.segments.len(),
                scan.replay.len(),
                scan.durable_sequence
            ));
            for repair in &scan.repairs {
                match repair {
                    JournalRepair::Discard { path } => report.info.push(format!(
                        "journal: {path} never completed creation; recovery would discard it"
                    )),
                    JournalRepair::Truncate { path, len } => report.info.push(format!(
                        "journal: {path} has a torn tail; recovery would truncate it to {len} bytes"
                    )),
                }
            }
        }
        Err(RecoveryError::Io(e)) => return Err(CoreError::Io(e)),
        Err(e) => report.errors.push(format!("journal: {e}")),
    }

    // Every allocated slot must read back exactly as the engine would read
    // it: valid header, matching unit, intact ciphertext CRC.
    match SlotStore::open(backing.clone(), superblock.geometry.clone()) {
        Ok(store) => {
            let mut checked = 0u64;
            let mut bad = 0u64;
            for unit in store.allocated_units() {
                checked += 1;
                if let Err(e) = store.read_slot(unit) {
                    bad += 1;
                    if bad as usize <= MAX_SLOT_ERRORS {
                        report.errors.push(format!("slot: {e}"));
                    }
                }
            }
            if bad as usize > MAX_SLOT_ERRORS {
                report.errors.push(format!(
                    "slot: {} more invalid slot(s) not listed",
                    bad - MAX_SLOT_ERRORS as u64
                ));
            }
            report
                .info
                .push(format!("slots: {checked} allocated, {bad} invalid"));
            // Slots the loaded allocation copy did not list but that hold
            // a header for their unit: the store repaired them at open and
            // the next checkpoint persists the map, but it means a copy of
            // the allocation metadata was lost.
            let repaired = store.repaired_allocations();
            if !repaired.is_empty() {
                report.warnings.push(format!(
                    "slots: {} unit(s) hold data their newest valid allocation map copy does \
                     not list (repaired from slot headers; the next checkpoint persists the map)",
                    repaired.len()
                ));
            }
        }
        Err(CoreError::Io(e)) => return Err(CoreError::Io(e)),
        Err(e) => report.errors.push(format!("slot store: {e}")),
    }

    Ok(report)
}

fn describe_side(generation: Option<u64>) -> String {
    match generation {
        Some(g) => format!("valid (generation {g})"),
        None => "invalid or absent".to_string(),
    }
}
