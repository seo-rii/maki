//! The ciphertext-level volume: journal + overlay + slot store + checkpoint
//! (SPEC §23–§27). Phase 4's engine layers crypto, RMW, and per-unit
//! concurrency on top of this.
//!
//! Overlay/journal ordering rule: the overlay's durable boundary is advanced
//! (`promote`) after *every* journal operation that can move
//! `durable_sequence` — including an automatic segment roll inside `append`
//! — and always *before* a newer version of a unit is published. Publishing
//! first would supersede a version that just became durable, and a
//! checkpoint at that boundary would then delete its journal segment without
//! ever copying it into a slot.

use std::sync::Arc;

use maki_backing::{Backing, VolumeLock};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::layout;
use maki_format::superblock::Superblock;

use crate::error::CoreError;
use crate::fp;
use crate::journal::{effective_segment_size, JournalWriter};
use crate::overlay::Overlay;
use crate::recovery::{recover_bounded, Recovered, RecoveryError};
use crate::store::{CheckpointSlotPlan, SlotRead, SlotStore};

#[derive(Debug, Clone)]
pub struct VolumeOptions {
    pub journal_segment_size: u64,
}

impl Default for VolumeOptions {
    fn default() -> Self {
        Self {
            journal_segment_size: 256 << 20,
        }
    }
}

pub struct Volume {
    backing: Arc<dyn Backing>,
    _lock: Box<dyn VolumeLock>,
    superblock: Superblock,
    journal: JournalWriter,
    store: SlotStore,
    overlay: Overlay,
    ck_ab: AbStore,
    ck_state: CheckpointState,
}

/// A fixed checkpoint horizon whose slot destinations have been captured
/// under the volume lock. Its fields are private so only `Volume` can finish
/// a plan it prepared.
pub(crate) struct PreparedCheckpoint {
    base_checkpoint: u64,
    horizon: u64,
    allow_discard: bool,
    items: Vec<(u64, Arc<crate::overlay::OverlayVersion>)>,
    slots: CheckpointSlotPlan,
}

pub(crate) struct CompletedCheckpoint(PreparedCheckpoint);

impl PreparedCheckpoint {
    /// Write and sync only immutable slot data. Allocation metadata,
    /// checkpoint state, journal reclamation, and overlay retirement remain
    /// for `Volume::finish_checkpoint` under the volume lock.
    pub(crate) fn execute(self) -> Result<CompletedCheckpoint, CoreError> {
        let mut slot_index = 0;
        for (_, version) in &self.items {
            if self.allow_discard && version.ciphertext.is_empty() {
                continue;
            }
            fp("checkpoint.slot_write")?;
            self.slots
                .write(slot_index, version.sequence, &version.ciphertext)?;
            slot_index += 1;
        }
        self.slots.sync_shards()?;
        self.slots.validate_reservation_barriers()?;
        Ok(CompletedCheckpoint(self))
    }
}

impl Volume {
    /// Run recovery (SPEC §27) and return a ready volume.
    pub fn recover(
        backing: Arc<dyn Backing>,
        options: VolumeOptions,
    ) -> Result<Self, RecoveryError> {
        let segment_size = effective_segment_size(options.journal_segment_size);
        let Recovered {
            lock,
            superblock,
            mut store,
            checkpoint_state,
            durable_sequence,
            durable_proof,
            next_segment_index,
            segments,
            replay,
        } = recover_bounded(&backing, segment_size)?;

        let mut journal = JournalWriter::resume(
            backing.clone(),
            superblock.volume_uuid,
            segment_size,
            durable_sequence,
            next_segment_index,
            segments,
            durable_proof,
        );
        journal.allow_covered_holes_below(checkpoint_state.checkpoint_sequence);

        // Bounded recovery checkpoints every surviving record before it
        // returns, so attach normally receives an empty replay. Keep this
        // construction for the public/full-replay recovery contract and as
        // a defensive invariant if another recovery mode is added.
        let mut overlay = Overlay::new();
        for record in replay {
            overlay.publish(record.unit_index, record.sequence, record.payload);
        }
        overlay.promote(durable_sequence);

        store.schedule_reclamation();

        let volume = Self {
            backing,
            _lock: lock,
            superblock,
            journal,
            store,
            overlay,
            ck_ab: AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B),
            ck_state: checkpoint_state,
        };
        volume.sanitize();
        Ok(volume)
    }

    pub fn backing(&self) -> &Arc<dyn Backing> {
        &self.backing
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn checkpoint_sequence(&self) -> u64 {
        self.ck_state.checkpoint_sequence
    }

    pub fn journal_durable_sequence(&self) -> u64 {
        self.journal.durable_sequence()
    }

    pub fn journal_appended_sequence(&self) -> u64 {
        self.journal.appended_sequence()
    }

    pub fn journal_pending_bytes(&self) -> u64 {
        self.journal.pending_bytes()
    }

    /// A journal sync failed and its bytes have not been rewritten and
    /// synced since: no barrier can succeed until they are (F01).
    pub fn journal_writeback_uncertain(&self) -> bool {
        self.journal.writeback_uncertain()
    }

    /// Journal segment syncs that failed since attach.
    pub fn journal_sync_failures(&self) -> u64 {
        self.journal.sync_failures()
    }

    /// Bytes of journal on disk (all segments).
    pub fn journal_total_bytes(&self) -> u64 {
        self.journal.total_bytes()
    }

    /// Exact bytes appending records of the given on-disk lengths would add
    /// to [`journal_total_bytes`], including any new segment headers a roll
    /// creates (review R08). Journal admission uses this so the hard limit
    /// accounts for rolls, not only record payloads.
    pub fn journal_append_footprint(&self, record_lens: impl IntoIterator<Item = u64>) -> u64 {
        self.journal.append_footprint(record_lens)
    }

    pub fn journal_segment_count(&self) -> usize {
        self.journal.segment_count()
    }

    /// Sealed segments the checkpoint already covers but that are still on
    /// disk (reclaimable by any checkpoint, even one with nothing new).
    pub fn journal_covered_segment_count(&self) -> usize {
        self.journal
            .covered_segment_count(self.ck_state.checkpoint_sequence)
    }

    pub fn journal_active_segment_path(&self) -> Option<String> {
        self.journal
            .active_segment_index()
            .map(layout::journal_segment)
    }

    /// Path of the first segment holding records newer than the checkpoint.
    pub fn journal_first_uncheckpointed_segment_path(&self) -> Option<String> {
        self.journal
            .first_uncovered_segment_index(self.ck_state.checkpoint_sequence)
            .map(layout::journal_segment)
    }

    pub fn overlay_len(&self) -> usize {
        self.overlay.len()
    }

    pub fn overlay_bytes(&self) -> u64 {
        self.overlay.bytes()
    }

    /// Sum of the overlay's latest versions; `2 *` this is the overlay's
    /// eventual charge once every version has a durable copy (R4-005).
    pub fn overlay_latest_bytes(&self) -> u64 {
        self.overlay.latest_bytes()
    }

    pub fn supports_discard(&self) -> bool {
        self.store.supports_discard()
    }

    /// Refuse service when an independent freshness authority no longer
    /// names this backing session. This must also guard in-memory overlay and
    /// plaintext-cache paths, which otherwise perform no backing read.
    pub fn check_freshness(&self) -> Result<(), CoreError> {
        self.backing.check_freshness()?;
        Ok(())
    }

    pub(crate) fn has_pending_reclamation(&self) -> bool {
        self.store.has_pending_reclamation()
    }

    /// True when no write has ever been acknowledged or applied: no
    /// checkpoint, no journal records, no shard. Used by the attach layer to
    /// decide whether binding a crypto identity to the volume is safe.
    pub fn is_pristine(&self) -> bool {
        self.ck_state.checkpoint_sequence == 0
            && self.journal.durable_sequence() == 0
            && self.journal.appended_sequence() == 0
            && self.overlay.is_empty()
            && self.store.shard_count() == 0
    }

    /// Some unit that currently holds ciphertext (overlay first, then the
    /// slots), for key probing on volumes without a canary.
    pub fn first_ciphertext_unit(&self) -> Result<Option<(u64, Vec<u8>)>, CoreError> {
        let overlay_unit = if self.supports_discard() {
            self.overlay.first_nonempty_unit()
        } else {
            self.overlay.first_unit()
        };
        if let Some(unit) = overlay_unit {
            return Ok(self.read_ct(unit)?.map(|(_, data)| (unit, data)));
        }
        // A live overlay tombstone can hide the first stored allocation.
        // Keep searching without checkpointing or changing the volume.
        for unit in self.store.allocated_units() {
            if let Some((_, data)) = self.read_ct(unit)? {
                return Ok(Some((unit, data)));
            }
        }
        Ok(None)
    }

    /// Journal a ciphertext write; publish to the overlay on success.
    /// With `fua`, the record is made durable and verified before returning
    /// (SPEC §24).
    pub fn write_ct(&mut self, unit: u64, ciphertext: &[u8], fua: bool) -> Result<u64, CoreError> {
        self.check_freshness()?;
        // Counter refusal must precede physical reservation and its barrier,
        // including an exhausted segment index when this append would roll.
        self.journal.check_append(ciphertext.len())?;
        if ciphertext.len() > self.superblock.geometry.max_ciphertext_size as usize {
            return Err(CoreError::Corrupt(format!(
                "ciphertext {} exceeds max {}",
                ciphertext.len(),
                self.superblock.geometry.max_ciphertext_size
            )));
        }
        // Reserve the checkpoint destination before the journal makes this
        // version visible or durable. This closes the free-space sample race
        // for slot data: an admitted record always has physical completion
        // space even if another filesystem user consumes every free byte.
        self.store.reserve_slot(unit)?;
        let appended = self.journal.append(unit, ciphertext);
        // An automatic roll inside `append` may have advanced the durable
        // boundary (even when the append itself failed). Promote *before*
        // publishing, so a just-durable previous version of this unit is
        // captured rather than superseded.
        self.overlay.promote(self.journal.durable_sequence());
        let sequence = appended?;
        // The record is in the journal now, so it must be visible: a later
        // barrier (or recovery) would surface it anyway. Publish before the
        // FUA sync so a sync failure never leaves the live view behind the
        // on-disk journal.
        self.overlay.publish(unit, sequence, ciphertext.to_vec());
        self.overlay.promote(self.journal.durable_sequence());
        if fua {
            let sync = self.journal.sync();
            self.overlay.promote(self.journal.durable_sequence());
            let durable = sync?;
            if durable < sequence {
                return Err(CoreError::Durability(format!(
                    "FUA verify failed: durable {durable} < sequence {sequence}"
                )));
            }
        }
        self.sanitize();
        Ok(sequence)
    }

    /// Journal a v3 logical discard without creating or reserving storage for
    /// a unit that is already zero.
    pub fn discard_ct(&mut self, unit: u64, fua: bool) -> Result<u64, CoreError> {
        self.check_freshness()?;
        if !self.supports_discard() {
            return Err(CoreError::Invalid(
                "discard requires a v3 discard-enabled volume".into(),
            ));
        }
        if unit >= self.superblock.geometry.num_units() {
            return Err(CoreError::Invalid(format!("unit {unit} beyond the device")));
        }
        if let Some(version) = self.overlay.get(unit) {
            if version.ciphertext.is_empty() {
                let sequence = version.sequence;
                if fua {
                    let durable = self.journal.sync()?;
                    self.overlay.promote(durable);
                    if durable < sequence {
                        return Err(CoreError::Durability(format!(
                            "discard FUA verify failed: durable {durable} < sequence {sequence}"
                        )));
                    }
                }
                self.sanitize();
                return Ok(sequence);
            }
        } else if self.reclaim_unwritten(unit)? {
            // Only a header proving the unit unwritten skips the tombstone;
            // a damaged slot is retired by one rather than refused (R5-012).
            return Ok(self.journal.appended_sequence());
        }
        if self.journal.next_sequence() == u64::MAX {
            return Err(CoreError::Corrupt("journal sequence exhausted".into()));
        }
        let appended = self.journal.append(unit, &[]);
        self.overlay.promote(self.journal.durable_sequence());
        let sequence = appended?;
        self.overlay.publish(unit, sequence, Vec::new());
        self.overlay.promote(self.journal.durable_sequence());
        if fua {
            let sync = self.journal.sync();
            self.overlay.promote(self.journal.durable_sequence());
            let durable = sync?;
            if durable < sequence {
                return Err(CoreError::Durability(format!(
                    "discard FUA verify failed: durable {durable} < sequence {sequence}"
                )));
            }
        }
        self.sanitize();
        Ok(sequence)
    }

    /// Skip a zero-only TRIM's journal record while retaining its physical
    /// release hint. A volatile overlay tombstone must not expose the older
    /// durable write's reservation to reclamation. Header errors still take
    /// the normal tombstone path so damaged units can be retired (R5-012).
    pub(crate) fn reclaim_unwritten(&mut self, unit: u64) -> Result<bool, CoreError> {
        self.check_freshness()?;
        if let Some(version) = self.overlay.get(unit) {
            return Ok(version.ciphertext.is_empty());
        }
        if !matches!(self.store.slot_sequence(unit), Ok(None)) {
            return Ok(false);
        }
        self.store.reclaim_unwritten(unit)?;
        Ok(true)
    }

    /// FLUSH barrier (SPEC §25): everything appended becomes durable.
    pub fn flush(&mut self) -> Result<(), CoreError> {
        self.check_freshness()?;
        let durable = self.journal.sync()?;
        self.overlay.promote(durable);
        self.sanitize();
        Ok(())
    }

    /// The write sequence of a unit's current version without reading its
    /// payload (overlay first, then the slot header); `None` = unwritten
    /// zeros. Under the same volume lock this equals the sequence `read_ct`
    /// would return, so a plaintext-cache entry keyed by it is current
    /// (R4-006).
    pub fn current_sequence(&self, unit: u64) -> Result<Option<u64>, CoreError> {
        self.check_freshness()?;
        if let Some(v) = self.overlay.get(unit) {
            if self.supports_discard() && v.ciphertext.is_empty() {
                return Ok(None);
            }
            return Ok(Some(v.sequence));
        }
        self.store.slot_sequence(unit)
    }

    /// Read one unit's ciphertext: overlay first, then slots.
    /// `None` = unwritten zeros.
    pub fn read_ct(&self, unit: u64) -> Result<Option<(u64, Vec<u8>)>, CoreError> {
        self.check_freshness()?;
        if let Some(v) = self.overlay.get(unit) {
            if self.supports_discard() && v.ciphertext.is_empty() {
                return Ok(None);
            }
            return Ok(Some((v.sequence, v.ciphertext.clone())));
        }
        match self.store.read_slot(unit)? {
            SlotRead::Zero => Ok(None),
            SlotRead::Ciphertext {
                write_sequence,
                data,
            } => Ok(Some((write_sequence, data))),
        }
    }

    /// Checkpoint (SPEC §26). Consumes only durable journal records;
    /// `checkpoint_sequence <= durable_sequence` always.
    pub fn checkpoint(&mut self) -> Result<u64, CoreError> {
        let prepared = self.prepare_checkpoint()?;
        let completed = prepared.execute()?;
        self.finish_checkpoint(completed)
    }

    /// Capture a fixed durable horizon and immutable slot-I/O targets. The
    /// caller may execute the returned plan without holding the volume lock;
    /// publication is deferred until `finish_checkpoint`.
    pub(crate) fn prepare_checkpoint(&mut self) -> Result<PreparedCheckpoint, CoreError> {
        let durable = self.journal.durable_sequence();
        // Never rely on callers having promoted after the last boundary
        // move: the checkpointable set is derived here, from the journal's
        // own durable boundary.
        self.overlay.promote(durable);
        let base_checkpoint = self.ck_state.checkpoint_sequence;
        let allow_discard = self.supports_discard();
        let items = if durable <= base_checkpoint {
            Vec::new()
        } else {
            self.overlay.collect_durable_shared(durable)
        };
        let slots =
            self.store
                .checkpoint_slot_plan(items.iter().filter_map(|(unit, version)| {
                    (!allow_discard || !version.ciphertext.is_empty()).then_some(*unit)
                }))?;
        Ok(PreparedCheckpoint {
            base_checkpoint,
            horizon: durable.max(base_checkpoint),
            allow_discard,
            items,
            slots,
        })
    }

    /// Publish a completed fixed-horizon slot plan. The checkpoint gate in
    /// the engine ensures plans do not overlap; the base check also refuses
    /// accidental stale-plan publication by another in-crate caller.
    pub(crate) fn finish_checkpoint(
        &mut self,
        completed: CompletedCheckpoint,
    ) -> Result<u64, CoreError> {
        // A foreground reservation may have failed fsync while the plan's
        // slot writes ran without this lock, clearing their dirty bits.
        // Recheck under the volume lock before publishing any metadata.
        completed.0.slots.validate_reservation_barriers()?;
        let PreparedCheckpoint {
            base_checkpoint,
            horizon,
            allow_discard,
            items,
            slots: _,
        } = completed.0;
        if self.ck_state.checkpoint_sequence != base_checkpoint {
            return Err(CoreError::Durability(format!(
                "stale checkpoint plan based at {base_checkpoint}, current checkpoint is {}",
                self.ck_state.checkpoint_sequence
            )));
        }
        if horizon <= base_checkpoint {
            // Nothing new is durable; still retire anything a previously
            // interrupted checkpoint applied but could not clean up, and
            // persist metadata the store repaired at open (an adopted shard
            // or an allocation map rebuilt from slot headers).
            self.overlay.retire(base_checkpoint);
            if self.store.has_pending_repairs() {
                self.store.persist_discards()?;
                self.store.persist_allocations()?;
            }
            // Segments the checkpoint already covers can still be on disk:
            // their deletion failed (state was stored first) or was lost in
            // a crash. Reclaim them, or the journal stays at its limit and
            // every write fails with ENOSPC while nothing is "new" (K-02).
            if self.journal.delete_covered(base_checkpoint)? > 0 {
                fp("checkpoint.dirsync")?;
                self.backing.sync_dir(layout::JOURNAL_DIR)?;
            }
            // Physical reclamation is a space hint (R5-008): a window that
            // cannot be punched (ENOSPC splitting an extent, EIO) is logged
            // and retried by a later checkpoint, never failed here, or
            // `maki drain` and a clean shutdown could never succeed while it
            // keeps failing (BUG-123).
            if let Err(error) = self
                .store
                .retry_reclamation(|unit| self.overlay.get(unit).is_none())
            {
                tracing::warn!("checkpoint: slot reclamation deferred: {error}");
            }
            self.sanitize();
            return Ok(base_checkpoint);
        }
        // 3. update + sync allocation metadata
        for (unit, version) in &items {
            if !allow_discard || !version.ciphertext.is_empty() {
                self.store.mark_allocated(*unit)?;
            }
        }
        if allow_discard {
            for (unit, version) in &items {
                self.store
                    .set_discarded(*unit, version.ciphertext.is_empty())?;
            }
            // Both complete logical copies and their directory entries must
            // be durable before a slot reservation can be physically removed.
            self.store.persist_discards()?;
        }
        // Slots this checkpoint retires, punched only once its state is
        // durable: until then recovery replays from the older checkpoint and
        // may rewrite an older durable write of the unit into its slot
        // before the tombstone, which needs the reservation (R5-008).
        let punchable: Vec<u64> = if allow_discard {
            items
                .iter()
                .filter_map(|(unit, version)| {
                    (version.ciphertext.is_empty()
                        && self
                            .overlay
                            .get(*unit)
                            .is_none_or(|latest| latest.sequence <= version.sequence))
                    .then_some(*unit)
                })
                .collect()
        } else {
            Vec::new()
        };
        self.store.persist_allocations()?;
        // 4. sync checkpoint metadata (in-memory state only advances after
        //    the durable store succeeds)
        fp("checkpoint.state_store")?;
        let mut new_state = self.ck_state.clone();
        new_state.checkpoint_sequence = horizon;
        self.ck_ab.store(self.backing.as_ref(), &mut new_state)?;
        self.backing.sync_dir(layout::CHECKPOINT_DIR)?;
        self.ck_state = new_state;
        // Physical reclamation. The checkpoint is published from here on: a
        // failure only leaves space unreclaimed (the discard map is durable
        // and reads return zeros), so it never fails this call; the
        // reclamation scan retries it (R5-008).
        let mut reclamation_failed = false;
        if !punchable.is_empty() {
            if let Err(error) = self.store.punch_slots(punchable) {
                tracing::warn!("checkpoint: slot reclamation deferred: {error}");
                self.store.schedule_reclamation();
                reclamation_failed = true;
            }
        }
        // 5. delete completed journal segments
        self.journal.delete_covered(horizon)?;
        // 6. fsync journal directory
        fp("checkpoint.dirsync")?;
        self.backing.sync_dir(layout::JOURNAL_DIR)?;

        self.overlay.retire(horizon);
        // Not straight after a failed punch (the same units would fail
        // again). A scan failure keeps its cursor; the next idle checkpoint
        // retries it and reports a persistent failure there.
        if !reclamation_failed {
            if let Err(error) = self
                .store
                .retry_reclamation(|unit| self.overlay.get(unit).is_none())
            {
                tracing::warn!("checkpoint: slot reclamation deferred: {error}");
            }
        }
        self.sanitize();
        Ok(horizon)
    }

    /// Cross-component invariants (SPEC §12, §26): the checkpoint never
    /// leads the durable boundary, the overlay holds nothing at or below
    /// the checkpoint, and both sub-structures pass their own audits.
    /// Panics on violation; debug builds run it after every volume
    /// mutation.
    pub fn check_invariants(&self) {
        let checkpoint = self.ck_state.checkpoint_sequence;
        let durable = self.journal.durable_sequence();
        assert!(
            checkpoint <= durable,
            "volume sanitizer: checkpoint {checkpoint} > durable {durable}"
        );
        self.journal.check_invariants();
        // The overlay audit is O(units); skip it on very large overlays so
        // debug stress tests stay linear (the overlay samples on its own).
        if self.overlay.len() <= 4096 {
            self.overlay.check_invariants();
            if let Some((_, newest)) = self.overlay.sequence_bounds() {
                // Versions at or below the checkpoint may linger after an
                // interrupted checkpoint (retired by the next one); versions
                // above the journal's appended sequence never exist.
                assert!(
                    newest <= self.journal.appended_sequence(),
                    "volume sanitizer: overlay version {newest} beyond appended {}",
                    self.journal.appended_sequence()
                );
            }
        }
    }

    #[cfg(debug_assertions)]
    fn sanitize(&self) {
        self.check_invariants();
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn sanitize(&self) {}
}

#[cfg(test)]
mod discard_tests {
    use std::io;
    use std::sync::Arc;

    use maki_format::geometry::Geometry;
    use maki_format::init::create_volume_with_discard;
    use maki_format::superblock::Superblock;
    use maki_test_support::crash_backing::FaultOp;
    use maki_test_support::CrashableBacking;

    use super::{Volume, VolumeOptions};

    #[test]
    fn zero_trim_registered_during_checkpoint_preserves_its_durable_write() {
        let backing = Arc::new(CrashableBacking::new());
        create_volume_with_discard(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0x134c1),
                provider_type: "fake".into(),
                crypto_compatibility_id: "zero-trim-checkpoint".into(),
                key_identity: "key".into(),
                geometry: Geometry::compute(512, 512, 512, 520, 4096, 4096).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
        volume.write_ct(0, &[0x41; 520], true).unwrap();
        let prepared = volume.prepare_checkpoint().unwrap();
        backing.set_fault_hook(Some(Arc::new(|operation| {
            matches!(operation, FaultOp::WriteAt { path, .. } if path.starts_with("journal/seg-"))
                .then(|| io::Error::new(io::ErrorKind::StorageFull, "rejected new reservation"))
        })));
        assert!(volume.write_ct(1, &[0x42; 520], false).is_err());
        backing.set_fault_hook(None);
        volume.discard_ct(1, false).unwrap();
        let completed = prepared.execute().unwrap();
        assert_eq!(volume.finish_checkpoint(completed).unwrap(), 1);
        drop(volume);
        backing.crash_all_lost();
        let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
        assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![0x41; 520]);
        assert!(recovered.read_ct(1).unwrap().is_none());
    }

    #[test]
    fn newer_tombstone_cannot_hide_an_intermediate_write_reservation_from_punch() {
        let backing = Arc::new(CrashableBacking::new());
        let geometry = Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap();
        let slot_size = geometry.slot_size as usize;
        create_volume_with_discard(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0x007a_1234),
                provider_type: "fake".into(),
                crypto_compatibility_id: "discard-reservation-v1".into(),
                key_identity: "k".into(),
                geometry,
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
        volume.write_ct(1, &[0x11; 1032], true).unwrap();
        volume.checkpoint().unwrap();

        volume.discard_ct(1, true).unwrap(); // snapshot tombstone 2
        let prepared = volume.prepare_checkpoint().unwrap();
        let completed = prepared.execute().unwrap();
        volume.write_ct(1, &[0x13; 1032], true).unwrap(); // durable reservation 3
        volume.discard_ct(1, false).unwrap(); // volatile latest tombstone 4

        backing.set_fault_hook(Some(Arc::new(move |operation| match operation {
            FaultOp::WriteAt { path, len, .. } if path.ends_with(".dat") && *len == slot_size => {
                Some(io::Error::other("checkpoint punched a newer reservation"))
            }
            _ => None,
        })));
        assert_eq!(volume.finish_checkpoint(completed).unwrap(), 2);
        backing.set_fault_hook(None);
    }
}

#[cfg(test)]
mod reservation_barrier_tests {
    use super::{CompletedCheckpoint, Volume, VolumeOptions};
    use maki_format::{geometry::Geometry, init, superblock::Superblock};
    use maki_test_support::crash_backing::FaultOp;
    use maki_test_support::CrashableBacking;
    use std::io;
    use std::sync::Arc;

    #[test]
    fn review_f09_concurrent_reservation_sync_failure_cannot_publish_checkpoint() {
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0xf0902),
                provider_type: "fake".into(),
                crypto_compatibility_id: "reservation-checkpoint".into(),
                key_identity: "key".into(),
                geometry: Geometry::compute(512, 512, 512, 512, 4096, 4096).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
        volume.write_ct(0, &[0x86; 512], true).unwrap();
        let prepared = volume.prepare_checkpoint().unwrap();
        // Deterministically interleave the exact slot-write and shard-sync
        // steps execute() runs without the volume lock. A foreground write
        // is allowed to reserve another unit between these two steps.
        prepared.slots.write(0, 1, &[0x86; 512]).unwrap();
        backing.set_fault_hook(Some(Arc::new(|op| match op {
            FaultOp::SyncData { path } if path.ends_with(".dat") => Some(io::Error::other(
                "reservation sync lost checkpoint dirty bits",
            )),
            _ => None,
        })));
        assert!(volume.write_ct(1, &[0x97; 512], false).is_err());
        backing.set_fault_hook(None);
        // Linux-style failed writeback left the checkpoint bytes readable
        // but clean and not durable. This later sync succeeds with no writes.
        prepared.slots.sync_shards().unwrap();
        assert!(
            volume
                .finish_checkpoint(CompletedCheckpoint(prepared))
                .is_err(),
            "checkpoint published after another fsync discarded its dirty writes"
        );
        assert_eq!(volume.checkpoint_sequence(), 0);
        volume.checkpoint().unwrap(); // rewrite all slots from the kept journal
        drop(volume);
        backing.crash_all_lost();
        let recovered = Volume::recover(backing, VolumeOptions::default()).unwrap();
        assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, vec![0x86; 512]);
    }
}

#[cfg(test)]
mod zero_trim_freshness_tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use maki_backing::{Backing, BackingFile, MemBacking, VolumeLock};
    use maki_format::{geometry::Geometry, init, superblock::Superblock};

    use super::{Volume, VolumeOptions};

    #[derive(Default)]
    struct FreshnessGate {
        inner: MemBacking,
        revoked: AtomicBool,
    }

    impl Backing for FreshnessGate {
        fn check_freshness(&self) -> io::Result<()> {
            if self.revoked.load(Ordering::SeqCst) {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test writer revoked",
                ))
            } else {
                Ok(())
            }
        }

        fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
            self.inner.open(path, create)
        }

        fn exists(&self, path: &str) -> io::Result<bool> {
            self.inner.exists(path)
        }

        fn remove(&self, path: &str) -> io::Result<()> {
            self.inner.remove(path)
        }

        fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            self.inner.rename(from, to)
        }

        fn create_dir_all(&self, path: &str) -> io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn list(&self, dir: &str) -> io::Result<Vec<String>> {
            self.inner.list(dir)
        }

        fn sync_dir(&self, dir: &str) -> io::Result<()> {
            self.inner.sync_dir(dir)
        }

        fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
            self.inner.try_lock(path)
        }
    }

    #[test]
    fn zero_trim_prefilter_rechecks_freshness_before_skipping_overlay_tombstone() {
        let backing = Arc::new(FreshnessGate::default());
        init::create_volume_with_discard(
            backing.as_ref(),
            Superblock {
                generation: 0,
                volume_uuid: uuid::Uuid::from_u128(0x134f1),
                provider_type: "fake".into(),
                crypto_compatibility_id: "zero-trim-freshness".into(),
                key_identity: "key".into(),
                geometry: Geometry::compute(512, 512, 512, 520, 4096, 4096).unwrap(),
                format_version: 1,
                created_unix: 0,
            },
        )
        .unwrap();
        let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
        volume.write_ct(0, &[0x41; 520], true).unwrap();
        volume.discard_ct(0, false).unwrap();
        assert!(volume.reclaim_unwritten(0).unwrap());

        // The engine's initial guard may pass before a request waits for its
        // unit locks. The zero-only publication path must check again even
        // when an overlay tombstone lets it skip all storage and journaling.
        backing.revoked.store(true, Ordering::SeqCst);
        assert!(volume.check_freshness().is_err());
        let error = volume
            .reclaim_unwritten(0)
            .expect_err("a revoked session must not accept a zero-only TRIM");
        assert!(error.to_string().contains("test writer revoked"));
    }
}
