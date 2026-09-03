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
use crate::recovery::{recover, Recovered, RecoveryError};
use crate::store::{SlotRead, SlotStore};

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
            store,
            checkpoint_state,
            durable_sequence,
            next_segment_index,
            segments,
            replay,
        } = recover(&backing, segment_size)?;

        let mut journal = JournalWriter::resume(
            backing.clone(),
            superblock.volume_uuid,
            segment_size,
            durable_sequence,
            next_segment_index,
            segments,
        );
        journal.allow_covered_holes_below(checkpoint_state.checkpoint_sequence);

        // Rebuild overlay: everything in the surviving journal is durable.
        let mut overlay = Overlay::new();
        for record in replay {
            overlay.publish(record.unit_index, record.sequence, record.payload);
        }
        overlay.promote(durable_sequence);

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

    /// Bytes of journal on disk (all segments).
    pub fn journal_total_bytes(&self) -> u64 {
        self.journal.total_bytes()
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
        if let Some(unit) = self.overlay.first_unit() {
            return Ok(self.read_ct(unit)?.map(|(_, data)| (unit, data)));
        }
        let Some(unit) = self.store.first_allocated_unit() else {
            return Ok(None);
        };
        Ok(self.read_ct(unit)?.map(|(_, data)| (unit, data)))
    }

    /// Journal a ciphertext write; publish to the overlay on success.
    /// With `fua`, the record is made durable and verified before returning
    /// (SPEC §24).
    pub fn write_ct(&mut self, unit: u64, ciphertext: &[u8], fua: bool) -> Result<u64, CoreError> {
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

    /// FLUSH barrier (SPEC §25): everything appended becomes durable.
    pub fn flush(&mut self) -> Result<(), CoreError> {
        let durable = self.journal.sync()?;
        self.overlay.promote(durable);
        self.sanitize();
        Ok(())
    }

    /// Read one unit's ciphertext: overlay first, then slots.
    /// `None` = unwritten zeros.
    pub fn read_ct(&self, unit: u64) -> Result<Option<(u64, Vec<u8>)>, CoreError> {
        if let Some(v) = self.overlay.get(unit) {
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
        let durable = self.journal.durable_sequence();
        // Never rely on callers having promoted after the last boundary
        // move: the checkpointable set is derived here, from the journal's
        // own durable boundary.
        self.overlay.promote(durable);
        if durable <= self.ck_state.checkpoint_sequence {
            // Nothing new is durable; still retire anything a previously
            // interrupted checkpoint applied but could not clean up, and
            // persist metadata the store repaired at open (an adopted shard
            // or an allocation map rebuilt from slot headers).
            self.overlay.retire(self.ck_state.checkpoint_sequence);
            if self.store.has_pending_repairs() {
                self.store.persist_allocations()?;
            }
            // Segments the checkpoint already covers can still be on disk:
            // their deletion failed (state was stored first) or was lost in
            // a crash. Reclaim them, or the journal stays at its limit and
            // every write fails with ENOSPC while nothing is "new" (K-02).
            if self
                .journal
                .delete_covered(self.ck_state.checkpoint_sequence)?
                > 0
            {
                fp("checkpoint.dirsync")?;
                self.backing.sync_dir(layout::JOURNAL_DIR)?;
            }
            self.sanitize();
            return Ok(self.ck_state.checkpoint_sequence);
        }
        let items = self.overlay.collect_durable(durable);

        // 1. write main slots
        for (unit, version) in &items {
            fp("checkpoint.slot_write")?;
            self.store
                .write_slot(*unit, version.sequence, &version.ciphertext)?;
        }
        // 2. fdatasync affected data shards
        for shard in self.store.shards_of_units(items.iter().map(|(u, _)| u)) {
            fp("checkpoint.shard_sync")?;
            self.store.sync_shard_data(shard)?;
        }
        // 3. update + sync allocation metadata
        for (unit, _) in &items {
            self.store.mark_allocated(*unit)?;
        }
        self.store.persist_allocations()?;
        // 4. sync checkpoint metadata (in-memory state only advances after
        //    the durable store succeeds)
        fp("checkpoint.state_store")?;
        let mut new_state = self.ck_state.clone();
        new_state.checkpoint_sequence = durable;
        self.ck_ab.store(self.backing.as_ref(), &mut new_state)?;
        self.backing.sync_dir(layout::CHECKPOINT_DIR)?;
        self.ck_state = new_state;
        // 5. delete completed journal segments
        self.journal.delete_covered(durable)?;
        // 6. fsync journal directory
        fp("checkpoint.dirsync")?;
        self.backing.sync_dir(layout::JOURNAL_DIR)?;

        self.overlay.retire(durable);
        self.sanitize();
        Ok(durable)
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
