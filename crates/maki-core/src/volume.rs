//! The ciphertext-level volume: journal + overlay + slot store + checkpoint
//! (SPEC §23–§27). Phase 4's engine layers crypto, RMW, and per-unit
//! concurrency on top of this.

use std::sync::Arc;

use maki_backing::{Backing, VolumeLock};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::layout;
use maki_format::superblock::Superblock;

use crate::error::CoreError;
use crate::fp;
use crate::journal::JournalWriter;
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
        let Recovered {
            lock,
            superblock,
            store,
            checkpoint_sequence,
            durable_sequence,
            next_segment_index,
            segments,
            replay,
        } = recover(&backing)?;

        let journal = JournalWriter::resume(
            backing.clone(),
            superblock.volume_uuid,
            options.journal_segment_size,
            durable_sequence,
            next_segment_index,
            segments,
        );

        // Rebuild overlay: everything in the surviving journal is durable.
        let mut overlay = Overlay::new();
        for record in replay {
            overlay.publish(record.unit_index, record.sequence, record.payload);
        }
        overlay.promote(durable_sequence);

        let mut ck_state = CheckpointState::default();
        ck_state.checkpoint_sequence = checkpoint_sequence;

        Ok(Self {
            backing,
            _lock: lock,
            superblock,
            journal,
            store,
            overlay,
            ck_ab: AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B),
            ck_state,
        })
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

    pub fn journal_segment_count(&self) -> usize {
        self.journal.segment_count()
    }

    pub fn journal_active_segment_path(&self) -> Option<String> {
        self.journal
            .active_segment_index()
            .map(layout::journal_segment)
    }

    pub fn overlay_len(&self) -> usize {
        self.overlay.len()
    }

    pub fn overlay_bytes(&self) -> u64 {
        self.overlay.bytes()
    }

    /// Journal a ciphertext write; publish to the overlay on success.
    /// With `fua`, the record is made durable and verified before returning
    /// (SPEC §24).
    pub fn write_ct(&mut self, unit: u64, ciphertext: &[u8], fua: bool) -> Result<u64, CoreError> {
        let sequence = self.journal.append(unit, ciphertext)?;
        if fua {
            let durable = self.journal.sync()?;
            if durable < sequence {
                return Err(CoreError::Durability(format!(
                    "FUA verify failed: durable {durable} < sequence {sequence}"
                )));
            }
        }
        self.overlay.publish(unit, sequence, ciphertext.to_vec());
        self.overlay.promote(self.journal.durable_sequence());
        Ok(sequence)
    }

    /// FLUSH barrier (SPEC §25): everything appended becomes durable.
    pub fn flush(&mut self) -> Result<(), CoreError> {
        let durable = self.journal.sync()?;
        self.overlay.promote(durable);
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
        if durable <= self.ck_state.checkpoint_sequence {
            // Nothing new is durable; still retire anything a previously
            // interrupted checkpoint applied but could not clean up.
            self.overlay.retire(self.ck_state.checkpoint_sequence);
            return Ok(self.ck_state.checkpoint_sequence);
        }
        let items = self.overlay.collect_durable(durable);
        if items.is_empty() {
            // Nothing to apply, but the boundary may still advance so
            // covered segments can be reclaimed.
        }

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
        Ok(durable)
    }
}
