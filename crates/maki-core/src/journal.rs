//! Ordered ciphertext journal writer (SPEC §23–§25).
//!
//! One writer per volume. Tracks `next_sequence`, `appended_sequence`,
//! `durable_sequence`, and the active segment. Segment-creation protocol
//! (create → header → fdatasync → dir fsync) completes before any record in
//! the segment can be acknowledged, so a durable record can never live in a
//! file whose dirent might vanish.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::{Backing, BackingFile};
use maki_format::journal::{encode_record, JournalRecord, SegmentHeader, SEGMENT_HEADER_SIZE};
use maki_format::layout;

use crate::error::CoreError;
use crate::fp;

#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub index: u64,
    pub base_sequence: u64,
    pub record_count: u64,
    pub size: u64,
}

impl SegmentInfo {
    /// Sequence of the last record in this segment, or of the last record
    /// before it if the segment is empty.
    pub fn last_sequence(&self) -> u64 {
        if self.record_count > 0 {
            self.base_sequence + self.record_count - 1
        } else {
            self.base_sequence.saturating_sub(1)
        }
    }
}

struct ActiveSegment {
    info: SegmentInfo,
    file: Arc<dyn BackingFile>,
    write_offset: u64,
    unsynced: bool,
}

pub struct JournalWriter {
    backing: Arc<dyn Backing>,
    volume_uuid: Uuid,
    segment_size: u64,
    next_sequence: u64,
    appended_sequence: u64,
    durable_sequence: u64,
    sealed: Vec<SegmentInfo>,
    active: Option<ActiveSegment>,
    next_segment_index: u64,
}

impl JournalWriter {
    /// Resume after recovery. All `sealed` segments are fully durable;
    /// appends start a fresh segment.
    pub fn resume(
        backing: Arc<dyn Backing>,
        volume_uuid: Uuid,
        segment_size: u64,
        durable_sequence: u64,
        next_segment_index: u64,
        sealed: Vec<SegmentInfo>,
    ) -> Self {
        Self {
            backing,
            volume_uuid,
            segment_size: segment_size.max(SEGMENT_HEADER_SIZE as u64 + 64),
            next_sequence: durable_sequence + 1,
            appended_sequence: durable_sequence,
            durable_sequence,
            sealed,
            active: None,
            next_segment_index,
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn appended_sequence(&self) -> u64 {
        self.appended_sequence
    }

    pub fn durable_sequence(&self) -> u64 {
        self.durable_sequence
    }

    pub fn segment_count(&self) -> usize {
        self.sealed.len() + usize::from(self.active.is_some())
    }

    pub fn active_segment_index(&self) -> Option<u64> {
        self.active.as_ref().map(|a| a.info.index)
    }

    /// Bytes appended but not yet durable (admission control input).
    pub fn pending_bytes(&self) -> u64 {
        self.active
            .as_ref()
            .filter(|a| a.unsynced)
            .map(|a| a.write_offset)
            .unwrap_or(0)
    }

    fn seal_active(&mut self) -> Result<(), CoreError> {
        if let Some(mut active) = self.active.take() {
            if active.unsynced {
                fp("journal.sync")?;
                active.file.sync_data()?;
                self.durable_sequence = self.appended_sequence;
            }
            self.sealed.push(active.info);
        }
        Ok(())
    }

    fn roll(&mut self) -> Result<(), CoreError> {
        self.seal_active()?;
        let index = self.next_segment_index;
        let path = layout::journal_segment(index);
        let base_sequence = self.next_sequence;

        let result: Result<Arc<dyn BackingFile>, CoreError> = (|| {
            fp("journal.segment.create")?;
            let file = self.backing.open(&path, true)?;
            file.set_len(0)?;
            let header = SegmentHeader {
                segment_index: index,
                volume_uuid: self.volume_uuid,
                base_sequence,
            };
            file.write_at(0, &header.encode())?;
            fp("journal.segment.header_sync")?;
            file.sync_data()?;
            fp("journal.segment.dirsync")?;
            self.backing.sync_dir(layout::JOURNAL_DIR)?;
            Ok(file)
        })();

        match result {
            Ok(file) => {
                self.next_segment_index += 1;
                self.active = Some(ActiveSegment {
                    info: SegmentInfo {
                        index,
                        base_sequence,
                        record_count: 0,
                        size: SEGMENT_HEADER_SIZE as u64,
                    },
                    file,
                    write_offset: SEGMENT_HEADER_SIZE as u64,
                    unsynced: false,
                });
                Ok(())
            }
            Err(e) => {
                // Best-effort cleanup; the retry recreates the same index.
                let _ = self.backing.remove(&path);
                Err(e)
            }
        }
    }

    /// Append one ciphertext record. Returns its sequence. On error, no
    /// sequence is consumed and the journal remains consistent.
    pub fn append(&mut self, unit_index: u64, payload: &[u8]) -> Result<u64, CoreError> {
        let record_len = 32 + payload.len() as u64;
        let needs_roll = match &self.active {
            None => true,
            Some(a) => a.info.record_count > 0 && a.write_offset + record_len > self.segment_size,
        };
        if needs_roll {
            self.roll()?;
        }
        let sequence = self.next_sequence;
        let record = JournalRecord {
            sequence,
            unit_index,
            payload: payload.to_vec(),
        };
        let bytes = encode_record(&record);
        let active = self.active.as_mut().expect("active segment after roll");
        fp("journal.append.write")?;
        active.file.write_at(active.write_offset, &bytes)?;
        active.write_offset += bytes.len() as u64;
        active.info.record_count += 1;
        active.info.size = active.write_offset;
        active.unsynced = true;
        self.next_sequence += 1;
        self.appended_sequence = sequence;
        Ok(sequence)
    }

    /// Make all appended records durable (FLUSH barrier / FUA tail).
    pub fn sync(&mut self) -> Result<u64, CoreError> {
        if let Some(active) = self.active.as_mut() {
            if active.unsynced {
                fp("journal.sync")?;
                active.file.sync_data()?;
                active.unsynced = false;
            }
        }
        self.durable_sequence = self.appended_sequence;
        Ok(self.durable_sequence)
    }

    /// Delete sealed segments fully covered by `checkpoint_sequence`.
    /// Returns how many were deleted. The caller fsyncs the journal dir.
    pub fn delete_covered(&mut self, checkpoint_sequence: u64) -> Result<usize, CoreError> {
        let mut kept = Vec::new();
        let mut deleted = 0usize;
        let mut error: Option<CoreError> = None;
        for seg in self.sealed.drain(..) {
            let covered = seg.last_sequence() <= checkpoint_sequence;
            if covered && error.is_none() {
                let step: Result<(), CoreError> = (|| {
                    fp("checkpoint.segment_delete")?;
                    self.backing.remove(&layout::journal_segment(seg.index))?;
                    Ok(())
                })();
                match step {
                    Ok(()) => deleted += 1,
                    Err(e) => {
                        error = Some(e);
                        kept.push(seg);
                    }
                }
            } else {
                kept.push(seg);
            }
        }
        self.sealed = kept;
        match error {
            Some(e) => Err(e),
            None => Ok(deleted),
        }
    }
}
