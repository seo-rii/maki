//! Ordered ciphertext journal writer (SPEC §23–§25).
//!
//! One writer per volume. Tracks `next_sequence`, `appended_sequence`,
//! `durable_sequence`, and the active segment. Segment-creation protocol
//! (create → header → fdatasync → dir fsync) completes before any record in
//! the segment can be acknowledged, so a durable record can never live in a
//! file whose dirent might vanish.
//!
//! Durability boundary contract: `durable_sequence` only advances after a
//! successful `sync_data`, and a failed seal keeps the active segment (its
//! records stay pending) so a later barrier still syncs them. Callers must
//! treat *every* return from [`JournalWriter::append`] — including errors —
//! as a point where `durable_sequence` may have moved (an automatic roll
//! seals the previous segment).
//!
//! After every successful segment fdatasync the writer records the synced
//! prefix in the durable mark (`journal/durable-mark`, see
//! `maki_format::journal::DurableMark`) with a plain, un-synced write. The
//! mark lets recovery tell durable-body corruption from a torn tail; it is
//! only ever a lower bound, so a failed mark write is logged, not fatal.

use std::sync::Arc;

use uuid::Uuid;

use maki_backing::{Backing, BackingFile};
use maki_format::journal::{
    encode_record, DurableMark, JournalRecord, SegmentHeader, SEGMENT_HEADER_SIZE,
};
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
    /// File offset up to which this segment has been fdatasync'd.
    synced_offset: u64,
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
    /// `journal/durable-mark`, opened lazily on the first successful sync.
    mark: Option<Arc<dyn BackingFile>>,
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
            segment_size: effective_segment_size(segment_size),
            next_sequence: durable_sequence + 1,
            appended_sequence: durable_sequence,
            durable_sequence,
            sealed,
            active: None,
            next_segment_index,
            mark: None,
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

    /// Index of the first segment holding a record newer than
    /// `checkpoint_sequence` (sealed first, then the active one).
    pub fn first_uncovered_segment_index(&self, checkpoint_sequence: u64) -> Option<u64> {
        self.sealed
            .iter()
            .chain(self.active.as_ref().map(|a| &a.info))
            .find(|s| s.record_count > 0 && s.last_sequence() > checkpoint_sequence)
            .map(|s| s.index)
    }

    /// Bytes appended but not yet durable (admission control input).
    pub fn pending_bytes(&self) -> u64 {
        self.active
            .as_ref()
            .filter(|a| a.unsynced)
            .map(|a| a.write_offset.saturating_sub(a.synced_offset))
            .unwrap_or(0)
    }

    /// Total bytes of every journal segment on disk (sealed + active): the
    /// quantity a journal size limit bounds.
    pub fn total_bytes(&self) -> u64 {
        self.sealed.iter().map(|s| s.size).sum::<u64>()
            + self.active.as_ref().map(|a| a.info.size).unwrap_or(0)
    }

    /// fdatasync the active segment's pending records and publish the
    /// durable mark. On success `durable_sequence` covers every appended
    /// record.
    fn sync_active(&mut self) -> Result<(), CoreError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        if !active.unsynced {
            return Ok(());
        }
        fp("journal.sync")?;
        active.file.sync_data()?;
        active.unsynced = false;
        active.synced_offset = active.write_offset;
        self.durable_sequence = self.appended_sequence;
        let mark = DurableMark {
            segment_index: active.info.index,
            durable_size: active.write_offset,
        };
        self.write_mark(mark);
        self.sanitize();
        Ok(())
    }

    /// Best-effort, never fsync'd (see module docs): a mark can only make
    /// recovery *stricter* about bytes that are provably durable.
    fn write_mark(&mut self, mark: DurableMark) {
        if self.mark.is_none() {
            match self.backing.open(layout::JOURNAL_DURABLE_MARK, true) {
                Ok(file) => self.mark = Some(file),
                Err(e) => {
                    tracing::warn!("journal durable mark unavailable: {e}");
                    return;
                }
            }
        }
        if let Some(file) = &self.mark {
            if let Err(e) = file.write_at(0, &mark.encode()) {
                tracing::warn!("journal durable mark write failed: {e}");
            }
        }
    }

    /// Sync the active segment (if it has pending records) and retire it to
    /// the sealed list. On a sync failure the segment stays active and
    /// unsynced so a later barrier still covers its records.
    fn seal_active(&mut self) -> Result<(), CoreError> {
        self.sync_active()?;
        if let Some(active) = self.active.take() {
            self.sealed.push(active.info);
        }
        self.sanitize();
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
                    synced_offset: SEGMENT_HEADER_SIZE as u64,
                    unsynced: false,
                });
                // Point the mark at the new segment (header only) so it
                // names the newest segment index even before the first
                // sync; recovery continues numbering above it.
                self.write_mark(DurableMark {
                    segment_index: index,
                    durable_size: SEGMENT_HEADER_SIZE as u64,
                });
                self.sanitize();
                Ok(())
            }
            Err(e) => {
                // Best-effort cleanup; the retry recreates the same index.
                let _ = self.backing.remove(&path);
                self.sanitize();
                Err(e)
            }
        }
    }

    /// Append one ciphertext record. Returns its sequence. On error, no
    /// sequence is consumed and the journal remains consistent — but
    /// `durable_sequence` may still have advanced (an automatic roll seals
    /// the previous segment before the failure).
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
        self.sanitize();
        Ok(sequence)
    }

    /// Make all appended records durable (FLUSH barrier / FUA tail).
    pub fn sync(&mut self) -> Result<u64, CoreError> {
        self.sync_active()?;
        // Every sealed segment was synced before it was sealed (a failed
        // seal keeps the segment active), so the active segment is the only
        // possible holder of pending records.
        self.durable_sequence = self.appended_sequence;
        self.sanitize();
        Ok(self.durable_sequence)
    }

    /// Structural invariants of the writer (SPEC §23–§25). Panics on
    /// violation; debug builds run it after every mutation.
    ///
    /// * `durable_sequence <= appended_sequence < next_sequence` and the
    ///   two differ by exactly one.
    /// * Sealed segments carry strictly increasing indexes and contiguous
    ///   base sequences; the active segment (if any) follows them and its
    ///   records end exactly at `appended_sequence`.
    /// * The active segment's synced prefix never exceeds its size, an
    ///   unsynced segment has bytes past the synced prefix, and a synced one
    ///   has none.
    /// * Every sealed segment is fully durable: its last record is at or
    ///   below `durable_sequence`.
    /// * `next_segment_index` is above every segment index in use.
    pub fn check_invariants(&self) {
        assert!(
            self.durable_sequence <= self.appended_sequence,
            "journal sanitizer: durable {} > appended {}",
            self.durable_sequence,
            self.appended_sequence
        );
        assert_eq!(
            self.next_sequence,
            self.appended_sequence + 1,
            "journal sanitizer: next sequence not appended + 1"
        );
        let mut prev_index: Option<u64> = None;
        let mut expected_base: Option<u64> = None;
        let all = self
            .sealed
            .iter()
            .map(|s| (s, false))
            .chain(self.active.as_ref().map(|a| (&a.info, true)));
        for (seg, is_active) in all {
            if let Some(p) = prev_index {
                assert!(
                    seg.index > p,
                    "journal sanitizer: segment {} after {}",
                    seg.index,
                    p
                );
            }
            prev_index = Some(seg.index);
            assert!(
                seg.index < self.next_segment_index,
                "journal sanitizer: segment {} >= next index {}",
                seg.index,
                self.next_segment_index
            );
            if let Some(base) = expected_base {
                assert_eq!(
                    seg.base_sequence, base,
                    "journal sanitizer: segment {} base not contiguous",
                    seg.index
                );
            }
            expected_base = Some(seg.base_sequence + seg.record_count);
            assert!(
                seg.size >= SEGMENT_HEADER_SIZE as u64,
                "journal sanitizer: segment {} smaller than its header",
                seg.index
            );
            if !is_active && seg.record_count > 0 {
                assert!(
                    seg.last_sequence() <= self.durable_sequence,
                    "journal sanitizer: sealed segment {} ends at {} past durable {}",
                    seg.index,
                    seg.last_sequence(),
                    self.durable_sequence
                );
            }
        }
        if let Some(a) = &self.active {
            assert_eq!(
                a.info.base_sequence + a.info.record_count,
                self.next_sequence,
                "journal sanitizer: active segment does not end at next sequence"
            );
            assert_eq!(
                a.write_offset, a.info.size,
                "journal sanitizer: size != offset"
            );
            assert!(
                a.synced_offset <= a.write_offset,
                "journal sanitizer: synced past written"
            );
            if a.unsynced {
                assert!(
                    a.synced_offset < a.write_offset,
                    "journal sanitizer: unsynced segment with nothing pending"
                );
            } else {
                assert_eq!(
                    a.synced_offset, a.write_offset,
                    "journal sanitizer: synced segment with pending bytes"
                );
                assert_eq!(
                    self.durable_sequence, self.appended_sequence,
                    "journal sanitizer: fully synced but durable lags appended"
                );
            }
        } else {
            assert_eq!(
                self.durable_sequence, self.appended_sequence,
                "journal sanitizer: no active segment but durable lags appended"
            );
        }
    }

    #[cfg(debug_assertions)]
    fn sanitize(&self) {
        self.check_invariants();
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn sanitize(&self) {}

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
        self.sanitize();
        match error {
            Some(e) => Err(e),
            None => Ok(deleted),
        }
    }
}

/// The segment size the writer actually rolls at for a configured value
/// (a floor keeps the header plus one small record possible).
pub fn effective_segment_size(configured: u64) -> u64 {
    configured.max(SEGMENT_HEADER_SIZE as u64 + 64)
}
