use std::collections::BTreeMap;

use super::{scan::RecordHeader, RecoveryError, RecoveryProgress};
use crate::store::SlotStore;

/// One metadata-only window covers a default-sized segment of 4 KiB writes.
/// Larger surviving ranges are checked in additional windows.
pub(super) const MAX_CHECKPOINT_UNITS: usize = 65_536;

/// Latest record per unit in the contiguous journal suffix ending at the
/// checkpoint. A newer replay record replaces that unit's obligation.
pub(super) struct CheckpointEvidence {
    checkpoint: u64,
    first_unit: u64,
    limit: usize,
    suffix_start: Option<u64>,
    last_covered: Option<u64>,
    more: bool,
    records: BTreeMap<u64, Option<RecordHeader>>,
}

impl CheckpointEvidence {
    pub(super) fn new(checkpoint: u64, first_unit: u64, limit: usize) -> Self {
        assert!(limit > 0);
        Self {
            checkpoint,
            first_unit,
            limit,
            suffix_start: None,
            last_covered: None,
            more: false,
            records: BTreeMap::new(),
        }
    }

    pub(super) fn observe(&mut self, record: RecordHeader) {
        if record.sequence > self.checkpoint {
            // Preserve the key so a replacement doesn't move this window
            // or skip the first unit of the next one.
            if let Some(covered) = self.records.get_mut(&record.unit) {
                *covered = None;
            }
            return;
        }

        if self.last_covered.and_then(|seq| seq.checked_add(1)) != Some(record.sequence) {
            // A normally pruned segment can contain a superseding record.
            // Evidence before a gap says nothing about the final slot.
            self.records.clear();
            self.more = false;
            self.suffix_start = Some(record.sequence);
        }
        self.last_covered = Some(record.sequence);

        if record.unit < self.first_unit {
            return;
        }
        if let Some(covered) = self.records.get_mut(&record.unit) {
            *covered = Some(record);
            return;
        }
        if self.records.len() == self.limit {
            self.more = true;
            let (&last_unit, _) = self.records.last_key_value().expect("full evidence window");
            if record.unit > last_unit {
                return;
            }
            self.records.pop_last();
        }
        self.records.insert(record.unit, Some(record));
    }

    fn covers_checkpoint(&self) -> bool {
        self.last_covered == Some(self.checkpoint)
    }

    pub(super) fn suffix_start(&self) -> Option<u64> {
        self.suffix_start
    }

    fn next_window(&self) -> Option<u64> {
        if !self.covers_checkpoint() || !self.more {
            return None;
        }
        self.records.last_key_value()?.0.checked_add(1)
    }

    pub(super) fn verify(
        self,
        store: &SlotStore,
        progress: &RecoveryProgress<'_>,
    ) -> Result<Option<u64>, RecoveryError> {
        let next = self.next_window();
        if self.covers_checkpoint() {
            for record in self.records.into_values().flatten() {
                store.verify_covered_slot(
                    record.unit,
                    record.sequence,
                    record.payload_len,
                    record.payload_crc,
                )?;
                progress();
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sequence: u64, unit: u64) -> RecordHeader {
        RecordHeader {
            sequence,
            unit,
            payload_len: 512,
            payload_crc: 1,
        }
    }

    #[test]
    fn keep_only_latest_evidence_in_the_contiguous_covered_suffix() {
        let mut evidence = CheckpointEvidence::new(7, 0, 8);
        for (seq, unit) in [(1, 8), (4, 1), (5, 2), (6, 1), (7, 3), (8, 2)] {
            evidence.observe(record(seq, unit));
        }
        let obligations: Vec<_> = evidence
            .records
            .values()
            .flatten()
            .map(|r| (r.unit, r.sequence))
            .collect();
        assert_eq!(obligations, [(1, 6), (3, 7)]);
    }

    #[test]
    fn ordered_windows_keep_every_unit_even_with_replacements() {
        let records = [(1, 4), (2, 1), (3, 6), (4, 2), (5, 4), (6, 2)];
        let mut first_unit = 0;
        let mut units = Vec::new();
        loop {
            let mut evidence = CheckpointEvidence::new(5, first_unit, 2);
            for (seq, unit) in records {
                evidence.observe(record(seq, unit));
            }
            assert!(evidence.records.len() <= 2);
            units.extend(
                evidence
                    .records
                    .values()
                    .flatten()
                    .map(|r| (r.unit, r.sequence)),
            );
            let Some(next) = evidence.next_window() else {
                break;
            };
            assert!(next > first_unit);
            first_unit = next;
        }
        assert_eq!(units, [(1, 2), (4, 5), (6, 3)]);
    }

    #[test]
    fn an_incomplete_suffix_does_not_assert_slot_coverage() {
        let mut evidence = CheckpointEvidence::new(5, 0, 1);
        for (seq, unit) in [(1, 1), (2, 2), (6, 2)] {
            evidence.observe(record(seq, unit));
        }
        assert!(!evidence.covers_checkpoint());
        assert_eq!(evidence.next_window(), None);
    }
}
