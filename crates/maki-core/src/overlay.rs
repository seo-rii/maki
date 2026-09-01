//! Ciphertext overlay: journal records not yet checkpointed (SPEC §23).
//!
//! Per unit we keep the *latest* version (serves reads) and, separately, the
//! latest *durable* version (what a checkpoint may apply). Keeping the
//! durable copy is what makes `checkpoint_sequence = durable_sequence` safe
//! when a newer, still-volatile overwrite of the same unit exists: without
//! it, deleting the journal segment holding the durable version would lose
//! the only crash-safe copy of that unit.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct OverlayVersion {
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Default)]
struct UnitOverlay {
    latest: OverlayVersion,
    durable: Option<OverlayVersion>,
}

impl Default for OverlayVersion {
    fn default() -> Self {
        Self {
            sequence: 0,
            ciphertext: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct Overlay {
    units: BTreeMap<u64, UnitOverlay>,
    /// sequence -> unit, promoted (moved into `durable`) once the journal
    /// reports the sequence durable. Processed strictly in sequence order.
    pending_promotion: BTreeMap<u64, u64>,
    bytes: u64,
}

impl Overlay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Publish a freshly journaled version (after successful append).
    pub fn publish(&mut self, unit: u64, sequence: u64, ciphertext: Vec<u8>) {
        self.bytes += ciphertext.len() as u64;
        let entry = self.units.entry(unit).or_default();
        if entry.latest.sequence != 0 {
            self.bytes = self.bytes.saturating_sub(entry.latest.ciphertext.len() as u64);
        }
        entry.latest = OverlayVersion {
            sequence,
            ciphertext,
        };
        self.pending_promotion.insert(sequence, unit);
    }

    /// Latest version for reads.
    pub fn get(&self, unit: u64) -> Option<&OverlayVersion> {
        self.units.get(&unit).map(|e| &e.latest)
    }

    /// Advance the durable boundary: versions with sequence <=
    /// `durable_sequence` become checkpointable.
    pub fn promote(&mut self, durable_sequence: u64) {
        loop {
            let Some((&seq, &unit)) = self.pending_promotion.iter().next() else {
                break;
            };
            if seq > durable_sequence {
                break;
            }
            self.pending_promotion.remove(&seq);
            if let Some(entry) = self.units.get_mut(&unit) {
                // Only promote if this is still the unit's newest sequence at
                // or below the durable boundary; a superseded version's data
                // is gone, but its successor is either also <= durable (its
                // own queue entry promotes it) or still volatile (the old
                // durable copy, if any, stays).
                if entry.latest.sequence == seq {
                    if entry
                        .durable
                        .as_ref()
                        .map(|d| d.sequence < seq)
                        .unwrap_or(true)
                    {
                        if entry.durable.is_none() {
                            self.bytes += entry.latest.ciphertext.len() as u64;
                        } else {
                            // replacing durable: bytes stay ~same
                        }
                        entry.durable = Some(entry.latest.clone());
                    }
                }
            }
        }
    }

    /// Durable versions eligible for a checkpoint at `durable_sequence`.
    pub fn collect_durable(&self, durable_sequence: u64) -> Vec<(u64, OverlayVersion)> {
        self.units
            .iter()
            .filter_map(|(unit, e)| {
                e.durable
                    .as_ref()
                    .filter(|d| d.sequence <= durable_sequence)
                    .map(|d| (*unit, d.clone()))
            })
            .collect()
    }

    /// Retire state covered by a completed checkpoint.
    pub fn retire(&mut self, checkpoint_sequence: u64) {
        let mut remove = Vec::new();
        for (unit, entry) in self.units.iter_mut() {
            if entry
                .durable
                .as_ref()
                .map(|d| d.sequence <= checkpoint_sequence)
                .unwrap_or(false)
            {
                if let Some(d) = entry.durable.take() {
                    self.bytes = self.bytes.saturating_sub(d.ciphertext.len() as u64);
                }
            }
            if entry.latest.sequence <= checkpoint_sequence {
                self.bytes = self
                    .bytes
                    .saturating_sub(entry.latest.ciphertext.len() as u64);
                remove.push(*unit);
            }
        }
        for unit in remove {
            self.units.remove(&unit);
        }
        self.pending_promotion
            .retain(|seq, _| *seq > checkpoint_sequence);
    }
}
