//! Ciphertext overlay: journal records not yet checkpointed (SPEC §23).
//!
//! Per unit we keep the *latest* version (serves reads) and, separately, the
//! latest *durable* version (what a checkpoint may apply). Keeping the
//! durable copy is what makes `checkpoint_sequence = durable_sequence` safe
//! when a newer, still-volatile overwrite of the same unit exists: without
//! it, deleting the journal segment holding the durable version would lose
//! the only crash-safe copy of that unit.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct OverlayVersion {
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Default)]
struct UnitOverlay {
    latest: OverlayVersion,
    durable: Option<OverlayVersion>,
}

#[derive(Default)]
pub struct Overlay {
    units: BTreeMap<u64, UnitOverlay>,
    /// sequence -> unit, promoted (moved into `durable`) once the journal
    /// reports the sequence durable. Processed strictly in sequence order.
    pending_promotion: BTreeMap<u64, u64>,
    bytes: u64,
    /// Highest durable boundary ever promoted to (debug sanitizer input).
    durable_boundary: u64,
    #[cfg(debug_assertions)]
    sanitizer_ticks: u64,
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

    /// Lowest unit currently held in the overlay.
    pub fn first_unit(&self) -> Option<u64> {
        self.units.keys().next().copied()
    }

    /// (oldest, newest) latest-version sequence across all units. O(units).
    pub fn sequence_bounds(&self) -> Option<(u64, u64)> {
        self.units
            .values()
            .map(|e| e.latest.sequence)
            .fold(None, |acc, s| match acc {
                None => Some((s, s)),
                Some((lo, hi)) => Some((lo.min(s), hi.max(s))),
            })
    }

    /// Publish a freshly journaled version (after successful append).
    pub fn publish(&mut self, unit: u64, sequence: u64, ciphertext: Vec<u8>) {
        self.bytes += ciphertext.len() as u64;
        let entry = self.units.entry(unit).or_default();
        if entry.latest.sequence != 0 {
            self.bytes = self
                .bytes
                .saturating_sub(entry.latest.ciphertext.len() as u64);
        }
        entry.latest = OverlayVersion {
            sequence,
            ciphertext,
        };
        self.pending_promotion.insert(sequence, unit);
        self.sanitize();
    }

    /// Latest version for reads.
    pub fn get(&self, unit: u64) -> Option<&OverlayVersion> {
        self.units.get(&unit).map(|e| &e.latest)
    }

    /// Advance the durable boundary: versions with sequence <=
    /// `durable_sequence` become checkpointable.
    pub fn promote(&mut self, durable_sequence: u64) {
        self.durable_boundary = self.durable_boundary.max(durable_sequence);
        while let Some((&seq, &unit)) = self.pending_promotion.first_key_value() {
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
                if entry.latest.sequence == seq
                    && entry
                        .durable
                        .as_ref()
                        .map(|d| d.sequence < seq)
                        .unwrap_or(true)
                {
                    if let Some(old) = entry.durable.take() {
                        self.bytes = self.bytes.saturating_sub(old.ciphertext.len() as u64);
                    }
                    self.bytes += entry.latest.ciphertext.len() as u64;
                    entry.durable = Some(entry.latest.clone());
                }
            }
        }
        self.sanitize();
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
        self.sanitize();
    }

    /// Debug-build sanitizer, run after every mutation. Cheap invariants
    /// always; the full O(n) audit on small overlays and periodically on
    /// large ones so debug stress tests stay quadratic-free.
    #[cfg(debug_assertions)]
    fn sanitize(&mut self) {
        self.sanitizer_ticks += 1;
        if self.units.len() > 4096 && !self.sanitizer_ticks.is_multiple_of(256) {
            return;
        }
        self.check_invariants();
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn sanitize(&mut self) {}

    /// Structural invariants of the overlay (SPEC §23). Panics on violation.
    ///
    /// * `bytes` equals the size of every live version (latest + durable).
    /// * A unit's durable version never leads its latest version, and an
    ///   equal sequence means identical bytes.
    /// * Every version at or below the promoted boundary has been promoted:
    ///   a latest version below the boundary *is* the durable version.
    /// * Durable versions never exceed the boundary.
    /// * Pending promotions are all above the boundary and name a unit
    ///   whose latest sequence is at least the pending one.
    pub fn check_invariants(&self) {
        let mut expected = 0u64;
        for (unit, e) in &self.units {
            assert!(
                e.latest.sequence != 0,
                "overlay sanitizer: unit {unit} has no latest version"
            );
            expected += e.latest.ciphertext.len() as u64;
            if let Some(d) = &e.durable {
                expected += d.ciphertext.len() as u64;
                assert!(
                    d.sequence <= e.latest.sequence,
                    "overlay sanitizer: unit {unit} durable {} > latest {}",
                    d.sequence,
                    e.latest.sequence
                );
                assert!(
                    d.sequence <= self.durable_boundary,
                    "overlay sanitizer: unit {unit} durable {} above boundary {}",
                    d.sequence,
                    self.durable_boundary
                );
                if d.sequence == e.latest.sequence {
                    assert!(
                        d.ciphertext == e.latest.ciphertext,
                        "overlay sanitizer: unit {unit} same sequence, different bytes"
                    );
                }
            }
            if e.latest.sequence <= self.durable_boundary {
                assert!(
                    e.durable
                        .as_ref()
                        .map(|d| d.sequence == e.latest.sequence)
                        .unwrap_or(false),
                    "overlay sanitizer: unit {unit} latest {} <= boundary {} but not promoted",
                    e.latest.sequence,
                    self.durable_boundary
                );
            }
        }
        assert_eq!(
            self.bytes, expected,
            "overlay sanitizer: byte accounting drifted"
        );
        for (seq, unit) in &self.pending_promotion {
            assert!(
                *seq > self.durable_boundary,
                "overlay sanitizer: pending {seq} at or below boundary {}",
                self.durable_boundary
            );
            let latest = self
                .units
                .get(unit)
                .map(|e| e.latest.sequence)
                .unwrap_or_else(|| {
                    panic!("overlay sanitizer: pending {seq} names missing unit {unit}")
                });
            assert!(
                latest >= *seq,
                "overlay sanitizer: pending {seq} newer than unit {unit} latest {latest}"
            );
        }
    }
}
