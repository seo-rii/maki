//! Recovery: runs before the volume is exposed (SPEC §27).
//!
//! ```text
//! acquire volume lock → select valid superblock → validate shard catalog
//! → validate allocation metadata → load checkpoint state → scan journal
//! → make the superblock and checkpoint state durable
//! → discard/truncate partial tail → bounded replay checkpoint → READY
//! ```
//! (The provider self-test, crypto-compatibility verification and the key
//! canary check are the attach layer's final steps, on top of this.)
//!
//! Scan policy — fail closed on anything that is not provably a crash
//! artifact:
//! - a torn tail is legal only in the *last* segment (older segments were
//!   fdatasync'd before their successor was created), and only *after* the
//!   prefix proved by the required v2 evidence (and advisory durable mark);
//! - a final segment shorter than a header, or entirely zero-filled, is a
//!   creation crash and is discarded, and so is a final segment exactly one
//!   header long whose header fails its checksum at an index above every
//!   segment the durable proof and mark name (the torn header writers that
//!   preallocated it left; damage there cannot be told from that tear, and
//!   such a file holds nothing acknowledged); any other invalid header is
//!   durable damage;
//! - the surviving journal must bridge from `checkpoint_sequence + 1` and
//!   be contiguous — a missing segment is never silently skipped;
//! - a segment larger than the writer can ever produce is rejected before
//!   it is read into memory;
//! - the selected checkpoint never lies above the required proof's horizon
//!   (checkpoints only consume records the proof attests);
//! - a surviving contiguous journal suffix through the checkpoint must
//!   agree with readable slot metadata for units recovery will not replay;
//! - metadata read errors other than "not found" are I/O errors, never
//!   "invalid copy" (an initialized volume must have checkpoint state).
//!
//! [`scan_journal`] is the read-only core of the scan: it returns the
//! records to replay together with the repairs recovery *would* apply
//! (discarding an unwritten final segment, truncating a torn tail). The
//! offline deep checker uses the same validation with payload retention
//! disabled; repair decisions and corruption checks remain shared.

use std::sync::Arc;

use maki_backing::{Backing, VolumeLock};
use maki_format::ab::{AbRecord, AbStore};
use maki_format::canary::KeyCanary;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::codec::strip_verify_crc;
use maki_format::durable_proof::{DurableProof, DurableProofStore};
use maki_format::journal::{
    max_segment_file_size, DurableMark, JournalRecord, ScanOutcome, SegmentHeader,
    DURABLE_MARK_SIZE, RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE,
};
use maki_format::layout;
use maki_format::superblock::{
    load_volume_superblock, load_volume_superblock_with_fallback, persist_volume_superblock,
    Superblock, VolumeSuperblock, SUPERBLOCK_VERSION_V2, SUPERBLOCK_VERSION_V3,
};
use maki_format::FormatError;

use crate::journal::{rewrite_verified_range_with_progress, SegmentInfo};
use crate::store::SlotStore;

#[path = "recovery_scan.rs"]
mod scan;
use scan::{range_is_zero, RecordHeader, SegmentScanner};

#[path = "checkpoint_evidence.rs"]
mod checkpoint_evidence;
use checkpoint_evidence::{CheckpointEvidence, MAX_CHECKPOINT_UNITS};

/// Observes completed, bounded recovery work, without claiming that a new
/// checkpoint is durable. The callback is borrowed only during recovery and
/// is never retained by the ready volume or its normal I/O path.
pub type RecoveryProgress<'a> = dyn Fn() + Send + Sync + 'a;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("VOLUME_ALREADY_ATTACHED")]
    AlreadyAttached,
    #[error("volume corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<crate::error::CoreError> for RecoveryError {
    fn from(e: crate::error::CoreError) -> Self {
        match e {
            crate::error::CoreError::Io(io) => RecoveryError::Io(io),
            crate::error::CoreError::Format(f) => RecoveryError::Format(f),
            other => RecoveryError::Corrupt(other.to_string()),
        }
    }
}

pub struct Recovered {
    pub lock: Box<dyn VolumeLock>,
    pub superblock: Superblock,
    pub store: SlotStore,
    pub checkpoint_state: CheckpointState,
    pub durable_sequence: u64,
    pub durable_proof: DurableProof,
    pub next_segment_index: u64,
    pub segments: Vec<SegmentInfo>,
    /// Records with sequence > checkpoint_sequence, in sequence order.
    pub replay: Vec<JournalRecord>,
}

/// A change recovery applies to the journal after a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRepair {
    /// A final segment that never completed its creation protocol.
    Discard { path: String },
    /// Truncate a torn tail; `len` is the resulting file length.
    Truncate { path: String, len: u64 },
}

/// Result of a read-only journal scan.
pub struct JournalScan {
    pub durable_sequence: u64,
    pub next_segment_index: u64,
    pub segments: Vec<SegmentInfo>,
    /// Records with sequence > checkpoint_sequence, in sequence order.
    pub replay: Vec<JournalRecord>,
    /// Units with at least one such record, when the scan was asked to
    /// collect units instead of payloads (`summarize_journal`).
    pub replay_units: std::collections::BTreeSet<u64>,
    /// The subset of `replay_units` whose newest such record carries
    /// ciphertext (not a v3 discard tombstone): after replay their slots
    /// hold data.
    pub replay_written: std::collections::BTreeSet<u64>,
    pub repairs: Vec<JournalRepair>,
    /// Whether a durable mark was found for the final segment.
    pub mark: Option<DurableMark>,
    /// Fingerprints bind recovery's later rewrite to the exact bytes this
    /// read-only scan accepted, with constant metadata per segment.
    verified_prefixes: Vec<VerifiedPrefix>,
    checkpoint_evidence: Option<CheckpointEvidence>,
}

struct VerifiedPrefix {
    path: String,
    len: u64,
    fingerprint: u64,
}

impl JournalScan {
    /// Validate covered record effects before any recovery writes. The
    /// initial scan collected the first window. On larger journals, reread
    /// the verified prefixes with fixed memory to check further unit ranges.
    fn verify_checkpoint_slots(
        &mut self,
        backing: &Arc<dyn Backing>,
        superblock: &Superblock,
        store: &SlotStore,
        checkpoint_sequence: u64,
        progress: &RecoveryProgress<'_>,
    ) -> Result<(), RecoveryError> {
        let Some(mut evidence) = self.checkpoint_evidence.take() else {
            return Ok(());
        };
        let suffix_start = evidence.suffix_start();
        while let Some(first_unit) = evidence.verify(store, progress)? {
            evidence =
                CheckpointEvidence::new(checkpoint_sequence, first_unit, MAX_CHECKPOINT_UNITS);
            for (segment, prefix) in self.segments.iter().zip(&self.verified_prefixes) {
                if segment.record_count == 0
                    || suffix_start.is_some_and(|first| segment.last_sequence() < first)
                {
                    continue;
                }
                let file = backing.open(&prefix.path, false)?;
                let mut header = [0u8; SEGMENT_HEADER_SIZE];
                file.read_at(0, &mut header)?;
                let body_len = prefix.len - SEGMENT_HEADER_SIZE as u64;
                let scan = SegmentScanner {
                    file: file.as_ref(),
                    header: &header,
                    body_len,
                    first_sequence: segment.base_sequence,
                    durable_len: body_len,
                    required_boundary: None,
                    geometry: &superblock.geometry,
                    // This pass needs only metadata from the accepted prefix.
                    checkpoint_sequence: u64::MAX,
                    name: &prefix.path,
                    progress,
                }
                .scan_observing(false, |header, _| {
                    evidence.observe(header);
                    Ok(())
                })?;
                if !matches!(scan.outcome, ScanOutcome::Clean)
                    || scan.valid_body_bytes != body_len
                    || scan.record_count != segment.record_count
                    || scan.fingerprint != prefix.fingerprint
                {
                    return Err(RecoveryError::Corrupt(format!(
                        "{} changed during checkpoint verification",
                        prefix.path
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The public scan/recovery APIs expose every uncovered record. Volume attach
/// discards payloads during validation and reads them again through a bounded
/// checkpoint batch. Select retention independently of validation so the
/// public API and attach can share every durability check.
enum ReplayRecords {
    All(Vec<JournalRecord>),
    /// The public journal-only API returns records without comparing slots.
    ScanOnly(Vec<JournalRecord>),
    Discard,
    /// Only the units that have an uncovered replay record: what the deep
    /// checker needs to tell recoverable slot damage from unrecoverable
    /// damage (R4-004), and which of them hold ciphertext after replay (the
    /// key-canary verdict). At most two `u64` per distinct unit, no payloads.
    Units {
        units: std::collections::BTreeSet<u64>,
        written: std::collections::BTreeSet<u64>,
    },
}

impl ReplayRecords {
    fn retain_payloads(&self) -> bool {
        matches!(self, Self::All(_) | Self::ScanOnly(_))
    }

    fn push(&mut self, header: RecordHeader, payload: Option<Vec<u8>>) {
        match self {
            Self::All(records) | Self::ScanOnly(records) => records.push(JournalRecord {
                sequence: header.sequence,
                unit_index: header.unit,
                payload: payload.expect("uncovered replay payload requested"),
            }),
            Self::Discard => {}
            Self::Units { units, written } => {
                units.insert(header.unit);
                // Records arrive in sequence order: the newest one decides.
                if header.payload_len == 0 {
                    written.remove(&header.unit);
                } else {
                    written.insert(header.unit);
                }
            }
        }
    }

    /// (retained records, units with an uncovered record, those of them
    /// whose newest record carries ciphertext). Only the mode that was
    /// asked for is populated; the other parts are empty.
    fn into_parts(
        self,
    ) -> (
        Vec<JournalRecord>,
        std::collections::BTreeSet<u64>,
        std::collections::BTreeSet<u64>,
    ) {
        match self {
            Self::All(records) | Self::ScanOnly(records) => {
                (records, Default::default(), Default::default())
            }
            Self::Discard => Default::default(),
            Self::Units { units, written } => (Vec::new(), units, written),
        }
    }
}

/// Recover a volume. `segment_size` is the writer's effective segment size.
/// A segment file may be as large as any configuration's writer can produce
/// (`max_journal_segment_file_size`), so a segment written before the size
/// was lowered stays readable (R5-033); a larger `segment_size` raises that
/// bound.
pub fn recover(backing: &Arc<dyn Backing>, segment_size: u64) -> Result<Recovered, RecoveryError> {
    recover_with_replay(
        backing,
        segment_size,
        ReplayRecords::All(Vec::new()),
        false,
        &|| {},
    )
}

/// Attach validates without retaining replay payload history, then checkpoints
/// the accepted records through a fixed-size working set before exposing the
/// volume. Payload memory is bounded independently of journal fill ratio and
/// distinct unit count.
pub(crate) fn recover_bounded(
    backing: &Arc<dyn Backing>,
    segment_size: u64,
    progress: &RecoveryProgress<'_>,
) -> Result<Recovered, RecoveryError> {
    recover_with_replay(
        backing,
        segment_size,
        ReplayRecords::Discard,
        true,
        progress,
    )
}

fn recover_with_replay(
    backing: &Arc<dyn Backing>,
    segment_size: u64,
    replay: ReplayRecords,
    checkpoint_replay: bool,
    progress: &RecoveryProgress<'_>,
) -> Result<Recovered, RecoveryError> {
    // 1. exclusive volume lock
    let lock = acquire_lock(backing)?;
    progress();

    // 2. superblock
    let (envelope, invalid_partner) = load_volume_superblock_with_fallback(backing.as_ref())?;
    if !matches!(
        envelope.metadata_version,
        SUPERBLOCK_VERSION_V2 | SUPERBLOCK_VERSION_V3
    ) {
        return Err(RecoveryError::Format(FormatError::Unsupported(
            "legacy v1 volume requires an explicit migration; writable recovery refuses it without changing recovery metadata".into(),
        )));
    }
    let superblock = envelope.superblock.clone();
    // Missing evidence must fail even on an empty-looking volume, before
    // checkpoint metadata or any recovery repair is written.
    let mut durable_proof = DurableProofStore::load(backing.as_ref(), superblock.volume_uuid)?;
    progress();

    // 3./4. catalog + allocation metadata
    let mut store = SlotStore::open_from_superblock(backing.clone(), &envelope, progress)?;

    // checkpoint state
    let checkpoint_state = load_checkpoint_state(backing)?;
    check_checkpoint_horizon(checkpoint_state.checkpoint_sequence, &durable_proof)?;
    progress();

    // 5./6. scan journal, then apply the repairs the scan decided on
    let mut scan = scan_journal_with_proof(
        backing,
        &superblock,
        checkpoint_state.checkpoint_sequence,
        segment_size,
        Some(&durable_proof),
        replay,
        progress,
    )?;
    scan.verify_checkpoint_slots(
        backing,
        &superblock,
        &store,
        checkpoint_state.checkpoint_sequence,
        progress,
    )?;
    // This recovery, the attach after it and later checkpoints store A/B
    // metadata; refuse a generation that leaves no room before any write.
    check_metadata_generations(
        backing,
        &store,
        invalid_partner.is_none().then_some(superblock.generation),
    )?;
    // The superblock is the volume's commit point; every repair below, and
    // the resumed writer, depends on it. A failed or interrupted creation, or
    // a restart, can hand recovery a copy that exists only in the page cache
    // (K-01): accepting it as is lets FUA/FLUSH succeed on a volume the next
    // power loss turns into "no valid superblock". Rewrite and sync both
    // copies first, the selected one before the other, completing a copy an
    // interrupted creation never wrote. The scan above is read-only, so the
    // required-horizon checks still precede every recovery write.
    let superblock = persist_volume_superblock(backing.as_ref(), &envelope)?.superblock;
    progress();
    // The selected checkpoint state gates which journal segments a later
    // checkpoint may reclaim (`allow_covered_holes_below`, `delete_covered`).
    // A restart hands recovery page-cache bytes that were never fdatasync'd,
    // so the highest-generation copy we just chose may be durable only in the
    // cache. If the writer then reclaims journal covered by it and a power
    // loss follows, an older checkpoint would resurface with its covering
    // segments already gone, and the next recovery would refuse to bridge
    // ("base sequence N does not bridge from checkpoint M", BUG-022). Make
    // the selected state durable *now*, before the writer resumes: re-store
    // it (which rewrites and syncs a copy, and, per the A/B rules, preserves
    // the other valid side first). A failure here fails recovery closed
    // rather than reclaiming journal against a volatile checkpoint.
    {
        let ck_ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
        let mut durable_checkpoint = checkpoint_state.clone();
        ck_ab.store(backing.as_ref(), &mut durable_checkpoint)?;
        backing.sync_dir(layout::CHECKPOINT_DIR)?;
        progress();
    }

    for repair in &scan.repairs {
        match repair {
            JournalRepair::Discard { path } => {
                backing.remove(path)?;
                backing.sync_dir(layout::JOURNAL_DIR)?;
            }
            JournalRepair::Truncate { path, len } => {
                let file = backing.open(path, false)?;
                file.set_len(*len)?;
                file.sync_data()?;
            }
        }
        progress();
    }

    // 7. Everything the scan accepted is durable *from now on*. A process
    //    restart (no power loss) hands recovery page-cache bytes that were
    //    never fdatasync'd; the writer resumes with every segment sealed and
    //    no active one, so no later barrier would ever sync them, a FLUSH
    //    would acknowledge them anyway, and a successor segment would turn
    //    their torn tail into "corruption" after a real power loss (S-06).
    //    A writeback EIO may also have cleared the cached pages' dirty bits:
    //    plain fsync can then succeed without writing them. Rewrite each
    //    accepted prefix and its exact length, verify it against the scan,
    //    and only then sync it. A prior recovery may have truncated a tail
    //    before a failed sync: its next scan sees the short cached length,
    //    so no explicit Truncate repair is emitted, while disk still holds
    //    the old tail (BUG-020).
    for prefix in &scan.verified_prefixes {
        let file = backing.open(&prefix.path, false)?;
        file.set_len(prefix.len)?;
        rewrite_verified_range_with_progress(
            file.as_ref(),
            0..prefix.len,
            prefix.fingerprint,
            progress,
        )?;
        file.sync_data()?;
        progress();
    }
    if let Some(last) = scan.segments.last() {
        backing.sync_dir(layout::JOURNAL_DIR)?;
        let mark = DurableMark {
            segment_index: last.index,
            durable_size: last.size,
        };
        let file = backing.open(layout::JOURNAL_DURABLE_MARK, true)?;
        file.write_at(0, &mark.encode())?;
        file.sync_data()?;
        progress();
    }

    // Recovery adopts every accepted tail as durable. Publish that decision
    // in both required copies before exposing the resumed writer. If the
    // checkpoint already covers the old proof's segment, retain its location;
    // it is valid for that segment to have been pruned.
    if scan.durable_sequence > durable_proof.durable_sequence {
        if let Some(last) = horizon_end(&scan.segments, scan.durable_sequence) {
            durable_proof.durable_sequence = scan.durable_sequence;
            durable_proof.segment_index = last.index;
            durable_proof.durable_size = last.size;
        } else if scan.durable_sequence > checkpoint_state.checkpoint_sequence {
            return Err(RecoveryError::Corrupt(
                "recovered durable horizon has no journal boundary".into(),
            ));
        }
    }
    DurableProofStore::advance(backing.as_ref(), &mut durable_proof)?;
    progress();

    let (checkpoint_state, segments) =
        if checkpoint_replay && scan.durable_sequence > checkpoint_state.checkpoint_sequence {
            let checkpoint_state = checkpoint_validated_replay(
                backing,
                &superblock,
                &mut store,
                &checkpoint_state,
                &scan,
                progress,
            )?;
            (checkpoint_state, Vec::new())
        } else {
            (checkpoint_state, scan.segments)
        };

    // Valid discard copies may still contain different generations after a
    // failed two-copy publication. Replay selected the authoritative logical
    // value when necessary; restabilize it into both sides even when there
    // was no replay before exposing the volume or pruning later journal.
    store.persist_discards_with_progress(progress)?;
    progress();

    Ok(Recovered {
        lock,
        superblock,
        store,
        checkpoint_state,
        durable_sequence: scan.durable_sequence,
        durable_proof,
        next_segment_index: scan.next_segment_index,
        segments,
        replay: scan.replay,
    })
}

// A target for grouped records, not a cap on a geometry-valid single record.
const REPLAY_BATCH_BYTES: usize = 1 << 20;

fn checkpoint_validated_replay(
    backing: &Arc<dyn Backing>,
    superblock: &Superblock,
    store: &mut SlotStore,
    checkpoint_state: &CheckpointState,
    scan: &JournalScan,
    progress: &RecoveryProgress<'_>,
) -> Result<CheckpointState, RecoveryError> {
    let allow_discard = store.supports_discard();
    let mut batch = Vec::new();
    let mut batch_bytes = 0usize;

    for segment in &scan.segments {
        let path = layout::journal_segment(segment.index);
        let name = path.rsplit('/').next().unwrap_or(&path);
        let file = backing.open(&path, false)?;
        let mut header = [0u8; SEGMENT_HEADER_SIZE];
        file.read_at(0, &mut header)?;
        let decoded = SegmentHeader::decode(&header).map_err(|error| {
            RecoveryError::Corrupt(format!(
                "journal segment {name} changed after validation: {error}"
            ))
        })?;
        if decoded.segment_index != segment.index
            || decoded.base_sequence != segment.base_sequence
            || decoded.volume_uuid != superblock.volume_uuid
        {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name} changed after validation"
            )));
        }
        let body_len = segment
            .size
            .checked_sub(SEGMENT_HEADER_SIZE as u64)
            .ok_or_else(|| {
                RecoveryError::Corrupt(format!("journal segment {name} is too short"))
            })?;
        let replayed = SegmentScanner {
            file: file.as_ref(),
            header: &header,
            body_len,
            first_sequence: segment.base_sequence,
            durable_len: body_len,
            required_boundary: None,
            geometry: &superblock.geometry,
            checkpoint_sequence: checkpoint_state.checkpoint_sequence,
            name,
            progress,
        }
        .scan(|record| {
            let record_bytes = RECORD_HEADER_SIZE.saturating_add(record.payload.len());
            if !batch.is_empty() && batch_bytes.saturating_add(record_bytes) > REPLAY_BATCH_BYTES {
                apply_replay_batch(store, &mut batch, allow_discard, progress)?;
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes.saturating_add(record_bytes);
            batch.push(record);
            // Do not retain a full/oversized batch while the scanner allocates
            // its next payload. A single permitted ciphertext can exceed the
            // target, but is applied and dropped before the scan continues.
            if batch_bytes >= REPLAY_BATCH_BYTES {
                apply_replay_batch(store, &mut batch, allow_discard, progress)?;
                batch_bytes = 0;
            }
            Ok(())
        })?;
        if replayed.record_count != segment.record_count
            || replayed.valid_body_bytes != body_len
            || !matches!(replayed.outcome, ScanOutcome::Clean)
        {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name} changed after validation"
            )));
        }
    }
    apply_replay_batch(store, &mut batch, allow_discard, progress)?;

    let mut new_state = checkpoint_state.clone();
    new_state.checkpoint_sequence = scan.durable_sequence;
    AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B).store(backing.as_ref(), &mut new_state)?;
    backing.sync_dir(layout::CHECKPOINT_DIR)?;
    progress();

    for segment in &scan.segments {
        backing.remove(&layout::journal_segment(segment.index))?;
        progress();
    }
    backing.sync_dir(layout::JOURNAL_DIR)?;
    progress();
    Ok(new_state)
}

fn apply_replay_batch(
    store: &mut SlotStore,
    records: &mut Vec<JournalRecord>,
    allow_discard: bool,
    progress: &RecoveryProgress<'_>,
) -> Result<(), RecoveryError> {
    if records.is_empty() {
        return Ok(());
    }
    // The scanner already validated every record in sequence order. Keep
    // the existing byte-bounded batch and metadata evidence, but avoid
    // writing superseded ciphertext to the same slot within this batch.
    // A latest discard suppresses earlier slot writes as well.
    let latest_sequences: std::collections::HashMap<_, _> = records
        .iter()
        .map(|record| (record.unit_index, record.sequence))
        .collect();
    let latest_writes = || {
        records.iter().filter(|record| {
            latest_sequences.get(&record.unit_index) == Some(&record.sequence)
                && (!allow_discard || !record.payload.is_empty())
        })
    };
    for record in latest_writes() {
        store.write_slot(record.unit_index, record.sequence, &record.payload)?;
        progress();
    }
    for shard in store.shards_of_units(latest_writes().map(|record| &record.unit_index)) {
        store.sync_shard_data(shard)?;
        progress();
    }
    // Preserve evidence of every accepted write, even when a later discard
    // skipped its slot data. This also creates any required shard before
    // publishing its final discard state; metadata ordering is unchanged.
    for record in records.iter() {
        if !allow_discard || !record.payload.is_empty() {
            store.mark_allocated(record.unit_index)?;
            progress();
        }
    }
    if allow_discard {
        for record in records.iter() {
            store.set_discarded(record.unit_index, record.payload.is_empty())?;
            progress();
        }
        store.persist_discards_with_progress(progress)?;
    }
    store.persist_allocations_with_progress(progress)?;
    records.clear();
    progress();
    Ok(())
}

/// The exclusive volume lock (`VOLUME_ALREADY_ATTACHED` when held).
pub fn acquire_lock(backing: &Arc<dyn Backing>) -> Result<Box<dyn VolumeLock>, RecoveryError> {
    backing.try_lock(layout::VOLUME_LOCK).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            RecoveryError::AlreadyAttached
        } else {
            RecoveryError::Io(e)
        }
    })
}

pub fn load_superblock(backing: &Arc<dyn Backing>) -> Result<Superblock, RecoveryError> {
    Ok(load_volume_superblock(backing.as_ref())?.superblock)
}

/// Checkpoint state is written at volume creation, so an initialized volume
/// always has at least one valid copy. Losing both is damage — restarting
/// at sequence 0 would replay stale journal history over newer slots.
pub fn load_checkpoint_state(backing: &Arc<dyn Backing>) -> Result<CheckpointState, RecoveryError> {
    AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B)
        .load::<CheckpointState>(backing.as_ref())?
        .ok_or_else(|| RecoveryError::Corrupt("no valid checkpoint state copy".to_string()))
}

/// Read-only journal scan: verifies every segment, decides the repairs a
/// recovery would apply, and collects the records newer than the checkpoint.
/// Segment validation uses fixed read scratch and at most one bounded payload
/// candidate; checkpoint-covered payloads are discarded immediately. The replay
/// result still retains all uncovered payloads and is not a total recovery-memory
/// bound (MAKI-025 remains partially addressed).
pub fn scan_journal(
    backing: &Arc<dyn Backing>,
    superblock: &Superblock,
    checkpoint_sequence: u64,
    segment_size: u64,
) -> Result<JournalScan, RecoveryError> {
    scan_journal_with_replay(
        backing,
        superblock,
        checkpoint_sequence,
        segment_size,
        ReplayRecords::ScanOnly(Vec::new()),
    )
}

/// The checker needs counts and repair decisions, not replay payloads. Keep
/// the empty replay representation private so the public all-record API keeps
/// its contract. Each candidate is fully validated with fixed read scratch.
pub(crate) struct JournalSummary {
    pub segment_count: usize,
    pub uncovered_records: u64,
    pub durable_sequence: u64,
    pub repairs: Vec<JournalRepair>,
    /// Units recovery would rewrite (or discard) from a validated record:
    /// damage to their slots is recoverable (R4-004).
    pub replay_units: std::collections::BTreeSet<u64>,
    /// Those of them whose newest record carries ciphertext.
    pub replay_written: std::collections::BTreeSet<u64>,
}

pub(crate) fn summarize_journal(
    backing: &Arc<dyn Backing>,
    envelope: &VolumeSuperblock,
    checkpoint_sequence: u64,
    segment_size: u64,
    store: Option<&SlotStore>,
) -> Result<JournalSummary, RecoveryError> {
    // The deep check scans against the volume's stored checkpoint state, so
    // it applies the rule recovery applies to that state.
    let superblock = &envelope.superblock;
    let proof = load_required_proof(backing, envelope)?;
    if let Some(proof) = &proof {
        check_checkpoint_horizon(checkpoint_sequence, proof)?;
    }
    let mut scan = scan_journal_with_proof(
        backing,
        superblock,
        checkpoint_sequence,
        segment_size,
        proof.as_ref(),
        ReplayRecords::Units {
            units: Default::default(),
            written: Default::default(),
        },
        &|| {},
    )?;
    if let Some(store) = store {
        scan.verify_checkpoint_slots(backing, superblock, store, checkpoint_sequence, &|| {})?;
    }
    let uncovered_records = scan
        .segments
        .iter()
        .map(|segment| {
            segment
                .record_count
                .min(segment.last_sequence().saturating_sub(checkpoint_sequence))
        })
        .sum();
    Ok(JournalSummary {
        segment_count: scan.segments.len(),
        uncovered_records,
        durable_sequence: scan.durable_sequence,
        repairs: scan.repairs,
        replay_units: scan.replay_units,
        replay_written: scan.replay_written,
    })
}

fn scan_journal_with_replay(
    backing: &Arc<dyn Backing>,
    superblock: &Superblock,
    checkpoint_sequence: u64,
    segment_size: u64,
    replay: ReplayRecords,
) -> Result<JournalScan, RecoveryError> {
    let envelope = load_volume_superblock(backing.as_ref())?;
    if envelope.superblock.volume_uuid != superblock.volume_uuid {
        return Err(RecoveryError::Corrupt(
            "journal scan superblock identity mismatch".into(),
        ));
    }
    let proof = load_required_proof(backing, &envelope)?;
    scan_journal_with_proof(
        backing,
        superblock,
        checkpoint_sequence,
        segment_size,
        proof.as_ref(),
        replay,
        &|| {},
    )
}

/// The required durable proof of a v2/v3 volume; `None` for a legacy v1
/// volume, whose read-only inspection retains its historical classification.
fn load_required_proof(
    backing: &Arc<dyn Backing>,
    envelope: &VolumeSuperblock,
) -> Result<Option<DurableProof>, RecoveryError> {
    if !matches!(
        envelope.metadata_version,
        SUPERBLOCK_VERSION_V2 | SUPERBLOCK_VERSION_V3
    ) {
        return Ok(None);
    }
    Ok(Some(DurableProofStore::load(
        backing.as_ref(),
        envelope.superblock.volume_uuid,
    )?))
}

/// A record becomes checkpoint-eligible only once both proof copies attest
/// it, and recovery publishes the proof before it advances the checkpoint,
/// so no crash or restart leaves the stored checkpoint above the proof.
/// Accepting one would treat the acknowledged records between the two as
/// applied, and let a later checkpoint prune them, although no slot holds
/// them. Recovery and the deep check refuse it before any recovery write.
fn check_checkpoint_horizon(
    checkpoint_sequence: u64,
    proof: &DurableProof,
) -> Result<(), RecoveryError> {
    if checkpoint_sequence > proof.durable_sequence {
        return Err(RecoveryError::Corrupt(format!(
            "checkpoint sequence {checkpoint_sequence} is above the required durable proof's \
             horizon {}; checkpoints only consume records the proof attests",
            proof.durable_sequence
        )));
    }
    Ok(())
}

fn scan_journal_with_proof(
    backing: &Arc<dyn Backing>,
    superblock: &Superblock,
    checkpoint_sequence: u64,
    segment_size: u64,
    proof: Option<&DurableProof>,
    mut replay: ReplayRecords,
    progress: &RecoveryProgress<'_>,
) -> Result<JournalScan, RecoveryError> {
    // A resumed writer must have a representable next sequence. Validate
    // even an empty journal here, before recovery persists its checkpoint
    // or proof; JournalWriter::resume is already past that mutation boundary.
    let after_checkpoint = checkpoint_sequence.checked_add(1).ok_or_else(|| {
        RecoveryError::Corrupt("checkpoint sequence has no representable successor".into())
    })?;
    // V2 never relies solely on this optional advisory lower bound.
    let mark = load_durable_mark(backing)?;
    let required = proof.filter(|proof| proof.durable_sequence > checkpoint_sequence);
    let mut required_seen = false;
    let mut checkpoint_evidence = proof
        .filter(|_| checkpoint_sequence != 0 && !matches!(&replay, ReplayRecords::ScanOnly(_)))
        .map(|_| CheckpointEvidence::new(checkpoint_sequence, 0, MAX_CHECKPOINT_UNITS));

    // Only segment names matter here, and they are ASCII: any other entry,
    // one whose name is not UTF-8 included, is ignored.
    let mut names: Vec<(u64, String)> = backing
        .list_skipping_non_utf8(layout::JOURNAL_DIR)?
        .into_iter()
        .filter_map(|n| layout::parse_journal_segment(&n).map(|i| (i, n)))
        .collect();
    names.sort();
    progress();

    // Bounded by the largest size any configuration may use, so a segment
    // written before `journal_segment_size` was lowered stays readable
    // (R5-033); a library caller's larger size still counts.
    let max_file_size = max_segment_file_size(segment_size)
        .max(maki_format::journal::max_journal_segment_file_size());
    let mut segments: Vec<SegmentInfo> = Vec::new();
    let mut repairs: Vec<JournalRepair> = Vec::new();
    let mut prev_last_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;
    let mut final_mark: Option<DurableMark> = None;
    let mut verified_prefixes = Vec::new();

    let count = names.len();
    for (pos, (index, name)) in names.into_iter().enumerate() {
        let is_last = pos + 1 == count;
        let path = format!("{}/{}", layout::JOURNAL_DIR, name);
        let file = backing.open(&path, false)?;
        let len = file.len()?;

        if len > max_file_size {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: size {len} exceeds maximum {max_file_size}, larger than \
                 any journal segment a writer can produce"
            )));
        }

        // What the durable mark proves about *this* segment, if anything.
        let proof_here = proof.filter(|p| p.durable_sequence > 0 && p.segment_index == index);
        let marked_durable: Option<u64> = mark
            .filter(|m| m.segment_index == index)
            .map(|m| m.durable_size)
            .into_iter()
            .chain(proof_here.map(|p| p.durable_size))
            .max();
        if let Some(durable) = marked_durable {
            if durable > len {
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {name}: durable mark covers {durable} bytes but file has {len}"
                )));
            }
        }
        if is_last {
            final_mark = mark.filter(|m| m.segment_index == index);
        }

        // Shorter than a header: the creation protocol never reached its
        // fdatasync, so no record can have been acknowledged from it.
        if len < SEGMENT_HEADER_SIZE as u64 {
            if is_last && marked_durable.is_none() {
                repairs.push(JournalRepair::Discard { path });
                continue;
            }
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: truncated header in non-final or synced segment"
            )));
        }

        let mut header_bytes = [0u8; SEGMENT_HEADER_SIZE];
        file.read_at(0, &mut header_bytes)?;
        let header = match SegmentHeader::decode(&header_bytes) {
            Ok(h) => h,
            Err(e) => {
                if is_last && marked_durable.is_none() {
                    // A never-written (zero-filled) final segment is a
                    // creation crash.
                    let unwritten = range_is_zero(file.as_ref(), 0..len, progress)?;
                    // So is a final segment exactly one header long whose
                    // header is torn (fails its checksum) above everything
                    // the durable evidence names: writers that extended a
                    // new segment to a full header before writing it left
                    // this when the write tore and the failed creation's
                    // cleanup never finished. It holds no record byte, and
                    // no acknowledged record can live at its index.
                    let torn_creation = len == SEGMENT_HEADER_SIZE as u64
                        && strip_verify_crc(&header_bytes, "journal segment header").is_err()
                        && above_durable_evidence(index, proof, mark);
                    if unwritten || torn_creation {
                        repairs.push(JournalRepair::Discard { path });
                        continue;
                    }
                }
                // Anything else with a full-sized header is damage,
                // including an intact (checksum-valid) one that does not
                // decode.
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {name}: invalid header ({e})"
                )));
            }
        };
        if header.volume_uuid != superblock.volume_uuid {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: foreign volume uuid"
            )));
        }
        if header.segment_index != index {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: header index {} mismatch",
                header.segment_index
            )));
        }

        // The oldest surviving segment must connect to the checkpoint
        // boundary; a later base means an uncheckpointed segment is gone.
        if prev_last_seq.is_none() && header.base_sequence > after_checkpoint {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: base sequence {} does not bridge from checkpoint {}",
                header.base_sequence, checkpoint_sequence
            )));
        }

        let body_len = len - SEGMENT_HEADER_SIZE as u64;
        // Non-final segments were fdatasync'd in full before their
        // successor was created; the final one uses the stronger of the
        // required proof and the advisory mark. If neither covers it, that
        // successor has no proven durable records, so damage after its
        // header can be an unacknowledged torn tail. Never
        // fall back to classifying by what follows the damage: unsynced
        // records persist in any order, and an intact record after a torn
        // one is a normal crash state (M-007, S-04).
        let durable_len = if is_last {
            marked_durable
                .map(|d| d.saturating_sub(SEGMENT_HEADER_SIZE as u64))
                .unwrap_or(0)
        } else {
            body_len
        };
        let scanned = SegmentScanner {
            file: file.as_ref(),
            header: &header_bytes,
            body_len,
            first_sequence: header.base_sequence,
            durable_len,
            required_boundary: required.filter(|p| p.segment_index == index).map(|p| {
                (
                    p.durable_sequence,
                    p.durable_size - SEGMENT_HEADER_SIZE as u64,
                )
            }),
            geometry: &superblock.geometry,
            checkpoint_sequence,
            name: &name,
            progress,
        }
        .scan_observing(replay.retain_payloads(), |header, payload| {
            if let Some(evidence) = &mut checkpoint_evidence {
                evidence.observe(header);
            }
            if header.sequence > checkpoint_sequence {
                replay.push(header, payload);
            }
            Ok(())
        })?;
        if required.is_some_and(|p| p.segment_index == index) {
            required_seen = true;
        }

        let mut size = len;
        match scanned.outcome {
            ScanOutcome::Clean => {
                // A clean scan may still end in a zero-filled tail (a torn
                // unsynced record whose sectors never arrived). It is
                // harmless in the final segment, but the writer seals that
                // segment as-is when it opens a successor, and a non-final
                // segment is durable in full — the same zeros would then be
                // corruption. Normalize the final segment to exactly its
                // records so no sealed segment ever carries a zero tail.
                if is_last && scanned.valid_body_bytes < body_len {
                    size = SEGMENT_HEADER_SIZE as u64 + scanned.valid_body_bytes;
                    repairs.push(JournalRepair::Truncate {
                        path: path.clone(),
                        len: size,
                    });
                }
            }
            ScanOutcome::TornTail { at } => {
                if !is_last {
                    return Err(RecoveryError::Corrupt(format!(
                        "journal segment {name}: torn tail in non-final segment"
                    )));
                }
                // discard/truncate partial tail (SPEC §27)
                size = SEGMENT_HEADER_SIZE as u64 + at as u64;
                repairs.push(JournalRepair::Truncate {
                    path: path.clone(),
                    len: size,
                });
            }
            ScanOutcome::Corrupt { at, reason } => {
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {name}: corrupt at body offset {at}: {reason}"
                )));
            }
        }

        // The exclusive end must fit as well as each record's sequence:
        // accepting a final record at MAX would leave no next writer value.
        // Compute the end before subtracting one so even that intermediate
        // addition cannot wrap in release builds.
        let record_count = scanned.record_count;
        let after_segment = header
            .base_sequence
            .checked_add(record_count)
            .ok_or_else(|| {
                RecoveryError::Corrupt(format!(
                    "journal segment {name}: sequence range has no representable successor"
                ))
            })?;
        let last = after_segment.saturating_sub(1);

        // Cross-segment sequence continuity. Segments fully covered by the
        // checkpoint are deleted by it; a crash can lose some of those
        // unlinks and not others, so a *covered* prefix may have holes.
        // Only records above the checkpoint must be contiguous, and the
        // first uncovered segment must bridge the checkpoint (checked
        // below).
        if let Some(prev) = prev_last_seq {
            if header.base_sequence != prev + 1 {
                let hole_is_covered =
                    prev <= checkpoint_sequence && header.base_sequence <= after_checkpoint;
                if !hole_is_covered {
                    return Err(RecoveryError::Corrupt(format!(
                        "journal segment {name}: base sequence {} does not follow {}",
                        header.base_sequence, prev
                    )));
                }
            }
        }
        prev_last_seq = Some(last);
        max_seq = max_seq.max(last);

        segments.push(SegmentInfo {
            index,
            base_sequence: header.base_sequence,
            record_count,
            size,
        });
        // This fingerprint is ephemeral, never written to the disk format.
        // CRC32 over CRC-protected headers would have a constant residue
        // and fail to bind their contents, so use a different hash here.
        verified_prefixes.push(VerifiedPrefix {
            path,
            len: size,
            fingerprint: scanned.fingerprint,
        });
    }

    if required.is_some() && !required_seen {
        return Err(RecoveryError::Corrupt(
            "required durable journal segment is missing; refusing to discard acknowledged history"
                .into(),
        ));
    }
    let durable_sequence = checkpoint_sequence.max(max_seq);
    // Segment indexes must never be reused: the durable mark is a plain,
    // never-cleaned file naming the newest segment it saw, so a fresh
    // segment under an old index would be judged against a stale mark
    // (a checkpoint right after recovery can delete every segment, which
    // used to restart numbering at zero). Continue above both the surviving
    // segments and the mark.
    let highest_segment_index = segments
        .iter()
        .map(|s| s.index)
        .chain(mark.map(|m| m.segment_index))
        .chain(
            proof
                .filter(|p| p.durable_sequence > 0)
                .map(|p| p.segment_index),
        )
        .max();
    let next_segment_index = match highest_segment_index {
        Some(index) => index.checked_add(1).ok_or_else(|| {
            RecoveryError::Corrupt("journal segment index has no representable successor".into())
        })?,
        None => 0,
    };
    // A resumed writer opens a new segment for its first append and refuses
    // `u64::MAX` as a record sequence or a segment index
    // (`JournalWriter::check_append`). A horizon or index that leaves no
    // value for one more record and one more segment would make every write
    // fail forever, on a volume the deep check called clean. Each value is
    // consumed one record or one segment at a time, so in practice only
    // damage gets there: refuse it rather than attach a volume nothing can
    // write. The advisory mark counts like a segment (S-03: numbering never
    // falls back below it). Read-only legacy inspection keeps its historical
    // classification.
    if proof.is_some() {
        if durable_sequence.checked_add(2).is_none() {
            return Err(RecoveryError::Corrupt(format!(
                "journal sequence space exhausted: durable sequence {durable_sequence} leaves no \
                 sequence for another record"
            )));
        }
        if next_segment_index == u64::MAX {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment index space exhausted: segment index {} (of a surviving \
                 segment, the durable proof or the durable mark) leaves no index for another \
                 segment",
                u64::MAX - 1
            )));
        }
    }

    // Recovery publishes the accepted horizon as the new proof, whose record
    // end must follow the stored one (`DurableProof::follows`). A proof the
    // checkpoint covers is not matched against the journal above it, so
    // refuse here, read-only, a stored location at or beyond the end of the
    // newer records: segment indexes only grow and a proof names its own
    // record end, so no writer leaves one, and the deep check must refuse
    // what recovery refuses.
    if let Some(proof) = proof.filter(|proof| durable_sequence > proof.durable_sequence) {
        if let Some(end) = horizon_end(&segments, durable_sequence) {
            if (end.index, end.size) <= (proof.segment_index, proof.durable_size) {
                return Err(RecoveryError::Corrupt(format!(
                    "durable proof for sequence {} names segment {} byte {}, at or beyond \
                     the end of the newer journal records (segment {} byte {})",
                    proof.durable_sequence,
                    proof.segment_index,
                    proof.durable_size,
                    end.index,
                    end.size
                )));
            }
        }
    }

    let (replay, replay_units, replay_written) = replay.into_parts();
    Ok(JournalScan {
        durable_sequence,
        next_segment_index,
        segments,
        replay,
        replay_units,
        replay_written,
        repairs,
        mark: final_mark,
        verified_prefixes,
        checkpoint_evidence,
    })
}

/// Whether segment `index` lies above every segment the durable evidence
/// names. The required proof is published to both copies before every
/// acknowledgement and names the segment holding its horizon, so every
/// acknowledged record lies in that segment or an earlier one; an empty proof
/// (sequence 0) has acknowledged nothing. The advisory mark names a segment
/// only once its creation completed. Without a proof (read-only legacy
/// inspection) nothing vouches for any index.
fn above_durable_evidence(
    index: u64,
    proof: Option<&DurableProof>,
    mark: Option<DurableMark>,
) -> bool {
    let Some(proof) = proof else {
        return false;
    };
    (proof.durable_sequence == 0 || index > proof.segment_index)
        && mark.is_none_or(|mark| index > mark.segment_index)
}

/// The durable mark, if present and intact. Absent, empty, short, or
/// CRC-invalid all mean "no information" (the mark is written without
/// fsync and may be torn); only hard I/O errors are reported.
pub fn load_durable_mark(backing: &Arc<dyn Backing>) -> Result<Option<DurableMark>, RecoveryError> {
    let file = match backing.open(layout::JOURNAL_DURABLE_MARK, false) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(RecoveryError::Io(e)),
    };
    if file.len()? < DURABLE_MARK_SIZE as u64 {
        return Ok(None);
    }
    let mut buf = [0u8; DURABLE_MARK_SIZE];
    match file.read_at(0, &mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(RecoveryError::Io(e)),
    }
    Ok(DurableMark::decode(&buf).ok())
}

/// The surviving segment whose records end at `sequence`: the record end
/// recovery publishes in the durable proof when it adopts that horizon.
fn horizon_end(segments: &[SegmentInfo], sequence: u64) -> Option<&SegmentInfo> {
    segments
        .iter()
        .rev()
        .find(|segment| segment.record_count > 0 && segment.last_sequence() == sequence)
}

/// The highest A/B metadata generation recovery accepts: the top quarter of
/// the generation space is refused. Every store advances a record's
/// generation by one from zero, so no writer comes near it, and a larger
/// CRC-valid generation is damage. The bound sits `2^62` stores below the
/// store's own exhaustion check, so no attach, replay or later checkpoint
/// can reach that check, however many stores the journal makes it perform:
/// the read-only deep check can then refuse exactly what recovery refuses,
/// without predicting how often each record is stored. It also sits `2^62`
/// above `i64::MAX`, so a damaged generation at that common boundary value
/// keeps working instead of crossing the bound after a few stores.
const MAX_METADATA_GENERATION: u64 = u64::MAX - (1 << 62);

/// Refuse, read-only, A/B metadata whose raw generation (as a store ranks
/// it) is above [`MAX_METADATA_GENERATION`]: the superblock, checkpoint
/// state, durable proof, key canary, shard catalog and each loaded shard's
/// allocation and discard maps. Recovery runs this before its first write;
/// the deep check reports the same refusal.
pub(crate) fn check_metadata_generations(
    backing: &Arc<dyn Backing>,
    store: &SlotStore,
    // Known only when both superblocks decoded under this lock. A malformed
    // partner can still contain a CRC-valid raw generation above the selected one.
    known_superblock_generation: Option<u64>,
) -> Result<(), RecoveryError> {
    fn highest<T: AbRecord>(
        backing: &Arc<dyn Backing>,
        a: &str,
        b: &str,
    ) -> Result<Option<u64>, RecoveryError> {
        let (a, b) = AbStore::new(a, b).raw_generations::<T>(backing.as_ref())?;
        Ok(a.max(b))
    }
    let mut pairs = Vec::new();
    for (what, generation) in [
        (
            "superblock",
            match known_superblock_generation {
                Some(generation) => Some(generation),
                None => highest::<VolumeSuperblock>(
                    backing,
                    layout::SUPERBLOCK_A,
                    layout::SUPERBLOCK_B,
                )?,
            },
        ),
        (
            "checkpoint state",
            highest::<CheckpointState>(backing, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B)?,
        ),
        (
            "durable proof",
            highest::<DurableProof>(
                backing,
                maki_format::durable_proof::DURABLE_PROOF_A,
                maki_format::durable_proof::DURABLE_PROOF_B,
            )?,
        ),
        (
            "key canary",
            highest::<KeyCanary>(backing, layout::KEY_CANARY_A, layout::KEY_CANARY_B)?,
        ),
    ] {
        if let Some(generation) = generation {
            pairs.push((what.to_string(), generation));
        }
    }
    pairs.extend(store.metadata_generations()?);
    if let Some((what, generation)) = pairs
        .into_iter()
        .find(|(_, generation)| *generation > MAX_METADATA_GENERATION)
    {
        return Err(RecoveryError::Corrupt(format!(
            "{what}: A/B generation {generation} is above {MAX_METADATA_GENERATION}; every store \
             advances it by one, so no writer produces it, and later stores could exhaust it"
        )));
    }
    Ok(())
}
