//! Recovery: runs before the volume is exposed (SPEC §27).
//!
//! ```text
//! acquire volume lock → select valid superblock → validate shard catalog
//! → validate allocation metadata → load checkpoint state → scan journal
//! → discard/truncate partial tail → rebuild overlay → READY
//! ```
//! (The provider self-test, crypto-compatibility verification and the key
//! canary check are the attach layer's final steps, on top of this.)
//!
//! Scan policy — fail closed on anything that is not provably a crash
//! artifact:
//! - a torn tail is legal only in the *last* segment (older segments were
//!   fdatasync'd before their successor was created), and only *after* the
//!   prefix the writer's durable mark proves was fdatasync'd;
//! - a final segment shorter than a header, or entirely zero-filled, is a
//!   creation crash and is discarded; a *complete* but invalid header is
//!   durable damage;
//! - the surviving journal must bridge from `checkpoint_sequence + 1` and
//!   be contiguous — a missing segment is never silently skipped;
//! - a segment larger than the writer can ever produce is rejected before
//!   it is read into memory;
//! - metadata read errors other than "not found" are I/O errors, never
//!   "invalid copy" (an initialized volume must have checkpoint state).
//!
//! [`scan_journal`] is the read-only core of the scan: it returns the
//! records to replay together with the repairs recovery *would* apply
//! (discarding an unwritten final segment, truncating a torn tail). The
//! offline deep checker reuses it verbatim, so "what recovery would do" and
//! "what the checker reports" can never drift apart.

use std::sync::Arc;

use maki_backing::{Backing, VolumeLock};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::journal::{
    max_segment_file_size, scan_segment_bounded, DurableMark, JournalRecord, ScanOutcome,
    SegmentHeader, DURABLE_MARK_SIZE, SEGMENT_HEADER_SIZE,
};
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_format::FormatError;

use crate::journal::SegmentInfo;
use crate::store::SlotStore;

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
    pub repairs: Vec<JournalRepair>,
    /// Whether a durable mark was found for the final segment.
    pub mark: Option<DurableMark>,
}

/// Recover a volume. `segment_size` is the writer's effective segment size;
/// it bounds how large any segment file may legitimately be.
pub fn recover(backing: &Arc<dyn Backing>, segment_size: u64) -> Result<Recovered, RecoveryError> {
    // 1. exclusive volume lock
    let lock = acquire_lock(backing)?;

    // 2. superblock
    let superblock = load_superblock(backing)?;

    // 3./4. catalog + allocation metadata
    let store = SlotStore::open(backing.clone(), superblock.geometry.clone())?;

    // checkpoint state
    let checkpoint_state = load_checkpoint_state(backing)?;

    // 5./6. scan journal, then apply the repairs the scan decided on
    let scan = scan_journal(
        backing,
        &superblock,
        checkpoint_state.checkpoint_sequence,
        segment_size,
    )?;
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
    }

    Ok(Recovered {
        lock,
        superblock,
        store,
        checkpoint_state,
        durable_sequence: scan.durable_sequence,
        next_segment_index: scan.next_segment_index,
        segments: scan.segments,
        replay: scan.replay,
    })
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
    AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B)
        .load::<Superblock>(backing.as_ref())?
        .ok_or_else(|| RecoveryError::Corrupt("no valid superblock copy".to_string()))
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
pub fn scan_journal(
    backing: &Arc<dyn Backing>,
    superblock: &Superblock,
    checkpoint_sequence: u64,
    segment_size: u64,
) -> Result<JournalScan, RecoveryError> {
    // The writer's fdatasync high-water mark (absent or invalid = no
    // information; the scan then falls back to the heuristic).
    let mark = load_durable_mark(backing)?;

    let mut names: Vec<(u64, String)> = backing
        .list(layout::JOURNAL_DIR)?
        .into_iter()
        .filter_map(|n| layout::parse_journal_segment(&n).map(|i| (i, n)))
        .collect();
    names.sort();

    let max_file_size = max_segment_file_size(segment_size);
    let mut segments: Vec<SegmentInfo> = Vec::new();
    let mut replay: Vec<JournalRecord> = Vec::new();
    let mut repairs: Vec<JournalRepair> = Vec::new();
    let mut prev_last_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;
    let mut final_mark: Option<DurableMark> = None;

    let count = names.len();
    for (pos, (index, name)) in names.into_iter().enumerate() {
        let is_last = pos + 1 == count;
        let path = format!("{}/{}", layout::JOURNAL_DIR, name);
        let file = backing.open(&path, false)?;
        let len = file.len()?;

        if len > max_file_size {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: size {len} exceeds maximum {max_file_size}"
            )));
        }

        // What the durable mark proves about *this* segment, if anything.
        let marked_durable: Option<u64> = mark
            .filter(|m| m.segment_index == index)
            .map(|m| m.durable_size);
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

        let mut image = vec![0u8; len as usize];
        file.read_at(0, &mut image)?;
        let header = match SegmentHeader::decode(&image[..SEGMENT_HEADER_SIZE]) {
            Ok(h) => h,
            Err(e) => {
                // A never-written (zero-filled) final segment is a creation
                // crash; anything else with a full-sized header is damage.
                if is_last && marked_durable.is_none() && image.iter().all(|b| *b == 0) {
                    repairs.push(JournalRepair::Discard { path });
                    continue;
                }
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
        if prev_last_seq.is_none() && header.base_sequence > checkpoint_sequence + 1 {
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: base sequence {} does not bridge from checkpoint {}",
                header.base_sequence, checkpoint_sequence
            )));
        }

        let body = &image[SEGMENT_HEADER_SIZE..];
        // Non-final segments were fdatasync'd in full before their
        // successor was created; the final one is durable up to the mark.
        let durable_len = if is_last {
            marked_durable.map(|d| (d as usize).saturating_sub(SEGMENT_HEADER_SIZE))
        } else {
            Some(body.len())
        };
        let (records, outcome) = scan_segment_bounded(body, header.base_sequence, durable_len);

        let mut size = len;
        match outcome {
            ScanOutcome::Clean => {}
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

        // Cross-segment sequence continuity.
        if let Some(prev) = prev_last_seq {
            if header.base_sequence != prev + 1 {
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {name}: base sequence {} does not follow {}",
                    header.base_sequence, prev
                )));
            }
        }
        let record_count = records.len() as u64;
        let last = if record_count > 0 {
            header.base_sequence + record_count - 1
        } else {
            header.base_sequence.saturating_sub(1)
        };
        prev_last_seq = Some(last);
        max_seq = max_seq.max(last);

        for record in records {
            if record.sequence > checkpoint_sequence {
                replay.push(record);
            }
        }

        segments.push(SegmentInfo {
            index,
            base_sequence: header.base_sequence,
            record_count,
            size,
        });
    }

    let durable_sequence = checkpoint_sequence.max(max_seq);
    // Segment indexes must never be reused: the durable mark is a plain,
    // never-cleaned file naming the newest segment it saw, so a fresh
    // segment under an old index would be judged against a stale mark
    // (a checkpoint right after recovery can delete every segment, which
    // used to restart numbering at zero). Continue above both the surviving
    // segments and the mark.
    let next_segment_index = segments
        .iter()
        .map(|s| s.index + 1)
        .max()
        .unwrap_or(0)
        .max(mark.map(|m| m.segment_index + 1).unwrap_or(0));

    Ok(JournalScan {
        durable_sequence,
        next_segment_index,
        segments,
        replay,
        repairs,
        mark: final_mark,
    })
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
