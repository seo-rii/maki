//! Recovery: runs before the volume is exposed (SPEC §27).
//!
//! ```text
//! acquire volume lock → select valid superblock → validate shard catalog
//! → validate allocation metadata → scan journal → discard/truncate partial
//! tail → rebuild overlay → READY
//! ```
//! (The provider self-test and crypto-compatibility verification are the
//! attach layer's final step, on top of this.)
//!
//! Scan policy: a torn tail is legal only in the *last* segment (older
//! segments were fdatasync'd before their successor was created). Any other
//! damage is `Corrupt` — attach is refused rather than risk silent loss.

use std::sync::Arc;

use maki_backing::{Backing, VolumeLock};
use maki_format::ab::AbStore;
use maki_format::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use maki_format::journal::{scan_segment, JournalRecord, ScanOutcome, SegmentHeader, SEGMENT_HEADER_SIZE};
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
    pub checkpoint_sequence: u64,
    pub durable_sequence: u64,
    pub next_segment_index: u64,
    pub segments: Vec<SegmentInfo>,
    /// Records with sequence > checkpoint_sequence, in sequence order.
    pub replay: Vec<JournalRecord>,
}

pub fn recover(backing: &Arc<dyn Backing>) -> Result<Recovered, RecoveryError> {
    // 1. exclusive volume lock
    let lock = backing.try_lock(layout::VOLUME_LOCK).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            RecoveryError::AlreadyAttached
        } else {
            RecoveryError::Io(e)
        }
    })?;

    // 2. superblock
    let superblock = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B)
        .load::<Superblock>(backing.as_ref())?
        .ok_or_else(|| RecoveryError::Corrupt("no valid superblock copy".to_string()))?;

    // 3./4. catalog + allocation metadata
    let store = SlotStore::open(backing.clone(), superblock.geometry.clone())?;

    // checkpoint state
    let ck_state = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B)
        .load::<CheckpointState>(backing.as_ref())?
        .unwrap_or_default();
    let checkpoint_sequence = ck_state.checkpoint_sequence;

    // 5./6. scan journal, truncate torn tail, verify continuity
    let mut names: Vec<(u64, String)> = backing
        .list(layout::JOURNAL_DIR)?
        .into_iter()
        .filter_map(|n| layout::parse_journal_segment(&n).map(|i| (i, n)))
        .collect();
    names.sort();

    let mut segments: Vec<SegmentInfo> = Vec::new();
    let mut replay: Vec<JournalRecord> = Vec::new();
    let mut prev_last_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;

    let count = names.len();
    for (pos, (index, name)) in names.into_iter().enumerate() {
        let is_last = pos + 1 == count;
        let path = format!("{}/{}", layout::JOURNAL_DIR, name);
        let file = backing.open(&path, false)?;
        let len = file.len()?;

        let header = if len < SEGMENT_HEADER_SIZE as u64 {
            None
        } else {
            let mut hdr = vec![0u8; SEGMENT_HEADER_SIZE];
            file.read_at(0, &mut hdr)?;
            SegmentHeader::decode(&hdr).ok()
        };
        let Some(header) = header else {
            if is_last {
                // Crash during segment creation: discard.
                backing.remove(&path)?;
                backing.sync_dir(layout::JOURNAL_DIR)?;
                continue;
            }
            return Err(RecoveryError::Corrupt(format!(
                "journal segment {name}: invalid header in non-final segment"
            )));
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

        let mut body = vec![0u8; (len - SEGMENT_HEADER_SIZE as u64) as usize];
        file.read_at(SEGMENT_HEADER_SIZE as u64, &mut body)?;
        let (records, outcome) = scan_segment(&body, header.base_sequence);

        match outcome {
            ScanOutcome::Clean => {}
            ScanOutcome::TornTail { at } => {
                if !is_last {
                    return Err(RecoveryError::Corrupt(format!(
                        "journal segment {name}: torn tail in non-final segment"
                    )));
                }
                // discard/truncate partial tail (SPEC §27)
                file.set_len(SEGMENT_HEADER_SIZE as u64 + at as u64)?;
                file.sync_data()?;
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
            size: file.len()?,
        });
    }

    let durable_sequence = checkpoint_sequence.max(max_seq);
    let next_segment_index = segments.iter().map(|s| s.index + 1).max().unwrap_or(0);

    Ok(Recovered {
        lock,
        superblock,
        store,
        checkpoint_sequence,
        durable_sequence,
        next_segment_index,
        segments,
        replay,
    })
}
