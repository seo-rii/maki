//! Ciphertext journal record framing and segment scanning (SPEC §23, §43).
//!
//! Record: `MJR1 | sequence u64 | unit_index u64 | payload_len u32 |`
//! `payload_crc u32 | header_crc u32 | payload…` (header = 32 bytes).
//!
//! Scanning distinguishes:
//! - `Clean` — segment ends exactly after the last record (or in zeros),
//! - `TornTail` — an incomplete/invalid tail record: normal after crash,
//!   recovery truncates it,
//! - `Corrupt` — damage in the durable body (or a sequence gap): must fail
//!   recovery loudly, never silently drop acknowledged records.
//!
//! Damage-vs-tail decision. Bytes that were covered by an fdatasync cannot
//! be lost or torn by a crash, so any damage there is corruption. Bytes
//! after the last fdatasync may persist in *any* order (a later record can
//! survive while an earlier one is lost), so damage there is a torn tail
//! and everything from the damage on is dropped — those records were never
//! acknowledged durable. The writer records the fdatasync'd prefix in the
//! [`DurableMark`] (`journal/durable-mark`) after every sync; recovery
//! passes it to [`scan_segment_bounded`]. Without a mark (older volumes,
//! or the mark's own write lost) the scanner falls back to the heuristic in
//! [`scan_segment`]: a failed payload CRC immediately followed by a valid
//! successor record is treated as corruption.

use uuid::Uuid;

use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const RECORD_MAGIC: &[u8; 4] = b"MJR1";
pub const RECORD_HEADER_SIZE: usize = 32;
/// Sanity cap on a single record payload (a crypto unit's ciphertext).
pub const MAX_PAYLOAD: u32 = 16 << 20;

pub const SEGMENT_MAGIC: &[u8; 8] = b"MAKIJSG1";
pub const SEGMENT_VERSION: u32 = 1;
pub const SEGMENT_HEADER_SIZE: usize = 48;

pub const DURABLE_MARK_MAGIC: &[u8; 8] = b"MAKIJDM1";
pub const DURABLE_MARK_VERSION: u32 = 1;
pub const DURABLE_MARK_SIZE: usize = 32;

/// Largest segment file the writer can produce for a configured segment
/// size: a segment only exceeds its size by the single record that would
/// not fit an empty segment. The generous multiple tolerates a segment size
/// that was lowered in configuration after older segments were written.
pub fn max_segment_file_size(segment_size: u64) -> u64 {
    segment_size
        .saturating_mul(4)
        .saturating_add(SEGMENT_HEADER_SIZE as u64 + RECORD_HEADER_SIZE as u64 + MAX_PAYLOAD as u64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRecord {
    pub sequence: u64,
    pub unit_index: u64,
    /// Ciphertext. Plaintext is never journaled (SPEC §12).
    pub payload: Vec<u8>,
}

pub fn encode_record(rec: &JournalRecord) -> Vec<u8> {
    let mut header = Writer::new();
    header
        .bytes(RECORD_MAGIC)
        .u64(rec.sequence)
        .u64(rec.unit_index)
        .u32(rec.payload.len() as u32)
        .u32(crc32fast::hash(&rec.payload));
    let mut out = header.finish_with_crc();
    debug_assert_eq!(out.len(), RECORD_HEADER_SIZE);
    out.extend_from_slice(&rec.payload);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// All bytes consumed by valid records (possibly followed by zeros).
    Clean,
    /// Valid records up to `at`; the rest is a torn tail to truncate.
    TornTail { at: usize },
    /// Damage in the durable body of the journal.
    Corrupt { at: usize, reason: String },
}

struct ParsedHeader {
    sequence: u64,
    unit_index: u64,
    payload_len: u32,
    payload_crc: u32,
}

/// Parse a record header if its magic+CRC are intact.
fn parse_header(buf: &[u8]) -> Option<ParsedHeader> {
    if buf.len() < RECORD_HEADER_SIZE {
        return None;
    }
    let hdr = &buf[..RECORD_HEADER_SIZE];
    if &hdr[0..4] != RECORD_MAGIC {
        return None;
    }
    let payload = strip_verify_crc(hdr, "journal record header").ok()?;
    let mut r = Reader::new(payload);
    r.take(4).ok()?;
    Some(ParsedHeader {
        sequence: r.u64().ok()?,
        unit_index: r.u64().ok()?,
        payload_len: r.u32().ok()?,
        payload_crc: r.u32().ok()?,
    })
}

/// Scan a segment body (after the segment header) expecting sequences to
/// start at `first_sequence` and increase by one per record, with no
/// knowledge of the durable prefix (heuristic mode — see module docs).
pub fn scan_segment(buf: &[u8], first_sequence: u64) -> (Vec<JournalRecord>, ScanOutcome) {
    scan_segment_bounded(buf, first_sequence, None)
}

/// Scan a segment body whose first `durable_len` bytes are known to have
/// been fdatasync'd: damage inside that prefix is corruption, damage after
/// it is a torn tail. `None` selects the heuristic mode of
/// [`scan_segment`].
pub fn scan_segment_bounded(
    buf: &[u8],
    first_sequence: u64,
    durable_len: Option<usize>,
) -> (Vec<JournalRecord>, ScanOutcome) {
    let mut records = Vec::new();
    let mut pos = 0usize;
    let mut expected = first_sequence;
    let in_durable = |pos: usize| durable_len.map(|d| pos < d).unwrap_or(false);

    loop {
        if pos == buf.len() {
            return (records, ScanOutcome::Clean);
        }
        let rem = &buf[pos..];

        let header = match parse_header(rem) {
            Some(h) => h,
            None => {
                if rem.iter().all(|b| *b == 0) {
                    // Preallocated-zeros tail — unless the durable prefix
                    // says a record should be here.
                    return if in_durable(pos) {
                        (
                            records,
                            ScanOutcome::Corrupt {
                                at: pos,
                                reason: "zeroed record inside durable prefix".to_string(),
                            },
                        )
                    } else {
                        (records, ScanOutcome::Clean)
                    };
                }
                return if in_durable(pos) {
                    (
                        records,
                        ScanOutcome::Corrupt {
                            at: pos,
                            reason: "record header damaged inside durable prefix".to_string(),
                        },
                    )
                } else {
                    (records, ScanOutcome::TornTail { at: pos })
                };
            }
        };

        if header.payload_len > MAX_PAYLOAD {
            return (
                records,
                ScanOutcome::Corrupt {
                    at: pos,
                    reason: format!("payload_len {} exceeds cap", header.payload_len),
                },
            );
        }
        if header.sequence != expected {
            return (
                records,
                ScanOutcome::Corrupt {
                    at: pos,
                    reason: format!("sequence {} where {} expected", header.sequence, expected),
                },
            );
        }

        let payload_end = pos + RECORD_HEADER_SIZE + header.payload_len as usize;
        if payload_end > buf.len() {
            return if in_durable(pos) {
                (
                    records,
                    ScanOutcome::Corrupt {
                        at: pos,
                        reason: "record truncated inside durable prefix".to_string(),
                    },
                )
            } else {
                (records, ScanOutcome::TornTail { at: pos })
            };
        }
        let payload = &buf[pos + RECORD_HEADER_SIZE..payload_end];
        if crc32fast::hash(payload) != header.payload_crc {
            let corrupt = match durable_len {
                Some(_) => in_durable(pos),
                // Heuristic: a torn payload at the tail is normal; a valid
                // record *after* the damaged one suggests durable damage.
                None => parse_header(&buf[payload_end..])
                    .map(|h| h.sequence == expected + 1)
                    .unwrap_or(false),
            };
            return if corrupt {
                (
                    records,
                    ScanOutcome::Corrupt {
                        at: pos,
                        reason: "payload CRC failure in durable body".to_string(),
                    },
                )
            } else {
                (records, ScanOutcome::TornTail { at: pos })
            };
        }

        records.push(JournalRecord {
            sequence: header.sequence,
            unit_index: header.unit_index,
            payload: payload.to_vec(),
        });
        expected += 1;
        pos = payload_end;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {
    pub segment_index: u64,
    pub volume_uuid: Uuid,
    /// Sequence of the first record in this segment.
    pub base_sequence: u64,
}

impl SegmentHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(SEGMENT_MAGIC)
            .u32(SEGMENT_VERSION)
            .u64(self.segment_index)
            .uuid(&self.volume_uuid)
            .u64(self.base_sequence);
        let out = w.finish_with_crc();
        debug_assert_eq!(out.len(), SEGMENT_HEADER_SIZE);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < SEGMENT_HEADER_SIZE {
            return Err(FormatError::Truncated(format!(
                "segment header: {} < {SEGMENT_HEADER_SIZE}",
                data.len()
            )));
        }
        let data = &data[..SEGMENT_HEADER_SIZE];
        if &data[0..8] != SEGMENT_MAGIC {
            return Err(FormatError::BadMagic("journal segment".to_string()));
        }
        let payload = strip_verify_crc(data, "journal segment header")?;
        let mut r = Reader::new(payload);
        let _magic = r.take(8)?;
        let version = r.u32()?;
        if version != SEGMENT_VERSION {
            return Err(FormatError::Unsupported(format!(
                "journal segment version {version}"
            )));
        }
        Ok(Self {
            segment_index: r.u64()?,
            volume_uuid: r.uuid()?,
            base_sequence: r.u64()?,
        })
    }
}

/// The writer's record of the fdatasync'd prefix of one segment: bytes
/// `[0, durable_size)` of segment `segment_index` are durable.
///
/// Written (never fsync'd) after every successful segment fdatasync. It is
/// always a *lower bound*: a mark can only persist after the sync it
/// describes completed, and a lost or torn mark merely leaves an older
/// bound (or none) behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableMark {
    pub segment_index: u64,
    pub durable_size: u64,
}

impl DurableMark {
    pub fn encode(&self) -> [u8; DURABLE_MARK_SIZE] {
        let mut w = Writer::new();
        w.bytes(DURABLE_MARK_MAGIC)
            .u32(DURABLE_MARK_VERSION)
            .u64(self.segment_index)
            .u64(self.durable_size);
        let out = w.finish_with_crc();
        out.try_into().expect("durable mark is 32 bytes")
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < DURABLE_MARK_SIZE {
            return Err(FormatError::Truncated(format!(
                "durable mark: {} < {DURABLE_MARK_SIZE}",
                data.len()
            )));
        }
        let data = &data[..DURABLE_MARK_SIZE];
        if &data[0..8] != DURABLE_MARK_MAGIC {
            return Err(FormatError::BadMagic("durable mark".to_string()));
        }
        let payload = strip_verify_crc(data, "durable mark")?;
        let mut r = Reader::new(payload);
        let _magic = r.take(8)?;
        let version = r.u32()?;
        if version != DURABLE_MARK_VERSION {
            return Err(FormatError::Unsupported(format!(
                "durable mark version {version}"
            )));
        }
        Ok(Self {
            segment_index: r.u64()?,
            durable_size: r.u64()?,
        })
    }
}
