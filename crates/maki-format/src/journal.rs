//! Ciphertext journal record framing and segment scanning (SPEC §23, §43).
//!
//! Record: `MJR1 | sequence u64 | unit_index u64 | payload_len u32 |`
//! `payload_crc u32 | header_crc u32 | payload…` (header = 32 bytes).
//!
//! Scanning distinguishes:
//! - `Clean` — segment ends exactly after the last record (or in zeros),
//! - `TornTail` — an incomplete/invalid tail record: normal after crash,
//!   recovery truncates it,
//! - `Corrupt` — damage *before* valid data (payload CRC failure followed by
//!   a valid record, or a sequence gap): must fail recovery loudly, never
//!   silently drop acknowledged records.

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
/// start at `first_sequence` and increase by one per record.
pub fn scan_segment(buf: &[u8], first_sequence: u64) -> (Vec<JournalRecord>, ScanOutcome) {
    let mut records = Vec::new();
    let mut pos = 0usize;
    let mut expected = first_sequence;

    loop {
        if pos == buf.len() {
            return (records, ScanOutcome::Clean);
        }
        let rem = &buf[pos..];

        let header = match parse_header(rem) {
            Some(h) => h,
            None => {
                // Torn header or preallocated-zeros tail.
                return if rem.iter().all(|b| *b == 0) {
                    (records, ScanOutcome::Clean)
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
                    reason: format!(
                        "sequence {} where {} expected",
                        header.sequence, expected
                    ),
                },
            );
        }

        let payload_end = pos + RECORD_HEADER_SIZE + header.payload_len as usize;
        if payload_end > buf.len() {
            return (records, ScanOutcome::TornTail { at: pos });
        }
        let payload = &buf[pos + RECORD_HEADER_SIZE..payload_end];
        if crc32fast::hash(payload) != header.payload_crc {
            // Torn payload at the tail is normal; a valid record *after* the
            // damaged one means the damage is in the durable body → corrupt.
            let followed_by_valid_record = parse_header(&buf[payload_end.min(buf.len())..])
                .map(|h| h.sequence == expected + 1)
                .unwrap_or(false);
            return if followed_by_valid_record {
                (
                    records,
                    ScanOutcome::Corrupt {
                        at: pos,
                        reason: "payload CRC failure before valid successor record".to_string(),
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
