//! Streaming counterpart of the format scanner's durable-prefix policy.
//! Differential regressions keep its clean/torn/corrupt outcomes aligned.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::ops::Range;

use maki_backing::BackingFile;
use maki_format::codec::{strip_verify_crc, Reader};
use maki_format::geometry::Geometry;
use maki_format::journal::{
    JournalRecord, ScanOutcome, MAX_PAYLOAD, RECORD_HEADER_SIZE, RECORD_MAGIC, SEGMENT_HEADER_SIZE,
};

use super::RecoveryError;

const READ_CHUNK: usize = 64 * 1024;

/// A zero-filled creation/tail artifact must be zero throughout its range,
/// including bytes beyond the first read buffer.
pub(super) fn range_is_zero(file: &dyn BackingFile, range: Range<u64>) -> std::io::Result<bool> {
    let mut buffer = [0u8; READ_CHUNK];
    let mut offset = range.start;
    let mut zero = true;
    while offset < range.end {
        let count = (range.end - offset).min(buffer.len() as u64) as usize;
        file.read_at(offset, &mut buffer[..count])?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            zero = false;
        }
        offset += count as u64;
    }
    Ok(zero)
}

struct RecordHeader {
    sequence: u64,
    unit: u64,
    payload_len: u32,
    payload_crc: u32,
}

impl RecordHeader {
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RECORD_HEADER_SIZE || &bytes[..4] != RECORD_MAGIC {
            return None;
        }
        let mut reader = Reader::new(strip_verify_crc(bytes, "journal record header").ok()?);
        reader.take(4).ok()?;
        Some(Self {
            sequence: reader.u64().ok()?,
            unit: reader.u64().ok()?,
            payload_len: reader.u32().ok()?,
            payload_crc: reader.u32().ok()?,
        })
    }
}

pub(super) struct SegmentBodyScan {
    pub record_count: u64,
    pub valid_body_bytes: u64,
    pub outcome: ScanOutcome,
    pub fingerprint: u64,
}

pub(super) struct SegmentScanner<'a> {
    pub file: &'a dyn BackingFile,
    pub header: &'a [u8; SEGMENT_HEADER_SIZE],
    pub body_len: u64,
    pub first_sequence: u64,
    pub durable_len: u64,
    pub geometry: &'a Geometry,
    pub checkpoint_sequence: u64,
    pub name: &'a str,
}

impl SegmentScanner<'_> {
    /// Only uncovered, CRC-valid, geometry-valid payloads are retained. A
    /// covered record or an invalid geometry candidate uses fixed scratch;
    /// the returned replay collection remains a separate memory consumer.
    pub fn scan(self, replay: &mut Vec<JournalRecord>) -> Result<SegmentBodyScan, RecoveryError> {
        let mut fingerprint = DefaultHasher::new();
        fingerprint.write(self.header);
        let mut scratch = [0u8; READ_CHUNK];
        let mut position = 0u64;
        let mut record_count = 0u64;
        let mut read_end = 0u64;

        let outcome = loop {
            if position == self.body_len {
                break ScanOutcome::Clean;
            }
            let at = usize::try_from(position).map_err(|_| {
                RecoveryError::Corrupt(
                    "journal body offset exceeds the platform index range".into(),
                )
            })?;
            let in_durable = position < self.durable_len;
            let mut bytes = [0u8; RECORD_HEADER_SIZE];
            let header_len = (self.body_len - position).min(RECORD_HEADER_SIZE as u64) as usize;
            self.file.read_at(
                SEGMENT_HEADER_SIZE as u64 + position,
                &mut bytes[..header_len],
            )?;
            read_end = position + header_len as u64;
            let Some(header) = RecordHeader::decode(&bytes[..header_len]) else {
                let zero = range_is_zero(
                    self.file,
                    SEGMENT_HEADER_SIZE as u64 + position
                        ..SEGMENT_HEADER_SIZE as u64 + self.body_len,
                )?;
                read_end = self.body_len;
                break if in_durable {
                    ScanOutcome::Corrupt {
                        at,
                        reason: if zero {
                            "zeroed record inside durable prefix"
                        } else {
                            "record header damaged inside durable prefix"
                        }
                        .into(),
                    }
                } else if zero {
                    ScanOutcome::Clean
                } else {
                    ScanOutcome::TornTail { at }
                };
            };

            // Match the format scanner's order: an impossible framing length
            // or sequence is corruption even outside the durable prefix.
            if header.payload_len > MAX_PAYLOAD {
                break ScanOutcome::Corrupt {
                    at,
                    reason: format!("payload_len {} exceeds cap", header.payload_len),
                };
            }
            let expected = self
                .first_sequence
                .checked_add(record_count)
                .ok_or_else(|| RecoveryError::Corrupt("journal record sequence overflow".into()))?;
            if header.sequence != expected {
                break ScanOutcome::Corrupt {
                    at,
                    reason: format!("sequence {} where {} expected", header.sequence, expected),
                };
            }
            let record_len = RECORD_HEADER_SIZE as u64 + u64::from(header.payload_len);
            if record_len > self.body_len - position {
                break if in_durable {
                    ScanOutcome::Corrupt {
                        at,
                        reason: "record truncated inside durable prefix".into(),
                    }
                } else {
                    ScanOutcome::TornTail { at }
                };
            }

            let valid_geometry = header.unit < self.geometry.num_units()
                && header.payload_len <= self.geometry.max_ciphertext_size;
            // Refuse to allocate geometry-invalid lengths. Their CRC still
            // determines whether they were a record at all: an unsynced torn
            // payload retains its torn-tail classification.
            let mut payload = (valid_geometry && header.sequence > self.checkpoint_sequence)
                .then(|| vec![0u8; header.payload_len as usize]);
            let mut crc = crc32fast::Hasher::new();
            let mut candidate_fingerprint = fingerprint.clone();
            candidate_fingerprint.write(&bytes);
            let mut read = 0usize;
            while read < header.payload_len as usize {
                let count = (header.payload_len as usize - read).min(READ_CHUNK);
                let chunk = match payload.as_deref_mut() {
                    Some(payload) => &mut payload[read..read + count],
                    None => &mut scratch[..count],
                };
                self.file.read_at(
                    SEGMENT_HEADER_SIZE as u64 + position + RECORD_HEADER_SIZE as u64 + read as u64,
                    chunk,
                )?;
                read_end += count as u64;
                crc.update(chunk);
                candidate_fingerprint.write(chunk);
                read += count;
            }
            if crc.finalize() != header.payload_crc {
                break if in_durable {
                    ScanOutcome::Corrupt {
                        at,
                        reason: "payload CRC failure in durable body".into(),
                    }
                } else {
                    ScanOutcome::TornTail { at }
                };
            }

            // Geometry is a semantic check on a valid record, exactly as in
            // the old scanner. Covered records are checked just as strictly.
            if header.unit >= self.geometry.num_units() {
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {}: record {} names unit {} beyond the device ({} units)",
                    self.name,
                    header.sequence,
                    header.unit,
                    self.geometry.num_units(),
                )));
            }
            if header.payload_len > self.geometry.max_ciphertext_size {
                return Err(RecoveryError::Corrupt(format!(
                    "journal segment {}: record {} payload of {} bytes exceeds the volume's \
                     maximum ciphertext size {}",
                    self.name,
                    header.sequence,
                    header.payload_len,
                    self.geometry.max_ciphertext_size,
                )));
            }
            if let Some(payload) = payload {
                replay.push(JournalRecord {
                    sequence: header.sequence,
                    unit_index: header.unit,
                    payload,
                });
            }
            // Commit only the accepted record. Invalid/zero/torn tails must
            // not enter the prefix later redirtied and acknowledged durable.
            fingerprint = candidate_fingerprint;
            position += record_len;
            record_count += 1;
        };

        // The old whole-image read surfaced I/O errors anywhere in a file
        // before deciding to truncate it. Consume a truncated/CRC-invalid
        // tail's unread suffix too; a torn-tail decision must not hide EIO.
        if !matches!(outcome, ScanOutcome::Corrupt { .. }) && read_end < self.body_len {
            range_is_zero(
                self.file,
                SEGMENT_HEADER_SIZE as u64 + read_end..SEGMENT_HEADER_SIZE as u64 + self.body_len,
            )?;
        }

        Ok(SegmentBodyScan {
            record_count,
            valid_body_bytes: position,
            outcome,
            fingerprint: fingerprint.finish(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use maki_format::journal::{encode_record, SegmentHeader};
    use uuid::Uuid;

    struct UnreadableTail {
        bytes: Vec<u8>,
    }

    impl BackingFile for UnreadableTail {
        fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let start = offset as usize;
            let end = start + out.len();
            if end == self.bytes.len() {
                return Err(io::Error::other("unreadable final sector"));
            }
            out.copy_from_slice(
                self.bytes
                    .get(start..end)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"))?,
            );
            Ok(())
        }

        fn write_at(&self, _: u64, _: &[u8]) -> io::Result<()> {
            panic!("read-only scanner attempted a write")
        }

        fn set_len(&self, _: u64) -> io::Result<()> {
            panic!("read-only scanner attempted a truncation")
        }

        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn sync_data(&self) -> io::Result<()> {
            panic!("read-only scanner attempted a sync")
        }
    }

    #[test]
    fn nonzero_tail_does_not_hide_a_later_read_error() {
        let file = UnreadableTail {
            bytes: vec![1; READ_CHUNK * 2 + 17],
        };
        assert!(
            range_is_zero(&file, 0..file.bytes.len() as u64).is_err(),
            "the old whole-image read would report the final-sector EIO"
        );
    }

    #[test]
    fn a_torn_payload_does_not_hide_a_later_read_error() {
        let header: [u8; SEGMENT_HEADER_SIZE] = SegmentHeader {
            segment_index: 0,
            volume_uuid: Uuid::nil(),
            base_sequence: 1,
        }
        .encode()
        .try_into()
        .unwrap();
        let mut body = encode_record(&JournalRecord {
            sequence: 1,
            unit_index: 0,
            payload: vec![7; 512],
        });
        body[RECORD_HEADER_SIZE] ^= 1;
        body.resize(READ_CHUNK * 2 + 17, 1);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&body);
        let file = UnreadableTail { bytes };
        let geometry = Geometry::compute(512, 512, 512, 512, 1 << 20, 1 << 16).unwrap();
        let result = SegmentScanner {
            file: &file,
            header: &header,
            body_len: body.len() as u64,
            first_sequence: 1,
            durable_len: 0,
            geometry: &geometry,
            checkpoint_sequence: 0,
            name: "seg-0000000000000000",
        }
        .scan(&mut Vec::new());
        assert!(
            matches!(result, Err(RecoveryError::Io(_))),
            "a torn-tail decision must not bypass unreadable remaining bytes"
        );
    }
}
