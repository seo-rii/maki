//! A/B dual-copy metadata protocol (SPEC §43).
//!
//! Records carry a monotonically increasing generation and are CRC-protected.
//! `store` always overwrites the *stale* side, so a torn write can only
//! destroy the copy being replaced; `load` selects the valid copy with the
//! highest generation.

use maki_backing::Backing;

use crate::error::FormatError;

pub trait AbRecord: Sized {
    fn generation(&self) -> u64;
    fn set_generation(&mut self, generation: u64);
    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Result<Self, FormatError>;
}

pub struct AbStore {
    a: String,
    b: String,
}

impl AbStore {
    pub fn new(a: impl Into<String>, b: impl Into<String>) -> Self {
        Self {
            a: a.into(),
            b: b.into(),
        }
    }

    fn read_side<T: AbRecord>(&self, backing: &dyn Backing, path: &str) -> Option<T> {
        let file = backing.open(path, false).ok()?;
        let len = file.len().ok()?;
        if len == 0 || len > 1 << 30 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        file.read_at(0, &mut buf).ok()?;
        T::decode(&buf).ok()
    }

    /// Best valid copy, if any.
    pub fn load<T: AbRecord>(&self, backing: &dyn Backing) -> Result<Option<T>, FormatError> {
        let a = self.read_side::<T>(backing, &self.a);
        let b = self.read_side::<T>(backing, &self.b);
        Ok(match (a, b) {
            (Some(a), Some(b)) => Some(if a.generation() >= b.generation() {
                a
            } else {
                b
            }),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        })
    }

    /// The side the *next* store will overwrite (the invalid or older one).
    pub fn next_target_path(&self, backing: &dyn Backing) -> Result<&str, FormatError> {
        let ga = self
            .read_side::<RawGeneration>(backing, &self.a)
            .map(|r| r.generation);
        let gb = self
            .read_side::<RawGeneration>(backing, &self.b)
            .map(|r| r.generation);
        Ok(match (ga, gb) {
            (None, _) => &self.a,
            (_, None) => &self.b,
            (Some(ga), Some(gb)) => {
                if ga <= gb {
                    &self.a
                } else {
                    &self.b
                }
            }
        })
    }

    /// Bump the record's generation past both sides, write it to the stale
    /// side, and fdatasync it. (Directory durability of freshly created
    /// files is the caller's responsibility — see `init::create_volume`.)
    pub fn store<T: AbRecord>(
        &self,
        backing: &dyn Backing,
        record: &mut T,
    ) -> Result<(), FormatError> {
        let ga = self
            .read_side::<RawGeneration>(backing, &self.a)
            .map(|r| r.generation);
        let gb = self
            .read_side::<RawGeneration>(backing, &self.b)
            .map(|r| r.generation);
        let max_existing = ga.into_iter().chain(gb).max().unwrap_or(0);
        record.set_generation(max_existing.max(record.generation()) + 1);

        let target = match (ga, gb) {
            (None, _) => &self.a,
            (_, None) => &self.b,
            (Some(ga), Some(gb)) => {
                if ga <= gb {
                    &self.a
                } else {
                    &self.b
                }
            }
        };
        let bytes = record.encode();
        let file = backing.open(target, true)?;
        file.set_len(bytes.len() as u64)?;
        file.write_at(0, &bytes)?;
        file.sync_data()?;
        Ok(())
    }
}

/// Minimal decoder used to compare generations without knowing the record
/// type: every A/B record encodes `magic[8] version[4] generation[8] ...`
/// with a trailing CRC.
struct RawGeneration {
    generation: u64,
}

impl AbRecord for RawGeneration {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        unreachable!("RawGeneration is read-only")
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let payload = crate::codec::strip_verify_crc(data, "ab record")?;
        let mut r = crate::codec::Reader::new(payload);
        let _magic = r.take(8)?;
        let _version = r.u32()?;
        let generation = r.u64()?;
        Ok(Self { generation })
    }
}
