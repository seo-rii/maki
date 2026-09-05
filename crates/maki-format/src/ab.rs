//! A/B dual-copy metadata protocol (SPEC §43).
//!
//! Records carry a monotonically increasing generation and are CRC-protected.
//! `store` makes the valid side it will preserve durable before overwriting
//! the *stale* side, so a torn write can only destroy the copy being replaced;
//! `load` selects the valid copy with the highest generation. Readable bytes
//! are not proof of durability: a failed sync or a process restart can leave
//! a newer valid copy in the page cache.
//!
//! Read classification: a side that is absent, empty, short, or fails its
//! CRC/decode is an *invalid copy* (the other side is authoritative). Any
//! other I/O failure — permissions, EIO, a device error — is reported as an
//! error: it says nothing about the copy's validity, and treating it as
//! "invalid" could silently select an older generation.

use maki_backing::Backing;

use crate::error::FormatError;

/// Sanity cap on a metadata record file; larger is an invalid copy.
const MAX_RECORD_SIZE: u64 = 1 << 30;

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

    /// One side and its exact validated bytes: `Ok(None)` for an absent or
    /// invalid copy, `Err` for a hard I/O failure.
    fn read_copy<T: AbRecord>(
        &self,
        backing: &dyn Backing,
        path: &str,
    ) -> Result<Option<(T, Vec<u8>)>, FormatError> {
        let file = match backing.open(path, false) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(FormatError::Io(e)),
        };
        let len = file.len()?;
        if len == 0 || len > MAX_RECORD_SIZE {
            return Ok(None);
        }
        let mut buf = vec![0u8; len as usize];
        match file.read_at(0, &mut buf) {
            Ok(()) => {}
            // The file shrank under us or is shorter than its size claims:
            // a torn copy, not an I/O fault.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(FormatError::Io(e)),
        }
        Ok(T::decode(&buf).ok().map(|record| (record, buf)))
    }

    fn read_side<T: AbRecord>(
        &self,
        backing: &dyn Backing,
        path: &str,
    ) -> Result<Option<T>, FormatError> {
        Ok(self.read_copy(backing, path)?.map(|(record, _)| record))
    }

    /// Best valid copy, if any. `Err` only for hard I/O failures.
    pub fn load<T: AbRecord>(&self, backing: &dyn Backing) -> Result<Option<T>, FormatError> {
        let a = self.read_side::<T>(backing, &self.a)?;
        let b = self.read_side::<T>(backing, &self.b)?;
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

    fn generations(
        &self,
        backing: &dyn Backing,
    ) -> Result<(Option<u64>, Option<u64>), FormatError> {
        let ga = self
            .read_side::<RawGeneration>(backing, &self.a)?
            .map(|r| r.generation);
        let gb = self
            .read_side::<RawGeneration>(backing, &self.b)?
            .map(|r| r.generation);
        Ok((ga, gb))
    }

    fn target_for(&self, ga: Option<u64>, gb: Option<u64>) -> &str {
        match (ga, gb) {
            (None, _) => &self.a,
            (_, None) => &self.b,
            (Some(ga), Some(gb)) => {
                if ga <= gb {
                    &self.a
                } else {
                    &self.b
                }
            }
        }
    }

    /// Generation of each side when it holds a valid record of type `T`
    /// (`None` = absent or invalid); hard I/O errors are reported.
    pub fn side_generations<T: AbRecord>(
        &self,
        backing: &dyn Backing,
    ) -> Result<(Option<u64>, Option<u64>), FormatError> {
        let a = self
            .read_side::<T>(backing, &self.a)?
            .map(|r| r.generation());
        let b = self
            .read_side::<T>(backing, &self.b)?
            .map(|r| r.generation());
        Ok((a, b))
    }

    /// The side the *next* store will overwrite: a side that does not hold
    /// a valid record *of type `T`* first (whatever its raw generation says),
    /// otherwise the older one. Choosing by raw generation alone would let a
    /// CRC-valid but undecodable side (wrong type, newer version, damaged
    /// payload) count as "newest" and the only loadable copy be overwritten.
    /// This only selects a path; `store` establishes the preserved side's
    /// durability before overwriting the selected target.
    pub fn next_target_path<T: AbRecord>(
        &self,
        backing: &dyn Backing,
    ) -> Result<&str, FormatError> {
        let (ga, gb) = self.side_generations::<T>(backing)?;
        Ok(self.target_for(ga, gb))
    }

    /// Bump the record's generation past both sides (raw generations, so a
    /// foreign or newer-version record never outranks the new one), write it
    /// to the side `next_target_path` names, and fdatasync it. Before touching
    /// that target, rewrite and sync the other typed-valid copy and sync its
    /// parent directory: either may still be volatile after a failed store
    /// or caller dirsync. Rewriting is required because writeback errors can
    /// clear dirty page-cache bits without making those bytes durable.
    /// Directory durability of the freshly created target remains the
    /// caller's responsibility — see `init::create_volume`.
    pub fn store<T: AbRecord>(
        &self,
        backing: &dyn Backing,
        record: &mut T,
    ) -> Result<(), FormatError> {
        let (ga, gb) = self.generations(backing)?;
        let max_existing = ga.into_iter().chain(gb).max().unwrap_or(0);
        let a = self.read_copy::<T>(backing, &self.a)?;
        let b = self.read_copy::<T>(backing, &self.b)?;
        let ta = a.as_ref().map(|(record, _)| record.generation());
        let tb = b.as_ref().map(|(record, _)| record.generation());
        let target = self.target_for(ta, tb);
        let preserved = if target == self.a {
            b.map(|(_, bytes)| (self.b.as_str(), bytes))
        } else {
            a.map(|(_, bytes)| (self.a.as_str(), bytes))
        };
        if let Some((preserved, bytes)) = preserved {
            // A failed sync can leave this newer generation readable but
            // volatile. Retrying (even after restarting the process) must
            // not overwrite the last durable copy until this one is safe.
            // Redirty the exact validated image: after writeback EIO a
            // plain fsync retry may succeed without persisting clean cache
            // pages. Do not truncate or re-encode the preserved copy.
            // Its dirent may also be new if the caller's dirsync failed.
            let file = backing.open(preserved, false)?;
            file.write_at(0, &bytes)?;
            file.sync_data()?;
            backing.sync_dir(maki_backing::path::parent(preserved))?;
        }

        record.set_generation(max_existing.max(record.generation()) + 1);
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
