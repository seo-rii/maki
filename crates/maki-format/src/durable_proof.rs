//! Required acknowledgement horizon, mirrored before a barrier can succeed.
//!
//! A normal A/B update leaves an older horizon on one side. Losing its newest
//! side could then hide acknowledged journal corruption. Every successful
//! advance here stores the same horizon on BOTH sides, preserving the highest
//! valid side before replacing its alternative. The caller must serialize
//! updates under the volume lock and make the described journal data durable
//! before advancing this proof. CRC detects corruption; it is not authenticity
//! or protection against coordinated rollback of both copies.

use maki_backing::Backing;
use uuid::Uuid;

use crate::ab::{AbRecord, AbStore};
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::journal::{RECORD_HEADER_SIZE, SEGMENT_HEADER_SIZE};
use crate::{layout, FormatError};

pub const DURABLE_PROOF_A: &str = "journal/durable-proof.a";
pub const DURABLE_PROOF_B: &str = "journal/durable-proof.b";
pub const DURABLE_PROOF_MAGIC: &[u8; 8] = b"MAKIJDP1";
pub const DURABLE_PROOF_VERSION: u32 = 1;
pub const DURABLE_PROOF_SIZE: usize = 64;

/// A lower bound on the journal sequence that recovery must preserve or
/// reject explicitly. `segment_index`/`durable_size` identify that record's
/// exact end; they do not move when an empty successor segment is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableProof {
    pub generation: u64,
    pub volume_uuid: Uuid,
    pub durable_sequence: u64,
    pub segment_index: u64,
    pub durable_size: u64,
}

impl DurableProof {
    pub fn initial(volume_uuid: Uuid) -> Self {
        Self {
            generation: 0,
            volume_uuid,
            durable_sequence: 0,
            segment_index: 0,
            durable_size: 0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer
            .bytes(DURABLE_PROOF_MAGIC)
            .u32(DURABLE_PROOF_VERSION)
            .u64(self.generation)
            .uuid(&self.volume_uuid)
            .u64(self.durable_sequence)
            .u64(self.segment_index)
            .u64(self.durable_size);
        writer.finish_with_crc()
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < DURABLE_PROOF_SIZE {
            return Err(FormatError::Truncated("durable proof".into()));
        }
        if data.len() != DURABLE_PROOF_SIZE {
            return Err(FormatError::Invalid(
                "durable proof has trailing bytes".into(),
            ));
        }
        let mut reader = Reader::new(strip_verify_crc(data, "durable proof")?);
        if reader.take(8)? != DURABLE_PROOF_MAGIC {
            return Err(FormatError::BadMagic("durable proof".into()));
        }
        let version = reader.u32()?;
        if version != DURABLE_PROOF_VERSION {
            return Err(FormatError::Unsupported(format!(
                "durable proof version {version}"
            )));
        }
        let proof = Self {
            generation: reader.u64()?,
            volume_uuid: reader.uuid()?,
            durable_sequence: reader.u64()?,
            segment_index: reader.u64()?,
            durable_size: reader.u64()?,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(&self) -> Result<(), FormatError> {
        if self.durable_sequence == 0 {
            if self.segment_index != 0 || self.durable_size != 0 {
                return Err(FormatError::Invalid(
                    "empty durable proof has a segment location".into(),
                ));
            }
        } else if self.durable_sequence == u64::MAX
            || self.segment_index == u64::MAX
            || self.durable_size < (SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE) as u64
            || self.durable_size > i64::MAX as u64
        {
            return Err(FormatError::Invalid(
                "durable proof horizon is outside supported bounds".into(),
            ));
        }
        Ok(())
    }

    fn follows(&self, previous: &Self) -> Result<(), FormatError> {
        if self.volume_uuid != previous.volume_uuid {
            return Err(FormatError::Invalid(
                "durable proof volume UUID changed".into(),
            ));
        }
        if self.durable_sequence < previous.durable_sequence {
            return Err(FormatError::Invalid(
                "durable proof sequence regressed".into(),
            ));
        }
        if self.durable_sequence == previous.durable_sequence {
            if self.segment_index != previous.segment_index
                || self.durable_size != previous.durable_size
            {
                return Err(FormatError::Invalid(
                    "unchanged durable sequence has a different record end".into(),
                ));
            }
        } else if self.segment_index < previous.segment_index
            || (self.segment_index == previous.segment_index
                && self.durable_size <= previous.durable_size)
        {
            return Err(FormatError::Invalid(
                "advancing durable sequence regressed its segment location".into(),
            ));
        }
        Ok(())
    }
}

impl AbRecord for DurableProof {
    const MAX_ENCODED_LEN: u64 = DURABLE_PROOF_SIZE as u64;

    fn generation(&self) -> u64 {
        self.generation
    }
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }
    fn encode(&self) -> Vec<u8> {
        DurableProof::encode(self)
    }
    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        DurableProof::decode(data)
    }
}

/// Required metadata access. The enclosing volume format must require these
/// files: their absence must never trigger legacy recovery or initialization.
pub struct DurableProofStore;

impl DurableProofStore {
    /// Select the highest valid horizon without modifying storage. A single
    /// invalid/absent side is recoverable; hard I/O, an unsupported version,
    /// foreign UUID, inconsistent pair, or no valid side fails closed.
    pub fn load(backing: &dyn Backing, volume_uuid: Uuid) -> Result<DurableProof, FormatError> {
        let a = Self::read_copy(backing, DURABLE_PROOF_A, volume_uuid)?;
        let b = Self::read_copy(backing, DURABLE_PROOF_B, volume_uuid)?;
        match (a, b) {
            (Some(a), Some(b)) => {
                if a.generation == b.generation && a != b {
                    return Err(FormatError::Invalid(
                        "durable proof copies disagree at the same generation".into(),
                    ));
                }
                let (older, newer) = if a.generation <= b.generation {
                    (a, b)
                } else {
                    (b, a)
                };
                newer.follows(&older)?;
                Ok(newer)
            }
            (Some(proof), None) | (None, Some(proof)) => Ok(proof),
            (None, None) => Err(FormatError::Invalid(
                "required durable proof has no valid copy".into(),
            )),
        }
    }

    /// Initialize only a new namespace. Never overwrite even invalid or
    /// partially initialized proof files: that could erase an ACK horizon.
    /// A required-format superblock may be published only after this succeeds.
    pub fn initialize(
        backing: &dyn Backing,
        volume_uuid: Uuid,
    ) -> Result<DurableProof, FormatError> {
        for path in [DURABLE_PROOF_A, DURABLE_PROOF_B] {
            // Preserve hard I/O and future-format errors even on this path.
            Self::read_copy(backing, path, volume_uuid)?;
            if backing.exists(path)? {
                return Err(FormatError::AlreadyExists(
                    "durable proof already exists; initialization cannot reset history".into(),
                ));
            }
        }
        backing.create_dir_all(layout::JOURNAL_DIR)?;
        let mut proof = DurableProof::initial(volume_uuid);
        let store = AbStore::new(DURABLE_PROOF_A, DURABLE_PROOF_B);
        store.store(backing, &mut proof)?;
        backing.sync_dir(layout::JOURNAL_DIR)?;
        store.store(backing, &mut proof)?;
        backing.sync_dir(layout::JOURNAL_DIR)?;
        backing.sync_dir("")?;
        Ok(proof)
    }

    /// Publish this candidate to both copies before returning success. The
    /// caller's value is unchanged on error; readable newer metadata may still
    /// exist, so retries revalidate storage and preserve it before overwriting
    /// the other side. Call only after the candidate's data is durable.
    pub fn advance(backing: &dyn Backing, proof: &mut DurableProof) -> Result<(), FormatError> {
        proof.validate()?;
        let current = Self::load(backing, proof.volume_uuid)?;
        proof.follows(&current)?;
        if proof.generation > current.generation {
            return Err(FormatError::Invalid(
                "candidate proof generation is ahead of stored metadata".into(),
            ));
        }
        current
            .generation
            .checked_add(2)
            .ok_or_else(|| FormatError::Overflow("durable proof generation exhausted".into()))?;
        let mut candidate = proof.clone();
        let store = AbStore::new(DURABLE_PROOF_A, DURABLE_PROOF_B);
        // Each store rewrites/syncs its preserved valid side before touching
        // the lower/invalid side. Calling twice makes BOTH copies attest this
        // horizon, even when one was absent or stale before this operation.
        store.store(backing, &mut candidate)?;
        backing.sync_dir(layout::JOURNAL_DIR)?;
        Self::load(backing, proof.volume_uuid)?;
        store.store(backing, &mut candidate)?;
        backing.sync_dir(layout::JOURNAL_DIR)?;
        *proof = candidate;
        Ok(())
    }

    /// Bounded prevalidation is necessary because generic AbStore considers
    /// every decode error an invalid copy, including Unsupported. A future
    /// required format must not be overwritten using an older valid side.
    fn read_copy(
        backing: &dyn Backing,
        path: &str,
        volume_uuid: Uuid,
    ) -> Result<Option<DurableProof>, FormatError> {
        let file = match backing.open(path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let len = file.len()?;
        if len != DURABLE_PROOF_SIZE as u64 {
            if len >= 12 {
                let mut header = [0; 12];
                match file.read_at(0, &mut header) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None)
                    }
                    Err(error) => return Err(error.into()),
                }
                // A future format may change record length. Refuse a known
                // magic/new version without reading its unbounded payload.
                let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
                if &header[..8] == DURABLE_PROOF_MAGIC && version != DURABLE_PROOF_VERSION {
                    return Err(FormatError::Unsupported(format!(
                        "durable proof version {version}"
                    )));
                }
            }
            return Ok(None);
        }
        let mut bytes = [0; DURABLE_PROOF_SIZE];
        match file.read_at(0, &mut bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        match DurableProof::decode(&bytes) {
            Ok(proof) if proof.volume_uuid == volume_uuid => Ok(Some(proof)),
            Ok(_) => Err(FormatError::Invalid(
                "durable proof belongs to a different volume".into(),
            )),
            Err(error @ FormatError::Unsupported(_)) => Err(error),
            Err(_) => Ok(None),
        }
    }
}
