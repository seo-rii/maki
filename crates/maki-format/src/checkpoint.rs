//! Checkpoint state record (SPEC §26), A/B replicated under `checkpoint/`.
//! Invariant: `checkpoint_sequence <= durable_sequence`.

use crate::ab::AbRecord;
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const CHECKPOINT_MAGIC: &[u8; 8] = b"MAKICKP1";
pub const CHECKPOINT_VERSION: u32 = 1;

pub const CHECKPOINT_STATE_A: &str = "checkpoint/state.a";
pub const CHECKPOINT_STATE_B: &str = "checkpoint/state.b";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointState {
    generation: u64,
    /// All journal records with sequence <= this have been applied to slots.
    pub checkpoint_sequence: u64,
}

impl CheckpointState {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(CHECKPOINT_MAGIC)
            .u32(CHECKPOINT_VERSION)
            .u64(self.generation)
            .u64(self.checkpoint_sequence);
        w.finish_with_crc()
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let payload = strip_verify_crc(data, "checkpoint state")?;
        let mut r = Reader::new(payload);
        let magic = r.take(8)?;
        if magic != CHECKPOINT_MAGIC {
            return Err(FormatError::BadMagic("checkpoint state".to_string()));
        }
        let version = r.u32()?;
        if version != CHECKPOINT_VERSION {
            return Err(FormatError::Unsupported(format!(
                "checkpoint state version {version}"
            )));
        }
        let generation = r.u64()?;
        let checkpoint_sequence = r.u64()?;
        // A frozen fixed-length v1 record must consume exactly its payload:
        // trailing bytes (even under a valid CRC) are corruption, never a
        // forward-compatible extension (FUP-012).
        if r.remaining() != 0 {
            return Err(FormatError::Invalid(
                "checkpoint state: unexpected trailing bytes after a fixed-length v1 record"
                    .to_string(),
            ));
        }
        Ok(Self {
            generation,
            checkpoint_sequence,
        })
    }
}

impl AbRecord for CheckpointState {
    // A v1 checkpoint record is a fixed 32 bytes (magic+version+generation+
    // checkpoint_sequence+crc); a larger file is corruption, rejected before it
    // is read rather than inheriting the 1 GiB last-resort cap (FUP-012).
    const MAX_ENCODED_LEN: u64 = 32;

    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        CheckpointState::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        CheckpointState::decode(data)
    }
}
