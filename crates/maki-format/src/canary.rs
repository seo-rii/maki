//! Key canary: a provider/key-bound ciphertext that proves, at attach time,
//! that the configured provider and key are the ones this volume was
//! written with (SPEC §12 "crypto profile mismatch prevents attach").
//!
//! The compatibility ID and the self-test only show that the provider is
//! coherent *with itself*; a different key under the same profile passes
//! both. The canary is a fixed, domain-separated plaintext encrypted at a
//! reserved unit index when the volume is first attached; every later attach
//! must decrypt it back to the same bytes before the volume is exposed. For
//! unauthenticated ciphers (XTS) this comparison is the only wrong-key
//! detection there is.
//!
//! Stored A/B-replicated as `canary.a` / `canary.b` in the volume root:
//! `MAKICNY1 | version u32 | generation u64 | volume_uuid[16] |`
//! `unit_index u64 | ciphertext_len u32 | ciphertext | crc32`.

use uuid::Uuid;

use crate::ab::AbRecord;
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const CANARY_MAGIC: &[u8; 8] = b"MAKICNY1";
pub const CANARY_VERSION: u32 = 1;
/// Sanity cap on the stored ciphertext (a single crypto unit).
pub const MAX_CANARY_CIPHERTEXT: u32 = 16 << 20;

/// Reserved unit index the canary is encrypted at. Above any unit a volume
/// can address in practice (attach refuses geometries that reach it), yet
/// below 2^53 so JSON-based remote providers represent it exactly.
pub const CANARY_UNIT_INDEX: u64 = 0x0010_0000_4D41_4B49;

/// The fixed plaintext of a volume's canary: an ASCII tag followed by a
/// deterministic pattern derived from the volume UUID. Not secret; its only
/// property is that it is stable forever for a given volume.
pub fn canary_plaintext(volume_uuid: &Uuid, unit_size: usize) -> Vec<u8> {
    const TAG: &[u8] = b"MAKI-KEY-CANARY-V1";
    let bytes = volume_uuid.as_bytes();
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let mut x = lo ^ hi.rotate_left(32) ^ 0x4D41_4B49_4341_4E59;
    if x == 0 {
        x = 0x9E37_79B9_7F4A_7C15;
    }
    let mut out = vec![0u8; unit_size];
    for b in out.iter_mut() {
        // xorshift64* — deterministic, not a secret
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
    }
    let n = TAG.len().min(unit_size);
    out[..n].copy_from_slice(&TAG[..n]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCanary {
    pub generation: u64,
    pub volume_uuid: Uuid,
    pub unit_index: u64,
    pub ciphertext: Vec<u8>,
}

impl KeyCanary {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(CANARY_MAGIC)
            .u32(CANARY_VERSION)
            .u64(self.generation)
            .uuid(&self.volume_uuid)
            .u64(self.unit_index)
            .u32(self.ciphertext.len() as u32)
            .bytes(&self.ciphertext);
        w.finish_with_crc()
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < 8 || &data[0..8] != CANARY_MAGIC {
            return Err(FormatError::BadMagic("key canary".to_string()));
        }
        let payload = strip_verify_crc(data, "key canary")?;
        let mut r = Reader::new(payload);
        let _magic = r.take(8)?;
        let version = r.u32()?;
        if version != CANARY_VERSION {
            return Err(FormatError::Unsupported(format!(
                "key canary version {version}"
            )));
        }
        let generation = r.u64()?;
        let volume_uuid = r.uuid()?;
        let unit_index = r.u64()?;
        let len = r.u32()?;
        if len > MAX_CANARY_CIPHERTEXT {
            return Err(FormatError::Invalid(format!(
                "key canary ciphertext length {len} exceeds cap"
            )));
        }
        let ciphertext = r.take(len as usize)?.to_vec();
        Ok(Self {
            generation,
            volume_uuid,
            unit_index,
            ciphertext,
        })
    }
}

impl AbRecord for KeyCanary {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        KeyCanary::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        KeyCanary::decode(data)
    }
}
