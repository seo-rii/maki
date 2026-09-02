//! Volume superblock (v1, fixed 4096-byte image, A/B replicated).
//!
//! Layout: `MAKISB01 | version u32 | generation u64 | uuid[16] |`
//! `device_block u32 | crypto_unit u32 | slot_align u32 | max_ct u32 |`
//! `slot_hdr u32 | slot_size u64 | max_virtual u64 | shard_logical u64 |`
//! `format_version u32 | created u64 | flags u64 |`
//! `provider_type str | compat_id str | key_identity str | pad | crc32`.

use uuid::Uuid;

use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;
use crate::geometry::Geometry;

pub const SUPERBLOCK_SIZE: usize = 4096;
pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"MAKISB01";
pub const SUPERBLOCK_VERSION: u32 = 1;
/// On-disk length cap for the superblock's string fields; config validation
/// enforces it so `encode` can never be handed an over-long value.
pub const MAX_STR: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub generation: u64,
    pub volume_uuid: Uuid,
    pub provider_type: String,
    pub crypto_compatibility_id: String,
    pub key_identity: String,
    pub geometry: Geometry,
    pub format_version: u32,
    pub created_unix: u64,
}

impl Superblock {
    pub fn encode(&self) -> Vec<u8> {
        let g = &self.geometry;
        let mut w = Writer::new();
        w.bytes(SUPERBLOCK_MAGIC)
            .u32(SUPERBLOCK_VERSION)
            .u64(self.generation)
            .uuid(&self.volume_uuid)
            .u32(g.device_block_size)
            .u32(g.crypto_unit_size)
            .u32(g.slot_alignment)
            .u32(g.max_ciphertext_size)
            .u32(g.slot_header_size)
            .u64(g.slot_size)
            .u64(g.max_virtual_size)
            .u64(g.shard_logical_size)
            .u32(self.format_version)
            .u64(self.created_unix)
            .u64(0); // flags
        w.string(&self.provider_type, MAX_STR)
            .expect("validated provider_type");
        w.string(&self.crypto_compatibility_id, MAX_STR)
            .expect("validated compat id");
        w.string(&self.key_identity, MAX_STR)
            .expect("validated key identity");
        w.pad_to(SUPERBLOCK_SIZE - 4);
        let out = w.finish_with_crc();
        debug_assert_eq!(out.len(), SUPERBLOCK_SIZE);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(FormatError::Truncated(format!(
                "superblock: {} < {SUPERBLOCK_SIZE}",
                data.len()
            )));
        }
        let data = &data[..SUPERBLOCK_SIZE];
        if &data[0..8] != SUPERBLOCK_MAGIC {
            return Err(FormatError::BadMagic("superblock".to_string()));
        }
        let payload = strip_verify_crc(data, "superblock")?;
        let mut r = Reader::new(payload);
        let _magic = r.take(8)?;
        let version = r.u32()?;
        if version != SUPERBLOCK_VERSION {
            return Err(FormatError::Unsupported(format!(
                "superblock version {version}"
            )));
        }
        let generation = r.u64()?;
        let volume_uuid = r.uuid()?;
        let device_block_size = r.u32()?;
        let crypto_unit_size = r.u32()?;
        let slot_alignment = r.u32()?;
        let max_ciphertext_size = r.u32()?;
        let slot_header_size = r.u32()?;
        let slot_size = r.u64()?;
        let max_virtual_size = r.u64()?;
        let shard_logical_size = r.u64()?;
        let format_version = r.u32()?;
        let created_unix = r.u64()?;
        let _flags = r.u64()?;
        let provider_type = r.string(MAX_STR)?;
        let crypto_compatibility_id = r.string(MAX_STR)?;
        let key_identity = r.string(MAX_STR)?;

        let geometry = Geometry::compute(
            device_block_size,
            crypto_unit_size,
            slot_alignment,
            max_ciphertext_size,
            max_virtual_size,
            shard_logical_size,
        )?;
        if geometry.slot_size != slot_size || geometry.slot_header_size != slot_header_size {
            return Err(FormatError::Invalid(format!(
                "stored slot geometry ({slot_header_size}, {slot_size}) does not match computed ({}, {})",
                geometry.slot_header_size, geometry.slot_size
            )));
        }
        Ok(Self {
            generation,
            volume_uuid,
            provider_type,
            crypto_compatibility_id,
            key_identity,
            geometry,
            format_version,
            created_unix,
        })
    }
}

impl crate::ab::AbRecord for Superblock {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        Superblock::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        Superblock::decode(data)
    }
}
