//! Volume superblock (fixed 4096-byte image, A/B replicated).
//!
//! Envelope v2 requires the durable-proof recovery policy; the cryptographic
//! context's `format_version` is separate and is not changed by this envelope.
//! Writable recovery must use [`load_volume_superblock`] and retain that policy
//! version. [`Superblock::encode`] deliberately remains the frozen v1 format.
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
pub const SUPERBLOCK_VERSION_V2: u32 = 2;
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
        self.encode_metadata_version(SUPERBLOCK_VERSION)
    }

    fn encode_metadata_version(&self, metadata_version: u32) -> Vec<u8> {
        let g = &self.geometry;
        let mut w = Writer::new();
        w.bytes(SUPERBLOCK_MAGIC)
            .u32(metadata_version)
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
        if !matches!(version, SUPERBLOCK_VERSION | SUPERBLOCK_VERSION_V2) {
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

/// The volume model together with the envelope version that selects its
/// recovery policy. Loading this does not migrate or mutate a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSuperblock {
    pub superblock: Superblock,
    pub metadata_version: u32,
}

impl VolumeSuperblock {
    /// Encode an explicitly selected, supported envelope. Callers must not
    /// use this to convert an existing volume without an offline migration.
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            matches!(
                self.metadata_version,
                SUPERBLOCK_VERSION | SUPERBLOCK_VERSION_V2
            ),
            "unsupported metadata envelope for encoding"
        );
        self.superblock
            .encode_metadata_version(self.metadata_version)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let superblock = Superblock::decode(data)?;
        // Model decoding checked the complete block, CRC, and supported version.
        let metadata_version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        Ok(Self {
            superblock,
            metadata_version,
        })
    }
}

impl crate::ab::AbRecord for VolumeSuperblock {
    const MAX_ENCODED_LEN: u64 = SUPERBLOCK_SIZE as u64;

    fn generation(&self) -> u64 {
        self.superblock.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.superblock.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        VolumeSuperblock::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        VolumeSuperblock::decode(data)
    }
}

fn read_volume_copy(
    backing: &dyn maki_backing::Backing,
    path: &str,
) -> Result<Option<(VolumeSuperblock, Vec<u8>)>, FormatError> {
    let file = match backing.open(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // Never allocate according to an untrusted length. A future envelope may
    // legitimately have a different size: inspect only its fixed header before
    // deciding that this side is merely a torn copy of a supported version.
    let length = file.len()?;
    if length != SUPERBLOCK_SIZE as u64 {
        if length >= 12 {
            let mut header = [0; 12];
            match file.read_at(0, &mut header) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
            if &header[..8] == SUPERBLOCK_MAGIC
                && !matches!(version, SUPERBLOCK_VERSION | SUPERBLOCK_VERSION_V2)
            {
                // The future layout's checksum location is unknown. Refusing
                // its recognizable header is safer than downgrading policy.
                return Err(FormatError::Unsupported(format!(
                    "superblock version {version}"
                )));
            }
        }
        return Ok(None);
    }
    let mut bytes = vec![0; SUPERBLOCK_SIZE];
    match file.read_at(0, &mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    match VolumeSuperblock::decode(&bytes) {
        Ok(record) => Ok(Some((record, bytes))),
        // The decoder checks magic and CRC before checking the envelope. An
        // unknown version with a valid CRC is not permission to select v1.
        Err(error @ FormatError::Unsupported(_)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// Load A/B superblocks without erasing their recovery-policy version.
///
/// Unlike the generic A/B record loader, this refuses supported-version
/// mixtures, same-generation byte conflicts, and CRC-valid unknown versions.
/// A different-sized image with a recognizable unsupported-version header is
/// also refused; its checksum layout cannot be assumed to match this version.
/// Hard I/O errors propagate; only absent, torn, or malformed copies may be
/// replaced by the other side. No disk changes are made here.
pub fn load_volume_superblock(
    backing: &dyn maki_backing::Backing,
) -> Result<VolumeSuperblock, FormatError> {
    let a = read_volume_copy(backing, crate::layout::SUPERBLOCK_A)?;
    let b = read_volume_copy(backing, crate::layout::SUPERBLOCK_B)?;
    match (a, b) {
        (Some((a, a_bytes)), Some((b, b_bytes))) => {
            if a.metadata_version != b.metadata_version {
                return Err(FormatError::Invalid(
                    "mixed superblock metadata versions; refusing an interrupted format change"
                        .into(),
                ));
            }
            if a.superblock.generation == b.superblock.generation && a_bytes != b_bytes {
                return Err(FormatError::Invalid(
                    "conflicting superblocks at the same generation".into(),
                ));
            }
            Ok(if a.superblock.generation >= b.superblock.generation {
                a
            } else {
                b
            })
        }
        (Some((record, _)), None) | (None, Some((record, _))) => Ok(record),
        (None, None) => Err(FormatError::Invalid("no valid superblock".into())),
    }
}

impl crate::ab::AbRecord for Superblock {
    // A superblock is always exactly one fixed-size block; anything larger is
    // corruption and is rejected before it is read (MAKI-026).
    const MAX_ENCODED_LEN: u64 = SUPERBLOCK_SIZE as u64;

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
