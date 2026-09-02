//! Device geometry and slot-size calculation (SPEC §13–14).
//! All arithmetic is checked; invalid or overflowing inputs are errors.

use crate::error::FormatError;

pub const SLOT_HEADER_SIZE: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub device_block_size: u32,
    pub crypto_unit_size: u32,
    pub slot_alignment: u32,
    pub max_ciphertext_size: u32,
    pub slot_header_size: u32,
    /// `align_up(slot_header_size + max_ciphertext_size, slot_alignment)`
    pub slot_size: u64,
    pub max_virtual_size: u64,
    pub shard_logical_size: u64,
}

fn is_pow2(v: u64) -> bool {
    v != 0 && (v & (v - 1)) == 0
}

fn align_up(v: u64, align: u64) -> Result<u64, FormatError> {
    debug_assert!(is_pow2(align));
    let sum = v
        .checked_add(align - 1)
        .ok_or_else(|| FormatError::Overflow("align_up".to_string()))?;
    Ok(sum & !(align - 1))
}

impl Geometry {
    pub fn compute(
        device_block_size: u32,
        crypto_unit_size: u32,
        slot_alignment: u32,
        max_ciphertext_size: u32,
        max_virtual_size: u64,
        shard_logical_size: u64,
    ) -> Result<Self, FormatError> {
        if !is_pow2(device_block_size as u64) || !(512..=65536).contains(&device_block_size) {
            return Err(FormatError::Invalid(format!(
                "device_block_size {device_block_size} must be a power of two in [512, 65536]"
            )));
        }
        if crypto_unit_size == 0
            || crypto_unit_size < device_block_size
            || !crypto_unit_size.is_multiple_of(device_block_size)
        {
            return Err(FormatError::Invalid(format!(
                "crypto_unit_size {crypto_unit_size} must be a positive multiple of device_block_size {device_block_size}"
            )));
        }
        if !is_pow2(slot_alignment as u64) || slot_alignment < 512 {
            return Err(FormatError::Invalid(format!(
                "slot_alignment {slot_alignment} must be a power of two >= 512"
            )));
        }
        if max_ciphertext_size < crypto_unit_size {
            return Err(FormatError::Invalid(format!(
                "max_ciphertext_size {max_ciphertext_size} < crypto_unit_size {crypto_unit_size}"
            )));
        }
        if max_virtual_size == 0 || !max_virtual_size.is_multiple_of(crypto_unit_size as u64) {
            return Err(FormatError::Invalid(format!(
                "max_virtual_size {max_virtual_size} must be a positive multiple of crypto_unit_size"
            )));
        }
        if shard_logical_size == 0 || !shard_logical_size.is_multiple_of(crypto_unit_size as u64) {
            return Err(FormatError::Invalid(format!(
                "shard_logical_size {shard_logical_size} must be a positive multiple of crypto_unit_size"
            )));
        }

        let slot_size = align_up(
            SLOT_HEADER_SIZE as u64 + max_ciphertext_size as u64,
            slot_alignment as u64,
        )?;

        let geometry = Self {
            device_block_size,
            crypto_unit_size,
            slot_alignment,
            max_ciphertext_size,
            slot_header_size: SLOT_HEADER_SIZE,
            slot_size,
            max_virtual_size,
            shard_logical_size,
        };

        // A full shard's physical byte size must be representable.
        geometry
            .units_per_shard()
            .checked_mul(slot_size)
            .ok_or_else(|| FormatError::Overflow("shard physical size".to_string()))?;

        Ok(geometry)
    }

    pub fn num_units(&self) -> u64 {
        self.max_virtual_size / self.crypto_unit_size as u64
    }

    pub fn units_per_shard(&self) -> u64 {
        self.shard_logical_size / self.crypto_unit_size as u64
    }

    pub fn num_shards(&self) -> u64 {
        self.num_units().div_ceil(self.units_per_shard())
    }

    /// (shard index, unit index within the shard)
    pub fn shard_of_unit(&self, unit: u64) -> (u64, u64) {
        let per = self.units_per_shard();
        (unit / per, unit % per)
    }

    /// Byte offset of a slot within its shard data file.
    pub fn slot_offset(&self, index_in_shard: u64) -> u64 {
        index_in_shard * self.slot_size
    }
}
