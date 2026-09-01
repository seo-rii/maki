//! Per-shard allocation bitmap (SPEC §22), A/B replicated.

use crate::ab::AbRecord;
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const ALLOCATION_MAGIC: &[u8; 8] = b"MAKIALC1";
pub const ALLOCATION_VERSION: u32 = 1;
/// Hard cap: 64 GiB shard at 4 KiB units = 16 Mi units = 2 MiB of bitmap.
const MAX_UNITS: u64 = 1 << 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationMap {
    generation: u64,
    units: u64,
    bits: Vec<u8>,
}

impl AllocationMap {
    pub fn new(units: u64) -> Self {
        assert!(units <= MAX_UNITS);
        Self {
            generation: 0,
            units,
            bits: vec![0u8; units.div_ceil(8) as usize],
        }
    }

    pub fn units(&self) -> u64 {
        self.units
    }

    pub fn get(&self, unit: u64) -> bool {
        assert!(unit < self.units, "unit {unit} out of range {}", self.units);
        self.bits[(unit / 8) as usize] & (1 << (unit % 8)) != 0
    }

    pub fn set(&mut self, unit: u64, allocated: bool) {
        assert!(unit < self.units, "unit {unit} out of range {}", self.units);
        let byte = &mut self.bits[(unit / 8) as usize];
        if allocated {
            *byte |= 1 << (unit % 8);
        } else {
            *byte &= !(1 << (unit % 8));
        }
    }

    pub fn set_count(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(ALLOCATION_MAGIC)
            .u32(ALLOCATION_VERSION)
            .u64(self.generation)
            .u64(self.units)
            .bytes(&self.bits);
        w.finish_with_crc()
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let payload = strip_verify_crc(data, "allocation map")?;
        let mut r = Reader::new(payload);
        let magic = r.take(8)?;
        if magic != ALLOCATION_MAGIC {
            return Err(FormatError::BadMagic("allocation map".to_string()));
        }
        let version = r.u32()?;
        if version != ALLOCATION_VERSION {
            return Err(FormatError::Unsupported(format!(
                "allocation map version {version}"
            )));
        }
        let generation = r.u64()?;
        let units = r.u64()?;
        if units > MAX_UNITS {
            return Err(FormatError::Invalid(format!("allocation units {units}")));
        }
        let expected = units.div_ceil(8) as usize;
        let bits = r.take(expected)?.to_vec();
        if r.remaining() != 0 {
            return Err(FormatError::Invalid(
                "trailing bytes after allocation bitmap".to_string(),
            ));
        }
        Ok(Self {
            generation,
            units,
            bits,
        })
    }
}

impl AbRecord for AllocationMap {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        AllocationMap::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        AllocationMap::decode(data)
    }
}
