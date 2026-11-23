//! Per-shard allocation bitmap (SPEC §22), A/B replicated.

use crate::ab::AbRecord;
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const ALLOCATION_MAGIC: &[u8; 8] = b"MAKIALC1";
pub const ALLOCATION_VERSION: u32 = 1;
pub(crate) const ENCODED_FIXED_BYTES: u64 = ALLOCATION_MAGIC.len() as u64 + 4 + 8 + 8 + 4;
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

    /// Set units below an exclusive limit, in ascending order. Skip empty
    /// bytes and stop at the addressable end of a partially filled shard.
    pub fn set_units(&self, limit: u64) -> impl Iterator<Item = u64> + '_ {
        let limit = limit.min(self.units);
        self.bits[..limit.div_ceil(8) as usize]
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, byte)| *byte != 0)
            .flat_map(|(index, byte)| {
                let base = index as u64 * 8;
                (0..8).filter_map(move |bit| (byte & (1 << bit) != 0).then_some(base + bit))
            })
            .take_while(move |&unit| unit < limit)
    }

    /// Number of allocated units (padding bits are always clear).
    pub fn set_count(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::encoded_len(self.units) as usize);
        w.bytes(ALLOCATION_MAGIC)
            .u32(ALLOCATION_VERSION)
            .u64(self.generation)
            .u64(self.units)
            .bytes(&self.bits);
        w.finish_with_crc()
    }

    /// Exact encoded size of a map over `units` units (header, bitmap, CRC).
    pub fn encoded_len(units: u64) -> u64 {
        ENCODED_FIXED_BYTES + units.div_ceil(8)
    }

    fn decode_parts(data: &[u8]) -> Result<(u64, u64, &[u8]), FormatError> {
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
        let bits = r.take(expected)?;
        if r.remaining() != 0 {
            return Err(FormatError::Invalid(
                "trailing bytes after allocation bitmap".to_string(),
            ));
        }
        Ok((generation, units, bits))
    }

    /// Check the entire frame and return its generation and geometry.
    pub(crate) fn decode_geometry(data: &[u8]) -> Result<(u64, u64), FormatError> {
        let (generation, units, _) = Self::decode_parts(data)?;
        Ok((generation, units))
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let (generation, units, bits) = Self::decode_parts(data)?;
        let mut bits = bits.to_vec();
        // The last byte's bits past `units` name no unit. No writer sets
        // them, but they were never checked, so a copy with them set stays
        // valid; they are cleared here instead. Counted, they would make an
        // empty map look like one that lists a slot, which is how
        // `SlotStore::open` tells a short never-finished shard from a
        // truncated one (SPEC §22).
        let used = units % 8;
        if used != 0 {
            if let Some(last) = bits.last_mut() {
                *last &= (1u8 << used) - 1;
            }
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

#[cfg(test)]
mod tests {
    use super::AllocationMap;

    #[test]
    fn set_units_stops_at_the_addressable_limit() {
        let mut map = AllocationMap::new(67);
        for slot in [0, 7, 32, 35, 63, 65] {
            map.set(slot, true);
        }
        for limit in [0, 1, 7, 8, 24, 35, 36, 64, 66, 67, u64::MAX] {
            let expected: Vec<_> = (0..limit.min(map.units()))
                .filter(|&slot| map.get(slot))
                .collect();
            assert_eq!(map.set_units(limit).collect::<Vec<_>>(), expected);
        }
    }
}
