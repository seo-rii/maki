//! Shard catalog (SPEC §22): the durable set of shards that exist.
//! A shard absent from the catalog reads as unwritten zeros.

use std::collections::BTreeSet;

use crate::ab::AbRecord;
use crate::codec::{strip_verify_crc, Reader, Writer};
use crate::error::FormatError;

pub const CATALOG_MAGIC: &[u8; 8] = b"MAKICAT1";
pub const CATALOG_VERSION: u32 = 1;
const MAX_SHARDS: u32 = 1 << 24;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShardCatalog {
    generation: u64,
    shards: BTreeSet<u64>,
}

impl ShardCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, shard: u64) -> bool {
        self.shards.contains(&shard)
    }

    pub fn insert(&mut self, shard: u64) -> bool {
        self.shards.insert(shard)
    }

    pub fn shard_indices(&self) -> impl Iterator<Item = u64> + '_ {
        self.shards.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.shards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(CATALOG_MAGIC)
            .u32(CATALOG_VERSION)
            .u64(self.generation)
            .u32(self.shards.len() as u32);
        for shard in &self.shards {
            w.u64(*shard);
        }
        w.finish_with_crc()
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let payload = strip_verify_crc(data, "shard catalog")?;
        let mut r = Reader::new(payload);
        let magic = r.take(8)?;
        if magic != CATALOG_MAGIC {
            return Err(FormatError::BadMagic("shard catalog".to_string()));
        }
        let version = r.u32()?;
        if version != CATALOG_VERSION {
            return Err(FormatError::Unsupported(format!(
                "shard catalog version {version}"
            )));
        }
        let generation = r.u64()?;
        let count = r.u32()?;
        if count > MAX_SHARDS {
            return Err(FormatError::Invalid(format!("shard count {count}")));
        }
        let mut shards = BTreeSet::new();
        let mut prev: Option<u64> = None;
        for _ in 0..count {
            let s = r.u64()?;
            if let Some(p) = prev {
                if s <= p {
                    return Err(FormatError::Invalid(
                        "catalog entries not strictly ascending".to_string(),
                    ));
                }
            }
            prev = Some(s);
            shards.insert(s);
        }
        if r.remaining() != 0 {
            return Err(FormatError::Invalid(
                "trailing bytes after catalog".to_string(),
            ));
        }
        Ok(Self { generation, shards })
    }
}

impl AbRecord for ShardCatalog {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn encode(&self) -> Vec<u8> {
        ShardCatalog::encode(self)
    }

    fn decode(data: &[u8]) -> Result<Self, FormatError> {
        ShardCatalog::decode(data)
    }
}
