//! `maki-format` — configuration schema and on-disk format (SPEC §43).
//!
//! Everything here is deterministic, panic-free on malformed input, and
//! CRC-protected. Multi-copy metadata uses the A/B generation protocol
//! ([`ab`]). Golden vectors freeze the v1 encodings.

pub mod ab;
pub mod allocation;
pub mod catalog;
pub mod checker;
pub mod codec;
pub mod config;
pub mod error;
pub mod geometry;
pub mod init;
pub mod journal;
pub mod slot;
pub mod superblock;

pub use error::FormatError;

/// On-disk layout names within a volume backing root (SPEC §21).
pub mod layout {
    pub const VOLUME_LOCK: &str = "volume.lock";
    pub const SUPERBLOCK_A: &str = "superblock.a";
    pub const SUPERBLOCK_B: &str = "superblock.b";
    pub const SHARD_CATALOG_A: &str = "shard-catalog.a";
    pub const SHARD_CATALOG_B: &str = "shard-catalog.b";
    pub const DATA_DIR: &str = "data";
    pub const JOURNAL_DIR: &str = "journal";
    pub const CHECKPOINT_DIR: &str = "checkpoint";

    pub fn shard_data(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.dat")
    }

    pub fn shard_alloc_a(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.alloc.a")
    }

    pub fn shard_alloc_b(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.alloc.b")
    }

    pub fn journal_segment(index: u64) -> String {
        format!("{JOURNAL_DIR}/seg-{index:016x}")
    }

    /// Parse a journal segment file name back to its index.
    pub fn parse_journal_segment(name: &str) -> Option<u64> {
        let hex = name.strip_prefix("seg-")?;
        if hex.len() != 16 {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    }
}
