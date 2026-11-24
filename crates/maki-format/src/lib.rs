//! `maki-format` — configuration schema and on-disk format (SPEC §43).
//!
//! Everything here is deterministic, panic-free on malformed input, and
//! CRC-protected. Multi-copy metadata uses the A/B generation protocol
//! ([`ab`]). Golden vectors freeze the v1 encodings.

// Diagnostics go through `tracing`: the `print!` family panics when the
// write fails (a closed pipe, a full disk). Tests may print.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod ab;
pub mod allocation;
pub mod canary;
pub mod catalog;
pub mod checker;
pub mod checkpoint;
pub mod codec;
pub mod config;
pub mod durable_proof;
pub mod endpoint_limits;
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
    /// The first superblock copy of a creation while it is written, before
    /// it is renamed to [`SUPERBLOCK_A`]. Nothing reads it.
    pub const SUPERBLOCK_NEXT: &str = "superblock.next";
    pub const SHARD_CATALOG_A: &str = "shard-catalog.a";
    pub const SHARD_CATALOG_B: &str = "shard-catalog.b";
    /// Provider/key-bound canary (see `canary`), established at first attach.
    pub const KEY_CANARY_A: &str = "canary.a";
    pub const KEY_CANARY_B: &str = "canary.b";
    pub const DATA_DIR: &str = "data";
    pub const JOURNAL_DIR: &str = "journal";
    pub const CHECKPOINT_DIR: &str = "checkpoint";
    /// The journal writer's fdatasync high-water mark (see `journal::DurableMark`).
    pub const JOURNAL_DURABLE_MARK: &str = "journal/durable-mark";

    /// Every volume metadata file at the root of the backing except
    /// [`VOLUME_LOCK`]. Volume creation refuses a root that holds any of
    /// them, so a new root-level file must be listed here.
    pub const ROOT_METADATA: [&str; 7] = [
        SUPERBLOCK_A,
        SUPERBLOCK_B,
        SUPERBLOCK_NEXT,
        SHARD_CATALOG_A,
        SHARD_CATALOG_B,
        KEY_CANARY_A,
        KEY_CANARY_B,
    ];

    pub fn shard_data(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.dat")
    }

    /// Parse a shard data file name (an entry of [`DATA_DIR`]) back to its
    /// index. Only the exact spelling [`shard_data`] produces is a shard.
    pub fn parse_shard_data(name: &str) -> Option<u64> {
        let hex = name.strip_prefix("shard-")?.strip_suffix(".dat")?;
        let index = u64::from_str_radix(hex, 16).ok()?;
        (shard_data(index) == format!("{DATA_DIR}/{name}")).then_some(index)
    }

    pub fn shard_alloc_a(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.alloc.a")
    }

    pub fn shard_alloc_b(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.alloc.b")
    }

    pub fn shard_discard_a(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.discard.a")
    }

    pub fn shard_discard_b(shard: u64) -> String {
        format!("{DATA_DIR}/shard-{shard:08x}.discard.b")
    }

    pub fn journal_segment(index: u64) -> String {
        format!("{JOURNAL_DIR}/seg-{index:016x}")
    }

    /// Parse a journal segment file name back to its index. Only the exact
    /// spelling [`journal_segment`] produces is a segment: recovery scans a
    /// listed name but replays and reclaims through the canonical path, so a
    /// second spelling (upper-case hex, a sign) must never be accepted.
    pub fn parse_journal_segment(name: &str) -> Option<u64> {
        let hex = name.strip_prefix("seg-")?;
        let index = u64::from_str_radix(hex, 16).ok()?;
        (journal_segment(index) == format!("{JOURNAL_DIR}/{name}")).then_some(index)
    }
}
