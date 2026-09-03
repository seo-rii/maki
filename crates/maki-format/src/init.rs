//! Volume initialization (mkfs): create the durable on-disk layout (SPEC §21).

use maki_backing::Backing;

use crate::ab::AbStore;
use crate::catalog::ShardCatalog;
use crate::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use crate::error::FormatError;
use crate::layout;
use crate::superblock::Superblock;

/// Create a new volume in an empty backing root. Everything created here is
/// durable when this returns (dirs synced), so a crash immediately after
/// creation leaves a valid volume.
pub fn create_volume(
    backing: &dyn Backing,
    mut superblock: Superblock,
) -> Result<Superblock, FormatError> {
    if backing.exists(layout::SUPERBLOCK_A)? || backing.exists(layout::SUPERBLOCK_B)? {
        return Err(FormatError::AlreadyExists(
            "volume superblock already present".to_string(),
        ));
    }

    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        backing.create_dir_all(dir)?;
    }

    // Lock file (contents unused; presence + advisory lock semantics).
    let lock_file = backing.open(layout::VOLUME_LOCK, true)?;
    lock_file.sync_data()?;

    // Both superblock copies, so a single later torn write can never leave
    // the volume unreadable.
    superblock.generation = 0;
    let sb_ab = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B);
    sb_ab.store(backing, &mut superblock)?; // side A, gen 1
    sb_ab.store(backing, &mut superblock)?; // side B, gen 2

    // Empty shard catalog (single copy now; second side written on first
    // update).
    let cat_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    let mut catalog = ShardCatalog::new();
    cat_ab.store(backing, &mut catalog)?;

    // Initial checkpoint state (sequence 0), both copies: recovery requires
    // a valid copy on every initialized volume, so that losing the state
    // can never be mistaken for "never checkpointed".
    let ck_ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state = CheckpointState::default();
    ck_ab.store(backing, &mut state)?;
    ck_ab.store(backing, &mut state)?;

    // The journal writer's durable mark (empty = no information yet); its
    // dirent is made durable here so the first mark write never depends on
    // a later directory fsync.
    let mark = backing.open(layout::JOURNAL_DURABLE_MARK, true)?;
    mark.set_len(0)?;
    mark.sync_data()?;

    // Make all dirents durable.
    backing.sync_dir(layout::DATA_DIR)?;
    backing.sync_dir(layout::JOURNAL_DIR)?;
    backing.sync_dir(layout::CHECKPOINT_DIR)?;
    backing.sync_dir("")?;

    Ok(superblock)
}

/// Load the current superblock of an existing volume.
pub fn load_superblock(backing: &dyn Backing) -> Result<Superblock, FormatError> {
    AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B)
        .load::<Superblock>(backing)?
        .ok_or_else(|| FormatError::Invalid("no valid superblock".to_string()))
}
